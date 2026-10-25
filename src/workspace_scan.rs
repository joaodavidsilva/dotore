//! Disk-backed workspace scanning, scan result caching, and `dotore design` orchestration.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

#[cfg(any(feature = "js", feature = "py", feature = "rs"))]
use rayon::prelude::*;

use dotore_core::{
    ir::{FNV1A_64_OFFSET_BASIS, fnv1a_64_step, fnv1a_64_str},
    scanner::collect_source_files_for_analyzers,
};
#[cfg(feature = "js")]
use dotore_js::{JsLanguageAnalyzer, evaluate_file_in_package};

use crate::{
    BaselineSummary, Capability, CliOverrides, Diagnostic, DiffScope, DotoreConfig, ExtractedFile,
    FileContext, GitDiffInfo, JSON_REPORT_SCHEMA_VERSION, JsonReport, LanguageAnalyzer,
    RuleId, RuleSeverity, RuleSeverityOverride, RuleTag, SCAN_CACHE_SCHEMA_VERSION,
    ScanCacheEntry, ScanMode, ScanOptions, WorkspacePackage, analyze_polyglot_sources,
    build_polyglot_report, compare_baseline_diagnostics, default_analyzers,
    diff::{collect_git_diff, load_baseline_entries},
    discover_workspace_packages_with_analyzers, filter_diagnostics_by_scope,
    filter_workspace_packages, is_cache_disabled, lookup_scan_cache, register_active_core_hooks,
    resolve_package_for_file, resolve_scan_cache_path, rule_registry, set_progress_phase,
    store_scan_cache, tick_progress_file,
};
#[cfg(not(feature = "js"))]
use crate::build_extracted_report;
#[cfg(feature = "js")]
use crate::{build_report_with_packages, scanner::collect_style_files};

/// Scans the filesystem according to [`ScanOptions`], returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files fails.
pub fn scan_workspace(options: &ScanOptions) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    scan_workspace_with_overrides(options, &CliOverrides::default())
}

fn read_workspace_source_pairs(
    paths: Vec<PathBuf>,
    options: &ScanOptions,
    all_packages: &[WorkspacePackage],
    packages: &[WorkspacePackage],
) -> (Vec<(PathBuf, String)>, HashMap<PathBuf, String>) {
    #[cfg(any(feature = "js", feature = "py", feature = "rs"))]
    let mut pairs: Vec<(PathBuf, String)> = paths
        .into_par_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path).ok()?;
            tick_progress_file(&path);
            Some((path, content))
        })
        .collect();
    #[cfg(not(any(feature = "js", feature = "py", feature = "rs")))]
    let mut pairs: Vec<(PathBuf, String)> = paths
        .into_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path).ok()?;
            tick_progress_file(&path);
            Some((path, content))
        })
        .collect();

    let sources: HashMap<PathBuf, String> = pairs.iter().cloned().collect();
    if packages.iter().any(|pkg| {
        pkg.capability_gate.has(Capability::Motion)
            || pkg.capability_gate.has(Capability::AngularMaterial)
            || pkg.capability_gate.has(Capability::Angular)
    }) {
        for style_path in collect_style_files(&options.paths) {
            if resolve_package_for_file(&style_path, all_packages).is_none_or(|resolved_pkg| {
                packages
                    .iter()
                    .any(|sel| sel.root_dir == resolved_pkg.root_dir)
                    && !resolved_pkg
                        .config
                        .is_file_ignored(&style_path, &resolved_pkg.root_dir)
            }) && let Ok(content) = fs::read_to_string(&style_path)
            {
                pairs.push((style_path, content));
            }
        }
    }
    #[cfg(not(feature = "js"))]
    let _ = (options, all_packages, packages);

    (pairs, sources)
}

struct ScopeAndBaselineOutcome {
    diagnostics: Vec<Diagnostic>,
    mode: ScanMode,
    diff_info: Option<GitDiffInfo>,
    baseline_summary: Option<BaselineSummary>,
    baseline_degraded: bool,
}

fn apply_diff_and_baseline_filters(
    workspace_root: &Path,
    options: &ScanOptions,
    overrides: &CliOverrides,
    all_extracted: &[ExtractedFile],
    sources: &HashMap<PathBuf, String>,
    mut diagnostics: Vec<Diagnostic>,
) -> io::Result<ScopeAndBaselineOutcome> {
    let effective_scope = if overrides.staged && overrides.scope == DiffScope::Full {
        DiffScope::Changed
    } else {
        overrides.scope
    };

    let mut mode = ScanMode::Full;
    let mut diff_info = None;
    let mut baseline_summary = None;
    let mut baseline_degraded = false;
    if effective_scope != DiffScope::Full || overrides.staged || overrides.base_ref.is_some() {
        let diff_snap = collect_git_diff(
            workspace_root,
            overrides.base_ref.as_deref(),
            overrides.staged,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        diagnostics = filter_diagnostics_by_scope(
            diagnostics,
            effective_scope,
            &diff_snap.repo_root,
            &diff_snap.changed_files,
            &diff_snap.line_ranges,
            all_extracted,
            sources,
        );
        diff_info = Some(diff_snap.info);
        mode = if overrides.staged {
            ScanMode::Staged
        } else {
            ScanMode::Diff
        };
    }

    if let Some(baseline_arg) = &overrides.baseline_path {
        match load_baseline_entries(workspace_root, baseline_arg, options.rules.as_deref()) {
            Ok(base_entries) => {
                let delta = compare_baseline_diagnostics(
                    &diagnostics,
                    sources,
                    &base_entries,
                    &baseline_arg.to_string_lossy(),
                );
                diagnostics = delta.introduced_diagnostics;
                baseline_summary = Some(delta.summary);
                mode = ScanMode::Baseline;
            }
            Err(_) => {
                baseline_degraded = true;
                mode = ScanMode::Diff;
                if diff_info.is_none()
                    && let Ok(diff_snap) = collect_git_diff(
                        workspace_root,
                        overrides.base_ref.as_deref(),
                        overrides.staged,
                    )
                {
                    diagnostics = filter_diagnostics_by_scope(
                        diagnostics,
                        DiffScope::Changed,
                        &diff_snap.repo_root,
                        &diff_snap.changed_files,
                        &diff_snap.line_ranges,
                        all_extracted,
                        sources,
                    );
                    diff_info = Some(diff_snap.info);
                }
            }
        }
    }

    Ok(ScopeAndBaselineOutcome {
        diagnostics,
        mode,
        diff_info,
        baseline_summary,
        baseline_degraded,
    })
}

/// Scans the filesystem according to [`ScanOptions`] and [`CliOverrides`] across all active
/// [`LanguageAnalyzer`]s, returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files or an explicit `--config` file fails.
pub fn scan_workspace_with_overrides(
    options: &ScanOptions,
    overrides: &CliOverrides,
) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    register_active_core_hooks();
    set_progress_phase(1, 0);
    let analyzers = default_analyzers();
    let (workspace_root, all_packages, packages, paths) =
        discover_filtered_workspace_packages_and_paths(options, overrides, analyzers)?;
    set_progress_phase(2, paths.len());
    let (pairs, sources) = read_workspace_source_pairs(paths, options, &all_packages, &packages);

    let manifests = load_disk_manifests(&workspace_root, &packages, &sources);
    let cache_context = if !is_cache_disabled(overrides.no_cache)
        && let Some(cache_path) = resolve_scan_cache_path()
    {
        let (cache_key, canonical_root, head_sha) = compute_scan_cache_meta_and_key(
            &workspace_root,
            options,
            overrides,
            &packages,
            &pairs,
            &manifests,
        );
        if let Some(cached_report) = lookup_scan_cache(&cache_path, &cache_key) {
            return Ok((cached_report, sources));
        }
        Some((cache_path, cache_key, canonical_root, head_sha))
    } else {
        None
    };

    let (all_extracted, js_graph_opt, mut diagnostics) = analyze_polyglot_sources(
        &packages,
        manifests,
        pairs,
        &sources,
        options.rules.as_deref(),
    );

    if let Some(allowed_tiers) = &options.tiers {
        diagnostics.retain(|d| allowed_tiers.contains(&d.tier));
    }

    let filtered = apply_diff_and_baseline_filters(
        &workspace_root,
        options,
        overrides,
        &all_extracted,
        &sources,
        diagnostics,
    )?;

    let mut report = build_polyglot_report(
        &all_extracted,
        js_graph_opt.as_ref(),
        filtered.diagnostics,
        &sources,
        &packages,
    );
    report.mode = filtered.mode;
    report.diff = filtered.diff_info;
    report.baseline = filtered.baseline_summary;
    report.baseline_degraded = filtered.baseline_degraded;

    if let Some((cache_path, cache_key, canonical_root, head_sha)) = cache_context {
        let updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        let _ = store_scan_cache(
            &cache_path,
            ScanCacheEntry {
                key: cache_key,
                workspace_root: canonical_root,
                head_sha,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                updated_at_ms,
                report: report.clone(),
            },
        );
    }
    Ok((report, sources))
}

fn run_git_capture(workspace_root: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn resolve_git_head_sha(workspace_root: &Path) -> String {
    if let Some(sha) = run_git_capture(workspace_root, &["rev-parse", "HEAD"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        sha
    } else if workspace_root.join(".git").exists()
        || run_git_capture(workspace_root, &["rev-parse", "--is-inside-work-tree"]).is_some()
    {
        "uncommitted".to_string()
    } else {
        "no-git".to_string()
    }
}

fn hash_binary_and_options(hash: &mut u64, canonical_root_str: &str, options: &ScanOptions) {
    fnv1a_64_str(hash, env!("CARGO_PKG_VERSION"));
    if let Ok(exe_path) = std::env::current_exe()
        && let Ok(meta) = fs::metadata(&exe_path)
    {
        fnv1a_64_str(hash, &meta.len().to_string());
        if let Ok(modified) = meta.modified()
            && let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH)
        {
            fnv1a_64_str(hash, &dur.as_nanos().to_string());
        }
    }
    fnv1a_64_str(hash, &JSON_REPORT_SCHEMA_VERSION.to_string());
    fnv1a_64_str(hash, &SCAN_CACHE_SCHEMA_VERSION.to_string());
    fnv1a_64_str(hash, canonical_root_str);

    fnv1a_64_str(hash, &options.paths.len().to_string());
    for p in &options.paths {
        fnv1a_64_str(hash, &p.to_string_lossy());
    }
    fnv1a_64_str(
        hash,
        if options.include_tests {
            "tests:1"
        } else {
            "tests:0"
        },
    );
    if let Some(rules) = &options.rules {
        fnv1a_64_str(hash, &format!("rules:{}", rules.len()));
        for r in rules {
            fnv1a_64_str(hash, r.as_str());
        }
    } else {
        fnv1a_64_str(hash, "rules:all");
    }
    if let Some(tiers) = &options.tiers {
        fnv1a_64_str(hash, &format!("tiers:{}", tiers.len()));
        for t in tiers {
            fnv1a_64_str(hash, t.as_str());
        }
    } else {
        fnv1a_64_str(hash, "tiers:all");
    }
}

fn hash_cli_overrides_and_git(
    hash: &mut u64,
    workspace_root: &Path,
    overrides: &CliOverrides,
    head_sha: &str,
) {
    fnv1a_64_str(
        hash,
        if overrides.no_inline_disables {
            "nid:1"
        } else {
            "nid:0"
        },
    );
    fnv1a_64_str(
        hash,
        if overrides.custom_rules_only {
            "cro:1"
        } else {
            "cro:0"
        },
    );
    fnv1a_64_str(hash, &format!("tags:{}", overrides.ignore_tags.len()));
    for tag in &overrides.ignore_tags {
        fnv1a_64_str(hash, tag);
    }
    fnv1a_64_str(hash, &format!("projects:{}", overrides.projects.len()));
    for proj in &overrides.projects {
        fnv1a_64_str(hash, proj);
    }
    fnv1a_64_str(hash, overrides.scope.as_str());
    fnv1a_64_str(hash, overrides.base_ref.as_deref().unwrap_or(""));
    fnv1a_64_str(
        hash,
        if overrides.staged {
            "staged:1"
        } else {
            "staged:0"
        },
    );
    if let Some(cfg_path) = &overrides.config_path {
        fnv1a_64_str(hash, &cfg_path.to_string_lossy());
        if let Ok(cfg_bytes) = fs::read_to_string(cfg_path) {
            fnv1a_64_str(hash, &cfg_bytes);
        }
    }
    hash_baseline_and_git_diff_state(hash, workspace_root, overrides, head_sha);
}

fn hash_git_working_tree_state(hash: &mut u64, workspace_root: &Path, overrides: &CliOverrides) {
    if let Some(status_out) = run_git_capture(workspace_root, &["status", "--porcelain", "-uall"]) {
        fnv1a_64_str(hash, &status_out);
    }
    if !(overrides.staged || overrides.scope != DiffScope::Full || overrides.base_ref.is_some()) {
        return;
    }
    if let Some(cached_diff) = run_git_capture(workspace_root, &["diff", "--cached"]) {
        fnv1a_64_str(hash, &cached_diff);
    }
    if let Some(work_diff) = run_git_capture(workspace_root, &["diff"]) {
        fnv1a_64_str(hash, &work_diff);
    }
    if let Some(base_ref) = &overrides.base_ref
        && let Some(base_sha) = run_git_capture(workspace_root, &["rev-parse", base_ref])
    {
        fnv1a_64_str(hash, &base_sha);
    }
}

fn hash_baseline_and_git_diff_state(
    hash: &mut u64,
    workspace_root: &Path,
    overrides: &CliOverrides,
    head_sha: &str,
) {
    if let Some(base_path) = &overrides.baseline_path {
        fnv1a_64_str(hash, &base_path.to_string_lossy());
        let resolved_base = if base_path.is_file() {
            Some(base_path.clone())
        } else {
            let cand = workspace_root.join(base_path);
            cand.is_file().then_some(cand)
        };
        if let Some(rp) = resolved_base
            && let Ok(base_bytes) = fs::read_to_string(&rp)
        {
            fnv1a_64_str(hash, &base_bytes);
        } else if let Some(rev_out) =
            run_git_capture(workspace_root, &["rev-parse", &base_path.to_string_lossy()])
        {
            fnv1a_64_str(hash, &rev_out);
        }
    }

    fnv1a_64_str(hash, head_sha);
    if head_sha != "no-git" {
        hash_git_working_tree_state(hash, workspace_root, overrides);
    }
}

fn hash_packages_and_source_maps(
    hash: &mut u64,
    packages: &[WorkspacePackage],
    pairs: &[(PathBuf, String)],
    manifests: &HashMap<PathBuf, String>,
) {
    fnv1a_64_str(hash, &format!("pkgs:{}", packages.len()));
    for pkg in packages {
        fnv1a_64_str(hash, &pkg.name);
        fnv1a_64_str(hash, &pkg.root_dir.to_string_lossy());
        if let Ok(pkg_json) = serde_json::to_string(pkg) {
            fnv1a_64_str(hash, &pkg_json);
        }
        for cfg_name in [
            "dotore.config.json",
            "dotore.config.js",
            "dotore.config.ts",
            "dotore.config.mjs",
            "dotore.config.cjs",
            "pyproject.toml",
            "requirements.txt",
            "Cargo.toml",
            "angular.json",
        ] {
            let p = pkg.root_dir.join(cfg_name);
            if let Ok(content) = fs::read_to_string(&p) {
                fnv1a_64_str(hash, cfg_name);
                fnv1a_64_str(hash, &content);
            }
        }
    }

    let mut sorted_pairs: Vec<(&Path, &str)> = pairs
        .iter()
        .map(|(p, c)| (p.as_path(), c.as_str()))
        .collect();
    sorted_pairs.sort_by_key(|(a, _)| *a);
    fnv1a_64_str(hash, &format!("pairs:{}", sorted_pairs.len()));
    for (path, content) in sorted_pairs {
        fnv1a_64_str(hash, &path.to_string_lossy());
        fnv1a_64_str(hash, &content.len().to_string());
        *hash = fnv1a_64_step(*hash, content.as_bytes());
    }

    let mut sorted_manifests: Vec<(&Path, &str)> = manifests
        .iter()
        .map(|(p, c)| (p.as_path(), c.as_str()))
        .collect();
    sorted_manifests.sort_by_key(|(a, _)| *a);
    fnv1a_64_str(hash, &format!("manifests:{}", sorted_manifests.len()));
    for (path, content) in sorted_manifests {
        fnv1a_64_str(hash, &path.to_string_lossy());
        fnv1a_64_str(hash, &content.len().to_string());
        *hash = fnv1a_64_step(*hash, content.as_bytes());
    }
}

fn compute_scan_cache_meta_and_key(
    workspace_root: &Path,
    options: &ScanOptions,
    overrides: &CliOverrides,
    packages: &[WorkspacePackage],
    pairs: &[(PathBuf, String)],
    manifests: &HashMap<PathBuf, String>,
) -> (String, String, String) {
    let canonical_root = fs::canonicalize(workspace_root)
        .unwrap_or_else(|_| dotore_core::config::normalize_path_buf(workspace_root));
    let canonical_root_str = canonical_root.to_string_lossy().to_string();
    let head_sha = resolve_git_head_sha(workspace_root);

    let mut hash = FNV1A_64_OFFSET_BASIS;
    hash_binary_and_options(&mut hash, &canonical_root_str, options);
    hash_cli_overrides_and_git(&mut hash, workspace_root, overrides, &head_sha);
    hash_packages_and_source_maps(&mut hash, packages, pairs, manifests);

    (format!("scan::{hash:016x}"), canonical_root_str, head_sha)
}

/// Returns all [`RuleId`]s tagged with [`RuleTag::Design`] (excluding whole-project analysis rules).
#[must_use]
pub fn design_rule_ids() -> Vec<RuleId> {
    rule_registry()
        .iter()
        .filter(|meta| {
            meta.tags.contains(&RuleTag::Design) && !meta.tags.contains(&RuleTag::ProjectAnalysis)
        })
        .map(|meta| meta.id)
        .collect()
}

/// Runs a focused UI design audit (`dotore design`), enabling all [`RuleTag::Design`] rules
/// while skipping unrelated project-analysis, supply-chain, and general effect/state rules.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files or an explicit `--config` file fails.
pub fn scan_design(
    options: &ScanOptions,
    overrides: &CliOverrides,
) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    register_active_core_hooks();
    #[cfg(feature = "js")]
    {
        scan_design_js(options, overrides)
    }
    #[cfg(not(feature = "js"))]
    {
        let _ = (options, overrides);
        let sources = HashMap::new();
        let mut report = build_extracted_report(&[], Vec::new(), &sources);
        report.summary.health_score = 100;
        report.summary.score_label = "Excellent".to_string();
        Ok((report, sources))
    }
}

#[cfg(feature = "js")]
fn scan_design_js(
    options: &ScanOptions,
    overrides: &CliOverrides,
) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    let mut design_rules = design_rule_ids();
    if let Some(explicit_rules) = &options.rules {
        design_rules.retain(|r| explicit_rules.contains(r));
    }
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    let (_, _, packages, paths) =
        discover_filtered_workspace_packages_and_paths(options, overrides, analyzers)?;
    set_progress_phase(2, paths.len());
    let pairs: Vec<(PathBuf, String)> = paths
        .into_par_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path).ok()?;
            tick_progress_file(&path);
            Some((path, content))
        })
        .collect();
    let sources: HashMap<PathBuf, String> = pairs.iter().cloned().collect();

    set_progress_phase(3, pairs.len());
    let extracted_files: Vec<ExtractedFile> = pairs
        .into_par_iter()
        .map(|(path, source)| {
            tick_progress_file(&path);
            js_analyzer.extract_file(&path, &source)
        })
        .collect();
    set_progress_phase(4, extracted_files.len());
    let graph = js_analyzer.build_graph_from_extracted(&extracted_files, HashMap::new());

    let mut diagnostics = Vec::new();
    let mut design_cfg = DotoreConfig::default();
    for file in &graph.files {
        tick_progress_file(&file.path);
        let Some(pkg) = resolve_package_for_file(&file.path, &packages) else {
            continue;
        };
        design_cfg.clone_from(&pkg.config);
        for &rule in &design_rules {
            if design_cfg.explicit_rule_override(rule).is_none() {
                let meta = rule.metadata();
                if file.file_context != FileContext::Production
                    && meta.tags.contains(&RuleTag::TestNoise)
                    && !meta.tags.contains(&RuleTag::MigrationHint)
                    && options.rules.is_none()
                {
                    continue;
                }
                let default_ov = match meta.default_severity {
                    RuleSeverity::Error => RuleSeverityOverride::Error,
                    RuleSeverity::Warning => RuleSeverityOverride::Warn,
                };
                design_cfg
                    .rules
                    .insert(rule.as_str().to_string(), default_ov);
            }
        }
        let mut file_diags = Vec::new();
        evaluate_file_in_package(
            &graph,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &design_cfg,
            None,
            &mut file_diags,
        );
        file_diags.retain(|d| design_rules.contains(&d.rule));
        diagnostics.extend(file_diags);
    }

    if let Some(allowed_tiers) = &options.tiers {
        diagnostics.retain(|d| allowed_tiers.contains(&d.tier));
    }

    let mut report = build_report_with_packages(&graph, diagnostics, &sources, &packages);
    report.summary.health_score = 100;
    report.summary.score_label = "Excellent".to_string();
    for proj in &mut report.projects {
        proj.health_score = 100;
        proj.score_label = "Excellent".to_string();
    }
    Ok((report, sources))
}

type DiscoveredWorkspaceSelection = (
    PathBuf,
    Vec<WorkspacePackage>,
    Vec<WorkspacePackage>,
    Vec<PathBuf>,
);

fn discover_filtered_workspace_packages_and_paths(
    options: &ScanOptions,
    overrides: &CliOverrides,
    analyzers: &[&dyn LanguageAnalyzer],
) -> io::Result<DiscoveredWorkspaceSelection> {
    let workspace_root = determine_workspace_root(&options.paths);
    let all_packages = discover_workspace_packages_with_analyzers(&workspace_root, analyzers);
    let mut packages =
        filter_workspace_packages(&all_packages, &workspace_root, &overrides.projects)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let explicit_cfg = if let Some(cfg_path) = &overrides.config_path {
        let content = fs::read_to_string(cfg_path)?;
        Some(
            DotoreConfig::from_config_file_str(cfg_path, &content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        )
    } else {
        None
    };

    for pkg in &mut packages {
        if let Some(cfg) = &explicit_cfg {
            pkg.config.clone_from(cfg);
        }
        apply_cli_overrides_to_config(&mut pkg.config, overrides);
    }

    let raw_paths =
        collect_source_files_for_analyzers(&options.paths, options.include_tests, analyzers);
    let paths: Vec<PathBuf> = raw_paths
        .into_iter()
        .filter(|p| {
            resolve_package_for_file(p, &all_packages).is_none_or(|resolved_pkg| {
                packages
                    .iter()
                    .any(|sel| sel.root_dir == resolved_pkg.root_dir)
                    && !resolved_pkg
                        .config
                        .is_file_ignored(p, &resolved_pkg.root_dir)
            })
        })
        .collect();

    Ok((workspace_root, all_packages, packages, paths))
}

fn determine_workspace_root(paths: &[PathBuf]) -> PathBuf {
    let Some(first) = paths.first() else {
        return PathBuf::from(".");
    };
    let dir_of = |p: &Path| -> PathBuf {
        if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent()
                .filter(|par| !par.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        }
    };
    let mut common = dir_of(first);
    for other in paths.iter().skip(1) {
        let other_dir = dir_of(other);
        while !other_dir.starts_with(&common) {
            let Some(parent) = common.parent() else {
                break;
            };
            if parent.as_os_str().is_empty() {
                common = PathBuf::from(".");
                break;
            }
            common = parent.to_path_buf();
        }
    }
    common
}

fn apply_cli_overrides_to_config(config: &mut DotoreConfig, overrides: &CliOverrides) {
    if overrides.no_inline_disables {
        config.respect_inline_disables = false;
    }
    if overrides.custom_rules_only {
        config.custom_rules_only = true;
    }
    for tag in &overrides.ignore_tags {
        if !config.ignore.tags.contains(tag) {
            config.ignore.tags.push(tag.to_string());
        }
    }
}

pub(crate) fn load_disk_manifests(
    workspace_root: &Path,
    packages: &[WorkspacePackage],
    sources: &HashMap<PathBuf, String>,
) -> HashMap<PathBuf, String> {
    let mut manifests = HashMap::new();
    let mut candidate_dirs = Vec::new();
    for pkg in packages {
        if !candidate_dirs.contains(&pkg.root_dir) {
            candidate_dirs.push(pkg.root_dir.clone());
        }
    }
    if candidate_dirs.is_empty() {
        candidate_dirs.push(workspace_root.to_path_buf());
    }
    for dir in candidate_dirs {
        for name in [
            "package.json",
            "tsconfig.json",
            "tsconfig.base.json",
            "tsconfig.app.json",
            "jsconfig.json",
            "app.json",
            "app.config.json",
            "babel.config.json",
            ".babelrc",
            ".babelrc.json",
            "android/app/build.gradle",
            "android/app/build.gradle.kts",
            ".gitignore",
            "Cargo.toml",
            "Cargo.lock",
            ".cargo/config.toml",
            ".cargo/config",
            "bun.lockb",
            "bun.lock",
            ".env.local",
            ".env.development.local",
            ".env.production.local",
            ".env.test.local",
            "pnpm-workspace.yaml",
            "pnpm-lock.yaml",
            "package-lock.json",
            "yarn.lock",
            "node_modules/next/package.json",
            "node_modules/react-server-dom-webpack/package.json",
            "node_modules/react-server-dom-parcel/package.json",
            "node_modules/react-server-dom-turbopack/package.json",
        ] {
            let p = if dir == Path::new(".") {
                PathBuf::from(name)
            } else {
                dir.join(name)
            };
            if let Ok(content) = fs::read_to_string(&p) {
                manifests.insert(p, content);
            }
        }
    }
    for (path, content) in sources {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".config.") || n.contains(".setup."))
        {
            manifests.insert(path.clone(), content.clone());
        }
    }
    manifests
}
