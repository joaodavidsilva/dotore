//! Pure-Rust React and TypeScript static analyzer, deterministic auto-fixer,
//! and visual **Render Cascade** remediation engine.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

use rayon::prelude::*;

/// Project configuration loader (`dotore.config.*` / `package.json#dotore`) and **Capability Gate**.
pub(crate) mod config;
/// Git diff scopes (`--scope`, `--base`, `--staged`), **Contextual Owner** filtering, and `--baseline` multiset comparison.
pub(crate) mod diff;
/// Surgical auto-fixer for `Autofix`-tier diagnostics.
pub(crate) mod fixer;
/// Deterministic **Root-Cause Grouping**, **Blast Radius**, **Fix Capsules**, and `dotore plan` generator.
pub(crate) mod planner;
/// Terminal and JSON reporters.
pub(crate) mod report;
/// Native Chrome DevTools Protocol (CDP) runtime profiler (`dotore scan`).
pub(crate) mod runtime_scan;
/// Parallel gitignore-aware file discovery.
pub(crate) mod scanner;
/// Deterministic local `0..=100` Health Score and `P0`–`P3` tier calculation.
pub(crate) mod score;
/// Native fuzzy AST **Symbol Outline** search (`dotore search`).
pub(crate) mod search;

pub use config::{
    Capability, CapabilityGate, CapabilityPredicate, ConfigMutation, ConfigTargetKind,
    DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole, SupplyChainConfig,
    WorkspacePackage, discover_workspace_packages, discover_workspace_packages_with_analyzers,
    load_config_from_dir, mutate_config_in_dir, resolve_package_for_file,
};
pub use diff::{
    BaselineDeltaResult, BaselineDiagnosticEntry, BaselineSummary, BlockingLevel,
    ChangedFileLineRanges, ContextualSpanProvider, DiffScope, GitDiffInfo, ScanMode,
    compare_baseline_diagnostics, compute_diagnostic_fingerprint, compute_diagnostic_id,
    compute_structural_fingerprint, diagnostic_intersects_changed_lines,
    filter_diagnostics_by_scope, normalize_ast_tokens, parse_baseline_report_str,
    parse_changed_line_ranges, resolve_scan_exit_code, validate_git_revision,
    validate_warning_exit_code,
};
pub use dotore_core::{
    CliOverrides, ScanOptions,
    ir::{
        BlockDisableRange, ByteSpan, ContextualOwnerSpansIr, ExtractedFile, FileContext,
        FileSuppressions, LanguageAnalyzer, LanguageId, LineDisableDirective, OpenerLineRange,
        PackageAnalysisResult, RelatedHookOwnerSpanIr, SourceLoc, SubjectEffectOwner, SymbolKind,
        SymbolOutline, classify_file_context, compute_line_starts, loc_from_line_starts,
    },
    rules::{
        AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
        FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
        RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry,
    },
};
pub use dotore_js::{
    CallerSite, DepRef, DepsSpec, EffectNode, FileIr, JsLanguageAnalyzer, JsxElementIr,
    ProjectGraph, ResolvedCallerSite, SecuritySinkKind, SetterCallSite, SubjectIr, SubjectKind,
    inspect_file_semantic, is_compiler_config_filename, parse_file_ir, supply_chain_purl_hash,
};
pub use dotore_py::{PyFileIr, PyLanguageAnalyzer};
pub use dotore_rs::{RsFileIr, RsLanguageAnalyzer, RsSubjectIr, RsSubjectKind};
pub use fixer::{
    FileFixResult, apply_autofixes, apply_autofixes_with_analyzers, apply_autofixes_with_validator,
    apply_patches_to_source, apply_patches_to_source_with_analyzers,
    apply_patches_to_source_with_validator,
};
pub use planner::{
    PlanResult, PlannerContext, build_fix_capsule, build_root_cause_groups_and_capsules,
    compute_root_cause_group_id, format_plan_report, plan_project,
};
pub use report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, ProjectCoverageMetadata, ReportSummary,
    RuleCatalogEntry, RulesListOptions, WhyEntry, WhyLocation, WhyReport, build_extracted_report,
    build_extracted_report_with_packages, build_report, build_report_with_packages,
    build_rule_catalog, ci_config, ci_install, ci_upgrade, explain_location,
    explain_location_with_analyzers, explain_rule, format_design_report, format_fix_report,
    format_install_report, format_rule_catalog_text, format_rule_explanation_text,
    format_terminal_report, format_why_report_text, install_dotore, parse_why_location,
    render_html_report, write_and_open_html_report, write_json_report,
};
pub use runtime_scan::{
    BuildRuntimeScanReportInput, ComponentEventSource, LocalUrlSuggestion,
    RUNTIME_SCAN_INTERACTION_DURATION_THRESHOLD_MS, RUNTIME_SCAN_LAYOUT_THRASH_RATIO,
    RUNTIME_SCAN_LOCAL_DEV_PORTS, RUNTIME_SCAN_MAX_COMPONENT_EVENTS,
    RUNTIME_SCAN_MAX_COMPONENTS_PER_COMMIT, RUNTIME_SCAN_MAX_DOCUMENT_SNAPSHOTS,
    RUNTIME_SCAN_MAX_HOTSPOTS, RUNTIME_SCAN_MAX_INTERACTIONS, RUNTIME_SCAN_MAX_LOAF_ENTRIES,
    RUNTIME_SCAN_MAX_RECORDING_DURATION_MS, RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF,
    RUNTIME_SCAN_MAX_SNAPSHOT_BYTES, RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES,
    RUNTIME_SCAN_MAX_STRING_LENGTH, RUNTIME_SCAN_MAX_TRACE_BYTES,
    RUNTIME_SCAN_MIN_COMPONENT_DURATION_MS, RUNTIME_SCAN_SAFE_CDP_PAGE_URLS,
    RUNTIME_SCAN_SCHEMA_VERSION, RUNTIME_SCAN_SNAPSHOT_ENVELOPE_RESERVE_BYTES,
    RUNTIME_SCAN_TRACE_CATEGORIES, RUNTIME_SCAN_TRACE_FILE_MODE,
    RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS, RUNTIME_SCAN_UNKNOWN_SOURCE_CHAR_POSITION,
    ReactBuildType, RecordRuntimeTraceInput, RecordRuntimeTraceResult, RuntimeScanComponentEvent,
    RuntimeScanComponentHotspot, RuntimeScanConnection, RuntimeScanFormat, RuntimeScanInteraction,
    RuntimeScanLongAnimationFrame, RuntimeScanProbeSnapshot, RuntimeScanProbeSupport,
    RuntimeScanReport, RuntimeScanScriptHotspot, RuntimeScanScriptTiming, RuntimeScanSummary,
    assert_cdp_profile_uncontaminated, build_runtime_scan_report, detect_local_runtime_urls,
    format_runtime_scan_error_report, format_runtime_scan_report, is_runtime_scan_probe_snapshot,
    merge_probe_snapshots, parse_runtime_scan_snapshot_payload, prompt_runtime_scan_url_with_io,
    record_runtime_trace, resolve_runtime_scan_format, resolve_runtime_trace_path,
    sanitize_runtime_text, sanitize_runtime_url,
};
pub use score::{HealthScore, compute_local_health_score, score_label};
pub use search::{
    SearchJsonLocation, SearchJsonReport, SearchJsonResult, SearchOptions, SymbolSearchResult,
    format_search_json, format_search_text, score_fuzzy, search_extracted_files,
    search_project_sources, search_project_sources_with, search_project_sources_with_analyzers,
    search_symbols, search_symbols_with, search_symbols_with_analyzers, should_highlight_search,
    should_highlight_stdout,
};

use diff::{collect_git_diff, load_baseline_entries};
use dotore_core::scanner::collect_source_files_for_analyzers;
use dotore_js::{
    enrich_cross_file_autofixes, evaluate_file_in_package, evaluate_project_with_packages,
};
use scanner::collect_style_files;

/// Analyzes a single in-memory source file through [`JsLanguageAnalyzer`] and returns its [`Diagnostic`]s.
#[must_use]
pub fn analyze_source(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    if RsLanguageAnalyzer.supports_path(path) {
        return dotore_rs::analyze_rs_source(path, source, enabled_rules);
    }
    let py = PyLanguageAnalyzer::new();
    if py.supports_path(path) {
        let pkg_root = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let pkg = WorkspacePackage {
            name: "root".to_string(),
            root_dir: pkg_root.to_path_buf(),
            capability_gate: CapabilityGate::default_python(),
            config: DotoreConfig::default(),
        };
        let extracted = py.extract_file(path, source);
        return py
            .analyze_package(&pkg, &[extracted], enabled_rules)
            .diagnostics;
    }
    let analyzer = JsLanguageAnalyzer;
    let extracted = analyzer.extract_file(path, source);
    let capability_gate = if is_standalone_angular_source(path, source) {
        CapabilityGate::default_angular()
    } else {
        CapabilityGate::default_react()
    };
    let default_pkg = WorkspacePackage {
        name: "default".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate,
        config: DotoreConfig::default(),
    };
    analyzer
        .analyze_package(&default_pkg, &[extracted], enabled_rules)
        .diagnostics
}

fn is_standalone_angular_source(path: &Path, source: &str) -> bool {
    if source.contains("from 'react'") || source.contains("from \"react\"") {
        return false;
    }
    let path_str = path.to_string_lossy();
    source.contains("@angular/")
        || source.contains("@Component(")
        || source.contains("@Directive(")
        || source.contains("@Injectable(")
        || path_str.ends_with(".component.ts")
        || path_str.ends_with(".directive.ts")
        || path_str.ends_with(".service.ts")
        || path_str.ends_with(".component.html")
        || (matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("html" | "htm")
        ) && source.contains("@for"))
}

/// Analyzes a single in-memory source file under an explicit [`DotoreConfig`] and [`CapabilityGate`]
/// through [`JsLanguageAnalyzer`].
#[must_use]
pub fn analyze_source_with_config(
    path: &Path,
    source: &str,
    config: &DotoreConfig,
    gate: &CapabilityGate,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    if RsLanguageAnalyzer.supports_path(path) {
        return dotore_rs::analyze_rs_source_with_config(path, source, config, gate, enabled_rules);
    }
    let py = PyLanguageAnalyzer::new();
    if py.supports_path(path) {
        let pkg_root = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let pkg = WorkspacePackage {
            name: "root".to_string(),
            root_dir: pkg_root.to_path_buf(),
            capability_gate: gate.clone(),
            config: config.clone(),
        };
        let extracted = py.extract_file(path, source);
        return py
            .analyze_package(&pkg, &[extracted], enabled_rules)
            .diagnostics;
    }
    let analyzer = JsLanguageAnalyzer;
    let extracted = analyzer.extract_file(path, source);
    let pkg_root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    analyzer.analyze_single_file(&extracted, pkg_root, gate, config, enabled_rules)
}

/// Analyzes multiple in-memory `(PathBuf, String)` files with full cross-file [`ProjectGraph`] resolution
/// dispatched through [`JsLanguageAnalyzer`].
///
/// If `files` includes virtual `package.json` or `dotore.config.*` entries, nested packages,
/// per-package **Capability Gates**, and user configuration are automatically inferred in memory.
#[must_use]
pub fn analyze_project_sources(
    files: Vec<(PathBuf, String)>,
    enabled_rules: Option<&[RuleId]>,
) -> JsonReport {
    let py = PyLanguageAnalyzer::new();
    let has_python_inputs = files.iter().any(|(p, _)| {
        py.supports_path(p)
            || p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "pyproject.toml" || n == "requirements.txt")
    });
    if has_python_inputs {
        return analyze_project_sources_with_python(files, enabled_rules);
    }

    let js_analyzer = JsLanguageAnalyzer;
    let has_rs_files = files
        .iter()
        .any(|(p, _)| RsLanguageAnalyzer.supports_path(p));
    let has_virtual_manifests = files.iter().any(|(p, _)| {
        p.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            name == "package.json"
                || name == "angular.json"
                || name == "Cargo.toml"
                || name == "tsconfig.json"
                || name == "jsconfig.json"
                || name == "pnpm-workspace.yaml"
                || name == "pnpm-lock.yaml"
                || name == "package-lock.json"
                || name == "yarn.lock"
                || (name.starts_with("tsconfig.") && name.ends_with(".json"))
                || name.starts_with("dotore.config.")
        })
    });

    if !has_virtual_manifests && !has_rs_files {
        let sources: HashMap<PathBuf, String> = files.iter().cloned().collect();
        let extracted_files: Vec<ExtractedFile> = files
            .into_par_iter()
            .map(|(path, source)| js_analyzer.extract_file(&path, &source))
            .collect();
        let default_pkg = WorkspacePackage {
            name: "default".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: CapabilityGate::default_react(),
            config: DotoreConfig::default(),
        };
        let pkg_result =
            js_analyzer.analyze_package(&default_pkg, &extracted_files, enabled_rules);
        let graph = js_analyzer.build_graph_from_extracted(&extracted_files, HashMap::new());
        return build_report(&graph, pkg_result.diagnostics, &sources);
    }

    let split = extract_virtual_workspace_packages(&js_analyzer, files);
    let packages = split.packages;
    let manifests = split.manifests;
    let filtered_sources: Vec<(PathBuf, String)> = split
        .source_files
        .into_iter()
        .filter(|(path, _)| {
            resolve_package_for_file(path, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(path, &pkg.root_dir))
        })
        .collect();
    let sources: HashMap<PathBuf, String> = filtered_sources.iter().cloned().collect();

    let (rs_sources, js_sources): (Vec<_>, Vec<_>) = filtered_sources
        .into_iter()
        .partition(|(path, _)| RsLanguageAnalyzer.supports_path(path));

    if js_sources.is_empty() && !rs_sources.is_empty() {
        let extracted_rs: Vec<ExtractedFile> = rs_sources
            .into_par_iter()
            .map(|(path, source)| RsLanguageAnalyzer.extract_file(&path, &source))
            .collect();
        let mut diagnostics = Vec::new();
        for extracted in &extracted_rs {
            if let Some(pkg) = resolve_package_for_file(&extracted.path, &packages) {
                dotore_rs::evaluate_rs_file(
                    extracted,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                    enabled_rules,
                    &mut diagnostics,
                );
            }
        }
        return build_extracted_report_with_packages(&extracted_rs, diagnostics, &sources, &packages);
    }

    let extracted_files: Vec<ExtractedFile> = js_sources
        .into_par_iter()
        .map(|(path, source)| js_analyzer.extract_file(&path, &source))
        .collect();
    let graph = js_analyzer.build_graph_from_extracted(&extracted_files, manifests);
    let mut diagnostics = evaluate_project_with_packages(&graph, &packages, enabled_rules);
    if !rs_sources.is_empty() {
        let extracted_rs: Vec<ExtractedFile> = rs_sources
            .into_par_iter()
            .map(|(path, source)| RsLanguageAnalyzer.extract_file(&path, &source))
            .collect();
        for extracted in &extracted_rs {
            if let Some(pkg) = resolve_package_for_file(&extracted.path, &packages) {
                dotore_rs::evaluate_rs_file(
                    extracted,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                    enabled_rules,
                    &mut diagnostics,
                );
            }
        }
    }
    build_report_with_packages(&graph, diagnostics, &sources, &packages)
}

fn analyze_project_sources_with_python(
    files: Vec<(PathBuf, String)>,
    enabled_rules: Option<&[RuleId]>,
) -> JsonReport {
    let py = PyLanguageAnalyzer::new();
    let mut py_manifests: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut remaining_files: Vec<(PathBuf, String)> = Vec::new();

    for (path, content) in files {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if file_name == "pyproject.toml" || file_name == "requirements.txt" {
            let parent_dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            py_manifests.push((parent_dir, path, content));
        } else {
            remaining_files.push((path, content));
        }
    }

    let js_analyzer = JsLanguageAnalyzer;
    let mut split = extract_virtual_workspace_packages(&js_analyzer, remaining_files);
    if py_manifests.is_empty() {
        for pkg in &mut split.packages {
            let py_default = CapabilityGate::default_python();
            pkg.capability_gate.merge(&py_default);
        }
    } else {
        // Group Python manifests by package directory
        let mut py_dirs: Vec<PathBuf> = Vec::new();
        for (dir, _, _) in &py_manifests {
            if !py_dirs.contains(dir) {
                py_dirs.push(dir.clone());
            }
        }
        // If split only created a synthetic default root package and no package.json/Cargo.toml existed, replace or update it
        let had_real_js_or_rs_pkg = split.manifests.keys().any(|k| {
            k.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "package.json" || n == "Cargo.toml")
        });
        if !had_real_js_or_rs_pkg {
            let default_cfg = split
                .packages
                .first()
                .map(|p| p.config.clone())
                .unwrap_or_default();
            split.packages.clear();
            for dir in py_dirs {
                let dir_manifests: Vec<(PathBuf, &str)> = py_manifests
                    .iter()
                    .filter(|(d, _, _)| d == &dir)
                    .map(|(_, p, c)| (p.clone(), c.as_str()))
                    .collect();
                let gate = py.infer_capability_gate(&dir, &dir_manifests);
                let name = dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("root")
                    .to_string();
                split.packages.push(WorkspacePackage {
                    name,
                    root_dir: dir,
                    capability_gate: gate,
                    config: default_cfg.clone(),
                });
            }
        } else {
            for dir in py_dirs {
                let dir_manifests: Vec<(PathBuf, &str)> = py_manifests
                    .iter()
                    .filter(|(d, _, _)| d == &dir)
                    .map(|(_, p, c)| (p.clone(), c.as_str()))
                    .collect();
                let py_gate = py.infer_capability_gate(&dir, &dir_manifests);
                if let Some(existing) = split.packages.iter_mut().find(|p| p.root_dir == dir) {
                    existing.capability_gate.merge(&py_gate);
                } else {
                    let name = dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("root")
                        .to_string();
                    split.packages.push(WorkspacePackage {
                        name,
                        root_dir: dir,
                        capability_gate: py_gate,
                        config: DotoreConfig::default(),
                    });
                }
            }
        }
    }

    let packages = split.packages;
    let filtered_sources: Vec<(PathBuf, String)> = split
        .source_files
        .into_iter()
        .filter(|(path, _)| {
            resolve_package_for_file(path, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(path, &pkg.root_dir))
        })
        .collect();
    let sources: HashMap<PathBuf, String> = filtered_sources.iter().cloned().collect();

    let (py_pairs, non_py_pairs): (Vec<_>, Vec<_>) = filtered_sources
        .into_iter()
        .partition(|(path, _)| py.supports_path(path));
    let (rs_pairs, js_pairs): (Vec<_>, Vec<_>) = non_py_pairs
        .into_iter()
        .partition(|(path, _)| RsLanguageAnalyzer.supports_path(path));

    let mut py_and_rs_extracted: Vec<ExtractedFile> = py_pairs
        .into_par_iter()
        .map(|(path, source)| py.extract_file(&path, &source))
        .collect();

    let mut diagnostics = Vec::new();
    for pkg in &packages {
        let pkg_files: Vec<ExtractedFile> = py_and_rs_extracted
            .iter()
            .filter(|f| {
                resolve_package_for_file(&f.path, &packages)
                    .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
            })
            .map(clone_extracted_file_with_py_ir)
            .collect();
        if !pkg_files.is_empty() {
            let res = py.analyze_package(pkg, &pkg_files, enabled_rules);
            diagnostics.extend(res.diagnostics);
        }
    }
    if !rs_pairs.is_empty() {
        let rs_extracted: Vec<ExtractedFile> = rs_pairs
            .into_par_iter()
            .map(|(path, source)| RsLanguageAnalyzer.extract_file(&path, &source))
            .collect();
        for extracted in &rs_extracted {
            if let Some(pkg) = resolve_package_for_file(&extracted.path, &packages) {
                dotore_rs::evaluate_rs_file(
                    extracted,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                    enabled_rules,
                    &mut diagnostics,
                );
            }
        }
        py_and_rs_extracted.extend(rs_extracted);
    }

    if js_pairs.is_empty() {
        return build_extracted_report_with_packages(
            &py_and_rs_extracted,
            diagnostics,
            &sources,
            &packages,
        );
    }

    let mut all_extracted: Vec<ExtractedFile> = js_pairs
        .into_par_iter()
        .map(|(path, source)| js_analyzer.extract_file(&path, &source))
        .collect();
    let graph = js_analyzer.build_graph_from_extracted(&all_extracted, split.manifests);
    let js_diags = evaluate_project_with_packages(&graph, &packages, enabled_rules);
    diagnostics.extend(js_diags);

    all_extracted.extend(py_and_rs_extracted);
    build_extracted_report_with_packages(&all_extracted, diagnostics, &sources, &packages)
}

fn clone_extracted_file_with_py_ir(file: &ExtractedFile) -> ExtractedFile {
    let mut cloned =
        ExtractedFile::new(file.path.clone(), file.source.clone(), file.language_id);
    cloned.file_context = file.file_context;
    cloned.symbol_outlines.clone_from(&file.symbol_outlines);
    cloned
        .contextual_owner_spans
        .clone_from(&file.contextual_owner_spans);
    cloned.suppressions.clone_from(&file.suppressions);
    cloned.subjects_count = file.subjects_count;
    cloned.effects_count = file.effects_count;
    cloned.subject_spans.clone_from(&file.subject_spans);
    if let Some(ir) = file.downcast_payload::<PyFileIr>() {
        cloned = cloned.with_payload(ir.clone());
    }
    cloned
}

struct VirtualWorkspaceSplit {
    packages: Vec<WorkspacePackage>,
    manifests: HashMap<PathBuf, String>,
    source_files: Vec<(PathBuf, String)>,
}

fn extract_virtual_workspace_packages(
    js_analyzer: &JsLanguageAnalyzer,
    files: Vec<(PathBuf, String)>,
) -> VirtualWorkspaceSplit {
    let mut pkg_jsons: Vec<(PathBuf, String)> = Vec::new();
    let mut angular_jsons: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut cargo_tomls: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut config_files: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut compiler_configs: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut manifests: HashMap<PathBuf, String> = HashMap::new();
    let mut source_files: Vec<(PathBuf, String)> = Vec::new();
    for (path, content) in files {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let parent_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let is_in_node_modules = path
            .to_string_lossy()
            .replace('\\', "/")
            .contains("node_modules/");
        if file_name == "package.json" {
            manifests.insert(path, content.clone());
            if !is_in_node_modules {
                pkg_jsons.push((parent_dir, content));
            }
        } else if file_name == "angular.json" {
            if !is_in_node_modules {
                angular_jsons.push((parent_dir, path.clone(), content.clone()));
            }
            manifests.insert(path, content);
        } else if file_name == "Cargo.toml" {
            manifests.insert(path.clone(), content.clone());
            cargo_tomls.push((parent_dir, path, content));
        } else if is_non_js_manifest_filename(file_name) {
            if is_compiler_config_filename(file_name) {
                compiler_configs.push((parent_dir, path.clone(), content.clone()));
            }
            manifests.insert(path, content);
        } else if file_name.starts_with("dotore.config.") {
            config_files.push((parent_dir, path, content));
        } else {
            if is_compiler_config_filename(file_name) {
                compiler_configs.push((parent_dir, path.clone(), content.clone()));
            }
            manifests.insert(path.clone(), content.clone());
            source_files.push((path, content));
        }
    }
    let root_config = config_files
        .iter()
        .find(|(dir, _, _)| dir == Path::new("."))
        .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
        .or_else(|| {
            pkg_jsons
                .iter()
                .find(|(dir, _)| dir == Path::new("."))
                .and_then(|(_, c)| DotoreConfig::from_package_json_str(c))
        })
        .or_else(|| {
            config_files
                .first()
                .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
        })
        .unwrap_or_default();

    let mut packages = Vec::new();
    for (dir, pkg_content) in &pkg_jsons {
        let mut dir_manifest_sources: Vec<(PathBuf, &str)> =
            vec![(dir.join("package.json"), pkg_content.as_str())];
        for (ng_dir, ng_path, ng_text) in &angular_jsons {
            if ng_dir == dir || ng_dir == Path::new(".") {
                dir_manifest_sources.push((ng_path.clone(), ng_text.as_str()));
            }
        }
        for (c_dir, c_path, c_text) in &compiler_configs {
            if c_dir == dir {
                dir_manifest_sources.push((c_path.clone(), c_text.as_str()));
            }
        }
        let gate = js_analyzer.infer_capability_gate(dir, &dir_manifest_sources);
        let local_cfg = config_files
            .iter()
            .find(|(c_dir, _, _)| c_dir == dir)
            .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
            .or_else(|| DotoreConfig::from_package_json_str(pkg_content))
            .unwrap_or_else(|| root_config.clone());

        let name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string();
        packages.push(WorkspacePackage {
            name,
            root_dir: dir.clone(),
            capability_gate: gate,
            config: local_cfg,
        });
    }
    for (dir, cargo_path, cargo_content) in &cargo_tomls {
        let rs_gate = RsLanguageAnalyzer
            .infer_capability_gate(dir, &[(cargo_path.clone(), cargo_content.as_str())]);
        if let Some(existing) = packages.iter_mut().find(|p| &p.root_dir == dir) {
            existing.capability_gate.merge(&rs_gate);
        } else {
            let local_cfg = config_files
                .iter()
                .find(|(c_dir, _, _)| c_dir == dir)
                .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
                .unwrap_or_else(|| root_config.clone());
            let name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("root")
                .to_string();
            packages.push(WorkspacePackage {
                name,
                root_dir: dir.clone(),
                capability_gate: rs_gate,
                config: local_cfg,
            });
        }
    }

    for (ng_dir, ng_path, ng_text) in &angular_jsons {
        if packages.iter().any(|p| &p.root_dir == ng_dir) {
            continue;
        }
        let dir_manifest_sources: Vec<(PathBuf, &str)> =
            vec![(ng_path.clone(), ng_text.as_str())];
        let gate = js_analyzer.infer_capability_gate(ng_dir, &dir_manifest_sources);
        let local_cfg = config_files
            .iter()
            .find(|(c_dir, _, _)| c_dir == ng_dir)
            .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
            .unwrap_or_else(|| root_config.clone());
        let name = ng_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string();
        packages.push(WorkspacePackage {
            name,
            root_dir: ng_dir.clone(),
            capability_gate: gate,
            config: local_cfg,
        });
    }

    if packages.is_empty() {
        let mut default_gate = CapabilityGate::default_react();
        if source_files
            .iter()
            .any(|(p, _)| RsLanguageAnalyzer.supports_path(p))
        {
            default_gate.merge(&CapabilityGate::default_rust());
        }
        packages.push(WorkspacePackage {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: default_gate,
            config: root_config,
        });
    }

    VirtualWorkspaceSplit {
        packages,
        manifests,
        source_files,
    }
}

fn is_non_js_manifest_filename(file_name: &str) -> bool {
    file_name == "angular.json"
        || file_name == "tsconfig.json"
        || file_name == "jsconfig.json"
        || (file_name.starts_with("tsconfig.") && file_name.ends_with(".json"))
        || file_name == "app.json"
        || file_name == "app.config.json"
        || file_name == "babel.config.json"
        || file_name == ".babelrc"
        || file_name == ".babelrc.json"
        || file_name == "build.gradle"
        || file_name == "build.gradle.kts"
        || file_name == ".gitignore"
        || file_name == "pnpm-lock.yaml"
        || file_name == "yarn.lock"
        || file_name == "package-lock.json"
        || file_name == "bun.lockb"
        || file_name == "bun.lock"
        || file_name == "pnpm-workspace.yaml"
        || file_name.starts_with(".env")
}

/// Scans the filesystem according to [`ScanOptions`], returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files fails.
pub fn scan_workspace(options: &ScanOptions) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    scan_workspace_with_overrides(options, &CliOverrides::default())
}

/// Scans the filesystem according to [`ScanOptions`] and [`CliOverrides`] through [`JsLanguageAnalyzer`],
/// returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files or an explicit `--config` file fails.
pub fn scan_workspace_with_overrides(
    options: &ScanOptions,
    overrides: &CliOverrides,
) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    let workspace_root = determine_workspace_root(&options.paths);
    let mut packages = discover_workspace_packages_with_analyzers(&workspace_root, analyzers);

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
            pkg.config = cfg.clone();
        }
        apply_cli_overrides_to_config(&mut pkg.config, overrides);
    }

    let raw_paths =
        collect_source_files_for_analyzers(&options.paths, options.include_tests, analyzers);
    let paths: Vec<PathBuf> = raw_paths
        .into_iter()
        .filter(|p| {
            resolve_package_for_file(p, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(p, &pkg.root_dir))
        })
        .collect();

    let mut sources = HashMap::with_capacity(paths.len());
    let mut pairs = Vec::with_capacity(paths.len());

    for path in paths {
        if let Ok(content) = fs::read_to_string(&path) {
            sources.insert(path.clone(), content.clone());
            pairs.push((path, content));
        }
    }

    if packages
        .iter()
        .any(|pkg| pkg.capability_gate.has(Capability::Motion))
    {
        for style_path in collect_style_files(&options.paths) {
            if resolve_package_for_file(&style_path, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(&style_path, &pkg.root_dir))
                && let Ok(content) = fs::read_to_string(&style_path)
            {
                pairs.push((style_path, content));
            }
        }
    }

    let extracted_files: Vec<ExtractedFile> = pairs
        .into_par_iter()
        .map(|(path, source)| js_analyzer.extract_file(&path, &source))
        .collect();

    let manifests = load_disk_manifests(&workspace_root, &packages, &sources);
    let graph = js_analyzer.build_graph_from_extracted(&extracted_files, manifests);
    let mut diagnostics =
        evaluate_project_with_packages(&graph, &packages, options.rules.as_deref());
    enrich_cross_file_autofixes(&graph, &mut diagnostics, &sources);

    if let Some(allowed_tiers) = &options.tiers {
        diagnostics.retain(|d| allowed_tiers.contains(&d.tier));
    }

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
            &workspace_root,
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
            &extracted_files,
            &sources,
        );
        diff_info = Some(diff_snap.info);
        mode = if overrides.staged {
            ScanMode::Staged
        } else {
            ScanMode::Diff
        };
    }

    if let Some(baseline_arg) = &overrides.baseline_path {
        match load_baseline_entries(&workspace_root, baseline_arg, options.rules.as_deref()) {
            Ok(base_entries) => {
                let delta = compare_baseline_diagnostics(
                    &diagnostics,
                    &sources,
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
                        &workspace_root,
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
                        &extracted_files,
                        &sources,
                    );
                    diff_info = Some(diff_snap.info);
                }
            }
        }
    }

    let mut report = build_report_with_packages(&graph, diagnostics, &sources, &packages);
    report.mode = mode;
    report.diff = diff_info;
    report.baseline = baseline_summary;
    report.baseline_degraded = baseline_degraded;

    Ok((report, sources))
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
    let mut design_rules = design_rule_ids();
    if let Some(explicit_rules) = &options.rules {
        design_rules.retain(|r| explicit_rules.contains(r));
    }

    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    let workspace_root = determine_workspace_root(&options.paths);
    let mut packages = discover_workspace_packages_with_analyzers(&workspace_root, analyzers);

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
            pkg.config = cfg.clone();
        }
        apply_cli_overrides_to_config(&mut pkg.config, overrides);
    }

    let raw_paths =
        collect_source_files_for_analyzers(&options.paths, options.include_tests, analyzers);
    let paths: Vec<PathBuf> = raw_paths
        .into_iter()
        .filter(|p| {
            resolve_package_for_file(p, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(p, &pkg.root_dir))
        })
        .collect();

    let mut sources = HashMap::with_capacity(paths.len());
    let mut pairs = Vec::with_capacity(paths.len());
    for path in paths {
        if let Ok(content) = fs::read_to_string(&path) {
            sources.insert(path.clone(), content.clone());
            pairs.push((path, content));
        }
    }

    let extracted_files: Vec<ExtractedFile> = pairs
        .into_par_iter()
        .map(|(path, source)| js_analyzer.extract_file(&path, &source))
        .collect();

    // Build a lightweight ProjectGraph without manifests to skip supply-chain, dead-code, and cycle passes
    let graph = js_analyzer.build_graph_from_extracted(&extracted_files, HashMap::new());

    let mut diagnostics = Vec::new();
    for file in &graph.files {
        let Some(pkg) = resolve_package_for_file(&file.path, &packages) else {
            continue;
        };
        let mut design_cfg = pkg.config.clone();
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

fn determine_workspace_root(paths: &[PathBuf]) -> PathBuf {
    let Some(first) = paths.first() else {
        return PathBuf::from(".");
    };
    if first.is_dir() {
        first.clone()
    } else {
        first
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    }
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
            config.ignore.tags.push(tag.clone());
        }
    }
}

pub(crate) fn load_disk_manifests(
    workspace_root: &Path,
    packages: &[WorkspacePackage],
    sources: &HashMap<PathBuf, String>,
) -> HashMap<PathBuf, String> {
    let mut manifests = HashMap::new();
    let mut candidate_dirs = vec![workspace_root.to_path_buf()];
    for pkg in packages {
        if !candidate_dirs.contains(&pkg.root_dir) {
            candidate_dirs.push(pkg.root_dir.clone());
        }
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
