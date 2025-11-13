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
/// Surgical auto-fixer for `Autofix`-tier diagnostics.
pub(crate) mod fixer;
/// Cross-file JSX caller index and multi-effect **Render Cascade** solver.
pub(crate) mod graph;
/// React **Subject**, **State Slot**, **Effect Node**, and **Caller Site** IR.
pub(crate) mod ir;
/// Terminal and JSON reporters.
pub(crate) mod report;
/// Diagnostic rules engine over `SubjectIr` and `ProjectGraph`.
pub(crate) mod rules;
/// Native Chrome DevTools Protocol (CDP) runtime profiler (`dotore scan`).
pub(crate) mod runtime_scan;
/// Parallel gitignore-aware file discovery.
pub(crate) mod scanner;

pub use config::{
    Capability, CapabilityGate, CapabilityPredicate, DotoreConfig, IgnoreConfig, IgnoreOverride,
    PackageRole, WorkspacePackage, discover_workspace_packages, load_config_from_dir,
    resolve_package_for_file,
};
pub use fixer::{FileFixResult, apply_autofixes, apply_patches_to_source};
pub use graph::ResolvedCallerSite;
pub use ir::{
    ByteSpan, FileIr, SecuritySinkKind, SourceLoc, SymbolKind, SymbolOutline,
    inspect_file_semantic, parse_file_ir,
};
pub use report::{
    JsonReport, ReportSummary, format_fix_report, format_terminal_report, render_html_report,
    write_and_open_html_report,
};
pub use rules::{
    AutofixPatch, ByteEdit, ContextualOwnerPolicy, Diagnostic, PrescriptionTier, RuleCategory,
    RuleId, RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, rule_registry,
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

use config::content_enables_react_compiler;
use graph::ProjectGraph;
use report::build_report;
use rules::{evaluate_file_in_package, evaluate_project, evaluate_project_with_packages};
use scanner::collect_source_files;

/// Options for scanning a project or file list.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Paths (files or directories) to analyze. Empty defaults to `"."`.
    pub paths: Vec<PathBuf>,
    /// Whether to include `.test.*` / `.spec.*` files when walking directories.
    pub include_tests: bool,
    /// Optional filter of enabled [`RuleId`]s (`None` enables all rules matching the **Capability Gate** and config).
    pub rules: Option<Vec<RuleId>>,
    /// Optional filter of [`PrescriptionTier`]s (`None` includes all tiers).
    pub tiers: Option<Vec<PrescriptionTier>>,
}

/// CLI-level configuration overrides that take precedence over `dotore.config.*` and `package.json#dotore`.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// Bypass inline suppression comments (`--no-inline-disables`).
    pub no_inline_disables: bool,
    /// Disable rules originally ported from external plugins unless explicitly enabled (`--custom-rules-only`).
    pub custom_rules_only: bool,
    /// Additional rule tags to ignore (`--ignore-tag`).
    pub ignore_tags: Vec<String>,
    /// Optional explicit path to a `dotore.config.*` file (`--config`).
    pub config_path: Option<PathBuf>,
}

/// Analyzes a single in-memory source file and returns its [`Diagnostic`]s.
#[must_use]
pub fn analyze_source(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let file_ir = parse_file_ir(path, source);
    let graph = ProjectGraph::build(vec![file_ir]);
    evaluate_project(&graph, enabled_rules)
}

/// Analyzes a single in-memory source file under an explicit [`DotoreConfig`] and [`CapabilityGate`].
#[must_use]
pub fn analyze_source_with_config(
    path: &Path,
    source: &str,
    config: &DotoreConfig,
    gate: &CapabilityGate,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let file_ir = parse_file_ir(path, source);
    let graph = ProjectGraph::build(vec![file_ir]);
    let mut diagnostics = Vec::new();
    let pkg_root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Some(first_file) = graph.files.first() {
        evaluate_file_in_package(
            &graph,
            first_file,
            pkg_root,
            gate,
            config,
            enabled_rules,
            &mut diagnostics,
        );
    }
    diagnostics
}

/// Analyzes multiple in-memory `(PathBuf, String)` files with full cross-file [`ProjectGraph`] resolution.
///
/// If `files` includes virtual `package.json` or `dotore.config.*` entries, nested packages,
/// per-package **Capability Gates**, and user configuration are automatically inferred in memory.
#[must_use]
pub fn analyze_project_sources(
    files: Vec<(PathBuf, String)>,
    enabled_rules: Option<&[RuleId]>,
) -> JsonReport {
    let has_virtual_manifests = files.iter().any(|(p, _)| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name == "package.json" || name.starts_with("dotore.config."))
    });

    if !has_virtual_manifests {
        let file_irs: Vec<_> = files
            .into_par_iter()
            .map(|(path, source)| parse_file_ir(&path, &source))
            .collect();
        let graph = ProjectGraph::build(file_irs);
        let diagnostics = evaluate_project(&graph, enabled_rules);
        return build_report(&graph, diagnostics);
    }

    let (packages, source_files) = extract_virtual_workspace_packages(files);
    let filtered_sources: Vec<(PathBuf, String)> = source_files
        .into_iter()
        .filter(|(path, _)| {
            resolve_package_for_file(path, &packages)
                .is_none_or(|pkg| !pkg.config.is_file_ignored(path, &pkg.root_dir))
        })
        .collect();

    let file_irs: Vec<_> = filtered_sources
        .into_par_iter()
        .map(|(path, source)| parse_file_ir(&path, &source))
        .collect();
    let graph = ProjectGraph::build(file_irs);
    let diagnostics = evaluate_project_with_packages(&graph, &packages, enabled_rules);
    build_report(&graph, diagnostics)
}

fn extract_virtual_workspace_packages(
    files: Vec<(PathBuf, String)>,
) -> (Vec<WorkspacePackage>, Vec<(PathBuf, String)>) {
    let mut pkg_jsons: Vec<(PathBuf, String)> = Vec::new();
    let mut config_files: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut compiler_configs: Vec<(PathBuf, String)> = Vec::new();
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

        if file_name == "package.json" {
            pkg_jsons.push((parent_dir, content));
        } else if file_name.starts_with("dotore.config.") {
            config_files.push((parent_dir, path, content));
        } else if is_compiler_config_filename(file_name) {
            compiler_configs.push((parent_dir, content));
        } else {
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
        let mut gate = CapabilityGate::from_package_json_str(pkg_content);
        if compiler_configs
            .iter()
            .any(|(c_dir, c_text)| c_dir == dir && content_enables_react_compiler(c_text))
        {
            gate.has_react_compiler = true;
            gate.capabilities.insert(Capability::ReactCompiler);
        }
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

    if packages.is_empty() {
        packages.push(WorkspacePackage {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: CapabilityGate::default_react(),
            config: root_config,
        });
    }

    (packages, source_files)
}

fn is_compiler_config_filename(file_name: &str) -> bool {
    file_name.starts_with("next.config.")
        || file_name.starts_with("babel.config.")
        || file_name.starts_with(".babelrc")
        || file_name.starts_with("vite.config.")
        || file_name == "app.json"
        || file_name.starts_with("app.config.")
}

/// Scans the filesystem according to [`ScanOptions`], returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files fails.
pub fn scan_workspace(options: &ScanOptions) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    scan_workspace_with_overrides(options, &CliOverrides::default())
}

/// Scans the filesystem according to [`ScanOptions`] and [`CliOverrides`], returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files or an explicit `--config` file fails.
pub fn scan_workspace_with_overrides(
    options: &ScanOptions,
    overrides: &CliOverrides,
) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    let workspace_root = determine_workspace_root(&options.paths);
    let mut packages = discover_workspace_packages(&workspace_root);

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

    let raw_paths = collect_source_files(&options.paths, options.include_tests);
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

    let file_irs: Vec<_> = pairs
        .into_par_iter()
        .map(|(path, source)| parse_file_ir(&path, &source))
        .collect();

    let graph = ProjectGraph::build(file_irs);
    let mut diagnostics =
        evaluate_project_with_packages(&graph, &packages, options.rules.as_deref());

    if let Some(allowed_tiers) = &options.tiers {
        diagnostics.retain(|d| allowed_tiers.contains(&d.tier));
    }

    Ok((build_report(&graph, diagnostics), sources))
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
