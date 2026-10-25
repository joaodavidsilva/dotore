//! Pure-Rust React, TypeScript, Angular, Python, and Rust static analyzer,
//! deterministic auto-fixer, and remediation engine.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(any(feature = "js", feature = "py", feature = "rs"))]
use rayon::prelude::*;

/// Clap command-line argument parser and subcommand execution runners.
pub(crate) mod cli;
/// Project configuration loader (`dotore.config.*` / `package.json#dotore`) and **Capability Gate**.
pub(crate) mod config;
/// Git diff scopes (`--scope`, `--base`, `--staged`), **Contextual Owner** filtering, and `--baseline` multiset comparison.
pub(crate) mod diff;
/// Surgical auto-fixer for `Autofix`-tier diagnostics.
pub(crate) mod fixer;
/// Deterministic **Root-Cause Grouping**, **Blast Radius**, **Fix Capsules**, and `dotore plan` generator.
pub(crate) mod planner;
/// Live terminal progress bar and 30fps spinner animation for workspace scans.
pub(crate) mod progress;
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
/// Interactive TUI explorer (`hjkl`/arrow navigation, dynamic filter tabs, grouping modes, `/` search, `ESC` exit).
pub(crate) mod tui;
/// In-memory virtual workspace package and manifest extraction.
pub(crate) mod virtual_workspace;
/// Disk-backed workspace scanning, scan result caching, and `dotore design` orchestration.
pub(crate) mod workspace_scan;

pub use cli::{Cli, Commands, run_cli};
pub use config::{
    ArchitectureThresholdsConfig, Capability, CapabilityGate, CapabilityPredicate, ConfigMutation,
    ConfigTargetKind, DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole,
    SupplyChainConfig, WorkspacePackage, discover_workspace_packages,
    discover_workspace_packages_with_analyzers, filter_workspace_packages, is_cache_disabled,
    load_config_from_dir, mutate_config_in_dir, resolve_dotore_home_dir, resolve_package_for_file,
    write_file_atomically,
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
        ArchitectureFileFacets, BlockDisableRange, ByteSpan, ConcernBucket, ConcernSignalSite,
        ContextualOwnerSpansIr, ExtractedFile, FileContext, FileSuppressions, HelperFingerprintIr,
        InlineTerminalUiPrimitiveSiteIr, LanguageAnalyzer, LanguageId, LineDisableDirective,
        OpenerLineRange, PackageAnalysisResult, RelatedHookOwnerSpanIr, ResolvedCallerSite,
        SourceLoc, StaticCatalogSiteIr, StructLiteralConstructionSiteIr, SubjectEffectOwner,
        SymbolKind, SymbolOutline, TerminalUiPrimitiveKind, classify_file_context,
        compute_line_starts, loc_from_line_starts,
    },
    rules::{
        AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
        FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
        RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry,
        supply_chain_purl_hash,
    },
    ui::{
        self, AsciiBox, Badge, BadgeKind, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH,
        FilterTabBar, FilterTabItem, FlowDiagram, GaugeBar, StatusBar, TuiFilterKind,
        build_filter_tabs, classify_style_bucket, strip_ansi_codes, style_bucket_color,
        truncate_ansi_to_width, visible_char_width,
    },
};
#[cfg(feature = "js")]
pub use dotore_js::{
    CallerSite, DepRef, DepsSpec, EffectNode, FileIr, JsLanguageAnalyzer, JsxElementIr,
    ProjectGraph, SecuritySinkKind, SetterCallSite, SubjectIr, SubjectKind, inspect_file_semantic,
    is_compiler_config_filename, parse_file_ir,
};
#[cfg(feature = "py")]
pub use dotore_py::{PyFileIr, PyLanguageAnalyzer};
#[cfg(feature = "rs")]
pub use dotore_rs::{RsFileIr, RsLanguageAnalyzer, RsSubjectIr, RsSubjectKind};
pub use fixer::{
    FileFixResult, apply_autofixes, apply_autofixes_with_analyzers, apply_autofixes_with_validator,
    apply_patches_to_source, apply_patches_to_source_with_analyzers,
    apply_patches_to_source_with_validator,
};
pub use planner::{
    DiagnosticsBundle, HandoffTarget, MIGRATION_BUCKET_MIN_FILES, MigrationRuleBucket, PlanResult,
    PlannerContext, build_agent_handoff_prompt, build_fix_capsule,
    build_root_cause_groups_and_capsules, compute_root_cause_group_id, copy_to_clipboard,
    detect_available_coding_agents, detect_migration_rule_buckets, excerpt_from_span,
    execute_handoff, filter_report_for_diagnostics, format_plan_report,
    load_preferred_handoff_target, plan_project, render_rule_bundle_summary_text,
    resolve_agent_binary_path, save_preferred_handoff_target, write_diagnostics_bundle,
};
pub use progress::{
    LiveScanProgressSnapshot, LiveSpinner, SPINNER_FRAMES, current_scan_progress,
    format_spinner_frame, format_spinner_frame_with_width, set_progress_phase, tick_discovery_file,
    tick_progress_file,
};
pub use report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, MAX_SCAN_CACHE_ENTRIES, PR_COMMENT_MARKER,
    PrCommentEnv, PrCommentRepoContext, ProjectCoverageMetadata, ReportSummary, RuleCatalogEntry,
    RulesListOptions, SCAN_CACHE_SCHEMA_VERSION, ScanCacheEntry, ScanResultCacheFile, WhyEntry,
    build_extracted_report, build_extracted_report_with_packages,
    build_report_from_planner_context, build_rule_catalog, ci_config, ci_install, ci_upgrade,
    explain_location, explain_location_with_analyzers, explain_rule,
    format_architecture_signal_explanation, format_design_report, format_design_report_pretty,
    format_fix_report, format_install_report, format_rule_catalog_text,
    format_rule_explanation_text, format_terminal_report, format_terminal_report_pretty,
    format_why_report_text, generate_ci_comment, install_dotore, load_scan_result_cache,
    lookup_scan_cache, mask_credentials, parse_why_location, read_json_report, render_ci_workflow,
    render_code_frame, render_github_actions_workflow, render_github_pr_comment,
    render_github_pr_comment_from_env, render_gitlab_ci_snippet, render_html_report,
    render_pr_comment_markdown, render_pr_comment_markdown_with_env, resolve_scan_cache_path,
    store_scan_cache, write_and_open_html_report, write_github_pr_comment, write_json_report,
};
#[cfg(feature = "js")]
pub use report::{build_report, build_report_with_packages};
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
    CachedFileSymbols, SYMBOL_INDEX_SCHEMA_VERSION, SearchJsonLocation, SearchJsonReport,
    SearchJsonResult, SearchOptions, SymbolIndexCache, SymbolSearchResult, format_search_json,
    format_search_text, load_symbol_index_cache, resolve_symbol_cache_path,
    save_symbol_index_cache, score_fuzzy, search_extracted_files, search_project_sources,
    search_project_sources_with, search_project_sources_with_analyzers, search_symbols,
    search_symbols_with, search_symbols_with_analyzers, search_symbols_with_analyzers_and_cache,
    search_symbols_with_cache, search_symbols_with_extractor_and_cache, should_highlight_search,
    should_highlight_stdout,
};
pub use tui::{
    FilteredPackageRow, TuiFilterTab, TuiGroupMode, TuiPackageItem, TuiState, build_score_gauge,
    diagnostic_matches_tab_and_search, draw_tui_frame, handle_tui_picker_key,
    handle_tui_search_key, highlight_fuzzy_matches, render_package_picker_lines,
    render_tui_body_lines, render_tui_body_lines_for_width, render_tui_frame,
    render_tui_frame_with_state, run_interactive_tui, should_launch_tui,
};
pub use workspace_scan::{
    design_rule_ids, scan_design, scan_workspace, scan_workspace_with_overrides,
};

#[cfg(feature = "js")]
use dotore_js::{enrich_cross_file_autofixes, evaluate_project_with_packages};
use virtual_workspace::extract_virtual_workspace_packages;
pub(crate) use workspace_scan::load_disk_manifests;

const DEFAULT_ANALYZERS: &[&dyn LanguageAnalyzer] = &[
    #[cfg(feature = "js")]
    &JsLanguageAnalyzer,
    #[cfg(feature = "py")]
    &PyLanguageAnalyzer,
    #[cfg(feature = "rs")]
    &RsLanguageAnalyzer,
];

/// Returns all active [`LanguageAnalyzer`] implementations enabled by Cargo features (`js`, `py`, `rs`).
#[must_use]
pub const fn default_analyzers() -> &'static [&'static dyn LanguageAnalyzer] {
    DEFAULT_ANALYZERS
}

pub(crate) fn register_active_core_hooks() {
    #[cfg(feature = "js")]
    JsLanguageAnalyzer::register_core_hooks();
}

/// Analyzes a single in-memory source file through the matching [`LanguageAnalyzer`] and returns its [`Diagnostic`]s.
#[must_use]
pub fn analyze_source(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    register_active_core_hooks();
    let mut diagnostics = analyze_source_unmasked(path, source, enabled_rules);
    for diag in &mut diagnostics {
        diag.message = mask_credentials(&diag.message);
    }
    diagnostics
}

fn analyze_source_unmasked(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    #[cfg(feature = "rs")]
    if RsLanguageAnalyzer.supports_path(path) {
        return dotore_rs::analyze_rs_source(path, source, enabled_rules);
    }
    #[cfg(feature = "py")]
    {
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
    }
    #[cfg(feature = "js")]
    {
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
    #[cfg(not(feature = "js"))]
    {
        let _ = (path, source, enabled_rules);
        Vec::new()
    }
}

#[cfg(feature = "js")]
fn is_standalone_angular_source(path: &Path, source: &str) -> bool {
    if source.contains("from 'react'") || source.contains("from \"react\"") {
        return false;
    }
    if [
        "@angular/",
        "@ngrx/",
        "@Component(",
        "@Directive(",
        "@Injectable(",
        "@Pipe(",
        "@NgModule(",
        "@Effect(",
        "createEffect(",
        "createReducer(",
        "@include mat.",
    ]
    .iter()
    .any(|marker| source.contains(marker))
    {
        return true;
    }
    let path_str = path.to_string_lossy();
    [
        ".component.ts",
        ".directive.ts",
        ".service.ts",
        ".pipe.ts",
        ".module.ts",
        ".effects.ts",
        ".reducer.ts",
        ".actions.ts",
        ".selectors.ts",
        ".facade.ts",
        ".store.ts",
        ".component.html",
    ]
    .iter()
    .any(|suffix| path_str.ends_with(suffix))
        || matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("html" | "htm")
        )
}

/// Analyzes a single in-memory source file under an explicit [`DotoreConfig`] and [`CapabilityGate`]
/// through the matching [`LanguageAnalyzer`].
#[must_use]
pub fn analyze_source_with_config(
    path: &Path,
    source: &str,
    config: &DotoreConfig,
    gate: &CapabilityGate,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    register_active_core_hooks();
    let mut diagnostics =
        analyze_source_with_config_unmasked(path, source, config, gate, enabled_rules);
    for diag in &mut diagnostics {
        diag.message = mask_credentials(&diag.message);
    }
    diagnostics
}

fn analyze_source_with_config_unmasked(
    path: &Path,
    source: &str,
    config: &DotoreConfig,
    gate: &CapabilityGate,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    #[cfg(feature = "rs")]
    if RsLanguageAnalyzer.supports_path(path) {
        return dotore_rs::analyze_rs_source_with_config(path, source, config, gate, enabled_rules);
    }
    #[cfg(feature = "py")]
    {
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
    }
    #[cfg(feature = "js")]
    {
        let analyzer = JsLanguageAnalyzer;
        let extracted = analyzer.extract_file(path, source);
        let pkg_root = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        analyzer.analyze_single_file(&extracted, pkg_root, gate, config, enabled_rules)
    }
    #[cfg(not(feature = "js"))]
    {
        let _ = (path, source, config, gate, enabled_rules);
        Vec::new()
    }
}

#[cfg(feature = "js")]
fn has_non_js_or_manifest_entries(files: &[(PathBuf, String)]) -> bool {
    files.iter().any(|(p, _)| {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if matches!(ext, "py" | "pyi" | "rs") {
            return true;
        }
        let norm_p = p.to_string_lossy().replace('\\', "/");
        if norm_p.ends_with(".cargo/config.toml") || norm_p.ends_with(".cargo/config") {
            return true;
        }
        p.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            matches!(
                name,
                "package.json"
                    | "angular.json"
                    | "pyproject.toml"
                    | "requirements.txt"
                    | "Cargo.toml"
                    | "Cargo.lock"
                    | "tsconfig.json"
                    | "jsconfig.json"
                    | "pnpm-workspace.yaml"
                    | "pnpm-lock.yaml"
                    | "package-lock.json"
                    | "yarn.lock"
            ) || (name.starts_with("tsconfig.") && name.ends_with(".json"))
                || name.starts_with("dotore.config.")
        })
    })
}

/// Analyzes multiple in-memory `(PathBuf, String)` files with full cross-file graph resolution
/// dispatched across all active [`LanguageAnalyzer`]s.
///
/// If `files` includes virtual `package.json`, `angular.json`, `pyproject.toml`, `requirements.txt`,
/// `Cargo.toml`, or `dotore.config.*` entries, nested packages, per-package **Capability Gates**,
/// and user configuration are automatically inferred in memory.
#[must_use]
pub fn analyze_project_sources(
    files: Vec<(PathBuf, String)>,
    enabled_rules: Option<&[RuleId]>,
) -> JsonReport {
    register_active_core_hooks();

    #[cfg(feature = "js")]
    if !has_non_js_or_manifest_entries(&files) {
        let js_analyzer = JsLanguageAnalyzer;
        let sources: HashMap<PathBuf, String> = files.iter().cloned().collect();
        let extracted_files: Vec<ExtractedFile> = files
            .into_par_iter()
            .map(|(path, source)| js_analyzer.extract_file(&path, &source))
            .collect();
        let has_angular = extracted_files
            .iter()
            .any(|f| is_standalone_angular_source(&f.path, &f.source));
        let mut capability_gate = CapabilityGate::default_react();
        if has_angular {
            capability_gate.merge(&CapabilityGate::default_angular());
        }
        let default_pkg = WorkspacePackage {
            name: "default".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate,
            config: DotoreConfig::default(),
        };
        let pkg_result =
            js_analyzer.analyze_package(&default_pkg, &extracted_files, enabled_rules);
        let graph = js_analyzer.build_graph_from_extracted(&extracted_files, HashMap::new());
        return build_report(&graph, pkg_result.diagnostics, &sources);
    }

    let split = extract_virtual_workspace_packages(files);
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

    let (all_extracted, js_graph_opt, diagnostics) = analyze_polyglot_sources(
        &packages,
        manifests,
        filtered_sources,
        &sources,
        enabled_rules,
    );

    build_polyglot_report(
        &all_extracted,
        js_graph_opt.as_ref(),
        diagnostics,
        &sources,
        &packages,
    )
}

struct PolyglotPlannerContext<'a> {
    extracted_files: &'a [ExtractedFile],
    extracted_index_by_path: HashMap<&'a Path, usize>,
    #[cfg(feature = "js")]
    js_graph: Option<&'a ProjectGraph>,
}

impl PlannerContext for PolyglotPlannerContext<'_> {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        self.extracted_files.analyzed_files()
    }

    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        if let Some(&idx) = self.extracted_index_by_path.get(file)
            && let Some(f) = self.extracted_files.get(idx)
        {
            if !f.subject_spans.is_empty() {
                return f
                    .subject_spans
                    .iter()
                    .map(|(name, span, _)| (name.clone(), *span))
                    .collect();
            }
            return Vec::new();
        }
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.subject_spans_for_file(file);
        }
        self.extracted_files.subject_spans_for_file(file)
    }

    fn callers_of(&self, target_file: &Path, subject_name: &str) -> Vec<ResolvedCallerSite> {
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.callers_of(target_file, subject_name);
        }
        let _ = (target_file, subject_name);
        Vec::new()
    }

    fn child_components_of(&self, file: &Path, subject_name: &str) -> Vec<String> {
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.child_components_of(file, subject_name);
        }
        let _ = (file, subject_name);
        Vec::new()
    }

    fn span_in_list_loop(&self, file: &Path, span: ByteSpan) -> bool {
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.span_in_list_loop(file, span);
        }
        let _ = (file, span);
        false
    }

    fn subject_rendered_in_list_loop(&self, target_file: &Path, subject_name: &str) -> bool {
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.subject_rendered_in_list_loop(target_file, subject_name);
        }
        let _ = (target_file, subject_name);
        false
    }

    fn count_context_consumers(
        &self,
        context_name: &str,
        sources: &HashMap<PathBuf, String>,
    ) -> usize {
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.count_context_consumers(context_name, sources);
        }
        self.extracted_files
            .count_context_consumers(context_name, sources)
    }

    fn architecture_facets_for_file(&self, file: &Path) -> Option<&ArchitectureFileFacets> {
        if let Some(&idx) = self.extracted_index_by_path.get(file)
            && let Some(f) = self.extracted_files.get(idx)
        {
            return Some(&f.architecture_facets);
        }
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph
            && let Some(facets) = g.architecture_facets_for_file(file)
        {
            return Some(facets);
        }
        self.extracted_files.architecture_facets_for_file(file)
    }

    fn find_rule_exemplar(
        &self,
        group: &RootCauseGroup,
        diagnostics: &[Diagnostic],
        sources: &HashMap<PathBuf, String>,
    ) -> Option<SourceExcerpt> {
        #[cfg(feature = "js")]
        if JsLanguageAnalyzer.supports_path(&group.file)
            && let Some(g) = self.js_graph
            && let Some(ex) = g.find_rule_exemplar(group, diagnostics, sources)
        {
            return Some(ex);
        }
        self.extracted_files
            .find_rule_exemplar(group, diagnostics, sources)
    }
}

#[cfg(feature = "js")]
type OptionalJsGraph = Option<ProjectGraph>;
#[cfg(not(feature = "js"))]
type OptionalJsGraph = Option<()>;

pub(crate) fn build_polyglot_report(
    all_extracted: &[ExtractedFile],
    #[cfg(feature = "js")] js_graph: Option<&ProjectGraph>,
    #[cfg(not(feature = "js"))] _js_graph: Option<&()>,
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
    packages: &[WorkspacePackage],
) -> JsonReport {
    let file_subject_counts: Vec<(PathBuf, usize)> = all_extracted
        .iter()
        .filter(|f| {
            !matches!(
                f.path.extension().and_then(|e| e.to_str()),
                Some("css" | "scss" | "html" | "htm")
            )
        })
        .map(|f| (f.path.clone(), f.subjects_count))
        .collect();
    let effects_scanned: usize = all_extracted.iter().map(|f| f.effects_count).sum();
    let extracted_index_by_path: HashMap<&Path, usize> = all_extracted
        .iter()
        .enumerate()
        .map(|(idx, f)| (f.path.as_path(), idx))
        .collect();
    let ctx = PolyglotPlannerContext {
        extracted_files: all_extracted,
        extracted_index_by_path,
        #[cfg(feature = "js")]
        js_graph,
    };
    build_report_from_planner_context(
        &ctx,
        &file_subject_counts,
        effects_scanned,
        diagnostics,
        sources,
        packages,
    )
}

#[cfg(any(feature = "py", feature = "rs"))]
fn resolve_package_index_for_file(
    file_path: &Path,
    packages: &[WorkspacePackage],
) -> Option<usize> {
    let resolved = resolve_package_for_file(file_path, packages)?;
    packages
        .iter()
        .position(|p| p.root_dir == resolved.root_dir)
}

#[cfg(any(feature = "py", feature = "rs"))]
fn bucket_extracted_by_package(
    extracted: Vec<ExtractedFile>,
    packages: &[WorkspacePackage],
    unmatched_out: &mut Vec<ExtractedFile>,
) -> Vec<Vec<ExtractedFile>> {
    let mut buckets: Vec<Vec<ExtractedFile>> = (0..packages.len()).map(|_| Vec::new()).collect();
    for file in extracted {
        if let Some(idx) = resolve_package_index_for_file(&file.path, packages)
            && let Some(bucket) = buckets.get_mut(idx)
        {
            bucket.push(file);
        } else {
            unmatched_out.push(file);
        }
    }
    buckets
}

#[cfg(feature = "py")]
fn evaluate_py_extracted(
    py_extracted: Vec<ExtractedFile>,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    all_extracted: &mut Vec<ExtractedFile>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if py_extracted.is_empty() {
        return;
    }
    let py = PyLanguageAnalyzer::new();
    let buckets = bucket_extracted_by_package(py_extracted, packages, all_extracted);
    for (pkg, bucket) in packages.iter().zip(buckets) {
        if !bucket.is_empty() {
            let res = py.analyze_package(pkg, &bucket, enabled_rules);
            diagnostics.extend(res.diagnostics);
            all_extracted.extend(bucket);
        }
    }
}

#[cfg(feature = "rs")]
fn evaluate_rs_extracted(
    rs_extracted: Vec<ExtractedFile>,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    all_extracted: &mut Vec<ExtractedFile>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if rs_extracted.is_empty()
        && !packages
            .iter()
            .any(|p| p.capability_gate.has(Capability::Rust))
    {
        return;
    }
    let buckets = bucket_extracted_by_package(rs_extracted, packages, all_extracted);
    let rs_pkg_count = buckets.iter().filter(|b| !b.is_empty()).count();
    if rs_pkg_count >= 2 {
        dotore_rs::evaluate_workspace_near_duplicate_functions(
            packages,
            &buckets,
            enabled_rules,
            diagnostics,
        );
    }
    for (pkg, bucket) in packages.iter().zip(buckets) {
        let has_rs_manifests = pkg
            .capability_gate
            .dependencies
            .keys()
            .any(|k| k.starts_with("__manifest:"));
        if !bucket.is_empty() || has_rs_manifests {
            let res = RsLanguageAnalyzer.analyze_package(pkg, &bucket, enabled_rules);
            diagnostics.extend(res.diagnostics);
            all_extracted.extend(bucket);
        }
    }
}

#[cfg(any(feature = "js", feature = "py", feature = "rs"))]
fn extract_files_in_parallel(
    pairs: Vec<(PathBuf, String)>,
    analyzer: &(dyn LanguageAnalyzer + Sync),
) -> Vec<ExtractedFile> {
    if pairs.is_empty() {
        return Vec::new();
    }
    pairs
        .into_par_iter()
        .map(|(path, source)| {
            tick_progress_file(&path);
            analyzer.extract_file(&path, &source)
        })
        .collect()
}

pub(crate) fn analyze_polyglot_sources(
    packages: &[WorkspacePackage],
    manifests: HashMap<PathBuf, String>,
    filtered_sources: Vec<(PathBuf, String)>,
    sources: &HashMap<PathBuf, String>,
    enabled_rules: Option<&[RuleId]>,
) -> (Vec<ExtractedFile>, OptionalJsGraph, Vec<Diagnostic>) {
    #[cfg(not(any(feature = "js", feature = "py", feature = "rs")))]
    {
        let _ = (
            packages,
            manifests,
            filtered_sources,
            sources,
            enabled_rules,
        );
        return (Vec::new(), None, Vec::new());
    }

    #[cfg(any(feature = "js", feature = "py", feature = "rs"))]
    {
        #[cfg(feature = "py")]
        let mut py_pairs: Vec<(PathBuf, String)> = Vec::new();
        #[cfg(feature = "rs")]
        let mut rs_pairs: Vec<(PathBuf, String)> = Vec::new();
        #[cfg(feature = "js")]
        let mut js_pairs: Vec<(PathBuf, String)> = Vec::new();

        for (path, content) in filtered_sources {
            #[cfg(feature = "py")]
            if PyLanguageAnalyzer.supports_path(&path) {
                py_pairs.push((path, content));
                continue;
            }
            #[cfg(feature = "rs")]
            if RsLanguageAnalyzer.supports_path(&path) {
                rs_pairs.push((path, content));
                continue;
            }
            #[cfg(feature = "js")]
            if JsLanguageAnalyzer.supports_path(&path)
                || matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("css" | "scss" | "html" | "htm")
                )
            {
                js_pairs.push((path, content));
                continue;
            }
            let _ = (path, content);
        }

        let mut total_to_extract = 0usize;
        #[cfg(feature = "py")]
        {
            total_to_extract += py_pairs.len();
        }
        #[cfg(feature = "rs")]
        {
            total_to_extract += rs_pairs.len();
        }
        #[cfg(feature = "js")]
        {
            total_to_extract += js_pairs.len();
        }
        set_progress_phase(3, total_to_extract);

        #[cfg(feature = "py")]
        let py_extracted = extract_files_in_parallel(py_pairs, &PyLanguageAnalyzer::new());
        #[cfg(feature = "rs")]
        let rs_extracted = extract_files_in_parallel(rs_pairs, &RsLanguageAnalyzer);
        #[cfg(feature = "js")]
        let js_extracted = extract_files_in_parallel(js_pairs, &JsLanguageAnalyzer);

        set_progress_phase(4, total_to_extract);

        let mut all_extracted: Vec<ExtractedFile> = Vec::new();
        let mut diagnostics: Vec<Diagnostic> = Vec::new();

        #[cfg(feature = "py")]
        evaluate_py_extracted(
            py_extracted,
            packages,
            enabled_rules,
            &mut all_extracted,
            &mut diagnostics,
        );
        #[cfg(feature = "rs")]
        evaluate_rs_extracted(
            rs_extracted,
            packages,
            enabled_rules,
            &mut all_extracted,
            &mut diagnostics,
        );

        #[cfg(feature = "js")]
        let js_graph_opt = if !js_extracted.is_empty() || !manifests.is_empty() {
            let js_analyzer = JsLanguageAnalyzer;
            let graph = js_analyzer.build_graph_from_extracted(&js_extracted, manifests);
            let mut js_diags = evaluate_project_with_packages(&graph, packages, enabled_rules);
            enrich_cross_file_autofixes(&graph, &mut js_diags, sources);
            diagnostics.extend(js_diags);
            all_extracted.extend(js_extracted);
            Some(graph)
        } else {
            None
        };
        #[cfg(not(feature = "js"))]
        let js_graph_opt = {
            let _ = (manifests, sources);
            None
        };

        (all_extracted, js_graph_opt, diagnostics)
    }
}
