//! Pure-Rust React, TypeScript, Angular, Python, and Rust static analyzer,
//! deterministic auto-fixer, and remediation engine.

use std::{
    collections::HashMap,
    fs, io,
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

pub use cli::{Cli, Commands, run_cli};
pub use config::{
    ArchitectureThresholdsConfig, Capability, CapabilityGate, CapabilityPredicate, ConfigMutation,
    ConfigTargetKind, DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole,
    SupplyChainConfig, WorkspacePackage, discover_workspace_packages,
    discover_workspace_packages_with_analyzers, filter_workspace_packages, is_cache_disabled,
    load_config_from_dir, mutate_config_in_dir, resolve_dotore_home_dir, resolve_package_for_file,
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
    PlanResult, PlannerContext, build_fix_capsule, build_root_cause_groups_and_capsules,
    compute_root_cause_group_id, format_plan_report, plan_project,
};
pub use progress::{
    LiveScanProgressSnapshot, LiveSpinner, SPINNER_FRAMES, current_scan_progress,
    format_spinner_frame, format_spinner_frame_with_width, set_progress_phase, tick_discovery_file,
    tick_progress_file,
};
pub use report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, ProjectCoverageMetadata, ReportSummary,
    RuleCatalogEntry, RulesListOptions, WhyEntry, WhyLocation, WhyReport, build_extracted_report,
    build_extracted_report_with_packages, build_rule_catalog, ci_config, ci_install, ci_upgrade,
    explain_location, explain_location_with_analyzers, explain_rule,
    format_architecture_signal_explanation, format_design_report, format_design_report_pretty,
    format_fix_report, format_install_report, format_rule_catalog_text,
    format_rule_explanation_text, format_terminal_report, format_terminal_report_pretty,
    format_why_report_text, install_dotore, parse_why_location, render_html_report,
    write_and_open_html_report, write_json_report,
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
    TuiFilterTab, TuiGroupMode, TuiState, build_score_gauge, diagnostic_matches_tab_and_search,
    draw_tui_frame, handle_tui_search_key, render_tui_body_lines, render_tui_body_lines_for_width,
    render_tui_frame, run_interactive_tui, should_launch_tui,
};

use diff::{collect_git_diff, load_baseline_entries};
use dotore_core::{
    report::build_report_from_planner_context, scanner::collect_source_files_for_analyzers,
};
#[cfg(feature = "js")]
use dotore_js::{
    enrich_cross_file_autofixes, evaluate_file_in_package, evaluate_project_with_packages,
};
#[cfg(feature = "js")]
use scanner::collect_style_files;

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
    {
        let has_non_js_or_manifests = files.iter().any(|(p, _)| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default();
            if matches!(ext, "py" | "pyi" | "rs") {
                return true;
            }
            p.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
                name == "package.json"
                    || name == "angular.json"
                    || name == "pyproject.toml"
                    || name == "requirements.txt"
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

        if !has_non_js_or_manifests {
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
    #[cfg(feature = "js")]
    js_graph: Option<&'a ProjectGraph>,
}

impl PlannerContext for PolyglotPlannerContext<'_> {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        self.extracted_files.analyzed_files()
    }

    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        let spans = self.extracted_files.subject_spans_for_file(file);
        if !spans.is_empty() {
            return spans;
        }
        #[cfg(feature = "js")]
        if let Some(g) = self.js_graph {
            return g.subject_spans_for_file(file);
        }
        Vec::new()
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

fn build_polyglot_report(
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
    let ctx = PolyglotPlannerContext {
        extracted_files: all_extracted,
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

fn analyze_polyglot_sources(
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

        let mut all_extracted: Vec<ExtractedFile> = Vec::new();
        let mut diagnostics: Vec<Diagnostic> = Vec::new();

        let total_to_extract = {
            let mut n = 0usize;
            #[cfg(feature = "py")]
            {
                n += py_pairs.len();
            }
            #[cfg(feature = "rs")]
            {
                n += rs_pairs.len();
            }
            #[cfg(feature = "js")]
            {
                n += js_pairs.len();
            }
            n
        };
        set_progress_phase(3, total_to_extract);

        #[cfg(feature = "py")]
        let py_extracted: Vec<ExtractedFile> = if !py_pairs.is_empty() {
            let py = PyLanguageAnalyzer::new();
            py_pairs
                .into_par_iter()
                .map(|(path, source)| {
                    tick_progress_file(&path);
                    py.extract_file(&path, &source)
                })
                .collect()
        } else {
            Vec::new()
        };

        #[cfg(feature = "rs")]
        let rs_extracted: Vec<ExtractedFile> = if !rs_pairs.is_empty() {
            rs_pairs
                .into_par_iter()
                .map(|(path, source)| {
                    tick_progress_file(&path);
                    RsLanguageAnalyzer.extract_file(&path, &source)
                })
                .collect()
        } else {
            Vec::new()
        };

        #[cfg(feature = "js")]
        let js_extracted: Vec<ExtractedFile> = if !js_pairs.is_empty() {
            let js_analyzer = JsLanguageAnalyzer;
            js_pairs
                .into_par_iter()
                .map(|(path, source)| {
                    tick_progress_file(&path);
                    js_analyzer.extract_file(&path, &source)
                })
                .collect()
        } else {
            Vec::new()
        };

        set_progress_phase(4, total_to_extract);

        #[cfg(feature = "py")]
        if !py_extracted.is_empty() {
            let py = PyLanguageAnalyzer::new();
            let mut buckets: Vec<Vec<ExtractedFile>> =
                (0..packages.len()).map(|_| Vec::new()).collect();
            for file in py_extracted {
                if let Some(idx) = resolve_package_index_for_file(&file.path, packages) {
                    buckets[idx].push(file);
                } else {
                    all_extracted.push(file);
                }
            }
            for (pkg, bucket) in packages.iter().zip(buckets) {
                if !bucket.is_empty() {
                    let res = py.analyze_package(pkg, &bucket, enabled_rules);
                    diagnostics.extend(res.diagnostics);
                    all_extracted.extend(bucket);
                }
            }
        }

        #[cfg(feature = "rs")]
        if !rs_extracted.is_empty() {
            let mut buckets: Vec<Vec<ExtractedFile>> =
                (0..packages.len()).map(|_| Vec::new()).collect();
            for file in rs_extracted {
                if let Some(idx) = resolve_package_index_for_file(&file.path, packages) {
                    buckets[idx].push(file);
                } else {
                    all_extracted.push(file);
                }
            }
            for (pkg, bucket) in packages.iter().zip(buckets) {
                if !bucket.is_empty() {
                    let res = RsLanguageAnalyzer.analyze_package(pkg, &bucket, enabled_rules);
                    diagnostics.extend(res.diagnostics);
                    all_extracted.extend(bucket);
                }
            }
        }

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
struct VirtualWorkspaceSplit {
    packages: Vec<WorkspacePackage>,
    manifests: HashMap<PathBuf, String>,
    source_files: Vec<(PathBuf, String)>,
}

fn extract_virtual_workspace_packages(files: Vec<(PathBuf, String)>) -> VirtualWorkspaceSplit {
    let mut pkg_jsons: Vec<(PathBuf, String)> = Vec::new();
    let mut angular_jsons: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    let mut py_manifests: Vec<(PathBuf, PathBuf, String)> = Vec::new();
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
        } else if file_name == "pyproject.toml"
            || file_name == "requirements.txt"
            || (file_name.starts_with("requirements") && file_name.ends_with(".txt"))
            || (file_name.starts_with("constraints") && file_name.ends_with(".txt"))
        {
            py_manifests.push((parent_dir, path, content));
        } else if file_name == "Cargo.toml" {
            manifests.insert(path.clone(), content.clone());
            cargo_tomls.push((parent_dir, path, content));
        } else if is_non_js_manifest_filename(file_name) {
            if is_compiler_config_name(file_name) {
                compiler_configs.push((parent_dir, path.clone(), content.clone()));
            }
            manifests.insert(path, content);
        } else if file_name.starts_with("dotore.config.") {
            config_files.push((parent_dir, path, content));
        } else {
            if is_compiler_config_name(file_name) {
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

    let mut packages: Vec<WorkspacePackage> = Vec::new();

    #[cfg(feature = "js")]
    {
        let js_analyzer = JsLanguageAnalyzer;
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
    }

    #[cfg(feature = "py")]
    {
        let py = PyLanguageAnalyzer::new();
        let mut py_dirs: Vec<PathBuf> = Vec::new();
        for (dir, _, _) in &py_manifests {
            if !py_dirs.contains(dir) {
                py_dirs.push(dir.clone());
            }
        }
        for dir in py_dirs {
            let dir_manifests: Vec<(PathBuf, &str)> = py_manifests
                .iter()
                .filter(|(d, _, _)| d == &dir)
                .map(|(_, p, c)| (p.clone(), c.as_str()))
                .collect();
            let py_gate = py.infer_capability_gate(&dir, &dir_manifests);
            if let Some(existing) = packages.iter_mut().find(|p| p.root_dir == dir) {
                existing.capability_gate.merge(&py_gate);
            } else {
                let local_cfg = config_files
                    .iter()
                    .find(|(c_dir, _, _)| c_dir == &dir)
                    .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
                    .unwrap_or_else(|| root_config.clone());
                let name = dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("root")
                    .to_string();
                packages.push(WorkspacePackage {
                    name,
                    root_dir: dir,
                    capability_gate: py_gate,
                    config: local_cfg,
                });
            }
        }
    }

    #[cfg(feature = "rs")]
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

    #[cfg(feature = "py")]
    let has_py_files = source_files
        .iter()
        .any(|(p, _)| PyLanguageAnalyzer.supports_path(p));
    #[cfg(not(feature = "py"))]
    let has_py_files = false;

    #[cfg(feature = "rs")]
    let has_rs_files = source_files
        .iter()
        .any(|(p, _)| RsLanguageAnalyzer.supports_path(p));
    #[cfg(not(feature = "rs"))]
    let has_rs_files = false;

    if packages.is_empty() {
        let mut default_gate = CapabilityGate::default_react();
        if has_py_files {
            default_gate.merge(&CapabilityGate::default_python());
        }
        if has_rs_files {
            default_gate.merge(&CapabilityGate::default_rust());
        }
        packages.push(WorkspacePackage {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: default_gate,
            config: root_config,
        });
    } else {
        if py_manifests.is_empty() && has_py_files {
            let py_default = CapabilityGate::default_python();
            for pkg in &mut packages {
                pkg.capability_gate.merge(&py_default);
            }
        }
        if cargo_tomls.is_empty() && has_rs_files {
            let rs_default = CapabilityGate::default_rust();
            for pkg in &mut packages {
                pkg.capability_gate.merge(&rs_default);
            }
        }
    }

    VirtualWorkspaceSplit {
        packages,
        manifests,
        source_files,
    }
}

fn is_compiler_config_name(file_name: &str) -> bool {
    file_name.starts_with("next.config.")
        || file_name.starts_with("babel.config.")
        || file_name.starts_with(".babelrc")
        || file_name.starts_with("vite.config.")
        || file_name == "app.json"
        || file_name.starts_with("app.config.")
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
            pkg.config = cfg.clone();
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

    set_progress_phase(2, paths.len());
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
    let pairs: Vec<(PathBuf, String)> = paths
        .into_iter()
        .filter_map(|path| {
            let content = fs::read_to_string(&path).ok()?;
            tick_progress_file(&path);
            Some((path, content))
        })
        .collect();
    let sources: HashMap<PathBuf, String> = pairs.iter().cloned().collect();
    #[cfg(feature = "js")]
    if packages
        .iter()
        .any(|pkg| pkg.capability_gate.has(Capability::Motion))
    {
        for style_path in collect_style_files(&options.paths) {
            if resolve_package_for_file(&style_path, &all_packages).is_none_or(|resolved_pkg| {
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

    let manifests = load_disk_manifests(&workspace_root, &packages, &sources);
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
            &all_extracted,
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
                        &all_extracted,
                        &sources,
                    );
                    diff_info = Some(diff_snap.info);
                }
            }
        }
    }

    let mut report = build_polyglot_report(
        &all_extracted,
        js_graph_opt.as_ref(),
        diagnostics,
        &sources,
        &packages,
    );
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
            pkg.config = cfg.clone();
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
    for file in &graph.files {
        tick_progress_file(&file.path);
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
