//! Language-agnostic intermediate representation, configuration & **Capability Gate** inference,
//! remediation engine, `LanguageAnalyzer` trait contract, scorer, fuzzy symbol search,
//! and terminal/JSON/HTML reporters for `dotore`.

use std::path::PathBuf;

/// Project configuration loader (`dotore.config.*` / `package.json#dotore`) and **Capability Gate**.
pub mod config;
/// Git diff scopes (`--scope`, `--base`, `--staged`), **Contextual Owner** filtering, and `--baseline` multiset comparison.
pub mod diff;
/// Surgical auto-fixer for `Autofix`-tier diagnostics.
pub mod fixer;
/// Language-agnostic IR (`SourceLoc`, `ByteSpan`, `SymbolOutline`, `ExtractedFile`, `LanguageAnalyzer`).
pub mod ir;
/// Deterministic **Root-Cause Grouping**, **Blast Radius**, **Fix Capsules**, and `dotore plan` generator.
pub mod planner;
/// Terminal, JSON, and self-contained HTML reporters.
pub mod report;
/// Unified diagnostic rule registry and metadata types.
pub mod rules;
/// Parallel gitignore-aware file discovery.
pub mod scanner;
/// Deterministic local `0..=100` Health Score and `P0`–`P3` tier calculation.
pub mod score;
/// Native fuzzy AST **Symbol Outline** search (`dotore search`).
pub mod search;
/// Reusable ASCII/Unicode and ANSI terminal UI component kit (`AsciiBox`, `GaugeBar`, `Badge`, `FlowDiagram`, `FilterTabBar`, `StatusBar`, `LiveSpinner`).
pub mod ui;

pub use config::{
    ArchitectureThresholdsConfig, Capability, CapabilityGate, CapabilityPredicate, ConfigMutation,
    ConfigTargetKind, DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole,
    SupplyChainConfig, WorkspacePackage, content_enables_react_compiler,
    discover_workspace_packages, discover_workspace_packages_with_analyzers,
    find_nearest_ancestor_file, is_cache_disabled, load_config_from_dir, load_local_config_in_dir,
    mutate_config_in_dir, normalize_path_buf, normalize_rel_path_str, relative_forward_slash,
    resolve_dotore_home_dir, resolve_package_for_file, strip_jsonc, strip_source_extension,
};
pub use diff::{
    BaselineDeltaResult, BaselineDiagnosticEntry, BaselineSummary, BlockingLevel,
    ChangedFileLineRanges, ContextualSpanProvider, DiffScope, GitDiffInfo, GitDiffSnapshot,
    ScanMode, collect_git_diff, compare_baseline_diagnostics, compute_diagnostic_fingerprint,
    compute_diagnostic_id, compute_structural_fingerprint, diagnostic_intersects_changed_lines,
    filter_diagnostics_by_scope, load_baseline_entries_with, normalize_ast_tokens,
    parse_baseline_report_str, parse_changed_line_ranges, resolve_scan_exit_code,
    validate_git_revision, validate_warning_exit_code,
};
pub use fixer::{
    FileFixResult, apply_autofixes, apply_autofixes_with_analyzers, apply_autofixes_with_validator,
    apply_patches_to_source, apply_patches_to_source_with_analyzers,
    apply_patches_to_source_with_validator, register_default_syntax_validator,
};
pub use ir::{
    ArchitectureFileFacets, BlockDisableRange, ByteSpan, ConcernBucket, ConcernSignalSite,
    ContextualOwnerSpansIr, ExtractedFile, FNV1A_64_OFFSET_BASIS, FileContext, FileSuppressions,
    HelperFingerprintIr, InlineTerminalUiPrimitiveSiteIr, LanguageAnalyzer, LanguageId,
    LineDisableDirective, OpenerLineRange, PackageAnalysisResult, RelatedHookOwnerSpanIr,
    ResolvedCallerSite, SourceLoc, StaticCatalogSiteIr, StructLiteralConstructionSiteIr,
    SubjectEffectOwner, SuppressionDirectiveKind, SymbolKind, SymbolOutline,
    TerminalUiPrimitiveKind, classify_file_context, compute_line_starts,
    extract_c_style_comment_suppressions, extract_normalized_signature_header, fnv1a_64_byte,
    fnv1a_64_step, fnv1a_64_str, loc_from_line_starts, map_rust_allow_lint_to_rules,
    parse_comment_disable_directive, parse_python_suppression_directive, rule_list_matches,
    tokenize_suppression_rules,
};
pub use planner::{
    PlanResult, PlannerContext, build_caller_site_excerpt, build_fix_capsule,
    build_root_cause_groups_and_capsules, compute_root_cause_group_id, excerpt_from_span,
    find_architecture_exemplar_from_facets, format_plan_report, plan_project, slice_span,
    spans_intersect,
};
pub use report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, MAX_SCAN_CACHE_ENTRIES, ProjectCoverageMetadata,
    ReportSummary, RuleCatalogEntry, RulesListOptions, SCAN_CACHE_SCHEMA_VERSION, ScanCacheEntry,
    ScanResultCacheFile, WhyEntry, WhyLocation, WhyReport, build_extracted_report,
    build_extracted_report_with_packages, build_report_from_planner_context, build_rule_catalog,
    ci_config, ci_install, ci_upgrade, diagnose_why_not_active_common, explain_location,
    explain_location_with_analyzers, explain_rule, format_architecture_signal_explanation,
    format_design_report, format_design_report_pretty, format_fix_report, format_install_report,
    format_rule_catalog_text, format_rule_explanation_text, format_terminal_report,
    format_terminal_report_pretty, format_why_report_text, install_dotore, load_scan_result_cache,
    lookup_scan_cache, parse_why_location, render_code_frame, render_html_report,
    resolve_scan_cache_path, store_scan_cache, write_and_open_html_report, write_json_report,
};
pub use rules::{
    AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
    FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
    RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry,
    supply_chain_purl_hash,
};
pub use scanner::{
    JS_SOURCE_EXTENSIONS, POLYGLOT_SOURCE_EXTENSIONS, collect_source_files,
    collect_source_files_for_analyzers, collect_source_files_with_extensions, collect_style_files,
    is_explicit_file_ignored, is_supported_file, is_supported_file_with_extensions,
};
pub use score::{HealthScore, compute_local_health_score, score_label};
pub use search::{
    SearchJsonLocation, SearchJsonReport, SearchJsonResult, SearchOptions, SymbolSearchResult,
    format_search_json, format_search_text, register_default_symbol_extractor, score_fuzzy,
    search_extracted_files, search_project_sources, search_project_sources_with,
    search_project_sources_with_analyzers, search_symbols, search_symbols_with,
    search_symbols_with_analyzers, should_highlight_search, should_highlight_stdout,
};
pub use ui::{
    AsciiBox, Badge, BadgeKind, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, FilterTabBar,
    FilterTabItem, FlowDiagram, GaugeBar, LiveScanProgressSnapshot, LiveSpinner, SPINNER_FRAMES,
    StatusBar, TuiFilterKind, build_filter_tabs, classify_style_bucket, current_scan_progress,
    format_spinner_frame, format_spinner_frame_with_width, set_progress_phase, strip_ansi_codes,
    style_bucket_color, tick_discovery_file, tick_progress_file, truncate_ansi_to_width,
    visible_char_width,
};

/// Options for scanning a project or file list.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Target files or directories to scan (empty defaults to `"."`).
    pub paths: Vec<PathBuf>,
    /// Whether to include test files (`.test.*`, `.spec.*`, `__tests__`, `test_*.py`, `tests/`) when walking directories.
    pub include_tests: bool,
    /// Optional subset of rules to run (`None` runs all rules).
    pub rules: Option<Vec<RuleId>>,
    /// Optional filter of [`PrescriptionTier`]s to keep in the report (`None` keeps all tiers).
    pub tiers: Option<Vec<PrescriptionTier>>,
}

/// CLI-level configuration overrides that take precedence over `dotore.config.*` and `package.json#dotore`.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// When `true` (`--no-inline-disables`), inline disable comments are ignored for audit runs.
    pub no_inline_disables: bool,
    /// When `true` (`--custom-rules-only`), rules originally ported from external plugins are disabled.
    pub custom_rules_only: bool,
    /// Additional rule tags to ignore (`--ignore-tag`).
    pub ignore_tags: Vec<String>,
    /// Explicit path to a configuration file (`--config <path>`).
    pub config_path: Option<PathBuf>,
    /// Active git diff scope (`--scope full|changed|contextual|lines`).
    pub scope: DiffScope,
    /// Explicit git base revision (`--base <rev>`).
    pub base_ref: Option<String>,
    /// Scan staged git index changes (`--staged`).
    pub staged: bool,
    /// Compare against a saved baseline JSON report or git revision (`--baseline <path>`).
    pub baseline_path: Option<PathBuf>,
    /// Bypass the persistent workspace scan result cache (`--no-cache`).
    pub no_cache: bool,
}
