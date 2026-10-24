//! Terminal, JSON, rule catalog, location diagnosis (`dotore why`), CI/install automation,
//! and self-contained HTML cascade reporters for `dotore`.

/// CI workflow automation (`dotore ci`) and `/dotore` skill / git hook installer (`dotore install`).
pub mod ci_install;
/// Self-contained visual HTML cascade report renderer (`dotore report`).
pub mod html;
/// Machine-readable [`JsonReport`] schema, builders, and JSON serializer.
pub mod json;
/// Rule catalog listing (`dotore rules list`) and rule explanation (`dotore rules explain`).
pub mod rules;
/// Terminal and ASCII report rendering (`dotore check`, `dotore design`, and `dotore fix`).
pub mod terminal;
/// Location diagnosis (`dotore why <file:line>`), suppression/gate explanation, and code frames.
pub mod why;

pub use ci_install::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult, ci_config,
    ci_install, ci_upgrade, format_install_report, install_dotore,
};
pub use html::{render_html_report, write_and_open_html_report};
pub use json::{
    JSON_REPORT_SCHEMA_VERSION, JsonReport, MAX_SCAN_CACHE_ENTRIES, ProjectCoverageMetadata,
    ReportSummary, SCAN_CACHE_SCHEMA_VERSION, ScanCacheEntry, ScanResultCacheFile,
    build_extracted_report, build_extracted_report_with_packages,
    build_report_from_planner_context, load_scan_result_cache, lookup_scan_cache,
    resolve_scan_cache_path, store_scan_cache, write_json_report,
};
pub use rules::{
    RuleCatalogEntry, RulesListOptions, build_rule_catalog, explain_rule, format_rule_catalog_text,
    format_rule_explanation_text,
};
pub use terminal::{
    format_design_report, format_design_report_pretty, format_fix_report, format_terminal_report,
    format_terminal_report_pretty,
};
pub use why::{
    WhyEntry, WhyLocation, WhyReport, diagnose_why_not_active_common, explain_location,
    explain_location_with_analyzers, format_architecture_signal_explanation,
    format_why_report_text, parse_why_location, render_code_frame,
};
