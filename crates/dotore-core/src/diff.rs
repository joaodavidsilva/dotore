//! Git diff execution (`--base`, `--staged`), unified diff hunk line-range parsing,
//! **Contextual Owner** span resolution (`--scope full|changed|contextual|lines`),
//! `--baseline <report.json>` multiset fingerprint comparison, and CI exit-code resolution.

/// Diagnostic fingerprinting and `--baseline` multiset comparison.
pub mod baseline;
/// **Contextual Owner** span resolution and scope filtering.
pub mod contextual_owner;
/// Git revision validation, unified diff patch parsing, and git diff execution.
pub mod patch;

pub use baseline::{
    BaselineDeltaResult, BaselineDiagnosticEntry, BaselineSummary, compare_baseline_diagnostics,
    compute_diagnostic_fingerprint, compute_diagnostic_id, compute_structural_fingerprint,
    load_baseline_entries_with, normalize_ast_tokens, parse_baseline_report_str,
};
pub use contextual_owner::{
    ContextualSpanProvider, diagnostic_intersects_changed_lines, filter_diagnostics_by_scope,
};
pub use patch::{
    BlockingLevel, ChangedFileLineRanges, DiffScope, GitDiffInfo, GitDiffSnapshot, ScanMode,
    collect_git_diff, parse_changed_line_ranges, resolve_scan_exit_code, validate_git_revision,
    validate_warning_exit_code,
};
