//! Git diff execution (`--base`, `--staged`), unified diff hunk line-range parsing,
//! **Contextual Owner** span resolution (`--scope full|changed|contextual|lines`),
//! `--baseline <report.json>` multiset fingerprint comparison, and CI exit-code resolution.

use std::path::Path;

pub use dotore_core::diff::{
    BaselineDeltaResult, BaselineDiagnosticEntry, BaselineSummary, BlockingLevel,
    ChangedFileLineRanges, ContextualSpanProvider, DiffScope, GitDiffInfo, ScanMode,
    collect_git_diff, compare_baseline_diagnostics, compute_diagnostic_fingerprint,
    compute_diagnostic_id, compute_structural_fingerprint, diagnostic_intersects_changed_lines,
    filter_diagnostics_by_scope, load_baseline_entries_with, normalize_ast_tokens,
    parse_baseline_report_str, parse_changed_line_ranges, resolve_scan_exit_code,
    validate_git_revision, validate_warning_exit_code,
};
use dotore_core::rules::RuleId;

/// Attempts to load baseline diagnostic entries from a JSON file path or a git revision's base blobs.
pub(crate) fn load_baseline_entries(
    workspace_root: &Path,
    baseline_arg: &Path,
    enabled_rules: Option<&[RuleId]>,
) -> Result<Vec<BaselineDiagnosticEntry>, String> {
    load_baseline_entries_with(
        workspace_root,
        baseline_arg,
        enabled_rules,
        |files, rules| crate::analyze_project_sources(files, rules).diagnostics,
    )
}
