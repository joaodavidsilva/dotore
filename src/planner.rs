//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, cross-file **Caller Site** autofix enrichment, repository **Exemplar**
//! discovery, **Fix Capsule** assembly, and Markdown execution plan generation (`dotore plan`).

pub use dotore_core::planner::{
    DiagnosticsBundle, HandoffTarget, MIGRATION_BUCKET_MIN_FILES, MigrationRuleBucket, PlanResult,
    PlannerContext, build_agent_handoff_prompt, build_fix_capsule,
    build_root_cause_groups_and_capsules, compute_root_cause_group_id, copy_to_clipboard,
    detect_available_coding_agents, detect_migration_rule_buckets, excerpt_from_span,
    execute_handoff, filter_report_for_diagnostics, format_plan_report,
    load_preferred_handoff_target, plan_project, render_rule_bundle_summary_text,
    resolve_agent_binary_path, save_preferred_handoff_target, write_diagnostics_bundle,
};
