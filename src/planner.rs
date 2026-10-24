//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, cross-file **Caller Site** autofix enrichment, repository **Exemplar**
//! discovery, **Fix Capsule** assembly, and Markdown execution plan generation (`dotore plan`).

pub use dotore_core::planner::{
    DiagnosticsBundle, MIGRATION_BUCKET_MIN_FILES, MigrationRuleBucket, PlanResult, PlannerContext,
    build_agent_handoff_prompt, build_fix_capsule, build_root_cause_groups_and_capsules,
    compute_root_cause_group_id, detect_migration_rule_buckets, format_plan_report, plan_project,
    render_rule_bundle_summary_text, write_diagnostics_bundle,
};
