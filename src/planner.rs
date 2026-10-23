//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, cross-file **Caller Site** autofix enrichment, repository **Exemplar**
//! discovery, **Fix Capsule** assembly, and Markdown execution plan generation (`dotore plan`).

pub use dotore_core::planner::{
    PlanResult, PlannerContext, build_fix_capsule, build_root_cause_groups_and_capsules,
    compute_root_cause_group_id, format_plan_report, plan_project,
};
