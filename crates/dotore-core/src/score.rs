//! Deterministic local `0..=100` Health Score, rating label, and `P0`–`P3` tier aggregation.

use serde::{Deserialize, Serialize};

use crate::rules::{BlastRadiusTier, RootCauseGroup, RuleSeverity};

/// Deterministic local health score and tier breakdown for a project or workspace scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthScore {
    /// Numeric health score in `0..=100` (`100` when zero diagnostics are present).
    pub score: u32,
    /// Human-readable rating (`"Excellent"`, `"Good"`, `"Needs Attention"`, `"Critical"`).
    pub label: String,
    /// Count of `P0` **Root-Cause Groups**.
    pub p0_groups: usize,
    /// Count of `P1` **Root-Cause Groups**.
    pub p1_groups: usize,
    /// Count of `P2` **Root-Cause Groups**.
    pub p2_groups: usize,
    /// Count of `P3` **Root-Cause Groups**.
    pub p3_groups: usize,
}

/// Returns the canonical human-readable rating label for a `0..=100` health score.
///
/// - `90..=100`: `"Excellent"`
/// - `75..=89`: `"Good"`
/// - `50..=74`: `"Needs Attention"`
/// - `0..=49`: `"Critical"`
#[must_use]
pub const fn score_label(score: u32) -> &'static str {
    match score {
        90..=u32::MAX => "Excellent",
        75..=89 => "Good",
        50..=74 => "Needs Attention",
        0..=49 => "Critical",
    }
}

/// Computes the deterministic local `0..=100` [`HealthScore`] from active [`RootCauseGroup`]s,
/// their static [`BlastRadiusTier`] and [`RuleSeverity`] weights, and the total analyzed
/// **Subjects** and files.
#[must_use]
pub fn compute_local_health_score(
    root_cause_groups: &[RootCauseGroup],
    files_scanned: usize,
    subjects_scanned: usize,
) -> HealthScore {
    let mut p0_groups = 0;
    let mut p1_groups = 0;
    let mut p2_groups = 0;
    let mut p3_groups = 0;

    if root_cause_groups.is_empty() {
        return HealthScore {
            score: 100,
            label: score_label(100).to_string(),
            p0_groups: 0,
            p1_groups: 0,
            p2_groups: 0,
            p3_groups: 0,
        };
    }

    let mut total_weighted_points: usize = 0;
    for group in root_cause_groups {
        let tier_base: usize = match group.blast_radius.tier {
            BlastRadiusTier::P0 => {
                p0_groups += 1;
                20
            }
            BlastRadiusTier::P1 => {
                p1_groups += 1;
                12
            }
            BlastRadiusTier::P2 => {
                p2_groups += 1;
                6
            }
            BlastRadiusTier::P3 => {
                p3_groups += 1;
                3
            }
        };

        let severity_num: usize = match group.severity {
            RuleSeverity::Error => 3,
            RuleSeverity::Warning => 2,
        };

        let blast_bonus = usize::try_from(group.blast_radius.score.min(80)).unwrap_or(0) / 10;
        let site_bonus = group.blast_radius.site_count.saturating_sub(1).min(5);
        let group_points = ((tier_base * severity_num) / 2) + blast_bonus + site_bonus;
        total_weighted_points = total_weighted_points.saturating_add(group_points);
    }

    // Normalize defect weight by analyzed Subjects and files so larger codebases are scored
    // by defect density rather than raw count alone.
    let norm_units = 2_usize
        .saturating_add(subjects_scanned)
        .saturating_add(files_scanned / 2)
        .max(1);

    let raw_penalty = (total_weighted_points.saturating_mul(3) + (norm_units / 2)) / norm_units;
    let clamped_penalty = raw_penalty.clamp(1, 100);
    let score = u32::try_from(100_usize.saturating_sub(clamped_penalty)).unwrap_or(0);

    HealthScore {
        score,
        label: score_label(score).to_string(),
        p0_groups,
        p1_groups,
        p2_groups,
        p3_groups,
    }
}
