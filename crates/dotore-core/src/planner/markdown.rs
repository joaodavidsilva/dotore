//! Markdown execution plan generation (`dotore plan`).

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Serialize;

use crate::{
    report::{JsonReport, ReportSummary},
    rules::{BlastRadius, Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup, RuleSeverity},
    score::compute_local_health_score,
};
use super::normalize_slug;

/// Result of running `dotore plan` (`plan_project`) to write deterministic Markdown execution plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanResult {
    /// Output directory where `README.md` and `NNN-<slug>.md` files were written.
    pub output_dir: PathBuf,
    /// Short git commit SHA stamped into the plan index (`"uncommitted"` if unavailable).
    pub commit_sha: String,
    /// Path to the generated `README.md` index file.
    pub index_file: PathBuf,
    /// Generated `(filename, path)` entries in priority order (`001-...`, `002-...`).
    pub plan_files: Vec<PathBuf>,
}

/// Generates deterministic `NNN-<slug>.md` execution plans and a prioritized `README.md` index
/// inside `output_dir`, stamped with the current git commit SHA.
///
/// # Errors
/// Returns an `io::Error` if creating `output_dir` or writing any Markdown file fails.
pub fn plan_project(report: &JsonReport, output_dir: &Path) -> io::Result<PlanResult> {
    fs::create_dir_all(output_dir)?;
    let commit_sha = resolve_git_commit_sha(output_dir);

    let mut plan_files = Vec::with_capacity(report.fix_capsules.len());
    let mut index_rows = Vec::with_capacity(report.fix_capsules.len());

    for (idx, capsule) in report.fix_capsules.iter().enumerate() {
        let ordinal = idx + 1;
        let slug = build_capsule_filename_slug(capsule, report);
        let file_name = format!("{ordinal:03}-{slug}.md");
        let file_path = output_dir.join(&file_name);
        let markdown = render_capsule_plan_markdown(ordinal, capsule, report, &commit_sha);
        fs::write(&file_path, markdown)?;
        plan_files.push(file_path);
        index_rows.push((ordinal, file_name, capsule));
    }

    let index_file = output_dir.join("README.md");
    let readme_md = render_plan_readme_markdown(report, &commit_sha, &index_rows);
    fs::write(&index_file, readme_md)?;

    Ok(PlanResult {
        output_dir: output_dir.to_path_buf(),
        commit_sha,
        index_file,
        plan_files,
    })
}

/// Formats a human-readable terminal summary for `dotore plan`.
#[must_use]
pub fn format_plan_report(result: &PlanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "dotore plan  commit: {}  plans: {}  index: {}",
        result.commit_sha,
        result.plan_files.len(),
        result.index_file.display()
    );
    for path in &result.plan_files {
        let _ = writeln!(out, "  - {}", path.display());
    }
    out
}

fn build_capsule_filename_slug(capsule: &FixCapsule, report: &JsonReport) -> String {
    let group = report
        .root_cause_groups
        .iter()
        .find(|g| g.id == capsule.root_cause_group_id);
    let subject_or_target = group
        .and_then(|g| g.subject_name.as_deref())
        .or_else(|| group.map(|g| g.target_name.as_str()))
        .unwrap_or("root");
    format!(
        "{}-{}",
        capsule.rule.as_str(),
        normalize_slug(subject_or_target)
    )
}

pub(super) fn excerpt_code_fence_lang(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py" | "pyi") => "python",
        Some("rs") => "rust",
        _ => "tsx",
    }
}

fn render_capsule_plan_markdown(
    ordinal: usize,
    capsule: &FixCapsule,
    report: &JsonReport,
    commit_sha: &str,
) -> String {
    let mut md = String::new();
    let meta = capsule.rule.metadata();
    let group = report
        .root_cause_groups
        .iter()
        .find(|g| g.id == capsule.root_cause_group_id);

    let title_target = group
        .and_then(|g| g.subject_name.as_deref())
        .or_else(|| group.map(|g| g.target_name.as_str()))
        .unwrap_or("module");

    let _ = writeln!(
        md,
        "# Plan {ordinal:03}: `{}` in `{title_target}`\n",
        capsule.rule.as_str()
    );
    let _ = writeln!(
        md,
        "- **Root-Cause Group**: `{}`",
        capsule.root_cause_group_id
    );
    let _ = writeln!(
        md,
        "- **Rule**: `{}` ({})",
        capsule.rule.as_str(),
        meta.title
    );
    let _ = writeln!(md, "- **Category**: `{}`", meta.category.as_str());
    let _ = writeln!(md, "- **Prescription Tier**: `{}`", capsule.tier.as_str());
    let _ = writeln!(
        md,
        "- **Blast Radius**: `{}` (score `{}`, frequency `{}`, fan-out `{}`, cascade depth `{}`, sites `{}`, files `{}`)",
        capsule.blast_radius.tier.as_str(),
        capsule.blast_radius.score,
        capsule.blast_radius.render_frequency.as_str(),
        capsule.blast_radius.fan_out,
        capsule.blast_radius.cascade_depth,
        capsule.blast_radius.site_count,
        capsule.blast_radius.file_count,
    );
    let _ = writeln!(md, "- **Commit SHA**: `{commit_sha}`");
    let _ = writeln!(md, "- **Docs**: {}\n", meta.docs_url);

    if let Some(g) = group {
        let _ = writeln!(md, "## Findings ({})\n", g.diagnostic_indices.len());
        for &diag_idx in &g.diagnostic_indices {
            if let Some(d) = report.diagnostics.get(diag_idx) {
                let _ = writeln!(
                    md,
                    "- `{}:{}:{}` — {}",
                    d.file.display(),
                    d.loc.line,
                    d.loc.column,
                    crate::report::mask_credentials(&d.message)
                );
                if !d.cascade_steps.is_empty() {
                    let _ = writeln!(md, "  - Render Cascade: `{}`", d.cascade_steps.join(" -> "));
                }
            }
        }
        let _ = writeln!(md);
    }

    let subj_lang = excerpt_code_fence_lang(&capsule.subject_excerpt.file);
    let _ = writeln!(
        md,
        "## Subject Excerpt (`{}:{}-{}`)\n",
        capsule.subject_excerpt.file.display(),
        capsule.subject_excerpt.start_line,
        capsule.subject_excerpt.end_line
    );
    let _ = writeln!(
        md,
        "```{subj_lang}\n{}\n```\n",
        crate::report::mask_credentials(&capsule.subject_excerpt.source)
    );

    if !capsule.caller_site_excerpts.is_empty() {
        let _ = writeln!(
            md,
            "## Caller Site Excerpts ({})\n",
            capsule.caller_site_excerpts.len()
        );
        for caller_ex in &capsule.caller_site_excerpts {
            let caller_lang = excerpt_code_fence_lang(&caller_ex.file);
            let _ = writeln!(
                md,
                "### `{}:{}-{}`\n",
                caller_ex.file.display(),
                caller_ex.start_line,
                caller_ex.end_line
            );
            let _ = writeln!(
                md,
                "```{caller_lang}\n{}\n```\n",
                crate::report::mask_credentials(&caller_ex.source)
            );
        }
    }

    let _ = writeln!(md, "## Transformation Recipe\n");
    let _ = writeln!(md, "{}\n", capsule.recipe_markdown);

    let _ = writeln!(md, "## Invariants to Preserve\n");
    for inv in &capsule.invariants {
        let _ = writeln!(md, "- {inv}");
    }
    let _ = writeln!(md);

    if let Some(exemplar) = &capsule.exemplar {
        let ex_lang = excerpt_code_fence_lang(&exemplar.file);
        let _ = writeln!(
            md,
            "## Repository Exemplar (`{}:{}-{}`)\n",
            exemplar.file.display(),
            exemplar.start_line,
            exemplar.end_line
        );
        let _ = writeln!(
            md,
            "```{ex_lang}\n{}\n```\n",
            crate::report::mask_credentials(&exemplar.source)
        );
    }

    md
}

fn render_plan_readme_markdown(
    report: &JsonReport,
    commit_sha: &str,
    rows: &[(usize, String, &FixCapsule)],
) -> String {
    let mut md = String::new();
    let s = &report.summary;

    let _ = writeln!(md, "# Dotore Deterministic Remediation Plan\n");
    let _ = writeln!(md, "- **Commit SHA**: `{commit_sha}`");
    let _ = writeln!(md, "- **Health Score**: `{}/100`", s.health_score);
    let _ = writeln!(
        md,
        "- **Scanned**: `{}` file(s), `{}` Subject(s), `{}` Effect Node(s)",
        s.files_scanned, s.subjects_scanned, s.effects_scanned
    );
    let _ = writeln!(
        md,
        "- **Diagnostics**: `{}` total (`{}` autofix, `{}` surgical, `{}` refactor)",
        s.total_diagnostics, s.autofix_count, s.surgical_count, s.refactor_count
    );
    let _ = writeln!(md, "- **Actionable Fix Capsules**: `{}`\n", rows.len());

    if rows.is_empty() {
        let _ = writeln!(
            md,
            "No `Surgical` or `Refactor` Root-Cause Groups require manual or agent remediation."
        );
        return md;
    }

    let _ = writeln!(
        md,
        "## Prioritized Execution Queue (Ordered by Blast Radius)\n"
    );
    let _ = writeln!(
        md,
        "| # | Priority | Blast Score | Rule | Tier | Subject / File | Plan |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|---|");

    for (ordinal, file_name, capsule) in rows {
        let group = report
            .root_cause_groups
            .iter()
            .find(|g| g.id == capsule.root_cause_group_id);
        let subject_label = group
            .and_then(|g| g.subject_name.as_deref())
            .unwrap_or("<module>");
        let _ = writeln!(
            md,
            "| {:03} | `{}` | `{}` | `{}` | `{}` | `{}` (`{}:{}`) | [{}](./{}) |",
            ordinal,
            capsule.blast_radius.tier.as_str(),
            capsule.blast_radius.score,
            capsule.rule.as_str(),
            capsule.tier.as_str(),
            subject_label,
            capsule.subject_excerpt.file.display(),
            capsule.subject_excerpt.start_line,
            file_name,
            file_name
        );
    }

    md
}

fn resolve_git_commit_sha(dir: &Path) -> String {
    let cwd = if dir.exists() { dir } else { Path::new(".") };
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(cwd)
        .output()
        && output.status.success()
    {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        && output.status.success()
    {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }
    "uncommitted".to_string()
}
/// Builds a filtered [`JsonReport`] containing only `selected_diagnostics` and their corresponding
/// [`RootCauseGroup`]s, [`FixCapsule`]s, and summary counts (used by TUI `y`/`a` handoff).
#[must_use]
pub fn filter_report_for_diagnostics(
    report: &JsonReport,
    selected_diagnostics: &[&Diagnostic],
) -> JsonReport {
    let diagnostics: Vec<Diagnostic> = selected_diagnostics.iter().copied().cloned().collect();
    let mut old_to_new: HashMap<usize, usize> = HashMap::with_capacity(selected_diagnostics.len());

    for (new_idx, &sel) in selected_diagnostics.iter().enumerate() {
        if let Some(old_idx) = report
            .diagnostics
            .iter()
            .position(|d| std::ptr::eq(d, sel) || d == sel)
        {
            old_to_new.entry(old_idx).or_insert(new_idx);
        }
    }

    let mut root_cause_groups = Vec::new();
    let mut kept_group_ids: BTreeSet<String> = BTreeSet::new();
    for group in &report.root_cause_groups {
        let remapped: Vec<usize> = group
            .diagnostic_indices
            .iter()
            .filter_map(|old_idx| old_to_new.get(old_idx).copied())
            .collect();
        if !remapped.is_empty() {
            kept_group_ids.insert(group.id.clone());
            root_cause_groups.push(RootCauseGroup {
                blast_radius: BlastRadius {
                    site_count: remapped.len(),
                    ..group.blast_radius
                },
                diagnostic_indices: remapped,
                ..group.clone()
            });
        }
    }

    let fix_capsules: Vec<FixCapsule> = report
        .fix_capsules
        .iter()
        .filter(|c| kept_group_ids.contains(&c.root_cause_group_id))
        .cloned()
        .collect();

    let mut error_count = 0usize;
    let mut warning_count = 0usize;
    let mut autofix_count = 0usize;
    let mut surgical_count = 0usize;
    let mut refactor_count = 0usize;
    let mut affected_files: BTreeSet<&Path> = BTreeSet::new();

    for d in &diagnostics {
        match d.severity {
            RuleSeverity::Error => error_count += 1,
            RuleSeverity::Warning => warning_count += 1,
        }
        match d.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
        affected_files.insert(d.file.as_path());
    }

    let hs = compute_local_health_score(
        &root_cause_groups,
        report.summary.files_scanned,
        report.summary.subjects_scanned,
    );

    let summary = ReportSummary {
        files_scanned: report.summary.files_scanned,
        subjects_scanned: report.summary.subjects_scanned,
        effects_scanned: report.summary.effects_scanned,
        total_diagnostics: diagnostics.len(),
        error_count,
        warning_count,
        affected_file_count: affected_files.len(),
        autofix_count,
        surgical_count,
        refactor_count,
        health_score: hs.score,
        score_label: hs.label,
    };

    JsonReport {
        schema_version: report.schema_version,
        mode: report.mode,
        summary,
        projects: report.projects.clone(),
        diagnostics,
        root_cause_groups,
        fix_capsules,
        diagnostic_fingerprints: report.diagnostic_fingerprints.clone(),
        diff: report.diff.clone(),
        baseline: report.baseline.clone(),
        baseline_degraded: report.baseline_degraded,
    }
}
