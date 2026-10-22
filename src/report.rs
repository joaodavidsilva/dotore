//! Terminal, JSON, and self-contained HTML cascade reporters for `dotore`.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    config::{
        Capability, CapabilityGate, DotoreConfig, PackageRole, WorkspacePackage,
        discover_workspace_packages, resolve_package_for_file,
    },
    diff::{BaselineSummary, GitDiffInfo, ScanMode},
    fixer::FileFixResult,
    graph::ProjectGraph,
    ir::{
        FileContext, FileIr, parse_file_ir,
        types::{compute_line_starts, loc_from_line_starts},
    },
    load_disk_manifests,
    planner::{
        build_fix_capsule, build_root_cause_groups_and_capsules, enrich_cross_file_autofixes,
    },
    rules::{
        BlastRadius, BlastRadiusTier, Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup,
        RuleCategory, RuleId, RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag,
        evaluate_file_in_package, evaluate_project_graph_rules,
        reduced_motion::evaluate_project_reduced_motion, rule_registry,
    },
    scanner::{collect_source_files, collect_style_files},
    score::compute_local_health_score,
};

/// Current version of the machine-readable [`JsonReport`] schema.
pub const JSON_REPORT_SCHEMA_VERSION: u32 = 3;

/// Per-project (workspace package) coverage and health score metadata in [`JsonReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCoverageMetadata {
    /// Package name (`package.json#name` or `"root"`).
    pub name: String,
    /// Root directory of the package.
    pub root_dir: PathBuf,
    /// Inferred package role (`application` or `library`).
    pub role: PackageRole,
    /// Active capabilities detected by the **Capability Gate**.
    pub capabilities: Vec<Capability>,
    /// Sorted list of analyzed file paths belonging to this package.
    pub analyzed_files: Vec<PathBuf>,
    /// Total number of analyzed files in this package.
    pub analyzed_file_count: usize,
    /// Total number of analyzed React **Subjects** in this package.
    pub subjects_scanned: usize,
    /// Number of diagnostics reported in this package.
    pub diagnostic_count: usize,
    /// Local `0..=100` Health Score for this package.
    pub health_score: u32,
    /// Human-readable score label (`"Excellent"`, `"Good"`, `"Needs Attention"`, `"Critical"`).
    pub score_label: String,
    /// Whether the scan of this package completed without skipped checks.
    pub complete: bool,
}

/// Aggregate metrics for a `dotore` scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total source files scanned.
    pub files_scanned: usize,
    /// Total React **Subjects** (components and custom hooks) analyzed.
    pub subjects_scanned: usize,
    /// Total `useEffect` **Effect Nodes** analyzed.
    pub effects_scanned: usize,
    /// Total diagnostics found.
    pub total_diagnostics: usize,
    /// Count of `Error`-severity diagnostics.
    pub error_count: usize,
    /// Count of `Warning`-severity diagnostics.
    pub warning_count: usize,
    /// Count of distinct files with at least one reported diagnostic.
    pub affected_file_count: usize,
    /// Count of `Autofix` diagnostics (`dotore fix`).
    pub autofix_count: usize,
    /// Count of `Surgical` single-**Subject** diagnostics.
    pub surgical_count: usize,
    /// Count of `Refactor` state-model / cross-**Subject** diagnostics.
    pub refactor_count: usize,
    /// Overall React Effect & State health score (`0..=100`).
    pub health_score: u32,
    /// Human-readable health score rating (`"Excellent"`, `"Good"`, `"Needs Attention"`, `"Critical"`).
    pub score_label: String,
}

/// Complete machine-readable report emitted by `dotore check --json` and `--json-out <path>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonReport {
    /// Version of the machine-readable JSON report schema (`3`).
    pub schema_version: u32,
    /// Active scan mode (`full`, `diff`, `staged`, `baseline`).
    pub mode: ScanMode,
    /// Aggregate metrics and local health score.
    pub summary: ReportSummary,
    /// Per-project coverage and capability metadata.
    pub projects: Vec<ProjectCoverageMetadata>,
    /// Individual diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Clustered **Root-Cause Groups** ordered by static **Blast Radius** descending.
    pub root_cause_groups: Vec<RootCauseGroup>,
    /// Self-contained **Fix Capsules** for `Surgical` and `Refactor` **Root-Cause Groups**.
    pub fix_capsules: Vec<FixCapsule>,
    /// Source-token-enriched fingerprints keyed by diagnostic `id`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub diagnostic_fingerprints: BTreeMap<String, String>,
    /// Optional git diff metadata when running a diff or staged scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<GitDiffInfo>,
    /// Optional baseline multiset delta summary when `--baseline` succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineSummary>,
    /// `true` when `--baseline` degraded gracefully to diff mode because base blobs/files were unavailable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub baseline_degraded: bool,
}

/// Writes `report` as pretty-printed JSON to `path`, creating parent directories if needed.
///
/// # Errors
/// Returns an `io::Error` if serializing or writing the file fails.
pub fn write_json_report(report: &JsonReport, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, format!("{json}\n"))
}

/// Builds a [`JsonReport`] from a [`ProjectGraph`], its evaluated [`Diagnostic`]s, and file sources.
#[must_use]
pub(crate) fn build_report(
    graph: &ProjectGraph,
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
) -> JsonReport {
    build_report_with_packages(graph, diagnostics, sources, &[])
}

/// Builds a [`JsonReport`] including per-project coverage metadata for discovered [`WorkspacePackage`]s.
#[must_use]
pub(crate) fn build_report_with_packages(
    graph: &ProjectGraph,
    mut diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
    packages: &[WorkspacePackage],
) -> JsonReport {
    enrich_cross_file_autofixes(graph, &mut diagnostics, sources);

    let files_scanned = graph
        .files
        .iter()
        .filter(|f| {
            !matches!(
                f.path.extension().and_then(|e| e.to_str()),
                Some("css" | "scss" | "html" | "htm")
            )
        })
        .count();
    let subjects_scanned: usize = graph.files.iter().map(|f| f.subjects.len()).sum();
    let effects_scanned: usize = graph
        .files
        .iter()
        .flat_map(|f| &f.subjects)
        .map(|s| s.effect_nodes.len())
        .sum();

    let mut error_count = 0;
    let mut warning_count = 0;
    let mut autofix_count = 0;
    let mut surgical_count = 0;
    let mut refactor_count = 0;
    let mut affected_files: BTreeSet<&Path> = BTreeSet::new();
    let mut diagnostic_fingerprints = BTreeMap::new();

    for diag in &diagnostics {
        affected_files.insert(&diag.file);
        match diag.severity {
            RuleSeverity::Error => error_count += 1,
            RuleSeverity::Warning => warning_count += 1,
        }
        match diag.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
        let src = sources.get(&diag.file).map(String::as_str);
        diagnostic_fingerprints.insert(diag.id(), diag.fingerprint_with_source(src));
    }

    let (root_cause_groups, fix_capsules) =
        build_root_cause_groups_and_capsules(graph, &diagnostics, sources);

    let health = compute_local_health_score(&root_cause_groups, files_scanned, subjects_scanned);
    let projects =
        build_project_coverage_metadata(graph, &diagnostics, &root_cause_groups, packages);

    JsonReport {
        schema_version: JSON_REPORT_SCHEMA_VERSION,
        mode: ScanMode::Full,
        summary: ReportSummary {
            files_scanned,
            subjects_scanned,
            effects_scanned,
            total_diagnostics: diagnostics.len(),
            error_count,
            warning_count,
            affected_file_count: affected_files.len(),
            autofix_count,
            surgical_count,
            refactor_count,
            health_score: health.score,
            score_label: health.label,
        },
        projects,
        diagnostics,
        root_cause_groups,
        fix_capsules,
        diagnostic_fingerprints,
        diff: None,
        baseline: None,
        baseline_degraded: false,
    }
}

fn build_project_coverage_metadata(
    graph: &ProjectGraph,
    diagnostics: &[Diagnostic],
    root_cause_groups: &[RootCauseGroup],
    packages: &[WorkspacePackage],
) -> Vec<ProjectCoverageMetadata> {
    if packages.is_empty() {
        let mut analyzed_files: Vec<PathBuf> = graph.files.iter().map(|f| f.path.clone()).collect();
        analyzed_files.sort();
        let analyzed_file_count = analyzed_files.len();
        let subjects_scanned: usize = graph.files.iter().map(|f| f.subjects.len()).sum();
        let health =
            compute_local_health_score(root_cause_groups, analyzed_file_count, subjects_scanned);
        return vec![ProjectCoverageMetadata {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            role: PackageRole::Application,
            capabilities: vec![Capability::React],
            analyzed_files,
            analyzed_file_count,
            subjects_scanned,
            diagnostic_count: diagnostics.len(),
            health_score: health.score,
            score_label: health.label,
            complete: true,
        }];
    }

    packages
        .iter()
        .map(|pkg| {
            let mut analyzed_files = Vec::new();
            let mut subjects_scanned = 0;
            for file in &graph.files {
                if resolve_package_for_file(&file.path, packages)
                    .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
                {
                    analyzed_files.push(file.path.clone());
                    subjects_scanned += file.subjects.len();
                }
            }
            analyzed_files.sort();
            let analyzed_file_count = analyzed_files.len();
            let diagnostic_count = diagnostics
                .iter()
                .filter(|d| {
                    resolve_package_for_file(&d.file, packages)
                        .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
                })
                .count();
            let pkg_groups: Vec<RootCauseGroup> = root_cause_groups
                .iter()
                .filter(|g| {
                    resolve_package_for_file(&g.file, packages)
                        .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
                })
                .cloned()
                .collect();
            let health =
                compute_local_health_score(&pkg_groups, analyzed_file_count, subjects_scanned);
            let mut capabilities: Vec<Capability> =
                pkg.capability_gate.capabilities.iter().copied().collect();
            capabilities.sort_by_key(|c| c.as_str());

            ProjectCoverageMetadata {
                name: pkg.name.clone(),
                root_dir: pkg.root_dir.clone(),
                role: pkg.capability_gate.package_role,
                capabilities,
                analyzed_files,
                analyzed_file_count,
                subjects_scanned,
                diagnostic_count,
                health_score: health.score,
                score_label: health.label,
                complete: true,
            }
        })
        .collect()
}

/// Formats a human-readable terminal report with **Render Cascade** traces and **Caller Sites**.
#[must_use]
pub fn format_terminal_report(report: &JsonReport) -> String {
    let mut out = String::new();
    let s = &report.summary;

    let _ = writeln!(
        out,
        "dotore  score: {}/100 ({})  files: {}  subjects: {}  effects: {}  findings: {} (autofix: {}, surgical: {}, refactor: {})",
        s.health_score,
        s.score_label,
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.total_diagnostics,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    );
    if let Some(base) = &report.baseline {
        let _ = writeln!(
            out,
            "baseline: {}  introduced: {}  fixed: {}  pre-existing: {}",
            base.baseline_source, base.introduced_count, base.fixed_count, base.preexisting_count
        );
    }
    if report.diagnostics.is_empty() {
        let _ = writeln!(out, "\nNo unnecessary effects or state cascades detected.");
        return out;
    }

    let _ = writeln!(out);
    for diag in &report.diagnostics {
        format_single_diagnostic(&mut out, diag);
    }

    if s.autofix_count > 0 {
        let _ = writeln!(
            out,
            "Run `dotore fix` to automatically apply {} deterministic rewrite(s).",
            s.autofix_count
        );
    }

    out
}

/// Formats the terminal output for `dotore design` (focused UI polish audit, omitting health score).
#[must_use]
pub fn format_design_report(report: &JsonReport) -> String {
    let mut out = String::new();
    let s = &report.summary;

    let _ = writeln!(
        out,
        "dotore design  files: {}  subjects: {}  findings: {} (autofix: {}, surgical: {}, refactor: {})",
        s.files_scanned,
        s.subjects_scanned,
        s.total_diagnostics,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    );

    if report.diagnostics.is_empty() {
        let _ = writeln!(out, "\nNo UI design findings detected.");
        return out;
    }

    let _ = writeln!(out);
    for diag in &report.diagnostics {
        format_single_diagnostic(&mut out, diag);
    }
    out
}

/// Formats the terminal output for `dotore fix` (and `dotore fix --dry-run`).
#[must_use]
pub fn format_fix_report(results: &[FileFixResult], dry_run: bool) -> String {
    if results.is_empty() {
        return "No autofixable diagnostics found.\n".to_string();
    }

    let mut out = String::new();
    let prefix = if dry_run { "[dry-run]" } else { "[fixed]" };
    let mut total_patches = 0;
    for res in results {
        total_patches += res.patches_applied;
        let _ = writeln!(
            out,
            "{prefix} {} ({} patch(es))",
            res.file.display(),
            res.patches_applied
        );
        for desc in &res.descriptions {
            let _ = writeln!(out, "  - {desc}");
        }
    }
    let _ = writeln!(
        out,
        "Applied {total_patches} autofix(es) across {} file(s).",
        results.len()
    );
    out
}

fn format_single_diagnostic(out: &mut String, diag: &Diagnostic) {
    let subject = diag.subject_name.as_deref().unwrap_or("<anonymous>");
    let _ = writeln!(
        out,
        "[{}] ({}) {}:{}:{} in `{}`",
        diag.rule.as_str(),
        diag.tier.as_str(),
        diag.file.display(),
        diag.loc.line,
        diag.loc.column,
        subject
    );
    let _ = writeln!(out, "  {}", diag.message);
    if !diag.cascade_steps.is_empty() {
        let _ = writeln!(out, "  cascade: {}", diag.cascade_steps.join(" -> "));
    }
    for caller in &diag.caller_sites {
        let key_note = if caller.has_key {
            "has key={...}"
        } else {
            "missing key={...}"
        };
        if let Some(parent) = &caller.parent_subject_name {
            let _ = writeln!(
                out,
                "  caller:  {}:{}:{} in `{parent}` (<{} /> {key_note})",
                caller.caller_file.display(),
                caller.loc.line,
                caller.loc.column,
                caller.component_name
            );
        } else {
            let _ = writeln!(
                out,
                "  caller:  {}:{}:{} (<{} /> {key_note})",
                caller.caller_file.display(),
                caller.loc.line,
                caller.loc.column,
                caller.component_name
            );
        }
    }
    if let Some(fix) = &diag.autofix {
        let _ = writeln!(out, "  autofix: {}", fix.description);
    }
    let _ = writeln!(out, "  docs:    {}\n", diag.docs_url);
}

const HTML_REPORT_STYLES: &str = r#"
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: #020617;
    color: #f1f5f9;
    min-height: 100vh;
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
    line-height: 1.5;
  }
  code, .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  .container { max-width: 64rem; margin: 0 auto; padding: 2.5rem 1.5rem; }
  .header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 2rem;
  }
  .eyebrow {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #22d3ee;
    font-weight: 600;
  }
  .title { font-size: 1.875rem; font-weight: 700; margin-top: 0.25rem; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .score-box {
    display: flex;
    align-items: center;
    gap: 1rem;
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 1rem;
    padding: 1rem 1.5rem;
  }
  .score-label { font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; }
  .score-value { font-size: 2.25rem; font-weight: 800; color: #22d3ee; line-height: 1.1; }
  .tier-counts {
    border-left: 1px solid #1e293b;
    padding-left: 1rem;
    font-size: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-weight: 500;
  }
  .text-autofix { color: #34d399; }
  .text-surgical { color: #fbbf24; }
  .text-refactor { color: #fb7185; }
  .cards { margin-top: 2rem; display: flex; flex-direction: column; gap: 1rem; }
  .empty-state {
    border-radius: 0.75rem;
    border: 1px solid rgba(16, 185, 129, 0.3);
    background-color: rgba(6, 78, 59, 0.2);
    padding: 2rem;
    text-align: center;
    color: #6ee7b7;
  }
  .card {
    border-radius: 0.75rem;
    border: 1px solid #1e293b;
    background-color: rgba(15, 23, 42, 0.7);
    padding: 1.25rem;
  }
  .card-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }
  .card-meta { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .muted { font-size: 0.75rem; color: #94a3b8; }
  .badge {
    padding: 0.125rem 0.625rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    border: 1px solid transparent;
  }
  .badge-autofix {
    background-color: rgba(16, 185, 129, 0.2);
    color: #6ee7b7;
    border-color: rgba(16, 185, 129, 0.4);
  }
  .badge-surgical {
    background-color: rgba(245, 158, 11, 0.2);
    color: #fcd34d;
    border-color: rgba(245, 158, 11, 0.4);
  }
  .badge-refactor {
    background-color: rgba(244, 63, 94, 0.2);
    color: #fda4af;
    border-color: rgba(244, 63, 94, 0.4);
  }
  .rule-code { font-size: 0.875rem; font-weight: 600; color: #67e8f9; }
  .message { margin-top: 0.75rem; font-size: 0.875rem; color: #e2e8f0; }
  .cascade { margin-top: 0.75rem; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
  .cascade-step {
    padding: 0.25rem 0.625rem;
    border-radius: 0.375rem;
    background-color: #1e293b;
    color: #e2e8f0;
    font-size: 0.75rem;
  }
  .cascade-arrow { color: #64748b; font-weight: 700; }
  .callers {
    margin-top: 0.75rem;
    border-radius: 0.5rem;
    background-color: rgba(2, 6, 23, 0.6);
    border: 1px solid #1e293b;
    padding: 0.5rem 0.75rem;
  }
  .callers-title { font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.25rem; }
  .callers-list { list-style: none; display: flex; flex-direction: column; gap: 0.25rem; }
  .caller-item { font-size: 0.75rem; color: #cbd5e1; }
  .autofix-box {
    margin-top: 0.75rem;
    border-radius: 0.5rem;
    background-color: rgba(6, 78, 59, 0.3);
    border: 1px solid rgba(16, 185, 129, 0.3);
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    color: #a7f3d0;
  }
  .blast-box {
    margin-top: 0.75rem;
    border-radius: 0.5rem;
    background-color: rgba(15, 23, 42, 0.7);
    border: 1px solid #334155;
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    color: #cbd5e1;
  }
  .badge-blast-p0 {
    background-color: rgba(244, 63, 94, 0.25);
    color: #fda4af;
    border-color: rgba(244, 63, 94, 0.5);
  }
  .badge-blast-p1 {
    background-color: rgba(245, 158, 11, 0.25);
    color: #fcd34d;
    border-color: rgba(245, 158, 11, 0.5);
  }
  .badge-blast-p2 {
    background-color: rgba(56, 189, 248, 0.2);
    color: #7dd3fc;
    border-color: rgba(56, 189, 248, 0.4);
  }
  .badge-blast-p3 {
    background-color: rgba(148, 163, 184, 0.2);
    color: #cbd5e1;
    border-color: rgba(148, 163, 184, 0.4);
  }
  .section-heading {
    margin-top: 1.5rem;
    margin-bottom: 0.75rem;
    font-size: 0.875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #94a3b8;
  }
  .docs-row { margin-top: 0.75rem; font-size: 0.75rem; }
  .docs-link { color: #22d3ee; text-decoration: none; }
  .docs-link:hover { text-decoration: underline; }
"#;

/// Renders a self-contained visual HTML report with **Root-Cause Groups**, static **Blast Radius**
/// (`tier`, `score`, and rationale), **Render Cascade** cards, **Caller Sites**, and `Autofix` previews.
#[must_use]
pub fn render_html_report(report: &JsonReport) -> String {
    let s = &report.summary;
    let mut groups_html = String::new();
    for (idx, group) in report.root_cause_groups.iter().enumerate() {
        append_root_cause_group_card(&mut groups_html, idx + 1, group);
    }
    let groups_section = if groups_html.is_empty() {
        String::new()
    } else {
        format!(
            r#"<h2 class="section-heading">Root-Cause Groups ({})</h2><section class="cards">{groups_html}</section><h2 class="section-heading">Diagnostics ({})</h2>"#,
            report.root_cause_groups.len(),
            report.diagnostics.len()
        )
    };

    let mut cards_html = String::new();
    for (idx, diag) in report.diagnostics.iter().enumerate() {
        let group = report
            .root_cause_groups
            .iter()
            .find(|g| g.diagnostic_indices.contains(&idx));
        append_diagnostic_card(&mut cards_html, idx + 1, diag, group);
    }

    if cards_html.is_empty() {
        cards_html.push_str(
            r#"<div class="empty-state">No unnecessary effects or state cascades detected.</div>"#,
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>dotore: React Effect &amp; State Report</title>
  <style>{HTML_REPORT_STYLES}</style>
</head>
<body>
  <main class="container">
    <header class="header">
      <div>
        <div class="eyebrow">dotore static analysis</div>
        <h1 class="title">React Effect &amp; State Report</h1>
        <p class="subtitle">Scanned {} file(s), {} Subject(s), {} Effect Node(s)</p>
      </div>
      <div class="score-box">
        <div>
          <div class="score-label">Health Score</div>
          <div class="score-value">{}/100</div>
        </div>
        <div class="tier-counts">
          <div class="text-autofix">Autofix: {}</div>
          <div class="text-surgical">Surgical: {}</div>
          <div class="text-refactor">Refactor: {}</div>
        </div>
      </div>
    </header>
    {groups_section}
    <section class="cards">
      {cards_html}
    </section>
  </main>
</body>
</html>"#,
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.health_score,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    )
}

fn blast_tier_badge_class(tier: BlastRadiusTier) -> &'static str {
    match tier {
        BlastRadiusTier::P0 => "badge-blast-p0",
        BlastRadiusTier::P1 => "badge-blast-p1",
        BlastRadiusTier::P2 => "badge-blast-p2",
        BlastRadiusTier::P3 => "badge-blast-p3",
    }
}

fn format_blast_radius_rationale(br: &BlastRadius) -> String {
    format!(
        "frequency: {}, fan-out: {}, cascade depth: {}, sites: {}, files: {}",
        br.render_frequency.as_str(),
        br.fan_out,
        br.cascade_depth,
        br.site_count,
        br.file_count
    )
}

fn append_root_cause_group_card(out: &mut String, index: usize, group: &RootCauseGroup) {
    let tier_class = match group.tier {
        PrescriptionTier::Autofix => "badge-autofix",
        PrescriptionTier::Surgical => "badge-surgical",
        PrescriptionTier::Refactor => "badge-refactor",
    };
    let blast_class = blast_tier_badge_class(group.blast_radius.tier);
    let subject = html_escape(group.subject_name.as_deref().unwrap_or("<module>"));
    let file_loc = format!(
        "{}:{}:{}",
        html_escape(&group.file.display().to_string()),
        group.loc.line,
        group.loc.column
    );
    let rationale = html_escape(&format_blast_radius_rationale(&group.blast_radius));

    let _ = writeln!(
        out,
        r#"<article class="card">
  <div class="card-header">
    <div class="card-meta">
      <span class="muted mono">RCG #{index}</span>
      <span class="badge {blast_class}">{} (score {})</span>
      <span class="badge {tier_class}">{}</span>
      <code class="rule-code">{}</code>
      <span class="muted">in <code>{subject}</code></span>
    </div>
    <code class="muted">{file_loc}</code>
  </div>
  <p class="message">{}</p>
  <div class="blast-box mono">Root-Cause Group <code>{}</code> &middot; Blast Radius: {} (score {}) &mdash; {rationale}</div>
</article>"#,
        group.blast_radius.tier.as_str(),
        group.blast_radius.score,
        group.tier.as_str(),
        group.rule.as_str(),
        html_escape(&group.message),
        html_escape(&group.id),
        group.blast_radius.tier.as_str(),
        group.blast_radius.score,
    );
}

fn append_diagnostic_card(
    out: &mut String,
    index: usize,
    diag: &Diagnostic,
    group: Option<&RootCauseGroup>,
) {
    let badge_class = match diag.tier {
        PrescriptionTier::Autofix => "badge-autofix",
        PrescriptionTier::Surgical => "badge-surgical",
        PrescriptionTier::Refactor => "badge-refactor",
    };
    let subject = html_escape(diag.subject_name.as_deref().unwrap_or("<anonymous>"));
    let file_loc = format!(
        "{}:{}:{}",
        html_escape(&diag.file.display().to_string()),
        diag.loc.line,
        diag.loc.column
    );
    let blast_badge = group.map_or_else(String::new, |g| {
        let b_class = blast_tier_badge_class(g.blast_radius.tier);
        format!(
            r#"<span class="badge {b_class}">{} (score {})</span>"#,
            g.blast_radius.tier.as_str(),
            g.blast_radius.score
        )
    });
    let blast_html = group.map_or_else(String::new, |g| {
        let rationale = html_escape(&format_blast_radius_rationale(&g.blast_radius));
        format!(
            r#"<div class="blast-box mono">Blast Radius: {} (score {}) &mdash; {rationale}</div>"#,
            g.blast_radius.tier.as_str(),
            g.blast_radius.score
        )
    });
    let cascade_html = render_cascade_steps_html(&diag.cascade_steps);
    let callers_html = render_caller_sites_html(diag);
    let autofix_html = render_autofix_html(diag);
    let docs_url = html_escape(diag.docs_url);

    let _ = writeln!(
        out,
        r#"<article class="card">
  <div class="card-header">
    <div class="card-meta">
      <span class="muted mono">#{index}</span>
      {blast_badge}
      <span class="badge {badge_class}">{}</span>
      <code class="rule-code">{}</code>
      <span class="muted">in <code>{subject}</code></span>
    </div>
    <code class="muted">{file_loc}</code>
  </div>
  <p class="message">{}</p>
  {blast_html}
  {cascade_html}
  {callers_html}
  {autofix_html}
  <div class="docs-row"><a class="docs-link" href="{docs_url}">{docs_url}</a></div>
</article>"#,
        diag.tier.as_str(),
        diag.rule.as_str(),
        html_escape(&diag.message),
    );
}

fn render_cascade_steps_html(steps: &[String]) -> String {
    if steps.is_empty() {
        return String::new();
    }
    let items = steps
        .iter()
        .map(|step| {
            format!(
                r#"<span class="cascade-step mono">{}</span>"#,
                html_escape(step)
            )
        })
        .collect::<Vec<_>>()
        .join(r#"<span class="cascade-arrow">&rarr;</span>"#);
    format!(r#"<div class="cascade">{items}</div>"#)
}

fn render_caller_sites_html(diag: &Diagnostic) -> String {
    if diag.caller_sites.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for caller in &diag.caller_sites {
        let key_note = if caller.has_key {
            "has key={...}"
        } else {
            "missing key={...}"
        };
        let parent_part = caller
            .parent_subject_name
            .as_deref()
            .map_or_else(String::new, |parent| {
                format!(" in <code>{}</code>", html_escape(parent))
            });
        let _ = writeln!(
            rows,
            r#"<li class="caller-item mono"><code>{}:{}:{}</code>{parent_part} (<code>&lt;{} /&gt;</code> {key_note})</li>"#,
            html_escape(&caller.caller_file.display().to_string()),
            caller.loc.line,
            caller.loc.column,
            html_escape(&caller.component_name),
        );
    }
    format!(
        r#"<div class="callers"><div class="callers-title">Caller Sites</div><ul class="callers-list">{rows}</ul></div>"#
    )
}

fn render_autofix_html(diag: &Diagnostic) -> String {
    diag.autofix.as_ref().map_or_else(String::new, |fix| {
        format!(
            r#"<div class="autofix-box mono">Autofix: {}</div>"#,
            html_escape(&fix.description)
        )
    })
}
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Writes the HTML report to `output` (or an isolated temp directory) and optionally opens it in the browser.
///
/// # Errors
/// Returns an `io::Error` if creating the report file fails.
pub fn write_and_open_html_report(
    report: &JsonReport,
    output: Option<&Path>,
    open_browser: bool,
) -> io::Result<PathBuf> {
    let target_path = if let Some(out_path) = output {
        if let Some(parent) = out_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        out_path.to_path_buf()
    } else {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("dotore-report-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        dir.join("dotore-report.html")
    };

    let html = render_html_report(report);
    fs::write(&target_path, html)?;

    if open_browser {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(target_os = "windows") {
            "start"
        } else {
            "xdg-open"
        };
        let _ = Command::new(opener).arg(&target_path).status();
    }

    Ok(target_path)
}

/// Filter options for `dotore rules list` ([`build_rule_catalog`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesListOptions {
    /// Optional category filter (case-insensitive, e.g. `"Performance"`, `"Bugs"`).
    pub category: Option<String>,
    /// Optional behavioral tag filter (e.g. `"design"`, `"test-noise"`, `"r3f"`).
    pub tag: Option<String>,
    /// Optional framework/capability filter (e.g. `"react"`, `"nextjs"`, `"global"`).
    pub framework: Option<String>,
    /// When `true`, include only rules with an active configuration override (`source != "default"` and `source != "opt-in"`).
    pub configured: bool,
}

/// Machine-readable catalog and explanation entry for a single rule in `dotore rules list` and `dotore rules explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCatalogEntry {
    /// Qualified rule key (`"dotore/no-derived-state"`).
    pub key: String,
    /// Canonical short rule identifier (`"no-derived-state"`).
    pub id: String,
    /// Legacy rule aliases accepted in config and inline suppressions.
    pub aliases: Vec<String>,
    /// Short human-readable headline.
    pub title: String,
    /// Display category (`"Bugs"`, `"Performance"`, `"Accessibility"`, `"Security"`, `"Maintainability"`).
    pub category: String,
    /// Framework or capability gate (`"react"`, `"nextjs"`, `"tanstack-query"`, `"global"`, etc.).
    pub framework: String,
    /// Behavioral tags attached to this rule.
    pub tags: Vec<String>,
    /// Default **Prescription Tier** (`autofix`, `surgical`, `refactor`).
    pub tier: PrescriptionTier,
    /// Default severity in config vocabulary (`"error"` or `"warn"`).
    pub default_severity: String,
    /// Whether the rule is enabled by default in standard scans.
    pub default_enabled: bool,
    /// Effective severity under the active [`DotoreConfig`] (`"error"`, `"warn"`, or `"off"`).
    pub severity: String,
    /// Configuration layer that determined `severity` (`"default"`, `"rules"`, `"categories"`, `"ignore.rules"`, `"ignore.tags"`, `"opt-in"`, `"custom-rules-only"`, `"warnings"`).
    pub source: String,
    /// Runtime problem description and rationale.
    pub rationale: String,
    /// Compiled-in remediation recipe in Markdown.
    pub recipe_markdown: String,
    /// Problematic "Before" code example.
    pub before_example: String,
    /// Idiomatic "After" code example.
    pub after_example: String,
    /// Ready-to-paste `dotore.config.json` configuration snippet.
    pub config_snippet: String,
    /// Official documentation URL.
    pub docs_url: String,
}

/// Builds the filtered [`RuleCatalogEntry`] list for `dotore rules list`.
#[must_use]
pub fn build_rule_catalog(
    config: &DotoreConfig,
    filter: &RulesListOptions,
) -> Vec<RuleCatalogEntry> {
    let cat_filter = filter
        .category
        .as_deref()
        .and_then(RuleCategory::parse)
        .map(RuleCategory::as_str);
    let raw_cat_lower = filter
        .category
        .as_ref()
        .map(|c| c.trim().to_ascii_lowercase());
    let tag_filter = filter.tag.as_ref().map(|t| t.trim().to_ascii_lowercase());
    let fw_filter = filter
        .framework
        .as_ref()
        .map(|f| f.trim().to_ascii_lowercase());

    let mut out = Vec::new();
    for meta in rule_registry() {
        if let Some(expected_cat) = cat_filter {
            if meta.category.as_str() != expected_cat {
                continue;
            }
        } else if let Some(raw_cat) = &raw_cat_lower
            && meta.category.as_str().to_ascii_lowercase() != *raw_cat
        {
            continue;
        }

        if let Some(tag_q) = &tag_filter
            && !meta
                .tags
                .iter()
                .any(|t| t.as_str().eq_ignore_ascii_case(tag_q))
        {
            continue;
        }

        let fw_label = framework_label(meta);
        if let Some(fw_q) = &fw_filter {
            let matches_fw = fw_label.eq_ignore_ascii_case(fw_q)
                || (fw_q == "global" && meta.capability_gate.requires.is_empty())
                || meta
                    .capability_gate
                    .requires
                    .iter()
                    .any(|cap| cap.as_str().eq_ignore_ascii_case(fw_q));
            if !matches_fw {
                continue;
            }
        }

        let entry = build_catalog_entry(meta, config);
        if filter.configured && (entry.source == "default" || entry.source == "opt-in") {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Resolves a rule by canonical ID (`"no-derived-state"`), qualified key (`"dotore/no-derived-state"`),
/// or legacy alias (`"effect/no-derived-state"`, `"react/jsx-key"`) and returns its [`RuleCatalogEntry`].
#[must_use]
pub fn explain_rule(rule_query: &str, config: &DotoreConfig) -> Option<RuleCatalogEntry> {
    let rule_id = RuleId::parse(rule_query)?;
    Some(build_catalog_entry(rule_id.metadata(), config))
}

/// Formats the terminal output for `dotore rules list`.
#[must_use]
pub fn format_rule_catalog_text(entries: &[RuleCatalogEntry]) -> String {
    if entries.is_empty() {
        return "No rules match the given filters.\n".to_string();
    }

    let mut by_category: HashMap<&str, Vec<&RuleCatalogEntry>> = HashMap::new();
    for entry in entries {
        by_category
            .entry(entry.category.as_str())
            .or_default()
            .push(entry);
    }

    let mut categories: Vec<&str> = by_category.keys().copied().collect();
    categories.sort_unstable();

    let mut out = String::new();
    for cat in categories {
        let Some(mut rows) = by_category.remove(cat) else {
            continue;
        };
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        let _ = writeln!(out, "{cat} ({})", rows.len());
        for row in rows {
            let tags_suffix = if row.tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", row.tags.join(", "))
            };
            let _ = writeln!(
                out,
                "  {:<6} {} ({}) [tier: {}]{tags_suffix}",
                row.severity,
                row.key,
                row.source,
                row.tier.as_str()
            );
        }
        let _ = writeln!(out);
    }
    let plural = if entries.len() == 1 { "" } else { "s" };
    let _ = writeln!(out, "{} rule{plural} shown.", entries.len());
    out
}

/// Formats the terminal output for `dotore rules explain <rule>`.
#[must_use]
pub fn format_rule_explanation_text(entry: &RuleCatalogEntry) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} — {}\n", entry.key, entry.title);
    let _ = writeln!(out, "  {:<18}{}", "Category", entry.category);
    let _ = writeln!(
        out,
        "  {:<18}{}",
        "Default severity", entry.default_severity
    );
    let _ = writeln!(
        out,
        "  {:<18}{} ({})",
        "Current severity", entry.severity, entry.source
    );
    let _ = writeln!(out, "  {:<18}{}", "Prescription Tier", entry.tier.as_str());
    let _ = writeln!(out, "  {:<18}{}", "Framework", entry.framework);
    let tags_display = if entry.tags.is_empty() {
        "none".to_string()
    } else {
        entry.tags.join(", ")
    };
    let _ = writeln!(out, "  {:<18}{tags_display}", "Tags");
    if !entry.aliases.is_empty() {
        let _ = writeln!(out, "  {:<18}{}", "Aliases", entry.aliases.join(", "));
    }
    let enabled_display = if entry.default_enabled {
        "yes"
    } else {
        "no (opt-in)"
    };
    let _ = writeln!(out, "  {:<18}{enabled_display}", "Default enabled");

    let _ = writeln!(out, "\nWhy it matters");
    for line in entry.rationale.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nBefore (anti-pattern)");
    for line in entry.before_example.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nAfter (recommended)");
    for line in entry.after_example.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nConfiguration snippet (dotore.config.json)");
    for line in entry.config_snippet.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nConfigure via CLI");
    let _ = writeln!(out, "  dotore rules disable {}", entry.key);
    let _ = writeln!(out, "  dotore rules enable {} --severity error", entry.key);
    let _ = writeln!(out, "  dotore rules set {} warn", entry.key);

    let _ = writeln!(out, "\nLearn more");
    let _ = writeln!(out, "  {}", entry.docs_url);
    out
}

fn build_catalog_entry(meta: &RuleMetadata, config: &DotoreConfig) -> RuleCatalogEntry {
    let default_sev_str = match meta.default_severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warn",
    };
    let (eff_sev, source) = resolve_catalog_severity_and_source(meta, config);
    let (before_example, after_example) = rule_before_after_examples(meta);
    let rationale = format!("{}: {}", meta.title, meta.recipe_markdown);
    let config_snippet = format!(
        "{{\n  \"rules\": {{\n    \"{}\": \"{}\"\n  }}\n}}",
        meta.qualified_key, default_sev_str
    );

    RuleCatalogEntry {
        key: meta.qualified_key.to_string(),
        id: meta.canonical_id.to_string(),
        aliases: meta
            .legacy_aliases
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        title: meta.title.to_string(),
        category: meta.category.as_str().to_string(),
        framework: framework_label(meta).to_string(),
        tags: meta.tags.iter().map(|t| t.as_str().to_string()).collect(),
        tier: meta.default_tier,
        default_severity: default_sev_str.to_string(),
        default_enabled: meta.default_enabled,
        severity: eff_sev.to_string(),
        source: source.to_string(),
        rationale,
        recipe_markdown: meta.recipe_markdown.to_string(),
        before_example,
        after_example,
        config_snippet,
        docs_url: meta.docs_url.to_string(),
    }
}

fn framework_label(meta: &RuleMetadata) -> &'static str {
    if meta.capability_gate.requires.is_empty() {
        return "global";
    }
    for &cap in meta.capability_gate.requires {
        if cap != Capability::React {
            return cap.as_str();
        }
    }
    meta.capability_gate.requires[0].as_str()
}

fn resolve_catalog_severity_and_source(
    meta: &RuleMetadata,
    config: &DotoreConfig,
) -> (&'static str, &'static str) {
    if meta.tags.iter().any(|&t| config.is_tag_ignored(t)) {
        return ("off", "ignore.tags");
    }
    if config
        .ignore
        .rules
        .iter()
        .any(|r| RuleId::parse(r) == Some(meta.id))
    {
        return ("off", "ignore.rules");
    }
    if let Some(ov) = config.explicit_rule_override(meta.id) {
        let sev = match ov {
            RuleSeverityOverride::Error => "error",
            RuleSeverityOverride::Warn => "warn",
            RuleSeverityOverride::Off => "off",
        };
        return (sev, "rules");
    }
    if config.custom_rules_only && meta.originally_external {
        return ("off", "custom-rules-only");
    }
    if !meta.default_enabled {
        return ("off", "opt-in");
    }
    if let Some(cat_ov) = config.category_override(meta.category) {
        let sev = match cat_ov {
            RuleSeverityOverride::Error => "error",
            RuleSeverityOverride::Warn => "warn",
            RuleSeverityOverride::Off => "off",
        };
        return (sev, "categories");
    }
    let default_sev = match meta.default_severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warn",
    };
    if !config.warnings && meta.default_severity == RuleSeverity::Warning {
        return ("off", "warnings");
    }
    (default_sev, "default")
}

fn rule_before_after_examples(meta: &RuleMetadata) -> (String, String) {
    match meta.canonical_id {
        "no-derived-state" => (
            "const [fullName, setFullName] = useState('');\nuseEffect(() => {\n  setFullName(`${firstName} ${lastName}`);\n}, [firstName, lastName]);".to_string(),
            "const fullName = `${firstName} ${lastName}`;".to_string(),
        ),
        "no-chain-state-updates" => (
            "useEffect(() => {\n  setStep2(step1 + 1);\n}, [step1]);".to_string(),
            "const step2 = step1 + 1;".to_string(),
        ),
        "no-event-handler" => (
            "useEffect(() => {\n  if (submitted) submitOrder(cart);\n}, [submitted, cart]);".to_string(),
            "function handleCheckout() {\n  submitOrder(cart);\n}".to_string(),
        ),
        "no-reset-all-state-on-prop-change" => (
            "function Profile({ userId }: { userId: string }) {\n  const [draft, setDraft] = useState('');\n  useEffect(() => { setDraft(''); }, [userId]);\n}".to_string(),
            "<Profile key={userId} userId={userId} />".to_string(),
        ),
        "no-adjust-state-on-prop-change" => (
            "useEffect(() => {\n  setSelected(null);\n}, [items]);".to_string(),
            "const selected = items.find(i => i.id === selectedId) ?? null;".to_string(),
        ),
        "no-initialize-state" => (
            "const [count, setCount] = useState(0);\nuseEffect(() => {\n  setCount(initialCount);\n}, []);".to_string(),
            "const [count, setCount] = useState(initialCount);".to_string(),
        ),
        "no-pass-live-state-to-parent" | "no-pass-data-to-parent" => (
            "useEffect(() => {\n  onChange(value);\n}, [value, onChange]);".to_string(),
            "function updateValue(next: string) {\n  setValue(next);\n  onChange(next);\n}".to_string(),
        ),
        "no-external-store-subscription" => (
            "useEffect(() => {\n  const onResize = () => setWidth(window.innerWidth);\n  window.addEventListener('resize', onResize);\n  return () => window.removeEventListener('resize', onResize);\n}, []);".to_string(),
            "const width = useSyncExternalStore(subscribeResize, () => window.innerWidth, () => 0);".to_string(),
        ),
        "no-fetch-in-effect" => (
            "useEffect(() => {\n  fetch(url).then(r => r.json()).then(setData);\n}, [url]);".to_string(),
            "useEffect(() => {\n  const ctrl = new AbortController();\n  fetch(url, { signal: ctrl.signal }).then(r => r.json()).then(setData);\n  return () => ctrl.abort();\n}, [url]);".to_string(),
        ),
        _ => (
            format!("// Anti-pattern triggering `{}`:\n// {}", meta.qualified_key, meta.title),
            format!("// Recommended fix ({}):\n// {}", meta.default_tier.as_str(), meta.recipe_markdown),
        ),
    }
}

/// Parsed `<file>:<line>` (and optional `:<column>`) argument for `dotore why`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyLocation {
    /// File path component.
    pub file: PathBuf,
    /// 1-based line number.
    pub line: u32,
    /// Optional 1-based column number.
    pub column: Option<u32>,
}

/// Single diagnostic or suppression/gate explanation produced by `dotore why <file:line>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhyEntry {
    /// Status of the finding at this location (`"active"`, `"suppressed"`, `"disabled"`, or `"gated"`).
    pub status: String,
    /// Qualified rule key (`"dotore/no-derived-state"`).
    pub rule: String,
    /// Rule category.
    pub category: RuleCategory,
    /// Severity (`error` or `warning`).
    pub severity: RuleSeverity,
    /// **Prescription Tier** (`autofix`, `surgical`, `refactor`).
    pub tier: PrescriptionTier,
    /// Diagnostic message.
    pub message: String,
    /// Human-readable explanation of why the diagnostic fired or why a suppression/config/Capability Gate applied or did not apply.
    pub explanation: String,
    /// Numbered source code frame around the target line.
    pub code_frame: String,
    /// **Render Cascade** steps, if any.
    pub cascade_steps: Vec<String>,
    /// Static **Blast Radius** score and priority tier.
    pub blast_radius: BlastRadius,
    /// Complete self-contained **Fix Capsule** for this finding.
    pub fix_capsule: FixCapsule,
}

/// Complete report returned by [`explain_location`] (`dotore why <file:line>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhyReport {
    /// Requested file path.
    pub file: PathBuf,
    /// Requested 1-based line number.
    pub line: u32,
    /// Optional requested 1-based column number.
    pub column: Option<u32>,
    /// Matched active, suppressed, disabled, or capability-gated findings at `<file:line>`.
    pub entries: Vec<WhyEntry>,
    /// High-level summary note when no entries matched or when explaining line status.
    pub summary_note: String,
}

/// Parses a `<file:line>` or `<file:line:column>` CLI location string.
///
/// # Errors
/// Returns an error message if `input` does not contain a valid `<file>:<line>` pair.
pub fn parse_why_location(input: &str) -> Result<WhyLocation, String> {
    let trimmed = input.trim();
    let Some((prefix1, last_seg)) = trimmed.rsplit_once(':') else {
        return Err(format!(
            "Invalid location {input:?}; expected `<file:line>` or `<file:line:column>`."
        ));
    };
    let Ok(last_num) = last_seg.parse::<u32>() else {
        return Err(format!(
            "Invalid line number in {input:?}; expected `<file:line>`."
        ));
    };
    if last_num == 0 || prefix1.is_empty() {
        return Err(format!(
            "Invalid location {input:?}; line number must be >= 1."
        ));
    }

    if let Some((file_part, mid_seg)) = prefix1.rsplit_once(':')
        && !file_part.is_empty()
        && let Ok(line_num) = mid_seg.parse::<u32>()
        && line_num >= 1
    {
        return Ok(WhyLocation {
            file: PathBuf::from(file_part),
            line: line_num,
            column: Some(last_num),
        });
    }

    Ok(WhyLocation {
        file: PathBuf::from(prefix1),
        line: last_num,
        column: None,
    })
}

/// Explains why a diagnostic fired (or why a rule, inline suppression, config, or **Capability Gate**
/// did or did not apply) at `location_arg` (`<file:line>`) under `cwd`, including its complete [`FixCapsule`].
///
/// # Errors
/// Returns an error string if `location_arg` is malformed or the target file cannot be read.
pub fn explain_location(location_arg: &str, cwd: &Path) -> Result<WhyReport, String> {
    let parsed_loc = parse_why_location(location_arg)?;
    let resolved_file = if parsed_loc.file.is_absolute() {
        parsed_loc.file.clone()
    } else {
        cwd.join(&parsed_loc.file)
    };
    if !resolved_file.is_file() {
        return Err(format!(
            "Target file `{}` does not exist.",
            resolved_file.display()
        ));
    }

    let packages = discover_workspace_packages(cwd);
    let mut discovered_files = collect_source_files(&[cwd.to_path_buf()], true);
    for style_path in collect_style_files(&[cwd.to_path_buf()]) {
        if !discovered_files.contains(&style_path) {
            discovered_files.push(style_path);
        }
    }
    if !discovered_files.contains(&resolved_file) {
        discovered_files.push(resolved_file.clone());
    }

    let mut sources: HashMap<PathBuf, String> = HashMap::new();
    let mut file_irs: Vec<FileIr> = Vec::new();
    for path in discovered_files {
        if let Ok(src) = fs::read_to_string(&path) {
            file_irs.push(parse_file_ir(&path, &src));
            sources.insert(path, src);
        }
    }

    let manifests = load_disk_manifests(cwd, &packages, &sources);
    let graph = ProjectGraph::build_with_manifests(file_irs, manifests);
    let Some(target_file_ir) = graph.files.iter().find(|f| f.path == resolved_file) else {
        return Err(format!(
            "Failed to parse target file `{}`.",
            resolved_file.display()
        ));
    };
    let target_source = sources.get(&resolved_file).cloned().unwrap_or_default();
    let line_starts = compute_line_starts(&target_source);

    let default_pkg;
    let pkg = if let Some(found) = resolve_package_for_file(&resolved_file, &packages) {
        found
    } else {
        default_pkg = crate::config::WorkspacePackage {
            name: "root".to_string(),
            root_dir: cwd.to_path_buf(),
            capability_gate: CapabilityGate::discover(cwd),
            config: crate::config::load_config_from_dir(cwd),
        };
        &default_pkg
    };

    // 1. Evaluate target file + project-graph rules under active package config & capability gate
    let mut active_diags = Vec::new();
    evaluate_file_in_package(
        &graph,
        target_file_ir,
        &pkg.root_dir,
        &pkg.capability_gate,
        &pkg.config,
        None,
        &mut active_diags,
    );
    let active_pkgs = if packages.is_empty() {
        vec![pkg.clone()]
    } else {
        packages.clone()
    };
    let mut active_graph_diags = Vec::new();
    evaluate_project_graph_rules(&graph, &active_pkgs, None, &mut active_graph_diags);
    evaluate_project_reduced_motion(&graph, &active_pkgs, None, &mut active_graph_diags);
    active_diags.extend(
        active_graph_diags
            .into_iter()
            .filter(|d| d.file == resolved_file),
    );
    enrich_cross_file_autofixes(&graph, &mut active_diags, &sources);

    // 2. Evaluate target file + project-graph rules with an unrestricted probe (all rules, all capabilities, no inline disables)
    let all_rules: Vec<RuleId> = rule_registry().iter().map(|m| m.id).collect();
    let mut permissive_cfg = pkg.config.clone();
    permissive_cfg.respect_inline_disables = false;
    permissive_cfg.custom_rules_only = false;
    permissive_cfg.warnings = true;
    permissive_cfg.rules.clear();
    permissive_cfg.categories.clear();
    permissive_cfg.ignore = crate::config::IgnoreConfig::default();
    let permissive_gate = CapabilityGate::default_react();
    let mut probe_diags = Vec::new();
    evaluate_file_in_package(
        &graph,
        target_file_ir,
        &pkg.root_dir,
        &permissive_gate,
        &permissive_cfg,
        Some(&all_rules),
        &mut probe_diags,
    );
    let permissive_pkg = crate::config::WorkspacePackage {
        name: pkg.name.clone(),
        root_dir: pkg.root_dir.clone(),
        capability_gate: permissive_gate,
        config: permissive_cfg,
    };
    let mut probe_graph_diags = Vec::new();
    evaluate_project_graph_rules(
        &graph,
        std::slice::from_ref(&permissive_pkg),
        Some(&all_rules),
        &mut probe_graph_diags,
    );
    evaluate_project_reduced_motion(
        &graph,
        std::slice::from_ref(&permissive_pkg),
        Some(&all_rules),
        &mut probe_graph_diags,
    );
    probe_diags.extend(
        probe_graph_diags
            .into_iter()
            .filter(|d| d.file == resolved_file),
    );
    enrich_cross_file_autofixes(&graph, &mut probe_diags, &sources);

    let active_at_line: Vec<Diagnostic> = active_diags
        .into_iter()
        .filter(|d| diagnostic_matches_line(target_file_ir, d, &line_starts, parsed_loc.line))
        .collect();

    let mut entries = Vec::new();
    if !active_at_line.is_empty() {
        let (groups, _) = build_root_cause_groups_and_capsules(&graph, &active_at_line, &sources);
        for (idx, diag) in active_at_line.iter().enumerate() {
            let group = groups
                .iter()
                .find(|g| g.diagnostic_indices.contains(&idx))
                .unwrap_or(&groups[0]);
            let capsule = build_fix_capsule(&graph, group, &active_at_line, &sources);
            let mismatch_note = detect_mismatched_inline_suppression(target_file_ir, diag);
            let explanation = if let Some(note) = mismatch_note {
                format!(
                    "Diagnostic `{}` fired at {}:{}. {note}",
                    diag.rule.metadata().qualified_key,
                    parsed_loc.file.display(),
                    diag.loc.line
                )
            } else {
                format!(
                    "Diagnostic `{}` fired at {}:{} because `{}` triggered rule `{}`.",
                    diag.rule.metadata().qualified_key,
                    parsed_loc.file.display(),
                    diag.loc.line,
                    diag.target_name,
                    diag.rule.as_str()
                )
            };
            entries.push(WhyEntry {
                status: "active".to_string(),
                rule: diag.rule.metadata().qualified_key.to_string(),
                category: diag.category,
                severity: diag.severity,
                tier: diag.tier,
                message: diag.message.clone(),
                explanation,
                code_frame: render_code_frame(&target_source, diag.loc.line),
                cascade_steps: diag.cascade_steps.clone(),
                blast_radius: group.blast_radius.clone(),
                fix_capsule: capsule,
            });
        }
    } else {
        let probe_at_line: Vec<Diagnostic> = probe_diags
            .into_iter()
            .filter(|d| diagnostic_matches_line(target_file_ir, d, &line_starts, parsed_loc.line))
            .collect();
        if !probe_at_line.is_empty() {
            let (groups, _) =
                build_root_cause_groups_and_capsules(&graph, &probe_at_line, &sources);
            for (idx, diag) in probe_at_line.iter().enumerate() {
                let group = groups
                    .iter()
                    .find(|g| g.diagnostic_indices.contains(&idx))
                    .unwrap_or(&groups[0]);
                let capsule = build_fix_capsule(&graph, group, &probe_at_line, &sources);
                let (status, explanation) = diagnose_why_not_active(
                    diag,
                    target_file_ir,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                );
                entries.push(WhyEntry {
                    status,
                    rule: diag.rule.metadata().qualified_key.to_string(),
                    category: diag.category,
                    severity: diag.severity,
                    tier: diag.tier,
                    message: diag.message.clone(),
                    explanation,
                    code_frame: render_code_frame(&target_source, diag.loc.line),
                    cascade_steps: diag.cascade_steps.clone(),
                    blast_radius: group.blast_radius.clone(),
                    fix_capsule: capsule,
                });
            }
        }
    }

    let summary_note = if !entries.is_empty() {
        format!(
            "{} finding(s) explained at {}:{}.",
            entries.len(),
            parsed_loc.file.display(),
            parsed_loc.line
        )
    } else if let Some(unused_dir) = target_file_ir
        .suppressions
        .line_directives
        .iter()
        .find(|d| d.target_line == parsed_loc.line || d.target_line == parsed_loc.line + 1)
    {
        format!(
            "No diagnostic fired at {}:{}; inline suppression comment (rules: {:?}) had no matching finding to suppress.",
            parsed_loc.file.display(),
            parsed_loc.line,
            unused_dir.rules
        )
    } else {
        format!(
            "No diagnostics fired (and no suppressed or gated rules matched) at {}:{}.",
            parsed_loc.file.display(),
            parsed_loc.line
        )
    };

    Ok(WhyReport {
        file: parsed_loc.file,
        line: parsed_loc.line,
        column: parsed_loc.column,
        entries,
        summary_note,
    })
}

/// Formats a [`WhyReport`] (`dotore why <file:line>`) for terminal output.
#[must_use]
pub fn format_why_report_text(report: &WhyReport) -> String {
    let mut out = String::new();
    if report.entries.is_empty() {
        let _ = writeln!(out, "{}", report.summary_note);
        return out;
    }

    for entry in &report.entries {
        let _ = writeln!(
            out,
            "[{}] {} ({}, tier: {}, category: {})",
            entry.status,
            entry.rule,
            entry.severity.as_str(),
            entry.tier.as_str(),
            entry.category.as_str()
        );
        let _ = writeln!(out, "  Message:     {}", entry.message);
        let _ = writeln!(out, "  Explanation: {}", entry.explanation);
        let _ = writeln!(
            out,
            "  Blast Radius: {} (score: {}, frequency: {}, fan-out: {}, cascade depth: {})",
            entry.blast_radius.tier.as_str(),
            entry.blast_radius.score,
            entry.blast_radius.render_frequency.as_str(),
            entry.blast_radius.fan_out,
            entry.blast_radius.cascade_depth
        );
        if !entry.cascade_steps.is_empty() {
            let _ = writeln!(out, "  Cascade:     {}", entry.cascade_steps.join(" -> "));
        }
        if !entry.code_frame.is_empty() {
            let _ = writeln!(out, "\n  Code Frame:");
            for line in entry.code_frame.lines() {
                let _ = writeln!(out, "    {line}");
            }
        }
        let _ = writeln!(
            out,
            "\n  Fix Capsule ({}):",
            entry.fix_capsule.root_cause_group_id
        );
        let _ = writeln!(
            out,
            "    Subject Excerpt ({}:{}-{}):",
            entry.fix_capsule.subject_excerpt.file.display(),
            entry.fix_capsule.subject_excerpt.start_line,
            entry.fix_capsule.subject_excerpt.end_line
        );
        for line in entry.fix_capsule.subject_excerpt.source.lines() {
            let _ = writeln!(out, "      {line}");
        }
        if !entry.fix_capsule.caller_site_excerpts.is_empty() {
            let _ = writeln!(out, "    Caller Site Excerpts:");
            for caller in &entry.fix_capsule.caller_site_excerpts {
                let _ = writeln!(
                    out,
                    "      {}:{}-{}: {}",
                    caller.file.display(),
                    caller.start_line,
                    caller.end_line,
                    caller.source.trim()
                );
            }
        }
        let _ = writeln!(
            out,
            "    Recipe:\n      {}",
            entry.fix_capsule.recipe_markdown
        );
        if !entry.fix_capsule.invariants.is_empty() {
            let _ = writeln!(
                out,
                "    Invariants: {}",
                entry.fix_capsule.invariants.join("; ")
            );
        }
        if let Some(ex) = &entry.fix_capsule.exemplar {
            let _ = writeln!(
                out,
                "    Repository Exemplar ({}:{}-{}):",
                ex.file.display(),
                ex.start_line,
                ex.end_line
            );
            for line in ex.source.lines() {
                let _ = writeln!(out, "      {line}");
            }
        }
        let _ = writeln!(out);
    }
    out
}

fn diagnostic_matches_line(
    file_ir: &FileIr,
    diag: &Diagnostic,
    line_starts: &[u32],
    target_line: u32,
) -> bool {
    if diag.loc.line == target_line {
        return true;
    }
    let start_line = loc_from_line_starts(line_starts, diag.span.start).line;
    let end_line = loc_from_line_starts(line_starts, diag.span.end.saturating_sub(1)).line;
    if start_line <= target_line && target_line <= end_line {
        return true;
    }
    for subject in &file_ir.subjects {
        for effect in &subject.effect_nodes {
            if effect.call_span.start <= diag.span.start && diag.span.end <= effect.call_span.end {
                let eff_start = loc_from_line_starts(line_starts, effect.call_span.start).line;
                let eff_end =
                    loc_from_line_starts(line_starts, effect.call_span.end.saturating_sub(1)).line;
                if eff_start <= target_line && target_line <= eff_end {
                    return true;
                }
            }
        }
    }
    false
}

fn detect_mismatched_inline_suppression(file_ir: &FileIr, diag: &Diagnostic) -> Option<String> {
    let mut candidate_lines = vec![diag.loc.line];
    for subject in &file_ir.subjects {
        if subject.span.start <= diag.span.start && diag.span.end <= subject.span.end {
            candidate_lines.push(subject.loc.line);
        }
        for effect in &subject.effect_nodes {
            if effect.call_span.start <= diag.span.start && diag.span.end <= effect.call_span.end {
                candidate_lines.push(effect.loc.line);
            }
        }
    }
    for dir in &file_ir.suppressions.line_directives {
        if candidate_lines.contains(&dir.target_line)
            && !dir.rules.is_empty()
            && !dir.rules.iter().any(|r| diag.rule.matches_key(r))
        {
            return Some(format!(
                "Inline suppression comment targeting line {} listed {:?}, which did not match `{}`.",
                dir.target_line,
                dir.rules,
                diag.rule.metadata().qualified_key
            ));
        }
    }
    None
}

fn diagnose_why_not_active(
    diag: &Diagnostic,
    file_ir: &FileIr,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
) -> (String, String) {
    let meta = diag.rule.metadata();

    if config.respect_inline_disables
        && file_ir.suppressions.is_suppressed(
            diag.rule,
            diag.loc.line,
            diag.span,
            &file_ir.jsx_elements,
            &file_ir.subjects,
        )
    {
        return (
            "suppressed".to_string(),
            format!(
                "Rule `{}` matched at line {}, but was suppressed by an inline disable comment (`// dotore-disable-next-line` or block directive).",
                meta.qualified_key, diag.loc.line
            ),
        );
    }

    if config.is_file_ignored(&file_ir.path, package_root) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` was skipped because `{}` matches `ignore.files` in configuration.",
                meta.qualified_key,
                file_ir.path.display()
            ),
        );
    }

    if file_ir.file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && config.explicit_rule_override(diag.rule).is_none()
    {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` carries the `test-noise` tag and is automatically suppressed in {:?} files.",
                meta.qualified_key, file_ir.file_context
            ),
        );
    }

    if meta.capability_gate.app_only
        && gate.is_library_entrypoint(&file_ir.path, package_root)
        && config.explicit_rule_override(diag.rule).is_none()
    {
        return (
            "gated".to_string(),
            format!(
                "Rule `{}` is application-only and is skipped on library package entrypoints.",
                meta.qualified_key
            ),
        );
    }

    if config.is_overridden_for_file(diag.rule, &file_ir.path, package_root) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is suppressed for `{}` by `ignore.overrides` in configuration.",
                meta.qualified_key,
                file_ir.path.display()
            ),
        );
    }

    if !gate.allows_rule(meta) {
        let req: Vec<&str> = meta
            .capability_gate
            .requires
            .iter()
            .map(|c| c.as_str())
            .collect();
        let dis: Vec<&str> = meta
            .capability_gate
            .disabled_when
            .iter()
            .map(|c| c.as_str())
            .collect();
        return (
            "gated".to_string(),
            format!(
                "Rule `{}` was gated off by the package's Capability Gate (requires: [{}], disabled_when: [{}]).",
                meta.qualified_key,
                req.join(", "),
                dis.join(", ")
            ),
        );
    }

    if let Some(&ignored_tag) = meta.tags.iter().find(|&&t| config.is_tag_ignored(t)) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled because tag `{}` is listed in `ignore.tags`.",
                meta.qualified_key,
                ignored_tag.as_str()
            ),
        );
    }

    if config
        .ignore
        .rules
        .iter()
        .any(|r| RuleId::parse(r) == Some(diag.rule))
    {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled via `ignore.rules` in configuration.",
                meta.qualified_key
            ),
        );
    }

    if config.explicit_rule_override(diag.rule) == Some(RuleSeverityOverride::Off) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is explicitly set to `\"off\"` in `rules` configuration.",
                meta.qualified_key
            ),
        );
    }

    if config.category_override(meta.category) == Some(RuleSeverityOverride::Off) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled because category `{}` is set to `\"off\"` in configuration.",
                meta.qualified_key,
                meta.category.as_str()
            ),
        );
    }

    if !meta.default_enabled {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is opt-in (`default_enabled: false`) and is not enabled in configuration.",
                meta.qualified_key
            ),
        );
    }

    (
        "disabled".to_string(),
        format!(
            "Rule `{}` is disabled by the current configuration.",
            meta.qualified_key
        ),
    )
}

fn render_code_frame(source: &str, target_line: u32) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = (target_line.saturating_sub(1) as usize).min(lines.len().saturating_sub(1));
    let start = idx.saturating_sub(2);
    let end = (idx + 2).min(lines.len().saturating_sub(1));
    let mut out = String::new();
    for (i, line_text) in lines.iter().enumerate().take(end + 1).skip(start) {
        let line_no = i + 1;
        let marker = if line_no == target_line as usize {
            ">"
        } else {
            " "
        };
        let _ = writeln!(out, "{marker} {line_no:>4} | {line_text}");
    }
    out.trim_end().to_string()
}

/// Supported CI provider backends for `dotore ci`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiProviderKind {
    /// GitHub Actions (`.github/workflows/dotore.yml`).
    GithubActions,
    /// GitLab CI/CD (`.gitlab-ci.yml`).
    GitlabCi,
}

impl CiProviderKind {
    /// Canonical kebab-case identifier (`"github-actions"` or `"gitlab-ci"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubActions => "github-actions",
            Self::GitlabCi => "gitlab-ci",
        }
    }

    /// Parses a CI provider identifier string.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "github-actions" | "github" | "gha" => Some(Self::GithubActions),
            "gitlab-ci" | "gitlab" => Some(Self::GitlabCi),
            _ => None,
        }
    }
}

/// Options for `dotore ci install | upgrade | config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiOptions {
    /// Target repository directory.
    pub cwd: PathBuf,
    /// Explicit CI provider override (`None` auto-detects or defaults to GitHub Actions).
    pub provider: Option<CiProviderKind>,
    /// Optional gate blocking level (`"none"`, `"warning"`, or `"error"`).
    pub blocking: Option<String>,
    /// Optional diff scope (`"changed"`, `"contextual"`, `"lines"`, or `"full"`).
    pub scope: Option<String>,
}

/// Outcome of running `ci_install`, `ci_upgrade`, or `ci_config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiActionResult {
    /// Selected CI provider.
    pub provider: CiProviderKind,
    /// Path to the workflow configuration file.
    pub workflow_path: PathBuf,
    /// Action status (`"created"`, `"exists"`, `"updated"`, `"upgraded"`, `"unchanged"`, `"not-needed"`).
    pub status: String,
    /// Effective `--blocking` level in the workflow.
    pub blocking: String,
    /// Effective `--scope` setting in the workflow.
    pub scope: String,
}

/// Generates a CI pull-request workflow (`.github/workflows/dotore.yml` or `.gitlab-ci.yml`).
///
/// # Errors
/// Returns an error message if `--blocking` or `--scope` is invalid or writing the workflow fails.
pub fn ci_install(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let blocking = validate_ci_blocking(options.blocking.as_deref().unwrap_or("none"))?;
    let scope = validate_ci_scope(options.scope.as_deref().unwrap_or("changed"))?;
    let wf_path = ci_workflow_path(&options.cwd, provider);

    if wf_path.is_file() {
        return Ok(CiActionResult {
            provider,
            workflow_path: wf_path,
            status: "exists".to_string(),
            blocking,
            scope,
        });
    }

    if let Some(parent) = wf_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let content = render_ci_workflow(provider, &blocking, &scope);
    fs::write(&wf_path, content)
        .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;

    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: "created".to_string(),
        blocking,
        scope,
    })
}

/// Upgrades an existing CI workflow file in place to the latest `dotore` v2 configuration.
///
/// # Errors
/// Returns an error message if no workflow file exists or writing fails.
pub fn ci_upgrade(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let wf_path = ci_workflow_path(&options.cwd, provider);
    if !wf_path.is_file() {
        return Err(format!(
            "No CI workflow found at {}. Run `dotore ci install` first.",
            wf_path.display()
        ));
    }
    let existing = fs::read_to_string(&wf_path)
        .map_err(|e| format!("Failed to read {}: {e}", wf_path.display()))?;
    let (cur_blocking, cur_scope) = parse_ci_gate_from_workflow(&existing);
    let next_content = render_ci_workflow(provider, &cur_blocking, &cur_scope);
    let needs_upgrade = existing.contains("# dotore workflow v1")
        || existing.contains("@v1")
        || existing != next_content;
    if !needs_upgrade {
        return Ok(CiActionResult {
            provider,
            workflow_path: wf_path,
            status: "not-needed".to_string(),
            blocking: cur_blocking,
            scope: cur_scope,
        });
    }
    fs::write(&wf_path, &next_content)
        .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;
    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: "upgraded".to_string(),
        blocking: cur_blocking,
        scope: cur_scope,
    })
}

/// Updates the `blocking` and `scope` gate settings in an existing CI workflow file.
///
/// # Errors
/// Returns an error message if no workflow exists, gate values are invalid, or writing fails.
pub fn ci_config(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let wf_path = ci_workflow_path(&options.cwd, provider);
    if !wf_path.is_file() {
        return Err(format!(
            "No CI workflow found at {}. Run `dotore ci install` first.",
            wf_path.display()
        ));
    }
    let existing = fs::read_to_string(&wf_path)
        .map_err(|e| format!("Failed to read {}: {e}", wf_path.display()))?;
    let (cur_blocking, cur_scope) = parse_ci_gate_from_workflow(&existing);
    let blocking = match &options.blocking {
        Some(b) => validate_ci_blocking(b)?,
        None => cur_blocking,
    };
    let scope = match &options.scope {
        Some(s) => validate_ci_scope(s)?,
        None => cur_scope,
    };
    let next_content = render_ci_workflow(provider, &blocking, &scope);
    let changed = next_content != existing;
    if changed {
        fs::write(&wf_path, &next_content)
            .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;
    }
    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: if changed { "updated" } else { "unchanged" }.to_string(),
        blocking,
        scope,
    })
}

fn resolve_ci_provider(options: &CiOptions) -> CiProviderKind {
    if let Some(p) = options.provider {
        return p;
    }
    if options.cwd.join(".gitlab-ci.yml").is_file()
        && !options.cwd.join(".github").join("workflows").is_dir()
    {
        return CiProviderKind::GitlabCi;
    }
    CiProviderKind::GithubActions
}

fn ci_workflow_path(cwd: &Path, provider: CiProviderKind) -> PathBuf {
    match provider {
        CiProviderKind::GithubActions => cwd.join(".github").join("workflows").join("dotore.yml"),
        CiProviderKind::GitlabCi => cwd.join(".gitlab-ci.yml"),
    }
}

fn validate_ci_blocking(raw: &str) -> Result<String, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "none" | "warning" | "error" => Ok(raw.trim().to_ascii_lowercase()),
        _ => Err(format!(
            "Invalid --blocking value {raw:?}. Expected one of: none, warning, error."
        )),
    }
}

fn validate_ci_scope(raw: &str) -> Result<String, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "changed" | "contextual" | "lines" | "full" => Ok(raw.trim().to_ascii_lowercase()),
        _ => Err(format!(
            "Invalid --scope value {raw:?}. Expected one of: changed, contextual, lines, full."
        )),
    }
}

fn render_ci_workflow(provider: CiProviderKind, blocking: &str, scope: &str) -> String {
    match provider {
        CiProviderKind::GithubActions => format!(
            r#"# dotore workflow v2
# Static React & TypeScript analysis and deterministic remediation gate.
name: dotore

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  push:
    branches: ["main"]

permissions:
  contents: read

concurrency:
  group: dotore-${{{{ github.event.pull_request.number || github.ref }}}}
  cancel-in-progress: true

jobs:
  dotore:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - name: Run dotore
        run: dotore check --scope {scope} --blocking {blocking}
"#
        ),
        CiProviderKind::GitlabCi => format!(
            r#"# dotore workflow v2
dotore:
  stage: test
  script:
    - dotore check --scope {scope} --blocking {blocking}
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"#
        ),
    }
}

fn parse_ci_gate_from_workflow(content: &str) -> (String, String) {
    let mut blocking = "none".to_string();
    let mut scope = "changed".to_string();
    let tokens: Vec<&str> = content.split_whitespace().collect();
    for window in tokens.windows(2) {
        if window[0] == "--blocking" {
            blocking = window[1].trim_matches(&['"', '\''][..]).to_string();
        } else if window[0] == "--scope" {
            scope = window[1].trim_matches(&['"', '\''][..]).to_string();
        }
    }
    (blocking, scope)
}

/// Options for `dotore install` ([`install_dotore`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallOptions {
    /// Target project root directory.
    pub cwd: PathBuf,
    /// Non-interactive mode enabling full setup (skill, package.json script, git pre-commit hook, agent hooks).
    pub yes: bool,
    /// Preview planned file operations without writing to disk.
    pub dry_run: bool,
    /// Install agent stop hooks (`.claude/settings.json` and `.claude/hooks/dotore.mjs`).
    pub agent_hooks: bool,
}

/// Result of running [`install_dotore`] (`dotore install`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallResult {
    /// Installed (or planned) `/dotore` agent skill files.
    pub skill_files: Vec<PathBuf>,
    /// Whether `package.json#scripts.dotore` was added or updated.
    pub package_json_updated: bool,
    /// Path to the installed (or planned) git pre-commit hook file, if any.
    pub git_hook_path: Option<PathBuf>,
    /// Installed (or planned) agent hook configuration and script files.
    pub agent_hook_files: Vec<PathBuf>,
    /// Whether this run was a dry run (`--dry-run`).
    pub dry_run: bool,
}

const DOTORE_SKILL_CONTENT: &str = r#"---
name: dotore
description: Use when finishing a feature, fixing a bug, before committing React or TypeScript code, or when the user types `/dotore`. Runs static correctness, performance, accessibility, security, and architecture analysis and applies deterministic remediation.
version: "1.0.0"
---

# /dotore — Deterministic React & TypeScript Analysis and Remediation

`dotore` is a pure-Rust static analyzer, deterministic auto-fixer, and remediation engine for React and TypeScript codebases.

## Workflow

1. **Check (`dotore check`)**:
   - Run `dotore check --scope changed` after edits (or `dotore check --json` for structured machine output with **Root-Cause Groups**, **Blast Radius**, and **Fix Capsules**).
2. **Auto-fix (`dotore fix`)**:
   - Run `dotore fix` to deterministically apply all `Autofix`-tier single- and cross-file rewrites directly in Rust.
3. **Inspect Root Cause (`dotore why <file:line>`)**:
   - Run `dotore why <file:line>` to inspect why a diagnostic fired (or why a rule, inline suppression, or **Capability Gate** did or did not apply) and read its self-contained **Fix Capsule**.
4. **Search Symbols (`dotore search <query>`)**:
   - Run `dotore search <query>` to fuzzy-search AST **Symbol Outlines** across the repository without reading whole files.
5. **Generate Execution Plans (`dotore plan`)**:
   - Run `dotore plan --out plans` to emit prioritized `plans/NNN-<slug>.md` remediation plans and `plans/README.md`.
6. **Configure & Explain Rules (`dotore rules`)**:
   - Run `dotore rules list` or `dotore rules explain <rule>` to inspect rules offline, and `dotore rules set | enable | disable | category | ignore-tag` to update `dotore.config.*` or `package.json#dotore` in place.
7. **UI Design Audit (`dotore design`)**:
   - Run `dotore design` to run a focused UI polish audit enabling all `design`-tagged rules.
8. **Live Runtime Profiling (`dotore scan <url>`)**:
   - Run `dotore scan <url> --format json` to capture a Chrome DevTools Protocol (CDP) trace and React component render hotspots.
"#;

const GIT_HOOK_BLOCK_START: &str = "# dotore hook start";
const GIT_HOOK_BLOCK_END: &str = "# dotore hook end";

/// Installs the unified `/dotore` agent skill, `package.json` script, git pre-commit hook,
/// and optional agent hooks under `options.cwd` (or previews operations when `options.dry_run` is `true`).
///
/// # Errors
/// Returns an error message if reading or writing target files fails.
pub fn install_dotore(options: &InstallOptions) -> Result<InstallResult, String> {
    let cwd = if options.cwd.as_os_str().is_empty() {
        Path::new(".")
    } else {
        options.cwd.as_path()
    };

    let claude_skill = cwd
        .join(".claude")
        .join("skills")
        .join("dotore")
        .join("SKILL.md");
    let agents_skill = cwd
        .join(".agents")
        .join("skills")
        .join("dotore")
        .join("SKILL.md");
    let skill_files = vec![claude_skill, agents_skill];

    let pkg_json_path = cwd.join("package.json");
    let package_json_updated = if pkg_json_path.is_file() {
        let raw = fs::read_to_string(&pkg_json_path)
            .map_err(|e| format!("Failed to read {}: {e}", pkg_json_path.display()))?;
        !raw.contains("\"dotore\":")
    } else {
        false
    };

    let git_hook_path = if cwd.join(".husky").is_dir() {
        Some(cwd.join(".husky").join("pre-commit"))
    } else if cwd.join(".git").exists() || options.yes {
        Some(cwd.join(".git").join("hooks").join("pre-commit"))
    } else {
        None
    };

    let agent_hook_files = if options.agent_hooks || options.yes {
        vec![
            cwd.join(".claude").join("settings.json"),
            cwd.join(".claude").join("hooks").join("dotore.mjs"),
        ]
    } else {
        Vec::new()
    };

    if options.dry_run {
        return Ok(InstallResult {
            skill_files,
            package_json_updated,
            git_hook_path,
            agent_hook_files,
            dry_run: true,
        });
    }

    for skill_path in &skill_files {
        if let Some(parent) = skill_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        fs::write(skill_path, DOTORE_SKILL_CONTENT)
            .map_err(|e| format!("Failed to write {}: {e}", skill_path.display()))?;
    }

    if package_json_updated {
        add_dotore_script_to_package_json(&pkg_json_path)?;
    }

    if let Some(hook_path) = &git_hook_path {
        write_git_pre_commit_hook(hook_path)?;
    }

    if !agent_hook_files.is_empty() {
        write_claude_agent_hooks(cwd)?;
    }

    Ok(InstallResult {
        skill_files,
        package_json_updated,
        git_hook_path,
        agent_hook_files,
        dry_run: false,
    })
}

/// Formats the terminal summary for [`install_dotore`] (`dotore install`).
#[must_use]
pub fn format_install_report(result: &InstallResult) -> String {
    let mut out = String::new();
    let prefix = if result.dry_run { "[dry-run] " } else { "" };
    for skill in &result.skill_files {
        let _ = writeln!(out, "{prefix}Installed /dotore skill: {}", skill.display());
    }
    if result.package_json_updated {
        let _ = writeln!(
            out,
            "{prefix}Added \"dotore\": \"dotore check\" to package.json scripts."
        );
    }
    if let Some(hook) = &result.git_hook_path {
        let _ = writeln!(
            out,
            "{prefix}Installed pre-commit git hook: {}",
            hook.display()
        );
    }
    for ah in &result.agent_hook_files {
        let _ = writeln!(out, "{prefix}Installed agent hook file: {}", ah.display());
    }
    out
}

fn add_dotore_script_to_package_json(pkg_json_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(pkg_json_path)
        .map_err(|e| format!("Failed to read {}: {e}", pkg_json_path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid JSON in {}: {e}", pkg_json_path.display()))?;
    let Some(obj) = root.as_object_mut() else {
        return Err(format!(
            "{} root is not a JSON object",
            pkg_json_path.display()
        ));
    };
    let scripts_val = obj
        .entry("scripts".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(scripts_obj) = scripts_val.as_object_mut() {
        scripts_obj
            .entry("dotore".to_string())
            .or_insert_with(|| serde_json::Value::String("dotore check".to_string()));
    }
    let serialized = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    fs::write(pkg_json_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", pkg_json_path.display()))
}

fn write_git_pre_commit_hook(hook_path: &Path) -> Result<(), String> {
    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let existing = fs::read_to_string(hook_path).unwrap_or_default();
    let block = format!(
        "{GIT_HOOK_BLOCK_START}\nif command -v dotore >/dev/null 2>&1; then\n  dotore check --staged\nfi\n{GIT_HOOK_BLOCK_END}\n"
    );
    let next = if let Some(start_idx) = existing.find(GIT_HOOK_BLOCK_START)
        && let Some(end_rel) = existing[start_idx..].find(GIT_HOOK_BLOCK_END)
    {
        let end_idx = start_idx + end_rel + GIT_HOOK_BLOCK_END.len();
        let mut updated = String::new();
        updated.push_str(&existing[..start_idx]);
        updated.push_str(block.trim_end());
        updated.push_str(&existing[end_idx..]);
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated
    } else if existing.trim().is_empty() {
        format!("#!/bin/sh\n\n{block}")
    } else if existing.starts_with("#!") {
        format!("{}\n{block}", existing.trim_end())
    } else {
        format!("#!/bin/sh\n\n{}\n{block}", existing.trim_end())
    };
    fs::write(hook_path, next)
        .map_err(|e| format!("Failed to write {}: {e}", hook_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(hook_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(hook_path, perms);
        }
    }
    Ok(())
}

fn write_claude_agent_hooks(cwd: &Path) -> Result<(), String> {
    let claude_dir = cwd.join(".claude");
    let hooks_dir = claude_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)
        .map_err(|e| format!("Failed to create {}: {e}", hooks_dir.display()))?;

    let hook_script_path = hooks_dir.join("dotore.mjs");
    let hook_script = r#"import { spawnSync } from 'node:child_process';
const res = spawnSync('dotore', ['check', '--scope', 'changed'], { encoding: 'utf8', shell: true });
if (res.status !== 0 && res.stdout) {
  process.stderr.write(res.stdout);
}
process.exit(0);
"#;
    fs::write(&hook_script_path, hook_script)
        .map_err(|e| format!("Failed to write {}: {e}", hook_script_path.display()))?;

    let settings_path = claude_dir.join("settings.json");
    let mut settings: serde_json::Value = if settings_path.is_file() {
        let raw = fs::read_to_string(&settings_path)
            .map_err(|e| format!("Failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let cmd = "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/dotore.mjs\"";
    if let Some(obj) = settings.as_object_mut() {
        let hooks_val = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(hooks_obj) = hooks_val.as_object_mut() {
            hooks_obj.insert(
                "Stop".to_string(),
                serde_json::json!([
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": cmd
                            }
                        ]
                    }
                ]),
            );
        }
    }
    let serialized = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&settings_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", settings_path.display()))
}
