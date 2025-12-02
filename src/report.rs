//! Terminal, JSON, and self-contained HTML cascade reporters for `dotore`.

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    fixer::FileFixResult,
    graph::ProjectGraph,
    planner::{build_root_cause_groups_and_capsules, enrich_cross_file_autofixes},
    rules::{Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup},
};

/// Aggregate metrics for a `dotore` scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportSummary {
    /// Total source files scanned.
    pub files_scanned: usize,
    /// Total React **Subjects** (components and custom hooks) analyzed.
    pub subjects_scanned: usize,
    /// Total `useEffect` **Effect Nodes** analyzed.
    pub effects_scanned: usize,
    /// Total diagnostics found.
    pub total_diagnostics: usize,
    /// Count of `Autofix` diagnostics (`dotore fix`).
    pub autofix_count: usize,
    /// Count of `Surgical` single-**Subject** diagnostics.
    pub surgical_count: usize,
    /// Count of `Refactor` state-model / cross-**Subject** diagnostics.
    pub refactor_count: usize,
    /// Overall React Effect & State health score (`0..=100`).
    pub health_score: u32,
}

/// Complete machine-readable report emitted by `dotore check --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonReport {
    /// Aggregate metrics.
    pub summary: ReportSummary,
    /// Individual diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// Clustered **Root-Cause Groups** ordered by static **Blast Radius** descending.
    pub root_cause_groups: Vec<RootCauseGroup>,
    /// Self-contained **Fix Capsules** for `Surgical` and `Refactor` **Root-Cause Groups**.
    pub fix_capsules: Vec<FixCapsule>,
}

/// Builds a [`JsonReport`] from a [`ProjectGraph`], its evaluated [`Diagnostic`]s, and file sources.
#[must_use]
pub(crate) fn build_report(
    graph: &ProjectGraph,
    mut diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
) -> JsonReport {
    enrich_cross_file_autofixes(graph, &mut diagnostics, sources);

    let files_scanned = graph.files.len();
    let subjects_scanned: usize = graph.files.iter().map(|f| f.subjects.len()).sum();
    let effects_scanned: usize = graph
        .files
        .iter()
        .flat_map(|f| &f.subjects)
        .map(|s| s.effect_nodes.len())
        .sum();

    let mut autofix_count = 0;
    let mut surgical_count = 0;
    let mut refactor_count = 0;

    for diag in &diagnostics {
        match diag.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
    }

    let (root_cause_groups, fix_capsules) =
        build_root_cause_groups_and_capsules(graph, &diagnostics, sources);

    let health_score = compute_health_score(effects_scanned, diagnostics.len());

    JsonReport {
        summary: ReportSummary {
            files_scanned,
            subjects_scanned,
            effects_scanned,
            total_diagnostics: diagnostics.len(),
            autofix_count,
            surgical_count,
            refactor_count,
            health_score,
        },
        diagnostics,
        root_cause_groups,
        fix_capsules,
    }
}

fn compute_health_score(effects_scanned: usize, total_diagnostics: usize) -> u32 {
    if total_diagnostics == 0 {
        return 100;
    }
    let denom = effects_scanned.max(total_diagnostics).max(1);
    let penalty = (total_diagnostics.saturating_mul(100)) / denom;
    let raw = 100_usize.saturating_sub(penalty.min(95));
    u32::try_from(raw).unwrap_or(5)
}

/// Formats a human-readable terminal report with **Render Cascade** traces and **Caller Sites**.
#[must_use]
pub fn format_terminal_report(report: &JsonReport) -> String {
    let mut out = String::new();
    let s = &report.summary;

    let _ = writeln!(
        out,
        "dotore  score: {}/100  files: {}  subjects: {}  effects: {}  findings: {} (autofix: {}, surgical: {}, refactor: {})",
        s.health_score,
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.total_diagnostics,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    );

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
  .docs-row { margin-top: 0.75rem; font-size: 0.75rem; }
  .docs-link { color: #22d3ee; text-decoration: none; }
  .docs-link:hover { text-decoration: underline; }
"#;

/// Renders a self-contained visual HTML report with **Render Cascade** cards,
/// **Caller Sites**, and `Autofix` previews.
#[must_use]
pub fn render_html_report(report: &JsonReport) -> String {
    let s = &report.summary;
    let mut cards_html = String::new();

    for (idx, diag) in report.diagnostics.iter().enumerate() {
        append_diagnostic_card(&mut cards_html, idx + 1, diag);
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

fn append_diagnostic_card(out: &mut String, index: usize, diag: &Diagnostic) {
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
      <span class="badge {badge_class}">{}</span>
      <code class="rule-code">{}</code>
      <span class="muted">in <code>{subject}</code></span>
    </div>
    <code class="muted">{file_loc}</code>
  </div>
  <p class="message">{}</p>
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
