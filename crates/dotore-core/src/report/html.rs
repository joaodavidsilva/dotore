//! Self-contained visual HTML cascade report renderer (`dotore report`).

use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::rules::{BlastRadius, BlastRadiusTier, Diagnostic, PrescriptionTier, RootCauseGroup};

use super::json::JsonReport;

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
