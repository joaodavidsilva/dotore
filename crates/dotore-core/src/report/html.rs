//! Self-contained visual HTML cascade report renderer (`dotore report`).

use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use super::json::JsonReport;
use crate::{
    config::PackageRole,
    rules::{
        BlastRadius, BlastRadiusTier, Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup,
        RuleSeverity,
    },
    ui::classify_style_bucket,
};

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
  .badge-error {
    background-color: rgba(244, 63, 94, 0.25);
    color: #fda4af;
    border-color: rgba(244, 63, 94, 0.5);
  }
  .badge-warning {
    background-color: rgba(245, 158, 11, 0.2);
    color: #fde68a;
    border-color: rgba(245, 158, 11, 0.45);
  }
  .badge-bucket {
    background-color: rgba(34, 211, 238, 0.14);
    color: #67e8f9;
    border-color: rgba(34, 211, 238, 0.35);
  }
  .toolbar {
    margin-top: 1.5rem;
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 0.75rem;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .filter-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .tab-btn {
    background-color: #1e293b;
    color: #cbd5e1;
    border: 1px solid #334155;
    border-radius: 9999px;
    padding: 0.3rem 0.75rem;
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
  }
  .tab-btn.active {
    background-color: #22d3ee;
    color: #020617;
    border-color: #22d3ee;
  }
  .search-input {
    width: 100%;
    background-color: #020617;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 0.5rem;
    padding: 0.5rem 0.75rem;
    font-size: 0.8125rem;
  }
  .projects-grid {
    margin-top: 0.75rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
    gap: 0.75rem;
  }
  .project-card {
    background-color: rgba(15, 23, 42, 0.85);
    border: 1px solid #1e293b;
    border-radius: 0.625rem;
    padding: 0.75rem 1rem;
    font-size: 0.75rem;
    color: #cbd5e1;
  }
  .capsule-details {
    margin-top: 0.75rem;
    border: 1px solid #1e293b;
    border-radius: 0.5rem;
    background-color: rgba(2, 6, 23, 0.75);
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
  }
  .capsule-summary {
    cursor: pointer;
    font-weight: 600;
    color: #38bdf8;
  }
  .code-block {
    margin-top: 0.5rem;
    padding: 0.625rem;
    background-color: #020617;
    border: 1px solid #1e293b;
    border-radius: 0.375rem;
    overflow-x: auto;
    white-space: pre;
    color: #e2e8f0;
    font-size: 0.75rem;
  }
"#;

const HTML_REPORT_SCRIPT: &str = r#"
  (function() {
    const buttons = document.querySelectorAll('.tab-btn');
    const searchInput = document.getElementById('report-search');
    const cards = document.querySelectorAll('[data-filter-card]');
    let activeFilter = 'ALL';
    function applyFilters() {
      const q = (searchInput ? searchInput.value : '').trim().toLowerCase();
      cards.forEach(function(card) {
        const bucket = card.getAttribute('data-bucket') || '';
        const tier = card.getAttribute('data-tier') || '';
        const sev = card.getAttribute('data-severity') || '';
        const searchHay = (card.getAttribute('data-search') || '').toLowerCase();
        let matchTab = true;
        if (activeFilter === 'AUTOFIX') matchTab = (tier === 'autofix');
        else if (activeFilter === 'ERRORS') matchTab = (sev === 'error');
        else if (activeFilter === 'WARNINGS') matchTab = (sev === 'warning');
        else if (activeFilter !== 'ALL') matchTab = (bucket === activeFilter);
        const matchQuery = !q || searchHay.indexOf(q) !== -1;
        card.style.display = (matchTab && matchQuery) ? '' : 'none';
      });
    }
    buttons.forEach(function(btn) {
      btn.addEventListener('click', function() {
        buttons.forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-tab') || 'ALL';
        applyFilters();
      });
    });
    if (searchInput) {
      searchInput.addEventListener('input', applyFilters);
    }
  })();
"#;

/// Renders a self-contained visual HTML report with **Root-Cause Groups**, **Fix Capsules**,
/// static **Blast Radius** (`tier`, `score`, and rationale), **Workspace Packages**, interactive
/// style-bucket filter tabs, **Render Cascade** cards, **Caller Sites**, and `Autofix` previews.
#[must_use]
pub fn render_html_report(report: &JsonReport) -> String {
    let s = &report.summary;
    let p0 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P0)
        .count();
    let p1 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P1)
        .count();
    let p2 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P2)
        .count();
    let p3 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P3)
        .count();

    let projects_section = render_projects_section(report);
    let toolbar_section = render_filter_toolbar_section(report);

    let mut groups_html = String::new();
    for (idx, group) in report.root_cause_groups.iter().enumerate() {
        let capsule = report
            .fix_capsules
            .iter()
            .find(|c| c.root_cause_group_id == group.id);
        let first_diag = group
            .diagnostic_indices
            .first()
            .and_then(|&i| report.diagnostics.get(i));
        append_root_cause_group_card(&mut groups_html, idx + 1, group, first_diag, capsule);
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
        <div class="eyebrow">dotore static analysis &middot; polyglot analyzer</div>
        <h1 class="title">React Effect &amp; State Report</h1>
        <p class="subtitle">Scanned {} file(s), {} Subject(s), {} Effect Node(s) &middot; {} affected file(s) &middot; Errors: {} &middot; Warnings: {} &middot; Blast Radius: P0: {p0}, P1: {p1}, P2: {p2}, P3: {p3}</p>
      </div>
      <div class="score-box">
        <div>
          <div class="score-label">Health Score ({})</div>
          <div class="score-value">{}/100</div>
        </div>
        <div class="tier-counts">
          <div class="text-autofix">Autofix: {}</div>
          <div class="text-surgical">Surgical: {}</div>
          <div class="text-refactor">Refactor: {}</div>
        </div>
      </div>
    </header>
    {projects_section}
    {toolbar_section}
    {groups_section}
    <section class="cards">
      {cards_html}
    </section>
  </main>
  <script>{HTML_REPORT_SCRIPT}</script>
</body>
</html>"#,
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.affected_file_count,
        s.error_count,
        s.warning_count,
        html_escape(&s.score_label),
        s.health_score,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    )
}

fn render_projects_section(report: &JsonReport) -> String {
    if report.projects.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for proj in &report.projects {
        let caps = proj
            .capabilities
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let role_str = match proj.role {
            PackageRole::Application => "application",
            PackageRole::Library => "library",
            PackageRole::Unknown => "unknown",
        };
        let _ = writeln!(
            items,
            r#"<div class="project-card"><div><strong>{}</strong> <span class="muted">({role_str})</span></div><div class="muted mono" style="margin-top:0.25rem">score: {}/100 ({}) &middot; files: {} &middot; subjects: {} &middot; findings: {}</div><div class="muted" style="margin-top:0.25rem">capabilities: {}</div></div>"#,
            html_escape(&proj.name),
            proj.health_score,
            html_escape(&proj.score_label),
            proj.analyzed_file_count,
            proj.subjects_scanned,
            proj.diagnostic_count,
            html_escape(&caps),
        );
    }
    format!(
        r#"<h2 class="section-heading">Workspace Packages ({})</h2><div class="projects-grid">{items}</div>"#,
        report.projects.len()
    )
}

fn render_filter_toolbar_section(report: &JsonReport) -> String {
    if report.diagnostics.is_empty() {
        return String::new();
    }
    let s = &report.summary;
    let mut tabs_html = format!(
        r#"<button type="button" class="tab-btn active" data-tab="ALL">ALL ({})</button>"#,
        report.diagnostics.len()
    );
    if s.autofix_count > 0 {
        let _ = write!(
            tabs_html,
            r#"<button type="button" class="tab-btn" data-tab="AUTOFIX">⚙ AUTOFIX ({})</button>"#,
            s.autofix_count
        );
    }
    if s.error_count > 0 {
        let _ = write!(
            tabs_html,
            r#"<button type="button" class="tab-btn" data-tab="ERRORS">✖ ERRORS ({})</button>"#,
            s.error_count
        );
    }
    if s.warning_count > 0 {
        let _ = write!(
            tabs_html,
            r#"<button type="button" class="tab-btn" data-tab="WARNINGS">▲ WARNINGS ({})</button>"#,
            s.warning_count
        );
    }
    let ordered_buckets = [
        "UNUSED",
        "EFFECTS & STATE",
        "ASYNC & STREAMS",
        "PERF & LOOPS",
        "SAFETY & GUARDS",
        "JSX & A11Y",
        "SECURITY",
        "IMPORTS & ARCH",
        "UI DESIGN",
        "CORRECTNESS",
    ];
    for bucket in ordered_buckets {
        let count = report
            .diagnostics
            .iter()
            .filter(|d| classify_style_bucket(d) == bucket)
            .count();
        if count > 0 {
            let esc = html_escape(bucket);
            let _ = write!(
                tabs_html,
                r#"<button type="button" class="tab-btn" data-tab="{esc}">{esc} ({count})</button>"#
            );
        }
    }
    format!(
        r#"<section class="toolbar"><div class="filter-tabs">{tabs_html}</div><input id="report-search" class="search-input mono" type="search" placeholder="Filter by file path, rule ID, subject name, or message..." /></section>"#
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

fn severity_badge_html(sev: RuleSeverity) -> &'static str {
    match sev {
        RuleSeverity::Error => r#"<span class="badge badge-error">✖ error</span>"#,
        RuleSeverity::Warning => r#"<span class="badge badge-warning">▲ warning</span>"#,
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

fn append_root_cause_group_card(
    out: &mut String,
    index: usize,
    group: &RootCauseGroup,
    first_diag: Option<&Diagnostic>,
    capsule: Option<&FixCapsule>,
) {
    let tier_class = match group.tier {
        PrescriptionTier::Autofix => "badge-autofix",
        PrescriptionTier::Surgical => "badge-surgical",
        PrescriptionTier::Refactor => "badge-refactor",
    };
    let blast_class = blast_tier_badge_class(group.blast_radius.tier);
    let sev_badge = severity_badge_html(group.severity);
    let sev_str = match group.severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warning",
    };
    let bucket = first_diag.map_or("CORRECTNESS", classify_style_bucket);
    let bucket_esc = html_escape(bucket);
    let subject = html_escape(group.subject_name.as_deref().unwrap_or("<module>"));
    let file_str = group.file.display().to_string();
    let file_loc = format!(
        "{}:{}:{}",
        html_escape(&file_str),
        group.loc.line,
        group.loc.column
    );
    let rationale = html_escape(&format_blast_radius_rationale(&group.blast_radius));
    let capsule_html = capsule.map_or_else(String::new, render_fix_capsule_html);
    let masked_group_msg = super::mask_credentials(&group.message);
    let search_attr = html_escape(&format!(
        "{} {} {} {}",
        file_str,
        group.rule.as_str(),
        group.subject_name.as_deref().unwrap_or(""),
        masked_group_msg
    ));

    let _ = writeln!(
        out,
        r#"<article class="card" data-filter-card="1" data-bucket="{bucket_esc}" data-tier="{}" data-severity="{sev_str}" data-search="{search_attr}">
  <div class="card-header">
    <div class="card-meta">
      <span class="muted mono">RCG #{index}</span>
      <span class="badge badge-bucket">{bucket_esc}</span>
      {sev_badge}
      <span class="badge {blast_class}">{} (score {})</span>
      <span class="badge {tier_class}">{}</span>
      <code class="rule-code">{}</code>
      <span class="muted">in <code>{subject}</code></span>
    </div>
    <code class="muted">{file_loc}</code>
  </div>
  <p class="message">{}</p>
  <div class="blast-box mono">Root-Cause Group <code>{}</code> &middot; Blast Radius: {} (score {}) &mdash; {rationale}</div>
  {capsule_html}
</article>"#,
        group.tier.as_str(),
        group.blast_radius.tier.as_str(),
        group.blast_radius.score,
        group.tier.as_str(),
        group.rule.as_str(),
        html_escape(&masked_group_msg),
        html_escape(&group.id),
        group.blast_radius.tier.as_str(),
        group.blast_radius.score,
    );
}

fn render_fix_capsule_html(capsule: &FixCapsule) -> String {
    let mut body = format!(
        r#"<div style="margin-top:0.5rem"><strong>Transformation Recipe:</strong> {}</div>"#,
        html_escape(capsule.recipe_markdown)
    );
    if !capsule.subject_excerpt.source.is_empty() {
        let _ = write!(
            body,
            r#"<div style="margin-top:0.5rem"><span class="muted mono">Subject Excerpt ({}:{}-{}):</span><pre class="code-block mono">{}</pre></div>"#,
            html_escape(&capsule.subject_excerpt.file.display().to_string()),
            capsule.subject_excerpt.start_line,
            capsule.subject_excerpt.end_line,
            html_escape(&super::mask_credentials(&capsule.subject_excerpt.source)),
        );
    }
    if let Some(ex) = &capsule.exemplar
        && !ex.source.is_empty()
    {
        let _ = write!(
            body,
            r#"<div style="margin-top:0.5rem"><span class="muted mono">Repository Exemplar ({}:{}-{}):</span><pre class="code-block mono">{}</pre></div>"#,
            html_escape(&ex.file.display().to_string()),
            ex.start_line,
            ex.end_line,
            html_escape(&super::mask_credentials(&ex.source)),
        );
    }
    format!(
        r#"<details class="capsule-details"><summary class="capsule-summary">Fix Capsule &amp; Exemplar</summary>{body}</details>"#
    )
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
    let bucket = classify_style_bucket(diag);
    let bucket_esc = html_escape(bucket);
    let sev_badge = severity_badge_html(diag.severity);
    let sev_str = match diag.severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warning",
    };
    let subject = html_escape(diag.subject_name.as_deref().unwrap_or("<anonymous>"));
    let file_str = diag.file.display().to_string();
    let file_loc = format!(
        "{}:{}:{}",
        html_escape(&file_str),
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
    let masked_diag_msg = super::mask_credentials(&diag.message);
    let search_attr = html_escape(&format!(
        "{} {} {} {}",
        file_str,
        diag.rule.as_str(),
        diag.subject_name.as_deref().unwrap_or(""),
        masked_diag_msg
    ));

    let _ = writeln!(
        out,
        r#"<article class="card" data-filter-card="1" data-bucket="{bucket_esc}" data-tier="{}" data-severity="{sev_str}" data-search="{search_attr}">
  <div class="card-header">
    <div class="card-meta">
      <span class="muted mono">#{index}</span>
      <span class="badge badge-bucket">{bucket_esc}</span>
      {sev_badge}
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
        diag.tier.as_str(),
        diag.rule.as_str(),
        html_escape(&masked_diag_msg),
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
