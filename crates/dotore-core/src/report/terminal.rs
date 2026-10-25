//! Terminal and ASCII report rendering (`dotore check`, `dotore design`, and `dotore fix`)
//! built on the reusable terminal UI component kit (`crate::ui`).

use std::fmt::Write as _;

use crate::{
    config::Capability,
    fixer::FileFixResult,
    rules::{BlastRadiusTier, Diagnostic, PrescriptionTier},
    ui::{
        AsciiBox, Badge, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, FlowDiagram, GaugeBar,
        StatusBar,
    },
};

use super::json::JsonReport;

/// Formats a human-readable terminal report with **Render Cascade** traces and **Caller Sites**.
#[must_use]
pub fn format_terminal_report(report: &JsonReport) -> String {
    format_terminal_report_pretty(report, false)
}

/// Formats a human-readable terminal report with ASCII art dashboard, **Render Cascade** flow
/// diagrams, **Caller Sites**, and optional ANSI color styling.
#[must_use]
pub fn format_terminal_report_pretty(report: &JsonReport, color: bool) -> String {
    let mut out = String::new();
    let mode = ColorMode::from_bool(color);
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

    let dim = mode.dim();
    let bold = mode.bold();
    let green = mode.green();
    let yellow = mode.yellow();
    let red = mode.red();
    let reset = mode.reset();

    let score_color = if s.health_score >= 85 {
        green
    } else if s.health_score >= 60 {
        yellow
    } else {
        red
    };

    let score_bar = ascii_progress_bar(s.health_score as usize, 100, 20);
    let total_diag_denom = s.total_diagnostics.max(1);
    let autofix_bar = GaugeBar::new(s.autofix_count, total_diag_denom, 16)
        .with_color("\x1b[32;1m")
        .render(mode);
    let surgical_bar = GaugeBar::new(s.surgical_count, total_diag_denom, 16)
        .with_color("\x1b[33;1m")
        .render(mode);
    let refactor_bar = GaugeBar::new(s.refactor_count, total_diag_denom, 16)
        .with_color("\x1b[31;1m")
        .render(mode);

    let mut dashboard =
        AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH).with_border_color("\x1b[36;1m");
    dashboard.add_closed_row("   ____   ___ _____ ___  ____  _____");
    dashboard.add_closed_row(format!(
        "  |  _ \\ / _ \\_   _/ _ \\|  _ \\| ____|   {bold}STATIC ANALYZER & REMEDIATION ENGINE{reset}"
    ));
    dashboard.add_closed_row(format!(
        "  | | | | | | || || | | | |_) |  _|     {dim}JS/TS · React · Angular · Python · Rs{reset}"
    ));
    dashboard.add_closed_row("  | |_| | |_| || || |_| |  _ <| |___");
    dashboard.add_closed_row("  |____/ \\___/ |_| \\___/|_| \\_\\_____|");
    dashboard.add_divider();
    dashboard.add_open_row(format!(
        "  {bold}HEALTH SCORE{reset}   {score_color}{score_bar}  {:>3}/100 ({}){reset}",
        s.health_score, s.score_label
    ));
    dashboard.add_open_row(format!(
        "  {bold}SCAN SCOPE{reset}     {} files · {} subjects · {} effects · {} findings",
        s.files_scanned, s.subjects_scanned, s.effects_scanned, s.total_diagnostics
    ));
    dashboard.add_open_row(format!(
        "  {bold}SEVERITY{reset}       {red}✖ {} error(s){reset}   {yellow}▲ {} warning(s){reset}   ({} affected file(s))",
        s.error_count, s.warning_count, s.affected_file_count
    ));
    dashboard.add_open_row(format!(
        "  {bold}TIERS{reset}          {}   {autofix_bar}  {}",
        Badge::tier(PrescriptionTier::Autofix).render_dashboard_label(mode),
        s.autofix_count
    ));
    dashboard.add_open_row(format!(
        "                 {}   {surgical_bar}  {}",
        Badge::tier(PrescriptionTier::Surgical).render_dashboard_label(mode),
        s.surgical_count
    ));
    dashboard.add_open_row(format!(
        "                 {}   {refactor_bar}  {}",
        Badge::tier(PrescriptionTier::Refactor).render_dashboard_label(mode),
        s.refactor_count
    ));
    dashboard.add_open_row(format!(
        "  {bold}BLAST RADIUS{reset}   {}   {}   {}   {}",
        Badge::blast_radius_count(BlastRadiusTier::P0, p0).render(mode),
        Badge::blast_radius_count(BlastRadiusTier::P1, p1).render(mode),
        Badge::blast_radius_count(BlastRadiusTier::P2, p2).render(mode),
        Badge::blast_radius_count(BlastRadiusTier::P3, p3).render(mode),
    ));
    out.push_str(&dashboard.render(mode));

    if !report.projects.is_empty() {
        let mut pkg_box = AsciiBox::new(BoxBorderStyle::Single, DEFAULT_BOX_WIDTH)
            .with_title(format!("WORKSPACE PACKAGES ({})", report.projects.len()))
            .with_border_color("\x1b[2m");
        for proj in &report.projects {
            let caps: Vec<&str> = proj
                .capabilities
                .iter()
                .copied()
                .map(Capability::as_str)
                .collect();
            let caps_label = if caps.is_empty() {
                "none".to_string()
            } else {
                caps.join(", ")
            };
            pkg_box.add_open_row(format!(
                "  • {bold}{}{reset} ({caps_label})  score: {}/100 ({})  files: {}  findings: {}",
                proj.name,
                proj.health_score,
                proj.score_label,
                proj.analyzed_file_count,
                proj.diagnostic_count
            ));
        }
        out.push_str(&pkg_box.render(mode));
    }

    if report.diagnostics.is_empty() {
        let mut clean_box = AsciiBox::new(BoxBorderStyle::Double, DEFAULT_BOX_WIDTH)
            .with_border_color("\x1b[32;1m");
        clean_box.add_closed_row("  ✔  No unnecessary effects or state cascades detected.");
        let _ = writeln!(out, "\n{}", clean_box.render(mode));
    } else {
        let _ = writeln!(out);
        for diag in &report.diagnostics {
            format_single_diagnostic(&mut out, diag, color);
        }
    }

    out.push_str(&StatusBar::from_report(report).render(mode));
    out
}

/// Formats the terminal output for `dotore design` (focused UI polish audit, omitting health score).
#[must_use]
pub fn format_design_report(report: &JsonReport) -> String {
    format_design_report_pretty(report, false)
}

/// Formats the terminal output for `dotore design` with ASCII art header and optional ANSI colors.
#[must_use]
pub fn format_design_report_pretty(report: &JsonReport, color: bool) -> String {
    let mut out = String::new();
    let mode = ColorMode::from_bool(color);
    let s = &report.summary;
    let bold = mode.bold();
    let reset = mode.reset();

    let mut header_box = AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH)
        .with_title("DOTORE DESIGN AUDIT")
        .with_border_color("\x1b[36;1m");
    header_box.add_open_row(format!(
        "  {bold}UI POLISH{reset}      {} files · {} subjects · {} findings (autofix: {}, surgical: {}, refactor: {})",
        s.files_scanned,
        s.subjects_scanned,
        s.total_diagnostics,
        s.autofix_count,
        s.surgical_count,
        s.refactor_count
    ));
    out.push_str(&header_box.render(mode));

    if report.diagnostics.is_empty() {
        let _ = writeln!(out, "\nNo UI design findings detected.\n");
    } else {
        let _ = writeln!(out);
        for diag in &report.diagnostics {
            format_single_diagnostic(&mut out, diag, color);
        }
    }

    out.push_str(&StatusBar::design_summary(report).render(mode));
    out
}

fn ascii_progress_bar(value: usize, max: usize, width: usize) -> String {
    GaugeBar::new(value, max, width).render(ColorMode::Plain)
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

fn format_single_diagnostic(out: &mut String, diag: &Diagnostic, color: bool) {
    let mode = ColorMode::from_bool(color);
    let subject = diag.subject_name.as_deref().unwrap_or("<anonymous>");
    let dim = mode.dim();
    let green = mode.green();
    let reset = mode.reset();
    let rule_badge = Badge::rule(diag.rule).render(mode);
    let tier_badge = Badge::tier(diag.tier).render(mode);

    let _ = writeln!(
        out,
        "{dim}╭──{reset} {rule_badge} {tier_badge} {}:{}:{} in `{}`",
        diag.file.display(),
        diag.loc.line,
        diag.loc.column,
        subject
    );
    let _ = writeln!(
        out,
        "{dim}│{reset}  {}",
        super::mask_credentials(&diag.message)
    );
    if !diag.cascade_steps.is_empty() {
        let flow = FlowDiagram::new(&diag.cascade_steps);
        let _ = writeln!(out, "{dim}│{reset}  cascade: {}", flow.render_arrow_chain());
        let _ = writeln!(
            out,
            "{dim}│{reset}  flow:    {}",
            flow.render(ColorMode::Plain)
        );
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
                "{dim}│{reset}  caller:  {}:{}:{} in `{parent}` (<{} /> {key_note})",
                caller.caller_file.display(),
                caller.loc.line,
                caller.loc.column,
                caller.component_name
            );
        } else {
            let _ = writeln!(
                out,
                "{dim}│{reset}  caller:  {}:{}:{} (<{} /> {key_note})",
                caller.caller_file.display(),
                caller.loc.line,
                caller.loc.column,
                caller.component_name
            );
        }
    }
    if let Some(fix) = &diag.autofix {
        let _ = writeln!(
            out,
            "{dim}│{reset}  {green}autofix:{reset} {}",
            fix.description
        );
    }
    let _ = writeln!(out, "{dim}╰──{reset} docs:    {}\n", diag.docs_url);
}
