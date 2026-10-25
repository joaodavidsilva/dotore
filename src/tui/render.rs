//! Frame, viewport body, header metrics, and package picker rendering for [`super::TuiState`].

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::{self, Write},
    path::Path,
};

use dotore_core::{
    planner::filter_report_for_diagnostics,
    report::JsonReport,
    rules::{BlastRadiusTier, Diagnostic, PrescriptionTier, RootCauseGroup, RuleSeverity},
    score::compute_local_health_score,
    ui::{
        AsciiBox, Badge, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, FilterTabBar, FlowDiagram,
        GaugeBar, StatusBar, build_filter_tabs, classify_style_bucket, truncate_ansi_to_width,
        visible_char_width,
    },
};

use super::{TuiFilterTab, TuiGroupMode, TuiState};

fn split_oversized_word(word: &str, limit: usize, wrapped: &mut Vec<String>) -> (String, usize) {
    let mut chunk = String::new();
    let mut chunk_len = 0usize;
    for ch in word.chars() {
        let ch_w = visible_char_width(&ch.to_string());
        if chunk_len + ch_w > limit && !chunk.is_empty() {
            wrapped.push(chunk);
            chunk = String::new();
            chunk_len = 0;
        }
        chunk.push(ch);
        chunk_len += ch_w;
    }
    (chunk, chunk_len)
}

fn wrap_plain_text(text: &str, max_width: usize) -> Vec<String> {
    let limit = max_width.max(16);
    if visible_char_width(text) <= limit {
        return vec![text.to_string()];
    }
    let mut wrapped = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for word in text.split_whitespace() {
        let word_len = visible_char_width(word);
        if current.is_empty() {
            if word_len <= limit {
                current.push_str(word);
                current_len = word_len;
            } else {
                let (rem, rem_len) = split_oversized_word(word, limit, &mut wrapped);
                current = rem;
                current_len = rem_len;
            }
        } else if current_len + 1 + word_len <= limit {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + word_len;
        } else {
            wrapped.push(current);
            current = word.to_string();
            current_len = word_len;
        }
    }
    if !current.is_empty() {
        wrapped.push(current);
    }
    if wrapped.is_empty() {
        wrapped.push(String::new());
    }
    wrapped
}

fn append_diag_detail_rows(
    target_box: &mut AsciiBox,
    diag: &Diagnostic,
    text_wrap_width: usize,
    include_flow: bool,
) {
    for msg_line in wrap_plain_text(&diag.message, text_wrap_width) {
        target_box.add_closed_row(format!("      \x1b[38;5;254m{msg_line}\x1b[0m"));
    }
    if include_flow && !diag.cascade_steps.is_empty() {
        let flow_plain = FlowDiagram::new(&diag.cascade_steps).render(ColorMode::Plain);
        for flow_line in wrap_plain_text(&flow_plain, text_wrap_width) {
            target_box.add_closed_row(format!("      \x1b[38;5;201m{flow_line}\x1b[0m"));
        }
    }
    if let Some(fix) = &diag.autofix {
        let fix_width = text_wrap_width.saturating_sub(12);
        for fix_line in wrap_plain_text(&fix.description, fix_width) {
            target_box.add_closed_row(format!(
                "      \x1b[38;5;48;1m⚙ autofix:\x1b[0m \x1b[38;5;121m{fix_line}\x1b[0m"
            ));
        }
    }
}

fn render_by_rule_style_boxes(
    filtered: &[&Diagnostic],
    box_width: usize,
    text_wrap_width: usize,
    lines: &mut Vec<String>,
) {
    let mut by_rule: BTreeMap<&'static str, Vec<&Diagnostic>> = BTreeMap::new();
    for d in filtered {
        by_rule.entry(d.rule.as_str()).or_default().push(*d);
    }
    let mut groups: Vec<(&'static str, Vec<&Diagnostic>)> = by_rule.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

    for (rule_name, items) in groups {
        let Some(first) = items.first() else {
            continue;
        };
        let bucket = classify_style_bucket(first);
        let bucket_badge = Badge::style_bucket(bucket).render(ColorMode::Ansi);
        let tier_badge = Badge::tier(first.tier).render_pill(ColorMode::Ansi);
        let sev_badge = Badge::severity(first.severity).render(ColorMode::Ansi);
        let mut rule_box = AsciiBox::new(BoxBorderStyle::Rounded, box_width)
            .with_indent(" ")
            .with_border_color("\x1b[38;5;240m")
            .with_title(format!(
                "{bucket_badge} \x1b[38;5;51;1m{rule_name}\x1b[0m  {tier_badge}  {sev_badge}  \x1b[38;5;252;1m({} finding{})\x1b[0m",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            ));
        for line in wrap_plain_text(first.rule.metadata().title, text_wrap_width) {
            rule_box.add_closed_row(format!("  \x1b[38;5;245m{line}\x1b[0m"));
        }
        for d in &items {
            let subj = d.subject_name.as_deref().unwrap_or("<module>");
            rule_box.add_closed_row(format!(
                "  ▸ \x1b[38;5;153;1m{}:{}:{}\x1b[0m \x1b[38;5;244min\x1b[0m \x1b[38;5;219m`{subj}`\x1b[0m",
                d.file.display(),
                d.loc.line,
                d.loc.column
            ));
            append_diag_detail_rows(&mut rule_box, d, text_wrap_width, true);
        }
        lines.extend(rule_box.render_lines(ColorMode::Ansi));
        lines.push(String::new());
    }
}

fn render_by_file_boxes(
    filtered: &[&Diagnostic],
    box_width: usize,
    text_wrap_width: usize,
    lines: &mut Vec<String>,
) {
    let mut by_file: BTreeMap<String, Vec<&Diagnostic>> = BTreeMap::new();
    for d in filtered {
        by_file
            .entry(d.file.display().to_string())
            .or_default()
            .push(*d);
    }
    for (file_path, items) in by_file {
        let mut file_box = AsciiBox::new(BoxBorderStyle::Rounded, box_width)
            .with_indent(" ")
            .with_border_color("\x1b[38;5;240m")
            .with_title(format!(
                "\x1b[38;5;117;1m▸ {file_path}\x1b[0m  \x1b[38;5;252;1m({} finding{})\x1b[0m",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            ));
        for d in items {
            let bucket = classify_style_bucket(d);
            let bucket_badge = Badge::style_bucket(bucket).render(ColorMode::Ansi);
            let rule_badge = Badge::rule(d.rule).render(ColorMode::Ansi);
            let subj = d.subject_name.as_deref().unwrap_or("<module>");
            file_box.add_closed_row(format!(
                "  ▸ \x1b[38;5;228;1mL{}:{}\x1b[0m {bucket_badge} {rule_badge} \x1b[38;5;244min\x1b[0m \x1b[38;5;219m`{subj}`\x1b[0m",
                d.loc.line,
                d.loc.column
            ));
            append_diag_detail_rows(&mut file_box, d, text_wrap_width, false);
        }
        lines.extend(file_box.render_lines(ColorMode::Ansi));
        lines.push(String::new());
    }
}

fn render_detailed_card_boxes(
    filtered: &[&Diagnostic],
    box_width: usize,
    text_wrap_width: usize,
    lines: &mut Vec<String>,
) {
    for d in filtered {
        let bucket = classify_style_bucket(d);
        let bucket_badge = Badge::style_bucket(bucket).render(ColorMode::Ansi);
        let rule_badge = Badge::rule(d.rule).render(ColorMode::Ansi);
        let tier_badge = Badge::tier(d.tier).render(ColorMode::Ansi);
        let subj = d.subject_name.as_deref().unwrap_or("<module>");
        let mut card_box = AsciiBox::new(BoxBorderStyle::Rounded, box_width)
            .with_indent(" ")
            .with_border_color("\x1b[38;5;240m")
            .with_title(format!(
                "{bucket_badge} {rule_badge} {tier_badge} \x1b[38;5;153;1m{}:{}:{}\x1b[0m in \x1b[38;5;219m`{subj}`\x1b[0m",
                d.file.display(),
                d.loc.line,
                d.loc.column
            ));
        for msg_line in wrap_plain_text(&d.message, text_wrap_width) {
            card_box.add_closed_row(format!("  {msg_line}"));
        }
        if !d.cascade_steps.is_empty() {
            let flow = FlowDiagram::new(&d.cascade_steps).render(ColorMode::Plain);
            card_box.add_closed_row(format!("  \x1b[38;5;201mflow:    {flow}\x1b[0m"));
        }
        if let Some(fix) = &d.autofix {
            card_box.add_closed_row(format!(
                "  \x1b[38;5;48;1mautofix:\x1b[0m {}",
                fix.description
            ));
        }
        card_box.add_closed_row(format!("  \x1b[38;5;244mdocs:    {}\x1b[0m", d.docs_url));
        lines.extend(card_box.render_lines(ColorMode::Ansi));
        lines.push(String::new());
    }
}

/// Renders the scrollable TUI viewport body lines for `filtered` diagnostics under `group_mode`.
#[must_use]
pub fn render_tui_body_lines(filtered: &[&Diagnostic], group_mode: TuiGroupMode) -> Vec<String> {
    render_tui_body_lines_for_width(filtered, group_mode, DEFAULT_BOX_WIDTH + 4)
}

/// Renders the scrollable TUI viewport body lines fitted dynamically to `cols` terminal columns.
#[must_use]
pub fn render_tui_body_lines_for_width(
    filtered: &[&Diagnostic],
    group_mode: TuiGroupMode,
    cols: usize,
) -> Vec<String> {
    let box_width = cols.saturating_sub(4).max(46);
    let text_wrap_width = box_width.saturating_sub(8).max(24);
    let mut lines = Vec::new();
    if filtered.is_empty() {
        lines.push(String::new());
        let mut empty_box = AsciiBox::new(BoxBorderStyle::Double, box_width.min(78))
            .with_indent(" ")
            .with_border_color("\x1b[38;5;48;1m");
        empty_box.add_closed_row("  ✔  Zero findings match this filter!");
        lines.extend(empty_box.render_lines(ColorMode::Ansi));
        return lines;
    }

    match group_mode {
        TuiGroupMode::ByRuleStyle => {
            render_by_rule_style_boxes(filtered, box_width, text_wrap_width, &mut lines);
        }
        TuiGroupMode::ByFile => {
            render_by_file_boxes(filtered, box_width, text_wrap_width, &mut lines);
        }
        TuiGroupMode::DetailedCards => {
            render_detailed_card_boxes(filtered, box_width, text_wrap_width, &mut lines);
        }
    }

    lines
}

/// Renders the 256-color health score gauge bar (`[████░░░░] 92/100`) using [`GaugeBar`].
#[must_use]
pub fn build_score_gauge(score: u32, width: usize) -> String {
    GaugeBar::health_score(score, width)
        .with_256_palette(true)
        .with_ratio_suffix(true)
        .render(ColorMode::Ansi)
}

/// Highlights 0-based `matched_indices` in `text` using `match_ansi` and non-matching characters using `base_ansi`.
#[must_use]
pub fn highlight_fuzzy_matches(
    text: &str,
    matched_indices: &[usize],
    base_ansi: &str,
    match_ansi: &str,
) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(text.len() * 8);
    for (idx, ch) in text.chars().enumerate() {
        if matched_indices.contains(&idx) {
            let _ = write!(out, "{match_ansi}{ch}\x1b[0m");
        } else if base_ansi.is_empty() {
            out.push(ch);
        } else {
            let _ = write!(out, "{base_ansi}{ch}\x1b[0m");
        }
    }
    out
}

/// Renders the resizable workspace package picker overlay box (`p`) fitted to `cols` terminal columns.
#[must_use]
pub fn render_package_picker_lines(state: &TuiState, cols: usize) -> Vec<String> {
    let box_width = cols.saturating_sub(4).max(46);
    let mut picker_box = AsciiBox::new(BoxBorderStyle::Double, box_width)
        .with_indent(" ")
        .with_border_color("\x1b[38;5;51;1m")
        .with_title(
            "WORKSPACE PACKAGE PICKER (Space: toggle, a: toggle all, Enter: apply, ESC: cancel)",
        );

    let selected_count = state.picker_selected.iter().filter(|&&b| b).count();
    let total_pkg = state.packages.len();
    picker_box.add_closed_row(format!(
        " \x1b[48;5;236;38;5;226;1m FILTER \x1b[0m \x1b[38;5;255;1m{}█\x1b[0m   \x1b[38;5;245mSelected: {selected_count}/{total_pkg} packages\x1b[0m",
        state.picker_query
    ));
    picker_box.add_titled_divider("DISCOVERED WORKSPACE PACKAGES");

    let filtered = state.filtered_picker_packages();
    if filtered.is_empty() {
        picker_box.add_closed_row(
            "  \x1b[38;5;244mNo workspace packages match the current filter.\x1b[0m",
        );
    } else {
        let cursor = state.picker_cursor.min(filtered.len().saturating_sub(1));
        for (row_idx, row) in filtered.iter().enumerate() {
            let Some(pkg) = state.packages.get(row.package_idx) else {
                continue;
            };
            let is_cursor = row_idx == cursor;
            let is_selected = state
                .picker_selected
                .get(row.package_idx)
                .copied()
                .unwrap_or(true);
            let cursor_glyph = if is_cursor {
                "\x1b[38;5;51;1m▶\x1b[0m"
            } else {
                " "
            };
            let checkbox = if is_selected {
                "\x1b[38;5;48;1m[x]\x1b[0m"
            } else {
                "\x1b[38;5;240m[ ]\x1b[0m"
            };
            let name_str = highlight_fuzzy_matches(
                &pkg.name,
                &row.name_matches,
                "\x1b[38;5;255;1m",
                "\x1b[38;5;226;1;4m",
            );
            let path_str = highlight_fuzzy_matches(
                &pkg.rel_path,
                &row.path_matches,
                "\x1b[38;5;245m",
                "\x1b[38;5;226;1;4m",
            );
            picker_box.add_closed_row(format!(
                " {cursor_glyph} {checkbox} {name_str} ({path_str})  \x1b[38;5;250mscore:\x1b[0m \x1b[38;5;48;1m{}/100 ({})\x1b[0m  \x1b[38;5;250mfindings:\x1b[0m \x1b[38;5;220;1m{}\x1b[0m",
                pkg.health_score, pkg.score_label, pkg.diagnostic_count
            ));
        }
    }

    picker_box.render_lines(ColorMode::Ansi)
}

struct FilteredHeaderMetrics {
    health_score: u32,
    score_label: String,
    error_count: usize,
    warning_count: usize,
    autofix_count: usize,
    surgical_count: usize,
    refactor_count: usize,
    files_scanned: usize,
    subjects_scanned: usize,
    effects_scanned: usize,
    affected_file_count: usize,
    p0: usize,
    p1: usize,
    p2: usize,
    package_badge: String,
}

fn count_blast_tiers(groups: &[RootCauseGroup]) -> (usize, usize, usize) {
    let p0 = groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P0)
        .count();
    let p1 = groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P1)
        .count();
    let p2 = groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P2)
        .count();
    (p0, p1, p2)
}

fn compute_header_metrics(report: &JsonReport, state: &TuiState) -> FilteredHeaderMetrics {
    let s = &report.summary;
    if !state.has_active_package_filter() {
        let (p0, p1, p2) = count_blast_tiers(&report.root_cause_groups);
        return FilteredHeaderMetrics {
            health_score: s.health_score,
            score_label: s.score_label.clone(),
            error_count: s.error_count,
            warning_count: s.warning_count,
            autofix_count: s.autofix_count,
            surgical_count: s.surgical_count,
            refactor_count: s.refactor_count,
            files_scanned: s.files_scanned,
            subjects_scanned: s.subjects_scanned,
            effects_scanned: s.effects_scanned,
            affected_file_count: s.affected_file_count,
            p0,
            p1,
            p2,
            package_badge: String::new(),
        };
    }

    let mut error_count = 0usize;
    let mut warning_count = 0usize;
    let mut autofix_count = 0usize;
    let mut surgical_count = 0usize;
    let mut refactor_count = 0usize;
    let mut affected_files: BTreeSet<&Path> = BTreeSet::new();

    for d in &report.diagnostics {
        if !state.is_file_in_active_packages(&d.file) {
            continue;
        }
        affected_files.insert(&d.file);
        match d.severity {
            RuleSeverity::Error => error_count += 1,
            RuleSeverity::Warning => warning_count += 1,
        }
        match d.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
    }

    let active_groups: Vec<RootCauseGroup> = report
        .root_cause_groups
        .iter()
        .filter(|g| state.is_file_in_active_packages(&g.file))
        .cloned()
        .collect();
    let (p0, p1, p2) = count_blast_tiers(&active_groups);

    let selected_indices: Vec<usize> = state
        .active_packages
        .iter()
        .enumerate()
        .filter_map(|(idx, &active)| active.then_some(idx))
        .collect();

    let files_scanned: usize = selected_indices
        .iter()
        .filter_map(|&idx| {
            report
                .projects
                .get(idx)
                .map(|p| p.analyzed_file_count)
                .or_else(|| state.packages.get(idx).map(|p| p.analyzed_files.len()))
        })
        .sum();
    let subjects_scanned: usize = selected_indices
        .iter()
        .filter_map(|&idx| report.projects.get(idx).map(|p| p.subjects_scanned))
        .sum();

    let (health_score, score_label) = if let &[only_idx] = selected_indices.as_slice()
        && let Some(pkg) = state.packages.get(only_idx)
    {
        (pkg.health_score, pkg.score_label.clone())
    } else if selected_indices.is_empty() {
        (100, "Excellent".to_string())
    } else {
        let computed = compute_local_health_score(&active_groups, files_scanned, subjects_scanned);
        (computed.score, computed.label)
    };

    let selected_names: Vec<&str> = selected_indices
        .iter()
        .filter_map(|&idx| state.packages.get(idx).map(|p| p.name.as_str()))
        .collect();
    let names_label = if selected_names.is_empty() {
        "none".to_string()
    } else {
        selected_names.join(", ")
    };
    let package_badge = format!(
        " · \x1b[38;5;250mPackages:\x1b[0m \x1b[38;5;51;1m{}/{} ({names_label})\x1b[0m",
        selected_indices.len(),
        state.packages.len()
    );

    FilteredHeaderMetrics {
        health_score,
        score_label,
        error_count,
        warning_count,
        autofix_count,
        surgical_count,
        refactor_count,
        files_scanned,
        subjects_scanned,
        effects_scanned: s.effects_scanned,
        affected_file_count: affected_files.len(),
        p0,
        p1,
        p2,
        package_badge,
    }
}

fn format_tui_search_or_status_row(
    effective_tabs: &[TuiFilterTab],
    active_tab_idx: usize,
    state: &TuiState,
) -> String {
    let search_query = state.search_query.as_str();
    let active = effective_tabs.get(active_tab_idx);
    let active_badge = active.map_or("", |t| t.badge_ansi);
    let active_label = active.map_or("All", |t| t.label.as_str());
    let active_count = active.map_or(0, |t| t.count);

    if state.in_search_input {
        format!(
            " \x1b[48;5;236;38;5;226;1m SEARCH / \x1b[0m \x1b[38;5;255;1m{search_query}█\x1b[0m  \x1b[38;5;244m(Enter to lock, ESC to clear)\x1b[0m"
        )
    } else if let Some(status_msg) = state.status_message.as_deref() {
        format!(
            " \x1b[38;5;48;1m{status_msg}\x1b[0m   \x1b[38;5;245mActive Filter:\x1b[0m {active_badge}{active_label} ({active_count} matching)\x1b[0m"
        )
    } else if !search_query.is_empty() {
        format!(
            " \x1b[48;5;236;38;5;48;1m FILTER / \x1b[0m \x1b[38;5;255;1m\"{search_query}\"\x1b[0m  \x1b[38;5;244m(press / to edit, c to clear search)\x1b[0m"
        )
    } else {
        format!(
            " \x1b[38;5;245mActive Filter:\x1b[0m {active_badge}{active_label} ({active_count} matching)\x1b[0m   \x1b[38;5;244mPress `/` to search by file, rule, or Subject\x1b[0m"
        )
    }
}

fn build_tui_header_box(
    metrics: &FilteredHeaderMetrics,
    effective_tabs: &[TuiFilterTab],
    active_tab_idx: usize,
    state: &TuiState,
    box_inner_width: usize,
    design_mode: bool,
) -> AsciiBox {
    let gauge_cells = if box_inner_width < 88 { 10 } else { 16 };
    let score_gauge = if design_mode {
        "\x1b[38;5;219;1mUI DESIGN AUDIT\x1b[0m".to_string()
    } else {
        format!(
            "{} \x1b[38;5;248m({})\x1b[0m",
            build_score_gauge(metrics.health_score, gauge_cells),
            metrics.score_label
        )
    };

    let p0_badge =
        Badge::blast_radius_count(BlastRadiusTier::P0, metrics.p0).render_pill(ColorMode::Ansi);
    let p1_badge =
        Badge::blast_radius_count(BlastRadiusTier::P1, metrics.p1).render_pill(ColorMode::Ansi);
    let p2_badge =
        Badge::blast_radius_count(BlastRadiusTier::P2, metrics.p2).render_pill(ColorMode::Ansi);

    let mut header_box = AsciiBox::new(BoxBorderStyle::Double, box_inner_width)
        .with_indent(" ")
        .with_border_color("\x1b[38;5;51;1m")
        .with_title(format!(
            "DOTORE\x1b[0m \x1b[38;5;245m· Polyglot Static Analyzer\x1b[0m   {score_gauge}"
        ));
    header_box.add_closed_row(format!(
        " \x1b[38;5;196;1m✖ {} err\x1b[0m  \x1b[38;5;220;1m▲ {} warn\x1b[0m │ \x1b[38;5;48;1m⚙ {} autofix\x1b[0m  \x1b[38;5;220;1m✎ {} surgical\x1b[0m  \x1b[38;5;203;1m⇄ {} refactor\x1b[0m │ \x1b[38;5;250mBlast:\x1b[0m {p0_badge} {p1_badge} {p2_badge}",
        metrics.error_count,
        metrics.warning_count,
        metrics.autofix_count,
        metrics.surgical_count,
        metrics.refactor_count
    ));
    header_box.add_closed_row(format!(
        "  \x1b[38;5;250mScope:\x1b[0m {} files · {} subjects · {} effects · {} affected files{}  \x1b[38;5;250mView:\x1b[0m \x1b[38;5;219;1m{}\x1b[0m",
        metrics.files_scanned,
        metrics.subjects_scanned,
        metrics.effects_scanned,
        metrics.affected_file_count,
        metrics.package_badge,
        state.group_mode.label()
    ));
    header_box.add_titled_divider("FILTER TABS (h/l or ←/→ or Tab to switch)");

    let tab_strip = FilterTabBar::new(effective_tabs, active_tab_idx)
        .with_max_width(box_inner_width.saturating_sub(2))
        .render(ColorMode::Ansi);
    header_box.add_closed_row(format!(" {tab_strip}"));
    header_box.add_closed_row(format_tui_search_or_status_row(
        effective_tabs,
        active_tab_idx,
        state,
    ));
    header_box
}

/// Renders a complete TUI frame (header banner, [`FilterTabBar`], body viewport, and [`StatusBar`] footer)
/// as an ANSI string fitted to `(rows, cols)` using `state`.
#[must_use]
pub fn render_tui_frame_with_state(
    report: &JsonReport,
    tabs: &[TuiFilterTab],
    state: &TuiState,
    body_lines: &[String],
    rows: usize,
    cols: usize,
    design_mode: bool,
) -> String {
    let effective_tabs: Vec<TuiFilterTab> = if state.has_active_package_filter() {
        let pkg_diags: Vec<&Diagnostic> = report
            .diagnostics
            .iter()
            .filter(|d| state.is_file_in_active_packages(&d.file))
            .collect();
        let pkg_report = filter_report_for_diagnostics(report, &pkg_diags);
        build_filter_tabs(&pkg_report)
    } else {
        tabs.to_vec()
    };
    let active_tab_idx = state
        .active_tab_idx
        .min(effective_tabs.len().saturating_sub(1));
    let scroll_offset = state.scroll_offset;
    let metrics = compute_header_metrics(report, state);
    let effective_cols = cols.max(52);
    let box_inner_width = effective_cols.saturating_sub(4).max(46);
    let line_cap = effective_cols.saturating_sub(1);

    let mut frame = String::with_capacity(16384);
    frame.push_str("\x1b[H");

    let header_box = build_tui_header_box(
        &metrics,
        &effective_tabs,
        active_tab_idx,
        state,
        box_inner_width,
        design_mode,
    );
    let header_rendered = header_box.render_lines(ColorMode::Ansi);
    for line in &header_rendered {
        let fitted = truncate_ansi_to_width(line, line_cap);
        let _ = writeln!(frame, "\x1b[2K{fitted}");
    }
    let _ = writeln!(frame, "\x1b[2K");

    let header_rows = header_rendered.len() + 1;
    let footer_rows = 2usize;
    let viewport_height = rows.saturating_sub(header_rows + footer_rows).max(2);

    let overlay_lines = if state.in_package_picker {
        let mut lines = render_package_picker_lines(state, effective_cols);
        lines.push(String::new());
        lines
    } else {
        Vec::new()
    };

    let total_lines = body_lines.len().max(1);
    for row_idx in 0..viewport_height {
        if let Some(overlay_line) = overlay_lines.get(row_idx) {
            let fitted = truncate_ansi_to_width(overlay_line, line_cap);
            let _ = writeln!(frame, "\x1b[2K{fitted}");
            continue;
        }
        let line_idx = scroll_offset + row_idx.saturating_sub(overlay_lines.len());
        if let Some(line) = body_lines.get(line_idx) {
            let fitted = truncate_ansi_to_width(line, line_cap);
            let _ = writeln!(frame, "\x1b[2K{fitted}");
        } else {
            let _ = writeln!(frame, "\x1b[2K \x1b[38;5;237m~\x1b[0m");
        }
    }

    let end_line = (scroll_offset + viewport_height).min(total_lines);
    let active_tab_label = effective_tabs
        .get(active_tab_idx)
        .map_or("All", |t| t.label.as_str());
    let active_tab_count = effective_tabs.get(active_tab_idx).map_or(0, |t| t.count);
    let footer = StatusBar::tui_footer(
        active_tab_label,
        active_tab_count,
        state.group_mode.label(),
        (scroll_offset + 1).min(total_lines),
        end_line,
        total_lines,
        metrics.health_score,
        &metrics.score_label,
    );
    let footer_lines = footer.render_lines(ColorMode::Ansi);
    if let Some(row1) = footer_lines.first() {
        let fitted1 = truncate_ansi_to_width(row1, line_cap);
        let _ = writeln!(frame, "\x1b[2K{fitted1}");
    }
    if let Some(row2) = footer_lines.get(1) {
        let fitted2 = truncate_ansi_to_width(row2, line_cap);
        let _ = write!(frame, "\x1b[2K{fitted2}");
    }

    frame
}

/// Renders a complete TUI frame (header banner, [`FilterTabBar`], body viewport, and [`StatusBar`] footer)
/// as an ANSI string fitted to `(rows, cols)`.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "TUI frame renderer takes viewport dimensions and current UI state directly (#50)"
)]
pub fn render_tui_frame(
    report: &JsonReport,
    tabs: &[TuiFilterTab],
    active_tab_idx: usize,
    group_mode: TuiGroupMode,
    search_query: &str,
    in_search_input: bool,
    body_lines: &[String],
    scroll_offset: usize,
    rows: usize,
    cols: usize,
    design_mode: bool,
) -> String {
    let mut state = TuiState::new(tabs.len());
    state.active_tab_idx = active_tab_idx;
    state.group_mode = group_mode;
    state.search_query = search_query.to_string();
    state.in_search_input = in_search_input;
    state.scroll_offset = scroll_offset;
    render_tui_frame_with_state(report, tabs, &state, body_lines, rows, cols, design_mode)
}

/// Renders and flushes a TUI frame to `stdout`.
#[expect(
    clippy::too_many_arguments,
    reason = "TUI frame renderer takes viewport dimensions and current UI state directly (#50)"
)]
pub fn draw_tui_frame(
    report: &JsonReport,
    tabs: &[TuiFilterTab],
    active_tab_idx: usize,
    group_mode: TuiGroupMode,
    search_query: &str,
    in_search_input: bool,
    body_lines: &[String],
    scroll_offset: usize,
    rows: usize,
    cols: usize,
    design_mode: bool,
) {
    let frame = render_tui_frame(
        report,
        tabs,
        active_tab_idx,
        group_mode,
        search_query,
        in_search_input,
        body_lines,
        scroll_offset,
        rows,
        cols,
        design_mode,
    );
    let mut stdout = io::stdout();
    let _ = stdout.write_all(frame.as_bytes());
    let _ = stdout.flush();
}
