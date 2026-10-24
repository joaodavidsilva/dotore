//! Interactive TUI explorer (`hjkl`/arrow navigation, dynamic error-style filter tabs,
//! grouping modes, `/` search, and `ESC` clean exit) built on `dotore_core::ui`.

use std::{
    collections::BTreeMap,
    env,
    fmt::Write as _,
    fs::OpenOptions,
    io::{self, IsTerminal, Read, Write},
    process::{Command, Stdio},
};

pub use dotore_core::ui::{FilterTabItem, TuiFilterKind, build_filter_tabs, classify_style_bucket};
use dotore_core::{
    report::JsonReport,
    rules::{BlastRadiusTier, Diagnostic, PrescriptionTier, RuleSeverity},
    ui::{
        AsciiBox, Badge, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, FilterTabBar, FlowDiagram,
        GaugeBar, StatusBar, truncate_ansi_to_width, visible_char_width,
    },
};

/// Filter tab descriptor rendered in the TUI header bar.
pub type TuiFilterTab = FilterTabItem;

/// Diagnostic grouping mode in the interactive TUI explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TuiGroupMode {
    /// Group diagnostics by error style bucket and rule ID.
    #[default]
    ByRuleStyle,
    /// Group diagnostics by file path.
    ByFile,
    /// Render each diagnostic as a standalone detailed **Render Cascade** card.
    DetailedCards,
}

impl TuiGroupMode {
    /// Cycles to the next [`TuiGroupMode`].
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::ByRuleStyle => Self::ByFile,
            Self::ByFile => Self::DetailedCards,
            Self::DetailedCards => Self::ByRuleStyle,
        }
    }

    /// Human-readable status label for the current grouping mode.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ByRuleStyle => "By Error Style / Rule",
            Self::ByFile => "By File",
            Self::DetailedCards => "Detailed Cascade Cards",
        }
    }
}

/// Interactive navigation, filter tab, grouping, and search state for the TUI explorer.
#[derive(Debug, Clone)]
pub struct TuiState {
    /// Currently selected filter tab index.
    pub active_tab_idx: usize,
    /// Total number of filter tabs available.
    pub tab_count: usize,
    /// Active diagnostic grouping mode.
    pub group_mode: TuiGroupMode,
    /// Active `/` search query string.
    pub search_query: String,
    /// Whether the user is currently typing in the `/` search input bar.
    pub in_search_input: bool,
    /// Current vertical scroll line offset.
    pub scroll_offset: usize,
}

impl TuiState {
    /// Creates a new [`TuiState`] for `tab_count` filter tabs.
    #[must_use]
    pub const fn new(tab_count: usize) -> Self {
        Self {
            active_tab_idx: 0,
            tab_count: if tab_count == 0 { 1 } else { tab_count },
            group_mode: TuiGroupMode::ByRuleStyle,
            search_query: String::new(),
            in_search_input: false,
            scroll_offset: 0,
        }
    }

    /// Processes a single raw key sequence (`key_bytes`), updating scroll, tab, group mode, or search state.
    ///
    /// Returns `true` when the user requested a clean exit (`ESC`, `q`, `Q`, or `Ctrl+C`).
    pub fn handle_key(
        &mut self,
        key_bytes: &[u8],
        viewport_height: usize,
        max_scroll: usize,
    ) -> bool {
        if self.in_search_input {
            handle_tui_search_key(
                key_bytes,
                &mut self.search_query,
                &mut self.in_search_input,
                &mut self.scroll_offset,
            );
            return false;
        }

        match key_bytes {
            // Bare ESC or 'q' or 'Q' or Ctrl+C -> exit TUI cleanly!
            [0x1b] | [b'q'] | [b'Q'] | [0x03] => return true,
            // Up arrow or 'k'
            [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] | [b'k'] => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            // Down arrow or 'j' or Enter
            [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] | [b'j'] | [b'\r'] | [b'\n'] => {
                self.scroll_offset = (self.scroll_offset + 1).min(max_scroll);
            }
            // Right arrow or 'l' or Tab -> next filter tab
            [0x1b, b'[', b'C'] | [0x1b, b'O', b'C'] | [b'l'] | [b'\t'] => {
                self.active_tab_idx = (self.active_tab_idx + 1) % self.tab_count;
                self.scroll_offset = 0;
            }
            // Left arrow or 'h' or Shift+Tab -> previous filter tab
            [0x1b, b'[', b'D'] | [0x1b, b'O', b'D'] | [0x1b, b'[', b'Z'] | [b'h'] => {
                self.active_tab_idx = if self.active_tab_idx == 0 {
                    self.tab_count - 1
                } else {
                    self.active_tab_idx - 1
                };
                self.scroll_offset = 0;
            }
            // PageDown or Space or 'd' or Ctrl+D
            [0x1b, b'[', b'6', b'~'] | [b' '] | [b'd'] | [0x04] => {
                self.scroll_offset =
                    (self.scroll_offset + viewport_height.saturating_sub(2)).min(max_scroll);
            }
            // PageUp or 'b' or 'u' or Ctrl+U
            [0x1b, b'[', b'5', b'~'] | [b'b'] | [b'u'] | [0x15] => {
                self.scroll_offset = self
                    .scroll_offset
                    .saturating_sub(viewport_height.saturating_sub(2));
            }
            // Home or 'g' or '0' -> top
            [0x1b, b'[', b'H'] | [b'g'] | [b'0'] => {
                self.scroll_offset = 0;
            }
            // End or 'G' -> bottom
            [0x1b, b'[', b'F'] | [b'G'] => {
                self.scroll_offset = max_scroll;
            }
            // 'v' -> toggle grouping mode (By Error Style / By File / Detailed Cards)
            [b'v'] | [b'V'] => {
                self.group_mode = self.group_mode.next();
                self.scroll_offset = 0;
            }
            // '/' -> start search filter
            [b'/'] => {
                self.in_search_input = true;
            }
            // 'c' -> clear search filter
            [b'c'] | [b'C'] => {
                self.search_query.clear();
                self.scroll_offset = 0;
            }
            // '1'..'9' quick filter tab jump
            [ch @ b'1'..=b'9'] => {
                let idx = (ch - b'1') as usize;
                if idx < self.tab_count {
                    self.active_tab_idx = idx;
                    self.scroll_offset = 0;
                }
            }
            _ => {}
        }
        false
    }
}

/// Returns `true` when the interactive TUI explorer should launch for the current terminal environment.
#[must_use]
pub fn should_launch_tui(no_pager: bool) -> bool {
    !no_pager
        && io::stdout().is_terminal()
        && io::stdin().is_terminal()
        && env::var_os("DOTORE_NO_PAGER").is_none()
        && env::var_os("CI").is_none()
        && !env::var("TERM").is_ok_and(|t| t == "dumb")
}

/// Returns `true` if `diag` matches both the active `tab` filter and `search_query`.
#[must_use]
pub fn diagnostic_matches_tab_and_search(
    diag: &Diagnostic,
    tab: &TuiFilterTab,
    search_query: &str,
) -> bool {
    let matches_tab = match &tab.kind {
        TuiFilterKind::All => true,
        TuiFilterKind::Autofix => diag.tier == PrescriptionTier::Autofix || diag.autofix.is_some(),
        TuiFilterKind::Errors => diag.severity == RuleSeverity::Error,
        TuiFilterKind::Warnings => diag.severity == RuleSeverity::Warning,
        TuiFilterKind::StyleBucket(bucket) => classify_style_bucket(diag) == *bucket,
        TuiFilterKind::Rule(r) => diag.rule == *r,
    };
    if !matches_tab {
        return false;
    }
    if search_query.is_empty() {
        return true;
    }
    let q = search_query.to_ascii_lowercase();
    diag.rule.as_str().to_ascii_lowercase().contains(&q)
        || diag
            .file
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(&q)
        || diag
            .subject_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(&q)
        || diag.message.to_ascii_lowercase().contains(&q)
}

struct TtyRawGuard {
    saved_stty: Option<String>,
}

impl TtyRawGuard {
    fn enter() -> Option<Self> {
        let tty_for_get = OpenOptions::new().read(true).open("/dev/tty").ok()?;
        let stty_out = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::from(tty_for_get))
            .output()
            .ok()?;
        let saved_stty = if stty_out.status.success() {
            Some(String::from_utf8_lossy(&stty_out.stdout).trim().to_string())
        } else {
            None
        };

        let tty_in = OpenOptions::new().read(true).open("/dev/tty").ok()?;
        let status = Command::new("stty")
            .args(["-icanon", "-echo", "min", "0", "time", "1"])
            .stdin(Stdio::from(tty_in))
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }

        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        let _ = stdout.flush();

        Some(Self { saved_stty })
    }
}

impl Drop for TtyRawGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved_stty
            && let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty")
        {
            let _ = Command::new("stty")
                .arg(saved)
                .stdin(Stdio::from(tty_in))
                .status();
        } else if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty") {
            let _ = Command::new("stty")
                .arg("sane")
                .stdin(Stdio::from(tty_in))
                .status();
        }
        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[?25h\x1b[?1049l");
        let _ = stdout.flush();
    }
}

fn query_terminal_size() -> (usize, usize) {
    if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty")
        && let Ok(out) = Command::new("stty")
            .arg("size")
            .stdin(Stdio::from(tty_in))
            .output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut parts = s.split_whitespace();
        if let (Some(r), Some(c)) = (parts.next(), parts.next())
            && let (Ok(rows), Ok(cols)) = (r.parse::<usize>(), c.parse::<usize>())
            && rows >= 12
            && cols >= 40
        {
            return (rows, cols);
        }
    }
    (36, 120)
}

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
        TuiGroupMode::ByFile => {
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
        TuiGroupMode::DetailedCards => {
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

/// Renders a complete TUI frame (header banner, [`FilterTabBar`], body viewport, and [`StatusBar`] footer)
/// as an ANSI string fitted to `(rows, cols)`.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "TUI frame renderer takes viewport dimensions and current UI state directly"
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
    let s = &report.summary;
    let effective_cols = cols.max(52);
    let box_inner_width = effective_cols.saturating_sub(4).max(46);
    let line_cap = effective_cols.saturating_sub(1);

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

    let mut frame = String::with_capacity(16384);
    frame.push_str("\x1b[H");

    let gauge_cells = if box_inner_width < 88 { 10 } else { 16 };
    let score_gauge = if design_mode {
        "\x1b[38;5;219;1mUI DESIGN AUDIT\x1b[0m".to_string()
    } else {
        format!(
            "{} \x1b[38;5;248m({})\x1b[0m",
            build_score_gauge(s.health_score, gauge_cells),
            s.score_label
        )
    };

    let p0_badge = Badge::blast_radius_count(BlastRadiusTier::P0, p0).render_pill(ColorMode::Ansi);
    let p1_badge = Badge::blast_radius_count(BlastRadiusTier::P1, p1).render_pill(ColorMode::Ansi);
    let p2_badge = Badge::blast_radius_count(BlastRadiusTier::P2, p2).render_pill(ColorMode::Ansi);

    let mut header_box = AsciiBox::new(BoxBorderStyle::Double, box_inner_width)
        .with_indent(" ")
        .with_border_color("\x1b[38;5;51;1m")
        .with_title(format!(
            "DOTORE\x1b[0m \x1b[38;5;245m· Polyglot Static Analyzer\x1b[0m   {score_gauge}"
        ));
    header_box.add_closed_row(format!(
        " \x1b[38;5;196;1m✖ {} err\x1b[0m  \x1b[38;5;220;1m▲ {} warn\x1b[0m │ \x1b[38;5;48;1m⚙ {} autofix\x1b[0m  \x1b[38;5;220;1m✎ {} surgical\x1b[0m  \x1b[38;5;203;1m⇄ {} refactor\x1b[0m │ \x1b[38;5;250mBlast:\x1b[0m {p0_badge} {p1_badge} {p2_badge}",
        s.error_count, s.warning_count, s.autofix_count, s.surgical_count, s.refactor_count
    ));
    header_box.add_closed_row(format!(
        "  \x1b[38;5;250mScope:\x1b[0m {} files · {} subjects · {} effects · {} affected files   \x1b[38;5;250mView:\x1b[0m \x1b[38;5;219;1m{}\x1b[0m",
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.affected_file_count,
        group_mode.label()
    ));
    header_box.add_titled_divider("FILTER TABS (h/l or ←/→ or Tab to switch)");

    let tab_strip = FilterTabBar::new(tabs, active_tab_idx)
        .with_max_width(box_inner_width.saturating_sub(2))
        .render(ColorMode::Ansi);
    header_box.add_closed_row(format!(" {tab_strip}"));

    let search_row = if in_search_input {
        format!(
            " \x1b[48;5;236;38;5;226;1m SEARCH / \x1b[0m \x1b[38;5;255;1m{search_query}█\x1b[0m  \x1b[38;5;244m(Enter to lock, ESC to clear)\x1b[0m"
        )
    } else if !search_query.is_empty() {
        format!(
            " \x1b[48;5;236;38;5;48;1m FILTER / \x1b[0m \x1b[38;5;255;1m\"{search_query}\"\x1b[0m  \x1b[38;5;244m(press / to edit, c to clear search)\x1b[0m"
        )
    } else {
        let active = &tabs[active_tab_idx];
        format!(
            " \x1b[38;5;245mActive Filter:\x1b[0m {}{} ({} matching)\x1b[0m   \x1b[38;5;244mPress `/` to search by file, rule, or component\x1b[0m",
            active.badge_ansi, active.label, active.count
        )
    };
    header_box.add_closed_row(search_row);

    let header_rendered = header_box.render_lines(ColorMode::Ansi);
    for line in &header_rendered {
        let fitted = truncate_ansi_to_width(line, line_cap);
        let _ = writeln!(frame, "\x1b[2K{fitted}");
    }
    let _ = writeln!(frame, "\x1b[2K");

    let header_rows = header_rendered.len() + 1;
    let footer_rows = 2usize;
    let viewport_height = rows.saturating_sub(header_rows + footer_rows).max(2);

    let total_lines = body_lines.len().max(1);
    for row_idx in 0..viewport_height {
        let line_idx = scroll_offset + row_idx;
        if let Some(line) = body_lines.get(line_idx) {
            let fitted = truncate_ansi_to_width(line, line_cap);
            let _ = writeln!(frame, "\x1b[2K{fitted}");
        } else {
            let _ = writeln!(frame, "\x1b[2K \x1b[38;5;237m~\x1b[0m");
        }
    }

    let end_line = (scroll_offset + viewport_height).min(total_lines);
    let active_tab = &tabs[active_tab_idx];
    let footer = StatusBar::tui_footer(
        &active_tab.label,
        active_tab.count,
        group_mode.label(),
        (scroll_offset + 1).min(total_lines),
        end_line,
        total_lines,
        s.health_score,
        &s.score_label,
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

/// Renders and flushes a TUI frame to `stdout`.
#[expect(
    clippy::too_many_arguments,
    reason = "TUI frame renderer takes viewport dimensions and current UI state directly"
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

/// Runs the interactive `/dev/tty` TUI explorer loop (`hjkl`/arrows, filter tabs, grouping modes, `/` search, `ESC` exit).
///
/// Automatically detects terminal resize events and reflows all boxes, tabs, and cards in real time.
/// Returns `true` if `/dev/tty` was available and the TUI ran, or `false` to fall back to static terminal output.
pub fn run_interactive_tui(report: &JsonReport, design_mode: bool) -> bool {
    let Ok(mut tty) = OpenOptions::new().read(true).open("/dev/tty") else {
        return false;
    };
    let Some(_guard) = TtyRawGuard::enter() else {
        return false;
    };

    let tabs = build_filter_tabs(report);
    let mut state = TuiState::new(tabs.len());
    let mut last_size = (0usize, 0usize);
    let mut needs_redraw = true;
    let mut cached_body_lines: Vec<String> = Vec::new();

    loop {
        let (rows, cols) = query_terminal_size();
        if (rows, cols) != last_size {
            last_size = (rows, cols);
            needs_redraw = true;
            let mut stdout = io::stdout();
            let _ = write!(stdout, "\x1b[2J\x1b[H");
            let _ = stdout.flush();
        }

        let viewport_height = rows.saturating_sub(10).max(2);
        if needs_redraw {
            let active_tab = &tabs[state.active_tab_idx];
            let filtered: Vec<&Diagnostic> = report
                .diagnostics
                .iter()
                .filter(|d| diagnostic_matches_tab_and_search(d, active_tab, &state.search_query))
                .collect();
            cached_body_lines = render_tui_body_lines_for_width(&filtered, state.group_mode, cols);
            let max_scroll = cached_body_lines.len().saturating_sub(viewport_height);
            if state.scroll_offset > max_scroll {
                state.scroll_offset = max_scroll;
            }

            draw_tui_frame(
                report,
                &tabs,
                state.active_tab_idx,
                state.group_mode,
                &state.search_query,
                state.in_search_input,
                &cached_body_lines,
                state.scroll_offset,
                rows,
                cols,
                design_mode,
            );
            needs_redraw = false;
        }

        let mut buf = [0u8; 16];
        let Ok(n) = tty.read(&mut buf) else {
            break;
        };
        if n == 0 {
            continue;
        }

        let max_scroll = cached_body_lines.len().saturating_sub(viewport_height);
        if state.handle_key(&buf[..n], viewport_height, max_scroll) {
            break;
        }
        needs_redraw = true;
    }

    true
}

/// Processes a key event while the TUI `/` search input bar is active.
pub fn handle_tui_search_key(
    key_bytes: &[u8],
    search_query: &mut String,
    in_search_input: &mut bool,
    scroll_offset: &mut usize,
) {
    if key_bytes == [0x1b] {
        search_query.clear();
        *in_search_input = false;
        *scroll_offset = 0;
        return;
    }
    if matches!(key_bytes, [b'\r' | b'\n']) {
        *in_search_input = false;
        return;
    }
    if matches!(key_bytes, [0x7f | 0x08]) {
        search_query.pop();
        *scroll_offset = 0;
        return;
    }
    let Ok(s) = std::str::from_utf8(key_bytes) else {
        return;
    };
    for ch in s.chars().filter(|c| !c.is_control()) {
        search_query.push(ch);
        *scroll_offset = 0;
    }
}
