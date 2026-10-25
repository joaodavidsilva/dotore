//! Terminal UI widgets (`Badge`, `FlowDiagram`, `FilterTabBar`, and `StatusBar`).

use std::{collections::BTreeMap, fmt::Write as _};

use crate::{
    report::JsonReport,
    rules::{BlastRadiusTier, PrescriptionTier, RuleId, RuleSeverity},
};

use super::{
    AsciiBox, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, classify_style_bucket,
     strip_ansi_codes, style_bucket_color, truncate_ansi_to_width, visible_char_width,
};

/// Semantic variant of a [`Badge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadgeKind {
    /// **Prescription Tier** (`Autofix`, `Surgical`, `Refactor`).
    PrescriptionTier(PrescriptionTier),
    /// Diagnostic severity (`Error`, `Warning`).
    Severity(RuleSeverity),
    /// **Blast Radius** priority tier (`P0`–`P3`) with optional group count.
    BlastRadius(BlastRadiusTier, Option<usize>),
    /// TUI/report style bucket tag (`[EFFECTS & STATE]`, `[UNUSED]`, etc.).
    StyleBucket(&'static str),
    /// Canonical rule ID tag (`[no-derived-state]`).
    Rule(RuleId),
    /// Custom badge with explicit text and ANSI style.
    Custom {
        /// Visible badge label.
        label: String,
        /// ANSI escape sequence applied in [`ColorMode::Ansi`].
        ansi_code: &'static str,
    },
}

/// Reusable terminal badge/pill component for **Prescription Tiers**, **Blast Radius** (`P0`–`P3`),
/// severities, style buckets, and rule identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge {
    /// Semantic badge kind.
    pub kind: BadgeKind,
}

impl Badge {
    /// Creates a **Prescription Tier** badge (`Autofix`, `Surgical`, `Refactor`).
    #[must_use]
    pub const fn tier(tier: PrescriptionTier) -> Self {
        Self {
            kind: BadgeKind::PrescriptionTier(tier),
        }
    }

    /// Creates a severity badge (`Error`, `Warning`).
    #[must_use]
    pub const fn severity(severity: RuleSeverity) -> Self {
        Self {
            kind: BadgeKind::Severity(severity),
        }
    }

    /// Creates a **Blast Radius** tier badge (`P0`–`P3`).
    #[must_use]
    pub const fn blast_radius(tier: BlastRadiusTier) -> Self {
        Self {
            kind: BadgeKind::BlastRadius(tier, None),
        }
    }

    /// Creates a **Blast Radius** tier badge with a group count (`P0: 2`).
    #[must_use]
    pub const fn blast_radius_count(tier: BlastRadiusTier, count: usize) -> Self {
        Self {
            kind: BadgeKind::BlastRadius(tier, Some(count)),
        }
    }

    /// Creates a style bucket badge (`[EFFECTS & STATE]`, `[UNUSED]`, etc.).
    #[must_use]
    pub const fn style_bucket(bucket: &'static str) -> Self {
        Self {
            kind: BadgeKind::StyleBucket(bucket),
        }
    }

    /// Creates a rule identifier badge (`[no-derived-state]`).
    #[must_use]
    pub const fn rule(rule: RuleId) -> Self {
        Self {
            kind: BadgeKind::Rule(rule),
        }
    }

    /// Creates a custom badge with an explicit label and ANSI color sequence.
    #[must_use]
    pub fn custom(label: impl Into<String>, ansi_code: &'static str) -> Self {
        Self {
            kind: BadgeKind::Custom {
                label: label.into(),
                ansi_code,
            },
        }
    }

    /// Renders the compact inline representation of the badge for static reports and headers.
    #[must_use]
    pub fn render(&self, mode: ColorMode) -> String {
        match &self.kind {
            BadgeKind::PrescriptionTier(tier) => {
                let col = match tier {
                    PrescriptionTier::Autofix => "\x1b[32;1m",
                    PrescriptionTier::Surgical => "\x1b[33;1m",
                    PrescriptionTier::Refactor => "\x1b[31;1m",
                };
                mode.paint(col, &format!("({})", tier.as_str()))
            }
            BadgeKind::Severity(sev) => match sev {
                RuleSeverity::Error => mode.paint("\x1b[38;5;196;1m", "✖ ERROR"),
                RuleSeverity::Warning => mode.paint("\x1b[38;5;220;1m", "▲ WARN "),
            },
            BadgeKind::BlastRadius(tier, count) => {
                let col = match tier {
                    BlastRadiusTier::P0 => "\x1b[31;1m",
                    BlastRadiusTier::P1 => "\x1b[33;1m",
                    BlastRadiusTier::P2 => "\x1b[36;1m",
                    BlastRadiusTier::P3 => "\x1b[2m",
                };
                let text = match count {
                    Some(n) => format!("{}: {n}", tier.as_str()),
                    None => tier.as_str().to_string(),
                };
                mode.paint(col, &text)
            }
            BadgeKind::StyleBucket(bucket) => {
                mode.paint(style_bucket_color(bucket), &format!("[{bucket}]"))
            }
            BadgeKind::Rule(rule) => mode.paint("\x1b[36;1m", &format!("[{}]", rule.as_str())),
            BadgeKind::Custom { label, ansi_code } => mode.paint(ansi_code, label),
        }
    }

    /// Renders the dashboard tier label (`⚙ Autofix `, `✎ Surgical`, `⇄ Refactor`).
    #[must_use]
    pub fn render_dashboard_label(&self, mode: ColorMode) -> String {
        match &self.kind {
            BadgeKind::PrescriptionTier(PrescriptionTier::Autofix) => {
                mode.paint("\x1b[32;1m", "⚙ Autofix ")
            }
            BadgeKind::PrescriptionTier(PrescriptionTier::Surgical) => {
                mode.paint("\x1b[33;1m", "✎ Surgical")
            }
            BadgeKind::PrescriptionTier(PrescriptionTier::Refactor) => {
                mode.paint("\x1b[31;1m", "⇄ Refactor")
            }
            BadgeKind::Severity(_)
            | BadgeKind::BlastRadius(..)
            | BadgeKind::StyleBucket(_)
            | BadgeKind::Rule(_)
            | BadgeKind::Custom { .. } => self.render(mode),
        }
    }

    /// Renders the high-contrast pill representation (` ⚙ AUTOFIX `, `[P0: 3]`, etc.).
    #[must_use]
    pub fn render_pill(&self, mode: ColorMode) -> String {
        match &self.kind {
            BadgeKind::PrescriptionTier(PrescriptionTier::Autofix) => {
                mode.paint("\x1b[48;5;22;38;5;48;1m", " ⚙ AUTOFIX ")
            }
            BadgeKind::PrescriptionTier(PrescriptionTier::Surgical) => {
                mode.paint("\x1b[48;5;58;38;5;220;1m", " ✎ SURGICAL ")
            }
            BadgeKind::PrescriptionTier(PrescriptionTier::Refactor) => {
                mode.paint("\x1b[48;5;52;38;5;203;1m", " ⇄ REFACTOR ")
            }
            BadgeKind::BlastRadius(tier, count) => {
                let col = match tier {
                    BlastRadiusTier::P0 => "\x1b[38;5;196;1m",
                    BlastRadiusTier::P1 => "\x1b[38;5;208;1m",
                    BlastRadiusTier::P2 => "\x1b[38;5;51;1m",
                    BlastRadiusTier::P3 => "\x1b[38;5;244m",
                };
                let text = match count {
                    Some(n) => format!("[{}: {n}]", tier.as_str()),
                    None => format!("[{}]", tier.as_str()),
                };
                mode.paint(col, &text)
            }
            BadgeKind::Severity(_)
            | BadgeKind::StyleBucket(_)
            | BadgeKind::Rule(_)
            | BadgeKind::Custom { .. } => self.render(mode),
        }
    }
}

/// Reusable **Render Cascade** flow diagram renderer (`┌─► [node] ──► ... ──► ↻ re-render`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowDiagram<'a> {
    /// Ordered **Render Cascade** step labels.
    pub steps: &'a [String],
    /// Optional terminal sink label (defaults to `Some("↻ re-render")`).
    pub terminal_node: Option<&'a str>,
    /// Optional ANSI escape code applied to the entire flow diagram in [`ColorMode::Ansi`].
    pub color_override: Option<&'static str>,
}

impl<'a> FlowDiagram<'a> {
    /// Creates a new [`FlowDiagram`] from `steps` with default terminal node `"↻ re-render"`.
    #[must_use]
    pub const fn new(steps: &'a [String]) -> Self {
        Self {
            steps,
            terminal_node: Some("↻ re-render"),
            color_override: None,
        }
    }

    /// Sets or clears the terminal node appended at the end of the flow chain.
    #[must_use]
    pub const fn with_terminal_node(mut self, terminal_node: Option<&'a str>) -> Self {
        self.terminal_node = terminal_node;
        self
    }

    /// Sets the ANSI escape sequence used when rendering in [`ColorMode::Ansi`].
    #[must_use]
    pub const fn with_color(mut self, ansi_code: &'static str) -> Self {
        self.color_override = Some(ansi_code);
        self
    }

    /// Returns `true` when `steps` is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Renders the compact `step1 -> step2` cascade string.
    #[must_use]
    pub fn render_arrow_chain(&self) -> String {
        self.steps.join(" -> ")
    }

    /// Renders the boxed **Render Cascade** flow diagram (`┌─► [node] ──► ...`).
    #[must_use]
    pub fn render(&self, mode: ColorMode) -> String {
        if self.steps.is_empty() {
            return String::new();
        }
        let nodes: Vec<String> = self.steps.iter().map(|s| format!("[{s}]")).collect();
        let chain = nodes.join(" ──► ");
        let text = match self.terminal_node {
            Some(term) => format!("┌─► {chain} ──► {term}"),
            None => format!("┌─► {chain}"),
        };
        match self.color_override {
            Some(col) => mode.paint(col, &text),
            None => text,
        }
    }
}

/// Filter category kind for a [`FilterTabItem`] in [`FilterTabBar`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiFilterKind {
    /// All diagnostics.
    All,
    /// Only `Autofix`-tier diagnostics.
    Autofix,
    /// Only `Error`-severity diagnostics.
    Errors,
    /// Only `Warning`-severity diagnostics.
    Warnings,
    /// Diagnostics matching a specific style bucket (`"EFFECTS & STATE"`, `"UNUSED"`, etc.).
    StyleBucket(&'static str),
    /// Diagnostics emitted by a specific [`RuleId`].
    Rule(RuleId),
}

/// Single filter tab entry rendered by [`FilterTabBar`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterTabItem {
    /// Display label for the tab (`"ALL"`, `"⚙ AUTOFIX"`, `"EFFECTS & STATE"`, `"#no-derived-state"`).
    pub label: String,
    /// ANSI foreground escape sequence for inactive tab rendering.
    pub badge_ansi: &'static str,
    /// Semantic filter predicate kind.
    pub kind: TuiFilterKind,
    /// Number of diagnostics matching this tab.
    pub count: usize,
}

impl FilterTabItem {
    /// Creates a new [`FilterTabItem`].
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        count: usize,
        badge_ansi: &'static str,
        kind: TuiFilterKind,
    ) -> Self {
        Self {
            label: label.into(),
            badge_ansi,
            kind,
            count,
        }
    }
}

/// Builds the ordered list of [`FilterTabItem`]s for a [`JsonReport`].
#[must_use]
pub fn build_filter_tabs(report: &JsonReport) -> Vec<FilterTabItem> {
    let mut tabs = Vec::with_capacity(14 + report.diagnostics.len().min(32));
    tabs.push(FilterTabItem {
        label: "ALL".to_string(),
        badge_ansi: "\x1b[38;5;51;1m",
        kind: TuiFilterKind::All,
        count: report.diagnostics.len(),
    });

    let autofix_count = report
        .diagnostics
        .iter()
        .filter(|d| d.tier == PrescriptionTier::Autofix || d.autofix.is_some())
        .count();
    if autofix_count > 0 {
        tabs.push(FilterTabItem {
            label: "⚙ AUTOFIX".to_string(),
            badge_ansi: "\x1b[38;5;48;1m",
            kind: TuiFilterKind::Autofix,
            count: autofix_count,
        });
    }

    let err_count = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Error)
        .count();
    if err_count > 0 && err_count < report.diagnostics.len() {
        tabs.push(FilterTabItem {
            label: "✖ ERRORS".to_string(),
            badge_ansi: "\x1b[38;5;196;1m",
            kind: TuiFilterKind::Errors,
            count: err_count,
        });
    }

    let warn_count = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Warning)
        .count();
    if warn_count > 0 && warn_count < report.diagnostics.len() {
        tabs.push(FilterTabItem {
            label: "▲ WARNINGS".to_string(),
            badge_ansi: "\x1b[38;5;220;1m",
            kind: TuiFilterKind::Warnings,
            count: warn_count,
        });
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
        let c = report
            .diagnostics
            .iter()
            .filter(|d| classify_style_bucket(d) == bucket)
            .count();
        if c > 0 {
            tabs.push(FilterTabItem {
                label: bucket.to_string(),
                badge_ansi: style_bucket_color(bucket),
                kind: TuiFilterKind::StyleBucket(bucket),
                count: c,
            });
        }
    }

    let mut rule_counts: BTreeMap<&'static str, (RuleId, usize)> = BTreeMap::new();
    for d in &report.diagnostics {
        let entry = rule_counts.entry(d.rule.as_str()).or_insert((d.rule, 0));
        entry.1 += 1;
    }
    let mut sorted_rules: Vec<(RuleId, &'static str, usize)> = rule_counts
        .into_iter()
        .map(|(name, (id, count))| (id, name, count))
        .collect();
    sorted_rules.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(b.1)));

    for (rule_id, rule_name, count) in sorted_rules {
        tabs.push(FilterTabItem {
            label: format!("#{rule_name}"),
            badge_ansi: "\x1b[38;5;117;1m",
            kind: TuiFilterKind::Rule(rule_id),
            count,
        });
    }

    tabs
}

/// Windowed horizontal filter tab bar component supporting active pill highlighting and overflow indicators.
#[derive(Debug, Clone, Copy)]
pub struct FilterTabBar<'a> {
    /// Slice of all available filter tabs.
    pub tabs: &'a [FilterTabItem],
    /// Currently active tab index.
    pub active_index: usize,
    /// Maximum number of tabs visible in the sliding window (defaults to `8`).
    pub max_visible: usize,
    /// Optional maximum character width for the rendered tab strip (`0` = unbounded).
    pub max_width: usize,
}

impl<'a> FilterTabBar<'a> {
    /// Creates a new [`FilterTabBar`] with a default sliding window of `8` tabs.
    #[must_use]
    pub const fn new(tabs: &'a [FilterTabItem], active_index: usize) -> Self {
        Self {
            tabs,
            active_index,
            max_visible: 8,
            max_width: 0,
        }
    }

    /// Overrides the maximum number of visible tabs in the window.
    #[must_use]
    pub const fn with_max_visible(mut self, max_visible: usize) -> Self {
        self.max_visible = max_visible;
        self
    }

    /// Constrains the rendered tab strip to at most `max_width` visible characters (`0` = unbounded).
    #[must_use]
    pub const fn with_max_width(mut self, max_width: usize) -> Self {
        self.max_width = max_width;
        self
    }

    /// Renders the horizontal tab strip for the given [`ColorMode`].
    #[must_use]
    pub fn render(&self, mode: ColorMode) -> String {
        if self.tabs.is_empty() {
            return String::new();
        }
        let active_idx = self.active_index.min(self.tabs.len().saturating_sub(1));
        let (window_start, window_end) = if self.max_width == 0 {
            let start = active_idx.saturating_sub(3);
            let end = (start + self.max_visible.max(1)).min(self.tabs.len());
            (start, end)
        } else {
            self.compute_fitted_window(active_idx)
        };

        let mut out = String::new();
        if window_start > 0 {
            out.push_str(&mode.paint("\x1b[38;5;244m", "« "));
        }
        for (idx, tab) in self
            .tabs
            .iter()
            .enumerate()
            .take(window_end)
            .skip(window_start)
        {
            if idx == active_idx {
                let pill = format!(" ▶ {} ({}) ", tab.label, tab.count);
                let _ = write!(out, "{} ", mode.paint("\x1b[48;5;51;38;5;16;1m", &pill));
            } else {
                let item = format!("[ {} ({}) ]", tab.label, tab.count);
                let _ = write!(out, "{} ", mode.paint(tab.badge_ansi, &item));
            }
        }
        if window_end < self.tabs.len() {
            let more = format!("» (+{} more)", self.tabs.len() - window_end);
            out.push_str(&mode.paint("\x1b[38;5;244m", &more));
        }
        if self.max_width > 0 {
            truncate_ansi_to_width(&out, self.max_width)
        } else {
            out
        }
    }

    fn tab_display_width(&self, idx: usize, active_idx: usize) -> usize {
        let Some(tab) = self.tabs.get(idx) else {
            return 0;
        };
        if idx == active_idx {
            visible_char_width(&format!(" ▶ {} ({})  ", tab.label, tab.count))
        } else {
            visible_char_width(&format!("[ {} ({}) ] ", tab.label, tab.count))
        }
    }

    fn compute_fitted_window(&self, active_idx: usize) -> (usize, usize) {
        let mut start = active_idx;
        let mut end = active_idx + 1;
        let mut used = self.tab_display_width(active_idx, active_idx);
        let max_tabs = self.max_visible.max(1);

        while (end - start) < max_tabs {
            if self.try_expand_window_right(active_idx, start, &mut end, &mut used) {
                continue;
            }
            if self.try_expand_window_left(active_idx, &mut start, end, &mut used) {
                continue;
            }
            break;
        }
        (start, end)
    }

    fn try_expand_window_right(
        &self,
        active_idx: usize,
        start: usize,
        end: &mut usize,
        used: &mut usize,
    ) -> bool {
        if *end >= self.tabs.len() {
            return false;
        }
        let reserve_left = if start > 0 { 2 } else { 0 };
        let next_right_reserve = if *end + 1 < self.tabs.len() { 13 } else { 0 };
        let w = self.tab_display_width(*end, active_idx);
        if reserve_left + *used + w + next_right_reserve <= self.max_width {
            *used += w;
            *end += 1;
            true
        } else {
            false
        }
    }

    fn try_expand_window_left(
        &self,
        active_idx: usize,
        start: &mut usize,
        end: usize,
        used: &mut usize,
    ) -> bool {
        if *start == 0 {
            return false;
        }
        let reserve_right = if end < self.tabs.len() { 13 } else { 0 };
        let next_left_reserve = if *start - 1 > 0 { 2 } else { 0 };
        let w = self.tab_display_width(*start - 1, active_idx);
        if next_left_reserve + *used + w + reserve_right <= self.max_width {
            *used += w;
            *start -= 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
enum StatusBarLayout {
    ReportSummary {
        summary_line: String,
        baseline_line: Option<String>,
        autofix_hint: Option<String>,
    },
    DesignSummary(String),
    TuiFooter {
        active_tab_label: String,
        active_tab_count: usize,
        mode_label: String,
        start_line: usize,
        end_line: usize,
        total_lines: usize,
        health_score: u32,
        score_label: String,
    },
    Segments(Vec<String>),
}

/// Reusable terminal status bar component for both static report summary blocks and the
/// interactive TUI 2-row status/keybinding footer.
#[derive(Debug, Clone)]
pub struct StatusBar {
    layout: StatusBarLayout,
}

impl StatusBar {
    /// Creates a segmented status bar joining `segments` with `"  │  "`.
    #[must_use]
    pub const fn new(segments: Vec<String>) -> Self {
        Self {
            layout: StatusBarLayout::Segments(segments),
        }
    }

    /// Builds the static terminal report `SUMMARY` status box from a [`JsonReport`].
    #[must_use]
    pub fn from_report(report: &JsonReport) -> Self {
        let s = &report.summary;
        let summary_line = format!(
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
        let baseline_line = report.baseline.as_ref().map(|base| {
            format!(
                "baseline: {}  introduced: {}  fixed: {}  pre-existing: {}",
                base.baseline_source,
                base.introduced_count,
                base.fixed_count,
                base.preexisting_count
            )
        });
        let autofix_hint = if s.autofix_count > 0 {
            Some(format!(
                "Run `dotore fix` to automatically apply {} deterministic rewrite(s).",
                s.autofix_count
            ))
        } else {
            None
        };
        Self {
            layout: StatusBarLayout::ReportSummary {
                summary_line,
                baseline_line,
                autofix_hint,
            },
        }
    }

    /// Builds the single-line summary status bar for `dotore design`.
    #[must_use]
    pub fn design_summary(report: &JsonReport) -> Self {
        let s = &report.summary;
        Self {
            layout: StatusBarLayout::DesignSummary(format!(
                "dotore design  files: {}  subjects: {}  findings: {} (autofix: {}, surgical: {}, refactor: {})",
                s.files_scanned,
                s.subjects_scanned,
                s.total_diagnostics,
                s.autofix_count,
                s.surgical_count,
                s.refactor_count
            )),
        }
    }

    /// Builds the 2-row interactive TUI status and keybinding footer bar.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "TUI status bar captures active tab, mode, scroll range, and score directly (#50)"
    )]
    pub fn tui_footer(
        active_tab_label: impl Into<String>,
        active_tab_count: usize,
        mode_label: impl Into<String>,
        start_line: usize,
        end_line: usize,
        total_lines: usize,
        health_score: u32,
        score_label: impl Into<String>,
    ) -> Self {
        Self {
            layout: StatusBarLayout::TuiFooter {
                active_tab_label: active_tab_label.into(),
                active_tab_count,
                mode_label: mode_label.into(),
                start_line,
                end_line,
                total_lines,
                health_score,
                score_label: score_label.into(),
            },
        }
    }

    /// Renders the status bar into lines (without trailing newlines) for the given [`ColorMode`].
    #[must_use]
    pub fn render_lines(&self, mode: ColorMode) -> Vec<String> {
        match &self.layout {
            StatusBarLayout::ReportSummary {
                summary_line,
                baseline_line,
                autofix_hint,
            } => {
                let mut summary_box = AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH)
                    .with_title("SUMMARY")
                    .with_border_color("\x1b[36;1m");
                summary_box.add_unbordered_row(summary_line.clone());
                if let Some(base) = baseline_line {
                    summary_box.add_unbordered_row(base.clone());
                }
                if let Some(hint) = autofix_hint {
                    summary_box.add_unbordered_row(hint.clone());
                }
                summary_box.render_lines(mode)
            }
            StatusBarLayout::DesignSummary(line) => vec![line.clone()],
            StatusBarLayout::TuiFooter {
                active_tab_label,
                active_tab_count,
                mode_label,
                start_line,
                end_line,
                total_lines,
                health_score,
                score_label,
            } => {
                let clamped_total = (*total_lines).max(1);
                let pct = (*end_line * 100) / clamped_total;
                let ansi_row1 = format!(
                    "\x1b[48;5;235;38;5;255;1m DOTORE \x1b[48;5;238;38;5;51;1m {active_tab_label} ({active_tab_count}) \x1b[48;5;235;38;5;250m  Mode: {mode_label}  │  Lines {start_line}-{end_line} / {clamped_total} ({pct}%)  │  Score: {health_score}/100 ({score_label}) \x1b[0m"
                );
                let ansi_row2 = "\x1b[48;5;234;38;5;252m \x1b[38;5;51;1m[h/l or ←/→]\x1b[38;5;252m Filter Tab \x1b[38;5;51;1m[j/k]\x1b[38;5;252m Scroll \x1b[38;5;51;1m[v]\x1b[38;5;252m Group \x1b[38;5;51;1m[/]\x1b[38;5;252m Search \x1b[38;5;51;1m[p]\x1b[38;5;252m Packages \x1b[38;5;51;1m[y]\x1b[38;5;252m Copy Handoff \x1b[38;5;51;1m[a]\x1b[38;5;252m Launch Agent \x1b[38;5;196;1m[ESC/q]\x1b[38;5;252m Quit\x1b[0m".to_string();
                if mode.is_ansi() {
                    vec![ansi_row1, ansi_row2]
                } else {
                    vec![strip_ansi_codes(&ansi_row1), strip_ansi_codes(&ansi_row2)]
                }
            }
            StatusBarLayout::Segments(segments) => {
                let joined = segments.join("  │  ");
                if mode.is_ansi() {
                    vec![joined]
                } else {
                    vec![strip_ansi_codes(&joined)]
                }
            }
        }
    }

    /// Renders the status bar as a string for the given [`ColorMode`].
    #[must_use]
    pub fn render(&self, mode: ColorMode) -> String {
        let mut out = String::new();
        for line in self.render_lines(mode) {
            let _ = writeln!(out, "{line}");
        }
        out
    }
}
