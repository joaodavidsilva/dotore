//! Reusable terminal UI component kit (`AsciiBox`, `GaugeBar`, `Badge`, `FlowDiagram`,
//! `FilterTabBar`, `StatusBar`, and `LiveSpinner`) for static terminal reports and the
//! interactive TUI explorer.

use crate::{
    report::JsonReport,
    rules::{
        BlastRadiusTier, Diagnostic, PrescriptionTier, RuleCategory, RuleId, RuleSeverity, RuleTag,
    },
};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::OpenOptions,
    io::Write as _,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// Standard horizontal inner width (`78` characters between left and right box corners)
/// used across terminal reports.
pub const DEFAULT_BOX_WIDTH: usize = 78;

/// Controls whether terminal UI components emit plain ASCII/Unicode text or ANSI escape sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Emit plain text with zero ANSI escape sequences.
    #[default]
    Plain,
    /// Emit ANSI color and style escape sequences.
    Ansi,
}

impl ColorMode {
    /// Converts a boolean color flag (`true` = [`ColorMode::Ansi`], `false` = [`ColorMode::Plain`]).
    #[must_use]
    pub const fn from_bool(color: bool) -> Self {
        if color { Self::Ansi } else { Self::Plain }
    }

    /// Returns `true` when ANSI escape sequences are enabled.
    #[must_use]
    pub const fn is_ansi(self) -> bool {
        matches!(self, Self::Ansi)
    }

    /// Returns `code` in [`ColorMode::Ansi`] or `""` in [`ColorMode::Plain`].
    #[must_use]
    pub const fn code(self, ansi_code: &'static str) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Ansi => ansi_code,
        }
    }

    /// Bold cyan (`\x1b[36;1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn cyan(self) -> &'static str {
        self.code("\x1b[36;1m")
    }

    /// Dimmed text (`\x1b[2m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn dim(self) -> &'static str {
        self.code("\x1b[2m")
    }

    /// Bold text (`\x1b[1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn bold(self) -> &'static str {
        self.code("\x1b[1m")
    }

    /// Bold green (`\x1b[32;1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn green(self) -> &'static str {
        self.code("\x1b[32;1m")
    }

    /// Bold yellow (`\x1b[33;1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn yellow(self) -> &'static str {
        self.code("\x1b[33;1m")
    }

    /// Bold red (`\x1b[31;1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn red(self) -> &'static str {
        self.code("\x1b[31;1m")
    }

    /// Bold magenta (`\x1b[35;1m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn magenta(self) -> &'static str {
        self.code("\x1b[35;1m")
    }

    /// Reset escape sequence (`\x1b[0m`) in ANSI mode, `""` in plain mode.
    #[must_use]
    pub const fn reset(self) -> &'static str {
        self.code("\x1b[0m")
    }

    /// Wraps `text` with `ansi_code` and `\x1b[0m` when in [`ColorMode::Ansi`], or returns `text` unchanged.
    #[must_use]
    pub fn paint(self, ansi_code: &str, text: &str) -> String {
        if self.is_ansi() && !ansi_code.is_empty() {
            format!("{ansi_code}{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// Strips CSI ANSI escape sequences (`\x1b[...<final>`) from `input`, returning only visible characters.
#[must_use]
pub fn strip_ansi_codes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

const fn char_display_width(ch: char) -> usize {
    if matches!(
        ch,
        '\u{1100}'..='\u{115F}'
            | '\u{2E80}'..='\u{303E}'
            | '\u{3040}'..='\u{A4CF}'
            | '\u{AC00}'..='\u{D7A3}'
            | '\u{F900}'..='\u{FAFF}'
            | '\u{FE10}'..='\u{FE6F}'
            | '\u{FF00}'..='\u{FF60}'
            | '\u{1F300}'..='\u{1FAFF}'
    ) {
        2
    } else {
        1
    }
}

/// Computes the visible terminal column width of `input`, ignoring embedded ANSI CSI escape sequences.
#[must_use]
pub fn visible_char_width(input: &str) -> usize {
    let mut count = 0usize;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            count += char_display_width(ch);
        }
    }
    count
}

/// Truncates `input` (preserving ANSI CSI escape sequences) so its visible column width does not exceed `max_width`.
///
/// When truncation occurs and `max_width >= 1`, appends `…` (and `\x1b[0m` if `input` contained ANSI sequences).
#[must_use]
pub fn truncate_ansi_to_width(input: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if visible_char_width(input) <= max_width {
        return input.to_string();
    }
    let target_width = max_width.saturating_sub(1);
    let mut out = String::with_capacity(input.len());
    let mut width = 0usize;
    let mut saw_ansi = false;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            saw_ansi = true;
            out.push(ch);
            if let Some(bracket) = chars.next() {
                out.push(bracket);
            }
            for c in chars.by_ref() {
                out.push(c);
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            let ch_w = char_display_width(ch);
            if width + ch_w > target_width {
                break;
            }
            out.push(ch);
            width += ch_w;
        }
    }
    out.push('…');
    if saw_ansi {
        out.push_str("\x1b[0m");
    }
    out
}
/// Border glyph style for [`AsciiBox`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BoxBorderStyle {
    /// Rounded Unicode box (`╭ ╮ ╰ ╯ ─ │ ├ ┤`).
    #[default]
    Rounded,
    /// Single-line Unicode box (`┌ ┐ └ ┘ ─ │ ├ ┤`).
    Single,
    /// Double-line Unicode box (`╔ ╗ ╚ ╝ ═ ║ ╠ ╣`).
    Double,
}

#[derive(Debug, Clone, Copy)]
struct BorderGlyphs {
    top_left: char,
    top_right: char,
    bottom_left: char,
    bottom_right: char,
    horizontal: char,
    vertical: char,
    mid_left: char,
    mid_right: char,
}

impl BoxBorderStyle {
    const fn glyphs(self) -> BorderGlyphs {
        match self {
            Self::Rounded => BorderGlyphs {
                top_left: '╭',
                top_right: '╮',
                bottom_left: '╰',
                bottom_right: '╯',
                horizontal: '─',
                vertical: '│',
                mid_left: '├',
                mid_right: '┤',
            },
            Self::Single => BorderGlyphs {
                top_left: '┌',
                top_right: '┐',
                bottom_left: '└',
                bottom_right: '┘',
                horizontal: '─',
                vertical: '│',
                mid_left: '├',
                mid_right: '┤',
            },
            Self::Double => BorderGlyphs {
                top_left: '╔',
                top_right: '╗',
                bottom_left: '╚',
                bottom_right: '╝',
                horizontal: '═',
                vertical: '║',
                mid_left: '╠',
                mid_right: '╣',
            },
        }
    }
}

#[derive(Debug, Clone)]
enum BoxRow {
    Closed(String),
    Open(String),
    Unbordered(String),
    Divider,
    TitledDivider(String),
}

/// Deterministic ASCII/Unicode box layout builder supporting both plain-text and ANSI-color modes.
#[derive(Debug, Clone)]
pub struct AsciiBox {
    style: BoxBorderStyle,
    width: usize,
    title: Option<String>,
    border_color: &'static str,
    indent: String,
    rows: Vec<BoxRow>,
}

impl AsciiBox {
    /// Creates a new [`AsciiBox`] with the given `style` and inner character `width`.
    #[must_use]
    pub fn new(style: BoxBorderStyle, width: usize) -> Self {
        Self {
            style,
            width,
            title: None,
            border_color: "",
            indent: String::new(),
            rows: Vec::new(),
        }
    }

    /// Creates a rounded [`AsciiBox`] with the default `78`-character inner width.
    #[must_use]
    pub fn rounded_default() -> Self {
        Self::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH)
    }

    /// Sets an inline header title on the top border (e.g. `╭─ SUMMARY ────...────╮`).
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the ANSI escape code applied to the border glyphs when rendered in [`ColorMode::Ansi`].
    #[must_use]
    pub fn with_border_color(mut self, ansi_code: &'static str) -> Self {
        self.border_color = ansi_code;
        self
    }

    /// Sets a left indentation prefix prepended to every rendered line.
    #[must_use]
    pub fn with_indent(mut self, indent: impl Into<String>) -> Self {
        self.indent = indent.into();
        self
    }

    /// Appends a row enclosed by both left and right vertical borders, padded to `width`.
    pub fn add_closed_row(&mut self, content: impl Into<String>) -> &mut Self {
        self.rows.push(BoxRow::Closed(content.into()));
        self
    }

    /// Appends a row with a left vertical border and open right side (`│  content`).
    pub fn add_open_row(&mut self, content: impl Into<String>) -> &mut Self {
        self.rows.push(BoxRow::Open(content.into()));
        self
    }

    /// Appends a raw line inside the box without left or right vertical border characters.
    pub fn add_unbordered_row(&mut self, content: impl Into<String>) -> &mut Self {
        self.rows.push(BoxRow::Unbordered(content.into()));
        self
    }

    /// Appends a horizontal divider line (`├────...────┤`).
    pub fn add_divider(&mut self) -> &mut Self {
        self.rows.push(BoxRow::Divider);
        self
    }

    /// Appends a titled horizontal divider line (`╠══ TITLE ═══...═══╣`).
    pub fn add_titled_divider(&mut self, title: impl Into<String>) -> &mut Self {
        self.rows.push(BoxRow::TitledDivider(title.into()));
        self
    }

    /// Renders the box into a vector of lines (without trailing newlines) for the given [`ColorMode`].
    #[must_use]
    pub fn render_lines(&self, mode: ColorMode) -> Vec<String> {
        let g = self.style.glyphs();
        let bcol = mode.code(self.border_color);
        let reset = if bcol.is_empty() { "" } else { mode.reset() };
        let mut lines = Vec::with_capacity(self.rows.len() + 2);

        // Top border
        let top_inner = if let Some(title) = &self.title {
            let raw_title = if mode.is_ansi() {
                title.clone()
            } else {
                strip_ansi_codes(title)
            };
            let lead = if self.style == BoxBorderStyle::Double {
                format!("{}{}", g.horizontal, g.horizontal)
            } else {
                g.horizontal.to_string()
            };
            let lead_cols = visible_char_width(&lead) + 2;
            let max_title_cols = self.width.saturating_sub(lead_cols.min(self.width));
            let rendered_title = truncate_ansi_to_width(&raw_title, max_title_cols);
            let prefix = format!("{lead} {rendered_title} ");
            let prefix_len = visible_char_width(&prefix);
            let rem = self.width.saturating_sub(prefix_len);
            if mode.is_ansi() && !bcol.is_empty() && rendered_title.contains("\x1b[") {
                format!("{prefix}{bcol}{}", g.horizontal.to_string().repeat(rem))
            } else {
                format!("{prefix}{}", g.horizontal.to_string().repeat(rem))
            }
        } else {
            g.horizontal.to_string().repeat(self.width)
        };
        lines.push(format!(
            "{}{bcol}{}{top_inner}{}{reset}",
            self.indent, g.top_left, g.top_right
        ));

        for row in &self.rows {
            match row {
                BoxRow::Closed(content) => {
                    let raw_content = if mode.is_ansi() {
                        content.clone()
                    } else {
                        strip_ansi_codes(content)
                    };
                    let rendered_content = truncate_ansi_to_width(&raw_content, self.width);
                    let vis_len = visible_char_width(&rendered_content);
                    let pad = " ".repeat(self.width.saturating_sub(vis_len));
                    if mode.is_ansi() && !bcol.is_empty() && rendered_content.contains("\x1b[") {
                        lines.push(format!(
                            "{}{bcol}{}{rendered_content}{bcol}{pad}{}{reset}",
                            self.indent, g.vertical, g.vertical
                        ));
                    } else {
                        lines.push(format!(
                            "{}{bcol}{}{rendered_content}{pad}{}{reset}",
                            self.indent, g.vertical, g.vertical
                        ));
                    }
                }
                BoxRow::Open(content) => {
                    let rendered_content = if mode.is_ansi() {
                        content.clone()
                    } else {
                        strip_ansi_codes(content)
                    };
                    lines.push(format!(
                        "{}{bcol}{}{reset}{rendered_content}",
                        self.indent, g.vertical
                    ));
                }
                BoxRow::Unbordered(content) => {
                    let rendered_content = if mode.is_ansi() {
                        content.clone()
                    } else {
                        strip_ansi_codes(content)
                    };
                    lines.push(format!("{}{rendered_content}", self.indent));
                }
                BoxRow::Divider => {
                    let horiz = g.horizontal.to_string().repeat(self.width);
                    lines.push(format!(
                        "{}{bcol}{}{horiz}{}{reset}",
                        self.indent, g.mid_left, g.mid_right
                    ));
                }
                BoxRow::TitledDivider(title) => {
                    let raw_title = if mode.is_ansi() {
                        title.clone()
                    } else {
                        strip_ansi_codes(title)
                    };
                    let max_title_cols = self.width.saturating_sub(4);
                    let rendered_title = truncate_ansi_to_width(&raw_title, max_title_cols);
                    let prefix = format!("{}{} {} ", g.horizontal, g.horizontal, rendered_title);
                    let prefix_len = visible_char_width(&prefix);
                    let rem = self.width.saturating_sub(prefix_len);
                    let horiz = g.horizontal.to_string().repeat(rem);
                    if mode.is_ansi() && !bcol.is_empty() && rendered_title.contains("\x1b[") {
                        lines.push(format!(
                            "{}{bcol}{}{prefix}{bcol}{horiz}{}{reset}",
                            self.indent, g.mid_left, g.mid_right
                        ));
                    } else {
                        lines.push(format!(
                            "{}{bcol}{}{prefix}{horiz}{}{reset}",
                            self.indent, g.mid_left, g.mid_right
                        ));
                    }
                }
            }
        }

        // Bottom border
        let bottom_inner = g.horizontal.to_string().repeat(self.width);
        lines.push(format!(
            "{}{bcol}{}{bottom_inner}{}{reset}",
            self.indent, g.bottom_left, g.bottom_right
        ));

        lines
    }

    /// Renders the box as a newline-terminated string for the given [`ColorMode`].
    #[must_use]
    pub fn render(&self, mode: ColorMode) -> String {
        let mut out = String::new();
        for line in self.render_lines(mode) {
            let _ = writeln!(out, "{line}");
        }
        out
    }
}

/// Deterministic Unicode progress bar (`[████░░░░]`) with optional threshold coloring and ratio suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GaugeBar {
    /// Current numerator value.
    pub value: usize,
    /// Denominator maximum value (clamped to `>= 1` during rendering).
    pub max: usize,
    /// Character width of the inner bar (`█` + `░`).
    pub width: usize,
    /// Whether to append ` {value}/{max}` after the closing bracket.
    pub show_ratio: bool,
    /// Optional ANSI color escape sequence override.
    pub color_override: Option<&'static str>,
}

impl GaugeBar {
    /// Creates a new [`GaugeBar`] of `width` cells for `value / max`.
    #[must_use]
    pub const fn new(value: usize, max: usize, width: usize) -> Self {
        Self {
            value,
            max,
            width,
            show_ratio: false,
            color_override: None,
        }
    }

    /// Creates a health score [`GaugeBar`] (`0..=100`) colored by health threshold
    /// (`>= 85` green, `>= 60` yellow, `< 60` red).
    #[must_use]
    pub const fn health_score(score: u32, width: usize) -> Self {
        let col = if score >= 85 {
            "\x1b[32;1m"
        } else if score >= 60 {
            "\x1b[33;1m"
        } else {
            "\x1b[31;1m"
        };
        Self {
            value: score as usize,
            max: 100,
            width,
            show_ratio: false,
            color_override: Some(col),
        }
    }

    /// Overrides the ANSI color escape code used in [`ColorMode::Ansi`].
    #[must_use]
    pub const fn with_color(mut self, ansi_code: &'static str) -> Self {
        self.color_override = Some(ansi_code);
        self
    }

    /// Appends ` {value}/{max}` after `[████░░░░]` when `show` is `true`.
    #[must_use]
    pub const fn with_ratio_suffix(mut self, show: bool) -> Self {
        self.show_ratio = show;
        self
    }

    /// Switches threshold coloring to the 256-color TUI palette (`\x1b[38;5;48;1m`, `\x1b[38;5;220;1m`, `\x1b[38;5;196;1m`).
    #[must_use]
    pub const fn with_256_palette(mut self, enabled: bool) -> Self {
        if enabled {
            let col = if self.value >= 85 {
                "\x1b[38;5;48;1m"
            } else if self.value >= 60 {
                "\x1b[38;5;220;1m"
            } else {
                "\x1b[38;5;196;1m"
            };
            self.color_override = Some(col);
        }
        self
    }

    /// Computes `(filled, empty)` cell counts using rounded integer division.
    #[must_use]
    pub fn cells(self) -> (usize, usize) {
        let clamped_max = self.max.max(1);
        let filled = ((self.value.min(clamped_max) * self.width) + (clamped_max / 2)) / clamped_max;
        let filled = filled.min(self.width);
        let empty = self.width.saturating_sub(filled);
        (filled, empty)
    }

    /// Renders only the inner `████░░░░` cells without surrounding `[` `]` brackets.
    #[must_use]
    pub fn render_unbracketed(self) -> String {
        let (filled, empty) = self.cells();
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }

    /// Renders `[████░░░░]` (and optional ` {value}/{max}`) for the given [`ColorMode`].
    #[must_use]
    pub fn render(self, mode: ColorMode) -> String {
        let inner = self.render_unbracketed();
        let body = if self.show_ratio {
            format!("[{inner}] {}/{}", self.value, self.max)
        } else {
            format!("[{inner}]")
        };
        match self.color_override {
            Some(col) => mode.paint(col, &body),
            None => body,
        }
    }
}

/// Classifies a [`Diagnostic`] into its high-level TUI / report style bucket label.
#[must_use]
pub fn classify_style_bucket(diag: &Diagnostic) -> &'static str {
    let id = diag.rule.as_str();
    if id.contains("unused") || id.contains("dead") || id.contains("orphan") {
        "UNUSED"
    } else if diag.rule.is_architecture_soc_or_reuse_rule()
        || id.contains("import")
        || id.contains("circular")
        || id.contains("barrel")
        || id.contains("arch")
        || id.contains("export")
    {
        "IMPORTS & ARCH"
    } else if id.contains("derived-state")
        || id.contains("effect")
        || id.contains("state")
        || id.contains("signal")
        || id.contains("prop-change")
        || id.contains("hook")
        || !diag.cascade_steps.is_empty()
    {
        "EFFECTS & STATE"
    } else if id.contains("async")
        || id.contains("await")
        || id.contains("tokio")
        || id.contains("subscribe")
        || id.contains("rxjs")
        || id.contains("promise")
    {
        "ASYNC & STREAMS"
    } else if id.contains("unwrap")
        || id.contains("guard")
        || id.contains("optional-chain")
        || id.contains("parse")
        || id.contains("except")
        || id.contains("unsafe")
        || id.contains("cast")
        || id.contains("context-manager")
        || id.contains("mutable-default")
    {
        "SAFETY & GUARDS"
    } else if diag.category == RuleCategory::Security
        || id.contains("security")
        || id.contains("sql")
        || id.contains("xss")
        || id.contains("auth")
        || id.contains("eval")
    {
        "SECURITY"
    } else if diag.category == RuleCategory::Accessibility
        || id.contains("a11y")
        || id.contains("aria")
        || id.contains("jsx")
        || id.contains("key")
        || id.contains("track")
        || id.contains("dom")
    {
        "JSX & A11Y"
    } else if diag.category == RuleCategory::Performance
        || id.contains("perf")
        || id.contains("loop")
        || id.contains("clone")
        || id.contains("memo")
        || id.contains("on-push")
        || id.contains("bundle")
        || id.contains("capacity")
    {
        "PERF & LOOPS"
    } else if diag.rule.metadata().tags.contains(&RuleTag::Design) || id.contains("design") {
        "UI DESIGN"
    } else {
        "CORRECTNESS"
    }
}

/// Returns the 256-color ANSI foreground escape sequence for a style bucket name.
#[must_use]
pub const fn style_bucket_color(bucket: &str) -> &'static str {
    match bucket.as_bytes() {
        b"UNUSED" => "\x1b[38;5;214;1m",
        b"EFFECTS & STATE" => "\x1b[38;5;201;1m",
        b"ASYNC & STREAMS" => "\x1b[38;5;45;1m",
        b"SAFETY & GUARDS" => "\x1b[38;5;208;1m",
        b"SECURITY" => "\x1b[38;5;196;1m",
        b"JSX & A11Y" => "\x1b[38;5;141;1m",
        b"PERF & LOOPS" => "\x1b[38;5;220;1m",
        b"IMPORTS & ARCH" => "\x1b[38;5;75;1m",
        b"UI DESIGN" => "\x1b[38;5;219;1m",
        _ => "\x1b[38;5;81;1m",
    }
}

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
    let mut tabs = Vec::new();
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

    fn compute_fitted_window(&self, active_idx: usize) -> (usize, usize) {
        let tab_width = |idx: usize| -> usize {
            let tab = &self.tabs[idx];
            if idx == active_idx {
                visible_char_width(&format!(" ▶ {} ({})  ", tab.label, tab.count))
            } else {
                visible_char_width(&format!("[ {} ({}) ] ", tab.label, tab.count))
            }
        };
        let mut start = active_idx;
        let mut end = active_idx + 1;
        let mut used = tab_width(active_idx);
        let max_tabs = self.max_visible.max(1);

        while (end - start) < max_tabs {
            let reserve_left = if start > 0 { 2 } else { 0 };
            let reserve_right = if end < self.tabs.len() { 13 } else { 0 };
            // Prefer adding to the right first, then to the left
            if end < self.tabs.len() {
                let w = tab_width(end);
                let next_right_reserve = if end + 1 < self.tabs.len() { 13 } else { 0 };
                if reserve_left + used + w + next_right_reserve <= self.max_width {
                    used += w;
                    end += 1;
                    continue;
                }
            }
            if start > 0 {
                let w = tab_width(start - 1);
                let next_left_reserve = if start - 1 > 0 { 2 } else { 0 };
                if next_left_reserve + used + w + reserve_right <= self.max_width {
                    used += w;
                    start -= 1;
                    continue;
                }
            }
            break;
        }
        (start, end)
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
        reason = "TUI status bar captures active tab, mode, scroll range, and score directly"
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
                let ansi_row2 = "\x1b[48;5;234;38;5;252m \x1b[38;5;51;1m[h/l or ←/→]\x1b[38;5;252m Filter Tab  \x1b[38;5;51;1m[j/k or ↑/↓]\x1b[38;5;252m Scroll  \x1b[38;5;51;1m[Space/b]\x1b[38;5;252m Page  \x1b[38;5;51;1m[g/G]\x1b[38;5;252m Top/End  \x1b[38;5;51;1m[v]\x1b[38;5;252m Group Mode  \x1b[38;5;51;1m[/]\x1b[38;5;252m Search  \x1b[38;5;196;1m[ESC / q]\x1b[38;5;252m Quit \x1b[0m".to_string();
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

/// Braille animation frames used by [`LiveSpinner`].
pub const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Snapshot of live workspace scan progress for terminal loading animations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveScanProgressSnapshot {
    /// Current scan phase (`"Discovering workspace & files"`, `"Reading source files"`, `"Extracting AST & IR (parallel)"`, `"Evaluating ProjectGraph & Rules"`).
    pub phase: &'static str,
    /// Number of files processed in the current phase.
    pub completed_files: usize,
    /// Total files discovered for the scan.
    pub total_files: usize,
    /// Most recent file path touched by a worker thread.
    pub current_file: String,
}

static PROGRESS_PHASE_CODE: AtomicUsize = AtomicUsize::new(0);
static PROGRESS_COMPLETED: AtomicUsize = AtomicUsize::new(0);
static PROGRESS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static PROGRESS_CURRENT_FILE: Mutex<String> = Mutex::new(String::new());

fn normalize_progress_display_path(path: &Path) -> String {
    let raw = if let Ok(cwd) = std::env::current_dir()
        && let Ok(stripped) = path.strip_prefix(&cwd)
    {
        stripped.to_string_lossy().into_owned()
    } else {
        path.to_string_lossy().into_owned()
    };
    let clean = raw.replace('\\', "/");
    clean
        .strip_prefix("./")
        .unwrap_or(clean.as_str())
        .to_string()
}

fn set_current_progress_file(path: &Path) {
    let formatted = normalize_progress_display_path(path);
    if !formatted.is_empty()
        && let Ok(mut guard) = PROGRESS_CURRENT_FILE.try_lock()
    {
        *guard = formatted;
    }
}

/// Updates the active workspace scan phase code (`1..=4`) and resets the completed file counter.
pub fn set_progress_phase(code: usize, total: usize) {
    PROGRESS_PHASE_CODE.store(code, Ordering::Relaxed);
    PROGRESS_COMPLETED.store(0, Ordering::Relaxed);
    PROGRESS_TOTAL.store(total, Ordering::Relaxed);
    if code <= 1
        && total == 0
        && let Ok(mut guard) = PROGRESS_CURRENT_FILE.try_lock()
    {
        guard.clear();
    }
}

/// Records a newly discovered source file during Phase 1 (`Discovering workspace & files`),
/// incrementing both the discovered total and completed counters and updating `current_file`.
pub fn tick_discovery_file(path: &Path) {
    if PROGRESS_PHASE_CODE.load(Ordering::Relaxed) == 1 {
        let total = PROGRESS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        PROGRESS_COMPLETED.store(total, Ordering::Relaxed);
        set_current_progress_file(path);
    }
}

/// Increments the completed file counter and updates `path` in the lock-free progress snapshot.
pub fn tick_progress_file(path: &Path) {
    PROGRESS_COMPLETED.fetch_add(1, Ordering::Relaxed);
    set_current_progress_file(path);
}

/// Returns a lock-free snapshot of the current workspace scan progress.
#[must_use]
pub fn current_scan_progress() -> LiveScanProgressSnapshot {
    let phase = match PROGRESS_PHASE_CODE.load(Ordering::Relaxed) {
        1 => "Discovering workspace & files",
        2 => "Reading source files",
        3 => "Extracting AST & IR (parallel)",
        4 => "Evaluating ProjectGraph & Rules",
        _ => "Initializing",
    };
    let completed_files = PROGRESS_COMPLETED.load(Ordering::Relaxed);
    let total_files = PROGRESS_TOTAL.load(Ordering::Relaxed);
    let current_file = PROGRESS_CURRENT_FILE
        .try_lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    LiveScanProgressSnapshot {
        phase,
        completed_files,
        total_files,
        current_file,
    }
}

/// Formats a single 30fps [`LiveSpinner`] progress line for `snap` at `tick` and `elapsed_secs`.
#[must_use]
pub fn format_spinner_frame(
    snap: &LiveScanProgressSnapshot,
    tick: usize,
    elapsed_secs: f32,
    mode: ColorMode,
) -> String {
    format_spinner_frame_with_width(snap, tick, elapsed_secs, mode, 140)
}

/// Formats a single 30fps [`LiveSpinner`] progress line fitted to `max_cols` terminal columns.
#[must_use]
pub fn format_spinner_frame_with_width(
    snap: &LiveScanProgressSnapshot,
    tick: usize,
    elapsed_secs: f32,
    mode: ColorMode,
    max_cols: usize,
) -> String {
    let frame_ch = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
    let total = snap.total_files.max(1);
    let done = snap.completed_files.min(snap.total_files);
    let pct = if snap.total_files > 0 {
        (done * 100) / total
    } else {
        0
    };
    let bar_width = if max_cols > 0 && max_cols < 90 {
        10usize
    } else if max_cols > 0 && max_cols < 115 {
        14usize
    } else {
        22usize
    };
    let phase_label = if max_cols > 0 && max_cols < 115 {
        match snap.phase {
            "Discovering workspace & files" => "Discovering",
            "Reading source files" => "Reading",
            "Extracting AST & IR (parallel)" => "Parsing",
            "Evaluating ProjectGraph & Rules" => "Analyzing",
            other => other,
        }
    } else {
        snap.phase
    };
    let bar = if snap.total_files > 0 {
        GaugeBar::new(done, total, bar_width).render_unbracketed()
    } else {
        let filled = (tick % bar_width).min(bar_width);
        let empty = bar_width.saturating_sub(filled);
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    };

    let prefix_plain = format!(
        " {frame_ch} DOTORE  [{bar}] {pct:>3}% ({done}/{}) · {elapsed_secs:.1}s · {phase_label}  ",
        snap.total_files
    );
    let prefix_cols = visible_char_width(&prefix_plain);
    let file_budget = if max_cols > prefix_cols + 8 {
        (max_cols - prefix_cols).min(48)
    } else {
        24
    };

    let short_file = if snap.current_file.chars().count() > file_budget {
        let keep = file_budget.saturating_sub(1).max(8);
        let tail: String = snap
            .current_file
            .chars()
            .rev()
            .take(keep)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("…{tail}")
    } else {
        snap.current_file.clone()
    };

    let ansi = format!(
        " \x1b[38;5;51;1m{frame_ch} DOTORE\x1b[0m  \x1b[38;5;48;1m[{bar}]\x1b[0m \x1b[38;5;255;1m{pct:>3}%\x1b[0m \x1b[38;5;245m({done}/{})\x1b[0m · \x1b[38;5;220;1m{elapsed_secs:.1}s\x1b[0m · \x1b[38;5;141;1m{phase_label}\x1b[0m  \x1b[38;5;117;1m{short_file}\x1b[0m",
        snap.total_files
    );
    let rendered = if mode.is_ansi() {
        ansi
    } else {
        strip_ansi_codes(&ansi)
    };
    if max_cols > 0 {
        truncate_ansi_to_width(&rendered, max_cols)
    } else {
        rendered
    }
}

fn query_tty_cols() -> usize {
    if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty")
        && let Ok(out) = std::process::Command::new("stty")
            .arg("size")
            .stdin(std::process::Stdio::from(tty_in))
            .output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut parts = s.split_whitespace();
        let _ = parts.next();
        if let Some(c) = parts.next()
            && let Ok(cols) = c.parse::<usize>()
            && cols >= 40
        {
            return cols;
        }
    }
    120
}

/// Lock-free ~30fps (`30ms` interval) background `/dev/tty` spinner and progress bar RAII guard.
#[derive(Debug)]
pub struct LiveSpinner {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LiveSpinner {
    /// Starts the background `/dev/tty` spinner thread if `/dev/tty` is writable.
    #[must_use]
    pub fn start() -> Option<Self> {
        let mut tty = OpenOptions::new().write(true).open("/dev/tty").ok()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut tick = 0usize;
            let mut cols = query_tty_cols();
            let _ = write!(tty, "\x1b[?25l");
            let _ = tty.flush();
            while !stop_clone.load(Ordering::Relaxed) {
                if tick.is_multiple_of(10) {
                    cols = query_tty_cols();
                }
                let snap = current_scan_progress();
                let elapsed = start.elapsed().as_secs_f32();
                let frame = format_spinner_frame_with_width(
                    &snap,
                    tick,
                    elapsed,
                    ColorMode::Ansi,
                    cols.saturating_sub(2),
                );
                let _ = write!(tty, "\r\x1b[2K{frame}");
                let _ = tty.flush();
                tick += 1;
                thread::sleep(Duration::from_millis(30));
            }
            let _ = write!(tty, "\r\x1b[2K\x1b[?25h");
            let _ = tty.flush();
        });
        Some(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for LiveSpinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
