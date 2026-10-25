//! Reusable terminal UI component kit (`AsciiBox`, `GaugeBar`, `Badge`, `FlowDiagram`,
//! `FilterTabBar`, `StatusBar`, and `LiveSpinner`) for static terminal reports and the
//! interactive TUI explorer.

mod spinner;
mod widgets;

use std::{borrow::Cow, fmt::Write as _};

use crate::rules::{Diagnostic, RuleCategory, RuleTag};

pub use self::{spinner::*, widgets::*};
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

        let top_inner = self.render_top_border_inner(mode, g, bcol);
        lines.push(format!(
            "{}{bcol}{}{top_inner}{}{reset}",
            self.indent, g.top_left, g.top_right
        ));
        for row in &self.rows {
            lines.push(self.render_box_row(row, mode, g, bcol, reset));
        }
        let bottom_inner = g.horizontal.to_string().repeat(self.width);
        lines.push(format!(
            "{}{bcol}{}{bottom_inner}{}{reset}",
            self.indent, g.bottom_left, g.bottom_right
        ));
        lines
    }

    fn render_top_border_inner(&self, mode: ColorMode, g: BorderGlyphs, bcol: &str) -> String {
        let Some(title) = &self.title else {
            return g.horizontal.to_string().repeat(self.width);
        };
        let raw_title = mode_filtered_text(title, mode);
        let lead = if self.style == BoxBorderStyle::Double {
            format!("{}{}", g.horizontal, g.horizontal)
        } else {
            g.horizontal.to_string()
        };
        let lead_cols = visible_char_width(&lead) + 2;
        let max_title_cols = self.width.saturating_sub(lead_cols.min(self.width));
        let rendered_title = truncate_ansi_to_width(&raw_title, max_title_cols);
        let prefix = format!("{lead} {rendered_title} ");
        let rem = self.width.saturating_sub(visible_char_width(&prefix));
        let horiz = g.horizontal.to_string().repeat(rem);
        let restore = if mode.is_ansi() && !bcol.is_empty() && rendered_title.contains("\x1b[") {
            bcol
        } else {
            ""
        };
        format!("{prefix}{restore}{horiz}")
    }

    fn render_box_row(
        &self,
        row: &BoxRow,
        mode: ColorMode,
        g: BorderGlyphs,
        bcol: &str,
        reset: &str,
    ) -> String {
        match row {
            BoxRow::Closed(content) => self.render_closed_row(content, mode, g, bcol, reset),
            BoxRow::Open(content) => {
                let rendered = mode_filtered_text(content, mode);
                format!("{}{bcol}{}{reset}{rendered}", self.indent, g.vertical)
            }
            BoxRow::Unbordered(content) => {
                let rendered = mode_filtered_text(content, mode);
                format!("{}{rendered}", self.indent)
            }
            BoxRow::Divider => {
                let horiz = g.horizontal.to_string().repeat(self.width);
                format!("{}{bcol}{}{horiz}{}{reset}", self.indent, g.mid_left, g.mid_right)
            }
            BoxRow::TitledDivider(title) => {
                self.render_titled_divider_row(title, mode, g, bcol, reset)
            }
        }
    }

    fn render_closed_row(
        &self,
        content: &str,
        mode: ColorMode,
        g: BorderGlyphs,
        bcol: &str,
        reset: &str,
    ) -> String {
        let raw = mode_filtered_text(content, mode);
        let rendered = truncate_ansi_to_width(&raw, self.width);
        let pad = " ".repeat(self.width.saturating_sub(visible_char_width(&rendered)));
        let restore = if mode.is_ansi() && !bcol.is_empty() && rendered.contains("\x1b[") {
            bcol
        } else {
            ""
        };
        format!(
            "{}{bcol}{}{rendered}{restore}{pad}{}{reset}",
            self.indent, g.vertical, g.vertical
        )
    }

    fn render_titled_divider_row(
        &self,
        title: &str,
        mode: ColorMode,
        g: BorderGlyphs,
        bcol: &str,
        reset: &str,
    ) -> String {
        let raw = mode_filtered_text(title, mode);
        let rendered_title = truncate_ansi_to_width(&raw, self.width.saturating_sub(4));
        let prefix = format!("{}{} {} ", g.horizontal, g.horizontal, rendered_title);
        let horiz = g
            .horizontal
            .to_string()
            .repeat(self.width.saturating_sub(visible_char_width(&prefix)));
        let restore = if mode.is_ansi() && !bcol.is_empty() && rendered_title.contains("\x1b[") {
            bcol
        } else {
            ""
        };
        format!(
            "{}{bcol}{}{prefix}{restore}{horiz}{}{reset}",
            self.indent, g.mid_left, g.mid_right
        )
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

fn mode_filtered_text(text: &str, mode: ColorMode) -> Cow<'_, str> {
    if mode.is_ansi() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(strip_ansi_codes(text))
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

const STYLE_BUCKET_KEYWORD_RULES: &[(&[&str], Option<RuleCategory>, &str)] = &[
    (&["unused", "dead", "orphan"], None, "UNUSED"),
    (
        &["import", "circular", "barrel", "arch", "export"],
        None,
        "IMPORTS & ARCH",
    ),
    (
        &[
            "derived-state",
            "effect",
            "state",
            "signal",
            "prop-change",
            "hook",
        ],
        None,
        "EFFECTS & STATE",
    ),
    (
        &["async", "await", "tokio", "subscribe", "rxjs", "promise"],
        None,
        "ASYNC & STREAMS",
    ),
    (
        &[
            "unwrap",
            "guard",
            "optional-chain",
            "parse",
            "except",
            "unsafe",
            "cast",
            "context-manager",
            "mutable-default",
        ],
        None,
        "SAFETY & GUARDS",
    ),
    (
        &["security", "sql", "xss", "auth", "eval"],
        Some(RuleCategory::Security),
        "SECURITY",
    ),
    (
        &["a11y", "aria", "jsx", "key", "track", "dom"],
        Some(RuleCategory::Accessibility),
        "JSX & A11Y",
    ),
    (
        &[
            "perf", "loop", "clone", "memo", "on-push", "bundle", "capacity",
        ],
        Some(RuleCategory::Performance),
        "PERF & LOOPS",
    ),
];

/// Classifies a [`Diagnostic`] into its high-level TUI / report style bucket label.
#[must_use]
pub fn classify_style_bucket(diag: &Diagnostic) -> &'static str {
    let id = diag.rule.as_str();
    for &(keywords, cat_opt, bucket) in STYLE_BUCKET_KEYWORD_RULES {
        if (bucket == "IMPORTS & ARCH" && diag.rule.is_architecture_soc_or_reuse_rule())
            || (bucket == "EFFECTS & STATE" && !diag.cascade_steps.is_empty())
            || cat_opt == Some(diag.category)
            || keywords.iter().any(|kw| id.contains(kw))
        {
            return bucket;
        }
    }
    if diag.rule.metadata().tags.contains(&RuleTag::Design) || id.contains("design") {
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

