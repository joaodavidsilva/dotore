//! Interactive TUI explorer (`hjkl`/arrow navigation, dynamic error-style filter tabs,
//! grouping modes, `/` search, and `ESC` clean exit) built on `dotore_core::ui`.

mod render;

use std::{
    borrow::Cow,
    env,
    fs::OpenOptions,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub use dotore_core::ui::{FilterTabItem, TuiFilterKind, build_filter_tabs, classify_style_bucket};
use dotore_core::{
    config::resolve_dotore_home_dir,
    planner::{
        build_agent_handoff_prompt, copy_to_clipboard, detect_available_coding_agents,
        execute_handoff, filter_report_for_diagnostics, load_preferred_handoff_target,
    },
    report::{JsonReport, ProjectCoverageMetadata},
    rules::{Diagnostic, PrescriptionTier, RuleSeverity},
    search::score_fuzzy,
};

pub use self::render::{
    build_score_gauge, draw_tui_frame, highlight_fuzzy_matches, render_package_picker_lines,
    render_tui_body_lines, render_tui_body_lines_for_width, render_tui_frame,
    render_tui_frame_with_state,
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

/// A workspace package entry displayed in the interactive TUI package picker (`p`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiPackageItem {
    /// Package name.
    pub name: String,
    /// Workspace-relative directory path display string.
    pub rel_path: String,
    /// Root directory path of the package.
    pub root_dir: PathBuf,
    /// Number of diagnostics in this package.
    pub diagnostic_count: usize,
    /// Individual `0..=100` Health Score for this package.
    pub health_score: u32,
    /// Human-readable score label (`"Excellent"`, `"Good"`, etc.).
    pub score_label: String,
    /// Analyzed files belonging to this package.
    pub analyzed_files: Vec<PathBuf>,
}

impl TuiPackageItem {
    /// Converts a [`ProjectCoverageMetadata`] record from [`JsonReport`] into a [`TuiPackageItem`].
    #[must_use]
    pub fn from_metadata(meta: &ProjectCoverageMetadata) -> Self {
        Self {
            name: meta.name.clone(),
            rel_path: format_package_rel_path(&meta.root_dir),
            root_dir: meta.root_dir.clone(),
            diagnostic_count: meta.diagnostic_count,
            health_score: meta.health_score,
            score_label: meta.score_label.clone(),
            analyzed_files: meta.analyzed_files.clone(),
        }
    }
}

fn normalize_rel_display(raw: &str) -> String {
    let clean = raw.replace('\\', "/");
    let trimmed = clean
        .strip_prefix("./")
        .unwrap_or(clean.as_str())
        .trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        ".".to_string()
    } else {
        trimmed.to_string()
    }
}

fn format_package_rel_path(root_dir: &Path) -> String {
    if root_dir.is_relative() {
        return normalize_rel_display(&root_dir.to_string_lossy());
    }
    if let Ok(cwd) = env::current_dir()
        && let Ok(stripped) = root_dir.strip_prefix(&cwd)
    {
        return normalize_rel_display(&stripped.to_string_lossy());
    }
    if let Some(parent) = root_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        && matches!(
            parent,
            "apps" | "packages" | "services" | "crates" | "libs" | "modules"
        )
        && let Some(leaf) = root_dir.file_name().and_then(|s| s.to_str())
    {
        return format!("{parent}/{leaf}");
    }
    normalize_rel_display(&root_dir.to_string_lossy())
}

fn common_ancestor_dir(paths: &[PathBuf]) -> Option<PathBuf> {
    let [first, rest @ ..] = paths else {
        return None;
    };
    if !first.is_absolute() {
        return None;
    }
    let mut ancestor = first.clone();
    for path in rest {
        if !path.is_absolute() {
            return None;
        }
        while !path.starts_with(&ancestor) {
            if !ancestor.pop() {
                return None;
            }
        }
    }
    (ancestor.components().count() > 1).then_some(ancestor)
}

/// A fuzzy-filtered package row in the TUI package picker with character match indices.
#[derive(Debug, Clone, PartialEq)]
pub struct FilteredPackageRow {
    /// Index into `TuiState::packages`.
    pub package_idx: usize,
    /// Fuzzy match score (`0.0` when query is empty).
    pub score: f64,
    /// 0-based matched character indices in `name`.
    pub name_matches: Vec<usize>,
    /// 0-based matched character indices in `rel_path`.
    pub path_matches: Vec<usize>,
}

/// Interactive navigation, filter tab, grouping, search, and package picker state for the TUI explorer.
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
    /// Whether the workspace package picker overlay (`p`) is currently open.
    pub in_package_picker: bool,
    /// Discovered workspace packages available in the package picker (`p`).
    pub packages: Vec<TuiPackageItem>,
    /// Currently highlighted row index inside the filtered package picker list.
    pub picker_cursor: usize,
    /// Fuzzy filter query typed inside the package picker.
    pub picker_query: String,
    /// Working package selection flags inside the picker (indexed by `packages`).
    pub picker_selected: Vec<bool>,
    /// Active package selection flags applied via `Enter` (indexed by `packages`).
    pub active_packages: Vec<bool>,
    /// Transient status bar confirmation or error message from TUI actions (`y`, `a`, `p`).
    pub status_message: Option<String>,
    report_snapshot: Option<(JsonReport, Vec<TuiFilterTab>)>,
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
            in_package_picker: false,
            packages: Vec::new(),
            picker_cursor: 0,
            picker_query: String::new(),
            picker_selected: Vec::new(),
            active_packages: Vec::new(),
            status_message: None,
            report_snapshot: None,
        }
    }

    /// Attaches discovered workspace `packages` to this [`TuiState`], selecting all packages by default.
    #[must_use]
    pub fn with_packages(mut self, packages: Vec<TuiPackageItem>) -> Self {
        let count = packages.len();
        self.packages = packages;
        self.picker_selected = vec![true; count];
        self.active_packages = vec![true; count];
        self
    }

    /// Creates a [`TuiState`] initialized with `report` and `tabs` so package filtering (`p`)
    /// and TUI handoff actions (`y`/`a`) operate on the full report metadata.
    #[must_use]
    pub fn from_report(report: &JsonReport, tabs: &[TuiFilterTab]) -> Self {
        let mut packages: Vec<TuiPackageItem> = report
            .projects
            .iter()
            .map(TuiPackageItem::from_metadata)
            .collect();
        let root_dirs: Vec<PathBuf> = report.projects.iter().map(|p| p.root_dir.clone()).collect();
        if root_dirs.len() > 1
            && let Some(ancestor) = common_ancestor_dir(&root_dirs)
        {
            for item in &mut packages {
                if Path::new(&item.rel_path).is_absolute()
                    && let Ok(stripped) = item.root_dir.strip_prefix(&ancestor)
                {
                    item.rel_path = normalize_rel_display(&stripped.to_string_lossy());
                }
            }
        }
        let mut state = Self::new(tabs.len()).with_packages(packages);
        state.report_snapshot = Some((report.clone(), tabs.to_vec()));
        state
    }

    /// Returns `true` if a subset of workspace packages is currently filtered via the package picker.
    #[must_use]
    pub fn has_active_package_filter(&self) -> bool {
        !self.packages.is_empty()
            && self.active_packages.len() == self.packages.len()
            && !self.active_packages.iter().all(|&b| b)
    }

    /// Returns `true` if `file` belongs to one of the currently active workspace packages.
    #[must_use]
    pub fn is_file_in_active_packages(&self, file: &Path) -> bool {
        if !self.has_active_package_filter() {
            return true;
        }
        if self.active_packages.iter().all(|&b| !b) {
            return false;
        }
        for (idx, pkg) in self.packages.iter().enumerate() {
            let is_active = self.active_packages.get(idx).copied().unwrap_or(false);
            if is_active && pkg.analyzed_files.iter().any(|f| f == file) {
                return true;
            }
        }
        if let Some(best_idx) = self.resolve_package_index_for_path(file) {
            return self.active_packages.get(best_idx).copied().unwrap_or(false);
        }
        false
    }

    fn resolve_package_index_for_path(&self, file: &Path) -> Option<usize> {
        let file_norm = normalize_rel_display(&file.to_string_lossy());
        let mut best: Option<(usize, usize)> = None;
        for (idx, pkg) in self.packages.iter().enumerate() {
            let matches_root = pkg.root_dir == Path::new(".")
                || file.starts_with(&pkg.root_dir)
                || pkg.rel_path == "."
                || file_norm == pkg.rel_path
                || file_norm
                    .strip_prefix(&pkg.rel_path)
                    .is_some_and(|rest| rest.starts_with('/'));
            if !matches_root {
                continue;
            }
            let specificity = if pkg.rel_path == "." {
                0
            } else {
                pkg.rel_path.len().max(pkg.root_dir.as_os_str().len())
            };
            if best.is_none_or(|(_, best_len)| specificity > best_len) {
                best = Some((idx, specificity));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// Returns the workspace packages matching `picker_query`, ranked by fuzzy match score
    /// with character match indices for `name` and `rel_path`.
    #[must_use]
    pub fn filtered_picker_packages(&self) -> Vec<FilteredPackageRow> {
        let query = self.picker_query.trim();
        if query.is_empty() {
            return (0..self.packages.len())
                .map(|package_idx| FilteredPackageRow {
                    package_idx,
                    score: 0.0,
                    name_matches: Vec::new(),
                    path_matches: Vec::new(),
                })
                .collect();
        }
        let mut rows: Vec<FilteredPackageRow> = self
            .packages
            .iter()
            .enumerate()
            .filter_map(|(package_idx, pkg)| {
                let name_hit = score_fuzzy(query, &pkg.name);
                let path_hit = score_fuzzy(query, &pkg.rel_path);
                if name_hit.is_none() && path_hit.is_none() {
                    return None;
                }
                let name_score = name_hit.as_ref().map(|(s, _)| *s + 2.0);
                let path_score = path_hit.as_ref().map(|(s, _)| *s);
                let score = match (name_score, path_score) {
                    (Some(ns), Some(ps)) => ns.max(ps),
                    (Some(ns), None) => ns,
                    (None, Some(ps)) => ps,
                    (None, None) => 0.0,
                };
                let name_matches = name_hit.map(|(_, m)| m).unwrap_or_default();
                let path_matches = path_hit.map(|(_, m)| m).unwrap_or_default();
                Some(FilteredPackageRow {
                    package_idx,
                    score,
                    name_matches,
                    path_matches,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.package_idx.cmp(&b.package_idx))
        });
        rows
    }

    fn active_filtered_report(&self) -> (JsonReport, usize) {
        if let Some((report, tabs)) = &self.report_snapshot {
            let active_idx = self.active_tab_idx.min(tabs.len().saturating_sub(1));
            let filtered: Vec<&Diagnostic> = if let Some(active_tab) = tabs.get(active_idx) {
                report
                    .diagnostics
                    .iter()
                    .filter(|d| {
                        self.is_file_in_active_packages(&d.file)
                            && diagnostic_matches_tab_and_search(d, active_tab, &self.search_query)
                    })
                    .collect()
            } else {
                report
                    .diagnostics
                    .iter()
                    .filter(|d| self.is_file_in_active_packages(&d.file))
                    .collect()
            };
            let count = filtered.len();
            (filter_report_for_diagnostics(report, &filtered), count)
        } else {
            let empty = dotore_core::report::build_extracted_report(
                &[],
                Vec::new(),
                &std::collections::HashMap::new(),
            );
            (empty, 0)
        }
    }

    /// Copies the active filter's coding-agent handoff prompt to the system clipboard and updates `status_message`.
    pub fn copy_active_handoff_to_clipboard(&mut self) {
        let (filtered_report, count) = self.active_filtered_report();
        let prompt = build_agent_handoff_prompt(&filtered_report, None);
        match copy_to_clipboard(&prompt) {
            Ok(()) => {
                self.status_message = Some(format!(
                    "✔ Copied handoff prompt ({count} findings) to clipboard"
                ));
            }
            Err(err) => {
                self.status_message = Some(format!("✖ Clipboard copy failed: {err}"));
            }
        }
    }

    /// Launches the preferred or first available coding agent CLI with the active filter's handoff bundle,
    /// or sets a status bar prompt if no coding agent CLI is detected on `PATH`.
    pub fn launch_active_coding_agent(&mut self) {
        let available = detect_available_coding_agents();
        let preferred = load_preferred_handoff_target().filter(|t| available.contains(t));
        let selected_agent = preferred.or_else(|| available.first().copied());
        let Some(agent) = selected_agent else {
            self.status_message = Some(
                "No coding agent CLI detected on PATH (claude, codex, cursor, amp, opencode)"
                    .to_string(),
            );
            return;
        };
        let multi_agent_hint = if preferred.is_none() && available.len() > 1 {
            let names: Vec<&str> = available.iter().map(|t| t.as_str()).collect();
            format!(
                " (available: {} — set preferred via --handoff <agent>)",
                names.join(", ")
            )
        } else {
            String::new()
        };
        let (filtered_report, count) = self.active_filtered_report();
        let bundle_dir = resolve_dotore_home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("handoff-bundle");
        match execute_handoff(&filtered_report, agent, &bundle_dir) {
            Ok(_) => {
                self.status_message = Some(format!(
                    "✔ Handed off {count} findings to {}{multi_agent_hint}",
                    agent.as_str()
                ));
            }
            Err(err) => {
                self.status_message = Some(format!("✖ Failed launching {}: {err}", agent.as_str()));
            }
        }
    }

    fn open_package_picker_overlay(&mut self) {
        if self.picker_selected.len() != self.packages.len() {
            self.picker_selected = vec![true; self.packages.len()];
        }
        if self.active_packages.len() != self.packages.len() {
            self.active_packages = vec![true; self.packages.len()];
        }
        self.in_package_picker = true;
        self.picker_cursor = 0;
        self.picker_query.clear();
        self.picker_selected = self.active_packages.clone();
    }

    fn handle_navigation_key(
        &mut self,
        key_bytes: &[u8],
        viewport_height: usize,
        max_scroll: usize,
    ) -> bool {
        match key_bytes {
            [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] | [b'k'] => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
                true
            }
            [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] | [b'j'] | [b'\r'] | [b'\n'] => {
                self.scroll_offset = (self.scroll_offset + 1).min(max_scroll);
                true
            }
            [0x1b, b'[', b'C'] | [0x1b, b'O', b'C'] | [b'l'] | [b'\t'] => {
                self.active_tab_idx = (self.active_tab_idx + 1) % self.tab_count;
                self.scroll_offset = 0;
                true
            }
            [0x1b, b'[', b'D'] | [0x1b, b'O', b'D'] | [0x1b, b'[', b'Z'] | [b'h'] => {
                self.active_tab_idx = if self.active_tab_idx == 0 {
                    self.tab_count - 1
                } else {
                    self.active_tab_idx - 1
                };
                self.scroll_offset = 0;
                true
            }
            [0x1b, b'[', b'6', b'~'] | [b' '] | [b'd'] | [0x04] => {
                self.scroll_offset =
                    (self.scroll_offset + viewport_height.saturating_sub(2)).min(max_scroll);
                true
            }
            [0x1b, b'[', b'5', b'~'] | [b'b'] | [b'u'] | [0x15] => {
                self.scroll_offset = self
                    .scroll_offset
                    .saturating_sub(viewport_height.saturating_sub(2));
                true
            }
            [0x1b, b'[', b'H'] | [b'g'] | [b'0'] => {
                self.scroll_offset = 0;
                true
            }
            [0x1b, b'[', b'F'] | [b'G'] => {
                self.scroll_offset = max_scroll;
                true
            }
            _ => false,
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
        if self.in_package_picker {
            return handle_tui_picker_key(self, key_bytes);
        }
        if self.in_search_input {
            handle_tui_search_key(
                key_bytes,
                &mut self.search_query,
                &mut self.in_search_input,
                &mut self.scroll_offset,
            );
            return false;
        }
        if matches!(key_bytes, [0x1b] | [b'q'] | [b'Q'] | [0x03]) {
            return true;
        }
        if self.handle_navigation_key(key_bytes, viewport_height, max_scroll) {
            return false;
        }

        match key_bytes {
            [b'v' | b'V'] => {
                self.group_mode = self.group_mode.next();
                self.scroll_offset = 0;
            }
            [b'/'] => {
                self.in_search_input = true;
            }
            [b'c' | b'C'] => {
                self.search_query.clear();
                self.scroll_offset = 0;
            }
            [b'p' | b'P'] => {
                self.open_package_picker_overlay();
            }
            [b'y' | b'Y'] => {
                self.copy_active_handoff_to_clipboard();
            }
            [b'a' | b'A'] => {
                self.launch_active_coding_agent();
            }
            [ch @ b'1'..=b'9'] => {
                let idx = usize::from(ch - b'1');
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
    let mut state = TuiState::from_report(report, &tabs);
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
            let effective_tabs: Cow<'_, [TuiFilterTab]> = if state.has_active_package_filter() {
                let pkg_diags: Vec<&Diagnostic> = report
                    .diagnostics
                    .iter()
                    .filter(|d| state.is_file_in_active_packages(&d.file))
                    .collect();
                let pkg_report = filter_report_for_diagnostics(report, &pkg_diags);
                Cow::Owned(build_filter_tabs(&pkg_report))
            } else {
                Cow::Borrowed(&tabs)
            };
            state.tab_count = effective_tabs.len().max(1);
            if state.active_tab_idx >= state.tab_count {
                state.active_tab_idx = state.tab_count - 1;
            }
            let Some(active_tab) = effective_tabs.get(state.active_tab_idx) else {
                break;
            };
            let filtered: Vec<&Diagnostic> = report
                .diagnostics
                .iter()
                .filter(|d| {
                    state.is_file_in_active_packages(&d.file)
                        && diagnostic_matches_tab_and_search(d, active_tab, &state.search_query)
                })
                .collect();
            cached_body_lines = render_tui_body_lines_for_width(&filtered, state.group_mode, cols);
            let max_scroll = cached_body_lines.len().saturating_sub(viewport_height);
            if state.scroll_offset > max_scroll {
                state.scroll_offset = max_scroll;
            }

            let frame = render_tui_frame_with_state(
                report,
                &tabs,
                &state,
                &cached_body_lines,
                rows,
                cols,
                design_mode,
            );
            let mut stdout = io::stdout();
            let _ = stdout.write_all(frame.as_bytes());
            let _ = stdout.flush();
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

/// Processes a key event while the TUI workspace package picker overlay (`p`) is active.
pub fn handle_tui_picker_key(state: &mut TuiState, key_bytes: &[u8]) -> bool {
    match key_bytes {
        [0x03] => return true,
        [0x1b] => {
            state.in_package_picker = false;
            state.picker_query.clear();
            return false;
        }
        [b'\r' | b'\n'] => {
            state.active_packages = state.picker_selected.clone();
            state.in_package_picker = false;
            state.picker_query.clear();
            state.scroll_offset = 0;
            return false;
        }
        [b' '] => {
            let filtered = state.filtered_picker_packages();
            let cursor = state.picker_cursor.min(filtered.len().saturating_sub(1));
            if let Some(row) = filtered.get(cursor)
                && let Some(slot) = state.picker_selected.get_mut(row.package_idx)
            {
                *slot = !*slot;
            }
            return false;
        }
        [0x01] => {
            let all_selected =
                !state.picker_selected.is_empty() && state.picker_selected.iter().all(|&b| b);
            state.picker_selected.fill(!all_selected);
            return false;
        }
        [b'a' | b'A'] if state.picker_query.is_empty() => {
            let all_selected =
                !state.picker_selected.is_empty() && state.picker_selected.iter().all(|&b| b);
            state.picker_selected.fill(!all_selected);
            return false;
        }
        [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] => {
            state.picker_cursor = state.picker_cursor.saturating_sub(1);
            return false;
        }
        [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] => {
            let max_idx = state.filtered_picker_packages().len().saturating_sub(1);
            state.picker_cursor = (state.picker_cursor + 1).min(max_idx);
            return false;
        }
        [0x7f | 0x08] => {
            state.picker_query.pop();
            state.picker_cursor = 0;
            return false;
        }
        _ => {}
    }
    if let Ok(s) = std::str::from_utf8(key_bytes) {
        for ch in s.chars().filter(|c| !c.is_control()) {
            state.picker_query.push(ch);
            state.picker_cursor = 0;
        }
    }
    false
}
