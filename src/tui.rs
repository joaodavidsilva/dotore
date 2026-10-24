//! Interactive TUI explorer (`hjkl`/arrow navigation, dynamic error-style filter tabs,
//! grouping modes, `/` search, and `ESC` clean exit) built on `dotore_core::ui`.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write as _,
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
    rules::{BlastRadiusTier, Diagnostic, PrescriptionTier, RootCauseGroup, RuleSeverity},
    score::compute_local_health_score,
    search::score_fuzzy,
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

        match key_bytes {
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
            // 'p' -> open workspace package picker overlay
            [b'p'] | [b'P'] => {
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
            // 'y' -> copy active filter's handoff prompt to clipboard
            [b'y'] | [b'Y'] => {
                self.copy_active_handoff_to_clipboard();
            }
            // 'a' -> launch preferred or detected coding agent CLI
            [b'a'] | [b'A'] => {
                self.launch_active_coding_agent();
            }
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

fn compute_header_metrics(report: &JsonReport, state: &TuiState) -> FilteredHeaderMetrics {
    let s = &report.summary;
    if !state.has_active_package_filter() {
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
    let p0 = active_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P0)
        .count();
    let p1 = active_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P1)
        .count();
    let p2 = active_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P2)
        .count();

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
    let group_mode = state.group_mode;
    let search_query = state.search_query.as_str();
    let in_search_input = state.in_search_input;
    let scroll_offset = state.scroll_offset;
    let metrics = compute_header_metrics(report, state);
    let effective_cols = cols.max(52);
    let box_inner_width = effective_cols.saturating_sub(4).max(46);
    let line_cap = effective_cols.saturating_sub(1);

    let mut frame = String::with_capacity(16384);
    frame.push_str("\x1b[H");

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
        group_mode.label()
    ));
    header_box.add_titled_divider("FILTER TABS (h/l or ←/→ or Tab to switch)");

    let tab_strip = FilterTabBar::new(&effective_tabs, active_tab_idx)
        .with_max_width(box_inner_width.saturating_sub(2))
        .render(ColorMode::Ansi);
    header_box.add_closed_row(format!(" {tab_strip}"));

    let search_row = if in_search_input {
        format!(
            " \x1b[48;5;236;38;5;226;1m SEARCH / \x1b[0m \x1b[38;5;255;1m{search_query}█\x1b[0m  \x1b[38;5;244m(Enter to lock, ESC to clear)\x1b[0m"
        )
    } else if let Some(status_msg) = state.status_message.as_deref() {
        let active = &effective_tabs[active_tab_idx];
        format!(
            " \x1b[38;5;48;1m{status_msg}\x1b[0m   \x1b[38;5;245mActive Filter:\x1b[0m {}{} ({} matching)\x1b[0m",
            active.badge_ansi, active.label, active.count
        )
    } else if !search_query.is_empty() {
        format!(
            " \x1b[48;5;236;38;5;48;1m FILTER / \x1b[0m \x1b[38;5;255;1m\"{search_query}\"\x1b[0m  \x1b[38;5;244m(press / to edit, c to clear search)\x1b[0m"
        )
    } else {
        let active = &effective_tabs[active_tab_idx];
        format!(
            " \x1b[38;5;245mActive Filter:\x1b[0m {}{} ({} matching)\x1b[0m   \x1b[38;5;244mPress `/` to search by file, rule, or Subject\x1b[0m",
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
    let active_tab = &effective_tabs[active_tab_idx];
    let footer = StatusBar::tui_footer(
        &active_tab.label,
        active_tab.count,
        group_mode.label(),
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
            let effective_tabs: Vec<TuiFilterTab> = if state.has_active_package_filter() {
                let pkg_diags: Vec<&Diagnostic> = report
                    .diagnostics
                    .iter()
                    .filter(|d| state.is_file_in_active_packages(&d.file))
                    .collect();
                let pkg_report = filter_report_for_diagnostics(report, &pkg_diags);
                build_filter_tabs(&pkg_report)
            } else {
                tabs.clone()
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
        // Ctrl+C exits TUI cleanly
        [0x03] => return true,
        // ESC closes package picker without applying changes (does not exit TUI)
        [0x1b] => {
            state.in_package_picker = false;
            state.picker_query.clear();
            return false;
        }
        // Enter applies selected packages to active_packages and closes picker
        [b'\r' | b'\n'] => {
            state.active_packages = state.picker_selected.clone();
            state.in_package_picker = false;
            state.picker_query.clear();
            state.scroll_offset = 0;
            return false;
        }
        // Space toggles selection of the highlighted package row
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
        // Ctrl-A always toggles all packages; bare 'a'/'A' toggles all when picker_query is empty
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
        // Up arrow moves picker cursor up
        [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] => {
            state.picker_cursor = state.picker_cursor.saturating_sub(1);
            return false;
        }
        // Down arrow moves picker cursor down
        [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] => {
            let max_idx = state.filtered_picker_packages().len().saturating_sub(1);
            state.picker_cursor = (state.picker_cursor + 1).min(max_idx);
            return false;
        }
        // Backspace deletes last char from picker_query
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
