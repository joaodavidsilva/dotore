//! Lock-free ~30fps (`30ms` interval) background `/dev/tty` spinner and progress bar RAII guard.

use std::{
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

use super::{ColorMode, GaugeBar, strip_ansi_codes, truncate_ansi_to_width, visible_char_width};

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
    let raw = if path.is_absolute()
        && let Ok(cwd) = std::env::current_dir()
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
    let frame_ch = SPINNER_FRAMES
        .get(tick % SPINNER_FRAMES.len())
        .copied()
        .unwrap_or("⠋");
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
