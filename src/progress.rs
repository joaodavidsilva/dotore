//! Live terminal progress bar and 30fps spinner animation for workspace scans.

pub use dotore_core::ui::{
    LiveScanProgressSnapshot, LiveSpinner, SPINNER_FRAMES, current_scan_progress,
    format_spinner_frame, set_progress_phase, tick_progress_file,
};

/// Lock-free ~30fps (`30ms` interval) background `/dev/tty` progress bar and spinner RAII guard,
/// delegating to [`LiveSpinner`].
#[derive(Debug)]
pub struct LiveProgressBar {
    inner: LiveSpinner,
}

impl LiveProgressBar {
    /// Starts the background `/dev/tty` progress bar thread if `/dev/tty` is writable.
    #[must_use]
    pub fn start() -> Option<Self> {
        LiveSpinner::start().map(|inner| Self { inner })
    }

    /// Borrows the underlying [`LiveSpinner`] guard.
    #[must_use]
    pub const fn as_spinner(&self) -> &LiveSpinner {
        &self.inner
    }
}
