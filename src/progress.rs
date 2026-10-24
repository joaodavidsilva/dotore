//! Live terminal progress bar and 30fps spinner animation for workspace scans.

pub use dotore_core::ui::{
    LiveScanProgressSnapshot, LiveSpinner, SPINNER_FRAMES, current_scan_progress,
    format_spinner_frame, set_progress_phase, tick_progress_file,
};

