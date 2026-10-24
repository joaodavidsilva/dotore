//! Native Chrome DevTools Protocol (CDP) runtime profiler (`dotore scan`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

mod analysis;
mod capture;
mod probe;
mod report;
mod transport;

pub use analysis::{
    build_runtime_scan_report, is_runtime_scan_probe_snapshot, merge_probe_snapshots,
    parse_runtime_scan_snapshot_payload, sanitize_runtime_text, sanitize_runtime_url,
};
pub use capture::{
    assert_cdp_profile_uncontaminated, record_runtime_trace, resolve_runtime_trace_path,
};
pub use probe::{detect_local_runtime_urls, prompt_runtime_scan_url_with_io};
pub use report::{
    format_runtime_scan_error_report, format_runtime_scan_report, resolve_runtime_scan_format,
};

/// Schema version for `dotore scan` reports and JSONL records.
pub const RUNTIME_SCAN_SCHEMA_VERSION: u32 = 1;
/// Maximum Long Animation Frame entries retained per snapshot or merged report.
pub const RUNTIME_SCAN_MAX_LOAF_ENTRIES: usize = 100;
/// Maximum script timing entries retained per Long Animation Frame.
pub const RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF: usize = 100;
/// Maximum React component render events retained per snapshot or merged report.
pub const RUNTIME_SCAN_MAX_COMPONENT_EVENTS: usize = 2_000;
/// Maximum components recorded per React commit in the browser probe.
pub const RUNTIME_SCAN_MAX_COMPONENTS_PER_COMMIT: usize = 250;
/// Maximum user interactions retained per snapshot or merged report.
pub const RUNTIME_SCAN_MAX_INTERACTIONS: usize = 500;
/// Maximum script and component hotspots included in the summary report.
pub const RUNTIME_SCAN_MAX_HOTSPOTS: usize = 10;
/// Maximum document snapshots buffered across navigations.
pub const RUNTIME_SCAN_MAX_DOCUMENT_SNAPSHOTS: usize = 10;
/// Maximum byte length of a raw snapshot relay envelope payload (5 MiB).
pub const RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES: usize = 5 * 1_024 * 1_024;
/// Byte reserve for the snapshot relay token envelope (64 KiB).
pub const RUNTIME_SCAN_SNAPSHOT_ENVELOPE_RESERVE_BYTES: usize = 64 * 1_024;
/// Maximum serialized byte length of a validated [`RuntimeScanProbeSnapshot`].
pub const RUNTIME_SCAN_MAX_SNAPSHOT_BYTES: usize =
    RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES - RUNTIME_SCAN_SNAPSHOT_ENVELOPE_RESERVE_BYTES;
/// Maximum uncompressed DevTools trace stream size (512 MiB).
pub const RUNTIME_SCAN_MAX_TRACE_BYTES: usize = 512 * 1_024 * 1_024;
/// Maximum string length accepted from browser probe fields.
pub const RUNTIME_SCAN_MAX_STRING_LENGTH: usize = 4_096;
/// Sentinel value when a script's character position is unknown.
pub const RUNTIME_SCAN_UNKNOWN_SOURCE_CHAR_POSITION: i64 = -1;
/// Minimum component self-render duration (ms) recorded by the fallback fiber profiler.
pub const RUNTIME_SCAN_MIN_COMPONENT_DURATION_MS: f64 = 0.05;
/// Event Timing `durationThreshold` (ms) for interaction observation.
pub const RUNTIME_SCAN_INTERACTION_DURATION_THRESHOLD_MS: u32 = 16;
/// Forced style/layout ratio threshold (`>= 0.25`) that triggers a layout-thrash warning.
pub const RUNTIME_SCAN_LAYOUT_THRASH_RATIO: f64 = 0.25;
/// Maximum recording duration before automatic stop (5 minutes).
pub const RUNTIME_SCAN_MAX_RECORDING_DURATION_MS: u64 = 5 * 60 * 1_000;
/// Timeout waiting for `Tracing.tracingComplete` after `Tracing.end` (60 seconds).
pub const RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS: u64 = 60_000;
/// Restrictive Unix file mode (`0o600`) for saved `.json.gz` traces.
pub const RUNTIME_SCAN_TRACE_FILE_MODE: u32 = 0o600;

/// Safe blank page URLs allowed in a `--cdp` browser profile without contaminating traces.
pub const RUNTIME_SCAN_SAFE_CDP_PAGE_URLS: &[&str] =
    &["about:blank", "chrome://newtab/", "chrome://new-tab-page/"];

/// Chrome DevTools trace categories enabled during `dotore scan`.
pub const RUNTIME_SCAN_TRACE_CATEGORIES: &[&str] = &[
    "-*",
    "blink.console",
    "blink.user_timing",
    "devtools.timeline",
    "disabled-by-default-devtools.timeline",
    "disabled-by-default-devtools.timeline.invalidationTracking",
    "disabled-by-default-devtools.timeline.frame",
    "disabled-by-default-devtools.timeline.stack",
    "disabled-by-default-v8.cpu_profiler",
    "disabled-by-default-v8.cpu_profiler.hires",
    "latencyInfo",
    "loading",
    "v8",
    "v8.execute",
];

/// Default local development/production HTTP ports probed when `url` is omitted interactively.
pub const RUNTIME_SCAN_LOCAL_DEV_PORTS: &[u16] = &[
    1234, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 4000, 4001, 4002, 4003,
    4004, 4005, 4006, 4007, 4008, 4009, 4010, 4173, 4200, 4321, 5000, 5001, 5002, 5003, 5004, 5005,
    5006, 5007, 5008, 5009, 5010, 5173, 5174, 5175, 5176, 5177, 5178, 5179, 5180, 5181, 5182, 5183,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8888,
];

/// Output format for `dotore scan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeScanFormat {
    /// Human-readable terminal summary.
    Text,
    /// Pretty-printed JSON report (`kind: "dotore-runtime-scan"`).
    Json,
    /// Newline-delimited JSON records.
    Jsonl,
}

/// Browser connection mode used for a runtime scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeScanConnection {
    /// Isolated Chrome/Chromium child process launched by `dotore`.
    Isolated,
    /// Existing debug-enabled browser attached via `--cdp`.
    Cdp,
}

/// Detected React build type (`development` or `production`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReactBuildType {
    /// Development build of React.
    Development,
    /// Production build of React.
    Production,
}

/// Source of a captured React component timing entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentEventSource {
    /// Native React 19.2+ User Timing `Components` track.
    Native,
    /// Fiber commit hook fallback (`bippy`).
    Bippy,
}

/// Script timing entry inside a [`RuntimeScanLongAnimationFrame`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanScriptTiming {
    /// Script invoker descriptor (e.g. `"BUTTON#save.onclick"`).
    pub invoker: String,
    /// Invoker category (e.g. `"event-listener"`).
    pub invoker_type: String,
    /// Sanitized script source URL.
    pub source_url: String,
    /// Source function name (empty string when anonymous in raw snapshot).
    pub source_function_name: String,
    /// Character offset in the source file (`-1` when unknown).
    pub source_char_position: i64,
    /// Execution start timestamp (ms) relative to `timeOrigin`.
    pub execution_start: f64,
    /// Total script execution duration (ms).
    pub duration_ms: f64,
    /// Time spent in forced style recalculation and layout (ms).
    pub forced_style_and_layout_duration_ms: f64,
    /// Time spent paused (ms).
    pub pause_duration_ms: f64,
}

/// Long Animation Frame (`long-animation-frame`) entry captured by the browser probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanLongAnimationFrame {
    /// Frame start timestamp (ms) relative to `timeOrigin`.
    pub start_time: f64,
    /// Total frame duration (ms).
    pub duration_ms: f64,
    /// Blocking duration (ms).
    pub blocking_duration_ms: f64,
    /// Render start timestamp (ms), or `0.0` if absent.
    pub render_start: f64,
    /// Style and layout start timestamp (ms), or `0.0` if absent.
    pub style_and_layout_start: f64,
    /// Timestamp of the first UI event processed in the frame (ms), or `0.0`.
    pub first_ui_event_timestamp: f64,
    /// Scripts attributed to this Long Animation Frame.
    pub scripts: Vec<RuntimeScanScriptTiming>,
}

/// Single React component render timing event captured by the browser probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanComponentEvent {
    /// Display name of the rendered React component.
    pub name: String,
    /// Render start timestamp (ms) relative to `timeOrigin`.
    pub start_time: f64,
    /// Self-render duration (ms).
    pub duration_ms: f64,
    /// Fiber tree depth (`0` for native User Timing measures).
    pub depth: u64,
    /// Capture mechanism (`native` or `bippy`).
    pub source: ComponentEventSource,
}

/// User interaction timing entry (`PerformanceEventTiming` with `interactionId > 0`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanInteraction {
    /// Event name (e.g. `"click"`, `"pointerdown"`, `"keydown"`).
    pub name: String,
    /// Event start timestamp (ms) relative to `timeOrigin`.
    pub start_time: f64,
    /// Total interaction duration (ms).
    pub duration_ms: f64,
    /// Event handler processing start timestamp (ms).
    pub processing_start: f64,
    /// Event handler processing end timestamp (ms).
    pub processing_end: f64,
    /// Browser-assigned `interactionId`.
    pub interaction_id: u64,
    /// Document navigation index assigned during multi-document snapshot merging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_index: Option<u64>,
    /// Target element tag name (e.g. `"BUTTON"`), if available.
    pub target_tag: Option<String>,
}

/// Browser and React capability flags detected by the runtime probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanProbeSupport {
    /// Whether a React renderer was detected on the page.
    pub react_detected: bool,
    /// Detected React version string, if available.
    pub react_version: Option<String>,
    /// Detected React build type (`development` or `production`).
    pub react_build_type: Option<ReactBuildType>,
    /// Whether native React 19.2+ User Timing component tracks were observed.
    pub native_react_tracks: bool,
    /// Whether fiber commit fallback component tracks were recorded.
    pub bippy_component_tracks: bool,
    /// Whether the browser supports `long-animation-frame` observation.
    pub loaf: bool,
}

/// Snapshot of runtime performance and React render events from one or more documents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanProbeSnapshot {
    /// `performance.timeOrigin` of the document (or earliest document when merged).
    pub time_origin: f64,
    /// Sanitized final document URL.
    pub final_url: String,
    /// Browser and React support metadata.
    pub support: RuntimeScanProbeSupport,
    /// Captured Long Animation Frame entries.
    pub long_animation_frames: Vec<RuntimeScanLongAnimationFrame>,
    /// Captured React component render events.
    pub component_events: Vec<RuntimeScanComponentEvent>,
    /// Captured user interaction entries.
    pub interactions: Vec<RuntimeScanInteraction>,
    /// Cumulative Layout Shift (CLS) score.
    pub cumulative_layout_shift: f64,
    /// Largest Contentful Paint (LCP) timestamp in milliseconds, if observed.
    pub largest_contentful_paint_ms: Option<f64>,
    /// Number of Long Animation Frame entries dropped due to capacity/byte limits.
    pub dropped_long_animation_frames: u64,
    /// Number of script timing entries dropped due to per-frame limits.
    pub dropped_script_timings: u64,
    /// Number of component render events dropped due to capacity/byte limits.
    pub dropped_component_events: u64,
    /// Number of interaction entries dropped due to capacity/byte limits.
    pub dropped_interactions: u64,
}

/// Aggregated Long Animation Frame script hotspot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanScriptHotspot {
    /// Sanitized script source URL.
    pub source_url: String,
    /// Function name (or `"(anonymous)"` when empty).
    pub function_name: String,
    /// Character offset in the source file.
    pub source_char_position: i64,
    /// Invoker descriptor.
    pub invoker: String,
    /// Total duration across all Long Animation Frames (ms).
    pub total_duration_ms: f64,
    /// Maximum single-invocation duration (ms).
    pub max_duration_ms: f64,
    /// Total forced style and layout duration (ms).
    pub forced_style_and_layout_duration_ms: f64,
    /// Number of distinct Long Animation Frames containing this hotspot.
    pub frame_count: usize,
}

/// Aggregated React component render hotspot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanComponentHotspot {
    /// Component display name.
    pub name: String,
    /// Capture source (`native` or `bippy`).
    pub source: ComponentEventSource,
    /// Total number of recorded renders.
    pub render_count: usize,
    /// Sum of self-render durations across all renders (ms).
    pub total_duration_ms: f64,
    /// Maximum single self-render duration (ms).
    pub max_duration_ms: f64,
}

/// High-level performance summary metrics for a runtime scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanSummary {
    /// Total recording wall-clock duration (ms).
    pub duration_ms: f64,
    /// Number of Long Animation Frames captured.
    pub long_animation_frame_count: usize,
    /// Duration of the longest animation frame (ms).
    pub worst_frame_duration_ms: f64,
    /// Sum of `blockingDurationMs` across all Long Animation Frames (ms).
    pub total_blocking_duration_ms: f64,
    /// Number of deduplicated user interactions captured.
    pub interaction_count: usize,
    /// Duration of the slowest user interaction (INP candidate, ms).
    pub worst_interaction_duration_ms: f64,
    /// Cumulative Layout Shift (CLS).
    pub cumulative_layout_shift: f64,
    /// Largest Contentful Paint (LCP, ms), if observed.
    pub largest_contentful_paint_ms: Option<f64>,
}

/// Complete structured report produced by `dotore scan`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanReport {
    /// Schema version (`1`).
    pub schema_version: u32,
    /// Report kind (`"dotore-runtime-scan"`).
    pub kind: String,
    /// Sanitized requested URL.
    pub requested_url: String,
    /// Sanitized final URL after navigations.
    pub final_url: String,
    /// Filesystem path to the compressed `.json.gz` DevTools trace.
    pub trace_path: String,
    /// ISO-8601 UTC timestamp when recording started.
    pub captured_at: String,
    /// Earliest `performance.timeOrigin` across captured documents.
    pub time_origin: f64,
    /// Browser connection mode (`isolated` or `cdp`).
    pub connection: RuntimeScanConnection,
    /// Browser and React capability support flags.
    pub support: RuntimeScanProbeSupport,
    /// Aggregated performance summary metrics.
    pub summary: RuntimeScanSummary,
    /// Top script execution hotspots ranked by `totalDurationMs` descending.
    pub script_hotspots: Vec<RuntimeScanScriptHotspot>,
    /// Top React component render hotspots ranked by `totalDurationMs` descending.
    pub component_hotspots: Vec<RuntimeScanComponentHotspot>,
    /// Long Animation Frames sorted by `durationMs` descending.
    pub long_animation_frames: Vec<RuntimeScanLongAnimationFrame>,
    /// Deduplicated user interactions sorted by `startTime` ascending.
    pub interactions: Vec<RuntimeScanInteraction>,
    /// Actionable limitation or layout-thrash warnings.
    pub warnings: Vec<String>,
}

/// Input parameters for [`build_runtime_scan_report`].
#[derive(Debug, Clone)]
pub struct BuildRuntimeScanReportInput {
    /// Raw or sanitized URL requested by the user.
    pub requested_url: String,
    /// Path where the `.json.gz` trace was written.
    pub trace_path: String,
    /// ISO-8601 timestamp when recording started.
    pub captured_at: String,
    /// Wall-clock duration of the recording (ms).
    pub duration_ms: f64,
    /// Merged probe snapshot.
    pub snapshot: RuntimeScanProbeSnapshot,
    /// Browser connection type (`isolated` or `cdp`).
    pub connection: RuntimeScanConnection,
}

/// Discovered local HTTP server suggestion for interactive URL selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUrlSuggestion {
    /// Local TCP port number.
    pub port: u16,
    /// Suggested URL (`http://localhost:<port>`).
    pub url: String,
}

/// Input parameters for [`record_runtime_trace`].
#[derive(Debug, Clone)]
pub struct RecordRuntimeTraceInput {
    /// Target `http(s)` URL to open and profile.
    pub url: String,
    /// Optional explicit output path for the `.json.gz` trace.
    pub trace_out: Option<PathBuf>,
    /// Optional existing Chrome DevTools Protocol WebSocket or HTTP endpoint URL (`--cdp`).
    pub cdp_url: Option<String>,
    /// Optional maximum recording duration override in milliseconds (defaults to 5 minutes).
    pub max_recording_duration_ms: Option<u64>,
}

/// Result returned by [`record_runtime_trace`].
#[derive(Debug, Clone)]
pub struct RecordRuntimeTraceResult {
    /// Resolved path to the written `.json.gz` trace file.
    pub trace_path: String,
    /// ISO-8601 timestamp when recording began.
    pub captured_at: String,
    /// Recording duration in milliseconds.
    pub duration_ms: f64,
    /// Merged runtime probe snapshot across documents.
    pub snapshot: RuntimeScanProbeSnapshot,
    /// Browser connection mode (`isolated` or `cdp`).
    pub connection: RuntimeScanConnection,
}

/// Record emitted as a line in `--format jsonl` output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeScanJsonlRecord {
    /// Schema version (`1`).
    pub schema_version: u32,
    /// Record kind (`metadata`, `summary`, `script-hotspot`, `component-hotspot`, `long-animation-frame`, `interaction`).
    pub kind: String,
    /// Record payload.
    pub data: serde_json::Value,
}
