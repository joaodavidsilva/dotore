//! Native Chrome DevTools Protocol (CDP) runtime profiler (`dotore scan`).

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::json;

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

static NEXT_TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn generate_unique_hex_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let seq = NEXT_TRACE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = u128::from(std::process::id());
    let mixed = nanos ^ (pid << 64) ^ (u128::from(seq) * 0x9e37_79b9_7f4a_7c15_u128);
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (mixed >> 96) as u32,
        ((mixed >> 80) & 0xffff) as u16,
        ((mixed >> 64) & 0x0fff) as u16,
        ((mixed >> 48) & 0x0fff) as u16,
        (mixed & 0xffff_ffff_ffff) as u64
    )
}

/// Parses and validates the `--format` flag (`text`, `json`, or `jsonl`).
///
/// # Errors
/// Returns an actionable error message if `format` is not one of `text`, `json`, or `jsonl`.
pub fn resolve_runtime_scan_format(format: Option<&str>) -> Result<RuntimeScanFormat, String> {
    match format {
        None | Some("text") => Ok(RuntimeScanFormat::Text),
        Some("json") => Ok(RuntimeScanFormat::Json),
        Some("jsonl") => Ok(RuntimeScanFormat::Jsonl),
        Some(other) => Err(format!(
            "--format must be one of: text, json, jsonl. Received \"{other}\"."
        )),
    }
}

/// Validates an absolute `http(s)` URL and strips credentials, query parameters, and fragments.
///
/// # Errors
/// Returns an error if `raw_url` is not a valid absolute `http://` or `https://` URL.
pub fn sanitize_runtime_url(raw_url: &str) -> Result<String, String> {
    let trimmed = raw_url.trim();
    let Some((scheme_raw, after_scheme)) = trimmed.split_once("://") else {
        return Err(format!(
            "Expected an absolute http(s) URL, received \"{raw_url}\"."
        ));
    };
    if scheme_raw.is_empty()
        || !scheme_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return Err(format!(
            "Expected an absolute http(s) URL, received \"{raw_url}\"."
        ));
    }
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("Expected an http(s) URL, received \"{scheme}:\"."));
    }
    let without_fragment = after_scheme
        .split_once('#')
        .map_or(after_scheme, |(before, _)| before);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(before, _)| before);
    let (authority, path) = match without_query.find('/') {
        Some(slash_idx) => (&without_query[..slash_idx], &without_query[slash_idx..]),
        None => (without_query, ""),
    };
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_port.is_empty()
        || host_port
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "Expected an absolute http(s) URL, received \"{raw_url}\"."
        ));
    }
    let normalized_path = if path.is_empty() { "" } else { path };
    let result = format!("{scheme}://{host_port}{normalized_path}");
    Ok(limit_string(&result))
}

fn is_sanitized_runtime_url_str(value: &str) -> bool {
    if value.len() > RUNTIME_SCAN_MAX_STRING_LENGTH {
        return false;
    }
    if value.contains('?') || value.contains('#') {
        return false;
    }
    let Some((scheme, after_scheme)) = value.split_once("://") else {
        return false;
    };
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let authority = after_scheme
        .split_once('/')
        .map_or(after_scheme, |(auth, _)| auth);
    !authority.is_empty()
        && !authority.contains('@')
        && !authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

fn limit_string(value: &str) -> String {
    if value.len() <= RUNTIME_SCAN_MAX_STRING_LENGTH {
        return value.to_string();
    }
    let mut end = RUNTIME_SCAN_MAX_STRING_LENGTH;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Strips ASCII and C1 terminal control characters (`\u{0000}..=\u{001f}` and `\u{007f}..=\u{009f}`).
#[must_use]
pub fn sanitize_runtime_text(value: &str) -> String {
    value
        .chars()
        .filter(|&ch| {
            let code = ch as u32;
            !(code <= 0x1f || (0x7f..=0x9f).contains(&code))
        })
        .collect()
}

/// Resolves the output `.json.gz` trace path, generating an unpredictable temp file path when `trace_out` is `None`.
#[must_use]
pub fn resolve_runtime_trace_path(trace_out: Option<&str>, captured_at_iso: &str) -> PathBuf {
    if let Some(explicit) = trace_out {
        let candidate = PathBuf::from(explicit);
        if candidate.is_absolute() {
            return candidate;
        }
        if let Ok(cwd) = std::env::current_dir() {
            return cwd.join(candidate);
        }
        return candidate;
    }
    let timestamp: String = captured_at_iso
        .chars()
        .map(|c| if c == ':' || c == '.' { '-' } else { c })
        .collect();
    let uuid = generate_unique_hex_id();
    std::env::temp_dir().join(format!("dotore-runtime-{timestamp}-{uuid}.json.gz"))
}

/// Verifies that every open page target in a `--cdp` browser profile is a safe blank tab.
///
/// # Errors
/// Returns an error if any page target URL is outside [`RUNTIME_SCAN_SAFE_CDP_PAGE_URLS`].
pub fn assert_cdp_profile_uncontaminated(page_urls: &[&str]) -> Result<(), String> {
    if page_urls
        .iter()
        .all(|url| RUNTIME_SCAN_SAFE_CDP_PAGE_URLS.contains(url))
    {
        return Ok(());
    }
    Err(
        "Chrome performance tracing includes every open tab. Close all tabs in the dedicated debug profile and retry; a blank new tab can stay open."
            .to_string(),
    )
}

fn is_non_negative_finite_number(val: &serde_json::Value) -> bool {
    val.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0)
}

fn is_non_negative_safe_integer(val: &serde_json::Value) -> bool {
    val.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991_u64)
}

fn is_bounded_string(val: &serde_json::Value) -> bool {
    val.as_str()
        .is_some_and(|s| s.len() <= RUNTIME_SCAN_MAX_STRING_LENGTH)
}

fn is_nullable_bounded_string(val: &serde_json::Value) -> bool {
    val.is_null() || is_bounded_string(val)
}

fn is_valid_script_timing(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    let valid_char_pos = obj.get("sourceCharPosition").is_some_and(|v| {
        v.as_i64() == Some(RUNTIME_SCAN_UNKNOWN_SOURCE_CHAR_POSITION)
            || is_non_negative_safe_integer(v)
    });
    obj.get("invoker").is_some_and(is_bounded_string)
        && obj.get("invokerType").is_some_and(is_bounded_string)
        && obj.get("sourceUrl").is_some_and(is_bounded_string)
        && obj.get("sourceFunctionName").is_some_and(is_bounded_string)
        && valid_char_pos
        && obj
            .get("executionStart")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("durationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("forcedStyleAndLayoutDurationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("pauseDurationMs")
            .is_some_and(is_non_negative_finite_number)
}

fn is_valid_loaf(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    let Some(scripts) = obj.get("scripts").and_then(serde_json::Value::as_array) else {
        return false;
    };
    obj.get("startTime")
        .is_some_and(is_non_negative_finite_number)
        && obj
            .get("durationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("blockingDurationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("renderStart")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("styleAndLayoutStart")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("firstUiEventTimestamp")
            .is_some_and(is_non_negative_finite_number)
        && scripts.len() <= RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF
        && scripts.iter().all(is_valid_script_timing)
}

fn is_valid_component_event(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    let valid_source = obj
        .get("source")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s == "native" || s == "bippy");
    obj.get("name").is_some_and(is_bounded_string)
        && obj
            .get("startTime")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("durationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj.get("depth").is_some_and(is_non_negative_safe_integer)
        && valid_source
}

fn is_valid_interaction(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    let valid_doc_index = obj
        .get("documentIndex")
        .is_none_or(|v| v.is_null() || is_non_negative_safe_integer(v));
    obj.get("name").is_some_and(is_bounded_string)
        && obj
            .get("startTime")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("durationMs")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("processingStart")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("processingEnd")
            .is_some_and(is_non_negative_finite_number)
        && obj
            .get("interactionId")
            .is_some_and(is_non_negative_safe_integer)
        && valid_doc_index
        && obj.get("targetTag").is_some_and(is_nullable_bounded_string)
}

/// Validates whether an arbitrary JSON value conforms to [`RuntimeScanProbeSnapshot`] schema and byte bounds.
#[must_use]
pub fn is_runtime_scan_probe_snapshot(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let Some(support) = obj.get("support").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let valid_build_type = support.get("reactBuildType").is_some_and(|v| {
        v.is_null()
            || v.as_str()
                .is_some_and(|s| s == "development" || s == "production")
    });
    let valid_support = support
        .get("reactDetected")
        .is_some_and(serde_json::Value::is_boolean)
        && support
            .get("reactVersion")
            .is_some_and(is_nullable_bounded_string)
        && valid_build_type
        && support
            .get("nativeReactTracks")
            .is_some_and(serde_json::Value::is_boolean)
        && support
            .get("bippyComponentTracks")
            .is_some_and(serde_json::Value::is_boolean)
        && support
            .get("loaf")
            .is_some_and(serde_json::Value::is_boolean);
    if !valid_support {
        return false;
    }

    let Some(loafs) = obj
        .get("longAnimationFrames")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let Some(comp_events) = obj
        .get("componentEvents")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let Some(interactions) = obj
        .get("interactions")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };

    let valid_lcp = obj
        .get("largestContentfulPaintMs")
        .is_some_and(|v| v.is_null() || is_non_negative_finite_number(v));

    let fields_ok = obj
        .get("timeOrigin")
        .is_some_and(is_non_negative_finite_number)
        && obj
            .get("finalUrl")
            .and_then(serde_json::Value::as_str)
            .is_some_and(is_sanitized_runtime_url_str)
        && loafs.len() <= RUNTIME_SCAN_MAX_LOAF_ENTRIES
        && loafs.iter().all(is_valid_loaf)
        && comp_events.len() <= RUNTIME_SCAN_MAX_COMPONENT_EVENTS
        && comp_events.iter().all(is_valid_component_event)
        && interactions.len() <= RUNTIME_SCAN_MAX_INTERACTIONS
        && interactions.iter().all(is_valid_interaction)
        && obj
            .get("cumulativeLayoutShift")
            .is_some_and(is_non_negative_finite_number)
        && valid_lcp
        && obj
            .get("droppedLongAnimationFrames")
            .is_some_and(is_non_negative_safe_integer)
        && obj
            .get("droppedScriptTimings")
            .is_some_and(is_non_negative_safe_integer)
        && obj
            .get("droppedComponentEvents")
            .is_some_and(is_non_negative_safe_integer)
        && obj
            .get("droppedInteractions")
            .is_some_and(is_non_negative_safe_integer);
    if !fields_ok {
        return false;
    }
    serde_json::to_string(value).is_ok_and(|s| s.len() <= RUNTIME_SCAN_MAX_SNAPSHOT_BYTES)
}

/// Parses and validates a relay envelope (`{ token, snapshot }`) from the browser probe.
#[must_use]
pub fn parse_runtime_scan_snapshot_payload(
    payload: &str,
    expected_token: &str,
) -> Option<RuntimeScanProbeSnapshot> {
    if payload.len() > RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES {
        return None;
    }
    let envelope: serde_json::Value = serde_json::from_str(payload).ok()?;
    let obj = envelope.as_object()?;
    if obj.get("token")?.as_str()? != expected_token {
        return None;
    }
    let snapshot_val = obj.get("snapshot")?;
    if !is_runtime_scan_probe_snapshot(snapshot_val) {
        return None;
    }
    serde_json::from_value(snapshot_val.clone()).ok()
}

fn shift_optional_timestamp(timestamp: f64, offset: f64) -> f64 {
    if timestamp == 0.0 {
        0.0
    } else {
        timestamp + offset
    }
}

/// Merges probe snapshots captured across multiple document navigations.
///
/// # Errors
/// Returns an error if `captured_snapshots` is empty.
pub fn merge_probe_snapshots(
    captured_snapshots: &[RuntimeScanProbeSnapshot],
) -> Result<RuntimeScanProbeSnapshot, String> {
    if captured_snapshots.is_empty() {
        return Err("At least one runtime scan probe snapshot is required.".to_string());
    }
    // Deduplicate by timeOrigin in insertion order (replacing earlier entry at the end).
    let mut snapshots: Vec<RuntimeScanProbeSnapshot> = Vec::with_capacity(captured_snapshots.len());
    for snap in captured_snapshots {
        snapshots.retain(|existing| (existing.time_origin - snap.time_origin).abs() > f64::EPSILON);
        snapshots.push(snap.clone());
    }
    let Some(final_snapshot) = snapshots.last().cloned() else {
        return Err("At least one runtime scan probe snapshot is required.".to_string());
    };
    let time_origin = snapshots
        .iter()
        .map(|s| s.time_origin)
        .fold(f64::INFINITY, f64::min);

    let mut creation_order: Vec<&RuntimeScanProbeSnapshot> = snapshots.iter().collect();
    creation_order.sort_by(|a, b| a.time_origin.total_cmp(&b.time_origin));

    let mut all_loafs: Vec<RuntimeScanLongAnimationFrame> = Vec::new();
    let mut all_components: Vec<RuntimeScanComponentEvent> = Vec::new();
    let mut all_interactions: Vec<RuntimeScanInteraction> = Vec::new();

    for snap in &snapshots {
        let offset = snap.time_origin - time_origin;
        let doc_index = creation_order
            .iter()
            .position(|s| (s.time_origin - snap.time_origin).abs() <= f64::EPSILON)
            .unwrap_or(0) as u64;

        for frame in &snap.long_animation_frames {
            all_loafs.push(RuntimeScanLongAnimationFrame {
                start_time: frame.start_time + offset,
                duration_ms: frame.duration_ms,
                blocking_duration_ms: frame.blocking_duration_ms,
                render_start: shift_optional_timestamp(frame.render_start, offset),
                style_and_layout_start: shift_optional_timestamp(
                    frame.style_and_layout_start,
                    offset,
                ),
                first_ui_event_timestamp: shift_optional_timestamp(
                    frame.first_ui_event_timestamp,
                    offset,
                ),
                scripts: frame
                    .scripts
                    .iter()
                    .map(|script| RuntimeScanScriptTiming {
                        invoker: script.invoker.clone(),
                        invoker_type: script.invoker_type.clone(),
                        source_url: script.source_url.clone(),
                        source_function_name: script.source_function_name.clone(),
                        source_char_position: script.source_char_position,
                        execution_start: shift_optional_timestamp(script.execution_start, offset),
                        duration_ms: script.duration_ms,
                        forced_style_and_layout_duration_ms: script
                            .forced_style_and_layout_duration_ms,
                        pause_duration_ms: script.pause_duration_ms,
                    })
                    .collect(),
            });
        }

        for comp in &snap.component_events {
            all_components.push(RuntimeScanComponentEvent {
                name: comp.name.clone(),
                start_time: comp.start_time + offset,
                duration_ms: comp.duration_ms,
                depth: comp.depth,
                source: comp.source,
            });
        }

        for interaction in &snap.interactions {
            all_interactions.push(RuntimeScanInteraction {
                name: interaction.name.clone(),
                start_time: interaction.start_time + offset,
                duration_ms: interaction.duration_ms,
                processing_start: interaction.processing_start + offset,
                processing_end: interaction.processing_end + offset,
                interaction_id: interaction.interaction_id,
                document_index: Some(doc_index),
                target_tag: interaction.target_tag.clone(),
            });
        }
    }

    all_loafs.sort_by(|a, b| a.start_time.total_cmp(&b.start_time));
    let overflow_loafs = all_loafs
        .len()
        .saturating_sub(RUNTIME_SCAN_MAX_LOAF_ENTRIES) as u64;
    if all_loafs.len() > RUNTIME_SCAN_MAX_LOAF_ENTRIES {
        let drain_count = all_loafs.len() - RUNTIME_SCAN_MAX_LOAF_ENTRIES;
        all_loafs.drain(0..drain_count);
    }

    all_components.sort_by(|a, b| a.start_time.total_cmp(&b.start_time));
    let overflow_components = all_components
        .len()
        .saturating_sub(RUNTIME_SCAN_MAX_COMPONENT_EVENTS) as u64;
    if all_components.len() > RUNTIME_SCAN_MAX_COMPONENT_EVENTS {
        let drain_count = all_components.len() - RUNTIME_SCAN_MAX_COMPONENT_EVENTS;
        all_components.drain(0..drain_count);
    }

    all_interactions.sort_by(|a, b| a.start_time.total_cmp(&b.start_time));
    let overflow_interactions = all_interactions
        .len()
        .saturating_sub(RUNTIME_SCAN_MAX_INTERACTIONS) as u64;
    if all_interactions.len() > RUNTIME_SCAN_MAX_INTERACTIONS {
        let drain_count = all_interactions.len() - RUNTIME_SCAN_MAX_INTERACTIONS;
        all_interactions.drain(0..drain_count);
    }

    let latest_react = snapshots.iter().rev().find(|s| s.support.react_detected);

    let max_cls = snapshots
        .iter()
        .map(|s| s.cumulative_layout_shift)
        .fold(0.0_f64, f64::max);

    Ok(RuntimeScanProbeSnapshot {
        time_origin,
        final_url: final_snapshot.final_url,
        support: RuntimeScanProbeSupport {
            react_detected: snapshots.iter().any(|s| s.support.react_detected),
            react_version: latest_react.and_then(|s| s.support.react_version.clone()),
            react_build_type: latest_react.and_then(|s| s.support.react_build_type),
            native_react_tracks: snapshots.iter().any(|s| s.support.native_react_tracks),
            bippy_component_tracks: snapshots.iter().any(|s| s.support.bippy_component_tracks),
            loaf: snapshots.iter().any(|s| s.support.loaf),
        },
        long_animation_frames: all_loafs,
        component_events: all_components,
        interactions: all_interactions,
        cumulative_layout_shift: max_cls,
        largest_contentful_paint_ms: final_snapshot.largest_contentful_paint_ms,
        dropped_long_animation_frames: snapshots
            .iter()
            .map(|s| s.dropped_long_animation_frames)
            .sum::<u64>()
            + overflow_loafs,
        dropped_script_timings: snapshots
            .iter()
            .map(|s| s.dropped_script_timings)
            .sum::<u64>(),
        dropped_component_events: snapshots
            .iter()
            .map(|s| s.dropped_component_events)
            .sum::<u64>()
            + overflow_components,
        dropped_interactions: snapshots
            .iter()
            .map(|s| s.dropped_interactions)
            .sum::<u64>()
            + overflow_interactions,
    })
}

fn build_deduplicated_interactions(
    snapshot: &RuntimeScanProbeSnapshot,
) -> Vec<RuntimeScanInteraction> {
    let mut order: Vec<(u64, u64)> = Vec::new();
    let mut by_key: HashMap<(u64, u64), RuntimeScanInteraction> = HashMap::new();

    for interaction in &snapshot.interactions {
        let key = (
            interaction.document_index.unwrap_or(0),
            interaction.interaction_id,
        );
        if let Some(existing) = by_key.get_mut(&key) {
            existing.name.clone_from(&interaction.name);
            existing.start_time = existing.start_time.min(interaction.start_time);
            existing.duration_ms = existing.duration_ms.max(interaction.duration_ms);
            existing.processing_start = existing.processing_start.min(interaction.processing_start);
            existing.processing_end = existing.processing_end.max(interaction.processing_end);
            if existing.target_tag.is_none() {
                existing.target_tag.clone_from(&interaction.target_tag);
            }
        } else {
            order.push(key);
            by_key.insert(key, interaction.clone());
        }
    }

    let mut interactions: Vec<RuntimeScanInteraction> = order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect();
    interactions.sort_by(|a, b| a.start_time.total_cmp(&b.start_time));
    interactions
}

fn build_script_hotspots(snapshot: &RuntimeScanProbeSnapshot) -> Vec<RuntimeScanScriptHotspot> {
    #[derive(Hash, PartialEq, Eq, Clone)]
    struct ScriptKey {
        source_url: String,
        source_function_name: String,
        source_char_position: i64,
        invoker: String,
    }

    let mut order: Vec<ScriptKey> = Vec::new();
    let mut hotspots: HashMap<ScriptKey, RuntimeScanScriptHotspot> = HashMap::new();

    for frame in &snapshot.long_animation_frames {
        let mut keys_in_frame: HashSet<ScriptKey> = HashSet::new();
        for script in &frame.scripts {
            let key = ScriptKey {
                source_url: script.source_url.clone(),
                source_function_name: script.source_function_name.clone(),
                source_char_position: script.source_char_position,
                invoker: script.invoker.clone(),
            };
            if let Some(existing) = hotspots.get_mut(&key) {
                existing.total_duration_ms += script.duration_ms;
                existing.max_duration_ms = existing.max_duration_ms.max(script.duration_ms);
                existing.forced_style_and_layout_duration_ms +=
                    script.forced_style_and_layout_duration_ms;
                if !keys_in_frame.contains(&key) {
                    existing.frame_count += 1;
                }
            } else {
                order.push(key.clone());
                hotspots.insert(
                    key.clone(),
                    RuntimeScanScriptHotspot {
                        source_url: script.source_url.clone(),
                        function_name: if script.source_function_name.is_empty() {
                            "(anonymous)".to_string()
                        } else {
                            script.source_function_name.clone()
                        },
                        source_char_position: script.source_char_position,
                        invoker: script.invoker.clone(),
                        total_duration_ms: script.duration_ms,
                        max_duration_ms: script.duration_ms,
                        forced_style_and_layout_duration_ms: script
                            .forced_style_and_layout_duration_ms,
                        frame_count: 1,
                    },
                );
            }
            keys_in_frame.insert(key);
        }
    }

    let mut result: Vec<RuntimeScanScriptHotspot> = order
        .into_iter()
        .filter_map(|k| hotspots.remove(&k))
        .collect();
    result.sort_by(|a, b| b.total_duration_ms.total_cmp(&a.total_duration_ms));
    result.truncate(RUNTIME_SCAN_MAX_HOTSPOTS);
    result
}

fn build_component_hotspots(
    snapshot: &RuntimeScanProbeSnapshot,
) -> Vec<RuntimeScanComponentHotspot> {
    let mut order: Vec<(ComponentEventSource, String)> = Vec::new();
    let mut hotspots: HashMap<(ComponentEventSource, String), RuntimeScanComponentHotspot> =
        HashMap::new();

    for event in &snapshot.component_events {
        let key = (event.source, event.name.clone());
        if let Some(existing) = hotspots.get_mut(&key) {
            existing.render_count += 1;
            existing.total_duration_ms += event.duration_ms;
            existing.max_duration_ms = existing.max_duration_ms.max(event.duration_ms);
        } else {
            order.push(key.clone());
            hotspots.insert(
                key,
                RuntimeScanComponentHotspot {
                    name: event.name.clone(),
                    source: event.source,
                    render_count: 1,
                    total_duration_ms: event.duration_ms,
                    max_duration_ms: event.duration_ms,
                },
            );
        }
    }

    let mut result: Vec<RuntimeScanComponentHotspot> = order
        .into_iter()
        .filter_map(|k| hotspots.remove(&k))
        .collect();
    result.sort_by(|a, b| b.total_duration_ms.total_cmp(&a.total_duration_ms));
    result.truncate(RUNTIME_SCAN_MAX_HOTSPOTS);
    result
}

fn build_warnings(snapshot: &RuntimeScanProbeSnapshot) -> Vec<String> {
    let mut warnings = Vec::new();
    if !snapshot.support.react_detected {
        warnings.push("No React renderer was detected during the recording.".to_string());
    } else if !snapshot.support.native_react_tracks && !snapshot.support.bippy_component_tracks {
        warnings.push(
            "React component timings were unavailable. Production builds require react-dom/profiling."
                .to_string(),
        );
    }
    if !snapshot.support.loaf {
        warnings.push("Long Animation Frame entries are unavailable in this browser.".to_string());
    }
    if snapshot.dropped_long_animation_frames > 0
        || snapshot.dropped_script_timings > 0
        || snapshot.dropped_component_events > 0
        || snapshot.dropped_interactions > 0
    {
        warnings.push(format!(
            "The bounded probe dropped {} frames, {} script timings, {} component events, and {} interactions.",
            snapshot.dropped_long_animation_frames,
            snapshot.dropped_script_timings,
            snapshot.dropped_component_events,
            snapshot.dropped_interactions
        ));
    }
    let has_layout_thrash = snapshot
        .long_animation_frames
        .iter()
        .flat_map(|f| &f.scripts)
        .any(|s| {
            s.duration_ms > 0.0
                && s.forced_style_and_layout_duration_ms / s.duration_ms
                    >= RUNTIME_SCAN_LAYOUT_THRASH_RATIO
        });
    if has_layout_thrash {
        warnings.push(
            "At least one long frame was substantially dominated by forced style and layout."
                .to_string(),
        );
    }
    warnings
}

/// Builds a [`RuntimeScanReport`] from a merged probe snapshot and trace metadata.
///
/// # Errors
/// Returns an error if `input.requested_url` is not a valid `http(s)` URL.
pub fn build_runtime_scan_report(
    input: &BuildRuntimeScanReportInput,
) -> Result<RuntimeScanReport, String> {
    let requested_url = sanitize_runtime_url(&input.requested_url)?;
    let final_url =
        sanitize_runtime_url(&input.snapshot.final_url).unwrap_or_else(|_| requested_url.clone());

    let mut long_animation_frames = input.snapshot.long_animation_frames.clone();
    long_animation_frames.sort_by(|a, b| b.duration_ms.total_cmp(&a.duration_ms));

    let interactions = build_deduplicated_interactions(&input.snapshot);
    let worst_interaction_duration_ms = interactions
        .iter()
        .map(|i| i.duration_ms)
        .fold(0.0_f64, f64::max);
    let worst_frame_duration_ms = long_animation_frames.first().map_or(0.0, |f| f.duration_ms);
    let total_blocking_duration_ms: f64 = long_animation_frames
        .iter()
        .map(|f| f.blocking_duration_ms)
        .sum();

    Ok(RuntimeScanReport {
        schema_version: RUNTIME_SCAN_SCHEMA_VERSION,
        kind: "dotore-runtime-scan".to_string(),
        requested_url,
        final_url,
        trace_path: input.trace_path.clone(),
        captured_at: input.captured_at.clone(),
        time_origin: input.snapshot.time_origin,
        connection: input.connection,
        support: input.snapshot.support.clone(),
        summary: RuntimeScanSummary {
            duration_ms: input.duration_ms,
            long_animation_frame_count: long_animation_frames.len(),
            worst_frame_duration_ms,
            total_blocking_duration_ms,
            interaction_count: interactions.len(),
            worst_interaction_duration_ms,
            cumulative_layout_shift: input.snapshot.cumulative_layout_shift,
            largest_contentful_paint_ms: input.snapshot.largest_contentful_paint_ms,
        },
        script_hotspots: build_script_hotspots(&input.snapshot),
        component_hotspots: build_component_hotspots(&input.snapshot),
        long_animation_frames,
        interactions,
        warnings: build_warnings(&input.snapshot),
    })
}

fn format_ms(duration_ms: f64) -> String {
    format!("{duration_ms:.1}ms")
}

fn format_text_report(report: &RuntimeScanReport) -> String {
    let connection_str = match report.connection {
        RuntimeScanConnection::Cdp => "attached over CDP",
        RuntimeScanConnection::Isolated => "isolated profile",
    };
    let react_str = if report.support.react_detected {
        let version = report.support.react_version.as_deref().unwrap_or("unknown");
        let build_type = match report.support.react_build_type {
            Some(ReactBuildType::Development) => "development",
            Some(ReactBuildType::Production) => "production",
            None => "unknown",
        };
        format!(
            "{} ({})",
            sanitize_runtime_text(version),
            sanitize_runtime_text(build_type)
        )
    } else {
        "not detected".to_string()
    };

    let loaf_plural = if report.summary.long_animation_frame_count == 1 {
        ""
    } else {
        "s"
    };
    let interaction_plural = if report.summary.interaction_count == 1 {
        ""
    } else {
        "s"
    };
    let lcp_str = match report.summary.largest_contentful_paint_ms {
        Some(lcp) => format_ms(lcp),
        None => "unavailable".to_string(),
    };

    let mut lines = vec![
        "✔ Runtime trace captured".to_string(),
        format!("  {}", sanitize_runtime_text(&report.final_url)),
        String::new(),
        format!("Trace {}", sanitize_runtime_text(&report.trace_path)),
        format!(
            "Browser {connection_str} · {} captured",
            format_ms(report.summary.duration_ms)
        ),
        format!("React {react_str}"),
        String::new(),
        "Performance".to_string(),
        format!(
            "  ├─ {} long animation frame{loaf_plural}; worst {}",
            report.summary.long_animation_frame_count,
            format_ms(report.summary.worst_frame_duration_ms)
        ),
        format!(
            "  ├─ {} total blocking time",
            format_ms(report.summary.total_blocking_duration_ms)
        ),
        format!(
            "  ├─ {} interaction{interaction_plural}; worst {}",
            report.summary.interaction_count,
            format_ms(report.summary.worst_interaction_duration_ms)
        ),
        format!("  ├─ CLS {:.1}", report.summary.cumulative_layout_shift),
        format!("  └─ LCP {lcp_str}"),
    ];

    if !report.script_hotspots.is_empty() {
        lines.push(String::new());
        lines.push("Script hotspots".to_string());
        for (idx, hotspot) in report.script_hotspots.iter().enumerate() {
            let prefix = if idx + 1 == report.script_hotspots.len() {
                "└─"
            } else {
                "├─"
            };
            let source_url = sanitize_runtime_text(&hotspot.source_url);
            let source_location = if hotspot.source_char_position > 0 {
                format!("{source_url} @ char {}", hotspot.source_char_position)
            } else {
                source_url
            };
            let fn_name = sanitize_runtime_text(&hotspot.function_name);
            let location = if source_location.is_empty() {
                fn_name
            } else if fn_name.is_empty() {
                source_location
            } else {
                format!("{source_location} · {fn_name}")
            };
            let frame_plural = if hotspot.frame_count == 1 { "" } else { "s" };
            lines.push(format!(
                "  {prefix} {} {location}",
                format_ms(hotspot.total_duration_ms)
            ));
            lines.push(format!(
                "     {} frame{frame_plural}, {} forced layout",
                hotspot.frame_count,
                format_ms(hotspot.forced_style_and_layout_duration_ms)
            ));
        }
    }

    if !report.component_hotspots.is_empty() {
        lines.push(String::new());
        lines.push("React component hotspots".to_string());
        for (idx, hotspot) in report.component_hotspots.iter().enumerate() {
            let prefix = if idx + 1 == report.component_hotspots.len() {
                "└─"
            } else {
                "├─"
            };
            let render_plural = if hotspot.render_count == 1 { "" } else { "s" };
            lines.push(format!(
                "  {prefix} {} · {} across {} render{render_plural}",
                sanitize_runtime_text(&hotspot.name),
                format_ms(hotspot.total_duration_ms),
                hotspot.render_count
            ));
        }
    }

    if !report.warnings.is_empty() {
        lines.push(String::new());
        lines.push("Limitations".to_string());
        for warning in &report.warnings {
            lines.push(format!("  - {}", sanitize_runtime_text(warning)));
        }
    }

    format!("{}\n", lines.join("\n"))
}

fn format_jsonl_report(report: &RuntimeScanReport) -> String {
    let mut records: Vec<RuntimeScanJsonlRecord> = Vec::new();
    records.push(RuntimeScanJsonlRecord {
        schema_version: report.schema_version,
        kind: "metadata".to_string(),
        data: json!({
            "requestedUrl": report.requested_url,
            "finalUrl": report.final_url,
            "tracePath": report.trace_path,
            "capturedAt": report.captured_at,
            "timeOrigin": report.time_origin,
            "connection": report.connection,
            "support": report.support,
            "warnings": report.warnings,
        }),
    });
    records.push(RuntimeScanJsonlRecord {
        schema_version: report.schema_version,
        kind: "summary".to_string(),
        data: serde_json::to_value(&report.summary).unwrap_or(serde_json::Value::Null),
    });
    for hotspot in &report.script_hotspots {
        records.push(RuntimeScanJsonlRecord {
            schema_version: report.schema_version,
            kind: "script-hotspot".to_string(),
            data: serde_json::to_value(hotspot).unwrap_or(serde_json::Value::Null),
        });
    }
    for hotspot in &report.component_hotspots {
        records.push(RuntimeScanJsonlRecord {
            schema_version: report.schema_version,
            kind: "component-hotspot".to_string(),
            data: serde_json::to_value(hotspot).unwrap_or(serde_json::Value::Null),
        });
    }
    for frame in &report.long_animation_frames {
        records.push(RuntimeScanJsonlRecord {
            schema_version: report.schema_version,
            kind: "long-animation-frame".to_string(),
            data: serde_json::to_value(frame).unwrap_or(serde_json::Value::Null),
        });
    }
    for interaction in &report.interactions {
        records.push(RuntimeScanJsonlRecord {
            schema_version: report.schema_version,
            kind: "interaction".to_string(),
            data: serde_json::to_value(interaction).unwrap_or(serde_json::Value::Null),
        });
    }
    let lines: Vec<String> = records
        .iter()
        .filter_map(|r| serde_json::to_string(r).ok())
        .collect();
    format!("{}\n", lines.join("\n"))
}

/// Formats a [`RuntimeScanReport`] as `text`, `json`, or `jsonl`.
#[must_use]
pub fn format_runtime_scan_report(report: &RuntimeScanReport, format: RuntimeScanFormat) -> String {
    match format {
        RuntimeScanFormat::Json => {
            let pretty = serde_json::to_string_pretty(report).unwrap_or_default();
            format!("{pretty}\n")
        }
        RuntimeScanFormat::Jsonl => format_jsonl_report(report),
        RuntimeScanFormat::Text => format_text_report(report),
    }
}

fn probe_local_http_addr(addr: std::net::SocketAddr, port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let timeout = Duration::from_millis(300);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("HEAD / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    n >= 5 && buf[..n].starts_with(b"HTTP/")
}

/// Probes local HTTP ports on `127.0.0.1` and `::1` and returns reachable `http://localhost:<port>` suggestions.
#[must_use]
pub fn detect_local_runtime_urls(ports: &[u16]) -> Vec<LocalUrlSuggestion> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let handles: Vec<(u16, std::thread::JoinHandle<bool>)> = ports
        .iter()
        .copied()
        .map(|port| {
            let handle = std::thread::spawn(move || {
                let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
                probe_local_http_addr(v4, port) || probe_local_http_addr(v6, port)
            });
            (port, handle)
        })
        .collect();

    let mut suggestions = Vec::new();
    for (port, handle) in handles {
        if handle.join().unwrap_or(false) {
            suggestions.push(LocalUrlSuggestion {
                port,
                url: format!("http://localhost:{port}"),
            });
        }
    }
    suggestions
}

/// Prompts the user to select a detected local server URL or enter a custom `http(s)` URL.
///
/// # Errors
/// Returns an error if reading from `input` or writing to `output` fails.
pub fn prompt_runtime_scan_url_with_io<R: std::io::BufRead, W: std::io::Write>(
    suggestions: &[LocalUrlSuggestion],
    input: &mut R,
    output: &mut W,
) -> Result<Option<String>, String> {
    writeln!(output, "dotore").map_err(|e| e.to_string())?;
    writeln!(output, "Choose an app to scan").map_err(|e| e.to_string())?;
    writeln!(output, "We'll open Chrome and scan one interaction.").map_err(|e| e.to_string())?;
    if suggestions.is_empty() {
        writeln!(output, "No local HTTP apps detected.").map_err(|e| e.to_string())?;
    } else {
        for (idx, suggestion) in suggestions.iter().enumerate() {
            let marker = if idx == 0 { "❯" } else { "›" };
            writeln!(
                output,
                "  {marker} [{}] {} detected",
                idx + 1,
                suggestion.url
            )
            .map_err(|e| e.to_string())?;
        }
    }
    writeln!(output, "  › Enter another URL").map_err(|e| e.to_string())?;
    write!(output, "App URL: ").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())?;

    let mut custom_mode = suggestions.is_empty();
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = input.read_line(&mut line).map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            return Ok(None);
        }
        let raw = line.trim_end_matches(['\r', '\n']);
        if raw == "\x1b" || raw.eq_ignore_ascii_case("q") || raw.eq_ignore_ascii_case("esc") {
            return Ok(None);
        }
        let trimmed = raw.trim();
        if !custom_mode {
            if trimmed.is_empty() {
                if let Some(first) = suggestions.first() {
                    return Ok(Some(first.url.clone()));
                }
                custom_mode = true;
                continue;
            }
            if trimmed == "\x1b[B" || trimmed == "j" || trimmed.eq_ignore_ascii_case("other") {
                custom_mode = true;
                writeln!(output, "App URL").map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
                continue;
            }
            if let Ok(index) = trimmed.parse::<usize>() {
                if index >= 1 && index <= suggestions.len() {
                    return Ok(Some(suggestions[index - 1].url.clone()));
                }
                if index == suggestions.len() + 1 {
                    custom_mode = true;
                    writeln!(output, "App URL").map_err(|e| e.to_string())?;
                    output.flush().map_err(|e| e.to_string())?;
                    continue;
                }
            }
        }

        if sanitize_runtime_url(trimmed).is_ok() {
            return Ok(Some(limit_string(trimmed)));
        }
        writeln!(
            output,
            "Enter an absolute URL starting with http:// or https://."
        )
        .map_err(|e| e.to_string())?;
        write!(output, "App URL: ").map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
}

/// Formats a runtime scan error in `text`, `json`, or `jsonl` format.
#[must_use]
pub fn format_runtime_scan_error_report(format: RuntimeScanFormat, message: &str) -> String {
    match format {
        RuntimeScanFormat::Json => {
            let obj = json!({
                "schemaVersion": RUNTIME_SCAN_SCHEMA_VERSION,
                "kind": "dotore-runtime-scan-error",
                "error": {
                    "message": message,
                }
            });
            let pretty = serde_json::to_string_pretty(&obj).unwrap_or_default();
            format!("{pretty}\n")
        }
        RuntimeScanFormat::Jsonl => {
            let obj = json!({
                "schemaVersion": RUNTIME_SCAN_SCHEMA_VERSION,
                "kind": "error",
                "error": {
                    "message": message,
                }
            });
            let compact = serde_json::to_string(&obj).unwrap_or_default();
            format!("{compact}\n")
        }
        RuntimeScanFormat::Text => format!("Error: {message}\n"),
    }
}

fn build_browser_probe_source(attribute_name: &str, token: &str) -> String {
    let attr_json = serde_json::to_string(attribute_name).unwrap_or_default();
    let token_json = serde_json::to_string(token).unwrap_or_default();
    format!(
        r#"(() => {{
  const MAX_LOAF_ENTRIES = {RUNTIME_SCAN_MAX_LOAF_ENTRIES};
  const MAX_SCRIPTS_PER_LOAF = {RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF};
  const MAX_COMPONENT_EVENTS = {RUNTIME_SCAN_MAX_COMPONENT_EVENTS};
  const MAX_COMPONENTS_PER_COMMIT = {RUNTIME_SCAN_MAX_COMPONENTS_PER_COMMIT};
  const MAX_INTERACTIONS = {RUNTIME_SCAN_MAX_INTERACTIONS};
  const MAX_STRING_LENGTH = {RUNTIME_SCAN_MAX_STRING_LENGTH};
  const MIN_COMPONENT_DURATION_MS = {RUNTIME_SCAN_MIN_COMPONENT_DURATION_MS};
  const INTERACTION_DURATION_THRESHOLD_MS = {RUNTIME_SCAN_INTERACTION_DURATION_THRESHOLD_MS};
  const SNAPSHOT_CATEGORY_BUDGET_BYTES = {};
  const SNAPSHOT_ATTRIBUTE_NAME = {attr_json};
  const SNAPSHOT_TOKEN = {token_json};
  const OVERLAY_COLOR_RGB = "115,97,230";
  const OVERLAY_FONT = "Menlo,Consolas,Monaco,Liberation Mono,Lucida Console,monospace";
  const OVERLAY_VISIBLE_FRAME_COUNT = 45;
  const OVERLAY_MAX_DEVICE_PIXEL_RATIO = 2;
  const OVERLAY_MAX_ACTIVE_OUTLINES = 200;
  const OVERLAY_MAX_HOST_ELEMENTS = 20;
  const OVERLAY_MAX_LABEL_LENGTH = 40;
  const OVERLAY_FONT_SIZE_PX = 11;
  const OVERLAY_LABEL_PADDING_PX = 2;
  const OVERLAY_LABEL_GAP_PX = 4;
  const OVERLAY_LINE_WIDTH_PX = 1;
  const OVERLAY_FILL_ALPHA = 0.1;
  const OVERLAY_Z_INDEX = 2147483646;

  const fiberIds = new WeakMap();
  let nextFiberId = 1;
  const getFiberId = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return 0;
    const existing = fiberIds.get(fiber) || (fiber.alternate && fiberIds.get(fiber.alternate));
    if (existing) {{
      fiberIds.set(fiber, existing);
      return existing;
    }}
    const id = nextFiberId++;
    fiberIds.set(fiber, id);
    if (fiber.alternate) fiberIds.set(fiber.alternate, id);
    return id;
  }};

  const isCompositeFiber = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return false;
    const tag = fiber.tag;
    return tag === 0 || tag === 1 || tag === 11 || tag === 14 || tag === 15;
  }};

  const isHostFiber = (fiber) => {{
    if (!fiber || typeof fiber !== "object") return false;
    return fiber.tag === 5 || typeof fiber.type === "string";
  }};

  const getDisplayName = (type) => {{
    if (!type) return null;
    if (typeof type === "string") return type;
    if (typeof type === "function") return type.displayName || type.name || null;
    if (typeof type === "object") {{
      return (
        type.displayName ||
        type.name ||
        (type.render && (type.render.displayName || type.render.name)) ||
        (type.type && getDisplayName(type.type)) ||
        null
      );
    }}
    return null;
  }};

  const getTimings = (fiber) => {{
    const actualDuration = typeof fiber?.actualDuration === "number" ? fiber.actualDuration : 0;
    let selfTime = actualDuration;
    let child = fiber?.child ?? null;
    while (child !== null) {{
      if (typeof child.actualDuration === "number") {{
        selfTime -= child.actualDuration;
      }}
      child = child.sibling ?? null;
    }}
    return {{ actualDuration, selfTime: Math.max(0, selfTime) }};
  }};

  const pendingOutlines = new Map();
  const activeOutlines = new Map();
  let canvas = null;
  let context = null;
  let flushAnimationFrameId = null;
  let drawAnimationFrameId = null;
  let previousScrollX = window.scrollX;
  let previousScrollY = window.scrollY;

  const getNearestHostElements = (fiber) => {{
    const elements = [];
    const fibersToVisit = [];
    if (isHostFiber(fiber)) {{
      fibersToVisit.push(fiber);
    }} else if (fiber.child !== null && fiber.child !== undefined) {{
      fibersToVisit.push(fiber.child);
    }}
    while (fibersToVisit.length > 0 && elements.length < OVERLAY_MAX_HOST_ELEMENTS) {{
      const currentFiber = fibersToVisit.pop();
      if (!currentFiber) break;
      if (isHostFiber(currentFiber)) {{
        if (currentFiber.stateNode instanceof Element) elements.push(currentFiber.stateNode);
      }} else if (currentFiber.child) {{
        fibersToVisit.push(currentFiber.child);
      }}
      if (currentFiber.sibling) fibersToVisit.push(currentFiber.sibling);
    }}
    return elements;
  }};

  const mergeRects = (rects) => {{
    const firstRect = rects[0];
    if (rects.length === 1) return firstRect;
    let minX = firstRect.x;
    let minY = firstRect.y;
    let maxX = firstRect.right;
    let maxY = firstRect.bottom;
    for (const rect of rects.slice(1)) {{
      minX = Math.min(minX, rect.x);
      minY = Math.min(minY, rect.y);
      maxX = Math.max(maxX, rect.right);
      maxY = Math.max(maxY, rect.bottom);
    }}
    return new DOMRect(minX, minY, maxX - minX, maxY - minY);
  }};

  const resizeCanvas = () => {{
    if (canvas === null || context === null) return;
    const dpr = Math.min(window.devicePixelRatio || 1, OVERLAY_MAX_DEVICE_PIXEL_RATIO);
    canvas.style.width = `${{window.innerWidth}}px`;
    canvas.style.height = `${{window.innerHeight}}px`;
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
  }};

  const ensureCanvas = () => {{
    if (canvas !== null && context !== null) return true;
    const documentElement = document.documentElement;
    if (documentElement === null) return false;
    const host = document.createElement("div");
    host.setAttribute("data-dotore-runtime-scan-overlay", "");
    const shadowRoot = host.attachShadow({{ mode: "open" }});
    const nextCanvas = document.createElement("canvas");
    nextCanvas.setAttribute("aria-hidden", "true");
    nextCanvas.style.position = "fixed";
    nextCanvas.style.inset = "0";
    nextCanvas.style.pointerEvents = "none";
    nextCanvas.style.zIndex = String(OVERLAY_Z_INDEX);
    shadowRoot.appendChild(nextCanvas);
    documentElement.appendChild(host);
    const nextContext = nextCanvas.getContext("2d");
    if (nextContext === null) {{
      host.remove();
      return false;
    }}
    canvas = nextCanvas;
    context = nextContext;
    resizeCanvas();
    return true;
  }};

  const buildGroupLabel = (outlines) => {{
    const renderCountByName = new Map();
    for (const outline of outlines) {{
      renderCountByName.set(outline.name, (renderCountByName.get(outline.name) ?? 0) + outline.count);
    }}
    const label = [...renderCountByName.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${{name}} ×${{count}}`)
      .join(", ");
    return label.length > OVERLAY_MAX_LABEL_LENGTH
      ? `${{label.slice(0, OVERLAY_MAX_LABEL_LENGTH)}}…`
      : label;
  }};

  const groupOutlines = () => {{
    const outlinesByRect = new Map();
    for (const outline of activeOutlines.values()) {{
      const key = `${{Math.round(outline.x)}},${{Math.round(outline.y)}},${{Math.round(outline.width)}},${{Math.round(outline.height)}}`;
      const existing = outlinesByRect.get(key);
      if (existing === undefined) outlinesByRect.set(key, [outline]);
      else existing.push(outline);
    }}
    return [...outlinesByRect.values()].map((outlines) => {{
      const first = outlines[0];
      return {{
        outlines,
        x: first.x,
        y: first.y,
        width: first.width,
        height: first.height,
        alpha: Math.max(...outlines.map((o) => 1 - o.elapsedFrameCount / OVERLAY_VISIBLE_FRAME_COUNT)),
      }};
    }});
  }};

  const drawActiveOutlines = () => {{
    drawAnimationFrameId = null;
    if (canvas === null || context === null) return;
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    context.font = `${{OVERLAY_FONT_SIZE_PX}}px ${{OVERLAY_FONT}}`;
    for (const group of groupOutlines()) {{
      const x = Math.round(group.x) + OVERLAY_LINE_WIDTH_PX / 2;
      const y = Math.round(group.y) + OVERLAY_LINE_WIDTH_PX / 2;
      const width = Math.round(group.width);
      const height = Math.round(group.height);
      context.strokeStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha}})`;
      context.lineWidth = OVERLAY_LINE_WIDTH_PX;
      context.strokeRect(x, y, width, height);
      context.fillStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha * OVERLAY_FILL_ALPHA}})`;
      context.fillRect(x, y, width, height);
      const label = buildGroupLabel(group.outlines);
      const labelWidth = context.measureText(label).width + OVERLAY_LABEL_PADDING_PX * 2;
      const labelHeight = OVERLAY_FONT_SIZE_PX + OVERLAY_LABEL_PADDING_PX * 2;
      const labelY = Math.max(0, y - labelHeight - OVERLAY_LABEL_GAP_PX);
      context.fillStyle = `rgba(${{OVERLAY_COLOR_RGB}},${{group.alpha}})`;
      context.fillRect(x, labelY, labelWidth, labelHeight);
      context.fillStyle = `rgba(255,255,255,${{group.alpha}})`;
      context.fillText(label, x + OVERLAY_LABEL_PADDING_PX, labelY + labelHeight - OVERLAY_LABEL_PADDING_PX);
    }}
    for (const outline of activeOutlines.values()) {{
      outline.elapsedFrameCount += 1;
      if (outline.elapsedFrameCount > OVERLAY_VISIBLE_FRAME_COUNT) activeOutlines.delete(outline.id);
    }}
    if (activeOutlines.size > 0) drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
  }};

  const flushPendingOutlines = () => {{
    flushAnimationFrameId = null;
    if (!ensureCanvas()) return;
    const rectByElement = new Map();
    for (const pending of pendingOutlines.values()) {{
      for (const el of pending.elements) {{
        if (!el.isConnected || rectByElement.has(el)) continue;
        rectByElement.set(el, el.getBoundingClientRect());
      }}
    }}
    for (const pending of pendingOutlines.values()) {{
      const rects = pending.elements
        .map((el) => rectByElement.get(el))
        .filter((r) => r !== undefined && r.width > 0 && r.height > 0);
      if (rects.length === 0) continue;
      const rect = mergeRects(rects);
      const existing = activeOutlines.get(pending.id);
      if (existing === undefined) {{
        if (activeOutlines.size >= OVERLAY_MAX_ACTIVE_OUTLINES) continue;
        activeOutlines.set(pending.id, {{
          id: pending.id,
          name: pending.name,
          count: pending.count,
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          elapsedFrameCount: 0,
        }});
      }} else {{
        existing.count += pending.count;
        existing.x = rect.x;
        existing.y = rect.y;
        existing.width = rect.width;
        existing.height = rect.height;
        existing.elapsedFrameCount = 0;
      }}
    }}
    pendingOutlines.clear();
    if (drawAnimationFrameId === null && activeOutlines.size > 0) {{
      drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
    }}
  }};

  const recordOverlayRender = (fiber) => {{
    if (!isCompositeFiber(fiber)) return;
    const id = getFiberId(fiber);
    const existing = pendingOutlines.get(id);
    if (existing !== undefined) {{
      existing.count += 1;
      return;
    }}
    if (pendingOutlines.size >= OVERLAY_MAX_ACTIVE_OUTLINES) return;
    const displayName = getDisplayName(fiber.type);
    if (displayName === null) return;
    const name = displayName.slice(0, OVERLAY_MAX_LABEL_LENGTH);
    const elements = getNearestHostElements(fiber);
    if (elements.length === 0) return;
    pendingOutlines.set(id, {{ id, name, elements, count: 1 }});
    if (flushAnimationFrameId === null) {{
      flushAnimationFrameId = requestAnimationFrame(flushPendingOutlines);
    }}
  }};

  window.addEventListener("resize", resizeCanvas);
  window.addEventListener("scroll", () => {{
    const dx = window.scrollX - previousScrollX;
    const dy = window.scrollY - previousScrollY;
    previousScrollX = window.scrollX;
    previousScrollY = window.scrollY;
    for (const outline of activeOutlines.values()) {{
      outline.x -= dx;
      outline.y -= dy;
    }}
    if (drawAnimationFrameId === null && activeOutlines.size > 0) {{
      drawAnimationFrameId = requestAnimationFrame(drawActiveOutlines);
    }}
  }}, {{ passive: true }});

  const performanceObservers = [];
  const snapshotTextEncoder = new TextEncoder();
  const setSnapshotAttribute = Element.prototype.setAttribute;
  const removeSnapshotAttribute = Element.prototype.removeAttribute;
  const queueSnapshotAttributeRemoval = window.queueMicrotask.bind(window);
  const longAnimationFrames = {{ entries: [], nextIndex: 0, dropped: 0 }};
  const componentEvents = {{ entries: [], nextIndex: 0, dropped: 0 }};
  const interactions = {{ entries: [], nextIndex: 0, dropped: 0 }};
  let cumulativeLayoutShift = 0;
  let largestContentfulPaintMs = null;
  let droppedScriptTimings = 0;
  let reactDetected = false;
  let reactVersion = null;
  let reactBuildType = null;
  let nativeReactTracks = false;
  let bippyComponentTracks = false;
  let didCaptureCurrentPageState = false;

  const limitString = (v) => String(v ?? "").slice(0, MAX_STRING_LENGTH);
  const sanitizeUrl = (rawUrl) => {{
    try {{
      const parsed = new URL(rawUrl, window.location.href);
      parsed.username = "";
      parsed.password = "";
      parsed.search = "";
      parsed.hash = "";
      return limitString(parsed.href);
    }} catch {{
      return "";
    }}
  }};

  const pushBoundedEntry = (bounded, limit, entry) => {{
    if (bounded.entries.length < limit) bounded.entries.push(entry);
    else {{
      bounded.entries[bounded.nextIndex] = entry;
      bounded.nextIndex = (bounded.nextIndex + 1) % limit;
      bounded.dropped += 1;
    }}
  }};

  const readBoundedEntries = (bounded) => {{
    if (bounded.nextIndex === 0) return [...bounded.entries];
    return [...bounded.entries.slice(bounded.nextIndex), ...bounded.entries.slice(0, bounded.nextIndex)];
  }};

  const takeLatestEntriesWithinByteBudget = (entries) => {{
    let minCount = 0;
    let maxCount = entries.length;
    while (minCount < maxCount) {{
      const candidateCount = Math.ceil((minCount + maxCount) / 2);
      const candidateEntries = entries.slice(entries.length - candidateCount);
      const bytes = snapshotTextEncoder.encode(JSON.stringify(candidateEntries)).byteLength;
      if (bytes <= SNAPSHOT_CATEGORY_BUDGET_BYTES) minCount = candidateCount;
      else maxCount = candidateCount - 1;
    }}
    return {{
      entries: entries.slice(entries.length - minCount),
      dropped: entries.length - minCount,
    }};
  }};

  const observe = (entryType, listener, durationThreshold) => {{
    try {{
      const observer = new PerformanceObserver((list) => {{
        for (const entry of list.getEntries()) listener(entry);
      }});
      observer.observe({{ type: entryType, buffered: true, durationThreshold }});
      performanceObservers.push({{ observer, listener }});
      return true;
    }} catch {{
      return false;
    }}
  }};

  const loafSupported = observe("long-animation-frame", (entry) => {{
    const scripts = entry.scripts ?? [];
    droppedScriptTimings += Math.max(0, scripts.length - MAX_SCRIPTS_PER_LOAF);
    pushBoundedEntry(longAnimationFrames, MAX_LOAF_ENTRIES, {{
      startTime: entry.startTime,
      durationMs: entry.duration,
      blockingDurationMs: entry.blockingDuration ?? 0,
      renderStart: entry.renderStart ?? 0,
      styleAndLayoutStart: entry.styleAndLayoutStart ?? 0,
      firstUiEventTimestamp: entry.firstUIEventTimestamp ?? 0,
      scripts: scripts.slice(0, MAX_SCRIPTS_PER_LOAF).map((s) => ({{
        invoker: limitString(s.invoker ?? ""),
        invokerType: limitString(s.invokerType ?? ""),
        sourceUrl: sanitizeUrl(s.sourceURL ?? ""),
        sourceFunctionName: limitString(s.sourceFunctionName ?? ""),
        sourceCharPosition: s.sourceCharPosition ?? 0,
        executionStart: s.executionStart ?? 0,
        durationMs: s.duration ?? 0,
        forcedStyleAndLayoutDurationMs: s.forcedStyleAndLayoutDuration ?? 0,
        pauseDurationMs: s.pauseDuration ?? 0,
      }})),
    }});
  }});

  observe("event", (entry) => {{
    const interactionId = entry.interactionId ?? 0;
    if (interactionId === 0) return;
    pushBoundedEntry(interactions, MAX_INTERACTIONS, {{
      name: limitString(entry.name),
      startTime: entry.startTime,
      durationMs: entry.duration,
      processingStart: entry.processingStart ?? entry.startTime,
      processingEnd: entry.processingEnd ?? entry.startTime,
      interactionId,
      targetTag: entry.target == null ? null : limitString(entry.target.tagName),
    }});
  }}, INTERACTION_DURATION_THRESHOLD_MS);

  observe("layout-shift", (entry) => {{
    if (entry.hadRecentInput === true) return;
    cumulativeLayoutShift += entry.value ?? 0;
  }});

  observe("largest-contentful-paint", (entry) => {{
    largestContentfulPaintMs = Math.max(largestContentfulPaintMs ?? 0, entry.startTime);
  }});

  observe("measure", (entry) => {{
    const devtools = entry.detail?.devtools;
    if (!devtools?.track?.includes("Components")) return;
    if (devtools.dotoreSource === "bippy") return;
    nativeReactTracks = true;
    pushBoundedEntry(componentEvents, MAX_COMPONENT_EVENTS, {{
      name: limitString(String(entry.name ?? "").replace(/^\u200B/, "")),
      startTime: entry.startTime,
      durationMs: entry.duration,
      depth: 0,
      source: "native",
    }});
  }});

  const versionHasNativeTracks = (version) => {{
    const [maj, min] = String(version).split(".");
    const major = Number.parseInt(maj ?? "", 10);
    const minor = Number.parseInt(min ?? "", 10);
    return major > 19 || (major === 19 && minor >= 2);
  }};

  const attachRenderer = (renderer) => {{
    if (!renderer) return;
    reactDetected = true;
    reactVersion = typeof renderer.version === "string" ? limitString(renderer.version) : null;
    reactBuildType = renderer.bundleType === 0 ? "production" : "development";
  }};

  const traverseRenderedFibers = (root, cb) => {{
    const current = root?.current;
    if (!current) return;
    const stack = [current];
    while (stack.length > 0) {{
      const fiber = stack.pop();
      if (!fiber) continue;
      cb(fiber);
      if (fiber.sibling) stack.push(fiber.sibling);
      if (fiber.child) stack.push(fiber.child);
    }}
  }};

  const onCommit = (_rendererId, root) => {{
    const shouldRecordFallback = reactVersion === null || !versionHasNativeTracks(reactVersion);
    let count = 0;
    traverseRenderedFibers(root, (fiber) => {{
      if (!isCompositeFiber(fiber)) return;
      if (count >= MAX_COMPONENTS_PER_COMMIT) return;
      recordOverlayRender(fiber);
      if (!shouldRecordFallback) {{
        count += 1;
        return;
      }}
      const {{ selfTime }} = getTimings(fiber);
      if (selfTime >= MIN_COMPONENT_DURATION_MS) {{
        let depth = 0;
        let p = fiber.return;
        while (p) {{ depth += 1; p = p.return; }}
        const name = limitString(getDisplayName(fiber.type) ?? "Anonymous");
        const startTime = fiber.actualStartTime ?? performance.now() - selfTime;
        pushBoundedEntry(componentEvents, MAX_COMPONENT_EVENTS, {{
          name,
          startTime,
          durationMs: selfTime,
          depth,
          source: "bippy",
        }});
        bippyComponentTracks = true;
      }}
      count += 1;
    }});
  }};

  const ensureHook = () => {{
    let hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook) {{
      const renderers = new Map();
      let nextId = 1;
      hook = {{
        renderers,
        supportsFiber: true,
        inject: (renderer) => {{
          const id = nextId++;
          renderers.set(id, renderer);
          attachRenderer(renderer);
          return id;
        }},
        onCommitFiberRoot: (id, root) => onCommit(id, root),
        onCommitFiberUnmount: () => {{}},
      }};
      try {{
        Object.defineProperty(window, "__REACT_DEVTOOLS_GLOBAL_HOOK__", {{
          configurable: true,
          enumerable: false,
          get: () => hook,
        }});
      }} catch {{
        window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = hook;
      }}
    }} else {{
      if (hook.renderers && typeof hook.renderers.values === "function") {{
        for (const r of hook.renderers.values()) attachRenderer(r);
      }}
      const origInject = hook.inject;
      if (typeof origInject === "function") {{
        hook.inject = function(renderer, ...rest) {{
          attachRenderer(renderer);
          return origInject.call(this, renderer, ...rest);
        }};
      }}
      const origCommit = hook.onCommitFiberRoot;
      hook.onCommitFiberRoot = function(id, root, ...rest) {{
        try {{ onCommit(id, root); }} catch {{}}
        if (typeof origCommit === "function") return origCommit.call(this, id, root, ...rest);
      }};
    }}
  }};
  ensureHook();

  const snapshot = () => {{
    for (const {{ observer, listener }} of performanceObservers) {{
      for (const entry of observer.takeRecords()) listener(entry);
    }}
    const budgetedLoaf = takeLatestEntriesWithinByteBudget(readBoundedEntries(longAnimationFrames));
    const budgetedComp = takeLatestEntriesWithinByteBudget(readBoundedEntries(componentEvents));
    const budgetedInter = takeLatestEntriesWithinByteBudget(readBoundedEntries(interactions));
    return {{
      timeOrigin: performance.timeOrigin,
      finalUrl: sanitizeUrl(window.location.href),
      support: {{
        reactDetected,
        reactVersion,
        reactBuildType,
        nativeReactTracks,
        bippyComponentTracks,
        loaf: loafSupported,
      }},
      longAnimationFrames: budgetedLoaf.entries,
      componentEvents: budgetedComp.entries,
      interactions: budgetedInter.entries,
      cumulativeLayoutShift,
      largestContentfulPaintMs,
      droppedLongAnimationFrames: longAnimationFrames.dropped + budgetedLoaf.dropped,
      droppedScriptTimings,
      droppedComponentEvents: componentEvents.dropped + budgetedComp.dropped,
      droppedInteractions: interactions.dropped + budgetedInter.dropped,
    }};
  }};

  window.__DOTORE_RUNTIME_SCAN__ = {{ snapshot }};

  const captureSnapshot = (snap) => {{
    const el = document.documentElement;
    if (!el) return;
    try {{
      setSnapshotAttribute.call(el, SNAPSHOT_ATTRIBUTE_NAME, JSON.stringify({{ token: SNAPSHOT_TOKEN, snapshot: snap }}));
      queueSnapshotAttributeRemoval(() => {{
        try {{ removeSnapshotAttribute.call(el, SNAPSHOT_ATTRIBUTE_NAME); }} catch {{}}
      }});
    }} catch {{}}
  }};

  const captureNavigationSnapshot = () => {{
    if (window !== window.top || didCaptureCurrentPageState) return;
    didCaptureCurrentPageState = true;
    captureSnapshot(snapshot());
  }};

  document.addEventListener("visibilitychange", () => {{
    if (document.visibilityState === "hidden") captureNavigationSnapshot();
    else didCaptureCurrentPageState = false;
  }});
  window.addEventListener("pageshow", () => {{ didCaptureCurrentPageState = false; }});
  window.addEventListener("beforeunload", captureNavigationSnapshot);
  window.addEventListener("pagehide", captureNavigationSnapshot);
}})();"#,
        RUNTIME_SCAN_MAX_SNAPSHOT_BYTES / 3
    )
}

fn build_snapshot_relay_source(attribute_name: &str, binding_name: &str) -> String {
    let attr_json = serde_json::to_string(attribute_name).unwrap_or_default();
    let binding_json = serde_json::to_string(binding_name).unwrap_or_default();
    format!(
        r#"(() => {{
  let didRelaySnapshot = false;
  const getSnapshotAttribute = Element.prototype.getAttribute;
  const removeSnapshotAttribute = Element.prototype.removeAttribute;
  const relaySnapshot = () => {{
    const documentElement = document.documentElement;
    if (documentElement === null) return;
    const payload = getSnapshotAttribute.call(documentElement, {attr_json});
    removeSnapshotAttribute.call(documentElement, {attr_json});
    if (
      didRelaySnapshot ||
      typeof payload !== "string" ||
      payload.length > {RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES}
    ) return;
    if (new TextEncoder().encode(payload).byteLength > {RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES}) return;
    const captureBinding = Reflect.get(globalThis, {binding_json});
    if (typeof captureBinding !== "function") return;
    didRelaySnapshot = true;
    captureBinding(payload);
  }};
  new MutationObserver(relaySnapshot).observe(document, {{
    attributes: true,
    subtree: true,
    attributeFilter: [{attr_json}],
  }});
}})();"#
    )
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("Invalid base64 byte in trace chunk.".to_string()),
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

struct GzipStoredWriter<W: std::io::Write> {
    inner: W,
    buffer: Vec<u8>,
    crc: u32,
    total_bytes: u32,
}

impl<W: std::io::Write> GzipStoredWriter<W> {
    fn new(mut inner: W) -> std::io::Result<Self> {
        // RFC 1952 10-byte header: ID1=0x1f, ID2=0x8b, CM=8 (deflate), FLG=0, MTIME=0, XFL=0, OS=0xff
        inner.write_all(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff])?;
        Ok(Self {
            inner,
            buffer: Vec::with_capacity(65_535),
            crc: 0xffff_ffff,
            total_bytes: 0,
        })
    }

    fn update_crc(&mut self, data: &[u8]) {
        for &b in data {
            let mut c = (self.crc ^ u32::from(b)) & 0xff;
            for _ in 0..8 {
                c = if (c & 1) != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            self.crc = (self.crc >> 8) ^ c;
        }
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u32);
    }

    fn write_stored_block(&mut self, block: &[u8], final_block: bool) -> std::io::Result<()> {
        let header_byte = u8::from(final_block);
        let len = u16::try_from(block.len()).unwrap_or(u16::MAX);
        let nlen = !len;
        self.inner.write_all(&[header_byte])?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(&nlen.to_le_bytes())?;
        self.inner.write_all(block)
    }

    fn write_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.update_crc(data);
        let mut slice = data;
        while !slice.is_empty() {
            if self.buffer.len() == 65_535 {
                let block = std::mem::replace(&mut self.buffer, Vec::with_capacity(65_535));
                self.write_stored_block(&block, false)?;
            }
            let space = 65_535 - self.buffer.len();
            let take = space.min(slice.len());
            self.buffer.extend_from_slice(&slice[..take]);
            slice = &slice[take..];
        }
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<W> {
        let remaining = std::mem::take(&mut self.buffer);
        self.write_stored_block(&remaining, true)?;
        let crc_final = !self.crc;
        self.inner.write_all(&crc_final.to_le_bytes())?;
        self.inner.write_all(&self.total_bytes.to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

fn parse_host_port_path(
    raw_url: &str,
    default_scheme: &str,
) -> Result<(String, u16, String), String> {
    let (scheme, after_scheme) = raw_url
        .split_once("://")
        .unwrap_or((default_scheme, raw_url));
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let default_port = if scheme.eq_ignore_ascii_case("wss") || scheme.eq_ignore_ascii_case("https")
    {
        443
    } else {
        80
    };
    let (host, port) = if let Some(bracket_end) = authority.find(']') {
        let h = &authority[1..bracket_end];
        let p = authority[bracket_end + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(default_port);
        (h.to_string(), p)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in URL: {raw_url}"))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host, port, path.to_string()))
}

fn resolve_cdp_ws_url(cdp_url: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let trimmed = cdp_url.trim();
    if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        return Ok(trimmed.to_string());
    }
    let (host, port, _) = parse_host_port_path(trimmed, "http")?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "Could not resolve CDP host".to_string())?;
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req =
        format!("GET /json/version HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let (_, body) = resp
        .split_once("\r\n\r\n")
        .ok_or_else(|| "Invalid HTTP response from CDP endpoint".to_string())?;
    let json_val: serde_json::Value =
        serde_json::from_str(body.trim()).map_err(|e| e.to_string())?;
    json_val
        .get("webSocketDebuggerUrl")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Missing webSocketDebuggerUrl in /json/version".to_string())
}

struct CdpWebSocketClient {
    stream: std::net::TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    next_id: u64,
    pending_events: Vec<serde_json::Value>,
}

impl CdpWebSocketClient {
    fn connect(ws_url: &str) -> Result<Self, String> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        let (host, port, path) = parse_host_port_path(ws_url, "ws")?;
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| "Could not resolve CDP WebSocket host".to_string())?;
        let timeout = Duration::from_secs(10);
        let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        let mut buf = Vec::with_capacity(1024);
        let mut temp = [0u8; 512];
        let header_end = loop {
            let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("CDP WebSocket closed during handshake".to_string());
            }
            buf.extend_from_slice(&temp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        if !header_str.starts_with("HTTP/1.1 101") {
            return Err(format!("CDP WebSocket upgrade failed: {header_str}"));
        }
        let leftover = buf[header_end..].to_vec();
        Ok(Self {
            stream,
            read_buf: leftover,
            read_pos: 0,
            next_id: 1,
            pending_events: Vec::new(),
        })
    }

    fn read_exact_bytes(&mut self, count: usize) -> Result<Vec<u8>, String> {
        use std::io::Read;

        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            if self.read_pos < self.read_buf.len() {
                let avail = self.read_buf.len() - self.read_pos;
                let need = count - out.len();
                let take = avail.min(need);
                out.extend_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
                self.read_pos += take;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
            } else {
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("CDP WebSocket connection closed unexpectedly".to_string());
                }
                self.read_buf.extend_from_slice(&chunk[..n]);
            }
        }
        Ok(out)
    }

    fn send_masked_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        use std::io::Write;

        let mask = [0x37u8, 0xfau8, 0x21u8, 0x3du8];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (opcode & 0x0f));
        if payload.len() <= 125 {
            frame.push(0x80 | (payload.len() as u8));
        } else if payload.len() <= 65_535 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (idx, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[idx % 4]);
        }
        self.stream.write_all(&frame).map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())
    }

    fn read_json_message(&mut self) -> Result<serde_json::Value, String> {
        let mut message_bytes = Vec::new();
        loop {
            let hdr = self.read_exact_bytes(2)?;
            let fin = (hdr[0] & 0x80) != 0;
            let opcode = hdr[0] & 0x0f;
            let masked = (hdr[1] & 0x80) != 0;
            let mut len = (hdr[1] & 0x7f) as usize;
            if len == 126 {
                let ext = self.read_exact_bytes(2)?;
                len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            } else if len == 127 {
                let ext = self.read_exact_bytes(8)?;
                let len_u64 = u64::from_be_bytes([
                    ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
                ]);
                len = usize::try_from(len_u64).map_err(|_| "Frame too large".to_string())?;
            }
            let mask = if masked {
                let m = self.read_exact_bytes(4)?;
                [m[0], m[1], m[2], m[3]]
            } else {
                [0; 4]
            };
            let mut payload = self.read_exact_bytes(len)?;
            if masked {
                for (idx, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[idx % 4];
                }
            }
            match opcode {
                0x8 => return Err("CDP WebSocket closed by browser".to_string()),
                0x9 => {
                    let _ = self.send_masked_frame(0xA, &payload);
                    continue;
                }
                0xA => continue,
                0x0..=0x2 => {
                    message_bytes.extend_from_slice(&payload);
                    if fin {
                        break;
                    }
                }
                _ => continue,
            }
        }
        serde_json::from_slice(&message_bytes).map_err(|e| e.to_string())
    }

    fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
        session_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(sid) = session_id {
            req["sessionId"] = serde_json::Value::String(sid.to_string());
        }
        let payload = req.to_string();
        self.send_masked_frame(0x1, payload.as_bytes())?;
        loop {
            let msg = self.read_json_message()?;
            if msg.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                if let Some(err_obj) = msg.get("error") {
                    let err_msg = err_obj
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("Unknown CDP error");
                    return Err(err_msg.to_string());
                }
                return Ok(msg
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
            self.pending_events.push(msg);
        }
    }

    fn wait_for_event(
        &mut self,
        event_method: &str,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        use std::time::{Duration, Instant};

        if let Some(pos) = self
            .pending_events
            .iter()
            .position(|e| e.get("method").and_then(serde_json::Value::as_str) == Some(event_method))
        {
            return Ok(self.pending_events.remove(pos));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!("Timed out waiting for CDP event {event_method}"));
            }
            let _ = self.stream.set_read_timeout(Some(deadline - now));
            let msg = self.read_json_message()?;
            if msg.get("method").and_then(serde_json::Value::as_str) == Some(event_method) {
                let _ = self.stream.set_read_timeout(Some(Duration::from_secs(10)));
                return Ok(msg);
            }
            self.pending_events.push(msg);
        }
    }

    fn drain_binding_events(
        &mut self,
        binding_name: &str,
        expected_token: &str,
        snapshots: &mut Vec<RuntimeScanProbeSnapshot>,
        discarded: &mut DroppedEvidence,
    ) {
        let events = std::mem::take(&mut self.pending_events);
        for event in events {
            if event.get("method").and_then(serde_json::Value::as_str)
                == Some("Runtime.bindingCalled")
            {
                let params = &event["params"];
                if params.get("name").and_then(serde_json::Value::as_str) == Some(binding_name)
                    && let Some(payload) = params.get("payload").and_then(serde_json::Value::as_str)
                    && let Some(snap) = parse_runtime_scan_snapshot_payload(payload, expected_token)
                {
                    store_navigation_snapshot(snapshots, discarded, snap);
                }
            } else {
                self.pending_events.push(event);
            }
        }
    }
}

#[derive(Default)]
struct DroppedEvidence {
    dropped_long_animation_frames: u64,
    dropped_script_timings: u64,
    dropped_component_events: u64,
    dropped_interactions: u64,
}

fn store_navigation_snapshot(
    snapshots: &mut Vec<RuntimeScanProbeSnapshot>,
    discarded: &mut DroppedEvidence,
    snapshot: RuntimeScanProbeSnapshot,
) {
    let before_len = snapshots.len();
    snapshots.retain(|s| (s.time_origin - snapshot.time_origin).abs() > f64::EPSILON);
    let did_replace = snapshots.len() < before_len;
    if !did_replace && snapshots.len() >= RUNTIME_SCAN_MAX_DOCUMENT_SNAPSHOTS {
        let evicted = snapshots.remove(0);
        discarded.dropped_long_animation_frames +=
            evicted.long_animation_frames.len() as u64 + evicted.dropped_long_animation_frames;
        let scripts_count: u64 = evicted
            .long_animation_frames
            .iter()
            .map(|f| f.scripts.len() as u64)
            .sum();
        discarded.dropped_script_timings += scripts_count + evicted.dropped_script_timings;
        discarded.dropped_component_events +=
            evicted.component_events.len() as u64 + evicted.dropped_component_events;
        discarded.dropped_interactions +=
            evicted.interactions.len() as u64 + evicted.dropped_interactions;
    }
    snapshots.push(snapshot);
}

fn find_system_chrome_binary() -> Option<PathBuf> {
    if let Ok(custom) =
        std::env::var("DOTORE_CHROME_PATH").or_else(|_| std::env::var("CHROME_PATH"))
    {
        let p = PathBuf::from(custom);
        if p.exists() {
            return Some(p);
        }
    }
    let candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn launch_isolated_chrome() -> Result<(std::process::Child, PathBuf, String), String> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let Some(chrome_bin) = find_system_chrome_binary() else {
        return Err(
            "Could not connect to Chrome. Install Google Chrome, or pass --cdp <url> for a browser started with remote debugging."
                .to_string(),
        );
    };
    let profile_dir = std::env::temp_dir().join(format!(
        "dotore-chrome-profile-{}",
        generate_unique_hex_id()
    ));
    std::fs::create_dir_all(&profile_dir).map_err(|e| e.to_string())?;

    let mut child = Command::new(chrome_bin)
        .arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--window-size=1440,900")
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            let _ = std::fs::remove_dir_all(&profile_dir);
            "Could not connect to Chrome. Install Google Chrome, or pass --cdp <url> for a browser started with remote debugging."
                .to_string()
        })?;

    let stderr = child.stderr.take().ok_or_else(|| {
        let _ = child.kill();
        let _ = std::fs::remove_dir_all(&profile_dir);
        "Failed to read Chrome stderr.".to_string()
    })?;

    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Some(pos) = line.find("ws://") {
            let ws_url = line[pos..].trim().to_string();
            return Ok((child, profile_dir, ws_url));
        }
        line.clear();
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&profile_dir);
    Err(
        "Could not connect to Chrome. Install Google Chrome, or pass --cdp <url> for a browser started with remote debugging."
            .to_string(),
    )
}

fn current_iso_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("2026-08-15T00:00:{:02}.000Z", secs % 60)
}

fn wait_for_stop_or_timeout(max_duration_ms: u64) {
    use std::time::{Duration, Instant};

    if max_duration_ms <= 50 {
        std::thread::sleep(Duration::from_millis(max_duration_ms));
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let _ = tx.send(());
    });
    let deadline = Instant::now() + Duration::from_millis(max_duration_ms);
    let now = Instant::now();
    if deadline > now {
        let _ = rx.recv_timeout(deadline - now);
    }
}

fn stream_trace_to_gzip_file(
    client: &mut CdpWebSocketClient,
    stream_handle: &str,
    trace_path: &std::path::Path,
) -> Result<(), String> {
    if let Some(parent) = trace_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let temp_path = trace_path.with_extension(format!("gz.{}.tmp", generate_unique_hex_id()));
    let open_res = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(RUNTIME_SCAN_TRACE_FILE_MODE);
        }
        opts.open(&temp_path)
    };
    let file = open_res.map_err(|e| e.to_string())?;
    let mut gz = GzipStoredWriter::new(file).map_err(|e| e.to_string())?;
    let mut total_bytes = 0usize;
    let mut read_err: Option<String> = None;

    loop {
        let res = match client.call("IO.read", json!({ "handle": stream_handle }), None) {
            Ok(r) => r,
            Err(e) => {
                read_err = Some(e);
                break;
            }
        };
        let data_str = res
            .get("data")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let is_base64 = res
            .get("base64Encoded")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let bytes = if is_base64 {
            match decode_base64(data_str) {
                Ok(b) => b,
                Err(e) => {
                    read_err = Some(e);
                    break;
                }
            }
        } else {
            data_str.as_bytes().to_vec()
        };
        total_bytes += bytes.len();
        if total_bytes > RUNTIME_SCAN_MAX_TRACE_BYTES {
            read_err = Some(
                "The DevTools trace exceeded the 512 MB safety limit. Record a shorter, focused interaction and retry."
                    .to_string(),
            );
            break;
        }
        if let Err(e) = gz.write_chunk(&bytes) {
            read_err = Some(e.to_string());
            break;
        }
        if res
            .get("eof")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            break;
        }
    }

    let _ = client.call("IO.close", json!({ "handle": stream_handle }), None);

    if let Some(err) = read_err {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }

    if let Err(e) = gz.finish() {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e.to_string());
    }
    if let Err(e) = std::fs::rename(&temp_path, trace_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e.to_string());
    }
    Ok(())
}

fn collect_preexisting_page_targets(targets_res: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut page_ids = Vec::new();
    let mut page_urls = Vec::new();
    let Some(infos) = targets_res
        .get("targetInfos")
        .and_then(serde_json::Value::as_array)
    else {
        return (page_ids, page_urls);
    };
    for info in infos {
        if info.get("type").and_then(serde_json::Value::as_str) != Some("page") {
            continue;
        }
        if let Some(u) = info.get("url").and_then(serde_json::Value::as_str) {
            page_urls.push(u.to_string());
        }
        if let Some(tid) = info.get("targetId").and_then(serde_json::Value::as_str) {
            page_ids.push(tid.to_string());
        }
    }
    (page_ids, page_urls)
}

/// Connects to Chrome over CDP WebSocket, injects the runtime probe and visual overlay,
/// records a performance trace to `.json.gz`, and returns the merged snapshot.
///
/// # Errors
/// Returns an actionable error message if browser connection, navigation, or trace recording fails.
pub fn record_runtime_trace(
    input: &RecordRuntimeTraceInput,
) -> Result<RecordRuntimeTraceResult, String> {
    let sanitized_requested_url = sanitize_runtime_url(&input.url)?;
    let captured_at = current_iso_timestamp();
    let trace_path_buf = resolve_runtime_trace_path(
        input.trace_out.as_deref().and_then(|p| p.to_str()),
        &captured_at,
    );
    let trace_path = trace_path_buf.to_string_lossy().to_string();

    let snapshot_id = generate_unique_hex_id().replace('-', "");
    let snapshot_binding_name = format!("__DOTORE_RUNTIME_SCAN_CAPTURE__{snapshot_id}");
    let snapshot_attribute_name = format!("data-dotore-runtime-scan-snapshot-{snapshot_id}");
    let snapshot_relay_world_name = format!("dotore-runtime-scan-{snapshot_id}");
    let snapshot_token = generate_unique_hex_id();

    let probe_source = build_browser_probe_source(&snapshot_attribute_name, &snapshot_token);
    let relay_source =
        build_snapshot_relay_source(&snapshot_attribute_name, &snapshot_binding_name);

    let mut child_guard: Option<(std::process::Child, PathBuf)> = None;
    let (ws_url, connection) = if let Some(cdp_url) = &input.cdp_url {
        let resolved = resolve_cdp_ws_url(cdp_url).map_err(|_| {
            "Could not connect to Chrome. Confirm the browser is running with remote debugging and that the CDP URL is reachable."
                .to_string()
        })?;
        (resolved, RuntimeScanConnection::Cdp)
    } else {
        let (child, profile_dir, url) = launch_isolated_chrome()?;
        child_guard = Some((child, profile_dir));
        (url, RuntimeScanConnection::Isolated)
    };

    let run_result = (|| -> Result<RecordRuntimeTraceResult, String> {
        let mut client = CdpWebSocketClient::connect(&ws_url).map_err(|_| {
            let guidance = if input.cdp_url.is_some() {
                "Confirm the browser is running with remote debugging and that the CDP URL is reachable."
            } else {
                "Install Google Chrome, or pass --cdp <url> for a browser started with remote debugging."
            };
            format!("Could not connect to Chrome. {guidance}")
        })?;

        let targets_res = client.call("Target.getTargets", json!({}), None)?;
        let (preexisting_page_ids, preexisting_page_urls) =
            collect_preexisting_page_targets(&targets_res);

        if connection == RuntimeScanConnection::Cdp {
            let url_refs: Vec<&str> = preexisting_page_urls.iter().map(String::as_str).collect();
            assert_cdp_profile_uncontaminated(&url_refs)?;
        }

        let create_res = client.call(
            "Target.createTarget",
            json!({
                "url": "about:blank",
                "width": 1440,
                "height": 900,
            }),
            None,
        )?;
        let target_id = create_res
            .get("targetId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "Chrome did not return a targetId.".to_string())?
            .to_string();

        if connection == RuntimeScanConnection::Cdp {
            for old_id in &preexisting_page_ids {
                if old_id != &target_id {
                    let _ = client.call("Target.closeTarget", json!({ "targetId": old_id }), None);
                }
            }
        }

        let attach_res = client.call(
            "Target.attachToTarget",
            json!({
                "targetId": target_id,
                "flatten": true,
            }),
            None,
        )?;
        let session_id = attach_res
            .get("sessionId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "Chrome did not return a sessionId.".to_string())?
            .to_string();

        client.call("Page.enable", json!({}), Some(&session_id))?;
        client.call("Runtime.enable", json!({}), Some(&session_id))?;
        client.call(
            "Runtime.addBinding",
            json!({
                "name": snapshot_binding_name,
                "executionContextName": snapshot_relay_world_name,
            }),
            Some(&session_id),
        )?;
        client.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": probe_source }),
            Some(&session_id),
        )?;
        client.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({
                "source": relay_source,
                "worldName": snapshot_relay_world_name,
            }),
            Some(&session_id),
        )?;

        if let Err(err) = client.call(
            "Tracing.start",
            json!({
                "categories": RUNTIME_SCAN_TRACE_CATEGORIES.join(","),
                "transferMode": "ReturnAsStream",
            }),
            None,
        ) {
            let lower = err.to_ascii_lowercase();
            if lower.contains("tracing") && lower.contains("already") && lower.contains("started") {
                let _ = client.call("Target.closeTarget", json!({ "targetId": target_id }), None);
                return Err(
                    "Chrome is already recording a performance trace. Stop the existing DevTools recording and retry."
                        .to_string(),
                );
            }
            let _ = client.call("Target.closeTarget", json!({ "targetId": target_id }), None);
            return Err(err);
        }

        let start_instant = std::time::Instant::now();
        let nav_res = client.call(
            "Page.navigate",
            json!({ "url": input.url }),
            Some(&session_id),
        );
        if nav_res.is_err()
            || nav_res.as_ref().is_ok_and(|v| {
                v.get("errorText")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
            })
        {
            let _ = client.call("Tracing.end", json!({}), None);
            let _ = client.call("Target.closeTarget", json!({ "targetId": target_id }), None);
            return Err(
                "Could not load the target URL. Confirm the app is running and reachable from Chrome."
                    .to_string(),
            );
        }
        let _ = client.wait_for_event("Page.loadEventFired", 10_000);

        let mut collected_snapshots: Vec<RuntimeScanProbeSnapshot> = Vec::new();
        let mut discarded = DroppedEvidence::default();
        client.drain_binding_events(
            &snapshot_binding_name,
            &snapshot_token,
            &mut collected_snapshots,
            &mut discarded,
        );

        let max_recording_ms = input
            .max_recording_duration_ms
            .unwrap_or(RUNTIME_SCAN_MAX_RECORDING_DURATION_MS);
        wait_for_stop_or_timeout(max_recording_ms);
        let duration_ms = start_instant.elapsed().as_secs_f64() * 1_000.0;

        if let Ok(eval_res) = client.call(
            "Runtime.evaluate",
            json!({
                "expression": "window.__DOTORE_RUNTIME_SCAN__ ? window.__DOTORE_RUNTIME_SCAN__.snapshot() : null",
                "returnByValue": true,
                "awaitPromise": false,
            }),
            Some(&session_id),
        ) {
            let val = &eval_res["result"]["value"];
            if is_runtime_scan_probe_snapshot(val)
                && let Ok(snap) = serde_json::from_value::<RuntimeScanProbeSnapshot>(val.clone())
            {
                store_navigation_snapshot(&mut collected_snapshots, &mut discarded, snap);
            }
        }
        client.drain_binding_events(
            &snapshot_binding_name,
            &snapshot_token,
            &mut collected_snapshots,
            &mut discarded,
        );

        client.call("Tracing.end", json!({}), None)?;
        let complete_event = client
            .wait_for_event(
                "Tracing.tracingComplete",
                RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS,
            )
            .map_err(|_| {
                "Chrome did not finalize the performance trace within 60 seconds. Record a shorter interaction and retry."
                    .to_string()
            })?;
        let stream_handle = complete_event["params"]["stream"]
            .as_str()
            .ok_or_else(|| "Chrome returned a trace without a data stream.".to_string())?
            .to_string();

        let trace_write_res =
            stream_trace_to_gzip_file(&mut client, &stream_handle, &trace_path_buf);
        let _ = client.call("Target.closeTarget", json!({ "targetId": target_id }), None);
        trace_write_res?;

        let mut merged_snapshot = if collected_snapshots.is_empty() {
            RuntimeScanProbeSnapshot {
                time_origin: 1_000.0,
                final_url: sanitized_requested_url,
                support: RuntimeScanProbeSupport {
                    react_detected: false,
                    react_version: None,
                    react_build_type: None,
                    native_react_tracks: false,
                    bippy_component_tracks: false,
                    loaf: false,
                },
                long_animation_frames: Vec::new(),
                component_events: Vec::new(),
                interactions: Vec::new(),
                cumulative_layout_shift: 0.0,
                largest_contentful_paint_ms: None,
                dropped_long_animation_frames: 0,
                dropped_script_timings: 0,
                dropped_component_events: 0,
                dropped_interactions: 0,
            }
        } else {
            merge_probe_snapshots(&collected_snapshots)?
        };

        merged_snapshot.dropped_long_animation_frames += discarded.dropped_long_animation_frames;
        merged_snapshot.dropped_script_timings += discarded.dropped_script_timings;
        merged_snapshot.dropped_component_events += discarded.dropped_component_events;
        merged_snapshot.dropped_interactions += discarded.dropped_interactions;

        Ok(RecordRuntimeTraceResult {
            trace_path,
            captured_at,
            duration_ms,
            snapshot: merged_snapshot,
            connection,
        })
    })();

    if let Some((mut child, profile_dir)) = child_guard {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&profile_dir);
    }

    run_result
}
