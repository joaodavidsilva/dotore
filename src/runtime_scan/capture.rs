//! Chrome browser discovery, isolated process launcher, CDP target selection, and live trace
//! session capture.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::json;

use super::{
    RUNTIME_SCAN_MAX_DOCUMENT_SNAPSHOTS, RUNTIME_SCAN_MAX_RECORDING_DURATION_MS,
    RUNTIME_SCAN_MAX_TRACE_BYTES, RUNTIME_SCAN_SAFE_CDP_PAGE_URLS, RUNTIME_SCAN_TRACE_CATEGORIES,
    RUNTIME_SCAN_TRACE_FILE_MODE, RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS,
    RecordRuntimeTraceInput, RecordRuntimeTraceResult, RuntimeScanConnection,
    RuntimeScanProbeSnapshot, RuntimeScanProbeSupport,
    analysis::{is_runtime_scan_probe_snapshot, merge_probe_snapshots, sanitize_runtime_url},
    probe::{build_browser_probe_source, build_snapshot_relay_source},
    transport::{CdpWebSocketClient, GzipStoredWriter, decode_base64, resolve_cdp_ws_url},
};

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

#[derive(Default)]
pub(super) struct DroppedEvidence {
    pub(super) dropped_long_animation_frames: u64,
    pub(super) dropped_script_timings: u64,
    pub(super) dropped_component_events: u64,
    pub(super) dropped_interactions: u64,
}

pub(super) fn store_navigation_snapshot(
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
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let secs_of_day = total_secs % 86_400;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant algorithm)
    let z = (total_secs / 86_400) + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
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

        client.drain_binding_events(
            &snapshot_binding_name,
            &snapshot_token,
            &mut collected_snapshots,
            &mut discarded,
        );
        if let Ok(eval_res) = client.call(
            "Runtime.evaluate",
            json!({
                "expression": "window.__DOTORE_RUNTIME_SCAN__ ? window.__DOTORE_RUNTIME_SCAN__.snapshot() : null",
                "returnByValue": true,
                "awaitPromise": false,
            }),
            Some(&session_id),
        ) {
            client.drain_binding_events(
                &snapshot_binding_name,
                &snapshot_token,
                &mut collected_snapshots,
                &mut discarded,
            );
            let val = &eval_res["result"]["value"];
            if is_runtime_scan_probe_snapshot(val)
                && let Ok(snap) = serde_json::from_value::<RuntimeScanProbeSnapshot>(val.clone())
            {
                store_navigation_snapshot(&mut collected_snapshots, &mut discarded, snap);
            }
        }

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
