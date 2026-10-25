//! Integration tests for `dotore scan` (native Chrome CDP runtime profiler).

use dotore::{
    BuildRuntimeScanReportInput, ComponentEventSource, RUNTIME_SCAN_MAX_COMPONENT_EVENTS,
    RUNTIME_SCAN_MAX_LOAF_ENTRIES, RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES,
    RUNTIME_SCAN_MAX_STRING_LENGTH, RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS, ReactBuildType,
    RuntimeScanComponentEvent, RuntimeScanConnection, RuntimeScanFormat, RuntimeScanInteraction,
    RuntimeScanLongAnimationFrame, RuntimeScanProbeSnapshot, RuntimeScanProbeSupport,
    RuntimeScanScriptTiming, assert_cdp_profile_uncontaminated, build_runtime_scan_report,
    format_runtime_scan_report, is_runtime_scan_probe_snapshot, merge_probe_snapshots,
    parse_runtime_scan_snapshot_payload, resolve_runtime_scan_format, resolve_runtime_trace_path,
    sanitize_runtime_url,
};
use serde_json::json;

fn sample_snapshot() -> RuntimeScanProbeSnapshot {
    RuntimeScanProbeSnapshot {
        time_origin: 1_000.0,
        final_url: "https://example.com/dashboard?token=secret#private".to_string(),
        support: RuntimeScanProbeSupport {
            react_detected: true,
            react_version: Some("19.2.0".to_string()),
            react_build_type: Some(ReactBuildType::Development),
            native_react_tracks: true,
            bippy_component_tracks: false,
            loaf: true,
        },
        long_animation_frames: vec![RuntimeScanLongAnimationFrame {
            start_time: 100.0,
            duration_ms: 120.0,
            blocking_duration_ms: 70.0,
            render_start: 150.0,
            style_and_layout_start: 180.0,
            first_ui_event_timestamp: 90.0,
            scripts: vec![RuntimeScanScriptTiming {
                invoker: "BUTTON#save.onclick".to_string(),
                invoker_type: "event-listener".to_string(),
                source_url: "https://example.com/assets/app.js".to_string(),
                source_function_name: "save".to_string(),
                source_char_position: 42,
                execution_start: 110.0,
                duration_ms: 80.0,
                forced_style_and_layout_duration_ms: 30.0,
                pause_duration_ms: 0.0,
            }],
        }],
        component_events: vec![
            RuntimeScanComponentEvent {
                name: "SaveButton".to_string(),
                start_time: 115.0,
                duration_ms: 40.0,
                depth: 2,
                source: ComponentEventSource::Native,
            },
            RuntimeScanComponentEvent {
                name: "SaveButton".to_string(),
                start_time: 160.0,
                duration_ms: 20.0,
                depth: 2,
                source: ComponentEventSource::Native,
            },
        ],
        interactions: vec![RuntimeScanInteraction {
            name: "click".to_string(),
            start_time: 90.0,
            duration_ms: 130.0,
            processing_start: 100.0,
            processing_end: 180.0,
            interaction_id: 1,
            document_index: None,
            target_tag: Some("BUTTON".to_string()),
        }],
        cumulative_layout_shift: 0.02,
        largest_contentful_paint_ms: Some(800.0),
        dropped_long_animation_frames: 0,
        dropped_script_timings: 0,
        dropped_component_events: 0,
        dropped_interactions: 0,
    }
}

fn build_test_report(
    probe_snapshot: RuntimeScanProbeSnapshot,
) -> Result<dotore::RuntimeScanReport, String> {
    build_runtime_scan_report(&BuildRuntimeScanReportInput {
        requested_url: "https://user:password@example.com/dashboard?token=secret#private"
            .to_string(),
        trace_path: "/tmp/runtime.json.gz".to_string(),
        captured_at: "2026-08-15T00:00:00.000Z".to_string(),
        duration_ms: 5_000.0,
        snapshot: probe_snapshot,
        connection: RuntimeScanConnection::Isolated,
    })
}

#[test]
fn aggregates_script_and_component_hotspots() {
    let report = build_test_report(sample_snapshot()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.summary.worst_frame_duration_ms, 120.0);
    assert_eq!(report.summary.total_blocking_duration_ms, 70.0);
    assert_eq!(report.time_origin, 1_000.0);
    assert_eq!(report.script_hotspots.len(), 1);
    assert_eq!(report.script_hotspots[0].function_name, "save");
    assert_eq!(report.script_hotspots[0].source_char_position, 42);
    assert_eq!(report.script_hotspots[0].total_duration_ms, 80.0);
    assert_eq!(
        report.script_hotspots[0].forced_style_and_layout_duration_ms,
        30.0
    );
    assert_eq!(report.component_hotspots.len(), 1);
    assert_eq!(report.component_hotspots[0].name, "SaveButton");
    assert_eq!(report.component_hotspots[0].render_count, 2);
    assert_eq!(report.component_hotspots[0].total_duration_ms, 60.0);
    assert_eq!(report.component_hotspots[0].max_duration_ms, 40.0);
}

#[test]
fn removes_credentials_query_strings_and_fragments_from_report_urls() {
    let report = build_test_report(sample_snapshot()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.requested_url, "https://example.com/dashboard");
    assert_eq!(report.final_url, "https://example.com/dashboard");
    let serialized = serde_json::to_string(&report).unwrap_or_else(|e| panic!("{e}"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("password"));
}

#[test]
fn groups_browser_events_that_belong_to_one_interaction() {
    let mut snap = sample_snapshot();
    snap.interactions = vec![
        RuntimeScanInteraction {
            name: "pointerdown".to_string(),
            start_time: 90.0,
            duration_ms: 130.0,
            processing_start: 100.0,
            processing_end: 110.0,
            interaction_id: 1,
            document_index: None,
            target_tag: Some("BUTTON".to_string()),
        },
        RuntimeScanInteraction {
            name: "pointerup".to_string(),
            start_time: 91.0,
            duration_ms: 130.0,
            processing_start: 111.0,
            processing_end: 120.0,
            interaction_id: 1,
            document_index: None,
            target_tag: Some("BUTTON".to_string()),
        },
        RuntimeScanInteraction {
            name: "click".to_string(),
            start_time: 91.0,
            duration_ms: 130.0,
            processing_start: 121.0,
            processing_end: 180.0,
            interaction_id: 1,
            document_index: None,
            target_tag: Some("BUTTON".to_string()),
        },
    ];
    let report = build_test_report(snap).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.summary.interaction_count, 1);
    assert_eq!(
        report.interactions,
        vec![RuntimeScanInteraction {
            name: "click".to_string(),
            start_time: 90.0,
            duration_ms: 130.0,
            processing_start: 100.0,
            processing_end: 180.0,
            interaction_id: 1,
            document_index: None,
            target_tag: Some("BUTTON".to_string()),
        }]
    );
}

#[test]
fn keeps_script_hotspots_at_different_source_positions_separate_and_counts_distinct_frames() {
    let base = sample_snapshot();
    let mut second_frame = base.long_animation_frames[0].clone();
    second_frame.scripts[0].source_char_position = 84;
    let mut snap = base.clone();
    snap.long_animation_frames = vec![base.long_animation_frames[0].clone(), second_frame];
    let report = build_test_report(snap).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.script_hotspots.len(), 2);
    let positions: Vec<i64> = report
        .script_hotspots
        .iter()
        .map(|h| h.source_char_position)
        .collect();
    assert_eq!(positions, vec![42, 84]);

    // Repeated script in the same frame counts as 1 frame
    let repeated_script = base.long_animation_frames[0].scripts[0].clone();
    let mut repeated_snap = base.clone();
    repeated_snap.long_animation_frames[0].scripts = vec![repeated_script.clone(), repeated_script];
    let repeated_report = build_test_report(repeated_snap).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(repeated_report.script_hotspots[0].frame_count, 1);
}

#[test]
fn merges_probe_evidence_across_document_navigations_and_retains_latest_entries() {
    let base = sample_snapshot();
    let mut second_doc = base.clone();
    second_doc.time_origin = 2_000.0;
    second_doc.final_url = "https://example.com/settings".to_string();
    second_doc.long_animation_frames[0].start_time = 10.0;
    second_doc.component_events = vec![RuntimeScanComponentEvent {
        start_time: 20.0,
        ..base.component_events[0].clone()
    }];
    second_doc.interactions = vec![RuntimeScanInteraction {
        start_time: 30.0,
        interaction_id: 1,
        ..base.interactions[0].clone()
    }];

    let mut returned_first_doc = base.clone();
    returned_first_doc.final_url = "https://example.com/dashboard-returned".to_string();
    returned_first_doc
        .component_events
        .push(RuntimeScanComponentEvent {
            start_time: 200.0,
            ..base.component_events[0].clone()
        });

    let merged = merge_probe_snapshots(&[base.clone(), second_doc, returned_first_doc])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(merged.final_url, "https://example.com/dashboard-returned");
    assert!(
        merged
            .long_animation_frames
            .iter()
            .any(|f| (f.start_time - 1_010.0).abs() < f64::EPSILON)
    );
    assert_eq!(merged.component_events.len(), 4);
    assert!(
        merged
            .component_events
            .iter()
            .any(|c| (c.start_time - 1_020.0).abs() < f64::EPSILON)
    );
    let doc_indices: Vec<Option<u64>> = merged
        .interactions
        .iter()
        .map(|i| i.document_index)
        .collect();
    assert_eq!(doc_indices, vec![Some(0), Some(1)]);
    assert_eq!(merged.cumulative_layout_shift, 0.02);
    let report = build_test_report(merged).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.summary.interaction_count, 2);

    // Overflow retention check
    let mut many_frames_doc = base.clone();
    many_frames_doc.long_animation_frames = (0..RUNTIME_SCAN_MAX_LOAF_ENTRIES)
        .map(|idx| RuntimeScanLongAnimationFrame {
            start_time: idx as f64,
            ..base.long_animation_frames[0].clone()
        })
        .collect();
    let mut later_doc = base.clone();
    later_doc.time_origin = 2_000.0;
    later_doc.long_animation_frames = vec![RuntimeScanLongAnimationFrame {
        start_time: 100.0,
        ..base.long_animation_frames[0].clone()
    }];
    let merged_overflow =
        merge_probe_snapshots(&[many_frames_doc, later_doc]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        merged_overflow.long_animation_frames.len(),
        RUNTIME_SCAN_MAX_LOAF_ENTRIES
    );
    assert!(
        !merged_overflow
            .long_animation_frames
            .iter()
            .any(|f| f.start_time == 0.0)
    );
    assert_eq!(
        merged_overflow
            .long_animation_frames
            .last()
            .map(|f| f.start_time),
        Some(1_100.0)
    );
    assert_eq!(merged_overflow.dropped_long_animation_frames, 1);
}

#[test]
fn formats_text_json_and_jsonl_outputs_and_strips_control_characters() {
    let mut snap = sample_snapshot();
    snap.component_events[0].name = "Save\u{001B}]52;c;clipboard\u{0007}Button".to_string();
    let report = build_test_report(snap).unwrap_or_else(|e| panic!("{e}"));

    let text = format_runtime_scan_report(&report, RuntimeScanFormat::Text);
    assert!(text.contains("React component hotspots"));
    assert!(!text.contains("\u{001B}]52"));
    assert!(!text.contains('\u{0007}'));
    assert!(text.contains(
        "At least one long frame was substantially dominated by forced style and layout."
    ));

    let json_text = format_runtime_scan_report(&report, RuntimeScanFormat::Json);
    assert!(json_text.contains("\\u001b"));
    let parsed_json: serde_json::Value =
        serde_json::from_str(&json_text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed_json["schemaVersion"], 1);
    assert_eq!(parsed_json["kind"], "dotore-runtime-scan");

    let jsonl_text = format_runtime_scan_report(&report, RuntimeScanFormat::Jsonl);
    let records: Vec<serde_json::Value> = jsonl_text
        .trim()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    assert!(records.iter().any(|r| r["kind"] == "metadata"));
    assert!(records.iter().any(|r| r["kind"] == "summary"));
    assert!(records.iter().any(|r| r["kind"] == "script-hotspot"));
    assert!(records.iter().any(|r| r["kind"] == "component-hotspot"));
    assert!(records.iter().any(|r| r["kind"] == "long-animation-frame"));
    assert!(records.iter().any(|r| r["kind"] == "interaction"));
}

#[test]
fn validates_formats_urls_cdp_profiles_trace_paths_and_snapshot_payloads() {
    assert_eq!(RUNTIME_SCAN_TRACING_COMPLETE_TIMEOUT_MS, 60_000);
    assert_eq!(
        resolve_runtime_scan_format(None),
        Ok(RuntimeScanFormat::Text)
    );
    assert_eq!(
        resolve_runtime_scan_format(Some("jsonl")),
        Ok(RuntimeScanFormat::Jsonl)
    );
    assert!(
        resolve_runtime_scan_format(Some("xml"))
            .is_err_and(|msg| msg.contains("--format must be one of"))
    );
    assert!(
        sanitize_runtime_url("file:///tmp/index.html").is_err_and(|msg| msg.contains("http(s)"))
    );

    assert!(assert_cdp_profile_uncontaminated(&["about:blank", "chrome://newtab/"]).is_ok());
    assert!(
        assert_cdp_profile_uncontaminated(&["about:blank", "https://example.com/private"])
            .is_err_and(|msg| msg.contains("includes every open tab"))
    );

    let first_path = resolve_runtime_trace_path(None, "2026-08-15T00:00:00.000Z");
    let second_path = resolve_runtime_trace_path(None, "2026-08-15T00:00:00.000Z");
    assert_ne!(first_path, second_path);
    assert!(first_path.to_string_lossy().ends_with(".json.gz"));

    let token = "expected-token";
    let mut valid_snap = sample_snapshot();
    valid_snap.final_url = "https://example.com/dashboard".to_string();
    let valid_envelope = json!({
        "token": token,
        "snapshot": valid_snap,
    })
    .to_string();
    assert_eq!(
        parse_runtime_scan_snapshot_payload(&valid_envelope, token),
        Some(valid_snap.clone())
    );

    // Wrong token
    let wrong_token_envelope = json!({
        "token": "wrong-token",
        "snapshot": valid_snap,
    })
    .to_string();
    assert!(parse_runtime_scan_snapshot_payload(&wrong_token_envelope, token).is_none());

    // Negative droppedInteractions
    let mut invalid_val = serde_json::to_value(&valid_snap).unwrap_or_else(|e| panic!("{e}"));
    invalid_val["droppedInteractions"] = json!(-1);
    let invalid_envelope = json!({
        "token": token,
        "snapshot": invalid_val,
    })
    .to_string();
    assert!(parse_runtime_scan_snapshot_payload(&invalid_envelope, token).is_none());

    // Oversized payload
    let oversized = "x".repeat(RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES + 1);
    assert!(parse_runtime_scan_snapshot_payload(&oversized, token).is_none());

    // Source char position -1 is allowed
    let mut unknown_pos_snap = valid_snap.clone();
    unknown_pos_snap.long_animation_frames[0].scripts[0].source_char_position = -1;
    let unknown_pos_val = serde_json::to_value(&unknown_pos_snap).unwrap_or_else(|e| panic!("{e}"));
    assert!(is_runtime_scan_probe_snapshot(&unknown_pos_val));

    // Exceeding snapshot byte limit via max-length strings in 2000 component events
    let mut huge_snap = valid_snap;
    huge_snap.component_events = (0..RUNTIME_SCAN_MAX_COMPONENT_EVENTS)
        .map(|idx| {
            let prefix = idx.to_string();
            let pad = "x".repeat(RUNTIME_SCAN_MAX_STRING_LENGTH - prefix.len());
            RuntimeScanComponentEvent {
                name: format!("{prefix}{pad}"),
                start_time: idx as f64,
                duration_ms: 1.0,
                depth: 0,
                source: ComponentEventSource::Native,
            }
        })
        .collect();
    let huge_val = serde_json::to_value(&huge_snap).unwrap_or_else(|e| panic!("{e}"));
    assert!(!is_runtime_scan_probe_snapshot(&huge_val));
}

#[test]
fn detects_running_local_http_servers_and_prompts_for_url() {
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let active_port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();

    let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let dead_port = dead_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();
    drop(dead_listener);

    let server_thread = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });

    let suggestions = dotore::detect_local_runtime_urls(&[dead_port, active_port]);
    let _ = server_thread.join();

    assert_eq!(
        suggestions,
        vec![dotore::LocalUrlSuggestion {
            port: active_port,
            url: format!("http://localhost:{active_port}"),
        }]
    );

    // 1. Pressing Enter with detected suggestions selects the first suggestion
    let mut input = Cursor::new(b"\n".to_vec());
    let mut output = Vec::new();
    let chosen = dotore::prompt_runtime_scan_url_with_io(&suggestions, &mut input, &mut output)
        .unwrap_or_else(|e| panic!("{e}"));
    let rendered = String::from_utf8_lossy(&output);
    assert!(rendered.contains("Choose an app to scan"));
    assert!(rendered.contains(&format!("http://localhost:{active_port} detected")));
    assert!(rendered.contains("Enter another URL"));
    assert_eq!(chosen, Some(format!("http://localhost:{active_port}")));

    // 2. Invalid URL keeps prompting until valid http(s) URL is entered
    let mut input2 =
        Cursor::new(b"localhost:3000\nhttp://localhost:3000/dashboard?view=slow\n".to_vec());
    let mut output2 = Vec::new();
    let chosen2 = dotore::prompt_runtime_scan_url_with_io(&[], &mut input2, &mut output2)
        .unwrap_or_else(|e| panic!("{e}"));
    let rendered2 = String::from_utf8_lossy(&output2);
    assert!(rendered2.contains("Enter an absolute URL starting with http:// or https://."));
    assert_eq!(
        chosen2,
        Some("http://localhost:3000/dashboard?view=slow".to_string())
    );

    // 3. Escape cancels and returns None
    let mut input3 = Cursor::new(b"\x1b\n".to_vec());
    let mut output3 = Vec::new();
    let chosen3 = dotore::prompt_runtime_scan_url_with_io(&[], &mut input3, &mut output3)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(chosen3, None);
}

/// Minimal server-side RFC 6455 WebSocket helper for testing `dotore scan` CDP interactions.
#[cfg(test)]
mod mock_cdp {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    pub fn read_http_request(stream: &mut TcpStream) -> Option<(String, String)> {
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).ok()? == 0 {
            return None;
        }
        let mut ws_key = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("sec-websocket-key")
            {
                ws_key = v.trim().to_string();
            }
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();
        Some((path, ws_key))
    }

    pub fn send_ws_upgrade_response(stream: &mut TcpStream) {
        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    pub fn read_ws_frame(stream: &mut TcpStream) -> Option<String> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).ok()?;
        let opcode = header[0] & 0x0f;
        if opcode == 0x8 {
            return None;
        }
        let masked = (header[1] & 0x80) != 0;
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).ok()?;
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).ok()?;
            len = usize::try_from(u64::from_be_bytes(ext)).ok()?;
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask).ok()?;
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).ok()?;
        if masked {
            for (idx, b) in payload.iter_mut().enumerate() {
                *b ^= mask[idx % 4];
            }
        }
        String::from_utf8(payload).ok()
    }

    pub fn write_ws_frame(stream: &mut TcpStream, text: &str) {
        let bytes = text.as_bytes();
        let mut frame = Vec::with_capacity(bytes.len() + 10);
        frame.push(0x81);
        if bytes.len() <= 125 {
            frame.push(bytes.len() as u8);
        } else if bytes.len() <= 65535 {
            frame.push(126);
            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(bytes);
        let _ = stream.write_all(&frame);
        let _ = stream.flush();
    }
}

#[derive(Default)]
struct MockCdpState {
    open_page_urls: Vec<String>,
    injected_scripts: Vec<String>,
    binding_name: String,
    relay_token: String,
    read_calls: usize,
}

fn extract_token_from_probe(source: &str) -> Option<String> {
    let idx = source.find("SNAPSHOT_TOKEN =")?;
    let after = &source[idx..];
    let first_quote = after.find('"')?;
    let rest = &after[first_quote + 1..];
    let second_quote = rest.find('"')?;
    Some(rest[..second_quote].to_string())
}

fn send_cdp_reply(
    stream: &mut std::net::TcpStream,
    id: u64,
    session_id: Option<&str>,
    result: serde_json::Value,
) {
    let mut obj = serde_json::json!({
        "id": id,
        "result": result,
    });
    if let Some(sid) = session_id {
        obj["sessionId"] = serde_json::Value::String(sid.to_string());
    }
    mock_cdp::write_ws_frame(stream, &obj.to_string());
}

fn handle_mock_cdp_command(
    stream: &mut std::net::TcpStream,
    state: &mut MockCdpState,
    msg: &serde_json::Value,
) -> bool {
    let id = msg["id"].as_u64().unwrap_or(0);
    let method = msg["method"].as_str().unwrap_or("");
    let session_id = msg["sessionId"].as_str();

    match method {
        "Target.getTargets" => {
            let infos: Vec<serde_json::Value> = state
                .open_page_urls
                .iter()
                .enumerate()
                .map(|(idx, u)| {
                    serde_json::json!({
                        "targetId": format!("preexisting-{idx}"),
                        "type": "page",
                        "title": "Tab",
                        "url": u,
                        "attached": false
                    })
                })
                .collect();
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "targetInfos": infos }),
            );
            !state
                .open_page_urls
                .iter()
                .any(|u| !dotore::RUNTIME_SCAN_SAFE_CDP_PAGE_URLS.contains(&u.as_str()))
        }
        "Target.createTarget" => {
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "targetId": "scan-page-1" }),
            );
            true
        }
        "Target.closeTarget" => {
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "success": true }),
            );
            msg["params"]["targetId"].as_str() != Some("scan-page-1")
        }
        "Target.attachToTarget" => {
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "sessionId": "session-1" }),
            );
            true
        }
        "Runtime.addBinding" => {
            if let Some(name) = msg["params"]["name"].as_str() {
                state.binding_name = name.to_string();
            }
            send_cdp_reply(stream, id, session_id, serde_json::json!({}));
            true
        }
        "Page.addScriptToEvaluateOnNewDocument" => {
            if let Some(source) = msg["params"]["source"].as_str() {
                state.injected_scripts.push(source.to_string());
                if let Some(tok) = extract_token_from_probe(source) {
                    state.relay_token = tok;
                }
            }
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "identifier": "script-1" }),
            );
            true
        }
        "Page.navigate" => {
            if !state.binding_name.is_empty() && !state.relay_token.is_empty() {
                let mut nav_snap = sample_snapshot();
                nav_snap.time_origin = 1_000.0;
                nav_snap.final_url = "https://example.com/landing".to_string();
                let payload = serde_json::json!({
                    "token": state.relay_token,
                    "snapshot": nav_snap,
                })
                .to_string();
                let binding_event = serde_json::json!({
                    "method": "Runtime.bindingCalled",
                    "params": {
                        "name": state.binding_name,
                        "payload": payload,
                    },
                    "sessionId": "session-1"
                });
                mock_cdp::write_ws_frame(stream, &binding_event.to_string());
            }
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({ "frameId": "frame-1" }),
            );
            let load_event = serde_json::json!({
                "method": "Page.loadEventFired",
                "params": { "timestamp": 1.0 },
                "sessionId": "session-1"
            });
            mock_cdp::write_ws_frame(stream, &load_event.to_string());
            true
        }
        "Runtime.evaluate" => {
            let mut final_snap = sample_snapshot();
            final_snap.time_origin = 2_000.0;
            final_snap.final_url = "https://example.com/dashboard".to_string();
            send_cdp_reply(
                stream,
                id,
                session_id,
                serde_json::json!({
                    "result": {
                        "type": "object",
                        "value": final_snap,
                    }
                }),
            );
            true
        }
        "Tracing.end" => {
            send_cdp_reply(stream, id, session_id, serde_json::json!({}));
            let complete_event = serde_json::json!({
                "method": "Tracing.tracingComplete",
                "params": {
                    "dataLossOccurred": false,
                    "stream": "trace-stream-1"
                }
            });
            mock_cdp::write_ws_frame(stream, &complete_event.to_string());
            true
        }
        "IO.read" => {
            state.read_calls += 1;
            let chunk_res = if state.read_calls == 1 {
                serde_json::json!({
                    "base64Encoded": false,
                    "data": "{\"traceEvents\":[{\"name\":\"RunTask\"}",
                    "eof": false
                })
            } else {
                serde_json::json!({
                    "base64Encoded": true,
                    "data": "XX0=",
                    "eof": true
                })
            };
            send_cdp_reply(stream, id, session_id, chunk_res);
            true
        }
        _ => {
            send_cdp_reply(stream, id, session_id, serde_json::json!({}));
            true
        }
    }
}

#[cfg(test)]
fn spawn_mock_cdp_server(
    open_page_urls: Vec<String>,
) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();

    let handle = std::thread::spawn(move || {
        let mut state = MockCdpState {
            open_page_urls,
            ..MockCdpState::default()
        };

        while let Ok((mut stream, _)) = listener.accept() {
            let Some((path, ws_key)) = mock_cdp::read_http_request(&mut stream) else {
                continue;
            };
            if ws_key.is_empty() && path.starts_with("/json/version") {
                let body = serde_json::json!({
                    "Browser": "Chrome/130.0.0.0",
                    "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/mock-1")
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                continue;
            }

            mock_cdp::send_ws_upgrade_response(&mut stream);
            while let Some(msg_text) = mock_cdp::read_ws_frame(&mut stream) {
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&msg_text)
                    && !handle_mock_cdp_command(&mut stream, &mut state, &msg)
                {
                    break;
                }
            }
            break;
        }
        state.injected_scripts
    });

    (port, handle)
}

#[test]
fn records_cdp_runtime_trace_merges_snapshots_and_streams_gzip_trace() {
    use std::process::Command;

    let (port, server_handle) = spawn_mock_cdp_server(vec!["about:blank".to_string()]);
    let temp_dir = std::env::temp_dir().join(format!("dotore-test-trace-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let trace_out = temp_dir.join("captured-trace.json.gz");

    let result = dotore::record_runtime_trace(&dotore::RecordRuntimeTraceInput {
        url: "https://example.com/dashboard?secret=1".to_string(),
        trace_out: Some(trace_out.clone()),
        cdp_url: Some(format!("http://127.0.0.1:{port}")),
        max_recording_duration_ms: Some(10),
    })
    .unwrap_or_else(|e| panic!("record_runtime_trace failed: {e}"));

    let injected_scripts = server_handle
        .join()
        .unwrap_or_else(|_| panic!("server panicked"));
    assert!(
        injected_scripts
            .iter()
            .any(|s| s.contains("__DOTORE_RUNTIME_SCAN__") && s.contains("115,97,230")),
        "expected embedded runtime probe and purple overlay script to be injected via Page.addScriptToEvaluateOnNewDocument"
    );

    assert_eq!(result.connection, RuntimeScanConnection::Cdp);
    assert_eq!(result.trace_path, trace_out.to_string_lossy());
    assert_eq!(result.snapshot.final_url, "https://example.com/dashboard");
    assert_eq!(result.snapshot.long_animation_frames.len(), 2);
    assert_eq!(result.snapshot.component_events.len(), 4);
    assert_eq!(result.snapshot.interactions.len(), 2);

    let metadata = std::fs::metadata(&trace_out).unwrap_or_else(|e| panic!("{e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    let raw_gz = std::fs::read(&trace_out).unwrap_or_else(|e| panic!("{e}"));
    assert!(raw_gz.starts_with(&[0x1f, 0x8b, 0x08]));

    let gunzip_out = Command::new("gzip")
        .arg("-dc")
        .arg(&trace_out)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gzip -dc: {e}"));
    assert!(gunzip_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&gunzip_out.stdout),
        "{\"traceEvents\":[{\"name\":\"RunTask\"}]}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn rejects_contaminated_cdp_profile_with_open_non_blank_tabs() {
    let (port, server_handle) = spawn_mock_cdp_server(vec![
        "about:blank".to_string(),
        "https://example.com/already-open".to_string(),
    ]);

    let err = dotore::record_runtime_trace(&dotore::RecordRuntimeTraceInput {
        url: "https://example.com/dashboard".to_string(),
        trace_out: None,
        cdp_url: Some(format!("ws://127.0.0.1:{port}/devtools/browser/mock-1")),
        max_recording_duration_ms: Some(10),
    })
    .expect_err("expected contaminated CDP profile to be rejected");

    let _ = server_handle.join();
    assert!(err.contains("includes every open tab"));
}

#[test]
fn cli_dotore_scan_end_to_end_json_and_non_interactive_error() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_dotore");

    // 1. Omitting URL outside an interactive terminal produces structured error in --format json
    let no_url_out = Command::new(bin)
        .args(["scan", "--format", "json"])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!no_url_out.status.success());
    let err_json: serde_json::Value =
        serde_json::from_slice(&no_url_out.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(err_json["kind"], "dotore-runtime-scan-error");
    assert!(
        err_json["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("A URL is required outside an interactive terminal"))
    );

    // 2. Running `dotore scan <url> --cdp <ws> --trace-out <path> --format json`
    let (port, server_handle) = spawn_mock_cdp_server(vec!["about:blank".to_string()]);
    let temp_dir =
        std::env::temp_dir().join(format!("dotore-cli-scan-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let trace_out = temp_dir.join("cli-trace.json.gz");

    let mut child = Command::new(bin)
        .args([
            "scan",
            "https://example.com/dashboard?token=secret",
            "--cdp",
            &format!("ws://127.0.0.1:{port}/devtools/browser/mock-1"),
            "--trace-out",
            &trace_out.to_string_lossy(),
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{e}"));

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    let output = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let _ = server_handle.join();

    assert!(
        output.status.success(),
        "dotore scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report_json["kind"], "dotore-runtime-scan");
    assert_eq!(report_json["requestedUrl"], "https://example.com/dashboard");
    assert_eq!(report_json["connection"], "cdp");
    assert_eq!(report_json["summary"]["longAnimationFrameCount"], 2);
    assert!(trace_out.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);

    // 3. Interactive CLI URL detection when URL is omitted (`DOTORE_FORCE_INTERACTIVE=1`)
    use std::io::Read;
    use std::net::TcpListener;

    let local_app_listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let local_app_port = local_app_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();
    let app_thread = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = local_app_listener.accept() {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });

    let (cdp_port, cdp_handle) = spawn_mock_cdp_server(vec!["about:blank".to_string()]);
    let temp_dir2 =
        std::env::temp_dir().join(format!("dotore-cli-interactive-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir2);
    let trace_out2 = temp_dir2.join("interactive-trace.json.gz");
    let fake_chrome = temp_dir2.join("fake-chrome.sh");
    std::fs::write(
        &fake_chrome,
        format!(
            "#!/bin/sh\necho \"DevTools listening on ws://127.0.0.1:{cdp_port}/devtools/browser/isolated\" >&2\nsleep 5\n"
        ),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&fake_chrome)
            .unwrap_or_else(|e| panic!("{e}"))
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_chrome, perms).unwrap_or_else(|e| panic!("{e}"));
    }

    let mut child2 = Command::new(bin)
        .args([
            "scan",
            "--trace-out",
            &trace_out2.to_string_lossy(),
            "--format",
            "jsonl",
        ])
        .env("DOTORE_FORCE_INTERACTIVE", "1")
        .env("DOTORE_SCAN_PORTS", local_app_port.to_string())
        .env("DOTORE_CHROME_PATH", &fake_chrome)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{e}"));

    // First newline selects detected localhost server; second newline stops trace recording
    if let Some(mut stdin) = child2.stdin.take() {
        let _ = stdin.write_all(b"\n\n");
    }
    let output2 = child2.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let _ = app_thread.join();
    let _ = cdp_handle.join();

    assert!(
        output2.status.success(),
        "interactive dotore scan failed: stderr={}",
        String::from_utf8_lossy(&output2.stderr)
    );
    let stderr_str = String::from_utf8_lossy(&output2.stderr);
    assert!(stderr_str.contains(&format!("http://localhost:{local_app_port} detected")));
    let stdout_str = String::from_utf8_lossy(&output2.stdout);
    let first_line: serde_json::Value = serde_json::from_str(
        stdout_str
            .lines()
            .next()
            .unwrap_or_else(|| panic!("empty jsonl output")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(first_line["kind"], "metadata");
    assert_eq!(
        first_line["data"]["requestedUrl"],
        format!("http://localhost:{local_app_port}")
    );
    assert_eq!(first_line["data"]["connection"], "isolated");
    assert!(trace_out2.exists());

    let _ = std::fs::remove_dir_all(&temp_dir2);
}
