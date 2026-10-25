//! Snapshot validation, multi-navigation snapshot merging, React/LoAF/interaction hotspot
//! aggregation, URL/text sanitization, and [`RuntimeScanReport`] builder.

use std::collections::{HashMap, HashSet};

use super::{
    BuildRuntimeScanReportInput, ComponentEventSource, RUNTIME_SCAN_LAYOUT_THRASH_RATIO,
    RUNTIME_SCAN_MAX_COMPONENT_EVENTS, RUNTIME_SCAN_MAX_HOTSPOTS, RUNTIME_SCAN_MAX_INTERACTIONS,
    RUNTIME_SCAN_MAX_LOAF_ENTRIES, RUNTIME_SCAN_MAX_SCRIPTS_PER_LOAF,
    RUNTIME_SCAN_MAX_SNAPSHOT_BYTES, RUNTIME_SCAN_MAX_SNAPSHOT_PAYLOAD_BYTES,
    RUNTIME_SCAN_MAX_STRING_LENGTH, RUNTIME_SCAN_SCHEMA_VERSION,
    RUNTIME_SCAN_UNKNOWN_SOURCE_CHAR_POSITION, RuntimeScanComponentEvent,
    RuntimeScanComponentHotspot, RuntimeScanInteraction, RuntimeScanLongAnimationFrame,
    RuntimeScanProbeSnapshot, RuntimeScanProbeSupport, RuntimeScanReport, RuntimeScanScriptHotspot,
    RuntimeScanScriptTiming, RuntimeScanSummary,
};

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

pub(super) fn limit_string(value: &str) -> String {
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
            let code = u32::from(ch);
            !(code <= 0x1f || (0x7f..=0x9f).contains(&code))
        })
        .collect()
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

fn is_valid_probe_support(support: &serde_json::Map<String, serde_json::Value>) -> bool {
    let valid_build_type = support.get("reactBuildType").is_some_and(|v| {
        v.is_null()
            || v.as_str()
                .is_some_and(|s| s == "development" || s == "production")
    });
    let bool_keys = [
        "reactDetected",
        "nativeReactTracks",
        "bippyComponentTracks",
        "loaf",
    ];
    bool_keys
        .iter()
        .all(|k| support.get(*k).is_some_and(serde_json::Value::is_boolean))
        && support
            .get("reactVersion")
            .is_some_and(is_nullable_bounded_string)
        && valid_build_type
}

fn has_valid_dropped_counters(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    [
        "droppedLongAnimationFrames",
        "droppedScriptTimings",
        "droppedComponentEvents",
        "droppedInteractions",
    ]
    .iter()
    .all(|k| obj.get(*k).is_some_and(is_non_negative_safe_integer))
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
    if !is_valid_probe_support(support) {
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
        && has_valid_dropped_counters(obj);
    fields_ok
        && serde_json::to_string(value).is_ok_and(|s| s.len() <= RUNTIME_SCAN_MAX_SNAPSHOT_BYTES)
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

fn shift_loaf_frame(
    frame: &RuntimeScanLongAnimationFrame,
    offset: f64,
) -> RuntimeScanLongAnimationFrame {
    RuntimeScanLongAnimationFrame {
        start_time: frame.start_time + offset,
        duration_ms: frame.duration_ms,
        blocking_duration_ms: frame.blocking_duration_ms,
        render_start: shift_optional_timestamp(frame.render_start, offset),
        style_and_layout_start: shift_optional_timestamp(frame.style_and_layout_start, offset),
        first_ui_event_timestamp: shift_optional_timestamp(frame.first_ui_event_timestamp, offset),
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
                forced_style_and_layout_duration_ms: script.forced_style_and_layout_duration_ms,
                pause_duration_ms: script.pause_duration_ms,
            })
            .collect(),
    }
}

fn sort_and_cap_events<T>(items: &mut Vec<T>, limit: usize, start_time_of: fn(&T) -> f64) -> u64 {
    items.sort_by(|a, b| start_time_of(a).total_cmp(&start_time_of(b)));
    let overflow = items.len().saturating_sub(limit) as u64;
    if items.len() > limit {
        let drain_count = items.len() - limit;
        items.drain(0..drain_count);
    }
    overflow
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
    let mut snapshots: Vec<&RuntimeScanProbeSnapshot> =
        Vec::with_capacity(captured_snapshots.len());
    for snap in captured_snapshots {
        snapshots.retain(|existing| (existing.time_origin - snap.time_origin).abs() > f64::EPSILON);
        snapshots.push(snap);
    }
    let Some(&final_snapshot) = snapshots.last() else {
        return Err("At least one runtime scan probe snapshot is required.".to_string());
    };
    let time_origin = snapshots
        .iter()
        .map(|s| s.time_origin)
        .fold(f64::INFINITY, f64::min);

    let mut creation_order: Vec<&RuntimeScanProbeSnapshot> = snapshots.clone();
    creation_order.sort_by(|a, b| a.time_origin.total_cmp(&b.time_origin));

    let mut all_loafs: Vec<RuntimeScanLongAnimationFrame> = Vec::new();
    let mut all_components: Vec<RuntimeScanComponentEvent> = Vec::new();
    let mut all_interactions: Vec<RuntimeScanInteraction> = Vec::new();

    for &snap in &snapshots {
        let offset = snap.time_origin - time_origin;
        let doc_index = creation_order
            .iter()
            .position(|s| (s.time_origin - snap.time_origin).abs() <= f64::EPSILON)
            .unwrap_or(0) as u64;

        all_loafs.extend(
            snap.long_animation_frames
                .iter()
                .map(|frame| shift_loaf_frame(frame, offset)),
        );
        all_components.extend(
            snap.component_events
                .iter()
                .map(|comp| RuntimeScanComponentEvent {
                    name: comp.name.clone(),
                    start_time: comp.start_time + offset,
                    duration_ms: comp.duration_ms,
                    depth: comp.depth,
                    source: comp.source,
                }),
        );
        all_interactions.extend(snap.interactions.iter().map(|interaction| {
            RuntimeScanInteraction {
                name: interaction.name.clone(),
                start_time: interaction.start_time + offset,
                duration_ms: interaction.duration_ms,
                processing_start: interaction.processing_start + offset,
                processing_end: interaction.processing_end + offset,
                interaction_id: interaction.interaction_id,
                document_index: Some(doc_index),
                target_tag: interaction.target_tag.clone(),
            }
        }));
    }

    let overflow_loafs =
        sort_and_cap_events(&mut all_loafs, RUNTIME_SCAN_MAX_LOAF_ENTRIES, |f| {
            f.start_time
        });
    let overflow_components =
        sort_and_cap_events(&mut all_components, RUNTIME_SCAN_MAX_COMPONENT_EVENTS, |c| {
            c.start_time
        });
    let overflow_interactions =
        sort_and_cap_events(&mut all_interactions, RUNTIME_SCAN_MAX_INTERACTIONS, |i| {
            i.start_time
        });

    let latest_react = snapshots.iter().rev().find(|s| s.support.react_detected);
    let max_cls = snapshots
        .iter()
        .map(|s| s.cumulative_layout_shift)
        .fold(0.0_f64, f64::max);

    Ok(RuntimeScanProbeSnapshot {
        time_origin,
        final_url: final_snapshot.final_url.clone(),
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
    struct ScriptKey<'a> {
        source_url: &'a str,
        source_function_name: &'a str,
        source_char_position: i64,
        invoker: &'a str,
    }

    let mut order: Vec<ScriptKey<'_>> = Vec::new();
    let mut hotspots: HashMap<ScriptKey<'_>, RuntimeScanScriptHotspot> = HashMap::new();

    for frame in &snapshot.long_animation_frames {
        let mut keys_in_frame: HashSet<ScriptKey<'_>> = HashSet::new();
        for script in &frame.scripts {
            let key = ScriptKey {
                source_url: script.source_url.as_str(),
                source_function_name: script.source_function_name.as_str(),
                source_char_position: script.source_char_position,
                invoker: script.invoker.as_str(),
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
                order.push(ScriptKey {
                    source_url: script.source_url.as_str(),
                    source_function_name: script.source_function_name.as_str(),
                    source_char_position: script.source_char_position,
                    invoker: script.invoker.as_str(),
                });
                hotspots.insert(
                    ScriptKey {
                        source_url: script.source_url.as_str(),
                        source_function_name: script.source_function_name.as_str(),
                        source_char_position: script.source_char_position,
                        invoker: script.invoker.as_str(),
                    },
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
    let mut order: Vec<(ComponentEventSource, &str)> = Vec::new();
    let mut hotspots: HashMap<(ComponentEventSource, &str), RuntimeScanComponentHotspot> =
        HashMap::new();

    for event in &snapshot.component_events {
        let key = (event.source, event.name.as_str());
        if let Some(existing) = hotspots.get_mut(&key) {
            existing.render_count += 1;
            existing.total_duration_ms += event.duration_ms;
            existing.max_duration_ms = existing.max_duration_ms.max(event.duration_ms);
        } else {
            order.push(key);
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
