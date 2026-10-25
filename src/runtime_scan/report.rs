//! Terminal, JSON, and JSONL report formatters for [`RuntimeScanReport`].

use serde_json::json;

use super::{
    RUNTIME_SCAN_SCHEMA_VERSION, ReactBuildType, RuntimeScanConnection, RuntimeScanFormat,
    RuntimeScanJsonlRecord, RuntimeScanReport, analysis::sanitize_runtime_text,
};

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

fn format_ms(duration_ms: f64) -> String {
    format!("{duration_ms:.1}ms")
}

fn format_react_support_label(report: &RuntimeScanReport) -> String {
    if !report.support.react_detected {
        return "not detected".to_string();
    }
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
}

fn append_script_hotspots_section(lines: &mut Vec<String>, report: &RuntimeScanReport) {
    if report.script_hotspots.is_empty() {
        return;
    }
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
        let location = match (source_location.is_empty(), fn_name.is_empty()) {
            (true, _) => fn_name,
            (false, true) => source_location,
            (false, false) => format!("{source_location} · {fn_name}"),
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

fn append_component_hotspots_section(lines: &mut Vec<String>, report: &RuntimeScanReport) {
    if report.component_hotspots.is_empty() {
        return;
    }
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

fn format_text_report(report: &RuntimeScanReport) -> String {
    let connection_str = match report.connection {
        RuntimeScanConnection::Cdp => "attached over CDP",
        RuntimeScanConnection::Isolated => "isolated profile",
    };
    let react_str = format_react_support_label(report);
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
    let lcp_str = report
        .summary
        .largest_contentful_paint_ms
        .map_or_else(|| "unavailable".to_string(), format_ms);

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

    append_script_hotspots_section(&mut lines, report);
    append_component_hotspots_section(&mut lines, report);

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
    let mut records: Vec<RuntimeScanJsonlRecord> = Vec::with_capacity(
        2 + report.script_hotspots.len()
            + report.component_hotspots.len()
            + report.long_animation_frames.len()
            + report.interactions.len(),
    );
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
