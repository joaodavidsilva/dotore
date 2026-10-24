//! Security and `security-scan` rule detectors, including cross-file HTML sanitizer
//! and KaTeX provenance (`dangerous-html-sink`) and `window.open` target/rel/destination
//! propagation (`window-open-without-noopener`).

mod artifacts_and_runtime;
mod dom_and_client;
mod injection_and_baas;

use crate::{
    graph::ProjectGraph,
    ir::{ByteSpan, FileIr, SourceLoc, types::compute_line_starts},
    matchers::{make_diag_for_subject, offset_to_loc},
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

use dom_and_client::{
    check_auth_token_in_web_storage, check_dangerous_html_sink, check_iframe_missing_sandbox,
    check_no_danger_with_children, check_no_eval, check_no_path_prefix_containment,
    check_no_secrets_in_client_code, check_public_env_secret_name,
    check_react_markdown_unsanitized_raw_html, check_react_router_csp_nonce_consistency,
    check_unsafe_json_in_html, check_window_open_without_noopener,
};
use injection_and_baas::evaluate_security_scan_patterns;

#[cfg(test)]
use dom_and_client::find_suspicious_public_env_in_line;

/// Evaluates all `security` and `security-scan` rules on `file` using `graph` for cross-file resolution.
pub(crate) fn evaluate_security_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let line_starts = compute_line_starts(&file.source);
    let path_str = file.path.to_string_lossy().replace('\\', "/");

    if is_active(RuleId::DangerousHtmlSink).is_some() {
        check_dangerous_html_sink(graph, file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::WindowOpenWithoutNoopener).is_some() {
        check_window_open_without_noopener(graph, file, &line_starts, out);
    }
    if is_active(RuleId::UnsafeJsonInHtml).is_some() {
        check_unsafe_json_in_html(file, &line_starts, out);
    }
    if is_active(RuleId::NoSecretsInClientCode).is_some() {
        check_no_secrets_in_client_code(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::PublicEnvSecretName).is_some() {
        check_public_env_secret_name(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::AuthTokenInWebStorage).is_some() {
        check_auth_token_in_web_storage(file, &line_starts, out);
    }
    if is_active(RuleId::NoEval).is_some() {
        check_no_eval(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::NoPathPrefixContainment).is_some() {
        check_no_path_prefix_containment(file, &line_starts, out);
    }
    if is_active(RuleId::ReactMarkdownUnsanitizedRawHtml).is_some() {
        check_react_markdown_unsanitized_raw_html(file, &line_starts, out);
    }
    if is_active(RuleId::ReactRouterCspNonceConsistency).is_some() {
        check_react_router_csp_nonce_consistency(file, &line_starts, out);
    }
    if is_active(RuleId::NoDangerWithChildren).is_some() {
        check_no_danger_with_children(file, out);
    }
    if is_active(RuleId::IframeMissingSandbox).is_some() {
        check_iframe_missing_sandbox(file, out);
    }

    evaluate_security_scan_patterns(file, &path_str, &line_starts, is_active, out);
}

#[expect(
    clippy::too_many_arguments,
    reason = "Direct diagnostic constructor avoids intermediate allocations"
)]
fn push_sec_diag(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: &str,
    loc: SourceLoc,
    span: ByteSpan,
) {
    out.push(make_diag_for_subject(
        rule,
        file.path.clone(),
        None,
        message_id,
        target_name,
        message,
        loc,
        span,
    ));
}

#[expect(
    clippy::too_many_arguments,
    reason = "Direct line-level diagnostic emitter avoids intermediate struct"
)]
fn emit_line_diag(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: &str,
    line_idx: usize,
    line: &str,
    line_starts: &[u32],
) {
    let first_non_ws = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
    let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
    let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
    push_sec_diag(
        out,
        file,
        rule,
        message_id,
        target_name,
        message,
        offset_to_loc(line_starts, byte_start),
        ByteSpan {
            start: byte_start,
            end: byte_end,
        },
    );
}

pub(crate) fn resolve_imported_binding<'a>(
    graph: &'a ProjectGraph,
    file: &FileIr,
    local_name: &str,
) -> Option<(&'a FileIr, String)> {
    for imp in &file.module.imports {
        if imp.is_type_only {
            continue;
        }
        for b in &imp.bindings {
            if !b.is_type_only && b.local_name == local_name {
                let exported = if b.is_default {
                    "default"
                } else {
                    b.imported_name.as_str()
                };
                if let Some(resolved) =
                    graph.resolve_exported_symbol(&file.path, &imp.source, exported)
                {
                    return Some(resolved);
                }
            }
        }
    }
    None
}

fn find_binding_initializer_in_source(source: &str, name: &str) -> Option<String> {
    for kw in ["const ", "let ", "var "] {
        let pattern = format!("{kw}{name}");
        let mut search_from = 0;
        while let Some(rel) = source[search_from..].find(&pattern) {
            let hit = search_from + rel;
            let after_name = &source[hit + pattern.len()..];
            let next_char = after_name.chars().next();
            if next_char.is_none_or(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                search_from = hit + pattern.len();
                continue;
            }
            if let Some(eq_pos) = after_name.find('=')
                && !after_name[..eq_pos].contains(';')
                && !after_name[..eq_pos].contains('\n')
            {
                let rhs = after_name[eq_pos + 1..].trim_start();
                return Some(slice_until_sink_terminator(rhs));
            }
            search_from = hit + pattern.len();
        }
    }
    None
}

fn find_const_initializer_in_source(source: &str, name: &str) -> Option<String> {
    let pattern = format!("const {name}");
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(&pattern) {
        let hit = search_from + rel;
        let after_name = &source[hit + pattern.len()..];
        let next_char = after_name.chars().next();
        if next_char.is_none_or(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
            search_from = hit + pattern.len();
            continue;
        }
        if let Some(eq_pos) = after_name.find('=')
            && !after_name[..eq_pos].contains(';')
            && !after_name[..eq_pos].contains('\n')
        {
            let rhs = after_name[eq_pos + 1..].trim_start();
            return Some(slice_until_sink_terminator(rhs));
        }
        search_from = hit + pattern.len();
    }
    None
}

pub(crate) fn find_function_body_in_source(source: &str, name: &str) -> Option<String> {
    for prefix in [
        format!("function {name}"),
        format!("const {name}"),
        format!("let {name}"),
    ] {
        let mut search_from = 0;
        while let Some(rel) = source[search_from..].find(&prefix) {
            let pos = search_from + rel;
            let tail = &source[pos + prefix.len()..];
            let next_char = tail.chars().next();
            if next_char.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                search_from = pos + prefix.len();
                continue;
            }
            if let Some(end) = find_function_declaration_end(tail) {
                return tail.get(..end).map(str::to_string);
            }
            search_from = pos + prefix.len();
        }
    }
    None
}

fn find_function_declaration_end(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    let mut i = 0;
    let mut paren_depth = 0_usize;
    let mut brace_depth = 0_usize;
    let mut started_body_block = false;
    let mut after_arrow = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'\'' || b == b'"' || b == b'`' {
            let quote = b;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            continue;
        }

        if !started_body_block {
            match b {
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'=' if paren_depth == 0 && bytes.get(i + 1) == Some(&b'>') => {
                    after_arrow = true;
                    i += 2;
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if bytes.get(i) == Some(&b'{') {
                        started_body_block = true;
                        brace_depth = 1;
                        i += 1;
                    }
                    continue;
                }
                b'{' if paren_depth == 0 => {
                    started_body_block = true;
                    brace_depth = 1;
                }
                b';' if after_arrow && paren_depth == 0 => {
                    return Some(i + 1);
                }
                b'\n' if after_arrow && paren_depth == 0 => {
                    return Some(i);
                }
                _ => {}
            }
        } else {
            match b {
                b'{' => brace_depth += 1,
                b'}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    if brace_depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }

    if after_arrow && !started_body_block {
        Some(tail.len())
    } else {
        None
    }
}

fn slice_until_sink_terminator(s: &str) -> String {
    let mut paren = 0_i32;
    let mut brace = 0_i32;
    let mut bracket = 0_i32;
    let mut in_quote: Option<u8> = None;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => in_quote = Some(b),
            b'(' => paren += 1,
            b')' => {
                if paren == 0 {
                    return s[..i].trim().to_string();
                }
                paren -= 1;
            }
            b'{' => brace += 1,
            b'}' => {
                if brace == 0 {
                    return s[..i].trim().to_string();
                }
                brace -= 1;
            }
            b'[' => bracket += 1,
            b']' => bracket = (bracket - 1).max(0),
            b';' if paren == 0 && brace == 0 && bracket == 0 => {
                return s[..i].trim().to_string();
            }
            b'\n' if paren == 0 && brace == 0 && bracket == 0 => {
                return s[..i].trim().to_string();
            }
            _ => {}
        }
        i += 1;
    }
    s.trim().to_string()
}

fn resolve_static_string_in_file(source: &str, expr: &str) -> Option<String> {
    let trimmed = expr.trim();
    if let Some(lit) = unquote_js_string_literal(trimmed) {
        return Some(lit.to_string());
    }
    if is_identifier_token(trimmed)
        && let Some(init) = find_const_initializer_in_source(source, trimmed)
        && let Some(lit) = unquote_js_string_literal(init.trim())
    {
        return Some(lit.to_string());
    }
    None
}

fn unquote_js_string_literal(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"'))
            || (t.starts_with('\'') && t.ends_with('\''))
            || (t.starts_with('`') && t.ends_with('`') && !t.contains("${")))
    {
        Some(&t[1..t.len() - 1])
    } else {
        None
    }
}

fn is_static_string_or_no_interp_template(s: &str) -> bool {
    unquote_js_string_literal(s).is_some()
}

fn is_screaming_constant_ident(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && t.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_identifier_token(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

fn extract_template_interpolations(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(pos) = rest.find("${") {
        let after = &rest[pos + 2..];
        if let Some(close) = after.find('}') {
            out.push(after[..close].to_string());
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    out
}

pub(crate) fn split_balanced_parens(s: &str) -> Option<(&str, &str)> {
    let mut depth = 1_i32;
    let mut in_quote: Option<u8> = None;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => in_quote = Some(b),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&s[..i], &s[i + 1..]));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(crate) fn split_top_level_args(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut paren = 0_i32;
    let mut brace = 0_i32;
    let mut bracket = 0_i32;
    let mut in_quote: Option<u8> = None;
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => in_quote = Some(b),
            b'(' => paren += 1,
            b')' => paren = (paren - 1).max(0),
            b'{' => brace += 1,
            b'}' => brace = (brace - 1).max(0),
            b'[' => bracket += 1,
            b']' => bracket = (bracket - 1).max(0),
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                out.push(s.get(start..i).unwrap_or_default().trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = s.get(start..).unwrap_or_default().trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn split_top_level_ternary(s: &str) -> Option<(&str, &str, &str)> {
    let q_pos = s.find('?')?;
    if s[q_pos..].starts_with("??") || s[q_pos..].starts_with("?.") {
        return None;
    }
    let after_q = &s[q_pos + 1..];
    let mut in_quote: Option<u8> = None;
    let bytes = after_q.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(b, b'"' | b'\'' | b'`') {
            in_quote = Some(b);
        } else if b == b':' {
            return Some((
                s[..q_pos].trim(),
                after_q[..i].trim(),
                after_q[i + 1..].trim(),
            ));
        }
        i += 1;
    }
    None
}

fn find_standalone_call(line: &str, call_token: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(rel) = line[search_from..].find(call_token) {
        let hit = search_from + rel;
        let prev = if hit > 0 {
            Some(line.as_bytes()[hit - 1])
        } else {
            None
        };
        if prev.is_none_or(|b| !b.is_ascii_alphanumeric() && b != b'_' && b != b'$' && b != b'.') {
            return Some(hit);
        }
        search_from = hit + call_token.len();
    }
    None
}

fn is_server_only_path(path_str: &str) -> bool {
    let lower = path_str.to_ascii_lowercase();
    lower.contains("/server/")
        || lower.contains("/api/")
        || lower.ends_with(".server.ts")
        || lower.ends_with(".server.tsx")
        || lower.ends_with("/route.ts")
        || lower.ends_with("/route.tsx")
}

fn extract_jsx_attr_value(src: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_pos = src.find(&format!("<{tag}"))?;
    let after_tag = &src[tag_pos..];
    let close = after_tag.find('>')?;
    let opener = &after_tag[..close];
    let attr_pos = opener.find(&format!("{attr}="))?;
    let val_start = opener.get(attr_pos + attr.len() + 1..)?.trim_start();
    if let Some(inner) = val_start.strip_prefix('{') {
        let end = inner.find('}')?;
        return Some(inner[..end].trim().to_string());
    }
    None
}

fn extract_object_prop_after_call(src: &str, callees: &[&str], prop: &str) -> Option<String> {
    for &callee in callees {
        if let Some(pos) = src.find(callee) {
            let tail = &src[pos..];
            if let Some(prop_pos) = tail.find(&format!("{prop}:")) {
                let after = tail.get(prop_pos + prop.len() + 1..)?.trim_start();
                let val = after.split([',', '}', ')']).next().unwrap_or("").trim();
                return Some(val.to_string());
            }
        }
    }
    None
}

fn find_string_timer_call(line: &str) -> Option<usize> {
    for timer in ["setTimeout(", "setInterval("] {
        if let Some(pos) = line.find(timer) {
            let after = line[pos + timer.len()..].trim_start();
            if after.starts_with('"') || after.starts_with('\'') {
                return Some(pos);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        graph::ProjectGraph,
        ir::extract::parse_file_ir,
        rules::types::{Diagnostic, RuleId, RuleSeverity},
    };

    use super::{evaluate_security_rules, find_suspicious_public_env_in_line};

    fn run_security_rules(path: &str, source: &str) -> Vec<Diagnostic> {
        let file = parse_file_ir(Path::new(path), source);
        let graph = ProjectGraph::build(vec![file]);
        let mut out = Vec::new();
        let active = |rule: RuleId| Some(rule.metadata().default_severity);
        evaluate_security_rules(&graph, &graph.files[0], &active, &mut out);
        let _ = RuleSeverity::Error;
        out
    }

    #[test]
    fn find_suspicious_public_env_detects_secret_names_and_allows_trusted_public_keys() {
        assert_eq!(
            find_suspicious_public_env_in_line("const s = process.env.NEXT_PUBLIC_STRIPE_SECRET;"),
            Some((22, "NEXT_PUBLIC_STRIPE_SECRET"))
        );
        assert_eq!(
            find_suspicious_public_env_in_line(
                "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;"
            ),
            None
        );
    }

    #[test]
    fn evaluate_security_rules_exercises_dom_injection_and_artifact_submodules() {
        let diags = run_security_rules(
            "src/App.tsx",
            r#"
export function App({ rawHtml }: { rawHtml: string }) {
    eval(rawHtml);
    db.$queryRawUnsafe(rawHtml);
    const key = "-----BEGIN RSA PRIVATE KEY-----";
    return <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;
}
"#,
        );
        assert!(diags.iter().any(|d| d.rule == RuleId::DangerousHtmlSink));
        assert!(diags.iter().any(|d| d.rule == RuleId::NoEval));
        assert!(diags.iter().any(|d| d.rule == RuleId::RawSqlInjectionRisk));
        assert!(diags.iter().any(|d| d.rule == RuleId::KeyLifecycleRisk));
    }
}
