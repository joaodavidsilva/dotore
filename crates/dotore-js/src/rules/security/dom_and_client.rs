//! Core DOM, client-side, and SSR security rules (`dangerous-html-sink`,
//! `window-open-without-noopener`, `unsafe-json-in-html`, `no-secrets-in-client-code`,
//! `public-env-secret-name`, `auth-token-in-web-storage`, `no-eval`,
//! `no-path-prefix-containment`, `react-markdown-unsanitized-raw-html`,
//! `react-router-csp-nonce-consistency`, `no-danger-with-children`,
//! `iframe-missing-sandbox`).

use crate::{
    graph::ProjectGraph,
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId},
};

use super::{
    extract_jsx_attr_value, extract_object_prop_after_call, extract_template_interpolations,
    find_binding_initializer_in_source, find_const_initializer_in_source,
    find_function_body_in_source, find_standalone_call, find_string_timer_call,
    is_identifier_token, is_screaming_constant_ident, is_server_only_path,
    is_static_string_or_no_interp_template, push_sec_diag, resolve_imported_binding,
    resolve_static_string_in_file, slice_until_sink_terminator, split_balanced_parens,
    split_top_level_args, split_top_level_ternary, unquote_js_string_literal,
};

pub(super) fn check_dangerous_html_sink(
    graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let lower_path = path_str.to_ascii_lowercase();
    if lower_path.contains("/emails/")
        || lower_path.contains("email-template")
        || lower_path.contains("rawhtml")
        || lower_path.ends_with("email.tsx")
        || lower_path.ends_with("email.jsx")
        || (lower_path.contains("sanitiz") && !lower_path.contains("unsanitiz"))
    {
        return;
    }

    let src = &file.source;
    for (line_idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
            continue;
        }
        let sink_pos = line
            .find("dangerouslySetInnerHTML")
            .or_else(|| line.find(".innerHTML"))
            .or_else(|| line.find(".outerHTML"))
            .or_else(|| line.find("[\"innerHTML\"]"))
            .or_else(|| line.find("['innerHTML']"))
            .or_else(|| line.find(".insertAdjacentHTML("))
            .or_else(|| line.find("document.write("))
            .or_else(|| line.find("document.writeln("))
            .or_else(|| line.find(".createContextualFragment("))
            .or_else(|| line.find(".setHTMLUnsafe("));
        let Some(col_offset) = sink_pos else {
            continue;
        };

        // Ignore `<style dangerouslySetInnerHTML=...>`
        if line[..col_offset].contains("<style") {
            continue;
        }

        let Some(val_expr) = extract_html_sink_value_expr(src, line_idx, col_offset) else {
            continue;
        };
        let clean_val = val_expr
            .trim()
            .trim_end_matches([',', ';', '}', ')'])
            .trim();
        if clean_val.is_empty() {
            continue;
        }

        if is_safe_html_sink_expression(graph, file, clean_val, 0) {
            continue;
        }

        let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
        let byte_start = line_start + u32::try_from(col_offset).unwrap_or(0);
        let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
        push_sec_diag(
            out,
            file,
            RuleId::DangerousHtmlSink,
            "dangerousHtmlSink",
            clean_val,
            "HTML is injected from a dynamic-looking source, which can become XSS if the value is user-controlled or unsanitized.",
            offset_to_loc(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_end,
            },
        );
    }
}

fn extract_html_sink_value_expr(src: &str, line_idx: usize, col_offset: usize) -> Option<String> {
    let lines: Vec<&str> = src.lines().collect();
    let window = lines
        .iter()
        .skip(line_idx)
        .take(5)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let after_sink = &window[col_offset.min(window.len())..];

    if let Some(html_pos) = after_sink.find("__html") {
        let after_key = &after_sink[html_pos + "__html".len()..];
        let colon = after_key.find(':')?;
        let val_tail = after_key[colon + 1..].trim_start();
        return Some(slice_until_sink_terminator(val_tail));
    }
    if let Some(ias_pos) = after_sink.find("insertAdjacentHTML(") {
        let after_open = &after_sink[ias_pos + "insertAdjacentHTML(".len()..];
        let comma = after_open.find(',')?;
        let val_tail = after_open[comma + 1..].trim_start();
        return Some(slice_until_sink_terminator(val_tail));
    }
    for call_prefix in [
        "document.write(",
        "document.writeln(",
        "createContextualFragment(",
        "setHTMLUnsafe(",
    ] {
        if let Some(pos) = after_sink.find(call_prefix) {
            let val_tail = after_sink[pos + call_prefix.len()..].trim_start();
            return Some(slice_until_sink_terminator(val_tail));
        }
    }
    if let Some(eq_pos) = after_sink.find('=') {
        if after_sink[eq_pos + 1..].starts_with('=') {
            return None;
        }
        let val_tail = after_sink[eq_pos + 1..].trim_start();
        return Some(slice_until_sink_terminator(val_tail));
    }
    None
}

fn is_safe_html_sink_expression(
    graph: &ProjectGraph,
    file: &FileIr,
    expr: &str,
    depth: usize,
) -> bool {
    if depth > 6 {
        return false;
    }
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return true;
    }

    // 1. Static string literal or substitution-free template literal
    if is_static_string_or_no_interp_template(trimmed) {
        return true;
    }

    // 2. SCREAMING_SNAKE_CASE module constant (`LOGO_SVG_MARKUP`)
    if is_screaming_constant_ident(trimmed) {
        return true;
    }

    // 3. DOM-to-DOM read (`svg.outerHTML`, `button.innerHTML`) without `+`
    if !trimmed.contains('+')
        && (trimmed.ends_with(".outerHTML") || trimmed.ends_with(".innerHTML"))
    {
        return true;
    }

    // 4. Template literal whose interpolations are only `process.env.*` or safe expressions
    if trimmed.starts_with('`') && trimmed.ends_with('`') {
        let interps = extract_template_interpolations(trimmed);
        if !interps.is_empty()
            && interps.iter().all(|interp| {
                interp.trim().starts_with("process.env.")
                    || is_safe_html_sink_expression(graph, file, interp, depth + 1)
            })
        {
            return true;
        }
    }

    // 5. Direct sanitizer, i18n, or safe serializer call
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("dompurify.sanitize(")
        || lower.starts_with("sanitize(")
        || lower.starts_with("sanitizehtml(")
        || lower.starts_with("purify(")
        || lower.starts_with("escapehtml(")
        || (lower.contains("safehtml(") && !lower.contains("unsafehtml("))
        || lower.starts_with("t(")
        || lower.starts_with("i18n.")
        || lower.starts_with("translate(")
        || lower.starts_with("formatmessage(")
        || lower.starts_with("codetohtml(")
        || lower.starts_with("hl.codetohtml(")
        || lower.starts_with("shiki.")
        || lower.starts_with("hljs.highlight")
        || lower.starts_with("prism.highlight")
        || lower.starts_with("rendertostaticmarkup(")
    {
        return true;
    }

    // 6. Direct `katex.renderToString(expr, opts)` call
    if trimmed.contains("katex.renderToString(") {
        return is_katex_call_options_safe(trimmed);
    }

    // 7. Function call `fnName(args...)` -> resolve locally or across files via `ProjectGraph`
    if let Some(open_paren) = trimmed.find('(')
        && trimmed.ends_with(')')
    {
        let callee = trimmed[..open_paren].trim();
        let args_str = &trimmed[open_paren + 1..trimmed.len() - 1];
        if is_identifier_token(callee)
            && let Some(safe) =
                evaluate_html_helper_call(graph, file, callee, args_str, None, depth + 1)
        {
            return safe;
        }
    }

    // 8. Member access `obj.html` where `obj = helper(...)`
    if let Some((base_ident, prop_name)) = trimmed.split_once('.')
        && is_identifier_token(base_ident.trim())
        && is_identifier_token(prop_name.trim())
        && let Some(init) = find_binding_initializer_in_source(&file.source, base_ident.trim())
        && let Some(open_paren) = init.find('(')
        && init.ends_with(')')
    {
        let callee = init[..open_paren].trim();
        let args_str = &init[open_paren + 1..init.len() - 1];
        if is_identifier_token(callee)
            && let Some(safe) = evaluate_html_helper_call(
                graph,
                file,
                callee,
                args_str,
                Some(prop_name.trim()),
                depth + 1,
            )
        {
            return safe;
        }
    }

    // 9. Bare identifier `payload` or `html` -> resolve initializer in `file.source`
    if is_identifier_token(trimmed) {
        if let Some(init) = find_binding_initializer_in_source(&file.source, trimmed) {
            return is_safe_html_sink_expression(graph, file, &init, depth + 1);
        }
        // Cross-file imported constant
        if let Some((target_file, target_local)) = resolve_imported_binding(graph, file, trimmed)
            && let Some(init) =
                find_binding_initializer_in_source(&target_file.source, &target_local)
        {
            return is_safe_html_sink_expression(graph, target_file, &init, depth + 1);
        }
    }

    false
}

fn evaluate_html_helper_call(
    graph: &ProjectGraph,
    caller_file: &FileIr,
    callee_name: &str,
    call_args_str: &str,
    accessed_property: Option<&str>,
    depth: usize,
) -> Option<bool> {
    if depth > 6 {
        return None;
    }
    // Check if caller arguments explicitly pass `trust: true`, `trust: dynamic`, or spread `...`
    if call_args_have_unsafe_katex_options(call_args_str) {
        return Some(false);
    }

    // 1. Same-file helper function
    if let Some(fn_body) = find_function_body_in_source(&caller_file.source, callee_name) {
        return Some(is_helper_body_safe_html(
            &caller_file.source,
            &fn_body,
            call_args_str,
            accessed_property,
        ));
    }

    // 2. Cross-file imported helper resolved via `ProjectGraph`
    if let Some((target_file, target_name)) =
        resolve_imported_binding(graph, caller_file, callee_name)
        && let Some(fn_body) = find_function_body_in_source(&target_file.source, &target_name)
    {
        return Some(is_helper_body_safe_html(
            &target_file.source,
            &fn_body,
            call_args_str,
            accessed_property,
        ));
    }

    None
}

fn is_helper_body_safe_html(
    file_source: &str,
    fn_body: &str,
    call_args_str: &str,
    accessed_property: Option<&str>,
) -> bool {
    let _ = file_source;
    let has_sanitizer_or_katex = fn_body.contains("DOMPurify.sanitize(")
        || fn_body.contains("sanitizeHtml(")
        || fn_body.contains("katex.renderToString(");
    if !has_sanitizer_or_katex {
        return false;
    }

    // If helper calls `katex.renderToString(...)`, check if helper body itself sets `trust: true`
    if fn_body.contains("katex.renderToString(") && !is_katex_call_options_safe(fn_body) {
        return false;
    }

    // If helper forwards a 2nd positional options parameter `katex.renderToString(val, options)`
    // and caller passes a bare variable `options` (not `{ trust: false }` or `{ throwOnError: false }`),
    // then options are unproven!
    if fn_body.contains("katex.renderToString(") {
        let top_args = split_top_level_args(call_args_str);
        if let Some(second_arg) = top_args.get(1) {
            let trimmed_opt = second_arg.trim();
            if !trimmed_opt.is_empty() && !trimmed_opt.starts_with('{') {
                return false;
            }
        }
    }

    if let Some(prop) = accessed_property {
        let needle = format!("{prop}:");
        if !fn_body.contains(&needle) {
            return false;
        }
    }

    // If helper has a `catch` block, check that the `catch` block does NOT return a raw unescaped parameter
    if let Some(catch_pos) = fn_body.find("catch") {
        let catch_tail = &fn_body[catch_pos..];
        if let Some(ret_pos) = catch_tail.find("return ") {
            let ret_expr = catch_tail[ret_pos + "return ".len()..]
                .split([';', '}'])
                .next()
                .unwrap_or("")
                .trim();
            let is_safe_fallback = is_static_string_or_no_interp_template(ret_expr)
                || ret_expr.starts_with("String(error")
                || ret_expr.starts_with("String(err")
                || ret_expr.contains("escapeHtml(")
                || ret_expr.contains("DOMPurify.sanitize(")
                || ret_expr.contains(".replaceAll(\"<\"")
                || ret_expr.contains(".replace(/</g");
            if !is_safe_fallback {
                return false;
            }
        }
    }

    true
}

fn call_args_have_unsafe_katex_options(args_str: &str) -> bool {
    let compact: String = args_str.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("...") {
        return true;
    }
    if let Some(trust_pos) = compact.find("trust:") {
        let after = &compact[trust_pos + "trust:".len()..];
        if !after.starts_with("false") && !after.starts_with("undefined") {
            return true;
        }
    }
    false
}

fn is_katex_call_options_safe(text: &str) -> bool {
    !call_args_have_unsafe_katex_options(text)
}

pub(super) fn check_window_open_without_noopener(
    graph: &ProjectGraph,
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    for (line_idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let open_pos = line
            .find("window.open(")
            .or_else(|| line.find("globalThis.open("))
            .or_else(|| line.find("self.open("))
            .or_else(|| line.find("parent.open("))
            .or_else(|| line.find("top.open("));
        let Some(col_offset) = open_pos else {
            continue;
        };

        let before = line[..col_offset].trim_end();
        // If handle is captured (`const win = window.open(...)`, `w = window.open(...)`, `return window.open(...)`), skip
        if before.ends_with('=') && !before.ends_with("=>") && !before.ends_with("==") {
            continue;
        }
        if before.ends_with("return") {
            continue;
        }
        // If `const openPopup = () => window.open(...)` stored in variable (not JSX prop), skip
        if before.ends_with("=>")
            && (before.contains("const ") || before.contains("let "))
            && !before.contains("onClick")
        {
            continue;
        }

        let after_callee = &line[col_offset..];
        let Some(open_paren_rel) = after_callee.find('(') else {
            continue;
        };
        let args_tail = &after_callee[open_paren_rel + 1..];
        let Some((args_inside, after_close)) = split_balanced_parens(args_tail) else {
            continue;
        };
        // If result is immediately chained (`window.open(url).focus()`), handle is used -> skip
        if after_close.trim_start().starts_with('.') || after_close.trim_start().starts_with("?.") {
            continue;
        }

        let args = split_top_level_args(args_inside);
        let url_arg = args.first().map(|s| s.trim()).unwrap_or("");
        let target_arg = args.get(1).map(|s| s.trim()).unwrap_or("");
        let features_arg = args.get(2).map(|s| s.trim());

        // 1. Empty or nullish URL (`window.open()`, `window.open(null)`, `window.open(undefined)`, `window.open(void 0)`)
        if is_nullish_url_expr(url_arg) {
            continue;
        }

        // 2. Navigating target (`_self`, `_top`, `_parent`)
        if let Some(target_lit) = unquote_js_string_literal(target_arg)
            && matches!(target_lit, "_self" | "_top" | "_parent")
        {
            continue;
        }

        // 3. Features argument contains `noopener` or `noreferrer` (directly or via `const` string)
        if let Some(feat_expr) = features_arg
            && !is_nullish_url_expr(feat_expr)
        {
            if let Some(feat_text) = resolve_static_string_in_file(src, feat_expr) {
                if features_protect_opener(&feat_text) {
                    continue;
                }
            } else {
                // Opaque non-null features expression
                continue;
            }
        }

        // 4. Check if URL argument is a direct external literal vs trusted destination
        let is_direct_external_literal = unquote_js_string_literal(url_arg)
            .is_some_and(|lit| !lit.trim().is_empty() && !is_same_origin_or_protocol_url(lit));
        if !is_direct_external_literal
            && is_trusted_window_open_destination(graph, file, url_arg, false, 0)
        {
            continue;
        }

        let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
        let byte_start = line_start + u32::try_from(col_offset).unwrap_or(0);
        let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
        push_sec_diag(
            out,
            file,
            RuleId::WindowOpenWithoutNoopener,
            "windowOpenWithoutNoopener",
            "window.open",
            "This `window.open` call leaves the opened page able to redirect your tab via `window.opener`, so pass `'noopener'` in the features argument.",
            offset_to_loc(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_end,
            },
        );
    }
}

fn is_trusted_window_open_destination(
    graph: &ProjectGraph,
    file: &FileIr,
    expr: &str,
    is_foreign: bool,
    depth: usize,
) -> bool {
    if depth > 6 {
        return false;
    }
    let trimmed = expr.trim();
    if is_nullish_url_expr(trimmed) {
        return true;
    }

    // Direct string literal: trusted if same-origin / non-browsing scheme, OR if in-file `const` binding
    if let Some(lit) = unquote_js_string_literal(trimmed) {
        if is_same_origin_or_protocol_url(lit) {
            return true;
        }
        return !is_foreign && depth > 0;
    }

    // Template literal: trusted if prefix pins origin (`https://host/...`, `/path...`, `mailto:...`)
    if trimmed.starts_with('`') && trimmed.ends_with('`') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let static_prefix = inner.split("${").next().unwrap_or(inner);
        if is_same_origin_or_protocol_url(static_prefix) && static_prefix != "/" {
            return true;
        }
        if !is_foreign && has_complete_origin_prefix(static_prefix) {
            return true;
        }
        return false;
    }

    // `chrome.runtime.getURL(...)` or `URL.createObjectURL(...)`
    if (trimmed.starts_with("chrome.runtime.getURL(")
        && !file.source.contains("const chrome")
        && !file.source.contains("chrome.runtime.getURL ="))
        || trimmed.starts_with("URL.createObjectURL(")
    {
        return true;
    }

    // Ternary `cond ? a : b` -> trusted only if BOTH branches are trusted
    if let Some((_cond, then_branch, else_branch)) = split_top_level_ternary(trimmed) {
        return is_trusted_window_open_destination(graph, file, then_branch, is_foreign, depth + 1)
            && is_trusted_window_open_destination(graph, file, else_branch, is_foreign, depth + 1);
    }

    // Logical `a && b`: if `a` is nullish (`null && x`), result is nullish -> trusted
    if let Some((left, right)) = trimmed.split_once("&&") {
        if is_nullish_url_expr(left.trim()) {
            return true;
        }
        return is_trusted_window_open_destination(
            graph,
            file,
            right.trim(),
            is_foreign,
            depth + 1,
        );
    }

    // Identifier -> resolve `const` initializer in `file.source` (never `let` if reassigned)
    if is_identifier_token(trimmed) {
        if let Some(const_init) = find_const_initializer_in_source(&file.source, trimmed) {
            return is_trusted_window_open_destination(
                graph,
                file,
                &const_init,
                is_foreign,
                depth + 1,
            );
        }
        if !is_foreign
            && let Some((target_file, target_local)) =
                resolve_imported_binding(graph, file, trimmed)
            && let Some(foreign_init) =
                find_const_initializer_in_source(&target_file.source, &target_local)
        {
            return is_trusted_window_open_destination(
                graph,
                target_file,
                &foreign_init,
                true,
                depth + 1,
            );
        }
    }

    false
}

fn is_nullish_url_expr(expr: &str) -> bool {
    let t = expr.trim();
    t.is_empty() || matches!(t, "null" | "undefined" | "void 0")
}

fn is_same_origin_or_protocol_url(url: &str) -> bool {
    let trimmed = url.trim();
    for scheme in ["mailto:", "tel:", "sms:", "file:"] {
        if trimmed.len() >= scheme.len() && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return true;
        }
    }
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        return true;
    }
    trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('?')
        || trimmed.starts_with('#')
}

fn has_complete_origin_prefix(prefix: &str) -> bool {
    let lower = prefix.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    if let Some(pos) = rest.find(['/', '?', '#']) {
        pos > 0
    } else {
        false
    }
}

fn features_protect_opener(features_text: &str) -> bool {
    for part in features_text.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        let token = part.trim().to_ascii_lowercase();
        if token == "noopener" || token == "noreferrer" {
            return true;
        }
        if let Some((k, v)) = token.split_once('=')
            && (k.trim() == "noopener" || k.trim() == "noreferrer")
            && matches!(v.trim(), "1" | "true" | "yes")
        {
            return true;
        }
    }
    false
}

pub(super) fn check_unsafe_json_in_html(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    for (line_idx, line) in file.source.lines().enumerate() {
        let Some(json_pos) = line.find("JSON.stringify(") else {
            continue;
        };
        let is_in_html_or_script =
            line.contains("dangerouslySetInnerHTML") || line.contains("<script");
        if !is_in_html_or_script {
            continue;
        }
        let after = &line[json_pos + "JSON.stringify(".len()..];
        let Some((arg_inside, after_close)) = split_balanced_parens(after) else {
            continue;
        };
        // Skip static object/string literals (`JSON.stringify({ "@context": "https://schema.org" })`)
        if is_static_json_stringify_arg(arg_inside) {
            continue;
        }
        // Skip if output is escaped with `.replace(/</g, "\\u003c")` / `.replaceAll("<", ...)`
        let tail = after_close.trim_start();
        if (tail.starts_with(".replace(") || tail.starts_with(".replaceAll("))
            && (tail.contains("\\u003c") || tail.contains("\\u003C") || tail.contains("&lt;"))
        {
            continue;
        }
        let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
        let byte_start = line_start + u32::try_from(json_pos).unwrap_or(0);
        let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
        push_sec_diag(
            out,
            file,
            RuleId::UnsafeJsonInHtml,
            "unsafeJsonInHtml",
            "JSON.stringify",
            "Unescaped `JSON.stringify` output is injected into HTML or `<script>`, allowing `</script>` breakout XSS.",
            offset_to_loc(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_end,
            },
        );
    }
}

fn is_static_json_stringify_arg(arg: &str) -> bool {
    let trimmed = arg.trim();
    unquote_js_string_literal(trimmed).is_some()
}

pub(super) fn check_no_secrets_in_client_code(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if file.module.has_use_server || is_server_only_path(path_str) {
        return;
    }
    for (line_idx, line) in file.source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        // Check known secret value prefixes (excluding `pk_live_`, `pk_test_`, `sb_publishable_`)
        if let Some((prefix_col, _)) = find_secret_value_in_line(line) {
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(prefix_col).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::NoSecretsInClientCode,
                "noSecretsInClientCode",
                "secret",
                "This hardcoded secret is a security vulnerability: it ships to the browser where anyone can read it.",
                offset_to_loc(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

pub(super) fn find_secret_value_in_line(line: &str) -> Option<(usize, &'static str)> {
    if line.contains("pk_live_")
        || line.contains("pk_test_")
        || line.contains("sb_publishable_")
        || line.contains("placeholder")
        || line.contains("example")
    {
        return None;
    }
    for pat in [
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "sb_secret_",
        "whsec_",
        "SG.",
    ] {
        if let Some(pos) = line.find(pat) {
            let tail = &line[pos + pat.len()..];
            let token_len = tail
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                .count();
            if token_len >= 12 {
                return Some((pos, pat));
            }
        }
    }
    None
}

pub(super) fn check_public_env_secret_name(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if is_server_only_path(path_str) {
        return;
    }
    for (line_idx, line) in file.source.lines().enumerate() {
        if let Some((col, env_name)) = find_suspicious_public_env_in_line(line) {
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(col).unwrap_or(0);
            let byte_end = byte_start + u32::try_from(env_name.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::PublicEnvSecretName,
                "publicEnvSecretName",
                env_name,
                "Client code references a public env variable whose name looks like a secret or privileged credential.",
                offset_to_loc(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

pub(crate) fn find_suspicious_public_env_in_line(line: &str) -> Option<(usize, &str)> {
    for prefix in ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_"] {
        let mut search_from = 0;
        while let Some(rel) = line[search_from..].find(prefix) {
            let start = search_from + rel;
            let rest = &line[start..];
            let len = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            let candidate = &rest[..len];
            let upper = candidate.to_ascii_uppercase();
            let has_secret_word = [
                "SECRET",
                "TOKEN",
                "PASSWORD",
                "PRIVATE",
                "DATABASE_URL",
                "SERVICE_ROLE",
                "AWS_ACCESS_KEY",
                "AWS_SECRET",
            ]
            .iter()
            .any(|w| upper.contains(w));
            let is_trusted_public = [
                "PUBLISHABLE",
                "ANON_KEY",
                "PUBLIC_KEY",
                "PUBLIC_TOKEN",
                "SENTRY_DSN",
                "POSTHOG",
                "MAPBOX_TOKEN",
                "MIXPANEL_TOKEN",
                "ALGOLIA_SEARCH_KEY",
                "GOOGLE_MAPS_API_KEY",
                "_URL",
                "_ENDPOINT",
                "_HEADER",
                "_NAME",
                "_KIND",
                "_TYPE",
            ]
            .iter()
            .any(|t| upper.contains(t) && !upper.ends_with("DATABASE_URL"));

            if has_secret_word && !is_trusted_public {
                return Some((start, candidate));
            }
            search_from = start + len.max(1);
        }
    }
    None
}

pub(super) fn check_auth_token_in_web_storage(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    for (line_idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        for storage in ["localStorage", "sessionStorage"] {
            let set_item_pat = format!("{storage}.setItem(");
            if let Some(pos) = line.find(&set_item_pat) {
                let after = &line[pos + set_item_pat.len()..];
                let first_arg = after.split(',').next().unwrap_or("").trim();
                let resolved_key = resolve_static_string_in_file(src, first_arg);
                if let Some(key) = resolved_key
                    && is_auth_credential_storage_key(&key)
                {
                    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
                    let byte_start = line_start + u32::try_from(pos).unwrap_or(0);
                    let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
                    push_sec_diag(
                        out,
                        file,
                        RuleId::AuthTokenInWebStorage,
                        "authTokenInWebStorage",
                        &key,
                        "Storing an auth token in `localStorage`/`sessionStorage` exposes it to any XSS on the page. Keep tokens in an `HttpOnly`, `Secure`, `SameSite` cookie instead.",
                        offset_to_loc(line_starts, byte_start),
                        ByteSpan {
                            start: byte_start,
                            end: byte_end,
                        },
                    );
                }
            }
        }
    }
}

fn is_auth_credential_storage_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let has_sensitive = [
        "token",
        "jwt",
        "secret",
        "password",
        "passwd",
        "credential",
        "api_key",
        "api-key",
        "apikey",
        "bearer",
        "private_key",
        "private-key",
    ]
    .iter()
    .any(|w| lower.contains(w));
    if !has_sensitive {
        return false;
    }
    let has_non_auth = [
        "csrf", "xsrf", "device", "fcm", "apns", "push", "design", "tokeniz", "syntax", "css",
        "theme", "color",
    ]
    .iter()
    .any(|w| lower.contains(w));
    let has_strong_auth = [
        "jwt",
        "secret",
        "password",
        "passwd",
        "credential",
        "private_key",
        "api_key",
        "bearer",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "auth_token",
        "authtoken",
        "id_token",
        "idtoken",
        "session",
    ]
    .iter()
    .any(|w| lower.contains(w));
    !has_non_auth || has_strong_auth
}

pub(super) fn check_no_eval(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let lower_path = path_str.to_ascii_lowercase();
    if lower_path.contains("/sandbox/")
        || lower_path.contains("-sandbox/")
        || lower_path.contains("-sandbox.")
    {
        return;
    }
    for (line_idx, line) in file.source.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let hit = find_standalone_call(line, "eval(")
            .or_else(|| line.find("globalThis.eval("))
            .or_else(|| {
                let pos = line.find("new Function(")?;
                if line[pos..].contains("\"return this\"") || line[pos..].contains("'return this'")
                {
                    None
                } else {
                    Some(pos)
                }
            })
            .or_else(|| find_string_timer_call(line));
        if let Some(col) = hit {
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(col).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::NoEval,
                "noEval",
                "eval",
                "eval() is a code-injection vulnerability: it runs any string as code.",
                offset_to_loc(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

pub(super) fn check_no_path_prefix_containment(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let has_path_resolve =
        file.source.contains("path.resolve(") || file.source.contains("import path");
    if !has_path_resolve {
        return;
    }
    for (line_idx, line) in file.source.lines().enumerate() {
        let Some(sw_pos) = line.find(".startsWith(") else {
            continue;
        };
        let after = &line[sw_pos + ".startsWith(".len()..];
        let Some((arg_inside, _)) = split_balanced_parens(after) else {
            continue;
        };
        let arg = arg_inside.trim();
        // Safe if argument appends `path.sep` or `"/"` or ends with `/`
        if arg.contains("path.sep")
            || arg.contains("+ \"/\"")
            || arg.contains("+ '/'")
            || arg.ends_with("/`")
            || arg.ends_with("/\"")
            || arg.ends_with("/'")
        {
            continue;
        }
        if is_identifier_token(arg) || arg.starts_with("path.resolve(") {
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(sw_pos).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::NoPathPrefixContainment,
                "noPathPrefixContainment",
                arg,
                "Path containment check uses `.startsWith(root)` without a trailing path separator, allowing sibling-prefix bypasses (`/app/root-evil`).",
                offset_to_loc(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

pub(super) fn check_react_markdown_unsanitized_raw_html(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !file.source.contains("rehype-raw") && !file.source.contains("rehypeRaw") {
        return;
    }
    if file.source.contains("rehype-sanitize")
        || file.source.contains("rehypeSanitize")
        || file.source.contains("DOMPurify.sanitize")
    {
        return;
    }
    for jsx in &file.jsx_elements {
        if matches!(
            jsx.name.as_str(),
            "ReactMarkdown" | "Markdown" | "MarkdownAsync" | "MarkdownHooks"
        ) && jsx.attributes.iter().any(|a| a == "rehypePlugins")
        {
            let _ = line_starts;
            push_sec_diag(
                out,
                file,
                RuleId::ReactMarkdownUnsanitizedRawHtml,
                "reactMarkdownUnsanitizedRawHtml",
                &jsx.name,
                "React Markdown parses dynamic raw HTML when `rehype-raw` is enabled. Add `rehype-sanitize` to `rehypePlugins` or sanitize the markdown before rendering it.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}

pub(super) fn check_react_router_csp_nonce_consistency(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !file.source.contains("ServerRouter")
        || (!file.source.contains("renderToPipeableStream")
            && !file.source.contains("renderToReadableStream"))
    {
        return;
    }
    let router_nonce = extract_jsx_attr_value(&file.source, "ServerRouter", "nonce");
    let stream_nonce = extract_object_prop_after_call(
        &file.source,
        &["renderToPipeableStream", "renderToReadableStream"],
        "nonce",
    );
    if router_nonce != stream_nonce && (router_nonce.is_some() || stream_nonce.is_some()) {
        let pos = file.source.find("ServerRouter").unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_sec_diag(
            out,
            file,
            RuleId::ReactRouterCspNonceConsistency,
            "reactRouterCspNonceConsistency",
            "ServerRouter",
            "CSP `nonce` passed to `<ServerRouter>` and the React server rendering stream options must match.",
            offset_to_loc(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 12,
            },
        );
    }
}

pub(super) fn check_no_danger_with_children(file: &FileIr, out: &mut Vec<Diagnostic>) {
    for jsx in &file.jsx_elements {
        if jsx
            .attributes
            .iter()
            .any(|a| a == "dangerouslySetInnerHTML")
            && (jsx.has_raw_text_child
                || jsx.has_element_children
                || jsx.attributes.iter().any(|a| a == "children"))
        {
            push_sec_diag(
                out,
                file,
                RuleId::NoDangerWithChildren,
                "noDangerWithChildren",
                &jsx.name,
                "Do not pass both `children` and `dangerouslySetInnerHTML` to the same JSX element.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}

pub(super) fn check_iframe_missing_sandbox(file: &FileIr, out: &mut Vec<Diagnostic>) {
    for jsx in &file.jsx_elements {
        if jsx.name == "iframe" && !jsx.attributes.iter().any(|a| a == "sandbox") {
            push_sec_diag(
                out,
                file,
                RuleId::IframeMissingSandbox,
                "iframeMissingSandbox",
                "iframe",
                "`<iframe>` element is missing a `sandbox` attribute.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}
