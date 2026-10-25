//! Cross-file HTML sanitizer/KaTeX provenance (`dangerous-html-sink`) and
//! `window.open` target/rel/destination propagation (`window-open-without-noopener`).

use crate::{
    graph::ProjectGraph,
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId},
};

use super::{
    extract_template_interpolations, find_binding_initializer_in_source,
    find_const_initializer_in_source, find_function_body_in_source, is_identifier_token,
    is_screaming_constant_ident, is_static_string_or_no_interp_template, push_sec_diag,
    resolve_imported_binding, resolve_static_string_in_file, slice_until_sink_terminator,
    split_balanced_parens, split_top_level_args, split_top_level_ternary,
    unquote_js_string_literal,
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
        if line
            .get(..col_offset)
            .is_some_and(|prefix| prefix.contains("<style"))
        {
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
        let after_key = after_sink.get(html_pos + "__html".len()..)?;
        let colon = after_key.find(':')?;
        let val_tail = after_key.get(colon + 1..)?.trim_start();
        return Some(slice_until_sink_terminator(val_tail));
    }
    if let Some(ias_pos) = after_sink.find("insertAdjacentHTML(") {
        let after_open = after_sink.get(ias_pos + "insertAdjacentHTML(".len()..)?;
        let comma = after_open.find(',')?;
        let val_tail = after_open.get(comma + 1..)?.trim_start();
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
            let ret_expr = catch_tail
                .get(ret_pos + "return ".len()..)
                .unwrap_or_default()
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
        let after = compact
            .get(trust_pos + "trust:".len()..)
            .unwrap_or_default();
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

        let before = line.get(..col_offset).unwrap_or_default().trim_end();
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

        let after_callee = line.get(col_offset..).unwrap_or_default();
        let Some(open_paren_rel) = after_callee.find('(') else {
            continue;
        };
        let args_tail = after_callee.get(open_paren_rel + 1..).unwrap_or_default();
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
        if trimmed
            .get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
        {
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

