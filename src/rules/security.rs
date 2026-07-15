//! Security and `security-scan` rule detectors, including cross-file HTML sanitizer
//! and KaTeX provenance (`dangerous-html-sink`) and `window.open` target/rel/destination
//! propagation (`window-open-without-noopener`).

use std::collections::HashSet;

use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, SourceLoc,
        types::{compute_line_starts, loc_from_line_starts},
    },
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

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
    if is_active(RuleId::JsxNoScriptUrl).is_some() {
        check_jsx_no_script_url(file, &line_starts, out);
    }
    if is_active(RuleId::JsxNoTargetBlank).is_some() {
        check_jsx_no_target_blank(file, &line_starts, out);
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
    let meta = rule.metadata();
    out.push(Diagnostic {
        file: file.path.clone(),
        subject_name: None,
        rule,
        category: meta.category,
        severity: meta.default_severity,
        message_id,
        tier: meta.default_tier,
        target_name: target_name.to_string(),
        message: message.to_string(),
        docs_url: meta.docs_url,
        loc,
        span,
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: None,
    });
}

fn check_dangerous_html_sink(
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
            loc_from_line_starts(line_starts, byte_start),
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

fn check_window_open_without_noopener(
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
            loc_from_line_starts(line_starts, byte_start),
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

fn check_unsafe_json_in_html(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
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
            loc_from_line_starts(line_starts, byte_start),
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

fn check_no_secrets_in_client_code(
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
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn find_secret_value_in_line(line: &str) -> Option<(usize, &'static str)> {
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

fn check_public_env_secret_name(
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
                loc_from_line_starts(line_starts, byte_start),
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

fn check_auth_token_in_web_storage(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
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
                        loc_from_line_starts(line_starts, byte_start),
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

fn check_no_eval(file: &FileIr, path_str: &str, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
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
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn check_no_path_prefix_containment(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
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
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn check_react_markdown_unsanitized_raw_html(
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

fn check_react_router_csp_nonce_consistency(
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
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 12,
            },
        );
    }
}

fn check_no_danger_with_children(file: &FileIr, out: &mut Vec<Diagnostic>) {
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

fn check_iframe_missing_sandbox(file: &FileIr, out: &mut Vec<Diagnostic>) {
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

fn check_jsx_no_script_url(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    for (line_idx, line) in file.source.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if let Some(pos) = lower.find("javascript:")
            && (lower.contains("href=") || lower.contains("src=") || lower.contains("to="))
        {
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(pos).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::JsxNoScriptUrl,
                "jsxNoScriptUrl",
                "javascript:",
                "`javascript:` URLs in JSX are a script-injection hazard; use an `onClick` handler instead.",
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn check_jsx_no_target_blank(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    for (line_idx, line) in file.source.lines().enumerate() {
        if (line.contains("target=\"_blank\"") || line.contains("target='_blank'"))
            && (!line.contains("rel=")
                || (!line.contains("noopener") && !line.contains("noreferrer")))
        {
            let pos = line.find("target=").unwrap_or(0);
            let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(pos).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_sec_diag(
                out,
                file,
                RuleId::JsxNoTargetBlank,
                "jsxNoTargetBlank",
                "_blank",
                "Using `target=\"_blank\"` without `rel=\"noreferrer\"` or `rel=\"noopener\"` exposes `window.opener`.",
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn evaluate_security_scan_patterns<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;

    // 1. raw-sql-injection-risk
    if is_active(RuleId::RawSqlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("$queryRawUnsafe(")
                || line.contains("$executeRawUnsafe(")
                || (line.contains("Prisma.raw(") && line.contains("${"))
                || (line.contains("sql.raw(") && line.contains("${"))
                || (line.contains(".query(")
                    && line.contains("${")
                    && (line.to_ascii_uppercase().contains("SELECT ")
                        || line.to_ascii_uppercase().contains("INSERT ")
                        || line.to_ascii_uppercase().contains("UPDATE ")
                        || line.to_ascii_uppercase().contains("DELETE ")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::RawSqlInjectionRisk,
                    "rawSqlInjectionRisk",
                    "sql",
                    "Code uses a raw SQL escape hatch or string-built query shape that can bypass parameter binding.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 2. nosql-injection-risk
    if is_active(RuleId::NosqlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("$where")
                || (line.contains(".find(")
                    && line.contains("JSON.parse(")
                    && (line.contains("req.") || line.contains("request.")))
                || (line.contains("$regex") && (line.contains("req.") || line.contains("request.")))
                || (line.contains("new RegExp(")
                    && (line.contains("req.") || line.contains("request.")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::NosqlInjectionRisk,
                    "nosqlInjectionRisk",
                    "nosql",
                    "Code appears to pass raw JSON, regex, or `$where` style input into a NoSQL query.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 3. command-execution-input-risk
    if is_active(RuleId::CommandExecutionInputRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            let has_exec = find_standalone_call(line, "exec(").is_some()
                || find_standalone_call(line, "execSync(").is_some()
                || line.contains("child_process.exec")
                || line.contains("cp.exec")
                || (line.contains("spawn") && line.contains("shell: true"));
            let has_taint = line.contains("req.")
                || line.contains("request.")
                || line.contains("params.")
                || line.contains("query.")
                || line.contains("body.")
                || line.contains("searchParams");
            if has_exec && has_taint {
                emit_line_diag(
                    out,
                    file,
                    RuleId::CommandExecutionInputRisk,
                    "commandExecutionInputRisk",
                    "exec",
                    "Command execution appears to include request, query, body, or shell-interpolated input.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 4. path-traversal-risk
    if is_active(RuleId::PathTraversalRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            let has_fs = line.contains("readFile(")
                || line.contains("readFileSync(")
                || line.contains("writeFile(")
                || line.contains("writeFileSync(")
                || line.contains("path.join(")
                || line.contains("path.resolve(");
            let has_taint = line.contains("req.")
                || line.contains("request.")
                || line.contains("params.")
                || line.contains("query.")
                || line.contains("body.");
            if has_fs && has_taint && !line.contains("basename(") {
                emit_line_diag(
                    out,
                    file,
                    RuleId::PathTraversalRisk,
                    "pathTraversalRisk",
                    "path",
                    "Filesystem access appears to use request, query, params, or body data as part of the path.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 5. untrusted-redirect-following
    if is_active(RuleId::UntrustedRedirectFollowing).is_some()
        && !src.contains("redirect: \"manual\"")
        && !src.contains("redirect: 'manual'")
        && !src.contains("redirect: \"error\"")
    {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("fetch(") || line.contains("axios.get(") || line.contains("got("))
                && (line.contains("req.")
                    || line.contains("request.")
                    || line.contains("searchParams")
                    || line.contains("targetUrl")
                    || line.contains("callbackUrl")
                    || line.contains("redirectUrl")
                    || line.contains("webhookUrl"))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::UntrustedRedirectFollowing,
                    "untrustedRedirectFollowing",
                    "fetch",
                    "Server-side fetch code appears to follow redirects for a URL shaped like caller-controlled input.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 6. clickjacking-redirect-risk & svg-filter-clickjacking-risk
    if is_active(RuleId::ClickjackingRedirectRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            let is_unsafe_redirect = line.contains("redirect(")
                && (line.contains("searchParams.get")
                    || line.contains("nextUrl.searchParams")
                    || line.contains("returnTo")
                    || line.contains("callbackUrl"))
                && !line.contains("safe")
                && !line.contains("valid")
                && !line.contains("allowlist");
            let is_unsafe_frame = line.contains("frame-ancestors *")
                || line.contains("X-Frame-Options: ALLOW")
                || line.contains("\"X-Frame-Options\": \"ALLOW\"");
            if is_unsafe_redirect || is_unsafe_frame {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ClickjackingRedirectRisk,
                    "clickjackingRedirectRisk",
                    "redirect",
                    "Redirect or framing configuration may let attacker-controlled URLs chain into privileged UI or clickjacking.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
    if is_active(RuleId::SvgFilterClickjackingRisk).is_some()
        && src.contains("<iframe")
        && (src.contains("filter: url(#")
            || src.contains("filter:url(#")
            || src.contains("<feDisplacementMap"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::SvgFilterClickjackingRisk,
            "svgFilterClickjackingRisk",
            "iframe",
            "An iframe is rendered through an SVG/CSS filter, which can support advanced clickjacking or visual exfiltration tricks.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    // 7. jwt-insecure-verification
    if is_active(RuleId::JwtInsecureVerification).is_some()
        && (src.contains("jwt") || src.contains("jsonwebtoken") || src.contains("jose"))
    {
        for (idx, line) in src.lines().enumerate() {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let lower = compact.to_ascii_lowercase();
            if lower.contains("alg:\"none\"")
                || lower.contains("alg:'none'")
                || lower.contains("algorithms:[\"none\"]")
                || lower.contains("algorithms:['none']")
                || lower.contains("algorithm:\"none\"")
                || lower.contains("algorithm:'none'")
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::JwtInsecureVerification,
                    "jwtInsecureVerification",
                    "none",
                    "JWT is configured with the 'none' algorithm, which disables signature verification, so any forged token is accepted.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 8. insecure-crypto-risk
    if is_active(RuleId::InsecureCryptoRisk).is_some() {
        let lower_src = src.to_ascii_lowercase();
        let has_sec_ctx = [
            "password",
            "token",
            "secret",
            "signature",
            "auth",
            "credential",
            "session",
            "cookie",
            "csrf",
        ]
        .iter()
        .any(|w| lower_src.contains(w));
        for (idx, line) in src.lines().enumerate() {
            let lower_line = line.to_ascii_lowercase();
            let is_weak_hash = (lower_line.contains("createhash(\"md5\")")
                || lower_line.contains("createhash('md5')")
                || lower_line.contains("createhash(\"sha1\")")
                || lower_line.contains("createhash('sha1')")
                || lower_line.contains("md5("))
                && has_sec_ctx;
            let is_weak_cipher = lower_line.contains("createcipher(")
                || lower_line.contains("createdecipher(")
                || lower_line.contains("createcipheriv(\"des")
                || lower_line.contains("createcipheriv(\"rc4");
            let is_math_random_secret = line.contains("Math.random(")
                && [
                    "token", "secret", "password", "nonce", "salt", "csrf", "otp",
                ]
                .iter()
                .any(|w| lower_line.contains(w));
            if is_weak_hash || is_weak_cipher || is_math_random_secret {
                emit_line_diag(
                    out,
                    file,
                    RuleId::InsecureCryptoRisk,
                    "insecureCryptoRisk",
                    "crypto",
                    "Weak cryptographic primitive or non-cryptographic randomness used in a security-sensitive context.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 9. insecure-session-cookie
    if is_active(RuleId::InsecureSessionCookie).is_some() {
        for (idx, line) in src.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let is_cookie_set = lower.contains(".cookie(")
                || lower.contains(".cookies.set(")
                || lower.contains("cookies().set(")
                || lower.contains("document.cookie");
            let has_auth_name = [
                "session",
                "sess",
                "sid",
                "auth",
                "jwt",
                "access_token",
                "refresh_token",
                "id_token",
            ]
            .iter()
            .any(|w| lower.contains(w));
            let is_insecure = lower.contains("httponly: false")
                || lower.contains("httponly:false")
                || lower.contains("document.cookie");
            if is_cookie_set && has_auth_name && is_insecure {
                emit_line_diag(
                    out,
                    file,
                    RuleId::InsecureSessionCookie,
                    "insecureSessionCookie",
                    "cookie",
                    "Auth or session cookie is set with `httpOnly: false` or via `document.cookie`, making it readable by XSS.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 10. webhook-signature-risk
    if is_active(RuleId::WebhookSignatureRisk).is_some() {
        let lower_path = path_str.to_ascii_lowercase();
        let lower_src = src.to_ascii_lowercase();
        let is_webhook_file =
            lower_path.contains("webhook") || lower_src.contains("webhookhandler");
        let has_post_handler = src.contains("function POST")
            || src.contains("const POST")
            || src.contains("webhookHandler");
        let has_req_read = src.contains("request.") || src.contains("req.");
        let has_verification = [
            "verifysignature",
            "constructevent",
            "createhmac",
            "timingsafeequal",
            "svix",
            "webhooksecret",
            "stripe.webhooks",
            "signature",
        ]
        .iter()
        .any(|w| lower_src.contains(w));
        if is_webhook_file && has_post_handler && has_req_read && !has_verification {
            let line_idx = src
                .lines()
                .position(|l| l.contains("POST") || l.contains("webhook"))
                .unwrap_or(0);
            emit_line_diag(
                out,
                file,
                RuleId::WebhookSignatureRisk,
                "webhookSignatureRisk",
                "POST",
                "Webhook handler code does not show an obvious signature verification step.",
                line_idx,
                src.lines().nth(line_idx).unwrap_or(""),
                line_starts,
            );
        }
    }

    // 11. postmessage-origin-risk
    if is_active(RuleId::PostmessageOriginRisk).is_some()
        && (src.contains("addEventListener(\"message\"")
            || src.contains("addEventListener('message'")
            || src.contains("window.onmessage"))
        && (src.contains("event.data") || src.contains("e.data") || src.contains("msg.data"))
        && !src.contains(".origin")
        && !src.contains("Origin")
        && !src.contains(".source")
    {
        let line_idx = src.lines().position(|l| l.contains("message")).unwrap_or(0);
        emit_line_diag(
            out,
            file,
            RuleId::PostmessageOriginRisk,
            "postmessageOriginRisk",
            "message",
            "`postMessage` listener reads `event.data` without validating `event.origin`.",
            line_idx,
            src.lines().nth(line_idx).unwrap_or(""),
            line_starts,
        );
    }

    // 12. cors-cookie-trust-risk
    if is_active(RuleId::CorsCookieTrustRisk).is_some()
        && src.contains("Access-Control-Allow-Credentials")
        && src.contains("true")
        && src.contains("Access-Control-Allow-Origin")
        && (src.contains("\"*\"") || src.contains("'*'") || src.contains("https://docs."))
    {
        let line_idx = src
            .lines()
            .position(|l| l.contains("Access-Control-Allow-"))
            .unwrap_or(0);
        emit_line_diag(
            out,
            file,
            RuleId::CorsCookieTrustRisk,
            "corsCookieTrustRisk",
            "Access-Control-Allow-Origin",
            "Credentialed CORS or broad auth-cookie scope can make a docs/custom-domain XSS become account compromise.",
            line_idx,
            src.lines().nth(line_idx).unwrap_or(""),
            line_starts,
        );
    }

    // 13. request-body-mass-assignment
    if is_active(RuleId::RequestBodyMassAssignment).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("...req.body")
                || line.contains("...request.body")
                || line.contains("...req.query")
                || (line.contains("Object.assign(")
                    && (line.contains("req.body") || line.contains("request.body")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::RequestBodyMassAssignment,
                    "requestBodyMassAssignment",
                    "req.body",
                    "Request input is spread or merged into an object without a field allowlist, enabling mass assignment or prototype pollution.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 14. supabase-table-missing-rls & supabase-rls-policy-risk & supabase-client-owned-authz-field
    if is_active(RuleId::SupabaseTableMissingRls).is_some() && path_str.ends_with(".sql") {
        check_supabase_table_missing_rls(file, line_starts, out);
    }
    if is_active(RuleId::SupabaseRlsPolicyRisk).is_some() && path_str.ends_with(".sql") {
        check_supabase_rls_policy_risk(file, line_starts, out);
    }
    if is_active(RuleId::SupabaseClientOwnedAuthzField).is_some() && !file.module.has_use_server {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("supabase") || line.contains(".from("))
                && (line.contains(".insert(")
                    || line.contains(".update(")
                    || line.contains(".upsert("))
                && [
                    "ownerId",
                    "creatorId",
                    "userId",
                    "orgId",
                    "tenantId",
                    "role",
                    "isAdmin",
                ]
                .iter()
                .any(|f| line.contains(f))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::SupabaseClientOwnedAuthzField,
                    "supabaseClientOwnedAuthzField",
                    "supabase",
                    "Client Supabase code appears to write user, tenant, owner, or role fields that should be enforced by RLS.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 15. firebase-permissive-rules, firebase-client-owned-authz-field, firebase-query-filter-as-auth
    if is_active(RuleId::FirebasePermissiveRules).is_some() && path_str.ends_with(".rules") {
        for (idx, line) in src.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("allow ")
                && (lower.contains("if true") || lower.contains("request.auth != null"))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::FirebasePermissiveRules,
                    "firebasePermissiveRules",
                    "allow",
                    "Firebase rules grant broad access to everyone or to any signed-in user.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
    if is_active(RuleId::FirebaseClientOwnedAuthzField).is_some()
        && (src.contains("firebase")
            || src.contains("firestore")
            || src.contains("setDoc(")
            || src.contains("updateDoc(")
            || src.contains("addDoc("))
    {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("setDoc(")
                || line.contains("updateDoc(")
                || line.contains("addDoc(")
                || line.contains(".set(")
                || line.contains(".update("))
                && [
                    "ownerId",
                    "creatorId",
                    "orgId",
                    "tenantId",
                    "workspaceId",
                    "role",
                    "roles",
                    "isAdmin",
                ]
                .iter()
                .any(|f| line.contains(f))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::FirebaseClientOwnedAuthzField,
                    "firebaseClientOwnedAuthzField",
                    "firestore",
                    "Client code writes an ownership, tenant, or role field that should be server-owned and immutable.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
    if is_active(RuleId::FirebaseQueryFilterAsAuth).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains(".where(")
                && (line.contains("\"==\"") || line.contains("'=='"))
                && ["uid", "userId", "ownerId", "orgId", "tenantId", "role"]
                    .iter()
                    .any(|f| line.contains(&format!("\"{f}\"")) || line.contains(&format!("'{f}'")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::FirebaseQueryFilterAsAuth,
                    "firebaseQueryFilterAsAuth",
                    "where",
                    "Firestore query code filters by an auth-shaped field; filtering is not authorization unless rules enforce the same boundary.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 16. mcp-tool-capability-risk & agent-tool-capability-risk
    let has_dangerous_cap = [
        "exec(",
        "execSync(",
        "spawn(",
        "child_process",
        "eval(",
        "new Function",
        "vm.run",
        "readFile",
        "writeFile",
        "fetch(",
    ]
    .iter()
    .any(|c| src.contains(c));
    if is_active(RuleId::McpToolCapabilityRisk).is_some()
        && has_dangerous_cap
        && (src.contains("@modelcontextprotocol/sdk")
            || src.contains("McpServer")
            || src.contains("McpAgent"))
    {
        for (idx, line) in src.lines().enumerate() {
            if line.contains(".tool(")
                || line.contains("registerTool(")
                || line.contains("CallToolRequestSchema")
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::McpToolCapabilityRisk,
                    "mcpToolCapabilityRisk",
                    "tool",
                    "An MCP tool/resource/prompt handler appears to expose file, shell, network, or code-execution capability.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
    if is_active(RuleId::AgentToolCapabilityRisk).is_some() && has_dangerous_cap {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("createTool(")
                || line.contains("defineTool(")
                || line.contains("new DynamicTool(")
                || line.contains("new StructuredTool(")
                || line.contains("tool({")
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::AgentToolCapabilityRisk,
                    "agentToolCapabilityRisk",
                    "tool",
                    "An agent-callable tool appears to expose network, filesystem, shell, or code-execution capability.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 17. secret-in-fallback
    if is_active(RuleId::SecretInFallback).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("process.env.")
                && (line.contains("??") || line.contains("||"))
                && [
                    "SECRET",
                    "TOKEN",
                    "PASSWORD",
                    "PRIVATE_KEY",
                    "API_KEY",
                    "APIKEY",
                    "CREDENTIAL",
                    "SIGNING_KEY",
                ]
                .iter()
                .any(|w| line.contains(w))
                && (line.contains('"') || line.contains('\''))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::SecretInFallback,
                    "secretInFallback",
                    "process.env",
                    "A secret env var has a hardcoded string fallback: the literal is a committed secret and the app fails open when the variable is unset.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 18. Remaining security-scan rules (`artifact-secret-leak`, `artifact-env-leak`, `artifact-baas-authority-surface`, `build-pipeline-secret-boundary`, `local-rpc-native-bridge-risk`, `plugin-update-trust-risk`, `import-metadata-execution-risk`, `mdx-ssr-execution-risk`, `git-provider-url-injection-risk`, `key-lifecycle-risk`, `package-metadata-secret`, `public-debug-artifact`, `repository-secret-file`, `tenant-static-proxy-risk`, `url-prefilled-privileged-action`, `active-static-asset`)
    evaluate_remaining_security_scan_rules(file, path_str, line_starts, is_active, out);
}

fn evaluate_remaining_security_scan_rules<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;

    if is_active(RuleId::ArtifactSecretLeak).is_some()
        && let Some((col, _)) = find_secret_value_in_line(src)
    {
        let loc = loc_from_line_starts(line_starts, u32::try_from(col).unwrap_or(0));
        push_sec_diag(
            out,
            file,
            RuleId::ArtifactSecretLeak,
            "artifactSecretLeak",
            "artifact",
            "A browser-delivered artifact contains a secret-looking credential value.",
            loc,
            ByteSpan {
                start: u32::try_from(col).unwrap_or(0),
                end: u32::try_from(col + 16).unwrap_or(0),
            },
        );
    }

    if is_active(RuleId::ArtifactEnvLeak).is_some()
        && (find_suspicious_public_env_in_line(src).is_some()
            || (src.contains("DATABASE_URL") && src.contains("AWS_SECRET_ACCESS_KEY")))
    {
        emit_line_diag(
            out,
            file,
            RuleId::ArtifactEnvLeak,
            "artifactEnvLeak",
            "env",
            "A browser artifact contains server-secret environment names or a full environment dump shape.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::ArtifactBaasAuthoritySurface).is_some()
        && (src.contains("initializeApp") || src.contains("SUPABASE_URL"))
        && (src.contains("isAdmin") || src.contains("SuperAdmin") || src.contains("ownerId"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::ArtifactBaasAuthoritySurface,
            "artifactBaasAuthoritySurface",
            "baas",
            "A browser artifact exposes Firebase/Supabase config together with sensitive collections or authorization fields.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::BuildPipelineSecretBoundary).is_some()
        && (src.contains("npm install")
            || src.contains("pnpm install")
            || src.contains("yarn install")
            || src.contains("npm ci"))
        && !src.contains("--ignore-scripts")
        && src.contains("secrets.")
    {
        emit_line_diag(
            out,
            file,
            RuleId::BuildPipelineSecretBoundary,
            "buildPipelineSecretBoundary",
            "secrets",
            "The build or install pipeline can execute package lifecycle code while CI secrets may be present.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::LocalRpcNativeBridgeRisk).is_some()
        && (src.contains("127.0.0.1") || src.contains("localhost") || src.contains("WebSocket"))
        && (src.contains("UpdateApp") || src.contains("InstallApp") || src.contains("execSync("))
    {
        emit_line_diag(
            out,
            file,
            RuleId::LocalRpcNativeBridgeRisk,
            "localRpcNativeBridgeRisk",
            "localhost",
            "Code appears to bridge browser code to localhost/native capabilities with weak origin or update/install checks.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PluginUpdateTrustRisk).is_some()
        && ((src.contains("curl ") && (src.contains("| sh") || src.contains("| bash")))
            || (src.contains("updateUrl") && src.contains(".exe")))
        && !src.contains("sha256")
        && !src.contains("checksum")
    {
        emit_line_diag(
            out,
            file,
            RuleId::PluginUpdateTrustRisk,
            "pluginUpdateTrustRisk",
            "updater",
            "Code appears to download, install, update, or execute plugin/updater content across a trust boundary.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::ImportMetadataExecutionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("eval(")
                || line.contains("new Function(")
                || line.contains("execSync("))
                && [
                    "exif", "metadata", "manifest", "preset", "plugin", "archive",
                ]
                .iter()
                .any(|w| line.contains(w))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ImportMetadataExecutionRisk,
                    "importMetadataExecutionRisk",
                    "metadata",
                    "Imported metadata, uploads, or plugin manifests appear to reach code execution.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::MdxSsrExecutionRisk).is_some()
        && (src.contains("compileMDX") || src.contains("MDXRemote") || src.contains("evaluateMdx"))
        && (src.contains("rehypeRaw")
            || src.contains("allowDangerousHtml")
            || src.contains("untrusted")
            || src.contains("userContent")
            || src.contains("req."))
    {
        emit_line_diag(
            out,
            file,
            RuleId::MdxSsrExecutionRisk,
            "mdxSsrExecutionRisk",
            "MDX",
            "MDX/markdown rendering code may evaluate user or repository content during SSR or static generation.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::GitProviderUrlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("api.github.com")
                || line.contains("github.com")
                || line.contains("gitlab.com"))
                && line.contains("${")
                && (line.contains("req.") || line.contains("params.") || line.contains("query."))
                && !line.contains("encodeURIComponent(")
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::GitProviderUrlInjectionRisk,
                    "gitProviderUrlInjectionRisk",
                    "github.com",
                    "GitHub/GitLab/Bitbucket URL construction interpolates path components that may be attacker-controlled.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::KeyLifecycleRisk).is_some()
        && (src.contains("-----BEGIN RSA PRIVATE KEY-----")
            || src.contains("-----BEGIN PRIVATE KEY-----")
            || src.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::KeyLifecycleRisk,
            "keyLifecycleRisk",
            "PRIVATE KEY",
            "Private or long-lived release key material appears in the repository.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PackageMetadataSecret).is_some()
        && path_str.ends_with("package.json")
        && (find_secret_value_in_line(src).is_some()
            || find_suspicious_public_env_in_line(src).is_some())
    {
        emit_line_diag(
            out,
            file,
            RuleId::PackageMetadataSecret,
            "packageMetadataSecret",
            "package.json",
            "Package metadata contains secret-like values or public env secret names.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PublicDebugArtifact).is_some()
        && path_str.contains("public/")
        && (path_str.ends_with(".log")
            || path_str.ends_with(".sql")
            || path_str.ends_with(".env")
            || path_str.contains("debug"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::PublicDebugArtifact,
            "publicDebugArtifact",
            path_str,
            "A browser-reachable debug, log, dump, report, or env artifact is present.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::RepositorySecretFile).is_some()
        && (path_str.contains(".env") || path_str.ends_with(".pem"))
        && !path_str.contains("example")
        && !path_str.contains("sample")
        && (find_secret_value_in_line(src).is_some()
            || find_suspicious_public_env_in_line(src).is_some())
    {
        emit_line_diag(
            out,
            file,
            RuleId::RepositorySecretFile,
            "repositorySecretFile",
            path_str,
            "A repository credential/config file contains secret-looking values.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::TenantStaticProxyRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("fetch(")
                || line.contains("getObject(")
                || line.contains("GetObjectCommand("))
                && (line.contains("${tenant")
                    || line.contains("${subdomain")
                    || line.contains("${workspace"))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::TenantStaticProxyRisk,
                    "tenantStaticProxyRisk",
                    "tenant",
                    "Route code appears to compose tenant or subdomain input into a static/CDN/object-store fetch path.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::UrlPrefilledPrivilegedAction).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("searchParams.get(")
                && [
                    "\"role\"",
                    "'role'",
                    "\"admin\"",
                    "'admin'",
                    "\"invite\"",
                    "'invite'",
                    "\"redirect_uri\"",
                    "\"callbackUrl\"",
                ]
                .iter()
                .any(|p| line.contains(p))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::UrlPrefilledPrivilegedAction,
                    "urlPrefilledPrivilegedAction",
                    "searchParams",
                    "Client code reads sensitive action state from the URL, which can pre-fill invites, roles, redirects, or sharing flows with attacker values.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::ActiveStaticAsset).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("dangerouslyAllowSVG: true")
                || (path_str.ends_with(".svg")
                    && (line.contains("<script") || line.contains("onload=")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ActiveStaticAsset,
                    "activeStaticAsset",
                    "svg",
                    "The app enables or embeds SVG in an executable browser context.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
}

fn check_supabase_table_missing_rls(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    let lower = file.source.to_ascii_lowercase();
    let mut enabled_tables = HashSet::new();
    for line in lower.lines() {
        if let Some(pos) = line.find("alter table")
            && line.contains("enable row level security")
        {
            let after = line[pos + "alter table".len()..].trim();
            let after_if = after.strip_prefix("if exists").unwrap_or(after).trim();
            let after_only = after_if.strip_prefix("only").unwrap_or(after_if).trim();
            let table_token = after_only
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(['"', '`']);
            let table_name = table_token.strip_prefix("public.").unwrap_or(table_token);
            if !table_name.is_empty() {
                enabled_tables.insert(table_name.to_string());
            }
        }
    }

    for (idx, line) in file.source.lines().enumerate() {
        let l = line.to_ascii_lowercase();
        let Some(pos) = l.find("create table") else {
            continue;
        };
        let after = l[pos + "create table".len()..].trim();
        let after_if = after.strip_prefix("if not exists").unwrap_or(after).trim();
        let raw_table = after_if
            .split(|c: char| c.is_whitespace() || c == '(')
            .next()
            .unwrap_or("")
            .trim_matches(['"', '`']);
        if raw_table.contains('.') && !raw_table.starts_with("public.") {
            continue;
        }
        let table_name = raw_table.strip_prefix("public.").unwrap_or(raw_table);
        if !table_name.is_empty() && !enabled_tables.contains(table_name) {
            emit_line_diag(
                out,
                file,
                RuleId::SupabaseTableMissingRls,
                "supabaseTableMissingRls",
                table_name,
                &format!(
                    "Public table `{table_name}` is created without `alter table {table_name} enable row level security;`."
                ),
                idx,
                line,
                line_starts,
            );
        }
    }
}

fn check_supabase_rls_policy_risk(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    for (idx, line) in file.source.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let is_disabled = lower.contains("disable row level security");
        let is_service_role_bypass =
            lower.contains("auth.role()") && lower.contains("service_role");
        let is_permissive_write_policy = lower.contains("create policy")
            && (lower.contains("using (true)") || lower.contains("with check (true)"))
            && !lower.contains("for select")
            && !lower.contains("to service_role");
        if is_disabled || is_service_role_bypass || is_permissive_write_policy {
            emit_line_diag(
                out,
                file,
                RuleId::SupabaseRlsPolicyRisk,
                "supabaseRlsPolicyRisk",
                "policy",
                "Supabase policy SQL disables RLS, permits writes broadly, or references a service-role bypass.",
                idx,
                line,
                line_starts,
            );
        }
    }
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
        loc_from_line_starts(line_starts, byte_start),
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
        if let Some(pos) = source.find(&prefix) {
            let tail = &source[pos + prefix.len()..];
            let next_char = tail.chars().next();
            if next_char.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                continue;
            }
            let body_end = tail.find("\nexport ").unwrap_or(tail.len());
            return Some(tail[..body_end].to_string());
        }
    }
    None
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
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = s[start..].trim();
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
    let val_start = opener[attr_pos + attr.len() + 1..].trim_start();
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
                let after = tail[prop_pos + prop.len() + 1..].trim_start();
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
