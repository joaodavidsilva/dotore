//! Next.js (`nextjs-*`) rule detectors, including `nextjs-async-dynamic-api-not-awaited`,
//! `nextjs-no-img-element`, `nextjs-no-use-search-params-without-suspense`, and
//! metadata/script/link/route-handler rules.

use std::collections::HashSet;

use super::push_srv_diag;
use crate::{
    graph::ProjectGraph,
    ir::{ByteSpan, FileIr, types::loc_from_line_starts},
    rules::{
        security::{find_function_body_in_source, resolve_imported_binding},
        types::{Diagnostic, RuleId},
    },
};

pub(super) fn check_nextjs_async_dynamic_api_not_awaited(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if path_str.ends_with("sitemap.ts") || path_str.ends_with("sitemap.js") {
        return;
    }
    let src = &file.source;
    let (dynamic_callees, namespace_imports) = collect_nextjs_dynamic_api_imports(file);
    let mut pending_bindings = seed_pending_promise_prop_bindings(src);

    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("import ") {
            continue;
        }
        if check_dynamic_callees_on_line(
            file,
            src,
            idx,
            line,
            &dynamic_callees,
            &mut pending_bindings,
            line_starts,
            out,
        ) {
            continue;
        }
        if check_namespace_dynamic_calls_on_line(
            file,
            idx,
            line,
            &namespace_imports,
            line_starts,
            out,
        ) {
            continue;
        }
        propagate_pending_binding_aliases(trimmed, &mut pending_bindings);
        check_pending_bindings_sync_access_on_line(
            file,
            idx,
            line,
            &pending_bindings,
            line_starts,
            out,
        );
    }
}

fn collect_nextjs_dynamic_api_imports(file: &FileIr) -> (HashSet<String>, HashSet<String>) {
    let mut dynamic_callees: HashSet<String> = HashSet::new();
    let mut namespace_imports: HashSet<String> = HashSet::new();
    for imp in &file.module.imports {
        if imp.source == "next/headers" && !imp.is_type_only {
            for b in &imp.bindings {
                if b.is_namespace {
                    namespace_imports.insert(b.local_name.clone());
                } else if matches!(
                    b.imported_name.as_str(),
                    "cookies" | "headers" | "draftMode"
                ) {
                    dynamic_callees.insert(b.local_name.clone());
                }
            }
        }
    }
    (dynamic_callees, namespace_imports)
}

fn seed_pending_promise_prop_bindings(src: &str) -> HashSet<String> {
    let mut pending_bindings: HashSet<String> = HashSet::new();
    if src.contains("params:")
        && src.contains("Promise<")
        && !src.contains("await params")
        && !src.contains("use(params)")
    {
        pending_bindings.insert("params".to_string());
    }
    if src.contains("searchParams:")
        && src.contains("Promise<")
        && !src.contains("await searchParams")
        && !src.contains("use(searchParams)")
    {
        pending_bindings.insert("searchParams".to_string());
    }
    pending_bindings
}

#[expect(
    clippy::too_many_arguments,
    reason = "Scans a source line for synchronous consumption or local assignment of dynamic Next.js APIs (#50)"
)]
fn check_dynamic_callees_on_line(
    file: &FileIr,
    src: &str,
    idx: usize,
    line: &str,
    dynamic_callees: &HashSet<String>,
    pending_bindings: &mut HashSet<String>,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) -> bool {
    for callee in dynamic_callees {
        let call_token = format!("{callee}()");
        let Some(call_pos) = line.find(&call_token) else {
            continue;
        };
        let before = line[..call_pos].trim_end();
        let after = line[call_pos + call_token.len()..].trim_start();
        if before.ends_with("await") || before.ends_with("use(") {
            continue;
        }
        if is_sync_dynamic_call_consumption(src, before, after) {
            emit_dynamic_api_diag(out, file, callee, idx, line, line_starts);
            return true;
        }
        if let Some(lhs_ident) = extract_assigned_ident_before(before) {
            pending_bindings.insert(lhs_ident);
        }
    }
    false
}

fn is_sync_dynamic_call_consumption(src: &str, before: &str, after: &str) -> bool {
    let is_direct_member = (after.starts_with('.') || after.starts_with("?."))
        && ![".then(", ".catch(", ".finally("]
            .iter()
            .any(|p| after.starts_with(p));
    let is_spread_or_iter = before.ends_with("...")
        || [
            "for (",
            "Object.keys(",
            "Object.values(",
            "Object.entries(",
            "Object.fromEntries(",
            "Object.assign(",
            "Reflect.ownKeys(",
            "Array.from(",
        ]
        .iter()
        .any(|p| before.contains(p))
        || (before.contains("new Map(") && !src.contains("(Map)"))
        || (before.contains("new Set(") && !src.contains("(Set)"));
    let is_destructured = (before.contains('{') || before.contains('['))
        && before.ends_with('=')
        && !is_only_promise_settlement_destructure(before);
    is_direct_member || is_spread_or_iter || is_destructured
}

fn check_namespace_dynamic_calls_on_line(
    file: &FileIr,
    idx: usize,
    line: &str,
    namespace_imports: &HashSet<String>,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) -> bool {
    for ns in namespace_imports {
        let Some(ns_pos) = line.find(ns.as_str()) else {
            continue;
        };
        let after_ns = line.get(ns_pos + ns.len()..).unwrap_or_default();
        if (after_ns.starts_with('.') || after_ns.starts_with('['))
            && after_ns.contains("().")
            && !line
                .get(..ns_pos)
                .unwrap_or_default()
                .trim_end()
                .ends_with("await")
        {
            emit_dynamic_api_diag(out, file, ns, idx, line, line_starts);
            return true;
        }
    }
    false
}

fn propagate_pending_binding_aliases(trimmed: &str, pending_bindings: &mut HashSet<String>) {
    let Some(eq_pos) = trimmed.find('=') else {
        return;
    };
    if trimmed[eq_pos + 1..].starts_with('=') {
        return;
    }
    let lhs = trimmed[..eq_pos].trim();
    let rhs = trimmed[eq_pos + 1..].trim();
    if rhs.contains("await ") {
        return;
    }
    let mut new_aliases = Vec::new();
    for existing in pending_bindings.iter() {
        if rhs.starts_with(existing.as_str())
            && let Some(alias_id) = extract_assigned_ident_before(&format!("{lhs} ="))
        {
            new_aliases.push(alias_id);
        }
    }
    pending_bindings.extend(new_aliases);
}

fn check_pending_bindings_sync_access_on_line(
    file: &FileIr,
    idx: usize,
    line: &str,
    pending_bindings: &HashSet<String>,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    for pending in pending_bindings {
        if line_synchronously_consumes_pending_binding(line, pending) {
            emit_dynamic_api_diag(out, file, pending, idx, line, line_starts);
            return;
        }
    }
}

fn line_synchronously_consumes_pending_binding(line: &str, pending: &str) -> bool {
    let dot_access = format!("{pending}.");
    let opt_access = format!("{pending}?.");
    let cast_access = format!("{pending} as ");
    let has_sync_member = (line.contains(&dot_access)
        && !line.contains(&format!("{pending}.then"))
        && !line.contains(&format!("{pending}.catch"))
        && !line.contains(&format!("{pending}.finally")))
        || line.contains(&opt_access)
        || (line.contains(&cast_access) && line.contains(")."));
    let has_destructure = line.contains(" = ")
        && line.contains(pending)
        && (line.contains('{') || line.contains('['))
        && !line.contains(&format!("await {pending}"))
        && !is_only_promise_settlement_destructure(line);
    let has_spread_or_enum = [
        format!("...{pending}"),
        format!("of {pending}"),
        format!("in {pending}"),
        format!("yield* {pending}"),
        format!("Object.keys({pending})"),
        format!("new Set({pending})"),
        format!("new Map({pending})"),
    ]
    .iter()
    .any(|p| line.contains(p));

    has_sync_member || has_destructure || has_spread_or_enum
}

fn is_only_promise_settlement_destructure(text: &str) -> bool {
    let Some(open) = text.rfind('{') else {
        return false;
    };
    let Some(close) = text[open..].find('}') else {
        return false;
    };
    let inside = text[open + 1..open + close].trim();
    if inside.is_empty() {
        return true;
    }
    if inside.contains("...") {
        return false;
    }
    inside.split(',').all(|part| {
        let key = part
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(['[', ']', '"', '\'']);
        matches!(key, "then" | "catch" | "finally")
    })
}

fn extract_assigned_ident_before(before_call: &str) -> Option<String> {
    let trimmed = before_call.trim_end();
    let without_eq = trimmed.strip_suffix('=')?.trim_end();
    let ident: String = without_eq
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

fn emit_dynamic_api_diag(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    target: &str,
    line_idx: usize,
    line: &str,
    line_starts: &[u32],
) {
    let first_non_ws = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
    let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
    let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
    push_srv_diag(
        out,
        file,
        None,
        RuleId::NextjsAsyncDynamicApiNotAwaited,
        "nextjsAsyncDynamicApiNotAwaited",
        target,
        "This Next.js request API returns a Promise. Synchronous property access warns in Next.js 15 and is removed in Next.js 16; await it or unwrap it with React `use()`.",
        loc_from_line_starts(line_starts, byte_start),
        ByteSpan {
            start: byte_start,
            end: byte_end,
        },
    );
}

pub(super) fn check_nextjs_no_img_element(
    graph: &ProjectGraph,
    file: &FileIr,
    out: &mut Vec<Diagnostic>,
) {
    if file_is_generated_image_or_email_context(&file.source)
        || is_file_exclusively_consumed_by_image_response(graph, file)
    {
        return;
    }

    for jsx in &file.jsx_elements {
        if jsx.name != "img" {
            continue;
        }
        let span_start = usize::try_from(jsx.span.start).unwrap_or(0);
        let span_end = usize::try_from(jsx.span.end).unwrap_or(0);
        let tag_text = file
            .source
            .get(span_start..span_end.min(file.source.len()))
            .unwrap_or("");
        if [
            "src=\"data:",
            "src='data:",
            "src=\"blob:",
            "src='blob:",
            "scarf.sh/",
        ]
        .iter()
        .any(|p| tag_text.contains(p))
        {
            continue;
        }
        push_srv_diag(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::NextjsNoImgElement,
            "nextjsNoImgElement",
            "img",
            "Prefer `<Image />` from `next/image` over raw `<img>` in Next.js.",
            jsx.loc,
            jsx.span,
        );
    }
}

fn file_is_generated_image_or_email_context(source: &str) -> bool {
    [
        "ImageResponse",
        "from \"satori\"",
        "from 'satori'",
        "@react-email/",
        "from \"react-email\"",
        "createObjectURL(",
        ".toDataURL(",
        ".readAsDataURL(",
    ]
    .iter()
    .any(|p| source.contains(p))
}

fn is_file_exclusively_consumed_by_image_response(
    graph: &ProjectGraph,
    target_file: &FileIr,
) -> bool {
    if target_file.module.exports.is_empty() {
        return false;
    }
    let mut found_consumer = false;
    for other_file in &graph.files {
        if other_file.path == target_file.path {
            continue;
        }
        if let Some(is_img_ctx) =
            file_imports_target_for_image_response(graph, other_file, &target_file.path)
        {
            if is_img_ctx {
                found_consumer = true;
            } else {
                return false;
            }
        }
    }
    found_consumer
}

fn file_imports_target_for_image_response(
    graph: &ProjectGraph,
    other_file: &FileIr,
    target_path: &std::path::Path,
) -> Option<bool> {
    let mut matched = false;
    for imp in &other_file.module.imports {
        if imp.is_type_only {
            continue;
        }
        for b in &imp.bindings {
            let exported = if b.is_default {
                "default"
            } else {
                b.imported_name.as_str()
            };
            if let Some((resolved_file, _)) =
                graph.resolve_exported_symbol(&other_file.path, &imp.source, exported)
                && resolved_file.path == target_path
            {
                matched = true;
            }
        }
    }
    matched.then(|| file_is_generated_image_or_email_context(&other_file.source))
}

pub(super) fn check_nextjs_no_use_search_params_without_suspense(
    graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let norm = format!("/{}", path_str.trim_start_matches('/'));
    let is_page_or_layout = norm.contains("/page.") || norm.contains("/layout.");
    if !is_page_or_layout || has_ancestor_suspense_layout(graph, &file.path) {
        return;
    }

    if file.source.contains("useSearchParams(") && !file_contains_suspense_boundary(&file.source) {
        let pos = file.source.find("useSearchParams(").unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsNoUseSearchParamsWithoutSuspense,
            "nextjsNoUseSearchParamsWithoutSuspense",
            "useSearchParams",
            "`useSearchParams()` in a Next.js page/layout without a `<Suspense>` boundary forces the route into client-side rendering.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 17,
            },
        );
        return;
    }

    if !norm.contains("/page.") {
        return;
    }
    let suspense_names = collect_suspense_component_names(file);
    for jsx in &file.jsx_elements {
        if !jsx.is_component {
            continue;
        }
        let is_wrapped = jsx
            .ancestor_elements
            .iter()
            .any(|anc| suspense_names.contains(anc.as_str()) || anc.ends_with(".Suspense"));
        if !is_wrapped
            && let Some((target_file, target_local)) = resolve_imported_binding(graph, file, &jsx.name)
            && component_calls_use_search_params(target_file, &target_local)
        {
            push_srv_diag(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::NextjsNoUseSearchParamsWithoutSuspense,
                "nextjsNoUseSearchParamsWithoutSuspense",
                &jsx.name,
                &format!(
                    "`<{}>` calls `useSearchParams()` without an enclosing `<Suspense>` boundary.",
                    jsx.name
                ),
                jsx.loc,
                jsx.span,
            );
        }
    }
}

fn collect_suspense_component_names(file: &FileIr) -> HashSet<String> {
    let mut names = HashSet::from(["Suspense".to_string(), "React.Suspense".to_string()]);
    for imp in &file.module.imports {
        if imp.source == "react" {
            for b in &imp.bindings {
                if b.imported_name == "Suspense" {
                    names.insert(b.local_name.clone());
                }
            }
        }
    }
    names
}

fn file_contains_suspense_boundary(src: &str) -> bool {
    src.contains("<Suspense") || src.contains("<React.Suspense")
}

fn component_calls_use_search_params(file: &FileIr, component_name: &str) -> bool {
    if let Some(body) = find_function_body_in_source(&file.source, component_name) {
        return body.contains("useSearchParams(") && !file_contains_suspense_boundary(&body);
    }
    file.source.contains("useSearchParams(") && !file_contains_suspense_boundary(&file.source)
}

fn has_ancestor_suspense_layout(graph: &ProjectGraph, page_path: &std::path::Path) -> bool {
    let mut cur = page_path.parent();
    while let Some(dir) = cur {
        for candidate_file in &graph.files {
            if candidate_file.path.parent() == Some(dir)
                && candidate_file
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("layout."))
                && file_contains_suspense_boundary(&candidate_file.source)
            {
                return true;
            }
        }
        cur = dir.parent();
    }
    false
}

pub(super) fn check_nextjs_no_side_effect_in_get_handler(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let lower_path = path_str.to_ascii_lowercase();
    if ["/callback", "/verify", "/confirm", "/magic-link", "/cron"]
        .iter()
        .any(|p| lower_path.contains(p))
    {
        return;
    }
    let Some(get_body) = find_function_body_in_source(&file.source, "GET") else {
        return;
    };
    let has_side_effect = [
        ".delete(",
        ".set(",
        ".insert(",
        ".update(",
        ".upsert(",
        ".create(",
        ".destroy(",
        "method: \"POST\"",
        "method: 'POST'",
        "method: \"DELETE\"",
    ]
    .iter()
    .any(|m| get_body.contains(m));
    if has_side_effect {
        let pos = file.source.find("GET").unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            Some("GET".to_string()),
            RuleId::NextjsNoSideEffectInGetHandler,
            "nextjsNoSideEffectInGetHandler",
            "GET",
            "GET route handler performs a state-changing side effect. Move mutations to a POST handler.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 3,
            },
        );
    }
}

