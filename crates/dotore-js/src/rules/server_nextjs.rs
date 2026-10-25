//! Server (`server-*`) and Next.js (`nextjs-*`) rule detectors, including
//! `server-auth-actions`, `server-sequential-independent-await` with cross-file
//! cached async awareness (`React.cache()`, `"use cache"`, guarded `WeakMap`/`Map` caches),
//! `nextjs-async-dynamic-api-not-awaited`, `nextjs-no-img-element` with cross-file
//! `ImageResponse`/`satori` wrapper awareness, and `nextjs-no-use-search-params-without-suspense`
//! with cross-file `<Suspense>` caller and layout awareness.

mod nextjs_metadata_and_jsx;
mod nextjs_rules;

use std::collections::HashSet;

use self::{
    nextjs_metadata_and_jsx::{
        check_nextjs_async_client_component, check_nextjs_no_head_import,
        check_nextjs_no_script_in_head, check_nextjs_no_vercel_og_import,
        evaluate_remaining_nextjs_rules,
    },
    nextjs_rules::{
        check_nextjs_async_dynamic_api_not_awaited, check_nextjs_no_img_element,
        check_nextjs_no_side_effect_in_get_handler,
        check_nextjs_no_use_search_params_without_suspense,
    },
};
use crate::{
    config::DotoreConfig,
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, SourceLoc,
        types::{compute_line_starts, loc_from_line_starts},
    },
    matchers::{make_diag_at_offset, make_diag_for_subject},
    rules::{
        security::{
            find_function_body_in_source, resolve_imported_binding, split_balanced_parens,
            split_top_level_args,
        },
        types::{Diagnostic, RuleId, RuleSeverity},
    },
};
const BUILTIN_AUTH_GUARDS: &[&str] = &[
    "auth(",
    "getSession(",
    "getServerSession(",
    "verifySession(",
    "requireSession(",
    "requireAuth(",
    "requireUser(",
    "requireAdmin(",
    "ensureAuthenticated(",
    "ensureSignedIn(",
    "checkAuth(",
    "verifyAuth(",
    "verifyToken(",
    "currentUser(",
    "getCurrentUser(",
    "getUser(",
    "validateRequest(",
    "withAuth(",
    "protectedAction(",
];

const CREDENTIAL_ESTABLISHING_ACTION_TOKENS: &[&str] = &[
    "login",
    "signin",
    "signup",
    "register",
    "resetpassword",
    "forgotpassword",
    "verifyotp",
    "verifyemail",
    "verifyauthcode",
    "emailverification",
    "passwordreset",
    "oauthcallback",
    "handleoauthcallback",
    "magiclink",
];

/// Evaluates all `server-*` and `nextjs-*` rules on `file` using `graph` and `config`.
pub(crate) fn evaluate_server_and_nextjs_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    config: &DotoreConfig,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let line_starts = compute_line_starts(&file.source);
    let path_str = file.path.to_string_lossy().replace('\\', "/");

    evaluate_server_rules(graph, file, config, &path_str, &line_starts, is_active, out);
    evaluate_core_nextjs_rules(graph, file, &path_str, &line_starts, is_active, out);
    evaluate_remaining_nextjs_rules(graph, file, &path_str, &line_starts, is_active, out);
}

fn evaluate_server_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    config: &DotoreConfig,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if is_active(RuleId::ServerAuthActions).is_some() {
        check_server_auth_actions(file, config, line_starts, out);
    }
    if is_active(RuleId::ServerSequentialIndependentAwait).is_some() {
        check_server_sequential_independent_await(graph, file, line_starts, out);
    }
    if is_active(RuleId::ServerNoMutableModuleState).is_some() {
        check_server_no_mutable_module_state(file, line_starts, out);
    }
    if is_active(RuleId::ServerHoistStaticIo).is_some() {
        check_server_hoist_static_io(file, path_str, line_starts, out);
    }
    if is_active(RuleId::ServerFetchWithoutRevalidate).is_some() {
        check_server_fetch_without_revalidate(file, path_str, line_starts, out);
    }
    if is_active(RuleId::ServerAfterNonblocking).is_some() {
        check_server_after_nonblocking(file, path_str, line_starts, out);
    }
    if is_active(RuleId::ServerDedupProps).is_some() {
        check_server_dedup_props(file, line_starts, out);
    }
    if is_active(RuleId::ServerCacheWithObjectLiteral).is_some() {
        check_server_cache_with_object_literal(file, line_starts, out);
    }
}

fn evaluate_core_nextjs_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if is_active(RuleId::NextjsAsyncDynamicApiNotAwaited).is_some() {
        check_nextjs_async_dynamic_api_not_awaited(file, path_str, line_starts, out);
    }
    if is_active(RuleId::NextjsNoImgElement).is_some() {
        check_nextjs_no_img_element(graph, file, out);
    }
    if is_active(RuleId::NextjsNoUseSearchParamsWithoutSuspense).is_some() {
        check_nextjs_no_use_search_params_without_suspense(
            graph,
            file,
            path_str,
            line_starts,
            out,
        );
    }
    if is_active(RuleId::NextjsNoSideEffectInGetHandler).is_some() {
        check_nextjs_no_side_effect_in_get_handler(file, path_str, line_starts, out);
    }
    if is_active(RuleId::NextjsNoScriptInHead).is_some() {
        check_nextjs_no_script_in_head(file, out);
    }
    if is_active(RuleId::NextjsNoHeadImport).is_some() {
        check_nextjs_no_head_import(file, path_str, out);
    }
    if is_active(RuleId::NextjsNoVercelOgImport).is_some() {
        check_nextjs_no_vercel_og_import(file, out);
    }
    if is_active(RuleId::NextjsAsyncClientComponent).is_some() {
        check_nextjs_async_client_component(file, line_starts, out);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Direct diagnostic constructor avoids intermediate allocations"
)]
pub(super) fn push_srv_diag(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    subject_name: Option<String>,
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
        subject_name,
        message_id,
        target_name,
        message,
        loc,
        span,
    ));
}

fn check_server_auth_actions(
    file: &FileIr,
    config: &DotoreConfig,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    for sink in &file.security_sinks {
        if sink.kind != crate::ir::SecuritySinkKind::UnauthenticatedServerAction {
            continue;
        }
        let action_name = &sink.target_name;
        if is_exempt_server_action(file, action_name, config) {
            continue;
        }
        push_srv_diag(
            out,
            file,
            sink.subject_name.clone(),
            RuleId::ServerAuthActions,
            "serverAuthActions",
            action_name,
            &format!(
                "Exported Server Action {action_name:?} performs privileged server work without an authentication/authorization guard."
            ),
            sink.loc,
            sink.span,
        );
    }

    let _ = line_starts;
}

fn is_exempt_server_action(file: &FileIr, action_name: &str, config: &DotoreConfig) -> bool {
    let normalized_name: String = action_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();

    // 1. Public-named actions (`getPostPublicAction`) or credential-establishing actions (`login`, `signup`, `resetPassword`, `verifyOtp`)
    if normalized_name.contains("public") {
        return true;
    }
    if CREDENTIAL_ESTABLISHING_ACTION_TOKENS
        .iter()
        .any(|tok| normalized_name.starts_with(tok) || normalized_name == *tok)
    {
        return true;
    }

    let Some(body) = find_function_body_in_source(&file.source, action_name) else {
        return false;
    };

    // 2. Custom `serverAuthFunctionNames` or built-in auth guards
    if BUILTIN_AUTH_GUARDS.iter().any(|g| body.contains(g)) {
        return true;
    }
    if config
        .server_auth_function_names
        .iter()
        .any(|custom| body.contains(&format!("{custom}(")))
    {
        return true;
    }

    // 3. Neutral credential-establishing action (`createAccountAction`) calling `.auth.signUp` / `auth.signUp` / `resetPasswordForEmail`
    if (normalized_name.contains("account") || normalized_name.contains("auth"))
        && (body.contains(".signUp(")
            || body.contains(".signIn")
            || body.contains(".verifyOtp(")
            || body.contains(".resetPasswordForEmail("))
        && !body.contains(".delete(")
    {
        return true;
    }

    // 4. Read-only / cache-revalidation-only action (no privileged write, no delete/update/insert/create/set, no secret leak)
    let has_mutation = [
        ".insert(",
        ".update(",
        ".delete(",
        ".upsert(",
        ".create(",
        ".destroy(",
        ".remove(",
        ".execute(",
        ".set(",
        "writeFile",
        "unlink",
        "fetch(",
        "stripe.",
        "resend.",
        "sendEmail",
    ]
    .iter()
    .any(|m| body.contains(m));

    !has_mutation
}

fn check_server_sequential_independent_await(
    graph: &ProjectGraph,
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let lines: Vec<&str> = file.source.lines().collect();
    let mut idx = 0;
    while idx + 1 < lines.len() {
        let first_line = lines[idx].trim();
        let second_line = lines[idx + 1].trim();
        if let Some((first_bindings, first_awaited)) = parse_awaited_var_decl(first_line)
            && let Some((_second_bindings, second_awaited)) = parse_awaited_var_decl(second_line)
        {
            let second_reads_first = first_bindings
                .iter()
                .any(|b| expression_mentions_identifier(second_awaited, b));
            let awaits_existing_promise = is_bare_or_member_identifier(second_awaited);
            let is_request_scoped =
                is_request_scoped_await(first_awaited) || is_request_scoped_await(second_awaited);
            let is_gate = is_gate_await(first_awaited);
            let shares_cached_work =
                awaited_calls_share_cached_work(graph, file, first_awaited, second_awaited);

            if !second_reads_first
                && !awaits_existing_promise
                && !is_request_scoped
                && !is_gate
                && !shares_cached_work
            {
                let raw_second = lines[idx + 1];
                let first_non_ws = raw_second.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                let line_start = line_starts.get(idx + 1).copied().unwrap_or(0);
                let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
                let byte_end = line_start + u32::try_from(raw_second.len()).unwrap_or(0);
                out.push(
                    make_diag_at_offset(
                        RuleId::ServerSequentialIndependentAwait,
                        file.path.clone(),
                        line_starts,
                        oxc_span::Span::new(byte_start, byte_end),
                        "This awaited initializer does not read the previous result. If the operations are independent asynchronous work, they may overlap with `Promise.all([...])`.",
                    )
                    .with_message_id("serverSequentialIndependentAwait")
                    .with_target_name(second_awaited),
                );
                idx += 2;
                continue;
            }
        }
        idx += 1;
    }
}

fn parse_awaited_var_decl(trimmed_line: &str) -> Option<(Vec<String>, &str)> {
    let rest = trimmed_line
        .strip_prefix("const ")
        .or_else(|| trimmed_line.strip_prefix("let "))
        .or_else(|| trimmed_line.strip_prefix("var "))?;
    let (lhs, rhs) = rest.split_once('=')?;
    if rhs.starts_with('=') {
        return None;
    }
    let rhs_trimmed = rhs.trim().trim_end_matches(';').trim();
    let awaited = rhs_trimmed.strip_prefix("await ")?.trim();
    let mut bindings = Vec::new();
    for token in lhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$') {
        if !token.is_empty() {
            bindings.push(token.to_string());
        }
    }
    Some((bindings, awaited))
}

fn is_bare_or_member_identifier(expr: &str) -> bool {
    !expr.contains('(')
        && expr
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'.'))
}

fn is_request_scoped_await(expr: &str) -> bool {
    for api in [
        "headers(",
        "cookies(",
        "draftMode(",
        "connection(",
        "getTranslations(",
        "getMessages(",
        "getLocale(",
    ] {
        if expr.starts_with(api) {
            return true;
        }
    }
    false
}

fn is_gate_await(expr: &str) -> bool {
    let Some(open) = expr.find('(') else {
        return false;
    };
    let callee = expr[..open].trim();
    let short_name = callee.rsplit('.').next().unwrap_or(callee);
    let lower = short_name.to_ascii_lowercase();
    for prefix in [
        "require",
        "ensure",
        "assert",
        "verify",
        "validate",
        "check",
        "connect",
        "disconnect",
        "begin",
        "acquire",
        "lock",
        "init",
        "setup",
        "authorize",
        "authenticate",
        "auth",
        "getsession",
    ] {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    false
}

fn awaited_calls_share_cached_work(
    graph: &ProjectGraph,
    file: &FileIr,
    first_awaited: &str,
    second_awaited: &str,
) -> bool {
    let Some((first_callee, first_args)) = parse_simple_call(first_awaited) else {
        return false;
    };
    let Some((second_callee, second_args)) = parse_simple_call(second_awaited) else {
        return false;
    };
    if first_args.is_empty() || first_args != second_args {
        return false;
    }

    let first_roots = resolve_underlying_cached_callees(graph, file, first_callee, 0);
    let second_roots = resolve_underlying_cached_callees(graph, file, second_callee, 0);
    !first_roots.is_empty() && first_roots.iter().any(|r| second_roots.contains(r))
}

fn resolve_underlying_cached_callees(
    graph: &ProjectGraph,
    file: &FileIr,
    callee: &str,
    depth: usize,
) -> HashSet<String> {
    let mut out = HashSet::new();
    if depth > 4 {
        return out;
    }

    // 1. Check if `callee` is defined in `file`
    if let Some(body) = find_function_body_in_source(&file.source, callee) {
        collect_cached_roots_from_body(graph, file, callee, &body, depth, &mut out);
        return out;
    }

    // 2. Check if `callee` is imported from another file in `ProjectGraph`
    if let Some((target_file, target_name)) = resolve_imported_binding(graph, file, callee)
        && let Some(body) = find_function_body_in_source(&target_file.source, &target_name)
    {
        collect_cached_roots_from_body(graph, target_file, &target_name, &body, depth, &mut out);
    }

    out
}

fn collect_cached_roots_from_body(
    graph: &ProjectGraph,
    defining_file: &FileIr,
    fn_name: &str,
    body: &str,
    depth: usize,
    out: &mut HashSet<String>,
) {
    let canonical_self = format!("{}::{fn_name}", defining_file.path.to_string_lossy());
    if is_cached_function_body(&defining_file.source, body) {
        out.insert(canonical_self);
    }
    // Also check any local or imported functions awaited inside `body`
    for token in extract_called_identifiers(body) {
        if token != fn_name {
            for root in resolve_underlying_cached_callees(graph, defining_file, &token, depth + 1) {
                out.insert(root);
            }
        }
    }
}

fn is_cached_function_body(file_source: &str, body: &str) -> bool {
    // 1. `React.cache(...)` or `cache(...)`
    if body.contains("cache(") || body.contains("React.cache(") {
        return true;
    }
    // 2. `"use cache"` directive
    if body.contains("\"use cache\"")
        || body.contains("'use cache'")
        || file_source.contains("\"use cache\"")
        || file_source.contains("'use cache'")
    {
        return true;
    }
    // 3. Guarded `Map` / `WeakMap` cache reader (`cache.get(...)` + `cache.set(...)`)
    (body.contains(".get(") && body.contains(".set("))
        || (body.contains(".has(") && body.contains(".get("))
}

fn extract_called_identifiers(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' && i > 0 {
            let mut start = i;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric()
                    || bytes[start - 1] == b'_'
                    || bytes[start - 1] == b'$')
            {
                start -= 1;
            }
            if start < i {
                let ident = &body[start..i];
                if !matches!(
                    ident,
                    "if" | "for" | "while" | "switch" | "catch" | "function" | "return" | "String"
                ) {
                    out.push(ident.to_string());
                }
            }
        }
        i += 1;
    }
    out
}

fn parse_simple_call(expr: &str) -> Option<(&str, Vec<&str>)> {
    let open = expr.find('(')?;
    let callee = expr[..open].trim();
    let after = &expr[open + 1..];
    let (inside, _) = split_balanced_parens(after)?;
    let args = split_top_level_args(inside);
    Some((callee, args))
}

fn check_server_no_mutable_module_state(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !file.module.has_use_server {
        return;
    }
    let mut brace_depth = 0_i32;
    for (idx, line) in file.source.lines().enumerate() {
        let trimmed = line.trim();
        if brace_depth == 0
            && let Some(rest) = trimmed
                .strip_prefix("let ")
                .or_else(|| trimmed.strip_prefix("var "))
                .or_else(|| trimmed.strip_prefix("export let "))
                .or_else(|| trimmed.strip_prefix("export var "))
        {
            let var_name = rest
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
                .next()
                .unwrap_or("state");
            let first_non_ws = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let line_start = line_starts.get(idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_srv_diag(
                out,
                file,
                None,
                RuleId::ServerNoMutableModuleState,
                "serverNoMutableModuleState",
                var_name,
                &format!(
                    "Module-scoped mutable binding `{var_name}` in a `'use server'` file is shared across concurrent requests."
                ),
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
        for b in line.bytes() {
            if b == b'{' {
                brace_depth += 1;
            } else if b == b'}' {
                brace_depth = (brace_depth - 1).max(0);
            }
        }
    }
}

fn check_server_hoist_static_io(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let is_route_file = path_str.contains("/route.") || path_str.contains("/pages/api/");
    if !is_route_file {
        return;
    }
    for (idx, line) in file.source.lines().enumerate() {
        let first_non_ws = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
        // Must be inside a handler function (indented > 0)
        if first_non_ws == 0 {
            continue;
        }
        let is_static_fs_read = (line.contains("readFileSync(") || line.contains("readFile("))
            && (line.contains("(\"") || line.contains("('"));
        let is_import_meta_fetch = line.contains("fetch(")
            && line.contains("new URL(")
            && line.contains("import.meta.url");
        if is_static_fs_read || is_import_meta_fetch {
            let line_start = line_starts.get(idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_srv_diag(
                out,
                file,
                None,
                RuleId::ServerHoistStaticIo,
                "serverHoistStaticIo",
                "readFile",
                "Static file I/O inside a route handler runs on every request; hoist the read to module scope.",
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn check_server_fetch_without_revalidate(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if file.module.has_use_client {
        return;
    }
    let norm = format!("/{}", path_str.trim_start_matches('/'));
    let is_app_router_file = norm.contains("/app/")
        && [
            "/page.",
            "/layout.",
            "/route.",
            "/template.",
            "/loading.",
            "/error.",
            "/default.",
        ]
        .iter()
        .any(|pat| norm.contains(pat));
    if !is_app_router_file {
        return;
    }

    for (idx, line) in file.source.lines().enumerate() {
        let Some(fetch_pos) = line.find("fetch(") else {
            continue;
        };
        if fetch_pos > 0 && line.as_bytes()[fetch_pos - 1].is_ascii_alphanumeric() {
            continue;
        }
        if line.contains("import.meta.url") {
            continue;
        }
        let window: String = file
            .source
            .lines()
            .skip(idx)
            .take(5)
            .collect::<Vec<_>>()
            .join("\n");
        if window.contains("revalidate") || window.contains("cache:") || window.contains("tags:") {
            continue;
        }
        let line_start = line_starts.get(idx).copied().unwrap_or(0);
        let byte_start = line_start + u32::try_from(fetch_pos).unwrap_or(0);
        let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            None,
            RuleId::ServerFetchWithoutRevalidate,
            "serverFetchWithoutRevalidate",
            "fetch",
            "Server `fetch(...)` without `{ next: { revalidate } }` or `{ cache: 'no-store' }`. Specify caching behavior explicitly.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_end,
            },
        );
    }
}

fn check_server_after_nonblocking(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let is_server_ctx = file.module.has_use_server || path_str.contains("/route.");
    if !is_server_ctx {
        return;
    }
    if file.source.contains("after(") || file.source.contains("unstable_after(") {
        return;
    }
    for (idx, line) in file.source.lines().enumerate() {
        let trimmed = line.trim();
        let is_deferrable = [
            "analytics.track(",
            "analytics.identify(",
            "posthog.capture(",
            "mixpanel.track(",
            "segment.track(",
            "amplitude.track(",
            "console.log(",
            "console.info(",
            "console.warn(",
        ]
        .iter()
        .any(|call| trimmed.contains(call));
        if is_deferrable {
            let first_non_ws = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let line_start = line_starts.get(idx).copied().unwrap_or(0);
            let byte_start = line_start + u32::try_from(first_non_ws).unwrap_or(0);
            let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
            push_srv_diag(
                out,
                file,
                None,
                RuleId::ServerAfterNonblocking,
                "serverAfterNonblocking",
                "after",
                "Wrap non-blocking logging or analytics in `after(() => ...)` from `'next/server'` so the response is not delayed.",
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
    }
}

fn check_server_dedup_props(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    if file.module.has_use_client {
        return;
    }
    for (idx, line) in file.source.lines().enumerate() {
        if !line.contains('<') {
            continue;
        }
        for method in [".filter(", ".map(", ".slice(", ".toSorted(", ".toReversed("] {
            if let Some(m_pos) = line.find(method) {
                let before = &line[..m_pos];
                let base_ident: String = before
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                if !base_ident.is_empty() && line.contains(&format!("{{{base_ident}}}")) {
                    let line_start = line_starts.get(idx).copied().unwrap_or(0);
                    let byte_start = line_start + u32::try_from(m_pos).unwrap_or(0);
                    let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
                    push_srv_diag(
                        out,
                        file,
                        None,
                        RuleId::ServerDedupProps,
                        "serverDedupProps",
                        &base_ident,
                        &format!(
                            "Passing both `{base_ident}` and `{base_ident}{method}...)` serializes duplicate array data across the RSC boundary."
                        ),
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

fn check_server_cache_with_object_literal(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let mut cached_fns = Vec::new();
    for line in file.source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("const ")
            && let Some((name, rhs)) = rest.split_once('=')
            && (rhs.contains("cache(") || rhs.contains("React.cache("))
        {
            cached_fns.push(name.trim().to_string());
        }
    }
    if cached_fns.is_empty() {
        return;
    }

    for (idx, line) in file.source.lines().enumerate() {
        for fn_name in &cached_fns {
            let call_pat = format!("{fn_name}(");
            if let Some(pos) = line.find(&call_pat) {
                let after = line[pos + call_pat.len()..].trim_start();
                if after.starts_with('{') || after.starts_with('[') {
                    let line_start = line_starts.get(idx).copied().unwrap_or(0);
                    let byte_start = line_start + u32::try_from(pos).unwrap_or(0);
                    let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
                    push_srv_diag(
                        out,
                        file,
                        None,
                        RuleId::ServerCacheWithObjectLiteral,
                        "serverCacheWithObjectLiteral",
                        fn_name,
                        "Passing a new object or array literal to `React.cache()` misses the cache on every render because arguments are compared by reference.",
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


fn expression_mentions_identifier(expr: &str, ident: &str) -> bool {
    for token in expr.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$') {
        if token == ident {
            return true;
        }
    }
    false
}
