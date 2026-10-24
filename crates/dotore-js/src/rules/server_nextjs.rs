//! Server (`server-*`) and Next.js (`nextjs-*`) rule detectors, including
//! `server-auth-actions`, `server-sequential-independent-await` with cross-file
//! cached async awareness (`React.cache()`, `"use cache"`, guarded `WeakMap`/`Map` caches),
//! `nextjs-async-dynamic-api-not-awaited`, `nextjs-no-img-element` with cross-file
//! `ImageResponse`/`satori` wrapper awareness, and `nextjs-no-use-search-params-without-suspense`
//! with cross-file `<Suspense>` caller and layout awareness.

use std::collections::HashSet;

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

    // 1. Server rules
    if is_active(RuleId::ServerAuthActions).is_some() {
        check_server_auth_actions(file, config, &line_starts, out);
    }
    if is_active(RuleId::ServerSequentialIndependentAwait).is_some() {
        check_server_sequential_independent_await(graph, file, &line_starts, out);
    }
    if is_active(RuleId::ServerNoMutableModuleState).is_some() {
        check_server_no_mutable_module_state(file, &line_starts, out);
    }
    if is_active(RuleId::ServerHoistStaticIo).is_some() {
        check_server_hoist_static_io(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::ServerFetchWithoutRevalidate).is_some() {
        check_server_fetch_without_revalidate(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::ServerAfterNonblocking).is_some() {
        check_server_after_nonblocking(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::ServerDedupProps).is_some() {
        check_server_dedup_props(file, &line_starts, out);
    }
    if is_active(RuleId::ServerCacheWithObjectLiteral).is_some() {
        check_server_cache_with_object_literal(file, &line_starts, out);
    }

    // 2. Next.js rules
    if is_active(RuleId::NextjsAsyncDynamicApiNotAwaited).is_some() {
        check_nextjs_async_dynamic_api_not_awaited(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::NextjsNoImgElement).is_some() {
        check_nextjs_no_img_element(graph, file, out);
    }
    if is_active(RuleId::NextjsNoUseSearchParamsWithoutSuspense).is_some() {
        check_nextjs_no_use_search_params_without_suspense(
            graph,
            file,
            &path_str,
            &line_starts,
            out,
        );
    }
    if is_active(RuleId::NextjsNoSideEffectInGetHandler).is_some() {
        check_nextjs_no_side_effect_in_get_handler(file, &path_str, &line_starts, out);
    }
    if is_active(RuleId::NextjsNoScriptInHead).is_some() {
        check_nextjs_no_script_in_head(file, out);
    }
    if is_active(RuleId::NextjsNoHeadImport).is_some() {
        check_nextjs_no_head_import(file, &path_str, out);
    }
    if is_active(RuleId::NextjsNoVercelOgImport).is_some() {
        check_nextjs_no_vercel_og_import(file, out);
    }
    if is_active(RuleId::NextjsAsyncClientComponent).is_some() {
        check_nextjs_async_client_component(file, &line_starts, out);
    }

    evaluate_remaining_nextjs_rules(graph, file, &path_str, &line_starts, is_active, out);
}

#[expect(
    clippy::too_many_arguments,
    reason = "Direct diagnostic constructor avoids intermediate allocations"
)]
fn push_srv_diag(
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

fn check_nextjs_async_dynamic_api_not_awaited(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if path_str.ends_with("sitemap.ts") || path_str.ends_with("sitemap.js") {
        return;
    }
    let src = &file.source;

    // Collect local names of `cookies`, `headers`, `draftMode` imported from `next/headers` (plus namespace imports)
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

    // Track un-awaited pending bindings (`const pending = cookies()`, `let pending = cookies()`)
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

    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("import ") {
            continue;
        }

        // Check for direct or aliased call `cookies()`, `headers()`, `draftMode()`, `ns.headers()`, `ns["headers"]()`
        let mut line_flagged = false;
        for callee in &dynamic_callees {
            let call_token = format!("{callee}()");
            if let Some(call_pos) = line.find(&call_token) {
                let before = line[..call_pos].trim_end();
                let after = line[call_pos + call_token.len()..].trim_start();
                let is_awaited = before.ends_with("await") || before.ends_with("use(");
                if is_awaited {
                    continue;
                }

                // Direct synchronous consumption: `.get(...)`, `.value`, `?.get(...)`, `[...cookies()]`, `{ ...headers() }`, `Object.keys(cookies())`, `new Map(headers())`, `for (const x of headers())`
                let is_direct_member = (after.starts_with('.') || after.starts_with("?."))
                    && !after.starts_with(".then(")
                    && !after.starts_with(".catch(")
                    && !after.starts_with(".finally(");
                let is_spread_or_iter = before.ends_with("...")
                    || before.contains("for (")
                    || before.contains("Object.keys(")
                    || before.contains("Object.values(")
                    || before.contains("Object.entries(")
                    || before.contains("Object.fromEntries(")
                    || before.contains("Object.assign(")
                    || before.contains("Reflect.ownKeys(")
                    || before.contains("Array.from(")
                    || (before.contains("new Map(") && !src.contains("(Map)"))
                    || (before.contains("new Set(") && !src.contains("(Set)"));
                let is_destructured = (before.contains('{') || before.contains('['))
                    && before.ends_with('=')
                    && !is_only_promise_settlement_destructure(before);

                if is_direct_member || is_spread_or_iter || is_destructured {
                    emit_dynamic_api_diag(out, file, callee, idx, line, line_starts);
                    line_flagged = true;
                    break;
                }

                // Check if assigned to a local identifier (`const pending = cookies();`)
                if let Some(lhs_ident) = extract_assigned_ident_before(before) {
                    pending_bindings.insert(lhs_ident);
                }
            }
        }
        if line_flagged {
            continue;
        }

        // Check namespace calls `nextHeaders.headers().get(...)` or `nextHeaders["headers"]().get(...)` or `nextHeaders[apiName]().get(...)`
        for ns in &namespace_imports {
            if let Some(ns_pos) = line.find(ns.as_str()) {
                let after_ns = &line[ns_pos + ns.len()..];
                if (after_ns.starts_with('.') || after_ns.starts_with('['))
                    && after_ns.contains("().")
                    && !line[..ns_pos].trim_end().ends_with("await")
                {
                    emit_dynamic_api_diag(out, file, ns, idx, line, line_starts);
                    line_flagged = true;
                    break;
                }
            }
        }
        if line_flagged {
            continue;
        }

        // Propagate aliases (`const alias = pendingCookies as any`)
        for existing in pending_bindings.clone() {
            let Some(eq_pos) = trimmed.find('=') else {
                continue;
            };
            if trimmed[eq_pos + 1..].starts_with('=') {
                continue;
            }
            let lhs = trimmed[..eq_pos].trim();
            let rhs = trimmed[eq_pos + 1..].trim();
            if rhs.starts_with(&existing)
                && !rhs.contains("await ")
                && let Some(alias_id) = extract_assigned_ident_before(&format!("{lhs} ="))
            {
                pending_bindings.insert(alias_id);
            }
        }

        // Check synchronous consumption of any `pending_bindings` on this line
        for pending in &pending_bindings {
            let dot_access = format!("{pending}.");
            let opt_access = format!("{pending}?.");
            let cast_access = format!("{pending} as ");
            let has_sync_member = (line.contains(&dot_access)
                && !line.contains(&format!("{pending}.then"))
                && !line.contains(&format!("{pending}.catch"))
                && !line.contains(&format!("{pending}.finally")))
                || line.contains(&opt_access)
                || (line.contains(&cast_access) && line.contains(")."));
            let has_destructure = (line.contains(" = ") && line.contains(pending.as_str()))
                && (line.contains('{') || line.contains('['))
                && !line.contains(&format!("await {pending}"))
                && !is_only_promise_settlement_destructure(line);
            let has_spread_or_enum = line.contains(&format!("...{pending}"))
                || line.contains(&format!("of {pending}"))
                || line.contains(&format!("in {pending}"))
                || line.contains(&format!("yield* {pending}"))
                || line.contains(&format!("Object.keys({pending})"))
                || line.contains(&format!("new Set({pending})"))
                || line.contains(&format!("new Map({pending})"));

            if has_sync_member || has_destructure || has_spread_or_enum {
                emit_dynamic_api_diag(out, file, pending, idx, line, line_starts);
                break;
            }
        }
    }
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

fn check_nextjs_no_img_element(graph: &ProjectGraph, file: &FileIr, out: &mut Vec<Diagnostic>) {
    // Skip if file itself uses `ImageResponse` / `satori` / `@react-email` / `createObjectURL` / `toDataURL`
    if file_is_generated_image_or_email_context(&file.source) {
        return;
    }
    // Skip if every exported helper in `file` is consumed by a file in `graph` that uses `ImageResponse` or `satori`
    if is_file_exclusively_consumed_by_image_response(graph, file) {
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
        if tag_text.contains("src=\"data:")
            || tag_text.contains("src='data:")
            || tag_text.contains("src=\"blob:")
            || tag_text.contains("src='blob:")
            || tag_text.contains("scarf.sh/")
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
    source.contains("ImageResponse")
        || source.contains("from \"satori\"")
        || source.contains("from 'satori'")
        || source.contains("@react-email/")
        || source.contains("from \"react-email\"")
        || source.contains("createObjectURL(")
        || source.contains(".toDataURL(")
        || source.contains(".readAsDataURL(")
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

fn check_nextjs_no_use_search_params_without_suspense(
    graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let norm = format!("/{}", path_str.trim_start_matches('/'));
    let is_page_or_layout = norm.contains("/page.") || norm.contains("/layout.");
    if !is_page_or_layout {
        return;
    }
    if has_ancestor_suspense_layout(graph, &file.path) {
        return;
    }

    // 1. Direct `useSearchParams()` call in `page.*` / `layout.*` without `<Suspense>` in the same file
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

    // 2. Cross-file imported component rendered in `page.*` that calls `useSearchParams()` without an enclosing `<Suspense>`
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
        if is_wrapped {
            continue;
        }
        if let Some((target_file, target_local)) = resolve_imported_binding(graph, file, &jsx.name)
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

fn check_nextjs_no_side_effect_in_get_handler(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let lower_path = path_str.to_ascii_lowercase();
    if lower_path.contains("/callback")
        || lower_path.contains("/verify")
        || lower_path.contains("/confirm")
        || lower_path.contains("/magic-link")
        || lower_path.contains("/cron")
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

fn check_nextjs_no_script_in_head(file: &FileIr, out: &mut Vec<Diagnostic>) {
    for jsx in &file.jsx_elements {
        if jsx.name == "Script" && jsx.ancestor_elements.iter().any(|a| a == "Head") {
            push_srv_diag(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::NextjsNoScriptInHead,
                "nextjsNoScriptInHead",
                "Script",
                "`next/script` `<Script>` inside `next/head` `<Head>` is silently ignored; move `<Script>` outside `<Head>`.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}

fn check_nextjs_no_head_import(file: &FileIr, path_str: &str, out: &mut Vec<Diagnostic>) {
    let norm = format!("/{}", path_str.trim_start_matches('/'));
    if !norm.contains("/app/") {
        return;
    }
    for imp in &file.module.imports {
        if imp.source == "next/head" {
            push_srv_diag(
                out,
                file,
                None,
                RuleId::NextjsNoHeadImport,
                "nextjsNoHeadImport",
                "next/head",
                "`next/head` silently does nothing in the App Router; use the Metadata API instead.",
                imp.loc,
                imp.span,
            );
        }
    }
}

fn check_nextjs_no_vercel_og_import(file: &FileIr, out: &mut Vec<Diagnostic>) {
    for imp in &file.module.imports {
        if imp.source == "@vercel/og" {
            push_srv_diag(
                out,
                file,
                None,
                RuleId::NextjsNoVercelOgImport,
                "nextjsNoVercelOgImport",
                "@vercel/og",
                "`@vercel/og` is bundled into Next.js; import from `'next/og'` instead.",
                imp.loc,
                imp.span,
            );
        }
    }
}

fn check_nextjs_async_client_component(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !file.module.has_use_client {
        return;
    }
    for (idx, line) in file.source.lines().enumerate() {
        if let Some(pos) = line.find("async function ") {
            let after = line[pos + "async function ".len()..].trim();
            let fn_name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if fn_name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
            {
                let line_start = line_starts.get(idx).copied().unwrap_or(0);
                let byte_start = line_start + u32::try_from(pos).unwrap_or(0);
                let byte_end = line_start + u32::try_from(line.len()).unwrap_or(0);
                push_srv_diag(
                    out,
                    file,
                    Some(fn_name.clone()),
                    RuleId::NextjsAsyncClientComponent,
                    "nextjsAsyncClientComponent",
                    &fn_name,
                    &format!(
                        "Async client component \"{fn_name}\" fails to render because client components cannot be async."
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

fn evaluate_remaining_nextjs_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let _ = graph;
    let src = &file.source;
    let norm = format!("/{}", path_str.trim_start_matches('/'));

    // nextjs-error-boundary-missing-use-client
    if is_active(RuleId::NextjsErrorBoundaryMissingUseClient).is_some()
        && norm.contains("/app/")
        && (norm.contains("/error.") || norm.contains("/global-error."))
        && !file.module.has_use_client
    {
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsErrorBoundaryMissingUseClient,
            "nextjsErrorBoundaryMissingUseClient",
            "error.tsx",
            "This error boundary silently does nothing without `'use client'`.",
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
        );
    }

    // nextjs-global-error-missing-html-body
    if is_active(RuleId::NextjsGlobalErrorMissingHtmlBody).is_some()
        && norm.contains("/app/")
        && norm.contains("/global-error.")
        && (!file.jsx_elements.iter().any(|j| j.name == "html")
            || !file.jsx_elements.iter().any(|j| j.name == "body"))
    {
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsGlobalErrorMissingHtmlBody,
            "nextjsGlobalErrorMissingHtmlBody",
            "global-error.tsx",
            "`global-error.tsx` is missing `<html>` and `<body>`.",
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
        );
    }

    // nextjs-image-missing-sizes & nextjs-inline-script-missing-id & nextjs-no-a-element & nextjs-no-css-link & nextjs-no-font-link & nextjs-no-google-analytics-script & nextjs-no-polyfill-script & nextjs-no-native-script
    for jsx in &file.jsx_elements {
        if jsx.name == "Image"
            && jsx.attributes.iter().any(|a| a == "fill")
            && !jsx
                .attributes
                .iter()
                .any(|a| a == "sizes" || a == "unoptimized")
            && is_active(RuleId::NextjsImageMissingSizes).is_some()
        {
            push_srv_diag(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::NextjsImageMissingSizes,
                "nextjsImageMissingSizes",
                "Image",
                "`next/image` uses `fill` without `sizes`, causing browsers to download the largest image.",
                jsx.loc,
                jsx.span,
            );
        }

        if jsx.name == "Script"
            && !jsx.attributes.iter().any(|a| a == "src" || a == "id")
            && is_active(RuleId::NextjsInlineScriptMissingId).is_some()
        {
            push_srv_diag(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::NextjsInlineScriptMissingId,
                "nextjsInlineScriptMissingId",
                "Script",
                "Without an `id`, Next.js cannot track this inline `<Script>` and may execute it multiple times.",
                jsx.loc,
                jsx.span,
            );
        }

        if jsx.name == "a" && is_active(RuleId::NextjsNoAElement).is_some() {
            let tag_text = src
                .get(jsx.span.start as usize..jsx.span.end as usize)
                .unwrap_or("");
            if (tag_text.contains("href=\"/") || tag_text.contains("href='/"))
                && !tag_text.contains("href=\"//")
                && !tag_text.contains("download")
                && !tag_text.contains("target=\"_blank\"")
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoAElement,
                    "nextjsNoAElement",
                    "a",
                    "Plain `<a>` reloads the whole page for internal links; use `<Link>` from `'next/link'`.",
                    jsx.loc,
                    jsx.span,
                );
            }
        }

        if jsx.name == "link" {
            let tag_text = src
                .get(jsx.span.start as usize..jsx.span.end as usize)
                .unwrap_or("");
            if tag_text.contains("fonts.googleapis.com")
                && is_active(RuleId::NextjsNoFontLink).is_some()
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoFontLink,
                    "nextjsNoFontLink",
                    "link",
                    "Loading Google Fonts with `<link>` blocks rendering; use `next/font/google` instead.",
                    jsx.loc,
                    jsx.span,
                );
            } else if tag_text.contains("rel=\"stylesheet\"")
                && !tag_text.contains("http://")
                && !tag_text.contains("https://")
                && is_active(RuleId::NextjsNoCssLink).is_some()
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoCssLink,
                    "nextjsNoCssLink",
                    "link",
                    "This `<link rel=\"stylesheet\">` bypasses Next.js CSS bundling.",
                    jsx.loc,
                    jsx.span,
                );
            }
        }

        if jsx.name == "script" || jsx.name == "Script" {
            let tag_text = src
                .get(jsx.span.start as usize..jsx.span.end as usize)
                .unwrap_or("");
            if (tag_text.contains("google-analytics.com")
                || tag_text.contains("googletagmanager.com/gtag"))
                && is_active(RuleId::NextjsNoGoogleAnalyticsScript).is_some()
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoGoogleAnalyticsScript,
                    "nextjsNoGoogleAnalyticsScript",
                    &jsx.name,
                    "Use `GoogleAnalytics` from `'@next/third-parties/google'` instead of manual Google Analytics scripts.",
                    jsx.loc,
                    jsx.span,
                );
            }
            if tag_text.contains("polyfill.io")
                && is_active(RuleId::NextjsNoPolyfillScript).is_some()
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoPolyfillScript,
                    "nextjsNoPolyfillScript",
                    &jsx.name,
                    "This polyfill CDN script downloads polyfills Next.js already includes.",
                    jsx.loc,
                    jsx.span,
                );
            }
            if jsx.name == "script"
                && jsx.attributes.iter().any(|a| a == "src")
                && is_active(RuleId::NextjsNoNativeScript).is_some()
            {
                push_srv_diag(
                    out,
                    file,
                    jsx.enclosing_subject.clone(),
                    RuleId::NextjsNoNativeScript,
                    "nextjsNoNativeScript",
                    "script",
                    "Use `<Script>` from `'next/script'` instead of native `<script src=\"...\">`.",
                    jsx.loc,
                    jsx.span,
                );
            }
        }
    }

    // nextjs-no-default-export-in-route-handler
    if is_active(RuleId::NextjsNoDefaultExportInRouteHandler).is_some()
        && norm.contains("/app/")
        && norm.contains("/route.")
        && !file.module.exports.iter().any(|e| {
            matches!(
                e.name.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
            )
        })
        && let Some(def_exp) = file.module.exports.iter().find(|e| e.name == "default")
    {
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsNoDefaultExportInRouteHandler,
            "nextjsNoDefaultExportInRouteHandler",
            "default",
            "Default exports in `route.ts` are silently ignored; export named HTTP methods (`GET`, `POST`, etc.).",
            def_exp.loc,
            def_exp.span,
        );
    }

    // nextjs-no-edge-og-runtime
    if is_active(RuleId::NextjsNoEdgeOgRuntime).is_some()
        && (norm.contains("/opengraph-image") || norm.contains("/twitter-image"))
        && (src.contains("runtime = \"edge\"") || src.contains("runtime = 'edge'"))
    {
        let pos = src.find("runtime").unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsNoEdgeOgRuntime,
            "nextjsNoEdgeOgRuntime",
            "runtime",
            "Edge runtime limits OG image generation; use the default Node.js runtime.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 7,
            },
        );
    }

    // nextjs-no-redirect-in-try-catch
    if is_active(RuleId::NextjsNoRedirectInTryCatch).is_some()
        && src.contains("try {")
        && (src.contains("redirect(")
            || src.contains("permanentRedirect(")
            || src.contains("notFound("))
        && !src.contains("unstable_rethrow(")
    {
        let pos = src
            .find("redirect(")
            .or_else(|| src.find("permanentRedirect("))
            .or_else(|| src.find("notFound("))
            .unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsNoRedirectInTryCatch,
            "nextjsNoRedirectInTryCatch",
            "redirect",
            "`redirect()` / `notFound()` inside `try-catch` gets swallowed; move it outside `try` or call `unstable_rethrow`.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 8,
            },
        );
    }

    // nextjs-no-client-fetch-for-server-data & nextjs-no-client-side-redirect
    if file.module.has_use_client
        && (norm.contains("/page.") || norm.contains("/layout."))
        && is_active(RuleId::NextjsNoClientFetchForServerData).is_some()
    {
        emit_client_fetch_for_server_data(file, out);
    }
    if is_active(RuleId::NextjsNoClientSideRedirect).is_some()
        && src.contains("useEffect(")
        && (src.contains("router.push(")
            || src.contains("router.replace(")
            || src.contains("window.location.href ="))
    {
        let pos = src
            .find("router.push(")
            .or_else(|| src.find("router.replace("))
            .or_else(|| src.find("window.location.href ="))
            .unwrap_or(0);
        let byte_start = u32::try_from(pos).unwrap_or(0);
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsNoClientSideRedirect,
            "nextjsNoClientSideRedirect",
            "router",
            "Avoid client-side redirects inside `useEffect`; redirect on the server or in an event handler.",
            loc_from_line_starts(line_starts, byte_start),
            ByteSpan {
                start: byte_start,
                end: byte_start + 11,
            },
        );
    }

    // nextjs-metadata-url-consistency & nextjs-missing-metadata
    if is_active(RuleId::NextjsMetadataUrlConsistency).is_some()
        && (norm.contains("/page.") || norm.contains("/layout."))
        && src.contains("canonical:")
        && src.contains("openGraph:")
    {
        let canonical = extract_string_after_key(src, "canonical:");
        let og_url = extract_string_after_key(src, "url:");
        if let (Some(c), Some(u)) = (canonical, og_url)
            && c.trim_end_matches('/') != u.trim_end_matches('/')
        {
            let pos = src.find("url:").unwrap_or(0);
            let byte_start = u32::try_from(pos).unwrap_or(0);
            push_srv_diag(
                out,
                file,
                None,
                RuleId::NextjsMetadataUrlConsistency,
                "nextjsMetadataUrlConsistency",
                "url",
                &format!("`openGraph.url` is \"{u}\" but `alternates.canonical` is \"{c}\"."),
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_start + 4,
                },
            );
        }
    }

    if is_active(RuleId::NextjsMissingMetadata).is_some()
        && norm.contains("/app/")
        && norm.contains("/page.")
        && !file.module.has_use_client
        && !file
            .module
            .exports
            .iter()
            .any(|e| e.name == "metadata" || e.name == "generateMetadata")
        && !src.contains("redirect(")
    {
        push_srv_diag(
            out,
            file,
            None,
            RuleId::NextjsMissingMetadata,
            "nextjsMissingMetadata",
            "metadata",
            "Page is missing exported `metadata` or `generateMetadata()`.",
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
        );
    }
}

fn extract_string_after_key(src: &str, key: &str) -> Option<String> {
    let pos = src.find(key)?;
    let after = src[pos + key.len()..].trim_start();
    let quote = after.bytes().next()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.find(char::from(quote))?;
    Some(rest[..end].to_string())
}

fn expression_mentions_identifier(expr: &str, ident: &str) -> bool {
    for token in expr.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$') {
        if token == ident {
            return true;
        }
    }
    false
}

fn emit_client_fetch_for_server_data(file: &FileIr, out: &mut Vec<Diagnostic>) {
    for subj in &file.subjects {
        for eff in &subj.effect_nodes {
            if !eff.fetch_sites.is_empty() {
                push_srv_diag(
                    out,
                    file,
                    subj.name.clone(),
                    RuleId::NextjsNoClientFetchForServerData,
                    "nextjsNoClientFetchForServerData",
                    "fetch",
                    "`useEffect` + `fetch` in a Next.js page/layout causes an extra client waterfall; fetch in a Server Component.",
                    eff.loc,
                    eff.call_span,
                );
            }
        }
    }
}
