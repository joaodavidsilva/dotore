//! Deterministic trust-boundary security rules (`#58`):
//! - `electron-webview-bridge-risk`
//! - `untrusted-host-header-origin`
//! - `private-response-public-cache`
//! - `llm-prompt-role-and-tool-sink-risk`
//! - `supabase-service-role-unscoped-query`

use crate::{
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId},
};

use super::{
    emit_line_diag, find_standalone_call, push_sec_diag, split_balanced_parens,
    unquote_js_string_literal,
};

pub(super) fn check_electron_webview_bridge_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let has_electron_ctx = src.contains("electron")
        || src.contains("BrowserWindow")
        || src.contains("BrowserView")
        || src.contains("WebContentsView")
        || src.contains("webPreferences")
        || src.contains("ipcMain")
        || src.contains("shell.openExternal");

    // 1. Electron BrowserWindow / webPreferences flags
    if has_electron_ctx {
        for (idx, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let has_insecure_pref = compact.contains("nodeIntegration:true")
                || compact.contains("nodeIntegrationInWorker:true")
                || compact.contains("nodeIntegrationInSubFrames:true")
                || compact.contains("contextIsolation:false")
                || compact.contains("webSecurity:false")
                || compact.contains("sandbox:false")
                || compact.contains("allowRunningInsecureContent:true")
                || compact.contains("enableRemoteModule:true");
            if has_insecure_pref {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ElectronWebviewBridgeRisk,
                    "electronWebviewBridgeRisk",
                    "webPreferences",
                    "Electron `webPreferences` enables `nodeIntegration` or disables `contextIsolation`/`sandbox`/`webSecurity`, exposing native OS privileges to renderer content.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    // 2. ipcMain.handle / ipcMain.on invoking privileged APIs without checking event.senderFrame
    for ipc_pat in ["ipcMain.handle(", "ipcMain.on("] {
        let mut search_from = 0;
        while let Some(rel) = src[search_from..].find(ipc_pat) {
            let hit = search_from + rel;
            let after = &src[hit + ipc_pat.len()..];
            if let Some((call_inside, _)) = split_balanced_parens(after) {
                let has_privileged_sink = [
                    "exec(",
                    "execSync(",
                    "spawn(",
                    "fork(",
                    "shell.openExternal(",
                    "shell.openPath(",
                    "fs.readFile",
                    "fs.writeFile",
                    "fs.unlink",
                    "fs.rm",
                    "fs.promises.",
                ]
                .iter()
                .any(|s| call_inside.contains(s));
                let checks_sender_frame =
                    call_inside.contains("senderFrame") || src.contains("validateSender");
                if has_privileged_sink && !checks_sender_frame {
                    let byte_start = u32::try_from(hit).unwrap_or(0);
                    let byte_end = byte_start + u32::try_from(ipc_pat.len() - 1).unwrap_or(10);
                    push_sec_diag(
                        out,
                        file,
                        RuleId::ElectronWebviewBridgeRisk,
                        "electronWebviewBridgeRisk",
                        "ipcMain",
                        "`ipcMain` handler invokes a privileged shell/filesystem API without validating `event.senderFrame.url`.",
                        offset_to_loc(line_starts, byte_start),
                        ByteSpan {
                            start: byte_start,
                            end: byte_end,
                        },
                    );
                }
            }
            search_from = hit + ipc_pat.len();
        }
    }

    // 3. Unvalidated `shell.openExternal(url)`
    if src.contains("shell.openExternal(") {
        let has_protocol_validation = (src.contains("new URL(")
            && (src.contains(".protocol")
                || src.contains(".origin")
                || src.contains(".hostname")))
            || src.contains(".startsWith(\"https://\")")
            || src.contains(".startsWith('https://')")
            || src.contains("ALLOWED_")
            || src.contains("allowlist");
        if !has_protocol_validation {
            for (idx, line) in src.lines().enumerate() {
                let Some(pos) = line.find("shell.openExternal(") else {
                    continue;
                };
                let after = &line[pos + "shell.openExternal(".len()..];
                let Some((arg_inside, _)) = split_balanced_parens(after) else {
                    continue;
                };
                let is_static_safe = unquote_js_string_literal(arg_inside)
                    .is_some_and(|lit| lit.starts_with("https://") || lit.starts_with("mailto:"));
                if !is_static_safe {
                    emit_line_diag(
                        out,
                        file,
                        RuleId::ElectronWebviewBridgeRisk,
                        "electronWebviewBridgeRisk",
                        "shell.openExternal",
                        "`shell.openExternal()` is called without validating that the target URL uses an allowlisted `https:` protocol.",
                        idx,
                        line,
                        line_starts,
                    );
                }
            }
        }
    }

    // 4. React Native `<WebView>` with file/universal access from file URLs
    for jsx in &file.jsx_elements {
        if jsx.name != "WebView" && !jsx.name.ends_with(".WebView") {
            continue;
        }
        let start = usize::try_from(jsx.span.start).unwrap_or(0);
        let end = usize::try_from(jsx.span.end).unwrap_or(src.len());
        let snippet = src.get(start..end).unwrap_or("");
        let opener = snippet.split('>').next().unwrap_or(snippet);
        let compact: String = opener.chars().filter(|c| !c.is_whitespace()).collect();
        let has_file_url_access = (jsx
            .attributes
            .iter()
            .any(|a| a == "allowFileAccessFromFileURLs")
            && !compact.contains("allowFileAccessFromFileURLs={false}"))
            || (jsx
                .attributes
                .iter()
                .any(|a| a == "allowUniversalAccessFromFileURLs")
                && !compact.contains("allowUniversalAccessFromFileURLs={false}"))
            || compact.contains("mixedContentMode=\"always\"")
            || compact.contains("mixedContentMode={'always'}");
        if has_file_url_access {
            push_sec_diag(
                out,
                file,
                RuleId::ElectronWebviewBridgeRisk,
                "electronWebviewBridgeRisk",
                "WebView",
                "`<WebView>` enables `allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs`, or `mixedContentMode=\"always\"`, allowing untrusted content to read local app files.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}

pub(super) fn check_untrusted_host_header_origin(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let lower_src = src.to_ascii_lowercase();
    let reads_untrusted_host = lower_src.contains("req.headers.host")
        || lower_src.contains("req.headers[\"host\"]")
        || lower_src.contains("req.headers['host']")
        || lower_src.contains("req.headers[\"x-forwarded-host\"]")
        || lower_src.contains("req.headers['x-forwarded-host']")
        || lower_src.contains(".get(\"x-forwarded-host\")")
        || lower_src.contains(".get('x-forwarded-host')")
        || lower_src.contains("header(\"x-forwarded-host\")")
        || lower_src.contains("header('x-forwarded-host')")
        || ((lower_src.contains("headers") || lower_src.contains("req"))
            && (lower_src.contains(".get(\"host\")")
                || lower_src.contains(".get('host')")
                || lower_src.contains("header(\"host\")")
                || lower_src.contains("header('host')")));
    if !reads_untrusted_host {
        return;
    }

    let has_host_allowlist = lower_src.contains("allowed_hosts")
        || lower_src.contains("allowedhosts")
        || lower_src.contains("valid_hosts")
        || lower_src.contains("validhosts")
        || lower_src.contains("trusted_hosts")
        || lower_src.contains("trustedhosts")
        || lower_src.contains("allowlist")
        || lower_src.contains("whitelist")
        || lower_src.contains(".has(host)")
        || lower_src.contains(".includes(host)")
        || lower_src.contains(".has(forwardedhost)")
        || lower_src.contains(".includes(forwardedhost)");
    if has_host_allowlist {
        return;
    }

    let has_sensitive_url_purpose = [
        "reset",
        "magic",
        "verify",
        "invite",
        "recovery",
        "oauth",
        "callback",
        "redirect_uri",
        "redirecturi",
        "returnto",
        "token=",
    ]
    .iter()
    .any(|kw| lower_src.contains(kw));
    if !has_sensitive_url_purpose {
        return;
    }

    for (idx, line) in src.lines().enumerate() {
        let lower_line = line.to_ascii_lowercase();
        let builds_url = (lower_line.contains("http://${")
            || lower_line.contains("https://${")
            || lower_line.contains("new url(")
            || lower_line.contains("redirect_uri")
            || lower_line.contains("callbackurl")
            || lower_line.contains("reseturl")
            || lower_line.contains("resetlink")
            || lower_line.contains("magiclink"))
            && (lower_line.contains("host") || lower_line.contains("origin"));
        if builds_url {
            emit_line_diag(
                out,
                file,
                RuleId::UntrustedHostHeaderOrigin,
                "untrustedHostHeaderOrigin",
                "Host",
                "Password-reset, magic-link, or OAuth callback URL is constructed from an unvalidated `Host` or `X-Forwarded-Host` header, enabling host-header poisoning.",
                idx,
                line,
                line_starts,
            );
            return;
        }
    }
}

pub(super) fn check_private_response_public_cache(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let lower_src = src.to_ascii_lowercase();
    if !lower_src.contains("cache-control") {
        return;
    }

    let reads_private_auth = src.contains("cookies()")
        || src.contains("req.cookies")
        || src.contains("request.cookies")
        || src.contains("ctx.cookies")
        || lower_src.contains(".get(\"authorization\")")
        || lower_src.contains(".get('authorization')")
        || lower_src.contains("headers.authorization")
        || lower_src.contains("headers[\"authorization\"]")
        || lower_src.contains("headers['authorization']")
        || lower_src.contains(".get(\"cookie\")")
        || lower_src.contains(".get('cookie')")
        || lower_src.contains("headers.cookie")
        || find_standalone_call(src, "auth(").is_some()
        || src.contains("getServerSession(")
        || src.contains("currentUser(")
        || src.contains("getSession(")
        || src.contains("supabase.auth.getUser");
    if !reads_private_auth {
        return;
    }

    for (idx, line) in src.lines().enumerate() {
        let lower_line = line.to_ascii_lowercase();
        if !lower_line.contains("cache-control") {
            continue;
        }
        let has_public_or_shared_maxage =
            lower_line.contains("public") || lower_line.contains("s-maxage");
        let has_private_or_no_store =
            lower_line.contains("private") || lower_line.contains("no-store");
        if has_public_or_shared_maxage && !has_private_or_no_store {
            emit_line_diag(
                out,
                file,
                RuleId::PrivateResponsePublicCache,
                "privateResponsePublicCache",
                "Cache-Control",
                "Authenticated handler reads cookies, authorization headers, or session state while setting `Cache-Control: public` or `s-maxage`, risking cross-user CDN cache bleed.",
                idx,
                line,
                line_starts,
            );
        }
    }
}

pub(super) fn check_llm_prompt_role_and_tool_sink_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;

    // 1. Unfiltered client `messages` passed into LLM completion APIs
    let has_llm_call = src.contains(".chat.completions.create(")
        || src.contains(".messages.create(")
        || src.contains("generateText(")
        || src.contains("streamText(")
        || src.contains("generateObject(")
        || src.contains("streamObject(");
    if has_llm_call {
        let filters_roles = src.contains(".filter(")
            && (src.contains(".role") || src.contains("role ==="))
            || src.contains("allowedRoles")
            || src.contains("sanitizeMessages")
            || src.contains("z.enum([\"user\"");
        if !filters_roles {
            let destructures_raw_messages = (src.contains("{ messages }")
                || src.contains("{messages}"))
                && (src.contains("req.json(")
                    || src.contains("request.json(")
                    || src.contains("req.body")
                    || src.contains("request.body"));
            for (idx, line) in src.lines().enumerate() {
                let passes_raw_messages = line.contains("messages: req.body.messages")
                    || line.contains("messages: request.body.messages")
                    || line.contains("messages: body.messages")
                    || line.contains("messages: input.messages")
                    || line.contains("messages: params.messages")
                    || (destructures_raw_messages
                        && (line.contains("messages,")
                            || line.contains("messages: messages")
                            || line.contains("messages }")));
                if passes_raw_messages {
                    emit_line_diag(
                        out,
                        file,
                        RuleId::LlmPromptRoleAndToolSinkRisk,
                        "llmPromptRoleAndToolSinkRisk",
                        "messages",
                        "Raw client `messages` array is passed directly to an LLM API without filtering out `system`, `developer`, or `tool` roles.",
                        idx,
                        line,
                        line_starts,
                    );
                }
            }
        }
    }

    // 2. `generateText` / `streamText` with `tools` missing `maxSteps` or `stopWhen`
    for call_name in ["generateText(", "streamText("] {
        let mut search_from = 0;
        while let Some(rel) = src[search_from..].find(call_name) {
            let hit = search_from + rel;
            let after = &src[hit + call_name.len()..];
            if let Some((call_inside, _)) = split_balanced_parens(after) {
                let has_tools = call_inside.contains("tools:")
                    || call_inside.contains("tools,")
                    || call_inside.contains("tools }")
                    || call_inside.contains("tools\n");
                let has_step_bound =
                    call_inside.contains("maxSteps") || call_inside.contains("stopWhen");
                if has_tools && !has_step_bound {
                    let byte_start = u32::try_from(hit).unwrap_or(0);
                    let byte_end = byte_start + u32::try_from(call_name.len() - 1).unwrap_or(12);
                    push_sec_diag(
                        out,
                        file,
                        RuleId::LlmPromptRoleAndToolSinkRisk,
                        "llmPromptRoleAndToolSinkRisk",
                        call_name.trim_end_matches('('),
                        "Tool-calling LLM invocation includes `tools` without setting `maxSteps` or `stopWhen`, allowing unbounded agent execution loops.",
                        offset_to_loc(line_starts, byte_start),
                        ByteSpan {
                            start: byte_start,
                            end: byte_end,
                        },
                    );
                }
            }
            search_from = hit + call_name.len();
        }
    }

    // 3. MCP / AI SDK tool `execute` handler passing tool arguments directly to dangerous sinks
    let defines_tool = find_standalone_call(src, "tool(").is_some()
        || src.contains("createTool(")
        || src.contains("defineTool(")
        || src.contains("server.tool(")
        || src.contains("registerTool(");
    let has_sink_guard = (src.contains("path.resolve(") && src.contains(".startsWith("))
        || src.contains("ALLOWED_")
        || src.contains("allowlist");
    if defines_tool && !has_sink_guard {
        for (idx, line) in src.lines().enumerate() {
            let has_execute_or_tool = line.contains("execute:")
                || line.contains("server.tool(")
                || line.contains("registerTool(")
                || src.contains("execute:");
            let has_dangerous_sink = find_standalone_call(line, "exec(").is_some()
                || find_standalone_call(line, "execSync(").is_some()
                || find_standalone_call(line, "spawn(").is_some()
                || line.contains("fs.readFile")
                || line.contains("fs.writeFile")
                || line.contains("fs.unlink")
                || line.contains("fs.rm")
                || line.contains("$queryRawUnsafe(")
                || line.contains("$executeRawUnsafe(");
            if has_execute_or_tool && has_dangerous_sink {
                emit_line_diag(
                    out,
                    file,
                    RuleId::LlmPromptRoleAndToolSinkRisk,
                    "llmPromptRoleAndToolSinkRisk",
                    "execute",
                    "Agent or MCP tool `execute` handler passes model-controlled arguments directly into a shell, filesystem, or raw SQL sink without allowlist validation.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
}

pub(super) fn check_supabase_service_role_unscoped_query(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let uses_service_role = src.contains("SUPABASE_SERVICE_ROLE_KEY")
        || src.contains("SUPABASE_SERVICE_KEY")
        || src.contains("SERVICE_ROLE_KEY")
        || src.contains("serviceRoleKey")
        || src.contains("supabaseAdmin")
        || src.contains("adminSupabase");
    if !uses_service_role {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = src.get(search_from..).and_then(|s| s.find(".from(")) {
        let hit = search_from + rel;
        let Some(tail) = src.get(hit..) else {
            break;
        };
        let chain_end = tail
            .find(';')
            .or_else(|| tail.find("\n\n"))
            .unwrap_or(tail.len());
        let chain = tail.get(..chain_end).unwrap_or(tail);

        let has_data_op = chain.contains(".select(")
            || chain.contains(".update(")
            || chain.contains(".delete(")
            || chain.contains(".upsert(");
        let uses_request_param = chain.contains("req.")
            || chain.contains("request.")
            || chain.contains("params.")
            || chain.contains("query.")
            || chain.contains("body.")
            || chain.contains("searchParams")
            || chain.contains(".eq(\"id\"")
            || chain.contains(".eq('id'");
        let has_tenant_or_owner_scope = [
            "\"user_id\"",
            "'user_id'",
            "\"userId\"",
            "'userId'",
            "\"tenant_id\"",
            "'tenant_id'",
            "\"tenantId\"",
            "'tenantId'",
            "\"org_id\"",
            "'org_id'",
            "\"orgId\"",
            "'orgId'",
            "\"organization_id\"",
            "'organization_id'",
            "\"owner_id\"",
            "'owner_id'",
            "\"ownerId\"",
            "'ownerId'",
            "\"account_id\"",
            "'account_id'",
            "\"workspace_id\"",
            "'workspace_id'",
            "\"team_id\"",
            "'team_id'",
        ]
        .iter()
        .any(|col| chain.contains(col));

        if has_data_op && uses_request_param && !has_tenant_or_owner_scope {
            let byte_start = u32::try_from(hit + 1).unwrap_or(0);
            let byte_end = byte_start + 4;
            push_sec_diag(
                out,
                file,
                RuleId::SupabaseServiceRoleUnscopedQuery,
                "supabaseServiceRoleUnscopedQuery",
                "from",
                "Supabase `service_role` client bypasses Row Level Security (RLS) and executes a request-driven query without an explicit `.eq(\"user_id\" | \"tenant_id\" | \"org_id\" | \"owner_id\", ...)` filter.",
                offset_to_loc(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
        search_from = hit + ".from(".len();
    }
}
