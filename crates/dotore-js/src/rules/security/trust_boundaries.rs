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
    check_electron_web_preferences(file, line_starts, out);
    check_electron_ipc_main_handlers(file, line_starts, out);
    check_electron_shell_open_external(file, line_starts, out);
    check_react_native_webview_props(file, out);
}

fn check_electron_web_preferences(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let has_electron_ctx = [
        "electron",
        "BrowserWindow",
        "BrowserView",
        "WebContentsView",
        "webPreferences",
        "ipcMain",
        "shell.openExternal",
    ]
    .iter()
    .any(|kw| src.contains(kw));
    if !has_electron_ctx {
        return;
    }
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let has_insecure_pref = [
            "nodeIntegration:true",
            "nodeIntegrationInWorker:true",
            "nodeIntegrationInSubFrames:true",
            "contextIsolation:false",
            "webSecurity:false",
            "sandbox:false",
            "allowRunningInsecureContent:true",
            "enableRemoteModule:true",
        ]
        .iter()
        .any(|p| compact.contains(p));
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

fn check_electron_ipc_main_handlers(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
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
}

fn check_electron_shell_open_external(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    if !src.contains("shell.openExternal(") || has_shell_open_external_validation(src) {
        return;
    }
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

fn has_shell_open_external_validation(src: &str) -> bool {
    (src.contains("new URL(")
        && [".protocol", ".origin", ".hostname"]
            .iter()
            .any(|p| src.contains(p)))
        || [
            ".startsWith(\"https://\")",
            ".startsWith('https://')",
            "ALLOWED_",
            "allowlist",
        ]
        .iter()
        .any(|p| src.contains(p))
}

fn check_react_native_webview_props(file: &FileIr, out: &mut Vec<Diagnostic>) {
    let src = &file.source;
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
    if !reads_untrusted_host_header(&lower_src) || has_host_header_allowlist(&lower_src) {
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
        if line_builds_url_from_host(&line.to_ascii_lowercase()) {
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

fn reads_untrusted_host_header(lower_src: &str) -> bool {
    [
        "req.headers.host",
        "req.headers[\"host\"]",
        "req.headers['host']",
        "req.headers[\"x-forwarded-host\"]",
        "req.headers['x-forwarded-host']",
        ".get(\"x-forwarded-host\")",
        ".get('x-forwarded-host')",
        "header(\"x-forwarded-host\")",
        "header('x-forwarded-host')",
    ]
    .iter()
    .any(|p| lower_src.contains(p))
        || ((lower_src.contains("headers") || lower_src.contains("req"))
            && [
                ".get(\"host\")",
                ".get('host')",
                "header(\"host\")",
                "header('host')",
            ]
            .iter()
            .any(|p| lower_src.contains(p)))
}

fn has_host_header_allowlist(lower_src: &str) -> bool {
    [
        "allowed_hosts",
        "allowedhosts",
        "valid_hosts",
        "validhosts",
        "trusted_hosts",
        "trustedhosts",
        "allowlist",
        "whitelist",
        ".has(host)",
        ".includes(host)",
        ".has(forwardedhost)",
        ".includes(forwardedhost)",
    ]
    .iter()
    .any(|p| lower_src.contains(p))
}

fn line_builds_url_from_host(lower_line: &str) -> bool {
    (lower_line.contains("host") || lower_line.contains("origin"))
        && [
            "http://${",
            "https://${",
            "new url(",
            "redirect_uri",
            "callbackurl",
            "reseturl",
            "resetlink",
            "magiclink",
        ]
        .iter()
        .any(|p| lower_line.contains(p))
}

pub(super) fn check_private_response_public_cache(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let lower_src = src.to_ascii_lowercase();
    if !lower_src.contains("cache-control") || !reads_private_auth_context(src, &lower_src) {
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

fn reads_private_auth_context(src: &str, lower_src: &str) -> bool {
    find_standalone_call(src, "auth(").is_some()
        || [
            "cookies()",
            "req.cookies",
            "request.cookies",
            "ctx.cookies",
            "getServerSession(",
            "currentUser(",
            "getSession(",
            "supabase.auth.getUser",
        ]
        .iter()
        .any(|p| src.contains(p))
        || [
            ".get(\"authorization\")",
            ".get('authorization')",
            "headers.authorization",
            "headers[\"authorization\"]",
            "headers['authorization']",
            ".get(\"cookie\")",
            ".get('cookie')",
            "headers.cookie",
        ]
        .iter()
        .any(|p| lower_src.contains(p))
}

pub(super) fn check_llm_prompt_role_and_tool_sink_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if file.source.is_empty() {
        return;
    }
    check_llm_unfiltered_client_messages(file, line_starts, out);
    check_llm_tools_missing_step_bound(file, line_starts, out);
    check_llm_tool_execute_dangerous_sinks(file, line_starts, out);
}

fn check_llm_unfiltered_client_messages(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let has_llm_call = [
        ".chat.completions.create(",
        ".messages.create(",
        "generateText(",
        "streamText(",
        "generateObject(",
        "streamObject(",
    ]
    .iter()
    .any(|p| src.contains(p));
    if !has_llm_call || llm_src_filters_roles(src) {
        return;
    }
    let destructures_raw_messages = (src.contains("{ messages }") || src.contains("{messages}"))
        && ["req.json(", "request.json(", "req.body", "request.body"]
            .iter()
            .any(|p| src.contains(p));
    for (idx, line) in src.lines().enumerate() {
        if line_passes_raw_llm_messages(line, destructures_raw_messages) {
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

fn llm_src_filters_roles(src: &str) -> bool {
    (src.contains(".filter(") && (src.contains(".role") || src.contains("role ===")))
        || ["allowedRoles", "sanitizeMessages", "z.enum([\"user\""]
            .iter()
            .any(|p| src.contains(p))
}

fn line_passes_raw_llm_messages(line: &str, destructures_raw_messages: bool) -> bool {
    [
        "messages: req.body.messages",
        "messages: request.body.messages",
        "messages: body.messages",
        "messages: input.messages",
        "messages: params.messages",
    ]
    .iter()
    .any(|p| line.contains(p))
        || (destructures_raw_messages
            && ["messages,", "messages: messages", "messages }"]
                .iter()
                .any(|p| line.contains(p)))
}

fn check_llm_tools_missing_step_bound(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    for call_name in ["generateText(", "streamText("] {
        let mut search_from = 0;
        while let Some(rel) = src[search_from..].find(call_name) {
            let hit = search_from + rel;
            let after = &src[hit + call_name.len()..];
            if let Some((call_inside, _)) = split_balanced_parens(after) {
                let has_tools = ["tools:", "tools,", "tools }", "tools\n"]
                    .iter()
                    .any(|p| call_inside.contains(p));
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
}

fn check_llm_tool_execute_dangerous_sinks(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let defines_tool = find_standalone_call(src, "tool(").is_some()
        || [
            "createTool(",
            "defineTool(",
            "server.tool(",
            "registerTool(",
        ]
        .iter()
        .any(|p| src.contains(p));
    let has_sink_guard = (src.contains("path.resolve(") && src.contains(".startsWith("))
        || src.contains("ALLOWED_")
        || src.contains("allowlist");
    if !defines_tool || has_sink_guard {
        return;
    }
    let src_has_execute = src.contains("execute:");
    for (idx, line) in src.lines().enumerate() {
        let has_execute_or_tool = src_has_execute
            || ["execute:", "server.tool(", "registerTool("]
                .iter()
                .any(|p| line.contains(p));
        if has_execute_or_tool && line_has_dangerous_tool_sink(line) {
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

fn line_has_dangerous_tool_sink(line: &str) -> bool {
    find_standalone_call(line, "exec(").is_some()
        || find_standalone_call(line, "execSync(").is_some()
        || find_standalone_call(line, "spawn(").is_some()
        || [
            "fs.readFile",
            "fs.writeFile",
            "fs.unlink",
            "fs.rm",
            "$queryRawUnsafe(",
            "$executeRawUnsafe(",
        ]
        .iter()
        .any(|p| line.contains(p))
}

pub(super) fn check_supabase_service_role_unscoped_query(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    let uses_service_role = [
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_SERVICE_KEY",
        "SERVICE_ROLE_KEY",
        "serviceRoleKey",
        "supabaseAdmin",
        "adminSupabase",
    ]
    .iter()
    .any(|p| src.contains(p));
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

        if is_unscoped_supabase_request_chain(chain) {
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

fn is_unscoped_supabase_request_chain(chain: &str) -> bool {
    let has_data_op = [".select(", ".update(", ".delete(", ".upsert("]
        .iter()
        .any(|p| chain.contains(p));
    let uses_request_param = [
        "req.",
        "request.",
        "params.",
        "query.",
        "body.",
        "searchParams",
        ".eq(\"id\"",
        ".eq('id'",
    ]
    .iter()
    .any(|p| chain.contains(p));
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

    has_data_op && uses_request_param && !has_tenant_or_owner_scope
}
