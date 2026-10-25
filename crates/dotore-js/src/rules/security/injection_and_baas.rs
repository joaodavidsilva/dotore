//! Injection, auth, crypto, BaaS (Supabase/Firebase), and AI/MCP tool capability
//! security-scan rules (`raw-sql-injection-risk`, `nosql-injection-risk`,
//! `command-execution-input-risk`, `path-traversal-risk`, `untrusted-redirect-following`,
//! `clickjacking-redirect-risk`, `svg-filter-clickjacking-risk`,
//! `jwt-insecure-verification`, `insecure-crypto-risk`, `insecure-session-cookie`,
//! `webhook-signature-risk`, `postmessage-origin-risk`, `cors-cookie-trust-risk`,
//! `request-body-mass-assignment`, `supabase-table-missing-rls`,
//! `supabase-rls-policy-risk`, `supabase-client-owned-authz-field`,
//! `firebase-permissive-rules`, `firebase-client-owned-authz-field`,
//! `firebase-query-filter-as-auth`, `mcp-tool-capability-risk`,
//! `agent-tool-capability-risk`, `secret-in-fallback`).

use std::collections::HashSet;

use crate::{
    ir::FileIr,
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

use super::{
    artifacts_and_runtime::evaluate_remaining_security_scan_rules,
    auth_and_origin::{
        check_cors_cookie_trust_risk, check_insecure_crypto_risk, check_jwt_insecure_verification,
        check_postmessage_origin_risk,
    },
    emit_line_diag, find_standalone_call,
};

pub(super) fn evaluate_security_scan_patterns<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    check_injection_and_redirect_scan_rules(file, line_starts, is_active, out);
    check_auth_crypto_and_cookie_scan_rules(file, path_str, line_starts, is_active, out);
    check_supabase_and_firebase_scan_rules(file, path_str, line_starts, is_active, out);
    check_mcp_agent_and_fallback_scan_rules(file, line_starts, is_active, out);
    evaluate_remaining_security_scan_rules(file, path_str, line_starts, is_active, out);
}

fn check_injection_and_redirect_scan_rules<F>(
    file: &FileIr,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
    if is_active(RuleId::RawSqlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_raw_sql_injection_line(line) {
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
    if is_active(RuleId::NosqlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_nosql_injection_line(line) {
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
    if is_active(RuleId::CommandExecutionInputRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_command_exec_input_line(line) {
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
    if is_active(RuleId::PathTraversalRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_path_traversal_line(line) {
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
    check_redirect_and_clickjacking_scan_rules(file, line_starts, is_active, out);
}

fn is_raw_sql_injection_line(line: &str) -> bool {
    if line.contains("$queryRawUnsafe(")
        || line.contains("$executeRawUnsafe(")
        || (line.contains("Prisma.raw(") && line.contains("${"))
        || (line.contains("sql.raw(") && line.contains("${"))
    {
        return true;
    }
    if line.contains(".query(") && line.contains("${") {
        let upper = line.to_ascii_uppercase();
        return ["SELECT ", "INSERT ", "UPDATE ", "DELETE "]
            .iter()
            .any(|kw| upper.contains(kw));
    }
    false
}

fn is_nosql_injection_line(line: &str) -> bool {
    if line.contains("$where") {
        return true;
    }
    let has_req = line.contains("req.") || line.contains("request.");
    has_req
        && ((line.contains(".find(") && line.contains("JSON.parse("))
            || line.contains("$regex")
            || line.contains("new RegExp("))
}

fn is_command_exec_input_line(line: &str) -> bool {
    let has_exec = find_standalone_call(line, "exec(").is_some()
        || find_standalone_call(line, "execSync(").is_some()
        || line.contains("child_process.exec")
        || line.contains("cp.exec")
        || (line.contains("spawn") && line.contains("shell: true"));
    let has_taint = [
        "req.",
        "request.",
        "params.",
        "query.",
        "body.",
        "searchParams",
    ]
    .iter()
    .any(|t| line.contains(t));
    has_exec && has_taint
}

fn is_path_traversal_line(line: &str) -> bool {
    let has_fs = [
        "readFile(",
        "readFileSync(",
        "writeFile(",
        "writeFileSync(",
        "path.join(",
        "path.resolve(",
    ]
    .iter()
    .any(|p| line.contains(p));
    let has_taint = ["req.", "request.", "params.", "query.", "body."]
        .iter()
        .any(|t| line.contains(t));
    has_fs && has_taint && !line.contains("basename(")
}

fn check_redirect_and_clickjacking_scan_rules<F>(
    file: &FileIr,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
    if is_active(RuleId::UntrustedRedirectFollowing).is_some()
        && !src.contains("redirect: \"manual\"")
        && !src.contains("redirect: 'manual'")
        && !src.contains("redirect: \"error\"")
    {
        for (idx, line) in src.lines().enumerate() {
            if is_untrusted_redirect_fetch_line(line) {
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

    if is_active(RuleId::ClickjackingRedirectRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_clickjacking_or_redirect_line(line) {
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
        && ["filter: url(#", "filter:url(#", "<feDisplacementMap"]
            .iter()
            .any(|p| src.contains(p))
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
}

fn is_untrusted_redirect_fetch_line(line: &str) -> bool {
    (line.contains("fetch(") || line.contains("axios.get(") || line.contains("got("))
        && [
            "req.",
            "request.",
            "searchParams",
            "targetUrl",
            "callbackUrl",
            "redirectUrl",
            "webhookUrl",
        ]
        .iter()
        .any(|p| line.contains(p))
}

fn is_clickjacking_or_redirect_line(line: &str) -> bool {
    let is_unsafe_redirect = line.contains("redirect(")
        && [
            "searchParams.get",
            "nextUrl.searchParams",
            "returnTo",
            "callbackUrl",
        ]
        .iter()
        .any(|p| line.contains(p))
        && !["safe", "valid", "allowlist"].iter().any(|g| line.contains(g));
    let is_unsafe_frame = [
        "frame-ancestors *",
        "X-Frame-Options: ALLOW",
        "\"X-Frame-Options\": \"ALLOW\"",
    ]
    .iter()
    .any(|p| line.contains(p));
    is_unsafe_redirect || is_unsafe_frame
}

fn check_auth_crypto_and_cookie_scan_rules<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
    if is_active(RuleId::JwtInsecureVerification).is_some() {
        check_jwt_insecure_verification(file, line_starts, out);
    }
    if is_active(RuleId::InsecureCryptoRisk).is_some() {
        check_insecure_crypto_risk(file, line_starts, out);
    }
    if is_active(RuleId::InsecureSessionCookie).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_insecure_session_cookie_line(line) {
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
    if is_active(RuleId::WebhookSignatureRisk).is_some() && is_unverified_webhook_handler(path_str, src) {
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
    if is_active(RuleId::PostmessageOriginRisk).is_some() {
        check_postmessage_origin_risk(file, line_starts, out);
    }
    if is_active(RuleId::CorsCookieTrustRisk).is_some() {
        check_cors_cookie_trust_risk(file, line_starts, out);
    }
    if is_active(RuleId::RequestBodyMassAssignment).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_mass_assignment_line(line) {
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
}

fn is_insecure_session_cookie_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let is_cookie_set = [
        ".cookie(",
        ".cookies.set(",
        "cookies().set(",
        "document.cookie",
    ]
    .iter()
    .any(|p| lower.contains(p));
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
    let is_insecure = ["httponly: false", "httponly:false", "document.cookie"]
        .iter()
        .any(|p| lower.contains(p));
    is_cookie_set && has_auth_name && is_insecure
}

fn is_unverified_webhook_handler(path_str: &str, src: &str) -> bool {
    let lower_path = path_str.to_ascii_lowercase();
    let lower_src = src.to_ascii_lowercase();
    let is_webhook_file = lower_path.contains("webhook") || lower_src.contains("webhookhandler");
    let has_post_handler = ["function POST", "const POST", "webhookHandler"]
        .iter()
        .any(|p| src.contains(p));
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
    is_webhook_file && has_post_handler && has_req_read && !has_verification
}

fn is_mass_assignment_line(line: &str) -> bool {
    ["...req.body", "...request.body", "...req.query"]
        .iter()
        .any(|p| line.contains(p))
        || (line.contains("Object.assign(")
            && (line.contains("req.body") || line.contains("request.body")))
}

fn check_supabase_and_firebase_scan_rules<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
    if is_active(RuleId::SupabaseTableMissingRls).is_some() && path_str.ends_with(".sql") {
        check_supabase_table_missing_rls(file, line_starts, out);
    }
    if is_active(RuleId::SupabaseRlsPolicyRisk).is_some() && path_str.ends_with(".sql") {
        check_supabase_rls_policy_risk(file, line_starts, out);
    }
    if is_active(RuleId::SupabaseClientOwnedAuthzField).is_some() && !file.module.has_use_server {
        for (idx, line) in src.lines().enumerate() {
            if is_supabase_client_authz_write_line(line) {
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
    check_firebase_client_code_rules(file, line_starts, is_active, out);
}

fn is_supabase_client_authz_write_line(line: &str) -> bool {
    (line.contains("supabase") || line.contains(".from("))
        && [".insert(", ".update(", ".upsert("]
            .iter()
            .any(|p| line.contains(p))
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
}

fn check_firebase_client_code_rules<F>(
    file: &FileIr,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
    let has_firebase_ctx = [
        "firebase",
        "firestore",
        "setDoc(",
        "updateDoc(",
        "addDoc(",
    ]
    .iter()
    .any(|p| src.contains(p));
    if is_active(RuleId::FirebaseClientOwnedAuthzField).is_some() && has_firebase_ctx {
        for (idx, line) in src.lines().enumerate() {
            if is_firebase_client_authz_write_line(line) {
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
            if is_firebase_query_filter_auth_line(line) {
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
}

fn is_firebase_client_authz_write_line(line: &str) -> bool {
    ["setDoc(", "updateDoc(", "addDoc(", ".set(", ".update("]
        .iter()
        .any(|p| line.contains(p))
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
}

fn is_firebase_query_filter_auth_line(line: &str) -> bool {
    line.contains(".where(")
        && (line.contains("\"==\"") || line.contains("'=='"))
        && ["uid", "userId", "ownerId", "orgId", "tenantId", "role"]
            .iter()
            .any(|f| line.contains(&format!("\"{f}\"")) || line.contains(&format!("'{f}'")))
}

fn check_mcp_agent_and_fallback_scan_rules<F>(
    file: &FileIr,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;
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
        && ["@modelcontextprotocol/sdk", "McpServer", "McpAgent"]
            .iter()
            .any(|p| src.contains(p))
    {
        for (idx, line) in src.lines().enumerate() {
            if [".tool(", "registerTool(", "CallToolRequestSchema"]
                .iter()
                .any(|p| line.contains(p))
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
            if [
                "createTool(",
                "defineTool(",
                "new DynamicTool(",
                "new StructuredTool(",
                "tool({",
            ]
            .iter()
            .any(|p| line.contains(p))
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
    if is_active(RuleId::SecretInFallback).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if is_secret_in_fallback_line(line) {
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
}

fn is_secret_in_fallback_line(line: &str) -> bool {
    line.contains("process.env.")
        && (line.contains("??") || line.contains("||"))
        && (line.contains('"') || line.contains('\''))
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
}

fn check_supabase_table_missing_rls(file: &FileIr, line_starts: &[u32], out: &mut Vec<Diagnostic>) {
    let lower = file.source.to_ascii_lowercase();
    let mut enabled_tables = HashSet::new();
    for line in lower.lines() {
        if let Some(pos) = line.find("alter table")
            && line.contains("enable row level security")
        {
            let after = line
                .get(pos + "alter table".len()..)
                .unwrap_or_default()
                .trim();
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
        let after = l
            .get(pos + "create table".len()..)
            .unwrap_or_default()
            .trim();
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
