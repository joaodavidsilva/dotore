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
    artifacts_and_runtime::evaluate_remaining_security_scan_rules, emit_line_diag,
    find_standalone_call,
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

    // 18. Remaining security-scan rules
    evaluate_remaining_security_scan_rules(file, path_str, line_starts, is_active, out);
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
