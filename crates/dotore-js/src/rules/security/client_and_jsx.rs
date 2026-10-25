//! Client-side secret exposure, storage, `eval`, path containment, React Markdown,
//! React Router CSP nonce, `dangerouslySetInnerHTML`, and `<iframe>` sandbox rules.

use crate::{
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId},
};

use super::{
    extract_jsx_attr_value, extract_object_prop_after_call, find_standalone_call,
    find_string_timer_call, is_identifier_token, is_server_only_path, push_sec_diag,
    resolve_static_string_in_file, split_balanced_parens, unquote_js_string_literal,
};

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
        let after = line
            .get(json_pos + "JSON.stringify(".len()..)
            .unwrap_or_default();
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
        while let Some(rel) = line.get(search_from..).and_then(|s| s.find(prefix)) {
            let start = search_from + rel;
            let rest = line.get(start..).unwrap_or_default();
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
        let after = line
            .get(sw_pos + ".startsWith(".len()..)
            .unwrap_or_default();
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
        if jsx.name != "iframe" {
            continue;
        }
        if !jsx.attributes.iter().any(|a| a == "sandbox") {
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
            continue;
        }
        let start = usize::try_from(jsx.span.start).unwrap_or(0);
        let end = usize::try_from(jsx.span.end).unwrap_or(file.source.len());
        let snippet = file.source.get(start..end).unwrap_or("");
        let opener = snippet.split('>').next().unwrap_or(snippet);
        if iframe_sandbox_allows_scripts_and_same_origin(opener) {
            push_sec_diag(
                out,
                file,
                RuleId::IframeMissingSandbox,
                "iframeMissingSandbox",
                "iframe",
                "`<iframe>` combines `allow-scripts` and `allow-same-origin` in `sandbox`, allowing framed content to remove its own sandbox.",
                jsx.loc,
                jsx.span,
            );
        }
    }
}

fn iframe_sandbox_allows_scripts_and_same_origin(opener: &str) -> bool {
    let lower = opener.to_ascii_lowercase();
    let Some(pos) = lower.find("sandbox") else {
        return false;
    };
    let after = &lower[pos + "sandbox".len()..];
    after.contains("allow-scripts") && after.contains("allow-same-origin")
}
