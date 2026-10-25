//! Upgraded authentication, cryptography, CORS, and `postMessage` origin trust rules
//! (`postmessage-origin-risk`, `cors-cookie-trust-risk`, `jwt-insecure-verification`,
//! `insecure-crypto-risk`).

use crate::{
    ir::FileIr,
    rules::types::{Diagnostic, RuleId},
};

use super::{
    emit_line_diag, find_binding_initializer_in_source, find_standalone_call, is_identifier_token,
    split_balanced_parens, split_top_level_args, unquote_js_string_literal,
};

pub(super) fn check_postmessage_origin_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;

    // 1. Listener reading event.data without any .origin check
    let has_message_listener = src.contains("addEventListener(\"message\"")
        || src.contains("addEventListener('message'")
        || src.contains("window.onmessage");
    if has_message_listener
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

    // 2. Weak event.origin checks and sensitive postMessage(payload, "*")
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if has_weak_origin_check_in_line(line, src) {
            emit_line_diag(
                out,
                file,
                RuleId::PostmessageOriginRisk,
                "postmessageOriginRisk",
                "origin",
                "`postMessage` origin check uses substring, prefix, suffix, or unanchored regex matching that can be bypassed by attacker-controlled domains.",
                idx,
                line,
                line_starts,
            );
            continue;
        }

        if is_sensitive_wildcard_postmessage_in_line(line, src) {
            emit_line_diag(
                out,
                file,
                RuleId::PostmessageOriginRisk,
                "postmessageOriginRisk",
                "postMessage",
                "`postMessage` sends sensitive token, auth, or session data to wildcard targetOrigin `\"*\"`.",
                idx,
                line,
                line_starts,
            );
        }
    }
}

fn has_weak_origin_check_in_line(line: &str, src: &str) -> bool {
    for prefix in ["event.origin", "e.origin", "msg.origin", "ev.origin"] {
        for weak_method in [".includes(", ".startsWith(", ".indexOf(", ".search("] {
            let pat = format!("{prefix}{weak_method}");
            if line.contains(&pat) {
                return true;
            }
        }
        let ends_with_pat = format!("{prefix}.endsWith(");
        if let Some(pos) = line.find(&ends_with_pat) {
            let after = &line[pos + ends_with_pat.len()..];
            if let Some((arg_inside, _)) = split_balanced_parens(after)
                && let Some(lit) = unquote_js_string_literal(arg_inside)
                && !lit.starts_with('.')
                && !lit.starts_with("://")
            {
                return true;
            }
        }
        let match_pat = format!("{prefix}.match(");
        if let Some(pos) = line.find(&match_pat) {
            let after = &line[pos + match_pat.len()..];
            if let Some((arg_inside, _)) = split_balanced_parens(after)
                && is_unanchored_regex_expr(arg_inside, src)
            {
                return true;
            }
        }
        let test_pat = format!(".test({prefix})");
        if let Some(pos) = line.find(&test_pat) {
            let receiver = line[..pos].trim_end();
            if is_unanchored_regex_receiver(receiver, src) {
                return true;
            }
        }
    }
    false
}

fn is_unanchored_regex_receiver(receiver: &str, src: &str) -> bool {
    let token = receiver
        .rsplit(|c: char| {
            c.is_whitespace() || matches!(c, '(' | '!' | '&' | '|' | '=' | '?' | ':' | '{' | ';')
        })
        .next()
        .unwrap_or(receiver)
        .trim();
    is_unanchored_regex_expr(token, src)
}

fn is_unanchored_regex_expr(expr: &str, src: &str) -> bool {
    let trimmed = expr.trim();
    if let Some(body) = extract_regex_literal_body(trimmed) {
        return !body.starts_with('^') || !body.ends_with('$');
    }
    if is_identifier_token(trimmed)
        && let Some(init) = find_binding_initializer_in_source(src, trimmed)
        && let Some(body) = extract_regex_literal_body(init.trim())
    {
        return !body.starts_with('^') || !body.ends_with('$');
    }
    false
}

fn extract_regex_literal_body(s: &str) -> Option<&str> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('/') {
        let last_slash = rest.rfind('/')?;
        return Some(&rest[..last_slash]);
    }
    if let Some(after_new) = t.strip_prefix("new RegExp(")
        && let Some((inside, _)) = split_balanced_parens(after_new)
    {
        let first_arg = split_top_level_args(inside).first().copied()?;
        return unquote_js_string_literal(first_arg);
    }
    None
}

fn is_sensitive_wildcard_postmessage_in_line(line: &str, src: &str) -> bool {
    let call_pos = line
        .find(".postMessage(")
        .map(|p| p + 1)
        .or_else(|| find_standalone_call(line, "postMessage("));
    let Some(pos) = call_pos else {
        return false;
    };
    let Some(after) = line.get(pos + "postMessage(".len()..) else {
        return false;
    };
    let Some((inside, _)) = split_balanced_parens(after) else {
        return false;
    };
    let args = split_top_level_args(inside);
    if args.len() < 2 {
        return false;
    }
    let target_origin = args[1].trim();
    if !matches!(target_origin, "\"*\"" | "'*'" | "`*`") {
        return false;
    }
    let payload = args[0].trim();
    if expr_references_sensitive_data(payload) {
        return true;
    }
    if is_identifier_token(payload)
        && let Some(init) = find_binding_initializer_in_source(src, payload)
    {
        return expr_references_sensitive_data(&init);
    }
    false
}

fn expr_references_sensitive_data(expr: &str) -> bool {
    let lower = expr.to_ascii_lowercase();
    for kw in [
        "token",
        "secret",
        "jwt",
        "password",
        "passwd",
        "session",
        "apikey",
        "api_key",
        "credential",
        "cookie",
        "bearer",
        "privatekey",
        "private_key",
    ] {
        if lower.contains(kw) {
            return true;
        }
    }
    // Check "auth" without matching "author"
    if let Some(pos) = lower.find("auth") {
        let after = &lower[pos + 4..];
        if !after.starts_with("or") {
            return true;
        }
    }
    false
}

pub(super) fn check_cors_cookie_trust_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;

    // 1. Existing wildcard / broad subdomain with Access-Control-Allow-Credentials: true
    let has_allow_creds = src.contains("Access-Control-Allow-Credentials") && src.contains("true");
    if has_allow_creds && src.contains("Access-Control-Allow-Origin") {
        let is_wildcard_or_broad =
            src.contains("\"*\"") || src.contains("'*'") || src.contains("https://docs.");
        let reads_request_origin = src.contains("req.headers.origin")
            || src.contains("req.headers[\"origin\"]")
            || src.contains("req.headers['origin']")
            || src.contains("request.headers.get(\"origin\")")
            || src.contains("request.headers.get('origin')")
            || src.contains("req.get(\"origin\")")
            || src.contains("req.get('origin')")
            || src.contains("headers().get(\"origin\")")
            || src.contains("headers().get('origin')");
        let has_origin_guard = has_origin_allowlist_guard(src);

        if is_wildcard_or_broad || (reads_request_origin && !has_origin_guard) {
            let line_idx = src
                .lines()
                .position(|l| l.contains("Access-Control-Allow-Origin"))
                .or_else(|| src.lines().position(|l| l.contains("Access-Control-Allow-")))
                .unwrap_or(0);
            emit_line_diag(
                out,
                file,
                RuleId::CorsCookieTrustRisk,
                "corsCookieTrustRisk",
                "Access-Control-Allow-Origin",
                "Credentialed CORS reflects an unvalidated `Origin` header or uses a wildcard/broad origin alongside `Access-Control-Allow-Credentials: true`.",
                line_idx,
                src.lines().nth(line_idx).unwrap_or(""),
                line_starts,
            );
            return;
        }
    }

    // 2. cors({ origin: true | "*" | (o, cb) => cb(null, true), credentials: true })
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("credentials:true") && !has_origin_allowlist_guard(src) {
        let is_permissive_cors_obj = compact.contains("origin:true")
            || compact.contains("origin:\"*\"")
            || compact.contains("origin:'*'")
            || compact.contains("cb(null,true)")
            || compact.contains("callback(null,true)");
        if is_permissive_cors_obj {
            let line_idx = src
                .lines()
                .position(|l| l.contains("cors(") || l.contains("origin:"))
                .unwrap_or(0);
            emit_line_diag(
                out,
                file,
                RuleId::CorsCookieTrustRisk,
                "corsCookieTrustRisk",
                "cors",
                "CORS configuration enables `credentials: true` while reflecting or allowing any origin without an allowlist.",
                line_idx,
                src.lines().nth(line_idx).unwrap_or(""),
                line_starts,
            );
        }
    }
}

fn has_origin_allowlist_guard(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    lower.contains(".includes(")
        || lower.contains(".has(")
        || lower.contains("allowlist")
        || lower.contains("whitelist")
        || lower.contains("allowedorigins")
        || lower.contains("allowed_origins")
        || src.contains("ALLOWED")
        || src.contains("origin === ")
        || src.contains("origin !== ")
}

pub(super) fn check_jwt_insecure_verification(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
    if !src.contains("jwt")
        && !src.contains("jsonwebtoken")
        && !src.contains("jose")
        && !src.contains("decodeJwt")
        && !src.contains("jwtVerify")
    {
        return;
    }

    let module_verifies_jwt = src.contains("jwt.verify(")
        || src.contains("jwtVerify(")
        || src.contains(".verify(")
        || src.contains("createRemoteJWKSet(");

    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = compact.to_ascii_lowercase();

        // 1. Explicit `none` algorithm
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
            continue;
        }

        // 2. Asymmetric + symmetric algorithm confusion (`RS256` + `HS256`)
        let has_asymmetric = ["rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "eddsa"]
            .iter()
            .any(|a| lower.contains(a));
        let has_symmetric = ["hs256", "hs384", "hs512"].iter().any(|s| lower.contains(s));
        if lower.contains("algorithms:[") && has_asymmetric && has_symmetric {
            emit_line_diag(
                out,
                file,
                RuleId::JwtInsecureVerification,
                "jwtInsecureVerification",
                "algorithms",
                "JWT verification mixes asymmetric (`RS*`/`ES*`) and symmetric (`HS*`) algorithms, enabling key-confusion forgery.",
                idx,
                line,
                line_starts,
            );
            continue;
        }
        if has_unpinned_public_key_jwt_verify(line) {
            emit_line_diag(
                out,
                file,
                RuleId::JwtInsecureVerification,
                "jwtInsecureVerification",
                "jwt.verify",
                "`jwt.verify` passes an asymmetric public key without pinning `algorithms: [\"RS256\"]`, allowing `HS256` key-confusion forgery.",
                idx,
                line,
                line_starts,
            );
            continue;
        }

        // 3. Unvalidated `header.jku` or `header.x5u` key fetch
        if (line.contains(".jku") || line.contains(".x5u"))
            && (line.contains("fetch(")
                || line.contains("axios.")
                || line.contains("got(")
                || line.contains("createRemoteJWKSet(")
                || line.contains("jwksUri"))
            && !has_origin_allowlist_guard(src)
        {
            emit_line_diag(
                out,
                file,
                RuleId::JwtInsecureVerification,
                "jwtInsecureVerification",
                "jku",
                "JWT verification fetches signing keys from an unvalidated `header.jku` or `header.x5u` URL.",
                idx,
                line,
                line_starts,
            );
            continue;
        }

        // 4. `jwt.decode` / `decodeJwt` used without signature verification in the module
        if !module_verifies_jwt
            && (line.contains("jwt.decode(")
                || line.contains("jose.decodeJwt(")
                || find_standalone_call(line, "decodeJwt(").is_some())
        {
            emit_line_diag(
                out,
                file,
                RuleId::JwtInsecureVerification,
                "jwtInsecureVerification",
                "decode",
                "`jwt.decode()` / `decodeJwt()` reads token claims without verifying the cryptographic signature.",
                idx,
                line,
                line_starts,
            );
        }
    }
}

fn has_unpinned_public_key_jwt_verify(line: &str) -> bool {
    let Some(pos) = line.find("jwt.verify(") else {
        return false;
    };
    let after = &line[pos + "jwt.verify(".len()..];
    let Some((inside, _)) = split_balanced_parens(after) else {
        return false;
    };
    let args = split_top_level_args(inside);
    if args.len() != 2 {
        return false;
    }
    let key_arg = args[1].to_ascii_lowercase();
    ["public", "pubkey", "cert", "pem", "rsa"]
        .iter()
        .any(|w| key_arg.contains(w))
}

pub(super) fn check_insecure_crypto_risk(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let src = &file.source;
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
    let has_constant_time_eq =
        src.contains("timingSafeEqual") || src.contains("constantTimeEqual");

    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
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
            || lower_line.contains("createcipheriv('des")
            || lower_line.contains("createcipheriv(\"rc4")
            || lower_line.contains("createcipheriv('rc4")
            || ((lower_line.contains("createcipheriv(")
                || lower_line.contains("createdecipheriv("))
                && (lower_line.contains("-ecb\"") || lower_line.contains("-ecb'")));
        let is_static_iv = !is_weak_cipher && has_static_iv_in_cipheriv(line, src);
        let is_math_random_secret = line.contains("Math.random(")
            && [
                "token", "secret", "password", "nonce", "salt", "csrf", "otp",
            ]
            .iter()
            .any(|w| lower_line.contains(w));
        let is_non_constant_time_cmp =
            !has_constant_time_eq && has_non_constant_time_secret_comparison(line);

        if is_weak_hash
            || is_weak_cipher
            || is_static_iv
            || is_math_random_secret
            || is_non_constant_time_cmp
        {
            emit_line_diag(
                out,
                file,
                RuleId::InsecureCryptoRisk,
                "insecureCryptoRisk",
                "crypto",
                "Weak cryptographic primitive, static IV, non-constant-time secret comparison, or non-cryptographic randomness used in a security-sensitive context.",
                idx,
                line,
                line_starts,
            );
        }
    }
}

fn has_static_iv_in_cipheriv(line: &str, src: &str) -> bool {
    let Some(pos) = line.find("createCipheriv(") else {
        return false;
    };
    let after = &line[pos + "createCipheriv(".len()..];
    let Some((inside, _)) = split_balanced_parens(after) else {
        return false;
    };
    let args = split_top_level_args(inside);
    if args.len() < 3 {
        return false;
    }
    let iv_arg = args[2].trim();
    if is_static_iv_expr(iv_arg) {
        return true;
    }
    if is_identifier_token(iv_arg)
        && let Some(init) = find_binding_initializer_in_source(src, iv_arg)
    {
        return is_static_iv_expr(init.trim());
    }
    false
}

fn is_static_iv_expr(expr: &str) -> bool {
    let t = expr.trim();
    if unquote_js_string_literal(t).is_some() {
        return true;
    }
    t.starts_with("Buffer.alloc(")
        || t.starts_with("Buffer.allocUnsafe(")
        || t.starts_with("new Uint8Array(")
        || (t.starts_with("Buffer.from(")
            && (t.contains("Buffer.from(\"") || t.contains("Buffer.from('")))
}

fn has_non_constant_time_secret_comparison(line: &str) -> bool {
    for op in ["===", "!==", "==", "!="] {
        let Some(pos) = line.find(op) else {
            continue;
        };
        let lhs = line[..pos].trim();
        let rhs = line[pos + op.len()..]
            .trim()
            .trim_end_matches([';', '{', ')', ','])
            .trim();
        if is_trivial_null_or_type_operand(lhs) || is_trivial_null_or_type_operand(rhs) {
            return false;
        }
        if is_signature_or_secret_operand(lhs) || is_signature_or_secret_operand(rhs) {
            return true;
        }
        return false;
    }
    false
}

fn is_trivial_null_or_type_operand(side: &str) -> bool {
    let mut t = side.trim();
    for prefix in ["if", "return"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            t = rest.trim_start();
        }
    }
    t = t.trim_start_matches(['(', '&', '|']).trim();
    t.is_empty()
        || matches!(
            t,
            "null" | "undefined" | "\"\"" | "''" | "``" | "true" | "false" | "0" | "-1"
        )
        || t.starts_with("typeof ")
        || t.ends_with(".length")
        || t.contains(".indexOf(")
}

fn is_signature_or_secret_operand(side: &str) -> bool {
    let lower = side.to_ascii_lowercase();
    [
        "signature",
        "expectedsignature",
        "receivedsignature",
        "computedsignature",
        "webhooksignature",
        "hmac",
        "computedhmac",
        "expectedhmac",
        "digest",
        "expecteddigest",
        "x-api-key",
        "x-hub-signature",
        "x-signature",
        "stripe-signature",
        "secretapikey",
        "apikey",
        "api_key",
        "secrettoken",
        "webhooksecret",
        "authorization",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}
