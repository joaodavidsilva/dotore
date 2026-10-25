//! Next.js JSX element, `<Head>`, `<Script>`, `<Image>`, `<Link>`, error boundary,
//! route handler, redirect, and metadata rule detectors.

use super::push_srv_diag;
use crate::{
    graph::ProjectGraph,
    ir::{ByteSpan, FileIr, JsxElementIr, SourceLoc, types::loc_from_line_starts},
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

pub(super) fn check_nextjs_no_script_in_head(file: &FileIr, out: &mut Vec<Diagnostic>) {
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

pub(super) fn check_nextjs_no_head_import(
    file: &FileIr,
    path_str: &str,
    out: &mut Vec<Diagnostic>,
) {
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

pub(super) fn check_nextjs_no_vercel_og_import(file: &FileIr, out: &mut Vec<Diagnostic>) {
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

pub(super) fn check_nextjs_async_client_component(
    file: &FileIr,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !file.module.has_use_client {
        return;
    }
    for (idx, line) in file.source.lines().enumerate() {
        let Some(pos) = line.find("async function ") else {
            continue;
        };
        let after = line
            .get(pos + "async function ".len()..)
            .unwrap_or_default()
            .trim();
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

pub(super) fn evaluate_remaining_nextjs_rules<F>(
    _graph: &ProjectGraph,
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let norm = format!("/{}", path_str.trim_start_matches('/'));
    check_nextjs_error_boundary_rules(file, &norm, is_active, out);
    for jsx in &file.jsx_elements {
        check_nextjs_jsx_element_rules(file, jsx, is_active, out);
    }
    check_nextjs_route_and_redirect_rules(file, &norm, line_starts, is_active, out);
    check_nextjs_metadata_and_client_fetch_rules(file, &norm, line_starts, is_active, out);
}

fn check_nextjs_error_boundary_rules<F>(
    file: &FileIr,
    norm: &str,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
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
}

fn check_nextjs_jsx_element_rules<F>(
    file: &FileIr,
    jsx: &JsxElementIr,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let start = usize::try_from(jsx.span.start).unwrap_or(0);
    let end = usize::try_from(jsx.span.end).unwrap_or(0);
    let tag_text = file.source.get(start..end).unwrap_or("");

    match jsx.name.as_str() {
        "Image" => {
            if jsx.attributes.iter().any(|a| a == "fill")
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
        }
        "a" => {
            if is_active(RuleId::NextjsNoAElement).is_some()
                && (tag_text.contains("href=\"/") || tag_text.contains("href='/"))
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
        "link" => check_nextjs_jsx_link_element(file, jsx, tag_text, is_active, out),
        "script" | "Script" => check_nextjs_jsx_script_element(file, jsx, tag_text, is_active, out),
        _ => {}
    }
}

fn check_nextjs_jsx_link_element<F>(
    file: &FileIr,
    jsx: &JsxElementIr,
    tag_text: &str,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if tag_text.contains("fonts.googleapis.com") && is_active(RuleId::NextjsNoFontLink).is_some() {
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

fn check_nextjs_jsx_script_element<F>(
    file: &FileIr,
    jsx: &JsxElementIr,
    tag_text: &str,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
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
    if tag_text.contains("polyfill.io") && is_active(RuleId::NextjsNoPolyfillScript).is_some() {
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

fn check_nextjs_route_and_redirect_rules<F>(
    file: &FileIr,
    norm: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;

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

    if is_active(RuleId::NextjsNoRedirectInTryCatch).is_some()
        && src.contains("try {")
        && ["redirect(", "permanentRedirect(", "notFound("]
            .iter()
            .any(|p| src.contains(p))
        && !src.contains("unstable_rethrow(")
    {
        let pos = ["redirect(", "permanentRedirect(", "notFound("]
            .into_iter()
            .find_map(|p| src.find(p))
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

    if is_active(RuleId::NextjsNoClientSideRedirect).is_some()
        && src.contains("useEffect(")
        && [
            "router.push(",
            "router.replace(",
            "window.location.href =",
        ]
        .iter()
        .any(|p| src.contains(p))
    {
        let pos = [
            "router.push(",
            "router.replace(",
            "window.location.href =",
        ]
        .into_iter()
        .find_map(|p| src.find(p))
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
}

fn check_nextjs_metadata_and_client_fetch_rules<F>(
    file: &FileIr,
    norm: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;

    if file.module.has_use_client
        && (norm.contains("/page.") || norm.contains("/layout."))
        && is_active(RuleId::NextjsNoClientFetchForServerData).is_some()
    {
        emit_client_fetch_for_server_data(file, out);
    }

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
    let rest = after.get(1..)?;
    let end = rest.find(char::from(quote))?;
    rest.get(..end).map(str::to_string)
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
