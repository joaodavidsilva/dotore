//! Integration tests for Ticket #10:
//! - Security & `security-scan` rule families (all 56 security rules, cross-file HTML sanitizer / KaTeX provenance, `window.open` target/rel/destination propagation)
//! - `server` & `nextjs` rule families (`server-auth-actions`, `server-sequential-independent-await` with cross-file cached async work, `nextjs-async-dynamic-api-not-awaited`, `nextjs-no-img-element` with cross-file `ImageResponse`/`satori` wrapper awareness, `nextjs-no-use-search-params-without-suspense` with cross-file `<Suspense>` awareness, and all remaining `server` and `nextjs` rules)
//! - Project-level supply-chain & RSC checks (`require-pnpm-hardening`, `no-vulnerable-react-server-components`, and fail-open `low-supply-chain-score` with local disk cache)

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    CapabilityGate, DotoreConfig, RuleCategory, RuleId, RuleSeverity, ScanOptions,
    analyze_project_sources, analyze_source, analyze_source_with_config, rule_registry,
    scan_workspace,
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dotore-t10-{prefix}-{nanos}"))
}

#[test]
fn registry_contains_all_56_security_rules_all_server_nextjs_rules_and_supply_chain_rules() {
    let registry = rule_registry();
    let security_count = registry
        .iter()
        .filter(|m| m.category == RuleCategory::Security)
        .count();
    assert!(
        security_count >= 56,
        "Expected at least 56 Security-category rules in registry, found {security_count}"
    );

    let required_ids = [
        // security & security-scan
        "no-danger",
        "no-danger-with-children",
        "iframe-missing-sandbox",
        "jsx-no-script-url",
        "jsx-no-target-blank",
        "window-open-without-noopener",
        "no-secrets-in-client-code",
        "auth-token-in-web-storage",
        "no-eval",
        "no-path-prefix-containment",
        "react-markdown-unsanitized-raw-html",
        "react-router-csp-nonce-consistency",
        "active-static-asset",
        "agent-tool-capability-risk",
        "artifact-baas-authority-surface",
        "artifact-env-leak",
        "artifact-secret-leak",
        "build-pipeline-secret-boundary",
        "clickjacking-redirect-risk",
        "command-execution-input-risk",
        "cors-cookie-trust-risk",
        "dangerous-html-sink",
        "firebase-client-owned-authz-field",
        "firebase-permissive-rules",
        "firebase-query-filter-as-auth",
        "git-provider-url-injection-risk",
        "import-metadata-execution-risk",
        "insecure-crypto-risk",
        "insecure-session-cookie",
        "jwt-insecure-verification",
        "key-lifecycle-risk",
        "local-rpc-native-bridge-risk",
        "mcp-tool-capability-risk",
        "mdx-ssr-execution-risk",
        "nosql-injection-risk",
        "package-metadata-secret",
        "path-traversal-risk",
        "plugin-update-trust-risk",
        "postmessage-origin-risk",
        "public-debug-artifact",
        "public-env-secret-name",
        "raw-sql-injection-risk",
        "repository-secret-file",
        "request-body-mass-assignment",
        "secret-in-fallback",
        "supabase-client-owned-authz-field",
        "supabase-rls-policy-risk",
        "supabase-table-missing-rls",
        "svg-filter-clickjacking-risk",
        "tenant-static-proxy-risk",
        "unsafe-json-in-html",
        "untrusted-redirect-following",
        "url-prefilled-privileged-action",
        "webhook-signature-risk",
        // server (8)
        "server-auth-actions",
        "server-after-nonblocking",
        "server-cache-with-object-literal",
        "server-dedup-props",
        "server-fetch-without-revalidate",
        "server-hoist-static-io",
        "server-no-mutable-module-state",
        "server-sequential-independent-await",
        // nextjs (25)
        "nextjs-async-client-component",
        "nextjs-async-dynamic-api-not-awaited",
        "nextjs-error-boundary-missing-use-client",
        "nextjs-global-error-missing-html-body",
        "nextjs-image-missing-sizes",
        "nextjs-inline-script-missing-id",
        "nextjs-metadata-url-consistency",
        "nextjs-missing-metadata",
        "nextjs-no-a-element",
        "nextjs-no-client-fetch-for-server-data",
        "nextjs-no-client-side-redirect",
        "nextjs-no-css-link",
        "nextjs-no-default-export-in-route-handler",
        "nextjs-no-edge-og-runtime",
        "nextjs-no-font-link",
        "nextjs-no-google-analytics-script",
        "nextjs-no-head-import",
        "nextjs-no-img-element",
        "nextjs-no-native-script",
        "nextjs-no-polyfill-script",
        "nextjs-no-redirect-in-try-catch",
        "nextjs-no-script-in-head",
        "nextjs-no-side-effect-in-get-handler",
        "nextjs-no-use-search-params-without-suspense",
        "nextjs-no-vercel-og-import",
        // project-level supply chain & RSC (3)
        "require-pnpm-hardening",
        "no-vulnerable-react-server-components",
        "low-supply-chain-score",
        "supply-chain-risk",
    ];

    for key in required_ids {
        assert!(
            RuleId::parse(key).is_some(),
            "Expected RuleId::parse({key:?}) to succeed"
        );
    }
}

#[test]
fn dangerous_html_sink_respects_same_file_and_cross_file_dompurify_and_katex_provenance() {
    let rules = &[RuleId::DangerousHtmlSink];

    // 1. Unsanitized prop HTML flags
    let diags = analyze_source(
        Path::new("src/components/Preview.tsx"),
        r#"export const Preview = ({ html }: { html: string }) => {
            const payload = html;
            return <div dangerouslySetInnerHTML={{ __html: payload }} />;
        };"#,
        Some(rules),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::DangerousHtmlSink);

    // 2. DOMPurify.sanitize at sink or via local variable is safe
    let clean_dompurify = analyze_source(
        Path::new("src/components/RichText.tsx"),
        r#"import DOMPurify from "dompurify";
        export const RichText = ({ html }: { html: string }) => {
            const clean = DOMPurify.sanitize(html);
            return <div dangerouslySetInnerHTML={{ __html: clean }} />;
        };"#,
        Some(rules),
    );
    assert!(clean_dompurify.is_empty());

    // 3. Cross-file DOMPurify / KaTeX helper provenance via ProjectGraph
    let cross_file_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("tsconfig.json"),
                r#"{
                    "compilerOptions": {
                        "baseUrl": ".",
                        "paths": { "@platejs/math": ["packages/math/src/index.ts"] }
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("packages/math/src/index.ts"),
                r#"export { getEquationHtml } from "./get-equation-html";"#.to_string(),
            ),
            (
                PathBuf::from("packages/math/src/get-equation-html.ts"),
                r#"import katex from "katex";
                export const getEquationHtml = ({ element, options }: any) =>
                    katex.renderToString(element.texExpression, options);"#
                    .to_string(),
            ),
            (
                PathBuf::from("src/safe-helper.ts"),
                r#"import katex from "katex";
                const escapeHtml = (value: string) => value.replaceAll("<", "&lt;");
                export const renderKaTeX = (value: string) => {
                    try { return katex.renderToString(value); }
                    catch { return `<span>${escapeHtml(value)}</span>`; }
                };"#
                .to_string(),
            ),
            (
                PathBuf::from("src/raw-helper.ts"),
                r#"import katex from "katex";
                export const renderMathToHtml = (value: string) => {
                    try { return katex.renderToString(value); }
                    catch { return value; }
                };"#
                .to_string(),
            ),
            (
                PathBuf::from("src/SafeMath.tsx"),
                r#"import { renderKaTeX } from "./safe-helper";
                import { getEquationHtml } from "@platejs/math";
                export const SafeMath = ({ value, element }: any) => {
                    const html = renderKaTeX(value);
                    const eq = getEquationHtml({ element, options: { throwOnError: false, trust: false } });
                    return (
                        <div>
                            <div dangerouslySetInnerHTML={{ __html: html }} />
                            <span dangerouslySetInnerHTML={{ __html: eq }} />
                        </div>
                    );
                };"#
                .to_string(),
            ),
            (
                PathBuf::from("src/UnsafeMath.tsx"),
                r#"import { renderMathToHtml } from "./raw-helper";
                import { getEquationHtml } from "@platejs/math";
                export const UnsafeMath = ({ value, element }: any) => {
                    const eq = getEquationHtml({ element, options: { trust: true } });
                    return (
                        <div>
                            <div dangerouslySetInnerHTML={{ __html: renderMathToHtml(value) }} />
                            <span dangerouslySetInnerHTML={{ __html: eq }} />
                        </div>
                    );
                };"#
                .to_string(),
            ),
        ],
        Some(rules),
    );

    let flagged_files: Vec<String> = cross_file_report
        .diagnostics
        .iter()
        .map(|d| d.file.to_string_lossy().to_string())
        .collect();
    assert!(
        !flagged_files.iter().any(|f| f.ends_with("SafeMath.tsx")),
        "SafeMath.tsx should not be flagged, got {flagged_files:?}"
    );
    assert_eq!(
        cross_file_report
            .diagnostics
            .iter()
            .filter(|d| d.file.ends_with("UnsafeMath.tsx"))
            .count(),
        2,
        "Expected both raw fallback and trust:true sinks in UnsafeMath.tsx to be flagged"
    );
}

#[test]
fn window_open_without_noopener_tracks_targets_features_handles_and_destinations() {
    let rules = &[RuleId::WindowOpenWithoutNoopener];

    // 1. Dynamic URL or direct external literal with _blank and discarded handle flags
    assert_eq!(
        analyze_source(
            Path::new("src/open.tsx"),
            r#"export const OpenBtn = ({ url }: { url: string }) => (
                <button onClick={() => window.open(url, "_blank")}>Open</button>
            );"#,
            Some(rules),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/open.tsx"),
            r#"window.open("https://example.com/external", "_blank");"#,
            Some(rules),
        )
        .len(),
        1
    );

    // 2. Navigating targets (_self, _top, _parent), noopener/noreferrer features, captured handles, mailto:, same-origin relative URLs, and const trusted URLs do NOT flag
    let safe_cases = [
        r#"window.open(url, "_self");"#,
        r#"window.open(url, "_top");"#,
        r#"window.open(url, "_parent");"#,
        r#"window.open(url, "_blank", "noopener");"#,
        r#"window.open(url, "_blank", "noopener,noreferrer");"#,
        r#"const features = "width=400,noopener"; window.open(url, "_blank", features);"#,
        r#"const win = window.open(url, "_blank"); win?.focus();"#,
        r#"function openPopup(url: string) { return window.open(url, "_blank"); }"#,
        r#"window.open("mailto:support@example.com", "_blank");"#,
        r#"window.open("/reports/print", "_blank");"#,
        r#"window.open(`https://github.com/${owner}/${repo}`, "_blank");"#,
        r#"const docsUrl = "https://docs.example.com/guide"; window.open(docsUrl, "_blank");"#,
        r#"const releaseUrl = v ? `https://github.com/org/repo/releases/tag/v${v}` : null; window.open(releaseUrl, "_blank");"#,
    ];
    for case in safe_cases {
        let diags = analyze_source(Path::new("src/safe.tsx"), case, Some(rules));
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for safe window.open case: {case}\ngot: {diags:?}"
        );
    }

    // 3. Reassigned let binding or ternary with untrusted branch flags
    assert_eq!(
        analyze_source(
            Path::new("src/let.tsx"),
            r#"let url = "/safe/route"; url = userInput; window.open(url, "_blank");"#,
            Some(rules),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/ternary.tsx"),
            r#"const url = useMirror ? mirrorUrl : "https://example.com/download"; window.open(url, "_blank");"#,
            Some(rules),
        )
        .len(),
        1
    );

    // 4. Cross-file imported destination verified via ProjectGraph
    let cross_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/routes.ts"),
                r#"export const INTERNAL_PRINT_URL = "/reports/print";
                export const EXTERNAL_PARTNER_URL = "https://partner.evil.example/landing";"#
                    .to_string(),
            ),
            (
                PathBuf::from("src/View.tsx"),
                r#"import { INTERNAL_PRINT_URL, EXTERNAL_PARTNER_URL } from "./routes";
                export function openInternal() { window.open(INTERNAL_PRINT_URL, "_blank"); }
                export function openExternal() { window.open(EXTERNAL_PARTNER_URL, "_blank"); }"#
                    .to_string(),
            ),
        ],
        Some(rules),
    );
    assert_eq!(cross_report.diagnostics.len(), 1);
    assert_eq!(cross_report.diagnostics[0].loc.line, 3);
}

#[test]
fn security_and_security_scan_detectors_flag_vulnerable_patterns_and_respect_exemptions() {
    // 1. unsafe-json-in-html
    assert_eq!(
        analyze_source(
            Path::new("src/Page.tsx"),
            r#"export const Page = ({ data }: any) => (
                <script dangerouslySetInnerHTML={{ __html: `window.__DATA__ = ${JSON.stringify(data)}` }} />
            );"#,
            Some(&[RuleId::UnsafeJsonInHtml]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Page.tsx"),
            r#"export const Page = ({ data }: any) => (
                <script dangerouslySetInnerHTML={{ __html: `window.__DATA__ = ${JSON.stringify(data).replace(/</g, "\\u003c")}` }} />
            );"#,
            Some(&[RuleId::UnsafeJsonInHtml]),
        )
        .is_empty()
    );

    // 2. no-secrets-in-client-code
    assert_eq!(
        analyze_source(
            Path::new("src/client/pay.ts"),
            r#"const stripeKey = "sk_live_51Nz9aBcDeFgHiJkLmNoPqRsTuVwXyZ1234";
            export { stripeKey };"#,
            Some(&[RuleId::NoSecretsInClientCode]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/client/pay.ts"),
            r#"const stripePub = "pk_live_51Nz9aBcDeFgHiJkLmNoPqRsTuVwXyZ1234";
            export { stripePub };"#,
            Some(&[RuleId::NoSecretsInClientCode]),
        )
        .is_empty()
    );

    // 3. public-env-secret-name
    assert_eq!(
        analyze_source(
            Path::new("src/components/Billing.tsx"),
            r#"export const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;"#,
            Some(&[RuleId::PublicEnvSecretName]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/components/Billing.tsx"),
            r#"export const key = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;"#,
            Some(&[RuleId::PublicEnvSecretName]),
        )
        .is_empty()
    );

    // 4. auth-token-in-web-storage
    assert_eq!(
        analyze_source(
            Path::new("src/auth.ts"),
            r#"const KEY = "access_token";
            export function saveToken(t: string) { localStorage.setItem(KEY, t); }"#,
            Some(&[RuleId::AuthTokenInWebStorage]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/auth.ts"),
            r#"export function saveTheme(t: string) { localStorage.setItem("designTokens", t); }"#,
            Some(&[RuleId::AuthTokenInWebStorage]),
        )
        .is_empty()
    );

    // 5. no-eval
    assert_eq!(
        analyze_source(
            Path::new("src/calc.ts"),
            r#"export const run = (code: string) => eval(code);"#,
            Some(&[RuleId::NoEval]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/lib/plugin-sandbox/runtime.ts"),
            r#"export const run = (code: string) => eval(code);"#,
            Some(&[RuleId::NoEval]),
        )
        .is_empty()
    );

    // 6. no-path-prefix-containment
    assert_eq!(
        analyze_source(
            Path::new("src/server/files.ts"),
            r#"import path from "node:path";
            export function isInside(root: string, candidate: string) {
                const resolvedRoot = path.resolve(root);
                const resolvedCandidate = path.resolve(candidate);
                return resolvedCandidate.startsWith(resolvedRoot);
            }"#,
            Some(&[RuleId::NoPathPrefixContainment]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/server/files.ts"),
            r#"import path from "node:path";
            export function isInside(root: string, candidate: string) {
                const resolvedRoot = path.resolve(root);
                const resolvedCandidate = path.resolve(candidate);
                return resolvedCandidate.startsWith(resolvedRoot + path.sep);
            }"#,
            Some(&[RuleId::NoPathPrefixContainment]),
        )
        .is_empty()
    );

    // 7. raw-sql-injection-risk, nosql-injection-risk, command-execution-input-risk, path-traversal-risk
    assert_eq!(
        analyze_source(
            Path::new("src/server/db.ts"),
            r#"export const findUser = (prisma: any, id: string) => prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);"#,
            Some(&[RuleId::RawSqlInjectionRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/mongo.ts"),
            r#"export const search = (db: any, req: any) => db.collection("users").find(JSON.parse(req.body.filter));"#,
            Some(&[RuleId::NosqlInjectionRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/cmd.ts"),
            r#"import { exec } from "node:child_process";
            export const run = (req: any) => exec(`convert ${req.query.file} out.png`);"#,
            Some(&[RuleId::CommandExecutionInputRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/read.ts"),
            r#"import fs from "node:fs";
            export const load = (req: any) => fs.readFileSync(req.query.path, "utf8");"#,
            Some(&[RuleId::PathTraversalRisk]),
        )
        .len(),
        1
    );

    // 8. jwt-insecure-verification, insecure-crypto-risk, insecure-session-cookie, webhook-signature-risk, postmessage-origin-risk, cors-cookie-trust-risk, request-body-mass-assignment
    assert_eq!(
        analyze_source(
            Path::new("src/server/jwt.ts"),
            r#"import jwt from "jsonwebtoken";
            export const check = (t: string, k: string) => jwt.verify(t, k, { algorithms: ["none"] });"#,
            Some(&[RuleId::JwtInsecureVerification]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/hash.ts"),
            r#"import crypto from "node:crypto";
            export const hashPassword = (password: string) => crypto.createHash("md5").update(password).digest("hex");"#,
            Some(&[RuleId::InsecureCryptoRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/cookie.ts"),
            r#"export const login = (res: any, token: string) => res.cookie("session_id", token, { httpOnly: false });"#,
            Some(&[RuleId::InsecureSessionCookie]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/app/api/webhook/route.ts"),
            r#"export async function POST(request: Request) {
                const payload = await request.json();
                return Response.json({ ok: true, id: payload.id });
            }"#,
            Some(&[RuleId::WebhookSignatureRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/components/Embed.tsx"),
            r#"export function register() {
                window.addEventListener("message", (event) => {
                    eval(event.data.cmd);
                });
            }"#,
            Some(&[RuleId::PostmessageOriginRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/cors.ts"),
            r#"export const headers = {
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Origin": "*",
            };"#,
            Some(&[RuleId::CorsCookieTrustRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/users.ts"),
            r#"export const updateUser = (db: any, req: any) => db.user.update({ data: { ...req.body } });"#,
            Some(&[RuleId::RequestBodyMassAssignment]),
        )
        .len(),
        1
    );

    // 9. Supabase & Firebase & MCP & Agent & Secret-in-fallback
    assert_eq!(
        analyze_source(
            Path::new("supabase/migrations/20260101_init.sql"),
            r#"create table public.accounts (id uuid primary key, balance int);"#,
            Some(&[RuleId::SupabaseTableMissingRls]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("supabase/migrations/20260101_init.sql"),
            r#"create table public.accounts (id uuid primary key, balance int);
            alter table public.accounts enable row level security;"#,
            Some(&[RuleId::SupabaseTableMissingRls]),
        )
        .is_empty()
    );
    assert_eq!(
        analyze_source(
            Path::new("supabase/migrations/20260102_policy.sql"),
            r#"create policy "allow_all_writes" on public.accounts for update using (true);"#,
            Some(&[RuleId::SupabaseRlsPolicyRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/components/UpdateOrg.tsx"),
            r#"export const elevate = (supabase: any, uid: string) =>
                supabase.from("memberships").update({ role: "admin", ownerId: uid });"#,
            Some(&[RuleId::SupabaseClientOwnedAuthzField]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("firestore.rules"),
            r#"service cloud.firestore { match /databases/{db}/documents { match /{document=**} { allow read, write: if true; } } }"#,
            Some(&[RuleId::FirebasePermissiveRules]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/components/FirebaseRole.tsx"),
            r#"import { updateDoc } from "firebase/firestore";
            export const makeAdmin = (ref: any) => updateDoc(ref, { isAdmin: true, role: "owner" });"#,
            Some(&[RuleId::FirebaseClientOwnedAuthzField]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/components/DocsList.tsx"),
            r#"export const queryDocs = (q: any, tenantId: string) => q.where("tenantId", "==", tenantId);"#,
            Some(&[RuleId::FirebaseQueryFilterAsAuth]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/mcp/server.ts"),
            r#"import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
            import { execSync } from "node:child_process";
            const server = new McpServer({ name: "demo", version: "1.0.0" });
            server.tool("run", {}, async ({ cmd }: any) => ({ content: [{ type: "text", text: String(execSync(cmd)) }] }));"#,
            Some(&[RuleId::McpToolCapabilityRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/agents/tools.ts"),
            r#"import { execSync } from "node:child_process";
            export const shellTool = createTool({
                name: "shell",
                execute: async ({ cmd }: any) => execSync(cmd),
            });"#,
            Some(&[RuleId::AgentToolCapabilityRisk]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/server/auth.ts"),
            r#"export const JWT_SECRET = process.env.JWT_SECRET_KEY ?? "super-secret-fallback-production-key";"#,
            Some(&[RuleId::SecretInFallback]),
        )
        .len(),
        1
    );
}

#[test]
fn server_auth_actions_and_sequential_awaits_with_cross_file_cache_awareness() {
    // 1. server-auth-actions: flags unauthenticated mutation or secret leak, skips login/signup/resetPassword/public/authenticated
    let auth_rules = &[RuleId::ServerAuthActions];
    assert_eq!(
        analyze_source(
            Path::new("app/actions/user.ts"),
            r#""use server";
            export async function deleteAccountAction(userId: string) {
                await db.users.delete({ where: { id: userId } });
            }"#,
            Some(auth_rules),
        )
        .len(),
        1
    );

    let safe_actions = [
        r#""use server";
        export async function deleteAccountAction(userId: string) {
            const session = await getSession();
            if (!session) throw new Error("Unauthorized");
            await db.users.delete({ where: { id: userId } });
        }"#,
        r#""use server";
        export async function login(formData: FormData) {
            const user = await db.users.findFirst();
            await setSession(user.id);
        }"#,
        r#""use server";
        export async function signup(data: any) {
            const res = await db.insert(userTable).values(data);
            await setSession(res[0].id);
        }"#,
        r#""use server";
        export async function resetPassword(token: string, nextPassword: string) {
            await db.update(userTable).set({ passwordHash: nextPassword });
        }"#,
        r#""use server";
        export async function getPostPublicAction(id: string) {
            return db.posts.findUnique({ where: { id } });
        }"#,
    ];
    for action_src in safe_actions {
        let diags = analyze_source(
            Path::new("app/actions/auth.ts"),
            action_src,
            Some(auth_rules),
        );
        assert!(
            diags.is_empty(),
            "Expected 0 server-auth-actions diagnostics for:\n{action_src}\ngot: {diags:?}"
        );
    }

    // Custom `serverAuthFunctionNames` in DotoreConfig
    let mut custom_cfg = DotoreConfig::default();
    custom_cfg
        .server_auth_function_names
        .push("enforceTenantGate".to_string());
    assert!(
        analyze_source_with_config(
            Path::new("app/actions/custom.ts"),
            r#""use server";
            export async function archiveWorkspace(id: string) {
                await enforceTenantGate();
                await db.workspaces.delete({ where: { id } });
            }"#,
            &custom_cfg,
            &CapabilityGate::default_react(),
            Some(auth_rules),
        )
        .is_empty()
    );

    // 2. server-sequential-independent-await: flags independent awaits, skips dependent, skips cross-file React.cache / guarded WeakMap cache
    let seq_rules = &[RuleId::ServerSequentialIndependentAwait];
    assert_eq!(
        analyze_source(
            Path::new("app/page.tsx"),
            r#"export default async function Page() {
                const user = await fetchUser();
                const posts = await fetchPosts();
                return <div>{user.name}{posts.length}</div>;
            }"#,
            Some(seq_rules),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("app/page.tsx"),
            r#"export default async function Page() {
                const user = await fetchUser();
                const posts = await fetchPosts(user.id);
                return <div>{user.name}{posts.length}</div>;
            }"#,
            Some(seq_rules),
        )
        .is_empty()
    );

    // Cross-file cached async work (`React.cache` and guarded `WeakMap` cache reader)
    let cached_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/source.ts"),
                r#"import { cache } from "react";
                const weakCache = new WeakMap();
                export const read = (key: object) => {
                    const cached = weakCache.get(key);
                    if (cached) return cached;
                    const promise = fetchValue(key);
                    weakCache.set(key, promise);
                    return promise;
                };
                export const format = async (key: object) => {
                    const value = await read(key);
                    return String(value);
                };
                export const getUser = cache(async (id: string) => fetchUser(id));
                export const getUserDisplayName = async (id: string) => {
                    const u = await getUser(id);
                    return u.name;
                };"#
                .to_string(),
            ),
            (
                PathBuf::from("src/consumer.ts"),
                r#"import { read, format, getUser, getUserDisplayName } from "./source";
                export const loadWeakCached = async (key: object) => {
                    const value = await read(key);
                    const text = await format(key);
                    return [value, text];
                };
                export const loadReactCached = async (id: string) => {
                    const user = await getUser(id);
                    const name = await getUserDisplayName(id);
                    return [user, name];
                };
                export const loadDifferentKeys = async (id1: string, id2: string) => {
                    const user = await getUser(id1);
                    const name = await getUserDisplayName(id2);
                    return [user, name];
                };"#
                .to_string(),
            ),
        ],
        Some(seq_rules),
    );
    assert_eq!(
        cached_report.diagnostics.len(),
        1,
        "Only loadDifferentKeys should be flagged for sequential independent await, got: {:?}",
        cached_report.diagnostics
    );
}

#[test]
fn nextjs_async_dynamic_api_img_wrapper_and_suspense_rules_work_across_files() {
    // 1. nextjs-async-dynamic-api-not-awaited
    let dyn_rules = &[RuleId::NextjsAsyncDynamicApiNotAwaited];
    for bad_case in [
        r#"import { cookies } from "next/headers";
        export const read = () => cookies().get("session");"#,
        r#"import { headers as reqHeaders } from "next/headers";
        export const read = () => { const h = reqHeaders(); return h.get("x-id"); };"#,
        r#"import { draftMode } from "next/headers";
        export const read = () => { const { isEnabled } = draftMode(); return isEnabled; };"#,
        r#"import { headers } from "next/headers";
        export const read = () => [...headers()];"#,
        r#"import { cookies } from "next/headers";
        export const read = () => Object.keys(cookies());"#,
        r#"export default async function Page({ params }: { params: Promise<{ slug: string }> }) {
            return <div>{params.slug}</div>;
        }"#,
    ] {
        let diags = analyze_source(Path::new("app/page.tsx"), bad_case, Some(dyn_rules));
        assert_eq!(
            diags.len(),
            1,
            "Expected 1 nextjs-async-dynamic-api-not-awaited diagnostic for:\n{bad_case}\ngot: {diags:?}"
        );
    }

    for good_case in [
        r#"import { cookies } from "next/headers";
        export const read = async () => { const c = await cookies(); return c.get("session"); };"#,
        r#"import { cookies } from "next/headers";
        export const read = () => { const { then } = cookies(); return then; };"#,
        r#"export default async function Page({ params }: { params: Promise<{ slug: string }> }) {
            const { slug } = await params;
            return <div>{slug}</div>;
        }"#,
    ] {
        let diags = analyze_source(Path::new("app/page.tsx"), good_case, Some(dyn_rules));
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for valid async API usage:\n{good_case}\ngot: {diags:?}"
        );
    }

    // 2. nextjs-no-img-element with cross-file ImageResponse / satori wrapper awareness
    let img_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("lib/card.tsx"),
                r#"export const cardLayout = (src: string) => (
                    <div><img src={src} alt="" width={100} height={100} /></div>
                );"#
                .to_string(),
            ),
            (
                PathBuf::from("lib/index.ts"),
                r#"export * from "./card";"#.to_string(),
            ),
            (
                PathBuf::from("app/api/og/route.tsx"),
                r#"import { ImageResponse } from "next/og";
                import { cardLayout } from "../../../lib";
                export const GET = () => new ImageResponse(cardLayout("/photo.png"));"#
                    .to_string(),
            ),
            (
                PathBuf::from("app/page.tsx"),
                r#"export default function Page() {
                    return <img src="/hero.png" alt="Hero" />;
                }"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::NextjsNoImgElement]),
    );
    assert_eq!(
        img_report.diagnostics.len(),
        1,
        "Only app/page.tsx should be flagged, not lib/card.tsx consumed by ImageResponse"
    );
    assert!(img_report.diagnostics[0].file.ends_with("app/page.tsx"));

    // 3. nextjs-no-use-search-params-without-suspense across files and layouts
    let suspense_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("components/SearchBar.tsx"),
                r#""use client";
                import { useSearchParams } from "next/navigation";
                export function SearchBar() {
                    const params = useSearchParams();
                    return <div>{params.get("q")}</div>;
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("app/unwrapped/page.tsx"),
                r#"import { SearchBar } from "../../components/SearchBar";
                export default function UnwrappedPage() {
                    return <main><SearchBar /></main>;
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("app/wrapped/page.tsx"),
                r#"import { Suspense } from "react";
                import { SearchBar } from "../../components/SearchBar";
                export default function WrappedPage() {
                    return <Suspense fallback={null}><SearchBar /></Suspense>;
                }"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::NextjsNoUseSearchParamsWithoutSuspense]),
    );
    assert_eq!(suspense_report.diagnostics.len(), 1);
    assert!(
        suspense_report.diagnostics[0]
            .file
            .ends_with("app/unwrapped/page.tsx")
    );
}

#[test]
fn remaining_server_and_nextjs_rules_detect_violations() {
    // server-no-mutable-module-state
    assert_eq!(
        analyze_source(
            Path::new("app/actions.ts"),
            r#""use server";
            let currentUserId: string | null = null;
            export async function setCurrentUser(id: string) { currentUserId = id; }"#,
            Some(&[RuleId::ServerNoMutableModuleState]),
        )
        .len(),
        1
    );

    // server-hoist-static-io
    assert_eq!(
        analyze_source(
            Path::new("app/api/font/route.ts"),
            r#"import fs from "node:fs";
            export async function GET() {
                const font = fs.readFileSync("./public/Inter.ttf");
                return new Response(font);
            }"#,
            Some(&[RuleId::ServerHoistStaticIo]),
        )
        .len(),
        1
    );

    // server-fetch-without-revalidate
    assert_eq!(
        analyze_source(
            Path::new("app/posts/page.tsx"),
            r#"export default async function PostsPage() {
                const res = await fetch("https://api.example.com/posts");
                return <div>{res.status}</div>;
            }"#,
            Some(&[RuleId::ServerFetchWithoutRevalidate]),
        )
        .len(),
        1
    );

    // server-after-nonblocking
    assert_eq!(
        analyze_source(
            Path::new("app/actions/track.ts"),
            r#""use server";
            export async function submitOrder(data: any) {
                analytics.track("order_submitted", data);
                return { ok: true };
            }"#,
            Some(&[RuleId::ServerAfterNonblocking]),
        )
        .len(),
        1
    );

    // server-dedup-props & server-cache-with-object-literal
    assert_eq!(
        analyze_source(
            Path::new("app/list/page.tsx"),
            r#"export default async function ListPage({ items }: { items: any[] }) {
                return <ClientList items={items} activeItems={items.filter(Boolean)} />;
            }"#,
            Some(&[RuleId::ServerDedupProps]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("app/data.ts"),
            r#"import { cache } from "react";
            const getUser = cache(async (opts: { id: string }) => opts.id);
            export const load = () => getUser({ id: "123" });"#,
            Some(&[RuleId::ServerCacheWithObjectLiteral]),
        )
        .len(),
        1
    );

    // nextjs-no-side-effect-in-get-handler, nextjs-no-script-in-head, nextjs-no-head-import, nextjs-no-vercel-og-import, nextjs-async-client-component
    assert_eq!(
        analyze_source(
            Path::new("app/api/logout/route.ts"),
            r#"import { cookies } from "next/headers";
            export async function GET() {
                (await cookies()).delete("session");
                return Response.json({ ok: true });
            }"#,
            Some(&[RuleId::NextjsNoSideEffectInGetHandler]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("pages/index.tsx"),
            r#"import Head from "next/head";
            import Script from "next/script";
            export default function Home() {
                return <Head><Script src="/analytics.js" /></Head>;
            }"#,
            Some(&[RuleId::NextjsNoScriptInHead]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("app/layout.tsx"),
            r#"import Head from "next/head";
            export default function Layout({ children }: any) { return <html><body><Head />{children}</body></html>; }"#,
            Some(&[RuleId::NextjsNoHeadImport]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("app/api/og/route.tsx"),
            r#"import { ImageResponse } from "@vercel/og";
            export const GET = () => new ImageResponse(<div />);"#,
            Some(&[RuleId::NextjsNoVercelOgImport]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("app/ClientComp.tsx"),
            r#""use client";
            export async function ClientComp() { return <div />; }"#,
            Some(&[RuleId::NextjsAsyncClientComponent]),
        )
        .len(),
        1
    );
}

#[test]
fn project_level_pnpm_hardening_rsc_advisory_and_supply_chain_cache_work() {
    // 1. require-pnpm-hardening
    let unhardened_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{"name": "app", "packageManager": "pnpm@10.0.0"}"#.to_string(),
            ),
            (
                PathBuf::from("pnpm-workspace.yaml"),
                "packages:\n  - 'packages/*'\nblockExoticSubdeps: false\ntrustPolicy: any\n"
                    .to_string(),
            ),
        ],
        Some(&[RuleId::RequirePnpmHardening]),
    );
    assert_eq!(
        unhardened_report.diagnostics.len(),
        3,
        "Expected 3 require-pnpm-hardening diagnostics (missing minimumReleaseAge, blockExoticSubdeps: false, trustPolicy: any), got: {:?}",
        unhardened_report.diagnostics
    );

    let hardened_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{"name": "app", "packageManager": "pnpm@10.0.0"}"#.to_string(),
            ),
            (
                PathBuf::from("pnpm-workspace.yaml"),
                "packages:\n  - 'packages/*'\nminimumReleaseAge: 10080\nblockExoticSubdeps: true\ntrustPolicy: no-downgrade\n"
                    .to_string(),
            ),
        ],
        Some(&[RuleId::RequirePnpmHardening]),
    );
    assert!(hardened_report.diagnostics.is_empty());

    // 2. no-vulnerable-react-server-components
    let rsc_rce_report = analyze_project_sources(
        vec![(
            PathBuf::from("package.json"),
            r#"{"name": "rsc-app", "dependencies": {"react": "19.2.0", "react-server-dom-webpack": "19.2.0"}}"#
                .to_string(),
        )],
        Some(&[RuleId::NoVulnerableReactServerComponents]),
    );
    assert_eq!(rsc_rce_report.diagnostics.len(), 1);
    assert_eq!(rsc_rce_report.diagnostics[0].severity, RuleSeverity::Error);
    assert!(
        rsc_rce_report.diagnostics[0]
            .message
            .contains("CVE-2025-55182")
    );

    let next_dos_report = analyze_project_sources(
        vec![(
            PathBuf::from("package.json"),
            r#"{"name": "next-app", "dependencies": {"next": "15.5.7", "react": "19.2.0"}}"#
                .to_string(),
        )],
        Some(&[RuleId::NoVulnerableReactServerComponents]),
    );
    assert_eq!(next_dos_report.diagnostics.len(), 1);
    assert_eq!(
        next_dos_report.diagnostics[0].severity,
        RuleSeverity::Warning
    );
    assert!(
        next_dos_report.diagnostics[0]
            .message
            .contains("CVE-2026-23870")
    );

    let next_safe_report = analyze_project_sources(
        vec![(
            PathBuf::from("package.json"),
            r#"{"name": "next-app", "dependencies": {"next": "15.5.18", "react": "19.2.6"}}"#
                .to_string(),
        )],
        Some(&[RuleId::NoVulnerableReactServerComponents]),
    );
    assert!(next_safe_report.diagnostics.is_empty());

    // 3. low-supply-chain-score with local disk cache & fail-open behavior
    let temp_dir = unique_temp_dir("supply-chain");
    let cache_dir = temp_dir.join(".cache");
    let sc_cache_subdir = cache_dir.join("supply-chain");
    fs::create_dir_all(&sc_cache_subdir).expect("create supply-chain cache dir");

    // Pre-populate cache entry for `pkg:npm/event-stream@3.3.6`
    let purl = "pkg:npm/event-stream@3.3.6";
    let hash = dotore::supply_chain_purl_hash(purl);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    let artifact_line = r#"{"id":"test","type":"npm","score":{"supplyChain":1.0,"vulnerability":0.25,"maintenance":1.0,"quality":1.0,"license":1.0,"overall":0.25},"alerts":[]}"#;
    let cache_json = serde_json::json!({
        "fetchedAtMs": now_ms,
        "body": artifact_line,
    });
    fs::write(
        sc_cache_subdir.join(format!("{hash}.json")),
        cache_json.to_string(),
    )
    .expect("write cached socket artifact");

    fs::write(
        temp_dir.join("package.json"),
        serde_json::json!({
            "name": "sc-fixture",
            "version": "1.0.0",
            "dependencies": {
                "event-stream": "3.3.6"
            },
            "dotore": {
                "supplyChain": {
                    "cacheDir": cache_dir.to_string_lossy(),
                    "apiBaseUrl": "http://127.0.0.1:9"
                }
            }
        })
        .to_string(),
    )
    .expect("write package.json");
    fs::write(
        temp_dir.join("index.tsx"),
        "export const App = () => <div />;\n",
    )
    .expect("write index.tsx");

    let (report, _) = scan_workspace(&ScanOptions {
        paths: vec![temp_dir.clone()],
        rules: Some(vec![RuleId::LowSupplyChainScore]),
        ..ScanOptions::default()
    })
    .expect("scan workspace with supply chain cache");

    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].rule, RuleId::LowSupplyChainScore);
    assert!(
        report.diagnostics[0]
            .message
            .contains("scored 25/100 on Socket's vulnerability axis")
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
