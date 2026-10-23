//! Integration tests for Ticket #4 (03):
//! React Router v7/v8 Rule Family (34 Rules + v8 Autofix).

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleId, analyze_project_sources,
    analyze_source, analyze_source_with_config, apply_patches_to_source, rule_registry,
};

fn run_rule(path: &str, source: &str, rule: RuleId) -> Vec<dotore::Diagnostic> {
    analyze_source(Path::new(path), source, Some(&[rule]))
}

#[test]
fn react_router_catalog_and_capability_gate_activation() {
    let registry = rule_registry();
    let expected_ids = [
        // 1. Route tree configuration rules (9)
        "react-router-descendant-routes-require-splat",
        "react-router-nested-route-requires-outlet",
        "react-router-no-duplicate-route-id",
        "react-router-no-empty-leaf-route",
        "react-router-no-invalid-absolute-child-path",
        "react-router-no-invalid-lazy-route-properties",
        "react-router-no-invalid-splat-path",
        "react-router-require-root-error-boundary",
        "react-router-valid-route-object",
        // 2. Loader, action, and middleware safety rules (12)
        "react-router-guard-aborted-handle-error",
        "react-router-no-catch-middleware-next",
        "react-router-no-client-module-in-server-render",
        "react-router-no-loader-request-body",
        "react-router-no-middleware-response-body-consumption",
        "react-router-no-multiple-middleware-next",
        "react-router-no-redirect-in-try-catch",
        "react-router-no-route-module-environment-suffix",
        "react-router-no-session-mutation-in-loader",
        "react-router-no-static-cookie-expires",
        "react-router-server-middleware-return-response",
        "react-router-session-mutation-requires-commit",
        // 3. Client navigation and v8 migration rules (13)
        "react-router-internal-route-anchor",
        "react-router-no-multiple-blockers",
        "react-router-no-multiple-set-search-params-in-tick",
        "react-router-no-navigate-in-render",
        "react-router-no-nested-router",
        "react-router-no-router-in-render",
        "react-router-no-unsynchronized-search-params-mutation",
        "react-router-no-use-loader-data-in-error-ui",
        "react-router-resource-link-requires-reload",
        "react-router-return-navigation-promise-in-transition",
        "react-router-v8-no-meta-data-field",
        "react-router-v8-no-react-router-dom-import",
        "react-router-v8-no-removed-future-flags",
    ];
    assert_eq!(expected_ids.len(), 34);

    for id_str in expected_ids {
        let parsed = RuleId::parse(id_str)
            .unwrap_or_else(|| panic!("Expected RuleId::parse({id_str:?}) to succeed"));
        assert_eq!(parsed.as_str(), id_str);
        assert!(
            registry.iter().any(|m| m.id == parsed),
            "Rule {id_str} missing from rule_registry()"
        );
    }

    let sample = r#"
        import { useNavigate } from "react-router-dom";
        export function Page() {
            const navigate = useNavigate();
            navigate("/login");
            return <div>Page</div>;
        }
    "#;
    let cfg = DotoreConfig::default();

    // Plain React gate does not activate React Router rules
    let plain_react_gate = CapabilityGate::default_react();
    let plain_diags = analyze_source_with_config(
        Path::new("src/Page.tsx"),
        sample,
        &cfg,
        &plain_react_gate,
        None,
    );
    assert!(
        !plain_diags.iter().any(|d| matches!(
            d.rule,
            RuleId::ReactRouterV8NoReactRouterDomImport | RuleId::ReactRouterNoNavigateInRender
        )),
        "Plain React gate should not activate React Router rules: {plain_diags:#?}"
    );

    // Gate with Capability::ReactRouter activates React Router rules
    let rr_gate = CapabilityGate::with_capabilities([Capability::React, Capability::ReactRouter]);
    let rr_diags =
        analyze_source_with_config(Path::new("src/Page.tsx"), sample, &cfg, &rr_gate, None);
    assert!(
        rr_diags
            .iter()
            .any(|d| d.rule == RuleId::ReactRouterV8NoReactRouterDomImport)
    );
    assert!(
        rr_diags
            .iter()
            .any(|d| d.rule == RuleId::ReactRouterNoNavigateInRender)
    );

    // Project capability gate inferred from package.json with react-router
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "dependencies": { "react": "^19.0.0", "react-router": "^7.2.0" } }"#
                    .to_string(),
            ),
            (PathBuf::from("src/Page.tsx"), sample.to_string()),
        ],
        None,
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ReactRouterV8NoReactRouterDomImport)
    );
}

#[test]
fn route_tree_configuration_rules_suite() {
    // 1. react-router-descendant-routes-require-splat
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            function DashboardRoutes() {
                return (
                    <Routes>
                        <Route path="settings" element={<div />} />
                    </Routes>
                );
            }
            export function App() {
                return (
                    <Routes>
                        <Route path="/dashboard" element={<DashboardRoutes />} />
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterDescendantRoutesRequireSplat,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            function DashboardRoutes() {
                return (
                    <Routes>
                        <Route path="settings" element={<div />} />
                    </Routes>
                );
            }
            export function App() {
                return (
                    <Routes>
                        <Route path="/dashboard/*" element={<DashboardRoutes />} />
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterDescendantRoutesRequireSplat,
        )
        .is_empty()
    );

    // 2. react-router-nested-route-requires-outlet
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            function DashboardLayout() {
                return <div className="layout">Header only</div>;
            }
            function SettingsPage() {
                return <div>Settings</div>;
            }
            export const router = createBrowserRouter([
                {
                    path: "/dashboard",
                    Component: DashboardLayout,
                    children: [
                        { path: "settings", Component: SettingsPage },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterNestedRouteRequiresOutlet,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter, Outlet } from "react-router";
            function DashboardLayout() {
                return (
                    <div className="layout">
                        <Outlet />
                    </div>
                );
            }
            function SettingsPage() {
                return <div>Settings</div>;
            }
            export const router = createBrowserRouter([
                {
                    path: "/dashboard",
                    Component: DashboardLayout,
                    children: [
                        { path: "settings", Component: SettingsPage },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterNestedRouteRequiresOutlet,
        )
        .is_empty()
    );

    // 3. react-router-no-duplicate-route-id
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { id: "users-route", path: "/users", Component: Users },
                { id: "users-route", path: "/team", Component: Team },
            ]);
            "#,
            RuleId::ReactRouterNoDuplicateRouteId,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { id: "users-route", path: "/users", Component: Users },
                { id: "team-route", path: "/team", Component: Team },
            ]);
            "#,
            RuleId::ReactRouterNoDuplicateRouteId,
        )
        .is_empty()
    );

    // 4. react-router-no-empty-leaf-route
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { path: "/empty-page" },
            ]);
            "#,
            RuleId::ReactRouterNoEmptyLeafRoute,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { path: "/page", Component: Page },
                { path: "/api/webhook", loader: handleWebhook },
            ]);
            "#,
            RuleId::ReactRouterNoEmptyLeafRoute,
        )
        .is_empty()
    );

    // 5. react-router-no-invalid-absolute-child-path
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/dashboard",
                    Component: Layout,
                    children: [
                        { path: "/settings", Component: Settings },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidAbsoluteChildPath,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/dashboard",
                    Component: Layout,
                    children: [
                        { path: "settings", Component: Settings },
                        { path: "/dashboard/billing", Component: Billing },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidAbsoluteChildPath,
        )
        .is_empty()
    );

    // 6. react-router-no-invalid-lazy-route-properties
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/reports",
                    lazy: async () => ({
                        path: "/reports-override",
                        Component: ReportsPage,
                    }),
                },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidLazyRouteProperties,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/reports",
                    lazy: async () => ({
                        loader: reportsLoader,
                        Component: ReportsPage,
                    }),
                },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidLazyRouteProperties,
        )
        .is_empty()
    );

    // 7. react-router-no-invalid-splat-path
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { path: "/files/*/details", Component: FileDetails },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidSplatPath,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                { path: "/files/*", Component: FilesCatchAll },
                { path: "*", Component: NotFound },
            ]);
            "#,
            RuleId::ReactRouterNoInvalidSplatPath,
        )
        .is_empty()
    );

    // 8. react-router-require-root-error-boundary
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/",
                    Component: RootLayout,
                    children: [
                        { index: true, Component: Home },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterRequireRootErrorBoundary,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    path: "/",
                    Component: RootLayout,
                    ErrorBoundary: RootErrorBoundary,
                    children: [
                        { index: true, Component: Home },
                    ],
                },
            ]);
            "#,
            RuleId::ReactRouterRequireRootErrorBoundary,
        )
        .is_empty()
    );

    // 9. react-router-valid-route-object
    assert_eq!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    index: true,
                    children: [{ path: "sub", Component: Sub }],
                    Component: Home,
                },
            ]);
            "#,
            RuleId::ReactRouterValidRouteObject,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/router.tsx",
            r#"
            import { createBrowserRouter } from "react-router";
            export const router = createBrowserRouter([
                {
                    index: true,
                    Component: Home,
                },
            ]);
            "#,
            RuleId::ReactRouterValidRouteObject,
        )
        .is_empty()
    );
}

#[test]
fn loader_action_and_middleware_safety_rules_suite() {
    // 1. react-router-guard-aborted-handle-error
    assert_eq!(
        run_rule(
            "src/entry.server.tsx",
            r#"
            export function handleError(error: unknown, { request }: { request: Request }) {
                reportError(error);
            }
            "#,
            RuleId::ReactRouterGuardAbortedHandleError,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/entry.server.tsx",
            r#"
            export function handleError(error: unknown, { request }: { request: Request }) {
                if (!request.signal.aborted) {
                    reportError(error);
                }
            }
            "#,
            RuleId::ReactRouterGuardAbortedHandleError,
        )
        .is_empty()
    );

    // 2. react-router-no-catch-middleware-next
    assert_eq!(
        run_rule(
            "src/routes/dashboard.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                try {
                    return await next();
                } catch (err) {
                    console.error(err);
                    throw err;
                }
            }
            "#,
            RuleId::ReactRouterNoCatchMiddlewareNext,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/dashboard.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const response = await next();
                return response;
            }
            "#,
            RuleId::ReactRouterNoCatchMiddlewareNext,
        )
        .is_empty()
    );

    // 3. react-router-no-client-module-in-server-render
    assert_eq!(
        run_rule(
            "src/routes/chart.tsx",
            r#"
            import { ClientChart } from "./chart.client";
            export default function ChartRoute() {
                return <div><ClientChart /></div>;
            }
            "#,
            RuleId::ReactRouterNoClientModuleInServerRender,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/chart.tsx",
            r#"
            import { ClientChart } from "./chart.client";
            import { ClientOnly } from "remix-utils/client-only";
            export default function ChartRoute() {
                return <ClientOnly fallback={<div />}>{() => <ClientChart />}</ClientOnly>;
            }
            "#,
            RuleId::ReactRouterNoClientModuleInServerRender,
        )
        .is_empty()
    );

    // 4. react-router-no-loader-request-body
    assert_eq!(
        run_rule(
            "src/routes/search.tsx",
            r#"
            export async function loader({ request }: { request: Request }) {
                const body = await request.json();
                return { results: body };
            }
            "#,
            RuleId::ReactRouterNoLoaderRequestBody,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/search.tsx",
            r#"
            export async function loader({ request }: { request: Request }) {
                const url = new URL(request.url);
                return { q: url.searchParams.get("q") };
            }
            export async function action({ request }: { request: Request }) {
                const body = await request.json();
                return { ok: Boolean(body) };
            }
            "#,
            RuleId::ReactRouterNoLoaderRequestBody,
        )
        .is_empty()
    );

    // 5. react-router-no-middleware-response-body-consumption
    assert_eq!(
        run_rule(
            "src/routes/audit.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const res = await next();
                const data = await res.json();
                console.log(data);
                return res;
            }
            "#,
            RuleId::ReactRouterNoMiddlewareResponseBodyConsumption,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/audit.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const res = await next();
                res.headers.set("X-Timing", "12ms");
                return res;
            }
            "#,
            RuleId::ReactRouterNoMiddlewareResponseBodyConsumption,
        )
        .is_empty()
    );

    // 6. react-router-no-multiple-middleware-next
    assert_eq!(
        run_rule(
            "src/routes/retry.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const first = await next();
                const second = await next();
                return second ?? first;
            }
            "#,
            RuleId::ReactRouterNoMultipleMiddlewareNext,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/retry.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const response = await next();
                return response;
            }
            "#,
            RuleId::ReactRouterNoMultipleMiddlewareNext,
        )
        .is_empty()
    );

    // 7. react-router-no-redirect-in-try-catch
    assert_eq!(
        run_rule(
            "src/routes/checkout.tsx",
            r#"
            import { redirect } from "react-router";
            export async function action() {
                try {
                    await saveOrder();
                    return redirect("/thank-you");
                } catch (err) {
                    return { error: "Failed" };
                }
            }
            "#,
            RuleId::ReactRouterNoRedirectInTryCatch,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/checkout.tsx",
            r#"
            import { redirect } from "react-router";
            export async function action() {
                try {
                    await saveOrder();
                } catch (err) {
                    return { error: "Failed" };
                }
                return redirect("/thank-you");
            }
            "#,
            RuleId::ReactRouterNoRedirectInTryCatch,
        )
        .is_empty()
    );

    // 8. react-router-no-route-module-environment-suffix
    assert_eq!(
        run_rule(
            "app/routes/dashboard.server.tsx",
            r#"
            export async function loader() {
                return { ok: true };
            }
            export default function Dashboard() {
                return <div>Dashboard</div>;
            }
            "#,
            RuleId::ReactRouterNoRouteModuleEnvironmentSuffix,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "app/routes/dashboard.tsx",
            r#"
            export async function loader() {
                return { ok: true };
            }
            export default function Dashboard() {
                return <div>Dashboard</div>;
            }
            "#,
            RuleId::ReactRouterNoRouteModuleEnvironmentSuffix,
        )
        .is_empty()
    );

    // 9. react-router-no-session-mutation-in-loader
    assert_eq!(
        run_rule(
            "src/routes/profile.tsx",
            r#"
            export async function loader({ request }: { request: Request }) {
                const session = await getSession(request.headers.get("Cookie"));
                session.set("lastVisited", "/profile");
                return { user: session.get("user") };
            }
            "#,
            RuleId::ReactRouterNoSessionMutationInLoader,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/profile.tsx",
            r#"
            export async function loader({ request }: { request: Request }) {
                const session = await getSession(request.headers.get("Cookie"));
                return { user: session.get("user") };
            }
            "#,
            RuleId::ReactRouterNoSessionMutationInLoader,
        )
        .is_empty()
    );

    // 10. react-router-no-static-cookie-expires
    assert_eq!(
        run_rule(
            "src/cookies.server.ts",
            r#"
            import { createCookie } from "react-router";
            export const prefsCookie = createCookie("prefs", {
                expires: new Date(Date.now() + 86400_000),
            });
            "#,
            RuleId::ReactRouterNoStaticCookieExpires,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/cookies.server.ts",
            r#"
            import { createCookie } from "react-router";
            export const prefsCookie = createCookie("prefs", {
                maxAge: 86400,
            });
            "#,
            RuleId::ReactRouterNoStaticCookieExpires,
        )
        .is_empty()
    );

    // 11. react-router-server-middleware-return-response
    assert_eq!(
        run_rule(
            "src/routes/logging.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                await next();
            }
            "#,
            RuleId::ReactRouterServerMiddlewareReturnResponse,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/logging.tsx",
            r#"
            export async function middleware({ request }: any, next: () => Promise<Response>) {
                const response = await next();
                return response;
            }
            "#,
            RuleId::ReactRouterServerMiddlewareReturnResponse,
        )
        .is_empty()
    );

    // 12. react-router-session-mutation-requires-commit
    assert_eq!(
        run_rule(
            "src/routes/login.tsx",
            r#"
            import { redirect } from "react-router";
            export async function action({ request }: { request: Request }) {
                const session = await getSession(request.headers.get("Cookie"));
                session.set("userId", "u_123");
                return redirect("/dashboard");
            }
            "#,
            RuleId::ReactRouterSessionMutationRequiresCommit,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/login.tsx",
            r#"
            import { redirect } from "react-router";
            export async function action({ request }: { request: Request }) {
                const session = await getSession(request.headers.get("Cookie"));
                session.set("userId", "u_123");
                return redirect("/dashboard", {
                    headers: { "Set-Cookie": await commitSession(session) },
                });
            }
            "#,
            RuleId::ReactRouterSessionMutationRequiresCommit,
        )
        .is_empty()
    );
}

#[test]
fn client_navigation_and_v8_migration_rules_suite() {
    // 1. react-router-internal-route-anchor
    assert_eq!(
        run_rule(
            "src/Nav.tsx",
            r#"
            import { useLocation } from "react-router";
            export function Nav() {
                const loc = useLocation();
                return <a href="/dashboard/settings">Settings ({loc.pathname})</a>;
            }
            "#,
            RuleId::ReactRouterInternalRouteAnchor,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Nav.tsx",
            r#"
            import { Link } from "react-router";
            export function Nav() {
                return (
                    <div>
                        <Link to="/dashboard/settings">Settings</Link>
                        <a href="https://example.com">External</a>
                        <a href="/files/report.pdf" download>Download</a>
                    </div>
                );
            }
            "#,
            RuleId::ReactRouterInternalRouteAnchor,
        )
        .is_empty()
    );

    // 2. react-router-no-multiple-blockers
    assert_eq!(
        run_rule(
            "src/Editor.tsx",
            r#"
            import { useBlocker } from "react-router";
            export function Editor({ dirtyA, dirtyB }: { dirtyA: boolean; dirtyB: boolean }) {
                const blockerA = useBlocker(dirtyA);
                const blockerB = useBlocker(dirtyB);
                return <div>{String(blockerA.state)} {String(blockerB.state)}</div>;
            }
            "#,
            RuleId::ReactRouterNoMultipleBlockers,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Editor.tsx",
            r#"
            import { useBlocker } from "react-router";
            export function Editor({ dirtyA, dirtyB }: { dirtyA: boolean; dirtyB: boolean }) {
                const blocker = useBlocker(dirtyA || dirtyB);
                return <div>{String(blocker.state)}</div>;
            }
            "#,
            RuleId::ReactRouterNoMultipleBlockers,
        )
        .is_empty()
    );

    // 3. react-router-no-multiple-set-search-params-in-tick
    assert_eq!(
        run_rule(
            "src/Filters.tsx",
            r#"
            import { useSearchParams } from "react-router";
            export function Filters() {
                const [searchParams, setSearchParams] = useSearchParams();
                function applyBoth() {
                    setSearchParams({ page: "1" });
                    setSearchParams({ sort: "asc" });
                }
                return <button onClick={applyBoth}>{searchParams.toString()}</button>;
            }
            "#,
            RuleId::ReactRouterNoMultipleSetSearchParamsInTick,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Filters.tsx",
            r#"
            import { useSearchParams } from "react-router";
            export function Filters() {
                const [searchParams, setSearchParams] = useSearchParams();
                function applyBoth() {
                    setSearchParams({ page: "1", sort: "asc" });
                }
                return <button onClick={applyBoth}>{searchParams.toString()}</button>;
            }
            "#,
            RuleId::ReactRouterNoMultipleSetSearchParamsInTick,
        )
        .is_empty()
    );

    // 4. react-router-no-navigate-in-render
    assert_eq!(
        run_rule(
            "src/Protected.tsx",
            r#"
            import { useNavigate } from "react-router";
            export function Protected({ user }: { user: string | null }) {
                const navigate = useNavigate();
                if (!user) {
                    navigate("/login");
                }
                return <div>Protected</div>;
            }
            "#,
            RuleId::ReactRouterNoNavigateInRender,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Protected.tsx",
            r#"
            import { Navigate, useNavigate } from "react-router";
            export function Protected({ user }: { user: string | null }) {
                const navigate = useNavigate();
                if (!user) {
                    return <Navigate to="/login" replace />;
                }
                return <button onClick={() => navigate("/home")}>Home</button>;
            }
            "#,
            RuleId::ReactRouterNoNavigateInRender,
        )
        .is_empty()
    );

    // 5. react-router-no-nested-router
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { BrowserRouter, MemoryRouter } from "react-router";
            export function App() {
                return (
                    <BrowserRouter>
                        <MemoryRouter>
                            <div />
                        </MemoryRouter>
                    </BrowserRouter>
                );
            }
            "#,
            RuleId::ReactRouterNoNestedRouter,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { BrowserRouter, Routes, Route } from "react-router";
            export function App() {
                return (
                    <BrowserRouter>
                        <Routes>
                            <Route path="/" element={<div />} />
                        </Routes>
                    </BrowserRouter>
                );
            }
            "#,
            RuleId::ReactRouterNoNestedRouter,
        )
        .is_empty()
    );

    // 6. react-router-no-router-in-render
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { createBrowserRouter, RouterProvider } from "react-router";
            export function App() {
                const router = createBrowserRouter([{ path: "/", Component: Home }]);
                return <RouterProvider router={router} />;
            }
            "#,
            RuleId::ReactRouterNoRouterInRender,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { createBrowserRouter, RouterProvider } from "react-router";
            const router = createBrowserRouter([{ path: "/", Component: Home }]);
            export function App() {
                return <RouterProvider router={router} />;
            }
            "#,
            RuleId::ReactRouterNoRouterInRender,
        )
        .is_empty()
    );

    // 7. react-router-no-unsynchronized-search-params-mutation
    assert_eq!(
        run_rule(
            "src/Search.tsx",
            r#"
            import { useSearchParams } from "react-router";
            export function Search() {
                const [searchParams] = useSearchParams();
                function updateFilter() {
                    searchParams.set("filter", "active");
                }
                return <button onClick={updateFilter}>Filter</button>;
            }
            "#,
            RuleId::ReactRouterNoUnsynchronizedSearchParamsMutation,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Search.tsx",
            r#"
            import { useSearchParams } from "react-router";
            export function Search() {
                const [searchParams, setSearchParams] = useSearchParams();
                function updateFilter() {
                    const next = new URLSearchParams(searchParams);
                    next.set("filter", "active");
                    setSearchParams(next);
                }
                return <button onClick={updateFilter}>Filter</button>;
            }
            "#,
            RuleId::ReactRouterNoUnsynchronizedSearchParamsMutation,
        )
        .is_empty()
    );

    // 8. react-router-no-use-loader-data-in-error-ui
    assert_eq!(
        run_rule(
            "src/routes/invoice.tsx",
            r#"
            import { useLoaderData, useRouteError } from "react-router";
            export function ErrorBoundary() {
                const data = useLoaderData();
                const error = useRouteError();
                return <div>{String(data)} {String(error)}</div>;
            }
            "#,
            RuleId::ReactRouterNoUseLoaderDataInErrorUi,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/invoice.tsx",
            r#"
            import { useRouteLoaderData, useRouteError } from "react-router";
            export function ErrorBoundary() {
                const data = useRouteLoaderData("routes/invoice");
                const error = useRouteError();
                return <div>{String(data)} {String(error)}</div>;
            }
            "#,
            RuleId::ReactRouterNoUseLoaderDataInErrorUi,
        )
        .is_empty()
    );

    // 9. react-router-resource-link-requires-reload
    assert_eq!(
        run_rule(
            "src/ExportLink.tsx",
            r#"
            import { Link } from "react-router";
            export function ExportLink() {
                return <Link to="/reports/annual.pdf">Download PDF</Link>;
            }
            "#,
            RuleId::ReactRouterResourceLinkRequiresReload,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/ExportLink.tsx",
            r#"
            import { Link } from "react-router";
            export function ExportLink() {
                return <Link to="/reports/annual.pdf" reloadDocument>Download PDF</Link>;
            }
            "#,
            RuleId::ReactRouterResourceLinkRequiresReload,
        )
        .is_empty()
    );

    // 10. react-router-return-navigation-promise-in-transition
    assert_eq!(
        run_rule(
            "src/TabSwitcher.tsx",
            r#"
            import { startTransition } from "react";
            import { useNavigate } from "react-router";
            export function TabSwitcher() {
                const navigate = useNavigate();
                function switchTab() {
                    startTransition(() => {
                        navigate("/analytics");
                    });
                }
                return <button onClick={switchTab}>Analytics</button>;
            }
            "#,
            RuleId::ReactRouterReturnNavigationPromiseInTransition,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/TabSwitcher.tsx",
            r#"
            import { startTransition } from "react";
            import { useNavigate } from "react-router";
            export function TabSwitcher() {
                const navigate = useNavigate();
                function switchTab() {
                    startTransition(async () => {
                        await navigate("/analytics");
                    });
                }
                return <button onClick={switchTab}>Analytics</button>;
            }
            "#,
            RuleId::ReactRouterReturnNavigationPromiseInTransition,
        )
        .is_empty()
    );

    // 11. react-router-v8-no-meta-data-field
    assert_eq!(
        run_rule(
            "src/routes/product.tsx",
            r#"
            export function meta({ data }: { data: { title: string } }) {
                return [{ title: data.title }];
            }
            "#,
            RuleId::ReactRouterV8NoMetaDataField,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/product.tsx",
            r#"
            export function meta({ loaderData }: { loaderData: { title: string } }) {
                return [{ title: loaderData.title }];
            }
            "#,
            RuleId::ReactRouterV8NoMetaDataField,
        )
        .is_empty()
    );

    // 12. react-router-v8-no-react-router-dom-import (plus Autofix round-trip)
    let dom_import_src = r#"import { Link, useNavigate } from "react-router-dom";
export function Header() {
    const navigate = useNavigate();
    return <Link to="/" onClick={() => navigate("/")}>Home</Link>;
}
"#;
    let dom_diags = run_rule(
        "src/Header.tsx",
        dom_import_src,
        RuleId::ReactRouterV8NoReactRouterDomImport,
    );
    assert_eq!(dom_diags.len(), 1);
    assert_eq!(dom_diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten, descriptions) = apply_patches_to_source(dom_import_src, &dom_diags);
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten.contains(r#"from "react-router""#));
    assert!(!rewritten.contains("react-router-dom"));
    let reanalyzed = run_rule(
        "src/Header.tsx",
        &rewritten,
        RuleId::ReactRouterV8NoReactRouterDomImport,
    );
    assert!(reanalyzed.is_empty());

    // 13. react-router-v8-no-removed-future-flags
    assert_eq!(
        run_rule(
            "react-router.config.ts",
            r#"
            export default {
                future: {
                    v3_fetcherPersist: true,
                },
            };
            "#,
            RuleId::ReactRouterV8NoRemovedFutureFlags,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "react-router.config.ts",
            r#"
            export default {
                ssr: true,
                splitRouteModules: true,
            };
            "#,
            RuleId::ReactRouterV8NoRemovedFutureFlags,
        )
        .is_empty()
    );
}

#[test]
fn jsx_route_tree_and_single_quote_autofix_suite() {
    // JSX <Route> duplicate id, invalid splat, invalid absolute child path, empty leaf, and missing Outlet
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            export function App() {
                return (
                    <Routes>
                        <Route id="dup" path="/a" element={<div />} />
                        <Route id="dup" path="/b" element={<div />} />
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterNoDuplicateRouteId,
        )
        .len(),
        1
    );

    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            export function App() {
                return (
                    <Routes>
                        <Route path="/docs/*/edit" element={<div />} />
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterNoInvalidSplatPath,
        )
        .len(),
        1
    );

    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            export function App() {
                return (
                    <Routes>
                        <Route path="/parent" element={<Layout />}>
                            <Route path="/other" element={<div />} />
                        </Route>
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterNoInvalidAbsoluteChildPath,
        )
        .len(),
        1
    );

    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Routes, Route } from "react-router";
            export function App() {
                return (
                    <Routes>
                        <Route path="/orphan" />
                    </Routes>
                );
            }
            "#,
            RuleId::ReactRouterNoEmptyLeafRoute,
        )
        .len(),
        1
    );

    // Single-quote autofix for react-router-v8-no-react-router-dom-import
    let single_quote_src = "import { Outlet } from 'react-router-dom';\nexport function Layout() { return <Outlet />; }\n";
    let diags = run_rule(
        "src/Layout.tsx",
        single_quote_src,
        RuleId::ReactRouterV8NoReactRouterDomImport,
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten, _) = apply_patches_to_source(single_quote_src, &diags);
    assert!(rewritten.contains("from 'react-router'"));
    assert!(
        run_rule(
            "src/Layout.tsx",
            &rewritten,
            RuleId::ReactRouterV8NoReactRouterDomImport,
        )
        .is_empty()
    );
}
