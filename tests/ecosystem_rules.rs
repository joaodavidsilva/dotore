//! Integration tests for Ticket #11:
//! Ecosystem Rule Families — TanStack Query/Start, React Native/Expo, Zustand,
//! Jotai, MobX, Valtio, Preact, Ink, and Zod.

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, RuleId, analyze_project_sources, analyze_source,
    analyze_source_with_config, rule_registry,
};

fn run_rule(path: &str, source: &str, rule: RuleId) -> Vec<dotore::Diagnostic> {
    analyze_source(Path::new(path), source, Some(&[rule]))
}

#[test]
fn ecosystem_rule_catalog_and_capability_gate_activation() {
    let registry = rule_registry();
    let expected_ids = [
        // TanStack Query (9)
        "query-destructure-result",
        "query-floating-mutate-async",
        "query-mutation-missing-invalidation",
        "query-no-mutation-in-effect-as-read",
        "query-no-query-in-effect",
        "query-no-rest-destructuring",
        "query-no-use-query-for-mutation",
        "query-no-void-query-fn",
        "query-stable-query-client",
        // TanStack Start (15)
        "tanstack-start-get-mutation",
        "tanstack-start-loader-parallel-fetch",
        "tanstack-start-missing-head-content",
        "tanstack-start-missing-scripts",
        "tanstack-start-no-anchor-element",
        "tanstack-start-no-direct-fetch-in-loader",
        "tanstack-start-no-dynamic-server-fn-import",
        "tanstack-start-no-navigate-in-render",
        "tanstack-start-no-secrets-in-loader",
        "tanstack-start-no-use-effect-fetch",
        "tanstack-start-no-use-server-in-handler",
        "tanstack-start-redirect-in-try-catch",
        "tanstack-start-route-property-order",
        "tanstack-start-server-fn-method-order",
        "tanstack-start-server-fn-validate-input",
        // React Native & Expo AST rules (42)
        "expo-no-non-inlined-env",
        "rn-animate-layout-property",
        "rn-animation-reaction-as-derived",
        "rn-bottom-sheet-no-ignored-scroll-prop",
        "rn-bottom-sheet-no-state-in-on-animate",
        "rn-bottom-sheet-prefer-native",
        "rn-bottom-sheet-use-integrated-scrollable",
        "rn-detox-missing-await",
        "rn-list-callback-per-row",
        "rn-list-data-mapped",
        "rn-list-missing-estimated-item-size",
        "rn-list-recyclable-without-types",
        "rn-no-deep-imports",
        "rn-no-deprecated-modules",
        "rn-no-dimensions-get",
        "rn-no-falsy-and-render",
        "rn-no-image-children",
        "rn-no-inline-flatlist-renderitem",
        "rn-no-inline-object-in-list-item",
        "rn-no-legacy-expo-packages",
        "rn-no-legacy-shadow-styles",
        "rn-no-non-native-navigator",
        "rn-no-panresponder",
        "rn-no-raw-text",
        "rn-no-renderitem-key",
        "rn-no-scroll-state",
        "rn-no-scrollview-mapped-list",
        "rn-no-set-native-props",
        "rn-no-single-element-style-array",
        "rn-platform-shaking-use-direct-import",
        "rn-prefer-content-inset-adjustment",
        "rn-prefer-expo-image",
        "rn-prefer-pressable-over-gesture-detector",
        "rn-prefer-pressable",
        "rn-prefer-reanimated",
        "rn-pressable-shared-value-mutation",
        "rn-reanimated-4-no-legacy-spring-thresholds",
        "rn-reanimated-4-no-removed-api",
        "rn-reanimated-4-use-worklets-scheduler",
        "rn-scrollview-dynamic-padding",
        "rn-scrollview-flex-in-content-container",
        "rn-style-prefer-box-shadow",
        // React Native & Expo project config rules
        "rn-no-metro-babel-preset",
        "rn-no-metro-babel-runtime-version",
        "rn-library-react-in-dependencies",
        "rn-react-compiler-plugin-first",
        "rn-reanimated-worklets-plugin-last",
        "rn-android-release-shrinking-disabled",
        "expo-no-unimodules-packages",
        "expo-no-cli-dependencies",
        "expo-no-redundant-dependency",
        "expo-no-conflicting-dependency-override",
        "expo-router-no-react-navigation",
        "expo-vector-icons-conflict",
        "expo-package-json-conflict",
        "expo-lockfile",
        "expo-metro-config",
        "expo-env-local-not-gitignored",
        "expo-gitignore",
        "expo-reanimated-v4-requires-new-arch",
        "expo-updates-no-unsafe-production-config",
        // Zustand, Jotai, MobX, Valtio (12)
        "zustand-no-mutating-state",
        "zustand-no-fresh-selector-result",
        "zustand-no-whole-store-destructure",
        "zustand-no-get-during-initialization",
        "jotai-select-atom-in-render-body",
        "jotai-derived-atom-returns-fresh-object",
        "jotai-tq-use-raw-query-atom",
        "mobx-reaction-disposer-discarded",
        "mobx-no-observer-wrapped-memo",
        "mobx-no-make-auto-observable-in-inheritance",
        "valtio-no-proxy-read-in-render",
        "valtio-no-snapshot-in-callback",
        // Preact (6)
        "preact-no-react-import",
        "preact-prefer-oninput",
        "preact-prefer-ondblclick",
        "preact-no-render-arguments",
        "preact-no-react-hooks-import",
        "preact-no-children-length",
        // Ink (22)
        "ink-ctrl-c-handler-requires-exit-option",
        "ink-newline-inside-text",
        "ink-no-bare-process-exit",
        "ink-no-direct-raw-mode",
        "ink-no-dom-host-elements",
        "ink-no-dom-router",
        "ink-no-focus-in-render",
        "ink-no-layout-inside-text",
        "ink-no-live-hooks-in-render-to-string",
        "ink-no-measure-element-in-render",
        "ink-no-multiple-static",
        "ink-no-raw-text",
        "ink-no-repeated-render",
        "ink-prefer-use-animation",
        "ink-prefer-use-paste",
        "ink-static-is-append-only",
        "ink-static-requires-key",
        "ink-suspense-requires-concurrent",
        "ink-use-reactive-window-size",
        "ink-use-string-width-for-cursor",
        "ink-use-suspend-terminal",
        "ink-valid-aria-semantics",
        // Zod (5)
        "zod-v4-deprecated-parse",
        "zod-v4-prefer-top-level-string-formats",
        "zod-v4-no-deprecated-schema-apis",
        "zod-v4-no-deprecated-error-customization",
        "zod-v4-no-deprecated-error-apis",
    ];

    for id_str in expected_ids {
        let parsed = RuleId::parse(id_str)
            .unwrap_or_else(|| panic!("Expected RuleId::parse({id_str:?}) to succeed"));
        assert_eq!(parsed.as_str(), id_str);
        assert!(
            registry.iter().any(|m| m.id == parsed),
            "Rule {id_str} missing from rule_registry()"
        );
    }

    // Legacy alias `tanstack-start-no-useeffect-fetch` resolves to `TanstackStartNoUseEffectFetch`
    assert_eq!(
        RuleId::parse("tanstack-start-no-useeffect-fetch"),
        Some(RuleId::TanstackStartNoUseEffectFetch)
    );

    // Capability Gate verification: plain React gate does NOT activate ecosystem rules
    let plain_react_gate = CapabilityGate::default_react();
    let cfg = DotoreConfig::default();
    let sample = r#"
        import { useQuery } from "@tanstack/react-query";
        export function Comp() {
            const client = new QueryClient();
            const { data, ...rest } = useQuery({ queryKey: ["k"], queryFn: () => {} });
            return <View>raw text</View>;
        }
    "#;
    let plain_diags = analyze_source_with_config(
        Path::new("src/Comp.tsx"),
        sample,
        &cfg,
        &plain_react_gate,
        None,
    );
    assert!(
        !plain_diags.iter().any(|d| matches!(
            d.rule,
            RuleId::QueryStableQueryClient
                | RuleId::QueryNoRestDestructuring
                | RuleId::QueryNoVoidQueryFn
                | RuleId::RnNoRawText
        )),
        "Plain React gate should not activate TanStack or RN rules: {plain_diags:#?}"
    );

    // Activating TanStackQuery + ReactNative activates those families
    let active_gate = CapabilityGate::with_capabilities([
        Capability::React,
        Capability::TanstackQuery,
        Capability::ReactNative,
    ]);
    let active_diags =
        analyze_source_with_config(Path::new("src/Comp.tsx"), sample, &cfg, &active_gate, None);
    assert!(
        active_diags
            .iter()
            .any(|d| d.rule == RuleId::QueryStableQueryClient)
    );
    assert!(
        active_diags
            .iter()
            .any(|d| d.rule == RuleId::QueryNoRestDestructuring)
    );
    assert!(
        active_diags
            .iter()
            .any(|d| d.rule == RuleId::QueryNoVoidQueryFn)
    );
    assert!(active_diags.iter().any(|d| d.rule == RuleId::RnNoRawText));
}

#[test]
fn tanstack_query_rules_suite() {
    // 1. query-no-query-in-effect
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useEffect } from "react";
            import { useQuery } from "@tanstack/react-query";
            export function App({ id }: { id: string }) {
                const { refetch } = useQuery({ queryKey: ["user", id], queryFn: () => fetchUser(id) });
                useEffect(() => {
                    refetch();
                }, [id, refetch]);
                return null;
            }
            "#,
            RuleId::QueryNoQueryInEffect,
        )
        .len(),
        1
    );
    // Valid: refetch inside an event listener registered in useEffect is not unconditional effect execution
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useEffect } from "react";
            import { useQuery } from "@tanstack/react-query";
            export function App() {
                const { refetch } = useQuery({ queryKey: ["user"], queryFn: fetchUser });
                useEffect(() => {
                    const onFocus = () => refetch();
                    window.addEventListener("focus", onFocus);
                    return () => window.removeEventListener("focus", onFocus);
                }, [refetch]);
                return null;
            }
            "#,
            RuleId::QueryNoQueryInEffect,
        )
        .is_empty()
    );

    // 2. query-no-mutation-in-effect-as-read
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useEffect } from "react";
            import { useMutation } from "@tanstack/react-query";
            export function UserProfile({ userId }: { userId: string }) {
                const { mutate: fetchUserDetails, data } = useMutation({
                    mutationFn: (id: string) => getUser(id),
                });
                useEffect(() => {
                    fetchUserDetails(userId);
                }, [userId]);
                return <div>{data?.name}</div>;
            }
            "#,
            RuleId::QueryNoMutationInEffectAsRead,
        )
        .len(),
        1
    );
    // Valid: write-intent mutation (`trackPageView`) without consumed response data
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useEffect } from "react";
            import { useMutation } from "@tanstack/react-query";
            export function PageTracker({ page }: { page: string }) {
                const { mutate: createAuditLog } = useMutation({
                    mutationFn: (p: string) => postAuditLog(p),
                });
                useEffect(() => {
                    createAuditLog(page);
                }, [page]);
                return null;
            }
            "#,
            RuleId::QueryNoMutationInEffectAsRead,
        )
        .is_empty()
    );

    // 3. query-no-use-query-for-mutation
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function DeleteUser({ id }: { id: string }) {
                useQuery({
                    queryKey: ["delete", id],
                    queryFn: () => fetch(`/api/users/${id}`, { method: "DELETE" }),
                });
                return null;
            }
            "#,
            RuleId::QueryNoUseQueryForMutation,
        )
        .len(),
        1
    );
    // Valid: GraphQL POST query (not mutation)
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function Users() {
                useQuery({
                    queryKey: ["users"],
                    queryFn: () => fetch("/graphql", {
                        method: "POST",
                        body: JSON.stringify({ query: "query { users { id } }" }),
                    }),
                });
                return null;
            }
            "#,
            RuleId::QueryNoUseQueryForMutation,
        )
        .is_empty()
    );

    // 4. query-stable-query-client
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
            export function App() {
                const queryClient = new QueryClient();
                return <QueryClientProvider client={queryClient}><div /></QueryClientProvider>;
            }
            "#,
            RuleId::QueryStableQueryClient,
        )
        .len(),
        1
    );
    // Valid: module scope or inside useState initializer
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useState } from "react";
            import { QueryClient } from "@tanstack/react-query";
            const globalClient = new QueryClient();
            export function App() {
                const [client] = useState(() => new QueryClient());
                return null;
            }
            "#,
            RuleId::QueryStableQueryClient,
        )
        .is_empty()
    );

    // 5. query-no-void-query-fn
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function App() {
                useQuery({ queryKey: ["todos"], queryFn: () => {} });
                return null;
            }
            "#,
            RuleId::QueryNoVoidQueryFn,
        )
        .len(),
        1
    );

    // 6. query-no-rest-destructuring
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function App() {
                const { data, ...rest } = useQuery({ queryKey: ["todos"], queryFn: fetchTodos });
                return <div>{data}</div>;
            }
            "#,
            RuleId::QueryNoRestDestructuring,
        )
        .len(),
        1
    );
    // Valid: non-TanStack useQuery from another library
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "convex/react";
            export function App() {
                const { data, ...rest } = useQuery("todos");
                return <div>{data}</div>;
            }
            "#,
            RuleId::QueryNoRestDestructuring,
        )
        .is_empty()
    );

    // 7. query-destructure-result
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function App() {
                const query = useQuery({ queryKey: ["todos"], queryFn: fetchTodos });
                return <TodoView {...query} />;
            }
            "#,
            RuleId::QueryDestructureResult,
        )
        .len(),
        1
    );
    // Valid: spreading query in custom hook return value
    assert!(
        run_rule(
            "src/useTodos.ts",
            r#"
            import { useQuery } from "@tanstack/react-query";
            export function useTodos() {
                const query = useQuery({ queryKey: ["todos"], queryFn: fetchTodos });
                return { ...query, count: 0 };
            }
            "#,
            RuleId::QueryDestructureResult,
        )
        .is_empty()
    );

    // 8. query-floating-mutate-async
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useMutation } from "@tanstack/react-query";
            export function App() {
                const { mutateAsync } = useMutation({ mutationFn: saveTodo });
                const handleClick = () => {
                    mutateAsync({ title: "New" });
                };
                return <button onClick={handleClick}>Save</button>;
            }
            "#,
            RuleId::QueryFloatingMutateAsync,
        )
        .len(),
        1
    );
    // Valid: awaited mutateAsync
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useMutation } from "@tanstack/react-query";
            export function App() {
                const { mutateAsync } = useMutation({ mutationFn: saveTodo });
                const handleClick = async () => {
                    await mutateAsync({ title: "New" });
                };
                return <button onClick={handleClick}>Save</button>;
            }
            "#,
            RuleId::QueryFloatingMutateAsync,
        )
        .is_empty()
    );

    // 9. query-mutation-missing-invalidation
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useMutation, useQueryClient } from "@tanstack/react-query";
            export function App() {
                const queryClient = useQueryClient();
                const mutation = useMutation({
                    mutationFn: updateProfile,
                    onSuccess: () => {
                        console.log("saved");
                    },
                });
                return null;
            }
            "#,
            RuleId::QueryMutationMissingInvalidation,
        )
        .len(),
        1
    );
    // Valid: invalidates queries in onSuccess
    assert!(
        run_rule(
            "src/App.tsx",
            r#"
            import { useMutation, useQueryClient } from "@tanstack/react-query";
            export function App() {
                const queryClient = useQueryClient();
                const mutation = useMutation({
                    mutationFn: updateProfile,
                    onSuccess: () => {
                        queryClient.invalidateQueries({ queryKey: ["profile"] });
                    },
                });
                return null;
            }
            "#,
            RuleId::QueryMutationMissingInvalidation,
        )
        .is_empty()
    );
}

#[test]
fn tanstack_start_rules_suite() {
    // 1. tanstack-start-server-fn-validate-input
    assert_eq!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const updatePost = createServerFn({ method: "POST" })
                .handler(async ({ data }) => {
                    return db.update(data.id);
                });
            "#,
            RuleId::TanstackStartServerFnValidateInput,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const updatePost = createServerFn({ method: "POST" })
                .validator(postSchema)
                .handler(async ({ data }) => {
                    return db.update(data.id);
                });
            "#,
            RuleId::TanstackStartServerFnValidateInput,
        )
        .is_empty()
    );

    // 2. tanstack-start-server-fn-method-order
    assert_eq!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const saveFn = createServerFn()
                .validator(schema)
                .middleware([authMiddleware])
                .handler(async () => {});
            "#,
            RuleId::TanstackStartServerFnMethodOrder,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const saveFn = createServerFn()
                .middleware([authMiddleware])
                .validator(schema)
                .handler(async () => {});
            "#,
            RuleId::TanstackStartServerFnMethodOrder,
        )
        .is_empty()
    );

    // 3. tanstack-start-route-property-order
    assert_eq!(
        run_rule(
            "src/routes/posts.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            export const Route = createFileRoute("/posts")({
                loader: async () => fetchPosts(),
                beforeLoad: async () => checkAuth(),
            });
            "#,
            RuleId::TanstackStartRoutePropertyOrder,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/posts.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            export const Route = createFileRoute("/posts")({
                beforeLoad: async () => checkAuth(),
                loader: async () => fetchPosts(),
            });
            "#,
            RuleId::TanstackStartRoutePropertyOrder,
        )
        .is_empty()
    );

    // 4. tanstack-start-redirect-in-try-catch
    assert_eq!(
        run_rule(
            "src/routes/posts.tsx",
            r#"
            import { redirect } from "@tanstack/react-router";
            export async function loadPost() {
                try {
                    throw redirect({ to: "/login" });
                } catch (err) {
                    console.error(err);
                }
            }
            "#,
            RuleId::TanstackStartRedirectInTryCatch,
        )
        .len(),
        1
    );
    // Valid: catch block re-throws error
    assert!(
        run_rule(
            "src/routes/posts.tsx",
            r#"
            import { redirect } from "@tanstack/react-router";
            export async function loadPost() {
                try {
                    throw redirect({ to: "/login" });
                } catch (err) {
                    throw err;
                }
            }
            "#,
            RuleId::TanstackStartRedirectInTryCatch,
        )
        .is_empty()
    );

    // 5. tanstack-start-no-use-server-in-handler
    assert_eq!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const myFn = createServerFn().handler(async () => {
                "use server";
                return 42;
            });
            "#,
            RuleId::TanstackStartNoUseServerInHandler,
        )
        .len(),
        1
    );

    // 6. tanstack-start-get-mutation
    assert_eq!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const removeUser = createServerFn({ method: "GET" }).handler(async () => {
                await db.delete(users);
            });
            "#,
            RuleId::TanstackStartGetMutation,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/fn.ts",
            r#"
            import { createServerFn } from "@tanstack/react-start";
            export const removeUser = createServerFn({ method: "POST" }).handler(async () => {
                await db.delete(users);
            });
            "#,
            RuleId::TanstackStartGetMutation,
        )
        .is_empty()
    );

    // 7. tanstack-start-loader-parallel-fetch
    assert_eq!(
        run_rule(
            "src/routes/dashboard.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            export const Route = createFileRoute("/dashboard")({
                loader: async () => {
                    const user = await fetchUser();
                    const posts = await fetchPosts();
                    return { user, posts };
                },
            });
            "#,
            RuleId::TanstackStartLoaderParallelFetch,
        )
        .len(),
        1
    );
    // Valid: second await depends on first await's binding
    assert!(
        run_rule(
            "src/routes/dashboard.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            export const Route = createFileRoute("/dashboard")({
                loader: async () => {
                    const user = await fetchUser();
                    const posts = await fetchPosts(user.id);
                    return { user, posts };
                },
            });
            "#,
            RuleId::TanstackStartLoaderParallelFetch,
        )
        .is_empty()
    );

    // 8. tanstack-start-missing-head-content
    assert_eq!(
        run_rule(
            "src/routes/__root.tsx",
            r#"
            export function RootDocument() {
                return (
                    <html>
                        <head>
                            <meta charSet="utf-8" />
                        </head>
                        <body><div /></body>
                    </html>
                );
            }
            "#,
            RuleId::TanstackStartMissingHeadContent,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/__root.tsx",
            r#"
            import { HeadContent } from "@tanstack/react-router";
            export function RootDocument() {
                return (
                    <html>
                        <head>
                            <HeadContent />
                        </head>
                        <body><div /></body>
                    </html>
                );
            }
            "#,
            RuleId::TanstackStartMissingHeadContent,
        )
        .is_empty()
    );

    // 9. tanstack-start-missing-scripts
    assert_eq!(
        run_rule(
            "src/routes/__root.tsx",
            r#"
            import { createRootRoute, Outlet } from "@tanstack/react-router";
            export const Route = createRootRoute({
                component: RootComponent,
            });
            function RootComponent() {
                return (
                    <html>
                        <body>
                            <Outlet />
                        </body>
                    </html>
                );
            }
            "#,
            RuleId::TanstackStartMissingScripts,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/__root.tsx",
            r#"
            import { createRootRoute, Outlet, Scripts } from "@tanstack/react-router";
            export const Route = createRootRoute({
                component: RootComponent,
            });
            function RootComponent() {
                return (
                    <html>
                        <body>
                            <Outlet />
                            <Scripts />
                        </body>
                    </html>
                );
            }
            "#,
            RuleId::TanstackStartMissingScripts,
        )
        .is_empty()
    );

    // 10. tanstack-start-no-anchor-element
    assert_eq!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            export function Home() {
                return <a href="/about">About</a>;
            }
            "#,
            RuleId::TanstackStartNoAnchorElement,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            export function Home() {
                return (
                    <>
                        <a href="https://example.com">External</a>
                        <a href="/resume.pdf">PDF</a>
                        <a href="/about" target="_blank">New Tab</a>
                    </>
                );
            }
            "#,
            RuleId::TanstackStartNoAnchorElement,
        )
        .is_empty()
    );

    // 11. tanstack-start-no-dynamic-server-fn-import
    assert_eq!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            export async function load() {
                const mod = await import("../utils/posts.functions");
                return mod;
            }
            "#,
            RuleId::TanstackStartNoDynamicServerFnImport,
        )
        .len(),
        1
    );

    // 12. tanstack-start-no-navigate-in-render
    assert_eq!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            import { useNavigate } from "@tanstack/react-router";
            export function Page({ isLoggedOut }: { isLoggedOut: boolean }) {
                const navigate = useNavigate();
                if (isLoggedOut) {
                    navigate({ to: "/login" });
                }
                return <div />;
            }
            "#,
            RuleId::TanstackStartNoNavigateInRender,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            import { useNavigate } from "@tanstack/react-router";
            export function Page() {
                const navigate = useNavigate();
                return <button onClick={() => navigate({ to: "/login" })}>Login</button>;
            }
            "#,
            RuleId::TanstackStartNoNavigateInRender,
        )
        .is_empty()
    );

    // 13. tanstack-start-no-secrets-in-loader
    assert_eq!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            export const Route = createFileRoute("/")({
                loader: async () => {
                    const key = process.env.STRIPE_SECRET_KEY;
                    return { key };
                },
            });
            "#,
            RuleId::TanstackStartNoSecretsInLoader,
        )
        .len(),
        1
    );
    // Valid: inside createServerFn().handler(...)
    assert!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            import { createFileRoute } from "@tanstack/react-router";
            import { createServerFn } from "@tanstack/react-start";
            export const Route = createFileRoute("/")({
                loader: async () => {
                    const fn = createServerFn().handler(async () => process.env.STRIPE_SECRET_KEY);
                    return fn();
                },
            });
            "#,
            RuleId::TanstackStartNoSecretsInLoader,
        )
        .is_empty()
    );

    // 14. tanstack-start-no-use-effect-fetch
    assert_eq!(
        run_rule(
            "src/routes/index.tsx",
            r#"
            import { useEffect } from "react";
            export function RoutePage() {
                useEffect(() => {
                    fetch("/api/posts");
                }, []);
                return <div />;
            }
            "#,
            RuleId::TanstackStartNoUseEffectFetch,
        )
        .len(),
        1
    );
}

#[test]
fn react_native_and_expo_ast_rules_suite() {
    // 1. rn-no-raw-text across files (honoring textComponents, rawTextWrapperComponents, and cross-file wrappers)
    let cross_file_rn_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "name": "rn-app",
                    "dependencies": { "react": "19.0.0", "react-native": "0.76.0" },
                    "dotore": {
                        "textComponents": ["BrandHeading"],
                        "rawTextWrapperComponents": ["BadgePill"]
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/wrappers.tsx"),
                r#"
                import { View, Text } from "react-native";
                export const CardBox = ({ children }: { children: any }) => <View>{children}</View>;
                export const SafeLabel = ({ children }: { children: any }) => <Text>{children}</Text>;
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/Screen.tsx"),
                r#"
                import { View, Text } from "react-native";
                import { CardBox, SafeLabel } from "./wrappers";
                export function Screen() {
                    return (
                        <View>
                            <Text>Valid RN text</Text>
                            <BrandHeading>Valid configured textComponent</BrandHeading>
                            <BadgePill>Valid string-only rawTextWrapperComponent</BadgePill>
                            <SafeLabel>Valid cross-file Text wrapper</SafeLabel>
                            <CardBox>Invalid raw text forwarded into cross-file View wrapper</CardBox>
                        </View>
                    );
                }
                "#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RnNoRawText]),
    );
    assert_eq!(
        cross_file_rn_report.diagnostics.len(),
        1,
        "Expected only CardBox raw text to be flagged, got: {:#?}",
        cross_file_rn_report.diagnostics
    );
    assert_eq!(cross_file_rn_report.diagnostics[0].target_name, "CardBox");

    // DOM tags inside RN package stay silent (DevTools / react-native-web regression)
    assert!(
        run_rule(
            "src/WebPanel.tsx",
            r#"
            export const CookieCard = () => (
                <div className="p-3">
                    <span>Domain:</span> example.com
                </div>
            );
            "#,
            RuleId::RnNoRawText,
        )
        .is_empty()
    );

    // 2. rn-list-recyclable-without-types
    assert_eq!(
        run_rule(
            "src/Feed.tsx",
            r#"
            import { FlashList } from "@shopify/flash-list";
            export function Feed({ items }: { items: any[] }) {
                return (
                    <FlashList
                        data={items}
                        estimatedItemSize={80}
                        renderItem={({ item }) =>
                            item.kind === "video" ? <VideoRow item={item} /> : <TextRow item={item} />
                        }
                    />
                );
            }
            "#,
            RuleId::RnListRecyclableWithoutTypes,
        )
        .len(),
        1
    );
    // Valid: getItemType provided
    assert!(
        run_rule(
            "src/Feed.tsx",
            r#"
            import { FlashList } from "@shopify/flash-list";
            export function Feed({ items }: { items: any[] }) {
                return (
                    <FlashList
                        data={items}
                        estimatedItemSize={80}
                        getItemType={(item) => item.kind}
                        renderItem={({ item }) =>
                            item.kind === "video" ? <VideoRow item={item} /> : <TextRow item={item} />
                        }
                    />
                );
            }
            "#,
            RuleId::RnListRecyclableWithoutTypes,
        )
        .is_empty()
    );

    // 3. rn-list-missing-estimated-item-size
    assert_eq!(
        run_rule(
            "src/Feed.tsx",
            r#"
            import { FlashList } from "@shopify/flash-list";
            export function Feed({ items }: { items: any[] }) {
                return <FlashList data={items} renderItem={({ item }) => <Row item={item} />} />;
            }
            "#,
            RuleId::RnListMissingEstimatedItemSize,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Feed.tsx",
            r#"
            import { FlashList } from "@shopify/flash-list";
            export function Feed({ items }: { items: any[] }) {
                return <FlashList data={items} estimatedItemSize={64} renderItem={({ item }) => <Row item={item} />} />;
            }
            "#,
            RuleId::RnListMissingEstimatedItemSize,
        )
        .is_empty()
    );

    // 4. rn-scrollview-flex-in-content-container
    assert_eq!(
        run_rule(
            "src/Screen.tsx",
            r#"
            import { ScrollView } from "react-native";
            export function Screen() {
                return <ScrollView contentContainerStyle={{ flex: 1 }} />;
            }
            "#,
            RuleId::RnScrollviewFlexInContentContainer,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Screen.tsx",
            r#"
            import { ScrollView } from "react-native";
            export function Screen() {
                return <ScrollView contentContainerStyle={{ flexGrow: 1 }} />;
            }
            "#,
            RuleId::RnScrollviewFlexInContentContainer,
        )
        .is_empty()
    );

    // 5. rn-scrollview-dynamic-padding
    assert_eq!(
        run_rule(
            "src/Screen.tsx",
            r#"
            import { ScrollView } from "react-native";
            export function Screen({ keyboardHeight }: { keyboardHeight: number }) {
                return <ScrollView contentContainerStyle={{ paddingBottom: keyboardHeight }} />;
            }
            "#,
            RuleId::RnScrollviewDynamicPadding,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Screen.tsx",
            r#"
            import { ScrollView } from "react-native";
            const BASE_PADDING = 24;
            export function Screen() {
                return <ScrollView contentContainerStyle={{ paddingBottom: BASE_PADDING + 8 }} />;
            }
            "#,
            RuleId::RnScrollviewDynamicPadding,
        )
        .is_empty()
    );

    // 6. rn-prefer-expo-image
    assert_eq!(
        run_rule(
            "src/Avatar.tsx",
            r#"
            import { Image } from "react-native";
            export function Avatar({ uri }: { uri: string }) {
                return <Image source={{ uri }} />;
            }
            "#,
            RuleId::RnPreferExpoImage,
        )
        .len(),
        1
    );
    // Valid: bundled static require('./logo.png') asset
    assert!(
        run_rule(
            "src/Logo.tsx",
            r#"
            import { Image } from "react-native";
            export function Logo() {
                return <Image source={require("./logo.png")} />;
            }
            "#,
            RuleId::RnPreferExpoImage,
        )
        .is_empty()
    );

    // 7. rn-style-prefer-box-shadow & rn-no-legacy-shadow-styles
    assert_eq!(
        run_rule(
            "src/Card.tsx",
            r#"
            import { StyleSheet } from "react-native";
            const styles = StyleSheet.create({
                card: {
                    shadowColor: '#000',
                    shadowOpacity: 0.2,
                    elevation: 4,
                },
            });
            "#,
            RuleId::RnStylePreferBoxShadow,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/Card.tsx",
            r#"
            import { View } from "react-native";
            export function Card() {
                return <View style={{ shadowColor: '#000', shadowRadius: 4 }} />;
            }
            "#,
            RuleId::RnNoLegacyShadowStyles,
        )
        .len(),
        1
    );

    // 8. expo-no-non-inlined-env (both computed and destructured process.env)
    assert_eq!(
        run_rule(
            "src/Config.tsx",
            r#"
            export function readEnv(key: string) {
                const { EXPO_PUBLIC_API_URL } = process.env;
                return process.env[key] ?? EXPO_PUBLIC_API_URL;
            }
            "#,
            RuleId::ExpoNoNonInlinedEnv,
        )
        .len(),
        2
    );

    // 9. Remaining RN AST rules
    // rn-animation-reaction-as-derived
    assert_eq!(
        run_rule(
            "src/Anim.tsx",
            r#"
            import { useAnimatedReaction } from "react-native-reanimated";
            export function Anim({ sv1, sv2 }: any) {
                useAnimatedReaction(() => sv1.value, (cur) => { sv2.value = cur; });
                return null;
            }
            "#,
            RuleId::RnAnimationReactionAsDerived,
        )
        .len(),
        1
    );

    // rn-bottom-sheet-no-ignored-scroll-prop
    assert_eq!(
        run_rule(
            "src/Sheet.tsx",
            r#"
            import { BottomSheetScrollView } from "@gorhom/bottom-sheet";
            export function Sheet() {
                return <BottomSheetScrollView scrollEventThrottle={16} />;
            }
            "#,
            RuleId::RnBottomSheetNoIgnoredScrollProp,
        )
        .len(),
        1
    );

    // rn-bottom-sheet-no-state-in-on-animate
    assert_eq!(
        run_rule(
            "src/Sheet.tsx",
            r#"
            import { useState } from "react";
            import BottomSheet from "@gorhom/bottom-sheet";
            export function Sheet() {
                const [index, setIndex] = useState(0);
                return <BottomSheet onAnimate={(from, to) => setIndex(to)} />;
            }
            "#,
            RuleId::RnBottomSheetNoStateInOnAnimate,
        )
        .len(),
        1
    );

    // rn-bottom-sheet-prefer-native
    assert_eq!(
        run_rule(
            "src/Sheet.tsx",
            r#"import ActionSheet from "react-native-actions-sheet";"#,
            RuleId::RnBottomSheetPreferNative,
        )
        .len(),
        1
    );

    // rn-bottom-sheet-use-integrated-scrollable
    assert_eq!(
        run_rule(
            "src/Sheet.tsx",
            r#"
            import { ScrollView } from "react-native";
            import BottomSheet from "@gorhom/bottom-sheet";
            export function Sheet() {
                return <BottomSheet><ScrollView /></BottomSheet>;
            }
            "#,
            RuleId::RnBottomSheetUseIntegratedScrollable,
        )
        .len(),
        1
    );

    // rn-detox-missing-await
    assert_eq!(
        run_rule(
            "e2e/login.e2e.ts",
            r#"
            it("taps login", async () => {
                element(by.id("login-btn")).tap();
            });
            "#,
            RuleId::RnDetoxMissingAwait,
        )
        .len(),
        1
    );

    // rn-list-callback-per-row
    assert_eq!(
        run_rule(
            "src/List.tsx",
            r#"
            import { FlatList, Pressable } from "react-native";
            export function List({ items, onSelect }: any) {
                return (
                    <FlatList
                        data={items}
                        renderItem={({ item }) => <Pressable onPress={() => onSelect(item.id)} />}
                    />
                );
            }
            "#,
            RuleId::RnListCallbackPerRow,
        )
        .len(),
        1
    );

    // rn-list-data-mapped
    assert_eq!(
        run_rule(
            "src/List.tsx",
            r#"
            import { FlatList } from "react-native";
            export function List({ items }: any) {
                return <FlatList data={items.filter(Boolean)} renderItem={renderRow} />;
            }
            "#,
            RuleId::RnListDataMapped,
        )
        .len(),
        1
    );

    // rn-no-deep-imports
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"import StyleSheet from "react-native/Libraries/StyleSheet/StyleSheet";"#,
            RuleId::RnNoDeepImports,
        )
        .len(),
        1
    );

    // rn-no-deprecated-modules
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"import { AsyncStorage } from "react-native";"#,
            RuleId::RnNoDeprecatedModules,
        )
        .len(),
        1
    );

    // rn-no-dimensions-get
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Dimensions } from "react-native";
            export function App() {
                const { width } = Dimensions.get("window");
                return null;
            }
            "#,
            RuleId::RnNoDimensionsGet,
        )
        .len(),
        1
    );

    // rn-no-falsy-and-render
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { View, Text } from "react-native";
            export function App({ items }: { items: any[] }) {
                return <View>{items.length && <Text>Has items</Text>}</View>;
            }
            "#,
            RuleId::RnNoFalsyAndRender,
        )
        .len(),
        1
    );

    // rn-no-image-children
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { Image, Text } from "react-native";
            export function App({ src }: any) {
                return <Image source={src}><Text>Caption</Text></Image>;
            }
            "#,
            RuleId::RnNoImageChildren,
        )
        .len(),
        1
    );

    // rn-no-inline-flatlist-renderitem & rn-no-inline-object-in-list-item
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { FlatList, View } from "react-native";
            export function App({ items }: any) {
                return <FlatList data={items} renderItem={({ item }) => <View style={{ padding: 8 }} />} />;
            }
            "#,
            RuleId::RnNoInlineFlatlistRenderitem,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"
            import { FlatList, View } from "react-native";
            export function App({ items }: any) {
                return <FlatList data={items} renderItem={({ item }) => <View style={{ padding: 8 }} />} />;
            }
            "#,
            RuleId::RnNoInlineObjectInListItem,
        )
        .len(),
        1
    );

    // rn-no-legacy-expo-packages
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"import { Audio } from "expo-av";"#,
            RuleId::RnNoLegacyExpoPackages,
        )
        .len(),
        1
    );

    // rn-no-non-native-navigator
    assert_eq!(
        run_rule(
            "src/Nav.tsx",
            r#"import { createStackNavigator } from "@react-navigation/stack";"#,
            RuleId::RnNoNonNativeNavigator,
        )
        .len(),
        1
    );

    // rn-no-panresponder
    assert_eq!(
        run_rule(
            "src/Gesture.tsx",
            r#"import { PanResponder } from "react-native";"#,
            RuleId::RnNoPanresponder,
        )
        .len(),
        1
    );

    // rn-no-renderitem-key
    assert_eq!(
        run_rule(
            "src/List.tsx",
            r#"
            import { FlatList, View } from "react-native";
            export function List({ items }: any) {
                return <FlatList data={items} renderItem={({ item }) => <View key={item.id} />} />;
            }
            "#,
            RuleId::RnNoRenderitemKey,
        )
        .len(),
        1
    );

    // rn-no-scroll-state
    assert_eq!(
        run_rule(
            "src/Scroll.tsx",
            r#"
            import { useState } from "react";
            import { ScrollView } from "react-native";
            export function Scroll() {
                const [offset, setOffset] = useState(0);
                return <ScrollView onScroll={(e) => setOffset(e.nativeEvent.contentOffset.y)} />;
            }
            "#,
            RuleId::RnNoScrollState,
        )
        .len(),
        1
    );

    // rn-no-scrollview-mapped-list
    assert_eq!(
        run_rule(
            "src/Scroll.tsx",
            r#"
            import { ScrollView, View } from "react-native";
            export function Scroll({ items }: { items: any[] }) {
                return <ScrollView>{items.map((item) => <View key={item.id} />)}</ScrollView>;
            }
            "#,
            RuleId::RnNoScrollviewMappedList,
        )
        .len(),
        1
    );

    // rn-platform-shaking-use-direct-import
    assert_eq!(
        run_rule(
            "src/PlatformCheck.tsx",
            r#"
            import * as RN from "react-native";
            export const isIos = RN.Platform.OS === "ios";
            "#,
            RuleId::RnPlatformShakingUseDirectImport,
        )
        .len(),
        1
    );

    // rn-prefer-pressable-over-gesture-detector
    assert_eq!(
        run_rule(
            "src/TapItem.tsx",
            r#"
            import { Gesture, GestureDetector } from "react-native-gesture-handler";
            import { View } from "react-native";
            export function TapItem({ onTap }: any) {
                const tap = Gesture.Tap().onEnd(onTap);
                return <GestureDetector gesture={tap}><View /></GestureDetector>;
            }
            "#,
            RuleId::RnPreferPressableOverGestureDetector,
        )
        .len(),
        1
    );

    // rn-prefer-pressable
    assert_eq!(
        run_rule(
            "src/Btn.tsx",
            r#"import { TouchableOpacity } from "react-native";"#,
            RuleId::RnPreferPressable,
        )
        .len(),
        1
    );

    // rn-pressable-shared-value-mutation
    assert_eq!(
        run_rule(
            "src/Btn.tsx",
            r#"
            import { Pressable } from "react-native";
            import { useSharedValue, withSpring } from "react-native-reanimated";
            export function Btn() {
                const scale = useSharedValue(1);
                return <Pressable onPressIn={() => { scale.value = withSpring(0.95); }} />;
            }
            "#,
            RuleId::RnPressableSharedValueMutation,
        )
        .len(),
        1
    );

    // Reanimated 4 migration rules
    assert_eq!(
        run_rule(
            "src/Anim4.tsx",
            r#"
            import { withSpring, useAnimatedGestureHandler, runOnJS } from "react-native-reanimated";
            export function Anim4(cb: any) {
                const anim = withSpring(1, { restSpeedThreshold: 0.01 });
                const handler = useAnimatedGestureHandler({});
                runOnJS(cb)();
                return { anim, handler };
            }
            "#,
            RuleId::RnReanimated4NoLegacySpringThresholds,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/Anim4.tsx",
            r#"
            import { useAnimatedGestureHandler } from "react-native-reanimated";
            export const h = useAnimatedGestureHandler({});
            "#,
            RuleId::RnReanimated4NoRemovedApi,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/Anim4.tsx",
            r#"
            import { runOnJS } from "react-native-reanimated";
            export const run = (fn: any) => runOnJS(fn)();
            "#,
            RuleId::RnReanimated4UseWorkletsScheduler,
        )
        .len(),
        1
    );
}

#[test]
fn react_native_and_expo_project_checks_suite() {
    // 1. React Native project checks (metro preset, builder-bob, babel plugin order, android release shrinking)
    let rn_project_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "name": "my-rn-lib",
                    "react-native-builder-bob": { "source": "src", "output": "lib" },
                    "dependencies": {
                        "react": "19.0.0",
                        "react-native": "0.76.0",
                        "react-native-reanimated": "^4.0.0"
                    },
                    "devDependencies": {
                        "babel-plugin-react-compiler": "1.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("babel.config.js"),
                r#"
                module.exports = {
                    presets: ['module:metro-react-native-babel-preset'],
                    plugins: [
                        'react-native-reanimated/plugin',
                        'babel-plugin-react-compiler',
                        'react-native-worklets/plugin',
                        'other-plugin'
                    ],
                };
                "#
                .to_string(),
            ),
            (
                PathBuf::from("android/app/build.gradle"),
                r#"
                android {
                    buildTypes {
                        release {
                            minifyEnabled false
                            shrinkResources false
                        }
                    }
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/index.tsx"),
                r#"export const App = () => null;"#.to_string(),
            ),
        ],
        None,
    );
    let rn_rules: Vec<RuleId> = rn_project_report
        .diagnostics
        .iter()
        .map(|d| d.rule)
        .collect();
    for expected in [
        RuleId::RnNoMetroBabelPreset,
        RuleId::RnLibraryReactInDependencies,
        RuleId::RnReactCompilerPluginFirst,
        RuleId::RnReanimatedWorkletsPluginLast,
        RuleId::RnAndroidReleaseShrinkingDisabled,
    ] {
        assert!(
            rn_rules.contains(&expected),
            "Expected RN project rule {expected:?}, got: {rn_rules:#?}"
        );
    }

    // 2. Expo project checks (unimodules, cli deps, redundant deps, overrides, router+nav, vector icons,
    //    package.json conflict, lockfile, metro config, app.json newArchEnabled & disableAntiBrickingMeasures)
    let expo_project_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "name": "expo-router",
                    "scripts": { "expo": "expo start" },
                    "dependencies": {
                        "react": "19.0.0",
                        "react-native": "0.79.0",
                        "expo": "~56.0.0",
                        "expo-router": "~4.0.0",
                        "@react-navigation/native": "^7.0.0",
                        "@react-native-vector-icons/common": "^12.0.0",
                        "@expo/vector-icons": "^14.0.0",
                        "@unimodules/core": "^7.0.0",
                        "expo-modules-core": "~1.0.0",
                        "react-native-reanimated": "~4.0.0"
                    },
                    "devDependencies": {
                        "expo-cli": "^6.0.0"
                    },
                    "overrides": {
                        "metro": "0.80.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("app.json"),
                r#"{
                    "expo": {
                        "name": "my-app",
                        "newArchEnabled": false,
                        "updates": {
                            "disableAntiBrickingMeasures": true
                        }
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("metro.config.js"),
                r#"module.exports = { resolver: {} };"#.to_string(),
            ),
            (
                PathBuf::from("src/App.tsx"),
                r#"export const App = () => null;"#.to_string(),
            ),
        ],
        None,
    );
    let expo_rules: Vec<RuleId> = expo_project_report
        .diagnostics
        .iter()
        .map(|d| d.rule)
        .collect();
    for expected in [
        RuleId::ExpoNoUnimodulesPackages,
        RuleId::ExpoNoCliDependencies,
        RuleId::ExpoNoRedundantDependency,
        RuleId::ExpoNoConflictingDependencyOverride,
        RuleId::ExpoRouterNoReactNavigation,
        RuleId::ExpoVectorIconsConflict,
        RuleId::ExpoPackageJsonConflict,
        RuleId::ExpoLockfile,
        RuleId::ExpoMetroConfig,
        RuleId::ExpoReanimatedV4RequiresNewArch,
        RuleId::ExpoUpdatesNoUnsafeProductionConfig,
    ] {
        assert!(
            expo_rules.contains(&expected),
            "Expected Expo project rule {expected:?}, got: {expo_rules:#?}"
        );
    }
}

#[test]
fn state_stores_rules_suite() {
    // 1. zustand-no-mutating-state
    assert_eq!(
        run_rule(
            "src/store.ts",
            r#"
            import { create } from "zustand";
            export const useTodoStore = create((set) => ({
                todos: [] as string[],
                addTodo: (text: string) =>
                    set((state: any) => {
                        state.todos.push(text);
                        return state;
                    }),
            }));
            "#,
            RuleId::ZustandNoMutatingState,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/store.ts",
            r#"
            import { create } from "zustand";
            export const useTodoStore = create((set) => ({
                todos: [] as string[],
                addTodo: (text: string) =>
                    set((state: any) => ({ todos: [...state.todos, text] })),
            }));
            "#,
            RuleId::ZustandNoMutatingState,
        )
        .is_empty()
    );

    // 2. zustand-no-fresh-selector-result
    assert_eq!(
        run_rule(
            "src/View.tsx",
            r#"
            import { create } from "zustand";
            const useUserStore = create(() => ({ name: "Ada", age: 30 }));
            export function View() {
                const { name, age } = useUserStore((s) => ({ name: s.name, age: s.age }));
                return <div>{name} {age}</div>;
            }
            "#,
            RuleId::ZustandNoFreshSelectorResult,
        )
        .len(),
        1
    );
    // Valid: wrapped in useShallow
    assert!(
        run_rule(
            "src/View.tsx",
            r#"
            import { create } from "zustand";
            import { useShallow } from "zustand/react/shallow";
            const useUserStore = create(() => ({ name: "Ada", age: 30 }));
            export function View() {
                const { name, age } = useUserStore(useShallow((s) => ({ name: s.name, age: s.age })));
                return <div>{name} {age}</div>;
            }
            "#,
            RuleId::ZustandNoFreshSelectorResult,
        )
        .is_empty()
    );

    // 3. zustand-no-whole-store-destructure
    assert_eq!(
        run_rule(
            "src/View.tsx",
            r#"
            export function View() {
                const { count } = useCounterStore();
                return <div>{count}</div>;
            }
            "#,
            RuleId::ZustandNoWholeStoreDestructure,
        )
        .len(),
        1
    );

    // 4. zustand-no-get-during-initialization
    assert_eq!(
        run_rule(
            "src/store.ts",
            r#"
            import { create } from "zustand";
            export const useStore = create((set, get: any) => ({
                base: 10,
                doubled: get().base * 2,
            }));
            "#,
            RuleId::ZustandNoGetDuringInitialization,
        )
        .len(),
        1
    );
    // Valid: get() inside deferred action method
    assert!(
        run_rule(
            "src/store.ts",
            r#"
            import { create } from "zustand";
            export const useStore = create((set, get: any) => ({
                base: 10,
                getDoubled: () => get().base * 2,
            }));
            "#,
            RuleId::ZustandNoGetDuringInitialization,
        )
        .is_empty()
    );

    // 5. jotai-select-atom-in-render-body
    assert_eq!(
        run_rule(
            "src/Counter.tsx",
            r#"
            import { useAtomValue } from "jotai";
            import { selectAtom } from "jotai/utils";
            export function Counter({ baseAtom }: any) {
                const countAtom = selectAtom(baseAtom, (s: any) => s.count);
                const count = useAtomValue(countAtom);
                return <div>{count}</div>;
            }
            "#,
            RuleId::JotaiSelectAtomInRenderBody,
        )
        .len(),
        1
    );
    // Valid: wrapped in useMemo
    assert!(
        run_rule(
            "src/Counter.tsx",
            r#"
            import { useMemo } from "react";
            import { useAtomValue } from "jotai";
            import { selectAtom } from "jotai/utils";
            export function Counter({ baseAtom }: any) {
                const countAtom = useMemo(() => selectAtom(baseAtom, (s: any) => s.count), [baseAtom]);
                const count = useAtomValue(countAtom);
                return <div>{count}</div>;
            }
            "#,
            RuleId::JotaiSelectAtomInRenderBody,
        )
        .is_empty()
    );

    // 6. jotai-derived-atom-returns-fresh-object
    assert_eq!(
        run_rule(
            "src/atoms.ts",
            r#"
            import { atom } from "jotai";
            const rawAtom = atom({ a: 1, b: 2 });
            export const summaryAtom = atom((get) => ({
                a: get(rawAtom).a,
                b: get(rawAtom).b,
            }));
            "#,
            RuleId::JotaiDerivedAtomReturnsFreshObject,
        )
        .len(),
        1
    );
    // Valid: primitive derived atom
    assert!(
        run_rule(
            "src/atoms.ts",
            r#"
            import { atom } from "jotai";
            const rawAtom = atom({ a: 1, b: 2 });
            export const aAtom = atom((get) => get(rawAtom).a);
            "#,
            RuleId::JotaiDerivedAtomReturnsFreshObject,
        )
        .is_empty()
    );

    // 7. jotai-tq-use-raw-query-atom
    assert_eq!(
        run_rule(
            "src/Users.tsx",
            r#"
            import { useAtomValue } from "jotai";
            import { atomWithQuery } from "jotai-tanstack-query";
            const usersQueryAtom = atomWithQuery(() => ({ queryKey: ["users"], queryFn: fetchUsers }));
            export function Users() {
                const { data, isLoading } = useAtomValue(usersQueryAtom);
                return <div>{isLoading ? "..." : data}</div>;
            }
            "#,
            RuleId::JotaiTqUseRawQueryAtom,
        )
        .len(),
        1
    );

    // 8. mobx-reaction-disposer-discarded
    assert_eq!(
        run_rule(
            "src/View.tsx",
            r#"
            import { useEffect } from "react";
            import { autorun } from "mobx";
            export function View({ store }: any) {
                useEffect(() => {
                    autorun(() => console.log(store.count));
                }, [store]);
                return null;
            }
            "#,
            RuleId::MobxReactionDisposerDiscarded,
        )
        .len(),
        1
    );

    // 9. mobx-no-observer-wrapped-memo
    assert_eq!(
        run_rule(
            "src/View.tsx",
            r#"
            import { memo } from "react";
            import { observer } from "mobx-react-lite";
            export const View = observer(memo(() => <div />));
            "#,
            RuleId::MobxNoObserverWrappedMemo,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/View.tsx",
            r#"
            import { memo } from "react";
            import { observer } from "mobx-react-lite";
            export const View = memo(observer(() => <div />));
            "#,
            RuleId::MobxNoObserverWrappedMemo,
        )
        .is_empty()
    );

    // 10. mobx-no-make-auto-observable-in-inheritance
    assert_eq!(
        run_rule(
            "src/Store.ts",
            r#"
            import { makeAutoObservable } from "mobx";
            class BaseStore {}
            export class ChildStore extends BaseStore {
                count = 0;
                constructor() {
                    super();
                    makeAutoObservable(this);
                }
            }
            "#,
            RuleId::MobxNoMakeAutoObservableInInheritance,
        )
        .len(),
        1
    );

    // 11. valtio-no-proxy-read-in-render
    assert_eq!(
        run_rule(
            "src/Counter.tsx",
            r#"
            import { proxy, useSnapshot } from "valtio";
            const state = proxy({ count: 0 });
            export function Counter() {
                const snap = useSnapshot(state);
                return <div>{state.count} / {snap.count}</div>;
            }
            "#,
            RuleId::ValtioNoProxyReadInRender,
        )
        .len(),
        1
    );

    // 12. valtio-no-snapshot-in-callback
    assert_eq!(
        run_rule(
            "src/Counter.tsx",
            r#"
            import { proxy, useSnapshot } from "valtio";
            const state = proxy({ count: 0 });
            export function Counter() {
                const snap = useSnapshot(state);
                return <button onClick={() => console.log(snap.count)}>{snap.count}</button>;
            }
            "#,
            RuleId::ValtioNoSnapshotInCallback,
        )
        .len(),
        1
    );
}

#[test]
fn preact_ink_and_zod_rules_suite() {
    // --- Preact (6 rules) ---
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"import { useState } from "react";"#,
            RuleId::PreactNoReactImport,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/App.tsx",
            r#"import { useState, useEffect } from "react";"#,
            RuleId::PreactNoReactHooksImport,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/Form.tsx",
            r#"
            export function Form({ onUpdate }: any) {
                return <input type="text" onChange={onUpdate} />;
            }
            "#,
            RuleId::PreactPreferOninput,
        )
        .len(),
        1
    );
    // Valid: checkbox input is exempt from preact-prefer-oninput
    assert!(
        run_rule(
            "src/Form.tsx",
            r#"
            export function Form({ onToggle }: any) {
                return <input type="checkbox" onChange={onToggle} />;
            }
            "#,
            RuleId::PreactPreferOninput,
        )
        .is_empty()
    );
    assert_eq!(
        run_rule(
            "src/Row.tsx",
            r#"
            export function Row({ onOpen }: any) {
                return <div onDoubleClick={onOpen} />;
            }
            "#,
            RuleId::PreactPreferOndblclick,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/Card.tsx",
            r#"
            import { Component } from "preact";
            export class Card extends Component {
                render(props: any, state: any) {
                    return <div>{props.title}</div>;
                }
            }
            "#,
            RuleId::PreactNoRenderArguments,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/List.tsx",
            r#"
            export function List({ children }: any) {
                return <div>{children.length}</div>;
            }
            "#,
            RuleId::PreactNoChildrenLength,
        )
        .len(),
        1
    );

    // --- Ink (all 20 active + 2 retired = 22 rules, including cross-file ink-no-raw-text) ---
    let ink_cross_file = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "name": "cli-app", "dependencies": { "react": "19.0.0", "ink": "5.0.0" } }"#
                    .to_string(),
            ),
            (
                PathBuf::from("src/panel.tsx"),
                r#"import { Box } from "ink"; export const Panel = ({ children }: any) => <Box>{children}</Box>;"#.to_string(),
            ),
            (
                PathBuf::from("src/label.tsx"),
                r#"import { Text } from "ink"; export const Label = ({ children }: any) => <Text>{children}</Text>;"#.to_string(),
            ),
            (
                PathBuf::from("src/app.tsx"),
                r#"
                import { Panel } from "./panel";
                import { Label } from "./label";
                export const Unsafe = () => <Panel>bad</Panel>;
                export const Safe = () => <Label>good</Label>;
                export const Shadowed = (Panel: any) => <Panel>shadowed is ok</Panel>;
                "#
                .to_string(),
            ),
        ],
        Some(&[RuleId::InkNoRawText]),
    );
    assert_eq!(
        ink_cross_file.diagnostics.len(),
        1,
        "Expected 1 cross-file ink-no-raw-text diagnostic on <Panel>bad</Panel>, got: {:#?}",
        ink_cross_file.diagnostics
    );

    let ink_cases: &[(RuleId, &str, &str)] = &[
        (
            RuleId::InkNoLayoutInsideText,
            r#"import { Text, Box } from "ink"; const App = () => <Text><><Box /></></Text>;"#,
            r#"import { Text, Box } from "ink"; const App = () => <Box><Text>ok</Text></Box>;"#,
        ),
        (
            RuleId::InkStaticRequiresKey,
            r#"import { Static, Text } from "ink"; const App = ({ items }: any) => <Static items={items}>{(item: any) => <Text>{item}</Text>}</Static>;"#,
            r#"import { Static, Text } from "ink"; const App = ({ items }: any) => <Static items={items}>{(item: any, idx: number) => <Text key={idx}>{item}</Text>}</Static>;"#,
        ),
        (
            RuleId::InkNoMeasureElementInRender,
            r#"import { measureElement as measure, Text } from "ink"; const App = ({ node }: any) => { measure(node); return <Text />; };"#,
            r#"import { measureElement, Text } from "ink"; import { useLayoutEffect } from "react"; const App = ({ node }: any) => { useLayoutEffect(() => measureElement(node), [node]); return <Text />; };"#,
        ),
        (
            RuleId::InkNoFocusInRender,
            r#"import { useFocusManager, Text } from "ink"; const App = () => { const manager = useFocusManager(); manager.focus("name"); return <Text />; };"#,
            r#"import { useFocusManager, useInput, Text } from "ink"; const App = () => { const manager = useFocusManager(); useInput(() => manager.focus("name")); return <Text />; };"#,
        ),
        (
            RuleId::InkNoDomRouter,
            r#"import { Box } from "ink"; import { Link } from "react-router-dom"; const App = () => <Box><Link to="/" /></Box>;"#,
            r#"import { Box } from "ink"; import { MemoryRouter, Route, Routes } from "react-router"; const App = () => <MemoryRouter><Box><Routes><Route path="/" element={null} /></Routes></Box></MemoryRouter>;"#,
        ),
        (
            RuleId::InkNoDirectRawMode,
            r#"import { useStdin, Text } from "ink"; const App = () => { const { setRawMode } = useStdin(); setRawMode(true); return <Text />; };"#,
            r#"import { useInput, Text } from "ink"; const App = () => { useInput(() => {}); return <Text />; };"#,
        ),
        (
            RuleId::InkUseSuspendTerminal,
            r#"import { useInput } from "ink"; import { spawn } from "node:child_process"; const App = () => { useInput(() => spawn("vim", [], { stdio: "inherit" })); return null; };"#,
            r#"import { useApp, useInput } from "ink"; import { spawn } from "node:child_process"; const App = () => { const { suspendTerminal } = useApp(); useInput(() => suspendTerminal(() => spawn("vim", [], { stdio: "inherit" }))); return null; };"#,
        ),
        (
            RuleId::InkStaticIsAppendOnly,
            r#"import { Static } from "ink"; const App = ({ items }: any) => <Static items={items.toReversed()}>{(item: any) => null}</Static>;"#,
            r#"import { Static } from "ink"; const App = ({ items }: any) => <Static items={items}>{(item: any) => null}</Static>;"#,
        ),
        (
            RuleId::InkNoMultipleStatic,
            r#"import { Static } from "ink"; const App = () => <><Static items={[]} /> <Static items={[]} /></>;"#,
            r#"import { Static } from "ink"; const App = () => <Static items={[]} />;"#,
        ),
        (
            RuleId::InkNoRepeatedRender,
            r#"import { render as mount } from "ink"; mount(null); mount(null);"#,
            r#"import { render } from "ink"; const instance = render(null); instance.rerender(null);"#,
        ),
        (
            RuleId::InkNoBareProcessExit,
            r#"import { useInput } from "ink"; const App = () => { useInput(() => process.exit(0)); return null; };"#,
            r#"import { useApp, useInput } from "ink"; const App = () => { const { exit } = useApp(); useInput(() => exit()); return null; };"#,
        ),
        (
            RuleId::InkCtrlCHandlerRequiresExitOption,
            r#"import { render, useInput } from "ink"; const App = () => { useInput((input, key) => { if (key.ctrl && input === "c") work(); }); return null; }; render(<App />);"#,
            r#"import { render, useInput } from "ink"; const App = () => { useInput((input, key) => { if (key.ctrl && input === "c") work(); }); return null; }; render(<App />, { exitOnCtrlC: false });"#,
        ),
        (
            RuleId::InkNoLiveHooksInRenderToString,
            r#"import { renderToString, useInput, Text } from "ink"; const App = () => { useInput(() => {}); return <Text />; }; renderToString(<App />);"#,
            r#"import { renderToString, Text } from "ink"; const App = () => <Text>snapshot</Text>; renderToString(<App />);"#,
        ),
        (
            RuleId::InkUseStringWidthForCursor,
            r#"import { useCursor } from "ink"; const App = ({ label }: any) => { const cursor = useCursor(); cursor.setCursorPosition({ x: label.length, y: 0 }); return null; };"#,
            r#"import { useCursor } from "ink"; import stringWidth from "string-width"; const App = ({ label }: any) => { const cursor = useCursor(); cursor.setCursorPosition({ x: stringWidth(label), y: 0 }); return null; };"#,
        ),
        (
            RuleId::InkUseReactiveWindowSize,
            r#"import { Text } from "ink"; const App = () => <Text>{process.stdout.columns}</Text>;"#,
            r#"import { useWindowSize, Text } from "ink"; const App = () => { const { columns } = useWindowSize(); return <Text>{columns}</Text>; };"#,
        ),
        (
            RuleId::InkPreferUsePaste,
            r#"import { useInput } from "ink"; const App = () => { useInput((input) => { if (input.includes("\n")) paste(input); }); return null; };"#,
            r#"import { usePaste } from "ink"; const App = () => { usePaste((input) => paste(input)); return null; };"#,
        ),
        (
            RuleId::InkNoDomHostElements,
            r#"import { Box } from "ink"; const App = () => <Box><div /></Box>;"#,
            r#"import { Box, Text } from "ink"; const App = () => <Box><Text>ok</Text></Box>;"#,
        ),
        (
            RuleId::InkValidAriaSemantics,
            r#"import { Text } from "ink"; const App = () => <Text aria-role="dialog">open</Text>;"#,
            r#"import { Box, Text } from "ink"; const App = () => <Box aria-role="button" aria-label="Open"><Text>open</Text></Box>;"#,
        ),
        (
            RuleId::InkPreferUseAnimation,
            r#"import { useEffect, useState } from "react"; import { Text } from "ink"; const App = () => { const [frame, setFrame] = useState(0); useEffect(() => { const timer = setInterval(() => setFrame((value) => value + 1), 80); return () => clearInterval(timer); }, []); return <Text>{frame}</Text>; };"#,
            r#"import { useAnimation, Text } from "ink"; const App = () => { const { frame } = useAnimation({ interval: 80 }); return <Text>{frame}</Text>; };"#,
        ),
    ];
    for &(rule, invalid_src, valid_src) in ink_cases {
        assert_eq!(
            run_rule("src/cli.tsx", invalid_src, rule).len(),
            1,
            "Expected invalid Ink case for {rule:?} to report 1 diagnostic"
        );
        assert!(
            run_rule("src/cli.tsx", valid_src, rule).is_empty(),
            "Expected valid Ink case for {rule:?} to report 0 diagnostics"
        );
    }

    // --- Zod v4 (4 rules) ---
    assert_eq!(
        run_rule(
            "src/schema.ts",
            r#"
            import { z } from "zod";
            export const emailSchema = z.string().email();
            "#,
            RuleId::ZodV4PreferTopLevelStringFormats,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/schema.ts",
            r#"
            import { z } from "zod";
            export const userSchema = z.object({ id: z.string() }).strict();
            export const mapSchema = z.record(z.string());
            "#,
            RuleId::ZodV4NoDeprecatedSchemaApis,
        )
        .len(),
        2
    );
    assert_eq!(
        run_rule(
            "src/schema.ts",
            r#"
            import { z } from "zod";
            export const nameSchema = z.string({ required_error: "Required" });
            "#,
            RuleId::ZodV4NoDeprecatedErrorCustomization,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/schema.ts",
            r#"
            import { z, ZodError } from "zod";
            export const err = ZodError.create([]);
            export const formatted = (new ZodError([])).format();
            "#,
            RuleId::ZodV4NoDeprecatedErrorApis,
        )
        .len(),
        2
    );
}
