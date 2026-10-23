//! Integration tests for Ticket #02:
//! Wiring all 53 previously metadata-only registered rules across:
//! - Group A: UI Design heuristics (`src/rules/design.rs`)
//! - Group B: React Performance, Motion & JS Performance (`src/rules/performance.rs`, `src/rules/js_performance.rs`)
//! - Group C: Ecosystem rules (`src/rules/tanstack.rs`, `src/rules/react_native.rs`, `src/rules/ecosystem_ui.rs`)
//! - Group D: State & Effects (`src/rules/state_and_effects.rs`)
//! - Group E: React Builtins & Class Lifecycles (`src/rules/react_builtins.rs`)
//! - Group F: Correctness (`src/rules/correctness.rs`)
//! - Group G: Architecture & Complexity (`src/rules/architecture.rs`)
//!
//! Including Capability Gate activation and deterministic `Autofix` round-trips for
//! `jsx-no-useless-fragment`, `jsx-fragments`, and `js-tosorted-immutable`.

use std::path::Path;

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleId, RuleSeverityOverride,
    analyze_source, analyze_source_with_config, apply_patches_to_source,
};

fn run_rule(path: &str, source: &str, rule: RuleId) -> Vec<dotore::Diagnostic> {
    analyze_source(Path::new(path), source, Some(&[rule]))
}

#[test]
fn group_a_design_rules_detect_violations_and_preserve_adversarial_valid_cases() {
    let cases: &[(RuleId, &str, &str)] = &[
        (
            RuleId::NoCommonRootFont,
            r#"export const Page = () => <main className="font-sans" style={{ fontFamily: "Arial, sans-serif" }}>Content</main>;"#,
            r#"export const Page = () => <main style={{ fontFamily: "Instrument Sans, sans-serif" }}>Content</main>;"#,
        ),
        (
            RuleId::NoDefaultPurplePageGradient,
            r#"export const Page = () => <main className="bg-gradient-to-br from-purple-600 to-indigo-600">Hero</main>;"#,
            r#"export const Page = () => <main className="bg-slate-950 text-white">Hero</main>;"#,
        ),
        (
            RuleId::NoDefaultWarmPageSurface,
            r##"export const Page = () => <main style={{ backgroundColor: "#faf8f5" }}>Content</main>;"##,
            r##"export const Page = () => <main style={{ backgroundColor: "#ffffff" }}>Content</main>;"##,
        ),
        (
            RuleId::NoFullViewportCenteredHero,
            r#"export const Hero = () => <section className="min-h-screen flex items-center justify-center text-center"><h1>Welcome</h1></section>;"#,
            r#"export const Hero = () => <section className="py-24"><h1 className="text-left">Welcome</h1></section>;"#,
        ),
        (
            RuleId::NoHeroEyebrowChip,
            r#"export const Hero = () => <section><span className="rounded-full px-3 py-1 text-xs uppercase">Introducing v2</span><h1>Fast analytics</h1></section>;"#,
            r#"export const Hero = () => <section><h1>Fast analytics</h1><p>Real-time insights</p></section>;"#,
        ),
        (
            RuleId::NoIconTileHeadingStack,
            r#"export const FeatureCard = () => <article className="rounded-xl border p-6"><div className="w-10 h-10 rounded-lg bg-blue-500"><svg /></div><h3>Fast</h3><p>Details</p></article>;"#,
            r#"export const FeatureCard = () => <article className="rounded-xl border p-6"><h3>Fast</h3><p>Details</p></article>;"#,
        ),
        (
            RuleId::NoItalicSerifDisplayHeading,
            r#"export const Hero = () => <h1 className="font-serif italic text-5xl">Crafted with care</h1>;"#,
            r#"export const Hero = () => <h1 className="font-serif text-5xl">Crafted with care</h1>;"#,
        ),
        (
            RuleId::NoMonotonousPageSpacing,
            r#"export const Page = () => <main><section className="py-16">A</section><section className="py-16">B</section><section className="py-16">C</section><section className="py-16">D</section></main>;"#,
            r#"export const Page = () => <main><section className="py-24">A</section><section className="py-12">B</section><section className="py-16">C</section></main>;"#,
        ),
        (
            RuleId::NoNumberedSectionMarkers,
            r#"export const Section = () => <section><span className="font-mono text-xs">01</span><h2>Overview</h2></section>;"#,
            r#"export const Section = () => <section><h2>Overview</h2><p>99 items available</p></section>;"#,
        ),
        (
            RuleId::NoPureBlackBackground,
            r#"export const Page = () => <div className="bg-black text-white">Dark surface</div>;"#,
            r#"export const Page = () => <div className="bg-zinc-950 text-white">Dark surface</div>;"#,
        ),
    ];

    for &(rule, invalid_code, valid_code) in cases {
        let invalid_diags = run_rule("src/Page.tsx", invalid_code, rule);
        assert_eq!(
            invalid_diags.len(),
            1,
            "Expected 1 diagnostic for {rule:?} on invalid code, got: {invalid_diags:#?}"
        );
        assert_eq!(invalid_diags[0].rule, rule);

        let valid_diags = run_rule("src/Page.tsx", valid_code, rule);
        assert!(
            valid_diags.is_empty(),
            "Expected 0 diagnostics for {rule:?} on valid code, got: {valid_diags:#?}"
        );
    }
}

#[test]
fn group_b_performance_and_js_performance_rules_and_tosorted_autofix() {
    // 1. no-scale-from-zero
    assert_eq!(
        run_rule(
            "src/Modal.tsx",
            r#"import { motion } from "framer-motion"; export const Modal = () => <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} />;"#,
            RuleId::NoScaleFromZero,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Modal.tsx",
            r#"import { motion } from "framer-motion"; export const Modal = () => <motion.div initial={{ scale: 0.95 }} animate={{ scale: 1 }} />;"#,
            RuleId::NoScaleFromZero,
        )
        .is_empty()
    );
    assert!(
        RuleId::NoScaleFromZero
            .metadata()
            .tags
            .contains(&dotore::RuleTag::Design)
    );
    assert_eq!(
        RuleId::parse("design/no-scale-from-zero"),
        Some(RuleId::NoScaleFromZero)
    );
    assert!(dotore::design_rule_ids().contains(&RuleId::NoScaleFromZero));

    // 2. rendering-animate-svg-wrapper
    assert_eq!(
        run_rule(
            "src/Icon.tsx",
            r#"import { motion } from "framer-motion"; export const Icon = () => <motion.svg animate={{ rotate: 180 }} />;"#,
            RuleId::RenderingAnimateSvgWrapper,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Icon.tsx",
            r#"import { motion } from "framer-motion"; export const Icon = () => <motion.div animate={{ rotate: 180 }}><svg /></motion.div>;"#,
            RuleId::RenderingAnimateSvgWrapper,
        )
        .is_empty()
    );

    // 3. rendering-usetransition-loading
    assert_eq!(
        run_rule(
            "src/Search.tsx",
            r#"
            import { useState, useTransition } from "react";
            export function Search() {
                const [isPending, startTransition] = useTransition();
                const [isLoading, setIsLoading] = useState(false);
                return <div>{isPending || isLoading ? "Loading" : "Ready"}</div>;
            }
            "#,
            RuleId::RenderingUsetransitionLoading,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Search.tsx",
            r#"
            import { useTransition } from "react";
            export function Search() {
                const [isPending, startTransition] = useTransition();
                return <div onClick={() => startTransition(() => {})}>{isPending ? "Loading" : "Ready"}</div>;
            }
            "#,
            RuleId::RenderingUsetransitionLoading,
        )
        .is_empty()
    );
    assert!(
        run_rule(
            "src/Search.tsx",
            r#"
            import { useState } from "react";
            export function OrdinaryFetchComponent() {
                const [isLoading, setIsLoading] = useState(false);
                return <button onClick={() => setIsLoading(true)}>{isLoading ? "Loading" : "Ready"}</button>;
            }
            "#,
            RuleId::RenderingUsetransitionLoading,
        )
        .is_empty()
    );

    // 4. js-tosorted-immutable with deterministic Autofix round-trip
    let tosorted_src = "export const sortItems = (items: number[], names: string[]) => {\n  const a = [...items].sort((x, y) => x - y);\n  const b = names.slice().reverse();\n  return { a, b };\n};\n";
    let tosorted_diags = run_rule("src/sort.ts", tosorted_src, RuleId::JsTosortedImmutable);
    assert_eq!(tosorted_diags.len(), 2);
    assert_eq!(
        RuleId::JsTosortedImmutable.metadata().default_tier,
        PrescriptionTier::Autofix
    );
    assert!(
        tosorted_diags
            .iter()
            .all(|d| d.tier == PrescriptionTier::Autofix && d.autofix.is_some())
    );
    let (rewritten_tosorted, descs) = apply_patches_to_source(tosorted_src, &tosorted_diags);
    assert_eq!(descs.len(), 2);
    assert!(rewritten_tosorted.contains("items.toSorted((x, y) => x - y)"));
    assert!(rewritten_tosorted.contains("names.toReversed()"));
    assert!(
        run_rule("src/sort.ts", &rewritten_tosorted, RuleId::JsTosortedImmutable).is_empty(),
        "Expected 0 diagnostics after js-tosorted-immutable autofix"
    );

    // 5. js-early-exit
    assert_eq!(
        run_rule(
            "src/process.ts",
            r#"
            export function processOrder(order: any) {
                if (order) {
                    if (order.items) {
                        if (order.items.length > 0) {
                            return order.items[0];
                        }
                    }
                }
                return null;
            }
            "#,
            RuleId::JsEarlyExit,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/process.ts",
            r#"
            export function processOrder(order: any) {
                if (!order?.items?.length) return null;
                return order.items[0];
            }
            "#,
            RuleId::JsEarlyExit,
        )
        .is_empty()
    );

    // 6. client-localstorage-no-version
    assert_eq!(
        run_rule(
            "src/storage.ts",
            r#"export const saveTheme = (t: string) => localStorage.setItem("user-prefs", t);"#,
            RuleId::ClientLocalstorageNoVersion,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/storage.ts",
            r#"export const saveTheme = (t: string) => localStorage.setItem("user-prefs:v1", t);"#,
            RuleId::ClientLocalstorageNoVersion,
        )
        .is_empty()
    );
}

#[test]
fn group_c_ecosystem_stub_rules_and_capability_gate_enforcement() {
    // 1. tanstack-start-no-direct-fetch-in-loader
    let ts_invalid = r#"
        import { createFileRoute } from "@tanstack/react-router";
        export const Route = createFileRoute("/posts")({
            loader: async () => {
                const res = await fetch("/api/posts");
                return res.json();
            },
        });
    "#;
    let ts_valid = r#"
        import { createFileRoute } from "@tanstack/react-router";
        export const Route = createFileRoute("/posts")({
            loader: async () => {
                return fetchPostsServerFn();
            },
        });
    "#;
    assert_eq!(
        run_rule(
            "src/routes/posts.tsx",
            ts_invalid,
            RuleId::TanstackStartNoDirectFetchInLoader
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/routes/posts.tsx",
            ts_valid,
            RuleId::TanstackStartNoDirectFetchInLoader
        )
        .is_empty()
    );

    // CapabilityGate test for TanstackStartNoDirectFetchInLoader
    let mut ts_cfg = DotoreConfig::default();
    ts_cfg.rules.insert(
        "tanstack-start-no-direct-fetch-in-loader".to_string(),
        RuleSeverityOverride::Warn,
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/routes/posts.tsx"),
            ts_invalid,
            &ts_cfg,
            &CapabilityGate::default_react(),
            None,
        )
        .is_empty(),
        "Plain React gate should not activate TanstackStart rule"
    );
    assert_eq!(
        analyze_source_with_config(
            Path::new("src/routes/posts.tsx"),
            ts_invalid,
            &ts_cfg,
            &CapabilityGate::with_capabilities([Capability::React, Capability::TanstackStart]),
            None,
        )
        .len(),
        1
    );

    // 2. React Native 5 rules
    let rn_cases: &[(RuleId, &str, &str)] = &[
        (
            RuleId::RnAnimateLayoutProperty,
            r#"
            import { useAnimatedStyle, withTiming } from "react-native-reanimated";
            export function Box({ expanded }: { expanded: boolean }) {
                const style = useAnimatedStyle(() => ({
                    width: withTiming(expanded ? 200 : 100),
                }));
                return null;
            }
            "#,
            r#"
            import { useAnimatedStyle, withTiming } from "react-native-reanimated";
            export function Box({ expanded }: { expanded: boolean }) {
                const style = useAnimatedStyle(() => ({
                    opacity: withTiming(expanded ? 1 : 0.5),
                }));
                return null;
            }
            "#,
        ),
        (
            RuleId::RnNoSetNativeProps,
            r#"
            export function ImperativeInput({ inputRef }: any) {
                const clear = () => inputRef.current.setNativeProps({ text: "" });
                return null;
            }
            "#,
            r#"
            export function DeclarativeInput({ value }: any) {
                return null;
            }
            "#,
        ),
        (
            RuleId::RnNoSingleElementStyleArray,
            r#"
            import { View } from "react-native";
            export const Card = ({ styles }: any) => <View style={[styles.card]} />;
            "#,
            r#"
            import { View } from "react-native";
            export const Card = ({ styles }: any) => <View style={[styles.card, styles.active]} />;
            "#,
        ),
        (
            RuleId::RnPreferContentInsetAdjustment,
            r#"
            import { SafeAreaView, ScrollView } from "react-native";
            export const Screen = () => <SafeAreaView><ScrollView /></SafeAreaView>;
            "#,
            r#"
            import { ScrollView } from "react-native";
            export const Screen = () => <ScrollView contentInsetAdjustmentBehavior="automatic" />;
            "#,
        ),
        (
            RuleId::RnPreferReanimated,
            r#"
            import { Animated } from "react-native";
            export const fade = (val: any) => Animated.timing(val, { toValue: 1, useNativeDriver: true });
            "#,
            r#"
            import { View } from "react-native";
            export const Box = () => <View />;
            "#,
        ),
    ];

    for &(rule, invalid_src, valid_src) in rn_cases {
        assert_eq!(
            run_rule("src/Screen.tsx", invalid_src, rule).len(),
            1,
            "Expected 1 diagnostic for {rule:?}"
        );
        assert!(
            run_rule("src/Screen.tsx", valid_src, rule).is_empty(),
            "Expected 0 diagnostics for {rule:?} on valid code"
        );
    }

    // 3. Ink 2 rules (`ink-newline-inside-text`, `ink-suspense-requires-concurrent`)
    assert_eq!(
        run_rule(
            "src/cli.tsx",
            r#"import { Box, Newline } from "ink"; export const Cli = () => <Box><Newline /></Box>;"#,
            RuleId::InkNewlineInsideText,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/cli.tsx",
            r#"import { Text, Newline } from "ink"; export const Cli = () => <Text>Line 1<Newline />Line 2</Text>;"#,
            RuleId::InkNewlineInsideText,
        )
        .is_empty()
    );

    assert_eq!(
        run_rule(
            "src/cli.tsx",
            r#"import { Suspense } from "react"; import { render, Text } from "ink"; const App = () => <Suspense fallback={<Text>Loading</Text>}><Text>Done</Text></Suspense>; render(<App />);"#,
            RuleId::InkSuspenseRequiresConcurrent,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/cli.tsx",
            r#"import { Suspense } from "react"; import { render, Text } from "ink"; const App = () => <Suspense fallback={<Text>Loading</Text>}><Text>Done</Text></Suspense>; render(<App />, { concurrent: true });"#,
            RuleId::InkSuspenseRequiresConcurrent,
        )
        .is_empty()
    );
}

#[test]
fn group_d_state_and_effects_rules_detect_violations_and_preserve_valid_cases() {
    // 1. no-stale-timer-ref
    assert_eq!(
        run_rule(
            "src/Timer.tsx",
            r#"
            import { useEffect } from "react";
            export function Timer() {
                useEffect(() => {
                    setTimeout(() => console.log("tick"), 1000);
                }, []);
                return <div />;
            }
            "#,
            RuleId::NoStaleTimerRef,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Timer.tsx",
            r#"
            import { useEffect, useRef } from "react";
            export function Timer() {
                const timerRef = useRef<any>(null);
                useEffect(() => {
                    timerRef.current = setTimeout(() => console.log("tick"), 1000);
                    return () => clearTimeout(timerRef.current);
                }, []);
                return <div />;
            }
            "#,
            RuleId::NoStaleTimerRef,
        )
        .is_empty()
    );

    // 2. no-unowned-async-error-clear
    assert_eq!(
        run_rule(
            "src/Loader.tsx",
            r#"
            import { useState } from "react";
            export function Loader() {
                const [error, setError] = useState<string | null>(null);
                async function handleLoad() {
                    setError(null);
                    await fetch("/api/data");
                }
                return <button onClick={handleLoad}>{error}</button>;
            }
            "#,
            RuleId::NoUnownedAsyncErrorClear,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Loader.tsx",
            r#"
            import { useState, useRef } from "react";
            export function Loader() {
                const [error, setError] = useState<string | null>(null);
                const reqIdRef = useRef(0);
                async function handleLoad() {
                    const id = ++reqIdRef.current;
                    if (id === reqIdRef.current) setError(null);
                    await fetch("/api/data");
                }
                return <button onClick={handleLoad}>{error}</button>;
            }
            "#,
            RuleId::NoUnownedAsyncErrorClear,
        )
        .is_empty()
    );

    // 3. prefer-use-effect-event
    assert_eq!(
        run_rule(
            "src/ChatRoom.tsx",
            r#"
            import { useEffect } from "react";
            export function ChatRoom({ roomId, onConnected }: { roomId: string; onConnected: (id: string) => void }) {
                useEffect(() => {
                    onConnected(roomId);
                }, [roomId, onConnected]);
                return <div>{roomId}</div>;
            }
            "#,
            RuleId::PreferUseEffectEvent,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/ChatRoom.tsx",
            r#"
            import { useEffect } from "react";
            export function ChatRoom({ roomId }: { roomId: string }) {
                useEffect(() => {
                    console.log(roomId);
                }, [roomId]);
                return <div>{roomId}</div>;
            }
            "#,
            RuleId::PreferUseEffectEvent,
        )
        .is_empty()
    );

    // 4. rerender-defer-reads-hook
    assert_eq!(
        run_rule(
            "src/Checkout.tsx",
            r#"
            export function Checkout() {
                const cart = useCartStore();
                const handleBuy = () => {
                    submitOrder(cart);
                };
                return <button onClick={handleBuy}>Buy</button>;
            }
            "#,
            RuleId::RerenderDeferReadsHook,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Checkout.tsx",
            r#"
            export function Checkout() {
                const cart = useCartStore();
                return <div>{cart.total}</div>;
            }
            "#,
            RuleId::RerenderDeferReadsHook,
        )
        .is_empty()
    );
}

#[test]
fn group_e_react_builtins_jsx_and_class_lifecycle_rules_and_autofixes() {
    // 1. jsx-no-useless-fragment with Autofix round-trip
    let useless_frag_src = "export const Comp = () => <><span>Hello</span></>;\n";
    let uf_diags = run_rule(
        "src/Comp.tsx",
        useless_frag_src,
        RuleId::JsxNoUselessFragment,
    );
    assert_eq!(uf_diags.len(), 1);
    assert_eq!(
        RuleId::JsxNoUselessFragment.metadata().default_tier,
        PrescriptionTier::Autofix
    );
    assert_eq!(uf_diags[0].tier, PrescriptionTier::Autofix);
    let (uf_fixed, uf_descs) = apply_patches_to_source(useless_frag_src, &uf_diags);
    assert_eq!(uf_descs.len(), 1);
    assert_eq!(uf_fixed, "export const Comp = () => <span>Hello</span>;\n");
    assert!(run_rule("src/Comp.tsx", &uf_fixed, RuleId::JsxNoUselessFragment).is_empty());
    // Empty fragment inside JSX parent -> replaced with ""
    let nested_empty_frag = "export const Comp = () => <div><></><span>Hi</span></div>;\n";
    let nef_diags = run_rule(
        "src/Comp.tsx",
        nested_empty_frag,
        RuleId::JsxNoUselessFragment,
    );
    assert_eq!(nef_diags.len(), 1);
    let (nef_fixed, _) = apply_patches_to_source(nested_empty_frag, &nef_diags);
    assert_eq!(
        nef_fixed,
        "export const Comp = () => <div><span>Hi</span></div>;\n"
    );
    // Single text child inside JSX parent -> replaced with text child
    let nested_text_frag = "export const Comp = () => <div><>Hello</></div>;\n";
    let ntf_diags = run_rule(
        "src/Comp.tsx",
        nested_text_frag,
        RuleId::JsxNoUselessFragment,
    );
    assert_eq!(ntf_diags.len(), 1);
    let (ntf_fixed, _) = apply_patches_to_source(nested_text_frag, &ntf_diags);
    assert_eq!(ntf_fixed, "export const Comp = () => <div>Hello</div>;\n");

    // Valid fragment with 2 children or keyed Fragment
    assert!(
        run_rule(
            "src/Comp.tsx",
            "export const Comp = () => <><span>A</span><span>B</span></>;",
            RuleId::JsxNoUselessFragment,
        )
        .is_empty()
    );

    // 2. jsx-fragments with Autofix round-trip
    let frag_src =
        "import React from 'react';\nexport const Comp = () => <React.Fragment><span>A</span><span>B</span></React.Fragment>;\n";
    let frag_diags = run_rule("src/Comp.tsx", frag_src, RuleId::JsxFragments);
    assert_eq!(frag_diags.len(), 1);
    assert_eq!(
        RuleId::JsxFragments.metadata().default_tier,
        PrescriptionTier::Autofix
    );
    assert_eq!(frag_diags[0].tier, PrescriptionTier::Autofix);
    let (frag_fixed, frag_descs) = apply_patches_to_source(frag_src, &frag_diags);
    assert_eq!(frag_descs.len(), 1);
    assert!(frag_fixed.contains("<><span>A</span><span>B</span></>"));
    assert!(run_rule("src/Comp.tsx", &frag_fixed, RuleId::JsxFragments).is_empty());

    // Valid: <React.Fragment key={id}> has key attribute
    assert!(
        run_rule(
            "src/Comp.tsx",
            "import React from 'react';\nexport const Comp = ({ id }: any) => <React.Fragment key={id}><span>A</span></React.Fragment>;",
            RuleId::JsxFragments,
        )
        .is_empty()
    );

    // 3. jsx-pascal-case
    assert_eq!(
        run_rule(
            "src/Comp.tsx",
            "export const Comp = () => <USER_CARD />;",
            RuleId::JsxPascalCase,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Comp.tsx",
            "export const Comp = () => <UserCard />;",
            RuleId::JsxPascalCase,
        )
        .is_empty()
    );

    // 4. jsx-props-no-spreading
    assert_eq!(
        run_rule(
            "src/Comp.tsx",
            "export const Comp = (props: any) => <CustomWidget {...props} />;",
            RuleId::JsxPropsNoSpreading,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Comp.tsx",
            "export const Comp = ({ title }: any) => <CustomWidget title={title} />;",
            RuleId::JsxPropsNoSpreading,
        )
        .is_empty()
    );

    // 5. jsx-max-depth
    assert_eq!(
        run_rule(
            "src/Deep.tsx",
            "export const Deep = () => <div><div><div><div><div><span>Too deep</span></div></div></div></div></div>;",
            RuleId::JsxMaxDepth,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Deep.tsx",
            "export const Shallow = () => <div><section><p>Ok</p></section></div>;",
            RuleId::JsxMaxDepth,
        )
        .is_empty()
    );

    // 6. no-unstable-nested-components
    assert_eq!(
        run_rule(
            "src/Parent.tsx",
            r#"
            export function Parent({ items }: any) {
                const InnerRow = () => <div>Row</div>;
                return <List header={() => <div />}><InnerRow /></List>;
            }
            "#,
            RuleId::NoUnstableNestedComponents,
        )
        .len(),
        2
    );
    assert!(
        run_rule(
            "src/Parent.tsx",
            r#"
            const InnerRow = () => <div>Row</div>;
            export function Parent() {
                return <div><InnerRow /></div>;
            }
            "#,
            RuleId::NoUnstableNestedComponents,
        )
        .is_empty()
    );

    // 7. hook-use-state
    assert_eq!(
        run_rule(
            "src/HookState.tsx",
            "import { useState } from 'react'; export function Comp() { const [count, updateVal] = useState(0); return <div>{count}</div>; }",
            RuleId::HookUseState,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/HookState.tsx",
            "import { useState } from 'react'; export function Comp() { const [count, setCount] = useState(0); return <div>{count}</div>; }",
            RuleId::HookUseState,
        )
        .is_empty()
    );

    // 8. display-name
    assert_eq!(
        run_rule(
            "src/Anon.tsx",
            "import { forwardRef } from 'react'; export default forwardRef((props, ref) => <div ref={ref} />);",
            RuleId::DisplayName,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/AnonVar.tsx",
            "import { memo } from 'react'; export const Comp = memo(() => <div />);",
            RuleId::DisplayName,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/WithDisplayName.tsx",
            "import { memo } from 'react'; export const Comp = memo(() => <div />); Comp.displayName = 'Comp';",
            RuleId::DisplayName,
        )
        .is_empty()
    );
    assert!(
        run_rule(
            "src/Named.tsx",
            "import { forwardRef } from 'react'; export const Named = forwardRef(function Named(props, ref) { return <div ref={ref} />; });",
            RuleId::DisplayName,
        )
        .is_empty()
    );

    // 9. Class lifecycle & component rules:
    // no-unsafe, no-did-mount-set-state, no-did-update-set-state, no-will-update-set-state,
    // state-in-constructor, prefer-es6-class, prefer-function-component
    let class_violations = r#"
        import React, { Component } from "react";

        export class LegacyWidget extends Component {
            state = { ready: false };
            UNSAFE_componentWillMount() {}
            componentDidMount() {
                this.setState({ ready: true });
            }
            componentDidUpdate() {
                this.setState({ ready: false });
            }
            componentWillUpdate() {
                this.setState({ ready: false });
            }
            render() {
                return <div>{String(this.state.ready)}</div>;
            }
        }

        export class StatelessBox extends Component {
            render() {
                return <div>{this.props.title}</div>;
            }
        }

        export const OldClass = createReactClass({
            render() {
                return <div />;
            }
        });
    "#;
    for rule in [
        RuleId::NoUnsafe,
        RuleId::NoDidMountSetState,
        RuleId::NoDidUpdateSetState,
        RuleId::NoWillUpdateSetState,
        RuleId::StateInConstructor,
        RuleId::PreferEs6Class,
        RuleId::PreferFunctionComponent,
    ] {
        let diags = run_rule("src/ClassComp.tsx", class_violations, rule);
        assert!(
            !diags.is_empty(),
            "Expected {rule:?} to report violation in ClassComp.tsx"
        );
    }

    // Valid class component: constructor state, guarded componentDidUpdate, and lifecycle method so not stateless
    let valid_class = r#"
        import React, { Component } from "react";
        export class ValidWidget extends Component<{ id: string }, { data: any }> {
            constructor(props: { id: string }) {
                super(props);
                this.state = { data: null };
            }
            componentDidUpdate(prevProps: { id: string }) {
                if (prevProps.id !== this.props.id) {
                    this.setState({ data: this.props.id });
                }
            }
            componentWillUnmount() {
                console.log("cleanup");
            }
            render() {
                return <div>{this.state.data}</div>;
            }
        }
    "#;
    for rule in [
        RuleId::NoUnsafe,
        RuleId::NoDidMountSetState,
        RuleId::NoDidUpdateSetState,
        RuleId::NoWillUpdateSetState,
        RuleId::StateInConstructor,
        RuleId::PreferEs6Class,
        RuleId::PreferFunctionComponent,
    ] {
        let diags = run_rule("src/ValidClass.tsx", valid_class, rule);
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for {rule:?} on ValidClass.tsx, got: {diags:#?}"
        );
    }
}

#[test]
fn group_f_and_g_correctness_and_architecture_rules() {
    // 1. no-prevent-default
    assert_eq!(
        run_rule(
            "src/Nav.tsx",
            r#"export const Nav = () => <Link to="/home" onClick={(e: any) => e.preventDefault()}>Home</Link>;"#,
            RuleId::NoPreventDefault,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Nav.tsx",
            r#"export const Form = () => <form onSubmit={(e) => { e.preventDefault(); }}>Save</form>;"#,
            RuleId::NoPreventDefault,
        )
        .is_empty()
    );

    // 2. no-fetch-response-used-without-status-check
    assert_eq!(
        run_rule(
            "src/api.ts",
            r#"
            export async function loadUser() {
                const res = await fetch("/api/user");
                return await res.json();
            }
            "#,
            RuleId::NoFetchResponseUsedWithoutStatusCheck,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/api.ts",
            r#"
            export async function loadUser() {
                const res = await fetch("/api/user");
                if (!res.ok) throw new Error("Failed");
                return await res.json();
            }
            "#,
            RuleId::NoFetchResponseUsedWithoutStatusCheck,
        )
        .is_empty()
    );

    // 3. no-legacy-class-lifecycles
    assert_eq!(
        run_rule(
            "src/Legacy.tsx",
            r#"
            import { Component } from "react";
            export class Legacy extends Component {
                componentWillMount() {}
                componentWillReceiveProps() {}
                render() { return <div />; }
            }
            "#,
            RuleId::NoLegacyClassLifecycles,
        )
        .len(),
        2
    );

    // 4. no-inline-hoc-on-component
    assert_eq!(
        run_rule(
            "src/Hoc.tsx",
            r#"
            export function Page() {
                const Enhanced = withAuth(ProfileCard);
                return <Enhanced />;
            }
            "#,
            RuleId::NoInlineHocOnComponent,
        )
        .len(),
        1
    );
    assert_eq!(
        run_rule(
            "src/HocExport.tsx",
            r#"
            function ProfileCard() { return <div />; }
            export default withAuth(ProfileCard);
            "#,
            RuleId::NoInlineHocOnComponent,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Hoc.tsx",
            r#"
            const Enhanced = withAuth(ProfileCard);
            export function Page() {
                return <Enhanced />;
            }
            "#,
            RuleId::NoInlineHocOnComponent,
        )
        .is_empty()
    );

    // 5. no-giant-component
    let mut giant_lines = String::from("export function GiantComponent() {\n");
    for i in 0..210 {
        giant_lines.push_str(&format!("  const v{i} = {i};\n"));
    }
    giant_lines.push_str("  return <div>{v0}</div>;\n}\n");
    assert_eq!(
        run_rule("src/Giant.tsx", &giant_lines, RuleId::NoGiantComponent).len(),
        1
    );
    assert!(
        run_rule(
            "src/Small.tsx",
            "export function SmallComponent() { return <div />; }",
            RuleId::NoGiantComponent,
        )
        .is_empty()
    );

    // 6. no-high-complexity-react-function
    let complex_fn = r#"
        export function ComplexView({ a, b, c, d, e, f, g, h, i, j, k, l }: any) {
            if (a && b) return <div />;
            if (c || d) return <div />;
            if (e && f) return <div />;
            if (g || h) return <div />;
            if (i && j) return <div />;
            if (k || l) return <div />;
            return <span>{a ? (b ? (c ? (d ? "1" : "2") : "3") : "4") : "5"}</span>;
        }
    "#;
    assert_eq!(
        run_rule(
            "src/Complex.tsx",
            complex_fn,
            RuleId::NoHighComplexityReactFunction,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Simple.tsx",
            "export function SimpleView({ a }: any) { return <div>{a ? 'yes' : 'no'}</div>; }",
            RuleId::NoHighComplexityReactFunction,
        )
        .is_empty()
    );

    // 7. no-many-boolean-props
    assert_eq!(
        run_rule(
            "src/Button.tsx",
            r#"
            export function Button({
                isPrimary = false,
                isSecondary = false,
                isDanger = false,
                isOutline = false,
                isLarge = false,
            }: {
                isPrimary?: boolean;
                isSecondary?: boolean;
                isDanger?: boolean;
                isOutline?: boolean;
                isLarge?: boolean;
            }) {
                return <button />;
            }
            "#,
            RuleId::NoManyBooleanProps,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Button.tsx",
            r#"
            export function Button({ variant = "primary", isDisabled = false }: { variant?: string; isDisabled?: boolean }) {
                return <button disabled={isDisabled}>{variant}</button>;
            }
            "#,
            RuleId::NoManyBooleanProps,
        )
        .is_empty()
    );
    // 3 optional boolean props with neither prefix nor boolean default should NOT be double-counted to 6
    assert!(
        run_rule(
            "src/Button3Bool.tsx",
            r#"
            export function Button3Bool({
                primary,
                secondary,
                danger,
            }: {
                primary?: boolean;
                secondary?: boolean;
                danger?: boolean;
            }) {
                return <button />;
            }
            "#,
            RuleId::NoManyBooleanProps,
        )
        .is_empty()
    );

    // 8. no-generic-handler-names
    assert_eq!(
        run_rule(
            "src/Form.tsx",
            r#"
            export function Form() {
                const handleClick = () => {};
                return <button onClick={handleClick}>Save</button>;
            }
            "#,
            RuleId::NoGenericHandlerNames,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Form.tsx",
            r#"
            export function Form() {
                const handleSaveProfile = () => {};
                return <button onClick={handleSaveProfile}>Save</button>;
            }
            "#,
            RuleId::NoGenericHandlerNames,
        )
        .is_empty()
    );

    // 9. no-render-in-render
    assert_eq!(
        run_rule(
            "src/Card.tsx",
            r#"
            export function Card() {
                const renderHeader = () => <header>Title</header>;
                return <div>{renderHeader()}</div>;
            }
            "#,
            RuleId::NoRenderInRender,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/Card.tsx",
            r#"
            function CardHeader() { return <header>Title</header>; }
            export function Card() {
                return <div><CardHeader /></div>;
            }
            "#,
            RuleId::NoRenderInRender,
        )
        .is_empty()
    );

    // 10. no-react19-deprecated-apis
    assert_eq!(
        run_rule(
            "src/LegacyReact19.tsx",
            r#"
            import React from "react";
            export const divFactory = React.createFactory("div");
            "#,
            RuleId::NoReact19DeprecatedApis,
        )
        .len(),
        1
    );
    assert!(
        run_rule(
            "src/ModernReact19.tsx",
            r#"
            export const Box = () => <div />;
            "#,
            RuleId::NoReact19DeprecatedApis,
        )
        .is_empty()
    );
}
