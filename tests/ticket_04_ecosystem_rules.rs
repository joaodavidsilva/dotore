//! Integration tests for Ticket #5 (`04: Motion, Remotion, TanStack Form/Table/Virtual, Redux & UI Primitive Rules (31 Rules)`).

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleId, analyze_project_sources,
    analyze_source, analyze_source_with_config, rule_registry,
};

fn run_rule(path: &str, source: &str, rule: RuleId) -> Vec<dotore::Diagnostic> {
    analyze_source(Path::new(path), source, Some(&[rule]))
}

#[test]
fn motion_rules_capability_gate_and_detectors() {
    let cfg = DotoreConfig::default();
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    let motion_gate = CapabilityGate::with_capabilities([Capability::React, Capability::Motion]);

    let source_create = r#"
import { motion } from "framer-motion";
export function Card() {
    const MotionSection = motion.create("section");
    return <MotionSection />;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/Card.tsx"),
            source_create,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::MotionCreateInRender),
        "motion-create-in-render must not run without Capability::Motion"
    );
    let gated_diags = analyze_source_with_config(
        Path::new("src/Card.tsx"),
        source_create,
        &cfg,
        &motion_gate,
        None,
    );
    assert!(
        gated_diags
            .iter()
            .any(|d| d.rule == RuleId::MotionCreateInRender),
        "motion-create-in-render must run when Capability::Motion is active"
    );

    // 1. motion-animate-presence-must-outlive-child
    let invalid_outlive = run_rule(
        "src/Modal.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Modal({ open }: { open: boolean }) {
    return (
        <div>
            {open && (
                <AnimatePresence>
                    <motion.div key="modal" exit={{ opacity: 0 }} />
                </AnimatePresence>
            )}
        </div>
    );
}
"#,
        RuleId::MotionAnimatePresenceMustOutliveChild,
    );
    assert_eq!(invalid_outlive.len(), 1);
    assert_eq!(invalid_outlive[0].tier, PrescriptionTier::Surgical);

    let invalid_outlive_early_return = run_rule(
        "src/Modal.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Modal({ open }: { open: boolean }) {
    if (!open) return null;
    return (
        <AnimatePresence>
            <motion.div key="modal" exit={{ opacity: 0 }} />
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceMustOutliveChild,
    );
    assert_eq!(invalid_outlive_early_return.len(), 1);

    let valid_outlive = run_rule(
        "src/Modal.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Modal({ open }: { open: boolean }) {
    return (
        <AnimatePresence>
            {open && <motion.div key="modal" exit={{ opacity: 0 }} />}
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceMustOutliveChild,
    );
    assert!(valid_outlive.is_empty());

    // 2. motion-animate-presence-requires-key
    let invalid_key = run_rule(
        "src/Switcher.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Switcher({ step }: { step: number }) {
    return (
        <AnimatePresence>
            {step === 0 ? <motion.div exit={{ opacity: 0 }} /> : <motion.span key="two" exit={{ opacity: 0 }} />}
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceRequiresKey,
    );
    assert_eq!(invalid_key.len(), 1);

    let valid_key = run_rule(
        "src/Switcher.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Switcher({ step }: { step: number }) {
    return (
        <AnimatePresence>
            {step === 0 ? <motion.div key="one" exit={{ opacity: 0 }} /> : <motion.span key="two" exit={{ opacity: 0 }} />}
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceRequiresKey,
    );
    assert!(valid_key.is_empty());

    // 3. motion-animate-presence-wait-single-child
    let invalid_wait = run_rule(
        "src/Steps.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Steps() {
    return (
        <AnimatePresence mode="wait">
            <motion.div key="a" exit={{ opacity: 0 }} />
            <motion.div key="b" exit={{ opacity: 0 }} />
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceWaitSingleChild,
    );
    assert_eq!(invalid_wait.len(), 1);

    let valid_wait = run_rule(
        "src/Steps.tsx",
        r#"
import { AnimatePresence, motion } from "framer-motion";
export function Steps({ active }: { active: boolean }) {
    return (
        <AnimatePresence mode="wait">
            {active ? <motion.div key="a" exit={{ opacity: 0 }} /> : <motion.div key="b" exit={{ opacity: 0 }} />}
        </AnimatePresence>
    );
}
"#,
        RuleId::MotionAnimatePresenceWaitSingleChild,
    );
    assert!(valid_wait.is_empty());

    // 4. motion-create-in-render
    let invalid_create = run_rule("src/Card.tsx", source_create, RuleId::MotionCreateInRender);
    assert_eq!(invalid_create.len(), 1);

    let valid_create = run_rule(
        "src/Card.tsx",
        r#"
import { motion } from "framer-motion";
const MotionSection = motion.create("section");
export function Card() {
    return <MotionSection />;
}
"#,
        RuleId::MotionCreateInRender,
    );
    assert!(valid_create.is_empty());

    // 5. motion-drag-axis-constraint-mismatch
    let invalid_drag_axis = run_rule(
        "src/Slider.tsx",
        r#"
import { motion } from "framer-motion";
export function Slider() {
    return <motion.div drag="x" dragConstraints={{ top: 0, bottom: 100 }} />;
}
"#,
        RuleId::MotionDragAxisConstraintMismatch,
    );
    assert_eq!(invalid_drag_axis.len(), 1);

    let invalid_drag_inverted = run_rule(
        "src/Slider.tsx",
        r#"
import { motion } from "framer-motion";
export function Slider() {
    return <motion.div drag="x" dragConstraints={{ left: 100, right: 0 }} />;
}
"#,
        RuleId::MotionDragAxisConstraintMismatch,
    );
    assert_eq!(invalid_drag_inverted.len(), 1);

    let valid_drag = run_rule(
        "src/Slider.tsx",
        r#"
import { motion } from "framer-motion";
export function Slider() {
    return <motion.div drag="x" dragConstraints={{ left: -100, right: 100 }} />;
}
"#,
        RuleId::MotionDragAxisConstraintMismatch,
    );
    assert!(valid_drag.is_empty());

    // 6. motion-imperative-animation-in-render
    let invalid_imperative = run_rule(
        "src/Pulse.tsx",
        r#"
import { useAnimate } from "framer-motion";
export function Pulse() {
    const [scope, animate] = useAnimate();
    animate(scope.current, { opacity: 1 });
    return <div ref={scope} />;
}
"#,
        RuleId::MotionImperativeAnimationInRender,
    );
    assert_eq!(invalid_imperative.len(), 1);

    let valid_imperative = run_rule(
        "src/Pulse.tsx",
        r#"
import { useEffect } from "react";
import { useAnimate } from "framer-motion";
export function Pulse() {
    const [scope, animate] = useAnimate();
    useEffect(() => {
        animate(scope.current, { opacity: 1 });
    }, [animate, scope]);
    return <div ref={scope} />;
}
"#,
        RuleId::MotionImperativeAnimationInRender,
    );
    assert!(valid_imperative.is_empty());

    // 7. motion-keyframe-times-mismatch
    let invalid_keyframes = run_rule(
        "src/Wave.tsx",
        r#"
import { motion } from "framer-motion";
export function Wave() {
    return (
        <motion.div
            animate={{ opacity: [0, 1, 0] }}
            transition={{ times: [0, 1] }}
        />
    );
}
"#,
        RuleId::MotionKeyframeTimesMismatch,
    );
    assert_eq!(invalid_keyframes.len(), 1);

    let valid_keyframes = run_rule(
        "src/Wave.tsx",
        r#"
import { motion } from "framer-motion";
export function Wave() {
    return (
        <motion.div
            animate={{ opacity: [0, 1, 0] }}
            transition={{ times: [0, 0.5, 1] }}
        />
    );
}
"#,
        RuleId::MotionKeyframeTimesMismatch,
    );
    assert!(valid_keyframes.is_empty());

    // 8. motion-layout-on-inline-element
    let invalid_inline_layout = run_rule(
        "src/Badge.tsx",
        r#"
import { motion } from "framer-motion";
export function Badge() {
    return <motion.span layout>New</motion.span>;
}
"#,
        RuleId::MotionLayoutOnInlineElement,
    );
    assert_eq!(invalid_inline_layout.len(), 1);

    let valid_inline_block_layout = run_rule(
        "src/Badge.tsx",
        r#"
import { motion } from "framer-motion";
export function Badge() {
    return <motion.span layout className="inline-block">New</motion.span>;
}
"#,
        RuleId::MotionLayoutOnInlineElement,
    );
    assert!(valid_inline_block_layout.is_empty());

    // 9. motion-unstable-layout-id-in-iteration
    let invalid_layout_id = run_rule(
        "src/List.tsx",
        r#"
import { motion } from "framer-motion";
export function List({ items }: { items: { id: string }[] }) {
    return (
        <ul>
            {items.map((item) => (
                <motion.li key={item.id} layoutId="card" />
            ))}
        </ul>
    );
}
"#,
        RuleId::MotionUnstableLayoutIdInIteration,
    );
    assert_eq!(invalid_layout_id.len(), 1);

    let valid_layout_id = run_rule(
        "src/List.tsx",
        r#"
import { motion } from "framer-motion";
export function List({ items }: { items: { id: string }[] }) {
    return (
        <ul>
            {items.map((item) => (
                <motion.li key={item.id} layoutId={`card-${item.id}`} />
            ))}
        </ul>
    );
}
"#,
        RuleId::MotionUnstableLayoutIdInIteration,
    );
    assert!(valid_layout_id.is_empty());

    let valid_layout_group_parent = run_rule(
        "src/List.tsx",
        r#"
import { LayoutGroup, motion } from "framer-motion";
export function List({ items }: { items: { id: string }[] }) {
    return (
        <ul>
            {items.map((item) => (
                <LayoutGroup key={item.id} id={item.id}>
                    <motion.li layoutId="card" />
                </LayoutGroup>
            ))}
        </ul>
    );
}
"#,
        RuleId::MotionUnstableLayoutIdInIteration,
    );
    assert!(valid_layout_group_parent.is_empty());

    // 10. motion-use-transform-range-length
    let invalid_transform = run_rule(
        "src/Parallax.tsx",
        r#"
import { useMotionValue, useTransform } from "framer-motion";
export function Parallax() {
    const x = useMotionValue(0);
    const opacity = useTransform(x, [0, 100, 200], [0, 1]);
    return <div style={{ opacity: opacity.get() }} />;
}
"#,
        RuleId::MotionUseTransformRangeLength,
    );
    assert_eq!(invalid_transform.len(), 1);

    let valid_transform = run_rule(
        "src/Parallax.tsx",
        r#"
import { useMotionValue, useTransform } from "framer-motion";
export function Parallax() {
    const x = useMotionValue(0);
    const opacity = useTransform(x, [0, 100, 200], [0, 0.5, 1]);
    return <div style={{ opacity: opacity.get() }} />;
}
"#,
        RuleId::MotionUseTransformRangeLength,
    );
    assert!(valid_transform.is_empty());

    // 11. motion-value-subscription-in-render
    let invalid_sub = run_rule(
        "src/Tracker.tsx",
        r#"
import { useMotionValue } from "framer-motion";
export function Tracker() {
    const x = useMotionValue(0);
    x.on("change", (latest) => console.log(latest));
    return <div />;
}
"#,
        RuleId::MotionValueSubscriptionInRender,
    );
    assert_eq!(invalid_sub.len(), 1);

    let valid_sub = run_rule(
        "src/Tracker.tsx",
        r#"
import { useEffect } from "react";
import { useMotionValue } from "framer-motion";
export function Tracker() {
    const x = useMotionValue(0);
    useEffect(() => {
        return x.on("change", (latest) => console.log(latest));
    }, [x]);
    return <div />;
}
"#,
        RuleId::MotionValueSubscriptionInRender,
    );
    assert!(valid_sub.is_empty());
}

#[test]
fn remotion_rules_capability_gate_and_detectors() {
    let cfg = DotoreConfig::default();
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    let remotion_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::Remotion]);

    let source_rand = r#"
export function Comp() {
    const r = Math.random();
    return <div>{r}</div>;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/Comp.tsx"),
            source_rand,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::RemotionDeterministicRandomness),
        "remotion-deterministic-randomness must not run without Capability::Remotion"
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/Comp.tsx"),
            source_rand,
            &cfg,
            &remotion_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::RemotionDeterministicRandomness),
        "remotion-deterministic-randomness must run when Capability::Remotion is active"
    );

    // 1. remotion-calculate-metadata-fetch-signal
    let invalid_meta = run_rule(
        "src/Comp.tsx",
        r#"
export const calculateMetadata = async () => {
    const res = await fetch("https://api.example.com/meta");
    return { durationInFrames: (await res.json()).frames };
};
"#,
        RuleId::RemotionCalculateMetadataFetchSignal,
    );
    assert_eq!(invalid_meta.len(), 1);

    let valid_meta = run_rule(
        "src/Comp.tsx",
        r#"
export const calculateMetadata = async ({ abortSignal }: { abortSignal: AbortSignal }) => {
    const res = await fetch("https://api.example.com/meta", { signal: abortSignal });
    return { durationInFrames: (await res.json()).frames };
};
"#,
        RuleId::RemotionCalculateMetadataFetchSignal,
    );
    assert!(valid_meta.is_empty());

    // 2. remotion-deterministic-randomness
    let invalid_rand = run_rule(
        "src/Comp.tsx",
        source_rand,
        RuleId::RemotionDeterministicRandomness,
    );
    assert_eq!(invalid_rand.len(), 1);

    let valid_rand = run_rule(
        "src/Comp.tsx",
        r#"
import { random } from "remotion";
export function Comp() {
    const r = random("seed-1");
    return <div>{r}</div>;
}
"#,
        RuleId::RemotionDeterministicRandomness,
    );
    assert!(valid_rand.is_empty());

    // 3. remotion-no-css-animation
    let invalid_css_anim = run_rule(
        "src/Comp.tsx",
        r#"
export function Comp() {
    return <div className="animate-spin" style={{ animation: "fadeIn 1s ease" }} />;
}
"#,
        RuleId::RemotionNoCssAnimation,
    );
    assert_eq!(invalid_css_anim.len(), 1);

    let valid_css_anim = run_rule(
        "src/Comp.tsx",
        r#"
import { interpolate, useCurrentFrame } from "remotion";
export function Comp() {
    const frame = useCurrentFrame();
    const opacity = interpolate(frame, [0, 30], [0, 1]);
    return <div className="animate-none" style={{ opacity }} />;
}
"#,
        RuleId::RemotionNoCssAnimation,
    );
    assert!(valid_css_anim.is_empty());

    // 4. remotion-no-css-transition
    let invalid_css_trans = run_rule(
        "src/Comp.tsx",
        r#"
export function Comp() {
    return <div className="transition-opacity duration-300" />;
}
"#,
        RuleId::RemotionNoCssTransition,
    );
    assert_eq!(invalid_css_trans.len(), 1);

    let valid_css_trans = run_rule(
        "src/Comp.tsx",
        r#"
export function Comp() {
    return <div className="transition-none" style={{ opacity: 1 }} />;
}
"#,
        RuleId::RemotionNoCssTransition,
    );
    assert!(valid_css_trans.is_empty());

    // 5. remotion-no-css-url-assets
    let invalid_css_url = run_rule(
        "src/Comp.tsx",
        r#"
export function Comp() {
    return <div style={{ backgroundImage: "url(/hero.png)" }} />;
}
"#,
        RuleId::RemotionNoCssUrlAssets,
    );
    assert_eq!(invalid_css_url.len(), 1);

    let valid_css_url = run_rule(
        "src/Comp.tsx",
        r#"
import { AbsoluteFill, Img } from "remotion";
export function Comp() {
    return (
        <AbsoluteFill>
            <Img src="/hero.png" />
        </AbsoluteFill>
    );
}
"#,
        RuleId::RemotionNoCssUrlAssets,
    );
    assert!(valid_css_url.is_empty());

    // 6. remotion-no-module-scope-delay-render
    let invalid_module_delay = run_rule(
        "src/Comp.tsx",
        r#"
import { delayRender } from "remotion";
const handle = delayRender("loading font");
export function Comp() {
    return <div>{handle}</div>;
}
"#,
        RuleId::RemotionNoModuleScopeDelayRender,
    );
    assert_eq!(invalid_module_delay.len(), 1);

    let valid_module_delay = run_rule(
        "src/Comp.tsx",
        r#"
import { useState } from "react";
import { delayRender } from "remotion";
export function Comp() {
    const [handle] = useState(() => delayRender("loading font"));
    return <div>{handle}</div>;
}
"#,
        RuleId::RemotionNoModuleScopeDelayRender,
    );
    assert!(valid_module_delay.is_empty());

    // 7. remotion-no-native-media-elements
    let invalid_native_media = run_rule(
        "src/Comp.tsx",
        r#"
export function Comp() {
    return <video src="/clip.mp4" />;
}
"#,
        RuleId::RemotionNoNativeMediaElements,
    );
    assert_eq!(invalid_native_media.len(), 1);

    let valid_native_media = run_rule(
        "src/Comp.tsx",
        r#"
import { OffthreadVideo } from "remotion";
export function Comp() {
    return <OffthreadVideo src="/clip.mp4" />;
}
"#,
        RuleId::RemotionNoNativeMediaElements,
    );
    assert!(valid_native_media.is_empty());

    // 8. remotion-no-next-image
    let invalid_next_img = run_rule(
        "src/Comp.tsx",
        r#"
import Image from "next/image";
export function Comp() {
    return <Image src="/logo.png" width={100} height={100} alt="Logo" />;
}
"#,
        RuleId::RemotionNoNextImage,
    );
    assert_eq!(invalid_next_img.len(), 1);

    let valid_remotion_img = run_rule(
        "src/Comp.tsx",
        r#"
import { Img } from "remotion";
export function Comp() {
    return <Img src="/logo.png" />;
}
"#,
        RuleId::RemotionNoNextImage,
    );
    assert!(valid_remotion_img.is_empty());

    // 9. remotion-stable-delay-render-handle
    let invalid_stable_delay = run_rule(
        "src/Comp.tsx",
        r#"
import { delayRender } from "remotion";
export function Comp() {
    const handle = delayRender("frame");
    return <div>{handle}</div>;
}
"#,
        RuleId::RemotionStableDelayRenderHandle,
    );
    assert_eq!(invalid_stable_delay.len(), 1);

    let valid_stable_delay = run_rule(
        "src/Comp.tsx",
        r#"
import { useState } from "react";
import { delayRender } from "remotion";
export function Comp() {
    const [handle] = useState(() => delayRender("frame"));
    return <div>{handle}</div>;
}
"#,
        RuleId::RemotionStableDelayRenderHandle,
    );
    assert!(valid_stable_delay.is_empty());
}

#[test]
fn tanstack_and_redux_rules_capability_gate_and_detectors() {
    let cfg = DotoreConfig::default();
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    let form_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::TanstackForm]);
    let table_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::TanstackTable]);
    let virtual_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::TanstackVirtual]);
    let redux_gate = CapabilityGate::with_capabilities([Capability::React, Capability::Redux]);

    // 1. tanstack-form-on-submit-requires-prevent-default
    let invalid_form_src = r#"
import { useForm } from "@tanstack/react-form";
export function CheckoutForm() {
    const form = useForm({ defaultValues: { name: "" } });
    return (
        <form onSubmit={() => { form.handleSubmit(); }}>
            <button type="submit">Save</button>
        </form>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/CheckoutForm.tsx"),
            invalid_form_src,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::TanstackFormOnSubmitRequiresPreventDefault)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/CheckoutForm.tsx"),
            invalid_form_src,
            &cfg,
            &form_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::TanstackFormOnSubmitRequiresPreventDefault)
    );
    assert_eq!(
        run_rule(
            "src/CheckoutForm.tsx",
            invalid_form_src,
            RuleId::TanstackFormOnSubmitRequiresPreventDefault
        )
        .len(),
        1
    );

    let valid_form_src = r#"
import { useForm } from "@tanstack/react-form";
export function CheckoutForm() {
    const form = useForm({ defaultValues: { name: "" } });
    return (
        <form onSubmit={(e) => { e.preventDefault(); e.stopPropagation(); form.handleSubmit(); }}>
            <button type="submit">Save</button>
        </form>
    );
}
"#;
    assert!(
        run_rule(
            "src/CheckoutForm.tsx",
            valid_form_src,
            RuleId::TanstackFormOnSubmitRequiresPreventDefault
        )
        .is_empty()
    );

    // 2. tanstack-table-no-unstable-data-or-columns
    let invalid_table_src = r#"
import { useReactTable, getCoreRowModel } from "@tanstack/react-table";
export function UsersTable() {
    const table = useReactTable({
        data: [{ id: 1 }],
        columns: [{ accessorKey: "id" }],
        getCoreRowModel: getCoreRowModel(),
    });
    return <div>{table.getRowModel().rows.length}</div>;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/UsersTable.tsx"),
            invalid_table_src,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::TanstackTableNoUnstableDataOrColumns)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/UsersTable.tsx"),
            invalid_table_src,
            &cfg,
            &table_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::TanstackTableNoUnstableDataOrColumns)
    );
    assert_eq!(
        run_rule(
            "src/UsersTable.tsx",
            invalid_table_src,
            RuleId::TanstackTableNoUnstableDataOrColumns
        )
        .len(),
        1
    );

    let valid_table_src = r#"
import { useMemo } from "react";
import { useReactTable, getCoreRowModel } from "@tanstack/react-table";
const COLUMNS = [{ accessorKey: "id" }];
export function UsersTable({ rows }: { rows: { id: number }[] }) {
    const data = useMemo(() => rows, [rows]);
    const table = useReactTable({
        data,
        columns: COLUMNS,
        getCoreRowModel: getCoreRowModel(),
    });
    return <div>{table.getRowModel().rows.length}</div>;
}
"#;
    assert!(
        run_rule(
            "src/UsersTable.tsx",
            valid_table_src,
            RuleId::TanstackTableNoUnstableDataOrColumns
        )
        .is_empty()
    );

    // 3. tanstack-virtual-measure-element-requires-data-index
    let invalid_virtual_src = r#"
import { useVirtualizer } from "@tanstack/react-virtual";
export function VirtualList({ items, parentRef }: { items: string[]; parentRef: any }) {
    const rowVirtualizer = useVirtualizer({
        count: items.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => 35,
    });
    return (
        <div>
            {rowVirtualizer.getVirtualItems().map((virtualRow) => (
                <div key={virtualRow.key} ref={rowVirtualizer.measureElement}>
                    {items[virtualRow.index]}
                </div>
            ))}
        </div>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/VirtualList.tsx"),
            invalid_virtual_src,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::TanstackVirtualMeasureElementRequiresDataIndex)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/VirtualList.tsx"),
            invalid_virtual_src,
            &cfg,
            &virtual_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::TanstackVirtualMeasureElementRequiresDataIndex)
    );
    assert_eq!(
        run_rule(
            "src/VirtualList.tsx",
            invalid_virtual_src,
            RuleId::TanstackVirtualMeasureElementRequiresDataIndex
        )
        .len(),
        1
    );

    let valid_virtual_src = r#"
import { useVirtualizer } from "@tanstack/react-virtual";
export function VirtualList({ items, parentRef }: { items: string[]; parentRef: any }) {
    const rowVirtualizer = useVirtualizer({
        count: items.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => 35,
    });
    return (
        <div>
            {rowVirtualizer.getVirtualItems().map((virtualRow) => (
                <div
                    key={virtualRow.key}
                    data-index={virtualRow.index}
                    ref={rowVirtualizer.measureElement}
                >
                    {items[virtualRow.index]}
                </div>
            ))}
        </div>
    );
}
"#;
    assert!(
        run_rule(
            "src/VirtualList.tsx",
            valid_virtual_src,
            RuleId::TanstackVirtualMeasureElementRequiresDataIndex
        )
        .is_empty()
    );

    // 4. redux-useselector-inline-derivation
    let invalid_redux_deriv = r#"
import { useSelector } from "react-redux";
export function TodoList() {
    const completed = useSelector((state: any) => state.todos.filter((t: any) => t.done));
    return <div>{completed.length}</div>;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/TodoList.tsx"),
            invalid_redux_deriv,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::ReduxUseselectorInlineDerivation)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/TodoList.tsx"),
            invalid_redux_deriv,
            &cfg,
            &redux_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::ReduxUseselectorInlineDerivation)
    );
    assert_eq!(
        run_rule(
            "src/TodoList.tsx",
            invalid_redux_deriv,
            RuleId::ReduxUseselectorInlineDerivation
        )
        .len(),
        1
    );

    let valid_redux_deriv = r#"
import { useSelector } from "react-redux";
export function TodoList() {
    const todos = useSelector((state: any) => state.todos);
    return <div>{todos.length}</div>;
}
"#;
    assert!(
        run_rule(
            "src/TodoList.tsx",
            valid_redux_deriv,
            RuleId::ReduxUseselectorInlineDerivation
        )
        .is_empty()
    );

    // 5. redux-useselector-returns-new-collection
    let invalid_redux_coll = r#"
import { useSelector } from "react-redux";
export function Profile() {
    const user = useSelector((state: any) => ({ name: state.name, role: state.role }));
    return <div>{user.name}</div>;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/Profile.tsx"),
            invalid_redux_coll,
            &cfg,
            &redux_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::ReduxUseselectorReturnsNewCollection)
    );
    assert_eq!(
        run_rule(
            "src/Profile.tsx",
            invalid_redux_coll,
            RuleId::ReduxUseselectorReturnsNewCollection
        )
        .len(),
        1
    );

    let valid_redux_coll = r#"
import { shallowEqual, useSelector } from "react-redux";
export function Profile() {
    const user = useSelector((state: any) => ({ name: state.name, role: state.role }), shallowEqual);
    return <div>{user.name}</div>;
}
"#;
    assert!(
        run_rule(
            "src/Profile.tsx",
            valid_redux_coll,
            RuleId::ReduxUseselectorReturnsNewCollection
        )
        .is_empty()
    );
}

#[test]
fn ui_primitive_rules_capability_gate_and_detectors() {
    let cfg = DotoreConfig::default();
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    let radix_gate = CapabilityGate::with_capabilities([Capability::React, Capability::RadixUi]);
    let base_ui_gate = CapabilityGate::with_capabilities([Capability::React, Capability::BaseUi]);
    let shadcn_gate = CapabilityGate::with_capabilities([Capability::React, Capability::Shadcn]);
    let styled_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::StyledComponents]);

    // 1. radix-tabs-trigger-requires-list
    let invalid_radix_tabs = r#"
import * as Tabs from "@radix-ui/react-tabs";
export function AccountTabs() {
    return (
        <Tabs.Root defaultValue="account">
            <Tabs.Trigger value="account">Account</Tabs.Trigger>
            <Tabs.Content value="account">Settings</Tabs.Content>
        </Tabs.Root>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/AccountTabs.tsx"),
            invalid_radix_tabs,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::RadixTabsTriggerRequiresList)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/AccountTabs.tsx"),
            invalid_radix_tabs,
            &cfg,
            &radix_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::RadixTabsTriggerRequiresList)
    );
    assert_eq!(
        run_rule(
            "src/AccountTabs.tsx",
            invalid_radix_tabs,
            RuleId::RadixTabsTriggerRequiresList
        )
        .len(),
        1
    );

    let valid_radix_tabs = r#"
import * as Tabs from "@radix-ui/react-tabs";
export function AccountTabs() {
    return (
        <Tabs.Root defaultValue="account">
            <Tabs.List>
                <Tabs.Trigger value="account">Account</Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content value="account">Settings</Tabs.Content>
        </Tabs.Root>
    );
}
"#;
    assert!(
        run_rule(
            "src/AccountTabs.tsx",
            valid_radix_tabs,
            RuleId::RadixTabsTriggerRequiresList
        )
        .is_empty()
    );

    // 2. base-ui-tabs-tab-requires-list
    let invalid_base_ui_tabs = r#"
import { Tabs } from "@base-ui/react/tabs";
export function BillingTabs() {
    return (
        <Tabs.Root defaultValue="overview">
            <Tabs.Tab value="overview">Overview</Tabs.Tab>
            <Tabs.Panel value="overview">Panel</Tabs.Panel>
        </Tabs.Root>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/BillingTabs.tsx"),
            invalid_base_ui_tabs,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::BaseUiTabsTabRequiresList)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/BillingTabs.tsx"),
            invalid_base_ui_tabs,
            &cfg,
            &base_ui_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::BaseUiTabsTabRequiresList)
    );
    assert_eq!(
        run_rule(
            "src/BillingTabs.tsx",
            invalid_base_ui_tabs,
            RuleId::BaseUiTabsTabRequiresList
        )
        .len(),
        1
    );

    let valid_base_ui_tabs = r#"
import { Tabs } from "@base-ui/react/tabs";
export function BillingTabs() {
    return (
        <Tabs.Root defaultValue="overview">
            <Tabs.List>
                <Tabs.Tab value="overview">Overview</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="overview">Panel</Tabs.Panel>
        </Tabs.Root>
    );
}
"#;
    assert!(
        run_rule(
            "src/BillingTabs.tsx",
            valid_base_ui_tabs,
            RuleId::BaseUiTabsTabRequiresList
        )
        .is_empty()
    );

    // 3. shadcn-tabs-trigger-requires-list
    let invalid_shadcn_tabs = r#"
import { Tabs, TabsContent, TabsTrigger } from "@/components/ui/tabs";
export function SettingsTabs() {
    return (
        <Tabs defaultValue="general">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsContent value="general">General settings</TabsContent>
        </Tabs>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/SettingsTabs.tsx"),
            invalid_shadcn_tabs,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::ShadcnTabsTriggerRequiresList)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/SettingsTabs.tsx"),
            invalid_shadcn_tabs,
            &cfg,
            &shadcn_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::ShadcnTabsTriggerRequiresList)
    );
    assert_eq!(
        run_rule(
            "src/SettingsTabs.tsx",
            invalid_shadcn_tabs,
            RuleId::ShadcnTabsTriggerRequiresList
        )
        .len(),
        1
    );

    let valid_shadcn_tabs = r#"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
export function SettingsTabs() {
    return (
        <Tabs defaultValue="general">
            <TabsList>
                <TabsTrigger value="general">General</TabsTrigger>
            </TabsList>
            <TabsContent value="general">General settings</TabsContent>
        </Tabs>
    );
}
"#;
    assert!(
        run_rule(
            "src/SettingsTabs.tsx",
            valid_shadcn_tabs,
            RuleId::ShadcnTabsTriggerRequiresList
        )
        .is_empty()
    );

    // 4. shadcn-command-item-state-variant-requires-value
    let invalid_cmd_item = r#"
import { Command, CommandItem, CommandList } from "@/components/ui/command";
export function CommandMenu() {
    return (
        <Command>
            <CommandList>
                <CommandItem className="data-[selected]:bg-accent data-[disabled]:opacity-50">
                    Search
                </CommandItem>
            </CommandList>
        </Command>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/CommandMenu.tsx"),
            invalid_cmd_item,
            &cfg,
            &shadcn_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::ShadcnCommandItemStateVariantRequiresValue)
    );
    assert_eq!(
        run_rule(
            "src/CommandMenu.tsx",
            invalid_cmd_item,
            RuleId::ShadcnCommandItemStateVariantRequiresValue
        )
        .len(),
        1
    );

    let valid_cmd_item = r#"
import { Command, CommandItem, CommandList } from "@/components/ui/command";
export function CommandMenu() {
    return (
        <Command>
            <CommandList>
                <CommandItem className="data-[selected=true]:bg-accent data-[disabled=true]:opacity-50">
                    Search
                </CommandItem>
            </CommandList>
        </Command>
    );
}
"#;
    assert!(
        run_rule(
            "src/CommandMenu.tsx",
            valid_cmd_item,
            RuleId::ShadcnCommandItemStateVariantRequiresValue
        )
        .is_empty()
    );

    // 5. shadcn-input-group-no-raw-controls
    let invalid_input_group = r#"
import { InputGroup } from "@/components/ui/input-group";
export function SearchBox() {
    return (
        <InputGroup>
            <input type="text" placeholder="Search..." />
        </InputGroup>
    );
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/SearchBox.tsx"),
            invalid_input_group,
            &cfg,
            &shadcn_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::ShadcnInputGroupNoRawControls)
    );
    assert_eq!(
        run_rule(
            "src/SearchBox.tsx",
            invalid_input_group,
            RuleId::ShadcnInputGroupNoRawControls
        )
        .len(),
        1
    );

    let valid_input_group = r#"
import { InputGroup, InputGroupInput } from "@/components/ui/input-group";
export function SearchBox() {
    return (
        <InputGroup>
            <InputGroupInput placeholder="Search..." />
        </InputGroup>
    );
}
"#;
    assert!(
        run_rule(
            "src/SearchBox.tsx",
            valid_input_group,
            RuleId::ShadcnInputGroupNoRawControls
        )
        .is_empty()
    );

    // 6. styled-components-non-transient-custom-prop-on-intrinsic-element
    let invalid_styled = r#"
import styled from "styled-components";
const Pill = styled.button<{ active?: boolean }>`
    background: ${(props) => (props.active ? "black" : "white")};
`;
export function FilterPill() {
    return <Pill active={true}>All</Pill>;
}
"#;
    assert!(
        analyze_source_with_config(
            Path::new("src/FilterPill.tsx"),
            invalid_styled,
            &cfg,
            &react_only_gate,
            None
        )
        .iter()
        .all(|d| d.rule != RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement)
    );
    assert!(
        analyze_source_with_config(
            Path::new("src/FilterPill.tsx"),
            invalid_styled,
            &cfg,
            &styled_gate,
            None
        )
        .iter()
        .any(|d| d.rule == RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement)
    );
    assert_eq!(
        run_rule(
            "src/FilterPill.tsx",
            invalid_styled,
            RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement
        )
        .len(),
        1
    );

    let valid_styled = r#"
import styled from "styled-components";
const Pill = styled.button<{ $active?: boolean }>`
    background: ${(props) => (props.$active ? "black" : "white")};
`;
export function FilterPill() {
    return <Pill $active={true} disabled={false}>All</Pill>;
}
"#;
    assert!(
        run_rule(
            "src/FilterPill.tsx",
            valid_styled,
            RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement
        )
        .is_empty()
    );
}

#[test]
fn all_31_ticket_04_rules_registered_and_inferred_by_package_json() {
    let registry = rule_registry();
    let expected = [
        "motion-animate-presence-must-outlive-child",
        "motion-animate-presence-requires-key",
        "motion-animate-presence-wait-single-child",
        "motion-create-in-render",
        "motion-drag-axis-constraint-mismatch",
        "motion-imperative-animation-in-render",
        "motion-keyframe-times-mismatch",
        "motion-layout-on-inline-element",
        "motion-unstable-layout-id-in-iteration",
        "motion-use-transform-range-length",
        "motion-value-subscription-in-render",
        "remotion-calculate-metadata-fetch-signal",
        "remotion-deterministic-randomness",
        "remotion-no-css-animation",
        "remotion-no-css-transition",
        "remotion-no-css-url-assets",
        "remotion-no-module-scope-delay-render",
        "remotion-no-native-media-elements",
        "remotion-no-next-image",
        "remotion-stable-delay-render-handle",
        "tanstack-form-on-submit-requires-prevent-default",
        "tanstack-table-no-unstable-data-or-columns",
        "tanstack-virtual-measure-element-requires-data-index",
        "redux-useselector-inline-derivation",
        "redux-useselector-returns-new-collection",
        "radix-tabs-trigger-requires-list",
        "base-ui-tabs-tab-requires-list",
        "shadcn-tabs-trigger-requires-list",
        "shadcn-command-item-state-variant-requires-value",
        "shadcn-input-group-no-raw-controls",
        "styled-components-non-transient-custom-prop-on-intrinsic-element",
    ];
    assert_eq!(expected.len(), 31);
    for id in expected {
        let parsed = RuleId::parse(id).expect(id);
        assert!(
            registry
                .iter()
                .any(|m| m.id == parsed && m.canonical_id == id),
            "missing registry entry for {id}"
        );
    }

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "dependencies": {
                        "react": "^19.0.0",
                        "remotion": "^4.0.0",
                        "@tanstack/react-form": "^1.0.0",
                        "@tanstack/react-table": "^8.0.0",
                        "@tanstack/react-virtual": "^3.0.0",
                        "react-redux": "^9.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/VideoComp.tsx"),
                r#"
export function VideoComp() {
    const r = Math.random();
    return <div>{r}</div>;
}
"#
                .to_string(),
            ),
        ],
        None,
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::RemotionDeterministicRandomness)
    );
}
