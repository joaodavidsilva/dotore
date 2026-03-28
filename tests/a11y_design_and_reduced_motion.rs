//! Integration tests for Ticket #09:
//! - All 102 `a11y` rules (`RuleCategory::Accessibility` + `a11y/` rules)
//! - Project-wide `require-reduced-motion` across motion libraries and CSS/SCSS `@media (prefers-reduced-motion: reduce)`
//! - All 112 `design` and `react-ui` rules (`RuleTag::Design`, `default_enabled: false`)
//! - Deterministic `Autofix` patches for unambiguous single-element fixes (`design-no-redundant-padding-axes`, `design-no-redundant-size-axes`, `design-no-three-period-ellipsis`, `design-no-em-dash-in-jsx-text`, `prefer-truncate-shorthand`, `no-redundant-display-class`, `no-deprecated-tailwind-class`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleCategory, RuleId,
    RuleSeverityOverride, RuleTag, analyze_project_sources, analyze_source,
    analyze_source_with_config, apply_patches_to_source, rule_registry,
};

#[test]
fn registry_contains_all_102_a11y_and_112_design_rules_with_correct_metadata() {
    let registry = rule_registry();

    let a11y_rules: Vec<_> = registry
        .iter()
        .filter(|m| m.category == RuleCategory::Accessibility)
        .collect();
    assert!(
        a11y_rules.len() >= 102,
        "Expected at least 102 Accessibility rules in registry, got {}",
        a11y_rules.len()
    );

    let design_rules: Vec<_> = registry
        .iter()
        .filter(|m| m.tags.contains(&RuleTag::Design))
        .collect();
    assert!(
        design_rules.len() >= 112,
        "Expected at least 112 design-tagged rules in registry, got {}",
        design_rules.len()
    );
    assert!(
        design_rules.iter().all(|m| !m.default_enabled),
        "All design-tagged rules should be opt-in (default_enabled: false)"
    );

    // Verify canonical IDs and legacy aliases for key a11y and design rules
    for (id_str, alias_opt) in [
        ("alt-text", Some("jsx-a11y/alt-text")),
        ("aria-role", Some("jsx-a11y/aria-role")),
        ("no-redundant-roles", Some("jsx-a11y/no-redundant-roles")),
        (
            "control-has-associated-label",
            Some("jsx-a11y/control-has-associated-label"),
        ),
        (
            "click-events-have-key-events",
            Some("jsx-a11y/click-events-have-key-events"),
        ),
        (
            "mouse-events-have-key-events",
            Some("jsx-a11y/mouse-events-have-key-events"),
        ),
        (
            "no-static-element-interactions",
            Some("jsx-a11y/no-static-element-interactions"),
        ),
        (
            "no-noninteractive-element-to-interactive-role",
            Some("jsx-a11y/no-noninteractive-element-to-interactive-role"),
        ),
        ("no-autofocus", Some("jsx-a11y/no-autofocus")),
        ("html-has-lang", Some("jsx-a11y/html-has-lang")),
        ("anchor-is-valid", Some("jsx-a11y/anchor-is-valid")),
        ("anchor-has-content", Some("jsx-a11y/anchor-has-content")),
        (
            "anchor-ambiguous-text",
            Some("jsx-a11y/anchor-ambiguous-text"),
        ),
        ("anchor-target-exists", None),
        (
            "no-distracting-elements",
            Some("jsx-a11y/no-distracting-elements"),
        ),
        ("no-outline-none", None),
        ("no-disabled-zoom", None),
        ("require-reduced-motion", None),
        ("no-undersized-icon-button", None),
        ("no-img-without-dimensions", None),
        (
            "design-no-redundant-padding-axes",
            Some("no-redundant-padding-axes"),
        ),
        (
            "design-no-redundant-size-axes",
            Some("no-redundant-size-axes"),
        ),
        (
            "design-no-space-on-flex-children",
            Some("no-space-on-flex-children"),
        ),
        (
            "design-no-vague-button-label",
            Some("no-vague-button-label"),
        ),
        ("no-emoji-heading-decoration", None),
        ("no-decorative-pulse", None),
        ("no-decorative-radial-spotlight", None),
        ("no-side-tab-border", None),
        ("no-smooth-scroll-without-reduced-motion", None),
        ("no-repeated-container-text", None),
        ("no-flat-page-type-scale", None),
        (
            "design-no-three-period-ellipsis",
            Some("no-three-period-ellipsis"),
        ),
        (
            "design-no-em-dash-in-jsx-text",
            Some("no-em-dash-in-jsx-text"),
        ),
    ] {
        let parsed = RuleId::parse(id_str)
            .unwrap_or_else(|| panic!("Expected RuleId::parse({id_str:?}) to succeed"));
        assert_eq!(parsed.as_str(), id_str);
        if let Some(alias) = alias_opt {
            assert_eq!(
                RuleId::parse(alias),
                Some(parsed),
                "Expected alias {alias:?} to resolve to {parsed:?}"
            );
        }
    }
}

#[test]
fn require_reduced_motion_detects_motion_use_and_respects_all_handling_mechanisms() {
    let pkg_json = r#"{
        "name": "motion-app",
        "private": true,
        "dependencies": {
            "react": "^19.0.0",
            "framer-motion": "^12.0.0"
        }
    }"#;

    // 1. Direct `<motion.div>` without reduced-motion handling -> 1 diagnostic on `package.json`
    let unhandled_report = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { motion } from "framer-motion";
export const App = () => <motion.div animate={{ x: 120 }}>moving</motion.div>;
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert_eq!(unhandled_report.diagnostics.len(), 1);
    assert_eq!(
        unhandled_report.diagnostics[0].rule,
        RuleId::RequireReducedMotion
    );
    assert_eq!(
        unhandled_report.diagnostics[0].file,
        PathBuf::from("package.json")
    );

    // 2. Unused motion import / type-only import / non-visual hooks (`useScroll`, `inView`, `useMotionValue`, `stagger`, `<AnimatePresence>`, `<Reorder.Group>`) -> 0 diagnostics
    let unused_or_non_visual = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r##"
import { motion, AnimatePresence, Reorder, useScroll, inView, useMotionValue, stagger, type MotionProps } from "framer-motion";
const UnusedCard = motion.div;
const renderShadowed = (motion: { div: string }) => motion.div;
export const App = (_props: MotionProps) => {
    const pos = useMotionValue(0);
    const scroll = useScroll();
    const delay = stagger(0.1);
    inView("#target", () => undefined);
    return (
        <AnimatePresence>
            <Reorder.Group values={[]} onReorder={() => {}}>
                <div>{String(pos)}{String(scroll)}{String(delay)}{renderShadowed({ div: "still" })}</div>
            </Reorder.Group>
        </AnimatePresence>
    );
};
"##
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert!(
        unused_or_non_visual.diagnostics.is_empty(),
        "Expected 0 diagnostics for unused/non-visual motion imports, got: {:#?}",
        unused_or_non_visual.diagnostics
    );

    // 3. Re-exported motion wrapper across barrel files (`export * from`, `export { motion as animated }`, `export const AnimatedCard = motion.div`) -> 1 diagnostic
    let reexport_report = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/motion-barrel.ts"),
                r#"export * from "framer-motion";
import { motion } from "framer-motion";
export const AnimatedCard = motion.div;
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { AnimatedCard } from "./motion-barrel";
export const App = () => <AnimatedCard animate={{ x: 100 }}>moving</AnimatedCard>;
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert_eq!(reexport_report.diagnostics.len(), 1);

    // 4. Handled via `const shouldReduce = useReducedMotion()` -> 0 diagnostics
    let hook_handled = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { motion, useReducedMotion as usePref } from "framer-motion";
export const App = () => {
    const shouldReduce = usePref();
    return <motion.div animate={{ x: shouldReduce ? 0 : 120 }}>moving</motion.div>;
};
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert!(hook_handled.diagnostics.is_empty());

    // 5. Ignored or voided `useReducedMotion()` or local lookalike -> still reports 1 diagnostic!
    let ignored_hook = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { motion, useReducedMotion } from "framer-motion";
export const App = () => {
    useReducedMotion();
    void useReducedMotion();
    return <motion.div animate={{ x: 120 }}>moving</motion.div>;
};
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert_eq!(ignored_hook.diagnostics.len(), 1);

    // 6. Handled via `<MotionConfig reducedMotion="user">` (or const alias) in a separate provider file -> 0 diagnostics
    let config_handled = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { motion } from "framer-motion";
export const App = () => <motion.div animate={{ x: 120 }}>moving</motion.div>;
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/Providers.tsx"),
                r#"import { MotionConfig } from "framer-motion";
const PREF = "user";
export const Providers = ({ children }: { children: unknown }) => (
    <MotionConfig reducedMotion={PREF}>{children}</MotionConfig>
);
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert!(config_handled.diagnostics.is_empty());

    // 7. `<MotionConfig reducedMotion="never">` -> does NOT count as handling -> 1 diagnostic
    let config_never = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { MotionConfig, motion } from "framer-motion";
export const App = () => (
    <MotionConfig reducedMotion="never">
        <motion.div animate={{ x: 120 }}>moving</motion.div>
    </MotionConfig>
);
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert_eq!(config_never.diagnostics.len(), 1);

    // 8. Handled via CSS `@media (prefers-reduced-motion: reduce)` with declaration -> 0 diagnostics,
    // while commented-out, string-embedded, `not (prefers-reduced-motion: reduce)`, or empty `@media` -> 1 diagnostic
    let css_handled = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r##"import { animate } from "motion/react";
export const run = () => animate("#box", { x: 100 });
"##
                .to_string(),
            ),
            (
                PathBuf::from("src/styles.css"),
                r#"@media screen and (prefers-reduced-motion: reduce) {
  * { animation-duration: 0.01ms; }
}
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert!(css_handled.diagnostics.is_empty());

    let css_bogus = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), pkg_json.to_string()),
            (
                PathBuf::from("src/App.tsx"),
                r#"import { Reorder } from "framer-motion";
export const List = () => <Reorder.Item value="a">item</Reorder.Item>;
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/styles.scss"),
                r#"
/* @media (prefers-reduced-motion: reduce) { * { animation: none; } } */
// @media (prefers-reduced-motion: reduce) { * { animation: none; } }
.card::before { content: "@media (prefers-reduced-motion: reduce) { * { animation: none; } }"; }
@media not (prefers-reduced-motion: reduce) { .card { animation: pulse 1s infinite; } }
@media (prefers-reduced-motion: reduce) {}
"#
                .to_string(),
            ),
        ],
        Some(&[RuleId::RequireReducedMotion]),
    );
    assert_eq!(css_bogus.diagnostics.len(), 1);
}

#[test]
fn a11y_rule_family_detects_violations_and_preserves_valid_regression_cases() {
    let check =
        |rule: RuleId, code: &str, file: &str| analyze_source(Path::new(file), code, Some(&[rule]));

    // 1. `alt-text`
    assert_eq!(
        check(
            RuleId::AltText,
            r#"export const A = () => <img src="/a.png" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::AltText,
            r#"export const A = () => <img src="/a.png" alt={undefined} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::AltText,
            r#"export const A = () => <input type="image" src="/go.png" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::AltText,
            r#"export const A = () => <area href="/x" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::AltText,
            r#"export const A = () => <object data="/x.swf" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::AltText, r#"export const A = () => <><img src="/a.png" alt="" /><img src="/b.png" alt="Hero" /><img src="/c.png" aria-label="Hero" /></>;"#, "App.tsx").is_empty()
    );

    // 2. `aria-role`, `aria-props`, `aria-proptypes`, `aria-unsupported-elements`
    assert_eq!(
        check(
            RuleId::AriaRole,
            r#"export const A = () => <div role="datepicker" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::AriaRole, r#"export const A = () => <><div role="button" /><CustomWidget role="datepicker" /></>;"#, "App.tsx").is_empty()
    );
    assert_eq!(
        check(
            RuleId::AriaProps,
            r#"export const A = () => <div aria-labelled="x" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AriaProps,
            r#"export const A = () => <div aria-label="x" aria-labelledby="y" />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AriaProptypes,
            r#"export const A = () => <div aria-hidden="yes" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AriaProptypes,
            r#"export const A = () => <div aria-hidden="true" aria-checked="mixed" />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AriaUnsupportedElements,
            r#"export const A = () => <meta role="button" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AriaUnsupportedElements,
            r#"export const A = () => <div role="button" />;"#,
            "App.tsx"
        )
        .is_empty()
    );

    // 3. `no-redundant-roles`
    assert_eq!(
        check(
            RuleId::NoRedundantRoles,
            r#"export const A = () => <nav role="navigation" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    // Safari VoiceOver workaround `<ul role="list">` and href-less `<a role="link">` are valid
    assert!(
        check(
            RuleId::NoRedundantRoles,
            r#"export const A = () => <><ul role="list" /><a role="link">Item</a></>;"#,
            "App.tsx"
        )
        .is_empty()
    );

    // 4. `control-has-associated-label` & `label-has-associated-control`
    assert_eq!(
        check(
            RuleId::ControlHasAssociatedLabel,
            r#"export const A = () => <button type="button" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::ControlHasAssociatedLabel,
            r#"export const A = ({ fileRef }) => (
                <div>
                    <label htmlFor="email">Email</label>
                    <input id="email" type="email" />
                    <input ref={fileRef} type="file" className="hidden" />
                    <button type="button" aria-label="Close"><svg /></button>
                    <button type="button"><span>Save</span></button>
                </div>
            );"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::LabelHasAssociatedControl,
            r#"export const A = () => <label>Email</label>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::LabelHasAssociatedControl,
            r#"export const A = () => <><label htmlFor="email">Email</label><label>Name <input /></label></>;"#,
            "App.tsx"
        )
        .is_empty()
    );

    // 5. `click-events-have-key-events`, `mouse-events-have-key-events`, `no-static-element-interactions`
    assert_eq!(
        check(
            RuleId::ClickEventsHaveKeyEvents,
            r#"export const A = ({ go }) => <div onClick={go} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::ClickEventsHaveKeyEvents,
            r#"export const A = ({ go }) => (
                <>
                    <button onClick={go}>Go</button>
                    <div onClick={go} onKeyDown={go} role="button" tabIndex={0} />
                    <div onClick={(e) => { if (e.target === e.currentTarget) go(); }} />
                    <div role="option" onClick={go} />
                </>
            );"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::MouseEventsHaveKeyEvents,
            r#"export const A = ({ fn }) => <div onMouseOver={fn} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::MouseEventsHaveKeyEvents, r#"export const A = ({ fn }) => <div onMouseOver={fn} onFocus={fn} onMouseOut={fn} onBlur={fn} />;"#, "App.tsx").is_empty()
    );
    assert_eq!(
        check(
            RuleId::NoStaticElementInteractions,
            r#"export const A = ({ fn }) => <div onClick={fn} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoStaticElementInteractions, r#"export const A = ({ fn }) => <><button onClick={fn} /><div role="button" onClick={fn} /></>;"#, "App.tsx").is_empty()
    );

    // 6. `no-noninteractive-element-to-interactive-role`, `no-interactive-element-to-noninteractive-role`, `no-noninteractive-element-interactions`, `no-noninteractive-tabindex`, `interactive-supports-focus`
    assert_eq!(
        check(
            RuleId::NoNoninteractiveElementToInteractiveRole,
            r#"export const A = () => <main role="button" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::NoNoninteractiveElementToInteractiveRole,
            r#"export const A = () => <ul role="listbox"><li role="option" /></ul>;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::NoInteractiveElementToNoninteractiveRole,
            r#"export const A = () => <a href="/x" role="img" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoNoninteractiveElementInteractions,
            r#"export const A = ({ fn }) => <li onClick={fn}>Item</li>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoNoninteractiveTabindex,
            r#"export const A = () => <div tabIndex={0}>static</div>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoNoninteractiveTabindex, r#"export const A = () => <><div tabIndex={-1}>ok</div><div role="button" tabIndex={0}>ok</div><div tabIndex={0} className="overflow-auto">scroll</div></>;"#, "App.tsx").is_empty()
    );
    assert_eq!(
        check(
            RuleId::InteractiveSupportsFocus,
            r#"export const A = ({ fn }) => <div role="button" onClick={fn} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::InteractiveSupportsFocus,
            r#"export const A = ({ fn }) => <div role="button" tabIndex={0} onClick={fn} />;"#,
            "App.tsx"
        )
        .is_empty()
    );

    // 7. `no-autofocus`, `html-has-lang`, `lang`, `heading-has-content`, `iframe-has-title`
    assert_eq!(
        check(
            RuleId::NoAutofocus,
            r#"export const A = () => <main><input autoFocus /></main>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoAutofocus, r#"export const A = ({ open }) => <><dialog><input autoFocus /></dialog>{open && <input autoFocus />}</>;"#, "App.tsx").is_empty()
    );
    assert_eq!(
        check(
            RuleId::HtmlHasLang,
            r#"export const A = () => <html />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::HtmlHasLang,
            r#"export const A = () => <html lang="en" />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::Lang,
            r#"export const A = () => <html lang="invalidlangcode" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::Lang,
            r#"export const A = () => <html lang="en-US" />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::HeadingHasContent,
            r#"export const A = () => <h1 />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::HeadingHasContent,
            r#"export const A = () => <h1>Title</h1>;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::IframeHasTitle,
            r#"export const A = () => <iframe src="/embed" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::IframeHasTitle,
            r#"export const A = () => <iframe src="/embed" title="Map" />;"#,
            "App.tsx"
        )
        .is_empty()
    );

    // 8. `anchor-is-valid`, `anchor-has-content`, `anchor-ambiguous-text`, `anchor-target-exists`
    assert_eq!(
        check(
            RuleId::AnchorIsValid,
            r##"export const A = ({ go }) => <a href="#" onClick={go}>Go</a>;"##,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AnchorIsValid,
            r#"export const A = () => <a href="/pricing">Pricing</a>;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AnchorHasContent,
            r#"export const A = () => <a href="/pricing" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AnchorHasContent,
            r#"export const A = () => <a href="/pricing" aria-label="Pricing" />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AnchorAmbiguousText,
            r#"export const A = () => <a href="/pricing">click here</a>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AnchorAmbiguousText,
            r#"export const A = () => <a href="/pricing">View pricing details</a>;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AnchorTargetExists,
            r##"export const A = () => <a href="#missing">Jump</a>;"##,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::AnchorTargetExists,
            r##"export const A = () => <><a href="#about">About</a><section id="about" /></>;"##,
            "App.tsx"
        )
        .is_empty()
    );
    // Cross-file `anchor-target-exists` resolution in ProjectGraph
    let cross_file_anchor = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/Nav.tsx"),
                r##"export const Nav = () => <a href="#features">Features</a>;"##.to_string(),
            ),
            (
                PathBuf::from("src/Features.tsx"),
                r#"export const Features = () => <section id="features">List</section>;"#
                    .to_string(),
            ),
        ],
        Some(&[RuleId::AnchorTargetExists]),
    );
    assert!(cross_file_anchor.diagnostics.is_empty());

    // 9. `no-distracting-elements`, `no-outline-none`, `no-disabled-zoom`, `img-redundant-alt`, `media-has-caption`, `autocomplete-valid`, `role-has-required-aria-props`, `role-supports-aria-props`, `scope`, `tabindex-no-positive`, `no-access-key`, `no-aria-hidden-on-focusable`, `prefer-tag-over-role`
    assert_eq!(
        check(
            RuleId::NoDistractingElements,
            r#"export const A = () => <marquee>News</marquee>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoOutlineNone,
            r#"export const A = () => <button style={{ outline: "none" }}>Save</button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoOutlineNone,
            r#"export const A = () => <button className="outline-none">Save</button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoOutlineNone, r#"export const A = () => <button className="outline-none focus-visible:ring-2">Save</button>;"#, "App.tsx").is_empty()
    );
    assert_eq!(
        check(RuleId::NoDisabledZoom, r#"export const A = () => <meta name="viewport" content="width=device-width, user-scalable=no" />;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(
            RuleId::ImgRedundantAlt,
            r#"export const A = () => <img src="/a.png" alt="Photo of team" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::MediaHasCaption,
            r#"export const A = () => <video src="/demo.mp4" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::MediaHasCaption,
            r#"export const A = () => <video src="/demo.mp4" muted />;"#,
            "App.tsx"
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::AutocompleteValid,
            r#"export const A = () => <input type="text" autoComplete="foobar" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::RoleHasRequiredAriaProps,
            r#"export const A = () => <div role="switch" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::RoleSupportsAriaProps,
            r#"export const A = () => <input type="text" aria-expanded="true" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::Scope,
            r#"export const A = () => <div scope="col" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::TabindexNoPositive,
            r#"export const A = () => <input tabIndex={3} />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoAccessKey,
            r#"export const A = () => <button accessKey="s">Save</button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoAriaHiddenOnFocusable,
            r#"export const A = () => <button aria-hidden="true">Save</button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::PreferTagOverRole,
            r#"export const A = () => <div role="navigation" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );

    // 10. Additional custom a11y rules (`no-reduced-motion-content-removal`, `no-responsive-hidden-accessible-name`, `dialog-has-accessible-name`, `prefer-html-dialog`, `no-autoplay-without-muted`, `no-blocked-paste`, `no-placeholder-only-field`, `no-uninformative-aria-label`, `role-button-requires-complete-keyboard-activation`, `shadcn-*`, `radix-*`, `base-ui-*`, `react-aria-*`)
    assert_eq!(
        check(
            RuleId::NoReducedMotionContentRemoval,
            r#"export const A = () => <p className="motion-reduce:hidden">Payment failed</p>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoResponsiveHiddenAccessibleName,
            r#"export const A = () => <button><span className="md:hidden">Menu</span></button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::DialogHasAccessibleName,
            r#"export const A = () => <dialog open><p>Hi</p></dialog>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::PreferHtmlDialog, r#"export const A = () => <div role="dialog" aria-modal="true" aria-label="Confirm" />;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoAutoplayWithoutMuted,
            r#"export const A = () => <video autoPlay src="/hero.mp4" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::NoBlockedPaste, r#"export const A = () => <input type="password" onPaste={(e) => e.preventDefault()} />;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoPlaceholderOnlyField,
            r#"export const A = () => <input placeholder="Email address" />;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoUninformativeAriaLabel,
            r#"export const A = () => <button aria-label="icon"><svg /></button>;"#,
            "App.tsx"
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::RoleButtonRequiresCompleteKeyboardActivation, r#"export const A = ({ fn }) => <div role="button" tabIndex={0} onClick={fn} onKeyDown={(e) => { if (e.key === "Enter") fn(); }}>Save</div>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::ShadcnDialogContentRequiresTitle, r#"import { DialogContent } from "./dialog"; export const A = () => <DialogContent><p>Body</p></DialogContent>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::ShadcnFormItemRequiresLabel, r#"import { FormItem, FormControl } from "./form"; export const A = () => <FormItem><FormControl><input /></FormControl></FormItem>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::ShadcnIconButtonRequiresLabel, r#"import { Button } from "./button"; export const A = () => <Button size="icon"><TrashIcon /></Button>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::RadixDialogContentRequiresTitle, r#"import * as Dialog from "@radix-ui/react-dialog"; export const A = () => <Dialog.Content><p>Body</p></Dialog.Content>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::BaseUiDialogPopupRequiresTitle, r#"import { Dialog } from "@base-ui/react/dialog"; export const A = () => <Dialog.Popup><p>Body</p></Dialog.Popup>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::BaseUiFieldRequiresLabel, r#"import { Field } from "@base-ui/react/field"; export const A = () => <Field.Root><Field.Control /></Field.Root>;"#, "App.tsx").len(),
        1
    );
    assert_eq!(
        check(RuleId::ReactAriaDialogRequiresHeading, r#"import { Dialog } from "react-aria-components"; export const A = () => <Dialog><p>Body</p></Dialog>;"#, "App.tsx").len(),
        1
    );
}

#[test]
fn design_and_react_ui_rule_family_detects_violations_and_preserves_valid_cases() {
    let check = |rule: RuleId, code: &str| {
        analyze_source(Path::new("src/DesignView.tsx"), code, Some(&[rule]))
    };

    // 0. By default (without explicit rule filter or config opt-in), `design` rules stay off
    let default_diags = analyze_source(
        Path::new("src/DesignView.tsx"),
        r#"export const A = () => <button className="px-4 py-4 w-4 h-4">Submit</button>;"#,
        None,
    );
    assert!(
        !default_diags
            .iter()
            .any(|d| d.rule.metadata().tags.contains(&RuleTag::Design)),
        "Expected design-tagged rules to be off by default in standard scans"
    );

    // When explicitly enabled in `DotoreConfig.rules`, design rules fire
    let mut opt_in_cfg = DotoreConfig::default();
    opt_in_cfg.rules.insert(
        "design-no-redundant-padding-axes".to_string(),
        RuleSeverityOverride::Warn,
    );
    let opt_in_diags = analyze_source_with_config(
        Path::new("src/DesignView.tsx"),
        r#"export const A = () => <div className="px-4 py-4" />;"#,
        &opt_in_cfg,
        &CapabilityGate::with_capabilities([Capability::React, Capability::Tailwind]),
        None,
    );
    assert_eq!(opt_in_diags.len(), 1);
    assert_eq!(opt_in_diags[0].rule, RuleId::DesignNoRedundantPaddingAxes);

    // 1. `design-no-vague-button-label` (including wizard `Continue` + `Back` exemption!)
    assert_eq!(
        check(
            RuleId::DesignNoVagueButtonLabel,
            r#"export const A = () => <button>Submit</button>;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::DesignNoVagueButtonLabel,
            r#"export const A = () => <Button>Continue</Button>;"#
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::DesignNoVagueButtonLabel,
            r#"export const A = () => <form><button type="button">Back</button><Button type="submit">Continue</Button></form>;"#
        )
        .is_empty()
    );

    // 2. `design-no-redundant-padding-axes`, `design-no-redundant-size-axes`, `design-no-space-on-flex-children`
    assert_eq!(
        check(
            RuleId::DesignNoRedundantPaddingAxes,
            r#"export const A = () => <div className="px-4 py-4 rounded" />;"#
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::DesignNoRedundantPaddingAxes, r#"export const A = () => <><div className="px-4 py-2" /><div className="px-4 py-4 sm:py-6" /></>;"#).is_empty()
    );
    assert_eq!(
        check(RuleId::DesignNoRedundantSizeAxes, r#"export const A = () => <div><svg className="w-4 h-4" /><svg className="w-6 h-6" /></div>;"#).len(),
        1
    );
    assert!(
        check(RuleId::DesignNoRedundantSizeAxes, r#"export const A = () => <><div className="w-1/2 h-1/2" /><div className="w-4 h-4 md:w-8" /></>;"#).is_empty()
    );
    assert_eq!(
        check(
            RuleId::DesignNoSpaceOnFlexChildren,
            r#"export const A = () => <div className="flex space-x-4"><span /><span /></div>;"#
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::DesignNoSpaceOnFlexChildren,
            r#"export const A = () => <article className="space-y-4"><p>a</p></article>;"#
        )
        .is_empty()
    );

    // 3. `design-no-three-period-ellipsis` & `design-no-em-dash-in-jsx-text`
    assert_eq!(
        check(
            RuleId::DesignNoThreePeriodEllipsis,
            r#"export const A = () => <button>Loading...</button>;"#
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::DesignNoThreePeriodEllipsis, r#"export const A = () => <><span>Loading…</span><pre><code>const x = [...rest];</code></pre></>;"#).is_empty()
    );
    assert_eq!(
        check(
            RuleId::DesignNoEmDashInJsxText,
            r#"export const A = () => <p>The build is ready — deploy it now to production.</p>;"#
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::DesignNoEmDashInJsxText,
            r#"export const A = () => <code>git log --oneline — docs</code>;"#
        )
        .is_empty()
    );

    // 4. `no-undersized-icon-button` & `no-img-without-dimensions`
    assert_eq!(
        check(RuleId::NoUndersizedIconButton, r#"export const A = () => <button aria-label="Close" className="size-4 p-0"><CloseIcon /></button>;"#).len(),
        1
    );
    assert!(
        check(RuleId::NoUndersizedIconButton, r#"export const A = () => <button aria-label="Close" className="size-8"><CloseIcon /></button>;"#).is_empty()
    );
    assert_eq!(
        check(
            RuleId::NoImgWithoutDimensions,
            r#"export const A = () => <img src="/avatar.jpg" alt="Ada" />;"#
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoImgWithoutDimensions, r#"export const A = () => <><img src="/a.jpg" alt="Ada" width={40} height={40} /><img src="/b.jpg" alt="Ada" className="size-10" /></>;"#).is_empty()
    );

    // 5. `no-emoji-heading-decoration`, `no-decorative-pulse`, `no-decorative-radial-spotlight`, `no-side-tab-border`, `no-smooth-scroll-without-reduced-motion`, `no-repeated-container-text`, `no-flat-page-type-scale`
    assert_eq!(
        check(
            RuleId::NoEmojiHeadingDecoration,
            r#"export const A = () => <h2>🎧 Audio formats</h2>;"#
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::NoEmojiHeadingDecoration,
            r#"export const A = () => <h2>Audio formats</h2>;"#
        )
        .is_empty()
    );
    assert_eq!(
        check(
            RuleId::NoDecorativePulse,
            r#"export const A = () => <span className="animate-pulse">New feature</span>;"#
        )
        .len(),
        1
    );
    assert!(
        check(RuleId::NoDecorativePulse, r#"export const A = () => <span role="status" className="animate-pulse">Loading</span>;"#).is_empty()
    );
    assert_eq!(
        check(RuleId::NoDecorativeRadialSpotlight, r#"export const A = () => <div style={{ width: 320, height: 180, backgroundImage: "radial-gradient(circle, rgb(37 99 235 / 25%), transparent 70%)" }} />;"#).len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoSideTabBorder,
            r##"export const A = () => <div className="border-l-4 border-[#ff0000]" />;"##
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoSmoothScrollWithoutReducedMotion,
            r#"export const A = () => <main className="scroll-smooth" />;"#
        )
        .len(),
        1
    );
    assert!(
        check(
            RuleId::NoSmoothScrollWithoutReducedMotion,
            r#"export const A = () => <main className="motion-safe:scroll-smooth" />;"#
        )
        .is_empty()
    );
    assert_eq!(
        check(RuleId::NoRepeatedContainerText, r#"export const A = () => <article className="rounded-xl border bg-white p-6"><div className="title"><strong>Suspended</strong></div><div className="meta"><span>Suspended</span></div><p className="notice"><em>Suspended</em></p></article>;"#).len(),
        1
    );
    assert_eq!(
        check(RuleId::NoFlatPageTypeScale, r#"export const A = () => <main><p className="text-sm">A</p><h2 className="text-base">B</h2><h1 className="text-lg">C</h1></main>;"#).len(),
        1
    );
    assert!(
        check(RuleId::NoFlatPageTypeScale, r#"export const A = () => <main><p className="text-sm">A</p><h2 className="text-xl">B</h2><h1 className="text-4xl">C</h1></main>;"#).is_empty()
    );

    // 6. Additional UI design rules (`no-tiny-text`, `no-gradient-text`, `no-z-index-9999`, `prefer-dvh-over-vh`, `prefer-truncate-shorthand`, `no-redundant-display-class`, `no-deprecated-tailwind-class`, `no-cramped-container-padding`, `no-small-form-control-text`, `no-oversized-long-heading`, `no-radial-halo`, `no-hover-only-reveal`, `no-mixed-animation-owners`, `prefer-tabular-numeric-data`, `require-autoplay-video-poster`, `require-scale-reveal-transform-origin`, `styled-components-duplicate-css-property-in-block`)
    assert_eq!(
        check(
            RuleId::NoTinyText,
            r#"export const A = () => <p style={{ fontSize: 10 }}>Tiny hint</p>;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::NoGradientText, r#"export const A = () => <span className="text-transparent bg-clip-text bg-gradient-to-r from-pink-500 to-violet-500">Hi</span>;"#).len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoZIndex9999,
            r#"export const A = () => <div style={{ zIndex: 9999 }} />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::PreferDvhOverVh,
            r#"export const A = () => <main className="min-h-screen" />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::PreferTruncateShorthand, r#"export const A = () => <span className="overflow-hidden text-ellipsis whitespace-nowrap">Name</span>;"#).len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoRedundantDisplayClass,
            r#"export const A = () => <div className="block rounded-lg" />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoDeprecatedTailwindClass,
            r#"export const A = () => <div className="bg-gradient-to-r from-black to-white" />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoCrampedContainerPadding,
            r#"export const A = () => <div className="border rounded p-1">Status</div>;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::NoSmallFormControlText,
            r#"export const A = () => <input className="text-sm" />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::NoOversizedLongHeading, r#"export const A = () => <h1 className="text-8xl">Build a better workflow for every team in your growing organization</h1>;"#).len(),
        1
    );
    assert_eq!(
        check(RuleId::NoRadialHalo, r##"export const A = () => <div style={{ backgroundColor: "#050816", backgroundImage: "radial-gradient(circle, rgb(56 189 248 / 80%) 0%, transparent 70%)" }} />;"##).len(),
        1
    );
    assert_eq!(
        check(RuleId::NoHoverOnlyReveal, r#"export const A = () => <button className="opacity-0 hover:opacity-100">Edit</button>;"#).len(),
        1
    );
    assert_eq!(
        check(RuleId::NoMixedAnimationOwners, r#"import { motion } from "motion/react"; export const A = () => <motion.div animate={{ opacity: 1 }} className="transition-opacity duration-200" />;"#).len(),
        1
    );
    assert_eq!(
        check(
            RuleId::PreferTabularNumericData,
            r#"export const A = ({ total }) => <tr><td>{total.toLocaleString()}</td></tr>;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(
            RuleId::RequireAutoplayVideoPoster,
            r#"export const A = () => <video autoPlay muted src="/demo.mp4" />;"#
        )
        .len(),
        1
    );
    assert_eq!(
        check(RuleId::RequireScaleRevealTransformOrigin, r#"import { motion } from "motion/react"; export const A = () => <motion.div role="menu" initial={{ scale: 0.96 }} />;"#).len(),
        1
    );
    assert_eq!(
        check(RuleId::StyledComponentsDuplicateCssPropertyInBlock, r#"import { css } from "styled-components"; const shared = css`opacity: 1; opacity: 0.5;`;"#).len(),
        1
    );
}

#[test]
fn design_autofix_patches_collapse_axes_and_replace_typography_cleanly() {
    // 1. `design-no-redundant-padding-axes`: `px-4 py-4` -> `p-4`
    let pad_src = r#"export const Btn = () => <button className="rounded px-4 py-4 font-bold">Save</button>;"#;
    let pad_diags = analyze_source(
        Path::new("Btn.tsx"),
        pad_src,
        Some(&[RuleId::DesignNoRedundantPaddingAxes]),
    );
    assert_eq!(pad_diags.len(), 1);
    assert_eq!(pad_diags[0].tier, PrescriptionTier::Autofix);
    let (pad_fixed, _) = apply_patches_to_source(pad_src, &pad_diags);
    assert_eq!(
        pad_fixed,
        r#"export const Btn = () => <button className="rounded p-4 font-bold">Save</button>;"#
    );
    assert!(
        analyze_source(
            Path::new("Btn.tsx"),
            &pad_fixed,
            Some(&[RuleId::DesignNoRedundantPaddingAxes])
        )
        .is_empty()
    );

    // 2. `design-no-redundant-size-axes`: `w-6 h-6` -> `size-6`
    let size_src =
        r#"export const Icon = () => <svg className="inline-block w-6 h-6 text-gray-500" />;"#;
    let size_diags = analyze_source(
        Path::new("Icon.tsx"),
        size_src,
        Some(&[RuleId::DesignNoRedundantSizeAxes]),
    );
    assert_eq!(size_diags.len(), 1);
    assert_eq!(size_diags[0].tier, PrescriptionTier::Autofix);
    let (size_fixed, _) = apply_patches_to_source(size_src, &size_diags);
    assert_eq!(
        size_fixed,
        r#"export const Icon = () => <svg className="inline-block size-6 text-gray-500" />;"#
    );
    assert!(
        analyze_source(
            Path::new("Icon.tsx"),
            &size_fixed,
            Some(&[RuleId::DesignNoRedundantSizeAxes])
        )
        .is_empty()
    );

    // 3. `design-no-three-period-ellipsis`: `Loading...` -> `Loading…`
    let ellipsis_src = r#"export const Spinner = () => <span>Loading...</span>;"#;
    let ellipsis_diags = analyze_source(
        Path::new("Spinner.tsx"),
        ellipsis_src,
        Some(&[RuleId::DesignNoThreePeriodEllipsis]),
    );
    assert_eq!(ellipsis_diags.len(), 1);
    assert_eq!(ellipsis_diags[0].tier, PrescriptionTier::Autofix);
    let (ellipsis_fixed, _) = apply_patches_to_source(ellipsis_src, &ellipsis_diags);
    assert_eq!(
        ellipsis_fixed,
        r#"export const Spinner = () => <span>Loading…</span>;"#
    );
    assert!(
        analyze_source(
            Path::new("Spinner.tsx"),
            &ellipsis_fixed,
            Some(&[RuleId::DesignNoThreePeriodEllipsis])
        )
        .is_empty()
    );

    // 4. `design-no-em-dash-in-jsx-text`: `—` -> `--`
    let dash_src =
        r#"export const Copy = () => <p>The build is ready — deploy it now to production.</p>;"#;
    let dash_diags = analyze_source(
        Path::new("Copy.tsx"),
        dash_src,
        Some(&[RuleId::DesignNoEmDashInJsxText]),
    );
    assert_eq!(dash_diags.len(), 1);
    assert_eq!(dash_diags[0].tier, PrescriptionTier::Autofix);
    let (dash_fixed, _) = apply_patches_to_source(dash_src, &dash_diags);
    assert_eq!(
        dash_fixed,
        r#"export const Copy = () => <p>The build is ready -- deploy it now to production.</p>;"#
    );
    assert!(
        analyze_source(
            Path::new("Copy.tsx"),
            &dash_fixed,
            Some(&[RuleId::DesignNoEmDashInJsxText])
        )
        .is_empty()
    );

    // 5. `prefer-truncate-shorthand`: `overflow-hidden text-ellipsis whitespace-nowrap` -> `truncate`
    let trunc_src = r#"export const Label = () => <span className="max-w-xs overflow-hidden text-ellipsis whitespace-nowrap">Text</span>;"#;
    let trunc_diags = analyze_source(
        Path::new("Label.tsx"),
        trunc_src,
        Some(&[RuleId::PreferTruncateShorthand]),
    );
    assert_eq!(trunc_diags.len(), 1);
    assert_eq!(trunc_diags[0].tier, PrescriptionTier::Autofix);
    let (trunc_fixed, _) = apply_patches_to_source(trunc_src, &trunc_diags);
    assert_eq!(
        trunc_fixed,
        r#"export const Label = () => <span className="max-w-xs truncate">Text</span>;"#
    );
    assert!(
        analyze_source(
            Path::new("Label.tsx"),
            &trunc_fixed,
            Some(&[RuleId::PreferTruncateShorthand])
        )
        .is_empty()
    );
}
