//! Integration tests for Ticket #07:
//! - `state-and-effects`, `react-builtins`, `correctness`, and `architecture` rule families
//! - Cross-file `ProjectGraph` cold-path suppression for inline prop reference rules
//! - `ProjectGraph` unstable `Context.Provider` values and overloaded provider fan-out analysis
//! - `ProjectGraph` ancestral `<Suspense>` and `<ErrorBoundary>` verification across Caller Sites
//! - Deterministic `Autofix` patches verified by round-trip re-analysis

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, ContextualOwnerPolicy, DotoreConfig, PrescriptionTier, RuleId,
    analyze_project_sources, analyze_source, analyze_source_with_config, apply_patches_to_source,
};

#[test]
fn state_and_effects_rules_detect_invalid_patterns_and_respect_valid_regressions() {
    // 1. `no-self-updating-effect`: flags non-settling self-updates, allows convergent guards and scalar sets
    let self_updating_invalid = r#"
        import { useState, useEffect } from 'react';
        export function Counter() {
            const [count, setCount] = useState(0);
            const [items, setItems] = useState([1, 2]);
            useEffect(() => {
                setCount(count + 1);
            }, [count]);
            useEffect(() => {
                setCount(prev => prev + 1);
            }, [count]);
            useEffect(() => {
                setItems([]);
            }, [items]);
            return <div>{count}{items.length}</div>;
        }
    "#;
    let diags = analyze_source(
        Path::new("Counter.tsx"),
        self_updating_invalid,
        Some(&[RuleId::NoSelfUpdatingEffect]),
    );
    assert_eq!(
        diags.len(),
        3,
        "Expected 3 no-self-updating-effect diagnostics, got: {diags:#?}"
    );

    let self_updating_valid = r#"
        import { useState, useEffect } from 'react';
        export function ConvergentQueue({ initial }) {
            const [items, setItems] = useState(initial);
            const [open, setOpen] = useState(false);
            const [count, setCount] = useState(0);

            // Converges because early return stops when items is empty
            useEffect(() => {
                if (items.length === 0) return;
                setItems(items.slice(1));
            }, [items]);

            // Scalar constant settles immediately
            useEffect(() => {
                setOpen(true);
            }, [open]);

            // Identity write is a no-op
            useEffect(() => {
                setCount(count);
            }, [count]);

            // Reading other.count (member property, not state binding)
            useEffect(() => {
                const other = { count: 5 };
                setCount(other.count);
            }, [count]);

            return <div>{items.length}{String(open)}{count}</div>;
        }
    "#;
    let valid_diags = analyze_source(
        Path::new("ConvergentQueue.tsx"),
        self_updating_valid,
        Some(&[RuleId::NoSelfUpdatingEffect]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics for convergent/scalar effects, got: {valid_diags:#?}"
    );

    // 2. `no-set-state-in-render`: flags unconditional top-level setState, allows guarded prev-prop pattern
    let set_state_in_render_code = r#"
        import { useState } from 'react';
        export function BadCounter() {
            const [count, setCount] = useState(0);
            setCount(1);
            return <div>{count}</div>;
        }
        export function ValidDerivedFromPrevProp({ count }) {
            const [prevCount, setPrevCount] = useState(count);
            if (prevCount !== count) {
                setPrevCount(count);
            }
            return <div>{prevCount}</div>;
        }
    "#;
    let render_diags = analyze_source(
        Path::new("RenderSetState.tsx"),
        set_state_in_render_code,
        Some(&[RuleId::NoSetStateInRender]),
    );
    assert_eq!(render_diags.len(), 1);
    assert_eq!(render_diags[0].subject_name.as_deref(), Some("BadCounter"));

    // 3. `no-set-state-after-await-in-effect`: flags unguarded post-await setState, allows cancelled guard
    let after_await_code = r#"
        import { useState, useEffect } from 'react';
        export function AsyncEffectComp({ id }) {
            const [data, setData] = useState(null);
            useEffect(() => {
                async function loadBad() {
                    const res = await fetchData(id);
                    setData(res);
                }
                loadBad();
            }, [id]);

            useEffect(() => {
                let cancelled = false;
                async function loadGood() {
                    const res = await fetchData(id);
                    if (!cancelled) {
                        setData(res);
                    }
                }
                loadGood();
                return () => { cancelled = true; };
            }, [id]);
            return <div>{data}</div>;
        }
    "#;
    let await_diags = analyze_source(
        Path::new("AsyncEffectComp.tsx"),
        after_await_code,
        Some(&[RuleId::NoSetStateAfterAwaitInEffect]),
    );
    assert_eq!(await_diags.len(), 1);

    // 4. `no-side-effect-in-state-updater-function`, `no-ref-current-in-render`, `effect-needs-cleanup`
    let updater_and_ref_code = r#"
        import { useState, useRef, useEffect } from 'react';
        export function ImpureComponent({ onNotify }) {
            const [count, setCount] = useState(0);
            const countRef = useRef(0);
            countRef.current = count;
            onNotify(count);

            useEffect(() => {
                window.addEventListener('resize', () => {});
            }, []);

            const handleInc = () => {
                setCount(prev => {
                    onNotify(prev + 1);
                    return prev + 1;
                });
            };
            return <button type="button" onClick={handleInc}>{countRef.current}</button>;
        }
    "#;
    let side_effect_diags = analyze_source(
        Path::new("ImpureComponent.tsx"),
        updater_and_ref_code,
        Some(&[
            RuleId::NoSideEffectInStateUpdaterFunction,
            RuleId::NoRefCurrentInRender,
            RuleId::NoPropCallbackInRender,
            RuleId::EffectNeedsCleanup,
        ]),
    );
    let triggered_rules: Vec<RuleId> = side_effect_diags.iter().map(|d| d.rule).collect();
    assert!(triggered_rules.contains(&RuleId::NoSideEffectInStateUpdaterFunction));
    assert!(triggered_rules.contains(&RuleId::NoRefCurrentInRender));
    assert!(triggered_rules.contains(&RuleId::NoPropCallbackInRender));
    assert!(triggered_rules.contains(&RuleId::EffectNeedsCleanup));

    // 5. `rerender-lazy-state-init`, `rerender-lazy-ref-init`, `prefer-use-reducer`, `rerender-functional-setstate`
    let rerender_state_code = r#"
        import { useState, useRef, useEffect } from 'react';
        export function ExpensiveInitComponent({ raw }) {
            const [parsed, setParsed] = useState(JSON.parse(raw));
            const [a, setA] = useState(0);
            const [b, setB] = useState(0);
            const [c, setC] = useState(0);
            const [d, setD] = useState(0);
            const [e, setE] = useState(0);
            const parserRef = useRef(new DOMParser());

            const handleBatch = () => {
                setA(a + 1);
                setB(b + 1);
                setC(c + 1);
                setD(d + 1);
                setE(e + 1);
            };
            return <button type="button" onClick={handleBatch}>{parsed}{a}{b}{c}{d}{e}{String(parserRef.current)}</button>;
        }
    "#;
    let rerender_diags = analyze_source(
        Path::new("ExpensiveInitComponent.tsx"),
        rerender_state_code,
        Some(&[
            RuleId::RerenderLazyStateInit,
            RuleId::RerenderLazyRefInit,
            RuleId::PreferUseReducer,
            RuleId::RerenderFunctionalSetstate,
        ]),
    );
    let rerender_rules: Vec<RuleId> = rerender_diags.iter().map(|d| d.rule).collect();
    assert!(rerender_rules.contains(&RuleId::RerenderLazyStateInit));
    assert!(rerender_rules.contains(&RuleId::RerenderLazyRefInit));
    assert!(rerender_rules.contains(&RuleId::PreferUseReducer));
    assert!(rerender_rules.contains(&RuleId::RerenderFunctionalSetstate));
}

#[test]
fn react_builtins_exhaustive_deps_local_callback_ownership_and_rules_of_hooks() {
    assert_eq!(
        RuleId::ExhaustiveDeps.metadata().contextual_owner,
        ContextualOwnerPolicy::RelatedNodes
    );

    // 1. `exhaustive-deps`: missing deps in inline callback AND local callback passed or called
    let exhaustive_invalid = r#"
        import { useState, useEffect, useMemo, useCallback } from 'react';
        const MODULE_CONST = { scale: 2 };

        export function UserDashboard({ userId, filter, currentUser }) {
            const [multiplier, setMultiplier] = useState(1);

            function syncUser() {
                fetchUser(userId, multiplier);
            }

            // Local callback passed directly by identifier reference
            useEffect(syncUser, [userId]);

            // Inline callback missing `filter`
            const visibleItems = useMemo(() => {
                return computeItems(userId, filter, MODULE_CONST);
            }, [userId]);

            // Parameter default reading component-scope prop `filter`
            const buildQuery = useCallback((f = filter) => f, []);

            // Whole-object consumption when only `currentUser?.uid` is in deps
            const normalized = useMemo(() => normalizeUser(currentUser), [currentUser?.uid]);

            return <div>{visibleItems}{buildQuery()}{normalized}</div>;
        }
    "#;
    let exh_diags = analyze_source(
        Path::new("UserDashboard.tsx"),
        exhaustive_invalid,
        Some(&[RuleId::ExhaustiveDeps]),
    );
    assert_eq!(
        exh_diags.len(),
        4,
        "Expected 4 exhaustive-deps diagnostics, got: {exh_diags:#?}"
    );
    assert!(exh_diags.iter().any(|d| d.message.contains("multiplier")));
    assert!(exh_diags.iter().any(|d| d.message.contains("filter")));
    assert!(exh_diags.iter().any(|d| d.message.contains("currentUser")));

    // Adversarial valid cases from `exhaustive-deps.regressions.test.ts`
    let exhaustive_valid = r#"
        import { useState, useEffect, useMemo, useCallback, useRef, forwardRef } from 'react';
        const SOME_MODULE_CONST = { a: 1 };

        export function History({ versions, onlyShowMine, currentUser, activeFileTab }) {
            const [count, setCount] = useState(0);
            const latestRef = useRef(versions);

            // Member dependency when bare object read is only its null guard
            const filtered = useMemo(() => {
                let list = [...versions];
                if (onlyShowMine && currentUser) {
                    list = list.filter(v => v.owner === currentUser.uid);
                }
                return list;
            }, [versions, onlyShowMine, currentUser?.uid]);

            // Module-scope constant in parameter default, state setter, and ref container are stable
            const update = useCallback((opts = SOME_MODULE_CONST) => {
                setCount(c => c + 1);
                return latestRef.current.length + opts.a;
            }, []);

            // Accessor call in deps
            useEffect(() => {
                console.log(activeFileTab());
            }, [activeFileTab()]);

            return <div>{filtered.length}{count}{update()}</div>;
        }

        const buildComponent = (logger) => {
            const _Wrapped = forwardRef((props, ref) => {
                useEffect(() => {
                    logger(props.value);
                }, [props.value]);
                return <div ref={ref} />;
            });
            return _Wrapped;
        };
    "#;
    let exh_valid_diags = analyze_source(
        Path::new("History.tsx"),
        exhaustive_valid,
        Some(&[RuleId::ExhaustiveDeps]),
    );
    assert!(
        exh_valid_diags.is_empty(),
        "Expected 0 exhaustive-deps diagnostics on valid regressions, got: {exh_valid_diags:#?}"
    );

    // 2. `rules-of-hooks`: conditional, loop, after early return, and non-component function
    let hooks_invalid = r#"
        import { useState, useEffect } from 'react';

        export function ConditionalHooks({ ready, items }) {
            if (ready) {
                useState(0);
            }
            for (const item of items) {
                useEffect(() => { console.log(item); }, []);
            }
            if (!ready) {
                return null;
            }
            const [late] = useState(1);
            return <div>{late}</div>;
        }

        function regularHelper() {
            const [x] = useState(0);
            return x;
        }
    "#;
    let hooks_diags = analyze_source(
        Path::new("ConditionalHooks.tsx"),
        hooks_invalid,
        Some(&[RuleId::RulesOfHooks]),
    );
    assert_eq!(
        hooks_diags.len(),
        4,
        "Expected 4 rules-of-hooks diagnostics, got: {hooks_diags:#?}"
    );

    let hooks_valid = r#"
        import { useState, useEffect } from 'react';
        export function useCustomCounter(initial) {
            const [count, setCount] = useState(initial);
            useEffect(() => {
                document.title = String(count);
            }, [count]);
            return [count, setCount];
        }
        const _PrivateComponent = () => {
            const [v] = useCustomCounter(0);
            return <div>{v}</div>;
        };
    "#;
    let hooks_valid_diags = analyze_source(
        Path::new("ValidHooks.tsx"),
        hooks_valid,
        Some(&[RuleId::RulesOfHooks]),
    );
    assert!(hooks_valid_diags.is_empty());
}

#[test]
fn react_builtins_button_checked_only_export_components_and_correctness_rules() {
    // 1. `button-has-type` regressions: form owner vs outside form, spread, local const, prop forward
    let button_invalid = r#"
        const Inside = () => <form><button>Save</button></form>;
        const Associated = () => <><form id="settings" /><button form="settings">Save</button></>;
        const BareType = () => <button type>Save</button>;
        const BadLiteral = () => <button type="banana">Save</button>;
    "#;
    let btn_diags = analyze_source(
        Path::new("Buttons.tsx"),
        button_invalid,
        Some(&[RuleId::ButtonHasType]),
    );
    assert_eq!(
        btn_diags.len(),
        4,
        "Expected 4 button-has-type diagnostics, got: {btn_diags:#?}"
    );

    let button_valid = r#"
        const Outside = () => <main><button>Open menu</button></main>;
        const CustomForm = () => <Form><button>Save</button></Form>;
        const SpreadBtn = (props) => <form><button {...props} /></form>;
        const ConstType = () => {
            const kind = "submit" as const;
            return <form><button type={kind}>Save</button></form>;
        };
        const ForwardedType = ({ type: kind }) => <form><button type={kind}>Save</button></form>;
        const RenamedTypeWithDefault = ({ htmlType = "button" }) => <form><button type={htmlType}>Save</button></form>;
    "#;
    let btn_valid_diags = analyze_source(
        Path::new("ValidButtons.tsx"),
        button_valid,
        Some(&[RuleId::ButtonHasType]),
    );
    assert!(
        btn_valid_diags.is_empty(),
        "Expected 0 button-has-type diagnostics on valid regressions, got: {btn_valid_diags:#?}"
    );

    // 2. `checked-requires-onchange-or-readonly`
    let checked_code = r#"
        export function Checkboxes({ val, onChange, checked, defaultChecked, rest }) {
            return (
                <div>
                    <input type="checkbox" checked={val} />
                    <input type="checkbox" checked={true} defaultChecked={false} onChange={onChange} />
                    <input type="checkbox" checked={val} onChange={onChange} />
                    <input type="checkbox" checked={val} readOnly />
                    <input type="checkbox" checked={val} disabled />
                    <input type="checkbox" checked={val} {...rest} />
                    <input type="checkbox" checked={checked} defaultChecked={defaultChecked} onChange={onChange} />
                </div>
            );
        }
    "#;
    let checked_diags = analyze_source(
        Path::new("Checkboxes.tsx"),
        checked_code,
        Some(&[RuleId::CheckedRequiresOnchangeOrReadonly]),
    );
    assert_eq!(checked_diags.len(), 2);

    // 3. `only-export-components`: flags non-component function export alongside component, allows hooks & types
    let mixed_exports_invalid = r#"
        export function formatCurrency(n: number) {
            return `$${n}`;
        }
        export function PriceTag({ amount }: { amount: number }) {
            return <span>{formatCurrency(amount)}</span>;
        }
    "#;
    let oec_diags = analyze_source(
        Path::new("src/components/PriceTag.tsx"),
        mixed_exports_invalid,
        Some(&[RuleId::OnlyExportComponents]),
    );
    assert_eq!(oec_diags.len(), 1);

    let mixed_exports_valid = r#"
        export type CountryOption = { code: string; name: string };
        export const MAX_COUNTRIES = 50;
        export function useCountryOptions(): CountryOption[] {
            return [];
        }
        export function CountryPickerSheet() {
            const opts = useCountryOptions();
            return <div>{opts.length}</div>;
        }
    "#;
    let oec_valid_diags = analyze_source(
        Path::new("src/components/CountryPickerSheet.tsx"),
        mixed_exports_valid,
        Some(&[RuleId::OnlyExportComponents]),
    );
    assert!(
        oec_valid_diags.is_empty(),
        "Expected 0 only-export-components diagnostics when exporting hook + type + constant, got: {oec_valid_diags:#?}"
    );

    // 4. `no-random-key`, `no-array-index-as-key`, `rendering-conditional-render`, `radio-input-missing-name`
    let correctness_invalid = r#"
        import { nanoid } from 'nanoid';
        let globalKeyCounter = 0;

        export function BadCorrectness({ items, count, userCount }) {
            return (
                <div>
                    {items.map((item, idx) => (
                        <div key={`item-${idx}`}>{item.name}</div>
                    ))}
                    <span key={Math.random()}>A</span>
                    <span key={crypto.randomUUID()}>B</span>
                    <span key={nanoid()}>C</span>
                    <span key={globalKeyCounter++}>D</span>
                    {items.length && <ul><li>Item</li></ul>}
                    {count && <span>{count}</span>}
                    {userCount && <span>{userCount}</span>}
                    <input type="radio" value="a" />
                    <input type="radio" name="" value="b" />
                </div>
            );
        }
    "#;
    let corr_diags = analyze_source(
        Path::new("BadCorrectness.tsx"),
        correctness_invalid,
        Some(&[
            RuleId::NoArrayIndexAsKey,
            RuleId::NoRandomKey,
            RuleId::RenderingConditionalRender,
            RuleId::RadioInputMissingName,
        ]),
    );
    assert_eq!(
        corr_diags
            .iter()
            .filter(|d| d.rule == RuleId::NoArrayIndexAsKey)
            .count(),
        1
    );
    assert_eq!(
        corr_diags
            .iter()
            .filter(|d| d.rule == RuleId::NoRandomKey)
            .count(),
        4
    );
    assert_eq!(
        corr_diags
            .iter()
            .filter(|d| d.rule == RuleId::RenderingConditionalRender)
            .count(),
        3
    );
    assert_eq!(
        corr_diags
            .iter()
            .filter(|d| d.rule == RuleId::RadioInputMissingName)
            .count(),
        2
    );

    let correctness_valid = r#"
        function createId(item) {
            return item.id;
        }
        export function GoodCorrectness({ items, count, isCount, showCount, hasLength, discount, register }) {
            let localCounter = 0;
            const total = items.length > 0;
            return (
                <div>
                    {items.map((item) => (
                        <div key={createId(item)}>{item.name}</div>
                    ))}
                    <span key={localCounter++}>Deterministic per render</span>
                    {items.length > 0 && <ul><li>Item</li></ul>}
                    {Boolean(count) && <span>{count}</span>}
                    {isCount && <span>Flag</span>}
                    {showCount && <span>Show</span>}
                    {hasLength && <span>Has</span>}
                    {discount && <span>{discount}</span>}
                    {total && <span>Total boolean</span>}
                    <input type="radio" name="shipping" value="standard" />
                    <input type="radio" {...register('shipping')} value="express" />
                </div>
            );
        }
    "#;
    let corr_valid_diags = analyze_source(
        Path::new("GoodCorrectness.tsx"),
        correctness_valid,
        Some(&[
            RuleId::NoArrayIndexAsKey,
            RuleId::NoRandomKey,
            RuleId::RenderingConditionalRender,
            RuleId::RadioInputMissingName,
        ]),
    );
    assert!(
        corr_valid_diags.is_empty(),
        "Expected 0 correctness diagnostics on valid regressions, got: {corr_valid_diags:#?}"
    );
}

#[test]
fn architecture_rules_and_react_compiler_capability_gate_behavior() {
    let arch_code = r#"
        import { useMemo } from 'react';

        export function ParentCard({ items, filter }) {
            const STATIC_COLUMNS = ['name', 'role', 'status'];
            const formatCell = (val: string) => val.trim().toUpperCase();

            function InnerBadge() {
                return <span>Badge</span>;
            }

            const filtered = useMemo(() => items.filter(Boolean), [items]);
            return (
                <div>
                    <InnerBadge />
                    {STATIC_COLUMNS.map(col => <span key={col}>{formatCell(col)}</span>)}
                    {filtered.length > 0 ? 'yes' : 'no'}
                </div>
            );
        }

        export function ValidUnrenderedHelperCard({ x }) {
            const ALLOWED_KEYS = ['a', 'b'];
            const mutatedList = [1, 2];
            mutatedList.push(3);
            const impureObj = { ts: Date.now() };
            const renderClosure = (prefix: string) => `${prefix}:${x}`;

            // PascalCase helper called as a function, never rendered as <RenderHelper />
            function RenderHelper() {
                return <span>{x}</span>;
            }

            return (
                <div>
                    {ALLOWED_KEYS.includes(x) ? RenderHelper() : null}
                    {mutatedList.length}{impureObj.ts}{renderClosure('id')}
                </div>
            );
        }
    "#;

    let std_gate = CapabilityGate::default_react();
    let cfg = DotoreConfig::default();
    let arch_diags = analyze_source_with_config(
        Path::new("ParentCard.tsx"),
        arch_code,
        &cfg,
        &std_gate,
        Some(&[
            RuleId::NoNestedComponentDefinition,
            RuleId::PreferModuleScopeStaticValue,
            RuleId::PreferModuleScopePureFunction,
        ]),
    );
    assert_eq!(
        arch_diags
            .iter()
            .filter(|d| d.rule == RuleId::NoNestedComponentDefinition)
            .count(),
        1
    );
    assert_eq!(
        arch_diags
            .iter()
            .filter(|d| d.rule == RuleId::PreferModuleScopeStaticValue)
            .count(),
        1
    );
    assert_eq!(
        arch_diags
            .iter()
            .filter(|d| d.rule == RuleId::PreferModuleScopePureFunction)
            .count(),
        1
    );
    // Ensure all findings belong to ParentCard and none fired on ValidUnrenderedHelperCard
    assert!(
        arch_diags
            .iter()
            .all(|d| d.subject_name.as_deref() == Some("ParentCard")),
        "Expected all architecture diagnostics on ParentCard only, got: {arch_diags:#?}"
    );

    // When React Compiler is active in CapabilityGate:
    // - `prefer-module-scope-static-value` and `jsx-no-new-object-as-prop` are disabled by gate
    // - `react-compiler-no-manual-memoization` is allowed by gate
    let compiler_gate =
        CapabilityGate::with_capabilities([Capability::React, Capability::ReactCompiler]);
    let mut compiler_cfg = DotoreConfig::default();
    compiler_cfg.rules.insert(
        "react-compiler-no-manual-memoization".to_string(),
        dotore::RuleSeverityOverride::Warn,
    );
    let compiler_diags = analyze_source_with_config(
        Path::new("ParentCard.tsx"),
        arch_code,
        &compiler_cfg,
        &compiler_gate,
        None,
    );
    let compiler_rules: Vec<RuleId> = compiler_diags.iter().map(|d| d.rule).collect();
    assert!(!compiler_rules.contains(&RuleId::PreferModuleScopeStaticValue));
    assert!(compiler_rules.contains(&RuleId::ReactCompilerNoManualMemoization));
}

#[test]
fn project_graph_suppresses_cold_path_inline_props_and_flags_hot_paths() {
    let files = vec![
        (
            PathBuf::from("src/ColdModal.tsx"),
            r#"
            export function ColdModal({ config, items, onClose }) {
                return <div onClick={onClose}>{config.title}{items.length}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/MemoizedRow.tsx"),
            r#"
            import { memo } from 'react';
            export const MemoizedRow = memo(function MemoizedRow({ config, items, onSelect }) {
                return <div onClick={onSelect}>{config.title}{items.length}</div>;
            });
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/CustomComparatorRow.tsx"),
            r#"
            import { memo } from 'react';
            export const CustomComparatorRow = memo(
                function CustomComparatorRow({ config, items, onSelect }) {
                    return <div onClick={onSelect}>{config.title}{items.length}</div>;
                },
                (prev, next) => prev.config.title === next.config.title
            );
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/EffectDepChild.tsx"),
            r#"
            import { useEffect } from 'react';
            export function EffectDepChild({ options }) {
                useEffect(() => {
                    console.log(options);
                }, [options]);
                return <div />;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/Dashboard.tsx"),
            r#"
            import { ColdModal } from './ColdModal';
            import { MemoizedRow } from './MemoizedRow';
            import { CustomComparatorRow } from './CustomComparatorRow';
            import { EffectDepChild } from './EffectDepChild';

            export function Dashboard({ rows, a, b }) {
                return (
                    <div>
                        {/* 1. Cold path: ColdModal is not memoized, not in .map(), and does not use props in effect deps -> SUPPRESSED */}
                        <ColdModal
                            config={{ title: 'Settings' }}
                            items={[a, b]}
                            onClose={() => console.log('close')}
                        />

                        {/* 2. Custom comparator on memo -> SUPPRESSED */}
                        <CustomComparatorRow
                            config={{ title: 'Custom' }}
                            items={[a, b]}
                            onSelect={() => console.log('custom')}
                        />

                        {/* 3. Hot path A: MemoizedRow is wrapped in React.memo -> FLAGGED */}
                        <MemoizedRow
                            config={{ title: 'Memo' }}
                            items={[a, b]}
                            onSelect={() => console.log('select')}
                        />

                        {/* 4. Hot path B: ColdModal rendered inside .map() list loop -> FLAGGED */}
                        {rows.map((r) => (
                            <ColdModal
                                key={r.id}
                                config={{ title: r.title }}
                                items={[r.id]}
                                onClose={() => console.log(r.id)}
                            />
                        ))}

                        {/* 5. Hot path C: EffectDepChild feeds `options` into useEffect dependency array -> FLAGGED */}
                        <EffectDepChild options={{ retry: true }} />
                    </div>
                );
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(
        files,
        Some(&[
            RuleId::JsxNoNewObjectAsProp,
            RuleId::JsxNoNewArrayAsProp,
            RuleId::JsxNoNewFunctionAsProp,
            RuleId::NoInlinePropOnMemoComponent,
        ]),
    );

    // ColdModal outside loop (line ~12) and CustomComparatorRow (line ~19) must produce 0 diagnostics
    for diag in &report.diagnostics {
        assert!(
            !diag.message.contains("CustomComparatorRow"),
            "Custom comparator memo component should not be flagged: {diag:#?}"
        );
    }

    // MemoizedRow must be flagged for object, array, function, and NoInlinePropOnMemoComponent
    assert!(
        report.diagnostics.iter().any(|d| {
            d.rule == RuleId::JsxNoNewObjectAsProp && d.message.contains("MemoizedRow")
        })
    );
    assert!(
        report.diagnostics.iter().any(|d| {
            d.rule == RuleId::JsxNoNewArrayAsProp && d.message.contains("MemoizedRow")
        })
    );
    assert!(report.diagnostics.iter().any(|d| {
        d.rule == RuleId::JsxNoNewFunctionAsProp && d.message.contains("MemoizedRow")
    }));
    assert!(report.diagnostics.iter().any(|d| {
        d.rule == RuleId::NoInlinePropOnMemoComponent && d.message.contains("MemoizedRow")
    }));

    // ColdModal inside `.map()` must be flagged (1 time, not 2 times, confirming the cold call outside `.map()` was suppressed!)
    let cold_modal_obj_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::JsxNoNewObjectAsProp && d.message.contains("ColdModal"))
        .collect();
    assert_eq!(
        cold_modal_obj_diags.len(),
        1,
        "Expected ColdModal to be flagged only inside .map() and suppressed on cold path, got: {cold_modal_obj_diags:#?}"
    );

    // EffectDepChild must be flagged because `options` feeds into its `useEffect` deps
    assert!(
        report.diagnostics.iter().any(|d| {
            d.rule == RuleId::JsxNoNewObjectAsProp && d.message.contains("EffectDepChild")
        }),
        "Expected EffectDepChild to be flagged when prop feeds into EffectNode deps"
    );
}

#[test]
fn project_graph_flags_unstable_and_overloaded_context_providers_and_missing_boundaries() {
    let files = vec![
        (
            PathBuf::from("src/AppContext.tsx"),
            r#"
            import { createContext, useState, useMemo } from 'react';

            export const AppContext = createContext({
                mouseX: 0,
                setMouseX: (_x: number) => {},
                appTitle: 'Dotore',
                themeMode: 'dark',
            });

            export function AppProvider({ appTitle, themeMode, children }) {
                const [mouseX, setMouseX] = useState(0);

                // Unmemoized local object literal passed to Provider
                const providerValue = {
                    mouseX,
                    setMouseX,
                    appTitle,
                    themeMode,
                };

                return (
                    <AppContext.Provider value={providerValue}>
                        <div onMouseMove={(e) => setMouseX(e.clientX)}>{children}</div>
                    </AppContext.Provider>
                );
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/StaticHeader.tsx"),
            r#"
            import { useContext } from 'react';
            import { AppContext } from './AppContext';

            // Only reads static `appTitle` and `themeMode`, never reads `mouseX`!
            export function StaticHeader() {
                const { appTitle, themeMode } = useContext(AppContext);
                return <header className={themeMode}>{appTitle}</header>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/CursorTracker.tsx"),
            r#"
            import { useContext } from 'react';
            import { AppContext } from './AppContext';

            export function CursorTracker() {
                const { mouseX } = useContext(AppContext);
                return <span>{mouseX}</span>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/SuspendingFeed.tsx"),
            r#"
            import { useSuspenseQuery } from '@tanstack/react-query';

            export function SuspendingFeed() {
                const { data } = useSuspenseQuery({ queryKey: ['feed'], queryFn: fetchFeed });
                return <div>{data}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/App.tsx"),
            r#"
            import { Suspense } from 'react';
            import { SuspendingFeed } from './SuspendingFeed';

            export function UnwrappedPage() {
                return (
                    <main>
                        <SuspendingFeed />
                    </main>
                );
            }

            export function WrappedPage() {
                return (
                    <Suspense fallback={<div>Loading...</div>}>
                        <SuspendingFeed />
                    </Suspense>
                );
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(
        files,
        Some(&[
            RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
            RuleId::OverloadedContextProvider,
            RuleId::MissingSuspenseOrErrorBoundary,
        ]),
    );

    // 1. Unstable Context.Provider value
    let unstable_ctx = report
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::ContextProviderValueFromUnmemoizedLocalLiteral)
        .expect("Expected ContextProviderValueFromUnmemoizedLocalLiteral diagnostic");
    assert_eq!(unstable_ctx.file, PathBuf::from("src/AppContext.tsx"));

    // 2. Overloaded Context.Provider (bundles `mouseX` state slot with static `appTitle`/`themeMode` read by `StaticHeader`)
    let overloaded_ctx = report
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::OverloadedContextProvider)
        .expect("Expected OverloadedContextProvider diagnostic");
    assert_eq!(overloaded_ctx.file, PathBuf::from("src/AppContext.tsx"));
    assert!(
        overloaded_ctx.message.contains("mouseX")
            && overloaded_ctx.message.contains("StaticHeader"),
        "Expected OverloadedContextProvider message to name state slot `mouseX` and static consumer `StaticHeader`, got: {}",
        overloaded_ctx.message
    );

    // 3. Missing ancestral <Suspense> boundary for SuspendingFeed at UnwrappedPage caller site (but NOT WrappedPage)
    let suspense_diag = report
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::MissingSuspenseOrErrorBoundary)
        .expect("Expected MissingSuspenseOrErrorBoundary diagnostic");
    assert_eq!(suspense_diag.caller_sites.len(), 1);
    assert_eq!(
        suspense_diag.caller_sites[0].parent_subject_name.as_deref(),
        Some("UnwrappedPage")
    );
}

#[test]
fn mechanical_rules_provide_deterministic_autofix_verified_by_round_trip_reanalysis() {
    // 1. `button-has-type` autofix injects `type="button"` inside `<form>`
    let button_src = r#"export function LoginForm() {
    return (
        <form>
            <button onClick={() => console.log('cancel')}>Cancel</button>
        </form>
    );
}
"#;
    let btn_diags = analyze_source(
        Path::new("LoginForm.tsx"),
        button_src,
        Some(&[RuleId::ButtonHasType]),
    );
    assert_eq!(btn_diags.len(), 1);
    assert_eq!(btn_diags[0].tier, PrescriptionTier::Autofix);
    let (btn_fixed, btn_desc) = apply_patches_to_source(button_src, &btn_diags);
    assert_eq!(btn_desc.len(), 1);
    assert!(btn_fixed.contains("<button type=\"button\" onClick="));
    let btn_reanalyzed = analyze_source(
        Path::new("LoginForm.tsx"),
        &btn_fixed,
        Some(&[RuleId::ButtonHasType]),
    );
    assert!(
        btn_reanalyzed.is_empty(),
        "Expected 0 diagnostics after button-has-type autofix, got: {btn_reanalyzed:#?}"
    );

    // 2. `prefer-module-scope-static-value` and `prefer-module-scope-pure-function` autofixes hoist to module scope
    let hoist_src = r#"export function DataTable({ rows }) {
    const COLUMNS = ['id', 'name', 'email'];
    const normalizeCell = (text: string) => text.trim().toLowerCase();
    return (
        <table>
            <thead>
                <tr>
                    {COLUMNS.map(col => <th key={col}>{normalizeCell(col)}</th>)}
                </tr>
            </thead>
            <tbody>
                {rows.map(r => <tr key={r.id}><td>{r.name}</td></tr>)}
            </tbody>
        </table>
    );
}
"#;
    let hoist_diags = analyze_source(
        Path::new("DataTable.tsx"),
        hoist_src,
        Some(&[
            RuleId::PreferModuleScopeStaticValue,
            RuleId::PreferModuleScopePureFunction,
        ]),
    );
    assert_eq!(hoist_diags.len(), 2);
    assert!(
        hoist_diags
            .iter()
            .all(|d| d.tier == PrescriptionTier::Autofix && d.autofix.is_some()),
        "Expected both hoisting rules to provide Autofix patches, got: {hoist_diags:#?}"
    );
    let (hoist_fixed, hoist_desc) = apply_patches_to_source(hoist_src, &hoist_diags);
    assert_eq!(hoist_desc.len(), 2);
    let export_pos = hoist_fixed.find("export function DataTable").unwrap();
    let cols_pos = hoist_fixed.find("const COLUMNS =").unwrap();
    let fn_pos = hoist_fixed.find("const normalizeCell =").unwrap();
    assert!(
        cols_pos < export_pos && fn_pos < export_pos,
        "Expected hoisted declarations above `export function DataTable`, got:\n{hoist_fixed}"
    );
    let hoist_reanalyzed = analyze_source(
        Path::new("DataTable.tsx"),
        &hoist_fixed,
        Some(&[
            RuleId::PreferModuleScopeStaticValue,
            RuleId::PreferModuleScopePureFunction,
        ]),
    );
    assert!(
        hoist_reanalyzed.is_empty(),
        "Expected 0 diagnostics after module-scope hoisting autofixes, got: {hoist_reanalyzed:#?}"
    );

    // 3. `rerender-lazy-state-init`, `rendering-conditional-render`, `jsx-no-target-blank`,
    //    `self-closing-comp`, `no-unknown-property`, `jsx-boolean-value`, `jsx-curly-brace-presence`
    let multi_autofix_src = r#"import { useState } from 'react';
export function PromoBanner({ items, rawJson }) {
    const [config] = useState(JSON.parse(rawJson));
    const sorted = items.sort();
    return (
        <div class="banner">
            <a href="https://example.com" target="_blank">Read docs</a>
            <Badge disabled={true} label={"featured"}></Badge>
            {items.length && <span>{config.title}{sorted.length}</span>}
        </div>
    );
}
"#;
    let multi_rules = [
        RuleId::RerenderLazyStateInit,
        RuleId::RenderingConditionalRender,
        RuleId::JsxNoTargetBlank,
        RuleId::SelfClosingComp,
        RuleId::NoUnknownProperty,
        RuleId::JsxBooleanValue,
        RuleId::JsxCurlyBracePresence,
        RuleId::NoMutatingArrayMethodOnPropOrHookResult,
    ];
    let multi_diags = analyze_source(
        Path::new("PromoBanner.tsx"),
        multi_autofix_src,
        Some(&multi_rules),
    );
    assert_eq!(multi_diags.len(), 8);
    assert!(
        multi_diags
            .iter()
            .all(|d| d.tier == PrescriptionTier::Autofix && d.autofix.is_some())
    );
    let (multi_fixed, multi_desc) = apply_patches_to_source(multi_autofix_src, &multi_diags);
    assert_eq!(multi_desc.len(), 8);
    assert!(multi_fixed.contains("useState(() => JSON.parse(rawJson))"));
    assert!(multi_fixed.contains("[...items].sort()"));
    assert!(multi_fixed.contains("className=\"banner\""));
    assert!(multi_fixed.contains("rel=\"noopener noreferrer\""));
    assert!(multi_fixed.contains("items.length > 0 &&"));
    let multi_reanalyzed = analyze_source(
        Path::new("PromoBanner.tsx"),
        &multi_fixed,
        Some(&multi_rules),
    );
    assert!(
        multi_reanalyzed.is_empty(),
        "Expected 0 diagnostics after multi-rule autofix, got: {multi_reanalyzed:#?}"
    );
}

#[test]
fn additional_family_rules_and_multihop_error_boundary_verification() {
    // 1. Additional correctness, architecture, and state-and-effects rules
    let extra_code = r#"
        import { useState, useEffect } from 'react';

        export function ExtraComponent({ user, items, defaults }) {
            const [handlerOnlyCount, setHandlerOnlyCount] = useState(0);
            const merged = { theme: 'dark', ...defaults };
            const localOpts = { retry: 3 };

            useEffect(() => {
                console.log(user.id, localOpts);
            }, [user, localOpts]);

            const sorted = items.sort();
            const isMatch = user.role === 'admin' || 'editor';

            const runAnim = (el: HTMLElement) => {
                el.animate([{ opacity: 0, offset: 0.8 }, { opacity: 1, offset: 0.2 }]);
            };

            return (
                <div onClick={() => { setHandlerOnlyCount(1); console.log(handlerOnlyCount, merged, sorted, isMatch, runAnim); }}>
                    <form><form /></form>
                    <button type="button"><a href="/x">Nested</a></button>
                    <table><tr><td>Cell</td></tr></table>
                    <input value="a" defaultValue="b" readOnly />
                </div>
            );
        }
        ExtraComponent.defaultProps = { items: [] };
        ExtraComponent.propTypes = {};
        ExtraComponent.contextTypes = {};
        ReactDOM.render(<ExtraComponent />, document.body);
    "#;
    let extra_rules = [
        RuleId::NoWholeObjectDepWithMemberReads,
        RuleId::RerenderDependencies,
        RuleId::RerenderStateOnlyInHandlers,
        RuleId::NoSpreadPropsOverDefaultsClobbersWithUndefined,
        RuleId::NoMutatingArrayMethodOnPropOrHookResult,
        RuleId::NoCollapsedLiteralOrChainAsValue,
        RuleId::WebAnimationOffsetsValid,
        RuleId::HtmlNoNestedForm,
        RuleId::HtmlNoNestedInteractive,
        RuleId::HtmlNoInvalidTableNesting,
        RuleId::NoUncontrolledInput,
        RuleId::NoDefaultProps,
        RuleId::NoPropTypes,
        RuleId::NoLegacyContextApi,
        RuleId::NoReactDomDeprecatedApis,
    ];
    let extra_diags = analyze_source(
        Path::new("ExtraComponent.tsx"),
        extra_code,
        Some(&extra_rules),
    );
    let fired: Vec<RuleId> = extra_diags.iter().map(|d| d.rule).collect();
    for expected in extra_rules {
        assert!(
            fired.contains(&expected),
            "Expected rule {expected:?} to fire in ExtraComponent.tsx, got: {fired:?}"
        );
    }

    // 2. Multi-hop ancestral `<ErrorBoundary>` and React 19 `<Ctx value={{...}}>` verification
    let files = vec![
        (
            PathBuf::from("src/ThrowingLeaf.tsx"),
            r#"
            export function ThrowingLeaf({ valid }) {
                if (!valid) {
                    throw new Error('Invalid state');
                }
                return <div>Valid</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/MiddlePanel.tsx"),
            r#"
            import { ThrowingLeaf } from './ThrowingLeaf';
            export function SafeMiddlePanel({ valid }) {
                return <section><ThrowingLeaf valid={valid} /></section>;
            }
            export function UnsafeMiddlePanel({ valid }) {
                return <section><ThrowingLeaf valid={valid} /></section>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/RootApp.tsx"),
            r#"
            import { createContext } from 'react';
            import { SafeMiddlePanel, UnsafeMiddlePanel } from './MiddlePanel';

            const ShorthandCtx = createContext(null);

            export function RootApp({ valid }) {
                return (
                    <ShorthandCtx value={{ a: 1 }}>
                        <AppErrorBoundary>
                            <SafeMiddlePanel valid={valid} />
                        </AppErrorBoundary>
                        <UnsafeMiddlePanel valid={valid} />
                    </ShorthandCtx>
                );
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(
        files,
        Some(&[
            RuleId::MissingSuspenseOrErrorBoundary,
            RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
        ]),
    );
    assert!(
        report.diagnostics.iter().any(|d| {
            d.rule == RuleId::ContextProviderValueFromUnmemoizedLocalLiteral
                && d.target_name == "ShorthandCtx"
        }),
        "Expected React 19 `<ShorthandCtx value={{...}}>` to be flagged"
    );
    let boundary_diag = report
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::MissingSuspenseOrErrorBoundary)
        .expect("Expected MissingSuspenseOrErrorBoundary for ThrowingLeaf");
    // SafeMiddlePanel is covered by AppErrorBoundary in RootApp, so only UnsafeMiddlePanel is uncovered!
    assert_eq!(boundary_diag.caller_sites.len(), 1);
    assert_eq!(
        boundary_diag.caller_sites[0].parent_subject_name.as_deref(),
        Some("UnsafeMiddlePanel")
    );
}
