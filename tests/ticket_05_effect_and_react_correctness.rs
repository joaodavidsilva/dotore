//! Integration tests for Ticket #6 (`05: Effect Node Teardown & React Component / Hook / JSX Correctness Rules`):
//! - 14 Effect Node & lifecycle cleanup rules
//! - 54 React component, hook, and JSX correctness rules
//! - Deterministic `Autofix` round-trips for `no-string-false-on-boolean-attribute`,
//!   `void-dom-elements-no-children`, `rendering-svg-precision`, and `effect-listener-cleanup-mismatch`.

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleId, RuleSeverityOverride,
    analyze_project_sources, analyze_source, analyze_source_with_config, apply_patches_to_source,
};

struct RuleTestCase {
    rule: RuleId,
    file_name: &'static str,
    invalid_code: &'static str,
    valid_code: &'static str,
}

fn assert_rule_invalid_and_valid(case: &RuleTestCase) {
    let invalid_diags = analyze_source(
        Path::new(case.file_name),
        case.invalid_code,
        Some(&[case.rule]),
    );
    assert!(
        !invalid_diags.is_empty(),
        "Expected rule {:?} ({}) to fire on invalid code:\n{}\ngot: {invalid_diags:#?}",
        case.rule,
        case.rule.as_str(),
        case.invalid_code
    );
    assert_eq!(invalid_diags[0].rule, case.rule);

    let valid_diags = analyze_source(
        Path::new(case.file_name),
        case.valid_code,
        Some(&[case.rule]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected rule {:?} ({}) to pass valid code:\n{}\ngot: {valid_diags:#?}",
        case.rule,
        case.rule.as_str(),
        case.valid_code
    );
}

#[test]
fn effect_node_and_lifecycle_teardown_14_rules_invalid_and_adversarial_valid() {
    let cases = [
        // 1. class-component-missing-component-will-unmount-teardown
        RuleTestCase {
            rule: RuleId::ClassComponentMissingComponentWillUnmountTeardown,
            file_name: "src/ResizeTracker.tsx",
            invalid_code: r#"
                import React from 'react';
                export class ResizeTracker extends React.Component {
                    componentDidMount() {
                        window.addEventListener('resize', this.handleResize);
                    }
                    handleResize = () => {};
                    render() {
                        return <div />;
                    }
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export class ResizeTracker extends React.Component {
                    componentDidMount() {
                        window.addEventListener('resize', this.handleResize);
                    }
                    componentWillUnmount() {
                        window.removeEventListener('resize', this.handleResize);
                    }
                    handleResize = () => {};
                    render() {
                        return <div />;
                    }
                }
            "#,
        },
        // 2. debounce-no-cleanup
        RuleTestCase {
            rule: RuleId::DebounceNoCleanup,
            file_name: "src/SearchInput.tsx",
            invalid_code: r#"
                import { useMemo } from 'react';
                import debounce from 'lodash/debounce';
                export function SearchInput({ onSearch }) {
                    const debouncedSearch = useMemo(() => debounce(onSearch, 300), [onSearch]);
                    return <input onChange={(e) => debouncedSearch(e.target.value)} />;
                }
            "#,
            valid_code: r#"
                import { useMemo, useEffect } from 'react';
                import debounce from 'lodash/debounce';
                export function SearchInput({ onSearch }) {
                    const debouncedSearch = useMemo(() => debounce(onSearch, 300), [onSearch]);
                    useEffect(() => {
                        return () => debouncedSearch.cancel();
                    }, [debouncedSearch]);
                    return <input onChange={(e) => debouncedSearch(e.target.value)} />;
                }
            "#,
        },
        // 3. effect-listener-cleanup-mismatch
        RuleTestCase {
            rule: RuleId::EffectListenerCleanupMismatch,
            file_name: "src/KeyWatcher.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function KeyWatcher() {
                    useEffect(() => {
                        const onKey = (e: KeyboardEvent) => console.log(e.key);
                        window.addEventListener('keydown', onKey);
                        return () => {
                            window.removeEventListener('keyup', onKey);
                        };
                    }, []);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function KeyWatcher() {
                    useEffect(() => {
                        const onKey = (e: KeyboardEvent) => console.log(e.key);
                        window.addEventListener('keydown', onKey);
                        return () => {
                            window.removeEventListener('keydown', onKey);
                        };
                    }, []);
                    return <div />;
                }
            "#,
        },
        // 4. effect-listener-cleanup-reference-mismatch
        RuleTestCase {
            rule: RuleId::EffectListenerCleanupReferenceMismatch,
            file_name: "src/ScrollWatcher.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function ScrollWatcher() {
                    useEffect(() => {
                        const handleScrollA = () => console.log('a');
                        const handleScrollB = () => console.log('b');
                        window.addEventListener('scroll', handleScrollA);
                        return () => {
                            window.removeEventListener('scroll', handleScrollB);
                        };
                    }, []);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function ScrollWatcher() {
                    useEffect(() => {
                        const handleScroll = () => console.log('scroll');
                        window.addEventListener('scroll', handleScroll);
                        return () => {
                            window.removeEventListener('scroll', handleScroll);
                        };
                    }, []);
                    return <div />;
                }
            "#,
        },
        // 5. effect-observer-needs-disconnect
        RuleTestCase {
            rule: RuleId::EffectObserverNeedsDisconnect,
            file_name: "src/BoxObserver.tsx",
            invalid_code: r#"
                import { useEffect, useRef } from 'react';
                export function BoxObserver() {
                    const ref = useRef(null);
                    useEffect(() => {
                        const observer = new ResizeObserver(() => {});
                        if (ref.current) observer.observe(ref.current);
                    }, []);
                    return <div ref={ref} />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useRef } from 'react';
                export function BoxObserver() {
                    const ref = useRef(null);
                    useEffect(() => {
                        const observer = new ResizeObserver(() => {});
                        if (ref.current) observer.observe(ref.current);
                        return () => observer.disconnect();
                    }, []);
                    return <div ref={ref} />;
                }
            "#,
        },
        // 6. effect-raf-loop-needs-cancel
        RuleTestCase {
            rule: RuleId::EffectRafLoopNeedsCancel,
            file_name: "src/RafTicker.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function RafTicker() {
                    useEffect(() => {
                        function tick() {
                            requestAnimationFrame(tick);
                        }
                        requestAnimationFrame(tick);
                    }, []);
                    return <canvas />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function RafTicker() {
                    useEffect(() => {
                        let id = 0;
                        function tick() {
                            id = requestAnimationFrame(tick);
                        }
                        id = requestAnimationFrame(tick);
                        return () => cancelAnimationFrame(id);
                    }, []);
                    return <canvas />;
                }
            "#,
        },
        // 7. effect-remove-listener-inline-handler
        RuleTestCase {
            rule: RuleId::EffectRemoveListenerInlineHandler,
            file_name: "src/InlineRemove.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function InlineRemove() {
                    useEffect(() => {
                        const onResize = () => console.log('resize');
                        window.addEventListener('resize', onResize);
                        return () => {
                            window.removeEventListener('resize', () => console.log('resize'));
                        };
                    }, []);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function InlineRemove() {
                    useEffect(() => {
                        const onResize = () => console.log('resize');
                        window.addEventListener('resize', onResize);
                        return () => {
                            window.removeEventListener('resize', onResize);
                        };
                    }, []);
                    return <div />;
                }
            "#,
        },
        // 8. no-async-effect-callback
        RuleTestCase {
            rule: RuleId::NoAsyncEffectCallback,
            file_name: "src/AsyncEffect.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function AsyncEffect() {
                    useEffect(async () => {
                        await Promise.resolve();
                    }, []);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function AsyncEffect() {
                    useEffect(() => {
                        async function run() {
                            await Promise.resolve();
                        }
                        void run();
                    }, []);
                    return <div />;
                }
            "#,
        },
        // 9. no-effect-event-in-deps
        RuleTestCase {
            rule: RuleId::NoEffectEventInDeps,
            file_name: "src/ChatRoom.tsx",
            invalid_code: r#"
                import { useEffect, useEffectEvent } from 'react';
                export function ChatRoom({ roomId, theme }) {
                    const onConnected = useEffectEvent(() => {
                        console.log('Connected with theme', theme);
                    });
                    useEffect(() => {
                        onConnected();
                    }, [roomId, onConnected]);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useEffectEvent } from 'react';
                export function ChatRoom({ roomId, theme }) {
                    const onConnected = useEffectEvent(() => {
                        console.log('Connected with theme', theme);
                    });
                    useEffect(() => {
                        onConnected();
                    }, [roomId]);
                    return <div />;
                }
            "#,
        },
        // 10. no-effect-with-fresh-deps
        RuleTestCase {
            rule: RuleId::NoEffectWithFreshDeps,
            file_name: "src/FreshDeps.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function FreshDeps({ userId }) {
                    const options = { userId, retries: 3 };
                    useEffect(() => {
                        console.log(options.userId);
                    }, [options]);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useMemo } from 'react';
                export function FreshDeps({ userId }) {
                    const options = useMemo(() => ({ userId, retries: 3 }), [userId]);
                    useEffect(() => {
                        console.log(options.userId);
                    }, [options]);
                    return <div />;
                }
            "#,
        },
        // 11. no-effect-wrapper-discards-callback-cleanup-return
        RuleTestCase {
            rule: RuleId::NoEffectWrapperDiscardsCallbackCleanupReturn,
            file_name: "src/useMountEffect.ts",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function useMountEffect(callback: () => void | (() => void)) {
                    useEffect(() => {
                        callback();
                    }, []);
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function useMountEffect(callback: () => void | (() => void)) {
                    useEffect(() => {
                        return callback();
                    }, []);
                }
            "#,
        },
        // 12. no-mutable-in-deps
        RuleTestCase {
            rule: RuleId::NoMutableInDeps,
            file_name: "src/MutableDeps.tsx",
            invalid_code: r#"
                import { useEffect, useRef } from 'react';
                export function MutableDeps() {
                    const boxRef = useRef<HTMLDivElement | null>(null);
                    useEffect(() => {
                        console.log(boxRef.current);
                    }, [boxRef.current]);
                    return <div ref={boxRef} />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useRef } from 'react';
                export function MutableDeps() {
                    const boxRef = useRef<HTMLDivElement | null>(null);
                    useEffect(() => {
                        console.log(boxRef.current);
                    }, []);
                    return <div ref={boxRef} />;
                }
            "#,
        },
        // 13. no-promise-then-side-effect-in-effect-without-catch
        RuleTestCase {
            rule: RuleId::NoPromiseThenSideEffectInEffectWithoutCatch,
            file_name: "src/ProfileLoader.tsx",
            invalid_code: r#"
                import { useEffect, useState } from 'react';
                export function ProfileLoader({ loadUser }) {
                    const [user, setUser] = useState(null);
                    useEffect(() => {
                        loadUser().then((u) => {
                            setUser(u);
                        });
                    }, [loadUser]);
                    return <div>{user}</div>;
                }
            "#,
            valid_code: r#"
                import { useEffect, useState } from 'react';
                export function ProfileLoader({ loadUser }) {
                    const [user, setUser] = useState(null);
                    useEffect(() => {
                        loadUser()
                            .then((u) => {
                                setUser(u);
                            })
                            .catch((err) => {
                                console.error(err);
                            });
                    }, [loadUser]);
                    return <div>{user}</div>;
                }
            "#,
        },
        // 14. no-ref-callback-cleanup-before-react-19
        RuleTestCase {
            rule: RuleId::NoRefCallbackCleanupBeforeReact19,
            file_name: "src/RefCleanup.tsx",
            invalid_code: r#"
                export function RefCleanup() {
                    return (
                        <div
                            ref={(node) => {
                                if (!node) return;
                                return () => {
                                    console.log('cleanup', node);
                                };
                            }}
                        />
                    );
                }
            "#,
            valid_code: r#"
                export function RefCleanup() {
                    return (
                        <div
                            ref={(node) => {
                                if (node) {
                                    console.log('mounted', node);
                                }
                            }}
                        />
                    );
                }
            "#,
        },
    ];

    for case in &cases {
        assert_rule_invalid_and_valid(case);
    }
}

#[test]
fn react_component_hook_and_jsx_correctness_54_rules_invalid_and_adversarial_valid() {
    let cases = [
        // 15. activity-wraps-effect-heavy-subtree
        RuleTestCase {
            rule: RuleId::ActivityWrapsEffectHeavySubtree,
            file_name: "src/ActivityTabs.tsx",
            invalid_code: r#"
                import { useEffect, Activity } from 'react';
                function HeavyPoller() {
                    useEffect(() => {
                        const id = setInterval(() => {}, 1000);
                        return () => clearInterval(id);
                    }, []);
                    return <div />;
                }
                export function ActivityTabs({ mode }) {
                    return (
                        <Activity mode={mode}>
                            <HeavyPoller />
                        </Activity>
                    );
                }
            "#,
            valid_code: r#"
                import { Activity } from 'react';
                function StaticView() {
                    return <div>Static</div>;
                }
                export function ActivityTabs({ mode }) {
                    return (
                        <Activity mode={mode}>
                            <StaticView />
                        </Activity>
                    );
                }
            "#,
        },
        // 16. advanced-event-handler-refs
        RuleTestCase {
            rule: RuleId::AdvancedEventHandlerRefs,
            file_name: "src/ListenerResubscribe.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function ListenerResubscribe({ onKeyDown }) {
                    useEffect(() => {
                        window.addEventListener('keydown', onKeyDown);
                        return () => window.removeEventListener('keydown', onKeyDown);
                    }, [onKeyDown]);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useRef } from 'react';
                export function ListenerResubscribe({ onKeyDown }) {
                    const handlerRef = useRef(onKeyDown);
                    useEffect(() => {
                        handlerRef.current = onKeyDown;
                    });
                    useEffect(() => {
                        const listener = (e: KeyboardEvent) => handlerRef.current(e);
                        window.addEventListener('keydown', listener);
                        return () => window.removeEventListener('keydown', listener);
                    }, []);
                    return <div />;
                }
            "#,
        },
        // 17. forbid-component-props
        RuleTestCase {
            rule: RuleId::ForbidComponentProps,
            file_name: "src/Caller.tsx",
            invalid_code: r#"
                export function Caller() {
                    return <CustomButton className="override" />;
                }
            "#,
            valid_code: r#"
                export function Caller() {
                    return <div className="container"><CustomButton variant="primary" /></div>;
                }
            "#,
        },
        // 18. forbid-dom-props
        RuleTestCase {
            rule: RuleId::ForbidDomProps,
            file_name: "src/LegacyTable.tsx",
            invalid_code: r##"
                export function LegacyTable() {
                    return <div bgcolor="#ffffff" />;
                }
            "##,
            valid_code: r#"
                export function LegacyTable() {
                    return <div className="bg-white" />;
                }
            "#,
        },
        // 19. forbid-elements
        RuleTestCase {
            rule: RuleId::ForbidElements,
            file_name: "src/Banner.tsx",
            invalid_code: r#"
                export function Banner() {
                    return <marquee>Breaking News</marquee>;
                }
            "#,
            valid_code: r#"
                export function Banner() {
                    return <section>Breaking News</section>;
                }
            "#,
        },
        // 20. forward-ref-uses-ref
        RuleTestCase {
            rule: RuleId::ForwardRefUsesRef,
            file_name: "src/FancyInput.tsx",
            invalid_code: r#"
                import { forwardRef } from 'react';
                export const FancyInput = forwardRef((props) => {
                    return <input {...props} />;
                });
            "#,
            valid_code: r#"
                import { forwardRef } from 'react';
                export const FancyInput = forwardRef((props, ref) => {
                    return <input ref={ref} {...props} />;
                });
            "#,
        },
        // 21. hook-import-rename-loses-use-prefix
        RuleTestCase {
            rule: RuleId::HookImportRenameLosesUsePrefix,
            file_name: "src/BadImport.tsx",
            invalid_code: r#"
                import { useState as createState } from 'react';
                export function BadImport() {
                    const [count] = createState(0);
                    return <div>{count}</div>;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                import { useAuth as useUserAuth } from './auth';
                export function GoodImport() {
                    const [count] = useState(0);
                    const auth = useUserAuth();
                    return <div>{count}{String(auth)}</div>;
                }
            "#,
        },
        // 22. hooks-no-nan-in-deps
        RuleTestCase {
            rule: RuleId::HooksNoNanInDeps,
            file_name: "src/NanDeps.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function NanDeps() {
                    useEffect(() => {
                        console.log('effect');
                    }, [NaN]);
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function NanDeps({ count }) {
                    useEffect(() => {
                        console.log(count);
                    }, [count]);
                    return <div />;
                }
            "#,
        },
        // 23. html-label-has-single-control
        RuleTestCase {
            rule: RuleId::HtmlLabelHasSingleControl,
            file_name: "src/MultiControlLabel.tsx",
            invalid_code: r#"
                export function MultiControlLabel() {
                    return (
                        <label>
                            Name
                            <input type="text" />
                            <input type="text" />
                        </label>
                    );
                }
            "#,
            valid_code: r#"
                export function SingleControlLabel() {
                    return (
                        <label>
                            Name
                            <input type="text" />
                        </label>
                    );
                }
            "#,
        },
        // 24. html-no-invalid-paragraph-child
        RuleTestCase {
            rule: RuleId::HtmlNoInvalidParagraphChild,
            file_name: "src/BadParagraph.tsx",
            invalid_code: r#"
                export function BadParagraph() {
                    return <p><div>Block inside paragraph</div></p>;
                }
            "#,
            valid_code: r#"
                export function GoodParagraph() {
                    return <p><span>Inline inside paragraph</span></p>;
                }
            "#,
        },
        // 25. jsx-filename-extension
        RuleTestCase {
            rule: RuleId::JsxFilenameExtension,
            file_name: "src/ComponentInJs.js",
            invalid_code: r#"
                export function ComponentInJs() {
                    return <div>Hello</div>;
                }
            "#,
            valid_code: r#"
                export function helperInJs(a, b) {
                    return a + b;
                }
            "#,
        },
        // 26. jsx-no-comment-textnodes
        RuleTestCase {
            rule: RuleId::JsxNoCommentTextnodes,
            file_name: "src/CommentText.tsx",
            invalid_code: r#"
                export function CommentText() {
                    return (
                        <div>
                            // accidental comment rendered as text
                            <span>Content</span>
                        </div>
                    );
                }
            "#,
            valid_code: r#"
                export function CommentText() {
                    return (
                        <div>
                            {/* proper comment */}
                            <span>https://example.com</span>
                        </div>
                    );
                }
            "#,
        },
        // 27. jsx-no-duplicate-props
        RuleTestCase {
            rule: RuleId::JsxNoDuplicateProps,
            file_name: "src/DupProps.tsx",
            invalid_code: r#"
                export function DupProps() {
                    return <div id="first" className="box" id="second" />;
                }
            "#,
            valid_code: r#"
                export function DupProps() {
                    return <div id="first" className="box" />;
                }
            "#,
        },
        // 28. jsx-no-jsx-as-prop
        RuleTestCase {
            rule: RuleId::JsxNoJsxAsProp,
            file_name: "src/PageHeader.tsx",
            invalid_code: r#"
                export function PageHeader() {
                    return <Card header={<h1>Title</h1>} />;
                }
            "#,
            valid_code: r#"
                const HEADER = <h1>Title</h1>;
                export function PageHeader() {
                    return <Card header={HEADER} />;
                }
            "#,
        },
        // 29. jsx-props-no-spread-multi
        RuleTestCase {
            rule: RuleId::JsxPropsNoSpreadMulti,
            file_name: "src/MultiSpread.tsx",
            invalid_code: r#"
                export function MultiSpread({ a, b }) {
                    return <div {...a} {...b} />;
                }
            "#,
            valid_code: r#"
                export function SingleSpread({ a }) {
                    return <div {...a} id="main" />;
                }
            "#,
        },
        // 30. no-boolean-toggle-without-functional-update
        RuleTestCase {
            rule: RuleId::NoBooleanToggleWithoutFunctionalUpdate,
            file_name: "src/ToggleButton.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function ToggleButton() {
                    const [open, setOpen] = useState(false);
                    return <button onClick={() => setOpen(!open)}>{String(open)}</button>;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function ToggleButton() {
                    const [open, setOpen] = useState(false);
                    return <button onClick={() => setOpen((prev) => !prev)}>{String(open)}</button>;
                }
            "#,
        },
        // 31. no-call-component-as-function
        RuleTestCase {
            rule: RuleId::NoCallComponentAsFunction,
            file_name: "src/DirectCall.tsx",
            invalid_code: r#"
                function ChildBadge({ label }: { label: string }) {
                    return <span>{label}</span>;
                }
                export function DirectCall() {
                    return <div>{ChildBadge({ label: 'Hi' })}</div>;
                }
            "#,
            valid_code: r#"
                function ChildBadge({ label }: { label: string }) {
                    return <span>{label}</span>;
                }
                export function DirectCall() {
                    return <div><ChildBadge label="Hi" /></div>;
                }
            "#,
        },
        // 32. no-cascading-set-state
        RuleTestCase {
            rule: RuleId::NoCascadingSetState,
            file_name: "src/CascadingEffect.tsx",
            invalid_code: r#"
                import { useState, useEffect } from 'react';
                export function CascadingEffect({ raw }) {
                    const [a, setA] = useState(0);
                    const [b, setB] = useState(0);
                    useEffect(() => {
                        setA(raw);
                        setB(raw * 2);
                    }, [raw]);
                    return <div>{a + b}</div>;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function CascadingEffect({ raw }) {
                    const [a] = useState(raw);
                    return <div>{a}</div>;
                }
            "#,
        },
        // 33. no-children-prop
        RuleTestCase {
            rule: RuleId::NoChildrenProp,
            file_name: "src/ChildrenProp.tsx",
            invalid_code: r#"
                export function ChildrenProp() {
                    return <div children="Hello" />;
                }
            "#,
            valid_code: r#"
                export function ChildrenProp() {
                    return <div>Hello</div>;
                }
            "#,
        },
        // 34. no-clone-element
        RuleTestCase {
            rule: RuleId::NoCloneElement,
            file_name: "src/CloneWrapper.tsx",
            invalid_code: r#"
                import { cloneElement } from 'react';
                export function CloneWrapper({ child }) {
                    return cloneElement(child, { active: true });
                }
            "#,
            valid_code: r#"
                export function CloneWrapper({ renderChild }) {
                    return renderChild({ active: true });
                }
            "#,
        },
        // 35. no-create-context-in-render
        RuleTestCase {
            rule: RuleId::NoCreateContextInRender,
            file_name: "src/InlineContext.tsx",
            invalid_code: r#"
                import { createContext } from 'react';
                export function InlineContext({ children }) {
                    const Ctx = createContext(null);
                    return <Ctx.Provider value={null}>{children}</Ctx.Provider>;
                }
            "#,
            valid_code: r#"
                import { createContext } from 'react';
                const Ctx = createContext(null);
                export function InlineContext({ children }) {
                    return <Ctx.Provider value={null}>{children}</Ctx.Provider>;
                }
            "#,
        },
        // 36. no-create-object-url-in-render
        RuleTestCase {
            rule: RuleId::NoCreateObjectUrlInRender,
            file_name: "src/BlobPreview.tsx",
            invalid_code: r#"
                export function BlobPreview({ file }: { file: Blob }) {
                    const previewUrl = URL.createObjectURL(file);
                    return <img src={previewUrl} alt="preview" />;
                }
            "#,
            valid_code: r#"
                import { useEffect, useState } from 'react';
                export function BlobPreview({ file }: { file: Blob }) {
                    const [previewUrl, setPreviewUrl] = useState('');
                    useEffect(() => {
                        const url = URL.createObjectURL(file);
                        setPreviewUrl(url);
                        return () => URL.revokeObjectURL(url);
                    }, [file]);
                    return <img src={previewUrl} alt="preview" />;
                }
            "#,
        },
        // 37. no-create-ref-in-function-component
        RuleTestCase {
            rule: RuleId::NoCreateRefInFunctionComponent,
            file_name: "src/FuncCreateRef.tsx",
            invalid_code: r#"
                import { createRef } from 'react';
                export function FuncCreateRef() {
                    const inputRef = createRef<HTMLInputElement>();
                    return <input ref={inputRef} />;
                }
            "#,
            valid_code: r#"
                import { useRef } from 'react';
                export function FuncCreateRef() {
                    const inputRef = useRef<HTMLInputElement>(null);
                    return <input ref={inputRef} />;
                }
            "#,
        },
        // 38. no-create-store-in-render
        RuleTestCase {
            rule: RuleId::NoCreateStoreInRender,
            file_name: "src/StoreInRender.tsx",
            invalid_code: r#"
                import { createStore } from 'redux';
                export function StoreInRender({ reducer }) {
                    const store = createStore(reducer);
                    return <div>{String(store)}</div>;
                }
            "#,
            valid_code: r#"
                import { createStore } from 'redux';
                const store = createStore(() => ({}));
                export function StoreInRender() {
                    return <div>{String(store)}</div>;
                }
            "#,
        },
        // 39. no-fill-map-element-as-key
        RuleTestCase {
            rule: RuleId::NoFillMapElementAsKey,
            file_name: "src/SkeletonList.tsx",
            invalid_code: r#"
                export function SkeletonList() {
                    return (
                        <ul>
                            {Array(5).fill(0).map((n) => (
                                <li key={n}>Item</li>
                            ))}
                        </ul>
                    );
                }
            "#,
            valid_code: r#"
                export function SkeletonList() {
                    return (
                        <ul>
                            {Array(5).fill(0).map((_, index) => (
                                <li key={index}>Item</li>
                            ))}
                        </ul>
                    );
                }
            "#,
        },
        // 40. no-find-dom-node
        RuleTestCase {
            rule: RuleId::NoFindDomNode,
            file_name: "src/LegacyDomNode.tsx",
            invalid_code: r#"
                import ReactDOM from 'react-dom';
                export function LegacyDomNode(instance: unknown) {
                    const node = ReactDOM.findDOMNode(instance);
                    return <div>{String(node)}</div>;
                }
            "#,
            valid_code: r#"
                import { useRef } from 'react';
                export function LegacyDomNode() {
                    const ref = useRef<HTMLDivElement>(null);
                    return <div ref={ref} />;
                }
            "#,
        },
        // 41. no-impure-call-at-module-scope
        RuleTestCase {
            rule: RuleId::NoImpureCallAtModuleScope,
            file_name: "src/ModuleRandom.tsx",
            invalid_code: r#"
                const REQUEST_SEED = Math.random();
                export function ModuleRandom() {
                    return <div>{REQUEST_SEED}</div>;
                }
            "#,
            valid_code: r#"
                export function ModuleRandom() {
                    const seed = 42;
                    return <div>{seed}</div>;
                }
            "#,
        },
        // 42. no-impure-state-updater
        RuleTestCase {
            rule: RuleId::NoImpureStateUpdater,
            file_name: "src/ImpureUpdater.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function ImpureUpdater() {
                    const [items, setItems] = useState<number[]>([]);
                    return (
                        <button
                            onClick={() =>
                                setItems((prev) => {
                                    prev.push(1);
                                    localStorage.setItem('items', JSON.stringify(prev));
                                    return prev;
                                })
                            }
                        >
                            Add
                        </button>
                    );
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function ImpureUpdater() {
                    const [items, setItems] = useState<number[]>([]);
                    return (
                        <button onClick={() => setItems((prev) => [...prev, 1])}>
                            {items.length}
                        </button>
                    );
                }
            "#,
        },
        // 43. no-indeterminate-attribute
        RuleTestCase {
            rule: RuleId::NoIndeterminateAttribute,
            file_name: "src/TriCheckbox.tsx",
            invalid_code: r#"
                export function TriCheckbox() {
                    return <input type="checkbox" indeterminate={true} />;
                }
            "#,
            valid_code: r#"
                export function TriCheckbox() {
                    return (
                        <input
                            type="checkbox"
                            ref={(el) => {
                                if (el) el.indeterminate = true;
                            }}
                        />
                    );
                }
            "#,
        },
        // 44. no-is-mounted
        RuleTestCase {
            rule: RuleId::NoIsMounted,
            file_name: "src/LegacyMounted.tsx",
            invalid_code: r#"
                import React from 'react';
                export class LegacyMounted extends React.Component {
                    handleData() {
                        if (this.isMounted()) {
                            console.log('still mounted');
                        }
                    }
                    render() {
                        return <div />;
                    }
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export class LegacyMounted extends React.Component {
                    render() {
                        return <div />;
                    }
                }
            "#,
        },
        // 45. no-jsx-element-type
        RuleTestCase {
            rule: RuleId::NoJsxElementType,
            file_name: "src/TypedComp.tsx",
            invalid_code: r#"
                export function TypedComp(): JSX.Element {
                    return <div />;
                }
            "#,
            valid_code: r#"
                import type { ReactNode } from 'react';
                export function TypedComp(): ReactNode {
                    return <div />;
                }
            "#,
        },
        // 46. no-mixed-srcset-descriptors
        RuleTestCase {
            rule: RuleId::NoMixedSrcsetDescriptors,
            file_name: "src/HeroImg.tsx",
            invalid_code: r#"
                export function HeroImg() {
                    return <img src="a.jpg" srcSet="small.jpg 400w, retina.jpg 2x" alt="hero" />;
                }
            "#,
            valid_code: r#"
                export function HeroImg() {
                    return <img src="a.jpg" srcSet="small.jpg 400w, large.jpg 800w" sizes="100vw" alt="hero" />;
                }
            "#,
        },
        // 47. no-multi-comp
        RuleTestCase {
            rule: RuleId::NoMultiComp,
            file_name: "src/TwoComps.tsx",
            invalid_code: r#"
                export function FirstComp() {
                    return <div>First</div>;
                }
                export function SecondComp() {
                    return <div>Second</div>;
                }
            "#,
            valid_code: r#"
                function formatLabel(text: string) {
                    return text.trim();
                }
                export function OnlyComp({ text }: { text: string }) {
                    return <div>{formatLabel(text)}</div>;
                }
            "#,
        },
        // 48. no-multi-component-file
        RuleTestCase {
            rule: RuleId::NoMultiComponentFile,
            file_name: "src/CrowdedComps.tsx",
            invalid_code: r#"
                export function AlphaComp() {
                    return <div>Alpha</div>;
                }
                export function BetaComp() {
                    return <div>Beta</div>;
                }
            "#,
            valid_code: r#"
                export function SingleComp() {
                    return <div>Single</div>;
                }
            "#,
        },
        // 49. no-mutate-queried-dom-node-in-component
        RuleTestCase {
            rule: RuleId::NoMutateQueriedDomNodeInComponent,
            file_name: "src/DomMutator.tsx",
            invalid_code: r#"
                import { useEffect } from 'react';
                export function DomMutator() {
                    useEffect(() => {
                        const el = document.getElementById('panel');
                        if (el) {
                            el.style.display = 'none';
                        }
                    }, []);
                    return <div id="panel" />;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function DomMutator() {
                    const [hidden] = useState(true);
                    return <div id="panel" hidden={hidden} />;
                }
            "#,
        },
        // 50. no-mutate-then-set-or-return-same-reference
        RuleTestCase {
            rule: RuleId::NoMutateThenSetOrReturnSameReference,
            file_name: "src/SameRefSetter.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function SameRefSetter() {
                    const [list, setList] = useState<number[]>([]);
                    const handleAdd = () => {
                        list.push(42);
                        setList(list);
                    };
                    return <button onClick={handleAdd}>{list.length}</button>;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function SameRefSetter() {
                    const [list, setList] = useState<number[]>([]);
                    const handleAdd = () => {
                        setList((prev) => [...prev, 42]);
                    };
                    return <button onClick={handleAdd}>{list.length}</button>;
                }
            "#,
        },
        // 51. no-mutating-reducer-state
        RuleTestCase {
            rule: RuleId::NoMutatingReducerState,
            file_name: "src/CounterReducer.tsx",
            invalid_code: r#"
                import { useReducer } from 'react';
                function counterReducer(state: { count: number }, action: { type: string }) {
                    if (action.type === 'inc') {
                        state.count += 1;
                        return state;
                    }
                    return state;
                }
                export function CounterReducer() {
                    const [state] = useReducer(counterReducer, { count: 0 });
                    return <div>{state.count}</div>;
                }
            "#,
            valid_code: r#"
                import { useReducer } from 'react';
                function counterReducer(state: { count: number }, action: { type: string }) {
                    if (action.type === 'inc') {
                        return { ...state, count: state.count + 1 };
                    }
                    return state;
                }
                export function CounterReducer() {
                    const [state] = useReducer(counterReducer, { count: 0 });
                    return <div>{state.count}</div>;
                }
            "#,
        },
        // 52. no-namespace
        RuleTestCase {
            rule: RuleId::NoNamespace,
            file_name: "src/NamespacedJsx.tsx",
            invalid_code: r#"
                export function NamespacedJsx() {
                    return <ns:Widget />;
                }
            "#,
            valid_code: r#"
                export function NamespacedJsx() {
                    return <Widget />;
                }
            "#,
        },
        // 53. no-nondeterministic-id-value-in-render-body
        RuleTestCase {
            rule: RuleId::NoNondeterministicIdValueInRenderBody,
            file_name: "src/RandomIdField.tsx",
            invalid_code: r#"
                export function RandomIdField() {
                    const id = crypto.randomUUID();
                    return <input id={id} />;
                }
            "#,
            valid_code: r#"
                import { useId } from 'react';
                export function RandomIdField() {
                    const id = useId();
                    return <input id={id} />;
                }
            "#,
        },
        // 54. no-polymorphic-children
        RuleTestCase {
            rule: RuleId::NoPolymorphicChildren,
            file_name: "src/PolymorphicBox.tsx",
            invalid_code: r#"
                export function PolymorphicBox({ children }) {
                    if (typeof children === 'string') {
                        return <span>{children}</span>;
                    }
                    return <div>{children}</div>;
                }
            "#,
            valid_code: r#"
                export function PolymorphicBox({ children }) {
                    return <div>{children}</div>;
                }
            "#,
        },
        // 55. no-react-children
        RuleTestCase {
            rule: RuleId::NoReactChildren,
            file_name: "src/ChildrenMapper.tsx",
            invalid_code: r#"
                import React from 'react';
                export function ChildrenMapper({ children }) {
                    return <div>{React.Children.map(children, (child) => child)}</div>;
                }
            "#,
            valid_code: r#"
                export function ChildrenMapper({ children }) {
                    return <div>{children}</div>;
                }
            "#,
        },
        // 56. no-redundant-should-component-update
        RuleTestCase {
            rule: RuleId::NoRedundantShouldComponentUpdate,
            file_name: "src/PureWithScu.tsx",
            invalid_code: r#"
                import React from 'react';
                export class PureWithScu extends React.PureComponent {
                    shouldComponentUpdate(nextProps: unknown) {
                        return nextProps !== this.props;
                    }
                    render() {
                        return <div />;
                    }
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export class PureWithoutScu extends React.PureComponent {
                    render() {
                        return <div />;
                    }
                }
            "#,
        },
        // 57. no-render-return-value
        RuleTestCase {
            rule: RuleId::NoRenderReturnValue,
            file_name: "src/MountApp.tsx",
            invalid_code: r#"
                import ReactDOM from 'react-dom';
                export function mount(container: Element) {
                    const app = ReactDOM.render(<div />, container);
                    return app;
                }
            "#,
            valid_code: r#"
                import ReactDOM from 'react-dom';
                export function mount(container: Element) {
                    ReactDOM.render(<div />, container);
                }
            "#,
        },
        // 58. no-set-state
        RuleTestCase {
            rule: RuleId::NoSetState,
            file_name: "src/StatefulClass.tsx",
            invalid_code: r#"
                import React from 'react';
                export class StatefulClass extends React.Component {
                    increment() {
                        this.setState({ count: 1 });
                    }
                    render() {
                        return <div />;
                    }
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export class StatelessClass extends React.Component<{ count: number }> {
                    render() {
                        return <div>{this.props.count}</div>;
                    }
                }
            "#,
        },
        // 59. no-string-false-on-boolean-attribute
        RuleTestCase {
            rule: RuleId::NoStringFalseOnBooleanAttribute,
            file_name: "src/StringBoolAttr.tsx",
            invalid_code: r#"
                export function StringBoolAttr() {
                    return <button type="button" disabled="false">Submit</button>;
                }
            "#,
            valid_code: r#"
                export function StringBoolAttr() {
                    return <button type="button" disabled={false}>Submit</button>;
                }
            "#,
        },
        // 60. no-this-in-sfc
        RuleTestCase {
            rule: RuleId::NoThisInSfc,
            file_name: "src/ThisInSfc.tsx",
            invalid_code: r#"
                export function ThisInSfc(props: { label: string }) {
                    return <div>{this.props.label}</div>;
                }
            "#,
            valid_code: r#"
                export function ThisInSfc(props: { label: string }) {
                    return <div>{props.label}</div>;
                }
            "#,
        },
        // 61. no-unescaped-entities
        RuleTestCase {
            rule: RuleId::NoUnescapedEntities,
            file_name: "src/UnescapedQuote.tsx",
            invalid_code: r#"
                export function UnescapedQuote() {
                    return <p>Don't forget to escape</p>;
                }
            "#,
            valid_code: r#"
                export function EscapedQuote() {
                    return <p>Do not forget to escape</p>;
                }
            "#,
        },
        // 62. no-unguarded-browser-global-at-module-scope
        RuleTestCase {
            rule: RuleId::NoUnguardedBrowserGlobalAtModuleScope,
            file_name: "src/ModuleWindow.tsx",
            invalid_code: r#"
                const INITIAL_WIDTH = window.innerWidth;
                export function ModuleWindow() {
                    return <div>{INITIAL_WIDTH}</div>;
                }
            "#,
            valid_code: r#"
                const INITIAL_WIDTH = typeof window !== 'undefined' ? window.innerWidth : 0;
                export function ModuleWindow() {
                    return <div>{INITIAL_WIDTH}</div>;
                }
            "#,
        },
        // 63. pointer-capture-needs-cancel-handler
        RuleTestCase {
            rule: RuleId::PointerCaptureNeedsCancelHandler,
            file_name: "src/DragHandle.tsx",
            invalid_code: r#"
                export function DragHandle() {
                    return (
                        <div
                            onPointerDown={(e) => e.currentTarget.setPointerCapture(e.pointerId)}
                            onPointerUp={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
                        />
                    );
                }
            "#,
            valid_code: r#"
                export function DragHandle() {
                    return (
                        <div
                            onPointerDown={(e) => e.currentTarget.setPointerCapture(e.pointerId)}
                            onPointerUp={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
                            onPointerCancel={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
                        />
                    );
                }
            "#,
        },
        // 64. react-in-jsx-scope
        RuleTestCase {
            rule: RuleId::ReactInJsxScope,
            file_name: "src/MissingReactScope.tsx",
            invalid_code: r#"
                export function MissingReactScope() {
                    return <div>Hello</div>;
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export function WithReactScope() {
                    return <div>Hello</div>;
                }
            "#,
        },
        // 65. rendering-svg-precision
        RuleTestCase {
            rule: RuleId::RenderingSvgPrecision,
            file_name: "src/PreciseIcon.tsx",
            invalid_code: r#"
                export function PreciseIcon() {
                    return (
                        <svg viewBox="0 0 24 24">
                            <path d="M10.12345 20.67891L30.55555 40.1" />
                        </svg>
                    );
                }
            "#,
            valid_code: r#"
                export function PreciseIcon() {
                    return (
                        <svg viewBox="0 0 24 24">
                            <path d="M10.12 20.68L30.56 40.1" />
                        </svg>
                    );
                }
            "#,
        },
        // 66. require-render-return
        RuleTestCase {
            rule: RuleId::RequireRenderReturn,
            file_name: "src/BrokenClassRender.tsx",
            invalid_code: r#"
                import React from 'react';
                export class BrokenClassRender extends React.Component {
                    render() {
                        const x = 1;
                        console.log(x);
                    }
                }
            "#,
            valid_code: r#"
                import React from 'react';
                export class ValidClassRender extends React.Component {
                    render() {
                        return <div>Ready</div>;
                    }
                }
            "#,
        },
        // 67. void-dom-elements-no-children
        RuleTestCase {
            rule: RuleId::VoidDomElementsNoChildren,
            file_name: "src/VoidChildren.tsx",
            invalid_code: r#"
                export function VoidChildren() {
                    return <br>Invalid child</br>;
                }
            "#,
            valid_code: r#"
                export function VoidChildren() {
                    return <br />;
                }
            "#,
        },
        // 68. waapi-animation-in-render
        RuleTestCase {
            rule: RuleId::WaapiAnimationInRender,
            file_name: "src/WaapiRender.tsx",
            invalid_code: r#"
                export function WaapiRender({ el }: { el: HTMLElement }) {
                    el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200 });
                    return <div />;
                }
            "#,
            valid_code: r#"
                import { useEffect } from 'react';
                export function WaapiRender({ el }: { el: HTMLElement }) {
                    useEffect(() => {
                        el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200 });
                    }, [el]);
                    return <div />;
                }
            "#,
        },
    ];

    assert_eq!(cases.len(), 54);
    for case in &cases {
        assert_rule_invalid_and_valid(case);
    }
}

#[test]
fn autofix_round_trips_for_boolean_attr_void_dom_children_and_svg_precision() {
    // 1. no-string-false-on-boolean-attribute
    let bool_src = r#"export function Btn() {
    return <button type="button" disabled="false">Save</button>;
}
"#;
    let bool_diags = analyze_source(
        Path::new("src/Btn.tsx"),
        bool_src,
        Some(&[RuleId::NoStringFalseOnBooleanAttribute]),
    );
    assert_eq!(bool_diags.len(), 1);
    assert_eq!(bool_diags[0].tier, PrescriptionTier::Autofix);
    let (bool_fixed, bool_descs) = apply_patches_to_source(bool_src, &bool_diags);
    assert_eq!(bool_descs.len(), 1);
    assert!(bool_fixed.contains("disabled={false}"));
    let bool_reanalyzed = analyze_source(
        Path::new("src/Btn.tsx"),
        &bool_fixed,
        Some(&[RuleId::NoStringFalseOnBooleanAttribute]),
    );
    assert!(bool_reanalyzed.is_empty());

    // 2. void-dom-elements-no-children
    let void_src = r#"export function Divider() {
    return <hr className="sep">not allowed</hr>;
}
"#;
    let void_diags = analyze_source(
        Path::new("src/Divider.tsx"),
        void_src,
        Some(&[RuleId::VoidDomElementsNoChildren]),
    );
    assert_eq!(void_diags.len(), 1);
    assert_eq!(void_diags[0].tier, PrescriptionTier::Autofix);
    let (void_fixed, void_descs) = apply_patches_to_source(void_src, &void_diags);
    assert_eq!(void_descs.len(), 1);
    assert!(void_fixed.contains("<hr className=\"sep\" />"));
    let void_reanalyzed = analyze_source(
        Path::new("src/Divider.tsx"),
        &void_fixed,
        Some(&[RuleId::VoidDomElementsNoChildren]),
    );
    assert!(void_reanalyzed.is_empty());

    // 3. rendering-svg-precision
    let svg_src = r#"export function Icon() {
    return <svg><path d="M1.23456 2.34567L3.45678 4.0" /></svg>;
}
"#;
    let svg_diags = analyze_source(
        Path::new("src/Icon.tsx"),
        svg_src,
        Some(&[RuleId::RenderingSvgPrecision]),
    );
    assert_eq!(svg_diags.len(), 1);
    assert_eq!(svg_diags[0].tier, PrescriptionTier::Autofix);
    let (svg_fixed, svg_descs) = apply_patches_to_source(svg_src, &svg_diags);
    assert_eq!(svg_descs.len(), 1);
    assert!(svg_fixed.contains("d=\"M1.23 2.35L3.46 4.0\""));
    let svg_reanalyzed = analyze_source(
        Path::new("src/Icon.tsx"),
        &svg_fixed,
        Some(&[RuleId::RenderingSvgPrecision]),
    );
    assert!(svg_reanalyzed.is_empty());

    // 4. effect-listener-cleanup-mismatch
    let listener_src = r#"import { useEffect } from 'react';
export function KeyListener() {
    useEffect(() => {
        const onKey = () => {};
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keyup', onKey);
    }, []);
    return <div />;
}
"#;
    let listener_diags = analyze_source(
        Path::new("src/KeyListener.tsx"),
        listener_src,
        Some(&[RuleId::EffectListenerCleanupMismatch]),
    );
    assert_eq!(listener_diags.len(), 1);
    assert_eq!(listener_diags[0].tier, PrescriptionTier::Autofix);
    let (listener_fixed, listener_descs) = apply_patches_to_source(listener_src, &listener_diags);
    assert_eq!(listener_descs.len(), 1);
    let listener_reanalyzed = analyze_source(
        Path::new("src/KeyListener.tsx"),
        &listener_fixed,
        Some(&[RuleId::EffectListenerCleanupMismatch]),
    );
    assert!(listener_reanalyzed.is_empty());
}

#[test]
fn capability_gates_govern_ssr_react_compiler_and_react_19_ref_cleanup() {
    let ssr_code = r#"
        const START_TIME = Date.now();
        const INITIAL_HREF = window.location.href;
        export function ServerPage() {
            return <div>{START_TIME}{INITIAL_HREF}</div>;
        }
    "#;
    let mut cfg = DotoreConfig::default();
    cfg.rules.insert(
        "no-impure-call-at-module-scope".to_string(),
        RuleSeverityOverride::Warn,
    );

    let client_gate = CapabilityGate::with_capabilities([Capability::React]);
    let client_diags = analyze_source_with_config(
        Path::new("src/ServerPage.tsx"),
        ssr_code,
        &cfg,
        &client_gate,
        None,
    );
    assert!(
        !client_diags.iter().any(|d| matches!(
            d.rule,
            RuleId::NoImpureCallAtModuleScope | RuleId::NoUnguardedBrowserGlobalAtModuleScope
        )),
        "SSR-only module-scope rules must not fire without Ssr capability"
    );

    let ssr_gate = CapabilityGate::with_capabilities([Capability::React, Capability::Ssr]);
    let ssr_diags = analyze_source_with_config(
        Path::new("src/ServerPage.tsx"),
        ssr_code,
        &cfg,
        &ssr_gate,
        None,
    );
    assert!(
        ssr_diags
            .iter()
            .any(|d| d.rule == RuleId::NoImpureCallAtModuleScope)
    );
    assert!(
        ssr_diags
            .iter()
            .any(|d| d.rule == RuleId::NoUnguardedBrowserGlobalAtModuleScope)
    );

    // React 18 vs React 19 package.json gating for `no-ref-callback-cleanup-before-react-19`
    let ref_cleanup_src = r#"
        export function Box() {
            return <div ref={(node) => () => console.log(node)} />;
        }
    "#;
    let react18_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "dependencies": { "react": "^18.2.0" } }"#.to_string(),
            ),
            (PathBuf::from("src/Box.tsx"), ref_cleanup_src.to_string()),
        ],
        None,
    );
    assert!(
        react18_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::NoRefCallbackCleanupBeforeReact19)
    );

    let react19_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "dependencies": { "react": "^19.0.0" } }"#.to_string(),
            ),
            (PathBuf::from("src/Box.tsx"), ref_cleanup_src.to_string()),
        ],
        None,
    );
    assert!(
        !react19_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::NoRefCallbackCleanupBeforeReact19)
    );
}
