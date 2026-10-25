//! Integration tests for Ticket #7 (`06: Defensive JS/TS/DOM Runtime Safety Rules (29 Rules) & 100% Zero-Stub Parity Verification`):
//! - All 21 newly wired defensive JS/TS/DOM runtime safety rules (plus verification of the full 29-rule defensive JS/TS/DOM family)
//! - Deterministic `Autofix` round-trip for `no-deprecated-keyboard-event-keycode-which`
//! - Automated 906/906 reference catalog resolution parity verification
//! - Automated 921/921 (100%) zero-stub detector coverage invariant across `src/`

use std::{
    fs,
    path::{Path, PathBuf},
};

use dotore::{
    CliOverrides, DotoreConfig, PrescriptionTier, RuleId, RulesListOptions, ScanOptions,
    analyze_source, apply_patches_to_source, build_rule_catalog, explain_rule, rule_registry,
    scan_workspace_with_overrides,
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
fn defensive_js_ts_dom_21_rules_invalid_and_adversarial_valid() {
    let cases = [
        // 1. no-arithmetic-on-optional-chained-operand
        RuleTestCase {
            rule: RuleId::NoArithmeticOnOptionalChainedOperand,
            file_name: "src/price.ts",
            invalid_code: r#"
                export function computeTotal(order?: { price?: number; qty: number }) {
                    return order?.price * 1.2;
                }
            "#,
            valid_code: r#"
                export function computeTotal(order?: { price?: number; qty: number }) {
                    return (order?.price ?? 0) * 1.2;
                }
            "#,
        },
        // 2. no-array-find-result-member-access-without-guard
        RuleTestCase {
            rule: RuleId::NoArrayFindResultMemberAccessWithoutGuard,
            file_name: "src/users.ts",
            invalid_code: r#"
                export function getAdminName(users: Array<{ id: string; role: string; name: string }>) {
                    const admin = users.find((u) => u.role === 'admin');
                    return admin.name;
                }
            "#,
            valid_code: r#"
                export function getAdminName(users: Array<{ id: string; role: string; name: string }>) {
                    const admin = users.find((u) => u.role === 'admin');
                    if (!admin) return 'None';
                    return admin.name;
                }
            "#,
        },
        // 3. no-array-index-deref-without-bounds-or-empty-guard
        RuleTestCase {
            rule: RuleId::NoArrayIndexDerefWithoutBoundsOrEmptyGuard,
            file_name: "src/firstItem.ts",
            invalid_code: r#"
                export function getFirstTitle(items: Array<{ title: string }>) {
                    return items[0].title;
                }
            "#,
            valid_code: r#"
                export function getFirstTitle(items: Array<{ title: string }>) {
                    if (items.length === 0) return '';
                    return items[0].title;
                }
            "#,
        },
        // 4. no-async-event-handler-without-reentry-guard
        RuleTestCase {
            rule: RuleId::NoAsyncEventHandlerWithoutReentryGuard,
            file_name: "src/SaveButton.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function SaveButton({ onSave }: { onSave: () => Promise<void> }) {
                    const [saved, setSaved] = useState(false);
                    return (
                        <button
                            onClick={async () => {
                                await onSave();
                                setSaved(true);
                            }}
                        >
                            {saved ? 'Saved' : 'Save'}
                        </button>
                    );
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function SaveButton({ onSave }: { onSave: () => Promise<void> }) {
                    const [busy, setBusy] = useState(false);
                    const [saved, setSaved] = useState(false);
                    return (
                        <button
                            disabled={busy}
                            onClick={async () => {
                                if (busy) return;
                                setBusy(true);
                                try {
                                    await onSave();
                                    setSaved(true);
                                } finally {
                                    setBusy(false);
                                }
                            }}
                        >
                            {saved ? 'Saved' : 'Save'}
                        </button>
                    );
                }
            "#,
        },
        // 5. no-collapse-request-error-to-empty-state
        RuleTestCase {
            rule: RuleId::NoCollapseRequestErrorToEmptyState,
            file_name: "src/UserList.tsx",
            invalid_code: r#"
                import { useState, useEffect } from 'react';
                export function UserList() {
                    const [users, setUsers] = useState<string[]>([]);
                    useEffect(() => {
                        fetch('/api/users')
                            .then((r) => r.json())
                            .then((data) => setUsers(data))
                            .catch(() => {
                                setUsers([]);
                            });
                    }, []);
                    return <ul>{users.map((u) => <li key={u}>{u}</li>)}</ul>;
                }
            "#,
            valid_code: r#"
                import { useState, useEffect } from 'react';
                export function UserList() {
                    const [users, setUsers] = useState<string[]>([]);
                    const [error, setError] = useState<Error | null>(null);
                    useEffect(() => {
                        fetch('/api/users')
                            .then((r) => r.json())
                            .then((data) => setUsers(data))
                            .catch((err) => {
                                setError(err);
                            });
                    }, []);
                    if (error) return <div>Failed to load</div>;
                    return <ul>{users.map((u) => <li key={u}>{u}</li>)}</ul>;
                }
            "#,
        },
        // 6. no-deprecated-keyboard-event-keycode-which
        RuleTestCase {
            rule: RuleId::NoDeprecatedKeyboardEventKeycodeWhich,
            file_name: "src/KeyHandler.tsx",
            invalid_code: r#"
                export function KeyHandler() {
                    return (
                        <input
                            onKeyDown={(e) => {
                                if (e.keyCode === 27) {
                                    console.log('escape');
                                }
                            }}
                        />
                    );
                }
            "#,
            valid_code: r#"
                export function KeyHandler() {
                    return (
                        <input
                            onKeyDown={(e) => {
                                if (e.key === 'Escape') {
                                    console.log('escape');
                                }
                            }}
                        />
                    );
                }
            "#,
        },
        // 7. no-enter-submit-without-ime-composition-guard
        RuleTestCase {
            rule: RuleId::NoEnterSubmitWithoutImeCompositionGuard,
            file_name: "src/ChatBox.tsx",
            invalid_code: r#"
                export function ChatBox({ onSend }: { onSend: () => void }) {
                    return (
                        <textarea
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    onSend();
                                }
                            }}
                        />
                    );
                }
            "#,
            valid_code: r#"
                export function ChatBox({ onSend }: { onSend: () => void }) {
                    return (
                        <textarea
                            onKeyDown={(e) => {
                                if (e.nativeEvent.isComposing) return;
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    onSend();
                                }
                            }}
                        />
                    );
                }
            "#,
        },
        // 8. no-floating-then-in-jsx-handler
        RuleTestCase {
            rule: RuleId::NoFloatingThenInJsxHandler,
            file_name: "src/DeleteButton.tsx",
            invalid_code: r#"
                export function DeleteButton({ id, onDeleted }: { id: string; onDeleted: () => void }) {
                    return (
                        <button
                            onClick={() => {
                                fetch(`/api/items/${id}`, { method: 'DELETE' }).then(() => {
                                    onDeleted();
                                });
                            }}
                        >
                            Delete
                        </button>
                    );
                }
            "#,
            valid_code: r#"
                export function DeleteButton({ id, onDeleted }: { id: string; onDeleted: () => void }) {
                    return (
                        <button
                            onClick={() => {
                                fetch(`/api/items/${id}`, { method: 'DELETE' })
                                    .then(() => {
                                        onDeleted();
                                    })
                                    .catch((err) => {
                                        console.error(err);
                                    });
                            }}
                        >
                            Delete
                        </button>
                    );
                }
            "#,
        },
        // 9. no-loading-flag-reset-outside-finally
        RuleTestCase {
            rule: RuleId::NoLoadingFlagResetOutsideFinally,
            file_name: "src/ProfileForm.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function ProfileForm({ save }: { save: () => Promise<void> }) {
                    const [isLoading, setIsLoading] = useState(false);
                    async function handleSubmit() {
                        setIsLoading(true);
                        await save();
                        setIsLoading(false);
                    }
                    return <button onClick={handleSubmit} disabled={isLoading}>Save</button>;
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function ProfileForm({ save }: { save: () => Promise<void> }) {
                    const [isLoading, setIsLoading] = useState(false);
                    async function handleSubmit() {
                        setIsLoading(true);
                        try {
                            await save();
                        } finally {
                            setIsLoading(false);
                        }
                    }
                    return <button onClick={handleSubmit} disabled={isLoading}>Save</button>;
                }
            "#,
        },
        // 10. no-non-literal-selector-query-without-try-catch
        RuleTestCase {
            rule: RuleId::NoNonLiteralSelectorQueryWithoutTryCatch,
            file_name: "src/scrollToHash.ts",
            invalid_code: r#"
                export function scrollToAnchor(hash: string) {
                    const el = document.querySelector(hash);
                    el?.scrollIntoView();
                }
            "#,
            valid_code: r#"
                export function scrollToAnchor(hash: string) {
                    try {
                        const el = document.querySelector(hash);
                        el?.scrollIntoView();
                    } catch {
                        // ignore invalid selector
                    }
                }
            "#,
        },
        // 11. no-non-null-assertion-on-maybe-undefined-result
        RuleTestCase {
            rule: RuleId::NoNonNullAssertionOnMaybeUndefinedResult,
            file_name: "src/lookup.ts",
            invalid_code: r#"
                export function getItem(items: Array<{ id: string }>, id: string) {
                    return items.find((item) => item.id === id)!;
                }
            "#,
            valid_code: r#"
                export function getItem(items: Array<{ id: string }>, id: string) {
                    return items.find((item) => item.id === id) ?? null;
                }
            "#,
        },
        // 12. no-nullish-coalescing-arithmetic-precedence
        RuleTestCase {
            rule: RuleId::NoNullishCoalescingArithmeticPrecedence,
            file_name: "src/math.ts",
            invalid_code: r#"
                export function addTax(subtotal: number | undefined, tax: number) {
                    return subtotal ?? 0 + tax;
                }
            "#,
            valid_code: r#"
                export function addTax(subtotal: number | undefined, tax: number) {
                    return (subtotal ?? 0) + tax;
                }
            "#,
        },
        // 13. no-object-keys-values-entries-on-maybe-undefined
        RuleTestCase {
            rule: RuleId::NoObjectKeysValuesEntriesOnMaybeUndefined,
            file_name: "src/headers.ts",
            invalid_code: r#"
                export function listHeaderKeys(config?: { headers?: Record<string, string> }) {
                    return Object.keys(config?.headers);
                }
            "#,
            valid_code: r#"
                export function listHeaderKeys(config?: { headers?: Record<string, string> }) {
                    return Object.keys(config?.headers ?? {});
                }
            "#,
        },
        // 14. no-object-or-array-coerced-to-string-in-template-literal
        RuleTestCase {
            rule: RuleId::NoObjectOrArrayCoercedToStringInTemplateLiteral,
            file_name: "src/log.ts",
            invalid_code: r#"
                export function formatPayload(payload: { id: string }) {
                    const meta = { id: payload.id, nested: true };
                    return `Payload: ${meta}`;
                }
            "#,
            valid_code: r#"
                export function formatPayload(payload: { id: string }) {
                    const meta = { id: payload.id, nested: true };
                    return `Payload: ${JSON.stringify(meta)}`;
                }
            "#,
        },
        // 15. no-passive-request-owner-ref
        RuleTestCase {
            rule: RuleId::NoPassiveRequestOwnerRef,
            file_name: "src/RoomFeed.tsx",
            invalid_code: r#"
                import { useEffect, useRef, useState } from 'react';
                export function RoomFeed({ roomId }: { roomId: string }) {
                    const [messages, setMessages] = useState<string[]>([]);
                    const latestRoomRef = useRef(roomId);
                    useEffect(() => {
                        latestRoomRef.current = roomId;
                    }, [roomId]);
                    useEffect(() => {
                        fetch(`/api/rooms/${roomId}`).then((r) => r.json()).then((data) => {
                            if (latestRoomRef.current === roomId) {
                                setMessages(data);
                            }
                        });
                    }, [roomId]);
                    return <div>{messages.length}</div>;
                }
            "#,
            valid_code: r#"
                import { useEffect, useState } from 'react';
                export function RoomFeed({ roomId }: { roomId: string }) {
                    const [messages, setMessages] = useState<string[]>([]);
                    useEffect(() => {
                        let cancelled = false;
                        fetch(`/api/rooms/${roomId}`).then((r) => r.json()).then((data) => {
                            if (!cancelled) {
                                setMessages(data);
                            }
                        });
                        return () => {
                            cancelled = true;
                        };
                    }, [roomId]);
                    return <div>{messages.length}</div>;
                }
            "#,
        },
        // 16. no-predicate-function-reference-in-boolean-position
        RuleTestCase {
            rule: RuleId::NoPredicateFunctionReferenceInBooleanPosition,
            file_name: "src/auth.ts",
            invalid_code: r#"
                function isAuthenticated() {
                    return Boolean(localStorage.getItem('token'));
                }
                export function canAccess() {
                    if (isAuthenticated) {
                        return true;
                    }
                    return false;
                }
            "#,
            valid_code: r#"
                function isAuthenticated() {
                    return Boolean(localStorage.getItem('token'));
                }
                export function canAccess() {
                    if (isAuthenticated()) {
                        return true;
                    }
                    return false;
                }
            "#,
        },
        // 17. no-unescaped-dynamic-string-in-regexp
        RuleTestCase {
            rule: RuleId::NoUnescapedDynamicStringInRegexp,
            file_name: "src/search.ts",
            invalid_code: r#"
                export function matchesQuery(text: string, query: string) {
                    const pattern = new RegExp(query, 'i');
                    return pattern.test(text);
                }
            "#,
            valid_code: r#"
                function escapeRegExp(s: string) {
                    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                }
                export function matchesQuery(text: string, query: string) {
                    const pattern = new RegExp(escapeRegExp(query), 'i');
                    return pattern.test(text);
                }
            "#,
        },
        // 18. no-unguarded-numeric-input-parse
        RuleTestCase {
            rule: RuleId::NoUnguardedNumericInputParse,
            file_name: "src/QuantityInput.tsx",
            invalid_code: r#"
                import { useState } from 'react';
                export function QuantityInput() {
                    const [qty, setQty] = useState(1);
                    return (
                        <input
                            type="number"
                            value={qty}
                            onChange={(e) => setQty(Number(e.target.value))}
                        />
                    );
                }
            "#,
            valid_code: r#"
                import { useState } from 'react';
                export function QuantityInput() {
                    const [qty, setQty] = useState(1);
                    return (
                        <input
                            type="number"
                            value={qty}
                            onChange={(e) => {
                                const raw = e.target.value;
                                if (raw === '') return;
                                const parsed = Number(raw);
                                if (!Number.isNaN(parsed)) {
                                    setQty(parsed);
                                }
                            }}
                        />
                    );
                }
            "#,
        },
        // 19. no-unguarded-throwing-parse-call
        RuleTestCase {
            rule: RuleId::NoUnguardedThrowingParseCall,
            file_name: "src/url.ts",
            invalid_code: r#"
                export function getHostname(rawUrl: string) {
                    const parsed = new URL(rawUrl);
                    return parsed.hostname;
                }
            "#,
            valid_code: r#"
                export function getHostname(rawUrl: string) {
                    if (!URL.canParse(rawUrl)) return null;
                    const parsed = new URL(rawUrl);
                    return parsed.hostname;
                }
            "#,
        },
        // 20. no-unsafe-json-parse
        RuleTestCase {
            rule: RuleId::NoUnsafeJsonParse,
            file_name: "src/storage.ts",
            invalid_code: r#"
                export function loadUserTheme(raw: string) {
                    return JSON.parse(raw).theme;
                }
            "#,
            valid_code: r#"
                export function loadUserTheme(raw: string) {
                    try {
                        const parsed = JSON.parse(raw);
                        return typeof parsed === 'object' && parsed !== null ? parsed.theme : 'light';
                    } catch {
                        return 'light';
                    }
                }
            "#,
        },
        // 21. no-whole-object-default-losing-per-key-defaults
        RuleTestCase {
            rule: RuleId::NoWholeObjectDefaultLosingPerKeyDefaults,
            file_name: "src/options.ts",
            invalid_code: r#"
                export function connect(options: { retries?: number; timeout?: number } = { retries: 3, timeout: 1000 }) {
                    return options.retries;
                }
            "#,
            valid_code: r#"
                export function connect({ retries = 3, timeout = 1000 }: { retries?: number; timeout?: number } = {}) {
                    return retries + timeout;
                }
            "#,
        },
    ];

    assert_eq!(cases.len(), 21);
    for case in &cases {
        assert_rule_invalid_and_valid(case);
    }
}

#[test]
fn deprecated_keyboard_event_keycode_which_autofix_round_trip() {
    let source = r#"export function ShortcutInput({ onClose }: { onClose: () => void }) {
    return (
        <input
            onKeyDown={(e) => {
                if (e.keyCode === 27) {
                    onClose();
                }
            }}
        />
    );
}
"#;
    let diags = analyze_source(
        Path::new("src/ShortcutInput.tsx"),
        source,
        Some(&[RuleId::NoDeprecatedKeyboardEventKeycodeWhich]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got: {diags:#?}");
    assert_eq!(diags[0].rule, RuleId::NoDeprecatedKeyboardEventKeycodeWhich);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);
    assert!(diags[0].autofix.is_some());

    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 1);
    assert!(
        rewritten.contains("e.key === \"Escape\"") || rewritten.contains("e.key === 'Escape'"),
        "Expected autofix to rewrite `e.keyCode === 27` to `e.key === 'Escape'`, got:\n{rewritten}"
    );

    let reanalyzed = analyze_source(
        Path::new("src/ShortcutInput.tsx"),
        &rewritten,
        Some(&[RuleId::NoDeprecatedKeyboardEventKeycodeWhich]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after autofix, got: {reanalyzed:#?}"
    );

    // ASCII letter keyCode (65 -> 'a') is safely rewritten, while non-equality or unknown keyCode has no unsafe autofix
    let ascii_src = "export function KeyA() { return <input onKeyDown={(e) => { if (e.keyCode === 65) {} }} />; }\n";
    let ascii_diags = analyze_source(
        Path::new("src/KeyA.tsx"),
        ascii_src,
        Some(&[RuleId::NoDeprecatedKeyboardEventKeycodeWhich]),
    );
    assert_eq!(ascii_diags.len(), 1);
    let (ascii_rewritten, _) = apply_patches_to_source(ascii_src, &ascii_diags);
    assert!(ascii_rewritten.contains("e.key === 'a'"));

    let unknown_src = "export function KeyUnknown() { return <input onKeyDown={(e) => { if (e.keyCode === 999) {} }} />; }\n";
    let unknown_diags = analyze_source(
        Path::new("src/KeyUnknown.tsx"),
        unknown_src,
        Some(&[RuleId::NoDeprecatedKeyboardEventKeycodeWhich]),
    );
    assert_eq!(unknown_diags.len(), 1);
    assert!(unknown_diags[0].autofix.is_none());

    // Direct `await fetch(...).then(...)` in JSX handler is handled by `AwaitExpression` immediate parent
    let awaited_then_src = "export function Btn() { return <button onClick={async () => { await fetch('/api').then((r) => r.json()); }} />; }\n";
    assert!(
        analyze_source(
            Path::new("src/Btn.tsx"),
            awaited_then_src,
            Some(&[RuleId::NoFloatingThenInJsxHandler]),
        )
        .is_empty()
    );
}

#[test]
fn zero_stub_parity_invariant_all_921_rule_variants_have_active_detectors() {
    let registry = rule_registry();
    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert!(
        registry.len() >= 1076,
        "Expected at least 1076 total RuleId entries in rule_registry(), got {}",
        registry.len()
    );
    assert_eq!(
        catalog.len(),
        registry.len(),
        "Expected catalog length to match rule_registry(), got {}",
        catalog.len()
    );

    // Collect all Rust source files under `src/` and `crates/` except `src/rules/types.rs`
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let crates_dir = manifest_dir.join("crates");
    let mut detector_sources = String::new();
    collect_rs_sources_excluding_types(&src_dir, &mut detector_sources);
    if crates_dir.is_dir() {
        collect_rs_sources_excluding_types(&crates_dir, &mut detector_sources);
    }

    let mut unwired_rules = Vec::new();
    for meta in registry {
        let variant_token = format!("RuleId::{:?}", meta.id);
        if !detector_sources.contains(&variant_token) {
            unwired_rules.push(format!("{} ({})", variant_token, meta.canonical_id));
        }
    }

    assert!(
        unwired_rules.is_empty(),
        "Found {} unwired metadata-only RuleId stub(s) with no active detector in src/:\n{}",
        unwired_rules.len(),
        unwired_rules.join("\n")
    );
}

#[test]
fn all_906_reference_catalog_rules_resolve_via_parse_and_build_rule_catalog() {
    let reference_catalog_ids: &[&str] = &[
        "active-static-asset",
        "activity-wraps-effect-heavy-subtree",
        "advanced-event-handler-refs",
        "agent-tool-capability-risk",
        "alt-text",
        "anchor-ambiguous-text",
        "anchor-has-content",
        "anchor-is-valid",
        "anchor-target-exists",
        "aria-activedescendant-has-tabindex",
        "aria-braille-equivalent",
        "aria-props",
        "aria-proptypes",
        "aria-role",
        "aria-unsupported-elements",
        "artifact-baas-authority-surface",
        "artifact-env-leak",
        "artifact-secret-leak",
        "async-await-in-loop",
        "async-defer-await",
        "async-parallel",
        "auth-token-in-web-storage",
        "autocomplete-valid",
        "base-ui-dialog-popup-requires-title",
        "base-ui-field-requires-label",
        "base-ui-tabs-tab-requires-list",
        "build-pipeline-secret-boundary",
        "button-has-type",
        "checked-requires-onchange-or-readonly",
        "circular-dependency",
        "class-component-missing-component-will-unmount-teardown",
        "click-events-have-key-events",
        "clickjacking-redirect-risk",
        "client-localstorage-no-version",
        "client-passive-event-listeners",
        "command-execution-input-risk",
        "context-provider-value-from-unmemoized-local-literal",
        "control-has-associated-label",
        "cors-cookie-trust-risk",
        "dangerous-html-sink",
        "data-table-requires-accessible-name",
        "debounce-no-cleanup",
        "design-no-em-dash-in-jsx-text",
        "design-no-redundant-padding-axes",
        "design-no-redundant-size-axes",
        "design-no-space-on-flex-children",
        "design-no-three-period-ellipsis",
        "design-no-vague-button-label",
        "details-requires-summary",
        "dialog-has-accessible-name",
        "display-name",
        "duplicate-jsx-subtree",
        "effect-listener-cleanup-mismatch",
        "effect-listener-cleanup-reference-mismatch",
        "effect-needs-cleanup",
        "effect-observer-needs-disconnect",
        "effect-raf-loop-needs-cancel",
        "effect-remove-listener-inline-handler",
        "empty-table-header",
        "exhaustive-deps",
        "expo-no-non-inlined-env",
        "fieldset-requires-legend",
        "firebase-client-owned-authz-field",
        "firebase-permissive-rules",
        "firebase-query-filter-as-auth",
        "forbid-component-props",
        "forbid-dom-props",
        "forbid-elements",
        "form-control-requires-name",
        "forward-ref-uses-ref",
        "git-provider-url-injection-risk",
        "heading-has-content",
        "hook-import-rename-loses-use-prefix",
        "hook-use-state",
        "hooks-no-nan-in-deps",
        "html-has-lang",
        "html-label-has-single-control",
        "html-no-invalid-paragraph-child",
        "html-no-invalid-table-nesting",
        "html-no-nested-form",
        "html-no-nested-interactive",
        "html-xml-lang-mismatch",
        "iframe-has-title",
        "iframe-missing-sandbox",
        "iframe-title-unique",
        "img-redundant-alt",
        "import-metadata-execution-risk",
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
        "insecure-crypto-risk",
        "insecure-session-cookie",
        "interactive-supports-focus",
        "jotai-derived-atom-returns-fresh-object",
        "jotai-select-atom-in-render-body",
        "jotai-tq-use-raw-query-atom",
        "js-async-reduce-without-awaited-acc",
        "js-batch-dom-css",
        "js-cache-property-access",
        "js-cache-storage",
        "js-combine-iterations",
        "js-early-exit",
        "js-flatmap-filter",
        "js-hoist-intl",
        "js-hoist-regexp",
        "js-index-maps",
        "js-length-check-first",
        "js-min-max-loop",
        "js-set-map-lookups",
        "js-tosorted-immutable",
        "jsx-boolean-value",
        "jsx-curly-brace-presence",
        "jsx-filename-extension",
        "jsx-fragments",
        "jsx-handler-names",
        "jsx-key",
        "jsx-max-depth",
        "jsx-no-comment-textnodes",
        "jsx-no-constructed-context-values",
        "jsx-no-duplicate-props",
        "jsx-no-jsx-as-prop",
        "jsx-no-new-array-as-prop",
        "jsx-no-new-function-as-prop",
        "jsx-no-new-object-as-prop",
        "jsx-no-script-url",
        "jsx-no-target-blank",
        "jsx-no-undef",
        "jsx-no-useless-fragment",
        "jsx-numeric-and-leaked-render",
        "jsx-pascal-case",
        "jsx-props-no-spread-multi",
        "jsx-props-no-spreading",
        "jwt-insecure-verification",
        "key-lifecycle-risk",
        "label-has-associated-control",
        "lang",
        "loading-action-preserves-trigger",
        "local-rpc-native-bridge-risk",
        "mcp-tool-capability-risk",
        "mdx-ssr-execution-risk",
        "media-has-caption",
        "mobx-no-make-auto-observable-in-inheritance",
        "mobx-no-observer-wrapped-memo",
        "mobx-reaction-disposer-discarded",
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
        "motion-value-constructor-in-render",
        "motion-value-subscription-in-render",
        "mouse-events-have-key-events",
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
        "no-access-key",
        "no-adjust-state-on-prop-change",
        "no-all-caps-body-text",
        "no-arbitrary-px-font-size",
        "no-aria-hidden-on-body",
        "no-aria-hidden-on-focusable",
        "no-aria-invalid-without-description",
        "no-arithmetic-on-optional-chained-operand",
        "no-array-find-result-member-access-without-guard",
        "no-array-index-as-key",
        "no-array-index-deref-without-bounds-or-empty-guard",
        "no-array-index-key",
        "no-assertive-status",
        "no-async-effect-callback",
        "no-async-event-handler-without-reentry-guard",
        "no-auto-scrolling-content",
        "no-autofocus",
        "no-autoplay-without-muted",
        "no-barrel-import",
        "no-blocked-paste",
        "no-boolean-toggle-without-functional-update",
        "no-broken-image-source",
        "no-call-component-as-function",
        "no-cascading-set-state",
        "no-chain-state-updates",
        "no-children-prop",
        "no-clipped-overlay",
        "no-clone-element",
        "no-collapse-request-error-to-empty-state",
        "no-collapsed-literal-or-chain-as-value",
        "no-common-root-font",
        "no-conflicting-spring-options",
        "no-controlled-input-value-without-state-update",
        "no-controlled-selection-focus-effect",
        "no-cramped-container-padding",
        "no-create-context-in-render",
        "no-create-object-url-in-render",
        "no-create-object-url-without-revoke",
        "no-create-ref-in-function-component",
        "no-create-store-in-render",
        "no-crushed-letter-spacing",
        "no-danger",
        "no-danger-with-children",
        "no-dark-mode-glow",
        "no-decorative-blur-orb",
        "no-decorative-grid-background",
        "no-decorative-pulse",
        "no-decorative-radial-spotlight",
        "no-default-props",
        "no-default-purple-page-gradient",
        "no-default-warm-page-surface",
        "no-deprecated-keyboard-event-keycode-which",
        "no-deprecated-tailwind-class",
        "no-derived-state",
        "no-derived-state-effect",
        "no-derived-useState",
        "no-did-mount-set-state",
        "no-did-update-set-state",
        "no-direct-mutation-state",
        "no-direct-state-mutation",
        "no-disabled-zoom",
        "no-distracting-elements",
        "no-document-start-view-transition",
        "no-document-write",
        "no-duplicate-static-id-reference",
        "no-dynamic-import-path",
        "no-dynamic-tailwind-class-fragment",
        "no-eager-new-in-use-state-initializer",
        "no-ease-in-motion",
        "no-effect-chain",
        "no-effect-event-handler",
        "no-effect-event-in-deps",
        "no-effect-with-fresh-deps",
        "no-effect-wrapper-discards-callback-cleanup-return",
        "no-emoji-heading-decoration",
        "no-empty-card-shell",
        "no-enter-submit-without-ime-composition-guard",
        "no-eval",
        "no-event-handler",
        "no-event-trigger-state",
        "no-excessive-card-surfaces",
        "no-excessive-centered-copy",
        "no-excessive-font-families",
        "no-excessive-motion-stagger",
        "no-excessive-pill-treatment",
        "no-fake-browser-chrome",
        "no-fetch-in-effect",
        "no-fetch-response-used-without-status-check",
        "no-fill-map-element-as-key",
        "no-find-dom-node",
        "no-fixed-inside-transformed-ancestor",
        "no-flat-page-type-scale",
        "no-floating-then-in-jsx-handler",
        "no-flush-sync",
        "no-focus-in-animation-completion-handler",
        "no-focusable-content-in-aria-hidden",
        "no-focusable-content-in-role-text",
        "no-full-lodash-import",
        "no-full-viewport-centered-hero",
        "no-full-viewport-width",
        "no-generic-handler-names",
        "no-generic-marketing-copy",
        "no-generic-purple-blue-icon-gradient",
        "no-giant-component",
        "no-global-css-variable-animation",
        "no-gradient-text",
        "no-gray-on-colored-background",
        "no-hairline-border-wide-shadow",
        "no-hero-eyebrow-chip",
        "no-high-complexity-react-function",
        "no-hover-only-reveal",
        "no-hydration-branch-on-browser-global",
        "no-icon-tile-heading-stack",
        "no-image-hover-transform",
        "no-img-lazy-with-high-fetchpriority",
        "no-img-without-dimensions",
        "no-impure-call-at-module-scope",
        "no-impure-state-updater",
        "no-indeterminate-attribute",
        "no-inert-pointer-affordance",
        "no-inert-sticky-position",
        "no-initialize-state",
        "no-inline-bounce-easing",
        "no-inline-exhaustive-style",
        "no-inline-hoc-on-component",
        "no-inline-prop-on-memo-component",
        "no-interactive-element-to-noninteractive-role",
        "no-invalid-progress-range",
        "no-invisible-focus-control",
        "no-is-mounted",
        "no-italic-serif-display-heading",
        "no-json-parse-stringify-clone",
        "no-jsx-element-type",
        "no-justified-text",
        "no-large-animated-blur",
        "no-layout-property-animation",
        "no-layout-shifting-interaction-state",
        "no-layout-transition-inline",
        "no-legacy-class-lifecycles",
        "no-legacy-context-api",
        "no-loading-flag-reset-outside-finally",
        "no-locale-format-in-render",
        "no-long-transition-duration",
        "no-low-contrast-inline-style",
        "no-manufactured-contrast-copy",
        "no-many-boolean-props",
        "no-match-media-in-state-initializer",
        "no-mirror-prop-effect",
        "no-mixed-animation-owners",
        "no-mixed-icon-libraries",
        "no-mixed-srcset-descriptors",
        "no-moment",
        "no-monotonous-page-spacing",
        "no-multi-comp",
        "no-multi-component-file",
        "no-multiple-main-landmarks",
        "no-multiple-unlabeled-navigation-landmarks",
        "no-mutable-in-deps",
        "no-mutate-queried-dom-node-in-component",
        "no-mutate-then-set-or-return-same-reference",
        "no-mutating-array-method-on-prop-or-hook-result",
        "no-mutating-reducer-state",
        "no-namespace",
        "no-nested-card-surface",
        "no-nested-component-definition",
        "no-non-literal-selector-query-without-try-catch",
        "no-non-null-assertion-on-maybe-undefined-result",
        "no-nondeterministic-id-value-in-render-body",
        "no-noninteractive-element-interactions",
        "no-noninteractive-element-to-interactive-role",
        "no-noninteractive-tabindex",
        "no-nonresizable-textarea",
        "no-nullish-coalescing-arithmetic-precedence",
        "no-numbered-section-markers",
        "no-object-keys-values-entries-on-maybe-undefined",
        "no-object-or-array-coerced-to-string-in-template-literal",
        "no-outline-none",
        "no-overloaded-hover-state",
        "no-oversized-long-heading",
        "no-overwide-text-measure",
        "no-pass-data-to-parent",
        "no-pass-live-state-to-parent",
        "no-passive-request-owner-ref",
        "no-path-prefix-containment",
        "no-permanent-will-change",
        "no-pill-navigation-count",
        "no-placeholder-only-field",
        "no-placeholder-persona-copy",
        "no-pointer-disabled-enabled-control",
        "no-polymorphic-children",
        "no-predicate-function-reference-in-boolean-position",
        "no-presentation-role-conflict",
        "no-prevent-default",
        "no-promise-then-side-effect-in-effect-without-catch",
        "no-prop-callback-in-effect",
        "no-prop-callback-in-render",
        "no-prop-types",
        "no-pulsing-status-dot",
        "no-pure-black-background",
        "no-pure-black-shadow",
        "no-radial-halo",
        "no-random-key",
        "no-react-children",
        "no-react-dom-deprecated-apis",
        "no-react19-deprecated-apis",
        "no-reduced-motion-content-removal",
        "no-redundant-display-class",
        "no-redundant-roles",
        "no-redundant-should-component-update",
        "no-redundant-title-tooltip",
        "no-ref-callback-cleanup-before-react-19",
        "no-ref-current-in-render",
        "no-render-in-render",
        "no-render-prop-children",
        "no-render-return-value",
        "no-repeated-container-text",
        "no-repeated-emoji-tiles",
        "no-repeated-glass-surfaces",
        "no-repeated-hover-scale",
        "no-repeated-kicker-labels",
        "no-repeated-placeholder-navigation",
        "no-repeated-section-shells",
        "no-repeating-gradient-decoration",
        "no-reset-all-state-on-prop-change",
        "no-responsive-hidden-accessible-name",
        "no-scale-from-zero",
        "no-secrets-in-client-code",
        "no-self-updating-effect",
        "no-server-side-image-map",
        "no-set-state",
        "no-set-state-after-await-in-effect",
        "no-set-state-in-render",
        "no-shape-assembled-illustration",
        "no-side-effect-in-state-updater-function",
        "no-side-tab-border",
        "no-skipped-heading-level",
        "no-small-form-control-text",
        "no-smooth-scroll-without-reduced-motion",
        "no-spread-accumulator-in-reduce",
        "no-spread-props-over-defaults-clobbers-with-undefined",
        "no-srcset-without-sizes",
        "no-stale-timer-ref",
        "no-static-element-interactions",
        "no-static-motion-config-never",
        "no-string-false-on-boolean-attribute",
        "no-string-refs",
        "no-svg-currentcolor-with-fill-class",
        "no-symmetric-text-button-padding",
        "no-sync-xhr",
        "no-tailwind-layout-transition",
        "no-this-in-sfc",
        "no-tight-all-caps-heading",
        "no-tight-body-leading",
        "no-tight-display-tracking",
        "no-tiny-text",
        "no-tiny-uppercase-tracked-label",
        "no-transition-all",
        "no-transitioned-composite-widget-state",
        "no-transitioned-focus-ring",
        "no-unbounded-animation-frame-loop",
        "no-uncontrolled-input",
        "no-undeferred-third-party",
        "no-undersized-icon-button",
        "no-unescaped-dynamic-string-in-regexp",
        "no-unescaped-entities",
        "no-ungated-tailwind-animation",
        "no-unguarded-browser-global-at-module-scope",
        "no-unguarded-browser-global-in-render-or-hook-init",
        "no-unguarded-numeric-input-parse",
        "no-unguarded-throwing-parse-call",
        "no-uniform-feature-card-grid",
        "no-uninformative-aria-label",
        "no-unknown-property",
        "no-unowned-async-error-clear",
        "no-unsafe",
        "no-unsafe-json-parse",
        "no-unstable-nested-components",
        "no-unthrottled-scroll-mutation",
        "no-uppercase-mono-label",
        "no-uppercase-tracked-navigation-label",
        "no-usememo-simple-expression",
        "no-whole-object-default-losing-per-key-defaults",
        "no-whole-object-dep-with-member-reads",
        "no-wide-letter-spacing",
        "no-will-update-set-state",
        "no-z-index-9999",
        "nosql-injection-risk",
        "only-export-components",
        "package-metadata-secret",
        "path-traversal-risk",
        "plugin-update-trust-risk",
        "pointer-capture-needs-cancel-handler",
        "postmessage-origin-risk",
        "preact-no-children-length",
        "preact-no-react-hooks-import",
        "preact-no-render-arguments",
        "preact-prefer-ondblclick",
        "preact-prefer-oninput",
        "prefer-dvh-over-vh",
        "prefer-dynamic-import",
        "prefer-es6-class",
        "prefer-explicit-variants",
        "prefer-function-component",
        "prefer-html-dialog",
        "prefer-module-scope-pure-function",
        "prefer-module-scope-static-value",
        "prefer-motion-transform-property",
        "prefer-stable-empty-fallback",
        "prefer-tabular-numeric-data",
        "prefer-tag-over-role",
        "prefer-truncate-shorthand",
        "prefer-use-effect-event",
        "prefer-use-sync-external-store",
        "prefer-useReducer",
        "public-debug-artifact",
        "public-env-secret-name",
        "query-destructure-result",
        "query-floating-mutate-async",
        "query-mutation-missing-invalidation",
        "query-no-mutation-in-effect-as-read",
        "query-no-query-in-effect",
        "query-no-rest-destructuring",
        "query-no-usequery-for-mutation",
        "query-no-void-query-fn",
        "query-stable-query-client",
        "r3f-cap-device-pixel-ratio",
        "r3f-limit-shadowed-point-lights",
        "r3f-no-advancing-clock-in-use-frame",
        "r3f-no-allocation-in-pointer-move",
        "r3f-no-async-use-frame",
        "r3f-no-clone-in-use-frame",
        "r3f-no-compile-in-use-frame",
        "r3f-no-deep-use-three-selector",
        "r3f-no-dispose-loader-cache",
        "r3f-no-duplicate-primitive-object",
        "r3f-no-extend-in-render",
        "r3f-no-extend-three-namespace",
        "r3f-no-fresh-portal-container",
        "r3f-no-fresh-use-three-selector",
        "r3f-no-ignored-basic-material-properties",
        "r3f-no-ignored-linewidth",
        "r3f-no-imperative-attach-of-managed-ref",
        "r3f-no-inline-primitive-object",
        "r3f-no-inline-resource-prop",
        "r3f-no-internal-imports",
        "r3f-no-manual-canvas-resize",
        "r3f-no-mutate-loader-cache",
        "r3f-no-mutate-uniform-prop-source-in-use-frame",
        "r3f-no-mutating-pointer-event-data",
        "r3f-no-new-in-use-frame",
        "r3f-no-normalized-float-buffer-attribute",
        "r3f-no-null-loader-input",
        "r3f-no-object-pointer-capture",
        "r3f-no-recursive-raf-with-use-frame",
        "r3f-no-shader-configuration-mutation-in-use-frame",
        "r3f-no-shadows-on-unsupported-light",
        "r3f-no-state-in-pointer-move",
        "r3f-no-state-in-use-frame",
        "r3f-no-sync-readback-in-use-frame",
        "r3f-no-unstable-args",
        "r3f-no-use-frame-dependency-array",
        "r3f-prefer-gpu-instanced-animation",
        "r3f-prefer-gpu-position-animation",
        "r3f-prefer-instanced-mesh",
        "r3f-prefer-use-loader",
        "r3f-require-animation-mixer-update",
        "r3f-require-data-texture-update",
        "r3f-require-dynamic-buffer-usage",
        "r3f-require-environment-for-metal",
        "r3f-require-frame-delta",
        "r3f-require-global-effect-cleanup",
        "r3f-require-instanced-buffer-update",
        "r3f-require-lighting-for-pbr",
        "r3f-require-lit-material-normals",
        "r3f-require-owned-texture-cleanup",
        "r3f-require-position-buffer-update",
        "r3f-require-projection-matrix-update",
        "r3f-require-render-target-reset",
        "r3f-require-render-with-positive-priority",
        "r3f-require-root-unmount",
        "r3f-require-shadows-enabled",
        "r3f-require-transparent-for-opacity",
        "r3f-require-uv-for-texture-map",
        "r3f-texture-repeat-requires-wrapping",
        "r3f-valid-buffer-attribute-array-length",
        "r3f-valid-buffer-attribute-item-size",
        "r3f-valid-fog-parameters",
        "r3f-valid-material-opacity",
        "r3f-valid-orthographic-camera",
        "r3f-valid-pbr-material-properties",
        "r3f-valid-perspective-camera",
        "r3f-valid-physical-material-properties",
        "r3f-valid-raycaster-range",
        "r3f-valid-shadow-map-size",
        "r3f-valid-spot-light-properties",
        "r3f-valid-texture-color-space",
        "r3f-webgpu-canvas-prop-compatibility",
        "r3f-webgpu-no-gl-state",
        "r3f-webgpu-no-high-precision-instancing",
        "r3f-webgpu-no-js-uniform-branch",
        "r3f-webgpu-no-legacy-effect-composer",
        "r3f-webgpu-no-legacy-material-api",
        "r3f-webgpu-no-unregistered-pipeline-pass",
        "r3f-webgpu-require-async-init",
        "radio-input-missing-name",
        "radix-dialog-content-requires-title",
        "radix-tabs-trigger-requires-list",
        "raw-sql-injection-risk",
        "react-aria-dialog-requires-heading",
        "react-compiler-no-manual-memoization",
        "react-in-jsx-scope",
        "react-markdown-unsanitized-raw-html",
        "react-router-csp-nonce-consistency",
        "react-router-descendant-routes-require-splat",
        "react-router-guard-aborted-handle-error",
        "react-router-internal-route-anchor",
        "react-router-loader-fetch-forwards-signal",
        "react-router-loader-parallel-fetch",
        "react-router-nested-route-requires-outlet",
        "react-router-no-catch-middleware-next",
        "react-router-no-client-module-in-server-render",
        "react-router-no-duplicate-route-id",
        "react-router-no-empty-leaf-route",
        "react-router-no-invalid-absolute-child-path",
        "react-router-no-invalid-lazy-route-properties",
        "react-router-no-invalid-splat-path",
        "react-router-no-loader-request-body",
        "react-router-no-middleware-response-body-consumption",
        "react-router-no-multiple-blockers",
        "react-router-no-multiple-middleware-next",
        "react-router-no-multiple-set-search-params-in-tick",
        "react-router-no-navigate-in-render",
        "react-router-no-nested-router",
        "react-router-no-redirect-in-try-catch",
        "react-router-no-route-module-environment-suffix",
        "react-router-no-router-in-render",
        "react-router-no-session-mutation-in-loader",
        "react-router-no-static-cookie-expires",
        "react-router-no-unsynchronized-search-params-mutation",
        "react-router-no-use-loader-data-in-error-ui",
        "react-router-prefer-route-lazy",
        "react-router-require-root-error-boundary",
        "react-router-resource-link-requires-reload",
        "react-router-return-navigation-promise-in-transition",
        "react-router-server-middleware-return-response",
        "react-router-session-mutation-requires-commit",
        "react-router-v8-no-meta-data-field",
        "react-router-v8-no-react-router-dom-import",
        "react-router-v8-no-removed-future-flags",
        "react-router-valid-route-object",
        "redux-useselector-inline-derivation",
        "redux-useselector-returns-new-collection",
        "remotion-calculate-metadata-fetch-signal",
        "remotion-deterministic-randomness",
        "remotion-no-css-animation",
        "remotion-no-css-transition",
        "remotion-no-css-url-assets",
        "remotion-no-module-scope-delay-render",
        "remotion-no-native-media-elements",
        "remotion-no-next-image",
        "remotion-stable-delay-render-handle",
        "rendering-animate-svg-wrapper",
        "rendering-conditional-render",
        "rendering-hoist-jsx",
        "rendering-hydration-mismatch-time",
        "rendering-hydration-no-flicker",
        "rendering-script-defer-async",
        "rendering-svg-precision",
        "rendering-usetransition-loading",
        "repository-secret-file",
        "request-body-mass-assignment",
        "require-autoplay-video-poster",
        "require-render-return",
        "require-scale-reveal-transform-origin",
        "rerender-defer-reads-hook",
        "rerender-dependencies",
        "rerender-derived-state-from-hook",
        "rerender-functional-setstate",
        "rerender-lazy-ref-init",
        "rerender-lazy-state-init",
        "rerender-memo-before-early-return",
        "rerender-memo-with-default-value",
        "rerender-state-only-in-handlers",
        "rerender-transitions-scroll",
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
        "rn-prefer-pressable",
        "rn-prefer-pressable-over-gesture-detector",
        "rn-prefer-reanimated",
        "rn-pressable-shared-value-mutation",
        "rn-reanimated-4-no-legacy-spring-thresholds",
        "rn-reanimated-4-no-removed-api",
        "rn-reanimated-4-use-worklets-scheduler",
        "rn-scrollview-dynamic-padding",
        "rn-scrollview-flex-in-content-container",
        "rn-style-prefer-boxshadow",
        "role-button-requires-complete-keyboard-activation",
        "role-has-required-aria-props",
        "role-supports-aria-props",
        "rules-of-hooks",
        "scope",
        "secret-in-fallback",
        "self-closing-comp",
        "server-after-nonblocking",
        "server-auth-actions",
        "server-cache-with-object-literal",
        "server-dedup-props",
        "server-fetch-without-revalidate",
        "server-hoist-static-io",
        "server-no-mutable-module-state",
        "server-sequential-independent-await",
        "shadcn-command-item-state-variant-requires-value",
        "shadcn-dialog-content-requires-title",
        "shadcn-form-item-requires-label",
        "shadcn-icon-button-requires-label",
        "shadcn-input-group-no-raw-controls",
        "shadcn-tabs-trigger-requires-list",
        "state-in-constructor",
        "style-prop-object",
        "styled-components-duplicate-css-property-in-block",
        "styled-components-non-transient-custom-prop-on-intrinsic-element",
        "supabase-client-owned-authz-field",
        "supabase-rls-policy-risk",
        "supabase-table-missing-rls",
        "svg-filter-clickjacking-risk",
        "tabindex-no-positive",
        "tanstack-form-on-submit-requires-prevent-default",
        "tanstack-start-get-mutation",
        "tanstack-start-loader-parallel-fetch",
        "tanstack-start-missing-head-content",
        "tanstack-start-missing-scripts",
        "tanstack-start-no-anchor-element",
        "tanstack-start-no-direct-fetch-in-loader",
        "tanstack-start-no-dynamic-server-fn-import",
        "tanstack-start-no-navigate-in-render",
        "tanstack-start-no-secrets-in-loader",
        "tanstack-start-no-use-server-in-handler",
        "tanstack-start-no-useeffect-fetch",
        "tanstack-start-redirect-in-try-catch",
        "tanstack-start-route-property-order",
        "tanstack-start-server-fn-method-order",
        "tanstack-start-server-fn-validate-input",
        "tanstack-table-no-unstable-data-or-columns",
        "tanstack-virtual-measure-element-requires-data-index",
        "tenant-static-proxy-risk",
        "three-cap-device-pixel-ratio",
        "three-effect-composer-output-pass-last",
        "three-effect-composer-require-size-on-resize",
        "three-gpu-computation-handle-init-error",
        "three-gpu-computation-require-init-before-compute",
        "three-gpu-computation-valid-variable-name",
        "three-limit-shadowed-point-lights",
        "three-no-allocation-in-pointer-move",
        "three-no-async-animation-loop",
        "three-no-clone-in-animation-loop",
        "three-no-compile-in-animation-loop",
        "three-no-ignored-basic-material-properties",
        "three-no-ignored-linewidth",
        "three-no-material-recompile-in-animation-loop",
        "three-no-new-in-animation-loop",
        "three-no-normalized-float-buffer-attribute",
        "three-no-object-construction-in-render",
        "three-no-redundant-uniforms-need-update",
        "three-no-shader-configuration-mutation-in-animation-loop",
        "three-no-shadows-on-unsupported-light",
        "three-no-state-in-animation-loop",
        "three-no-state-in-pointer-move",
        "three-no-sync-readback-in-animation-loop",
        "three-no-unconditional-renderer-resize-in-animation-loop",
        "three-on-before-compile-require-program-cache-key",
        "three-prefer-gpu-instanced-animation",
        "three-prefer-gpu-position-animation",
        "three-prefer-instanced-mesh",
        "three-prefer-set-animation-loop",
        "three-raw-shader-require-fragment-float-precision",
        "three-raw-shader-require-glsl3-version",
        "three-require-animation-mixer-cleanup",
        "three-require-animation-mixer-update",
        "three-require-camera-aspect-on-resize",
        "three-require-controls-cleanup",
        "three-require-controls-update",
        "three-require-data-texture-update",
        "three-require-dynamic-buffer-usage",
        "three-require-environment-for-metal",
        "three-require-frame-delta",
        "three-require-gpu-computation-cleanup",
        "three-require-instanced-buffer-update",
        "three-require-ktx2-detect-support",
        "three-require-lighting-for-pbr",
        "three-require-lit-material-normals",
        "three-require-loader-error-handling",
        "three-require-owned-geometry-cleanup",
        "three-require-owned-material-cleanup",
        "three-require-owned-texture-cleanup",
        "three-require-position-buffer-update",
        "three-require-postprocessing-cleanup",
        "three-require-projection-matrix-update",
        "three-require-render-in-animation-loop",
        "three-require-render-target-cleanup",
        "three-require-render-target-reset",
        "three-require-renderer-cleanup",
        "three-require-renderer-dom-attachment",
        "three-require-renderer-size",
        "three-require-shadows-enabled",
        "three-require-texture-update-after-wrapping-change",
        "three-require-transparent-for-opacity",
        "three-require-uv-for-texture-map",
        "three-require-worker-loader-cleanup",
        "three-shader-no-constant-out-of-bounds-index",
        "three-shader-no-derivatives-in-nonuniform-flow",
        "three-shader-no-glsl1-syntax-with-glsl3",
        "three-shader-no-invalid-clamp-bounds",
        "three-shader-no-invalid-constant-bit-operations",
        "three-shader-no-invalid-constant-math",
        "three-shader-no-invalid-smoothstep-edges",
        "three-shader-no-inverse-of-uniform",
        "three-shader-no-redeclared-builtins",
        "three-shader-no-redundant-frag-depth",
        "three-shader-no-reserved-identifiers",
        "three-shader-no-version-directive",
        "three-shader-prefer-small-integer-pow",
        "three-shader-prefer-squared-distance-comparison",
        "three-shader-require-compatible-uniform-values",
        "three-shader-require-fragment-output-on-all-paths",
        "three-shader-require-matching-uniforms",
        "three-shader-require-matching-varyings",
        "three-shader-require-position-on-all-paths",
        "three-shader-require-uniform-bindings",
        "three-shader-valid-global-initializers",
        "three-shader-valid-uniform-definitions",
        "three-texture-repeat-requires-wrapping",
        "three-tsl-no-js-uniform-branch",
        "three-valid-buffer-attribute-array-length",
        "three-valid-buffer-attribute-item-size",
        "three-valid-data-texture-data-length",
        "three-valid-data-texture-dimensions",
        "three-valid-fog-parameters",
        "three-valid-gpu-computation-dimensions",
        "three-valid-material-opacity",
        "three-valid-orthographic-camera",
        "three-valid-pbr-material-properties",
        "three-valid-perspective-camera",
        "three-valid-physical-material-properties",
        "three-valid-raycaster-range",
        "three-valid-shadow-map-size",
        "three-valid-spot-light-properties",
        "three-valid-texture-color-space",
        "three-webgpu-no-high-precision-instancing",
        "three-webgpu-no-legacy-effect-composer",
        "three-webgpu-no-legacy-material-api",
        "three-webgpu-require-init-before-sync-operation",
        "unsafe-json-in-html",
        "untrusted-redirect-following",
        "unused-dependency",
        "unused-dev-dependency",
        "unused-export",
        "unused-file",
        "unused-type",
        "url-prefilled-privileged-action",
        "use-lazy-motion",
        "valtio-no-proxy-read-in-render",
        "valtio-no-snapshot-in-callback",
        "void-dom-elements-no-children",
        "waapi-animation-in-render",
        "web-animation-offsets-valid",
        "webgl-no-sync-readback-in-animation-loop",
        "webhook-signature-risk",
        "window-open-without-noopener",
        "zod-v4-no-deprecated-error-apis",
        "zod-v4-no-deprecated-error-customization",
        "zod-v4-no-deprecated-schema-apis",
        "zod-v4-prefer-top-level-string-formats",
        "zustand-no-fresh-selector-result",
        "zustand-no-get-during-initialization",
        "zustand-no-mutating-state",
        "zustand-no-whole-store-destructure",
    ];
    assert_eq!(reference_catalog_ids.len(), 906);

    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert!(
        catalog.len() >= 906,
        "Expected at least 906 rules in catalog, got {}",
        catalog.len()
    );

    for &rule_key in reference_catalog_ids {
        let parsed = RuleId::parse(rule_key).unwrap_or_else(|| {
            panic!("Reference catalog rule {rule_key:?} failed to resolve via RuleId::parse")
        });
        let meta = parsed.metadata();
        assert!(
            catalog.iter().any(|entry| entry.id == meta.canonical_id),
            "Rule {} (from {rule_key}) missing from build_rule_catalog",
            meta.canonical_id
        );
        let explained = explain_rule(rule_key, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({rule_key:?}) returned None"));
        assert_eq!(explained.id, meta.canonical_id);
    }
}

fn collect_rs_sources_excluding_types(dir: &Path, out: &mut String) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir({dir:?}) failed: {e}"));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("dir entry failed: {e}"));
        let path = entry.path();
        if path.is_dir() {
            if path.ends_with("src/rules/catalog") {
                continue;
            }
            collect_rs_sources_excluding_types(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if path.ends_with("src/rules/types.rs") || path.ends_with("src/rules/catalog.rs") {
                continue;
            }
            let content =
                fs::read_to_string(&path).unwrap_or_else(|e| panic!("read({path:?}) failed: {e}"));
            out.push_str(&content);
            out.push('\n');
        }
    }
}

#[test]
fn polyglot_100_new_rules_and_reference_aliases_resolve_via_parse_and_explain_rule() {
    let registry = rule_registry();
    assert_eq!(registry.len(), 1076);

    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert_eq!(catalog.len(), 1076);

    // Verify every single registered rule (including all 100 new rules 976..=1075)
    // and every one of its legacy aliases resolves via `RuleId::parse` and `explain_rule`.
    for meta in &registry[976..1076] {
        assert_eq!(
            RuleId::parse(meta.canonical_id),
            Some(meta.id),
            "Canonical ID {:?} failed to resolve to {:?}",
            meta.canonical_id,
            meta.id
        );
        assert_eq!(
            RuleId::parse(meta.qualified_key),
            Some(meta.id),
            "Qualified key {:?} failed to resolve to {:?}",
            meta.qualified_key,
            meta.id
        );
        let explained_canonical = explain_rule(meta.canonical_id, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({:?}) returned None", meta.canonical_id));
        assert_eq!(explained_canonical.id, meta.canonical_id);

        assert!(
            !meta.legacy_aliases.is_empty(),
            "New polyglot/security rule {} ({:?}) must declare at least one reference alias",
            meta.canonical_id,
            meta.id
        );
        for &alias in meta.legacy_aliases {
            let parsed = RuleId::parse(alias).unwrap_or_else(|| {
                panic!(
                    "Reference alias {alias:?} for {} ({:?}) failed to resolve via RuleId::parse",
                    meta.canonical_id, meta.id
                )
            });
            assert_eq!(
                parsed, meta.id,
                "Reference alias {alias:?} resolved to {parsed:?}, expected {:?}",
                meta.id
            );
            let explained = explain_rule(alias, &cfg)
                .unwrap_or_else(|| panic!("explain_rule({alias:?}) returned None"));
            assert_eq!(explained.id, meta.canonical_id);
        }
    }

    // Explicitly verify reference aliases from angular-doctor, python-doctor, rust-doctor, and security-audit-skill.
    let expected_reference_aliases: &[(&str, RuleId)] = &[
        // angular-doctor (30 core + 8 template + 7 NgRx/Material = 45 rules)
        ("@angular-eslint/no-uncalled-signals", RuleId::AngularNoUncalledSignals),
        ("@angular-eslint/prefer-signal-model", RuleId::AngularPreferSignalModel),
        ("@angular-eslint/prefer-signals", RuleId::AngularPreferSignals),
        ("@angular-eslint/no-conflicting-lifecycle", RuleId::AngularNoConflictingLifecycle),
        ("@angular-eslint/contextual-lifecycle", RuleId::AngularContextualLifecycle),
        ("@angular-eslint/contextual-decorator", RuleId::AngularContextualDecorator),
        ("@angular-eslint/no-async-lifecycle-method", RuleId::AngularNoAsyncLifecycleMethod),
        ("@angular-eslint/no-lifecycle-call", RuleId::AngularNoLifecycleCall),
        ("@angular-eslint/require-lifecycle-on-prototype", RuleId::AngularRequireLifecycleOnPrototype),
        ("@angular-eslint/no-empty-lifecycle-method", RuleId::AngularNoEmptyLifecycleMethod),
        ("@angular-eslint/use-lifecycle-interface", RuleId::AngularUseLifecycleInterface),
        ("@angular-eslint/use-pipe-transform-interface", RuleId::AngularUsePipeTransformInterface),
        ("@angular-eslint/no-pipe-impure", RuleId::AngularNoPipeImpure),
        ("@angular-eslint/no-output-native", RuleId::AngularNoOutputNative),
        ("@angular-eslint/no-output-on-prefix", RuleId::AngularNoOutputOnPrefix),
        ("@angular-eslint/relative-url-prefix", RuleId::AngularRelativeUrlPrefix),
        ("@angular-eslint/prefer-standalone", RuleId::AngularPreferStandalone),
        ("@angular-eslint/prefer-inject", RuleId::AngularPreferInject),
        ("@angular-eslint/use-injectable-provided-in", RuleId::AngularUseInjectableProvidedIn),
        ("@angular-eslint/prefer-host-metadata-property", RuleId::AngularPreferHostMetadataProperty),
        ("@angular-eslint/no-duplicates-in-metadata-arrays", RuleId::AngularNoDuplicatesInMetadataArrays),
        ("@angular-eslint/no-forward-ref", RuleId::AngularNoForwardRef),
        ("@angular-eslint/no-inputs-metadata-property", RuleId::AngularNoInputsMetadataProperty),
        ("@angular-eslint/no-outputs-metadata-property", RuleId::AngularNoOutputsMetadataProperty),
        ("@angular-eslint/no-queries-metadata-property", RuleId::AngularNoQueriesMetadataProperty),
        ("@angular-eslint/prefer-output-readonly", RuleId::AngularPreferOutputReadonly),
        ("@angular-eslint/prefer-output-emitter-ref", RuleId::AngularPreferOutputEmitterRef),
        ("@angular-eslint/use-component-view-encapsulation", RuleId::AngularUseComponentViewEncapsulation),
        ("@angular-eslint/no-attribute-decorator", RuleId::AngularNoAttributeDecorator),
        ("@angular-eslint/component-max-inline-declarations", RuleId::AngularComponentMaxInlineDeclarations),
        ("@angular-eslint/template/no-any", RuleId::AngularTemplateNoAny),
        ("@angular-eslint/template/alt-text", RuleId::AngularTemplateAltText),
        ("@angular-eslint/template/click-events-have-key-events", RuleId::AngularTemplateClickEventsHaveKeyEvents),
        ("@angular-eslint/template/mouse-events-have-key-events", RuleId::AngularTemplateMouseEventsHaveKeyEvents),
        ("@angular-eslint/template/elements-have-content", RuleId::AngularTemplateElementsHaveContent),
        ("@angular-eslint/template/interactive-supports-focus", RuleId::AngularTemplateInteractiveSupportsFocus),
        ("@angular-eslint/template/table-scope", RuleId::AngularTemplateTableScope),
        ("@angular-eslint/template/valid-aria", RuleId::AngularTemplateValidAria),
        ("@ngrx/no-multiple-actions-in-effects", RuleId::NgrxNoMultipleActionsInEffects),
        ("@ngrx/no-effect-decorator-and-creator", RuleId::NgrxNoEffectDecoratorAndCreator),
        ("@ngrx/no-effect-decorator", RuleId::NgrxNoEffectDecoratorAndCreator),
        ("@ngrx/no-cyclic-action-creators", RuleId::NgrxNoCyclicActionCreators),
        ("@ngrx/no-typed-global-store", RuleId::NgrxNoTypedGlobalStore),
        ("@ngrx/on-function-explicit-return-type", RuleId::NgrxOnFunctionExplicitReturnType),
        ("@ngrx/select-style", RuleId::NgrxSelectStyle),
        ("@angular/material/no-conflicting-mixins", RuleId::AngularMaterialNoConflictingMixins),
        // python-doctor (7 Zen/imports + 5 Bandit + 2 structure = 14 rules)
        ("zen/complex-function", RuleId::PyZenComplexFunction),
        ("radon/CC", RuleId::PyZenComplexFunction),
        ("zen/deep-nesting", RuleId::PyZenDeepNesting),
        ("zen/long-function", RuleId::PyZenLongFunction),
        ("zen/too-many-params", RuleId::PyZenTooManyParams),
        ("zen/large-class", RuleId::PyZenLargeClass),
        ("zen/dense-code", RuleId::PyZenNoDenseSemicolonStatements),
        ("E702", RuleId::PyZenNoDenseSemicolonStatements),
        ("imports/star", RuleId::PyNoWildcardImport),
        ("F403", RuleId::PyNoWildcardImport),
        ("bandit/B113", RuleId::PySecurityHttpRequestRequiresTimeout),
        ("bandit/B501", RuleId::PySecurityNoDisabledTlsVerify),
        ("bandit/B303", RuleId::PySecurityNoWeakCryptoOrRandom),
        ("bandit/B311", RuleId::PySecurityNoWeakCryptoOrRandom),
        ("bandit/B324", RuleId::PySecurityNoWeakCryptoOrRandom),
        ("bandit/B202", RuleId::PySecurityNoXxeOrUnsafeArchive),
        ("bandit/B314", RuleId::PySecurityNoXxeOrUnsafeArchive),
        ("bandit/B320", RuleId::PySecurityNoXxeOrUnsafeArchive),
        ("bandit/B105", RuleId::PySecurityNoHardcodedSecretOrTmp),
        ("bandit/B106", RuleId::PySecurityNoHardcodedSecretOrTmp),
        ("bandit/B108", RuleId::PySecurityNoHardcodedSecretOrTmp),
        ("structure/no-py-typed", RuleId::PyStructureMissingPyTyped),
        ("structure/type-hints", RuleId::PyStructureLowTypeHintCoverage),
        // rust-doctor (9 SourceKernel + 11 Cargo + 8 Structure + 7 Clippy = 35 rules)
        ("rust_doctor::source::block_in_place_on_current_thread", RuleId::RsTokioNoBlockInPlaceOnCurrentThread),
        ("rust_doctor::source::block_on_in_async", RuleId::RsAsyncNoBlockOnInAsync),
        ("rust_doctor::source::disabled_tls_verification", RuleId::RsSecurityNoDisabledTlsVerification),
        ("rust_doctor::source::dynamic_shell_command", RuleId::RsSecurityNoDynamicShellCommand),
        ("rust_doctor::source::unchecked_http_status", RuleId::RsHttpNoUncheckedResponseStatus),
        ("rust_doctor::source::secret_env_fallback", RuleId::RsSecurityNoSecretEnvFallback),
        ("rust_doctor::source::permissive_cors", RuleId::RsSecurityNoPermissiveCors),
        ("rust_doctor::source::insecure_auth_cookie", RuleId::RsSecurityNoInsecureAuthCookie),
        ("rust_doctor::source::disabled_jwt_validation", RuleId::RsSecurityNoDisabledJwtValidation),
        ("rust_doctor::cargo::duplicate_major_versions", RuleId::RsCargoDuplicateMajorVersions),
        ("rust_doctor::cargo::missing_lockfile", RuleId::RsCargoMissingLockfile),
        ("rust_doctor::cargo::path_dependency_outside_workspace", RuleId::RsCargoPathDepOutsideWorkspace),
        ("rust_doctor::cargo::permissive_lint_table", RuleId::RsCargoPermissiveLintTable),
        ("rust_doctor::cargo::permissive_rustflags", RuleId::RsCargoPermissiveRustflags),
        ("rust_doctor::cargo::release_debug_symbols", RuleId::RsCargoReleaseDebugSymbols),
        ("rust_doctor::cargo::unchecked_release_overflow", RuleId::RsCargoUncheckedReleaseOverflow),
        ("rust_doctor::cargo::unused_dependency", RuleId::RsCargoUnusedDependency),
        ("rust_doctor::cargo::test_only_dependency", RuleId::RsCargoTestOnlyDependency),
        ("rust_doctor::cargo::unbounded_registry_dependency", RuleId::RsCargoUnboundedWildcardDependency),
        ("rust_doctor::cargo::unpinned_git_dependency", RuleId::RsCargoUnpinnedGitDependency),
        ("rust_doctor::structure::crate_level_allow", RuleId::RsStructureCrateLevelAllow),
        ("rust_doctor::structure::unreasoned_allow_attribute", RuleId::RsStructureUnreasonedAllow),
        ("rust_doctor::structure::stacked_allow_attribute", RuleId::RsStructureStackedAllow),
        ("rust_doctor::structure::complex_function", RuleId::RsStructureComplexFunction),
        ("rust_doctor::structure::oversized_unit", RuleId::RsStructureOversizedUnit),
        ("rust_doctor::structure::orphan_module_file", RuleId::RsStructureOrphanModuleFile),
        ("rust_doctor::structure::unreferenced_feature", RuleId::RsStructureUnreferencedFeature),
        ("rust_doctor::structure::near_duplicate_function_body", RuleId::RsStructureNearDuplicateFunction),
        ("rust_doctor::structure::duplicate_function_body", RuleId::RsStructureNearDuplicateFunction),
        ("clippy::await_holding_refcell_ref", RuleId::RsNoAwaitHoldingRefcell),
        ("clippy::panic", RuleId::RsNoPanicOrTodoInProduction),
        ("clippy::todo", RuleId::RsNoPanicOrTodoInProduction),
        ("clippy::dbg_macro", RuleId::RsNoDbgOrPrintInLibrary),
        ("clippy::print_stdout", RuleId::RsNoDbgOrPrintInLibrary),
        ("clippy::permissions_set_readonly_false", RuleId::RsSecurityNoWorldWritablePermissions),
        ("clippy::zombie_processes", RuleId::RsNoZombieChildProcess),
        ("clippy::missing_transmute_annotations", RuleId::RsNoTransmuteWithoutTypeAnnotations),
        ("clippy::missing_safety_doc", RuleId::RsRequireSafetyDocOnPubUnsafeFn),
        // security-audit-skill & rust_doctor::repo (6 rules)
        ("rust_doctor::repo::secret_in_build_step", RuleId::CiWorkflowSecurityRisk),
        ("workflow-injection", RuleId::CiWorkflowSecurityRisk),
        ("ci-workflow-security-risk", RuleId::CiWorkflowSecurityRisk),
        ("electron-webview-bridge-risk", RuleId::ElectronWebviewBridgeRisk),
        ("untrusted-host-header-origin", RuleId::UntrustedHostHeaderOrigin),
        ("private-response-public-cache", RuleId::PrivateResponsePublicCache),
        ("llm-prompt-role-and-tool-sink-risk", RuleId::LlmPromptRoleAndToolSinkRisk),
        ("supabase-service-role-unscoped-query", RuleId::SupabaseServiceRoleUnscopedQuery),
    ];

    for &(alias, expected_id) in expected_reference_aliases {
        assert_eq!(
            RuleId::parse(alias),
            Some(expected_id),
            "Expected reference alias {alias:?} to parse to {expected_id:?}"
        );
        let explained = explain_rule(alias, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({alias:?}) returned None"));
        assert_eq!(explained.id, expected_id.as_str());
    }
}

#[test]
fn self_hosting_workspace_scan_reports_zero_findings_and_100_health_score() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![manifest_dir],
            include_tests: false,
            ..Default::default()
        },
        &CliOverrides {
            no_cache: true,
            ..Default::default()
        },
    )
    .expect("Self-hosting scan_workspace_with_overrides must succeed");

    assert!(
        report.diagnostics.is_empty(),
        "Expected 0 self-hosting diagnostics across dotore workspace, got {}:\n{:#?}",
        report.diagnostics.len(),
        report.diagnostics
    );
    assert_eq!(report.summary.health_score, 100);
    assert_eq!(report.summary.score_label, "Excellent");
    assert!(
        report.projects.len() >= 5,
        "Expected at least 5 workspace packages, got {}",
        report.projects.len()
    );
    for proj in &report.projects {
        assert_eq!(
            proj.diagnostic_count, 0,
            "Expected 0 findings in workspace package {}, got {}",
            proj.name, proj.diagnostic_count
        );
        assert_eq!(
            proj.health_score, 100,
            "Expected 100/100 score in workspace package {}, got {}",
            proj.name, proj.health_score
        );
    }
}
