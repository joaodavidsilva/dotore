//! Domain types for the unified rule registry, metadata, categories, tags,
//! **Capability Gate** predicates, **Contextual Owner** policies, **Prescription Tiers**,
//! and autofix patches.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    config::{Capability, CapabilityPredicate},
    graph::ResolvedCallerSite,
    ir::{ByteSpan, SourceLoc},
};

/// High-level category for a diagnostic rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    /// Correctness and runtime bug rules.
    Bugs,
    /// Re-render, CPU, network, and bundle performance rules.
    Performance,
    /// WCAG and UI accessibility rules.
    Accessibility,
    /// Security and trust-boundary rules.
    Security,
    /// Architecture, dead-code, and maintainability rules.
    Maintainability,
}

impl RuleCategory {
    /// Returns the canonical display name of this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bugs => "Bugs",
            Self::Performance => "Performance",
            Self::Accessibility => "Accessibility",
            Self::Security => "Security",
            Self::Maintainability => "Maintainability",
        }
    }

    /// Parses a category name (case-insensitive).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bugs" | "correctness" => Some(Self::Bugs),
            "performance" | "perf" => Some(Self::Performance),
            "accessibility" | "a11y" => Some(Self::Accessibility),
            "security" => Some(Self::Security),
            "maintainability" | "architecture" => Some(Self::Maintainability),
            _ => None,
        }
    }
}

/// Diagnostic severity level (`error` or `warning`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSeverity {
    /// Error-level finding (blocks CI by default).
    Error,
    /// Warning-level finding (advisory by default unless `--blocking warning` is set).
    Warning,
}

impl RuleSeverity {
    /// Returns `"error"` or `"warning"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// Severity override accepted in `dotore.config.*` and `package.json#dotore` (`"off"`, `"warn"`, `"error"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSeverityOverride {
    /// Promote or keep the rule at error severity.
    Error,
    /// Downgrade or enable the rule at warning severity.
    #[serde(alias = "warning")]
    Warn,
    /// Disable the rule completely.
    Off,
}

impl RuleSeverityOverride {
    /// Parses a severity override string (`"off"`, `"warn"`, `"warning"`, `"error"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Behavioral tag attached to a rule in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleTag {
    /// Automatically suppressed in test and story files unless also tagged `MigrationHint`.
    TestNoise,
    /// UI design polish rule (opt-in during standard scans, active via `dotore design`).
    Design,
    /// API or version migration rule (still runs in test files even when tagged `TestNoise`).
    MigrationHint,
    /// Applies React JSX semantics and requires `Capability::React`.
    ReactJsxOnly,
    /// WebGL resource or rendering rule.
    Webgl,
    /// Three.js 3D engine rule.
    Three,
    /// React Three Fiber (`@react-three/fiber`) rule.
    R3f,
    /// React Native / Expo mobile rule.
    ReactNative,
    /// Security and trust-boundary scan rule.
    SecurityScan,
    /// Ink terminal UI rule.
    Ink,
    /// Server Action / Server Function boundary rule.
    ServerAction,
    /// Whole-project module graph / dead-code analysis rule.
    ProjectAnalysis,
    /// Opt-in rule (`default_enabled: false`).
    OptIn,
}

impl RuleTag {
    /// Returns the canonical kebab-case tag string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestNoise => "test-noise",
            Self::Design => "design",
            Self::MigrationHint => "migration-hint",
            Self::ReactJsxOnly => "react-jsx-only",
            Self::Webgl => "webgl",
            Self::Three => "three",
            Self::R3f => "r3f",
            Self::ReactNative => "react-native",
            Self::SecurityScan => "security-scan",
            Self::Ink => "ink",
            Self::ServerAction => "server-action",
            Self::ProjectAnalysis => "project-analysis",
            Self::OptIn => "opt-in",
        }
    }

    /// Parses a [`RuleTag`] from its kebab-case string.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "test-noise" => Some(Self::TestNoise),
            "design" => Some(Self::Design),
            "migration-hint" => Some(Self::MigrationHint),
            "react-jsx-only" => Some(Self::ReactJsxOnly),
            "webgl" => Some(Self::Webgl),
            "three" => Some(Self::Three),
            "r3f" => Some(Self::R3f),
            "react-native" => Some(Self::ReactNative),
            "security-scan" => Some(Self::SecurityScan),
            "ink" => Some(Self::Ink),
            "server-action" => Some(Self::ServerAction),
            "project-analysis" => Some(Self::ProjectAnalysis),
            "opt-in" => Some(Self::OptIn),
            _ => None,
        }
    }
}

/// **Contextual Owner** policy determining the syntax unit that owns a diagnostic during `--scope contextual` diff filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextualOwnerPolicy {
    /// Owned by the flagged source line(s).
    Line,
    /// Owned by the enclosing JSX element.
    JsxElement,
    /// Owned by the enclosing React **Subject** (component or custom hook) or function.
    Subject,
    /// Owned by explicit related AST nodes (such as a hook callback and its dependency array).
    RelatedNodes,
    /// Owned by the entire source file.
    File,
}

impl ContextualOwnerPolicy {
    /// Returns the kebab-case policy identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::JsxElement => "jsx-element",
            Self::Subject => "subject",
            Self::RelatedNodes => "related-nodes",
            Self::File => "file",
        }
    }
}

/// Level of intervention required to resolve a diagnostic (see `GLOSSARY.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrescriptionTier {
    /// Deterministic single- or cross-file rewrite applied directly by `dotore fix`.
    Autofix,
    /// Localized single-**Subject** change with a direct code recipe.
    Surgical,
    /// State-model or cross-**Subject** contract redesign.
    Refactor,
}

impl PrescriptionTier {
    /// Returns the kebab-case label for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Autofix => "autofix",
            Self::Surgical => "surgical",
            Self::Refactor => "refactor",
        }
    }

    /// Parses a tier name from CLI filters.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "autofix" => Some(Self::Autofix),
            "surgical" => Some(Self::Surgical),
            "refactor" => Some(Self::Refactor),
            _ => None,
        }
    }
}

/// Canonical identifier for each diagnostic rule in `dotore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleId {
    /// Updating state from props or state inside `useEffect`.
    NoDerivedState,
    /// Chaining state updates across one or multiple `useEffect`s.
    NoChainStateUpdates,
    /// Using state/props + `useEffect` as an event handler.
    NoEventHandler,
    /// Adjusting partial state when a prop changes.
    NoAdjustStateOnPropChange,
    /// Resetting all state when a prop changes instead of passing `key`.
    NoResetAllStateOnPropChange,
    /// Calling a parent callback prop with live local state inside `useEffect`.
    NoPassLiveStateToParent,
    /// Calling a parent callback prop with fetched/hook data inside `useEffect`.
    NoPassDataToParent,
    /// Subscribing to an external store in `useEffect` instead of `useSyncExternalStore`.
    NoExternalStoreSubscription,
    /// Initializing state synchronously in a mount-only `useEffect(..., [])`.
    NoInitializeState,
    /// Fetching data inside `useEffect` (with or without cancellation cleanup).
    NoFetchInEffect,
    /// Missing `key` prop on elements in an array or iterator.
    JsxKey,
    /// Using array index as `key` prop in `.map()`.
    NoArrayIndexAsKey,
    /// Referencing an undefined JSX component identifier.
    JsxNoUndef,
    /// Missing or unnecessary dependencies in React hooks (`useEffect`, `useMemo`, `useCallback`).
    ExhaustiveDeps,
    /// Exporting non-component values alongside React components in Fast Refresh modules.
    OnlyExportComponents,
    /// Mutating `useState` value binding directly instead of calling the state setter.
    NoDirectMutationState,
    /// Passing a freshly allocated object literal as a JSX prop (disabled when React Compiler is active).
    JsxNoNewObjectAsProp,
    /// `<img>` element missing accessible `alt` attribute.
    AltText,
    /// Animation / motion usage without reduced-motion guard.
    RequireReducedMotion,
    /// Vague button label (`"Click here"`, `"Submit"`) flagged in design audit.
    DesignNoVagueButtonLabel,
    /// Using `dangerouslySetInnerHTML` on a JSX element.
    NoDanger,
    /// `"use server"` action missing an authentication guard.
    ServerAuthActions,
    /// `await` inside a `for`/`while` loop instead of `Promise.all`.
    AsyncAwaitInLoop,
    /// Passing render-prop children function to a component (skipped on library entrypoints).
    NoRenderPropChildren,
    /// Unreferenced source file in the project module graph.
    UnusedFile,
    /// Raw `<img>` element in Next.js instead of `next/image`.
    NextjsNoImgElement,
    /// Raw text node outside `<Text>` or configured `textComponents` in React Native.
    RnNoRawText,
    /// Dynamic `process.env[key]` access in Expo instead of static `process.env.EXPO_PUBLIC_*`.
    ExpoNoNonInlinedEnv,
    /// `useQuery` with a `queryFn` that returns `undefined` / `void`.
    QueryNoVoidQueryFn,
    /// TanStack Start `createServerFn` handler without `.validator(...)` input validation.
    TanstackStartServerFnValidateInput,
    /// Allocating Three.js geometry inside `requestAnimationFrame`.
    ThreeNoGeometryInFrameLoop,
    /// Allocating `new THREE.*` objects inside React Three Fiber `useFrame`.
    R3fNoNewInUseFrame,
    /// Calling a Zustand store hook without a selector (`useStore()`).
    ZustandNoWholeStoreDestructure,
    /// Calling Jotai `selectAtom` inline inside a component render body.
    JotaiSelectAtomInRenderBody,
    /// Calling MobX `reaction` / `autorun` inside `useEffect` without returning its disposer.
    MobxReactionDisposerDiscarded,
    /// Reading a Valtio `useSnapshot` result inside an event handler callback instead of the proxy.
    ValtioNoSnapshotInCallback,
    /// Importing from `'react'` in a pure Preact project.
    PreactNoReactImport,
    /// Raw text outside Ink `<Text>` in terminal UI components.
    InkNoRawText,
    /// Deprecated Zod v4 `.strict()` / `.passthrough()` / `.strip()` schema calls.
    ZodV4DeprecatedParse,
}

/// Static catalog metadata for a registered diagnostic rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    /// Typed [`RuleId`] variant.
    pub id: RuleId,
    /// Canonical short identifier (`"no-derived-state"`).
    pub canonical_id: &'static str,
    /// Qualified identifier (`"dotore/no-derived-state"`).
    pub qualified_key: &'static str,
    /// Legacy plugin-prefixed aliases (`"effect/no-derived-state"`, `"react/jsx-key"`, etc.).
    pub legacy_aliases: &'static [&'static str],
    /// Short human-readable headline.
    pub title: &'static str,
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    pub category: RuleCategory,
    /// Default severity (`Error` or `Warning`).
    pub default_severity: RuleSeverity,
    /// Whether the rule is enabled by default in standard scans.
    pub default_enabled: bool,
    /// Whether the rule was originally ported from an external plugin (governed by `customRulesOnly`).
    pub originally_external: bool,
    /// Behavioral tags attached to this rule.
    pub tags: &'static [RuleTag],
    /// **Capability Gate** activation predicate.
    pub capability_gate: CapabilityPredicate,
    /// **Contextual Owner** policy for `--scope contextual` diff filtering.
    pub contextual_owner: ContextualOwnerPolicy,
    /// Default **Prescription Tier** (`Autofix`, `Surgical`, `Refactor`).
    pub default_tier: PrescriptionTier,
    /// Official documentation URL.
    pub docs_url: &'static str,
    /// Compiled-in remediation recipe (Markdown transformation instructions).
    pub recipe_markdown: &'static str,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Static rule registry constructor binds all 15 metadata fields in a single compact table entry"
)]
const fn rule_meta(
    id: RuleId,
    canonical_id: &'static str,
    qualified_key: &'static str,
    legacy_aliases: &'static [&'static str],
    title: &'static str,
    category: RuleCategory,
    default_severity: RuleSeverity,
    default_enabled: bool,
    originally_external: bool,
    tags: &'static [RuleTag],
    capability_gate: CapabilityPredicate,
    contextual_owner: ContextualOwnerPolicy,
    default_tier: PrescriptionTier,
    docs_url: &'static str,
    recipe_markdown: &'static str,
) -> RuleMetadata {
    RuleMetadata {
        id,
        canonical_id,
        qualified_key,
        legacy_aliases,
        title,
        category,
        default_severity,
        default_enabled,
        originally_external,
        tags,
        capability_gate,
        contextual_owner,
        default_tier,
        docs_url,
        recipe_markdown,
    }
}

const RULE_REGISTRY: &[RuleMetadata] = &[
    rule_meta(
        RuleId::NoDerivedState,
        "no-derived-state",
        "dotore/no-derived-state",
        &["effect/no-derived-state", "no-derived-state-effect"],
        "Derived state computed inside useEffect",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Autofix,
        "https://react.dev/learn/you-might-not-need-an-effect#updating-state-based-on-props-or-state",
        "Replace the `useState` + `useEffect` pair with a `const` computed directly during render from props or existing state.",
    ),
    rule_meta(
        RuleId::NoChainStateUpdates,
        "no-chain-state-updates",
        "dotore/no-chain-state-updates",
        &["effect/no-chain-state-updates"],
        "Chained state updates across Effect Nodes",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/you-might-not-need-an-effect#chains-of-computations",
        "Compute derived values during render and apply all related state transitions together inside the originating event handler.",
    ),
    rule_meta(
        RuleId::NoEventHandler,
        "no-event-handler",
        "dotore/no-event-handler",
        &["effect/no-event-handler"],
        "Event-specific logic inside useEffect",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/you-might-not-need-an-effect#sharing-logic-between-event-handlers",
        "Move action-triggered side effects out of `useEffect` and invoke them directly from the user event handler.",
    ),
    rule_meta(
        RuleId::NoAdjustStateOnPropChange,
        "no-adjust-state-on-prop-change",
        "dotore/no-adjust-state-on-prop-change",
        &["effect/no-adjust-state-on-prop-change"],
        "Partial state adjusted in useEffect on prop change",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/you-might-not-need-an-effect#adjusting-some-state-when-a-prop-changes",
        "Derive the value during render (e.g. storing an ID instead of the selected object) or pass a `key` prop to reset component state.",
    ),
    rule_meta(
        RuleId::NoResetAllStateOnPropChange,
        "no-reset-all-state-on-prop-change",
        "dotore/no-reset-all-state-on-prop-change",
        &["effect/no-reset-all-state-on-prop-change"],
        "All state reset in useEffect on prop change",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/you-might-not-need-an-effect#resetting-all-state-when-a-prop-changes",
        "Remove the state-resetting `useEffect` and pass `key={prop}` on the component at its parent JSX Caller Sites.",
    ),
    rule_meta(
        RuleId::NoPassLiveStateToParent,
        "no-pass-live-state-to-parent",
        "dotore/no-pass-live-state-to-parent",
        &["effect/no-pass-live-state-to-parent"],
        "Live local state pushed to parent via useEffect",
        RuleCategory::Maintainability,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/you-might-not-need-an-effect#notifying-parent-components-about-state-changes",
        "Call the parent callback alongside `setState` in the event handler, or lift the State Slot up to the parent Subject.",
    ),
    rule_meta(
        RuleId::NoPassDataToParent,
        "no-pass-data-to-parent",
        "dotore/no-pass-data-to-parent",
        &["effect/no-pass-data-to-parent"],
        "External or fetched data passed upward via useEffect",
        RuleCategory::Maintainability,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/you-might-not-need-an-effect#passing-data-to-the-parent",
        "Fetch or subscribe to the data in the parent Subject and pass it down as props instead of pushing it upward in an Effect Node.",
    ),
    rule_meta(
        RuleId::NoExternalStoreSubscription,
        "no-external-store-subscription",
        "dotore/no-external-store-subscription",
        &["effect/no-external-store-subscription"],
        "Manual external store subscription inside useEffect",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/you-might-not-need-an-effect#subscribing-to-an-external-store",
        "Replace manual `useEffect` + `useState` subscription logic with `useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)`.",
    ),
    rule_meta(
        RuleId::NoInitializeState,
        "no-initialize-state",
        "dotore/no-initialize-state",
        &["effect/no-initialize-state"],
        "Synchronous state initialization in mount useEffect",
        RuleCategory::Performance,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Autofix,
        "https://tkdodo.eu/blog/avoiding-hydration-mismatches-with-use-sync-external-store",
        "Pass the initial value or lazy initializer function directly to `useState(init)` instead of setting state on mount.",
    ),
    rule_meta(
        RuleId::NoFetchInEffect,
        "no-fetch-in-effect",
        "dotore/no-fetch-in-effect",
        &["effect/no-fetch-in-effect"],
        "Data fetching inside useEffect",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/you-might-not-need-an-effect#fetching-data",
        "Add an `AbortController` or cleanup cancellation flag to prevent race conditions, or migrate to `useQuery` / framework data loaders.",
    ),
    rule_meta(
        RuleId::JsxKey,
        "jsx-key",
        "dotore/jsx-key",
        &["react/jsx-key"],
        "Missing key prop on list JSX element",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        true,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/rendering-lists#keeping-list-items-in-order-with-key",
        "Provide a stable, unique `key={item.id}` prop on the root JSX element returned from `.map()`.",
    ),
    rule_meta(
        RuleId::NoArrayIndexAsKey,
        "no-array-index-as-key",
        "dotore/no-array-index-as-key",
        &["react/no-array-index-key", "no-array-index-key"],
        "Array index used as JSX key",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        true,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/rendering-lists#why-does-react-need-keys",
        "Use a stable domain identifier (such as `item.id`) instead of the array index as the `key` prop.",
    ),
    rule_meta(
        RuleId::JsxNoUndef,
        "jsx-no-undef",
        "dotore/jsx-no-undef",
        &["react/jsx-no-undef"],
        "Undefined JSX component",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        true,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/importing-and-exporting-components",
        "Import the component or declare it in `runtimeGlobals` if it is injected by the host environment.",
    ),
    rule_meta(
        RuleId::ExhaustiveDeps,
        "exhaustive-deps",
        "dotore/exhaustive-deps",
        &["react-hooks/exhaustive-deps", "react/exhaustive-deps"],
        "Missing or unnecessary hook dependencies",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        true,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::RelatedNodes,
        PrescriptionTier::Surgical,
        "https://react.dev/reference/react/useEffect#specifying-reactive-dependencies",
        "Include all reactive values read inside the hook callback in its dependency array, or move static helpers outside the component.",
    ),
    rule_meta(
        RuleId::OnlyExportComponents,
        "only-export-components",
        "dotore/only-export-components",
        &[
            "react-refresh/only-export-components",
            "react/only-export-components",
        ],
        "Mixed component and non-component exports break Fast Refresh",
        RuleCategory::Maintainability,
        RuleSeverity::Warning,
        true,
        true,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::File,
        PrescriptionTier::Refactor,
        "https://github.com/ArnaudBarre/eslint-plugin-react-refresh",
        "Move shared constants, hooks, or utility functions into a separate module so the component file exports only React components.",
    ),
    rule_meta(
        RuleId::NoDirectMutationState,
        "no-direct-mutation-state",
        "dotore/no-direct-mutation-state",
        &["react/no-direct-mutation-state"],
        "Direct mutation of React state",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        true,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Surgical,
        "https://react.dev/learn/updating-objects-in-state",
        "Treat React state as immutable and pass a new object or array copy to the state setter instead of mutating properties in place.",
    ),
    rule_meta(
        RuleId::JsxNoNewObjectAsProp,
        "jsx-no-new-object-as-prop",
        "dotore/jsx-no-new-object-as-prop",
        &[
            "react-perf/jsx-no-new-object-as-prop",
            "react/jsx-no-new-object-as-prop",
        ],
        "Fresh object literal passed as JSX prop",
        RuleCategory::Performance,
        RuleSeverity::Warning,
        true,
        true,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate {
            requires: &[Capability::React],
            disabled_when: &[Capability::ReactCompiler],
            app_only: false,
        },
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://react.dev/reference/react/useMemo",
        "Hoist static objects to module scope or memoize dynamic objects passed to memoized child components.",
    ),
    rule_meta(
        RuleId::AltText,
        "alt-text",
        "dotore/alt-text",
        &["jsx-a11y/alt-text"],
        "Image missing alt text",
        RuleCategory::Accessibility,
        RuleSeverity::Error,
        true,
        true,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://www.w3.org/WAI/tutorials/images/",
        "Provide a descriptive `alt` attribute on `<img>` elements, or `alt=\"\"` for decorative images.",
    ),
    rule_meta(
        RuleId::RequireReducedMotion,
        "require-reduced-motion",
        "dotore/require-reduced-motion",
        &[],
        "Motion animation without prefers-reduced-motion handling",
        RuleCategory::Accessibility,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::TestNoise],
        CapabilityPredicate::require(&[Capability::Motion]),
        ContextualOwnerPolicy::File,
        PrescriptionTier::Surgical,
        "https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion",
        "Respect `prefers-reduced-motion` via `useReducedMotion()`, `<MotionConfig reducedMotion=\"user\">`, or `@media (prefers-reduced-motion: reduce)`.",
    ),
    rule_meta(
        RuleId::DesignNoVagueButtonLabel,
        "design-no-vague-button-label",
        "dotore/design-no-vague-button-label",
        &[],
        "Vague button label",
        RuleCategory::Accessibility,
        RuleSeverity::Warning,
        false,
        false,
        &[RuleTag::Design, RuleTag::ReactJsxOnly, RuleTag::OptIn],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://www.w3.org/WAI/WCAG21/Understanding/headings-and-labels.html",
        "Replace generic button labels (`Click here`, `Submit`) with specific action verbs describing what the button does.",
    ),
    rule_meta(
        RuleId::NoDanger,
        "no-danger",
        "dotore/no-danger",
        &["react/no-danger"],
        "Dangerous raw HTML injection via dangerouslySetInnerHTML",
        RuleCategory::Security,
        RuleSeverity::Warning,
        true,
        true,
        &[RuleTag::ReactJsxOnly, RuleTag::SecurityScan],
        CapabilityPredicate::REACT_ONLY,
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
        "Avoid `dangerouslySetInnerHTML` or sanitize untrusted HTML with DOMPurify before rendering.",
    ),
    rule_meta(
        RuleId::ServerAuthActions,
        "server-auth-actions",
        "dotore/server-auth-actions",
        &[],
        "Server Action missing authentication check",
        RuleCategory::Security,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ServerAction, RuleTag::SecurityScan],
        CapabilityPredicate::require(&[Capability::ServerActions]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#security",
        "Verify the caller's session and authorization at the entry of every exported `'use server'` action before mutating data.",
    ),
    rule_meta(
        RuleId::AsyncAwaitInLoop,
        "async-await-in-loop",
        "dotore/async-await-in-loop",
        &["no-await-in-loop"],
        "Sequential await inside loop",
        RuleCategory::Performance,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::TestNoise],
        CapabilityPredicate::UNIVERSAL,
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Surgical,
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all",
        "Collect promises across iterations and await them concurrently with `await Promise.all(...)` when iterations are independent.",
    ),
    rule_meta(
        RuleId::NoRenderPropChildren,
        "no-render-prop-children",
        "dotore/no-render-prop-children",
        &[],
        "Render-prop function passed as JSX children",
        RuleCategory::Maintainability,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate {
            requires: &[Capability::React],
            disabled_when: &[],
            app_only: true,
        },
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/passing-props-to-a-component",
        "Prefer custom hooks or composable JSX children over inline render-prop child functions in application components.",
    ),
    rule_meta(
        RuleId::UnusedFile,
        "unused-file",
        "dotore/unused-file",
        &["deslop/unused-file"],
        "Unreferenced source file",
        RuleCategory::Maintainability,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ProjectAnalysis],
        CapabilityPredicate::UNIVERSAL,
        ContextualOwnerPolicy::File,
        PrescriptionTier::Refactor,
        "https://react.dev/learn/importing-and-exporting-components",
        "Remove the unreferenced file or export and wire it into the module dependency graph.",
    ),
    rule_meta(
        RuleId::NextjsNoImgElement,
        "nextjs-no-img-element",
        "dotore/nextjs-no-img-element",
        &["@next/next/no-img-element"],
        "Raw <img> element in Next.js component",
        RuleCategory::Performance,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::require(&[Capability::Nextjs]),
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://nextjs.org/docs/messages/no-img-element",
        "Use `<Image />` from `next/image` for automatic image optimization, sizing, and lazy loading.",
    ),
    rule_meta(
        RuleId::RnNoRawText,
        "rn-no-raw-text",
        "dotore/rn-no-raw-text",
        &["react-native/no-raw-text"],
        "Raw text outside <Text> in React Native",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactNative, RuleTag::ReactJsxOnly],
        CapabilityPredicate::require(&[Capability::ReactNative]),
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://reactnative.dev/docs/text",
        "Wrap raw strings in React Native `<Text>` (or register custom text wrappers in `textComponents` / `rawTextWrapperComponents`).",
    ),
    rule_meta(
        RuleId::ExpoNoNonInlinedEnv,
        "expo-no-non-inlined-env",
        "dotore/expo-no-non-inlined-env",
        &[],
        "Dynamic process.env access in Expo bundle",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactNative],
        CapabilityPredicate::require(&[Capability::Expo]),
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Surgical,
        "https://docs.expo.dev/guides/environment-variables/",
        "Access Expo environment variables using static dot notation (`process.env.EXPO_PUBLIC_KEY`) so Metro can inline them at build time.",
    ),
    rule_meta(
        RuleId::QueryNoVoidQueryFn,
        "query-no-void-query-fn",
        "dotore/query-no-void-query-fn",
        &[],
        "TanStack useQuery queryFn returns void/undefined",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::TestNoise],
        CapabilityPredicate::require(&[Capability::TanstackQuery]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://tanstack.com/query/latest/docs/framework/react/guides/query-functions",
        "Return the resolved data promise from `queryFn` instead of swallowing the result in a void block.",
    ),
    rule_meta(
        RuleId::TanstackStartServerFnValidateInput,
        "tanstack-start-server-fn-validate-input",
        "dotore/tanstack-start-server-fn-validate-input",
        &[],
        "TanStack Start createServerFn missing input validator",
        RuleCategory::Security,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ServerAction, RuleTag::SecurityScan],
        CapabilityPredicate::require(&[Capability::TanstackStart]),
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Surgical,
        "https://tanstack.com/start/latest/docs/framework/react/server-functions",
        "Chain `.validator(schema)` or `.inputValidator(schema)` before `.handler(...)` when `handler` accepts client input.",
    ),
    rule_meta(
        RuleId::ThreeNoGeometryInFrameLoop,
        "three-no-geometry-in-frame-loop",
        "dotore/three-no-geometry-in-frame-loop",
        &[],
        "Three.js geometry allocated inside frame loop",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::Three, RuleTag::Webgl],
        CapabilityPredicate::require(&[Capability::Three]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://threejs.org/docs/#manual/en/introduction/How-to-dispose-of-objects",
        "Allocate Three.js geometries and materials once outside the animation loop and mutate transforms or uniforms in place.",
    ),
    rule_meta(
        RuleId::R3fNoNewInUseFrame,
        "r3f-no-new-in-use-frame",
        "dotore/r3f-no-new-in-use-frame",
        &[],
        "Object allocation with new inside R3F useFrame",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::R3f, RuleTag::Three, RuleTag::Webgl],
        CapabilityPredicate::require(&[Capability::R3f]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://r3f.docs.pmnd.rs/api/hooks#useframe",
        "Hoist reusable `Vector3`, `Quaternion`, `Color`, or `Matrix4` scratch instances outside `useFrame` and call `.set()` / `.copy()` per frame.",
    ),
    rule_meta(
        RuleId::ZustandNoWholeStoreDestructure,
        "zustand-no-whole-store-destructure",
        "dotore/zustand-no-whole-store-destructure",
        &[],
        "Zustand store subscribed without a slice selector",
        RuleCategory::Performance,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly, RuleTag::TestNoise],
        CapabilityPredicate::require(&[Capability::Zustand]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://zustand.docs.pmnd.rs/guides/prevent-rerenders-with-use-shallow",
        "Pass a slice selector (`useStore(s => s.field)`) so the component only re-renders when the selected slice changes.",
    ),
    rule_meta(
        RuleId::JotaiSelectAtomInRenderBody,
        "jotai-select-atom-in-render-body",
        "dotore/jotai-select-atom-in-render-body",
        &[],
        "Jotai selectAtom created inline during render",
        RuleCategory::Performance,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::require(&[Capability::Jotai]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://jotai.org/docs/utilities/select",
        "Hoist `selectAtom(...)` to module scope or wrap it in `useMemo` so a new derived atom is not created on every render.",
    ),
    rule_meta(
        RuleId::MobxReactionDisposerDiscarded,
        "mobx-reaction-disposer-discarded",
        "dotore/mobx-reaction-disposer-discarded",
        &[],
        "MobX reaction/autorun disposer discarded in useEffect",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::require(&[Capability::Mobx]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://mobx.js.org/reactions.html#always-dispose-of-reactions",
        "Return the disposer function returned by `autorun` / `reaction` from `useEffect` so the MobX subscription is cleaned up on unmount.",
    ),
    rule_meta(
        RuleId::ValtioNoSnapshotInCallback,
        "valtio-no-snapshot-in-callback",
        "dotore/valtio-no-snapshot-in-callback",
        &[],
        "Valtio snapshot read inside callback instead of proxy state",
        RuleCategory::Bugs,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::ReactJsxOnly],
        CapabilityPredicate::require(&[Capability::Valtio]),
        ContextualOwnerPolicy::Subject,
        PrescriptionTier::Surgical,
        "https://valtio.pmnd.rs/docs/api/basic/useSnapshot",
        "Read `useSnapshot(state)` during render for reactive UI, and read or mutate the underlying `state` proxy directly inside callbacks.",
    ),
    rule_meta(
        RuleId::PreactNoReactImport,
        "preact-no-react-import",
        "dotore/preact-no-react-import",
        &[],
        "Importing from 'react' in a pure Preact package",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::MigrationHint],
        CapabilityPredicate::require(&[Capability::PurePreact]),
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Autofix,
        "https://preactjs.com/guide/v10/differences-to-react",
        "Import hooks and primitives from `'preact'` / `'preact/hooks'` instead of `'react'` in pure Preact packages.",
    ),
    rule_meta(
        RuleId::InkNoRawText,
        "ink-no-raw-text",
        "dotore/ink-no-raw-text",
        &[],
        "Raw text outside <Text> in Ink terminal component",
        RuleCategory::Bugs,
        RuleSeverity::Error,
        true,
        false,
        &[RuleTag::Ink, RuleTag::ReactJsxOnly],
        CapabilityPredicate::require(&[Capability::Ink]),
        ContextualOwnerPolicy::JsxElement,
        PrescriptionTier::Surgical,
        "https://github.com/vadimdemedes/ink#text",
        "Wrap all text nodes in Ink's `<Text>` component so terminal output renders without throwing.",
    ),
    rule_meta(
        RuleId::ZodV4DeprecatedParse,
        "zod-v4-deprecated-parse",
        "dotore/zod-v4-deprecated-parse",
        &[],
        "Deprecated Zod object schema method (.strict() / .passthrough())",
        RuleCategory::Maintainability,
        RuleSeverity::Warning,
        true,
        false,
        &[RuleTag::TestNoise, RuleTag::MigrationHint],
        CapabilityPredicate::require(&[Capability::Zod]),
        ContextualOwnerPolicy::Line,
        PrescriptionTier::Surgical,
        "https://zod.dev/v4",
        "Migrate `z.object(...).strict()` and `z.object(...).passthrough()` to `z.strictObject(...)` and `z.looseObject(...)`.",
    ),
];

/// Returns the static catalog of all registered [`RuleMetadata`] entries.
#[must_use]
pub const fn rule_registry() -> &'static [RuleMetadata] {
    RULE_REGISTRY
}

impl RuleId {
    /// Returns the static [`RuleMetadata`] for this rule.
    #[must_use]
    pub fn metadata(self) -> &'static RuleMetadata {
        RULE_REGISTRY
            .iter()
            .find(|m| m.id == self)
            .unwrap_or(&RULE_REGISTRY[0])
    }

    /// Returns the kebab-case CLI / config rule identifier.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.metadata().canonical_id
    }

    /// Official documentation URL for this rule.
    #[must_use]
    pub fn docs_url(self) -> &'static str {
        self.metadata().docs_url
    }

    /// Parses a rule identifier from its canonical short ID (`"no-derived-state"`),
    /// qualified key (`"dotore/no-derived-state"`), or any legacy alias (`"effect/no-derived-state"`, `"react/jsx-key"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }
        let without_prefix = trimmed.strip_prefix("dotore/").unwrap_or(trimmed);
        for meta in RULE_REGISTRY {
            if meta.canonical_id == without_prefix
                || meta.qualified_key == trimmed
                || meta.legacy_aliases.contains(&trimmed)
            {
                return Some(meta.id);
            }
        }
        None
    }

    /// Returns `true` if `candidate` resolves to `self` via canonical ID, qualified key, or legacy alias.
    #[must_use]
    pub fn matches_key(self, candidate: &str) -> bool {
        Self::parse(candidate) == Some(self)
    }
}

/// A single byte-range replacement in a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByteEdit {
    /// Byte span in the original file to replace.
    pub span: ByteSpan,
    /// Replacement source text.
    pub replacement: String,
}

/// Deterministic patch for an `Autofix`-tier diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutofixPatch {
    /// Summary of the transformation.
    pub description: String,
    /// Non-overlapping byte edits to apply to the file.
    pub edits: Vec<ByteEdit>,
}

/// A single diagnostic emitted by `dotore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// File path where the diagnostic occurred.
    pub file: PathBuf,
    /// Enclosing **Subject** name (`"Form"`, `"useOnlineStatus"`, or `None` if anonymous/module-level).
    pub subject_name: Option<String>,
    /// Rule identifier.
    pub rule: RuleId,
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    pub category: RuleCategory,
    /// Effective severity (`Error` or `Warning`).
    pub severity: RuleSeverity,
    /// Message identifier (for compatibility with rule tests).
    pub message_id: &'static str,
    /// Prescription tier (`Autofix`, `Surgical`, `Refactor`).
    pub tier: PrescriptionTier,
    /// Primary target name (state name, prop name, component name, or data source).
    pub target_name: String,
    /// Human-readable diagnostic message.
    pub message: String,
    /// Official documentation link.
    pub docs_url: &'static str,
    /// 1-based line and column.
    pub loc: SourceLoc,
    /// Byte span of the flagged AST node.
    pub span: ByteSpan,
    /// Steps of the **Render Cascade** eliminated by fixing this diagnostic.
    pub cascade_steps: Vec<String>,
    /// Cross-file JSX **Caller Sites** relevant to this diagnostic (e.g. missing `key`).
    pub caller_sites: Vec<ResolvedCallerSite>,
    /// Optional deterministic auto-fix patch.
    pub autofix: Option<AutofixPatch>,
}
