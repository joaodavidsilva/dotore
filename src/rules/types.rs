//! Domain types for diagnostic rules, prescription tiers, and autofix patches.

use std::path::PathBuf;

use serde::Serialize;

use crate::{
    graph::ResolvedCallerSite,
    ir::{ByteSpan, SourceLoc},
};

/// Canonical identifier for each diagnostic rule in `dotore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
}

impl RuleId {
    /// Returns the kebab-case CLI / config rule identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoDerivedState => "no-derived-state",
            Self::NoChainStateUpdates => "no-chain-state-updates",
            Self::NoEventHandler => "no-event-handler",
            Self::NoAdjustStateOnPropChange => "no-adjust-state-on-prop-change",
            Self::NoResetAllStateOnPropChange => "no-reset-all-state-on-prop-change",
            Self::NoPassLiveStateToParent => "no-pass-live-state-to-parent",
            Self::NoPassDataToParent => "no-pass-data-to-parent",
            Self::NoExternalStoreSubscription => "no-external-store-subscription",
            Self::NoInitializeState => "no-initialize-state",
            Self::NoFetchInEffect => "no-fetch-in-effect",
        }
    }

    /// Parses a rule name from CLI filters.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "no-derived-state" => Some(Self::NoDerivedState),
            "no-chain-state-updates" => Some(Self::NoChainStateUpdates),
            "no-event-handler" => Some(Self::NoEventHandler),
            "no-adjust-state-on-prop-change" => Some(Self::NoAdjustStateOnPropChange),
            "no-reset-all-state-on-prop-change" => Some(Self::NoResetAllStateOnPropChange),
            "no-pass-live-state-to-parent" => Some(Self::NoPassLiveStateToParent),
            "no-pass-data-to-parent" => Some(Self::NoPassDataToParent),
            "no-external-store-subscription" => Some(Self::NoExternalStoreSubscription),
            "no-initialize-state" => Some(Self::NoInitializeState),
            "no-fetch-in-effect" => Some(Self::NoFetchInEffect),
            _ => None,
        }
    }

    /// Official React docs URL for this rule.
    #[must_use]
    pub const fn docs_url(self) -> &'static str {
        match self {
            Self::NoDerivedState => {
                "https://react.dev/learn/you-might-not-need-an-effect#updating-state-based-on-props-or-state"
            }
            Self::NoChainStateUpdates => {
                "https://react.dev/learn/you-might-not-need-an-effect#chains-of-computations"
            }
            Self::NoEventHandler => {
                "https://react.dev/learn/you-might-not-need-an-effect#sharing-logic-between-event-handlers"
            }
            Self::NoAdjustStateOnPropChange => {
                "https://react.dev/learn/you-might-not-need-an-effect#adjusting-some-state-when-a-prop-changes"
            }
            Self::NoResetAllStateOnPropChange => {
                "https://react.dev/learn/you-might-not-need-an-effect#resetting-all-state-when-a-prop-changes"
            }
            Self::NoPassLiveStateToParent => {
                "https://react.dev/learn/you-might-not-need-an-effect#notifying-parent-components-about-state-changes"
            }
            Self::NoPassDataToParent => {
                "https://react.dev/learn/you-might-not-need-an-effect#passing-data-to-the-parent"
            }
            Self::NoExternalStoreSubscription => {
                "https://react.dev/learn/you-might-not-need-an-effect#subscribing-to-an-external-store"
            }
            Self::NoInitializeState => {
                "https://tkdodo.eu/blog/avoiding-hydration-mismatches-with-use-sync-external-store"
            }
            Self::NoFetchInEffect => {
                "https://react.dev/learn/you-might-not-need-an-effect#fetching-data"
            }
        }
    }
}

/// Level of intervention required to resolve a diagnostic (see `GLOSSARY.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrescriptionTier {
    /// Deterministic single-**Subject** rewrite applied directly by `dotore fix`.
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

/// A single diagnostic emitted on an **Effect Node** inside a **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// File path where the diagnostic occurred.
    pub file: PathBuf,
    /// Enclosing **Subject** name (`"Form"`, `"useOnlineStatus"`, or `None` if anonymous).
    pub subject_name: Option<String>,
    /// Rule identifier.
    pub rule: RuleId,
    /// Message identifier (for compatibility with rule tests).
    pub message_id: &'static str,
    /// Prescription tier (`Autofix`, `Surgical`, `Refactor`).
    pub tier: PrescriptionTier,
    /// Primary target name (state name, prop name, or data source).
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
