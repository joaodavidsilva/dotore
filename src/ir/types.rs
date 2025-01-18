//! Typed IR structures representing React **Subjects**, **State Slots**, **Effect Nodes**, and **Caller Sites**.

use std::path::PathBuf;

use serde::Serialize;

/// 1-based line and column in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceLoc {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (UTF-8 byte offset on line + 1).
    pub column: u32,
}

/// 0-based byte span `[start, end)` in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteSpan {
    /// Inclusive start byte offset.
    pub start: u32,
    /// Exclusive end byte offset.
    pub end: u32,
}

/// Whether a **Subject** is a functional component or a custom hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    /// React functional component (`function MyComp()` or `const MyComp = () => ...`).
    Component,
    /// React custom hook (`function useMyHook()` or `const useMyHook = () => ...`).
    CustomHook,
}

/// A reactive `(value, setter)` pair declared via `useState` inside a **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StateSlot {
    /// Index of this slot within `SubjectIr::state_slots`.
    pub index: usize,
    /// Name of the state value binding (`first` in `const [first, setFirst] = useState()`).
    pub state_name: Option<String>,
    /// Name of the setter binding (`setFirst` in `const [first, setFirst] = useState()`).
    pub setter_name: Option<String>,
    /// Display name (`state_name` if present, otherwise `setter_name`).
    pub display_name: String,
    /// Span of the entire `const [x, setX] = useState(...);` statement when it is a single declarator.
    pub decl_stmt_span: Option<ByteSpan>,
    /// Span of the `useState(...)` call expression (`const [x, setX] = <call_span>`).
    pub call_span: ByteSpan,
    /// Normalized source text of the initial value argument passed to `useState(init)`, or `None` for `useState()`.
    pub init_arg_text: Option<String>,
    /// Number of references to `setter` outside any `useEffect` in this **Subject**.
    pub setter_calls_outside_effects: usize,
    /// Number of references to `setter` across all `useEffect`s in this **Subject**.
    pub setter_calls_in_effects: usize,
    /// Whether `setter` is returned from the **Subject** or passed into JSX/other calls as an argument.
    pub setter_escaped: bool,
}

/// Dependency list classification for an **Effect Node**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DepsSpec {
    /// Second argument to `useEffect(fn)` was omitted.
    Omitted,
    /// Second argument is `[]` (or contains only state setters).
    MountOnly,
    /// Second argument is `[a, b, ...]` with at least one non-setter dependency.
    Tracked(Vec<DepRef>),
}

/// A dependency reference inside `useEffect(fn, [dep])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DepRef {
    /// Identifier name written in the dependency array.
    pub name: String,
    /// State slot indices (`SubjectIr::state_slots`) feeding this dependency upstream.
    pub upstream_state_indices: Vec<usize>,
    /// Prop names feeding this dependency upstream.
    pub upstream_prop_names: Vec<String>,
}

/// A synchronous state setter call inside an **Effect Node**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SetterCallSite {
    /// Index into `SubjectIr::state_slots`, if resolved.
    pub state_slot_index: Option<usize>,
    /// State display name (`fullName`).
    pub state_name: String,
    /// Byte span of the `setX(...)` call expression.
    pub call_span: ByteSpan,
    /// 1-based line and column of the `setX(...)` call expression.
    pub loc: SourceLoc,
    /// Source text of the first argument passed to `setX(arg)`, or `"undefined"` if omitted.
    pub arg_text: String,
    /// Whether the first argument is a callback updater (`setX(prev => ...)`).
    pub is_updater_fn: bool,
    /// Whether the argument's upstream references include any **State Slot** of this **Subject**.
    pub arg_reads_state: bool,
    /// State slot indices read by the argument.
    pub arg_state_indices: Vec<usize>,
    /// Whether the argument's upstream references include any prop of this **Subject**.
    pub arg_reads_prop: bool,
    /// Prop names read by the argument.
    pub arg_prop_names: Vec<String>,
    /// Whether the argument sets the state back to its exact `useState` initial value.
    pub resets_to_initial_value: bool,
    /// Whether the setter (or its upstream helper/alias) is also referenced in the effect's cleanup.
    pub shares_cleanup_symbol: bool,
}

/// A synchronous call to a prop callback (`onTextChanged(text)`) inside an **Effect Node**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PropCallSite {
    /// Name of the prop being called (`onTextChanged`).
    pub prop_name: String,
    /// Byte span of the call expression.
    pub call_span: ByteSpan,
    /// 1-based line and column of the call expression.
    pub loc: SourceLoc,
    /// State names in `SubjectIr` passed into the call arguments.
    pub arg_state_names: Vec<String>,
    /// External data source names (e.g. `"useSomeAPI"`) passed into the call arguments.
    pub arg_external_data_names: Vec<String>,
    /// Whether the callee chain touches a React ref (`ref.current`).
    pub is_ref_call: bool,
}

/// An `if (cond)` without `else` inside an **Effect Node** whose condition reads state or props.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct IfGuardSite {
    /// Identifier name in the `if` condition (`dataToSubmit`).
    pub identifier_name: String,
    /// Byte span of the identifier in the `if` test.
    pub span: ByteSpan,
    /// 1-based line and column of the identifier.
    pub loc: SourceLoc,
    /// True if the identifier derives upstream from a **State Slot**.
    pub reads_state: bool,
    /// True if the identifier derives upstream from a prop.
    pub reads_prop: bool,
}

/// A subscription in an **Effect Node** (`addEventListener` / `.subscribe`) paired with cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ExternalStoreSite {
    /// State display name updated by the subscription.
    pub state_name: String,
    /// Byte span of the setter or subscribe call.
    pub span: ByteSpan,
    /// 1-based line and column.
    pub loc: SourceLoc,
}

/// An asynchronous `fetch` / promise chain inside an **Effect Node** that updates state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FetchSite {
    /// State display name updated when the fetch resolves.
    pub state_name: String,
    /// Byte span of the `useEffect` or `fetch` call.
    pub span: ByteSpan,
    /// 1-based line and column.
    pub loc: SourceLoc,
    /// Whether the effect defines a cleanup function or `AbortController` cancellation guard.
    pub has_cancellation_guard: bool,
}

/// A `useEffect` registration inside a **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EffectNode {
    /// Index of this effect within `SubjectIr::effect_nodes`.
    pub index: usize,
    /// Byte span of the `useEffect(...)` call expression.
    pub call_span: ByteSpan,
    /// Byte span of the enclosing `ExpressionStatement` (`useEffect(...);`), if standalone.
    pub stmt_span: Option<ByteSpan>,
    /// 1-based line and column of `useEffect(...)`.
    pub loc: SourceLoc,
    /// Dependency array classification.
    pub deps: DepsSpec,
    /// Whether the effect returns a non-empty cleanup expression (`return () => ...` or `return fn`).
    pub has_cleanup: bool,
    /// Number of top-level statements in the effect body (1 for expression bodies).
    pub top_level_stmt_count: usize,
    /// Synchronous state setter calls inside the effect body.
    pub sync_setter_calls: Vec<SetterCallSite>,
    /// Synchronous prop callback calls inside the effect body.
    pub sync_prop_calls: Vec<PropCallSite>,
    /// `if (cond)` guards without `else` whose test reads state or props.
    pub if_guards: Vec<IfGuardSite>,
    /// External store subscription sites detected in this effect.
    pub external_store_sites: Vec<ExternalStoreSite>,
    /// Async fetch + `setState` sites detected in this effect.
    pub fetch_sites: Vec<FetchSite>,
}

/// A React functional component or custom hook analyzed as a self-contained hook scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SubjectIr {
    /// Name of the component or custom hook (`"Form"`, `"useOnlineStatus"`, or `"<anonymous>"`).
    pub name: Option<String>,
    /// Component vs. CustomHook.
    pub kind: SubjectKind,
    /// Whether wrapped in a non-pure HOC (`withRouter`, `observer`).
    pub is_hoc_wrapped: bool,
    /// Byte span of the **Subject** declaration.
    pub span: ByteSpan,
    /// 1-based line and column of the **Subject**.
    pub loc: SourceLoc,
    /// Reactive **State Slots** declared in this **Subject**.
    pub state_slots: Vec<StateSlot>,
    /// `useEffect` **Effect Nodes** registered in this **Subject**.
    pub effect_nodes: Vec<EffectNode>,
}

/// A JSX element in a parent file rendering a component (`<ProfilePage userId={id} />`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CallerSite {
    /// Name of the rendered JSX component (`"ProfilePage"`).
    pub component_name: String,
    /// Resolved or raw module specifier if the component was imported (`"./ProfilePage"`).
    pub import_source: Option<String>,
    /// Enclosing parent **Subject** name, if any.
    pub parent_subject_name: Option<String>,
    /// Byte span of the JSX opening element.
    pub span: ByteSpan,
    /// 1-based line and column of the JSX opening element.
    pub loc: SourceLoc,
    /// Whether a `key={...}` attribute is present on the JSX element.
    pub has_key: bool,
    /// Names of JSX attributes passed to the component.
    pub passed_props: Vec<String>,
}

/// Parsed IR for a single source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileIr {
    /// Path to the source file.
    pub path: PathBuf,
    /// React **Subjects** (components and custom hooks) in this file.
    pub subjects: Vec<SubjectIr>,
    /// Outgoing JSX **Caller Sites** in this file.
    pub caller_sites: Vec<CallerSite>,
}

/// Computes 0-based line start byte offsets for `source`.
#[must_use]
pub(crate) fn compute_line_starts(source: &str) -> Vec<u32> {
    let mut starts = vec![0];
    for (idx, byte) in source.bytes().enumerate() {
        if byte == b'\n'
            && let Ok(next_pos) = u32::try_from(idx + 1)
        {
            starts.push(next_pos);
        }
    }
    starts
}

/// Converts a 0-based byte offset into a 1-based [`SourceLoc`].
#[must_use]
pub(crate) fn loc_from_line_starts(line_starts: &[u32], byte_offset: u32) -> SourceLoc {
    let line_idx = match line_starts.binary_search(&byte_offset) {
        Ok(exact) => exact,
        Err(insert) => insert.saturating_sub(1),
    };
    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
    let line = u32::try_from(line_idx + 1).unwrap_or(1);
    let column = byte_offset.saturating_sub(line_start) + 1;
    SourceLoc { line, column }
}
