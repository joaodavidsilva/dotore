//! Typed IR structures representing React **Subjects**, **State Slots**, **Effect Nodes**,
//! **Caller Sites**, JSX elements, module imports/exports, **Symbol Outlines**, mutations,
//! async flows, security sinks, and inline suppressions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use dotore_core::diff::ContextualSpanProvider;
pub use dotore_core::ir::{
    ArchitectureFileFacets, BlockDisableRange, ByteSpan, ConcernBucket, ConcernSignalSite,
    ContextualOwnerSpansIr, ExtractedFile, FileContext, FileSuppressions, HelperFingerprintIr,
    InlineTerminalUiPrimitiveSiteIr, LanguageAnalyzer, LanguageId, LineDisableDirective,
    OpenerLineRange, PackageAnalysisResult, RelatedHookOwnerSpanIr, SourceLoc, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, SubjectEffectOwner, SymbolKind, SymbolOutline,
    classify_file_context, compute_line_starts, loc_from_line_starts,
};

use crate::rules::{AutofixPatch, RuleId};
/// Whether a **Subject** is a functional component or a custom hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    /// React functional component (`function MyComp()` or `const MyComp = () => ...`).
    Component,
    /// React custom hook (`function useMyHook()` or `const useMyHook = () => ...`).
    CustomHook,
}

/// A reactive `(value, setter)` pair declared via `useState` inside a **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateSlot {
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
pub enum DepsSpec {
    /// Second argument to `useEffect(fn)` was omitted.
    Omitted,
    /// Second argument is `[]` (or contains only state setters).
    MountOnly,
    /// Second argument is `[a, b, ...]` with at least one non-setter dependency.
    Tracked(Vec<DepRef>),
}

/// A dependency reference inside `useEffect(fn, [dep])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DepRef {
    /// Identifier name written in the dependency array.
    pub name: String,
    /// State slot indices (`SubjectIr::state_slots`) feeding this dependency upstream.
    pub upstream_state_indices: Vec<usize>,
    /// Prop names feeding this dependency upstream.
    pub upstream_prop_names: Vec<String>,
}

/// A synchronous state setter call inside an **Effect Node**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetterCallSite {
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
pub struct PropCallSite {
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
pub struct IfGuardSite {
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
pub struct ExternalStoreSite {
    /// State display name updated by the subscription.
    pub state_name: String,
    /// Byte span of the setter or subscribe call.
    pub span: ByteSpan,
    /// 1-based line and column.
    pub loc: SourceLoc,
}

/// An asynchronous `fetch` / promise chain inside an **Effect Node** that updates state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FetchSite {
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
pub struct EffectNode {
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
pub struct SubjectIr {
    /// Name of the component or custom hook (`"Form"`, `"useOnlineStatus"`, or `None` if anonymous).
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
    /// Whether wrapped in `memo(...)` / `React.memo(...)` without a custom comparator.
    pub is_memoized: bool,
    /// Whether wrapped in `memo(Comp, customAreEqual)` with a custom comparator.
    pub has_custom_memo_comparator: bool,
    /// Names of component props referenced inside hook dependency arrays (`useEffect`, `useMemo`, `useCallback`).
    pub props_in_hook_deps: Vec<String>,
    /// Whether this **Subject** invokes suspending APIs (`use(promise)`, `useSuspenseQuery`, `useSearchParams`, unwrapped `lazy`) without a local `<Suspense>`.
    pub suspends: bool,
    /// Whether this **Subject** throws synchronously in its render path without a local `<ErrorBoundary>`.
    pub throws_in_render: bool,
}

/// A JSX element in a parent file rendering a component (`<ProfilePage userId={id} />`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallerSite {
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

/// Extracted IR for a JSX element (component or DOM tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsxElementIr {
    /// Element tag or component name (`"div"`, `"Button"`, `"Animated.Text"`).
    pub name: String,
    /// Root identifier of the JSX element (`"Animated"` for `<Animated.Text>`).
    pub root_identifier: String,
    /// Whether this JSX element is a component (`PascalCase` or member expression) rather than a DOM tag.
    pub is_component: bool,
    /// Enclosing **Subject** name, if any.
    pub enclosing_subject: Option<String>,
    /// Chain of ancestor JSX element names from outermost to immediate parent.
    pub ancestor_elements: Vec<String>,
    /// Attribute names present on the opening element.
    pub attributes: Vec<String>,
    /// Whether a `key` attribute is present.
    pub has_key: bool,
    /// Whether the `key` attribute value references the index parameter of an enclosing `.map((item, idx) => ...)`.
    pub key_is_array_index: bool,
    /// Names of props whose values are inline object literals (`style={{ color: 'red' }}`).
    pub object_literal_props: Vec<String>,
    /// Names of props whose values allocate a fresh array literal or array-producing call.
    pub array_literal_props: Vec<String>,
    /// Names of props whose values allocate an inline function or `.bind()` call.
    pub function_props: Vec<String>,
    /// Names of props whose values are inline JSX elements or fragments.
    pub inline_jsx_props: Vec<String>,
    /// Whether this JSX element is the root element returned inside an array `.map(...)` callback.
    pub in_array_map: bool,
    /// Whether the element has non-whitespace direct `JSXText` children.
    pub has_raw_text_child: bool,
    /// Trimmed text preview of direct `JSXText` children, if any.
    pub raw_text_preview: Option<String>,
    /// Whether the element also contains nested JSX element children alongside any text children.
    pub has_element_children: bool,
    /// Whether the element passes a function expression as JSX children (`<Comp>{() => <div />}</Comp>`).
    pub has_render_prop_children: bool,
    /// Whether the root component identifier is unresolved in `oxc_semantic` scope.
    pub is_unresolved_component: bool,
    /// Whether the root component identifier resolves to a static module import binding.
    pub is_imported_component: bool,
    /// Static `#target` fragment ID if this element has an `href="#target"` attribute (for `anchor-target-exists`).
    pub fragment_href_target: Option<String>,
    /// 1-based start line of the `<Tag` opening element.
    pub opener_start_line: u32,
    /// 1-based end line of the `<Tag ...>` opening element.
    pub opener_end_line: u32,
    /// Byte span of the JSX opening element.
    pub span: ByteSpan,
    /// 1-based location of the JSX opening element.
    pub loc: SourceLoc,
}

/// Structural JSX subtree hash and composition metadata for duplicate-JSX detection (`duplicate-jsx-subtree`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsxSubtreeIr {
    /// Deterministic structural hash (`jsx:<hex>`).
    pub fingerprint: String,
    /// Total JSX element/fragment nodes in this subtree.
    pub node_count: usize,
    /// Maximum JSX nesting depth of this subtree.
    pub depth: usize,
    /// Root JSX element or fragment name (`"Page"`, `"div"`, `"Fragment"`).
    pub root_name: String,
    /// Enclosing **Subject** or function name, if any.
    pub enclosing_subject: Option<String>,
    /// Start byte offset of the enclosing **Subject** or function declaration (`compositionRootStartOffset`).
    pub composition_root_offset: Option<u32>,
    /// Composition path from enclosing **Subject** through ancestor JSX elements to `root_name`.
    pub composition_path: Vec<String>,
    /// Full byte span `[start, end)` of the JSX element or fragment subtree.
    pub span: ByteSpan,
    /// 1-based start line and column.
    pub loc: SourceLoc,
    /// 1-based inclusive end line.
    pub end_line: u32,
}

/// A single imported binding inside an [`ImportDeclIr`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportBindingIr {
    /// Exported symbol name in the target module (`"default"`, `"*"`, or named export).
    pub imported_name: String,
    /// Local binding identifier name in the importing module.
    pub local_name: String,
    /// Whether this binding is a default import (`import Foo from '...'`).
    pub is_default: bool,
    /// Whether this binding is a namespace import (`import * as ns from '...'`).
    pub is_namespace: bool,
    /// Whether this binding is type-only (`import type ...` or `import { type T } ...`).
    pub is_type_only: bool,
    /// Whether this binding is referenced in a runtime value position (including JSX or value re-export).
    pub has_runtime_value_reference: bool,
}

/// A static `import` declaration in a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportDeclIr {
    /// Module specifier string (`"react"`, `"./Button"`).
    pub source: String,
    /// Local binding names imported by this declaration.
    pub specifiers: Vec<String>,
    /// Detailed imported bindings (`imported_name`, `local_name`, `is_default`, `is_namespace`, `is_type_only`).
    pub bindings: Vec<ImportBindingIr>,
    /// Whether this is a type-only import (`import type ...`).
    pub is_type_only: bool,
    /// Byte span of the import declaration.
    pub span: ByteSpan,
    /// 1-based location of the import declaration.
    pub loc: SourceLoc,
}

/// An `export` declaration in a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportDeclIr {
    /// Exported symbol name (`"default"`, `"Button"`, `"API_URL"`).
    pub name: String,
    /// Original or local symbol name (for `export { orig as alias } from '...'`, `export { local as alias }`, or `export default Foo`).
    pub local_name: Option<String>,
    /// Re-export source specifier if this is `export { ... } from '...'` or `export * from '...'`.
    pub from_source: Option<String>,
    /// Whether this export is a namespace wildcard re-export (`export * from '...'` or `export * as ns from '...'`).
    pub is_namespace_re_export: bool,
    /// Whether this export is type-only (`export type` / `export interface`).
    pub is_type_only: bool,
    /// Whether the exported symbol is a React component.
    pub is_component: bool,
    /// Byte span of the export declaration.
    pub span: ByteSpan,
    /// 1-based location of the export declaration.
    pub loc: SourceLoc,
}

/// Module-level import, export, and directive facts extracted in the single OXC pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModuleIr {
    /// Static `import` declarations.
    pub imports: Vec<ImportDeclIr>,
    /// Dynamic `import("...")` module specifiers.
    pub dynamic_imports: Vec<String>,
    /// CommonJS `require("...")` / `require.resolve("...")` / `import.meta.resolve("...")` specifiers.
    pub require_sources: Vec<String>,
    /// TypeScript `import("./mod").Type` type query specifiers and optional root type name.
    pub type_import_sources: Vec<(String, Option<String>)>,
    /// React Router route file references (`route(..., "file")`, `index("file")`, `layout("file")`).
    pub route_module_entries: Vec<String>,
    /// Static `export` declarations.
    pub exports: Vec<ExportDeclIr>,
    /// Identifier names referenced locally in this module (outside export specifiers).
    pub local_references: Vec<String>,
    /// Namespace member accesses `(namespace_local_name, member_name)` (e.g. `ns.foo`, `<ns.Foo />`, `const { foo } = ns`).
    pub namespace_member_accesses: Vec<(String, String)>,
    /// Namespace local names consumed as whole objects (`Object.keys(ns)`, `{ ...ns }`, `ns[dyn]`).
    pub whole_namespace_uses: Vec<String>,
    /// Whether the module has a `"use client"` directive.
    pub has_use_client: bool,
    /// Whether the module has a `"use server"` directive.
    pub has_use_server: bool,
    /// Whether the module body consists solely of imports and re-exports (an aggregation barrel).
    pub is_aggregation_barrel: bool,
    /// Local component declarations `(component_name, target_jsx_name)` that forward `children` into `<Target>`.
    pub component_children_targets: Vec<(String, String)>,
}

impl OpenerLineRange for JsxElementIr {
    fn opener_start_line(&self) -> u32 {
        self.opener_start_line
    }

    fn opener_end_line(&self) -> u32 {
        self.opener_end_line
    }
}

impl SubjectEffectOwner for SubjectIr {
    fn subject_span(&self) -> ByteSpan {
        self.span
    }

    fn subject_line(&self) -> u32 {
        self.loc.line
    }

    fn for_each_effect_span(&self, f: &mut dyn FnMut(ByteSpan, u32)) {
        for eff in &self.effect_nodes {
            f(eff.call_span, eff.loc.line);
        }
    }
}

/// A direct property or array mutation site (`state.foo = 1`, `items.push(x)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MutationSiteIr {
    /// Mutated root identifier name.
    pub target_name: String,
    /// Whether the mutated identifier resolves to a `useState` **State Slot** value.
    pub is_state_slot: bool,
    /// Source slice of the mutation expression.
    pub expression_text: String,
    /// Enclosing **Subject** name, if any.
    pub subject_name: Option<String>,
    /// Byte span of the mutation expression.
    pub span: ByteSpan,
    /// 1-based source location.
    pub loc: SourceLoc,
}

/// An `await` expression and its control-flow context extracted during the single OXC pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsyncFlowIr {
    /// Source slice of the awaited expression.
    pub awaited_expr: String,
    /// Whether this `await` is nested inside a loop (`for`, `for..of`, `for..in`, `while`, `do..while`).
    pub inside_loop: bool,
    /// Enclosing **Subject** or function name, if any.
    pub enclosing_name: Option<String>,
    /// Byte span of the `AwaitExpression`.
    pub span: ByteSpan,
    /// 1-based source location.
    pub loc: SourceLoc,
}

/// Kind of security or trust-boundary sink extracted during the single OXC pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySinkKind {
    /// JSX `dangerouslySetInnerHTML` attribute.
    DangerouslySetInnerHtml,
    /// DOM `.innerHTML` / `.outerHTML` assignment.
    InnerHtmlAssignment,
    /// `eval(...)` call.
    DynamicCodeEval,
    /// Dynamic `process.env[key]` access.
    DynamicProcessEnv,
    /// Exported `"use server"` function without an auth guard call.
    UnauthenticatedServerAction,
}

/// A security or trust-boundary sink extracted in `FileIr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecuritySinkIr {
    /// Kind of security sink.
    pub kind: SecuritySinkKind,
    /// Primary identifier or sink target name.
    pub target_name: String,
    /// Enclosing **Subject** or function name, if any.
    pub subject_name: Option<String>,
    /// Byte span of the sink AST node.
    pub span: ByteSpan,
    /// 1-based source location.
    pub loc: SourceLoc,
}

/// Ecosystem or semantic rule site detected directly on `oxc_semantic::Semantic` during the single-pass parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticRuleSite {
    /// Rule triggered at this site.
    pub rule: RuleId,
    /// Enclosing **Subject** name, if any.
    pub subject_name: Option<String>,
    /// Message identifier.
    pub message_id: &'static str,
    /// Target identifier name.
    pub target_name: String,
    /// Diagnostic message.
    pub message: String,
    /// 1-based line and column.
    pub loc: SourceLoc,
    /// Byte span of the flagged AST node.
    pub span: ByteSpan,
    /// Optional deterministic auto-fix patch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autofix: Option<AutofixPatch>,
}

/// Classification of a motion expression or export for `require-reduced-motion`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MotionExpressionEvidence {
    /// Whether the expression is an animation function (`animate`).
    pub is_animation_function: bool,
    /// Whether the expression is a motion component (`motion.div`, `m.div`, `Reorder.Item`).
    pub is_motion_component: bool,
    /// Whether the expression is a motion component factory (`motion`, `m`).
    pub is_motion_component_factory: bool,
    /// Whether the expression is a motion component namespace (`Reorder`).
    pub is_motion_component_namespace: bool,
    /// Whether the expression is `MotionConfig`.
    pub is_motion_config: bool,
    /// Whether the expression is a namespace import of a motion library (`import * as Framer`).
    pub is_motion_namespace: bool,
    /// Whether the expression is `useReducedMotion`.
    pub is_reduced_motion_hook: bool,
}

impl MotionExpressionEvidence {
    /// Merges two [`MotionExpressionEvidence`] records.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self {
            is_animation_function: self.is_animation_function || other.is_animation_function,
            is_motion_component: self.is_motion_component || other.is_motion_component,
            is_motion_component_factory: self.is_motion_component_factory
                || other.is_motion_component_factory,
            is_motion_component_namespace: self.is_motion_component_namespace
                || other.is_motion_component_namespace,
            is_motion_config: self.is_motion_config || other.is_motion_config,
            is_motion_namespace: self.is_motion_namespace || other.is_motion_namespace,
            is_reduced_motion_hook: self.is_reduced_motion_hook || other.is_reduced_motion_hook,
        }
    }

    /// Returns `true` if any motion capability flag is set.
    #[must_use]
    pub const fn has_any(self) -> bool {
        self.is_animation_function
            || self.is_motion_component
            || self.is_motion_component_factory
            || self.is_motion_component_namespace
            || self.is_motion_config
            || self.is_motion_namespace
            || self.is_reduced_motion_hook
    }
}

/// An unresolved cross-file motion usage or re-export waiting on `ProjectGraph` resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingMotionRef {
    /// Relative module specifier (`"./motion-barrel"`).
    pub module_source: String,
    /// Exported symbol name in the target module (`"AnimatedCard"`, `"default"`, `"*"`).
    pub imported_name: String,
    /// Member accesses applied to the imported symbol (`["div"]` for `<animated.div>`).
    pub member_chain: Vec<String>,
    /// How the resulting expression is used in this file.
    pub usage: PendingMotionUsage,
}

/// How an unresolved cross-file motion symbol is used in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PendingMotionUsage {
    /// Rendered as a JSX tag (`<AnimatedCard />` or `<animated.div />`).
    JsxTag {
        /// Static `reducedMotion` attribute value if present (`"user"`, `"always"`, `"never"`).
        reduced_motion_prop: Option<String>,
    },
    /// Called as a function (`runAnimation(...)` or `usePref()`).
    Call {
        /// Whether the call's return value is consumed (not an expression statement or `void`).
        value_consumed: bool,
        /// Whether the call was invoked via `.call(...)` or `.apply(...)`.
        via_call_or_apply: bool,
    },
    /// Re-exported from this module as `exported_as`.
    ReExport {
        /// Name under which this module exports the symbol.
        exported_as: String,
    },
}

/// Single-pass motion library and CSS reduced-motion facts extracted for `require-reduced-motion`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MotionFileIr {
    /// Direct motion animation use proven within this file.
    pub has_motion_use: bool,
    /// Direct reduced-motion handling (`useReducedMotion()`, `<MotionConfig reducedMotion="user"|"always">`, or CSS `@media (prefers-reduced-motion: reduce)`) proven within this file.
    pub has_reduced_motion_handling: bool,
    /// Direct motion evidence for symbols exported by this file (`export_name -> evidence`).
    pub exported_evidence: Vec<(String, MotionExpressionEvidence)>,
    /// Non-type `export * from "..."` module sources in this file.
    pub star_reexports: Vec<String>,
    /// Cross-file motion usages and re-exports that depend on local module resolution.
    pub pending_refs: Vec<PendingMotionRef>,
}

/// Kind of 60fps animation/frame loop registration (`useFrame`, `requestAnimationFrame`, or `setAnimationLoop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameLoopRootKind {
    /// React Three Fiber `useFrame(...)` callback.
    UseFrame,
    /// Browser `requestAnimationFrame(...)` or Three.js `renderer.setAnimationLoop(...)` callback.
    AnimationLoop,
}

/// Outgoing function call inside a 60fps frame loop callback or helper function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameCallTargetIr {
    /// Local callee identifier or member method name (`"stepPhysics"`).
    pub callee_name: String,
    /// Exported symbol name in the target module (`"stepPhysics"`, `"default"`) if imported.
    pub imported_name: Option<String>,
    /// Module specifier (`"./physics"`) if imported.
    pub import_source: Option<String>,
    /// 1-based location of the call site.
    pub call_loc: SourceLoc,
    /// Byte span of the call site.
    pub call_span: ByteSpan,
}

/// A 60fps `useFrame`, `requestAnimationFrame`, or `setAnimationLoop` callback registered in a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameLoopRootIr {
    /// Kind of frame loop (`UseFrame` or `AnimationLoop`).
    pub kind: FrameLoopRootKind,
    /// Enclosing React **Subject** or function name, if any.
    pub subject_name: Option<String>,
    /// 1-based location of the loop registration call.
    pub loc: SourceLoc,
    /// Byte span of the loop registration call.
    pub span: ByteSpan,
    /// Outgoing calls made unconditionally inside the frame loop callback.
    pub outgoing_calls: Vec<FrameCallTargetIr>,
}

/// Kind of per-frame allocation, state update, or synchronous GPU readback inside a helper function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameHelperHazardKind {
    /// `new <Constructor>(...)` object allocation (`"Vector3"`, `"BoxGeometry"`, etc.).
    NewAllocation(String),
    /// `.clone()` call allocating a new Three.js object.
    CloneAllocation(String),
    /// Fresh array literal (`[...]`) or array allocation.
    ArrayAllocation,
    /// Fresh object literal (`{ ... }`).
    ObjectAllocation,
    /// React `setState` setter invocation or store `.setState(...)` call.
    StateUpdate(String),
    /// Synchronous GPU readback (`readPixels`, `readRenderTargetPixels`, `getParameter`, `getError`, `finish`, `getBufferSubData`).
    SyncReadback(String),
}

/// A per-frame hazard recorded inside a declared helper function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameHelperHazard {
    /// Kind of per-frame hazard.
    pub kind: FrameHelperHazardKind,
    /// 1-based location of the hazard inside the helper function.
    pub loc: SourceLoc,
    /// Byte span of the hazard inside the helper function.
    pub span: ByteSpan,
}

/// A declared function or arrow function helper in a module analyzed for 60fps frame-loop call graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameHelperIr {
    /// Local binding name of the helper function (`"stepPhysics"`).
    pub name: String,
    /// Exported names under which this helper is exposed from the module (`["stepPhysics"]`, `["default"]`).
    pub exported_names: Vec<String>,
    /// 1-based location of the helper declaration.
    pub loc: SourceLoc,
    /// Byte span of the helper declaration.
    pub span: ByteSpan,
    /// Per-frame hazards executed inside this helper function.
    pub hazards: Vec<FrameHelperHazard>,
    /// Outgoing calls to other local or imported functions inside this helper.
    pub outgoing_calls: Vec<FrameCallTargetIr>,
}

/// Extracted `<Context.Provider value={...}>` or React 19 `<Context value={...}>` site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ContextProviderSiteIr {
    /// Base context identifier name (`"AppContext"` or `"ThemeContext"`).
    pub(crate) context_name: String,
    /// Full JSX tag name (`"AppContext.Provider"` or `"AppContext"`).
    pub(crate) provider_tag_name: String,
    /// Enclosing **Subject** name, if any.
    pub(crate) subject_name: Option<String>,
    /// Whether `value={...}` is an unmemoized inline literal or unmemoized render-local literal variable.
    pub(crate) is_unmemoized_value: bool,
    /// Property names in the provider `value` object backed by `useState` **State Slots** in the enclosing **Subject**.
    pub(crate) state_slot_fields: Vec<String>,
    /// Property names in the provider `value` object backed by static values, props, or setters.
    pub(crate) static_fields: Vec<String>,
    /// 1-based location of the provider JSX element.
    pub(crate) loc: SourceLoc,
    /// Byte span of the provider JSX element.
    pub(crate) span: ByteSpan,
}

/// Extracted `useContext(MyContext)` or `use(MyContext)` consumer site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ContextConsumerSiteIr {
    /// Consumed context identifier name (`"AppContext"`).
    pub(crate) context_name: String,
    /// Enclosing **Subject** name, if any.
    pub(crate) subject_name: Option<String>,
    /// Property names read from the context value (via object destructuring or member expressions).
    pub(crate) read_fields: Vec<String>,
    /// 1-based location of the `useContext` call.
    pub(crate) loc: SourceLoc,
    /// Byte span of the `useContext` call.
    pub(crate) span: ByteSpan,
}

/// Complete single-pass intermediate representation for a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileIr {
    /// Path to the source file.
    pub path: PathBuf,
    /// Verbatim source text of the file.
    pub source: String,
    /// Classification of the file (`Production`, `Test`, or `Story`).
    pub file_context: FileContext,
    /// React **Subjects** (components and custom hooks) in this file.
    pub subjects: Vec<SubjectIr>,
    /// Outgoing JSX **Caller Sites** in this file.
    pub caller_sites: Vec<CallerSite>,
    /// All JSX elements in this file.
    pub jsx_elements: Vec<JsxElementIr>,
    /// Structural JSX subtrees extracted for cross-file duplicate JSX detection.
    pub jsx_subtrees: Vec<JsxSubtreeIr>,
    /// Module-level imports, exports, and directives.
    pub module: ModuleIr,
    /// Extracted **Symbol Outlines** for fuzzy symbol search.
    pub symbol_outlines: Vec<SymbolOutline>,
    /// Direct state/object/array mutation sites.
    pub mutations: Vec<MutationSiteIr>,
    /// `await` expressions and loop-nesting facts.
    pub async_flows: Vec<AsyncFlowIr>,
    /// Security and trust-boundary sinks.
    pub security_sinks: Vec<SecuritySinkIr>,
    /// Inline suppression directives (`dotore-disable*`, `eslint-disable*`, `oxlint-disable*`).
    pub suppressions: FileSuppressions,
    /// Semantic rule sites captured directly from `oxc_semantic` during the single parse pass.
    pub semantic_sites: Vec<SemanticRuleSite>,
    /// Single-pass motion and reduced-motion evidence for `require-reduced-motion`.
    pub motion: MotionFileIr,
    /// Static DOM `id` values declared on JSX or HTML elements in this file (for `anchor-target-exists`).
    pub static_dom_ids: Vec<String>,
    /// Whether any JSX element in this file has an unresolved dynamic spread `{...props}` that could supply an `id`.
    pub has_unresolved_id_spread: bool,
    /// 60fps `useFrame` and `requestAnimationFrame` callback registrations and their outgoing calls.
    pub frame_loop_roots: Vec<FrameLoopRootIr>,
    /// Declared functions/helpers in this module with their per-frame hazards and outgoing calls.
    pub frame_helpers: Vec<FrameHelperIr>,
    /// `<Context.Provider value={...}>` sites extracted for cross-file context analysis.
    pub(crate) context_providers: Vec<ContextProviderSiteIr>,
    /// `useContext(MyContext)` consumer sites extracted for cross-file context fan-out and overload analysis.
    pub(crate) context_consumers: Vec<ContextConsumerSiteIr>,
    /// Single-pass AST owner spans for `--scope contextual` diff filtering.
    pub contextual_owner_spans: ContextualOwnerSpansIr,
    /// Language-agnostic multi-signal structural facets for architecture, SoC, and reuse rules.
    pub architecture_facets: ArchitectureFileFacets,
}

impl FileIr {
    /// Converts this [`FileIr`] into a language-agnostic [`ExtractedFile`] carrying `self` as its payload.
    #[must_use]
    pub fn into_extracted_file(self) -> ExtractedFile {
        let language_id = LanguageId::from_path(&self.path).unwrap_or(LanguageId::JavaScript);
        let subjects_count = self.subjects.len();
        let effects_count = self.subjects.iter().map(|s| s.effect_nodes.len()).sum();
        let subject_spans = self
            .subjects
            .iter()
            .map(|s| (s.name.clone(), s.span, s.loc))
            .collect();
        let mut contextual_owner_spans = self.contextual_owner_spans.clone();
        if contextual_owner_spans.element_spans.is_empty() && !self.jsx_subtrees.is_empty() {
            contextual_owner_spans.element_spans =
                self.jsx_subtrees.iter().map(|s| s.span).collect();
        }
        let path = self.path.clone();
        let source = self.source.clone();
        let file_context = self.file_context;
        let symbol_outlines = self.symbol_outlines.clone();
        let suppressions = self.suppressions.clone();
        let architecture_facets = self.architecture_facets.clone();
        ExtractedFile {
            path,
            source,
            language_id,
            file_context,
            symbol_outlines,
            contextual_owner_spans,
            suppressions,
            subjects_count,
            effects_count,
            subject_spans,
            architecture_facets,
            payload: Box::new(self),
        }
    }
}

impl ContextualSpanProvider for FileIr {
    fn file_path(&self) -> &Path {
        &self.path
    }

    fn file_source(&self) -> &str {
        &self.source
    }

    fn for_each_element_span(&self, f: &mut dyn FnMut(ByteSpan)) {
        for subtree in &self.jsx_subtrees {
            f(subtree.span);
        }
    }

    fn for_each_subject_span(&self, f: &mut dyn FnMut(ByteSpan)) {
        for subj in &self.subjects {
            f(subj.span);
        }
    }

    fn contextual_owner_spans(&self) -> &ContextualOwnerSpansIr {
        &self.contextual_owner_spans
    }
}
