//! Effect Node teardown and React component, hook, and JSX correctness rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; rule dispatcher and shared helpers forward site metadata"
)]

mod dom_and_timer_teardown;
mod hook_and_state_correctness;
mod jsx_and_lint_parity;
mod jsx_element_parity;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{CallExpression, Expression, UnaryOperator},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite, SubjectIr,
        react_ast::{find_enclosing_react_node, is_inside_use_effect},
    },
    matchers::{is_react_hook_callee, push_semantic_site, push_semantic_site_with_fix},
    rules::types::{AutofixPatch, RuleId},
};

pub(super) const EFFECT_HOOKS: &[&str] = &["useEffect", "useLayoutEffect", "useInsertionEffect"];

pub(super) const DEPS_HOOKS: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useInsertionEffect",
    "useMemo",
    "useCallback",
    "useImperativeHandle",
];

pub(super) const OBSERVER_CLASSES: &[&str] = &[
    "ResizeObserver",
    "IntersectionObserver",
    "MutationObserver",
    "PerformanceObserver",
];

pub(super) const VOID_DOM_TAGS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
    "source", "track", "wbr",
];

pub(super) const BOOLEAN_DOM_ATTRIBUTES: &[&str] = &[
    "allowFullScreen",
    "async",
    "autoFocus",
    "autoPlay",
    "checked",
    "controls",
    "defaultChecked",
    "defer",
    "disabled",
    "formNoValidate",
    "hidden",
    "inert",
    "ismap",
    "itemScope",
    "loop",
    "multiple",
    "muted",
    "noModule",
    "noValidate",
    "novalidate",
    "open",
    "playsInline",
    "readOnly",
    "readonly",
    "required",
    "reversed",
    "selected",
];

pub(super) const FORBIDDEN_ELEMENTS: &[&str] = &[
    "acronym",
    "applet",
    "basefont",
    "bgsound",
    "big",
    "blink",
    "center",
    "dir",
    "font",
    "frame",
    "frameset",
    "isindex",
    "keygen",
    "marquee",
    "multicol",
    "nextid",
    "nobr",
    "noembed",
    "noframes",
    "plaintext",
    "spacer",
    "strike",
    "tt",
    "xmp",
    "ForbiddenElement",
];

pub(super) const FORBIDDEN_DOM_PROPS: &[&str] = &[
    "alink",
    "background",
    "bgcolor",
    "border",
    "forbidProp",
    "forbiddenProp",
    "data-forbidden-prop",
    "frameborder",
    "marginheight",
    "marginwidth",
    "nowrap",
    "scrolling",
    "valign",
    "vlink",
];

pub(super) const INVALID_PARAGRAPH_CHILD_TAGS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "dd",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "search",
    "section",
    "table",
    "ul",
];

pub(super) const NATIVE_LABEL_CONTROLS: &[&str] = &[
    "button", "input", "meter", "output", "progress", "select", "textarea",
];

pub(super) const NONDETERMINISTIC_ID_CALLEES: &[&str] = &[
    "nanoid", "uuid", "uuidv4", "uuidV4", "v4", "uniqueId", "shortid", "cuid", "cuid2", "createId",
    "ulid",
];

pub(super) const BUILTIN_UPPERCASE_CALLS: &[&str] = &[
    "String",
    "Number",
    "Boolean",
    "BigInt",
    "Symbol",
    "Array",
    "Object",
    "Error",
    "TypeError",
    "RangeError",
    "SyntaxError",
    "Date",
    "RegExp",
    "Promise",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Int8Array",
    "Uint8Array",
    "Float32Array",
    "Float64Array",
];

pub(super) const ARRAY_MUTATING_METHODS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
    "set",
    "add",
    "delete",
    "clear",
];

/// Extracts all 68 Effect Node teardown and React correctness rule sites in a single pass.
pub(crate) fn extract_effect_teardown_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    jsx_and_lint_parity::check_file_level_rules(path, semantic, subjects, line_starts, sites);
    jsx_and_lint_parity::check_class_component_rules(semantic, line_starts, sites);

    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            hook_and_state_correctness::check_subject_effect_and_correctness_rules(
                semantic,
                subj_id,
                line_starts,
                sites,
            );
        }
    }

    jsx_and_lint_parity::check_ast_node_rules(semantic, subjects, line_starts, sites);
}

pub(super) fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl AsRef<str>,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    if autofix.is_some() {
        push_site_with_fix(
            sites,
            rule,
            subject_name,
            message_id,
            target_name.as_ref(),
            message,
            span,
            line_starts,
            autofix,
        );
    } else {
        push_semantic_site(
            sites,
            rule,
            subject_name,
            message_id,
            target_name.as_ref(),
            message,
            line_starts,
            span,
        );
    }
}

pub(super) fn push_site_with_fix(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl AsRef<str>,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    push_semantic_site_with_fix(
        sites,
        rule,
        subject_name,
        message_id,
        target_name.as_ref(),
        message,
        line_starts,
        span,
        autofix,
    );
}

pub(super) fn is_at_module_scope(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::MethodDefinition(_)
            | AstKind::PropertyDefinition(_)
            | AstKind::StaticBlock(_)
            | AstKind::TSTypeAnnotation(_)
            | AstKind::TSTypeReference(_)
            | AstKind::TSTypeQuery(_)
            | AstKind::TSInterfaceDeclaration(_)
            | AstKind::TSTypeAliasDeclaration(_) => return false,
            _ => {}
        }
    }
    true
}

pub(super) fn is_mutation_of_named_binding(kind: AstKind<'_>, var_name: &str) -> bool {
    match kind {
        AstKind::AssignmentExpression(assign) => {
            let Some(mem) = assign.left.as_member_expression() else {
                return false;
            };
            expr_roots_at_identifier(mem.object(), var_name)
        }
        AstKind::UpdateExpression(upd) => {
            let Some(mem) = upd.argument.as_member_expression() else {
                return false;
            };
            expr_roots_at_identifier(mem.object(), var_name)
        }
        AstKind::UnaryExpression(un) if un.operator == UnaryOperator::Delete => {
            match un.argument.without_parentheses() {
                Expression::StaticMemberExpression(m) => {
                    expr_roots_at_identifier(&m.object, var_name)
                }
                Expression::ComputedMemberExpression(m) => {
                    expr_roots_at_identifier(&m.object, var_name)
                }
                _ => false,
            }
        }
        AstKind::CallExpression(call) => {
            let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
                return false;
            };
            ARRAY_MUTATING_METHODS.contains(&mem.property.name.as_str())
                && expr_roots_at_identifier(&mem.object, var_name)
        }
        _ => false,
    }
}

fn expr_roots_at_identifier(expr: &Expression<'_>, var_name: &str) -> bool {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return id.name.as_str() == var_name,
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            _ => return false,
        }
    }
}

pub(super) fn check_render_phase_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_inside_state_memo_or_ref_initializer(semantic, node_id) {
        return;
    }

    let callee = call.callee.without_parentheses();
    let callee_text = callee.span().source_text(semantic.source_text());

    if matches!(
        callee_text,
        "URL.createObjectURL" | "webkitURL.createObjectURL" | "window.URL.createObjectURL"
    ) {
        push_site(
            sites,
            RuleId::NoCreateObjectUrlInRender,
            subj_name.clone(),
            "noCreateObjectUrlInRender",
            callee_text,
            "Creating an object URL during render leaks blob memory on every re-render; move `URL.createObjectURL` into `useEffect` or an event handler.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    if is_store_factory_callee(callee) {
        push_site(
            sites,
            RuleId::NoCreateStoreInRender,
            subj_name.clone(),
            "noCreateStoreInRender",
            callee_text,
            format!(
                "Calling `{callee_text}` during render recreates the store on every render; hoist it to module scope."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    if is_nondeterministic_id_callee(callee, callee_text) && !is_inside_jsx_key_attr(semantic, node_id) {
        push_site(
            sites,
            RuleId::NoNondeterministicIdValueInRenderBody,
            subj_name.clone(),
            "noNondeterministicIdValueInRenderBody",
            callee_text,
            format!(
                "`{callee_text}()` in the render body produces a new ID on every render; use `useId()` instead."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    if let Expression::StaticMemberExpression(mem) = callee
        && mem.property.name == "animate"
        && !call.arguments.is_empty()
        && !is_inside_use_effect(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::WaapiAnimationInRender,
            subj_name.clone(),
            "waapiAnimationInRender",
            "animate",
            "Starting a Web Animation (`.animate(...)`) during render causes impure side effects; move it to `useEffect` or an event handler.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
}

fn is_inside_state_memo_or_ref_initializer(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        if let AstKind::CallExpression(parent_call) = semantic.nodes().kind(anc_id) {
            is_react_hook_callee(semantic, &parent_call.callee, "useState")
                || is_react_hook_callee(semantic, &parent_call.callee, "useMemo")
                || is_react_hook_callee(semantic, &parent_call.callee, "useRef")
        } else {
            false
        }
    })
}

fn is_store_factory_callee(callee: &Expression<'_>) -> bool {
    match callee {
        Expression::Identifier(id) => matches!(id.name.as_str(), "createStore" | "configureStore"),
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.property.name.as_str(), "createStore" | "configureStore")
        }
        _ => false,
    }
}

fn is_nondeterministic_id_callee(callee: &Expression<'_>, callee_text: &str) -> bool {
    match callee {
        Expression::Identifier(id) => NONDETERMINISTIC_ID_CALLEES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            matches!(
                callee_text,
                "crypto.randomUUID" | "_.uniqueId" | "lodash.uniqueId"
            ) || mem.property.name == "randomUUID"
        }
        _ => false,
    }
}

fn is_inside_jsx_key_attr(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::JSXAttribute(attr) if attr.name.as_identifier().is_some_and(|i| i.name == "key")
        )
    })
}

pub(super) fn check_state_setter_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    setter_name: &str,
    state_name: &str,
    first_arg: &Expression<'_>,
    subj_id: NodeId,
    subj_name: &Option<String>,
    setter_to_state: &HashMap<String, String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::UnaryExpression(un) = first_arg
        && un.operator == UnaryOperator::LogicalNot
        && let Expression::Identifier(arg_id) = un.argument.without_parentheses()
        && arg_id.name.as_str() == state_name
    {
        push_site(
            sites,
            RuleId::NoBooleanToggleWithoutFunctionalUpdate,
            subj_name.clone(),
            "noBooleanToggleWithoutFunctionalUpdate",
            setter_name,
            format!(
                "Toggle `{state_name}` with `{setter_name}((prev) => !prev)` instead of `{setter_name}(!{state_name})`."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    if let Expression::Identifier(arg_id) = first_arg
        && arg_id.name.as_str() == state_name
        && is_mutated_before_setter_in_scope(semantic, node_id, subj_id, call.span.start, state_name)
    {
        push_site(
            sites,
            RuleId::NoMutateThenSetOrReturnSameReference,
            subj_name.clone(),
            "noMutateThenSetOrReturnSameReference",
            state_name,
            format!(
                "`{state_name}` is mutated in place and then passed to `{setter_name}({state_name})`; React ignores updates with the same reference."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    check_state_updater_function_purity(
        semantic,
        first_arg,
        setter_name,
        subj_name,
        setter_to_state,
        line_starts,
        sites,
    );
}

fn is_mutated_before_setter_in_scope(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subj_id: NodeId,
    call_start: u32,
    state_name: &str,
) -> bool {
    let scope_span = semantic
        .nodes()
        .ancestor_ids(node_id)
        .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
            AstKind::FunctionBody(b) => Some(b.span),
            AstKind::BlockStatement(b) => Some(b.span),
            _ => None,
        })
        .unwrap_or_else(|| semantic.nodes().get_node(subj_id).span());

    semantic.nodes().iter_enumerated().any(|(_, n)| {
        scope_span.contains_inclusive(n.span())
            && n.span().start < call_start
            && is_mutation_of_named_binding(n.kind(), state_name)
    })
}

fn check_state_updater_function_purity(
    semantic: &Semantic<'_>,
    first_arg: &Expression<'_>,
    setter_name: &str,
    subj_name: &Option<String>,
    setter_to_state: &HashMap<String, String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let (u_span, updater_param) = match first_arg {
        Expression::ArrowFunctionExpression(arr) => (
            arr.span,
            arr.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        Expression::FunctionExpression(f) => (
            f.span,
            f.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        _ => return,
    };

    let mut is_impure = false;
    let mut mutates_param = false;
    for (_, inner) in semantic.nodes().iter_enumerated() {
        if !u_span.contains_inclusive(inner.span()) || inner.span() == u_span {
            continue;
        }
        if let Some(param) = &updater_param
            && is_mutation_of_named_binding(inner.kind(), param)
        {
            is_impure = true;
            mutates_param = true;
        }
        if is_impure_updater_node(semantic, inner.kind(), setter_to_state) {
            is_impure = true;
        }
    }
    if is_impure {
        push_site(
            sites,
            RuleId::NoImpureStateUpdater,
            subj_name.clone(),
            "noImpureStateUpdater",
            setter_name,
            format!(
                "State updater passed to `{setter_name}` performs side effects or in-place mutations; keep state updaters pure."
            ),
            u_span,
            line_starts,
            None,
        );
    }
    if mutates_param {
        push_site(
            sites,
            RuleId::NoMutateThenSetOrReturnSameReference,
            subj_name.clone(),
            "noMutateThenSetOrReturnSameReference",
            setter_name,
            format!(
                "State updater passed to `{setter_name}` mutates the previous state in place and returns the same reference."
            ),
            u_span,
            line_starts,
            None,
        );
    }
}

fn is_impure_updater_node(
    semantic: &Semantic<'_>,
    kind: AstKind<'_>,
    setter_to_state: &HashMap<String, String>,
) -> bool {
    match kind {
        AstKind::AssignmentExpression(_) | AstKind::UpdateExpression(_) => true,
        AstKind::CallExpression(c) => {
            let c_text = c
                .callee
                .without_parentheses()
                .span()
                .source_text(semantic.source_text());
            setter_to_state.contains_key(c_text)
                || c_text.starts_with("localStorage.")
                || c_text.starts_with("sessionStorage.")
                || c_text.starts_with("console.")
                || matches!(
                    c_text,
                    "fetch" | "setTimeout" | "setInterval" | "dispatch" | "alert"
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        ir::{extract::inspect_file_semantic, types::compute_line_starts},
        rules::RuleId,
    };

    use super::extract_effect_teardown_sites;

    fn run_effect_teardown(path_str: &str, source: &str) -> Vec<crate::ir::SemanticRuleSite> {
        let path = Path::new(path_str);
        inspect_file_semantic(path, source, |file_ir, semantic| {
            let line_starts = compute_line_starts(source);
            let mut sites = Vec::new();
            extract_effect_teardown_sites(
                path,
                semantic,
                &file_ir.subjects,
                &line_starts,
                &mut sites,
            );
            sites
        })
    }

    #[test]
    fn dom_and_timer_teardown_submodule_rules() {
        let source = r#"
import React, { useEffect, useMemo } from "react";

export function Widget() {
    const debounced = useMemo(() => debounce(() => {}, 100), []);
    useEffect(() => {
        const obs = new ResizeObserver(() => {});
        requestAnimationFrame(() => {});
        const onKey = () => {};
        window.addEventListener("keydown", onKey);
        return () => {
            window.removeEventListener("keyup", onKey);
        };
    }, []);
    return <div onClick={debounced} />;
}
"#;
        let sites = run_effect_teardown("Widget.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::DebounceNoCleanup));
        assert!(rules.contains(&RuleId::EffectObserverNeedsDisconnect));
        assert!(rules.contains(&RuleId::EffectRafLoopNeedsCancel));
        let mismatch = sites
            .iter()
            .find(|s| s.rule == RuleId::EffectListenerCleanupMismatch);
        assert!(mismatch.is_some());
        assert!(mismatch.is_some_and(|s| s.autofix.is_some()));
    }

    #[test]
    fn hook_and_state_correctness_submodule_rules() {
        let source = r#"
import React, { useEffect, useReducer, useState } from "react";

export function Counter({ refObj, blob }: { refObj: { current: number }; blob: Blob }) {
    const [open, setOpen] = useState(false);
    const [state, dispatch] = useReducer((prev, action) => {
        prev.count = action;
        return prev;
    }, { count: 0 });
    const url = URL.createObjectURL(blob);

    useEffect(() => {
        setOpen(!open);
    }, [NaN, refObj.current]);

    return <button onClick={() => dispatch(1)}>{url}{state.count}</button>;
}
"#;
        let sites = run_effect_teardown("Counter.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::HooksNoNanInDeps));
        assert!(rules.contains(&RuleId::NoMutableInDeps));
        assert!(rules.contains(&RuleId::NoMutatingReducerState));
        assert!(rules.contains(&RuleId::NoCreateObjectUrlInRender));
        assert!(rules.contains(&RuleId::NoBooleanToggleWithoutFunctionalUpdate));
    }

    #[test]
    fn jsx_and_lint_parity_submodule_rules() {
        let source = r#"
import React from "react";

const SEED = Math.random();

class LegacyBox extends React.PureComponent {
    componentDidMount() {
        window.addEventListener("resize", this.onResize);
    }
    shouldComponentUpdate() {
        return true;
    }
    render() {
        return (
            <div>
                <img src="/a.png">child</img>
                <button disabled="false">{SEED} unescaped ' quote</button>
            </div>
        );
    }
}
"#;
        let sites = run_effect_teardown("LegacyBox.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::NoImpureCallAtModuleScope));
        assert!(rules.contains(&RuleId::NoRedundantShouldComponentUpdate));
        assert!(rules.contains(&RuleId::ClassComponentMissingComponentWillUnmountTeardown));
        assert!(rules.contains(&RuleId::NoUnescapedEntities));

        let void_site = sites
            .iter()
            .find(|s| s.rule == RuleId::VoidDomElementsNoChildren);
        assert!(void_site.is_some_and(|s| s.autofix.is_some()));

        let bool_site = sites
            .iter()
            .find(|s| s.rule == RuleId::NoStringFalseOnBooleanAttribute);
        assert!(bool_site.is_some_and(|s| s.autofix.is_some()));
    }
}
