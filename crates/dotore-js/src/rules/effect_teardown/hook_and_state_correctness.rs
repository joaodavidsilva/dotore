//! Hook dependency, `useReducer`, render-phase purity, and state-setter correctness rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; hook and state correctness detectors match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{AssignmentTarget, BinaryOperator, BindingPattern, CallExpression, Expression},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite,
        react_ast::{
            find_enclosing_react_node, get_subject_name, is_custom_hook,
            is_direct_render_phase_node, is_functional_component,
        },
    },
    matchers::{is_react_hook_callee, resolve_ident_symbol},
    rules::types::RuleId,
};

use super::{
    DEPS_HOOKS, EFFECT_HOOKS, check_render_phase_call, check_state_setter_call,
    dom_and_timer_teardown::{
        check_debounce_no_cleanup, check_effect_hook_call, is_memoized_debounce_call,
    },
    is_at_module_scope, is_mutation_of_named_binding, push_site,
};

#[derive(Default)]
struct SubjectCorrectnessBindings {
    state_to_setter: HashMap<String, String>,
    setter_to_state: HashMap<String, String>,
    effect_event_names: HashSet<String>,
    fresh_render_bindings: HashSet<String>,
    queried_dom_vars: HashSet<String>,
    debounce_vars: Vec<(String, Span)>,
    subj_param_names: HashSet<String>,
}

pub(super) fn check_subject_effect_and_correctness_rules(
    semantic: &Semantic<'_>,
    subj_id: NodeId,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subj_id).span();
    let subj_name = get_subject_name(semantic, subj_id);
    let is_comp = is_functional_component(semantic, subj_id);
    let is_hook = is_custom_hook(semantic, subj_id);
    let bindings = collect_subject_correctness_bindings(semantic, subj_id, subj_span);

    check_debounce_no_cleanup(
        semantic,
        subj_span,
        &subj_name,
        &bindings.debounce_vars,
        line_starts,
        sites,
    );

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span())
            || find_enclosing_react_node(semantic, node_id) != Some(subj_id)
        {
            continue;
        }
        visit_subject_correctness_node(
            semantic,
            node_id,
            node.kind(),
            subj_id,
            &subj_name,
            is_comp,
            is_hook,
            &bindings,
            line_starts,
            sites,
        );
    }
}

fn collect_subject_correctness_bindings(
    semantic: &Semantic<'_>,
    subj_id: NodeId,
    subj_span: Span,
) -> SubjectCorrectnessBindings {
    let mut bindings = SubjectCorrectnessBindings {
        subj_param_names: get_function_param_names(semantic, subj_id),
        ..SubjectCorrectnessBindings::default()
    };

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span())
            || find_enclosing_react_node(semantic, node_id) != Some(subj_id)
        {
            continue;
        }
        if let AstKind::VariableDeclarator(decl) = node.kind() {
            record_declarator_in_subject(semantic, node_id, decl, &mut bindings);
        }
    }
    bindings
}

fn record_declarator_in_subject(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    bindings: &mut SubjectCorrectnessBindings,
) {
    let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
        return;
    };
    if let Expression::CallExpression(call) = init {
        if is_react_hook_callee(semantic, &call.callee, "useState")
            && let BindingPattern::ArrayPattern(arr) = &decl.id
        {
            let s_opt = arr
                .elements
                .first()
                .and_then(Option::as_ref)
                .and_then(BindingPattern::get_binding_identifier)
                .map(|id| id.name.to_string());
            let set_opt = arr
                .elements
                .get(1)
                .and_then(Option::as_ref)
                .and_then(BindingPattern::get_binding_identifier)
                .map(|id| id.name.to_string());
            if let (Some(s), Some(setter)) = (s_opt, set_opt) {
                bindings.state_to_setter.insert(s.clone(), setter.clone());
                bindings.setter_to_state.insert(setter, s);
            }
        } else if let Some(id) = decl.id.get_binding_identifier() {
            if is_react_hook_callee(semantic, &call.callee, "useEffectEvent")
                || is_react_hook_callee(semantic, &call.callee, "experimental_useEffectEvent")
            {
                bindings.effect_event_names.insert(id.name.to_string());
            } else if is_memoized_debounce_call(semantic, call) {
                bindings
                    .debounce_vars
                    .push((id.name.to_string(), decl.span));
            } else if is_dom_query_call(call) {
                bindings.queried_dom_vars.insert(id.name.to_string());
            }
        }
    }
    if is_direct_render_phase_node(semantic, node_id)
        && is_fresh_render_expression(init)
        && let Some(id) = decl.id.get_binding_identifier()
    {
        bindings.fresh_render_bindings.insert(id.name.to_string());
    }
}

fn visit_subject_correctness_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
    subj_id: NodeId,
    subj_name: &Option<String>,
    is_comp: bool,
    is_hook: bool,
    bindings: &SubjectCorrectnessBindings,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match kind {
        AstKind::ThisExpression(this_expr)
            if is_comp && is_direct_subject_this(semantic, node_id, subj_id) =>
        {
            push_site(
                sites,
                RuleId::NoThisInSfc,
                subj_name.clone(),
                "noThisInSfc",
                "this",
                "Function components do not have a `this` instance; read from `props` directly."
                    .to_string(),
                this_expr.span,
                line_starts,
                None,
            );
        }
        AstKind::CallExpression(call) => {
            check_subject_call_rules(
                semantic,
                node_id,
                call,
                subj_id,
                subj_name,
                is_comp,
                is_hook,
                bindings,
                line_starts,
                sites,
            );
        }
        AstKind::AssignmentExpression(assign)
            if !bindings.queried_dom_vars.is_empty()
                && is_mutation_of_queried_dom_target(&assign.left, &bindings.queried_dom_vars) =>
        {
            push_site(
                sites,
                RuleId::NoMutateQueriedDomNodeInComponent,
                subj_name.clone(),
                "noMutateQueriedDomNodeInComponent",
                assign.left.span().source_text(semantic.source_text()),
                "Avoid querying and mutating DOM nodes inside a React component; drive DOM updates via state or refs.".to_string(),
                assign.span,
                line_starts,
                None,
            );
        }
        AstKind::BinaryExpression(bin)
            if is_comp
                && matches!(
                    bin.operator,
                    BinaryOperator::StrictEquality
                        | BinaryOperator::Equality
                        | BinaryOperator::StrictInequality
                        | BinaryOperator::Inequality
                ) =>
        {
            let text = bin.span.source_text(semantic.source_text());
            if text.contains("typeof children") || text.contains("typeof props.children") {
                push_site(
                    sites,
                    RuleId::NoPolymorphicChildren,
                    subj_name.clone(),
                    "noPolymorphicChildren",
                    "children",
                    "Avoid branching on `typeof children` at runtime.".to_string(),
                    bin.span,
                    line_starts,
                    None,
                );
            }
        }
        _ => {}
    }
}

fn is_dom_query_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(
        mem.object.without_parentheses(),
        Expression::Identifier(id) if id.name == "document"
    ) && matches!(
        mem.property.name.as_str(),
        "getElementById"
            | "querySelector"
            | "querySelectorAll"
            | "getElementsByClassName"
            | "getElementsByTagName"
    )
}

fn is_mutation_of_queried_dom_target(
    target: &AssignmentTarget<'_>,
    queried_dom_vars: &HashSet<String>,
) -> bool {
    let Some(mem) = target.as_member_expression() else {
        return false;
    };
    let mut curr = mem.object().without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return queried_dom_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::CallExpression(c) => return is_dom_query_call(c),
            _ => return false,
        }
    }
}

fn is_fresh_render_expression(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::NewExpression(_) => true,
        Expression::CallExpression(call) => match call.callee.without_parentheses() {
            Expression::StaticMemberExpression(mem) => matches!(
                mem.property.name.as_str(),
                "filter" | "map" | "slice" | "concat" | "flat" | "flatMap" | "from"
            ),
            _ => false,
        },
        _ => false,
    }
}

fn get_function_param_names(semantic: &Semantic<'_>, fn_node_id: NodeId) -> HashSet<String> {
    let mut names = HashSet::new();
    match semantic.nodes().kind(fn_node_id) {
        AstKind::Function(f) => {
            for param in &f.params.items {
                if let Some(id) = param.pattern.get_binding_identifier() {
                    names.insert(id.name.to_string());
                }
            }
        }
        AstKind::ArrowFunctionExpression(arr) => {
            for param in &arr.params.items {
                if let Some(id) = param.pattern.get_binding_identifier() {
                    names.insert(id.name.to_string());
                }
            }
        }
        _ => {}
    }
    names
}

fn is_direct_subject_this(semantic: &Semantic<'_>, node_id: NodeId, subj_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subj_id {
            return true;
        }
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::MethodDefinition(_) | AstKind::Class(_)
        ) {
            return false;
        }
    }
    false
}

fn check_subject_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_id: NodeId,
    subj_name: &Option<String>,
    is_comp: bool,
    is_hook: bool,
    bindings: &SubjectCorrectnessBindings,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee = call.callee.without_parentheses();
    let _ = &bindings.state_to_setter;

    if EFFECT_HOOKS
        .iter()
        .any(|h| is_react_hook_callee(semantic, callee, h))
    {
        check_effect_hook_call(
            semantic,
            node_id,
            call,
            subj_name,
            is_hook,
            &bindings.subj_param_names,
            &bindings.setter_to_state,
            &bindings.effect_event_names,
            &bindings.fresh_render_bindings,
            line_starts,
            sites,
        );
    }

    if let Some(hook_name) = DEPS_HOOKS
        .iter()
        .copied()
        .find(|h| is_react_hook_callee(semantic, callee, h))
    {
        check_hook_deps_array(semantic, call, hook_name, subj_name, bindings, line_starts, sites);
    }

    if is_react_hook_callee(semantic, callee, "useReducer")
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        check_reducer_arg_for_mutation(semantic, first_arg, subj_name, line_starts, sites);
    }

    check_context_ref_and_render_phase_calls(
        semantic,
        node_id,
        call,
        callee,
        subj_name,
        is_comp,
        is_hook,
        line_starts,
        sites,
    );

    if let Expression::Identifier(callee_id) = callee
        && let Some(state_name) = bindings.setter_to_state.get(callee_id.name.as_str())
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        check_state_setter_call(
            semantic,
            node_id,
            call,
            callee_id.name.as_str(),
            state_name,
            first_arg.without_parentheses(),
            subj_id,
            subj_name,
            &bindings.setter_to_state,
            line_starts,
            sites,
        );
    }

    check_queried_dom_method_mutation(
        callee,
        call.span,
        &bindings.queried_dom_vars,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_hook_deps_array(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    hook_name: &str,
    subj_name: &Option<String>,
    bindings: &SubjectCorrectnessBindings,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let deps_idx = if hook_name == "useImperativeHandle" {
        2
    } else {
        1
    };
    let Some(deps_expr) = call.arguments.get(deps_idx).and_then(|a| a.as_expression()) else {
        return;
    };
    let Expression::ArrayExpression(arr) = deps_expr.without_parentheses() else {
        return;
    };
    for elem in &arr.elements {
        if let Some(dep_expr) = elem.as_expression() {
            check_single_dep_expression(
                semantic,
                dep_expr.without_parentheses(),
                hook_name,
                subj_name,
                &bindings.effect_event_names,
                &bindings.fresh_render_bindings,
                line_starts,
                sites,
            );
        }
    }
}

fn check_context_ref_and_render_phase_calls(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    subj_name: &Option<String>,
    is_comp: bool,
    is_hook: bool,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_at_module_scope(semantic, node_id) {
        return;
    }
    if is_react_hook_callee(semantic, callee, "createContext") {
        push_site(
            sites,
            RuleId::NoCreateContextInRender,
            subj_name.clone(),
            "noCreateContextInRender",
            "createContext",
            "Move `createContext(...)` to module scope so context identity does not reset on every render.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
    if (is_comp || is_hook) && is_react_hook_callee(semantic, callee, "createRef") {
        push_site(
            sites,
            RuleId::NoCreateRefInFunctionComponent,
            subj_name.clone(),
            "noCreateRefInFunctionComponent",
            "createRef",
            "Replace `createRef()` with `useRef()` inside function components and hooks."
                .to_string(),
            call.span,
            line_starts,
            None,
        );
    }
    if is_direct_render_phase_node(semantic, node_id) {
        check_render_phase_call(semantic, node_id, call, subj_name, line_starts, sites);
    }
}

fn check_queried_dom_method_mutation(
    callee: &Expression<'_>,
    call_span: Span,
    queried_dom_vars: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if queried_dom_vars.is_empty() {
        return;
    }
    let Expression::StaticMemberExpression(mem) = callee else {
        return;
    };
    let prop = mem.property.name.as_str();
    if matches!(
        prop,
        "setAttribute"
            | "removeAttribute"
            | "toggleAttribute"
            | "appendChild"
            | "removeChild"
            | "replaceChild"
            | "remove"
            | "add"
            | "toggle"
    ) && expr_roots_at_queried_dom(mem.object.without_parentheses(), queried_dom_vars)
    {
        push_site(
            sites,
            RuleId::NoMutateQueriedDomNodeInComponent,
            subj_name.clone(),
            "noMutateQueriedDomNodeInComponent",
            prop,
            "Avoid querying and mutating DOM nodes inside a React component; drive DOM updates via state or refs.".to_string(),
            call_span,
            line_starts,
            None,
        );
    }
}

fn expr_roots_at_queried_dom(expr: &Expression<'_>, queried_dom_vars: &HashSet<String>) -> bool {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return queried_dom_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::CallExpression(c) => return is_dom_query_call(c),
            _ => return false,
        }
    }
}

fn check_single_dep_expression(
    semantic: &Semantic<'_>,
    dep_expr: &Expression<'_>,
    hook_name: &str,
    subj_name: &Option<String>,
    effect_event_names: &HashSet<String>,
    fresh_render_bindings: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_effect_hook = EFFECT_HOOKS.contains(&hook_name);

    match dep_expr {
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            if name == "NaN" {
                push_site(
                    sites,
                    RuleId::HooksNoNanInDeps,
                    subj_name.clone(),
                    "hooksNoNanInDeps",
                    "NaN",
                    "`NaN` should not be listed in hook dependency arrays.".to_string(),
                    id.span,
                    line_starts,
                    None,
                );
            }
            if effect_event_names.contains(name) {
                push_site(
                    sites,
                    RuleId::NoEffectEventInDeps,
                    subj_name.clone(),
                    "noEffectEventInDeps",
                    name,
                    format!(
                        "Effect Event `{name}` must not be listed in `{hook_name}` dependencies."
                    ),
                    id.span,
                    line_starts,
                    None,
                );
            }
            if is_effect_hook && fresh_render_bindings.contains(name) {
                push_site(
                    sites,
                    RuleId::NoEffectWithFreshDeps,
                    subj_name.clone(),
                    "noEffectWithFreshDeps",
                    name,
                    format!(
                        "`{name}` is recreated on every render and listed in `{hook_name}` dependencies."
                    ),
                    id.span,
                    line_starts,
                    None,
                );
            }
        }
        Expression::StaticMemberExpression(mem) => {
            let full_text = mem.span.source_text(semantic.source_text());
            if full_text == "Number.NaN" {
                push_site(
                    sites,
                    RuleId::HooksNoNanInDeps,
                    subj_name.clone(),
                    "hooksNoNanInDeps",
                    "Number.NaN",
                    "`Number.NaN` should not be listed in hook dependency arrays.".to_string(),
                    mem.span,
                    line_starts,
                    None,
                );
            } else if mem.property.name == "current"
                || full_text.starts_with("window.")
                || full_text.starts_with("location.")
                || full_text.starts_with("document.")
                || full_text.starts_with("navigator.")
                || full_text.contains(".current.")
            {
                push_site(
                    sites,
                    RuleId::NoMutableInDeps,
                    subj_name.clone(),
                    "noMutableInDeps",
                    full_text,
                    format!(
                        "Mutable value `{full_text}` in `{hook_name}` dependencies does not trigger re-renders when mutated."
                    ),
                    mem.span,
                    line_starts,
                    None,
                );
            }
        }
        other if is_effect_hook && is_fresh_render_expression(other) => {
            let text = other.span().source_text(semantic.source_text());
            push_site(
                sites,
                RuleId::NoEffectWithFreshDeps,
                subj_name.clone(),
                "noEffectWithFreshDeps",
                text,
                format!(
                    "Fresh inline value `{text}` in `{hook_name}` dependencies causes the effect to re-run every render."
                ),
                other.span(),
                line_starts,
                None,
            );
        }
        _ => {}
    }
}

fn check_reducer_arg_for_mutation(
    semantic: &Semantic<'_>,
    first_arg: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let reducer_fn_node = match first_arg.without_parentheses() {
        Expression::Identifier(id) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, id) else {
                return;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(_) => Some(decl_id),
                AstKind::VariableDeclarator(decl) => decl.init.as_ref().and_then(|init| {
                    for (nid, n) in semantic.nodes().iter_enumerated() {
                        if n.span() == init.without_parentheses().span()
                            && matches!(
                                n.kind(),
                                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                            )
                        {
                            return Some(nid);
                        }
                    }
                    None
                }),
                _ => None,
            }
        }
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            let target_span = first_arg.without_parentheses().span();
            semantic
                .nodes()
                .iter_enumerated()
                .find_map(|(nid, n)| (n.span() == target_span).then_some(nid))
        }
        _ => None,
    };

    let Some(fn_id) = reducer_fn_node else {
        return;
    };
    let state_param_name = match semantic.nodes().kind(fn_id) {
        AstKind::Function(f) => f
            .params
            .items
            .first()
            .and_then(|p| p.pattern.get_binding_identifier())
            .map(|id| id.name.to_string()),
        AstKind::ArrowFunctionExpression(arr) => arr
            .params
            .items
            .first()
            .and_then(|p| p.pattern.get_binding_identifier())
            .map(|id| id.name.to_string()),
        _ => None,
    };
    let Some(state_param) = state_param_name else {
        return;
    };
    let fn_span = semantic.nodes().get_node(fn_id).span();

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        if is_mutation_of_named_binding(node.kind(), &state_param) {
            push_site(
                sites,
                RuleId::NoMutatingReducerState,
                subj_name.clone(),
                "noMutatingReducerState",
                &state_param,
                format!(
                    "Reducer mutates `{state_param}` in place; return a new state object instead."
                ),
                node.span(),
                line_starts,
                None,
            );
            break;
        }
    }
}

