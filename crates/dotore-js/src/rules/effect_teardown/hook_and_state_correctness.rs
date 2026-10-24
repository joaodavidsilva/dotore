//! Hook dependency, `useReducer`, render-phase purity, and state-setter correctness rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; hook and state correctness detectors match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        AssignmentTarget, BinaryOperator, BindingPattern, CallExpression, Expression, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite,
        react_ast::{
            find_enclosing_react_node, get_subject_name, is_custom_hook,
            is_direct_render_phase_node, is_functional_component, is_inside_use_effect,
        },
    },
    matchers::{is_react_hook_callee, resolve_ident_symbol},
    rules::types::RuleId,
};

use super::{
    ARRAY_MUTATING_METHODS, DEPS_HOOKS, EFFECT_HOOKS, NONDETERMINISTIC_ID_CALLEES,
    dom_and_timer_teardown::{
        check_debounce_no_cleanup, check_effect_hook_call, is_memoized_debounce_call,
    },
    is_at_module_scope, push_site,
};

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

    let mut state_to_setter: HashMap<String, String> = HashMap::new();
    let mut setter_to_state: HashMap<String, String> = HashMap::new();
    let mut effect_event_names: HashSet<String> = HashSet::new();
    let mut fresh_render_bindings: HashSet<String> = HashSet::new();
    let mut queried_dom_vars: HashSet<String> = HashSet::new();
    let mut debounce_vars: Vec<(String, Span)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if find_enclosing_react_node(semantic, node_id) != Some(subj_id) {
            continue;
        }

        if let AstKind::VariableDeclarator(decl) = node.kind()
            && let Some(init) = decl.init.as_ref().map(Expression::without_parentheses)
        {
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
                        state_to_setter.insert(s.clone(), setter.clone());
                        setter_to_state.insert(setter, s);
                    }
                } else if (is_react_hook_callee(semantic, &call.callee, "useEffectEvent")
                    || is_react_hook_callee(semantic, &call.callee, "experimental_useEffectEvent"))
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    effect_event_names.insert(id.name.to_string());
                } else if is_memoized_debounce_call(semantic, call)
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    debounce_vars.push((id.name.to_string(), decl.span));
                } else if is_dom_query_call(call)
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    queried_dom_vars.insert(id.name.to_string());
                }
            }
            if is_direct_render_phase_node(semantic, node_id)
                && is_fresh_render_expression(init)
                && let Some(id) = decl.id.get_binding_identifier()
            {
                fresh_render_bindings.insert(id.name.to_string());
            }
        }
    }

    // `debounce-no-cleanup`
    check_debounce_no_cleanup(
        semantic,
        subj_span,
        &subj_name,
        &debounce_vars,
        line_starts,
        sites,
    );

    // Collect parameter names of this Subject for `no-effect-wrapper-discards-callback-cleanup-return`
    let subj_param_names = get_function_param_names(semantic, subj_id);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if find_enclosing_react_node(semantic, node_id) != Some(subj_id) {
            continue;
        }

        match node.kind() {
            AstKind::ThisExpression(this_expr) if is_comp => {
                if is_direct_subject_this(semantic, node_id, subj_id) {
                    push_site(
                        sites,
                        RuleId::NoThisInSfc,
                        subj_name.clone(),
                        "noThisInSfc",
                        "this",
                        "Function components do not have a `this` instance; read from `props` directly.".to_string(),
                        this_expr.span,
                        line_starts,
                        None,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                check_subject_call_rules(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subj_name,
                    is_comp,
                    is_hook,
                    &subj_param_names,
                    &state_to_setter,
                    &setter_to_state,
                    &effect_event_names,
                    &fresh_render_bindings,
                    &queried_dom_vars,
                    line_starts,
                    sites,
                );
            }
            AstKind::AssignmentExpression(assign) => {
                if !queried_dom_vars.is_empty()
                    && is_mutation_of_queried_dom_target(&assign.left, &queried_dom_vars)
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
            }
            AstKind::BinaryExpression(bin) if is_comp => {
                if matches!(
                    bin.operator,
                    BinaryOperator::StrictEquality
                        | BinaryOperator::Equality
                        | BinaryOperator::StrictInequality
                        | BinaryOperator::Inequality
                ) {
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
            }
            _ => {}
        }
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
    subj_param_names: &HashSet<String>,
    state_to_setter: &HashMap<String, String>,
    setter_to_state: &HashMap<String, String>,
    effect_event_names: &HashSet<String>,
    fresh_render_bindings: &HashSet<String>,
    queried_dom_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee = call.callee.without_parentheses();
    let in_render_phase = is_direct_render_phase_node(semantic, node_id);

    // 1. Effect hooks (`useEffect`, `useLayoutEffect`, `useInsertionEffect`)
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
            subj_param_names,
            setter_to_state,
            effect_event_names,
            fresh_render_bindings,
            line_starts,
            sites,
        );
    }

    // 2. All hooks with dependency arrays (`hooks-no-nan-in-deps`, `no-mutable-in-deps`, `no-effect-event-in-deps`)
    if let Some(hook_name) = DEPS_HOOKS
        .iter()
        .copied()
        .find(|h| is_react_hook_callee(semantic, callee, h))
    {
        let deps_idx = if hook_name == "useImperativeHandle" {
            2
        } else {
            1
        };
        if let Some(deps_expr) = call.arguments.get(deps_idx).and_then(|a| a.as_expression())
            && let Expression::ArrayExpression(arr) = deps_expr.without_parentheses()
        {
            for elem in &arr.elements {
                let Some(dep_expr) = elem.as_expression() else {
                    continue;
                };
                check_single_dep_expression(
                    semantic,
                    dep_expr.without_parentheses(),
                    hook_name,
                    subj_name,
                    effect_event_names,
                    fresh_render_bindings,
                    line_starts,
                    sites,
                );
            }
        }
    }

    // 3. `useReducer(reducerFn, ...)` -> `no-mutating-reducer-state`
    if is_react_hook_callee(semantic, callee, "useReducer")
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        check_reducer_arg_for_mutation(semantic, first_arg, subj_name, line_starts, sites);
    }

    // 4. `createContext` in render (`no-create-context-in-render`)
    if !is_at_module_scope(semantic, node_id)
        && is_react_hook_callee(semantic, callee, "createContext")
    {
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

    // 5. `createRef` in function component (`no-create-ref-in-function-component`)
    if (is_comp || is_hook)
        && !is_at_module_scope(semantic, node_id)
        && is_react_hook_callee(semantic, callee, "createRef")
    {
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

    // 6. Render-phase-only calls (`no-create-object-url-in-render`, `no-create-store-in-render`, `no-nondeterministic-id-value-in-render-body`, `waapi-animation-in-render`)
    if in_render_phase && !is_at_module_scope(semantic, node_id) {
        check_render_phase_call(semantic, node_id, call, subj_name, line_starts, sites);
    }

    // 7. State setter calls (`no-boolean-toggle-without-functional-update`, `no-impure-state-updater`, `no-mutate-then-set-or-return-same-reference`)
    if let Expression::Identifier(callee_id) = callee
        && let Some(state_name) = setter_to_state.get(callee_id.name.as_str())
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
            setter_to_state,
            line_starts,
            sites,
        );
    }

    // 8. Mutating method call on queried DOM variable (`no-mutate-queried-dom-node-in-component`)
    if !queried_dom_vars.is_empty()
        && let Expression::StaticMemberExpression(mem) = callee
    {
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
                call.span,
                line_starts,
                None,
            );
        }
    }

    let _ = state_to_setter;
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

fn is_mutation_of_named_binding(kind: AstKind<'_>, var_name: &str) -> bool {
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

fn check_render_phase_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Exclude calls inside `useState(() => ...)` or `useMemo(() => ...)` or `useRef(...)`
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(parent_call) = semantic.nodes().kind(anc_id)
            && (is_react_hook_callee(semantic, &parent_call.callee, "useState")
                || is_react_hook_callee(semantic, &parent_call.callee, "useMemo")
                || is_react_hook_callee(semantic, &parent_call.callee, "useRef"))
        {
            return;
        }
    }

    let callee = call.callee.without_parentheses();
    let callee_text = callee.span().source_text(semantic.source_text());

    // `no-create-object-url-in-render`
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

    // `no-create-store-in-render`
    let is_store_factory = match callee {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "createStore" | "configureStore")
        }
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.property.name.as_str(), "createStore" | "configureStore")
        }
        _ => false,
    };
    if is_store_factory {
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

    // `no-nondeterministic-id-value-in-render-body`
    let is_nondeterministic_id = match callee {
        Expression::Identifier(id) => NONDETERMINISTIC_ID_CALLEES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            matches!(
                callee_text,
                "crypto.randomUUID" | "_.uniqueId" | "lodash.uniqueId"
            ) || mem.property.name == "randomUUID"
        }
        _ => false,
    };
    if is_nondeterministic_id {
        // Skip if used inside a JSX `key` prop (handled by `no-random-key`)
        let in_jsx_key = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::JSXAttribute(attr) if attr.name.as_identifier().is_some_and(|i| i.name == "key")
            )
        });
        if !in_jsx_key {
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
    }

    // `waapi-animation-in-render`
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

fn check_state_setter_call(
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
    // 1. `no-boolean-toggle-without-functional-update`: `setX(!x)`
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

    // 2. `no-mutate-then-set-or-return-same-reference`: `list.push(...); setList(list)`
    if let Expression::Identifier(arg_id) = first_arg
        && arg_id.name.as_str() == state_name
    {
        let scope_span = semantic
            .nodes()
            .ancestor_ids(node_id)
            .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
                AstKind::FunctionBody(b) => Some(b.span),
                AstKind::BlockStatement(b) => Some(b.span),
                _ => None,
            })
            .unwrap_or_else(|| semantic.nodes().get_node(subj_id).span());

        let mutated_in_scope = semantic.nodes().iter_enumerated().any(|(_, n)| {
            scope_span.contains_inclusive(n.span())
                && n.span().start < call.span.start
                && is_mutation_of_named_binding(n.kind(), state_name)
        });
        if mutated_in_scope {
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
    }

    // 3. `no-impure-state-updater` (and `no-mutate-then-set-or-return-same-reference` inside updater)
    let (updater_span, updater_param) = match first_arg {
        Expression::ArrowFunctionExpression(arr) => (
            Some(arr.span),
            arr.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        Expression::FunctionExpression(f) => (
            Some(f.span),
            f.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        _ => (None, None),
    };

    if let Some(u_span) = updater_span {
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
            match inner.kind() {
                AstKind::AssignmentExpression(_) | AstKind::UpdateExpression(_) => {
                    is_impure = true;
                }
                AstKind::CallExpression(c) => {
                    let c_text = c
                        .callee
                        .without_parentheses()
                        .span()
                        .source_text(semantic.source_text());
                    if setter_to_state.contains_key(c_text)
                        || c_text.starts_with("localStorage.")
                        || c_text.starts_with("sessionStorage.")
                        || c_text.starts_with("console.")
                        || matches!(
                            c_text,
                            "fetch" | "setTimeout" | "setInterval" | "dispatch" | "alert"
                        )
                    {
                        is_impure = true;
                    }
                }
                _ => {}
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
}
