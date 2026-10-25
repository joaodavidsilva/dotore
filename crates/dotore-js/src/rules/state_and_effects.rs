//! `state-and-effects` rule family detectors (`no-self-updating-effect`, `no-set-state-in-render`,
//! `no-set-state-after-await-in-effect`, `no-side-effect-in-state-updater-function`,
//! `no-ref-current-in-render`, `no-prop-callback-in-render`, `no-prop-callback-in-effect`,
//! `effect-needs-cleanup`, `rerender-lazy-state-init`, `rerender-lazy-ref-init`,
//! `prefer-use-reducer`, `rerender-functional-setstate`, `no-whole-object-dep-with-member-reads`,
//! `no-spread-props-over-defaults-clobbers-with-undefined`, `no-stale-timer-ref`,
//! `no-unowned-async-error-clear`, `prefer-use-effect-event`, `rerender-state-only-in-handlers`,
//! `rerender-defer-reads-hook`, and `rerender-dependencies`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

mod effects_and_async;

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{BindingPattern, CallExpression, Expression, ObjectPropertyKind, Statement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use self::effects_and_async::{
    check_effect_hook_rules, check_no_stale_timer_ref, check_no_unowned_async_error_clear,
    expression_reads_state_value,
};
use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        dataflow::{is_prop, is_ref},
        react_ast::{
            find_enclosing_react_node, get_subject_body_statements, get_subject_name,
            is_functional_component, is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, RuleId},
};

const SIDE_EFFECT_CALLEE_PREFIXES: &[&str] = &[
    "on", "notify", "fetch", "send", "dispatch", "emit", "track", "log", "record", "report",
    "save", "submit", "persist",
];

const CHEAP_PRIMITIVE_WRAPPERS: &[&str] = &["Boolean", "String", "Number", "BigInt", "Symbol"];

const PREFER_USE_REDUCER_MIN_STATE_SLOTS: usize = 5;

/// Extracts all single-pass `state-and-effects` semantic sites and autofix patches.
pub(crate) fn extract_state_and_effects_sites(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            check_subject_state_and_effects(semantic, subj_id, line_starts, sites);
        }
    }
}

fn check_subject_state_and_effects(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let subj_name = get_subject_name(semantic, subject_node_id);
    let is_component = is_functional_component(semantic, subject_node_id);

    let (setter_to_state, setter_names, state_slot_count) = collect_subject_state_and_ref_slots(
        semantic,
        subject_node_id,
        subj_span,
        &subj_name,
        line_starts,
        sites,
    );

    if state_slot_count >= PREFER_USE_REDUCER_MIN_STATE_SLOTS {
        sites.push(SemanticRuleSite {
            rule: RuleId::PreferUseReducer,
            subject_name: subj_name.clone(),
            message_id: "preferUseReducer",
            target_name: subj_name.clone().unwrap_or_else(|| "Component".to_string()),
            message: format!(
                "This component manages {state_slot_count} separate `useState` slots; consolidate coupled state transitions into `useReducer`."
            ),
            loc: loc_from_line_starts(line_starts, subj_span.start),
            span: ByteSpan {
                start: subj_span.start,
                end: subj_span.end,
            },
            autofix: None,
        });
    }

    if is_component && !setter_names.is_empty() {
        check_no_set_state_in_render(
            semantic,
            subject_node_id,
            &setter_names,
            &subj_name,
            line_starts,
            sites,
        );
    }

    walk_subject_state_and_effect_nodes(
        semantic,
        subject_node_id,
        subj_span,
        is_component,
        &setter_to_state,
        &setter_names,
        &subj_name,
        line_starts,
        sites,
    );

    if is_component {
        check_rerender_state_only_in_handlers_and_defer_reads(
            semantic,
            subject_node_id,
            subj_span,
            &subj_name,
            line_starts,
            sites,
        );
    }
}

fn collect_subject_state_and_ref_slots(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    subj_span: Span,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) -> (HashMap<String, String>, HashSet<String>, usize) {
    let mut setter_to_state: HashMap<String, String> = HashMap::new();
    let mut setter_names: HashSet<String> = HashSet::new();
    let mut state_slot_count = 0_usize;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        if find_enclosing_react_node(semantic, node_id) != Some(subject_node_id) {
            continue;
        }
        let Some(Expression::CallExpression(call)) =
            decl.init.as_ref().map(Expression::without_parentheses)
        else {
            continue;
        };

        if is_react_hook_callee(semantic, &call.callee, "useState") {
            state_slot_count += 1;
            check_lazy_state_init(semantic, call, subj_name, line_starts, sites);
            record_use_state_binding_names(
                &decl.id,
                &mut setter_to_state,
                &mut setter_names,
            );
        } else if is_react_hook_callee(semantic, &call.callee, "useRef") {
            check_lazy_ref_init(call, subj_name, line_starts, sites);
        }
    }
    (setter_to_state, setter_names, state_slot_count)
}

fn record_use_state_binding_names(
    pat: &BindingPattern<'_>,
    setter_to_state: &mut HashMap<String, String>,
    setter_names: &mut HashSet<String>,
) {
    let BindingPattern::ArrayPattern(arr) = pat else {
        return;
    };
    let state_opt = arr
        .elements
        .first()
        .and_then(Option::as_ref)
        .and_then(BindingPattern::get_binding_identifier)
        .map(|id| id.name.to_string());
    let setter_opt = arr
        .elements
        .get(1)
        .and_then(Option::as_ref)
        .and_then(BindingPattern::get_binding_identifier)
        .map(|id| id.name.to_string());
    if let Some(set_name) = setter_opt {
        setter_names.insert(set_name.clone());
        let associated_state = state_opt.unwrap_or_else(|| set_name.clone());
        setter_to_state.insert(set_name, associated_state);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Walks all AST nodes owned by a Subject for effect, setter, ref, and prop-callback rules (#50)"
)]
fn walk_subject_state_and_effect_nodes(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    subj_span: Span,
    is_component: bool,
    setter_to_state: &HashMap<String, String>,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span())
            || find_enclosing_react_node(semantic, node_id) != Some(subject_node_id)
        {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                check_subject_call_node(
                    semantic,
                    node_id,
                    call,
                    subject_node_id,
                    subj_span,
                    is_component,
                    setter_to_state,
                    setter_names,
                    subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::StaticMemberExpression(mem)
                if is_component && mem.property.name == "current" =>
            {
                check_ref_current_in_render(
                    semantic,
                    node_id,
                    mem,
                    subject_node_id,
                    subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ObjectExpression(obj) => {
                check_spread_props_over_defaults(semantic, obj, subj_name, line_starts, sites);
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                check_no_unowned_async_error_clear(
                    semantic,
                    node_id,
                    setter_to_state,
                    subj_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Dispatches CallExpression checks inside a Subject (#50)"
)]
fn check_subject_call_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_node_id: NodeId,
    subj_span: Span,
    is_component: bool,
    setter_to_state: &HashMap<String, String>,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_react_hook_callee(semantic, &call.callee, "useEffect")
        || is_react_hook_callee(semantic, &call.callee, "useLayoutEffect")
    {
        check_effect_hook_rules(
            semantic,
            node_id,
            call,
            setter_to_state,
            setter_names,
            subj_name,
            line_starts,
            sites,
        );
    }
    if ["useEffect", "useLayoutEffect", "useMemo", "useCallback"]
        .iter()
        .any(|h| is_react_hook_callee(semantic, &call.callee, h))
    {
        check_hook_dependency_granularity_and_stability(
            semantic,
            call,
            subj_span,
            subj_name,
            line_starts,
            sites,
        );
    }
    if let Expression::Identifier(callee_ident) = call.callee.without_parentheses()
        && let Some(state_name) = setter_to_state.get(callee_ident.name.as_str())
    {
        check_setter_call_rules(
            semantic,
            node_id,
            call,
            callee_ident.name.as_str(),
            state_name,
            setter_names,
            subject_node_id,
            subj_name,
            line_starts,
            sites,
        );
    }
    if is_component {
        check_prop_callback_in_render(
            semantic,
            node_id,
            call,
            subject_node_id,
            subj_name,
            line_starts,
            sites,
        );
    }
    check_no_stale_timer_ref(semantic, node_id, call, subj_name, line_starts, sites);
}

fn check_prop_callback_in_render(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_node_id: NodeId,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::Identifier(callee_ident) = call.callee.without_parentheses()
        && let Some(ref_id) = callee_ident.reference_id.get()
        && is_prop(semantic, ref_id)
        && (callee_ident.name.starts_with("on")
            || matches!(
                semantic.nodes().parent_kind(node_id),
                AstKind::ExpressionStatement(_)
            ))
        && is_in_render_execution_scope(semantic, node_id, subject_node_id)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoPropCallbackInRender,
            subject_name: subj_name.clone(),
            message_id: "noPropCallbackInRender",
            target_name: callee_ident.name.to_string(),
            message: format!(
                "Prop callback `{}` is invoked directly during render; move it into an event handler or effect.",
                callee_ident.name
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_ref_current_in_render(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    subject_node_id: NodeId,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::Identifier(obj_ident) = mem.object.without_parentheses()
        && let Some(ref_id) = obj_ident.reference_id.get()
        && is_ref(semantic, ref_id)
        && is_in_render_execution_scope(semantic, node_id, subject_node_id)
        && !is_lazy_ref_init_guard(semantic, node_id, obj_ident.name.as_str())
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoRefCurrentInRender,
            subject_name: subj_name.clone(),
            message_id: "noRefCurrentInRender",
            target_name: format!("{}.current", obj_ident.name),
            message: format!(
                "Do not read or write `{}.current` during render; refs do not trigger re-renders and must be accessed in effects or event handlers.",
                obj_ident.name
            ),
            loc: loc_from_line_starts(line_starts, mem.span.start),
            span: ByteSpan {
                start: mem.span.start,
                end: mem.span.end,
            },
            autofix: None,
        });
    }
}

fn check_lazy_state_init(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let unwrapped = first_arg.without_parentheses();
    let Expression::CallExpression(init_call) = unwrapped else {
        return;
    };
    if let Expression::Identifier(id) = init_call.callee.without_parentheses()
        && (id.name.starts_with("use") || CHEAP_PRIMITIVE_WRAPPERS.contains(&id.name.as_str()))
    {
        return;
    }

    let arg_span = first_arg.span();
    let arg_text = arg_span.source_text(semantic.source_text()).trim();
    let span = ByteSpan {
        start: init_call.span.start,
        end: init_call.span.end,
    };
    let loc = loc_from_line_starts(line_starts, init_call.span.start);
    let patch = AutofixPatch::replace(
        format!("Wrap `useState` initializer in `() => {arg_text}`"),
        ByteSpan {
            start: arg_span.start,
            end: arg_span.end,
        },
        format!("() => {arg_text}"),
    );
    sites.push(SemanticRuleSite {
        rule: RuleId::RerenderLazyStateInit,
        subject_name: subj_name.clone(),
        message_id: "rerenderLazyStateInit",
        target_name: arg_text.to_string(),
        message: format!(
            "`useState({arg_text})` evaluates `{arg_text}` on every render; pass a lazy initializer `useState(() => {arg_text})`."
        ),
        loc,
        span,
        autofix: Some(patch),
    });
}

fn check_lazy_ref_init(
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if let Expression::NewExpression(new_expr) = first_arg.without_parentheses() {
        let ctor_name = match new_expr.callee.without_parentheses() {
            Expression::Identifier(id) => id.name.as_str(),
            _ => "Object",
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::RerenderLazyRefInit,
            subject_name: subj_name.clone(),
            message_id: "rerenderLazyRefInit",
            target_name: ctor_name.to_string(),
            message: format!(
                "`useRef(new {ctor_name}(...))` allocates a new `{ctor_name}` instance on every render; initialize `useRef(null)` and lazily construct it."
            ),
            loc: loc_from_line_starts(line_starts, new_expr.span.start),
            span: ByteSpan {
                start: new_expr.span.start,
                end: new_expr.span.end,
            },
            autofix: None,
        });
    }
}

fn check_no_set_state_in_render(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(stmts) = get_subject_body_statements(semantic, subject_node_id) else {
        return;
    };
    for stmt in stmts {
        let Statement::ExpressionStatement(expr_stmt) = stmt else {
            continue;
        };
        let Expression::CallExpression(call) = expr_stmt.expression.without_parentheses() else {
            continue;
        };
        let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
            continue;
        };
        if setter_names.contains(callee_id.name.as_str()) {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoSetStateInRender,
                subject_name: subj_name.clone(),
                message_id: "noSetStateInRender",
                target_name: callee_id.name.to_string(),
                message: format!(
                    "{}() triggers another render while rendering. Move it to an effect or event handler, or compute the value during render.",
                    callee_id.name
                ),
                loc: loc_from_line_starts(line_starts, call.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks both updater purity and functional-setstate rules on a resolved state setter call"
)]
fn check_setter_call_rules(
    semantic: &Semantic<'_>,
    setter_call_id: NodeId,
    call: &CallExpression<'_>,
    setter_name: &str,
    state_name: &str,
    all_setter_names: &HashSet<String>,
    subject_node_id: NodeId,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let unwrapped = first_arg.without_parentheses();

    // 1. `no-side-effect-in-state-updater-function`: updater function (`prev => { ... }`) performing side effects
    if matches!(
        unwrapped,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) {
        let updater_span = unwrapped.span();
        for (_, inner) in semantic.nodes().iter_enumerated() {
            if !updater_span.contains_inclusive(inner.span()) || inner.span() == updater_span {
                continue;
            }
            if let AstKind::CallExpression(inner_call) = inner.kind() {
                let is_side_effect = match inner_call.callee.without_parentheses() {
                    Expression::Identifier(id) => {
                        all_setter_names.contains(id.name.as_str())
                            || id.reference_id.get().is_some_and(|r| is_prop(semantic, r))
                            || SIDE_EFFECT_CALLEE_PREFIXES
                                .iter()
                                .any(|p| id.name.starts_with(p))
                    }
                    Expression::StaticMemberExpression(mem) => matches!(
                        mem.property.name.as_str(),
                        "setItem" | "removeItem" | "appendChild" | "dispatchEvent" | "fetch"
                    ),
                    _ => false,
                };
                if is_side_effect {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::NoSideEffectInStateUpdaterFunction,
                        subject_name: subj_name.clone(),
                        message_id: "noSideEffectInStateUpdaterFunction",
                        target_name: setter_name.to_string(),
                        message: "This side-effecting call runs inside a state updater, which React may invoke more than once. Move it outside the setter after computing the next state.".to_string(),
                        loc: loc_from_line_starts(line_starts, inner_call.span.start),
                        span: ByteSpan {
                            start: inner_call.span.start,
                            end: inner_call.span.end,
                        },
                        autofix: None,
                    });
                }
            }
        }
        return;
    }

    // 2. `rerender-functional-setstate`: `setA(a + 1)` inside a handler/callback reading `a` directly
    if !is_in_render_execution_scope(semantic, setter_call_id, subject_node_id)
        && matches!(unwrapped, Expression::BinaryExpression(_))
        && expression_reads_state_value(unwrapped, state_name)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RerenderFunctionalSetstate,
            subject_name: subj_name.clone(),
            message_id: "rerenderFunctionalSetstate",
            target_name: setter_name.to_string(),
            message: format!(
                "`{setter_name}(...)` reads `{state_name}` directly; use a functional updater `{setter_name}(prev => ...)` to avoid stale closures."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn is_in_render_execution_scope(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subject_node_id: NodeId,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subject_node_id {
            return true;
        }
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            let parent_id = semantic.nodes().parent_id(anc_id);
            if parent_id == subject_node_id {
                continue;
            }
            return false;
        }
    }
    false
}

fn is_lazy_ref_init_guard(semantic: &Semantic<'_>, node_id: NodeId, ref_name: &str) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::IfStatement(if_stmt) = semantic.nodes().kind(anc_id) {
            let test_text = if_stmt.test.span().source_text(semantic.source_text());
            if test_text.contains(&format!("{ref_name}.current"))
                && (test_text.contains("null") || test_text.starts_with('!'))
            {
                return true;
            }
        }
    }
    false
}

fn check_spread_props_over_defaults(
    semantic: &Semantic<'_>,
    obj: &oxc_ast::ast::ObjectExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen_default_key = false;
    for prop in &obj.properties {
        match prop {
            ObjectPropertyKind::ObjectProperty(_) => {
                seen_default_key = true;
            }
            ObjectPropertyKind::SpreadProperty(spread) if seen_default_key => {
                if let Expression::Identifier(id) = spread.argument.without_parentheses()
                    && let Some(ref_id) = id.reference_id.get()
                    && is_prop(semantic, ref_id)
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::NoSpreadPropsOverDefaultsClobbersWithUndefined,
                        subject_name: subj_name.clone(),
                        message_id: "noSpreadPropsOverDefaults",
                        target_name: id.name.to_string(),
                        message: format!(
                            "Spreading `...{}` after default object properties overwrites defaults when a prop is explicitly `undefined`.",
                            id.name
                        ),
                        loc: loc_from_line_starts(line_starts, spread.span.start),
                        span: ByteSpan {
                            start: spread.span.start,
                            end: spread.span.end,
                        },
                        autofix: None,
                    });
                }
            }
            ObjectPropertyKind::SpreadProperty(_) => {}
        }
    }
}

fn check_hook_dependency_granularity_and_stability(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subj_span: Span,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(cb_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let Some(deps_arg) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
        return;
    };
    let Expression::ArrayExpression(deps_arr) = deps_arg.without_parentheses() else {
        return;
    };
    let cb_span = cb_arg.span();

    for elem in &deps_arr.elements {
        let Some(Expression::Identifier(dep_id)) =
            elem.as_expression().map(Expression::without_parentheses)
        else {
            continue;
        };
        let Some(ref_id) = dep_id.reference_id.get() else {
            continue;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
            continue;
        };
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        let decl_node = semantic.nodes().get_node(decl_id);

        // 1. `rerender-dependencies`: dep is a render-local object/array/function literal
        if subj_span.contains_inclusive(decl_node.span())
            && let AstKind::VariableDeclarator(decl) = decl_node.kind()
            && let Some(init) = &decl.init
            && matches!(
                init.without_parentheses(),
                Expression::ObjectExpression(_)
                    | Expression::ArrayExpression(_)
                    | Expression::ArrowFunctionExpression(_)
                    | Expression::FunctionExpression(_)
            )
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RerenderDependencies,
                subject_name: subj_name.clone(),
                message_id: "rerenderDependencies",
                target_name: dep_id.name.to_string(),
                message: format!(
                    "Dependency `{}` is recreated on every render; memoize it or move it inside the hook.",
                    dep_id.name
                ),
                loc: loc_from_line_starts(line_starts, dep_id.span.start),
                span: ByteSpan {
                    start: dep_id.span.start,
                    end: dep_id.span.end,
                },
                autofix: None,
            });
        }

        // 2. `no-whole-object-dep-with-member-reads`: dep `obj` is only accessed via `obj.prop` inside `cb_span`
        let mut member_reads = 0_usize;
        let mut bare_reads = 0_usize;
        for reference in semantic.scoping().get_resolved_references(sym_id) {
            let r_node_id = reference.node_id();
            let r_span = semantic.nodes().get_node(r_node_id).span();
            if !cb_span.contains_inclusive(r_span) {
                continue;
            }
            let parent_id = semantic.nodes().parent_id(r_node_id);
            if let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(parent_id)
                && mem.object.span().contains_inclusive(r_span)
            {
                member_reads += 1;
            } else {
                bare_reads += 1;
            }
        }
        if member_reads > 0 && bare_reads == 0 {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoWholeObjectDepWithMemberReads,
                subject_name: subj_name.clone(),
                message_id: "noWholeObjectDepWithMemberReads",
                target_name: dep_id.name.to_string(),
                message: format!(
                    "Hook dependency array lists whole object `{}` even though the callback only reads its properties; list the specific property reads instead.",
                    dep_id.name
                ),
                loc: loc_from_line_starts(line_starts, dep_id.span.start),
                span: ByteSpan {
                    start: dep_id.span.start,
                    end: dep_id.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_rerender_state_only_in_handlers_and_defer_reads(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    subj_span: Span,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        if find_enclosing_react_node(semantic, node_id) != Some(subject_node_id) {
            continue;
        }
        let Some(Expression::CallExpression(call)) =
            decl.init.as_ref().map(Expression::without_parentheses)
        else {
            continue;
        };

        if is_react_hook_callee(semantic, &call.callee, "useState")
            && let BindingPattern::ArrayPattern(arr) = &decl.id
            && let Some(Some(BindingPattern::BindingIdentifier(state_id))) = arr.elements.first()
            && let Some(sym_id) = state_id.symbol_id.get()
            && is_symbol_read_only_in_handlers(semantic, sym_id, subject_node_id)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RerenderStateOnlyInHandlers,
                subject_name: subj_name.clone(),
                message_id: "rerenderStateOnlyInHandlers",
                target_name: state_id.name.to_string(),
                message: format!(
                    "State `{}` is only read inside callbacks/handlers and never affects rendered output; use `useRef` to avoid unnecessary re-renders.",
                    state_id.name
                ),
                loc: loc_from_line_starts(line_starts, state_id.span.start),
                span: ByteSpan {
                    start: decl.span.start,
                    end: decl.span.end,
                },
                autofix: None,
            });
        } else if let BindingPattern::BindingIdentifier(val_id) = &decl.id
            && let Some(sym_id) = val_id.symbol_id.get()
            && is_reactive_custom_hook_call(semantic, call)
            && is_symbol_read_only_in_handlers(semantic, sym_id, subject_node_id)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RerenderDeferReadsHook,
                subject_name: subj_name.clone(),
                message_id: "rerenderDeferReadsHook",
                target_name: val_id.name.to_string(),
                message: format!(
                    "Reactive hook value `{}` is only read inside callbacks/handlers; defer the read into the callback to avoid unnecessary re-renders.",
                    val_id.name
                ),
                loc: loc_from_line_starts(line_starts, val_id.span.start),
                span: ByteSpan {
                    start: decl.span.start,
                    end: decl.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn is_symbol_read_only_in_handlers(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    subject_node_id: NodeId,
) -> bool {
    let mut handler_reads = 0_usize;
    let mut render_reads = 0_usize;
    for reference in semantic.scoping().get_resolved_references(sym_id) {
        if is_in_render_execution_scope(semantic, reference.node_id(), subject_node_id) {
            render_reads += 1;
        } else {
            handler_reads += 1;
        }
    }
    handler_reads > 0 && render_reads == 0
}

fn is_reactive_custom_hook_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    for builtin in [
        "useState",
        "useRef",
        "useCallback",
        "useMemo",
        "useEffect",
        "useLayoutEffect",
        "useInsertionEffect",
        "useImperativeHandle",
        "useReducer",
        "useTransition",
        "useId",
    ] {
        if is_react_hook_callee(semantic, &call.callee, builtin) {
            return false;
        }
    }
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => crate::ir::react_ast::is_custom_hook_name(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            crate::ir::react_ast::is_custom_hook_name(mem.property.name.as_str())
        }
        _ => false,
    }
}

