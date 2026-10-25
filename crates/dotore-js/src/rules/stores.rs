//! State-store rule detectors for Zustand, Jotai, MobX, and Valtio.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{
            callee_name, find_enclosing_react_node, get_subject_name, has_import_from,
            is_direct_render_phase_node, is_inside_use_effect,
        },
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const MUTATING_ARRAY_METHODS: &[&str] = &[
    "push",
    "pop",
    "splice",
    "sort",
    "reverse",
    "shift",
    "unshift",
    "fill",
    "copyWithin",
];

const ALLOCATING_ARRAY_METHODS: &[&str] = &[
    "concat",
    "filter",
    "flat",
    "flatMap",
    "map",
    "slice",
    "toReversed",
    "toSorted",
    "toSpliced",
    "with",
];

const JOTAI_TQ_ENVELOPE_FIELDS: &[&str] = &[
    "data",
    "error",
    "isLoading",
    "isPending",
    "isError",
    "isSuccess",
    "isFetching",
    "refetch",
    "status",
    "fetchStatus",
];

/// Extracts all Zustand, Jotai, MobX, and Valtio semantic rule sites in a single pass.
pub(crate) fn extract_store_sites(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let subclassed_classes = collect_subclassed_class_names(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };

        check_zustand_call_rules(
            semantic,
            node_id,
            call,
            &subject_name,
            source,
            line_starts,
            sites,
        );
        check_jotai_call_rules(
            program,
            semantic,
            node_id,
            call,
            &subject_name,
            source,
            line_starts,
            sites,
        );
        check_mobx_call_rules(
            program,
            semantic,
            node_id,
            call,
            &subclassed_classes,
            &subject_name,
            line_starts,
            sites,
        );
        check_valtio_call_rules(semantic, node_id, call, &subject_name, line_starts, sites);
    }
}

fn collect_subclassed_class_names(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut set = HashSet::new();
    let source = semantic.source_text();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::Class(cls) = node.kind() {
            let header = Span::new(cls.span.start, cls.body.span.start).source_text(source);
            if let Some(ext_idx) = header.find("extends ") {
                let super_name = header
                    .get(ext_idx + "extends ".len()..)
                    .unwrap_or_default()
                    .split([' ', '<', '{'])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !super_name.is_empty() && super_name != "null" {
                    set.insert(super_name.to_string());
                }
            }
        }
    }
    set
}

fn check_zustand_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = callee_name(&call.callee);

    // 1. `zustand-no-whole-store-destructure`
    if subject_name.is_some()
        && call.arguments.is_empty()
        && callee_name.is_some_and(|n| {
            n.starts_with("use") && n.ends_with("Store") && n != "useSyncExternalStore"
        })
        && let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(node_id)
        && matches!(decl.id, BindingPattern::ObjectPattern(_))
    {
        let store_name = callee_name.unwrap_or("useStore");
        sites.push(SemanticRuleSite {
            rule: RuleId::ZustandNoWholeStoreDestructure,
            subject_name: subject_name.clone(),
            message_id: "noWholeStoreDestructure",
            target_name: store_name.to_string(),
            message: format!(
                "Destructuring `{store_name}()` without a selector subscribes the component to the entire Zustand store."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `zustand-no-fresh-selector-result`
    if callee_name.is_some_and(|n| {
        (n.starts_with("use") && n.ends_with("Store") && n != "useSyncExternalStore")
            || n == "useStore"
    }) {
        let selector_arg_idx = if callee_name == Some("useStore") && call.arguments.len() >= 2 {
            1
        } else {
            0
        };
        let has_equality_arg = call.arguments.len() > selector_arg_idx + 1;
        if !has_equality_arg
            && let Some(sel_arg) = call
                .arguments
                .get(selector_arg_idx)
                .and_then(Argument::as_expression)
            && !is_use_shallow_wrapped(sel_arg)
            && function_returns_fresh_object_or_array(sel_arg)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::ZustandNoFreshSelectorResult,
                subject_name: subject_name.clone(),
                message_id: "zustandNoFreshSelectorResult",
                target_name: callee_name.unwrap_or("useStore").to_string(),
                message: "This Zustand selector returns a fresh object or array on every call; wrap it in `useShallow(...)` or select primitive fields.".to_string(),
                loc: loc_from_line_starts(line_starts, sel_arg.span().start),
                span: ByteSpan {
                    start: sel_arg.span().start,
                    end: sel_arg.span().end,
                },
                autofix: None,
            });
        }
    }

    // 3. `create((set, get) => ...)` / `createStore((set, get) => ...)`
    if let Some(creator_fn) = extract_zustand_creator_function(call) {
        check_zustand_creator_rules(
            semantic,
            creator_fn,
            subject_name,
            source,
            line_starts,
            sites,
        );
    }
}

fn is_use_shallow_wrapped(expr: &Expression<'_>) -> bool {
    if let Expression::CallExpression(c) = expr.without_parentheses() {
        callee_name(&c.callee) == Some("useShallow")
    } else {
        false
    }
}

fn extract_zustand_creator_function<'a>(
    call: &'a CallExpression<'a>,
) -> Option<&'a Expression<'a>> {
    let is_zustand_create = match call.callee.without_parentheses() {
        Expression::Identifier(id) => matches!(id.name.as_str(), "create" | "createStore"),
        Expression::CallExpression(inner) => matches!(
            inner.callee.without_parentheses(),
            Expression::Identifier(id) if matches!(id.name.as_str(), "create" | "createStore")
        ),
        _ => false,
    };
    if !is_zustand_create {
        return None;
    }
    let first_arg = call.arguments.first()?.as_expression()?;
    let unwrapped = first_arg.without_parentheses();
    if matches!(
        unwrapped,
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) {
        return Some(unwrapped);
    }
    None
}

fn check_zustand_creator_rules(
    semantic: &Semantic<'_>,
    creator_fn: &Expression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let params = match creator_fn {
        Expression::ArrowFunctionExpression(a) => &a.params,
        Expression::FunctionExpression(f) => &f.params,
        _ => return,
    };

    let set_param = params.items.first().and_then(|p| match &p.pattern {
        BindingPattern::BindingIdentifier(id) => Some((id.name.as_str(), id.symbol_id.get())),
        _ => None,
    });
    let get_param = params.items.get(1).and_then(|p| match &p.pattern {
        BindingPattern::BindingIdentifier(id) => Some((id.name.as_str(), id.symbol_id.get())),
        _ => None,
    });

    // `zustand-no-get-during-initialization`: `get()` called synchronously inside creator body (not inside a nested function)
    if let Some((_, Some(get_sym))) = get_param {
        for r in semantic.scoping().get_resolved_references(get_sym) {
            let ref_node_id = r.node_id();
            let p_id = semantic.nodes().parent_id(ref_node_id);
            let AstKind::CallExpression(get_call) = semantic.nodes().kind(p_id) else {
                continue;
            };
            if !get_call
                .callee
                .span()
                .contains_inclusive(semantic.nodes().get_node(ref_node_id).span())
            {
                continue;
            }
            // Check if there is any nested function between `p_id` and `creator_fn.span()`
            let is_deferred_in_nested_fn = semantic.nodes().ancestor_ids(p_id).any(|anc_id| {
                let anc_span = semantic.nodes().get_node(anc_id).span();
                creator_fn.span().contains_inclusive(anc_span)
                    && anc_span != creator_fn.span()
                    && matches!(
                        semantic.nodes().kind(anc_id),
                        AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                    )
            });
            if !is_deferred_in_nested_fn {
                sites.push(SemanticRuleSite {
                    rule: RuleId::ZustandNoGetDuringInitialization,
                    subject_name: subject_name.clone(),
                    message_id: "zustandNoGetDuringInitialization",
                    target_name: "get".to_string(),
                    message: "Zustand `get()` cannot be called synchronously while initializing the store; move the read into a deferred action.".to_string(),
                    loc: loc_from_line_starts(line_starts, get_call.span.start),
                    span: ByteSpan {
                        start: get_call.span.start,
                        end: get_call.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // `zustand-no-mutating-state`: inside `set((state) => { state.x = ...; return state; })`
    if let Some((_, Some(set_sym))) = set_param {
        for r in semantic.scoping().get_resolved_references(set_sym) {
            let ref_node_id = r.node_id();
            let p_id = semantic.nodes().parent_id(ref_node_id);
            let AstKind::CallExpression(set_call) = semantic.nodes().kind(p_id) else {
                continue;
            };
            let Some(updater) = set_call.arguments.first().and_then(Argument::as_expression) else {
                continue;
            };
            if let Some(mut_span) = find_in_place_zustand_state_mutation(semantic, updater, source)
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::ZustandNoMutatingState,
                    subject_name: subject_name.clone(),
                    message_id: "zustandNoMutatingState",
                    target_name: "state".to_string(),
                    message: "This Zustand state reference is mutated and reused, so subscribers can miss the update.".to_string(),
                    loc: loc_from_line_starts(line_starts, mut_span.start),
                    span: ByteSpan {
                        start: mut_span.start,
                        end: mut_span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}

fn find_in_place_zustand_state_mutation(
    semantic: &Semantic<'_>,
    updater: &Expression<'_>,
    source: &str,
) -> Option<Span> {
    let (params, body_span) = match updater.without_parentheses() {
        Expression::ArrowFunctionExpression(a) => (&a.params, a.body.span()),
        Expression::FunctionExpression(f) => (&f.params, f.body.as_ref()?.span),
        _ => return None,
    };
    let state_param = params.items.first().and_then(|p| match &p.pattern {
        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    })?;

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        if let Some(span) = zustand_node_state_mutation_span(node.kind(), state_param, source) {
            return Some(span);
        }
    }
    None
}

fn zustand_node_state_mutation_span(
    kind: AstKind<'_>,
    state_param: &str,
    source: &str,
) -> Option<Span> {
    match kind {
        AstKind::AssignmentExpression(assign) => {
            let lhs = assign.left.span().source_text(source).trim();
            is_state_member_target(lhs, state_param).then_some(assign.span)
        }
        AstKind::UpdateExpression(upd) => {
            let arg = upd.argument.span().source_text(source).trim();
            is_state_member_target(arg, state_param).then_some(upd.span)
        }
        AstKind::CallExpression(c) => {
            let Expression::StaticMemberExpression(mem) = c.callee.without_parentheses() else {
                return None;
            };
            if !MUTATING_ARRAY_METHODS.contains(&mem.property.name.as_str()) {
                return None;
            }
            let recv = mem.object.span().source_text(source).trim();
            (recv == state_param || is_state_member_target(recv, state_param)).then_some(c.span)
        }
        _ => None,
    }
}

fn is_state_member_target(text: &str, state_param: &str) -> bool {
    text.strip_prefix(state_param)
        .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all Jotai CallExpression rules in a single pass"
)]
fn check_jotai_call_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = callee_name(&call.callee);

    // 1. `jotai-select-atom-in-render-body`
    if subject_name.is_some()
        && callee_name == Some("selectAtom")
        && !is_inside_memo_or_effect(semantic, node_id)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::JotaiSelectAtomInRenderBody,
            subject_name: subject_name.clone(),
            message_id: "noSelectAtomInRenderBody",
            target_name: "selectAtom".to_string(),
            message: "Avoid calling `selectAtom(...)` directly in render without `useMemo` or hoisting to module scope.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `jotai-derived-atom-returns-fresh-object`
    if callee_name == Some("atom")
        && has_import_from(program, &["jotai", "jotai/vanilla"])
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && is_jotai_derived_getter(first_arg, source)
        && function_returns_fresh_object_or_array(first_arg)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::JotaiDerivedAtomReturnsFreshObject,
            subject_name: subject_name.clone(),
            message_id: "jotaiDerivedAtomReturnsFreshObject",
            target_name: "atom".to_string(),
            message: "This derived Jotai atom returns a fresh object or array on every read, busting `Object.is` equality and re-rendering every consumer.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 3. `jotai-tq-use-raw-query-atom`
    if matches!(callee_name, Some("useAtomValue" | "useAtom"))
        && let Some(Argument::Identifier(atom_ident)) = call.arguments.first()
        && is_raw_tanstack_query_atom(semantic, atom_ident)
        && is_hook_result_consumed_as_query_envelope(semantic, node_id)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::JotaiTqUseRawQueryAtom,
            subject_name: subject_name.clone(),
            message_id: "jotaiTqUseRawQueryAtom",
            target_name: atom_ident.name.to_string(),
            message: "Subscribing directly to an `atomWithQuery` envelope atom re-renders on every observer notify; derive a focused field atom first.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn is_inside_memo_or_effect(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(c) = semantic.nodes().kind(anc_id)
            && let Some(name) = callee_name(&c.callee)
            && matches!(
                name,
                "useMemo" | "useCallback" | "useEffect" | "useLayoutEffect"
            )
        {
            return true;
        }
    }
    false
}

fn is_jotai_derived_getter(fn_expr: &Expression<'_>, source: &str) -> bool {
    let params = match fn_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(a) => &a.params,
        Expression::FunctionExpression(f) => &f.params,
        _ => return false,
    };
    let Some(first_param) = params.items.first() else {
        return false;
    };
    let BindingPattern::BindingIdentifier(get_id) = &first_param.pattern else {
        return false;
    };
    let body_text = fn_expr.span().source_text(source);
    body_text.contains(&format!("{}(", get_id.name))
}

fn function_returns_fresh_object_or_array(fn_expr: &Expression<'_>) -> bool {
    match fn_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => body.statements.iter().any(|s| {
                if let Statement::ReturnStatement(ret) = s
                    && let Some(arg) = &ret.argument
                {
                    expr_allocates_fresh_object_or_array(arg)
                } else {
                    false
                }
            }),
            _ => arrow
                .body
                .as_expression()
                .is_some_and(expr_allocates_fresh_object_or_array),
        },
        Expression::FunctionExpression(func) => func.body.as_ref().is_some_and(|body| {
            body.statements.iter().any(|s| {
                if let Statement::ReturnStatement(ret) = s
                    && let Some(arg) = &ret.argument
                {
                    expr_allocates_fresh_object_or_array(arg)
                } else {
                    false
                }
            })
        }),
        _ => false,
    }
}

fn expr_allocates_fresh_object_or_array(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_) => true,
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                let method = mem.property.name.as_str();
                if ALLOCATING_ARRAY_METHODS.contains(&method) {
                    return true;
                }
                if let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                    && ((obj_id.name == "Object"
                        && matches!(method, "keys" | "values" | "entries" | "fromEntries"))
                        || (obj_id.name == "Array" && matches!(method, "from" | "of")))
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_raw_tanstack_query_atom(
    semantic: &Semantic<'_>,
    atom_ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(ref_id) = atom_ident.reference_id.get() else {
        return atom_ident.name.ends_with("QueryAtom");
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return atom_ident.name.ends_with("QueryAtom");
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
        && let Some(init) = &decl.init
        && let Expression::CallExpression(call) = init.without_parentheses()
        && let Some(callee) = callee_name(&call.callee)
    {
        return matches!(
            callee,
            "atomWithQuery" | "atomWithSuspenseQuery" | "atomWithInfiniteQuery"
        );
    }
    atom_ident.name.ends_with("QueryAtom")
}

fn is_hook_result_consumed_as_query_envelope(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
) -> bool {
    let parent_id = semantic.nodes().parent_id(call_node_id);
    match semantic.nodes().kind(parent_id) {
        AstKind::StaticMemberExpression(mem) => {
            JOTAI_TQ_ENVELOPE_FIELDS.contains(&mem.property.name.as_str())
        }
        AstKind::VariableDeclarator(decl) => match &decl.id {
            BindingPattern::ObjectPattern(pat) => pat.properties.iter().any(|p| {
                p.key
                    .static_name()
                    .as_ref()
                    .and_then(|n| n.as_str())
                    .is_some_and(|k| JOTAI_TQ_ENVELOPE_FIELDS.contains(&k))
            }),
            BindingPattern::BindingIdentifier(id) => {
                let Some(sym_id) = id.symbol_id.get() else {
                    return false;
                };
                semantic.scoping().get_resolved_references(sym_id).any(|r| {
                    let p = semantic.nodes().parent_id(r.node_id());
                    matches!(
                        semantic.nodes().kind(p),
                        AstKind::StaticMemberExpression(m)
                            if JOTAI_TQ_ENVELOPE_FIELDS.contains(&m.property.name.as_str())
                    )
                })
            }
            _ => false,
        },
        _ => false,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates MobX CallExpression rules with precomputed subclass set"
)]
fn check_mobx_call_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subclassed_classes: &HashSet<String>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = callee_name(&call.callee);

    // 1. `mobx-reaction-disposer-discarded`
    if matches!(callee_name, Some("autorun" | "reaction"))
        && matches!(
            semantic.nodes().parent_kind(node_id),
            AstKind::ExpressionStatement(_)
        )
        && is_inside_use_effect(semantic, node_id)
    {
        let fn_name = callee_name.unwrap_or("reaction");
        sites.push(SemanticRuleSite {
            rule: RuleId::MobxReactionDisposerDiscarded,
            subject_name: subject_name.clone(),
            message_id: "mobxReactionDisposerDiscarded",
            target_name: fn_name.to_string(),
            message: format!(
                "`{fn_name}(...)` disposer is discarded inside `useEffect`; return the disposer so the MobX reaction is cleaned up."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `mobx-no-observer-wrapped-memo`
    if callee_name == Some("observer")
        && has_import_from(program, &["mobx-react", "mobx-react-lite"])
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && is_memo_or_observer_wrapped(semantic, first_arg)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::MobxNoObserverWrappedMemo,
            subject_name: subject_name.clone(),
            message_id: "mobxNoObserverWrappedMemo",
            target_name: "observer".to_string(),
            message: "`observer` cannot wrap an already memoized or observed component. Apply `observer` first, then place `memo` outside only if needed.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 3. `mobx-no-make-auto-observable-in-inheritance`
    if callee_name == Some("makeAutoObservable")
        && has_import_from(program, &["mobx"])
        && matches!(
            call.arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::without_parentheses),
            Some(Expression::ThisExpression(_))
        )
        && is_inside_inherited_or_subclassed_class(semantic, node_id, subclassed_classes)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::MobxNoMakeAutoObservableInInheritance,
            subject_name: subject_name.clone(),
            message_id: "mobxNoMakeAutoObservableInInheritance",
            target_name: "makeAutoObservable".to_string(),
            message: "MobX does not support `makeAutoObservable(this)` in inherited classes. Use composition or explicit `makeObservable` annotations.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn is_memo_or_observer_wrapped(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::CallExpression(c) => {
            matches!(callee_name(&c.callee), Some("memo" | "observer"))
        }
        Expression::Identifier(ident) => {
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
                && let Some(init) = &decl.init
            {
                return is_memo_or_observer_wrapped(semantic, init);
            }
            false
        }
        _ => false,
    }
}

fn is_inside_inherited_or_subclassed_class(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subclassed_classes: &HashSet<String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::Class(cls) = semantic.nodes().kind(anc_id) {
            let header =
                Span::new(cls.span.start, cls.body.span.start).source_text(semantic.source_text());
            if let Some(ext_idx) = header.find("extends ") {
                let after = header
                    .get(ext_idx + "extends ".len()..)
                    .unwrap_or_default()
                    .trim();
                if !after.starts_with("null") {
                    return true;
                }
            }
            if let Some(id) = &cls.id
                && subclassed_classes.contains(id.name.as_str())
            {
                return true;
            }
            return false;
        }
    }
    false
}

fn check_valtio_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if callee_name(&call.callee) != Some("useSnapshot") {
        return;
    }
    let Some(Argument::Identifier(proxy_ident)) = call.arguments.first() else {
        return;
    };
    let Some(enclosing_subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    let subj_span = semantic.nodes().get_node(enclosing_subj_id).span();

    check_valtio_proxy_read_in_render(
        semantic,
        proxy_ident,
        subj_span,
        subject_name,
        line_starts,
        sites,
    );
    check_valtio_snapshot_in_callback(
        semantic,
        node_id,
        subj_span,
        subject_name,
        line_starts,
        sites,
    );
}

fn check_valtio_proxy_read_in_render(
    semantic: &Semantic<'_>,
    proxy_ident: &oxc_ast::ast::IdentifierReference<'_>,
    subj_span: Span,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(proxy_ref_id) = proxy_ident.reference_id.get() else {
        return;
    };
    let Some(proxy_sym_id) = semantic.scoping().get_reference(proxy_ref_id).symbol_id() else {
        return;
    };
    for r in semantic.scoping().get_resolved_references(proxy_sym_id) {
        let ref_node_id = r.node_id();
        let ref_span = semantic.nodes().get_node(ref_node_id).span();
        if ref_span == proxy_ident.span || !subj_span.contains_inclusive(ref_span) {
            continue;
        }
        let p_id = semantic.nodes().parent_id(ref_node_id);
        let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(p_id) else {
            continue;
        };
        if is_direct_render_phase_node(semantic, ref_node_id) {
            sites.push(SemanticRuleSite {
                rule: RuleId::ValtioNoProxyReadInRender,
                subject_name: subject_name.clone(),
                message_id: "valtioNoProxyReadInRender",
                target_name: proxy_ident.name.to_string(),
                message: "Read this Valtio value from the useSnapshot result during render. Keep proxy reads for callbacks so render uses the tracked, consistent snapshot.".to_string(),
                loc: loc_from_line_starts(line_starts, mem.span.start),
                span: ByteSpan {
                    start: mem.span.start,
                    end: mem.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_valtio_snapshot_in_callback(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subj_span: Span,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id) else {
        return;
    };
    let mut snap_syms: Vec<SymbolId> = Vec::new();
    collect_pattern_symbols(&decl.id, &mut snap_syms);
    for snap_sym in snap_syms {
        for r in semantic.scoping().get_resolved_references(snap_sym) {
            let ref_node_id = r.node_id();
            let ref_span = semantic.nodes().get_node(ref_node_id).span();
            if !subj_span.contains_inclusive(ref_span) {
                continue;
            }
            if !is_direct_render_phase_node(semantic, ref_node_id) {
                sites.push(SemanticRuleSite {
                    rule: RuleId::ValtioNoSnapshotInCallback,
                    subject_name: subject_name.clone(),
                    message_id: "valtioNoSnapshotInCallback",
                    target_name: semantic.scoping().symbol_name(snap_sym).to_string(),
                    message: "Read or mutate the underlying Valtio proxy inside callbacks instead of reading a stale `useSnapshot` value.".to_string(),
                    loc: loc_from_line_starts(line_starts, ref_span.start),
                    span: ByteSpan {
                        start: ref_span.start,
                        end: ref_span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}

fn collect_pattern_symbols(pat: &BindingPattern<'_>, out: &mut Vec<SymbolId>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => {
            if let Some(s) = id.symbol_id.get() {
                out.push(s);
            }
        }
        BindingPattern::ObjectPattern(obj) => {
            for p in &obj.properties {
                collect_pattern_symbols(&p.value, out);
            }
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter().flatten() {
                collect_pattern_symbols(elem, out);
            }
        }
        BindingPattern::AssignmentPattern(a) => collect_pattern_symbols(&a.left, out),
    }
}
