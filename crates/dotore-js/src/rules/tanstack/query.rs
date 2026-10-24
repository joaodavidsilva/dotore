//! TanStack Query (`query-*`) hook, `QueryClient` lifecycle, destructuring, `queryFn`,
//! `refetch`, and `mutateAsync` rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, ObjectExpression,
        ObjectPropertyKind, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    ImportedBindingInfo, MUTATING_HTTP_METHODS, TANSTACK_MUTATION_HOOKS, TANSTACK_QUERY_HOOKS,
    extract_static_http_method, is_identifier_shadowed_by_local, is_inside_use_effect_execution,
    is_tanstack_observer_method_call, is_tanstack_query_source, resolve_const_initializer,
    resolve_tanstack_hook_call, router_and_invalidation::check_mutation_missing_invalidation,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name, is_use_effect_call},
        types::SemanticRuleSite,
    },
    matchers::{is_component_name, is_custom_hook_name, push_semantic_site, unwrap_expr},
    rules::RuleId,
};

pub(crate) fn check_stable_query_client(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    span: Span,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Exempt direct argument to `useState(new QueryClient())` or `useRef(new QueryClient())`
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::CallExpression(parent_call) = semantic.nodes().kind(parent_id)
        && let Expression::Identifier(callee_id) = parent_call.callee.without_parentheses()
        && matches!(callee_id.name.as_str(), "useState" | "useRef")
        && parent_call
            .arguments
            .iter()
            .any(|arg| arg.span().contains_inclusive(span))
    {
        return;
    }

    // Walk up to nearest enclosing function, skipping IIFEs
    let mut enclosing_fn_id = None;
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            let is_iife = semantic.nodes().ancestor_ids(anc_id).take(3).any(|p_id| {
                if let AstKind::CallExpression(c) = semantic.nodes().kind(p_id) {
                    c.callee
                        .span()
                        .contains_inclusive(semantic.nodes().get_node(anc_id).span())
                } else {
                    false
                }
            });
            if is_iife {
                continue;
            }
            enclosing_fn_id = Some(anc_id);
            break;
        }
    }

    let Some(fn_id) = enclosing_fn_id else {
        return;
    };
    let Some(fn_name) = get_subject_name(semantic, fn_id).or_else(|| {
        let p_id = semantic.nodes().parent_id(fn_id);
        get_subject_name(semantic, p_id)
    }) else {
        return;
    };

    if !is_component_name(&fn_name) {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::QueryStableQueryClient,
        subject_name.clone(),
        "queryStableQueryClient",
        "QueryClient",
        "new QueryClient() inside a component wipes your cache on every render.".to_string(),
        line_starts,
        span,
    );
}

pub(crate) fn check_query_rest_destructuring_and_spread(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(init) = &decl.init else {
        return;
    };

    // 1. `query-no-rest-destructuring`
    if let BindingPattern::ObjectPattern(obj_pat) = &decl.id
        && obj_pat.rest.is_some()
        && let Some((_, hook_name)) =
            resolve_tanstack_hook_call(semantic, init, imports, TANSTACK_QUERY_HOOKS, false)
    {
        push_semantic_site(
            sites,
            RuleId::QueryNoRestDestructuring,
            subject_name.clone(),
            "queryNoRestDestructuring",
            &hook_name,
            format!(
                "Rest-destructuring {hook_name}() subscribes to every field, so it re-renders on each change."
            ),
            line_starts,
            obj_pat.span,
        );
    }

    // 2. `query-destructure-result` (spreading a whole query result binding)
    if let BindingPattern::BindingIdentifier(bind_ident) = &decl.id
        && let Some(sym_id) = bind_ident.symbol_id.get()
        && let Expression::CallExpression(call) = init.without_parentheses()
        && let Expression::Identifier(callee_ident) = call.callee.without_parentheses()
        && TANSTACK_QUERY_HOOKS.contains(&callee_ident.name.as_str())
    {
        let callee_name = callee_ident.name.as_str();
        if let Some(imp) = imports.get(callee_name)
            && !is_tanstack_query_source(&imp.source)
        {
            return;
        }
        if is_identifier_shadowed_by_local(semantic, callee_ident) {
            return;
        }
        for reference in semantic.scoping().get_resolved_references(sym_id) {
            let ref_node_id = reference.node_id();
            let ref_span = semantic.nodes().get_node(ref_node_id).span();
            if is_enumerating_query_spread(semantic, ref_node_id) {
                push_semantic_site(
                    sites,
                    RuleId::QueryDestructureResult,
                    subject_name.clone(),
                    "queryDestructureResult",
                    callee_name,
                    format!(
                        "Spreading the whole {callee_name}() result reads every field, so TanStack Query subscribes to all of them and re-renders on each change. Spread only the fields you need."
                    ),
                    line_starts,
                    ref_span,
                );
            }
        }
    }
}

fn is_enumerating_query_spread(semantic: &Semantic<'_>, ref_node_id: NodeId) -> bool {
    let mut current_id = ref_node_id;
    for anc_id in semantic.nodes().ancestor_ids(ref_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSAsExpression(_)
            | AstKind::TSSatisfiesExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSTypeAssertion(_) => {
                current_id = anc_id;
            }
            AstKind::JSXSpreadAttribute(_) => return true,
            AstKind::SpreadElement(_) => {
                let obj_id = semantic.nodes().parent_id(anc_id);
                if matches!(semantic.nodes().kind(obj_id), AstKind::ObjectExpression(_)) {
                    return !is_hook_return_forwarding_spread(semantic, obj_id);
                }
                return false;
            }
            _ => {
                let _ = current_id;
                return false;
            }
        }
    }
    false
}

fn is_hook_return_forwarding_spread(semantic: &Semantic<'_>, obj_node_id: NodeId) -> bool {
    let parent_id = semantic.nodes().parent_id(obj_node_id);
    let is_returned = matches!(
        semantic.nodes().kind(parent_id),
        AstKind::ReturnStatement(_)
    ) || matches!(
        semantic.nodes().kind(parent_id),
        AstKind::ArrowFunctionExpression(arrow) if arrow.body.as_expression().is_some()
    );
    if !is_returned {
        return false;
    }
    find_enclosing_react_node(semantic, obj_node_id)
        .and_then(|subj_id| get_subject_name(semantic, subj_id))
        .is_some_and(|name| {
            is_custom_hook_name(&name)
                || (name.starts_with("use")
                    && name.chars().nth(3).is_some_and(|c| c.is_ascii_digit()))
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Passes pre-extracted module imports, file context, and line table without intermediate struct allocation"
)]
pub(crate) fn check_query_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    subject_name: &Option<String>,
    _is_routes_file: bool,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();

    // 1. `query-no-void-query-fn` & `query-no-use-query-for-mutation`
    if let Expression::Identifier(callee_ident) = call.callee.without_parentheses()
        && TANSTACK_QUERY_HOOKS.contains(&callee_ident.name.as_str())
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && let Expression::ObjectExpression(options_obj) = first_arg.without_parentheses()
    {
        check_void_query_fn_and_mutation_in_query(
            semantic,
            call,
            options_obj,
            subject_name,
            source,
            line_starts,
            sites,
        );
    }

    // 2. `query-no-query-in-effect`: `refetch()` or `query.refetch()` inside `useEffect`
    if is_inside_use_effect_execution(semantic, node_id)
        && is_tanstack_observer_method_call(
            semantic,
            call,
            imports,
            "refetch",
            TANSTACK_QUERY_HOOKS,
            true,
        )
    {
        push_semantic_site(
            sites,
            RuleId::QueryNoQueryInEffect,
            subject_name.clone(),
            "queryNoQueryInEffect",
            "refetch",
            "Calling refetch() inside useEffect triggers an extra network request after render; drive the query from its queryKey and enabled option instead.".to_string(),
            line_starts,
            call.span,
        );
    }

    // 3. `query-floating-mutate-async`
    if is_tanstack_observer_method_call(
        semantic,
        call,
        imports,
        "mutateAsync",
        TANSTACK_MUTATION_HOOKS,
        false,
    ) && is_floating_promise_call(semantic, node_id)
    {
        push_semantic_site(
            sites,
            RuleId::QueryFloatingMutateAsync,
            subject_name.clone(),
            "queryFloatingMutateAsync",
            "mutateAsync",
            "mutateAsync() returns a Promise that rejects on mutation failure; await it, attach .catch(), or use mutate() instead.".to_string(),
            line_starts,
            call.span,
        );
    }

    // 4. `query-mutation-missing-invalidation`
    check_mutation_missing_invalidation(
        semantic,
        node_id,
        call,
        imports,
        subject_name,
        line_starts,
        sites,
    );
}

fn check_void_query_fn_and_mutation_in_query(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let has_polling_interval = options_obj.properties.iter().any(|prop_kind| {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            return false;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("refetchInterval") {
            return false;
        }
        match prop.value.without_parentheses() {
            Expression::BooleanLiteral(b) => b.value,
            Expression::NumericLiteral(n) => n.value > 0.0,
            _ => true,
        }
    });

    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("queryFn") {
            continue;
        };
        let val = prop.value.without_parentheses();
        let body_opt = match val {
            Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
                ArrowFunctionBody::FunctionBody(b) => Some(b),
                _ => None,
            },
            Expression::FunctionExpression(func) => func.body.as_ref(),
            _ => None,
        };

        if let Some(body) = body_opt {
            let non_noop_stmts: Vec<_> = body
                .statements
                .iter()
                .filter(|s| {
                    !matches!(
                        s,
                        Statement::EmptyStatement(_) | Statement::DebuggerStatement(_)
                    )
                })
                .collect();
            let has_return = body.span.source_text(source).contains("return ");
            if non_noop_stmts.is_empty() || !has_return {
                push_semantic_site(
                    sites,
                    RuleId::QueryNoVoidQueryFn,
                    subject_name.clone(),
                    "noVoidQueryFn",
                    "useQuery",
                    "This empty queryFn caches undefined, so the component never gets data."
                        .to_string(),
                    line_starts,
                    prop.span,
                );
            }
        }

        if !has_polling_interval
            && let Some(method) = find_mutating_http_in_query_fn(semantic, prop.value.span())
        {
            push_semantic_site(
                sites,
                RuleId::QueryNoUseQueryForMutation,
                subject_name.clone(),
                "queryNoUseQueryForMutation",
                &method,
                format!(
                    "useQuery with {method} request acts like a mutation; use useMutation so TanStack Query does not auto-retry or background-refetch it."
                ),
                line_starts,
                call.span,
            );
        }
    }
}

fn find_mutating_http_in_query_fn(semantic: &Semantic<'_>, query_fn_span: Span) -> Option<String> {
    let source = semantic.source_text();
    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !query_fn_span.contains_inclusive(call.span) {
            continue;
        }
        // Check `fetch(url, { method: "DELETE" | "POST" | "PUT" | "PATCH" })`
        if let Expression::Identifier(id) = call.callee.without_parentheses()
            && id.name == "fetch"
        {
            let url_arg = call.arguments.first().and_then(Argument::as_expression);
            let Some(opts_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
                continue;
            };
            let Expression::ObjectExpression(opts_obj) = opts_arg.without_parentheses() else {
                continue;
            };
            let Some(method) = extract_static_http_method(opts_obj) else {
                continue;
            };
            if !MUTATING_HTTP_METHODS.contains(&method.as_str()) {
                continue;
            }
            let url_text = url_arg
                .and_then(|u| resolve_static_url_text(semantic, u))
                .unwrap_or_default();

            if method == "POST" {
                if is_graphql_url_segment(&url_text) && !has_graphql_mutation_body(opts_obj, source)
                {
                    continue;
                }
                if is_read_named_rpc_url(&url_text) {
                    continue;
                }
            }
            return Some(method);
        }

        // Also check `axios.post(...)`, `api.delete(...)`, etc.
        if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
            let prop_upper = mem.property.name.to_ascii_uppercase();
            if matches!(prop_upper.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
                && let Expression::Identifier(recv) = mem.object.without_parentheses()
                && matches!(recv.name.as_str(), "axios" | "http" | "client" | "ky")
            {
                return Some(prop_upper);
            }
        }
    }
    None
}

fn resolve_static_url_text(semantic: &Semantic<'_>, url_expr: &Expression<'_>) -> Option<String> {
    match unwrap_expr(url_expr) {
        Expression::StringLiteral(s) => s.value.as_str().map(str::to_string),
        Expression::TemplateLiteral(tpl) => {
            let joined: String = tpl
                .quasis
                .iter()
                .map(|q| q.value.raw.as_str())
                .collect::<Vec<_>>()
                .join("");
            Some(joined)
        }
        Expression::Identifier(ident) => {
            let init = resolve_const_initializer(semantic, ident)?;
            resolve_static_url_text(semantic, init)
        }
        _ => None,
    }
}

fn is_graphql_url_segment(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    for (idx, _) in lower.match_indices("graphql") {
        let before_ok = idx == 0 || lower.as_bytes().get(idx - 1) == Some(&b'/');
        let after_idx = idx + "graphql".len();
        let after_ok = after_idx == lower.len()
            || matches!(lower.as_bytes().get(after_idx), Some(b'/' | b'?' | b'#'));
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn is_read_named_rpc_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    for segment in lower.split(['/', '?', '#']) {
        if segment.is_empty() {
            continue;
        }
        for prefix in ["get", "list", "search", "query", "quote"] {
            if segment == prefix
                || segment
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(['-', '_', '.']))
            {
                return true;
            }
        }
    }
    false
}

fn has_graphql_mutation_body(opts_obj: &ObjectExpression<'_>, source: &str) -> bool {
    for prop_kind in &opts_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("body") {
            continue;
        };
        let body_text = prop.value.span().source_text(source);
        if body_text.contains("mutation ") || body_text.contains("mutation{") {
            return true;
        }
    }
    false
}

fn is_floating_promise_call(semantic: &Semantic<'_>, call_node_id: NodeId) -> bool {
    let mut current_id = call_node_id;
    for anc_id in semantic.nodes().ancestor_ids(call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSAsExpression(_)
            | AstKind::TSSatisfiesExpression(_)
            | AstKind::TSNonNullExpression(_) => {
                current_id = anc_id;
            }
            AstKind::ExpressionStatement(_) => return true,
            AstKind::UnaryExpression(un) if un.operator.as_str() == "void" => return true,
            AstKind::ArrowFunctionExpression(arrow) if arrow.body.as_expression().is_some() => {
                // Concise arrow `() => mutateAsync(...)`: floating if the arrow is an event handler or effect callback
                let p_id = semantic.nodes().parent_id(anc_id);
                if matches!(
                    semantic.nodes().kind(p_id),
                    AstKind::JSXExpressionContainer(_)
                ) {
                    return true;
                }
                if let AstKind::CallExpression(parent_call) = semantic.nodes().kind(p_id)
                    && is_use_effect_call(semantic, parent_call)
                {
                    return true;
                }
                return false;
            }
            AstKind::StaticMemberExpression(mem) => {
                if matches!(mem.property.name.as_str(), "catch" | "then") {
                    return false;
                }
                if mem.property.name == "finally" {
                    let grand_id = semantic.nodes().parent_id(anc_id);
                    if matches!(semantic.nodes().kind(grand_id), AstKind::CallExpression(_)) {
                        return is_floating_promise_call(semantic, grand_id);
                    }
                }
                return false;
            }
            AstKind::AwaitExpression(_)
            | AstKind::ReturnStatement(_)
            | AstKind::VariableDeclarator(_) => return false,
            _ => {
                let _ = current_id;
                return false;
            }
        }
    }
    false
}
