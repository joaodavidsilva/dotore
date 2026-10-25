//! React Router v7/v8 navigation, `<Link>`, `<a>`, `useSearchParams`, `useBlocker`,
//! `startTransition`, and nested/client-only component rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, ArrowFunctionBody, BindingPattern, CallExpression, Expression,
        JSXChild, JSXElement, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    DATA_ROUTER_FACTORIES, RESOURCE_EXTENSIONS, ROUTER_JSX_COMPONENTS, get_jsx_attr_static_str,
    get_object_prop, get_object_prop_static_str, has_jsx_attr, has_jsx_truthy_attr,
    jsx_element_tag_name,
    loaders_and_actions::{
        check_redirect_in_try_catch, check_static_cookie_expires, check_use_loader_data_in_error_ui,
    },
    push_site,
    routes_and_middleware::{
        check_jsx_route_element_recursive, check_route_object_recursive,
        jsx_route_subtree_has_loader_or_action, route_object_has_error_boundary,
    },
};
use crate::{
    ir::{
        react_ast::{
            callee_name, find_enclosing_react_node, get_subject_name, is_direct_render_phase_node,
        },
        types::SemanticRuleSite,
    },
    matchers::is_named_hook_call,
    rules::RuleId,
};

#[expect(
    clippy::too_many_arguments,
    reason = "single-pass call dispatcher shares precomputed component sets and state maps (#50)"
)]
pub(crate) fn check_call_expression_rules(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    blocker_calls_by_subject: &mut HashMap<NodeId, Vec<(Span, Option<String>)>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(callee_name) = callee_name(&call.callee) else {
        return;
    };

    if DATA_ROUTER_FACTORIES.contains(&callee_name) {
        check_data_router_factory_call(
            node_id,
            call,
            callee_name,
            semantic,
            source,
            line_starts,
            components_with_routes,
            components_with_outlet,
            sites,
        );
    }

    if callee_name == "createCookie" || callee_name == "createCookieSessionStorage" {
        check_static_cookie_expires(node_id, call, callee_name, semantic, line_starts, sites);
    }

    if (callee_name == "useBlocker" || callee_name == "unstable_useBlocker")
        && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
    {
        let subject_name = get_subject_name(semantic, subj_id);
        blocker_calls_by_subject
            .entry(subj_id)
            .or_default()
            .push((call.span, subject_name));
    }

    if callee_name == "useLoaderData" {
        check_use_loader_data_in_error_ui(node_id, call, semantic, line_starts, sites);
    }

    if callee_name == "redirect" || callee_name == "redirectDocument" {
        check_redirect_in_try_catch(
            node_id,
            call,
            callee_name,
            semantic,
            source,
            line_starts,
            sites,
        );
    }

    if callee_name == "navigate"
        && is_direct_render_phase_node(semantic, node_id)
        && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
    {
        let subject_name = get_subject_name(semantic, subj_id);
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoNavigateInRender,
            subject_name,
            "reactRouterNoNavigateInRender",
            "navigate",
            "Do not call `navigate()` synchronously during render; render `<Navigate />` or trigger navigation from an event handler or effect.",
            call.span,
            None,
        );
    }

    if callee_name == "startTransition" {
        check_transition_navigation_promise(node_id, call, semantic, line_starts, sites);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Data router factory inspector validates render placement and route tree together (#50)"
)]
fn check_data_router_factory_call(
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_name: &str,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_direct_render_phase_node(semantic, node_id)
        && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
    {
        let subject_name = get_subject_name(semantic, subj_id);
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoRouterInRender,
            subject_name,
            "reactRouterNoRouterInRender",
            callee_name,
            "Do not create a router instance during render; hoist router creation to module scope so navigation state survives re-renders.",
            call.span,
            None,
        );
    }

    let Some(first_arg) = call.arguments.first() else {
        return;
    };
    let Some(expr) = first_arg.as_expression() else {
        return;
    };
    let Expression::ArrayExpression(arr) = expr.without_parentheses() else {
        return;
    };

    let mut seen_ids = HashSet::new();
    for (idx, elem) in arr.elements.iter().enumerate() {
        let ArrayExpressionElement::ObjectExpression(route_obj) = elem else {
            continue;
        };
        if idx == 0 && !route_object_has_error_boundary(route_obj) {
            let has_children = get_object_prop(route_obj, "children").is_some();
            let is_root_path = get_object_prop_static_str(route_obj, "path")
                .is_some_and(|p| p == "/" || p.is_empty());
            if has_children || is_root_path {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterRequireRootErrorBoundary,
                    None,
                    "reactRouterRequireRootErrorBoundary",
                    callee_name,
                    "Root route is missing `ErrorBoundary` or `errorElement`; define a root error boundary so unhandled route errors have a fallback UI.",
                    route_obj.span,
                    None,
                );
            }
        }
        check_route_object_recursive(
            route_obj,
            None,
            semantic,
            source,
            line_starts,
            components_with_routes,
            components_with_outlet,
            &mut seen_ids,
            sites,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "single-pass JSX element rule check receives precomputed sets (#50)"
)]
pub(crate) fn check_jsx_element_rules(
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    client_imported_symbols: &HashSet<String>,
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let Some(tag) = jsx_element_tag_name(&opening.name) else {
        return;
    };
    let subject_name = find_enclosing_react_node(semantic, node_id)
        .and_then(|subj_id| get_subject_name(semantic, subj_id));

    if tag == "Routes" {
        check_jsx_routes_container(
            jsx_el,
            semantic,
            line_starts,
            components_with_routes,
            components_with_outlet,
            sites,
        );
    }

    if ROUTER_JSX_COMPONENTS.contains(&tag.as_str())
        && has_ancestor_router_jsx_component(semantic, node_id)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoNestedRouter,
            subject_name.clone(),
            "reactRouterNoNestedRouter",
            &tag,
            &format!(
                "`<{tag}>` is nested inside another router component; keep a single router provider at the application root."
            ),
            opening.span,
            None,
        );
    }

    if client_imported_symbols.contains(&tag) && !is_inside_client_only_boundary(semantic, node_id)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoClientModuleInServerRender,
            subject_name.clone(),
            "reactRouterNoClientModuleInServerRender",
            &tag,
            &format!(
                "Client-only component `<{tag}>` (imported from a `.client` module) cannot be rendered directly on the server; wrap it in a `<ClientOnly>` or hydration boundary."
            ),
            opening.span,
            None,
        );
    }

    check_jsx_link_and_anchor_rules(program, opening, &tag, subject_name, line_starts, sites);
}

fn check_jsx_routes_container(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen_ids = HashSet::new();
    let mut root_route_checked = false;
    for child in &jsx_el.children {
        let JSXChild::Element(child_el) = child else {
            continue;
        };
        if jsx_element_tag_name(&child_el.opening_element.name).as_deref() == Some("Route")
            && !root_route_checked
        {
            root_route_checked = true;
            let child_opening = &child_el.opening_element;
            let has_err = has_jsx_attr(child_opening, "errorElement")
                || has_jsx_attr(child_opening, "ErrorBoundary");
            if !has_err && jsx_route_subtree_has_loader_or_action(child_el) {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterRequireRootErrorBoundary,
                    None,
                    "reactRouterRequireRootErrorBoundary",
                    "Route",
                    "Root `<Route>` is missing `ErrorBoundary` or `errorElement`; define a root error boundary so unhandled loader or action errors have a fallback UI.",
                    child_opening.span,
                    None,
                );
            }
        }
        check_jsx_route_element_recursive(
            child_el,
            None,
            semantic,
            line_starts,
            components_with_routes,
            components_with_outlet,
            &mut seen_ids,
            sites,
        );
    }
}

fn has_ancestor_router_jsx_component(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        if let AstKind::JSXElement(anc_jsx) = semantic.nodes().kind(anc_id)
            && let Some(anc_tag) = jsx_element_tag_name(&anc_jsx.opening_element.name)
        {
            ROUTER_JSX_COMPONENTS.contains(&anc_tag.as_str())
        } else {
            false
        }
    })
}

fn check_jsx_link_and_anchor_rules(
    program: &Program<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    tag: &str,
    subject_name: Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if tag == "a"
        && file_uses_react_router(program)
        && let Some((href_val, _)) = get_jsx_attr_static_str(opening, "href")
        && is_internal_route_href(&href_val)
        && !has_jsx_attr(opening, "download")
        && !has_jsx_attr(opening, "reloadDocument")
        && get_jsx_attr_static_str(opening, "target").is_none_or(|(t, _)| t != "_blank")
        && !has_resource_extension(&href_val)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterInternalRouteAnchor,
            subject_name,
            "reactRouterInternalRouteAnchor",
            "a",
            &format!(
                "Anchor `<a href=\"{href_val}\">` triggers a full document reload for an internal route; use `<Link to=\"{href_val}\">` instead."
            ),
            opening.span,
            None,
        );
        return;
    }

    if (tag == "Link" || tag == "NavLink")
        && let Some((to_val, _)) = get_jsx_attr_static_str(opening, "to")
        && has_resource_extension(&to_val)
        && !has_jsx_truthy_attr(opening, "reloadDocument")
        && !has_jsx_attr(opening, "download")
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterResourceLinkRequiresReload,
            subject_name,
            "reactRouterResourceLinkRequiresReload",
            tag,
            &format!(
                "`<{tag} to=\"{to_val}\">` points to a static/resource asset without `reloadDocument`; add `reloadDocument` so the browser loads the resource directly."
            ),
            opening.span,
            None,
        );
    }
}

/// Checks `react-router-return-navigation-promise-in-transition`.
pub(crate) fn check_transition_navigation_promise(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first() else {
        return;
    };
    let Some(expr) = first_arg.as_expression() else {
        return;
    };
    let statements: &[Statement<'_>] = match expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => {
            if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                &body.statements
            } else {
                return; // concise expression body implicitly returns the promise
            }
        }
        Expression::FunctionExpression(func) => {
            if let Some(body) = &func.body {
                &body.statements
            } else {
                return;
            }
        }
        _ => return,
    };

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));

    for stmt in statements {
        if let Statement::ExpressionStatement(expr_stmt) = stmt
            && let Expression::CallExpression(inner_call) =
                expr_stmt.expression.without_parentheses()
            && let Some(name) = callee_name(&inner_call.callee)
            && (name == "navigate" || name == "revalidate" || name == "submit")
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterReturnNavigationPromiseInTransition,
                subject_name.clone(),
                "reactRouterReturnNavigationPromiseInTransition",
                name,
                &format!(
                    "`{name}()` inside `startTransition` is not returned or awaited, so transition pending state ends before navigation completes."
                ),
                inner_call.span,
                None,
            );
        }
    }
}

/// Checks `react-router-no-multiple-set-search-params-in-tick` and
/// `react-router-no-unsynchronized-search-params-mutation`.
pub(crate) fn check_search_params_in_statements(
    fn_node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let (search_params_vars, set_search_params_vars) = collect_search_params_bindings(statements);
    if search_params_vars.is_empty() && set_search_params_vars.is_empty() {
        return;
    }

    let subject_name = find_enclosing_react_node(semantic, fn_node_id)
        .and_then(|id| get_subject_name(semantic, id));
    let fn_span = semantic.nodes().get_node(fn_node_id).span();

    if !search_params_vars.is_empty() {
        check_unsynchronized_search_params_mutations(
            semantic,
            fn_span,
            &search_params_vars,
            &set_search_params_vars,
            &subject_name,
            source,
            line_starts,
            sites,
        );
    }

    if !set_search_params_vars.is_empty() {
        check_multiple_set_search_params_in_tick(
            semantic,
            fn_span,
            &set_search_params_vars,
            &subject_name,
            line_starts,
            sites,
        );
    }
}

fn collect_search_params_bindings(statements: &[Statement<'_>]) -> (Vec<String>, Vec<String>) {
    let mut search_params_vars = Vec::new();
    let mut set_search_params_vars = Vec::new();

    for stmt in statements {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        for decl in &var_decl.declarations {
            let Some(init) = &decl.init else {
                continue;
            };
            let Expression::CallExpression(call) = init.without_parentheses() else {
                continue;
            };
            if !is_named_hook_call(call, "useSearchParams") {
                continue;
            }
            if let BindingPattern::ArrayPattern(arr_pat) = &decl.id {
                if let Some(Some(first)) = arr_pat.elements.first()
                    && let Some(id) = first.get_binding_identifier()
                {
                    search_params_vars.push(id.name.to_string());
                }
                if let Some(Some(second)) = arr_pat.elements.get(1)
                    && let Some(id) = second.get_binding_identifier()
                {
                    set_search_params_vars.push(id.name.to_string());
                }
            }
        }
    }
    (search_params_vars, set_search_params_vars)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks in-place URLSearchParams mutations against setter calls in the enclosing function (#50)"
)]
fn check_unsynchronized_search_params_mutations(
    semantic: &Semantic<'_>,
    fn_span: Span,
    search_params_vars: &[String],
    set_search_params_vars: &[String],
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let sp_refs: Vec<&str> = search_params_vars.iter().map(String::as_str).collect();
    let fn_src = fn_span.source_text(source);

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::CallExpression(call) = node.kind()
            && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
            && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
            && sp_refs.contains(&obj_id.name.as_str())
            && matches!(
                mem.property.name.as_str(),
                "set" | "append" | "delete" | "sort"
            )
        {
            let passed_to_setter = set_search_params_vars
                .iter()
                .any(|setter| fn_src.contains(&format!("{setter}({})", obj_id.name)));
            if !passed_to_setter {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoUnsynchronizedSearchParamsMutation,
                    subject_name.clone(),
                    "reactRouterNoUnsynchronizedSearchParamsMutation",
                    &format!("{}.{}", obj_id.name, mem.property.name),
                    &format!(
                        "Mutating `{}.{}(...)` in place does not trigger navigation or re-render; clone `URLSearchParams` and pass it to `setSearchParams`.",
                        obj_id.name, mem.property.name
                    ),
                    call.span,
                    None,
                );
            }
        }
    }
}

fn check_multiple_set_search_params_in_tick(
    semantic: &Semantic<'_>,
    fn_span: Span,
    set_search_params_vars: &[String],
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        let stmts: &[Statement<'_>] = match node.kind() {
            AstKind::FunctionBody(body) => &body.statements,
            AstKind::BlockStatement(block) => &block.body,
            _ => continue,
        };
        let setter_calls = collect_direct_setter_calls_in_block(stmts, set_search_params_vars);
        for (setter_name, span) in setter_calls.into_iter().skip(1) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoMultipleSetSearchParamsInTick,
                subject_name.clone(),
                "reactRouterNoMultipleSetSearchParamsInTick",
                setter_name,
                &format!(
                    "Calling `{setter_name}()` multiple times in the same tick overwrites earlier updates; combine search param changes into a single `{setter_name}()` call."
                ),
                span,
                None,
            );
        }
    }
}

fn collect_direct_setter_calls_in_block<'a>(
    stmts: &'a [Statement<'a>],
    set_search_params_vars: &[String],
) -> Vec<(&'a str, Span)> {
    let mut setter_calls = Vec::new();
    for stmt in stmts {
        if let Statement::ExpressionStatement(expr_stmt) = stmt
            && let Expression::CallExpression(call) = expr_stmt.expression.without_parentheses()
            && let Expression::Identifier(callee_id) = call.callee.without_parentheses()
            && set_search_params_vars
                .iter()
                .any(|s| s == callee_id.name.as_str())
        {
            setter_calls.push((callee_id.name.as_str(), call.span));
        }
    }
    setter_calls
}

fn is_inside_client_only_boundary(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::JSXElement(anc_jsx) => {
                if let Some(tag) = jsx_element_tag_name(&anc_jsx.opening_element.name)
                    && (tag == "ClientOnly" || tag == "Hydrated" || tag == "Suspense")
                {
                    return true;
                }
            }
            AstKind::CallExpression(call) if is_named_hook_call(call, "useEffect") => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn file_uses_react_router(program: &Program<'_>) -> bool {
    for stmt in &program.body {
        if let Statement::ImportDeclaration(imp) = stmt {
            let Some(src) = imp.source.value.as_str() else {
                continue;
            };
            if src == "react-router"
                || src == "react-router-dom"
                || src.starts_with("@react-router/")
                || src.starts_with("react-router/")
            {
                return true;
            }
        }
    }
    false
}

fn is_internal_route_href(href: &str) -> bool {
    href.starts_with('/') && !href.starts_with("//")
}

fn has_resource_extension(url: &str) -> bool {
    let path_part = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    RESOURCE_EXTENSIONS
        .iter()
        .any(|ext| path_part.ends_with(ext))
}
