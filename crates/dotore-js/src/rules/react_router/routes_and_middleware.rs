//! React Router v7/v8 route tree, `<Route>`, lazy routes, middleware,
//! module environment suffix, and v8 migration rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, ArrowFunctionBody, Expression, FormalParameters, JSXAttributeItem,
        JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement, JSXOpeningElement,
        ObjectExpression, ObjectPropertyKind, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    IMMUTABLE_ROUTE_PROPERTIES, REMOVED_V8_FUTURE_FLAGS, expr_calls_function,
    extract_component_ref_name, find_member_calls_in_statements, get_jsx_attr_expr,
    get_jsx_attr_static_str, get_object_prop, get_object_prop_bool,
    get_object_prop_static_str_with_span, has_jsx_attr, has_jsx_truthy_attr,
    is_component_defined_in_file, jsx_element_tag_name, jsx_subtree_contains_outlet,
    loaders_and_actions::check_inline_route_handler_expr, push_site,
};
use crate::{
    ir::{
        ByteSpan,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::is_named_hook_call,
    rules::{AutofixPatch, RuleId},
};

/// Checks `react-router-no-route-module-environment-suffix`.
pub(crate) fn check_route_module_environment_suffix(
    path: &Path,
    program: &Program<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let is_route_file = path_str.contains("/routes/") || path_str.starts_with("routes/");
    if !is_route_file {
        return;
    }
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let has_env_suffix = file_name.contains(".server.") || file_name.contains(".client.");
    if !has_env_suffix {
        return;
    }
    let span = program.body.first().map_or(program.span, GetSpan::span);
    push_site(
        sites,
        line_starts,
        RuleId::ReactRouterNoRouteModuleEnvironmentSuffix,
        None,
        "reactRouterNoRouteModuleEnvironmentSuffix",
        file_name,
        "Route modules cannot use `.server` or `.client` file suffixes; keep the route module environment-neutral and move environment-specific logic to imported modules.",
        span,
        None,
    );
}

/// Checks `react-router-v8-no-react-router-dom-import` and collects `.client` imported identifiers.
pub(crate) fn check_imports_and_collect_client_symbols(
    program: &Program<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) -> HashSet<String> {
    let mut client_symbols = HashSet::new();

    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        let Some(spec) = imp.source.value.as_str() else {
            continue;
        };
        if spec == "react-router-dom" || spec.starts_with("react-router-dom/") {
            let raw_lit = imp.source.span.source_text(source);
            let quote = if raw_lit.starts_with('\'') { '\'' } else { '"' };
            let new_spec = if spec == "react-router-dom" {
                "react-router".to_string()
            } else {
                spec.replacen("react-router-dom/", "react-router/", 1)
            };
            let replacement = format!("{quote}{new_spec}{quote}");
            let autofix = Some(AutofixPatch::replace(
                format!("Replace `{spec}` import with `{new_spec}`"),
                ByteSpan {
                    start: imp.source.span.start,
                    end: imp.source.span.end,
                },
                replacement,
            ));
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterV8NoReactRouterDomImport,
                None,
                "reactRouterV8NoReactRouterDomImport",
                spec,
                "`react-router-dom` is removed in React Router v8; import from `react-router` instead.",
                imp.source.span,
                autofix,
            );
        }

        if is_client_module_specifier(spec)
            && let Some(specifiers) = &imp.specifiers
        {
            for s in specifiers {
                client_symbols.insert(s.local().name.to_string());
            }
        }
    }

    client_symbols
}

fn is_client_module_specifier(spec: &str) -> bool {
    spec.ends_with(".client") || spec.contains(".client.") || spec.ends_with("/client")
}

/// Collects **Subjects** in the file that render `<Routes>` or `<Outlet>` / `useOutlet`.
pub(crate) fn collect_subject_router_traits(
    semantic: &Semantic<'_>,
) -> (HashSet<String>, HashSet<String>) {
    let mut with_routes = HashSet::new();
    let mut with_outlet = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::JSXOpeningElement(opening) => {
                let Some(tag) = jsx_element_tag_name(&opening.name) else {
                    continue;
                };
                if tag == "Routes" {
                    if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
                        && let Some(name) = get_subject_name(semantic, subj_id)
                    {
                        with_routes.insert(name);
                    }
                } else if tag == "Outlet"
                    && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
                    && let Some(name) = get_subject_name(semantic, subj_id)
                {
                    with_outlet.insert(name);
                }
            }
            AstKind::CallExpression(call) => {
                if is_named_hook_call(call, "useOutlet")
                    && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
                    && let Some(name) = get_subject_name(semantic, subj_id)
                {
                    with_outlet.insert(name);
                }
            }
            _ => {}
        }
    }

    (with_routes, with_outlet)
}

#[expect(
    clippy::too_many_arguments,
    reason = "recursive route object validator carries parent path and precomputed component traits"
)]
pub(crate) fn check_route_object_recursive(
    route_obj: &ObjectExpression<'_>,
    parent_path: Option<&str>,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    seen_ids: &mut HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let id_prop = get_object_prop_static_str_with_span(route_obj, "id");
    let path_prop = get_object_prop_static_str_with_span(route_obj, "path");
    let is_index = get_object_prop_bool(route_obj, "index").unwrap_or(false);
    let children_prop = get_object_prop(route_obj, "children");
    let lazy_prop = get_object_prop(route_obj, "lazy");
    let component_prop = get_object_prop(route_obj, "Component");
    let element_prop = get_object_prop(route_obj, "element");
    let loader_prop = get_object_prop(route_obj, "loader");
    let action_prop = get_object_prop(route_obj, "action");
    let client_loader_prop = get_object_prop(route_obj, "clientLoader");
    let client_action_prop = get_object_prop(route_obj, "clientAction");

    // 1. `react-router-no-duplicate-route-id`
    if let Some((route_id, span)) = id_prop
        && !seen_ids.insert(route_id.clone())
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoDuplicateRouteId,
            None,
            "reactRouterNoDuplicateRouteId",
            &route_id,
            &format!(
                "Duplicate route id `{route_id}`; every route `id` must be unique within the router."
            ),
            span,
            None,
        );
    }

    // 2. `react-router-no-invalid-splat-path`
    if let Some((path_val, path_span)) = &path_prop
        && is_invalid_splat_path(path_val)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoInvalidSplatPath,
            None,
            "reactRouterNoInvalidSplatPath",
            path_val,
            &format!(
                "Invalid splat route path `{path_val}`; `*` may only appear as `*` or at the end of a path as `/*`."
            ),
            *path_span,
            None,
        );
    }

    // 3. `react-router-no-invalid-absolute-child-path`
    if let Some(p_path) = parent_path
        && let Some((child_path, child_span)) = &path_prop
        && child_path.starts_with('/')
    {
        let norm_parent = p_path.trim_end_matches("/*").trim_end_matches('/');
        if !norm_parent.is_empty()
            && child_path != norm_parent
            && !child_path.starts_with(&format!("{norm_parent}/"))
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoInvalidAbsoluteChildPath,
                None,
                "reactRouterNoInvalidAbsoluteChildPath",
                child_path,
                &format!(
                    "Absolute child route path `{child_path}` does not start with parent path `{norm_parent}`."
                ),
                *child_span,
                None,
            );
        }
    }

    // 4. `react-router-valid-route-object`
    let has_both_comp_and_element = component_prop.is_some() && element_prop.is_some();
    let index_with_children = is_index && children_prop.is_some();
    let index_with_non_empty_path =
        is_index && path_prop.as_ref().is_some_and(|(p, _)| !p.is_empty());
    if has_both_comp_and_element || index_with_children || index_with_non_empty_path {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterValidRouteObject,
            None,
            "reactRouterValidRouteObject",
            "route",
            "Route object contains contradictory properties (such as `index: true` with `children` or `path`, or both `Component` and `element`).",
            route_obj.span,
            None,
        );
    }

    // 5. `react-router-no-invalid-lazy-route-properties`
    if let Some((_lazy_span, lazy_expr)) = lazy_prop {
        check_lazy_route_expression(lazy_expr, line_starts, sites);
    }

    // Extract rendered component name if any
    let rendered_component = component_prop
        .and_then(|(_, expr)| extract_component_ref_name(expr))
        .or_else(|| element_prop.and_then(|(_, expr)| extract_component_ref_name(expr)));

    // 6. `react-router-descendant-routes-require-splat`
    if let Some(comp_name) = &rendered_component
        && components_with_routes.contains(comp_name)
        && let Some((path_val, path_span)) = &path_prop
        && path_val != "*"
        && !path_val.ends_with("/*")
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterDescendantRoutesRequireSplat,
            Some(comp_name.clone()),
            "reactRouterDescendantRoutesRequireSplat",
            path_val,
            &format!(
                "Route `{path_val}` renders `{comp_name}` which contains descendant `<Routes>`, so its path must end with `/*`."
            ),
            *path_span,
            None,
        );
    }

    let has_non_empty_children = children_prop.is_some_and(|(_, expr)| {
        if let Expression::ArrayExpression(arr) = expr.without_parentheses() {
            !arr.elements.is_empty()
        } else {
            true
        }
    });

    // 7. `react-router-nested-route-requires-outlet`
    if has_non_empty_children {
        if let Some(comp_name) = &rendered_component
            && !components_with_outlet.contains(comp_name)
            && is_component_defined_in_file(semantic, comp_name)
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNestedRouteRequiresOutlet,
                Some(comp_name.clone()),
                "reactRouterNestedRouteRequiresOutlet",
                comp_name,
                &format!(
                    "Parent route component `{comp_name}` has child routes but does not render `<Outlet />`."
                ),
                route_obj.span,
                None,
            );
        } else if let Some((_, expr)) = element_prop
            && let Expression::JSXElement(inline_jsx) = expr.without_parentheses()
            && let Some(tag) = jsx_element_tag_name(&inline_jsx.opening_element.name)
            && tag.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && !jsx_subtree_contains_outlet(inline_jsx)
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNestedRouteRequiresOutlet,
                None,
                "reactRouterNestedRouteRequiresOutlet",
                &tag,
                "Parent route `element` has child routes but does not render `<Outlet />`.",
                inline_jsx.span,
                None,
            );
        }
    }

    // 8. `react-router-no-empty-leaf-route`
    if !has_non_empty_children
        && component_prop.is_none()
        && element_prop.is_none()
        && lazy_prop.is_none()
        && loader_prop.is_none()
        && action_prop.is_none()
        && client_loader_prop.is_none()
        && client_action_prop.is_none()
        && (path_prop.is_some() || is_index)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoEmptyLeafRoute,
            None,
            "reactRouterNoEmptyLeafRoute",
            "route",
            "Leaf route has no `Component`, `element`, `lazy`, `loader`, `action`, or `children` and will render nothing.",
            route_obj.span,
            None,
        );
    }

    // Check inline loader/action/middleware properties on route object
    for (prop_key, role_name) in [
        ("loader", "loader"),
        ("clientLoader", "clientLoader"),
        ("action", "action"),
        ("clientAction", "clientAction"),
    ] {
        if let Some((_, expr)) = get_object_prop(route_obj, prop_key) {
            check_inline_route_handler_expr(expr, role_name, source, line_starts, sites);
        }
    }

    // Recurse into children
    let effective_parent_path = path_prop.as_ref().map(|(p, _)| p.as_str()).or(parent_path);
    if let Some((_, expr)) = children_prop
        && let Expression::ArrayExpression(arr) = expr.without_parentheses()
    {
        for elem in &arr.elements {
            if let ArrayExpressionElement::ObjectExpression(child_obj) = elem {
                check_route_object_recursive(
                    child_obj,
                    effective_parent_path,
                    semantic,
                    source,
                    line_starts,
                    components_with_routes,
                    components_with_outlet,
                    seen_ids,
                    sites,
                );
            }
        }
    }
}

pub(crate) fn check_lazy_route_expression(
    lazy_expr: &Expression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match lazy_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                if let Expression::ObjectExpression(obj) = expr.without_parentheses() {
                    check_lazy_returned_object(obj, line_starts, sites);
                }
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                        && let Expression::ObjectExpression(obj) = arg.without_parentheses()
                    {
                        check_lazy_returned_object(obj, line_starts, sites);
                    }
                }
            }
        }
        Expression::FunctionExpression(func) => {
            if let Some(body) = &func.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                        && let Expression::ObjectExpression(obj) = arg.without_parentheses()
                    {
                        check_lazy_returned_object(obj, line_starts, sites);
                    }
                }
            }
        }
        _ => {}
    }
}

fn check_lazy_returned_object(
    obj: &ObjectExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let Some(key_name) = prop.key.static_name() else {
            continue;
        };
        let Some(key_str) = key_name.as_str() else {
            continue;
        };
        if IMMUTABLE_ROUTE_PROPERTIES.contains(&key_str) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoInvalidLazyRouteProperties,
                None,
                "reactRouterNoInvalidLazyRouteProperties",
                key_str,
                &format!(
                    "Route `lazy()` cannot return immutable route-matching property `{key_str}`; move `{key_str}` onto the static route definition."
                ),
                prop.span,
                None,
            );
        }
    }
}

pub(crate) fn is_invalid_splat_path(path_val: &str) -> bool {
    if !path_val.contains('*') {
        return false;
    }
    path_val != "*" && !path_val.ends_with("/*") || path_val.matches('*').count() > 1
}

pub(crate) fn route_object_has_error_boundary(route_obj: &ObjectExpression<'_>) -> bool {
    get_object_prop(route_obj, "ErrorBoundary").is_some()
        || get_object_prop(route_obj, "errorElement").is_some()
        || get_object_prop(route_obj, "HydrateFallback").is_some()
}

#[expect(
    clippy::too_many_arguments,
    reason = "recursive JSX Route validator threads parent path and precomputed sets"
)]
pub(crate) fn check_jsx_route_element_recursive(
    jsx_el: &JSXElement<'_>,
    parent_path: Option<&str>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    components_with_routes: &HashSet<String>,
    components_with_outlet: &HashSet<String>,
    seen_ids: &mut HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    if jsx_element_tag_name(&opening.name).as_deref() != Some("Route") {
        return;
    }

    let id_attr = get_jsx_attr_static_str(opening, "id");
    let path_attr = get_jsx_attr_static_str(opening, "path");
    let is_index = has_jsx_truthy_attr(opening, "index");
    let has_element = has_jsx_attr(opening, "element");
    let has_component = has_jsx_attr(opening, "Component");
    let has_lazy = has_jsx_attr(opening, "lazy");
    let has_loader = has_jsx_attr(opening, "loader");
    let has_action = has_jsx_attr(opening, "action");

    let child_routes: Vec<&JSXElement<'_>> = jsx_el
        .children
        .iter()
        .filter_map(|c| {
            if let JSXChild::Element(el) = c
                && jsx_element_tag_name(&el.opening_element.name).as_deref() == Some("Route")
            {
                Some(&**el)
            } else {
                None
            }
        })
        .collect();
    let has_child_routes = !child_routes.is_empty();

    // Duplicate id
    if let Some((route_id, span)) = id_attr
        && !seen_ids.insert(route_id.clone())
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoDuplicateRouteId,
            None,
            "reactRouterNoDuplicateRouteId",
            &route_id,
            &format!("Duplicate route id `{route_id}`; every route `id` must be unique."),
            span,
            None,
        );
    }

    // Invalid splat path
    if let Some((path_val, path_span)) = &path_attr
        && is_invalid_splat_path(path_val)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoInvalidSplatPath,
            None,
            "reactRouterNoInvalidSplatPath",
            path_val,
            &format!(
                "Invalid splat route path `{path_val}`; `*` may only appear as `*` or at the end of a path as `/*`."
            ),
            *path_span,
            None,
        );
    }

    // Invalid absolute child path
    if let Some(p_path) = parent_path
        && let Some((child_path, child_span)) = &path_attr
        && child_path.starts_with('/')
    {
        let norm_parent = p_path.trim_end_matches("/*").trim_end_matches('/');
        if !norm_parent.is_empty()
            && child_path != norm_parent
            && !child_path.starts_with(&format!("{norm_parent}/"))
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoInvalidAbsoluteChildPath,
                None,
                "reactRouterNoInvalidAbsoluteChildPath",
                child_path,
                &format!(
                    "Absolute child route path `{child_path}` does not start with parent path `{norm_parent}`."
                ),
                *child_span,
                None,
            );
        }
    }

    // Contradictory JSX <Route> props
    let has_non_empty_path = path_attr.as_ref().is_some_and(|(p, _)| !p.is_empty());
    if (has_element && has_component)
        || (is_index && has_child_routes)
        || (is_index && has_non_empty_path)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterValidRouteObject,
            None,
            "reactRouterValidRouteObject",
            "Route",
            "JSX `<Route>` has contradictory properties (such as `index` with `path` or child `<Route>`s, or both `Component` and `element`).",
            opening.span,
            None,
        );
    }

    // Invalid lazy route properties on JSX `<Route>`
    if let Some(lazy_expr) = get_jsx_attr_expr(opening, "lazy") {
        check_lazy_route_expression(lazy_expr, line_starts, sites);
    }
    if has_lazy
        && (has_element
            || has_component
            || has_jsx_attr(opening, "ErrorBoundary")
            || has_jsx_attr(opening, "errorElement")
            || has_jsx_attr(opening, "hydrateFallbackElement")
            || has_jsx_attr(opening, "HydrateFallback"))
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoInvalidLazyRouteProperties,
            None,
            "reactRouterNoInvalidLazyRouteProperties",
            "Route",
            "JSX `<Route>` with `lazy` should not also define static `Component`, `element`, `ErrorBoundary`, `errorElement`, or `hydrateFallbackElement` props.",
            opening.span,
            None,
        );
    }

    let rendered_comp = get_jsx_route_rendered_component(opening);

    // Descendant routes require splat
    if let Some(comp_name) = &rendered_comp
        && components_with_routes.contains(comp_name)
        && let Some((path_val, path_span)) = &path_attr
        && path_val != "*"
        && !path_val.ends_with("/*")
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterDescendantRoutesRequireSplat,
            Some(comp_name.clone()),
            "reactRouterDescendantRoutesRequireSplat",
            path_val,
            &format!(
                "Route `{path_val}` renders `{comp_name}` which contains descendant `<Routes>`, so its path must end with `/*`."
            ),
            *path_span,
            None,
        );
    }

    // Nested route requires Outlet
    if has_child_routes {
        if let Some(comp_name) = &rendered_comp
            && !components_with_outlet.contains(comp_name)
            && is_component_defined_in_file(semantic, comp_name)
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNestedRouteRequiresOutlet,
                Some(comp_name.clone()),
                "reactRouterNestedRouteRequiresOutlet",
                comp_name,
                &format!(
                    "Parent `<Route>` component `{comp_name}` has nested routes but does not render `<Outlet />`."
                ),
                opening.span,
                None,
            );
        } else if let Some(el_expr) = get_jsx_attr_expr(opening, "element")
            && let Expression::JSXElement(inline_jsx) = el_expr.without_parentheses()
            && let Some(tag) = jsx_element_tag_name(&inline_jsx.opening_element.name)
            && tag.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && !jsx_subtree_contains_outlet(inline_jsx)
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNestedRouteRequiresOutlet,
                None,
                "reactRouterNestedRouteRequiresOutlet",
                &tag,
                "Parent `<Route>` `element` has nested routes but does not render `<Outlet />`.",
                inline_jsx.span,
                None,
            );
        }
    }

    // Empty leaf route
    if !has_child_routes
        && !has_element
        && !has_component
        && !has_lazy
        && !has_loader
        && !has_action
        && (path_attr.is_some() || is_index)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoEmptyLeafRoute,
            None,
            "reactRouterNoEmptyLeafRoute",
            "Route",
            "Leaf `<Route>` has no `element`, `Component`, `lazy`, `loader`, `action`, or child routes and will render nothing.",
            opening.span,
            None,
        );
    }

    let effective_parent_path = path_attr.as_ref().map(|(p, _)| p.as_str()).or(parent_path);
    for child_route in child_routes {
        check_jsx_route_element_recursive(
            child_route,
            effective_parent_path,
            semantic,
            line_starts,
            components_with_routes,
            components_with_outlet,
            seen_ids,
            sites,
        );
    }
}

pub(crate) fn jsx_route_subtree_has_loader_or_action(jsx_el: &JSXElement<'_>) -> bool {
    let opening = &jsx_el.opening_element;
    if has_jsx_attr(opening, "loader")
        || has_jsx_attr(opening, "action")
        || has_jsx_attr(opening, "clientLoader")
        || has_jsx_attr(opening, "clientAction")
    {
        return true;
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child
            && jsx_element_tag_name(&child_el.opening_element.name).as_deref() == Some("Route")
            && jsx_route_subtree_has_loader_or_action(child_el)
        {
            return true;
        }
    }
    false
}

fn get_jsx_route_rendered_component(opening: &JSXOpeningElement<'_>) -> Option<String> {
    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let JSXAttributeName::Identifier(id) = &attr.name else {
            continue;
        };
        if id.name != "Component" && id.name != "element" {
            continue;
        }
        let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
            continue;
        };
        if let Some(expr) = c.expression.as_expression()
            && let Some(name) = extract_component_ref_name(expr)
        {
            return Some(name);
        }
    }
    None
}

pub(crate) fn is_inside_middleware_array_export(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(anc_id)
            && let Some(id) = decl.id.get_binding_identifier()
            && matches!(
                id.name.as_str(),
                "middleware"
                    | "unstable_middleware"
                    | "clientMiddleware"
                    | "unstable_clientMiddleware"
            )
        {
            return true;
        }
    }
    false
}

/// Checks middleware rules:
/// - `react-router-no-catch-middleware-next`
/// - `react-router-no-middleware-response-body-consumption`
/// - `react-router-no-multiple-middleware-next`
/// - `react-router-server-middleware-return-response`
pub(crate) fn check_middleware_statements(
    fn_name: &str,
    params: &FormalParameters<'_>,
    statements: &[Statement<'_>],
    fn_span: Span,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let next_name = extract_middleware_next_param_name(params).unwrap_or("next");

    // 1. `react-router-no-catch-middleware-next`: `next()` inside a `try { ... } catch`
    for stmt in statements {
        if let Statement::TryStatement(try_stmt) = stmt
            && try_stmt.handler.is_some()
        {
            let try_src = try_stmt.block.span.source_text(source);
            if contains_call_to_ident(try_src, next_name) {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoCatchMiddlewareNext,
                    Some(fn_name.to_string()),
                    "reactRouterNoCatchMiddlewareNext",
                    next_name,
                    &format!(
                        "Wrapping `{next_name}()` in `try/catch` inside middleware does not reliably catch downstream route errors; use `ErrorBoundary` or `handleError`."
                    ),
                    try_stmt.span,
                    None,
                );
            }
        }
    }

    // 2. `react-router-no-multiple-middleware-next`
    let next_call_spans = find_calls_to_ident_in_statements(statements, next_name);
    if next_call_spans.len() >= 2 {
        for span in next_call_spans.iter().skip(1) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoMultipleMiddlewareNext,
                Some(fn_name.to_string()),
                "reactRouterNoMultipleMiddlewareNext",
                next_name,
                &format!(
                    "Middleware calls `{next_name}()` multiple times; call `{next_name}()` at most once and reuse the returned `Response`."
                ),
                *span,
                None,
            );
        }
    }

    // 3. `react-router-no-middleware-response-body-consumption`
    let response_vars = collect_vars_assigned_from_call(statements, next_name);
    if !response_vars.is_empty() {
        let var_refs: Vec<&str> = response_vars.iter().map(String::as_str).collect();
        for (method, call_span) in find_member_calls_in_statements(
            statements,
            &var_refs,
            &["json", "text", "arrayBuffer", "blob", "formData"],
        ) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoMiddlewareResponseBodyConsumption,
                Some(fn_name.to_string()),
                "reactRouterNoMiddlewareResponseBodyConsumption",
                &format!("response.{method}"),
                &format!(
                    "Middleware consumes the outgoing response body via `.{method}()`, leaving an empty stream for the client."
                ),
                call_span,
                None,
            );
        }
    }

    // 4. `react-router-server-middleware-return-response`
    if !next_call_spans.is_empty() && !statements_have_value_return_or_throw(statements) {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterServerMiddlewareReturnResponse,
            Some(fn_name.to_string()),
            "reactRouterServerMiddlewareReturnResponse",
            fn_name,
            &format!(
                "Server middleware `{fn_name}` calls `{next_name}()` without returning a `Response`."
            ),
            fn_span,
            None,
        );
    }
}

fn extract_middleware_next_param_name<'a>(params: &'a FormalParameters<'a>) -> Option<&'a str> {
    if let Some(second) = params.items.get(1)
        && let Some(id) = second.pattern.get_binding_identifier()
    {
        return Some(id.name.as_str());
    }
    None
}

/// Checks `react-router-v8-no-removed-future-flags`.
pub(crate) fn check_removed_future_flags(
    obj: &ObjectExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some((_, future_expr)) = get_object_prop(obj, "future") else {
        return;
    };
    let Expression::ObjectExpression(future_obj) = future_expr.without_parentheses() else {
        return;
    };
    for prop_kind in &future_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let Some(flag_name) = prop.key.static_name() else {
            continue;
        };
        let Some(flag_str) = flag_name.as_str() else {
            continue;
        };
        if REMOVED_V8_FUTURE_FLAGS.contains(&flag_str) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterV8NoRemovedFutureFlags,
                None,
                "reactRouterV8NoRemovedFutureFlags",
                flag_str,
                &format!("React Router future flag `{flag_str}` has been removed in v8."),
                prop.span,
                None,
            );
        }
    }
}

fn contains_call_to_ident(src: &str, ident: &str) -> bool {
    src.contains(&format!("{ident}("))
}

fn find_calls_to_ident_in_statements(statements: &[Statement<'_>], ident: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for stmt in statements {
        collect_calls_to_ident_in_stmt(stmt, ident, &mut spans);
    }
    spans
}

fn collect_calls_to_ident_in_stmt(stmt: &Statement<'_>, ident: &str, spans: &mut Vec<Span>) {
    match stmt {
        Statement::VariableDeclaration(var_decl) => {
            for decl in &var_decl.declarations {
                if let Some(init) = &decl.init
                    && expr_calls_function(init, ident)
                {
                    spans.push(init.span());
                }
            }
        }
        Statement::ExpressionStatement(expr_stmt) => {
            if expr_calls_function(&expr_stmt.expression, ident) {
                spans.push(expr_stmt.expression.span());
            }
        }
        Statement::ReturnStatement(ret) => {
            if let Some(arg) = &ret.argument
                && expr_calls_function(arg, ident)
            {
                spans.push(arg.span());
            }
        }
        Statement::BlockStatement(block) => {
            for s in &block.body {
                collect_calls_to_ident_in_stmt(s, ident, spans);
            }
        }
        Statement::TryStatement(try_stmt) => {
            for s in &try_stmt.block.body {
                collect_calls_to_ident_in_stmt(s, ident, spans);
            }
        }
        _ => {}
    }
}

fn collect_vars_assigned_from_call(statements: &[Statement<'_>], fn_name: &str) -> Vec<String> {
    let mut vars = Vec::new();
    for stmt in statements {
        if let Statement::VariableDeclaration(var_decl) = stmt {
            for decl in &var_decl.declarations {
                if let Some(id) = decl.id.get_binding_identifier()
                    && let Some(init) = &decl.init
                    && expr_calls_function(init, fn_name)
                {
                    vars.push(id.name.to_string());
                }
            }
        }
    }
    vars
}

fn statements_have_value_return_or_throw(statements: &[Statement<'_>]) -> bool {
    for stmt in statements {
        match stmt {
            Statement::ReturnStatement(ret) if ret.argument.is_some() => return true,
            Statement::ThrowStatement(_) => return true,
            Statement::IfStatement(if_stmt) => {
                if stmt_has_value_return_or_throw(&if_stmt.consequent) {
                    return true;
                }
                if let Some(alt) = &if_stmt.alternate
                    && stmt_has_value_return_or_throw(alt)
                {
                    return true;
                }
            }
            Statement::TryStatement(try_stmt)
                if statements_have_value_return_or_throw(&try_stmt.block.body) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn stmt_has_value_return_or_throw(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::ReturnStatement(ret) => ret.argument.is_some(),
        Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(b) => statements_have_value_return_or_throw(&b.body),
        _ => false,
    }
}
