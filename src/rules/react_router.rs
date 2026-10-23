//! React Router v7 and v8 (`react-router-*`) single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, ArrowFunctionBody, BindingPattern, CallExpression, Expression,
        FormalParameters, JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXChild,
        JSXElement, JSXElementName, JSXOpeningElement, ObjectExpression, ObjectPropertyKind,
        Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{
            extract_callee_short_name, find_enclosing_react_node, get_subject_name,
            is_direct_render_phase_node,
        },
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::{AutofixPatch, ByteEdit, RuleId},
};

const DATA_ROUTER_FACTORIES: &[&str] = &[
    "createBrowserRouter",
    "createMemoryRouter",
    "createHashRouter",
    "createStaticRouter",
    "createRoutesStub",
];

const ROUTER_JSX_COMPONENTS: &[&str] = &[
    "BrowserRouter",
    "MemoryRouter",
    "HashRouter",
    "StaticRouter",
    "Router",
    "RouterProvider",
    "NativeRouter",
    "ServerRouter",
    "HydratedRouter",
];

const IMMUTABLE_ROUTE_PROPERTIES: &[&str] = &["id", "path", "index", "children", "caseSensitive"];

const REMOVED_V8_FUTURE_FLAGS: &[&str] = &[
    "v3_fetcherPersist",
    "v3_relativeSplatPath",
    "v3_throwAbortReason",
    "v3_singleFetch",
    "v3_lazyRouteDiscovery",
    "v3_routeConfig",
    "v7_startTransition",
    "v7_relativeSplatPath",
    "v7_fetcherPersist",
    "v7_normalizeFormMethod",
    "v7_partialHydration",
    "v7_skipActionErrorRevalidation",
    "v8_middleware",
    "v8_splitRouteModules",
    "v8_viteEnvironmentApi",
    "unstable_middleware",
    "unstable_splitRouteModules",
    "unstable_viteEnvironmentApi",
    "unstable_subResourceIntegrity",
];

const RESOURCE_EXTENSIONS: &[&str] = &[
    ".pdf", ".csv", ".zip", ".tar", ".gz", ".xlsx", ".xls", ".doc", ".docx", ".xml", ".rss",
    ".ics", ".json", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp3", ".mp4",
];

/// Extracts all React Router v7/v8 semantic rule sites in a single pass.
pub(crate) fn extract_react_router_sites(
    path: &Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();

    // File-level & import-level checks
    check_route_module_environment_suffix(path, program, line_starts, sites);
    let client_imported_symbols =
        check_imports_and_collect_client_symbols(program, source, line_starts, sites);

    // Precompute component info: which components render <Routes> or <Outlet>
    let (components_with_routes, components_with_outlet) =
        collect_component_router_traits(semantic);

    // Track per-component useBlocker count
    let mut blocker_calls_by_subject: HashMap<NodeId, Vec<(Span, Option<String>)>> = HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                check_call_expression_rules(
                    node_id,
                    call,
                    semantic,
                    source,
                    line_starts,
                    &components_with_routes,
                    &components_with_outlet,
                    &mut blocker_calls_by_subject,
                    sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                check_jsx_element_rules(
                    node_id,
                    jsx_el,
                    program,
                    semantic,
                    line_starts,
                    &client_imported_symbols,
                    &components_with_routes,
                    &components_with_outlet,
                    sites,
                );
            }
            AstKind::Function(func) => {
                if let Some(body) = &func.body {
                    check_function_like_rules(
                        node_id,
                        func.id.as_ref().map(|id| id.name.as_str()),
                        &func.params,
                        &body.statements,
                        func.span,
                        semantic,
                        source,
                        line_starts,
                        sites,
                    );
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                let fn_name = get_arrow_assigned_name(semantic, node_id);
                check_arrow_function_rules(
                    node_id,
                    fn_name,
                    &arrow.params,
                    &arrow.body,
                    arrow.span,
                    semantic,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::ObjectExpression(obj) => {
                check_removed_future_flags(obj, line_starts, sites);
            }
            _ => {}
        }
    }

    for (_, calls) in blocker_calls_by_subject {
        if calls.len() >= 2 {
            for (span, subject_name) in calls.into_iter().skip(1) {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoMultipleBlockers,
                    subject_name,
                    "reactRouterNoMultipleBlockers",
                    "useBlocker",
                    "Multiple `useBlocker` hooks are called in the same component; combine blocking conditions into a single `useBlocker` call.",
                    span,
                    None,
                );
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "single-pass site builder consolidates diagnostic fields"
)]
fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    line_starts: &[u32],
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: &str,
    span: Span,
    autofix: Option<AutofixPatch>,
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message: message.to_string(),
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix,
    });
}

/// Checks `react-router-no-route-module-environment-suffix`.
fn check_route_module_environment_suffix(
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
    let span = program
        .body
        .first()
        .map_or(program.span, GetSpan::span);
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
fn check_imports_and_collect_client_symbols(
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
            let autofix = Some(AutofixPatch {
                description: format!("Replace `{spec}` import with `{new_spec}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: imp.source.span.start,
                        end: imp.source.span.end,
                    },
                    replacement,
                }],
            });
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
    spec.ends_with(".client")
        || spec.contains(".client.")
        || spec.ends_with("/client")
}

/// Collects components in the file that render `<Routes>` or `<Outlet>` / `useOutlet`.
fn collect_component_router_traits(
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
                if extract_callee_short_name(&call.callee) == Some("useOutlet")
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
    reason = "single-pass call dispatcher shares precomputed component sets and state maps"
)]
fn check_call_expression_rules(
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
    let Some(callee_name) = extract_callee_short_name(&call.callee) else {
        return;
    };

    // Data router creation calls: `createBrowserRouter([...], opts)` etc.
    if DATA_ROUTER_FACTORIES.contains(&callee_name) {
        // Check `react-router-no-router-in-render`
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

        // Inspect route tree array passed as first argument
        if let Some(first_arg) = call.arguments.first()
            && let Some(expr) = first_arg.as_expression()
            && let Expression::ArrayExpression(arr) = expr.without_parentheses()
        {
            let mut seen_ids = HashSet::new();
            for (idx, elem) in arr.elements.iter().enumerate() {
                let ArrayExpressionElement::ObjectExpression(route_obj) = elem else {
                    continue;
                };
                // Check root error boundary on top-level route(s)
                if idx == 0 && !route_object_has_error_boundary(route_obj) {
                    // Only flag root route if it has children or is `/` root layout
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
    }

    // `createCookie("name", { expires: ... })` -> `react-router-no-static-cookie-expires`
    if callee_name == "createCookie" || callee_name == "createCookieSessionStorage" {
        check_static_cookie_expires(node_id, call, callee_name, semantic, line_starts, sites);
    }

    // `useBlocker(...)` -> `react-router-no-multiple-blockers`
    if (callee_name == "useBlocker" || callee_name == "unstable_useBlocker")
        && let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
    {
        let subject_name = get_subject_name(semantic, subj_id);
        blocker_calls_by_subject
            .entry(subj_id)
            .or_default()
            .push((call.span, subject_name));
    }

    // `useLoaderData()` inside `ErrorBoundary` -> `react-router-no-use-loader-data-in-error-ui`
    if callee_name == "useLoaderData" {
        check_use_loader_data_in_error_ui(node_id, call, semantic, line_starts, sites);
    }

    // `redirect(...)` inside `try { ... } catch` -> `react-router-no-redirect-in-try-catch`
    if callee_name == "redirect" || callee_name == "redirectDocument" {
        check_redirect_in_try_catch(node_id, call, callee_name, semantic, source, line_starts, sites);
    }

    // `navigate(...)` during render -> `react-router-no-navigate-in-render`
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

    // `startTransition(() => { navigate(...); })` -> `react-router-return-navigation-promise-in-transition`
    if callee_name == "startTransition" {
        check_transition_navigation_promise(node_id, call, semantic, line_starts, sites);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "recursive route object validator carries parent path and precomputed component traits"
)]
fn check_route_object_recursive(
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
            &format!("Duplicate route id `{route_id}`; every route `id` must be unique within the router."),
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
            &format!("Invalid splat route path `{path_val}`; `*` may only appear as `*` or at the end of a path as `/*`."),
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
                &format!("Absolute child route path `{child_path}` does not start with parent path `{norm_parent}`."),
                *child_span,
                None,
            );
        }
    }

    // 4. `react-router-valid-route-object`
    let has_both_comp_and_element = component_prop.is_some() && element_prop.is_some();
    let index_with_children = is_index && children_prop.is_some();
    let index_with_non_empty_path = is_index
        && path_prop
            .as_ref()
            .is_some_and(|(p, _)| !p.is_empty());
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
            &format!("Route `{path_val}` renders `{comp_name}` which contains descendant `<Routes>`, so its path must end with `/*`."),
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
                &format!("Parent route component `{comp_name}` has child routes but does not render `<Outlet />`."),
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
    let effective_parent_path = path_prop
        .as_ref()
        .map(|(p, _)| p.as_str())
        .or(parent_path);
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

fn check_inline_route_handler_expr(
    expr: &Expression<'_>,
    role_name: &str,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match expr.without_parentheses() {
        Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                check_loader_or_action_statements(
                    role_name,
                    &body.statements,
                    f.span,
                    source,
                    line_starts,
                    sites,
                );
            }
        }
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(body_expr) = arrow.body.as_expression() {
                check_loader_or_action_expr(role_name, body_expr, source, line_starts, sites);
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                check_loader_or_action_statements(
                    role_name,
                    &body.statements,
                    arrow.span,
                    source,
                    line_starts,
                    sites,
                );
            }
        }
        _ => {}
    }
}

fn check_lazy_route_expression(
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
                &format!("Route `lazy()` cannot return immutable route-matching property `{key_str}`; move `{key_str}` onto the static route definition."),
                prop.span,
                None,
            );
        }
    }
}

fn is_invalid_splat_path(path_val: &str) -> bool {
    if !path_val.contains('*') {
        return false;
    }
    path_val != "*" && !path_val.ends_with("/*") || path_val.matches('*').count() > 1
}

fn route_object_has_error_boundary(route_obj: &ObjectExpression<'_>) -> bool {
    get_object_prop(route_obj, "ErrorBoundary").is_some()
        || get_object_prop(route_obj, "errorElement").is_some()
        || get_object_prop(route_obj, "HydrateFallback").is_some()
}

fn get_object_prop<'a>(
    obj: &'a ObjectExpression<'a>,
    name: &str,
) -> Option<(Span, &'a Expression<'a>)> {
    for prop_kind in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
            && prop.key.static_name().is_some_and(|n| n.as_str() == Some(name))
        {
            return Some((prop.span, &prop.value));
        }
    }
    None
}

fn get_object_prop_static_str(obj: &ObjectExpression<'_>, name: &str) -> Option<String> {
    get_object_prop_static_str_with_span(obj, name).map(|(s, _)| s)
}

fn get_object_prop_static_str_with_span(
    obj: &ObjectExpression<'_>,
    name: &str,
) -> Option<(String, Span)> {
    let (span, val) = get_object_prop(obj, name)?;
    match val.without_parentheses() {
        Expression::StringLiteral(s) => s.value.as_str().map(|v| (v.to_string(), span)),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => t
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref())
            .and_then(|c| c.as_str())
            .map(|c| (c.to_string(), span)),
        _ => None,
    }
}

fn get_object_prop_bool(obj: &ObjectExpression<'_>, name: &str) -> Option<bool> {
    let (_, val) = get_object_prop(obj, name)?;
    if let Expression::BooleanLiteral(b) = val.without_parentheses() {
        Some(b.value)
    } else {
        None
    }
}

fn extract_component_ref_name(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::JSXElement(jsx_el) => jsx_element_tag_name(&jsx_el.opening_element.name),
        _ => None,
    }
}

fn is_component_defined_in_file(semantic: &Semantic<'_>, comp_name: &str) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(f) if f.id.as_ref().is_some_and(|id| id.name == comp_name) => {
                return true;
            }
            AstKind::VariableDeclarator(decl)
                if decl
                    .id
                    .get_binding_identifier()
                    .is_some_and(|id| id.name == comp_name) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn jsx_subtree_contains_outlet(jsx_el: &JSXElement<'_>) -> bool {
    if jsx_element_tag_name(&jsx_el.opening_element.name).as_deref() == Some("Outlet") {
        return true;
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child
            && jsx_subtree_contains_outlet(child_el)
        {
            return true;
        }
    }
    false
}

#[expect(
    clippy::too_many_arguments,
    reason = "single-pass JSX element rule check receives precomputed sets"
)]
fn check_jsx_element_rules(
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

    // 1. `<Routes>` tree inspection for JSX `<Route>` elements
    if tag == "Routes" {
        let mut seen_ids = HashSet::new();
        for child in &jsx_el.children {
            if let JSXChild::Element(child_el) = child {
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
    }

    // 2. `react-router-no-nested-router`
    if ROUTER_JSX_COMPONENTS.contains(&tag.as_str()) {
        let has_ancestor_router = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            if let AstKind::JSXElement(anc_jsx) = semantic.nodes().kind(anc_id)
                && let Some(anc_tag) = jsx_element_tag_name(&anc_jsx.opening_element.name)
            {
                ROUTER_JSX_COMPONENTS.contains(&anc_tag.as_str())
            } else {
                false
            }
        });
        if has_ancestor_router {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoNestedRouter,
                subject_name.clone(),
                "reactRouterNoNestedRouter",
                &tag,
                &format!("`<{tag}>` is nested inside another router component; keep a single router provider at the application root."),
                opening.span,
                None,
            );
        }
    }

    // 3. `react-router-no-client-module-in-server-render`
    if client_imported_symbols.contains(&tag) && !is_inside_client_only_boundary(semantic, node_id) {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoClientModuleInServerRender,
            subject_name.clone(),
            "reactRouterNoClientModuleInServerRender",
            &tag,
            &format!("Client-only component `<{tag}>` (imported from a `.client` module) cannot be rendered directly on the server; wrap it in a `<ClientOnly>` or hydration boundary."),
            opening.span,
            None,
        );
    }

    // 4. `react-router-internal-route-anchor`
    if tag == "a"
        && file_uses_react_router(program)
        && let Some((href_val, _)) = get_jsx_attr_static_str(opening, "href")
        && is_internal_route_href(&href_val)
        && !has_jsx_attr(opening, "download")
        && !has_jsx_attr(opening, "reloadDocument")
        && get_jsx_attr_static_str(opening, "target")
            .is_none_or(|(t, _)| t != "_blank")
        && !has_resource_extension(&href_val)
    {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterInternalRouteAnchor,
            subject_name.clone(),
            "reactRouterInternalRouteAnchor",
            "a",
            &format!("Anchor `<a href=\"{href_val}\">` triggers a full document reload for an internal route; use `<Link to=\"{href_val}\">` instead."),
            opening.span,
            None,
        );
    }

    // 5. `react-router-resource-link-requires-reload`
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
            &tag,
            &format!("`<{tag} to=\"{to_val}\">` points to a static/resource asset without `reloadDocument`; add `reloadDocument` so the browser loads the resource directly."),
            opening.span,
            None,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "recursive JSX Route validator threads parent path and precomputed sets"
)]
fn check_jsx_route_element_recursive(
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
            &format!("Invalid splat route path `{path_val}`; `*` may only appear as `*` or at the end of a path as `/*`."),
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
                &format!("Absolute child route path `{child_path}` does not start with parent path `{norm_parent}`."),
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
            &format!("Route `{path_val}` renders `{comp_name}` which contains descendant `<Routes>`, so its path must end with `/*`."),
            *path_span,
            None,
        );
    }

    // Nested route requires Outlet
    if has_child_routes
        && let Some(comp_name) = &rendered_comp
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
            &format!("Parent `<Route>` component `{comp_name}` has nested routes but does not render `<Outlet />`."),
            opening.span,
            None,
        );
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

    let effective_parent_path = path_attr
        .as_ref()
        .map(|(p, _)| p.as_str())
        .or(parent_path);
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

#[expect(
    clippy::too_many_arguments,
    reason = "function-like dispatcher passes params, body statements, and semantic context"
)]
fn check_function_like_rules(
    node_id: NodeId,
    fn_name: Option<&str>,
    params: &FormalParameters<'_>,
    statements: &[Statement<'_>],
    fn_span: Span,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(name) = fn_name {
        match name {
            "handleError" => {
                check_handle_error_fn(name, statements, fn_span, source, line_starts, sites);
            }
            "loader" | "clientLoader" | "action" | "clientAction" => {
                check_loader_or_action_statements(
                    name,
                    statements,
                    fn_span,
                    source,
                    line_starts,
                    sites,
                );
            }
            "middleware" | "unstable_middleware" | "serverMiddleware" => {
                check_middleware_statements(
                    name,
                    params,
                    statements,
                    fn_span,
                    source,
                    line_starts,
                    sites,
                );
            }
            "meta" => {
                check_meta_data_field(params, statements, source, line_starts, sites);
            }
            _ => {}
        }
    }

    // Check if this function is inside an exported `middleware = [...]` or `unstable_middleware = [...]` array
    if fn_name.is_none() && is_inside_middleware_array_export(semantic, node_id) {
        check_middleware_statements(
            "middleware",
            params,
            statements,
            fn_span,
            source,
            line_starts,
            sites,
        );
    }

    // Check `useSearchParams()` destructuring & mutations inside any function/component body
    check_search_params_in_statements(node_id, statements, semantic, source, line_starts, sites);
}

#[expect(
    clippy::too_many_arguments,
    reason = "arrow function dispatcher mirrors check_function_like_rules"
)]
fn check_arrow_function_rules(
    node_id: NodeId,
    fn_name: Option<&str>,
    params: &FormalParameters<'_>,
    body: &ArrowFunctionBody<'_>,
    fn_span: Span,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(expr) = body.as_expression() {
        if let Some(name) = fn_name {
            if matches!(name, "loader" | "clientLoader" | "action" | "clientAction") {
                check_loader_or_action_expr(name, expr, source, line_starts, sites);
            } else if name == "meta" {
                check_meta_data_field_expr(params, expr, source, line_starts, sites);
            }
        }
    } else if let ArrowFunctionBody::FunctionBody(fn_body) = body {
        check_function_like_rules(
            node_id,
            fn_name,
            params,
            &fn_body.statements,
            fn_span,
            semantic,
            source,
            line_starts,
            sites,
        );
    }
}

fn get_arrow_assigned_name<'a>(semantic: &'a Semantic<'a>, node_id: NodeId) -> Option<&'a str> {
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
        && let Some(id) = decl.id.get_binding_identifier()
    {
        return Some(id.name.as_str());
    }
    None
}

fn is_inside_middleware_array_export(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(anc_id)
            && let Some(id) = decl.id.get_binding_identifier()
            && matches!(
                id.name.as_str(),
                "middleware" | "unstable_middleware" | "clientMiddleware" | "unstable_clientMiddleware"
            )
        {
            return true;
        }
    }
    false
}

/// Checks `react-router-guard-aborted-handle-error`.
fn check_handle_error_fn(
    fn_name: &str,
    statements: &[Statement<'_>],
    fn_span: Span,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if statements.is_empty() {
        return;
    }
    let body_src = fn_span.source_text(source);
    if !body_src.contains("aborted") {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterGuardAbortedHandleError,
            Some(fn_name.to_string()),
            "reactRouterGuardAbortedHandleError",
            fn_name,
            "`handleError` reports errors without guarding against `request.signal.aborted`; return early when the request was aborted.",
            fn_span,
            None,
        );
    }
}

/// Checks loader and action safety rules:
/// - `react-router-no-loader-request-body`
/// - `react-router-no-session-mutation-in-loader`
/// - `react-router-session-mutation-requires-commit`
fn check_loader_or_action_statements(
    role_name: &str,
    statements: &[Statement<'_>],
    fn_span: Span,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_loader = role_name == "loader" || role_name == "clientLoader";
    let fn_src = fn_span.source_text(source);

    if is_loader {
        // Check `request.json()`, `request.formData()`, `request.text()`, `request.arrayBuffer()`, `request.blob()`
        for (method, call_span) in find_member_calls_in_statements(
            statements,
            &["request", "req"],
            &["json", "formData", "text", "arrayBuffer", "blob"],
        ) {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterNoLoaderRequestBody,
                Some(role_name.to_string()),
                "reactRouterNoLoaderRequestBody",
                &format!("request.{method}"),
                &format!("`{role_name}` reads `request.{method}()`; loaders run on GET requests and must not read a request body (use `action` instead)."),
                call_span,
                None,
            );
        }
    }

    // Collect session variables (`const session = await getSession(...)`) and any direct `session.set` / `session.flash` / `session.unset` calls
    let session_mutations = find_session_mutations_in_statements(statements);
    if !session_mutations.is_empty() {
        if is_loader {
            for (method, span) in &session_mutations {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoSessionMutationInLoader,
                    Some(role_name.to_string()),
                    "reactRouterNoSessionMutationInLoader",
                    &format!("session.{method}"),
                    &format!("`{role_name}` mutates session state via `session.{method}(...)`; move session mutations into an `action`."),
                    *span,
                    None,
                );
            }
        } else {
            // In an `action`: verify `commitSession` or `destroySession` is called and Set-Cookie is returned
            let commits_session =
                fn_src.contains("commitSession") || fn_src.contains("destroySession");
            if !commits_session
                && let Some((method, span)) = session_mutations.first()
            {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterSessionMutationRequiresCommit,
                    Some(role_name.to_string()),
                    "reactRouterSessionMutationRequiresCommit",
                    &format!("session.{method}"),
                    "Session state is mutated with `session.set`/`flash`/`unset` but never committed with `commitSession` or `destroySession` in the response.",
                    *span,
                    None,
                );
            }
        }
    }
}

fn check_loader_or_action_expr(
    role_name: &str,
    expr: &Expression<'_>,
    _source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_loader = role_name == "loader" || role_name == "clientLoader";
    if !is_loader {
        return;
    }
    if let Some((method, call_span)) = find_member_call_in_expr(
        expr,
        &["request", "req"],
        &["json", "formData", "text", "arrayBuffer", "blob"],
    ) {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoLoaderRequestBody,
            Some(role_name.to_string()),
            "reactRouterNoLoaderRequestBody",
            &format!("request.{method}"),
            &format!("`{role_name}` reads `request.{method}()`; loaders run on GET requests and must not read a request body."),
            call_span,
            None,
        );
    }
}

/// Checks middleware rules:
/// - `react-router-no-catch-middleware-next`
/// - `react-router-no-middleware-response-body-consumption`
/// - `react-router-no-multiple-middleware-next`
/// - `react-router-server-middleware-return-response`
fn check_middleware_statements(
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
                    &format!("Wrapping `{next_name}()` in `try/catch` inside middleware does not reliably catch downstream route errors; use `ErrorBoundary` or `handleError`."),
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
                &format!("Middleware calls `{next_name}()` multiple times; call `{next_name}()` at most once and reuse the returned `Response`."),
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
                &format!("Middleware consumes the outgoing response body via `.{method}()`, leaving an empty stream for the client."),
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
            &format!("Server middleware `{fn_name}` calls `{next_name}()` without returning a `Response`."),
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

/// Checks `react-router-v8-no-meta-data-field`.
fn check_meta_data_field(
    params: &FormalParameters<'_>,
    statements: &[Statement<'_>],
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(span) = find_meta_data_param_or_access(params, statements, None, source) {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterV8NoMetaDataField,
            Some("meta".to_string()),
            "reactRouterV8NoMetaDataField",
            "data",
            "The `data` argument field in `meta()` was removed in React Router v8; use `loaderData` instead.",
            span,
            None,
        );
    }
}

fn check_meta_data_field_expr(
    params: &FormalParameters<'_>,
    expr: &Expression<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(span) = find_meta_data_param_or_access(params, &[], Some(expr), source) {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterV8NoMetaDataField,
            Some("meta".to_string()),
            "reactRouterV8NoMetaDataField",
            "data",
            "The `data` argument field in `meta()` was removed in React Router v8; use `loaderData` instead.",
            span,
            None,
        );
    }
}

fn find_meta_data_param_or_access(
    params: &FormalParameters<'_>,
    statements: &[Statement<'_>],
    body_expr: Option<&Expression<'_>>,
    source: &str,
) -> Option<Span> {
    let first_param = params.items.first()?;
    match &first_param.pattern {
        BindingPattern::ObjectPattern(obj_pat) => {
            for prop in &obj_pat.properties {
                if prop.key.static_name().is_some_and(|n| n.as_str() == Some("data")) {
                    return Some(prop.span);
                }
            }
        }
        BindingPattern::BindingIdentifier(id) => {
            let param_name = id.name.as_str();
            let needle = format!("{param_name}.data");
            for stmt in statements {
                let s = stmt.span().source_text(source);
                if s.contains(&needle) {
                    return Some(stmt.span());
                }
            }
            if let Some(expr) = body_expr {
                let s = expr.span().source_text(source);
                if s.contains(&needle) {
                    return Some(expr.span());
                }
            }
        }
        _ => {}
    }
    None
}

/// Checks `react-router-no-static-cookie-expires`.
fn check_static_cookie_expires(
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_name: &str,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Must be at module scope (not inside a per-request function) or passing a static `expires` option
    let in_fn = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        )
    });
    if in_fn {
        return;
    }
    for arg in &call.arguments {
        let Some(expr) = arg.as_expression() else {
            continue;
        };
        if let Expression::ObjectExpression(obj) = expr.without_parentheses() {
            if let Some((span, _)) = get_object_prop(obj, "expires") {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoStaticCookieExpires,
                    None,
                    "reactRouterNoStaticCookieExpires",
                    callee_name,
                    "Setting `expires` on a cookie created at module scope fixes a single timestamp at server startup; use `maxAge` instead.",
                    span,
                    None,
                );
                return;
            }
            if let Some((_, cookie_expr)) = get_object_prop(obj, "cookie")
                && let Expression::ObjectExpression(cookie_obj) = cookie_expr.without_parentheses()
                && let Some((span, _)) = get_object_prop(cookie_obj, "expires")
            {
                push_site(
                    sites,
                    line_starts,
                    RuleId::ReactRouterNoStaticCookieExpires,
                    None,
                    "reactRouterNoStaticCookieExpires",
                    callee_name,
                    "Setting `expires` on a cookie created at module scope fixes a single timestamp at server startup; use `maxAge` instead.",
                    span,
                    None,
                );
                return;
            }
        }
    }
}

/// Checks `react-router-no-use-loader-data-in-error-ui`.
fn check_use_loader_data_in_error_ui(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    let Some(subj_name) = get_subject_name(semantic, subj_id) else {
        return;
    };
    let is_error_ui = subj_name == "ErrorBoundary"
        || subj_name.ends_with("ErrorBoundary")
        || subject_calls_use_route_error(semantic, subj_id);
    if is_error_ui {
        push_site(
            sites,
            line_starts,
            RuleId::ReactRouterNoUseLoaderDataInErrorUi,
            Some(subj_name),
            "reactRouterNoUseLoaderDataInErrorUi",
            "useLoaderData",
            "`useLoaderData()` is unsafe inside `ErrorBoundary` because the loader itself may have thrown; use `useRouteLoaderData()` and handle `undefined`.",
            call.span,
            None,
        );
    }
}

fn subject_calls_use_route_error(semantic: &Semantic<'_>, subj_id: NodeId) -> bool {
    let subj_span = semantic.nodes().get_node(subj_id).span();
    let src = subj_span.source_text(semantic.source_text());
    src.contains("useRouteError(")
}

/// Checks `react-router-no-redirect-in-try-catch`.
fn check_redirect_in_try_catch(
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_name: &str,
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            AstKind::TryStatement(try_stmt) => {
                // Ensure the redirect call is inside the `try` block (not `catch` or `finally`)
                if try_stmt.block.span.contains_inclusive(call.span)
                    && let Some(handler) = &try_stmt.handler
                {
                    let catch_src = handler.body.span.source_text(source);
                    // If catch block explicitly checks for Response/redirect and rethrows, allow
                    if catch_src.contains("instanceof Response") {
                        return;
                    }
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|id| get_subject_name(semantic, id));
                    push_site(
                        sites,
                        line_starts,
                        RuleId::ReactRouterNoRedirectInTryCatch,
                        subject_name,
                        "reactRouterNoRedirectInTryCatch",
                        callee_name,
                        &format!("`{callee_name}()` inside a `try` block can be swallowed or mishandled if thrown or caught; move `{callee_name}()` outside `try/catch`."),
                        call.span,
                        None,
                    );
                    return;
                }
            }
            _ => {}
        }
    }
}

/// Checks `react-router-return-navigation-promise-in-transition`.
fn check_transition_navigation_promise(
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
            && let Expression::CallExpression(inner_call) = expr_stmt.expression.without_parentheses()
            && let Some(name) = extract_callee_short_name(&inner_call.callee)
            && (name == "navigate" || name == "revalidate" || name == "submit")
        {
            push_site(
                sites,
                line_starts,
                RuleId::ReactRouterReturnNavigationPromiseInTransition,
                subject_name.clone(),
                "reactRouterReturnNavigationPromiseInTransition",
                name,
                &format!("`{name}()` inside `startTransition` is not returned or awaited, so transition pending state ends before navigation completes."),
                inner_call.span,
                None,
            );
        }
    }
}

/// Checks `react-router-no-multiple-set-search-params-in-tick` and
/// `react-router-no-unsynchronized-search-params-mutation`.
fn check_search_params_in_statements(
    fn_node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Collect `[searchParams, setSearchParams] = useSearchParams()` bindings in this scope
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
            if extract_callee_short_name(&call.callee) != Some("useSearchParams") {
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

    if search_params_vars.is_empty() && set_search_params_vars.is_empty() {
        return;
    }

    let subject_name = find_enclosing_react_node(semantic, fn_node_id)
        .and_then(|id| get_subject_name(semantic, id));

    // 1. Check `searchParams.set(...)` / `append` / `delete` / `sort` without passing to `setSearchParams`
    if !search_params_vars.is_empty() {
        let sp_refs: Vec<&str> = search_params_vars.iter().map(String::as_str).collect();
        let fn_span = semantic.nodes().get_node(fn_node_id).span();
        let fn_src = fn_span.source_text(source);

        // Walk all statements and nested functions inside this component
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
                // Check if `setSearchParams(searchParams)` is called in the same function
                let passed_to_setter = set_search_params_vars.iter().any(|setter| {
                    fn_src.contains(&format!("{setter}({})", obj_id.name))
                });
                if !passed_to_setter {
                    push_site(
                        sites,
                        line_starts,
                        RuleId::ReactRouterNoUnsynchronizedSearchParamsMutation,
                        subject_name.clone(),
                        "reactRouterNoUnsynchronizedSearchParamsMutation",
                        &format!("{}.{}", obj_id.name, mem.property.name),
                        &format!("Mutating `{}.{}(...)` in place does not trigger navigation or re-render; clone `URLSearchParams` and pass it to `setSearchParams`.", obj_id.name, mem.property.name),
                        call.span,
                        None,
                    );
                }
            }
        }
    }

    // 2. Check multiple `setSearchParams(...)` calls in the same synchronous block/function
    if !set_search_params_vars.is_empty() {
        let fn_span = semantic.nodes().get_node(fn_node_id).span();
        for (_, node) in semantic.nodes().iter_enumerated() {
            if !fn_span.contains_inclusive(node.span()) {
                continue;
            }
            let block_stmts: Option<&[Statement<'_>]> = match node.kind() {
                AstKind::FunctionBody(body) => Some(&body.statements),
                AstKind::BlockStatement(block) => Some(&block.body),
                _ => None,
            };
            let Some(stmts) = block_stmts else {
                continue;
            };
            let mut setter_calls = Vec::new();
            for stmt in stmts {
                if let Statement::ExpressionStatement(expr_stmt) = stmt
                    && let Expression::CallExpression(call) = expr_stmt.expression.without_parentheses()
                    && let Expression::Identifier(callee_id) = call.callee.without_parentheses()
                    && set_search_params_vars.iter().any(|s| s == callee_id.name.as_str())
                {
                    setter_calls.push((callee_id.name.as_str(), call.span));
                }
            }
            if setter_calls.len() >= 2 {
                for (setter_name, span) in setter_calls.into_iter().skip(1) {
                    push_site(
                        sites,
                        line_starts,
                        RuleId::ReactRouterNoMultipleSetSearchParamsInTick,
                        subject_name.clone(),
                        "reactRouterNoMultipleSetSearchParamsInTick",
                        setter_name,
                        &format!("Calling `{setter_name}()` multiple times in the same tick overwrites earlier updates; combine search param changes into a single `{setter_name}()` call."),
                        span,
                        None,
                    );
                }
            }
        }
    }
}

/// Checks `react-router-v8-no-removed-future-flags`.
fn check_removed_future_flags(
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

// --- Helper utilities ---

fn jsx_element_tag_name(name: &JSXElementName<'_>) -> Option<String> {
    match name {
        JSXElementName::Identifier(id) => Some(id.name.to_string()),
        JSXElementName::IdentifierReference(id) => Some(id.name.to_string()),
        JSXElementName::NamespacedName(ns) => Some(format!("{}:{}", ns.namespace.name, ns.name.name)),
        JSXElementName::MemberExpression(mem) => Some(mem.property.name.to_string()),
        JSXElementName::ThisExpression(_) => None,
    }
}

fn get_jsx_attr_static_str(
    opening: &JSXOpeningElement<'_>,
    attr_name: &str,
) -> Option<(String, Span)> {
    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let JSXAttributeName::Identifier(id) = &attr.name else {
            continue;
        };
        if id.name != attr_name {
            continue;
        }
        let val = attr.value.as_ref()?;
        match val {
            JSXAttributeValue::StringLiteral(s) => {
                if let Some(v) = s.value.as_str() {
                    return Some((v.to_string(), attr.span));
                }
            }
            JSXAttributeValue::ExpressionContainer(c) => {
                if let Some(expr) = c.expression.as_expression() {
                    match expr.without_parentheses() {
                        Expression::StringLiteral(s) => {
                            if let Some(v) = s.value.as_str() {
                                return Some((v.to_string(), attr.span));
                            }
                        }
                        Expression::TemplateLiteral(t) if t.expressions.is_empty() => {
                            if let Some(cooked) = t
                                .quasis
                                .first()
                                .and_then(|q| q.value.cooked.as_ref())
                                .and_then(|c| c.as_str())
                            {
                                return Some((cooked.to_string(), attr.span));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn has_jsx_attr(opening: &JSXOpeningElement<'_>, attr_name: &str) -> bool {
    opening.attributes.iter().any(|item| {
        if let JSXAttributeItem::Attribute(attr) = item
            && let JSXAttributeName::Identifier(id) = &attr.name
        {
            id.name == attr_name
        } else {
            false
        }
    })
}

fn has_jsx_truthy_attr(opening: &JSXOpeningElement<'_>, attr_name: &str) -> bool {
    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let JSXAttributeName::Identifier(id) = &attr.name else {
            continue;
        };
        if id.name != attr_name {
            continue;
        }
        let Some(val) = &attr.value else {
            return true; // boolean shorthand `<Link reloadDocument>`
        };
        if let JSXAttributeValue::ExpressionContainer(c) = val
            && let Some(expr) = c.expression.as_expression()
            && let Expression::BooleanLiteral(b) = expr.without_parentheses()
        {
            return b.value;
        }
        return true;
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
            AstKind::CallExpression(call)
                if extract_callee_short_name(&call.callee) == Some("useEffect") =>
            {
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
    let path_part = url.split(['?', '#']).next().unwrap_or(url).to_ascii_lowercase();
    RESOURCE_EXTENSIONS.iter().any(|ext| path_part.ends_with(ext))
}

fn find_member_calls_in_statements(
    statements: &[Statement<'_>],
    objects: &[&str],
    methods: &[&str],
) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    for stmt in statements {
        collect_member_calls_in_stmt(stmt, objects, methods, &mut out);
    }
    out
}

fn collect_member_calls_in_stmt(
    stmt: &Statement<'_>,
    objects: &[&str],
    methods: &[&str],
    out: &mut Vec<(String, Span)>,
) {
    match stmt {
        Statement::VariableDeclaration(var_decl) => {
            for decl in &var_decl.declarations {
                if let Some(init) = &decl.init
                    && let Some(hit) = find_member_call_in_expr(init, objects, methods)
                {
                    out.push(hit);
                }
            }
        }
        Statement::ExpressionStatement(expr_stmt) => {
            if let Some(hit) = find_member_call_in_expr(&expr_stmt.expression, objects, methods) {
                out.push(hit);
            }
        }
        Statement::ReturnStatement(ret) => {
            if let Some(arg) = &ret.argument
                && let Some(hit) = find_member_call_in_expr(arg, objects, methods)
            {
                out.push(hit);
            }
        }
        Statement::BlockStatement(block) => {
            for s in &block.body {
                collect_member_calls_in_stmt(s, objects, methods, out);
            }
        }
        Statement::IfStatement(if_stmt) => {
            collect_member_calls_in_stmt(&if_stmt.consequent, objects, methods, out);
            if let Some(alt) = &if_stmt.alternate {
                collect_member_calls_in_stmt(alt, objects, methods, out);
            }
        }
        Statement::TryStatement(try_stmt) => {
            for s in &try_stmt.block.body {
                collect_member_calls_in_stmt(s, objects, methods, out);
            }
        }
        _ => {}
    }
}

fn find_member_call_in_expr(
    expr: &Expression<'_>,
    objects: &[&str],
    methods: &[&str],
) -> Option<(String, Span)> {
    match expr.without_parentheses() {
        Expression::AwaitExpression(aw) => find_member_call_in_expr(&aw.argument, objects, methods),
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                && objects.contains(&obj_id.name.as_str())
                && methods.contains(&mem.property.name.as_str())
            {
                return Some((mem.property.name.to_string(), call.span));
            }
            for arg in &call.arguments {
                if let Some(arg_expr) = arg.as_expression()
                    && let Some(hit) = find_member_call_in_expr(arg_expr, objects, methods)
                {
                    return Some(hit);
                }
            }
            None
        }
        _ => None,
    }
}

fn find_session_mutations_in_statements(statements: &[Statement<'_>]) -> Vec<(String, Span)> {
    let mut session_vars = vec!["session".to_string()];
    for stmt in statements {
        if let Statement::VariableDeclaration(var_decl) = stmt {
            for decl in &var_decl.declarations {
                if let Some(id) = decl.id.get_binding_identifier()
                    && let Some(init) = &decl.init
                    && expr_calls_function(init, "getSession")
                {
                    session_vars.push(id.name.to_string());
                }
            }
        }
    }
    let refs: Vec<&str> = session_vars.iter().map(String::as_str).collect();
    find_member_calls_in_statements(statements, &refs, &["set", "flash", "unset"])
}

fn expr_calls_function(expr: &Expression<'_>, fn_name: &str) -> bool {
    match expr.without_parentheses() {
        Expression::AwaitExpression(aw) => expr_calls_function(&aw.argument, fn_name),
        Expression::CallExpression(call) => extract_callee_short_name(&call.callee) == Some(fn_name),
        _ => false,
    }
}

fn contains_call_to_ident(src: &str, ident: &str) -> bool {
    src.contains(&format!("{ident}("))
}

fn find_calls_to_ident_in_statements(
    statements: &[Statement<'_>],
    ident: &str,
) -> Vec<Span> {
    let mut spans = Vec::new();
    for stmt in statements {
        collect_calls_to_ident_in_stmt(stmt, ident, &mut spans);
    }
    spans
}

fn collect_calls_to_ident_in_stmt(
    stmt: &Statement<'_>,
    ident: &str,
    spans: &mut Vec<Span>,
) {
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
