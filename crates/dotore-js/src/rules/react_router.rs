//! React Router v7 and v8 (`react-router-*`) single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

pub(crate) mod loaders_and_actions;
pub(crate) mod navigation_and_links;
pub(crate) mod routes_and_middleware;

use std::{collections::HashMap, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        Expression, JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement,
        JSXElementName, JSXOpeningElement, ObjectExpression, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::{
    ir::{react_ast::callee_name, types::SemanticRuleSite},
    matchers::{
        find_jsx_attr, get_object_prop as matcher_get_object_prop,
        get_object_prop_bool as matcher_get_object_prop_bool,
        get_object_prop_static_str as matcher_get_object_prop_static_str,
        has_jsx_attr as matcher_has_jsx_attr, jsx_attr_expr as matcher_jsx_attr_expr,
        jsx_attr_string_value, push_semantic_site_with_fix,
    },
    rules::{AutofixPatch, RuleId},
};

use self::{
    loaders_and_actions::{
        check_arrow_function_rules, check_function_like_rules, get_arrow_assigned_name,
    },
    navigation_and_links::{check_call_expression_rules, check_jsx_element_rules},
    routes_and_middleware::{
        check_imports_and_collect_client_symbols, check_removed_future_flags,
        check_route_module_environment_suffix, collect_subject_router_traits,
    },
};

pub(crate) const DATA_ROUTER_FACTORIES: &[&str] = &[
    "createBrowserRouter",
    "createMemoryRouter",
    "createHashRouter",
    "createStaticRouter",
    "createRoutesStub",
];

pub(crate) const ROUTER_JSX_COMPONENTS: &[&str] = &[
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

pub(crate) const IMMUTABLE_ROUTE_PROPERTIES: &[&str] =
    &["id", "path", "index", "children", "caseSensitive"];

pub(crate) const REMOVED_V8_FUTURE_FLAGS: &[&str] = &[
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

pub(crate) const RESOURCE_EXTENSIONS: &[&str] = &[
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
    let (components_with_routes, components_with_outlet) = collect_subject_router_traits(semantic);

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
pub(crate) fn push_site(
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
    push_semantic_site_with_fix(
        sites,
        rule,
        subject_name,
        message_id,
        target_name,
        message.to_string(),
        line_starts,
        span,
        autofix,
    );
}

// --- Shared AST/JSX/Object helper utilities ---

pub(crate) fn get_object_prop<'a>(
    obj: &'a ObjectExpression<'a>,
    name: &str,
) -> Option<(Span, &'a Expression<'a>)> {
    let prop = matcher_get_object_prop(obj, name)?;
    Some((prop.span, &prop.value))
}

pub(crate) fn get_object_prop_static_str(obj: &ObjectExpression<'_>, name: &str) -> Option<String> {
    matcher_get_object_prop_static_str(obj, name).map(str::to_string)
}

pub(crate) fn get_object_prop_static_str_with_span(
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

pub(crate) fn get_object_prop_bool(obj: &ObjectExpression<'_>, name: &str) -> Option<bool> {
    matcher_get_object_prop_bool(obj, name)
}

pub(crate) fn extract_component_ref_name(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::JSXElement(jsx_el) => jsx_element_tag_name(&jsx_el.opening_element.name),
        _ => None,
    }
}

pub(crate) fn is_component_defined_in_file(semantic: &Semantic<'_>, comp_name: &str) -> bool {
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

pub(crate) fn jsx_subtree_contains_outlet(jsx_el: &JSXElement<'_>) -> bool {
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

pub(crate) fn jsx_element_tag_name(name: &JSXElementName<'_>) -> Option<String> {
    match name {
        JSXElementName::Identifier(id) => Some(id.name.to_string()),
        JSXElementName::IdentifierReference(id) => Some(id.name.to_string()),
        JSXElementName::NamespacedName(ns) => {
            Some(format!("{}:{}", ns.namespace.name, ns.name.name))
        }
        JSXElementName::MemberExpression(mem) => Some(mem.property.name.to_string()),
        JSXElementName::ThisExpression(_) => None,
    }
}

pub(crate) fn get_jsx_attr_static_str(
    opening: &JSXOpeningElement<'_>,
    attr_name: &str,
) -> Option<(String, Span)> {
    let attr = find_jsx_attr(&opening.attributes, attr_name)?;
    let val = jsx_attr_string_value(attr)?;
    Some((val.to_string(), attr.span))
}

pub(crate) fn has_jsx_attr(opening: &JSXOpeningElement<'_>, attr_name: &str) -> bool {
    matcher_has_jsx_attr(&opening.attributes, attr_name)
}

pub(crate) fn get_jsx_attr_expr<'a>(
    opening: &'a JSXOpeningElement<'a>,
    attr_name: &str,
) -> Option<&'a Expression<'a>> {
    matcher_jsx_attr_expr(&opening.attributes, attr_name)
}

pub(crate) fn has_jsx_truthy_attr(opening: &JSXOpeningElement<'_>, attr_name: &str) -> bool {
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

pub(crate) fn find_member_calls_in_statements(
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

pub(crate) fn find_member_call_in_expr(
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

pub(crate) fn expr_calls_function(expr: &Expression<'_>, fn_name: &str) -> bool {
    match expr.without_parentheses() {
        Expression::AwaitExpression(aw) => expr_calls_function(&aw.argument, fn_name),
        Expression::CallExpression(call) => callee_name(&call.callee) == Some(fn_name),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
    use crate::rules::RuleId;

    #[test]
    fn react_router_submodules_expose_loaders_routes_and_navigation_detectors() {
        let _ = (
            super::loaders_and_actions::check_loader_or_action_statements as fn(_, _, _, _, _, _),
            super::routes_and_middleware::check_route_module_environment_suffix as fn(_, _, _, _),
            super::navigation_and_links::check_transition_navigation_promise as fn(_, _, _, _, _),
        );

        let ir = parse_file_ir(
            Path::new("app/routes/dashboard.server.tsx"),
            r#"
import { Link } from "react-router-dom";

export async function loader({ request }: { request: Request }) {
    const body = await request.json();
    return body;
}

export function Dashboard() {
    return (
        <div>
            <a href="/settings">Settings</a>
            <Link to="/report.pdf">Report</Link>
        </div>
    );
}
"#,
        );
        let rules: Vec<RuleId> = ir.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::ReactRouterNoRouteModuleEnvironmentSuffix));
        assert!(rules.contains(&RuleId::ReactRouterV8NoReactRouterDomImport));
        assert!(rules.contains(&RuleId::ReactRouterNoLoaderRequestBody));
        assert!(rules.contains(&RuleId::ReactRouterInternalRouteAnchor));
        assert!(rules.contains(&RuleId::ReactRouterResourceLinkRequiresReload));
    }
}
