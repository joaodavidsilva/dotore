//! TanStack Start (`tanstack-start-*`) server functions, loaders, and root route rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, FormalParameters,
        FunctionBody,
        JSXChild, JSXElement, JSXElementName, JSXMemberExpressionObject, ObjectExpression,
        ObjectPropertyKind, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    ImportedBindingInfo, MUTATING_HTTP_METHODS, TANSTACK_MIDDLEWARE_METHOD_ORDER,
    extract_static_http_method, is_inside_use_effect_execution,
    router_and_invalidation::{
        check_loader_parallel_fetch, check_route_property_order, extract_route_options_object,
    },
};
use crate::{
    ir::{
        react_ast::{is_direct_render_phase_node, is_use_effect_call},
        types::SemanticRuleSite,
    },
    matchers::push_semantic_site,
    rules::RuleId,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all CallExpression-rooted TanStack Start rules in one visit"
)]
pub(crate) fn check_tanstack_start_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    is_routes_file: bool,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. Server function chain rules (`createServerFn(...)`)
    check_server_fn_chain_rules(call, subject_name, source, line_starts, sites);

    // 2. Route options rules (`createFileRoute`, `createRoute`, `createRootRoute`, `createRootRouteWithContext`)
    if let Some(options_obj) = extract_route_options_object(call) {
        check_route_property_order(options_obj, subject_name, line_starts, sites);
        check_loader_parallel_fetch(
            semantic,
            options_obj,
            subject_name,
            source,
            line_starts,
            sites,
        );
        check_no_secrets_in_loader(semantic, options_obj, subject_name, line_starts, sites);
        check_no_direct_fetch_in_loader(semantic, options_obj, subject_name, line_starts, sites);
    }

    // 3. `tanstack-start-no-navigate-in-render`
    if let Expression::Identifier(callee_id) = call.callee.without_parentheses()
        && callee_id.name == "navigate"
        && is_direct_render_phase_node(semantic, node_id)
    {
        push_semantic_site(
            sites,
            RuleId::TanstackStartNoNavigateInRender,
            subject_name.clone(),
            "tanstackStartNoNavigateInRender",
            "navigate",
            "Calling navigate() during render causes hydration mismatches; use <Navigate /> or throw redirect() in beforeLoad/loader.".to_string(),
            line_starts,
            call.span,
        );
    }

    // 4. `tanstack-start-no-use-effect-fetch` (in routes directory)
    if is_routes_file
        && is_use_effect_call(semantic, call)
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && effect_callback_has_direct_fetch(semantic, first_arg.span())
    {
        push_semantic_site(
            sites,
            RuleId::TanstackStartNoUseEffectFetch,
            subject_name.clone(),
            "tanstackStartNoUseEffectFetch",
            "fetch",
            "fetch() inside useEffect makes your users wait through a loading spinner after render."
                .to_string(),
            line_starts,
            call.span,
        );
    }
}

struct ServerFnChainInfo {
    pub(crate) is_server_fn_chain: bool,
    pub(crate) specified_method: Option<String>,
    pub(crate) has_input_validation: bool,
    pub(crate) method_names: Vec<String>,
}

fn walk_server_fn_chain(outer_call: &CallExpression<'_>) -> ServerFnChainInfo {
    let mut info = ServerFnChainInfo {
        is_server_fn_chain: false,
        specified_method: None,
        has_input_validation: false,
        method_names: Vec::new(),
    };

    let mut current_expr = &outer_call.callee;
    if let Expression::StaticMemberExpression(mem) = current_expr.without_parentheses() {
        info.method_names.push(mem.property.name.to_string());
        current_expr = &mem.object;
    } else {
        return info;
    }

    while let Expression::CallExpression(inner_call) = current_expr.without_parentheses() {
        match inner_call.callee.without_parentheses() {
            Expression::Identifier(id) if id.name == "createServerFn" => {
                info.is_server_fn_chain = true;
                if let Some(Argument::ObjectExpression(opts)) = inner_call.arguments.first() {
                    info.specified_method = extract_static_http_method(opts);
                }
                break;
            }
            Expression::StaticMemberExpression(mem) => {
                let method_name = mem.property.name.as_str();
                if matches!(method_name, "validator" | "inputValidator") {
                    info.has_input_validation = true;
                }
                info.method_names.push(method_name.to_string());
                current_expr = &mem.object;
            }
            _ => break,
        }
    }

    info.method_names.reverse();
    info
}

fn check_server_fn_chain_rules(
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(callee_mem) = call.callee.without_parentheses() else {
        return;
    };
    let own_method = callee_mem.property.name.as_str();
    let chain = walk_server_fn_chain(call);
    if !chain.is_server_fn_chain {
        return;
    }

    if own_method == "handler" || chain.method_names.last().map(String::as_str) == Some(own_method)
    {
        check_server_fn_method_order(
            call.span,
            own_method,
            &chain.method_names,
            subject_name,
            line_starts,
            sites,
        );
    }

    if own_method != "handler" {
        return;
    }

    let Some(handler_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let (params, body_opt, handler_span) = match handler_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => (
            &arrow.params,
            match &arrow.body {
                ArrowFunctionBody::FunctionBody(b) => Some(b.as_ref()),
                _ => None,
            },
            arrow.span,
        ),
        Expression::FunctionExpression(func) => (&func.params, func.body.as_deref(), func.span),
        _ => return,
    };

    if body_opt.is_some_and(function_body_has_use_server) {
        push_semantic_site(
            sites,
            RuleId::TanstackStartNoUseServerInHandler,
            subject_name.clone(),
            "tanstackStartNoUseServerInHandler",
            "use server",
            "\"use server\" inside a createServerFn handler duplicates TanStack Start's server boundary, so the route can fail to compile.".to_string(),
            line_starts,
            handler_span,
        );
    }

    if !chain.has_input_validation && handler_accesses_input_data(params, handler_span, source) {
        push_semantic_site(
            sites,
            RuleId::TanstackStartServerFnValidateInput,
            subject_name.clone(),
            "tanstackStartServerFnValidateInput",
            "handler",
            "This server function reads network data with no validator(), so anyone can send unvalidated input.".to_string(),
            line_starts,
            call.span,
        );
    }

    let is_mutating_method = chain
        .specified_method
        .as_deref()
        .is_some_and(|m| MUTATING_HTTP_METHODS.contains(&m));
    if !is_mutating_method && let Some(side_effect) = find_handler_side_effect(handler_span, source)
    {
        push_semantic_site(
            sites,
            RuleId::TanstackStartGetMutation,
            subject_name.clone(),
            "tanstackStartGetMutation",
            side_effect,
            format!(
                "This GET server function's side effect ({side_effect}) is vulnerable to CSRF attacks."
            ),
            line_starts,
            call.span,
        );
    }
}

fn check_server_fn_method_order(
    call_span: Span,
    own_method: &str,
    method_names: &[String],
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut last_idx: Option<usize> = None;
    for m in method_names {
        let normalized = if m == "inputValidator" {
            "validator"
        } else {
            m.as_str()
        };
        let Some(curr_idx) = TANSTACK_MIDDLEWARE_METHOD_ORDER
            .iter()
            .position(|&item| item == normalized)
        else {
            continue;
        };
        if let Some(prev_idx) = last_idx
            && curr_idx < prev_idx
        {
            if own_method == "handler"
                && let Some(&expected_before) = TANSTACK_MIDDLEWARE_METHOD_ORDER.get(prev_idx)
            {
                push_semantic_site(
                    sites,
                    RuleId::TanstackStartServerFnMethodOrder,
                    subject_name.clone(),
                    "tanstackStartServerFnMethodOrder",
                    m,
                    format!("Chaining .{m}() after .{expected_before}() breaks type inference."),
                    line_starts,
                    call_span,
                );
            }
            break;
        }
        last_idx = Some(curr_idx);
    }
}

fn function_body_has_use_server(body: &FunctionBody<'_>) -> bool {
    body.directives
        .iter()
        .any(|d| d.directive.as_str() == "use server")
        || body.statements.iter().any(|s| {
            if let Statement::ExpressionStatement(es) = s
                && let Expression::StringLiteral(lit) = es.expression.without_parentheses()
            {
                lit.value == "use server"
            } else {
                false
            }
        })
}

fn handler_accesses_input_data(
    params: &FormalParameters<'_>,
    handler_span: Span,
    source: &str,
) -> bool {
    let Some(first_param) = params.items.first() else {
        return false;
    };
    match &first_param.pattern {
        BindingPattern::ObjectPattern(pat) => pat
            .properties
            .iter()
            .any(|p| p.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("data")),
        BindingPattern::BindingIdentifier(id) => {
            let param_name = id.name.as_str();
            let body_text = handler_span.source_text(source);
            body_text.contains(&format!("{param_name}.data"))
                || (body_text.contains("data")
                    && (body_text.contains(&format!("= {param_name}"))
                        || body_text.contains(&format!("={param_name}"))))
        }
        _ => false,
    }
}

fn find_handler_side_effect(handler_span: Span, source: &str) -> Option<&'static str> {
    let body_text = handler_span.source_text(source);
    for (pattern, label) in [
        (".insert(", "db.insert"),
        (".update(", "db.update"),
        (".delete(", "db.delete"),
        (".upsert(", "db.upsert"),
        (".create(", "db.create"),
        (".destroy(", "db.destroy"),
        (".writeFile(", "fs.writeFile"),
        (".unlink(", "fs.unlink"),
        ("method: \"POST\"", "POST fetch"),
        ("method: 'POST'", "POST fetch"),
        ("method: \"DELETE\"", "DELETE fetch"),
        ("method: 'DELETE'", "DELETE fetch"),
    ] {
        if body_text.contains(pattern) {
            return Some(label);
        }
    }
    None
}

fn check_no_secrets_in_loader(
    semantic: &Semantic<'_>,
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let prop_key = prop.key.static_name();
        let Some(key_name) = prop_key.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        if !matches!(key_name, "loader" | "beforeLoad") {
            continue;
        }

        let loader_span = prop.value.span();
        for (node_id, node) in semantic.nodes().iter_enumerated() {
            let AstKind::StaticMemberExpression(mem) = node.kind() else {
                continue;
            };
            if !loader_span.contains_inclusive(mem.span) {
                continue;
            }
            // Skip if inside an inline `createServerFn().handler(...)`
            if is_inside_server_fn_handler(semantic, node_id, loader_span) {
                continue;
            }

            let env_source = match mem.object.without_parentheses() {
                Expression::StaticMemberExpression(inner) if inner.property.name == "env" => {
                    match inner.object.without_parentheses() {
                        Expression::Identifier(id) if id.name == "process" => Some("process.env"),
                        Expression::ImportMeta(_) => Some("import.meta.env"),
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(env_src) = env_source else {
                continue;
            };
            let var_name = mem.property.name.as_str();
            if is_likely_secret_env_name(var_name) {
                push_semantic_site(
                    sites,
                    RuleId::TanstackStartNoSecretsInLoader,
                    subject_name.clone(),
                    "tanstackStartNoSecretsInLoader",
                    var_name,
                    format!(
                        "Reading {env_src}.{var_name} in {key_name} leaks this secret to the client, where anyone can read it."
                    ),
                    line_starts,
                    mem.span,
                );
            }
        }
    }
}

fn check_no_direct_fetch_in_loader(
    semantic: &Semantic<'_>,
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let prop_key = prop.key.static_name();
        let Some(key_name) = prop_key.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        if !matches!(key_name, "loader" | "beforeLoad") {
            continue;
        }
        let loader_span = prop.value.span();
        for (node_id, node) in semantic.nodes().iter_enumerated() {
            let AstKind::CallExpression(call) = node.kind() else {
                continue;
            };
            if !loader_span.contains_inclusive(call.span) {
                continue;
            }
            if is_inside_server_fn_handler(semantic, node_id, loader_span) {
                continue;
            }
            let is_fetch = match call.callee.without_parentheses() {
                Expression::Identifier(id) => id.name == "fetch",
                Expression::StaticMemberExpression(mem) => {
                    mem.property.name == "fetch"
                        && matches!(mem.object.without_parentheses(), Expression::Identifier(id) if matches!(id.name.as_str(), "window" | "globalThis"))
                }
                _ => false,
            };
            if is_fetch {
                push_semantic_site(
                    sites,
                    RuleId::TanstackStartNoDirectFetchInLoader,
                    subject_name.clone(),
                    "tanstackStartNoDirectFetchInLoader",
                    "fetch",
                    "Direct `fetch()` in a route loader bypasses TanStack Start's typed RPC boundary; call a `createServerFn` instead.".to_string(),
                    line_starts,
                    call.span,
                );
            }
        }
    }
}

fn is_inside_server_fn_handler(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    loader_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_span = semantic.nodes().get_node(anc_id).span();
        if !loader_span.contains_inclusive(anc_span) {
            break;
        }
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
            && mem.property.name == "handler"
            && walk_server_fn_chain(call).is_server_fn_chain
        {
            return true;
        }
    }
    false
}

fn is_likely_secret_env_name(name: &str) -> bool {
    if matches!(name, "NODE_ENV" | "MODE" | "DEV" | "PROD") {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("secret")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("password")
        || lower.contains("private")
}

fn effect_callback_has_direct_fetch(semantic: &Semantic<'_>, callback_span: Span) -> bool {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !callback_span.contains_inclusive(call.span) {
            continue;
        }
        if let Expression::Identifier(id) = call.callee.without_parentheses()
            && id.name == "fetch"
            && is_inside_use_effect_execution(semantic, node_id)
        {
            return true;
        }
    }
    false
}

pub(crate) fn check_dynamic_server_fn_import(
    imp_expr: &oxc_ast::ast::ImportExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let spec = match imp_expr.source.without_parentheses() {
        Expression::StringLiteral(s) => s.value.as_str(),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
            tpl.quasis.first().map(|q| q.value.raw.as_str())
        }
        _ => None,
    };
    let Some(import_path) = spec else {
        return;
    };

    let is_functions_file = import_path.ends_with(".functions")
        || import_path.ends_with(".functions.ts")
        || import_path.ends_with(".functions.tsx")
        || import_path.ends_with(".functions.js")
        || import_path.ends_with(".functions.jsx");

    if is_functions_file {
        push_semantic_site(
            sites,
            RuleId::TanstackStartNoDynamicServerFnImport,
            subject_name.clone(),
            "tanstackStartNoDynamicServerFnImport",
            import_path,
            "Dynamically importing a server-functions file leaks server code into the client bundle.".to_string(),
            line_starts,
            imp_expr.span,
        );
    }
}

pub(crate) fn check_missing_head_content(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut head_content_names: HashSet<String> = HashSet::from(["HeadContent".to_string()]);
    for (local, imp) in imports {
        if imp.imported_name == "HeadContent" {
            head_content_names.insert(local.clone());
        }
    }

    let mut has_head_el = false;
    let mut has_head_content = false;

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        if let JSXElementName::Identifier(id) = &jsx_el.opening_element.name
            && id.name == "head"
        {
            has_head_el = true;
            if jsx_subtree_has_head_content_or_custom(jsx_el, &head_content_names) {
                has_head_content = true;
            }
        }
    }

    if has_head_el && !has_head_content {
        push_semantic_site(
            sites,
            RuleId::TanstackStartMissingHeadContent,
            None,
            "tanstackStartMissingHeadContent",
            "HeadContent",
            "Without <HeadContent /> in the __root route, your route head() meta tags never render.".to_string(),
            line_starts,
            program.span,
        );
    }
}

fn jsx_subtree_has_head_content_or_custom(
    head_el: &JSXElement<'_>,
    head_content_names: &HashSet<String>,
) -> bool {
    for child in &head_el.children {
        let JSXChild::Element(child_el) = child else {
            continue;
        };
        match &child_el.opening_element.name {
            JSXElementName::Identifier(id) => {
                if head_content_names.contains(id.name.as_str()) {
                    return true;
                }
            }
            JSXElementName::IdentifierReference(id) => {
                if head_content_names.contains(id.name.as_str())
                    || id
                        .name
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_uppercase())
                {
                    return true;
                }
            }
            JSXElementName::MemberExpression(mem) => {
                if mem.property.name == "HeadContent" || is_custom_jsx_member(&mem.object) {
                    return true;
                }
            }
            JSXElementName::NamespacedName(_) | JSXElementName::ThisExpression(_) => {}
        }
    }
    false
}

fn is_custom_jsx_member(obj: &JSXMemberExpressionObject<'_>) -> bool {
    match obj {
        JSXMemberExpressionObject::IdentifierReference(id) => id
            .name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase()),
        JSXMemberExpressionObject::MemberExpression(inner) => is_custom_jsx_member(&inner.object),
        JSXMemberExpressionObject::ThisExpression(_) => false,
    }
}

pub(crate) fn check_missing_scripts(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut scripts_names: HashSet<String> = HashSet::from(["Scripts".to_string()]);
    for (local, imp) in imports {
        if imp.imported_name == "Scripts" {
            scripts_names.insert(local.clone());
        }
    }

    let mut has_body_el = false;
    let mut has_scripts_in_body = false;

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        if let JSXElementName::Identifier(id) = &jsx_el.opening_element.name
            && id.name == "body"
        {
            has_body_el = true;
            let body_src = jsx_el.span.source_text(semantic.source_text());
            if scripts_names
                .iter()
                .any(|s| body_src.contains(&format!("<{s}")) || body_src.contains(&format!(".{s}")))
            {
                has_scripts_in_body = true;
            }
        }
    }

    if has_body_el && !has_scripts_in_body {
        push_semantic_site(
            sites,
            RuleId::TanstackStartMissingScripts,
            None,
            "tanstackStartMissingScripts",
            "Scripts",
            "Without <Scripts /> inside <body>, the __root route does not load TanStack Start's client-side JavaScript.".to_string(),
            line_starts,
            program.span,
        );
    }
}
