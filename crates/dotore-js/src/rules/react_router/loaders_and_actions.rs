//! React Router v7/v8 loader, action, session, cookie, `handleError`, `meta`,
//! `useLoaderData` in `ErrorBoundary`, and `redirect` in `try/catch` rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, BindingPattern, CallExpression, Expression, FormalParameters,
        ObjectExpression, ObjectPropertyKind, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    REMOVED_V8_FUTURE_FLAGS, expr_calls_function, find_member_call_in_expr,
    find_member_calls_in_statements, get_object_prop,
    navigation_and_links::check_search_params_in_statements, push_site,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    rules::RuleId,
};

#[expect(
    clippy::too_many_arguments,
    reason = "function-like dispatcher passes params, body statements, and semantic context"
)]
pub(crate) fn check_function_like_rules(
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
pub(crate) fn check_arrow_function_rules(
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

pub(crate) fn get_arrow_assigned_name<'a>(
    semantic: &'a Semantic<'a>,
    node_id: NodeId,
) -> Option<&'a str> {
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
        && let Some(id) = decl.id.get_binding_identifier()
    {
        return Some(id.name.as_str());
    }
    None
}

pub(crate) fn check_inline_route_handler_expr(
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
pub(crate) fn check_loader_or_action_statements(
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
                &format!(
                    "`{role_name}` reads `request.{method}()`; loaders run on GET requests and must not read a request body (use `action` instead)."
                ),
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
                    &format!(
                        "`{role_name}` mutates session state via `session.{method}(...)`; move session mutations into an `action`."
                    ),
                    *span,
                    None,
                );
            }
        } else {
            // In an `action`: verify `commitSession` or `destroySession` is called and Set-Cookie is returned
            let commits_session =
                fn_src.contains("commitSession") || fn_src.contains("destroySession");
            if !commits_session && let Some((method, span)) = session_mutations.first() {
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
            &format!(
                "`{role_name}` reads `request.{method}()`; loaders run on GET requests and must not read a request body."
            ),
            call_span,
            None,
        );
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
                if prop
                    .key
                    .static_name()
                    .is_some_and(|n| n.as_str() == Some("data"))
                {
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
pub(crate) fn check_static_cookie_expires(
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
pub(crate) fn check_use_loader_data_in_error_ui(
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
pub(crate) fn check_redirect_in_try_catch(
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
                        &format!(
                            "`{callee_name}()` inside a `try` block can be swallowed or mishandled if thrown or caught; move `{callee_name}()` outside `try/catch`."
                        ),
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

pub(super) fn is_inside_middleware_array_export(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
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

pub(super) fn check_middleware_statements(
    fn_name: &str,
    params: &FormalParameters<'_>,
    statements: &[Statement<'_>],
    fn_span: Span,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let next_name = extract_middleware_next_param_name(params).unwrap_or("next");

    for stmt in statements {
        if let Statement::TryStatement(try_stmt) = stmt
            && try_stmt.handler.is_some()
            && contains_call_to_ident(try_stmt.block.span.source_text(source), next_name)
        {
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

    let next_call_spans = find_calls_to_ident_in_statements(statements, next_name);
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
    params
        .items
        .get(1)
        .and_then(|second| second.pattern.get_binding_identifier())
        .map(|id| id.name.as_str())
}

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
                if stmt_has_value_return_or_throw(&if_stmt.consequent)
                    || if_stmt
                        .alternate
                        .as_ref()
                        .is_some_and(|alt| stmt_has_value_return_or_throw(alt))
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
