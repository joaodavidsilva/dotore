//! TanStack Query (`query-*`) and TanStack Start (`tanstack-start-*`) rule detectors.
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
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, FormalParameters,
        FunctionBody, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement, JSXElementName,
        JSXMemberExpressionObject, ObjectExpression, ObjectPropertyKind, Program, Statement,
        VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{
            find_enclosing_react_node, get_subject_name, is_direct_render_phase_node,
            is_use_effect_call,
        },
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const TANSTACK_QUERY_HOOKS: &[&str] = &[
    "useQuery",
    "useInfiniteQuery",
    "useSuspenseQuery",
    "useSuspenseInfiniteQuery",
];

const TANSTACK_MUTATION_HOOKS: &[&str] = &["useMutation"];

const QUERY_CACHE_UPDATE_METHODS: &[&str] = &[
    "invalidateQueries",
    "setQueryData",
    "setQueriesData",
    "resetQueries",
    "refetchQueries",
    "removeQueries",
    "cancelQueries",
    "clear",
];

const MUTATING_HTTP_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

const READ_ONLY_MUTATION_WORDS: &[&str] = &[
    "check",
    "compute",
    "download",
    "estimate",
    "export",
    "fetch",
    "find",
    "generate",
    "get",
    "inspect",
    "list",
    "load",
    "login",
    "logout",
    "lookup",
    "oauth",
    "pair",
    "parse",
    "preview",
    "query",
    "quote",
    "read",
    "render",
    "resolve",
    "search",
    "select",
    "simulate",
    "test",
    "translate",
    "validate",
    "verify",
];

const WRITE_INTENT_WORDS: &[&str] = &[
    "accept",
    "ack",
    "acknowledge",
    "add",
    "append",
    "apply",
    "approve",
    "archive",
    "assign",
    "attach",
    "cancel",
    "change",
    "clear",
    "close",
    "commit",
    "complete",
    "confirm",
    "connect",
    "create",
    "deactivate",
    "decline",
    "delete",
    "destroy",
    "detach",
    "disable",
    "Cancel",
    "disconnect",
    "dismiss",
    "drop",
    "edit",
    "enable",
    "enqueue",
    "execute",
    "flush",
    "grant",
    "import",
    "increment",
    " initialize",
    "insert",
    "invalidate",
    "invite",
    "join",
    "leave",
    "link",
    "lock",
    "log",
    "mark",
    "merge",
    "modify",
    "move",
    "mutate",
    "notify",
    "patch",
    "pause",
    "perform",
    "persist",
    "pin",
    "post",
    "publish",
    "purge",
    "push",
    "put",
    "record",
    "redeem",
    "refresh",
    "register",
    "reject",
    "release",
    "remove",
    "rename",
    "replace",
    "reply",
    "report",
    "reset",
    "restore",
    "resume",
    "retry",
    "revoke",
    "rotate",
    "run",
    "save",
    "schedule",
    "seed",
    "send",
    "set",
    "start",
    "stop",
    "store",
    "submit",
    "subscribe",
    "sync",
    "tag",
    "terminate",
    "toggle",
    "touch",
    "track",
    "transfer",
    "trigger",
    "unarchive",
    "unassign",
    "unbind",
    "unfollow",
    "unlink",
    "unlock",
    "unpin",
    "unpublish",
    "unregister",
    "unsubscribe",
    "update",
    "upgrade",
    "upload",
    "upsert",
    "vote",
    "write",
];

const TANSTACK_ROUTE_PROPERTY_ORDER: &[&str] = &[
    "params",
    "validateSearch",
    "loaderDeps",
    "search.middlewares",
    "ssr",
    "context",
    "beforeLoad",
    "loader",
    "onEnter",
    "onStay",
    "onLeave",
    "head",
    "scripts",
    "headers",
    "remountDeps",
];

const TANSTACK_ROUTE_CREATION_FUNCTIONS: &[&str] = &[
    "createFileRoute",
    "createRoute",
    "createRootRoute",
    "createRootRouteWithContext",
];

const TANSTACK_MIDDLEWARE_METHOD_ORDER: &[&str] =
    &["middleware", "validator", "client", "server", "handler"];

/// Extracts all TanStack Query and TanStack Start semantic rule sites in a single pass.
pub(crate) fn extract_tanstack_sites(
    path: &Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let path_str = path.to_string_lossy().replace('\\', "/");
    let is_routes_file = path_str.contains("/routes/") || path_str.starts_with("routes/");
    let is_root_route = path
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "__root.tsx" | "__root.ts" | "__root.jsx" | "__root.js"
            )
        });

    let imports = collect_file_imports(program);

    // Whole-file root route checks (`__root.tsx`)
    if is_root_route {
        check_missing_head_content(program, semantic, &imports, line_starts, sites);
        check_missing_scripts(program, semantic, &imports, line_starts, sites);
    }

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::NewExpression(new_expr) => {
                if let Expression::Identifier(ident) = new_expr.callee.without_parentheses()
                    && ident.name == "QueryClient"
                {
                    check_stable_query_client(
                        semantic,
                        node_id,
                        new_expr.span,
                        &subject_name,
                        line_starts,
                        sites,
                    );
                }
            }
            AstKind::VariableDeclarator(decl) => {
                check_query_rest_destructuring_and_spread(
                    semantic,
                    node_id,
                    decl,
                    &imports,
                    &subject_name,
                    line_starts,
                    sites,
                );
                check_mutation_in_effect_as_read(
                    semantic,
                    node_id,
                    decl,
                    &imports,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_query_call_rules(
                    semantic,
                    node_id,
                    call,
                    &imports,
                    &subject_name,
                    is_routes_file,
                    line_starts,
                    sites,
                );
                check_tanstack_start_call_rules(
                    semantic,
                    node_id,
                    call,
                    &subject_name,
                    is_routes_file,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::ThrowStatement(throw_stmt) => {
                check_redirect_in_try_catch(
                    semantic,
                    node_id,
                    throw_stmt,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ImportExpression(imp_expr) => {
                check_dynamic_server_fn_import(imp_expr, &subject_name, line_starts, sites);
            }
            AstKind::JSXOpeningElement(opening) if is_routes_file => {
                check_no_anchor_element(opening, &subject_name, line_starts, sites);
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
struct ImportedBindingInfo {
    source: String,
    imported_name: String,
    is_namespace: bool,
}

fn collect_file_imports(program: &Program<'_>) -> HashMap<String, ImportedBindingInfo> {
    let mut map = HashMap::new();
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        let Some(src) = imp.source.value.as_str() else {
            continue;
        };
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            match spec {
                oxc_ast::ast::ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    map.insert(
                        s.local.name.to_string(),
                        ImportedBindingInfo {
                            source: src.to_string(),
                            imported_name: s.imported.name().to_string(),
                            is_namespace: false,
                        },
                    );
                }
                oxc_ast::ast::ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    map.insert(
                        s.local.name.to_string(),
                        ImportedBindingInfo {
                            source: src.to_string(),
                            imported_name: "default".to_string(),
                            is_namespace: false,
                        },
                    );
                }
                oxc_ast::ast::ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                    map.insert(
                        s.local.name.to_string(),
                        ImportedBindingInfo {
                            source: src.to_string(),
                            imported_name: "*".to_string(),
                            is_namespace: true,
                        },
                    );
                }
            }
        }
    }
    map
}

fn is_tanstack_query_source(src: &str) -> bool {
    (src.starts_with("@tanstack/") && src.contains("query")) || src == "react-query"
}

fn unwrap_ts_and_parens<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(ts) => expr = &ts.expression,
            Expression::TSSatisfiesExpression(ts) => expr = &ts.expression,
            Expression::TSNonNullExpression(ts) => expr = &ts.expression,
            Expression::TSTypeAssertion(ts) => expr = &ts.expression,
            Expression::TSInstantiationExpression(ts) => expr = &ts.expression,
            _ => return expr,
        }
    }
}

fn static_member_prop_name<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    match unwrap_ts_and_parens(expr) {
        Expression::StaticMemberExpression(mem) => Some((&mem.object, mem.property.name.as_str())),
        Expression::ComputedMemberExpression(comp) => {
            match unwrap_ts_and_parens(&comp.expression) {
                Expression::StringLiteral(lit) => Some((&comp.object, lit.value.as_str()?)),
                Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
                    let raw = tpl.quasis.first()?.value.raw.as_str();
                    Some((&comp.object, raw))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_identifier_shadowed_by_local(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    !matches!(
        semantic.nodes().kind(decl_id),
        AstKind::ImportSpecifier(_)
            | AstKind::ImportDefaultSpecifier(_)
            | AstKind::ImportNamespaceSpecifier(_)
    )
}

fn resolve_const_initializer<'a>(
    semantic: &'a Semantic<'a>,
    ident: &oxc_ast::ast::IdentifierReference<'a>,
) -> Option<&'a Expression<'a>> {
    let ref_id = ident.reference_id.get()?;
    let sym_id = semantic.scoping().get_reference(ref_id).symbol_id()?;
    // Must not be reassigned
    if semantic
        .scoping()
        .get_resolved_references(sym_id)
        .any(|r| r.is_write())
    {
        return None;
    }
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return None;
    };
    if !matches!(
        semantic.nodes().parent_kind(decl_id),
        AstKind::VariableDeclaration(var_decl) if var_decl.kind == VariableDeclarationKind::Const
    ) {
        return None;
    }
    decl.init.as_ref()
}

fn resolve_tanstack_hook_call<'a>(
    semantic: &'a Semantic<'a>,
    expr: &'a Expression<'a>,
    imports: &HashMap<String, ImportedBindingInfo>,
    allowed_hooks: &[&str],
    allow_unimported: bool,
) -> Option<(&'a CallExpression<'a>, String)> {
    let mut current = unwrap_ts_and_parens(expr);
    for _ in 0..5 {
        match current {
            Expression::CallExpression(call) => {
                let hook_name = resolve_tanstack_callee_name(
                    semantic,
                    &call.callee,
                    imports,
                    allowed_hooks,
                    allow_unimported,
                )?;
                return Some((call, hook_name));
            }
            Expression::Identifier(ident) => {
                current = unwrap_ts_and_parens(resolve_const_initializer(semantic, ident)?);
            }
            _ => return None,
        }
    }
    None
}

fn resolve_tanstack_callee_name<'a>(
    semantic: &'a Semantic<'a>,
    callee: &'a Expression<'a>,
    imports: &HashMap<String, ImportedBindingInfo>,
    allowed_hooks: &[&str],
    allow_unimported: bool,
) -> Option<String> {
    let mut current = unwrap_ts_and_parens(callee);
    for _ in 0..5 {
        if let Expression::Identifier(ident) = current {
            let name = ident.name.as_str();
            if is_identifier_shadowed_by_local(semantic, ident) {
                if let Some(init) = resolve_const_initializer(semantic, ident) {
                    current = unwrap_ts_and_parens(init);
                    continue;
                }
                return None;
            }
            if let Some(imp) = imports.get(name) {
                if !imp.is_namespace
                    && is_tanstack_query_source(&imp.source)
                    && allowed_hooks.contains(&imp.imported_name.as_str())
                {
                    return Some(imp.imported_name.clone());
                }
                return None;
            }
            if allow_unimported && allowed_hooks.contains(&name) {
                return Some(name.to_string());
            }
            return None;
        }
        if let Some((obj, prop_name)) = static_member_prop_name(current) {
            if !allowed_hooks.contains(&prop_name) {
                return None;
            }
            let mut ns_expr = unwrap_ts_and_parens(obj);
            for _ in 0..4 {
                if let Expression::Identifier(ns_ident) = ns_expr {
                    if is_identifier_shadowed_by_local(semantic, ns_ident) {
                        if let Some(init) = resolve_const_initializer(semantic, ns_ident) {
                            ns_expr = unwrap_ts_and_parens(init);
                            continue;
                        }
                        return None;
                    }
                    if let Some(imp) = imports.get(ns_ident.name.as_str())
                        && imp.is_namespace
                        && is_tanstack_query_source(&imp.source)
                    {
                        return Some(prop_name.to_string());
                    }
                    return None;
                }
                break;
            }
            return None;
        }
        return None;
    }
    None
}

fn check_stable_query_client(
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
            let grand_id = semantic.nodes().parent_id(anc_id);
            let is_iife = semantic.nodes().ancestor_ids(anc_id).take(3).any(|p_id| {
                if let AstKind::CallExpression(c) = semantic.nodes().kind(p_id) {
                    c.callee
                        .span()
                        .contains_inclusive(semantic.nodes().get_node(anc_id).span())
                } else {
                    false
                }
            });
            let _ = grand_id;
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

    if !fn_name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
    {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::QueryStableQueryClient,
        subject_name: subject_name.clone(),
        message_id: "queryStableQueryClient",
        target_name: "QueryClient".to_string(),
        message: "new QueryClient() inside a component wipes your cache on every render."
            .to_string(),
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix: None,
    });
}

fn check_query_rest_destructuring_and_spread(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::QueryNoRestDestructuring,
            subject_name: subject_name.clone(),
            message_id: "queryNoRestDestructuring",
            target_name: hook_name.clone(),
            message: format!(
                "Rest-destructuring {hook_name}() subscribes to every field, so it re-renders on each change."
            ),
            loc: loc_from_line_starts(line_starts, obj_pat.span.start),
            span: ByteSpan {
                start: obj_pat.span.start,
                end: obj_pat.span.end,
            },
            autofix: None,
        });
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::QueryDestructureResult,
                    subject_name: subject_name.clone(),
                    message_id: "queryDestructureResult",
                    target_name: callee_name.to_string(),
                    message: format!(
                        "Spreading the whole {callee_name}() result reads every field, so TanStack Query subscribes to all of them and re-renders on each change. Spread only the fields you need."
                    ),
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
            name.starts_with("use")
                && name
                    .chars()
                    .nth(3)
                    .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Passes pre-extracted module imports, file context, and line table without intermediate struct allocation"
)]
fn check_query_call_rules(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::QueryNoQueryInEffect,
            subject_name: subject_name.clone(),
            message_id: "queryNoQueryInEffect",
            target_name: "refetch".to_string(),
            message: "Calling refetch() inside useEffect triggers an extra network request after render; drive the query from its queryKey and enabled option instead.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
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
        sites.push(SemanticRuleSite {
            rule: RuleId::QueryFloatingMutateAsync,
            subject_name: subject_name.clone(),
            message_id: "queryFloatingMutateAsync",
            target_name: "mutateAsync".to_string(),
            message:
                "mutateAsync() returns a Promise that rejects on mutation failure; await it, attach .catch(), or use mutate() instead."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
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
        }
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::QueryNoVoidQueryFn,
                    subject_name: subject_name.clone(),
                    message_id: "noVoidQueryFn",
                    target_name: "useQuery".to_string(),
                    message:
                        "This empty queryFn caches undefined, so the component never gets data."
                            .to_string(),
                    loc: loc_from_line_starts(line_starts, prop.span.start),
                    span: ByteSpan {
                        start: prop.span.start,
                        end: prop.span.end,
                    },
                    autofix: None,
                });
            }
        }

        if !has_polling_interval
            && let Some(method) = find_mutating_http_in_query_fn(semantic, prop.value.span())
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::QueryNoUseQueryForMutation,
                subject_name: subject_name.clone(),
                message_id: "queryNoUseQueryForMutation",
                target_name: method.clone(),
                message: format!(
                    "useQuery with {method} request acts like a mutation; use useMutation so TanStack Query does not auto-retry or background-refetch it."
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
                .and_then(|u| resolve_static_url_text(semantic, u, source))
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

fn extract_static_http_method(opts_obj: &ObjectExpression<'_>) -> Option<String> {
    for prop_kind in &opts_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("method") {
            continue;
        }
        if let Expression::StringLiteral(s) = prop.value.without_parentheses()
            && let Some(val) = s.value.as_str()
        {
            return Some(val.to_ascii_uppercase());
        }
    }
    None
}

fn resolve_static_url_text(
    semantic: &Semantic<'_>,
    url_expr: &Expression<'_>,
    source: &str,
) -> Option<String> {
    match unwrap_ts_and_parens(url_expr) {
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
            let _ = source;
            resolve_static_url_text(semantic, init, source)
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
        }
        let body_text = prop.value.span().source_text(source);
        if body_text.contains("mutation ") || body_text.contains("mutation{") {
            return true;
        }
    }
    false
}

fn is_inside_use_effect_execution(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                let p_id = semantic.nodes().parent_id(anc_id);
                if let AstKind::CallExpression(call) = semantic.nodes().kind(p_id) {
                    if is_use_effect_call(semantic, call)
                        && call.arguments.first().is_some_and(|arg| {
                            arg.span() == semantic.nodes().get_node(anc_id).span()
                        })
                    {
                        return true;
                    }
                    // Allow async IIFE `(() => { refetch(); })()` or `.then(() => refetch())` inside effect
                    if call
                        .callee
                        .span()
                        .contains_inclusive(semantic.nodes().get_node(anc_id).span())
                    {
                        continue;
                    }
                    if let Expression::StaticMemberExpression(mem) =
                        call.callee.without_parentheses()
                        && matches!(mem.property.name.as_str(), "then" | "catch" | "finally")
                    {
                        continue;
                    }
                }
                // Otherwise it's a nested callback (like `onFocus = () => refetch()` or `setInterval(() => refetch())`)
                return false;
            }
            _ => {}
        }
    }
    false
}

fn is_tanstack_observer_method_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    method_name: &str,
    allowed_hooks: &[&str],
    reject_reassigned: bool,
) -> bool {
    let callee = unwrap_ts_and_parens(&call.callee);
    // 1. Direct `refetch()` / `mutateAsync()` or renamed `const { refetch: reload } = useQuery(...)`
    if let Expression::Identifier(ident) = callee {
        let Some(ref_id) = ident.reference_id.get() else {
            return false;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
            return false;
        };
        if reject_reassigned
            && semantic
                .scoping()
                .get_resolved_references(sym_id)
                .any(|r| r.is_write())
        {
            return false;
        }
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        let sym_name = semantic.scoping().symbol_name(sym_id);
        for anc_id in std::iter::once(decl_id).chain(semantic.nodes().ancestor_ids(decl_id)) {
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(anc_id) {
                if let BindingPattern::ObjectPattern(pat) = &decl.id {
                    let is_target_prop = pat.properties.iter().any(|p| {
                        p.key.static_name().as_ref().and_then(|n| n.as_str()) == Some(method_name)
                            && matches!(
                                &p.value,
                                BindingPattern::BindingIdentifier(b) if b.name.as_str() == sym_name
                            )
                    });
                    if is_target_prop
                        && let Some(init) = &decl.init
                        && resolve_tanstack_hook_call(semantic, init, imports, allowed_hooks, true)
                            .is_some()
                    {
                        return true;
                    }
                }
                break;
            }
        }
    }

    // 2. Member call `query.refetch()` / `mutation.mutateAsync()` or computed string equivalent
    if let Some((obj, prop_name)) = static_member_prop_name(callee)
        && prop_name == method_name
    {
        if resolve_tanstack_hook_call(semantic, obj, imports, allowed_hooks, true).is_some() {
            return true;
        }
        if let Expression::Identifier(obj_ident) = unwrap_ts_and_parens(obj)
            && let Some(init) = resolve_const_initializer(semantic, obj_ident)
            && resolve_tanstack_hook_call(semantic, init, imports, allowed_hooks, true).is_some()
        {
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

fn check_mutation_in_effect_as_read(
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
    let Some((mutation_call, _)) =
        resolve_tanstack_hook_call(semantic, init, imports, TANSTACK_MUTATION_HOOKS, true)
    else {
        return;
    };

    // Collect `mutate` / `mutateAsync` trigger symbols and check whether `data` is read or intent is read-like
    let mut trigger_syms: Vec<SymbolId> = Vec::new();
    let mut consumes_data = false;
    let mut binding_names: Vec<String> = Vec::new();

    match &decl.id {
        BindingPattern::ObjectPattern(pat) => {
            for prop in &pat.properties {
                let key_name = prop.key.static_name();
                let key_str = key_name.as_ref().and_then(|n| n.as_str());
                if matches!(key_str, Some("mutate" | "mutateAsync"))
                    && let BindingPattern::BindingIdentifier(id) = &prop.value
                    && let Some(sym) = id.symbol_id.get()
                {
                    trigger_syms.push(sym);
                    binding_names.push(id.name.to_string());
                }
                if key_str == Some("data") {
                    consumes_data = true;
                }
            }
        }
        BindingPattern::BindingIdentifier(id) => {
            binding_names.push(id.name.to_string());
            if let Some(sym) = id.symbol_id.get() {
                trigger_syms.push(sym);
                for r in semantic.scoping().get_resolved_references(sym) {
                    let p_id = semantic.nodes().parent_id(r.node_id());
                    if let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(p_id)
                        && mem.property.name == "data"
                    {
                        consumes_data = true;
                    }
                }
            }
        }
        _ => {}
    }

    if trigger_syms.is_empty() {
        return;
    }

    // Check mutationFn name intent
    if let Some(Argument::ObjectExpression(opts)) = mutation_call.arguments.first() {
        for prop_kind in &opts.properties {
            if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
                && prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("mutationFn")
            {
                let text = prop.value.span().source_text(semantic.source_text());
                binding_names.push(text.to_string());
            }
        }
    }

    let has_read_intent = binding_names
        .iter()
        .any(|n| has_word_in_set(n, READ_ONLY_MUTATION_WORDS));
    let has_write_intent = binding_names
        .iter()
        .any(|n| has_word_in_set(n, WRITE_INTENT_WORDS));

    if !consumes_data && (!has_read_intent || has_write_intent) {
        return;
    }

    for sym_id in trigger_syms {
        for reference in semantic.scoping().get_resolved_references(sym_id) {
            let ref_node_id = reference.node_id();
            let p_id = semantic.nodes().parent_id(ref_node_id);
            let call_span = match semantic.nodes().kind(p_id) {
                AstKind::CallExpression(c) => Some(c.span),
                AstKind::StaticMemberExpression(mem)
                    if matches!(mem.property.name.as_str(), "mutate" | "mutateAsync") =>
                {
                    let gp_id = semantic.nodes().parent_id(p_id);
                    if let AstKind::CallExpression(c) = semantic.nodes().kind(gp_id) {
                        Some(c.span)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(span) = call_span
                && is_inside_use_effect_execution(semantic, ref_node_id)
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::QueryNoMutationInEffectAsRead,
                    subject_name: subject_name.clone(),
                    message_id: "queryNoMutationInEffectAsRead",
                    target_name: "useMutation".to_string(),
                    message: "Triggering useMutation inside useEffect to load data bypasses caching and deduplication; use useQuery instead.".to_string(),
                    loc: loc_from_line_starts(line_starts, span.start),
                    span: ByteSpan {
                        start: span.start,
                        end: span.end,
                    },
                    autofix: None,
                });
                return;
            }
        }
    }
}

fn check_mutation_missing_invalidation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let has_tanstack_import = imports
        .values()
        .any(|i| is_tanstack_query_source(&i.source));
    let has_query_signal_in_file = has_tanstack_import
        || source.contains("useQuery(")
        || source.contains("useQueryClient(")
        || source.contains("useSuspenseQuery(")
        || source.contains("useUtils(");

    if !has_query_signal_in_file {
        return;
    }

    let Some(hook_name) = resolve_tanstack_callee_name(
        semantic,
        &call.callee,
        imports,
        TANSTACK_MUTATION_HOOKS,
        true,
    ) else {
        return;
    };
    let _ = hook_name;

    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::ObjectExpression(opts_obj) = first_arg.without_parentheses() else {
        return;
    };

    // Skip read-only mutation names (check, download, estimate, export, generate, login, logout, verify, etc.)
    if let Some(subj) = subject_name
        && has_word_in_set(subj, READ_ONLY_MUTATION_WORDS)
    {
        return;
    }
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
        && let BindingPattern::BindingIdentifier(id) = &decl.id
        && has_word_in_set(id.name.as_str(), READ_ONLY_MUTATION_WORDS)
    {
        return;
    }

    for prop_kind in &opts_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("mutationFn") {
            let fn_text = prop.value.span().source_text(source);
            if has_word_in_set(fn_text, READ_ONLY_MUTATION_WORDS) {
                return;
            }
        }
    }

    // Check if any lifecycle callback or mutationFn updates/invalidates the query cache
    if span_has_query_cache_update(semantic, opts_obj.span, source) {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::QueryMutationMissingInvalidation,
        subject_name: subject_name.clone(),
        message_id: "queryMutationMissingInvalidation",
        target_name: "useMutation".to_string(),
        message:
            "useMutation does not invalidate or update the query cache in onSuccess/onSettled, leaving cached queries stale."
                .to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn span_has_query_cache_update(semantic: &Semantic<'_>, span: Span, source: &str) -> bool {
    let text = span.source_text(source);
    if text.contains("location.href")
        || text.contains("location.assign")
        || text.contains("location.replace")
        || text.contains("location.reload")
    {
        return true;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(c) => {
                let callee = unwrap_ts_and_parens(&c.callee);
                if let Expression::StaticMemberExpression(mem) = callee {
                    let prop_name = mem.property.name.as_str();
                    if QUERY_CACHE_UPDATE_METHODS.contains(&prop_name) {
                        return true;
                    }
                    if prop_name == "invalidate"
                        && !matches!(
                            mem.object.without_parentheses(),
                            Expression::Identifier(id) if id.name == "session"
                        )
                    {
                        return true;
                    }
                }
                if let Expression::Identifier(id) = callee {
                    let lower = id.name.to_ascii_lowercase();
                    if lower.contains("invalidat")
                        || lower.contains("refetch")
                        || lower.contains("querycache")
                    {
                        // Check if `id` resolves to a local function that does NOT update cache
                        if let Some(ref_id) = id.reference_id.get()
                            && let Some(sym_id) =
                                semantic.scoping().get_reference(ref_id).symbol_id()
                        {
                            let decl_id = semantic.scoping().symbol_declaration(sym_id);
                            if let AstKind::VariableDeclarator(d) = semantic.nodes().kind(decl_id)
                                && let Some(init) = &d.init
                                && matches!(
                                    init.without_parentheses(),
                                    Expression::ArrowFunctionExpression(_)
                                        | Expression::FunctionExpression(_)
                                )
                            {
                                if span_has_query_cache_update(semantic, init.span(), source) {
                                    return true;
                                }
                                continue;
                            }
                        }
                        return true;
                    }
                    if QUERY_CACHE_UPDATE_METHODS.contains(&id.name.as_str()) && id.name != "clear"
                    {
                        return true;
                    }
                }
                // Check if `queryClient` is passed as an argument to a helper
                if c.arguments.iter().any(|arg| {
                    arg.as_expression().is_some_and(|e| {
                        matches!(
                            e.without_parentheses(),
                            Expression::Identifier(id) if id.name == "queryClient"
                        )
                    })
                }) {
                    return true;
                }
            }
            AstKind::IdentifierReference(ident) => {
                // Callback reference like `onSuccess: invalidate`
                if let Some(ref_id) = ident.reference_id.get()
                    && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
                {
                    let decl_id = semantic.scoping().symbol_declaration(sym_id);
                    if let AstKind::Function(func) = semantic.nodes().kind(decl_id)
                        && func.span != span
                        && span_has_query_cache_update(semantic, func.span, source)
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn has_word_in_set(identifier: &str, words: &[&str]) -> bool {
    for token in tokenize_identifier_words(identifier) {
        if words.contains(&token.as_str()) {
            return true;
        }
    }
    false
}

fn tokenize_identifier_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(current.to_ascii_lowercase());
                current.clear();
            }
            continue;
        }
        if ch.is_ascii_uppercase() && !current.is_empty() {
            words.push(current.to_ascii_lowercase());
            current.clear();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all CallExpression-rooted TanStack Start rules in one visit"
)]
fn check_tanstack_start_call_rules(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartNoNavigateInRender,
            subject_name: subject_name.clone(),
            message_id: "tanstackStartNoNavigateInRender",
            target_name: "navigate".to_string(),
            message: "Calling navigate() during render causes hydration mismatches; use <Navigate /> or throw redirect() in beforeLoad/loader.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 4. `tanstack-start-no-use-effect-fetch` (in routes directory)
    if is_routes_file
        && is_use_effect_call(semantic, call)
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && effect_callback_has_direct_fetch(semantic, first_arg.span())
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartNoUseEffectFetch,
            subject_name: subject_name.clone(),
            message_id: "tanstackStartNoUseEffectFetch",
            target_name: "fetch".to_string(),
            message:
                "fetch() inside useEffect makes your users wait through a loading spinner after render."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

struct ServerFnChainInfo {
    is_server_fn_chain: bool,
    specified_method: Option<String>,
    has_input_validation: bool,
    method_names: Vec<String>,
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

    // 1. `tanstack-start-server-fn-method-order` (report on the outermost call that violates order)
    if own_method == "handler" || chain.method_names.last().map(String::as_str) == Some(own_method)
    {
        let mut last_idx: Option<usize> = None;
        for m in &chain.method_names {
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
                if own_method == "handler" {
                    let expected_before = TANSTACK_MIDDLEWARE_METHOD_ORDER[prev_idx];
                    sites.push(SemanticRuleSite {
                        rule: RuleId::TanstackStartServerFnMethodOrder,
                        subject_name: subject_name.clone(),
                        message_id: "tanstackStartServerFnMethodOrder",
                        target_name: m.clone(),
                        message: format!(
                            "Chaining .{m}() after .{expected_before}() breaks type inference."
                        ),
                        loc: loc_from_line_starts(line_starts, call.span.start),
                        span: ByteSpan {
                            start: call.span.start,
                            end: call.span.end,
                        },
                        autofix: None,
                    });
                }
                break;
            }
            last_idx = Some(curr_idx);
        }
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

    // 2. `tanstack-start-no-use-server-in-handler`
    if let Some(body) = body_opt {
        let has_use_server = body
            .directives
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
            });
        if has_use_server {
            sites.push(SemanticRuleSite {
                rule: RuleId::TanstackStartNoUseServerInHandler,
                subject_name: subject_name.clone(),
                message_id: "tanstackStartNoUseServerInHandler",
                target_name: "use server".to_string(),
                message:
                    "\"use server\" inside a createServerFn handler duplicates TanStack Start's server boundary, so the route can fail to compile."
                        .to_string(),
                loc: loc_from_line_starts(line_starts, handler_span.start),
                span: ByteSpan {
                    start: handler_span.start,
                    end: handler_span.end,
                },
                autofix: None,
            });
        }
    }

    // 3. `tanstack-start-server-fn-validate-input`
    if !chain.has_input_validation && handler_accesses_input_data(params, handler_span, source) {
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartServerFnValidateInput,
            subject_name: subject_name.clone(),
            message_id: "tanstackStartServerFnValidateInput",
            target_name: "handler".to_string(),
            message:
                "This server function reads network data with no validator(), so anyone can send unvalidated input."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 4. `tanstack-start-get-mutation`
    let is_mutating_method = chain
        .specified_method
        .as_deref()
        .is_some_and(|m| MUTATING_HTTP_METHODS.contains(&m));
    if !is_mutating_method && let Some(side_effect) = find_handler_side_effect(handler_span, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartGetMutation,
            subject_name: subject_name.clone(),
            message_id: "tanstackStartGetMutation",
            target_name: side_effect.to_string(),
            message: format!(
                "This GET server function's side effect ({side_effect}) is vulnerable to CSRF attacks."
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

fn extract_route_options_object<'a>(
    call: &'a CallExpression<'a>,
) -> Option<&'a ObjectExpression<'a>> {
    let is_route_factory = match call.callee.without_parentheses() {
        Expression::Identifier(id) => TANSTACK_ROUTE_CREATION_FUNCTIONS.contains(&id.name.as_str()),
        Expression::CallExpression(inner) => matches!(
            inner.callee.without_parentheses(),
            Expression::Identifier(id) if TANSTACK_ROUTE_CREATION_FUNCTIONS.contains(&id.name.as_str())
        ),
        _ => false,
    };
    if !is_route_factory {
        return None;
    }
    let first_arg = call.arguments.first()?.as_expression()?;
    if let Expression::ObjectExpression(obj) = first_arg.without_parentheses() {
        Some(obj)
    } else {
        None
    }
}

fn check_route_property_order(
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut last_idx: Option<usize> = None;
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let key_name = prop.key.static_name();
        let Some(prop_name) = key_name.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(curr_idx) = TANSTACK_ROUTE_PROPERTY_ORDER
            .iter()
            .position(|&p| p == prop_name)
        else {
            continue;
        };
        if let Some(prev_idx) = last_idx
            && curr_idx < prev_idx
        {
            let expected_before = TANSTACK_ROUTE_PROPERTY_ORDER[prev_idx];
            sites.push(SemanticRuleSite {
                rule: RuleId::TanstackStartRoutePropertyOrder,
                subject_name: subject_name.clone(),
                message_id: "tanstackStartRoutePropertyOrder",
                target_name: prop_name.to_string(),
                message: format!(
                    "Ordering route property \"{prop_name}\" after \"{expected_before}\" breaks type inference."
                ),
                loc: loc_from_line_starts(line_starts, options_obj.span.start),
                span: ByteSpan {
                    start: options_obj.span.start,
                    end: options_obj.span.end,
                },
                autofix: None,
            });
            return;
        }
        last_idx = Some(curr_idx);
    }
}

fn check_loader_parallel_fetch(
    _semantic: &Semantic<'_>,
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("loader") {
            continue;
        }
        let body_opt = match prop.value.without_parentheses() {
            Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
                ArrowFunctionBody::FunctionBody(b) => Some(b.as_ref()),
                _ => None,
            },
            Expression::FunctionExpression(func) => func.body.as_deref(),
            _ => None,
        };
        let Some(body) = body_opt else {
            continue;
        };

        if has_two_independent_top_level_awaits(body, source) {
            sites.push(SemanticRuleSite {
                rule: RuleId::TanstackStartLoaderParallelFetch,
                subject_name: subject_name.clone(),
                message_id: "tanstackStartLoaderParallelFetch",
                target_name: "loader".to_string(),
                message:
                    "Sequential awaits in this loader create a request waterfall that slows the route."
                        .to_string(),
                loc: loc_from_line_starts(line_starts, prop.span.start),
                span: ByteSpan {
                    start: prop.span.start,
                    end: prop.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn has_two_independent_top_level_awaits(body: &FunctionBody<'_>, source: &str) -> bool {
    let mut prior_bindings: Vec<String> = Vec::new();
    let mut independent_await_count = 0usize;

    for stmt in &body.statements {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    let Some(init) = &decl.init else {
                        continue;
                    };
                    let Expression::AwaitExpression(await_expr) = init.without_parentheses() else {
                        continue;
                    };
                    let arg_text = await_expr.argument.span().source_text(source);
                    let depends_on_prior = prior_bindings
                        .iter()
                        .any(|b| contains_identifier_token(arg_text, b));
                    if !depends_on_prior {
                        independent_await_count += 1;
                    }
                    collect_pattern_binding_names(&decl.id, &mut prior_bindings);
                }
            }
            Statement::ExpressionStatement(es) => {
                if let Expression::AwaitExpression(await_expr) = es.expression.without_parentheses()
                {
                    let arg_text = await_expr.argument.span().source_text(source);
                    let depends_on_prior = prior_bindings
                        .iter()
                        .any(|b| contains_identifier_token(arg_text, b));
                    if !depends_on_prior {
                        independent_await_count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    independent_await_count >= 2
}

fn collect_pattern_binding_names(pat: &BindingPattern<'_>, out: &mut Vec<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => out.push(id.name.to_string()),
        BindingPattern::ObjectPattern(obj) => {
            for p in &obj.properties {
                collect_pattern_binding_names(&p.value, out);
            }
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter().flatten() {
                collect_pattern_binding_names(elem, out);
            }
        }
        BindingPattern::AssignmentPattern(assign) => {
            collect_pattern_binding_names(&assign.left, out);
        }
    }
}

fn contains_identifier_token(haystack: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(ident) {
        let before_ok = idx == 0
            || !haystack.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && haystack.as_bytes()[idx - 1] != b'_'
                && haystack.as_bytes()[idx - 1] != b'$';
        let after_idx = idx + ident.len();
        let after_ok = after_idx == haystack.len()
            || !haystack.as_bytes()[after_idx].is_ascii_alphanumeric()
                && haystack.as_bytes()[after_idx] != b'_'
                && haystack.as_bytes()[after_idx] != b'$';
        if before_ok && after_ok {
            return true;
        }
    }
    false
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::TanstackStartNoSecretsInLoader,
                    subject_name: subject_name.clone(),
                    message_id: "tanstackStartNoSecretsInLoader",
                    target_name: var_name.to_string(),
                    message: format!(
                        "Reading {env_src}.{var_name} in {key_name} leaks this secret to the client, where anyone can read it."
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::TanstackStartNoDirectFetchInLoader,
                    subject_name: subject_name.clone(),
                    message_id: "tanstackStartNoDirectFetchInLoader",
                    target_name: "fetch".to_string(),
                    message: "Direct `fetch()` in a route loader bypasses TanStack Start's typed RPC boundary; call a `createServerFn` instead.".to_string(),
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

fn check_redirect_in_try_catch(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    throw_stmt: &oxc_ast::ast::ThrowStatement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::CallExpression(call) = throw_stmt.argument.without_parentheses() else {
        return;
    };
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    if !matches!(callee_id.name.as_str(), "redirect" | "notFound") {
        return;
    }

    let source = semantic.source_text();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                // Stop at non-IIFE function boundary
                let is_iife = semantic.nodes().ancestor_ids(anc_id).take(3).any(|p_id| {
                    if let AstKind::CallExpression(c) = semantic.nodes().kind(p_id) {
                        c.callee
                            .span()
                            .contains_inclusive(semantic.nodes().get_node(anc_id).span())
                    } else {
                        false
                    }
                });
                if !is_iife {
                    break;
                }
            }
            AstKind::TryStatement(try_stmt) => {
                // Only applies if `throw` is inside the `try` block (`try_stmt.block`)
                if !try_stmt.block.span.contains_inclusive(throw_stmt.span) {
                    continue;
                }
                let Some(handler) = &try_stmt.handler else {
                    continue;
                };
                let catch_text = handler.body.span.source_text(source);
                let catch_rethrows = catch_text.contains("throw ");
                if !catch_rethrows {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::TanstackStartRedirectInTryCatch,
                        subject_name: subject_name.clone(),
                        message_id: "tanstackStartRedirectInTryCatch",
                        target_name: callee_id.name.to_string(),
                        message: format!(
                            "throw {}() inside a try block gets swallowed, so the redirect silently fails.",
                            callee_id.name
                        ),
                        loc: loc_from_line_starts(line_starts, throw_stmt.span.start),
                        span: ByteSpan {
                            start: throw_stmt.span.start,
                            end: throw_stmt.span.end,
                        },
                        autofix: None,
                    });
                    return;
                }
            }
            _ => {}
        }
    }
}

fn check_dynamic_server_fn_import(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartNoDynamicServerFnImport,
            subject_name: subject_name.clone(),
            message_id: "tanstackStartNoDynamicServerFnImport",
            target_name: import_path.to_string(),
            message:
                "Dynamically importing a server-functions file leaks server code into the client bundle."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, imp_expr.span.start),
            span: ByteSpan {
                start: imp_expr.span.start,
                end: imp_expr.span.end,
            },
            autofix: None,
        });
    }
}

fn check_no_anchor_element(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let JSXElementName::Identifier(ident) = &opening.name else {
        return;
    };
    if ident.name != "a" {
        return;
    }

    let mut href_val: Option<&str> = None;
    let mut has_download = false;
    let mut is_target_blank = false;

    for attr_item in &opening.attributes {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        match attr_id.name.as_str() {
            "download" => has_download = true,
            "target" => {
                if extract_jsx_attr_string_value(attr.value.as_ref()) == Some("_blank") {
                    is_target_blank = true;
                }
            }
            "href" => {
                href_val = extract_jsx_attr_string_value(attr.value.as_ref());
            }
            _ => {}
        }
    }

    if has_download || is_target_blank {
        return;
    }
    let Some(href) = href_val else {
        return;
    };
    if !href.starts_with('/') || href.starts_with("//") {
        return;
    }
    let pathname = href.split(['?', '#']).next().unwrap_or(href);
    if pathname.starts_with("/api/") {
        return;
    }
    if let Some(last_dot) = pathname.rfind('.') {
        let ext = &pathname[last_dot + 1..];
        if !ext.is_empty() && ext.len() <= 8 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return;
        }
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::TanstackStartNoAnchorElement,
        subject_name: subject_name.clone(),
        message_id: "tanstackStartNoAnchorElement",
        target_name: "a".to_string(),
        message:
            "Plain <a> reloads the whole page for internal navigation, so TanStack Router loses client state and preloading."
                .to_string(),
        loc: loc_from_line_starts(line_starts, opening.span.start),
        span: ByteSpan {
            start: opening.span.start,
            end: opening.span.end,
        },
        autofix: None,
    });
}

fn extract_jsx_attr_string_value<'a>(val: Option<&'a JSXAttributeValue<'a>>) -> Option<&'a str> {
    match val? {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
        JSXAttributeValue::ExpressionContainer(c) => match &c.expression {
            oxc_ast::ast::JSXExpression::StringLiteral(s) => s.value.as_str(),
            _ => None,
        },
        _ => None,
    }
}

fn check_missing_head_content(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartMissingHeadContent,
            subject_name: None,
            message_id: "tanstackStartMissingHeadContent",
            target_name: "HeadContent".to_string(),
            message:
                "Without <HeadContent /> in the __root route, your route head() meta tags never render."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, program.span.start),
            span: ByteSpan {
                start: program.span.start,
                end: program.span.end,
            },
            autofix: None,
        });
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

fn check_missing_scripts(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::TanstackStartMissingScripts,
            subject_name: None,
            message_id: "tanstackStartMissingScripts",
            target_name: "Scripts".to_string(),
            message:
                "Without <Scripts /> inside <body>, the __root route does not load TanStack Start's client-side JavaScript."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, program.span.start),
            span: ByteSpan {
                start: program.span.start,
                end: program.span.end,
            },
            autofix: None,
        });
    }
}
