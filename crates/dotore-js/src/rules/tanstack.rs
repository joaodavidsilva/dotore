//! TanStack Query (`query-*`) and TanStack Start (`tanstack-start-*`) rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

pub(crate) mod query;
pub(crate) mod router_and_invalidation;
pub(crate) mod start;

use std::{collections::HashMap, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Expression, ObjectExpression, ObjectPropertyKind, Program,
        Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name, is_use_effect_call},
        types::SemanticRuleSite,
    },
    matchers::{member_call_parts, unwrap_expr},
};

use self::{
    query::{
        check_query_call_rules, check_query_rest_destructuring_and_spread,
        check_stable_query_client,
    },
    router_and_invalidation::{
        check_mutation_in_effect_as_read, check_no_anchor_element, check_redirect_in_try_catch,
    },
    start::{
        check_dynamic_server_fn_import, check_missing_head_content, check_missing_scripts,
        check_tanstack_start_call_rules,
    },
};

pub(crate) const TANSTACK_QUERY_HOOKS: &[&str] = &[
    "useQuery",
    "useInfiniteQuery",
    "useSuspenseQuery",
    "useSuspenseInfiniteQuery",
];

pub(crate) const TANSTACK_MUTATION_HOOKS: &[&str] = &["useMutation"];

pub(crate) const QUERY_CACHE_UPDATE_METHODS: &[&str] = &[
    "invalidateQueries",
    "setQueryData",
    "setQueriesData",
    "resetQueries",
    "refetchQueries",
    "removeQueries",
    "cancelQueries",
    "clear",
];

pub(crate) const MUTATING_HTTP_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

pub(crate) const READ_ONLY_MUTATION_WORDS: &[&str] = &[
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

pub(crate) const WRITE_INTENT_WORDS: &[&str] = &[
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

pub(crate) const TANSTACK_ROUTE_PROPERTY_ORDER: &[&str] = &[
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

pub(crate) const TANSTACK_ROUTE_CREATION_FUNCTIONS: &[&str] = &[
    "createFileRoute",
    "createRoute",
    "createRootRoute",
    "createRootRouteWithContext",
];

pub(crate) const TANSTACK_MIDDLEWARE_METHOD_ORDER: &[&str] =
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
pub(crate) struct ImportedBindingInfo {
    pub(crate) source: String,
    pub(crate) imported_name: String,
    pub(crate) is_namespace: bool,
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

pub(crate) fn is_tanstack_query_source(src: &str) -> bool {
    (src.starts_with("@tanstack/") && src.contains("query")) || src == "react-query"
}

fn static_member_prop_name<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    if let Some(parts) = member_call_parts(expr) {
        return Some(parts);
    }
    if let Expression::ComputedMemberExpression(comp) = unwrap_expr(expr)
        && let Expression::TemplateLiteral(tpl) = unwrap_expr(&comp.expression)
        && tpl.expressions.is_empty()
    {
        let raw = tpl.quasis.first()?.value.raw.as_str();
        return Some((&comp.object, raw));
    }
    None
}

pub(crate) fn is_identifier_shadowed_by_local(
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

pub(crate) fn resolve_const_initializer<'a>(
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

pub(crate) fn resolve_tanstack_hook_call<'a>(
    semantic: &'a Semantic<'a>,
    expr: &'a Expression<'a>,
    imports: &HashMap<String, ImportedBindingInfo>,
    allowed_hooks: &[&str],
    allow_unimported: bool,
) -> Option<(&'a CallExpression<'a>, String)> {
    let mut current = unwrap_expr(expr);
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
                current = unwrap_expr(resolve_const_initializer(semantic, ident)?);
            }
            _ => return None,
        }
    }
    None
}

pub(crate) fn resolve_tanstack_callee_name<'a>(
    semantic: &'a Semantic<'a>,
    callee: &'a Expression<'a>,
    imports: &HashMap<String, ImportedBindingInfo>,
    allowed_hooks: &[&str],
    allow_unimported: bool,
) -> Option<String> {
    let mut current = unwrap_expr(callee);
    for _ in 0..5 {
        if let Expression::Identifier(ident) = current {
            let name = ident.name.as_str();
            if is_identifier_shadowed_by_local(semantic, ident) {
                if let Some(init) = resolve_const_initializer(semantic, ident) {
                    current = unwrap_expr(init);
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
            let mut ns_expr = unwrap_expr(obj);
            for _ in 0..4 {
                if let Expression::Identifier(ns_ident) = ns_expr {
                    if is_identifier_shadowed_by_local(semantic, ns_ident) {
                        if let Some(init) = resolve_const_initializer(semantic, ns_ident) {
                            ns_expr = unwrap_expr(init);
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

pub(crate) fn extract_static_http_method(opts_obj: &ObjectExpression<'_>) -> Option<String> {
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

pub(crate) fn is_inside_use_effect_execution(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
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

pub(crate) fn is_tanstack_observer_method_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    method_name: &str,
    allowed_hooks: &[&str],
    reject_reassigned: bool,
) -> bool {
    let callee = unwrap_expr(&call.callee);
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
        if let Expression::Identifier(obj_ident) = unwrap_expr(obj)
            && let Some(init) = resolve_const_initializer(semantic, obj_ident)
            && resolve_tanstack_hook_call(semantic, init, imports, allowed_hooks, true).is_some()
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
    use crate::rules::RuleId;

    #[test]
    fn tanstack_submodules_expose_query_start_and_invalidation_detectors() {
        let _ = (
            super::query::check_stable_query_client as fn(_, _, _, _, _, _),
            super::start::check_tanstack_start_call_rules as fn(_, _, _, _, _, _, _, _),
            super::router_and_invalidation::check_mutation_missing_invalidation
                as fn(_, _, _, _, _, _, _),
        );

        let ir = parse_file_ir(
            Path::new("src/routes/index.tsx"),
            r#"
import { useQuery, useMutation, QueryClient } from "@tanstack/react-query";

export function Page() {
    const client = new QueryClient();
    const { data, ...rest } = useQuery({ queryKey: ["todos"], queryFn: () => {} });
    const mutation = useMutation({ mutationFn: (x: string) => saveTodo(x) });
    return <a href="/dashboard">{String(Boolean(client) || Boolean(data) || Boolean(rest) || Boolean(mutation))}</a>;
}
"#,
        );
        let rules: Vec<RuleId> = ir.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::QueryStableQueryClient));
        assert!(rules.contains(&RuleId::QueryNoRestDestructuring));
        assert!(rules.contains(&RuleId::QueryNoVoidQueryFn));
        assert!(rules.contains(&RuleId::QueryMutationMissingInvalidation));
        assert!(rules.contains(&RuleId::TanstackStartNoAnchorElement));
    }
}
