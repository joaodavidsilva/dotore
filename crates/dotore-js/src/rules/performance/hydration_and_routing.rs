//! Hydration, SSR/browser globals, locale formatting, and React Router loader performance rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
)]

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, JSXAttributeItem, JSXAttributeName,
        ObjectPropertyKind, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{BROWSER_GLOBALS, extract_jsx_identifier_name, is_react_named_hook_call};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::{is_global_ident, push_semantic_site, unwrap_expr},
    rules::RuleId,
};

pub(super) fn check_rendering_hydration_mismatch_time(
    node_id: NodeId,
    container: &oxc_ast::ast::JSXExpressionContainer<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(expr) = container.expression.as_expression() else {
        return;
    };
    // Skip if inside a JSX attribute named `transition` on a motion element, or parent has `suppressHydrationWarning`
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let has_suppress = el.opening_element.attributes.iter().any(|a| {
                if let JSXAttributeItem::Attribute(attr) = a
                    && let JSXAttributeName::Identifier(id) = &attr.name
                {
                    id.name == "suppressHydrationWarning"
                } else {
                    false
                }
            });
            if has_suppress {
                return;
            }
            break;
        }
    }

    let matched_label = match unwrap_expr(expr) {
        Expression::NewExpression(new_expr) => {
            if matches!(unwrap_expr(&new_expr.callee), Expression::Identifier(id) if id.name == "Date")
                && new_expr.arguments.is_empty()
            {
                Some("new Date()")
            } else {
                None
            }
        }
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
                && let Expression::Identifier(obj_id) = unwrap_expr(&mem.object)
            {
                match (obj_id.name.as_str(), mem.property.name.as_str()) {
                    ("Date", "now") => Some("Date.now()"),
                    ("Math", "random") => Some("Math.random()"),
                    ("performance", "now") => Some("performance.now()"),
                    ("crypto", "randomUUID") => Some("crypto.randomUUID()"),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    };

    if let Some(display) = matched_label {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::RenderingHydrationMismatchTime,
            subject_name,
            "renderingHydrationMismatchTime",
            display,
            format!(
                "This can cause a hydration mismatch because {display} in JSX gives a different value on the server than in the browser. Move it into useEffect+useState to run only in the browser, or add suppressHydrationWarning to the parent if it's on purpose."
            ),
            line_starts,
            container.span,
        );
    }
}

pub(super) fn check_rendering_hydration_no_flicker(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_named_hook_call(call, "useEffect") {
        return;
    }
    let Some(Expression::ArrayExpression(deps)) = call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)
        .map(unwrap_expr)
    else {
        return;
    };
    if !deps.elements.is_empty() {
        return;
    }
    let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb_text = cb_arg.span().source_text(semantic.source_text());
    if (cb_text.contains("window.innerWidth")
        || cb_text.contains("window.innerHeight")
        || cb_text.contains("window.matchMedia"))
        && cb_text.contains("addEventListener")
        && cb_text.contains("set")
    {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::RenderingHydrationNoFlicker,
            subject_name,
            "renderingHydrationNoFlicker",
            "useEffect",
            "Synchronizing viewport/media state inside `useEffect` flashes after first paint; prefer CSS media queries or `useSyncExternalStore`.".to_string(),
            line_starts,
            call.span,
        );
    }
}

pub(super) fn check_no_hydration_branch_on_browser_global(
    node_id: NodeId,
    test: &Expression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    let test_text = test.span().source_text(semantic.source_text());
    if test_text.contains("typeof window") || test_text.contains("typeof document") {
        let subject_name = get_subject_name(semantic, subj_id);
        push_semantic_site(
            out,
            RuleId::NoHydrationBranchOnBrowserGlobal,
            subject_name,
            "noHydrationBranchOnBrowserGlobal",
            "typeof window",
            "Branching on `typeof window` or `typeof document` during render causes server and client HTML to diverge during hydration.".to_string(),
            line_starts,
            test.span(),
        );
    }
}

pub(super) fn check_no_unguarded_browser_global_in_render(
    node_id: NodeId,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let name = ident.name.as_str();
    if !BROWSER_GLOBALS.contains(&name) || !is_global_ident(semantic, ident) {
        return;
    }
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    // Must be in render body, not inside a nested callback (`useEffect`, event handler, etc.)
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        if anc_id == subj_id {
            break;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => return,
            AstKind::UnaryExpression(u) if u.operator == oxc_ast::ast::UnaryOperator::Typeof => {
                return;
            }
            AstKind::IfStatement(if_stmt) => {
                let test_src = if_stmt.test.span().source_text(semantic.source_text());
                if test_src.contains("typeof ") || test_src.contains(name) {
                    return;
                }
            }
            AstKind::ConditionalExpression(cond) => {
                let test_src = cond.test.span().source_text(semantic.source_text());
                if test_src.contains("typeof ") || test_src.contains(name) {
                    return;
                }
            }
            _ => {}
        }
    }
    // Check if preceded by an availability early return in the component body
    let subj_span = semantic.nodes().get_node(subj_id).span();
    let prefix = &semantic.source_text()[subj_span.start as usize..ident.span.start as usize];
    if prefix.contains("typeof window") || prefix.contains("typeof document") {
        return;
    }

    let subject_name = get_subject_name(semantic, subj_id);
    push_semantic_site(
        out,
        RuleId::NoUnguardedBrowserGlobalInRenderOrHookInit,
        subject_name,
        "noUnguardedBrowserGlobalInRenderOrHookInit",
        name,
        format!(
            "`{name}` is read while React is rendering on the server, where browser globals are unavailable. Move the read into an effect or event, or provide a stable server snapshot."
        ),
        line_starts,
        ident.span,
    );
}

pub(super) fn check_no_locale_format_in_render(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let method = mem.property.name.as_str();
    if !matches!(
        method,
        "toLocaleString" | "toLocaleDateString" | "toLocaleTimeString"
    ) {
        return;
    }
    if !call.arguments.is_empty() {
        return;
    }
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    let in_nested_fn = semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .take_while(|&anc_id| anc_id != subj_id)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        });
    if in_nested_fn {
        return;
    }

    let subject_name = get_subject_name(semantic, subj_id);
    push_semantic_site(
        out,
        RuleId::NoLocaleFormatInRender,
        subject_name,
        "noLocaleFormatInRender",
        method,
        format!(
            "This can cause a hydration mismatch because .{method}() formats with the server's locale and timezone during server rendering but the user's in the browser. Format it in a post-mount useEffect, or pass an explicit locale and timeZone."
        ),
        line_starts,
        call.span,
    );
}

pub(super) fn check_react_router_prefer_route_lazy(
    _node_id: NodeId,
    obj: &oxc_ast::ast::ObjectExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut has_path = false;
    let mut has_lazy = false;
    let mut comp_prop: Option<(Span, &Expression<'_>)> = None;

    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let Some(k) = prop
            .key
            .static_name()
            .and_then(|n| n.as_str().map(str::to_string))
        else {
            continue;
        };
        match k.as_str() {
            "path" | "index" => has_path = true,
            "lazy" => has_lazy = true,
            "Component" | "element" => comp_prop = Some((prop.span, &prop.value)),
            _ => {}
        }
    }
    if !has_path || has_lazy {
        return;
    }
    let Some((prop_span, comp_val)) = comp_prop else {
        return;
    };
    let comp_ident_name: Option<&str> = match unwrap_expr(comp_val) {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::JSXElement(el) => extract_jsx_identifier_name(&el.opening_element.name),
        _ => None,
    };
    let Some(target_name) = comp_ident_name else {
        return;
    };
    let is_react_lazy = semantic.nodes().iter_enumerated().any(|(_, n)| {
        if let AstKind::VariableDeclarator(decl) = n.kind()
            && decl
                .id
                .get_binding_identifier()
                .is_some_and(|id| id.name == target_name)
            && let Some(init) = &decl.init
        {
            let src = init.span().source_text(semantic.source_text());
            src.contains("lazy(")
        } else {
            false
        }
    });
    if is_react_lazy {
        push_semantic_site(
            out,
            RuleId::ReactRouterPreferRouteLazy,
            None,
            "reactRouterPreferRouteLazy",
            target_name,
            "React.lazy defers only the component; use the route lazy property to load the full route module in parallel.".to_string(),
            line_starts,
            prop_span,
        );
    }
}

pub(super) fn check_react_router_loader_parallel_fetch(
    node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    if !is_react_router_loader_fn(semantic, parent_id) {
        return;
    }
    let mut fetch_await_spans = Vec::new();
    for stmt in statements {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        if var_decl.declarations.len() == 1
            && let Some(init) = &var_decl.declarations[0].init
            && let Expression::AwaitExpression(aw) = unwrap_expr(init)
            && let Expression::CallExpression(call) = unwrap_expr(&aw.argument)
            && matches!(unwrap_expr(&call.callee), Expression::Identifier(id) if id.name == "fetch")
        {
            fetch_await_spans.push(stmt.span());
        }
    }
    if fetch_await_spans.len() >= 2 {
        let span = fetch_await_spans[1];
        push_semantic_site(
            out,
            RuleId::ReactRouterLoaderParallelFetch,
            Some("loader".to_string()),
            "reactRouterLoaderParallelFetch",
            "fetch",
            "Independent awaits run sequentially in this loader and create a navigation waterfall."
                .to_string(),
            line_starts,
            span,
        );
    }
}

pub(super) fn check_react_router_loader_fetch_forwards_signal(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
        return;
    };
    if callee_id.name != "fetch" || !is_global_ident(semantic, callee_id) {
        return;
    }
    let Some(loader_id) = semantic
        .nodes()
        .ancestor_ids(node_id)
        .find(|&anc_id| is_react_router_loader_fn(semantic, anc_id))
    else {
        return;
    };
    let loader_src = semantic
        .nodes()
        .get_node(loader_id)
        .span()
        .source_text(semantic.source_text());
    if !loader_src.contains("request") {
        return;
    }
    let call_src = call.span.source_text(semantic.source_text());
    if call_src.contains("signal") {
        return;
    }
    push_semantic_site(
        out,
        RuleId::ReactRouterLoaderFetchForwardsSignal,
        Some("loader".to_string()),
        "reactRouterLoaderFetchForwardsSignal",
        "fetch",
        "fetch() in this loader does not receive request.signal, so abandoned navigation work continues.".to_string(),
        line_starts,
        call.span,
    );
}

fn is_react_router_loader_fn(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(f) => {
            f.id.as_ref()
                .is_some_and(|id| id.name == "loader" || id.name == "clientLoader")
        }
        AstKind::ArrowFunctionExpression(_) => {
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(node_id) {
                decl.id
                    .get_binding_identifier()
                    .is_some_and(|id| id.name == "loader" || id.name == "clientLoader")
            } else {
                false
            }
        }
        _ => false,
    }
}
