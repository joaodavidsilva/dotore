//! React re-render performance, hydration, motion, and rendering rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
)]
#![expect(
    clippy::excessive_nesting,
    reason = "JSX attribute and object property AST destructuring traverses opening element, attribute, container, and object property layers directly"
)]

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BinaryOperator, BindingPattern, CallExpression, Expression,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName,
        JSXMemberExpressionObject, LogicalOperator, ObjectPropertyKind, Statement,
        VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{find_enclosing_react_node, get_subject_name, is_component_name},
        types::{ModuleIr, SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const LAYOUT_PROPERTIES: &[&str] = &[
    "width",
    "height",
    "top",
    "left",
    "right",
    "bottom",
    "padding",
    "paddingTop",
    "paddingRight",
    "paddingBottom",
    "paddingLeft",
    "margin",
    "marginTop",
    "marginRight",
    "marginBottom",
    "marginLeft",
    "borderWidth",
    "fontSize",
    "lineHeight",
    "gap",
];

const MOTION_ANIMATE_PROPS: &[&str] = &[
    "animate",
    "initial",
    "exit",
    "whileHover",
    "whileTap",
    "whileFocus",
    "whileDrag",
    "whileInView",
];

const INDIVIDUAL_MOTION_TRANSFORM_PROPS: &[&str] = &[
    "x",
    "y",
    "z",
    "translateX",
    "translateY",
    "translateZ",
    "scale",
    "scaleX",
    "scaleY",
    "rotate",
    "rotateX",
    "rotateY",
    "rotateZ",
    "skewX",
    "skewY",
    "transformPerspective",
];

const HIGH_FREQUENCY_DOM_EVENTS: &[&str] = &[
    "scroll",
    "mousemove",
    "wheel",
    "pointermove",
    "touchmove",
    "drag",
];

const DEP_HOOK_NAMES: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useMemo",
    "useCallback",
    "useInsertionEffect",
    "useImperativeHandle",
];

const CHEAP_CONSTRUCTORS: &[&str] = &[
    "Boolean",
    "Number",
    "Object",
    "String",
    "Array",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Date",
    "RegExp",
    "URL",
    "URLSearchParams",
    "Headers",
    "DOMRect",
    "DOMRectReadOnly",
    "DOMPoint",
    "DOMPointReadOnly",
    "DOMMatrix",
    "DOMMatrixReadOnly",
    "DOMQuad",
    "Path2D",
];

const BROWSER_GLOBALS: &[&str] = &[
    "window",
    "document",
    "localStorage",
    "sessionStorage",
    "navigator",
    "location",
    "history",
    "screen",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoStatus {
    Memoized,
    CustomComparatorMemo,
    NotMemoized,
}

/// Extracts React re-render, hydration, motion, and rendering performance rule sites.
pub(crate) fn extract_performance_sites(
    _path: &Path,
    semantic: &Semantic<'_>,
    _module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let memo_registry = build_same_file_memo_registry(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && is_component_name(id.name.as_str())
                    && let Some(body) = &func.body
                {
                    check_component_function(
                        node_id,
                        &func.params.items,
                        &body.statements,
                        body.span,
                        &memo_registry,
                        semantic,
                        line_starts,
                        out,
                    );
                }
                check_unbounded_animation_frame_loop(
                    node_id,
                    func.id.as_ref().map(|i| i.name.as_str()),
                    func.body.as_ref().map(|b| b.span),
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && let Some(init) = &decl.init
                {
                    let name = id.name.as_str();
                    if is_component_name(name)
                        && let Some((params, stmts, body_span)) = extract_component_fn_parts(init)
                    {
                        check_component_function(
                            node_id,
                            params,
                            stmts,
                            body_span,
                            &memo_registry,
                            semantic,
                            line_starts,
                            out,
                        );
                    }
                    let fn_body_span = match unwrap_expr(init) {
                        Expression::ArrowFunctionExpression(a) => Some(a.body.span()),
                        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| b.span),
                        _ => None,
                    };
                    check_unbounded_animation_frame_loop(
                        node_id,
                        Some(name),
                        fn_body_span,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                check_rerender_transitions_scroll(node_id, call, semantic, line_starts, out);
                check_no_match_media_in_state_initializer(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                check_no_eager_new_in_use_state_initializer(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                check_no_usememo_simple_expression(node_id, call, semantic, line_starts, out);
                check_no_unthrottled_scroll_mutation(node_id, call, semantic, line_starts, out);
                check_no_global_css_variable_animation(node_id, call, semantic, line_starts, out);
                check_web_animation_keyframes(node_id, call, semantic, line_starts, out);
                check_motion_value_constructor_in_render(node_id, call, semantic, line_starts, out);
                check_rendering_hydration_no_flicker(node_id, call, semantic, line_starts, out);
                check_no_locale_format_in_render(node_id, call, semantic, line_starts, out);
                check_react_router_loader_fetch_forwards_signal(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_jsx_opening_performance_rules(
                    node_id,
                    opening,
                    &memo_registry,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::JSXExpressionContainer(container) => {
                check_rendering_hydration_mismatch_time(
                    node_id,
                    container,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::ObjectExpression(obj) => {
                check_react_router_prefer_route_lazy(node_id, obj, semantic, line_starts, out);
            }
            AstKind::FunctionBody(body) => {
                check_react_router_loader_parallel_fetch(
                    node_id,
                    &body.statements,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::IdentifierReference(ident) => {
                check_no_unguarded_browser_global_in_render(
                    node_id,
                    ident,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::ConditionalExpression(cond) => {
                check_no_hydration_branch_on_browser_global(
                    node_id,
                    &cond.test,
                    semantic,
                    line_starts,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn unwrap_expr<'a>(mut expr: &'a Expression<'a>) -> &'a Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(ts) => expr = &ts.expression,
            Expression::TSSatisfiesExpression(ts) => expr = &ts.expression,
            Expression::TSNonNullExpression(ts) => expr = &ts.expression,
            Expression::TSTypeAssertion(ts) => expr = &ts.expression,
            _ => return expr,
        }
    }
}

fn is_global_ident(semantic: &Semantic<'_>, ident: &oxc_ast::ast::IdentifierReference<'_>) -> bool {
    ident.reference_id.get().is_none_or(|ref_id| {
        semantic
            .scoping()
            .get_reference(ref_id)
            .symbol_id()
            .is_none()
    })
}

fn resolve_ident_symbol(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    let ref_id = ident.reference_id.get()?;
    semantic.scoping().get_reference(ref_id).symbol_id()
}

fn build_same_file_memo_registry(semantic: &Semantic<'_>) -> HashMap<String, MemoStatus> {
    let mut registry = HashMap::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && is_component_name(id.name.as_str())
                {
                    registry
                        .entry(id.name.to_string())
                        .or_insert(MemoStatus::NotMemoized);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                let Some(id) = decl.id.get_binding_identifier() else {
                    continue;
                };
                if !is_component_name(id.name.as_str()) {
                    continue;
                }
                let Some(init) = &decl.init else {
                    continue;
                };
                match classify_memo_call_init(init, semantic) {
                    Some(status) => {
                        registry.insert(id.name.to_string(), status);
                    }
                    None => {
                        if matches!(
                            unwrap_expr(init),
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        ) {
                            registry.insert(id.name.to_string(), MemoStatus::NotMemoized);
                        }
                    }
                }
            }
            AstKind::ExportDefaultDeclaration(exp) => {
                if let oxc_ast::ast::ExportDefaultDeclarationKind::CallExpression(call) =
                    &exp.declaration
                    && is_memo_callee(&call.callee)
                    && let Some(first_arg) =
                        call.arguments.first().and_then(Argument::as_expression)
                    && let Expression::Identifier(inner_id) = unwrap_expr(first_arg)
                {
                    let status = if has_custom_memo_comparator(call, semantic) {
                        MemoStatus::CustomComparatorMemo
                    } else {
                        MemoStatus::Memoized
                    };
                    registry.insert(inner_id.name.to_string(), status);
                }
            }
            _ => {}
        }
    }
    registry
}

fn classify_memo_call_init(expr: &Expression<'_>, semantic: &Semantic<'_>) -> Option<MemoStatus> {
    let Expression::CallExpression(call) = unwrap_expr(expr) else {
        return None;
    };
    if !is_memo_callee(&call.callee) {
        return None;
    }
    if has_custom_memo_comparator(call, semantic) {
        Some(MemoStatus::CustomComparatorMemo)
    } else {
        Some(MemoStatus::Memoized)
    }
}

fn is_memo_callee(callee: &Expression<'_>) -> bool {
    match unwrap_expr(callee) {
        Expression::Identifier(id) => id.name == "memo",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "memo"
                && matches!(unwrap_expr(&mem.object), Expression::Identifier(id) if id.name == "React")
        }
        _ => false,
    }
}

fn has_custom_memo_comparator(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return false;
    };
    match unwrap_expr(second_arg) {
        Expression::Identifier(id) => {
            if (id.name == "undefined" || id.name == "shallowEqual")
                && resolve_ident_symbol(semantic, id).is_none_or(|sym| {
                    semantic
                        .scoping()
                        .symbol_flags(sym)
                        .contains(SymbolFlags::Import)
                })
            {
                return false;
            }
            true
        }
        _ => true,
    }
}

fn extract_component_fn_parts<'a>(
    expr: &'a Expression<'a>,
) -> Option<(
    &'a [oxc_ast::ast::FormalParameter<'a>],
    &'a [Statement<'a>],
    Span,
)> {
    let mut cur = unwrap_expr(expr);
    while let Expression::CallExpression(call) = cur {
        let first_arg = call.arguments.first().and_then(Argument::as_expression)?;
        cur = unwrap_expr(first_arg);
    }
    match cur {
        Expression::ArrowFunctionExpression(arrow) => {
            let ArrowFunctionBody::FunctionBody(body) = &arrow.body else {
                return None;
            };
            Some((&arrow.params.items, &body.statements, body.span))
        }
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            Some((&func.params.items, &body.statements, body.span))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Component-body rules:
// 1. `rerender-memo-with-default-value`
// 2. `rerender-memo-before-early-return`
// 3. `rerender-derived-state-from-hook`
// 4. `rendering-hoist-jsx`
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "Passes unpacked component signature, body statements, and shared registries together"
)]
fn check_component_function(
    comp_node_id: NodeId,
    params: &[oxc_ast::ast::FormalParameter<'_>],
    statements: &[Statement<'_>],
    body_span: Span,
    memo_registry: &HashMap<String, MemoStatus>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let subject_name = get_subject_name(semantic, comp_node_id);
    check_rerender_memo_with_default_value(
        &subject_name,
        params,
        statements,
        body_span,
        memo_registry,
        semantic,
        line_starts,
        out,
    );
    check_rerender_memo_before_early_return(&subject_name, statements, semantic, line_starts, out);
    check_rerender_derived_state_from_hook(
        &subject_name,
        statements,
        body_span,
        semantic,
        line_starts,
        out,
    );
    check_rendering_hoist_jsx(&subject_name, statements, semantic, line_starts, out);
    check_rendering_usetransition_loading(
        &subject_name,
        statements,
        body_span,
        semantic,
        line_starts,
        out,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyLiteralKind {
    Object,
    Array,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Inspects parameter and body destructuring defaults against component body uses"
)]
fn check_rerender_memo_with_default_value(
    subject_name: &Option<String>,
    params: &[oxc_ast::ast::FormalParameter<'_>],
    statements: &[Statement<'_>],
    body_span: Span,
    memo_registry: &HashMap<String, MemoStatus>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut defaults: Vec<(String, EmptyLiteralKind, Span)> = Vec::new();
    for param in params {
        collect_empty_defaults_from_pattern(&param.pattern, &mut defaults);
    }
    if let Some(first_param) = params.first()
        && let Some(props_id) = first_param.pattern.get_binding_identifier()
    {
        for stmt in statements {
            if let Statement::VariableDeclaration(var_decl) = stmt {
                for decl in &var_decl.declarations {
                    if let Some(init) = &decl.init
                        && matches!(unwrap_expr(init), Expression::Identifier(id) if id.name == props_id.name)
                    {
                        collect_empty_defaults_from_pattern(&decl.id, &mut defaults);
                    }
                }
            }
        }
    }
    if defaults.is_empty() {
        return;
    }

    for (name, kind, def_span) in defaults {
        let mut used_in_deps = false;
        let mut used_in_memo_prop = false;

        for (_, node) in semantic.nodes().iter_enumerated() {
            if !body_span.contains_inclusive(node.span()) {
                continue;
            }
            match node.kind() {
                AstKind::CallExpression(call) => {
                    if is_hook_with_deps_call(call) {
                        for arg in &call.arguments {
                            if let Some(Expression::ArrayExpression(arr)) =
                                arg.as_expression().map(unwrap_expr)
                            {
                                for elem in &arr.elements {
                                    if let Some(expr) = elem.as_expression()
                                        && matches!(unwrap_expr(expr), Expression::Identifier(id) if id.name == name.as_str())
                                    {
                                        used_in_deps = true;
                                    }
                                }
                            }
                        }
                    }
                }
                AstKind::JSXOpeningElement(opening) => {
                    let Some(tag_name) = extract_jsx_identifier_name(&opening.name) else {
                        continue;
                    };
                    if !is_component_name(tag_name) {
                        continue;
                    }
                    if memo_registry.get(tag_name) == Some(&MemoStatus::NotMemoized) {
                        continue;
                    }
                    for attr_item in &opening.attributes {
                        let JSXAttributeItem::Attribute(attr) = attr_item else {
                            continue;
                        };
                        if let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value
                            && let Some(expr) = cont.expression.as_expression()
                            && matches!(unwrap_expr(expr), Expression::Identifier(id) if id.name == name.as_str())
                        {
                            used_in_memo_prop = true;
                        }
                    }
                }
                _ => {}
            }
        }

        if used_in_deps || used_in_memo_prop {
            let (lit, alloc) = match kind {
                EmptyLiteralKind::Object => ("{}", "object"),
                EmptyLiteralKind::Array => ("[]", "array"),
            };
            let message = if used_in_deps {
                format!(
                    "This reruns hooks that list it in their dependency array because default prop value {lit} makes a brand new {alloc} every render, so move it to a constant at the top of the file"
                )
            } else {
                format!(
                    "This keeps redrawing children that compare props because default prop value {lit} makes a brand new {alloc} every render, so move it to a constant at the top of the file"
                )
            };
            out.push(SemanticRuleSite {
                rule: RuleId::RerenderMemoWithDefaultValue,
                subject_name: subject_name.clone(),
                message_id: "rerenderMemoWithDefaultValue",
                target_name: name,
                message,
                loc: loc_from_line_starts(line_starts, def_span.start),
                span: ByteSpan {
                    start: def_span.start,
                    end: def_span.end,
                },
                autofix: None,
            });
        }
    }
}

fn collect_empty_defaults_from_pattern(
    pat: &BindingPattern<'_>,
    out: &mut Vec<(String, EmptyLiteralKind, Span)>,
) {
    let inner = match pat {
        BindingPattern::AssignmentPattern(a) => &a.left,
        other => other,
    };
    let BindingPattern::ObjectPattern(obj) = inner else {
        return;
    };
    for prop in &obj.properties {
        let BindingPattern::AssignmentPattern(assign) = &prop.value else {
            continue;
        };
        let Some(id) = assign.left.get_binding_identifier() else {
            continue;
        };
        match unwrap_expr(&assign.right) {
            Expression::ObjectExpression(o) if o.properties.is_empty() => {
                out.push((
                    id.name.to_string(),
                    EmptyLiteralKind::Object,
                    assign.right.span(),
                ));
            }
            Expression::ArrayExpression(a) if a.elements.is_empty() => {
                out.push((
                    id.name.to_string(),
                    EmptyLiteralKind::Array,
                    assign.right.span(),
                ));
            }
            _ => {}
        }
    }
}

fn is_hook_with_deps_call(call: &CallExpression<'_>) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(id) => DEP_HOOK_NAMES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            DEP_HOOK_NAMES.contains(&mem.property.name.as_str())
        }
        _ => false,
    }
}

fn check_rerender_memo_before_early_return(
    subject_name: &Option<String>,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut memo_decl_span: Option<Span> = None;
    let mut memo_consumers: HashSet<String> = HashSet::new();
    let mut callback_guard_texts: Vec<String> = Vec::new();

    for stmt in statements {
        if memo_decl_span.is_none() {
            let Statement::VariableDeclaration(var_decl) = stmt else {
                continue;
            };
            for decl in &var_decl.declarations {
                let Some(init) = &decl.init else {
                    continue;
                };
                if let Expression::CallExpression(call) = unwrap_expr(init)
                    && is_named_hook_call(call, "useMemo")
                    && let Some(first_arg) =
                        call.arguments.first().and_then(Argument::as_expression)
                    && span_contains_jsx(first_arg.span(), semantic)
                {
                    memo_decl_span = Some(decl.span);
                    if let Some(id) = decl.id.get_binding_identifier() {
                        memo_consumers.insert(id.name.to_string());
                    }
                    callback_guard_texts =
                        collect_leading_guard_texts(first_arg, semantic.source_text());
                    break;
                }
            }
            continue;
        }

        if let Statement::VariableDeclaration(var_decl) = stmt {
            for decl in &var_decl.declarations {
                if let (Some(id), Some(init)) = (decl.id.get_binding_identifier(), &decl.init)
                    && span_references_any(init.span(), &memo_consumers, semantic)
                {
                    memo_consumers.insert(id.name.to_string());
                }
            }
        }

        if let Statement::IfStatement(if_stmt) = stmt
            && !memo_consumers.is_empty()
            && has_early_return_ignoring_memo(&if_stmt.consequent, &memo_consumers, semantic)
        {
            if span_references_any(if_stmt.test.span(), &memo_consumers, semantic) {
                continue;
            }
            let test_norm = normalize_ws(if_stmt.test.span().source_text(semantic.source_text()));
            if callback_guard_texts.iter().any(|g| g == &test_norm) {
                continue;
            }
            if let Some(span) = memo_decl_span {
                out.push(SemanticRuleSite {
                    rule: RuleId::RerenderMemoBeforeEarlyReturn,
                    subject_name: subject_name.clone(),
                    message_id: "rerenderMemoBeforeEarlyReturn",
                    target_name: "useMemo".to_string(),
                    message: "This rebuilds the JSX whenever its dependencies change even on renders that take the early return, so move the JSX into a child component rendered after the early return to skip it".to_string(),
                    loc: loc_from_line_starts(line_starts, span.start),
                    span: ByteSpan {
                        start: span.start,
                        end: span.end,
                    },
                    autofix: None,
                });
            }
            return;
        }
    }
}

fn is_named_hook_call(call: &CallExpression<'_>, hook_name: &str) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(id) => id.name == hook_name,
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == hook_name
                && matches!(
                    unwrap_expr(&mem.object),
                    Expression::Identifier(id) if id.name == "React" || id.name == "react"
                )
        }
        _ => false,
    }
}

fn span_contains_jsx(span: Span, semantic: &Semantic<'_>) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        span.contains_inclusive(n.span())
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn span_references_any(span: Span, names: &HashSet<String>, semantic: &Semantic<'_>) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        if !span.contains_inclusive(n.span()) {
            return false;
        }
        if let AstKind::IdentifierReference(id) = n.kind() {
            names.contains(id.name.as_str())
        } else {
            false
        }
    })
}

fn has_early_return_ignoring_memo(
    consequent: &Statement<'_>,
    memo_consumers: &HashSet<String>,
    semantic: &Semantic<'_>,
) -> bool {
    match consequent {
        Statement::ReturnStatement(ret) => ret
            .argument
            .as_ref()
            .is_none_or(|arg| !span_references_any(arg.span(), memo_consumers, semantic)),
        Statement::BlockStatement(block) => block.body.iter().any(|s| {
            if let Statement::ReturnStatement(ret) = s {
                ret.argument
                    .as_ref()
                    .is_none_or(|arg| !span_references_any(arg.span(), memo_consumers, semantic))
            } else {
                false
            }
        }),
        _ => false,
    }
}

fn collect_leading_guard_texts(cb_expr: &Expression<'_>, source: &str) -> Vec<String> {
    let stmts: &[Statement<'_>] = match unwrap_expr(cb_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            let ArrowFunctionBody::FunctionBody(body) = &arrow.body else {
                return Vec::new();
            };
            &body.statements
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return Vec::new();
            };
            &body.statements
        }
        _ => return Vec::new(),
    };
    let mut guards = Vec::new();
    for stmt in stmts {
        let Statement::IfStatement(if_stmt) = stmt else {
            break;
        };
        let is_return = match &if_stmt.consequent {
            Statement::ReturnStatement(_) => true,
            Statement::BlockStatement(b) => {
                b.body.len() == 1 && matches!(b.body[0], Statement::ReturnStatement(_))
            }
            _ => false,
        };
        if !is_return {
            break;
        }
        guards.push(normalize_ws(if_stmt.test.span().source_text(source)));
    }
    guards
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn check_rerender_derived_state_from_hook(
    subject_name: &Option<String>,
    statements: &[Statement<'_>],
    body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for (idx, stmt) in statements.iter().enumerate() {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        for decl in &var_decl.declarations {
            let Some(id) = decl.id.get_binding_identifier() else {
                continue;
            };
            let Some(Expression::CallExpression(call)) = decl.init.as_ref().map(unwrap_expr) else {
                continue;
            };
            let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
                continue;
            };
            let hook_name = callee_id.name.as_str();
            if !is_continuous_value_hook_name(hook_name) {
                continue;
            }
            let cont_name = id.name.as_str();

            let mut threshold_spans: Vec<Span> = Vec::new();
            for next_stmt in &statements[idx + 1..] {
                let Statement::VariableDeclaration(next_var) = next_stmt else {
                    break;
                };
                for next_decl in &next_var.declarations {
                    if let Some(next_init) = &next_decl.init
                        && is_threshold_comparison_expr(unwrap_expr(next_init), cont_name)
                    {
                        threshold_spans.push(next_decl.span);
                    }
                }
            }
            if threshold_spans.is_empty() {
                continue;
            }

            let referenced_elsewhere = semantic.nodes().iter_enumerated().any(|(_, n)| {
                if !body_span.contains_inclusive(n.span()) {
                    return false;
                }
                if decl.span.contains_inclusive(n.span())
                    || threshold_spans
                        .iter()
                        .any(|s| s.contains_inclusive(n.span()))
                {
                    return false;
                }
                if let AstKind::IdentifierReference(ref_id) = n.kind() {
                    ref_id.name == cont_name
                } else {
                    false
                }
            });

            if !referenced_elsewhere {
                out.push(SemanticRuleSite {
                    rule: RuleId::RerenderDerivedStateFromHook,
                    subject_name: subject_name.clone(),
                    message_id: "rerenderDerivedStateFromHook",
                    target_name: hook_name.to_string(),
                    message: format!(
                        "This redraws the screen far more than needed because {hook_name}() changes constantly but you only check it against a cutoff, so use a threshold hook like `useMediaQuery(\"(max-width: 767px)\")` to redraw only when the answer changes"
                    ),
                    loc: loc_from_line_starts(line_starts, decl.span.start),
                    span: ByteSpan {
                        start: decl.span.start,
                        end: decl.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}

fn is_continuous_value_hook_name(name: &str) -> bool {
    name.starts_with("useWindowWidth")
        || name.starts_with("useWindowHeight")
        || name.starts_with("useWindowDimensions")
        || name.starts_with("useScrollPosition")
        || name.starts_with("useScrollY")
        || name.starts_with("useScrollX")
        || name.starts_with("useMousePosition")
        || name.starts_with("useResizeObserver")
        || name.starts_with("useIntersectionObserver")
}

fn is_threshold_comparison_expr(expr: &Expression<'_>, cont_name: &str) -> bool {
    let Expression::BinaryExpression(bin) = expr else {
        return false;
    };
    if !matches!(
        bin.operator,
        BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
            | BinaryOperator::Equality
            | BinaryOperator::Inequality
    ) {
        return false;
    }
    let left_is_var =
        matches!(unwrap_expr(&bin.left), Expression::Identifier(id) if id.name == cont_name);
    let right_is_var =
        matches!(unwrap_expr(&bin.right), Expression::Identifier(id) if id.name == cont_name);
    let left_is_lit = matches!(
        unwrap_expr(&bin.left),
        Expression::NumericLiteral(_) | Expression::StringLiteral(_)
    );
    let right_is_lit = matches!(
        unwrap_expr(&bin.right),
        Expression::NumericLiteral(_) | Expression::StringLiteral(_)
    );
    (left_is_var && right_is_lit) || (right_is_var && left_is_lit)
}

fn check_rendering_hoist_jsx(
    subject_name: &Option<String>,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for stmt in statements {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        if var_decl.kind != VariableDeclarationKind::Const {
            continue;
        }
        for decl in &var_decl.declarations {
            let Some(init) = &decl.init else {
                continue;
            };
            let unwrapped = unwrap_expr(init);
            if !matches!(
                unwrapped,
                Expression::JSXElement(_) | Expression::JSXFragment(_)
            ) {
                continue;
            }
            let has_dynamic_jsx = semantic.nodes().iter_enumerated().any(|(_, n)| {
                if !unwrapped.span().contains_inclusive(n.span()) {
                    return false;
                }
                matches!(
                    n.kind(),
                    AstKind::JSXExpressionContainer(_) | AstKind::JSXSpreadAttribute(_)
                )
            });
            if has_dynamic_jsx {
                continue;
            }
            let name = decl
                .id
                .get_binding_identifier()
                .map_or("<unnamed>", |id| id.name.as_str());
            out.push(SemanticRuleSite {
                rule: RuleId::RenderingHoistJsx,
                subject_name: subject_name.clone(),
                message_id: "renderingHoistJsx",
                target_name: name.to_string(),
                message: format!(
                    "This rebuilds on every render because static JSX \"{name}\" is built inside the component, so move it to the top of the file to make it just once"
                ),
                loc: loc_from_line_starts(line_starts, decl.span.start),
                span: ByteSpan {
                    start: decl.span.start,
                    end: decl.span.end,
                },
                autofix: None,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// 5. `rerender-transitions-scroll`, `no-match-media-in-state-initializer`,
//    `no-eager-new-in-use-state-initializer`, `no-usememo-simple-expression`
// ---------------------------------------------------------------------------

fn check_rerender_transitions_scroll(
    _node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "addEventListener" {
        return;
    }
    let Some(event_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::StringLiteral(event_lit) = unwrap_expr(event_arg) else {
        return;
    };
    let Some(event_name) = event_lit.value.as_str() else {
        return;
    };
    if !HIGH_FREQUENCY_DOM_EVENTS.contains(&event_name) {
        return;
    }
    let Some(handler_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    let handler_span = match unwrap_expr(handler_arg) {
        Expression::ArrowFunctionExpression(a) => a.body.span(),
        Expression::FunctionExpression(f) => {
            let Some(b) = &f.body else {
                return;
            };
            b.span
        }
        _ => return,
    };

    // Skip if handler deduplicates via ref-guarded return (`if (target === ref.current) return`)
    for (_, n) in semantic.nodes().iter_enumerated() {
        if !handler_span.contains_inclusive(n.span()) {
            continue;
        }
        if let AstKind::IfStatement(if_stmt) = n.kind()
            && if_stmt
                .test
                .span()
                .source_text(semantic.source_text())
                .contains(".current")
            && if_stmt
                .consequent
                .span()
                .source_text(semantic.source_text())
                .contains("return")
        {
            return;
        }
    }

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !handler_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let AstKind::CallExpression(set_call) = inner_node.kind() else {
            continue;
        };
        let Expression::Identifier(callee_id) = unwrap_expr(&set_call.callee) else {
            continue;
        };
        let name = callee_id.name.as_str();
        if !name.starts_with("set") || !name.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase) {
            continue;
        }
        // Check that `setX` resolves to a local declaration (e.g. `useState`)
        if resolve_ident_symbol(semantic, callee_id).is_none() {
            continue;
        }
        // Skip constant-only setter calls (`setShow(false)`, `setTip(null)`)
        if set_call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_none_or(is_constant_setter_arg)
        {
            continue;
        }
        // Skip if wrapped in `startTransition` or `requestAnimationFrame`
        let is_wrapped = semantic
            .nodes()
            .ancestor_ids(inner_id)
            .skip(1)
            .any(|anc_id| {
                if let AstKind::CallExpression(anc_call) = semantic.nodes().kind(anc_id)
                    && let Expression::Identifier(id) = unwrap_expr(&anc_call.callee)
                {
                    matches!(
                        id.name.as_str(),
                        "startTransition" | "requestAnimationFrame" | "requestIdleCallback"
                    )
                } else {
                    false
                }
            });
        if is_wrapped {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, inner_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::RerenderTransitionsScroll,
            subject_name,
            message_id: "rerenderTransitionsScroll",
            target_name: name.to_string(),
            message: format!(
                "This can make scrolling stutter because setState in a \"{event_name}\" handler redraws on every event. Wrap it in startTransition, use useDeferredValue, or keep the value in a ref and throttle with requestAnimationFrame."
            ),
            loc: loc_from_line_starts(line_starts, set_call.span.start),
            span: ByteSpan {
                start: set_call.span.start,
                end: set_call.span.end,
            },
            autofix: None,
        });
        return;
    }
}

fn is_constant_setter_arg(expr: &Expression<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::UnaryExpression(u) => is_constant_setter_arg(&u.argument),
        _ => false,
    }
}

fn is_bound_react_hook_call(
    call: &CallExpression<'_>,
    hook_name: &str,
    semantic: &Semantic<'_>,
) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            if !semantic
                .scoping()
                .symbol_flags(sym_id)
                .contains(SymbolFlags::Import)
            {
                return false;
            }
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::ImportSpecifier(spec) = semantic.nodes().kind(decl_id) {
                spec.imported.name() == hook_name
            } else {
                false
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name != hook_name {
                return false;
            }
            let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) else {
                return false;
            };
            if let Some(sym_id) = resolve_ident_symbol(semantic, obj_id) {
                semantic
                    .scoping()
                    .symbol_flags(sym_id)
                    .contains(SymbolFlags::Import)
            } else {
                obj_id.name == "React"
            }
        }
        _ => false,
    }
}

fn check_no_match_media_in_state_initializer(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_bound_react_hook_call(call, "useState", semantic) {
        return;
    }
    let Some(init_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let search_span = match unwrap_expr(init_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            if arrow.r#async {
                return;
            }
            arrow.body.span()
        }
        Expression::FunctionExpression(func) => {
            if func.r#async || func.generator {
                return;
            }
            let Some(b) = &func.body else {
                return;
            };
            b.span
        }
        other => other.span(),
    };

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !search_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let AstKind::CallExpression(mm_call) = inner_node.kind() else {
            continue;
        };
        // Skip if inside a nested function/callback inside search_span
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(inner_id)
            .skip(1)
            .take_while(|&anc_id| {
                search_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
            })
            .any(|anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_nested_fn {
            continue;
        }
        if !is_global_match_media_call(mm_call, semantic) {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::NoMatchMediaInStateInitializer,
            subject_name,
            message_id: "noMatchMediaInStateInitializer",
            target_name: "matchMedia".to_string(),
            message: "`matchMedia()` in a useState initializer can cause an SSR crash or seed different server and hydration state. Prefer CSS media queries for layout, or use `useSyncExternalStore` with a stable server snapshot.".to_string(),
            loc: loc_from_line_starts(line_starts, mm_call.span.start),
            span: ByteSpan {
                start: mm_call.span.start,
                end: mm_call.span.end,
            },
            autofix: None,
        });
        return;
    }
}

fn is_global_match_media_call(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(id) => id.name == "matchMedia" && is_global_ident(semantic, id),
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name != "matchMedia" {
                return false;
            }
            if let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) {
                (obj_id.name == "window" || obj_id.name == "globalThis")
                    && is_global_ident(semantic, obj_id)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn check_no_eager_new_in_use_state_initializer(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_named_hook_call(call, "useState") {
        return;
    }
    let Some(init_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::NewExpression(new_expr) = unwrap_expr(init_expr) else {
        return;
    };
    let ctor_name = match unwrap_expr(&new_expr.callee) {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(mem) => mem.property.name.as_str(),
        _ => "constructor",
    };
    if CHEAP_CONSTRUCTORS.contains(&ctor_name) && new_expr.arguments.is_empty() {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoEagerNewInUseStateInitializer,
        subject_name,
        message_id: "noEagerNewInUseStateInitializer",
        target_name: format!("new {ctor_name}()"),
        message: format!(
            "`new {ctor_name}()` inside `useState(...)` runs on every render; pass a lazy initializer `useState(() => new {ctor_name}(...))` so it only runs on mount."
        ),
        loc: loc_from_line_starts(line_starts, new_expr.span.start),
        span: ByteSpan {
            start: new_expr.span.start,
            end: new_expr.span.end,
        },
        autofix: None,
    });
}

fn check_no_usememo_simple_expression(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_named_hook_call(call, "useMemo") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let ret_expr: Option<&Expression<'_>> = match unwrap_expr(first_arg) {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                Some(expr)
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                if body.statements.len() == 1
                    && let Statement::ReturnStatement(ret) = &body.statements[0]
                {
                    ret.argument.as_ref()
                } else {
                    None
                }
            } else {
                None
            }
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return;
            };
            if body.statements.len() == 1
                && let Statement::ReturnStatement(ret) = &body.statements[0]
            {
                ret.argument.as_ref()
            } else {
                None
            }
        }
        _ => None,
    };
    let Some(expr) = ret_expr.map(unwrap_expr) else {
        return;
    };
    if matches!(
        expr,
        Expression::Identifier(_) | Expression::StaticMemberExpression(_)
    ) {
        return;
    }
    if !is_simple_cheap_expr(expr) {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoUsememoSimpleExpression,
        subject_name,
        message_id: "noUsememoSimpleExpression",
        target_name: "useMemo".to_string(),
        message: "This costs more than it saves because useMemo is wrapping a value that's already cheap, so remove the useMemo".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn is_simple_cheap_expr(expr: &Expression<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::BinaryExpression(bin) => {
            is_simple_cheap_expr(&bin.left) && is_simple_cheap_expr(&bin.right)
        }
        Expression::UnaryExpression(u) => is_simple_cheap_expr(&u.argument),
        Expression::StaticMemberExpression(mem) => is_simple_cheap_expr(&mem.object),
        Expression::ConditionalExpression(cond) => {
            is_simple_cheap_expr(&cond.test)
                && is_simple_cheap_expr(&cond.consequent)
                && is_simple_cheap_expr(&cond.alternate)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 6. JSX Opening Element performance rules:
//    `no-transition-all`, `no-layout-property-animation`,
//    `no-inline-prop-on-memo-component`, `prefer-stable-empty-fallback`,
//    `context-provider-value-from-unmemoized-local-literal`,
//    `no-permanent-will-change`, `no-srcset-without-sizes`,
//    `no-img-lazy-with-high-fetchpriority`, `rendering-script-defer-async`,
//    `no-conflicting-spring-options`, `no-excessive-motion-stagger`,
//    `no-large-animated-blur`, `prefer-motion-transform-property`
// ---------------------------------------------------------------------------

fn check_jsx_opening_performance_rules(
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    memo_registry: &HashMap<String, MemoStatus>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    let is_motion = is_motion_jsx_element(&opening.name);
    let tag_ident = extract_jsx_identifier_name(&opening.name);
    if is_motion && matches!(&opening.name, JSXElementName::MemberExpression(mem) if mem.property.name == "svg")
        && opening.attributes.iter().any(|item| {
            if let JSXAttributeItem::Attribute(attr) = item
                && let JSXAttributeName::Identifier(id) = &attr.name
            {
                MOTION_ANIMATE_PROPS.contains(&id.name.as_str())
            } else {
                false
            }
        })
    {
        out.push(SemanticRuleSite {
            rule: RuleId::RenderingAnimateSvgWrapper,
            subject_name: subject_name.clone(),
            message_id: "renderingAnimateSvgWrapper",
            target_name: "motion.svg".to_string(),
            message: "Animating an `<svg>` directly can bypass hardware-accelerated compositing; animate a wrapper `<div>` or `<span>` instead.".to_string(),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 1. `no-transition-all` & `no-permanent-will-change`
    for attr_item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = attr_item else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_name) = &attr.name else {
            continue;
        };
        let name = attr_name.name.as_str();
        if (name == "className" || name == "class")
            && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
            && let Some(val) = s.value.as_str()
        {
            if val.split_whitespace().any(|t| {
                let u = t.rsplit(':').next().unwrap_or(t).trim_start_matches('!');
                u == "transition-all"
            }) {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoTransitionAll,
                    subject_name: subject_name.clone(),
                    message_id: "noTransitionAll",
                    target_name: "transition-all".to_string(),
                    message: "Your users see janky animation because `transition-all` animates every property that changes, including expensive layout ones and instant ones like focus rings. Name the properties: `transition-colors`, `transition-opacity`, or `transition-transform`.".to_string(),
                    loc: loc_from_line_starts(line_starts, opening.span.start),
                    span: ByteSpan {
                        start: opening.span.start,
                        end: opening.span.end,
                    },
                    autofix: None,
                });
            }
            if let Some(perm) = val.split_whitespace().find(|t| {
                let u = t.trim_start_matches('!');
                !u.contains(':')
                    && u.starts_with("will-change-")
                    && !matches!(
                        u,
                        "will-change-auto"
                            | "will-change-scroll"
                            | "will-change-[auto]"
                            | "will-change-[scroll-position]"
                    )
            }) {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoPermanentWillChange,
                    subject_name: subject_name.clone(),
                    message_id: "noPermanentWillChange",
                    target_name: perm.to_string(),
                    message: format!(
                        "This keeps {perm} active permanently, which can waste GPU memory. Apply the hint only immediately before the animation and remove it afterward."
                    ),
                    loc: loc_from_line_starts(line_starts, attr.span.start),
                    span: ByteSpan {
                        start: attr.span.start,
                        end: attr.span.end,
                    },
                    autofix: None,
                });
            }
        }

        if name == "style"
            && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value
            && let Some(Expression::ObjectExpression(obj)) =
                cont.expression.as_expression().map(unwrap_expr)
        {
            for prop_kind in &obj.properties {
                let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                    continue;
                };
                let Some(key_name) = prop
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                if (key_name == "transition" || key_name == "transitionProperty")
                    && let Expression::StringLiteral(s) = unwrap_expr(&prop.value)
                    && s.value
                        .as_str()
                        .is_some_and(|v| v.trim() == "all" || v.trim().starts_with("all "))
                {
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoTransitionAll,
                        subject_name: subject_name.clone(),
                        message_id: "noTransitionAll",
                        target_name: key_name.clone(),
                        message: "This can stutter because transition: \"all\" animates every property, even slow layout ones, so list only the properties you actually change".to_string(),
                        loc: loc_from_line_starts(line_starts, opening.span.start),
                        span: ByteSpan {
                            start: opening.span.start,
                            end: opening.span.end,
                        },
                        autofix: None,
                    });
                }
                if key_name == "willChange" {
                    let val = unwrap_expr(&prop.value);
                    if !matches!(
                        val,
                        Expression::ConditionalExpression(_) | Expression::LogicalExpression(_)
                    ) && !matches!(val, Expression::StringLiteral(s) if s.value.as_str().map(str::trim) == Some("scroll-position"))
                    {
                        out.push(SemanticRuleSite {
                            rule: RuleId::NoPermanentWillChange,
                            subject_name: subject_name.clone(),
                            message_id: "noPermanentWillChange",
                            target_name: "willChange".to_string(),
                            message: "This wastes GPU memory because will-change is left on all the time, so add it right before the animation & remove it when the animation ends".to_string(),
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
        }

        // 2. Motion animation attributes (`no-layout-property-animation`, `no-large-animated-blur`, `prefer-motion-transform-property`)
        if MOTION_ANIMATE_PROPS.contains(&name)
            && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value
            && let Some(Expression::ObjectExpression(obj)) =
                cont.expression.as_expression().map(unwrap_expr)
        {
            for prop_kind in &obj.properties {
                let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                    continue;
                };
                let Some(prop_name) = prop
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                if is_motion && LAYOUT_PROPERTIES.contains(&prop_name.as_str()) {
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoLayoutPropertyAnimation,
                        subject_name: subject_name.clone(),
                        message_id: "noLayoutPropertyAnimation",
                        target_name: prop_name.clone(),
                        message: format!(
                            "This stutters because animating \"{prop_name}\" makes the browser redo page layout every frame, so animate transform or scale instead, or use the layout prop"
                        ),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
                if matches!(
                    prop_name.as_str(),
                    "filter" | "backdropFilter" | "WebkitBackdropFilter"
                ) && let Expression::StringLiteral(s) = unwrap_expr(&prop.value)
                    && let Some(radius) = s.value.as_str().and_then(parse_blur_px)
                    && radius > 10.0
                {
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoLargeAnimatedBlur,
                        subject_name: subject_name.clone(),
                        message_id: "noLargeAnimatedBlur",
                        target_name: prop_name.clone(),
                        message: format!(
                            "Large animated blurs can use significant GPU memory on phones because blur({radius}px) gets heavier as the blur and element grow. Use a smaller blur or a smaller element."
                        ),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
                if is_motion
                    && name != "initial"
                    && INDIVIDUAL_MOTION_TRANSFORM_PROPS.contains(&prop_name.as_str())
                {
                    out.push(SemanticRuleSite {
                        rule: RuleId::PreferMotionTransformProperty,
                        subject_name: subject_name.clone(),
                        message_id: "preferMotionTransformProperty",
                        target_name: prop_name.clone(),
                        message: format!(
                            "Motion's individual {prop_name} transform keys can keep this animation on the main thread. Use a single transform string when compositor acceleration is important."
                        ),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
                if is_motion
                    && matches!(prop_name.as_str(), "scale" | "scaleX" | "scaleY")
                    && matches!(unwrap_expr(&prop.value), Expression::NumericLiteral(n) if n.value == 0.0)
                {
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoScaleFromZero,
                        subject_name: subject_name.clone(),
                        message_id: "noScaleFromZero",
                        target_name: prop_name.clone(),
                        message: format!(
                            "Animating `{prop_name}` from `0` makes elements pop out of nowhere; start from a subtle non-zero scale such as `0.95`."
                        ),
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

        // 3. Motion `transition` attribute (`no-conflicting-spring-options`, `no-excessive-motion-stagger`)
        if is_motion
            && name == "transition"
            && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value
            && let Some(Expression::ObjectExpression(obj)) =
                cont.expression.as_expression().map(unwrap_expr)
        {
            let mut has_physics = false;
            let mut duration_prop_span: Option<Span> = None;
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
                if matches!(k.as_str(), "stiffness" | "damping" | "mass") {
                    has_physics = true;
                }
                if matches!(k.as_str(), "duration" | "bounce") && duration_prop_span.is_none() {
                    duration_prop_span = Some(prop.span);
                }
                if k == "staggerChildren"
                    && let Expression::NumericLiteral(n) = unwrap_expr(&prop.value)
                    && n.value > 0.08
                {
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoExcessiveMotionStagger,
                        subject_name: subject_name.clone(),
                        message_id: "noExcessiveMotionStagger",
                        target_name: "staggerChildren".to_string(),
                        message: format!(
                            "This {}-second per-item stagger makes later children wait unnecessarily. Keep the interval at 0.08 seconds or less.",
                            n.value
                        ),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
            }
            if has_physics && let Some(dur_span) = duration_prop_span {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoConflictingSpringOptions,
                    subject_name: subject_name.clone(),
                    message_id: "noConflictingSpringOptions",
                    target_name: "duration".to_string(),
                    message: "This spring mixes physics controls with duration-based controls, so Motion ignores duration and bounce. Keep only one spring configuration mode.".to_string(),
                    loc: loc_from_line_starts(line_starts, dur_span.start),
                    span: ByteSpan {
                        start: dur_span.start,
                        end: dur_span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // 4. `prefer-stable-empty-fallback`
    if let Some(comp_name) = tag_ident
        && memo_registry.get(comp_name) == Some(&MemoStatus::Memoized)
    {
        for attr_item in &opening.attributes {
            let JSXAttributeItem::Attribute(attr) = attr_item else {
                continue;
            };
            let JSXAttributeName::Identifier(attr_name) = &attr.name else {
                continue;
            };
            if attr_name.name == "key" {
                continue;
            }
            let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
                continue;
            };
            let Some(expr) = cont.expression.as_expression() else {
                continue;
            };
            if let Expression::LogicalExpression(log) = unwrap_expr(expr)
                && matches!(
                    log.operator,
                    LogicalOperator::Or | LogicalOperator::Coalesce
                )
            {
                let right = unwrap_expr(&log.right);
                let empty_kind = match right {
                    Expression::ArrayExpression(a) if a.elements.is_empty() => {
                        Some(("array", "[]", "const EMPTY_ITEMS: Item[] = []"))
                    }
                    Expression::ObjectExpression(o) if o.properties.is_empty() => {
                        Some(("object", "{}", "const EMPTY_CONFIG: Config = {}"))
                    }
                    _ => None,
                };
                if let Some((kind_str, lit, ex)) = empty_kind {
                    out.push(SemanticRuleSite {
                        rule: RuleId::PreferStableEmptyFallback,
                        subject_name: subject_name.clone(),
                        message_id: "preferStableEmptyFallback",
                        target_name: attr_name.name.to_string(),
                        message: format!(
                            "This redraws the memo child anyway because fallback `{lit}` builds a brand new {kind_str} each render when the left value is empty, so the child sees a different value. Hoist a constant (e.g. `{ex}`) & use that as the fallback."
                        ),
                        loc: loc_from_line_starts(line_starts, right.span().start),
                        span: ByteSpan {
                            start: right.span().start,
                            end: right.span().end,
                        },
                        autofix: None,
                    });
                }
            }
        }
    }

    // 6. `no-srcset-without-sizes`, `no-img-lazy-with-high-fetchpriority`, `rendering-script-defer-async`
    if tag_ident == Some("img") {
        let has_spread = opening
            .attributes
            .iter()
            .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)));
        let mut srcset_attr: Option<(&oxc_ast::ast::JSXAttribute<'_>, &str)> = None;
        let mut has_sizes = false;
        let mut is_loading_lazy = false;
        let mut is_fetch_priority_high = false;

        for attr_item in &opening.attributes {
            let JSXAttributeItem::Attribute(attr) = attr_item else {
                continue;
            };
            let JSXAttributeName::Identifier(attr_name) = &attr.name else {
                continue;
            };
            let name_lower = attr_name.name.to_ascii_lowercase();
            match name_lower.as_str() {
                "srcset" => {
                    if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                        && let Some(val) = s.value.as_str()
                    {
                        srcset_attr = Some((attr, val));
                    }
                }
                "sizes" => has_sizes = true,
                "loading" => {
                    if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                        && s.value
                            .as_str()
                            .is_some_and(|v| v.eq_ignore_ascii_case("lazy"))
                    {
                        is_loading_lazy = true;
                    }
                }
                "fetchpriority" => {
                    if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                        && s.value
                            .as_str()
                            .is_some_and(|v| v.eq_ignore_ascii_case("high"))
                    {
                        is_fetch_priority_high = true;
                    }
                }
                _ => {}
            }
        }

        if !has_spread
            && !has_sizes
            && let Some((attr, srcset_val)) = srcset_attr
            && srcset_has_width_descriptor(srcset_val)
        {
            out.push(SemanticRuleSite {
                rule: RuleId::NoSrcsetWithoutSizes,
                subject_name: subject_name.clone(),
                message_id: "noSrcsetWithoutSizes",
                target_name: "srcSet".to_string(),
                message: "This responsive image supplies srcSet without sizes, so the browser assumes a 100vw slot and may download an unnecessarily large candidate. Describe its actual responsive width with sizes.".to_string(),
                loc: loc_from_line_starts(line_starts, attr.span.start),
                span: ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
                autofix: None,
            });
        }

        if is_loading_lazy && is_fetch_priority_high {
            out.push(SemanticRuleSite {
                rule: RuleId::NoImgLazyWithHighFetchpriority,
                subject_name: subject_name.clone(),
                message_id: "noImgLazyWithHighFetchpriority",
                target_name: "img".to_string(),
                message: "`<img loading=\"lazy\">` defers the request while `fetchPriority=\"high\"` asks the browser to rush it, so the two directives contradict each other. Drop one: keep `fetchPriority=\"high\"` (and eager loading) for an LCP image, or `loading=\"lazy\"` for a below-the-fold one.".to_string(),
                loc: loc_from_line_starts(line_starts, opening.name.span().start),
                span: ByteSpan {
                    start: opening.name.span().start,
                    end: opening.name.span().end,
                },
                autofix: None,
            });
        }
    }

    if tag_ident == Some("script") {
        let mut has_src = false;
        let mut src_val: Option<&str> = None;
        let mut has_no_module = false;
        let mut type_val: Option<&str> = None;
        let mut has_defer_or_async = false;

        for attr_item in &opening.attributes {
            let JSXAttributeItem::Attribute(attr) = attr_item else {
                continue;
            };
            let JSXAttributeName::Identifier(attr_name) = &attr.name else {
                continue;
            };
            match attr_name.name.as_str() {
                "src" => {
                    has_src = true;
                    if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value {
                        src_val = s.value.as_str();
                    }
                }
                "noModule" => has_no_module = true,
                "type" => {
                    if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value {
                        type_val = s.value.as_str();
                    }
                }
                "defer" | "async" => has_defer_or_async = true,
                _ => {}
            }
        }

        if has_src && !has_no_module && !has_defer_or_async {
            let is_bootstrap = src_val.is_some_and(|s| {
                let lower = s.to_ascii_lowercase();
                lower.contains("theme-init")
                    || lower.contains("__env")
                    || lower.contains("env-config")
                    || lower.contains("runtime-env")
            });
            let is_non_blocking_type = type_val.is_some_and(|t| {
                t == "module"
                    || (!t.is_empty() && t != "text/javascript" && t != "application/javascript")
            });
            if !is_bootstrap && !is_non_blocking_type {
                out.push(SemanticRuleSite {
                    rule: RuleId::RenderingScriptDeferAsync,
                    subject_name,
                    message_id: "renderingScriptDeferAsync",
                    target_name: "script".to_string(),
                    message: "This blocks the page from loading until the script downloads because <script src> has no defer or async, so add defer for scripts that need the page, or async for standalone ones".to_string(),
                    loc: loc_from_line_starts(line_starts, opening.span.start),
                    span: ByteSpan {
                        start: opening.span.start,
                        end: opening.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}

fn is_motion_jsx_element(name: &JSXElementName<'_>) -> bool {
    match name {
        JSXElementName::Identifier(id) => id.name.starts_with("Motion"),
        JSXElementName::IdentifierReference(id) => id.name.starts_with("Motion"),
        JSXElementName::MemberExpression(mem) => {
            if let JSXMemberExpressionObject::IdentifierReference(obj) = &mem.object {
                obj.name == "motion" || obj.name == "m"
            } else {
                false
            }
        }
        _ => false,
    }
}

fn extract_jsx_identifier_name<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(id) => Some(id.name.as_str()),
        JSXElementName::IdentifierReference(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn srcset_has_width_descriptor(srcset: &str) -> bool {
    srcset.split(',').any(|candidate| {
        let mut tokens = candidate.split_whitespace();
        let _url = tokens.next();
        tokens.next().is_some_and(|desc| {
            desc.strip_suffix('w')
                .is_some_and(|num| !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
        })
    })
}

fn parse_blur_px(val: &str) -> Option<f64> {
    let idx = val.find("blur(")?;
    let after = &val[idx + "blur(".len()..];
    let px_idx = after.find("px)")?;
    after[..px_idx].trim().parse::<f64>().ok()
}

// ---------------------------------------------------------------------------
// 7. Remaining animation, hydration, and React Router performance rules
// ---------------------------------------------------------------------------

fn check_unbounded_animation_frame_loop(
    _node_id: NodeId,
    fn_name: Option<&str>,
    body_span: Option<Span>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let (Some(name), Some(span)) = (fn_name, body_span) else {
        return;
    };
    let mut has_stop_gate = false;
    let mut recursive_raf_span: Option<Span> = None;

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(inner_id)
            .skip(1)
            .take_while(|&anc_id| span.contains_inclusive(semantic.nodes().get_node(anc_id).span()))
            .any(|anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_nested_fn {
            continue;
        }
        match inner_node.kind() {
            AstKind::IfStatement(_)
            | AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::SwitchStatement(_)
            | AstKind::TryStatement(_) => {
                has_stop_gate = true;
            }
            AstKind::CallExpression(call) => {
                let is_raf = match unwrap_expr(&call.callee) {
                    Expression::Identifier(id) => {
                        id.name == "requestAnimationFrame" && is_global_ident(semantic, id)
                    }
                    Expression::StaticMemberExpression(mem) => {
                        mem.property.name == "requestAnimationFrame"
                    }
                    _ => false,
                };
                if is_raf
                    && let Some(arg) = call.arguments.first().and_then(Argument::as_expression)
                    && matches!(unwrap_expr(arg), Expression::Identifier(id) if id.name == name)
                {
                    let parent_kind = semantic.nodes().parent_kind(inner_id);
                    let retained = matches!(
                        parent_kind,
                        AstKind::VariableDeclarator(_)
                            | AstKind::AssignmentExpression(_)
                            | AstKind::ReturnStatement(_)
                    );
                    if !retained {
                        recursive_raf_span = Some(call.span);
                    }
                }
            }
            _ => {}
        }
    }

    if !has_stop_gate && let Some(raf_span) = recursive_raf_span {
        out.push(SemanticRuleSite {
            rule: RuleId::NoUnboundedAnimationFrameLoop,
            subject_name: Some(name.to_string()),
            message_id: "noUnboundedAnimationFrameLoop",
            target_name: "requestAnimationFrame".to_string(),
            message: "This callback schedules itself forever with no stop path and discards the active request ID. Add a stop condition and retain the ID for cancelAnimationFrame().".to_string(),
            loc: loc_from_line_starts(line_starts, raf_span.start),
            span: ByteSpan {
                start: raf_span.start,
                end: raf_span.end,
            },
            autofix: None,
        });
    }
}

fn check_no_unthrottled_scroll_mutation(
    _node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "addEventListener" {
        return;
    }
    let Some(event_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::StringLiteral(event_lit) = unwrap_expr(event_arg) else {
        return;
    };
    if event_lit.value.as_str() != Some("scroll") {
        return;
    }
    let Some(handler_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    let handler_span = match unwrap_expr(handler_arg) {
        Expression::ArrowFunctionExpression(a) => a.body.span(),
        Expression::FunctionExpression(f) => {
            let Some(b) = &f.body else {
                return;
            };
            b.span
        }
        _ => return,
    };

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !handler_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        // Skip if guarded by `if` inside the scroll handler (e.g. `if (!ticking) requestAnimationFrame(...)`)
        let guarded = semantic
            .nodes()
            .ancestor_ids(inner_id)
            .take_while(|&anc_id| {
                handler_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
            })
            .any(|anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::IfStatement(_)));
        if guarded {
            continue;
        }
        if let AstKind::AssignmentExpression(assign) = inner_node.kind() {
            let lhs = assign.left.span().source_text(semantic.source_text());
            if lhs.contains(".style.") {
                let subject_name = find_enclosing_react_node(semantic, inner_id)
                    .and_then(|id| get_subject_name(semantic, id));
                out.push(SemanticRuleSite {
                    rule: RuleId::NoUnthrottledScrollMutation,
                    subject_name,
                    message_id: "noUnthrottledScrollMutation",
                    target_name: "scroll".to_string(),
                    message: "This drives animation work from every scroll event, which can make scrolling jank. Use a scroll timeline, IntersectionObserver, or a real timer throttle.".to_string(),
                    loc: loc_from_line_starts(line_starts, assign.span.start),
                    span: ByteSpan {
                        start: assign.span.start,
                        end: assign.span.end,
                    },
                    autofix: None,
                });
                return;
            }
        }
    }
}

fn check_no_global_css_variable_animation(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
        return;
    };
    let callee_name = callee_id.name.as_str();
    if callee_name != "requestAnimationFrame" && callee_name != "setInterval" {
        return;
    }
    let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb_span = cb_arg.span();

    for (_, inner_node) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let AstKind::CallExpression(inner_call) = inner_node.kind() else {
            continue;
        };
        let callee_text = inner_call
            .callee
            .span()
            .source_text(semantic.source_text())
            .trim();
        if callee_text != "document.documentElement.style.setProperty"
            && callee_text != "document.body.style.setProperty"
        {
            continue;
        }
        let Some(first_arg) = inner_call
            .arguments
            .first()
            .and_then(Argument::as_expression)
        else {
            continue;
        };
        let Expression::StringLiteral(var_lit) = unwrap_expr(first_arg) else {
            continue;
        };
        let Some(var_name) = var_lit.value.as_str() else {
            continue;
        };
        if !var_name.starts_with("--") {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::NoGlobalCssVariableAnimation,
            subject_name,
            message_id: "noGlobalCssVariableAnimation",
            target_name: var_name.to_string(),
            message: format!(
                "This forces every element using \"{var_name}\" to recompute its styles each frame because {callee_name} changes it every frame, so set it on just the element that needs it"
            ),
            loc: loc_from_line_starts(line_starts, inner_call.span.start),
            span: ByteSpan {
                start: inner_call.span.start,
                end: inner_call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_web_animation_keyframes(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "animate" {
        return;
    }
    let recv_text = mem.object.span().source_text(semantic.source_text());
    if !recv_text.contains("document.")
        && !recv_text.contains("querySelector")
        && !recv_text.contains("getElementById")
        && !recv_text.contains(".current")
    {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };

    let mut keyframe_objs = Vec::new();
    match unwrap_expr(first_arg) {
        Expression::ArrayExpression(arr) => {
            for elem in &arr.elements {
                if let Some(Expression::ObjectExpression(obj)) =
                    elem.as_expression().map(unwrap_expr)
                {
                    keyframe_objs.push(obj);
                }
            }
        }
        Expression::ObjectExpression(obj) => keyframe_objs.push(obj),
        _ => {}
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));

    for obj in keyframe_objs {
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Some(raw_name) = prop
                .key
                .static_name()
                .and_then(|n| n.as_str().map(str::to_string))
            else {
                continue;
            };
            let camel = kebab_to_camel(&raw_name);
            if LAYOUT_PROPERTIES.contains(&camel.as_str()) {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoLayoutPropertyAnimation,
                    subject_name: subject_name.clone(),
                    message_id: "noLayoutPropertyAnimation",
                    target_name: raw_name.clone(),
                    message: format!(
                        "This Web Animation changes \"{raw_name}\" every frame, forcing layout work. Animate transform or opacity instead."
                    ),
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
}

fn kebab_to_camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper_next = false;
    for ch in s.chars() {
        if ch == '-' {
            upper_next = true;
        } else if upper_next {
            out.push(ch.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn check_motion_value_constructor_in_render(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
        return;
    };
    if callee_id.name != "motionValue" {
        return;
    }
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    // Skip if inside useMemo / useState / useRef callback
    let in_nested_hook_cb = semantic
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
    if in_nested_hook_cb {
        return;
    }

    let subject_name = get_subject_name(semantic, subj_id);
    out.push(SemanticRuleSite {
        rule: RuleId::MotionValueConstructorInRender,
        subject_name,
        message_id: "motionValueConstructorInRender",
        target_name: "motionValue".to_string(),
        message: "motionValue() creates a fresh reactive object during this render. Use useMotionValue() so React preserves the value across renders.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_rendering_hydration_mismatch_time(
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
        out.push(SemanticRuleSite {
            rule: RuleId::RenderingHydrationMismatchTime,
            subject_name,
            message_id: "renderingHydrationMismatchTime",
            target_name: display.to_string(),
            message: format!(
                "This can cause a hydration mismatch because {display} in JSX gives a different value on the server than in the browser. Move it into useEffect+useState to run only in the browser, or add suppressHydrationWarning to the parent if it's on purpose."
            ),
            loc: loc_from_line_starts(line_starts, container.span.start),
            span: ByteSpan {
                start: container.span.start,
                end: container.span.end,
            },
            autofix: None,
        });
    }
}

fn check_rendering_hydration_no_flicker(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_named_hook_call(call, "useEffect") {
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
        out.push(SemanticRuleSite {
            rule: RuleId::RenderingHydrationNoFlicker,
            subject_name,
            message_id: "renderingHydrationNoFlicker",
            target_name: "useEffect".to_string(),
            message: "Synchronizing viewport/media state inside `useEffect` flashes after first paint; prefer CSS media queries or `useSyncExternalStore`.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_no_hydration_branch_on_browser_global(
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
        out.push(SemanticRuleSite {
            rule: RuleId::NoHydrationBranchOnBrowserGlobal,
            subject_name,
            message_id: "noHydrationBranchOnBrowserGlobal",
            target_name: "typeof window".to_string(),
            message: "Branching on `typeof window` or `typeof document` during render causes server and client HTML to diverge during hydration.".to_string(),
            loc: loc_from_line_starts(line_starts, test.span().start),
            span: ByteSpan {
                start: test.span().start,
                end: test.span().end,
            },
            autofix: None,
        });
    }
}

fn check_no_unguarded_browser_global_in_render(
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
    out.push(SemanticRuleSite {
        rule: RuleId::NoUnguardedBrowserGlobalInRenderOrHookInit,
        subject_name,
        message_id: "noUnguardedBrowserGlobalInRenderOrHookInit",
        target_name: name.to_string(),
        message: format!(
            "`{name}` is read while React is rendering on the server, where browser globals are unavailable. Move the read into an effect or event, or provide a stable server snapshot."
        ),
        loc: loc_from_line_starts(line_starts, ident.span.start),
        span: ByteSpan {
            start: ident.span.start,
            end: ident.span.end,
        },
        autofix: None,
    });
}

fn check_no_locale_format_in_render(
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
    out.push(SemanticRuleSite {
        rule: RuleId::NoLocaleFormatInRender,
        subject_name,
        message_id: "noLocaleFormatInRender",
        target_name: method.to_string(),
        message: format!(
            "This can cause a hydration mismatch because .{method}() formats with the server's locale and timezone during server rendering but the user's in the browser. Format it in a post-mount useEffect, or pass an explicit locale and timeZone."
        ),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_react_router_prefer_route_lazy(
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
        out.push(SemanticRuleSite {
            rule: RuleId::ReactRouterPreferRouteLazy,
            subject_name: None,
            message_id: "reactRouterPreferRouteLazy",
            target_name: target_name.to_string(),
            message: "React.lazy defers only the component; use the route lazy property to load the full route module in parallel.".to_string(),
            loc: loc_from_line_starts(line_starts, prop_span.start),
            span: ByteSpan {
                start: prop_span.start,
                end: prop_span.end,
            },
            autofix: None,
        });
    }
}

fn check_react_router_loader_parallel_fetch(
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
        out.push(SemanticRuleSite {
            rule: RuleId::ReactRouterLoaderParallelFetch,
            subject_name: Some("loader".to_string()),
            message_id: "reactRouterLoaderParallelFetch",
            target_name: "fetch".to_string(),
            message: "Independent awaits run sequentially in this loader and create a navigation waterfall.".to_string(),
            loc: loc_from_line_starts(line_starts, span.start),
            span: ByteSpan {
                start: span.start,
                end: span.end,
            },
            autofix: None,
        });
    }
}

fn check_react_router_loader_fetch_forwards_signal(
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
    out.push(SemanticRuleSite {
        rule: RuleId::ReactRouterLoaderFetchForwardsSignal,
        subject_name: Some("loader".to_string()),
        message_id: "reactRouterLoaderFetchForwardsSignal",
        target_name: "fetch".to_string(),
        message: "fetch() in this loader does not receive request.signal, so abandoned navigation work continues.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
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

fn check_rendering_usetransition_loading(
    subject_name: &Option<String>,
    statements: &[Statement<'_>],
    body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let body_src = body_span.source_text(semantic.source_text());
    let has_transition =
        body_src.contains("useTransition(") || body_src.contains("startTransition(");
    for stmt in statements {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        for decl in &var_decl.declarations {
            let Some(Expression::CallExpression(call)) = decl.init.as_ref().map(unwrap_expr) else {
                continue;
            };
            if !is_named_hook_call(call, "useState") {
                continue;
            }
            let BindingPattern::ArrayPattern(arr) = &decl.id else {
                continue;
            };
            let Some(Some(first_pat)) = arr.elements.first() else {
                continue;
            };
            let Some(state_id) = first_pat.get_binding_identifier() else {
                continue;
            };
            let lower = state_id.name.to_ascii_lowercase();
            let is_loading_name = lower == "loading"
                || lower == "isloading"
                || lower == "ispending"
                || lower.ends_with("loading");
            if is_loading_name && has_transition {
                out.push(SemanticRuleSite {
                    rule: RuleId::RenderingUsetransitionLoading,
                    subject_name: subject_name.clone(),
                    message_id: "renderingUsetransitionLoading",
                    target_name: state_id.name.to_string(),
                    message: format!(
                        "Manual loading state `{}` forces an extra render pass; prefer `useTransition`'s `isPending` flag.",
                        state_id.name
                    ),
                    loc: loc_from_line_starts(line_starts, decl.span.start),
                    span: ByteSpan {
                        start: decl.span.start,
                        end: decl.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}
