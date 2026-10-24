//! React component re-render, memoization, and state/memo initializer rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
)]
#![expect(
    clippy::excessive_nesting,
    reason = "Component body, hook argument, and JSX attribute AST destructuring traverses nested AST layers directly"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BinaryOperator, BindingPattern, CallExpression, Expression,
        JSXAttributeItem, JSXAttributeValue, Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags};
use oxc_span::{GetSpan, Span};

use super::{
    CHEAP_CONSTRUCTORS, DEP_HOOK_NAMES, HIGH_FREQUENCY_DOM_EVENTS, MemoStatus,
    extract_jsx_identifier_name, is_react_named_hook_call,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name, is_component_name},
        types::SemanticRuleSite,
    },
    matchers::{is_global_ident, push_semantic_site, resolve_ident_symbol, unwrap_expr},
    rules::RuleId,
};

pub(super) fn build_same_file_memo_registry(semantic: &Semantic<'_>) -> HashMap<String, MemoStatus> {
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

pub(super) fn extract_component_fn_parts<'a>(
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
// 5. `rendering-usetransition-loading`
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "Passes unpacked component signature, body statements, and shared registries together"
)]
pub(super) fn check_component_function(
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
                    if is_dep_hook_call(call) {
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
            push_semantic_site(
                out,
                RuleId::RerenderMemoWithDefaultValue,
                subject_name.clone(),
                "rerenderMemoWithDefaultValue",
                &name,
                message,
                line_starts,
                def_span,
            );
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

fn is_dep_hook_call(call: &CallExpression<'_>) -> bool {
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
                    && is_react_named_hook_call(call, "useMemo")
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
                push_semantic_site(
                    out,
                    RuleId::RerenderMemoBeforeEarlyReturn,
                    subject_name.clone(),
                    "rerenderMemoBeforeEarlyReturn",
                    "useMemo",
                    "This rebuilds the JSX whenever its dependencies change even on renders that take the early return, so move the JSX into a child component rendered after the early return to skip it".to_string(),
                    line_starts,
                    span,
                );
            }
            return;
        }
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
                push_semantic_site(
                    out,
                    RuleId::RerenderDerivedStateFromHook,
                    subject_name.clone(),
                    "rerenderDerivedStateFromHook",
                    hook_name,
                    format!(
                        "This redraws the screen far more than needed because {hook_name}() changes constantly but you only check it against a cutoff, so use a threshold hook like `useMediaQuery(\"(max-width: 767px)\")` to redraw only when the answer changes"
                    ),
                    line_starts,
                    decl.span,
                );
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
            push_semantic_site(
                out,
                RuleId::RenderingHoistJsx,
                subject_name.clone(),
                "renderingHoistJsx",
                name,
                format!(
                    "This rebuilds on every render because static JSX \"{name}\" is built inside the component, so move it to the top of the file to make it just once"
                ),
                line_starts,
                decl.span,
            );
        }
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
            if !is_react_named_hook_call(call, "useState") {
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
                push_semantic_site(
                    out,
                    RuleId::RenderingUsetransitionLoading,
                    subject_name.clone(),
                    "renderingUsetransitionLoading",
                    state_id.name.as_str(),
                    format!(
                        "Manual loading state `{}` forces an extra render pass; prefer `useTransition`'s `isPending` flag.",
                        state_id.name
                    ),
                    line_starts,
                    decl.span,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CallExpression rules:
// 6. `rerender-transitions-scroll`
// 7. `no-match-media-in-state-initializer`
// 8. `no-eager-new-in-use-state-initializer`
// 9. `no-usememo-simple-expression`
// ---------------------------------------------------------------------------

pub(super) fn check_rerender_transitions_scroll(
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
        push_semantic_site(
            out,
            RuleId::RerenderTransitionsScroll,
            subject_name,
            "rerenderTransitionsScroll",
            name,
            format!(
                "This can make scrolling stutter because setState in a \"{event_name}\" handler redraws on every event. Wrap it in startTransition, use useDeferredValue, or keep the value in a ref and throttle with requestAnimationFrame."
            ),
            line_starts,
            set_call.span,
        );
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

pub(super) fn check_no_match_media_in_state_initializer(
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
        push_semantic_site(
            out,
            RuleId::NoMatchMediaInStateInitializer,
            subject_name,
            "noMatchMediaInStateInitializer",
            "matchMedia",
            "`matchMedia()` in a useState initializer can cause an SSR crash or seed different server and hydration state. Prefer CSS media queries for layout, or use `useSyncExternalStore` with a stable server snapshot.".to_string(),
            line_starts,
            mm_call.span,
        );
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

pub(super) fn check_no_eager_new_in_use_state_initializer(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_named_hook_call(call, "useState") {
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
    let target_name = format!("new {ctor_name}()");
    push_semantic_site(
        out,
        RuleId::NoEagerNewInUseStateInitializer,
        subject_name,
        "noEagerNewInUseStateInitializer",
        &target_name,
        format!(
            "`new {ctor_name}()` inside `useState(...)` runs on every render; pass a lazy initializer `useState(() => new {ctor_name}(...))` so it only runs on mount."
        ),
        line_starts,
        new_expr.span,
    );
}

pub(super) fn check_no_usememo_simple_expression(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_named_hook_call(call, "useMemo") {
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
    push_semantic_site(
        out,
        RuleId::NoUsememoSimpleExpression,
        subject_name,
        "noUsememoSimpleExpression",
        "useMemo",
        "This costs more than it saves because useMemo is wrapping a value that's already cheap, so remove the useMemo".to_string(),
        line_starts,
        call.span,
    );
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
