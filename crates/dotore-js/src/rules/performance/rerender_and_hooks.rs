//! React component re-render, memoization, and state/memo initializer rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
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
    DEP_HOOK_NAMES, MemoStatus, extract_jsx_identifier_name, is_react_named_hook_call,
};
use crate::{
    ir::{
        react_ast::{get_subject_name, is_component_name},
        types::SemanticRuleSite,
    },
    matchers::{is_hook_with_deps_call, push_semantic_site, resolve_ident_symbol, unwrap_expr},
    rules::RuleId,
};

pub(super) fn build_same_file_memo_registry(
    semantic: &Semantic<'_>,
) -> HashMap<String, MemoStatus> {
    let mut registry = HashMap::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        register_memo_node_in_registry(node.kind(), semantic, &mut registry);
    }
    registry
}

fn register_memo_node_in_registry(
    kind: AstKind<'_>,
    semantic: &Semantic<'_>,
    registry: &mut HashMap<String, MemoStatus>,
) {
    match kind {
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
                return;
            };
            if !is_component_name(id.name.as_str()) {
                return;
            };
            let Some(init) = &decl.init else {
                return;
            };
            if let Some(status) = classify_memo_call_init(init, semantic) {
                registry.insert(id.name.to_string(), status);
            } else if matches!(
                unwrap_expr(init),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            ) {
                registry.insert(id.name.to_string(), MemoStatus::NotMemoized);
            }
        }
        AstKind::ExportDefaultDeclaration(exp) => {
            if let oxc_ast::ast::ExportDefaultDeclarationKind::CallExpression(call) =
                &exp.declaration
                && is_memo_callee(&call.callee)
                && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
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
    reason = "Inspects parameter and body destructuring defaults against component body uses (#50)"
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
    let defaults = collect_component_empty_defaults(params, statements);
    if defaults.is_empty() {
        return;
    }

    for (name, kind, def_span) in defaults {
        let (used_in_deps, used_in_memo_prop) =
            find_default_value_memo_usage(&name, body_span, memo_registry, semantic);
        if !used_in_deps && !used_in_memo_prop {
            continue;
        }
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

fn collect_component_empty_defaults(
    params: &[oxc_ast::ast::FormalParameter<'_>],
    statements: &[Statement<'_>],
) -> Vec<(String, EmptyLiteralKind, Span)> {
    let mut defaults: Vec<(String, EmptyLiteralKind, Span)> = Vec::new();
    for param in params {
        collect_empty_defaults_from_pattern(&param.pattern, &mut defaults);
    }
    let Some(first_param) = params.first() else {
        return defaults;
    };
    let Some(props_id) = first_param.pattern.get_binding_identifier() else {
        return defaults;
    };
    for stmt in statements {
        let Statement::VariableDeclaration(var_decl) = stmt else {
            continue;
        };
        for decl in &var_decl.declarations {
            if let Some(init) = &decl.init
                && matches!(unwrap_expr(init), Expression::Identifier(id) if id.name == props_id.name)
            {
                collect_empty_defaults_from_pattern(&decl.id, &mut defaults);
            }
        }
    }
    defaults
}

fn find_default_value_memo_usage(
    name: &str,
    body_span: Span,
    memo_registry: &HashMap<String, MemoStatus>,
    semantic: &Semantic<'_>,
) -> (bool, bool) {
    let mut used_in_deps = false;
    let mut used_in_memo_prop = false;

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                if is_dep_hook_call(semantic, call) && call_deps_reference_ident(call, name) {
                    used_in_deps = true;
                }
            }
            AstKind::JSXOpeningElement(opening)
                if jsx_memo_prop_references_ident(opening, name, memo_registry) =>
            {
                used_in_memo_prop = true;
            }
            _ => {}
        }
    }
    (used_in_deps, used_in_memo_prop)
}

fn call_deps_reference_ident(call: &CallExpression<'_>, name: &str) -> bool {
    for arg in &call.arguments {
        let Some(Expression::ArrayExpression(arr)) = arg.as_expression().map(unwrap_expr) else {
            continue;
        };
        for elem in &arr.elements {
            if let Some(expr) = elem.as_expression()
                && matches!(unwrap_expr(expr), Expression::Identifier(id) if id.name == name)
            {
                return true;
            }
        }
    }
    false
}

fn jsx_memo_prop_references_ident(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    name: &str,
    memo_registry: &HashMap<String, MemoStatus>,
) -> bool {
    let Some(tag_name) = extract_jsx_identifier_name(&opening.name) else {
        return false;
    };
    if !is_component_name(tag_name) || memo_registry.get(tag_name) == Some(&MemoStatus::NotMemoized)
    {
        return false;
    }
    opening.attributes.iter().any(|attr_item| {
        let JSXAttributeItem::Attribute(attr) = attr_item else {
            return false;
        };
        if let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value
            && let Some(expr) = cont.expression.as_expression()
        {
            matches!(unwrap_expr(expr), Expression::Identifier(id) if id.name == name)
        } else {
            false
        }
    })
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

fn is_dep_hook_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    if is_hook_with_deps_call(semantic, call) {
        return true;
    }
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
            if let Some((span, name_opt, guards)) = try_find_jsx_use_memo_in_stmt(stmt, semantic) {
                memo_decl_span = Some(span);
                if let Some(name) = name_opt {
                    memo_consumers.insert(name);
                }
                callback_guard_texts = guards;
            }
            continue;
        }

        extend_memo_consumers_from_stmt(stmt, &mut memo_consumers, semantic);

        if let Statement::IfStatement(if_stmt) = stmt
            && is_unguarded_early_return_after_memo(
                if_stmt,
                &memo_consumers,
                &callback_guard_texts,
                semantic,
            )
        {
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

fn try_find_jsx_use_memo_in_stmt(
    stmt: &Statement<'_>,
    semantic: &Semantic<'_>,
) -> Option<(Span, Option<String>, Vec<String>)> {
    let Statement::VariableDeclaration(var_decl) = stmt else {
        return None;
    };
    for decl in &var_decl.declarations {
        let Some(init) = &decl.init else {
            continue;
        };
        if let Expression::CallExpression(call) = unwrap_expr(init)
            && is_react_named_hook_call(call, "useMemo")
            && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
            && span_contains_jsx(first_arg.span(), semantic)
        {
            let name_opt = decl
                .id
                .get_binding_identifier()
                .map(|id| id.name.to_string());
            let guards = collect_leading_guard_texts(first_arg, semantic.source_text());
            return Some((decl.span, name_opt, guards));
        }
    }
    None
}

fn extend_memo_consumers_from_stmt(
    stmt: &Statement<'_>,
    memo_consumers: &mut HashSet<String>,
    semantic: &Semantic<'_>,
) {
    let Statement::VariableDeclaration(var_decl) = stmt else {
        return;
    };
    for decl in &var_decl.declarations {
        if let (Some(id), Some(init)) = (decl.id.get_binding_identifier(), &decl.init)
            && span_references_any(init.span(), memo_consumers, semantic)
        {
            memo_consumers.insert(id.name.to_string());
        }
    }
}

fn is_unguarded_early_return_after_memo(
    if_stmt: &oxc_ast::ast::IfStatement<'_>,
    memo_consumers: &HashSet<String>,
    callback_guard_texts: &[String],
    semantic: &Semantic<'_>,
) -> bool {
    if memo_consumers.is_empty()
        || !has_early_return_ignoring_memo(&if_stmt.consequent, memo_consumers, semantic)
        || span_references_any(if_stmt.test.span(), memo_consumers, semantic)
    {
        return false;
    }
    let test_norm = normalize_ws(if_stmt.test.span().source_text(semantic.source_text()));
    !callback_guard_texts.iter().any(|g| g == &test_norm)
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
            let Some((cont_name, hook_name)) = extract_continuous_hook_binding(decl) else {
                continue;
            };
            let threshold_spans =
                collect_following_threshold_spans(&statements[idx + 1..], cont_name);
            if threshold_spans.is_empty() {
                continue;
            }
            if !is_referenced_outside_thresholds(
                cont_name,
                decl.span,
                &threshold_spans,
                body_span,
                semantic,
            ) {
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

fn extract_continuous_hook_binding<'a>(
    decl: &'a oxc_ast::ast::VariableDeclarator<'a>,
) -> Option<(&'a str, &'a str)> {
    let id = decl.id.get_binding_identifier()?;
    let Expression::CallExpression(call) = decl.init.as_ref().map(unwrap_expr)? else {
        return None;
    };
    let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
        return None;
    };
    let hook_name = callee_id.name.as_str();
    is_continuous_value_hook_name(hook_name).then_some((id.name.as_str(), hook_name))
}

fn collect_following_threshold_spans(
    following_stmts: &[Statement<'_>],
    cont_name: &str,
) -> Vec<Span> {
    let mut threshold_spans: Vec<Span> = Vec::new();
    for next_stmt in following_stmts {
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
    threshold_spans
}

fn is_referenced_outside_thresholds(
    cont_name: &str,
    decl_span: Span,
    threshold_spans: &[Span],
    body_span: Span,
    semantic: &Semantic<'_>,
) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        if !body_span.contains_inclusive(n.span())
            || decl_span.contains_inclusive(n.span())
            || threshold_spans
                .iter()
                .any(|s| s.contains_inclusive(n.span()))
        {
            return false;
        }
        matches!(n.kind(), AstKind::IdentifierReference(ref_id) if ref_id.name == cont_name)
    })
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

