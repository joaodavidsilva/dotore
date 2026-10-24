//! Nullish, optional-chain, array, and object runtime guard rule detectors.

use oxc_ast::{
    AstKind,
    ast::{
        BinaryExpression, BinaryOperator, BindingPattern, CallExpression, ChainElement, Expression,
        FormalParameter, LogicalExpression, LogicalOperator, TSNonNullExpression, TemplateLiteral,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    MAYBE_UNDEFINED_METHODS, enclosing_function_or_program_start, get_var_declarator_init,
    has_nullish_guard_before, is_guarded_in_enclosing_short_circuit,
    is_inside_optional_chain_parent, resolve_symbol_id,
};
use crate::{
    ir::{ByteSpan, SemanticRuleSite, types::loc_from_line_starts},
    matchers::push_semantic_site,
    rules::types::RuleId,
};

// ---------------------------------------------------------------------------
// 1. `no-arithmetic-on-optional-chained-operand`
// ---------------------------------------------------------------------------
pub(super) fn check_no_arithmetic_on_optional_chained_operand(
    semantic: &Semantic<'_>,
    bin: &BinaryExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !matches!(
        bin.operator,
        BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Subtraction
            | BinaryOperator::Exponential
            | BinaryOperator::Addition
    ) {
        return;
    }

    // For Addition, skip if the other operand is a StringLiteral or TemplateLiteral (string concatenation)
    if bin.operator == BinaryOperator::Addition
        && (is_string_like_expr(&bin.left) || is_string_like_expr(&bin.right))
    {
        return;
    }

    let left_opt = is_unguarded_optional_chain(semantic, &bin.left);
    let right_opt = is_unguarded_optional_chain(semantic, &bin.right);
    if left_opt || right_opt {
        let target_expr = if left_opt { &bin.left } else { &bin.right };
        let target = target_expr.span().source_text(semantic.source_text());
        push_semantic_site(
            sites,
            RuleId::NoArithmeticOnOptionalChainedOperand,
            subj_name.clone(),
            "noArithmeticOnOptionalChainedOperand",
            target,
            "Arithmetic on an optional-chained operand evaluates to `NaN` when the chain short-circuits to `undefined`; provide a `?? fallback` or guard the chain root first.".to_string(),
            line_starts,
            bin.span,
        );
    }
}

fn is_string_like_expr(expr: &Expression<'_>) -> bool {
    matches!(
        expr.without_parentheses(),
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
    )
}

fn is_unguarded_optional_chain(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ChainExpression(_) => true,
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            matches!(init.without_parentheses(), Expression::ChainExpression(_))
                && !has_nullish_guard_before(semantic, ident.span.start, ident.name.as_str())
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 2. `no-array-find-result-member-access-without-guard`
// ---------------------------------------------------------------------------
#[expect(
    clippy::too_many_arguments,
    reason = "Receives member access AST context and output accumulator"
)]
pub(super) fn check_no_array_find_result_member_access_without_guard(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    access_span: Span,
    object: &Expression<'_>,
    is_optional: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_optional || is_inside_optional_chain_parent(semantic, node_id) {
        return;
    }

    let is_unguarded_find = match object.without_parentheses() {
        Expression::CallExpression(call) => is_find_or_find_last_call(call),
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return;
            };
            let Expression::CallExpression(call) = init.without_parentheses() else {
                return;
            };
            if !is_find_or_find_last_call(call) {
                return;
            }
            !has_nullish_guard_before(semantic, access_span.start, ident.name.as_str())
                && !is_guarded_in_enclosing_short_circuit(semantic, node_id, ident.name.as_str())
        }
        _ => false,
    };

    if is_unguarded_find {
        let target = object.span().source_text(semantic.source_text());
        push_semantic_site(
            sites,
            RuleId::NoArrayFindResultMemberAccessWithoutGuard,
            subj_name.clone(),
            "noArrayFindResultMemberAccessWithoutGuard",
            target,
            "`Array.prototype.find`/`findLast` can return `undefined`; guard the result with `?.` or a null check before accessing members.".to_string(),
            line_starts,
            access_span,
        );
    }
}

fn is_find_or_find_last_call(call: &CallExpression<'_>) -> bool {
    match call.callee.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.property.name.as_str(), "find" | "findLast")
        }
        Expression::ChainExpression(chain) => {
            if let ChainElement::CallExpression(inner_call) = &chain.expression
                && let Expression::StaticMemberExpression(mem) =
                    inner_call.callee.without_parentheses()
            {
                matches!(mem.property.name.as_str(), "find" | "findLast")
            } else {
                false
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 3. `no-array-index-deref-without-bounds-or-empty-guard`
// ---------------------------------------------------------------------------
#[expect(
    clippy::too_many_arguments,
    reason = "Receives member access AST context and output accumulator"
)]
pub(super) fn check_no_array_index_deref_without_bounds_or_empty_guard(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    access_span: Span,
    object: &Expression<'_>,
    is_optional: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_optional || is_inside_optional_chain_parent(semantic, node_id) {
        return;
    }
    // Skip left-hand side of assignment (`items[0].title = ...` vs read — actually dereferencing `items[0].title = ...` also crashes if `items[0]` is undefined, but skip direct `items[0] = ...` which is ComputedMemberExpression, not member on ComputedMemberExpression)
    let index_expr = match object.without_parentheses() {
        Expression::ComputedMemberExpression(comp) if !comp.optional => Some(comp.as_ref()),
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return;
            };
            if let Expression::ComputedMemberExpression(comp) = init.without_parentheses()
                && !comp.optional
            {
                if has_nullish_guard_before(semantic, access_span.start, ident.name.as_str())
                    || is_guarded_in_enclosing_short_circuit(semantic, node_id, ident.name.as_str())
                {
                    return;
                }
                Some(comp.as_ref())
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(comp) = index_expr else {
        return;
    };

    // Check if the index is a numeric literal or identifier and the receiver is an array/call
    let is_numeric_or_dynamic_index = matches!(
        comp.expression.without_parentheses(),
        Expression::NumericLiteral(_)
            | Expression::Identifier(_)
            | Expression::BinaryExpression(_)
            | Expression::UnaryExpression(_)
    );
    if !is_numeric_or_dynamic_index {
        return;
    }

    // Skip if receiver is a literal non-empty array `[a, b][0].foo`
    if let Expression::ArrayExpression(arr) = comp.object.without_parentheses()
        && !arr.elements.is_empty()
    {
        return;
    }

    let arr_text = comp
        .object
        .span()
        .source_text(semantic.source_text())
        .trim();
    let full_comp_text = comp.span.source_text(semantic.source_text()).trim();

    if has_bounds_or_length_guard_before(
        semantic,
        node_id,
        access_span.start,
        arr_text,
        full_comp_text,
    ) {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::NoArrayIndexDerefWithoutBoundsOrEmptyGuard,
        subj_name.clone(),
        "noArrayIndexDerefWithoutBoundsOrEmptyGuard",
        full_comp_text,
        format!(
            "Indexing `{full_comp_text}` and dereferencing it without a length/bounds guard or `?.` throws when `{arr_text}` is empty or shorter than expected."
        ),
        line_starts,
        access_span,
    );
}

fn has_bounds_or_length_guard_before(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    before_offset: u32,
    arr_name: &str,
    indexed_expr: &str,
) -> bool {
    if is_guarded_in_enclosing_short_circuit(semantic, node_id, indexed_expr)
        || is_guarded_in_enclosing_short_circuit(semantic, node_id, &format!("{arr_name}.length"))
    {
        return true;
    }

    // Also allow inside traditional `for (let i = 0; i < arr.length; i++)`
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::ForStatement(for_stmt) = semantic.nodes().kind(anc_id)
            && let Some(test) = &for_stmt.test
        {
            let test_src = test.span().source_text(semantic.source_text());
            if test_src.contains(&format!("{arr_name}.length")) {
                return true;
            }
        }
    }

    let scope_start = enclosing_function_or_program_start(semantic, node_id);
    let prefix = semantic
        .source_text()
        .get(scope_start as usize..before_offset as usize)
        .unwrap_or_default();

    prefix.contains(&format!("{arr_name}.length"))
        || prefix.contains(&format!("!{indexed_expr}"))
        || prefix.contains(&format!("{indexed_expr} != null"))
        || prefix.contains(&format!("{indexed_expr} !== undefined"))
        || prefix.contains(&format!("Array.isArray({arr_name})"))
}

// ---------------------------------------------------------------------------
// 11. `no-non-null-assertion-on-maybe-undefined-result`
// ---------------------------------------------------------------------------
pub(super) fn check_no_non_null_assertion_on_maybe_undefined_result(
    semantic: &Semantic<'_>,
    non_null: &TSNonNullExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_maybe_undefined_lookup_expr(semantic, &non_null.expression) {
        let target = non_null
            .expression
            .span()
            .source_text(semantic.source_text());
        push_semantic_site(
            sites,
            RuleId::NoNonNullAssertionOnMaybeUndefinedResult,
            subj_name.clone(),
            "noNonNullAssertionOnMaybeUndefinedResult",
            target,
            "Non-null assertion (`!`) on a lookup result (`.find()`, `.match()`, `.get()`, etc.) hides `undefined`/`null` from TypeScript and crashes when no match is found.".to_string(),
            line_starts,
            non_null.span,
        );
    }
}

fn is_maybe_undefined_lookup_expr(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                MAYBE_UNDEFINED_METHODS.contains(&mem.property.name.as_str())
            } else {
                false
            }
        }
        Expression::ChainExpression(_) => true,
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            is_maybe_undefined_lookup_expr(semantic, init)
                && !has_nullish_guard_before(semantic, ident.span.start, ident.name.as_str())
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 12. `no-nullish-coalescing-arithmetic-precedence`
// ---------------------------------------------------------------------------
pub(super) fn check_no_nullish_coalescing_arithmetic_precedence(
    log: &LogicalExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if log.operator != LogicalOperator::Coalesce {
        return;
    }

    // Notice we check `log.left` and `log.right` WITHOUT stripping parentheses!
    // Because `(a ?? 0) + b` parses as `BinaryExpression(ParenthesizedExpression(LogicalExpression), b)`,
    // whereas `a ?? 0 + b` parses as `LogicalExpression(a, BinaryExpression(0, b))` where `log.right` is an unparenthesized `BinaryExpression`.
    let right_is_unparenthesized_arith = is_unparenthesized_arithmetic(&log.right);
    let left_is_unparenthesized_arith = is_unparenthesized_arithmetic(&log.left);

    if right_is_unparenthesized_arith || left_is_unparenthesized_arith {
        push_semantic_site(
            sites,
            RuleId::NoNullishCoalescingArithmeticPrecedence,
            subj_name.clone(),
            "noNullishCoalescingArithmeticPrecedence",
            "??",
            "Arithmetic binds tighter than `??`, so unparenthesized arithmetic next to `??` evaluates before the fallback; wrap the nullish coalescing expression in parentheses (`(x ?? 0) + y`).".to_string(),
            line_starts,
            log.span,
        );
    }
}

fn is_unparenthesized_arithmetic(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::BinaryExpression(bin)
            if matches!(
                bin.operator,
                BinaryOperator::Addition
                    | BinaryOperator::Subtraction
                    | BinaryOperator::Multiplication
                    | BinaryOperator::Division
                    | BinaryOperator::Remainder
                    | BinaryOperator::Exponential
            )
    )
}

// ---------------------------------------------------------------------------
// 13. `no-object-keys-values-entries-on-maybe-undefined`
// ---------------------------------------------------------------------------
pub(super) fn check_no_object_keys_values_entries_on_maybe_undefined(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let Expression::Identifier(obj_id) = mem.object.without_parentheses() else {
        return;
    };
    if obj_id.name != "Object"
        || !matches!(mem.property.name.as_str(), "keys" | "values" | "entries")
    {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };

    if is_maybe_undefined_object_arg(semantic, node_id, first_arg, call.span.start) {
        let method = mem.property.name.as_str();
        push_semantic_site(
            sites,
            RuleId::NoObjectKeysValuesEntriesOnMaybeUndefined,
            subj_name.clone(),
            "noObjectKeysValuesEntriesOnMaybeUndefined",
            &format!("Object.{method}"),
            format!(
                "`Object.{method}(...)` throws a `TypeError` when its argument is `undefined` or `null`; provide a `?? {{}}` fallback or guard the value first."
            ),
            line_starts,
            call.span,
        );
    }
}

fn is_maybe_undefined_object_arg(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    arg: &Expression<'_>,
    call_start: u32,
) -> bool {
    match arg.without_parentheses() {
        Expression::ChainExpression(_) => true,
        Expression::Identifier(ident) => {
            let name = ident.name.as_str();
            if has_nullish_guard_before(semantic, call_start, name)
                || is_guarded_in_enclosing_short_circuit(semantic, node_id, name)
            {
                return false;
            }
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::FormalParameter(param) => {
                    param.optional || {
                        let param_src = param.span.source_text(semantic.source_text());
                        (param_src.contains("undefined") || param_src.contains("?:"))
                            && !param_src.contains('=')
                    }
                }
                AstKind::VariableDeclarator(decl) => decl.init.as_ref().is_some_and(|init| {
                    matches!(init.without_parentheses(), Expression::ChainExpression(_))
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 14. `no-object-or-array-coerced-to-string-in-template-literal`
// ---------------------------------------------------------------------------
pub(super) fn check_no_object_or_array_coerced_to_string_in_template_literal(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    tpl: &TemplateLiteral<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Skip tagged template literals (e.g. `css`...``, `sql`...``, `gql`...``)
    if matches!(
        semantic.nodes().parent_kind(node_id),
        AstKind::TaggedTemplateExpression(_)
    ) {
        return;
    }

    for expr in &tpl.expressions {
        if is_object_or_array_valued_expr(semantic, expr) {
            let target = expr.span().source_text(semantic.source_text()).to_string();
            sites.push(SemanticRuleSite {
                rule: RuleId::NoObjectOrArrayCoercedToStringInTemplateLiteral,
                subject_name: subj_name.clone(),
                message_id: "noObjectOrArrayCoercedToStringInTemplateLiteral",
                target_name: target,
                message: "Interpolating an object or array directly into a template literal coerces it to `\"[object Object]\"` or comma-joined text; format a specific property or use `JSON.stringify(...)` / `.join(...)`.".to_string(),
                loc: loc_from_line_starts(line_starts, expr.span().start),
                span: ByteSpan {
                    start: tpl.span.start,
                    end: tpl.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn is_object_or_array_valued_expr(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_) => true,
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::VariableDeclarator(decl) => {
                    if let Some(init) = &decl.init {
                        matches!(
                            init.without_parentheses(),
                            Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
                        )
                    } else {
                        false
                    }
                }
                AstKind::FormalParameter(param) => {
                    let src = param.span.source_text(semantic.source_text());
                    src.contains(": {")
                        || src.contains("Record<")
                        || src.contains("Array<")
                        || src.contains("[]")
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 21. `no-whole-object-default-losing-per-key-defaults`
// ---------------------------------------------------------------------------
pub(super) fn check_no_whole_object_default_losing_per_key_defaults(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    param: &FormalParameter<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(init) = &param.initializer else {
        return;
    };
    let Expression::ObjectExpression(obj) = init.without_parentheses() else {
        return;
    };
    if obj.properties.is_empty() {
        return;
    }

    // Check if the parameter binding is an identifier or an ObjectPattern without per-key defaults
    let loses_per_key_defaults = match &param.pattern {
        BindingPattern::BindingIdentifier(_) => true,
        BindingPattern::ObjectPattern(obj_pat) => obj_pat
            .properties
            .iter()
            .any(|p| !matches!(p.value, BindingPattern::AssignmentPattern(_))),
        _ => false,
    };

    if loses_per_key_defaults {
        let target = param.pattern.span().source_text(semantic.source_text());
        push_semantic_site(
            sites,
            RuleId::NoWholeObjectDefaultLosingPerKeyDefaults,
            subj_name.clone(),
            "noWholeObjectDefaultLosingPerKeyDefaults",
            target,
            "Whole-object parameter default (`= { ... }`) only applies when the argument is `undefined`; destructure with per-key defaults (`{ a = 1, b = 2 } = {}`) so partial arguments keep fallback values.".to_string(),
            line_starts,
            param.span,
        );
    }
}
