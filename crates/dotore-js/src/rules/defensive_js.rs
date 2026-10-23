//! Defensive JavaScript, TypeScript, and DOM runtime safety rule detectors (21 rules).
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use oxc_ast::{
    AstKind,
    ast::{
        AssignmentTarget, BinaryExpression, BinaryOperator, BindingPattern, CallExpression,
        ChainElement, Expression, FormalParameter, JSXAttributeItem, JSXAttributeValue,
        JSXOpeningElement, LogicalExpression, LogicalOperator, NewExpression,
        StaticMemberExpression, TSNonNullExpression, TemplateLiteral,
    },
};
use oxc_semantic::{NodeId, ReferenceId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan, SemanticRuleSite, SubjectIr,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

const PREDICATE_PREFIXES: &[&str] = &["is", "has", "can", "should", "will"];

const SELECTOR_QUERY_METHODS: &[&str] =
    &["querySelector", "querySelectorAll", "matches", "closest"];

const MAYBE_UNDEFINED_METHODS: &[&str] = &[
    "find",
    "findLast",
    "match",
    "get",
    "pop",
    "shift",
    "at",
    "exec",
    "querySelector",
    "getElementById",
    "closest",
];

const THROWING_PARSE_FUNCTIONS: &[&str] = &[
    "decodeURIComponent",
    "decodeURI",
    "atob",
    "readableColor",
    "parseToRgb",
    "parseToHsl",
    "chroma",
];

/// Extracts all single-pass defensive JS/TS/DOM runtime safety rule sites and autofixes.
pub(crate) fn extract_defensive_js_sites(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::BinaryExpression(bin) => {
                check_no_arithmetic_on_optional_chained_operand(
                    semantic,
                    bin,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::LogicalExpression(log) => {
                check_no_nullish_coalescing_arithmetic_precedence(
                    log,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_predicate_in_logical(
                    semantic,
                    node_id,
                    log,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::StaticMemberExpression(mem) => {
                check_no_array_find_result_member_access_without_guard(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_array_index_deref_without_bounds_or_empty_guard(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_deprecated_keyboard_event_keycode_which(
                    semantic,
                    node_id,
                    mem,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unsafe_json_parse_member(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ComputedMemberExpression(comp) => {
                check_no_array_find_result_member_access_without_guard(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_array_index_deref_without_bounds_or_empty_guard(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unsafe_json_parse_member(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_no_object_keys_values_entries_on_maybe_undefined(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_non_literal_selector_query_without_try_catch(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_numeric_input_parse(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_throwing_parse_call(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_collapse_request_error_to_empty_state_call(
                    semantic,
                    call,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_loading_flag_reset_outside_finally(
                    semantic,
                    node_id,
                    call,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::NewExpression(new_expr) => {
                check_no_unescaped_dynamic_string_in_regexp(
                    semantic,
                    new_expr,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_throwing_new_url(
                    semantic,
                    node_id,
                    new_expr,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TSNonNullExpression(non_null) => {
                check_no_non_null_assertion_on_maybe_undefined_result(
                    semantic,
                    non_null,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TemplateLiteral(tpl) => {
                check_no_object_or_array_coerced_to_string_in_template_literal(
                    semantic,
                    node_id,
                    tpl,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::IfStatement(if_stmt) => {
                check_predicate_in_condition(
                    semantic,
                    &if_stmt.test,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ConditionalExpression(cond) => {
                check_predicate_in_condition(
                    semantic,
                    &cond.test,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::WhileStatement(while_stmt) => {
                check_predicate_in_condition(
                    semantic,
                    &while_stmt.test,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::UnaryExpression(un) if un.operator == oxc_ast::ast::UnaryOperator::LogicalNot => {
                check_predicate_in_condition(
                    semantic,
                    &un.argument,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::FormalParameter(param) => {
                check_no_whole_object_default_losing_per_key_defaults(
                    semantic,
                    node_id,
                    param,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_jsx_event_handler_defensive_rules(
                    semantic,
                    opening,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TryStatement(try_stmt) => {
                check_no_collapse_request_error_in_try_catch(
                    semantic,
                    try_stmt,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }

    check_no_passive_request_owner_ref(semantic, line_starts, sites);
}

// ---------------------------------------------------------------------------
// 1. `no-arithmetic-on-optional-chained-operand`
// ---------------------------------------------------------------------------
fn check_no_arithmetic_on_optional_chained_operand(
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
        let target = target_expr
            .span()
            .source_text(semantic.source_text())
            .to_string();
        sites.push(SemanticRuleSite {
            rule: RuleId::NoArithmeticOnOptionalChainedOperand,
            subject_name: subj_name.clone(),
            message_id: "noArithmeticOnOptionalChainedOperand",
            target_name: target,
            message: "Arithmetic on an optional-chained operand evaluates to `NaN` when the chain short-circuits to `undefined`; provide a `?? fallback` or guard the chain root first.".to_string(),
            loc: loc_from_line_starts(line_starts, bin.span.start),
            span: ByteSpan {
                start: bin.span.start,
                end: bin.span.end,
            },
            autofix: None,
        });
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
fn check_no_array_find_result_member_access_without_guard(
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
        let target = object
            .span()
            .source_text(semantic.source_text())
            .to_string();
        sites.push(SemanticRuleSite {
            rule: RuleId::NoArrayFindResultMemberAccessWithoutGuard,
            subject_name: subj_name.clone(),
            message_id: "noArrayFindResultMemberAccessWithoutGuard",
            target_name: target,
            message: "`Array.prototype.find`/`findLast` can return `undefined`; guard the result with `?.` or a null check before accessing members.".to_string(),
            loc: loc_from_line_starts(line_starts, access_span.start),
            span: ByteSpan {
                start: access_span.start,
                end: access_span.end,
            },
            autofix: None,
        });
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
fn check_no_array_index_deref_without_bounds_or_empty_guard(
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

    sites.push(SemanticRuleSite {
        rule: RuleId::NoArrayIndexDerefWithoutBoundsOrEmptyGuard,
        subject_name: subj_name.clone(),
        message_id: "noArrayIndexDerefWithoutBoundsOrEmptyGuard",
        target_name: full_comp_text.to_string(),
        message: format!(
            "Indexing `{full_comp_text}` and dereferencing it without a length/bounds guard or `?.` throws when `{arr_text}` is empty or shorter than expected."
        ),
        loc: loc_from_line_starts(line_starts, access_span.start),
        span: ByteSpan {
            start: access_span.start,
            end: access_span.end,
        },
        autofix: None,
    });
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
// 4, 7, 8. JSX Event Handler Rules:
// - `no-async-event-handler-without-reentry-guard`
// - `no-enter-submit-without-ime-composition-guard`
// - `no-floating-then-in-jsx-handler`
// ---------------------------------------------------------------------------
fn check_jsx_event_handler_defensive_rules(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let (tag_name, _, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);
    let has_disabled_attr = opening.attributes.iter().any(|item| {
        matches!(
            item,
            JSXAttributeItem::Attribute(a)
                if a.name.as_identifier().is_some_and(|id| id.name == "disabled")
        )
    });
    let has_composition_handlers = opening.attributes.iter().any(|item| {
        matches!(
            item,
            JSXAttributeItem::Attribute(a)
                if a.name.as_identifier().is_some_and(|id| {
                    matches!(id.name.as_str(), "onCompositionStart" | "onCompositionEnd")
                })
        )
    });

    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let Some(attr_ident) = attr.name.as_identifier() else {
            continue;
        };
        let attr_name = attr_ident.name.as_str();
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value else {
            continue;
        };
        let Some(expr) = container.expression.as_expression() else {
            continue;
        };

        // 4. `no-async-event-handler-without-reentry-guard`
        if !is_comp && matches!(attr_name, "onClick" | "onSubmit" | "onPress") {
            check_async_event_handler_reentry(
                semantic,
                expr,
                attr.span,
                &tag_name,
                has_disabled_attr,
                subjects,
                subj_name,
                line_starts,
                sites,
            );
        }

        // 7. `no-enter-submit-without-ime-composition-guard`
        if matches!(attr_name, "onKeyDown" | "onKeyPress" | "onKeyUp") && !has_composition_handlers {
            check_enter_submit_without_ime_guard(
                semantic,
                expr,
                attr.span,
                subj_name,
                line_starts,
                sites,
            );
        }

        // 8. `no-floating-then-in-jsx-handler`
        if attr_name.starts_with("on") && attr_name.len() > 2 {
            check_floating_then_in_jsx_handler(
                semantic,
                expr,
                attr.span,
                attr_name,
                subj_name,
                line_starts,
                sites,
            );
        }
    }
}

fn check_async_event_handler_reentry(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    attr_span: Span,
    tag_name: &str,
    has_disabled_attr: bool,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some((is_async, body_span)) = resolve_handler_function_body(semantic, expr) else {
        return;
    };
    if !is_async {
        return;
    }

    let body_src = body_span.source_text(semantic.source_text());
    let Some(await_pos) = body_src.find("await ") else {
        return;
    };

    let before_await = &body_src[..await_pos];
    let after_await = &body_src[await_pos..];

    // Check if state is set after `await`
    let has_setter_after_await = has_state_setter_call_in_text(after_await, subjects, subj_name);
    if !has_setter_after_await {
        return;
    }

    // Check if there is a re-entry guard before `await`:
    // e.g. `if (busy) return`, `if (loading) return`, `if (submitting.current) return`,
    // or a state setter / ref assignment before `await` paired with `disabled={...}` on the host control.
    let has_early_return_guard = before_await.contains("return");
    let has_pre_await_lock = (has_disabled_attr
        && has_state_setter_call_in_text(before_await, subjects, subj_name))
        || before_await.contains(".current = true");

    if !has_early_return_guard && !has_pre_await_lock {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoAsyncEventHandlerWithoutReentryGuard,
            subject_name: subj_name.clone(),
            message_id: "noAsyncEventHandlerWithoutReentryGuard",
            target_name: tag_name.to_string(),
            message: format!(
                "Async handler on `<{tag_name}>` awaits an operation and updates state afterward without a re-entry guard (`if (busy) return` or disabling the control before `await`)."
            ),
            loc: loc_from_line_starts(line_starts, attr_span.start),
            span: ByteSpan {
                start: attr_span.start,
                end: attr_span.end,
            },
            autofix: None,
        });
    }
}

fn check_enter_submit_without_ime_guard(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    attr_span: Span,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some((_, body_span)) = resolve_handler_function_body(semantic, expr) else {
        return;
    };
    let body_src = body_span.source_text(semantic.source_text());

    let checks_enter = body_src.contains("'Enter'") || body_src.contains("\"Enter\"");
    if !checks_enter {
        return;
    }

    let has_ime_guard = body_src.contains("isComposing")
        || body_src.contains("keyCode === 229")
        || body_src.contains("keyCode !== 229")
        || body_src.contains("which === 229")
        || body_src.contains("which !== 229")
        || body_src.contains("composing");

    if !has_ime_guard {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoEnterSubmitWithoutImeCompositionGuard,
            subject_name: subj_name.clone(),
            message_id: "noEnterSubmitWithoutImeCompositionGuard",
            target_name: "Enter".to_string(),
            message: "Keyboard handler acts on `'Enter'` without checking `e.nativeEvent.isComposing`, which prematurely submits mid-composition for CJK IME users.".to_string(),
            loc: loc_from_line_starts(line_starts, attr_span.start),
            span: ByteSpan {
                start: attr_span.start,
                end: attr_span.end,
            },
            autofix: None,
        });
    }
}

fn check_floating_then_in_jsx_handler(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    attr_span: Span,
    attr_name: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some((_, body_span)) = resolve_handler_function_body(semantic, expr) else {
        return;
    };
    let body_src = body_span.source_text(semantic.source_text());
    if !body_src.contains(".then(") {
        return;
    }

    // Check if there is a `.then(` call inside `body_span` without `.catch(` or a 2nd error callback argument
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if call.span.start < body_span.start || call.span.end > body_span.end {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
            continue;
        };
        if mem.property.name != "then" {
            continue;
        }
        // If `.then(onFulfilled, onRejected)` has 2 arguments, it handles rejection
        if call.arguments.len() >= 2 {
            continue;
        }
        // If this `.then(...)` is part of an outer chain that has `.catch(...)` or is `await`ed, skip
        if is_then_chain_handled(semantic, node_id) {
            continue;
        }

        sites.push(SemanticRuleSite {
            rule: RuleId::NoFloatingThenInJsxHandler,
            subject_name: subj_name.clone(),
            message_id: "noFloatingThenInJsxHandler",
            target_name: attr_name.to_string(),
            message: format!(
                "JSX handler `{attr_name}` invokes `.then(...)` without `.catch(...)`, causing rejections to become uncaught promise rejections."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: attr_span.start,
                end: attr_span.end,
            },
            autofix: None,
        });
        break;
    }
}

fn is_then_chain_handled(semantic: &Semantic<'_>, then_call_node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(then_call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::CallExpression(outer_call) => {
                if let Expression::StaticMemberExpression(outer_mem) =
                    outer_call.callee.without_parentheses()
                {
                    if outer_mem.property.name == "catch" {
                        return true;
                    }
                    if outer_mem.property.name == "then" && outer_call.arguments.len() >= 2 {
                        return true;
                    }
                }
            }
            AstKind::AwaitExpression(_) => return true,
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            _ => {}
        }
    }
    false
}

fn resolve_handler_function_body(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
) -> Option<(bool, Span)> {
    match expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => Some((arrow.r#async, arrow.body.span())),
        Expression::FunctionExpression(func) => {
            Some((func.r#async, func.body.as_ref()?.span))
        }
        Expression::Identifier(ident) => {
            let sym_id = resolve_symbol_id(semantic, ident)?;
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(func) => Some((func.r#async, func.body.as_ref()?.span)),
                AstKind::VariableDeclarator(decl) => {
                    let init = decl.init.as_ref()?.without_parentheses();
                    match init {
                        Expression::ArrowFunctionExpression(arrow) => {
                            Some((arrow.r#async, arrow.body.span()))
                        }
                        Expression::FunctionExpression(func) => {
                            Some((func.r#async, func.body.as_ref()?.span))
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn has_state_setter_call_in_text(
    text: &str,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
) -> bool {
    if let Some(name) = subj_name
        && let Some(subj) = subjects.iter().find(|s| s.name.as_deref() == Some(name.as_str()))
    {
        for slot in &subj.state_slots {
            if let Some(setter) = &slot.setter_name
                && text.contains(&format!("{setter}("))
            {
                return true;
            }
        }
    }
    // Fallback heuristic for `set[A-Z]...(`
    for (idx, _) in text.match_indices("set") {
        let rest = &text[idx + 3..];
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
            && rest.contains('(')
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 5. `no-collapse-request-error-to-empty-state`
// ---------------------------------------------------------------------------
fn check_no_collapse_request_error_to_empty_state_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    if mem.property.name != "catch" {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let handler_span = match first_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => arrow.body.span(),
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return;
            };
            body.span
        }
        _ => return,
    };

    check_catch_body_collapses_to_empty(
        semantic,
        handler_span,
        call.span,
        subjects,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_no_collapse_request_error_in_try_catch(
    semantic: &Semantic<'_>,
    try_stmt: &oxc_ast::ast::TryStatement<'_>,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(handler) = &try_stmt.handler else {
        return;
    };
    let try_src = try_stmt.block.span.source_text(semantic.source_text());
    if !try_src.contains("fetch(") && !try_src.contains("axios") && !try_src.contains("await ") {
        return;
    }

    check_catch_body_collapses_to_empty(
        semantic,
        handler.body.span,
        handler.span,
        subjects,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_catch_body_collapses_to_empty(
    semantic: &Semantic<'_>,
    catch_body_span: Span,
    report_span: Span,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let catch_src = catch_body_span.source_text(semantic.source_text());
    // If catch body also records error state (e.g., `setError`, `setErr`, `setStatus`, `toast.error`), it is not collapsing error to empty state
    if catch_src.contains("setError")
        || catch_src.contains("setErr")
        || catch_src.contains("Error(")
        || catch_src.contains("toast.")
        || catch_src.contains("throw ")
    {
        return;
    }

    // Look for a state setter call inside `catch_body_span` that passes `[]`, `null`, `{}`, or `""`
    for (_node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(inner_call) = node.kind() else {
            continue;
        };
        if inner_call.span.start < catch_body_span.start
            || inner_call.span.end > catch_body_span.end
        {
            continue;
        }
        let Expression::Identifier(callee_id) = inner_call.callee.without_parentheses() else {
            continue;
        };
        let setter_name = callee_id.name.as_str();
        if !is_subject_state_setter(setter_name, subjects, subj_name) {
            continue;
        }
        let Some(arg) = inner_call.arguments.first().and_then(|a| a.as_expression()) else {
            continue;
        };
        let is_empty_value = match arg.without_parentheses() {
            Expression::ArrayExpression(arr) => arr.elements.is_empty(),
            Expression::ObjectExpression(obj) => obj.properties.is_empty(),
            Expression::NullLiteral(_) => true,
            Expression::StringLiteral(s) => s.value.is_empty(),
            _ => false,
        };
        if is_empty_value {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoCollapseRequestErrorToEmptyState,
                subject_name: subj_name.clone(),
                message_id: "noCollapseRequestErrorToEmptyState",
                target_name: setter_name.to_string(),
                message: format!(
                    "Catch block resets data via `{setter_name}(...)` to an empty value without recording error state, making request failures indistinguishable from empty results."
                ),
                loc: loc_from_line_starts(line_starts, inner_call.span.start),
                span: ByteSpan {
                    start: report_span.start,
                    end: report_span.end,
                },
                autofix: None,
            });
            return;
        }
    }
}

fn is_subject_state_setter(
    callee_name: &str,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
) -> bool {
    if let Some(name) = subj_name
        && let Some(subj) = subjects.iter().find(|s| s.name.as_deref() == Some(name.as_str()))
    {
        for slot in &subj.state_slots {
            if slot.setter_name.as_deref() == Some(callee_name) {
                return true;
            }
        }
    }
    callee_name.starts_with("set")
        && callee_name
            .chars()
            .nth(3)
            .is_some_and(|c| c.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// 6. `no-deprecated-keyboard-event-keycode-which` (with Autofix)
// ---------------------------------------------------------------------------
fn check_no_deprecated_keyboard_event_keycode_which(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    mem: &StaticMemberExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let prop_name = mem.property.name.as_str();
    if !matches!(prop_name, "keyCode" | "which" | "charCode") {
        return;
    }

    let obj_text = mem.object.span().source_text(semantic.source_text()).trim();
    let autofix = build_keycode_autofix(semantic, node_id, mem, obj_text);

    sites.push(SemanticRuleSite {
        rule: RuleId::NoDeprecatedKeyboardEventKeycodeWhich,
        subject_name: subj_name.clone(),
        message_id: "noDeprecatedKeyboardEventKeycodeWhich",
        target_name: prop_name.to_string(),
        message: format!(
            "`KeyboardEvent.{prop_name}` is deprecated; inspect `{obj_text}.key` or `{obj_text}.code` instead."
        ),
        loc: loc_from_line_starts(line_starts, mem.span.start),
        span: ByteSpan {
            start: mem.span.start,
            end: mem.span.end,
        },
        autofix,
    });
}

fn build_keycode_autofix(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    mem: &StaticMemberExpression<'_>,
    obj_text: &str,
) -> Option<AutofixPatch> {
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::BinaryExpression(bin) = semantic.nodes().kind(parent_id)
        && matches!(
            bin.operator,
            BinaryOperator::StrictEquality
                | BinaryOperator::Equality
                | BinaryOperator::StrictInequality
                | BinaryOperator::Inequality
        )
    {
        let other_expr = if bin.left.span() == mem.span {
            Some(&bin.right)
        } else if bin.right.span() == mem.span {
            Some(&bin.left)
        } else {
            None
        };

        if let Some(Expression::NumericLiteral(num)) = other_expr.map(Expression::without_parentheses)
            && let Some(key_str) = keycode_number_to_key_name(num.value as u32)
        {
            let op_str = match bin.operator {
                BinaryOperator::StrictEquality | BinaryOperator::Equality => "===",
                BinaryOperator::StrictInequality | BinaryOperator::Inequality => "!==",
                _ => "===",
            };
            return Some(AutofixPatch {
                description: format!(
                    "Replace deprecated `{}` check with `{obj_text}.key {op_str} '{key_str}'`",
                    bin.span.source_text(semantic.source_text())
                ),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: bin.span.start,
                        end: bin.span.end,
                    },
                    replacement: format!("{obj_text}.key {op_str} '{key_str}'"),
                }],
            });
        }
    }

    None
}

fn keycode_number_to_key_name(code: u32) -> Option<String> {
    match code {
        8 => Some("Backspace".to_string()),
        9 => Some("Tab".to_string()),
        13 => Some("Enter".to_string()),
        27 => Some("Escape".to_string()),
        32 => Some(" ".to_string()),
        37 => Some("ArrowLeft".to_string()),
        38 => Some("ArrowUp".to_string()),
        39 => Some("ArrowRight".to_string()),
        40 => Some("ArrowDown".to_string()),
        46 => Some("Delete".to_string()),
        48..=57 => char::from_u32(code).map(|c| c.to_string()),
        65..=90 => char::from_u32(code).map(|c| c.to_ascii_lowercase().to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 9. `no-loading-flag-reset-outside-finally`
// ---------------------------------------------------------------------------
fn check_no_loading_flag_reset_outside_finally(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    let setter_name = callee_id.name.as_str();
    if !is_loading_like_setter(setter_name, subjects, subj_name) {
        return;
    }

    // Check if the argument is `false`
    let Some(Expression::BooleanLiteral(bool_lit)) = call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
        .map(Expression::without_parentheses)
    else {
        return;
    };
    if bool_lit.value {
        return;
    }

    // Check if this call is inside a `finally` block or a `catch` block
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::TryStatement(try_stmt) => {
                if let Some(finalizer) = &try_stmt.finalizer
                    && call.span.start >= finalizer.span.start
                    && call.span.end <= finalizer.span.end
                {
                    return;
                }
                if let Some(handler) = &try_stmt.handler
                    && call.span.start >= handler.span.start
                    && call.span.end <= handler.span.end
                {
                    return;
                }
            }
            AstKind::CallExpression(outer_call) if outer_call.span != call.span => {
                if let Expression::StaticMemberExpression(mem) =
                    outer_call.callee.without_parentheses()
                    && matches!(mem.property.name.as_str(), "finally" | "catch")
                {
                    return;
                }
            }
            AstKind::Function(func) => {
                if !func.r#async {
                    return;
                }
                if let Some(body) = &func.body {
                    let prefix = semantic
                        .source_text()
                        .get(body.span.start as usize..call.span.start as usize)
                        .unwrap_or_default();
                    let suffix = semantic
                        .source_text()
                        .get(call.span.end as usize..body.span.end as usize)
                        .unwrap_or_default();
                    // If `await` precedes `setLoading(false)` and there is no `finally` resetting it
                    if prefix.contains("await ")
                        && !suffix.contains(&format!("{setter_name}(false)"))
                    {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoLoadingFlagResetOutsideFinally,
                            subject_name: subj_name.clone(),
                            message_id: "noLoadingFlagResetOutsideFinally",
                            target_name: setter_name.to_string(),
                            message: format!(
                                "`{setter_name}(false)` runs after `await` outside a `finally` block; if the awaited promise rejects, the loading flag remains stuck `true`."
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
                return;
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                if !arrow.r#async {
                    return;
                }
                let body_span = arrow.body.span();
                let prefix = semantic
                    .source_text()
                    .get(body_span.start as usize..call.span.start as usize)
                    .unwrap_or_default();
                let suffix = semantic
                    .source_text()
                    .get(call.span.end as usize..body_span.end as usize)
                    .unwrap_or_default();
                if prefix.contains("await ") && !suffix.contains(&format!("{setter_name}(false)")) {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::NoLoadingFlagResetOutsideFinally,
                        subject_name: subj_name.clone(),
                        message_id: "noLoadingFlagResetOutsideFinally",
                        target_name: setter_name.to_string(),
                        message: format!(
                            "`{setter_name}(false)` runs after `await` outside a `finally` block; if the awaited promise rejects, the loading flag remains stuck `true`."
                        ),
                        loc: loc_from_line_starts(line_starts, call.span.start),
                        span: ByteSpan {
                            start: call.span.start,
                            end: call.span.end,
                        },
                        autofix: None,
                    });
                }
                return;
            }
            _ => {}
        }
    }
}

fn is_loading_like_setter(
    setter_name: &str,
    subjects: &[SubjectIr],
    subj_name: &Option<String>,
) -> bool {
    let lower = setter_name.to_ascii_lowercase();
    let matches_name = lower.starts_with("set")
        && (lower.contains("loading")
            || lower.contains("submitting")
            || lower.contains("saving")
            || lower.contains("pending")
            || lower.contains("busy")
            || lower.contains("fetching"));
    if !matches_name {
        return false;
    }
    if subjects.is_empty() {
        return true;
    }
    is_subject_state_setter(setter_name, subjects, subj_name)
}

// ---------------------------------------------------------------------------
// 10. `no-non-literal-selector-query-without-try-catch`
// ---------------------------------------------------------------------------
fn check_no_non_literal_selector_query_without_try_catch(
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
    let method = mem.property.name.as_str();
    if !SELECTOR_QUERY_METHODS.contains(&method) {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if is_safe_selector_argument(semantic, first_arg) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::NoNonLiteralSelectorQueryWithoutTryCatch,
        subject_name: subj_name.clone(),
        message_id: "noNonLiteralSelectorQueryWithoutTryCatch",
        target_name: method.to_string(),
        message: format!(
            "Calling `.{method}(...)` with a dynamic selector outside `try/catch` and without `CSS.escape(...)` throws a `DOMException` when the selector is malformed."
        ),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn is_safe_selector_argument(semantic: &Semantic<'_>, arg: &Expression<'_>) -> bool {
    match arg.without_parentheses() {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => {
            if tpl.expressions.is_empty() {
                return true;
            }
            tpl.expressions.iter().all(|e| {
                let src = e.span().source_text(semantic.source_text());
                src.contains("CSS.escape")
            })
        }
        Expression::CallExpression(c) => {
            let src = c.callee.span().source_text(semantic.source_text());
            src.contains("CSS.escape")
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            is_safe_selector_argument(semantic, init)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 11. `no-non-null-assertion-on-maybe-undefined-result`
// ---------------------------------------------------------------------------
fn check_no_non_null_assertion_on_maybe_undefined_result(
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
            .source_text(semantic.source_text())
            .to_string();
        sites.push(SemanticRuleSite {
            rule: RuleId::NoNonNullAssertionOnMaybeUndefinedResult,
            subject_name: subj_name.clone(),
            message_id: "noNonNullAssertionOnMaybeUndefinedResult",
            target_name: target,
            message: "Non-null assertion (`!`) on a lookup result (`.find()`, `.match()`, `.get()`, etc.) hides `undefined`/`null` from TypeScript and crashes when no match is found.".to_string(),
            loc: loc_from_line_starts(line_starts, non_null.span.start),
            span: ByteSpan {
                start: non_null.span.start,
                end: non_null.span.end,
            },
            autofix: None,
        });
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
fn check_no_nullish_coalescing_arithmetic_precedence(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::NoNullishCoalescingArithmeticPrecedence,
            subject_name: subj_name.clone(),
            message_id: "noNullishCoalescingArithmeticPrecedence",
            target_name: "??".to_string(),
            message: "Arithmetic binds tighter than `??`, so unparenthesized arithmetic next to `??` evaluates before the fallback; wrap the nullish coalescing expression in parentheses (`(x ?? 0) + y`).".to_string(),
            loc: loc_from_line_starts(line_starts, log.span.start),
            span: ByteSpan {
                start: log.span.start,
                end: log.span.end,
            },
            autofix: None,
        });
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
fn check_no_object_keys_values_entries_on_maybe_undefined(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::NoObjectKeysValuesEntriesOnMaybeUndefined,
            subject_name: subj_name.clone(),
            message_id: "noObjectKeysValuesEntriesOnMaybeUndefined",
            target_name: format!("Object.{method}"),
            message: format!(
                "`Object.{method}(...)` throws a `TypeError` when its argument is `undefined` or `null`; provide a `?? {{}}` fallback or guard the value first."
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
                AstKind::VariableDeclarator(decl) => {
                    decl.init.as_ref().is_some_and(|init| {
                        matches!(init.without_parentheses(), Expression::ChainExpression(_))
                    })
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 14. `no-object-or-array-coerced-to-string-in-template-literal`
// ---------------------------------------------------------------------------
fn check_no_object_or_array_coerced_to_string_in_template_literal(
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
            let target = expr
                .span()
                .source_text(semantic.source_text())
                .to_string();
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
                    src.contains(": {") || src.contains("Record<") || src.contains("Array<") || src.contains("[]")
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 15. `no-passive-request-owner-ref`
// ---------------------------------------------------------------------------
fn check_no_passive_request_owner_ref(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Find refs synchronized inside a `useEffect`: `ref.current = prop`
    // and then read inside another `useEffect`'s async continuation (`if (ref.current === prop)`).
    let mut synced_refs_by_subject: std::collections::HashMap<Option<String>, Vec<(String, Span)>> =
        std::collections::HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::AssignmentExpression(assign) = node.kind() else {
            continue;
        };
        let AssignmentTarget::StaticMemberExpression(mem) = &assign.left else {
            continue;
        };
        if mem.property.name != "current" {
            continue;
        }
        let Expression::Identifier(ref_ident) = mem.object.without_parentheses() else {
            continue;
        };
        // Check if inside a `useEffect`
        if !crate::ir::react_ast::is_inside_use_effect(semantic, node_id) {
            continue;
        }
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));
        synced_refs_by_subject
            .entry(subj_name)
            .or_default()
            .push((ref_ident.name.to_string(), assign.span));
    }

    if synced_refs_by_subject.is_empty() {
        return;
    }

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !is_react_hook_callee(semantic, &call.callee, "useEffect") {
            continue;
        }
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));
        let Some(synced_refs) = synced_refs_by_subject.get(&subj_name) else {
            continue;
        };
        let effect_src = call.span.source_text(semantic.source_text());
        if !effect_src.contains("fetch(")
            && !effect_src.contains(".then(")
            && !effect_src.contains("await ")
        {
            continue;
        }

        for (ref_name, sync_span) in synced_refs {
            // Must be synced in a different effect or used as an ownership guard
            if sync_span.start >= call.span.start && sync_span.end <= call.span.end {
                continue;
            }
            if effect_src.contains(&format!("{ref_name}.current")) {
                sites.push(SemanticRuleSite {
                    rule: RuleId::NoPassiveRequestOwnerRef,
                    subject_name: subj_name.clone(),
                    message_id: "noPassiveRequestOwnerRef",
                    target_name: ref_name.clone(),
                    message: format!(
                        "Async request checks `{ref_name}.current` synchronized by a separate `useEffect`; use a local effect cleanup flag (`let cancelled = false`) or `AbortController` instead."
                    ),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 16. `no-predicate-function-reference-in-boolean-position`
// ---------------------------------------------------------------------------
fn check_predicate_in_condition(
    semantic: &Semantic<'_>,
    test_expr: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(ident) = test_expr.without_parentheses() else {
        return;
    };
    emit_if_predicate_function_reference(semantic, ident, subj_name, line_starts, sites);
}

fn check_predicate_in_logical(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    log: &LogicalExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !matches!(log.operator, LogicalOperator::And | LogicalOperator::Or) {
        return;
    }
    if let Expression::Identifier(ident) = log.left.without_parentheses() {
        emit_if_predicate_function_reference(semantic, ident, subj_name, line_starts, sites);
    }
}

fn emit_if_predicate_function_reference(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let name = ident.name.as_str();
    if !has_predicate_prefix(name) {
        return;
    }
    let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
        return;
    };
    if !is_function_symbol(semantic, sym_id) {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::NoPredicateFunctionReferenceInBooleanPosition,
        subject_name: subj_name.clone(),
        message_id: "noPredicateFunctionReferenceInBooleanPosition",
        target_name: name.to_string(),
        message: format!(
            "Predicate function `{name}` is referenced without calling it (`{name}()`), which is always truthy in a boolean condition."
        ),
        loc: loc_from_line_starts(line_starts, ident.span.start),
        span: ByteSpan {
            start: ident.span.start,
            end: ident.span.end,
        },
        autofix: None,
    });
}

fn has_predicate_prefix(name: &str) -> bool {
    for prefix in PREDICATE_PREFIXES {
        if let Some(rest) = name.strip_prefix(prefix)
            && rest.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

fn is_function_symbol(semantic: &Semantic<'_>, sym_id: SymbolId) -> bool {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    match semantic.nodes().kind(decl_id) {
        AstKind::Function(_) => true,
        AstKind::VariableDeclarator(decl) => decl.init.as_ref().is_some_and(|init| {
            matches!(
                init.without_parentheses(),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        }),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 17. `no-unescaped-dynamic-string-in-regexp`
// ---------------------------------------------------------------------------
fn check_no_unescaped_dynamic_string_in_regexp(
    semantic: &Semantic<'_>,
    new_expr: &NewExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = new_expr.callee.without_parentheses() else {
        return;
    };
    if callee_id.name != "RegExp" {
        return;
    }
    let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if is_escaped_or_static_regexp_arg(semantic, first_arg) {
        return;
    }

    let target = first_arg
        .span()
        .source_text(semantic.source_text())
        .to_string();
    sites.push(SemanticRuleSite {
        rule: RuleId::NoUnescapedDynamicStringInRegexp,
        subject_name: subj_name.clone(),
        message_id: "noUnescapedDynamicStringInRegexp",
        target_name: target,
        message: "Dynamic string passed to `new RegExp(...)` without escaping regex metacharacters (`escapeRegExp` / `.replace(...)`).".to_string(),
        loc: loc_from_line_starts(line_starts, new_expr.span.start),
        span: ByteSpan {
            start: new_expr.span.start,
            end: new_expr.span.end,
        },
        autofix: None,
    });
}

fn is_escaped_or_static_regexp_arg(semantic: &Semantic<'_>, arg: &Expression<'_>) -> bool {
    match arg.without_parentheses() {
        Expression::StringLiteral(_) | Expression::RegExpLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => {
            if tpl.expressions.is_empty() {
                return true;
            }
            tpl.expressions
                .iter()
                .all(|e| is_escaped_or_static_regexp_arg(semantic, e))
        }
        Expression::CallExpression(call) => {
            let src = call.span.source_text(semantic.source_text());
            src.contains("escape") || src.contains(".replace(")
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            is_escaped_or_static_regexp_arg(semantic, init)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 18. `no-unguarded-numeric-input-parse`
// ---------------------------------------------------------------------------
fn check_no_unguarded_numeric_input_parse(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_numeric_parse = match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "Number" | "parseInt" | "parseFloat")
        }
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.object.without_parentheses(), Expression::Identifier(id) if id.name == "Number")
                && matches!(mem.property.name.as_str(), "parseInt" | "parseFloat")
        }
        _ => false,
    };
    if !is_numeric_parse {
        return;
    }

    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let arg_src = first_arg.span().source_text(semantic.source_text());
    let is_dom_input_value = arg_src.ends_with(".target.value")
        || arg_src.ends_with(".currentTarget.value")
        || matches!(first_arg.without_parentheses(), Expression::Identifier(ident) if {
            resolve_symbol_id(semantic, ident)
                .and_then(|sym_id| get_var_declarator_init(semantic, sym_id))
                .is_some_and(|init| {
                    let s = init.span().source_text(semantic.source_text());
                    s.ends_with(".target.value") || s.ends_with(".currentTarget.value")
                })
        });

    if !is_dom_input_value {
        return;
    }

    // Check if guarded against empty string and `isNaN` in enclosing handler/function
    let scope_span = enclosing_function_span(semantic, node_id);
    let scope_src = scope_span.source_text(semantic.source_text());
    let has_nan_or_empty_guard = scope_src.contains("isNaN(")
        || scope_src.contains("isFinite(")
        || scope_src.contains("=== ''")
        || scope_src.contains("=== \"\"")
        || scope_src.contains(".trim()");

    if !has_nan_or_empty_guard {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoUnguardedNumericInputParse,
            subject_name: subj_name.clone(),
            message_id: "noUnguardedNumericInputParse",
            target_name: call
                .callee
                .span()
                .source_text(semantic.source_text())
                .to_string(),
            message: "Parsing `e.target.value` with `Number`/`parseInt`/`parseFloat` without guarding empty strings and `NaN` turns empty input into `0` or `NaN`.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

// ---------------------------------------------------------------------------
// 19. `no-unguarded-throwing-parse-call`
// ---------------------------------------------------------------------------
fn check_no_unguarded_throwing_parse_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    let name = callee_id.name.as_str();
    if !THROWING_PARSE_FUNCTIONS.contains(&name) {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if matches!(first_arg.without_parentheses(), Expression::StringLiteral(_)) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }
    let scope_src = enclosing_function_span(semantic, node_id).source_text(semantic.source_text());
    if scope_src.contains("chroma.valid") || scope_src.contains("canParse") {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::NoUnguardedThrowingParseCall,
        subject_name: subj_name.clone(),
        message_id: "noUnguardedThrowingParseCall",
        target_name: name.to_string(),
        message: format!(
            "`{name}(...)` throws on malformed runtime input; wrap the call in `try/catch` or validate the input first."
        ),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_no_unguarded_throwing_new_url(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = new_expr.callee.without_parentheses() else {
        return;
    };
    if callee_id.name != "URL" {
        return;
    }
    let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if matches!(first_arg.without_parentheses(), Expression::StringLiteral(_)) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }
    let scope_src = enclosing_function_span(semantic, node_id).source_text(semantic.source_text());
    if scope_src.contains("URL.canParse") {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::NoUnguardedThrowingParseCall,
        subject_name: subj_name.clone(),
        message_id: "noUnguardedThrowingParseCall",
        target_name: "new URL".to_string(),
        message: "`new URL(...)` throws a `TypeError` on malformed URLs; guard with `URL.canParse(...)` or wrap in `try/catch`.".to_string(),
        loc: loc_from_line_starts(line_starts, new_expr.span.start),
        span: ByteSpan {
            start: new_expr.span.start,
            end: new_expr.span.end,
        },
        autofix: None,
    });
}

// ---------------------------------------------------------------------------
// 20. `no-unsafe-json-parse`
// ---------------------------------------------------------------------------
fn check_no_unsafe_json_parse_member(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    access_span: Span,
    object: &Expression<'_>,
    is_optional: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_unguarded_json_parse = match object.without_parentheses() {
        Expression::CallExpression(call) => {
            is_json_parse_call(call) && !is_inside_try_block(semantic, node_id)
        }
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
            if !is_json_parse_call(call) {
                return;
            }
            !is_inside_try_block(semantic, node_id)
                && !is_optional
                && !has_nullish_guard_before(semantic, access_span.start, ident.name.as_str())
        }
        _ => false,
    };

    if is_unguarded_json_parse {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoUnsafeJsonParse,
            subject_name: subj_name.clone(),
            message_id: "noUnsafeJsonParse",
            target_name: "JSON.parse".to_string(),
            message: "Dereferencing `JSON.parse(...)` outside `try/catch` without validating the parsed value throws on malformed JSON or `null` payloads.".to_string(),
            loc: loc_from_line_starts(line_starts, access_span.start),
            span: ByteSpan {
                start: access_span.start,
                end: access_span.end,
            },
            autofix: None,
        });
    }
}

fn is_json_parse_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(mem.object.without_parentheses(), Expression::Identifier(id) if id.name == "JSON")
        && mem.property.name == "parse"
}

// ---------------------------------------------------------------------------
// 21. `no-whole-object-default-losing-per-key-defaults`
// ---------------------------------------------------------------------------
fn check_no_whole_object_default_losing_per_key_defaults(
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
        let target = param
            .pattern
            .span()
            .source_text(semantic.source_text())
            .to_string();
        sites.push(SemanticRuleSite {
            rule: RuleId::NoWholeObjectDefaultLosingPerKeyDefaults,
            subject_name: subj_name.clone(),
            message_id: "noWholeObjectDefaultLosingPerKeyDefaults",
            target_name: target,
            message: "Whole-object parameter default (`= { ... }`) only applies when the argument is `undefined`; destructure with per-key defaults (`{ a = 1, b = 2 } = {}`) so partial arguments keep fallback values.".to_string(),
            loc: loc_from_line_starts(line_starts, param.span.start),
            span: ByteSpan {
                start: param.span.start,
                end: param.span.end,
            },
            autofix: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Shared AST / Scope Helpers
// ---------------------------------------------------------------------------
fn resolve_symbol_id(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    let ref_id: ReferenceId = ident.reference_id.get()?;
    semantic.scoping().get_reference(ref_id).symbol_id()
}

fn get_var_declarator_init<'a>(
    semantic: &'a Semantic<'a>,
    sym_id: SymbolId,
) -> Option<&'a Expression<'a>> {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) {
        decl.init.as_ref()
    } else {
        None
    }
}

fn is_inside_optional_chain_parent(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let kind = semantic.nodes().kind(anc_id);
        if matches!(kind, AstKind::ChainExpression(_)) {
            return true;
        }
        if kind.is_statement() || kind.is_declaration() {
            break;
        }
    }
    false
}

fn is_inside_try_block(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let node_span = semantic.nodes().kind(node_id).span();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::TryStatement(try_stmt) => {
                if node_span.start >= try_stmt.block.span.start
                    && node_span.end <= try_stmt.block.span.end
                {
                    return true;
                }
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            _ => {}
        }
    }
    false
}

fn enclosing_function_or_program_start(semantic: &Semantic<'_>, node_id: NodeId) -> u32 {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                if let Some(body) = &func.body {
                    return body.span.start;
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => return arrow.body.span().start,
            _ => {}
        }
    }
    0
}

fn enclosing_function_span(semantic: &Semantic<'_>, node_id: NodeId) -> Span {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                if let Some(body) = &func.body {
                    return body.span;
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => return arrow.body.span(),
            _ => {}
        }
    }
    Span::new(0, semantic.source_text().len() as u32)
}

fn has_nullish_guard_before(semantic: &Semantic<'_>, before_offset: u32, var_name: &str) -> bool {
    let src = semantic
        .source_text()
        .get(..before_offset as usize)
        .unwrap_or_default();
    src.contains(&format!("if (!{var_name})"))
        || src.contains(&format!("if ({var_name})"))
        || src.contains(&format!("if ({var_name} == null)"))
        || src.contains(&format!("if ({var_name} != null)"))
        || src.contains(&format!("if ({var_name} === undefined)"))
        || src.contains(&format!("if ({var_name} !== undefined)"))
}

fn is_guarded_in_enclosing_short_circuit(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    var_name: &str,
) -> bool {
    let node_span = semantic.nodes().kind(node_id).span();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::LogicalExpression(log) if log.operator == LogicalOperator::And => {
                if node_span.start >= log.right.span().start {
                    let left_src = log.left.span().source_text(semantic.source_text());
                    if left_src.contains(var_name) {
                        return true;
                    }
                }
            }
            AstKind::ConditionalExpression(cond) => {
                if node_span.start >= cond.consequent.span().start {
                    let test_src = cond.test.span().source_text(semantic.source_text());
                    if test_src.contains(var_name) {
                        return true;
                    }
                }
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            _ => {}
        }
    }
    false
}
