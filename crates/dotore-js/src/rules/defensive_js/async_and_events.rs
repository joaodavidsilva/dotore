//! Async/event handler, request error/loading state, and DOM/keyboard defensive rule detectors.

use oxc_ast::{
    AstKind,
    ast::{
        AssignmentTarget, BinaryOperator, CallExpression, Expression, IdentifierReference,
        JSXAttributeItem, JSXAttributeValue, JSXOpeningElement, LogicalExpression, LogicalOperator,
        StaticMemberExpression, TryStatement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::{PREDICATE_PREFIXES, resolve_symbol_id};
use crate::{
    ir::{
        ByteSpan, SemanticRuleSite, SubjectIr,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_inside_use_effect,
        },
        types::loc_from_line_starts,
    },
    matchers::{is_react_hook_callee, push_semantic_site, push_semantic_site_with_fix},
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

// ---------------------------------------------------------------------------
// 4, 7, 8. JSX Event Handler Rules:
// - `no-async-event-handler-without-reentry-guard`
// - `no-enter-submit-without-ime-composition-guard`
// - `no-floating-then-in-jsx-handler`
// ---------------------------------------------------------------------------
pub(super) fn check_jsx_event_handler_defensive_rules(
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

#[expect(
    clippy::too_many_arguments,
    reason = "Receives JSX event attribute AST context, subject state slots, and output accumulator"
)]
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
        push_semantic_site(
            sites,
            RuleId::NoAsyncEventHandlerWithoutReentryGuard,
            subj_name.clone(),
            "noAsyncEventHandlerWithoutReentryGuard",
            tag_name,
            format!(
                "Async handler on `<{tag_name}>` awaits an operation and updates state afterward without a re-entry guard (`if (busy) return` or disabling the control before `await`)."
            ),
            line_starts,
            attr_span,
        );
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
        push_semantic_site(
            sites,
            RuleId::NoEnterSubmitWithoutImeCompositionGuard,
            subj_name.clone(),
            "noEnterSubmitWithoutImeCompositionGuard",
            "Enter",
            "Keyboard handler acts on `'Enter'` without checking `e.nativeEvent.isComposing`, which prematurely submits mid-composition for CJK IME users.".to_string(),
            line_starts,
            attr_span,
        );
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
        Expression::FunctionExpression(func) => Some((func.r#async, func.body.as_ref()?.span)),
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
        && let Some(subj) = subjects
            .iter()
            .find(|s| s.name.as_deref() == Some(name.as_str()))
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
pub(super) fn check_no_collapse_request_error_to_empty_state_call(
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

pub(super) fn check_no_collapse_request_error_in_try_catch(
    semantic: &Semantic<'_>,
    try_stmt: &TryStatement<'_>,
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
        && let Some(subj) = subjects
            .iter()
            .find(|s| s.name.as_deref() == Some(name.as_str()))
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
pub(super) fn check_no_deprecated_keyboard_event_keycode_which(
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

    push_semantic_site_with_fix(
        sites,
        RuleId::NoDeprecatedKeyboardEventKeycodeWhich,
        subj_name.clone(),
        "noDeprecatedKeyboardEventKeycodeWhich",
        prop_name,
        format!(
            "`KeyboardEvent.{prop_name}` is deprecated; inspect `{obj_text}.key` or `{obj_text}.code` instead."
        ),
        line_starts,
        mem.span,
        autofix,
    );
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

        if let Some(Expression::NumericLiteral(num)) =
            other_expr.map(Expression::without_parentheses)
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
pub(super) fn check_no_loading_flag_reset_outside_finally(
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
                        push_semantic_site(
                            sites,
                            RuleId::NoLoadingFlagResetOutsideFinally,
                            subj_name.clone(),
                            "noLoadingFlagResetOutsideFinally",
                            setter_name,
                            format!(
                                "`{setter_name}(false)` runs after `await` outside a `finally` block; if the awaited promise rejects, the loading flag remains stuck `true`."
                            ),
                            line_starts,
                            call.span,
                        );
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
                    push_semantic_site(
                        sites,
                        RuleId::NoLoadingFlagResetOutsideFinally,
                        subj_name.clone(),
                        "noLoadingFlagResetOutsideFinally",
                        setter_name,
                        format!(
                            "`{setter_name}(false)` runs after `await` outside a `finally` block; if the awaited promise rejects, the loading flag remains stuck `true`."
                        ),
                        line_starts,
                        call.span,
                    );
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
// 15. `no-passive-request-owner-ref`
// ---------------------------------------------------------------------------
pub(super) fn check_no_passive_request_owner_ref(
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
        if !is_inside_use_effect(semantic, node_id) {
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
                push_semantic_site(
                    sites,
                    RuleId::NoPassiveRequestOwnerRef,
                    subj_name.clone(),
                    "noPassiveRequestOwnerRef",
                    ref_name,
                    format!(
                        "Async request checks `{ref_name}.current` synchronized by a separate `useEffect`; use a local effect cleanup flag (`let cancelled = false`) or `AbortController` instead."
                    ),
                    line_starts,
                    call.span,
                );
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 16. `no-predicate-function-reference-in-boolean-position`
// ---------------------------------------------------------------------------
pub(super) fn check_predicate_in_condition(
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

pub(super) fn check_predicate_in_logical(
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
    ident: &IdentifierReference<'_>,
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

    push_semantic_site(
        sites,
        RuleId::NoPredicateFunctionReferenceInBooleanPosition,
        subj_name.clone(),
        "noPredicateFunctionReferenceInBooleanPosition",
        name,
        format!(
            "Predicate function `{name}` is referenced without calling it (`{name}()`), which is always truthy in a boolean condition."
        ),
        line_starts,
        ident.span,
    );
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
