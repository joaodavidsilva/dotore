//! Effect hook, self-updating effect, async `await` state update, timer ref, and
//! unowned async error clear detectors for `state-and-effects`.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds (#50)"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, CallExpression, Expression, ObjectExpression, ObjectPropertyKind,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        dataflow::{is_prop, is_synchronous},
        react_ast::{get_effect_cleanup_span, get_effect_fn_node},
        types::loc_from_line_starts,
    },
    rules::types::RuleId,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Inspects an effect hook call against the enclosing Subject's state and setter tables (#50)"
)]
pub(super) fn check_effect_hook_rules(
    semantic: &Semantic<'_>,
    effect_call_id: NodeId,
    call: &CallExpression<'_>,
    setter_to_state: &HashMap<String, String>,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(effect_fn_id) = get_effect_fn_node(semantic, effect_call_id) else {
        return;
    };
    let effect_fn_span = semantic.nodes().get_node(effect_fn_id).span();
    let has_cleanup = get_effect_cleanup_span(semantic, effect_fn_id).is_some();
    let dep_names = collect_effect_dep_ident_names(call);

    if !dep_names.is_empty() && !setter_to_state.is_empty() {
        check_no_self_updating_effect_body(
            semantic,
            effect_fn_id,
            &dep_names,
            setter_to_state,
            subj_name,
            line_starts,
            sites,
        );
    }

    if !setter_names.is_empty() {
        check_set_state_after_await_in_effect(
            semantic,
            effect_fn_span,
            setter_names,
            subj_name,
            line_starts,
            sites,
        );
    }

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !effect_fn_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(inner_call) = node.kind() else {
            continue;
        };
        check_effect_inner_call(
            semantic,
            node_id,
            effect_fn_id,
            inner_call,
            has_cleanup,
            &dep_names,
            subj_name,
            line_starts,
            sites,
        );
    }
}

fn collect_effect_dep_ident_names(call: &CallExpression<'_>) -> HashSet<String> {
    crate::matchers::collect_effect_dep_ident_names(call)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates cleanup, prop-callback, and useEffectEvent rules on an inner call inside useEffect (#50)"
)]
fn check_effect_inner_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    effect_fn_id: NodeId,
    inner_call: &CallExpression<'_>,
    has_cleanup: bool,
    dep_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = match inner_call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    if !has_cleanup
        && let Some(name_str @ ("addEventListener" | "setInterval" | "subscribe")) = callee_name
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::EffectNeedsCleanup,
            subject_name: subj_name.clone(),
            message_id: "effectNeedsCleanup",
            target_name: name_str.to_string(),
            message: format!(
                "`{name_str}` inside `useEffect` has no cleanup return; return a cleanup function to release the listener or timer."
            ),
            loc: loc_from_line_starts(line_starts, inner_call.span.start),
            span: ByteSpan {
                start: inner_call.span.start,
                end: inner_call.span.end,
            },
            autofix: None,
        });
    }

    let Expression::Identifier(id) = inner_call.callee.without_parentheses() else {
        return;
    };
    let is_prop_ident = id.reference_id.get().is_some_and(|r| is_prop(semantic, r));

    if is_prop_ident && id.name.starts_with("on") && is_synchronous(semantic, node_id, effect_fn_id)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoPropCallbackInEffect,
            subject_name: subj_name.clone(),
            message_id: "noPropCallbackInEffect",
            target_name: id.name.to_string(),
            message: format!(
                "Avoid invoking parent callback prop `{}` synchronously inside `useEffect`; call it directly from the originating event handler.",
                id.name
            ),
            loc: loc_from_line_starts(line_starts, inner_call.span.start),
            span: ByteSpan {
                start: inner_call.span.start,
                end: inner_call.span.end,
            },
            autofix: None,
        });
    }

    if dep_names.contains(id.name.as_str())
        && (is_prop_ident
            || ["on", "handle", "log", "track"]
                .iter()
                .any(|p| id.name.starts_with(p)))
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::PreferUseEffectEvent,
            subject_name: subj_name.clone(),
            message_id: "preferUseEffectEvent",
            target_name: id.name.to_string(),
            message: format!(
                "Effect re-runs whenever `{}` changes; wrap non-reactive event notification logic in `useEffectEvent`.",
                id.name
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

fn check_no_self_updating_effect_body(
    semantic: &Semantic<'_>,
    effect_fn_id: NodeId,
    dep_names: &HashSet<String>,
    setter_to_state: &HashMap<String, String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut top_calls: Vec<&CallExpression<'_>> = Vec::new();
    let mut early_return_tests: Vec<&Expression<'_>> = Vec::new();

    match semantic.nodes().kind(effect_fn_id) {
        AstKind::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                collect_effect_top_level_calls_and_guards(
                    &body.statements,
                    &mut top_calls,
                    &mut early_return_tests,
                );
            }
            _ => {
                if let Some(expr) = arrow.body.as_expression()
                    && let Expression::CallExpression(c) = expr.without_parentheses()
                {
                    top_calls.push(c);
                }
            }
        },
        AstKind::Function(func) => {
            if let Some(body) = &func.body {
                collect_effect_top_level_calls_and_guards(
                    &body.statements,
                    &mut top_calls,
                    &mut early_return_tests,
                );
            }
        }
        _ => {}
    }

    for setter_call in top_calls {
        let Expression::Identifier(callee_id) = setter_call.callee.without_parentheses() else {
            continue;
        };
        let Some(state_name) = setter_to_state.get(callee_id.name.as_str()) else {
            continue;
        };
        if !dep_names.contains(state_name) {
            continue;
        }
        if early_return_tests
            .iter()
            .any(|test| guard_converges_on_state(test, state_name, semantic.source_text()))
        {
            continue;
        }
        if is_non_settling_setter_argument(setter_call, state_name) {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoSelfUpdatingEffect,
                subject_name: subj_name.clone(),
                message_id: "noSelfUpdatingEffect",
                target_name: state_name.clone(),
                message: format!(
                    "Effect unconditionally calls `{}` while tracking `{state_name}` in its dependency array, causing an infinite re-render loop.",
                    callee_id.name
                ),
                loc: loc_from_line_starts(line_starts, setter_call.span.start),
                span: ByteSpan {
                    start: setter_call.span.start,
                    end: setter_call.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn collect_effect_top_level_calls_and_guards<'a>(
    stmts: &'a [Statement<'a>],
    top_calls: &mut Vec<&'a CallExpression<'a>>,
    early_return_tests: &mut Vec<&'a Expression<'a>>,
) {
    for stmt in stmts {
        match stmt {
            Statement::IfStatement(if_stmt) => {
                let is_early_return = match &if_stmt.consequent {
                    Statement::ReturnStatement(_) => true,
                    Statement::BlockStatement(blk) => blk
                        .body
                        .iter()
                        .any(|s| matches!(s, Statement::ReturnStatement(_))),
                    _ => false,
                };
                if is_early_return {
                    early_return_tests.push(&if_stmt.test);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                if let Expression::CallExpression(call) = expr_stmt.expression.without_parentheses()
                {
                    top_calls.push(call);
                }
            }
            _ => {}
        }
    }
}

fn guard_converges_on_state(test: &Expression<'_>, state_name: &str, source: &str) -> bool {
    let text = test.span().source_text(source);
    expression_reads_state_value(test, state_name)
        && (text.starts_with('!')
            || [".length", "null", "undefined", "<=", ">=", "==="]
                .iter()
                .any(|p| text.contains(p)))
}

fn is_non_settling_setter_argument(setter_call: &CallExpression<'_>, state_name: &str) -> bool {
    let Some(first_arg) = setter_call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
    else {
        return false;
    };
    let arg = first_arg.without_parentheses();
    if let Expression::Identifier(id) = arg
        && id.name.as_str() == state_name
    {
        return false;
    }
    if matches!(
        arg,
        Expression::ArrowFunctionExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_)
            | Expression::NewExpression(_)
            | Expression::RegExpLiteral(_)
    ) {
        return true;
    }
    expression_reads_state_value(arg, state_name)
}

pub(super) fn expression_reads_state_value(expr: &Expression<'_>, state_name: &str) -> bool {
    match expr.without_parentheses() {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => false,
        Expression::Identifier(id) => id.name.as_str() == state_name,
        Expression::StaticMemberExpression(mem) => {
            expression_reads_state_value(&mem.object, state_name)
        }
        Expression::ComputedMemberExpression(comp) => {
            expression_reads_state_value(&comp.object, state_name)
                || expression_reads_state_value(&comp.expression, state_name)
        }
        Expression::BinaryExpression(bin) => {
            expression_reads_state_value(&bin.left, state_name)
                || expression_reads_state_value(&bin.right, state_name)
        }
        Expression::LogicalExpression(log) => {
            expression_reads_state_value(&log.left, state_name)
                || expression_reads_state_value(&log.right, state_name)
        }
        Expression::ConditionalExpression(cond) => {
            expression_reads_state_value(&cond.test, state_name)
                || expression_reads_state_value(&cond.consequent, state_name)
                || expression_reads_state_value(&cond.alternate, state_name)
        }
        Expression::UnaryExpression(un) => expression_reads_state_value(&un.argument, state_name),
        other => composite_expression_reads_state_value(other, state_name),
    }
}

fn composite_expression_reads_state_value(expr: &Expression<'_>, state_name: &str) -> bool {
    match expr {
        Expression::CallExpression(call) => {
            expression_reads_state_value(&call.callee, state_name)
                || call
                    .arguments
                    .iter()
                    .filter_map(|a| a.as_expression())
                    .any(|a| expression_reads_state_value(a, state_name))
        }
        Expression::TemplateLiteral(tpl) => tpl
            .expressions
            .iter()
            .any(|e| expression_reads_state_value(e, state_name)),
        Expression::ObjectExpression(obj) => object_expression_reads_state_value(obj, state_name),
        Expression::ArrayExpression(arr) => arr
            .elements
            .iter()
            .filter_map(|e| e.as_expression())
            .any(|e| expression_reads_state_value(e, state_name)),
        _ => false,
    }
}

fn object_expression_reads_state_value(obj: &ObjectExpression<'_>, state_name: &str) -> bool {
    obj.properties.iter().any(|p| match p {
        ObjectPropertyKind::ObjectProperty(prop) => {
            (prop.computed
                && prop
                    .key
                    .as_expression()
                    .is_some_and(|k| expression_reads_state_value(k, state_name)))
                || expression_reads_state_value(&prop.value, state_name)
        }
        ObjectPropertyKind::SpreadProperty(sp) => {
            expression_reads_state_value(&sp.argument, state_name)
        }
    })
}

fn check_set_state_after_await_in_effect(
    semantic: &Semantic<'_>,
    effect_fn_span: Span,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (fn_node_id, fn_node) in semantic.nodes().iter_enumerated() {
        if !effect_fn_span.contains_inclusive(fn_node.span()) || !is_async_fn_node(fn_node.kind()) {
            continue;
        }
        let async_span = fn_node.span();
        let Some(await_start) = find_first_await_start(semantic, async_span) else {
            continue;
        };
        if has_early_cancel_return_in_text(async_span.source_text(semantic.source_text())) {
            continue;
        }
        report_setters_after_await(
            semantic,
            fn_node_id,
            async_span,
            await_start,
            setter_names,
            subj_name,
            line_starts,
            sites,
        );
    }
}

fn is_async_fn_node(kind: AstKind<'_>) -> bool {
    match kind {
        AstKind::Function(f) => f.r#async,
        AstKind::ArrowFunctionExpression(a) => a.r#async,
        _ => false,
    }
}

fn find_first_await_start(semantic: &Semantic<'_>, async_span: Span) -> Option<u32> {
    let mut first_await_start: Option<u32> = None;
    for (_, inner) in semantic.nodes().iter_enumerated() {
        if !async_span.contains_inclusive(inner.span()) {
            continue;
        }
        if let AstKind::AwaitExpression(aw) = inner.kind() {
            first_await_start =
                Some(first_await_start.map_or(aw.span.start, |prev| prev.min(aw.span.start)));
        }
    }
    first_await_start
}

fn has_early_cancel_return_in_text(async_text: &str) -> bool {
    [
        "if (cancelled)",
        "if (canceled)",
        "if (ignore)",
        "if (signal.aborted)",
    ]
    .iter()
    .any(|p| async_text.contains(p))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Scans an async effect callback for unguarded setter calls after the first await (#50)"
)]
fn report_setters_after_await(
    semantic: &Semantic<'_>,
    fn_node_id: NodeId,
    async_span: Span,
    await_start: u32,
    setter_names: &HashSet<String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (call_id, inner) in semantic.nodes().iter_enumerated() {
        if !async_span.contains_inclusive(inner.span()) || inner.span().start <= await_start {
            continue;
        }
        let AstKind::CallExpression(call) = inner.kind() else {
            continue;
        };
        let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
            continue;
        };
        if !setter_names.contains(callee_id.name.as_str())
            || is_guarded_by_cancel_if(semantic, call_id, fn_node_id)
        {
            continue;
        }
        sites.push(SemanticRuleSite {
            rule: RuleId::NoSetStateAfterAwaitInEffect,
            subject_name: subj_name.clone(),
            message_id: "noSetStateAfterAwaitInEffect",
            target_name: callee_id.name.to_string(),
            message: format!(
                "`{}()` runs after `await` inside `useEffect` without a cancellation guard, which can overwrite newer state when effects resolve out of order.",
                callee_id.name
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

fn is_guarded_by_cancel_if(semantic: &Semantic<'_>, call_id: NodeId, async_fn_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(call_id) {
        if anc_id == async_fn_id {
            break;
        }
        if let AstKind::IfStatement(if_stmt) = semantic.nodes().kind(anc_id) {
            let test_text = if_stmt
                .test
                .span()
                .source_text(semantic.source_text())
                .to_ascii_lowercase();
            if ["cancel", "abort", "ignore", "mount", "active", "current"]
                .iter()
                .any(|kw| test_text.contains(kw))
            {
                return true;
            }
        }
    }
    false
}

pub(super) fn check_no_stale_timer_ref(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let timer_name = match call.callee.without_parentheses() {
        Expression::Identifier(id) if matches!(id.name.as_str(), "setTimeout" | "setInterval") => {
            Some(id.name.as_str())
        }
        Expression::StaticMemberExpression(mem)
            if matches!(mem.property.name.as_str(), "setTimeout" | "setInterval") =>
        {
            Some(mem.property.name.as_str())
        }
        _ => None,
    };
    let Some(t_name) = timer_name else {
        return;
    };
    if matches!(
        semantic.nodes().parent_kind(node_id),
        AstKind::ExpressionStatement(_)
    ) {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoStaleTimerRef,
            subject_name: subj_name.clone(),
            message_id: "noStaleTimerRef",
            target_name: t_name.to_string(),
            message: format!(
                "`{t_name}(...)` timer ID is discarded; store the timer handle in `timerRef.current` and clear it on cleanup or before scheduling a new timer."
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

pub(super) fn check_no_unowned_async_error_clear(
    semantic: &Semantic<'_>,
    fn_node_id: NodeId,
    setter_to_state: &HashMap<String, String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_async_fn_node(semantic.nodes().kind(fn_node_id)) {
        return;
    }
    let fn_span = semantic.nodes().get_node(fn_node_id).span();
    let Some(await_start) = find_first_await_start(semantic, fn_span) else {
        return;
    };
    let fn_text = fn_span.source_text(semantic.source_text());
    if [".current", "AbortController", "requestId", "reqId"]
        .iter()
        .any(|p| fn_text.contains(p))
    {
        return;
    }

    for (call_id, inner) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(inner.span()) || inner.span().end > await_start {
            continue;
        }
        let AstKind::CallExpression(call) = inner.kind() else {
            continue;
        };
        if let Some(setter_name) = classify_error_clear_setter_call(call, setter_to_state)
            && !is_guarded_by_cancel_if(semantic, call_id, fn_node_id)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoUnownedAsyncErrorClear,
                subject_name: subj_name.clone(),
                message_id: "noUnownedAsyncErrorClear",
                target_name: setter_name.to_string(),
                message: format!(
                    "`{setter_name}(...)` clears error state before an async operation without a request ownership guard, so overlapping requests can clobber each other's error state."
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

fn classify_error_clear_setter_call<'a>(
    call: &'a CallExpression<'a>,
    setter_to_state: &HashMap<String, String>,
) -> Option<&'a str> {
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return None;
    };
    let is_error_setter = setter_to_state
        .get(callee_id.name.as_str())
        .is_some_and(|s| s.to_ascii_lowercase().contains("err"))
        || callee_id.name.to_ascii_lowercase().contains("err");
    if !is_error_setter {
        return None;
    }
    let clears_to_falsy = call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
        .is_some_and(is_falsy_clear_arg);
    clears_to_falsy.then_some(callee_id.name.as_str())
}

fn is_falsy_clear_arg(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::BooleanLiteral(b) => !b.value,
        Expression::StringLiteral(s) => s.value.is_empty(),
        Expression::Identifier(id) => id.name == "undefined",
        _ => false,
    }
}
