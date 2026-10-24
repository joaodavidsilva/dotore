//! DOM, timer, observer, `requestAnimationFrame`, Promise `.then`, and event-listener teardown rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; DOM and timer teardown detectors match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{ArrowFunctionBody, CallExpression, Expression, Statement},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite,
        dataflow::is_synchronous,
        react_ast::{get_effect_cleanup_span, get_effect_fn_node},
    },
    matchers::{is_react_hook_callee, span_to_byte_span},
    rules::types::{AutofixPatch, RuleId},
};

use super::{OBSERVER_CLASSES, push_site, push_site_with_fix};

#[derive(Clone)]
struct ListenerCallInfo {
    target_text: String,
    event_type: Option<String>,
    event_type_span: Option<Span>,
    handler_text: Option<String>,
    handler_is_ident: bool,
    capture_flag: bool,
    has_abort_signal: bool,
    call_span: Span,
}

pub(super) fn is_memoized_debounce_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
) -> bool {
    let is_hook_wrapper = is_react_hook_callee(semantic, &call.callee, "useMemo")
        || is_react_hook_callee(semantic, &call.callee, "useCallback")
        || is_react_hook_callee(semantic, &call.callee, "useRef");
    if !is_hook_wrapper {
        return false;
    }
    let Some(first_arg) = call.arguments.first() else {
        return false;
    };
    let text = first_arg.span().source_text(semantic.source_text());
    text.contains("debounce(") || text.contains("throttle(")
}

pub(super) fn check_debounce_no_cleanup(
    semantic: &Semantic<'_>,
    subj_span: Span,
    subj_name: &Option<String>,
    debounce_vars: &[(String, Span)],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (deb_name, deb_span) in debounce_vars {
        let cancel_pattern = format!("{deb_name}.cancel(");
        let current_cancel_pattern = format!("{deb_name}.current.cancel(");
        let current_opt_cancel_pattern = format!("{deb_name}.current?.cancel(");
        let subj_text = subj_span.source_text(semantic.source_text());
        if !subj_text.contains(&cancel_pattern)
            && !subj_text.contains(&current_cancel_pattern)
            && !subj_text.contains(&current_opt_cancel_pattern)
        {
            push_site(
                sites,
                RuleId::DebounceNoCleanup,
                subj_name.clone(),
                "debounceNoCleanup",
                deb_name.clone(),
                format!(
                    "Memoized debounced/throttled callback `{deb_name}` is never cancelled in a `useEffect` cleanup."
                ),
                *deb_span,
                line_starts,
                None,
            );
        }
    }
}

pub(super) fn check_class_unmount_teardown(
    semantic: &Semantic<'_>,
    class_name: &str,
    mount_or_ctor_spans: &[Span],
    unmount_span: Option<Span>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for mount_span in mount_or_ctor_spans {
        let mount_text = mount_span.source_text(semantic.source_text());
        if mount_text.contains("disposeOnUnmount") {
            continue;
        }
        for (_, inner) in semantic.nodes().iter_enumerated() {
            if !mount_span.contains_inclusive(inner.span()) {
                continue;
            }
            let acquired_resource = match inner.kind() {
                AstKind::CallExpression(c) => match c.callee.without_parentheses() {
                    Expression::Identifier(id) => matches!(
                        id.name.as_str(),
                        "setInterval" | "setTimeout" | "requestAnimationFrame"
                    )
                    .then_some((id.name.as_str(), c.span)),
                    Expression::StaticMemberExpression(mem) => matches!(
                        mem.property.name.as_str(),
                        "addEventListener" | "subscribe"
                    )
                    .then_some((mem.property.name.as_str(), c.span)),
                    _ => None,
                },
                AstKind::NewExpression(n) => match n.callee.without_parentheses() {
                    Expression::Identifier(id) if OBSERVER_CLASSES.contains(&id.name.as_str()) => {
                        Some((id.name.as_str(), n.span))
                    }
                    _ => None,
                },
                _ => None,
            };
            let Some((res_name, res_span)) = acquired_resource else {
                continue;
            };
            let has_teardown = unmount_span.is_some_and(|u_span| {
                let u_text = u_span.source_text(semantic.source_text());
                u_text.contains("removeEventListener")
                    || u_text.contains("clearInterval")
                    || u_text.contains("clearTimeout")
                    || u_text.contains("cancelAnimationFrame")
                    || u_text.contains("unsubscribe")
                    || u_text.contains("disconnect")
                    || u_text.contains("dispose")
                    || u_text.contains("abort")
            });
            if !has_teardown {
                push_site(
                    sites,
                    RuleId::ClassComponentMissingComponentWillUnmountTeardown,
                    Some(class_name.to_string()),
                    "classComponentMissingComponentWillUnmountTeardown",
                    res_name,
                    format!(
                        "`{class_name}` acquires `{res_name}` without releasing it in `componentWillUnmount`."
                    ),
                    res_span,
                    line_starts,
                    None,
                );
            }
        }
    }
}

pub(super) fn check_remove_listener_inline_handler(
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::StaticMemberExpression(mem) = callee
        && matches!(
            mem.property.name.as_str(),
            "removeEventListener" | "removeListener" | "off"
        )
        && let Some(handler_arg) = call.arguments.get(1).and_then(|a| a.as_expression())
    {
        let handler_unwrapped = handler_arg.without_parentheses();
        let is_inline = match handler_unwrapped {
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
            Expression::CallExpression(c) => matches!(
                c.callee.without_parentheses(),
                Expression::StaticMemberExpression(m) if m.property.name == "bind"
            ),
            _ => false,
        };
        if is_inline {
            push_site(
                sites,
                RuleId::EffectRemoveListenerInlineHandler,
                subj_name.clone(),
                "effectRemoveListenerInlineHandler",
                mem.property.name.as_str(),
                format!(
                    "`{}` called with a fresh inline function reference that can never match the registered listener.",
                    mem.property.name
                ),
                handler_unwrapped.span(),
                line_starts,
                None,
            );
        }
    }
}

fn parse_listener_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    expected_method: &str,
) -> Option<ListenerCallInfo> {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return None;
    };
    if mem.property.name.as_str() != expected_method {
        return None;
    }
    let target_text = mem
        .object
        .without_parentheses()
        .span()
        .source_text(semantic.source_text())
        .trim()
        .to_string();

    let first_arg = call.arguments.first()?.as_expression()?.without_parentheses();
    let (event_type, event_type_span) = match first_arg {
        Expression::StringLiteral(s) => (
            Some(s.value.as_str().unwrap_or_default().to_string()),
            Some(s.span),
        ),
        _ => (None, None),
    };

    let second_arg = call
        .arguments
        .get(1)
        .and_then(|a| a.as_expression())
        .map(Expression::without_parentheses);
    let (handler_text, handler_is_ident) = match second_arg {
        Some(Expression::Identifier(id)) => (Some(id.name.to_string()), true),
        Some(Expression::StaticMemberExpression(m)) => (
            Some(
                m.span
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            ),
            true,
        ),
        Some(other) => (
            Some(
                other
                    .span()
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            ),
            false,
        ),
        None => (None, false),
    };

    let third_arg = call
        .arguments
        .get(2)
        .and_then(|a| a.as_expression())
        .map(Expression::without_parentheses);
    let mut capture_flag = false;
    let mut has_abort_signal = false;
    if let Some(opt) = third_arg {
        match opt {
            Expression::BooleanLiteral(b) => capture_flag = b.value,
            Expression::ObjectExpression(obj) => {
                let obj_text = obj.span.source_text(semantic.source_text());
                if obj_text.contains("capture: true") || obj_text.contains("capture:true") {
                    capture_flag = true;
                }
                if obj_text.contains("signal") {
                    has_abort_signal = true;
                }
            }
            _ => {}
        }
    }

    Some(ListenerCallInfo {
        target_text,
        event_type,
        event_type_span,
        handler_text,
        handler_is_ident,
        capture_flag,
        has_abort_signal,
        call_span: call.span,
    })
}

pub(super) fn check_effect_hook_call(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    is_hook: bool,
    subj_param_names: &HashSet<String>,
    setter_to_state: &HashMap<String, String>,
    _effect_event_names: &HashSet<String>,
    _fresh_render_bindings: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let cb = first_arg.without_parentheses();

    // `no-async-effect-callback`
    let is_async = match cb {
        Expression::ArrowFunctionExpression(arr) => arr.r#async,
        Expression::FunctionExpression(f) => f.r#async,
        _ => false,
    };
    if is_async {
        push_site(
            sites,
            RuleId::NoAsyncEffectCallback,
            subj_name.clone(),
            "noAsyncEffectCallback",
            "useEffect",
            "Effect callbacks cannot be `async` because an `async` function returns a Promise instead of a cleanup function.".to_string(),
            cb.span(),
            line_starts,
            None,
        );
    }

    let Some(effect_fn_id) = get_effect_fn_node(semantic, call_node_id) else {
        return;
    };
    let effect_fn_span = semantic.nodes().get_node(effect_fn_id).span();
    let cleanup_span = get_effect_cleanup_span(semantic, effect_fn_id);
    let cleanup_text = cleanup_span
        .map(|s| s.source_text(semantic.source_text()))
        .unwrap_or_default();

    // Collect deps identifier names
    let mut dep_ident_names: HashSet<String> = HashSet::new();
    if let Some(deps_arg) = call.arguments.get(1).and_then(|a| a.as_expression())
        && let Expression::ArrayExpression(arr) = deps_arg.without_parentheses()
    {
        for elem in &arr.elements {
            if let Some(Expression::Identifier(id)) =
                elem.as_expression().map(Expression::without_parentheses)
            {
                dep_ident_names.insert(id.name.to_string());
            }
        }
    }

    // `no-effect-wrapper-discards-callback-cleanup-return`
    if is_hook
        && cleanup_span.is_none()
        && !subj_param_names.is_empty()
        && let AstKind::ArrowFunctionExpression(arr) = semantic.nodes().kind(effect_fn_id)
        && let ArrowFunctionBody::FunctionBody(body) = &arr.body
    {
        for stmt in &body.statements {
            if let Statement::ExpressionStatement(expr_stmt) = stmt
                && let Expression::CallExpression(inner_call) =
                    expr_stmt.expression.without_parentheses()
                && let Expression::Identifier(callee_id) =
                    inner_call.callee.without_parentheses()
                && subj_param_names.contains(callee_id.name.as_str())
            {
                push_site(
                    sites,
                    RuleId::NoEffectWrapperDiscardsCallbackCleanupReturn,
                    subj_name.clone(),
                    "noEffectWrapperDiscardsCallbackCleanupReturn",
                    callee_id.name.as_str(),
                    format!(
                        "Custom effect wrapper calls `{}` without returning its cleanup function; use `return {}()`.",
                        callee_id.name, callee_id.name
                    ),
                    inner_call.span,
                    line_starts,
                    None,
                );
            }
        }
    }

    let mut add_listeners: Vec<ListenerCallInfo> = Vec::new();
    let mut remove_listeners: Vec<ListenerCallInfo> = Vec::new();
    let mut distinct_sync_setters: HashSet<String> = HashSet::new();

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        let inner_span = inner_node.span();
        if !effect_fn_span.contains_inclusive(inner_span) {
            continue;
        }
        let in_cleanup = cleanup_span.is_some_and(|cs| cs.contains_inclusive(inner_span));

        match inner_node.kind() {
            AstKind::NewExpression(new_expr) if !in_cleanup => {
                if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                    && OBSERVER_CLASSES.contains(&id.name.as_str())
                {
                    let has_disconnect = cleanup_text.contains(".disconnect(")
                        || cleanup_text.contains(".unobserve(");
                    if !has_disconnect {
                        push_site(
                            sites,
                            RuleId::EffectObserverNeedsDisconnect,
                            subj_name.clone(),
                            "effectObserverNeedsDisconnect",
                            id.name.as_str(),
                            format!(
                                "`new {}` in `useEffect` is never disconnected in cleanup; return `() => observer.disconnect()`.",
                                id.name
                            ),
                            new_expr.span,
                            line_starts,
                            None,
                        );
                    }
                }
            }
            AstKind::CallExpression(inner_call) => {
                if in_cleanup {
                    if let Some(rem) =
                        parse_listener_call(semantic, inner_call, "removeEventListener")
                    {
                        remove_listeners.push(rem);
                    }
                    continue;
                }

                if let Some(add) = parse_listener_call(semantic, inner_call, "addEventListener") {
                    // `advanced-event-handler-refs`
                    if let Some(handler_name) = &add.handler_text
                        && add.handler_is_ident
                        && dep_ident_names.contains(handler_name)
                    {
                        push_site(
                            sites,
                            RuleId::AdvancedEventHandlerRefs,
                            subj_name.clone(),
                            "advancedEventHandlerRefs",
                            handler_name.clone(),
                            format!(
                                "Effect re-subscribes `addEventListener` whenever `{handler_name}` changes; store `{handler_name}` in a ref or `useEffectEvent`."
                            ),
                            inner_call.span,
                            line_starts,
                            None,
                        );
                    }
                    add_listeners.push(add);
                }

                // `effect-raf-loop-needs-cancel`
                let is_raf = match inner_call.callee.without_parentheses() {
                    Expression::Identifier(id) => id.name == "requestAnimationFrame",
                    Expression::StaticMemberExpression(mem) => {
                        mem.property.name == "requestAnimationFrame"
                    }
                    _ => false,
                };
                if is_raf && !cleanup_text.contains("cancelAnimationFrame") {
                    push_site(
                        sites,
                        RuleId::EffectRafLoopNeedsCancel,
                        subj_name.clone(),
                        "effectRafLoopNeedsCancel",
                        "requestAnimationFrame",
                        "`requestAnimationFrame` inside `useEffect` has no `cancelAnimationFrame` in cleanup.".to_string(),
                        inner_call.span,
                        line_starts,
                        None,
                    );
                }

                // `no-cascading-set-state`
                if let Expression::Identifier(callee_id) = inner_call.callee.without_parentheses()
                    && setter_to_state.contains_key(callee_id.name.as_str())
                    && is_synchronous(semantic, inner_id, effect_fn_id)
                {
                    distinct_sync_setters.insert(callee_id.name.to_string());
                }

                // `no-promise-then-side-effect-in-effect-without-catch`
                if let Expression::StaticMemberExpression(mem) =
                    inner_call.callee.without_parentheses()
                    && mem.property.name == "then"
                    && inner_call.arguments.len() == 1
                {
                    check_promise_then_without_catch(
                        semantic,
                        inner_id,
                        inner_call,
                        setter_to_state,
                        subj_name,
                        line_starts,
                        sites,
                    );
                }
            }
            _ => {}
        }
    }

    if distinct_sync_setters.len() >= 2 {
        push_site(
            sites,
            RuleId::NoCascadingSetState,
            subj_name.clone(),
            "noCascadingSetState",
            "useEffect",
            "Effect calls multiple state setters synchronously; combine related state or derive values during render.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // Match `add_listeners` vs `remove_listeners`
    check_effect_listener_mismatches(
        &add_listeners,
        &remove_listeners,
        cleanup_text,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_effect_listener_mismatches(
    add_listeners: &[ListenerCallInfo],
    remove_listeners: &[ListenerCallInfo],
    cleanup_text: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if add_listeners.is_empty() || remove_listeners.is_empty() {
        return;
    }
    for add in add_listeners {
        if add.has_abort_signal && cleanup_text.contains(".abort(") {
            continue;
        }
        // Check if there is an exact matching remove
        let has_exact_match = remove_listeners.iter().any(|rem| {
            rem.target_text == add.target_text
                && rem.event_type == add.event_type
                && rem.handler_text == add.handler_text
                && rem.handler_is_ident
                && add.handler_is_ident
                && rem.capture_flag == add.capture_flag
        });
        if has_exact_match {
            continue;
        }

        // Check if there is a remove with the same target & event_type, but different handler reference
        if let Some(rem_same_event) = remove_listeners
            .iter()
            .find(|rem| rem.target_text == add.target_text && rem.event_type == add.event_type)
        {
            if rem_same_event.handler_text != add.handler_text
                || !rem_same_event.handler_is_ident
                || !add.handler_is_ident
            {
                push_site(
                    sites,
                    RuleId::EffectListenerCleanupReferenceMismatch,
                    subj_name.clone(),
                    "effectListenerCleanupReferenceMismatch",
                    rem_same_event
                        .handler_text
                        .clone()
                        .unwrap_or_else(|| "removeEventListener".to_string()),
                    "Effect cleanup passes a different listener reference to `removeEventListener` than was registered with `addEventListener`.".to_string(),
                    rem_same_event.call_span,
                    line_starts,
                    None,
                );
            } else if rem_same_event.capture_flag != add.capture_flag {
                push_site(
                    sites,
                    RuleId::EffectListenerCleanupMismatch,
                    subj_name.clone(),
                    "effectListenerCleanupMismatch",
                    rem_same_event
                        .event_type
                        .clone()
                        .unwrap_or_else(|| "removeEventListener".to_string()),
                    "`removeEventListener` capture flag does not match `addEventListener`.".to_string(),
                    rem_same_event.call_span,
                    line_starts,
                    None,
                );
            }
            continue;
        }

        // Otherwise, if there is a remove with the same handler (or only 1 add & 1 remove), it's a listener cleanup mismatch (wrong event type or wrong target)
        let candidate_rem = remove_listeners
            .iter()
            .find(|rem| rem.handler_text == add.handler_text)
            .or_else(|| {
                (add_listeners.len() == 1 && remove_listeners.len() == 1)
                    .then(|| &remove_listeners[0])
            });

        if let Some(rem) = candidate_rem {
            let autofix = if rem.target_text == add.target_text
                && let (Some(add_ev), Some(rem_ev_span)) = (&add.event_type, rem.event_type_span)
            {
                Some(AutofixPatch::replace(
                    format!(
                        "Change `removeEventListener` event type to `'{add_ev}'` to match `addEventListener`"
                    ),
                    span_to_byte_span(rem_ev_span),
                    format!("'{add_ev}'"),
                ))
            } else {
                None
            };

            push_site_with_fix(
                sites,
                RuleId::EffectListenerCleanupMismatch,
                subj_name.clone(),
                "effectListenerCleanupMismatch",
                rem.event_type
                    .clone()
                    .unwrap_or_else(|| "removeEventListener".to_string()),
                "`removeEventListener` in effect cleanup does not match the event type or target of `addEventListener`.".to_string(),
                rem.call_span,
                line_starts,
                autofix,
            );
        }
    }
}

fn check_promise_then_without_catch(
    semantic: &Semantic<'_>,
    then_node_id: NodeId,
    then_call: &CallExpression<'_>,
    setter_to_state: &HashMap<String, String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Check if an enclosing chain has `.catch(...)` or if this is the outermost `.then(...)`
    for anc_id in semantic.nodes().ancestor_ids(then_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::StaticMemberExpression(mem) => {
                if mem.property.name == "catch" {
                    return;
                }
                if mem.property.name == "then" {
                    // Outer `.then` will be checked instead
                    return;
                }
            }
            AstKind::CallExpression(_) | AstKind::ParenthesizedExpression(_) => {}
            _ => break,
        }
    }

    let Some(cb_arg) = then_call.arguments.first() else {
        return;
    };
    let cb_span = cb_arg.span();
    let mut calls_setter = false;
    for (_, inner) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(inner.span()) {
            continue;
        }
        if let AstKind::CallExpression(c) = inner.kind()
            && let Expression::Identifier(id) = c.callee.without_parentheses()
            && (setter_to_state.contains_key(id.name.as_str()) || id.name.starts_with("set"))
        {
            calls_setter = true;
            break;
        }
    }

    if calls_setter {
        push_site(
            sites,
            RuleId::NoPromiseThenSideEffectInEffectWithoutCatch,
            subj_name.clone(),
            "noPromiseThenSideEffectInEffectWithoutCatch",
            "then",
            "Promise `.then(...)` in `useEffect` updates state without a `.catch(...)` handler.".to_string(),
            then_call.span,
            line_starts,
            None,
        );
    }
}
