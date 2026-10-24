//! Framer Motion / `motion/react` (`motion-*`) `AnimatePresence`, layout, drag, keyframe,
//! `useTransform`, and render-body rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrayExpressionElement, ArrowFunctionBody, CallExpression, Expression,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement,
        JSXElementName, JSXMemberExpressionObject, ObjectExpression, ObjectPropertyKind, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;
use oxc_syntax::operator::LogicalOperator;

use super::{
    FileImports, extract_attr_string_value, extract_callee_name, extract_jsx_class_name_str,
    extract_jsx_style_string_prop, extract_object_array_prop_len, extract_object_number_prop,
    find_jsx_attr, get_jsx_element_name, has_jsx_truthy_attr, has_object_prop,
    is_in_direct_render_body, is_iteration_call, property_key_name, push_site,
};
use crate::{
    ir::{
        ByteSpan,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::jsx_has_spread_attr,
    rules::RuleId,
};

const INLINE_HTML_TAGS: &[&str] = &[
    "a", "abbr", "b", "bdi", "bdo", "cite", "code", "data", "del", "dfn", "em", "i", "ins", "kbd",
    "label", "mark", "q", "rp", "rt", "ruby", "s", "samp", "small", "span", "strong", "sub", "sup",
    "time", "u", "var",
];

const NON_INLINE_DISPLAY_CLASSES: &[&str] = &[
    "block",
    "inline-block",
    "flex",
    "inline-flex",
    "grid",
    "inline-grid",
    "table",
    "table-row",
    "table-cell",
    "contents",
    "flow-root",
    "list-item",
];

const MOTION_KEYFRAME_ATTRS: &[&str] = &[
    "animate",
    "whileHover",
    "whileTap",
    "whileInView",
    "whileFocus",
    "whileDrag",
    "exit",
];

pub(crate) fn check_motion_jsx_element(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    imports: &FileImports,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&jsx_el.opening_element.name);
    let is_animate_presence = imports.animate_presence_locals.contains(&tag_name)
        || tag_name.ends_with(".AnimatePresence");
    if !is_animate_presence {
        return;
    }

    let loc = loc_from_line_starts(line_starts, jsx_el.span.start);
    let span = ByteSpan {
        start: jsx_el.span.start,
        end: jsx_el.span.end,
    };

    // 1. `motion-animate-presence-must-outlive-child`
    let has_conditional_child = animate_presence_has_conditional_child(&jsx_el.children);
    let directly_in_conditional = is_animate_presence_in_conditional(semantic, node_id, subj_id);
    let subject_has_early_null_return =
        subj_id.is_some_and(|sid| subject_has_early_empty_return(semantic, sid, jsx_el.span.start));

    if !has_conditional_child && (directly_in_conditional || subject_has_early_null_return) {
        push_site(
            sites,
            RuleId::MotionAnimatePresenceMustOutliveChild,
            subject_name.clone(),
            "motionAnimatePresenceMustOutliveChild",
            &tag_name,
            "`<AnimatePresence>` unmounts at the same time as its child; keep `<AnimatePresence>` mounted and move the condition inside it.".to_string(),
            loc,
            span,
        );
    }

    // 2. `motion-animate-presence-requires-key`
    let mut missing_key_elements: Vec<&JSXElement<'_>> = Vec::new();
    collect_direct_animate_presence_children_missing_key(
        &jsx_el.children,
        &mut missing_key_elements,
    );
    for child_el in missing_key_elements {
        let child_tag = get_jsx_element_name(&child_el.opening_element.name);
        push_site(
            sites,
            RuleId::MotionAnimatePresenceRequiresKey,
            subject_name.clone(),
            "motionAnimatePresenceRequiresKey",
            &child_tag,
            format!(
                "Direct `<AnimatePresence>` child `<{child_tag}>` requires a unique `key` prop so Motion can track exiting elements."
            ),
            loc_from_line_starts(line_starts, child_el.span.start),
            ByteSpan {
                start: child_el.span.start,
                end: child_el.span.end,
            },
        );
    }

    // 3. `motion-animate-presence-wait-single-child`
    let is_wait_mode = find_jsx_attr(&jsx_el.opening_element.attributes, "mode")
        .and_then(|a| a.value.as_ref())
        .and_then(extract_attr_string_value)
        == Some("wait")
        || has_jsx_truthy_attr(&jsx_el.opening_element.attributes, "exitBeforeEnter");

    if is_wait_mode && count_simultaneous_animate_presence_children(&jsx_el.children) > 1 {
        push_site(
            sites,
            RuleId::MotionAnimatePresenceWaitSingleChild,
            subject_name.clone(),
            "motionAnimatePresenceWaitSingleChild",
            &tag_name,
            "`<AnimatePresence mode=\"wait\">` only animates one child at a time; render a single active child or switch mode.".to_string(),
            loc,
            span,
        );
    }
}

fn animate_presence_has_conditional_child(children: &[JSXChild<'_>]) -> bool {
    for child in children {
        if let JSXChild::ExpressionContainer(cont) = child
            && let Some(expr) = cont.expression.as_expression()
        {
            let inner = expr.without_parentheses();
            if matches!(
                inner,
                Expression::LogicalExpression(_)
                    | Expression::ConditionalExpression(_)
                    | Expression::CallExpression(_)
            ) {
                return true;
            }
        }
    }
    false
}

fn is_animate_presence_in_conditional(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subj_id: Option<NodeId>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if Some(anc_id) == subj_id {
            break;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::JSXElement(_) => break,
            AstKind::LogicalExpression(log)
                if matches!(
                    log.operator,
                    LogicalOperator::And | LogicalOperator::Or | LogicalOperator::Coalesce
                ) =>
            {
                return true;
            }
            AstKind::ConditionalExpression(_) | AstKind::IfStatement(_) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn subject_has_early_empty_return(
    semantic: &Semantic<'_>,
    subj_id: NodeId,
    before_pos: u32,
) -> bool {
    let subj_span = semantic.nodes().get_node(subj_id).span();
    for (nid, node) in semantic.nodes().iter_enumerated() {
        let span = node.span();
        if !subj_span.contains_inclusive(span) || span.start >= before_pos {
            continue;
        }
        let AstKind::ReturnStatement(ret) = node.kind() else {
            continue;
        };
        let is_empty_ret = match &ret.argument {
            None => true,
            Some(expr) => match expr.without_parentheses() {
                Expression::NullLiteral(_) => true,
                Expression::BooleanLiteral(b) => !b.value,
                Expression::Identifier(id) => id.name == "undefined",
                _ => false,
            },
        };
        if !is_empty_ret {
            continue;
        }
        // Must be inside an IfStatement within the same subject (not nested function)
        let in_if = semantic
            .nodes()
            .ancestor_ids(nid)
            .take_while(|&anc| anc != subj_id)
            .any(|anc| matches!(semantic.nodes().kind(anc), AstKind::IfStatement(_)));
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(nid)
            .take_while(|&anc| anc != subj_id)
            .any(|anc| {
                matches!(
                    semantic.nodes().kind(anc),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_if && !in_nested_fn {
            return true;
        }
    }
    false
}

fn collect_direct_animate_presence_children_missing_key<'a>(
    children: &'a [JSXChild<'a>],
    out: &mut Vec<&'a JSXElement<'a>>,
) {
    let direct_element_count = children
        .iter()
        .filter(|c| matches!(c, JSXChild::Element(_)))
        .count();

    for child in children {
        match child {
            JSXChild::Element(el) => {
                let has_exit = find_jsx_attr(&el.opening_element.attributes, "exit").is_some();
                if (direct_element_count > 1 || has_exit) && jsx_element_missing_key(el) {
                    out.push(el);
                }
            }
            JSXChild::ExpressionContainer(cont) => {
                if let Some(expr) = cont.expression.as_expression() {
                    collect_expr_jsx_elements_missing_key(expr, out);
                }
            }
            _ => {}
        }
    }
}

fn collect_expr_jsx_elements_missing_key<'a>(
    expr: &'a Expression<'a>,
    out: &mut Vec<&'a JSXElement<'a>>,
) {
    match expr.without_parentheses() {
        Expression::JSXElement(el) => {
            if jsx_element_missing_key(el) {
                out.push(el);
            }
        }
        Expression::ConditionalExpression(cond) => {
            collect_expr_jsx_elements_missing_key(&cond.consequent, out);
            collect_expr_jsx_elements_missing_key(&cond.alternate, out);
        }
        Expression::LogicalExpression(log) => {
            collect_expr_jsx_elements_missing_key(&log.right, out);
        }
        Expression::CallExpression(call) => {
            if is_iteration_call(call)
                && let Some(cb) = call.arguments.first().and_then(Argument::as_expression)
            {
                collect_callback_returned_jsx_missing_key(cb, out);
            }
        }
        _ => {}
    }
}

fn collect_callback_returned_jsx_missing_key<'a>(
    cb: &'a Expression<'a>,
    out: &mut Vec<&'a JSXElement<'a>>,
) {
    match cb.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                collect_expr_jsx_elements_missing_key(expr, out);
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                    {
                        collect_expr_jsx_elements_missing_key(arg, out);
                    }
                }
            }
        }
        Expression::FunctionExpression(func) => {
            if let Some(body) = &func.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                    {
                        collect_expr_jsx_elements_missing_key(arg, out);
                    }
                }
            }
        }
        _ => {}
    }
}

fn jsx_element_missing_key(el: &JSXElement<'_>) -> bool {
    let attrs = &el.opening_element.attributes;
    if jsx_has_spread_attr(attrs) {
        return false;
    }
    find_jsx_attr(attrs, "key").is_none()
}

fn count_simultaneous_animate_presence_children(children: &[JSXChild<'_>]) -> usize {
    let mut count = 0;
    for child in children {
        match child {
            JSXChild::Element(_) => count += 1,
            JSXChild::Fragment(frag) => {
                count += count_simultaneous_animate_presence_children(&frag.children);
            }
            JSXChild::ExpressionContainer(cont) => {
                if let Some(expr) = cont.expression.as_expression() {
                    let inner = expr.without_parentheses();
                    match inner {
                        Expression::ArrayExpression(arr) => count += arr.elements.len(),
                        Expression::CallExpression(call) if is_iteration_call(call) => {
                            count += 2;
                        }
                        Expression::ConditionalExpression(_)
                        | Expression::LogicalExpression(_)
                        | Expression::JSXElement(_) => {
                            count += 1;
                        }
                        _ => {}
                    }
                }
            }
            JSXChild::Spread(_) => count += 2,
            JSXChild::Text(_) => {}
        }
    }
    count
}

pub(crate) fn check_motion_jsx_opening(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    imports: &FileImports,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);
    let is_motion_el = is_motion_jsx_tag(&opening.name, imports);

    // 5. `motion-drag-axis-constraint-mismatch`
    if let Some(constraints_attr) = find_jsx_attr(&opening.attributes, "dragConstraints")
        && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &constraints_attr.value
        && let Some(Expression::ObjectExpression(obj)) = cont
            .expression
            .as_expression()
            .map(Expression::without_parentheses)
    {
        let drag_axis = find_jsx_attr(&opening.attributes, "drag")
            .and_then(|a| a.value.as_ref())
            .and_then(extract_attr_string_value);

        let left = extract_object_number_prop(obj, "left");
        let right = extract_object_number_prop(obj, "right");
        let top = extract_object_number_prop(obj, "top");
        let bottom = extract_object_number_prop(obj, "bottom");

        let has_horiz = has_object_prop(obj, "left") || has_object_prop(obj, "right");
        let has_vert = has_object_prop(obj, "top") || has_object_prop(obj, "bottom");

        let axis_mismatch = (drag_axis == Some("x") && has_vert && !has_horiz)
            || (drag_axis == Some("y") && has_horiz && !has_vert);
        let bounds_inverted = left.zip(right).is_some_and(|(l, r)| l > r)
            || top.zip(bottom).is_some_and(|(t, b)| t > b);

        if axis_mismatch || bounds_inverted {
            push_site(
                sites,
                RuleId::MotionDragAxisConstraintMismatch,
                subject_name.clone(),
                "motionDragAxisConstraintMismatch",
                "dragConstraints",
                "Motion `dragConstraints` bounds do not match the configured `drag` axis or have inverted min/max bounds.".to_string(),
                loc_from_line_starts(line_starts, constraints_attr.span.start),
                ByteSpan {
                    start: constraints_attr.span.start,
                    end: constraints_attr.span.end,
                },
            );
        }
    }

    // 7. `motion-keyframe-times-mismatch` on JSX attributes
    if let Some(trans_attr) = find_jsx_attr(&opening.attributes, "transition")
        && let Some(JSXAttributeValue::ExpressionContainer(trans_cont)) = &trans_attr.value
        && let Some(Expression::ObjectExpression(trans_obj)) = trans_cont
            .expression
            .as_expression()
            .map(Expression::without_parentheses)
        && let Some(times_len) = extract_object_array_prop_len(trans_obj, "times")
    {
        let mut mismatch_found = false;
        for &kf_attr_name in MOTION_KEYFRAME_ATTRS {
            if let Some(kf_attr) = find_jsx_attr(&opening.attributes, kf_attr_name)
                && let Some(JSXAttributeValue::ExpressionContainer(kf_cont)) = &kf_attr.value
                && let Some(Expression::ObjectExpression(kf_obj)) = kf_cont
                    .expression
                    .as_expression()
                    .map(Expression::without_parentheses)
                && object_has_keyframe_array_length_mismatch(kf_obj, times_len)
            {
                mismatch_found = true;
                break;
            }
        }
        if mismatch_found {
            push_site(
                sites,
                RuleId::MotionKeyframeTimesMismatch,
                subject_name.clone(),
                "motionKeyframeTimesMismatch",
                "times",
                "`transition.times` length does not match the number of keyframes in the animation target.".to_string(),
                loc_from_line_starts(line_starts, trans_attr.span.start),
                ByteSpan {
                    start: trans_attr.span.start,
                    end: trans_attr.span.end,
                },
            );
        }
    }

    // 8. `motion-layout-on-inline-element`
    if is_motion_el && has_motion_layout_prop(&opening.attributes) {
        let intrinsic_tag = tag_name
            .split_once('.')
            .map_or(tag_name.as_str(), |(_, member)| member);
        let style_display = extract_jsx_style_string_prop(&opening.attributes, "display");
        let class_name = extract_jsx_class_name_str(&opening.attributes);
        let has_inline_class = class_name
            .as_deref()
            .is_some_and(|cls| cls.split_whitespace().any(|tok| tok == "inline"));
        let has_non_inline_class = class_name.as_deref().is_some_and(|cls| {
            cls.split_whitespace().any(|tok| {
                let base = tok.rsplit(':').next().unwrap_or(tok);
                NON_INLINE_DISPLAY_CLASSES.contains(&base)
            })
        });
        let has_non_inline_style = style_display
            .as_deref()
            .is_some_and(|d| d != "inline" && !d.is_empty());

        let is_inline = style_display.as_deref() == Some("inline")
            || has_inline_class
            || (INLINE_HTML_TAGS.contains(&intrinsic_tag)
                && !has_non_inline_class
                && !has_non_inline_style);

        if is_inline {
            push_site(
                sites,
                RuleId::MotionLayoutOnInlineElement,
                subject_name.clone(),
                "motionLayoutOnInlineElement",
                &tag_name,
                format!(
                    "`<{tag_name}>` uses Motion `layout` on a `display: inline` element; browsers ignore transforms on inline boxes."
                ),
                loc_from_line_starts(line_starts, opening.span.start),
                ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                },
            );
        }
    }

    // 9. `motion-unstable-layout-id-in-iteration`
    if let Some(layout_id_attr) = find_jsx_attr(&opening.attributes, "layoutId")
        && is_static_jsx_attr_value(&layout_id_attr.value)
        && is_inside_iteration_without_dynamic_layout_group(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::MotionUnstableLayoutIdInIteration,
            subject_name.clone(),
            "motionUnstableLayoutIdInIteration",
            "layoutId",
            "Static `layoutId` inside an iteration causes every item to share the same layout projection identity.".to_string(),
            loc_from_line_starts(line_starts, layout_id_attr.span.start),
            ByteSpan {
                start: layout_id_attr.span.start,
                end: layout_id_attr.span.end,
            },
        );
    }
}

pub(crate) fn check_motion_call_expression(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    imports: &FileImports,
    animate_bindings: &HashSet<String>,
    const_arrays: &HashMap<SymbolId, usize>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let in_render = subj_id.is_some_and(|sid| is_in_direct_render_body(semantic, node_id, sid));

    // 4. `motion-create-in-render`: `motion.create(...)` / `m.create(...)` / `motion(Comp)` in render
    if in_render && is_motion_create_call(call, imports) {
        push_site(
            sites,
            RuleId::MotionCreateInRender,
            subject_name.clone(),
            "motionCreateInRender",
            "motion.create",
            "`motion.create()` called during render creates a new component type on every render and resets state.".to_string(),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
        );
    }

    // 6. `motion-imperative-animation-in-render`
    if in_render && is_imperative_motion_animation_call(call, imports, animate_bindings) {
        let callee_name = extract_callee_name(&call.callee).unwrap_or("animate");
        push_site(
            sites,
            RuleId::MotionImperativeAnimationInRender,
            subject_name.clone(),
            "motionImperativeAnimationInRender",
            callee_name,
            format!(
                "Imperative `{callee_name}()` animation started during render; trigger imperative animations inside `useEffect` or an event handler."
            ),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
        );
    }

    // 7b. `motion-keyframe-times-mismatch` on `animate(target, keyframes, options)`
    let callee_name = extract_callee_name(&call.callee);
    if (callee_name
        .is_some_and(|n| imports.motion_animate_locals.contains(n) || animate_bindings.contains(n))
        || callee_name == Some("animate"))
        && call.arguments.len() >= 3
        && let Some(Expression::ObjectExpression(kf_obj)) = call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .map(Expression::without_parentheses)
        && let Some(Expression::ObjectExpression(opt_obj)) = call
            .arguments
            .get(2)
            .and_then(Argument::as_expression)
            .map(Expression::without_parentheses)
        && let Some(times_len) = extract_object_array_prop_len(opt_obj, "times")
        && object_has_keyframe_array_length_mismatch(kf_obj, times_len)
    {
        push_site(
            sites,
            RuleId::MotionKeyframeTimesMismatch,
            subject_name.clone(),
            "motionKeyframeTimesMismatch",
            "times",
            "`times` length does not match the number of keyframes passed to `animate()`."
                .to_string(),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
        );
    }

    // 10. `motion-use-transform-range-length`
    if callee_name.is_some_and(|n| imports.use_transform_locals.contains(n))
        && call.arguments.len() >= 3
        && let Some(in_arg) = call.arguments.get(1).and_then(Argument::as_expression)
        && let Some(out_arg) = call.arguments.get(2).and_then(Argument::as_expression)
        && let Some(in_len) = resolve_array_length(semantic, in_arg, const_arrays)
        && let Some(out_len) = resolve_array_length(semantic, out_arg, const_arrays)
        && in_len != out_len
    {
        push_site(
            sites,
            RuleId::MotionUseTransformRangeLength,
            subject_name.clone(),
            "motionUseTransformRangeLength",
            "useTransform",
            format!(
                "`useTransform` input range has {in_len} stops but output range has {out_len} stops; both ranges must have equal length."
            ),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
        );
    }

    // 11. `motion-value-subscription-in-render`
    if in_render && is_motion_value_subscription_call(call) {
        push_site(
            sites,
            RuleId::MotionValueSubscriptionInRender,
            subject_name.clone(),
            "motionValueSubscriptionInRender",
            "on",
            "MotionValue subscription registered during render leaks listeners on every re-render; use `useMotionValueEvent` or `useEffect`.".to_string(),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
        );
    }
}

fn is_motion_create_call(call: &CallExpression<'_>, imports: &FileImports) -> bool {
    match call.callee.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            if matches!(mem.property.name.as_str(), "create" | "custom")
                && let Expression::Identifier(obj) = mem.object.without_parentheses()
            {
                return imports.motion_factory_locals.contains(obj.name.as_str());
            }
            false
        }
        Expression::Identifier(id) => {
            imports.motion_factory_locals.contains(id.name.as_str()) && !call.arguments.is_empty()
        }
        _ => false,
    }
}

fn is_imperative_motion_animation_call(
    call: &CallExpression<'_>,
    imports: &FileImports,
    animate_bindings: &HashSet<String>,
) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            imports.motion_animate_locals.contains(name) || animate_bindings.contains(name)
        }
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name == "start"
                && let Expression::Identifier(obj) = mem.object.without_parentheses()
            {
                return animate_bindings.contains(obj.name.as_str())
                    || obj.name == "controls"
                    || obj.name == "animationControls";
            }
            false
        }
        _ => false,
    }
}

fn is_motion_value_subscription_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    let prop = mem.property.name.as_str();
    if prop == "onChange" && call.arguments.len() == 1 {
        return true;
    }
    if prop == "on"
        && call.arguments.len() >= 2
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && let Expression::StringLiteral(s) = first_arg.without_parentheses()
    {
        return matches!(
            s.value.as_str(),
            Some(
                "change"
                    | "renderRequest"
                    | "animationStart"
                    | "animationComplete"
                    | "animationCancel"
            )
        );
    }
    false
}

fn resolve_array_length(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    const_arrays: &HashMap<SymbolId, usize>,
) -> Option<usize> {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => {
            if arr.elements.iter().any(ArrayExpressionElement::is_spread) {
                None
            } else {
                Some(arr.elements.len())
            }
        }
        Expression::Identifier(id) => {
            let ref_id = id.reference_id.get()?;
            let sym_id = semantic.scoping().get_reference(ref_id).symbol_id()?;
            const_arrays.get(&sym_id).copied()
        }
        _ => None,
    }
}

fn is_motion_jsx_tag(name: &JSXElementName<'_>, imports: &FileImports) -> bool {
    match name {
        JSXElementName::Identifier(id) => id.name.starts_with("Motion"),
        JSXElementName::IdentifierReference(id) => id.name.starts_with("Motion"),
        JSXElementName::MemberExpression(mem) => {
            if let JSXMemberExpressionObject::IdentifierReference(obj) = &mem.object {
                imports.motion_factory_locals.contains(obj.name.as_str())
            } else {
                false
            }
        }
        _ => false,
    }
}

fn has_motion_layout_prop(attrs: &[JSXAttributeItem<'_>]) -> bool {
    for attr in attrs {
        let JSXAttributeItem::Attribute(a) = attr else {
            continue;
        };
        let JSXAttributeName::Identifier(id) = &a.name else {
            continue;
        };
        if id.name == "layoutId" {
            return true;
        }
        if id.name == "layout" {
            if let Some(JSXAttributeValue::ExpressionContainer(cont)) = &a.value
                && let Some(Expression::BooleanLiteral(b)) = cont
                    .expression
                    .as_expression()
                    .map(Expression::without_parentheses)
            {
                return b.value;
            }
            return true;
        }
    }
    false
}

fn is_static_jsx_attr_value(val: &Option<JSXAttributeValue<'_>>) -> bool {
    let Some(v) = val else {
        return false;
    };
    match v {
        JSXAttributeValue::StringLiteral(_) => true,
        JSXAttributeValue::ExpressionContainer(cont) => {
            let Some(expr) = cont.expression.as_expression() else {
                return false;
            };
            match expr.without_parentheses() {
                Expression::StringLiteral(_) => true,
                Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_inside_iteration_without_dynamic_layout_group(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> bool {
    let mut saw_dynamic_layout_group = false;
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::JSXElement(el) => {
                let tag = get_jsx_element_name(&el.opening_element.name);
                if (tag == "LayoutGroup" || tag.ends_with(".LayoutGroup"))
                    && let Some(id_attr) = find_jsx_attr(&el.opening_element.attributes, "id")
                    && !is_static_jsx_attr_value(&id_attr.value)
                {
                    saw_dynamic_layout_group = true;
                }
            }
            AstKind::CallExpression(call) if is_iteration_call(call) => {
                return !saw_dynamic_layout_group;
            }
            AstKind::ForStatement(_) | AstKind::ForOfStatement(_) | AstKind::ForInStatement(_) => {
                return !saw_dynamic_layout_group;
            }
            _ => {}
        }
    }
    false
}

fn object_has_keyframe_array_length_mismatch(
    kf_obj: &ObjectExpression<'_>,
    times_len: usize,
) -> bool {
    for prop in &kf_obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some("transition") {
            continue;
        }
        if let Expression::ArrayExpression(arr) = p.value.without_parentheses()
            && !arr.elements.iter().any(ArrayExpressionElement::is_spread)
            && arr.elements.len() >= 2
            && arr.elements.len() != times_len
        {
            return true;
        }
    }
    false
}
