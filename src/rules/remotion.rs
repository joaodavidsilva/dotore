//! Motion / Framer Motion, Remotion, TanStack Form/Table/Virtual, Redux,
//! and UI primitive composition (`radix-ui`, `base-ui`, `shadcn`, `styled-components`)
//! single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    clippy::too_many_arguments,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrayExpressionElement, ArrowFunctionBody, BindingPattern, CallExpression,
        Expression, ImportDeclarationSpecifier, JSXAttributeItem, JSXAttributeName,
        JSXAttributeValue, JSXChild, JSXElement, JSXElementName, JSXMemberExpressionObject,
        ObjectExpression, ObjectPropertyKind, Program, PropertyKey, Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;
use oxc_syntax::operator::LogicalOperator;

use crate::{
    ir::{
        ByteSpan,
        react_ast::{is_component_name, is_custom_hook_name},
        types::{SemanticRuleSite, SourceLoc, loc_from_line_starts},
    },
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

/// Extracts all Motion, Remotion, TanStack Form/Table/Virtual, Redux, and UI primitive
/// composition rule sites in a single pass.
pub(crate) fn extract_remotion_and_ecosystem_sites(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let imports = collect_file_imports(program, semantic);
    let animate_bindings = collect_use_animate_bindings(semantic);
    let const_arrays = collect_const_array_lengths(semantic);
    let styled_intrinsics = collect_styled_intrinsic_components(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let (subj_id, subject_name) = find_enclosing_react_fn_scope(semantic, node_id);

        match node.kind() {
            AstKind::JSXElement(jsx_el) => {
                check_motion_jsx_element(
                    semantic,
                    node_id,
                    jsx_el,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_motion_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_remotion_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_tanstack_jsx_opening(
                    semantic,
                    opening,
                    &subject_name,
                    line_starts,
                    sites,
                );
                check_ui_primitive_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    &subject_name,
                    &imports,
                    &styled_intrinsics,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_motion_call_expression(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subject_name,
                    &imports,
                    &animate_bindings,
                    &const_arrays,
                    line_starts,
                    sites,
                );
                check_remotion_call_expression(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_tanstack_and_redux_call_expression(
                    semantic,
                    call,
                    subj_id,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct FileImports {
    animate_presence_locals: HashSet<String>,
    motion_factory_locals: HashSet<String>,
    motion_animate_locals: HashSet<String>,
    use_transform_locals: HashSet<String>,
    next_image_locals: HashSet<String>,
    delay_render_locals: HashSet<String>,
    radix_tabs_trigger_locals: HashSet<String>,
    base_ui_tab_locals: HashSet<String>,
}

fn is_motion_module(src: &str) -> bool {
    matches!(
        src,
        "framer-motion" | "motion" | "motion/react" | "motion/react-client" | "motion/react-m"
    ) || src.starts_with("framer-motion/")
        || src.starts_with("motion/")
}

fn collect_file_imports(program: &Program<'_>, _semantic: &Semantic<'_>) -> FileImports {
    let mut out = FileImports::default();
    out.animate_presence_locals
        .insert("AnimatePresence".to_string());
    out.motion_factory_locals.insert("motion".to_string());
    out.motion_factory_locals.insert("m".to_string());
    out.use_transform_locals.insert("useTransform".to_string());
    out.delay_render_locals.insert("delayRender".to_string());

    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        let Some(src) = imp.source.value.as_str() else {
            continue;
        };
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            if let ImportDeclarationSpecifier::ImportSpecifier(s) = spec {
                let imported = s.imported.name().as_str();
                let local = s.local.name.as_str();
                if is_motion_module(src) {
                    match imported {
                        "AnimatePresence" => {
                            out.animate_presence_locals.insert(local.to_string());
                        }
                        "motion" | "m" => {
                            out.motion_factory_locals.insert(local.to_string());
                        }
                        "animate" => {
                            out.motion_animate_locals.insert(local.to_string());
                        }
                        "useTransform" => {
                            out.use_transform_locals.insert(local.to_string());
                        }
                        _ => {}
                    }
                }
            }
            match spec {
                ImportDeclarationSpecifier::ImportDefaultSpecifier(def) => {
                    if matches!(src, "next/image" | "next/legacy/image") {
                        out.next_image_locals.insert(def.local.name.to_string());
                    }
                }
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    let imported = s.imported.name().as_str();
                    let local = s.local.name.as_str();
                    if matches!(src, "next/image" | "next/legacy/image") {
                        out.next_image_locals.insert(local.to_string());
                    } else if src == "remotion" || src.starts_with("@remotion/") {
                        if imported == "delayRender" {
                            out.delay_render_locals.insert(local.to_string());
                        }
                    } else if src == "radix-ui" || src.starts_with("@radix-ui/") {
                        if matches!(imported, "Trigger" | "TabsTrigger") {
                            out.radix_tabs_trigger_locals.insert(local.to_string());
                        } else if imported == "Tabs" {
                            out.radix_tabs_trigger_locals
                                .insert(format!("{local}.Trigger"));
                        }
                    } else if src.starts_with("@base-ui") {
                        if imported == "Tab" {
                            out.base_ui_tab_locals.insert(local.to_string());
                        } else if imported == "Tabs" {
                            out.base_ui_tab_locals.insert(format!("{local}.Tab"));
                        }
                    }
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                    if src == "radix-ui" || src.starts_with("@radix-ui/") {
                        out.radix_tabs_trigger_locals
                            .insert(format!("{}.Trigger", ns.local.name));
                    } else if src.starts_with("@base-ui") {
                        out.base_ui_tab_locals
                            .insert(format!("{}.Tab", ns.local.name));
                    }
                }
            }
        }
    }
    out
}

fn collect_use_animate_bindings(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        let Expression::CallExpression(call) = init.without_parentheses() else {
            continue;
        };
        let callee_name = extract_callee_name(&call.callee);
        if callee_name == Some("useAnimate")
            && let BindingPattern::ArrayPattern(arr) = &decl.id
            && let Some(Some(BindingPattern::BindingIdentifier(second))) = arr.elements.get(1)
        {
            out.insert(second.name.to_string());
        }
        if matches!(
            callee_name,
            Some("useAnimation" | "useAnimationControls")
        ) && let BindingPattern::BindingIdentifier(ident) = &decl.id
        {
            out.insert(ident.name.to_string());
        }
    }
    out
}

fn collect_const_array_lengths(semantic: &Semantic<'_>) -> HashMap<SymbolId, usize> {
    let mut out = HashMap::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let BindingPattern::BindingIdentifier(id) = &decl.id else {
            continue;
        };
        let Some(sym_id) = id.symbol_id.get() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if let Expression::ArrayExpression(arr) = init.without_parentheses()
            && !arr.elements.iter().any(ArrayExpressionElement::is_spread)
        {
            out.insert(sym_id, arr.elements.len());
        }
    }
    out
}

fn check_motion_jsx_element(
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
        };
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
    if attrs
        .iter()
        .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)))
    {
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

fn check_motion_jsx_opening(
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
        && let Some(Expression::ObjectExpression(obj)) =
            cont.expression.as_expression().map(Expression::without_parentheses)
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

fn check_motion_call_expression(
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
    let in_render =
        subj_id.is_some_and(|sid| is_in_direct_render_body(semantic, node_id, sid));

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
    if (callee_name.is_some_and(|n| imports.motion_animate_locals.contains(n) || animate_bindings.contains(n))
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
            "`times` length does not match the number of keyframes passed to `animate()`.".to_string(),
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

fn find_enclosing_react_fn_scope(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> (Option<NodeId>, Option<String>) {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let Some(name) = react_fn_scope_name(semantic, anc_id) {
            return (Some(anc_id), Some(name));
        }
    }
    (None, None)
}

fn react_fn_scope_name(semantic: &Semantic<'_>, node_id: NodeId) -> Option<String> {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(func) => {
            if let Some(id) = &func.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            let parent_id = semantic.nodes().parent_id(node_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            None
        }
        AstKind::ArrowFunctionExpression(_) => {
            let parent_id = semantic.nodes().parent_id(node_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            None
        }
        _ => None,
    }
}

fn is_in_direct_render_body(semantic: &Semantic<'_>, node_id: NodeId, subj_id: NodeId) -> bool {
    !semantic
        .nodes()
        .ancestor_ids(node_id)
        .take_while(|&anc_id| anc_id != subj_id)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
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
                && let Some(Expression::BooleanLiteral(b)) =
                    cont.expression.as_expression().map(Expression::without_parentheses)
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
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
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

fn is_iteration_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(mem.property.name.as_str(), "map" | "flatMap" | "forEach")
}

fn extract_callee_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

fn get_jsx_element_name(name: &JSXElementName<'_>) -> String {
    match name {
        JSXElementName::Identifier(id) => id.name.to_string(),
        JSXElementName::IdentifierReference(id) => id.name.to_string(),
        JSXElementName::NamespacedName(ns) => format!("{}:{}", ns.namespace.name, ns.name.name),
        JSXElementName::MemberExpression(mem) => {
            format!(
                "{}.{}",
                jsx_member_object_name(&mem.object),
                mem.property.name
            )
        }
        JSXElementName::ThisExpression(_) => "this".to_string(),
    }
}

fn jsx_member_object_name(obj: &JSXMemberExpressionObject<'_>) -> String {
    match obj {
        JSXMemberExpressionObject::IdentifierReference(id) => id.name.to_string(),
        JSXMemberExpressionObject::MemberExpression(mem) => {
            format!(
                "{}.{}",
                jsx_member_object_name(&mem.object),
                mem.property.name
            )
        }
        JSXMemberExpressionObject::ThisExpression(_) => "this".to_string(),
    }
}

fn find_jsx_attr<'a>(
    attrs: &'a [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    for item in attrs {
        if let JSXAttributeItem::Attribute(attr) = item
            && let JSXAttributeName::Identifier(id) = &attr.name
            && id.name == target
        {
            return Some(attr);
        }
    }
    None
}

fn has_jsx_truthy_attr(attrs: &[JSXAttributeItem<'_>], target: &str) -> bool {
    let Some(attr) = find_jsx_attr(attrs, target) else {
        return false;
    };
    match &attr.value {
        None => true,
        Some(JSXAttributeValue::ExpressionContainer(cont)) => {
            if let Some(Expression::BooleanLiteral(b)) =
                cont.expression.as_expression().map(Expression::without_parentheses)
            {
                b.value
            } else {
                true
            }
        }
        Some(_) => true,
    }
}

fn extract_attr_string_value<'a>(val: &'a JSXAttributeValue<'a>) -> Option<&'a str> {
    match val {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
        JSXAttributeValue::ExpressionContainer(cont) => {
            if let Some(Expression::StringLiteral(s)) =
                cont.expression.as_expression().map(Expression::without_parentheses)
            {
                s.value.as_str()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_jsx_class_name_str(attrs: &[JSXAttributeItem<'_>]) -> Option<String> {
    let attr = find_jsx_attr(attrs, "className").or_else(|| find_jsx_attr(attrs, "class"))?;
    let val = attr.value.as_ref()?;
    extract_attr_string_value(val).map(ToString::to_string)
}

fn extract_jsx_style_string_prop(attrs: &[JSXAttributeItem<'_>], prop_name: &str) -> Option<String> {
    let attr = find_jsx_attr(attrs, "style")?;
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return None;
    };
    let Expression::ObjectExpression(obj) = cont.expression.as_expression()?.without_parentheses()
    else {
        return None;
    };
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(prop_name)
            && let Expression::StringLiteral(s) = p.value.without_parentheses()
            && let Some(v) = s.value.as_str()
        {
            return Some(v.to_string());
        }
    }
    None
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => s.value.as_str().map(str::to_string),
        _ => None,
    }
}

fn has_object_prop(obj: &ObjectExpression<'_>, name: &str) -> bool {
    obj.properties.iter().any(|prop| {
        if let ObjectPropertyKind::ObjectProperty(p) = prop {
            property_key_name(&p.key).as_deref() == Some(name)
        } else {
            false
        }
    })
}

fn extract_object_number_prop(obj: &ObjectExpression<'_>, name: &str) -> Option<f64> {
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(name) {
            return extract_numeric_literal(&p.value);
        }
    }
    None
}

fn extract_numeric_literal(expr: &Expression<'_>) -> Option<f64> {
    match expr.without_parentheses() {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            extract_numeric_literal(&u.argument).map(|v| -v)
        }
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryPlus => {
            extract_numeric_literal(&u.argument)
        }
        _ => None,
    }
}

fn extract_object_array_prop_len(obj: &ObjectExpression<'_>, name: &str) -> Option<usize> {
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(name)
            && let Expression::ArrayExpression(arr) = p.value.without_parentheses()
            && !arr.elements.iter().any(ArrayExpressionElement::is_spread)
        {
            return Some(arr.elements.len());
        }
    }
    None
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

fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix: None,
    });
}

// ---------------------------------------------------------------------------
// Remotion Rules (`remotion-*`)
// ---------------------------------------------------------------------------

const NATIVE_MEDIA_TAGS: &[&str] = &["img", "video", "audio", "iframe"];

const TAILWIND_TRANSITION_CLASSES: &[&str] = &[
    "transition",
    "transition-all",
    "transition-colors",
    "transition-opacity",
    "transition-shadow",
    "transition-transform",
    "transition-discrete",
];

fn check_remotion_jsx_opening(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    imports: &FileImports,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };

    // 7. `remotion-no-native-media-elements`
    if NATIVE_MEDIA_TAGS.contains(&tag_name.as_str()) {
        push_site(
            sites,
            RuleId::RemotionNoNativeMediaElements,
            subject_name.clone(),
            "remotionNoNativeMediaElements",
            &tag_name,
            format!(
                "Native `<{tag_name}>` element bypasses Remotion frame synchronization; use Remotion's `<Img>`, `<OffthreadVideo>`, `<Audio>`, or `<IFrame>`."
            ),
            loc,
            span,
        );
    }

    // 8. `remotion-no-next-image`
    if imports.next_image_locals.contains(&tag_name) {
        push_site(
            sites,
            RuleId::RemotionNoNextImage,
            subject_name.clone(),
            "remotionNoNextImage",
            &tag_name,
            "Next.js `<Image>` loads asynchronously without blocking Remotion frame rendering; use `<Img>` from `remotion`.".to_string(),
            loc,
            span,
        );
    }

    let class_name = extract_jsx_class_name_str(&opening.attributes);

    // 3. `remotion-no-css-animation`
    let has_tw_anim = class_name.as_deref().is_some_and(|cls| {
        cls.split_whitespace().any(|tok| {
            let base = tok.rsplit(':').next().unwrap_or(tok);
            base.starts_with("animate-") && base != "animate-none"
        })
    });
    let has_style_anim = ["animation", "animationName", "WebkitAnimation"]
        .iter()
        .any(|prop| {
            extract_jsx_style_string_prop(&opening.attributes, prop)
                .is_some_and(|v| !v.trim().is_empty() && v.trim() != "none")
        });
    if has_tw_anim || has_style_anim {
        push_site(
            sites,
            RuleId::RemotionNoCssAnimation,
            subject_name.clone(),
            "remotionNoCssAnimation",
            &tag_name,
            "CSS animations are not driven by `useCurrentFrame()` and render non-deterministically in Remotion.".to_string(),
            loc,
            span,
        );
    }

    // 4. `remotion-no-css-transition`
    let has_tw_transition = class_name.as_deref().is_some_and(|cls| {
        cls.split_whitespace().any(|tok| {
            let base = tok.rsplit(':').next().unwrap_or(tok);
            TAILWIND_TRANSITION_CLASSES.contains(&base)
                || (base.starts_with("transition-[") && base != "transition-none")
        })
    });
    let has_style_transition = [
        "transition",
        "transitionProperty",
        "transitionDuration",
        "WebkitTransition",
    ]
    .iter()
    .any(|prop| {
        extract_jsx_style_string_prop(&opening.attributes, prop)
            .is_some_and(|v| !v.trim().is_empty() && v.trim() != "none" && v.trim() != "0s")
    });
    if has_tw_transition || has_style_transition {
        push_site(
            sites,
            RuleId::RemotionNoCssTransition,
            subject_name.clone(),
            "remotionNoCssTransition",
            &tag_name,
            "CSS transitions are time-based rather than frame-driven and cause flickering in Remotion renders.".to_string(),
            loc,
            span,
        );
    }

    // 5. `remotion-no-css-url-assets`
    let has_tw_url_asset = class_name.as_deref().is_some_and(|cls| {
        cls.split_whitespace().any(|tok| {
            let base = tok.rsplit(':').next().unwrap_or(tok);
            (base.starts_with("bg-[url(") || base.starts_with("mask-[url("))
                && !base.contains("data:")
        })
    });
    let has_style_url_asset = has_css_url_in_style_attr(semantic, &opening.attributes);
    let preloaded_by_img = subj_id.is_some_and(|sid| subject_renders_remotion_img(semantic, sid));
    if (has_tw_url_asset || has_style_url_asset) && !preloaded_by_img {
        push_site(
            sites,
            RuleId::RemotionNoCssUrlAssets,
            subject_name.clone(),
            "remotionNoCssUrlAssets",
            &tag_name,
            "CSS `url(...)` assets are not awaited by Remotion and can flicker between frames; use `<Img>` from `remotion`.".to_string(),
            loc,
            span,
        );
    }
}

fn has_css_url_in_style_attr(semantic: &Semantic<'_>, attrs: &[JSXAttributeItem<'_>]) -> bool {
    let Some(attr) = find_jsx_attr(attrs, "style") else {
        return false;
    };
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return false;
    };
    let Some(Expression::ObjectExpression(obj)) =
        cont.expression.as_expression().map(Expression::without_parentheses)
    else {
        return false;
    };
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let Some(key) = property_key_name(&p.key) else {
            continue;
        };
        if matches!(
            key.as_str(),
            "background"
                | "backgroundImage"
                | "mask"
                | "maskImage"
                | "WebkitMask"
                | "WebkitMaskImage"
                | "borderImage"
                | "borderImageSource"
        ) {
            let val_text = p.value.span().source_text(semantic.source_text());
            if val_text.contains("url(") && !val_text.contains("url(data:") && !val_text.contains("url(\"data:") && !val_text.contains("url('data:") {
                return true;
            }
        }
    }
    false
}

fn subject_renders_remotion_img(semantic: &Semantic<'_>, subj_id: NodeId) -> bool {
    let subj_span = semantic.nodes().get_node(subj_id).span();
    for node in semantic.nodes() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::JSXOpeningElement(op) = node.kind() {
            let tag = get_jsx_element_name(&op.name);
            if tag == "Img" || tag.ends_with(".Img") {
                return true;
            }
        }
    }
    false
}

fn check_remotion_call_expression(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    imports: &FileImports,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let loc = loc_from_line_starts(line_starts, call.span.start);
    let span = ByteSpan {
        start: call.span.start,
        end: call.span.end,
    };

    // 1. `remotion-calculate-metadata-fetch-signal`
    if extract_callee_name(&call.callee) == Some("fetch")
        && is_inside_calculate_metadata(semantic, node_id)
        && !fetch_call_passes_signal(semantic, call)
    {
        push_site(
            sites,
            RuleId::RemotionCalculateMetadataFetchSignal,
            subject_name.clone().or_else(|| Some("calculateMetadata".to_string())),
            "remotionCalculateMetadataFetchSignal",
            "fetch",
            "`fetch()` inside `calculateMetadata` does not forward `abortSignal` via `{ signal: abortSignal }`.".to_string(),
            loc,
            span,
        );
    }

    // 2. `remotion-deterministic-randomness`
    if is_nondeterministic_random_call(call) {
        let target = call
            .callee
            .span()
            .source_text(semantic.source_text())
            .trim();
        push_site(
            sites,
            RuleId::RemotionDeterministicRandomness,
            subject_name.clone(),
            "remotionDeterministicRandomness",
            target,
            format!(
                "`{target}()` produces non-deterministic values across Remotion render workers; use `random(seed)` from `remotion`."
            ),
            loc,
            span,
        );
    }

    // 6 & 9. `remotion-no-module-scope-delay-render` and `remotion-stable-delay-render-handle`
    if is_delay_render_call(call, imports) {
        let has_enclosing_fn = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        });
        if !has_enclosing_fn {
            push_site(
                sites,
                RuleId::RemotionNoModuleScopeDelayRender,
                None,
                "remotionNoModuleScopeDelayRender",
                "delayRender",
                "`delayRender()` called at module scope blocks every composition in the bundle; call it inside a component via `useDelayRender()` or `useState(() => delayRender())`.".to_string(),
                loc,
                span,
            );
        } else if let Some(sid) = subj_id
            && is_in_direct_render_body(semantic, node_id, sid)
        {
            push_site(
                sites,
                RuleId::RemotionStableDelayRenderHandle,
                subject_name.clone(),
                "remotionStableDelayRenderHandle",
                "delayRender",
                "`delayRender()` called directly during render creates a new handle on every re-render; use `useDelayRender()` or `useState(() => delayRender())`.".to_string(),
                loc,
                span,
            );
        }
    }
}

fn is_inside_calculate_metadata(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func)
                if func
                    .id
                    .as_ref()
                    .is_some_and(|id| id.name == "calculateMetadata") =>
            {
                return true;
            }
            AstKind::VariableDeclarator(decl)
                if matches!(
                    &decl.id,
                    BindingPattern::BindingIdentifier(id) if id.name == "calculateMetadata"
                ) =>
            {
                return true;
            }
            AstKind::ObjectProperty(prop)
                if property_key_name(&prop.key).as_deref() == Some("calculateMetadata") =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn fetch_call_passes_signal(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return false;
    };
    match second_arg.without_parentheses() {
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                match prop {
                    ObjectPropertyKind::ObjectProperty(p) => {
                        if property_key_name(&p.key).as_deref() == Some("signal") {
                            return true;
                        }
                    }
                    ObjectPropertyKind::SpreadProperty(_) => return true,
                }
            }
            false
        }
        Expression::Identifier(id) => {
            // Check if local variable is an object containing `signal`
            if let Some(ref_id) = id.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
                    && let Some(Expression::ObjectExpression(obj)) =
                        decl.init.as_ref().map(Expression::without_parentheses)
                {
                    return has_object_prop(obj, "signal");
                }
            }
            false
        }
        _ => false,
    }
}

fn is_nondeterministic_random_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    let prop = mem.property.name.as_str();
    match mem.object.without_parentheses() {
        Expression::Identifier(obj) => {
            (obj.name == "Math" && prop == "random")
                || (obj.name == "crypto" && matches!(prop, "randomUUID" | "getRandomValues"))
        }
        Expression::StaticMemberExpression(inner) => {
            inner.property.name == "crypto"
                && matches!(prop, "randomUUID" | "getRandomValues")
                && matches!(
                    inner.object.without_parentheses(),
                    Expression::Identifier(id) if matches!(id.name.as_str(), "window" | "globalThis" | "self")
                )
        }
        _ => false,
    }
}

fn is_delay_render_call(call: &CallExpression<'_>, imports: &FileImports) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => imports.delay_render_locals.contains(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => mem.property.name == "delayRender",
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// TanStack Form, Table, Virtual & Redux Rules
// ---------------------------------------------------------------------------

const REDUX_DERIVATION_METHODS: &[&str] = &[
    "filter",
    "map",
    "flatMap",
    "reduce",
    "reduceRight",
    "sort",
    "toSorted",
    "reverse",
    "toReversed",
    "slice",
    "concat",
];

fn check_tanstack_jsx_opening(
    semantic: &Semantic<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);

    // 1. `tanstack-form-on-submit-requires-prevent-default`
    if tag_name == "form"
        && let Some(on_submit_attr) = find_jsx_attr(&opening.attributes, "onSubmit")
        && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &on_submit_attr.value
        && let Some(expr) = cont.expression.as_expression()
        && is_tanstack_form_submit_without_prevent_default(semantic, expr)
    {
        push_site(
            sites,
            RuleId::TanstackFormOnSubmitRequiresPreventDefault,
            subject_name.clone(),
            "tanstackFormOnSubmitRequiresPreventDefault",
            "onSubmit",
            "`<form onSubmit>` calls `form.handleSubmit()` without `event.preventDefault()`, causing a full-page browser submit.".to_string(),
            loc_from_line_starts(line_starts, on_submit_attr.span.start),
            ByteSpan {
                start: on_submit_attr.span.start,
                end: on_submit_attr.span.end,
            },
        );
    }

    // 3. `tanstack-virtual-measure-element-requires-data-index`
    let has_spread = opening
        .attributes
        .iter()
        .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)));
    if !has_spread
        && let Some(ref_attr) = find_jsx_attr(&opening.attributes, "ref")
        && ref_is_virtualizer_measure_element(semantic, ref_attr)
        && find_jsx_attr(&opening.attributes, "data-index").is_none()
    {
        push_site(
            sites,
            RuleId::TanstackVirtualMeasureElementRequiresDataIndex,
            subject_name.clone(),
            "tanstackVirtualMeasureElementRequiresDataIndex",
            &tag_name,
            format!(
                "`<{tag_name}>` uses `measureElement` ref without `data-index={{virtualItem.index}}`."
            ),
            loc_from_line_starts(line_starts, opening.span.start),
            ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
        );
    }
}

fn is_tanstack_form_submit_without_prevent_default(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => mem.property.name == "handleSubmit",
        Expression::ArrowFunctionExpression(arrow) => {
            let span = arrow.body.span();
            let text = span.source_text(semantic.source_text());
            text.contains(".handleSubmit(") && !text.contains(".preventDefault(")
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            let text = body.span.source_text(semantic.source_text());
            text.contains(".handleSubmit(") && !text.contains(".preventDefault(")
        }
        Expression::Identifier(id) => {
            if let Some(ref_id) = id.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                let decl_span = semantic.nodes().get_node(decl_id).span();
                let text = decl_span.source_text(semantic.source_text());
                return text.contains(".handleSubmit(") && !text.contains(".preventDefault(");
            }
            false
        }
        _ => false,
    }
}

fn ref_is_virtualizer_measure_element(
    semantic: &Semantic<'_>,
    ref_attr: &oxc_ast::ast::JSXAttribute<'_>,
) -> bool {
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &ref_attr.value else {
        return false;
    };
    let Some(expr) = cont.expression.as_expression() else {
        return false;
    };
    let text = expr.span().source_text(semantic.source_text());
    text.contains("measureElement")
}

fn check_tanstack_and_redux_call_expression(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(callee_name) = extract_callee_name(&call.callee) else {
        return;
    };

    // 2. `tanstack-table-no-unstable-data-or-columns`
    if matches!(callee_name, "useReactTable" | "createReactTable")
        && let Some(sid) = subj_id
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && let Expression::ObjectExpression(obj) = first_arg.without_parentheses()
    {
        let subj_span = semantic.nodes().get_node(sid).span();
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(key) = property_key_name(&p.key) else {
                continue;
            };
            if matches!(key.as_str(), "data" | "columns")
                && is_unstable_table_input(semantic, &p.value, subj_span)
            {
                push_site(
                    sites,
                    RuleId::TanstackTableNoUnstableDataOrColumns,
                    subject_name.clone(),
                    "tanstackTableNoUnstableDataOrColumns",
                    &key,
                    format!(
                        "`useReactTable` option `{key}` is recreated on every render; memoize `{key}` with `useMemo`/`useState` or hoist it to module scope."
                    ),
                    loc_from_line_starts(line_starts, p.span.start),
                    ByteSpan {
                        start: p.span.start,
                        end: p.span.end,
                    },
                );
                break;
            }
        }
    }

    // 4 & 5. `redux-useselector-inline-derivation` and `redux-useselector-returns-new-collection`
    if matches!(callee_name, "useSelector" | "useAppSelector")
        && let Some(sel_arg) = call.arguments.first().and_then(Argument::as_expression)
    {
        let has_equality_fn = call.arguments.len() >= 2;
        if !has_equality_fn && selector_returns_new_collection(sel_arg) {
            push_site(
                sites,
                RuleId::ReduxUseselectorReturnsNewCollection,
                subject_name.clone(),
                "reduxUseselectorReturnsNewCollection",
                callee_name,
                format!(
                    "`{callee_name}` returns a new object or array literal on every call; pass `shallowEqual` or select primitive fields."
                ),
                loc_from_line_starts(line_starts, sel_arg.span().start),
                ByteSpan {
                    start: sel_arg.span().start,
                    end: sel_arg.span().end,
                },
            );
        } else if selector_computes_inline_derivation(semantic, sel_arg) {
            push_site(
                sites,
                RuleId::ReduxUseselectorInlineDerivation,
                subject_name.clone(),
                "reduxUseselectorInlineDerivation",
                callee_name,
                format!(
                    "`{callee_name}` computes a derived collection inline; use `createSelector` or `useMemo` so store dispatches do not recompute and force re-renders."
                ),
                loc_from_line_starts(line_starts, sel_arg.span().start),
                ByteSpan {
                    start: sel_arg.span().start,
                    end: sel_arg.span().end,
                },
            );
        }
    }
}

fn is_unstable_table_input(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    subj_span: oxc_span::Span,
) -> bool {
    match expr.without_parentheses() {
        Expression::ArrayExpression(_) => true,
        Expression::CallExpression(call) => {
            let Some(name) = extract_callee_name(&call.callee) else {
                return false;
            };
            matches!(
                name,
                "filter" | "map" | "flatMap" | "slice" | "concat" | "toSorted" | "values" | "keys" | "entries"
            )
        }
        Expression::Identifier(id) => {
            let Some(ref_id) = id.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !subj_span.contains_inclusive(decl_node.span()) {
                return false;
            }
            if let AstKind::VariableDeclarator(decl) = decl_node.kind()
                && let Some(init) = &decl.init
            {
                return match init.without_parentheses() {
                    Expression::ArrayExpression(_) => true,
                    Expression::CallExpression(c) => {
                        let Some(name) = extract_callee_name(&c.callee) else {
                            return false;
                        };
                        matches!(
                            name,
                            "filter" | "map" | "flatMap" | "slice" | "concat" | "toSorted"
                        )
                    }
                    _ => false,
                };
            }
            false
        }
        _ => false,
    }
}

fn selector_returns_new_collection(sel_arg: &Expression<'_>) -> bool {
    let ret_expr = extract_function_returned_expr(sel_arg);
    let Some(ret) = ret_expr else {
        return false;
    };
    matches!(
        ret.without_parentheses(),
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
    )
}

fn selector_computes_inline_derivation(semantic: &Semantic<'_>, sel_arg: &Expression<'_>) -> bool {
    let body_span = match sel_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => arrow.body.span(),
        Expression::FunctionExpression(func) => {
            let Some(b) = &func.body else {
                return false;
            };
            b.span
        }
        _ => return false,
    };

    for node in semantic.nodes() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                    let prop = mem.property.name.as_str();
                    if REDUX_DERIVATION_METHODS.contains(&prop) {
                        return true;
                    }
                    if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                        if obj.name == "Object"
                            && matches!(prop, "keys" | "values" | "entries" | "fromEntries")
                        {
                            return true;
                        }
                        if obj.name == "Array" && prop == "from" {
                            return true;
                        }
                    }
                }
            }
            AstKind::NewExpression(new_expr) => {
                if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                    && matches!(id.name.as_str(), "Map" | "Set")
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn extract_function_returned_expr<'a>(fn_expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match fn_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                return Some(expr);
            }
            if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                    {
                        return Some(arg);
                    }
                }
            }
            None
        }
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            for stmt in &body.statements {
                if let Statement::ReturnStatement(ret) = stmt
                    && let Some(arg) = &ret.argument
                {
                    return Some(arg);
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// UI Primitive Composition Rules (`radix-ui`, `base-ui`, `shadcn`, `styled-components`)
// ---------------------------------------------------------------------------

const SHADCN_RAW_INPUT_GROUP_CONTROLS: &[&str] = &[
    "input", "textarea", "select", "button", "Input", "Textarea", "Button",
];

const STANDARD_DOM_OR_REACT_PROPS: &[&str] = &[
    "id",
    "className",
    "class",
    "style",
    "children",
    "key",
    "ref",
    "as",
    "forwardedAs",
    "theme",
    "title",
    "role",
    "tabIndex",
    "dir",
    "lang",
    "hidden",
    "draggable",
    "contentEditable",
    "spellCheck",
    "translate",
    "slot",
    "part",
    "inert",
    "popover",
    "popoverTarget",
    "popoverTargetAction",
    "type",
    "name",
    "value",
    "defaultValue",
    "checked",
    "defaultChecked",
    "disabled",
    "readOnly",
    "required",
    "multiple",
    "placeholder",
    "autoFocus",
    "autoComplete",
    "min",
    "max",
    "step",
    "pattern",
    "minLength",
    "maxLength",
    "size",
    "rows",
    "cols",
    "wrap",
    "form",
    "formAction",
    "formEncType",
    "formMethod",
    "formNoValidate",
    "formTarget",
    "href",
    "target",
    "rel",
    "download",
    "src",
    "srcSet",
    "sizes",
    "alt",
    "width",
    "height",
    "loading",
    "decoding",
    "crossOrigin",
    "referrerPolicy",
    "fetchPriority",
    "htmlFor",
    "for",
    "label",
    "open",
    " colSpan",
    "colSpan",
    "rowSpan",
    "headers",
    "scope",
    " dangerouslySetInnerHTML",
    "dangerouslySetInnerHTML",
    "suppressHydrationWarning",
    "suppressContentEditableWarning",
];

fn collect_styled_intrinsic_components(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let BindingPattern::BindingIdentifier(id) = &decl.id else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if is_styled_intrinsic_initializer(semantic, init) {
            out.insert(id.name.to_string());
        }
    }
    out
}

fn is_styled_intrinsic_initializer(semantic: &Semantic<'_>, init: &Expression<'_>) -> bool {
    let text = init.span().source_text(semantic.source_text()).trim();
    if let Some(after) = text.strip_prefix("styled.") {
        return after
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase());
    }
    if let Some(after) = text.strip_prefix("styled(") {
        let trimmed = after.trim_start();
        return trimmed.starts_with('"') || trimmed.starts_with('\'');
    }
    false
}

fn check_ui_primitive_jsx_opening(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    imports: &FileImports,
    styled_intrinsics: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };

    let has_tabs_list_ancestor = has_enclosing_jsx_tag(
        semantic,
        node_id,
        &["Tabs.List", "TabsList", "List"],
    );

    // 1. `radix-tabs-trigger-requires-list`
    let is_radix_trigger = tag_name == "Tabs.Trigger"
        || imports.radix_tabs_trigger_locals.contains(&tag_name);
    if is_radix_trigger && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::RadixTabsTriggerRequiresList,
            subject_name.clone(),
            "radixTabsTriggerRequiresList",
            &tag_name,
            format!(
                "Radix `<{tag_name}>` must be rendered inside `<Tabs.List>` so roving keyboard focus and `tablist` semantics apply."
            ),
            loc,
            span,
        );
    }

    // 2. `base-ui-tabs-tab-requires-list`
    let is_base_ui_tab =
        tag_name == "Tabs.Tab" || imports.base_ui_tab_locals.contains(&tag_name);
    if is_base_ui_tab && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::BaseUiTabsTabRequiresList,
            subject_name.clone(),
            "baseUiTabsTabRequiresList",
            &tag_name,
            format!(
                "Base UI `<{tag_name}>` must be rendered inside `<Tabs.List>` so the `tablist` role and arrow-key navigation cover every tab."
            ),
            loc,
            span,
        );
    }

    // 3. `shadcn-tabs-trigger-requires-list`
    let is_shadcn_trigger =
        tag_name == "TabsTrigger" && !imports.radix_tabs_trigger_locals.contains(&tag_name);
    if is_shadcn_trigger && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::ShadcnTabsTriggerRequiresList,
            subject_name.clone(),
            "shadcnTabsTriggerRequiresList",
            &tag_name,
            "`<TabsTrigger>` must be rendered inside `<TabsList>` so keyboard navigation and `tablist` semantics share one scope.".to_string(),
            loc,
            span,
        );
    }

    // 4. `shadcn-command-item-state-variant-requires-value`
    if matches!(tag_name.as_str(), "CommandItem" | "Command.Item")
        && let Some(class_attr) = find_jsx_attr(&opening.attributes, "className")
    {
        let attr_text = class_attr.span.source_text(semantic.source_text());
        if attr_text.contains("data-[selected]:") || attr_text.contains("data-[disabled]:") {
            push_site(
                sites,
                RuleId::ShadcnCommandItemStateVariantRequiresValue,
                subject_name.clone(),
                "shadcnCommandItemStateVariantRequiresValue",
                &tag_name,
                "`<CommandItem>` uses presence-only `data-[selected]:` or `data-[disabled]:` variant; use `data-[selected=true]:` and `data-[disabled=true]:` because cmdk sets both attributes to `\"true\"` or `\"false\"`.".to_string(),
                loc_from_line_starts(line_starts, class_attr.span.start),
                ByteSpan {
                    start: class_attr.span.start,
                    end: class_attr.span.end,
                },
            );
        }
    }

    // 5. `shadcn-input-group-no-raw-controls`
    if SHADCN_RAW_INPUT_GROUP_CONTROLS.contains(&tag_name.as_str())
        && is_direct_child_of_input_group(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::ShadcnInputGroupNoRawControls,
            subject_name.clone(),
            "shadcnInputGroupNoRawControls",
            &tag_name,
            format!(
                "Raw `<{tag_name}>` inside `<InputGroup>` creates conflicting borders and focus rings; use `InputGroupInput`, `InputGroupTextarea`, or `InputGroupAddon` with `InputGroupButton`."
            ),
            loc,
            span,
        );
    }

    // 6. `styled-components-non-transient-custom-prop-on-intrinsic-element`
    if styled_intrinsics.contains(&tag_name) {
        for item in &opening.attributes {
            let JSXAttributeItem::Attribute(attr) = item else {
                continue;
            };
            let JSXAttributeName::Identifier(id) = &attr.name else {
                continue;
            };
            let prop_name = id.name.as_str();
            if !is_transient_or_standard_dom_prop(prop_name) {
                push_site(
                    sites,
                    RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement,
                    subject_name.clone(),
                    "styledComponentsNonTransientCustomPropOnIntrinsicElement",
                    prop_name,
                    format!(
                        "Custom prop `{prop_name}` on styled intrinsic component `<{tag_name}>` is forwarded to the DOM; prefix it with `$` (`${prop_name}`) to make it transient."
                    ),
                    loc_from_line_starts(line_starts, attr.span.start),
                    ByteSpan {
                        start: attr.span.start,
                        end: attr.span.end,
                    },
                );
                break;
            }
        }
    }
}

fn has_enclosing_jsx_tag(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    allowed_tags: &[&str],
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_element_name(&el.opening_element.name);
            if allowed_tags.contains(&tag.as_str()) {
                return true;
            }
        }
    }
    false
}

fn is_direct_child_of_input_group(semantic: &Semantic<'_>, opening_node_id: NodeId) -> bool {
    // `opening_node_id` is `JSXOpeningElement`; its parent is `JSXElement`; find the next enclosing `JSXElement`
    let mut skipped_self = false;
    for anc_id in semantic.nodes().ancestor_ids(opening_node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            if !skipped_self {
                skipped_self = true;
                continue;
            }
            let parent_tag = get_jsx_element_name(&el.opening_element.name);
            return parent_tag == "InputGroup" || parent_tag.ends_with(".InputGroup");
        }
    }
    false
}

fn is_transient_or_standard_dom_prop(prop_name: &str) -> bool {
    if prop_name.starts_with('$')
        || prop_name.starts_with("data-")
        || prop_name.starts_with("aria-")
    {
        return true;
    }
    if prop_name.starts_with("on")
        && prop_name
            .as_bytes()
            .get(2)
            .is_some_and(u8::is_ascii_uppercase)
    {
        return true;
    }
    STANDARD_DOM_OR_REACT_PROPS.contains(&prop_name)
}
