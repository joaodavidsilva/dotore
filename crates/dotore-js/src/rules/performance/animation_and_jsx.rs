//! JSX opening element, CSS/WAAPI/motion animation, and scroll/RAF loop performance rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, JSXAttributeItem, JSXAttributeName,
        JSXAttributeValue, JSXElementName, JSXMemberExpressionObject, LogicalOperator,
        ObjectPropertyKind,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    INDIVIDUAL_MOTION_TRANSFORM_PROPS, LAYOUT_PROPERTIES, MOTION_ANIMATE_PROPS, MemoStatus,
    extract_jsx_identifier_name,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::{is_global_ident, jsx_has_spread_attr, push_semantic_site, unwrap_expr},
    rules::RuleId,
};

pub(super) fn check_jsx_opening_performance_rules(
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

    check_motion_svg_wrapper(opening, is_motion, &subject_name, line_starts, out);
    check_jsx_css_and_motion_attributes(opening, is_motion, &subject_name, line_starts, out);
    check_prefer_stable_empty_fallback(
        opening,
        tag_ident,
        memo_registry,
        &subject_name,
        line_starts,
        out,
    );
    if tag_ident == Some("img") {
        check_jsx_img_attributes(opening, &subject_name, line_starts, out);
    }
    if tag_ident == Some("script") {
        check_jsx_script_attributes(opening, subject_name, line_starts, out);
    }
}

fn check_motion_svg_wrapper(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    is_motion: bool,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_motion
        || !matches!(&opening.name, JSXElementName::MemberExpression(mem) if mem.property.name == "svg")
    {
        return;
    }
    let has_animate_prop = opening.attributes.iter().any(|item| {
        if let JSXAttributeItem::Attribute(attr) = item
            && let JSXAttributeName::Identifier(id) = &attr.name
        {
            MOTION_ANIMATE_PROPS.contains(&id.name.as_str())
        } else {
            false
        }
    });
    if has_animate_prop {
        push_semantic_site(
            out,
            RuleId::RenderingAnimateSvgWrapper,
            subject_name.clone(),
            "renderingAnimateSvgWrapper",
            "motion.svg",
            "Animating an `<svg>` directly can bypass hardware-accelerated compositing; animate a wrapper `<div>` or `<span>` instead.".to_string(),
            line_starts,
            opening.span,
        );
    }
}

fn check_jsx_css_and_motion_attributes(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    is_motion: bool,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for attr_item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = attr_item else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_name) = &attr.name else {
            continue;
        };
        let name = attr_name.name.as_str();
        if name == "className" || name == "class" {
            check_jsx_class_attr_transitions(opening.span, attr, subject_name, line_starts, out);
        } else if name == "style" {
            check_jsx_style_attr_transitions(opening.span, attr, subject_name, line_starts, out);
        } else if MOTION_ANIMATE_PROPS.contains(&name) {
            check_motion_animate_attr(attr, name, is_motion, subject_name, line_starts, out);
        } else if is_motion && name == "transition" {
            check_motion_transition_attr(attr, subject_name, line_starts, out);
        }
    }
}

fn check_jsx_class_attr_transitions(
    opening_span: Span,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value else {
        return;
    };
    let Some(val) = s.value.as_str() else {
        return;
    };
    if val.split_whitespace().any(|t| {
        let u = t.rsplit(':').next().unwrap_or(t).trim_start_matches('!');
        u == "transition-all"
    }) {
        push_semantic_site(
            out,
            RuleId::NoTransitionAll,
            subject_name.clone(),
            "noTransitionAll",
            "transition-all",
            "Your users see janky animation because `transition-all` animates every property that changes, including expensive layout ones and instant ones like focus rings. Name the properties: `transition-colors`, `transition-opacity`, or `transition-transform`.".to_string(),
            line_starts,
            opening_span,
        );
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
        push_semantic_site(
            out,
            RuleId::NoPermanentWillChange,
            subject_name.clone(),
            "noPermanentWillChange",
            perm,
            format!(
                "This keeps {perm} active permanently, which can waste GPU memory. Apply the hint only immediately before the animation and remove it afterward."
            ),
            line_starts,
            attr.span,
        );
    }
}

fn check_jsx_style_attr_transitions(
    opening_span: Span,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return;
    };
    let Some(Expression::ObjectExpression(obj)) = cont.expression.as_expression().map(unwrap_expr)
    else {
        return;
    };
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
            push_semantic_site(
                out,
                RuleId::NoTransitionAll,
                subject_name.clone(),
                "noTransitionAll",
                &key_name,
                "This can stutter because transition: \"all\" animates every property, even slow layout ones, so list only the properties you actually change".to_string(),
                line_starts,
                opening_span,
            );
        }
        if key_name == "willChange" {
            let val = unwrap_expr(&prop.value);
            if !matches!(
                val,
                Expression::ConditionalExpression(_) | Expression::LogicalExpression(_)
            ) && !matches!(val, Expression::StringLiteral(s) if s.value.as_str().map(str::trim) == Some("scroll-position"))
            {
                push_semantic_site(
                    out,
                    RuleId::NoPermanentWillChange,
                    subject_name.clone(),
                    "noPermanentWillChange",
                    "willChange",
                    "This wastes GPU memory because will-change is left on all the time, so add it right before the animation & remove it when the animation ends".to_string(),
                    line_starts,
                    prop.span,
                );
            }
        }
    }
}

fn check_motion_animate_attr(
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    attr_name: &str,
    is_motion: bool,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return;
    };
    let Some(Expression::ObjectExpression(obj)) = cont.expression.as_expression().map(unwrap_expr)
    else {
        return;
    };
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
        check_single_motion_animate_prop(
            prop,
            &prop_name,
            attr_name,
            is_motion,
            subject_name,
            line_starts,
            out,
        );
    }
}

fn check_single_motion_animate_prop(
    prop: &oxc_ast::ast::ObjectProperty<'_>,
    prop_name: &str,
    attr_name: &str,
    is_motion: bool,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if is_motion && LAYOUT_PROPERTIES.contains(&prop_name) {
        push_semantic_site(
            out,
            RuleId::NoLayoutPropertyAnimation,
            subject_name.clone(),
            "noLayoutPropertyAnimation",
            prop_name,
            format!(
                "This stutters because animating \"{prop_name}\" makes the browser redo page layout every frame, so animate transform or scale instead, or use the layout prop"
            ),
            line_starts,
            prop.span,
        );
    }
    if matches!(
        prop_name,
        "filter" | "backdropFilter" | "WebkitBackdropFilter"
    ) && let Expression::StringLiteral(s) = unwrap_expr(&prop.value)
        && let Some(radius) = s.value.as_str().and_then(parse_blur_px)
        && radius > 10.0
    {
        push_semantic_site(
            out,
            RuleId::NoLargeAnimatedBlur,
            subject_name.clone(),
            "noLargeAnimatedBlur",
            prop_name,
            format!(
                "Large animated blurs can use significant GPU memory on phones because blur({radius}px) gets heavier as the blur and element grow. Use a smaller blur or a smaller element."
            ),
            line_starts,
            prop.span,
        );
    }
    if is_motion
        && attr_name != "initial"
        && INDIVIDUAL_MOTION_TRANSFORM_PROPS.contains(&prop_name)
    {
        push_semantic_site(
            out,
            RuleId::PreferMotionTransformProperty,
            subject_name.clone(),
            "preferMotionTransformProperty",
            prop_name,
            format!(
                "Motion's individual {prop_name} transform keys can keep this animation on the main thread. Use a single transform string when compositor acceleration is important."
            ),
            line_starts,
            prop.span,
        );
    }
    if is_motion
        && matches!(prop_name, "scale" | "scaleX" | "scaleY")
        && matches!(unwrap_expr(&prop.value), Expression::NumericLiteral(n) if n.value == 0.0)
    {
        push_semantic_site(
            out,
            RuleId::NoScaleFromZero,
            subject_name.clone(),
            "noScaleFromZero",
            prop_name,
            format!(
                "Animating `{prop_name}` from `0` makes elements pop out of nowhere; start from a subtle non-zero scale such as `0.95`."
            ),
            line_starts,
            prop.span,
        );
    }
}

fn check_motion_transition_attr(
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return;
    };
    let Some(Expression::ObjectExpression(obj)) = cont.expression.as_expression().map(unwrap_expr)
    else {
        return;
    };
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
            push_semantic_site(
                out,
                RuleId::NoExcessiveMotionStagger,
                subject_name.clone(),
                "noExcessiveMotionStagger",
                "staggerChildren",
                format!(
                    "This {}-second per-item stagger makes later children wait unnecessarily. Keep the interval at 0.08 seconds or less.",
                    n.value
                ),
                line_starts,
                prop.span,
            );
        }
    }
    if has_physics && let Some(dur_span) = duration_prop_span {
        push_semantic_site(
            out,
            RuleId::NoConflictingSpringOptions,
            subject_name.clone(),
            "noConflictingSpringOptions",
            "duration",
            "This spring mixes physics controls with duration-based controls, so Motion ignores duration and bounce. Keep only one spring configuration mode.".to_string(),
            line_starts,
            dur_span,
        );
    }
}

fn check_prefer_stable_empty_fallback(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    tag_ident: Option<&str>,
    memo_registry: &HashMap<String, MemoStatus>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some(comp_name) = tag_ident else {
        return;
    };
    if memo_registry.get(comp_name) != Some(&MemoStatus::Memoized) {
        return;
    }
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
        let Expression::LogicalExpression(log) = unwrap_expr(expr) else {
            continue;
        };
        if !matches!(
            log.operator,
            LogicalOperator::Or | LogicalOperator::Coalesce
        ) {
            continue;
        }
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
            push_semantic_site(
                out,
                RuleId::PreferStableEmptyFallback,
                subject_name.clone(),
                "preferStableEmptyFallback",
                attr_name.name.as_str(),
                format!(
                    "This redraws the memo child anyway because fallback `{lit}` builds a brand new {kind_str} each render when the left value is empty, so the child sees a different value. Hoist a constant (e.g. `{ex}`) & use that as the fallback."
                ),
                line_starts,
                right.span(),
            );
        }
    }
}

fn check_jsx_img_attributes(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let has_spread = jsx_has_spread_attr(&opening.attributes);
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
        push_semantic_site(
            out,
            RuleId::NoSrcsetWithoutSizes,
            subject_name.clone(),
            "noSrcsetWithoutSizes",
            "srcSet",
            "This responsive image supplies srcSet without sizes, so the browser assumes a 100vw slot and may download an unnecessarily large candidate. Describe its actual responsive width with sizes.".to_string(),
            line_starts,
            attr.span,
        );
    }

    if is_loading_lazy && is_fetch_priority_high {
        push_semantic_site(
            out,
            RuleId::NoImgLazyWithHighFetchpriority,
            subject_name.clone(),
            "noImgLazyWithHighFetchpriority",
            "img",
            "`<img loading=\"lazy\">` defers the request while `fetchPriority=\"high\"` asks the browser to rush it, so the two directives contradict each other. Drop one: keep `fetchPriority=\"high\"` (and eager loading) for an LCP image, or `loading=\"lazy\"` for a below-the-fold one.".to_string(),
            line_starts,
            opening.name.span(),
        );
    }
}

fn check_jsx_script_attributes(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: Option<String>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
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

    if has_src
        && !has_no_module
        && !has_defer_or_async
        && !is_non_blocking_or_bootstrap_script(src_val, type_val)
    {
        push_semantic_site(
            out,
            RuleId::RenderingScriptDeferAsync,
            subject_name,
            "renderingScriptDeferAsync",
            "script",
            "This blocks the page from loading until the script downloads because <script src> has no defer or async, so add defer for scripts that need the page, or async for standalone ones".to_string(),
            line_starts,
            opening.span,
        );
    }
}

fn is_non_blocking_or_bootstrap_script(src_val: Option<&str>, type_val: Option<&str>) -> bool {
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
    is_bootstrap || is_non_blocking_type
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
    let after = val.get(idx + "blur(".len()..)?;
    let px_idx = after.find("px)")?;
    after[..px_idx].trim().parse::<f64>().ok()
}

pub(super) fn check_unbounded_animation_frame_loop(
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
        push_semantic_site(
            out,
            RuleId::NoUnboundedAnimationFrameLoop,
            Some(name.to_string()),
            "noUnboundedAnimationFrameLoop",
            "requestAnimationFrame",
            "This callback schedules itself forever with no stop path and discards the active request ID. Add a stop condition and retain the ID for cancelAnimationFrame().".to_string(),
            line_starts,
            raf_span,
        );
    }
}

pub(super) fn check_no_unthrottled_scroll_mutation(
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
                push_semantic_site(
                    out,
                    RuleId::NoUnthrottledScrollMutation,
                    subject_name,
                    "noUnthrottledScrollMutation",
                    "scroll",
                    "This drives animation work from every scroll event, which can make scrolling jank. Use a scroll timeline, IntersectionObserver, or a real timer throttle.".to_string(),
                    line_starts,
                    assign.span,
                );
                return;
            }
        }
    }
}

pub(super) fn check_no_global_css_variable_animation(
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
        push_semantic_site(
            out,
            RuleId::NoGlobalCssVariableAnimation,
            subject_name,
            "noGlobalCssVariableAnimation",
            var_name,
            format!(
                "This forces every element using \"{var_name}\" to recompute its styles each frame because {callee_name} changes it every frame, so set it on just the element that needs it"
            ),
            line_starts,
            inner_call.span,
        );
    }
}

