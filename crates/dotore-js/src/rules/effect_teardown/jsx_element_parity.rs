//! JSX element, opening attribute, and JSX text lint parity rules for [`super`].
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JSX parity detectors match only relevant AST node kinds (#50)"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, Expression, JSXAttribute, JSXAttributeItem, JSXAttributeValue,
        JSXElement, JSXElementName, JSXOpeningElement, JSXText,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use crate::{
    ir::{SemanticRuleSite, react_ast::classify_jsx_element_name},
    matchers::span_to_byte_span,
    rules::types::{AutofixPatch, RuleId},
};

use super::{
    BOOLEAN_DOM_ATTRIBUTES, FORBIDDEN_DOM_PROPS, FORBIDDEN_ELEMENTS, INVALID_PARAGRAPH_CHILD_TAGS,
    NATIVE_LABEL_CONTROLS, VOID_DOM_TAGS, push_site, push_site_with_fix,
};

pub(super) fn check_jsx_element_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subj_name: &Option<String>,
    effectful_subject_names: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    if let JSXElementName::NamespacedName(ns) = &opening.name {
        let ns_text = ns.span.source_text(semantic.source_text());
        push_site(
            sites,
            RuleId::NoNamespace,
            subj_name.clone(),
            "noNamespace",
            ns_text,
            format!("Namespaced JSX element `<{ns_text}>` is not supported by React."),
            ns.span,
            line_starts,
            None,
        );
    }

    let (tag_name, _root_ident, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);

    if FORBIDDEN_ELEMENTS.contains(&tag_name.as_str()) {
        push_site(
            sites,
            RuleId::ForbidElements,
            subj_name.clone(),
            "forbidElements",
            &tag_name,
            format!(
                "Element `<{tag_name}>` is forbidden; use an approved semantic HTML or UI primitive instead."
            ),
            opening.span,
            line_starts,
            None,
        );
    }

    check_jsx_activity_and_label_subtree(
        semantic,
        jsx_el,
        &tag_name,
        subj_name,
        effectful_subject_names,
        line_starts,
        sites,
    );
    check_jsx_paragraph_and_void_dom(
        semantic,
        node_id,
        jsx_el,
        &tag_name,
        is_comp,
        subj_name,
        line_starts,
        sites,
    );
    check_jsx_opening_attributes(
        semantic,
        opening,
        &tag_name,
        is_comp,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_jsx_activity_and_label_subtree(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    tag_name: &str,
    subj_name: &Option<String>,
    effectful_subject_names: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    if matches!(tag_name, "Activity" | "unstable_Activity" | "Offscreen") {
        let wraps_effectful = semantic.nodes().iter_enumerated().any(|(_, n)| {
            jsx_el.span.contains_inclusive(n.span())
                && n.span() != jsx_el.span
                && matches!(
                    n.kind(),
                    AstKind::JSXOpeningElement(child_open)
                        if effectful_subject_names.contains(
                            &classify_jsx_element_name(semantic, &child_open.name).0
                        )
                )
        });
        if wraps_effectful {
            push_site(
                sites,
                RuleId::ActivityWrapsEffectHeavySubtree,
                subj_name.clone(),
                "activityWrapsEffectHeavySubtree",
                tag_name,
                format!("`<{tag_name}>` wraps an effect-heavy child subtree."),
                opening.span,
                line_starts,
                None,
            );
        }
    }

    if tag_name == "label" {
        let mut control_count = 0_usize;
        for (_, inner) in semantic.nodes().iter_enumerated() {
            if !jsx_el.span.contains_inclusive(inner.span()) || inner.span() == jsx_el.span {
                continue;
            }
            if let AstKind::JSXOpeningElement(child_open) = inner.kind() {
                let (child_tag, _, child_is_comp, _) =
                    classify_jsx_element_name(semantic, &child_open.name);
                if !child_is_comp && NATIVE_LABEL_CONTROLS.contains(&child_tag.as_str()) {
                    control_count += 1;
                }
            }
        }
        if control_count >= 2 {
            push_site(
                sites,
                RuleId::HtmlLabelHasSingleControl,
                subj_name.clone(),
                "htmlLabelHasSingleControl",
                "label",
                "`<label>` wraps multiple native form controls; associate each `<label>` with a single control.".to_string(),
                opening.span,
                line_starts,
                None,
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks paragraph child nesting and void DOM element children with autofix (#50)"
)]
fn check_jsx_paragraph_and_void_dom(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_comp {
        return;
    }
    let opening = &jsx_el.opening_element;

    if INVALID_PARAGRAPH_CHILD_TAGS.contains(&tag_name)
        && has_enclosing_html_paragraph(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::HtmlNoInvalidParagraphChild,
            subj_name.clone(),
            "htmlNoInvalidParagraphChild",
            tag_name,
            format!("Block element `<{tag_name}>` cannot be nested inside `<p>`."),
            opening.span,
            line_starts,
            None,
        );
    }

    if VOID_DOM_TAGS.contains(&tag_name) {
        check_void_dom_element_children(semantic, jsx_el, tag_name, subj_name, line_starts, sites);
    }
}

fn has_enclosing_html_paragraph(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(anc_el) = semantic.nodes().kind(anc_id) {
            let (anc_tag, _, anc_is_comp, _) =
                classify_jsx_element_name(semantic, &anc_el.opening_element.name);
            if !anc_is_comp && anc_tag == "svg" {
                return false;
            }
            if !anc_is_comp && anc_tag == "p" {
                return true;
            }
        }
    }
    false
}

fn check_void_dom_element_children(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    tag_name: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let has_children_attr = opening.attributes.iter().any(|item| {
        matches!(
            item,
            JSXAttributeItem::Attribute(attr)
                if attr.name.as_identifier().is_some_and(|id| {
                    matches!(id.name.as_str(), "children" | "dangerouslySetInnerHTML")
                })
        )
    });
    if jsx_el.children.is_empty() && !has_children_attr {
        return;
    }
    let kept_attrs: Vec<&str> = opening
        .attributes
        .iter()
        .filter(|item| {
            !matches!(
                item,
                JSXAttributeItem::Attribute(attr)
                    if attr.name.as_identifier().is_some_and(|id| {
                        matches!(id.name.as_str(), "children" | "dangerouslySetInnerHTML")
                    })
            )
        })
        .map(|item| item.span().source_text(semantic.source_text()).trim())
        .collect();
    let replacement = if kept_attrs.is_empty() {
        format!("<{tag_name} />")
    } else {
        format!("<{tag_name} {} />", kept_attrs.join(" "))
    };
    let autofix = Some(AutofixPatch::replace(
        format!("Remove children from void element `<{tag_name} />`"),
        span_to_byte_span(jsx_el.span),
        replacement,
    ));
    push_site_with_fix(
        sites,
        RuleId::VoidDomElementsNoChildren,
        subj_name.clone(),
        "voidDomElementsNoChildren",
        tag_name,
        format!("Void DOM element `<{tag_name}>` cannot have children."),
        jsx_el.span,
        line_starts,
        autofix,
    );
}

fn check_jsx_opening_attributes(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen_attr_names: HashSet<String> = HashSet::new();
    let mut spread_count = 0_usize;
    let mut has_set_pointer_capture = false;
    let mut has_pointer_cancel = false;

    for item in &opening.attributes {
        match item {
            JSXAttributeItem::SpreadAttribute(spread) => {
                spread_count += 1;
                if spread_count >= 2 {
                    push_site(
                        sites,
                        RuleId::JsxPropsNoSpreadMulti,
                        subj_name.clone(),
                        "jsxPropsNoSpreadMulti",
                        tag_name,
                        format!(
                            "Multiple prop spreads on `<{tag_name}>` can silently clobber earlier props."
                        ),
                        spread.span,
                        line_starts,
                        None,
                    );
                }
            }
            JSXAttributeItem::Attribute(attr) => {
                let Some(attr_ident) = attr.name.as_identifier() else {
                    continue;
                };
                let attr_name = attr_ident.name.as_str();
                if !seen_attr_names.insert(attr_name.to_string()) {
                    push_site(
                        sites,
                        RuleId::JsxNoDuplicateProps,
                        subj_name.clone(),
                        "jsxNoDuplicateProps",
                        attr_name,
                        format!("Duplicate prop `{attr_name}` on `<{tag_name}>`."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }
                check_single_jsx_attribute_parity(
                    semantic,
                    attr,
                    attr_name,
                    tag_name,
                    is_comp,
                    subj_name,
                    &mut has_set_pointer_capture,
                    &mut has_pointer_cancel,
                    line_starts,
                    sites,
                );
            }
        }
    }

    if has_set_pointer_capture && !has_pointer_cancel {
        push_site(
            sites,
            RuleId::PointerCaptureNeedsCancelHandler,
            subj_name.clone(),
            "pointerCaptureNeedsCancelHandler",
            tag_name,
            format!(
                "`<{tag_name}>` calls `setPointerCapture` in `onPointerDown` without an `onPointerCancel` or `onLostPointerCapture` handler."
            ),
            opening.span,
            line_starts,
            None,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates a single JSX attribute across forbidden, boolean, srcset, SVG precision, and ref rules (#50)"
)]
fn check_single_jsx_attribute_parity(
    semantic: &Semantic<'_>,
    attr: &JSXAttribute<'_>,
    attr_name: &str,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    has_set_pointer_capture: &mut bool,
    has_pointer_cancel: &mut bool,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_forbidden_and_boolean_jsx_attr(
        attr,
        attr_name,
        tag_name,
        is_comp,
        subj_name,
        line_starts,
        sites,
    );
    check_media_svg_and_ref_jsx_attr(
        semantic,
        attr,
        attr_name,
        tag_name,
        is_comp,
        subj_name,
        line_starts,
        sites,
    );

    if matches!(attr_name, "onPointerCancel" | "onLostPointerCapture") {
        *has_pointer_cancel = true;
    }
    if attr_name == "onPointerDown"
        && attr
            .span
            .source_text(semantic.source_text())
            .contains("setPointerCapture(")
    {
        *has_set_pointer_capture = true;
    }
}

fn check_forbidden_and_boolean_jsx_attr(
    attr: &JSXAttribute<'_>,
    attr_name: &str,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_comp && matches!(attr_name, "className" | "style") {
        push_site(
            sites,
            RuleId::ForbidComponentProps,
            subj_name.clone(),
            "forbidComponentProps",
            attr_name,
            format!("Prop `{attr_name}` is forbidden on custom component `<{tag_name}>`."),
            attr.span,
            line_starts,
            None,
        );
    }
    if !is_comp && FORBIDDEN_DOM_PROPS.contains(&attr_name) {
        push_site(
            sites,
            RuleId::ForbidDomProps,
            subj_name.clone(),
            "forbidDomProps",
            attr_name,
            format!("DOM prop `{attr_name}` is forbidden on `<{tag_name}>`."),
            attr.span,
            line_starts,
            None,
        );
    }
    if attr_name == "children" {
        push_site(
            sites,
            RuleId::NoChildrenProp,
            subj_name.clone(),
            "noChildrenProp",
            "children",
            format!(
                "Pass children as nested elements between `<{tag_name}>...</{tag_name}>` instead of a `children` prop."
            ),
            attr.span,
            line_starts,
            None,
        );
    }
    if !is_comp && tag_name == "input" && attr_name == "indeterminate" {
        push_site(
            sites,
            RuleId::NoIndeterminateAttribute,
            subj_name.clone(),
            "noIndeterminateAttribute",
            "indeterminate",
            "HTML `<input>` has no `indeterminate` attribute; assign `el.indeterminate = true` via a ref instead.".to_string(),
            attr.span,
            line_starts,
            None,
        );
    }
    if !is_comp
        && BOOLEAN_DOM_ATTRIBUTES.contains(&attr_name)
        && let Some((bool_val, val_span)) = extract_string_boolean_attr_value(attr)
    {
        let autofix = Some(AutofixPatch::replace(
            format!(
                "Replace string `{attr_name}=\"{bool_val}\"` with boolean `{attr_name}={{{bool_val}}}`"
            ),
            span_to_byte_span(val_span),
            format!("{{{bool_val}}}"),
        ));
        push_site_with_fix(
            sites,
            RuleId::NoStringFalseOnBooleanAttribute,
            subj_name.clone(),
            "noStringFalseOnBooleanAttribute",
            attr_name,
            format!(
                "Boolean attribute `{attr_name}` on `<{tag_name}>` is given string `\"{bool_val}\"` instead of `{{{bool_val}}}`."
            ),
            attr.span,
            line_starts,
            autofix,
        );
    }
}

fn extract_string_boolean_attr_value<'a>(
    attr: &'a JSXAttribute<'a>,
) -> Option<(&'a str, oxc_span::Span)> {
    match &attr.value {
        Some(JSXAttributeValue::StringLiteral(s))
            if matches!(s.value.as_str(), Some("false" | "true")) =>
        {
            s.value.as_str().map(|v| (v, s.span))
        }
        Some(JSXAttributeValue::ExpressionContainer(c)) => {
            if let Some(Expression::StringLiteral(s)) = c
                .expression
                .as_expression()
                .map(Expression::without_parentheses)
                && matches!(s.value.as_str(), Some("false" | "true"))
            {
                s.value.as_str().map(|v| (v, c.span))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn check_media_svg_and_ref_jsx_attr(
    semantic: &Semantic<'_>,
    attr: &JSXAttribute<'_>,
    attr_name: &str,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(attr_name, "srcSet" | "srcset")
        && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
        && let Some(val_str) = s.value.as_str()
        && has_mixed_srcset_descriptors(val_str)
    {
        push_site(
            sites,
            RuleId::NoMixedSrcsetDescriptors,
            subj_name.clone(),
            "noMixedSrcsetDescriptors",
            attr_name,
            "`srcSet` mixes width (`w`) and density (`x`) descriptors in the same attribute."
                .to_string(),
            attr.span,
            line_starts,
            None,
        );
    }

    if matches!(attr_name, "d" | "points" | "transform")
        && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
        && let Some(val_str) = s.value.as_str()
        && let Some(rounded) = round_svg_precision_string(val_str)
    {
        let autofix = Some(AutofixPatch::replace(
            format!("Round `{attr_name}` coordinates to at most 2 decimal places"),
            span_to_byte_span(s.span),
            format!("\"{rounded}\""),
        ));
        push_site_with_fix(
            sites,
            RuleId::RenderingSvgPrecision,
            subj_name.clone(),
            "renderingSvgPrecision",
            attr_name,
            format!(
                "SVG `{attr_name}` attribute contains coordinates with more than 2 decimal places."
            ),
            attr.span,
            line_starts,
            autofix,
        );
    }

    if is_comp
        && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
        && matches!(
            expr.without_parentheses(),
            Expression::JSXElement(_) | Expression::JSXFragment(_)
        )
    {
        push_site(
            sites,
            RuleId::JsxNoJsxAsProp,
            subj_name.clone(),
            "jsxNoJsxAsProp",
            attr_name,
            format!(
                "JSX element passed inline to prop `{attr_name}` on `<{tag_name}>` creates a new element on every render."
            ),
            attr.span,
            line_starts,
            None,
        );
    }

    if attr_name == "ref"
        && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
        && ref_callback_returns_cleanup_fn(semantic, expr.without_parentheses())
    {
        push_site(
            sites,
            RuleId::NoRefCallbackCleanupBeforeReact19,
            subj_name.clone(),
            "noRefCallbackCleanupBeforeReact19",
            "ref",
            "Returning a cleanup function from a `ref` callback requires React 19+.".to_string(),
            attr.span,
            line_starts,
            None,
        );
    }
}

fn has_mixed_srcset_descriptors(value: &str) -> bool {
    let mut has_w = false;
    let mut has_x = false;
    for candidate in value.split(',') {
        let Some(desc) = candidate.split_whitespace().nth(1) else {
            continue;
        };
        if desc.ends_with('w') && desc[..desc.len() - 1].chars().all(|c| c.is_ascii_digit()) {
            has_w = true;
        } else if desc.ends_with('x')
            && desc[..desc.len() - 1]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
        {
            has_x = true;
        }
    }
    has_w && has_x
}

fn round_svg_precision_string(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let int_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'.' {
                i += 1;
                let frac_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let frac_len = i - frac_start;
                let num_slice = &input[int_start..i];
                if frac_len > 2
                    && let Ok(val) = num_slice.parse::<f64>()
                {
                    changed = true;
                    let formatted = format!("{val:.2}");
                    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
                    out.push_str(trimmed);
                    continue;
                }
                out.push_str(num_slice);
            } else {
                out.push_str(&input[int_start..i]);
            }
        } else {
            let ch = input[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }

    changed.then_some(out)
}

fn ref_callback_returns_cleanup_fn(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    let fn_span = match expr {
        Expression::ArrowFunctionExpression(arr) => match &arr.body {
            ArrowFunctionBody::FunctionBody(body) => body.span,
            ArrowFunctionBody::ArrowFunctionExpression(_)
            | ArrowFunctionBody::FunctionExpression(_) => return true,
            _ => return false,
        },
        Expression::FunctionExpression(f) => {
            let Some(body) = &f.body else {
                return false;
            };
            body.span
        }
        _ => return false,
    };
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::ReturnStatement(ret) = node.kind()
            && let Some(arg) = &ret.argument
            && matches!(
                arg.without_parentheses(),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        {
            return true;
        }
    }
    false
}

pub(super) fn check_jsx_text_rules(
    jsx_text: &JSXText<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let raw = jsx_text.value.as_str();

    let has_comment_line = raw.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("//") || trimmed.starts_with("/*")
    });
    if has_comment_line {
        push_site(
            sites,
            RuleId::JsxNoCommentTextnodes,
            subj_name.clone(),
            "jsxNoCommentTextnodes",
            "comment",
            "Comment syntax inside JSX text will be rendered literally; wrap it in `{/* ... */}`."
                .to_string(),
            jsx_text.span,
            line_starts,
            None,
        );
    }

    if let Some(ch) = raw.chars().find(|&c| matches!(c, '\'' | '"' | '>' | '}')) {
        push_site(
            sites,
            RuleId::NoUnescapedEntities,
            subj_name.clone(),
            "noUnescapedEntities",
            ch.to_string(),
            format!(
                "Unescaped `{ch}` in JSX text; escape it with an HTML entity or JSX expression."
            ),
            jsx_text.span,
            line_starts,
            None,
        );
    }
}
