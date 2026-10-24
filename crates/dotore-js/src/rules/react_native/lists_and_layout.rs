//! React Native host JSX element, `ScrollView`, `FlatList` / `FlashList` / `LegendList`,
//! and layout container rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        Expression, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement, JSXExpression,
        LogicalOperator, ObjectPropertyKind, Program,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    LIST_ROW_PRESS_PROPS, REACT_NATIVE_LIST_COMPONENTS, RENDER_ITEM_PROP_NAMES,
    SCROLL_CONTAINER_NAMES,
    animations_and_styles::{check_gesture_and_pressable_jsx_rules, check_style_object_shadows},
    find_jsx_attr, find_state_setter_in_attr, is_named_import_from, is_static_style_value,
    navigation_and_expo::check_bottom_sheet_jsx_rules,
};
use crate::{ir::types::SemanticRuleSite, matchers::push_semantic_site, rules::RuleId};

#[expect(
    clippy::too_many_arguments,
    reason = "Single-pass JSXElement visitor for all React Native JSX rules"
)]
pub(crate) fn check_rn_jsx_element_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let el_name = opening.name.span().source_text(source).trim();

    // 1. Style attribute legacy shadow check
    for attr_item in &opening.attributes {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        let attr_name = attr_id.name.as_str();
        if (attr_name == "style" || attr_name.ends_with("Style"))
            && let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value
            && let Some(expr) = container.expression.as_expression()
        {
            match expr.without_parentheses() {
                Expression::ObjectExpression(obj) => {
                    check_style_object_shadows(obj, subject_name, line_starts, sites);
                }
                Expression::ArrayExpression(arr) => {
                    for elem in &arr.elements {
                        if let Some(e) = elem.as_expression()
                            && let Expression::ObjectExpression(obj) = e.without_parentheses()
                        {
                            check_style_object_shadows(obj, subject_name, line_starts, sites);
                        }
                    }
                    if arr.elements.len() == 1
                        && !matches!(
                            &arr.elements[0],
                            oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)
                        )
                    {
                        push_semantic_site(
                            sites,
                            RuleId::RnNoSingleElementStyleArray,
                            subject_name.clone(),
                            "rnNoSingleElementStyleArray",
                            attr_name,
                            format!(
                                "Single-element style array `{attr_name}={{[...]}}` allocates an unnecessary array wrapper; pass the style value directly."
                            ),
                            line_starts,
                            attr.span,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // 2. `rn-no-falsy-and-render`: `{items.length && <Text>...}`
    for child in &jsx_el.children {
        if let JSXChild::ExpressionContainer(container) = child
            && let JSXExpression::LogicalExpression(logical) = &container.expression
            && logical.operator == LogicalOperator::And
            && is_likely_numeric_falsy_lhs(&logical.left, source)
        {
            push_semantic_site(
                sites,
                RuleId::RnNoFalsyAndRender,
                subject_name.clone(),
                "rnNoFalsyAndRender",
                logical.left.span().source_text(source),
                "If the left-hand side of `&&` evaluates to `0`, React Native renders a bare number outside `<Text>` and crashes.".to_string(),
                line_starts,
                logical.span,
            );
        }
    }

    // 3. `rn-no-image-children`
    if el_name == "Image"
        && is_named_import_from(program, "Image", "Image", "react-native")
        && jsx_el.children.iter().any(is_meaningful_jsx_child)
    {
        push_semantic_site(
            sites,
            RuleId::RnNoImageChildren,
            subject_name.clone(),
            "rnNoImageChildren",
            "Image",
            "React Native's <Image> does not render children, so this content silently disappears. Use <ImageBackground> to layer content over an image.".to_string(),
            line_starts,
            opening.span,
        );
    }

    // 4. `rn-bottom-sheet-*`
    check_bottom_sheet_jsx_rules(
        program,
        semantic,
        jsx_el,
        el_name,
        subject_name,
        source,
        line_starts,
        sites,
    );

    // 5. ScrollView & List rules
    check_scrollview_and_list_jsx_rules(
        program,
        semantic,
        jsx_el,
        el_name,
        subject_name,
        source,
        line_starts,
        sites,
    );

    // 6. `rn-prefer-pressable-over-gesture-detector` & `rn-pressable-shared-value-mutation`
    check_gesture_and_pressable_jsx_rules(
        semantic,
        jsx_el,
        el_name,
        subject_name,
        source,
        line_starts,
        sites,
    );

    // 7. `rn-prefer-content-inset-adjustment`
    if el_name == "SafeAreaView"
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::Element(child_el) = c {
                let child_name = child_el
                    .opening_element
                    .name
                    .span()
                    .source_text(source)
                    .trim();
                SCROLL_CONTAINER_NAMES.contains(&child_name)
            } else {
                false
            }
        })
    {
        push_semantic_site(
            sites,
            RuleId::RnPreferContentInsetAdjustment,
            subject_name.clone(),
            "rnPreferContentInsetAdjustment",
            "SafeAreaView",
            "Prefer `contentInsetAdjustmentBehavior=\"automatic\"` on the scrollable container instead of wrapping it in `<SafeAreaView>`.".to_string(),
            line_starts,
            opening.span,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates ScrollView and virtualized list JSX rules in one pass"
)]
pub(crate) fn check_scrollview_and_list_jsx_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    el_name: &str,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // `onScroll` state setter (`rn-no-scroll-state`)
    if let Some(on_scroll_attr) = find_jsx_attr(opening, "onScroll")
        && let Some(setter_span) = find_state_setter_in_attr(semantic, on_scroll_attr)
    {
        push_semantic_site(
            sites,
            RuleId::RnNoScrollState,
            subject_name.clone(),
            "rnNoScrollState",
            "onScroll",
            "Updating React state inside onScroll triggers a re-render on every scroll frame; use a Reanimated shared value or ref instead.".to_string(),
            line_starts,
            setter_span,
        );
    }

    // `ScrollView` mapped list (`rn-no-scrollview-mapped-list`)
    if el_name == "ScrollView" {
        for child in &jsx_el.children {
            if let JSXChild::ExpressionContainer(container) = child
                && let Some(expr) = container.expression.as_expression()
                && let Expression::CallExpression(call) = expr.without_parentheses()
                && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                && matches!(mem.property.name.as_str(), "map" | "flatMap")
                && !matches!(mem.object.without_parentheses(), Expression::ArrayExpression(arr) if arr.elements.len() <= 10)
            {
                push_semantic_site(
                    sites,
                    RuleId::RnNoScrollviewMappedList,
                    subject_name.clone(),
                    "rnNoScrollviewMappedList",
                    "ScrollView",
                    "Rendering a dynamic .map() list inside <ScrollView> mounts every item at once; use FlashList, LegendList, or FlatList instead.".to_string(),
                    line_starts,
                    call.span,
                );
            }
        }
    }

    // `contentContainerStyle` rules (`rn-scrollview-flex-in-content-container`, `rn-scrollview-dynamic-padding`)
    if SCROLL_CONTAINER_NAMES.contains(&el_name)
        && let Some(ccs_attr) = find_jsx_attr(opening, "contentContainerStyle")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &ccs_attr.value
        && let Some(expr) = container.expression.as_expression()
        && let Expression::ObjectExpression(ccs_obj) = expr.without_parentheses()
    {
        let has_explicit_flex_grow_or_basis = ccs_obj.properties.iter().any(|p| {
            let ObjectPropertyKind::ObjectProperty(prop) = p else {
                return false;
            };
            matches!(
                prop.key.static_name().as_ref().and_then(|n| n.as_str()),
                Some("flexGrow" | "flexBasis")
            )
        });

        for prop_kind in &ccs_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let key_name = prop.key.static_name();
            let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
                continue;
            };
            if k == "flex" && !has_explicit_flex_grow_or_basis {
                push_semantic_site(
                    sites,
                    RuleId::RnScrollviewFlexInContentContainer,
                    subject_name.clone(),
                    "rnScrollviewFlexInContentContainer",
                    "flex",
                    "Using `flex` on `contentContainerStyle` sets `flexBasis: 0` and clips scrolling when content overflows; use `flexGrow: 1` instead.".to_string(),
                    line_starts,
                    prop.span,
                );
            }
            if matches!(k, "paddingBottom" | "paddingTop")
                && !is_static_style_value(semantic, &prop.value)
            {
                push_semantic_site(
                    sites,
                    RuleId::RnScrollviewDynamicPadding,
                    subject_name.clone(),
                    "rnScrollviewDynamicPadding",
                    k,
                    format!(
                        "Dynamic `{k}` on `contentContainerStyle` relayouts the entire scroll content on every change; use `contentInset` instead."
                    ),
                    line_starts,
                    prop.span,
                );
            }
        }
    }

    // List component rules
    if !REACT_NATIVE_LIST_COMPONENTS.contains(&el_name) {
        return;
    }

    // `rn-list-data-mapped`
    if let Some(data_attr) = find_jsx_attr(opening, "data")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &data_attr.value
        && let Some(expr) = container.expression.as_expression()
        && is_fresh_array_data_expr(expr)
    {
        push_semantic_site(
            sites,
            RuleId::RnListDataMapped,
            subject_name.clone(),
            "rnListDataMapped",
            "data",
            format!(
                "Passing a fresh array expression to `data` on `<{el_name}>` invalidates row memoization on every render; wrap the derived array in `useMemo`."
            ),
            line_starts,
            data_attr.span,
        );
    }

    let is_recycler = matches!(
        el_name,
        "FlashList"
            | "AnimatedFlashList"
            | "LegendList"
            | "AnimatedLegendList"
            | "KeyboardAwareLegendList"
            | "KeyboardAvoidingLegendList"
    ) && (is_named_import_from(program, el_name, el_name, "@shopify/flash-list")
        || is_named_import_from(program, el_name, el_name, "@legendapp/list"));

    // `rn-list-missing-estimated-item-size`
    if is_recycler
        && find_jsx_attr(opening, "estimatedItemSize").is_none()
        && find_jsx_attr(opening, "estimatedListSize").is_none()
    {
        push_semantic_site(
            sites,
            RuleId::RnListMissingEstimatedItemSize,
            subject_name.clone(),
            "rnListMissingEstimatedItemSize",
            el_name,
            format!(
                "`<{el_name}>` is missing `estimatedItemSize`, which can cause blank cells to flash during fast scrolling."
            ),
            line_starts,
            opening.span,
        );
    }

    // `renderItem` rules
    for &prop_name in RENDER_ITEM_PROP_NAMES {
        let Some(render_attr) = find_jsx_attr(opening, prop_name) else {
            continue;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &render_attr.value else {
            continue;
        };
        let Some(expr) = container.expression.as_expression() else {
            continue;
        };
        let fn_expr = expr.without_parentheses();
        if !matches!(
            fn_expr,
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        ) {
            continue;
        }
        let fn_span = fn_expr.span();

        // 1. `rn-no-inline-flatlist-renderitem`
        if prop_name == "renderItem" {
            push_semantic_site(
                sites,
                RuleId::RnNoInlineFlatlistRenderitem,
                subject_name.clone(),
                "rnNoInlineFlatlistRenderitem",
                el_name,
                format!(
                    "Your users see extra row work when renderItem on <{el_name}> is rebuilt every time the screen redraws."
                ),
                line_starts,
                fn_span,
            );
        }

        // 2. `rn-list-recyclable-without-types`
        if is_recycler
            && prop_name == "renderItem"
            && find_jsx_attr(opening, "getItemType").is_none()
            && render_item_has_heterogeneous_roots(semantic, fn_span, source)
        {
            push_semantic_site(
                sites,
                RuleId::RnListRecyclableWithoutTypes,
                subject_name.clone(),
                "rnListRecyclableWithoutTypes",
                el_name,
                format!(
                    "`<{el_name}>` `renderItem` returns multiple root component types without `getItemType`, causing recycled views to mismatch."
                ),
                line_starts,
                render_attr.span,
            );
        }

        // Scan JSX elements inside `renderItem` for:
        // - `rn-list-callback-per-row`
        // - `rn-no-inline-object-in-list-item`
        // - `rn-no-renderitem-key`
        let mut reported_key = false;
        for (_, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::JSXOpeningElement(inner_open) = inner_node.kind() else {
                continue;
            };
            if !fn_span.contains_inclusive(inner_open.span) {
                continue;
            }
            for attr_item in &inner_open.attributes {
                let Some(attr) = attr_item.as_attribute() else {
                    continue;
                };
                let JSXAttributeName::Identifier(attr_id) = &attr.name else {
                    continue;
                };
                let k = attr_id.name.as_str();
                if k == "key" && !reported_key {
                    reported_key = true;
                    push_semantic_site(
                        sites,
                        RuleId::RnNoRenderitemKey,
                        subject_name.clone(),
                        "rnNoRenderitemKey",
                        "key",
                        "A `key` on the JSX returned from `renderItem` is ignored by React Native lists; use `keyExtractor` on the list instead.".to_string(),
                        line_starts,
                        attr.span,
                    );
                }
                if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
                    && let Some(val_expr) = c.expression.as_expression()
                {
                    let unwrapped = val_expr.without_parentheses();
                    if LIST_ROW_PRESS_PROPS.contains(&k)
                        && matches!(
                            unwrapped,
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        )
                    {
                        push_semantic_site(
                            sites,
                            RuleId::RnListCallbackPerRow,
                            subject_name.clone(),
                            "rnListCallbackPerRow",
                            k,
                            format!(
                                "Inline `{k}` closure inside `{prop_name}` allocates a new function for every row on every render."
                            ),
                            line_starts,
                            unwrapped.span(),
                        );
                    }
                    if matches!(unwrapped, Expression::ObjectExpression(_)) {
                        push_semantic_site(
                            sites,
                            RuleId::RnNoInlineObjectInListItem,
                            subject_name.clone(),
                            "rnNoInlineObjectInListItem",
                            k,
                            format!(
                                "Inline object literal on `{k}` inside `{prop_name}` allocates a new reference per row."
                            ),
                            line_starts,
                            unwrapped.span(),
                        );
                    }
                }
            }
        }
    }
}

fn is_fresh_array_data_expr(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => !arr.elements.is_empty(),
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                matches!(
                    mem.property.name.as_str(),
                    "map"
                        | "filter"
                        | "slice"
                        | "concat"
                        | "flat"
                        | "flatMap"
                        | "toSorted"
                        | "toReversed"
                        | "toSpliced"
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

fn render_item_has_heterogeneous_roots(
    semantic: &Semantic<'_>,
    fn_span: Span,
    source: &str,
) -> bool {
    let mut root_names: HashSet<String> = HashSet::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        if !fn_span.contains_inclusive(jsx_el.span) {
            continue;
        }
        // Only count top-level JSX elements inside `fn_span` (no ancestor JSXElement inside `fn_span`)
        let has_jsx_parent_in_fn = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            let anc_span = semantic.nodes().get_node(anc_id).span();
            fn_span.contains_inclusive(anc_span)
                && matches!(semantic.nodes().kind(anc_id), AstKind::JSXElement(_))
        });
        if has_jsx_parent_in_fn {
            continue;
        }
        let name = jsx_el
            .opening_element
            .name
            .span()
            .source_text(source)
            .trim()
            .to_string();
        root_names.insert(name);
    }
    root_names.len() >= 2
}

fn is_likely_numeric_falsy_lhs(expr: &Expression<'_>, source: &str) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            matches!(
                mem.property.name.as_str(),
                "length" | "size" | "count" | "total" | "index" | "width" | "height"
            )
        }
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            let lower = name.to_ascii_lowercase();
            (lower == "count"
                || lower.ends_with("count")
                || lower == "length"
                || lower.ends_with("length")
                || lower == "total"
                || lower == "index"
                || lower == "amount"
                || lower == "num")
                && !lower.starts_with("is")
                && !lower.starts_with("has")
                && !lower.starts_with("can")
                && !lower.starts_with("should")
        }
        _ => {
            let text = expr.span().source_text(source).trim();
            text.ends_with(".length") || text.ends_with(".size") || text.ends_with(".count")
        }
    }
}

fn is_meaningful_jsx_child(child: &JSXChild<'_>) -> bool {
    match child {
        JSXChild::Element(_) | JSXChild::Fragment(_) => true,
        JSXChild::Text(t) => !t.value.trim().is_empty(),
        JSXChild::ExpressionContainer(c) => !matches!(
            &c.expression,
            JSXExpression::EmptyExpression(_)
                | JSXExpression::NullLiteral(_)
                | JSXExpression::BooleanLiteral(_)
        ),
        JSXChild::Spread(_) => true,
    }
}
