//! React Native Reanimated 4, `StyleSheet`, `Dimensions`, `GestureDetector`/`Pressable`,
//! Detox, and layout animation rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, AssignmentTarget, CallExpression, Expression,
        JSXAttributeValue, JSXElement, ObjectExpression, ObjectPropertyKind, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{
    DETOX_ELEMENT_ACTIONS, LEGACY_SHADOW_PROPS, TOUCHABLE_COMPONENTS, find_jsx_attr,
    is_named_import_from,
};
use crate::{ir::types::SemanticRuleSite, matchers::push_semantic_site, rules::RuleId};

#[expect(
    clippy::too_many_arguments,
    reason = "Single-pass visitor for all React Native CallExpression rules (#50)"
)]
pub(crate) fn check_rn_call_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    is_detox_file: bool,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_rn_reanimated_and_identifier_calls(program, call, subject_name, source, line_starts, sites);
    check_rn_member_call_rules(call, subject_name, line_starts, sites);

    if is_detox_file
        && matches!(
            semantic.nodes().parent_kind(node_id),
            AstKind::ExpressionStatement(_)
        )
        && is_unawaited_detox_action(call, source)
    {
        push_semantic_site(
            sites,
            RuleId::RnDetoxMissingAwait,
            subject_name.clone(),
            "rnDetoxMissingAwait",
            "detox",
            "Detox actions and expectations return a Promise; prepend `await` so the test synchronizes properly.".to_string(),
            line_starts,
            call.span,
        );
    }

    check_rn_animate_layout_property(semantic, call, subject_name, line_starts, sites);
}

fn check_rn_reanimated_and_identifier_calls(
    program: &Program<'_>,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(id) = call.callee.without_parentheses() else {
        return;
    };
    let fn_name = id.name.as_str();
    if !is_named_import_from(program, fn_name, fn_name, "react-native-reanimated") {
        return;
    }

    if fn_name == "useAnimatedReaction"
        && let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression)
        && is_single_shared_value_copy(second_arg, source)
    {
        push_semantic_site(
            sites,
            RuleId::RnAnimationReactionAsDerived,
            subject_name.clone(),
            "rnAnimationReactionAsDerived",
            "useAnimatedReaction",
            "This useAnimatedReaction only copies one shared value into another, so it can miss Reanimated's derived-value dependency tracking.".to_string(),
            line_starts,
            call.span,
        );
    }

    if fn_name == "withSpring"
        && let Some(Argument::ObjectExpression(cfg_obj)) = call.arguments.get(1)
    {
        check_reanimated_spring_legacy_thresholds(cfg_obj, subject_name, line_starts, sites);
    }

    if matches!(
        fn_name,
        "useAnimatedGestureHandler"
            | "useWorkletCallback"
            | "combineTransition"
            | "addWhitelistedNativeProps"
            | "addWhitelistedUIProps"
    ) {
        push_semantic_site(
            sites,
            RuleId::RnReanimated4NoRemovedApi,
            subject_name.clone(),
            "rnReanimated4NoRemovedApi",
            fn_name,
            format!(
                "Reanimated 4 removed `{fn_name}`; migrate to the Gesture API or Reanimated 4 replacement."
            ),
            line_starts,
            call.span,
        );
    }

    if matches!(
        fn_name,
        "runOnUI" | "runOnJS" | "executeOnUIRuntimeSync" | "runOnRuntime"
    ) {
        push_semantic_site(
            sites,
            RuleId::RnReanimated4UseWorkletsScheduler,
            subject_name.clone(),
            "rnReanimated4UseWorkletsScheduler",
            fn_name,
            format!(
                "For Reanimated 4, import the worklet scheduler replacement for `{fn_name}` from `react-native-worklets`."
            ),
            line_starts,
            call.span,
        );
    }
}

fn check_reanimated_spring_legacy_thresholds(
    cfg_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &cfg_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let key_name = prop.key.static_name();
        let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        if matches!(k, "restDisplacementThreshold" | "restSpeedThreshold") {
            push_semantic_site(
                sites,
                RuleId::RnReanimated4NoLegacySpringThresholds,
                subject_name.clone(),
                "rnReanimated4NoLegacySpringThresholds",
                k,
                format!(
                    "Reanimated 4 removed `{k}`; use the `energyThreshold` spring option instead."
                ),
                line_starts,
                prop.span,
            );
        }
    }
}

fn check_rn_member_call_rules(
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let prop_name = mem.property.name.as_str();

    if prop_name == "setNativeProps" {
        push_semantic_site(
            sites,
            RuleId::RnNoSetNativeProps,
            subject_name.clone(),
            "rnNoSetNativeProps",
            "setNativeProps",
            "Imperative `setNativeProps` bypasses React state and the New Architecture; use declarative props or Reanimated shared values.".to_string(),
            line_starts,
            call.span,
        );
        return;
    }

    let Expression::Identifier(obj_id) = mem.object.without_parentheses() else {
        return;
    };

    if subject_name.is_some() && obj_id.name == "Dimensions" && prop_name == "get" {
        push_semantic_site(
            sites,
            RuleId::RnNoDimensionsGet,
            subject_name.clone(),
            "rnNoDimensionsGet",
            "Dimensions.get",
            "Dimensions.get() inside a component does not update when the window rotates or resizes; use useWindowDimensions() instead.".to_string(),
            line_starts,
            call.span,
        );
    } else if obj_id.name == "StyleSheet"
        && prop_name == "create"
        && let Some(Argument::ObjectExpression(styles_obj)) = call.arguments.first()
    {
        for prop_kind in &styles_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Expression::ObjectExpression(style_def) = prop.value.without_parentheses() else {
                continue;
            };
            check_style_object_shadows(style_def, subject_name, line_starts, sites);
        }
    }
}

fn is_single_shared_value_copy(reaction_fn: &Expression<'_>, _source: &str) -> bool {
    let single_expr = match reaction_fn.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                if body.statements.len() != 1 {
                    return false;
                }
                if let Statement::ExpressionStatement(es) = &body.statements[0] {
                    Some(es.expression.without_parentheses())
                } else {
                    None
                }
            }
            _ => arrow
                .body
                .as_expression()
                .map(Expression::without_parentheses),
        },
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            if body.statements.len() != 1 {
                return false;
            }
            if let Statement::ExpressionStatement(es) = &body.statements[0] {
                Some(es.expression.without_parentheses())
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(expr) = single_expr else {
        return false;
    };
    match expr {
        Expression::AssignmentExpression(assign) => {
            matches!(
                &assign.left,
                AssignmentTarget::StaticMemberExpression(mem)
                    if mem.property.name == "value"
                        && matches!(mem.object.without_parentheses(), Expression::Identifier(_))
            )
        }
        Expression::CallExpression(c) => {
            matches!(
                c.callee.without_parentheses(),
                Expression::StaticMemberExpression(mem)
                    if mem.property.name == "set" && c.arguments.len() == 1
            )
        }
        _ => false,
    }
}

fn check_rn_animate_layout_property(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    const RN_LAYOUT_PROPS: &[&str] = &[
        "width",
        "height",
        "top",
        "left",
        "right",
        "bottom",
        "padding",
        "paddingTop",
        "paddingBottom",
        "paddingLeft",
        "paddingRight",
        "paddingHorizontal",
        "paddingVertical",
        "margin",
        "marginTop",
        "marginBottom",
        "marginLeft",
        "marginRight",
        "marginHorizontal",
        "marginVertical",
        "flex",
        "flexGrow",
        "borderWidth",
        "gap",
    ];
    let is_use_animated_style = matches!(
        call.callee.without_parentheses(),
        Expression::Identifier(id) if id.name == "useAnimatedStyle"
    );
    if !is_use_animated_style {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb_span = first_arg.span();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::ObjectProperty(prop) = node.kind() else {
            continue;
        };
        let Some(key_name) = prop.key.static_name() else {
            continue;
        };
        let Some(k) = key_name.as_str() else {
            continue;
        };
        if RN_LAYOUT_PROPS.contains(&k) {
            push_semantic_site(
                sites,
                RuleId::RnAnimateLayoutProperty,
                subject_name.clone(),
                "rnAnimateLayoutProperty",
                k,
                format!(
                    "Animating layout property `{k}` inside `useAnimatedStyle` triggers Yoga layout recalculations on every frame; animate `transform` or `opacity` instead."
                ),
                line_starts,
                prop.span,
            );
        }
    }
}

fn is_unawaited_detox_action(call: &CallExpression<'_>, source: &str) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    let method = mem.property.name.as_str();
    let call_text = call.span.source_text(source).trim();
    if DETOX_ELEMENT_ACTIONS.contains(&method) && call_text.starts_with("element(") {
        return true;
    }
    if method == "withTimeout" && call_text.starts_with("waitFor(") {
        return true;
    }
    if (call_text.starts_with("expect(element(") || call_text.starts_with("expect(web("))
        && method.starts_with("to")
    {
        return true;
    }
    false
}

pub(crate) fn check_style_object_shadows(
    style_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut shadow_keys = Vec::new();
    for prop_kind in &style_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let key_name = prop.key.static_name();
        let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        if LEGACY_SHADOW_PROPS.contains(&k) {
            shadow_keys.push((k.to_string(), prop.span));
        }
    }

    if shadow_keys.is_empty() {
        return;
    }

    let quoted: Vec<String> = shadow_keys
        .iter()
        .map(|(k, _)| format!("\"{k}\""))
        .collect();
    push_semantic_site(
        sites,
        RuleId::RnNoLegacyShadowStyles,
        subject_name.clone(),
        "rnNoLegacyShadowStyles",
        &shadow_keys[0].0,
        format!(
            "Shadow style{} {} only work on one platform, so your users on the other see no shadow.",
            if shadow_keys.len() > 1 { "s" } else { "" },
            quoted.join(", ")
        ),
        line_starts,
        style_obj.span,
    );

    let first_span = shadow_keys[0].1;
    push_semantic_site(
        sites,
        RuleId::RnStylePreferBoxShadow,
        subject_name.clone(),
        "rnStylePreferBoxShadow",
        &shadow_keys[0].0,
        "Prefer the standard CSS `boxShadow` string over legacy platform-specific shadow properties.".to_string(),
        line_starts,
        first_span,
    );
}

pub(crate) fn check_gesture_and_pressable_jsx_rules(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    el_name: &str,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    if el_name == "GestureDetector"
        && let Some(gesture_attr) = find_jsx_attr(opening, "gesture")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &gesture_attr.value
        && let Some(expr) = container.expression.as_expression()
    {
        let gesture_text = resolve_gesture_expr_source(semantic, expr, source);
        if gesture_text.contains("Gesture.Tap()") && !gesture_text.contains("numberOfTaps(") {
            push_semantic_site(
                sites,
                RuleId::RnPreferPressableOverGestureDetector,
                subject_name.clone(),
                "rnPreferPressableOverGestureDetector",
                "GestureDetector",
                "Simple single-tap `Gesture.Tap()` inside `<GestureDetector>` adds native handler registration overhead; use `<Pressable>` instead.".to_string(),
                line_starts,
                opening.span,
            );
        }
    }

    if (el_name == "Pressable" || TOUCHABLE_COMPONENTS.contains(&el_name))
        && source.contains("useSharedValue(")
    {
        check_pressable_shared_value_mutation(opening, subject_name, source, line_starts, sites);
    }
}

fn resolve_gesture_expr_source<'a>(
    semantic: &Semantic<'a>,
    expr: &Expression<'a>,
    source: &'a str,
) -> &'a str {
    match expr.without_parentheses() {
        Expression::Identifier(ident) => ident
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .and_then(|s| {
                let decl_id = semantic.scoping().symbol_declaration(s);
                if let AstKind::VariableDeclarator(d) = semantic.nodes().kind(decl_id) {
                    d.init.as_ref().map(|i| i.span().source_text(source))
                } else {
                    None
                }
            })
            .unwrap_or_default(),
        other => other.span().source_text(source),
    }
}

fn check_pressable_shared_value_mutation(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_name in ["onPress", "onPressIn", "onPressOut", "onLongPress"] {
        let Some(attr) = find_jsx_attr(opening, prop_name) else {
            continue;
        };
        let attr_text = attr.span.source_text(source);
        if attr_text.contains(".value =") || attr_text.contains(".value=") {
            push_semantic_site(
                sites,
                RuleId::RnPressableSharedValueMutation,
                subject_name.clone(),
                "rnPressableSharedValueMutation",
                prop_name,
                "Mutating a Reanimated shared value inside a Pressable JS handler crosses the bridge on press; use GestureDetector + Gesture.Tap() on the UI thread.".to_string(),
                line_starts,
                attr.span,
            );
            break;
        }
    }
}
