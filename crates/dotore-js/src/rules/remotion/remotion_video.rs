//! Remotion (`remotion-*`) `<Video>`/`<Audio>`/`<Img>`, CSS animation/transition/`url()`,
//! `calculateMetadata`, `random()`, and `delayRender` rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use oxc_ast::{
    AstKind,
    ast::{
        Argument, BindingPattern, CallExpression, Expression, JSXAttributeItem, JSXAttributeValue,
        ObjectPropertyKind,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{
    FileImports, extract_callee_name, extract_jsx_class_name_str, extract_jsx_style_string_prop,
    find_jsx_attr, get_jsx_element_name, has_object_prop, is_in_direct_render_body,
    property_key_name, push_site,
};
use crate::{
    ir::{
        ByteSpan,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

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

pub(crate) fn check_remotion_jsx_opening(
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
            if val_text.contains("url(")
                && !val_text.contains("url(data:")
                && !val_text.contains("url(\"data:")
                && !val_text.contains("url('data:")
            {
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

pub(crate) fn check_remotion_call_expression(
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
            subject_name
                .clone()
                .or_else(|| Some("calculateMetadata".to_string())),
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
