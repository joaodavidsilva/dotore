//! Extended card, surface, shadow, overlay, pointer, sticky, and interaction anti-pattern design rules.
use std::collections::{HashMap, HashSet};

use oxc_ast::AstKind;
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_style_prop_number, get_style_prop_str,
    },
    rules::RuleId,
};

use super::{
    JsxDesignElemCtx, LAYOUT_TRANSITION_PROPS, is_tailwind_card_tokens,
    page_composition::check_page_root_design_rules, parse_tailwind_size_px, push_design_site,
    typography_and_hero_patterns::check_typography_svg_and_hero_patterns,
};

pub(super) fn check_extended_design_patterns(
    ctx: &JsxDesignElemCtx<'_, '_>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_overlay_and_surface_shells(ctx, sites);
    check_color_border_and_shadow_surfaces(ctx, sites);
    check_pointer_sticky_and_focus_interactions(ctx, sites);
    check_hover_and_transition_interactions(ctx, sites);
    check_typography_svg_and_hero_patterns(ctx, kicker_candidates, sites);

    if matches!(ctx.tag, "main" | "article") {
        check_page_root_design_rules(
            ctx.jsx_el,
            ctx.tag,
            ctx.trimmed_text,
            ctx.semantic,
            ctx.const_strings,
            ctx.subject_name,
            ctx.loc,
            ctx.span,
            ctx.line_starts,
            sites,
        );
    }
}

fn check_overlay_and_surface_shells(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_scroll_overlay_and_orb_shells(ctx, sites);
    check_empty_fixed_and_nested_card_shells(ctx, sites);
}

fn check_scroll_overlay_and_orb_shells(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = ctx.opening;
    if (ctx.tag.starts_with("motion.") || ctx.tag.starts_with("m."))
        && find_attr(&opening.attributes, "animate")
            .is_some_and(|a| a.span.source_text(ctx.semantic.source_text()).contains("x:"))
        && find_attr(&opening.attributes, "transition").is_some_and(|a| {
            a.span
                .source_text(ctx.semantic.source_text())
                .contains("Infinity")
        })
    {
        push_design_site(
            sites,
            RuleId::NoAutoScrollingContent,
            ctx.subject_name.clone(),
            "noAutoScrollingContent",
            ctx.tag,
            "Content auto-scrolls infinitely without a pause control.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.contains(&"absolute")
        && find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .is_some_and(|r| matches!(r.as_str(), "dialog" | "listbox" | "menu" | "tooltip"))
        && has_ancestor_with_class(ctx.semantic, ctx.node_id, ctx.const_strings, |u| {
            matches!(u, "overflow-hidden" | "overflow-clip")
        })
    {
        push_design_site(
            sites,
            RuleId::NoClippedOverlay,
            ctx.subject_name.clone(),
            "noClippedOverlay",
            ctx.tag,
            "Positioned overlay sits inside an `overflow-hidden` ancestor and can be clipped."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if is_decorative_blur_orb(ctx) {
        push_design_site(
            sites,
            RuleId::NoDecorativeBlurOrb,
            ctx.subject_name.clone(),
            "noDecorativeBlurOrb",
            ctx.tag,
            "Empty positioned blurred color circle acts as generic decorative scaffolding."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn is_decorative_blur_orb(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    matches!(ctx.tag, "div" | "span")
        && ctx.trimmed_text.is_empty()
        && ctx
            .unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "absolute" | "fixed"))
        && ctx.unvariant_tokens.contains(&"rounded-full")
        && ctx
            .unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "blur-2xl" | "blur-3xl") || u.starts_with("blur-["))
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("bg-"))
}

fn check_empty_fixed_and_nested_card_shells(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "article" | "aside" | "section")
        && ctx.jsx_el.children.is_empty()
        && is_tailwind_card_tokens(ctx.unvariant_tokens)
    {
        push_design_site(
            sites,
            RuleId::NoEmptyCardShell,
            ctx.subject_name.clone(),
            "noEmptyCardShell",
            ctx.tag,
            "Empty semantic container renders a padded card shell without content.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if (ctx.unvariant_tokens.contains(&"fixed")
        || get_style_prop_str(ctx.opening, "position", ctx.semantic, ctx.const_strings).as_deref()
            == Some("fixed"))
        && has_ancestor_with_class(ctx.semantic, ctx.node_id, ctx.const_strings, |u| {
            u.starts_with("scale-")
                || u.starts_with("translate-")
                || u.starts_with("rotate-")
                || u == "transform"
        })
    {
        push_design_site(
            sites,
            RuleId::NoFixedInsideTransformedAncestor,
            ctx.subject_name.clone(),
            "noFixedInsideTransformedAncestor",
            ctx.tag,
            "Fixed element sits inside a transformed ancestor and will not attach to the viewport."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if is_tailwind_card_tokens(ctx.unvariant_tokens)
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && has_card_ancestor(ctx.semantic, ctx.node_id, ctx.const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoNestedCardSurface,
            ctx.subject_name.clone(),
            "noNestedCardSurface",
            ctx.tag,
            "Card surface is nested inside another card.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_color_border_and_shadow_surfaces(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_gradient_and_gray_on_color(ctx, sites);
    check_border_shadow_and_black_surface(ctx, sites);
}

fn check_gradient_and_gray_on_color(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.unvariant_tokens.iter().any(|u| {
        u.starts_with("from-purple-")
            || u.starts_with("from-violet-")
            || u.starts_with("from-indigo-")
    }) && ctx.unvariant_tokens.iter().any(|u| {
        u.starts_with("to-blue-") || u.starts_with("to-cyan-") || u.starts_with("to-sky-")
    }) && ctx
        .unvariant_tokens
        .iter()
        .any(|u| parse_tailwind_size_px(u).is_some_and(|px| px <= 64.0))
    {
        push_design_site(
            sites,
            RuleId::NoGenericPurpleBlueIconGradient,
            ctx.subject_name.clone(),
            "noGenericPurpleBlueIconGradient",
            ctx.tag,
            "Compact icon tile uses a generic purple-to-blue gradient.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.iter().any(|u| {
        u.starts_with("text-gray-") || u.starts_with("text-slate-") || u.starts_with("text-zinc-")
    }) && ctx.unvariant_tokens.iter().any(|u| {
        u.starts_with("bg-blue-")
            || u.starts_with("bg-indigo-")
            || u.starts_with("bg-purple-")
            || u.starts_with("bg-red-")
            || u.starts_with("bg-green-")
    }) {
        push_design_site(
            sites,
            RuleId::NoGrayOnColoredBackground,
            ctx.subject_name.clone(),
            "noGrayOnColoredBackground",
            ctx.tag,
            "Gray text on a saturated colored background looks washed out.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_border_shadow_and_black_surface(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx
        .unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "border" | "border-1" | "border-px"))
        && ctx
            .unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "shadow-xl" | "shadow-2xl"))
    {
        push_design_site(
            sites,
            RuleId::NoHairlineBorderWideShadow,
            ctx.subject_name.clone(),
            "noHairlineBorderWideShadow",
            ctx.tag,
            "Surface combines a hairline border with a wide diffuse shadow.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx
        .unvariant_tokens
        .iter()
        .any(|u| *u == "shadow-black" || u.starts_with("shadow-black/"))
    {
        push_design_site(
            sites,
            RuleId::NoPureBlackShadow,
            ctx.subject_name.clone(),
            "noPureBlackShadow",
            ctx.tag,
            "Surface uses a pure-black shadow.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if has_pure_black_bg_surface(ctx) {
        push_design_site(
            sites,
            RuleId::NoPureBlackBackground,
            ctx.subject_name.clone(),
            "noPureBlackBackground",
            ctx.tag,
            "Surface uses a pure-black background; prefer a tinted dark neutral token.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn has_pure_black_bg_surface(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    ctx.unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "bg-black" | "bg-[#000]" | "bg-[#000000]"))
        || ["backgroundColor", "background"].iter().any(|prop| {
            get_style_prop_str(ctx.opening, prop, ctx.semantic, ctx.const_strings).is_some_and(
                |v| {
                    matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "#000" | "#000000" | "black" | "rgb(0, 0, 0)" | "rgb(0,0,0)"
                    )
                },
            )
        })
}

fn check_pointer_sticky_and_focus_interactions(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.opening.attributes.is_empty() || !ctx.tokens.is_empty() {
        check_anim_focus_and_inert_pointer(ctx, sites);
        check_sticky_and_focus_control_rules(ctx, sites);
    }
    check_tooltip_and_button_padding_rules(ctx, sites);
}

fn check_anim_focus_and_inert_pointer(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = ctx.opening;
    for handler_name in ["onAnimationEnd", "onTransitionEnd"] {
        if let Some(h_attr) = find_attr(&opening.attributes, handler_name)
            && h_attr
                .span
                .source_text(ctx.semantic.source_text())
                .contains(".focus(")
        {
            push_design_site(
                sites,
                RuleId::NoFocusInAnimationCompletionHandler,
                ctx.subject_name.clone(),
                "noFocusInAnimationCompletionHandler",
                handler_name,
                "Moving focus inside an animation completion handler fails when animations are disabled or canceled.".to_string(),
                loc_from_line_starts(ctx.line_starts, h_attr.span.start),
                ByteSpan {
                    start: h_attr.span.start,
                    end: h_attr.span.end,
                },
                None,
            );
        }
    }

    if matches!(ctx.tag, "article" | "div" | "section" | "span" | "p")
        && ctx.unvariant_tokens.contains(&"cursor-pointer")
        && !opening.attributes.iter().any(|item| {
            item.as_attribute()
                .and_then(|a| a.name.as_identifier())
                .is_some_and(|id| {
                    id.name.starts_with("on") || id.name == "role" || id.name == "tabIndex"
                })
        })
    {
        push_design_site(
            sites,
            RuleId::NoInertPointerAffordance,
            ctx.subject_name.clone(),
            "noInertPointerAffordance",
            ctx.tag,
            "`cursor-pointer` is applied to a non-interactive element with no click handler."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_sticky_and_focus_control_rules(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_inert_sticky_element(ctx) {
        push_design_site(
            sites,
            RuleId::NoInertStickyPosition,
            ctx.subject_name.clone(),
            "noInertStickyPosition",
            ctx.tag,
            "Sticky element has no `top`/`bottom`/`inset` offset and will not stick.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "input" | "select" | "textarea" | "button")
        && ctx.unvariant_tokens.contains(&"opacity-0")
        && !ctx.tokens.iter().any(|t| {
            t.starts_with("focus:") || t.starts_with("focus-visible:") || t.starts_with("peer-")
        })
        && !has_ancestor_with_class(ctx.semantic, ctx.node_id, ctx.const_strings, |t| {
            t.starts_with("focus-within:")
        })
    {
        push_design_site(
            sites,
            RuleId::NoInvisibleFocusControl,
            ctx.subject_name.clone(),
            "noInvisibleFocusControl",
            ctx.tag,
            "Invisible native control (`opacity-0`) lacks a visible focus or `focus-within:` indicator.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "button" | "input" | "select" | "textarea" | "a")
        && (ctx.unvariant_tokens.contains(&"pointer-events-none")
            || get_style_prop_str(
                ctx.opening,
                "pointerEvents",
                ctx.semantic,
                ctx.const_strings,
            )
            .as_deref()
                == Some("none"))
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "disabled").is_none()
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-disabled").is_none()
    {
        push_design_site(
            sites,
            RuleId::NoPointerDisabledEnabledControl,
            ctx.subject_name.clone(),
            "noPointerDisabledEnabledControl",
            ctx.tag,
            "Enabled control has `pointer-events-none` without `disabled` semantics.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn is_inert_sticky_element(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    let is_sticky = ctx.unvariant_tokens.contains(&"sticky")
        || get_style_prop_str(ctx.opening, "position", ctx.semantic, ctx.const_strings).as_deref()
            == Some("sticky");
    if !is_sticky {
        return false;
    }
    let has_inset = ctx.unvariant_tokens.iter().any(|u| {
        (u.starts_with("top-")
            || u.starts_with("bottom-")
            || u.starts_with("left-")
            || u.starts_with("right-")
            || u.starts_with("inset-"))
            && !u.ends_with("-auto")
    }) || ["top", "bottom", "left", "right", "inset"].iter().any(|p| {
        get_style_prop_str(ctx.opening, p, ctx.semantic, ctx.const_strings).is_some()
            || get_style_prop_number(ctx.opening, p).is_some()
    });
    !has_inset
}

fn check_tooltip_and_button_padding_rules(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "button" | "a" | "summary")
        && !ctx.trimmed_text.is_empty()
        && let Some(title_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "title")
        && let Some(title_val) = get_attr_static_str(ctx.semantic, title_attr, ctx.const_strings)
        && title_val.trim().eq_ignore_ascii_case(ctx.trimmed_text)
        && !ctx.unvariant_tokens.iter().any(|u| {
            *u == "truncate" || *u == "text-ellipsis" || u.starts_with("line-clamp-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoRedundantTitleTooltip,
            ctx.subject_name.clone(),
            "noRedundantTitleTooltip",
            "title",
            "Title tooltip repeats the control's visible text.".to_string(),
            loc_from_line_starts(ctx.line_starts, title_attr.span.start),
            ByteSpan {
                start: title_attr.span.start,
                end: title_attr.span.end,
            },
            None,
        );
    }

    if ctx.tag == "button"
        && !ctx.trimmed_text.is_empty()
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && !ctx.unvariant_tokens.iter().any(|u| {
            u.starts_with("px-")
                || u.starts_with("py-")
                || u.starts_with("pl-")
                || u.starts_with("pr-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoSymmetricTextButtonPadding,
            ctx.subject_name.clone(),
            "noSymmetricTextButtonPadding",
            "button",
            "Text button uses equal padding on all sides; give horizontal axis more padding."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_hover_and_transition_interactions(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "img"
        && ctx.tokens.iter().any(|t| {
            t.starts_with("hover:scale-")
                || t.starts_with("hover:rotate-")
                || t.starts_with("group-hover:scale-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoImageHoverTransform,
            ctx.subject_name.clone(),
            "noImageHoverTransform",
            "img",
            "Image scales or rotates on hover.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.contains(&"animate-bounce")
        && !ctx.unvariant_tokens.iter().any(|u| u.contains("delay"))
    {
        push_design_site(
            sites,
            RuleId::NoInlineBounceEasing,
            ctx.subject_name.clone(),
            "noInlineBounceEasing",
            ctx.tag,
            "`animate-bounce` uses bouncy easing; prefer smooth curves for UI elements."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if let Some(shift_tok) = find_layout_shifting_interaction_token(ctx.tokens) {
        push_design_site(
            sites,
            RuleId::NoLayoutShiftingInteractionState,
            ctx.subject_name.clone(),
            "noLayoutShiftingInteractionState",
            shift_tok,
            format!("`{shift_tok}` changes layout geometry on interaction."),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if count_distinct_hover_groups(ctx.tokens) >= 3 {
        push_design_site(
            sites,
            RuleId::NoOverloadedHoverState,
            ctx.subject_name.clone(),
            "noOverloadedHoverState",
            ctx.tag,
            "Hover state stacks 3+ distinct visual effect groups.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    check_tailwind_transition_rules(ctx, sites);
}

fn find_layout_shifting_interaction_token<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    tokens.iter().copied().find(|t| {
        (t.starts_with("hover:") || t.starts_with("focus:") || t.starts_with("active:")) && {
            let u = t.rsplit(':').next().unwrap_or(t);
            ["p-", "px-", "py-", "m-", "w-", "h-"]
                .iter()
                .any(|prefix| u.starts_with(prefix))
        }
    })
}

fn count_distinct_hover_groups(tokens: &[&str]) -> usize {
    let mut hover_groups: HashSet<&str> = HashSet::new();
    for &t in tokens {
        if let Some(u) = t.strip_prefix("hover:") {
            if u.starts_with("-translate") || u.starts_with("translate") || u.starts_with("scale") {
                hover_groups.insert("transform");
            } else if u.starts_with("bg-") || u.starts_with("text-") || u.starts_with("border-") {
                hover_groups.insert("color");
            } else if u.starts_with("shadow") {
                hover_groups.insert("shadow");
            }
        }
    }
    hover_groups.len()
}

fn check_tailwind_transition_rules(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for &u in ctx.unvariant_tokens {
        if let Some(inner) = u
            .strip_prefix("transition-[")
            .and_then(|s| s.strip_suffix(']'))
            && inner
                .split(',')
                .any(|p| LAYOUT_TRANSITION_PROPS.contains(&p.trim()))
        {
            push_design_site(
                sites,
                RuleId::NoTailwindLayoutTransition,
                ctx.subject_name.clone(),
                "noTailwindLayoutTransition",
                u,
                format!("`{u}` animates a layout property."),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if ctx.unvariant_tokens.contains(&"transition-colors")
        && ctx
            .tokens
            .iter()
            .any(|t| t.starts_with("aria-selected:") || t.starts_with("data-[state=active]:"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedCompositeWidgetState,
            ctx.subject_name.clone(),
            "noTransitionedCompositeWidgetState",
            ctx.tag,
            "Composite widget item delays selection color feedback with `transition-colors`."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "transition-shadow" | "transition-[box-shadow]" | "transition-[outline]"
        )
    }) && ctx
        .tokens
        .iter()
        .any(|t| t.starts_with("focus-visible:ring") || t.starts_with("focus-visible:outline"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedFocusRing,
            ctx.subject_name.clone(),
            "noTransitionedFocusRing",
            ctx.tag,
            "Transition utility delays the `focus-visible:` indicator.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn has_ancestor_with_class<F>(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
    pred: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
            && cls.split_whitespace().any(&pred)
        {
            return true;
        }
    }
    false
}

fn has_card_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
        {
            let toks: Vec<&str> = cls.split_whitespace().collect();
            if is_tailwind_card_tokens(&toks) {
                return true;
            }
        }
    }
    false
}
