//! Extended card, surface, shadow, illustration, and interaction anti-pattern design rules.
use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{JSXChild, JSXElement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, get_style_prop_number, get_style_prop_str, subtree_has_tag_matching,
    },
    rules::RuleId,
};

use super::{
    LAYOUT_TRANSITION_PROPS, collect_all_static_text, is_tailwind_card_tokens,
    page_composition::check_page_root_design_rules, parse_tailwind_size_px, push_design_site,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates extended typography, surface, motion, and page-composition design rules in one pass"
)]
pub(super) fn check_extended_design_patterns(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    tokens: &[&str],
    unvariant_tokens: &[&str],
    trimmed_text: &str,
    font_size: Option<f64>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // `no-all-caps-body-text`
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption" | "td")
        && trimmed_text.len() >= 48
        && (unvariant_tokens.contains(&"uppercase")
            || get_style_prop_str(opening, "textTransform", semantic, const_strings).as_deref()
                == Some("uppercase"))
    {
        push_design_site(
            sites,
            RuleId::NoAllCapsBodyText,
            subject_name.clone(),
            "noAllCapsBodyText",
            tag,
            "Long body copy is set in all caps, reducing reading speed.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-arbitrary-px-font-size`
    if let Some(px_tok) = unvariant_tokens
        .iter()
        .find(|u| u.starts_with("text-[") && u.contains("px]") && !u.starts_with("text-[0px]"))
    {
        push_design_site(
            sites,
            RuleId::NoArbitraryPxFontSize,
            subject_name.clone(),
            "noArbitraryPxFontSize",
            px_tok,
            format!(
                "`{px_tok}` uses pixels instead of `rem` and ignores user font-size preferences."
            ),
            loc,
            span,
            None,
        );
    }

    // `no-auto-scrolling-content`
    if (tag.starts_with("motion.") || tag.starts_with("m."))
        && find_attr(&opening.attributes, "animate")
            .is_some_and(|a| a.span.source_text(semantic.source_text()).contains("x:"))
        && find_attr(&opening.attributes, "transition").is_some_and(|a| {
            a.span
                .source_text(semantic.source_text())
                .contains("Infinity")
        })
    {
        push_design_site(
            sites,
            RuleId::NoAutoScrollingContent,
            subject_name.clone(),
            "noAutoScrollingContent",
            tag,
            "Content auto-scrolls infinitely without a pause control.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-clipped-overlay`
    if unvariant_tokens.contains(&"absolute")
        && find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|r| matches!(r.as_str(), "dialog" | "listbox" | "menu" | "tooltip"))
        && has_ancestor_with_class(semantic, node_id, const_strings, |u| {
            matches!(u, "overflow-hidden" | "overflow-clip")
        })
    {
        push_design_site(
            sites,
            RuleId::NoClippedOverlay,
            subject_name.clone(),
            "noClippedOverlay",
            tag,
            "Positioned overlay sits inside an `overflow-hidden` ancestor and can be clipped."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-decorative-blur-orb`
    if matches!(tag, "div" | "span")
        && trimmed_text.is_empty()
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "absolute" | "fixed"))
        && unvariant_tokens.contains(&"rounded-full")
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "blur-2xl" | "blur-3xl") || u.starts_with("blur-["))
        && unvariant_tokens.iter().any(|u| u.starts_with("bg-"))
    {
        push_design_site(
            sites,
            RuleId::NoDecorativeBlurOrb,
            subject_name.clone(),
            "noDecorativeBlurOrb",
            tag,
            "Empty positioned blurred color circle acts as generic decorative scaffolding."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-empty-card-shell`
    if matches!(tag, "article" | "aside" | "section")
        && jsx_el.children.is_empty()
        && is_tailwind_card_tokens(unvariant_tokens)
    {
        push_design_site(
            sites,
            RuleId::NoEmptyCardShell,
            subject_name.clone(),
            "noEmptyCardShell",
            tag,
            "Empty semantic container renders a padded card shell without content.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-fixed-inside-transformed-ancestor`
    if (unvariant_tokens.contains(&"fixed")
        || get_style_prop_str(opening, "position", semantic, const_strings).as_deref()
            == Some("fixed"))
        && has_ancestor_with_class(semantic, node_id, const_strings, |u| {
            u.starts_with("scale-")
                || u.starts_with("translate-")
                || u.starts_with("rotate-")
                || u == "transform"
        })
    {
        push_design_site(
            sites,
            RuleId::NoFixedInsideTransformedAncestor,
            subject_name.clone(),
            "noFixedInsideTransformedAncestor",
            tag,
            "Fixed element sits inside a transformed ancestor and will not attach to the viewport."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-focus-in-animation-completion-handler`
    for handler_name in ["onAnimationEnd", "onTransitionEnd"] {
        if let Some(h_attr) = find_attr(&opening.attributes, handler_name)
            && h_attr
                .span
                .source_text(semantic.source_text())
                .contains(".focus(")
        {
            push_design_site(
                sites,
                RuleId::NoFocusInAnimationCompletionHandler,
                subject_name.clone(),
                "noFocusInAnimationCompletionHandler",
                handler_name,
                "Moving focus inside an animation completion handler fails when animations are disabled or canceled.".to_string(),
                loc_from_line_starts(line_starts, h_attr.span.start),
                ByteSpan {
                    start: h_attr.span.start,
                    end: h_attr.span.end,
                },
                None,
            );
        }
    }

    // `no-generic-purple-blue-icon-gradient`
    if unvariant_tokens.iter().any(|u| {
        u.starts_with("from-purple-")
            || u.starts_with("from-violet-")
            || u.starts_with("from-indigo-")
    }) && unvariant_tokens
        .iter()
        .any(|u| u.starts_with("to-blue-") || u.starts_with("to-cyan-") || u.starts_with("to-sky-"))
        && unvariant_tokens
            .iter()
            .any(|u| parse_tailwind_size_px(u).is_some_and(|px| px <= 64.0))
    {
        push_design_site(
            sites,
            RuleId::NoGenericPurpleBlueIconGradient,
            subject_name.clone(),
            "noGenericPurpleBlueIconGradient",
            tag,
            "Compact icon tile uses a generic purple-to-blue gradient.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-gray-on-colored-background`
    if unvariant_tokens.iter().any(|u| {
        u.starts_with("text-gray-") || u.starts_with("text-slate-") || u.starts_with("text-zinc-")
    }) && unvariant_tokens.iter().any(|u| {
        u.starts_with("bg-blue-")
            || u.starts_with("bg-indigo-")
            || u.starts_with("bg-purple-")
            || u.starts_with("bg-red-")
            || u.starts_with("bg-green-")
    }) {
        push_design_site(
            sites,
            RuleId::NoGrayOnColoredBackground,
            subject_name.clone(),
            "noGrayOnColoredBackground",
            tag,
            "Gray text on a saturated colored background looks washed out.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-hairline-border-wide-shadow` (Tailwind)
    if unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "border" | "border-1" | "border-px"))
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "shadow-xl" | "shadow-2xl"))
    {
        push_design_site(
            sites,
            RuleId::NoHairlineBorderWideShadow,
            subject_name.clone(),
            "noHairlineBorderWideShadow",
            tag,
            "Surface combines a hairline border with a wide diffuse shadow.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-image-hover-transform`
    if tag == "img"
        && tokens.iter().any(|t| {
            t.starts_with("hover:scale-")
                || t.starts_with("hover:rotate-")
                || t.starts_with("group-hover:scale-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoImageHoverTransform,
            subject_name.clone(),
            "noImageHoverTransform",
            "img",
            "Image scales or rotates on hover.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inert-pointer-affordance`
    if matches!(tag, "article" | "div" | "section" | "span" | "p")
        && unvariant_tokens.contains(&"cursor-pointer")
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
            subject_name.clone(),
            "noInertPointerAffordance",
            tag,
            "`cursor-pointer` is applied to a non-interactive element with no click handler."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inert-sticky-position`
    let is_sticky = unvariant_tokens.contains(&"sticky")
        || get_style_prop_str(opening, "position", semantic, const_strings).as_deref()
            == Some("sticky");
    let has_inset = unvariant_tokens.iter().any(|u| {
        (u.starts_with("top-")
            || u.starts_with("bottom-")
            || u.starts_with("left-")
            || u.starts_with("right-")
            || u.starts_with("inset-"))
            && !u.ends_with("-auto")
    }) || ["top", "bottom", "left", "right", "inset"].iter().any(|p| {
        get_style_prop_str(opening, p, semantic, const_strings).is_some()
            || get_style_prop_number(opening, p).is_some()
    });
    if is_sticky && !has_inset {
        push_design_site(
            sites,
            RuleId::NoInertStickyPosition,
            subject_name.clone(),
            "noInertStickyPosition",
            tag,
            "Sticky element has no `top`/`bottom`/`inset` offset and will not stick.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inline-bounce-easing` (Tailwind `animate-bounce`)
    if unvariant_tokens.contains(&"animate-bounce")
        && !unvariant_tokens.iter().any(|u| u.contains("delay"))
    {
        push_design_site(
            sites,
            RuleId::NoInlineBounceEasing,
            subject_name.clone(),
            "noInlineBounceEasing",
            tag,
            "`animate-bounce` uses bouncy easing; prefer smooth curves for UI elements."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-invisible-focus-control`
    if matches!(tag, "input" | "select" | "textarea" | "button")
        && unvariant_tokens.contains(&"opacity-0")
        && !tokens.iter().any(|t| {
            t.starts_with("focus:") || t.starts_with("focus-visible:") || t.starts_with("peer-")
        })
        && !has_ancestor_with_class(semantic, node_id, const_strings, |t| {
            t.starts_with("focus-within:")
        })
    {
        push_design_site(
            sites,
            RuleId::NoInvisibleFocusControl,
            subject_name.clone(),
            "noInvisibleFocusControl",
            tag,
            "Invisible native control (`opacity-0`) lacks a visible focus or `focus-within:` indicator.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-layout-shifting-interaction-state`
    if let Some(shift_tok) = tokens.iter().find(|t| {
        (t.starts_with("hover:") || t.starts_with("focus:") || t.starts_with("active:")) && {
            let u = t.rsplit(':').next().unwrap_or(t);
            u.starts_with("p-")
                || u.starts_with("px-")
                || u.starts_with("py-")
                || u.starts_with("m-")
                || u.starts_with("w-")
                || u.starts_with("h-")
        }
    }) {
        push_design_site(
            sites,
            RuleId::NoLayoutShiftingInteractionState,
            subject_name.clone(),
            "noLayoutShiftingInteractionState",
            shift_tok,
            format!("`{shift_tok}` changes layout geometry on interaction."),
            loc,
            span,
            None,
        );
    }

    // `no-nested-card-surface`
    if is_tailwind_card_tokens(unvariant_tokens)
        && unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && has_card_ancestor(semantic, node_id, const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoNestedCardSurface,
            subject_name.clone(),
            "noNestedCardSurface",
            tag,
            "Card surface is nested inside another card.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-overloaded-hover-state`
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
    if hover_groups.len() >= 3 {
        push_design_site(
            sites,
            RuleId::NoOverloadedHoverState,
            subject_name.clone(),
            "noOverloadedHoverState",
            tag,
            "Hover state stacks 3+ distinct visual effect groups.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-overwide-text-measure`
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption") {
        let overwide = unvariant_tokens.iter().any(|u| {
            u.strip_prefix("max-w-[")
                .or_else(|| u.strip_prefix("w-["))
                .and_then(|s| s.strip_suffix("ch]"))
                .and_then(|n| n.parse::<f64>().ok())
                .is_some_and(|ch| ch > 80.0)
        }) || ["maxWidth", "width"].iter().any(|p| {
            get_style_prop_str(opening, p, semantic, const_strings)
                .and_then(|s| {
                    s.trim()
                        .strip_suffix("ch")
                        .and_then(|n| n.parse::<f64>().ok())
                })
                .is_some_and(|ch| ch > 80.0)
        });
        if overwide {
            push_design_site(
                sites,
                RuleId::NoOverwideTextMeasure,
                subject_name.clone(),
                "noOverwideTextMeasure",
                tag,
                "Text measure exceeds 80ch; constrain long-form text to 60–75ch.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-pill-navigation-count`
    if matches!(tag, "span" | "small")
        && !trimmed_text.is_empty()
        && trimmed_text.bytes().all(|b| b.is_ascii_digit())
        && unvariant_tokens.contains(&"rounded-full")
        && unvariant_tokens.iter().any(|u| u.starts_with("px-"))
        && has_enclosing_nav_or_aside(semantic, node_id)
    {
        push_design_site(
            sites,
            RuleId::NoPillNavigationCount,
            subject_name.clone(),
            "noPillNavigationCount",
            tag,
            "Navigation count is styled as a pill badge instead of plain tabular text.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-pointer-disabled-enabled-control`
    if matches!(tag, "button" | "input" | "select" | "textarea" | "a")
        && (unvariant_tokens.contains(&"pointer-events-none")
            || get_style_prop_str(opening, "pointerEvents", semantic, const_strings).as_deref()
                == Some("none"))
        && find_jsx_attr_ignore_case(&opening.attributes, "disabled").is_none()
        && find_jsx_attr_ignore_case(&opening.attributes, "aria-disabled").is_none()
    {
        push_design_site(
            sites,
            RuleId::NoPointerDisabledEnabledControl,
            subject_name.clone(),
            "noPointerDisabledEnabledControl",
            tag,
            "Enabled control has `pointer-events-none` without `disabled` semantics.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-pure-black-shadow` (Tailwind)
    if unvariant_tokens
        .iter()
        .any(|u| *u == "shadow-black" || u.starts_with("shadow-black/"))
    {
        push_design_site(
            sites,
            RuleId::NoPureBlackShadow,
            subject_name.clone(),
            "noPureBlackShadow",
            tag,
            "Surface uses a pure-black shadow.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-redundant-title-tooltip`
    if matches!(tag, "button" | "a" | "summary")
        && !trimmed_text.is_empty()
        && let Some(title_attr) = find_jsx_attr_ignore_case(&opening.attributes, "title")
        && let Some(title_val) = get_attr_static_str(semantic, title_attr, const_strings)
        && title_val.trim().eq_ignore_ascii_case(trimmed_text)
        && !unvariant_tokens
            .iter()
            .any(|u| *u == "truncate" || *u == "text-ellipsis" || u.starts_with("line-clamp-"))
    {
        push_design_site(
            sites,
            RuleId::NoRedundantTitleTooltip,
            subject_name.clone(),
            "noRedundantTitleTooltip",
            "title",
            "Title tooltip repeats the control's visible text.".to_string(),
            loc_from_line_starts(line_starts, title_attr.span.start),
            ByteSpan {
                start: title_attr.span.start,
                end: title_attr.span.end,
            },
            None,
        );
    }

    // `no-svg-currentcolor-with-fill-class`
    if tag == "svg" {
        for paint in ["fill", "stroke"] {
            if let Some(p_attr) = find_attr(&opening.attributes, paint)
                && get_attr_static_str(semantic, p_attr, const_strings)
                    .is_some_and(|v| v.eq_ignore_ascii_case("currentColor"))
                && unvariant_tokens.iter().any(|u| {
                    u.starts_with(&format!("{paint}-"))
                        && *u != format!("{paint}-current")
                        && *u != format!("{paint}-none")
                })
            {
                push_design_site(
                    sites,
                    RuleId::NoSvgCurrentcolorWithFillClass,
                    subject_name.clone(),
                    "noSvgCurrentcolorWithFillClass",
                    paint,
                    format!(
                        "`{paint}=\"currentColor\"` conflicts with a `{paint}-*` color utility class."
                    ),
                    loc_from_line_starts(line_starts, p_attr.span.start),
                    ByteSpan {
                        start: p_attr.span.start,
                        end: p_attr.span.end,
                    },
                    None,
                );
            }
        }
    }

    // `no-symmetric-text-button-padding`
    if tag == "button"
        && !trimmed_text.is_empty()
        && unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && !unvariant_tokens.iter().any(|u| {
            u.starts_with("px-")
                || u.starts_with("py-")
                || u.starts_with("pl-")
                || u.starts_with("pr-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoSymmetricTextButtonPadding,
            subject_name.clone(),
            "noSymmetricTextButtonPadding",
            "button",
            "Text button uses equal padding on all sides; give horizontal axis more padding."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-tailwind-layout-transition`
    for &u in unvariant_tokens {
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
                subject_name.clone(),
                "noTailwindLayoutTransition",
                u,
                format!("`{u}` animates a layout property."),
                loc,
                span,
                None,
            );
        }
    }

    // `no-tight-all-caps-heading`, `no-tight-body-leading`, `no-tight-display-tracking`
    if matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        if trimmed_text.len() >= 24
            && unvariant_tokens.contains(&"uppercase")
            && unvariant_tokens.contains(&"leading-none")
        {
            push_design_site(
                sites,
                RuleId::NoTightAllCapsHeading,
                subject_name.clone(),
                "noTightAllCapsHeading",
                tag,
                "Long all-caps heading uses `leading-none`, risking line collisions.".to_string(),
                loc,
                span,
                None,
            );
        }
        if matches!(tag, "h1" | "h2" | "h3")
            && !trimmed_text.is_empty()
            && unvariant_tokens.contains(&"tracking-tighter")
        {
            push_design_site(
                sites,
                RuleId::NoTightDisplayTracking,
                subject_name.clone(),
                "noTightDisplayTracking",
                tag,
                "Display heading uses `tracking-tighter`.".to_string(),
                loc,
                span,
                None,
            );
        }
    }
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption" | "td")
        && trimmed_text.len() >= 48
        && (unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "leading-none" | "leading-tight"))
            || get_style_prop_number(opening, "lineHeight").is_some_and(|lh| lh > 0.0 && lh < 1.3))
    {
        push_design_site(
            sites,
            RuleId::NoTightBodyLeading,
            subject_name.clone(),
            "noTightBodyLeading",
            tag,
            "Body copy has cramped line-height (< 1.3).".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-tiny-uppercase-tracked-label`, `no-uppercase-mono-label`, `no-uppercase-tracked-navigation-label`
    if !trimmed_text.is_empty()
        && trimmed_text.len() <= 32
        && unvariant_tokens.contains(&"uppercase")
        && unvariant_tokens.iter().any(|u| u.starts_with("tracking-"))
    {
        if font_size.is_some_and(|px| px > 0.0 && px <= 11.0) {
            push_design_site(
                sites,
                RuleId::NoTinyUppercaseTrackedLabel,
                subject_name.clone(),
                "noTinyUppercaseTrackedLabel",
                tag,
                "Tiny label (<= 11px) combines uppercase and letter-spacing.".to_string(),
                loc,
                span,
                None,
            );
        }
        if unvariant_tokens.contains(&"font-mono") {
            push_design_site(
                sites,
                RuleId::NoUppercaseMonoLabel,
                subject_name.clone(),
                "noUppercaseMonoLabel",
                tag,
                "Short label combines `font-mono`, `uppercase`, and tracking.".to_string(),
                loc,
                span,
                None,
            );
        }
        if has_enclosing_nav_or_aside(semantic, node_id) {
            push_design_site(
                sites,
                RuleId::NoUppercaseTrackedNavigationLabel,
                subject_name.clone(),
                "noUppercaseTrackedNavigationLabel",
                tag,
                "Navigation label uses uppercase tracking.".to_string(),
                loc,
                span,
                None,
            );
        }
        kicker_candidates.push((loc, span));
    }

    // `no-transitioned-composite-widget-state` & `no-transitioned-focus-ring`
    if unvariant_tokens.contains(&"transition-colors")
        && tokens
            .iter()
            .any(|t| t.starts_with("aria-selected:") || t.starts_with("data-[state=active]:"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedCompositeWidgetState,
            subject_name.clone(),
            "noTransitionedCompositeWidgetState",
            tag,
            "Composite widget item delays selection color feedback with `transition-colors`."
                .to_string(),
            loc,
            span,
            None,
        );
    }
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "transition-shadow" | "transition-[box-shadow]" | "transition-[outline]"
        )
    }) && tokens
        .iter()
        .any(|t| t.starts_with("focus-visible:ring") || t.starts_with("focus-visible:outline"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedFocusRing,
            subject_name.clone(),
            "noTransitionedFocusRing",
            tag,
            "Transition utility delays the `focus-visible:` indicator.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-shape-assembled-illustration`
    if tag == "svg" {
        let mut shape_count = 0;
        count_svg_primitives(jsx_el, &mut shape_count);
        if shape_count >= 8 {
            push_design_site(
                sites,
                RuleId::NoShapeAssembledIllustration,
                subject_name.clone(),
                "noShapeAssembledIllustration",
                "svg",
                "Large SVG illustration is assembled from 8+ primitive shapes.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-repeated-placeholder-navigation`
    if matches!(tag, "nav" | "aside") {
        let mut placeholder_links = 0;
        count_placeholder_anchors(jsx_el, semantic, const_strings, &mut placeholder_links);
        if placeholder_links >= 2 {
            push_design_site(
                sites,
                RuleId::NoRepeatedPlaceholderNavigation,
                subject_name.clone(),
                "noRepeatedPlaceholderNavigation",
                tag,
                "Navigation contains multiple `<a href=\"#\">` placeholder links.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-fake-browser-chrome`
    if unvariant_tokens.contains(&"overflow-hidden")
        && unvariant_tokens.iter().any(|u| u.starts_with("rounded"))
        && unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && has_traffic_light_dots(jsx_el, semantic, const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoFakeBrowserChrome,
            subject_name.clone(),
            "noFakeBrowserChrome",
            tag,
            "Preview redraws decorative traffic-light browser chrome.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-uniform-feature-card-grid`
    if matches!(tag, "div" | "section") && unvariant_tokens.contains(&"grid") {
        let direct_cards: Vec<&JSXElement<'_>> = jsx_el
            .children
            .iter()
            .filter_map(|c| {
                if let JSXChild::Element(el) = c {
                    Some(el.as_ref())
                } else {
                    None
                }
            })
            .collect();
        if direct_cards.len() >= 3
            && direct_cards.iter().all(|card| {
                let c_str = get_class_name_str(&card.opening_element, semantic, const_strings)
                    .unwrap_or_default();
                let c_toks: Vec<&str> = c_str.split_whitespace().collect();
                is_tailwind_card_tokens(&c_toks)
                    && subtree_has_tag_matching(card, |t| matches!(t, "h2" | "h3" | "h4"))
                    && subtree_has_tag_matching(card, |t| t == "p")
            })
        {
            push_design_site(
                sites,
                RuleId::NoUniformFeatureCardGrid,
                subject_name.clone(),
                "noUniformFeatureCardGrid",
                tag,
                "Feature grid repeats the same rounded card-and-heading recipe across all items."
                    .to_string(),
                loc,
                span,
                None,
            );
        }
    }
    // `no-pure-black-background`
    let has_pure_black_bg = unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "bg-black" | "bg-[#000]" | "bg-[#000000]"))
        || ["backgroundColor", "background"].iter().any(|prop| {
            get_style_prop_str(opening, prop, semantic, const_strings).is_some_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "#000" | "#000000" | "black" | "rgb(0, 0, 0)" | "rgb(0,0,0)"
                )
            })
        });
    if has_pure_black_bg {
        push_design_site(
            sites,
            RuleId::NoPureBlackBackground,
            subject_name.clone(),
            "noPureBlackBackground",
            tag,
            "Surface uses a pure-black background; prefer a tinted dark neutral token.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-italic-serif-display-heading`
    if matches!(tag, "h1" | "h2") {
        let is_serif = unvariant_tokens.contains(&"font-serif")
            || get_style_prop_str(opening, "fontFamily", semantic, const_strings).is_some_and(
                |ff| {
                    ff.to_ascii_lowercase().contains("serif")
                        && !ff.to_ascii_lowercase().contains("sans-serif")
                },
            );
        let is_italic = unvariant_tokens.contains(&"italic")
            || get_style_prop_str(opening, "fontStyle", semantic, const_strings).as_deref()
                == Some("italic")
            || subtree_has_tag_matching(jsx_el, |t| matches!(t, "em" | "i"));
        if is_serif && is_italic {
            push_design_site(
                sites,
                RuleId::NoItalicSerifDisplayHeading,
                subject_name.clone(),
                "noItalicSerifDisplayHeading",
                tag,
                "Display heading combines italic and serif styling.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-full-viewport-centered-hero`
    if matches!(tag, "section" | "header" | "div")
        && unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "min-h-screen"
                    | "h-screen"
                    | "min-h-dvh"
                    | "h-dvh"
                    | "min-h-[100vh]"
                    | "h-[100vh]"
            )
        })
        && unvariant_tokens.contains(&"items-center")
        && unvariant_tokens.contains(&"justify-center")
        && (unvariant_tokens.contains(&"text-center")
            || has_descendant_text_center(jsx_el, semantic, const_strings))
        && subtree_has_tag_matching(jsx_el, |t| t == "h1")
    {
        push_design_site(
            sites,
            RuleId::NoFullViewportCenteredHero,
            subject_name.clone(),
            "noFullViewportCenteredHero",
            tag,
            "Hero uses a full-viewport centered template.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-hero-eyebrow-chip` & `no-numbered-section-markers` & `no-icon-tile-heading-stack`
    let direct_el_children: Vec<&JSXElement<'_>> = jsx_el
        .children
        .iter()
        .filter_map(|c| {
            if let JSXChild::Element(el) = c {
                Some(el.as_ref())
            } else {
                None
            }
        })
        .collect();
    if direct_el_children.len() >= 2 {
        let first_el = direct_el_children[0];
        let second_el = direct_el_children[1];
        let first_tag = get_jsx_tag_name(&first_el.opening_element.name);
        let second_tag = get_jsx_tag_name(&second_el.opening_element.name);
        let first_cls = get_class_name_str(&first_el.opening_element, semantic, const_strings)
            .unwrap_or_default();
        let first_toks: Vec<&str> = first_cls
            .split_whitespace()
            .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
            .collect();
        let first_txt = collect_all_static_text(first_el);
        let first_trimmed = first_txt.trim();

        if second_tag == "h1"
            && !first_trimmed.is_empty()
            && first_trimmed.len() <= 40
            && (first_toks.contains(&"rounded-full")
                || (first_toks.contains(&"uppercase")
                    && first_toks
                        .iter()
                        .any(|u| u.starts_with("border") || u.starts_with("bg-"))))
        {
            push_design_site(
                sites,
                RuleId::NoHeroEyebrowChip,
                subject_name.clone(),
                "noHeroEyebrowChip",
                &first_tag,
                "Hero places a decorative eyebrow chip above its primary heading.".to_string(),
                loc_from_line_starts(line_starts, first_el.opening_element.span.start),
                ByteSpan {
                    start: first_el.opening_element.span.start,
                    end: first_el.opening_element.span.end,
                },
                None,
            );
        }

        if matches!(second_tag.as_str(), "h2" | "h3")
            && is_numbered_section_marker_text(first_trimmed)
        {
            push_design_site(
                sites,
                RuleId::NoNumberedSectionMarkers,
                subject_name.clone(),
                "noNumberedSectionMarkers",
                &first_tag,
                "Section uses a decorative numeric marker before its heading.".to_string(),
                loc_from_line_starts(line_starts, first_el.opening_element.span.start),
                ByteSpan {
                    start: first_el.opening_element.span.start,
                    end: first_el.opening_element.span.end,
                },
                None,
            );
        }

        if is_tailwind_card_tokens(unvariant_tokens)
            && matches!(second_tag.as_str(), "h2" | "h3" | "h4")
            && is_icon_tile_element(first_el, &first_toks)
        {
            push_design_site(
                sites,
                RuleId::NoIconTileHeadingStack,
                subject_name.clone(),
                "noIconTileHeadingStack",
                tag,
                "Card stacks a boxed icon tile above its heading.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // Page-root checks on `<main>` or `<article>`
    if matches!(tag, "main" | "article") {
        check_page_root_design_rules(
            jsx_el,
            tag,
            trimmed_text,
            semantic,
            const_strings,
            subject_name,
            loc,
            span,
            line_starts,
            sites,
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

fn has_enclosing_nav_or_aside(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if matches!(tag.as_str(), "nav" | "aside") {
                return true;
            }
        }
    }
    false
}

fn count_svg_primitives(jsx_el: &JSXElement<'_>, count: &mut usize) {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if matches!(tag.as_str(), "rect" | "circle" | "ellipse" | "polygon") {
                *count += 1;
            }
            count_svg_primitives(el, count);
        }
    }
}

fn count_placeholder_anchors(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    count: &mut usize,
) {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if tag == "a"
                && find_attr(&el.opening_element.attributes, "href")
                    .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                    .as_deref()
                    == Some("#")
            {
                *count += 1;
            }
            count_placeholder_anchors(el, semantic, const_strings, count);
        }
    }
}

fn has_traffic_light_dots(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let mut has_red = false;
    let mut has_yellow = false;
    let mut has_green = false;
    check_traffic_lights_recursive(
        jsx_el,
        semantic,
        const_strings,
        &mut has_red,
        &mut has_yellow,
        &mut has_green,
    );
    has_red && has_yellow && has_green
}

fn check_traffic_lights_recursive(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    has_red: &mut bool,
    has_yellow: &mut bool,
    has_green: &mut bool,
) {
    if let Some(cls) = get_class_name_str(&jsx_el.opening_element, semantic, const_strings)
        && cls.contains("rounded-full")
    {
        if cls.contains("bg-red-") {
            *has_red = true;
        }
        if cls.contains("bg-yellow-") {
            *has_yellow = true;
        }
        if cls.contains("bg-green-") {
            *has_green = true;
        }
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            check_traffic_lights_recursive(
                el,
                semantic,
                const_strings,
                has_red,
                has_yellow,
                has_green,
            );
        }
    }
}

fn has_descendant_text_center(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            if get_class_name_str(&el.opening_element, semantic, const_strings)
                .is_some_and(|cls| cls.split_whitespace().any(|t| t.ends_with("text-center")))
            {
                return true;
            }
            if has_descendant_text_center(el, semantic, const_strings) {
                return true;
            }
        }
    }
    false
}

fn is_numbered_section_marker_text(s: &str) -> bool {
    let trimmed = s
        .trim()
        .trim_start_matches(['0', '#'])
        .trim_end_matches(['.', '/', '—', '-']);
    !s.is_empty()
        && s.len() <= 4
        && (s.starts_with('0') || s.starts_with('#') || s.ends_with('.'))
        && !trimmed.is_empty()
        && trimmed.bytes().all(|b| b.is_ascii_digit())
}

fn is_icon_tile_element(el: &JSXElement<'_>, unvariant_tokens: &[&str]) -> bool {
    let has_box = unvariant_tokens
        .iter()
        .any(|u| u.starts_with("rounded") || u.starts_with("bg-") || u.starts_with("border"));
    let has_compact_size = unvariant_tokens
        .iter()
        .any(|u| parse_tailwind_size_px(u).is_some_and(|px| px <= 64.0));
    let has_icon = subtree_has_tag_matching(el, |t| {
        t == "svg" || t.ends_with("Icon") || t.starts_with("Icon")
    });
    has_box && (has_compact_size || has_icon)
}
