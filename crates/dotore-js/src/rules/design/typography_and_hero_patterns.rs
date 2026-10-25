//! Extended typography, label, SVG/navigation chrome, and hero/section layout design rules.
use std::collections::HashMap;

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
        find_attr, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, get_style_prop_number, get_style_prop_str, subtree_has_tag_matching,
    },
    rules::RuleId,
};

use super::{
    JsxDesignElemCtx, collect_all_static_text, is_tailwind_card_tokens, parse_tailwind_size_px,
    push_design_site,
};

pub(super) fn check_typography_svg_and_hero_patterns(
    ctx: &JsxDesignElemCtx<'_, '_>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_extended_typography_and_labels(ctx, kicker_candidates, sites);
    check_heading_and_body_leading_tracking(ctx, sites);
    check_svg_nav_and_chrome_patterns(ctx, sites);
    check_hero_and_feature_grid_patterns(ctx, sites);
    check_hero_eyebrow_and_section_markers(ctx, sites);
}

fn check_extended_typography_and_labels(
    ctx: &JsxDesignElemCtx<'_, '_>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(
        ctx.tag,
        "p" | "blockquote" | "li" | "dd" | "figcaption" | "td"
    ) && ctx.trimmed_text.len() >= 48
        && (ctx.unvariant_tokens.contains(&"uppercase")
            || get_style_prop_str(
                ctx.opening,
                "textTransform",
                ctx.semantic,
                ctx.const_strings,
            )
            .as_deref()
                == Some("uppercase"))
    {
        push_design_site(
            sites,
            RuleId::NoAllCapsBodyText,
            ctx.subject_name.clone(),
            "noAllCapsBodyText",
            ctx.tag,
            "Long body copy is set in all caps, reducing reading speed.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if let Some(px_tok) = ctx.unvariant_tokens.iter().find(|u| {
        u.starts_with("text-[") && u.contains("px]") && !u.starts_with("text-[0px]")
    }) {
        push_design_site(
            sites,
            RuleId::NoArbitraryPxFontSize,
            ctx.subject_name.clone(),
            "noArbitraryPxFontSize",
            px_tok,
            format!(
                "`{px_tok}` uses pixels instead of `rem` and ignores user font-size preferences."
            ),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "p" | "blockquote" | "li" | "dd" | "figcaption")
        && is_overwide_text_measure(ctx)
    {
        push_design_site(
            sites,
            RuleId::NoOverwideTextMeasure,
            ctx.subject_name.clone(),
            "noOverwideTextMeasure",
            ctx.tag,
            "Text measure exceeds 80ch; constrain long-form text to 60–75ch.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "span" | "small")
        && !ctx.trimmed_text.is_empty()
        && ctx.trimmed_text.bytes().all(|b| b.is_ascii_digit())
        && ctx.unvariant_tokens.contains(&"rounded-full")
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("px-"))
        && has_enclosing_nav_or_aside(ctx.semantic, ctx.node_id)
    {
        push_design_site(
            sites,
            RuleId::NoPillNavigationCount,
            ctx.subject_name.clone(),
            "noPillNavigationCount",
            ctx.tag,
            "Navigation count is styled as a pill badge instead of plain tabular text.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    check_uppercase_tracked_short_labels(ctx, kicker_candidates, sites);
}

fn is_overwide_text_measure(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    ctx.unvariant_tokens.iter().any(|u| {
        u.strip_prefix("max-w-[")
            .or_else(|| u.strip_prefix("w-["))
            .and_then(|s| s.strip_suffix("ch]"))
            .and_then(|n| n.parse::<f64>().ok())
            .is_some_and(|ch| ch > 80.0)
    }) || ["maxWidth", "width"].iter().any(|p| {
        get_style_prop_str(ctx.opening, p, ctx.semantic, ctx.const_strings)
            .and_then(|s| {
                s.trim()
                    .strip_suffix("ch")
                    .and_then(|n| n.parse::<f64>().ok())
            })
            .is_some_and(|ch| ch > 80.0)
    })
}

fn check_uppercase_tracked_short_labels(
    ctx: &JsxDesignElemCtx<'_, '_>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.trimmed_text.is_empty()
        || ctx.trimmed_text.len() > 32
        || !ctx.unvariant_tokens.contains(&"uppercase")
        || !ctx
            .unvariant_tokens
            .iter()
            .any(|u| u.starts_with("tracking-"))
    {
        return;
    }

    if ctx.font_size.is_some_and(|px| px > 0.0 && px <= 11.0) {
        push_design_site(
            sites,
            RuleId::NoTinyUppercaseTrackedLabel,
            ctx.subject_name.clone(),
            "noTinyUppercaseTrackedLabel",
            ctx.tag,
            "Tiny label (<= 11px) combines uppercase and letter-spacing.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
    if ctx.unvariant_tokens.contains(&"font-mono") {
        push_design_site(
            sites,
            RuleId::NoUppercaseMonoLabel,
            ctx.subject_name.clone(),
            "noUppercaseMonoLabel",
            ctx.tag,
            "Short label combines `font-mono`, `uppercase`, and tracking.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
    if has_enclosing_nav_or_aside(ctx.semantic, ctx.node_id) {
        push_design_site(
            sites,
            RuleId::NoUppercaseTrackedNavigationLabel,
            ctx.subject_name.clone(),
            "noUppercaseTrackedNavigationLabel",
            ctx.tag,
            "Navigation label uses uppercase tracking.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
    kicker_candidates.push((ctx.loc, ctx.span));
}

fn check_heading_and_body_leading_tracking(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        if ctx.trimmed_text.len() >= 24
            && ctx.unvariant_tokens.contains(&"uppercase")
            && ctx.unvariant_tokens.contains(&"leading-none")
        {
            push_design_site(
                sites,
                RuleId::NoTightAllCapsHeading,
                ctx.subject_name.clone(),
                "noTightAllCapsHeading",
                ctx.tag,
                "Long all-caps heading uses `leading-none`, risking line collisions.".to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
        if matches!(ctx.tag, "h1" | "h2" | "h3")
            && !ctx.trimmed_text.is_empty()
            && ctx.unvariant_tokens.contains(&"tracking-tighter")
        {
            push_design_site(
                sites,
                RuleId::NoTightDisplayTracking,
                ctx.subject_name.clone(),
                "noTightDisplayTracking",
                ctx.tag,
                "Display heading uses `tracking-tighter`.".to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if matches!(
        ctx.tag,
        "p" | "blockquote" | "li" | "dd" | "figcaption" | "td"
    ) && ctx.trimmed_text.len() >= 48
        && (ctx
            .unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "leading-none" | "leading-tight"))
            || get_style_prop_number(ctx.opening, "lineHeight")
                .is_some_and(|lh| lh > 0.0 && lh < 1.3))
    {
        push_design_site(
            sites,
            RuleId::NoTightBodyLeading,
            ctx.subject_name.clone(),
            "noTightBodyLeading",
            ctx.tag,
            "Body copy has cramped line-height (< 1.3).".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "h1" | "h2") && is_italic_serif_heading(ctx) {
        push_design_site(
            sites,
            RuleId::NoItalicSerifDisplayHeading,
            ctx.subject_name.clone(),
            "noItalicSerifDisplayHeading",
            ctx.tag,
            "Display heading combines italic and serif styling.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn is_italic_serif_heading(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    let is_serif = ctx.unvariant_tokens.contains(&"font-serif")
        || get_style_prop_str(ctx.opening, "fontFamily", ctx.semantic, ctx.const_strings)
            .is_some_and(|ff| {
                let lower = ff.to_ascii_lowercase();
                lower.contains("serif") && !lower.contains("sans-serif")
            });
    let is_italic = ctx.unvariant_tokens.contains(&"italic")
        || get_style_prop_str(ctx.opening, "fontStyle", ctx.semantic, ctx.const_strings).as_deref()
            == Some("italic")
        || subtree_has_tag_matching(ctx.jsx_el, |t| matches!(t, "em" | "i"));
    is_serif && is_italic
}

fn check_svg_nav_and_chrome_patterns(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "svg" {
        for paint in ["fill", "stroke"] {
            if let Some(p_attr) = find_attr(&ctx.opening.attributes, paint)
                && get_attr_static_str(ctx.semantic, p_attr, ctx.const_strings)
                    .is_some_and(|v| v.eq_ignore_ascii_case("currentColor"))
                && ctx.unvariant_tokens.iter().any(|u| {
                    u.starts_with(&format!("{paint}-"))
                        && *u != format!("{paint}-current")
                        && *u != format!("{paint}-none")
                })
            {
                push_design_site(
                    sites,
                    RuleId::NoSvgCurrentcolorWithFillClass,
                    ctx.subject_name.clone(),
                    "noSvgCurrentcolorWithFillClass",
                    paint,
                    format!(
                        "`{paint}=\"currentColor\"` conflicts with a `{paint}-*` color utility class."
                    ),
                    loc_from_line_starts(ctx.line_starts, p_attr.span.start),
                    ByteSpan {
                        start: p_attr.span.start,
                        end: p_attr.span.end,
                    },
                    None,
                );
            }
        }

        let mut shape_count = 0;
        count_svg_primitives(ctx.jsx_el, &mut shape_count);
        if shape_count >= 8 {
            push_design_site(
                sites,
                RuleId::NoShapeAssembledIllustration,
                ctx.subject_name.clone(),
                "noShapeAssembledIllustration",
                "svg",
                "Large SVG illustration is assembled from 8+ primitive shapes.".to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if matches!(ctx.tag, "nav" | "aside") {
        let mut placeholder_links = 0;
        count_placeholder_anchors(
            ctx.jsx_el,
            ctx.semantic,
            ctx.const_strings,
            &mut placeholder_links,
        );
        if placeholder_links >= 2 {
            push_design_site(
                sites,
                RuleId::NoRepeatedPlaceholderNavigation,
                ctx.subject_name.clone(),
                "noRepeatedPlaceholderNavigation",
                ctx.tag,
                "Navigation contains multiple `<a href=\"#\">` placeholder links.".to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if ctx.unvariant_tokens.contains(&"overflow-hidden")
        && ctx
            .unvariant_tokens
            .iter()
            .any(|u| u.starts_with("rounded"))
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && has_traffic_light_dots(ctx.jsx_el, ctx.semantic, ctx.const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoFakeBrowserChrome,
            ctx.subject_name.clone(),
            "noFakeBrowserChrome",
            ctx.tag,
            "Preview redraws decorative traffic-light browser chrome.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_hero_and_feature_grid_patterns(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "div" | "section") && ctx.unvariant_tokens.contains(&"grid") {
        let direct_cards: Vec<&JSXElement<'_>> = ctx
            .jsx_el
            .children
            .iter()
            .filter_map(|c| match c {
                JSXChild::Element(el) => Some(el.as_ref()),
                _ => None,
            })
            .collect();
        if direct_cards.len() >= 3
            && direct_cards.iter().all(|card| {
                let c_str =
                    get_class_name_str(&card.opening_element, ctx.semantic, ctx.const_strings)
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
                ctx.subject_name.clone(),
                "noUniformFeatureCardGrid",
                ctx.tag,
                "Feature grid repeats the same rounded card-and-heading recipe across all items."
                    .to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if matches!(ctx.tag, "section" | "header" | "div")
        && ctx.unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "min-h-screen" | "h-screen" | "min-h-dvh" | "h-dvh" | "min-h-[100vh]" | "h-[100vh]"
            )
        })
        && ctx.unvariant_tokens.contains(&"items-center")
        && ctx.unvariant_tokens.contains(&"justify-center")
        && (ctx.unvariant_tokens.contains(&"text-center")
            || has_descendant_text_center(ctx.jsx_el, ctx.semantic, ctx.const_strings))
        && subtree_has_tag_matching(ctx.jsx_el, |t| t == "h1")
    {
        push_design_site(
            sites,
            RuleId::NoFullViewportCenteredHero,
            ctx.subject_name.clone(),
            "noFullViewportCenteredHero",
            ctx.tag,
            "Hero uses a full-viewport centered template.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_hero_eyebrow_and_section_markers(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let direct_el_children: Vec<&JSXElement<'_>> = ctx
        .jsx_el
        .children
        .iter()
        .filter_map(|c| match c {
            JSXChild::Element(el) => Some(el.as_ref()),
            _ => None,
        })
        .collect();
    let Some(&[first_el, second_el, ..]) = direct_el_children.get(..) else {
        return;
    };
    let first_tag = get_jsx_tag_name(&first_el.opening_element.name);
    let second_tag = get_jsx_tag_name(&second_el.opening_element.name);
    let first_cls = get_class_name_str(&first_el.opening_element, ctx.semantic, ctx.const_strings)
        .unwrap_or_default();
    let first_toks: Vec<&str> = first_cls
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();
    let first_txt = collect_all_static_text(first_el);
    let first_trimmed = first_txt.trim();
    let first_loc = loc_from_line_starts(ctx.line_starts, first_el.opening_element.span.start);
    let first_span = ByteSpan {
        start: first_el.opening_element.span.start,
        end: first_el.opening_element.span.end,
    };

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
            ctx.subject_name.clone(),
            "noHeroEyebrowChip",
            &first_tag,
            "Hero places a decorative eyebrow chip above its primary heading.".to_string(),
            first_loc,
            first_span,
            None,
        );
    }

    if matches!(second_tag.as_str(), "h2" | "h3") && is_numbered_section_marker_text(first_trimmed)
    {
        push_design_site(
            sites,
            RuleId::NoNumberedSectionMarkers,
            ctx.subject_name.clone(),
            "noNumberedSectionMarkers",
            &first_tag,
            "Section uses a decorative numeric marker before its heading.".to_string(),
            first_loc,
            first_span,
            None,
        );
    }

    if is_tailwind_card_tokens(ctx.unvariant_tokens)
        && matches!(second_tag.as_str(), "h2" | "h3" | "h4")
        && is_icon_tile_element(first_el, &first_toks)
    {
        push_design_site(
            sites,
            RuleId::NoIconTileHeadingStack,
            ctx.subject_name.clone(),
            "noIconTileHeadingStack",
            ctx.tag,
            "Card stacks a boxed icon tile above its heading.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
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
