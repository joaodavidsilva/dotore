//! Typography, button label, control target size, and primary JSX element design rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{Expression, JSXAttributeValue, JSXChild, JSXElement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, get_style_prop_number, get_style_prop_str,
    },
    rules::{AutofixPatch, RuleId},
};

use super::{
    BLOCK_DEFAULT_TAGS, EXCLUDED_TYPOGRAPHY_TAGS, INLINE_DEFAULT_TAGS, JsxDesignElemCtx,
    VAGUE_BUTTON_LABELS, collect_all_static_text, collect_subtree_font_sizes,
    is_tailwind_card_tokens, parse_tailwind_size_px, push_design_site, resolve_element_font_size_px,
    starts_with_emoji, surfaces_and_interactions::check_extended_design_patterns,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all element- and page-level UI design rules in one pass (#50)"
)]
pub(super) fn check_jsx_element_design(
    _path: &std::path::Path,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let tokens: Vec<&str> = class_str.split_whitespace().collect();
    let unvariant_tokens: Vec<&str> = tokens
        .iter()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();
    let text = collect_all_static_text(jsx_el);
    let trimmed_text = text.trim();
    let font_size =
        resolve_element_font_size_px(opening, &unvariant_tokens, semantic, const_strings);

    let ctx = JsxDesignElemCtx {
        semantic,
        node_id,
        jsx_el,
        opening,
        tag: &tag,
        tokens: &tokens,
        unvariant_tokens: &unvariant_tokens,
        trimmed_text,
        font_size,
        subject_name,
        const_strings,
        loc,
        span,
        line_starts,
    };

    check_button_and_copy_punctuation_design(&ctx, sites);
    check_icon_button_img_and_emoji_heading(&ctx, sites);
    check_pulse_border_and_scroll_design(&ctx, sites);
    check_container_text_scale_and_display_class(&ctx, sites);
    check_text_size_viewport_and_padding_design(&ctx, sites);
    check_hover_motion_table_and_media_design(&ctx, sites);
    check_extended_design_patterns(&ctx, kicker_candidates, sites);
}

fn check_button_and_copy_punctuation_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "button" | "Button")
        && let Some(label_text) = collect_direct_button_label_text(ctx.jsx_el)
    {
        let norm = normalize_button_label(&label_text);
        if VAGUE_BUTTON_LABELS.contains(&norm.as_str())
            && !(norm == "continue"
                && enclosing_form_has_previous_step_control(ctx.semantic, ctx.node_id))
        {
            push_design_site(
                sites,
                RuleId::DesignNoVagueButtonLabel,
                ctx.subject_name.clone(),
                "designNoVagueButtonLabel",
                &label_text,
                format!(
                    "Screen reader users may not know what \"{label_text}\" does. Use a specific action label."
                ),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if is_inside_excluded_typography_element(ctx.semantic, ctx.node_id, ctx.const_strings) {
        return;
    }
    for child in &ctx.jsx_el.children {
        let JSXChild::Text(t) = child else {
            continue;
        };
        let raw = t.value.as_str();
        let tspan = ByteSpan {
            start: t.span.start,
            end: t.span.end,
        };
        let tloc = loc_from_line_starts(ctx.line_starts, t.span.start);
        if has_word_three_period_ellipsis(raw) {
            let patch = AutofixPatch::replace(
                "Replace `...` with typographic ellipsis `…`",
                tspan,
                raw.replace("...", "…"),
            );
            push_design_site(
                sites,
                RuleId::DesignNoThreePeriodEllipsis,
                ctx.subject_name.clone(),
                "designNoThreePeriodEllipsis",
                "...",
                "Use the typographic ellipsis character `…` instead of three periods `...`."
                    .to_string(),
                tloc,
                tspan,
                Some(patch),
            );
        }
        if raw.contains('—') && raw.split_whitespace().count() >= 5 {
            let patch = AutofixPatch::replace(
                "Replace em dash `—` with `--`",
                tspan,
                raw.replace('—', "--"),
            );
            push_design_site(
                sites,
                RuleId::DesignNoEmDashInJsxText,
                ctx.subject_name.clone(),
                "designNoEmDashInJsxText",
                "—",
                "Avoid em dashes in UI copy; use simpler punctuation.".to_string(),
                tloc,
                tspan,
                Some(patch),
            );
        }
    }
}

fn check_icon_button_img_and_emoji_heading(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "button"
        && !has_direct_visible_text(ctx.jsx_el)
        && ctx
            .jsx_el
            .children
            .iter()
            .any(|c| matches!(c, JSXChild::Element(_)))
    {
        let mut min_dim = get_style_prop_number(ctx.opening, "width")
            .or_else(|| get_style_prop_number(ctx.opening, "height"));
        for &u in ctx.unvariant_tokens {
            if let Some(px) = parse_tailwind_size_px(u) {
                min_dim = Some(min_dim.map_or(px, |cur| cur.min(px)));
            }
        }
        if min_dim.is_some_and(|d| d > 0.0 && d < 24.0) {
            push_design_site(
                sites,
                RuleId::NoUndersizedIconButton,
                ctx.subject_name.clone(),
                "noUndersizedIconButton",
                "button",
                "This icon button target is smaller than 24×24 CSS pixels (WCAG 2.5.8)."
                    .to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if ctx.tag == "img" && !has_img_dimensions(ctx) {
        push_design_site(
            sites,
            RuleId::NoImgWithoutDimensions,
            ctx.subject_name.clone(),
            "noImgWithoutDimensions",
            "img",
            "This image reserves no dimensions or aspect ratio before loading, causing layout shift.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
        && starts_with_emoji(ctx.trimmed_text)
    {
        push_design_site(
            sites,
            RuleId::NoEmojiHeadingDecoration,
            ctx.subject_name.clone(),
            "noEmojiHeadingDecoration",
            ctx.tag,
            "This heading uses emoji as decoration. Keep the heading typographic and move icons into a consistent icon system.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn has_img_dimensions(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    let has_attr_dims = find_jsx_attr_ignore_case(&ctx.opening.attributes, "width").is_some()
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "height").is_some();
    let has_tw_dims = ctx.unvariant_tokens.iter().any(|u| {
        u.starts_with("size-")
            || u.starts_with("aspect-")
            || (ctx.unvariant_tokens.iter().any(|w| w.starts_with("w-"))
                && ctx.unvariant_tokens.iter().any(|h| h.starts_with("h-")))
    });
    let has_style_dims = get_style_prop_number(ctx.opening, "width").is_some()
        && get_style_prop_number(ctx.opening, "height").is_some();
    has_attr_dims || has_tw_dims || has_style_dims
}

fn check_pulse_border_and_scroll_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx
        .unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "animate-pulse" | "animate-ping"))
        && !is_legitimate_live_status_pulse(ctx)
    {
        if !ctx.trimmed_text.is_empty() {
            push_design_site(
                sites,
                RuleId::NoDecorativePulse,
                ctx.subject_name.clone(),
                "noDecorativePulse",
                ctx.tag,
                "Stable copy pulses continuously for attention; reserve pulsing motion for real in-progress feedback.".to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        } else if ctx.unvariant_tokens.contains(&"rounded-full")
            && ctx
                .unvariant_tokens
                .iter()
                .any(|u| parse_tailwind_size_px(u).is_some_and(|px| (2.0..=16.0).contains(&px)))
        {
            push_design_site(
                sites,
                RuleId::NoPulsingStatusDot,
                ctx.subject_name.clone(),
                "noPulsingStatusDot",
                ctx.tag,
                "Decorative status dot pulses continuously without live-region semantics."
                    .to_string(),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if has_side_tab_border_tokens(ctx.unvariant_tokens) {
        push_design_site(
            sites,
            RuleId::NoSideTabBorder,
            ctx.subject_name.clone(),
            "noSideTabBorder",
            ctx.tag,
            "Thick one-sided colored stripe border; prefer a subtler surface treatment."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.tokens.contains(&"scroll-smooth")
        && !ctx
            .tokens
            .iter()
            .any(|t| t.starts_with("motion-safe:") || t.starts_with("motion-reduce:"))
    {
        push_design_site(
            sites,
            RuleId::NoSmoothScrollWithoutReducedMotion,
            ctx.subject_name.clone(),
            "noSmoothScrollWithoutReducedMotion",
            ctx.tag,
            "`scroll-smooth` ignores `prefers-reduced-motion`; use `motion-safe:scroll-smooth`."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn is_legitimate_live_status_pulse(ctx: &JsxDesignElemCtx<'_, '_>) -> bool {
    let role_val = find_jsx_attr_ignore_case(&ctx.opening.attributes, "role")
        .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings));
    if matches!(
        role_val.as_deref(),
        Some("status" | "progressbar" | "alert")
    ) || find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-busy").is_some()
    {
        return true;
    }
    let lower = ctx.trimmed_text.to_ascii_lowercase();
    lower.contains("loading") || lower.contains("saving") || lower.contains("processing")
}

fn has_side_tab_border_tokens(unvariant_tokens: &[&str]) -> bool {
    unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
        )
    }) && unvariant_tokens.iter().any(|u| {
        u.starts_with("border-[")
            || (u.starts_with("border-")
                && ![
                    "border-gray-",
                    "border-slate-",
                    "border-zinc-",
                    "border-neutral-",
                    "border-stone-",
                ]
                .iter()
                .any(|p| u.starts_with(p))
                && !matches!(
                    *u,
                    "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
                ))
    })
}

fn check_container_text_scale_and_display_class(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "article" | "aside" | "div" | "section")
        && is_tailwind_card_tokens(ctx.unvariant_tokens)
    {
        let mut leaf_texts: HashMap<String, usize> = HashMap::new();
        collect_leaf_element_texts(ctx.jsx_el, &mut leaf_texts);
        if let Some((repeated_text, _)) = leaf_texts
            .into_iter()
            .find(|(txt, count)| *count >= 3 && (4..=48).contains(&txt.len()))
        {
            push_design_site(
                sites,
                RuleId::NoRepeatedContainerText,
                ctx.subject_name.clone(),
                "noRepeatedContainerText",
                &repeated_text,
                format!(
                    "This card container repeats {:?} across multiple distinct slots.",
                    repeated_text
                ),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if ctx.tag == "main" {
        let mut font_sizes: Vec<f64> = Vec::new();
        collect_subtree_font_sizes(ctx.jsx_el, ctx.semantic, ctx.const_strings, &mut font_sizes);
        font_sizes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        font_sizes.dedup_by(|a, b| (*a - *b).abs() < 0.01);
        if font_sizes.len() >= 3
            && let (Some(&smallest), Some(&largest)) = (font_sizes.first(), font_sizes.last())
            && smallest > 0.0
            && (largest / smallest) < 2.0
        {
            push_design_site(
                sites,
                RuleId::NoFlatPageTypeScale,
                ctx.subject_name.clone(),
                "noFlatPageTypeScale",
                "main",
                format!(
                    "This page declares {} text sizes within less than a 2× range. Increase the hierarchy between supporting and display text.",
                    font_sizes.len()
                ),
                ctx.loc,
                ctx.span,
                None,
            );
        }
    }

    if let Some(class_attr) = find_attr(&ctx.opening.attributes, "className")
        && let Some(JSXAttributeValue::StringLiteral(s_lit)) = &class_attr.value
        && let Some(disp) = detect_redundant_display_class(ctx.tag, ctx.tokens)
    {
        let new_tokens: Vec<&str> = ctx.tokens.iter().copied().filter(|&t| t != disp).collect();
        let content_span = ByteSpan {
            start: s_lit.span.start + 1,
            end: s_lit.span.end.saturating_sub(1),
        };
        let patch = AutofixPatch::replace(
            format!("Remove redundant `{disp}` class on `<{}>`", ctx.tag),
            content_span,
            new_tokens.join(" "),
        );
        push_design_site(
            sites,
            RuleId::NoRedundantDisplayClass,
            ctx.subject_name.clone(),
            "noRedundantDisplayClass",
            disp,
            format!("`{disp}` is already the default display of `<{}>`.", ctx.tag),
            ctx.loc,
            ctx.span,
            Some(patch),
        );
    }
}

fn detect_redundant_display_class(tag: &str, tokens: &[&str]) -> Option<&'static str> {
    if BLOCK_DEFAULT_TAGS.contains(&tag)
        && tokens.contains(&"block")
        && !tokens.iter().any(|t| {
            t.contains(":flex")
                || t.contains(":grid")
                || t.contains(":hidden")
                || t.contains(":inline")
        })
    {
        return Some("block");
    }
    if INLINE_DEFAULT_TAGS.contains(&tag)
        && tokens.contains(&"inline")
        && !tokens
            .iter()
            .any(|t| t.contains(":block") || t.contains(":flex") || t.contains(":hidden"))
    {
        return Some("inline");
    }
    None
}

fn check_text_size_viewport_and_padding_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_tiny_and_gradient_text_design(ctx, sites);
    check_viewport_and_padding_bounds_design(ctx, sites);
}

fn check_tiny_and_gradient_text_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.trimmed_text.is_empty()
        && ctx.font_size.is_some_and(|px| px > 0.0 && px < 12.0)
        && !ctx.unvariant_tokens.contains(&"sr-only")
    {
        push_design_site(
            sites,
            RuleId::NoTinyText,
            ctx.subject_name.clone(),
            "noTinyText",
            ctx.tag,
            "Text is smaller than 12px and hard to read.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.contains(&"bg-clip-text")
        && ctx.unvariant_tokens.contains(&"text-transparent")
        && ctx.unvariant_tokens.iter().any(|u| {
            u.starts_with("bg-gradient-")
                || u.starts_with("bg-linear-")
                || u.starts_with("bg-radial")
        })
    {
        push_design_site(
            sites,
            RuleId::NoGradientText,
            ctx.subject_name.clone(),
            "noGradientText",
            ctx.tag,
            "Gradient text is harder to read; prefer solid text color.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_viewport_and_padding_bounds_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "h-screen" | "min-h-screen" | "h-[100vh]" | "min-h-[100vh]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::PreferDvhOverVh,
            ctx.subject_name.clone(),
            "preferDvhOverVh",
            ctx.tag,
            "`h-screen` / `100vh` overflows under mobile browser toolbars; use `h-dvh` / `min-h-dvh`.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "w-screen" | "min-w-screen" | "w-[100vw]" | "min-w-[100vw]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::NoFullViewportWidth,
            ctx.subject_name.clone(),
            "noFullViewportWidth",
            ctx.tag,
            "`w-screen` / `100vw` ignores the scrollbar gutter; use `w-full`.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if !ctx.trimmed_text.is_empty()
        && ctx.unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && ctx.unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "p-0.5" | "p-1" | "p-1.5" | "px-1" | "py-1" | "p-[2px]" | "p-[4px]"
            )
        })
    {
        push_design_site(
            sites,
            RuleId::NoCrampedContainerPadding,
            ctx.subject_name.clone(),
            "noCrampedContainerPadding",
            ctx.tag,
            "Bounded text container has cramped padding (< 8px).".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if matches!(ctx.tag, "input" | "select" | "textarea")
        && ctx.font_size.is_some_and(|px| px > 0.0 && px < 16.0)
    {
        push_design_site(
            sites,
            RuleId::NoSmallFormControlText,
            ctx.subject_name.clone(),
            "noSmallFormControlText",
            ctx.tag,
            format!(
                "Form control uses {}px text on mobile; use at least 16px to prevent auto-zoom.",
                ctx.font_size.unwrap_or(14.0)
            ),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.tag == "h1"
        && ctx.trimmed_text.len() >= 40
        && ctx.font_size.is_some_and(|px| px >= 64.0)
    {
        push_design_site(
            sites,
            RuleId::NoOversizedLongHeading,
            ctx.subject_name.clone(),
            "noOversizedLongHeading",
            "h1",
            "Long sentence-length headline uses an oversized hero display scale (>= 64px)."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_hover_motion_table_and_media_design(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_hover_reveal_and_mixed_animation(ctx, sites);
    check_table_video_and_scale_origin(ctx, sites);
}

fn check_hover_reveal_and_mixed_animation(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tokens.contains(&"opacity-0")
        && ctx
            .tokens
            .iter()
            .any(|t| *t == "hover:opacity-100" || *t == "group-hover:opacity-100")
        && !ctx.tokens.iter().any(|t| {
            t.contains("focus:opacity-100")
                || t.contains("focus-visible:opacity-100")
                || t.contains("focus-within:opacity-100")
        })
    {
        push_design_site(
            sites,
            RuleId::NoHoverOnlyReveal,
            ctx.subject_name.clone(),
            "noHoverOnlyReveal",
            ctx.tag,
            "Content is revealed only on hover without a keyboard focus reveal.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if (ctx.tag.starts_with("motion.") || ctx.tag.starts_with("m."))
        && find_attr(&ctx.opening.attributes, "animate").is_some()
        && ctx
            .unvariant_tokens
            .iter()
            .any(|u| u.starts_with("transition"))
    {
        push_design_site(
            sites,
            RuleId::NoMixedAnimationOwners,
            ctx.subject_name.clone(),
            "noMixedAnimationOwners",
            ctx.tag,
            "CSS transition and Motion `animate` both control properties on the same element."
                .to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn check_table_video_and_scale_origin(
    ctx: &JsxDesignElemCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "td"
        && !has_tabular_nums_in_ancestry(ctx.semantic, ctx.node_id, ctx.const_strings)
        && ctx.jsx_el.children.iter().any(|c| {
            if let JSXChild::ExpressionContainer(ec) = c {
                let s = ec.span.source_text(ctx.semantic.source_text());
                s.contains(".toLocaleString(")
                    || s.contains(".toFixed(")
                    || s.contains("formatCurrency(")
            } else {
                false
            }
        })
    {
        push_design_site(
            sites,
            RuleId::PreferTabularNumericData,
            ctx.subject_name.clone(),
            "preferTabularNumericData",
            "td",
            "Table cell renders a formatted number without `tabular-nums`.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if ctx.tag == "video"
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "autoPlay").is_some()
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "poster").is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireAutoplayVideoPoster,
            ctx.subject_name.clone(),
            "requireAutoplayVideoPoster",
            "video",
            "Autoplaying `<video>` has no `poster` frame.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }

    if find_jsx_attr_ignore_case(&ctx.opening.attributes, "role")
        .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
        .is_some_and(|r| matches!(r.as_str(), "menu" | "listbox"))
        && find_attr(&ctx.opening.attributes, "initial")
            .is_some_and(|a| a.span.source_text(ctx.semantic.source_text()).contains("scale"))
        && !ctx.unvariant_tokens.iter().any(|u| u.starts_with("origin-"))
        && get_style_prop_str(
            ctx.opening,
            "transformOrigin",
            ctx.semantic,
            ctx.const_strings,
        )
        .is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireScaleRevealTransformOrigin,
            ctx.subject_name.clone(),
            "requireScaleRevealTransformOrigin",
            ctx.tag,
            "Scaled menu/listbox omits an explicit `origin-*` or `transformOrigin`.".to_string(),
            ctx.loc,
            ctx.span,
            None,
        );
    }
}

fn collect_direct_button_label_text(jsx_el: &JSXElement<'_>) -> Option<String> {
    let mut out = String::new();
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) => out.push_str(t.value.as_str()),
            JSXChild::ExpressionContainer(c) => {
                if let Some(Expression::StringLiteral(s)) = c.expression.as_expression()
                    && let Some(v) = s.value.as_str()
                {
                    out.push_str(v);
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let trimmed = out.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn normalize_button_label(s: &str) -> String {
    s.trim()
        .trim_end_matches(['.', '!', '?', '…'])
        .trim()
        .to_ascii_lowercase()
}

fn enclosing_form_has_previous_step_control(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(form_el) = semantic.nodes().kind(anc_id)
            && get_jsx_tag_name(&form_el.opening_element.name) == "form"
        {
            return subtree_has_previous_step_control(&form_el.children);
        }
    }
    false
}

fn subtree_has_previous_step_control(children: &[JSXChild<'_>]) -> bool {
    for child in children {
        match child {
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if matches!(tag.as_str(), "button" | "Button" | "a" | "Link")
                    && let Some(lbl) = collect_direct_button_label_text(el)
                    && matches!(normalize_button_label(&lbl).as_str(), "back" | "previous")
                {
                    return true;
                }
                if subtree_has_previous_step_control(&el.children) {
                    return true;
                }
            }
            JSXChild::Fragment(frag) if subtree_has_previous_step_control(&frag.children) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_inside_excluded_typography_element(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for id in std::iter::once(node_id).chain(semantic.nodes().ancestor_ids(node_id)) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(id) {
            let tag = get_jsx_tag_name(&el.opening_element.name).to_ascii_lowercase();
            if EXCLUDED_TYPOGRAPHY_TAGS.contains(&tag.as_str()) {
                return true;
            }
            if find_jsx_attr_ignore_case(&el.opening_element.attributes, "translate")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .is_some_and(|v| v.eq_ignore_ascii_case("no"))
            {
                return true;
            }
        }
    }
    false
}

fn has_word_three_period_ellipsis(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (idx, _) in text.match_indices("...") {
        if idx > 0 && bytes[idx - 1].is_ascii_alphanumeric() {
            return true;
        }
    }
    false
}

fn has_direct_visible_text(jsx_el: &JSXElement<'_>) -> bool {
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) if !t.value.trim().is_empty() => return true,
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if tag != "svg"
                    && !tag.ends_with("Icon")
                    && !tag.starts_with("Icon")
                    && has_direct_visible_text(el)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn collect_leaf_element_texts(jsx_el: &JSXElement<'_>, counts: &mut HashMap<String, usize>) {
    let has_el_children = jsx_el
        .children
        .iter()
        .any(|c| matches!(c, JSXChild::Element(_)));
    if !has_el_children {
        let txt = collect_all_static_text(jsx_el).trim().to_string();
        if !txt.is_empty() {
            *counts.entry(txt).or_insert(0) += 1;
        }
        return;
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_leaf_element_texts(child_el, counts);
        }
    }
}

fn has_tabular_nums_in_ancestry(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for id in std::iter::once(node_id).chain(semantic.nodes().ancestor_ids(node_id)) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
            && cls
                .split_whitespace()
                .any(|t| matches!(t, "tabular-nums" | "font-mono"))
        {
            return true;
        }
    }
    false
}
