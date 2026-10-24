//! Typography, button label, control target size, and primary JSX element design rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{Expression, JSXAttributeValue, JSXChild, JSXElement, JSXOpeningElement},
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
    BLOCK_DEFAULT_TAGS, EXCLUDED_TYPOGRAPHY_TAGS, INLINE_DEFAULT_TAGS, VAGUE_BUTTON_LABELS,
    collect_all_static_text, is_tailwind_card_tokens, parse_px_or_rem, parse_tailwind_size_px,
    push_design_site, starts_with_emoji, surfaces_and_interactions::check_extended_design_patterns,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all element- and page-level UI design rules in one pass"
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

    // 1. `design-no-vague-button-label` (with wizard `Continue` + `Back`/`Previous` form exemption!)
    if matches!(tag.as_str(), "button" | "Button")
        && let Some(label_text) = collect_direct_button_label_text(jsx_el)
    {
        let norm = normalize_button_label(&label_text);
        if VAGUE_BUTTON_LABELS.contains(&norm.as_str()) {
            let is_wizard_continue =
                norm == "continue" && enclosing_form_has_previous_step_control(semantic, node_id);
            if !is_wizard_continue {
                push_design_site(
                    sites,
                    RuleId::DesignNoVagueButtonLabel,
                    subject_name.clone(),
                    "designNoVagueButtonLabel",
                    &label_text,
                    format!(
                        "Screen reader users may not know what \"{label_text}\" does. Use a specific action label."
                    ),
                    loc,
                    span,
                    None,
                );
            }
        }
    }

    // 2. `design-no-three-period-ellipsis` & `design-no-em-dash-in-jsx-text` (with Autofix!)
    if !is_inside_excluded_typography_element(semantic, node_id, const_strings) {
        for child in &jsx_el.children {
            if let JSXChild::Text(t) = child {
                let raw = t.value.as_str();
                if has_word_three_period_ellipsis(raw) {
                    let tspan = ByteSpan {
                        start: t.span.start,
                        end: t.span.end,
                    };
                    let patch = AutofixPatch::replace(
                        "Replace `...` with typographic ellipsis `…`",
                        tspan,
                        raw.replace("...", "…"),
                    );
                    push_design_site(
                        sites,
                        RuleId::DesignNoThreePeriodEllipsis,
                        subject_name.clone(),
                        "designNoThreePeriodEllipsis",
                        "...",
                        "Use the typographic ellipsis character `…` instead of three periods `...`.".to_string(),
                        loc_from_line_starts(line_starts, t.span.start),
                        tspan,
                        Some(patch),
                    );
                }
                if raw.contains('—') && raw.split_whitespace().count() >= 5 {
                    let tspan = ByteSpan {
                        start: t.span.start,
                        end: t.span.end,
                    };
                    let patch = AutofixPatch::replace(
                        "Replace em dash `—` with `--`",
                        tspan,
                        raw.replace('—', "--"),
                    );
                    push_design_site(
                        sites,
                        RuleId::DesignNoEmDashInJsxText,
                        subject_name.clone(),
                        "designNoEmDashInJsxText",
                        "—",
                        "Avoid em dashes in UI copy; use simpler punctuation.".to_string(),
                        loc_from_line_starts(line_starts, t.span.start),
                        tspan,
                        Some(patch),
                    );
                }
            }
        }
    }

    // 3. `no-undersized-icon-button`
    if tag == "button"
        && !has_direct_visible_text(jsx_el)
        && jsx_el
            .children
            .iter()
            .any(|c| matches!(c, JSXChild::Element(_)))
    {
        let mut min_dim = get_style_prop_number(opening, "width")
            .or_else(|| get_style_prop_number(opening, "height"));
        for &u in &unvariant_tokens {
            if let Some(px) = parse_tailwind_size_px(u) {
                min_dim = Some(min_dim.map_or(px, |cur| cur.min(px)));
            }
        }
        if min_dim.is_some_and(|d| d > 0.0 && d < 24.0) {
            push_design_site(
                sites,
                RuleId::NoUndersizedIconButton,
                subject_name.clone(),
                "noUndersizedIconButton",
                "button",
                "This icon button target is smaller than 24×24 CSS pixels (WCAG 2.5.8)."
                    .to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 4. `no-img-without-dimensions`
    if tag == "img" {
        let has_attr_dims = find_jsx_attr_ignore_case(&opening.attributes, "width").is_some()
            && find_jsx_attr_ignore_case(&opening.attributes, "height").is_some();
        let has_tw_dims = unvariant_tokens.iter().any(|u| {
            u.starts_with("size-")
                || u.starts_with("aspect-")
                || (unvariant_tokens.iter().any(|w| w.starts_with("w-"))
                    && unvariant_tokens.iter().any(|h| h.starts_with("h-")))
        });
        let has_style_dims = get_style_prop_number(opening, "width").is_some()
            && get_style_prop_number(opening, "height").is_some();
        if !has_attr_dims && !has_tw_dims && !has_style_dims {
            push_design_site(
                sites,
                RuleId::NoImgWithoutDimensions,
                subject_name.clone(),
                "noImgWithoutDimensions",
                "img",
                "This image reserves no dimensions or aspect ratio before loading, causing layout shift.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 5. `no-emoji-heading-decoration`
    if matches!(tag.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        let text = collect_all_static_text(jsx_el);
        if starts_with_emoji(text.trim_start()) {
            push_design_site(
                sites,
                RuleId::NoEmojiHeadingDecoration,
                subject_name.clone(),
                "noEmojiHeadingDecoration",
                &tag,
                "This heading uses emoji as decoration. Keep the heading typographic and move icons into a consistent icon system.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 6. `no-decorative-pulse` & `no-pulsing-status-dot`
    if unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "animate-pulse" | "animate-ping"))
    {
        let role_val = find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let is_live_status = matches!(
            role_val.as_deref(),
            Some("status" | "progressbar" | "alert")
        ) || find_jsx_attr_ignore_case(&opening.attributes, "aria-busy")
            .is_some();
        let text = collect_all_static_text(jsx_el);
        let lower_text = text.to_ascii_lowercase();
        let is_busy_copy = lower_text.contains("loading")
            || lower_text.contains("saving")
            || lower_text.contains("processing");

        if !is_live_status && !is_busy_copy {
            if !text.trim().is_empty() {
                push_design_site(
                    sites,
                    RuleId::NoDecorativePulse,
                    subject_name.clone(),
                    "noDecorativePulse",
                    &tag,
                    "Stable copy pulses continuously for attention; reserve pulsing motion for real in-progress feedback.".to_string(),
                    loc,
                    span,
                    None,
                );
            } else if unvariant_tokens.contains(&"rounded-full")
                && unvariant_tokens
                    .iter()
                    .any(|u| parse_tailwind_size_px(u).is_some_and(|px| (2.0..=16.0).contains(&px)))
            {
                push_design_site(
                    sites,
                    RuleId::NoPulsingStatusDot,
                    subject_name.clone(),
                    "noPulsingStatusDot",
                    &tag,
                    "Decorative status dot pulses continuously without live-region semantics."
                        .to_string(),
                    loc,
                    span,
                    None,
                );
            }
        }
    }

    // 7. `no-side-tab-border`
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
        )
    }) && unvariant_tokens.iter().any(|u| {
        u.starts_with("border-[")
            || (u.starts_with("border-")
                && !u.starts_with("border-gray-")
                && !u.starts_with("border-slate-")
                && !u.starts_with("border-zinc-")
                && !u.starts_with("border-neutral-")
                && !u.starts_with("border-stone-")
                && !matches!(
                    *u,
                    "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
                ))
    }) {
        push_design_site(
            sites,
            RuleId::NoSideTabBorder,
            subject_name.clone(),
            "noSideTabBorder",
            &tag,
            "Thick one-sided colored stripe border; prefer a subtler surface treatment."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 8. `no-smooth-scroll-without-reduced-motion`
    if tokens.contains(&"scroll-smooth")
        && !tokens
            .iter()
            .any(|t| t.starts_with("motion-safe:") || t.starts_with("motion-reduce:"))
    {
        push_design_site(
            sites,
            RuleId::NoSmoothScrollWithoutReducedMotion,
            subject_name.clone(),
            "noSmoothScrollWithoutReducedMotion",
            &tag,
            "`scroll-smooth` ignores `prefers-reduced-motion`; use `motion-safe:scroll-smooth`."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 9. `no-repeated-container-text`
    if matches!(tag.as_str(), "article" | "aside" | "div" | "section")
        && is_tailwind_card_tokens(&unvariant_tokens)
    {
        let mut leaf_texts: HashMap<String, usize> = HashMap::new();
        collect_leaf_element_texts(jsx_el, &mut leaf_texts);
        if let Some((repeated_text, _)) = leaf_texts
            .into_iter()
            .find(|(txt, count)| *count >= 3 && (4..=48).contains(&txt.len()))
        {
            push_design_site(
                sites,
                RuleId::NoRepeatedContainerText,
                subject_name.clone(),
                "noRepeatedContainerText",
                &repeated_text,
                format!(
                    "This card container repeats {:?} across multiple distinct slots.",
                    repeated_text
                ),
                loc,
                span,
                None,
            );
        }
    }

    // 10. `no-flat-page-type-scale`
    if tag == "main" {
        let mut font_sizes: Vec<f64> = Vec::new();
        collect_subtree_font_sizes(jsx_el, semantic, const_strings, &mut font_sizes);
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
                subject_name.clone(),
                "noFlatPageTypeScale",
                "main",
                format!(
                    "This page declares {} text sizes within less than a 2× range. Increase the hierarchy between supporting and display text.",
                    font_sizes.len()
                ),
                loc,
                span,
                None,
            );
        }
    }

    // 11. `no-redundant-display-class` (with Autofix!)
    if let Some(class_attr) = find_attr(&opening.attributes, "className")
        && let Some(JSXAttributeValue::StringLiteral(s_lit)) = &class_attr.value
    {
        let redundant_disp = if BLOCK_DEFAULT_TAGS.contains(&tag.as_str())
            && tokens.contains(&"block")
            && !tokens.iter().any(|t| {
                t.contains(":flex")
                    || t.contains(":grid")
                    || t.contains(":hidden")
                    || t.contains(":inline")
            }) {
            Some("block")
        } else if INLINE_DEFAULT_TAGS.contains(&tag.as_str())
            && tokens.contains(&"inline")
            && !tokens
                .iter()
                .any(|t| t.contains(":block") || t.contains(":flex") || t.contains(":hidden"))
        {
            Some("inline")
        } else {
            None
        };
        if let Some(disp) = redundant_disp {
            let new_tokens: Vec<&str> = tokens.iter().copied().filter(|&t| t != disp).collect();
            let content_span = ByteSpan {
                start: s_lit.span.start + 1,
                end: s_lit.span.end.saturating_sub(1),
            };
            let patch = AutofixPatch::replace(
                format!("Remove redundant `{disp}` class on `<{tag}>`"),
                content_span,
                new_tokens.join(" "),
            );
            push_design_site(
                sites,
                RuleId::NoRedundantDisplayClass,
                subject_name.clone(),
                "noRedundantDisplayClass",
                disp,
                format!("`{disp}` is already the default display of `<{tag}>`."),
                loc,
                span,
                Some(patch),
            );
        }
    }

    // 12. Remaining className / element design rules
    check_remaining_element_design_rules(
        semantic,
        node_id,
        jsx_el,
        &tag,
        &tokens,
        &unvariant_tokens,
        subject_name,
        const_strings,
        kicker_candidates,
        loc,
        span,
        line_starts,
        sites,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all remaining UI design rules on a JSXElement in a single pass"
)]
fn check_remaining_element_design_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    tokens: &[&str],
    unvariant_tokens: &[&str],
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let text = collect_all_static_text(jsx_el);
    let trimmed_text = text.trim();
    let font_size =
        resolve_element_font_size_px(opening, unvariant_tokens, semantic, const_strings);

    // 1. `no-tiny-text`
    if !trimmed_text.is_empty()
        && font_size.is_some_and(|px| px > 0.0 && px < 12.0)
        && !unvariant_tokens.contains(&"sr-only")
    {
        push_design_site(
            sites,
            RuleId::NoTinyText,
            subject_name.clone(),
            "noTinyText",
            tag,
            "Text is smaller than 12px and hard to read.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 2. `no-gradient-text`
    if unvariant_tokens.contains(&"bg-clip-text")
        && unvariant_tokens.contains(&"text-transparent")
        && unvariant_tokens.iter().any(|u| {
            u.starts_with("bg-gradient-")
                || u.starts_with("bg-linear-")
                || u.starts_with("bg-radial")
        })
    {
        push_design_site(
            sites,
            RuleId::NoGradientText,
            subject_name.clone(),
            "noGradientText",
            tag,
            "Gradient text is harder to read; prefer solid text color.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 3. `prefer-dvh-over-vh` & `no-full-viewport-width` (Tailwind classes)
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "h-screen" | "min-h-screen" | "h-[100vh]" | "min-h-[100vh]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::PreferDvhOverVh,
            subject_name.clone(),
            "preferDvhOverVh",
            tag,
            "`h-screen` / `100vh` overflows under mobile browser toolbars; use `h-dvh` / `min-h-dvh`.".to_string(),
            loc,
            span,
            None,
        );
    }
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "w-screen" | "min-w-screen" | "w-[100vw]" | "min-w-[100vw]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::NoFullViewportWidth,
            subject_name.clone(),
            "noFullViewportWidth",
            tag,
            "`w-screen` / `100vw` ignores the scrollbar gutter; use `w-full`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 4. `no-cramped-container-padding`
    if !trimmed_text.is_empty()
        && unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "p-0.5" | "p-1" | "p-1.5" | "px-1" | "py-1" | "p-[2px]" | "p-[4px]"
            )
        })
    {
        push_design_site(
            sites,
            RuleId::NoCrampedContainerPadding,
            subject_name.clone(),
            "noCrampedContainerPadding",
            tag,
            "Bounded text container has cramped padding (< 8px).".to_string(),
            loc,
            span,
            None,
        );
    }

    // 5. `no-small-form-control-text`
    if matches!(tag, "input" | "select" | "textarea")
        && font_size.is_some_and(|px| px > 0.0 && px < 16.0)
    {
        push_design_site(
            sites,
            RuleId::NoSmallFormControlText,
            subject_name.clone(),
            "noSmallFormControlText",
            tag,
            format!(
                "Form control uses {}px text on mobile; use at least 16px to prevent auto-zoom.",
                font_size.unwrap_or(14.0)
            ),
            loc,
            span,
            None,
        );
    }

    // 6. `no-oversized-long-heading`
    if tag == "h1" && trimmed_text.len() >= 40 && font_size.is_some_and(|px| px >= 64.0) {
        push_design_site(
            sites,
            RuleId::NoOversizedLongHeading,
            subject_name.clone(),
            "noOversizedLongHeading",
            "h1",
            "Long sentence-length headline uses an oversized hero display scale (>= 64px)."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 7. `no-hover-only-reveal`
    if tokens.contains(&"opacity-0")
        && tokens
            .iter()
            .any(|t| *t == "hover:opacity-100" || *t == "group-hover:opacity-100")
        && !tokens.iter().any(|t| {
            t.contains("focus:opacity-100")
                || t.contains("focus-visible:opacity-100")
                || t.contains("focus-within:opacity-100")
        })
    {
        push_design_site(
            sites,
            RuleId::NoHoverOnlyReveal,
            subject_name.clone(),
            "noHoverOnlyReveal",
            tag,
            "Content is revealed only on hover without a keyboard focus reveal.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 8. `no-mixed-animation-owners`
    if (tag.starts_with("motion.") || tag.starts_with("m."))
        && find_attr(&opening.attributes, "animate").is_some()
        && unvariant_tokens.iter().any(|u| u.starts_with("transition"))
    {
        push_design_site(
            sites,
            RuleId::NoMixedAnimationOwners,
            subject_name.clone(),
            "noMixedAnimationOwners",
            tag,
            "CSS transition and Motion `animate` both control properties on the same element."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 9. `prefer-tabular-numeric-data`
    if tag == "td"
        && !has_tabular_nums_in_ancestry(semantic, node_id, const_strings)
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::ExpressionContainer(ec) = c {
                let s = ec.span.source_text(semantic.source_text());
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
            subject_name.clone(),
            "preferTabularNumericData",
            "td",
            "Table cell renders a formatted number without `tabular-nums`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 10. `require-autoplay-video-poster`
    if tag == "video"
        && find_jsx_attr_ignore_case(&opening.attributes, "autoPlay").is_some()
        && find_jsx_attr_ignore_case(&opening.attributes, "poster").is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireAutoplayVideoPoster,
            subject_name.clone(),
            "requireAutoplayVideoPoster",
            "video",
            "Autoplaying `<video>` has no `poster` frame.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 11. `require-scale-reveal-transform-origin`
    if find_jsx_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .is_some_and(|r| matches!(r.as_str(), "menu" | "listbox"))
        && find_attr(&opening.attributes, "initial")
            .is_some_and(|a| a.span.source_text(semantic.source_text()).contains("scale"))
        && !unvariant_tokens.iter().any(|u| u.starts_with("origin-"))
        && get_style_prop_str(opening, "transformOrigin", semantic, const_strings).is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireScaleRevealTransformOrigin,
            subject_name.clone(),
            "requireScaleRevealTransformOrigin",
            tag,
            "Scaled menu/listbox omits an explicit `origin-*` or `transformOrigin`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 12. Additional single-element and page-level design checks
    check_extended_design_patterns(
        semantic,
        node_id,
        jsx_el,
        tag,
        tokens,
        unvariant_tokens,
        trimmed_text,
        font_size,
        subject_name,
        const_strings,
        kicker_candidates,
        loc,
        span,
        line_starts,
        sites,
    );
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

fn resolve_element_font_size_px(
    opening: &JSXOpeningElement<'_>,
    unvariant_tokens: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<f64> {
    if let Some(num) = get_style_prop_number(opening, "fontSize") {
        return Some(num);
    }
    if let Some(s) = get_style_prop_str(opening, "fontSize", semantic, const_strings)
        && let Some(px) = parse_px_or_rem(&s)
    {
        return Some(px);
    }
    for &u in unvariant_tokens.iter().rev() {
        let px = match u {
            "text-xs" => Some(12.0),
            "text-sm" => Some(14.0),
            "text-base" => Some(16.0),
            "text-lg" => Some(18.0),
            "text-xl" => Some(20.0),
            "text-2xl" => Some(24.0),
            "text-3xl" => Some(30.0),
            "text-4xl" => Some(36.0),
            "text-5xl" => Some(48.0),
            "text-6xl" => Some(60.0),
            "text-7xl" => Some(72.0),
            "text-8xl" => Some(96.0),
            "text-9xl" => Some(128.0),
            _ => u
                .strip_prefix("text-[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(parse_px_or_rem),
        };
        if px.is_some() {
            return px;
        }
    }
    None
}

fn collect_subtree_font_sizes(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    out: &mut Vec<f64>,
) {
    let class_str =
        get_class_name_str(&jsx_el.opening_element, semantic, const_strings).unwrap_or_default();
    let unvariants: Vec<&str> = class_str
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();
    if let Some(px) = resolve_element_font_size_px(
        &jsx_el.opening_element,
        &unvariants,
        semantic,
        const_strings,
    ) {
        out.push(px);
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_subtree_font_sizes(child_el, semantic, const_strings, out);
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
