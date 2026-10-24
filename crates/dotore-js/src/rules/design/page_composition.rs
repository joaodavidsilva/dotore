//! Page-level `<main>` / `<article>` composition, surface density, and marketing copy design rules.
use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{JSXChild, JSXElement};
use oxc_semantic::{Semantic, SymbolId};

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{get_class_name_str, get_jsx_tag_name, get_style_prop_str},
    rules::RuleId,
};

use super::{
    GENERIC_MARKETING_PHRASES, collect_all_static_text, is_tailwind_card_tokens, push_design_site,
    starts_with_emoji,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates page-level composition and copy design rules on <main>/<article> roots"
)]
pub(super) fn check_page_root_design_rules(
    jsx_el: &JSXElement<'_>,
    tag: &str,
    trimmed_text: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let lower_text = trimmed_text.to_ascii_lowercase();
    let root_opening = &jsx_el.opening_element;
    let root_cls = get_class_name_str(root_opening, semantic, const_strings).unwrap_or_default();
    let root_toks: Vec<&str> = root_cls
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();

    // `no-common-root-font`
    let has_common_font = root_toks.contains(&"font-sans")
        || get_style_prop_str(root_opening, "fontFamily", semantic, const_strings).is_some_and(
            |ff| {
                let primary = ff
                    .split(',')
                    .next()
                    .unwrap_or(&ff)
                    .trim()
                    .trim_matches(['"', '\''])
                    .to_ascii_lowercase();
                matches!(
                    primary.as_str(),
                    "inter"
                        | "roboto"
                        | "arial"
                        | "helvetica"
                        | "system-ui"
                        | "sans-serif"
                        | "open sans"
                        | "segoe ui"
                )
            },
        );
    if has_common_font {
        push_design_site(
            sites,
            RuleId::NoCommonRootFont,
            subject_name.clone(),
            "noCommonRootFont",
            tag,
            "Page root uses a generic default font choice.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-default-purple-page-gradient`
    let has_purple_page_gradient = (root_toks
        .iter()
        .any(|u| u.starts_with("bg-gradient-") || u.starts_with("bg-linear-"))
        && root_toks.iter().any(|u| {
            u.starts_with("from-purple-")
                || u.starts_with("from-violet-")
                || u.starts_with("from-indigo-")
                || u.starts_with("via-purple-")
                || u.starts_with("to-purple-")
                || u.starts_with("to-violet-")
                || u.starts_with("to-indigo-")
        }))
        || ["background", "backgroundImage"].iter().any(|p| {
            get_style_prop_str(root_opening, p, semantic, const_strings).is_some_and(|v| {
                let lower = v.to_ascii_lowercase();
                lower.contains("gradient(")
                    && (lower.contains("purple")
                        || lower.contains("violet")
                        || lower.contains("indigo")
                        || lower.contains("#7c3aed")
                        || lower.contains("#6366f1")
                        || lower.contains("#8b5cf6"))
            })
        });
    if has_purple_page_gradient {
        push_design_site(
            sites,
            RuleId::NoDefaultPurplePageGradient,
            subject_name.clone(),
            "noDefaultPurplePageGradient",
            tag,
            "Page root uses a default purple-spectrum gradient.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-default-warm-page-surface`
    let has_warm_page_surface = root_toks.iter().any(|u| {
        matches!(
            *u,
            "bg-amber-50"
                | "bg-orange-50"
                | "bg-yellow-50"
                | "bg-stone-50"
                | "bg-[#faf8f5]"
                | "bg-[#fdfbf7]"
                | "bg-[#f9f6f0]"
        )
    }) || ["backgroundColor", "background"].iter().any(|p| {
        get_style_prop_str(root_opening, p, semantic, const_strings).is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "#faf8f5" | "#fdfbf7" | "#f9f6f0" | "#fffbeb" | "#fefce8" | "#fafaf9"
            )
        })
    });
    if has_warm_page_surface {
        push_design_site(
            sites,
            RuleId::NoDefaultWarmPageSurface,
            subject_name.clone(),
            "noDefaultWarmPageSurface",
            tag,
            "Page defaults to a warm off-white surface.".to_string(),
            loc,
            span,
            None,
        );
    }

    if GENERIC_MARKETING_PHRASES
        .iter()
        .any(|phrase| lower_text.contains(phrase))
    {
        push_design_site(
            sites,
            RuleId::NoGenericMarketingCopy,
            subject_name.clone(),
            "noGenericMarketingCopy",
            tag,
            "Page uses generic marketing copy.".to_string(),
            loc,
            span,
            None,
        );
    }

    if lower_text.contains("jane doe")
        || lower_text.contains("john smith")
        || lower_text.contains("example user")
    {
        push_design_site(
            sites,
            RuleId::NoPlaceholderPersonaCopy,
            subject_name.clone(),
            "noPlaceholderPersonaCopy",
            tag,
            "Page renders a generic placeholder persona (`Jane Doe` / `John Smith`).".to_string(),
            loc,
            span,
            None,
        );
    }

    let contrast_hits = lower_text.matches("not just ").count()
        + lower_text.matches("no busywork").count()
        + lower_text.matches("not a ").count();
    if contrast_hits >= 3 {
        push_design_site(
            sites,
            RuleId::NoManufacturedContrastCopy,
            subject_name.clone(),
            "noManufacturedContrastCopy",
            tag,
            "Page repeatedly uses manufactured contrast copy (`Not X. It is Y.`).".to_string(),
            loc,
            span,
            None,
        );
    }

    let mut stats = PageSubtreeStats::default();
    collect_page_subtree_stats(jsx_el, semantic, const_strings, line_starts, &mut stats);

    if stats.card_count >= 6 {
        push_design_site(
            sites,
            RuleId::NoExcessiveCardSurfaces,
            subject_name.clone(),
            "noExcessiveCardSurfaces",
            tag,
            format!("Page boxes {} groups into cards.", stats.card_count),
            loc,
            span,
            None,
        );
    }
    if stats.centered_paragraph_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoExcessiveCenteredCopy,
            subject_name.clone(),
            "noExcessiveCenteredCopy",
            tag,
            "Page centers 3+ substantial body-copy paragraphs.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.font_families.len() >= 4 {
        push_design_site(
            sites,
            RuleId::NoExcessiveFontFamilies,
            subject_name.clone(),
            "noExcessiveFontFamilies",
            tag,
            "Page mixes 4+ distinct font families.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.pill_count >= 5 {
        push_design_site(
            sites,
            RuleId::NoExcessivePillTreatment,
            subject_name.clone(),
            "noExcessivePillTreatment",
            tag,
            "Page overuses pill-shaped (`rounded-full`) treatments.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.emoji_tile_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedEmojiTiles,
            subject_name.clone(),
            "noRepeatedEmojiTiles",
            tag,
            "Page repeats boxed emoji tiles as feature icons.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.glass_surface_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedGlassSurfaces,
            subject_name.clone(),
            "noRepeatedGlassSurfaces",
            tag,
            "Page repeats blurred translucent glass surfaces.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.hover_scale_sites.len() >= 3
        && let Some((hloc, hspan)) = stats.hover_scale_sites.first().copied()
    {
        push_design_site(
            sites,
            RuleId::NoRepeatedHoverScale,
            subject_name.clone(),
            "noRepeatedHoverScale",
            "hover:scale",
            "Hover scaling repeats across 3+ elements on the page.".to_string(),
            hloc,
            hspan,
            None,
        );
    }
    if stats.section_shell_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedSectionShells,
            subject_name.clone(),
            "noRepeatedSectionShells",
            tag,
            "Page repeats the same large-padding centered max-width section shell.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats
        .section_py_counts
        .values()
        .any(|&count| count >= 4 && stats.section_py_counts.len() == 1)
    {
        push_design_site(
            sites,
            RuleId::NoMonotonousPageSpacing,
            subject_name.clone(),
            "noMonotonousPageSpacing",
            tag,
            "Page repeats one vertical spacing value across all sections.".to_string(),
            loc,
            span,
            None,
        );
    }
}

#[derive(Default)]
pub(super) struct PageSubtreeStats {
    card_count: usize,
    centered_paragraph_count: usize,
    font_families: HashSet<String>,
    pill_count: usize,
    emoji_tile_count: usize,
    glass_surface_count: usize,
    hover_scale_sites: Vec<(SourceLoc, ByteSpan)>,
    section_shell_count: usize,
    section_py_counts: HashMap<String, usize>,
}

fn collect_page_subtree_stats(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    stats: &mut PageSubtreeStats,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    let cls = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let toks: Vec<&str> = cls.split_whitespace().collect();
    let txt = collect_all_static_text(jsx_el);
    let trimmed = txt.trim();

    if is_tailwind_card_tokens(&toks) && toks.iter().any(|t| t.starts_with("p-")) {
        stats.card_count += 1;
    }
    if tag == "p" && trimmed.len() >= 48 && toks.contains(&"text-center") {
        stats.centered_paragraph_count += 1;
    }
    if let Some(ff) = get_style_prop_str(opening, "fontFamily", semantic, const_strings) {
        let first = ff
            .split(',')
            .next()
            .unwrap_or(&ff)
            .trim()
            .to_ascii_lowercase();
        if !first.is_empty() {
            stats.font_families.insert(first);
        }
    }
    if !trimmed.is_empty()
        && trimmed.len() <= 32
        && toks.contains(&"rounded-full")
        && toks.iter().any(|t| t.starts_with("px-"))
    {
        stats.pill_count += 1;
    }
    if starts_with_emoji(trimmed)
        && trimmed.chars().count() <= 2
        && toks.iter().any(|t| t.starts_with("rounded"))
        && toks.iter().any(|t| t.starts_with("bg-"))
    {
        stats.emoji_tile_count += 1;
    }
    if toks.iter().any(|t| t.starts_with("backdrop-blur"))
        && toks.iter().any(|t| t.starts_with("bg-") && t.contains('/'))
    {
        stats.glass_surface_count += 1;
    }
    if toks.iter().any(|t| t.starts_with("hover:scale-")) {
        stats.hover_scale_sites.push((
            loc_from_line_starts(line_starts, opening.span.start),
            ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
        ));
    }
    if tag == "section"
        && toks.iter().any(|t| t.starts_with("py-2"))
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::Element(child_el) = c {
                let c_cls = get_class_name_str(&child_el.opening_element, semantic, const_strings)
                    .unwrap_or_default();
                c_cls.contains("mx-auto") && c_cls.contains("max-w-")
            } else {
                false
            }
        })
    {
        stats.section_shell_count += 1;
    }
    if tag == "section" {
        for &t in &toks {
            let u = t.rsplit(':').next().unwrap_or(t).trim_start_matches('!');
            if u.starts_with("py-") {
                *stats.section_py_counts.entry(u.to_string()).or_insert(0) += 1;
            }
        }
    }

    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_page_subtree_stats(child_el, semantic, const_strings, line_starts, stats);
        }
    }
}
