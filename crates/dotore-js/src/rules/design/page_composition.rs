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
    reason = "Evaluates page-level composition and copy design rules on <main>/<article> roots (#50)"
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
    check_page_root_font_and_surface(
        jsx_el,
        tag,
        semantic,
        const_strings,
        subject_name,
        loc,
        span,
        sites,
    );
    check_page_root_marketing_copy(tag, trimmed_text, subject_name, loc, span, sites);

    let mut stats = PageSubtreeStats::default();
    collect_page_subtree_stats(jsx_el, semantic, const_strings, line_starts, &mut stats);
    emit_page_subtree_stat_findings(tag, &stats, subject_name, loc, span, sites);
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks root font, gradient, and warm surface styling on a <main>/<article> root (#50)"
)]
fn check_page_root_font_and_surface(
    jsx_el: &JSXElement<'_>,
    tag: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let root_opening = &jsx_el.opening_element;
    let root_cls = get_class_name_str(root_opening, semantic, const_strings).unwrap_or_default();
    let root_toks: Vec<&str> = root_cls
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();

    if has_common_root_font(root_opening, &root_toks, semantic, const_strings) {
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

    if has_purple_page_gradient(root_opening, &root_toks, semantic, const_strings) {
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

    if has_warm_page_surface(root_opening, &root_toks, semantic, const_strings) {
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
}

fn has_common_root_font(
    root_opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    root_toks: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    root_toks.contains(&"font-sans")
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
        )
}

fn has_purple_page_gradient(
    root_opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    root_toks: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    (root_toks
        .iter()
        .any(|u| u.starts_with("bg-gradient-") || u.starts_with("bg-linear-"))
        && root_toks.iter().any(|u| {
            [
                "from-purple-",
                "from-violet-",
                "from-indigo-",
                "via-purple-",
                "to-purple-",
                "to-violet-",
                "to-indigo-",
            ]
            .iter()
            .any(|p| u.starts_with(p))
        }))
        || ["background", "backgroundImage"].iter().any(|p| {
            get_style_prop_str(root_opening, p, semantic, const_strings).is_some_and(|v| {
                let lower = v.to_ascii_lowercase();
                lower.contains("gradient(")
                    && ["purple", "violet", "indigo", "#7c3aed", "#6366f1", "#8b5cf6"]
                        .iter()
                        .any(|c| lower.contains(c))
            })
        })
}

fn has_warm_page_surface(
    root_opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    root_toks: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    root_toks.iter().any(|u| {
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
    })
}

fn check_page_root_marketing_copy(
    tag: &str,
    trimmed_text: &str,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let lower_text = trimmed_text.to_ascii_lowercase();
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
}

fn emit_page_subtree_stat_findings(
    tag: &str,
    stats: &PageSubtreeStats,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
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
    for (cond, rule, msg_id, msg) in [
        (
            stats.centered_paragraph_count >= 3,
            RuleId::NoExcessiveCenteredCopy,
            "noExcessiveCenteredCopy",
            "Page centers 3+ substantial body-copy paragraphs.",
        ),
        (
            stats.font_families.len() >= 4,
            RuleId::NoExcessiveFontFamilies,
            "noExcessiveFontFamilies",
            "Page mixes 4+ distinct font families.",
        ),
        (
            stats.pill_count >= 5,
            RuleId::NoExcessivePillTreatment,
            "noExcessivePillTreatment",
            "Page overuses pill-shaped (`rounded-full`) treatments.",
        ),
        (
            stats.emoji_tile_count >= 3,
            RuleId::NoRepeatedEmojiTiles,
            "noRepeatedEmojiTiles",
            "Page repeats boxed emoji tiles as feature icons.",
        ),
        (
            stats.glass_surface_count >= 3,
            RuleId::NoRepeatedGlassSurfaces,
            "noRepeatedGlassSurfaces",
            "Page repeats blurred translucent glass surfaces.",
        ),
        (
            stats.section_shell_count >= 3,
            RuleId::NoRepeatedSectionShells,
            "noRepeatedSectionShells",
            "Page repeats the same large-padding centered max-width section shell.",
        ),
        (
            stats.section_py_counts.len() == 1
                && stats.section_py_counts.values().any(|&count| count >= 4),
            RuleId::NoMonotonousPageSpacing,
            "noMonotonousPageSpacing",
            "Page repeats one vertical spacing value across all sections.",
        ),
    ] {
        if cond {
            push_design_site(
                sites,
                rule,
                subject_name.clone(),
                msg_id,
                tag,
                msg.to_string(),
                loc,
                span,
                None,
            );
        }
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
}

#[derive(Default)]
struct PageSubtreeStats {
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
    record_element_page_stats(jsx_el, semantic, const_strings, line_starts, stats);
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_page_subtree_stats(child_el, semantic, const_strings, line_starts, stats);
        }
    }
}

fn record_element_page_stats(
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

    record_card_pill_and_emoji_stats(&tag, trimmed, &toks, stats);
    record_font_glass_and_hover_stats(opening, &toks, semantic, const_strings, line_starts, stats);
    if tag == "section" {
        record_section_shell_and_spacing_stats(jsx_el, &toks, semantic, const_strings, stats);
    }
}

fn record_card_pill_and_emoji_stats(
    tag: &str,
    trimmed: &str,
    toks: &[&str],
    stats: &mut PageSubtreeStats,
) {
    if is_tailwind_card_tokens(toks) && toks.iter().any(|t| t.starts_with("p-")) {
        stats.card_count += 1;
    }
    if tag == "p" && trimmed.len() >= 48 && toks.contains(&"text-center") {
        stats.centered_paragraph_count += 1;
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
}

fn record_font_glass_and_hover_stats(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    toks: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    stats: &mut PageSubtreeStats,
) {
    if let Some(ff) = get_style_prop_str(opening, "fontFamily", semantic, const_strings) {
        let first = ff.split(',').next().unwrap_or(&ff).trim().to_ascii_lowercase();
        if !first.is_empty() {
            stats.font_families.insert(first);
        }
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
}

fn record_section_shell_and_spacing_stats(
    jsx_el: &JSXElement<'_>,
    toks: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    stats: &mut PageSubtreeStats,
) {
    if toks.iter().any(|t| t.starts_with("py-2"))
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
    for &t in toks {
        let u = t.rsplit(':').next().unwrap_or(t).trim_start_matches('!');
        if u.starts_with("py-") {
            *stats.section_py_counts.entry(u.to_string()).or_insert(0) += 1;
        }
    }
}
