//! Single-pass UI design (`design` and `react-ui`) rule evaluators and deterministic `Autofix` patches.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

mod page_composition;
mod surfaces_and_interactions;
mod tailwind_and_styles;
mod typography_and_controls;
mod typography_and_hero_patterns;

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{JSXChild, JSXElement, JSXOpeningElement, Program, VariableDeclarationKind},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;
use crate::{
    ir::{
        ByteSpan, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{eval_static_str, get_class_name_str, get_style_prop_number, get_style_prop_str},
    rules::{AutofixPatch, RuleId},
};

use self::{
    tailwind_and_styles::{check_jsx_attribute_design, check_tagged_template_design},
    typography_and_controls::check_jsx_element_design,
};

pub(super) const VAGUE_BUTTON_LABELS: &[&str] = &[
    "continue",
    "submit",
    "ok",
    "okay",
    "click here",
    "here",
    "yes",
    "no",
    "go",
    "done",
    "button",
    "link",
    "more",
];

pub(super) const EXCLUDED_TYPOGRAPHY_TAGS: &[&str] = &[
    "code",
    "pre",
    "kbd",
    "samp",
    "var",
    "tt",
    "markdown",
    "mdx",
    "prose",
    "richtext",
    "blockquote",
    "trans",
    "translation",
];

pub(super) const BLOCK_DEFAULT_TAGS: &[&str] = &[
    "div",
    "p",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "aside",
    "figure",
    "figcaption",
    "blockquote",
    "form",
    "fieldset",
    "address",
    "pre",
    "ul",
    "ol",
    "dl",
    "dt",
    "dd",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
];

pub(super) const INLINE_DEFAULT_TAGS: &[&str] = &[
    "span", "a", "b", "i", "em", "strong", "small", "code", "abbr", "cite", "label", "mark", "q",
    "s", "u", "sub", "sup", "kbd", "samp", "var", "time",
];

pub(super) const LAYOUT_TRANSITION_PROPS: &[&str] = &[
    "width",
    "height",
    "min-width",
    "max-width",
    "min-height",
    "max-height",
    "top",
    "right",
    "bottom",
    "left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "border-width",
];

pub(super) const GENERIC_MARKETING_PHRASES: &[&str] = &[
    "supercharge your workflow",
    "next-generation platform",
    "unlock the power of",
    "revolutionize the way",
    "seamless integration",
    "built for modern teams",
];

pub(super) struct JsxDesignElemCtx<'a, 'b> {
    pub(super) semantic: &'a Semantic<'b>,
    pub(super) node_id: NodeId,
    pub(super) jsx_el: &'a JSXElement<'b>,
    pub(super) opening: &'a JSXOpeningElement<'b>,
    pub(super) tag: &'a str,
    pub(super) tokens: &'a [&'a str],
    pub(super) unvariant_tokens: &'a [&'a str],
    pub(super) trimmed_text: &'a str,
    pub(super) font_size: Option<f64>,
    pub(super) subject_name: &'a Option<String>,
    pub(super) const_strings: &'a HashMap<SymbolId, String>,
    pub(super) loc: SourceLoc,
    pub(super) span: ByteSpan,
    pub(super) line_starts: &'a [u32],
}

/// Extracts all single-pass `design` and `react-ui` rule sites (including deterministic `Autofix` patches).
#[must_use]
pub(crate) fn extract_design_sites(
    path: &std::path::Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<SemanticRuleSite> {
    let _ = program;
    let mut sites = Vec::new();
    let (const_strings, icon_families) = collect_design_module_bindings(semantic);

    if icon_families.len() >= 2 {
        push_design_site(
            &mut sites,
            RuleId::NoMixedIconLibraries,
            None,
            "noMixedIconLibraries",
            "icons",
            "This file mixes multiple icon libraries. Standardize on one icon family so stroke weight and proportions stay consistent.".to_string(),
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
            None,
        );
    }

    let mut did_report_redundant_size_axes = false;
    let mut did_report_z_index_9999 = false;
    let mut kicker_candidates: Vec<(SourceLoc, ByteSpan)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::JSXAttribute(attr) => {
                check_jsx_attribute_design(
                    semantic,
                    node_id,
                    attr,
                    &subject_name,
                    &const_strings,
                    &mut did_report_redundant_size_axes,
                    &mut did_report_z_index_9999,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                check_jsx_element_design(
                    path,
                    semantic,
                    node_id,
                    jsx_el,
                    &subject_name,
                    &const_strings,
                    &mut kicker_candidates,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::TaggedTemplateExpression(tagged) => {
                check_tagged_template_design(
                    semantic,
                    tagged,
                    &subject_name,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::CallExpression(call) if !did_report_z_index_9999 => {
                check_stylesheet_create_z_index(
                    semantic,
                    call,
                    &subject_name,
                    &mut did_report_z_index_9999,
                    line_starts,
                    &mut sites,
                );
            }
            _ => {}
        }
    }

    if kicker_candidates.len() >= 3
        && let Some((loc, span)) = kicker_candidates.first().copied()
    {
        push_design_site(
            &mut sites,
            RuleId::NoRepeatedKickerLabels,
            None,
            "noRepeatedKickerLabels",
            "kicker",
            "The same uppercase tracked kicker repeats across several sections and makes the page feel templated.".to_string(),
            loc,
            span,
            None,
        );
    }

    sites
}

fn collect_design_module_bindings(
    semantic: &Semantic<'_>,
) -> (HashMap<SymbolId, String>, HashSet<String>) {
    let mut const_strings = HashMap::new();
    let mut icon_families = HashSet::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) if !imp.import_kind.is_type() => {
                let src = imp.source.value.as_str().unwrap_or_default();
                if let Some(fam) = classify_icon_library_family(src)
                    && imp.specifiers.as_ref().is_some_and(|s| !s.is_empty())
                {
                    icon_families.insert(fam.to_string());
                }
            }
            AstKind::VariableDeclaration(var_decl)
                if var_decl.kind == VariableDeclarationKind::Const =>
            {
                for decl in &var_decl.declarations {
                    if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &decl.id
                        && let Some(sym_id) = id.symbol_id.get()
                        && let Some(init) = &decl.init
                        && let Some(val) = eval_static_str(semantic, init, &const_strings)
                    {
                        const_strings.insert(sym_id, val);
                    }
                }
            }
            _ => {}
        }
    }
    (const_strings, icon_families)
}

fn check_stylesheet_create_z_index(
    semantic: &Semantic<'_>,
    call: &oxc_ast::ast::CallExpression<'_>,
    subject_name: &Option<String>,
    did_report_z_index_9999: &mut bool,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !call
        .callee
        .span()
        .source_text(semantic.source_text())
        .contains("StyleSheet.create")
    {
        return;
    }
    let call_src = call.span.source_text(semantic.source_text());
    if call_src.contains("zIndex: 9999") || call_src.contains("zIndex: 1000") {
        *did_report_z_index_9999 = true;
        push_design_site(
            sites,
            RuleId::NoZIndex9999,
            subject_name.clone(),
            "noZIndex9999",
            "zIndex",
            "z-index is unusually high and can hide a layering bug instead of fixing it."
                .to_string(),
            loc_from_line_starts(line_starts, call.span.start),
            ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            None,
        );
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a SemanticRuleSite with optional AutofixPatch directly"
)]
pub(super) fn push_design_site(
    out: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
    autofix: Option<AutofixPatch>,
) {
    out.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix,
    });
}

fn classify_icon_library_family(source: &str) -> Option<&str> {
    if source == "lucide-react" {
        Some("lucide")
    } else if source.starts_with("@heroicons/") {
        Some("heroicons")
    } else if source.starts_with("@radix-ui/react-icons") {
        Some("radix-icons")
    } else if source.starts_with("@tabler/icons") {
        Some("tabler")
    } else if source.starts_with("phosphor-react") || source.starts_with("@phosphor-icons/") {
        Some("phosphor")
    } else if source.starts_with("react-icons/") {
        Some(source)
    } else {
        None
    }
}

pub(super) fn parse_px_or_rem(val: &str) -> Option<f64> {
    let t = val.trim().to_ascii_lowercase();
    if let Some(px) = t.strip_suffix("px") {
        px.parse::<f64>().ok()
    } else if let Some(rem) = t.strip_suffix("rem") {
        rem.parse::<f64>().ok().map(|v| v * 16.0)
    } else {
        t.parse::<f64>().ok()
    }
}

pub(super) fn parse_tailwind_size_px(utility: &str) -> Option<f64> {
    let val = utility
        .strip_prefix("size-")
        .or_else(|| utility.strip_prefix("w-"))
        .or_else(|| utility.strip_prefix("h-"))?;
    if val == "px" {
        return Some(1.0);
    }
    if let Some(inner) = val.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return parse_px_or_rem(inner);
    }
    val.parse::<f64>().ok().map(|n| n * 4.0)
}

pub(super) fn collect_all_static_text(jsx_el: &JSXElement<'_>) -> String {
    let mut out = String::new();
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) => {
                out.push_str(t.value.as_str());
                out.push(' ');
            }
            JSXChild::Element(el) => {
                out.push_str(&collect_all_static_text(el));
                out.push(' ');
            }
            JSXChild::Fragment(frag) => {
                for fc in &frag.children {
                    if let JSXChild::Element(el) = fc {
                        out.push_str(&collect_all_static_text(el));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub(super) fn starts_with_emoji(s: &str) -> bool {
    let Some(first_ch) = s.chars().next() else {
        return false;
    };
    let code = u32::from(first_ch);
    (0x1F300..=0x1FAFF).contains(&code) || (0x2600..=0x27BF).contains(&code)
}

pub(super) fn is_tailwind_card_tokens(tokens: &[&str]) -> bool {
    let has_round = tokens
        .iter()
        .any(|t| *t == "rounded" || t.starts_with("rounded-"));
    let has_edge_or_bg = tokens.iter().any(|t| {
        *t == "border"
            || t.starts_with("border-")
            || t.starts_with("shadow")
            || t.starts_with("ring")
            || (t.starts_with("bg-") && *t != "bg-transparent")
    });
    has_round && has_edge_or_bg
}

pub(super) fn has_duration_over_1000ms(val: &str) -> bool {
    for tok in val.split(|c: char| c.is_whitespace() || c == ',') {
        if let Some(ms_str) = tok.strip_suffix("ms") {
            if ms_str.parse::<f64>().is_ok_and(|ms| ms > 1000.0) {
                return true;
            }
        } else if let Some(s_str) = tok.strip_suffix('s')
            && s_str.parse::<f64>().is_ok_and(|s| s > 1.0)
        {
            return true;
        }
    }
    false
}

pub(super) fn parse_hex_or_rgb_color(val: &str) -> Option<(f64, f64, f64)> {
    let t = val.trim().to_ascii_lowercase();
    if let Some(hex) = t.strip_prefix('#') {
        if hex.len() == 3 {
            let r = u8::from_str_radix(hex.get(0..1)?, 16).ok()? * 17;
            let g = u8::from_str_radix(hex.get(1..2)?, 16).ok()? * 17;
            let b = u8::from_str_radix(hex.get(2..3)?, 16).ok()? * 17;
            return Some((f64::from(r), f64::from(g), f64::from(b)));
        } else if hex.len() == 6 {
            let r = u8::from_str_radix(hex.get(0..2)?, 16).ok()?;
            let g = u8::from_str_radix(hex.get(2..4)?, 16).ok()?;
            let b = u8::from_str_radix(hex.get(4..6)?, 16).ok()?;
            return Some((f64::from(r), f64::from(g), f64::from(b)));
        }
    }
    if let Some(inner) = t
        .strip_prefix("rgb(")
        .or_else(|| t.strip_prefix("rgba("))
        .and_then(|s| s.strip_suffix(')'))
    {
        let nums: Vec<f64> = inner
            .split([',', ' ', '/'])
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<f64>().ok())
            .collect();
        if let &[r, g, b, ..] = nums.as_slice() {
            return Some((r, g, b));
        }
    }
    None
}

pub(super) fn wcag_contrast_ratio(fg: (f64, f64, f64), bg: (f64, f64, f64)) -> f64 {
    let lin = |c: f64| -> f64 {
        let n = c / 255.0;
        if n <= 0.03928 {
            n / 12.92
        } else {
            ((n + 0.055) / 1.055).powf(2.4)
        }
    };
    let lum = |(r, g, b): (f64, f64, f64)| 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    let l1 = lum(fg);
    let l2 = lum(bg);
    (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
}

pub(super) fn has_responsive_axis_prefix(tokens: &[&str], axis: &str) -> bool {
    let suffix = format!(":{axis}-");
    tokens.iter().any(|t| t.contains(&suffix))
}

pub(super) fn collect_matching_axis_values(
    tokens: &[&str],
    prefix_a: &str,
    prefix_b: &str,
) -> Vec<String> {
    let mut a_vals: Vec<&str> = Vec::new();
    for &t in tokens {
        if let Some(val) = t.strip_prefix(prefix_a)
            && !val.is_empty()
        {
            a_vals.push(val);
        }
    }
    let mut matched = Vec::new();
    for &t in tokens {
        if let Some(val) = t.strip_prefix(prefix_b)
            && a_vals.contains(&val)
            && !matched.iter().any(|m: &String| m == val)
        {
            matched.push(val.to_string());
        }
    }
    matched
}

const TAILWIND_FONT_SIZE_PX: &[(&str, f64)] = &[
    ("text-xs", 12.0),
    ("text-sm", 14.0),
    ("text-base", 16.0),
    ("text-lg", 18.0),
    ("text-xl", 20.0),
    ("text-2xl", 24.0),
    ("text-3xl", 30.0),
    ("text-4xl", 36.0),
    ("text-5xl", 48.0),
    ("text-6xl", 60.0),
    ("text-7xl", 72.0),
    ("text-8xl", 96.0),
    ("text-9xl", 128.0),
];

pub(super) fn resolve_element_font_size_px(
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
        if let Some(px) = TAILWIND_FONT_SIZE_PX
            .iter()
            .find_map(|&(tok, px)| (tok == u).then_some(px))
            .or_else(|| {
                u.strip_prefix("text-[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(parse_px_or_rem)
            })
        {
            return Some(px);
        }
    }
    None
}

pub(super) fn collect_subtree_font_sizes(
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use crate::{ir::types::compute_line_starts, rules::RuleId};

    use super::extract_design_sites;

    fn run_extract(source: &str) -> Vec<crate::ir::types::SemanticRuleSite> {
        let path = Path::new("src/Component.tsx");
        let allocator = Allocator::default();
        let source_type = SourceType::from_path(path)
            .unwrap_or_default()
            .with_jsx(true)
            .with_module(true);
        let parsed = Parser::new(&allocator, source, source_type).parse();
        let semantic = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let line_starts = compute_line_starts(source);
        extract_design_sites(path, &parsed.program, &semantic, &line_starts)
    }

    #[test]
    fn extracts_tailwind_and_inline_style_design_sites_with_autofix() {
        let sites = run_extract(
            r##"
            export function Box() {
                return (
                    <div
                        className="px-4 py-4 flex"
                        style={{ zIndex: 9999, color: "#777777", backgroundColor: "#888888" }}
                    />
                );
            }
            "##,
        );
        let pad_site = sites
            .iter()
            .find(|s| s.rule == RuleId::DesignNoRedundantPaddingAxes)
            .expect("expected DesignNoRedundantPaddingAxes");
        assert_eq!(pad_site.target_name, "p-4");
        assert_eq!(
            pad_site
                .autofix
                .as_ref()
                .and_then(|fix| fix.edits.first())
                .map(|e| e.replacement.as_str()),
            Some("p-4 flex")
        );
        assert!(sites.iter().any(|s| s.rule == RuleId::NoZIndex9999));
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoLowContrastInlineStyle)
        );
    }

    #[test]
    fn extracts_typography_and_control_design_sites() {
        let sites = run_extract(
            r#"
            export function Controls() {
                return (
                    <div className="block">
                        <button>Submit</button>
                        <p>Loading... please wait for the next step — it will finish shortly now.</p>
                    </div>
                );
            }
            "#,
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoRedundantDisplayClass && s.autofix.is_some())
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::DesignNoVagueButtonLabel)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::DesignNoThreePeriodEllipsis && s.autofix.is_some())
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::DesignNoEmDashInJsxText && s.autofix.is_some())
        );
    }

    #[test]
    fn extracts_surface_and_interaction_design_sites() {
        let sites = run_extract(
            r#"
            export function Surface() {
                return (
                    <div className="rounded-lg border p-4">
                        <div className="rounded-md bg-slate-100 p-2">
                            <span className="cursor-pointer">Inert label</span>
                        </div>
                    </div>
                );
            }
            "#,
        );
        assert!(sites.iter().any(|s| s.rule == RuleId::NoNestedCardSurface));
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoInertPointerAffordance)
        );
    }

    #[test]
    fn extracts_page_composition_design_sites() {
        let sites = run_extract(
            r#"
            export function LandingPage() {
                return (
                    <main className="font-sans bg-amber-50">
                        <h1>Supercharge your workflow</h1>
                        <p>Signed in as Jane Doe</p>
                    </main>
                );
            }
            "#,
        );
        assert!(sites.iter().any(|s| s.rule == RuleId::NoCommonRootFont));
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoDefaultWarmPageSurface)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoGenericMarketingCopy)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoPlaceholderPersonaCopy)
        );
    }
}
