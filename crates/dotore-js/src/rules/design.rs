//! Single-pass UI design (`design` and `react-ui`) rule evaluators and deterministic `Autofix` patches.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

mod page_composition;
mod surfaces_and_interactions;
mod tailwind_and_styles;
mod typography_and_controls;

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{JSXChild, JSXElement, Program, VariableDeclarationKind},
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{eval_static_str, push_semantic_site_with_fix},
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

/// Extracts all single-pass `design` and `react-ui` rule sites (including deterministic `Autofix` patches).
#[must_use]
pub(crate) fn extract_design_sites(
    path: &std::path::Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<SemanticRuleSite> {
    let mut sites = Vec::new();
    let mut const_strings: HashMap<SymbolId, String> = HashMap::new();
    let mut icon_families: HashSet<String> = HashSet::new();

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
            AstKind::CallExpression(call)
                if !did_report_z_index_9999
                    && call
                        .callee
                        .span()
                        .source_text(semantic.source_text())
                        .contains("StyleSheet.create") =>
            {
                let call_src = call.span.source_text(semantic.source_text());
                if call_src.contains("zIndex: 9999") || call_src.contains("zIndex: 1000") {
                    did_report_z_index_9999 = true;
                    let loc = loc_from_line_starts(line_starts, call.span.start);
                    let span = ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    };
                    push_design_site(
                        &mut sites,
                        RuleId::NoZIndex9999,
                        subject_name.clone(),
                        "noZIndex9999",
                        "zIndex",
                        "z-index is unusually high and can hide a layering bug instead of fixing it.".to_string(),
                        loc,
                        span,
                        None,
                    );
                }
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

    let _ = program;
    sites
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
    let line_starts = [0_u32];
    push_semantic_site_with_fix(
        out,
        rule,
        subject_name,
        message_id,
        target_name,
        message,
        &line_starts,
        Span::new(span.start, span.end),
        autofix,
    );
    if let Some(site) = out.last_mut() {
        site.loc = loc;
    }
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
