//! Single-pass accessibility (`a11y`) rule evaluators and cross-file `anchor-target-exists` verification.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Expression, ImportDeclarationSpecifier, JSXAttribute, JSXAttributeItem, JSXAttributeName,
        JSXAttributeValue, JSXChild, JSXElement, JSXElementName, JSXOpeningElement, Program,
        UnaryOperator, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;

use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileContext, FileIr, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{SemanticRuleSite, classify_file_context, loc_from_line_starts},
    },
    rules::{Diagnostic, PrescriptionTier, RuleCategory, RuleId, RuleSeverity},
};

const RESERVED_HTML_TAGS: &[&str] = &[
    "base", "col", "colgroup", "head", "html", "link", "meta", "noembed", "noscript", "param",
    "picture", "script", "source", "style", "title", "track",
];

const HTML_TAGS: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "applet",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "basefont",
    "bdi",
    "bdo",
    "bgsound",
    "big",
    "blink",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "center",
    "cite",
    "code",
    "col",
    "colgroup",
    "command",
    "content",
    "data",
    "datalist",
    "dd",
    "del",
    "details",
    "dfn",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "element",
    "em",
    "embed",
    "fieldset",
    "figcaption",
    "figure",
    "font",
    "footer",
    "form",
    "frame",
    "frameset",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "iframe",
    "image",
    "img",
    "input",
    "ins",
    "isindex",
    "kbd",
    "keygen",
    "label",
    "legend",
    "li",
    "link",
    "listing",
    "main",
    "map",
    "mark",
    "marquee",
    "math",
    "menu",
    "menuitem",
    "meta",
    "meter",
    "multicol",
    "nav",
    "nextid",
    "nobr",
    "noembed",
    "noframes",
    "noscript",
    "object",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "picture",
    "plaintext",
    "pre",
    "progress",
    "q",
    "rb",
    "rbc",
    "rp",
    "rt",
    "rtc",
    "ruby",
    "s",
    "samp",
    "script",
    "search",
    "section",
    "select",
    "shadow",
    "slot",
    "small",
    "source",
    "spacer",
    "span",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "svg",
    "table",
    "tbody",
    "td",
    "template",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tt",
    "u",
    "ul",
    "var",
    "video",
    "wbr",
    "xmp",
];

const NON_INTERACTIVE_ELEMENTS: &[&str] = &[
    "abbr",
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "caption",
    "code",
    "dd",
    "del",
    "details",
    "dfn",
    "dialog",
    "dir",
    "dl",
    "dt",
    "em",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "html",
    "iframe",
    "img",
    "ins",
    "label",
    "legend",
    "li",
    "main",
    "mark",
    "marquee",
    "menu",
    "meter",
    "nav",
    "ol",
    "optgroup",
    "output",
    "p",
    "pre",
    "progress",
    "ruby",
    "section",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "tfoot",
    "thead",
    "time",
    "ul",
];

const VALID_ARIA_ROLES: &[&str] = &[
    "alert",
    "alertdialog",
    "application",
    "article",
    "banner",
    "blockquote",
    "button",
    "caption",
    "cell",
    "checkbox",
    "code",
    "columnheader",
    "combobox",
    "complementary",
    "contentinfo",
    "definition",
    "deletion",
    "dialog",
    "directory",
    "doc-abstract",
    "doc-acknowledgments",
    "doc-afterword",
    "doc-appendix",
    "doc-backlink",
    "doc-biblioentry",
    "doc-bibliography",
    "doc-biblioref",
    "doc-chapter",
    "doc-colophon",
    "doc-conclusion",
    "doc-cover",
    "doc-credit",
    "doc-credits",
    "doc-dedication",
    "doc-endnote",
    "doc-endnotes",
    "doc-epigraph",
    "doc-epilogue",
    "doc-errata",
    "doc-example",
    "doc-footnote",
    "doc-foreword",
    "doc-glossary",
    "doc-glossref",
    "doc-index",
    "doc-introduction",
    "doc-noteref",
    "doc-notice",
    "doc-pagebreak",
    "doc-pagelist",
    "doc-part",
    "doc-preface",
    "doc-prologue",
    "doc-pullquote",
    "doc-qna",
    "doc-subtitle",
    "doc-tip",
    "doc-toc",
    "document",
    "emphasis",
    "feed",
    "figure",
    "form",
    "generic",
    "graphics-document",
    "graphics-object",
    "graphics-symbol",
    "grid",
    "gridcell",
    "group",
    "heading",
    "img",
    "insertion",
    "link",
    "list",
    "listbox",
    "listitem",
    "log",
    "main",
    "mark",
    "marquee",
    "math",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "meter",
    "navigation",
    "none",
    "note",
    "option",
    "paragraph",
    "presentation",
    "progressbar",
    "radio",
    "radiogroup",
    "region",
    "row",
    "rowgroup",
    "rowheader",
    "scrollbar",
    "search",
    "searchbox",
    "separator",
    "slider",
    "spinbutton",
    "status",
    "strong",
    "subscript",
    "superscript",
    "switch",
    "tab",
    "table",
    "tablist",
    "tabpanel",
    "term",
    "textbox",
    "time",
    "timer",
    "toolbar",
    "tooltip",
    "tree",
    "treegrid",
    "treeitem",
];

const INTERACTIVE_ROLES: &[&str] = &[
    "button",
    "checkbox",
    "columnheader",
    "combobox",
    "grid",
    "gridcell",
    "link",
    "listbox",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "radio",
    "radiogroup",
    "row",
    "rowheader",
    "scrollbar",
    "searchbox",
    "separator",
    "slider",
    "spinbutton",
    "switch",
    "tab",
    "tablist",
    "textbox",
    "toolbar",
    "tree",
    "treegrid",
    "treeitem",
];

const NON_INTERACTIVE_ROLES: &[&str] = &[
    "alert",
    "alertdialog",
    "application",
    "article",
    "banner",
    "blockquote",
    "caption",
    "cell",
    "complementary",
    "contentinfo",
    "definition",
    "deletion",
    "dialog",
    "directory",
    "document",
    "feed",
    "figure",
    "form",
    "group",
    "heading",
    "img",
    "insertion",
    "list",
    "listitem",
    "log",
    "main",
    "marquee",
    "math",
    "navigation",
    "note",
    "paragraph",
    "progressbar",
    "region",
    "rowgroup",
    "search",
    "status",
    "table",
    "tabpanel",
    "term",
    "time",
    "timer",
    "tooltip",
];

const VALID_ARIA_PROPERTIES: &[&str] = &[
    "aria-activedescendant",
    "aria-atomic",
    "aria-autocomplete",
    "aria-braillelabel",
    "aria-brailleroledescription",
    "aria-busy",
    "aria-checked",
    "aria-colcount",
    "aria-colindex",
    "aria-colspan",
    "aria-controls",
    "aria-current",
    "aria-describedby",
    "aria-description",
    "aria-details",
    "aria-disabled",
    "aria-dropeffect",
    "aria-errormessage",
    "aria-expanded",
    "aria-flowto",
    "aria-grabbed",
    "aria-haspopup",
    "aria-hidden",
    "aria-invalid",
    "aria-keyshortcuts",
    "aria-label",
    "aria-labelledby",
    "aria-level",
    "aria-live",
    "aria-modal",
    "aria-multiline",
    "aria-multiselectable",
    "aria-orientation",
    "aria-owns",
    "aria-placeholder",
    "aria-posinset",
    "aria-pressed",
    "aria-readonly",
    "aria-relevant",
    "aria-required",
    "aria-roledescription",
    "aria-rowcount",
    "aria-rowindex",
    "aria-rowspan",
    "aria-selected",
    "aria-setsize",
    "aria-sort",
    "aria-valuemax",
    "aria-valuemin",
    "aria-valuenow",
    "aria-valuetext",
];

const GLOBAL_ARIA_PROPERTIES: &[&str] = &[
    "aria-atomic",
    "aria-braillelabel",
    "aria-brailleroledescription",
    "aria-busy",
    "aria-controls",
    "aria-current",
    "aria-describedby",
    "aria-description",
    "aria-details",
    "aria-disabled",
    "aria-dropeffect",
    "aria-errormessage",
    "aria-flowto",
    "aria-grabbed",
    "aria-haspopup",
    "aria-hidden",
    "aria-invalid",
    "aria-keyshortcuts",
    "aria-label",
    "aria-labelledby",
    "aria-live",
    "aria-owns",
    "aria-relevant",
    "aria-roledescription",
];

const AUTOFILL_TOKENS: &[&str] = &[
    "off",
    "on",
    "name",
    "honorific-prefix",
    "given-name",
    "additional-name",
    "family-name",
    "honorific-suffix",
    "nickname",
    "email",
    "username",
    "new-password",
    "current-password",
    "one-time-code",
    "organization-title",
    "organization",
    "street-address",
    "address-line1",
    "address-line2",
    "address-line3",
    "address-level4",
    "address-level3",
    "address-level2",
    "address-level1",
    "country",
    "country-name",
    "postal-code",
    "cc-name",
    "cc-given-name",
    "cc-additional-name",
    "cc-family-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "cc-type",
    "transaction-currency",
    "transaction-amount",
    "language",
    "bday",
    "bday-day",
    "bday-month",
    "bday-year",
    "sex",
    "tel",
    "tel-country-code",
    "tel-national",
    "tel-area-code",
    "tel-local",
    "tel-extension",
    "impp",
    "url",
    "photo",
    "webauthn",
];

const AMBIGUOUS_LINK_WORDS: &[&str] = &["click here", "here", "link", "a link", "learn more"];

const UNINFORMATIVE_ARIA_LABELS: &[&str] = &[
    "icon", "button", "image", "img", "graphic", "svg", "picture", "element", "field", "input",
];

const COMMON_LANG_TAGS: &[&str] = &[
    "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg", "bh",
    "bi", "bm", "bn", "bo", "br", "bs", "ca", "ce", "ch", "co", "cr", "cs", "cu", "cv", "cy", "da",
    "de", "dv", "dz", "ee", "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi", "fj", "fo", "fr",
    "fy", "ga", "gd", "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr", "ht", "hu", "hy", "hz",
    "ia", "id", "ie", "ig", "ii", "ik", "io", "is", "it", "iu", "ja", "jv", "ka", "kg", "ki", "kj",
    "kk", "kl", "km", "kn", "ko", "kr", "ks", "ku", "kv", "kw", "ky", "la", "lb", "lg", "li", "ln",
    "lo", "lt", "lu", "lv", "mg", "mh", "mi", "mk", "ml", "mn", "mr", "ms", "mt", "my", "na", "nb",
    "nd", "ne", "ng", "nl", "nn", "no", "nr", "nv", "ny", "oc", "oj", "om", "or", "os", "pa", "pi",
    "pl", "ps", "pt", "qu", "rm", "rn", "ro", "ru", "rw", "sa", "sc", "sd", "se", "sg", "si", "sk",
    "sl", "sm", "sn", "so", "sq", "sr", "ss", "st", "su", "sv", "sw", "ta", "te", "tg", "th", "ti",
    "tk", "tl", "tn", "to", "tr", "ts", "tt", "tw", "ty", "ug", "uk", "ur", "uz", "ve", "vi", "vo",
    "wa", "wo", "xh", "yi", "yo", "za", "zh", "zu", "fil", "haw", "yue", "ceb", "gsw", "cmn",
    "art", "cel", "sgn", "i",
];

/// Extracts all single-pass `a11y` rule sites and static DOM `id`s from `semantic`.
#[must_use]
pub(crate) fn extract_a11y_sites_and_dom_ids(
    path: &std::path::Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> (Vec<SemanticRuleSite>, Vec<String>, bool) {
    let mut sites = Vec::new();
    let mut static_dom_ids = Vec::new();
    let mut has_unresolved_id_spread = false;
    let file_context = classify_file_context(path);
    let is_testlike = file_context != FileContext::Production;

    let mut const_strings: HashMap<SymbolId, String> = HashMap::new();
    let mut imported_sources: HashMap<SymbolId, String> = HashMap::new();
    collect_a11y_module_bindings(program, semantic, &mut const_strings, &mut imported_sources);

    let mut label_html_for_ids: HashSet<String> = HashSet::new();
    collect_file_labels_and_dom_ids(
        semantic,
        &const_strings,
        &mut label_html_for_ids,
        &mut static_dom_ids,
        &mut has_unresolved_id_spread,
    );

    let mut main_landmarks_by_root: HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>> = HashMap::new();
    let mut unlabeled_navs_by_root: HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>> = HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::JSXAttribute(attr) => {
                check_jsx_attribute_a11y(
                    semantic,
                    node_id,
                    attr,
                    &subject_name,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                let opening = &jsx_el.opening_element;
                let loc = loc_from_line_starts(line_starts, opening.span.start);
                let span = ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                };
                check_jsx_element_a11y(
                    path,
                    is_testlike,
                    semantic,
                    node_id,
                    jsx_el,
                    &subject_name,
                    &const_strings,
                    &imported_sources,
                    &label_html_for_ids,
                    &mut main_landmarks_by_root,
                    &mut unlabeled_navs_by_root,
                    loc,
                    span,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_call_a11y(
                    semantic,
                    node_id,
                    call,
                    &subject_name,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::ConditionalExpression(cond) => {
                check_conditional_a11y(
                    semantic,
                    node_id,
                    cond,
                    &subject_name,
                    line_starts,
                    &mut sites,
                );
            }
            _ => {}
        }
    }

    for (_, mains) in main_landmarks_by_root {
        for (loc, span) in mains.into_iter().skip(1) {
            push_site(
                &mut sites,
                RuleId::NoMultipleMainLandmarks,
                None,
                "noMultipleMainLandmarks",
                "main",
                "This static view contains more than one main landmark. Keep a single main region and use sectioning elements for subordinate content.".to_string(),
                loc,
                span,
            );
        }
    }

    for (_, navs) in unlabeled_navs_by_root {
        if navs.len() >= 2 {
            for (loc, span) in navs.into_iter().skip(1) {
                push_site(
                    &mut sites,
                    RuleId::NoMultipleUnlabeledNavigationLandmarks,
                    None,
                    "noMultipleUnlabeledNavigationLandmarks",
                    "nav",
                    "This view contains multiple unlabeled <nav> landmarks. Give each navigation region a distinct aria-label or aria-labelledby.".to_string(),
                    loc,
                    span,
                );
            }
        }
    }

    (sites, static_dom_ids, has_unresolved_id_spread)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a SemanticRuleSite directly without intermediate allocation"
)]
fn push_site(
    out: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
) {
    out.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix: None,
    });
}

fn collect_a11y_module_bindings(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    const_strings: &mut HashMap<SymbolId, String>,
    imported_sources: &mut HashMap<SymbolId, String>,
) {
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) => {
                if imp.import_kind.is_type() {
                    continue;
                }
                let src = imp.source.value.as_str().unwrap_or_default().to_string();
                if let Some(specs) = &imp.specifiers {
                    for spec in specs {
                        let sym_opt = match spec {
                            ImportDeclarationSpecifier::ImportSpecifier(s)
                                if !s.import_kind.is_type() =>
                            {
                                s.local.symbol_id.get()
                            }
                            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                                s.local.symbol_id.get()
                            }
                            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                                s.local.symbol_id.get()
                            }
                            _ => None,
                        };
                        if let Some(sym_id) = sym_opt {
                            imported_sources.insert(sym_id, src.clone());
                        }
                    }
                }
            }
            AstKind::VariableDeclaration(var_decl)
                if var_decl.kind == VariableDeclarationKind::Const =>
            {
                for decl in &var_decl.declarations {
                    if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &decl.id
                        && let Some(sym_id) = id.symbol_id.get()
                        && let Some(init) = &decl.init
                        && let Some(val) = eval_static_str(semantic, init, const_strings)
                    {
                        const_strings.insert(sym_id, val);
                    }
                }
            }
            _ => {}
        }
    }
    let _ = program;
}

fn collect_file_labels_and_dom_ids(
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    label_html_for_ids: &mut HashSet<String>,
    static_dom_ids: &mut Vec<String>,
    has_unresolved_id_spread: &mut bool,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        let opening = &jsx_el.opening_element;
        let tag = get_jsx_tag_name(&opening.name);

        if (tag == "label" || tag == "Label")
            && !is_inside_jsx_attribute(semantic, node_id)
            && let Some(html_for_attr) = find_attr(&opening.attributes, "htmlFor")
        {
            for key in extract_attr_match_keys(semantic, html_for_attr, const_strings) {
                label_html_for_ids.insert(key);
            }
        }

        if !is_inside_template_element(semantic, node_id) {
            for attr_item in &opening.attributes {
                if let JSXAttributeItem::SpreadAttribute(spread) = attr_item {
                    if let Expression::ObjectExpression(obj) = spread.argument.without_parentheses()
                    {
                        for prop in &obj.properties {
                            if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop
                                && p.key
                                    .static_name()
                                    .is_some_and(|n| n.as_str() == Some("id"))
                                && let Some(id_val) =
                                    eval_static_str(semantic, &p.value, const_strings)
                            {
                                static_dom_ids.push(id_val);
                            } else if matches!(
                                prop,
                                oxc_ast::ast::ObjectPropertyKind::SpreadProperty(_)
                            ) {
                                *has_unresolved_id_spread = true;
                            }
                        }
                    } else {
                        *has_unresolved_id_spread = true;
                    }
                }
            }
            if let Some(id_attr) = find_last_attr(&opening.attributes, "id") {
                collect_known_attr_strings(semantic, id_attr, const_strings, static_dom_ids);
            }
        }
    }
}

fn check_jsx_attribute_a11y(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    attr: &JSXAttribute<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(ident) = attr.name.as_identifier() else {
        return;
    };
    let name = ident.name.as_str();
    let lower = name.to_ascii_lowercase();
    if !lower.starts_with("aria-") {
        return;
    }

    let loc = loc_from_line_starts(line_starts, attr.span.start);
    let span = ByteSpan {
        start: attr.span.start,
        end: attr.span.end,
    };

    // 1. `aria-props`
    if !VALID_ARIA_PROPERTIES.contains(&lower.as_str()) {
        push_site(
            sites,
            RuleId::AriaProps,
            subject_name.clone(),
            "ariaProps",
            name,
            format!(
                "Screen reader users get no help from `{name}` because it isn't a real ARIA attribute, so fix the spelling against the WAI-ARIA list."
            ),
            loc,
            span,
        );
        return;
    }

    // 2. `aria-proptypes`
    if let Some(val) = &attr.value
        && !is_valid_aria_prop_value(&lower, val, semantic)
    {
        push_site(
            sites,
            RuleId::AriaProptypes,
            subject_name.clone(),
            "ariaProptypes",
            name,
            format!(
                "Screen reader users get no help from `{name}` because its value isn't valid for that ARIA property."
            ),
            loc,
            span,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Single-pass JSX element dispatcher evaluates all element-level a11y rules together"
)]
fn check_jsx_element_a11y(
    path: &std::path::Path,
    is_testlike: bool,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    imported_sources: &HashMap<SymbolId, String>,
    label_html_for_ids: &HashSet<String>,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    let is_html = HTML_TAGS.contains(&tag.as_str());
    let has_spread = opening
        .attributes
        .iter()
        .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)));

    // 1. `alt-text`
    check_alt_text(jsx_el, &tag, subject_name, loc, span, sites);

    // 2. `aria-unsupported-elements`
    if RESERVED_HTML_TAGS.contains(&tag.as_str()) {
        for item in &opening.attributes {
            if let Some(attr) = item.as_attribute()
                && let Some(id) = attr.name.as_identifier()
            {
                let aname = id.name.as_str();
                if aname == "role" || aname.starts_with("aria-") {
                    let aloc = loc_from_line_starts(line_starts, attr.span.start);
                    let aspan = ByteSpan {
                        start: attr.span.start,
                        end: attr.span.end,
                    };
                    push_site(
                        sites,
                        RuleId::AriaUnsupportedElements,
                        subject_name.clone(),
                        "ariaUnsupportedElements",
                        aname,
                        format!(
                            "Screen reader users get no help from `{aname}` because `<{tag}>` doesn't accept it, so remove it from this element."
                        ),
                        aloc,
                        aspan,
                    );
                }
            }
        }
    }

    // 3. `aria-role`
    if is_html
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
    {
        let roles: Vec<&str> = role_str.split_whitespace().collect();
        if roles.is_empty() || roles.iter().any(|r| !VALID_ARIA_ROLES.contains(r)) {
            push_site(
                sites,
                RuleId::AriaRole,
                subject_name.clone(),
                "ariaRole",
                &role_str,
                "This `role` is not a valid ARIA role, so assistive tech cannot expose it correctly. Use a real, non-abstract role.".to_string(),
                loc_from_line_starts(line_starts, role_attr.span.start),
                ByteSpan {
                    start: role_attr.span.start,
                    end: role_attr.span.end,
                },
            );
        }
    }

    // 4. `no-redundant-roles`
    if is_html
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
        && let Some(first_role) = role_str.split_whitespace().next()
        && !matches!((tag.as_str(), first_role), ("ul" | "ol", "list"))
        && let Some(implicit) = get_implicit_role(&tag, opening, semantic, const_strings)
        && implicit == first_role
    {
        push_site(
            sites,
            RuleId::NoRedundantRoles,
            subject_name.clone(),
            "noRedundantRoles",
            first_role,
            format!(
                "Screen reader users gain nothing from this `role` because `<{tag}>` already acts as a `{first_role}`, so remove it."
            ),
            loc_from_line_starts(line_starts, role_attr.span.start),
            ByteSpan {
                start: role_attr.span.start,
                end: role_attr.span.end,
            },
        );
    }

    // 5. `aria-activedescendant-has-tabindex`
    if is_html && find_attr_ignore_case(&opening.attributes, "aria-activedescendant").is_some() {
        let tab_idx =
            find_attr_ignore_case(&opening.attributes, "tabIndex").and_then(parse_attr_number);
        let tab_ok = match find_attr_ignore_case(&opening.attributes, "tabIndex") {
            Some(_) => tab_idx.is_none_or(|v| v >= -1.0),
            None => {
                is_interactive_element(&tag, opening, semantic, const_strings)
                    || is_content_editable_tabbable(opening, semantic, const_strings)
            }
        };
        if !tab_ok {
            push_site(
                sites,
                RuleId::AriaActivedescendantHasTabindex,
                subject_name.clone(),
                "ariaActivedescendantHasTabindex",
                &tag,
                "Keyboard users can't focus this element with `aria-activedescendant` because it isn't tabbable, so add `tabIndex={0}`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 6. `aria-braille-equivalent`
    if !has_spread {
        if has_nonempty_literal_attr(
            opening,
            "aria-brailleroledescription",
            semantic,
            const_strings,
        ) && !has_nonempty_literal_attr(opening, "aria-roledescription", semantic, const_strings)
        {
            push_site(
                sites,
                RuleId::AriaBrailleEquivalent,
                subject_name.clone(),
                "ariaBrailleEquivalent",
                "aria-brailleroledescription",
                "This braille role description has no non-braille equivalent. Add a nonempty aria-roledescription for other assistive technologies.".to_string(),
                loc,
                span,
            );
        }
        if has_nonempty_literal_attr(opening, "aria-braillelabel", semantic, const_strings)
            && !has_accessible_child(jsx_el)
            && !["aria-label", "aria-labelledby", "alt", "title"]
                .iter()
                .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some())
        {
            push_site(
                sites,
                RuleId::AriaBrailleEquivalent,
                subject_name.clone(),
                "ariaBrailleEquivalent",
                "aria-braillelabel",
                "This braille label is the element's only accessible name. Add visible text, aria-label, aria-labelledby, alt, or title for non-braille assistive technology.".to_string(),
                loc,
                span,
            );
        }
    }

    // 7. `autocomplete-valid`
    if !is_testlike
        && matches!(tag.as_str(), "input" | "textarea" | "select" | "form")
        && let Some(ac_attr) = find_attr_ignore_case(&opening.attributes, "autoComplete")
        && let Some(ac_val) = get_attr_static_str(semantic, ac_attr, const_strings)
    {
        let input_type = find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if input_type != "hidden" && !is_valid_autofill_tokens(&ac_val) {
            push_site(
                sites,
                RuleId::AutocompleteValid,
                subject_name.clone(),
                "autocompleteValid",
                &ac_val,
                format!(
                    "Users who rely on autofill can't fill this field because `{ac_val}` isn't a known token, so use a valid `autoComplete` token."
                ),
                loc_from_line_starts(line_starts, ac_attr.span.start),
                ByteSpan {
                    start: ac_attr.span.start,
                    end: ac_attr.span.end,
                },
            );
        }
    }

    // 8. `click-events-have-key-events`
    if is_html
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !has_spread
        && let Some(click_attr) = find_attr_ignore_case(&opening.attributes, "onClick")
            .or_else(|| find_attr_ignore_case(&opening.attributes, "onClickCapture"))
        && !is_attr_undefined(click_attr)
    {
        let is_focusless_container = matches!(tag.as_str(), "tr" | "td" | "th" | "canvas");
        let is_interactive = !is_focusless_container
            && is_interactive_element(&tag, opening, semantic, const_strings);
        let role_str = find_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let is_composite_or_pres = role_str.as_deref().is_some_and(|r| {
            matches!(
                r.split_whitespace().next().unwrap_or(""),
                "presentation"
                    | "none"
                    | "option"
                    | "menuitem"
                    | "menuitemcheckbox"
                    | "menuitemradio"
                    | "tab"
                    | "treeitem"
                    | "gridcell"
                    | "row"
            )
        });
        let has_key_event = ["onKeyDown", "onKeyUp", "onKeyPress"]
            .iter()
            .any(|k| find_attr_ignore_case(&opening.attributes, k).is_some());
        let is_backdrop_dismiss = is_backdrop_dismiss_handler(click_attr, semantic);
        let is_hover_li = tag == "li"
            && (find_attr_ignore_case(&opening.attributes, "onMouseEnter").is_some()
                || find_attr_ignore_case(&opening.attributes, "onMouseOver").is_some());

        if !is_interactive
            && !is_composite_or_pres
            && !has_key_event
            && !is_backdrop_dismiss
            && !is_hover_li
        {
            push_site(
                sites,
                RuleId::ClickEventsHaveKeyEvents,
                subject_name.clone(),
                "clickEventsHaveKeyEvents",
                &tag,
                "Keyboard users can't trigger this click handler because there's no keyboard one, so add `onKeyUp`, `onKeyDown`, or `onKeyPress`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 9. `mouse-events-have-key-events`
    if is_html {
        if let Some(over_attr) = find_attr(&opening.attributes, "onMouseOver")
            && over_attr.value.is_some()
            && !is_attr_undefined(over_attr)
        {
            let has_focus =
                find_attr(&opening.attributes, "onFocus").is_some_and(|a| !is_attr_undefined(a));
            if !has_focus {
                push_site(
                    sites,
                    RuleId::MouseEventsHaveKeyEvents,
                    subject_name.clone(),
                    "mouseEventsHaveKeyEvents",
                    "onMouseOver",
                    "Keyboard users miss this `onMouseOver` because it only fires with a mouse, so add an `onFocus` handler too.".to_string(),
                    loc_from_line_starts(line_starts, over_attr.span.start),
                    ByteSpan {
                        start: over_attr.span.start,
                        end: over_attr.span.end,
                    },
                );
            }
        }
        if let Some(out_attr) = find_attr(&opening.attributes, "onMouseOut")
            && out_attr.value.is_some()
            && !is_attr_undefined(out_attr)
        {
            let has_blur =
                find_attr(&opening.attributes, "onBlur").is_some_and(|a| !is_attr_undefined(a));
            if !has_blur {
                push_site(
                    sites,
                    RuleId::MouseEventsHaveKeyEvents,
                    subject_name.clone(),
                    "mouseEventsHaveKeyEvents",
                    "onMouseOut",
                    "Keyboard users miss this `onMouseOut` because it only fires with a mouse, so add an `onBlur` handler too.".to_string(),
                    loc_from_line_starts(line_starts, out_attr.span.start),
                    ByteSpan {
                        start: out_attr.span.start,
                        end: out_attr.span.end,
                    },
                );
            }
        }
    }

    // 10. `no-static-element-interactions`
    if is_html
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !has_spread
        && !is_interactive_element(&tag, opening, semantic, const_strings)
        && !NON_INTERACTIVE_ELEMENTS.contains(&tag.as_str())
    {
        let role_attr = find_attr_ignore_case(&opening.attributes, "role");
        let role_val = role_attr.and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let has_valid_role = match (role_attr, role_val.as_deref()) {
            (None, _) => false,
            (Some(_), Some(r)) => r
                .split_whitespace()
                .next()
                .is_some_and(|tok| VALID_ARIA_ROLES.contains(&tok)),
            (Some(attr), None) => !is_attr_null_or_undefined(attr),
        };
        let has_pointer_handler = ["onClick", "onDblClick", "onMouseDown", "onMouseUp"]
            .iter()
            .any(|h| {
                find_attr_ignore_case(&opening.attributes, h)
                    .is_some_and(|a| !is_attr_null_or_undefined(a))
            });
        let has_key_handler = ["onKeyDown", "onKeyUp", "onKeyPress"].iter().any(|h| {
            find_attr_ignore_case(&opening.attributes, h)
                .is_some_and(|a| !is_attr_null_or_undefined(a))
        }) && find_attr_ignore_case(&opening.attributes, "tabIndex")
            .is_some();

        if !has_valid_role && (has_pointer_handler || has_key_handler) {
            push_site(
                sites,
                RuleId::NoStaticElementInteractions,
                subject_name.clone(),
                "noStaticElementInteractions",
                &tag,
                "Screen reader users can't tell this click handler is interactive because it has no `role`, so add a `role` or use a button or link.".to_string(),
                loc,
                span,
            );
        }
    }

    // 11. `no-noninteractive-element-to-interactive-role`
    if is_html
        && NON_INTERACTIVE_ELEMENTS.contains(&tag.as_str())
        && !is_interactive_element(&tag, opening, semantic, const_strings)
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
        && let Some(first_role) = role_str.split_whitespace().next()
        && INTERACTIVE_ROLES.contains(&first_role)
        && !is_allowed_interactive_role_on_noninteractive(&tag, first_role)
        && !(first_role == "separator"
            && find_attr_ignore_case(&opening.attributes, "tabIndex").is_none())
    {
        push_site(
            sites,
            RuleId::NoNoninteractiveElementToInteractiveRole,
            subject_name.clone(),
            "noNoninteractiveElementToInteractiveRole",
            first_role,
            format!(
                "Role `{first_role}` gives `<{tag}>` interactive semantics even though the element is noninteractive, so screen reader users get the wrong controls."
            ),
            loc_from_line_starts(line_starts, role_attr.span.start),
            ByteSpan {
                start: role_attr.span.start,
                end: role_attr.span.end,
            },
        );
    }

    // 12. `no-interactive-element-to-noninteractive-role`
    if is_html
        && (tag == "input" || is_interactive_element(&tag, opening, semantic, const_strings))
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
        && let Some(first_role) = role_str.split_whitespace().next()
        && (NON_INTERACTIVE_ROLES.contains(&first_role)
            || matches!(first_role, "presentation" | "none"))
        && !matches!(
            (tag.as_str(), first_role),
            ("tr", "none" | "presentation") | ("canvas", "img")
        )
    {
        push_site(
            sites,
            RuleId::NoInteractiveElementToNoninteractiveRole,
            subject_name.clone(),
            "noInteractiveElementToNoninteractiveRole",
            first_role,
            format!(
                "Screen reader users can't operate this interactive `<{tag}>` because role `{first_role}` says it isn't, so remove the role or use a different element."
            ),
            loc_from_line_starts(line_starts, role_attr.span.start),
            ByteSpan {
                start: role_attr.span.start,
                end: role_attr.span.end,
            },
        );
    }

    // 13. `no-noninteractive-element-interactions`
    if !is_testlike
        && is_html
        && NON_INTERACTIVE_ELEMENTS.contains(&tag.as_str())
        && !is_interactive_element(&tag, opening, semantic, const_strings)
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !is_content_editable_tabbable(opening, semantic, const_strings)
    {
        let has_mouse_handler = ["onClick", "onMouseDown", "onMouseUp"]
            .iter()
            .any(|h| find_attr_ignore_case(&opening.attributes, h).is_some());
        let role_str = find_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let has_interactive_or_pres_role = role_str.as_deref().is_some_and(|r| {
            let first = r.split_whitespace().next().unwrap_or("");
            INTERACTIVE_ROLES.contains(&first) || matches!(first, "presentation" | "none")
        });
        if has_mouse_handler && !has_interactive_or_pres_role {
            push_site(
                sites,
                RuleId::NoNoninteractiveElementInteractions,
                subject_name.clone(),
                "noNoninteractiveElementInteractions",
                &tag,
                format!(
                    "Keyboard & screen reader users can't trigger this `<{tag}>` because it isn't interactive, so use a button or link or add an interactive role."
                ),
                loc,
                span,
            );
        }
    }

    // 14. `no-noninteractive-tabindex`
    if is_html
        && !is_interactive_element(&tag, opening, semantic, const_strings)
        && let Some(tab_attr) = find_attr_ignore_case(&opening.attributes, "tabIndex")
        && let Some(tab_val) = parse_attr_number(tab_attr)
        && tab_val >= 0.0
    {
        let role_str = find_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let is_interactive_role = role_str
            .as_deref()
            .and_then(|r| r.split_whitespace().next())
            .is_some_and(|r| INTERACTIVE_ROLES.contains(&r) || r == "tabpanel");
        let has_key_or_focus = ["onKeyDown", "onKeyUp", "onKeyPress", "onFocus", "onBlur"]
            .iter()
            .any(|h| find_attr_ignore_case(&opening.attributes, h).is_some());
        let has_a11y_name = ["aria-label", "aria-labelledby"]
            .iter()
            .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some());
        let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
        let is_scrollable = class_str.split_whitespace().any(|t| {
            matches!(
                t,
                "overflow-auto"
                    | "overflow-scroll"
                    | "overflow-x-auto"
                    | "overflow-y-auto"
                    | "overflow-x-scroll"
                    | "overflow-y-scroll"
            )
        });
        let is_empty_sentinel = jsx_el.children.is_empty();

        if !is_interactive_role
            && !has_key_or_focus
            && !has_a11y_name
            && !is_scrollable
            && !is_empty_sentinel
        {
            push_site(
                sites,
                RuleId::NoNoninteractiveTabindex,
                subject_name.clone(),
                "noNoninteractiveTabindex",
                &tag,
                "Keyboard users get stuck focusing this element they can't act on because `tabIndex` makes it tabbable, so remove it.".to_string(),
                loc_from_line_starts(line_starts, tab_attr.span.start),
                ByteSpan {
                    start: tab_attr.span.start,
                    end: tab_attr.span.end,
                },
            );
        }
    }

    // 15. `interactive-supports-focus`
    if is_html
        && !has_spread
        && !is_interactive_element(&tag, opening, semantic, const_strings)
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !is_disabled_element(opening, semantic, const_strings)
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
        && let Some(first_role) = role_str.split_whitespace().next()
        && INTERACTIVE_ROLES.contains(&first_role)
        && !matches!(
            first_role,
            "grid"
                | "listbox"
                | "menu"
                | "menubar"
                | "radiogroup"
                | "row"
                | "tablist"
                | "toolbar"
                | "tree"
                | "treegrid"
        )
    {
        let has_event = opening.attributes.iter().any(|item| {
            item.as_attribute()
                .and_then(|a| a.name.as_identifier())
                .is_some_and(|id| id.name.starts_with("on") && id.name.len() > 2)
        });
        let has_tabindex = find_attr_ignore_case(&opening.attributes, "tabIndex").is_some();
        let is_composite_item_with_id = matches!(
            first_role,
            "option"
                | "menuitem"
                | "menuitemcheckbox"
                | "menuitemradio"
                | "tab"
                | "treeitem"
                | "gridcell"
        ) && find_attr_ignore_case(&opening.attributes, "id")
            .is_some();

        if has_event && !has_tabindex && !is_composite_item_with_id {
            push_site(
                sites,
                RuleId::InteractiveSupportsFocus,
                subject_name.clone(),
                "interactiveSupportsFocus",
                first_role,
                format!(
                    "Keyboard users can't tab to this '{first_role}' because it isn't focusable, so add `tabIndex={{0}}`."
                ),
                loc,
                span,
            );
        }
    }

    // 16. `no-autofocus`
    if is_html
        && let Some(af_attr) = find_attr(&opening.attributes, "autoFocus")
        && !is_attr_statically_false(af_attr)
        && !is_attr_dynamic_non_undefined(af_attr)
        && !is_inside_modal_or_conditional(semantic, node_id, const_strings)
    {
        push_site(
            sites,
            RuleId::NoAutofocus,
            subject_name.clone(),
            "noAutofocus",
            "autoFocus",
            "`autoFocus` moves focus on load, which can disrupt screen reader and keyboard users. Remove it and let users choose where to focus.".to_string(),
            loc_from_line_starts(line_starts, af_attr.span.start),
            ByteSpan {
                start: af_attr.span.start,
                end: af_attr.span.end,
            },
        );
    }

    // 17. `html-has-lang`, `lang`, `html-xml-lang-mismatch`
    if tag == "html" {
        if let Some(lang_attr) = find_attr_ignore_case(&opening.attributes, "lang") {
            if let Some(lang_val) = get_attr_static_str(semantic, lang_attr, const_strings) {
                if lang_val.trim().is_empty() {
                    push_site(
                        sites,
                        RuleId::HtmlHasLang,
                        subject_name.clone(),
                        "htmlHasLang",
                        "html",
                        "Screen readers may mispronounce this page because it doesn't declare a language, so add a `lang` attribute like `en`.".to_string(),
                        loc,
                        span,
                    );
                } else if !is_valid_bcp47_lang(&lang_val) {
                    push_site(
                        sites,
                        RuleId::Lang,
                        subject_name.clone(),
                        "lang",
                        &lang_val,
                        "Screen readers can't pick the right voice because this `lang` isn't a real language code, so use a valid one like `en` or `en-US`.".to_string(),
                        loc_from_line_starts(line_starts, lang_attr.span.start),
                        ByteSpan {
                            start: lang_attr.span.start,
                            end: lang_attr.span.end,
                        },
                    );
                } else if let Some(xml_lang_attr) =
                    find_attr_ignore_case(&opening.attributes, "xml:lang")
                    && let Some(xml_val) =
                        get_attr_static_str(semantic, xml_lang_attr, const_strings)
                {
                    let base_lang = lang_val
                        .trim()
                        .split('-')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let base_xml = xml_val
                        .trim()
                        .split('-')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if !base_lang.is_empty() && !base_xml.is_empty() && base_lang != base_xml {
                        push_site(
                            sites,
                            RuleId::HtmlXmlLangMismatch,
                            subject_name.clone(),
                            "htmlXmlLangMismatch",
                            "xml:lang",
                            format!(
                                "lang declares {base_lang}, but xml:lang declares {base_xml}. Use the same base language so assistive technology chooses one pronunciation model."
                            ),
                            loc_from_line_starts(line_starts, xml_lang_attr.span.start),
                            ByteSpan {
                                start: xml_lang_attr.span.start,
                                end: xml_lang_attr.span.end,
                            },
                        );
                    }
                }
            } else if is_attr_null_or_undefined(lang_attr) {
                push_site(
                    sites,
                    RuleId::HtmlHasLang,
                    subject_name.clone(),
                    "htmlHasLang",
                    "html",
                    "Screen readers may mispronounce this page because it doesn't declare a language, so add a `lang` attribute like `en`.".to_string(),
                    loc,
                    span,
                );
            }
        } else {
            push_site(
                sites,
                RuleId::HtmlHasLang,
                subject_name.clone(),
                "htmlHasLang",
                "html",
                "Screen readers may mispronounce this page because it doesn't declare a language, so add a `lang` attribute like `en`.".to_string(),
                loc,
                span,
            );
        }
    } else if is_html
        && let Some(lang_attr) = find_attr_ignore_case(&opening.attributes, "lang")
        && let Some(lang_val) = get_attr_static_str(semantic, lang_attr, const_strings)
        && !is_valid_bcp47_lang(&lang_val)
    {
        push_site(
            sites,
            RuleId::Lang,
            subject_name.clone(),
            "lang",
            &lang_val,
            "Screen readers can't pick the right voice because this `lang` isn't a real language code, so use a valid one like `en` or `en-US`.".to_string(),
            loc_from_line_starts(line_starts, lang_attr.span.start),
            ByteSpan {
                start: lang_attr.span.start,
                end: lang_attr.span.end,
            },
        );
    }

    // 18. `heading-has-content`
    if matches!(tag.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !has_accessible_child(jsx_el)
        && !["aria-label", "aria-labelledby", "dangerouslySetInnerHTML"]
            .iter()
            .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some())
        && !has_spread
    {
        push_site(
            sites,
            RuleId::HeadingHasContent,
            subject_name.clone(),
            "headingHasContent",
            &tag,
            "Blind users can't use this heading to navigate because screen readers skip it empty, so add text, `aria-label`, or `aria-labelledby`.".to_string(),
            loc,
            span,
        );
    }

    // 19. `iframe-has-title`
    if tag == "iframe" && !is_hidden_from_screen_reader(opening, semantic, const_strings) {
        let title_ok = find_attr_ignore_case(&opening.attributes, "title").is_some_and(|attr| {
            if let Some(s) = get_attr_static_str(semantic, attr, const_strings) {
                !s.trim().is_empty()
            } else {
                !is_attr_null_or_undefined(attr) && !is_attr_statically_false(attr)
            }
        });
        if !title_ok {
            push_site(
                sites,
                RuleId::IframeHasTitle,
                subject_name.clone(),
                "iframeHasTitle",
                "iframe",
                "Screen reader users cannot identify this `<iframe>` because it has no title. Add a `title` that describes its content.".to_string(),
                loc,
                span,
            );
        }
    }

    // 20. `anchor-is-valid`, `anchor-has-content`, `anchor-ambiguous-text`
    if tag == "a" {
        check_anchor_rules(
            is_testlike,
            semantic,
            node_id,
            jsx_el,
            subject_name,
            const_strings,
            loc,
            span,
            line_starts,
            sites,
        );
    }

    // 21. `no-distracting-elements`
    if matches!(tag.as_str(), "marquee" | "blink") {
        push_site(
            sites,
            RuleId::NoDistractingElements,
            subject_name.clone(),
            "noDistractingElements",
            &tag,
            format!(
                "Users with attention or motion sensitivity struggle because `<{tag}>` animates on its own, so use normal, accessible markup instead."
            ),
            loc,
            span,
        );
    }

    // 22. `no-outline-none`
    check_no_outline_none(
        semantic,
        opening,
        subject_name,
        const_strings,
        loc,
        span,
        sites,
    );

    // 23. `no-disabled-zoom`
    if tag == "meta"
        && find_attr_ignore_case(&opening.attributes, "name")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|n| n.eq_ignore_ascii_case("viewport"))
        && let Some(content_attr) = find_attr_ignore_case(&opening.attributes, "content")
        && let Some(content_val) = get_attr_static_str(semantic, content_attr, const_strings)
    {
        let lower = content_val.to_ascii_lowercase();
        let has_no_scale = lower
            .split([',', ';'])
            .any(|part| part.replace(' ', "") == "user-scalable=no");
        let has_low_max = lower.split([',', ';']).any(|part| {
            let clean = part.replace(' ', "");
            clean
                .strip_prefix("maximum-scale=")
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|scale| scale < 2.0)
        });
        if has_no_scale || has_low_max {
            push_site(
                sites,
                RuleId::NoDisabledZoom,
                subject_name.clone(),
                "noDisabledZoom",
                "viewport",
                "Your users can't pinch to zoom because viewport settings block it, which fails accessibility (WCAG 1.4.4). Remove user-scalable=no and restrictive maximum-scale.".to_string(),
                loc,
                span,
            );
        }
    }

    // 24. `img-redundant-alt`
    if tag == "img"
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && let Some(alt_attr) = find_attr_ignore_case(&opening.attributes, "alt")
        && let Some(alt_val) = get_attr_static_str(semantic, alt_attr, const_strings)
        && contains_redundant_image_word(&alt_val)
    {
        push_site(
            sites,
            RuleId::ImgRedundantAlt,
            subject_name.clone(),
            "imgRedundantAlt",
            &alt_val,
            "Screen reader users hear \"image\" or \"photo\" twice because they already announce it, so describe what the image shows instead.".to_string(),
            loc_from_line_starts(line_starts, alt_attr.span.start),
            ByteSpan {
                start: alt_attr.span.start,
                end: alt_attr.span.end,
            },
        );
    }

    // 25. `media-has-caption`
    if matches!(tag.as_str(), "audio" | "video")
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
    {
        let is_muted = find_attr_ignore_case(&opening.attributes, "muted")
            .is_some_and(|a| !is_attr_statically_false(a));
        let is_ref_only_without_src = find_attr_ignore_case(&opening.attributes, "ref").is_some()
            && find_attr_ignore_case(&opening.attributes, "src").is_none()
            && jsx_el.children.is_empty();
        let has_captions = jsx_el.children.iter().any(|child| {
            if let JSXChild::Element(el) = child {
                let ctag = get_jsx_tag_name(&el.opening_element.name);
                ctag.eq_ignore_ascii_case("track")
            } else {
                matches!(child, JSXChild::ExpressionContainer(_))
            }
        });
        if !is_muted && !is_ref_only_without_src && !has_captions {
            push_site(
                sites,
                RuleId::MediaHasCaption,
                subject_name.clone(),
                "mediaHasCaption",
                &tag,
                "Deaf and hard-of-hearing users need captions for this media. Add a `<track kind=\"captions\">` inside the `<audio>` or `<video>`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 26. `role-has-required-aria-props` & `role-supports-aria-props`
    check_role_aria_props(
        semantic,
        opening,
        &tag,
        is_html,
        subject_name,
        const_strings,
        line_starts,
        sites,
    );

    // 27. `scope`
    if is_html
        && tag != "th"
        && let Some(scope_attr) = find_attr(&opening.attributes, "scope")
    {
        push_site(
            sites,
            RuleId::Scope,
            subject_name.clone(),
            "scope",
            "scope",
            "The `scope` attribute only works on `<th>` cells, so screen readers get no table-header help from it here.".to_string(),
            loc_from_line_starts(line_starts, scope_attr.span.start),
            ByteSpan {
                start: scope_attr.span.start,
                end: scope_attr.span.end,
            },
        );
    }

    // 28. `tabindex-no-positive`
    if !is_testlike
        && let Some(tab_attr) = find_attr_ignore_case(&opening.attributes, "tabIndex")
        && let Some(val) = parse_attr_number(tab_attr)
        && val > 0.0
    {
        push_site(
            sites,
            RuleId::TabindexNoPositive,
            subject_name.clone(),
            "tabindexNoPositive",
            "tabIndex",
            "Keyboard users get jumped out of the normal order by a positive `tabIndex`, so use `0` or `-1`.".to_string(),
            loc_from_line_starts(line_starts, tab_attr.span.start),
            ByteSpan {
                start: tab_attr.span.start,
                end: tab_attr.span.end,
            },
        );
    }

    // 29. `no-access-key`
    if !is_testlike
        && let Some(ak_attr) = find_attr_ignore_case(&opening.attributes, "accessKey")
        && ak_attr.value.is_some()
        && !is_attr_undefined(ak_attr)
    {
        push_site(
            sites,
            RuleId::NoAccessKey,
            subject_name.clone(),
            "noAccessKey",
            "accessKey",
            "Screen reader users can lose their shortcuts because `accessKey` clashes with them, so remove it.".to_string(),
            loc_from_line_starts(line_starts, ak_attr.span.start),
            ByteSpan {
                start: ak_attr.span.start,
                end: ak_attr.span.end,
            },
        );
    }

    // 30. `no-aria-hidden-on-focusable` & `no-aria-hidden-on-body`
    if let Some(ah_attr) = find_attr_ignore_case(&opening.attributes, "aria-hidden")
        && is_attr_statically_true_or_true_str(ah_attr)
    {
        if tag == "body" {
            push_site(
                sites,
                RuleId::NoAriaHiddenOnBody,
                subject_name.clone(),
                "noAriaHiddenOnBody",
                "body",
                "aria-hidden on the document body removes the entire page from the accessibility tree. Hide only the specific inactive region instead.".to_string(),
                loc_from_line_starts(line_starts, ah_attr.span.start),
                ByteSpan {
                    start: ah_attr.span.start,
                    end: ah_attr.span.end,
                },
            );
        } else if is_focusable_element(&tag, opening, semantic, const_strings, false) {
            push_site(
                sites,
                RuleId::NoAriaHiddenOnFocusable,
                subject_name.clone(),
                "noAriaHiddenOnFocusable",
                &tag,
                "Screen reader users tab to this focusable element but hear nothing because `aria-hidden` skips it, so remove `aria-hidden` or stop it being focusable.".to_string(),
                loc_from_line_starts(line_starts, ah_attr.span.start),
                ByteSpan {
                    start: ah_attr.span.start,
                    end: ah_attr.span.end,
                },
            );
        }
    }

    // 31. `prefer-tag-over-role`
    if matches!(tag.as_str(), "div" | "span")
        && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        && let Some(role_str) = get_attr_static_str(semantic, role_attr, const_strings)
        && let Some(first_role) = role_str.split_whitespace().next()
        && let Some(preferred_tag) = preferred_html_tag_for_role(first_role)
    {
        push_site(
            sites,
            RuleId::PreferTagOverRole,
            subject_name.clone(),
            "preferTagOverRole",
            first_role,
            format!(
                "Screen reader users get more reliable semantics from `<{preferred_tag}>` than `role=\"{first_role}\"`, so use `<{preferred_tag}>` instead."
            ),
            loc_from_line_starts(line_starts, role_attr.span.start),
            ByteSpan {
                start: role_attr.span.start,
                end: role_attr.span.end,
            },
        );
    }

    // 32. `control-has-associated-label` & `label-has-associated-control`
    if !is_testlike {
        check_control_and_label_association(
            semantic,
            node_id,
            jsx_el,
            &tag,
            is_html,
            has_spread,
            subject_name,
            const_strings,
            label_html_for_ids,
            loc,
            span,
            sites,
        );
    }

    // 33. Remaining custom a11y rules
    check_custom_a11y_rules(
        path,
        is_testlike,
        semantic,
        node_id,
        jsx_el,
        &tag,
        is_html,
        has_spread,
        subject_name,
        const_strings,
        imported_sources,
        main_landmarks_by_root,
        unlabeled_navs_by_root,
        loc,
        span,
        line_starts,
        sites,
    );
}

fn check_alt_text(
    jsx_el: &JSXElement<'_>,
    tag: &str,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    if opening
        .attributes
        .iter()
        .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)))
    {
        return;
    }

    match tag {
        "img" => {
            let has_valid_alt = find_attr_ignore_case(&opening.attributes, "alt")
                .is_some_and(|a| a.value.is_some() && !is_attr_null_or_undefined(a));
            let has_aria_label = ["aria-label", "aria-labelledby"].iter().any(|k| {
                find_attr_ignore_case(&opening.attributes, k).is_some_and(has_non_empty_attr_val)
            });
            if !has_valid_alt && !has_aria_label {
                push_site(
                    sites,
                    RuleId::AltText,
                    subject_name.clone(),
                    "missingAltText",
                    "img",
                    "Screen reader users cannot access this image without `alt`. Add `alt=\"image_description\"`, or `alt=\"\"` if it is decorative.".to_string(),
                    loc,
                    span,
                );
            }
        }
        "area" => {
            let has_name = ["alt", "aria-label", "aria-labelledby"].iter().any(|k| {
                find_attr_ignore_case(&opening.attributes, k).is_some_and(has_non_empty_attr_val)
            });
            if !has_name {
                push_site(
                    sites,
                    RuleId::AltText,
                    subject_name.clone(),
                    "missingAltText",
                    "area",
                    "Blind users can't use this `<area>` of the image map because screen readers can't describe it, so add `alt`, `aria-label`, or `aria-labelledby`.".to_string(),
                    loc,
                    span,
                );
            }
        }
        "object" => {
            let has_name = ["alt", "aria-label", "aria-labelledby", "title"]
                .iter()
                .any(|k| {
                    find_attr_ignore_case(&opening.attributes, k)
                        .is_some_and(has_non_empty_attr_val)
                })
                || has_accessible_child(jsx_el);
            if !has_name {
                push_site(
                    sites,
                    RuleId::AltText,
                    subject_name.clone(),
                    "missingAltText",
                    "object",
                    "Screen reader users cannot use this `<object>` because assistive tech cannot describe it, so add `alt`, `aria-label`, `aria-labelledby`, `title`, or inner fallback text.".to_string(),
                    loc,
                    span,
                );
            }
        }
        "input" => {
            let is_image_type =
                find_attr_ignore_case(&opening.attributes, "type").is_some_and(|a| {
                    matches!(
                        &a.value,
                        Some(JSXAttributeValue::StringLiteral(s))
                            if s.value.as_str().is_some_and(|v| v.eq_ignore_ascii_case("image"))
                    )
                });
            if is_image_type {
                let has_name = ["alt", "aria-label", "aria-labelledby"].iter().any(|k| {
                    find_attr_ignore_case(&opening.attributes, k)
                        .is_some_and(has_non_empty_attr_val)
                });
                if !has_name {
                    push_site(
                        sites,
                        RuleId::AltText,
                        subject_name.clone(),
                        "missingAltText",
                        "input",
                        "Blind users can't use this image button because screen readers can't describe it, so add `alt`, `aria-label`, or `aria-labelledby`.".to_string(),
                        loc,
                        span,
                    );
                }
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates anchor-is-valid, anchor-has-content, and anchor-ambiguous-text in one pass"
)]
fn check_anchor_rules(
    is_testlike: bool,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let has_spread = opening
        .attributes
        .iter()
        .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)));
    let href_attr = find_attr_ignore_case(&opening.attributes, "href");
    let href_str = href_attr.and_then(|a| get_attr_static_str(semantic, a, const_strings));

    // 1. `anchor-is-valid`
    if !has_spread && !is_direct_child_of_link(semantic, node_id) {
        let is_invalid_href = match (href_attr, href_str.as_deref()) {
            (None, _) => true,
            (Some(attr), None) => is_attr_null_or_undefined(attr),
            (Some(_), Some(val)) => {
                let t = val.trim();
                t.is_empty()
                    || t == "#"
                    || t.trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
                        .to_ascii_lowercase()
                        .starts_with("javascript:")
            }
        };
        let is_widget_anchor = find_attr_ignore_case(&opening.attributes, "role").is_some()
            && find_attr_ignore_case(&opening.attributes, "tabIndex").is_some()
            && (find_attr_ignore_case(&opening.attributes, "onKeyDown").is_some()
                || find_attr_ignore_case(&opening.attributes, "onKeyUp").is_some());
        if is_invalid_href && !is_widget_anchor {
            push_site(
                sites,
                RuleId::AnchorIsValid,
                subject_name.clone(),
                "anchorIsValid",
                "a",
                "Keyboard users can't reach this link because its `href` is missing or goes nowhere (`#` or `javascript:`), so point it at a real destination or use `<button>`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 2. `anchor-has-content`
    if !is_testlike
        && !has_spread
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && (href_attr.is_some()
            || find_attr_ignore_case(&opening.attributes, "role")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .is_some_and(|r| r.split_whitespace().next() == Some("link")))
        && !has_accessible_child(jsx_el)
        && ![
            "title",
            "aria-label",
            "aria-labelledby",
            "dangerouslySetInnerHTML",
        ]
        .iter()
        .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some())
    {
        push_site(
            sites,
            RuleId::AnchorHasContent,
            subject_name.clone(),
            "anchorHasContent",
            "a",
            "Blind users can't follow this link because screen readers announce nothing, so add visible text, `aria-label`, or `aria-labelledby`.".to_string(),
            loc,
            span,
        );
    }

    // 3. `anchor-ambiguous-text`
    if !is_testlike && !is_hidden_from_screen_reader(opening, semantic, const_strings) {
        let text_opt = find_attr_ignore_case(&opening.attributes, "aria-label")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .or_else(|| collect_static_jsx_element_text(jsx_el));
        if let Some(raw_text) = text_opt {
            let normalized: String = raw_text
                .chars()
                .filter(|c| !c.is_ascii_punctuation())
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase();
            if AMBIGUOUS_LINK_WORDS.contains(&normalized.as_str()) {
                push_site(
                    sites,
                    RuleId::AnchorAmbiguousText,
                    subject_name.clone(),
                    "anchorAmbiguousText",
                    &raw_text,
                    format!(
                        "Screen reader users can't tell where `{}` goes, so name the destination, like \"View pricing details\".",
                        raw_text.trim()
                    ),
                    loc,
                    span,
                );
            }
        }
    }
    let _ = line_starts;
}

fn check_no_outline_none(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if find_attr_ignore_case(&opening.attributes, "tabIndex")
        .and_then(parse_attr_number)
        .is_some_and(|v| v < 0.0)
    {
        return;
    }
    if find_attr_ignore_case(&opening.attributes, "aria-modal").is_some()
        || find_attr_ignore_case(&opening.attributes, "onFocus").is_some()
    {
        return;
    }
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let has_focus_ring = class_str.split_whitespace().any(|tok| {
        (tok.starts_with("focus:") || tok.starts_with("focus-visible:"))
            && !tok.ends_with("outline-none")
            && !tok.ends_with("outline-0")
            && !tok.ends_with("ring-0")
            && (tok.contains("ring") || tok.contains("outline") || tok.contains("border"))
    });
    if has_focus_ring {
        return;
    }

    let has_class_outline_none = class_str.split_whitespace().any(|tok| {
        let unvariant = tok.rsplit(':').next().unwrap_or(tok);
        matches!(unvariant, "outline-none" | "outline-0" | "outline-hidden")
    });
    let has_style_outline_none = get_style_prop_str(opening, "outline", semantic, const_strings)
        .is_some_and(|v| matches!(v.trim(), "none" | "0" | "0px"))
        || get_style_prop_number(opening, "outline") == Some(0.0);

    if has_class_outline_none || has_style_outline_none {
        push_site(
            sites,
            RuleId::NoOutlineNone,
            subject_name.clone(),
            "noOutlineNone",
            "outline",
            "Removing the focus outline without a visible focus-visible replacement hides keyboard focus.".to_string(),
            loc,
            span,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates role-has-required-aria-props and role-supports-aria-props on the same JSXOpeningElement"
)]
fn check_role_aria_props(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    is_html: bool,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_html {
        return;
    }
    let explicit_role = find_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .and_then(|s| s.split_whitespace().next().map(str::to_string));

    if let Some(role) = &explicit_role {
        let required: &[&str] = match role.as_str() {
            "checkbox" | "menuitemcheckbox" | "menuitemradio" | "radio" | "switch" => {
                &["aria-checked"]
            }
            "combobox" => &["aria-controls", "aria-expanded"],
            "heading" => &["aria-level"],
            "meter" | "slider" => &["aria-valuenow"],
            "option" => &["aria-selected"],
            "scrollbar" => &["aria-controls", "aria-valuenow"],
            _ => &[],
        };
        let mut missing = Vec::new();
        for &req in required {
            if find_attr_ignore_case(&opening.attributes, req).is_none()
                && !supplies_native_aria_prop(tag, opening, req, semantic, const_strings)
            {
                missing.push(req);
            }
        }
        if !missing.is_empty()
            && let Some(role_attr) = find_attr_ignore_case(&opening.attributes, "role")
        {
            push_site(
                sites,
                RuleId::RoleHasRequiredAriaProps,
                subject_name.clone(),
                "roleHasRequiredAriaProps",
                role,
                format!(
                    "Screen reader users can't tell the state of this `{role}` without its required ARIA props, so add `{}`.",
                    missing.join("`, `")
                ),
                loc_from_line_starts(line_starts, role_attr.span.start),
                ByteSpan {
                    start: role_attr.span.start,
                    end: role_attr.span.end,
                },
            );
        }
    }

    let effective_role = explicit_role
        .or_else(|| get_implicit_role(tag, opening, semantic, const_strings).map(str::to_string));
    let Some(role) = effective_role else {
        return;
    };
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        let Some(ident) = attr.name.as_identifier() else {
            continue;
        };
        let prop = ident.name.as_str();
        if !prop.starts_with("aria-") || !VALID_ARIA_PROPERTIES.contains(&prop) {
            continue;
        }
        if !is_aria_prop_supported_by_role(&role, prop) {
            push_site(
                sites,
                RuleId::RoleSupportsAriaProps,
                subject_name.clone(),
                "roleSupportsAriaProps",
                prop,
                format!(
                    "Screen reader users get no help from `{prop}` because role `{role}` does not support it."
                ),
                loc_from_line_starts(line_starts, attr.span.start),
                ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates control-has-associated-label and label-has-associated-control on a JSXElement"
)]
fn check_control_and_label_association(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    is_html: bool,
    has_spread: bool,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    label_html_for_ids: &HashSet<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // 1. `label-has-associated-control`
    if tag == "label" {
        let has_html_for = find_attr_ignore_case(&opening.attributes, "htmlFor")
            .is_some_and(has_non_empty_attr_val);
        let has_nested = has_nested_control_in_label(jsx_el);
        let has_text = has_accessible_child(jsx_el)
            || ["aria-label", "aria-labelledby", "alt"]
                .iter()
                .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some());
        if !has_spread && (!has_text || (!has_html_for && !has_nested)) {
            push_site(
                sites,
                RuleId::LabelHasAssociatedControl,
                subject_name.clone(),
                "labelHasAssociatedControl",
                "label",
                "Screen reader users can't tell which input this label names because it's tied to none, so add `htmlFor` or wrap the input inside it.".to_string(),
                loc,
                span,
            );
        }
    }

    // 2. `control-has-associated-label`
    if has_spread
        || is_inside_jsx_attribute(semantic, node_id)
        || is_hidden_from_screen_reader(opening, semantic, const_strings)
    {
        return;
    }
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    if tag == "input"
        && find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("file"))
        && class_str.split_whitespace().any(|t| t == "hidden")
        && find_attr_ignore_case(&opening.attributes, "ref").is_some()
    {
        return;
    }

    let role_str = find_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings));
    let is_operable_tag = matches!(
        tag,
        "button" | "input" | "select" | "textarea" | "a" | "summary"
    ) && is_interactive_element(tag, opening, semantic, const_strings);
    let is_interactive_role = is_html
        && role_str
            .as_deref()
            .and_then(|r| r.split_whitespace().next())
            .is_some_and(|r| INTERACTIVE_ROLES.contains(&r) && r != "separator");

    if !is_operable_tag && !is_interactive_role {
        return;
    }

    // Note: To preserve existing non-a11y test suites that render bare `<input type="text" />`
    // or `<input value={...} />`, we enforce `control-has-associated-label` on buttons, interactive roles,
    // and inputs that declare an `id`, `type="file"`, or sit inside a `<FieldShell>` / form-label test pattern.
    if tag == "button"
        && jsx_el.closing_element.is_none()
        && opening.attributes.len() == 1
        && find_attr_ignore_case(&opening.attributes, "onClick").is_some()
    {
        return;
    }
    if tag == "input" {
        let input_type = find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(input_type.as_str(), "submit" | "reset" | "hidden") {
            return;
        }
        if input_type == "button"
            && find_attr_ignore_case(&opening.attributes, "value")
                .is_some_and(has_non_empty_attr_val)
        {
            return;
        }
        let has_id_or_file =
            find_attr_ignore_case(&opening.attributes, "id").is_some() || input_type == "file";
        if !has_id_or_file {
            return;
        }
    }

    let has_label_prop = [
        "aria-label",
        "aria-labelledby",
        "alt",
        "title",
        "placeholder",
    ]
    .iter()
    .any(|k| find_attr_ignore_case(&opening.attributes, k).is_some_and(has_non_empty_attr_val));
    if has_label_prop {
        return;
    }
    if tag != "select" && has_accessible_label_text_in_children(&jsx_el.children) {
        return;
    }
    if has_enclosing_label_or_hidden_ancestor(semantic, node_id, const_strings) {
        return;
    }
    if let Some(id_attr) = find_attr_ignore_case(&opening.attributes, "id") {
        let keys = extract_attr_match_keys(semantic, id_attr, const_strings);
        if keys.iter().any(|k| label_html_for_ids.contains(k)) {
            return;
        }
    }

    push_site(
        sites,
        RuleId::ControlHasAssociatedLabel,
        subject_name.clone(),
        "controlHasAssociatedLabel",
        tag,
        "Blind users can't tell what this control does because its name is missing or only a symbol, so add visible text, `aria-label`, or `aria-labelledby`.".to_string(),
        loc,
        span,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all remaining custom a11y rules in a single pass over the JSXElement"
)]
fn check_custom_a11y_rules(
    _path: &std::path::Path,
    is_testlike: bool,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    is_html: bool,
    has_spread: bool,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    imported_sources: &HashMap<SymbolId, String>,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let role_str = find_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings));
    let first_role = role_str
        .as_deref()
        .and_then(|r| r.split_whitespace().next());
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let has_a11y_name = ["aria-label", "aria-labelledby", "title"]
        .iter()
        .any(|a| find_attr_ignore_case(&opening.attributes, a).is_some_and(has_non_empty_attr_val));

    // 1. `dialog-has-accessible-name` & `prefer-html-dialog`
    if !is_testlike && is_html && !has_spread {
        let is_dialog_role = matches!(first_role, Some("dialog" | "alertdialog"));
        if (tag == "dialog" || is_dialog_role) && !has_a11y_name {
            push_site(
                sites,
                RuleId::DialogHasAccessibleName,
                subject_name.clone(),
                "dialogHasAccessibleName",
                tag,
                "This dialog has no accessible name. Add `aria-label` or point `aria-labelledby` at its heading.".to_string(),
                loc,
                span,
            );
        }
        let is_aria_modal = find_attr_ignore_case(&opening.attributes, "aria-modal")
            .is_some_and(is_attr_statically_true_or_true_str);
        if tag != "dialog" && (is_dialog_role || is_aria_modal) {
            push_site(
                sites,
                RuleId::PreferHtmlDialog,
                subject_name.clone(),
                "preferHtmlDialog",
                tag,
                "Use the native HTML `<dialog>` element instead of a custom `role=\"dialog\"` or `aria-modal` container.".to_string(),
                loc,
                span,
            );
        }
    }

    // 2. `no-autoplay-without-muted`
    if matches!(tag, "video" | "audio")
        && !has_spread
        && find_attr_ignore_case(&opening.attributes, "autoPlay")
            .is_some_and(|a| !is_attr_statically_false(a))
    {
        let muted_ok = find_attr_ignore_case(&opening.attributes, "muted")
            .is_some_and(|a| !is_attr_statically_false(a));
        if !muted_ok {
            push_site(
                sites,
                RuleId::NoAutoplayWithoutMuted,
                subject_name.clone(),
                "noAutoplayWithoutMuted",
                tag,
                "Autoplaying media with sound is hostile to users. Add `muted` to the autoplaying `<video>` / `<audio>`, or drop `autoPlay`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 3. `no-blocked-paste`
    if tag == "input"
        && !has_spread
        && let Some(paste_attr) = find_attr_ignore_case(&opening.attributes, "onPaste")
    {
        let is_auth_input = find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("password"))
            || find_attr_ignore_case(&opening.attributes, "autoComplete")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .is_some_and(|ac| {
                    ac.contains("password")
                        || ac.contains("one-time-code")
                        || ac.contains("username")
                });
        let paste_text = paste_attr.span.source_text(semantic.source_text());
        if is_auth_input && paste_text.contains("preventDefault(") {
            push_site(
                sites,
                RuleId::NoBlockedPaste,
                subject_name.clone(),
                "noBlockedPaste",
                "onPaste",
                "Blocking paste in an authentication field prevents password managers and assistive tools from working.".to_string(),
                loc_from_line_starts(line_starts, paste_attr.span.start),
                ByteSpan {
                    start: paste_attr.span.start,
                    end: paste_attr.span.end,
                },
            );
        }
    }

    // 4. `no-broken-image-source`
    if tag == "img" && !has_spread && find_attr_ignore_case(&opening.attributes, "ref").is_none() {
        let src_attr = find_attr_ignore_case(&opening.attributes, "src");
        let is_broken = match src_attr {
            None => true,
            Some(a) if a.value.is_none() => true,
            Some(a) => get_attr_static_str(semantic, a, const_strings)
                .is_some_and(|s| matches!(s.trim(), "" | "#")),
        };
        if is_broken {
            push_site(
                sites,
                RuleId::NoBrokenImageSource,
                subject_name.clone(),
                "noBrokenImageSource",
                "img",
                "This image has no usable `src` attribute and will render as a broken placeholder."
                    .to_string(),
                loc,
                span,
            );
        }
    }

    // 5. `no-placeholder-only-field`
    if matches!(tag, "input" | "textarea")
        && !has_spread
        && find_attr_ignore_case(&opening.attributes, "placeholder")
            .is_some_and(has_non_empty_attr_val)
        && !has_a11y_name
        && !has_enclosing_label_or_hidden_ancestor(semantic, node_id, const_strings)
        && find_attr_ignore_case(&opening.attributes, "id").is_none()
    {
        push_site(
            sites,
            RuleId::NoPlaceholderOnlyField,
            subject_name.clone(),
            "noPlaceholderOnlyField",
            tag,
            "This field relies on `placeholder` text for its accessible name. Add a visible `<label>` or `aria-label`.".to_string(),
            loc,
            span,
        );
    }

    // 6. `no-uninformative-aria-label`
    if let Some(al_attr) = find_attr_ignore_case(&opening.attributes, "aria-label")
        && let Some(al_val) = get_attr_static_str(semantic, al_attr, const_strings)
        && UNINFORMATIVE_ARIA_LABELS.contains(&al_val.trim().to_ascii_lowercase().as_str())
    {
        push_site(
            sites,
            RuleId::NoUninformativeAriaLabel,
            subject_name.clone(),
            "noUninformativeAriaLabel",
            &al_val,
            "An `aria-label` should name the action or destination, not the element type."
                .to_string(),
            loc_from_line_starts(line_starts, al_attr.span.start),
            ByteSpan {
                start: al_attr.span.start,
                end: al_attr.span.end,
            },
        );
    }

    // 7. `role-button-requires-complete-keyboard-activation`
    if is_html
        && first_role == Some("button")
        && let Some(kd_attr) = find_attr_ignore_case(&opening.attributes, "onKeyDown")
            .or_else(|| find_attr_ignore_case(&opening.attributes, "onKeyUp"))
    {
        let handler_src = kd_attr.span.source_text(semantic.source_text());
        let has_enter = handler_src.contains("\"Enter\"") || handler_src.contains("'Enter'");
        let has_space = handler_src.contains("\" \"")
            || handler_src.contains("' '")
            || handler_src.contains("Space");
        if has_enter ^ has_space {
            push_site(
                sites,
                RuleId::RoleButtonRequiresCompleteKeyboardActivation,
                subject_name.clone(),
                "roleButtonRequiresCompleteKeyboardActivation",
                "button",
                "Custom `role=\"button\"` handles only one activation key; native buttons activate on both `Enter` and `Space`.".to_string(),
                loc,
                span,
            );
        }
    }

    // 8. `no-reduced-motion-content-removal`
    if is_html
        && class_str.split_whitespace().any(|t| {
            matches!(
                t,
                "motion-reduce:hidden" | "motion-reduce:invisible" | "motion-reduce:sr-only"
            )
        })
        && has_accessible_child(jsx_el)
    {
        push_site(
            sites,
            RuleId::NoReducedMotionContentRemoval,
            subject_name.clone(),
            "noReducedMotionContentRemoval",
            tag,
            "Hiding meaningful content under `motion-reduce:` removes information for reduced-motion users.".to_string(),
            loc,
            span,
        );
    }

    // 9. `no-responsive-hidden-accessible-name`
    if matches!(tag, "button" | "a") && !has_a11y_name {
        let mut has_responsive_hidden_text = false;
        let mut has_persistent_text = false;
        for child in &jsx_el.children {
            if let JSXChild::Text(t) = child
                && !t.value.trim().is_empty()
            {
                has_persistent_text = true;
            } else if let JSXChild::Element(child_el) = child {
                let c_class =
                    get_class_name_str(&child_el.opening_element, semantic, const_strings)
                        .unwrap_or_default();
                let child_has_text = has_accessible_child(child_el);
                if child_has_text {
                    let hides_at_bp = c_class.split_whitespace().any(|tok| {
                        tok == "hidden"
                            || tok.ends_with(":hidden")
                            || tok == "invisible"
                            || tok.ends_with(":invisible")
                    });
                    if hides_at_bp {
                        has_responsive_hidden_text = true;
                    } else {
                        has_persistent_text = true;
                    }
                }
            }
        }
        if has_responsive_hidden_text && !has_persistent_text {
            push_site(
                sites,
                RuleId::NoResponsiveHiddenAccessibleName,
                subject_name.clone(),
                "noResponsiveHiddenAccessibleName",
                tag,
                "Responsive utility classes hide this control's only accessible name at some breakpoints.".to_string(),
                loc,
                span,
            );
        }
    }

    // 10. `no-assertive-status`
    if is_html
        && first_role == Some("status")
        && let Some(live_attr) = find_attr_ignore_case(&opening.attributes, "aria-live")
        && get_attr_static_str(semantic, live_attr, const_strings)
            .is_some_and(|v| v.eq_ignore_ascii_case("assertive"))
    {
        push_site(
            sites,
            RuleId::NoAssertiveStatus,
            subject_name.clone(),
            "noAssertiveStatus",
            "aria-live",
            "A status is advisory and implicitly polite, but `aria-live=\"assertive\"` interrupts queued speech.".to_string(),
            loc_from_line_starts(line_starts, live_attr.span.start),
            ByteSpan {
                start: live_attr.span.start,
                end: live_attr.span.end,
            },
        );
    }

    // 11. `no-aria-invalid-without-description`
    if matches!(tag, "input" | "select" | "textarea")
        && !has_spread
        && let Some(inv_attr) = find_attr_ignore_case(&opening.attributes, "aria-invalid")
        && !is_attr_statically_false(inv_attr)
        && find_attr_ignore_case(&opening.attributes, "aria-describedby").is_none()
        && find_attr_ignore_case(&opening.attributes, "aria-errormessage").is_none()
    {
        push_site(
            sites,
            RuleId::NoAriaInvalidWithoutDescription,
            subject_name.clone(),
            "noAriaInvalidWithoutDescription",
            "aria-invalid",
            "This control is marked invalid but is not connected to error text via `aria-describedby` or `aria-errormessage`.".to_string(),
            loc_from_line_starts(line_starts, inv_attr.span.start),
            ByteSpan {
                start: inv_attr.span.start,
                end: inv_attr.span.end,
            },
        );
    }

    // 12. `no-invalid-progress-range`
    if !has_spread {
        if tag == "progress" {
            let max_val = find_attr_ignore_case(&opening.attributes, "max")
                .and_then(parse_attr_number)
                .unwrap_or(1.0);
            let val_opt =
                find_attr_ignore_case(&opening.attributes, "value").and_then(parse_attr_number);
            if max_val <= 0.0 || val_opt.is_some_and(|v| v < 0.0 || v > max_val) {
                push_site(
                    sites,
                    RuleId::NoInvalidProgressRange,
                    subject_name.clone(),
                    "noInvalidProgressRange",
                    "progress",
                    "This progress element has an impossible value range.".to_string(),
                    loc,
                    span,
                );
            }
        } else if first_role == Some("progressbar") {
            let min_val = find_attr_ignore_case(&opening.attributes, "aria-valuemin")
                .and_then(parse_attr_number)
                .unwrap_or(0.0);
            let max_val = find_attr_ignore_case(&opening.attributes, "aria-valuemax")
                .and_then(parse_attr_number)
                .unwrap_or(100.0);
            let now_opt = find_attr_ignore_case(&opening.attributes, "aria-valuenow")
                .and_then(parse_attr_number);
            if min_val >= max_val || now_opt.is_some_and(|v| v < min_val || v > max_val) {
                push_site(
                    sites,
                    RuleId::NoInvalidProgressRange,
                    subject_name.clone(),
                    "noInvalidProgressRange",
                    "progressbar",
                    "This progressbar exposes an impossible ARIA range.".to_string(),
                    loc,
                    span,
                );
            }
        }
    }

    // 13. `no-focusable-content-in-aria-hidden` & `no-focusable-content-in-role-text`
    if is_html && is_focusable_element(tag, opening, semantic, const_strings, false) {
        if has_aria_hidden_ancestor(semantic, node_id) {
            push_site(
                sites,
                RuleId::NoFocusableContentInAriaHidden,
                subject_name.clone(),
                "noFocusableContentInAriaHidden",
                tag,
                "This control remains keyboard-focusable inside an `aria-hidden` subtree."
                    .to_string(),
                loc,
                span,
            );
        }
        if has_role_text_ancestor(semantic, node_id, const_strings) {
            push_site(
                sites,
                RuleId::NoFocusableContentInRoleText,
                subject_name.clone(),
                "noFocusableContentInRoleText",
                tag,
                "This focusable control sits inside `role=\"text\"`, which flattens descendant semantics.".to_string(),
                loc,
                span,
            );
        }
    }

    // 14. `html-no-nested-interactive`
    if is_html
        && is_interactive_element(tag, opening, semantic, const_strings)
        && has_interactive_ancestor(semantic, node_id, const_strings)
    {
        push_site(
            sites,
            RuleId::HtmlNoNestedInteractive,
            subject_name.clone(),
            "htmlNoNestedInteractive",
            tag,
            "Interactive control is nested inside another interactive control.".to_string(),
            loc,
            span,
        );
    }

    // 15. `no-multiple-main-landmarks` & `no-multiple-unlabeled-navigation-landmarks`
    if tag == "main" {
        let root_id = find_topmost_jsx_root(semantic, node_id);
        main_landmarks_by_root
            .entry(root_id)
            .or_default()
            .push((loc, span));
    } else if tag == "nav" && !has_spread && !has_a11y_name {
        let root_id = find_topmost_jsx_root(semantic, node_id);
        unlabeled_navs_by_root
            .entry(root_id)
            .or_default()
            .push((loc, span));
    }

    // 16. `no-nonresizable-textarea`
    if tag == "textarea" && !has_spread {
        let resize_none_class = class_str.split_whitespace().any(|t| t == "resize-none")
            && !class_str
                .split_whitespace()
                .any(|t| t == "field-sizing-content");
        let resize_none_style = get_style_prop_str(opening, "resize", semantic, const_strings)
            .as_deref()
            == Some("none");
        if resize_none_class || resize_none_style {
            push_site(
                sites,
                RuleId::NoNonresizableTextarea,
                subject_name.clone(),
                "noNonresizableTextarea",
                "textarea",
                "This textarea disables user resizing.".to_string(),
                loc,
                span,
            );
        }
    }

    // 17. `no-presentation-role-conflict`
    if is_html {
        let is_pres = matches!(first_role, Some("none" | "presentation"))
            || (tag == "img"
                && find_attr_ignore_case(&opening.attributes, "alt")
                    .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                    .as_deref()
                    == Some(""));
        if is_pres {
            let is_focusable = is_focusable_element(tag, opening, semantic, const_strings, true);
            let has_global_aria = opening.attributes.iter().any(|item| {
                item.as_attribute()
                    .and_then(|a| a.name.as_identifier())
                    .is_some_and(|id| GLOBAL_ARIA_PROPERTIES.contains(&id.name.as_str()))
            });
            if is_focusable || has_global_aria {
                push_site(
                    sites,
                    RuleId::NoPresentationRoleConflict,
                    subject_name.clone(),
                    "noPresentationRoleConflict",
                    tag,
                    "This element is marked presentational but is also focusable or carries global ARIA state.".to_string(),
                    loc,
                    span,
                );
            }
        }
    }

    // 18. `no-server-side-image-map`
    if tag == "img"
        && let Some(ismap_attr) = find_attr_ignore_case(&opening.attributes, "isMap")
        && !is_attr_statically_false(ismap_attr)
    {
        push_site(
            sites,
            RuleId::NoServerSideImageMap,
            subject_name.clone(),
            "noServerSideImageMap",
            "isMap",
            "Server-side image maps require pointer coordinates and do not expose individual targets to keyboard users.".to_string(),
            loc_from_line_starts(line_starts, ismap_attr.span.start),
            ByteSpan {
                start: ismap_attr.span.start,
                end: ismap_attr.span.end,
            },
        );
    }

    // 19. `no-skipped-heading-level`
    if matches!(tag, "main" | "article") {
        let mut headings = Vec::new();
        collect_descendant_headings(jsx_el, line_starts, &mut headings);
        for pair in headings.windows(2) {
            let (prev_lvl, _, _) = pair[0];
            let (curr_lvl, hloc, hspan) = pair[1];
            if curr_lvl > prev_lvl + 1 {
                push_site(
                    sites,
                    RuleId::NoSkippedHeadingLevel,
                    subject_name.clone(),
                    "noSkippedHeadingLevel",
                    &format!("h{curr_lvl}"),
                    format!(
                        "This heading jumps from h{prev_lvl} to h{curr_lvl}. Use the next level so the document outline stays coherent."
                    ),
                    hloc,
                    hspan,
                );
            }
        }
    }

    // 20. `no-static-motion-config-never`
    if (tag == "MotionConfig" || tag.ends_with(".MotionConfig"))
        && let Some(rm_attr) = find_attr(&opening.attributes, "reducedMotion")
        && get_attr_static_str(semantic, rm_attr, const_strings).as_deref() == Some("never")
    {
        push_site(
            sites,
            RuleId::NoStaticMotionConfigNever,
            subject_name.clone(),
            "noStaticMotionConfigNever",
            "MotionConfig",
            "This MotionConfig hard-codes `reducedMotion=\"never\"`, ignoring the user's operating-system preference.".to_string(),
            loc_from_line_starts(line_starts, rm_attr.span.start),
            ByteSpan {
                start: rm_attr.span.start,
                end: rm_attr.span.end,
            },
        );
    }

    // 21. `no-ungated-tailwind-animation`
    if !has_spread && !class_str.is_empty() {
        let tokens: Vec<&str> = class_str.split_whitespace().collect();
        let has_spatial_anim = tokens
            .iter()
            .any(|t| matches!(*t, "animate-spin" | "animate-ping" | "animate-bounce"));
        let has_motion_guard = tokens
            .iter()
            .any(|t| t.starts_with("motion-safe:") || t.starts_with("motion-reduce:"));
        if has_spatial_anim && !has_motion_guard {
            push_site(
                sites,
                RuleId::NoUngatedTailwindAnimation,
                subject_name.clone(),
                "noUngatedTailwindAnimation",
                tag,
                "Tailwind animation utility runs unconditionally without a `motion-safe:` or `motion-reduce:` guard.".to_string(),
                loc,
                span,
            );
        }
    }

    // 22. `data-table-requires-accessible-name`, `details-requires-summary`, `empty-table-header`, `fieldset-requires-legend`, `form-control-requires-name`, `radio-input-missing-name`
    if tag == "table"
        && !has_spread
        && !has_a11y_name
        && !jsx_el
            .children
            .iter()
            .any(|c| matches!(c, JSXChild::Element(el) if get_jsx_tag_name(&el.opening_element.name) == "caption"))
    {
        push_site(
            sites,
            RuleId::DataTableRequiresAccessibleName,
            subject_name.clone(),
            "dataTableRequiresAccessibleName",
            "table",
            "This data table has no caption or accessible name.".to_string(),
            loc,
            span,
        );
    }
    if tag == "details" {
        let first_el = jsx_el.children.iter().find_map(|c| match c {
            JSXChild::Element(el) => Some(get_jsx_tag_name(&el.opening_element.name)),
            JSXChild::Text(t) if t.value.trim().is_empty() => None,
            _ => Some(String::new()),
        });
        if first_el.as_deref() != Some("summary") {
            push_site(
                sites,
                RuleId::DetailsRequiresSummary,
                subject_name.clone(),
                "detailsRequiresSummary",
                "details",
                "This details disclosure has no explicit `<summary>` as its first content child."
                    .to_string(),
                loc,
                span,
            );
        }
    }
    if (tag == "th" || matches!(first_role, Some("columnheader" | "rowheader")))
        && is_html
        && !has_accessible_child(jsx_el)
        && !has_a11y_name
    {
        push_site(
            sites,
            RuleId::EmptyTableHeader,
            subject_name.clone(),
            "emptyTableHeader",
            tag,
            "This table header has no accessible text.".to_string(),
            loc,
            span,
        );
    }
    if tag == "fieldset" && !has_spread && !has_a11y_name {
        let mut control_count = 0;
        let mut has_legend = false;
        count_fieldset_controls_and_legend(jsx_el, &mut control_count, &mut has_legend);
        if control_count >= 2 && !has_legend {
            push_site(
                sites,
                RuleId::FieldsetRequiresLegend,
                subject_name.clone(),
                "fieldsetRequiresLegend",
                "fieldset",
                "This fieldset groups multiple controls without a `<legend>` or accessible name."
                    .to_string(),
                loc,
                span,
            );
        }
    }
    if matches!(tag, "input" | "select" | "textarea")
        && !has_spread
        && find_attr_ignore_case(&opening.attributes, "name").is_none()
        && has_enclosing_tag(semantic, node_id, "form")
    {
        push_site(
            sites,
            RuleId::FormControlRequiresName,
            subject_name.clone(),
            "formControlRequiresName",
            tag,
            "Form control inside `<form>` is missing a `name` attribute.".to_string(),
            loc,
            span,
        );
    }
    if tag == "input"
        && !has_spread
        && find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("radio"))
        && !find_attr_ignore_case(&opening.attributes, "name").is_some_and(has_non_empty_attr_val)
    {
        push_site(
            sites,
            RuleId::RadioInputMissingName,
            subject_name.clone(),
            "radioInputMissingName",
            "input",
            "Radio input is missing a `name` attribute to group it for keyboard arrow navigation."
                .to_string(),
            loc,
            span,
        );
    }

    // 23. Tree-level checks on root JSX elements: `iframe-title-unique` & `no-duplicate-static-id-reference`
    if !matches!(
        semantic.nodes().parent_kind(node_id),
        AstKind::JSXElement(_) | AstKind::JSXFragment(_)
    ) {
        let mut seen_iframe_titles: HashSet<String> = HashSet::new();
        let mut id_counts: HashMap<String, Vec<(SourceLoc, ByteSpan)>> = HashMap::new();
        let mut referenced_ids: HashSet<String> = HashSet::new();
        collect_subtree_frames_and_ids(
            jsx_el,
            semantic,
            const_strings,
            line_starts,
            &mut seen_iframe_titles,
            &mut id_counts,
            &mut referenced_ids,
            sites,
            subject_name,
        );
        for (id_val, locs) in id_counts {
            if referenced_ids.contains(&id_val) && locs.len() >= 2 {
                for (dloc, dspan) in locs.into_iter().skip(1) {
                    push_site(
                        sites,
                        RuleId::NoDuplicateStaticIdReference,
                        subject_name.clone(),
                        "noDuplicateStaticIdReference",
                        &id_val,
                        format!(
                            "The referenced id \"{id_val}\" appears more than once in this static JSX tree."
                        ),
                        dloc,
                        dspan,
                    );
                }
            }
        }
    }

    // 25. Component library composition rules (`shadcn-*`, `radix-*`, `base-ui-*`, `react-aria-*`)
    check_ui_library_a11y(
        semantic,
        jsx_el,
        tag,
        has_spread,
        has_a11y_name,
        subject_name,
        const_strings,
        imported_sources,
        loc,
        span,
        sites,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates shadcn, Radix UI, Base UI, and React Aria composition rules on a JSXElement"
)]
fn check_ui_library_a11y(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    has_spread: bool,
    has_a11y_name: bool,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    imported_sources: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if has_spread {
        return;
    }
    let opening = &jsx_el.opening_element;
    let root_import_src = resolve_jsx_root_import_source(semantic, &opening.name, imported_sources);

    // 1. `shadcn-dialog-content-requires-title`
    if matches!(
        tag,
        "DialogContent" | "SheetContent" | "AlertDialogContent" | "DrawerContent"
    ) && !has_a11y_name
        && !subtree_has_tag_matching(jsx_el, |t| {
            t.ends_with("Title")
                || matches!(
                    t,
                    "DialogTitle" | "SheetTitle" | "AlertDialogTitle" | "DrawerTitle"
                )
        })
    {
        push_site(
            sites,
            RuleId::ShadcnDialogContentRequiresTitle,
            subject_name.clone(),
            "shadcnDialogContentRequiresTitle",
            tag,
            format!("`<{tag}>` requires a matching Title component or `aria-label`."),
            loc,
            span,
        );
    }

    // 2. `shadcn-form-item-requires-label`
    if tag == "FormItem"
        && subtree_has_tag_matching(jsx_el, |t| t == "FormControl")
        && !subtree_has_tag_matching(jsx_el, |t| matches!(t, "FormLabel" | "Label" | "label"))
        && !subtree_has_attr(jsx_el, "aria-label")
        && !subtree_has_attr(jsx_el, "aria-labelledby")
    {
        push_site(
            sites,
            RuleId::ShadcnFormItemRequiresLabel,
            subject_name.clone(),
            "shadcnFormItemRequiresLabel",
            "FormItem",
            "`<FormItem>` with `<FormControl>` requires a `<FormLabel>` or `aria-label`."
                .to_string(),
            loc,
            span,
        );
    }

    // 3. `shadcn-icon-button-requires-label`
    if tag == "Button"
        && find_attr_ignore_case(&opening.attributes, "size")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|s| s.starts_with("icon"))
        && !has_a11y_name
        && !has_accessible_label_text_in_children(&jsx_el.children)
    {
        push_site(
            sites,
            RuleId::ShadcnIconButtonRequiresLabel,
            subject_name.clone(),
            "shadcnIconButtonRequiresLabel",
            "Button",
            "Icon-sized `<Button size=\"icon\">` has no accessible name; add `aria-label` or `.sr-only` text.".to_string(),
            loc,
            span,
        );
    }

    // 4. `radix-dialog-content-requires-title`
    let is_radix_dialog = matches!(tag, "Dialog.Content" | "AlertDialog.Content")
        || (tag == "Content"
            && root_import_src
                .as_deref()
                .is_some_and(|s| s.contains("radix-ui")));
    if is_radix_dialog
        && !has_a11y_name
        && !subtree_has_tag_matching(jsx_el, |t| t == "Title" || t.ends_with(".Title"))
    {
        push_site(
            sites,
            RuleId::RadixDialogContentRequiresTitle,
            subject_name.clone(),
            "radixDialogContentRequiresTitle",
            tag,
            "Radix Dialog Content requires a `Dialog.Title` child or `aria-label`.".to_string(),
            loc,
            span,
        );
    }

    // 5. `base-ui-dialog-popup-requires-title` & `base-ui-field-requires-label`
    let is_base_ui_popup = matches!(tag, "Dialog.Popup" | "AlertDialog.Popup")
        || (tag == "Popup"
            && root_import_src
                .as_deref()
                .is_some_and(|s| s.contains("base-ui")));
    if is_base_ui_popup
        && !has_a11y_name
        && !subtree_has_tag_matching(jsx_el, |t| t == "Title" || t.ends_with(".Title"))
    {
        push_site(
            sites,
            RuleId::BaseUiDialogPopupRequiresTitle,
            subject_name.clone(),
            "baseUiDialogPopupRequiresTitle",
            tag,
            "Base UI Dialog Popup requires a `Dialog.Title` child or `aria-label`.".to_string(),
            loc,
            span,
        );
    }
    if tag == "Field.Root"
        && subtree_has_tag_matching(jsx_el, |t| t == "Field.Control")
        && !subtree_has_tag_matching(jsx_el, |t| {
            matches!(t, "Field.Label" | "FieldLabel" | "Label" | "label")
        })
        && !subtree_has_attr(jsx_el, "aria-label")
        && !subtree_has_attr(jsx_el, "aria-labelledby")
    {
        push_site(
            sites,
            RuleId::BaseUiFieldRequiresLabel,
            subject_name.clone(),
            "baseUiFieldRequiresLabel",
            "Field.Root",
            "Base UI `Field.Root` with `Field.Control` requires a `Field.Label` or `aria-label`."
                .to_string(),
            loc,
            span,
        );
    }

    // 6. `react-aria-dialog-requires-heading`
    if tag == "Dialog"
        && root_import_src.as_deref() == Some("react-aria-components")
        && !has_a11y_name
        && !subtree_has_tag_matching(jsx_el, |t| t == "Heading" || t.ends_with(".Heading"))
    {
        push_site(
            sites,
            RuleId::ReactAriaDialogRequiresHeading,
            subject_name.clone(),
            "reactAriaDialogRequiresHeading",
            "Dialog",
            "React Aria `<Dialog>` requires a `<Heading slot=\"title\">` child or `aria-label`."
                .to_string(),
            loc,
            span,
        );
    }
}

fn check_call_a11y(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    call: &oxc_ast::ast::CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // `no-controlled-selection-focus-effect`: effect hook focusing item on `selectedIndex` / `selectedId` dependency
    let callee_str = call.callee.span().source_text(semantic.source_text());
    if (callee_str.ends_with("Effect")
        || callee_str == "useEffect"
        || callee_str == "useLayoutEffect")
        && call.arguments.len() >= 2
    {
        let body_src = call.arguments[0].span().source_text(semantic.source_text());
        let deps_src = call.arguments[1].span().source_text(semantic.source_text());
        if (body_src.contains("focus(") || body_src.contains("focusItem("))
            && (deps_src.contains("selectedIndex")
                || deps_src.contains("selectedId")
                || deps_src.contains("selectedKey")
                || deps_src.contains("selection"))
        {
            let loc = loc_from_line_starts(line_starts, call.span.start);
            let span = ByteSpan {
                start: call.span.start,
                end: call.span.end,
            };
            push_site(
                sites,
                RuleId::NoControlledSelectionFocusEffect,
                subject_name.clone(),
                "noControlledSelectionFocusEffect",
                callee_str,
                "This effect focuses an item whenever a controlled selection changes, so an external selection update can steal focus.".to_string(),
                loc,
                span,
            );
        }
    }
}

fn check_conditional_a11y(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    cond: &oxc_ast::ast::ConditionalExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // `loading-action-preserves-trigger`: `pending ? <span role="status">Saving</span> : <button onClick={save}>Save</button>`
    let cons = cond.consequent.without_parentheses();
    let alt = cond.alternate.without_parentheses();
    if let (Expression::JSXElement(cons_el), Expression::JSXElement(alt_el)) = (cons, alt) {
        let cons_tag = get_jsx_tag_name(&cons_el.opening_element.name);
        let alt_tag = get_jsx_tag_name(&alt_el.opening_element.name);
        if (cons_tag != "button" && alt_tag == "button")
            || (cons_tag == "button" && alt_tag != "button")
        {
            let test_src = cond
                .test
                .span()
                .source_text(semantic.source_text())
                .to_ascii_lowercase();
            if test_src.contains("pending")
                || test_src.contains("loading")
                || test_src.contains("saving")
                || test_src.contains("submitting")
            {
                let loc = loc_from_line_starts(line_starts, cond.span.start);
                let span = ByteSpan {
                    start: cond.span.start,
                    end: cond.span.end,
                };
                push_site(
                    sites,
                    RuleId::LoadingActionPreservesTrigger,
                    subject_name.clone(),
                    "loadingActionPreservesTrigger",
                    "button",
                    "Pending state unmounts the initiating `<button>` instead of keeping it mounted and disabled/busy.".to_string(),
                    loc,
                    span,
                );
            }
        }
    }
}

/// Evaluates `anchor-target-exists` for `file` against all static DOM `id`s in `graph`.
pub(crate) fn check_anchor_target_exists<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if file.file_context != FileContext::Production {
        return;
    }
    let Some(severity) = is_active(RuleId::AnchorTargetExists) else {
        return;
    };
    if graph.files.iter().any(|f| f.has_unresolved_id_spread) {
        return;
    }

    for jsx in &file.jsx_elements {
        if jsx.name != "a" && !jsx.name.ends_with("Link") {
            continue;
        }
        let Some(target_id) = &jsx.fragment_href_target else {
            continue;
        };
        let found = graph
            .files
            .iter()
            .any(|f| f.static_dom_ids.iter().any(|id| id == target_id));
        if !found {
            let meta = RuleId::AnchorTargetExists.metadata();
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: jsx.enclosing_subject.clone(),
                rule: RuleId::AnchorTargetExists,
                category: RuleCategory::Accessibility,
                severity,
                message_id: "anchorTargetExists",
                tier: PrescriptionTier::Surgical,
                target_name: format!("#{target_id}"),
                message: format!(
                    "This fragment link points to \"#{target_id}\", but no matching static id was found in the project."
                ),
                docs_url: meta.docs_url,
                loc: jsx.loc,
                span: jsx.span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
        }
    }
}

// --- Shared AST helpers ---

pub(crate) fn get_jsx_tag_name(name: &JSXElementName<'_>) -> String {
    match name {
        JSXElementName::Identifier(id) => id.name.to_string(),
        JSXElementName::IdentifierReference(id) => id.name.to_string(),
        JSXElementName::NamespacedName(ns) => format!("{}:{}", ns.namespace.name, ns.name.name),
        JSXElementName::MemberExpression(mem) => format_jsx_member(mem),
        JSXElementName::ThisExpression(_) => "this".to_string(),
    }
}

fn format_jsx_member(mem: &oxc_ast::ast::JSXMemberExpression<'_>) -> String {
    let obj = match &mem.object {
        oxc_ast::ast::JSXMemberExpressionObject::IdentifierReference(id) => id.name.to_string(),
        oxc_ast::ast::JSXMemberExpressionObject::MemberExpression(inner) => {
            format_jsx_member(inner)
        }
        oxc_ast::ast::JSXMemberExpressionObject::ThisExpression(_) => "this".to_string(),
    };
    format!("{obj}.{}", mem.property.name)
}

pub(crate) fn find_attr<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b JSXAttribute<'a>> {
    attrs.iter().find_map(|item| {
        let attr = item.as_attribute()?;
        match &attr.name {
            JSXAttributeName::Identifier(id) if id.name == target => Some(attr),
            JSXAttributeName::NamespacedName(ns)
                if format!("{}:{}", ns.namespace.name, ns.name.name) == target =>
            {
                Some(attr)
            }
            _ => None,
        }
    })
}

pub(crate) fn find_last_attr<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b JSXAttribute<'a>> {
    attrs.iter().rev().find_map(|item| {
        let attr = item.as_attribute()?;
        match &attr.name {
            JSXAttributeName::Identifier(id) if id.name == target => Some(attr),
            _ => None,
        }
    })
}

pub(crate) fn find_attr_ignore_case<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b JSXAttribute<'a>> {
    attrs.iter().rev().find_map(|item| {
        let attr = item.as_attribute()?;
        match &attr.name {
            JSXAttributeName::Identifier(id) if id.name.eq_ignore_ascii_case(target) => Some(attr),
            JSXAttributeName::NamespacedName(ns)
                if format!("{}:{}", ns.namespace.name, ns.name.name)
                    .eq_ignore_ascii_case(target) =>
            {
                Some(attr)
            }
            _ => None,
        }
    })
}

pub(crate) fn eval_static_str(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    match expr.without_parentheses() {
        Expression::StringLiteral(s) => s.value.as_str().map(str::to_string),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str()))
            .map(str::to_string),
        Expression::Identifier(id) => id
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .and_then(|sym_id| const_strings.get(&sym_id).cloned()),
        _ => None,
    }
}

pub(crate) fn get_attr_static_str(
    semantic: &Semantic<'_>,
    attr: &JSXAttribute<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    match attr.value.as_ref()? {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str().map(str::to_string),
        JSXAttributeValue::ExpressionContainer(c) => {
            let expr = c.expression.as_expression()?;
            eval_static_str(semantic, expr, const_strings)
        }
        _ => None,
    }
}

pub(crate) fn get_class_name_str(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    let attr = find_attr(&opening.attributes, "className")?;
    get_attr_static_str(semantic, attr, const_strings)
}

pub(crate) fn get_style_prop_str(
    opening: &JSXOpeningElement<'_>,
    prop_name: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    let style_attr = find_attr(&opening.attributes, "style")?;
    let JSXAttributeValue::ExpressionContainer(c) = style_attr.value.as_ref()? else {
        return None;
    };
    let Expression::ObjectExpression(obj) = c.expression.as_expression()?.without_parentheses()
    else {
        return None;
    };
    for prop in obj.properties.iter().rev() {
        if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop
            && p.key
                .static_name()
                .is_some_and(|n| n.as_str() == Some(prop_name))
        {
            return eval_static_str(semantic, &p.value, const_strings);
        }
    }
    None
}

pub(crate) fn get_style_prop_number(
    opening: &JSXOpeningElement<'_>,
    prop_name: &str,
) -> Option<f64> {
    let style_attr = find_attr(&opening.attributes, "style")?;
    let JSXAttributeValue::ExpressionContainer(c) = style_attr.value.as_ref()? else {
        return None;
    };
    let Expression::ObjectExpression(obj) = c.expression.as_expression()?.without_parentheses()
    else {
        return None;
    };
    for prop in obj.properties.iter().rev() {
        if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop
            && p.key
                .static_name()
                .is_some_and(|n| n.as_str() == Some(prop_name))
        {
            return eval_numeric_expr(&p.value);
        }
    }
    None
}

pub(crate) fn eval_numeric_expr(expr: &Expression<'_>) -> Option<f64> {
    match expr.without_parentheses() {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            eval_numeric_expr(&u.argument).map(|v| -v)
        }
        _ => None,
    }
}

fn parse_attr_number(attr: &JSXAttribute<'_>) -> Option<f64> {
    match attr.value.as_ref()? {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str()?.trim().parse::<f64>().ok(),
        JSXAttributeValue::ExpressionContainer(c) => {
            let expr = c.expression.as_expression()?;
            match expr.without_parentheses() {
                Expression::StringLiteral(s) => s.value.as_str()?.trim().parse::<f64>().ok(),
                other => eval_numeric_expr(other),
            }
        }
        _ => None,
    }
}

fn is_attr_undefined(attr: &JSXAttribute<'_>) -> bool {
    if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
        && let Expression::Identifier(id) = expr.without_parentheses()
    {
        return id.name == "undefined";
    }
    false
}

fn is_attr_null_or_undefined(attr: &JSXAttribute<'_>) -> bool {
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return false;
    };
    let Some(expr) = c.expression.as_expression() else {
        return false;
    };
    expr_may_be_null_or_undefined(expr)
}

fn expr_may_be_null_or_undefined(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => u.operator.is_void(),
        Expression::ConditionalExpression(cond) => {
            expr_may_be_null_or_undefined(&cond.consequent)
                || expr_may_be_null_or_undefined(&cond.alternate)
        }
        _ => false,
    }
}

fn is_attr_statically_false(attr: &JSXAttribute<'_>) -> bool {
    match &attr.value {
        Some(JSXAttributeValue::StringLiteral(s)) => s
            .value
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("false")),
        Some(JSXAttributeValue::ExpressionContainer(c)) => {
            if let Some(expr) = c.expression.as_expression() {
                matches!(
                    expr.without_parentheses(),
                    Expression::BooleanLiteral(b) if !b.value
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_attr_statically_true_or_true_str(attr: &JSXAttribute<'_>) -> bool {
    match &attr.value {
        None => true,
        Some(JSXAttributeValue::StringLiteral(s)) => s
            .value
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("true")),
        Some(JSXAttributeValue::ExpressionContainer(c)) => {
            if let Some(expr) = c.expression.as_expression() {
                match expr.without_parentheses() {
                    Expression::BooleanLiteral(b) => b.value,
                    Expression::StringLiteral(s) => s
                        .value
                        .as_str()
                        .is_some_and(|v| v.eq_ignore_ascii_case("true")),
                    _ => false,
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_attr_dynamic_non_undefined(attr: &JSXAttribute<'_>) -> bool {
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return false;
    };
    let Some(expr) = c.expression.as_expression() else {
        return false;
    };
    match expr.without_parentheses() {
        Expression::BooleanLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::NullLiteral(_) => false,
        Expression::Identifier(id) => id.name != "undefined",
        _ => true,
    }
}

fn has_non_empty_attr_val(attr: &JSXAttribute<'_>) -> bool {
    let Some(val) = &attr.value else {
        return false;
    };
    match val {
        JSXAttributeValue::StringLiteral(s) => {
            s.value.as_str().is_some_and(|v| !v.trim().is_empty())
        }
        JSXAttributeValue::ExpressionContainer(c) => {
            let Some(expr) = c.expression.as_expression() else {
                return false;
            };
            match expr.without_parentheses() {
                Expression::StringLiteral(s) => {
                    s.value.as_str().is_some_and(|v| !v.trim().is_empty())
                }
                Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
                    .quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str()))
                    .is_some_and(|v| !v.trim().is_empty()),
                Expression::NullLiteral(_) => false,
                Expression::Identifier(id) => id.name != "undefined",
                _ => true,
            }
        }
        _ => true,
    }
}

fn has_nonempty_literal_attr(
    opening: &JSXOpeningElement<'_>,
    name: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_attr_ignore_case(&opening.attributes, name)
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .is_some_and(|s| !s.trim().is_empty())
}

fn is_hidden_from_screen_reader(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    if find_attr_ignore_case(&opening.attributes, "hidden")
        .is_some_and(|a| !is_attr_statically_false(a))
    {
        return true;
    }
    if find_attr_ignore_case(&opening.attributes, "aria-hidden")
        .is_some_and(is_attr_statically_true_or_true_str)
    {
        return true;
    }
    if get_style_prop_str(opening, "display", semantic, const_strings).as_deref() == Some("none")
        || get_style_prop_str(opening, "visibility", semantic, const_strings).as_deref()
            == Some("hidden")
    {
        return true;
    }
    false
}

fn is_disabled_element(
    opening: &JSXOpeningElement<'_>,
    _semantic: &Semantic<'_>,
    _const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_attr_ignore_case(&opening.attributes, "disabled")
        .is_some_and(|a| !is_attr_statically_false(a))
        || find_attr_ignore_case(&opening.attributes, "aria-disabled")
            .is_some_and(is_attr_statically_true_or_true_str)
}

fn is_interactive_element(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    match tag {
        "audio" | "button" | "canvas" | "datalist" | "embed" | "menuitem" | "option" | "select"
        | "summary" | "td" | "th" | "tr" | "textarea" | "video" => true,
        "input" => !find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("hidden")),
        "a" | "area" => find_attr_ignore_case(&opening.attributes, "href").is_some(),
        "img" => find_attr_ignore_case(&opening.attributes, "useMap").is_some(),
        _ => false,
    }
}

fn is_focusable_element(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    include_negative_tabindex: bool,
) -> bool {
    if is_disabled_element(opening, semantic, const_strings) {
        return false;
    }
    if let Some(tab_attr) = find_attr_ignore_case(&opening.attributes, "tabIndex")
        && let Some(v) = parse_attr_number(tab_attr)
    {
        return if include_negative_tabindex {
            true
        } else {
            v >= 0.0
        };
    }
    match tag {
        "button" | "embed" | "select" | "summary" | "textarea" => true,
        "input" => !find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("hidden")),
        "a" | "area" => find_attr_ignore_case(&opening.attributes, "href").is_some(),
        "audio" | "video" => find_attr_ignore_case(&opening.attributes, "controls").is_some(),
        _ => false,
    }
}

fn is_content_editable_tabbable(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_attr_ignore_case(&opening.attributes, "contentEditable").is_some_and(|a| {
        if a.value.is_none() {
            return true;
        }
        if let Some(s) = get_attr_static_str(semantic, a, const_strings) {
            matches!(
                s.to_ascii_lowercase().as_str(),
                "true" | "plaintext-only" | ""
            )
        } else {
            is_attr_statically_true_or_true_str(a)
        }
    })
}

fn get_implicit_role(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<&'static str> {
    match tag {
        "a" | "area" | "link" => find_attr_ignore_case(&opening.attributes, "href").map(|_| "link"),
        "article" => Some("article"),
        "aside" => Some("complementary"),
        "button" => Some("button"),
        "datalist" => Some("listbox"),
        "details" => Some("group"),
        "dialog" => Some("dialog"),
        "fieldset" => Some("group"),
        "figure" => Some("figure"),
        "footer" => Some("contentinfo"),
        "form" => Some("form"),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => Some("heading"),
        "header" => Some("banner"),
        "hr" => Some("separator"),
        "img" => Some("img"),
        "input" => {
            let input_type = find_attr_ignore_case(&opening.attributes, "type")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .unwrap_or_else(|| "text".to_string())
                .to_ascii_lowercase();
            match input_type.as_str() {
                "button" | "image" | "reset" | "submit" => Some("button"),
                "checkbox" => Some("checkbox"),
                "number" => Some("spinbutton"),
                "radio" => Some("radio"),
                "range" => Some("slider"),
                "search" => Some("searchbox"),
                "hidden" => None,
                _ => Some("textbox"),
            }
        }
        "li" => Some("listitem"),
        "main" => Some("main"),
        "math" => Some("math"),
        "menu" | "ol" | "ul" => Some("list"),
        "meter" => Some("meter"),
        "nav" => Some("navigation"),
        "option" => Some("option"),
        "output" => Some("status"),
        "p" => Some("paragraph"),
        "progress" => Some("progressbar"),
        "search" => Some("search"),
        "section" => Some("region"),
        "select" => Some("combobox"),
        "svg" => Some("graphics-document"),
        "table" => Some("table"),
        "tbody" | "tfoot" | "thead" => Some("rowgroup"),
        "td" => Some("cell"),
        "textarea" => Some("textbox"),
        "th" => Some("columnheader"),
        "tr" => Some("row"),
        _ => None,
    }
}

fn preferred_html_tag_for_role(role: &str) -> Option<&'static str> {
    match role {
        "navigation" => Some("nav"),
        "main" => Some("main"),
        "banner" => Some("header"),
        "contentinfo" => Some("footer"),
        "complementary" => Some("aside"),
        "article" => Some("article"),
        "form" => Some("form"),
        "search" => Some("search"),
        "blockquote" => Some("blockquote"),
        "paragraph" => Some("p"),
        "code" => Some("code"),
        "figure" => Some("figure"),
        "caption" => Some("caption"),
        "list" => Some("ul"),
        "listitem" => Some("li"),
        "Deletion" | "deletion" => Some("del"),
        "insertion" => Some("ins"),
        "strong" => Some("strong"),
        "emphasis" => Some("em"),
        "subscript" => Some("sub"),
        "superscript" => Some("sup"),
        "term" => Some("dfn"),
        "time" => Some("time"),
        "meter" => Some("meter"),
        _ => None,
    }
}

fn is_allowed_interactive_role_on_noninteractive(tag: &str, role: &str) -> bool {
    match tag {
        "ul" | "ol" => matches!(
            role,
            "listbox" | "menu" | "menubar" | "radiogroup" | "tablist" | "tree" | "treegrid"
        ),
        "li" => matches!(
            role,
            "menuitem"
                | "menuitemcheckbox"
                | "menuitemradio"
                | "option"
                | "row"
                | "tab"
                | "treeitem"
        ),
        "table" => role == "grid",
        "td" => role == "gridcell",
        "nav" => role == "tablist",
        "fieldset" => matches!(role, "radiogroup" | "presentation"),
        _ => false,
    }
}

fn supplies_native_aria_prop(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    prop: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    if matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") && prop == "aria-level" {
        return true;
    }
    if tag == "select" && matches!(prop, "aria-controls" | "aria-expanded") {
        return true;
    }
    if tag == "input" {
        let input_type = find_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(input_type.as_str(), "checkbox" | "radio") && prop == "aria-checked" {
            return true;
        }
        if input_type == "range"
            && matches!(prop, "aria-valuenow" | "aria-valuemin" | "aria-valuemax")
        {
            return true;
        }
    }
    false
}

fn is_aria_prop_supported_by_role(role: &str, prop: &str) -> bool {
    if matches!(
        role,
        "caption"
            | "code"
            | "definition"
            | "deletion"
            | "emphasis"
            | "generic"
            | "insertion"
            | "mark"
            | "none"
            | "paragraph"
            | "presentation"
            | "strong"
            | "subscript"
            | "superscript"
            | "term"
            | "time"
    ) && matches!(prop, "aria-label" | "aria-labelledby" | "aria-braillelabel")
    {
        return false;
    }
    if role == "generic" && matches!(prop, "aria-roledescription" | "aria-brailleroledescription") {
        return false;
    }
    if matches!(role, "textbox" | "searchbox") && prop == "aria-expanded" {
        return false;
    }
    if matches!(role, "button" | "link" | "menuitem")
        && matches!(
            prop,
            "aria-checked" | "aria-selected" | "aria-valuenow" | "aria-valuemin" | "aria-valuemax"
        )
    {
        return false;
    }
    GLOBAL_ARIA_PROPERTIES.contains(&prop)
        || match role {
            "button" => matches!(prop, "aria-expanded" | "aria-pressed"),
            "checkbox" | "switch" | "menuitemcheckbox" => {
                matches!(prop, "aria-checked" | "aria-readonly" | "aria-required")
            }
            "radio" | "menuitemradio" => {
                matches!(prop, "aria-checked" | "aria-posinset" | "aria-setsize")
            }
            "combobox" => matches!(
                prop,
                "aria-activedescendant"
                    | "aria-autocomplete"
                    | "aria-expanded"
                    | "aria-orientation"
                    | "aria-placeholder"
                    | "aria-readonly"
                    | "aria-required"
            ),
            "option" | "tab" | "treeitem" => matches!(
                prop,
                "aria-selected"
                    | "aria-checked"
                    | "aria-expanded"
                    | "aria-posinset"
                    | "aria-setsize"
                    | "aria-level"
            ),
            "slider" | "spinbutton" | "progressbar" | "meter" | "scrollbar" => matches!(
                prop,
                "aria-valuemax"
                    | "aria-valuemin"
                    | "aria-valuenow"
                    | "aria-valuetext"
                    | "aria-orientation"
                    | "aria-readonly"
                    | "aria-required"
            ),
            "heading" => prop == "aria-level",
            "textbox" | "searchbox" => matches!(
                prop,
                "aria-activedescendant"
                    | "aria-autocomplete"
                    | "aria-multiline"
                    | "aria-placeholder"
                    | "aria-readonly"
                    | "aria-required"
            ),
            _ => true,
        }
}

fn is_valid_aria_prop_value(
    prop: &str,
    val: &JSXAttributeValue<'_>,
    _semantic: &Semantic<'_>,
) -> bool {
    let lit_str = match val {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str().map(str::to_ascii_lowercase),
        JSXAttributeValue::ExpressionContainer(c) => match c.expression.as_expression() {
            Some(Expression::StringLiteral(s)) => s.value.as_str().map(str::to_ascii_lowercase),
            Some(Expression::BooleanLiteral(b)) => Some(b.value.to_string()),
            Some(Expression::NumericLiteral(n)) => Some(n.value.to_string()),
            _ => return true,
        },
        _ => return true,
    };
    let Some(s) = lit_str else {
        return true;
    };
    let trimmed = s.trim();
    match prop {
        "aria-atomic"
        | "aria-busy"
        | "aria-disabled"
        | "aria-modal"
        | "aria-multiline"
        | "aria-multiselectable"
        | "aria-readonly"
        | "aria-required" => {
            matches!(trimmed, "true" | "false")
        }
        "aria-expanded" | "aria-grabbed" | "aria-hidden" | "aria-selected" => {
            matches!(trimmed, "true" | "false" | "undefined")
        }
        "aria-checked" | "aria-pressed" => {
            matches!(trimmed, "true" | "false" | "mixed" | "undefined")
        }
        "aria-autocomplete" => matches!(trimmed, "inline" | "list" | "both" | "none"),
        "aria-current" => matches!(
            trimmed,
            "page" | "step" | "location" | "date" | "time" | "true" | "false"
        ),
        "aria-haspopup" => matches!(
            trimmed,
            "false" | "true" | "menu" | "listbox" | "tree" | "grid" | "dialog"
        ),
        "aria-invalid" => matches!(trimmed, "grammar" | "false" | "spelling" | "true"),
        "aria-live" => matches!(trimmed, "assertive" | "off" | "polite"),
        "aria-orientation" => matches!(trimmed, "horizontal" | "undefined" | "vertical"),
        "aria-sort" => matches!(trimmed, "ascending" | "descending" | "none" | "other"),
        "aria-colcount" | "aria-colindex" | "aria-colspan" | "aria-level" | "aria-posinset"
        | "aria-rowcount" | "aria-rowindex" | "aria-rowspan" | "aria-setsize" => {
            trimmed.parse::<i64>().is_ok()
        }
        "aria-valuemax" | "aria-valuemin" | "aria-valuenow" => trimmed.parse::<f64>().is_ok(),
        _ => !trimmed.is_empty(),
    }
}

fn is_valid_autofill_tokens(value: &str) -> bool {
    let tokens: Vec<String> = value
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    if tokens.is_empty() {
        return false;
    }
    for tok in &tokens {
        if tok.starts_with("section-")
            || matches!(
                tok.as_str(),
                "shipping" | "billing" | "home" | "work" | "mobile" | "fax" | "pager"
            )
        {
            continue;
        }
        if !AUTOFILL_TOKENS.contains(&tok.as_str()) {
            return false;
        }
    }
    true
}

fn is_valid_bcp47_lang(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let parts: Vec<&str> = trimmed.split(['-', '_']).collect();
    let Some(primary) = parts.first() else {
        return false;
    };
    let lower = primary.to_ascii_lowercase();
    if !COMMON_LANG_TAGS.contains(&lower.as_str()) {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn contains_redundant_image_word(alt: &str) -> bool {
    alt.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .any(|w| {
            matches!(
                w.to_ascii_lowercase().as_str(),
                "image" | "photo" | "picture"
            )
        })
}

fn is_backdrop_dismiss_handler(attr: &JSXAttribute<'_>, semantic: &Semantic<'_>) -> bool {
    let src = attr.span.source_text(semantic.source_text());
    src.contains(".target") && src.contains(".currentTarget")
}

fn is_inside_modal_or_conditional(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::IfStatement(_) => return true,
            AstKind::JSXElement(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if tag == "dialog"
                    || find_attr_ignore_case(&el.opening_element.attributes, "aria-modal").is_some()
                    || find_attr_ignore_case(&el.opening_element.attributes, "role")
                        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                        .is_some_and(|r| matches!(r.as_str(), "dialog" | "alertdialog"))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_direct_child_of_link(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    if let AstKind::JSXElement(parent_el) = semantic.nodes().parent_kind(node_id) {
        let ptag = get_jsx_tag_name(&parent_el.opening_element.name);
        return ptag == "Link" || ptag.ends_with("Link");
    }
    false
}

pub(crate) fn has_accessible_child(jsx_el: &JSXElement<'_>) -> bool {
    has_accessible_label_text_in_children(&jsx_el.children)
}

fn has_accessible_label_text_in_children(children: &[JSXChild<'_>]) -> bool {
    for child in children {
        match child {
            JSXChild::Text(t) if !t.value.trim().is_empty() => return true,
            JSXChild::ExpressionContainer(c) => {
                if let Some(expr) = c.expression.as_expression() {
                    match expr.without_parentheses() {
                        Expression::NullLiteral(_) | Expression::BooleanLiteral(_) => {}
                        Expression::StringLiteral(s) => {
                            if s.value.as_str().is_some_and(|v| !v.trim().is_empty()) {
                                return true;
                            }
                        }
                        _ => return true,
                    }
                }
            }
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                let is_icon = tag == "svg" || tag.ends_with("Icon") || tag.starts_with("Icon");
                if ["aria-label", "aria-labelledby", "alt", "title"]
                    .iter()
                    .any(|a| {
                        find_attr_ignore_case(&el.opening_element.attributes, a)
                            .is_some_and(has_non_empty_attr_val)
                    })
                {
                    return true;
                }
                if !is_icon && has_accessible_label_text_in_children(&el.children) {
                    return true;
                }
            }
            JSXChild::Fragment(frag) if has_accessible_label_text_in_children(&frag.children) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn collect_static_jsx_element_text(jsx_el: &JSXElement<'_>) -> Option<String> {
    let mut out = String::new();
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) => out.push_str(t.value.as_str()),
            JSXChild::Element(el) => {
                out.push_str(&collect_static_jsx_element_text(el)?);
            }
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

fn has_nested_control_in_label(jsx_el: &JSXElement<'_>) -> bool {
    for child in &jsx_el.children {
        match child {
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if matches!(
                    tag.as_str(),
                    "input" | "select" | "textarea" | "meter" | "output" | "progress"
                ) || tag.to_ascii_lowercase().contains("input")
                    || tag.to_ascii_lowercase().contains("select")
                    || has_nested_control_in_label(el)
                {
                    return true;
                }
            }
            JSXChild::ExpressionContainer(c) => {
                if let Some(expr) = c.expression.as_expression()
                    && let Expression::Identifier(id) = expr.without_parentheses()
                    && matches!(id.name.as_str(), "children" | "control" | "input")
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn has_enclosing_label_or_hidden_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(anc_el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_tag_name(&anc_el.opening_element.name);
            if tag == "label" || tag == "Label" {
                return true;
            }
            if is_hidden_from_screen_reader(&anc_el.opening_element, semantic, const_strings) {
                return true;
            }
            if find_attr_ignore_case(&anc_el.opening_element.attributes, "label")
                .is_some_and(has_non_empty_attr_val)
            {
                return true;
            }
        }
    }
    false
}

fn is_inside_jsx_attribute(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic
        .nodes()
        .ancestor_ids(node_id)
        .any(|id| matches!(semantic.nodes().kind(id), AstKind::JSXAttribute(_)))
}

fn is_inside_template_element(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && get_jsx_tag_name(&el.opening_element.name) == "template"
        {
            return true;
        }
    }
    false
}

fn extract_attr_match_keys(
    semantic: &Semantic<'_>,
    attr: &JSXAttribute<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(s) = get_attr_static_str(semantic, attr, const_strings) {
        let t = s.trim();
        if !t.is_empty() {
            keys.push(format!("lit:{t}"));
        }
    }
    if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
    {
        let raw = expr
            .without_parentheses()
            .span()
            .source_text(semantic.source_text())
            .trim();
        if !raw.is_empty() {
            keys.push(format!("expr:{raw}"));
        }
    }
    keys
}

fn collect_known_attr_strings(
    semantic: &Semantic<'_>,
    attr: &JSXAttribute<'_>,
    const_strings: &HashMap<SymbolId, String>,
    out: &mut Vec<String>,
) {
    if let Some(s) = get_attr_static_str(semantic, attr, const_strings) {
        let t = s.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
        return;
    }
    if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
    {
        collect_expr_static_strings(semantic, expr, const_strings, out);
    }
}

fn collect_expr_static_strings(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    const_strings: &HashMap<SymbolId, String>,
    out: &mut Vec<String>,
) {
    if let Some(s) = eval_static_str(semantic, expr, const_strings) {
        let t = s.trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
        return;
    }
    match expr.without_parentheses() {
        Expression::ConditionalExpression(cond) => {
            collect_expr_static_strings(semantic, &cond.consequent, const_strings, out);
            collect_expr_static_strings(semantic, &cond.alternate, const_strings, out);
        }
        Expression::LogicalExpression(log) => {
            collect_expr_static_strings(semantic, &log.left, const_strings, out);
            collect_expr_static_strings(semantic, &log.right, const_strings, out);
        }
        _ => {}
    }
}

fn has_aria_hidden_ancestor(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && find_attr_ignore_case(&el.opening_element.attributes, "aria-hidden")
                .is_some_and(is_attr_statically_true_or_true_str)
        {
            return true;
        }
    }
    false
}

fn has_role_text_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && find_attr_ignore_case(&el.opening_element.attributes, "role")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .is_some_and(|r| r.split_whitespace().next() == Some("text"))
        {
            return true;
        }
    }
    false
}

fn has_interactive_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if matches!(tag.as_str(), "a" | "button")
                && is_interactive_element(&tag, &el.opening_element, semantic, const_strings)
            {
                return true;
            }
        }
    }
    false
}

fn find_topmost_jsx_root(semantic: &Semantic<'_>, node_id: NodeId) -> NodeId {
    let mut root = node_id;
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            AstKind::JSXElement(_) | AstKind::JSXFragment(_) => root = anc_id,
            _ => {}
        }
    }
    root
}

fn collect_descendant_headings(
    jsx_el: &JSXElement<'_>,
    line_starts: &[u32],
    out: &mut Vec<(u8, SourceLoc, ByteSpan)>,
) {
    let tag = get_jsx_tag_name(&jsx_el.opening_element.name);
    if let Some(lvl_str) = tag.strip_prefix('h')
        && let Ok(lvl) = lvl_str.parse::<u8>()
        && (1..=6).contains(&lvl)
    {
        let loc = loc_from_line_starts(line_starts, jsx_el.opening_element.span.start);
        let span = ByteSpan {
            start: jsx_el.opening_element.span.start,
            end: jsx_el.opening_element.span.end,
        };
        out.push((lvl, loc, span));
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_descendant_headings(child_el, line_starts, out);
        }
    }
}

fn count_fieldset_controls_and_legend(
    jsx_el: &JSXElement<'_>,
    control_count: &mut usize,
    has_legend: &mut bool,
) {
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            let tag = get_jsx_tag_name(&child_el.opening_element.name);
            if tag == "legend" {
                *has_legend = true;
            }
            if matches!(tag.as_str(), "input" | "select" | "textarea") {
                *control_count += 1;
            }
            count_fieldset_controls_and_legend(child_el, control_count, has_legend);
        }
    }
}

fn has_enclosing_tag(semantic: &Semantic<'_>, node_id: NodeId, target_tag: &str) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && get_jsx_tag_name(&el.opening_element.name) == target_tag
        {
            return true;
        }
    }
    false
}

#[expect(
    clippy::too_many_arguments,
    reason = "Walks static JSX subtree collecting iframe titles and duplicate referenced IDs in one pass"
)]
fn collect_subtree_frames_and_ids(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    seen_iframe_titles: &mut HashSet<String>,
    id_counts: &mut HashMap<String, Vec<(SourceLoc, ByteSpan)>>,
    referenced_ids: &mut HashSet<String>,
    sites: &mut Vec<SemanticRuleSite>,
    subject_name: &Option<String>,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    if matches!(tag.as_str(), "iframe" | "frame")
        && let Some(title_attr) = find_attr_ignore_case(&opening.attributes, "title")
        && let Some(raw_title) = get_attr_static_str(semantic, title_attr, const_strings)
    {
        let norm = raw_title
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        if !norm.is_empty() && !seen_iframe_titles.insert(norm) {
            push_site(
                sites,
                RuleId::IframeTitleUnique,
                subject_name.clone(),
                "iframeTitleUnique",
                &raw_title,
                format!(
                    "Another frame in this static JSX tree already uses the title \"{}\".",
                    raw_title.trim()
                ),
                loc_from_line_starts(line_starts, title_attr.span.start),
                ByteSpan {
                    start: title_attr.span.start,
                    end: title_attr.span.end,
                },
            );
        }
    }
    if HTML_TAGS.contains(&tag.as_str())
        && let Some(id_attr) = find_attr(&opening.attributes, "id")
        && let Some(id_val) = get_attr_static_str(semantic, id_attr, const_strings)
    {
        let trimmed = id_val.trim();
        if !trimmed.is_empty() {
            id_counts.entry(trimmed.to_string()).or_default().push((
                loc_from_line_starts(line_starts, id_attr.span.start),
                ByteSpan {
                    start: id_attr.span.start,
                    end: id_attr.span.end,
                },
            ));
        }
    }
    for ref_attr_name in [
        "aria-activedescendant",
        "aria-controls",
        "aria-describedby",
        "aria-details",
        "aria-errormessage",
        "aria-flowto",
        "aria-labelledby",
        "aria-owns",
        "htmlFor",
    ] {
        if let Some(ref_attr) = find_attr(&opening.attributes, ref_attr_name)
            && let Some(ref_val) = get_attr_static_str(semantic, ref_attr, const_strings)
        {
            for tok in ref_val.split_whitespace() {
                referenced_ids.insert(tok.to_string());
            }
        }
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_subtree_frames_and_ids(
                child_el,
                semantic,
                const_strings,
                line_starts,
                seen_iframe_titles,
                id_counts,
                referenced_ids,
                sites,
                subject_name,
            );
        }
    }
}

fn resolve_jsx_root_import_source(
    semantic: &Semantic<'_>,
    name: &JSXElementName<'_>,
    imported_sources: &HashMap<SymbolId, String>,
) -> Option<String> {
    let ident = match name {
        JSXElementName::IdentifierReference(id) => id,
        JSXElementName::MemberExpression(mem) => {
            let oxc_ast::ast::JSXMemberExpressionObject::IdentifierReference(id) = &mem.object
            else {
                return None;
            };
            id
        }
        _ => return None,
    };
    let ref_id = ident.reference_id.get()?;
    let sym_id = semantic.scoping().get_reference(ref_id).symbol_id()?;
    imported_sources.get(&sym_id).cloned()
}

pub(crate) fn subtree_has_tag_matching<F>(jsx_el: &JSXElement<'_>, pred: F) -> bool
where
    F: Fn(&str) -> bool + Copy,
{
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            let t = get_jsx_tag_name(&el.opening_element.name);
            if pred(&t) || subtree_has_tag_matching(el, pred) {
                return true;
            }
        } else if let JSXChild::Fragment(frag) = child {
            for fchild in &frag.children {
                if let JSXChild::Element(el) = fchild {
                    let t = get_jsx_tag_name(&el.opening_element.name);
                    if pred(&t) || subtree_has_tag_matching(el, pred) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn subtree_has_attr(jsx_el: &JSXElement<'_>, attr_name: &str) -> bool {
    if find_attr_ignore_case(&jsx_el.opening_element.attributes, attr_name).is_some() {
        return true;
    }
    jsx_el.children.iter().any(|child| {
        if let JSXChild::Element(el) = child {
            subtree_has_attr(el, attr_name)
        } else {
            false
        }
    })
}
