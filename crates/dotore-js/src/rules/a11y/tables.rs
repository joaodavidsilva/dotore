//! Static HTML/ARIA/BCP-47/autofill lookup tables and role-mapping helpers for `a11y` rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; role/ARIA helpers match only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::ast::{Expression, JSXAttributeValue, JSXOpeningElement};
use oxc_semantic::{Semantic, SymbolId};

use crate::matchers::{find_attr_ignore_case, get_attr_static_str};

pub(super) const RESERVED_HTML_TAGS: &[&str] = &[
    "base", "col", "colgroup", "head", "html", "link", "meta", "noembed", "noscript", "param",
    "picture", "script", "source", "style", "title", "track",
];

pub(super) const HTML_TAGS: &[&str] = &[
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

pub(super) const NON_INTERACTIVE_ELEMENTS: &[&str] = &[
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

pub(super) const VALID_ARIA_ROLES: &[&str] = &[
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

pub(super) const INTERACTIVE_ROLES: &[&str] = &[
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

pub(super) const NON_INTERACTIVE_ROLES: &[&str] = &[
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

pub(super) const VALID_ARIA_PROPERTIES: &[&str] = &[
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

pub(super) const GLOBAL_ARIA_PROPERTIES: &[&str] = &[
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

pub(super) const AUTOFILL_TOKENS: &[&str] = &[
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

pub(super) const AMBIGUOUS_LINK_WORDS: &[&str] =
    &["click here", "here", "link", "a link", "learn more"];

pub(super) const UNINFORMATIVE_ARIA_LABELS: &[&str] = &[
    "icon", "button", "image", "img", "graphic", "svg", "picture", "element", "field", "input",
];

pub(super) const COMMON_LANG_TAGS: &[&str] = &[
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

pub(super) fn get_implicit_role(
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

pub(super) fn preferred_html_tag_for_role(role: &str) -> Option<&'static str> {
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

pub(super) fn is_allowed_interactive_role_on_noninteractive(tag: &str, role: &str) -> bool {
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

pub(super) fn supplies_native_aria_prop(
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

pub(super) fn is_aria_prop_supported_by_role(role: &str, prop: &str) -> bool {
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

pub(super) fn is_valid_aria_prop_value(
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

pub(super) fn is_valid_autofill_tokens(value: &str) -> bool {
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

pub(super) fn is_valid_bcp47_lang(value: &str) -> bool {
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

pub(super) fn contains_redundant_image_word(alt: &str) -> bool {
    alt.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .any(|w| {
            matches!(
                w.to_ascii_lowercase().as_str(),
                "image" | "photo" | "picture"
            )
        })
}
