//! Labels, form controls, `alt` text, anchors, media, headings, tables, and UI component library `a11y` rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{Expression, JSXAttributeValue, JSXChild, JSXElement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

pub(super) use super::custom_and_ui_a11y::check_custom_a11y_rules;

use super::{
    JsxElementA11yCtx, extract_attr_match_keys, has_accessible_child,
    has_accessible_label_text_in_children, has_non_empty_attr_val, is_attr_null_or_undefined,
    is_attr_statically_false, is_hidden_from_screen_reader, is_inside_jsx_attribute,
    is_interactive_element, push_site,
    tables::{
        AMBIGUOUS_LINK_WORDS, INTERACTIVE_ROLES, contains_redundant_image_word,
        is_valid_autofill_tokens, is_valid_bcp47_lang,
    },
};
use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, jsx_has_spread_attr,
    },
    rules::RuleId,
};
pub(super) fn check_element_content_media_and_form_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.opening.attributes.is_empty() || ctx.tag == "html" {
        check_autocomplete_and_lang_rules(ctx, sites);
    }
    check_heading_iframe_and_distracting_rules(ctx, sites);
    check_viewport_media_and_scope_rules(ctx, sites);
}

fn check_autocomplete_and_lang_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.is_testlike
        && matches!(ctx.tag, "input" | "textarea" | "select" | "form")
        && let Some(ac_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "autoComplete")
        && let Some(ac_val) = get_attr_static_str(ctx.semantic, ac_attr, ctx.const_strings)
    {
        let input_type = find_jsx_attr_ignore_case(&ctx.opening.attributes, "type")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if input_type != "hidden" && !is_valid_autofill_tokens(&ac_val) {
            push_site(
                sites,
                RuleId::AutocompleteValid,
                ctx.subject_name.clone(),
                "autocompleteValid",
                &ac_val,
                format!(
                    "Users who rely on autofill can't fill this field because `{ac_val}` isn't a known token, so use a valid `autoComplete` token."
                ),
                loc_from_line_starts(ctx.line_starts, ac_attr.span.start),
                ByteSpan {
                    start: ac_attr.span.start,
                    end: ac_attr.span.end,
                },
            );
        }
    }

    if ctx.tag == "html" {
        check_html_tag_lang_rules(ctx, sites);
    } else if ctx.is_html
        && let Some(lang_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "lang")
        && let Some(lang_val) = get_attr_static_str(ctx.semantic, lang_attr, ctx.const_strings)
        && !is_valid_bcp47_lang(&lang_val)
    {
        push_site(
            sites,
            RuleId::Lang,
            ctx.subject_name.clone(),
            "lang",
            &lang_val,
            "Screen readers can't pick the right voice because this `lang` isn't a real language code, so use a valid one like `en` or `en-US`.".to_string(),
            loc_from_line_starts(ctx.line_starts, lang_attr.span.start),
            ByteSpan {
                start: lang_attr.span.start,
                end: lang_attr.span.end,
            },
        );
    }
}

fn check_html_tag_lang_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let missing_lang_msg = "Screen readers may mispronounce this page because it doesn't declare a language, so add a `lang` attribute like `en`.";
    let Some(lang_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "lang") else {
        push_site(
            sites,
            RuleId::HtmlHasLang,
            ctx.subject_name.clone(),
            "htmlHasLang",
            "html",
            missing_lang_msg.to_string(),
            ctx.loc,
            ctx.span,
        );
        return;
    };
    let Some(lang_val) = get_attr_static_str(ctx.semantic, lang_attr, ctx.const_strings) else {
        if is_attr_null_or_undefined(lang_attr) {
            push_site(
                sites,
                RuleId::HtmlHasLang,
                ctx.subject_name.clone(),
                "htmlHasLang",
                "html",
                missing_lang_msg.to_string(),
                ctx.loc,
                ctx.span,
            );
        }
        return;
    };
    if lang_val.trim().is_empty() {
        push_site(
            sites,
            RuleId::HtmlHasLang,
            ctx.subject_name.clone(),
            "htmlHasLang",
            "html",
            missing_lang_msg.to_string(),
            ctx.loc,
            ctx.span,
        );
    } else if !is_valid_bcp47_lang(&lang_val) {
        push_site(
            sites,
            RuleId::Lang,
            ctx.subject_name.clone(),
            "lang",
            &lang_val,
            "Screen readers can't pick the right voice because this `lang` isn't a real language code, so use a valid one like `en` or `en-US`.".to_string(),
            loc_from_line_starts(ctx.line_starts, lang_attr.span.start),
            ByteSpan {
                start: lang_attr.span.start,
                end: lang_attr.span.end,
            },
        );
    } else if let Some(xml_lang_attr) =
        find_jsx_attr_ignore_case(&ctx.opening.attributes, "xml:lang")
        && let Some(xml_val) = get_attr_static_str(ctx.semantic, xml_lang_attr, ctx.const_strings)
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
                ctx.subject_name.clone(),
                "htmlXmlLangMismatch",
                "xml:lang",
                format!(
                    "lang declares {base_lang}, but xml:lang declares {base_xml}. Use the same base language so assistive technology chooses one pronunciation model."
                ),
                loc_from_line_starts(ctx.line_starts, xml_lang_attr.span.start),
                ByteSpan {
                    start: xml_lang_attr.span.start,
                    end: xml_lang_attr.span.end,
                },
            );
        }
    }
}

fn check_heading_iframe_and_distracting_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
        && !is_hidden_from_screen_reader(ctx.opening, ctx.semantic, ctx.const_strings)
        && !has_accessible_child(ctx.jsx_el)
        && !["aria-label", "aria-labelledby", "dangerouslySetInnerHTML"]
            .iter()
            .any(|a| find_jsx_attr_ignore_case(&ctx.opening.attributes, a).is_some())
        && !ctx.has_spread
    {
        push_site(
            sites,
            RuleId::HeadingHasContent,
            ctx.subject_name.clone(),
            "headingHasContent",
            ctx.tag,
            "Blind users can't use this heading to navigate because screen readers skip it empty, so add text, `aria-label`, or `aria-labelledby`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "iframe"
        && !is_hidden_from_screen_reader(ctx.opening, ctx.semantic, ctx.const_strings)
    {
        let title_ok =
            find_jsx_attr_ignore_case(&ctx.opening.attributes, "title").is_some_and(|attr| {
                if let Some(s) = get_attr_static_str(ctx.semantic, attr, ctx.const_strings) {
                    !s.trim().is_empty()
                } else {
                    !is_attr_null_or_undefined(attr) && !is_attr_statically_false(attr)
                }
            });
        if !title_ok {
            push_site(
                sites,
                RuleId::IframeHasTitle,
                ctx.subject_name.clone(),
                "iframeHasTitle",
                "iframe",
                "Screen reader users cannot identify this `<iframe>` because it has no title. Add a `title` that describes its content.".to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }

    if matches!(ctx.tag, "marquee" | "blink") {
        push_site(
            sites,
            RuleId::NoDistractingElements,
            ctx.subject_name.clone(),
            "noDistractingElements",
            ctx.tag,
            format!(
                "Users with attention or motion sensitivity struggle because `<{}>` animates on its own, so use normal, accessible markup instead.",
                ctx.tag
            ),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_viewport_media_and_scope_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "meta"
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "name")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .is_some_and(|n| n.eq_ignore_ascii_case("viewport"))
        && let Some(content_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "content")
        && let Some(content_val) =
            get_attr_static_str(ctx.semantic, content_attr, ctx.const_strings)
        && is_disabled_zoom_viewport(&content_val)
    {
        push_site(
            sites,
            RuleId::NoDisabledZoom,
            ctx.subject_name.clone(),
            "noDisabledZoom",
            "viewport",
            "Your users can't pinch to zoom because viewport settings block it, which fails accessibility (WCAG 1.4.4). Remove user-scalable=no and restrictive maximum-scale.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "img"
        && !is_hidden_from_screen_reader(ctx.opening, ctx.semantic, ctx.const_strings)
        && let Some(alt_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "alt")
        && let Some(alt_val) = get_attr_static_str(ctx.semantic, alt_attr, ctx.const_strings)
        && contains_redundant_image_word(&alt_val)
    {
        push_site(
            sites,
            RuleId::ImgRedundantAlt,
            ctx.subject_name.clone(),
            "imgRedundantAlt",
            &alt_val,
            "Screen reader users hear \"image\" or \"photo\" twice because they already announce it, so describe what the image shows instead.".to_string(),
            loc_from_line_starts(ctx.line_starts, alt_attr.span.start),
            ByteSpan {
                start: alt_attr.span.start,
                end: alt_attr.span.end,
            },
        );
    }

    if matches!(ctx.tag, "audio" | "video")
        && !is_hidden_from_screen_reader(ctx.opening, ctx.semantic, ctx.const_strings)
        && is_missing_media_caption(ctx)
    {
        push_site(
            sites,
            RuleId::MediaHasCaption,
            ctx.subject_name.clone(),
            "mediaHasCaption",
            ctx.tag,
            "Deaf and hard-of-hearing users need captions for this media. Add a `<track kind=\"captions\">` inside the `<audio>` or `<video>`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.is_html
        && ctx.tag != "th"
        && let Some(scope_attr) = find_attr(&ctx.opening.attributes, "scope")
    {
        push_site(
            sites,
            RuleId::Scope,
            ctx.subject_name.clone(),
            "scope",
            "scope",
            "The `scope` attribute only works on `<th>` cells, so screen readers get no table-header help from it here.".to_string(),
            loc_from_line_starts(ctx.line_starts, scope_attr.span.start),
            ByteSpan {
                start: scope_attr.span.start,
                end: scope_attr.span.end,
            },
        );
    }
}

fn is_disabled_zoom_viewport(content_val: &str) -> bool {
    let lower = content_val.to_ascii_lowercase();
    lower.split([',', ';']).any(|part| {
        let clean = part.replace(' ', "");
        clean == "user-scalable=no"
            || clean
                .strip_prefix("maximum-scale=")
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|scale| scale < 2.0)
    })
}

fn is_missing_media_caption(ctx: &JsxElementA11yCtx<'_, '_>) -> bool {
    let attrs = &ctx.opening.attributes;
    if find_jsx_attr_ignore_case(attrs, "muted").is_some_and(|a| !is_attr_statically_false(a)) {
        return false;
    }
    if find_jsx_attr_ignore_case(attrs, "ref").is_some()
        && find_jsx_attr_ignore_case(attrs, "src").is_none()
        && ctx.jsx_el.children.is_empty()
    {
        return false;
    }
    !ctx.jsx_el.children.iter().any(|child| match child {
        JSXChild::Element(el) => {
            get_jsx_tag_name(&el.opening_element.name).eq_ignore_ascii_case("track")
        }
        JSXChild::ExpressionContainer(_) => true,
        _ => false,
    })
}

pub(super) fn check_alt_text(
    jsx_el: &JSXElement<'_>,
    tag: &str,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    if jsx_has_spread_attr(&opening.attributes) {
        return;
    }

    match tag {
        "img" => {
            let has_valid_alt = find_jsx_attr_ignore_case(&opening.attributes, "alt")
                .is_some_and(|a| a.value.is_some() && !is_attr_null_or_undefined(a));
            let has_aria_label = ["aria-label", "aria-labelledby"].iter().any(|k| {
                find_jsx_attr_ignore_case(&opening.attributes, k)
                    .is_some_and(has_non_empty_attr_val)
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
                find_jsx_attr_ignore_case(&opening.attributes, k)
                    .is_some_and(has_non_empty_attr_val)
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
                    find_jsx_attr_ignore_case(&opening.attributes, k)
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
                find_jsx_attr_ignore_case(&opening.attributes, "type").is_some_and(|a| {
                    matches!(
                        &a.value,
                        Some(JSXAttributeValue::StringLiteral(s))
                            if s.value.as_str().is_some_and(|v| v.eq_ignore_ascii_case("image"))
                    )
                });
            if is_image_type {
                let has_name = ["alt", "aria-label", "aria-labelledby"].iter().any(|k| {
                    find_jsx_attr_ignore_case(&opening.attributes, k)
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
    reason = "Evaluates anchor-is-valid, anchor-has-content, and anchor-ambiguous-text in one pass (#50)"
)]
pub(super) fn check_anchor_rules(
    is_testlike: bool,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    _line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let has_spread = jsx_has_spread_attr(&opening.attributes);
    let href_attr = find_jsx_attr_ignore_case(&opening.attributes, "href");
    let href_str = href_attr.and_then(|a| get_attr_static_str(semantic, a, const_strings));

    if !has_spread
        && !is_direct_child_of_link(semantic, node_id)
        && is_invalid_anchor_destination(opening, href_attr, href_str.as_deref())
    {
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

    if is_testlike || is_hidden_from_screen_reader(opening, semantic, const_strings) {
        return;
    }

    if !has_spread && is_anchor_missing_content(semantic, jsx_el, href_attr, const_strings) {
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

    check_anchor_ambiguous_text(semantic, jsx_el, subject_name, const_strings, loc, span, sites);
}

fn is_invalid_anchor_destination(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    href_attr: Option<&oxc_ast::ast::JSXAttribute<'_>>,
    href_str: Option<&str>,
) -> bool {
    let is_invalid_href = match (href_attr, href_str) {
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
    if !is_invalid_href {
        return false;
    }
    let is_widget_anchor = find_jsx_attr_ignore_case(&opening.attributes, "role").is_some()
        && find_jsx_attr_ignore_case(&opening.attributes, "tabIndex").is_some()
        && (find_jsx_attr_ignore_case(&opening.attributes, "onKeyDown").is_some()
            || find_jsx_attr_ignore_case(&opening.attributes, "onKeyUp").is_some());
    !is_widget_anchor
}

fn is_anchor_missing_content(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    href_attr: Option<&oxc_ast::ast::JSXAttribute<'_>>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let opening = &jsx_el.opening_element;
    let has_link_semantics = href_attr.is_some()
        || find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|r| r.split_whitespace().next() == Some("link"));
    has_link_semantics
        && !has_accessible_child(jsx_el)
        && ![
            "title",
            "aria-label",
            "aria-labelledby",
            "dangerouslySetInnerHTML",
        ]
        .iter()
        .any(|a| find_jsx_attr_ignore_case(&opening.attributes, a).is_some())
}

fn check_anchor_ambiguous_text(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let Some(raw_text) = find_jsx_attr_ignore_case(&opening.attributes, "aria-label")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .or_else(|| collect_static_jsx_element_text(jsx_el))
    else {
        return;
    };
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

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates control-has-associated-label and label-has-associated-control on a JSXElement (#50)"
)]
pub(super) fn check_control_and_label_association(
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
    if tag == "label" {
        check_label_has_associated_control(jsx_el, has_spread, subject_name, loc, span, sites);
    }

    if !should_check_control_label(
        semantic,
        node_id,
        jsx_el,
        tag,
        is_html,
        has_spread,
        const_strings,
    ) {
        return;
    }

    if has_associated_control_label(
        semantic,
        node_id,
        jsx_el,
        tag,
        const_strings,
        label_html_for_ids,
    ) {
        return;
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

fn check_label_has_associated_control(
    jsx_el: &JSXElement<'_>,
    has_spread: bool,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let has_html_for = find_jsx_attr_ignore_case(&opening.attributes, "htmlFor")
        .is_some_and(has_non_empty_attr_val);
    let has_nested = has_nested_control_in_label(jsx_el);
    let has_text = has_accessible_child(jsx_el)
        || ["aria-label", "aria-labelledby", "alt"]
            .iter()
            .any(|a| find_jsx_attr_ignore_case(&opening.attributes, a).is_some());
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

fn should_check_control_label(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    is_html: bool,
    has_spread: bool,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let opening = &jsx_el.opening_element;
    if has_spread
        || is_inside_jsx_attribute(semantic, node_id)
        || is_hidden_from_screen_reader(opening, semantic, const_strings)
    {
        return false;
    }
    let is_operable_tag = matches!(
        tag,
        "button" | "input" | "select" | "textarea" | "a" | "summary"
    ) && is_interactive_element(tag, opening, semantic, const_strings);
    let is_interactive_role = is_html
        && find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .as_deref()
            .and_then(|r| r.split_whitespace().next())
            .is_some_and(|r| INTERACTIVE_ROLES.contains(&r) && r != "separator");

    if !is_operable_tag && !is_interactive_role {
        return false;
    }
    if tag == "button"
        && jsx_el.closing_element.is_none()
        && opening.attributes.len() == 1
        && find_jsx_attr_ignore_case(&opening.attributes, "onClick").is_some()
    {
        return false;
    }
    if tag == "input" {
        return should_check_input_control_label(semantic, opening, const_strings);
    }
    true
}

fn should_check_input_control_label(
    semantic: &Semantic<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let input_type = find_jsx_attr_ignore_case(&opening.attributes, "type")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(input_type.as_str(), "submit" | "reset" | "hidden") {
        return false;
    }
    if input_type == "file" {
        let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
        if class_str.split_whitespace().any(|t| t == "hidden")
            && find_jsx_attr_ignore_case(&opening.attributes, "ref").is_some()
        {
            return false;
        }
        return true;
    }
    if input_type == "button"
        && find_jsx_attr_ignore_case(&opening.attributes, "value")
            .is_some_and(has_non_empty_attr_val)
    {
        return false;
    }
    find_jsx_attr_ignore_case(&opening.attributes, "id").is_some()
}

fn has_associated_control_label(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    const_strings: &HashMap<SymbolId, String>,
    label_html_for_ids: &HashSet<String>,
) -> bool {
    let opening = &jsx_el.opening_element;
    if [
        "aria-label",
        "aria-labelledby",
        "alt",
        "title",
        "placeholder",
    ]
    .iter()
    .any(|k| find_jsx_attr_ignore_case(&opening.attributes, k).is_some_and(has_non_empty_attr_val))
    {
        return true;
    }
    if tag != "select" && has_accessible_label_text_in_children(&jsx_el.children) {
        return true;
    }
    if has_enclosing_label_or_hidden_ancestor(semantic, node_id, const_strings) {
        return true;
    }
    find_jsx_attr_ignore_case(&opening.attributes, "id").is_some_and(|id_attr| {
        extract_attr_match_keys(semantic, id_attr, const_strings)
            .iter()
            .any(|k| label_html_for_ids.contains(k))
    })
}


fn is_direct_child_of_link(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    if let AstKind::JSXElement(parent_el) = semantic.nodes().parent_kind(node_id) {
        let ptag = get_jsx_tag_name(&parent_el.opening_element.name);
        return ptag == "Link" || ptag.ends_with("Link");
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

pub(super) fn has_enclosing_label_or_hidden_ancestor(
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
            if find_jsx_attr_ignore_case(&anc_el.opening_element.attributes, "label")
                .is_some_and(has_non_empty_attr_val)
            {
                return true;
            }
        }
    }
    false
}

