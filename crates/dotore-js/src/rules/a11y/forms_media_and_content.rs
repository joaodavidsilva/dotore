//! Labels, form controls, `alt` text, anchors, media, headings, tables, and UI component library `a11y` rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{Expression, JSXAttributeValue, JSXChild, JSXElement, JSXElementName},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use super::{
    JsxElementA11yCtx,
    aria_and_roles::check_custom_aria_and_role_rules,
    extract_attr_match_keys, has_accessible_child, has_accessible_label_text_in_children,
    has_non_empty_attr_val, is_attr_null_or_undefined, is_attr_statically_false,
    is_hidden_from_screen_reader, is_inside_jsx_attribute, is_interactive_element,
    keyboard_and_focus::check_custom_keyboard_and_focus_rules,
    push_site,
    tables::{
        AMBIGUOUS_LINK_WORDS, HTML_TAGS, INTERACTIVE_ROLES, contains_redundant_image_word,
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
        get_jsx_tag_name, get_style_prop_str, jsx_has_spread_attr, subtree_has_tag_matching,
    },
    rules::RuleId,
};

pub(super) fn check_element_content_media_and_form_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let JsxElementA11yCtx {
        is_testlike,
        semantic,
        jsx_el,
        opening,
        tag,
        is_html,
        has_spread,
        subject_name,
        const_strings,
        loc,
        span,
        line_starts,
        ..
    } = *ctx;
    // 7. `autocomplete-valid`
    if !is_testlike
        && matches!(tag, "input" | "textarea" | "select" | "form")
        && let Some(ac_attr) = find_jsx_attr_ignore_case(&opening.attributes, "autoComplete")
        && let Some(ac_val) = get_attr_static_str(semantic, ac_attr, const_strings)
    {
        let input_type = find_jsx_attr_ignore_case(&opening.attributes, "type")
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

    // 17. `html-has-lang`, `lang`, `html-xml-lang-mismatch`
    if tag == "html" {
        if let Some(lang_attr) = find_jsx_attr_ignore_case(&opening.attributes, "lang") {
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
                    find_jsx_attr_ignore_case(&opening.attributes, "xml:lang")
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
        && let Some(lang_attr) = find_jsx_attr_ignore_case(&opening.attributes, "lang")
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
    if matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !has_accessible_child(jsx_el)
        && !["aria-label", "aria-labelledby", "dangerouslySetInnerHTML"]
            .iter()
            .any(|a| find_jsx_attr_ignore_case(&opening.attributes, a).is_some())
        && !has_spread
    {
        push_site(
            sites,
            RuleId::HeadingHasContent,
            subject_name.clone(),
            "headingHasContent",
            tag,
            "Blind users can't use this heading to navigate because screen readers skip it empty, so add text, `aria-label`, or `aria-labelledby`.".to_string(),
            loc,
            span,
        );
    }

    // 19. `iframe-has-title`
    if tag == "iframe" && !is_hidden_from_screen_reader(opening, semantic, const_strings) {
        let title_ok =
            find_jsx_attr_ignore_case(&opening.attributes, "title").is_some_and(|attr| {
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

    // 21. `no-distracting-elements`
    if matches!(tag, "marquee" | "blink") {
        push_site(
            sites,
            RuleId::NoDistractingElements,
            subject_name.clone(),
            "noDistractingElements",
            tag,
            format!(
                "Users with attention or motion sensitivity struggle because `<{tag}>` animates on its own, so use normal, accessible markup instead."
            ),
            loc,
            span,
        );
    }

    // 23. `no-disabled-zoom`
    if tag == "meta"
        && find_jsx_attr_ignore_case(&opening.attributes, "name")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|n| n.eq_ignore_ascii_case("viewport"))
        && let Some(content_attr) = find_jsx_attr_ignore_case(&opening.attributes, "content")
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
        && let Some(alt_attr) = find_jsx_attr_ignore_case(&opening.attributes, "alt")
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
    if matches!(tag, "audio" | "video")
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
    {
        let is_muted = find_jsx_attr_ignore_case(&opening.attributes, "muted")
            .is_some_and(|a| !is_attr_statically_false(a));
        let is_ref_only_without_src = find_jsx_attr_ignore_case(&opening.attributes, "ref")
            .is_some()
            && find_jsx_attr_ignore_case(&opening.attributes, "src").is_none()
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
                tag,
                "Deaf and hard-of-hearing users need captions for this media. Add a `<track kind=\"captions\">` inside the `<audio>` or `<video>`.".to_string(),
                loc,
                span,
            );
        }
    }

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
    reason = "Evaluates anchor-is-valid, anchor-has-content, and anchor-ambiguous-text in one pass"
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
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let has_spread = jsx_has_spread_attr(&opening.attributes);
    let href_attr = find_jsx_attr_ignore_case(&opening.attributes, "href");
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
        let is_widget_anchor = find_jsx_attr_ignore_case(&opening.attributes, "role").is_some()
            && find_jsx_attr_ignore_case(&opening.attributes, "tabIndex").is_some()
            && (find_jsx_attr_ignore_case(&opening.attributes, "onKeyDown").is_some()
                || find_jsx_attr_ignore_case(&opening.attributes, "onKeyUp").is_some());
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
            || find_jsx_attr_ignore_case(&opening.attributes, "role")
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
        .any(|a| find_jsx_attr_ignore_case(&opening.attributes, a).is_some())
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
        let text_opt = find_jsx_attr_ignore_case(&opening.attributes, "aria-label")
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

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates control-has-associated-label and label-has-associated-control on a JSXElement"
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
    let opening = &jsx_el.opening_element;

    // 1. `label-has-associated-control`
    if tag == "label" {
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

    // 2. `control-has-associated-label`
    if has_spread
        || is_inside_jsx_attribute(semantic, node_id)
        || is_hidden_from_screen_reader(opening, semantic, const_strings)
    {
        return;
    }
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    if tag == "input"
        && find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("file"))
        && class_str.split_whitespace().any(|t| t == "hidden")
        && find_jsx_attr_ignore_case(&opening.attributes, "ref").is_some()
    {
        return;
    }

    let role_str = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
        && find_jsx_attr_ignore_case(&opening.attributes, "onClick").is_some()
    {
        return;
    }
    if tag == "input" {
        let input_type = find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(input_type.as_str(), "submit" | "reset" | "hidden") {
            return;
        }
        if input_type == "button"
            && find_jsx_attr_ignore_case(&opening.attributes, "value")
                .is_some_and(has_non_empty_attr_val)
        {
            return;
        }
        let has_id_or_file =
            find_jsx_attr_ignore_case(&opening.attributes, "id").is_some() || input_type == "file";
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
    .any(|k| find_jsx_attr_ignore_case(&opening.attributes, k).is_some_and(has_non_empty_attr_val));
    if has_label_prop {
        return;
    }
    if tag != "select" && has_accessible_label_text_in_children(&jsx_el.children) {
        return;
    }
    if has_enclosing_label_or_hidden_ancestor(semantic, node_id, const_strings) {
        return;
    }
    if let Some(id_attr) = find_jsx_attr_ignore_case(&opening.attributes, "id") {
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

pub(super) fn check_custom_a11y_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    imported_sources: &HashMap<SymbolId, String>,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let JsxElementA11yCtx {
        semantic,
        node_id,
        jsx_el,
        opening,
        tag,
        is_html,
        has_spread,
        subject_name,
        const_strings,
        loc,
        span,
        line_starts,
        ..
    } = *ctx;
    let role_str = find_jsx_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings));
    let first_role = role_str
        .as_deref()
        .and_then(|r| r.split_whitespace().next());
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let has_a11y_name = ["aria-label", "aria-labelledby", "title"].iter().any(|a| {
        find_jsx_attr_ignore_case(&opening.attributes, a).is_some_and(has_non_empty_attr_val)
    });

    // 1, 6, 10–12, 15, 17. ARIA, dialog, status, landmark, and presentation role rules
    check_custom_aria_and_role_rules(
        ctx,
        first_role,
        has_a11y_name,
        main_landmarks_by_root,
        unlabeled_navs_by_root,
        sites,
    );

    // 7, 13–14. Keyboard activation, focusable content in aria-hidden / role="text", nested interactive
    check_custom_keyboard_and_focus_rules(
        semantic,
        node_id,
        opening,
        tag,
        is_html,
        first_role,
        subject_name,
        const_strings,
        loc,
        span,
        sites,
    );

    // 2. `no-autoplay-without-muted`
    if matches!(tag, "video" | "audio")
        && !has_spread
        && find_jsx_attr_ignore_case(&opening.attributes, "autoPlay")
            .is_some_and(|a| !is_attr_statically_false(a))
    {
        let muted_ok = find_jsx_attr_ignore_case(&opening.attributes, "muted")
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
        && let Some(paste_attr) = find_jsx_attr_ignore_case(&opening.attributes, "onPaste")
    {
        let is_auth_input = find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("password"))
            || find_jsx_attr_ignore_case(&opening.attributes, "autoComplete")
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
    if tag == "img"
        && !has_spread
        && find_jsx_attr_ignore_case(&opening.attributes, "ref").is_none()
    {
        let src_attr = find_jsx_attr_ignore_case(&opening.attributes, "src");
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
        && find_jsx_attr_ignore_case(&opening.attributes, "placeholder")
            .is_some_and(has_non_empty_attr_val)
        && !has_a11y_name
        && !has_enclosing_label_or_hidden_ancestor(semantic, node_id, const_strings)
        && find_jsx_attr_ignore_case(&opening.attributes, "id").is_none()
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

    // 18. `no-server-side-image-map`
    if tag == "img"
        && let Some(ismap_attr) = find_jsx_attr_ignore_case(&opening.attributes, "isMap")
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
        && find_jsx_attr_ignore_case(&opening.attributes, "name").is_none()
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
        && find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("radio"))
        && !find_jsx_attr_ignore_case(&opening.attributes, "name")
            .is_some_and(has_non_empty_attr_val)
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
        && find_jsx_attr_ignore_case(&opening.attributes, "size")
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
        && let Some(title_attr) = find_jsx_attr_ignore_case(&opening.attributes, "title")
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
            if find_jsx_attr_ignore_case(&anc_el.opening_element.attributes, "label")
                .is_some_and(has_non_empty_attr_val)
            {
                return true;
            }
        }
    }
    false
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

fn subtree_has_attr(jsx_el: &JSXElement<'_>, attr_name: &str) -> bool {
    if find_jsx_attr_ignore_case(&jsx_el.opening_element.attributes, attr_name).is_some() {
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
