//! Single-pass Angular HTML template analyzer covering:
//! - `angular-for-track-no-index`
//! - `angular-template-no-any`
//! - `angular-template-alt-text`
//! - `angular-template-click-events-have-key-events`
//! - `angular-template-mouse-events-have-key-events`
//! - `angular-template-elements-have-content`
//! - `angular-template-interactive-supports-focus`
//! - `angular-template-table-scope`
//! - `angular-template-valid-aria`
//! - `angular-material-no-conflicting-mixins` (mutually exclusive Material button directives on one element)

use std::collections::HashSet;

use crate::{
    ir::{ByteSpan, SemanticRuleSite, loc_from_line_starts},
    rules::{AutofixPatch, RuleId, a11y::VALID_ARIA_PROPERTIES},
};

const VOID_HTML_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

const NATIVE_INTERACTIVE_ELEMENTS: &[&str] = &[
    "a", "audio", "button", "details", "embed", "iframe", "input", "label", "object", "option",
    "select", "summary", "textarea", "video",
];

const INTERACTIVE_ARIA_ROLES: &[&str] = &[
    "button",
    "checkbox",
    "columnheader",
    "combobox",
    "gridcell",
    "link",
    "listbox",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "progressbar",
    "radio",
    "rowheader",
    "scrollbar",
    "searchbox",
    "slider",
    "spinbutton",
    "switch",
    "tab",
    "textbox",
    "treeitem",
];

const VALID_TABLE_SCOPES: &[&str] = &["col", "row", "colgroup", "rowgroup"];

const MATERIAL_BUTTON_DIRECTIVES: &[&str] = &[
    "mat-button",
    "mat-raised-button",
    "mat-flat-button",
    "mat-stroked-button",
    "mat-icon-button",
    "mat-fab",
    "mat-mini-fab",
];

#[derive(Debug, Clone)]
struct ParsedTemplateAttr<'a> {
    raw_name: &'a str,
    value: Option<&'a str>,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone)]
struct ParsedTemplateElement<'a> {
    tag_lower: String,
    attrs: Vec<ParsedTemplateAttr<'a>>,
    open_start: usize,
    open_end: usize,
    is_self_closing: bool,
}

/// Scans an Angular template string (either an external `.html` file or an inline `template: \`...\``)
/// for `@for (...; track ...)`, `$any(...)`, template accessibility rules, and Material button conflicts.
pub(crate) fn extract_angular_html_template_sites(
    template_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    scan_for_track_violations(
        template_source,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    scan_template_no_any(
        template_source,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    scan_template_elements(
        template_source,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
}

fn scan_for_track_violations(
    template_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let bytes = template_source.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let Some(rel_pos) = template_source[i..].find("@for") else {
            break;
        };
        let at_pos = i + rel_pos;
        let after_for = at_pos + 4;
        if after_for < bytes.len()
            && (bytes[after_for].is_ascii_alphanumeric() || bytes[after_for] == b'_')
        {
            i = after_for;
            continue;
        }
        let mut cursor = after_for;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            i = after_for;
            continue;
        }
        let open_paren = cursor;
        let Some(close_paren) = find_matching_paren(template_source, open_paren) else {
            i = open_paren + 1;
            continue;
        };
        let header = template_source
            .get(open_paren + 1..close_paren)
            .unwrap_or_default();
        if let Some((track_target, reason)) = classify_for_header_track_violation(header) {
            push_template_site(
                sites,
                RuleId::AngularForTrackNoIndex,
                subject_name,
                "angularForTrackNoIndex",
                track_target,
                reason,
                base_byte_offset,
                at_pos,
                close_paren + 1,
                line_starts,
                None,
            );
        }
        i = close_paren + 1;
    }
}

fn scan_template_no_any(
    template_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let bytes = template_source.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if template_source.get(i..).is_some_and(|s| s.starts_with("<!--")) {
            if let Some(end_comment) = template_source.get(i + 4..).and_then(|s| s.find("-->")) {
                i += 4 + end_comment + 3;
                continue;
            }
            break;
        }
        let Some(rel_pos) = template_source[i..].find("$any") else {
            break;
        };
        let pos = i + rel_pos;
        if pos > 0 {
            let prev = bytes[pos - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$' {
                i = pos + 4;
                continue;
            }
        }
        let mut cursor = pos + 4;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            i = pos + 4;
            continue;
        }
        let end_idx = find_matching_paren(template_source, cursor).map_or(cursor + 1, |c| c + 1);
        push_template_site(
            sites,
            RuleId::AngularTemplateNoAny,
            subject_name,
            "angularTemplateNoAny",
            "$any".to_string(),
            "Avoid `$any(...)` in Angular templates; it bypasses template type checking."
                .to_string(),
            base_byte_offset,
            pos,
            end_idx,
            line_starts,
            None,
        );
        i = end_idx;
    }
}

fn scan_template_elements(
    template_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let bytes = template_source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if template_source.get(i..).is_some_and(|s| s.starts_with("<!--")) {
            if let Some(end_c) = template_source.get(i + 4..).and_then(|s| s.find("-->")) {
                i += 4 + end_c + 3;
                continue;
            }
            break;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        let next_b = bytes[i + 1];
        if next_b == b'/' || next_b == b'!' || next_b == b'?' || !next_b.is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let Some(el) = parse_opening_element(template_source, i) else {
            i += 1;
            continue;
        };
        evaluate_template_element(
            template_source,
            &el,
            base_byte_offset,
            subject_name,
            line_starts,
            sites,
        );
        i = el.open_end;
    }
}

fn parse_opening_element(src: &str, open_lt: usize) -> Option<ParsedTemplateElement<'_>> {
    let bytes = src.as_bytes();
    let mut cursor = open_lt + 1;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric()
            || bytes[cursor] == b'-'
            || bytes[cursor] == b':'
            || bytes[cursor] == b'_')
    {
        cursor += 1;
    }
    if cursor == open_lt + 1 {
        return None;
    }
    let tag_lower = src.get(open_lt + 1..cursor)?.to_ascii_lowercase();
    let mut attrs = Vec::new();

    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            return None;
        }
        if bytes[cursor] == b'>' {
            return Some(ParsedTemplateElement {
                tag_lower,
                attrs,
                open_start: open_lt,
                open_end: cursor + 1,
                is_self_closing: false,
            });
        }
        if bytes[cursor] == b'/' && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'>' {
            return Some(ParsedTemplateElement {
                tag_lower,
                attrs,
                open_start: open_lt,
                open_end: cursor + 2,
                is_self_closing: true,
            });
        }

        let attr_start = cursor;
        while cursor < bytes.len()
            && !bytes[cursor].is_ascii_whitespace()
            && bytes[cursor] != b'='
            && bytes[cursor] != b'>'
            && !(bytes[cursor] == b'/' && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'>')
        {
            cursor += 1;
        }
        if cursor == attr_start {
            cursor += 1;
            continue;
        }
        let raw_name = &src[attr_start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let (value, next_cursor) = parse_attr_value(src, cursor);
        cursor = next_cursor;
        let attr_end = cursor;
        attrs.push(ParsedTemplateAttr {
            raw_name,
            value,
            start: attr_start,
            end: attr_end,
        });
    }
    None
}

fn parse_attr_value(src: &str, mut cursor: usize) -> (Option<&str>, usize) {
    let bytes = src.as_bytes();
    if cursor >= bytes.len() || bytes[cursor] != b'=' {
        return (None, cursor);
    }
    cursor += 1;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
        let quote = bytes[cursor];
        let val_start = cursor + 1;
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor] != quote {
            let step = if bytes[cursor] == b'\\' { 2 } else { 1 };
            cursor = (cursor + step).min(bytes.len());
        }
        let value = src.get(val_start..cursor);
        if cursor < bytes.len() && bytes[cursor] == quote {
            cursor += 1;
        }
        (value, cursor)
    } else {
        let val_start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'>'
        {
            cursor += 1;
        }
        (src.get(val_start..cursor), cursor)
    }
}

fn evaluate_template_element(
    template_source: &str,
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_element_alt_text(
        template_source,
        el,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    check_element_click_and_mouse_events(el, base_byte_offset, subject_name, line_starts, sites);
    check_element_has_content(
        template_source,
        el,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    check_element_interactive_supports_focus(
        el,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    check_element_table_scope(
        template_source,
        el,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
    check_element_valid_aria(el, base_byte_offset, subject_name, line_starts, sites);
    check_element_conflicting_material_directives(
        el,
        base_byte_offset,
        subject_name,
        line_starts,
        sites,
    );
}

fn check_element_alt_text(
    template_source: &str,
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag = el.tag_lower.as_str();
    if !matches!(tag, "img" | "area" | "input" | "object") {
        return;
    }
    if tag == "input" {
        let is_image_input = el.attrs.iter().any(|a| {
            normalize_bound_attr_name(a.raw_name) == "type"
                && a.value
                    .map(|v| v.trim().trim_matches(['\'', '"']))
                    .is_some_and(|v| v.eq_ignore_ascii_case("image"))
        });
        if !is_image_input {
            return;
        }
    }
    if is_decorative_or_aria_hidden(el) {
        return;
    }
    let has_accessible_label = el.attrs.iter().any(|a| {
        let norm = normalize_bound_attr_name(a.raw_name);
        matches!(
            norm.as_str(),
            "alt" | "aria-label" | "aria-labelledby" | "attr.alt" | "attr.aria-label" | "attr.aria-labelledby"
        ) || (tag == "object" && matches!(norm.as_str(), "title" | "attr.title"))
    });
    if has_accessible_label {
        return;
    }
    if tag == "object" && element_has_non_empty_inner_content(template_source, el) {
        return;
    }
    push_template_site(
        sites,
        RuleId::AngularTemplateAltText,
        subject_name,
        "angularTemplateAltText",
        el.tag_lower.clone(),
        format!(
            "`<{tag}>` element is missing an accessible `alt`, `[alt]`, `[attr.alt]`, `aria-label`, or `aria-labelledby` binding."
        ),
        base_byte_offset,
        el.open_start,
        el.open_end,
        line_starts,
        None,
    );
}

fn check_element_click_and_mouse_events(
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_custom_or_interactive = is_native_or_custom_interactive_tag(&el.tag_lower);
    let has_click = el
        .attrs
        .iter()
        .any(|a| normalize_event_attr_name(a.raw_name).as_deref() == Some("click"));
    if has_click && !is_custom_or_interactive && !is_decorative_or_aria_hidden(el) {
        let has_key_event = el.attrs.iter().any(|a| {
            normalize_event_attr_name(a.raw_name).is_some_and(|ev| {
                ev == "keyup"
                    || ev == "keydown"
                    || ev == "keypress"
                    || ev.starts_with("keyup.")
                    || ev.starts_with("keydown.")
                    || ev.starts_with("keypress.")
            })
        });
        if !has_key_event {
            push_template_site(
                sites,
                RuleId::AngularTemplateClickEventsHaveKeyEvents,
                subject_name,
                "angularTemplateClickEventsHaveKeyEvents",
                el.tag_lower.clone(),
                format!(
                    "Non-interactive `<{}>` with `(click)` must also bind `(keydown)`, `(keyup)`, or `(keypress)` for keyboard accessibility.",
                    el.tag_lower
                ),
                base_byte_offset,
                el.open_start,
                el.open_end,
                line_starts,
                None,
            );
        }
    }

    let has_mouseover = el
        .attrs
        .iter()
        .any(|a| normalize_event_attr_name(a.raw_name).as_deref() == Some("mouseover"));
    let has_focus = el.attrs.iter().any(|a| {
        matches!(
            normalize_event_attr_name(a.raw_name).as_deref(),
            Some("focus" | "focusin")
        )
    });
    let has_mouseout = el
        .attrs
        .iter()
        .any(|a| normalize_event_attr_name(a.raw_name).as_deref() == Some("mouseout"));
    let has_blur = el.attrs.iter().any(|a| {
        matches!(
            normalize_event_attr_name(a.raw_name).as_deref(),
            Some("blur" | "focusout")
        )
    });

    if (has_mouseover && !has_focus) || (has_mouseout && !has_blur) {
        push_template_site(
            sites,
            RuleId::AngularTemplateMouseEventsHaveKeyEvents,
            subject_name,
            "angularTemplateMouseEventsHaveKeyEvents",
            el.tag_lower.clone(),
            format!(
                "`<{}>` binds `(mouseover)` / `(mouseout)` without matching `(focus)` / `(blur)` handlers.",
                el.tag_lower
            ),
            base_byte_offset,
            el.open_start,
            el.open_end,
            line_starts,
            None,
        );
    }
}

fn check_element_has_content(
    template_source: &str,
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !matches!(
        el.tag_lower.as_str(),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "a"
    ) {
        return;
    }
    let has_content_binding = el.attrs.iter().any(|a| {
        let norm = normalize_bound_attr_name(a.raw_name);
        matches!(
            norm.as_str(),
            "innerhtml"
                | "innertext"
                | "textcontent"
                | "outerhtml"
                | "aria-label"
                | "arialabel"
                | "aria-labelledby"
                | "arialabelledby"
                | "title"
                | "ngtemplateoutlet"
                | "*ngtemplateoutlet"
        )
    });
    if has_content_binding || element_has_non_empty_inner_content(template_source, el) {
        return;
    }
    push_template_site(
        sites,
        RuleId::AngularTemplateElementsHaveContent,
        subject_name,
        "angularTemplateElementsHaveContent",
        el.tag_lower.clone(),
        format!(
            "`<{}>` element has no accessible text, child content, `[innerHTML]`, or `aria-label`.",
            el.tag_lower
        ),
        base_byte_offset,
        el.open_start,
        el.open_end,
        line_starts,
        None,
    );
}

fn check_element_interactive_supports_focus(
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_native_or_custom_interactive_tag(&el.tag_lower) {
        return;
    }
    let has_interactive_role = el.attrs.iter().any(|a| {
        normalize_bound_attr_name(a.raw_name) == "role"
            && a.value
                .map(|v| v.trim().trim_matches(['\'', '"']).to_ascii_lowercase())
                .is_some_and(|r| INTERACTIVE_ARIA_ROLES.contains(&r.as_str()))
    });
    if !has_interactive_role {
        return;
    }
    let has_tabindex = el.attrs.iter().any(|a| {
        matches!(
            normalize_bound_attr_name(a.raw_name).as_str(),
            "tabindex" | "attr.tabindex"
        )
    });
    if has_tabindex {
        return;
    }
    push_template_site(
        sites,
        RuleId::AngularTemplateInteractiveSupportsFocus,
        subject_name,
        "angularTemplateInteractiveSupportsFocus",
        el.tag_lower.clone(),
        format!(
            "Non-interactive `<{}>` with an interactive ARIA `role` must specify `tabindex` / `[attr.tabindex]` to be keyboard focusable.",
            el.tag_lower
        ),
        base_byte_offset,
        el.open_start,
        el.open_end,
        line_starts,
        None,
    );
}

fn check_element_table_scope(
    template_source: &str,
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for attr in &el.attrs {
        let norm = normalize_bound_attr_name(attr.raw_name);
        if norm != "scope" {
            continue;
        }
        if el.tag_lower != "th" {
            let mut remove_start = attr.start;
            let bytes = template_source.as_bytes();
            while remove_start > el.open_start
                && bytes.get(remove_start - 1).is_some_and(u8::is_ascii_whitespace)
            {
                remove_start -= 1;
            }
            let patch = AutofixPatch::delete(
                format!("Remove invalid `scope` attribute from `<{}>`", el.tag_lower),
                ByteSpan {
                    start: base_byte_offset + u32::try_from(remove_start).unwrap_or(0),
                    end: base_byte_offset + u32::try_from(attr.end).unwrap_or(0),
                },
            );
            push_template_site(
                sites,
                RuleId::AngularTemplateTableScope,
                subject_name,
                "angularTemplateTableScope",
                el.tag_lower.clone(),
                format!(
                    "The `scope` attribute may only be used on `<th>` elements, not `<{}>`.",
                    el.tag_lower
                ),
                base_byte_offset,
                attr.start,
                attr.end,
                line_starts,
                Some(patch),
            );
            continue;
        }
        let is_bound = attr.raw_name.starts_with('[') || attr.raw_name.starts_with("bind-");
        if let Some(val) = attr.value {
            let trimmed = val.trim();
            let literal_val = if is_bound {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                    .or_else(|| trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
            } else {
                Some(trimmed)
            };
            if let Some(lit) = literal_val
                && !VALID_TABLE_SCOPES.contains(&lit)
            {
                push_template_site(
                    sites,
                    RuleId::AngularTemplateTableScope,
                    subject_name,
                    "angularTemplateTableScope",
                    lit.to_string(),
                    format!(
                        "Invalid `scope=\"{lit}\"` on `<th>`; expected one of `col`, `row`, `colgroup`, or `rowgroup`."
                    ),
                    base_byte_offset,
                    attr.start,
                    attr.end,
                    line_starts,
                    None,
                );
            }
        }
    }
}

fn check_element_valid_aria(
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for attr in &el.attrs {
        let norm = normalize_bound_attr_name(attr.raw_name);
        if !norm.starts_with("aria-") {
            continue;
        }
        if !VALID_ARIA_PROPERTIES.contains(&norm.as_str()) {
            push_template_site(
                sites,
                RuleId::AngularTemplateValidAria,
                subject_name,
                "angularTemplateValidAria",
                norm.clone(),
                format!(
                    "Invalid WAI-ARIA attribute `{}` (`{norm}`); check spelling against the WAI-ARIA specification.",
                    attr.raw_name
                ),
                base_byte_offset,
                attr.start,
                attr.end,
                line_starts,
                None,
            );
        }
    }
}

fn check_element_conflicting_material_directives(
    el: &ParsedTemplateElement<'_>,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut matched_btn_directives = Vec::new();
    for attr in &el.attrs {
        let norm = normalize_bound_attr_name(attr.raw_name);
        if MATERIAL_BUTTON_DIRECTIVES.contains(&norm.as_str())
            && !matched_btn_directives.contains(&norm)
        {
            matched_btn_directives.push(norm);
        }
    }
    if matched_btn_directives.len() >= 2 {
        let joined = matched_btn_directives.join(", ");
        push_template_site(
            sites,
            RuleId::AngularMaterialNoConflictingMixins,
            subject_name,
            "angularMaterialNoConflictingMixins",
            matched_btn_directives[1].clone(),
            format!(
                "`<{}>` combines mutually exclusive Angular Material button directives ({joined}); apply only one button variant per element.",
                el.tag_lower
            ),
            base_byte_offset,
            el.open_start,
            el.open_end,
            line_starts,
            None,
        );
    }
}

fn element_has_non_empty_inner_content(src: &str, el: &ParsedTemplateElement<'_>) -> bool {
    if el.is_self_closing || VOID_HTML_ELEMENTS.contains(&el.tag_lower.as_str()) {
        return false;
    }
    let after_open = src.get(el.open_end..).unwrap_or_default();
    let close_needle = format!("</{}", el.tag_lower);
    let close_rel = after_open
        .to_ascii_lowercase()
        .find(&close_needle)
        .unwrap_or(after_open.len());
    let inner = after_open.get(..close_rel).unwrap_or(after_open);
    let stripped = strip_html_comments(inner);
    !stripped.trim().is_empty()
}

fn strip_html_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text.get(i..).is_some_and(|s| s.starts_with("<!--")) {
            if let Some(end_c) = text.get(i + 4..).and_then(|s| s.find("-->")) {
                i += 4 + end_c + 3;
                continue;
            }
            break;
        }
        if let Some(ch) = text.get(i..).and_then(|s| s.chars().next()) {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn is_native_or_custom_interactive_tag(tag_lower: &str) -> bool {
    NATIVE_INTERACTIVE_ELEMENTS.contains(&tag_lower) || tag_lower.contains('-')
}

fn is_decorative_or_aria_hidden(el: &ParsedTemplateElement<'_>) -> bool {
    el.attrs.iter().any(|a| {
        let norm = normalize_bound_attr_name(a.raw_name);
        if norm == "aria-hidden" {
            a.value
                .map(|v| v.trim().trim_matches(['\'', '"']))
                .is_some_and(|v| v == "true")
        } else if norm == "role" {
            a.value
                .map(|v| v.trim().trim_matches(['\'', '"']))
                .is_some_and(|v| matches!(v, "presentation" | "none"))
        } else {
            false
        }
    })
}

fn normalize_bound_attr_name(raw_name: &str) -> String {
    let trimmed = raw_name.trim();
    let unwrapped = trimmed
        .strip_prefix("[(")
        .and_then(|s| s.strip_suffix(")]"))
        .or_else(|| trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("bindon-"))
        .or_else(|| trimmed.strip_prefix("bind-"))
        .unwrap_or(trimmed);
    let without_attr = unwrapped.strip_prefix("attr.").unwrap_or(unwrapped);
    without_attr.to_ascii_lowercase()
}

fn normalize_event_attr_name(raw_name: &str) -> Option<String> {
    let trimmed = raw_name.trim();
    let ev = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .or_else(|| trimmed.strip_prefix("on-"))?;
    Some(ev.to_ascii_lowercase())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Template diagnostic constructor converts relative template offsets to file-absolute spans"
)]
fn push_template_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<&str>,
    message_id: &'static str,
    target_name: String,
    message: String,
    base_byte_offset: u32,
    rel_start: usize,
    rel_end: usize,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    let start = base_byte_offset + u32::try_from(rel_start).unwrap_or(0);
    let end = base_byte_offset + u32::try_from(rel_end).unwrap_or(0);
    sites.push(SemanticRuleSite {
        rule,
        subject_name: subject_name.map(ToOwned::to_owned),
        message_id,
        target_name,
        message,
        loc: loc_from_line_starts(line_starts, start),
        span: ByteSpan { start, end },
        autofix,
    });
}

fn find_matching_paren(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let bytes = text.as_bytes();
    let mut idx = open_idx;
    while idx < bytes.len() {
        let b = bytes[idx];
        if let Some(q) = in_quote {
            if b == b'\\' {
                idx += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
        } else if b == b'\'' || b == b'"' {
            in_quote = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
        idx += 1;
    }
    None
}

fn classify_for_header_track_violation(header: &str) -> Option<(String, String)> {
    let mut segments = header.split(';');
    let first_seg = segments.next()?.trim();
    let (item_part, _collection_part) = first_seg.split_once(" of ")?;
    let item_var = item_part.trim();
    if item_var.is_empty() {
        return None;
    }

    let mut index_aliases: HashSet<&str> = HashSet::from(["$index"]);
    let mut track_expr: Option<&str> = None;

    for seg in segments {
        let trimmed = seg.trim();
        if let Some(rest) = trimmed.strip_prefix("let ") {
            if let Some((alias, rhs)) = rest.split_once('=')
                && rhs.trim() == "$index"
            {
                index_aliases.insert(alias.trim());
            }
        } else if let Some(rest) = trimmed.strip_prefix("track")
            && rest.starts_with(char::is_whitespace)
        {
            track_expr = Some(rest.trim());
        }
    }

    let track = track_expr?;
    if index_aliases.contains(track) {
        return Some((
            track.to_string(),
            format!(
                "`@for` loop tracks `{track}` (`$index`); track a stable unique property like `track {item_var}.id` so DOM nodes are preserved when items reorder."
            ),
        ));
    }
    if track == item_var {
        return Some((
            track.to_string(),
            format!(
                "`@for` loop tracks raw object identity `track {item_var}`; track a unique key property like `track {item_var}.id` so immutable updates do not tear down DOM nodes."
            ),
        ));
    }
    None
}
