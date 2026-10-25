//! ARIA attributes, roles, landmarks, and semantic element `a11y` rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{JSXAttribute, JSXElement, JSXOpeningElement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use super::{
    JsxElementA11yCtx,
    forms_media_and_content::{
        check_alt_text, check_anchor_rules, check_control_and_label_association,
        check_custom_a11y_rules, check_element_content_media_and_form_rules,
    },
    has_accessible_child, has_nonempty_literal_attr, is_attr_statically_false,
    is_attr_statically_true_or_true_str, is_content_editable_tabbable, is_focusable_element,
    is_interactive_element,
    keyboard_and_focus::{check_element_keyboard_and_focus_rules, check_no_outline_none},
    parse_attr_number, push_site,
    tables::{
        GLOBAL_ARIA_PROPERTIES, HTML_TAGS, INTERACTIVE_ROLES, NON_INTERACTIVE_ELEMENTS,
        NON_INTERACTIVE_ROLES, RESERVED_HTML_TAGS, UNINFORMATIVE_ARIA_LABELS,
        VALID_ARIA_PROPERTIES, VALID_ARIA_ROLES, get_implicit_role,
        is_allowed_interactive_role_on_noninteractive, is_aria_prop_supported_by_role,
        is_valid_aria_prop_value, preferred_html_tag_for_role, supplies_native_aria_prop,
    },
};
use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_jsx_attr_ignore_case, get_attr_static_str, get_jsx_tag_name, jsx_has_spread_attr,
    },
    rules::RuleId,
};

pub(super) fn check_jsx_attribute_a11y(
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
pub(super) fn check_jsx_element_a11y(
    _path: &std::path::Path,
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
    let has_spread = jsx_has_spread_attr(&opening.attributes);

    let elem_ctx = JsxElementA11yCtx {
        is_testlike,
        semantic,
        node_id,
        jsx_el,
        opening,
        tag: &tag,
        is_html,
        has_spread,
        subject_name,
        const_strings,
        loc,
        span,
        line_starts,
    };
    check_alt_text(jsx_el, &tag, subject_name, loc, span, sites);
    check_element_core_aria_rules(&elem_ctx, sites);
    check_element_content_media_and_form_rules(&elem_ctx, sites);
    check_element_keyboard_and_focus_rules(&elem_ctx, sites);
    check_element_role_transition_rules(&elem_ctx, sites);

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

    check_no_outline_none(
        semantic,
        opening,
        subject_name,
        const_strings,
        loc,
        span,
        sites,
    );
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
    check_aria_hidden_and_prefer_tag(
        semantic,
        opening,
        &tag,
        subject_name,
        const_strings,
        line_starts,
        sites,
    );

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

    check_custom_a11y_rules(
        &elem_ctx,
        imported_sources,
        main_landmarks_by_root,
        unlabeled_navs_by_root,
        sites,
    );
}

fn check_element_core_aria_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if RESERVED_HTML_TAGS.contains(&ctx.tag) {
        check_aria_unsupported_elements(ctx, sites);
    }
    check_aria_role_and_redundant_roles(ctx, sites);
    check_aria_activedescendant_tabindex(ctx, sites);
    check_aria_braille_equivalent(ctx, sites);
}
fn check_aria_unsupported_elements(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !RESERVED_HTML_TAGS.contains(&ctx.tag) {
        return;
    }
    for item in &ctx.opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        let Some(id) = attr.name.as_identifier() else {
            continue;
        };
        let aname = id.name.as_str();
        if aname == "role" || aname.starts_with("aria-") {
            push_site(
                sites,
                RuleId::AriaUnsupportedElements,
                ctx.subject_name.clone(),
                "ariaUnsupportedElements",
                aname,
                format!(
                    "Screen reader users get no help from `{aname}` because `<{}>` doesn't accept it, so remove it from this element.",
                    ctx.tag
                ),
                loc_from_line_starts(ctx.line_starts, attr.span.start),
                ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
            );
        }
    }
}

fn check_aria_role_and_redundant_roles(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.is_html {
        return;
    }
    let Some(role_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "role") else {
        return;
    };
    let Some(role_str) = get_attr_static_str(ctx.semantic, role_attr, ctx.const_strings) else {
        return;
    };
    let roles: Vec<&str> = role_str.split_whitespace().collect();
    let role_loc = loc_from_line_starts(ctx.line_starts, role_attr.span.start);
    let role_span = ByteSpan {
        start: role_attr.span.start,
        end: role_attr.span.end,
    };
    if roles.is_empty() || roles.iter().any(|r| !VALID_ARIA_ROLES.contains(r)) {
        push_site(
            sites,
            RuleId::AriaRole,
            ctx.subject_name.clone(),
            "ariaRole",
            &role_str,
            "This `role` is not a valid ARIA role, so assistive tech cannot expose it correctly. Use a real, non-abstract role.".to_string(),
            role_loc,
            role_span,
        );
    }
    if let Some(&first_role) = roles.first()
        && !matches!((ctx.tag, first_role), ("ul" | "ol", "list"))
        && get_implicit_role(ctx.tag, ctx.opening, ctx.semantic, ctx.const_strings)
            == Some(first_role)
    {
        push_site(
            sites,
            RuleId::NoRedundantRoles,
            ctx.subject_name.clone(),
            "noRedundantRoles",
            first_role,
            format!(
                "Screen reader users gain nothing from this `role` because `<{}>` already acts as a `{first_role}`, so remove it.",
                ctx.tag
            ),
            role_loc,
            role_span,
        );
    }
}

fn check_aria_activedescendant_tabindex(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.is_html
        || find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-activedescendant").is_none()
    {
        return;
    }
    let tab_attr = find_jsx_attr_ignore_case(&ctx.opening.attributes, "tabIndex");
    let tab_ok = match tab_attr {
        Some(attr) => parse_attr_number(attr).is_none_or(|v| v >= -1.0),
        None => {
            is_interactive_element(ctx.tag, ctx.opening, ctx.semantic, ctx.const_strings)
                || is_content_editable_tabbable(ctx.opening, ctx.semantic, ctx.const_strings)
        }
    };
    if !tab_ok {
        push_site(
            sites,
            RuleId::AriaActivedescendantHasTabindex,
            ctx.subject_name.clone(),
            "ariaActivedescendantHasTabindex",
            ctx.tag,
            "Keyboard users can't focus this element with `aria-activedescendant` because it isn't tabbable, so add `tabIndex={0}`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_aria_braille_equivalent(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_spread {
        return;
    }
    if has_nonempty_literal_attr(
        ctx.opening,
        "aria-brailleroledescription",
        ctx.semantic,
        ctx.const_strings,
    ) && !has_nonempty_literal_attr(
        ctx.opening,
        "aria-roledescription",
        ctx.semantic,
        ctx.const_strings,
    ) {
        push_site(
            sites,
            RuleId::AriaBrailleEquivalent,
            ctx.subject_name.clone(),
            "ariaBrailleEquivalent",
            "aria-brailleroledescription",
            "This braille role description has no non-braille equivalent. Add a nonempty aria-roledescription for other assistive technologies.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
    if has_nonempty_literal_attr(
        ctx.opening,
        "aria-braillelabel",
        ctx.semantic,
        ctx.const_strings,
    ) && !has_accessible_child(ctx.jsx_el)
        && !["aria-label", "aria-labelledby", "alt", "title"]
            .iter()
            .any(|a| find_jsx_attr_ignore_case(&ctx.opening.attributes, a).is_some())
    {
        push_site(
            sites,
            RuleId::AriaBrailleEquivalent,
            ctx.subject_name.clone(),
            "ariaBrailleEquivalent",
            "aria-braillelabel",
            "This braille label is the element's only accessible name. Add visible text, aria-label, aria-labelledby, alt, or title for non-braille assistive technology.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_element_role_transition_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !ctx.is_html {
        return;
    }
    let Some(role_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "role") else {
        return;
    };
    let Some(role_str) = get_attr_static_str(ctx.semantic, role_attr, ctx.const_strings) else {
        return;
    };
    let Some(first_role) = role_str.split_whitespace().next() else {
        return;
    };
    let role_loc = loc_from_line_starts(ctx.line_starts, role_attr.span.start);
    let role_span = ByteSpan {
        start: role_attr.span.start,
        end: role_attr.span.end,
    };
    let is_interactive =
        is_interactive_element(ctx.tag, ctx.opening, ctx.semantic, ctx.const_strings);

    if NON_INTERACTIVE_ELEMENTS.contains(&ctx.tag)
        && !is_interactive
        && INTERACTIVE_ROLES.contains(&first_role)
        && !is_allowed_interactive_role_on_noninteractive(ctx.tag, first_role)
        && !(first_role == "separator"
            && find_jsx_attr_ignore_case(&ctx.opening.attributes, "tabIndex").is_none())
    {
        push_site(
            sites,
            RuleId::NoNoninteractiveElementToInteractiveRole,
            ctx.subject_name.clone(),
            "noNoninteractiveElementToInteractiveRole",
            first_role,
            format!(
                "Role `{first_role}` gives `<{}>` interactive semantics even though the element is noninteractive, so screen reader users get the wrong controls.",
                ctx.tag
            ),
            role_loc,
            role_span,
        );
    }

    if (ctx.tag == "input" || is_interactive)
        && (NON_INTERACTIVE_ROLES.contains(&first_role)
            || matches!(first_role, "presentation" | "none"))
        && !matches!(
            (ctx.tag, first_role),
            ("tr", "none" | "presentation") | ("canvas", "img")
        )
    {
        push_site(
            sites,
            RuleId::NoInteractiveElementToNoninteractiveRole,
            ctx.subject_name.clone(),
            "noInteractiveElementToNoninteractiveRole",
            first_role,
            format!(
                "Screen reader users can't operate this interactive `<{}>` because role `{first_role}` says it isn't, so remove the role or use a different element.",
                ctx.tag
            ),
            role_loc,
            role_span,
        );
    }
}

fn check_aria_hidden_and_prefer_tag(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 30. `no-aria-hidden-on-focusable` & `no-aria-hidden-on-body`
    if let Some(ah_attr) = find_jsx_attr_ignore_case(&opening.attributes, "aria-hidden")
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
        } else if is_focusable_element(tag, opening, semantic, const_strings, false) {
            push_site(
                sites,
                RuleId::NoAriaHiddenOnFocusable,
                subject_name.clone(),
                "noAriaHiddenOnFocusable",
                tag,
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
    if matches!(tag, "div" | "span")
        && let Some(role_attr) = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
    let explicit_role = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
            if find_jsx_attr_ignore_case(&opening.attributes, req).is_none()
                && !supplies_native_aria_prop(tag, opening, req, semantic, const_strings)
            {
                missing.push(req);
            }
        }
        if !missing.is_empty()
            && let Some(role_attr) = find_jsx_attr_ignore_case(&opening.attributes, "role")
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

pub(super) fn check_custom_aria_and_role_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    has_a11y_name: bool,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_dialog_and_label_aria_rules(ctx, first_role, has_a11y_name, sites);
    check_progress_range_rules(ctx, first_role, sites);
    check_landmarks_and_presentation_conflict(
        ctx,
        first_role,
        has_a11y_name,
        main_landmarks_by_root,
        unlabeled_navs_by_root,
        sites,
    );
}

fn check_dialog_and_label_aria_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_dialog_name_and_prefer_native_dialog(ctx, first_role, has_a11y_name, sites);
    check_label_live_and_invalid_aria_rules(ctx, first_role, sites);
}

fn check_dialog_name_and_prefer_native_dialog(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.is_testlike || !ctx.is_html || ctx.has_spread {
        return;
    }
    let is_dialog_role = matches!(first_role, Some("dialog" | "alertdialog"));
    if (ctx.tag == "dialog" || is_dialog_role) && !has_a11y_name {
        push_site(
            sites,
            RuleId::DialogHasAccessibleName,
            ctx.subject_name.clone(),
            "dialogHasAccessibleName",
            ctx.tag,
            "This dialog has no accessible name. Add `aria-label` or point `aria-labelledby` at its heading.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
    let is_aria_modal = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-modal")
        .is_some_and(is_attr_statically_true_or_true_str);
    if ctx.tag != "dialog" && (is_dialog_role || is_aria_modal) {
        push_site(
            sites,
            RuleId::PreferHtmlDialog,
            ctx.subject_name.clone(),
            "preferHtmlDialog",
            ctx.tag,
            "Use the native HTML `<dialog>` element instead of a custom `role=\"dialog\"` or `aria-modal` container.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_label_live_and_invalid_aria_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(al_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-label")
        && let Some(al_val) = get_attr_static_str(ctx.semantic, al_attr, ctx.const_strings)
        && UNINFORMATIVE_ARIA_LABELS.contains(&al_val.trim().to_ascii_lowercase().as_str())
    {
        push_site(
            sites,
            RuleId::NoUninformativeAriaLabel,
            ctx.subject_name.clone(),
            "noUninformativeAriaLabel",
            &al_val,
            "An `aria-label` should name the action or destination, not the element type."
                .to_string(),
            loc_from_line_starts(ctx.line_starts, al_attr.span.start),
            ByteSpan {
                start: al_attr.span.start,
                end: al_attr.span.end,
            },
        );
    }

    if ctx.is_html
        && first_role == Some("status")
        && let Some(live_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-live")
        && get_attr_static_str(ctx.semantic, live_attr, ctx.const_strings)
            .is_some_and(|v| v.eq_ignore_ascii_case("assertive"))
    {
        push_site(
            sites,
            RuleId::NoAssertiveStatus,
            ctx.subject_name.clone(),
            "noAssertiveStatus",
            "aria-live",
            "A status is advisory and implicitly polite, but `aria-live=\"assertive\"` interrupts queued speech.".to_string(),
            loc_from_line_starts(ctx.line_starts, live_attr.span.start),
            ByteSpan {
                start: live_attr.span.start,
                end: live_attr.span.end,
            },
        );
    }

    if matches!(ctx.tag, "input" | "select" | "textarea")
        && !ctx.has_spread
        && let Some(inv_attr) = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-invalid")
        && !is_attr_statically_false(inv_attr)
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-describedby").is_none()
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-errormessage").is_none()
    {
        push_site(
            sites,
            RuleId::NoAriaInvalidWithoutDescription,
            ctx.subject_name.clone(),
            "noAriaInvalidWithoutDescription",
            "aria-invalid",
            "This control is marked invalid but is not connected to error text via `aria-describedby` or `aria-errormessage`.".to_string(),
            loc_from_line_starts(ctx.line_starts, inv_attr.span.start),
            ByteSpan {
                start: inv_attr.span.start,
                end: inv_attr.span.end,
            },
        );
    }
}

fn check_progress_range_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_spread {
        return;
    }
    if ctx.tag == "progress" {
        let max_val = find_jsx_attr_ignore_case(&ctx.opening.attributes, "max")
            .and_then(parse_attr_number)
            .unwrap_or(1.0);
        let val_opt = find_jsx_attr_ignore_case(&ctx.opening.attributes, "value")
            .and_then(parse_attr_number);
        if max_val <= 0.0 || val_opt.is_some_and(|v| v < 0.0 || v > max_val) {
            push_site(
                sites,
                RuleId::NoInvalidProgressRange,
                ctx.subject_name.clone(),
                "noInvalidProgressRange",
                "progress",
                "This progress element has an impossible value range.".to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    } else if first_role == Some("progressbar") {
        let min_val = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-valuemin")
            .and_then(parse_attr_number)
            .unwrap_or(0.0);
        let max_val = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-valuemax")
            .and_then(parse_attr_number)
            .unwrap_or(100.0);
        let now_opt = find_jsx_attr_ignore_case(&ctx.opening.attributes, "aria-valuenow")
            .and_then(parse_attr_number);
        if min_val >= max_val || now_opt.is_some_and(|v| v < min_val || v > max_val) {
            push_site(
                sites,
                RuleId::NoInvalidProgressRange,
                ctx.subject_name.clone(),
                "noInvalidProgressRange",
                "progressbar",
                "This progressbar exposes an impossible ARIA range.".to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }
}

fn check_landmarks_and_presentation_conflict(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    has_a11y_name: bool,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "main" {
        let root_id = find_topmost_jsx_root(ctx.semantic, ctx.node_id);
        main_landmarks_by_root
            .entry(root_id)
            .or_default()
            .push((ctx.loc, ctx.span));
    } else if ctx.tag == "nav" && !ctx.has_spread && !has_a11y_name {
        let root_id = find_topmost_jsx_root(ctx.semantic, ctx.node_id);
        unlabeled_navs_by_root
            .entry(root_id)
            .or_default()
            .push((ctx.loc, ctx.span));
    }

    if !ctx.is_html {
        return;
    }
    let is_pres = matches!(first_role, Some("none" | "presentation"))
        || (ctx.tag == "img"
            && find_jsx_attr_ignore_case(&ctx.opening.attributes, "alt")
                .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
                .as_deref()
                == Some(""));
    if !is_pres {
        return;
    }
    let is_focusable =
        is_focusable_element(ctx.tag, ctx.opening, ctx.semantic, ctx.const_strings, true);
    let has_global_aria = ctx.opening.attributes.iter().any(|item| {
        item.as_attribute()
            .and_then(|a| a.name.as_identifier())
            .is_some_and(|id| GLOBAL_ARIA_PROPERTIES.contains(&id.name.as_str()))
    });
    if is_focusable || has_global_aria {
        push_site(
            sites,
            RuleId::NoPresentationRoleConflict,
            ctx.subject_name.clone(),
            "noPresentationRoleConflict",
            ctx.tag,
            "This element is marked presentational but is also focusable or carries global ARIA state.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
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
