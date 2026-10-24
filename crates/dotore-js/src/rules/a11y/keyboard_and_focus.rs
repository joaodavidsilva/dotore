//! Keyboard events, focusability, `tabIndex`, focus outline, and focus effect `a11y` rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        CallExpression, ConditionalExpression, Expression, JSXAttribute, JSXElement,
        JSXOpeningElement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;

use super::{
    is_attr_dynamic_non_undefined, is_attr_null_or_undefined, is_attr_statically_false,
    is_attr_statically_true_or_true_str, is_attr_undefined, is_content_editable_tabbable,
    is_disabled_element, is_focusable_element, is_hidden_from_screen_reader,
    is_interactive_element, parse_attr_number, push_site,
    tables::{INTERACTIVE_ROLES, NON_INTERACTIVE_ELEMENTS, VALID_ARIA_ROLES},
};
use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, get_style_prop_number, get_style_prop_str,
    },
    rules::RuleId,
};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates core JSX keyboard event, focusability, tabindex, and accessKey rules in one pass"
)]
pub(super) fn check_element_keyboard_and_focus_rules(
    is_testlike: bool,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    is_html: bool,
    has_spread: bool,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 8. `click-events-have-key-events`
    if is_html
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !has_spread
        && let Some(click_attr) = find_jsx_attr_ignore_case(&opening.attributes, "onClick")
            .or_else(|| find_jsx_attr_ignore_case(&opening.attributes, "onClickCapture"))
        && !is_attr_undefined(click_attr)
    {
        let is_focusless_container = matches!(tag, "tr" | "td" | "th" | "canvas");
        let is_interactive = !is_focusless_container
            && is_interactive_element(tag, opening, semantic, const_strings);
        let role_str = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
            .any(|k| find_jsx_attr_ignore_case(&opening.attributes, k).is_some());
        let is_backdrop_dismiss = is_backdrop_dismiss_handler(click_attr, semantic);
        let is_hover_li = tag == "li"
            && (find_jsx_attr_ignore_case(&opening.attributes, "onMouseEnter").is_some()
                || find_jsx_attr_ignore_case(&opening.attributes, "onMouseOver").is_some());

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
                tag,
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
        && !is_interactive_element(tag, opening, semantic, const_strings)
        && !NON_INTERACTIVE_ELEMENTS.contains(&tag)
    {
        let role_attr = find_jsx_attr_ignore_case(&opening.attributes, "role");
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
                find_jsx_attr_ignore_case(&opening.attributes, h)
                    .is_some_and(|a| !is_attr_null_or_undefined(a))
            });
        let has_key_handler = ["onKeyDown", "onKeyUp", "onKeyPress"].iter().any(|h| {
            find_jsx_attr_ignore_case(&opening.attributes, h)
                .is_some_and(|a| !is_attr_null_or_undefined(a))
        }) && find_jsx_attr_ignore_case(&opening.attributes, "tabIndex")
            .is_some();

        if !has_valid_role && (has_pointer_handler || has_key_handler) {
            push_site(
                sites,
                RuleId::NoStaticElementInteractions,
                subject_name.clone(),
                "noStaticElementInteractions",
                tag,
                "Screen reader users can't tell this click handler is interactive because it has no `role`, so add a `role` or use a button or link.".to_string(),
                loc,
                span,
            );
        }
    }

    // 13. `no-noninteractive-element-interactions`
    if !is_testlike
        && is_html
        && NON_INTERACTIVE_ELEMENTS.contains(&tag)
        && !is_interactive_element(tag, opening, semantic, const_strings)
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !is_content_editable_tabbable(opening, semantic, const_strings)
    {
        let has_mouse_handler = ["onClick", "onMouseDown", "onMouseUp"]
            .iter()
            .any(|h| find_jsx_attr_ignore_case(&opening.attributes, h).is_some());
        let role_str = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
                tag,
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
        && !is_interactive_element(tag, opening, semantic, const_strings)
        && let Some(tab_attr) = find_jsx_attr_ignore_case(&opening.attributes, "tabIndex")
        && let Some(tab_val) = parse_attr_number(tab_attr)
        && tab_val >= 0.0
    {
        let role_str = find_jsx_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let is_interactive_role = role_str
            .as_deref()
            .and_then(|r| r.split_whitespace().next())
            .is_some_and(|r| INTERACTIVE_ROLES.contains(&r) || r == "tabpanel");
        let has_key_or_focus = ["onKeyDown", "onKeyUp", "onKeyPress", "onFocus", "onBlur"]
            .iter()
            .any(|h| find_jsx_attr_ignore_case(&opening.attributes, h).is_some());
        let has_a11y_name = ["aria-label", "aria-labelledby"]
            .iter()
            .any(|a| find_jsx_attr_ignore_case(&opening.attributes, a).is_some());
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
                tag,
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
        && !is_interactive_element(tag, opening, semantic, const_strings)
        && !is_hidden_from_screen_reader(opening, semantic, const_strings)
        && !is_disabled_element(opening, semantic, const_strings)
        && let Some(role_attr) = find_jsx_attr_ignore_case(&opening.attributes, "role")
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
        let has_tabindex = find_jsx_attr_ignore_case(&opening.attributes, "tabIndex").is_some();
        let is_composite_item_with_id = matches!(
            first_role,
            "option"
                | "menuitem"
                | "menuitemcheckbox"
                | "menuitemradio"
                | "tab"
                | "treeitem"
                | "gridcell"
        ) && find_jsx_attr_ignore_case(&opening.attributes, "id")
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

    // 28. `tabindex-no-positive`
    if !is_testlike
        && let Some(tab_attr) = find_jsx_attr_ignore_case(&opening.attributes, "tabIndex")
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
        && let Some(ak_attr) = find_jsx_attr_ignore_case(&opening.attributes, "accessKey")
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
}

pub(super) fn check_no_outline_none(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if find_jsx_attr_ignore_case(&opening.attributes, "tabIndex")
        .and_then(parse_attr_number)
        .is_some_and(|v| v < 0.0)
    {
        return;
    }
    if find_jsx_attr_ignore_case(&opening.attributes, "aria-modal").is_some()
        || find_jsx_attr_ignore_case(&opening.attributes, "onFocus").is_some()
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
    reason = "Evaluates custom keyboard activation, focusable-in-aria-hidden/role-text, and nested interactive rules"
)]
pub(super) fn check_custom_keyboard_and_focus_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    is_html: bool,
    first_role: Option<&str>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 7. `role-button-requires-complete-keyboard-activation`
    if is_html
        && first_role == Some("button")
        && let Some(kd_attr) = find_jsx_attr_ignore_case(&opening.attributes, "onKeyDown")
            .or_else(|| find_jsx_attr_ignore_case(&opening.attributes, "onKeyUp"))
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
}

pub(super) fn check_call_a11y(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    call: &CallExpression<'_>,
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

pub(super) fn check_conditional_a11y(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    cond: &ConditionalExpression<'_>,
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
                    || find_jsx_attr_ignore_case(&el.opening_element.attributes, "aria-modal")
                        .is_some()
                    || find_jsx_attr_ignore_case(&el.opening_element.attributes, "role")
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

fn has_aria_hidden_ancestor(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && find_jsx_attr_ignore_case(&el.opening_element.attributes, "aria-hidden")
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
            && find_jsx_attr_ignore_case(&el.opening_element.attributes, "role")
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
