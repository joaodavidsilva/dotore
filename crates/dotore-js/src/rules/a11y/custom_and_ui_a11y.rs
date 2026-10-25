//! Custom accessibility rules and UI component library (`shadcn`, `Radix`, `Base UI`, `React Aria`) composition checks.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; custom a11y checks match only relevant JSX/AST node kinds (#50)"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{JSXChild, JSXElement, JSXElementName},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use super::{
    JsxElementA11yCtx,
    aria_and_roles::check_custom_aria_and_role_rules,
    forms_media_and_content::has_enclosing_label_or_hidden_ancestor,
    has_accessible_child, has_accessible_label_text_in_children, has_non_empty_attr_val,
    is_attr_statically_false,
    keyboard_and_focus::check_custom_keyboard_and_focus_rules,
    push_site,
    tables::HTML_TAGS,
};
use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        find_attr, find_jsx_attr_ignore_case, get_attr_static_str, get_class_name_str,
        get_jsx_tag_name, get_style_prop_str, subtree_has_tag_matching,
    },
    rules::RuleId,
};

pub(super) fn check_custom_a11y_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    imported_sources: &HashMap<SymbolId, String>,
    main_landmarks_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    unlabeled_navs_by_root: &mut HashMap<NodeId, Vec<(SourceLoc, ByteSpan)>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let role_str = find_jsx_attr_ignore_case(&ctx.opening.attributes, "role")
        .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings));
    let first_role = role_str
        .as_deref()
        .and_then(|r| r.split_whitespace().next());
    let class_str =
        get_class_name_str(ctx.opening, ctx.semantic, ctx.const_strings).unwrap_or_default();
    let has_a11y_name = ["aria-label", "aria-labelledby", "title"].iter().any(|a| {
        find_jsx_attr_ignore_case(&ctx.opening.attributes, a).is_some_and(has_non_empty_attr_val)
    });

    check_custom_aria_and_role_rules(
        ctx,
        first_role,
        has_a11y_name,
        main_landmarks_by_root,
        unlabeled_navs_by_root,
        sites,
    );
    check_custom_keyboard_and_focus_rules(
        ctx.semantic,
        ctx.node_id,
        ctx.opening,
        ctx.tag,
        ctx.is_html,
        first_role,
        ctx.subject_name,
        ctx.const_strings,
        ctx.loc,
        ctx.span,
        sites,
    );
    check_custom_media_and_input_rules(ctx, has_a11y_name, sites);
    check_custom_motion_and_responsive_rules(ctx, &class_str, has_a11y_name, sites);
    check_custom_table_fieldset_and_form_rules(ctx, first_role, has_a11y_name, sites);
    check_root_jsx_duplicate_frames_and_ids(ctx, sites);
    check_ui_library_a11y(ctx, has_a11y_name, imported_sources, sites);
}

fn check_custom_media_and_input_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_autoplay_and_blocked_paste_rules(ctx, sites);
    check_broken_img_and_placeholder_rules(ctx, has_a11y_name, sites);
}

fn check_autoplay_and_blocked_paste_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = ctx.opening;
    if matches!(ctx.tag, "video" | "audio")
        && !ctx.has_spread
        && find_jsx_attr_ignore_case(&opening.attributes, "autoPlay")
            .is_some_and(|a| !is_attr_statically_false(a))
        && !find_jsx_attr_ignore_case(&opening.attributes, "muted")
            .is_some_and(|a| !is_attr_statically_false(a))
    {
        push_site(
            sites,
            RuleId::NoAutoplayWithoutMuted,
            ctx.subject_name.clone(),
            "noAutoplayWithoutMuted",
            ctx.tag,
            "Autoplaying media with sound is hostile to users. Add `muted` to the autoplaying `<video>` / `<audio>`, or drop `autoPlay`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "input"
        && !ctx.has_spread
        && let Some(paste_attr) = find_jsx_attr_ignore_case(&opening.attributes, "onPaste")
        && is_auth_input_element(ctx)
        && paste_attr
            .span
            .source_text(ctx.semantic.source_text())
            .contains("preventDefault(")
    {
        push_site(
            sites,
            RuleId::NoBlockedPaste,
            ctx.subject_name.clone(),
            "noBlockedPaste",
            "onPaste",
            "Blocking paste in an authentication field prevents password managers and assistive tools from working.".to_string(),
            loc_from_line_starts(ctx.line_starts, paste_attr.span.start),
            ByteSpan {
                start: paste_attr.span.start,
                end: paste_attr.span.end,
            },
        );
    }
}

fn check_broken_img_and_placeholder_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = ctx.opening;
    if ctx.tag == "img"
        && !ctx.has_spread
        && find_jsx_attr_ignore_case(&opening.attributes, "ref").is_none()
        && is_broken_img_src(ctx)
    {
        push_site(
            sites,
            RuleId::NoBrokenImageSource,
            ctx.subject_name.clone(),
            "noBrokenImageSource",
            "img",
            "This image has no usable `src` attribute and will render as a broken placeholder."
                .to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if matches!(ctx.tag, "input" | "textarea")
        && !ctx.has_spread
        && find_jsx_attr_ignore_case(&opening.attributes, "placeholder")
            .is_some_and(has_non_empty_attr_val)
        && !has_a11y_name
        && !has_enclosing_label_or_hidden_ancestor(ctx.semantic, ctx.node_id, ctx.const_strings)
        && find_jsx_attr_ignore_case(&opening.attributes, "id").is_none()
    {
        push_site(
            sites,
            RuleId::NoPlaceholderOnlyField,
            ctx.subject_name.clone(),
            "noPlaceholderOnlyField",
            ctx.tag,
            "This field relies on `placeholder` text for its accessible name. Add a visible `<label>` or `aria-label`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "img"
        && let Some(ismap_attr) = find_jsx_attr_ignore_case(&opening.attributes, "isMap")
        && !is_attr_statically_false(ismap_attr)
    {
        push_site(
            sites,
            RuleId::NoServerSideImageMap,
            ctx.subject_name.clone(),
            "noServerSideImageMap",
            "isMap",
            "Server-side image maps require pointer coordinates and do not expose individual targets to keyboard users.".to_string(),
            loc_from_line_starts(ctx.line_starts, ismap_attr.span.start),
            ByteSpan {
                start: ismap_attr.span.start,
                end: ismap_attr.span.end,
            },
        );
    }
}

fn is_auth_input_element(ctx: &JsxElementA11yCtx<'_, '_>) -> bool {
    let attrs = &ctx.opening.attributes;
    find_jsx_attr_ignore_case(attrs, "type")
        .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
        .is_some_and(|t| t.eq_ignore_ascii_case("password"))
        || find_jsx_attr_ignore_case(attrs, "autoComplete")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .is_some_and(|ac| {
                ac.contains("password") || ac.contains("one-time-code") || ac.contains("username")
            })
}

fn is_broken_img_src(ctx: &JsxElementA11yCtx<'_, '_>) -> bool {
    match find_jsx_attr_ignore_case(&ctx.opening.attributes, "src") {
        None => true,
        Some(a) if a.value.is_none() => true,
        Some(a) => get_attr_static_str(ctx.semantic, a, ctx.const_strings)
            .is_some_and(|s| matches!(s.trim(), "" | "#")),
    }
}

fn check_custom_motion_and_responsive_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    class_str: &str,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_reduced_motion_and_responsive_name_rules(ctx, class_str, has_a11y_name, sites);
    check_textarea_motion_config_and_anim_rules(ctx, class_str, sites);
}

fn check_reduced_motion_and_responsive_name_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    class_str: &str,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.is_html
        && class_str.split_whitespace().any(|t| {
            matches!(
                t,
                "motion-reduce:hidden" | "motion-reduce:invisible" | "motion-reduce:sr-only"
            )
        })
        && has_accessible_child(ctx.jsx_el)
    {
        push_site(
            sites,
            RuleId::NoReducedMotionContentRemoval,
            ctx.subject_name.clone(),
            "noReducedMotionContentRemoval",
            ctx.tag,
            "Hiding meaningful content under `motion-reduce:` removes information for reduced-motion users.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if matches!(ctx.tag, "button" | "a")
        && !has_a11y_name
        && has_only_responsive_hidden_text(ctx.jsx_el, ctx.semantic, ctx.const_strings)
    {
        push_site(
            sites,
            RuleId::NoResponsiveHiddenAccessibleName,
            ctx.subject_name.clone(),
            "noResponsiveHiddenAccessibleName",
            ctx.tag,
            "Responsive utility classes hide this control's only accessible name at some breakpoints.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_textarea_motion_config_and_anim_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    class_str: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "textarea" && !ctx.has_spread {
        let resize_none_class = class_str.split_whitespace().any(|t| t == "resize-none")
            && !class_str
                .split_whitespace()
                .any(|t| t == "field-sizing-content");
        let resize_none_style =
            get_style_prop_str(ctx.opening, "resize", ctx.semantic, ctx.const_strings).as_deref()
                == Some("none");
        if resize_none_class || resize_none_style {
            push_site(
                sites,
                RuleId::NoNonresizableTextarea,
                ctx.subject_name.clone(),
                "noNonresizableTextarea",
                "textarea",
                "This textarea disables user resizing.".to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }

    if (ctx.tag == "MotionConfig" || ctx.tag.ends_with(".MotionConfig"))
        && let Some(rm_attr) = find_attr(&ctx.opening.attributes, "reducedMotion")
        && get_attr_static_str(ctx.semantic, rm_attr, ctx.const_strings).as_deref() == Some("never")
    {
        push_site(
            sites,
            RuleId::NoStaticMotionConfigNever,
            ctx.subject_name.clone(),
            "noStaticMotionConfigNever",
            "MotionConfig",
            "This MotionConfig hard-codes `reducedMotion=\"never\"`, ignoring the user's operating-system preference.".to_string(),
            loc_from_line_starts(ctx.line_starts, rm_attr.span.start),
            ByteSpan {
                start: rm_attr.span.start,
                end: rm_attr.span.end,
            },
        );
    }

    if !ctx.has_spread && !class_str.is_empty() {
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
                ctx.subject_name.clone(),
                "noUngatedTailwindAnimation",
                ctx.tag,
                "Tailwind animation utility runs unconditionally without a `motion-safe:` or `motion-reduce:` guard.".to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }
}

fn has_only_responsive_hidden_text(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let mut has_responsive_hidden_text = false;
    let mut has_persistent_text = false;
    for child in &jsx_el.children {
        if let JSXChild::Text(t) = child
            && !t.value.trim().is_empty()
        {
            has_persistent_text = true;
        } else if let JSXChild::Element(child_el) = child
            && has_accessible_child(child_el)
        {
            let c_class = get_class_name_str(&child_el.opening_element, semantic, const_strings)
                .unwrap_or_default();
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
    has_responsive_hidden_text && !has_persistent_text
}

fn check_custom_table_fieldset_and_form_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    first_role: Option<&str>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(ctx.tag, "main" | "article") {
        let mut headings = Vec::new();
        collect_descendant_headings(ctx.jsx_el, ctx.line_starts, &mut headings);
        for pair in headings.windows(2) {
            if let [(prev_lvl, _, _), (curr_lvl, hloc, hspan)] = *pair
                && curr_lvl > prev_lvl + 1
            {
                push_site(
                    sites,
                    RuleId::NoSkippedHeadingLevel,
                    ctx.subject_name.clone(),
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

    if ctx.tag == "table"
        && !ctx.has_spread
        && !has_a11y_name
        && !ctx
            .jsx_el
            .children
            .iter()
            .any(|c| matches!(c, JSXChild::Element(el) if get_jsx_tag_name(&el.opening_element.name) == "caption"))
    {
        push_site(
            sites,
            RuleId::DataTableRequiresAccessibleName,
            ctx.subject_name.clone(),
            "dataTableRequiresAccessibleName",
            "table",
            "This data table has no caption or accessible name.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "details" {
        let first_el = ctx.jsx_el.children.iter().find_map(|c| match c {
            JSXChild::Element(el) => Some(get_jsx_tag_name(&el.opening_element.name)),
            JSXChild::Text(t) if t.value.trim().is_empty() => None,
            _ => Some(String::new()),
        });
        if first_el.as_deref() != Some("summary") {
            push_site(
                sites,
                RuleId::DetailsRequiresSummary,
                ctx.subject_name.clone(),
                "detailsRequiresSummary",
                "details",
                "This details disclosure has no explicit `<summary>` as its first content child."
                    .to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }

    if (ctx.tag == "th" || matches!(first_role, Some("columnheader" | "rowheader")))
        && ctx.is_html
        && !has_accessible_child(ctx.jsx_el)
        && !has_a11y_name
    {
        push_site(
            sites,
            RuleId::EmptyTableHeader,
            ctx.subject_name.clone(),
            "emptyTableHeader",
            ctx.tag,
            "This table header has no accessible text.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    check_fieldset_and_form_control_name_rules(ctx, has_a11y_name, sites);
}

fn check_fieldset_and_form_control_name_rules(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "fieldset" && !ctx.has_spread && !has_a11y_name {
        let mut control_count = 0;
        let mut has_legend = false;
        count_fieldset_controls_and_legend(ctx.jsx_el, &mut control_count, &mut has_legend);
        if control_count >= 2 && !has_legend {
            push_site(
                sites,
                RuleId::FieldsetRequiresLegend,
                ctx.subject_name.clone(),
                "fieldsetRequiresLegend",
                "fieldset",
                "This fieldset groups multiple controls without a `<legend>` or accessible name."
                    .to_string(),
                ctx.loc,
                ctx.span,
            );
        }
    }

    if matches!(ctx.tag, "input" | "select" | "textarea")
        && !ctx.has_spread
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "name").is_none()
        && has_enclosing_tag(ctx.semantic, ctx.node_id, "form")
    {
        push_site(
            sites,
            RuleId::FormControlRequiresName,
            ctx.subject_name.clone(),
            "formControlRequiresName",
            ctx.tag,
            "Form control inside `<form>` is missing a `name` attribute.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "input"
        && !ctx.has_spread
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "type")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("radio"))
        && !find_jsx_attr_ignore_case(&ctx.opening.attributes, "name")
            .is_some_and(has_non_empty_attr_val)
    {
        push_site(
            sites,
            RuleId::RadioInputMissingName,
            ctx.subject_name.clone(),
            "radioInputMissingName",
            "input",
            "Radio input is missing a `name` attribute to group it for keyboard arrow navigation."
                .to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_root_jsx_duplicate_frames_and_ids(
    ctx: &JsxElementA11yCtx<'_, '_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(
        ctx.semantic.nodes().parent_kind(ctx.node_id),
        AstKind::JSXElement(_) | AstKind::JSXFragment(_)
    ) {
        return;
    }
    let mut seen_iframe_titles: HashSet<String> = HashSet::new();
    let mut id_counts: HashMap<String, Vec<(SourceLoc, ByteSpan)>> = HashMap::new();
    let mut referenced_ids: HashSet<String> = HashSet::new();
    collect_subtree_frames_and_ids(
        ctx.jsx_el,
        ctx.semantic,
        ctx.const_strings,
        ctx.line_starts,
        &mut seen_iframe_titles,
        &mut id_counts,
        &mut referenced_ids,
        sites,
        ctx.subject_name,
    );
    for (id_val, locs) in id_counts {
        if referenced_ids.contains(&id_val) && locs.len() >= 2 {
            for (dloc, dspan) in locs.into_iter().skip(1) {
                push_site(
                    sites,
                    RuleId::NoDuplicateStaticIdReference,
                    ctx.subject_name.clone(),
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

fn check_ui_library_a11y(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    imported_sources: &HashMap<SymbolId, String>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_spread {
        return;
    }
    check_shadcn_a11y(ctx, has_a11y_name, sites);
    let root_import_src =
        resolve_jsx_root_import_source(ctx.semantic, &ctx.opening.name, imported_sources);
    check_radix_base_ui_and_react_aria_a11y(ctx, has_a11y_name, root_import_src.as_deref(), sites);
}

fn check_shadcn_a11y(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(
        ctx.tag,
        "DialogContent" | "SheetContent" | "AlertDialogContent" | "DrawerContent"
    ) && !has_a11y_name
        && !subtree_has_tag_matching(ctx.jsx_el, |t| {
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
            ctx.subject_name.clone(),
            "shadcnDialogContentRequiresTitle",
            ctx.tag,
            format!("`<{}>` requires a matching Title component or `aria-label`.", ctx.tag),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "FormItem"
        && subtree_has_tag_matching(ctx.jsx_el, |t| t == "FormControl")
        && !subtree_has_tag_matching(ctx.jsx_el, |t| matches!(t, "FormLabel" | "Label" | "label"))
        && !subtree_has_attr(ctx.jsx_el, "aria-label")
        && !subtree_has_attr(ctx.jsx_el, "aria-labelledby")
    {
        push_site(
            sites,
            RuleId::ShadcnFormItemRequiresLabel,
            ctx.subject_name.clone(),
            "shadcnFormItemRequiresLabel",
            "FormItem",
            "`<FormItem>` with `<FormControl>` requires a `<FormLabel>` or `aria-label`."
                .to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "Button"
        && find_jsx_attr_ignore_case(&ctx.opening.attributes, "size")
            .and_then(|a| get_attr_static_str(ctx.semantic, a, ctx.const_strings))
            .is_some_and(|s| s.starts_with("icon"))
        && !has_a11y_name
        && !has_accessible_label_text_in_children(&ctx.jsx_el.children)
    {
        push_site(
            sites,
            RuleId::ShadcnIconButtonRequiresLabel,
            ctx.subject_name.clone(),
            "shadcnIconButtonRequiresLabel",
            "Button",
            "Icon-sized `<Button size=\"icon\">` has no accessible name; add `aria-label` or `.sr-only` text.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_radix_base_ui_and_react_aria_a11y(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    root_import_src: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_radix_and_base_ui_dialog_title(ctx, has_a11y_name, root_import_src, sites);
    check_base_ui_field_and_react_aria_dialog(ctx, has_a11y_name, root_import_src, sites);
}

fn check_radix_and_base_ui_dialog_title(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    root_import_src: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_radix_dialog = matches!(ctx.tag, "Dialog.Content" | "AlertDialog.Content")
        || (ctx.tag == "Content" && root_import_src.is_some_and(|s| s.contains("radix-ui")));
    if is_radix_dialog
        && !has_a11y_name
        && !subtree_has_tag_matching(ctx.jsx_el, |t| t == "Title" || t.ends_with(".Title"))
    {
        push_site(
            sites,
            RuleId::RadixDialogContentRequiresTitle,
            ctx.subject_name.clone(),
            "radixDialogContentRequiresTitle",
            ctx.tag,
            "Radix Dialog Content requires a `Dialog.Title` child or `aria-label`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    let is_base_ui_popup = matches!(ctx.tag, "Dialog.Popup" | "AlertDialog.Popup")
        || (ctx.tag == "Popup" && root_import_src.is_some_and(|s| s.contains("base-ui")));
    if is_base_ui_popup
        && !has_a11y_name
        && !subtree_has_tag_matching(ctx.jsx_el, |t| t == "Title" || t.ends_with(".Title"))
    {
        push_site(
            sites,
            RuleId::BaseUiDialogPopupRequiresTitle,
            ctx.subject_name.clone(),
            "baseUiDialogPopupRequiresTitle",
            ctx.tag,
            "Base UI Dialog Popup requires a `Dialog.Title` child or `aria-label`.".to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

fn check_base_ui_field_and_react_aria_dialog(
    ctx: &JsxElementA11yCtx<'_, '_>,
    has_a11y_name: bool,
    root_import_src: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.tag == "Field.Root"
        && subtree_has_tag_matching(ctx.jsx_el, |t| t == "Field.Control")
        && !subtree_has_tag_matching(ctx.jsx_el, |t| {
            matches!(t, "Field.Label" | "FieldLabel" | "Label" | "label")
        })
        && !subtree_has_attr(ctx.jsx_el, "aria-label")
        && !subtree_has_attr(ctx.jsx_el, "aria-labelledby")
    {
        push_site(
            sites,
            RuleId::BaseUiFieldRequiresLabel,
            ctx.subject_name.clone(),
            "baseUiFieldRequiresLabel",
            "Field.Root",
            "Base UI `Field.Root` with `Field.Control` requires a `Field.Label` or `aria-label`."
                .to_string(),
            ctx.loc,
            ctx.span,
        );
    }

    if ctx.tag == "Dialog"
        && root_import_src == Some("react-aria-components")
        && !has_a11y_name
        && !subtree_has_tag_matching(ctx.jsx_el, |t| t == "Heading" || t.ends_with(".Heading"))
    {
        push_site(
            sites,
            RuleId::ReactAriaDialogRequiresHeading,
            ctx.subject_name.clone(),
            "reactAriaDialogRequiresHeading",
            "Dialog",
            "React Aria `<Dialog>` requires a `<Heading slot=\"title\">` child or `aria-label`."
                .to_string(),
            ctx.loc,
            ctx.span,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Walks static JSX subtree collecting iframe titles and duplicate referenced IDs in one pass (#50)"
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
