//! Single-pass accessibility (`a11y`) rule evaluators and cross-file `anchor-target-exists` verification.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and JSX/AST traversal matches only relevant node kinds"
)]

mod aria_and_roles;
mod custom_and_ui_a11y;
mod forms_media_and_content;
mod keyboard_and_focus;
mod tables;
use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Expression, ImportDeclarationSpecifier, JSXAttribute, JSXAttributeItem, JSXAttributeValue,
        JSXChild, JSXElement, JSXOpeningElement, Program, VariableDeclarationKind,
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
    matchers::{
        eval_numeric_expr, eval_static_str, find_attr, find_jsx_attr_ignore_case, find_last_attr,
        get_attr_static_str, get_jsx_tag_name, get_style_prop_str, make_diag_for_subject,
    },
    rules::{Diagnostic, RuleId, RuleSeverity},
};

use self::{
    aria_and_roles::{check_jsx_attribute_a11y, check_jsx_element_a11y},
    keyboard_and_focus::{check_call_a11y, check_conditional_a11y},
};
pub(crate) use self::tables::VALID_ARIA_PROPERTIES;

struct JsxElementA11yCtx<'a, 'b> {
    is_testlike: bool,
    semantic: &'a Semantic<'b>,
    node_id: NodeId,
    jsx_el: &'a JSXElement<'b>,
    opening: &'a JSXOpeningElement<'b>,
    tag: &'a str,
    is_html: bool,
    has_spread: bool,
    subject_name: &'a Option<String>,
    const_strings: &'a HashMap<SymbolId, String>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &'a [u32],
}

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
pub(super) fn push_site(
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
    let _ = program;
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) if !imp.import_kind.is_type() => {
                record_a11y_import_declaration(imp, imported_sources);
            }
            AstKind::VariableDeclaration(var_decl)
                if var_decl.kind == VariableDeclarationKind::Const =>
            {
                record_a11y_const_declarations(semantic, var_decl, const_strings);
            }
            _ => {}
        }
    }
}

fn record_a11y_import_declaration(
    imp: &oxc_ast::ast::ImportDeclaration<'_>,
    imported_sources: &mut HashMap<SymbolId, String>,
) {
    let src = imp.source.value.as_str().unwrap_or_default().to_string();
    let Some(specs) = &imp.specifiers else {
        return;
    };
    for spec in specs {
        if let Some(sym_id) = import_specifier_symbol_id(spec) {
            imported_sources.insert(sym_id, src.clone());
        }
    }
}

fn import_specifier_symbol_id(spec: &ImportDeclarationSpecifier<'_>) -> Option<SymbolId> {
    match spec {
        ImportDeclarationSpecifier::ImportSpecifier(s) if !s.import_kind.is_type() => {
            s.local.symbol_id.get()
        }
        ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => s.local.symbol_id.get(),
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => s.local.symbol_id.get(),
        _ => None,
    }
}

fn record_a11y_const_declarations(
    semantic: &Semantic<'_>,
    var_decl: &oxc_ast::ast::VariableDeclaration<'_>,
    const_strings: &mut HashMap<SymbolId, String>,
) {
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
            label_html_for_ids.extend(extract_attr_match_keys(
                semantic,
                html_for_attr,
                const_strings,
            ));
        }

        if !is_inside_template_element(semantic, node_id) {
            collect_opening_dom_ids(
                semantic,
                opening,
                const_strings,
                static_dom_ids,
                has_unresolved_id_spread,
            );
        }
    }
}

fn collect_opening_dom_ids(
    semantic: &Semantic<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    const_strings: &HashMap<SymbolId, String>,
    static_dom_ids: &mut Vec<String>,
    has_unresolved_id_spread: &mut bool,
) {
    for attr_item in &opening.attributes {
        let JSXAttributeItem::SpreadAttribute(spread) = attr_item else {
            continue;
        };
        let Expression::ObjectExpression(obj) = spread.argument.without_parentheses() else {
            *has_unresolved_id_spread = true;
            continue;
        };
        for prop in &obj.properties {
            match prop {
                oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p)
                    if p.key.static_name().is_some_and(|n| n.as_str() == Some("id")) =>
                {
                    if let Some(id_val) = eval_static_str(semantic, &p.value, const_strings) {
                        static_dom_ids.push(id_val);
                    }
                }
                oxc_ast::ast::ObjectPropertyKind::SpreadProperty(_) => {
                    *has_unresolved_id_spread = true;
                }
                _ => {}
            }
        }
    }
    if let Some(id_attr) = find_last_attr(&opening.attributes, "id") {
        collect_known_attr_strings(semantic, id_attr, const_strings, static_dom_ids);
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
            out.push(
                make_diag_for_subject(
                    RuleId::AnchorTargetExists,
                    file.path.clone(),
                    jsx.enclosing_subject.clone(),
                    "anchorTargetExists",
                    format!("#{target_id}"),
                    format!(
                        "This fragment link points to \"#{target_id}\", but no matching static id was found in the project."
                    ),
                    jsx.loc,
                    jsx.span,
                )
                .with_severity(severity),
            );
        }
    }
}

// =============================================================================
// Shared A11y Helpers (consumed across `a11y/*` submodules)
// =============================================================================

pub(super) fn parse_attr_number(attr: &JSXAttribute<'_>) -> Option<f64> {
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

pub(super) fn is_attr_undefined(attr: &JSXAttribute<'_>) -> bool {
    if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        && let Some(expr) = c.expression.as_expression()
        && let Expression::Identifier(id) = expr.without_parentheses()
    {
        return id.name == "undefined";
    }
    false
}

pub(super) fn is_attr_null_or_undefined(attr: &JSXAttribute<'_>) -> bool {
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

pub(super) fn is_attr_statically_false(attr: &JSXAttribute<'_>) -> bool {
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

pub(super) fn is_attr_statically_true_or_true_str(attr: &JSXAttribute<'_>) -> bool {
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

pub(super) fn is_attr_dynamic_non_undefined(attr: &JSXAttribute<'_>) -> bool {
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

pub(super) fn has_non_empty_attr_val(attr: &JSXAttribute<'_>) -> bool {
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

pub(super) fn has_nonempty_literal_attr(
    opening: &JSXOpeningElement<'_>,
    name: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_jsx_attr_ignore_case(&opening.attributes, name)
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .is_some_and(|s| !s.trim().is_empty())
}

pub(super) fn is_hidden_from_screen_reader(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    if find_jsx_attr_ignore_case(&opening.attributes, "hidden")
        .is_some_and(|a| !is_attr_statically_false(a))
    {
        return true;
    }
    if find_jsx_attr_ignore_case(&opening.attributes, "aria-hidden")
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

pub(super) fn is_disabled_element(
    opening: &JSXOpeningElement<'_>,
    _semantic: &Semantic<'_>,
    _const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_jsx_attr_ignore_case(&opening.attributes, "disabled")
        .is_some_and(|a| !is_attr_statically_false(a))
        || find_jsx_attr_ignore_case(&opening.attributes, "aria-disabled")
            .is_some_and(is_attr_statically_true_or_true_str)
}

pub(super) fn is_interactive_element(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    match tag {
        "audio" | "button" | "canvas" | "datalist" | "embed" | "menuitem" | "option" | "select"
        | "summary" | "td" | "th" | "tr" | "textarea" | "video" => true,
        "input" => !find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("hidden")),
        "a" | "area" => find_jsx_attr_ignore_case(&opening.attributes, "href").is_some(),
        "img" => find_jsx_attr_ignore_case(&opening.attributes, "useMap").is_some(),
        _ => false,
    }
}

pub(super) fn is_focusable_element(
    tag: &str,
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    include_negative_tabindex: bool,
) -> bool {
    if is_disabled_element(opening, semantic, const_strings) {
        return false;
    }
    if let Some(tab_attr) = find_jsx_attr_ignore_case(&opening.attributes, "tabIndex")
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
        "input" => !find_jsx_attr_ignore_case(&opening.attributes, "type")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|t| t.eq_ignore_ascii_case("hidden")),
        "a" | "area" => find_jsx_attr_ignore_case(&opening.attributes, "href").is_some(),
        "audio" | "video" => find_jsx_attr_ignore_case(&opening.attributes, "controls").is_some(),
        _ => false,
    }
}

pub(super) fn is_content_editable_tabbable(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    find_jsx_attr_ignore_case(&opening.attributes, "contentEditable").is_some_and(|a| {
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

pub(crate) fn has_accessible_child(jsx_el: &JSXElement<'_>) -> bool {
    has_accessible_label_text_in_children(&jsx_el.children)
}

pub(super) fn has_accessible_label_text_in_children(children: &[JSXChild<'_>]) -> bool {
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
                        find_jsx_attr_ignore_case(&el.opening_element.attributes, a)
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

pub(super) fn is_inside_jsx_attribute(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
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

pub(super) fn extract_attr_match_keys(
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::{check_anchor_target_exists, extract_a11y_sites_and_dom_ids};
    use crate::{
        graph::ProjectGraph,
        ir::{parse_file_ir, types::compute_line_starts},
        rules::{RuleId, RuleSeverity},
    };

    fn extract_sites(source: &str) -> (Vec<RuleId>, Vec<String>, bool) {
        let allocator = Allocator::default();
        let source_type = SourceType::tsx();
        let parsed = Parser::new(&allocator, source, source_type).parse();
        let semantic_ret = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program);
        let line_starts = compute_line_starts(source);
        let (sites, dom_ids, has_spread) = extract_a11y_sites_and_dom_ids(
            Path::new("src/App.tsx"),
            &parsed.program,
            &semantic_ret.semantic,
            &line_starts,
        );
        (
            sites.into_iter().map(|s| s.rule).collect(),
            dom_ids,
            has_spread,
        )
    }

    #[test]
    fn extract_a11y_sites_across_aria_keyboard_and_content_submodules() {
        let source = r#"
            export function App() {
                return (
                    <div id="hero" aria-invalid-prop="true" role="unicorn">
                        <img src="/logo.png" />
                        <div onClick={() => {}} tabIndex={2}>Click</div>
                    </div>
                );
            }
        "#;
        let (rules, dom_ids, has_spread) = extract_sites(source);
        assert!(rules.contains(&RuleId::AriaProps));
        assert!(rules.contains(&RuleId::AriaRole));
        assert!(rules.contains(&RuleId::AltText));
        assert!(rules.contains(&RuleId::ClickEventsHaveKeyEvents));
        assert!(rules.contains(&RuleId::TabindexNoPositive));
        assert_eq!(dom_ids, vec!["hero".to_string()]);
        assert!(!has_spread);
    }

    #[test]
    fn check_anchor_target_exists_reports_missing_fragment_target() {
        let file_a = parse_file_ir(
            Path::new("src/Nav.tsx"),
            r##"export function Nav() { return <a href="#pricing">Pricing</a>; }"##,
        );
        let file_b = parse_file_ir(
            Path::new("src/Section.tsx"),
            r#"export function Section() { return <section id="features">Features</section>; }"#,
        );
        let graph = ProjectGraph::build(vec![file_a.clone(), file_b]);
        let mut out = Vec::new();
        check_anchor_target_exists(&graph, &file_a, &|_| Some(RuleSeverity::Warning), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, RuleId::AnchorTargetExists);
        assert_eq!(out[0].target_name, "#pricing");
    }
}
