//! JSX prop, attribute, fragment, PascalCase, max-depth, and `ProjectGraph`-gated
//! inline-prop detectors for `react-builtins`.

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, Expression, JSXAttributeItem, JSXAttributeValue, JSXElement,
        JSXOpeningElement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{
    UNKNOWN_DOM_PROP_FIXES,
    components_and_classes::{
        check_jsx_fragments_and_useless_fragment_element, check_jsx_no_useless_fragment_short,
        check_jsx_pascal_case_and_max_depth,
    },
    strip_ts_and_parens,
};
use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr, SemanticRuleSite,
        react_ast::{classify_jsx_element_name, find_enclosing_react_node, get_subject_name},
    },
    matchers::{
        push_semantic_site, push_semantic_site_with_fix, push_simple_diagnostic,
        resolve_ident_symbol,
    },
    rules::types::{AutofixPatch, Diagnostic, RuleId, RuleSeverity},
};

pub(super) fn check_jsx_builtin_rules_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            if let AstKind::JSXFragment(jsx_frag) = node.kind() {
                let subj_name = find_enclosing_react_node(semantic, node_id)
                    .and_then(|subj_id| get_subject_name(semantic, subj_id));
                check_jsx_no_useless_fragment_short(
                    node_id,
                    jsx_frag,
                    &subj_name,
                    semantic,
                    line_starts,
                    sites,
                );
            }
            continue;
        };
        let opening = &jsx_el.opening_element;
        let (tag_name, _, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        // 1. `button-has-type` (including `const ButtonTag = "button" as const`)
        if is_button_element(semantic, &tag_name, &opening.name) {
            check_button_has_type(semantic, node_id, opening, &subj_name, line_starts, sites);
        }

        // 2. `checked-requires-onchange-or-readonly`
        if tag_name == "input" {
            check_checked_requires_onchange(opening, &subj_name, line_starts, sites);
        }

        // 3. `jsx-no-target-blank` (with Autofix)
        if tag_name == "a" {
            check_jsx_no_target_blank(opening, &subj_name, line_starts, sites);
        }

        // 4. `self-closing-comp` (with Autofix)
        if is_comp && jsx_el.closing_element.is_some() && jsx_el.children.is_empty() {
            check_self_closing_comp(jsx_el, &tag_name, &subj_name, line_starts, sites);
        }

        // 5. Attribute-level built-in checks (`jsx-no-script-url`, `style-prop-object`, `no-unknown-property`, `no-string-refs`, `jsx-boolean-value`, `jsx-curly-brace-presence`)
        check_jsx_attributes_builtin(
            semantic,
            opening,
            &tag_name,
            is_comp,
            &subj_name,
            line_starts,
            sites,
        );
        check_jsx_fragments_and_useless_fragment_element(
            node_id,
            jsx_el,
            &tag_name,
            &subj_name,
            semantic,
            line_starts,
            sites,
        );
        check_jsx_pascal_case_and_max_depth(
            semantic,
            node_id,
            opening,
            &tag_name,
            is_comp,
            &subj_name,
            line_starts,
            sites,
        );
    }
}

fn is_button_element(
    semantic: &Semantic<'_>,
    tag_name: &str,
    opening_name: &oxc_ast::ast::JSXElementName<'_>,
) -> bool {
    if tag_name == "button" {
        return true;
    }
    if let oxc_ast::ast::JSXElementName::IdentifierReference(ident) = opening_name
        && let Some(sym_id) = resolve_ident_symbol(semantic, ident)
    {
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
            && let Some(init) = &decl.init
            && let Expression::StringLiteral(s) = strip_ts_and_parens(init)
        {
            return s.value == "button";
        }
    }
    false
}

fn check_button_has_type(
    semantic: &Semantic<'_>,
    jsx_node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut type_attr = None;
    let mut has_spread = false;
    let mut has_nonempty_form_attr = false;

    for item in &opening.attributes {
        match item {
            JSXAttributeItem::SpreadAttribute(_) => {
                has_spread = true;
            }
            JSXAttributeItem::Attribute(attr) => {
                let Some(ident) = attr.name.as_identifier() else {
                    continue;
                };
                if ident.name.eq_ignore_ascii_case("type") {
                    type_attr = Some(attr);
                } else if ident.name == "form"
                    && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                    && s.value.as_str().is_some_and(|v| !v.trim().is_empty())
                {
                    has_nonempty_form_attr = true;
                }
            }
        }
    }

    let Some(attr) = type_attr else {
        // Missing `type`: only flag when inside an intrinsic `<form>` ancestor or associated via `form="id"`, and no spread
        if has_spread
            || (!has_nonempty_form_attr && !has_intrinsic_form_ancestor(semantic, jsx_node_id))
        {
            return;
        }
        let insert_pos = opening.name.span().end;
        let patch = AutofixPatch::insert(
            "Add `type=\"button\"` to `<button>`",
            insert_pos,
            " type=\"button\"",
        );
        push_semantic_site_with_fix(
            sites,
            RuleId::ButtonHasType,
            subj_name.clone(),
            "buttonHasTypeMissing",
            "button",
            "Your users can submit the form by accident because a `<button>` with no `type` defaults to submit.".to_string(),
            line_starts,
            opening.span,
            Some(patch),
        );
        return;
    };

    // Validate explicit `type` attribute value
    let is_valid = match &attr.value {
        None => false,
        Some(JSXAttributeValue::StringLiteral(s)) => {
            matches!(s.value.as_str(), Some("button" | "submit" | "reset"))
        }
        Some(JSXAttributeValue::ExpressionContainer(container)) => container
            .expression
            .as_expression()
            .is_some_and(|expr| is_valid_button_type_expr(semantic, expr)),
        _ => false,
    };

    if !is_valid {
        push_semantic_site(
            sites,
            RuleId::ButtonHasType,
            subj_name.clone(),
            "buttonHasTypeInvalid",
            "button",
            "This button has an invalid `type`, so the browser may treat it like a submit button."
                .to_string(),
            line_starts,
            opening.span,
        );
    }
}

fn has_intrinsic_form_ancestor(semantic: &Semantic<'_>, jsx_node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(jsx_node_id) {
        if let AstKind::JSXElement(parent_jsx) = semantic.nodes().kind(anc_id) {
            let (parent_name, _, _, _) =
                classify_jsx_element_name(semantic, &parent_jsx.opening_element.name);
            if parent_name == "form" {
                return true;
            }
        }
    }
    false
}

fn is_valid_button_type_expr(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    let stripped = strip_ts_and_parens(expr);
    match stripped {
        Expression::StringLiteral(s) => {
            matches!(s.value.as_str(), Some("button" | "submit" | "reset"))
        }
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
            .quasis
            .first()
            .is_some_and(|q| matches!(q.value.raw.as_str(), "button" | "submit" | "reset")),
        Expression::ConditionalExpression(cond) => {
            is_valid_button_type_expr(semantic, &cond.consequent)
                && is_valid_button_type_expr(semantic, &cond.alternate)
        }
        Expression::LogicalExpression(log) => {
            is_valid_button_type_expr(semantic, &log.left)
                && is_valid_button_type_expr(semantic, &log.right)
        }
        Expression::StaticMemberExpression(mem) => mem.property.name == "type",
        Expression::Identifier(ident) => {
            if ident.name == "type" {
                return true;
            }
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::VariableDeclarator(decl) => {
                    let parent_id = semantic.nodes().parent_id(decl_id);
                    let is_const = matches!(
                        semantic.nodes().kind(parent_id),
                        AstKind::VariableDeclaration(vd) if vd.kind == VariableDeclarationKind::Const
                    );
                    if !is_const {
                        return false;
                    }
                    if let Some(init) = &decl.init {
                        is_valid_button_type_expr(semantic, init)
                    } else {
                        false
                    }
                }
                AstKind::FormalParameter(param) => {
                    is_valid_button_type_param_binding(semantic, param, ident.name.as_str())
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_valid_button_type_param_binding(
    semantic: &Semantic<'_>,
    param: &oxc_ast::ast::FormalParameter<'_>,
    local_name: &str,
) -> bool {
    let BindingPattern::ObjectPattern(obj_pat) = &param.pattern else {
        return false;
    };
    for prop in &obj_pat.properties {
        let key_name = prop.key.static_name();
        match &prop.value {
            BindingPattern::BindingIdentifier(b) if b.name.as_str() == local_name => {
                return key_name.as_ref().and_then(|n| n.as_str()) == Some("type");
            }
            BindingPattern::AssignmentPattern(assign)
                if assign
                    .left
                    .get_binding_identifier()
                    .is_some_and(|b| b.name.as_str() == local_name) =>
            {
                if key_name.as_ref().and_then(|n| n.as_str()) == Some("type") {
                    return true;
                }
                if local_name.ends_with("Type") {
                    return is_valid_button_type_expr(semantic, &assign.right);
                }
            }
            _ => {}
        }
    }
    false
}

fn check_checked_requires_onchange(
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut checked_attr = None;
    let mut checked_forwarded = false;
    let mut default_checked_attr = None;
    let mut default_checked_forwarded = false;
    let mut has_onchange_or_readonly = false;
    let mut has_spread = false;
    let mut has_truthy_disabled = false;

    for item in &opening.attributes {
        match item {
            JSXAttributeItem::SpreadAttribute(_) => {
                has_spread = true;
            }
            JSXAttributeItem::Attribute(attr) => {
                let Some(ident) = attr.name.as_identifier() else {
                    continue;
                };
                match ident.name.as_str() {
                    "checked" => {
                        checked_attr = Some(attr);
                        checked_forwarded = is_forwarded_jsx_attr_value(attr);
                    }
                    "defaultChecked" => {
                        default_checked_attr = Some(attr);
                        default_checked_forwarded = is_forwarded_jsx_attr_value(attr);
                    }
                    "onChange" | "readOnly" => {
                        has_onchange_or_readonly = true;
                    }
                    "disabled" => {
                        has_truthy_disabled = match &attr.value {
                            None => true,
                            Some(JSXAttributeValue::ExpressionContainer(c)) => matches!(
                                c.expression.as_expression().map(Expression::without_parentheses),
                                Some(Expression::BooleanLiteral(b)) if b.value
                            ),
                            _ => false,
                        };
                    }
                    _ => {}
                }
            }
        }
    }

    let Some(checked) = checked_attr else {
        return;
    };

    if default_checked_attr.is_some() && !(checked_forwarded && default_checked_forwarded) {
        push_semantic_site(
            sites,
            RuleId::CheckedRequiresOnchangeOrReadonly,
            subj_name.clone(),
            "exclusiveCheckedAttribute",
            "checked",
            "This input mixes `checked` with `defaultChecked`, so React can't tell whether it is controlled or uncontrolled.".to_string(),
            line_starts,
            checked.span,
        );
    }

    if !has_onchange_or_readonly && !has_spread && !has_truthy_disabled {
        push_semantic_site(
            sites,
            RuleId::CheckedRequiresOnchangeOrReadonly,
            subj_name.clone(),
            "checkedRequiresOnchangeOrReadonly",
            "checked",
            "Your users can't toggle this input because `checked` has no `onChange` or `readOnly`."
                .to_string(),
            line_starts,
            checked.span,
        );
    }
}

fn is_forwarded_jsx_attr_value(attr: &oxc_ast::ast::JSXAttribute<'_>) -> bool {
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return false;
    };
    let Some(expr) = c.expression.as_expression() else {
        return false;
    };
    matches!(
        expr.without_parentheses(),
        Expression::Identifier(_) | Expression::StaticMemberExpression(_)
    )
}

fn check_jsx_no_target_blank(
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut is_target_blank = false;
    let mut has_noopener = false;

    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let Some(ident) = attr.name.as_identifier() else {
            continue;
        };
        if ident.name == "target"
            && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
            && s.value
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case("_blank"))
        {
            is_target_blank = true;
        } else if ident.name == "rel"
            && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
            && s.value.as_str().is_some_and(|v| v.contains("noopener"))
        {
            has_noopener = true;
        }
    }

    if is_target_blank && !has_noopener {
        let insert_pos = opening.name.span().end;
        let patch = AutofixPatch::insert(
            "Add `rel=\"noopener noreferrer\"` to `<a target=\"_blank\">`",
            insert_pos,
            " rel=\"noopener noreferrer\"",
        );
        push_semantic_site_with_fix(
            sites,
            RuleId::JsxNoTargetBlank,
            subj_name.clone(),
            "jsxNoTargetBlank",
            "a",
            "Using `target=\"_blank\"` without `rel=\"noopener noreferrer\"` exposes the page to reverse tabnabbing.".to_string(),
            line_starts,
            opening.span,
            Some(patch),
        );
    }
}

fn check_self_closing_comp(
    jsx_el: &JSXElement<'_>,
    tag_name: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let replace_start = opening.span.end.saturating_sub(1);
    let patch = AutofixPatch::replace(
        format!("Convert `<{tag_name}></{tag_name}>` to `<{tag_name} />`"),
        ByteSpan {
            start: replace_start,
            end: jsx_el.span.end,
        },
        " />",
    );
    push_semantic_site_with_fix(
        sites,
        RuleId::SelfClosingComp,
        subj_name.clone(),
        "selfClosingComp",
        tag_name,
        format!(
            "Empty `<{tag_name}></{tag_name}>` component should be self-closing (`<{tag_name} />`)."
        ),
        line_starts,
        jsx_el.span,
        Some(patch),
    );
}

fn check_jsx_attributes_builtin(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            if let JSXAttributeItem::SpreadAttribute(spread) = item {
                push_semantic_site(
                    sites,
                    RuleId::JsxPropsNoSpreading,
                    subj_name.clone(),
                    "jsxPropsNoSpreading",
                    tag_name,
                    format!(
                        "Avoid spreading arbitrary props (`{{...}}`) onto `<{tag_name}>`; pass explicit props instead."
                    ),
                    line_starts,
                    spread.span,
                );
            }
            continue;
        };
        check_single_jsx_attribute_builtin(
            semantic,
            attr,
            tag_name,
            is_comp,
            subj_name,
            line_starts,
            sites,
        );
    }
}

fn check_single_jsx_attribute_builtin(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(ident) = attr.name.as_identifier() else {
        return;
    };
    let attr_name = ident.name.as_str();

    if !is_comp
        && !tag_name.contains('-')
        && let Some(&(_, standard_name)) = UNKNOWN_DOM_PROP_FIXES
            .iter()
            .find(|&&(bad, _)| bad == attr_name)
    {
        let patch = AutofixPatch::replace(
            format!("Replace `{attr_name}` with `{standard_name}`"),
            ByteSpan {
                start: ident.span.start,
                end: ident.span.end,
            },
            standard_name,
        );
        push_semantic_site_with_fix(
            sites,
            RuleId::NoUnknownProperty,
            subj_name.clone(),
            "noUnknownProperty",
            attr_name,
            format!(
                "Unknown DOM property `{attr_name}` on `<{tag_name}>`; did you mean `{standard_name}`?"
            ),
            line_starts,
            attr.span,
            Some(patch),
        );
    }

    if attr_name == "ref" && matches!(attr.value, Some(JSXAttributeValue::StringLiteral(_))) {
        push_semantic_site(
            sites,
            RuleId::NoStringRefs,
            subj_name.clone(),
            "noStringRefs",
            "ref",
            "String refs (`ref=\"...\"`) are deprecated; use `useRef()` or a callback ref instead."
                .to_string(),
            line_starts,
            attr.span,
        );
    }

    if attr_name == "style" && matches!(attr.value, Some(JSXAttributeValue::StringLiteral(_))) {
        push_semantic_site(
            sites,
            RuleId::StylePropObject,
            subj_name.clone(),
            "stylePropObject",
            "style",
            "The `style` prop expects a mapping from style properties to values, not a string."
                .to_string(),
            line_starts,
            attr.span,
        );
    }

    if matches!(attr_name, "href" | "src")
        && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
        && s.value.as_str().is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with("javascript:")
        })
    {
        push_semantic_site(
            sites,
            RuleId::JsxNoScriptUrl,
            subj_name.clone(),
            "jsxNoScriptUrl",
            attr_name,
            "`javascript:` URLs are a security and XSS hazard; use a `<button>` or a real URL."
                .to_string(),
            line_starts,
            attr.span,
        );
    }

    if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value {
        check_jsx_attribute_expression_builtin(
            semantic,
            attr,
            attr_name,
            c,
            subj_name,
            line_starts,
            sites,
        );
    }
}

fn check_jsx_attribute_expression_builtin(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    attr_name: &str,
    container: &oxc_ast::ast::JSXExpressionContainer<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(expr) = container
        .expression
        .as_expression()
        .map(Expression::without_parentheses)
    else {
        return;
    };
    if let Expression::BooleanLiteral(b) = expr
        && b.value
    {
        let patch = AutofixPatch::replace(
            format!("Simplify `{attr_name}={{true}}` to `{attr_name}`"),
            ByteSpan {
                start: attr.span.start,
                end: attr.span.end,
            },
            attr_name,
        );
        push_semantic_site_with_fix(
            sites,
            RuleId::JsxBooleanValue,
            subj_name.clone(),
            "jsxBooleanValue",
            attr_name,
            format!("Omit `={{true}}` on boolean JSX attribute `{attr_name}`."),
            line_starts,
            attr.span,
            Some(patch),
        );
    } else if let Expression::StringLiteral(s) = expr
        && !s.value.contains('"')
    {
        let s_text = s.span.source_text(semantic.source_text());
        let patch = AutofixPatch::replace(
            format!("Remove unnecessary curly braces around {s_text}"),
            ByteSpan {
                start: container.span.start,
                end: container.span.end,
            },
            s_text,
        );
        push_semantic_site_with_fix(
            sites,
            RuleId::JsxCurlyBracePresence,
            subj_name.clone(),
            "jsxCurlyBracePresence",
            attr_name,
            format!("Curly braces are unnecessary around string literal prop `{attr_name}`."),
            line_starts,
            attr.span,
            Some(patch),
        );
    }
}

/// Evaluates `jsx-no-new-object-as-prop`, `jsx-no-new-array-as-prop`,
/// `jsx-no-new-function-as-prop`, and `no-inline-prop-on-memo-component`
/// using [`ProjectGraph`] to suppress cold-path noise when the resolved target child
/// **Subject** is not memoized, not rendered inside a list/loop, and does not feed the prop
/// into a hook dependency list.
pub(crate) fn evaluate_inline_prop_rules_with_graph<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    jsx: &JsxElementIr,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if !jsx.is_component {
        return;
    }
    if jsx.name.ends_with(".Provider")
        && is_active(RuleId::ContextProviderValueFromUnmemoizedLocalLiteral).is_some()
    {
        return;
    }

    let resolved_target = graph
        .resolve_target_subject(&file.path, jsx.span, &jsx.name)
        .map(|(_, subj)| subj);
    if resolved_target.is_some_and(|subj| subj.has_custom_memo_comparator) {
        return;
    }

    let hot_check = |prop_name: &str| is_hot_path_for_inline_prop(resolved_target, jsx, prop_name);

    if is_active(RuleId::JsxNoNewObjectAsProp).is_some() {
        emit_hot_path_inline_prop_diags(
            out,
            file,
            jsx,
            &jsx.object_literal_props,
            &hot_check,
            RuleId::JsxNoNewObjectAsProp,
            "jsxNoNewObjectAsProp",
            "object literal",
        );
    }
    if is_active(RuleId::JsxNoNewArrayAsProp).is_some() {
        emit_hot_path_inline_prop_diags(
            out,
            file,
            jsx,
            &jsx.array_literal_props,
            &hot_check,
            RuleId::JsxNoNewArrayAsProp,
            "jsxNoNewArrayAsProp",
            "array allocation",
        );
    }
    if is_active(RuleId::JsxNoNewFunctionAsProp).is_some() {
        emit_hot_path_inline_prop_diags(
            out,
            file,
            jsx,
            &jsx.function_props,
            &hot_check,
            RuleId::JsxNoNewFunctionAsProp,
            "jsxNoNewFunctionAsProp",
            "function",
        );
    }
    if resolved_target.is_some_and(|subj| subj.is_memoized)
        && is_active(RuleId::NoInlinePropOnMemoComponent).is_some()
    {
        emit_memo_inline_prop_diags(out, file, jsx);
    }
}

fn is_hot_path_for_inline_prop(
    resolved_target: Option<&crate::ir::SubjectIr>,
    jsx: &JsxElementIr,
    prop_name: &str,
) -> bool {
    let Some(target_subj) = resolved_target else {
        return true;
    };
    target_subj.is_memoized
        || jsx.in_array_map
        || target_subj
            .props_in_hook_deps
            .iter()
            .any(|p| p == prop_name)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Shared emitter for hot-path inline object, array, and function prop diagnostics (#50)"
)]
fn emit_hot_path_inline_prop_diags<H>(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    jsx: &JsxElementIr,
    props: &[String],
    is_hot_path: &H,
    rule: RuleId,
    message_id: &'static str,
    alloc_noun: &str,
) where
    H: Fn(&str) -> bool,
{
    for prop_name in props {
        if is_hot_path(prop_name) {
            push_inline_prop_diag(
                out,
                file,
                jsx,
                rule,
                message_id,
                prop_name,
                format!(
                    "Prop `{prop_name}` on `<{}>` receives a fresh {alloc_noun} on every render.",
                    jsx.name
                ),
            );
        }
    }
}

fn emit_memo_inline_prop_diags(out: &mut Vec<Diagnostic>, file: &FileIr, jsx: &JsxElementIr) {
    for (prop_name, kind_label) in jsx
        .object_literal_props
        .iter()
        .map(|p| (p, "objects"))
        .chain(jsx.array_literal_props.iter().map(|p| (p, "Arrays")))
        .chain(jsx.function_props.iter().map(|p| (p, "functions")))
        .chain(jsx.inline_jsx_props.iter().map(|p| (p, "JSX")))
    {
        push_inline_prop_diag(
            out,
            file,
            jsx,
            RuleId::NoInlinePropOnMemoComponent,
            "noInlinePropOnMemoComponent",
            prop_name,
            format!(
                "This redraws {} on every render because prop `{prop_name}` is {kind_label} built inline, defeating `memo()`. Move it to `useMemo`, `useCallback`, or module scope.",
                jsx.name
            ),
        );
    }
}

fn push_inline_prop_diag(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    jsx: &JsxElementIr,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: String,
) {
    push_simple_diagnostic(
        out,
        file,
        jsx.enclosing_subject.clone(),
        rule,
        message_id,
        target_name,
        message,
        jsx.loc,
        jsx.span,
    );
}

