//! JSX tag, attribute, style, static value, object property, and binding pattern matchers.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JSX and object matcher helpers match only relevant AST node kinds (#50)"
)]

use std::collections::HashMap;

use oxc_ast::ast::{
    BindingPattern, Expression, JSXAttribute, JSXAttributeItem, JSXAttributeName,
    JSXAttributeValue, JSXChild, JSXElement, JSXElementName, JSXMemberExpression,
    JSXMemberExpressionObject, JSXOpeningElement, ObjectExpression, ObjectProperty,
    ObjectPropertyKind, PropertyKey, UnaryOperator,
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::Span;

use super::{resolve_ident_symbol, unparenthesized};

// =============================================================================
// 3. JSX Tag, Attribute, Style & Static Value Inspection
// =============================================================================

/// Formats a [`JSXElementName`] into its full tag string (`"div"`, `"Dialog.Content"`, `"svg:path"`).
#[must_use]
pub(crate) fn jsx_element_tag_name(name: &JSXElementName<'_>) -> String {
    match name {
        JSXElementName::Identifier(id) => id.name.to_string(),
        JSXElementName::IdentifierReference(id) => id.name.to_string(),
        JSXElementName::NamespacedName(ns) => format!("{}:{}", ns.namespace.name, ns.name.name),
        JSXElementName::MemberExpression(mem) => format_jsx_member(mem),
        JSXElementName::ThisExpression(_) => "this".to_string(),
    }
}

/// Alias for [`jsx_element_tag_name`].
#[must_use]
pub(crate) fn get_jsx_tag_name(name: &JSXElementName<'_>) -> String {
    jsx_element_tag_name(name)
}

fn format_jsx_member(mem: &JSXMemberExpression<'_>) -> String {
    let obj = match &mem.object {
        JSXMemberExpressionObject::IdentifierReference(id) => id.name.to_string(),
        JSXMemberExpressionObject::MemberExpression(inner) => format_jsx_member(inner),
        JSXMemberExpressionObject::ThisExpression(_) => "this".to_string(),
    };
    format!("{obj}.{}", mem.property.name)
}

/// Extracts the leaf tag or property name from a [`JSXOpeningElement`] (`"div"`, `"Canvas"`, `"Provider"`).
#[must_use]
pub(crate) fn jsx_opening_tag_name(opening: &JSXOpeningElement<'_>) -> Option<String> {
    match &opening.name {
        JSXElementName::Identifier(id) => Some(id.name.to_string()),
        JSXElementName::IdentifierReference(id) => Some(id.name.to_string()),
        JSXElementName::MemberExpression(mem) => Some(mem.property.name.to_string()),
        _ => None,
    }
}

/// Finds the first [`JSXAttribute`] matching `target` (supporting `ns:name` namespaced attributes).
#[must_use]
pub(crate) fn find_jsx_attr<'a, 'b>(
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

/// Alias for [`find_jsx_attr`].
#[must_use]
pub(crate) fn find_attr<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b JSXAttribute<'a>> {
    find_jsx_attr(attrs, target)
}

/// Finds the last [`JSXAttribute`] matching `target` (later attributes override earlier ones in JSX).
#[must_use]
pub(crate) fn find_last_jsx_attr<'a, 'b>(
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

/// Alias for [`find_last_jsx_attr`].
#[must_use]
pub(crate) fn find_last_attr<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b JSXAttribute<'a>> {
    find_last_jsx_attr(attrs, target)
}

/// Finds the last [`JSXAttribute`] matching `target` case-insensitively.
#[must_use]
pub(crate) fn find_jsx_attr_ignore_case<'a, 'b>(
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

/// Returns `true` if `attrs` contains an attribute named `target`.
#[must_use]
pub(crate) fn has_jsx_attr(attrs: &[JSXAttributeItem<'_>], target: &str) -> bool {
    find_jsx_attr(attrs, target).is_some()
}

/// Returns `true` if `attrs` contains `target` as a boolean shorthand (`<Comp disabled />`)
/// or with a literal `true` value (`<Comp disabled={true} />`).
#[must_use]
pub(crate) fn has_jsx_truthy_attr(attrs: &[JSXAttributeItem<'_>], target: &str) -> bool {
    let Some(attr) = find_last_jsx_attr(attrs, target) else {
        return false;
    };
    match &attr.value {
        None => true,
        Some(JSXAttributeValue::ExpressionContainer(c)) => matches!(
            c.expression.as_expression().map(unparenthesized),
            Some(Expression::BooleanLiteral(b)) if b.value
        ),
        _ => false,
    }
}

/// Returns `true` if `attrs` contains any `{...spread}` attribute.
#[must_use]
pub(crate) fn jsx_has_spread_attr(attrs: &[JSXAttributeItem<'_>]) -> bool {
    attrs
        .iter()
        .any(|item| matches!(item, JSXAttributeItem::SpreadAttribute(_)))
}

/// Extracts the static string value of a [`JSXAttribute`] (`foo="bar"` or `foo={"bar"}` or ``foo={`bar`}``).
#[must_use]
pub(crate) fn jsx_attr_string_value<'a>(attr: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match attr.value.as_ref()? {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
        JSXAttributeValue::ExpressionContainer(c) => {
            let expr = unparenthesized(c.expression.as_expression()?);
            match expr {
                Expression::StringLiteral(s) => s.value.as_str(),
                Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
                    .quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str())),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Extracts the unwrapped [`Expression`] inside `attr={expr}` for attribute `target`.
#[must_use]
pub(crate) fn jsx_attr_expr<'a, 'b>(
    attrs: &'b [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'b Expression<'a>> {
    let attr = find_last_jsx_attr(attrs, target)?;
    let JSXAttributeValue::ExpressionContainer(container) = attr.value.as_ref()? else {
        return None;
    };
    container.expression.as_expression().map(unparenthesized)
}

/// Evaluates `expr` to a static `String` if it is a string literal, template literal without substitutions,
/// or identifier bound in `const_strings`.
#[must_use]
pub(crate) fn eval_static_str(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    match unparenthesized(expr) {
        Expression::StringLiteral(s) => s.value.as_str().map(str::to_string),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str()))
            .map(str::to_string),
        Expression::Identifier(id) => resolve_ident_symbol(semantic, id)
            .and_then(|sym_id| const_strings.get(&sym_id).cloned()),
        _ => None,
    }
}

/// Evaluates a [`JSXAttribute`]'s value to a static `String` using `const_strings` for identifier lookup.
#[must_use]
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

/// Extracts the static `className` string from `opening`, if present.
#[must_use]
pub(crate) fn get_class_name_str(
    opening: &JSXOpeningElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    let attr = find_jsx_attr(&opening.attributes, "className")?;
    get_attr_static_str(semantic, attr, const_strings)
}

/// Extracts a static string property `prop_name` from an inline JSX `style={{ ... }}` attribute.
#[must_use]
pub(crate) fn get_style_prop_str(
    opening: &JSXOpeningElement<'_>,
    prop_name: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    let style_attr = find_jsx_attr(&opening.attributes, "style")?;
    let JSXAttributeValue::ExpressionContainer(c) = style_attr.value.as_ref()? else {
        return None;
    };
    let Expression::ObjectExpression(obj) = unparenthesized(c.expression.as_expression()?) else {
        return None;
    };
    let prop = get_object_prop(obj, prop_name)?;
    eval_static_str(semantic, &prop.value, const_strings)
}

/// Extracts a numeric property `prop_name` from an inline JSX `style={{ ... }}` attribute.
#[must_use]
pub(crate) fn get_style_prop_number(
    opening: &JSXOpeningElement<'_>,
    prop_name: &str,
) -> Option<f64> {
    let style_attr = find_jsx_attr(&opening.attributes, "style")?;
    let JSXAttributeValue::ExpressionContainer(c) = style_attr.value.as_ref()? else {
        return None;
    };
    let Expression::ObjectExpression(obj) = unparenthesized(c.expression.as_expression()?) else {
        return None;
    };
    get_object_prop_number(obj, prop_name)
}

/// Evaluates a numeric literal or negated numeric literal (`-10`) to `f64`.
#[must_use]
pub(crate) fn eval_numeric_expr(expr: &Expression<'_>) -> Option<f64> {
    match unparenthesized(expr) {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            eval_numeric_expr(&u.argument).map(|v| -v)
        }
        _ => None,
    }
}

/// Returns `true` if any descendant JSX element in `jsx_el` has a tag name satisfying `pred`.
#[must_use]
pub(crate) fn subtree_has_tag_matching<F>(jsx_el: &JSXElement<'_>, pred: F) -> bool
where
    F: Fn(&str) -> bool + Copy,
{
    jsx_children_have_tag_matching(&jsx_el.children, pred)
}

fn jsx_children_have_tag_matching<F>(children: &[JSXChild<'_>], pred: F) -> bool
where
    F: Fn(&str) -> bool + Copy,
{
    for child in children {
        match child {
            JSXChild::Element(el) => {
                let t = jsx_element_tag_name(&el.opening_element.name);
                if pred(&t) || subtree_has_tag_matching(el, pred) {
                    return true;
                }
            }
            JSXChild::Fragment(frag) if jsx_children_have_tag_matching(&frag.children, pred) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

// =============================================================================
// 4. Object Expression Property & Binding Pattern Helpers
// =============================================================================

/// Extracts the static property key name from a [`PropertyKey`] (including `#private` identifiers).
#[must_use]
pub(crate) fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::PrivateIdentifier(priv_id) => {
            (!priv_id.name.is_empty()).then(|| format!("#{}", priv_id.name))
        }
        _ => key
            .static_name()
            .and_then(|n| n.as_str().map(str::to_string))
            .filter(|s| !s.is_empty()),
    }
}

/// Finds the last [`ObjectProperty`] in `obj` with static key `key_name`.
#[must_use]
pub(crate) fn get_object_prop<'a, 'b>(
    obj: &'b ObjectExpression<'a>,
    key_name: &str,
) -> Option<&'b ObjectProperty<'a>> {
    for prop in obj.properties.iter().rev() {
        if let ObjectPropertyKind::ObjectProperty(p) = prop
            && p.key
                .static_name()
                .is_some_and(|n| n.as_str() == Some(key_name))
        {
            return Some(p);
        }
    }
    None
}

/// Extracts a static string value for property `key_name` on `obj`.
#[must_use]
pub(crate) fn get_object_prop_static_str<'a>(
    obj: &'a ObjectExpression<'a>,
    key_name: &str,
) -> Option<&'a str> {
    let prop = get_object_prop(obj, key_name)?;
    match unparenthesized(&prop.value) {
        Expression::StringLiteral(s) => s.value.as_str(),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str())),
        _ => None,
    }
}

/// Extracts a boolean literal value for property `key_name` on `obj`.
#[must_use]
pub(crate) fn get_object_prop_bool(obj: &ObjectExpression<'_>, key_name: &str) -> Option<bool> {
    let prop = get_object_prop(obj, key_name)?;
    if let Expression::BooleanLiteral(b) = unparenthesized(&prop.value) {
        Some(b.value)
    } else {
        None
    }
}

/// Extracts a numeric literal value for property `key_name` on `obj`.
#[must_use]
pub(crate) fn get_object_prop_number(obj: &ObjectExpression<'_>, key_name: &str) -> Option<f64> {
    let prop = get_object_prop(obj, key_name)?;
    eval_numeric_expr(&prop.value)
}

/// Collects all bound identifier names and their spans from a [`BindingPattern`].
pub(crate) fn collect_binding_identifiers(
    pattern: &BindingPattern<'_>,
    out: &mut Vec<(String, Span)>,
) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            if !id.name.is_empty() {
                out.push((id.name.to_string(), id.span));
            }
        }
        BindingPattern::AssignmentPattern(assign) => {
            collect_binding_identifiers(&assign.left, out);
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter().flatten() {
                collect_binding_identifiers(elem, out);
            }
            if let Some(rest) = &arr.rest {
                collect_binding_identifiers(&rest.argument, out);
            }
        }
        BindingPattern::ObjectPattern(obj) => {
            for prop in &obj.properties {
                collect_binding_identifiers(&prop.value, out);
            }
            if let Some(rest) = &obj.rest {
                collect_binding_identifiers(&rest.argument, out);
            }
        }
    }
}

/// Collects all bound identifier names from a [`BindingPattern`].
#[must_use]
pub(crate) fn collect_pattern_bound_names(pat: &BindingPattern<'_>) -> Vec<String> {
    let mut pairs = Vec::new();
    collect_binding_identifiers(pat, &mut pairs);
    pairs.into_iter().map(|(name, _)| name).collect()
}
