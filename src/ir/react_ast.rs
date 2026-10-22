//! React-specific AST and semantic predicates (`useState`, `useEffect`, `useRef`, props, HOCs, and JSX classification).

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, BindingPattern, CallExpression, Expression, JSXAttributeItem,
        JSXAttributeValue, JSXChild, JSXElementName, JSXExpression, Program, Statement,
    },
};
use oxc_semantic::{NodeId, ReferenceId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

use std::collections::{HashMap, HashSet};

use super::types::{ByteSpan, CallerSite, JsxElementIr, JsxSubtreeIr, loc_from_line_starts};

const PURE_HOCS: &[&str] = &["memo", "forwardRef"];

/// Reference index entry for fast span-based lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RefEntry {
    pub node_id: NodeId,
    pub ref_id: ReferenceId,
    pub span: Span,
}

/// Checks if a callee expression invokes a specific React hook (`useState`, `useEffect`, `useRef`),
/// supporting direct calls, `React.<hook>`, and renamed imports (`import { useState as s } from 'react'`).
pub(crate) fn is_react_hook_callee(
    semantic: &Semantic<'_>,
    callee: &Expression<'_>,
    hook_name: &str,
) -> bool {
    match callee.without_parentheses() {
        Expression::Identifier(ident) => {
            if ident.name == hook_name {
                return true;
            }
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            is_imported_react_hook_symbol(semantic, sym_id, hook_name)
        }
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == hook_name
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "React"
                )
        }
        _ => false,
    }
}

fn is_imported_react_hook_symbol(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    hook_name: &str,
) -> bool {
    if !semantic
        .scoping()
        .symbol_flags(sym_id)
        .contains(SymbolFlags::Import)
    {
        return false;
    }
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::ImportSpecifier(spec) = semantic.nodes().kind(decl_id) {
        return spec.imported.name() == hook_name;
    }
    false
}

/// Checks if `node_id` (an identifier or call callee) refers to `hook_name` (`useState`, `useRef`).
pub(crate) fn is_react_hook_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    hook_name: &str,
) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::IdentifierReference(ident) => {
            if ident.name == hook_name {
                return true;
            }
            if let Some(ref_id) = ident.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
                && is_imported_react_hook_symbol(semantic, sym_id, hook_name)
            {
                return true;
            }
            if let AstKind::StaticMemberExpression(mem) = semantic.nodes().parent_kind(node_id) {
                return mem.property.name == hook_name
                    && matches!(
                        mem.object.without_parentheses(),
                        Expression::Identifier(obj) if obj.name == "React"
                    );
            }
            false
        }
        AstKind::CallExpression(call) => is_react_hook_callee(semantic, &call.callee, hook_name),
        _ => false,
    }
}

/// Checks if `node_id` (an identifier or call callee) refers to `useState`.
pub(crate) fn is_use_state_node(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    is_react_hook_node(semantic, node_id, "useState")
}

/// Checks if `node_id` refers to `useRef`.
pub(crate) fn is_use_ref_node(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    is_react_hook_node(semantic, node_id, "useRef")
}

/// Checks if `call` is a `useEffect(...)` call (intentionally excluding `useLayoutEffect`).
pub(crate) fn is_use_effect_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    is_react_hook_callee(semantic, &call.callee, "useEffect")
}

/// Extracts the short identifier or static member property name of a `CallExpression` callee.
pub(crate) fn extract_callee_short_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

/// Checks if `program` contains a static `import` declaration from any module in `allowed_sources`.
pub(crate) fn has_import_from(program: &Program<'_>, allowed_sources: &[&str]) -> bool {
    for stmt in &program.body {
        if let Statement::ImportDeclaration(imp) = stmt
            && let Some(src) = imp.source.value.as_str()
            && allowed_sources.contains(&src)
        {
            return true;
        }
    }
    false
}

/// Checks if `node_id` is nested inside a `useEffect(...)` call.
pub(crate) fn is_inside_use_effect(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && is_use_effect_call(semantic, call)
        {
            return true;
        }
    }
    false
}

/// Checks if `node_id` executes directly in the render body of an enclosing **Subject**
/// (not inside a nested callback, effect, or event handler function).
pub(crate) fn is_direct_render_phase_node(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            if find_enclosing_react_node(semantic, anc_id) == Some(anc_id) {
                return true;
            }
            let p_id = semantic.nodes().parent_id(anc_id);
            if find_enclosing_react_node(semantic, p_id) == Some(p_id) {
                return true;
            }
            return false;
        }
    }
    false
}

/// Checks if `name` is a valid uppercase React component identifier (`MyComponent`).
pub(crate) fn is_component_name(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
}

/// Checks if `name` is a valid custom hook identifier (`useCustomHook`).
pub(crate) fn is_custom_hook_name(name: &str) -> bool {
    name.starts_with("use") && name.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase)
}

/// Checks if `node_id` declares a functional React component.
pub(crate) fn is_functional_component(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(func) if func.is_declaration() => func
            .id
            .as_ref()
            .is_some_and(|id| is_component_name(&id.name)),
        AstKind::VariableDeclarator(decl) => {
            let BindingPattern::BindingIdentifier(id) = &decl.id else {
                return false;
            };
            if !is_component_name(&id.name) {
                return false;
            }
            matches!(
                decl.init.as_ref().map(Expression::without_parentheses),
                Some(
                    Expression::ArrowFunctionExpression(_)
                        | Expression::FunctionExpression(_)
                        | Expression::CallExpression(_)
                )
            )
        }
        _ => false,
    }
}

/// Checks if `node_id` declares a React custom hook.
pub(crate) fn is_custom_hook(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(func) if func.is_declaration() => func
            .id
            .as_ref()
            .is_some_and(|id| is_custom_hook_name(&id.name)),
        AstKind::VariableDeclarator(decl) => {
            let BindingPattern::BindingIdentifier(id) = &decl.id else {
                return false;
            };
            if !is_custom_hook_name(&id.name) {
                return false;
            }
            matches!(
                decl.init.as_ref().map(Expression::without_parentheses),
                Some(Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_))
            )
        }
        _ => false,
    }
}

/// Checks if a functional component node is wrapped by a non-pure HOC (`withRouter`, `observer`).
pub(crate) fn is_functional_hoc(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    if !is_functional_component(semantic, node_id) {
        return false;
    }
    if is_wrapped_inline_hoc(semantic, node_id) {
        return true;
    }
    is_wrapped_separately_hoc(semantic, node_id)
}

fn is_pure_hoc_callee(callee: &Expression<'_>) -> bool {
    match callee.without_parentheses() {
        Expression::Identifier(id) => PURE_HOCS.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            PURE_HOCS.contains(&mem.property.name.as_str())
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "React"
                )
        }
        _ => false,
    }
}

fn is_wrapped_inline_hoc(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(node_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    !is_pure_hoc_callee(&call.callee) && call_wraps_function(call)
}

fn call_wraps_function(call: &CallExpression<'_>) -> bool {
    let Some(first_arg) = call.arguments.first().and_then(|arg| arg.as_expression()) else {
        return false;
    };
    match first_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
        Expression::CallExpression(inner_call) => call_wraps_function(inner_call),
        _ => false,
    }
}

fn is_wrapped_separately_hoc(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let sym_id = match semantic.nodes().kind(node_id) {
        AstKind::Function(func) => func.id.as_ref().and_then(|id| id.symbol_id.get()),
        AstKind::VariableDeclarator(decl) => match &decl.id {
            BindingPattern::BindingIdentifier(id) => id.symbol_id.get(),
            _ => None,
        },
        _ => None,
    };
    let Some(sym_id) = sym_id else {
        return false;
    };
    for reference in semantic.scoping().get_resolved_references(sym_id) {
        let ref_node = semantic.nodes().get_node(reference.node_id());
        if let AstKind::CallExpression(call) = semantic.nodes().parent_kind(reference.node_id())
            && !call.callee.span().contains_inclusive(ref_node.span())
            && !is_pure_hoc_callee(&call.callee)
        {
            return true;
        }
    }
    false
}

/// Finds the enclosing React component or custom hook node for `node_id`.
pub(crate) fn find_enclosing_react_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<NodeId> {
    std::iter::once(node_id)
        .chain(semantic.nodes().ancestor_ids(node_id))
        .find(|&anc_id| {
            is_functional_component(semantic, anc_id) || is_custom_hook(semantic, anc_id)
        })
}

/// Extracts the identifier name of a component or custom hook node.
pub(crate) fn get_subject_name(semantic: &Semantic<'_>, subject_node_id: NodeId) -> Option<String> {
    match semantic.nodes().kind(subject_node_id) {
        AstKind::Function(func) => func.id.as_ref().map(|id| id.name.to_string()),
        AstKind::VariableDeclarator(decl) => match &decl.id {
            BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Returns the top-level statements inside a **Subject** or function node (`Function` or `VariableDeclarator`).
pub(crate) fn get_subject_body_statements<'a>(
    semantic: &'a Semantic<'a>,
    subject_node_id: NodeId,
) -> Option<&'a [Statement<'a>]> {
    match semantic.nodes().kind(subject_node_id) {
        AstKind::Function(func) => func.body.as_ref().map(|b| b.statements.as_slice()),
        AstKind::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(b) => Some(b.statements.as_slice()),
            _ => None,
        },
        AstKind::VariableDeclarator(decl) => {
            match decl.init.as_ref().map(Expression::without_parentheses) {
                Some(Expression::ArrowFunctionExpression(arrow)) => match &arrow.body {
                    ArrowFunctionBody::FunctionBody(b) => Some(b.statements.as_slice()),
                    _ => None,
                },
                Some(Expression::FunctionExpression(func)) => {
                    func.body.as_ref().map(|b| b.statements.as_slice())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolves the effect callback AST node (`ArrowFunctionExpression` or `Function`) for a `useEffect` call.
pub(crate) fn get_effect_fn_node(semantic: &Semantic<'_>, call_node_id: NodeId) -> Option<NodeId> {
    let AstKind::CallExpression(call) = semantic.nodes().kind(call_node_id) else {
        return None;
    };
    let first_arg = call
        .arguments
        .first()?
        .as_expression()?
        .without_parentheses();
    match first_arg {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            find_node_by_span(semantic, call_node_id, first_arg.span())
        }
        Expression::Identifier(ident) => {
            let ref_id = ident.reference_id.get()?;
            let sym_id = semantic.scoping().get_reference(ref_id).symbol_id()?;
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(_) => Some(decl_id),
                AstKind::VariableDeclarator(decl) => {
                    let init = decl.init.as_ref()?.without_parentheses();
                    find_node_by_span(semantic, decl_id, init.span())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Returns the cleanup expression span if the effect function has a `return <expr>;` statement.
pub(crate) fn get_effect_cleanup_span(
    semantic: &Semantic<'_>,
    effect_fn_id: NodeId,
) -> Option<Span> {
    let body_stmts: &[Statement<'_>] = match semantic.nodes().kind(effect_fn_id) {
        AstKind::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => &body.statements,
            _ => return None,
        },
        AstKind::Function(func) => &func.body.as_ref()?.statements,
        _ => return None,
    };

    for stmt in body_stmts.iter().rev() {
        if let Statement::ReturnStatement(ret) = stmt
            && let Some(arg) = &ret.argument
        {
            return Some(arg.span());
        }
    }
    None
}

/// Finds a descendant `NodeId` under `ancestor_id` with exact `target_span`.
pub(crate) fn find_node_by_span(
    semantic: &Semantic<'_>,
    ancestor_id: NodeId,
    target_span: Span,
) -> Option<NodeId> {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if node.span() == target_span
            && !matches!(node.kind(), AstKind::FunctionBody(_))
            && (node_id == ancestor_id
                || semantic
                    .nodes()
                    .ancestor_ids(node_id)
                    .any(|a| a == ancestor_id))
        {
            return Some(node_id);
        }
    }
    None
}

/// Extracts all JSX `<Component ... />` caller sites in the file.
pub(crate) fn extract_caller_sites(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<CallerSite> {
    let mut sites = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXOpeningElement(opening) = node.kind() else {
            continue;
        };
        let JSXElementName::IdentifierReference(ident) = &opening.name else {
            continue;
        };
        if !is_component_name(&ident.name) {
            continue;
        }

        let import_source = ident
            .reference_id
            .get()
            .and_then(|ref_id| semantic.scoping().get_reference(ref_id).symbol_id())
            .and_then(|sym_id| resolve_import_source(semantic, sym_id));

        let (has_key, passed_props) = extract_jsx_props(&opening.attributes);

        let parent_subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        sites.push(CallerSite {
            component_name: ident.name.to_string(),
            import_source,
            parent_subject_name,
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            loc: loc_from_line_starts(line_starts, opening.span.start),
            has_key,
            passed_props,
        });
    }
    sites
}

fn extract_jsx_props(attributes: &[JSXAttributeItem<'_>]) -> (bool, Vec<String>) {
    let mut has_key = false;
    let mut passed_props = Vec::new();
    for attr_item in attributes {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let Some(ident_name) = attr.name.as_identifier() else {
            continue;
        };
        if ident_name.name == "key" {
            has_key = true;
        } else {
            passed_props.push(ident_name.name.to_string());
        }
    }
    (has_key, passed_props)
}

fn resolve_import_source(semantic: &Semantic<'_>, sym_id: SymbolId) -> Option<String> {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    for anc_id in std::iter::once(decl_id).chain(semantic.nodes().ancestor_ids(decl_id)) {
        if let AstKind::ImportDeclaration(import_decl) = semantic.nodes().kind(anc_id) {
            return import_decl.source.value.as_str().map(str::to_string);
        }
    }
    None
}

/// Extracts all [`JsxElementIr`] nodes from the file.
pub(crate) fn extract_jsx_elements(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<JsxElementIr> {
    let mut elements = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        let opening = &jsx_el.opening_element;
        let (name, root_identifier, is_component, is_unresolved_component) =
            classify_jsx_element_name(semantic, &opening.name);

        let enclosing_subject = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        let mut ancestor_elements = Vec::new();
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            if let AstKind::JSXElement(parent_jsx) = semantic.nodes().kind(anc_id) {
                let (parent_name, _, _, _) =
                    classify_jsx_element_name(semantic, &parent_jsx.opening_element.name);
                ancestor_elements.push(parent_name);
            }
        }
        ancestor_elements.reverse();

        let (in_array_map, map_index_param) = check_enclosing_array_map(semantic, node_id);
        let enclosing_subj_id = find_enclosing_react_node(semantic, node_id);
        let attr_facts = extract_jsx_element_attributes(
            semantic,
            &opening.attributes,
            map_index_param.as_deref(),
            enclosing_subj_id,
        );
        let (has_raw_text_child, raw_text_preview, has_element_children, has_render_prop_children) =
            inspect_jsx_children(&jsx_el.children);

        let opener_start_loc = loc_from_line_starts(line_starts, opening.span.start);
        let opener_end_loc = loc_from_line_starts(line_starts, opening.span.end.saturating_sub(1));
        let is_imported_component = is_jsx_root_imported(semantic, &opening.name);

        elements.push(JsxElementIr {
            name,
            root_identifier,
            is_component,
            enclosing_subject,
            ancestor_elements,
            attributes: attr_facts.attributes,
            has_key: attr_facts.has_key,
            key_is_array_index: attr_facts.key_is_array_index,
            object_literal_props: attr_facts.object_literal_props,
            array_literal_props: attr_facts.array_literal_props,
            function_props: attr_facts.function_props,
            inline_jsx_props: attr_facts.inline_jsx_props,
            in_array_map,
            has_raw_text_child,
            raw_text_preview,
            has_element_children,
            has_render_prop_children,
            is_unresolved_component,
            is_imported_component,
            fragment_href_target: attr_facts.fragment_href_target,
            opener_start_line: opener_start_loc.line,
            opener_end_line: opener_end_loc.line,
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            loc: opener_start_loc,
        });
    }
    elements
}

struct JsxAttrFacts {
    attributes: Vec<String>,
    has_key: bool,
    key_is_array_index: bool,
    object_literal_props: Vec<String>,
    array_literal_props: Vec<String>,
    function_props: Vec<String>,
    inline_jsx_props: Vec<String>,
    fragment_href_target: Option<String>,
}

fn extract_jsx_element_attributes(
    semantic: &Semantic<'_>,
    attr_items: &[JSXAttributeItem<'_>],
    map_index_param: Option<&str>,
    enclosing_subj_id: Option<NodeId>,
) -> JsxAttrFacts {
    let mut facts = JsxAttrFacts {
        attributes: Vec::new(),
        has_key: false,
        key_is_array_index: false,
        object_literal_props: Vec::new(),
        array_literal_props: Vec::new(),
        function_props: Vec::new(),
        inline_jsx_props: Vec::new(),
        fragment_href_target: None,
    };
    let subj_span = enclosing_subj_id.map(|id| semantic.nodes().get_node(id).span());

    for attr_item in attr_items {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let Some(ident_name) = attr.name.as_identifier() else {
            continue;
        };
        let attr_name = ident_name.name.to_string();
        if attr_name == "key" {
            facts.has_key = true;
            if let Some(idx_param) = map_index_param
                && let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value
                && let Some(expr) = container.expression.as_expression()
                && expr_uses_array_index_as_key(expr, idx_param)
            {
                facts.key_is_array_index = true;
            }
            continue;
        }
        record_non_key_jsx_attribute(semantic, attr, &attr_name, subj_span, &mut facts);
        facts.attributes.push(attr_name);
    }
    facts
}

fn record_non_key_jsx_attribute(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    attr_name: &str,
    subj_span: Option<Span>,
    facts: &mut JsxAttrFacts,
) {
    if matches!(attr_name, "href" | "to")
        && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
        && let Some(raw) = s.value.as_str()
    {
        facts.fragment_href_target = parse_fragment_target_id(raw);
    }
    match &attr.value {
        Some(JSXAttributeValue::Element(_) | JSXAttributeValue::Fragment(_)) => {
            facts.inline_jsx_props.push(attr_name.to_string());
        }
        Some(JSXAttributeValue::ExpressionContainer(container)) => {
            let Some(expr) = container.expression.as_expression() else {
                return;
            };
            let unwrapped = expr.without_parentheses();
            if expr_is_fresh_object_prop(semantic, unwrapped, subj_span) {
                facts.object_literal_props.push(attr_name.to_string());
            }
            if !attr_name.ends_with("Props")
                && expr_is_fresh_array_prop(semantic, unwrapped, subj_span)
            {
                facts.array_literal_props.push(attr_name.to_string());
            }
            if expr_is_fresh_function_prop(semantic, unwrapped, subj_span) {
                facts.function_props.push(attr_name.to_string());
            }
            if matches!(
                unwrapped,
                Expression::JSXElement(_) | Expression::JSXFragment(_)
            ) {
                facts.inline_jsx_props.push(attr_name.to_string());
            }
        }
        _ => {}
    }
}

fn expr_uses_array_index_as_key(expr: &Expression<'_>, idx_param: &str) -> bool {
    match expr.without_parentheses() {
        Expression::Identifier(id) => id.name.as_str() == idx_param,
        Expression::TemplateLiteral(tpl) => tpl.expressions.iter().any(|e| {
            matches!(
                e.without_parentheses(),
                Expression::Identifier(id) if id.name.as_str() == idx_param
            )
        }),
        Expression::BinaryExpression(bin) => {
            expr_uses_array_index_as_key(&bin.left, idx_param)
                || expr_uses_array_index_as_key(&bin.right, idx_param)
        }
        Expression::CallExpression(call) => match call.callee.without_parentheses() {
            Expression::StaticMemberExpression(mem)
                if mem.property.name == "toString"
                    && expr_uses_array_index_as_key(&mem.object, idx_param) =>
            {
                true
            }
            Expression::Identifier(id) if id.name == "String" => call
                .arguments
                .first()
                .and_then(|a| a.as_expression())
                .is_some_and(|a| expr_uses_array_index_as_key(a, idx_param)),
            _ => false,
        },
        _ => false,
    }
}

fn expr_is_fresh_object_prop(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    subj_span: Option<Span>,
) -> bool {
    match expr.without_parentheses() {
        Expression::ObjectExpression(_) => true,
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                && matches!(
                    mem.property.name.as_str(),
                    "freeze" | "seal" | "preventExtensions"
                )
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj_id) if obj_id.name == "Object"
                )
                && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
            {
                expr_is_fresh_object_prop(semantic, first_arg, subj_span)
            } else {
                false
            }
        }
        Expression::Identifier(ident) => {
            let Some(s_span) = subj_span else {
                return false;
            };
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !s_span.contains_inclusive(decl_node.span()) {
                return false;
            }
            if let AstKind::VariableDeclarator(decl) = decl_node.kind()
                && matches!(decl.id, BindingPattern::BindingIdentifier(_))
                && let Some(init) = &decl.init
            {
                return expr_is_fresh_object_prop(semantic, init, subj_span);
            }
            false
        }
        _ => false,
    }
}

fn expr_is_fresh_array_prop(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    subj_span: Option<Span>,
) -> bool {
    match expr.without_parentheses() {
        Expression::ArrayExpression(_) => true,
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                if matches!(
                    mem.property.name.as_str(),
                    "freeze" | "seal" | "preventExtensions"
                ) && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj_id) if obj_id.name == "Object"
                ) && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                {
                    return expr_is_fresh_array_prop(semantic, first_arg, subj_span);
                }
                matches!(
                    mem.property.name.as_str(),
                    "concat" | "filter" | "map" | "slice" | "flat" | "flatMap" | "toSorted"
                )
            } else {
                false
            }
        }
        Expression::Identifier(ident) => {
            let Some(s_span) = subj_span else {
                return false;
            };
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !s_span.contains_inclusive(decl_node.span()) {
                return false;
            }
            let AstKind::VariableDeclarator(decl) = decl_node.kind() else {
                return false;
            };
            if matches!(decl.id, BindingPattern::BindingIdentifier(_))
                && let Some(init) = &decl.init
            {
                return expr_is_fresh_array_prop(semantic, init, subj_span);
            }
            has_non_empty_array_destructure_default(&decl.id, ident.name.as_str())
        }
        _ => false,
    }
}

fn has_non_empty_array_destructure_default(
    pattern: &BindingPattern<'_>,
    target_name: &str,
) -> bool {
    let BindingPattern::ObjectPattern(obj_pat) = pattern else {
        return false;
    };
    for prop in &obj_pat.properties {
        if let BindingPattern::AssignmentPattern(assign_pat) = &prop.value
            && assign_pat
                .left
                .get_binding_identifier()
                .is_some_and(|b| b.name == target_name)
            && let Expression::ArrayExpression(arr) = assign_pat.right.without_parentheses()
        {
            return !arr.elements.is_empty();
        }
    }
    false
}

fn expr_is_fresh_function_prop(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    subj_span: Option<Span>,
) -> bool {
    match expr.without_parentheses() {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
        Expression::CallExpression(call) => {
            matches!(
                call.callee.without_parentheses(),
                Expression::StaticMemberExpression(mem) if mem.property.name == "bind"
            )
        }
        Expression::NewExpression(new_expr) => {
            matches!(
                new_expr.callee.without_parentheses(),
                Expression::Identifier(id) if id.name == "Function"
            )
        }
        Expression::LogicalExpression(log) => {
            expr_is_fresh_function_prop(semantic, &log.left, subj_span)
                || expr_is_fresh_function_prop(semantic, &log.right, subj_span)
        }
        Expression::ConditionalExpression(cond) => {
            expr_is_fresh_function_prop(semantic, &cond.consequent, subj_span)
                || expr_is_fresh_function_prop(semantic, &cond.alternate, subj_span)
        }
        Expression::Identifier(ident) => {
            let Some(s_span) = subj_span else {
                return false;
            };
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !s_span.contains_inclusive(decl_node.span()) {
                return false;
            }
            match decl_node.kind() {
                AstKind::Function(func) => func.span != s_span,
                AstKind::VariableDeclarator(decl) => {
                    if let Some(init) = &decl.init {
                        matches!(
                            init.without_parentheses(),
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        )
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn parse_fragment_target_id(href: &str) -> Option<String> {
    if !href.starts_with('#') || href.len() <= 1 || href.starts_with("#/") || href.starts_with("#!")
    {
        return None;
    }
    let rest = &href[1..];
    let target = rest.split(":~:").next().unwrap_or(rest);
    if target.is_empty() || target.eq_ignore_ascii_case("top") {
        return None;
    }
    Some(target.to_string())
}

fn inspect_jsx_children(children: &[JSXChild<'_>]) -> (bool, Option<String>, bool, bool) {
    let mut has_raw_text_child = false;
    let mut raw_text_preview = None;
    let mut has_element_children = false;
    let mut has_render_prop_children = false;

    for child in children {
        match child {
            JSXChild::Text(t) => {
                record_raw_text_snippet(
                    t.value.as_str(),
                    &mut has_raw_text_child,
                    &mut raw_text_preview,
                );
            }
            JSXChild::Element(_) | JSXChild::Fragment(_) => {
                has_element_children = true;
            }
            JSXChild::ExpressionContainer(container) => match &container.expression {
                JSXExpression::ArrowFunctionExpression(_)
                | JSXExpression::FunctionExpression(_) => {
                    has_render_prop_children = true;
                }
                JSXExpression::StringLiteral(s) => {
                    if let Some(val) = s.value.as_str() {
                        record_raw_text_snippet(
                            val,
                            &mut has_raw_text_child,
                            &mut raw_text_preview,
                        );
                    }
                }
                _ => {}
            },
            JSXChild::Spread(_) => {}
        }
    }
    (
        has_raw_text_child,
        raw_text_preview,
        has_element_children,
        has_render_prop_children,
    )
}

fn record_raw_text_snippet(
    raw: &str,
    has_raw_text_child: &mut bool,
    raw_text_preview: &mut Option<String>,
) {
    let trimmed = raw.trim();
    if !trimmed.is_empty() {
        *has_raw_text_child = true;
        if raw_text_preview.is_none() {
            *raw_text_preview = Some(trimmed.to_string());
        }
    }
}

pub(crate) fn classify_jsx_element_name(
    semantic: &Semantic<'_>,
    name: &JSXElementName<'_>,
) -> (String, String, bool, bool) {
    match name {
        JSXElementName::Identifier(ident) => {
            let s = ident.name.to_string();
            let comp = is_component_name(&s);
            (s.clone(), s, comp, false)
        }
        JSXElementName::IdentifierReference(ident) => {
            let s = ident.name.to_string();
            let comp = is_component_name(&s);
            let unresolved = comp
                && s != "React"
                && s != "Fragment"
                && ident.reference_id.get().is_some_and(|ref_id| {
                    semantic
                        .scoping()
                        .get_reference(ref_id)
                        .symbol_id()
                        .is_none()
                });
            (s.clone(), s, comp, unresolved)
        }
        JSXElementName::MemberExpression(mem) => {
            let full = mem
                .span()
                .source_text(semantic.source_text())
                .trim()
                .to_string();
            let root = full.split('.').next().unwrap_or(full.as_str()).to_string();
            (full, root, true, false)
        }
        JSXElementName::NamespacedName(ns) => {
            let full = format!("{}:{}", ns.namespace.name, ns.name.name);
            (full, ns.namespace.name.to_string(), false, false)
        }
        JSXElementName::ThisExpression(_) => ("this".to_string(), "this".to_string(), true, false),
    }
}

fn is_jsx_root_imported(semantic: &Semantic<'_>, name: &JSXElementName<'_>) -> bool {
    let JSXElementName::IdentifierReference(ident) = name else {
        return false;
    };
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    matches!(
        semantic.nodes().kind(decl_id),
        AstKind::ImportSpecifier(_)
            | AstKind::ImportDefaultSpecifier(_)
            | AstKind::ImportNamespaceSpecifier(_)
    )
}

pub(crate) fn check_enclosing_array_map(
    semantic: &Semantic<'_>,
    jsx_node_id: NodeId,
) -> (bool, Option<String>) {
    for anc_id in semantic.nodes().ancestor_ids(jsx_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::JSXElement(_) => return (false, None),
            AstKind::ArrowFunctionExpression(arrow) => {
                let parent_id = semantic.nodes().parent_id(anc_id);
                if let AstKind::CallExpression(call) = semantic.nodes().kind(parent_id)
                    && is_map_callee(&call.callee)
                {
                    let index_param = arrow
                        .params
                        .items
                        .get(1)
                        .and_then(|p| p.pattern.get_binding_identifier())
                        .map(|id| id.name.to_string());
                    return (true, index_param);
                }
                return (false, None);
            }
            AstKind::Function(func) => {
                let parent_id = semantic.nodes().parent_id(anc_id);
                if let AstKind::CallExpression(call) = semantic.nodes().kind(parent_id)
                    && is_map_callee(&call.callee)
                {
                    let index_param = func
                        .params
                        .items
                        .get(1)
                        .and_then(|p| p.pattern.get_binding_identifier())
                        .map(|id| id.name.to_string());
                    return (true, index_param);
                }
                return (false, None);
            }
            _ => {}
        }
    }
    (false, None)
}

fn is_map_callee(callee: &Expression<'_>) -> bool {
    matches!(
        callee.without_parentheses(),
        Expression::StaticMemberExpression(mem) if mem.property.name == "map"
    )
}

/// Extracts all [`JsxSubtreeIr`] candidates (`JSXElement` and `JSXFragment`) with bottom-up structural hashes.
pub(crate) fn extract_jsx_subtrees(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<JsxSubtreeIr> {
    let mut jsx_nodes = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if matches!(
            node.kind(),
            AstKind::JSXElement(_) | AstKind::JSXFragment(_)
        ) {
            jsx_nodes.push(node_id);
        }
    }
    if jsx_nodes.is_empty() {
        return Vec::new();
    }

    let mut direct_children_by_parent: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for &node_id in &jsx_nodes {
        if let Some(parent_jsx_id) = semantic.nodes().ancestor_ids(node_id).find(|&anc| {
            matches!(
                semantic.nodes().kind(anc),
                AstKind::JSXElement(_) | AstKind::JSXFragment(_)
            )
        }) {
            direct_children_by_parent
                .entry(parent_jsx_id)
                .or_default()
                .push(node_id);
        }
    }

    let mut meta_by_node: HashMap<NodeId, (String, usize, usize)> =
        HashMap::with_capacity(jsx_nodes.len());
    let mut fingerprint_by_span: HashMap<(u32, u32), String> =
        HashMap::with_capacity(jsx_nodes.len());

    for &node_id in jsx_nodes.iter().rev() {
        let children = direct_children_by_parent
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let node_count = 1 + children
            .iter()
            .filter_map(|c| meta_by_node.get(c))
            .map(|(_, nc, _)| *nc)
            .sum::<usize>();
        let depth = 1 + children
            .iter()
            .filter_map(|c| meta_by_node.get(c))
            .map(|(_, _, d)| *d)
            .max()
            .unwrap_or(0);

        let fp = compute_jsx_node_fingerprint(node_id, semantic, &fingerprint_by_span);
        let span = semantic.nodes().get_node(node_id).span();
        fingerprint_by_span.insert((span.start, span.end), fp.clone());
        meta_by_node.insert(node_id, (fp, node_count, depth));
    }

    let mut subtrees = Vec::with_capacity(jsx_nodes.len());
    for node_id in jsx_nodes {
        let Some((fingerprint, node_count, depth)) = meta_by_node.remove(&node_id) else {
            continue;
        };
        let root_name = jsx_subtree_root_name(semantic, node_id);
        let (enclosing_subject, composition_root_offset) =
            find_enclosing_function_identity(semantic, node_id);

        let mut ancestor_names = Vec::new();
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            if matches!(
                semantic.nodes().kind(anc_id),
                AstKind::JSXElement(_) | AstKind::JSXFragment(_)
            ) {
                ancestor_names.push(jsx_subtree_root_name(semantic, anc_id));
            }
        }
        ancestor_names.reverse();

        let mut composition_path = Vec::new();
        if let Some(fn_name) = &enclosing_subject {
            composition_path.push(fn_name.clone());
        }
        composition_path.extend(ancestor_names);
        composition_path.push(root_name.clone());

        let span = semantic.nodes().get_node(node_id).span();
        let loc = loc_from_line_starts(line_starts, span.start);
        let end_loc = loc_from_line_starts(line_starts, span.end.saturating_sub(1));

        subtrees.push(JsxSubtreeIr {
            fingerprint,
            node_count,
            depth,
            root_name,
            enclosing_subject,
            composition_root_offset,
            composition_path,
            span: ByteSpan {
                start: span.start,
                end: span.end,
            },
            loc,
            end_line: end_loc.line,
        });
    }

    subtrees
}

fn jsx_subtree_root_name(semantic: &Semantic<'_>, node_id: NodeId) -> String {
    match semantic.nodes().kind(node_id) {
        AstKind::JSXElement(el) => classify_jsx_element_name(semantic, &el.opening_element.name).0,
        AstKind::JSXFragment(_) => "Fragment".to_string(),
        _ => "Fragment".to_string(),
    }
}

fn find_enclosing_function_identity(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> (Option<String>, Option<u32>) {
    if let Some(subj_id) = find_enclosing_react_node(semantic, node_id) {
        let name =
            get_subject_name(semantic, subj_id).unwrap_or_else(|| "default export".to_string());
        let start = semantic.nodes().get_node(subj_id).span().start;
        return (Some(name), Some(start));
    }
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                let name = func
                    .id
                    .as_ref()
                    .map_or_else(|| "default export".to_string(), |id| id.name.to_string());
                return (Some(name), Some(func.span.start));
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier() {
                    return (Some(id.name.to_string()), Some(decl.span.start));
                }
            }
            AstKind::MethodDefinition(method) => {
                if let Some(name) = method
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                {
                    return (Some(name), Some(method.span.start));
                }
            }
            _ => {}
        }
    }
    (None, None)
}

fn compute_jsx_node_fingerprint(
    node_id: NodeId,
    semantic: &Semantic<'_>,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    let source = semantic.source_text();
    let mut parts = Vec::new();

    match semantic.nodes().kind(node_id) {
        AstKind::JSXElement(el) => {
            let kind_tag = if el.closing_element.is_none() {
                "JsxSelfClosingElement"
            } else {
                "JsxElement"
            };
            parts.push(kind_tag.to_string());
            let tag_name = classify_jsx_element_name(semantic, &el.opening_element.name).0;
            parts.push(tag_name);

            for attr_item in &el.opening_element.attributes {
                match attr_item {
                    JSXAttributeItem::Attribute(attr) => {
                        let attr_name = attr.name.span().source_text(source).trim();
                        let init_hash = match &attr.value {
                            None => "present".to_string(),
                            Some(JSXAttributeValue::StringLiteral(s)) => {
                                format!("string:{}", s.value.as_str().unwrap_or_default())
                            }
                            Some(JSXAttributeValue::Element(child_el)) => fingerprint_by_span
                                .get(&(child_el.span.start, child_el.span.end))
                                .cloned()
                                .unwrap_or_else(|| "jsx-el".to_string()),
                            Some(JSXAttributeValue::Fragment(child_frag)) => fingerprint_by_span
                                .get(&(child_frag.span.start, child_frag.span.end))
                                .cloned()
                                .unwrap_or_else(|| "jsx-frag".to_string()),
                            Some(JSXAttributeValue::ExpressionContainer(container)) => {
                                normalize_jsx_attr_expr(
                                    &container.expression,
                                    source,
                                    fingerprint_by_span,
                                )
                            }
                        };
                        parts.push(hash_framed_parts(&["attribute", attr_name, &init_hash]));
                    }
                    JSXAttributeItem::SpreadAttribute(spread) => {
                        let arg_hash =
                            normalize_ast_expr(&spread.argument, source, fingerprint_by_span);
                        parts.push(hash_framed_parts(&["spread", &arg_hash]));
                    }
                }
            }

            append_jsx_children_hashes(&el.children, source, fingerprint_by_span, &mut parts);
        }
        AstKind::JSXFragment(frag) => {
            parts.push("JsxFragment".to_string());
            parts.push("fragment".to_string());
            append_jsx_children_hashes(&frag.children, source, fingerprint_by_span, &mut parts);
        }
        _ => {}
    }

    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    format!("jsx:{}", hash_framed_parts(&refs))
}

fn append_jsx_children_hashes(
    children: &[JSXChild<'_>],
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
    parts: &mut Vec<String>,
) {
    for child in children {
        match child {
            JSXChild::Text(t) => {
                if !t.value.as_str().trim().is_empty() {
                    parts.push("jsx-text".to_string());
                }
            }
            JSXChild::Element(el) => {
                if let Some(fp) = fingerprint_by_span.get(&(el.span.start, el.span.end)) {
                    parts.push(fp.clone());
                }
            }
            JSXChild::Fragment(frag) => {
                if let Some(fp) = fingerprint_by_span.get(&(frag.span.start, frag.span.end)) {
                    parts.push(fp.clone());
                }
            }
            JSXChild::ExpressionContainer(container) => {
                if !matches!(container.expression, JSXExpression::EmptyExpression(_)) {
                    parts.push(normalize_jsx_expr(
                        &container.expression,
                        source,
                        fingerprint_by_span,
                    ));
                }
            }
            JSXChild::Spread(spread) => {
                let inner = normalize_ast_expr(&spread.expression, source, fingerprint_by_span);
                parts.push(hash_framed_parts(&["jsx-spread", &inner]));
            }
        }
    }
}

fn normalize_jsx_attr_expr(
    jsx_expr: &JSXExpression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    if let Some(expr) = jsx_expr.as_expression() {
        let inner = expr.without_parentheses();
        if matches!(
            inner,
            Expression::StringLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
        ) {
            return format!("static:{}", inner.span().source_text(source).trim());
        }
    }
    let inner_hash = normalize_jsx_expr(jsx_expr, source, fingerprint_by_span);
    hash_framed_parts(&["JsxExpression", &inner_hash])
}

fn normalize_jsx_expr(
    jsx_expr: &JSXExpression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    let Some(expr) = jsx_expr.as_expression() else {
        return "empty".to_string();
    };
    normalize_ast_expr(expr, source, fingerprint_by_span)
}

fn normalize_ast_expr(
    expr: &Expression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    match expr.without_parentheses() {
        Expression::JSXElement(el) => fingerprint_by_span
            .get(&(el.span.start, el.span.end))
            .cloned()
            .unwrap_or_else(|| "jsx-el".to_string()),
        Expression::JSXFragment(frag) => fingerprint_by_span
            .get(&(frag.span.start, frag.span.end))
            .cloned()
            .unwrap_or_else(|| "jsx-frag".to_string()),
        Expression::Identifier(_) => "identifier".to_string(),
        Expression::StringLiteral(_) => "StringLiteral".to_string(),
        Expression::NumericLiteral(_) => "NumericLiteral".to_string(),
        Expression::BooleanLiteral(b) => {
            if b.value {
                "TrueKeyword".to_string()
            } else {
                "FalseKeyword".to_string()
            }
        }
        Expression::NullLiteral(_) => "NullKeyword".to_string(),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
            "NoSubstitutionTemplateLiteral".to_string()
        }
        Expression::RegExpLiteral(_) => "RegularExpressionLiteral".to_string(),
        Expression::StaticMemberExpression(mem) => {
            let obj_hash = normalize_ast_expr(&mem.object, source, fingerprint_by_span);
            let opt = if mem.optional { "optional" } else { "required" };
            hash_framed_parts(&[
                "property-access",
                opt,
                &obj_hash,
                mem.property.name.as_str(),
            ])
        }
        Expression::ComputedMemberExpression(comp) => {
            let obj_hash = normalize_ast_expr(&comp.object, source, fingerprint_by_span);
            let opt = if comp.optional {
                "optional"
            } else {
                "required"
            };
            let arg_inner = comp.expression.without_parentheses();
            let arg_hash = match arg_inner {
                Expression::StringLiteral(s) => {
                    format!("StringLiteral:{}", s.value.as_str().unwrap_or_default())
                }
                Expression::NumericLiteral(n) => {
                    format!("NumericLiteral:{}", n.span.source_text(source).trim())
                }
                _ => normalize_ast_expr(arg_inner, source, fingerprint_by_span),
            };
            hash_framed_parts(&["element-access", opt, &obj_hash, &arg_hash])
        }
        Expression::BinaryExpression(bin) => {
            let left = normalize_ast_expr(&bin.left, source, fingerprint_by_span);
            let right = normalize_ast_expr(&bin.right, source, fingerprint_by_span);
            hash_framed_parts(&["binary-expression", bin.operator.as_str(), &left, &right])
        }
        Expression::LogicalExpression(log) => {
            let left = normalize_ast_expr(&log.left, source, fingerprint_by_span);
            let right = normalize_ast_expr(&log.right, source, fingerprint_by_span);
            hash_framed_parts(&["logical-expression", log.operator.as_str(), &left, &right])
        }
        Expression::UnaryExpression(un) => {
            let arg = normalize_ast_expr(&un.argument, source, fingerprint_by_span);
            hash_framed_parts(&["PrefixUnaryExpression", un.operator.as_str(), &arg])
        }
        Expression::ConditionalExpression(cond) => {
            let test = normalize_ast_expr(&cond.test, source, fingerprint_by_span);
            let cons = normalize_ast_expr(&cond.consequent, source, fingerprint_by_span);
            let alt = normalize_ast_expr(&cond.alternate, source, fingerprint_by_span);
            hash_framed_parts(&["ConditionalExpression", &test, &cons, &alt])
        }
        Expression::CallExpression(call) => {
            let mut parts = vec![
                "CallExpression".to_string(),
                normalize_ast_expr(&call.callee, source, fingerprint_by_span),
            ];
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    parts.push(normalize_ast_expr(e, source, fingerprint_by_span));
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let body_hash = if let Some(e) = arrow.body.as_expression() {
                normalize_ast_expr(e, source, fingerprint_by_span)
            } else if let ArrowFunctionBody::FunctionBody(b) = &arrow.body {
                format!("block:{}", b.statements.len())
            } else {
                "body".to_string()
            };
            hash_framed_parts(&["ArrowFunction", &body_hash])
        }
        Expression::ObjectExpression(obj) => {
            let mut parts = vec!["ObjectLiteralExpression".to_string()];
            for prop in &obj.properties {
                match prop {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                        let key = p.key.span().source_text(source).trim();
                        if p.shorthand {
                            parts.push(hash_framed_parts(&["shorthand-property", key]));
                        } else {
                            let val = normalize_ast_expr(&p.value, source, fingerprint_by_span);
                            parts.push(hash_framed_parts(&["property-assignment", key, &val]));
                        }
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(s) => {
                        let val = normalize_ast_expr(&s.argument, source, fingerprint_by_span);
                        parts.push(hash_framed_parts(&["spread", &val]));
                    }
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        Expression::ArrayExpression(arr) => {
            let mut parts = vec!["ArrayLiteralExpression".to_string()];
            for elem in &arr.elements {
                if let Some(e) = elem.as_expression() {
                    parts.push(normalize_ast_expr(e, source, fingerprint_by_span));
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        _ => "expr".to_string(),
    }
}

fn hash_framed_parts(parts: &[&str]) -> String {
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
    for &part in parts {
        let header = format!("{}:", part.len());
        for &b in header.as_bytes().iter().chain(part.as_bytes().iter()) {
            h1 ^= u64::from(b);
            h1 = h1.wrapping_mul(0x0100_0000_01b3);
            h2 = h2
                .wrapping_add(u64::from(b))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    format!("{h1:016x}{h2:016x}")
}

/// Inspects a **Subject** node (`Function` or `VariableDeclarator`) to determine if it is
/// wrapped in `memo(...)` / `React.memo(...)` and whether a custom comparator is supplied.
pub(crate) fn classify_subject_memoization(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
) -> (bool, bool) {
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(subject_node_id)
        && let Some(Expression::CallExpression(call)) =
            decl.init.as_ref().map(Expression::without_parentheses)
        && is_memo_callee(&call.callee)
    {
        if call.arguments.len() >= 2 {
            return (false, true);
        }
        return (true, false);
    }

    // Also check if `export default memo(SubjectName)` wraps this Subject in the same file
    if let Some(subj_name) = get_subject_name(semantic, subject_node_id) {
        for (_, node) in semantic.nodes().iter_enumerated() {
            if let AstKind::ExportDefaultDeclaration(exp) = node.kind()
                && let Some(expr) = exp.declaration.as_expression()
                && let Expression::CallExpression(call) = expr.without_parentheses()
                && is_memo_callee(&call.callee)
                && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                && let Expression::Identifier(id) = first_arg.without_parentheses()
                && id.name.as_str() == subj_name
            {
                if call.arguments.len() >= 2 {
                    return (false, true);
                }
                return (true, false);
            }
        }
    }

    (false, false)
}

fn is_memo_callee(callee: &Expression<'_>) -> bool {
    match callee.without_parentheses() {
        Expression::Identifier(id) => id.name == "memo",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "memo"
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "React"
                )
        }
        _ => false,
    }
}

/// Collects all component prop names that appear inside `useEffect`, `useLayoutEffect`,
/// `useMemo`, or `useCallback` dependency arrays within `subject_node_id`.
pub(crate) fn extract_subject_hook_dep_props(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
) -> Vec<String> {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let mut prop_names = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if find_enclosing_react_node(semantic, node_id) != Some(subject_node_id) {
            continue;
        }
        let is_deps_hook = ["useEffect", "useLayoutEffect", "useMemo", "useCallback"]
            .iter()
            .any(|h| is_react_hook_callee(semantic, &call.callee, h));
        if !is_deps_hook {
            continue;
        }
        let Some(deps_arg) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
            continue;
        };
        let Expression::ArrayExpression(arr) = deps_arg.without_parentheses() else {
            continue;
        };
        for elem in &arr.elements {
            let Some(expr) = elem.as_expression() else {
                continue;
            };
            if let Some(root_ident) = extract_root_identifier(expr)
                && let Some(ref_id) = root_ident.reference_id.get()
                && super::dataflow::is_prop(semantic, ref_id)
                && !prop_names.contains(&root_ident.name.to_string())
            {
                prop_names.push(root_ident.name.to_string());
            }
        }
    }
    prop_names
}

fn extract_root_identifier<'a>(
    expr: &'a Expression<'a>,
) -> Option<&'a oxc_ast::ast::IdentifierReference<'a>> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id),
        Expression::StaticMemberExpression(mem) => extract_root_identifier(&mem.object),
        Expression::ComputedMemberExpression(comp) => extract_root_identifier(&comp.object),
        Expression::ChainExpression(chain) => match &chain.expression {
            oxc_ast::ast::ChainElement::StaticMemberExpression(mem) => {
                extract_root_identifier(&mem.object)
            }
            oxc_ast::ast::ChainElement::ComputedMemberExpression(comp) => {
                extract_root_identifier(&comp.object)
            }
            oxc_ast::ast::ChainElement::CallExpression(call) => {
                extract_root_identifier(&call.callee)
            }
            oxc_ast::ast::ChainElement::TSNonNullExpression(nn) => {
                extract_root_identifier(&nn.expression)
            }
            oxc_ast::ast::ChainElement::PrivateFieldExpression(_) => None,
        },
        _ => None,
    }
}

/// Checks whether `subject_node_id` invokes suspending hooks/APIs (`use(promise)`, `useSuspenseQuery`,
/// `useSearchParams`, `React.lazy`) or throws synchronously in render without an enclosing `<Suspense>` / `<ErrorBoundary>`.
pub(crate) fn detect_subject_suspense_and_throws(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
) -> (bool, bool) {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let mut lazy_symbol_ids: HashSet<SymbolId> = HashSet::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::VariableDeclarator(decl) = node.kind()
            && let Some(id) = decl.id.get_binding_identifier()
            && let Some(sym_id) = id.symbol_id.get()
            && let Some(init) = &decl.init
            && let Expression::CallExpression(call) = init.without_parentheses()
            && is_react_lazy_call(call)
        {
            lazy_symbol_ids.insert(sym_id);
        }
    }

    let mut suspends = false;
    let mut throws_in_render = false;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if find_enclosing_react_node(semantic, node_id) != Some(subject_node_id) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                let callee_name = match call.callee.without_parentheses() {
                    Expression::Identifier(id) => Some(id.name.as_str()),
                    Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
                    _ => None,
                };
                match callee_name {
                    Some(
                        "useSuspenseQuery"
                        | "useSuspenseInfiniteQuery"
                        | "useSuspenseQueries"
                        | "useSearchParams",
                    ) => {
                        suspends = true;
                    }
                    Some("use") => {
                        // `use(promise)` suspends unless the argument is a Context (`*Context` / `Ctx`)
                        let is_context_arg = call
                            .arguments
                            .first()
                            .and_then(|a| a.as_expression())
                            .is_some_and(|arg| {
                                let txt = arg.span().source_text(semantic.source_text()).trim();
                                txt.ends_with("Context") || txt.ends_with("Ctx")
                            });
                        if !is_context_arg {
                            suspends = true;
                        }
                    }
                    _ => {
                        if is_react_lazy_call(call)
                            && !node_has_enclosing_jsx_boundary(
                                semantic,
                                node_id,
                                subject_node_id,
                                true,
                            )
                        {
                            suspends = true;
                        }
                    }
                }
            }
            AstKind::JSXOpeningElement(opening) => {
                if let oxc_ast::ast::JSXElementName::IdentifierReference(ident) = &opening.name
                    && let Some(ref_id) = ident.reference_id.get()
                    && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
                    && lazy_symbol_ids.contains(&sym_id)
                    && !node_has_enclosing_jsx_boundary(semantic, node_id, subject_node_id, true)
                {
                    suspends = true;
                }
            }
            AstKind::ThrowStatement(_)
                if is_in_subject_render_path(semantic, node_id, subject_node_id)
                    && !node_has_enclosing_jsx_boundary(
                        semantic,
                        node_id,
                        subject_node_id,
                        false,
                    ) =>
            {
                throws_in_render = true;
            }
            _ => {}
        }
    }

    (suspends, throws_in_render)
}

fn is_react_lazy_call(call: &CallExpression<'_>) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => id.name == "lazy",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "lazy"
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "React"
                )
        }
        _ => false,
    }
}

fn node_has_enclosing_jsx_boundary(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subject_node_id: NodeId,
    want_suspense: bool,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subject_node_id {
            break;
        }
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let (tag_name, _, _, _) = classify_jsx_element_name(semantic, &el.opening_element.name);
            if want_suspense && (tag_name == "Suspense" || tag_name.ends_with(".Suspense")) {
                return true;
            }
            if !want_suspense && tag_name.contains("ErrorBoundary") {
                return true;
            }
        }
    }
    false
}

fn is_in_subject_render_path(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subject_node_id: NodeId,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subject_node_id {
            return true;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::TryStatement(_) => return false,
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                let parent_id = semantic.nodes().parent_id(anc_id);
                if parent_id == subject_node_id {
                    continue;
                }
                return false;
            }
            _ => {}
        }
    }
    false
}
