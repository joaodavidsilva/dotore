//! React-specific AST and semantic predicates (`useState`, `useEffect`, `useRef`, props, HOCs).

use oxc_ast::{
    AstKind,
    ast::{ArrowFunctionBody, BindingPattern, CallExpression, Expression, Statement},
};
use oxc_semantic::{NodeId, ReferenceId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

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
