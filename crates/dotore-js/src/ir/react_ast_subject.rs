//! Subject-level memoization, hook dependency prop, suspense, and render-throw helpers for [`super::react_ast`].
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; subject inspection matches only relevant AST node kinds (#50)"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{CallExpression, Expression, JSXElementName, JSXOpeningElement},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;

use super::react_ast::{
    find_enclosing_react_node, get_subject_name, is_component_name, is_react_hook_callee,
};

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
    let lazy_symbol_ids = collect_lazy_symbol_ids(semantic);

    let mut suspends = false;
    let mut throws_in_render = false;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span())
            || find_enclosing_react_node(semantic, node_id) != Some(subject_node_id)
        {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                if call_suspends_subject(semantic, node_id, subject_node_id, call) {
                    suspends = true;
                }
            }
            AstKind::JSXOpeningElement(opening) => {
                if jsx_opening_suspends_subject(
                    semantic,
                    node_id,
                    subject_node_id,
                    opening,
                    &lazy_symbol_ids,
                ) {
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

fn collect_lazy_symbol_ids(semantic: &Semantic<'_>) -> HashSet<SymbolId> {
    let mut lazy_symbol_ids = HashSet::new();
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
    lazy_symbol_ids
}

fn call_suspends_subject(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subject_node_id: NodeId,
    call: &CallExpression<'_>,
) -> bool {
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
        ) => true,
        Some("use") => {
            // `use(promise)` suspends unless the argument is a Context (`*Context` / `Ctx`)
            !call
                .arguments
                .first()
                .and_then(|a| a.as_expression())
                .is_some_and(|arg| {
                    let txt = arg.span().source_text(semantic.source_text()).trim();
                    txt.ends_with("Context") || txt.ends_with("Ctx")
                })
        }
        _ => {
            is_react_lazy_call(call)
                && !node_has_enclosing_jsx_boundary(semantic, node_id, subject_node_id, true)
        }
    }
}

fn jsx_opening_suspends_subject(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subject_node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    lazy_symbol_ids: &HashSet<SymbolId>,
) -> bool {
    let oxc_ast::ast::JSXElementName::IdentifierReference(ident) = &opening.name else {
        return false;
    };
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    lazy_symbol_ids.contains(&sym_id)
        && !node_has_enclosing_jsx_boundary(semantic, node_id, subject_node_id, true)
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

pub(super) fn is_jsx_root_imported(semantic: &Semantic<'_>, name: &JSXElementName<'_>) -> bool {
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

pub(super) fn check_enclosing_array_map(
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
