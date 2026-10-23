//! Reference traversal (`ascend`, `descend`, synchronous call chains), mutations,
//! async flows, security sinks, and semantic rule sites over `oxc_semantic`.

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{AssignmentTarget, BindingPattern, Declaration, Expression, Program, Statement},
};
use oxc_semantic::{NodeId, ReferenceId, Semantic};
use oxc_span::{GetSpan, Span};
use oxc_syntax::{operator::UnaryOperator, symbol::SymbolFlags};

use super::{
    react_ast::{
        RefEntry, find_enclosing_react_node, get_subject_name, is_functional_hoc,
        is_react_hook_callee, is_use_ref_node, is_use_state_node,
    },
    types::{
        AsyncFlowIr, ByteSpan, ModuleIr, MutationSiteIr, SecuritySinkIr, SecuritySinkKind,
        SemanticRuleSite, loc_from_line_starts,
    },
};

const MUTATING_ARRAY_METHODS: &[&str] = &[
    "push", "pop", "splice", "sort", "reverse", "shift", "unshift", "fill",
];

const AUTH_GUARD_FUNCTION_NAMES: &[&str] = &[
    "auth",
    "getSession",
    "requireAuth",
    "verifySession",
    "getUser",
    "getCurrentUser",
    "requireUser",
    "ensureAuthenticated",
    "requireAdmin",
    "checkAuth",
];

/// Collects all `IdentifierReference`s inside `target_span`, skipping `CallExpression.arguments`
/// and `NewExpression.arguments` strictly within `target_span`.
pub(crate) fn get_downstream_refs_in_span(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    target_span: Span,
) -> Vec<ReferenceId> {
    let mut out = Vec::new();
    for entry in ref_entries {
        if target_span.contains_inclusive(entry.span)
            && is_outside_call_args_within(semantic, entry.node_id, entry.span, target_span)
        {
            out.push(entry.ref_id);
        }
    }
    out
}

/// Collects all `IdentifierReference`s inside `target_span` including inside call arguments.
pub(crate) fn get_all_refs_in_span(
    ref_entries: &[RefEntry],
    target_span: Span,
) -> Vec<ReferenceId> {
    ref_entries
        .iter()
        .filter(|entry| target_span.contains_inclusive(entry.span))
        .map(|entry| entry.ref_id)
        .collect()
}

fn is_outside_call_args_within(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    node_span: Span,
    target_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_node = semantic.nodes().get_node(anc_id);
        if !target_span.contains_inclusive(anc_node.span()) {
            break;
        }
        match anc_node.kind() {
            AstKind::CallExpression(call) if !call.callee.span().contains_inclusive(node_span) => {
                return false;
            }
            AstKind::NewExpression(new_expr)
                if !new_expr.callee.span().contains_inclusive(node_span) =>
            {
                return false;
            }
            _ => {}
        }
    }
    true
}

/// Traverses upstream variable and function definitions from `ref_id`, stopping at imports and parameters.
pub(crate) fn ascend<F>(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
    visit: &mut F,
    visited: &mut HashSet<ReferenceId>,
) where
    F: FnMut(ReferenceId) -> bool,
{
    if visited.contains(&ref_id) {
        return;
    }
    let keep_going = visit(ref_id);
    visited.insert(ref_id);
    if !keep_going {
        return;
    }

    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return;
    };
    if semantic
        .scoping()
        .symbol_flags(sym_id)
        .contains(SymbolFlags::Import)
    {
        return;
    }

    for decl_node_id in semantic.scoping().symbol_declarations(sym_id) {
        let maybe_span = match semantic.nodes().kind(decl_node_id) {
            AstKind::VariableDeclarator(decl) => decl.init.as_ref().map(GetSpan::span),
            AstKind::Function(func) => func.body.as_ref().map(|b| b.span),
            _ => None,
        };
        if let Some(span) = maybe_span {
            for next_ref in get_downstream_refs_in_span(semantic, ref_entries, span) {
                ascend(semantic, ref_entries, next_ref, visit, visited);
            }
        }
    }
}

/// Returns all upstream references reachable from `ref_id` (including `ref_id` itself).
pub(crate) fn get_upstream_refs(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> Vec<ReferenceId> {
    let mut refs = Vec::new();
    let mut visited = HashSet::new();
    ascend(
        semantic,
        ref_entries,
        ref_id,
        &mut |up_ref| {
            refs.push(up_ref);
            true
        },
        &mut visited,
    );
    refs
}

/// If `ref_id` is the identifier or root object of a `CallExpression` callee (`fn()` or `obj.fn()`),
/// returns that `CallExpression`'s `NodeId`.
pub(crate) fn get_call_expr(semantic: &Semantic<'_>, ref_id: ReferenceId) -> Option<NodeId> {
    let ref_node_id = semantic.scoping().get_reference(ref_id).node_id();
    let ref_span = semantic.nodes().get_node(ref_node_id).span();

    for anc_id in semantic.nodes().ancestor_ids(ref_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::StaticMemberExpression(_)
            | AstKind::ComputedMemberExpression(_)
            | AstKind::PrivateFieldExpression(_)
            | AstKind::ChainExpression(_)
            | AstKind::ParenthesizedExpression(_) => {}
            AstKind::CallExpression(call) => {
                if call.callee.span().contains_inclusive(ref_span) {
                    return Some(anc_id);
                }
                return None;
            }
            _ => return None,
        }
    }
    None
}

/// Collects upstream references of all arguments passed to call expressions in `ref_id`'s upstream chain.
pub(crate) fn get_args_upstream_refs(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> Vec<ReferenceId> {
    let mut out = Vec::new();
    for up_ref in get_upstream_refs(semantic, ref_entries, ref_id) {
        let Some(call_id) = get_call_expr(semantic, up_ref) else {
            continue;
        };
        let AstKind::CallExpression(call) = semantic.nodes().kind(call_id) else {
            continue;
        };
        for arg in &call.arguments {
            for arg_ref in get_downstream_refs_in_span(semantic, ref_entries, arg.span()) {
                out.extend(get_upstream_refs(semantic, ref_entries, arg_ref));
            }
        }
    }
    out
}

/// Checks if `node_id` executes synchronously within `within_node_id` (not inside `await`, `void`, or a nested function).
pub(crate) fn is_synchronous(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    within_node_id: NodeId,
) -> bool {
    for current_id in std::iter::once(node_id).chain(semantic.nodes().ancestor_ids(node_id)) {
        if current_id == within_node_id {
            return true;
        }
        match semantic.nodes().kind(current_id) {
            AstKind::AwaitExpression(_)
            | AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_) => return false,
            AstKind::UnaryExpression(unary) if unary.operator == UnaryOperator::Void => {
                return false;
            }
            _ => {}
        }
    }
    false
}

fn find_enclosing_function(semantic: &Semantic<'_>, node_id: NodeId) -> Option<NodeId> {
    std::iter::once(node_id)
        .chain(semantic.nodes().ancestor_ids(node_id))
        .find(|&id| {
            matches!(
                semantic.nodes().kind(id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
}

fn is_alias_ref(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let ref_node_id = semantic.scoping().get_reference(ref_id).node_id();
    let ref_span = semantic.nodes().get_node(ref_node_id).span();

    for anc_id in semantic.nodes().ancestor_ids(ref_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ObjectProperty(_)
            | AstKind::ObjectExpression(_)
            | AstKind::ArrayExpression(_)
            | AstKind::SequenceExpression(_)
            | AstKind::ParenthesizedExpression(_) => {}
            AstKind::VariableDeclarator(decl) => {
                return decl
                    .init
                    .as_ref()
                    .is_some_and(|init| init.span().contains_inclusive(ref_span));
            }
            _ => return false,
        }
    }
    false
}

/// Returns all references along a synchronous call/alias chain starting at `ref_id`.
pub(crate) fn get_synchronous_call_chain(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> Vec<ReferenceId> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    ascend(
        semantic,
        ref_entries,
        ref_id,
        &mut |up_ref| {
            if let Some(call_id) = get_call_expr(semantic, up_ref)
                && let Some(enclosing_fn) = find_enclosing_function(semantic, call_id)
                && is_synchronous(semantic, call_id, enclosing_fn)
            {
                chain.push(up_ref);
                true
            } else if is_alias_ref(semantic, up_ref) {
                chain.push(up_ref);
                true
            } else {
                false
            }
        },
        &mut visited,
    );
    chain
}

/// Checks if `ref_id` resolves to the state value binding (`x` in `const [x, setX] = useState()`).
pub(crate) fn is_state(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    if !is_react_hook_callee(semantic, &call.callee, "useState") {
        return false;
    }
    let BindingPattern::ArrayPattern(arr) = &decl.id else {
        return false;
    };
    if arr.elements.is_empty() || arr.elements.len() > 2 {
        return false;
    }
    matches!(
        arr.elements.first().and_then(Option::as_ref),
        Some(BindingPattern::BindingIdentifier(id)) if id.symbol_id.get() == Some(sym_id)
    )
}

/// Checks if `ref_id` resolves to the state setter binding (`setX` in `const [x, setX] = useState()`).
pub(crate) fn is_state_setter(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    if !is_react_hook_callee(semantic, &call.callee, "useState") {
        return false;
    }
    let BindingPattern::ArrayPattern(arr) = &decl.id else {
        return false;
    };
    if arr.elements.len() != 2 {
        return false;
    }
    matches!(
        arr.elements.get(1).and_then(Option::as_ref),
        Some(BindingPattern::BindingIdentifier(id)) if id.symbol_id.get() == Some(sym_id)
    )
}

/// Checks if `ref_id` resolves to a prop parameter of a functional component (excluding non-pure HOCs) or custom hook.
pub(crate) fn is_prop(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if !matches!(
        semantic.nodes().kind(decl_id),
        AstKind::FormalParameter(_)
            | AstKind::FormalParameterRest(_)
            | AstKind::BindingRestElement(_)
    ) {
        return false;
    }

    let Some(fn_id) = find_enclosing_function(semantic, decl_id) else {
        return false;
    };
    let Some(subject_id) = find_enclosing_react_node(semantic, fn_id) else {
        return false;
    };
    if is_functional_hoc(semantic, subject_id) {
        return false;
    }
    // Ensure `fn_id` is the component/hook function itself, not a nested callback inside the body.
    for anc_id in semantic.nodes().ancestor_ids(fn_id) {
        if anc_id == subject_id {
            return true;
        }
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_)
                | AstKind::ArrowFunctionExpression(_)
                | AstKind::FunctionBody(_)
                | AstKind::BlockStatement(_)
        ) {
            return false;
        }
    }
    fn_id == subject_id
}

/// Checks if `ref_id` resolves to a constant literal/array/object declaration.
pub(crate) fn is_constant(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
        return false;
    };
    init.is_literal()
        || matches!(
            init,
            Expression::TemplateLiteral(_)
                | Expression::ArrayExpression(_)
                | Expression::ObjectExpression(_)
        )
}

/// Checks if `ref_id` resolves to a `useRef` variable.
pub(crate) fn is_ref(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    is_react_hook_callee(semantic, &call.callee, "useRef")
}

/// Checks if `ref_id` is being accessed via `.current` (`ref.current`).
pub(crate) fn is_ref_current(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let node_id = semantic.scoping().get_reference(ref_id).node_id();
    let node_span = semantic.nodes().get_node(node_id).span();
    matches!(
        semantic.nodes().parent_kind(node_id),
        AstKind::StaticMemberExpression(mem)
            if mem.property.name == "current" && mem.object.span().contains_inclusive(node_span)
    )
}

/// Checks if `ref_id` synchronously invokes a state setter (directly, via alias, or via local helper).
pub(crate) fn is_state_call(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> bool {
    get_synchronous_call_chain(semantic, ref_entries, ref_id)
        .into_iter()
        .any(|r| is_state_setter(semantic, r))
}

/// Checks if `ref_id` synchronously invokes a prop callback.
pub(crate) fn is_prop_call(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> bool {
    get_synchronous_call_chain(semantic, ref_entries, ref_id)
        .into_iter()
        .any(|r| is_prop(semantic, r))
}

/// Checks if `ref_id` synchronously touches a React ref (`ref.current` or `useRef` binding).
pub(crate) fn is_ref_call(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> bool {
    get_synchronous_call_chain(semantic, ref_entries, ref_id)
        .into_iter()
        .any(|r| is_ref_current(semantic, r) || is_ref(semantic, r))
}

/// Finds the `VariableDeclarator` node of the `useState` call upstream from `ref_id`.
pub(crate) fn get_use_state_decl_node(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> Option<NodeId> {
    for up_ref in get_upstream_refs(semantic, ref_entries, ref_id) {
        let ref_node_id = semantic.scoping().get_reference(up_ref).node_id();
        if is_use_state_node(semantic, ref_node_id) {
            return semantic.nodes().ancestor_ids(ref_node_id).find(|&anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::VariableDeclarator(_)
                )
            });
        }
    }
    None
}

/// Extracts the state display name (`count` in `const [count, setCount] = useState()`, or `setCount` if value omitted).
pub(crate) fn get_state_name(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    ref_id: ReferenceId,
) -> Option<String> {
    let decl_id = get_use_state_decl_node(semantic, ref_entries, ref_id)?;
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return None;
    };
    let BindingPattern::ArrayPattern(arr) = &decl.id else {
        return None;
    };
    if let Some(Some(BindingPattern::BindingIdentifier(first))) = arr.elements.first() {
        return Some(first.name.to_string());
    }
    if let Some(Some(BindingPattern::BindingIdentifier(second))) = arr.elements.get(1) {
        return Some(second.name.to_string());
    }
    None
}

/// Checks if a leaf reference in `no-pass-data-to-parent` is a non-data origin (`useState`, `prop`, `useRef`, `ref.current`, or constant).
pub(crate) fn is_non_external_data_leaf(semantic: &Semantic<'_>, ref_id: ReferenceId) -> bool {
    let node_id = semantic.scoping().get_reference(ref_id).node_id();
    is_use_state_node(semantic, node_id)
        || is_prop(semantic, ref_id)
        || is_use_ref_node(semantic, node_id)
        || is_ref_current(semantic, ref_id)
        || is_constant(semantic, ref_id)
}

/// Extracts all in-place property assignments and array-mutating method calls from `semantic`.
pub(crate) fn extract_mutations(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
) -> Vec<MutationSiteIr> {
    let _ = ref_entries;
    let mut mutations = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::AssignmentExpression(assign) => {
                let Some(member) = assign.left.as_member_expression() else {
                    continue;
                };
                let Expression::Identifier(root_ident) = member.object().without_parentheses()
                else {
                    continue;
                };
                let is_state_slot = root_ident
                    .reference_id
                    .get()
                    .is_some_and(|ref_id| is_state(semantic, ref_id));
                let subject_name = find_enclosing_react_node(semantic, node_id)
                    .and_then(|subj_id| get_subject_name(semantic, subj_id));
                mutations.push(MutationSiteIr {
                    target_name: root_ident.name.to_string(),
                    is_state_slot,
                    expression_text: assign
                        .span
                        .source_text(semantic.source_text())
                        .trim()
                        .to_string(),
                    subject_name,
                    span: ByteSpan {
                        start: assign.span.start,
                        end: assign.span.end,
                    },
                    loc: loc_from_line_starts(line_starts, assign.span.start),
                });
            }
            AstKind::CallExpression(call) => {
                let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                else {
                    continue;
                };
                if !MUTATING_ARRAY_METHODS.contains(&mem.property.name.as_str()) {
                    continue;
                }
                let Expression::Identifier(root_ident) = mem.object.without_parentheses() else {
                    continue;
                };
                let is_state_slot = root_ident
                    .reference_id
                    .get()
                    .is_some_and(|ref_id| is_state(semantic, ref_id));
                if !is_state_slot {
                    continue;
                }
                let subject_name = find_enclosing_react_node(semantic, node_id)
                    .and_then(|subj_id| get_subject_name(semantic, subj_id));
                mutations.push(MutationSiteIr {
                    target_name: root_ident.name.to_string(),
                    is_state_slot: true,
                    expression_text: call
                        .span
                        .source_text(semantic.source_text())
                        .trim()
                        .to_string(),
                    subject_name,
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    loc: loc_from_line_starts(line_starts, call.span.start),
                });
            }
            _ => {}
        }
    }

    mutations
}

/// Extracts all `await <expr>` sites and records whether each is nested inside a loop.
pub(crate) fn extract_async_flows(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<AsyncFlowIr> {
    let mut flows = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::AwaitExpression(await_expr) = node.kind() else {
            continue;
        };
        let mut inside_loop = false;
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            match semantic.nodes().kind(anc_id) {
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
                AstKind::ForStatement(_)
                | AstKind::ForOfStatement(_)
                | AstKind::ForInStatement(_)
                | AstKind::WhileStatement(_)
                | AstKind::DoWhileStatement(_) => {
                    inside_loop = true;
                    break;
                }
                _ => {}
            }
        }
        let enclosing_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));
        flows.push(AsyncFlowIr {
            awaited_expr: await_expr
                .argument
                .span()
                .source_text(semantic.source_text())
                .trim()
                .to_string(),
            inside_loop,
            enclosing_name,
            span: ByteSpan {
                start: await_expr.span.start,
                end: await_expr.span.end,
            },
            loc: loc_from_line_starts(line_starts, await_expr.span.start),
        });
    }
    flows
}

/// Extracts all security-sensitive sinks (`dangerouslySetInnerHTML`, `innerHTML`, `eval`, dynamic `process.env[k]`, unauthenticated server actions).
pub(crate) fn extract_security_sinks(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
) -> Vec<SecuritySinkIr> {
    let mut sinks = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::JSXAttribute(attr) => {
                if let Some(ident) = attr.name.as_identifier()
                    && ident.name == "dangerouslySetInnerHTML"
                {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|subj_id| get_subject_name(semantic, subj_id));
                    sinks.push(SecuritySinkIr {
                        kind: SecuritySinkKind::DangerouslySetInnerHtml,
                        target_name: "dangerouslySetInnerHTML".to_string(),
                        subject_name,
                        span: ByteSpan {
                            start: attr.span.start,
                            end: attr.span.end,
                        },
                        loc: loc_from_line_starts(line_starts, attr.span.start),
                    });
                }
            }
            AstKind::AssignmentExpression(assign) => {
                if let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                    && (mem.property.name == "innerHTML" || mem.property.name == "outerHTML")
                {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|subj_id| get_subject_name(semantic, subj_id));
                    sinks.push(SecuritySinkIr {
                        kind: SecuritySinkKind::InnerHtmlAssignment,
                        target_name: mem.property.name.to_string(),
                        subject_name,
                        span: ByteSpan {
                            start: assign.span.start,
                            end: assign.span.end,
                        },
                        loc: loc_from_line_starts(line_starts, assign.span.start),
                    });
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::Identifier(ident) = call.callee.without_parentheses()
                    && ident.name == "eval"
                {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|subj_id| get_subject_name(semantic, subj_id));
                    sinks.push(SecuritySinkIr {
                        kind: SecuritySinkKind::DynamicCodeEval,
                        target_name: "eval".to_string(),
                        subject_name,
                        span: ByteSpan {
                            start: call.span.start,
                            end: call.span.end,
                        },
                        loc: loc_from_line_starts(line_starts, call.span.start),
                    });
                }
            }
            AstKind::ComputedMemberExpression(comp) => {
                if let Expression::StaticMemberExpression(inner) = comp.object.without_parentheses()
                    && inner.property.name == "env"
                    && matches!(
                        inner.object.without_parentheses(),
                        Expression::Identifier(id) if id.name == "process"
                    )
                    && !matches!(
                        comp.expression.without_parentheses(),
                        Expression::StringLiteral(_)
                    )
                {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|subj_id| get_subject_name(semantic, subj_id));
                    sinks.push(SecuritySinkIr {
                        kind: SecuritySinkKind::DynamicProcessEnv,
                        target_name: "process.env".to_string(),
                        subject_name,
                        span: ByteSpan {
                            start: comp.span.start,
                            end: comp.span.end,
                        },
                        loc: loc_from_line_starts(line_starts, comp.span.start),
                    });
                }
            }
            _ => {}
        }
    }

    if module.has_use_server {
        for stmt in &program.body {
            if let Statement::ExportDeclaration(exp) = stmt
                && let Declaration::FunctionDeclaration(func) = &exp.declaration
                && func.r#async
                && let Some(id) = &func.id
                && let Some(body) = &func.body
            {
                let body_text = body.span.source_text(semantic.source_text());
                let has_auth_guard = AUTH_GUARD_FUNCTION_NAMES
                    .iter()
                    .any(|guard| body_text.contains(guard));
                if !has_auth_guard {
                    sinks.push(SecuritySinkIr {
                        kind: SecuritySinkKind::UnauthenticatedServerAction,
                        target_name: id.name.to_string(),
                        subject_name: Some(id.name.to_string()),
                        span: ByteSpan {
                            start: func.span.start,
                            end: func.span.end,
                        },
                        loc: loc_from_line_starts(line_starts, func.span.start),
                    });
                }
            }
        }
    }

    sinks
}

/// Extracts framework-specific semantic rule sites from the single-pass AST and scope tree.
pub(crate) fn extract_semantic_rule_sites(
    path: &Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    _ref_entries: &[RefEntry],
    line_starts: &[u32],
) -> Vec<SemanticRuleSite> {
    let mut sites = Vec::new();

    crate::rules::tanstack::extract_tanstack_sites(
        path,
        program,
        semantic,
        line_starts,
        &mut sites,
    );
    crate::rules::react_native::extract_react_native_sites(
        path,
        program,
        semantic,
        line_starts,
        &mut sites,
    );
    crate::rules::react_router::extract_react_router_sites(
        path,
        program,
        semantic,
        line_starts,
        &mut sites,
    );
    crate::rules::stores::extract_store_sites(program, semantic, line_starts, &mut sites);
    crate::rules::ecosystem_ui::extract_ecosystem_ui_sites(
        program,
        semantic,
        line_starts,
        &mut sites,
    );

    sites
}
