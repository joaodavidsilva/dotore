//! `ExhaustiveDeps`, `RulesOfHooks`, and `HookUseState` detectors for `react-builtins`.

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{BindingPattern, CallExpression, ChainElement, Expression, Statement},
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

use super::DEPS_HOOK_NAMES;
use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        react_ast::{get_subject_body_statements, get_subject_name},
        types::loc_from_line_starts,
    },
    matchers::{
        callee_name, is_component_name, is_custom_hook_name, is_react_hook_callee,
        push_semantic_site, resolve_ident_symbol,
    },
    rules::types::RuleId,
};

pub(super) fn check_exhaustive_deps_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(hook_name) = DEPS_HOOK_NAMES
            .iter()
            .copied()
            .find(|&h| is_react_hook_callee(semantic, &call.callee, h))
        else {
            continue;
        };
        let Some(subj_id) = find_enclosing_hook_or_component_scope(semantic, node_id) else {
            continue;
        };
        let subj_span = semantic.nodes().get_node(subj_id).span();
        let subj_name = get_subject_name(semantic, subj_id);

        let cb_arg_idx = usize::from(hook_name == "useImperativeHandle");
        let deps_arg_idx = cb_arg_idx + 1;

        let Some(cb_arg) = call
            .arguments
            .get(cb_arg_idx)
            .and_then(|a| a.as_expression())
        else {
            continue;
        };
        let Some(deps_arg) = call
            .arguments
            .get(deps_arg_idx)
            .and_then(|a| a.as_expression())
        else {
            continue;
        };
        let Expression::ArrayExpression(deps_arr) = deps_arg.without_parentheses() else {
            continue;
        };

        // Resolve callback node (inline arrow/function OR local callback identifier in same Subject)
        let Some(cb_span) = resolve_hook_callback_span(semantic, cb_arg, subj_span) else {
            continue;
        };

        // Parse declared dependencies and check for complex computed call deps (`items[index]()`)
        let mut declared_deps: Vec<String> = Vec::new();
        let mut has_complex_dep = false;
        for elem in &deps_arr.elements {
            let Some(expr) = elem.as_expression() else {
                continue;
            };
            if is_computed_callee_call_dep(expr) {
                has_complex_dep = true;
                sites.push(SemanticRuleSite {
                    rule: RuleId::ExhaustiveDeps,
                    subject_name: subj_name.clone(),
                    message_id: "exhaustiveDepsComplex",
                    target_name: hook_name.to_string(),
                    message: format!(
                        "React Hook `{hook_name}` has a complex expression in the dependency array. Extract it to a separate variable so it can be statically checked."
                    ),
                    loc: loc_from_line_starts(line_starts, expr.span().start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
            }
            if let Some(norm) = normalize_dep_expr(expr, semantic.source_text()) {
                declared_deps.push(norm);
            }
        }
        if has_complex_dep {
            continue;
        }

        // Collect reactive captures inside `cb_span`
        let missing = collect_missing_hook_deps(semantic, cb_span, subj_span, &declared_deps);
        if !missing.is_empty() {
            let missing_list = missing.join("', '");
            sites.push(SemanticRuleSite {
                rule: RuleId::ExhaustiveDeps,
                subject_name: subj_name,
                message_id: "exhaustiveDeps",
                target_name: missing[0].clone(),
                message: format!(
                    "React Hook `{hook_name}` has missing dependencies: '{missing_list}'. Either include them or remove the dependency array."
                ),
                loc: loc_from_line_starts(line_starts, deps_arr.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn find_enclosing_hook_or_component_scope(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<NodeId> {
    semantic
        .nodes()
        .ancestor_ids(node_id)
        .find(|&anc_id| is_react_component_or_hook_scope_node(semantic, anc_id))
}

fn is_react_component_or_hook_scope_node(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(func) => {
            if let Some(id) = &func.id
                && (is_component_name(&id.name)
                    || is_custom_hook_name(&id.name)
                    || is_underscore_pascal_case(&id.name))
            {
                return true;
            }
            is_direct_arg_of_memo_or_forward_ref(semantic, node_id)
        }
        AstKind::ArrowFunctionExpression(_) => {
            let parent_id = semantic.nodes().parent_id(node_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && (is_component_name(&id.name)
                    || is_custom_hook_name(&id.name)
                    || is_underscore_pascal_case(&id.name))
            {
                return true;
            }
            is_direct_arg_of_memo_or_forward_ref(semantic, node_id)
        }
        _ => false,
    }
}

fn is_underscore_pascal_case(name: &str) -> bool {
    let trimmed = name.trim_start_matches('_');
    trimmed.len() < name.len() && is_component_name(trimmed)
}

fn is_direct_arg_of_memo_or_forward_ref(semantic: &Semantic<'_>, fn_node_id: NodeId) -> bool {
    let parent_id = semantic.nodes().parent_id(fn_node_id);
    let AstKind::CallExpression(call) = semantic.nodes().kind(parent_id) else {
        return false;
    };
    matches!(callee_name(&call.callee), Some("memo" | "forwardRef"))
}

fn resolve_hook_callback_span(
    semantic: &Semantic<'_>,
    cb_arg: &Expression<'_>,
    subj_span: Span,
) -> Option<Span> {
    match cb_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => Some(arrow.span),
        Expression::FunctionExpression(func) => Some(func.span),
        Expression::Identifier(ident) => {
            let sym_id = resolve_ident_symbol(semantic, ident)?;
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !subj_span.contains_inclusive(decl_node.span()) {
                return None;
            }
            match decl_node.kind() {
                AstKind::Function(func) => Some(func.span),
                AstKind::VariableDeclarator(decl) => {
                    let init = decl.init.as_ref()?.without_parentheses();
                    if matches!(
                        init,
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    ) {
                        Some(init.span())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_computed_callee_call_dep(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return false;
    };
    has_computed_member_in_chain(&call.callee)
}

fn has_computed_member_in_chain(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ComputedMemberExpression(_) => true,
        Expression::StaticMemberExpression(mem) => has_computed_member_in_chain(&mem.object),
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::ComputedMemberExpression(_) => true,
            ChainElement::StaticMemberExpression(mem) => has_computed_member_in_chain(&mem.object),
            _ => false,
        },
        _ => false,
    }
}

fn normalize_dep_expr(expr: &Expression<'_>, source: &str) -> Option<String> {
    let unwrapped = expr.without_parentheses();
    if let Expression::CallExpression(call) = unwrapped
        && call.arguments.is_empty()
    {
        return normalize_dep_expr(&call.callee, source);
    }
    let raw = unwrapped.span().source_text(source).trim();
    if raw.is_empty() {
        return None;
    }
    Some(raw.replace("?.", "."))
}

fn collect_missing_hook_deps(
    semantic: &Semantic<'_>,
    cb_span: Span,
    subj_span: Span,
    declared_deps: &[String],
) -> Vec<String> {
    let mut member_chains_by_root: HashMap<String, Vec<String>> = HashMap::new();
    let mut non_guard_bare_roots: HashSet<String> = HashSet::new();
    let mut ordered_candidates: Vec<(String, bool)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::IdentifierReference(ident) = node.kind() else {
            continue;
        };
        record_hook_dep_candidate(
            semantic,
            node_id,
            ident,
            cb_span,
            subj_span,
            &mut member_chains_by_root,
            &mut non_guard_bare_roots,
            &mut ordered_candidates,
        );
    }

    filter_unsatisfied_hook_deps(
        ordered_candidates,
        &non_guard_bare_roots,
        &member_chains_by_root,
        declared_deps,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Records candidate hook dependencies into member-chain and bare-root accumulators (#50)"
)]
fn record_hook_dep_candidate(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
    cb_span: Span,
    subj_span: Span,
    member_chains_by_root: &mut HashMap<String, Vec<String>>,
    non_guard_bare_roots: &mut HashSet<String>,
    ordered_candidates: &mut Vec<(String, bool)>,
) {
    let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
        return;
    };
    if semantic
        .scoping()
        .symbol_flags(sym_id)
        .contains(SymbolFlags::Import)
    {
        return;
    }
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let decl_span = semantic.nodes().get_node(decl_id).span();

    if !subj_span.contains_inclusive(decl_span) || cb_span.contains_inclusive(decl_span) {
        return;
    }
    if is_stable_hook_symbol(semantic, sym_id, decl_id) {
        return;
    }

    if let Some(full_chain) = extract_enclosing_static_member_chain(semantic, node_id, &ident.name)
    {
        member_chains_by_root
            .entry(ident.name.to_string())
            .or_default()
            .push(full_chain.clone());
        ordered_candidates.push((full_chain, true));
    } else {
        if !is_null_guard_only_read(semantic, node_id) {
            non_guard_bare_roots.insert(ident.name.to_string());
        }
        ordered_candidates.push((ident.name.to_string(), false));
    }
}

fn filter_unsatisfied_hook_deps(
    ordered_candidates: Vec<(String, bool)>,
    non_guard_bare_roots: &HashSet<String>,
    member_chains_by_root: &HashMap<String, Vec<String>>,
    declared_deps: &[String],
) -> Vec<String> {
    let mut missing = Vec::new();
    for (candidate, is_member_chain) in ordered_candidates {
        if !is_member_chain
            && !non_guard_bare_roots.contains(&candidate)
            && let Some(chains) = member_chains_by_root.get(&candidate)
            && chains.iter().any(|c| is_dep_satisfied(c, declared_deps))
        {
            continue;
        }
        if !is_dep_satisfied(&candidate, declared_deps) && !missing.contains(&candidate) {
            missing.push(candidate);
        }
    }
    missing
}

fn is_dep_satisfied(required: &str, declared_deps: &[String]) -> bool {
    for decl in declared_deps {
        if decl == required {
            return true;
        }
        // A declared parent object `user` satisfies `user.id`
        if let Some(rest) = required.strip_prefix(decl.as_str())
            && rest.starts_with('.')
        {
            return true;
        }
    }
    false
}

fn is_stable_hook_symbol(semantic: &Semantic<'_>, sym_id: SymbolId, decl_id: NodeId) -> bool {
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    if is_react_hook_callee(semantic, &call.callee, "useRef") {
        return true;
    }
    if (is_react_hook_callee(semantic, &call.callee, "useState")
        || is_react_hook_callee(semantic, &call.callee, "useReducer"))
        && let BindingPattern::ArrayPattern(arr) = &decl.id
        && let Some(Some(BindingPattern::BindingIdentifier(second))) = arr.elements.get(1)
    {
        return second.symbol_id.get() == Some(sym_id);
    }
    false
}

fn extract_enclosing_static_member_chain(
    semantic: &Semantic<'_>,
    ident_node_id: NodeId,
    root_name: &str,
) -> Option<String> {
    let mut parts = vec![root_name.to_string()];
    let mut current_span = semantic.nodes().get_node(ident_node_id).span();

    for anc_id in semantic.nodes().ancestor_ids(ident_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::StaticMemberExpression(mem) => {
                if !mem.object.span().contains_inclusive(current_span) {
                    break;
                }
                parts.push(mem.property.name.to_string());
                current_span = mem.span;
            }
            AstKind::ChainExpression(chain) => {
                current_span = chain.span;
            }
            _ => break,
        }
    }

    if parts.len() >= 2 {
        Some(parts.join("."))
    } else {
        None
    }
}

fn is_null_guard_only_read(semantic: &Semantic<'_>, ident_node_id: NodeId) -> bool {
    let ident_span = semantic.nodes().get_node(ident_node_id).span();
    for anc_id in semantic.nodes().ancestor_ids(ident_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::LogicalExpression(_) | AstKind::UnaryExpression(_) => {}
            AstKind::IfStatement(if_stmt) => {
                return if_stmt.test.span().contains_inclusive(ident_span);
            }
            AstKind::ConditionalExpression(cond) => {
                return cond.test.span().contains_inclusive(ident_span);
            }
            _ => return false,
        }
    }
    false
}

pub(super) fn check_rules_of_hooks_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Some(hook_name) = extract_react_hook_call_name(semantic, call) else {
            continue;
        };

        let mut crossed_conditional = false;
        let mut crossed_loop = false;
        let mut crossed_try = false;
        let mut enclosing_fn_id: Option<NodeId> = None;

        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            match semantic.nodes().kind(anc_id) {
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                    enclosing_fn_id = Some(anc_id);
                    break;
                }
                AstKind::IfStatement(_)
                | AstKind::ConditionalExpression(_)
                | AstKind::LogicalExpression(_)
                | AstKind::SwitchCase(_) => {
                    crossed_conditional = true;
                }
                AstKind::ForStatement(_)
                | AstKind::ForOfStatement(_)
                | AstKind::ForInStatement(_)
                | AstKind::WhileStatement(_)
                | AstKind::DoWhileStatement(_) => {
                    crossed_loop = true;
                }
                AstKind::TryStatement(_) | AstKind::CatchClause(_) => {
                    crossed_try = true;
                }
                _ => {}
            }
        }

        let Some(fn_id) = enclosing_fn_id else {
            push_semantic_site(
                sites,
                RuleId::RulesOfHooks,
                None,
                "rulesOfHooksTopLevel",
                &hook_name,
                format!(
                    "`{hook_name}` can only run inside a React component or custom Hook because React needs that render scope to track Hook state."
                ),
                line_starts,
                call.span,
            );
            continue;
        };

        let subj_name = get_subject_name(semantic, fn_id);
        if !is_react_component_or_hook_scope_node(semantic, fn_id) {
            push_semantic_site(
                sites,
                RuleId::RulesOfHooks,
                subj_name,
                "rulesOfHooksNonComponent",
                &hook_name,
                format!(
                    "`{hook_name}` is called inside a function that is neither a React function component nor a custom React Hook."
                ),
                line_starts,
                call.span,
            );
            continue;
        }

        if crossed_loop {
            push_semantic_site(
                sites,
                RuleId::RulesOfHooks,
                subj_name,
                "rulesOfHooksLoop",
                &hook_name,
                format!(
                    "`{hook_name}` can run a different number of times inside a loop, so React can attach state to the wrong Hook."
                ),
                line_starts,
                call.span,
            );
            continue;
        }

        if crossed_conditional
            || crossed_try
            || is_after_early_return_in_fn(semantic, fn_id, call.span.start)
        {
            push_semantic_site(
                sites,
                RuleId::RulesOfHooks,
                subj_name,
                "rulesOfHooksConditional",
                &hook_name,
                format!(
                    "`{hook_name}` changes Hook order between renders when called conditionally or after an early return."
                ),
                line_starts,
                call.span,
            );
        }
    }
}

fn extract_react_hook_call_name(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
) -> Option<String> {
    match call.callee.without_parentheses() {
        Expression::Identifier(ident) => {
            if !is_custom_hook_name(&ident.name) {
                return None;
            }
            if let Some(sym_id) = resolve_ident_symbol(semantic, ident) {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                if matches!(
                    semantic.nodes().kind(decl_id),
                    AstKind::FormalParameter(_) | AstKind::CatchParameter(_)
                ) {
                    return None;
                }
            }
            Some(ident.name.to_string())
        }
        Expression::StaticMemberExpression(mem) => {
            if is_custom_hook_name(&mem.property.name)
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "React"
                )
            {
                Some(mem.property.name.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_after_early_return_in_fn(semantic: &Semantic<'_>, fn_id: NodeId, call_start: u32) -> bool {
    let Some(stmts) = get_subject_body_statements(semantic, fn_id) else {
        return false;
    };
    for stmt in stmts {
        if stmt.span().end <= call_start && statement_contains_early_return(stmt) {
            return true;
        }
    }
    false
}

fn statement_contains_early_return(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::IfStatement(if_stmt) => {
            statement_contains_early_return(&if_stmt.consequent)
                || if_stmt
                    .alternate
                    .as_ref()
                    .is_some_and(statement_contains_early_return)
        }
        Statement::BlockStatement(blk) => blk.body.iter().any(statement_contains_early_return),
        _ => false,
    }
}

pub(super) fn check_hook_use_state_symmetry(
    semantic: &Semantic<'_>,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return;
    };
    if !is_react_hook_callee(semantic, &call.callee, "useState") {
        return;
    }
    let BindingPattern::ArrayPattern(arr) = &decl.id else {
        return;
    };
    let Some(Some(first_pat)) = arr.elements.first() else {
        return;
    };
    let Some(Some(second_pat)) = arr.elements.get(1) else {
        return;
    };
    let Some(state_id) = first_pat.get_binding_identifier() else {
        return;
    };
    let Some(setter_id) = second_pat.get_binding_identifier() else {
        return;
    };
    let state_clean = state_id.name.trim_matches('_');
    let setter_clean = setter_id.name.trim_matches('_');
    if state_clean.is_empty() || setter_clean.is_empty() {
        return;
    }
    let expected_setter = {
        let mut s = String::from("set");
        let mut chars = state_clean.chars();
        if let Some(first) = chars.next() {
            s.push(first.to_ascii_uppercase());
            s.push_str(chars.as_str());
        }
        s
    };
    if !setter_clean.eq_ignore_ascii_case(&expected_setter) {
        push_semantic_site(
            sites,
            RuleId::HookUseState,
            subj_name.clone(),
            "hookUseState",
            setter_id.name.as_str(),
            format!(
                "`useState` destructuring `[{}, {}]` is asymmetric; name the setter `{expected_setter}`.",
                state_id.name, setter_id.name
            ),
            line_starts,
            arr.span,
        );
    }
}
