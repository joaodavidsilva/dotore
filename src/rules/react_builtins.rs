//! `react-builtins` rule family detectors (`exhaustive-deps` with local callback ownership,
//! `rules-of-hooks`, `button-has-type` with `Autofix`, `checked-requires-onchange-or-readonly`,
//! `only-export-components`, `jsx-no-target-blank`, `self-closing-comp`, `jsx-boolean-value`,
//! `jsx-curly-brace-presence`, `jsx-no-script-url`, `style-prop-object`, `no-unknown-property`,
//! `no-string-refs`, and cross-file `ProjectGraph` cold-path gating for inline prop rules).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, ChainElement, Expression, JSXAttributeItem,
        JSXAttributeValue, JSXElement, JSXOpeningElement, Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr, SemanticRuleSite,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_body_statements,
            get_subject_name, is_component_name, is_custom_hook_name, is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, ByteEdit, Diagnostic, RuleId, RuleSeverity},
};

const DEPS_HOOK_NAMES: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useMemo",
    "useCallback",
    "useImperativeHandle",
    "useInsertionEffect",
];

const UNKNOWN_DOM_PROP_FIXES: &[(&str, &str)] = &[
    ("class", "className"),
    ("for", "htmlFor"),
    ("tabindex", "tabIndex"),
    ("autocomplete", "autoComplete"),
    ("autofocus", "autoFocus"),
    ("readonly", "readOnly"),
    ("maxlength", "maxLength"),
    ("minlength", "minLength"),
    ("colspan", "colSpan"),
    ("rowspan", "rowSpan"),
    ("stroke-width", "strokeWidth"),
    ("stroke-linecap", "strokeLinecap"),
    ("stroke-linejoin", "strokeLinejoin"),
    ("fill-rule", "fillRule"),
    ("clip-rule", "clipRule"),
];

/// Extracts all single-pass `react-builtins` semantic rule sites and autofixes.
pub(crate) fn extract_react_builtins_sites(
    semantic: &Semantic<'_>,
    path: &Path,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_exhaustive_deps_in_file(semantic, line_starts, sites);
    check_rules_of_hooks_in_file(semantic, line_starts, sites);
    check_jsx_builtin_rules_in_file(semantic, line_starts, sites);
    check_only_export_components_in_file(semantic, path, line_starts, sites);
    check_class_and_component_builtin_rules_in_file(semantic, line_starts, sites);
}

fn check_exhaustive_deps_in_file(
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
    let callee_name = match call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    matches!(callee_name, Some("memo" | "forwardRef"))
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
            let ref_id = ident.reference_id.get()?;
            let sym_id = semantic.scoping().get_reference(ref_id).symbol_id()?;
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
    // First pass: collect all member-read chains (`currentUser.uid`, `props.value`) and bare identifier reads
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
        let Some(ref_id) = ident.reference_id.get() else {
            continue;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
            continue;
        };
        if semantic
            .scoping()
            .symbol_flags(sym_id)
            .contains(SymbolFlags::Import)
        {
            continue;
        }
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        let decl_span = semantic.nodes().get_node(decl_id).span();

        // Must be declared inside `subj_span`, and outside `cb_span`
        if !subj_span.contains_inclusive(decl_span) || cb_span.contains_inclusive(decl_span) {
            continue;
        }

        // Skip stable hook bindings (`useState` setter, `useReducer` dispatch, `useRef` container)
        if is_stable_hook_symbol(semantic, sym_id, decl_id) {
            continue;
        }

        // Check if this identifier is the root object of a static member expression (`currentUser.uid`)
        if let Some(full_chain) =
            extract_enclosing_static_member_chain(semantic, node_id, &ident.name)
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

    let mut missing = Vec::new();
    for (candidate, is_member_chain) in ordered_candidates {
        if !is_member_chain {
            // If `candidate` is a bare root (e.g. `currentUser`) that was ONLY read in an `if` null guard,
            // and at least one of its member chains (`currentUser.uid`) is in `declared_deps`, skip!
            if !non_guard_bare_roots.contains(&candidate)
                && let Some(chains) = member_chains_by_root.get(&candidate)
                && chains.iter().any(|c| is_dep_satisfied(c, declared_deps))
            {
                continue;
            }
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

fn check_rules_of_hooks_in_file(
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

        let loc = loc_from_line_starts(line_starts, call.span.start);
        let span = ByteSpan {
            start: call.span.start,
            end: call.span.end,
        };

        let Some(fn_id) = enclosing_fn_id else {
            sites.push(SemanticRuleSite {
                rule: RuleId::RulesOfHooks,
                subject_name: None,
                message_id: "rulesOfHooksTopLevel",
                target_name: hook_name.clone(),
                message: format!(
                    "`{hook_name}` can only run inside a React component or custom Hook because React needs that render scope to track Hook state."
                ),
                loc,
                span,
                autofix: None,
            });
            continue;
        };

        let subj_name = get_subject_name(semantic, fn_id);
        if !is_react_component_or_hook_scope_node(semantic, fn_id) {
            sites.push(SemanticRuleSite {
                rule: RuleId::RulesOfHooks,
                subject_name: subj_name,
                message_id: "rulesOfHooksNonComponent",
                target_name: hook_name.clone(),
                message: format!(
                    "`{hook_name}` is called inside a function that is neither a React function component nor a custom React Hook."
                ),
                loc,
                span,
                autofix: None,
            });
            continue;
        }

        if crossed_loop {
            sites.push(SemanticRuleSite {
                rule: RuleId::RulesOfHooks,
                subject_name: subj_name,
                message_id: "rulesOfHooksLoop",
                target_name: hook_name.clone(),
                message: format!(
                    "`{hook_name}` can run a different number of times inside a loop, so React can attach state to the wrong Hook."
                ),
                loc,
                span,
                autofix: None,
            });
            continue;
        }

        if crossed_conditional
            || crossed_try
            || is_after_early_return_in_fn(semantic, fn_id, call.span.start)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RulesOfHooks,
                subject_name: subj_name,
                message_id: "rulesOfHooksConditional",
                target_name: hook_name.clone(),
                message: format!(
                    "`{hook_name}` changes Hook order between renders when called conditionally or after an early return."
                ),
                loc,
                span,
                autofix: None,
            });
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
            if let Some(ref_id) = ident.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
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

fn check_jsx_builtin_rules_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
        if let AstKind::JSXFragment(jsx_frag) = node.kind() {
            let subj_name = find_enclosing_react_node(semantic, node_id)
                .and_then(|subj_id| get_subject_name(semantic, subj_id));
            check_jsx_no_useless_fragment_short(jsx_frag, &subj_name, semantic, line_starts, sites);
            continue;
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
        && let Some(ref_id) = ident.reference_id.get()
        && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
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

fn strip_ts_and_parens<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut cur = expr.without_parentheses();
    loop {
        match cur {
            Expression::TSAsExpression(ts) => cur = ts.expression.without_parentheses(),
            Expression::TSSatisfiesExpression(ts) => cur = ts.expression.without_parentheses(),
            Expression::TSNonNullExpression(ts) => cur = ts.expression.without_parentheses(),
            _ => return cur,
        }
    }
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

    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };
    let loc = loc_from_line_starts(line_starts, opening.span.start);

    let Some(attr) = type_attr else {
        // Missing `type`: only flag when inside an intrinsic `<form>` ancestor or associated via `form="id"`, and no spread
        if has_spread
            || (!has_nonempty_form_attr && !has_intrinsic_form_ancestor(semantic, jsx_node_id))
        {
            return;
        }
        let insert_pos = opening.name.span().end;
        let patch = AutofixPatch {
            description: "Add `type=\"button\"` to `<button>`".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan {
                    start: insert_pos,
                    end: insert_pos,
                },
                replacement: " type=\"button\"".to_string(),
            }],
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::ButtonHasType,
            subject_name: subj_name.clone(),
            message_id: "buttonHasTypeMissing",
            target_name: "button".to_string(),
            message: "Your users can submit the form by accident because a `<button>` with no `type` defaults to submit.".to_string(),
            loc,
            span,
            autofix: Some(patch),
        });
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
        sites.push(SemanticRuleSite {
            rule: RuleId::ButtonHasType,
            subject_name: subj_name.clone(),
            message_id: "buttonHasTypeInvalid",
            target_name: "button".to_string(),
            message: "This button has an invalid `type`, so the browser may treat it like a submit button.".to_string(),
            loc,
            span,
            autofix: None,
        });
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
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
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
    let span = ByteSpan {
        start: checked.span.start,
        end: checked.span.end,
    };
    let loc = loc_from_line_starts(line_starts, checked.span.start);

    if default_checked_attr.is_some() && !(checked_forwarded && default_checked_forwarded) {
        sites.push(SemanticRuleSite {
            rule: RuleId::CheckedRequiresOnchangeOrReadonly,
            subject_name: subj_name.clone(),
            message_id: "exclusiveCheckedAttribute",
            target_name: "checked".to_string(),
            message: "This input mixes `checked` with `defaultChecked`, so React can't tell whether it is controlled or uncontrolled.".to_string(),
            loc,
            span,
            autofix: None,
        });
    }

    if !has_onchange_or_readonly && !has_spread && !has_truthy_disabled {
        sites.push(SemanticRuleSite {
            rule: RuleId::CheckedRequiresOnchangeOrReadonly,
            subject_name: subj_name.clone(),
            message_id: "checkedRequiresOnchangeOrReadonly",
            target_name: "checked".to_string(),
            message: "Your users can't toggle this input because `checked` has no `onChange` or `readOnly`.".to_string(),
            loc,
            span,
            autofix: None,
        });
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
        let span = ByteSpan {
            start: opening.span.start,
            end: opening.span.end,
        };
        let loc = loc_from_line_starts(line_starts, opening.span.start);
        let insert_pos = opening.name.span().end;
        let patch = AutofixPatch {
            description: "Add `rel=\"noopener noreferrer\"` to `<a target=\"_blank\">`".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan {
                    start: insert_pos,
                    end: insert_pos,
                },
                replacement: " rel=\"noopener noreferrer\"".to_string(),
            }],
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::JsxNoTargetBlank,
            subject_name: subj_name.clone(),
            message_id: "jsxNoTargetBlank",
            target_name: "a".to_string(),
            message: "Using `target=\"_blank\"` without `rel=\"noopener noreferrer\"` exposes the page to reverse tabnabbing.".to_string(),
            loc,
            span,
            autofix: Some(patch),
        });
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
    let span = ByteSpan {
        start: jsx_el.span.start,
        end: jsx_el.span.end,
    };
    let loc = loc_from_line_starts(line_starts, jsx_el.span.start);
    let replace_start = opening.span.end.saturating_sub(1);
    let patch = AutofixPatch {
        description: format!("Convert `<{tag_name}></{tag_name}>` to `<{tag_name} />`"),
        edits: vec![ByteEdit {
            file: None,
            span: ByteSpan {
                start: replace_start,
                end: jsx_el.span.end,
            },
            replacement: " />".to_string(),
        }],
    };
    sites.push(SemanticRuleSite {
        rule: RuleId::SelfClosingComp,
        subject_name: subj_name.clone(),
        message_id: "selfClosingComp",
        target_name: tag_name.to_string(),
        message: format!(
            "Empty `<{tag_name}></{tag_name}>` component should be self-closing (`<{tag_name} />`)."
        ),
        loc,
        span,
        autofix: Some(patch),
    });
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
            sites.push(SemanticRuleSite {
                rule: RuleId::JsxPropsNoSpreading,
                subject_name: subj_name.clone(),
                message_id: "jsxPropsNoSpreading",
                target_name: tag_name.to_string(),
                message: format!(
                    "Avoid spreading arbitrary props (`{{...}}`) onto `<{tag_name}>`; pass explicit props instead."
                ),
                loc: loc_from_line_starts(line_starts, spread.span.start),
                span: ByteSpan {
                    start: spread.span.start,
                    end: spread.span.end,
                },
                autofix: None,
            });
            continue;
        }
            continue;
        };
        let Some(ident) = attr.name.as_identifier() else {
            continue;
        };
        let attr_name = ident.name.as_str();
        let attr_span = ByteSpan {
            start: attr.span.start,
            end: attr.span.end,
        };
        let attr_loc = loc_from_line_starts(line_starts, attr.span.start);

        // 1. `no-unknown-property` on intrinsic DOM tags (`class` -> `className`, `for` -> `htmlFor`, etc.)
        if !is_comp
            && !tag_name.contains('-')
            && let Some(&(_, standard_name)) = UNKNOWN_DOM_PROP_FIXES
                .iter()
                .find(|&&(bad, _)| bad == attr_name)
        {
            let patch = AutofixPatch {
                description: format!("Replace `{attr_name}` with `{standard_name}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: ident.span.start,
                        end: ident.span.end,
                    },
                    replacement: standard_name.to_string(),
                }],
            };
            sites.push(SemanticRuleSite {
                rule: RuleId::NoUnknownProperty,
                subject_name: subj_name.clone(),
                message_id: "noUnknownProperty",
                target_name: attr_name.to_string(),
                message: format!(
                    "Unknown DOM property `{attr_name}` on `<{tag_name}>`; did you mean `{standard_name}`?"
                ),
                loc: attr_loc,
                span: attr_span,
                autofix: Some(patch),
            });
        }

        // 2. `no-string-refs`: `ref="myRef"`
        if attr_name == "ref" && matches!(attr.value, Some(JSXAttributeValue::StringLiteral(_))) {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoStringRefs,
                subject_name: subj_name.clone(),
                message_id: "noStringRefs",
                target_name: "ref".to_string(),
                message: "String refs (`ref=\"...\"`) are deprecated; use `useRef()` or a callback ref instead.".to_string(),
                loc: attr_loc,
                span: attr_span,
                autofix: None,
            });
        }

        // 3. `style-prop-object`: `style="color: red"` on JSX element
        if attr_name == "style" && matches!(attr.value, Some(JSXAttributeValue::StringLiteral(_))) {
            sites.push(SemanticRuleSite {
                rule: RuleId::StylePropObject,
                subject_name: subj_name.clone(),
                message_id: "stylePropObject",
                target_name: "style".to_string(),
                message: "The `style` prop expects a mapping from style properties to values, not a string.".to_string(),
                loc: attr_loc,
                span: attr_span,
                autofix: None,
            });
        }

        // 4. `jsx-no-script-url`: `href="javascript:..."`
        if matches!(attr_name, "href" | "src")
            && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
            && s.value.as_str().is_some_and(|v| {
                v.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("javascript:")
            })
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::JsxNoScriptUrl,
                subject_name: subj_name.clone(),
                message_id: "jsxNoScriptUrl",
                target_name: attr_name.to_string(),
                message: "`javascript:` URLs are a security and XSS hazard; use a `<button>` or a real URL.".to_string(),
                loc: attr_loc,
                span: attr_span,
                autofix: None,
            });
        }

        // 5. `jsx-boolean-value`: `disabled={true}`
        if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
            && let Some(Expression::BooleanLiteral(b)) = c
                .expression
                .as_expression()
                .map(Expression::without_parentheses)
            && b.value
        {
            let patch = AutofixPatch {
                description: format!("Simplify `{attr_name}={{true}}` to `{attr_name}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: attr_span,
                    replacement: attr_name.to_string(),
                }],
            };
            sites.push(SemanticRuleSite {
                rule: RuleId::JsxBooleanValue,
                subject_name: subj_name.clone(),
                message_id: "jsxBooleanValue",
                target_name: attr_name.to_string(),
                message: format!("Omit `={{true}}` on boolean JSX attribute `{attr_name}`."),
                loc: attr_loc,
                span: attr_span,
                autofix: Some(patch),
            });
        }

        // 6. `jsx-curly-brace-presence`: `title={"hello"}`
        if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
            && let Some(Expression::StringLiteral(s)) = c
                .expression
                .as_expression()
                .map(Expression::without_parentheses)
            && !s.value.contains('"')
        {
            let s_text = s.span.source_text(semantic.source_text());
            let patch = AutofixPatch {
                description: format!("Remove unnecessary curly braces around {s_text}"),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: c.span.start,
                        end: c.span.end,
                    },
                    replacement: s_text.to_string(),
                }],
            };
            sites.push(SemanticRuleSite {
                rule: RuleId::JsxCurlyBracePresence,
                subject_name: subj_name.clone(),
                message_id: "jsxCurlyBracePresence",
                target_name: attr_name.to_string(),
                message: format!(
                    "Curly braces are unnecessary around string literal prop `{attr_name}`."
                ),
                loc: attr_loc,
                span: attr_span,
                autofix: Some(patch),
            });
        }
    }
}

fn check_only_export_components_in_file(
    semantic: &Semantic<'_>,
    path: &Path,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let path_str = path.to_string_lossy().replace('\\', "/");
    // Only check `.tsx` and `.jsx` component files; skip route convention files (`_layout.tsx`, `+not-found.tsx`, `layout.tsx`, `page.tsx`, `route.tsx`)
    let is_jsx_ext = path_str.ends_with(".tsx") || path_str.ends_with(".jsx");
    if !is_jsx_ext || is_framework_route_file(&path_str, semantic.source_text()) {
        return;
    }

    let mut has_exported_component = false;
    let mut non_component_exports: Vec<(String, Span)> = Vec::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ExportDeclaration(exp) = node.kind() else {
            continue;
        };
        if exp.export_kind().is_type() {
            continue;
        }
        match &exp.declaration {
            oxc_ast::ast::Declaration::FunctionDeclaration(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let name = id.name.as_str();
                if is_component_name(name) {
                    has_exported_component = true;
                } else if !is_custom_hook_name(name) {
                    non_component_exports.push((name.to_string(), func.span));
                }
            }
            oxc_ast::ast::Declaration::VariableDeclaration(vd) => {
                collect_variable_exports_for_fast_refresh(
                    &vd.declarations,
                    &mut has_exported_component,
                    &mut non_component_exports,
                );
            }
            _ => {}
        }
    }

    if has_exported_component {
        for (export_name, span) in non_component_exports {
            sites.push(SemanticRuleSite {
                rule: RuleId::OnlyExportComponents,
                subject_name: None,
                message_id: "onlyExportComponents",
                target_name: export_name,
                message: "This file exports non-components alongside components, so Fast Refresh can't safely preserve component state.".to_string(),
                loc: loc_from_line_starts(line_starts, span.start),
                span: ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                autofix: None,
            });
        }
    }
}

fn collect_variable_exports_for_fast_refresh(
    declarations: &[oxc_ast::ast::VariableDeclarator<'_>],
    has_exported_component: &mut bool,
    non_component_exports: &mut Vec<(String, Span)>,
) {
    for declarator in declarations {
        let BindingPattern::BindingIdentifier(id) = &declarator.id else {
            continue;
        };
        let name = id.name.as_str();
        if is_component_name(name) {
            if declarator.init.as_ref().is_some_and(is_create_context_call) {
                non_component_exports.push((name.to_string(), declarator.span));
            } else {
                *has_exported_component = true;
            }
        } else if !is_custom_hook_name(name)
            && declarator
                .init
                .as_ref()
                .is_some_and(|init| !is_allowed_constant_export_init(init))
        {
            non_component_exports.push((name.to_string(), declarator.span));
        }
    }
}

fn is_framework_route_file(path_str: &str, source: &str) -> bool {
    let file_name = path_str.rsplit('/').next().unwrap_or(path_str);
    if matches!(
        file_name,
        "_layout.tsx"
            | "_layout.jsx"
            | "+not-found.tsx"
            | "+not-found.jsx"
            | "layout.tsx"
            | "layout.jsx"
            | "page.tsx"
            | "page.jsx"
            | "loading.tsx"
            | "error.tsx"
            | "route.tsx"
    ) && (path_str.contains("/app/")
        || path_str.starts_with("app/")
        || path_str.contains("/routes/")
        || path_str.starts_with("routes/"))
    {
        return true;
    }
    source.contains("createFileRoute(")
        || source.contains("createRootRouteWithContext")
        || source.contains("createLazyFileRoute(")
}

fn is_create_context_call(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = strip_ts_and_parens(expr) else {
        return false;
    };
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => id.name == "createContext",
        Expression::StaticMemberExpression(mem) => mem.property.name == "createContext",
        _ => false,
    }
}

fn is_allowed_constant_export_init(expr: &Expression<'_>) -> bool {
    let unwrapped = strip_ts_and_parens(expr);
    unwrapped.is_literal()
        || matches!(
            unwrapped,
            Expression::TemplateLiteral(_)
                | Expression::ArrayExpression(_)
                | Expression::ObjectExpression(_)
                | Expression::UnaryExpression(_)
                | Expression::BinaryExpression(_)
        )
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
    // Skip `<*.Provider value={{...}}>` when `context-provider-value-from-unmemoized-local-literal` handles it
    if jsx.name.ends_with(".Provider")
        && is_active(RuleId::ContextProviderValueFromUnmemoizedLocalLiteral).is_some()
    {
        return;
    }

    let resolved_target = graph
        .resolve_target_subject(&file.path, jsx.span, &jsx.name)
        .map(|(_, subj)| subj);

    // If the target component is wrapped in `memo(Comp, customAreEqual)`, reference identity is ignored
    if resolved_target.is_some_and(|subj| subj.has_custom_memo_comparator) {
        return;
    }

    let is_hot_path_for_prop = |prop_name: &str| -> bool {
        let Some(target_subj) = resolved_target else {
            // Unresolved external component in single-file analysis
            return true;
        };
        target_subj.is_memoized
            || jsx.in_array_map
            || target_subj
                .props_in_hook_deps
                .iter()
                .any(|p| p == prop_name)
    };

    // 1. `jsx-no-new-object-as-prop`
    if is_active(RuleId::JsxNoNewObjectAsProp).is_some() {
        for prop_name in &jsx.object_literal_props {
            if is_hot_path_for_prop(prop_name) {
                push_inline_prop_diag(
                    out,
                    file,
                    jsx,
                    RuleId::JsxNoNewObjectAsProp,
                    "jsxNoNewObjectAsProp",
                    prop_name,
                    format!(
                        "Prop `{prop_name}` on `<{}>` receives a fresh object literal on every render.",
                        jsx.name
                    ),
                );
            }
        }
    }

    // 2. `jsx-no-new-array-as-prop`
    if is_active(RuleId::JsxNoNewArrayAsProp).is_some() {
        for prop_name in &jsx.array_literal_props {
            if is_hot_path_for_prop(prop_name) {
                push_inline_prop_diag(
                    out,
                    file,
                    jsx,
                    RuleId::JsxNoNewArrayAsProp,
                    "jsxNoNewArrayAsProp",
                    prop_name,
                    format!(
                        "Prop `{prop_name}` on `<{}>` receives a fresh array allocation on every render.",
                        jsx.name
                    ),
                );
            }
        }
    }

    // 3. `jsx-no-new-function-as-prop`
    if is_active(RuleId::JsxNoNewFunctionAsProp).is_some() {
        for prop_name in &jsx.function_props {
            if is_hot_path_for_prop(prop_name) {
                push_inline_prop_diag(
                    out,
                    file,
                    jsx,
                    RuleId::JsxNoNewFunctionAsProp,
                    "jsxNoNewFunctionAsProp",
                    prop_name,
                    format!(
                        "Prop `{prop_name}` on `<{}>` receives a fresh function on every render.",
                        jsx.name
                    ),
                );
            }
        }
    }

    // 4. `no-inline-prop-on-memo-component` (fires when target Subject is proven `is_memoized`)
    if resolved_target.is_some_and(|subj| subj.is_memoized)
        && is_active(RuleId::NoInlinePropOnMemoComponent).is_some()
    {
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
    let meta = rule.metadata();
    out.push(Diagnostic {
        file: file.path.clone(),
        subject_name: jsx.enclosing_subject.clone(),
        rule,
        category: meta.category,
        severity: meta.default_severity,
        message_id,
        tier: meta.default_tier,
        target_name: target_name.to_string(),
        message,
        docs_url: meta.docs_url,
        loc: jsx.loc,
        span: jsx.span,
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: None,
    });
}

fn check_jsx_no_useless_fragment_short(
    jsx_frag: &oxc_ast::ast::JSXFragment<'_>,
    subj_name: &Option<String>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let meaningful = collect_meaningful_jsx_children(&jsx_frag.children);
    if meaningful.len() > 1 {
        return;
    }
    let autofix = if meaningful.len() == 1
        && let oxc_ast::ast::JSXChild::Element(child_el) = meaningful[0]
    {
        let child_text = child_el.span.source_text(semantic.source_text());
        Some(AutofixPatch {
            description: "Remove redundant `<>...</>` fragment wrapper".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan {
                    start: jsx_frag.span.start,
                    end: jsx_frag.span.end,
                },
                replacement: child_text.to_string(),
            }],
        })
    } else {
        None
    };
    sites.push(SemanticRuleSite {
        rule: RuleId::JsxNoUselessFragment,
        subject_name: subj_name.clone(),
        message_id: "jsxNoUselessFragment",
        target_name: "Fragment".to_string(),
        message: "Fragments with a single child or empty content are redundant.".to_string(),
        loc: loc_from_line_starts(line_starts, jsx_frag.span.start),
        span: ByteSpan {
            start: jsx_frag.span.start,
            end: jsx_frag.span.end,
        },
        autofix,
    });
}

fn check_jsx_fragments_and_useless_fragment_element(
    jsx_el: &JSXElement<'_>,
    tag_name: &str,
    subj_name: &Option<String>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !matches!(tag_name, "Fragment" | "React.Fragment") {
        return;
    }
    let opening = &jsx_el.opening_element;
    if !opening.attributes.is_empty() {
        return;
    }

    // 1. `jsx-fragments`: `<React.Fragment>` or `<Fragment>` with no attributes -> `<>...</>`
    let frag_autofix = jsx_el.closing_element.as_ref().map(|closing| AutofixPatch {
        description: format!("Replace `<{tag_name}>` with shorthand `<>...</>`"),
        edits: vec![
            ByteEdit {
                file: None,
                span: ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                },
                replacement: "<>".to_string(),
            },
            ByteEdit {
                file: None,
                span: ByteSpan {
                    start: closing.span.start,
                    end: closing.span.end,
                },
                replacement: "</>".to_string(),
            },
        ],
    });
    sites.push(SemanticRuleSite {
        rule: RuleId::JsxFragments,
        subject_name: subj_name.clone(),
        message_id: "jsxFragments",
        target_name: tag_name.to_string(),
        message: format!("Prefer shorthand `<>...</>` over `<{tag_name}>` when no `key` is needed."),
        loc: loc_from_line_starts(line_starts, jsx_el.span.start),
        span: ByteSpan {
            start: jsx_el.span.start,
            end: jsx_el.span.end,
        },
        autofix: frag_autofix,
    });

    // 2. `jsx-no-useless-fragment` on `<Fragment>` / `<React.Fragment>` with <= 1 meaningful child
    let meaningful = collect_meaningful_jsx_children(&jsx_el.children);
    if meaningful.len() <= 1 {
        let autofix = if meaningful.len() == 1
            && let oxc_ast::ast::JSXChild::Element(child_el) = meaningful[0]
        {
            let child_text = child_el.span.source_text(semantic.source_text());
            Some(AutofixPatch {
                description: format!("Remove redundant `<{tag_name}>` wrapper"),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: jsx_el.span.start,
                        end: jsx_el.span.end,
                    },
                    replacement: child_text.to_string(),
                }],
            })
        } else {
            None
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::JsxNoUselessFragment,
            subject_name: subj_name.clone(),
            message_id: "jsxNoUselessFragment",
            target_name: tag_name.to_string(),
            message: "Fragments with a single child or empty content are redundant.".to_string(),
            loc: loc_from_line_starts(line_starts, jsx_el.span.start),
            span: ByteSpan {
                start: jsx_el.span.start,
                end: jsx_el.span.end,
            },
            autofix,
        });
    }
}

fn collect_meaningful_jsx_children<'a, 'b>(
    children: &'a [oxc_ast::ast::JSXChild<'b>],
) -> Vec<&'a oxc_ast::ast::JSXChild<'b>> {
    children
        .iter()
        .filter(|c| match c {
            oxc_ast::ast::JSXChild::Text(t) => !t.value.trim().is_empty(),
            oxc_ast::ast::JSXChild::ExpressionContainer(ec) => {
                !matches!(ec.expression, oxc_ast::ast::JSXExpression::EmptyExpression(_))
            }
            _ => true,
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates both jsx-pascal-case and jsx-max-depth on a JSXElement node"
)]
fn check_jsx_pascal_case_and_max_depth(
    semantic: &Semantic<'_>,
    jsx_node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. `jsx-pascal-case`: component name is ALL_CAPS_WITH_UNDERSCORE or starts with `_` or contains `_`
    let check_seg = tag_name.rsplit('.').next().unwrap_or(tag_name);
    let is_bad_pascal = if is_comp {
        check_seg.contains('_')
            || (check_seg.len() > 1
                && check_seg
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
    } else {
        check_seg.starts_with('_')
            && check_seg
                .chars()
                .nth(1)
                .is_some_and(|c| c.is_ascii_uppercase())
    };
    if is_bad_pascal {
        sites.push(SemanticRuleSite {
            rule: RuleId::JsxPascalCase,
            subject_name: subj_name.clone(),
            message_id: "jsxPascalCase",
            target_name: tag_name.to_string(),
            message: format!("Component `<{tag_name}>` must use PascalCase naming."),
            loc: loc_from_line_starts(line_starts, opening.name.span().start),
            span: ByteSpan {
                start: opening.name.span().start,
                end: opening.name.span().end,
            },
            autofix: None,
        });
    }

    // 2. `jsx-max-depth`: flag leaf JSX element at depth > 4
    let has_jsx_el_children =
        if let AstKind::JSXElement(el) = semantic.nodes().kind(jsx_node_id) {
            el.children
                .iter()
                .any(|c| matches!(c, oxc_ast::ast::JSXChild::Element(_)))
        } else {
            false
        };
    if !has_jsx_el_children {
        let mut depth = 0_usize;
        for anc_id in semantic.nodes().ancestor_ids(jsx_node_id) {
            match semantic.nodes().kind(anc_id) {
                AstKind::JSXElement(_) | AstKind::JSXFragment(_) => {
                    depth += 1;
                }
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
                _ => {}
            }
        }
        if depth > 4 {
            sites.push(SemanticRuleSite {
                rule: RuleId::JsxMaxDepth,
                subject_name: subj_name.clone(),
                message_id: "jsxMaxDepth",
                target_name: tag_name.to_string(),
                message: format!(
                    "JSX nesting depth of {depth} exceeds the maximum depth of 4; extract a child component."
                ),
                loc: loc_from_line_starts(line_starts, opening.span.start),
                span: ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_class_and_component_builtin_rules_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::VariableDeclarator(decl) => {
                check_hook_use_state_symmetry(semantic, decl, &subj_name, line_starts, sites);
                check_nested_component_declarator(semantic, node_id, decl, &subj_name, line_starts, sites);
            }
            AstKind::Function(func) => {
                check_nested_component_function(semantic, node_id, func, &subj_name, line_starts, sites);
            }
            AstKind::JSXAttribute(attr) => {
                check_unstable_nested_component_prop(semantic, attr, &subj_name, line_starts, sites);
            }
            AstKind::CallExpression(call) => {
                check_display_name_and_create_class(semantic, node_id, call, &subj_name, line_starts, sites);
            }
            AstKind::Class(cls) => {
                check_react_class_component_rules(semantic, cls, line_starts, sites);
            }
            _ => {}
        }
    }
}

fn check_hook_use_state_symmetry(
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
        sites.push(SemanticRuleSite {
            rule: RuleId::HookUseState,
            subject_name: subj_name.clone(),
            message_id: "hookUseState",
            target_name: setter_id.name.to_string(),
            message: format!(
                "`useState` destructuring `[{}, {}]` is asymmetric; name the setter `{expected_setter}`.",
                state_id.name, setter_id.name
            ),
            loc: loc_from_line_starts(line_starts, arr.span.start),
            span: ByteSpan {
                start: arr.span.start,
                end: arr.span.end,
            },
            autofix: None,
        });
    }
}

fn check_nested_component_declarator(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let Some(enclosing_id) = find_enclosing_react_node(semantic, parent_id) else {
        return;
    };
    let enclosing_subj_name = get_subject_name(semantic, enclosing_id).or_else(|| subj_name.clone());
    let Some(id) = decl.id.get_binding_identifier() else {
        return;
    };
    if !is_component_name(id.name.as_str()) {
        return;
    }
    let Some(init) = &decl.init else {
        return;
    };
    if matches!(
        init.without_parentheses(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) && span_contains_jsx(semantic, init.span())
    {
        let _ = node_id;
        sites.push(SemanticRuleSite {
            rule: RuleId::NoUnstableNestedComponents,
            subject_name: enclosing_subj_name,
            message_id: "noUnstableNestedComponents",
            target_name: id.name.to_string(),
            message: format!(
                "Do not declare component `{}` inside another component; React will recreate its type and reset its state on every render.",
                id.name
            ),
            loc: loc_from_line_starts(line_starts, decl.span.start),
            span: ByteSpan {
                start: decl.span.start,
                end: decl.span.end,
            },
            autofix: None,
        });
    }
}

fn check_nested_component_function(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    func: &oxc_ast::ast::Function<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let Some(enclosing_id) = find_enclosing_react_node(semantic, parent_id) else {
        return;
    };
    let enclosing_subj_name = get_subject_name(semantic, enclosing_id).or_else(|| subj_name.clone());
    let Some(id) = &func.id else {
        return;
    };
    if !is_component_name(id.name.as_str()) || !span_contains_jsx(semantic, func.span) {
        return;
    }
    sites.push(SemanticRuleSite {
        rule: RuleId::NoUnstableNestedComponents,
        subject_name: enclosing_subj_name,
        message_id: "noUnstableNestedComponents",
        target_name: id.name.to_string(),
        message: format!(
            "Do not declare component `{}` inside another component; React will recreate its type and reset its state on every render.",
            id.name
        ),
        loc: loc_from_line_starts(line_starts, func.span.start),
        span: ByteSpan {
            start: func.span.start,
            end: func.span.end,
        },
        autofix: None,
    });
}

fn check_unstable_nested_component_prop(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(ident) = attr.name.as_identifier() else {
        return;
    };
    if ident.name.starts_with("on") || ident.name.starts_with("render") {
        return;
    }
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return;
    };
    let Some(expr) = c.expression.as_expression() else {
        return;
    };
    if matches!(
        expr.without_parentheses(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) && span_contains_jsx(semantic, expr.span())
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoUnstableNestedComponents,
            subject_name: subj_name.clone(),
            message_id: "noUnstableNestedComponents",
            target_name: ident.name.to_string(),
            message: format!(
                "Inline function prop `{}` returns JSX and creates an unstable component on every render.",
                ident.name
            ),
            loc: loc_from_line_starts(line_starts, expr.span().start),
            span: ByteSpan {
                start: expr.span().start,
                end: expr.span().end,
            },
            autofix: None,
        });
    }
}

fn span_contains_jsx(semantic: &Semantic<'_>, span: Span) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        span.contains_inclusive(n.span())
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn check_display_name_and_create_class(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = match call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            if matches!(mem.object.without_parentheses(), Expression::Identifier(obj) if obj.name == "React")
            {
                Some(mem.property.name.as_str())
            } else {
                None
            }
        }
        _ => None,
    };
    let Some(c_name) = callee_name else {
        return;
    };

    // 1. `prefer-es6-class`: `createReactClass({...})` or `React.createClass({...})`
    if matches!(c_name, "createReactClass" | "createClass") {
        sites.push(SemanticRuleSite {
            rule: RuleId::PreferEs6Class,
            subject_name: subj_name.clone(),
            message_id: "preferEs6Class",
            target_name: c_name.to_string(),
            message: format!(
                "`{c_name}({{...}})` is a legacy React class factory; use a function component or an ES6 `class` extending `React.Component`."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
        return;
    }

    // 2. `display-name`: `forwardRef((props, ref) => ...)` or `memo((props) => ...)` without a named function or variable binding + displayName
    if !matches!(c_name, "forwardRef" | "memo") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let is_anonymous_fn = match first_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::FunctionExpression(f) => f.id.is_none(),
        _ => false,
    };
    if !is_anonymous_fn {
        return;
    }
    let parent_kind = semantic.nodes().parent_kind(node_id);
    let assigned_var_name = if let AstKind::VariableDeclarator(decl) = parent_kind {
        decl.id.get_binding_identifier().map(|id| id.name.as_str())
    } else {
        None
    };
    if let Some(v_name) = assigned_var_name
        && semantic
            .source_text()
            .contains(&format!("{v_name}.displayName"))
    {
        return;
    }
    if assigned_var_name.is_none() {
        sites.push(SemanticRuleSite {
            rule: RuleId::DisplayName,
            subject_name: subj_name.clone(),
            message_id: "displayName",
            target_name: c_name.to_string(),
            message: format!(
                "Component wrapped in `{c_name}(...)` is anonymous and has no `displayName`; pass a named function `function MyComponent(...)`."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn is_react_component_class(cls: &oxc_ast::ast::Class<'_>, source: &str) -> bool {
    let header = Span::new(cls.span.start, cls.body.span.start).source_text(source);
    header.contains("extends ")
        && (header.contains("Component") || header.contains("PureComponent"))
}

fn check_react_class_component_rules(
    semantic: &Semantic<'_>,
    cls: &oxc_ast::ast::Class<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_component_class(cls, semantic.source_text()) {
        return;
    }
    let cls_name = cls
        .id
        .as_ref()
        .map_or_else(|| "Component".to_string(), |id| id.name.to_string());

    let mut has_state_or_lifecycle = false;

    for elem in &cls.body.body {
        match elem {
            oxc_ast::ast::ClassElement::PropertyDefinition(prop) if !prop.r#static => {
                if prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("state") {
                    has_state_or_lifecycle = true;
                    sites.push(SemanticRuleSite {
                        rule: RuleId::StateInConstructor,
                        subject_name: Some(cls_name.clone()),
                        message_id: "stateInConstructor",
                        target_name: "state".to_string(),
                        message: format!(
                            "Initialize `this.state` inside the constructor of `{cls_name}` instead of a class property."
                        ),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
            }
            oxc_ast::ast::ClassElement::MethodDefinition(method) if !method.r#static => {
                let Some(m_name) = method
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                if m_name != "render" {
                    has_state_or_lifecycle = true;
                }
                if matches!(
                    m_name.as_str(),
                    "UNSAFE_componentWillMount"
                        | "UNSAFE_componentWillReceiveProps"
                        | "UNSAFE_componentWillUpdate"
                ) {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::NoUnsafe,
                        subject_name: Some(cls_name.clone()),
                        message_id: "noUnsafe",
                        target_name: m_name.clone(),
                        message: format!(
                            "Legacy lifecycle method `{m_name}` in `{cls_name}` is unsafe for concurrent rendering."
                        ),
                        loc: loc_from_line_starts(line_starts, method.key.span().start),
                        span: ByteSpan {
                            start: method.key.span().start,
                            end: method.key.span().end,
                        },
                        autofix: None,
                    });
                }

                if let Some(body) = &method.value.body {
                    check_lifecycle_set_state_calls(
                        semantic,
                        &cls_name,
                        &m_name,
                        body.span,
                        line_starts,
                        sites,
                    );
                }
            }
            _ => {}
        }
    }

    if !has_state_or_lifecycle {
        let cls_src = cls.body.span.source_text(semantic.source_text());
        if !cls_src.contains("this.state")
            && !cls_src.contains("this.setState")
            && !cls_src.contains("this.refs")
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::PreferFunctionComponent,
                subject_name: Some(cls_name.clone()),
                message_id: "preferFunctionComponent",
                target_name: cls_name.clone(),
                message: format!(
                    "Stateless class component `{cls_name}` has no state or lifecycle methods; convert it to a function component."
                ),
                loc: loc_from_line_starts(line_starts, cls.span.start),
                span: ByteSpan {
                    start: cls.span.start,
                    end: cls.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_lifecycle_set_state_calls(
    semantic: &Semantic<'_>,
    cls_name: &str,
    method_name: &str,
    body_span: Span,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let target_rule = match method_name {
        "componentDidMount" => Some((
            RuleId::NoDidMountSetState,
            "noDidMountSetState",
            false,
        )),
        "componentDidUpdate" => Some((
            RuleId::NoDidUpdateSetState,
            "noDidUpdateSetState",
            true,
        )),
        "componentWillUpdate" | "UNSAFE_componentWillUpdate" => Some((
            RuleId::NoWillUpdateSetState,
            "noWillUpdateSetState",
            false,
        )),
        _ => None,
    };
    let Some((rule, message_id, allow_if_guarded)) = target_rule else {
        return;
    };

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
            continue;
        };
        if mem.property.name != "setState"
            || !matches!(
                mem.object.without_parentheses(),
                Expression::ThisExpression(_)
            )
        {
            continue;
        }
        if allow_if_guarded
            && semantic
                .nodes()
                .ancestor_ids(node_id)
                .take_while(|&anc_id| {
                    body_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
                })
                .any(|anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::IfStatement(_)))
        {
            continue;
        }
        sites.push(SemanticRuleSite {
            rule,
            subject_name: Some(cls_name.to_string()),
            message_id,
            target_name: method_name.to_string(),
            message: format!(
                "Do not call `this.setState` inside `{method_name}` in `{cls_name}`."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}
