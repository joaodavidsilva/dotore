//! Subject hoisting (`prefer-module-scope-static-value`, `prefer-module-scope-pure-function`),
//! nested component definitions (`no-nested-component-definition`), and React Compiler
//! manual memoization (`react-compiler-no-manual-memoization`) rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Expression, JSXAttributeValue, Statement, UnaryOperator,
        VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::{
    component_contracts::{
        check_generic_handler_name_attr, check_inline_hoc_and_render_in_render,
        check_subject_size_complexity_and_props,
    },
    is_reference_in_jsx,
};
use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        react_ast::{
            classify_jsx_element_name, get_subject_body_statements, get_subject_name,
            is_component_name, is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    matchers::{
        push_semantic_site, push_semantic_site_with_fix, resolve_ident_symbol, span_to_byte_span,
        unparenthesized,
    },
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

const SCALAR_LOOKUP_METHODS: &[&str] = &[
    "includes",
    "indexOf",
    "lastIndexOf",
    "has",
    "some",
    "every",
    "find",
    "findIndex",
];

const MUTATING_METHODS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
    "set",
    "add",
    "delete",
    "clear",
];

pub(super) fn check_subject_architecture_rules(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let Some(subj_name) = get_subject_name(semantic, subject_node_id) else {
        return;
    };
    let top_insert_offset = find_top_level_statement_start(semantic, subject_node_id);
    check_subject_size_complexity_and_props(
        semantic,
        subject_node_id,
        &subj_name,
        line_starts,
        sites,
    );

    // Collect rendered PascalCase JSX elements or attribute references inside `subj_span`
    let mut rendered_pascal_names: HashSet<String> = HashSet::new();
    for (inner_node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::JSXOpeningElement(opening) => {
                let (tag_name, _, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);
                if is_comp {
                    rendered_pascal_names.insert(tag_name);
                }
            }
            AstKind::JSXAttribute(attr) => {
                if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
                    && let Some(Expression::Identifier(id)) =
                        c.expression.as_expression().map(unparenthesized)
                    && is_component_name(&id.name)
                {
                    rendered_pascal_names.insert(id.name.to_string());
                }
                check_generic_handler_name_attr(attr, &subj_name, line_starts, sites);
            }
            AstKind::CallExpression(call)
                if is_react_hook_callee(semantic, &call.callee, "useMemo")
                    || is_react_hook_callee(semantic, &call.callee, "useCallback") =>
            {
                push_semantic_site(
                    sites,
                    RuleId::ReactCompilerNoManualMemoization,
                    Some(subj_name.clone()),
                    "reactCompilerNoManualMemoization",
                    &subj_name,
                    "Manual `useMemo`/`useCallback` memoization can be simplified when React Compiler is enabled.".to_string(),
                    line_starts,
                    call.span,
                );
            }
            AstKind::CallExpression(call) => {
                check_inline_hoc_and_render_in_render(
                    semantic,
                    subject_node_id,
                    inner_node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }

    // Inspect direct statements inside the Subject body
    let Some(stmts) = get_subject_body_statements(semantic, subject_node_id) else {
        return;
    };

    for stmt in stmts {
        match stmt {
            Statement::FunctionDeclaration(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let fn_name = id.name.as_str();
                if is_component_name(fn_name) {
                    if rendered_pascal_names.contains(fn_name) {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoNestedComponentDefinition,
                            subject_name: Some(subj_name.clone()),
                            message_id: "noNestedComponentDefinition",
                            target_name: fn_name.to_string(),
                            message: format!(
                                "Your users lose all state in \"{fn_name}\" on every render because it's defined inside \"{subj_name}\", so move it out to the top of the file."
                            ),
                            loc: loc_from_line_starts(line_starts, id.span.start),
                            span: ByteSpan {
                                start: func.span.start,
                                end: func.span.end,
                            },
                            autofix: None,
                        });
                    }
                } else if !has_local_captures_in_span(semantic, func.span, subj_span) {
                    emit_pure_function_hoist(
                        semantic,
                        fn_name,
                        &subj_name,
                        func.span,
                        stmt.span(),
                        top_insert_offset,
                        line_starts,
                        sites,
                    );
                }
            }
            Statement::VariableDeclaration(vd)
                if vd.kind == VariableDeclarationKind::Const && vd.declarations.len() == 1 =>
            {
                let decl = &vd.declarations[0];
                let BindingPattern::BindingIdentifier(id) = &decl.id else {
                    continue;
                };
                let Some(init) = &decl.init else {
                    continue;
                };
                let var_name = id.name.as_str();
                let unwrapped = init.without_parentheses();

                if is_component_name(var_name)
                    && matches!(
                        unwrapped,
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                {
                    if rendered_pascal_names.contains(var_name) {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoNestedComponentDefinition,
                            subject_name: Some(subj_name.clone()),
                            message_id: "noNestedComponentDefinition",
                            target_name: var_name.to_string(),
                            message: format!(
                                "Your users lose all state in \"{var_name}\" on every render because it's defined inside \"{subj_name}\", so move it out to the top of the file."
                            ),
                            loc: loc_from_line_starts(line_starts, id.span.start),
                            span: ByteSpan {
                                start: decl.span.start,
                                end: decl.span.end,
                            },
                            autofix: None,
                        });
                    }
                } else if !is_component_name(var_name)
                    && matches!(
                        unwrapped,
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                {
                    if !has_local_captures_in_span(semantic, unwrapped.span(), subj_span) {
                        emit_pure_function_hoist(
                            semantic,
                            var_name,
                            &subj_name,
                            unwrapped.span(),
                            stmt.span(),
                            top_insert_offset,
                            line_starts,
                            sites,
                        );
                    }
                } else if matches!(
                    unwrapped,
                    Expression::ArrayExpression(_) | Expression::ObjectExpression(_)
                ) && let Some(sym_id) = id.symbol_id.get()
                    && is_hoistable_static_value(semantic, sym_id, unwrapped, subj_span)
                {
                    let stmt_span = stmt.span();
                    let stmt_text = stmt_span.source_text(semantic.source_text()).trim();
                    let patch = AutofixPatch::insert(
                        format!("Hoist static `{var_name}` to module scope"),
                        top_insert_offset,
                        format!("{stmt_text}\n\n"),
                    )
                    .with_byte_edit(ByteEdit::delete(span_to_byte_span(stmt_span)));
                    push_semantic_site_with_fix(
                        sites,
                        RuleId::PreferModuleScopeStaticValue,
                        Some(subj_name.clone()),
                        "preferModuleScopeStaticValue",
                        var_name,
                        format!(
                            "`{var_name}` inside `{subj_name}` is a static value rebuilt on every render; hoist it to module scope."
                        ),
                        line_starts,
                        decl.span,
                        Some(patch),
                    );
                }
            }
            _ => {}
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs both the SemanticRuleSite and module-scope hoisting AutofixPatch for a pure helper function"
)]
fn emit_pure_function_hoist(
    semantic: &Semantic<'_>,
    fn_name: &str,
    subj_name: &str,
    fn_span: Span,
    stmt_span: Span,
    top_insert_offset: u32,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let stmt_text = stmt_span.source_text(semantic.source_text()).trim();
    let patch = AutofixPatch::insert(
        format!("Hoist pure function `{fn_name}` to module scope"),
        top_insert_offset,
        format!("{stmt_text}\n\n"),
    )
    .with_byte_edit(ByteEdit::delete(span_to_byte_span(stmt_span)));
    push_semantic_site_with_fix(
        sites,
        RuleId::PreferModuleScopePureFunction,
        Some(subj_name.to_string()),
        "preferModuleScopePureFunction",
        fn_name,
        format!(
            "`{fn_name}` inside `{subj_name}` uses no local state or props but is rebuilt on every render; move it to module scope."
        ),
        line_starts,
        fn_span,
        Some(patch),
    );
}

fn find_top_level_statement_start(semantic: &Semantic<'_>, subject_node_id: NodeId) -> u32 {
    let mut top_start = semantic.nodes().get_node(subject_node_id).span().start;
    for anc_id in semantic.nodes().ancestor_ids(subject_node_id) {
        let kind = semantic.nodes().kind(anc_id);
        if matches!(kind, AstKind::Program(_)) {
            break;
        }
        top_start = semantic.nodes().get_node(anc_id).span().start;
    }
    top_start
}

fn has_local_captures_in_span(semantic: &Semantic<'_>, inner_span: Span, subj_span: Span) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !inner_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::IdentifierReference(ident) = node.kind() else {
            continue;
        };
        let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
            continue;
        };
        let decl_span = semantic
            .nodes()
            .get_node(semantic.scoping().symbol_declaration(sym_id))
            .span();
        if subj_span.contains_inclusive(decl_span) && !inner_span.contains_inclusive(decl_span) {
            return true;
        }
    }
    false
}

fn is_hoistable_static_value(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    init_expr: &Expression<'_>,
    subj_span: Span,
) -> bool {
    let init_span = init_expr.span();

    // 1. Check that `init_expr` contains no local captures, no inner functions, and no impure calls
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !init_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::ArrowFunctionExpression(_) | AstKind::Function(_) => return false,
            AstKind::NewExpression(new_expr) => {
                if matches!(
                    new_expr.callee.without_parentheses(),
                    Expression::Identifier(id) if id.name == "Date"
                ) {
                    return false;
                }
            }
            AstKind::CallExpression(call) => {
                if is_impure_initializer_call(call) {
                    return false;
                }
            }
            AstKind::IdentifierReference(ident) => {
                if let Some(target_sym) = resolve_ident_symbol(semantic, ident) {
                    let decl_span = semantic
                        .nodes()
                        .get_node(semantic.scoping().symbol_declaration(target_sym))
                        .span();
                    if subj_span.contains_inclusive(decl_span) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }

    // 2. Inspect all references to `sym_id`: must not be mutated, and must not be used ONLY for scalar lookups
    let mut ref_count = 0_usize;
    let mut all_scalar_lookups = true;
    let mut used_in_jsx_or_render = false;

    for reference in semantic.scoping().get_resolved_references(sym_id) {
        ref_count += 1;
        let ref_node_id = reference.node_id();
        if is_reference_mutated(semantic, ref_node_id) {
            return false;
        }
        if !is_reference_scalar_lookup_only(semantic, ref_node_id) {
            all_scalar_lookups = false;
        }
        if is_reference_in_jsx(semantic, ref_node_id) {
            used_in_jsx_or_render = true;
        }
    }

    ref_count > 0 && !all_scalar_lookups && used_in_jsx_or_render
}

fn is_impure_initializer_call(call: &CallExpression<'_>) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => matches!(
            id.name.as_str(),
            "nanoid"
                | "uuid"
                | "v4"
                | "cuid"
                | "ulid"
                | "createId"
                | "randomUUID"
                | "generateId"
                | "random"
        ),
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                match obj.name.as_str() {
                    "Math" => mem.property.name == "random",
                    "Date" | "performance" => mem.property.name == "now",
                    "crypto" => matches!(
                        mem.property.name.as_str(),
                        "randomUUID" | "getRandomValues" | "randomBytes"
                    ),
                    _ => false,
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_reference_mutated(semantic: &Semantic<'_>, ref_node_id: NodeId) -> bool {
    let ref_span = semantic.nodes().get_node(ref_node_id).span();
    let mut method_name: Option<&str> = None;

    for anc_id in semantic.nodes().ancestor_ids(ref_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::StaticMemberExpression(mem) => {
                if !mem.object.span().contains_inclusive(ref_span) {
                    return false;
                }
                method_name = Some(mem.property.name.as_str());
            }
            AstKind::ComputedMemberExpression(comp) => {
                if !comp.object.span().contains_inclusive(ref_span) {
                    return false;
                }
            }
            AstKind::AssignmentExpression(assign) => {
                return assign.left.span().contains_inclusive(ref_span);
            }
            AstKind::UpdateExpression(upd) => {
                return upd.argument.span().contains_inclusive(ref_span);
            }
            AstKind::UnaryExpression(un) if un.operator == UnaryOperator::Delete => {
                return un.argument.span().contains_inclusive(ref_span);
            }
            AstKind::CallExpression(call) => {
                return call.callee.span().contains_inclusive(ref_span)
                    && method_name.is_some_and(|m| MUTATING_METHODS.contains(&m));
            }
            _ => return false,
        }
    }
    false
}

fn is_reference_scalar_lookup_only(semantic: &Semantic<'_>, ref_node_id: NodeId) -> bool {
    let ref_span = semantic.nodes().get_node(ref_node_id).span();
    let parent_id = semantic.nodes().parent_id(ref_node_id);
    let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(parent_id) else {
        return false;
    };
    if !mem.object.span().contains_inclusive(ref_span)
        || !SCALAR_LOOKUP_METHODS.contains(&mem.property.name.as_str())
    {
        return false;
    }
    let grandparent_id = semantic.nodes().parent_id(parent_id);
    matches!(
        semantic.nodes().kind(grandparent_id),
        AstKind::CallExpression(call) if call.callee.span().contains_inclusive(mem.span)
    )
}
