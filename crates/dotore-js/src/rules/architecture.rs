//! `architecture` rule family detectors (`no-nested-component-definition`,
//! `prefer-module-scope-static-value` with `Autofix`, `prefer-module-scope-pure-function` with `Autofix`,
//! `react-compiler-no-manual-memoization`, `no-default-props`, `no-prop-types`,
//! `no-legacy-context-api`, `no-legacy-class-lifecycles`, `no-inline-hoc-on-component`,
//! `no-render-in-render`, `no-react-dom-deprecated-apis`) and cross-file `ProjectGraph` detectors
//! (`context-provider-value-from-unmemoized-local-literal`, `overloaded-context-provider`,
//! and `missing-suspense-or-error-boundary`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, Expression, JSXAttributeItem, JSXAttributeValue, ObjectPropertyKind,
        Statement, UnaryOperator, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, ContextConsumerSiteIr, ContextProviderSiteIr, FileIr, SemanticRuleSite,
        SubjectIr,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_body_statements,
            get_subject_name, is_component_name, is_react_component_class, is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, ByteEdit, Diagnostic, RuleId, RuleSeverity},
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


const MAX_COMPONENT_LINES: u32 = 180;
const MAX_CYCLOMATIC_COMPLEXITY: usize = 12;
const MAX_BOOLEAN_PROPS: usize = 4;
/// Extracts single-pass `architecture` semantic rule sites, hoisting autofixes,
/// and `Context.Provider` / `useContext` IR records.
pub(crate) fn extract_architecture_sites(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
    context_providers: &mut Vec<ContextProviderSiteIr>,
    context_consumers: &mut Vec<ContextConsumerSiteIr>,
) {
    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            check_subject_architecture_rules(semantic, subj_id, line_starts, sites);
        }
    }

    check_module_and_expr_architecture_rules(semantic, line_starts, sites);
    extract_context_sites_in_file(
        semantic,
        subjects,
        line_starts,
        context_providers,
        context_consumers,
    );
}

fn check_subject_architecture_rules(
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
    check_subject_size_complexity_and_props(semantic, subject_node_id, &subj_name, line_starts, sites);

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
                    && let Some(Expression::Identifier(id)) = c
                        .expression
                        .as_expression()
                        .map(Expression::without_parentheses)
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::ReactCompilerNoManualMemoization,
                    subject_name: Some(subj_name.clone()),
                    message_id: "reactCompilerNoManualMemoization",
                    target_name: subj_name.clone(),
                    message: "Manual `useMemo`/`useCallback` memoization can be simplified when React Compiler is enabled.".to_string(),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
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
                    let span = ByteSpan {
                        start: decl.span.start,
                        end: decl.span.end,
                    };
                    let loc = loc_from_line_starts(line_starts, decl.span.start);
                    let patch = AutofixPatch {
                        description: format!("Hoist static `{var_name}` to module scope"),
                        edits: vec![
                            ByteEdit {
                                file: None,
                                span: ByteSpan {
                                    start: top_insert_offset,
                                    end: top_insert_offset,
                                },
                                replacement: format!("{stmt_text}\n\n"),
                            },
                            ByteEdit {
                                file: None,
                                span: ByteSpan {
                                    start: stmt_span.start,
                                    end: stmt_span.end,
                                },
                                replacement: String::new(),
                            },
                        ],
                    };
                    sites.push(SemanticRuleSite {
                        rule: RuleId::PreferModuleScopeStaticValue,
                        subject_name: Some(subj_name.clone()),
                        message_id: "preferModuleScopeStaticValue",
                        target_name: var_name.to_string(),
                        message: format!(
                            "`{var_name}` inside `{subj_name}` is a static value rebuilt on every render; hoist it to module scope."
                        ),
                        loc,
                        span,
                        autofix: Some(patch),
                    });
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
    let span = ByteSpan {
        start: fn_span.start,
        end: fn_span.end,
    };
    let loc = loc_from_line_starts(line_starts, fn_span.start);
    let patch = AutofixPatch {
        description: format!("Hoist pure function `{fn_name}` to module scope"),
        edits: vec![
            ByteEdit {
                file: None,
                span: ByteSpan {
                    start: top_insert_offset,
                    end: top_insert_offset,
                },
                replacement: format!("{stmt_text}\n\n"),
            },
            ByteEdit {
                file: None,
                span: ByteSpan {
                    start: stmt_span.start,
                    end: stmt_span.end,
                },
                replacement: String::new(),
            },
        ],
    };
    sites.push(SemanticRuleSite {
        rule: RuleId::PreferModuleScopePureFunction,
        subject_name: Some(subj_name.to_string()),
        message_id: "preferModuleScopePureFunction",
        target_name: fn_name.to_string(),
        message: format!(
            "`{fn_name}` inside `{subj_name}` uses no local state or props but is rebuilt on every render; move it to module scope."
        ),
        loc,
        span,
        autofix: Some(patch),
    });
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
        let Some(ref_id) = ident.reference_id.get() else {
            continue;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
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
                if let Some(ref_id) = ident.reference_id.get()
                    && let Some(target_sym) = semantic.scoping().get_reference(ref_id).symbol_id()
                {
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

fn is_impure_initializer_call(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
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

fn is_reference_in_jsx(semantic: &Semantic<'_>, ref_node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(ref_node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::JSXElement(_) | AstKind::JSXFragment(_) | AstKind::JSXExpressionContainer(_)
        )
    })
}

fn check_module_and_expr_architecture_rules(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::AssignmentExpression(assign) => {
                if let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && is_component_name(&obj.name)
                {
                    let prop = mem.property.name.as_str();
                    let span = ByteSpan {
                        start: assign.span.start,
                        end: assign.span.end,
                    };
                    let loc = loc_from_line_starts(line_starts, assign.span.start);
                    if prop == "defaultProps" {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoDefaultProps,
                            subject_name: Some(obj.name.to_string()),
                            message_id: "noDefaultProps",
                            target_name: format!("{}.defaultProps", obj.name),
                            message: format!(
                                "`{}.defaultProps` is deprecated in React 19; use JavaScript default parameters instead.",
                                obj.name
                            ),
                            loc,
                            span,
                            autofix: None,
                        });
                    } else if prop == "propTypes" {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoPropTypes,
                            subject_name: Some(obj.name.to_string()),
                            message_id: "noPropTypes",
                            target_name: format!("{}.propTypes", obj.name),
                            message: format!(
                                "`{}.propTypes` is removed in React 19; use TypeScript types instead.",
                                obj.name
                            ),
                            loc,
                            span,
                            autofix: None,
                        });
                    } else if prop == "contextTypes" || prop == "childContextTypes" {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::NoLegacyContextApi,
                            subject_name: Some(obj.name.to_string()),
                            message_id: "noLegacyContextApi",
                            target_name: format!("{}.{prop}", obj.name),
                            message: format!(
                                "Legacy `{}.{prop}` API was removed in React 19; migrate to `createContext` and `useContext`.",
                                obj.name
                            ),
                            loc,
                            span,
                            autofix: None,
                        });
                    }
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && obj.name == "ReactDOM"
                    && matches!(
                        mem.property.name.as_str(),
                        "render" | "hydrate" | "findDOMNode" | "unmountComponentAtNode"
                    )
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::NoReactDomDeprecatedApis,
                        subject_name: subj_name.clone(),
                        message_id: "noReactDomDeprecatedApis",
                        target_name: format!("ReactDOM.{}", mem.property.name),
                        message: format!(
                            "`ReactDOM.{}` was removed in React 19; use `createRoot` or `hydrateRoot` from `react-dom/client`.",
                            mem.property.name
                        ),
                        loc: loc_from_line_starts(line_starts, call.span.start),
                        span: ByteSpan {
                            start: call.span.start,
                            end: call.span.end,
                        },
                        autofix: None,
                    });
                }
                check_no_react19_deprecated_apis(call, &subj_name, line_starts, sites);
            }
            AstKind::ExportDefaultDeclaration(export_default) => {
                check_export_default_inline_hoc(export_default, line_starts, sites);
            }
            AstKind::Class(cls) => {
                check_no_legacy_class_lifecycles(semantic, cls, line_starts, sites);
            }
            _ => {}
        }
    }
}

fn extract_context_sites_in_file(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    context_providers: &mut Vec<ContextProviderSiteIr>,
    context_consumers: &mut Vec<ContextConsumerSiteIr>,
) {
    // 1. Collect file-local `const X = createContext(...)` bindings for React 19 `<X value={...}>`
    let mut local_context_names: HashSet<String> = HashSet::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::VariableDeclarator(decl) = node.kind()
            && let BindingPattern::BindingIdentifier(id) = &decl.id
            && let Some(Expression::CallExpression(call)) =
                decl.init.as_ref().map(Expression::without_parentheses)
        {
            let is_create_ctx = match call.callee.without_parentheses() {
                Expression::Identifier(c) => c.name == "createContext",
                Expression::StaticMemberExpression(m) => m.property.name == "createContext",
                _ => false,
            };
            if is_create_ctx {
                local_context_names.insert(id.name.to_string());
            }
        }
    }

    // 2. Scan JSXOpeningElements for `<Ctx.Provider value={...}>` or `<Ctx value={...}>`
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::JSXOpeningElement(opening) => {
                let (tag_name, _, _, _) = classify_jsx_element_name(semantic, &opening.name);
                let context_name_opt = if let Some(base) = tag_name.strip_suffix(".Provider") {
                    Some(base.to_string())
                } else if local_context_names.contains(&tag_name) {
                    Some(tag_name.clone())
                } else {
                    None
                };
                let Some(context_name) = context_name_opt else {
                    continue;
                };

                let enclosing_subj_id = find_enclosing_react_node(semantic, node_id);
                let subj_name = enclosing_subj_id.and_then(|id| get_subject_name(semantic, id));
                let subj_span = enclosing_subj_id.map(|id| semantic.nodes().get_node(id).span());
                let subj_ir = subj_name
                    .as_deref()
                    .and_then(|n| subjects.iter().find(|s| s.name.as_deref() == Some(n)));

                let Some(val_expr) = find_jsx_value_attribute_expr(&opening.attributes) else {
                    continue;
                };

                let (is_unmemoized_value, state_slot_fields, static_fields) =
                    analyze_context_provider_value_expr(semantic, val_expr, subj_span, subj_ir);

                context_providers.push(ContextProviderSiteIr {
                    context_name,
                    provider_tag_name: tag_name,
                    subject_name: subj_name,
                    is_unmemoized_value,
                    state_slot_fields,
                    static_fields,
                    loc: loc_from_line_starts(line_starts, opening.span.start),
                    span: ByteSpan {
                        start: opening.span.start,
                        end: opening.span.end,
                    },
                });
            }
            AstKind::CallExpression(call) => {
                let is_use_ctx = is_react_hook_callee(semantic, &call.callee, "useContext")
                    || is_react_hook_callee(semantic, &call.callee, "use");
                if !is_use_ctx {
                    continue;
                }
                let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
                    continue;
                };
                let Expression::Identifier(ctx_ident) = first_arg.without_parentheses() else {
                    continue;
                };
                let subj_name = find_enclosing_react_node(semantic, node_id)
                    .and_then(|id| get_subject_name(semantic, id));
                let read_fields = extract_use_context_read_fields(semantic, node_id);

                context_consumers.push(ContextConsumerSiteIr {
                    context_name: ctx_ident.name.to_string(),
                    subject_name: subj_name,
                    read_fields,
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                });
            }
            _ => {}
        }
    }
}

fn find_jsx_value_attribute_expr<'a>(
    attrs: &'a [JSXAttributeItem<'a>],
) -> Option<&'a Expression<'a>> {
    for item in attrs {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        if attr
            .name
            .as_identifier()
            .is_some_and(|id| id.name == "value")
            && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
        {
            return c.expression.as_expression();
        }
    }
    None
}

fn analyze_context_provider_value_expr(
    semantic: &Semantic<'_>,
    val_expr: &Expression<'_>,
    subj_span: Option<Span>,
    subj_ir: Option<&SubjectIr>,
) -> (bool, Vec<String>, Vec<String>) {
    let unwrapped = val_expr.without_parentheses();

    // Resolve the underlying expression if `val_expr` is a local variable inside `subj_span`
    let (target_expr, is_local_binding) = match unwrapped {
        Expression::Identifier(ident) => {
            if let Some(s_span) = subj_span
                && let Some(ref_id) = ident.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                let decl_node = semantic.nodes().get_node(decl_id);
                if s_span.contains_inclusive(decl_node.span())
                    && let AstKind::VariableDeclarator(decl) = decl_node.kind()
                    && let Some(init) = &decl.init
                {
                    (init.without_parentheses(), true)
                } else {
                    (unwrapped, false)
                }
            } else {
                (unwrapped, false)
            }
        }
        _ => (unwrapped, true),
    };

    let is_unmemoized = is_local_binding
        && matches!(
            target_expr,
            Expression::ObjectExpression(_)
                | Expression::ArrayExpression(_)
                | Expression::ArrowFunctionExpression(_)
                | Expression::FunctionExpression(_)
        );

    // Also inspect `useMemo(() => ({ ... }), [...])` or direct `ObjectExpression` for state_slot_fields vs static_fields
    let obj_expr_opt = match target_expr {
        Expression::ObjectExpression(obj) => Some(obj),
        Expression::CallExpression(call)
            if is_react_hook_callee(semantic, &call.callee, "useMemo") =>
        {
            call.arguments
                .first()
                .and_then(|a| a.as_expression())
                .and_then(|cb| match cb.without_parentheses() {
                    Expression::ArrowFunctionExpression(arrow) => arrow
                        .body
                        .as_expression()
                        .and_then(|e| match e.without_parentheses() {
                            Expression::ObjectExpression(o) => Some(o),
                            _ => None,
                        }),
                    _ => None,
                })
        }
        _ => None,
    };

    let mut state_slot_fields = Vec::new();
    let mut static_fields = Vec::new();

    if let (Some(obj), Some(subj)) = (obj_expr_opt, subj_ir) {
        let active_state_names: HashSet<&str> = subj
            .state_slots
            .iter()
            .filter(|s| {
                s.setter_calls_outside_effects > 0
                    || s.setter_calls_in_effects > 0
                    || s.setter_escaped
            })
            .filter_map(|s| s.state_name.as_deref())
            .collect();

        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Some(key_name) = prop.key.static_name() else {
                continue;
            };
            let Some(key_str) = key_name.as_str() else {
                continue;
            };
            let val_ident_name = match prop.value.without_parentheses() {
                Expression::Identifier(id) => Some(id.name.as_str()),
                _ => None,
            };
            if val_ident_name.is_some_and(|v| active_state_names.contains(v)) {
                state_slot_fields.push(key_str.to_string());
            } else {
                static_fields.push(key_str.to_string());
            }
        }
    }

    (is_unmemoized, state_slot_fields, static_fields)
}

fn extract_use_context_read_fields(semantic: &Semantic<'_>, call_node_id: NodeId) -> Vec<String> {
    let mut fields = Vec::new();
    let parent_id = semantic.nodes().parent_id(call_node_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id) else {
        return fields;
    };

    match &decl.id {
        BindingPattern::ObjectPattern(obj_pat) => {
            for prop in &obj_pat.properties {
                if let Some(key_name) = prop.key.static_name()
                    && let Some(key_str) = key_name.as_str()
                {
                    fields.push(key_str.to_string());
                }
            }
        }
        BindingPattern::BindingIdentifier(id) => {
            if let Some(sym_id) = id.symbol_id.get() {
                collect_member_reads_for_symbol(semantic, sym_id, &mut fields);
            }
        }
        _ => {}
    }

    fields
}

fn collect_member_reads_for_symbol(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    fields: &mut Vec<String>,
) {
    for reference in semantic.scoping().get_resolved_references(sym_id) {
        let ref_parent_id = semantic.nodes().parent_id(reference.node_id());
        if let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(ref_parent_id) {
            let prop_name = mem.property.name.to_string();
            if !fields.contains(&prop_name) {
                fields.push(prop_name);
            }
        }
    }
}

fn collect_consumers_for_provider(
    graph: &ProjectGraph,
    provider_file: &FileIr,
    provider: &ContextProviderSiteIr,
) -> (Vec<ResolvedCallerSite>, Vec<(String, ResolvedCallerSite)>) {
    let mut all_consumer_sites = Vec::new();
    let mut static_only_consumers = Vec::new();

    for consumer_file in &graph.files {
        for consumer in &consumer_file.context_consumers {
            if !context_consumer_matches_provider(
                graph,
                provider_file,
                provider,
                consumer_file,
                consumer,
            ) {
                continue;
            }
            let caller_site = ResolvedCallerSite {
                caller_file: consumer_file.path.clone(),
                parent_subject_name: consumer.subject_name.clone(),
                component_name: provider.context_name.clone(),
                loc: consumer.loc,
                span: consumer.span,
                has_key: false,
                passed_props: consumer.read_fields.clone(),
            };
            all_consumer_sites.push(caller_site.clone());

            if !provider.state_slot_fields.is_empty()
                && !consumer.read_fields.is_empty()
                && consumer
                    .read_fields
                    .iter()
                    .all(|f| !provider.state_slot_fields.contains(f))
            {
                static_only_consumers.push((
                    consumer
                        .subject_name
                        .clone()
                        .unwrap_or_else(|| "Consumer".to_string()),
                    caller_site,
                ));
            }
        }
    }

    (all_consumer_sites, static_only_consumers)
}

fn context_consumer_matches_provider(
    graph: &ProjectGraph,
    provider_file: &FileIr,
    provider: &ContextProviderSiteIr,
    consumer_file: &FileIr,
    consumer: &ContextConsumerSiteIr,
) -> bool {
    if consumer_file.path == provider_file.path {
        return consumer.context_name == provider.context_name;
    }
    let resolve_origin = |file: &FileIr, local_name: &str| -> (std::path::PathBuf, String) {
        for imp in &file.module.imports {
            for b in &imp.bindings {
                if b.local_name == local_name
                    && let Some((def_file, def_name)) =
                        graph.resolve_exported_symbol(&file.path, &imp.source, &b.imported_name)
                {
                    return (def_file.path.clone(), def_name);
                }
            }
        }
        (file.path.clone(), local_name.to_string())
    };
    resolve_origin(provider_file, &provider.context_name)
        == resolve_origin(consumer_file, &consumer.context_name)
}

/// Evaluates cross-file `ProjectGraph` rules for Ticket #07:
/// 1. `context-provider-value-from-unmemoized-local-literal`
/// 2. `overloaded-context-provider`
/// 3. `missing-suspense-or-error-boundary`
pub(crate) fn evaluate_architecture_project_graph_rules<F>(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &crate::config::DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    // 1 & 2: Context.Provider unstable value & Overloaded provider analysis
    for file in &graph.files {
        let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
            continue;
        };
        if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
            continue;
        }

        for provider in &file.context_providers {
            let (all_consumer_sites, static_only_consumers) =
                collect_consumers_for_provider(graph, file, provider);
            if provider.is_unmemoized_value
                && let Some(sev) = resolve_activation(
                    RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
                    file,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                    enabled_rules,
                )
                && !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
                        provider.loc.line,
                        provider.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            {
                let meta = RuleId::ContextProviderValueFromUnmemoizedLocalLiteral.metadata();
                out.push(Diagnostic {
                    file: file.path.clone(),
                    subject_name: provider.subject_name.clone(),
                    rule: RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
                    category: meta.category,
                    severity: sev,
                    message_id: "contextProviderValueFromUnmemoizedLocalLiteral",
                    tier: meta.default_tier,
                    target_name: provider.provider_tag_name.clone(),
                    message: format!(
                        "Every consumer of `<{}>` redraws on each render because its `value` is a fresh object/array/function rebuilt each render; wrap it in `useMemo` or hoist it outside the component.",
                        provider.provider_tag_name
                    ),
                    docs_url: meta.docs_url,
                    loc: provider.loc,
                    span: provider.span,
                    cascade_steps: Vec::new(),
                    caller_sites: all_consumer_sites,
                    autofix: None,
                });
            }

            if !provider.state_slot_fields.is_empty()
                && !provider.static_fields.is_empty()
                && !static_only_consumers.is_empty()
                && let Some(sev) = resolve_activation(
                    RuleId::OverloadedContextProvider,
                    file,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                    enabled_rules,
                )
                && !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::OverloadedContextProvider,
                        provider.loc.line,
                        provider.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            {
                let meta = RuleId::OverloadedContextProvider.metadata();
                let state_list = provider.state_slot_fields.join(", ");
                let consumer_names: Vec<String> = static_only_consumers
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect();
                let consumer_sites: Vec<ResolvedCallerSite> = static_only_consumers
                    .into_iter()
                    .map(|(_, site)| site)
                    .collect();
                out.push(Diagnostic {
                    file: file.path.clone(),
                    subject_name: provider.subject_name.clone(),
                    rule: RuleId::OverloadedContextProvider,
                    category: meta.category,
                    severity: sev,
                    message_id: "overloadedContextProvider",
                    tier: meta.default_tier,
                    target_name: provider.context_name.clone(),
                    message: format!(
                        "`<{}>` bundles frequently mutated State Slot(s) (`{state_list}`) with static properties, forcing unnecessary re-renders on static-only consumer(s): `{}`.",
                        provider.provider_tag_name,
                        consumer_names.join("`, `")
                    ),
                    docs_url: meta.docs_url,
                    loc: provider.loc,
                    span: provider.span,
                    cascade_steps: Vec::new(),
                    caller_sites: consumer_sites,
                    autofix: None,
                });
            }
        }
    }

    // 3: Ancestral `<Suspense>` and `<ErrorBoundary>` verification across Caller Sites
    for file in &graph.files {
        let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
            continue;
        };
        if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
            continue;
        }
        let Some(sev) = resolve_activation(
            RuleId::MissingSuspenseOrErrorBoundary,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        for subject in &file.subjects {
            if !subject.suspends && !subject.throws_in_render {
                continue;
            }
            let Some(subj_name) = &subject.name else {
                continue;
            };
            let callers = graph.callers_of(&file.path, subj_name);
            if callers.is_empty() {
                continue;
            }

            let mut uncovered_callers = Vec::new();
            for caller in callers {
                let mut visited = HashSet::new();
                let is_covered = caller_site_has_ancestral_boundary(
                    graph,
                    &caller,
                    subject.suspends,
                    subject.throws_in_render,
                    &mut visited,
                );
                if !is_covered {
                    uncovered_callers.push(caller);
                }
            }

            if !uncovered_callers.is_empty()
                && !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::MissingSuspenseOrErrorBoundary,
                        subject.loc.line,
                        subject.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            {
                let meta = RuleId::MissingSuspenseOrErrorBoundary.metadata();
                let boundary_label = match (subject.suspends, subject.throws_in_render) {
                    (true, true) => "`<Suspense>` and `<ErrorBoundary>`",
                    (true, false) => "`<Suspense>`",
                    (false, true) => "`<ErrorBoundary>`",
                    (false, false) => "`<Suspense>`",
                };
                out.push(Diagnostic {
                    file: file.path.clone(),
                    subject_name: Some(subj_name.clone()),
                    rule: RuleId::MissingSuspenseOrErrorBoundary,
                    category: meta.category,
                    severity: sev,
                    message_id: "missingSuspenseOrErrorBoundary",
                    tier: meta.default_tier,
                    target_name: subj_name.clone(),
                    message: format!(
                        "Subject `{subj_name}` suspends or throws during render but lacks an ancestral {boundary_label} wrapper across {} Caller Site(s).",
                        uncovered_callers.len()
                    ),
                    docs_url: meta.docs_url,
                    loc: subject.loc,
                    span: subject.span,
                    cascade_steps: Vec::new(),
                    caller_sites: uncovered_callers,
                    autofix: None,
                });
            }
        }
    }
}

fn caller_site_has_ancestral_boundary(
    graph: &ProjectGraph,
    caller: &ResolvedCallerSite,
    need_suspense: bool,
    need_error_boundary: bool,
    visited: &mut HashSet<(std::path::PathBuf, String)>,
) -> bool {
    let Some(caller_file) = graph.files.iter().find(|f| f.path == caller.caller_file) else {
        return false;
    };
    let jsx_opt = caller_file
        .jsx_elements
        .iter()
        .find(|el| el.span == caller.span);

    let mut local_suspense = false;
    let mut local_error = false;
    if let Some(jsx) = jsx_opt {
        local_suspense = jsx
            .ancestor_elements
            .iter()
            .any(|a| a == "Suspense" || a.ends_with(".Suspense"));
        local_error = jsx
            .ancestor_elements
            .iter()
            .any(|a| a.contains("ErrorBoundary"));
    }

    let rem_suspense = need_suspense && !local_suspense;
    let rem_error = need_error_boundary && !local_error;
    if !rem_suspense && !rem_error {
        return true;
    }

    // Walk upward to the parent Subject's Caller Sites in ProjectGraph
    let Some(parent_subj_name) = &caller.parent_subject_name else {
        return false;
    };
    let visit_key = (caller.caller_file.clone(), parent_subj_name.clone());
    if !visited.insert(visit_key) {
        return false;
    }

    let parent_callers = graph.callers_of(&caller.caller_file, parent_subj_name);
    if parent_callers.is_empty() {
        return false;
    }

    parent_callers.iter().all(|p_caller| {
        caller_site_has_ancestral_boundary(graph, p_caller, rem_suspense, rem_error, visited)
    })
}

fn check_subject_size_complexity_and_props(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let start_loc = loc_from_line_starts(line_starts, subj_span.start);
    let end_loc = loc_from_line_starts(line_starts, subj_span.end);
    let line_count = end_loc.line.saturating_sub(start_loc.line) + 1;
    let span = ByteSpan {
        start: subj_span.start,
        end: subj_span.end,
    };

    // 1. `no-giant-component`
    if line_count > MAX_COMPONENT_LINES {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoGiantComponent,
            subject_name: Some(subj_name.to_string()),
            message_id: "noGiantComponent",
            target_name: subj_name.to_string(),
            message: format!(
                "Component `{subj_name}` spans {line_count} lines (exceeding {MAX_COMPONENT_LINES} lines); split it into smaller focused components or custom hooks."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }

    // 2. `no-high-complexity-react-function`
    let mut branch_points = 1_usize;
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::IfStatement(_)
            | AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::SwitchCase(_)
            | AstKind::ForStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::WhileStatement(_)
            | AstKind::DoWhileStatement(_)
            | AstKind::CatchClause(_) => {
                branch_points += 1;
            }
            _ => {}
        }
    }
    if branch_points > MAX_CYCLOMATIC_COMPLEXITY {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoHighComplexityReactFunction,
            subject_name: Some(subj_name.to_string()),
            message_id: "noHighComplexityReactFunction",
            target_name: subj_name.to_string(),
            message: format!(
                "`{subj_name}` has a cyclomatic complexity of {branch_points} (exceeding {MAX_CYCLOMATIC_COMPLEXITY}); extract complex branching logic into helper functions or child components."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }

    // 3. `no-many-boolean-props`
    if count_boolean_props_on_subject(semantic, subject_node_id) >= MAX_BOOLEAN_PROPS {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoManyBooleanProps,
            subject_name: Some(subj_name.to_string()),
            message_id: "noManyBooleanProps",
            target_name: subj_name.to_string(),
            message: format!(
                "Component `{subj_name}` accepts {MAX_BOOLEAN_PROPS} or more boolean flag props; consolidate mutually exclusive or related flags into an explicit `variant` union prop."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }
}

fn count_boolean_props_on_subject(semantic: &Semantic<'_>, subject_node_id: NodeId) -> usize {
    let params = match semantic.nodes().kind(subject_node_id) {
        AstKind::Function(f) => Some(&f.params.items),
        AstKind::ArrowFunctionExpression(a) => Some(&a.params.items),
        AstKind::VariableDeclarator(decl) => match decl.init.as_ref().map(Expression::without_parentheses) {
            Some(Expression::ArrowFunctionExpression(a)) => Some(&a.params.items),
            Some(Expression::FunctionExpression(f)) => Some(&f.params.items),
            _ => None,
        },
        _ => None,
    };
    let Some(items) = params else {
        return 0;
    };
    let Some(first_param) = items.first() else {
        return 0;
    };
    let mut bool_names: HashSet<String> = HashSet::new();
    if let BindingPattern::ObjectPattern(obj_pat) = &first_param.pattern {
        for prop in &obj_pat.properties {
            let key_opt = prop.key.static_name().and_then(|n| n.as_str().map(str::to_string));
            let is_bool_default = matches!(
                &prop.value,
                BindingPattern::AssignmentPattern(assign)
                    if matches!(assign.right.without_parentheses(), Expression::BooleanLiteral(_))
            );
            if let Some(k) = key_opt
                && (is_bool_default || has_boolean_prop_prefix(&k))
            {
                bool_names.insert(k);
            }
        }
    }
    let param_src = first_param.span.source_text(semantic.source_text());
    let ts_bool_hits = param_src.matches(": boolean").count();
    bool_names.len().max(ts_bool_hits)
}

fn has_boolean_prop_prefix(name: &str) -> bool {
    for prefix in ["is", "has", "can", "should", "with"] {
        if let Some(rest) = name.strip_prefix(prefix)
            && rest.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

fn check_generic_handler_name_attr(
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    const GENERIC_HANDLER_NAMES: &[&str] = &[
        "handleClick",
        "handleChange",
        "handleSubmit",
        "handleInput",
        "handlePress",
        "handleEvent",
        "onClickHandler",
        "onChangeHandler",
        "onSubmitHandler",
    ];
    let Some(attr_id) = attr.name.as_identifier() else {
        return;
    };
    if !attr_id.name.starts_with("on") {
        return;
    }
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return;
    };
    let Some(Expression::Identifier(handler_id)) = c
        .expression
        .as_expression()
        .map(Expression::without_parentheses)
    else {
        return;
    };
    if GENERIC_HANDLER_NAMES.contains(&handler_id.name.as_str()) {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoGenericHandlerNames,
            subject_name: Some(subj_name.to_string()),
            message_id: "noGenericHandlerNames",
            target_name: handler_id.name.to_string(),
            message: format!(
                "Event handler `{}` has a generic name; name it after its domain action (e.g. `handleSaveProfile`).",
                handler_id.name
            ),
            loc: loc_from_line_starts(line_starts, handler_id.span.start),
            span: ByteSpan {
                start: handler_id.span.start,
                end: handler_id.span.end,
            },
            autofix: None,
        });
    }
}

fn check_inline_hoc_and_render_in_render(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    call_node_id: NodeId,
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Must belong to `subject_node_id` (not an unrelated outer subject when `subject_node_id` is a module-level VariableDeclarator)
    let enclosing_fn_subject = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find(|&anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            ) && find_enclosing_react_node(semantic, anc_id).is_some()
        })
        .and_then(|anc_id| find_enclosing_react_node(semantic, anc_id));
    if enclosing_fn_subject != Some(subject_node_id) {
        return;
    }
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

    // 1. `no-inline-hoc-on-component`: `with*(Comp)`, `memo(Comp)`, `forwardRef(...)`, `observer(Comp)`, `lazy(...)` called inside a component/hook render body
    let is_hoc_factory = matches!(c_name, "memo" | "forwardRef" | "observer" | "lazy")
        || (c_name.starts_with("with")
            && c_name.chars().nth(4).is_some_and(|c| c.is_ascii_uppercase())
            && call.arguments.first().and_then(|a| a.as_expression()).is_some_and(|arg| {
                match arg.without_parentheses() {
                    Expression::Identifier(id) => is_component_name(&id.name),
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
                    _ => false,
                }
            }));
    if is_hoc_factory {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoInlineHocOnComponent,
            subject_name: Some(subj_name.to_string()),
            message_id: "noInlineHocOnComponent",
            target_name: c_name.to_string(),
            message: format!(
                "Higher-order component `{c_name}(...)` is called inside `{subj_name}`, creating a new component identity on every render; hoist it to module scope."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `no-render-in-render`: `renderFoo()` helper returning JSX called inside JSX
    if c_name.starts_with("render")
        && c_name.chars().nth(6).is_some_and(|c| c.is_ascii_uppercase())
        && let Expression::Identifier(ident) = call.callee.without_parentheses()
        && is_reference_in_jsx(semantic, find_call_node_id(semantic, subject_node_id, call.span))
        && render_helper_returns_jsx(semantic, ident)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoRenderInRender,
            subject_name: Some(subj_name.to_string()),
            message_id: "noRenderInRender",
            target_name: c_name.to_string(),
            message: format!(
                "Calling `{c_name}()` inline in JSX bypasses React component boundaries; extract it as a standalone `<Component />`."
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

fn check_export_default_inline_hoc(
    export_default: &oxc_ast::ast::ExportDefaultDeclaration<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(expr) = export_default.declaration.as_expression() else {
        return;
    };
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return;
    };
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    let c_name = callee_id.name.as_str();
    if !c_name.starts_with("with")
        || !c_name.chars().nth(4).is_some_and(|c| c.is_ascii_uppercase())
    {
        return;
    }
    let is_component_arg = call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
        .is_some_and(|arg| match arg.without_parentheses() {
            Expression::Identifier(id) => is_component_name(&id.name),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
            _ => false,
        });
    if is_component_arg {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoInlineHocOnComponent,
            subject_name: None,
            message_id: "noInlineHocOnComponent",
            target_name: c_name.to_string(),
            message: format!(
                "Higher-order component `{c_name}(...)` is called inline in `export default`; assign the wrapped component to a named `const` before exporting."
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

fn find_call_node_id(semantic: &Semantic<'_>, fallback: NodeId, target_span: Span) -> NodeId {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if matches!(node.kind(), AstKind::CallExpression(_)) && node.span() == target_span {
            return node_id;
        }
    }
    fallback
}

fn render_helper_returns_jsx(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(ref_id) = ident.reference_id.get() else {
        return true;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return true;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let decl_span = semantic.nodes().get_node(decl_id).span();
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        decl_span.contains_inclusive(n.span())
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn check_no_react19_deprecated_apis(
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let deprecated = match call.callee.without_parentheses() {
        Expression::Identifier(id) => match id.name.as_str() {
            "createFactory" | "findDOMNode" | "unmountComponentAtNode" => Some(id.name.to_string()),
            _ => None,
        },
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                match (obj.name.as_str(), mem.property.name.as_str()) {
                    ("React", "createFactory") => Some("React.createFactory".to_string()),
                    (
                        "ReactDOM",
                        "render" | "hydrate" | "findDOMNode" | "unmountComponentAtNode",
                    ) => Some(format!("ReactDOM.{}", mem.property.name)),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(api_name) = deprecated {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoReact19DeprecatedApis,
            subject_name: subj_name.clone(),
            message_id: "noReact19DeprecatedApis",
            target_name: api_name.clone(),
            message: format!(
                "`{api_name}` is deprecated or removed in React 19; migrate to modern React 19 APIs."
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

fn check_no_legacy_class_lifecycles(
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

    for elem in &cls.body.body {
        let oxc_ast::ast::ClassElement::MethodDefinition(method) = elem else {
            continue;
        };
        if method.r#static {
            continue;
        }
        let Some(m_name) = method
            .key
            .static_name()
            .and_then(|n| n.as_str().map(str::to_string))
        else {
            continue;
        };
        if matches!(
            m_name.as_str(),
            "componentWillMount"
                | "componentWillReceiveProps"
                | "componentWillUpdate"
                | "UNSAFE_componentWillMount"
                | "UNSAFE_componentWillReceiveProps"
                | "UNSAFE_componentWillUpdate"
        ) {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoLegacyClassLifecycles,
                subject_name: Some(cls_name.clone()),
                message_id: "noLegacyClassLifecycles",
                target_name: m_name.clone(),
                message: format!(
                    "Legacy class lifecycle `{m_name}` in `{cls_name}` is unsafe in concurrent React; replace it with `componentDidMount`, `componentDidUpdate`, or hooks."
                ),
                loc: loc_from_line_starts(line_starts, method.key.span().start),
                span: ByteSpan {
                    start: method.key.span().start,
                    end: method.key.span().end,
                },
                autofix: None,
            });
        }
    }
}
