//! Context provider/consumer IR extraction and cross-file `ProjectGraph` architecture rules
//! (`context-provider-value-from-unmemoized-local-literal`, `overloaded-context-provider`,
//! and `missing-suspense-or-error-boundary`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{BindingPattern, Expression, JSXAttributeItem, JSXAttributeValue, ObjectPropertyKind},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, ContextConsumerSiteIr, ContextProviderSiteIr, FileIr, SubjectIr,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    matchers::{find_jsx_attr, make_diag_for_subject, resolve_ident_symbol},
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

pub(super) fn extract_context_sites_in_file(
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
    let attr = find_jsx_attr(attrs, "value")?;
    let JSXAttributeValue::ExpressionContainer(c) = attr.value.as_ref()? else {
        return None;
    };
    c.expression.as_expression()
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
                && let Some(sym_id) = resolve_ident_symbol(semantic, ident)
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
                out.push(
                    make_diag_for_subject(
                        RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
                        file.path.clone(),
                        provider.subject_name.clone(),
                        "contextProviderValueFromUnmemoizedLocalLiteral",
                        provider.provider_tag_name.clone(),
                        format!(
                            "Every consumer of `<{}>` redraws on each render because its `value` is a fresh object/array/function rebuilt each render; wrap it in `useMemo` or hoist it outside the component.",
                            provider.provider_tag_name
                        ),
                        provider.loc,
                        provider.span,
                    )
                    .with_severity(sev)
                    .with_caller_sites(all_consumer_sites),
                );
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
                let state_list = provider.state_slot_fields.join(", ");
                let consumer_names: Vec<String> = static_only_consumers
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect();
                let consumer_sites: Vec<ResolvedCallerSite> = static_only_consumers
                    .into_iter()
                    .map(|(_, site)| site)
                    .collect();
                out.push(
                    make_diag_for_subject(
                        RuleId::OverloadedContextProvider,
                        file.path.clone(),
                        provider.subject_name.clone(),
                        "overloadedContextProvider",
                        provider.context_name.clone(),
                        format!(
                            "`<{}>` bundles frequently mutated State Slot(s) (`{state_list}`) with static properties, forcing unnecessary re-renders on static-only consumer(s): `{}`.",
                            provider.provider_tag_name,
                            consumer_names.join("`, `")
                        ),
                        provider.loc,
                        provider.span,
                    )
                    .with_severity(sev)
                    .with_caller_sites(consumer_sites),
                );
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
                let boundary_label = match (subject.suspends, subject.throws_in_render) {
                    (true, true) => "`<Suspense>` and `<ErrorBoundary>`",
                    (true, false) => "`<Suspense>`",
                    (false, true) => "`<ErrorBoundary>`",
                    (false, false) => "`<Suspense>`",
                };
                out.push(
                    make_diag_for_subject(
                        RuleId::MissingSuspenseOrErrorBoundary,
                        file.path.clone(),
                        Some(subj_name.clone()),
                        "missingSuspenseOrErrorBoundary",
                        subj_name.clone(),
                        format!(
                            "Subject `{subj_name}` suspends or throws during render but lacks an ancestral {boundary_label} wrapper across {} Caller Site(s).",
                            uncovered_callers.len()
                        ),
                        subject.loc,
                        subject.span,
                    )
                    .with_severity(sev)
                    .with_caller_sites(uncovered_callers),
                );
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
