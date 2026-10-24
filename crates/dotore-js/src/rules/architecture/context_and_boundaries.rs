//! Context provider/consumer IR extraction and cross-file `ProjectGraph` architecture rules
//! (`context-provider-value-from-unmemoized-local-literal`, `overloaded-context-provider`,
//! and `missing-suspense-or-error-boundary`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, ClassElement, Expression, JSXAttributeItem, JSXAttributeValue,
        ObjectPropertyKind, TSSignature, TSType, TSTypeName,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ArchitectureFileFacets, ByteSpan, ContextConsumerSiteIr, ContextProviderSiteIr,
        FileContext, FileIr, HelperFingerprintIr, InlineTerminalUiPrimitiveSiteIr,
        StructLiteralConstructionSiteIr, SubjectIr, classify_file_context,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_react_hook_callee,
        },
        types::{ModuleIr, loc_from_line_starts},
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

    evaluate_reuse_architecture_rules(graph, packages, enabled_rules, resolve_activation, out);
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

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

fn fnv1a_step(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^= 0xff;
    hash.wrapping_mul(FNV_PRIME)
}

/// Extracts single-pass structural facets for helper duplication (`HelperFingerprintIr`),
/// builder candidates (`StructLiteralConstructionSiteIr`, `defined_builder_types`),
/// and inline terminal UI primitives (`InlineTerminalUiPrimitiveSiteIr`, `is_ui_kit_module`).
pub(crate) fn extract_reuse_architecture_facets(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    extract_helper_fingerprints_in_file(semantic, subjects, module, line_starts, facets);
    extract_builder_facets_in_file(semantic, line_starts, facets);
    extract_inline_terminal_ui_sites_in_file(path, source, semantic, line_starts, facets);
}

fn extract_helper_fingerprints_in_file(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let exported_names: HashSet<&str> = module
        .exports
        .iter()
        .flat_map(|e| std::iter::once(e.name.as_str()).chain(e.local_name.as_deref()))
        .collect();
    let subject_names: HashSet<&str> = subjects.iter().filter_map(|s| s.name.as_deref()).collect();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let Some(body) = &func.body else {
                    continue;
                };
                if !is_module_scope_helper_decl(semantic, node_id) {
                    continue;
                }
                let fn_name = id.name.as_str();
                if subject_names.contains(fn_name) || span_contains_jsx(semantic, body.span) {
                    continue;
                }
                let is_exported =
                    exported_names.contains(fn_name) || has_export_ancestor(semantic, node_id);
                if is_exported {
                    continue;
                }
                let param_count = func.params.items.len();
                let has_rest = func.params.rest.is_some();
                let (normalized_hash, statement_count) = compute_helper_body_fingerprint(
                    semantic,
                    node_id,
                    func.span,
                    body.span,
                    param_count,
                    has_rest,
                );
                if statement_count >= 4 {
                    facets.helper_fingerprints.push(HelperFingerprintIr {
                        name: fn_name.to_string(),
                        normalized_hash,
                        statement_count,
                        param_count,
                        is_private: true,
                        loc: loc_from_line_starts(line_starts, func.span.start),
                        span: ByteSpan {
                            start: func.span.start,
                            end: func.span.end,
                        },
                    });
                }
            }
            AstKind::VariableDeclarator(decl) => {
                let BindingPattern::BindingIdentifier(id) = &decl.id else {
                    continue;
                };
                let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
                    continue;
                };
                if !is_module_scope_helper_decl(semantic, node_id) {
                    continue;
                }
                let fn_name = id.name.as_str();
                if subject_names.contains(fn_name) {
                    continue;
                }
                let is_exported =
                    exported_names.contains(fn_name) || has_export_ancestor(semantic, node_id);
                if is_exported {
                    continue;
                }
                let (fn_span, body_span, param_count, has_rest) = match init {
                    Expression::ArrowFunctionExpression(arrow) => (
                        arrow.span,
                        arrow.body.span(),
                        arrow.params.items.len(),
                        arrow.params.rest.is_some(),
                    ),
                    Expression::FunctionExpression(func) => {
                        let Some(body) = &func.body else {
                            continue;
                        };
                        (
                            func.span,
                            body.span,
                            func.params.items.len(),
                            func.params.rest.is_some(),
                        )
                    }
                    _ => continue,
                };
                if span_contains_jsx(semantic, body_span) {
                    continue;
                }
                let (normalized_hash, statement_count) = compute_helper_body_fingerprint(
                    semantic,
                    node_id,
                    fn_span,
                    body_span,
                    param_count,
                    has_rest,
                );
                if statement_count >= 4 {
                    let parent_id = semantic.nodes().parent_id(node_id);
                    let full_span = if let AstKind::VariableDeclaration(var_decl) =
                        semantic.nodes().kind(parent_id)
                        && var_decl.declarations.len() == 1
                    {
                        var_decl.span
                    } else {
                        decl.span
                    };
                    facets.helper_fingerprints.push(HelperFingerprintIr {
                        name: fn_name.to_string(),
                        normalized_hash,
                        statement_count,
                        param_count,
                        is_private: true,
                        loc: loc_from_line_starts(line_starts, full_span.start),
                        span: ByteSpan {
                            start: full_span.start,
                            end: full_span.end,
                        },
                    });
                }
            }
            _ => {}
        }
    }
}

fn is_module_scope_helper_decl(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    !semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_)
                | AstKind::ArrowFunctionExpression(_)
                | AstKind::Class(_)
                | AstKind::ObjectExpression(_)
        )
    })
}

fn has_export_ancestor(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ExportNamedDeclaration(_)
                | AstKind::ExportDefaultDeclaration(_)
                | AstKind::TSExportAssignment(_)
        )
    })
}

fn span_contains_jsx(semantic: &Semantic<'_>, span: Span) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        let s = n.span();
        s.start >= span.start
            && s.end <= span.end
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn compute_helper_body_fingerprint(
    semantic: &Semantic<'_>,
    _owner_id: NodeId,
    fn_span: Span,
    body_span: Span,
    param_count: usize,
    has_rest: bool,
) -> (u64, usize) {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fnv1a_step(hash, b"HelperArity");
    hash = fnv1a_step(hash, &param_count.to_le_bytes());
    hash = fnv1a_step(hash, &[u8::from(has_rest)]);

    let mut statement_count = 0_usize;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let sp = node.span();
        if sp.start < body_span.start || sp.end > body_span.end {
            continue;
        }
        match node.kind() {
            AstKind::VariableDeclaration(decl) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"VarDecl");
                hash = fnv1a_step(hash, decl.kind.as_str().as_bytes());
            }
            AstKind::VariableDeclarator(_) => {
                hash = fnv1a_step(hash, b"VarDeclarator");
            }
            AstKind::BindingIdentifier(_) => {
                hash = fnv1a_step(hash, b"BindIdent");
            }
            AstKind::ObjectPattern(_) => {
                hash = fnv1a_step(hash, b"ObjPat");
            }
            AstKind::ArrayPattern(_) => {
                hash = fnv1a_step(hash, b"ArrPat");
            }
            AstKind::ExpressionStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"ExprStmt");
            }
            AstKind::ReturnStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Return");
            }
            AstKind::IfStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"If");
            }
            AstKind::ForStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"For");
            }
            AstKind::ForInStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"ForIn");
            }
            AstKind::ForOfStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"ForOf");
            }
            AstKind::WhileStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"While");
            }
            AstKind::DoWhileStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"DoWhile");
            }
            AstKind::SwitchStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Switch");
            }
            AstKind::SwitchCase(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"SwitchCase");
            }
            AstKind::TryStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Try");
            }
            AstKind::CatchClause(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Catch");
            }
            AstKind::ThrowStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Throw");
            }
            AstKind::BreakStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Break");
            }
            AstKind::ContinueStatement(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"Continue");
            }
            AstKind::ConditionalExpression(_) => {
                statement_count += 1;
                hash = fnv1a_step(hash, b"CondExpr");
            }
            AstKind::BinaryExpression(e) => {
                hash = fnv1a_step(hash, b"BinOp");
                hash = fnv1a_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::LogicalExpression(e) => {
                hash = fnv1a_step(hash, b"LogOp");
                hash = fnv1a_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::UnaryExpression(e) => {
                hash = fnv1a_step(hash, b"UnOp");
                hash = fnv1a_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::UpdateExpression(e) => {
                hash = fnv1a_step(hash, b"UpdOp");
                hash = fnv1a_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::AssignmentExpression(e) => {
                hash = fnv1a_step(hash, b"AssignOp");
                hash = fnv1a_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::CallExpression(call) => {
                hash = fnv1a_step(hash, b"Call");
                hash = fnv1a_step(hash, &call.arguments.len().to_le_bytes());
                match call.callee.without_parentheses() {
                    Expression::Identifier(ident) => {
                        let is_local =
                            resolve_ident_symbol(semantic, ident).is_some_and(|sym_id| {
                                let decl_span = semantic
                                    .nodes()
                                    .get_node(semantic.scoping().symbol_declaration(sym_id))
                                    .span();
                                decl_span.start >= fn_span.start && decl_span.end <= fn_span.end
                            });
                        if is_local {
                            hash = fnv1a_step(hash, b"local_fn");
                        } else {
                            hash = fnv1a_step(hash, ident.name.as_bytes());
                        }
                    }
                    Expression::StaticMemberExpression(mem) => {
                        hash = fnv1a_step(hash, mem.property.name.as_bytes());
                    }
                    _ => {}
                }
            }
            AstKind::NewExpression(new_e) => {
                hash = fnv1a_step(hash, b"New");
                hash = fnv1a_step(hash, &new_e.arguments.len().to_le_bytes());
                if let Expression::Identifier(ident) = new_e.callee.without_parentheses() {
                    hash = fnv1a_step(hash, ident.name.as_bytes());
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                hash = fnv1a_step(hash, b"Member");
                hash = fnv1a_step(hash, mem.property.name.as_bytes());
            }
            AstKind::ComputedMemberExpression(_) => {
                hash = fnv1a_step(hash, b"ComputedMember");
            }
            AstKind::IdentifierReference(_) => {
                let parent_kind = semantic.nodes().kind(semantic.nodes().parent_id(node_id));
                if !matches!(
                    parent_kind,
                    AstKind::CallExpression(_) | AstKind::NewExpression(_)
                ) {
                    hash = fnv1a_step(hash, b"IdentRef");
                }
            }
            AstKind::StringLiteral(_) => {
                hash = fnv1a_step(hash, b"StrLit");
            }
            AstKind::NumericLiteral(_) => {
                hash = fnv1a_step(hash, b"NumLit");
            }
            AstKind::BooleanLiteral(b) => {
                hash = fnv1a_step(hash, if b.value { b"BoolTrue" } else { b"BoolFalse" });
            }
            AstKind::NullLiteral(_) => {
                hash = fnv1a_step(hash, b"NullLit");
            }
            AstKind::RegExpLiteral(r) => {
                hash = fnv1a_step(hash, b"RegexLit");
                hash = fnv1a_step(hash, r.regex.pattern.text.as_bytes());
            }
            AstKind::TemplateLiteral(t) => {
                hash = fnv1a_step(hash, b"TplLit");
                hash = fnv1a_step(hash, &t.expressions.len().to_le_bytes());
            }
            AstKind::ArrayExpression(a) => {
                hash = fnv1a_step(hash, b"ArrExpr");
                hash = fnv1a_step(hash, &a.elements.len().to_le_bytes());
            }
            AstKind::ObjectExpression(o) => {
                hash = fnv1a_step(hash, b"ObjExpr");
                hash = fnv1a_step(hash, &o.properties.len().to_le_bytes());
            }
            AstKind::AwaitExpression(_) => {
                hash = fnv1a_step(hash, b"Await");
            }
            AstKind::SpreadElement(_) => {
                hash = fnv1a_step(hash, b"Spread");
            }
            _ => {}
        }
    }

    (hash, statement_count)
}

fn evaluate_reuse_architecture_rules<F>(
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
    for pkg in packages {
        let pkg_files: Vec<&FileIr> = graph
            .files
            .iter()
            .filter(|f| {
                f.file_context == FileContext::Production
                    && resolve_package_for_file(&f.path, packages)
                        .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
                    && !pkg.config.is_file_ignored(&f.path, &pkg.root_dir)
            })
            .collect();

        evaluate_duplicated_helpers_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_prefer_fluent_builder_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_inline_terminal_ui_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
    }
}

fn evaluate_duplicated_helpers_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
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
    let min_stmts = pkg.config.architecture.min_helper_statements;
    let min_modules = pkg.config.architecture.min_duplicated_helper_modules;

    let mut by_fingerprint: BTreeMap<(u64, usize), Vec<(&FileIr, &HelperFingerprintIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for helper in &file.architecture_facets.helper_fingerprints {
            if !helper.is_private || helper.statement_count < min_stmts {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    helper.loc.line,
                    helper.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            by_fingerprint
                .entry((helper.normalized_hash, helper.param_count))
                .or_default()
                .push((file, helper));
        }
    }

    for ((hash, param_count), occurrences) in by_fingerprint {
        let distinct_files: BTreeSet<&Path> =
            occurrences.iter().map(|(f, _)| f.path.as_path()).collect();
        if distinct_files.len() < min_modules {
            continue;
        }

        let first_name = &occurrences[0].1.name;
        let all_same_name = occurrences.iter().all(|(_, h)| &h.name == first_name);
        let shared_target_name = if all_same_name {
            first_name.clone()
        } else {
            format!(
                "{}::arity{}::hash_{:08x}",
                first_name,
                param_count,
                (hash & 0xffff_ffff) as u32
            )
        };

        let cascade_steps: Vec<String> = occurrences
            .iter()
            .map(|(f, h)| {
                format!(
                    "{}:{} (`{}`: {} stmts, arity {})",
                    f.path.to_string_lossy().replace('\\', "/"),
                    h.loc.line,
                    h.name,
                    h.statement_count,
                    h.param_count
                )
            })
            .collect();

        for (idx, &(file, helper)) in occurrences.iter().enumerate() {
            let Some(sev) = resolve_activation(
                RuleId::ArchNoDuplicatedHelperLogic,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };

            let peer_caller_sites: Vec<ResolvedCallerSite> = occurrences
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_helper))| ResolvedCallerSite {
                    caller_file: peer_file.path.clone(),
                    parent_subject_name: Some(peer_helper.name.clone()),
                    component_name: helper.name.clone(),
                    loc: peer_helper.loc,
                    span: peer_helper.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            let peer_files_summary: Vec<String> = occurrences
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_helper))| {
                    format!(
                        "`{}` in `{}:{}`",
                        peer_helper.name,
                        peer_file.path.to_string_lossy().replace('\\', "/"),
                        peer_helper.loc.line
                    )
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    file.path.clone(),
                    Some(helper.name.clone()),
                    "archNoDuplicatedHelperLogic",
                    shared_target_name.clone(),
                    format!(
                        "Private helper `{}` ({} statements, arity {}) duplicates normalized AST structure across {} modules ({}); extract a shared helper module.",
                        helper.name,
                        helper.statement_count,
                        helper.param_count,
                        distinct_files.len(),
                        peer_files_summary.join(", ")
                    ),
                    helper.loc,
                    helper.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}

fn extract_builder_facets_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let mut defined_builders: BTreeSet<String> = BTreeSet::new();
    let mut builder_body_spans: Vec<Span> = Vec::new();
    let mut local_type_shapes: Vec<(String, BTreeSet<String>)> = Vec::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Class(cls) => {
                let Some(id) = &cls.id else {
                    continue;
                };
                let cls_name = id.name.as_str();
                let mut is_builder_cls = false;
                if let Some(base) = cls_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(cls_name.to_string());
                    defined_builders.insert(base.to_string());
                    is_builder_cls = true;
                }
                let has_fluent_methods = cls.body.body.iter().any(|el| {
                    let ClassElement::MethodDefinition(m) = el else {
                        return false;
                    };
                    let Some(m_key) = m.key.static_name() else {
                        return false;
                    };
                    let Some(m_name) = m_key.as_str() else {
                        return false;
                    };
                    m_name == "builder"
                        || (m_name.starts_with("with")
                            && m_name.as_bytes().get(4).is_some_and(u8::is_ascii_uppercase))
                });
                if has_fluent_methods {
                    defined_builders.insert(cls_name.to_string());
                    is_builder_cls = true;
                }
                if is_builder_cls {
                    builder_body_spans.push(cls.span);
                }
            }
            AstKind::TSInterfaceDeclaration(iface) => {
                let iface_name = iface.id.name.as_str();
                if let Some(base) = iface_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(iface_name.to_string());
                    defined_builders.insert(base.to_string());
                }
                let prop_names = collect_ts_property_names(&iface.body.body);
                if prop_names.len() >= 3 {
                    local_type_shapes.push((iface_name.to_string(), prop_names));
                }
            }
            AstKind::TSTypeAliasDeclaration(alias) => {
                let alias_name = alias.id.name.as_str();
                if let Some(base) = alias_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(alias_name.to_string());
                    defined_builders.insert(base.to_string());
                }
                if let TSType::TSTypeLiteral(lit) = &alias.type_annotation {
                    let prop_names = collect_ts_property_names(&lit.members);
                    if prop_names.len() >= 3 {
                        local_type_shapes.push((alias_name.to_string(), prop_names));
                    }
                }
            }
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && let Some(target_type) = extract_factory_target_type(
                        id.name.as_str(),
                        func.return_type.as_ref().map(|r| &r.type_annotation),
                    )
                {
                    defined_builders.insert(target_type);
                    builder_body_spans.push(func.span);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let BindingPattern::BindingIdentifier(id) = &decl.id
                    && let Some(init) = decl.init.as_ref().map(Expression::without_parentheses)
                {
                    let ret_type = match init {
                        Expression::ArrowFunctionExpression(a) => {
                            a.return_type.as_ref().map(|r| &r.type_annotation)
                        }
                        Expression::FunctionExpression(f) => {
                            f.return_type.as_ref().map(|r| &r.type_annotation)
                        }
                        _ => None,
                    };
                    if matches!(
                        init,
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    ) && let Some(target_type) =
                        extract_factory_target_type(id.name.as_str(), ret_type)
                    {
                        defined_builders.insert(target_type);
                        builder_body_spans.push(decl.span);
                    }
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && mem.property.name == "builder"
                    && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                {
                    defined_builders.insert(obj_id.name.to_string());
                }
            }
            _ => {}
        }
    }

    facets.defined_builder_types.extend(defined_builders);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ObjectExpression(obj) = node.kind() else {
            continue;
        };
        if builder_body_spans
            .iter()
            .any(|sp| obj.span.start >= sp.start && obj.span.end <= sp.end)
        {
            continue;
        }
        let mut field_names = Vec::new();
        let mut default_or_literal_fields = Vec::new();
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Some(key_name) = prop.key.static_name() else {
                continue;
            };
            let Some(key_s) = key_name.as_str() else {
                continue;
            };
            let key_str = key_s.to_string();
            if is_default_or_boilerplate_literal(&prop.value) {
                default_or_literal_fields.push(key_str.clone());
            }
            field_names.push(key_str);
        }

        if field_names.len() < 3 || default_or_literal_fields.is_empty() {
            continue;
        }

        let (type_name, site_span) = resolve_object_literal_type_and_span(
            semantic,
            node_id,
            obj.span,
            &field_names,
            &local_type_shapes,
        );
        let Some(resolved_type) = type_name else {
            continue;
        };

        facets
            .struct_literal_sites
            .push(StructLiteralConstructionSiteIr {
                type_name: resolved_type,
                field_names,
                default_or_literal_fields,
                loc: loc_from_line_starts(line_starts, site_span.start),
                span: ByteSpan {
                    start: site_span.start,
                    end: site_span.end,
                },
            });
    }
}

fn extract_factory_target_type(fn_name: &str, return_type: Option<&TSType<'_>>) -> Option<String> {
    for prefix in ["create", "build", "make"] {
        if let Some(rest) = fn_name.strip_prefix(prefix)
            && rest.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        {
            if let Some(ret) = return_type.and_then(extract_ts_type_ref_name) {
                if ret == rest {
                    return Some(ret);
                }
            } else {
                return Some(rest.to_string());
            }
        }
    }
    if let Some(base) = fn_name.strip_suffix("Builder")
        && !base.is_empty()
    {
        let mut chars = base.chars();
        if let Some(first) = chars.next() {
            let mut pascal = first.to_ascii_uppercase().to_string();
            pascal.push_str(chars.as_str());
            return Some(pascal);
        }
    }
    None
}

fn extract_ts_type_ref_name(ts_type: &TSType<'_>) -> Option<String> {
    match ts_type {
        TSType::TSTypeReference(type_ref) => match &type_ref.type_name {
            TSTypeName::IdentifierReference(ident) => {
                if matches!(ident.name.as_str(), "Array" | "ReadonlyArray") {
                    type_ref
                        .type_arguments
                        .as_ref()
                        .and_then(|args| args.params.first())
                        .and_then(extract_ts_type_ref_name)
                } else {
                    Some(ident.name.to_string())
                }
            }
            TSTypeName::QualifiedName(q) => Some(q.right.name.to_string()),
            TSTypeName::ThisExpression(_) => None,
        },
        TSType::TSArrayType(arr) => extract_ts_type_ref_name(&arr.element_type),
        TSType::TSParenthesizedType(p) => extract_ts_type_ref_name(&p.type_annotation),
        _ => None,
    }
}

fn is_default_or_boilerplate_literal(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => u.operator.as_str() == "void",
        Expression::BooleanLiteral(b) => !b.value,
        Expression::NumericLiteral(n) => n.value == 0.0,
        Expression::BigIntLiteral(b) => b.value == "0",
        Expression::StringLiteral(s) => s.value.is_empty(),
        Expression::TemplateLiteral(t) => {
            t.expressions.is_empty() && t.quasis.iter().all(|q| q.value.raw.is_empty())
        }
        Expression::ArrayExpression(arr) => arr.elements.is_empty(),
        Expression::ObjectExpression(obj) => obj.properties.is_empty(),
        _ => false,
    }
}

fn resolve_object_literal_type_and_span(
    semantic: &Semantic<'_>,
    obj_node_id: NodeId,
    obj_span: Span,
    field_names: &[String],
    local_type_shapes: &[(String, BTreeSet<String>)],
) -> (Option<String>, Span) {
    for anc_id in semantic.nodes().ancestor_ids(obj_node_id) {
        if anc_id == obj_node_id {
            continue;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_) => {}
            AstKind::TSTypeAssertion(ta) => {
                if let Some(name) = extract_ts_type_ref_name(&ta.type_annotation) {
                    return (Some(name), ta.span);
                }
            }
            AstKind::TSAsExpression(as_e) => {
                if let Some(name) = extract_ts_type_ref_name(&as_e.type_annotation) {
                    return (Some(name), as_e.span);
                }
            }
            AstKind::TSSatisfiesExpression(sat_e) => {
                if let Some(name) = extract_ts_type_ref_name(&sat_e.type_annotation) {
                    return (Some(name), sat_e.span);
                }
            }
            AstKind::NewExpression(new_e) => {
                let name_opt = match new_e.callee.without_parentheses() {
                    Expression::Identifier(id) => Some(id.name.to_string()),
                    Expression::StaticMemberExpression(mem) => Some(mem.property.name.to_string()),
                    _ => None,
                };
                if let Some(name) = name_opt {
                    return (Some(name), new_e.span);
                }
                break;
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(ann) = &decl.type_annotation
                    && let Some(name) = extract_ts_type_ref_name(&ann.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::PropertyDefinition(prop) => {
                if let Some(ann) = &prop.type_annotation
                    && let Some(name) = extract_ts_type_ref_name(&ann.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ReturnStatement(_) => {
                if let Some(name) = enclosing_function_return_type_name(semantic, anc_id) {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                if let Some(ret) = &arrow.return_type
                    && let Some(name) = extract_ts_type_ref_name(&ret.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ObjectExpression(_) | AstKind::CallExpression(_) | AstKind::Function(_) => {
                break;
            }
            _ => {}
        }
    }

    let field_set: BTreeSet<String> = field_names.iter().cloned().collect();
    if let Some((matched_type, _)) = local_type_shapes
        .iter()
        .find(|(_, props)| props == &field_set)
    {
        return (Some(matched_type.clone()), obj_span);
    }

    if field_names.len() >= 5 {
        let sorted: Vec<&str> = field_set.iter().map(String::as_str).collect();
        return (Some(format!("ObjectShape<{}>", sorted.join(","))), obj_span);
    }

    (None, obj_span)
}

fn collect_ts_property_names(signatures: &[TSSignature<'_>]) -> BTreeSet<String> {
    let mut prop_names = BTreeSet::new();
    for sig in signatures {
        if let TSSignature::TSPropertySignature(prop) = sig
            && let Some(key) = prop.key.static_name()
            && let Some(key_str) = key.as_str()
        {
            prop_names.insert(key_str.to_string());
        }
    }
    prop_names
}

fn enclosing_function_return_type_name(
    semantic: &Semantic<'_>,
    start_id: NodeId,
) -> Option<String> {
    for fn_anc_id in semantic.nodes().ancestor_ids(start_id) {
        match semantic.nodes().kind(fn_anc_id) {
            AstKind::Function(func) => {
                return func
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                return arrow
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            _ => {}
        }
    }
    None
}

fn evaluate_prefer_fluent_builder_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
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
    let min_fields = pkg.config.architecture.min_builder_fields;
    let min_sites = pkg.config.architecture.min_builder_sites;

    let defined_builders: HashSet<&str> = pkg_files
        .iter()
        .flat_map(|f| {
            f.architecture_facets
                .defined_builder_types
                .iter()
                .map(String::as_str)
        })
        .collect();

    let mut sites_by_type: BTreeMap<&str, Vec<(&FileIr, &StructLiteralConstructionSiteIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for site in &file.architecture_facets.struct_literal_sites {
            if site.field_names.len() < min_fields {
                continue;
            }
            if defined_builders.contains(site.type_name.as_str()) {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchPreferFluentBuilder,
                    site.loc.line,
                    site.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            sites_by_type
                .entry(site.type_name.as_str())
                .or_default()
                .push((file, site));
        }
    }

    for (type_name, sites) in sites_by_type {
        if sites.len() < min_sites {
            continue;
        }

        let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for &(_, site) in &sites {
            let unique_defaults: BTreeSet<&str> = site
                .default_or_literal_fields
                .iter()
                .map(String::as_str)
                .collect();
            for field in unique_defaults {
                *default_field_counts.entry(field).or_insert(0) += 1;
            }
        }

        let overlapping_defaults: Vec<&str> = default_field_counts
            .into_iter()
            .filter_map(|(field, count)| (count >= 2).then_some(field))
            .collect();
        if overlapping_defaults.len() < 2 {
            continue;
        }

        let qualifying_sites: Vec<(&FileIr, &StructLiteralConstructionSiteIr)> = sites
            .into_iter()
            .filter(|(_, s)| {
                s.default_or_literal_fields
                    .iter()
                    .filter(|f| overlapping_defaults.contains(&f.as_str()))
                    .count()
                    >= 2
            })
            .collect();
        if qualifying_sites.len() < min_sites {
            continue;
        }

        let cascade_steps: Vec<String> = qualifying_sites
            .iter()
            .map(|(f, s)| {
                format!(
                    "{}:{} (`{}`: {} fields, defaults=[{}])",
                    f.path.to_string_lossy().replace('\\', "/"),
                    s.loc.line,
                    s.type_name,
                    s.field_names.len(),
                    s.default_or_literal_fields.join(", ")
                )
            })
            .collect();

        for (idx, &(file, site)) in qualifying_sites.iter().enumerate() {
            let Some(sev) = resolve_activation(
                RuleId::ArchPreferFluentBuilder,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };

            let peer_caller_sites: Vec<ResolvedCallerSite> = qualifying_sites
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_site))| ResolvedCallerSite {
                    caller_file: peer_file.path.clone(),
                    parent_subject_name: None,
                    component_name: type_name.to_string(),
                    loc: peer_site.loc,
                    span: peer_site.span,
                    has_key: false,
                    passed_props: peer_site.default_or_literal_fields.clone(),
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchPreferFluentBuilder,
                    file.path.clone(),
                    None,
                    "archPreferFluentBuilder",
                    type_name.to_string(),
                    format!(
                        "`{type_name}` ({} fields) is initialized across {} call sites with overlapping default/boilerplate fields (`{}`); introduce a fluent `{type_name}Builder` or `create{type_name}` factory.",
                        site.field_names.len(),
                        qualifying_sites.len(),
                        overlapping_defaults.join("`, `")
                    ),
                    site.loc,
                    site.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}

const BOX_DRAWING_CHARS: &[char] = &[
    '┌', '─', '┐', '│', '└', '┘', '╭', '╮', '╰', '╯', '├', '┤', '┬', '┴', '┼',
];

fn is_designated_ui_kit_path(path: &Path) -> bool {
    let norm = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if norm.contains("components/ui")
        || norm.contains("terminal_ui")
        || norm.contains("terminal-ui")
    {
        return true;
    }
    norm.split(['/', '_', '-', '.']).any(|seg| {
        matches!(
            seg,
            "ui" | "theme" | "themes" | "box" | "boxes" | "ansi" | "tui"
        )
    })
}

fn extract_inline_terminal_ui_sites_in_file(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let is_ui_kit = is_designated_ui_kit_path(path);
    facets.is_ui_kit_module = is_ui_kit;

    if is_ui_kit || classify_file_context(path) != FileContext::Production {
        return;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::StringLiteral(str_lit) => {
                let cooked_str = str_lit.value.as_str().unwrap_or_default();
                let raw_slice = source
                    .get(str_lit.span.start as usize..str_lit.span.end as usize)
                    .unwrap_or(cooked_str);
                if let Some((kind, snippet)) = classify_terminal_ui_literal(cooked_str, raw_slice) {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, str_lit.span.start),
                            span: ByteSpan {
                                start: str_lit.span.start,
                                end: str_lit.span.end,
                            },
                        });
                }
            }
            AstKind::TemplateLiteral(tpl) => {
                let raw_slice = source
                    .get(tpl.span.start as usize..tpl.span.end as usize)
                    .unwrap_or_default();
                let mut matched: Option<(String, String)> = None;
                for quasi in &tpl.quasis {
                    let cooked = quasi
                        .value
                        .cooked
                        .and_then(|c| c.as_str())
                        .unwrap_or(quasi.value.raw.as_str());
                    if let Some(hit) =
                        classify_terminal_ui_literal(cooked, quasi.value.raw.as_str())
                    {
                        matched = Some(hit);
                        break;
                    }
                }
                if matched.is_none() {
                    matched = classify_terminal_ui_literal(raw_slice, raw_slice);
                }
                if let Some((kind, snippet)) = matched {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, tpl.span.start),
                            span: ByteSpan {
                                start: tpl.span.start,
                                end: tpl.span.end,
                            },
                        });
                }
            }
            _ => {}
        }
    }
}

fn classify_terminal_ui_literal(cooked: &str, raw: &str) -> Option<(String, String)> {
    let raw_lower = raw.to_ascii_lowercase();
    if cooked.contains("\x1b[")
        || raw_lower.contains("\\x1b[")
        || raw_lower.contains("\\u001b[")
        || raw_lower.contains("\\u{1b}[")
        || raw_lower.contains("\\u{001b}[")
        || raw.contains("\\033[")
    {
        return Some(("ansi-escape".to_string(), "\\x1b[...]".to_string()));
    }
    if let Some(ch) = BOX_DRAWING_CHARS
        .iter()
        .copied()
        .find(|&c| cooked.contains(c) || raw.contains(c))
    {
        return Some(("box-drawing".to_string(), ch.to_string()));
    }
    None
}

fn evaluate_inline_terminal_ui_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
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
    for &file in pkg_files {
        if file.architecture_facets.is_ui_kit_module
            || file.architecture_facets.inline_terminal_ui_sites.is_empty()
        {
            continue;
        }
        let Some(sev) = resolve_activation(
            RuleId::ArchNoInlineTerminalUiPrimitives,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        let active_sites: Vec<&InlineTerminalUiPrimitiveSiteIr> = file
            .architecture_facets
            .inline_terminal_ui_sites
            .iter()
            .filter(|site| {
                !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::ArchNoInlineTerminalUiPrimitives,
                        site.loc.line,
                        site.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            })
            .collect();
        if active_sites.is_empty() {
            continue;
        }

        let file_stem = file
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();
        let cascade_steps: Vec<String> = active_sites
            .iter()
            .map(|s| {
                format!(
                    "{}:{} ({}: `{}`)",
                    file.path.to_string_lossy().replace('\\', "/"),
                    s.loc.line,
                    s.kind,
                    s.snippet
                )
            })
            .collect();

        for (idx, &site) in active_sites.iter().enumerate() {
            let peer_caller_sites: Vec<ResolvedCallerSite> = active_sites
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &peer)| ResolvedCallerSite {
                    caller_file: file.path.clone(),
                    parent_subject_name: None,
                    component_name: peer.kind.clone(),
                    loc: peer.loc,
                    span: peer.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchNoInlineTerminalUiPrimitives,
                    file.path.clone(),
                    None,
                    "archNoInlineTerminalUiPrimitives",
                    file_stem.clone(),
                    format!(
                        "Inline `{}` literal (`{}`) used in `{}` outside the terminal UI component kit; delegate to shared UI primitives.",
                        site.kind,
                        site.snippet,
                        file.path.to_string_lossy().replace('\\', "/")
                    ),
                    site.loc,
                    site.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}
