//! Builds `FileIr` and `SubjectIr` from a single pass of `oxc_parser` and `oxc_semantic`.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_allocator::Allocator;
use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, BindingPattern, CallExpression, Class, Declaration,
        ExportDefaultDeclarationKind, Expression, ImportDeclaration, ImportDeclarationSpecifier,
        Program, Statement, TSInterfaceDeclaration, VariableDeclarationKind,
    },
};
use oxc_parser::Parser;
use oxc_semantic::{NodeId, ReferenceId, Semantic, SemanticBuilder, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};

use crate::rules::RuleId;

use super::{
    dataflow::{
        extract_async_flows, extract_mutations, extract_security_sinks,
        extract_semantic_rule_sites, get_all_refs_in_span, get_args_upstream_refs, get_call_expr,
        get_downstream_refs_in_span, get_state_name, get_upstream_refs, get_use_state_decl_node,
        is_non_external_data_leaf, is_prop, is_prop_call, is_ref_call, is_state, is_state_call,
        is_state_setter, is_synchronous,
    },
    react_ast::{
        RefEntry, extract_caller_sites, extract_jsx_elements, find_enclosing_react_node,
        get_effect_cleanup_span, get_effect_fn_node, get_subject_name, is_component_name,
        is_custom_hook, is_functional_hoc, is_react_hook_callee, is_use_effect_call,
    },
    types::{
        BlockDisableRange, ByteSpan, DepRef, DepsSpec, EffectNode, ExportDeclIr, ExternalStoreSite,
        FetchSite, FileIr, FileSuppressions, IfGuardSite, ImportDeclIr, LineDisableDirective,
        ModuleIr, PropCallSite, SetterCallSite, SourceLoc, StateSlot, SubjectIr, SubjectKind,
        SymbolKind, SymbolOutline, classify_file_context, compute_line_starts,
        loc_from_line_starts,
    },
};
/// Parses a JS/TS/JSX/TSX file from `source` once via `oxc_parser` and `oxc_semantic`,
/// extracting its complete [`FileIr`].
#[must_use]
pub fn parse_file_ir(path: &Path, source: &str) -> FileIr {
    inspect_file_semantic(path, source, |file_ir, _semantic| file_ir.clone())
}

/// Parses `source` once with `oxc_parser` and `oxc_semantic`, constructs [`FileIr`],
/// and invokes `f(&FileIr, &Semantic<'_>)` while the semantic AST and scope tree are live.
#[must_use]
pub fn inspect_file_semantic<F, R>(path: &Path, source: &str, f: F) -> R
where
    F: FnOnce(&FileIr, &Semantic<'_>) -> R,
{
    let line_starts = compute_line_starts(source);
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);

    let parsed = Parser::new(&allocator, source, source_type).parse();
    let semantic_ret = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program);
    let semantic = semantic_ret.semantic;

    let ref_entries = collect_ref_entries(&semantic);
    let subjects = extract_subjects(&semantic, &ref_entries, &line_starts);
    let caller_sites = extract_caller_sites(&semantic, &line_starts);
    let jsx_elements = extract_jsx_elements(&semantic, &line_starts);
    let module = extract_module_ir(&parsed.program, &semantic, &line_starts);
    let symbol_outlines = extract_symbol_outlines(&parsed.program, source, &line_starts);
    let mutations = extract_mutations(&semantic, &ref_entries, &line_starts);
    let async_flows = extract_async_flows(&semantic, &line_starts);
    let security_sinks = extract_security_sinks(&parsed.program, &semantic, &module, &line_starts);
    let suppressions = extract_file_suppressions(source);
    let semantic_sites = extract_semantic_rule_sites(&semantic, &ref_entries, &line_starts);

    let file_ir = FileIr {
        path: path.to_path_buf(),
        file_context: classify_file_context(path),
        subjects,
        caller_sites,
        jsx_elements,
        module,
        symbol_outlines,
        mutations,
        async_flows,
        security_sinks,
        suppressions,
        semantic_sites,
    };

    f(&file_ir, &semantic)
}

fn collect_ref_entries(semantic: &Semantic<'_>) -> Vec<RefEntry> {
    let mut entries = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::IdentifierReference(ident) = node.kind()
            && let Some(ref_id) = ident.reference_id.get()
        {
            entries.push(RefEntry {
                node_id,
                ref_id,
                span: ident.span,
            });
        }
    }
    entries
}

fn extract_subjects(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
) -> Vec<SubjectIr> {
    let mut subject_nodes: Vec<NodeId> = Vec::new();
    let mut seen_subjects: HashSet<NodeId> = HashSet::new();
    let mut orphan_effects: Vec<NodeId> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            subject_nodes.push(subj_id);
        }
        if let AstKind::CallExpression(call) = node.kind()
            && is_use_effect_call(semantic, call)
            && find_enclosing_react_node(semantic, node_id).is_none()
        {
            orphan_effects.push(node_id);
        }
    }

    let mut subjects = Vec::new();
    for subj_id in subject_nodes {
        subjects.push(build_subject_ir(
            semantic,
            ref_entries,
            line_starts,
            Some(subj_id),
            None,
        ));
    }
    if !orphan_effects.is_empty() {
        subjects.push(build_subject_ir(
            semantic,
            ref_entries,
            line_starts,
            None,
            Some(&orphan_effects),
        ));
    }
    subjects
}

fn build_subject_ir(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    subject_node_id: Option<NodeId>,
    orphan_effect_ids: Option<&[NodeId]>,
) -> SubjectIr {
    let (name, kind, is_hoc_wrapped, span) = match subject_node_id {
        Some(id) => {
            let s = semantic.nodes().get_node(id).span();
            let k = if is_custom_hook(semantic, id) {
                SubjectKind::CustomHook
            } else {
                SubjectKind::Component
            };
            (
                get_subject_name(semantic, id),
                k,
                is_functional_hoc(semantic, id),
                ByteSpan {
                    start: s.start,
                    end: s.end,
                },
            )
        }
        None => (
            None,
            SubjectKind::Component,
            false,
            ByteSpan { start: 0, end: 0 },
        ),
    };

    let effect_call_ids: Vec<NodeId> = match (subject_node_id, orphan_effect_ids) {
        (Some(subj_id), _) => collect_subject_effects(semantic, subj_id),
        (None, Some(orphans)) => orphans.to_vec(),
        (None, None) => Vec::new(),
    };

    let effect_spans: Vec<Span> = effect_call_ids
        .iter()
        .map(|&id| semantic.nodes().get_node(id).span())
        .collect();

    let (state_slots, decl_to_slot) = match subject_node_id {
        Some(subj_id) => collect_state_slots(semantic, subj_id, &effect_spans),
        None => (Vec::new(), HashMap::new()),
    };

    let mut effect_nodes = Vec::new();
    for (idx, &call_id) in effect_call_ids.iter().enumerate() {
        if let Some(effect_node) = build_effect_node(
            semantic,
            ref_entries,
            line_starts,
            idx,
            call_id,
            &decl_to_slot,
        ) {
            effect_nodes.push(effect_node);
        }
    }

    SubjectIr {
        name,
        kind,
        is_hoc_wrapped,
        loc: loc_from_line_starts(line_starts, span.start),
        span,
        state_slots,
        effect_nodes,
    }
}

fn collect_subject_effects(semantic: &Semantic<'_>, subject_node_id: NodeId) -> Vec<NodeId> {
    let mut ids = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::CallExpression(call) = node.kind()
            && is_use_effect_call(semantic, call)
            && find_enclosing_react_node(semantic, node_id) == Some(subject_node_id)
        {
            ids.push(node_id);
        }
    }
    ids
}

fn collect_state_slots(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    effect_spans: &[Span],
) -> (Vec<StateSlot>, HashMap<NodeId, usize>) {
    let mut slots = Vec::new();
    let mut decl_to_slot = HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        if find_enclosing_react_node(semantic, node_id) != Some(subject_node_id) {
            continue;
        }
        let Some(Expression::CallExpression(call)) =
            decl.init.as_ref().map(Expression::without_parentheses)
        else {
            continue;
        };
        if !is_react_hook_callee(semantic, &call.callee, "useState") {
            continue;
        }
        let BindingPattern::ArrayPattern(arr) = &decl.id else {
            continue;
        };
        if arr.elements.is_empty() || arr.elements.len() > 2 {
            continue;
        }

        let state_name = match arr.elements.first().and_then(Option::as_ref) {
            Some(BindingPattern::BindingIdentifier(id)) => Some(id.name.to_string()),
            _ => None,
        };
        let (setter_name, setter_sym) = match arr.elements.get(1).and_then(Option::as_ref) {
            Some(BindingPattern::BindingIdentifier(id)) => {
                (Some(id.name.to_string()), id.symbol_id.get())
            }
            _ => (None, None),
        };
        let Some(display_name) = state_name.clone().or_else(|| setter_name.clone()) else {
            continue;
        };

        let (outside_calls, effect_calls, escaped) =
            classify_setter_usage(semantic, setter_sym, effect_spans);

        let init_arg_text = call.arguments.first().map(|arg| {
            arg.span()
                .source_text(semantic.source_text())
                .trim()
                .to_string()
        });

        let decl_stmt_span = find_standalone_var_decl_span(semantic, node_id);
        let idx = slots.len();
        decl_to_slot.insert(node_id, idx);
        slots.push(StateSlot {
            index: idx,
            state_name,
            setter_name,
            display_name,
            decl_stmt_span,
            call_span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            init_arg_text,
            setter_calls_outside_effects: outside_calls,
            setter_calls_in_effects: effect_calls,
            setter_escaped: escaped,
        });
    }

    (slots, decl_to_slot)
}

fn find_standalone_var_decl_span(
    semantic: &Semantic<'_>,
    declarator_id: NodeId,
) -> Option<ByteSpan> {
    let parent_id = semantic.nodes().parent_id(declarator_id);
    if let AstKind::VariableDeclaration(var_decl) = semantic.nodes().kind(parent_id)
        && var_decl.declarations.len() == 1
    {
        return Some(ByteSpan {
            start: var_decl.span.start,
            end: var_decl.span.end,
        });
    }
    None
}

fn classify_setter_usage(
    semantic: &Semantic<'_>,
    setter_sym: Option<SymbolId>,
    effect_spans: &[Span],
) -> (usize, usize, bool) {
    let Some(sym_id) = setter_sym else {
        return (0, 0, false);
    };
    let mut outside = 0;
    let mut in_effects = 0;
    let mut escaped = false;

    for reference in semantic.scoping().get_resolved_references(sym_id) {
        let ref_node = semantic.nodes().get_node(reference.node_id());
        let ref_span = ref_node.span();
        let inside_effect = effect_spans.iter().any(|s| s.contains_inclusive(ref_span));
        if inside_effect {
            in_effects += 1;
        } else {
            outside += 1;
        }

        let parent_kind = semantic.nodes().parent_kind(reference.node_id());
        let is_direct_callee = matches!(
            parent_kind,
            AstKind::CallExpression(call) if call.callee.span().contains_inclusive(ref_span)
        );
        if !is_direct_callee {
            escaped = true;
        }
    }

    (outside, in_effects, escaped)
}

fn build_effect_node(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    index: usize,
    call_node_id: NodeId,
    decl_to_slot: &HashMap<NodeId, usize>,
) -> Option<EffectNode> {
    let AstKind::CallExpression(call) = semantic.nodes().kind(call_node_id) else {
        return None;
    };
    let effect_fn_id = get_effect_fn_node(semantic, call_node_id)?;
    let effect_fn_span = semantic.nodes().get_node(effect_fn_id).span();
    let cleanup_span = get_effect_cleanup_span(semantic, effect_fn_id);
    let has_cleanup = cleanup_span.is_some();

    let fn_refs = get_downstream_refs_in_span(semantic, ref_entries, effect_fn_span);
    let deps = extract_deps_spec(semantic, ref_entries, call, decl_to_slot);
    let cleanup_syms = collect_cleanup_symbols(semantic, ref_entries, cleanup_span);

    let sync_setter_calls = extract_sync_setter_calls(
        semantic,
        ref_entries,
        line_starts,
        effect_fn_id,
        &cleanup_syms,
        decl_to_slot,
    );

    let external_store_sites = sync_setter_calls
        .iter()
        .filter(|s| has_cleanup && s.shares_cleanup_symbol)
        .map(|s| ExternalStoreSite {
            state_name: s.state_name.clone(),
            span: s.call_span,
            loc: s.loc,
        })
        .collect();

    let sync_prop_calls =
        extract_sync_prop_calls(semantic, ref_entries, line_starts, effect_fn_id, &fn_refs);

    let if_guards = if has_cleanup {
        Vec::new()
    } else {
        extract_if_guards(
            semantic,
            ref_entries,
            line_starts,
            effect_fn_id,
            effect_fn_span,
        )
    };

    let fetch_sites = extract_fetch_sites(
        semantic,
        ref_entries,
        line_starts,
        effect_fn_id,
        effect_fn_span,
        has_cleanup,
    );

    let stmt_span = match semantic.nodes().parent_kind(call_node_id) {
        AstKind::ExpressionStatement(stmt) => Some(ByteSpan {
            start: stmt.span.start,
            end: stmt.span.end,
        }),
        _ => None,
    };

    let top_level_stmt_count = count_effect_top_level_statements(semantic, effect_fn_id);

    Some(EffectNode {
        index,
        call_span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        stmt_span,
        loc: loc_from_line_starts(line_starts, call.span.start),
        deps,
        has_cleanup,
        top_level_stmt_count,
        sync_setter_calls,
        sync_prop_calls,
        if_guards,
        external_store_sites,
        fetch_sites,
    })
}

fn count_effect_top_level_statements(semantic: &Semantic<'_>, effect_fn_id: NodeId) -> usize {
    match semantic.nodes().kind(effect_fn_id) {
        AstKind::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => body.statements.len(),
            _ => 1,
        },
        AstKind::Function(func) => func.body.as_ref().map_or(0, |b| b.statements.len()),
        _ => 0,
    }
}

fn extract_deps_spec(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    call: &CallExpression<'_>,
    decl_to_slot: &HashMap<NodeId, usize>,
) -> DepsSpec {
    let Some(second_arg) = call.arguments.get(1).and_then(|a| a.as_expression()) else {
        return DepsSpec::Omitted;
    };
    let Expression::ArrayExpression(arr) = second_arg.without_parentheses() else {
        return DepsSpec::Omitted;
    };

    let deps_refs = get_downstream_refs_in_span(semantic, ref_entries, arr.span);
    let non_setter_count = deps_refs
        .iter()
        .filter(|&&r| !is_state_setter(semantic, r))
        .count();

    if non_setter_count == 0 {
        return DepsSpec::MountOnly;
    }

    let mut items = Vec::new();
    for dep_ref in deps_refs {
        let name = semantic
            .reference_name(semantic.scoping().get_reference(dep_ref))
            .to_string();
        let mut upstream_state_indices = Vec::new();
        let mut upstream_prop_names = Vec::new();

        for up_ref in get_upstream_refs(semantic, ref_entries, dep_ref) {
            collect_dep_upstream(
                semantic,
                ref_entries,
                up_ref,
                decl_to_slot,
                &mut upstream_state_indices,
                &mut upstream_prop_names,
            );
        }

        items.push(DepRef {
            name,
            upstream_state_indices,
            upstream_prop_names,
        });
    }

    DepsSpec::Tracked(items)
}

fn collect_dep_upstream(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    up_ref: ReferenceId,
    decl_to_slot: &HashMap<NodeId, usize>,
    upstream_state_indices: &mut Vec<usize>,
    upstream_prop_names: &mut Vec<String>,
) {
    if is_state(semantic, up_ref)
        && let Some(decl_id) = get_use_state_decl_node(semantic, ref_entries, up_ref)
        && let Some(&slot_idx) = decl_to_slot.get(&decl_id)
        && !upstream_state_indices.contains(&slot_idx)
    {
        upstream_state_indices.push(slot_idx);
    }
    if is_prop(semantic, up_ref) {
        let prop_name = semantic
            .reference_name(semantic.scoping().get_reference(up_ref))
            .to_string();
        if !upstream_prop_names.contains(&prop_name) {
            upstream_prop_names.push(prop_name);
        }
    }
}

fn collect_cleanup_symbols(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    cleanup_span: Option<Span>,
) -> HashSet<SymbolId> {
    let mut syms = HashSet::new();
    let Some(span) = cleanup_span else {
        return syms;
    };
    for ref_id in get_all_refs_in_span(ref_entries, span) {
        for up_ref in get_upstream_refs(semantic, ref_entries, ref_id) {
            if let Some(sym_id) = semantic.scoping().get_reference(up_ref).symbol_id() {
                syms.insert(sym_id);
            }
        }
    }
    syms
}

fn extract_sync_setter_calls(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    effect_fn_id: NodeId,
    cleanup_syms: &HashSet<SymbolId>,
    decl_to_slot: &HashMap<NodeId, usize>,
) -> Vec<SetterCallSite> {
    let effect_fn_span = semantic.nodes().get_node(effect_fn_id).span();
    let fn_refs = get_downstream_refs_in_span(semantic, ref_entries, effect_fn_span);
    let mut out = Vec::new();
    for &ref_id in &fn_refs {
        let ref_node_id = semantic.scoping().get_reference(ref_id).node_id();
        if !is_synchronous(semantic, ref_node_id, effect_fn_id)
            || !is_state_call(semantic, ref_entries, ref_id)
        {
            continue;
        }
        let Some(call_id) = get_call_expr(semantic, ref_id) else {
            continue;
        };
        let AstKind::CallExpression(call) = semantic.nodes().kind(call_id) else {
            continue;
        };
        let Some(state_name) = get_state_name(semantic, ref_entries, ref_id) else {
            continue;
        };
        let state_slot_index = get_use_state_decl_node(semantic, ref_entries, ref_id)
            .and_then(|decl_id| decl_to_slot.get(&decl_id).copied());

        let args_upstream = get_args_upstream_refs(semantic, ref_entries, ref_id);
        let mut arg_summary = SetterArgUpstream::default();
        for up_ref in args_upstream {
            collect_setter_arg_upstream(
                semantic,
                ref_entries,
                up_ref,
                decl_to_slot,
                &mut arg_summary,
            );
        }

        let first_arg = call.arguments.first();
        let arg_text = first_arg.map_or_else(
            || "undefined".to_string(),
            |arg| arg.span().source_text(semantic.source_text()).to_string(),
        );
        let is_updater_fn = first_arg
            .and_then(|a| a.as_expression())
            .is_some_and(|expr| {
                matches!(
                    expr.without_parentheses(),
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                )
            });

        let resets_to_initial_value =
            check_resets_to_initial_value(semantic, ref_entries, ref_id, call);

        let shares_cleanup_symbol = get_upstream_refs(semantic, ref_entries, ref_id)
            .into_iter()
            .any(|up_ref| {
                semantic
                    .scoping()
                    .get_reference(up_ref)
                    .symbol_id()
                    .is_some_and(|sym| cleanup_syms.contains(&sym))
            });

        out.push(SetterCallSite {
            state_slot_index,
            state_name,
            call_span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            loc: loc_from_line_starts(line_starts, call.span.start),
            arg_text,
            is_updater_fn,
            arg_reads_state: arg_summary.reads_state,
            arg_state_indices: arg_summary.state_indices,
            arg_reads_prop: arg_summary.reads_prop,
            arg_prop_names: arg_summary.prop_names,
            resets_to_initial_value,
            shares_cleanup_symbol,
        });
    }
    out
}

#[derive(Default)]
struct SetterArgUpstream {
    reads_state: bool,
    state_indices: Vec<usize>,
    reads_prop: bool,
    prop_names: Vec<String>,
}

fn collect_setter_arg_upstream(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    up_ref: ReferenceId,
    decl_to_slot: &HashMap<NodeId, usize>,
    summary: &mut SetterArgUpstream,
) {
    if is_state(semantic, up_ref) {
        summary.reads_state = true;
        if let Some(decl_id) = get_use_state_decl_node(semantic, ref_entries, up_ref)
            && let Some(&idx) = decl_to_slot.get(&decl_id)
            && !summary.state_indices.contains(&idx)
        {
            summary.state_indices.push(idx);
        }
    }
    if is_prop(semantic, up_ref) {
        summary.reads_prop = true;
        let p_name = semantic
            .reference_name(semantic.scoping().get_reference(up_ref))
            .to_string();
        if !summary.prop_names.contains(&p_name) {
            summary.prop_names.push(p_name);
        }
    }
}

fn check_resets_to_initial_value(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    setter_ref: ReferenceId,
    setter_call: &CallExpression<'_>,
) -> bool {
    let Some(decl_id) = get_use_state_decl_node(semantic, ref_entries, setter_ref) else {
        return false;
    };
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(init_call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };

    let set_arg = setter_call
        .arguments
        .first()
        .map(|a| a.span().source_text(semantic.source_text()).trim());
    let init_arg = init_call
        .arguments
        .first()
        .map(|a| a.span().source_text(semantic.source_text()).trim());

    let is_undef = |s: Option<&str>| matches!(s, None | Some("undefined"));
    if is_undef(set_arg) && is_undef(init_arg) {
        return true;
    }
    match (set_arg, init_arg) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn extract_sync_prop_calls(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    effect_fn_id: NodeId,
    fn_refs: &[ReferenceId],
) -> Vec<PropCallSite> {
    let mut out = Vec::new();
    for &ref_id in fn_refs {
        let ref_node_id = semantic.scoping().get_reference(ref_id).node_id();
        if !is_synchronous(semantic, ref_node_id, effect_fn_id)
            || !is_prop_call(semantic, ref_entries, ref_id)
        {
            continue;
        }
        let Some(call_id) = get_call_expr(semantic, ref_id) else {
            continue;
        };
        let AstKind::CallExpression(call) = semantic.nodes().kind(call_id) else {
            continue;
        };

        let prop_name = semantic
            .reference_name(semantic.scoping().get_reference(ref_id))
            .to_string();
        let args_upstream = get_args_upstream_refs(semantic, ref_entries, ref_id);

        let mut arg_state_names = Vec::new();
        let mut arg_external_data_names = Vec::new();

        for up_ref in args_upstream {
            if is_state(semantic, up_ref) {
                let s_name = semantic
                    .reference_name(semantic.scoping().get_reference(up_ref))
                    .to_string();
                arg_state_names.push(s_name);
            }
            if get_upstream_refs(semantic, ref_entries, up_ref).len() == 1
                && !is_non_external_data_leaf(semantic, up_ref)
            {
                let d_name = semantic
                    .reference_name(semantic.scoping().get_reference(up_ref))
                    .to_string();
                arg_external_data_names.push(d_name);
            }
        }

        out.push(PropCallSite {
            prop_name,
            call_span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            loc: loc_from_line_starts(line_starts, call.span.start),
            arg_state_names,
            arg_external_data_names,
            is_ref_call: is_ref_call(semantic, ref_entries, ref_id),
        });
    }
    out
}

fn extract_if_guards(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    effect_fn_id: NodeId,
    effect_fn_span: Span,
) -> Vec<IfGuardSite> {
    let mut guards = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::IfStatement(if_stmt) = node.kind() else {
            continue;
        };
        if if_stmt.alternate.is_some() || !effect_fn_span.contains_inclusive(if_stmt.span) {
            continue;
        }
        if !is_if_outside_call_args(
            semantic,
            node_id,
            if_stmt.span,
            effect_fn_id,
            effect_fn_span,
        ) {
            continue;
        }

        for test_ref in get_downstream_refs_in_span(semantic, ref_entries, if_stmt.test.span()) {
            let up_refs = get_upstream_refs(semantic, ref_entries, test_ref);
            let reads_state = up_refs.iter().any(|&r| is_state(semantic, r));
            let reads_prop = up_refs.iter().any(|&r| is_prop(semantic, r));
            if reads_state || reads_prop {
                let reference = semantic.scoping().get_reference(test_ref);
                let ref_span = semantic.reference_span(reference);
                guards.push(IfGuardSite {
                    identifier_name: semantic.reference_name(reference).to_string(),
                    span: ByteSpan {
                        start: ref_span.start,
                        end: ref_span.end,
                    },
                    loc: loc_from_line_starts(line_starts, ref_span.start),
                    reads_state,
                    reads_prop,
                });
            }
        }
    }
    guards
}

fn is_if_outside_call_args(
    semantic: &Semantic<'_>,
    if_node_id: NodeId,
    if_span: Span,
    effect_fn_id: NodeId,
    effect_fn_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(if_node_id) {
        if anc_id == effect_fn_id {
            return true;
        }
        let anc_node = semantic.nodes().get_node(anc_id);
        if !effect_fn_span.contains_inclusive(anc_node.span()) {
            return false;
        }
        match anc_node.kind() {
            AstKind::CallExpression(call) if !call.callee.span().contains_inclusive(if_span) => {
                return false;
            }
            AstKind::NewExpression(new_expr)
                if !new_expr.callee.span().contains_inclusive(if_span) =>
            {
                return false;
            }
            _ => {}
        }
    }
    false
}

fn extract_fetch_sites(
    semantic: &Semantic<'_>,
    ref_entries: &[RefEntry],
    line_starts: &[u32],
    effect_fn_id: NodeId,
    effect_fn_span: Span,
    has_cleanup: bool,
) -> Vec<FetchSite> {
    let all_refs = get_all_refs_in_span(ref_entries, effect_fn_span);
    let mut fetch_span: Option<Span> = None;
    let mut has_abort = has_cleanup;

    for &ref_id in &all_refs {
        let reference = semantic.scoping().get_reference(ref_id);
        let name = semantic.reference_name(reference);
        if name == "AbortController" || name == "abort" {
            has_abort = true;
        }
        if let Some(call_id) = get_call_expr(semantic, ref_id)
            && let AstKind::CallExpression(call) = semantic.nodes().kind(call_id)
            && is_fetch_callee(&call.callee)
        {
            fetch_span = Some(call.span);
        }
    }

    let Some(f_span) = fetch_span else {
        return Vec::new();
    };

    let mut sites = Vec::new();
    let mut seen_states = HashSet::new();
    for &ref_id in &all_refs {
        let ref_node_id = semantic.scoping().get_reference(ref_id).node_id();
        if !is_synchronous(semantic, ref_node_id, effect_fn_id)
            && is_state_setter(semantic, ref_id)
            && let Some(state_name) = get_state_name(semantic, ref_entries, ref_id)
            && seen_states.insert(state_name.clone())
        {
            sites.push(FetchSite {
                state_name,
                span: ByteSpan {
                    start: f_span.start,
                    end: f_span.end,
                },
                loc: loc_from_line_starts(line_starts, f_span.start),
                has_cancellation_guard: has_abort,
            });
        }
    }
    sites
}

fn is_fetch_callee(callee: &Expression<'_>) -> bool {
    match callee.without_parentheses() {
        Expression::Identifier(ident) => ident.name == "fetch",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "fetch"
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::Identifier(obj) if obj.name == "window" || obj.name == "globalThis"
                )
        }
        _ => false,
    }
}

fn extract_module_ir(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> ModuleIr {
    let mut module = ModuleIr::default();

    for dir in &program.directives {
        match dir.directive.as_str() {
            "use client" => module.has_use_client = true,
            "use server" => module.has_use_server = true,
            _ => {}
        }
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Directive(dir) => match dir.directive.as_str() {
                "use client" => module.has_use_client = true,
                "use server" => module.has_use_server = true,
                _ => {}
            },
            AstKind::ImportDeclaration(imp) => {
                let specifiers = extract_import_specifier_names(imp);
                module.imports.push(ImportDeclIr {
                    source: imp.source.value.as_str().unwrap_or_default().to_string(),
                    specifiers,
                    is_type_only: imp.import_kind.is_type(),
                    span: ByteSpan {
                        start: imp.span.start,
                        end: imp.span.end,
                    },
                    loc: loc_from_line_starts(line_starts, imp.span.start),
                });
            }
            AstKind::ImportExpression(dyn_imp) => {
                if let Expression::StringLiteral(s) = dyn_imp.source.without_parentheses()
                    && let Some(val) = s.value.as_str()
                {
                    module.dynamic_imports.push(val.to_string());
                }
            }
            AstKind::ExportDeclaration(exp) => {
                let loc = loc_from_line_starts(line_starts, exp.span.start);
                let span = ByteSpan {
                    start: exp.span.start,
                    end: exp.span.end,
                };
                collect_declaration_exports(
                    &exp.declaration,
                    false,
                    span,
                    loc,
                    &mut module.exports,
                );
            }
            AstKind::ExportNamedDeclaration(exp) => {
                let is_type_only = exp.export_kind.is_type();
                let loc = loc_from_line_starts(line_starts, exp.span.start);
                let span = ByteSpan {
                    start: exp.span.start,
                    end: exp.span.end,
                };
                for spec in &exp.specifiers {
                    let name = spec.exported.name().as_str().to_string();
                    module.exports.push(ExportDeclIr {
                        is_component: is_component_name(&name),
                        name,
                        from_source: None,
                        is_type_only: is_type_only || spec.export_kind.is_type(),
                        span,
                        loc,
                    });
                }
            }
            AstKind::ExportFromDeclaration(exp) => {
                let from_source = exp.source.value.as_str().map(str::to_string);
                let is_type_only = exp.export_kind.is_type();
                let loc = loc_from_line_starts(line_starts, exp.span.start);
                let span = ByteSpan {
                    start: exp.span.start,
                    end: exp.span.end,
                };
                for spec in &exp.specifiers {
                    let name = spec.exported.name().as_str().to_string();
                    module.exports.push(ExportDeclIr {
                        is_component: is_component_name(&name),
                        name,
                        from_source: from_source.clone(),
                        is_type_only: is_type_only || spec.export_kind.is_type(),
                        span,
                        loc,
                    });
                }
            }
            AstKind::ExportDefaultDeclaration(exp) => {
                let is_comp = match &exp.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                        f.id.as_ref().is_none_or(|id| is_component_name(&id.name))
                    }
                    _ => true,
                };
                module.exports.push(ExportDeclIr {
                    name: "default".to_string(),
                    from_source: None,
                    is_type_only: false,
                    is_component: is_comp,
                    span: ByteSpan {
                        start: exp.span.start,
                        end: exp.span.end,
                    },
                    loc: loc_from_line_starts(line_starts, exp.span.start),
                });
            }
            AstKind::ExportAllDeclaration(exp) => {
                module.exports.push(ExportDeclIr {
                    name: "*".to_string(),
                    from_source: exp.source.value.as_str().map(str::to_string),
                    is_type_only: exp.export_kind.is_type(),
                    is_component: false,
                    span: ByteSpan {
                        start: exp.span.start,
                        end: exp.span.end,
                    },
                    loc: loc_from_line_starts(line_starts, exp.span.start),
                });
            }
            _ => {}
        }
    }

    module
}

fn extract_import_specifier_names(imp: &ImportDeclaration<'_>) -> Vec<String> {
    let Some(specs) = &imp.specifiers else {
        return Vec::new();
    };
    specs
        .iter()
        .map(|spec| match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s) => s.local.name.to_string(),
            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => s.local.name.to_string(),
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => s.local.name.to_string(),
        })
        .collect()
}
fn collect_declaration_exports(
    decl: &Declaration<'_>,
    is_type_only: bool,
    span: ByteSpan,
    loc: SourceLoc,
    out: &mut Vec<ExportDeclIr>,
) {
    match decl {
        Declaration::FunctionDeclaration(f) => {
            if let Some(id) = &f.id {
                let name = id.name.to_string();
                out.push(ExportDeclIr {
                    is_component: is_component_name(&name),
                    name,
                    from_source: None,
                    is_type_only,
                    span,
                    loc,
                });
            }
        }
        Declaration::ClassDeclaration(c) => {
            if let Some(id) = &c.id {
                let name = id.name.to_string();
                out.push(ExportDeclIr {
                    is_component: is_component_name(&name),
                    name,
                    from_source: None,
                    is_type_only,
                    span,
                    loc,
                });
            }
        }
        Declaration::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(id) = d.id.get_binding_identifier() {
                    let name = id.name.to_string();
                    out.push(ExportDeclIr {
                        is_component: is_component_name(&name),
                        name,
                        from_source: None,
                        is_type_only,
                        span,
                        loc,
                    });
                }
            }
        }
        Declaration::TSInterfaceDeclaration(i) => {
            out.push(ExportDeclIr {
                name: i.id.name.to_string(),
                from_source: None,
                is_type_only: true,
                is_component: false,
                span,
                loc,
            });
        }
        Declaration::TSTypeAliasDeclaration(t) => {
            out.push(ExportDeclIr {
                name: t.id.name.to_string(),
                from_source: None,
                is_type_only: true,
                is_component: false,
                span,
                loc,
            });
        }
        Declaration::TSEnumDeclaration(e) => {
            out.push(ExportDeclIr {
                name: e.id.name.to_string(),
                from_source: None,
                is_type_only,
                is_component: false,
                span,
                loc,
            });
        }
        _ => {}
    }
}

fn extract_symbol_outlines(
    program: &Program<'_>,
    source: &str,
    line_starts: &[u32],
) -> Vec<SymbolOutline> {
    let lines: Vec<&str> = source.lines().collect();
    let mut outlines = Vec::new();

    for stmt in &program.body {
        match stmt {
            Statement::ExportDeclaration(exp) => {
                extract_decl_outlines(
                    &exp.declaration,
                    true,
                    exp.span.start,
                    source,
                    &lines,
                    line_starts,
                    &mut outlines,
                );
            }
            Statement::ExportDefaultDeclaration(exp) => match &exp.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    let name =
                        f.id.as_ref()
                            .map_or_else(|| "default".to_string(), |id| id.name.to_string());
                    push_symbol_outline(
                        &mut outlines,
                        name,
                        SymbolKind::Function,
                        exp.span,
                        exp.span.start,
                        None,
                        true,
                        source,
                        &lines,
                        line_starts,
                    );
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    let name =
                        c.id.as_ref()
                            .map_or_else(|| "default".to_string(), |id| id.name.to_string());
                    push_symbol_outline(
                        &mut outlines,
                        name,
                        SymbolKind::Class,
                        exp.span,
                        exp.span.start,
                        None,
                        true,
                        source,
                        &lines,
                        line_starts,
                    );
                }
                _ => {}
            },
            _ => {
                if let Some(decl) = stmt.as_declaration() {
                    extract_decl_outlines(
                        decl,
                        false,
                        stmt.span().start,
                        source,
                        &lines,
                        line_starts,
                        &mut outlines,
                    );
                }
            }
        }
    }

    outlines
}

fn extract_decl_outlines(
    decl: &Declaration<'_>,
    exported: bool,
    comment_anchor_start: u32,
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    out: &mut Vec<SymbolOutline>,
) {
    match decl {
        Declaration::FunctionDeclaration(f) => {
            if let Some(id) = &f.id {
                push_symbol_outline(
                    out,
                    id.name.to_string(),
                    SymbolKind::Function,
                    f.span,
                    comment_anchor_start,
                    None,
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
        }
        Declaration::ClassDeclaration(c) => {
            if let Some(id) = &c.id {
                let class_name = id.name.to_string();
                push_symbol_outline(
                    out,
                    class_name.clone(),
                    SymbolKind::Class,
                    c.span,
                    comment_anchor_start,
                    None,
                    exported,
                    source,
                    lines,
                    line_starts,
                );
                extract_class_member_outlines(
                    c,
                    &class_name,
                    exported,
                    source,
                    lines,
                    line_starts,
                    out,
                );
            }
        }
        Declaration::TSInterfaceDeclaration(iface) => {
            let iface_name = iface.id.name.to_string();
            push_symbol_outline(
                out,
                iface_name.clone(),
                SymbolKind::Interface,
                iface.span,
                comment_anchor_start,
                None,
                exported,
                source,
                lines,
                line_starts,
            );
            extract_interface_member_outlines(
                iface,
                &iface_name,
                exported,
                source,
                lines,
                line_starts,
                out,
            );
        }
        Declaration::TSTypeAliasDeclaration(t) => {
            push_symbol_outline(
                out,
                t.id.name.to_string(),
                SymbolKind::Type,
                t.span,
                comment_anchor_start,
                None,
                exported,
                source,
                lines,
                line_starts,
            );
        }
        Declaration::TSEnumDeclaration(e) => {
            let enum_name = e.id.name.to_string();
            push_symbol_outline(
                out,
                enum_name.clone(),
                SymbolKind::Enum,
                e.span,
                comment_anchor_start,
                None,
                exported,
                source,
                lines,
                line_starts,
            );
            for member in &e.body.members {
                let member_name = member
                    .id
                    .static_name()
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                push_symbol_outline(
                    out,
                    member_name,
                    SymbolKind::EnumMember,
                    member.span,
                    member.span.start,
                    Some(enum_name.clone()),
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
        }
        Declaration::VariableDeclaration(v) => {
            for declarator in &v.declarations {
                let Some(id) = declarator.id.get_binding_identifier() else {
                    continue;
                };
                let is_fn_init = declarator.init.as_ref().is_some_and(|init| {
                    matches!(
                        init.without_parentheses(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
                let kind = if is_fn_init {
                    SymbolKind::Function
                } else if v.kind == VariableDeclarationKind::Const {
                    SymbolKind::Constant
                } else {
                    SymbolKind::Variable
                };
                push_symbol_outline(
                    out,
                    id.name.to_string(),
                    kind,
                    v.span,
                    comment_anchor_start,
                    None,
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
        }
        _ => {}
    }
}

fn extract_class_member_outlines(
    class_decl: &Class<'_>,
    class_name: &str,
    exported: bool,
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    out: &mut Vec<SymbolOutline>,
) {
    for element in &class_decl.body.body {
        match element {
            oxc_ast::ast::ClassElement::MethodDefinition(m) => {
                let Some(m_name) = m
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                push_symbol_outline(
                    out,
                    m_name,
                    SymbolKind::Method,
                    m.span,
                    m.span.start,
                    Some(class_name.to_string()),
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
            oxc_ast::ast::ClassElement::PropertyDefinition(p) => {
                let Some(p_name) = p
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                push_symbol_outline(
                    out,
                    p_name,
                    SymbolKind::Property,
                    p.span,
                    p.span.start,
                    Some(class_name.to_string()),
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
            _ => {}
        }
    }
}

fn extract_interface_member_outlines(
    iface: &TSInterfaceDeclaration<'_>,
    iface_name: &str,
    exported: bool,
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    out: &mut Vec<SymbolOutline>,
) {
    for sig in &iface.body.body {
        match sig {
            oxc_ast::ast::TSSignature::TSPropertySignature(prop) => {
                let Some(p_name) = prop
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                push_symbol_outline(
                    out,
                    p_name,
                    SymbolKind::Property,
                    prop.span,
                    prop.span.start,
                    Some(iface_name.to_string()),
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
            oxc_ast::ast::TSSignature::TSMethodSignature(m) => {
                let Some(m_name) = m
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                push_symbol_outline(
                    out,
                    m_name,
                    SymbolKind::Method,
                    m.span,
                    m.span.start,
                    Some(iface_name.to_string()),
                    exported,
                    source,
                    lines,
                    line_starts,
                );
            }
            _ => {}
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a SymbolOutline directly from AST span and precomputed line tables"
)]
fn push_symbol_outline(
    out: &mut Vec<SymbolOutline>,
    name: String,
    kind: SymbolKind,
    span: Span,
    comment_anchor_start: u32,
    parent_name: Option<String>,
    exported: bool,
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
) {
    let loc = loc_from_line_starts(line_starts, span.start);
    let end_loc = loc_from_line_starts(line_starts, span.end.saturating_sub(1));
    let comment_loc = loc_from_line_starts(line_starts, comment_anchor_start);
    let doc_comment = extract_leading_doc_comment(lines, comment_loc.line);
    let first_line = span
        .source_text(source)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('{')
        .trim()
        .to_string();

    out.push(SymbolOutline {
        name,
        kind,
        signature: first_line,
        doc_comment,
        parent_name,
        exported,
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        loc,
        end_line: end_loc.line,
    });
}

fn extract_leading_doc_comment(lines: &[&str], start_line_1based: u32) -> Option<String> {
    if start_line_1based <= 1 {
        return None;
    }
    let mut idx = (start_line_1based as usize).saturating_sub(2);
    let mut collected = Vec::new();
    let mut in_block = false;

    loop {
        let line = lines.get(idx)?.trim();
        if in_block {
            collected.push(line);
            if line.starts_with("/*") {
                break;
            }
        } else if line.starts_with("//") {
            collected.push(line);
        } else if line.ends_with("*/") {
            collected.push(line);
            if line.starts_with("/*") {
                break;
            }
            in_block = true;
        } else {
            break;
        }
        if idx == 0 {
            break;
        }
        idx -= 1;
    }

    if collected.is_empty() {
        return None;
    }
    collected.reverse();
    Some(collected.join("\n"))
}

/// Parses inline disable directives (`dotore-disable*`, `eslint-disable*`, `oxlint-disable*`) from `source`.
#[must_use]
pub(crate) fn extract_file_suppressions(source: &str) -> FileSuppressions {
    let lines: Vec<&str> = source.lines().collect();
    let mut line_directives = Vec::new();
    let mut block_ranges: Vec<BlockDisableRange> = Vec::new();

    for (idx, &line) in lines.iter().enumerate() {
        let line_num = u32::try_from(idx + 1).unwrap_or(1);
        for comment in extract_comments_on_line(line) {
            let Some((kind, rules)) = parse_disable_comment(comment) else {
                continue;
            };
            match kind {
                DirectiveKind::DisableLine => {
                    line_directives.push(LineDisableDirective {
                        target_line: line_num,
                        rules,
                    });
                }
                DirectiveKind::DisableNextLine => {
                    let target_line = resolve_next_code_line(&lines, idx);
                    line_directives.push(LineDisableDirective { target_line, rules });
                }
                DirectiveKind::BlockDisable => {
                    block_ranges.push(BlockDisableRange {
                        start_line: line_num,
                        end_line: u32::MAX,
                        rules,
                    });
                }
                DirectiveKind::BlockEnable => {
                    close_matching_block_ranges(&mut block_ranges, &rules, line_num);
                }
            }
        }
    }

    FileSuppressions {
        line_directives,
        block_ranges,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectiveKind {
    DisableNextLine,
    DisableLine,
    BlockDisable,
    BlockEnable,
}

fn extract_comments_on_line(line: &str) -> Vec<&str> {
    let mut comments = Vec::new();
    let mut rest = line;

    while let Some((idx, is_block)) = find_next_comment_start(rest) {
        let after_open = &rest[idx + 2..];
        if is_block {
            if let Some(end_idx) = after_open.find("*/") {
                comments.push(after_open[..end_idx].trim());
                rest = &after_open[end_idx + 2..];
            } else {
                comments.push(after_open.trim());
                break;
            }
        } else {
            comments.push(after_open.trim());
            break;
        }
    }

    comments
}

fn find_next_comment_start(s: &str) -> Option<(usize, bool)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                return Some((i, false));
            }
            if bytes[i + 1] == b'*' {
                return Some((i, true));
            }
        }
        i += 1;
    }
    None
}

fn parse_disable_comment(comment: &str) -> Option<(DirectiveKind, Vec<String>)> {
    let trimmed = comment.trim().trim_end_matches('}').trim();
    for tool in ["dotore", "eslint", "oxlint"] {
        for (suffix, kind) in [
            ("-disable-next-line", DirectiveKind::DisableNextLine),
            ("-disable-line", DirectiveKind::DisableLine),
            ("-disable", DirectiveKind::BlockDisable),
            ("-enable", DirectiveKind::BlockEnable),
        ] {
            let prefix = format!("{tool}{suffix}");
            if let Some(after) = trimmed.strip_prefix(&prefix) {
                if !after.is_empty()
                    && !after.starts_with(char::is_whitespace)
                    && !after.starts_with(',')
                {
                    continue;
                }
                let rules = tokenize_directive_rule_list(after);
                return Some((kind, rules));
            }
        }
    }
    None
}

fn tokenize_directive_rule_list(raw_tail: &str) -> Vec<String> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // Strip `-- explanation` tail per ESLint/Oxlint convention
    let before_desc = if let Some(idx) = trimmed.find(" -- ") {
        &trimmed[..idx]
    } else if let Some(rest) = trimmed.strip_prefix("-- ") {
        let _ = rest;
        ""
    } else if trimmed == "--" {
        ""
    } else {
        trimmed
    };

    before_desc
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn resolve_next_code_line(lines: &[&str], comment_line_idx: usize) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while candidate < lines.len() {
        let text = lines[candidate].trim();
        let is_stacked_disable = extract_comments_on_line(text).into_iter().any(|c| {
            matches!(
                parse_disable_comment(c),
                Some((DirectiveKind::DisableNextLine, _))
            )
        });
        if is_stacked_disable {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}

fn close_matching_block_ranges(
    ranges: &mut Vec<BlockDisableRange>,
    enable_rules: &[String],
    enable_line: u32,
) {
    let mut split_additions = Vec::new();
    for range in ranges.iter_mut() {
        if range.end_line != u32::MAX {
            continue;
        }
        if enable_rules.is_empty() {
            range.end_line = enable_line;
            continue;
        }
        if range.rules.is_empty() {
            continue;
        }
        let overlaps = range.rules.iter().any(|r| {
            enable_rules.iter().any(|en| {
                r == en || RuleId::parse(r).is_some_and(|rule_id| rule_id.matches_key(en))
            })
        });
        if overlaps {
            let remaining: Vec<String> = range
                .rules
                .iter()
                .filter(|r| {
                    !enable_rules.iter().any(|en| {
                        *r == en || RuleId::parse(r).is_some_and(|rule_id| rule_id.matches_key(en))
                    })
                })
                .cloned()
                .collect();
            range.end_line = enable_line;
            if !remaining.is_empty() {
                split_additions.push(BlockDisableRange {
                    start_line: enable_line,
                    end_line: u32::MAX,
                    rules: remaining,
                });
            }
        }
    }
    ranges.extend(split_additions);
}
