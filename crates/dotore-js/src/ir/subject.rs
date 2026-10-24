//! Single-pass React **Subject**, **State Slot**, and **Effect Node** IR extraction.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; Subject extraction matches only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{ArrowFunctionBody, BindingPattern, CallExpression, Expression},
};
use oxc_semantic::{NodeId, ReferenceId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::{
    dataflow::{
        get_all_refs_in_span, get_args_upstream_refs, get_call_expr, get_downstream_refs_in_span,
        get_state_name, get_upstream_refs, get_use_state_decl_node, is_non_external_data_leaf,
        is_prop, is_prop_call, is_ref_call, is_state, is_state_call, is_state_setter,
        is_synchronous,
    },
    react_ast::{
        RefEntry, classify_subject_memoization, detect_subject_suspense_and_throws,
        extract_subject_hook_dep_props, find_enclosing_react_node, get_effect_cleanup_span,
        get_effect_fn_node, get_subject_name, is_custom_hook, is_functional_hoc,
        is_react_hook_callee, is_use_effect_call,
    },
    types::{
        ByteSpan, DepRef, DepsSpec, EffectNode, ExternalStoreSite, FetchSite, IfGuardSite,
        PropCallSite, SetterCallSite, StateSlot, SubjectIr, SubjectKind, loc_from_line_starts,
    },
};

/// Extracts all React **Subjects** (components, custom hooks, orphan effect containers, and Angular class subjects) in `semantic`.
pub(super) fn extract_subjects(
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

    let mut subjects =
        Vec::with_capacity(subject_nodes.len() + usize::from(!orphan_effects.is_empty()));
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
    crate::rules::angular::extract_angular_class_subjects(semantic, line_starts, &mut subjects);
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

    let (is_memoized, has_custom_memo_comparator) = match subject_node_id {
        Some(subj_id) => classify_subject_memoization(semantic, subj_id),
        None => (false, false),
    };
    let props_in_hook_deps = match subject_node_id {
        Some(subj_id) => extract_subject_hook_dep_props(semantic, subj_id),
        None => Vec::new(),
    };
    let (suspends, throws_in_render) = match subject_node_id {
        Some(subj_id) => detect_subject_suspense_and_throws(semantic, subj_id),
        None => (false, false),
    };

    SubjectIr {
        name,
        kind,
        is_hoc_wrapped,
        loc: loc_from_line_starts(line_starts, span.start),
        span,
        state_slots,
        effect_nodes,
        is_memoized,
        has_custom_memo_comparator,
        props_in_hook_deps,
        suspends,
        throws_in_render,
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
        let Some(display_name) = state_name
            .as_deref()
            .or(setter_name.as_deref())
            .map(str::to_string)
        else {
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

    let mut items = Vec::with_capacity(deps_refs.len());
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::{DepsSpec, SubjectKind, parse_file_ir};

    #[test]
    fn extracts_subject_state_slots_and_effect_nodes() {
        let src = r#"
import { useState, useEffect } from "react";

export function UserProfile({ userId, onUpdate }: { userId: string; onUpdate: (v: string) => void }) {
    const [fullName, setFullName] = useState("");
    useEffect(() => {
        setFullName(userId.trim());
        onUpdate(fullName);
    }, [userId, fullName]);
    return <div>{fullName}</div>;
}
"#;
        let file = parse_file_ir(Path::new("UserProfile.tsx"), src);
        assert_eq!(file.subjects.len(), 1);
        let subj = &file.subjects[0];
        assert_eq!(subj.name.as_deref(), Some("UserProfile"));
        assert_eq!(subj.kind, SubjectKind::Component);
        assert_eq!(subj.state_slots.len(), 1);
        assert_eq!(subj.state_slots[0].display_name, "fullName");
        assert_eq!(subj.effect_nodes.len(), 1);
        let eff = &subj.effect_nodes[0];
        assert!(matches!(eff.deps, DepsSpec::Tracked(_)));
        assert_eq!(eff.sync_setter_calls.len(), 1);
        assert!(eff.sync_setter_calls[0].arg_reads_prop);
        assert_eq!(eff.sync_prop_calls.len(), 1);
        assert_eq!(eff.sync_prop_calls[0].prop_name, "onUpdate");
    }
}
