//! Rules for derived state, chained state updates, and mount-only state initialization.

use crate::{
    graph::{MultiEffectCascade, find_multi_effect_cascades},
    ir::{DepRef, DepsSpec, EffectNode, FileIr, SetterCallSite, SubjectIr},
    matchers::{make_autofix_diag, make_diag, make_diag_for_subject},
    rules::types::{AutofixPatch, Diagnostic, PrescriptionTier, RuleId},
};

pub(crate) fn check_no_derived_state(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        if effect.has_cleanup {
            continue;
        }
        for call in &effect.sync_setter_calls {
            if !call.arg_reads_state && !call.arg_reads_prop {
                continue;
            }
            let autofix = build_derived_state_autofix(subject, effect, call);
            let msg = format!(
                "Avoid storing derived state. Instead, compute {:?} directly during render.",
                call.state_name
            );
            let base_diag = match autofix {
                Some(patch) => make_autofix_diag(
                    RuleId::NoDerivedState,
                    file.path.clone(),
                    call.loc,
                    call.call_span,
                    msg,
                    patch,
                ),
                None => make_diag(
                    RuleId::NoDerivedState,
                    file.path.clone(),
                    call.loc,
                    call.call_span,
                    msg,
                )
                .with_tier(PrescriptionTier::Surgical),
            };
            out.push(
                base_diag
                    .with_subject(subject.name.clone())
                    .with_message_id("avoidDerivedState")
                    .with_target_name(call.state_name.clone())
                    .with_cascade_steps(vec![
                        "Render #1 (stale derived value)".to_string(),
                        format!("useEffect runs -> sets {:?}", call.state_name),
                        "Render #2 (re-renders with derived value)".to_string(),
                    ]),
            );
        }
    }
}

fn build_derived_state_autofix(
    subject: &SubjectIr,
    effect: &EffectNode,
    call: &SetterCallSite,
) -> Option<AutofixPatch> {
    if effect.top_level_stmt_count != 1
        || effect.sync_setter_calls.len() != 1
        || call.is_updater_fn
        || call.arg_text == "undefined"
    {
        return None;
    }
    let eff_stmt_span = effect.stmt_span?;
    let slot = subject.state_slots.get(call.state_slot_index?)?;
    let var_name = slot.state_name.as_ref()?;
    let decl_span = slot.decl_stmt_span?;

    if slot.setter_calls_outside_effects != 0
        || slot.setter_calls_in_effects != 1
        || slot.setter_escaped
        || call.arg_state_indices.contains(&slot.index)
    {
        return None;
    }

    let replacement_decl = format!("const {var_name} = {};", call.arg_text);
    Some(
        AutofixPatch::new(format!(
            "Replace useState + useEffect with `{replacement_decl}`"
        ))
        .with_edit(decl_span, replacement_decl)
        .with_edit(eff_stmt_span, String::new()),
    )
}

pub(crate) fn check_no_chain_state_updates(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    let cascades = find_multi_effect_cascades(subject);
    for effect in &subject.effect_nodes {
        if effect.has_cleanup {
            continue;
        }
        let DepsSpec::Tracked(deps) = &effect.deps else {
            continue;
        };
        let tracked_states = collect_tracked_state_names(subject, deps);
        if tracked_states.is_empty() {
            continue;
        }
        emit_chain_state_diagnostics(file, subject, effect, &tracked_states, &cascades, out);
    }
}

fn collect_tracked_state_names<'a>(subject: &'a SubjectIr, deps: &[DepRef]) -> Vec<&'a str> {
    let mut names = Vec::new();
    for dep in deps {
        for &slot_idx in &dep.upstream_state_indices {
            if let Some(slot) = subject.state_slots.get(slot_idx)
                && !names.contains(&slot.display_name.as_str())
            {
                names.push(slot.display_name.as_str());
            }
        }
    }
    names
}

fn emit_chain_state_diagnostics(
    file: &FileIr,
    subject: &SubjectIr,
    effect: &EffectNode,
    tracked_states: &[&str],
    cascades: &[MultiEffectCascade],
    out: &mut Vec<Diagnostic>,
) {
    for call in &effect.sync_setter_calls {
        let matched_cascade = cascades
            .iter()
            .find(|c| c.second_effect_index == effect.index && c.span == call.call_span);
        if call.arg_reads_state && matched_cascade.is_none() {
            continue;
        }
        let (message, cascade_steps) = match matched_cascade {
            Some(cascade) => (
                format!(
                    "Avoid multi-effect state cascades (Effect #{} -> {:?} -> Effect #{} -> {:?}). Collapse chained state updates into the originating event handler or derive during render.",
                    cascade.first_effect_index + 1,
                    cascade.intermediate_state_name,
                    cascade.second_effect_index + 1,
                    cascade.final_state_name
                ),
                cascade.steps.clone(),
            ),
            None => (
                format!(
                    "Avoid chaining state updates. When state changes, update {:?} directly in the event handler or compute it during render.",
                    call.state_name
                ),
                vec![
                    format!(
                        "Render #1 (upstream state [{}] changes)",
                        tracked_states.join(", ")
                    ),
                    format!("useEffect runs -> sets {:?}", call.state_name),
                    format!("Render #2 (re-renders with updated {:?})", call.state_name),
                ],
            ),
        };
        out.push(
            make_diag_for_subject(
                RuleId::NoChainStateUpdates,
                file.path.clone(),
                subject.name.clone(),
                "avoidChainingStateUpdates",
                call.state_name.clone(),
                message,
                call.loc,
                call.call_span,
            )
            .with_tier(PrescriptionTier::Refactor)
            .with_cascade_steps(cascade_steps),
        );
    }
}

pub(crate) fn check_no_initialize_state(
    file: &FileIr,
    subject: &SubjectIr,
    derived_enabled: bool,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        if !matches!(effect.deps, DepsSpec::MountOnly) {
            continue;
        }
        for call in &effect.sync_setter_calls {
            if (effect.has_cleanup && call.shares_cleanup_symbol)
                || (derived_enabled && (call.arg_reads_state || call.arg_reads_prop))
            {
                continue;
            }
            let autofix = build_initialize_state_autofix(subject, effect, call);
            let tier = if autofix.is_some() {
                PrescriptionTier::Autofix
            } else {
                PrescriptionTier::Surgical
            };
            out.push(
                make_diag_for_subject(
                    RuleId::NoInitializeState,
                    file.path.clone(),
                    subject.name.clone(),
                    "avoidInitializingState",
                    call.state_name.clone(),
                    format!(
                        "Avoid initializing state in an effect. Instead, initialize {:?}'s \"useState()\" with {:?}. For SSR hydration, prefer \"useSyncExternalStore\".",
                        call.state_name, call.arg_text
                    ),
                    call.loc,
                    call.call_span,
                )
                .with_autofix(autofix)
                .with_tier(tier)
                .with_cascade_steps(vec![
                    format!("Render #1 with uninitialized {:?}", call.state_name),
                    format!("Mount useEffect sets {:?} to {}", call.state_name, call.arg_text),
                    "Render #2 with initialized state".to_string(),
                ]),
            );
        }
    }
}

fn build_initialize_state_autofix(
    subject: &SubjectIr,
    effect: &EffectNode,
    call: &SetterCallSite,
) -> Option<AutofixPatch> {
    if effect.has_cleanup
        || effect.top_level_stmt_count != 1
        || effect.sync_setter_calls.len() != 1
        || call.is_updater_fn
        || call.arg_text == "undefined"
    {
        return None;
    }
    let eff_stmt_span = effect.stmt_span?;
    let slot = subject.state_slots.get(call.state_slot_index?)?;
    if slot.init_arg_text.is_some()
        || slot.setter_calls_outside_effects != 0
        || slot.setter_calls_in_effects != 1
        || slot.setter_escaped
    {
        return None;
    }

    let replacement_call = format!("useState({})", call.arg_text);
    Some(
        AutofixPatch::new(format!(
            "Initialize {:?} directly in `{replacement_call}` and remove mount useEffect",
            call.state_name
        ))
        .with_edit(slot.call_span, replacement_call)
        .with_edit(eff_stmt_span, String::new()),
    )
}
