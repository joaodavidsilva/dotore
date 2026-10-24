//! Rules for state resets and partial state adjustments triggered by prop changes.

use crate::{
    graph::ProjectGraph,
    ir::{DepRef, DepsSpec, EffectNode, FileIr, SubjectIr, SubjectKind},
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, PrescriptionTier, RuleId},
};

pub(crate) fn check_no_reset_all_state_on_prop_change(
    graph: &ProjectGraph,
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    if subject.kind != SubjectKind::Component || subject.state_slots.is_empty() {
        return;
    }

    for effect in &subject.effect_nodes {
        if effect.has_cleanup || !is_full_component_state_reset(subject, effect) {
            continue;
        }
        let Some(prop_name) = first_tracked_prop(&effect.deps) else {
            continue;
        };
        let caller_sites = subject
            .name
            .as_deref()
            .map_or_else(Vec::new, |name| graph.callers_of(&file.path, name));

        out.push(
            make_diag_for_subject(
                RuleId::NoResetAllStateOnPropChange,
                file.path.clone(),
                subject.name.clone(),
                "avoidResettingAllStateWhenAPropChanges",
                prop_name.to_string(),
                format!(
                    "Avoid resetting all state when a prop changes. If {prop_name:?} is a key, pass it as `key` on the component instead so React will reset the component."
                ),
                effect.loc,
                effect.call_span,
            )
            .with_tier(PrescriptionTier::Refactor)
            .with_cascade_steps(vec![
                format!("Prop {prop_name:?} changes -> Render #1 with stale state"),
                "useEffect resets all state slots to initial values".to_string(),
                "Render #2 with reset state (pass `key` at caller instead)".to_string(),
            ])
            .with_caller_sites(caller_sites),
        );
    }
}

pub(crate) fn check_no_adjust_state_on_prop_change(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        if effect.has_cleanup || is_full_component_state_reset(subject, effect) {
            continue;
        }
        let DepsSpec::Tracked(deps) = &effect.deps else {
            continue;
        };
        let tracked_props = collect_tracked_prop_names(deps);
        if tracked_props.is_empty() {
            continue;
        }
        let props_label = format_quoted_prop_list(&tracked_props);
        for call in &effect.sync_setter_calls {
            if call.arg_reads_prop {
                continue;
            }
            out.push(
                make_diag_for_subject(
                    RuleId::NoAdjustStateOnPropChange,
                    file.path.clone(),
                    subject.name.clone(),
                    "avoidAdjustingStateWhenAPropChanges",
                    call.state_name.clone(),
                    format!(
                        "Avoid adjusting state when a prop changes. Instead, adjust {:?} directly during render when {props_label} changes, or store a stable identifier in state.",
                        call.state_name
                    ),
                    call.loc,
                    call.call_span,
                )
                .with_tier(PrescriptionTier::Refactor)
                .with_cascade_steps(vec![
                    format!(
                        "Render #1 (prop {props_label} changes, {:?} is stale)",
                        call.state_name
                    ),
                    format!("useEffect runs -> adjusts {:?}", call.state_name),
                    format!("Render #2 (re-renders with adjusted {:?})", call.state_name),
                ]),
            );
        }
    }
}

fn is_full_component_state_reset(subject: &SubjectIr, effect: &EffectNode) -> bool {
    subject.kind == SubjectKind::Component
        && !subject.state_slots.is_empty()
        && !effect.sync_setter_calls.is_empty()
        && effect
            .sync_setter_calls
            .iter()
            .all(|call| call.resets_to_initial_value)
        && subject.state_slots.iter().all(|slot| {
            effect.sync_setter_calls.iter().any(|call| {
                call.state_slot_index == Some(slot.index) && call.resets_to_initial_value
            })
        })
}

fn first_tracked_prop(deps: &DepsSpec) -> Option<&str> {
    let DepsSpec::Tracked(items) = deps else {
        return None;
    };
    items
        .iter()
        .flat_map(|item| &item.upstream_prop_names)
        .map(String::as_str)
        .next()
}

fn collect_tracked_prop_names(deps: &[DepRef]) -> Vec<&str> {
    let mut names = Vec::new();
    for dep in deps {
        for prop in &dep.upstream_prop_names {
            if !names.contains(&prop.as_str()) {
                names.push(prop.as_str());
            }
        }
    }
    names
}

fn format_quoted_prop_list(props: &[&str]) -> String {
    let quoted: Vec<String> = props.iter().map(|p| format!("{p:?}")).collect();
    match quoted.as_slice() {
        [] => String::new(),
        [single] => single.clone(),
        [first, second] => format!("{first} and {second}"),
        [head @ .., last] => format!("{}, and {last}", head.join(", ")),
    }
}
