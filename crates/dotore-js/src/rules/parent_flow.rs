//! Rules for event-handler effects and upward child-to-parent callback notifications.

use crate::{
    ir::{FileIr, SubjectIr, SubjectKind},
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, PrescriptionTier, RuleId},
};

pub(crate) fn check_no_event_handler(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        if effect.has_cleanup {
            continue;
        }
        for guard in &effect.if_guards {
            let (message_id, tier, message, cascade_steps) = if guard.reads_state {
                (
                    "avoidEventHandler",
                    PrescriptionTier::Surgical,
                    format!(
                        "Avoid using state and an effect as an event handler. Instead, call the event code directly from the event handler that updates {:?}.",
                        guard.identifier_name
                    ),
                    vec![
                        format!("Event sets state flag {:?}", guard.identifier_name),
                        "Render #1 (re-renders component with flag)".to_string(),
                        format!(
                            "useEffect sees `if ({})` -> runs event side effect",
                            guard.identifier_name
                        ),
                    ],
                )
            } else {
                (
                    "avoidPropHandler",
                    PrescriptionTier::Refactor,
                    format!(
                        "Avoid using a prop and an effect as an event handler. Instead, run the event action in the parent event handler rather than passing {:?} as a trigger prop.",
                        guard.identifier_name
                    ),
                    vec![
                        format!("Parent updates trigger prop {:?}", guard.identifier_name),
                        "Render #1 (child renders with updated prop)".to_string(),
                        format!(
                            "useEffect sees `if ({})` -> runs event side effect",
                            guard.identifier_name
                        ),
                    ],
                )
            };
            out.push(
                make_diag_for_subject(
                    RuleId::NoEventHandler,
                    file.path.clone(),
                    subject.name.clone(),
                    message_id,
                    guard.identifier_name.clone(),
                    message,
                    guard.loc,
                    guard.span,
                )
                .with_tier(tier)
                .with_cascade_steps(cascade_steps),
            );
        }
    }
}

pub(crate) fn check_no_pass_live_state_to_parent(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    if subject.is_hoc_wrapped {
        return;
    }
    let subject_label = subject.name.as_deref().unwrap_or("<anonymous>");
    for effect in &subject.effect_nodes {
        if effect.has_cleanup {
            continue;
        }
        for call in &effect.sync_prop_calls {
            if call.is_ref_call || call.arg_state_names.is_empty() {
                continue;
            }
            let quoted_states = format_quoted_list(&call.arg_state_names);
            let target_name = call.arg_state_names.join(", ");
            let (message_id, message) = match subject.kind {
                SubjectKind::Component => (
                    "avoidPassingLiveStateToParentInComponent",
                    format!(
                        "Avoid passing live state to parent components in an effect. Instead, lift {quoted_states} state up to the parent of {subject_label:?}, and pass it down to {subject_label:?} as a prop."
                    ),
                ),
                SubjectKind::CustomHook => (
                    "avoidPassingLiveStateToParentInHook",
                    format!(
                        "Avoid passing live state to callers in an effect. Instead, return {quoted_states} from {subject_label:?}."
                    ),
                ),
            };
            out.push(
                make_diag_for_subject(
                    RuleId::NoPassLiveStateToParent,
                    file.path.clone(),
                    subject.name.clone(),
                    message_id,
                    target_name.clone(),
                    message,
                    call.loc,
                    call.call_span,
                )
                .with_tier(PrescriptionTier::Refactor)
                .with_cascade_steps(vec![
                    format!("Render #1 updates local state ({target_name})"),
                    format!("useEffect runs -> calls prop `{}`", call.prop_name),
                    "Parent re-renders and cascades back down".to_string(),
                ]),
            );
        }
    }
}

pub(crate) fn check_no_pass_data_to_parent(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    if subject.is_hoc_wrapped {
        return;
    }
    let subject_label = subject.name.as_deref().unwrap_or("<anonymous>");
    for effect in &subject.effect_nodes {
        if effect.has_cleanup {
            continue;
        }
        for call in &effect.sync_prop_calls {
            if call.is_ref_call || call.arg_external_data_names.is_empty() {
                continue;
            }
            let quoted_data = format_quoted_list(&call.arg_external_data_names);
            let target_name = call.arg_external_data_names.join(", ");
            let (message_id, message) = match subject.kind {
                SubjectKind::Component => (
                    "avoidPassingDataToParentInComponent",
                    format!(
                        "Avoid passing data to parent components in an effect. Instead, let the parent fetch {quoted_data} itself, and pass it down to {subject_label:?} as a prop."
                    ),
                ),
                SubjectKind::CustomHook => (
                    "avoidPassingDataToParentInHook",
                    format!(
                        "Avoid passing data to callers in an effect. Instead, return {quoted_data} from {subject_label:?}."
                    ),
                ),
            };
            out.push(
                make_diag_for_subject(
                    RuleId::NoPassDataToParent,
                    file.path.clone(),
                    subject.name.clone(),
                    message_id,
                    target_name.clone(),
                    message,
                    call.loc,
                    call.call_span,
                )
                .with_tier(PrescriptionTier::Refactor)
                .with_cascade_steps(vec![
                    format!("Render #1 receives data ({target_name})"),
                    format!("useEffect runs -> calls prop `{}`", call.prop_name),
                    "Parent re-renders with passed data".to_string(),
                ]),
            );
        }
    }
}

fn format_quoted_list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(" and ")
}
