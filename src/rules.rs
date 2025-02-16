//! Diagnostic rules engine for React **Effect Nodes** and **State Slots**.

pub(crate) mod derived_state;
pub(crate) mod external_sync;
pub(crate) mod parent_flow;
pub(crate) mod prop_sync;
pub(crate) mod types;

pub use types::{AutofixPatch, ByteEdit, Diagnostic, PrescriptionTier, RuleId};

use crate::{
    graph::ProjectGraph,
    ir::{FileIr, SubjectIr},
    rules::{
        derived_state::{
            check_no_chain_state_updates, check_no_derived_state, check_no_initialize_state,
        },
        external_sync::{check_no_external_store_subscription, check_no_fetch_in_effect},
        parent_flow::{
            check_no_event_handler, check_no_pass_data_to_parent,
            check_no_pass_live_state_to_parent,
        },
        prop_sync::{
            check_no_adjust_state_on_prop_change, check_no_reset_all_state_on_prop_change,
        },
    },
};

/// Runs all enabled rules across the [`ProjectGraph`].
#[must_use]
pub(crate) fn evaluate_project(
    graph: &ProjectGraph,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for file in &graph.files {
        for subject in &file.subjects {
            if is_rule_enabled(RuleId::NoResetAllStateOnPropChange, enabled_rules) {
                check_no_reset_all_state_on_prop_change(graph, file, subject, &mut diagnostics);
            }
            evaluate_subject(file, subject, enabled_rules, &mut diagnostics);
        }
    }
    diagnostics
}

fn is_rule_enabled(rule: RuleId, enabled: Option<&[RuleId]>) -> bool {
    enabled.is_none_or(|list| list.contains(&rule))
}

fn evaluate_subject(
    file: &FileIr,
    subject: &SubjectIr,
    enabled: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if is_rule_enabled(RuleId::NoDerivedState, enabled) {
        check_no_derived_state(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoChainStateUpdates, enabled) {
        check_no_chain_state_updates(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoEventHandler, enabled) {
        check_no_event_handler(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoAdjustStateOnPropChange, enabled) {
        check_no_adjust_state_on_prop_change(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoInitializeState, enabled) {
        let derived_enabled = is_rule_enabled(RuleId::NoDerivedState, enabled);
        check_no_initialize_state(file, subject, derived_enabled, out);
    }
    if is_rule_enabled(RuleId::NoPassLiveStateToParent, enabled) {
        check_no_pass_live_state_to_parent(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoPassDataToParent, enabled) {
        check_no_pass_data_to_parent(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoExternalStoreSubscription, enabled) {
        check_no_external_store_subscription(file, subject, out);
    }
    if is_rule_enabled(RuleId::NoFetchInEffect, enabled) {
        check_no_fetch_in_effect(file, subject, out);
    }
}
