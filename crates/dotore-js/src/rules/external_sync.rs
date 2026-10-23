//! Rules for external store subscriptions and data fetching inside `useEffect`.

use crate::{
    ir::{FileIr, SubjectIr},
    rules::types::{Diagnostic, PrescriptionTier, RuleId},
};

pub(crate) fn check_no_external_store_subscription(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        for site in &effect.external_store_sites {
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: subject.name.clone(),
                rule: RuleId::NoExternalStoreSubscription,
                category: RuleId::NoExternalStoreSubscription.metadata().category,
                severity: RuleId::NoExternalStoreSubscription.metadata().default_severity,
                message_id: "avoidExternalStoreSubscription",
                tier: PrescriptionTier::Surgical,
                target_name: site.state_name.clone(),
                message: format!(
                    "Prefer \"useSyncExternalStore\" over \"useState\" + \"useEffect\" to subscribe {:?} to an external store.",
                    site.state_name
                ),
                docs_url: RuleId::NoExternalStoreSubscription.docs_url(),
                loc: site.loc,
                span: site.span,
                cascade_steps: vec![
                    format!("Render #1 with initial {:?} value", site.state_name),
                    format!(
                        "useEffect subscribes to store and synchronously sets {:?}",
                        site.state_name
                    ),
                    "Render #2 (risk of tearing before subscription attaches)".to_string(),
                ],
                caller_sites: Vec::new(),
                autofix: None,
            });
        }
    }
}

pub(crate) fn check_no_fetch_in_effect(
    file: &FileIr,
    subject: &SubjectIr,
    out: &mut Vec<Diagnostic>,
) {
    for effect in &subject.effect_nodes {
        for site in &effect.fetch_sites {
            let (tier, message_id, message, cascade_steps) = if site.has_cancellation_guard {
                (
                    PrescriptionTier::Refactor,
                    "avoidFetchInEffect",
                    format!(
                        "Prefer a query hook (`useQuery` / `useSWR`) or framework route loader over manual `fetch` + `setState` for {:?} in `useEffect`.",
                        site.state_name
                    ),
                    vec![
                        format!("Render #1 with empty/stale {:?}", site.state_name),
                        format!("useEffect starts fetch -> sets {:?}", site.state_name),
                        "Render #2 after network round-trip".to_string(),
                    ],
                )
            } else {
                (
                    PrescriptionTier::Surgical,
                    "avoidUncancelledFetchInEffect",
                    format!(
                        "Uncancelled `fetch` inside `useEffect` updating {:?} causes race conditions on rapid re-renders. Add an `AbortController` / cleanup ignore flag or migrate to a query hook.",
                        site.state_name
                    ),
                    vec![
                        format!(
                            "Render #1 starts uncancelled fetch for {:?}",
                            site.state_name
                        ),
                        "Rapid prop/state change starts fetch #2 before fetch #1 finishes"
                            .to_string(),
                        format!(
                            "Out-of-order response overwrites {:?} with stale data",
                            site.state_name
                        ),
                    ],
                )
            };
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: subject.name.clone(),
                rule: RuleId::NoFetchInEffect,
                category: RuleId::NoFetchInEffect.metadata().category,
                severity: RuleId::NoFetchInEffect.metadata().default_severity,
                message_id,
                tier,
                target_name: site.state_name.clone(),
                message,
                docs_url: RuleId::NoFetchInEffect.docs_url(),
                loc: site.loc,
                span: site.span,
                cascade_steps,
                caller_sites: Vec::new(),
                autofix: None,
            });
        }
    }
}
