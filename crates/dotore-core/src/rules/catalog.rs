//! Decomposed 965-rule static [`RuleMetadata`] catalog assembled at compile time.

use crate::rules::types::RuleMetadata;

/// WCAG accessibility, ARIA, and UI design polish rule metadata (`230..=421`).
pub mod a11y_and_design;
/// Defensive JS/TS/DOM runtime safety, React Router, Remotion, and correctness rule metadata (`767..=920`).
pub mod defensive_and_correctness;
/// Zustand, Jotai, MobX, Valtio, Preact, Ink, TanStack, Redux, and Zod v4 ecosystem rule metadata (`223..=229`, `656..=692`).
pub mod ecosystem;
/// React re-render, hydration, bundle size, and motion performance rule metadata (`422..=487`).
pub mod performance_and_bundle;
/// Angular, Python, and Rust polyglot rule metadata (`921..=964`).
pub mod polyglot;
/// React core **Effect Node**, **State Slot**, hooks, lifecycle, and architecture rule metadata (`0..=35`, `693..=766`).
pub mod react_core;
/// React Native and Expo mobile rule metadata (`597..=655`).
pub mod react_native_and_expo;
/// XSS, SSRF, Next.js App Router, Server Actions, RSC, and supply-chain security rule metadata (`488..=596`).
pub mod security_and_server;
/// Three.js, WebGL, and React Three Fiber 60fps frame-loop rule metadata (`36..=222`).
pub mod three_r3f_webgl;

const SLICES: &[&[RuleMetadata]] = &[
    react_core::CORE_INITIAL_RULES,
    three_r3f_webgl::RULES,
    ecosystem::INITIAL_ECOSYSTEM_RULES,
    a11y_and_design::RULES,
    performance_and_bundle::RULES,
    security_and_server::RULES,
    react_native_and_expo::RULES,
    ecosystem::EXTENDED_ECOSYSTEM_RULES,
    react_core::EXTENDED_REACT_RULES,
    defensive_and_correctness::RULES,
    polyglot::RULES,
];

/// Total number of registered rules in `dotore`.
pub const TOTAL_RULES: usize = 965;

static RULE_REGISTRY_ARRAY: [RuleMetadata; TOTAL_RULES] = {
    let mut out = [react_core::CORE_INITIAL_RULES[0]; TOTAL_RULES];
    let mut out_idx = 0;
    let mut s_idx = 0;
    while s_idx < SLICES.len() {
        let slice = SLICES[s_idx];
        let mut i = 0;
        while i < slice.len() {
            let meta = slice[i];
            assert!(meta.id as usize == out_idx);
            out[out_idx] = meta;
            out_idx += 1;
            i += 1;
        }
        s_idx += 1;
    }
    assert!(out_idx == TOTAL_RULES);
    out
};

/// Static slice of all 965 registered [`RuleMetadata`] entries in [`crate::rules::RuleId`] discriminant order.
pub const RULE_REGISTRY: &[RuleMetadata] = &RULE_REGISTRY_ARRAY;
