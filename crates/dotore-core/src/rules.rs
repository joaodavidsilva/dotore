//! Unified diagnostic rule registry, metadata, categories, tags,
//! **Capability Gate** predicates, **Contextual Owner** policies, and **Prescription Tiers**.

/// Domain types and compiled-in rule metadata registry.
pub mod types;

pub use types::{
    AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
    FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
    RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry,
};

/// Computes the deterministic 16-hex-character cache filename stem for a `pkg:npm/...` PURL.
#[must_use]
pub fn supply_chain_purl_hash(purl: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in purl.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}
