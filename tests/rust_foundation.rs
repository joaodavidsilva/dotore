//! Integration tests for Ticket #15 (`dotore-rs`):
//! - `RsLanguageAnalyzer` and `Cargo.toml` **Capability Gate** inference (`Rust`, `Tokio`, `Axum`,
//!   `Sqlx`, `Serde`, `Tracing`, `Leptos`, `Dioxus`)
//! - Top-level `dotore` routing (`analyze_source`, `analyze_source_with_config`,
//!   `analyze_project_sources`, `apply_patches_to_source`) for `.rs` files
//! - All 5 core Rust safety rules (`rs-no-unwrap-in-production`, `rs-no-unguarded-slice-index`,
//!   `rs-no-lossy-numeric-as-cast`, `rs-require-safety-comment-on-unsafe`, `rs-no-mem-forget`)
//! - Adversarial valid cases (`#[cfg(test)]`, `#[test]`, `#[tokio::test]`, `.get(idx)`,
//!   `if idx < items.len()`, `if !items.is_empty()`, `// SAFETY: ...`, `try_into()`, `ManuallyDrop`)

use std::path::{Path, PathBuf};

use dotore::{
    AutofixPatch, ByteEdit, ByteSpan, Capability, CapabilityGate, DotoreConfig, LanguageAnalyzer,
    PrescriptionTier, RuleId, RulesListOptions, SourceLoc, analyze_project_sources, analyze_source,
    analyze_source_with_config, apply_patches_to_source, build_rule_catalog, explain_rule,
};
use dotore_rs::RsLanguageAnalyzer;

#[test]
fn top_level_analyze_source_evaluates_all_five_core_rust_safety_rules() {
    let src = r#"use std::mem::forget;

pub fn handle_payment(
    amount_res: Result<u64, String>,
    label_opt: Option<String>,
    items: &[u64],
    idx: usize,
    raw_ptr: *const u8,
) -> u32 {
    let amount = amount_res.unwrap();
    let label = label_opt.expect("missing label");
    forget(label);
    let picked = items[idx];
    let truncated = (amount + picked) as u32;
    let flag = unsafe { *raw_ptr };
    truncated + u32::from(flag)
}
"#;

    let diags = analyze_source(Path::new("src/payment.rs"), src, None);
    let rules: Vec<RuleId> = diags.iter().map(|d| d.rule).collect();

    assert_eq!(
        diags
            .iter()
            .filter(|d| d.rule == RuleId::RsNoUnwrapInProduction)
            .count(),
        2,
        "Expected both .unwrap() and .expect() to be flagged: {diags:#?}"
    );
    assert!(rules.contains(&RuleId::RsNoUnguardedSliceIndex));
    assert!(rules.contains(&RuleId::RsNoLossyNumericAsCast));
    assert!(rules.contains(&RuleId::RsRequireSafetyCommentOnUnsafe));
    assert!(rules.contains(&RuleId::RsNoMemForget));

    for diag in &diags {
        assert_eq!(diag.subject_name.as_deref(), Some("handle_payment"));
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert!(diag.loc.line >= 10);
    }
}

#[test]
fn adversarial_valid_rust_cases_emit_zero_diagnostics() {
    let valid_src = r#"use std::mem::ManuallyDrop;

/// Safely processes a batch of items without panicking, truncating, or undocumented unsafe blocks.
pub fn process_batch(
    items: &[u64],
    idx: usize,
    small_byte: u8,
    small_u16: u16,
    ptr: *const u8,
    guard_token: String,
) -> Result<u64, String> {
    let _ kept = ManuallyDrop::new(guard_token);

    // 1. Guarded slice indexing (`idx < items.len()` and `!items.is_empty()`)
    let mut sum: u64 = 0;
    if idx < items.len() {
        sum += items[idx];
    }
    if items.len() > idx {
        sum += items[idx];
    }
    if !items.is_empty() {
        sum += items[0];
    }
    if let Some(&val) = items.get(idx) {
        sum += val;
    }

    // 2. Fixed-size array literal with in-bounds constant index and full range slice `&items[..]`
    let fixed = [10u64, 20, 30];
    sum += fixed[0] + fixed[2];
    let _full_slice = &items[..];
    let _zeros = [0u8; 32];

    // 3. Lossless numeric conversions (`from`, `try_into`, widening `as` casts, in-range literals)
    let widened_u32 = u32::from(small_byte);
    let widened_u64 = (small_byte as u32) as u64 + (small_u16 as u64) + (0 as u64);
    let checked_u32: u32 = sum.try_into().map_err(|_| "overflow".to_string())?;
    sum += u64::from(widened_u32) + widened_u64 + u64::from(checked_u32);

    // 4. Documented `unsafe` blocks (`// SAFETY:` before statement and inside block)
    // SAFETY: `ptr` is guaranteed non-null and aligned by caller precondition.
    let first_byte = unsafe { *ptr };
    let second_byte = unsafe {
        // SAFETY: `ptr` points to a single initialized byte.
        *ptr
    };

    Ok(sum + u64::from(first_byte) + u64::from(second_byte))
}

pub fn early_return_guarded_slice(items: &[u32], idx: usize) -> u32 {
    if idx >= items.len() {
        return 0;
    }
    items[idx]
}

pub fn assert_guarded_slice(items: &[u32], idx: usize) -> u32 {
    assert!(idx < items.len());
    items[idx]
}

pub struct ThreadSafeHandle(usize);

// SAFETY: `ThreadSafeHandle` holds only an integer handle with no interior mutability.
unsafe impl Send for ThreadSafeHandle {}

#[test]
fn unit_test_fn_is_exempt() {
    let xs = vec![1u64, 2];
    let v = Some(xs[0]).unwrap();
    let _trunc = v as u8;
}

#[tokio::test]
async fn tokio_test_fn_is_exempt() {
    let res: Result<u64, &str> = Ok(99);
    let v = res.expect("ok");
    assert_eq!(v as u16, 99);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_test_mod_is_exempt() {
        let arr = vec![10u64];
        let val = arr[0];
        let unwrapped = Some(val).unwrap();
        std::mem::forget(arr);
        assert_eq!(unwrapped as u8, 10);
    }
}
"#;

    let diags = analyze_source(Path::new("src/valid.rs"), valid_src, None);
    assert!(
        diags.is_empty(),
        "Expected 0 diagnostics on adversarial valid Rust source, got: {diags:#?}"
    );

    // Test files (`tests/...` and `benches/...`) skip `test-noise` rules by default
    let test_file_src = r#"
pub fn helper_in_integration_test() {
    let x: Option<i32> = Some(1);
    let _ = x.unwrap();
}
"#;
    assert!(
        analyze_source(Path::new("tests/api_integration.rs"), test_file_src, None).is_empty(),
        "Expected test file under tests/ to suppress test-noise rules by default"
    );

    // Non-Rust capability gate should not run Rust rules unless explicitly requested
    let react_gate = CapabilityGate::default_react();
    let cfg = DotoreConfig::default();
    let violating_rs = "pub fn bad(x: Option<i32>) -> i32 { x.unwrap() }\n";
    assert!(
        analyze_source_with_config(
            Path::new("src/bad.rs"),
            violating_rs,
            &cfg,
            &react_gate,
            None,
        )
        .is_empty(),
        "React-only capability gate must not activate Rust-only rules"
    );
}

#[test]
fn analyze_project_sources_discovers_cargo_toml_capabilities_and_builds_fix_capsules() {
    let cargo_toml = r#"
[package]
name = "billing-engine"
version = "0.2.0"
edition = "2024"

[dependencies]
tokio = { version = "1.41", features = ["full"] }
axum = "0.8"
sqlx = "0.8"
serde = "1.0"
tracing = "0.1"
"#;

    let rs_source = r#"
pub fn charge_invoice(raw_cents: Option<u64>, discounts: &[u64], idx: usize) -> u32 {
    let cents = raw_cents.unwrap();
    let disc = discounts[idx];
    (cents - disc) as u32
}
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_toml.to_string()),
            (PathBuf::from("src/lib.rs"), rs_source.to_string()),
        ],
        None,
    );

    assert_eq!(report.summary.files_scanned, 1);
    assert!(report.summary.subjects_scanned >= 1);
    assert_eq!(report.diagnostics.len(), 3);
    assert!(!report.root_cause_groups.is_empty());
    assert!(!report.fix_capsules.is_empty());

    let project = report
        .projects
        .first()
        .unwrap_or_else(|| panic!("Expected project coverage entry"));
    for expected_cap in [
        Capability::Rust,
        Capability::Tokio,
        Capability::Axum,
        Capability::Sqlx,
        Capability::Serde,
        Capability::Tracing,
    ] {
        assert!(
            project.capabilities.contains(&expected_cap),
            "Expected project capabilities {:?} to include {expected_cap:?}",
            project.capabilities
        );
    }
}

#[test]
fn apply_patches_to_source_validates_rust_syntax_before_committing_edits() {
    let orig_rs = "pub fn answer(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n";
    let valid_diag = dotore::Diagnostic {
        file: PathBuf::from("src/lib.rs"),
        subject_name: Some("answer".to_string()),
        rule: RuleId::RsNoUnwrapInProduction,
        category: dotore::RuleCategory::Bugs,
        severity: dotore::RuleSeverity::Error,
        message_id: "rsNoUnwrapInProduction",
        tier: PrescriptionTier::Autofix,
        target_name: "unwrap".to_string(),
        message: "Replace .unwrap() with .unwrap_or_default().".to_string(),
        docs_url: RuleId::RsNoUnwrapInProduction.docs_url(),
        loc: SourceLoc { line: 2, column: 7 },
        span: ByteSpan { start: 43, end: 53 },
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: Some(AutofixPatch {
            description: "Replace `.unwrap()` with `.unwrap_or_default()`".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan { start: 43, end: 53 },
                replacement: "x.unwrap_or_default()".to_string(),
            }],
        }),
    };

    let (rewritten, descriptions) =
        apply_patches_to_source(orig_rs, std::slice::from_ref(&valid_diag));
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten.contains("x.unwrap_or_default()"));
    assert!(RsLanguageAnalyzer.validate_syntax(Path::new("src/lib.rs"), &rewritten));

    // A patch that corrupts Rust syntax must be rejected by `apply_patches_to_source`
    let mut corrupt_diag = valid_diag;
    corrupt_diag.autofix = Some(AutofixPatch {
        description: "Corrupt syntax patch".to_string(),
        edits: vec![ByteEdit {
            file: None,
            span: ByteSpan { start: 43, end: 53 },
            replacement: "fn {{{ broken".to_string(),
        }],
    });
    let (unchanged, rejected_descs) = apply_patches_to_source(orig_rs, &[corrupt_diag]);
    assert!(rejected_descs.is_empty());
    assert_eq!(unchanged, orig_rs);
}

#[test]
fn rust_rules_are_registered_in_rule_catalog_and_explain_rule() {
    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            framework: Some("rust".to_string()),
            ..RulesListOptions::default()
        },
    );
    let ids: Vec<&str> = catalog.iter().map(|e| e.id.as_str()).collect();
    for expected_id in [
        "rs-no-unwrap-in-production",
        "rs-no-unguarded-slice-index",
        "rs-no-lossy-numeric-as-cast",
        "rs-require-safety-comment-on-unsafe",
        "rs-no-mem-forget",
    ] {
        assert!(
            ids.contains(&expected_id),
            "Expected {expected_id} in rust framework catalog: {ids:?}"
        );
        let explained =
            explain_rule(expected_id, &cfg).unwrap_or_else(|| panic!("explain {expected_id}"));
        assert_eq!(explained.id, expected_id);
        assert_eq!(explained.framework, "rust");
    }
}
