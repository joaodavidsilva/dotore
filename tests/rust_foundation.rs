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

#[test]
fn seven_clippy_grade_ast_rules_detect_violations_and_honor_expect_and_comment_suppressions() {
    let invalid_lib_src = r#"use std::cell::RefCell;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

pub async fn refcell_across_await(cell: &RefCell<Vec<u32>>) {
    let mut borrowed = cell.borrow_mut();
    borrowed.push(1);
    async_step().await;
}

async fn async_step() {}

pub fn production_panics_and_prints(flag: i32) -> Result<i32, &'static str> {
    dbg!(flag);
    println!("debug trace: {flag}");
    eprintln!("stderr trace: {flag}");
    if flag < 0 {
        panic!("negative flag");
    }
    if flag == 0 {
        todo!("handle zero");
    }
    if flag == 1 {
        unimplemented!("handle one");
    }
    if flag == 2 {
        std::process::exit(1);
    }
    Ok(flag)
}

pub fn world_writable_and_zombie(perms: &mut Permissions) -> std::io::Result<()> {
    perms.set_readonly(false);
    let _mode_perms = Permissions::from_mode(0o777);
    let _ = Command::new("/usr/bin/true").spawn();
    let mut child = Command::new("/usr/bin/sleep").arg("1").spawn()?;
    let _id = child.id();
    Ok(())
}

/// Performs a raw pointer cast without a `# Safety` section or explicit transmute types.
pub unsafe fn raw_cast_without_safety_doc(ptr: *const u8) -> *const u16 {
    // SAFETY: caller guarantees valid pointer alignment.
    unsafe { std::mem::transmute::<_, *const u16>(ptr) }
}
"#;

    let clippy_rules = [
        RuleId::RsNoAwaitHoldingRefcell,
        RuleId::RsNoPanicOrTodoInProduction,
        RuleId::RsNoDbgOrPrintInLibrary,
        RuleId::RsSecurityNoWorldWritablePermissions,
        RuleId::RsNoZombieChildProcess,
        RuleId::RsNoTransmuteWithoutTypeAnnotations,
        RuleId::RsRequireSafetyDocOnPubUnsafeFn,
    ];

    let diags = analyze_source(Path::new("src/lib.rs"), invalid_lib_src, Some(&clippy_rules));
    let rule_counts = |rule: RuleId| diags.iter().filter(|d| d.rule == rule).count();

    assert_eq!(
        rule_counts(RuleId::RsNoAwaitHoldingRefcell),
        1,
        "Expected 1 rs-no-await-holding-refcell, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsNoPanicOrTodoInProduction),
        4,
        "Expected panic!, todo!, unimplemented!, and process::exit to be flagged, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsNoDbgOrPrintInLibrary),
        3,
        "Expected dbg!, println!, and eprintln! in library to be flagged, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsSecurityNoWorldWritablePermissions),
        2,
        "Expected set_readonly(false) and from_mode(0o777) to be flagged, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsNoZombieChildProcess),
        2,
        "Expected discarded spawn() and unwaited child handle to be flagged, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsNoTransmuteWithoutTypeAnnotations),
        1,
        "Expected transmute::<_, *const u16> to be flagged, got: {diags:#?}"
    );
    assert_eq!(
        rule_counts(RuleId::RsRequireSafetyDocOnPubUnsafeFn),
        1,
        "Expected pub unsafe fn without # Safety doc to be flagged, got: {diags:#?}"
    );

    // Adversarial valid cases + #[expect(..., reason = "...")] and // dotore-disable suppressions
    let valid_and_suppressed_src = r#"use std::cell::RefCell;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command};

pub async fn refcell_dropped_before_await(cell: &RefCell<Vec<u32>>) {
    {
        let mut borrowed = cell.borrow_mut();
        borrowed.push(1);
    }
    let second = cell.borrow();
    let _len = second.len();
    drop(second);
    async_step().await;
}

async fn async_step() {}

pub fn restricted_permissions_and_reaped_child(perms: &mut Permissions) -> std::io::Result<Child> {
    perms.set_readonly(true);
    let _safe_mode = Permissions::from_mode(0o644);
    let mut waited = Command::new("/usr/bin/true").spawn()?;
    let _ = waited.wait()?;
    let returned = Command::new("/usr/bin/true").spawn()?;
    Ok(returned)
}

/// Reinterprets a `u32` as `[u8; 4]`.
///
/// # Safety
/// Any 4-byte aligned `u32` has a valid bit pattern as `[u8; 4]`.
pub unsafe fn documented_safe_transmute(val: u32) -> [u8; 4] {
    // SAFETY: `u32` and `[u8; 4]` have identical size and no invalid bit patterns.
    unsafe { std::mem::transmute::<u32, [u8; 4]>(val) }
}

#[expect(clippy::todo, reason = "tracked migration stub")]
pub fn suppressed_with_expect() {
    todo!("stub");
}

pub fn suppressed_with_comment() {
    // dotore-disable-next-line rs-no-dbg-or-print-in-library
    dbg!(42);
}
"#;

    let clean_diags = analyze_source(
        Path::new("src/lib.rs"),
        valid_and_suppressed_src,
        Some(&clippy_rules),
    );
    assert!(
        clean_diags.is_empty(),
        "Expected 0 diagnostics on valid and suppressed Clippy-grade AST cases, got: {clean_diags:#?}"
    );
}

#[test]
fn eleven_cargo_health_rules_evaluate_manifest_lockfile_and_config_in_memory_and_on_disk() {
    let cargo_toml = r#"[package]
name = "cargo-health-suite"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "cargo-health-suite"
path = "src/main.rs"

[dependencies]
used_crate = "1.0"
unused_crate = "1.2"
test_only_crate = "0.4"
wildcard_crate = "*"
unpinned_git_crate = { git = "https://example.invalid/repo.git", branch = "main" }
pinned_git_crate = { git = "https://example.invalid/repo.git", rev = "0123456789abcdef0123456789abcdef01234567" }
escaped_path_crate = { path = "../outside-workspace-crate" }

[lints.clippy]
unwrap_used = "allow"

[profile.release]
debug = 2
overflow-checks = false
"#;

    let cargo_lock = r#"version = 3

[[package]]
name = "dup_crate"
version = "1.0.0"

[[package]]
name = "dup_crate"
version = "2.0.0"

[[package]]
name = "zero_minor_dup"
version = "0.7.1"

[[package]]
name = "zero_minor_dup"
version = "0.8.0"
"#;

    let cargo_config = r#"[build]
rustflags = ["-A", "warnings", "--cap-lints=allow", "-Coverflow-checks=off"]
"#;

    let main_rs = r#"use used_crate::Runner;
use pinned_git_crate::Client;
use wildcard_crate:: Codec;
use unpinned_git_crate::Transport;
use escaped_path_crate::Bridge;

fn main() {
    let _ = (
        Runner::new(),
        Client::new(),
        Codec::new(),
        Transport::new(),
        Bridge::new(),
    );
}

#[cfg(test)]
mod tests {
    use test_only_crate::MockServer;

    #[test]
    fn uses_test_only_dep() {
        let _ = MockServer::start();
    }
}
"#;

    let cargo_rules = [
        RuleId::RsCargoDuplicateMajorVersions,
        RuleId::RsCargoMissingLockfile,
        RuleId::RsCargoPathDepOutsideWorkspace,
        RuleId::RsCargoPermissiveLintTable,
        RuleId::RsCargoPermissiveRustflags,
        RuleId::RsCargoReleaseDebugSymbols,
        RuleId::RsCargoUncheckedReleaseOverflow,
        RuleId::RsCargoUnusedDependency,
        RuleId::RsCargoTestOnlyDependency,
        RuleId::RsCargoUnboundedWildcardDependency,
        RuleId::RsCargoUnpinnedGitDependency,
    ];

    // 1. Virtual in-memory `analyze_project_sources` without Cargo.lock triggers `rs-cargo-missing-lockfile` + manifest/config rules
    let no_lock_report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_toml.to_string()),
            (PathBuf::from(".cargo/config.toml"), cargo_config.to_string()),
            (PathBuf::from("src/main.rs"), main_rs.to_string()),
        ],
        Some(&cargo_rules),
    );
    let count_no_lock = |r: RuleId| no_lock_report.diagnostics.iter().filter(|d| d.rule == r).count();
    assert_eq!(count_no_lock(RuleId::RsCargoMissingLockfile), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoPathDepOutsideWorkspace), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoPermissiveLintTable), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoPermissiveRustflags), 3);
    assert_eq!(count_no_lock(RuleId::RsCargoReleaseDebugSymbols), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoUncheckedReleaseOverflow), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoUnusedDependency), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoTestOnlyDependency), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoUnboundedWildcardDependency), 1);
    assert_eq!(count_no_lock(RuleId::RsCargoUnpinnedGitDependency), 1);

    // 2. Virtual in-memory `analyze_project_sources` with Cargo.lock triggers `rs-cargo-duplicate-major-versions` (and not missing-lockfile)
    let with_lock_report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_toml.to_string()),
            (PathBuf::from("Cargo.lock"), cargo_lock.to_string()),
            (PathBuf::from(".cargo/config.toml"), cargo_config.to_string()),
            (PathBuf::from("src/main.rs"), main_rs.to_string()),
        ],
        Some(&cargo_rules),
    );
    let count_with_lock = |r: RuleId| with_lock_report.diagnostics.iter().filter(|d| d.rule == r).count();
    assert_eq!(count_with_lock(RuleId::RsCargoMissingLockfile), 0);
    assert_eq!(count_with_lock(RuleId::RsCargoDuplicateMajorVersions), 2);

    // 3. On-disk `scan_workspace_with_overrides` evaluates all Cargo.toml, Cargo.lock, and .cargo/config.toml rules
    let temp_dir = std::env::temp_dir().join(format!("dotore-cargo-health-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(temp_dir.join("src")).unwrap();
    std::fs::create_dir_all(temp_dir.join(".cargo")).unwrap();
    std::fs::write(temp_dir.join("Cargo.toml"), cargo_toml).unwrap();
    std::fs::write(temp_dir.join("Cargo.lock"), cargo_lock).unwrap();
    std::fs::write(temp_dir.join(".cargo/config.toml"), cargo_config).unwrap();
    std::fs::write(temp_dir.join("src/main.rs"), main_rs).unwrap();

    let (disk_report, _) = dotore::scan_workspace_with_overrides(
        &dotore::ScanOptions {
            paths: vec![temp_dir.clone()],
            include_tests: false,
            rules: Some(cargo_rules.to_vec()),
            tiers: None,
        },
        &dotore::CliOverrides {
            no_cache: true,
            ..dotore::CliOverrides::default()
        },
    )
    .unwrap();
    let count_disk = |r: RuleId| disk_report.diagnostics.iter().filter(|d| d.rule == r).count();
    assert_eq!(count_disk(RuleId::RsCargoDuplicateMajorVersions), 2);
    assert_eq!(count_disk(RuleId::RsCargoPathDepOutsideWorkspace), 1);
    assert_eq!(count_disk(RuleId::RsCargoPermissiveLintTable), 1);
    assert_eq!(count_disk(RuleId::RsCargoPermissiveRustflags), 3);
    assert_eq!(count_disk(RuleId::RsCargoReleaseDebugSymbols), 1);
    assert_eq!(count_disk(RuleId::RsCargoUncheckedReleaseOverflow), 1);
    assert_eq!(count_disk(RuleId::RsCargoUnusedDependency), 1);
    assert_eq!(count_disk(RuleId::RsCargoTestOnlyDependency), 1);
    assert_eq!(count_disk(RuleId::RsCargoUnboundedWildcardDependency), 1);
    assert_eq!(count_disk(RuleId::RsCargoUnpinnedGitDependency), 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
