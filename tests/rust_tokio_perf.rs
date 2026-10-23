//! Integration tests for Ticket #16 (`dotore-rs` Tokio async hazards & Rust allocation performance rules):
//! - `rs-tokio-no-std-lock-across-await` (`RuleId::RsTokioNoStdLockAcrossAwait`, gated by `Capability::Tokio`)
//! - `rs-tokio-no-blocking-in-async` (`RuleId::RsTokioNoBlockingInAsync`, `PrescriptionTier::Autofix`, gated by `Capability::Tokio`)
//! - `rs-tokio-prefer-bounded-channel` (`RuleId::RsTokioPreferBoundedChannel`, gated by `Capability::Tokio`)
//! - `rs-perf-no-clone-in-loop` (`RuleId::RsPerfNoCloneInLoop`, gated by `Capability::Rust`)
//! - `rs-perf-hoist-regex-to-lazylock` (`RuleId::RsPerfHoistRegexToLazylock`, gated by `Capability::Rust`)
//! - `rs-perf-prefer-vec-with-capacity` (`RuleId::RsPerfPreferVecWithCapacity`, gated by `Capability::Rust`)
//! - `rs-perf-no-unnecessary-format` (`RuleId::RsPerfNoUnnecessaryFormat`, gated by `Capability::Rust`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, LanguageAnalyzer, PrescriptionTier, RuleId,
    RulesListOptions, analyze_project_sources, analyze_source, analyze_source_with_config,
    apply_patches_to_source, build_rule_catalog, explain_rule, rule_registry,
};
use dotore_rs::RsLanguageAnalyzer;

const TICKET_16_RULES: &[RuleId] = &[
    RuleId::RsTokioNoStdLockAcrossAwait,
    RuleId::RsTokioNoBlockingInAsync,
    RuleId::RsTokioPreferBoundedChannel,
    RuleId::RsPerfNoCloneInLoop,
    RuleId::RsPerfHoistRegexToLazylock,
    RuleId::RsPerfPreferVecWithCapacity,
    RuleId::RsPerfNoUnnecessaryFormat,
];

#[test]
fn all_seven_tokio_and_perf_rules_are_registered_in_catalog() {
    let registry = rule_registry();
    let cfg = DotoreConfig::default();

    for &rule in TICKET_16_RULES {
        assert!(
            registry.iter().any(|m| m.id == rule),
            "Expected {rule:?} in rule_registry()"
        );
        let explained = explain_rule(rule.as_str(), &cfg)
            .unwrap_or_else(|| panic!("Expected explain_rule for {}", rule.as_str()));
        assert_eq!(explained.id, rule.as_str());
    }

    assert_eq!(
        RuleId::RsTokioNoBlockingInAsync.metadata().default_tier,
        PrescriptionTier::Autofix
    );

    let tokio_catalog = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            framework: Some("tokio".to_string()),
            ..RulesListOptions::default()
        },
    );
    let tokio_ids: Vec<&str> = tokio_catalog.iter().map(|e| e.id.as_str()).collect();
    for expected in [
        "rs-tokio-no-std-lock-across-await",
        "rs-tokio-no-blocking-in-async",
        "rs-tokio-prefer-bounded-channel",
    ] {
        assert!(
            tokio_ids.contains(&expected),
            "Expected {expected} in tokio framework catalog, got {tokio_ids:?}"
        );
    }

    let rust_catalog = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            framework: Some("rust".to_string()),
            ..RulesListOptions::default()
        },
    );
    let rust_ids: Vec<&str> = rust_catalog.iter().map(|e| e.id.as_str()).collect();
    for expected in [
        "rs-perf-no-clone-in-loop",
        "rs-perf-hoist-regex-to-lazylock",
        "rs-perf-prefer-vec-with-capacity",
        "rs-perf-no-unnecessary-format",
    ] {
        assert!(
            rust_ids.contains(&expected),
            "Expected {expected} in rust framework catalog, got {rust_ids:?}"
        );
    }
}

#[test]
fn capability_gate_controls_tokio_vs_rust_only_rules() {
    let src = r#"
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn handler(m: &Mutex<u32>, names: &[String]) -> Vec<String> {
    let (_tx, _rx) = mpsc::unbounded_channel::<u32>();
    let guard = m.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::sleep(Duration::from_millis(10));
    fetch_remote(*guard).await;

    let mut out = Vec::new();
    for name in names {
        out.push(name.clone());
    }
    let _msg = format!("static_banner");
    out
}

async fn fetch_remote(_v: u32) {}
"#;

    let cfg = DotoreConfig::default();

    // 1. Rust-only gate (no Tokio): only `rs-perf-*` rules fire; `rs-tokio-*` rules are gated off.
    let rust_only_gate = CapabilityGate::with_capabilities([Capability::Rust]);
    let rust_only_diags = analyze_source_with_config(
        Path::new("src/handler.rs"),
        src,
        &cfg,
        &rust_only_gate,
        None,
    );
    let rust_only_rules: Vec<RuleId> = rust_only_diags.iter().map(|d| d.rule).collect();
    assert!(
        !rust_only_rules.contains(&RuleId::RsTokioNoStdLockAcrossAwait),
        "Tokio rule must not fire without Capability::Tokio: {rust_only_rules:?}"
    );
    assert!(
        !rust_only_rules.contains(&RuleId::RsTokioNoBlockingInAsync),
        "Tokio rule must not fire without Capability::Tokio: {rust_only_rules:?}"
    );
    assert!(
        !rust_only_rules.contains(&RuleId::RsTokioPreferBoundedChannel),
        "Tokio rule must not fire without Capability::Tokio: {rust_only_rules:?}"
    );
    assert!(rust_only_rules.contains(&RuleId::RsPerfNoCloneInLoop));
    assert!(rust_only_rules.contains(&RuleId::RsPerfPreferVecWithCapacity));
    assert!(rust_only_rules.contains(&RuleId::RsPerfNoUnnecessaryFormat));

    // 2. Rust + Tokio gate: both `rs-tokio-*` and `rs-perf-*` rules fire.
    let tokio_gate = CapabilityGate::with_capabilities([Capability::Rust, Capability::Tokio]);
    let tokio_diags =
        analyze_source_with_config(Path::new("src/handler.rs"), src, &cfg, &tokio_gate, None);
    let tokio_rules: Vec<RuleId> = tokio_diags.iter().map(|d| d.rule).collect();
    assert!(tokio_rules.contains(&RuleId::RsTokioNoStdLockAcrossAwait));
    assert!(tokio_rules.contains(&RuleId::RsTokioNoBlockingInAsync));
    assert!(tokio_rules.contains(&RuleId::RsTokioPreferBoundedChannel));
    assert!(tokio_rules.contains(&RuleId::RsPerfNoCloneInLoop));
    assert!(tokio_rules.contains(&RuleId::RsPerfPreferVecWithCapacity));
    assert!(tokio_rules.contains(&RuleId::RsPerfNoUnnecessaryFormat));

    // 3. Project analysis with Cargo.toml without `tokio` vs with `tokio`.
    let cargo_no_tokio = r#"
[package]
name = "cli-tool"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
    let report_no_tokio = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_no_tokio.to_string()),
            (PathBuf::from("src/lib.rs"), src.to_string()),
        ],
        None,
    );
    assert!(
        report_no_tokio
            .diagnostics
            .iter()
            .all(|d| !matches!(
                d.rule,
                RuleId::RsTokioNoStdLockAcrossAwait
                    | RuleId::RsTokioNoBlockingInAsync
                    | RuleId::RsTokioPreferBoundedChannel
            )),
        "Expected no Tokio diagnostics when Cargo.toml lacks tokio, got: {:#?}",
        report_no_tokio.diagnostics
    );

    let cargo_with_tokio = r#"
[package]
name = "async-service"
version = "0.1.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
"#;
    let report_with_tokio = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_with_tokio.to_string()),
            (PathBuf::from("src/lib.rs"), src.to_string()),
        ],
        None,
    );
    let project_rules: Vec<RuleId> = report_with_tokio
        .diagnostics
        .iter()
        .map(|d| d.rule)
        .collect();
    assert!(project_rules.contains(&RuleId::RsTokioNoStdLockAcrossAwait));
    assert!(project_rules.contains(&RuleId::RsTokioNoBlockingInAsync));
    assert!(project_rules.contains(&RuleId::RsTokioPreferBoundedChannel));
}

#[test]
fn invalid_cases_detected_for_all_seven_tokio_and_perf_rules() {
    let invalid_src = r#"
use std::sync::{Mutex, RwLock};
use std::time::Duration;
use regex::Regex;
use tokio::sync::mpsc;

pub async fn tokio_hazards(
    mu: &Mutex<Vec<String>>,
    rw: &RwLock<u64>,
    dur: Duration,
) -> std::io::Result<()> {
    let (_tx, _rx) = mpsc::unbounded_channel::<String>();

    let mut guard = mu.lock().unwrap();
    guard.push(String::from("start"));
    tokio::time::sleep(dur).await;

    let read_guard = rw.read().unwrap();
    let _val = *read_guard;
    tokio::task::yield_now().await;

    std::thread::sleep(dur);
    let _cfg = std::fs::read_to_string("config.toml")?;
    let _stream = std::net::TcpStream::connect("127.0.0.1:8080")?;
    Ok(())
}

pub fn perf_hazards(items: &[String], label: &str) -> Vec<String> {
    let email_re = Regex::new(r"^[^@]+@[^@]+\.[^@]+$").unwrap();
    let mut results = Vec::new();
    for item in items {
        let cloned = item.clone();
        if email_re.is_match(&cloned) {
            results.push(cloned);
        } else {
            results.push(String::new());
        }
    }

    let mut unconditional = Vec::new();
    for item in items {
        unconditional.push(item.len());
    }

    let _plain = format!("constant string without args");
    let _single_pos = format!("{}", label);
    let _single_named = format!("{label}");
    results
}
"#;

    let diags = analyze_source(
        Path::new("src/service.rs"),
        invalid_src,
        Some(TICKET_16_RULES),
    );
    let rules: Vec<RuleId> = diags.iter().map(|d| d.rule).collect();

    assert_eq!(
        diags
            .iter()
            .filter(|d| d.rule == RuleId::RsTokioNoStdLockAcrossAwait)
            .count(),
        2,
        "Expected both Mutex.lock() and RwLock.read() across .await to be flagged: {diags:#?}"
    );
    assert_eq!(
        diags
            .iter()
            .filter(|d| d.rule == RuleId::RsTokioNoBlockingInAsync)
            .count(),
        3,
        "Expected thread::sleep, std::fs::read_to_string, and std::net::TcpStream::connect to be flagged: {diags:#?}"
    );
    assert!(rules.contains(&RuleId::RsTokioPreferBoundedChannel));
    assert!(rules.contains(&RuleId::RsPerfNoCloneInLoop));
    assert!(rules.contains(&RuleId::RsPerfHoistRegexToLazylock));
    assert!(rules.contains(&RuleId::RsPerfPreferVecWithCapacity));
    assert_eq!(
        diags
            .iter()
            .filter(|d| d.rule == RuleId::RsPerfNoUnnecessaryFormat)
            .count(),
        3,
        "Expected all 3 unnecessary format! calls to be flagged: {diags:#?}"
    );
}

#[test]
fn adversarial_valid_tokio_and_perf_cases_emit_zero_diagnostics() {
    let valid_src = r#"
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use regex::Regex;
use tokio::sync::{Mutex as TokioMutex, RwLock as TokioRwLock, mpsc};

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^@]+@[^@]+\.[^@]+$").unwrap());

pub async fn safe_async_workflow(
    std_mu: &Mutex<u64>,
    tokio_mu: &TokioMutex<u64>,
    tokio_rw: &TokioRwLock<Vec<u8>>,
    dur: Duration,
) -> std::io::Result<u64> {
    // 1. Bounded channel
    let (tx, mut rx) = mpsc::channel::<u64>(32);

    // 2. Scoped inner block drops std::sync::MutexGuard before .await
    {
        let mut g = std_mu.lock().unwrap();
        *g += 1;
    }
    tx.send(1).await.ok();

    // 3. Explicit `drop(guard)` before .await
    let mut g2 = std_mu.lock().unwrap();
    *g2 += 2;
    drop(g2);
    let _received = rx.recv().await;

    // 4. `tokio::sync::Mutex` and `tokio::sync::RwLock` guards held across .await are safe
    let mut async_guard = tokio_mu.lock().await;
    *async_guard += 10;
    tokio::time::sleep(dur).await;

    let async_read = tokio_rw.read().await;
    let len = async_read.len() as u64;
    tokio::task::yield_now().await;

    // 5. Blocking work inside `tokio::task::spawn_blocking` is safe
    let blocking_handle = tokio::task::spawn_blocking(move || {
        std::thread::sleep(dur);
        std::fs::read_to_string("Cargo.toml")
    });
    let _ = blocking_handle.await;

    // 6. Async `tokio::fs` I/O is safe
    let _async_bytes = tokio::fs::read("Cargo.toml").await?;

    Ok(*async_guard + len)
}

pub fn safe_perf_patterns(
    items: &[String],
    shared_state: &Arc<Vec<u8>>,
    local_rc: &Rc<String>,
    http_client: & reqwest::Client,
) -> Vec<String> {
    // 1. Pre-allocated Vec::with_capacity
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        // 2. Cheap reference-counted handle clones in loop are allowed
        let _state = Arc::clone(shared_state);
        let _rc = Rc::clone(local_rc);
        let _arc2 = shared_state.clone();
        let _client = http_client.clone();

        if EMAIL_RE.is_match(item) {
            out.push(format!("valid:{item}"));
        } else {
            out.push(format!("invalid:{item:?}"));
        }
    }

    // 3. Vec::new() with conditional filter in loop (final length unknown upfront)
    let mut filtered = Vec::new();
    for item in items {
        if item.len() > 3 {
            filtered.push(item.as_str());
        }
    }

    // 4. Vec::new() followed by explicit reserve before loop
    let mut reserved = Vec::new();
    reserved.reserve(items.len());
    for item in items {
        reserved.push(item.len());
    }

    out
}
"#;

    let diags = analyze_source(
        Path::new("src/valid_service.rs"),
        valid_src,
        Some(TICKET_16_RULES),
    );
    assert!(
        diags.is_empty(),
        "Expected 0 diagnostics on adversarial valid Tokio & perf code, got: {diags:#?}"
    );
}

#[test]
fn rs_perf_no_clone_in_loop_ignores_copy_primitives_and_flags_heap_types() {
    let src = r#"
pub fn clone_precision_check(count: usize, flag: bool, ratio: f64, shared_slice: &[u8], text: String) {
    let local_idx: u32 = 7;
    let local_char: char = 'x';
    let inferred_num = 42usize;
    let mut total = 0usize;
    for _ in 0..10 {
        let _a = count.clone();
        let _b = flag.clone();
        let _c = ratio.clone();
        let _d = shared_slice.clone();
        let _e = local_idx.clone();
        let _f = local_char.clone();
        let _g = inferred_num.clone();
        let _heap = text.clone();
        total += _a;
    }
    let _ = total;
}
"#;
    let diags = analyze_source(
        Path::new("src/clone_precision.rs"),
        src,
        Some(&[RuleId::RsPerfNoCloneInLoop]),
    );
    assert_eq!(
        diags.len(),
        1,
        "Expected only heap `text.clone()` to be flagged, not Copy primitives or shared references, got: {diags:#?}"
    );
    assert_eq!(diags[0].target_name, "text.clone()");
}

#[test]
fn autofix_rewrites_std_thread_sleep_to_tokio_time_sleep_await() {
    let source = r#"use std::time::Duration;

pub async fn poll_endpoint(d: Duration) {
    std::thread::sleep(d);
    thread::sleep(Duration::from_millis(250));
}
"#;

    let diags = analyze_source(
        Path::new("src/poller.rs"),
        source,
        Some(&[RuleId::RsTokioNoBlockingInAsync]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics: {diags:#?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::RsTokioNoBlockingInAsync);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert!(
            diag.autofix.is_some(),
            "Expected Autofix patch on {diag:#?}"
        );
    }

    let (fixed, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 2);
    assert!(
        fixed.contains("tokio::time::sleep(d).await;"),
        "Expected `tokio::time::sleep(d).await;` in fixed source:\n{fixed}"
    );
    assert!(
        fixed.contains("tokio::time::sleep(Duration::from_millis(250)).await;"),
        "Expected `tokio::time::sleep(Duration::from_millis(250)).await;` in fixed source:\n{fixed}"
    );
    assert!(
        RsLanguageAnalyzer.validate_syntax(Path::new("src/poller.rs"), &fixed),
        "Fixed Rust source must be syntactically valid:\n{fixed}"
    );

    let remaining = analyze_source(
        Path::new("src/poller.rs"),
        &fixed,
        Some(&[RuleId::RsTokioNoBlockingInAsync]),
    );
    assert!(
        remaining.is_empty(),
        "Expected 0 remaining diagnostics after Autofix round-trip, got: {remaining:#?}"
    );
}
