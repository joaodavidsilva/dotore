//! Integration tests for Ticket #17 (`dotore-rs` Axum, SQLx, Leptos/Dioxus UI Signals, and Crate Architecture rules):
//! - `rs-sqlx-no-formatted-query-string` (`Capability::Sqlx`)
//! - `rs-sqlx-no-query-in-loop` (`Capability::Sqlx`)
//! - `rs-axum-no-contended-mutex-state` (`Capability::Axum`)
//! - `rs-ui-no-derived-signal-in-effect` (`Capability::Leptos` / `Capability::Dioxus`)
//! - `rs-arch-no-many-boolean-params` (`Capability::Rust`)
//! - `rs-arch-no-unused-pub-crate-items` (`Capability::Rust`, cross-file `ProjectGraph`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, PrescriptionTier, RuleId, analyze_project_sources,
    analyze_source, analyze_source_with_config,
};

#[test]
fn sqlx_rules_flag_formatted_queries_and_queries_in_loops_under_sqlx_capability_gate() {
    let invalid_src = r#"
pub async fn find_users_by_filter(
    pool: &sqlx::PgPool,
    tenant: &str,
    user_ids: &[i64],
) -> Result<(), String> {
    // 1. Direct format!(...) inside sqlx::query
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE tenant = '{tenant}'"))
        .fetch_all(pool)
        .await;

    // 2. Local variable holding format!(...) passed to sqlx::query_as
    let raw_sql = format!("SELECT id, name FROM users WHERE tenant = '{tenant}'");
    let _ = sqlx::query_as::<_, (i64, String)>(&raw_sql)
        .fetch_one(pool)
        .await;

    // 3. SQLx query executed inside a `for` loop (N+1 query hazard)
    for id in user_ids {
        let _ = sqlx::query("SELECT email FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await;
    }

    Ok(())
}
"#;

    let diags = analyze_source(Path::new("src/db.rs"), invalid_src, None);
    let formatted_diags: Vec<_> = diags
        .iter()
        .filter(|d| d.rule == RuleId::RsSqlxNoFormattedQueryString)
        .collect();
    let loop_diags: Vec<_> = diags
        .iter()
        .filter(|d| d.rule == RuleId::RsSqlxNoQueryInLoop)
        .collect();

    assert_eq!(
        formatted_diags.len(),
        2,
        "Expected 2 rs-sqlx-no-formatted-query-string diagnostics, got: {diags:#?}"
    );
    assert_eq!(
        loop_diags.len(),
        1,
        "Expected 1 rs-sqlx-no-query-in-loop diagnostic, got: {diags:#?}"
    );
    for d in formatted_diags.iter().chain(loop_diags.iter()) {
        assert_eq!(d.subject_name.as_deref(), Some("find_users_by_filter"));
        assert_eq!(d.tier, PrescriptionTier::Surgical);
    }

    // Capability Gate check: Cargo.toml without `sqlx` must NOT trigger `rs-sqlx-*` rules
    let rust_only_gate = CapabilityGate::with_capabilities([Capability::Rust]);
    let gated_off = analyze_source_with_config(
        Path::new("src/db.rs"),
        invalid_src,
        &DotoreConfig::default(),
        &rust_only_gate,
        None,
    );
    assert!(
        !gated_off.iter().any(|d| matches!(
            d.rule,
            RuleId::RsSqlxNoFormattedQueryString | RuleId::RsSqlxNoQueryInLoop
        )),
        "SQLx rules must not fire when Capability::Sqlx is absent: {gated_off:#?}"
    );

    // Adversarial valid cases: parameterized `.bind(...)` query and batched query outside loop
    let valid_src = r#"
pub async fn load_users_batched(
    pool: &sqlx::PgPool,
    tenant: &str,
    user_ids: &[i64],
) -> Result<Vec<i64>, String> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT id FROM users WHERE tenant = $1 AND id = ANY($2)",
    )
    .bind(tenant)
    .bind(user_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(rows.len());
    for (id,) in rows {
        out.push(id);
    }
    Ok(out)
}
"#;
    let valid_diags = analyze_source(Path::new("src/db_valid.rs"), valid_src, None);
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on parameterized batched SQLx queries, got: {valid_diags:#?}"
    );
}

#[test]
fn axum_rule_flags_contended_mutex_state_and_respects_axum_capability_gate() {
    let invalid_src = r#"use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use axum::extract::State;

pub struct ContendedState {
    pub sessions: Mutex<HashMap<String, String>>,
}

pub async fn get_cache_entry(
    State(cache): State<Arc<Mutex<HashMap<String, String>>>>,
) -> String {
    let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    guard.get("key").cloned().unwrap_or_default()
}

pub async fn record_session(
    State(state): State<Arc<ContendedState>>,
) -> &'static str {
    if let Ok(mut guard) = state.sessions.lock() {
        guard.insert("k".to_string(), "v".to_string());
    }
    "ok"
}
"#;

    let diags = analyze_source(Path::new("src/handlers.rs"), invalid_src, None);
    let axum_diags: Vec<_> = diags
        .iter()
        .filter(|d| d.rule == RuleId::RsAxumNoContendedMutexState)
        .collect();
    assert_eq!(
        axum_diags.len(),
        2,
        "Expected 2 rs-axum-no-contended-mutex-state diagnostics, got: {diags:#?}"
    );
    assert_eq!(axum_diags[0].subject_name.as_deref(), Some("get_cache_entry"));
    assert_eq!(axum_diags[1].subject_name.as_deref(), Some("record_session"));

    // Capability Gate check via Cargo.toml without `axum`
    let non_axum_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"cli-tool\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n"
                    .to_string(),
            ),
            (PathBuf::from("src/handlers.rs"), invalid_src.to_string()),
        ],
        None,
    );
    assert!(
        !non_axum_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::RsAxumNoContendedMutexState),
        "rs-axum-no-contended-mutex-state must not run when Cargo.toml lacks axum"
    );

    // Adversarial valid case: `State<Arc<AppState>>` without Mutex
    let valid_src = r#"use std::sync::{Arc, RwLock, atomic::AtomicU64};
use axum::extract::State;

pub struct AppState {
    pub request_count: AtomicU64,
    pub config_snapshot: RwLock<String>,
}

pub async fn health_handler(State(state): State<Arc<AppState>>) -> String {
    state.request_count.load(std::sync::atomic::Ordering::Relaxed).to_string()
}
"#;
    let valid_diags = analyze_source(Path::new("src/valid_handlers.rs"), valid_src, None);
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on Mutex-free Axum State, got: {valid_diags:#?}"
    );
}

#[test]
fn ui_rule_flags_derived_signal_in_effect_under_leptos_or_dioxus_capability_gate() {
    let leptos_invalid = r#"
pub fn UserBadge() {
    let (first, _set_first) = signal("Ada".to_string());
    let (last, _set_last) = signal("Lovelace".to_string());
    let (_full_name, set_full_name) = signal(String::new());

    Effect::new(move |_| {
        set_full_name.set(format!("{} {}", first.get(), last.get()));
    });
}
"#;

    let dioxus_invalid = r#"
pub fn CounterPanel() {
    let count = use_signal(|| 1);
    let mut doubled = use_signal(|| 2);

    use_effect(move || {
        doubled.set(count.read().clone() * 2);
    });
}
"#;

    // 1. Activated under Cargo.toml with ONLY `leptos`
    let leptos_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"leptos-ui\"\nversion = \"0.1.0\"\n[dependencies]\nleptos = \"0.7\"\n"
                    .to_string(),
            ),
            (PathBuf::from("src/lib.rs"), leptos_invalid.to_string()),
        ],
        None,
    );
    assert_eq!(
        leptos_report
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::RsUiNoDerivedSignalInEffect)
            .count(),
        1,
        "Expected 1 rs-ui-no-derived-signal-in-effect diagnostic under leptos Cargo.toml: {leptos_report:#?}"
    );

    // 2. Activated under Cargo.toml with ONLY `dioxus`
    let dioxus_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"dioxus-ui\"\nversion = \"0.1.0\"\n[dependencies]\ndioxus = \"0.6\"\n"
                    .to_string(),
            ),
            (PathBuf::from("src/lib.rs"), dioxus_invalid.to_string()),
        ],
        None,
    );
    assert_eq!(
        dioxus_report
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::RsUiNoDerivedSignalInEffect)
            .count(),
        1,
        "Expected 1 rs-ui-no-derived-signal-in-effect diagnostic under dioxus Cargo.toml: {dioxus_report:#?}"
    );

    // 3. Not activated when neither `leptos` nor `dioxus` is in Cargo.toml
    let backend_only_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"backend-only\"\nversion = \"0.1.0\"\n[dependencies]\naxum = \"0.8\"\n"
                    .to_string(),
            ),
            (PathBuf::from("src/lib.rs"), leptos_invalid.to_string()),
        ],
        None,
    );
    assert!(
        !backend_only_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::RsUiNoDerivedSignalInEffect),
        "Expected 0 UI signal diagnostics when neither leptos nor dioxus is present"
    );

    // 4. Adversarial valid cases: Memo::new / use_memo and side-effect-only Effect::new
    let valid_ui_src = r#"
pub fn ValidReactiveComponent() {
    let (first, _set_first) = signal("Ada".to_string());
    let (last, _set_last) = signal("Lovelace".to_string());
    let full_name = Memo::new(move |_| format!("{} {}", first.get(), last.get()));
    let upper = use_memo(move || full_name.get().to_uppercase());

    Effect::new(move |_| {
        tracing::info!("rendered user: {}", upper.read());
    });
}
"#;
    let valid_diags = analyze_source(Path::new("src/valid_ui.rs"), valid_ui_src, None);
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on Memo::new / use_memo and logging effect, got: {valid_diags:#?}"
    );
}

#[test]
fn arch_rules_flag_many_boolean_params_and_unused_pub_crate_items_across_project_graph() {
    let helpers_rs = r#"
pub(crate) struct UsedInternalConfig {
    pub max_retries: usize,
}

pub(crate) fn used_cross_module_helper(cfg: &UsedInternalConfig, dry_run: bool) -> usize {
    if dry_run { 0 } else { cfg.max_retries }
}

pub(crate) fn unused_dead_helper() -> usize {
    0
}

pub(crate) const UNUSED_CRATE_CONST: usize = 99;

pub fn deploy_release(
    env_name: &str,
    dry_run: bool,
    force_push: bool,
    skip_hooks: bool,
    notify_slack: bool,
) -> usize {
    let _ = (env_name, dry_run, force_push, skip_hooks, notify_slack);
    1
}
"#;

    let lib_rs = r#"mod helpers;

use crate::helpers::{UsedInternalConfig, used_cross_module_helper};

pub fn execute_workflow(dry_run: bool) -> usize {
    let cfg = UsedInternalConfig { max_retries: 3 };
    used_cross_module_helper(&cfg, dry_run)
}
"#;

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"workflow-crate\"\nversion = \"0.1.0\"\n".to_string(),
            ),
            (PathBuf::from("src/helpers.rs"), helpers_rs.to_string()),
            (PathBuf::from("src/lib.rs"), lib_rs.to_string()),
        ],
        None,
    );

    let bool_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::RsArchNoManyBooleanParams)
        .collect();
    assert_eq!(
        bool_diags.len(),
        1,
        "Expected 1 rs-arch-no-many-boolean-params diagnostic on deploy_release, got: {bool_diags:#?}"
    );
    assert_eq!(bool_diags[0].subject_name.as_deref(), Some("deploy_release"));

    let unused_pub_crate_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::RsArchNoUnusedPubCrateItems)
        .collect();
    let unused_targets: Vec<&str> = unused_pub_crate_diags
        .iter()
        .map(|d| d.target_name.as_str())
        .collect();
    assert_eq!(
        unused_pub_crate_diags.len(),
        2,
        "Expected 2 rs-arch-no-unused-pub-crate-items diagnostics, got: {unused_pub_crate_diags:#?}"
    );
    assert!(unused_targets.contains(&"unused_dead_helper"));
    assert!(unused_targets.contains(&"UNUSED_CRATE_CONST"));
    assert!(!unused_targets.contains(&"used_cross_module_helper"));
    assert!(!unused_targets.contains(&"UsedInternalConfig"));
}

#[test]
fn ticket_17_rules_are_registered_in_catalog_and_honor_inline_suppressions() {
    let cfg = DotoreConfig::default();
    let catalog = dotore::build_rule_catalog(
        &cfg,
        &dotore::RulesListOptions {
            framework: Some("rust".to_string()),
            ..dotore::RulesListOptions::default()
        },
    );
    let ids: Vec<&str> = catalog.iter().map(|e| e.id.as_str()).collect();
    for expected_id in [
        "rs-sqlx-no-formatted-query-string",
        "rs-sqlx-no-query-in-loop",
        "rs-axum-no-contended-mutex-state",
        "rs-ui-no-derived-signal-in-effect",
        "rs-arch-no-many-boolean-params",
        "rs-arch-no-unused-pub-crate-items",
    ] {
        assert!(
            ids.contains(&expected_id),
            "Expected {expected_id} in rust rule catalog: {ids:?}"
        );
        let entry = dotore::explain_rule(expected_id, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({expected_id})"));
        assert_eq!(entry.id, expected_id);
    }

    let suppressed_src = r#"
pub async fn suppressed_examples(pool: &sqlx::PgPool, filter: &str) {
    // dotore-disable-next-line rs-sqlx-no-formatted-query-string
    let _ = sqlx::query(&format!("SELECT * FROM t WHERE f = '{filter}'"))
        .fetch_all(pool)
        .await;
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn legacy_flags(a: bool, b: bool, c: bool, d: bool) -> bool {
    a && b && c && d
}
"#;
    let diags = analyze_source(Path::new("src/suppressed.rs"), suppressed_src, None);
    assert!(
        diags.is_empty(),
        "Expected inline and attribute suppressions to silence diagnostics, got: {diags:#?}"
    );
}
