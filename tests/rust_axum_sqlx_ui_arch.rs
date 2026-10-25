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
    assert_eq!(
        axum_diags[0].subject_name.as_deref(),
        Some("get_cache_entry")
    );
    assert_eq!(
        axum_diags[1].subject_name.as_deref(),
        Some("record_session")
    );

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

pub fn should_highlight_search(
    no_color_flag: bool,
    is_tty: bool,
    env_vars: &[(String, String)],
) -> bool {
    let _ = env_vars;
    !no_color_flag && is_tty
}
"#;

    let lib_rs = r#"mod helpers;

use crate::helpers::{UsedInternalConfig, used_cross_module_helper};

pub fn execute_workflow(dry_run: bool) -> usize {
    let cfg = UsedInternalConfig { max_retries: 3 };
    let _ = helpers::should_highlight_search(dry_run, true, &[]);
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
    assert_eq!(
        bool_diags[0].subject_name.as_deref(),
        Some("deploy_release")
    );

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
fn self_hosting_workspace_has_zero_unused_pub_crate_and_many_boolean_param_diagnostics() {
    use dotore::ScanOptions;
    use std::path::Path;

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (report, _sources) = dotore::scan_workspace(&ScanOptions {
        paths: vec![workspace_root.to_path_buf()],
        include_tests: false,
        rules: Some(vec![
            RuleId::RsArchNoUnusedPubCrateItems,
            RuleId::RsArchNoManyBooleanParams,
        ]),
        tiers: None,
    })
    .expect("Failed to scan dotore workspace");

    assert!(
        report.diagnostics.is_empty(),
        "Expected 0 diagnostics for rs-arch-no-unused-pub-crate-items and rs-arch-no-many-boolean-params, got {}:\n{:#?}",
        report.diagnostics.len(),
        report
            .diagnostics
            .iter()
            .map(|d| (&d.file, d.loc.line, d.rule, &d.target_name, &d.message))
            .collect::<Vec<_>>()
    );
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

#[allow(fn_params_excessive_bools, reason = "legacy API")]
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

#[test]
fn unused_pub_crate_items_in_inline_module_used_in_same_file_is_not_flagged_in_multi_file_crate() {
    let lib_rs = r#"mod other;

mod internal_inline {
    pub(crate) fn used_by_parent_module() -> u32 {
        42
    }

    pub(crate) fn truly_unused_in_inline() -> u32 {
        0
    }
}

pub fn public_entrypoint() -> u32 {
    internal_inline::used_by_parent_module() + other::step()
}
"#;
    let other_rs = r#"pub(crate) fn step() -> u32 { 1 }
"#;

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("Cargo.toml"),
                "[package]\nname = \"inline-mod-crate\"\nversion = \"0.1.0\"\n".to_string(),
            ),
            (PathBuf::from("src/lib.rs"), lib_rs.to_string()),
            (PathBuf::from("src/other.rs"), other_rs.to_string()),
        ],
        Some(&[RuleId::RsArchNoUnusedPubCrateItems]),
    );

    let targets: Vec<&str> = report
        .diagnostics
        .iter()
        .map(|d| d.target_name.as_str())
        .collect();
    assert_eq!(
        targets,
        vec!["truly_unused_in_inline"],
        "Expected `used_by_parent_module` in inline module not to be flagged even in multi-file crate, got: {:#?}",
        report.diagnostics
    );
}

#[test]
fn rs_sqlx_no_formatted_query_string_supports_multi_crate_drivers_and_exempts_constants_and_numeric_primitives()
 {
    let invalid_src = r#"
use std::fmt::Write;
use diesel::sql_query as run_sql;
use rusqlite::Connection as SqliteConn;
use sqlx::QueryBuilder;

type UserIdAlias = i64;

pub async fn multi_driver_injections(
    pool: &sqlx::PgPool,
    tenant: &str,
    aliased_id: UserIdAlias,
) {
    // 1. diesel::sql_query via use-alias
    let _ = run_sql(format!("DELETE FROM users WHERE tenant = '{tenant}'"));
    // 2. diesel::dsl::sql
    let _ = diesel::dsl::sql::<diesel::sql_types::Bool>(&format!("tenant = '{tenant}'"));
    // 3. sea_orm::Statement::from_string (arg 1)
    let _ = sea_orm::Statement::from_string(
        sea_orm::DatabaseBackend::Postgres,
        format!("SELECT * FROM users WHERE tenant = '{tenant}'"),
    );
    // 4. rusqlite::Connection::execute via let-bound connection
    let conn = SqliteConn::open_in_memory().unwrap();
    let _ = conn.execute(&format!("DELETE FROM users WHERE name = '{tenant}'"), ());
    // 5. sqlx::QueryBuilder::push with dynamic format!
    let mut qb = QueryBuilder::<sqlx::Postgres>::new("SELECT * FROM users WHERE ");
    qb.push(format!("tenant = '{tenant}'"));
    // 6. String concatenation with +
    let concat_sql = "SELECT * FROM users WHERE tenant = '".to_owned() + tenant + "'";
    let _ = sqlx::query(&concat_sql).fetch_all(pool).await;
    // 7. write! into String
    let mut buf_sql = String::new();
    let _ = write!(buf_sql, "SELECT * FROM users WHERE tenant = '{tenant}'");
    let _ = sqlx::query(&buf_sql).fetch_all(pool).await;
    // 8. Type alias of i64 is NOT trusted as a bare primitive
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE id = {aliased_id}"))
        .fetch_all(pool)
        .await;
}
"#;

    let diags = analyze_source(
        Path::new("src/multi_sql.rs"),
        invalid_src,
        Some(&[RuleId::RsSqlxNoFormattedQueryString]),
    );
    assert_eq!(
        diags.len(),
        8,
        "Expected all 8 multi-crate formatted SQL queries to be flagged, got: {diags:#?}"
    );

    let valid_src = r#"
use sqlx::QueryBuilder;

const TABLE_NAME: &str = "users";

struct Page {
    limit: i64,
}

pub async fn safe_queries(
    pool: &sqlx::PgPool,
    limit: i64,
    offset: usize,
    active: bool,
    non_zero: std::num::NonZeroU32,
    page: Page,
    name: &str,
) {
    // 1. Primitive numeric and bool parameters are exempt
    let _ = sqlx::query(&format!(
        "SELECT * FROM {TABLE_NAME} WHERE active = {active} LIMIT {limit} OFFSET {offset}"
    ))
    .fetch_all(pool)
    .await;

    // 2. NonZero* and cast to numeric primitive are exempt
    let _ = sqlx::query(&format!(
        "SELECT * FROM users WHERE org = {non_zero} LIMIT {}",
        offset as i64
    ))
    .fetch_all(pool)
    .await;

    // 3. Field stored in a local `let` with explicit numeric type annotation is exempt
    let page_limit: i64 = page.limit;
    let _ = sqlx::query(&format!("SELECT * FROM users LIMIT {page_limit}"))
        .fetch_all(pool)
        .await;

    // 4. QueryBuilder::push_bind is safe
    let mut qb = QueryBuilder::<sqlx::Postgres>::new("SELECT * FROM users WHERE name = ");
    qb.push_bind(name);
}
"#;
    let valid_diags = analyze_source(
        Path::new("src/multi_sql_valid.rs"),
        valid_src,
        Some(&[RuleId::RsSqlxNoFormattedQueryString]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on constant and numeric-primitive SQL interpolations, got: {valid_diags:#?}"
    );
}

#[test]
fn source_kernel_web_http_tls_shell_and_secret_rules_resolve_aliases_and_8_hop_bindings() {
    let invalid_src = r#"
use reqwest::Client as HttpClient;
use std::process::Command as ProcCmd;
use std::env::var as read_env;
use tower_http::cors::{Any, CorsLayer};
use cookie::Cookie as HttpCookie;
use jsonwebtoken::{Algorithm, Validation};

const ALLOW_INSECURE_TLS: bool = true;

pub async fn security_and_http_violations(user_arg: &str, url: &str) -> Result<(), reqwest::Error> {
    // 1. rs-security-no-disabled-tls-verification through 8-hop let binding (b0..b6 -> b7 = 8 hops) and const
    let b0 = HttpClient::builder();
    let b1 = b0;
    let b2 = b1;
    let b3 = b2;
    let b4 = b3;
    let b5 = b4;
    let b6 = b5;
    let _client = b6.danger_accept_invalid_certs(ALLOW_INSECURE_TLS).build()?;

    // 2. rs-security-no-dynamic-shell-command (shell -c script + dynamic program)
    let mut sh_cmd = ProcCmd::new("/bin/bash");
    let script = format!("echo {user_arg}");
    let _ = sh_cmd.arg("-c").arg(script).status();
    let _ = ProcCmd::new(format!("/opt/{user_arg}/run")).status();

    // 3. rs-http-no-unchecked-response-status
    let resp = HttpClient::new().get(url).send().await?;
    let _body = resp.text().await?;

    // 4. rs-security-no-secret-env-fallback
    let _jwt_secret = read_env("JWT_SECRET").unwrap_or("super-secret-fallback-key".to_string());
    let _gh_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();

    // 5. rs-security-no-permissive-cors
    let _cors1 = CorsLayer::very_permissive();
    let _cors2 = actix_cors::Cors::permissive();
    let base_cors = CorsLayer::new().allow_origin(Any);
    let _cors3 = base_cors.allow_credentials(true);

    // 6. rs-security-no-insecure-auth-cookie
    let mut auth_cookie = HttpCookie::new("session_id", "xyz");
    auth_cookie.set_http_only(false);

    // 7. rs-security-no-disabled-jwt-validation
    let mut val = Validation::new(Algorithm::HS256);
    val.insecure_disable_signature_validation();
    let _ = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>("tok");

    Ok(())
}
"#;

    let rules = &[
        RuleId::RsSecurityNoDisabledTlsVerification,
        RuleId::RsSecurityNoDynamicShellCommand,
        RuleId::RsHttpNoUncheckedResponseStatus,
        RuleId::RsSecurityNoSecretEnvFallback,
        RuleId::RsSecurityNoPermissiveCors,
        RuleId::RsSecurityNoInsecureAuthCookie,
        RuleId::RsSecurityNoDisabledJwtValidation,
    ];
    let diags = analyze_source(Path::new("src/security_kernel.rs"), invalid_src, Some(rules));

    let count = |r: RuleId| diags.iter().filter(|d| d.rule == r).count();
    assert_eq!(count(RuleId::RsSecurityNoDisabledTlsVerification), 1, "{diags:#?}");
    assert_eq!(count(RuleId::RsSecurityNoDynamicShellCommand), 2, "{diags:#?}");
    assert_eq!(count(RuleId::RsHttpNoUncheckedResponseStatus), 1, "{diags:#?}");
    assert_eq!(count(RuleId::RsSecurityNoSecretEnvFallback), 2, "{diags:#?}");
    assert_eq!(count(RuleId::RsSecurityNoPermissiveCors), 3, "{diags:#?}");
    assert_eq!(count(RuleId::RsSecurityNoInsecureAuthCookie), 1, "{diags:#?}");
    assert_eq!(count(RuleId::RsSecurityNoDisabledJwtValidation), 2, "{diags:#?}");
    // Verify `rs-security-no-insecure-auth-cookie` autofix replaces `false` with `true`
    let cookie_diag = diags
        .iter()
        .find(|d| d.rule == RuleId::RsSecurityNoInsecureAuthCookie)
        .unwrap();
    assert!(cookie_diag.autofix.is_some());

    // Verify empty string fallback `unwrap_or("".to_string())` on secret env var is flagged
    let empty_secret_src = r#"
pub fn read_empty_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or("".to_string())
}
"#;
    assert_eq!(
        analyze_source(
            Path::new("src/secret.rs"),
            empty_secret_src,
            Some(&[RuleId::RsSecurityNoSecretEnvFallback]),
        )
        .len(),
        1
    );

    let valid_src = r#"
use reqwest::Client;
use std::process::Command;
use tower_http::cors::CorsLayer;
use cookie::Cookie;
use jsonwebtoken::{Algorithm, Validation};

pub async fn safe_security_and_http(
    user_arg: &str,
    secs: u32,
    url: &str,
    flag: bool,
    origin: http::HeaderValue,
) -> Option<String> {
    // 1. TLS verification enabled or reassigned binding abstains
    let _c1 = Client::builder().danger_accept_invalid_certs(false).build().ok()?;
    let mut dynamic_flag = true;
    dynamic_flag &= flag;
    let _c2 = Client::builder().danger_accept_invalid_certs(dynamic_flag).build().ok()?;

    // 2. Shell command with numeric arg or non-shell binary with dynamic arg
    let _ = Command::new("sh").arg("-c").arg(format!("sleep {secs}")).status();
    let _ = Command::new("git").arg("log").arg(format!("--author={user_arg}")).status();

    // 3. Checked HTTP status via error_for_status() and .status().is_success()
    let _t1 = Client::new().get(url).send().await.ok()?.error_for_status().ok()?.text().await.ok()?;
    let resp = Client::new().get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let _t2 = resp.text().await.ok()?;

    // 4. Non-secret env vars or placeholder fallbacks
    let _db = std::env::var("DATABASE_URL").unwrap_or("postgres://localhost/dev".to_string());
    let _hdr = std::env::var("API_KEY_HEADER").unwrap_or("x-api-key-header".to_string());
    let _placeholder = std::env::var("APP_SECRET").unwrap_or("changeme-now".to_string());

    // 5. Explicit origin CORS or permissive without credentials
    let _cors1 = CorsLayer::permissive();
    let _cors2 = CorsLayer::new().allow_origin(origin).allow_credentials(true);

    // 6. CSRF cookie or http_only(true) auth cookie
    let _csrf = Cookie::build(("csrf_session", "val")).http_only(false);
    let _auth = Cookie::build(("session_id", "val")).http_only(true);

    // 7. Standard JWT validation
    let _val = Validation::new(Algorithm::HS256);

    Some(_t2)
}
"#;
    let valid_diags = analyze_source(Path::new("src/security_valid.rs"), valid_src, Some(rules));
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on valid security/HTTP code, got: {valid_diags:#?}"
    );
}

#[test]
fn source_kernel_resolves_cargo_toml_dependency_renames() {
    let cargo_toml = r#"
[package]
name = "renamed-deps-app"
version = "0.1.0"

[dependencies]
http_client = { package = "reqwest", version = "0.12" }
"#;
    let lib_rs = r#"
pub fn build_insecure_client() {
    let _ = http_client::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
}
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_toml.to_string()),
            (PathBuf::from("src/lib.rs"), lib_rs.to_string()),
        ],
        Some(&[RuleId::RsSecurityNoDisabledTlsVerification]),
    );
    assert_eq!(
        report.diagnostics.len(),
        1,
        "Expected http_client -> reqwest rename in Cargo.toml to be resolved: {:#?}",
        report.diagnostics
    );
    assert_eq!(
        report.diagnostics[0].rule,
        RuleId::RsSecurityNoDisabledTlsVerification
    );
    // Verify `tokio_postgres` dependency rename is resolved for `rs-sqlx-no-formatted-query-string`
    let pg_cargo = r#"
[package]
name = "pg-renamed"
version = "0.1.0"

[dependencies]
pg_async = { package = "tokio-postgres", version = "0.7" }
"#;
    let pg_rs = r#"
pub async fn query_user(user: &str) {
    let client = pg_async::Client::connect("host=localhost", pg_async::NoTls).await.unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{user}'");
    let _ = client.query(&sql, &[]).await;
}
"#;
    let pg_report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), pg_cargo.to_string()),
            (PathBuf::from("src/lib.rs"), pg_rs.to_string()),
        ],
        Some(&[RuleId::RsSqlxNoFormattedQueryString]),
    );
    assert_eq!(
        pg_report.diagnostics.len(),
        1,
        "Expected pg_async -> tokio-postgres rename to be resolved: {:#?}",
        pg_report.diagnostics
    );
}

#[test]
fn source_kernel_abstains_past_8_hops_or_on_reassigned_and_shadowed_bindings() {
    let src = r#"
use std::process::Command;
use reqwest::Client;

pub fn abstains_on_indeterminate_bindings(user: &str, check: bool, param_cmd: &mut Command) {
    // 1. 9 hops (> 8-hop limit) abstains
    let h0 = Command::new("sh");
    let h1 = h0;
    let h2 = h1;
    let h3 = h2;
    let h4 = h3;
    let h5 = h4;
    let h6 = h5;
    let h7 = h6;
    let mut h8 = h7;
    let _ = h8.arg("-c").arg(format!("echo {user}"));

    // 2. Reassigned binding abstains
    let mut cmd = Command::new("sh");
    if check {
        cmd = Command::new("ls");
    }
    let _ = cmd.arg("-c").arg(format!("echo {user}"));

    // 3. Tuple destructuring pattern abstains
    let (mut tup_cmd, _) = (Command::new("sh"), 0);
    let _ = tup_cmd.arg("-c").arg(format!("echo {user}"));

    // 4. let-else pattern abstains
    let Some(mut some_cmd) = Some(Command::new("sh")) else {
        return;
    };
    let _ = some_cmd.arg("-c").arg(format!("echo {user}"));

    // 5. Shadowed in a branch between let and use abstains
    let mut sh_cmd = Command::new("sh");
    if check {
        let sh_cmd = 0;
        let _ = sh_cmd;
    }
    let _ = sh_cmd.arg("-c").arg(format!("echo {user}"));

    // 6. Parameter receiver abstains
    let _ = param_cmd.arg("-c").arg(format!("echo {user}"));

    // 7. Duplicate cfg consts abstain
    #[cfg(unix)]
    const INSECURE: bool = true;
    #[cfg(not(unix))]
    const INSECURE: bool = true;
    let _ = Client::builder().danger_accept_invalid_certs(INSECURE);
}
"#;
    let diags = analyze_source(
        Path::new("src/abstentions.rs"),
        src,
        Some(&[
            RuleId::RsSecurityNoDynamicShellCommand,
            RuleId::RsSecurityNoDisabledTlsVerification,
        ]),
    );
    assert!(
        diags.is_empty(),
        "Expected 0 diagnostics when bindings exceed 8 hops, are reassigned, or are shadowed: {diags:#?}"
    );
}

#[test]
fn eight_rust_structure_and_allow_hygiene_rules_detect_violations_and_autofix() {
    let mut oversized_fn = String::from("pub fn giant_function(mut x: i32) -> i32 {\n");
    for i in 0..155 {
        oversized_fn.push_str(&format!("    x = x.wrapping_add({i});\n"));
    }
    oversized_fn.push_str("    x\n}\n");

    let lib_rs = format!(
        r#"#![allow(dead_code, reason = "file-wide allow is still flagged by crate-level-allow")]
mod used_child;
#[allow(unused_variables)]
pub fn unreasoned_allow_fn(a: i32) -> i32 {{ 1 }}
#[allow(dead_code, reason = "a")]
#[allow(unused_variables, reason = "b")]
pub fn stacked_two_allows(x: i32) -> i32 {{ x }}
#[allow(dead_code, unused_variables, unused_mut, non_snake_case, reason = "four lints")]
pub fn stacked_wide_allow(mut X: i32) -> i32 {{ 1 }}
pub fn deeply_complex_logic(a: i32, b: i32, c: i32, d: i32) -> i32 {{
    let mut acc = 0;
    if a > 0 {{
        if b > 0 {{
            for i in 0..a {{
                if c > i && d > 0 {{
                    match i % 4 {{
                        0 => {{ if a > b {{ acc += 1; }} else {{ acc -= 1; }} }}
                        1 => {{ while acc < 10 {{ acc += 2; }} }}
                        _ => acc += 3,
                    }}
                }}
            }}
        }}
    }}
    acc
}}
#[cfg(feature = "undeclared_ghost_feature")]
pub fn ghost_gated() {{}}
pub fn clone_alpha(items: &[i64], scale: i64, offset: i64) -> i64 {{
    let mut total = 0;
    for item in items {{
        if *item > 0 {{
            let adjusted = (*item * scale) + offset;
            total += adjusted;
        }} else {{
            total -= offset;
        }}
    }}
    total
}}
{oversized_fn}"#
    );
    let used_child_rs = r#"pub fn clone_beta(values: &[i64], factor: i64, bias: i64) -> i64 {
    let mut sum = 0;
    for val in values {
        if *val > 0 {
            let scaled = (*val * factor) + bias;
            sum += scaled;
        } else {
            sum -= bias;
        }
    }
    sum
}"#;
    let cargo_toml = "[package]\nname = \"structure-suite\"\nversion = \"0.1.0\"\n[features]\ndefault = []\nunused_dead_feature = []\n";
    let structure_rules = [
        RuleId::RsStructureCrateLevelAllow,
        RuleId::RsStructureUnreasonedAllow,
        RuleId::RsStructureStackedAllow,
        RuleId::RsStructureComplexFunction,
        RuleId::RsStructureOversizedUnit,
        RuleId::RsStructureOrphanModuleFile,
        RuleId::RsStructureUnreferencedFeature,
        RuleId::RsStructureNearDuplicateFunction,
    ];
    let report = analyze_project_sources(
        vec![
            (PathBuf::from("Cargo.toml"), cargo_toml.to_string()),
            (PathBuf::from("src/lib.rs"), lib_rs.clone()),
            (PathBuf::from("src/used_child.rs"), used_child_rs.to_string()),
            (PathBuf::from("src/orphan_dead.rs"), "pub fn dead() {}\n".to_string()),
        ],
        Some(&structure_rules),
    );
    let count = |r: RuleId| report.diagnostics.iter().filter(|d| d.rule == r).count();
    assert_eq!(count(RuleId::RsStructureCrateLevelAllow), 1);
    assert_eq!(count(RuleId::RsStructureUnreasonedAllow), 1);
    assert_eq!(count(RuleId::RsStructureStackedAllow), 2);
    assert_eq!(count(RuleId::RsStructureComplexFunction), 1);
    assert_eq!(count(RuleId::RsStructureOversizedUnit), 1);
    assert_eq!(count(RuleId::RsStructureOrphanModuleFile), 1);
    assert_eq!(count(RuleId::RsStructureUnreferencedFeature), 2);
    assert!(count(RuleId::RsStructureNearDuplicateFunction) >= 1);
    let unreasoned = report.diagnostics.iter().find(|d| d.rule == RuleId::RsStructureUnreasonedAllow).unwrap();
    assert_eq!(unreasoned.tier, PrescriptionTier::Autofix);
    let (rewritten, applied) = dotore::apply_patches_to_source(&lib_rs, std::slice::from_ref(unreasoned));
    assert_eq!(applied.len(), 1);
    assert!(rewritten.contains("#[expect(unused_variables, reason = \"explain lint suppression\")]"));
}
