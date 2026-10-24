//! End-to-end polyglot monorepo integration tests for Ticket #18:
//! - Multi-manifest workspace package discovery and per-package Capability Gates
//! - Unified polyglot `analyze_project_sources` and filesystem `scan_workspace`
//! - Cross-language Fix Capsules, `plan_project`, and `explain_location` (`dotore why`)
//! - Cross-language `apply_patches_to_source` and `apply_autofixes` with syntax validation
//! - Multi-language `search_project_sources` / `search_symbols` and `build_rule_catalog`
//! - Git diff Contextual Owner filtering across `.tsx`, `.py`, and `.rs`
//! - 100% zero-stub rule parity across all 950 registered rules

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use dotore::{
    ArchitectureFileFacets, ArchitectureThresholdsConfig, AutofixPatch, ByteEdit, ByteSpan,
    Capability, ChangedFileLineRanges, ConcernBucket, ConcernSignalSite, DiffScope, DotoreConfig,
    HelperFingerprintIr, InlineTerminalUiPrimitiveSiteIr, JsLanguageAnalyzer, LanguageAnalyzer,
    LanguageId, PrescriptionTier, PyLanguageAnalyzer, RsLanguageAnalyzer, RuleId, RuleSeverity,
    RulesListOptions, ScanOptions, SearchOptions, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, SymbolKind, analyze_project_sources, analyze_source,
    apply_autofixes, apply_patches_to_source, build_rule_catalog, default_analyzers,
    discover_workspace_packages, explain_location, explain_rule, filter_diagnostics_by_scope,
    format_architecture_signal_explanation, format_search_json, format_search_text, plan_project,
    resolve_package_for_file, rule_registry, scan_workspace, search_project_sources,
    search_symbols,
};

#[test]
fn polyglot_default_analyzers_and_multi_manifest_workspace_discovery() {
    let analyzers = default_analyzers();
    assert_eq!(analyzers.len(), 3);
    let lang_ids: Vec<LanguageId> = analyzers.iter().map(|a| a.language_id()).collect();
    assert!(lang_ids.contains(&LanguageId::JavaScript));
    assert!(lang_ids.contains(&LanguageId::Python));
    assert!(lang_ids.contains(&LanguageId::Rust));

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-disc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);

    let frontend_dir = temp_dir.join("frontend");
    let react_dir = temp_dir.join("web-react");
    let py_api_dir = temp_dir.join("services/api");
    let rs_worker_dir = temp_dir.join("services/worker");

    fs::create_dir_all(&frontend_dir).unwrap();
    fs::create_dir_all(&react_dir).unwrap();
    fs::create_dir_all(&py_api_dir).unwrap();
    fs::create_dir_all(&rs_worker_dir).unwrap();

    // Polyglot root containing package.json, pyproject.toml, and Cargo.toml
    fs::write(
        temp_dir.join("package.json"),
        r#"{"name": "polyglot-root", "private": true, "dependencies": {"zod": "^4.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join("pyproject.toml"),
        "[project]\nname = \"polyglot-root-py\"\ndependencies = [\"pydantic>=2.0\"]\n",
    )
    .unwrap();
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[package]\nname = \"polyglot-root-rs\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"\n",
    )
    .unwrap();

    // Subpackage 1: Angular frontend
    fs::write(
        frontend_dir.join("package.json"),
        r#"{"name": "ng-frontend", "dependencies": {"@angular/core": "^19.0.0", "rxjs": "^7.8.0"}}"#,
    )
    .unwrap();
    fs::write(
        frontend_dir.join("angular.json"),
        r#"{"version": 1, "projects": {}}"#,
    )
    .unwrap();

    // Subpackage 2: React web app
    fs::write(
        react_dir.join("package.json"),
        r#"{"name": "web-react", "dependencies": {"react": "^19.0.0", "next": "^15.0.0"}}"#,
    )
    .unwrap();

    // Subpackage 3: Python FastAPI + SQLAlchemy + Pytest service
    fs::write(
        py_api_dir.join("pyproject.toml"),
        "[project]\nname = \"api-service\"\ndependencies = [\"fastapi>=0.115.0\", \"pydantic>=2.9.0\", \"sqlalchemy>=2.0.0\"]\n",
    )
    .unwrap();
    fs::write(
        py_api_dir.join("requirements.txt"),
        "pytest>=8.0.0\nhttpx>=0.27.0\n",
    )
    .unwrap();

    // Subpackage 4: Rust Tokio + Axum + SQLx worker
    fs::write(
        rs_worker_dir.join("Cargo.toml"),
        "[package]\nname = \"worker-service\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1.40\"\naxum = \"0.8\"\nsqlx = \"0.8\"\nleptos = \"0.7\"\n",
    )
    .unwrap();

    let packages = discover_workspace_packages(&temp_dir);
    assert_eq!(
        packages.len(),
        5,
        "Expected root + 4 subpackages, got: {packages:#?}"
    );

    // Root package merges JS (Zod), Python (Pydantic), and Rust (Serde) capabilities
    let root_pkg = packages.iter().find(|p| p.root_dir == temp_dir).unwrap();
    assert!(root_pkg.capability_gate.has(Capability::Zod));
    assert!(root_pkg.capability_gate.has(Capability::Python));
    assert!(root_pkg.capability_gate.has(Capability::Pydantic));
    assert!(root_pkg.capability_gate.has(Capability::Rust));
    assert!(root_pkg.capability_gate.has(Capability::Serde));

    // Angular package
    let ng_pkg =
        resolve_package_for_file(&frontend_dir.join("src/app.component.ts"), &packages).unwrap();
    assert_eq!(ng_pkg.root_dir, frontend_dir);
    assert!(ng_pkg.capability_gate.has(Capability::Angular));
    assert!(ng_pkg.capability_gate.has(Capability::Rxjs));
    assert!(!ng_pkg.capability_gate.has(Capability::React));
    assert!(!ng_pkg.capability_gate.has(Capability::Python));
    assert!(!ng_pkg.capability_gate.has(Capability::Rust));

    // React package
    let react_pkg = resolve_package_for_file(&react_dir.join("src/App.tsx"), &packages).unwrap();
    assert_eq!(react_pkg.root_dir, react_dir);
    assert!(react_pkg.capability_gate.has(Capability::React));
    assert!(react_pkg.capability_gate.has(Capability::Nextjs));
    assert!(!react_pkg.capability_gate.has(Capability::Angular));

    // Python API package
    let py_pkg = resolve_package_for_file(&py_api_dir.join("app/routes.py"), &packages).unwrap();
    assert_eq!(py_pkg.root_dir, py_api_dir);
    assert!(py_pkg.capability_gate.has(Capability::Python));
    assert!(py_pkg.capability_gate.has(Capability::FastApi));
    assert!(py_pkg.capability_gate.has(Capability::Pydantic));
    assert!(py_pkg.capability_gate.has(Capability::SqlAlchemy));
    assert!(py_pkg.capability_gate.has(Capability::Pytest));
    assert!(py_pkg.capability_gate.has(Capability::Asyncio));
    assert!(!py_pkg.capability_gate.has(Capability::React));
    assert!(!py_pkg.capability_gate.has(Capability::Rust));

    // Rust worker package
    let rs_pkg = resolve_package_for_file(&rs_worker_dir.join("src/lib.rs"), &packages).unwrap();
    assert_eq!(rs_pkg.root_dir, rs_worker_dir);
    assert!(rs_pkg.capability_gate.has(Capability::Rust));
    assert!(rs_pkg.capability_gate.has(Capability::Tokio));
    assert!(rs_pkg.capability_gate.has(Capability::Axum));
    assert!(rs_pkg.capability_gate.has(Capability::Sqlx));
    assert!(rs_pkg.capability_gate.has(Capability::Leptos));
    assert!(!rs_pkg.capability_gate.has(Capability::React));
    assert!(!rs_pkg.capability_gate.has(Capability::Python));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn polyglot_monorepo_analyze_project_sources_and_scan_workspace_unify_packages_and_scores() {
    let files: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("frontend/package.json"),
            r#"{"name": "ng-frontend", "dependencies": {"@angular/core": "^19.0.0", "rxjs": "^7.8.0"}}"#
                .to_string(),
        ),
        (
            PathBuf::from("frontend/src/user.component.ts"),
            r#"import { Component, effect, signal } from '@angular/core';

@Component({
    selector: 'app-user',
    template: `<div>{{ fullName() }}</div>`
})
export class UserComponent {
    firstName = signal('Ada');
    lastName = signal('Lovelace');
    fullName = signal('');

    constructor() {
        effect(() => {
            this.fullName.set(this.firstName() + ' ' + this.lastName());
        });
    }
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("frontend/src/clean.component.ts"),
            r#"import { ChangeDetectionStrategy, Component, computed, signal } from '@angular/core';

@Component({
    selector: 'app-clean',
    changeDetection: ChangeDetectionStrategy.OnPush,
    template: `<span>{{ label() }}</span>`
})
export class CleanComponent {
    raw = signal('ok');
    label = computed(() => this.raw().toUpperCase());
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web-react/package.json"),
            r#"{"name": "web-react", "dependencies": {"react": "^19.0.0"}}"#.to_string(),
        ),
        (
            PathBuf::from("web-react/src/Profile.tsx"),
            r#"import { useState, useEffect } from 'react';

export function ProfileCard({ first, last }: { first: string; last: string }) {
    const [fullName, setFullName] = useState('');
    useEffect(() => {
        setFullName(`${first} ${last}`);
    }, [first, last]);
    return <div>{fullName}</div>;
}

export function CleanBadge({ title }: { title: string }) {
    return <span>{title.trim()}</span>;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/pyproject.toml"),
            r#"[project]
name = "backend-py"
dependencies = ["fastapi>=0.115.0", "pydantic>=2.9.0", "sqlalchemy>=2.0.0"]
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/app.py"),
            r#"import time
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import select
from unused_mod import used_helper

app = FastAPI()

class CreateOrderPayload(BaseModel):
    tags: list[str] = []

@app.post("/orders")
async def create_order(payload: CreateOrderPayload, session, order_ids: list[int]) -> dict[str, int]:
    time.sleep(0.1)
    for oid in order_ids:
        session.execute(select(oid))
    return {"count": used_helper(len(payload.tags))}

def clean_python_helper(values: list[int]) -> int:
    return sum(values)
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/unused_mod.py"),
            r#"def used_helper(x: int) -> int:
    return x + 1

def dead_export_fn(x: int) -> int:
    return x * 2
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/Cargo.toml"),
            r#"[package]
name = "backend-rs"
version = "0.1.0"

[dependencies]
tokio = "1.40"
axum = "0.8"
sqlx = "0.8"
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/src/lib.rs"),
            r#"mod helper;

use std::sync::Mutex;
use std::time::Duration;

pub async fn process_order(lock: &Mutex<u64>, pool: &sqlx::PgPool, user_id: &str) {
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::sleep(Duration::from_millis(10));
    let sql = format!("SELECT * FROM orders WHERE user_id = '{}'", user_id);
    let _ = sqlx::query(&sql).execute(pool).await;
    drop(guard);
    let _ = helper::used_internal(1);
}

pub fn clean_rust_subject(x: u32) -> u32 {
    x.saturating_add(1)
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/src/helper.rs"),
            r#"pub(crate) fn used_internal(x: u32) -> u32 {
    x + 1
}

pub(crate) fn unused_internal_helper(x: u32) -> u32 {
    x + 2
}
"#
            .to_string(),
        ),
    ];

    let in_memory_report = analyze_project_sources(files.clone(), None);

    // Verify all 7 source files across Angular (.ts), React (.tsx), Python (.py), and Rust (.rs) were scanned
    assert_eq!(in_memory_report.summary.files_scanned, 7);
    assert_eq!(in_memory_report.projects.len(), 4);

    let mem_rules: Vec<RuleId> = in_memory_report
        .diagnostics
        .iter()
        .map(|d| d.rule)
        .collect();
    // Angular diagnostics
    assert!(mem_rules.contains(&RuleId::AngularNoSignalWriteInEffect));
    assert!(mem_rules.contains(&RuleId::AngularPreferOnPushChangeDetection));
    // React diagnostics
    assert!(mem_rules.contains(&RuleId::NoDerivedState));
    // Python diagnostics (including cross-file unused export)
    assert!(mem_rules.contains(&RuleId::PyAsyncNoBlockingCall));
    assert!(mem_rules.contains(&RuleId::PyPydanticPreferDefaultFactory));
    assert!(mem_rules.contains(&RuleId::PyOrmNoQueryInLoop));
    assert!(mem_rules.contains(&RuleId::PyFastapiMutatingRouteRequiresAuth));
    assert!(mem_rules.contains(&RuleId::PyArchNoUnusedExports));
    // Rust diagnostics (including cross-file pub(crate) unused item)
    assert!(mem_rules.contains(&RuleId::RsTokioNoStdLockAcrossAwait));
    assert!(mem_rules.contains(&RuleId::RsTokioNoBlockingInAsync));
    assert!(mem_rules.contains(&RuleId::RsSqlxNoFormattedQueryString));
    assert!(
        mem_rules.contains(&RuleId::RsArchNoUnusedPubCrateItems),
        "Expected crate-level RsArchNoUnusedPubCrateItems in polyglot run, got: {mem_rules:?}"
    );

    // Write same polyglot monorepo to disk and run `scan_workspace`
    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-scan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    for (rel_path, content) in &files {
        let full_path = temp_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full_path, content).unwrap();
    }

    let (disk_report, disk_sources) = scan_workspace(&ScanOptions {
        paths: vec![temp_dir.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();

    assert_eq!(disk_sources.len(), 7);
    assert_eq!(disk_report.summary.files_scanned, 7);
    assert_eq!(disk_report.projects.len(), 4);
    assert_eq!(
        disk_report.summary.total_diagnostics,
        in_memory_report.summary.total_diagnostics
    );
    assert_eq!(
        disk_report.summary.health_score,
        in_memory_report.summary.health_score
    );

    let disk_rules: Vec<RuleId> = disk_report.diagnostics.iter().map(|d| d.rule).collect();
    assert!(disk_rules.contains(&RuleId::AngularNoSignalWriteInEffect));
    assert!(disk_rules.contains(&RuleId::NoDerivedState));
    assert!(disk_rules.contains(&RuleId::PyAsyncNoBlockingCall));
    assert!(disk_rules.contains(&RuleId::PyArchNoUnusedExports));
    assert!(disk_rules.contains(&RuleId::RsTokioNoStdLockAcrossAwait));
    assert!(disk_rules.contains(&RuleId::RsArchNoUnusedPubCrateItems));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn polyglot_fix_capsules_plan_project_and_explain_location_across_ts_py_and_rs() {
    let files: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("frontend/package.json"),
            r#"{"name": "ng-frontend", "dependencies": {"@angular/core": "^19.0.0", "rxjs": "^7.8.0"}}"#
                .to_string(),
        ),
        (
            PathBuf::from("frontend/src/user.component.ts"),
            r#"import { ChangeDetectionStrategy, Component, effect, signal } from '@angular/core';

@Component({
    selector: 'app-user',
    changeDetection: ChangeDetectionStrategy.OnPush,
    template: `<div>{{ fullName() }}</div>`
})
export class UserComponent {
    firstName = signal('Ada');
    lastName = signal('Lovelace');
    fullName = signal('');

    constructor() {
        effect(() => {
            this.fullName.set(this.firstName() + ' ' + this.lastName());
        });
    }
}

@Component({
    selector: 'app-clean',
    changeDetection: ChangeDetectionStrategy.OnPush,
    template: `<span>{{ label() }}</span>`
})
export class CleanComponent {
    raw = signal('ok');
    label = signal('ready');
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/pyproject.toml"),
            r#"[project]
name = "backend-py"
dependencies = ["fastapi>=0.115.0", "pydantic>=2.9.0", "sqlalchemy>=2.0.0"]
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/app.py"),
            r#"import time

async def sync_inventory(sku: str) -> str:
    time.sleep(0.2)
    return sku

def suppressed_broad_except(raw: str) -> int:
    try:
        return int(raw)
    # dotore-disable-next-line py-no-silent-broad-except
    except Exception:
        pass
    return 0

def clean_python_subject(items: list[int]) -> int:
    return sum(items)
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/Cargo.toml"),
            r#"[package]
name = "backend-rs"
version = "0.1.0"

[dependencies]
tokio = "1.40"
sqlx = "0.8"
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/src/lib.rs"),
            r#"use std::sync::Mutex;

pub async fn settle_ledger(lock: &Mutex<u64>, pool: &sqlx::PgPool) {
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let _ = sqlx::query("SELECT 1").execute(pool).await;
    drop(guard);
}

pub fn suppressed_unwrap_fn(opt: Option<u32>) -> u32 {
    // dotore-disable-next-line rs-no-unwrap-in-production
    opt.unwrap()
}

pub fn clean_rust_subject(val: u32) -> u32 {
    val.saturating_add(1)
}
"#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(files.clone(), None);

    // 1. Verify Fix Capsules exist for Angular, Python, and Rust Surgical Root-Cause Groups
    let ng_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::AngularNoSignalWriteInEffect)
        .expect("Expected Angular FixCapsule");
    assert_eq!(
        ng_capsule.subject_excerpt.file,
        Path::new("frontend/src/user.component.ts")
    );
    assert!(
        ng_capsule
            .subject_excerpt
            .source
            .contains("export class UserComponent")
    );
    let ng_ex = ng_capsule
        .exemplar
        .as_ref()
        .expect("Expected TS/Angular exemplar");
    assert_eq!(ng_ex.file, Path::new("frontend/src/user.component.ts"));
    assert!(ng_ex.source.contains("CleanComponent"));

    let py_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::PyAsyncNoBlockingCall)
        .expect("Expected Python FixCapsule");
    assert_eq!(
        py_capsule.subject_excerpt.file,
        Path::new("backend-py/app.py")
    );
    assert!(
        py_capsule
            .subject_excerpt
            .source
            .contains("async def sync_inventory")
    );
    let py_ex = py_capsule
        .exemplar
        .as_ref()
        .expect("Expected Python exemplar");
    assert_eq!(py_ex.file, Path::new("backend-py/app.py"));
    assert!(
        py_ex.source.contains("def suppressed_broad_except")
            || py_ex.source.contains("def clean_python_subject")
    );

    let rs_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::RsTokioNoStdLockAcrossAwait)
        .expect("Expected Rust FixCapsule");
    assert_eq!(
        rs_capsule.subject_excerpt.file,
        Path::new("backend-rs/src/lib.rs")
    );
    assert!(
        rs_capsule
            .subject_excerpt
            .source
            .contains("pub async fn settle_ledger")
    );
    let rs_ex = rs_capsule
        .exemplar
        .as_ref()
        .expect("Expected Rust exemplar");
    assert_eq!(rs_ex.file, Path::new("backend-rs/src/lib.rs"));
    assert!(
        rs_ex.source.contains("pub fn suppressed_unwrap_fn")
            || rs_ex.source.contains("pub fn clean_rust_subject")
    );

    // 2. Verify `plan_project` writes Markdown plans with `tsx`, `python`, and `rust` code fences
    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-plan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    let plan_dir = temp_dir.join("plans");
    let plan_res = plan_project(&report, &plan_dir).unwrap();
    assert!(plan_res.index_file.is_file());
    assert!(plan_res.plan_files.len() >= 3);

    let readme_md = fs::read_to_string(&plan_res.index_file).unwrap();
    assert!(readme_md.contains("angular-no-signal-write-in-effect"));
    assert!(readme_md.contains("py-async-no-blocking-call"));
    assert!(readme_md.contains("rs-tokio-no-std-lock-across-await"));

    let all_plans_md: String = plan_res
        .plan_files
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(all_plans_md.contains("```tsx\n"));
    assert!(all_plans_md.contains("```python\n"));
    assert!(all_plans_md.contains("```rust\n"));

    // 3. Verify `explain_location` (`dotore why file:line`) across `.ts`, `.py`, and `.rs`
    for (rel_path, content) in &files {
        let full_path = temp_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full_path, content).unwrap();
    }

    let ng_why = explain_location("frontend/src/user.component.ts:15", &temp_dir).unwrap();
    assert!(
        ng_why
            .entries
            .iter()
            .any(|e| e.status == "active" && e.rule == "dotore/angular-no-signal-write-in-effect"),
        "Expected active angular-no-signal-write-in-effect in ng_why: {ng_why:#?}"
    );

    let py_active_why = explain_location("backend-py/app.py:4", &temp_dir).unwrap();
    assert!(
        py_active_why
            .entries
            .iter()
            .any(|e| e.status == "active" && e.rule == "dotore/py-async-no-blocking-call"),
        "Expected active py-async-no-blocking-call in py_active_why: {py_active_why:#?}"
    );

    let py_supp_why = explain_location("backend-py/app.py:11", &temp_dir).unwrap();
    assert!(
        py_supp_why
            .entries
            .iter()
            .any(|e| e.status == "suppressed" && e.rule == "dotore/py-no-silent-broad-except"),
        "Expected suppressed py-no-silent-broad-except in py_supp_why: {py_supp_why:#?}"
    );

    let rs_active_why = explain_location("backend-rs/src/lib.rs:4", &temp_dir).unwrap();
    assert!(
        rs_active_why
            .entries
            .iter()
            .any(|e| e.status == "active" && e.rule == "dotore/rs-tokio-no-std-lock-across-await"),
        "Expected active rs-tokio-no-std-lock-across-await in rs_active_why: {rs_active_why:#?}"
    );

    let rs_supp_why = explain_location("backend-rs/src/lib.rs:11", &temp_dir).unwrap();
    assert!(
        rs_supp_why
            .entries
            .iter()
            .any(|e| e.status == "suppressed" && e.rule == "dotore/rs-no-unwrap-in-production"),
        "Expected suppressed rs-no-unwrap-in-production in rs_supp_why: {rs_supp_why:#?}"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn polyglot_autofix_round_trips_and_syntax_validation_across_ts_py_and_rs() {
    let ng_src = r#"import { Component } from '@angular/core';

@Component({
    selector: 'app-card',
    template: `<div>Card</div>`
})
export class CardComponent {}
"#;
    let py_src = r#"from datetime import datetime, timezone
import yaml
from pydantic import BaseModel

class ConfigModel(BaseModel):
    items: list[str] = []

def build_batch(batch: list[str] = []) -> dict:
    now = datetime.now()
    data = yaml.load("a: 1")
    return {"now": now, "data": data, "count": len(batch)}
"#;
    let rs_src = r#"use std::time::Duration;

pub async fn delay_worker() {
    std::thread::sleep(Duration::from_millis(25));
}
"#;

    let temp_dir = std::env::temp_dir().join(format!("dotore-polyglot-fix-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    let ng_dir = temp_dir.join("frontend");
    let py_dir = temp_dir.join("backend-py");
    let rs_dir = temp_dir.join("backend-rs");
    fs::create_dir_all(ng_dir.join("src")).unwrap();
    fs::create_dir_all(&py_dir).unwrap();
    fs::create_dir_all(rs_dir.join("src")).unwrap();

    fs::write(
        ng_dir.join("package.json"),
        r#"{"name": "ng", "dependencies": {"@angular/core": "^19.0.0"}}"#,
    )
    .unwrap();
    let ng_file = ng_dir.join("src/card.component.ts");
    fs::write(&ng_file, ng_src).unwrap();

    fs::write(
        py_dir.join("pyproject.toml"),
        "[project]\nname = \"py\"\ndependencies = [\"pydantic>=2.0\"]\n",
    )
    .unwrap();
    let py_file = py_dir.join("service.py");
    fs::write(&py_file, py_src).unwrap();

    fs::write(
        rs_dir.join("Cargo.toml"),
        "[package]\nname = \"rs\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1.40\"\n",
    )
    .unwrap();
    let rs_file = rs_dir.join("src/lib.rs");
    fs::write(&rs_file, rs_src).unwrap();

    let autofix_rules = vec![
        RuleId::AngularPreferOnPushChangeDetection,
        RuleId::PyPydanticPreferDefaultFactory,
        RuleId::PyNoMutableDefaultArg,
        RuleId::PyRequireTimezoneAwareDatetime,
        RuleId::PySecurityNoUnsafeDeserializationOrShell,
        RuleId::RsTokioNoBlockingInAsync,
    ];
    let (report, sources) = scan_workspace(&ScanOptions {
        paths: vec![temp_dir.clone()],
        include_tests: false,
        rules: Some(autofix_rules.clone()),
        tiers: None,
    })
    .unwrap();

    assert_eq!(report.diagnostics.len(), 6);

    let fix_results = apply_autofixes(&report.diagnostics, &sources, false).unwrap();
    assert_eq!(
        fix_results.len(),
        3,
        "Expected fixes across .ts, .py, and .rs"
    );

    let fixed_ng = fs::read_to_string(&ng_file).unwrap();
    let fixed_py = fs::read_to_string(&py_file).unwrap();
    let fixed_rs = fs::read_to_string(&rs_file).unwrap();

    assert!(JsLanguageAnalyzer.validate_syntax(&ng_file, &fixed_ng));
    assert!(PyLanguageAnalyzer.validate_syntax(&py_file, &fixed_py));
    assert!(RsLanguageAnalyzer.validate_syntax(&rs_file, &fixed_rs));

    assert!(fixed_ng.contains("ChangeDetectionStrategy.OnPush"));
    assert!(fixed_py.contains("Field(default_factory=list)"));
    assert!(fixed_py.contains("batch: list[str] = None") && fixed_py.contains("if batch is None:"));
    assert!(fixed_py.contains("datetime.now(timezone.utc)"));
    assert!(fixed_py.contains("yaml.safe_load("));
    assert!(fixed_rs.contains("tokio::time::sleep(Duration::from_millis(25)).await"));

    // Re-scanning after `apply_autofixes` yields 0 remaining diagnostics for those rules
    let (rescan_report, _) = scan_workspace(&ScanOptions {
        paths: vec![temp_dir.clone()],
        include_tests: false,
        rules: Some(autofix_rules),
        tiers: None,
    })
    .unwrap();
    assert!(
        rescan_report.diagnostics.is_empty(),
        "Expected 0 remaining autofixable diagnostics after round-trip, got: {:#?}",
        rescan_report.diagnostics
    );

    // Verify `apply_patches_to_source` rejects malformed syntax edits in TS, Python, and Rust
    for (path_str, valid_code, broken_replacement) in [
        (
            "src/card.ts",
            "export const x = 1;\n",
            "export const x = (((;\n",
        ),
        (
            "src/app.py",
            "def f():\n    return 1\n",
            "def f(:\n    return\n",
        ),
        (
            "src/lib.rs",
            "pub fn f() -> i32 { 1 }\n",
            "pub fn f() -> { {{{ }\n",
        ),
    ] {
        let mut fake_diag = report.diagnostics[0].clone();
        fake_diag.file = PathBuf::from(path_str);
        fake_diag.tier = PrescriptionTier::Autofix;
        fake_diag.autofix = Some(AutofixPatch {
            description: "malformed replacement".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan {
                    start: 0,
                    end: u32::try_from(valid_code.len()).unwrap(),
                },
                replacement: broken_replacement.to_string(),
            }],
        });
        let (after, applied) = apply_patches_to_source(valid_code, &[fake_diag]);
        assert!(
            applied.is_empty(),
            "Expected malformed edit for {path_str} to be rejected by validate_syntax"
        );
        assert_eq!(after, valid_code);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn polyglot_symbol_search_and_rule_catalog_across_ts_py_and_rs() {
    let files: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("frontend/src/OrderDashboard.tsx"),
            r#"/** Renders the interactive order dashboard component. */
export function OrderDashboard({ tenantId }: { tenantId: string }) {
    return <div>{tenantId}</div>;
}

export interface OrderFilterSpec {
    status: string;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-py/order_service.py"),
            r#"class OrderProcessor:
    """Processes incoming customer orders in Python."""
    def validate_order_total(self, cents: int) -> bool:
        return cents > 0

async def dispatch_order_webhook(order_id: str) -> None:
    pass
"#
            .to_string(),
        ),
        (
            PathBuf::from("backend-rs/src/order_engine.rs"),
            r#"/// High-throughput Rust order matching state.
pub struct OrderBookEngine {
    pub capacity: usize,
}

pub trait OrderValidator {
    fn verify_order(&self, id: u64) -> bool;
}

pub fn execute_order_match(id: u64) -> bool {
    id > 0
}
"#
            .to_string(),
        ),
    ];

    // 1. In-memory `search_project_sources` across `.tsx`, `.py`, and `.rs`
    let hits = search_project_sources("Order", &files, None, 20);
    let hit_names: Vec<&str> = hits.iter().map(|h| h.outline.name.as_str()).collect();
    assert!(hit_names.contains(&"OrderDashboard"));
    assert!(hit_names.contains(&"OrderFilterSpec"));
    assert!(hit_names.contains(&"OrderProcessor"));
    assert!(hit_names.contains(&"validate_order_total"));
    assert!(hit_names.contains(&"dispatch_order_webhook"));
    assert!(hit_names.contains(&"OrderBookEngine"));
    assert!(hit_names.contains(&"OrderValidator"));
    assert!(hit_names.contains(&"execute_order_match"));

    // Verify Struct and Trait kind filtering works across languages
    let struct_hits = search_project_sources("Order", &files, Some(&[SymbolKind::Struct]), 10);
    let struct_names: Vec<&str> = struct_hits
        .iter()
        .map(|h| h.outline.name.as_str())
        .collect();
    assert!(struct_names.contains(&"OrderProcessor"));
    assert!(struct_names.contains(&"OrderBookEngine"));

    let trait_hits = search_project_sources("Order", &files, Some(&[SymbolKind::Trait]), 10);
    let trait_names: Vec<&str> = trait_hits.iter().map(|h| h.outline.name.as_str()).collect();
    assert!(trait_names.contains(&"OrderFilterSpec"));
    assert!(trait_names.contains(&"OrderValidator"));

    // 2. Filesystem `search_symbols` and text/JSON formatting
    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-search-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    for (rel_path, content) in &files {
        let full_path = temp_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full_path, content).unwrap();
    }

    let (fs_hits, fs_sources) = search_symbols(
        "Order",
        &SearchOptions {
            paths: vec![temp_dir.clone()],
            kinds: None,
            limit: 20,
            include_tests: false,
        },
    )
    .unwrap();
    assert_eq!(fs_hits.len(), hits.len());

    let text_out = format_search_text(&fs_hits, &fs_sources, false);
    assert!(text_out.contains("```tsx\n"));
    assert!(text_out.contains("```py\n"));
    assert!(text_out.contains("```rs\n"));

    let json_out = format_search_json("Order", ".", &fs_hits);
    assert_eq!(json_out.count, fs_hits.len());
    let _ = fs::remove_dir_all(&temp_dir);

    // 3. Verify `build_rule_catalog` and `explain_rule` support all language & ecosystem frameworks
    let cfg = DotoreConfig::default();
    let all_catalog = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert_eq!(all_catalog.len(), 976);

    for (fw, expected_rule_id) in [
        ("angular", "angular-no-signal-write-in-effect"),
        ("rxjs", "angular-rxjs-subscribe-requires-teardown"),
        ("python", "py-no-mutable-default-arg"),
        ("fastapi", "py-fastapi-mutating-route-requires-auth"),
        ("pydantic", "py-pydantic-prefer-default-factory"),
        ("sqlalchemy", "py-orm-no-query-in-loop"),
        ("rust", "rs-no-unwrap-in-production"),
        ("tokio", "rs-tokio-no-std-lock-across-await"),
        ("axum", "rs-axum-no-contended-mutex-state"),
        ("sqlx", "rs-sqlx-no-formatted-query-string"),
        ("leptos", "rs-ui-no-derived-signal-in-effect"),
    ] {
        let filtered = build_rule_catalog(
            &cfg,
            &RulesListOptions {
                framework: Some(fw.to_string()),
                ..RulesListOptions::default()
            },
        );
        assert!(
            filtered.iter().any(|e| e.id == expected_rule_id),
            "Expected Capability Gate catalog filter `{fw}` to include `{expected_rule_id}`, got: {:?}",
            filtered.iter().map(|e| &e.id).collect::<Vec<_>>()
        );
        let explained = explain_rule(expected_rule_id, &cfg).unwrap();
        assert_eq!(explained.id, expected_rule_id);
    }
}

#[test]
fn polyglot_contextual_owner_diff_filtering_across_tsx_py_and_rs() {
    let tsx_path = PathBuf::from("frontend/src/App.tsx");
    let tsx_src = r#"import { useState, useEffect } from 'react';

export function TouchedComponent({ a }: { a: string }) {
    const [val, setVal] = useState('');
    // modified comment on line 5
    useEffect(() => {
        setVal(a.trim());
    }, [a]);
    return <div>{val}</div>;
}

export function UntouchedComponent({ b }: { b: string }) {
    const [other, setOther] = useState('');
    useEffect(() => {
        setOther(b.trim());
    }, [b]);
    return <div>{other}</div>;
}
"#;

    let py_path = PathBuf::from("backend-py/app.py");
    let py_src = r#"import time

async def touched_handler(x: int) -> int:
    y = x + 1
    time.sleep(0.1)
    return y

async def untouched_handler(x: int) -> int:
    z = x + 2
    time.sleep(0.1)
    return z
"#;

    let rs_path = PathBuf::from("backend-rs/src/lib.rs");
    let rs_src = r#"pub fn touched_rust_fn(opt: Option<u32>) -> u32 {
    let offset = 10;
    opt.unwrap() + offset
}

pub fn untouched_rust_fn(opt: Option<u32>) -> u32 {
    let base = 20;
    opt.unwrap() + base
}
"#;

    let extracted = vec![
        JsLanguageAnalyzer.extract_file(&tsx_path, tsx_src),
        PyLanguageAnalyzer.extract_file(&py_path, py_src),
        RsLanguageAnalyzer.extract_file(&rs_path, rs_src),
    ];

    let mut diagnostics = Vec::new();
    diagnostics.extend(analyze_source(
        &tsx_path,
        tsx_src,
        Some(&[RuleId::NoDerivedState]),
    ));
    diagnostics.extend(analyze_source(
        &py_path,
        py_src,
        Some(&[RuleId::PyAsyncNoBlockingCall]),
    ));
    diagnostics.extend(analyze_source(
        &rs_path,
        rs_src,
        Some(&[RuleId::RsNoUnwrapInProduction]),
    ));
    assert_eq!(
        diagnostics.len(),
        6,
        "Expected 2 findings per language before diff filter"
    );

    let mut sources = HashMap::new();
    sources.insert(tsx_path.clone(), tsx_src.to_string());
    sources.insert(py_path.clone(), py_src.to_string());
    sources.insert(rs_path.clone(), rs_src.to_string());

    // Touch only a non-diagnostic line inside the first function/component of each file:
    // - `frontend/src/App.tsx` line 5 (inside `TouchedComponent`, mentre `useEffect` is on lines 6-8)
    // - `backend-py/app.py` line 4 (inside `touched_handler`, while `time.sleep` is on line 5)
    // - `backend-rs/src/lib.rs` line 2 (inside `touched_rust_fn`, while `opt.unwrap()` is on line 3)
    let changed_files = vec![tsx_path.clone(), py_path.clone(), rs_path.clone()];
    let line_ranges = vec![
        ChangedFileLineRanges {
            file: tsx_path,
            ranges: vec![(5, 5)],
            deletion_lines: Vec::new(),
        },
        ChangedFileLineRanges {
            file: py_path,
            ranges: vec![(4, 4)],
            deletion_lines: Vec::new(),
        },
        ChangedFileLineRanges {
            file: rs_path,
            ranges: vec![(2, 2)],
            deletion_lines: Vec::new(),
        },
    ];

    // Under `DiffScope::Lines`, none of the diagnostics sit directly on the modified comment/variable lines
    let lines_only = filter_diagnostics_by_scope(
        diagnostics.clone(),
        DiffScope::Lines,
        Path::new("."),
        &changed_files,
        &line_ranges,
        &extracted,
        &sources,
    );
    assert!(
        lines_only.is_empty(),
        "Expected DiffScope::Lines to exclude diagnostics on untouched lines, got: {lines_only:#?}"
    );

    // Under `DiffScope::Contextual`, the enclosing Subject owns the modified line in all 3 languages!
    let contextual = filter_diagnostics_by_scope(
        diagnostics,
        DiffScope::Contextual,
        Path::new("."),
        &changed_files,
        &line_ranges,
        &extracted,
        &sources,
    );
    assert_eq!(contextual.len(), 3);
    let subjects: Vec<Option<&str>> = contextual
        .iter()
        .map(|d| d.subject_name.as_deref())
        .collect();
    assert!(subjects.contains(&Some("TouchedComponent")));
    assert!(subjects.contains(&Some("touched_handler")));
    assert!(subjects.contains(&Some("touched_rust_fn")));
    assert!(!subjects.contains(&Some("UntouchedComponent")));
    assert!(!subjects.contains(&Some("untouched_handler")));
    assert!(!subjects.contains(&Some("untouched_rust_fn")));
}

#[test]
fn polyglot_zero_stub_rule_parity_across_all_950_registered_rules() {
    let registry = rule_registry();
    assert_eq!(
        registry.len(),
        976,
        "Expected 976 total rules (928 React/TS/universal + 7 Angular + 19 Python + 22 Rust)"
    );

    let angular_count = registry
        .iter()
        .filter(|m| m.canonical_id.starts_with("angular-"))
        .count();
    let py_count = registry
        .iter()
        .filter(|m| m.canonical_id.starts_with("py-"))
        .count();
    let rs_count = registry
        .iter()
        .filter(|m| m.canonical_id.starts_with("rs-"))
        .count();
    let js_react_count = registry.len() - angular_count - py_count - rs_count;

    assert_eq!(js_react_count, 928, "Expected 928 React/TS/universal rules");
    assert_eq!(angular_count, 7, "Expected 7 Angular rules");
    assert_eq!(py_count, 19, "Expected 19 Python rules");
    assert_eq!(rs_count, 22, "Expected 22 Rust rules");

    // Collect all detector source text across `crates/dotore-js/src`, `crates/dotore-py/src`, and `crates/dotore-rs/src`
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut detector_corpus = String::new();
    for crate_src in [
        workspace_root.join("crates/dotore-js/src"),
        workspace_root.join("crates/dotore-py/src"),
        workspace_root.join("crates/dotore-rs/src"),
    ] {
        append_rs_sources_recursively(&crate_src, &mut detector_corpus);
    }

    for meta in registry {
        assert!(
            !meta.title.trim().is_empty(),
            "Empty title for {}",
            meta.canonical_id
        );
        assert!(
            !meta.recipe_markdown.trim().is_empty(),
            "Empty recipe_markdown for {}",
            meta.canonical_id
        );
        assert!(
            meta.docs_url.starts_with("https://"),
            "Invalid docs_url for {}",
            meta.canonical_id
        );
        assert_eq!(RuleId::parse(meta.canonical_id), Some(meta.id));
        assert_eq!(RuleId::parse(meta.qualified_key), Some(meta.id));

        let variant_token = format!("RuleId::{:?}", meta.id);
        assert!(
            detector_corpus.contains(&variant_token),
            "Rule {} ({variant_token}) has no detector reference across dotore-js, dotore-py, or dotore-rs!",
            meta.canonical_id
        );
    }
}

#[test]
fn spec_8_new_rules_contain_no_external_competitor_linter_names_and_cli_supports_score_subcommand()
{
    let registry = rule_registry();
    for meta in registry.iter().filter(|m| {
        m.canonical_id.starts_with("angular-")
            || m.canonical_id.starts_with("py-")
            || m.canonical_id.starts_with("rs-")
    }) {
        for &alias in meta.legacy_aliases {
            assert!(
                !alias.contains("angular-eslint")
                    && !alias.contains("flake8")
                    && !alias.contains("pylint")
                    && !alias.contains("bandit")
                    && !alias.contains("vulture")
                    && !alias.contains("clippy::"),
                "Rule `{}` contains external competitor tool name in legacy_aliases: `{alias}`",
                meta.canonical_id
            );
        }
        assert!(
            !meta.docs_url.contains("rust-clippy"),
            "Rule `{}` docs_url references external linter: `{}`",
            meta.canonical_id,
            meta.docs_url
        );
    }

    let bin = env!("CARGO_BIN_EXE_dotore");
    let output = std::process::Command::new(bin)
        .args(["score", "--help"])
        .output()
        .expect("Failed to run `dotore score --help`");
    assert!(
        output.status.success(),
        "Expected `dotore score --help` subcommand to succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn append_rs_sources_recursively(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            append_rs_sources_recursively(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(src) = fs::read_to_string(&path)
        {
            out.push_str(&src);
            out.push('\n');
        }
    }
}

#[test]
fn polyglot_architecture_soc_reuse_visibility_and_layout_rules_fix_capsules_and_why() {
    // Confirm top-level re-exports of architecture IR facets, threshold config, and signal formatter
    let default_thresholds = ArchitectureThresholdsConfig::default();
    assert_eq!(default_thresholds.min_helper_statements, 4);
    let _ = (
        std::mem::size_of::<ArchitectureFileFacets>(),
        std::mem::size_of::<ConcernBucket>(),
        std::mem::size_of::<ConcernSignalSite>(),
        std::mem::size_of::<HelperFingerprintIr>(),
        std::mem::size_of::<InlineTerminalUiPrimitiveSiteIr>(),
        std::mem::size_of::<StaticCatalogSiteIr>(),
        std::mem::size_of::<StructLiteralConstructionSiteIr>(),
        format_architecture_signal_explanation as fn(_, _) -> _,
    );

    let mut ts_catalog_entries = String::new();
    let mut py_catalog_entries = String::new();
    let mut rs_catalog_entries = String::new();
    for i in 1..=26 {
        ts_catalog_entries.push_str(&format!(
            "    {{ id: 'rule-{i}', severity: 'warning', enabled: true }},\n"
        ));
        py_catalog_entries.push_str(&format!("    \"RULE_{i:02}\": {{\"code\": {i}}},\n"));
        rs_catalog_entries.push_str(&format!("    (\"rule-{i}\", {i}),\n"));
    }

    let files: Vec<(PathBuf, String)> = vec![
        // --- TypeScript / React Package (`web/`) ---
        (
            PathBuf::from("web/package.json"),
            r#"{"name": "web", "dependencies": {"react": "^19.0.0", "react-dom": "^19.0.0"}}"#
                .to_string(),
        ),
        // 1. TS `arch-thin-entrypoint` (violating) + valid thin entrypoint exemplar
        (
            PathBuf::from("web/src/main.tsx"),
            r#"import fs from 'node:fs';

export interface BootstrapConfig {
    port: number;
    host: string;
}

export async function main() {
    const raw = fs.readFileSync('./config.json', 'utf8');
    const res = await fetch('https://api.example.com/bootstrap');
    const data = await res.json();
    return <main className="app-shell"><h1>{data.title}</h1><pre>{raw}</pre></main>;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/bin/cli.ts"),
            r#"import { runCli } from '../src/runner';
const exitCode = await runCli(process.argv.slice(2));
process.exit(exitCode);
"#
            .to_string(),
        ),
        // 2. TS `arch-no-mixed-io-and-presentation`
        (
            PathBuf::from("web/src/OrdersDashboard.tsx"),
            r#"import React from 'react';

export async function OrdersDashboard({ accountId }: { accountId: string }) {
    const response = await fetch(`/api/accounts/${accountId}/orders`);
    const orders = await response.json();
    return (
        <section className="orders-view">
            <h2>Orders</h2>
            <ul>{orders.map((o: { id: string; total: number }) => <li key={o.id}>{o.total}</li>)}</ul>
        </section>
    );
}
"#
            .to_string(),
        ),
        // 3. TS `arch-separate-static-catalog-from-types` + cohesive pure catalog
        (
            PathBuf::from("web/src/catalog.ts"),
            format!(
                r#"export interface RuleRecord {{
    id: string;
    severity: RuleLevel;
    enabled: boolean;
}}
export type RuleLevel = 'error' | 'warning';
export enum RuleDomain {{ Core = 'core', Arch = 'arch' }}
export const BUILTIN_RULES: RuleRecord[] = [
{ts_catalog_entries}];
"#
            ),
        ),
        (
            PathBuf::from("web/src/pureCatalog.ts"),
            format!(
                r#"import type {{ RuleRecord }} from './catalog';
export const SEPARATED_RULES: RuleRecord[] = [
{ts_catalog_entries}];
"#
            ),
        ),
        // 4. TS `arch-no-mixed-domain-monolith` + cohesive single-concern parser
        (
            PathBuf::from("web/src/monolith.tsx"),
            r#"import fs from 'node:fs';
export interface UserAccount { id: string; email: string; }
export interface InvoiceRecord { id: string; amount: number; }
export type PaymentStatus = 'pending' | 'paid' | 'failed';
export enum AuditCategory { Billing = 'billing', Security = 'security' }
export async function fetchUserAccount(id: string): Promise<UserAccount> {
    const res = await fetch(`/api/users/${id}`);
    return res.json();
}
export function readInvoiceCache(path: string): string {
    return fs.readFileSync(path, 'utf8');
}
export function validateUserEmail(email: string): boolean {
    if (!email.includes('@')) return false;
    return email.trim().length > 3;
}
export function parseInvoiceLine(line: string): InvoiceRecord {
    const parts = line.split(',');
    return { id: parts[0] ?? '', amount: Number(parts[1] ?? 0) };
}
export function normalizePaymentStatus(raw: string): PaymentStatus {
    if (raw === 'paid') return 'paid';
    if (raw === 'failed') return 'failed';
    return 'pending';
}
export function computeInvoiceTotal(items: InvoiceRecord[]): number {
    let sum = 0;
    for (const item of items) sum += item.amount;
    return sum;
}
export function AccountSummaryBanner({ user }: { user: UserAccount }) {
    return <header className="account-banner"><span>{user.email}</span></header>;
}
export function InvoiceTableView({ invoices }: { invoices: InvoiceRecord[] }) {
    return <section className="invoices">{invoices.map((inv) => <div key={inv.id}>{inv.amount}</div>)}</section>;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/src/cohesiveParser.ts"),
            r#"export interface Token { kind: string; text: string; }
export type NodeKind = 'ident' | 'number' | 'binary';
export function isDigit(ch: string): boolean { return ch >= '0' && ch <= '9'; }
export function isAlpha(ch: string): boolean { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); }
export function trimToken(raw: string): string { return raw.trim(); }
export function makeToken(kind: string, text: string): Token { return { kind, text }; }
export function parseIdent(src: string): Token { return makeToken('ident', trimToken(src)); }
export function parseNumber(src: string): Token { return makeToken('number', trimToken(src)); }
export function parsePrimary(src: string): Token { return isDigit(src[0] ?? '') ? parseNumber(src) : parseIdent(src); }
export function parseUnary(src: string): Token { return parsePrimary(src); }
export function parseMultiplicative(src: string): Token { return parseUnary(src); }
export function parseAdditive(src: string): Token { return parseMultiplicative(src); }
export function parseComparison(src: string): Token { return parseAdditive(src); }
export function parseExpression(src: string): Token { return parseComparison(src); }
"#
            .to_string(),
        ),
        // 5. TS `arch-no-inline-terminal-ui-primitives` + UI kit exemplar (`terminal_ui.ts`)
        (
            PathBuf::from("web/src/terminal_ui.ts"),
            r#"export function renderBox(title: string, body: string): string {
    return `\x1b[36m┌── ${title} ──┐\x1b[0m\n│ ${body} │\n└──────────┘`;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/src/reporter.ts"),
            r#"export function formatSummary(status: string): string {
    const header = "\x1b[31mFAIL\x1b[0m";
    const border = `╭────────────╮\n│ ${status} │\n╰────────────╯`;
    return `${header}\n${border}`;
}
"#
            .to_string(),
        ),
        // 6 & 7. TS `arch-prefer-fluent-builder` + `arch-no-duplicated-helper-logic` + builder exemplar
        (
            PathBuf::from("web/src/requestBuilder.ts"),
            r#"export interface RequestConfig {
    url: string;
    method: string;
    timeoutMs: number;
    retryCount: number;
    headers: Record<string, string>;
}
export class RequestConfigBuilder {
    withTimeout(ms: number): this { return this; }
    build(): RequestConfig {
        return { url: "/", method: "GET", timeoutMs: 0, retryCount: 0, headers: {} };
    }
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/src/routesA.ts"),
            r#"export interface DiagnosticRecord {
    rule: string;
    file: string;
    message: string;
    autofix: string | null;
    callerSites: string[];
    suppressed: boolean;
}
function normalizeHeader(raw: string, prefix: string): string {
    const trimmed = raw.trim();
    if (!trimmed) {
        return prefix;
    }
    const cleaned = trimmed.toLowerCase().replace(/\s+/g, "-");
    return `${prefix}:${cleaned}`;
}
export function checkFirst(file: string): DiagnosticRecord {
    const label = normalizeHeader(file, "first");
    const diag: DiagnosticRecord = {
        rule: "rule-a",
        file: label,
        message: "First issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
    return diag;
}
export function checkSecond(file: string): DiagnosticRecord {
    return <DiagnosticRecord>{
        rule: "rule-b",
        file,
        message: "Second issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/src/routesB.ts"),
            r#"import type { DiagnosticRecord } from "./routesA";
const cleanToken = (input: string, ns: string): string => {
    const stripped = input.trim();
    if (!stripped) {
        return ns;
    }
    const slug = stripped.toLowerCase().replace(/\s+/g, "-");
    return `${ns}:${slug}`;
};
export function checkThird(file: string): DiagnosticRecord {
    const tag = cleanToken(file, "third");
    const entry: DiagnosticRecord = {
        rule: "rule-c",
        file: tag,
        message: "Third issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
    return entry;
}
"#
            .to_string(),
        ),
        // --- Python Package (`py-svc/`) ---
        (
            PathBuf::from("py-svc/pyproject.toml"),
            "[project]\nname = \"py-svc\"\ndependencies = [\"pydantic>=2.0\", \"httpx>=0.27\", \"rich>=13.0\"]\n"
                .to_string(),
        ),
        // 1. Python `arch-thin-entrypoint` + valid thin `__main__.py`
        (
            PathBuf::from("py-svc/main.py"),
            r#"from pydantic import BaseModel
import httpx

class InvoicePayload(BaseModel):
    invoice_id: str
    amount_cents: int

def main() -> None:
    resp = httpx.get("https://api.example.com/invoices")
    data = resp.json()
    for row in data:
        payload = InvoicePayload(invoice_id=row["id"], amount_cents=row["amount"])
        httpx.post("https://api.example.com/ledger", json=payload.model_dump())

if __name__ == "__main__":
    main()
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/__main__.py"),
            r#"import sys
from py_svc.runner import run_cli

def main() -> int:
    return run_cli(sys.argv[1:])

if __name__ == "__main__":
    raise SystemExit(main())
"#
            .to_string(),
        ),
        // 2. Python `arch-no-mixed-io-and-presentation`
        (
            PathBuf::from("py-svc/views.py"),
            r#"from flask import render_template

def save_and_render_invoice(invoice_html: str):
    with open("/tmp/invoice.html", "w") as f:
        f.write(invoice_html)
    return render_template("invoice.html", body=invoice_html)
"#
            .to_string(),
        ),
        // 3. Python `arch-separate-static-catalog-from-types`
        (
            PathBuf::from("py-svc/catalog.py"),
            format!(
                r#"from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel

class Severity(Enum):
    WARN = "warn"
    ERROR = "error"

@dataclass
class RuleSpec:
    code: int

class RuleRecord(BaseModel):
    id: str

DEFAULT_RULE_CATALOG = {{
{py_catalog_entries}}}
"#
            ),
        ),
        // 4. Python `arch-no-mixed-domain-monolith`
        (
            PathBuf::from("py-svc/monolith.py"),
            r#"from pydantic import BaseModel
from rich.console import Console
import httpx

class OrderModel(BaseModel):
    order_id: str

class PaymentModel(BaseModel):
    payment_id: str

class ShipmentModel(BaseModel):
    shipment_id: str

def fetch_orders():
    return httpx.get("https://api.example.com/orders").json()

def fetch_payments():
    return httpx.get("https://api.example.com/payments").json()

def render_order_box(order_id: str) -> None:
    Console().print(f"Order: {order_id}")

def render_payment_status(payment_id: str) -> None:
    Console().print(f"Paid {payment_id}")

def parse_order_node(node):
    return str(node)

def validate_payment_schema(item):
    return bool(item)

def transform_shipment_row(row):
    return row

def compute_tax_cents(amount: int) -> int:
    return amount * 10

def normalize_currency_code(code: str) -> str:
    return code.upper()
"#
            .to_string(),
        ),
        // 5. Python `arch-no-inline-terminal-ui-primitives` + UI kit exemplar (`ui.py`)
        (
            PathBuf::from("py-svc/ui.py"),
            r#"def draw_banner(title: str) -> str:
    return f"\x1b[1m╭──────╮\n│ {title} │\n╰──────╯\x1b[0m"
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/status_printer.py"),
            r#"def print_failure(label: str) -> str:
    return f"\x1b[31m╭──────╮\n│ {label} │\n╰──────╯\x1b[0m"
"#
            .to_string(),
        ),
        // 6 & 7. Python `arch-prefer-fluent-builder` + `arch-no-duplicated-helper-logic` + builder exemplar
        (
            PathBuf::from("py-svc/builders.py"),
            r#"class AuditEventBuilder:
    def with_actor(self, actor: str):
        return self
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/alpha.py"),
            r#"__all__ = ["process_alpha"]

def sanitize_payload(raw: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw.items():
        clean_k = k.strip().lower()
        if clean_k:
            out[clean_k] = v.strip()
    return out

def process_alpha():
    return [
        JobEnvelope(job_id="1", actor="sys", retries=0, metadata=None, archived=False),
        JobEnvelope(job_id="2", actor="sys", retries=0, metadata=None, archived=False),
    ]
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/beta.py"),
            r#"__all__ = ["process_beta"]

def sanitize_payload(entries: dict[str, str]) -> dict[str, str]:
    acc: dict[str, str] = {}
    for key, val in entries.items():
        norm = key.strip().lower()
        if norm:
            acc[norm] = val.strip()
    return acc

def process_beta():
    return [
        JobEnvelope(job_id="3", actor="ops", retries=0, metadata=None, archived=False),
    ]
"#
            .to_string(),
        ),
        // --- Rust Package (`rs-svc/`) ---
        (
            PathBuf::from("rs-svc/Cargo.toml"),
            "[package]\nname = \"rs-svc\"\nversion = \"0.1.0\"\n[dependencies]\nsqlx = \"0.8\"\ncrossterm = \"0.28\"\n"
                .to_string(),
        ),
        // 8. Rust `rs-arch-prefer-pub-crate-modules` (lib.rs with `pub mod helpers;` re-exported via `pub use helpers::Helper;`)
        (
            PathBuf::from("rs-svc/src/lib.rs"),
            r#"pub mod helpers;
pub(crate) mod internal;
pub use helpers::Helper;

pub fn run_service(h: Helper) -> u32 {
    internal::compute() + h.0
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/helpers.rs"),
            "pub struct Helper(pub u32);\n".to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/internal.rs"),
            "pub(crate) fn compute() -> u32 { 42 }\n".to_string(),
        ),
        // 9. Rust `rs-arch-no-legacy-mod-rs`
        (
            PathBuf::from("rs-svc/src/legacy/mod.rs"),
            "pub fn legacy_helper() -> u32 { 7 }\n".to_string(),
        ),
        // 1. Rust `arch-thin-entrypoint`
        (
            PathBuf::from("rs-svc/src/main.rs"),
            r#"pub struct CliDomainModel {
    pub id: u64,
}

fn main() {
    let raw = std::fs::read_to_string("config.toml").unwrap_or_default();
    println!("loaded {} bytes", raw.len());
}
"#
            .to_string(),
        ),
        // 2 & 5. Rust `arch-no-mixed-io-and-presentation` + `arch-no-inline-terminal-ui-primitives` + UI kit exemplar (`ui.rs`)
        (
            PathBuf::from("rs-svc/src/ui.rs"),
            r#"pub struct AsciiBanner;
impl AsciiBanner {
    pub fn render(title: &str) -> String {
        format!("\x1b[36m┌── {title} ──┐\x1b[0m")
    }
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/mixed_worker.rs"),
            r#"pub async fn sync_and_render(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT 1").fetch_one(pool).await;
    println!("\x1b[31m┌─ SYNC DONE ─┐\x1b[0m");
}
"#
            .to_string(),
        ),
        // 3. Rust `arch-separate-static-catalog-from-types`
        (
            PathBuf::from("rs-svc/src/catalog_types.rs"),
            format!(
                r#"pub struct RuleEntry {{ pub id: &'static str, pub code: u32 }}
pub enum RuleKind {{ Safety, Perf }}
pub struct RuleGroup {{ pub name: &'static str }}
pub const STATIC_RULES: &[(&str, u32)] = &[
{rs_catalog_entries}];
"#
            ),
        ),
        // 4. Rust `arch-no-mixed-domain-monolith`
        (
            PathBuf::from("rs-svc/src/monolith.rs"),
            r#"pub struct Account { pub id: u64 }
pub struct LedgerEntry { pub cents: i64 }
pub enum Currency { Usd, Eur }
pub struct AuditRecord { pub actor: String }
pub struct Invoice { pub total: i64 }
pub struct TaxRate { pub bps: u32 }
pub const DEFAULT_FEE_CENTS: i64 = 25;
pub const MAX_BATCH_SIZE: usize = 100;
pub async fn fetch_account(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT 1").fetch_one(pool).await;
}
pub async fn save_ledger(pool: &sqlx::PgPool) {
    let _ = sqlx::query("INSERT INTO ledger VALUES (1)").execute(pool).await;
}
pub fn validate_account_token(raw: &str) -> bool {
    !raw.trim().is_empty()
}
pub fn render_ledger_tui() {
    let _ = crossterm::execute!(std::io::stdout());
}
"#
            .to_string(),
        ),
        // 6 & 7. Rust `arch-prefer-fluent-builder` + `arch-no-duplicated-helper-logic` + builder exemplar
        (
            PathBuf::from("rs-svc/src/builder.rs"),
            r#"pub struct ConfigSpec {
    pub host: String,
    pub port: u16,
}
impl ConfigSpec {
    pub fn new(host: impl Into<String>) -> Self {
        Self { host: host.into(), port: 8080 }
    }
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/job_a.rs"),
            r#"pub struct JobSpec {
    pub name: String,
    pub retries: u32,
    pub timeout_ms: Option<u64>,
    pub tags: Vec<String>,
    pub dry_run: bool,
    pub priority: u32,
}
fn normalize_slug_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let cleaned = lower.replace(' ', "-");
    Some(cleaned)
}
pub fn build_import_job(raw: &str) -> JobSpec {
    let name = normalize_slug_key(raw).unwrap_or_default();
    JobSpec {
        name,
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}
pub fn build_cleanup_job() -> JobSpec {
    JobSpec {
        name: "cleanup".to_string(),
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/job_b.rs"),
            r#"use crate::job_a::JobSpec;
fn sanitize_identifier(input: &str) -> Option<String> {
    let stripped = input.trim();
    if stripped.is_empty() {
        return None;
    }
    let downcased = stripped.to_ascii_lowercase();
    let dashed = downcased.replace(' ', "-");
    Some(dashed)
}
pub fn build_export_job(label: &str) -> JobSpec {
    let name = sanitize_identifier(label).unwrap_or_default();
    JobSpec {
        name,
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}
"#
            .to_string(),
        ),
    ];

    let arch_rules = [
        RuleId::ArchThinEntrypoint,
        RuleId::ArchNoMixedIoAndPresentation,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        RuleId::ArchNoMixedDomainMonolith,
        RuleId::ArchNoInlineTerminalUiPrimitives,
        RuleId::ArchPreferFluentBuilder,
        RuleId::ArchNoDuplicatedHelperLogic,
        RuleId::RsArchPreferPubCrateModules,
        RuleId::RsArchNoLegacyModRs,
    ];

    let report = analyze_project_sources(files.clone(), Some(&arch_rules));

    // Every architecture diagnostic must be Warning, Refactor or Surgical, and have patch: None
    assert!(!report.diagnostics.is_empty());
    for diag in &report.diagnostics {
        assert_eq!(
            diag.severity,
            RuleSeverity::Warning,
            "Expected Warning severity on {:?}",
            diag
        );
        assert!(
            matches!(
                diag.tier,
                PrescriptionTier::Refactor | PrescriptionTier::Surgical
            ),
            "Expected Refactor or Surgical tier on {:?}",
            diag
        );
        assert!(
            diag.autofix.is_none(),
            "Architecture rule {:?} must NEVER emit an autofix patch",
            diag.rule
        );
    }

    let has_finding = |path_suffix: &str, rule_id: &str| -> bool {
        report
            .diagnostics
            .iter()
            .any(|d| d.file.ends_with(path_suffix) && d.rule.as_str() == rule_id)
    };

    // Verify all 7 cross-language rules fire in TypeScript, Python, and Rust:
    for (path_suffix, rule_id) in [
        // TypeScript
        ("web/src/main.tsx", "arch-thin-entrypoint"),
        (
            "web/src/OrdersDashboard.tsx",
            "arch-no-mixed-io-and-presentation",
        ),
        (
            "web/src/catalog.ts",
            "arch-separate-static-catalog-from-types",
        ),
        ("web/src/monolith.tsx", "arch-no-mixed-domain-monolith"),
        (
            "web/src/reporter.ts",
            "arch-no-inline-terminal-ui-primitives",
        ),
        ("web/src/routesA.ts", "arch-prefer-fluent-builder"),
        ("web/src/routesA.ts", "arch-no-duplicated-helper-logic"),
        // Python
        ("py-svc/main.py", "arch-thin-entrypoint"),
        ("py-svc/views.py", "arch-no-mixed-io-and-presentation"),
        (
            "py-svc/catalog.py",
            "arch-separate-static-catalog-from-types",
        ),
        ("py-svc/monolith.py", "arch-no-mixed-domain-monolith"),
        (
            "py-svc/status_printer.py",
            "arch-no-inline-terminal-ui-primitives",
        ),
        ("py-svc/alpha.py", "arch-prefer-fluent-builder"),
        ("py-svc/alpha.py", "arch-no-duplicated-helper-logic"),
        // Rust
        ("rs-svc/src/main.rs", "arch-thin-entrypoint"),
        (
            "rs-svc/src/mixed_worker.rs",
            "arch-no-mixed-io-and-presentation",
        ),
        (
            "rs-svc/src/catalog_types.rs",
            "arch-separate-static-catalog-from-types",
        ),
        ("rs-svc/src/monolith.rs", "arch-no-mixed-domain-monolith"),
        (
            "rs-svc/src/mixed_worker.rs",
            "arch-no-inline-terminal-ui-primitives",
        ),
        ("rs-svc/src/job_a.rs", "arch-prefer-fluent-builder"),
        ("rs-svc/src/job_a.rs", "arch-no-duplicated-helper-logic"),
        ("rs-svc/src/lib.rs", "rs-arch-prefer-pub-crate-modules"),
        ("rs-svc/src/legacy/mod.rs", "rs-arch-no-legacy-mod-rs"),
    ] {
        assert!(
            has_finding(path_suffix, rule_id),
            "Missing expected finding `{rule_id}` on `{path_suffix}`. Emitted:\n{:#?}",
            report
                .diagnostics
                .iter()
                .map(|d| (&d.file, &d.rule))
                .collect::<Vec<_>>()
        );
    }

    // Adversarial valid files must have zero findings
    for valid_path in [
        "web/bin/cli.ts",
        "web/src/pureCatalog.ts",
        "web/src/cohesiveParser.ts",
        "web/src/terminal_ui.ts",
        "web/src/requestBuilder.ts",
        "py-svc/__main__.py",
        "py-svc/ui.py",
        "py-svc/builders.py",
        "rs-svc/src/ui.rs",
        "rs-svc/src/builder.rs",
        "rs-svc/src/internal.rs",
    ] {
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.file == Path::new(valid_path)),
            "Expected 0 findings on valid cohesive/kit file `{valid_path}`, got: {:#?}",
            report
                .diagnostics
                .iter()
                .filter(|d| d.file == Path::new(valid_path))
                .collect::<Vec<_>>()
        );
    }

    // Verify Fix Capsules & Repository Exemplars across TS, Python, and Rust
    assert!(!report.root_cause_groups.is_empty());
    assert_eq!(report.root_cause_groups.len(), report.fix_capsules.len());
    for capsule in &report.fix_capsules {
        assert!(!capsule.recipe_markdown.is_empty());
        assert!(!capsule.invariants.is_empty());
        let ex = capsule.exemplar.as_ref().unwrap_or_else(|| {
            panic!(
                "Expected repository exemplar for capsule `{}` (rule {:?}, file {})",
                capsule.root_cause_group_id,
                capsule.rule,
                capsule.subject_excerpt.file.display()
            )
        });
        // Exemplar must come from the same language family as the subject file
        let subj_ext = capsule
            .subject_excerpt
            .file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let ex_ext = ex
            .file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        match subj_ext {
            "py" => assert_eq!(ex_ext, "py", "Python capsule must get Python exemplar"),
            "rs" => assert_eq!(ex_ext, "rs", "Rust capsule must get Rust exemplar"),
            _ => assert!(
                matches!(ex_ext, "ts" | "tsx" | "js" | "jsx"),
                "TS/JS capsule must get TS/JS exemplar, got {ex_ext}"
            ),
        }
    }

    // Verify `plan_project` and `explain_location` on disk across TS, Python, and Rust
    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-arch-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    let plan_dir = temp_dir.join("plans");
    let plan_res = plan_project(&report, &plan_dir).unwrap();
    assert!(plan_res.index_file.is_file());
    assert_eq!(plan_res.plan_files.len(), report.fix_capsules.len());

    for (rel_path, content) in &files {
        let full_path = temp_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
    }

    for (loc_arg, expected_rule_substr) in [
        (
            "web/src/OrdersDashboard.tsx:4",
            "arch-no-mixed-io-and-presentation",
        ),
        ("py-svc/views.py:6", "arch-no-mixed-io-and-presentation"),
        (
            "rs-svc/src/mixed_worker.rs:2",
            "arch-no-mixed-io-and-presentation",
        ),
        ("rs-svc/src/legacy/mod.rs:1", "rs-arch-no-legacy-mod-rs"),
    ] {
        let why_rep = explain_location(loc_arg, &temp_dir).unwrap();
        let matching_entry = why_rep
            .entries
            .iter()
            .find(|e| e.rule.contains(expected_rule_substr))
            .unwrap_or_else(|| {
                panic!(
                    "Expected `explain_location(\"{loc_arg}\")` to explain `{expected_rule_substr}`, got: {:#?}",
                    why_rep.entries
                )
            });
        assert_eq!(matching_entry.status, "active");
        assert!(
            matching_entry.explanation.contains("Structural signals:"),
            "Expected `Structural signals:` in why explanation for `{loc_arg}`, got: {}",
            matching_entry.explanation
        );
        assert!(
            !matching_entry.cascade_steps.is_empty(),
            "Expected non-empty cascade_steps for `{loc_arg}`"
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn polyglot_architecture_threshold_overrides_and_inline_suppressions_across_ts_py_and_rs() {
    let mut ts_entries = String::new();
    let mut py_entries = String::new();
    let mut rs_entries = String::new();
    for i in 1..=26 {
        ts_entries.push_str(&format!("    {{ id: 'r-{i}', code: {i} }},\n"));
        py_entries.push_str(&format!("    \"R_{i:02}\": {i},\n"));
        rs_entries.push_str(&format!("    (\"r-{i}\", {i}),\n"));
    }

    let arch_rules = [
        RuleId::ArchThinEntrypoint,
        RuleId::ArchNoMixedIoAndPresentation,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        RuleId::ArchNoMixedDomainMonolith,
        RuleId::ArchNoInlineTerminalUiPrimitives,
        RuleId::ArchPreferFluentBuilder,
        RuleId::ArchNoDuplicatedHelperLogic,
        RuleId::RsArchPreferPubCrateModules,
        RuleId::RsArchNoLegacyModRs,
    ];

    // 1. Threshold overrides via root `dotore.config.json`:
    // Relax thresholds so 26-entry static catalogs, 4-statement helpers, and 6-field builders
    // are below the configured workspace thresholds across TS, Python, and Rust.
    let threshold_files: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("dotore.config.json"),
            r#"{
  "architecture": {
    "minHelperStatements": 15,
    "minDuplicatedHelperModules": 4,
    "minBuilderFields": 10,
    "minBuilderSites": 6,
    "minTypesWithCatalog": 10,
    "minStaticCatalogEntries": 100,
    "maxEntrypointStatements": 100,
    "minMonolithDomainClusters": 5,
    "minMonolithSymbols": 50
  }
}"#
            .to_string(),
        ),
        (
            PathBuf::from("web/package.json"),
            r#"{"name": "web", "dependencies": {"react": "^19.0.0"}}"#.to_string(),
        ),
        (
            PathBuf::from("web/src/catalog.ts"),
            format!(
                "export interface A {{ id: string; }}\nexport interface B {{ code: number; }}\nexport type C = A & B;\nexport const DATA: C[] = [\n{ts_entries}];\n"
            ),
        ),
        (
            PathBuf::from("web/src/modA.ts"),
            r#"function helperA(raw: string): string {
    const a = raw.trim();
    if (!a) return "x";
    const b = a.toLowerCase();
    return b;
}
export const runA = (s: string) => helperA(s);
"#
            .to_string(),
        ),
        (
            PathBuf::from("web/src/modB.ts"),
            r#"function helperB(input: string): string {
    const a = input.trim();
    if (!a) return "x";
    const b = a.toLowerCase();
    return b;
}
export const runB = (s: string) => helperB(s);
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/pyproject.toml"),
            "[project]\nname = \"py-svc\"\ndependencies = [\"pydantic>=2.0\"]\n".to_string(),
        ),
        (
            PathBuf::from("py-svc/catalog.py"),
            format!(
                "from pydantic import BaseModel\nclass A(BaseModel): pass\nclass B(BaseModel): pass\nclass C(BaseModel): pass\nDATA = {{\n{py_entries}}}\n"
            ),
        ),
        (
            PathBuf::from("py-svc/mod_a.py"),
            r#"__all__ = ["run_a"]
def helper_a(raw: str) -> str:
    a = raw.strip()
    if not a:
        return "x"
    b = a.lower()
    return b
def run_a(s: str) -> str:
    return helper_a(s)
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/mod_b.py"),
            r#"__all__ = ["run_b"]
def helper_b(raw: str) -> str:
    a = raw.strip()
    if not a:
        return "x"
    b = a.lower()
    return b
def run_b(s: str) -> str:
    return helper_b(s)
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/Cargo.toml"),
            "[package]\nname = \"rs-svc\"\nversion = \"0.1.0\"\n".to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/catalog.rs"),
            format!(
                "pub struct A;\npub struct B;\npub enum C {{ X, Y }}\npub const DATA: &[(&str, u32)] = &[\n{rs_entries}];\n"
            ),
        ),
        (
            PathBuf::from("rs-svc/src/mod_a.rs"),
            r#"fn helper_a(raw: &str) -> String {
    let a = raw.trim();
    if a.is_empty() {
        return "x".to_string();
    }
    let b = a.to_ascii_lowercase();
    b
}
pub fn run_a(s: &str) -> String { helper_a(s) }
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/mod_b.rs"),
            r#"fn helper_b(raw: &str) -> String {
    let a = raw.trim();
    if a.is_empty() {
        return "x".to_string();
    }
    let b = a.to_ascii_lowercase();
    b
}
pub fn run_b(s: &str) -> String { helper_b(s) }
"#
            .to_string(),
        ),
    ];

    let relaxed_report = analyze_project_sources(threshold_files, Some(&arch_rules));
    assert!(
        relaxed_report.diagnostics.is_empty(),
        "Expected relaxed `DotoreConfig.architecture` thresholds to produce 0 diagnostics across TS/Py/Rs, got: {:#?}",
        relaxed_report.diagnostics
    );

    // 2. Inline suppressions across TS, Python, and Rust + `explain_location` suppressed status
    let suppressed_files: Vec<(PathBuf, String)> = vec![
        (
            PathBuf::from("web/package.json"),
            r#"{"name": "web", "dependencies": {"react": "^19.0.0"}}"#.to_string(),
        ),
        (
            PathBuf::from("web/src/SuppressedOrders.tsx"),
            r#"import React from 'react';

// dotore-disable-next-line arch-no-mixed-io-and-presentation
export async function SuppressedOrders({ accountId }: { accountId: string }) {
    const response = await fetch(`/api/accounts/${accountId}/orders`);
    const orders = await response.json();
    return <section className="orders-view"><span>{orders.length}</span></section>;
}
"#
            .to_string(),
        ),
        (
            PathBuf::from("py-svc/pyproject.toml"),
            "[project]\nname = \"py-svc\"\ndependencies = [\"flask>=3.0\"]\n".to_string(),
        ),
        (
            PathBuf::from("py-svc/suppressed_views.py"),
            r#"from flask import render_template

def save_and_render(html: str):
    with open("/tmp/out.html", "w") as f:  # dotore-disable-line arch-no-mixed-io-and-presentation
        f.write(html)
    # dotore-disable-next-line arch-no-mixed-io-and-presentation
    return render_template("out.html", body=html)
"#
            .to_string(),
        ),
        (
            PathBuf::from("rs-svc/Cargo.toml"),
            "[package]\nname = \"rs-svc\"\nversion = \"0.1.0\"\n".to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/suppressed_mod/mod.rs"),
            "#[allow(clippy::mod_module_files)]\npub fn allowed_legacy() -> u32 { 1 }\n"
                .to_string(),
        ),
        (
            PathBuf::from("rs-svc/src/suppressed_ui.rs"),
            r#"pub fn print_alert() {
    // dotore-disable-next-line arch-no-inline-terminal-ui-primitives
    let banner = "\x1b[31m╭─ ALERT ─╮\x1b[0m";
    println!("{banner}");
}
"#
            .to_string(),
        ),
    ];

    let suppressed_report = analyze_project_sources(suppressed_files.clone(), Some(&arch_rules));
    assert!(
        suppressed_report.diagnostics.is_empty(),
        "Expected inline suppressions across TS/Py/Rs to silence all architecture diagnostics, got: {:#?}",
        suppressed_report.diagnostics
    );

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-arch-supp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    for (rel_path, content) in &suppressed_files {
        let full_path = temp_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full_path, content).unwrap();
    }

    for (loc_arg, expected_rule_substr) in [
        (
            "web/src/SuppressedOrders.tsx:4",
            "arch-no-mixed-io-and-presentation",
        ),
        (
            "py-svc/suppressed_views.py:7",
            "arch-no-mixed-io-and-presentation",
        ),
        (
            "rs-svc/src/suppressed_ui.rs:3",
            "arch-no-inline-terminal-ui-primitives",
        ),
        (
            "rs-svc/src/suppressed_mod/mod.rs:1",
            "rs-arch-no-legacy-mod-rs",
        ),
    ] {
        let why_rep = explain_location(loc_arg, &temp_dir).unwrap();
        let entry = why_rep
            .entries
            .iter()
            .find(|e| e.rule.contains(expected_rule_substr))
            .unwrap_or_else(|| {
                panic!(
                    "Expected `explain_location(\"{loc_arg}\")` to report suppressed `{expected_rule_substr}`, got: {:#?}",
                    why_rep.entries
                )
            });
        assert_eq!(entry.status, "suppressed");
        assert!(entry.explanation.contains("Structural signals:"));
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn self_hosting_dogfood_audit_zero_architectural_false_positives_across_dotore_workspace() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let arch_rules: Vec<RuleId> = dotore::rule_registry()
        .iter()
        .map(|m| m.id)
        .filter(|r| r.is_architecture_soc_or_reuse_rule())
        .collect();
    assert!(arch_rules.contains(&RuleId::RsArchNoUnusedPubCrateItems));

    let (report, _sources) = scan_workspace(&ScanOptions {
        paths: vec![
            workspace_root.join("crates/dotore-core/src"),
            workspace_root.join("crates/dotore-js/src"),
            workspace_root.join("crates/dotore-py/src"),
            workspace_root.join("crates/dotore-rs/src"),
            workspace_root.join("src"),
        ],
        include_tests: false,
        rules: Some(arch_rules),
        tiers: None,
    })
    .expect("Failed to scan dotore workspace during self-hosting dogfood audit");

    assert!(
        report.diagnostics.is_empty(),
        "Self-hosting dogfood audit found {} architectural false positive(s) across dotore's own modularized workspace:\n{:#?}",
        report.diagnostics.len(),
        report
            .diagnostics
            .iter()
            .map(|d| (&d.file, d.loc.line, d.rule, &d.target_name, &d.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn soc_rules_honor_subject_contextual_owner_and_cli_category_and_only_filters() {
    use clap::Parser;
    use dotore::Cli;

    let mut ts_entries = String::new();
    let mut py_entries = String::new();
    let mut rs_entries = String::new();
    for i in 1..=26 {
        ts_entries.push_str(&format!("    {{ id: 'r-{i}', code: {i} }},\n"));
        py_entries.push_str(&format!("    \"R_{i:02}\": {i},\n"));
        rs_entries.push_str(&format!("    (\"r-{i}\", {i}),\n"));
    }

    let ts_src = format!(
        "export interface A {{ id: string; }}\nexport interface B {{ code: number; }}\nexport type C = A & B;\nexport const DATA: C[] = [\n{ts_entries}];\n\nexport function unrelatedHelper(x: number): number {{\n    return x + 1;\n}}\n"
    );
    let py_src = format!(
        "from pydantic import BaseModel\nclass A(BaseModel): pass\nclass B(BaseModel): pass\nclass C(BaseModel): pass\nDATA = {{\n{py_entries}}}\n\ndef unrelated_helper(x: int) -> int:\n    return x + 1\n"
    );
    let rs_src = format!(
        "pub struct A;\npub struct B;\npub enum C {{ X, Y }}\npub const DATA: &[(&str, u32)] = &[\n{rs_entries}];\n\npub fn unrelated_helper(x: u32) -> u32 {{\n    x + 1\n}}\n"
    );

    let ts_ext = JsLanguageAnalyzer.extract_file(Path::new("web/src/catalog.ts"), &ts_src);
    let py_ext = PyLanguageAnalyzer::new().extract_file(Path::new("py-svc/catalog.py"), &py_src);
    let rs_ext = RsLanguageAnalyzer.extract_file(Path::new("rs-svc/src/catalog.rs"), &rs_src);

    let files = vec![
        (PathBuf::from("web/src/catalog.ts"), ts_src.clone()),
        (PathBuf::from("py-svc/catalog.py"), py_src.clone()),
        (PathBuf::from("rs-svc/src/catalog.rs"), rs_src.clone()),
    ];
    let report = analyze_project_sources(
        files.clone(),
        Some(&[RuleId::ArchSeparateStaticCatalogFromTypes]),
    );
    assert_eq!(report.diagnostics.len(), 3);

    let sources_map: HashMap<PathBuf, String> = files.into_iter().collect();
    let extracted_files = vec![ts_ext, py_ext, rs_ext];

    // 1. Touching only the unrelated function at the bottom of each file must NOT surface the catalog diagnostic under `--scope contextual`
    let ts_total_lines = u32::try_from(ts_src.lines().count()).unwrap();
    let py_total_lines = u32::try_from(py_src.lines().count()).unwrap();
    let rs_total_lines = u32::try_from(rs_src.lines().count()).unwrap();

    let unrelated_filtered = filter_diagnostics_by_scope(
        report.diagnostics.clone(),
        DiffScope::Contextual,
        Path::new("."),
        &[
            PathBuf::from("web/src/catalog.ts"),
            PathBuf::from("py-svc/catalog.py"),
            PathBuf::from("rs-svc/src/catalog.rs"),
        ],
        &[
            ChangedFileLineRanges {
                file: PathBuf::from("web/src/catalog.ts"),
                ranges: vec![(ts_total_lines - 1, ts_total_lines)],
                deletion_lines: Vec::new(),
            },
            ChangedFileLineRanges {
                file: PathBuf::from("py-svc/catalog.py"),
                ranges: vec![(py_total_lines, py_total_lines)],
                deletion_lines: Vec::new(),
            },
            ChangedFileLineRanges {
                file: PathBuf::from("rs-svc/src/catalog.rs"),
                ranges: vec![(rs_total_lines - 1, rs_total_lines)],
                deletion_lines: Vec::new(),
            },
        ],
        &extracted_files,
        &sources_map,
    );
    assert!(
        unrelated_filtered.is_empty(),
        "Touching an unrelated function in the same file must NOT trigger ArchSeparateStaticCatalogFromTypes under --scope contextual, got: {unrelated_filtered:#?}"
    );

    // 2. Touching lines inside the static catalog declaration DOES surface the diagnostic under `--scope contextual`
    let catalog_filtered = filter_diagnostics_by_scope(
        report.diagnostics,
        DiffScope::Contextual,
        Path::new("."),
        &[
            PathBuf::from("web/src/catalog.ts"),
            PathBuf::from("py-svc/catalog.py"),
            PathBuf::from("rs-svc/src/catalog.rs"),
        ],
        &[
            ChangedFileLineRanges {
                file: PathBuf::from("web/src/catalog.ts"),
                ranges: vec![(10, 10)],
                deletion_lines: Vec::new(),
            },
            ChangedFileLineRanges {
                file: PathBuf::from("py-svc/catalog.py"),
                ranges: vec![(10, 10)],
                deletion_lines: Vec::new(),
            },
            ChangedFileLineRanges {
                file: PathBuf::from("rs-svc/src/catalog.rs"),
                ranges: vec![(10, 10)],
                deletion_lines: Vec::new(),
            },
        ],
        &extracted_files,
        &sources_map,
    );
    assert_eq!(catalog_filtered.len(), 3);

    // 3. Verify CLI `--category architecture` and `--only arch` parse cleanly
    let cli_cat = Cli::try_parse_from(["dotore", "--category", "architecture", "--no-pager", "."])
        .expect("Failed to parse --category architecture");
    assert!(cli_cat.command.is_none());
    let cli_only = Cli::try_parse_from(["dotore", "check", "--only", "arch", "--no-pager", "."])
        .expect("Failed to parse --only arch");
    assert!(cli_only.command.is_some());
}
