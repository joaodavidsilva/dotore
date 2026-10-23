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
    AutofixPatch, ByteEdit, ByteSpan, Capability, ChangedFileLineRanges, DiffScope, DotoreConfig,
    JsLanguageAnalyzer, LanguageAnalyzer, LanguageId, PrescriptionTier, PyLanguageAnalyzer,
    RsLanguageAnalyzer, RuleId, RulesListOptions, ScanOptions, SearchOptions, SymbolKind,
    analyze_project_sources, analyze_source, apply_autofixes, apply_patches_to_source,
    build_rule_catalog, default_analyzers, discover_workspace_packages, explain_location,
    explain_rule, filter_diagnostics_by_scope, format_search_json, format_search_text,
    plan_project, resolve_package_for_file, rule_registry, scan_workspace, search_project_sources,
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
    fs::write(frontend_dir.join("angular.json"), r#"{"version": 1, "projects": {}}"#).unwrap();

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
    fs::write(py_api_dir.join("requirements.txt"), "pytest>=8.0.0\nhttpx>=0.27.0\n").unwrap();

    // Subpackage 4: Rust Tokio + Axum + SQLx worker
    fs::write(
        rs_worker_dir.join("Cargo.toml"),
        "[package]\nname = \"worker-service\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1.40\"\naxum = \"0.8\"\nsqlx = \"0.8\"\nleptos = \"0.7\"\n",
    )
    .unwrap();

    let packages = discover_workspace_packages(&temp_dir);
    assert_eq!(packages.len(), 5, "Expected root + 4 subpackages, got: {packages:#?}");

    // Root package merges JS (Zod), Python (Pydantic), and Rust (Serde) capabilities
    let root_pkg = packages.iter().find(|p| p.root_dir == temp_dir).unwrap();
    assert!(root_pkg.capability_gate.has(Capability::Zod));
    assert!(root_pkg.capability_gate.has(Capability::Python));
    assert!(root_pkg.capability_gate.has(Capability::Pydantic));
    assert!(root_pkg.capability_gate.has(Capability::Rust));
    assert!(root_pkg.capability_gate.has(Capability::Serde));

    // Angular package
    let ng_pkg = resolve_package_for_file(&frontend_dir.join("src/app.component.ts"), &packages).unwrap();
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

    let mem_rules: Vec<RuleId> = in_memory_report.diagnostics.iter().map(|d| d.rule).collect();
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
    assert!(ng_capsule.subject_excerpt.source.contains("export class UserComponent"));
    let ng_ex = ng_capsule.exemplar.as_ref().expect("Expected TS/Angular exemplar");
    assert_eq!(ng_ex.file, Path::new("frontend/src/user.component.ts"));
    assert!(ng_ex.source.contains("CleanComponent"));

    let py_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::PyAsyncNoBlockingCall)
        .expect("Expected Python FixCapsule");
    assert_eq!(py_capsule.subject_excerpt.file, Path::new("backend-py/app.py"));
    assert!(py_capsule.subject_excerpt.source.contains("async def sync_inventory"));
    let py_ex = py_capsule.exemplar.as_ref().expect("Expected Python exemplar");
    assert_eq!(py_ex.file, Path::new("backend-py/app.py"));
    assert!(py_ex.source.contains("def suppressed_broad_except") || py_ex.source.contains("def clean_python_subject"));

    let rs_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::RsTokioNoStdLockAcrossAwait)
        .expect("Expected Rust FixCapsule");
    assert_eq!(
        rs_capsule.subject_excerpt.file,
        Path::new("backend-rs/src/lib.rs")
    );
    assert!(rs_capsule.subject_excerpt.source.contains("pub async fn settle_ledger"));
    let rs_ex = rs_capsule.exemplar.as_ref().expect("Expected Rust exemplar");
    assert_eq!(rs_ex.file, Path::new("backend-rs/src/lib.rs"));
    assert!(rs_ex.source.contains("pub fn suppressed_unwrap_fn") || rs_ex.source.contains("pub fn clean_rust_subject"));

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

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-polyglot-fix-{}", std::process::id()));
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
    assert_eq!(fix_results.len(), 3, "Expected fixes across .ts, .py, and .rs");

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
        ("src/card.ts", "export const x = 1;\n", "export const x = (((;\n"),
        ("src/app.py", "def f():\n    return 1\n", "def f(:\n    return\n"),
        ("src/lib.rs", "pub fn f() -> i32 { 1 }\n", "pub fn f() -> { {{{ }\n"),
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
    let struct_names: Vec<&str> = struct_hits.iter().map(|h| h.outline.name.as_str()).collect();
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
    assert_eq!(all_catalog.len(), 965);

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
            "Expected framework filter `{fw}` to include `{expected_rule_id}`, got: {:?}",
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
    assert_eq!(diagnostics.len(), 6, "Expected 2 findings per language before diff filter");

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
        965,
        "Expected 965 total rules (921 React/TS + 7 Angular + 19 Python + 18 Rust)"
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

    assert_eq!(js_react_count, 921, "Expected 921 React/TS rules");
    assert_eq!(angular_count, 7, "Expected 7 Angular rules");
    assert_eq!(py_count, 19, "Expected 19 Python rules");
    assert_eq!(rs_count, 18, "Expected 18 Rust rules");

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
        assert!(!meta.title.trim().is_empty(), "Empty title for {}", meta.canonical_id);
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
