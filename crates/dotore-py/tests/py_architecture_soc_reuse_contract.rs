//! `PyLanguageAnalyzer` contract and integration tests for Ticket #33:
//! Python Separation of Concerns, Monolith & Reuse Rules (`dotore-py`).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    CapabilityGate, DotoreConfig, LanguageAnalyzer, PrescriptionTier, RuleId, RuleSeverity,
    WorkspacePackage, planner::build_root_cause_groups_and_capsules,
};
use dotore_py::PyLanguageAnalyzer;

fn default_py_package(name: &str, root: &str) -> WorkspacePackage {
    WorkspacePackage {
        name: name.to_string(),
        root_dir: PathBuf::from(root),
        capability_gate: CapabilityGate::default_python(),
        config: DotoreConfig::default(),
    }
}

#[test]
fn py_thin_entrypoint_detects_domain_classes_loops_and_statement_budget_violations() {
    let analyzer = PyLanguageAnalyzer::new();
    let pkg = default_py_package("worker", "worker");

    // 1. Entrypoint defining domain class + direct I/O
    let main_with_model_and_io = r#"from pydantic import BaseModel
import requests

class SyncTask(BaseModel):
    task_id: str

def main() -> None:
    resp = requests.get("https://api.example.com/tasks")
    task = SyncTask(task_id=resp.json()["id"])
    requests.post("https://api.example.com/ack", json=task.model_dump())
"#;

    // 2. Entrypoint embedding domain loop + direct DB queries
    let cli_with_loop_query = r#"def run(session) -> None:
    for user_id in [1, 2, 3]:
        session.execute("UPDATE users SET active = 1 WHERE id = :id", {"id": user_id})

if __name__ == "__main__":
    run(None)
"#;

    // 3. Adversarial valid thin entrypoints
    let thin_dunder_main = r#"import sys
from worker.runner import run_worker

def main() -> int:
    return run_worker(sys.argv[1:])

if __name__ == "__main__":
    raise SystemExit(main())
"#;

    let files = vec![
        analyzer.extract_file(Path::new("worker/main.py"), main_with_model_and_io),
        analyzer.extract_file(Path::new("worker/cli.py"), cli_with_loop_query),
        analyzer.extract_file(Path::new("worker/__main__.py"), thin_dunder_main),
    ];

    let res = analyzer.analyze_package(&pkg, &files, Some(&[RuleId::ArchThinEntrypoint]));
    assert_eq!(res.diagnostics.len(), 2);
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.file == Path::new("worker/main.py"))
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.file == Path::new("worker/cli.py"))
    );
    for diag in &res.diagnostics {
        assert_eq!(diag.rule, RuleId::ArchThinEntrypoint);
        assert_eq!(diag.severity, RuleSeverity::Warning);
        assert_eq!(diag.tier, PrescriptionTier::Refactor);
        assert!(diag.autofix.is_none());
    }
}

#[test]
fn py_mixed_io_and_presentation_covers_orm_http_file_and_terminal_template_ui_sinks() {
    let analyzer = PyLanguageAnalyzer::new();
    let pkg = default_py_package("web", "web");

    let click_and_cursor = r#"import click

def dump_users(cursor) -> None:
    cursor.execute("SELECT username FROM users")
    for row in cursor.fetchall():
        click.echo(click.style(row[0], fg="green"))
"#;

    let jinja_and_open = r#"from flask import render_template

def save_and_render_invoice(invoice_html: str):
    with open("/tmp/invoice.html", "w") as f:
        f.write(invoice_html)
    return render_template("invoice.html", body=invoice_html)
"#;

    // Adversarial valid: pure I/O repository module and pure presentation module
    let pure_repo = r#"def fetch_active_users(session):
    return session.query("User").all()
"#;
    let pure_view = r#"from rich.console import Console

def render_users(users: list[str]) -> None:
    console = Console()
    for user in users:
        console.print(user)
"#;
    // Adversarial valid: test file mixing I/O and presentation
    let test_file = r#"import httpx
from rich.console import Console

def test_endpoint_output():
    r = httpx.get("http://localhost:8000/health")
    Console().print(r.text)
"#;

    let files = vec![
        analyzer.extract_file(Path::new("web/cli_users.py"), click_and_cursor),
        analyzer.extract_file(Path::new("web/views.py"), jinja_and_open),
        analyzer.extract_file(Path::new("web/repo.py"), pure_repo),
        analyzer.extract_file(Path::new("web/presenter.py"), pure_view),
        analyzer.extract_file(Path::new("web/tests/test_health.py"), test_file),
    ];

    let res = analyzer.analyze_package(&pkg, &files, Some(&[RuleId::ArchNoMixedIoAndPresentation]));
    assert_eq!(res.diagnostics.len(), 2);
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.file == Path::new("web/cli_users.py"))
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.file == Path::new("web/views.py"))
    );
}

#[test]
fn py_duplicated_helpers_and_fluent_builder_produce_root_cause_groups_and_fix_capsules() {
    let analyzer = PyLanguageAnalyzer::new();
    let mut pkg = default_py_package("billing", "billing");
    pkg.config.architecture.min_helper_statements = 4;
    pkg.config.architecture.min_duplicated_helper_modules = 2;
    pkg.config.architecture.min_builder_fields = 5;
    pkg.config.architecture.min_builder_sites = 3;

    // Module using `__all__` where `sanitize_payload` is not exported in `__all__`
    let mod_one = r#"__all__ = ["process_alpha"]

def sanitize_payload(raw: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw.items():
        clean_k = k.strip().lower()
        if clean_k:
            out[clean_k] = v.strip()
    return out

def process_alpha():
    return [
        AuditEvent(event_id="1", actor="sys", retries=0, metadata=None, archived=False),
        AuditEvent(event_id="2", actor="sys", retries=0, metadata=None, archived=False),
    ]
"#;

    let mod_two = r#"__all__ = ["process_beta"]

def sanitize_payload(entries: dict[str, str]) -> dict[str, str]:
    acc: dict[str, str] = {}
    for key, val in entries.items():
        norm = key.strip().lower()
        if norm:
            acc[norm] = val.strip()
    return acc

def process_beta():
    return [
        AuditEvent(event_id="3", actor="ops", retries=0, metadata=None, archived=False),
         BuilderBackedItem(id="1", label="x", count=0, extra=None, active=False),
        BuilderBackedItem(id="2", label="y", count=0, extra=None, active=False),
        BuilderBackedItem(id="3", label="z", count=0, extra=None, active=False),
    ]
"#;

    let builders_mod = r#"class BuilderBackedItemBuilder:
    pass
"#;

    let sources_list = [
        ("billing/alpha.py", mod_one),
        ("billing/beta.py", mod_two),
        ("billing/builders.py", builders_mod),
    ];
    let mut files = Vec::new();
    let mut sources_map = HashMap::new();
    for (p, src) in sources_list {
        files.push(analyzer.extract_file(Path::new(p), src));
        sources_map.insert(PathBuf::from(p), src.to_string());
    }

    let res = analyzer.analyze_package(
        &pkg,
        &files,
        Some(&[
            RuleId::ArchNoDuplicatedHelperLogic,
            RuleId::ArchPreferFluentBuilder,
        ]),
    );

    let (groups, capsules) =
        build_root_cause_groups_and_capsules(&files, &res.diagnostics, &sources_map);
    assert_eq!(
        groups.len(),
        2,
        "Expected 1 RootCauseGroup for duplicated helper and 1 for builder, got: {groups:?}"
    );
    assert_eq!(capsules.len(), 2);
    for capsule in &capsules {
        assert!(!capsule.caller_site_excerpts.is_empty());
        assert!(!capsule.recipe_markdown.is_empty());
    }
}

#[test]
fn py_fluent_builder_requires_overlapping_default_values_and_line_suppression_is_scoped() {
    let analyzer = PyLanguageAnalyzer::new();
    let mut pkg = default_py_package("accounts", "accounts");
    pkg.config.architecture.min_builder_fields = 5;
    pkg.config.architecture.min_builder_sites = 3;

    // 1. Distinct non-default domain values (different emails, non-zero ints, True) must NOT be treated as boilerplate defaults
    let distinct_domain_calls = r#"def seed_accounts():
    return [
        UserAccount(email="alice@example.com", age=30, role="admin", verified=True, quota_mb=512),
        UserAccount(email="bob@example.com", age=28, role="editor", verified=True, quota_mb=256),
        UserAccount(email="carol@example.com", age=35, role="viewer", verified=True, quota_mb=128),
    ]
"#;
    let distinct_file = analyzer.extract_file(Path::new("accounts/seed.py"), distinct_domain_calls);
    let distinct_res = analyzer.analyze_package(
        &pkg,
        &[distinct_file],
        Some(&[RuleId::ArchPreferFluentBuilder]),
    );
    assert!(
        distinct_res.diagnostics.is_empty(),
        "Expected 0 ArchPreferFluentBuilder diagnostics when all keyword args are non-default domain values, got: {:#?}",
        distinct_res.diagnostics
    );

    // 2. Unrelated mid-file `# dotore-disable-next-line` on line 10 must NOT suppress a rule on line 4
    let mid_file_disable = r#"from flask import render_template

def handler_one(cursor):
    cursor.execute("SELECT 1")
    return render_template("index.html")

def handler_two():
    # dotore-disable-next-line arch-no-mixed-io-and-presentation
    x = 1
    return x
"#;
    let mid_file = analyzer.extract_file(Path::new("accounts/views.py"), mid_file_disable);
    let mid_res = analyzer.analyze_package(
        &pkg,
        &[mid_file],
        Some(&[RuleId::ArchNoMixedIoAndPresentation]),
    );
    assert_eq!(
        mid_res.diagnostics.len(),
        1,
        "Mid-file line disable on an unrelated function must not suppress file/subject SoC rule on handler_one"
    );
}
