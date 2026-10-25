//! Integration tests for Ticket #12 (`dotore-py`):
//! - `PyLanguageAnalyzer` contract (`supports_path`, `infer_capability_gate`, `extract_file`, `validate_syntax`)
//! - 5 Core Python Safety Rules (`py-no-mutable-default-arg`, `py-no-silent-broad-except`,
//!   `py-require-context-manager-for-resource`, `py-no-unguarded-parse-or-key-access`,
//!   `py-require-timezone-aware-datetime`)
//! - Top-level `dotore` routing (`analyze_source`, `analyze_source_with_config`,
//!   `analyze_project_sources`, `apply_patches_to_source`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, LanguageAnalyzer, LanguageId, PackageRole,
    PrescriptionTier, PyLanguageAnalyzer, RuleId, SymbolKind, WorkspacePackage,
    analyze_project_sources, analyze_source, analyze_source_with_config, apply_patches_to_source,
    search_project_sources,
};

#[test]
fn py_no_mutable_default_arg_flags_mutable_defaults_and_autofixes_cleanly() {
    let invalid_src = r#"def append_tag(tag: str, tags=[], metadata: dict = {}, seen=set()):
    """Appends a tag and returns the collection."""
    tags.append(tag)
    return tags
"#;

    let diags = analyze_source(
        Path::new("app/tags.py"),
        invalid_src,
        Some(&[RuleId::PyNoMutableDefaultArg]),
    );
    assert_eq!(diags.len(), 3, "Expected 3 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyNoMutableDefaultArg);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert_eq!(diag.subject_name.as_deref(), Some("append_tag"));
        assert_eq!(diag.loc.line, 1);
        assert!(diag.autofix.is_some());
    }
    assert_eq!(diags[0].target_name, "tags");
    assert_eq!(diags[1].target_name, "metadata");
    assert_eq!(diags[2].target_name, "seen");

    // Round-trip Autofix verification
    let (patched, descriptions) = apply_patches_to_source(invalid_src, &diags);
    assert_eq!(descriptions.len(), 3);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/tags.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(patched.contains("tags=None"));
    assert!(patched.contains("metadata: dict = None"));
    assert!(patched.contains("seen=None"));
    assert!(patched.contains("if tags is None:\n        tags = []"));
    assert!(patched.contains("if metadata is None:\n        metadata = {}"));
    assert!(patched.contains("if seen is None:\n        seen = set()"));

    let reanalyzed = analyze_source(
        Path::new("app/tags.py"),
        &patched,
        Some(&[RuleId::PyNoMutableDefaultArg]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after Autofix, got {reanalyzed:?}\nPatched:\n{patched}"
    );

    // Adversarial valid cases: None, tuples, frozenset, literals, .pyi stubs, and non-Python gate
    let valid_src = r#"def safe_fn(
    items: list[str] | None = None,
    coords: tuple[int, int] = (0, 0),
    frozen: frozenset[str] = frozenset(),
    name: str = "default",
    count: int = 0,
):
    if items is None:
        items = []
    return items
"#;
    assert!(
        analyze_source(
            Path::new("app/safe.py"),
            valid_src,
            Some(&[RuleId::PyNoMutableDefaultArg]),
        )
        .is_empty()
    );

    // .pyi stub files should not be flagged for default values
    let stub_src = "def append_tag(tag: str, tags: list[str] = []) -> list[str]: ...\n";
    assert!(
        analyze_source(
            Path::new("app/tags.pyi"),
            stub_src,
            Some(&[RuleId::PyNoMutableDefaultArg]),
        )
        .is_empty()
    );

    // Non-Python capability gate should not run Python rules
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    assert!(
        analyze_source_with_config(
            Path::new("app/tags.py"),
            invalid_src,
            &DotoreConfig::default(),
            &react_only_gate,
            None,
        )
        .is_empty()
    );
}
#[test]
fn py_no_silent_broad_except_flags_swallowed_broad_exceptions_and_allows_handled_or_specific() {
    let invalid_src = r#"def sync_records(records):
    try:
        process_first(records)
    except:
        pass

    try:
        process_second(records)
    except Exception:
        ...

    try:
        process_third(records)
    except (ValueError, BaseException) as err:
        "swallowed"
"#;

    let diags = analyze_source(
        Path::new("app/sync.py"),
        invalid_src,
        Some(&[RuleId::PyNoSilentBroadExcept]),
    );
    assert_eq!(diags.len(), 3, "Expected 3 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyNoSilentBroadExcept);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].subject_name.as_deref(), Some("sync_records"));
    assert_eq!(diags[0].loc.line, 4);
    assert_eq!(diags[1].loc.line, 9);
    assert_eq!(diags[2].loc.line, 14);

    let valid_src = r#"import logging

logger = logging.getLogger(__name__)

def parse_optional_int(raw: str) -> int | None:
    try:
        return int(raw)
    except ValueError:
        pass

    try:
        return int(raw, 16)
    except (ValueError, TypeError):
        return None

def run_safely(task):
    try:
        task()
    except Exception as exc:
        logger.exception("Task failed: %s", exc)

    try:
        task()
    except BaseException:
        cleanup()
        raise
"#;
    assert!(
        analyze_source(
            Path::new("app/safe_sync.py"),
            valid_src,
            Some(&[RuleId::PyNoSilentBroadExcept]),
        )
        .is_empty()
    );
}

#[test]
fn py_require_context_manager_for_resource_flags_unmanaged_files_and_db_sessions() {
    let invalid_src = r#"import sqlite3
from sqlalchemy.orm import Session

def load_report(path: str, engine):
    handle = open(path, "r")
    raw = open("header.txt").read()
    conn = sqlite3.connect(":memory:")
    session = Session(engine)
    return handle, raw, conn, session
"#;

    let diags = analyze_source(
        Path::new("app/resources.py"),
        invalid_src,
        Some(&[RuleId::PyRequireContextManagerForResource]),
    );
    assert_eq!(diags.len(), 4, "Expected 4 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyRequireContextManagerForResource);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].subject_name.as_deref(), Some("load_report"));
    assert_eq!(diags[0].loc.line, 5);
    assert_eq!(diags[1].loc.line, 6);
    assert_eq!(diags[2].loc.line, 7);
    assert_eq!(diags[3].loc.line, 8);

    let valid_src = r#"from contextlib import closing, contextmanager
import sqlite3
from sqlalchemy.orm import Session

def load_safely(path: str, engine):
    with open(path, "r", encoding="utf-8") as handle:
        data = handle.read()

    with closing(sqlite3.connect(":memory:")) as conn:
        conn.execute("SELECT 1")

    with Session(engine) as session:
        session.commit()

    return data

def create_reader(path: str):
    return open(path, "rb")

@contextmanager
def get_db(SessionLocal):
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
"#;
    assert!(
        analyze_source(
            Path::new("app/safe_resources.py"),
            valid_src,
            Some(&[RuleId::PyRequireContextManagerForResource]),
        )
        .is_empty()
    );
}

#[test]
fn py_no_unguarded_parse_or_key_access_flags_unguarded_loads_numeric_parses_and_dict_indexing() {
    let invalid_src = r#"import json
import os

def handle_webhook(raw_body: str, payload: dict, request):
    parsed = json.loads(raw_body)
    limit = int(request.query_params)
    ratio = float(raw_body)
    user_id = payload["user_id"]
    auth = request.headers["Authorization"]
    api_key = os.environ["API_KEY"]
    return parsed, limit, ratio, user_id, auth, api_key
"#;

    let diags = analyze_source(
        Path::new("app/webhook.py"),
        invalid_src,
        Some(&[RuleId::PyNoUnguardedParseOrKeyAccess]),
    );
    assert_eq!(diags.len(), 6, "Expected 6 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyNoUnguardedParseOrKeyAccess);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("handle_webhook"));
    }
    assert_eq!(diags[0].loc.line, 5);
    assert_eq!(diags[1].loc.line, 6);
    assert_eq!(diags[2].loc.line, 7);
    assert_eq!(diags[3].loc.line, 8);
    assert_eq!(diags[4].loc.line, 9);
    assert_eq!(diags[5].loc.line, 10);

    let valid_src = r#"import json
import os

def handle_webhook_safely(raw_body: str, raw_limit: str, payload: dict[str, str], items: list[int]):
    # Literal numeric conversions and list indexing are safe
    base_timeout = int("30")
    scale = float(2)
    first_item = items[0]
    slice_items = items[1:3]

    # Guarded by try/except
    try:
        parsed = json.loads(raw_body)
        limit = int(raw_limit)
        org_id = payload["org_id"]
    except (json.JSONDecodeError, ValueError, KeyError):
        return None

    # Guarded by .isdigit()
    if raw_limit.isdigit():
        checked_limit = int(raw_limit)

    # Guarded by `key in dict`
    if "user_id" in payload:
        user_id = payload["user_id"]
    else:
        user_id = payload.get("user_id", "anon")

    # Guarded by early-exit `key not in dict`
    if "tenant_id" not in payload:
        return None
    tenant_id = payload["tenant_id"]

    # Safe dictionary write and .get()
    payload["processed"] = "true"
    api_key = os.environ.get("API_KEY")
    return base_timeout, scale, first_item, slice_items, parsed, limit, org_id, checked_limit, user_id, tenant_id, api_key
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_webhook.py"),
        valid_src,
        Some(&[RuleId::PyNoUnguardedParseOrKeyAccess]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on guarded code, got {valid_diags:?}"
    );
}

#[test]
fn py_require_timezone_aware_datetime_flags_naive_now_and_utcnow_and_autofixes() {
    let invalid_src = r#"from datetime import datetime, timezone
import datetime as dt_mod

def build_audit_timestamps(epoch_ts: float):
    created_at = datetime.now()
    legacy_utc = datetime.utcnow()
    qualified_now = dt_mod.datetime.now()
    qualified_utc = dt_mod.datetime.utcnow()
    from_ts = datetime.fromtimestamp(epoch_ts)
    return created_at, legacy_utc, qualified_now, qualified_utc, from_ts
"#;

    let diags = analyze_source(
        Path::new("app/timestamps.py"),
        invalid_src,
        Some(&[RuleId::PyRequireTimezoneAwareDatetime]),
    );
    assert_eq!(diags.len(), 5, "Expected 5 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyRequireTimezoneAwareDatetime);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert_eq!(diag.subject_name.as_deref(), Some("build_audit_timestamps"));
        assert!(diag.autofix.is_some());
    }
    assert_eq!(diags[0].loc.line, 5);
    assert_eq!(diags[1].loc.line, 6);
    assert_eq!(diags[2].loc.line, 7);
    assert_eq!(diags[3].loc.line, 8);
    assert_eq!(diags[4].loc.line, 9);

    // Round-trip Autofix verification
    let (patched, descriptions) = apply_patches_to_source(invalid_src, &diags);
    assert_eq!(descriptions.len(), 5);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/timestamps.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(patched.contains("created_at = datetime.now(timezone.utc)"));
    assert!(patched.contains("legacy_utc = datetime.now(timezone.utc)"));
    assert!(patched.contains("qualified_now = dt_mod.datetime.now(dt_mod.timezone.utc)"));
    assert!(patched.contains("qualified_utc = dt_mod.datetime.now(dt_mod.timezone.utc)"));
    assert!(patched.contains("from_ts = datetime.fromtimestamp(epoch_ts, tz=timezone.utc)"));

    let reanalyzed = analyze_source(
        Path::new("app/timestamps.py"),
        &patched,
        Some(&[RuleId::PyRequireTimezoneAwareDatetime]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after Autofix, got {reanalyzed:?}\nPatched:\n{patched}"
    );

    // Adversarial valid cases
    let valid_src = r#"from datetime import datetime, timezone
from zoneinfo import ZoneInfo

def build_safe_timestamps(epoch_ts: float):
    a = datetime.now(timezone.utc)
    b = datetime.now(tz=timezone.utc)
    c = datetime.now(ZoneInfo("UTC"))
    d = datetime.fromtimestamp(epoch_ts, tz=timezone.utc)
    e = datetime.fromtimestamp(epoch_ts, timezone.utc)
    return a, b, c, d, e
"#;
    assert!(
        analyze_source(
            Path::new("app/safe_timestamps.py"),
            valid_src,
            Some(&[RuleId::PyRequireTimezoneAwareDatetime]),
        )
        .is_empty()
    );
}

#[test]
fn analyze_project_sources_discovers_pyproject_capabilities_and_supports_inline_suppressions() {
    let pyproject = r#"
[project]
name = "orders-service"
dependencies = [
    "fastapi[standard]>=0.115.0",
    "pydantic>=2.9.0",
    "sqlalchemy[asyncio]>=2.0.0",
]

[dependency-groups]
dev = ["pytest>=8.0", "django>=5.1"]
"#;

    let service_py = r#"from datetime import datetime
import json

class OrderProcessor:
    """Handles incoming order payloads."""

    # dotore-disable-next-line py-no-mutable-default-arg
    def suppressed_default(self, cache=[]):
        return cache

    def process(self, raw_payload: str, items=[]):
        data = json.loads(raw_payload)  # dotore-disable-line py-no-unguarded-parse-or-key-access
        try:
            risky()
        except Exception:  # noqa: BLE001
            pass

        now = datetime.now()
        handle = open("audit.log", "a")
        return data, items, now, handle
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), pyproject.to_string()),
            (PathBuf::from("app/service.py"), service_py.to_string()),
        ],
        None,
    );

    assert_eq!(report.projects.len(), 1);
    let proj = &report.projects[0];
    assert!(proj.capabilities.contains(&Capability::Python));
    assert!(proj.capabilities.contains(&Capability::FastApi));
    assert!(proj.capabilities.contains(&Capability::Pydantic));
    assert!(proj.capabilities.contains(&Capability::SqlAlchemy));
    assert!(proj.capabilities.contains(&Capability::Asyncio));
    assert!(proj.capabilities.contains(&Capability::Pytest));
    assert!(proj.capabilities.contains(&Capability::Django));
    assert_eq!(proj.subjects_scanned, 3);

    // Suppressed: `suppressed_default` (py-no-mutable-default-arg), `json.loads` (py-no-unguarded-parse-or-key-access), `except Exception:` (noqa: BLE001)
    // Active: `items=[]` on `process`, `datetime.now()`, `open("audit.log", "a")`
    let rules: Vec<RuleId> = report.diagnostics.iter().map(|d| d.rule).collect();
    assert_eq!(
        rules.len(),
        3,
        "Expected 3 unsuppressed diagnostics, got {:?}",
        report.diagnostics
    );
    assert!(rules.contains(&RuleId::PyNoMutableDefaultArg));
    assert!(rules.contains(&RuleId::PyRequireTimezoneAwareDatetime));
    assert!(rules.contains(&RuleId::PyRequireContextManagerForResource));

    // Verify FixCapsule generation for Surgical rule (py-require-context-manager-for-resource)
    assert!(!report.root_cause_groups.is_empty());
    assert!(
        report
            .fix_capsules
            .iter()
            .any(|c| c.rule == RuleId::PyRequireContextManagerForResource
                && c.subject_excerpt.source.contains("def process"))
    );
}

#[test]
fn py_language_analyzer_contract_and_symbol_search_integration() {
    let analyzer = PyLanguageAnalyzer::new();
    assert_eq!(analyzer.language_id(), LanguageId::Python);
    assert!(analyzer.supports_path(Path::new("pkg/module.py")));
    assert!(analyzer.supports_path(Path::new("pkg/module.pyi")));
    assert!(!analyzer.supports_path(Path::new("pkg/module.ts")));
    assert_eq!(
        analyzer.manifest_filenames(),
        &["pyproject.toml", "requirements.txt"]
    );

    let py_src = r#"DEFAULT_BATCH_SIZE = 100

class InvoiceGenerator:
    """Generates customer invoices."""

    def generate_invoice(self, customer_id: str, lines=[]):
        """Builds an invoice for a customer."""
        return {"customer_id": customer_id, "lines": lines}
"#;
    let extracted = analyzer.extract_file(Path::new("billing/invoices.py"), py_src);
    assert_eq!(extracted.subjects_count, 2);
    assert!(
        extracted
            .symbol_outlines
            .iter()
            .any(|s| s.name == "DEFAULT_BATCH_SIZE" && s.kind == SymbolKind::Constant)
    );
    assert!(
        extracted
            .symbol_outlines
            .iter()
            .any(|s| s.name == "InvoiceGenerator"
                && s.kind == SymbolKind::Class
                && s.doc_comment.as_deref() == Some("Generates customer invoices."))
    );
    assert!(
        extracted
            .symbol_outlines
            .iter()
            .any(|s| s.name == "generate_invoice"
                && s.kind == SymbolKind::Method
                && s.parent_name.as_deref() == Some("InvoiceGenerator"))
    );

    let pkg = WorkspacePackage {
        name: "billing".to_string(),
        root_dir: PathBuf::from("billing"),
        capability_gate: CapabilityGate::default_python(),
        config: DotoreConfig::default(),
    };
    let result = analyzer.analyze_package(&pkg, &[extracted], None);
    assert_eq!(result.subjects_scanned, 2);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].rule, RuleId::PyNoMutableDefaultArg);

    // Verify fuzzy Symbol Outline search works on Python files via top-level `search_project_sources`
    let search_hits = search_project_sources(
        "generate_invoice",
        &[(PathBuf::from("billing/invoices.py"), py_src.to_string())],
        Some(&[SymbolKind::Method]),
        10,
    );
    assert_eq!(search_hits.len(), 1);
    assert_eq!(search_hits[0].outline.name, "generate_invoice");
    assert_eq!(
        search_hits[0].outline.parent_name.as_deref(),
        Some("InvoiceGenerator")
    );
}

#[test]
fn pyproject_toml_tool_dotore_config_and_profiles_are_loaded_and_applied() {
    let analyzer = PyLanguageAnalyzer::new();

    // 1. Profile inference: library ([build-system]), web (fastapi/flask), cli (click or [project.scripts]), script (profile override)
    let lib_pyproject = r#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-sdk"
version = "0.1.0"
"#;
    let lib_gate = analyzer.infer_capability_gate(
        Path::new("packages/my-sdk"),
        &[(PathBuf::from("packages/my-sdk/pyproject.toml"), lib_pyproject)],
    );
    assert_eq!(lib_gate.package_role, PackageRole::Library);

    let web_pyproject = r#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "web-app"
dependencies = ["flask>=3.0"]
"#;
    let web_gate = analyzer.infer_capability_gate(
        Path::new("apps/web"),
        &[(PathBuf::from("apps/web/pyproject.toml"), web_pyproject)],
    );
    assert_eq!(web_gate.package_role, PackageRole::Application);

    let cli_pyproject = r#"
[project]
name = "my-cli"
dependencies = ["click>=8.1"]

[project.scripts]
my-cli = "my_cli.main:cli"
"#;
    let cli_gate = analyzer.infer_capability_gate(
        Path::new("apps/cli"),
        &[(PathBuf::from("apps/cli/pyproject.toml"), cli_pyproject)],
    );
    assert_eq!(cli_gate.package_role, PackageRole::Application);

    // 2. [tool.dotore] suppress, per-file-suppress, rules, and profile override
    let configured_pyproject = r#"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "configured-app"
version = "0.1.0"

[tool.dotore]
profile = "script"
suppress = ["py-require-timezone-aware-datetime"]

[tool.dotore.per-file-suppress]
"app/legacy/*" = ["B006"]
"app/compat.py" = "exceptions/silent"

[tool.dotore.rules]
"py-require-context-manager-for-resource" = "off"
"#;
    let cfg = DotoreConfig::from_pyproject_toml_str(configured_pyproject)
        .expect("Expected DotoreConfig from [tool.dotore]");
    assert!(cfg.effective_severity(RuleId::PyRequireTimezoneAwareDatetime).is_none());
    assert!(cfg.effective_severity(RuleId::PyRequireContextManagerForResource).is_none());
    assert!(cfg.is_overridden_for_file(
        RuleId::PyNoMutableDefaultArg,
        Path::new("app/legacy/old.py"),
        Path::new("."),
    ));
    assert!(cfg.is_overridden_for_file(
        RuleId::PyNoSilentBroadExcept,
        Path::new("app/compat.py"),
        Path::new("."),
    ));

    let legacy_py = r#"from datetime import datetime
__all__ = ["old_fn"]

def old_fn(items=[]):
    now = datetime.now()
    f = open("data.txt", "r")
    return items, now, f
"#;
    let active_py = r#"__all__ = ["active_fn"]
def active_fn(items: list = []):
    return items
"#;
    let report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), configured_pyproject.to_string()),
            (PathBuf::from("app/legacy/old.py"), legacy_py.to_string()),
            (PathBuf::from("app/active.py"), active_py.to_string()),
        ],
        None,
    );
    assert_eq!(
        report.diagnostics.len(),
        1,
        "Expected only active.py B006 to fire after pyproject.toml suppressions, got {:?}",
        report.diagnostics
    );
    assert_eq!(report.diagnostics[0].file, PathBuf::from("app/active.py"));
    assert_eq!(report.diagnostics[0].rule, RuleId::PyNoMutableDefaultArg);

    // 3. CLI profile auto-suppresses bandit/B110 (py-no-silent-broad-except) when `enabled_rules` is None
    let cli_code = r#"def run_cli():
    try:
        optional_cleanup()
    except Exception:
        pass
"#;
    let cli_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), cli_pyproject.to_string()),
            (PathBuf::from("my_cli/main.py"), cli_code.to_string()),
        ],
        None,
    );
    assert!(
        !cli_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyNoSilentBroadExcept),
        "Expected CLI profile to auto-suppress bandit/B110 (py-no-silent-broad-except), got {:?}",
        cli_report.diagnostics
    );
    // 4. `script` profile inferred when `pyproject.toml` has `[project]` without `[build-system]` and without web/cli deps,
    //    suppressing library-only `py-structure-missing-py-typed` and `py-structure-low-type-hint-coverage`.
    let script_pyproject = r#"
[project]
name = "data-runner"
version = "0.1.0"
dependencies = ["requests>=2.31"]
"#;
    let script_gate = analyzer.infer_capability_gate(
        Path::new("scripts/runner"),
        &[(PathBuf::from("scripts/runner/pyproject.toml"), script_pyproject)],
    );
    assert_eq!(script_gate.package_role, PackageRole::Application);
    let script_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), script_pyproject.to_string()),
            (
                PathBuf::from("run_a.py"),
                "def step_a(x: int) -> int:\n    return x + 1\n".to_string(),
            ),
            (
                PathBuf::from("run_b.py"),
                "def step_b(y):\n    return y * 2\n".to_string(),
            ),
            (
                PathBuf::from("run_c.py"),
                "def step_c(z):\n    return z - 1\n".to_string(),
            ),
        ],
        None,
    );
    assert!(
        !script_report.diagnostics.iter().any(|d| matches!(
            d.rule,
            RuleId::PyStructureMissingPyTyped | RuleId::PyStructureLowTypeHintCoverage
        )),
        "Expected script profile to suppress library-only structure rules, got: {:?}",
        script_report.diagnostics
    );
}

#[test]
fn py_structure_missing_py_typed_and_low_type_hint_coverage_evaluate_on_packages() {
    let lib_pyproject = r#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "typed-sdk"
version = "0.1.0"
"#;
    let typed_init = r#"from typed_sdk.client import Client
__all__ = ["Client"]
"#;
    let typed_client = r#"__all__ = ["Client"]

class Client:
    base_url: str

    def fetch(self, path: str) -> dict[str, str]:
        return {"url": f"{self.base_url}/{path}"}
"#;

    // 1. Typed library WITHOUT `py.typed` -> flags `py-structure-missing-py-typed`
    let missing_marker_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), lib_pyproject.to_string()),
            (PathBuf::from("typed_sdk/__init__.py"), typed_init.to_string()),
            (PathBuf::from("typed_sdk/client.py"), typed_client.to_string()),
        ],
        None,
    );
    assert!(
        missing_marker_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyStructureMissingPyTyped),
        "Expected py-structure-missing-py-typed on typed library without py.typed, got {:?}",
        missing_marker_report.diagnostics
    );

    // 2. Typed library WITH `py.typed` -> 0 `py-structure-missing-py-typed` diagnostics
    let with_marker_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), lib_pyproject.to_string()),
            (PathBuf::from("typed_sdk/py.typed"), String::new()),
            (PathBuf::from("typed_sdk/__init__.py"), typed_init.to_string()),
            (PathBuf::from("typed_sdk/client.py"), typed_client.to_string()),
        ],
        None,
    );
    assert!(
        !with_marker_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyStructureMissingPyTyped),
        "Expected 0 py-structure-missing-py-typed when py.typed is present, got {:?}",
        with_marker_report.diagnostics
    );

    // 3. Web application WITHOUT `py.typed` -> 0 `py-structure-missing-py-typed` diagnostics
    let web_pyproject = r#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "web-service"
dependencies = ["fastapi>=0.115.0"]
"#;
    let web_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), web_pyproject.to_string()),
            (PathBuf::from("typed_sdk/__init__.py"), typed_init.to_string()),
            (PathBuf::from("typed_sdk/client.py"), typed_client.to_string()),
        ],
        None,
    );
    assert!(
        !web_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyStructureMissingPyTyped),
        "Expected 0 py-structure-missing-py-typed on web application profile, got {:?}",
        web_report.diagnostics
    );

    // 4. Low type-hint coverage (< 50% of non-test .py files have type annotations)
    // 1 typed production file + 2 untyped production files = 33.3% (< 50%), plus 1 typed test file (ignored)
    let untyped_a = r#"__all__ = ["compute_a"]
def compute_a(x, y):
    return x + y
"#;
    let untyped_b = r#"__all__ = ["compute_b"]
def compute_b(items):
    return len(items)
"#;
    let typed_test = r#"def test_compute(x: int) -> None:
    assert x == 1
"#;
    let low_coverage_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), web_pyproject.to_string()),
            (PathBuf::from("app/typed_mod.py"), typed_client.to_string()),
            (PathBuf::from("app/untyped_a.py"), untyped_a.to_string()),
            (PathBuf::from("app/untyped_b.py"), untyped_b.to_string()),
            (PathBuf::from("tests/test_app.py"), typed_test.to_string()),
        ],
        None,
    );
    assert!(
        low_coverage_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyStructureLowTypeHintCoverage),
        "Expected py-structure-low-type-hint-coverage when only 1/3 production files have type hints, got {:?}",
        low_coverage_report.diagnostics
    );

    // 5. Sufficient type-hint coverage (>= 50%: 2 of 3 production files have type annotations)
    let typed_b = r#"__all__ = ["compute_b"]
def compute_b(items: list[str]) -> int:
    return len(items)
"#;
    let good_coverage_report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), web_pyproject.to_string()),
            (PathBuf::from("app/typed_mod.py"), typed_client.to_string()),
            (PathBuf::from("app/untyped_a.py"), untyped_a.to_string()),
            (PathBuf::from("app/typed_b.py"), typed_b.to_string()),
        ],
        None,
    );
    assert!(
        !good_coverage_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::PyStructureLowTypeHintCoverage),
        "Expected 0 py-structure-low-type-hint-coverage when 2/3 production files have type hints, got {:?}",
        good_coverage_report.diagnostics
    );
}
