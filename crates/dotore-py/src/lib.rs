//! Single-pass Python static analyzer (`PyLanguageAnalyzer`), `pyproject.toml` / `requirements.txt`
//! **Capability Gate** inference, and Python runtime, async, performance, web, ORM, security,
//! and package-graph rules.

use std::path::{Path, PathBuf};

use dotore_core::{
    CapabilityGate, ExtractedFile, LanguageAnalyzer, LanguageId, PackageAnalysisResult, RuleId,
    WorkspacePackage,
};
use ruff_python_ast::PySourceType;
use ruff_python_parser::parse_unchecked_source;

pub(crate) mod asyncio;
pub(crate) mod fastapi_pydantic;
pub(crate) mod graph;
pub(crate) mod ir;
pub(crate) mod manifest;
pub(crate) mod matchers;
pub(crate) mod orm;
pub(crate) mod perf;
pub(crate) mod safety;
pub(crate) mod security;

pub use ir::PyFileIr;

/// Python [`LanguageAnalyzer`] powered by `ruff_python_parser`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PyLanguageAnalyzer;

impl PyLanguageAnalyzer {
    /// Creates a new [`PyLanguageAnalyzer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageAnalyzer for PyLanguageAnalyzer {
    fn language_id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn supports_path(&self, path: &Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("py" | "pyi")
        )
    }

    fn manifest_filenames(&self) -> &'static [&'static str] {
        &["pyproject.toml", "requirements.txt"]
    }

    fn infer_capability_gate(
        &self,
        package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        manifest::infer_python_capability_gate(package_dir, manifest_sources)
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        ir::extract_python_file(path, source)
    }

    fn analyze_package(
        &self,
        package: &WorkspacePackage,
        files: &[ExtractedFile],
        enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult {
        let mut diagnostics = Vec::new();
        let mut subjects_scanned = 0;

        for file in files {
            if package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
            {
                continue;
            }
            subjects_scanned += file.subjects_count;
            let Some(ir) = file.downcast_payload::<PyFileIr>() else {
                continue;
            };
            for candidate in &ir.candidate_diagnostics {
                let Some(effective_sev) = matchers::resolve_active_py_rule_severity(
                    package,
                    file,
                    candidate.rule,
                    enabled_rules,
                    candidate.loc.line,
                    candidate.span,
                ) else {
                    continue;
                };
                diagnostics.push(candidate.clone().with_severity(effective_sev));
            }
        }
        graph::evaluate_package_graph_rules(package, files, enabled_rules, &mut diagnostics);

        PackageAnalysisResult {
            diagnostics,
            subjects_scanned,
            effects_scanned: 0,
        }
    }

    fn validate_syntax(&self, path: &Path, source: &str) -> bool {
        let source_type = PySourceType::from(path);
        parse_unchecked_source(source, source_type).has_valid_syntax()
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use dotore_core::{
        ByteSpan, Capability, FileContext, LanguageAnalyzer, LanguageId, RuleId, SymbolKind,
    };

    use super::{PyFileIr, PyLanguageAnalyzer};

    #[test]
    fn supports_python_paths_and_declares_manifest_filenames() {
        let analyzer = PyLanguageAnalyzer::new();
        assert_eq!(analyzer.language_id(), LanguageId::Python);
        assert!(analyzer.supports_path(Path::new("app/main.py")));
        assert!(analyzer.supports_path(Path::new("stubs/types.pyi")));
        assert!(!analyzer.supports_path(Path::new("src/App.tsx")));
        assert!(!analyzer.supports_path(Path::new("src/lib.rs")));
        assert_eq!(
            analyzer.manifest_filenames(),
            &["pyproject.toml", "requirements.txt"]
        );
    }

    #[test]
    fn infers_capability_gates_from_pyproject_toml_and_requirements_txt() {
        let analyzer = PyLanguageAnalyzer::new();

        let pyproject = r#"
[project]
name = "billing-api"
dependencies = [
    "fastapi[standard]>=0.115.0",
    "pydantic>=2.9,<3.0",
    "SQLAlchemy==2.0.35 ; python_version >= '3.11'",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

[dependency-groups]
test = ["django>=5.1"]
"#;
        let gate = analyzer.infer_capability_gate(
            Path::new("services/billing"),
            &[(PathBuf::from("services/billing/pyproject.toml"), pyproject)],
        );
        assert!(gate.has(Capability::Python));
        assert!(gate.has(Capability::FastApi));
        assert!(gate.has(Capability::Pydantic));
        assert!(gate.has(Capability::SqlAlchemy));
        assert!(gate.has(Capability::Pytest));
        assert!(gate.has(Capability::Asyncio));
        assert!(gate.has(Capability::Django));

        // Poetry + requirements.txt with comments, -r, and extras
        let poetry_pyproject = r#"
[tool.poetry]
name = "worker"

[tool.poetry.dependencies]
python = "^3.12"
pydantic-settings = "^2.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.2"
"#;
        let requirements = r#"
# Core web & DB dependencies
-r base.txt
fastapi[all]~=0.110.0 # inline comment
sqlalchemy[asyncio]>=2.0.0
"#;
        let combined_gate = analyzer.infer_capability_gate(
            Path::new("services/worker"),
            &[
                (
                    PathBuf::from("services/worker/pyproject.toml"),
                    poetry_pyproject,
                ),
                (
                    PathBuf::from("services/worker/requirements.txt"),
                    requirements,
                ),
            ],
        );
        assert!(combined_gate.has(Capability::Python));
        assert!(combined_gate.has(Capability::FastApi));
        assert!(combined_gate.has(Capability::Pydantic));
        assert!(combined_gate.has(Capability::SqlAlchemy));
        assert!(combined_gate.has(Capability::Asyncio));
        assert!(combined_gate.has(Capability::Pytest));
        assert!(!combined_gate.has(Capability::Django));
    }

    #[test]
    fn extracts_subjects_symbol_outlines_docstrings_suppressions_and_owner_spans() {
        let analyzer = PyLanguageAnalyzer::new();
        let source = r#"MAX_RETRIES = 3
default_timeout: int = 30

class OrderService:
    """Processes customer orders."""

    def __init__(self, db_url: str) -> None:
        self.db_url = db_url

    async def fetch_order(self, order_id: int) -> dict:
        """Fetches an order by ID."""
        # dotore-disable-next-line py-no-unguarded-parse-or-key-access
        return {"id": order_id}

def _helper(items=None):  # dotore-disable-line py-no-mutable-default-arg
    return items  # noqa: E501
"#;
        let extracted = analyzer.extract_file(Path::new("services/orders.py"), source);
        assert_eq!(extracted.language_id, LanguageId::Python);
        assert_eq!(extracted.file_context, FileContext::Production);
        let ir = extracted
            .downcast_payload::<PyFileIr>()
            .expect("Expected PyFileIr payload");
        assert!(ir.valid_syntax);

        // Subjects: OrderService, __init__, fetch_order, _helper
        assert_eq!(extracted.subjects_count, 4);
        let subject_names: Vec<Option<&str>> = extracted
            .subject_spans
            .iter()
            .map(|(n, _, _)| n.as_deref())
            .collect();
        assert!(subject_names.contains(&Some("OrderService")));
        assert!(subject_names.contains(&Some("OrderService.__init__")));
        assert!(subject_names.contains(&Some("OrderService.fetch_order")));
        assert!(subject_names.contains(&Some("_helper")));

        // Symbol Outlines
        let find_sym = |name: &str| {
            extracted
                .symbol_outlines
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("Missing symbol outline {name}"))
        };
        let max_retries = find_sym("MAX_RETRIES");
        assert_eq!(max_retries.kind, SymbolKind::Constant);
        assert!(max_retries.exported);

        let default_timeout = find_sym("default_timeout");
        assert_eq!(default_timeout.kind, SymbolKind::Variable);
        assert!(default_timeout.exported);

        let cls = find_sym("OrderService");
        assert_eq!(cls.kind, SymbolKind::Class);
        assert_eq!(
            cls.doc_comment.as_deref(),
            Some("Processes customer orders.")
        );
        assert!(cls.exported);

        let fetch_method = find_sym("fetch_order");
        assert_eq!(fetch_method.kind, SymbolKind::Method);
        assert_eq!(fetch_method.parent_name.as_deref(), Some("OrderService"));
        assert_eq!(
            fetch_method.doc_comment.as_deref(),
            Some("Fetches an order by ID.")
        );
        assert!(
            fetch_method
                .signature
                .contains("async def fetch_order(self, order_id: int) -> dict")
        );

        let helper_fn = find_sym("_helper");
        assert_eq!(helper_fn.kind, SymbolKind::Function);
        assert!(!helper_fn.exported);

        // Suppressions
        assert!(extracted.is_suppressed(
            RuleId::PyNoUnguardedParseOrKeyAccess,
            13,
            ByteSpan {
                start: 320,
                end: 340
            },
        ));
        assert!(extracted.is_suppressed(
            RuleId::PyNoMutableDefaultArg,
            15,
            ByteSpan {
                start: 350,
                end: 365
            },
        ));

        // Contextual Owner spans
        assert!(
            !extracted
                .contextual_owner_spans
                .function_boundary_spans
                .is_empty()
        );
    }

    #[test]
    fn validates_python_syntax_for_py_and_pyi() {
        let analyzer = PyLanguageAnalyzer::new();
        assert!(analyzer.validate_syntax(
            Path::new("app/main.py"),
            "def add(a: int, b: int) -> int:\n    return a + b\n"
        ));
        assert!(analyzer.validate_syntax(
            Path::new("app/main.pyi"),
            "def add(a: int, b: int) -> int: ...\n"
        ));
        assert!(!analyzer.validate_syntax(
            Path::new("app/broken.py"),
            "def add(a: int, :\n    return a\n"
        ));
    }

    #[test]
    fn detects_thin_entrypoint_and_mixed_io_presentation_while_allowing_cohesive_modules() {
        let analyzer = PyLanguageAnalyzer::new();
        let pkg = dotore_core::WorkspacePackage {
            name: "billing-service".to_string(),
            root_dir: PathBuf::from("services/billing"),
            capability_gate: dotore_core::CapabilityGate::default_python(),
            config: dotore_core::DotoreConfig::default(),
        };

        let bloated_main = r#"from pydantic import BaseModel
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
"#;
        let mixed_report = r#"from rich.console import Console

def render_overdue_invoices(session) -> None:
    rows = session.execute("SELECT id, total FROM invoices WHERE overdue = 1")
    console = Console()
    for row in rows:
        console.print(f"\x1b[31mOverdue invoice {row[0]}: ${row[1]}\x1b[0m")
"#;
        let thin_main = r#"import sys
from billing.runner import run_cli

def main() -> int:
    return run_cli(sys.argv[1:])

if __name__ == "__main__":
    raise SystemExit(main())
"#;

        let files = vec![
            analyzer.extract_file(Path::new("services/billing/main.py"), bloated_main),
            analyzer.extract_file(Path::new("services/billing/report.py"), mixed_report),
            analyzer.extract_file(Path::new("services/billing/__main__.py"), thin_main),
        ];

        assert!(files[0].architecture_facets.is_entrypoint);
        assert!(files[2].architecture_facets.is_entrypoint);

        let res = analyzer.analyze_package(
            &pkg,
            &files,
            Some(&[
                RuleId::ArchThinEntrypoint,
                RuleId::ArchNoMixedIoAndPresentation,
            ]),
        );

        let thin_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchThinEntrypoint)
            .collect();
        assert_eq!(thin_diags.len(), 1);
        assert_eq!(
            thin_diags[0].file,
            PathBuf::from("services/billing/main.py")
        );
        assert_eq!(thin_diags[0].severity, dotore_core::RuleSeverity::Warning);
        assert_eq!(thin_diags[0].tier, dotore_core::PrescriptionTier::Refactor);
        assert!(thin_diags[0].autofix.is_none());

        let mixed_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchNoMixedIoAndPresentation)
            .collect();
        assert_eq!(mixed_diags.len(), 1);
        assert_eq!(
            mixed_diags[0].file,
            PathBuf::from("services/billing/report.py")
        );
        assert_eq!(mixed_diags[0].severity, dotore_core::RuleSeverity::Warning);
        assert_eq!(mixed_diags[0].tier, dotore_core::PrescriptionTier::Refactor);
        assert!(mixed_diags[0].autofix.is_none());
    }

    #[test]
    fn detects_static_catalog_with_types_domain_monolith_and_inline_terminal_ui_primitives() {
        let analyzer = PyLanguageAnalyzer::new();
        let pkg = dotore_core::WorkspacePackage {
            name: "catalog-pkg".to_string(),
            root_dir: PathBuf::from("pkg"),
            capability_gate: dotore_core::CapabilityGate::default_python(),
            config: dotore_core::DotoreConfig::default(),
        };

        let mut catalog_entries = String::new();
        for i in 0..26 {
            catalog_entries.push_str(&format!("    \"RULE_{i:02}\": {{\"code\": {i}}},\n"));
        }
        let types_with_catalog = format!(
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
{catalog_entries}}}
"#
        );

        let monolith_src = r#"from pydantic import BaseModel
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
    Console().print(f"╭───╮\n│ {order_id} │\n╰───╯")

def render_payment_ansi(payment_id: str) -> None:
    Console().print(f"\x1b[32mPaid {payment_id}\x1b[0m")

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
"#;

        let ui_kit_src = r#"def draw_banner(title: str) -> str:
    return f"\x1b[1m╭──────╮\n│ {title} │\n╰──────╯\x1b[0m"
"#;

        let cohesive_parser_src = r#"def parse_header(line: str) -> str:
    return line.strip()

def parse_key(line: str) -> str:
    return line.split("=")[0].strip()

def parse_value(line: str) -> str:
    return line.split("=")[-1].strip()

def parse_section(lines: list[str]) -> dict[str, str]:
    return {parse_key(l): parse_value(l) for l in lines}

def parse_int_token(tok: str) -> int:
    return int(tok)

def parse_float_token(tok: str) -> float:
    return float(tok)

def parse_bool_token(tok: str) -> bool:
    return tok == "true"

def parse_list_tokens(raw: str) -> list[str]:
    return [x.strip() for x in raw.split(",")]

def parse_comment(line: str) -> str:
    return line.lstrip('#').strip()

def parse_identifier(raw: str) -> str:
    return raw.strip("_")

def parse_quoted(raw: str) -> str:
    return raw.strip('"')

def parse_document(text: str) -> dict[str, str]:
    return parse_section(text.splitlines())
"#;

        let files = vec![
            analyzer.extract_file(Path::new("pkg/models.py"), &types_with_catalog),
            analyzer.extract_file(Path::new("pkg/monolith.py"), monolith_src),
            analyzer.extract_file(Path::new("pkg/ui.py"), ui_kit_src),
            analyzer.extract_file(Path::new("pkg/parser.py"), cohesive_parser_src),
        ];

        let res = analyzer.analyze_package(
            &pkg,
            &files,
            Some(&[
                RuleId::ArchSeparateStaticCatalogFromTypes,
                RuleId::ArchNoMixedDomainMonolith,
                RuleId::ArchNoInlineTerminalUiPrimitives,
            ]),
        );

        let catalog_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchSeparateStaticCatalogFromTypes)
            .collect();
        assert_eq!(catalog_diags.len(), 1);
        assert_eq!(catalog_diags[0].file, PathBuf::from("pkg/models.py"));
        assert_eq!(
            catalog_diags[0].tier,
            dotore_core::PrescriptionTier::Refactor
        );

        let monolith_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchNoMixedDomainMonolith)
            .collect();
        assert_eq!(monolith_diags.len(), 1);
        assert_eq!(monolith_diags[0].file, PathBuf::from("pkg/monolith.py"));
        assert_eq!(
            monolith_diags[0].tier,
            dotore_core::PrescriptionTier::Refactor
        );

        let ui_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchNoInlineTerminalUiPrimitives)
            .collect();
        assert!(!ui_diags.is_empty());
        assert!(
            ui_diags
                .iter()
                .all(|d| d.file == Path::new("pkg/monolith.py"))
        );
        assert!(
            ui_diags
                .iter()
                .all(|d| d.tier == dotore_core::PrescriptionTier::Surgical)
        );
    }

    #[test]
    fn detects_duplicated_private_helpers_and_repeated_multi_field_constructor_calls() {
        let analyzer = PyLanguageAnalyzer::new();
        let pkg = dotore_core::WorkspacePackage {
            name: "orders-pkg".to_string(),
            root_dir: PathBuf::from("orders"),
            capability_gate: dotore_core::CapabilityGate::default_python(),
            config: dotore_core::DotoreConfig::default(),
        };

        let module_a = r#"from orders.models import DispatchJob, BuiltConfig

def _normalize_headers(raw_headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, val in raw_headers.items():
        norm_key = key.strip().lower()
        if norm_key:
            cleaned[norm_key] = val.strip()
    return cleaned

def _tiny_helper(x: int) -> int:
    return x + 1

def enqueue_first() -> DispatchJob:
    return DispatchJob(
        job_id="job-1",
        endpoint="https://api.example.com/v1",
        retries=0,
        timeout_ms=None,
        dry_run=False,
        headers={},
    )

def enqueue_second() -> DispatchJob:
    return DispatchJob(
        job_id="job-2",
        endpoint="https://api.example.com/v2",
        retries=0,
        timeout_ms=None,
        dry_run=False,
        headers={},
    )
"#;

        let module_b = r#"from orders.models import DispatchJob, BuiltConfig

def _normalize_headers(input_map: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for k, v in input_map.items():
        normalized = k.strip().lower()
        if normalized:
            result[normalized] = v.strip()
    return result

def _tiny_helper(y: int) -> int:
    return y + 1

def enqueue_third() -> DispatchJob:
    return DispatchJob(
        job_id="job-3",
        endpoint="https://api.example.com/v3",
        retries=0,
        timeout_ms=None,
        dry_run=False,
        headers={},
    )

def build_with_existing_builder() -> list[BuiltConfig]:
    return [
        BuiltConfig(a=1, b=None, c=False, d="", e=[]),
        BuiltConfig(a=2, b=None, c=False, d="", e=[]),
        BuiltConfig(a=3, b=None, c=False, d="", e=[]),
    ]
"#;

        let models_src = r#"from dataclasses import dataclass

@dataclass
class DispatchJob:
    job_id: str
    endpoint: str
    retries: int
    timeout_ms: int | None
    dry_run: bool
    headers: dict[str, str]

@dataclass
class BuiltConfig:
    a: int
    b: int | None
    c: bool
    d: str
    e: list[str]

    @classmethod
    def from_defaults(cls, a: int) -> "BuiltConfig":
        return cls(a=a, b=None, c=False, d="", e=[])
"#;

        let files = vec![
            analyzer.extract_file(Path::new("orders/service_a.py"), module_a),
            analyzer.extract_file(Path::new("orders/service_b.py"), module_b),
            analyzer.extract_file(Path::new("orders/models.py"), models_src),
        ];

        let res = analyzer.analyze_package(
            &pkg,
            &files,
            Some(&[
                RuleId::ArchNoDuplicatedHelperLogic,
                RuleId::ArchPreferFluentBuilder,
            ]),
        );

        let dup_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchNoDuplicatedHelperLogic)
            .collect();
        assert!(
            !dup_diags.is_empty(),
            "Expected ArchNoDuplicatedHelperLogic diagnostic"
        );
        assert!(
            dup_diags
                .iter()
                .all(|d| d.target_name == "_normalize_headers")
        );
        assert!(dup_diags.iter().all(|d| !d.caller_sites.is_empty()));
        assert!(
            dup_diags
                .iter()
                .all(|d| d.tier == dotore_core::PrescriptionTier::Refactor)
        );

        let builder_diags: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::ArchPreferFluentBuilder)
            .collect();
        assert!(
            !builder_diags.is_empty(),
            "Expected ArchPreferFluentBuilder diagnostic"
        );
        assert!(builder_diags.iter().all(|d| d.target_name == "DispatchJob"));
        assert!(
            builder_diags
                .iter()
                .all(|d| d.tier == dotore_core::PrescriptionTier::Refactor)
        );
    }

    #[test]
    fn respects_architecture_thresholds_suppressions_contextual_owner_spans_and_single_file_packages()
     {
        let analyzer = PyLanguageAnalyzer::new();

        // 1. Single-file package with custom threshold override (`max_entrypoint_statements = 3`)
        let mut custom_cfg = dotore_core::DotoreConfig::default();
        custom_cfg.architecture.max_entrypoint_statements = 3;
        custom_cfg.architecture.min_types_with_catalog = 2;
        custom_cfg.architecture.min_static_catalog_entries = 4;
        let custom_pkg = dotore_core::WorkspacePackage {
            name: "cli-pkg".to_string(),
            root_dir: PathBuf::from("cli"),
            capability_gate: dotore_core::CapabilityGate::default_python(),
            config: custom_cfg,
        };

        let single_cli_src = r#"from dataclasses import dataclass

@dataclass
class FlagSpec:
    name: str

@dataclass
class CommandSpec:
    cmd: str

STATIC_COMMANDS = ["run", "check", "fix", "plan", "why"]

def main() -> int:
    a = 1
    b = 2
    c = a + b
    return c
"#;
        let single_file = vec![analyzer.extract_file(Path::new("cli/cli.py"), single_cli_src)];
        let single_res = analyzer.analyze_package(
            &custom_pkg,
            &single_file,
            Some(&[
                RuleId::ArchThinEntrypoint,
                RuleId::ArchSeparateStaticCatalogFromTypes,
            ]),
        );
        assert_eq!(single_res.diagnostics.len(), 2);

        // 2. Inline suppressions (`# dotore-disable-next-line` and `# noqa`)
        let suppressed_src = r#"from pathlib import Path
import streamlit as st

def save_and_render(content: str) -> None:
    Path("report.txt").write_text(content)
    # dotore-disable-next-line arch-no-mixed-io-and-presentation
    st.markdown(content)
    # noqa: arch-no-inline-terminal-ui-primitives
    banner = "\x1b[33mWarning\x1b[0m"
"#;
        let default_pkg = dotore_core::WorkspacePackage {
            name: "app-pkg".to_string(),
            root_dir: PathBuf::from("app"),
            capability_gate: dotore_core::CapabilityGate::default_python(),
            config: dotore_core::DotoreConfig::default(),
        };
        let suppressed_file = vec![analyzer.extract_file(Path::new("app/view.py"), suppressed_src)];
        let suppressed_res = analyzer.analyze_package(
            &default_pkg,
            &suppressed_file,
            Some(&[
                RuleId::ArchNoMixedIoAndPresentation,
                RuleId::ArchNoInlineTerminalUiPrimitives,
            ]),
        );
        assert!(
            suppressed_res.diagnostics.is_empty(),
            "Expected inline suppressions to silence diagnostics, got: {:?}",
            suppressed_res.diagnostics
        );

        // 3. ContextualOwner spans include multi-keyword struct literal construction sites
        let builder_call_src = r#"def make_req():
    return JobRequest(
        id="1",
        name="sync",
        retries=0,
        timeout=None,
        dry_run=False,
    )
"#;
        let extracted_req = analyzer.extract_file(Path::new("app/req.py"), builder_call_src);
        assert_eq!(
            extracted_req.architecture_facets.struct_literal_sites.len(),
            1
        );
        let lit_span = extracted_req.architecture_facets.struct_literal_sites[0].span;
        assert!(
            extracted_req
                .contextual_owner_spans
                .element_spans
                .contains(&lit_span)
        );
    }
}
