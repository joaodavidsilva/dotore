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
            ByteSpan { start: 320, end: 340 },
        ));
        assert!(extracted.is_suppressed(
            RuleId::PyNoMutableDefaultArg,
            15,
            ByteSpan { start: 350, end: 365 },
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
}
