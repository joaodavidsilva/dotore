//! Integration tests verifying that the root `dotore` facade crate re-exports
//! `LanguageAnalyzer`, `LanguageId`, `ExtractedFile`, `PackageAnalysisResult`,
//! and all extended Angular/Python/Rust `Capability` variants from `dotore-core`.

use std::path::{Path, PathBuf};

use dotore::{
    ByteSpan, Capability, CapabilityGate, ExtractedFile, LanguageAnalyzer, LanguageId,
    PackageAnalysisResult, RuleId, SourceLoc, WorkspacePackage,
    discover_workspace_packages_with_analyzers,
};

impl LanguageAnalyzer for StubPyAnalyzer {
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
        _package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        let mut caps = vec![Capability::Python];
        for (_, src) in manifest_sources {
            if src.contains("fastapi") {
                caps.push(Capability::FastApi);
            }
            if src.contains("pydantic") {
                caps.push(Capability::Pydantic);
            }
            if src.contains("sqlalchemy") {
                caps.push(Capability::SqlAlchemy);
            }
            if src.contains("pytest") {
                caps.push(Capability::Pytest);
            }
        }
        CapabilityGate::with_capabilities(caps)
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        let mut extracted =
            ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Python);
        extracted.subjects_count = 1;
        extracted.subject_spans.push((
            Some("handler".to_string()),
            ByteSpan {
                start: 0,
                end: u32::try_from(source.len()).unwrap_or(0),
            },
            SourceLoc { line: 1, column: 1 },
        ));
        extracted
    }

    fn analyze_package(
        &self,
        _package: &WorkspacePackage,
        files: &[ExtractedFile],
        _enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult {
        PackageAnalysisResult {
            diagnostics: Vec::new(),
            subjects_scanned: files.iter().map(|f| f.subjects_count).sum(),
            effects_scanned: 0,
        }
    }

    fn validate_syntax(&self, _path: &Path, source: &str) -> bool {
        !source.is_empty()
    }
}

struct StubPyAnalyzer;

#[test]
fn root_dotore_facade_reexports_language_analyzer_and_multi_manifest_discovery() {
    let py = StubPyAnalyzer;
    assert_eq!(py.language_id(), LanguageId::Py);
    assert!(py.supports_path(Path::new("app/main.py")));
    assert!(py.supports_path(Path::new("app/types.pyi")));
    assert!(!py.supports_path(Path::new("app/main.ts")));

    let temp_dir = std::env::temp_dir().join(format!("dotore-core-facade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(
        temp_dir.join("pyproject.toml"),
        "[project]\nname = \"api\"\ndependencies = [\"fastapi\", \"pydantic\", \"sqlalchemy\"]\n",
    )
    .unwrap();

    let analyzers: &[&dyn LanguageAnalyzer] = &[&py];
    let packages = discover_workspace_packages_with_analyzers(&temp_dir, analyzers);
    assert_eq!(packages.len(), 1);
    assert!(packages[0].capability_gate.has(Capability::Python));
    assert!(packages[0].capability_gate.has(Capability::FastApi));
    assert!(packages[0].capability_gate.has(Capability::Pydantic));
    assert!(packages[0].capability_gate.has(Capability::SqlAlchemy));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
