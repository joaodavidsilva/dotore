//! Integration tests verifying that the root `dotore` facade crate re-exports
//! `LanguageAnalyzer`, `LanguageId`, `ExtractedFile`, `PackageAnalysisResult`,
//! and all extended Angular/Python/Rust `Capability` variants from `dotore-core`.

use std::path::{Path, PathBuf};

use dotore::{
    ByteSpan, Capability, CapabilityGate, DotoreConfig, ExtractedFile, JsLanguageAnalyzer,
    LanguageAnalyzer, LanguageId, PackageAnalysisResult, RuleId, ScanOptions, SourceLoc,
    WorkspacePackage, analyze_project_sources, analyze_source, analyze_source_with_config,
    apply_patches_to_source, discover_workspace_packages_with_analyzers, scan_workspace,
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

#[test]
fn root_dotore_facade_dispatches_js_ts_entrypoints_through_js_language_analyzer() {
    let js = JsLanguageAnalyzer::new();
    assert_eq!(js.language_id(), LanguageId::Js);
    assert!(js.supports_path(Path::new("src/App.tsx")));
    assert!(js.supports_path(Path::new("src/index.mjs")));
    assert!(js.supports_path(Path::new("src/index.cjs")));
    assert_eq!(js.manifest_filenames(), &["package.json", "angular.json"]);

    let bad_src = r#"import { useState, useEffect } from 'react';
export function Form({ first, last }: { first: string; last: string }) {
    const [full, setFull] = useState('');
    useEffect(() => {
        setFull(first + ' ' + last);
    }, [first, last]);
    return <div>{full}</div>;
}
"#;
    let diags = analyze_source(
        Path::new("src/Form.tsx"),
        bad_src,
        Some(&[RuleId::NoDerivedState]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::NoDerivedState);

    let cfg_diags = analyze_source_with_config(
        Path::new("src/Form.tsx"),
        bad_src,
        &DotoreConfig::default(),
        &CapabilityGate::default_react(),
        Some(&[RuleId::NoDerivedState]),
    );
    assert_eq!(cfg_diags.len(), 1);

    let (rewritten, applied) = apply_patches_to_source(bad_src, &diags);
    assert_eq!(applied.len(), 1);
    assert!(js.validate_syntax(Path::new("src/Form.tsx"), &rewritten));
    assert!(
        analyze_source(
            Path::new("src/Form.tsx"),
            &rewritten,
            Some(&[RuleId::NoDerivedState]),
        )
        .is_empty()
    );

    let report = analyze_project_sources(
        vec![(PathBuf::from("src/Form.tsx"), bad_src.to_string())],
        Some(&[RuleId::NoDerivedState]),
    );
    assert_eq!(report.summary.files_scanned, 1);
    assert_eq!(report.summary.total_diagnostics, 1);

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-js-facade-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(temp_dir.join("src")).unwrap();
    std::fs::write(temp_dir.join("src/Form.tsx"), bad_src).unwrap();
    let (ws_report, ws_sources) = scan_workspace(&ScanOptions {
        paths: vec![temp_dir.clone()],
        include_tests: false,
        rules: Some(vec![RuleId::NoDerivedState]),
        tiers: None,
    })
    .unwrap();
    assert_eq!(ws_report.summary.files_scanned, 1);
    assert_eq!(ws_report.summary.total_diagnostics, 1);
    assert_eq!(ws_sources.len(), 1);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn root_dotore_facade_reexports_decomposed_report_diff_and_config_apis() {
    use dotore::{
        CiProviderKind, ConfigTargetKind, DiffScope, JSON_REPORT_SCHEMA_VERSION,
        build_extracted_report, explain_rule, filter_diagnostics_by_scope, format_terminal_report,
        normalize_ast_tokens, parse_why_location, render_html_report,
    };

    let default_cfg = DotoreConfig::default();
    assert!(default_cfg.warnings);
    assert_eq!(
        serde_json::to_string(&ConfigTargetKind::JsonFile).unwrap(),
        "\"json-file\""
    );

    assert_eq!(
        DiffScope::parse("contextual"),
        Some(DiffScope::Contextual)
    );
    assert_eq!(
        normalize_ast_tokens("foo( 'bar' )"),
        "foo ( \"bar\" )"
    );
    let _ = filter_diagnostics_by_scope::<ExtractedFile>;

    assert_eq!(JSON_REPORT_SCHEMA_VERSION, 3);
    let empty_report =
        build_extracted_report(&[], Vec::new(), &std::collections::HashMap::new());
    assert!(format_terminal_report(&empty_report).contains("HEALTH SCORE"));
    assert!(render_html_report(&empty_report).contains("<!DOCTYPE html>"));
    assert!(explain_rule("no-derived-state", &default_cfg).is_some());
    assert_eq!(parse_why_location("src/App.tsx:10").unwrap().line, 10);
    assert_eq!(
        CiProviderKind::parse("github"),
        Some(CiProviderKind::GithubActions)
    );
}
