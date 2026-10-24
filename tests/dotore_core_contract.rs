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

    assert_eq!(DiffScope::parse("contextual"), Some(DiffScope::Contextual));
    assert_eq!(normalize_ast_tokens("foo( 'bar' )"), "foo ( \"bar\" )");
    let _ = filter_diagnostics_by_scope::<ExtractedFile>;

    assert_eq!(JSON_REPORT_SCHEMA_VERSION, 3);
    let empty_report = build_extracted_report(&[], Vec::new(), &std::collections::HashMap::new());
    assert!(format_terminal_report(&empty_report).contains("HEALTH SCORE"));
    assert!(render_html_report(&empty_report).contains("<!DOCTYPE html>"));
    assert!(explain_rule("no-derived-state", &default_cfg).is_some());
    assert_eq!(parse_why_location("src/App.tsx:10").unwrap().line, 10);
    assert_eq!(
        CiProviderKind::parse("github"),
        Some(CiProviderKind::GithubActions)
    );
}

#[test]
fn json_report_and_diagnostics_roundtrip_serialize_and_read_json_report() {
    use dotore::{JsonReport, read_json_report, write_json_report};

    let bad_src = r#"import { useState, useEffect } from 'react';
export function Form({ first, last, onSubmit }: { first: string; last: string; onSubmit: () => void }) {
    const [full, setFull] = useState('');
    const [submitted, setSubmitted] = useState(false);
    useEffect(() => {
        setFull(first + ' ' + last);
    }, [first, last]);
    useEffect(() => {
        if (submitted) {
            onSubmit();
        }
    }, [submitted, onSubmit]);
    return <button onClick={() => setSubmitted(true)}>{full}</button>;
}
"#;
    let report = analyze_project_sources(
        vec![(PathBuf::from("src/Form.tsx"), bad_src.to_string())],
        Some(&[RuleId::NoDerivedState, RuleId::NoEventHandler]),
    );
    assert_eq!(report.diagnostics.len(), 2);
    assert_eq!(report.root_cause_groups.len(), 2);
    assert_eq!(report.fix_capsules.len(), 1);

    let temp_dir = std::env::temp_dir().join(format!(
        "dotore-json-roundtrip-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let report_path = temp_dir.join("report.json");
    write_json_report(&report, &report_path).unwrap();

    let loaded: JsonReport = read_json_report(&report_path).unwrap();
    assert_eq!(loaded.schema_version, report.schema_version);
    assert_eq!(loaded.summary, report.summary);
    assert_eq!(loaded.projects, report.projects);
    assert_eq!(loaded.root_cause_groups, report.root_cause_groups);
    assert_eq!(loaded.fix_capsules, report.fix_capsules);
    assert_eq!(
        loaded.diagnostic_fingerprints,
        report.diagnostic_fingerprints
    );
    assert_eq!(loaded.diagnostics.len(), report.diagnostics.len());
    assert_eq!(loaded.diagnostics[0].rule, report.diagnostics[0].rule);
    assert_eq!(loaded.diagnostics[0].autofix, report.diagnostics[0].autofix);
    assert_eq!(loaded.diagnostics[1].rule, report.diagnostics[1].rule);
    assert_eq!(loaded.diagnostics[1].message, report.diagnostics[1].message);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn pr_comment_renderer_handles_clean_failing_baseline_degraded_and_repo_blob_links() {
    use dotore::{
        BaselineSummary, PR_COMMENT_MARKER, PrCommentEnv, PrCommentRepoContext, ScanMode,
        build_extracted_report, generate_ci_comment, render_github_actions_workflow,
        render_github_pr_comment, render_gitlab_ci_snippet, render_pr_comment_markdown_with_env,
        write_github_pr_comment, write_json_report,
    };

    // 1. Clean report
    let clean_report = build_extracted_report(&[], Vec::new(), &std::collections::HashMap::new());
    let local_ctx = PrCommentRepoContext::default();
    let clean_md = render_github_pr_comment(&clean_report, &local_ctx);
    assert!(clean_md.starts_with(PR_COMMENT_MARKER));
    assert!(clean_md.contains("100/100"));
    assert!(clean_md.contains("Excellent"));
    assert!(clean_md.contains("No issues found"));

    // 2. Failing report with error + warning, GitHub blob links, GitLab blob links, and local fallback
    let bad_src = r#"import { useState, useEffect } from 'react';
export function Form({ first, last, onSubmit }: { first: string; last: string; onSubmit: () => void }) {
    const [full, setFull] = useState('');
    const [submitted, setSubmitted] = useState(false);
    useEffect(() => {
        setFull(first + ' ' + last);
    }, [first, last]);
    useEffect(() => {
        if (submitted) {
            onSubmit();
        }
    }, [submitted, onSubmit]);
    return <button onClick={() => setSubmitted(true)}>{full}</button>;
}
"#;
    let mut failing_report = analyze_project_sources(
        vec![(PathBuf::from("src/Form.tsx"), bad_src.to_string())],
        Some(&[RuleId::NoDerivedState, RuleId::NoEventHandler]),
    );

    let local_failing_md = render_github_pr_comment(&failing_report, &local_ctx);
    assert!(local_failing_md.starts_with(PR_COMMENT_MARKER));
    assert!(local_failing_md.contains("`src/Form.tsx:6`"));
    assert!(local_failing_md.contains("`src/Form.tsx:9`"));
    assert!(local_failing_md.contains("<details>"));
    assert!(local_failing_md.contains("Warnings (1)"));

    let gh_ctx = PrCommentRepoContext::github("acme/web-app", "deadbeef12345678")
        .with_server_url("https://github.example.com/");
    let gh_md = render_pr_comment_markdown_with_env(&failing_report, &gh_ctx);
    assert!(gh_md.contains(
        "[src/Form.tsx:6](https://github.example.com/acme/web-app/blob/deadbeef12345678/src/Form.tsx#L6)"
    ));
    assert!(gh_md.contains(
        "[src/Form.tsx:9](https://github.example.com/acme/web-app/blob/deadbeef12345678/src/Form.tsx#L9)"
    ));

    let gl_ctx = PrCommentEnv::gitlab("https://gitlab.example.com/acme/web-app/", "cafebabe99");
    let gl_md = render_github_pr_comment(&failing_report, &gl_ctx);
    assert!(gl_md.contains(
        "[src/Form.tsx:6](https://gitlab.example.com/acme/web-app/-/blob/cafebabe99/src/Form.tsx#L6)"
    ));

    // 3. Baseline delta (--baseline introduced/fixed)
    failing_report.mode = ScanMode::Baseline;
    failing_report.baseline = Some(BaselineSummary {
        baseline_source: "origin/main".to_string(),
        introduced_count: 2,
        fixed_count: 3,
        preexisting_count: 5,
        baseline_total_count: 8,
    });
    let baseline_md = render_github_pr_comment(&failing_report, &gh_ctx);
    assert!(baseline_md.contains("origin/main"));
    assert!(baseline_md.contains("+2"));
    assert!(baseline_md.contains("-3"));
    assert!(baseline_md.contains("introduced"));
    assert!(baseline_md.contains("fixed"));

    // 4. baseline_degraded shallow checkout warning & DOTORE_SILENCE_MISSING_BASELINE_WARNING suppression
    failing_report.baseline_degraded = true;
    let degraded_md = render_github_pr_comment(&failing_report, &gh_ctx);
    assert!(degraded_md.contains("Shallow checkout detected"));
    assert!(degraded_md.contains("fetch-depth: 0"));
    assert!(degraded_md.contains("DOTORE_SILENCE_MISSING_BASELINE_WARNING=true"));

    let silenced_ctx = gh_ctx.clone().with_silence_missing_baseline_warning(true);
    let silenced_md = render_github_pr_comment(&failing_report, &silenced_ctx);
    assert!(!silenced_md.contains("Shallow checkout detected"));
    assert!(!silenced_md.contains("fetch-depth: 0"));

    // 5. write_github_pr_comment & generate_ci_comment
    let temp_dir = std::env::temp_dir().join(format!(
        "dotore-pr-comment-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let report_path = temp_dir.join("report.json");
    let comment_path = temp_dir.join("comment.md");
    write_json_report(&failing_report, &report_path).unwrap();
    let written = write_github_pr_comment(&failing_report, &comment_path, &gh_ctx).unwrap();
    assert_eq!(std::fs::read_to_string(&comment_path).unwrap(), written);

    let gen_path = temp_dir.join("gen-comment.md");
    let generated = generate_ci_comment(&report_path, Some(&gen_path)).unwrap();
    assert!(generated.starts_with(PR_COMMENT_MARKER));
    assert_eq!(std::fs::read_to_string(&gen_path).unwrap(), generated);
    let _ = std::fs::remove_dir_all(&temp_dir);

    // 6. Workflow templates include dotore ci comment
    let gha_wf = render_github_actions_workflow("error", "changed");
    assert!(gha_wf.contains("dotore check --scope changed --blocking error"));
    assert!(gha_wf.contains("dotore ci comment"));
    let gl_wf = render_gitlab_ci_snippet("warning", "contextual");
    assert!(gl_wf.contains("dotore check --scope contextual --blocking warning"));
    assert!(gl_wf.contains("dotore ci comment"));
}
