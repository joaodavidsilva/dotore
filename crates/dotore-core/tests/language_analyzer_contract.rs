//! Contract tests for `dotore-core`:
//! - `LanguageAnalyzer` trait contract (`language_id`, `supports_path`, `manifest_filenames`,
//!   `infer_capability_gate`, `extract_file`, `analyze_package`, `validate_syntax`)
//! - `ExtractedFile` opaque payload downcasting, **Symbol Outlines**, **Contextual Owner** spans,
//!   and inline suppressions
//! - Extended `Capability` and `CapabilityGate` tokens for Angular, Python, and Rust
//! - `apply_patches_to_source_with_analyzers` syntax validation via `LanguageAnalyzer::validate_syntax`
//! - `diagnostic_intersects_changed_lines` and `filter_diagnostics_by_scope` over `ExtractedFile`
//! - `build_extracted_report_with_packages` (**Root-Cause Groups**, **Blast Radius**, **Fix Capsules**,
//!   repository **Exemplar** lookup, and local `0..=100` health scoring)
//! - `search_extracted_files` over `ExtractedFile` **Symbol Outlines**

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    AutofixPatch, ByteEdit, ByteSpan, Capability, CapabilityGate, CapabilityPredicate,
    ChangedFileLineRanges, Diagnostic, DiffScope, ExtractedFile, LanguageAnalyzer, LanguageId,
    LineDisableDirective, PackageAnalysisResult, PrescriptionTier, RuleCategory, RuleId,
    RuleSeverity, SourceLoc, SymbolKind, SymbolOutline, WorkspacePackage,
    apply_patches_to_source_with_analyzers, build_extracted_report_with_packages,
    compute_line_starts, diagnostic_intersects_changed_lines, filter_diagnostics_by_scope,
    loc_from_line_starts, search_extracted_files,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct MockFilePayload {
    item_names: Vec<String>,
    has_violation: bool,
    violation_span: ByteSpan,
    violation_loc: SourceLoc,
}

struct MockRustLanguageAnalyzer;

impl LanguageAnalyzer for MockRustLanguageAnalyzer {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn supports_path(&self, path: &Path) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("rs")
    }

    fn manifest_filenames(&self) -> &'static [&'static str] {
        &["Cargo.toml"]
    }

    fn infer_capability_gate(
        &self,
        _package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        let mut caps = vec![Capability::Rust];
        for (_, src) in manifest_sources {
            if src.contains("tokio") {
                caps.push(Capability::Tokio);
            }
            if src.contains("axum") {
                caps.push(Capability::Axum);
            }
            if src.contains("sqlx") {
                caps.push(Capability::Sqlx);
            }
            if src.contains("serde") {
                caps.push(Capability::Serde);
            }
            if src.contains("tracing") {
                caps.push(Capability::Tracing);
            }
            if src.contains("leptos") {
                caps.push(Capability::Leptos);
            }
            if src.contains("dioxus") {
                caps.push(Capability::Dioxus);
            }
        }
        CapabilityGate::with_capabilities(caps)
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        let line_starts = compute_line_starts(source);
        let mut extracted =
            ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Rust);

        let mut item_names = Vec::new();
        for (line_idx, line) in source.lines().enumerate() {
            let line_no = u32::try_from(line_idx + 1).unwrap_or(1);
            let trimmed = line.trim();
            if let Some(after) = trimmed.strip_prefix("// dotore-disable-next-line") {
                let rules: Vec<String> = after
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                extracted
                    .suppressions
                    .line_directives
                    .push(LineDisableDirective {
                        target_line: line_no + 1,
                        rules,
                    });
            }
            if let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("fn "))
                && let Some(name) = rest.split('(').next()
            {
                let clean_name = name.trim().to_string();
                let start_byte = source
                    .find(trimmed)
                    .and_then(|o| u32::try_from(o).ok())
                    .unwrap_or(0);
                let end_byte = u32::try_from(source.len()).unwrap_or(start_byte);
                let span = ByteSpan {
                    start: start_byte,
                    end: end_byte,
                };
                let loc = loc_from_line_starts(&line_starts, start_byte);
                extracted.subjects_count += 1;
                extracted
                    .subject_spans
                    .push((Some(clean_name.clone()), span, loc));
                extracted
                    .contextual_owner_spans
                    .function_boundary_spans
                    .push(span);
                extracted.symbol_outlines.push(SymbolOutline {
                    name: clean_name.clone(),
                    kind: SymbolKind::Function,
                    signature: trimmed.trim_end_matches('{').trim().to_string(),
                    doc_comment: None,
                    comment_start_line: None,
                    parent_name: None,
                    exported: trimmed.starts_with("pub "),
                    span,
                    signature_end_line: line_no,
                    loc,
                    end_line: u32::try_from(source.lines().count()).unwrap_or(line_no),
                });
                item_names.push(clean_name);
            }
        }

        let (has_violation, violation_span, violation_loc) =
            if let Some(pos) = source.find(".unwrap()") {
                let start = u32::try_from(pos).unwrap_or(0);
                let end = start + 9;
                (
                    true,
                    ByteSpan { start, end },
                    loc_from_line_starts(&line_starts, start),
                )
            } else {
                (false, ByteSpan::default(), SourceLoc { line: 1, column: 1 })
            };

        extracted.with_payload(MockFilePayload {
            item_names,
            has_violation,
            violation_span,
            violation_loc,
        })
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
            subjects_scanned += file.subjects_count;
            let Some(payload) = file.downcast_payload::<MockFilePayload>() else {
                continue;
            };
            if !payload.has_violation {
                continue;
            }
            let rule = RuleId::NoDerivedState;
            if let Some(allowed) = enabled_rules
                && !allowed.contains(&rule)
            {
                continue;
            }
            if package.config.respect_inline_disables
                && file.is_suppressed(rule, payload.violation_loc.line, payload.violation_span)
            {
                continue;
            }
            let subj_name = file.subject_spans.first().and_then(|(n, _, _)| n.clone());
            diagnostics.push(Diagnostic {
                file: file.path.clone(),
                subject_name: subj_name,
                rule,
                category: RuleCategory::Bugs,
                severity: RuleSeverity::Error,
                message_id: "mockUnwrap",
                tier: PrescriptionTier::Surgical,
                target_name: "unwrap".to_string(),
                message: "Avoid `.unwrap()` in production service handler.".to_string(),
                docs_url: rule.docs_url(),
                loc: payload.violation_loc,
                span: payload.violation_span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
        }

        PackageAnalysisResult {
            diagnostics,
            subjects_scanned,
            effects_scanned: 0,
        }
    }

    fn validate_syntax(&self, _path: &Path, source: &str) -> bool {
        !source.contains("SYNTAX_ERROR")
            && source.matches('{').count() == source.matches('}').count()
    }
}

#[test]
fn capability_enum_and_predicates_cover_angular_python_and_rust_ecosystems() {
    let expected = [
        (Capability::Angular, "angular"),
        (Capability::Rxjs, "rxjs"),
        (Capability::Python, "python"),
        (Capability::FastApi, "fastapi"),
        (Capability::Pydantic, "pydantic"),
        (Capability::SqlAlchemy, "sqlalchemy"),
        (Capability::Django, "django"),
        (Capability::Asyncio, "asyncio"),
        (Capability::Pytest, "pytest"),
        (Capability::Rust, "rust"),
        (Capability::Tokio, "tokio"),
        (Capability::Axum, "axum"),
        (Capability::Sqlx, "sqlx"),
        (Capability::Serde, "serde"),
        (Capability::Tracing, "tracing"),
        (Capability::Leptos, "leptos"),
        (Capability::Dioxus, "dioxus"),
    ];

    for (cap, expected_str) in expected {
        assert_eq!(cap.as_str(), expected_str);
    }

    assert_eq!(
        CapabilityPredicate::ANGULAR_ONLY.requires,
        &[Capability::Angular]
    );
    assert_eq!(
        CapabilityPredicate::PYTHON_ONLY.requires,
        &[Capability::Python]
    );
    assert_eq!(CapabilityPredicate::RUST_ONLY.requires, &[Capability::Rust]);

    // Verify Angular inference from package.json
    let ng_pkg = r#"{
        "name": "ng-dashboard",
        "dependencies": {
            "@angular/core": "^19.0.0",
            "rxjs": "^7.8.0"
        }
    }"#;
    let ng_gate = CapabilityGate::from_package_json_str(ng_pkg);
    assert!(ng_gate.has(Capability::Angular));
    assert!(ng_gate.has(Capability::Rxjs));
    assert!(ng_gate.has(Capability::TypeScript));
}

#[test]
fn language_analyzer_contract_handles_extraction_payload_downcast_planning_diff_search_and_autofix()
{
    let analyzer = MockRustLanguageAnalyzer;
    assert_eq!(analyzer.language_id(), LanguageId::Rust);
    assert_eq!(analyzer.language_id(), LanguageId::Rs);
    assert!(analyzer.supports_path(Path::new("src/handler.rs")));
    assert!(!analyzer.supports_path(Path::new("src/App.tsx")));
    assert_eq!(analyzer.manifest_filenames(), &["Cargo.toml"]);

    let cargo_toml = r#"
        [package]
        name = "payments-service"
        version = "0.1.0"

        [dependencies]
        tokio = "1"
        axum = "0.8"
        sqlx = "0.8"
        serde = "1"
    "#;
    let gate = analyzer
        .infer_capability_gate(Path::new("."), &[(PathBuf::from("Cargo.toml"), cargo_toml)]);
    assert!(gate.has(Capability::Rust));
    assert!(gate.has(Capability::Tokio));
    assert!(gate.has(Capability::Axum));
    assert!(gate.has(Capability::Sqlx));
    assert!(gate.has(Capability::Serde));
    assert!(!gate.has(Capability::Leptos));

    let bad_rs = "pub fn handle_charge(input: Option<u64>) -> u64 {\n    let amount = input.unwrap();\n    amount\n}\n";
    let suppressed_rs = "pub fn suppressed_handler(input: Option<u64>) -> u64 {\n    // dotore-disable-next-line no-derived-state\n    input.unwrap()\n}\n";
    let clean_exemplar_rs =
        "pub fn safe_handler(input: Option<u64>) -> u64 {\n    input.unwrap_or(0)\n}\n";

    let extracted_bad = analyzer.extract_file(Path::new("src/charge.rs"), bad_rs);
    let extracted_suppressed = analyzer.extract_file(Path::new("src/suppressed.rs"), suppressed_rs);
    let extracted_clean = analyzer.extract_file(Path::new("src/safe.rs"), clean_exemplar_rs);

    let payload = extracted_bad
        .downcast_payload::<MockFilePayload>()
        .expect("payload should downcast to MockFilePayload");
    assert_eq!(payload.item_names, vec!["handle_charge".to_string()]);
    assert!(payload.has_violation);

    let files = vec![extracted_bad, extracted_suppressed, extracted_clean];
    let pkg = WorkspacePackage {
        name: "payments-service".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: gate,
        config: Default::default(),
    };

    let result = analyzer.analyze_package(&pkg, &files, None);
    assert_eq!(result.subjects_scanned, 3);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].file, PathBuf::from("src/charge.rs"));
    assert_eq!(result.diagnostics[0].loc.line, 2);

    // Contextual diff filtering over ExtractedFile (`ContextualOwnerPolicy::Subject`)
    let change_on_line_3 = ChangedFileLineRanges {
        file: PathBuf::from("src/charge.rs"),
        ranges: vec![(3, 3)],
        deletion_lines: Vec::new(),
    };
    assert!(!diagnostic_intersects_changed_lines(
        &result.diagnostics[0],
        Some(&files[0]),
        Some(bad_rs),
        &change_on_line_3,
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        &result.diagnostics[0],
        Some(&files[0]),
        Some(bad_rs),
        &change_on_line_3,
        true,
    ));

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/charge.rs"), bad_rs.to_string());
    sources.insert(
        PathBuf::from("src/suppressed.rs"),
        suppressed_rs.to_string(),
    );
    sources.insert(PathBuf::from("src/safe.rs"), clean_exemplar_rs.to_string());

    let scoped = filter_diagnostics_by_scope(
        result.diagnostics.clone(),
        DiffScope::Contextual,
        Path::new("."),
        &[PathBuf::from("src/charge.rs")],
        &[change_on_line_3],
        &files,
        &sources,
    );
    assert_eq!(scoped.len(), 1);

    // Build JsonReport from ExtractedFile slice (Root-Cause Groups, Fix Capsules, Exemplars, Health Score)
    let report = build_extracted_report_with_packages(
        &files,
        result.diagnostics,
        &sources,
        std::slice::from_ref(&pkg),
    );
    assert_eq!(report.summary.files_scanned, 3);
    assert_eq!(report.summary.subjects_scanned, 3);
    assert_eq!(report.root_cause_groups.len(), 1);
    assert_eq!(report.fix_capsules.len(), 1);
    assert!(
        report.fix_capsules[0]
            .subject_excerpt
            .source
            .contains("pub fn handle_charge")
    );
    let exemplar = report.fix_capsules[0]
        .exemplar
        .as_ref()
        .expect("should discover clean exemplar from ExtractedFile");
    assert_eq!(exemplar.file, PathBuf::from("src/safe.rs"));

    // Fuzzy symbol search over ExtractedFile
    let search_hits = search_extracted_files("charge", &files, None, 10);
    assert_eq!(search_hits.len(), 1);
    assert_eq!(search_hits[0].outline.name, "handle_charge");

    // Autofix syntax validation via LanguageAnalyzer::validate_syntax
    let analyzers: &[&dyn LanguageAnalyzer] = &[&analyzer];
    let valid_patch_diag = Diagnostic {
        file: PathBuf::from("src/charge.rs"),
        subject_name: Some("handle_charge".to_string()),
        rule: RuleId::NoDerivedState,
        category: RuleCategory::Bugs,
        severity: RuleSeverity::Error,
        message_id: "mockUnwrap",
        tier: PrescriptionTier::Autofix,
        target_name: "unwrap".to_string(),
        message: "Replace `.unwrap()` with `.unwrap_or_default()`.".to_string(),
        docs_url: RuleId::NoDerivedState.docs_url(),
        loc: SourceLoc {
            line: 2,
            column: 23,
        },
        span: ByteSpan { start: 72, end: 81 },
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: Some(AutofixPatch {
            description: "Replace `.unwrap()` with `.unwrap_or_default()`".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan { start: 72, end: 81 },
                replacement: ".unwrap_or_default()".to_string(),
            }],
        }),
    };
    let (rewritten, applied) = apply_patches_to_source_with_analyzers(
        bad_rs,
        std::slice::from_ref(&valid_patch_diag),
        analyzers,
    );
    assert_eq!(applied.len(), 1);
    assert!(rewritten.contains("input.unwrap_or_default()"));

    let mut invalid_patch_diag = valid_patch_diag;
    invalid_patch_diag.autofix = Some(AutofixPatch {
        description: "Corrupt syntax".to_string(),
        edits: vec![ByteEdit {
            file: None,
            span: ByteSpan { start: 72, end: 81 },
            replacement: "SYNTAX_ERROR {{{".to_string(),
        }],
    });
    let (untouched, rejected) =
        apply_patches_to_source_with_analyzers(bad_rs, &[invalid_patch_diag], analyzers);
    assert!(rejected.is_empty());
    assert_eq!(untouched, bad_rs);
}
