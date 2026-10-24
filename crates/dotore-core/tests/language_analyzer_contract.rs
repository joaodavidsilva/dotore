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
    LineDisableDirective, PackageAnalysisResult, PrescriptionTier, ResolvedCallerSite,
    RuleCategory, RuleId, RuleSeverity, SourceLoc, SuppressionDirectiveKind, SymbolKind,
    SymbolOutline, WorkspacePackage, apply_patches_to_source_with_analyzers,
    build_extracted_report_with_packages, compute_line_starts,
    diagnostic_intersects_changed_lines, extract_c_style_comment_suppressions,
    extract_normalized_signature_header, filter_diagnostics_by_scope, loc_from_line_starts,
    map_rust_allow_lint_to_rules, parse_comment_disable_directive,
    parse_python_suppression_directive, rule_registry, search_extracted_files,
    tokenize_suppression_rules,
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

#[test]
fn diagnostic_and_autofix_patch_fluent_builders_populate_rule_metadata_and_chain_overrides() {
    let loc = SourceLoc {
        line: 14,
        column: 5,
    };
    let span = ByteSpan {
        start: 120,
        end: 185,
    };
    let meta = RuleId::NoDerivedState.metadata();

    let diag = Diagnostic::new(
        RuleId::NoDerivedState,
        "src/UserProfile.tsx",
        loc,
        span,
        "fullName",
        "Derived state `fullName` computed inside `useEffect`.",
    );
    assert_eq!(diag.file, PathBuf::from("src/UserProfile.tsx"));
    assert_eq!(diag.subject_name, None);
    assert_eq!(diag.rule, RuleId::NoDerivedState);
    assert_eq!(diag.category, meta.category);
    assert_eq!(diag.severity, meta.default_severity);
    assert_eq!(diag.tier, meta.default_tier);
    assert_eq!(diag.docs_url, meta.docs_url);
    assert_eq!(diag.message_id, "");
    assert_eq!(diag.target_name, "fullName");
    assert_eq!(
        diag.message,
        "Derived state `fullName` computed inside `useEffect`."
    );
    assert_eq!(diag.loc, loc);
    assert_eq!(diag.span, span);
    assert!(diag.cascade_steps.is_empty());
    assert!(diag.caller_sites.is_empty());
    assert!(diag.autofix.is_none());

    let builder_diag = Diagnostic::builder(
        RuleId::NoDerivedState,
        "src/UserProfile.tsx",
        loc,
        span,
        "fullName",
        "Derived state `fullName` computed inside `useEffect`.",
    );
    assert_eq!(builder_diag, diag);

    let caller_site = ResolvedCallerSite {
        caller_file: PathBuf::from("src/App.tsx"),
        parent_subject_name: Some("App".to_string()),
        component_name: "UserProfile".to_string(),
        loc: SourceLoc { line: 8, column: 9 },
        span: ByteSpan { start: 60, end: 95 },
        has_key: false,
        passed_props: vec!["userId".to_string()],
    };

    let patch = AutofixPatch::replace(
        "Compute `fullName` inline during render",
        span,
        "const fullName = `${first} ${last}`;",
    )
    .with_edit(ByteSpan { start: 40, end: 80 }, "")
    .with_file_edit(
        "src/App.tsx",
        ByteSpan { start: 60, end: 95 },
        "<UserProfile key={userId} userId={userId} />",
    )
    .with_byte_edit(ByteEdit::delete(ByteSpan { start: 10, end: 20 }))
    .with_edits([ByteEdit::insert(0, "// header\n").in_file("src/App.tsx")]);

    assert_eq!(patch.description, "Compute `fullName` inline during render");
    assert_eq!(patch.edits.len(), 5);
    assert_eq!(
        patch.edits[0],
        ByteEdit {
            file: None,
            span,
            replacement: "const fullName = `${first} ${last}`;".to_string(),
        }
    );
    assert_eq!(
        patch.edits[2],
        ByteEdit {
            file: Some(PathBuf::from("src/App.tsx")),
            span: ByteSpan { start: 60, end: 95 },
            replacement: "<UserProfile key={userId} userId={userId} />".to_string(),
        }
    );
    assert_eq!(
        patch.edits[3],
        ByteEdit {
            file: None,
            span: ByteSpan { start: 10, end: 20 },
            replacement: String::new(),
        }
    );
    assert_eq!(
        patch.edits[4],
        ByteEdit {
            file: Some(PathBuf::from("src/App.tsx")),
            span: ByteSpan { start: 0, end: 0 },
            replacement: "// header\n".to_string(),
        }
    );

    let delete_patch = AutofixPatch::delete("Remove unused state", ByteSpan { start: 5, end: 15 });
    assert_eq!(delete_patch.edits.len(), 1);
    assert_eq!(delete_patch.edits[0].replacement, "");

    let insert_patch = AutofixPatch::insert("Add import", 0, "import React from 'react';\n");
    assert_eq!(insert_patch.edits.len(), 1);
    assert_eq!(insert_patch.edits[0].span, ByteSpan { start: 0, end: 0 });

    // `for_rule` defaults `target_name` to `rule.as_str()` and `.with_patch(...)` promotes tier to `Autofix`
    let rule_diag = Diagnostic::for_rule(
        RuleId::RsNoUnwrapInProduction,
        "src/lib.rs",
        loc,
        span,
        "Avoid `.unwrap()` in production.",
    )
    .with_subject_name("parse_header")
    .with_message_id("rsNoUnwrapInProduction")
    .with_severity(RuleSeverity::Error)
    .with_category(RuleCategory::Bugs)
    .with_docs_url("https://example.com/docs")
    .with_cascade_step("initial render")
    .with_cascade_step("effect setState")
    .with_caller_site(caller_site.clone())
    .with_patch(patch.clone());

    assert_eq!(rule_diag.target_name, "rs-no-unwrap-in-production");
    assert_eq!(rule_diag.subject_name.as_deref(), Some("parse_header"));
    assert_eq!(rule_diag.message_id, "rsNoUnwrapInProduction");
    assert_eq!(rule_diag.severity, RuleSeverity::Error);
    assert_eq!(rule_diag.category, RuleCategory::Bugs);
    assert_eq!(rule_diag.docs_url, "https://example.com/docs");
    assert_eq!(rule_diag.tier, PrescriptionTier::Autofix);
    assert_eq!(
        rule_diag.cascade_steps,
        vec!["initial render".to_string(), "effect setState".to_string()]
    );
    assert_eq!(rule_diag.caller_sites, vec![caller_site]);
    assert_eq!(rule_diag.autofix, Some(patch));
}

#[test]
fn shared_suppression_parser_handles_c_style_python_noqa_and_rust_allow_directives() {
    // 1. Rule list tokenizer strips `-- explanation` tail and splits commas/whitespace
    assert_eq!(
        tokenize_suppression_rules("no-derived-state, react/jsx-key -- legacy reason"),
        vec!["no-derived-state".to_string(), "react/jsx-key".to_string()]
    );
    assert!(tokenize_suppression_rules("-- blanket disable").is_empty());

    // 2. Comment directive parser supports dotore-disable*, dotore-ignore*, eslint-disable*, oxlint-disable*, JSX `}`, and Python `:`
    let prefixes = &["dotore", "eslint", "oxlint"];
    assert_eq!(
        parse_comment_disable_directive(
            "dotore-disable-next-line no-derived-state -- intentional}",
            prefixes
        ),
        Some((
            SuppressionDirectiveKind::DisableNextLine,
            vec!["no-derived-state".to_string()]
        ))
    );
    assert_eq!(
        parse_comment_disable_directive("dotore-ignore-next-line: py-no-mutable-default-arg", prefixes),
        Some((
            SuppressionDirectiveKind::DisableNextLine,
            vec!["py-no-mutable-default-arg".to_string()]
        ))
    );
    assert_eq!(
        parse_comment_disable_directive("eslint-disable-line react-hooks/exhaustive-deps", prefixes),
        Some((
            SuppressionDirectiveKind::DisableLine,
            vec!["react-hooks/exhaustive-deps".to_string()]
        ))
    );

    // 3. Python `# noqa` and `# ruff: noqa` parser
    assert_eq!(
        parse_python_suppression_directive("noqa: B006, E722"),
        Some((
            SuppressionDirectiveKind::DisableLine,
            vec!["B006".to_string(), "E722".to_string()]
        ))
    );
    assert_eq!(
        parse_python_suppression_directive("ruff: noqa: F401"),
        Some((
            SuppressionDirectiveKind::BlockDisable,
            vec!["F401".to_string()]
        ))
    );

    // 4. Rust `#[allow(...)]` / `#[expect(...)]` lint mapping
    assert_eq!(
        map_rust_allow_lint_to_rules("clippy::unwrap_used"),
        vec!["rs-no-unwrap-in-production".to_string()]
    );
    assert_eq!(
        map_rust_allow_lint_to_rules("dotore::rs_tokio_no_std_lock_across_await"),
        vec!["rs-tokio-no-std-lock-across-await".to_string()]
    );

    // 5. Quote-aware C-style comment scanner with stacked next-line and partial block enable
    let js_source = r#"const literal = "// dotore-disable-line no-derived-state";
// dotore-disable-next-line no-derived-state
// eslint-disable-next-line no-chain-state-updates
const derived = compute();
/* dotore-disable no-derived-state, no-event-handler */
const insideBoth = 1;
/* dotore-enable no-derived-state */
const onlyEventHandlerDisabled = 2;
/* dotore-enable */
const allEnabledAgain = 3;
"#;
    let supps = extract_c_style_comment_suppressions(js_source, prefixes);
    // Line 1 is inside a string literal so it must NOT suppress line 1
    assert!(!supps.matches_line_or_block(RuleId::NoDerivedState, 1));
    // Stacked disable-next-line comments on lines 2 & 3 both target line 4
    assert!(supps.matches_line_or_block(RuleId::NoDerivedState, 4));
    assert!(supps.matches_line_or_block(RuleId::NoChainStateUpdates, 4));
    // Line 6 has both rules disabled
    assert!(supps.matches_line_or_block(RuleId::NoDerivedState, 6));
    assert!(supps.matches_line_or_block(RuleId::NoEventHandler, 6));
    // Line 8 re-enabled NoDerivedState on line 7, but NoEventHandler stays disabled until line 9
    assert!(!supps.matches_line_or_block(RuleId::NoDerivedState, 8));
    assert!(supps.matches_line_or_block(RuleId::NoEventHandler, 8));
    // Line 10 has all block ranges closed
    assert!(!supps.matches_line_or_block(RuleId::NoEventHandler, 10));
}

#[test]
fn symbol_outline_builder_and_normalized_signature_header_extractor() {
    let source = "/// Renders a button.\nexport function Button(\n    props: ButtonProps,\n): JSX.Element {\n    return <button />;\n}\n";
    let line_starts = compute_line_starts(source);
    let decl_start = u32::try_from(source.find("export function").unwrap_or(0)).unwrap_or(0);
    let body_start = u32::try_from(source.find('{').unwrap_or(0)).unwrap_or(0);
    let decl_end = u32::try_from(source.len()).unwrap_or(0);

    let (sig, sig_end_line) = extract_normalized_signature_header(
        source,
        &line_starts,
        decl_start,
        decl_end,
        Some(body_start),
    );
    assert_eq!(sig, "export function Button( props: ButtonProps, ): JSX.Element");
    assert_eq!(sig_end_line, 4);

    let id_offset = u32::try_from(source.find("Button(").unwrap_or(0)).unwrap_or(0);
    let loc = loc_from_line_starts(&line_starts, id_offset);
    let outline = SymbolOutline::new(
        "Button",
        SymbolKind::Function,
        sig,
        ByteSpan {
            start: decl_start,
            end: decl_end,
        },
        loc,
        6,
    )
    .with_exported(true)
    .with_parent_name("UI")
    .with_doc_comment(Some("Renders a button.".to_string()), Some(1))
    .with_signature_end_line(sig_end_line);

    assert_eq!(outline.name, "Button");
    assert_eq!(outline.kind, SymbolKind::Function);
    assert!(outline.exported);
    assert_eq!(outline.parent_name.as_deref(), Some("UI"));
    assert_eq!(outline.doc_comment.as_deref(), Some("Renders a button."));
    assert_eq!(outline.comment_start_line, Some(1));
    assert_eq!(outline.signature_end_line, 4);
    assert_eq!(outline.loc.line, 2);
    assert_eq!(outline.end_line, 6);
}

#[test]
fn decomposed_rule_catalog_preserves_all_965_rules_discriminant_order_and_submodules() {
    use dotore_core::rules::catalog::{
        a11y_and_design, defensive_and_correctness, ecosystem, performance_and_bundle, polyglot,
        react_core, react_native_and_expo, security_and_server, three_r3f_webgl,
    };

    assert_eq!(react_core::CORE_INITIAL_RULES.len(), 36);
    assert_eq!(three_r3f_webgl::RULES.len(), 187);
    assert_eq!(ecosystem::INITIAL_ECOSYSTEM_RULES.len(), 7);
    assert_eq!(a11y_and_design::RULES.len(), 192);
    assert_eq!(performance_and_bundle::RULES.len(), 66);
    assert_eq!(security_and_server::RULES.len(), 109);
    assert_eq!(react_native_and_expo::RULES.len(), 59);
    assert_eq!(ecosystem::EXTENDED_ECOSYSTEM_RULES.len(), 37);
    assert_eq!(react_core::EXTENDED_REACT_RULES.len(), 74);
    assert_eq!(defensive_and_correctness::RULES.len(), 154);
    assert_eq!(polyglot::RULES.len(), 44);

    let registry = rule_registry();
    assert_eq!(registry.len(), 965);

    for (idx, meta) in registry.iter().enumerate() {
        assert_eq!(meta.id as usize, idx, "Rule {:?} out of discriminant order", meta.id);
        assert_eq!(meta.id.metadata(), meta);
        assert_eq!(RuleId::parse(meta.canonical_id), Some(meta.id));
        assert_eq!(RuleId::parse(meta.qualified_key), Some(meta.id));
        for &alias in meta.legacy_aliases {
            assert_eq!(RuleId::parse(alias), Some(meta.id));
            assert!(meta.id.matches_key(alias));
        }
    }

    assert_eq!(
        RuleId::NoDerivedState.metadata().capability_gate,
        CapabilityPredicate::REACT_ONLY
    );
    assert_eq!(
        RuleId::AngularNoSignalWriteInEffect.metadata().capability_gate,
        CapabilityPredicate::ANGULAR_ONLY
    );
    assert_eq!(
        RuleId::PyNoMutableDefaultArg.metadata().capability_gate,
        CapabilityPredicate::PYTHON_ONLY
    );
    assert_eq!(
        RuleId::RsPerfNoUnnecessaryFormat.metadata().capability_gate,
        CapabilityPredicate::RUST_ONLY
    );
}

#[test]
fn decomposed_config_submodules_expose_workspace_capability_gate_loader_and_mutator() {
    use dotore_core::config::{
        capability_gate::{Capability, PackageRole, content_enables_react_compiler},
        loader::{DotoreConfig, load_config_from_dir, load_local_config_in_dir},
        mutator::{ConfigMutation, ConfigTargetKind, mutate_config_in_dir},
        workspace::{
            discover_workspace_packages, resolve_package_for_file, strip_jsonc,
            strip_source_extension,
        },
    };
    use dotore_core::rules::RuleSeverityOverride;

    assert_eq!(strip_source_extension("src/App.tsx"), "src/App");
    assert!(content_enables_react_compiler("babel-plugin-react-compiler"));
    let clean = strip_jsonc("{\n  // comment\n  \"warnings\": false,\n}");
    let cfg = DotoreConfig::from_json_str(&clean).unwrap();
    assert!(!cfg.warnings);

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-cfg-submodules-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(
        temp_dir.join("package.json"),
        r#"{"name": "demo-app", "private": true, "dependencies": {"react": "^19.0.0", "next": "^15.0.0"}}"#,
    )
    .unwrap();

    let pkgs = discover_workspace_packages(&temp_dir);
    assert_eq!(pkgs.len(), 1);
    assert_eq!(pkgs[0].capability_gate.package_role, PackageRole::Application);
    assert!(pkgs[0].capability_gate.has(Capability::React));
    assert!(pkgs[0].capability_gate.has(Capability::Nextjs));
    let resolved = resolve_package_for_file(&temp_dir.join("src/App.tsx"), &pkgs).unwrap();
    assert_eq!(resolved.root_dir, temp_dir);

    assert!(load_local_config_in_dir(&temp_dir).is_none());
    let mut_res = mutate_config_in_dir(
        &temp_dir,
        ConfigMutation::SetRuleSeverity {
            rule: RuleId::NoDerivedState,
            severity: RuleSeverityOverride::Warn,
        },
    )
    .unwrap();
    assert!(mut_res.created);
    assert_eq!(mut_res.target_kind, ConfigTargetKind::JsonFile);
    let loaded = load_config_from_dir(&temp_dir);
    assert_eq!(
        loaded.explicit_rule_override(RuleId::NoDerivedState),
        Some(RuleSeverityOverride::Warn)
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn decomposed_diff_submodules_expose_patch_contextual_owner_and_baseline() {
    use dotore_core::diff::{
        baseline::{
            BaselineDiagnosticEntry, compare_baseline_diagnostics, compute_diagnostic_fingerprint,
            compute_diagnostic_id, compute_structural_fingerprint, normalize_ast_tokens,
            parse_baseline_report_str,
        },
        contextual_owner::{
            ContextualSpanProvider, diagnostic_intersects_changed_lines,
            filter_diagnostics_by_scope,
        },
        patch::{
            BlockingLevel, ChangedFileLineRanges, DiffScope, ScanMode, parse_changed_line_ranges,
            resolve_scan_exit_code, validate_git_revision, validate_warning_exit_code,
        },
    };

    assert_eq!(DiffScope::parse("contextual"), Some(DiffScope::Contextual));
    assert_eq!(ScanMode::Baseline.as_str(), "baseline");
    assert_eq!(BlockingLevel::parse("warn"), Some(BlockingLevel::Warning));
    assert_eq!(validate_warning_exit_code(2), Ok(2));
    assert!(validate_git_revision("main..HEAD").is_ok());
    assert!(validate_git_revision("--evil").is_err());

    let patch = "diff --git a/src/App.tsx b/src/App.tsx\n--- a/src/App.tsx\n+++ b/src/App.tsx\n@@ -3,1 +3,1 @@\n";
    let ranges = parse_changed_line_ranges(patch, true);
    assert_eq!(
        ranges,
        vec![ChangedFileLineRanges {
            file: PathBuf::from("src/App.tsx"),
            ranges: vec![(3, 3)],
            deletion_lines: Vec::new(),
        }]
    );

    let src = "fn app() {\n    let x = Some(1).unwrap();\n}\n";
    let analyzer = MockRustLanguageAnalyzer;
    let extracted = analyzer.extract_file(Path::new("src/App.tsx"), src);
    assert_eq!(extracted.file_path(), Path::new("src/App.tsx"));

    let diag = Diagnostic::for_rule(
        RuleId::NoDerivedState,
        "src/App.tsx",
        SourceLoc { line: 2, column: 21 },
        ByteSpan { start: 23, end: 32 },
        "Avoid `.unwrap()` in production.",
    )
    .with_subject_name("app");

    assert!(!diagnostic_intersects_changed_lines(
        &diag,
        Some(&extracted),
        Some(src),
        &ranges[0],
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        &diag,
        Some(&extracted),
        Some(src),
        &ranges[0],
        true,
    ));
    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/App.tsx"), src.to_string());
    let filtered = filter_diagnostics_by_scope(
        vec![diag.clone()],
        DiffScope::Contextual,
        Path::new("."),
        &[PathBuf::from("src/App.tsx")],
        &ranges,
        &[extracted],
        &sources,
    );
    assert_eq!(filtered.len(), 1);
    assert_eq!(
        resolve_scan_exit_code(&filtered, BlockingLevel::Warning, None),
        1
    );

    let id = compute_diagnostic_id(&diag, None);
    assert!(id.contains("src/App.tsx::2:21::dotore/no-derived-state::"));
    let fp = compute_diagnostic_fingerprint(&diag, Some(src));
    let sfp = compute_structural_fingerprint(&diag);
    assert!(fp.starts_with("fp::no-derived-state::"));
    assert!(sfp.starts_with("fp::no-derived-state::"));
    assert_eq!(normalize_ast_tokens("a  +  'b' // comment"), "a + \"b\"");

    let base_entry = BaselineDiagnosticEntry::from_diagnostic(&diag, Some(src));
    let delta = compare_baseline_diagnostics(&[diag], &sources, &[base_entry], "baseline.json");
    assert_eq!(delta.summary.preexisting_count, 1);
    assert_eq!(delta.summary.introduced_count, 0);
    let parsed_base = parse_baseline_report_str(
        r#"{"diagnostics": [{"rule": "no-derived-state", "file": "src/App.tsx", "message": "Avoid `.unwrap()` in production.", "loc": {"line": 2, "column": 21}}]}"#,
    )
    .unwrap();
    assert_eq!(parsed_base.len(), 1);
}

#[test]
fn decomposed_report_submodules_expose_json_terminal_html_rules_why_and_ci_install() {
    use dotore_core::config::DotoreConfig;
    use dotore_core::fixer::FileFixResult;
    use dotore_core::report::{
        ci_install::{
            CiOptions, CiProviderKind, InstallOptions, ci_config, ci_install, ci_upgrade,
            format_install_report, install_dotore,
        },
        html::render_html_report,
        json::{JSON_REPORT_SCHEMA_VERSION, build_extracted_report},
        rules::{
            RulesListOptions, build_rule_catalog, explain_rule, format_rule_catalog_text,
            format_rule_explanation_text,
        },
        terminal::{
            format_design_report, format_design_report_pretty, format_fix_report,
            format_terminal_report, format_terminal_report_pretty,
        },
        why::{
            explain_location_with_analyzers, format_why_report_text, parse_why_location,
            render_code_frame,
        },
    };

    let src = "pub fn handle() {\n    let v = Some(1).unwrap();\n}\n";
    let analyzer = MockRustLanguageAnalyzer;
    let extracted = analyzer.extract_file(Path::new("src/lib.rs"), src);
    let diag = Diagnostic::for_rule(
        RuleId::NoDerivedState,
        "src/lib.rs",
        SourceLoc { line: 2, column: 21 },
        ByteSpan { start: 30, end: 39 },
        "Avoid `.unwrap()` in production.",
    )
    .with_tier(PrescriptionTier::Surgical)
    .with_subject_name("handle")
    .with_cascade_step("Some(1).unwrap()")
    .with_cascade_step("panic");

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/lib.rs"), src.to_string());
    let report = build_extracted_report(&[extracted], vec![diag], &sources);
    assert_eq!(report.schema_version, JSON_REPORT_SCHEMA_VERSION);

    let term_plain = format_terminal_report(&report);
    assert!(term_plain.contains("[no-derived-state] (surgical)"));
    assert!(term_plain.contains("cascade: Some(1).unwrap() -> panic"));
    assert!(term_plain.contains("flow:    ┌─► [Some(1).unwrap()] ──► [panic] ──► ↻ re-render"));
    assert!(term_plain.contains("dotore  score:"));

    let term_ansi = format_terminal_report_pretty(&report, true);
    assert!(term_ansi.contains("\x1b["));

    let design_plain = format_design_report(&report);
    assert!(design_plain.contains("DOTORE DESIGN AUDIT"));
    assert!(design_plain.contains("dotore design  files: 1"));
    let design_ansi = format_design_report_pretty(&report, true);
    assert!(design_ansi.contains("\x1b["));

    let fix_out = format_fix_report(
        &[FileFixResult {
            file: PathBuf::from("src/lib.rs"),
            patches_applied: 1,
            descriptions: vec!["Replace unwrap".to_string()],
            new_source: src.to_string(),
        }],
        true,
    );
    assert!(fix_out.contains("[dry-run] src/lib.rs (1 patch(es))"));

    let html = render_html_report(&report);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("no-derived-state"));

    let catalog = build_rule_catalog(
        &DotoreConfig::default(),
        &RulesListOptions {
            framework: Some("rust".to_string()),
            ..RulesListOptions::default()
        },
    );
    assert_eq!(catalog.len(), 15);
    let cat_text = format_rule_catalog_text(&catalog);
    assert!(cat_text.contains("dotore/rs-perf-no-unnecessary-format"));
    let explained = explain_rule("no-derived-state", &DotoreConfig::default()).unwrap();
    let exp_text = format_rule_explanation_text(&explained);
    assert!(exp_text.contains("dotore/no-derived-state"));

    let loc = parse_why_location("src/lib.rs:2:5").unwrap();
    assert_eq!(loc.line, 2);
    assert_eq!(loc.column, Some(5));
    let frame = render_code_frame(src, 2);
    assert!(frame.contains(">    2 |     let v = Some(1).unwrap();"));

    let temp_dir =
        std::env::temp_dir().join(format!("dotore-report-submodules-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(temp_dir.join("src")).unwrap();
    std::fs::write(temp_dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    std::fs::write(temp_dir.join("src/lib.rs"), src).unwrap();

    let analyzers: &[&dyn LanguageAnalyzer] = &[&analyzer];
    let why_rep = explain_location_with_analyzers("src/lib.rs:2", &temp_dir, analyzers).unwrap();
    assert_eq!(why_rep.entries.len(), 1);
    let why_text = format_why_report_text(&why_rep);
    assert!(why_text.contains("[active] dotore/no-derived-state"));

    let ci_opts = CiOptions {
        cwd: temp_dir.clone(),
        provider: Some(CiProviderKind::GithubActions),
        blocking: Some("error".to_string()),
        scope: Some("contextual".to_string()),
    };
    let ci_res = ci_install(&ci_opts).unwrap();
    assert_eq!(ci_res.status, "created");
    let ci_up = ci_upgrade(&ci_opts).unwrap();
    assert_eq!(ci_up.status, "not-needed");
    let ci_cfg = ci_config(&CiOptions {
        blocking: Some("warning".to_string()),
        ..ci_opts
    })
    .unwrap();
    assert_eq!(ci_cfg.status, "updated");

    let inst_res = install_dotore(&InstallOptions {
        cwd: temp_dir.clone(),
        yes: true,
        dry_run: true,
        agent_hooks: true,
    })
    .unwrap();
    let inst_text = format_install_report(&inst_res);
    assert!(inst_text.contains("[dry-run] Installed /dotore skill:"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
