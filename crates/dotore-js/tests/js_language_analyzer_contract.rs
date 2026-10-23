//! Direct contract tests for `JsLanguageAnalyzer` at the `dotore_core::LanguageAnalyzer` seam.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    AutofixPatch, ByteEdit, ByteSpan, Capability, CapabilityGate, ChangedFileLineRanges,
    Diagnostic, DiffScope, DotoreConfig, FileContext, LanguageAnalyzer, LanguageId, PackageRole,
    PrescriptionTier, RuleCategory, RuleId, RuleSeverity, SourceLoc, SymbolKind, WorkspacePackage,
    apply_patches_to_source_with_analyzers, build_extracted_report_with_packages,
    diagnostic_intersects_changed_lines, filter_diagnostics_by_scope, search_extracted_files,
};
use dotore_js::{FileIr, JsLanguageAnalyzer};

#[test]
fn js_language_analyzer_supports_all_js_ts_extensions_and_manifest_filenames() {
    let analyzer = JsLanguageAnalyzer::new();
    assert_eq!(analyzer.language_id(), LanguageId::JavaScript);
    assert_eq!(analyzer.language_id(), LanguageId::Js);
    assert_eq!(analyzer.manifest_filenames(), &["package.json"]);

    for supported in [
        "src/index.js",
        "src/App.jsx",
        "src/utils.ts",
        "src/Component.tsx",
        "src/config.mjs",
        "src/legacy.cjs",
        "src/module.mts",
        "src/common.cts",
    ] {
        assert!(
            analyzer.supports_path(Path::new(supported)),
            "Expected JsLanguageAnalyzer to support `{supported}`"
        );
    }

    for unsupported in [
        "src/types.d.ts",
        "src/module.d.mts",
        "src/common.d.cts",
        "dotore.config.ts",
        "src/service.py",
        "src/types.pyi",
        "src/main.rs",
        "src/styles.css",
        "package.json",
        "README.md",
    ] {
        assert!(
            !analyzer.supports_path(Path::new(unsupported)),
            "Expected JsLanguageAnalyzer to reject `{unsupported}`"
        );
    }
}

#[test]
fn js_language_analyzer_infers_capability_gates_and_package_roles_from_manifests() {
    let analyzer = JsLanguageAnalyzer;

    let next_pkg_json = r#"{
        "name": "web-app",
        "private": true,
        "dependencies": {
            "react": "^19.0.0",
            "react-dom": "^19.0.0",
            "next": "^15.1.0",
            "@tanstack/react-query": "^5.60.0",
            "tailwindcss": "^4.0.0"
        },
        "devDependencies": {
            "typescript": "^5.7.0"
        }
    }"#;
    let next_config_ts = "export default { experimental: { reactCompiler: true } };";

    let gate = analyzer.infer_capability_gate(
        Path::new("apps/web"),
        &[
            (PathBuf::from("apps/web/package.json"), next_pkg_json),
            (PathBuf::from("apps/web/next.config.ts"), next_config_ts),
        ],
    );
    assert!(gate.has(Capability::React));
    assert!(gate.has(Capability::Nextjs));
    assert!(gate.has(Capability::ServerActions));
    assert!(gate.has(Capability::Ssr));
    assert!(gate.has(Capability::TanstackQuery));
    assert!(gate.has(Capability::Tailwind));
    assert!(gate.has(Capability::Tailwind4));
    assert!(gate.has(Capability::TypeScript));
    assert!(gate.has(Capability::ReactCompiler));
    assert!(gate.has_react_compiler);
    assert_eq!(gate.package_role, PackageRole::Application);

    let angular_pkg_json = r#"{
        "name": "ng-portal",
        "dependencies": {
            "@angular/core": "^19.0.0",
            "rxjs": "^7.8.0"
        }
    }"#;
    let ng_gate = analyzer.infer_capability_gate(
        Path::new("apps/portal"),
        &[(PathBuf::from("apps/portal/package.json"), angular_pkg_json)],
    );
    assert!(ng_gate.has(Capability::Angular));
    assert!(ng_gate.has(Capability::Rxjs));
    assert!(ng_gate.has(Capability::TypeScript));
    assert!(!ng_gate.has(Capability::React));

    let lib_pkg_json = r#"{
        "name": "@acme/design-system",
        "version": "1.0.0",
        "exports": {
            ".": "./src/index.tsx"
        },
        "peerDependencies": {
            "react": "^19.0.0"
        }
    }"#;
    let lib_gate = analyzer.infer_capability_gate(
        Path::new("packages/design-system"),
        &[(
            PathBuf::from("packages/design-system/package.json"),
            lib_pkg_json,
        )],
    );
    assert_eq!(lib_gate.package_role, PackageRole::Library);
    assert!(lib_gate.is_library_entrypoint(
        Path::new("packages/design-system/src/index.tsx"),
        Path::new("packages/design-system")
    ));
}

#[test]
fn js_language_analyzer_extracts_symbol_outlines_contextual_owner_spans_and_inline_suppressions() {
    let analyzer = JsLanguageAnalyzer;
    let source = r#"import { useState, useEffect } from 'react';

export interface UserCardProps {
    firstName: string;
    lastName: string;
}

export type DisplayMode = 'compact' | 'full';

export const DEFAULT_GREETING = 'Hello';

export function UserCard({ firstName, lastName }: UserCardProps) {
    const [fullName, setFullName] = useState('');
    const syncName = () => {
        setFullName(firstName + ' ' + lastName);
    };

    // dotore-disable-next-line no-derived-state
    useEffect(() => {
        syncName();
    }, [firstName, lastName]);

    return (
        <section className="card">
            <img src="/avatar.png" />
            <span>{fullName}</span>
        </section>
    );
}
"#;

    let extracted = analyzer.extract_file(Path::new("src/UserCard.tsx"), source);
    assert_eq!(extracted.path, PathBuf::from("src/UserCard.tsx"));
    assert_eq!(extracted.language_id, LanguageId::TypeScript);
    assert_eq!(extracted.file_context, FileContext::Production);
    assert_eq!(extracted.subjects_count, 1);
    assert_eq!(extracted.effects_count, 1);
    assert_eq!(extracted.subject_spans.len(), 1);
    assert_eq!(
        extracted.subject_spans[0].0.as_deref(),
        Some("UserCard")
    );

    // Verify Symbol Outlines
    let outline_names_and_kinds: Vec<(&str, SymbolKind)> = extracted
        .symbol_outlines
        .iter()
        .map(|o| (o.name.as_str(), o.kind))
        .collect();
    assert!(outline_names_and_kinds.contains(&("UserCardProps", SymbolKind::Interface)));
    assert!(outline_names_and_kinds.contains(&("DisplayMode", SymbolKind::Type)));
    assert!(outline_names_and_kinds.contains(&("DEFAULT_GREETING", SymbolKind::Constant)));
    assert!(outline_names_and_kinds.contains(&("UserCard", SymbolKind::Function)));

    // Verify Contextual Owner spans
    assert!(
        !extracted
            .contextual_owner_spans
            .function_boundary_spans
            .is_empty(),
        "Expected function_boundary_spans to be populated"
    );
    assert!(
        !extracted
            .contextual_owner_spans
            .related_hook_spans
            .is_empty(),
        "Expected related_hook_spans to be populated for useEffect"
    );
    assert!(
        !extracted.contextual_owner_spans.element_spans.is_empty(),
        "Expected element_spans to be populated from JSX subtrees"
    );
    assert!(
        extracted
            .contextual_owner_spans
            .related_hook_spans
            .iter()
            .any(|h| !h.referenced_decl_spans.is_empty()),
        "Expected useEffect related_hook_spans to include referenced local `syncName` declaration span"
    );

    // Verify inline suppressions
    assert_eq!(extracted.suppressions.line_directives.len(), 1);
    assert_eq!(extracted.suppressions.line_directives[0].target_line, 19);
    assert_eq!(
        extracted.suppressions.line_directives[0].rules,
        vec!["no-derived-state".to_string()]
    );
    assert!(
        extracted
            .suppressions
            .matches_line(RuleId::NoDerivedState, 19)
    );
    assert!(
        !extracted
            .suppressions
            .matches_line(RuleId::NoDerivedState, 12)
    );

    // Downcast opaque payload to `FileIr`
    let file_ir = extracted
        .downcast_payload::<FileIr>()
        .expect("ExtractedFile payload should downcast to FileIr");
    assert_eq!(file_ir.subjects.len(), 1);
    assert_eq!(file_ir.subjects[0].name.as_deref(), Some("UserCard"));
}

#[test]
fn js_language_analyzer_analyzes_package_with_cross_file_caller_sites_and_suppressions() {
    let analyzer = JsLanguageAnalyzer;

    let profile_src = r#"import { useState, useEffect } from 'react';
export function ProfilePage({ userId }: { userId: string }) {
    const [comment, setComment] = useState('');
    useEffect(() => {
        setComment('');
    }, [userId]);
    return <div>{comment}</div>;
}
"#;
    let app_src = r#"import { useState, useEffect } from 'react';
import { ProfilePage } from './ProfilePage';

export function App({ activeUserId, first, last }: { activeUserId: string; first: string; last: string }) {
    const [full, setFull] = useState('');
    useEffect(() => {
        setFull(first + ' ' + last);
    }, [first, last]);
    return <ProfilePage userId={activeUserId} />;
}

export function Suppressed({ a, b }: { a: string; b: string }) {
    const [sum, setSum] = useState('');
    // dotore-disable-next-line no-derived-state
    useEffect(() => {
        setSum(a + b);
    }, [a, b]);
    return <span>{sum}</span>;
}
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/ProfilePage.tsx"), profile_src),
        analyzer.extract_file(Path::new("src/App.tsx"), app_src),
    ];

    let pkg = WorkspacePackage {
        name: "web".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };

    let result = analyzer.analyze_package(&pkg, &files, None);
    assert_eq!(result.subjects_scanned, 3);
    assert_eq!(result.effects_scanned, 3);

    // `Suppressed` component's `no-derived-state` is suppressed by `// dotore-disable-next-line`
    let derived_diags: Vec<&Diagnostic> = result
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::NoDerivedState)
        .collect();
    assert_eq!(derived_diags.len(), 1);
    assert_eq!(derived_diags[0].subject_name.as_deref(), Some("App"));

    // `ProfilePage` has `no-reset-all-state-on-prop-change` enriched to `Autofix` with cross-file caller site in `App.tsx`
    let reset_diags: Vec<&Diagnostic> = result
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::NoResetAllStateOnPropChange)
        .collect();
    assert_eq!(reset_diags.len(), 1);
    assert_eq!(reset_diags[0].subject_name.as_deref(), Some("ProfilePage"));
    assert_eq!(reset_diags[0].caller_sites.len(), 1);
    assert_eq!(
        reset_diags[0].caller_sites[0].caller_file,
        PathBuf::from("src/App.tsx")
    );
    assert_eq!(reset_diags[0].tier, PrescriptionTier::Autofix);
    assert!(reset_diags[0].autofix.is_some());

    // Contextual diff filtering over ExtractedFile (`ContextualOwnerPolicy::Subject`)
    let change_in_app_return = ChangedFileLineRanges {
        file: PathBuf::from("src/App.tsx"),
        ranges: vec![(9, 9)],
        deletion_lines: Vec::new(),
    };
    assert!(!diagnostic_intersects_changed_lines(
        derived_diags[0],
        Some(&files[1]),
        Some(app_src),
        &change_in_app_return,
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        derived_diags[0],
        Some(&files[1]),
        Some(app_src),
        &change_in_app_return,
        true,
    ));

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/ProfilePage.tsx"), profile_src.to_string());
    sources.insert(PathBuf::from("src/App.tsx"), app_src.to_string());

    let scoped = filter_diagnostics_by_scope(
        result.diagnostics.clone(),
        DiffScope::Contextual,
        Path::new("."),
        &[PathBuf::from("src/App.tsx")],
        &[change_in_app_return],
        &files,
        &sources,
    );
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].rule, RuleId::NoDerivedState);

    let report = build_extracted_report_with_packages(
        &files,
        result.diagnostics,
        &sources,
        std::slice::from_ref(&pkg),
    );
    assert_eq!(report.summary.files_scanned, 2);
    assert_eq!(report.summary.subjects_scanned, 3);

    let hits = search_extracted_files("ProfilePage", &files, None, 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].outline.name, "ProfilePage");
}

#[test]
fn js_language_analyzer_validates_syntax_across_js_jsx_ts_tsx_mjs_cjs_and_autofix_patches() {
    let analyzer = JsLanguageAnalyzer;

    let valid_cases = [
        ("src/module.js", "export const add = (a, b) => a + b;\n"),
        (
            "src/Card.jsx",
            "export const Card = ({ title }) => <div className=\"card\">{title}</div>;\n",
        ),
        (
            "src/types.ts",
            "export interface Config<T> { readonly value: T; }\nexport const make = <T,>(value: T): Config<T> => ({ value });\n",
        ),
        (
            "src/View.tsx",
            "export function View({ items }: { items: string[] }) { return <ul>{items.map((x) => <li key={x}>{x}</li>)}</ul>; }\n",
        ),
        ("src/esm.mjs", "export default function run() { return 42; }\n"),
        ("src/cjs.cjs", "module.exports = { ok: true };\n"),
    ];

    for (path, valid_src) in valid_cases {
        assert!(
            analyzer.validate_syntax(Path::new(path), valid_src),
            "Expected validate_syntax to accept valid `{path}`"
        );
    }

    let invalid_cases = [
        ("src/module.js", "export const add = (a, b) => {\n"),
        ("src/Card.jsx", "export const Card = () => <div><span></div>;\n"),
        ("src/types.ts", "export interface Broken { x: ;\n"),
        ("src/View.tsx", "export function View() { return <div prop={ />; }\n"),
        ("src/esm.mjs", "import { from 'mod';\n"),
        ("src/cjs.cjs", "module.exports = {{{;\n"),
    ];

    for (path, invalid_src) in invalid_cases {
        assert!(
            !analyzer.validate_syntax(Path::new(path), invalid_src),
            "Expected validate_syntax to reject malformed `{path}`"
        );
    }

    let source = "export const Button = () => <><span>Save</span></>;\n";
    let analyzers: &[&dyn LanguageAnalyzer] = &[&analyzer];
    let valid_patch = Diagnostic {
        file: PathBuf::from("src/Button.tsx"),
        subject_name: Some("Button".to_string()),
        rule: RuleId::JsxNoUselessFragment,
        category: RuleCategory::Performance,
        severity: RuleSeverity::Warning,
        message_id: "noUselessFragment",
        tier: PrescriptionTier::Autofix,
        target_name: "Fragment".to_string(),
        message: "Avoid unnecessary fragment.".to_string(),
        docs_url: RuleId::JsxNoUselessFragment.docs_url(),
        loc: SourceLoc {
            line: 1,
            column: 29,
        },
        span: ByteSpan { start: 28, end: 50 },
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: Some(AutofixPatch {
            description: "Unwrap single-child fragment".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan { start: 28, end: 50 },
                replacement: "<span>Save</span>".to_string(),
            }],
        }),
    };

    let (rewritten, applied) = apply_patches_to_source_with_analyzers(
        source,
        std::slice::from_ref(&valid_patch),
        analyzers,
    );
    assert_eq!(applied.len(), 1);
    assert_eq!(
        rewritten,
        "export const Button = () => <span>Save</span>;\n"
    );

    let mut invalid_patch = valid_patch;
    invalid_patch.autofix = Some(AutofixPatch {
        description: "Corrupt JSX".to_string(),
        edits: vec![ByteEdit {
            file: None,
            span: ByteSpan { start: 28, end: 50 },
            replacement: "<span>Save</div>".to_string(),
        }],
    });
    let (untouched, rejected) =
        apply_patches_to_source_with_analyzers(source, &[invalid_patch], analyzers);
    assert!(rejected.is_empty());
    assert_eq!(untouched, source);
}
