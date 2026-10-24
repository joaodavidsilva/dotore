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
    assert_eq!(
        analyzer.manifest_filenames(),
        &["package.json", "angular.json"]
    );

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
    assert_eq!(extracted.subject_spans[0].0.as_deref(), Some("UserCard"));

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
    sources.insert(
        PathBuf::from("src/ProfilePage.tsx"),
        profile_src.to_string(),
    );
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
        (
            "src/esm.mjs",
            "export default function run() { return 42; }\n",
        ),
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
        (
            "src/Card.jsx",
            "export const Card = () => <div><span></div>;\n",
        ),
        ("src/types.ts", "export interface Broken { x: ;\n"),
        (
            "src/View.tsx",
            "export function View() { return <div prop={ />; }\n",
        ),
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

#[test]
fn js_language_analyzer_detects_duplicated_helper_logic_across_modules_and_ignores_trivial_helpers()
{
    use dotore_core::build_root_cause_groups_and_capsules;

    let analyzer = JsLanguageAnalyzer;

    let mod_a_src = r#"function normalizeHeader(raw: string, prefix: string): string {
    const trimmed = raw.trim();
    if (!trimmed) {
        return prefix;
    }
    const cleaned = trimmed.toLowerCase().replace(/\s+/g, "-");
    return `${prefix}:${cleaned}`;
}

const getId = (item: { id: string }) => item.id.trim();

export function formatRouteHeader(input: string): string {
    return normalizeHeader(input, "route") + getId({ id: input });
}
"#;

    let mod_b_src = r#"const cleanToken = (input: string, ns: string): string => {
    const stripped = input.trim();
    if (!stripped) {
        return ns;
    }
    const slug = stripped.toLowerCase().replace(/\s+/g, "-");
    return `${ns}:${slug}`;
};

const pickId = (entry: { id: string }) => entry.id.trim();

export function formatEventHeader(name: string): string {
    return cleanToken(name, "event") + pickId({ id: name });
}
"#;

    let mod_c_src = r#"export function uniqueSharedHelper(value: string): string {
    const lines = value.split("\n");
    const out: string[] = [];
    for (const line of lines) {
        if (line.length > 0) {
            out.push(line.toUpperCase());
        }
    }
    return out.join(",");
}
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/routes.ts"), mod_a_src),
        analyzer.extract_file(Path::new("src/events.ts"), mod_b_src),
        analyzer.extract_file(Path::new("src/shared.ts"), mod_c_src),
    ];

    // 1-2 line trivial helpers (`getId` / `pickId`) must not be recorded in helper_fingerprints
    assert_eq!(files[0].architecture_facets.helper_fingerprints.len(), 1);
    assert_eq!(
        files[0].architecture_facets.helper_fingerprints[0].name,
        "normalizeHeader"
    );
    assert_eq!(files[1].architecture_facets.helper_fingerprints.len(), 1);
    assert_eq!(
        files[1].architecture_facets.helper_fingerprints[0].name,
        "cleanToken"
    );
    assert_eq!(
        files[0].architecture_facets.helper_fingerprints[0].normalized_hash,
        files[1].architecture_facets.helper_fingerprints[0].normalized_hash
    );
    // Exported function in `src/shared.ts` is not a private helper
    assert!(files[2].architecture_facets.helper_fingerprints.is_empty());

    let pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };

    let res = analyzer.analyze_package(&pkg, &files, Some(&[RuleId::ArchNoDuplicatedHelperLogic]));
    assert!(
        !res.diagnostics.is_empty(),
        "Expected duplicated helper diagnostic"
    );
    for diag in &res.diagnostics {
        assert_eq!(diag.rule, RuleId::ArchNoDuplicatedHelperLogic);
        assert_eq!(diag.severity, RuleSeverity::Warning);
        assert_eq!(diag.tier, PrescriptionTier::Refactor);
        assert!(diag.autofix.is_none());
        assert!(!diag.caller_sites.is_empty());
        assert!(!diag.cascade_steps.is_empty());
    }

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/routes.ts"), mod_a_src.to_string());
    sources.insert(PathBuf::from("src/events.ts"), mod_b_src.to_string());
    sources.insert(PathBuf::from("src/shared.ts"), mod_c_src.to_string());

    let (groups, capsules) =
        build_root_cause_groups_and_capsules(&files, &res.diagnostics, &sources);
    assert_eq!(
        groups.len(),
        1,
        "Peer duplicated helpers must cluster into a single Root-Cause Group"
    );
    assert_eq!(capsules.len(), 1);
    assert!(!capsules[0].caller_site_excerpts.is_empty());
    assert!(capsules[0].exemplar.is_some());
}

#[test]
fn js_language_analyzer_detects_prefer_fluent_builder_and_skips_types_with_builders() {
    use dotore_core::build_root_cause_groups_and_capsules;

    let analyzer = JsLanguageAnalyzer;

    let builder_src = r#"export interface RequestConfig {
    url: string;
    method: string;
    timeoutMs: number;
    retryCount: number;
    headers: Record<string, string>;
}

export class RequestConfigBuilder {
    withTimeout(ms: number): this {
        return this;
    }
    build(): RequestConfig {
        return { url: "/", method: "GET", timeoutMs: 0, retryCount: 0, headers: {} };
    }
}
"#;

    let rules_a_src = r#"export interface DiagnosticRecord {
    rule: string;
    file: string;
    message: string;
    autofix: string | null;
    callerSites: string[];
    suppressed: boolean;
}

export function checkFirst(file: string): DiagnosticRecord {
    const diag: DiagnosticRecord = {
        rule: "rule-a",
        file,
        message: "First issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
    return diag;
}

export function checkSecond(file: string): DiagnosticRecord {
    return <DiagnosticRecord>{
        rule: "rule-b",
        file,
        message: "Second issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
}
"#;

    let rules_b_src = r#"import type { DiagnosticRecord } from "./rulesA";
import type { RequestConfig } from "./requestBuilder";

export function checkThird(file: string): DiagnosticRecord {
    const entry: DiagnosticRecord = {
        rule: "rule-c",
        file,
        message: "Third issue",
        autofix: null,
        callerSites: [],
        suppressed: false,
    };
    return entry;
}

export function makeRequests(): RequestConfig[] {
    const r1: RequestConfig = { url: "/a", method: "GET", timeoutMs: 0, retryCount: 0, headers: {} };
    const r2: RequestConfig = { url: "/b", method: "POST", timeoutMs: 0, retryCount: 0, headers: {} };
    const r3: RequestConfig = { url: "/c", method: "PUT", timeoutMs: 0, retryCount: 0, headers: {} };
    return [r1, r2, r3];
}
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/requestBuilder.ts"), builder_src),
        analyzer.extract_file(Path::new("src/rulesA.ts"), rules_a_src),
        analyzer.extract_file(Path::new("src/rulesB.ts"), rules_b_src),
    ];

    assert!(
        files[0]
            .architecture_facets
            .defined_builder_types
            .contains(&"RequestConfig".to_string())
    );
    assert_eq!(files[1].architecture_facets.struct_literal_sites.len(), 2);
    assert!(!files[2].architecture_facets.struct_literal_sites.is_empty());

    let pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };

    let res = analyzer.analyze_package(&pkg, &files, Some(&[RuleId::ArchPreferFluentBuilder]));
    assert!(
        !res.diagnostics.is_empty(),
        "Expected ArchPreferFluentBuilder diagnostic"
    );
    for diag in &res.diagnostics {
        assert_eq!(diag.rule, RuleId::ArchPreferFluentBuilder);
        assert_eq!(diag.target_name, "DiagnosticRecord");
        assert_eq!(diag.severity, RuleSeverity::Warning);
        assert_eq!(diag.tier, PrescriptionTier::Refactor);
        assert!(diag.autofix.is_none());
        assert!(!diag.caller_sites.is_empty());
        assert!(!diag.cascade_steps.is_empty());
    }

    let mut sources = HashMap::new();
    sources.insert(
        PathBuf::from("src/requestBuilder.ts"),
        builder_src.to_string(),
    );
    sources.insert(PathBuf::from("src/rulesA.ts"), rules_a_src.to_string());
    sources.insert(PathBuf::from("src/rulesB.ts"), rules_b_src.to_string());

    let (groups, capsules) =
        build_root_cause_groups_and_capsules(&files, &res.diagnostics, &sources);
    assert_eq!(
        groups.len(),
        1,
        "All DiagnosticRecord literal sites must cluster into one Root-Cause Group"
    );
    assert_eq!(capsules.len(), 1);
    assert!(!capsules[0].caller_site_excerpts.is_empty());
    let exemplar = capsules[0].exemplar.as_ref().expect("builder exemplar");
    assert_eq!(exemplar.file, PathBuf::from("src/requestBuilder.ts"));
}

#[test]
fn js_language_analyzer_detects_inline_terminal_ui_primitives_outside_ui_kit_modules() {
    use dotore_core::build_root_cause_groups_and_capsules;

    let analyzer = JsLanguageAnalyzer;

    let ui_kit_src = r#"export function renderBox(title: string, body: string): string {
    return `\x1b[36m┌── ${title} ──┐\x1b[0m\n│ ${body} │\n└──────────┘`;
}
"#;

    let reporter_src = r#"export function formatSummary(status: string): string {
    const header = "\x1b[31mFAIL\x1b[0m";
    const border = `╭────────────╮\n│ ${status} │\n╰────────────╯`;
    return `${header}\n${border}`;
}
"#;

    let test_src = r#"export function testSnapshot(): string {
    return "\x1b[32m┌──┐\x1b[0m";
}
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/terminal_ui.ts"), ui_kit_src),
        analyzer.extract_file(Path::new("src/reporter.ts"), reporter_src),
        analyzer.extract_file(Path::new("src/reporter.test.ts"), test_src),
    ];

    assert!(files[0].architecture_facets.is_ui_kit_module);
    assert!(
        files[0]
            .architecture_facets
            .inline_terminal_ui_sites
            .is_empty()
    );
    assert!(!files[1].architecture_facets.is_ui_kit_module);
    assert_eq!(
        files[1].architecture_facets.inline_terminal_ui_sites.len(),
        2
    );

    let pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };

    let res = analyzer.analyze_package(
        &pkg,
        &files,
        Some(&[RuleId::ArchNoInlineTerminalUiPrimitives]),
    );
    assert_eq!(res.diagnostics.len(), 2);
    for diag in &res.diagnostics {
        assert_eq!(diag.rule, RuleId::ArchNoInlineTerminalUiPrimitives);
        assert_eq!(diag.file, PathBuf::from("src/reporter.ts"));
        assert_eq!(diag.severity, RuleSeverity::Warning);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert!(diag.autofix.is_none());
    }

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/terminal_ui.ts"), ui_kit_src.to_string());
    sources.insert(PathBuf::from("src/reporter.ts"), reporter_src.to_string());
    sources.insert(PathBuf::from("src/reporter.test.ts"), test_src.to_string());

    let (groups, capsules) =
        build_root_cause_groups_and_capsules(&files, &res.diagnostics, &sources);
    assert_eq!(groups.len(), 1);
    assert_eq!(capsules.len(), 1);
    let exemplar = capsules[0].exemplar.as_ref().expect("UI kit exemplar");
    assert_eq!(exemplar.file, PathBuf::from("src/terminal_ui.ts"));
}
