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
fn js_soc_rules_detect_bloated_entrypoints_mixed_io_presentation_static_catalogs_and_monoliths() {
    use dotore_core::{
        ArchitectureThresholdsConfig, ConcernBucket, build_root_cause_groups_and_capsules,
    };
    use dotore_js::{ProjectGraph, evaluate_project_with_packages};

    let analyzer = JsLanguageAnalyzer;

    // 1. Violating entrypoint: embeds direct I/O + domain type + inline JSX
    let bloated_main_src = r#"import fs from 'node:fs';

export interface BootstrapConfig {
    port: number;
    host: string;
}

export async function main() {
    const raw = fs.readFileSync('./config.json', 'utf8');
    const res = await fetch('https://api.example.com/bootstrap');
    const data = await res.json();
    return <main className="app-shell"><h1>{data.title}</h1><pre>{raw}</pre></main>;
}
"#;

    // 2. Adversarial valid thin entrypoint: mounts <App /> and delegates
    let thin_main_src = r#"import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';

const root = document.getElementById('root');
if (root) {
    createRoot(root).render(
        <StrictMode>
            <App />
        </StrictMode>
    );
}
"#;

    // 3. Adversarial valid thin CLI entrypoint: parses args and calls runner
    let thin_cli_src = r#"import { runCli } from './runner';

const args = process.argv.slice(2);
const exitCode = await runCli(args);
process.exit(exitCode);
"#;

    // 4. Violating mixed I/O + presentation module (production)
    let mixed_io_ui_src = r#"import React from 'react';

export async function OrdersDashboard({ accountId }: { accountId: string }) {
    const response = await fetch(`/api/accounts/${accountId}/orders`);
    const orders = await response.json();
    return (
        <section className="orders-view">
            <h2>Orders</h2>
            <ul>{orders.map((o: { id: string; total: number }) => <li key={o.id}>{o.total}</li>)}</ul>
        </section>
    );
}
"#;

    // 5. Adversarial valid thin route loader file (React Router / Remix loader + route component)
    let valid_route_loader_src = r#"import { useLoaderData } from 'react-router';

export async function loader() {
    const res = await fetch('/api/orders');
    return res.json();
}

export default function OrdersRoute() {
    const orders = useLoaderData();
    return <div className="route-orders">{orders.length}</div>;
}
"#;

    // 6. Violating mixed types + static catalog module (3 domain types + 26-entry static catalog)
    let mut catalog_entries = String::new();
    for i in 1..=26 {
        catalog_entries.push_str(&format!(
            "    {{ id: 'rule-{i}', severity: 'warning', enabled: true }},\n"
        ));
    }
    let mixed_catalog_types_src = format!(
        r#"export interface RuleRecord {{
    id: string;
    severity: RuleLevel;
    enabled: boolean;
}}

export type RuleLevel = 'error' | 'warning';

export enum RuleDomain {{
    Core = 'core',
    Arch = 'arch',
}}

export const BUILTIN_RULES: RuleRecord[] = [
{catalog_entries}];
"#
    );

    // 7. Adversarial valid pure catalog module (0 domain types, only imports type)
    let pure_catalog_src = format!(
        r#"import type {{ RuleRecord }} from './types';

export const SEPARATED_RULES: RuleRecord[] = [
{catalog_entries}];
"#
    );

    // 8. Violating mixed-domain monolith (>= 3 concern buckets AND >= 12 top-level symbols)
    let monolith_src = r#"import fs from 'node:fs';

export interface UserAccount { id: string; email: string; }
export interface InvoiceRecord { id: string; amount: number; }
export type PaymentStatus = 'pending' | 'paid' | 'failed';
export enum AuditCategory { Billing = 'billing', Security = 'security' }

export async function fetchUserAccount(id: string): Promise<UserAccount> {
    const res = await fetch(`/api/users/${id}`);
    return res.json();
}

export function readInvoiceCache(path: string): string {
    return fs.readFileSync(path, 'utf8');
}

export function validateUserEmail(email: string): boolean {
    if (!email.includes('@')) {
        return false;
    }
    return email.trim().length > 3;
}

export function parseInvoiceLine(line: string): InvoiceRecord {
    const parts = line.split(',');
    return { id: parts[0] ?? '', amount: Number(parts[1] ?? 0) };
}

export function normalizePaymentStatus(raw: string): PaymentStatus {
    if (raw === 'paid') return 'paid';
    if (raw === 'failed') return 'failed';
    return 'pending';
}

export function computeInvoiceTotal(items: InvoiceRecord[]): number {
    let sum = 0;
    for (const item of items) {
        sum += item.amount;
    }
    return sum;
}

export function AccountSummaryBanner({ user }: { user: UserAccount }) {
    return <header className="account-banner"><span>{user.email}</span></header>;
}

export function InvoiceTableView({ invoices }: { invoices: InvoiceRecord[] }) {
    return <section className="invoices">{invoices.map((inv) => <div key={inv.id}>{inv.amount}</div>)}</section>;
}
"#;

    // 9. Adversarial valid large cohesive parser (>= 12 top-level symbols, but only TypeDefinitions + AstOrValidationHelper)
    let cohesive_parser_src = r#"export interface Token { kind: string; text: string; }
export type NodeKind = 'ident' | 'number' | 'binary';

export function isDigit(ch: string): boolean { return ch >= '0' && ch <= '9'; }
export function isAlpha(ch: string): boolean { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); }
export function trimToken(raw: string): string { return raw.trim(); }
export function makeToken(kind: string, text: string): Token { return { kind, text }; }
export function parseIdent(src: string): Token { return makeToken('ident', trimToken(src)); }
export function parseNumber(src: string): Token { return makeToken('number', trimToken(src)); }
export function parsePrimary(src: string): Token { return isDigit(src[0] ?? '') ? parseNumber(src) : parseIdent(src); }
export function parseUnary(src: string): Token { return parsePrimary(src); }
export function parseMultiplicative(src: string): Token { return parseUnary(src); }
export function parseAdditive(src: string): Token { return parseMultiplicative(src); }
export function parseComparison(src: string): Token { return parseAdditive(src); }
export function parseExpression(src: string): Token { return parseComparison(src); }
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/main.tsx"), bloated_main_src),
        analyzer.extract_file(Path::new("apps/clean/src/main.tsx"), thin_main_src),
        analyzer.extract_file(Path::new("bin/cli.ts"), thin_cli_src),
        analyzer.extract_file(
            Path::new("src/components/OrdersDashboard.tsx"),
            mixed_io_ui_src,
        ),
        analyzer.extract_file(Path::new("src/routes/orders.tsx"), valid_route_loader_src),
        analyzer.extract_file(
            Path::new("src/components/OrdersDashboard.test.tsx"),
            mixed_io_ui_src,
        ),
        analyzer.extract_file(Path::new("src/rules/catalog.ts"), &mixed_catalog_types_src),
        analyzer.extract_file(Path::new("src/rules/data.ts"), &pure_catalog_src),
        analyzer.extract_file(Path::new("src/monolith.tsx"), monolith_src),
        analyzer.extract_file(Path::new("src/parser.ts"), cohesive_parser_src),
    ];

    // Verify ArchitectureFileFacets were populated on ExtractedFile
    let main_extracted = &files[0];
    assert!(main_extracted.architecture_facets.is_entrypoint);
    assert!(
        main_extracted
            .architecture_facets
            .has_bucket(ConcernBucket::DataOrNetworkIo)
    );
    assert!(
        main_extracted
            .architecture_facets
            .has_bucket(ConcernBucket::TerminalOrUiPresentation)
    );

    let catalog_extracted = &files[6];
    assert_eq!(catalog_extracted.architecture_facets.public_type_count, 3);
    assert_eq!(
        catalog_extracted
            .architecture_facets
            .static_catalog_sites
            .len(),
        1
    );
    assert_eq!(
        catalog_extracted.architecture_facets.static_catalog_sites[0].entry_count,
        26
    );

    let pkg = WorkspacePackage {
        name: "web".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };

    let soc_rules = [
        RuleId::ArchThinEntrypoint,
        RuleId::ArchNoMixedIoAndPresentation,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        RuleId::ArchNoMixedDomainMonolith,
    ];
    let res = analyzer.analyze_package(&pkg, &files, Some(&soc_rules));

    for diag in &res.diagnostics {
        assert_eq!(diag.severity, RuleSeverity::Warning);
        assert_eq!(diag.tier, PrescriptionTier::Refactor);
        assert!(diag.autofix.is_none());
    }

    let by_file_and_rule: Vec<(PathBuf, RuleId)> = res
        .diagnostics
        .iter()
        .map(|d| (d.file.clone(), d.rule))
        .collect();

    // Positive detections
    assert!(
        by_file_and_rule.contains(&(PathBuf::from("src/main.tsx"), RuleId::ArchThinEntrypoint)),
        "Expected ArchThinEntrypoint on src/main.tsx, got: {by_file_and_rule:#?}"
    );
    assert!(
        by_file_and_rule.contains(&(
            PathBuf::from("src/components/OrdersDashboard.tsx"),
            RuleId::ArchNoMixedIoAndPresentation
        )),
        "Expected ArchNoMixedIoAndPresentation on OrdersDashboard.tsx, got: {by_file_and_rule:#?}"
    );
    assert!(
        by_file_and_rule.contains(&(
            PathBuf::from("src/rules/catalog.ts"),
            RuleId::ArchSeparateStaticCatalogFromTypes
        )),
        "Expected ArchSeparateStaticCatalogFromTypes on src/rules/catalog.ts, got: {by_file_and_rule:#?}"
    );
    assert!(
        by_file_and_rule.contains(&(
            PathBuf::from("src/monolith.tsx"),
            RuleId::ArchNoMixedDomainMonolith
        )),
        "Expected ArchNoMixedDomainMonolith on src/monolith.tsx, got: {by_file_and_rule:#?}"
    );

    // Zero diagnostics on adversarial valid files
    for valid_path in [
        "apps/clean/src/main.tsx",
        "bin/cli.ts",
        "src/routes/orders.tsx",
        "src/components/OrdersDashboard.test.tsx",
        "src/rules/data.ts",
        "src/parser.ts",
    ] {
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.file == Path::new(valid_path)),
            "Expected 0 SoC diagnostics on valid file `{valid_path}`, got: {:#?}",
            res.diagnostics
        );
    }

    // Verify Contextual Owner spans: touching an unrelated line outside the catalog does NOT trigger it,
    // while touching a line inside the catalog declaration DOES trigger it under contextual-scope.
    let catalog_diag = res
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::ArchSeparateStaticCatalogFromTypes)
        .expect("catalog diagnostic");
    let change_outside_catalog = ChangedFileLineRanges {
        file: PathBuf::from("src/rules/catalog.ts"),
        ranges: vec![(1, 1)],
        deletion_lines: Vec::new(),
    };
    assert!(!diagnostic_intersects_changed_lines(
        catalog_diag,
        Some(&files[6]),
        Some(&mixed_catalog_types_src),
        &change_outside_catalog,
        false,
    ));
    assert!(!diagnostic_intersects_changed_lines(
        catalog_diag,
        Some(&files[6]),
        Some(&mixed_catalog_types_src),
        &change_outside_catalog,
        true,
    ));
    let change_inside_catalog = ChangedFileLineRanges {
        file: PathBuf::from("src/rules/catalog.ts"),
        ranges: vec![(16, 16)],
        deletion_lines: Vec::new(),
    };
    assert!(diagnostic_intersects_changed_lines(
        catalog_diag,
        Some(&files[6]),
        Some(&mixed_catalog_types_src),
        &change_inside_catalog,
        true,
    ));
    // Verify ProjectGraph PlannerContext architecture_facets_for_file and Fix Capsules
    let file_irs: Vec<FileIr> = files
        .iter()
        .filter_map(|f| f.downcast_payload::<FileIr>().cloned())
        .collect();
    let graph = ProjectGraph::build(file_irs);
    let graph_diags =
        evaluate_project_with_packages(&graph, std::slice::from_ref(&pkg), Some(&soc_rules));
    assert_eq!(graph_diags.len(), res.diagnostics.len());

    let mut sources = HashMap::new();
    for f in &files {
        sources.insert(f.path.clone(), f.source.clone());
    }
    let (groups, capsules) = build_root_cause_groups_and_capsules(&graph, &graph_diags, &sources);
    assert!(!groups.is_empty());
    assert_eq!(groups.len(), capsules.len());
    for capsule in &capsules {
        assert!(!capsule.caller_site_excerpts.is_empty());
        assert!(capsule.exemplar.is_some());
    }

    // Verify threshold overrides in DotoreConfig::architecture
    let mut relaxed_pkg = pkg.clone();
    relaxed_pkg.config.architecture = ArchitectureThresholdsConfig {
        min_types_with_catalog: 10,
        min_static_catalog_entries: 100,
        max_entrypoint_statements: 200,
        min_monolith_domain_clusters: 6,
        min_monolith_symbols: 50,
        ..ArchitectureThresholdsConfig::default()
    };
    let relaxed_res = analyzer.analyze_package(&relaxed_pkg, &files, Some(&soc_rules));
    assert!(
        !relaxed_res
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchSeparateStaticCatalogFromTypes),
        "Expected relaxed catalog thresholds to suppress ArchSeparateStaticCatalogFromTypes"
    );
    assert!(
        !relaxed_res
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchNoMixedDomainMonolith),
        "Expected relaxed monolith thresholds to suppress ArchNoMixedDomainMonolith"
    );

    // Verify inline suppressions (`// dotore-disable-next-line`)
    let suppressed_mixed_src =
        format!("// dotore-disable-next-line arch-no-mixed-io-and-presentation\n{mixed_io_ui_src}");
    let suppressed_file = analyzer.extract_file(
        Path::new("src/components/SuppressedOrders.tsx"),
        &suppressed_mixed_src,
    );
    let suppressed_res = analyzer.analyze_package(
        &pkg,
        &[suppressed_file],
        Some(&[RuleId::ArchNoMixedIoAndPresentation]),
    );
    assert!(
        suppressed_res.diagnostics.is_empty(),
        "Expected inline suppression to silence ArchNoMixedIoAndPresentation, got: {:#?}",
        suppressed_res.diagnostics
    );
}

#[test]
fn js_soc_rules_cover_statement_budgets_cli_terminal_boxes_angular_templates_and_custom_thresholds()
{
    use dotore_core::ArchitectureThresholdsConfig;

    let analyzer = JsLanguageAnalyzer;

    // 1. Entrypoint exceeding custom `max_entrypoint_statements: 5` without I/O
    let statement_heavy_cli_src = r#"import { parseArgs } from './args';

export function cli(rawArgs: string[]): number {
    const parsed = parseArgs(rawArgs);
    let total = 0;
    const stepOne = parsed.count + 1;
    const stepTwo = stepOne * 2;
    const stepThree = stepTwo - 1;
    total += stepThree;
    return total;
}
"#;

    // 2. CLI command module mixing Prisma/DB I/O with inline ANSI & Unicode box-drawing presentation
    let cli_mixed_io_box_src = r#"export async function renderAccountStatus(prisma: any, db: any, userId: string) {
    const account = await prisma.account.findUnique({ where: { id: userId } });
    const rows = await db.query('SELECT * FROM audit_log WHERE user_id = $1', [userId]);
    const header = "\x1b[32m┌────────────────────────┐\x1b[0m";
    const footer = "└────────────────────────┘";
    return `${header}\n${account.email} (${rows.length})\n${footer}`;
}
"#;

    // 3. Angular @Component mixing axios/indexedDB I/O with inline HTML template presentation
    let angular_mixed_src = r#"import { Component } from '@angular/core';
import axios from 'axios';

@Component({
    selector: 'app-billing',
    template: `<div class="billing-card"><span>Billing</span></div>`
})
export class BillingComponent {
    async loadInvoices() {
        const res = await axios.get('/api/invoices');
        indexedDB.open('billing-cache', 1);
        return res.data;
    }
}
"#;

    // 4. Module with 2 domain types + 5-entry catalog (clean under defaults, flagged when thresholds lowered)
    let small_catalog_src = r#"export interface MetricDef {
    key: string;
    unit: MetricUnit;
}

export type MetricUnit = 'ms' | 'bytes';

export const METRIC_DEFS: readonly MetricDef[] = [
    { key: 'tti', unit: 'ms' },
    { key: 'fcp', unit: 'ms' },
    { key: 'lcp', unit: 'ms' },
    { key: 'cls', unit: 'ms' },
    { key: 'heap', unit: 'bytes' },
] as const;
"#;

    // 5. Cohesive state machine with 14 top-level symbols across only 2 buckets (TypeDefinitions + AstOrValidationHelper)
    let state_machine_src = r#"export type MachineState = 'idle' | 'loading' | 'ready' | 'error';
export interface MachineEvent { kind: string; payload?: string; }

export function isIdle(s: MachineState): boolean { return s === 'idle'; }
export function isLoading(s: MachineState): boolean { return s === 'loading'; }
export function isReady(s: MachineState): boolean { return s === 'ready'; }
export function isError(s: MachineState): boolean { return s === 'error'; }
export function validateEvent(e: MachineEvent): boolean { return e.kind.length > 0; }
export function normalizeEventKind(k: string): string { return k.trim().toLowerCase(); }
export function transitionFromIdle(e: MachineEvent): MachineState { return e.kind === 'fetch' ? 'loading' : 'idle'; }
export function transitionFromLoading(e: MachineEvent): MachineState { return e.kind === 'resolve' ? 'ready' : 'error'; }
export function transitionFromReady(e: MachineEvent): MachineState { return e.kind === 'reset' ? 'idle' : 'ready'; }
export function transitionFromError(e: MachineEvent): MachineState { return e.kind === 'retry' ? 'loading' : 'error'; }
export function computeNextState(s: MachineState, e: MachineEvent): MachineState {
    if (!validateEvent(e)) return s;
    if (s === 'idle') return transitionFromIdle(e);
    if (s === 'loading') return transitionFromLoading(e);
    if (s === 'ready') return transitionFromReady(e);
    return transitionFromError(e);
}
export function formatMachineState(s: MachineState): string { return `[state:${s}]`; }
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/cli.ts"), statement_heavy_cli_src),
        analyzer.extract_file(Path::new("src/commands/status.ts"), cli_mixed_io_box_src),
        analyzer.extract_file(Path::new("src/billing.component.ts"), angular_mixed_src),
        analyzer.extract_file(Path::new("src/metrics.ts"), small_catalog_src),
        analyzer.extract_file(Path::new("src/stateMachine.ts"), state_machine_src),
    ];

    let soc_rules = [
        RuleId::ArchThinEntrypoint,
        RuleId::ArchNoMixedIoAndPresentation,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        RuleId::ArchNoMixedDomainMonolith,
    ];

    // Under default thresholds:
    // - `src/commands/status.ts` and `src/billing.component.ts` fire `ArchNoMixedIoAndPresentation`
    // - `src/cli.ts` (7 statements <= 25), `src/metrics.ts` (2 types, 5 entries), and `src/stateMachine.ts` emit 0 diagnostics
    let default_pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_angular(),
        config: DotoreConfig::default(),
    };
    let default_res = analyzer.analyze_package(&default_pkg, &files, Some(&soc_rules));
    let default_hits: Vec<(PathBuf, RuleId)> = default_res
        .diagnostics
        .iter()
        .map(|d| (d.file.clone(), d.rule))
        .collect();
    assert!(default_hits.contains(&(
        PathBuf::from("src/commands/status.ts"),
        RuleId::ArchNoMixedIoAndPresentation
    )));
    assert!(default_hits.contains(&(
        PathBuf::from("src/billing.component.ts"),
        RuleId::ArchNoMixedIoAndPresentation
    )));
    assert!(
        !default_hits
            .iter()
            .any(|(f, _)| f == Path::new("src/cli.ts")
                || f == Path::new("src/metrics.ts")
                || f == Path::new("src/stateMachine.ts")),
        "Expected 0 default diagnostics on cli.ts, metrics.ts, and stateMachine.ts, got: {default_hits:#?}"
    );

    // Under tightened thresholds (`max_entrypoint_statements: 5`, `min_types_with_catalog: 2`, `min_static_catalog_entries: 4`):
    // `src/cli.ts` fires `ArchThinEntrypoint` and `src/metrics.ts` fires `ArchSeparateStaticCatalogFromTypes`,
    // while `src/stateMachine.ts` still emits 0 diagnostics!
    let mut strict_pkg = default_pkg;
    strict_pkg.config.architecture = ArchitectureThresholdsConfig {
        max_entrypoint_statements: 5,
        min_types_with_catalog: 2,
        min_static_catalog_entries: 4,
        ..ArchitectureThresholdsConfig::default()
    };
    let strict_res = analyzer.analyze_package(&strict_pkg, &files, Some(&soc_rules));
    let strict_hits: Vec<(PathBuf, RuleId)> = strict_res
        .diagnostics
        .iter()
        .map(|d| (d.file.clone(), d.rule))
        .collect();
    assert!(strict_hits.contains(&(PathBuf::from("src/cli.ts"), RuleId::ArchThinEntrypoint)));
    assert!(strict_hits.contains(&(
        PathBuf::from("src/metrics.ts"),
        RuleId::ArchSeparateStaticCatalogFromTypes
    )));
    assert!(
        !strict_hits
            .iter()
            .any(|(f, _)| f == Path::new("src/stateMachine.ts")),
        "Cohesive state machine must still emit 0 diagnostics under strict thresholds"
    );
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

#[test]
fn js_language_analyzer_supports_lowered_min_helper_statements_threshold() {
    let analyzer = JsLanguageAnalyzer;

    let mod_a = r#"function clampScore(val: number): number {
    const a = Math.max(0, val);
    const b = Math.min(100, a);
    return b;
}
export const scoreA = (x: number) => clampScore(x);
"#;
    let mod_b = r#"function boundValue(input: number): number {
    const low = Math.max(0, input);
    const high = Math.min(100, low);
    return high;
}
export const scoreB = (x: number) => boundValue(x);
"#;

    let files = vec![
        analyzer.extract_file(Path::new("src/a.ts"), mod_a),
        analyzer.extract_file(Path::new("src/b.ts"), mod_b),
    ];
    assert_eq!(files[0].architecture_facets.helper_fingerprints.len(), 1);
    assert_eq!(
        files[0].architecture_facets.helper_fingerprints[0].statement_count,
        3
    );

    // Default threshold (min_helper_statements = 4) skips 3-statement helpers
    let default_pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };
    let default_res = analyzer.analyze_package(
        &default_pkg,
        &files,
        Some(&[RuleId::ArchNoDuplicatedHelperLogic]),
    );
    assert!(default_res.diagnostics.is_empty());

    // Lowered threshold (min_helper_statements = 3) catches 3-statement helpers
    let mut lowered_cfg = DotoreConfig::default();
    lowered_cfg.architecture.min_helper_statements = 3;
    let lowered_pkg = WorkspacePackage {
        name: "app".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: lowered_cfg,
    };
    let lowered_res = analyzer.analyze_package(
        &lowered_pkg,
        &files,
        Some(&[RuleId::ArchNoDuplicatedHelperLogic]),
    );
    assert_eq!(lowered_res.diagnostics.len(), 2);
}
