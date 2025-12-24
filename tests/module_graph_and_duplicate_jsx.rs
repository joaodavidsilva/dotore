//! Integration tests for Ticket #04:
//! - Module specifier resolution (`import`/`export`, `export *`, dynamic `import()`, `require()`, `tsconfig.json` `baseUrl`/`paths`, workspace packages, framework entrypoints, build scripts, platform suffixes)
//! - Reachability analysis (`unused-file`, `unused-export`, `unused-type`)
//! - Package manifest dependency cross-referencing (`unused-dependency`, `unused-dev-dependency`)
//! - Strongly connected component cycle analysis (`circular-dependency`)
//! - Structural JSX subtree normalization, hashing, and Root-Cause Grouping (`duplicate-jsx-subtree`)

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{RuleCategory, RuleId, RuleSeverity, RuleTag, analyze_project_sources};

#[test]
fn resolves_module_specifiers_and_reports_unused_file_export_and_type_accurately() {
    for rule in [
        RuleId::UnusedFile,
        RuleId::UnusedExport,
        RuleId::UnusedType,
        RuleId::UnusedDependency,
        RuleId::UnusedDevDependency,
        RuleId::CircularDependency,
        RuleId::DuplicateJsxSubtree,
    ] {
        let meta = rule.metadata();
        assert_eq!(meta.category, RuleCategory::Maintainability);
        assert_eq!(meta.default_severity, RuleSeverity::Warning);
        assert!(meta.tags.contains(&RuleTag::ProjectAnalysis));
    }

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "name": "monorepo-root",
                    "private": true,
                    "workspaces": ["apps/*", "packages/*"],
                    "scripts": {
                        "seed": "tsx ./scripts/seed-db.ts"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("tsconfig.json"),
                r#"{
                    "compilerOptions": {
                        "baseUrl": ".",
                        "paths": {
                            "@web/*": ["apps/web/src/*"],
                            "@shared-utils/*": ["packages/shared/src/utils/*"]
                        }
                    }
                }"#
                .to_string(),
            ),
            // Workspace library package `@acme/shared`
            (
                PathBuf::from("packages/shared/package.json"),
                r#"{
                    "name": "@acme/shared",
                    "exports": {
                        ".": "./src/index.ts"
                    },
                    "peerDependencies": {
                        "react": "^19.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("packages/shared/src/index.ts"),
                r#"
                export * from './barrel';
                export function publicLibraryHelper() {
                    return 'public-lib-export-never-flagged';
                }
                export interface PublicLibraryContract {
                    id: string;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("packages/shared/src/barrel.ts"),
                r#"
                export { formatPrice } from './utils/math.js';
                "#
                .to_string(),
            ),
            (
                PathBuf::from("packages/shared/src/utils/math.ts"),
                r#"
                export type InternalPrecision = number;
                export function formatPrice(amount: InternalPrecision): string {
                    return `$${amount}`;
                }
                export const deadSharedHelper = 42;
                export interface DeadSharedShape {
                    obsolete: boolean;
                }
                "#
                .to_string(),
            ),
            // Next.js + Expo + React Router style application `apps/web`
            (
                PathBuf::from("apps/web/package.json"),
                r#"{
                    "name": "@acme/web",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "next": "^15.0.0",
                        "react-native": "0.76.0",
                        "@acme/shared": "workspace:*"
                    }
                }"#
                .to_string(),
            ),
            // Framework entrypoint: Next.js App Router page
            (
                PathBuf::from("apps/web/app/dashboard/page.tsx"),
                r#"
                import { formatPrice } from '@acme/shared';
                import { Widget } from '@web/components/Widget';
                import { NativeBanner } from '../components/NativeBanner';
                import * as ns from '@shared-utils/namespace';

                export const metadata = { title: 'Dashboard' };
                export async function generateStaticParams() {
                    return [];
                }

                export default function DashboardPage() {
                    const lazyMod = import('../features/lazy-panel');
                    const cjsMod = require('../features/cjs-helper');
                    console.log(lazyMod, cjsMod, ns.usedNsMember);
                    return (
                        <main>
                            <Widget label={formatPrice(10)} />
                            <NativeBanner />
                        </main>
                    );
                }
                "#
                .to_string(),
            ),
            // Framework entrypoint: TanStack Start / React Router route file
            (
                PathBuf::from("apps/web/src/routes/users.tsx"),
                r#"
                export async function loader() {
                    return { users: [] };
                }
                export default function UsersRoute() {
                    return <div>Users</div>;
                }
                "#
                .to_string(),
            ),
            // Component resolved via tsconfig `@web/*` alias
            (
                PathBuf::from("apps/web/src/components/Widget.tsx"),
                r#"
                export interface UsedWidgetProps {
                    label: string;
                }
                export interface UnusedWidgetType {
                    debug: boolean;
                }
                export function Widget({ label }: UsedWidgetProps) {
                    return <span>{label}</span>;
                }
                export function unusedWidgetHelper() {
                    return 'dead-value-export';
                }
                "#
                .to_string(),
            ),
            // Platform-specific siblings (`.ios.tsx`, `.android.tsx`, `.native.tsx`, `.web.tsx`)
            // Importing `../components/NativeBanner` without platform suffix must mark ALL siblings reachable
            // and credit `NativeBanner` across every sibling while still flagging `unusedPlatformExport`!
            (
                PathBuf::from("apps/web/app/components/NativeBanner.ios.tsx"),
                r#"
                export function NativeBanner() {
                    return <div>iOS Banner</div>;
                }
                export const unusedIosExport = 'unused-ios';
                "#
                .to_string(),
            ),
            (
                PathBuf::from("apps/web/app/components/NativeBanner.android.tsx"),
                r#"
                export function NativeBanner() {
                    return <div>Android Banner</div>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("apps/web/app/components/NativeBanner.native.tsx"),
                r#"
                export function NativeBanner() {
                    return <div>Native Banner</div>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("apps/web/app/components/NativeBanner.web.tsx"),
                r#"
                export function NativeBanner() {
                    return <div>Web Banner</div>;
                }
                "#
                .to_string(),
            ),
            // Namespace target resolved via `@shared-utils/*`
            (
                PathBuf::from("packages/shared/src/utils/namespace.ts"),
                r#"
                export const usedNsMember = 'used';
                export const unusedNsMember = 'unused';
                "#
                .to_string(),
            ),
            // Dynamically imported module (`import('../features/lazy-panel')` marks all exports used)
            (
                PathBuf::from("apps/web/app/features/lazy-panel.tsx"),
                r#"
                export default function LazyPanel() {
                    return <section>Lazy</section>;
                }
                export const lazyNamedExport = 'also-considered-used-via-dynamic-import';
                "#
                .to_string(),
            ),
            // CommonJS required module (`require('../features/cjs-helper')`)
            (
                PathBuf::from("apps/web/app/features/cjs-helper.ts"),
                r#"
                export const cjsHelper = () => 'ok';
                "#
                .to_string(),
            ),
            // Build-script referenced file (`"seed": "tsx ./scripts/seed-db.ts"`) + its imported helper
            (
                PathBuf::from("scripts/seed-db.ts"),
                r#"
                import { connectSeedDb } from '../apps/web/src/lib/seed-client';
                connectSeedDb();
                "#
                .to_string(),
            ),
            (
                PathBuf::from("apps/web/src/lib/seed-client.ts"),
                r#"
                export function connectSeedDb() {
                    return true;
                }
                "#
                .to_string(),
            ),
            // Truly unreachable orphan file
            (
                PathBuf::from("apps/web/src/components/OrphanModal.tsx"),
                r#"
                export function OrphanModal() {
                    return <div>Never imported anywhere</div>;
                }
                "#
                .to_string(),
            ),
        ],
        Some(&[RuleId::UnusedFile, RuleId::UnusedExport, RuleId::UnusedType]),
    );

    let unused_files: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::UnusedFile)
        .map(|d| d.file.to_string_lossy().to_string())
        .collect();
    assert_eq!(
        unused_files,
        vec!["apps/web/src/components/OrphanModal.tsx".to_string()],
        "Expected only OrphanModal.tsx to be flagged as unused-file, got: {unused_files:#?}"
    );

    let unused_exports: Vec<(String, String)> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::UnusedExport)
        .map(|d| (d.file.to_string_lossy().to_string(), d.target_name.clone()))
        .collect();
    assert!(
        unused_exports.contains(&(
            "packages/shared/src/utils/math.ts".to_string(),
            "deadSharedHelper".to_string()
        )),
        "Expected deadSharedHelper in unused_exports: {unused_exports:#?}"
    );
    assert!(
        unused_exports.contains(&(
            "apps/web/src/components/Widget.tsx".to_string(),
            "unusedWidgetHelper".to_string()
        )),
        "Expected unusedWidgetHelper in unused_exports: {unused_exports:#?}"
    );
    assert!(
        unused_exports.contains(&(
            "apps/web/app/components/NativeBanner.ios.tsx".to_string(),
            "unusedIosExport".to_string()
        )),
        "Expected unusedIosExport in unused_exports: {unused_exports:#?}"
    );
    assert!(
        unused_exports.contains(&(
            "packages/shared/src/utils/namespace.ts".to_string(),
            "unusedNsMember".to_string()
        )),
        "Expected unusedNsMember in unused_exports: {unused_exports:#?}"
    );
    // Ensure used exports, library entrypoint exports, route conventions, and platform sibling used exports are NOT flagged
    for forbidden in [
        "publicLibraryHelper",
        "formatPrice",
        "metadata",
        "generateStaticParams",
        "loader",
        "Widget",
        "NativeBanner",
        "usedNsMember",
        "lazyNamedExport",
        "cjsHelper",
        "connectSeedDb",
    ] {
        assert!(
            !unused_exports.iter().any(|(_, name)| name == forbidden),
            "Should NOT have flagged `{forbidden}` as unused-export: {unused_exports:#?}"
        );
    }

    let unused_types: Vec<(String, String)> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::UnusedType)
        .map(|d| (d.file.to_string_lossy().to_string(), d.target_name.clone()))
        .collect();
    assert_eq!(
        unused_types,
        vec![
            (
                "apps/web/src/components/Widget.tsx".to_string(),
                "UnusedWidgetType".to_string()
            ),
            (
                "packages/shared/src/utils/math.ts".to_string(),
                "DeadSharedShape".to_string()
            ),
        ],
        "Unexpected unused_types: {unused_types:#?}"
    );
}

#[test]
fn cross_references_package_manifest_dependencies_and_reports_unused_deps_and_dev_deps() {
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                    "name": "manifest-test",
                    "private": true,
                    "scripts": {
                        "db:migrate": "drizzle-kit push",
                        "lint": "dotore check ."
                    },
                    "dependencies": {
                        "react": "^19.0.0",
                        "zod": "^4.0.0",
                        "@config-plugins/react-native-webrtc": "^14.0.0",
                        "stale-runtime-pkg": "^1.2.3"
                    },
                    "devDependencies": {
                        "typescript": "^5.7.0",
                        "@types/node": "^22.0.0",
                        "@types/zod": "^4.0.0",
                        "@types/unreferenced-lib": "^1.0.0",
                        "drizzle-kit": "^0.30.0",
                        "@vitejs/plugin-react": "^4.3.0",
                        "stale-dev-pkg": "^2.0.0"
                    },
                    "peerDependencies": {
                        "peer-provided-pkg": "^1.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("app.config.ts"),
                r#"
                export default {
                    name: "demo",
                    plugins: [
                        "@config-plugins/react-native-webrtc",
                        "./plugins/with-custom-flag"
                    ]
                };
                "#
                .to_string(),
            ),
            (
                PathBuf::from("plugins/with-custom-flag.ts"),
                r#"
                export default function withCustomFlag(config: unknown) {
                    return config;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/index.tsx"),
                r#"
                import { z } from 'zod';
                import 'virtual:pwa-register';
                import path from 'node:path';

                const schema = z.string();
                export function App() {
                    return <div>{schema.parse(path.sep)}</div>;
                }
                "#
                .to_string(),
            ),
        ],
        Some(&[
            RuleId::UnusedDependency,
            RuleId::UnusedDevDependency,
            RuleId::UnusedFile,
        ]),
    );

    // Local Expo plugin `./plugins/with-custom-flag` must NOT be flagged as `unused-file`
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::UnusedFile),
        "Expected no unused-file diagnostics, got: {:#?}",
        report.diagnostics
    );

    let unused_deps: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::UnusedDependency)
        .map(|d| d.target_name.clone())
        .collect();
    assert_eq!(
        unused_deps,
        vec!["stale-runtime-pkg".to_string()],
        "Unexpected unused-dependency findings: {unused_deps:#?}"
    );

    let unused_dev_deps: Vec<String> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::UnusedDevDependency)
        .map(|d| d.target_name.clone())
        .collect();
    assert_eq!(
        unused_dev_deps,
        vec![
            "@types/unreferenced-lib".to_string(),
            "stale-dev-pkg".to_string(),
        ],
        "Unexpected unused-dev-dependency findings: {unused_dev_deps:#?}"
    );
}

#[test]
fn detects_strongly_connected_component_runtime_cycles_while_ignoring_type_only_and_dynamic_edges()
{
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/index.ts"),
                r#"
                import { a } from './cycle-a';
                import { x } from './three-x';
                import { valA } from './erased-a';
                import { dynA } from './dyn-a';
                console.log(a(), x(), valA, dynA());
                "#
                .to_string(),
            ),
            // 1. 2-node runtime value cycle: `src/cycle-a.ts -> src/cycle-b.ts -> src/cycle-a.ts`
            (
                PathBuf::from("src/cycle-b.ts"),
                r#"
                import { a } from './cycle-a';
                export function b(): number {
                    return a() + 1;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/cycle-a.ts"),
                r#"
                import { b } from './cycle-b';
                export function a(): number {
                    return b() + 1;
                }
                "#
                .to_string(),
            ),
            // 2. 3-node runtime value cycle: `src/three-x.ts -> src/three-y.ts -> src/three-z.ts -> src/three-x.ts`
            (
                PathBuf::from("src/three-z.ts"),
                r#"
                import { x } from './three-x';
                export const z = () => x();
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/three-x.ts"),
                r#"
                import { y } from './three-y';
                export const x = () => y();
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/three-y.ts"),
                r#"
                import { z } from './three-z';
                export const y = () => z();
                "#
                .to_string(),
            ),
            // 3. Value-form import that resolves EXCLUSIVELY to a type-only export (`interface`) -> NOT a runtime cycle!
            (
                PathBuf::from("src/erased-a.ts"),
                r#"
                import { ErasedContractB } from './erased-b';
                export const valA: ErasedContractB = { ok: true };
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/erased-b.ts"),
                r#"
                import { valA } from './erased-a';
                export interface ErasedContractB {
                    ok: boolean;
                }
                export const readA = () => valA.ok;
                "#
                .to_string(),
            ),
            // 4. Dynamic `import()` back-edge -> NOT a synchronous initialization cycle!
            (
                PathBuf::from("src/dyn-a.ts"),
                r#"
                import { dynB } from './dyn-b';
                export const dynA = () => dynB();
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/dyn-b.ts"),
                r#"
                export const dynB = () => import('./dyn-a');
                "#
                .to_string(),
            ),
        ],
        Some(&[RuleId::CircularDependency]),
    );

    let cycles: Vec<(String, String)> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::CircularDependency)
        .map(|d| (d.file.to_string_lossy().to_string(), d.message.clone()))
        .collect();

    assert_eq!(
        cycles.len(),
        2,
        "Expected 2 runtime cycles, got: {cycles:#?}"
    );
    assert_eq!(cycles[0].0, "src/cycle-a.ts");
    assert!(
        cycles[0]
            .1
            .contains("src/cycle-a.ts → src/cycle-b.ts → src/cycle-a.ts"),
        "Unexpected 2-node cycle message: {}",
        cycles[0].1
    );
    assert_eq!(cycles[1].0, "src/three-x.ts");
    assert!(
        cycles[1]
            .1
            .contains("src/three-x.ts → src/three-y.ts → src/three-z.ts → src/three-x.ts"),
        "Unexpected 3-node cycle message: {}",
        cycles[1].1
    );
}

#[test]
fn detects_maximal_duplicate_jsx_subtrees_across_subjects_and_groups_participating_locations() {
    let account_src = r#"
        export function Account({ account }) {
            return (
                <AccountScreen>
                    <Page>
                        <section>
                            <header><Title /></header>
                            <main><Value value={account} /></main>
                            <footer><Button variant="primary" disabled={false} /></footer>
                        </section>
                    </Page>
                </AccountScreen>
            );
        }
    "#;

    let user_src = r#"
        export function User({ user }) {
            return (
                <UserScreen>
                    <Page>
                        <section>
                            <header><Title /></header>
                            <main><Value value={user} /></main>
                            <footer><Button variant="primary" disabled={false} /></footer>
                        </section>
                    </Page>
                </UserScreen>
            );
        }
    "#;

    // Different static string attribute (`variant="danger"`) must NOT match the `variant="primary"` family
    let different_variant_src = r#"
        export function DangerPanel({ item }) {
            return (
                <DangerScreen>
                    <Page>
                        <section>
                            <header><Title /></header>
                            <main><Value value={item} /></main>
                            <footer><Button variant="danger" disabled={false} /></footer>
                        </section>
                    </Page>
                </DangerScreen>
            );
        }
    "#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("src/account.tsx"), account_src.to_string()),
            (PathBuf::from("src/user.tsx"), user_src.to_string()),
            (
                PathBuf::from("src/danger.tsx"),
                different_variant_src.to_string(),
            ),
            // Test files must be excluded from duplicate-jsx-subtree corpus
            (
                PathBuf::from("src/ignored.test.tsx"),
                account_src.to_string(),
            ),
        ],
        Some(&[RuleId::DuplicateJsxSubtree]),
    );

    assert_eq!(
        report.diagnostics.len(),
        1,
        "Expected exactly 1 maximal duplicate-jsx-subtree diagnostic, got: {:#?}",
        report.diagnostics
    );
    let diag = &report.diagnostics[0];
    assert_eq!(diag.rule, RuleId::DuplicateJsxSubtree);
    assert_eq!(diag.file, PathBuf::from("src/account.tsx"));
    assert_eq!(diag.subject_name.as_deref(), Some("Account"));
    assert!(
        diag.target_name.starts_with("jsx:"),
        "Expected normalized JSX fingerprint in target_name, got: {}",
        diag.target_name
    );
    assert!(
        diag.message
            .contains("2 copies of this 8-node JSX tree appear across 2 files"),
        "Unexpected message: {}",
        diag.message
    );
    assert!(
        diag.message
            .contains("Composition path: Account > AccountScreen > Page"),
        "Unexpected composition path in message: {}",
        diag.message
    );

    // Participating locations are grouped on `caller_sites` for the Root-Cause Group / Fix Capsule
    assert_eq!(diag.caller_sites.len(), 2);
    assert_eq!(
        diag.caller_sites[0].caller_file,
        PathBuf::from("src/account.tsx")
    );
    assert_eq!(
        diag.caller_sites[0].parent_subject_name.as_deref(),
        Some("Account")
    );
    assert_eq!(diag.caller_sites[0].component_name, "Page");
    assert_eq!(
        diag.caller_sites[1].caller_file,
        PathBuf::from("src/user.tsx")
    );
    assert_eq!(
        diag.caller_sites[1].parent_subject_name.as_deref(),
        Some("User")
    );
    assert_eq!(diag.caller_sites[1].component_name, "Page");
    assert_eq!(report.root_cause_groups.len(), 1);
    assert!(
        report.root_cause_groups[0]
            .id
            .starts_with("rcg::duplicate-jsx-subtree::")
    );
    assert_eq!(report.root_cause_groups[0].blast_radius.file_count, 2);
    assert_eq!(report.fix_capsules.len(), 1);
    assert_eq!(report.fix_capsules[0].caller_site_excerpts.len(), 2);

    // Also verify same-file duplication across two distinct Subjects in one production file
    let single_file_report = analyze_project_sources(
        vec![(
            PathBuf::from("src/cards.tsx"),
            format!("{account_src}\n{user_src}"),
        )],
        Some(&[RuleId::DuplicateJsxSubtree]),
    );
    assert_eq!(single_file_report.diagnostics.len(), 1);
    assert_eq!(
        single_file_report.diagnostics[0].file,
        PathBuf::from("src/cards.tsx")
    );
    assert_eq!(single_file_report.diagnostics[0].caller_sites.len(), 2);
}

#[test]
fn cli_check_reports_all_seven_module_graph_and_duplicate_jsx_diagnostics_in_single_pass() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("dotore-ticket04-cli-{nanos}"));
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("package.json"),
        r#"{
            "name": "cli-graph-test",
            "private": true,
            "dependencies": {
                "react": "^19.0.0",
                "unused-prod-pkg": "^1.0.0"
            },
            "devDependencies": {
                "unused-dev-pkg": "^1.0.0"
            }
        }"#,
    )
    .unwrap();

    fs::write(
        dir.join("src/index.tsx"),
        r#"
        import { usedVal } from './lib';
        import { cycleA } from './cycle-a';

        export function FirstView({ a }) {
            console.log(usedVal, cycleA());
            return (
                <FirstShell>
                    <Card>
                        <header><Title /></header>
                        <main><Body text={a} /></main>
                        <footer><Action /></footer>
                    </Card>
                </FirstShell>
            );
        }

        export function SecondView({ b }) {
            return (
                <SecondShell>
                    <Card>
                        <header><Title /></header>
                        <main><Body text={b} /></main>
                        <footer><Action /></footer>
                    </Card>
                </SecondShell>
            );
        }
        "#,
    )
    .unwrap();

    fs::write(
        dir.join("src/lib.ts"),
        r#"
        export const usedVal = 1;
        export const unusedVal = 2;
        export interface UnusedShape {
            id: string;
        }
        "#,
    )
    .unwrap();

    fs::write(
        dir.join("src/orphan.ts"),
        r#"export const neverImported = true;"#,
    )
    .unwrap();

    fs::write(
        dir.join("src/cycle-a.ts"),
        r#"
        import { cycleB } from './cycle-b';
        export const cycleA = () => cycleB();
        "#,
    )
    .unwrap();

    fs::write(
        dir.join("src/cycle-b.ts"),
        r#"
        import { cycleA } from './cycle-a';
        export const cycleB = () => cycleA();
        "#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");
    let out = Command::new(bin)
        .args(["check", "--json"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "Expected exit 1 when findings are present, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for expected_rule in [
        "\"unused-file\"",
        "\"unused-export\"",
        "\"unused-type\"",
        "\"unused-dependency\"",
        "\"unused-dev-dependency\"",
        "\"circular-dependency\"",
        "\"duplicate-jsx-subtree\"",
    ] {
        assert!(
            stdout.contains(expected_rule),
            "Expected CLI JSON output to contain {expected_rule}, got:\n{stdout}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}
