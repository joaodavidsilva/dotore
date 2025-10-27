//! Integration tests for Ticket #01:
//! - Unified Rule Registry & structured metadata (`RuleId`, `RuleMetadata`, `RuleCategory`, `RuleTag`, `ContextualOwnerPolicy`)
//! - Workspace package discovery & automatic `CapabilityGate` inference
//! - User configuration loader (`dotore.config.*` and `package.json#dotore`) & CLI flag precedence
//! - Inline suppression comments (`dotore-disable-*`, `eslint-disable-*`, `oxlint-disable-*`) & `--no-inline-disables`
//! - `test-noise` / `migration-hint` file-context filtering & library entrypoint `app_only` suppression
//! - Single-pass OXC extraction (`SymbolOutline`, `ModuleIr`, `JsxElementIr`, mutations, async flows, security sinks)

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    Capability, CapabilityGate, CliOverrides, ContextualOwnerPolicy, DotoreConfig, PackageRole,
    PrescriptionTier, RuleCategory, RuleId, RuleSeverity, RuleSeverityOverride, RuleTag,
    ScanOptions, SecuritySinkKind, SymbolKind, analyze_project_sources, analyze_source,
    analyze_source_with_config, discover_workspace_packages, inspect_file_semantic,
    load_config_from_dir, parse_file_ir, rule_registry, scan_workspace,
    scan_workspace_with_overrides,
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dotore-{prefix}-{nanos}"))
}

#[test]
fn registry_exposes_structured_metadata_aliases_tags_categories_and_recipes() {
    let registry = rule_registry();
    assert!(
        registry.len() >= 25,
        "Expected comprehensive rule registry, got {}",
        registry.len()
    );

    for meta in registry {
        assert!(!meta.canonical_id.is_empty());
        assert_eq!(meta.qualified_key, format!("dotore/{}", meta.canonical_id));
        assert!(!meta.title.is_empty());
        assert!(!meta.docs_url.is_empty());
        assert!(
            !meta.recipe_markdown.is_empty(),
            "Rule {} missing compiled-in remediation recipe",
            meta.canonical_id
        );
        assert_eq!(RuleId::parse(meta.canonical_id), Some(meta.id));
        assert_eq!(RuleId::parse(meta.qualified_key), Some(meta.id));
        for &alias in meta.legacy_aliases {
            assert_eq!(
                RuleId::parse(alias),
                Some(meta.id),
                "Legacy alias {alias} failed to resolve to {:?}",
                meta.id
            );
            assert!(meta.id.matches_key(alias));
        }
    }

    for category in [
        RuleCategory::Bugs,
        RuleCategory::Performance,
        RuleCategory::Accessibility,
        RuleCategory::Security,
        RuleCategory::Maintainability,
    ] {
        assert!(
            registry.iter().any(|m| m.category == category),
            "Missing category {category:?} in registry"
        );
    }

    for (tag_str, expected_tag) in [
        ("test-noise", RuleTag::TestNoise),
        ("design", RuleTag::Design),
        ("migration-hint", RuleTag::MigrationHint),
        ("react-jsx-only", RuleTag::ReactJsxOnly),
        ("webgl", RuleTag::Webgl),
        ("three", RuleTag::Three),
        ("r3f", RuleTag::R3f),
        ("react-native", RuleTag::ReactNative),
        ("security-scan", RuleTag::SecurityScan),
        ("ink", RuleTag::Ink),
        ("server-action", RuleTag::ServerAction),
        ("project-analysis", RuleTag::ProjectAnalysis),
        ("opt-in", RuleTag::OptIn),
    ] {
        assert_eq!(RuleTag::parse(tag_str), Some(expected_tag));
        assert_eq!(expected_tag.as_str(), tag_str);
        assert!(
            registry.iter().any(|m| m.tags.contains(&expected_tag)),
            "Missing tag {expected_tag:?} in registry"
        );
    }

    let derived_meta = RuleId::NoDerivedState.metadata();
    assert_eq!(derived_meta.category, RuleCategory::Performance);
    assert_eq!(derived_meta.default_severity, RuleSeverity::Error);
    assert!(derived_meta.default_enabled);
    assert_eq!(derived_meta.default_tier, PrescriptionTier::Autofix);
    assert_eq!(
        derived_meta.contextual_owner,
        ContextualOwnerPolicy::Subject
    );
    assert!(
        derived_meta
            .legacy_aliases
            .contains(&"effect/no-derived-state")
    );
}

#[test]
fn capability_gate_infers_all_ecosystem_dependencies_and_react_compiler() {
    let pkg_json = r#"{
        "name": "full-stack-app",
        "private": true,
        "dependencies": {
            "react": "^19.0.0",
            "next": "^15.1.0",
            "@tanstack/react-query": "^5.0.0",
            "@tanstack/react-start": "^1.0.0",
            "three": "^0.170.0",
            "@react-three/fiber": "^9.0.0",
            "zustand": "^5.0.0",
            "jotai": "^2.10.0",
            "mobx": "^6.13.0",
            "valtio": "^2.0.0",
            "ink": "^5.0.0",
            "zod": "^4.0.0",
            "framer-motion": "^11.0.0"
        },
        "devDependencies": {
            "babel-plugin-react-compiler": "^19.0.0",
            "typescript": "^5.7.0"
        }
    }"#;

    let gate = CapabilityGate::from_package_json_str(pkg_json);
    for expected in [
        Capability::React,
        Capability::Nextjs,
        Capability::ServerActions,
        Capability::Ssr,
        Capability::TanstackQuery,
        Capability::TanstackStart,
        Capability::Three,
        Capability::R3f,
        Capability::Zustand,
        Capability::Jotai,
        Capability::Mobx,
        Capability::Valtio,
        Capability::Ink,
        Capability::Zod,
        Capability::Motion,
        Capability::ReactCompiler,
        Capability::TypeScript,
    ] {
        assert!(
            gate.has(expected),
            "Expected CapabilityGate to contain {expected:?}"
        );
    }
    assert!(gate.has_react_compiler);
    assert_eq!(gate.package_role, PackageRole::Application);

    // React Compiler disables `jsx-no-new-object-as-prop` via `disabled_when`
    assert!(!gate.allows_rule(RuleId::JsxNoNewObjectAsProp.metadata()));

    // Mobile Expo + React Native package
    let mobile_gate = CapabilityGate::from_package_json_str(
        r#"{ "dependencies": { "react": "19.0.0", "react-native": "0.76.0", "expo": "~52.0.0" } }"#,
    );
    assert!(mobile_gate.has(Capability::ReactNative));
    assert!(mobile_gate.has(Capability::Expo));
    assert!(!mobile_gate.has(Capability::Nextjs));

    // Pure Preact package (preact without react)
    let preact_gate =
        CapabilityGate::from_package_json_str(r#"{ "dependencies": { "preact": "^10.24.0" } }"#);
    assert!(preact_gate.has(Capability::Preact));
    assert!(preact_gate.has(Capability::PurePreact));
    assert!(preact_gate.allows_rule(RuleId::PreactNoReactImport.metadata()));
}

#[test]
fn workspace_discovery_computes_per_package_capability_gates_in_monorepo() {
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "name": "monorepo", "private": true, "workspaces": ["apps/*", "packages/*"] }"#
                    .to_string(),
            ),
            // 1. Next.js + TanStack Query web package
            (
                PathBuf::from("apps/web/package.json"),
                r#"{
                    "name": "@acme/web",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "next": "^15.0.0",
                        "@tanstack/react-query": "^5.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/web/src/Page.tsx"),
                r#"
                export function WebPage() {
                    useQuery({
                        queryKey: ['users'],
                        queryFn: () => {
                            fetch('/api/users');
                        },
                    });
                    return <div><img src="/hero.png" alt="Hero" />Raw web text is valid here</div>;
                }
                "#
                .to_string(),
            ),
            // 2. React Native + Expo mobile package
            (
                PathBuf::from("apps/mobile/package.json"),
                r#"{
                    "name": "@acme/mobile",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "react-native": "0.76.0",
                        "expo": "~52.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/mobile/src/Screen.tsx"),
                r#"
                export function MobileScreen({ envKey }: { envKey: string }) {
                    const secret = process.env[envKey];
                    return <View>Raw text outside Text {secret}</View>;
                }
                "#
                .to_string(),
            ),
            // 3. R3F + Zustand + Jotai + MobX + Zod package
            (
                PathBuf::from("packages/scene/package.json"),
                r#"{
                    "name": "@acme/scene",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "three": "^0.170.0",
                        "@react-three/fiber": "^9.0.0",
                        "zustand": "^5.0.0",
                        "jotai": "^2.0.0",
                        "mobx": "^6.12.0",
                        "zod": "^4.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("packages/scene/src/CanvasScene.tsx"),
                r#"
                import { useEffect } from 'react';
                const schema = z.object({ id: z.string() }).strict();
                export function CanvasScene() {
                    const { camera } = useSceneStore();
                    const derived = selectAtom(baseAtom, (s) => s.count);
                    useFrame(() => {
                        const v = new THREE.Vector3();
                    });
                    useEffect(() => {
                        autorun(() => console.log(camera, derived));
                    }, []);
                    return null;
                }
                "#
                .to_string(),
            ),
            // 4. React Compiler enabled package (disables jsx-no-new-object-as-prop)
            (
                PathBuf::from("packages/compiled/package.json"),
                r#"{
                    "name": "@acme/compiled",
                    "private": true,
                    "dependencies": { "react": "^19.0.0" }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("packages/compiled/next.config.mjs"),
                r#"export default { experimental: { reactCompiler: true } };"#.to_string(),
            ),
            (
                PathBuf::from("packages/compiled/src/CompiledView.tsx"),
                r#"
                export function CompiledView() {
                    return <MemoChild style={{ color: 'red' }} />;
                }
                "#
                .to_string(),
            ),
        ],
        None,
    );

    let rules_by_file: Vec<(String, RuleId)> = report
        .diagnostics
        .iter()
        .map(|d| (d.file.to_string_lossy().to_string(), d.rule))
        .collect();

    // Web package got Next.js and TanStack Query rules, NOT React Native `rn-no-raw-text`
    assert!(rules_by_file.contains(&(
        "apps/web/src/Page.tsx".to_string(),
        RuleId::NextjsNoImgElement
    )));
    assert!(rules_by_file.contains(&(
        "apps/web/src/Page.tsx".to_string(),
        RuleId::QueryNoVoidQueryFn
    )));
    assert!(
        !rules_by_file
            .iter()
            .any(|(f, r)| f == "apps/web/src/Page.tsx" && *r == RuleId::RnNoRawText)
    );

    // Mobile package got `rn-no-raw-text` and `expo-no-non-inlined-env`
    assert!(rules_by_file.contains(&(
        "apps/mobile/src/Screen.tsx".to_string(),
        RuleId::RnNoRawText
    )));
    assert!(rules_by_file.contains(&(
        "apps/mobile/src/Screen.tsx".to_string(),
        RuleId::ExpoNoNonInlinedEnv
    )));

    // Scene package got R3F, Zustand, Jotai, MobX, and Zod rules
    for expected_rule in [
        RuleId::R3fNoNewInUseFrame,
        RuleId::ZustandNoWholeStoreDestructure,
        RuleId::JotaiSelectAtomInRenderBody,
        RuleId::MobxReactionDisposerDiscarded,
        RuleId::ZodV4DeprecatedParse,
    ] {
        assert!(
            rules_by_file.contains(&(
                "packages/scene/src/CanvasScene.tsx".to_string(),
                expected_rule
            )),
            "Expected {expected_rule:?} in packages/scene/src/CanvasScene.tsx, got: {rules_by_file:#?}"
        );
    }

    // Compiled package skipped `jsx-no-new-object-as-prop` because React Compiler is active
    assert!(
        !rules_by_file
            .iter()
            .any(|(f, r)| f == "packages/compiled/src/CompiledView.tsx"
                && *r == RuleId::JsxNoNewObjectAsProp),
        "Expected React Compiler to disable JsxNoNewObjectAsProp, got: {rules_by_file:#?}"
    );
}

#[test]
fn config_loader_parses_ts_js_jsonc_and_package_json_with_overrides_and_component_knobs() {
    // 1. Parse TypeScript `dotore.config.ts` with `defineConfig`
    let ts_config_src = r#"
        import { defineConfig } from 'dotore';

        const sharedConfig = defineConfig({
            customRulesOnly: true,
            rules: {
                "effect/no-derived-state": "warn",
                "react/jsx-key": "error",
                "no-initialize-state": "off",
            },
            categories: {
                "Performance": "error",
            },
            ignore: {
                files: ["src/generated/**", "*.gen.tsx"],
                rules: ["no-fetch-in-effect"],
                tags: ["design"],
                overrides: [
                    {
                        files: ["src/legacy/**"],
                        rules: ["no-derived-state"],
                    },
                ],
            },
            textComponents: ["CustomText", "Typography"],
            rawTextWrapperComponents: ["HeroButton"],
            runtimeGlobals: ["GlobalModal", "LivePreview"],
        });

        export default sharedConfig;
    "#;

    let cfg =
        DotoreConfig::from_config_file_str(Path::new("dotore.config.ts"), ts_config_src).unwrap();
    assert!(cfg.custom_rules_only);
    assert_eq!(cfg.text_components, vec!["CustomText", "Typography"]);
    assert_eq!(cfg.raw_text_wrapper_components, vec!["HeroButton"]);
    assert_eq!(cfg.runtime_globals, vec!["GlobalModal", "LivePreview"]);

    // Rule-level `"warn"` via legacy alias `"effect/no-derived-state"` beats category `"Performance": "error"`
    assert_eq!(
        cfg.effective_severity(RuleId::NoDerivedState),
        Some(RuleSeverity::Warning)
    );
    // Rule-level `"off"` disables `no-initialize-state`
    assert_eq!(cfg.effective_severity(RuleId::NoInitializeState), None);
    // `customRulesOnly` disables originally-external `alt-text`, but keeps explicitly opted-in `react/jsx-key`
    assert_eq!(cfg.effective_severity(RuleId::AltText), None);
    assert_eq!(
        cfg.effective_severity(RuleId::JsxKey),
        Some(RuleSeverity::Error)
    );
    // `ignore.rules` disables `no-fetch-in-effect`
    assert_eq!(cfg.effective_severity(RuleId::NoFetchInEffect), None);
    // `ignore.tags` disables `design` rules
    assert!(cfg.is_tag_ignored(RuleTag::Design));

    // File globs and per-path overrides
    let root = Path::new("/repo");
    assert!(cfg.is_file_ignored(Path::new("/repo/src/generated/api.tsx"), root));
    assert!(cfg.is_file_ignored(Path::new("/repo/src/routes.gen.tsx"), root));
    assert!(!cfg.is_file_ignored(Path::new("/repo/src/App.tsx"), root));
    assert!(cfg.is_overridden_for_file(
        RuleId::NoDerivedState,
        Path::new("/repo/src/legacy/OldForm.tsx"),
        root
    ));
    assert!(!cfg.is_overridden_for_file(
        RuleId::NoDerivedState,
        Path::new("/repo/src/modern/NewForm.tsx"),
        root
    ));

    // 2. Verify `textComponents`, `rawTextWrapperComponents`, and `runtimeGlobals` in rule evaluation
    let rn_gate = CapabilityGate::with_capabilities([Capability::React, Capability::ReactNative]);
    let rn_code = r#"
        import { View } from 'react-native';
        export function Screen() {
            return (
                <View>
                    <CustomText>Allowed inside CustomText</CustomText>
                    <HeroButton>Allowed string-only wrapper</HeroButton>
                    <HeroButton>Disallowed mixed wrapper <View /></HeroButton>
                    <GlobalModal />
                    <UnimportedWidget />
                </View>
            );
        }
    "#;
    let mut rn_cfg = cfg.clone();
    rn_cfg.custom_rules_only = false;
    let rn_diags = analyze_source_with_config(
        Path::new("src/Screen.tsx"),
        rn_code,
        &rn_cfg,
        &rn_gate,
        None,
    );

    // Exactly 1 `rn-no-raw-text` (for `<HeroButton>Disallowed mixed wrapper <View /></HeroButton>`)
    // and 1 `jsx-no-undef` (for `<UnimportedWidget />`, while `<GlobalModal />` is suppressed by `runtimeGlobals`)
    let rn_raw_diags: Vec<_> = rn_diags
        .iter()
        .filter(|d| d.rule == RuleId::RnNoRawText)
        .collect();
    assert_eq!(rn_raw_diags.len(), 1, "Got rn_raw_diags: {rn_raw_diags:#?}");
    assert_eq!(rn_raw_diags[0].target_name, "HeroButton");

    let undef_diags: Vec<_> = rn_diags
        .iter()
        .filter(|d| d.rule == RuleId::JsxNoUndef)
        .collect();
    assert_eq!(undef_diags.len(), 1, "Got undef_diags: {undef_diags:#?}");
    assert_eq!(undef_diags[0].target_name, "UnimportedWidget");
}

#[test]
fn inline_suppressions_and_file_directives_honored_by_default_and_bypassed_by_flag() {
    let source = r#"
/* eslint-disable no-initialize-state */
import { useState, useEffect } from 'react';

export function SuppressedComponent({ firstName, lastName, items }) {
  const [fullName, setFullName] = useState('');
  const [ aliasName, setAliasName ] = useState('');
  const [oxName, setOxName] = useState('');
  const [initVal, setInitVal] = useState();

  // dotore-disable-next-line no-derived-state -- intentional local exception
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);

  // eslint-disable-next-line effect/no-derived-state
  useEffect(() => {
    setAliasName(firstName);
  }, [firstName]);

  // oxlint-disable-next-line dotore/no-derived-state
  useEffect(() => {
    setOxName(lastName);
  }, [lastName]);

  useEffect(() => {
    setInitVal('ready');
  }, []);

  return (
    <div>
      {items.map((item, idx) => (
        // dotore-disable-next-line react/no-array-index-key
        <span key={idx}>{item}</span>
      ))}
    </div>
  );
}
"#;

    // 1. Honored by default
    let default_diags = analyze_source(Path::new("src/SuppressedComponent.tsx"), source, None);
    assert!(
        default_diags.is_empty(),
        "Expected all diagnostics to be suppressed by inline/file directives, got: {default_diags:#?}"
    );

    // 2. Bypassed when `respect_inline_disables: false`
    let audit_cfg = DotoreConfig {
        respect_inline_disables: false,
        ..Default::default()
    };
    let audit_diags = analyze_source_with_config(
        Path::new("src/SuppressedComponent.tsx"),
        source,
        &audit_cfg,
        &CapabilityGate::default_react(),
        None,
    );
    assert_eq!(
        audit_diags.len(),
        5,
        "Expected all 5 suppressed diagnostics to fire when inline disables are bypassed, got: {audit_diags:#?}"
    );

    // 3. Verify CLI `--no-inline-disables` flag and config precedence on disk
    let dir = unique_temp_dir("inline-disables-cli");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{
            "name": "cli-test",
            "dependencies": { "react": "^19.0.0" },
            "dotore": {
                "rules": { "no-derived-state": "warn" }
            }
        }"#,
    )
    .unwrap();
    fs::write(dir.join("src/Comp.tsx"), source).unwrap();

    // Default workspace scan honors inline disables -> 0 diagnostics
    let (default_report, _) = scan_workspace(&ScanOptions {
        paths: vec![dir.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    assert_eq!(default_report.summary.total_diagnostics, 0);

    // Workspace scan with `no_inline_disables: true` surfaces all 5 diagnostics
    let (audit_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            include_tests: false,
            rules: None,
            tiers: None,
        },
        &CliOverrides {
            no_inline_disables: true,
            ..CliOverrides::default()
        },
    )
    .unwrap();
    assert_eq!(audit_report.summary.total_diagnostics, 5);
    assert!(
        audit_report
            .diagnostics
            .iter()
            .filter(|d| d.rule == RuleId::NoDerivedState)
            .all(|d| d.severity == RuleSeverity::Warning)
    );

    // Also verify CLI binary `--no-inline-disables`
    let bin = env!("CARGO_BIN_EXE_dotore");
    let cli_out = Command::new(bin)
        .args(["check", "--no-inline-disables", "--json"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(cli_out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&cli_out.stdout);
    assert!(stdout.contains("\"total_diagnostics\": 5"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_noise_suppressed_in_tests_and_stories_while_migration_hint_runs_and_libraries_skip_app_only()
 {
    let code = r#"
        import { useState, useEffect } from 'react';
        const userSchema = z.object({ name: z.string() }).strict();

        export function Widget({ items, x }) {
            const [derived, setDerived] = useState(0);
            useEffect(() => {
                setDerived(x + 1);
            }, [x]);

            return (
                <div>
                    {items.map((item, idx) => <span key={idx}>{item}</span>)}
                </div>
            );
        }
    "#;

    let gate = CapabilityGate::with_capabilities([Capability::React, Capability::Zod]);
    let cfg = DotoreConfig::default();

    // In production file: `no-derived-state`, `no-array-index-as-key`, and `zod-v4-deprecated-parse` all fire
    let prod_diags =
        analyze_source_with_config(Path::new("src/Widget.tsx"), code, &cfg, &gate, None);
    let prod_rules: Vec<RuleId> = prod_diags.iter().map(|d| d.rule).collect();
    assert!(prod_rules.contains(&RuleId::NoDerivedState));
    assert!(prod_rules.contains(&RuleId::NoArrayIndexAsKey));
    assert!(prod_rules.contains(&RuleId::ZodV4DeprecatedParse));

    // In `.test.tsx` and `.stories.tsx` files: `test-noise` rules (`no-derived-state`, `no-array-index-as-key`)
    // are suppressed, while `zod-v4-deprecated-parse` (tagged both `test-noise` and `migration-hint`) still runs!
    for non_prod_path in [
        "src/Widget.test.tsx",
        "src/Widget.stories.tsx",
        "src/__tests__/Widget.tsx",
    ] {
        let diags = analyze_source_with_config(Path::new(non_prod_path), code, &cfg, &gate, None);
        let rules: Vec<RuleId> = diags.iter().map(|d| d.rule).collect();
        assert_eq!(
            rules,
            vec![RuleId::ZodV4DeprecatedParse],
            "Unexpected rules in {non_prod_path}: {rules:?}"
        );
    }

    // Library package role skips application-only rules (`no-render-prop-children`) on library entrypoints
    let lib_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("packages/ui-lib/package.json"),
                r#"{
                    "name": "@acme/ui-lib",
                    "exports": { ".": "./src/index.tsx" },
                    "peerDependencies": { "react": "^19.0.0" }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("packages/ui-lib/src/index.tsx"),
                r#"
                export function DataProvider() {
                    return <Listbox>{(item) => <div>{item}</div>}</Listbox>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("apps/dashboard/package.json"),
                r#"{
                    "name": "@acme/dashboard",
                    "private": true,
                    "dependencies": { "react": "^19.0.0" }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/dashboard/src/index.tsx"),
                r#"
                export function DashboardApp() {
                    return <Listbox>{(item) => <div>{item}</div>}</Listbox>;
                }
                "#
                .to_string(),
            ),
        ],
        None,
    );

    // Library entrypoint `packages/ui-lib/src/index.tsx` skipped `no-render-prop-children`,
    // while application `apps/dashboard/src/index.tsx` reported it!
    assert_eq!(lib_report.diagnostics.len(), 1);
    assert_eq!(
        lib_report.diagnostics[0].file,
        PathBuf::from("apps/dashboard/src/index.tsx")
    );
    assert_eq!(lib_report.diagnostics[0].rule, RuleId::NoRenderPropChildren);
}

#[test]
fn single_pass_oxc_extracts_all_ir_facets_and_provides_direct_semantic_access() {
    let source = r#"
"use server";
import { useState, useEffect } from 'react';
import type { UserRecord } from './types';

/**
 * Formats a user's display badge.
 */
export function formatBadge(user: UserRecord): string {
    return user.name;
}

/** Account status values. */
export enum AccountStatus {
    Active,
    Suspended,
}

/** Props for UserPanel. */
export interface UserPanelProps {
    userId: string;
    items: string[];
}

export type PanelTheme = 'light' | 'dark';

export const DEFAULT_THEME: PanelTheme = 'light';

export class AuditLogger {
    prefix: string = 'audit';
    logEvent(msg: string) {
        return msg;
    }
}

export async function updateAccountAction(items: string[]) {
    for (const item of items) {
        await saveItem(item);
    }
}

export function UserPanel({ userId, items }: UserPanelProps) {
    const [profile, setProfile] = useState({ name: 'Ada' });
    useEffect(() => {
        setProfile({ name: userId });
    }, [userId]);

    profile.name = 'Mutated';
    const dynamicEnv = process.env[userId];

    return (
        <section>
            <ChildCard userId={userId} />
            <div dangerouslySetInnerHTML={{ __html: dynamicEnv }} />
        </section>
    );
}
"#;

    let (ir, symbol_count, scope_count) = inspect_file_semantic(
        Path::new("src/UserPanel.tsx"),
        source,
        |file_ir, semantic| {
            (
                file_ir.clone(),
                semantic.scoping().symbols_len(),
                semantic.scoping().scopes_len(),
            )
        },
    );

    // Direct semantic access was live during the single pass
    assert!(symbol_count > 5);
    assert!(scope_count > 2);

    // 1. Subjects, State Slots, Effect Nodes, Caller Sites
    assert_eq!(ir.subjects.len(), 1);
    assert_eq!(ir.subjects[0].name.as_deref(), Some("UserPanel"));
    assert_eq!(ir.subjects[0].state_slots.len(), 1);
    assert_eq!(ir.subjects[0].effect_nodes.len(), 1);
    assert_eq!(ir.caller_sites.len(), 1);
    assert_eq!(ir.caller_sites[0].component_name, "ChildCard");

    // 2. JSX elements
    assert_eq!(ir.jsx_elements.len(), 3);

    // 3. Module imports, exports, and directives
    assert!(ir.module.has_use_server);
    assert_eq!(ir.module.imports.len(), 2);
    assert!(!ir.module.imports[0].is_type_only);
    assert!(ir.module.imports[1].is_type_only);
    assert!(
        ir.module
            .exports
            .iter()
            .any(|e| e.name == "UserPanel" && e.is_component)
    );
    assert!(
        ir.module
            .exports
            .iter()
            .any(|e| e.name == "formatBadge" && !e.is_component)
    );

    // 4. Symbol Outlines with signatures and leading doc comments
    let format_outline = ir
        .symbol_outlines
        .iter()
        .find(|s| s.name == "formatBadge")
        .unwrap();
    assert_eq!(format_outline.kind, SymbolKind::Function);
    assert!(format_outline.exported);
    assert!(
        format_outline
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Formats a user's display badge"))
    );

    assert!(
        ir.symbol_outlines
            .iter()
            .any(|s| s.name == "AccountStatus" && s.kind == SymbolKind::Enum)
    );
    assert!(ir.symbol_outlines.iter().any(|s| s.name == "Active"
        && s.kind == SymbolKind::EnumMember
        && s.parent_name.as_deref() == Some("AccountStatus")));
    assert!(
        ir.symbol_outlines
            .iter()
            .any(|s| s.name == "UserPanelProps" && s.kind == SymbolKind::Interface)
    );
    assert!(
        ir.symbol_outlines
            .iter()
            .any(|s| s.name == "PanelTheme" && s.kind == SymbolKind::Type)
    );
    assert!(
        ir.symbol_outlines
            .iter()
            .any(|s| s.name == "DEFAULT_THEME" && s.kind == SymbolKind::Constant)
    );
    assert!(
        ir.symbol_outlines
            .iter()
            .any(|s| s.name == "AuditLogger" && s.kind == SymbolKind::Class)
    );
    assert!(ir.symbol_outlines.iter().any(|s| s.name == "logEvent"
        && s.kind == SymbolKind::Method
        && s.parent_name.as_deref() == Some("AuditLogger")));

    // 5. Mutations
    assert_eq!(ir.mutations.len(), 1);
    assert_eq!(ir.mutations[0].target_name, "profile");
    assert!(ir.mutations[0].is_state_slot);

    // 6. Async flows
    assert_eq!(ir.async_flows.len(), 1);
    assert!(ir.async_flows[0].inside_loop);

    // 7. Security sinks
    let sink_kinds: Vec<SecuritySinkKind> = ir.security_sinks.iter().map(|s| s.kind).collect();
    assert!(sink_kinds.contains(&SecuritySinkKind::DangerouslySetInnerHtml));
    assert!(sink_kinds.contains(&SecuritySinkKind::DynamicProcessEnv));
    assert!(sink_kinds.contains(&SecuritySinkKind::UnauthenticatedServerAction));

    // Also confirm `parse_file_ir` produces the exact same `FileIr`
    assert_eq!(parse_file_ir(Path::new("src/UserPanel.tsx"), source), ir);
    let _ = (
        discover_workspace_packages,
        load_config_from_dir,
        RuleSeverityOverride::Error,
    );
}
