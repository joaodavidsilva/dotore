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
    RulesListOptions, ScanOptions, SecuritySinkKind, SymbolKind, analyze_project_sources,
    analyze_source, analyze_source_with_config, build_rule_catalog, discover_workspace_packages,
    explain_rule, inspect_file_semantic, load_config_from_dir, parse_file_ir, rule_registry,
    scan_workspace, scan_workspace_with_overrides,
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

    // React Router, Remotion, Redux, and TanStack Form/Table/Virtual capabilities
    let extended_gate = CapabilityGate::from_package_json_str(
        r#"{
            "dependencies": {
                "react": "^19.0.0",
                "@react-router/node": "^7.2.0",
                "@remotion/player": "^4.0.0",
                "@reduxjs/toolkit": "^2.5.0",
                "@tanstack/react-form": "^1.0.0",
                "@tanstack/react-table": "^8.20.0",
                "@tanstack/react-virtual": "^3.10.0"
            }
        }"#,
    );
    for expected in [
        Capability::React,
        Capability::ReactRouter,
        Capability::Remotion,
        Capability::Redux,
        Capability::TanstackForm,
        Capability::TanstackTable,
        Capability::TanstackVirtual,
    ] {
        assert!(
            extended_gate.has(expected),
            "Expected CapabilityGate to contain {expected:?}"
        );
    }

    for (pkg_spec, expected_cap) in [
        (
            r#"{ "dependencies": { "react-router": "^7.0.0" } }"#,
            Capability::ReactRouter,
        ),
        (
            r#"{ "dependencies": { "react-router-dom": "^6.28.0" } }"#,
            Capability::ReactRouter,
        ),
        (
            r#"{ "dependencies": { "@react-router/dev": "^7.0.0" } }"#,
            Capability::ReactRouter,
        ),
        (
            r#"{ "dependencies": { "@react-router/serve": "^7.0.0" } }"#,
            Capability::ReactRouter,
        ),
        (
            r#"{ "dependencies": { "remotion": "^4.0.0" } }"#,
            Capability::Remotion,
        ),
        (
            r#"{ "dependencies": { "@remotion/cli": "^4.0.0" } }"#,
            Capability::Remotion,
        ),
        (
            r#"{ "dependencies": { "@remotion/renderer": "^4.0.0" } }"#,
            Capability::Remotion,
        ),
        (
            r#"{ "dependencies": { "react-redux": "^9.0.0" } }"#,
            Capability::Redux,
        ),
        (
            r#"{ "dependencies": { "redux": "^5.0.0" } }"#,
            Capability::Redux,
        ),
        (
            r#"{ "dependencies": { "@tanstack/react-form": "^1.0.0" } }"#,
            Capability::TanstackForm,
        ),
        (
            r#"{ "dependencies": { "@tanstack/react-table": "^8.0.0" } }"#,
            Capability::TanstackTable,
        ),
        (
            r#"{ "dependencies": { "@tanstack/react-virtual": "^3.0.0" } }"#,
            Capability::TanstackVirtual,
        ),
    ] {
        let gate = CapabilityGate::from_package_json_str(pkg_spec);
        assert!(
            gate.has(expected_cap),
            "Expected {pkg_spec} to infer {expected_cap:?}"
        );
    }
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

#[test]
fn canonical_alias_variants_resolve_and_control_active_detectors() {
    let alias_mappings = [
        ("no-derived-useState", RuleId::NoDerivedState),
        ("no-direct-state-mutation", RuleId::NoDirectMutationState),
        ("no-effect-chain", RuleId::NoChainStateUpdates),
        ("no-effect-event-handler", RuleId::NoEventHandler),
        ("no-event-trigger-state", RuleId::NoEventHandler),
        ("no-mirror-prop-effect", RuleId::NoAdjustStateOnPropChange),
        ("prefer-useReducer", RuleId::PreferUseReducer),
        (
            "query-no-usequery-for-mutation",
            RuleId::QueryNoUseQueryForMutation,
        ),
        ("rn-style-prefer-boxshadow", RuleId::RnStylePreferBoxShadow),
        ("react/jsx-handler-names", RuleId::NoGenericHandlerNames),
    ];

    for (alias, expected_rule) in alias_mappings {
        assert_eq!(
            RuleId::parse(alias),
            Some(expected_rule),
            "Expected alias {alias:?} to resolve to {expected_rule:?}"
        );
        assert_eq!(
            RuleId::parse(&format!("dotore/{alias}")),
            Some(expected_rule),
            "Expected qualified alias dotore/{alias} to resolve to {expected_rule:?}"
        );
        assert!(expected_rule.matches_key(alias));
        assert!(expected_rule.matches_key(&format!("dotore/{alias}")));
    }

    // 1. Enabling opt-in `prefer-use-reducer` via `"prefer-useReducer"` in config triggers detector
    let reducer_src = r#"
        import { useState } from 'react';
        export function CheckoutForm() {
            const [step, setStep] = useState(0);
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState<string | null>(null);
            const [submitted, setSubmitted] = useState(false);
            const [retryCount, setRetryCount] = useState(0);
            function handleSubmit() {
                setLoading(true);
                setError(null);
                setSubmitted(true);
                setStep(1);
                setRetryCount(c => c + 1);
            }
            return <button onClick={handleSubmit}>{step}{String(loading)}{error}{String(submitted)}{retryCount}</button>;
        }
    "#;
    let mut cfg = DotoreConfig::default();
    cfg.rules
        .insert("prefer-useReducer".to_string(), RuleSeverityOverride::Error);
    let diags = analyze_source_with_config(
        Path::new("src/CheckoutForm.tsx"),
        reducer_src,
        &cfg,
        &CapabilityGate::default_react(),
        None,
    );
    assert!(
        diags
            .iter()
            .any(|d| d.rule == RuleId::PreferUseReducer && d.severity == RuleSeverity::Error),
        "Expected prefer-use-reducer to fire at error severity when enabled via prefer-useReducer alias: {diags:#?}"
    );

    // 2. Inline suppression using alias strings suppresses the canonical detector
    let suppressed_src = r#"
        import { useState, useEffect } from 'react';
        export function SuppressedAliases({ firstName, lastName, rawItem }) {
            const [full, setFull] = useState('');
            const [stateObj, setStateObj] = useState({ count: 0 });

            // dotore-disable-next-line no-derived-useState
            useEffect(() => {
                setFull(firstName + ' ' + lastName);
            }, [firstName, lastName]);

            // eslint-disable-next-line no-direct-state-mutation
            stateObj.count = 42;

            return <div>{full}{stateObj.count}{rawItem}</div>;
        }
    "#;
    let suppressed_diags =
        analyze_source(Path::new("src/SuppressedAliases.tsx"), suppressed_src, None);
    assert!(
        suppressed_diags.is_empty(),
        "Expected inline suppressions using alias names to suppress canonical rules, got: {suppressed_diags:#?}"
    );
}

#[test]
fn all_906_reference_catalog_rules_resolve_with_complete_metadata() {
    let reference_catalog_ids: &[&str] = &[
        "active-static-asset",
        "activity-wraps-effect-heavy-subtree",
        "advanced-event-handler-refs",
        "agent-tool-capability-risk",
        "alt-text",
        "anchor-ambiguous-text",
        "anchor-has-content",
        "anchor-is-valid",
        "anchor-target-exists",
        "aria-activedescendant-has-tabindex",
        "aria-braille-equivalent",
        "aria-props",
        "aria-proptypes",
        "aria-role",
        "aria-unsupported-elements",
        "artifact-baas-authority-surface",
        "artifact-env-leak",
        "artifact-secret-leak",
        "async-await-in-loop",
        "async-defer-await",
        "async-parallel",
        "auth-token-in-web-storage",
        "autocomplete-valid",
        "base-ui-dialog-popup-requires-title",
        "base-ui-field-requires-label",
        "base-ui-tabs-tab-requires-list",
        "build-pipeline-secret-boundary",
        "button-has-type",
        "checked-requires-onchange-or-readonly",
        "circular-dependency",
        "class-component-missing-component-will-unmount-teardown",
        "click-events-have-key-events",
        "clickjacking-redirect-risk",
        "client-localstorage-no-version",
        "client-passive-event-listeners",
        "command-execution-input-risk",
        "context-provider-value-from-unmemoized-local-literal",
        "control-has-associated-label",
        "cors-cookie-trust-risk",
        "dangerous-html-sink",
        "data-table-requires-accessible-name",
        "debounce-no-cleanup",
        "design-no-em-dash-in-jsx-text",
        "design-no-redundant-padding-axes",
        "design-no-redundant-size-axes",
        "design-no-space-on-flex-children",
        "design-no-three-period-ellipsis",
        "design-no-vague-button-label",
        "details-requires-summary",
        "dialog-has-accessible-name",
        "display-name",
        "duplicate-jsx-subtree",
        "effect-listener-cleanup-mismatch",
        "effect-listener-cleanup-reference-mismatch",
        "effect-needs-cleanup",
        "effect-observer-needs-disconnect",
        "effect-raf-loop-needs-cancel",
        "effect-remove-listener-inline-handler",
        "empty-table-header",
        "exhaustive-deps",
        "expo-no-non-inlined-env",
        "fieldset-requires-legend",
        "firebase-client-owned-authz-field",
        "firebase-permissive-rules",
        "firebase-query-filter-as-auth",
        "forbid-component-props",
        "forbid-dom-props",
        "forbid-elements",
        "form-control-requires-name",
        "forward-ref-uses-ref",
        "git-provider-url-injection-risk",
        "heading-has-content",
        "hook-import-rename-loses-use-prefix",
        "hook-use-state",
        "hooks-no-nan-in-deps",
        "html-has-lang",
        "html-label-has-single-control",
        "html-no-invalid-paragraph-child",
        "html-no-invalid-table-nesting",
        "html-no-nested-form",
        "html-no-nested-interactive",
        "html-xml-lang-mismatch",
        "iframe-has-title",
        "iframe-missing-sandbox",
        "iframe-title-unique",
        "img-redundant-alt",
        "import-metadata-execution-risk",
        "ink-ctrl-c-handler-requires-exit-option",
        "ink-newline-inside-text",
        "ink-no-bare-process-exit",
        "ink-no-direct-raw-mode",
        "ink-no-dom-host-elements",
        "ink-no-dom-router",
        "ink-no-focus-in-render",
        "ink-no-layout-inside-text",
        "ink-no-live-hooks-in-render-to-string",
        "ink-no-measure-element-in-render",
        "ink-no-multiple-static",
        "ink-no-raw-text",
        "ink-no-repeated-render",
        "ink-prefer-use-animation",
        "ink-prefer-use-paste",
        "ink-static-is-append-only",
        "ink-static-requires-key",
        "ink-suspense-requires-concurrent",
        "ink-use-reactive-window-size",
        "ink-use-string-width-for-cursor",
        "ink-use-suspend-terminal",
        "ink-valid-aria-semantics",
        "insecure-crypto-risk",
        "insecure-session-cookie",
        "interactive-supports-focus",
        "jotai-derived-atom-returns-fresh-object",
        "jotai-select-atom-in-render-body",
        "jotai-tq-use-raw-query-atom",
        "js-async-reduce-without-awaited-acc",
        "js-batch-dom-css",
        "js-cache-property-access",
        "js-cache-storage",
        "js-combine-iterations",
        "js-early-exit",
        "js-flatmap-filter",
        "js-hoist-intl",
        "js-hoist-regexp",
        "js-index-maps",
        "js-length-check-first",
        "js-min-max-loop",
        "js-set-map-lookups",
        "js-tosorted-immutable",
        "jsx-boolean-value",
        "jsx-curly-brace-presence",
        "jsx-filename-extension",
        "jsx-fragments",
        "jsx-handler-names",
        "jsx-key",
        "jsx-max-depth",
        "jsx-no-comment-textnodes",
        "jsx-no-constructed-context-values",
        "jsx-no-duplicate-props",
        "jsx-no-jsx-as-prop",
        "jsx-no-new-array-as-prop",
        "jsx-no-new-function-as-prop",
        "jsx-no-new-object-as-prop",
        "jsx-no-script-url",
        "jsx-no-target-blank",
        "jsx-no-undef",
        "jsx-no-useless-fragment",
        "jsx-numeric-and-leaked-render",
        "jsx-pascal-case",
        "jsx-props-no-spread-multi",
        "jsx-props-no-spreading",
        "jwt-insecure-verification",
        "key-lifecycle-risk",
        "label-has-associated-control",
        "lang",
        "loading-action-preserves-trigger",
        "local-rpc-native-bridge-risk",
        "mcp-tool-capability-risk",
        "mdx-ssr-execution-risk",
        "media-has-caption",
        "mobx-no-make-auto-observable-in-inheritance",
        "mobx-no-observer-wrapped-memo",
        "mobx-reaction-disposer-discarded",
        "motion-animate-presence-must-outlive-child",
        "motion-animate-presence-requires-key",
        "motion-animate-presence-wait-single-child",
        "motion-create-in-render",
        "motion-drag-axis-constraint-mismatch",
        "motion-imperative-animation-in-render",
        "motion-keyframe-times-mismatch",
        "motion-layout-on-inline-element",
        "motion-unstable-layout-id-in-iteration",
        "motion-use-transform-range-length",
        "motion-value-constructor-in-render",
        "motion-value-subscription-in-render",
        "mouse-events-have-key-events",
        "nextjs-async-client-component",
        "nextjs-async-dynamic-api-not-awaited",
        "nextjs-error-boundary-missing-use-client",
        "nextjs-global-error-missing-html-body",
        "nextjs-image-missing-sizes",
        "nextjs-inline-script-missing-id",
        "nextjs-metadata-url-consistency",
        "nextjs-missing-metadata",
        "nextjs-no-a-element",
        "nextjs-no-client-fetch-for-server-data",
        "nextjs-no-client-side-redirect",
        "nextjs-no-css-link",
        "nextjs-no-default-export-in-route-handler",
        "nextjs-no-edge-og-runtime",
        "nextjs-no-font-link",
        "nextjs-no-google-analytics-script",
        "nextjs-no-head-import",
        "nextjs-no-img-element",
        "nextjs-no-native-script",
        "nextjs-no-polyfill-script",
        "nextjs-no-redirect-in-try-catch",
        "nextjs-no-script-in-head",
        "nextjs-no-side-effect-in-get-handler",
        "nextjs-no-use-search-params-without-suspense",
        "nextjs-no-vercel-og-import",
        "no-access-key",
        "no-adjust-state-on-prop-change",
        "no-all-caps-body-text",
        "no-arbitrary-px-font-size",
        "no-aria-hidden-on-body",
        "no-aria-hidden-on-focusable",
        "no-aria-invalid-without-description",
        "no-arithmetic-on-optional-chained-operand",
        "no-array-find-result-member-access-without-guard",
        "no-array-index-as-key",
        "no-array-index-deref-without-bounds-or-empty-guard",
        "no-array-index-key",
        "no-assertive-status",
        "no-async-effect-callback",
        "no-async-event-handler-without-reentry-guard",
        "no-auto-scrolling-content",
        "no-autofocus",
        "no-autoplay-without-muted",
        "no-barrel-import",
        "no-blocked-paste",
        "no-boolean-toggle-without-functional-update",
        "no-broken-image-source",
        "no-call-component-as-function",
        "no-cascading-set-state",
        "no-chain-state-updates",
        "no-children-prop",
        "no-clipped-overlay",
        "no-clone-element",
        "no-collapse-request-error-to-empty-state",
        "no-collapsed-literal-or-chain-as-value",
        "no-common-root-font",
        "no-conflicting-spring-options",
        "no-controlled-input-value-without-state-update",
        "no-controlled-selection-focus-effect",
        "no-cramped-container-padding",
        "no-create-context-in-render",
        "no-create-object-url-in-render",
        "no-create-object-url-without-revoke",
        "no-create-ref-in-function-component",
        "no-create-store-in-render",
        "no-crushed-letter-spacing",
        "no-danger",
        "no-danger-with-children",
        "no-dark-mode-glow",
        "no-decorative-blur-orb",
        "no-decorative-grid-background",
        "no-decorative-pulse",
        "no-decorative-radial-spotlight",
        "no-default-props",
        "no-default-purple-page-gradient",
        "no-default-warm-page-surface",
        "no-deprecated-keyboard-event-keycode-which",
        "no-deprecated-tailwind-class",
        "no-derived-state",
        "no-derived-state-effect",
        "no-derived-useState",
        "no-did-mount-set-state",
        "no-did-update-set-state",
        "no-direct-mutation-state",
        "no-direct-state-mutation",
        "no-disabled-zoom",
        "no-distracting-elements",
        "no-document-start-view-transition",
        "no-document-write",
        "no-duplicate-static-id-reference",
        "no-dynamic-import-path",
        "no-dynamic-tailwind-class-fragment",
        "no-eager-new-in-use-state-initializer",
        "no-ease-in-motion",
        "no-effect-chain",
        "no-effect-event-handler",
        "no-effect-event-in-deps",
        "no-effect-with-fresh-deps",
        "no-effect-wrapper-discards-callback-cleanup-return",
        "no-emoji-heading-decoration",
        "no-empty-card-shell",
        "no-enter-submit-without-ime-composition-guard",
        "no-eval",
        "no-event-handler",
        "no-event-trigger-state",
        "no-excessive-card-surfaces",
        "no-excessive-centered-copy",
        "no-excessive-font-families",
        "no-excessive-motion-stagger",
        "no-excessive-pill-treatment",
        "no-fake-browser-chrome",
        "no-fetch-in-effect",
        "no-fetch-response-used-without-status-check",
        "no-fill-map-element-as-key",
        "no-find-dom-node",
        "no-fixed-inside-transformed-ancestor",
        "no-flat-page-type-scale",
        "no-floating-then-in-jsx-handler",
        "no-flush-sync",
        "no-focus-in-animation-completion-handler",
        "no-focusable-content-in-aria-hidden",
        "no-focusable-content-in-role-text",
        "no-full-lodash-import",
        "no-full-viewport-centered-hero",
        "no-full-viewport-width",
        "no-generic-handler-names",
        "no-generic-marketing-copy",
        "no-generic-purple-blue-icon-gradient",
        "no-giant-component",
        "no-global-css-variable-animation",
        "no-gradient-text",
        "no-gray-on-colored-background",
        "no-hairline-border-wide-shadow",
        "no-hero-eyebrow-chip",
        "no-high-complexity-react-function",
        "no-hover-only-reveal",
        "no-hydration-branch-on-browser-global",
        "no-icon-tile-heading-stack",
        "no-image-hover-transform",
        "no-img-lazy-with-high-fetchpriority",
        "no-img-without-dimensions",
        "no-impure-call-at-module-scope",
        "no-impure-state-updater",
        "no-indeterminate-attribute",
        "no-inert-pointer-affordance",
        "no-inert-sticky-position",
        "no-initialize-state",
        "no-inline-bounce-easing",
        "no-inline-exhaustive-style",
        "no-inline-hoc-on-component",
        "no-inline-prop-on-memo-component",
        "no-interactive-element-to-noninteractive-role",
        "no-invalid-progress-range",
        "no-invisible-focus-control",
        "no-is-mounted",
        "no-italic-serif-display-heading",
        "no-json-parse-stringify-clone",
        "no-jsx-element-type",
        "no-justified-text",
        "no-large-animated-blur",
        "no-layout-property-animation",
        "no-layout-shifting-interaction-state",
        "no-layout-transition-inline",
        "no-legacy-class-lifecycles",
        "no-legacy-context-api",
        "no-loading-flag-reset-outside-finally",
        "no-locale-format-in-render",
        "no-long-transition-duration",
        "no-low-contrast-inline-style",
        "no-manufactured-contrast-copy",
        "no-many-boolean-props",
        "no-match-media-in-state-initializer",
        "no-mirror-prop-effect",
        "no-mixed-animation-owners",
        "no-mixed-icon-libraries",
        "no-mixed-srcset-descriptors",
        "no-moment",
        "no-monotonous-page-spacing",
        "no-multi-comp",
        "no-multi-component-file",
        "no-multiple-main-landmarks",
        "no-multiple-unlabeled-navigation-landmarks",
        "no-mutable-in-deps",
        "no-mutate-queried-dom-node-in-component",
        "no-mutate-then-set-or-return-same-reference",
        "no-mutating-array-method-on-prop-or-hook-result",
        "no-mutating-reducer-state",
        "no-namespace",
        "no-nested-card-surface",
        "no-nested-component-definition",
        "no-non-literal-selector-query-without-try-catch",
        "no-non-null-assertion-on-maybe-undefined-result",
        "no-nondeterministic-id-value-in-render-body",
        "no-noninteractive-element-interactions",
        "no-noninteractive-element-to-interactive-role",
        "no-noninteractive-tabindex",
        "no-nonresizable-textarea",
        "no-nullish-coalescing-arithmetic-precedence",
        "no-numbered-section-markers",
        "no-object-keys-values-entries-on-maybe-undefined",
        "no-object-or-array-coerced-to-string-in-template-literal",
        "no-outline-none",
        "no-overloaded-hover-state",
        "no-oversized-long-heading",
        "no-overwide-text-measure",
        "no-pass-data-to-parent",
        "no-pass-live-state-to-parent",
        "no-passive-request-owner-ref",
        "no-path-prefix-containment",
        "no-permanent-will-change",
        "no-pill-navigation-count",
        "no-placeholder-only-field",
        "no-placeholder-persona-copy",
        "no-pointer-disabled-enabled-control",
        "no-polymorphic-children",
        "no-predicate-function-reference-in-boolean-position",
        "no-presentation-role-conflict",
        "no-prevent-default",
        "no-promise-then-side-effect-in-effect-without-catch",
        "no-prop-callback-in-effect",
        "no-prop-callback-in-render",
        "no-prop-types",
        "no-pulsing-status-dot",
        "no-pure-black-background",
        "no-pure-black-shadow",
        "no-radial-halo",
        "no-random-key",
        "no-react-children",
        "no-react-dom-deprecated-apis",
        "no-react19-deprecated-apis",
        "no-reduced-motion-content-removal",
        "no-redundant-display-class",
        "no-redundant-roles",
        "no-redundant-should-component-update",
        "no-redundant-title-tooltip",
        "no-ref-callback-cleanup-before-react-19",
        "no-ref-current-in-render",
        "no-render-in-render",
        "no-render-prop-children",
        "no-render-return-value",
        "no-repeated-container-text",
        "no-repeated-emoji-tiles",
        "no-repeated-glass-surfaces",
        "no-repeated-hover-scale",
        "no-repeated-kicker-labels",
        "no-repeated-placeholder-navigation",
        "no-repeated-section-shells",
        "no-repeating-gradient-decoration",
        "no-reset-all-state-on-prop-change",
        "no-responsive-hidden-accessible-name",
        "no-scale-from-zero",
        "no-secrets-in-client-code",
        "no-self-updating-effect",
        "no-server-side-image-map",
        "no-set-state",
        "no-set-state-after-await-in-effect",
        "no-set-state-in-render",
        "no-shape-assembled-illustration",
        "no-side-effect-in-state-updater-function",
        "no-side-tab-border",
        "no-skipped-heading-level",
        "no-small-form-control-text",
        "no-smooth-scroll-without-reduced-motion",
        "no-spread-accumulator-in-reduce",
        "no-spread-props-over-defaults-clobbers-with-undefined",
        "no-srcset-without-sizes",
        "no-stale-timer-ref",
        "no-static-element-interactions",
        "no-static-motion-config-never",
        "no-string-false-on-boolean-attribute",
        "no-string-refs",
        "no-svg-currentcolor-with-fill-class",
        "no-symmetric-text-button-padding",
        "no-sync-xhr",
        "no-tailwind-layout-transition",
        "no-this-in-sfc",
        "no-tight-all-caps-heading",
        "no-tight-body-leading",
        "no-tight-display-tracking",
        "no-tiny-text",
        "no-tiny-uppercase-tracked-label",
        "no-transition-all",
        "no-transitioned-composite-widget-state",
        "no-transitioned-focus-ring",
        "no-unbounded-animation-frame-loop",
        "no-uncontrolled-input",
        "no-undeferred-third-party",
        "no-undersized-icon-button",
        "no-unescaped-dynamic-string-in-regexp",
        "no-unescaped-entities",
        "no-ungated-tailwind-animation",
        "no-unguarded-browser-global-at-module-scope",
        "no-unguarded-browser-global-in-render-or-hook-init",
        "no-unguarded-numeric-input-parse",
        "no-unguarded-throwing-parse-call",
        "no-uniform-feature-card-grid",
        "no-uninformative-aria-label",
        "no-unknown-property",
        "no-unowned-async-error-clear",
        "no-unsafe",
        "no-unsafe-json-parse",
        "no-unstable-nested-components",
        "no-unthrottled-scroll-mutation",
        "no-uppercase-mono-label",
        "no-uppercase-tracked-navigation-label",
        "no-usememo-simple-expression",
        "no-whole-object-default-losing-per-key-defaults",
        "no-whole-object-dep-with-member-reads",
        "no-wide-letter-spacing",
        "no-will-update-set-state",
        "no-z-index-9999",
        "nosql-injection-risk",
        "only-export-components",
        "package-metadata-secret",
        "path-traversal-risk",
        "plugin-update-trust-risk",
        "pointer-capture-needs-cancel-handler",
        "postmessage-origin-risk",
        "preact-no-children-length",
        "preact-no-react-hooks-import",
        "preact-no-render-arguments",
        "preact-prefer-ondblclick",
        "preact-prefer-oninput",
        "prefer-dvh-over-vh",
        "prefer-dynamic-import",
        "prefer-es6-class",
        "prefer-explicit-variants",
        "prefer-function-component",
        "prefer-html-dialog",
        "prefer-module-scope-pure-function",
        "prefer-module-scope-static-value",
        "prefer-motion-transform-property",
        "prefer-stable-empty-fallback",
        "prefer-tabular-numeric-data",
        "prefer-tag-over-role",
        "prefer-truncate-shorthand",
        "prefer-use-effect-event",
        "prefer-use-sync-external-store",
        "prefer-useReducer",
        "public-debug-artifact",
        "public-env-secret-name",
        "query-destructure-result",
        "query-floating-mutate-async",
        "query-mutation-missing-invalidation",
        "query-no-mutation-in-effect-as-read",
        "query-no-query-in-effect",
        "query-no-rest-destructuring",
        "query-no-usequery-for-mutation",
        "query-no-void-query-fn",
        "query-stable-query-client",
        "r3f-cap-device-pixel-ratio",
        "r3f-limit-shadowed-point-lights",
        "r3f-no-advancing-clock-in-use-frame",
        "r3f-no-allocation-in-pointer-move",
        "r3f-no-async-use-frame",
        "r3f-no-clone-in-use-frame",
        "r3f-no-compile-in-use-frame",
        "r3f-no-deep-use-three-selector",
        "r3f-no-dispose-loader-cache",
        "r3f-no-duplicate-primitive-object",
        "r3f-no-extend-in-render",
        "r3f-no-extend-three-namespace",
        "r3f-no-fresh-portal-container",
        "r3f-no-fresh-use-three-selector",
        "r3f-no-ignored-basic-material-properties",
        "r3f-no-ignored-linewidth",
        "r3f-no-imperative-attach-of-managed-ref",
        "r3f-no-inline-primitive-object",
        "r3f-no-inline-resource-prop",
        "r3f-no-internal-imports",
        "r3f-no-manual-canvas-resize",
        "r3f-no-mutate-loader-cache",
        "r3f-no-mutate-uniform-prop-source-in-use-frame",
        "r3f-no-mutating-pointer-event-data",
        "r3f-no-new-in-use-frame",
        "r3f-no-normalized-float-buffer-attribute",
        "r3f-no-null-loader-input",
        "r3f-no-object-pointer-capture",
        "r3f-no-recursive-raf-with-use-frame",
        "r3f-no-shader-configuration-mutation-in-use-frame",
        "r3f-no-shadows-on-unsupported-light",
        "r3f-no-state-in-pointer-move",
        "r3f-no-state-in-use-frame",
        "r3f-no-sync-readback-in-use-frame",
        "r3f-no-unstable-args",
        "r3f-no-use-frame-dependency-array",
        "r3f-prefer-gpu-instanced-animation",
        "r3f-prefer-gpu-position-animation",
        "r3f-prefer-instanced-mesh",
        "r3f-prefer-use-loader",
        "r3f-require-animation-mixer-update",
        "r3f-require-data-texture-update",
        "r3f-require-dynamic-buffer-usage",
        "r3f-require-environment-for-metal",
        "r3f-require-frame-delta",
        "r3f-require-global-effect-cleanup",
        "r3f-require-instanced-buffer-update",
        "r3f-require-lighting-for-pbr",
        "r3f-require-lit-material-normals",
        "r3f-require-owned-texture-cleanup",
        "r3f-require-position-buffer-update",
        "r3f-require-projection-matrix-update",
        "r3f-require-render-target-reset",
        "r3f-require-render-with-positive-priority",
        "r3f-require-root-unmount",
        "r3f-require-shadows-enabled",
        "r3f-require-transparent-for-opacity",
        "r3f-require-uv-for-texture-map",
        "r3f-texture-repeat-requires-wrapping",
        "r3f-valid-buffer-attribute-array-length",
        "r3f-valid-buffer-attribute-item-size",
        "r3f-valid-fog-parameters",
        "r3f-valid-material-opacity",
        "r3f-valid-orthographic-camera",
        "r3f-valid-pbr-material-properties",
        "r3f-valid-perspective-camera",
        "r3f-valid-physical-material-properties",
        "r3f-valid-raycaster-range",
        "r3f-valid-shadow-map-size",
        "r3f-valid-spot-light-properties",
        "r3f-valid-texture-color-space",
        "r3f-webgpu-canvas-prop-compatibility",
        "r3f-webgpu-no-gl-state",
        "r3f-webgpu-no-high-precision-instancing",
        "r3f-webgpu-no-js-uniform-branch",
        "r3f-webgpu-no-legacy-effect-composer",
        "r3f-webgpu-no-legacy-material-api",
        "r3f-webgpu-no-unregistered-pipeline-pass",
        "r3f-webgpu-require-async-init",
        "radio-input-missing-name",
        "radix-dialog-content-requires-title",
        "radix-tabs-trigger-requires-list",
        "raw-sql-injection-risk",
        "react-aria-dialog-requires-heading",
        "react-compiler-no-manual-memoization",
        "react-in-jsx-scope",
        "react-markdown-unsanitized-raw-html",
        "react-router-csp-nonce-consistency",
        "react-router-descendant-routes-require-splat",
        "react-router-guard-aborted-handle-error",
        "react-router-internal-route-anchor",
        "react-router-loader-fetch-forwards-signal",
        "react-router-loader-parallel-fetch",
        "react-router-nested-route-requires-outlet",
        "react-router-no-catch-middleware-next",
        "react-router-no-client-module-in-server-render",
        "react-router-no-duplicate-route-id",
        "react-router-no-empty-leaf-route",
        "react-router-no-invalid-absolute-child-path",
        "react-router-no-invalid-lazy-route-properties",
        "react-router-no-invalid-splat-path",
        "react-router-no-loader-request-body",
        "react-router-no-middleware-response-body-consumption",
        "react-router-no-multiple-blockers",
        "react-router-no-multiple-middleware-next",
        "react-router-no-multiple-set-search-params-in-tick",
        "react-router-no-navigate-in-render",
        "react-router-no-nested-router",
        "react-router-no-redirect-in-try-catch",
        "react-router-no-route-module-environment-suffix",
        "react-router-no-router-in-render",
        "react-router-no-session-mutation-in-loader",
        "react-router-no-static-cookie-expires",
        "react-router-no-unsynchronized-search-params-mutation",
        "react-router-no-use-loader-data-in-error-ui",
        "react-router-prefer-route-lazy",
        "react-router-require-root-error-boundary",
        "react-router-resource-link-requires-reload",
        "react-router-return-navigation-promise-in-transition",
        "react-router-server-middleware-return-response",
        "react-router-session-mutation-requires-commit",
        "react-router-v8-no-meta-data-field",
        "react-router-v8-no-react-router-dom-import",
        "react-router-v8-no-removed-future-flags",
        "react-router-valid-route-object",
        "redux-useselector-inline-derivation",
        "redux-useselector-returns-new-collection",
        "remotion-calculate-metadata-fetch-signal",
        "remotion-deterministic-randomness",
        "remotion-no-css-animation",
        "remotion-no-css-transition",
        "remotion-no-css-url-assets",
        "remotion-no-module-scope-delay-render",
        "remotion-no-native-media-elements",
        "remotion-no-next-image",
        "remotion-stable-delay-render-handle",
        "rendering-animate-svg-wrapper",
        "rendering-conditional-render",
        "rendering-hoist-jsx",
        "rendering-hydration-mismatch-time",
        "rendering-hydration-no-flicker",
        "rendering-script-defer-async",
        "rendering-svg-precision",
        "rendering-usetransition-loading",
        "repository-secret-file",
        "request-body-mass-assignment",
        "require-autoplay-video-poster",
        "require-render-return",
        "require-scale-reveal-transform-origin",
        "rerender-defer-reads-hook",
        "rerender-dependencies",
        "rerender-derived-state-from-hook",
        "rerender-functional-setstate",
        "rerender-lazy-ref-init",
        "rerender-lazy-state-init",
        "rerender-memo-before-early-return",
        "rerender-memo-with-default-value",
        "rerender-state-only-in-handlers",
        "rerender-transitions-scroll",
        "rn-animate-layout-property",
        "rn-animation-reaction-as-derived",
        "rn-bottom-sheet-no-ignored-scroll-prop",
        "rn-bottom-sheet-no-state-in-on-animate",
        "rn-bottom-sheet-prefer-native",
        "rn-bottom-sheet-use-integrated-scrollable",
        "rn-detox-missing-await",
        "rn-list-callback-per-row",
        "rn-list-data-mapped",
        "rn-list-missing-estimated-item-size",
        "rn-list-recyclable-without-types",
        "rn-no-deep-imports",
        "rn-no-deprecated-modules",
        "rn-no-dimensions-get",
        "rn-no-falsy-and-render",
        "rn-no-image-children",
        "rn-no-inline-flatlist-renderitem",
        "rn-no-inline-object-in-list-item",
        "rn-no-legacy-expo-packages",
        "rn-no-legacy-shadow-styles",
        "rn-no-non-native-navigator",
        "rn-no-panresponder",
        "rn-no-raw-text",
        "rn-no-renderitem-key",
        "rn-no-scroll-state",
        "rn-no-scrollview-mapped-list",
        "rn-no-set-native-props",
        "rn-no-single-element-style-array",
        "rn-platform-shaking-use-direct-import",
        "rn-prefer-content-inset-adjustment",
        "rn-prefer-expo-image",
        "rn-prefer-pressable",
        "rn-prefer-pressable-over-gesture-detector",
        "rn-prefer-reanimated",
        "rn-pressable-shared-value-mutation",
        "rn-reanimated-4-no-legacy-spring-thresholds",
        "rn-reanimated-4-no-removed-api",
        "rn-reanimated-4-use-worklets-scheduler",
        "rn-scrollview-dynamic-padding",
        "rn-scrollview-flex-in-content-container",
        "rn-style-prefer-boxshadow",
        "role-button-requires-complete-keyboard-activation",
        "role-has-required-aria-props",
        "role-supports-aria-props",
        "rules-of-hooks",
        "scope",
        "secret-in-fallback",
        "self-closing-comp",
        "server-after-nonblocking",
        "server-auth-actions",
        "server-cache-with-object-literal",
        "server-dedup-props",
        "server-fetch-without-revalidate",
        "server-hoist-static-io",
        "server-no-mutable-module-state",
        "server-sequential-independent-await",
        "shadcn-command-item-state-variant-requires-value",
        "shadcn-dialog-content-requires-title",
        "shadcn-form-item-requires-label",
        "shadcn-icon-button-requires-label",
        "shadcn-input-group-no-raw-controls",
        "shadcn-tabs-trigger-requires-list",
        "state-in-constructor",
        "style-prop-object",
        "styled-components-duplicate-css-property-in-block",
        "styled-components-non-transient-custom-prop-on-intrinsic-element",
        "supabase-client-owned-authz-field",
        "supabase-rls-policy-risk",
        "supabase-table-missing-rls",
        "svg-filter-clickjacking-risk",
        "tabindex-no-positive",
        "tanstack-form-on-submit-requires-prevent-default",
        "tanstack-start-get-mutation",
        "tanstack-start-loader-parallel-fetch",
        "tanstack-start-missing-head-content",
        "tanstack-start-missing-scripts",
        "tanstack-start-no-anchor-element",
        "tanstack-start-no-direct-fetch-in-loader",
        "tanstack-start-no-dynamic-server-fn-import",
        "tanstack-start-no-navigate-in-render",
        "tanstack-start-no-secrets-in-loader",
        "tanstack-start-no-use-server-in-handler",
        "tanstack-start-no-useeffect-fetch",
        "tanstack-start-redirect-in-try-catch",
        "tanstack-start-route-property-order",
        "tanstack-start-server-fn-method-order",
        "tanstack-start-server-fn-validate-input",
        "tanstack-table-no-unstable-data-or-columns",
        "tanstack-virtual-measure-element-requires-data-index",
        "tenant-static-proxy-risk",
        "three-cap-device-pixel-ratio",
        "three-effect-composer-output-pass-last",
        "three-effect-composer-require-size-on-resize",
        "three-gpu-computation-handle-init-error",
        "three-gpu-computation-require-init-before-compute",
        "three-gpu-computation-valid-variable-name",
        "three-limit-shadowed-point-lights",
        "three-no-allocation-in-pointer-move",
        "three-no-async-animation-loop",
        "three-no-clone-in-animation-loop",
        "three-no-compile-in-animation-loop",
        "three-no-ignored-basic-material-properties",
        "three-no-ignored-linewidth",
        "three-no-material-recompile-in-animation-loop",
        "three-no-new-in-animation-loop",
        "three-no-normalized-float-buffer-attribute",
        "three-no-object-construction-in-render",
        "three-no-redundant-uniforms-need-update",
        "three-no-shader-configuration-mutation-in-animation-loop",
        "three-no-shadows-on-unsupported-light",
        "three-no-state-in-animation-loop",
        "three-no-state-in-pointer-move",
        "three-no-sync-readback-in-animation-loop",
        "three-no-unconditional-renderer-resize-in-animation-loop",
        "three-on-before-compile-require-program-cache-key",
        "three-prefer-gpu-instanced-animation",
        "three-prefer-gpu-position-animation",
        "three-prefer-instanced-mesh",
        "three-prefer-set-animation-loop",
        "three-raw-shader-require-fragment-float-precision",
        "three-raw-shader-require-glsl3-version",
        "three-require-animation-mixer-cleanup",
        "three-require-animation-mixer-update",
        "three-require-camera-aspect-on-resize",
        "three-require-controls-cleanup",
        "three-require-controls-update",
        "three-require-data-texture-update",
        "three-require-dynamic-buffer-usage",
        "three-require-environment-for-metal",
        "three-require-frame-delta",
        "three-require-gpu-computation-cleanup",
        "three-require-instanced-buffer-update",
        "three-require-ktx2-detect-support",
        "three-require-lighting-for-pbr",
        "three-require-lit-material-normals",
        "three-require-loader-error-handling",
        "three-require-owned-geometry-cleanup",
        "three-require-owned-material-cleanup",
        "three-require-owned-texture-cleanup",
        "three-require-position-buffer-update",
        "three-require-postprocessing-cleanup",
        "three-require-projection-matrix-update",
        "three-require-render-in-animation-loop",
        "three-require-render-target-cleanup",
        "three-require-render-target-reset",
        "three-require-renderer-cleanup",
        "three-require-renderer-dom-attachment",
        "three-require-renderer-size",
        "three-require-shadows-enabled",
        "three-require-texture-update-after-wrapping-change",
        "three-require-transparent-for-opacity",
        "three-require-uv-for-texture-map",
        "three-require-worker-loader-cleanup",
        "three-shader-no-constant-out-of-bounds-index",
        "three-shader-no-derivatives-in-nonuniform-flow",
        "three-shader-no-glsl1-syntax-with-glsl3",
        "three-shader-no-invalid-clamp-bounds",
        "three-shader-no-invalid-constant-bit-operations",
        "three-shader-no-invalid-constant-math",
        "three-shader-no-invalid-smoothstep-edges",
        "three-shader-no-inverse-of-uniform",
        "three-shader-no-redeclared-builtins",
        "three-shader-no-redundant-frag-depth",
        "three-shader-no-reserved-identifiers",
        "three-shader-no-version-directive",
        "three-shader-prefer-small-integer-pow",
        "three-shader-prefer-squared-distance-comparison",
        "three-shader-require-compatible-uniform-values",
        "three-shader-require-fragment-output-on-all-paths",
        "three-shader-require-matching-uniforms",
        "three-shader-require-matching-varyings",
        "three-shader-require-position-on-all-paths",
        "three-shader-require-uniform-bindings",
        "three-shader-valid-global-initializers",
        "three-shader-valid-uniform-definitions",
        "three-texture-repeat-requires-wrapping",
        "three-tsl-no-js-uniform-branch",
        "three-valid-buffer-attribute-array-length",
        "three-valid-buffer-attribute-item-size",
        "three-valid-data-texture-data-length",
        "three-valid-data-texture-dimensions",
        "three-valid-fog-parameters",
        "three-valid-gpu-computation-dimensions",
        "three-valid-material-opacity",
        "three-valid-orthographic-camera",
        "three-valid-pbr-material-properties",
        "three-valid-perspective-camera",
        "three-valid-physical-material-properties",
        "three-valid-raycaster-range",
        "three-valid-shadow-map-size",
        "three-valid-spot-light-properties",
        "three-valid-texture-color-space",
        "three-webgpu-no-high-precision-instancing",
        "three-webgpu-no-legacy-effect-composer",
        "three-webgpu-no-legacy-material-api",
        "three-webgpu-require-init-before-sync-operation",
        "unsafe-json-in-html",
        "untrusted-redirect-following",
        "unused-dependency",
        "unused-dev-dependency",
        "unused-export",
        "unused-file",
        "unused-type",
        "url-prefilled-privileged-action",
        "use-lazy-motion",
        "valtio-no-proxy-read-in-render",
        "valtio-no-snapshot-in-callback",
        "void-dom-elements-no-children",
        "waapi-animation-in-render",
        "web-animation-offsets-valid",
        "webgl-no-sync-readback-in-animation-loop",
        "webhook-signature-risk",
        "window-open-without-noopener",
        "zod-v4-no-deprecated-error-apis",
        "zod-v4-no-deprecated-error-customization",
        "zod-v4-no-deprecated-schema-apis",
        "zod-v4-prefer-top-level-string-formats",
        "zustand-no-fresh-selector-result",
        "zustand-no-get-during-initialization",
        "zustand-no-mutating-state",
        "zustand-no-whole-store-destructure",
    ];
    assert_eq!(reference_catalog_ids.len(), 906);

    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert!(
        catalog.len() >= 906,
        "Expected at least 906 rules in catalog, got {}",
        catalog.len()
    );

    for &rule_key in reference_catalog_ids {
        let parsed = RuleId::parse(rule_key).unwrap_or_else(|| {
            panic!("Reference catalog rule {rule_key:?} failed to resolve via RuleId::parse")
        });
        let meta = parsed.metadata();
        assert!(!meta.canonical_id.is_empty());
        assert_eq!(meta.qualified_key, format!("dotore/{}", meta.canonical_id));
        assert!(!meta.title.is_empty());
        assert!(!meta.docs_url.is_empty());
        assert!(
            !meta.recipe_markdown.is_empty(),
            "Rule {rule_key} missing recipe_markdown"
        );
        let explained = explain_rule(rule_key, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({rule_key:?}) returned None"));
        assert_eq!(explained.id, meta.canonical_id);
    }
}

#[test]
fn workspace_discovery_infers_nested_capabilities_for_react_router_remotion_redux_and_tanstack() {
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "name": "workspace-root", "private": true, "workspaces": ["apps/*"] }"#
                    .to_string(),
            ),
            (
                PathBuf::from("apps/router-app/package.json"),
                r#"{
                    "name": "router-app",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "@react-router/dev": "^7.2.0",
                        "react-redux": "^9.1.0",
                        "@tanstack/react-form": "^1.0.0",
                        "@tanstack/react-table": "^8.20.0",
                        "@tanstack/react-virtual": "^3.10.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/router-app/src/App.tsx"),
                "export function App() { return <div>Router App</div>; }".to_string(),
            ),
            (
                PathBuf::from("apps/video-studio/package.json"),
                r#"{
                    "name": "video-studio",
                    "private": true,
                    "dependencies": {
                        "react": "^19.0.0",
                        "remotion": "^4.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/video-studio/src/Video.tsx"),
                "export function Video() { return <div>Video</div>; }".to_string(),
            ),
        ],
        None,
    );

    let router_proj = report
        .projects
        .iter()
        .find(|p| p.name == "router-app")
        .expect("router-app project in report");
    for cap in [
        Capability::React,
        Capability::ReactRouter,
        Capability::Redux,
        Capability::TanstackForm,
        Capability::TanstackTable,
        Capability::TanstackVirtual,
    ] {
        assert!(
            router_proj.capabilities.contains(&cap),
            "Expected router-app to have {cap:?}, got: {:?}",
            router_proj.capabilities
        );
    }
    assert!(!router_proj.capabilities.contains(&Capability::Remotion));

    let video_proj = report
        .projects
        .iter()
        .find(|p| p.name == "video-studio")
        .expect("video-studio project in report");
    assert!(video_proj.capabilities.contains(&Capability::React));
    assert!(video_proj.capabilities.contains(&Capability::Remotion));
    assert!(!video_proj.capabilities.contains(&Capability::ReactRouter));

    // Also verify on-disk discover_workspace_packages
    let dir = unique_temp_dir("nested-new-caps");
    fs::create_dir_all(dir.join("apps/router")).unwrap();
    fs::create_dir_all(dir.join("apps/remotion")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "root", "private": true }"#,
    )
    .unwrap();
    fs::write(
        dir.join("apps/router/package.json"),
        r#"{ "name": "router", "dependencies": { "@react-router/serve": "^7.0.0", "@reduxjs/toolkit": "^2.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.join("apps/remotion/package.json"),
        r#"{ "name": "remotion-pkg", "dependencies": { "@remotion/cli": "^4.0.0", "@tanstack/react-table": "^8.0.0" } }"#,
    )
    .unwrap();

    let pkgs = discover_workspace_packages(&dir);
    let router_pkg = pkgs.iter().find(|p| p.name == "router").unwrap();
    assert!(router_pkg.capability_gate.has(Capability::ReactRouter));
    assert!(router_pkg.capability_gate.has(Capability::Redux));
    assert!(
        router_pkg
            .capability_gate
            .allows_rule(RuleId::ReactRouterNoNavigateInRender.metadata())
    );
    assert!(
        router_pkg
            .capability_gate
            .allows_rule(RuleId::ReduxUseselectorReturnsNewCollection.metadata())
    );
    assert!(
        !router_pkg
            .capability_gate
            .allows_rule(RuleId::RemotionDeterministicRandomness.metadata())
    );

    let remotion_pkg = pkgs.iter().find(|p| p.name == "remotion").unwrap();
    assert!(remotion_pkg.capability_gate.has(Capability::Remotion));
    assert!(remotion_pkg.capability_gate.has(Capability::TanstackTable));
    assert!(
        remotion_pkg
            .capability_gate
            .allows_rule(RuleId::RemotionDeterministicRandomness.metadata())
    );
    assert!(
        remotion_pkg
            .capability_gate
            .allows_rule(RuleId::TanstackTableNoUnstableDataOrColumns.metadata())
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn capability_gate_infers_ngrx_angular_material_and_rust_ecosystem_crates() {
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("apps/ng-portal/package.json"),
                r#"{
                    "name": "ng-portal",
                    "dependencies": {
                        "@angular/core": "^19.0.0",
                        "@angular/material": "^19.0.0",
                        "@ngrx/store": "^19.0.0",
                        "@ngrx/effects": "^19.0.0"
                    }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("apps/ng-portal/src/app.component.ts"),
                "export class AppComponent {}".to_string(),
            ),
            (
                PathBuf::from("services/api-rs/Cargo.toml"),
                r#"[package]
name = "api-rs"
version = "0.1.0"
edition = "2024"

[dependencies]
reqwest = "0.12"
diesel = "2.2"
sea-orm = "1.1"
rusqlite = "0.32"
tokio-postgres = "0.7"
futures = "0.3"
tower-http = "0.6"
actix-cors = "0.7"
cookie = "0.18"
jsonwebtoken = "9.3"
"#
                .to_string(),
            ),
            (
                PathBuf::from("services/api-rs/src/lib.rs"),
                "pub fn health() -> &'static str { \"ok\" }\n".to_string(),
            ),
        ],
        None,
    );

    let ng_proj = report
        .projects
        .iter()
        .find(|p| p.name == "ng-portal")
        .expect("ng-portal project in report");
    for cap in [
        Capability::Angular,
        Capability::NgRx,
        Capability::AngularMaterial,
        Capability::TypeScript,
    ] {
        assert!(
            ng_proj.capabilities.contains(&cap),
            "Expected ng-portal to have {cap:?}, got: {:?}",
            ng_proj.capabilities
        );
    }

    let rs_proj = report
        .projects
        .iter()
        .find(|p| p.name == "api-rs")
        .expect("api-rs project in report");
    for cap in [
        Capability::Rust,
        Capability::Reqwest,
        Capability::Diesel,
        Capability::SeaOrm,
        Capability::Rusqlite,
        Capability::Postgres,
        Capability::Futures,
        Capability::TowerHttp,
        Capability::ActixCors,
        Capability::Cookie,
        Capability::Jsonwebtoken,
    ] {
        assert!(
            rs_proj.capabilities.contains(&cap),
            "Expected api-rs to have {cap:?}, got: {:?}",
            rs_proj.capabilities
        );
    }
}

#[test]
fn polyglot_and_security_rule_registry_and_legacy_aliases_resolve_via_parse_and_explain() {
    let cfg = DotoreConfig::default();
    let catalog = build_rule_catalog(&cfg, &RulesListOptions::default());

    let expected_mappings: &[(RuleId, &str, &[&str])] = &[
        // #52 Angular AST rules (30)
        (
            RuleId::AngularNoUncalledSignals,
            "angular-no-uncalled-signals",
            &["@angular-eslint/no-uncalled-signals", "angular/no-uncalled-signals"],
        ),
        (
            RuleId::AngularPreferSignalModel,
            "angular-prefer-signal-model",
            &["@angular-eslint/prefer-signal-model", "angular/prefer-signal-model"],
        ),
        (
            RuleId::AngularPreferSignals,
            "angular-prefer-signals",
            &["@angular-eslint/prefer-signals", "angular/prefer-signals"],
        ),
        (
            RuleId::AngularNoConflictingLifecycle,
            "angular-no-conflicting-lifecycle",
            &["@angular-eslint/no-conflicting-lifecycle", "angular/no-conflicting-lifecycle"],
        ),
        (
            RuleId::AngularContextualLifecycle,
            "angular-contextual-lifecycle",
            &["@angular-eslint/contextual-lifecycle", "angular/contextual-lifecycle"],
        ),
        (
            RuleId::AngularContextualDecorator,
            "angular-contextual-decorator",
            &["@angular-eslint/contextual-decorator", "angular/contextual-decorator"],
        ),
        (
            RuleId::AngularNoAsyncLifecycleMethod,
            "angular-no-async-lifecycle-method",
            &["@angular-eslint/no-async-lifecycle-method", "angular/no-async-lifecycle-method"],
        ),
        (
            RuleId::AngularNoLifecycleCall,
            "angular-no-lifecycle-call",
            &["@angular-eslint/no-lifecycle-call", "angular/no-lifecycle-call"],
        ),
        (
            RuleId::AngularRequireLifecycleOnPrototype,
            "angular-require-lifecycle-on-prototype",
            &[
                "@angular-eslint/require-lifecycle-on-prototype",
                "angular/require-lifecycle-on-prototype",
            ],
        ),
        (
            RuleId::AngularNoEmptyLifecycleMethod,
            "angular-no-empty-lifecycle-method",
            &["@angular-eslint/no-empty-lifecycle-method", "angular/no-empty-lifecycle-method"],
        ),
        (
            RuleId::AngularUseLifecycleInterface,
            "angular-use-lifecycle-interface",
            &["@angular-eslint/use-lifecycle-interface", "angular/use-lifecycle-interface"],
        ),
        (
            RuleId::AngularUsePipeTransformInterface,
            "angular-use-pipe-transform-interface",
            &[
                "@angular-eslint/use-pipe-transform-interface",
                "angular/use-pipe-transform-interface",
            ],
        ),
        (
            RuleId::AngularNoPipeImpure,
            "angular-no-pipe-impure",
            &["@angular-eslint/no-pipe-impure", "angular/no-pipe-impure"],
        ),
        (
            RuleId::AngularNoOutputNative,
            "angular-no-output-native",
            &["@angular-eslint/no-output-native", "angular/no-output-native"],
        ),
        (
            RuleId::AngularNoOutputOnPrefix,
            "angular-no-output-on-prefix",
            &["@angular-eslint/no-output-on-prefix", "angular/no-output-on-prefix"],
        ),
        (
            RuleId::AngularRelativeUrlPrefix,
            "angular-relative-url-prefix",
            &["@angular-eslint/relative-url-prefix", "angular/relative-url-prefix"],
        ),
        (
            RuleId::AngularPreferStandalone,
            "angular-prefer-standalone",
            &["@angular-eslint/prefer-standalone", "angular/prefer-standalone"],
        ),
        (
            RuleId::AngularPreferInject,
            "angular-prefer-inject",
            &["@angular-eslint/prefer-inject", "angular/prefer-inject"],
        ),
        (
            RuleId::AngularUseInjectableProvidedIn,
            "angular-use-injectable-provided-in",
            &[
                "@angular-eslint/use-injectable-provided-in",
                "angular/use-injectable-provided-in",
            ],
        ),
        (
            RuleId::AngularPreferHostMetadataProperty,
            "angular-prefer-host-metadata-property",
            &[
                "@angular-eslint/prefer-host-metadata-property",
                "angular/prefer-host-metadata-property",
            ],
        ),
        (
            RuleId::AngularNoDuplicatesInMetadataArrays,
            "angular-no-duplicates-in-metadata-arrays",
            &[
                "@angular-eslint/no-duplicates-in-metadata-arrays",
                "angular/no-duplicates-in-metadata-arrays",
            ],
        ),
        (
            RuleId::AngularNoForwardRef,
            "angular-no-forward-ref",
            &["@angular-eslint/no-forward-ref", "angular/no-forward-ref"],
        ),
        (
            RuleId::AngularNoInputsMetadataProperty,
            "angular-no-inputs-metadata-property",
            &[
                "@angular-eslint/no-inputs-metadata-property",
                "angular/no-inputs-metadata-property",
            ],
        ),
        (
            RuleId::AngularNoOutputsMetadataProperty,
            "angular-no-outputs-metadata-property",
            &[
                "@angular-eslint/no-outputs-metadata-property",
                "angular/no-outputs-metadata-property",
            ],
        ),
        (
            RuleId::AngularNoQueriesMetadataProperty,
            "angular-no-queries-metadata-property",
            &[
                "@angular-eslint/no-queries-metadata-property",
                "angular/no-queries-metadata-property",
            ],
        ),
        (
            RuleId::AngularPreferOutputReadonly,
            "angular-prefer-output-readonly",
            &["@angular-eslint/prefer-output-readonly", "angular/prefer-output-readonly"],
        ),
        (
            RuleId::AngularPreferOutputEmitterRef,
            "angular-prefer-output-emitter-ref",
            &[
                "@angular-eslint/prefer-output-emitter-ref",
                "angular/prefer-output-emitter-ref",
            ],
        ),
        (
            RuleId::AngularUseComponentViewEncapsulation,
            "angular-use-component-view-encapsulation",
            &[
                "@angular-eslint/use-component-view-encapsulation",
                "angular/use-component-view-encapsulation",
            ],
        ),
        (
            RuleId::AngularNoAttributeDecorator,
            "angular-no-attribute-decorator",
            &["@angular-eslint/no-attribute-decorator", "angular/no-attribute-decorator"],
        ),
        (
            RuleId::AngularComponentMaxInlineDeclarations,
            "angular-component-max-inline-declarations",
            &[
                "@angular-eslint/component-max-inline-declarations",
                "angular/component-max-inline-declarations",
            ],
        ),
        // #53 Angular Template rules (8) + NgRx/Material rules (7)
        (
            RuleId::AngularTemplateNoAny,
            "angular-template-no-any",
            &["@angular-eslint/template/no-any", "angular-template/no-any"],
        ),
        (
            RuleId::AngularTemplateAltText,
            "angular-template-alt-text",
            &["@angular-eslint/template/alt-text", "angular-template/alt-text"],
        ),
        (
            RuleId::AngularTemplateClickEventsHaveKeyEvents,
            "angular-template-click-events-have-key-events",
            &[
                "@angular-eslint/template/click-events-have-key-events",
                "angular-template/click-events-have-key-events",
            ],
        ),
        (
            RuleId::AngularTemplateMouseEventsHaveKeyEvents,
            "angular-template-mouse-events-have-key-events",
            &[
                "@angular-eslint/template/mouse-events-have-key-events",
                "angular-template/mouse-events-have-key-events",
            ],
        ),
        (
            RuleId::AngularTemplateElementsHaveContent,
            "angular-template-elements-have-content",
            &[
                "@angular-eslint/template/elements-have-content",
                "angular-template/elements-have-content",
            ],
        ),
        (
            RuleId::AngularTemplateInteractiveSupportsFocus,
            "angular-template-interactive-supports-focus",
            &[
                "@angular-eslint/template/interactive-supports-focus",
                "angular-template/interactive-supports-focus",
            ],
        ),
        (
            RuleId::AngularTemplateTableScope,
            "angular-template-table-scope",
            &["@angular-eslint/template/table-scope", "angular-template/table-scope"],
        ),
        (
            RuleId::AngularTemplateValidAria,
            "angular-template-valid-aria",
            &["@angular-eslint/template/valid-aria", "angular-template/valid-aria"],
        ),
        (
            RuleId::NgrxNoMultipleActionsInEffects,
            "ngrx-no-multiple-actions-in-effects",
            &["@ngrx/no-multiple-actions-in-effects"],
        ),
        (
            RuleId::NgrxNoEffectDecoratorAndCreator,
            "ngrx-no-effect-decorator-and-creator",
            &["@ngrx/no-effect-decorator-and-creator", "@ngrx/no-effect-decorator"],
        ),
        (
            RuleId::NgrxNoCyclicActionCreators,
            "ngrx-no-cyclic-action-creators",
            &["@ngrx/no-cyclic-action-creators"],
        ),
        (
            RuleId::NgrxNoTypedGlobalStore,
            "ngrx-no-typed-global-store",
            &["@ngrx/no-typed-global-store"],
        ),
        (
            RuleId::NgrxOnFunctionExplicitReturnType,
            "ngrx-on-function-explicit-return-type",
            &["@ngrx/on-function-explicit-return-type"],
        ),
        (
            RuleId::NgrxSelectStyle,
            "ngrx-select-style",
            &["@ngrx/select-style"],
        ),
        (
            RuleId::AngularMaterialNoConflictingMixins,
            "angular-material-no-conflicting-mixins",
            &["@angular/material/no-conflicting-mixins"],
        ),
        // #54 Python Zen & Wildcard rules (7)
        (
            RuleId::PyZenComplexFunction,
            "py-zen-complex-function",
            &["zen/complex-function", "radon/CC", "radon/CC18", "C901"],
        ),
        (
            RuleId::PyZenDeepNesting,
            "py-zen-deep-nesting",
            &["zen/deep-nesting"],
        ),
        (
            RuleId::PyZenLongFunction,
            "py-zen-long-function",
            &["zen/long-function", "PLR0915"],
        ),
        (
            RuleId::PyZenTooManyParams,
            "py-zen-too-many-params",
            &["zen/too-many-params", "PLR0913"],
        ),
        (
            RuleId::PyZenLargeClass,
            "py-zen-large-class",
            &["zen/large-class", "PLR0904"],
        ),
        (
            RuleId::PyZenNoDenseSemicolonStatements,
            "py-zen-no-dense-semicolon-statements",
            &["zen/dense-code", "E702"],
        ),
        (
            RuleId::PyNoWildcardImport,
            "py-no-wildcard-import",
            &["imports/star", "F403"],
        ),
        // #55 Python Bandit & Structure rules (7)
        (
            RuleId::PySecurityHttpRequestRequiresTimeout,
            "py-security-http-request-requires-timeout",
            &["bandit/B113", "B113", "S113"],
        ),
        (
            RuleId::PySecurityNoDisabledTlsVerify,
            "py-security-no-disabled-tls-verify",
            &["bandit/B501", "B501", "S501"],
        ),
        (
            RuleId::PySecurityNoWeakCryptoOrRandom,
            "py-security-no-weak-crypto-or-random",
            &["bandit/B303", "bandit/B311", "bandit/B324", "B303", "B311", "B324"],
        ),
        (
            RuleId::PySecurityNoXxeOrUnsafeArchive,
            "py-security-no-xxe-or-unsafe-archive",
            &["bandit/B202", "bandit/B314", "bandit/B320", "B202", "B314", "B320"],
        ),
        (
            RuleId::PySecurityNoHardcodedSecretOrTmp,
            "py-security-no-hardcoded-secret-or-tmp",
            &["bandit/B105", "bandit/B106", "bandit/B107", "bandit/B108", "B105", "B108"],
        ),
        (
            RuleId::PyStructureMissingPyTyped,
            "py-structure-missing-py-typed",
            &["structure/no-py-typed", "no-py-typed"],
        ),
        (
            RuleId::PyStructureLowTypeHintCoverage,
            "py-structure-low-type-hint-coverage",
            &["structure/type-hints", "type-hints"],
        ),
        // #56 Rust SourceKernel rules (9)
        (
            RuleId::RsTokioNoBlockInPlaceOnCurrentThread,
            "rs-tokio-no-block-in-place-on-current-thread",
            &[
                "rust_doctor::source::block_in_place_on_current_thread",
                "block_in_place_on_current_thread",
            ],
        ),
        (
            RuleId::RsAsyncNoBlockOnInAsync,
            "rs-async-no-block-on-in-async",
            &["rust_doctor::source::block_on_in_async", "block_on_in_async"],
        ),
        (
            RuleId::RsSecurityNoDisabledTlsVerification,
            "rs-security-no-disabled-tls-verification",
            &[
                "rust_doctor::source::disabled_tls_verification",
                "disabled_tls_verification",
            ],
        ),
        (
            RuleId::RsSecurityNoDynamicShellCommand,
            "rs-security-no-dynamic-shell-command",
            &["rust_doctor::source::dynamic_shell_command", "dynamic_shell_command"],
        ),
        (
            RuleId::RsHttpNoUncheckedResponseStatus,
            "rs-http-no-unchecked-response-status",
            &["rust_doctor::source::unchecked_http_status", "unchecked_http_status"],
        ),
        (
            RuleId::RsSecurityNoSecretEnvFallback,
            "rs-security-no-secret-env-fallback",
            &["rust_doctor::source::secret_env_fallback", "secret_env_fallback"],
        ),
        (
            RuleId::RsSecurityNoPermissiveCors,
            "rs-security-no-permissive-cors",
            &["rust_doctor::source::permissive_cors", "permissive_cors"],
        ),
        (
            RuleId::RsSecurityNoInsecureAuthCookie,
            "rs-security-no-insecure-auth-cookie",
            &["rust_doctor::source::insecure_auth_cookie", "insecure_auth_cookie"],
        ),
        (
            RuleId::RsSecurityNoDisabledJwtValidation,
            "rs-security-no-disabled-jwt-validation",
            &[
                "rust_doctor::source::disabled_jwt_validation",
                "disabled_jwt_validation",
            ],
        ),
        // #57 Rust Cargo, Structure & Clippy rules (26)
        (
            RuleId::RsCargoDuplicateMajorVersions,
            "rs-cargo-duplicate-major-versions",
            &[
                "rust_doctor::cargo::duplicate_major_versions",
                "duplicate_major_versions",
            ],
        ),
        (
            RuleId::RsCargoMissingLockfile,
            "rs-cargo-missing-lockfile",
            &["rust_doctor::cargo::missing_lockfile", "missing_lockfile"],
        ),
        (
            RuleId::RsCargoPathDepOutsideWorkspace,
            "rs-cargo-path-dep-outside-workspace",
            &[
                "rust_doctor::cargo::path_dependency_outside_workspace",
                "path_dependency_outside_workspace",
            ],
        ),
        (
            RuleId::RsCargoPermissiveLintTable,
            "rs-cargo-permissive-lint-table",
            &["rust_doctor::cargo::permissive_lint_table", "permissive_lint_table"],
        ),
        (
            RuleId::RsCargoPermissiveRustflags,
            "rs-cargo-permissive-rustflags",
            &["rust_doctor::cargo::permissive_rustflags", "permissive_rustflags"],
        ),
        (
            RuleId::RsCargoReleaseDebugSymbols,
            "rs-cargo-release-debug-symbols",
            &["rust_doctor::cargo::release_debug_symbols", "release_debug_symbols"],
        ),
        (
            RuleId::RsCargoUncheckedReleaseOverflow,
            "rs-cargo-unchecked-release-overflow",
            &[
                "rust_doctor::cargo::unchecked_release_overflow",
                "unchecked_release_overflow",
            ],
        ),
        (
            RuleId::RsCargoUnusedDependency,
            "rs-cargo-unused-dependency",
            &["rust_doctor::cargo::unused_dependency", "unused_dependency"],
        ),
        (
            RuleId::RsCargoTestOnlyDependency,
            "rs-cargo-test-only-dependency",
            &["rust_doctor::cargo::test_only_dependency", "test_only_dependency"],
        ),
        (
            RuleId::RsCargoUnboundedWildcardDependency,
            "rs-cargo-unbounded-wildcard-dependency",
            &[
                "rust_doctor::cargo::unbounded_registry_dependency",
                "unbounded_registry_dependency",
            ],
        ),
        (
            RuleId::RsCargoUnpinnedGitDependency,
            "rs-cargo-unpinned-git-dependency",
            &["rust_doctor::cargo::unpinned_git_dependency", "unpinned_git_dependency"],
        ),
        (
            RuleId::RsStructureCrateLevelAllow,
            "rs-structure-crate-level-allow",
            &["rust_doctor::structure::crate_level_allow", "crate_level_allow"],
        ),
        (
            RuleId::RsStructureUnreasonedAllow,
            "rs-structure-unreasoned-allow",
            &[
                "rust_doctor::structure::unreasoned_allow_attribute",
                "unreasoned_allow_attribute",
                "clippy::allow_attributes_without_reason",
            ],
        ),
        (
            RuleId::RsStructureStackedAllow,
            "rs-structure-stacked-allow",
            &[
                "rust_doctor::structure::stacked_allow_attribute",
                "stacked_allow_attribute",
            ],
        ),
        (
            RuleId::RsStructureComplexFunction,
            "rs-structure-complex-function",
            &[
                "rust_doctor::structure::complex_function",
                "complex_function",
                "clippy::cognitive_complexity",
            ],
        ),
        (
            RuleId::RsStructureOversizedUnit,
            "rs-structure-oversized-unit",
            &[
                "rust_doctor::structure::oversized_unit",
                "oversized_unit",
                "clippy::too_many_lines",
            ],
        ),
        (
            RuleId::RsStructureOrphanModuleFile,
            "rs-structure-orphan-module-file",
            &["rust_doctor::structure::orphan_module_file", "orphan_module_file"],
        ),
        (
            RuleId::RsStructureUnreferencedFeature,
            "rs-structure-unreferenced-feature",
            &[
                "rust_doctor::structure::unreferenced_feature",
                "unreferenced_feature",
            ],
        ),
        (
            RuleId::RsStructureNearDuplicateFunction,
            "rs-structure-near-duplicate-function",
            &[
                "rust_doctor::structure::near_duplicate_function_body",
                "rust_doctor::structure::duplicate_function_body",
            ],
        ),
        (
            RuleId::RsNoAwaitHoldingRefcell,
            "rs-no-await-holding-refcell",
            &["clippy::await_holding_refcell_ref", "await_holding_refcell_ref"],
        ),
        (
            RuleId::RsNoPanicOrTodoInProduction,
            "rs-no-panic-or-todo-in-production",
            &[
                "clippy::panic",
                "clippy::todo",
                "clippy::unimplemented",
                "clippy::exit",
                "clippy::panic_in_result_fn",
            ],
        ),
        (
            RuleId::RsNoDbgOrPrintInLibrary,
            "rs-no-dbg-or-print-in-library",
            &["clippy::dbg_macro", "clippy::print_stdout", "clippy::print_stderr"],
        ),
        (
            RuleId::RsSecurityNoWorldWritablePermissions,
            "rs-security-no-world-writable-permissions",
            &["clippy::permissions_set_readonly_false", "permissions_set_readonly_false"],
        ),
        (
            RuleId::RsNoZombieChildProcess,
            "rs-no-zombie-child-process",
            &["clippy::zombie_processes", "zombie_processes"],
        ),
        (
            RuleId::RsNoTransmuteWithoutTypeAnnotations,
            "rs-no-transmute-without-type-annotations",
            &[
                "clippy::missing_transmute_annotations",
                "clippy::crosspointer_transmute",
            ],
        ),
        (
            RuleId::RsRequireSafetyDocOnPubUnsafeFn,
            "rs-require-safety-doc-on-pub-unsafe-fn",
            &["clippy::missing_safety_doc", "missing_safety_doc"],
        ),
        // #58 Trust-Boundary Security rules (6)
        (
            RuleId::CiWorkflowSecurityRisk,
            "ci-workflow-security-risk",
            &["rust_doctor::repo::secret_in_build_step", "secret_in_build_step"],
        ),
        (
            RuleId::ElectronWebviewBridgeRisk,
            "electron-webview-bridge-risk",
            &[],
        ),
        (
            RuleId::UntrustedHostHeaderOrigin,
            "untrusted-host-header-origin",
            &[],
        ),
        (
            RuleId::PrivateResponsePublicCache,
            "private-response-public-cache",
            &[],
        ),
        (
            RuleId::LlmPromptRoleAndToolSinkRisk,
            "llm-prompt-role-and-tool-sink-risk",
            &[],
        ),
        (
            RuleId::SupabaseServiceRoleUnscopedQuery,
            "supabase-service-role-unscoped-query",
            &[],
        ),
    ];

    assert_eq!(expected_mappings.len(), 100);

    for &(rule_id, canonical_id, aliases) in expected_mappings {
        assert_eq!(rule_id.as_str(), canonical_id);
        assert_eq!(RuleId::parse(canonical_id), Some(rule_id));
        assert_eq!(
            RuleId::parse(&format!("dotore/{canonical_id}")),
            Some(rule_id)
        );
        assert!(
            catalog.iter().any(|entry| entry.id == canonical_id),
            "Expected `{canonical_id}` in `dotore rules list` catalog"
        );
        let explained_canonical = explain_rule(canonical_id, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({canonical_id}) returned None"));
        assert_eq!(explained_canonical.id, canonical_id);

        for &alias in aliases {
            assert_eq!(
                RuleId::parse(alias),
                Some(rule_id),
                "Expected alias `{alias}` to resolve to `{canonical_id}`"
            );
            let explained_alias = explain_rule(alias, &cfg)
                .unwrap_or_else(|| panic!("explain_rule({alias}) returned None"));
            assert_eq!(explained_alias.id, canonical_id);
        }
    }
}

#[test]
fn mask_credentials_redacts_live_secrets_across_frames_capsules_reports_and_handoffs() {
    use std::collections::HashMap;

    use dotore::{
        ByteSpan, Diagnostic, ExtractedFile, SourceLoc, WorkspacePackage,
        build_agent_handoff_prompt, build_report_from_planner_context, excerpt_from_span,
        format_terminal_report_pretty, mask_credentials, render_code_frame, render_html_report,
        render_rule_bundle_summary_text,
    };

    let aws_tail = "Q3VJ7RNYH2KXW4PZ";
    let aws_key = format!("AKIA{aws_tail}");
    let ghp_tail = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let ghp_token = format!("ghp_{ghp_tail}");
    let gh_pat_tail = "11AAbbCCddEEffGGhhIIjjKKllMMnnOOpp";
    let gh_pat = format!("github_pat_{gh_pat_tail}");
    let sk_tail = "proj_9876543210abcdefghijKLMNOP";
    let sk_key = format!("sk-{sk_tail}");
    let slack_tail = "1234567890-abcdefABCDEF";
    let slack_token = format!("xoxb-{slack_tail}");
    let pem_body = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7";
    let pem_block = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{pem_body}\n-----END RSA PRIVATE KEY-----"
    );
    let db_secret = "V3ryS3cr3tPr0dP4ss!";
    let db_url = format!("postgres://app_user:{db_secret}@db.prod.internal:5432/orders");

    // 1. Direct unit checks on `mask_credentials`
    let combined = format!(
        "aws={aws_key}\ngithub={ghp_token}\npat={gh_pat}\nopenai={sk_key}\nslack={slack_token}\ndb={db_url}\n{pem_block}"
    );
    let redacted = mask_credentials(&combined);
    for leaked_fragment in [
        aws_tail,
        ghp_tail,
        gh_pat_tail,
        sk_tail,
        slack_tail,
        pem_body,
        db_secret,
    ] {
        assert!(
            !redacted.contains(leaked_fragment),
            "Expected `{leaked_fragment}` to be redacted, got:\n{redacted}"
        );
    }
    assert!(redacted.contains("AKIA<redacted>"));
    assert!(redacted.contains("ghp_<redacted>"));
    assert!(redacted.contains("gith<redacted>"));
    assert!(redacted.contains("sk-p<redacted>"));
    assert!(redacted.contains("xoxb<redacted>"));
    assert!(redacted.contains("<redacted>@db.prod.internal:5432/orders"));

    // 2. Non-secret text and placeholder DB URLs must remain untouched
    let safe_source = concat!(
        "const model = 'sk-learn';\n",
        "const shortCode = 'AKIA123';\n",
        "const localUrl = 'postgres://user:password@localhost:5432/dev';\n",
        "const envUrl = 'postgresql://user:${DB_PASSWORD}@db.prod.internal:5432/prod';\n",
        "const tplUrl = 'redis://default:<password>@cache.prod.internal:6379';\n",
    );
    assert_eq!(mask_credentials(safe_source), safe_source);

    // 3. End-to-end redaction across code frames, FixCapsule excerpts, JSON/terminal/HTML reports, and handoff prompts
    let file_path = PathBuf::from("src/config.ts");
    let file_source = format!(
        "export function initClient() {{\n  const key = \"{aws_key}\";\n  const token = \"{ghp_token}\";\n  const db = \"{db_url}\";\n  return {{ key, token, db }};\n}}\n"
    );

    let frame = render_code_frame(&file_source, 2);
    assert!(!frame.contains(aws_tail), "render_code_frame leaked AWS key:\n{frame}");
    assert!(!frame.contains(ghp_tail), "render_code_frame leaked GitHub PAT:\n{frame}");
    assert!(!frame.contains(db_secret), "render_code_frame leaked DB password:\n{frame}");
    assert!(frame.contains("AKIA<redacted>"));

    let span = ByteSpan {
        start: 0,
        end: file_source.len() as u32,
    };
    let excerpt = excerpt_from_span(&file_path, &file_source, span);
    assert!(!excerpt.source.contains(aws_tail));
    assert!(!excerpt.source.contains(ghp_tail));
    assert!(!excerpt.source.contains(db_secret));

    let diag = Diagnostic::for_rule(
        RuleId::NoSecretsInClientCode,
        &file_path,
        SourceLoc { line: 2, column: 15 },
        span,
        format!("Hardcoded credential `{aws_key}` and `{sk_key}` exposed in client bundle."),
    )
    .with_subject(Some("initClient".to_string()));

    let extracted = vec![ExtractedFile::new(
        file_path.clone(),
        file_source.clone(),
        dotore::LanguageId::TypeScript,
    )];
    let mut sources = HashMap::new();
    sources.insert(file_path.clone(), file_source);
    let packages = vec![WorkspacePackage {
        name: "web".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    }];
    let report = build_report_from_planner_context(
        extracted.as_slice(),
        &[(file_path, 1)],
        0,
        vec![diag],
        &sources,
        &packages,
    );

    assert!(!report.diagnostics[0].message.contains(aws_tail));
    assert!(!report.diagnostics[0].message.contains(sk_tail));
    assert!(!report.root_cause_groups[0].message.contains(aws_tail));
    assert!(!report.fix_capsules[0].subject_excerpt.source.contains(aws_tail));
    assert!(!report.fix_capsules[0].subject_excerpt.source.contains(ghp_tail));
    assert!(!report.fix_capsules[0].subject_excerpt.source.contains(db_secret));

    let terminal_out = format_terminal_report_pretty(&report, false);
    assert!(!terminal_out.contains(aws_tail));
    assert!(!terminal_out.contains(sk_tail));

    let html_out = render_html_report(&report);
    assert!(!html_out.contains(aws_tail));
    assert!(!html_out.contains(ghp_tail));
    assert!(!html_out.contains(db_secret));

    let handoff_out = build_agent_handoff_prompt(&report, None);
    assert!(!handoff_out.contains(aws_tail));
    assert!(!handoff_out.contains(ghp_tail));
    assert!(!handoff_out.contains(db_secret));

    let bundle_summary = render_rule_bundle_summary_text(RuleId::NoSecretsInClientCode, &report);
    assert!(!bundle_summary.contains(aws_tail));
    assert!(!bundle_summary.contains(sk_tail));
}
