//! Integration tests for Ticket #06:
//! - `dotore rules list` (`--category`, `--tag`, `--framework`, `--configured`, `--json`)
//! - `dotore rules explain <rule>` (canonical ID, qualified key, legacy alias, text & `--json`)
//! - `dotore rules enable | disable | set | category | ignore-tag | unignore-tag` in-place config mutations
//! - `dotore why <file:line>` (active diagnostic + **Fix Capsule**, inline suppression, config & **Capability Gate** explanations)
//! - `dotore design [paths...]` (focused UI design audit)
//! - `dotore ci install | upgrade | config` and `dotore install [--yes] [--dry-run] [--agent-hooks]`

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    CiOptions, CiProviderKind, CliOverrides, ConfigMutation, ConfigTargetKind, DotoreConfig,
    InstallOptions, PrescriptionTier, RuleCategory, RuleId, RuleSeverityOverride, RuleTag,
    RulesListOptions, ScanOptions, build_rule_catalog, ci_config, ci_install, ci_upgrade,
    design_rule_ids, explain_location, explain_rule, format_design_report, format_install_report,
    format_rule_catalog_text, format_rule_explanation_text, format_why_report_text, install_dotore,
    load_config_from_dir, mutate_config_in_dir, parse_why_location, scan_design, scan_workspace,
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dotore-t06-{prefix}-{nanos}"))
}

fn dotore_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dotore"))
}

#[test]
fn rules_list_and_explain_support_filters_aliases_and_json() {
    let mut cfg = DotoreConfig::default();
    cfg.rules.insert(
        "dotore/no-derived-state".to_string(),
        RuleSeverityOverride::Warn,
    );
    cfg.categories
        .insert("Security".to_string(), RuleSeverityOverride::Error);
    cfg.ignore.tags.push("r3f".to_string());

    // 1. Unfiltered catalog lists all rules with effective severities and sources
    let all_entries = build_rule_catalog(&cfg, &RulesListOptions::default());
    assert!(all_entries.len() >= 25);

    let derived = all_entries
        .iter()
        .find(|e| e.id == "no-derived-state")
        .expect("no-derived-state in catalog");
    assert_eq!(derived.key, "dotore/no-derived-state");
    assert_eq!(derived.severity, "warn");
    assert_eq!(derived.source, "rules");
    assert_eq!(derived.tier, PrescriptionTier::Autofix);

    let danger = all_entries
        .iter()
        .find(|e| e.id == "no-danger")
        .expect("no-danger in catalog");
    assert_eq!(danger.severity, "error");
    assert_eq!(danger.source, "categories");

    let r3f_rule = all_entries
        .iter()
        .find(|e| e.id == "r3f-no-new-in-use-frame")
        .expect("r3f rule in catalog");
    assert_eq!(r3f_rule.severity, "off");
    assert_eq!(r3f_rule.source, "ignore.tags");

    // 2. Filter by category, tag, framework, and configured
    let perf_only = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            category: Some("performance".to_string()),
            ..Default::default()
        },
    );
    assert!(!perf_only.is_empty());
    assert!(perf_only.iter().all(|e| e.category == "Performance"));

    let design_only = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            tag: Some("design".to_string()),
            ..Default::default()
        },
    );
    assert!(!design_only.is_empty());
    assert!(
        design_only
            .iter()
            .all(|e| e.tags.iter().any(|t| t == "design"))
    );

    let nextjs_only = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            framework: Some("nextjs".to_string()),
            ..Default::default()
        },
    );
    assert!(!nextjs_only.is_empty());
    assert!(nextjs_only.iter().any(|e| e.id == "nextjs-no-img-element"));

    let configured_only = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            configured: true,
            ..Default::default()
        },
    );
    assert!(!configured_only.is_empty());
    assert!(
        configured_only
            .iter()
            .all(|e| e.source != "default" && e.source != "opt-in")
    );

    let text_catalog = format_rule_catalog_text(&configured_only);
    assert!(text_catalog.contains("dotore/no-derived-state"));
    assert!(text_catalog.contains("(rules)"));

    // 3. `explain_rule` resolves canonical ID, qualified key, and legacy alias
    for query in [
        "no-derived-state",
        "dotore/no-derived-state",
        "effect/no-derived-state",
    ] {
        let explained = explain_rule(query, &cfg).expect("rule should resolve");
        assert_eq!(explained.key, "dotore/no-derived-state");
        assert_eq!(explained.tier, PrescriptionTier::Autofix);
        assert!(!explained.rationale.is_empty());
        assert!(!explained.before_example.is_empty());
        assert!(!explained.after_example.is_empty());
        assert!(explained.config_snippet.contains("dotore/no-derived-state"));

        let rendered = format_rule_explanation_text(&explained);
        assert!(rendered.contains("dotore/no-derived-state"));
        assert!(rendered.contains("Prescription Tier"));
        assert!(rendered.contains("autofix"));
        assert!(rendered.contains("Before"));
        assert!(rendered.contains("After"));
        assert!(rendered.contains("dotore rules set dotore/no-derived-state"));
    }

    // 4. Verify CLI `dotore rules list --json` and `dotore rules explain`
    let dir = unique_temp_dir("rules-list-explain");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("dotore.config.json"),
        r#"{ "rules": { "dotore/no-derived-state": "warn" } }"#,
    )
    .unwrap();

    let list_out = Command::new(dotore_bin())
        .args(["rules", "list", "--configured", "--json", "--cwd"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let arr = list_json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["key"], "dotore/no-derived-state");
    assert_eq!(arr[0]["severity"], "warn");
    assert_eq!(arr[0]["source"], "rules");

    let explain_out = Command::new(dotore_bin())
        .args([
            "rules",
            "explain",
            "effect/no-derived-state",
            "--json",
            "--cwd",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(explain_out.status.success());
    let explain_json: serde_json::Value = serde_json::from_slice(&explain_out.stdout).unwrap();
    assert_eq!(explain_json["key"], "dotore/no-derived-state");
    assert_eq!(explain_json["tier"], "autofix");
    assert!(
        explain_json["before_example"]
            .as_str()
            .unwrap()
            .contains("useEffect")
    );
    assert!(
        explain_json["config_snippet"]
            .as_str()
            .unwrap()
            .contains("dotore/no-derived-state")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rules_mutation_subcommands_update_json_ts_and_package_json_in_place() {
    // 1. When no config exists, creates `dotore.config.json`
    let dir_new = unique_temp_dir("rules-mutate-new");
    fs::create_dir_all(&dir_new).unwrap();

    // `unignore-tag` when no config exists is a no-op and does not create a stray file
    let noop_res = mutate_config_in_dir(
        &dir_new,
        ConfigMutation::UnignoreTag {
            tag: RuleTag::Design,
        },
    )
    .unwrap();
    assert!(!noop_res.changed);
    assert!(!dir_new.join("dotore.config.json").exists());

    // `enable` creates `dotore.config.json` with default severity
    let enable_out = Command::new(dotore_bin())
        .args(["rules", "enable", "design-no-vague-button-label", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(enable_out.status.success());
    assert!(dir_new.join("dotore.config.json").is_file());
    let cfg = load_config_from_dir(&dir_new);
    assert_eq!(
        cfg.explicit_rule_override(RuleId::DesignNoVagueButtonLabel),
        Some(RuleSeverityOverride::Warn)
    );

    // `disable`, `set`, `category`, `ignore-tag`, `unignore-tag` via CLI on `dotore.config.json`
    let disable_out = Command::new(dotore_bin())
        .args(["rules", "disable", "no-derived-state", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(disable_out.status.success());
    assert_eq!(
        load_config_from_dir(&dir_new).explicit_rule_override(RuleId::NoDerivedState),
        Some(RuleSeverityOverride::Off)
    );

    let set_out = Command::new(dotore_bin())
        .args(["rules", "set", "effect/no-derived-state", "warn", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(set_out.status.success());
    let cfg_after_set = load_config_from_dir(&dir_new);
    assert_eq!(
        cfg_after_set.explicit_rule_override(RuleId::NoDerivedState),
        Some(RuleSeverityOverride::Warn)
    );
    assert_eq!(
        cfg_after_set
            .rules
            .keys()
            .filter(|k| RuleId::parse(k) == Some(RuleId::NoDerivedState))
            .count(),
        1,
        "Legacy alias should be canonicalized without duplicate entries"
    );

    let cat_out = Command::new(dotore_bin())
        .args(["rules", "category", "security", "error", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(cat_out.status.success());
    assert_eq!(
        load_config_from_dir(&dir_new).category_override(RuleCategory::Security),
        Some(RuleSeverityOverride::Error)
    );

    let tag_out = Command::new(dotore_bin())
        .args(["rules", "ignore-tag", "r3f", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(tag_out.status.success());
    assert!(load_config_from_dir(&dir_new).is_tag_ignored(RuleTag::R3f));

    let untag_out = Command::new(dotore_bin())
        .args(["rules", "unignore-tag", "r3f", "--cwd"])
        .arg(&dir_new)
        .output()
        .unwrap();
    assert!(untag_out.status.success());
    assert!(!load_config_from_dir(&dir_new).is_tag_ignored(RuleTag::R3f));

    // 2. Preserves unrelated fields and key ordering in `package.json#dotore`
    let dir_pkg = unique_temp_dir("rules-mutate-pkg");
    fs::create_dir_all(&dir_pkg).unwrap();
    let initial_pkg_json = r#"{
  "name": "preserve-pkg",
  "version": "1.2.3",
  "scripts": {
    "build": "tsc"
  },
  "dotore": {
    "customRulesOnly": true,
    "textComponents": ["MyText"],
    "rules": {
      "effect/no-derived-state": "warn"
    }
  }
}
"#;
    fs::write(dir_pkg.join("package.json"), initial_pkg_json).unwrap();

    let pkg_res = mutate_config_in_dir(
        &dir_pkg,
        ConfigMutation::SetRuleSeverity {
            rule: RuleId::NoDerivedState,
            severity: RuleSeverityOverride::Error,
        },
    )
    .unwrap();
    assert_eq!(pkg_res.target_kind, ConfigTargetKind::PackageJson);
    assert!(pkg_res.changed);
    let updated_pkg_raw = fs::read_to_string(dir_pkg.join("package.json")).unwrap();
    assert!(updated_pkg_raw.contains("\"name\": \"preserve-pkg\""));
    assert!(updated_pkg_raw.contains("\"build\": \"tsc\""));
    assert!(updated_pkg_raw.contains("\"customRulesOnly\": true"));
    assert!(updated_pkg_raw.contains("\"MyText\""));
    assert!(!updated_pkg_raw.contains("effect/no-derived-state"));
    assert!(updated_pkg_raw.contains("\"dotore/no-derived-state\": \"error\""));

    // 3. Preserves comments, imports, and unrelated options in `dotore.config.ts`
    let dir_ts = unique_temp_dir("rules-mutate-ts");
    fs::create_dir_all(&dir_ts).unwrap();
    let initial_ts = r#"import { defineConfig } from 'dotore';

// Keep this header comment intact
export default defineConfig({
  customRulesOnly: true,
  runtimeGlobals: ['GlobalWidget'],
  rules: {
    'react/jsx-key': 'warn',
  },
});
"#;
    fs::write(dir_ts.join("dotore.config.ts"), initial_ts).unwrap();

    let ts_res = mutate_config_in_dir(
        &dir_ts,
        ConfigMutation::SetRuleSeverity {
            rule: RuleId::JsxKey,
            severity: RuleSeverityOverride::Error,
        },
    )
    .unwrap();
    assert_eq!(ts_res.target_kind, ConfigTargetKind::ModuleFile);
    let updated_ts_raw = fs::read_to_string(dir_ts.join("dotore.config.ts")).unwrap();
    assert!(updated_ts_raw.contains("// Keep this header comment intact"));
    assert!(updated_ts_raw.contains("runtimeGlobals: ['GlobalWidget']"));
    assert!(!updated_ts_raw.contains("react/jsx-key"));
    assert!(updated_ts_raw.contains("\"dotore/jsx-key\": \"error\""));
    let reloaded_ts = load_config_from_dir(&dir_ts);
    assert!(reloaded_ts.custom_rules_only);
    assert_eq!(reloaded_ts.runtime_globals, vec!["GlobalWidget"]);
    assert_eq!(
        reloaded_ts.explicit_rule_override(RuleId::JsxKey),
        Some(RuleSeverityOverride::Error)
    );

    let _ = fs::remove_dir_all(&dir_new);
    let _ = fs::remove_dir_all(&dir_pkg);
    let _ = fs::remove_dir_all(&dir_ts);
}

#[test]
fn why_subcommand_explains_active_findings_fix_capsules_suppressions_config_and_capability_gates() {
    // 1. Parse `<file:line>` and `<file:line:col>`
    let loc1 = parse_why_location("src/Form.tsx:14").unwrap();
    assert_eq!(loc1.file, PathBuf::from("src/Form.tsx"));
    assert_eq!(loc1.line, 14);
    assert_eq!(loc1.column, None);

    let loc2 = parse_why_location("src/Form.tsx:14:5").unwrap();
    assert_eq!(loc2.file, PathBuf::from("src/Form.tsx"));
    assert_eq!(loc2.line, 14);
    assert_eq!(loc2.column, Some(5));
    assert!(parse_why_location("src/Form.tsx").is_err());

    let dir = unique_temp_dir("why-explain");
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Plain React package (no Next.js dependency)
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "why-app", "dependencies": { "react": "^19.0.0" } }"#,
    )
    .unwrap();

    // Component file with:
    // - Line 9: active `no-derived-state` (with mismatched `// dotore-disable-next-line jsx-key` on line 8)
    // - Line 15: suppressed `no-initialize-state` (with `// dotore-disable-next-line no-initialize-state` on line 14)
    // - Line 19: `<img>` with `alt="hero"` (triggers `nextjs-no-img-element` only if Nextjs capability is active)
    let comp_src = r#"import { useState, useEffect } from 'react';

export function UserCard({ firstName, lastName, initialBio }: { firstName: string; lastName: string; initialBio: string }) {
  const [fullName, setFullName] = useState('');
  const [bio, setBio] = useState('');

  // dotore-disable-next-line jsx-key
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);

  // dotore-disable-next-line no-initialize-state
  useEffect(() => {
    setBio('Default bio');
  }, []);

  return (
    <div>
      <img src="/avatar.png" alt="Avatar" />
      <span>{fullName} - {bio}</span>
    </div>
  );
}
export const UNUSED_HELPER_CONST = 42;
"#;
    let comp_path = src_dir.join("UserCard.tsx");
    fs::write(&comp_path, comp_src).unwrap();

    // Parent caller file for cross-file Caller Site resolution
    let app_src = r#"import { UserCard } from './UserCard';
export function App() {
  return <UserCard firstName="Ada" lastName="Lovelace" initialBio="Math" />;
}
"#;
    fs::write(src_dir.join("App.tsx"), app_src).unwrap();

    // A. Active finding at line 9 (setFullName inside useEffect starting at line 8)
    let active_report = explain_location("src/UserCard.tsx:9", &dir).unwrap();
    assert!(!active_report.entries.is_empty());
    let entry = &active_report.entries[0];
    assert_eq!(entry.status, "active");
    assert_eq!(entry.rule, "dotore/no-derived-state");
    assert!(
        entry.explanation.contains("jsx-key"),
        "Should explain why the nearby disable comment for jsx-key did not suppress no-derived-state: {}",
        entry.explanation
    );
    assert!(
        entry
            .fix_capsule
            .subject_excerpt
            .source
            .contains("function UserCard")
    );
    assert!(!entry.fix_capsule.recipe_markdown.is_empty());
    let rendered_active = format_why_report_text(&active_report);
    assert!(rendered_active.contains("dotore/no-derived-state"));
    assert!(rendered_active.contains("Fix Capsule"));

    // B. Inline-suppressed finding at line 14 (setBio inside useEffect with dotore-disable-next-line)
    let suppressed_report = explain_location("src/UserCard.tsx:14", &dir).unwrap();
    assert!(!suppressed_report.entries.is_empty());
    let sup_entry = &suppressed_report.entries[0];
    assert_eq!(sup_entry.status, "suppressed");
    assert_eq!(sup_entry.rule, "dotore/no-initialize-state");
    assert!(sup_entry.explanation.contains("inline"));
    assert!(
        sup_entry
            .fix_capsule
            .subject_excerpt
            .source
            .contains("UserCard")
    );

    // C. Capability-gated finding at line 19 (`<img src="/avatar.png" alt="Avatar" />` -> `nextjs-no-img-element` gated off)
    let gated_report = explain_location("src/UserCard.tsx:19", &dir).unwrap();
    assert!(!gated_report.entries.is_empty());
    let gated_entry = gated_report
        .entries
        .iter()
        .find(|e| e.rule == "dotore/nextjs-no-img-element")
        .expect("should explain nextjs-no-img-element capability gate");
    assert_eq!(gated_entry.status, "gated");
    assert!(gated_entry.explanation.contains("Capability Gate"));
    assert!(gated_entry.explanation.contains("nextjs"));

    // D. Disabled-by-config finding when `no-derived-state` is set to `off`
    mutate_config_in_dir(
        &dir,
        ConfigMutation::SetRuleSeverity {
            rule: RuleId::NoDerivedState,
            severity: RuleSeverityOverride::Off,
        },
    )
    .unwrap();
    let disabled_report = explain_location("src/UserCard.tsx:9", &dir).unwrap();
    assert!(!disabled_report.entries.is_empty());
    let dis_entry = &disabled_report.entries[0];
    assert_eq!(dis_entry.status, "disabled");
    assert_eq!(dis_entry.rule, "dotore/no-derived-state");
    assert!(dis_entry.explanation.contains("off"));

    // E. CLI invocation `dotore why src/UserCard.tsx:9 --json --cwd <dir>`
    let cli_out = Command::new(dotore_bin())
        .args(["why", "src/UserCard.tsx:9", "--json", "--cwd"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(cli_out.status.success());
    let cli_json: serde_json::Value = serde_json::from_slice(&cli_out.stdout).unwrap();
    assert_eq!(cli_json["entries"][0]["rule"], "dotore/no-derived-state");
    assert!(
        cli_json["entries"][0]["fix_capsule"]["subject_excerpt"]["source"]
            .as_str()
            .unwrap()
            .contains("UserCard")
    );

    // F. Project-graph finding (`unused-export`) explained via `explain_location`
    let unused_report = explain_location("src/UserCard.tsx:24", &dir).unwrap();
    assert!(
        unused_report
            .entries
            .iter()
            .any(|e| e.rule == "dotore/unused-export" && e.status == "active"),
        "Expected `dotore/unused-export` project-graph finding at src/UserCard.tsx:24, got: {:?}",
        unused_report.entries
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn design_subcommand_runs_only_design_rules_and_skips_unrelated_passes() {
    let design_rules = design_rule_ids();
    assert!(!design_rules.is_empty());
    assert!(design_rules.contains(&RuleId::DesignNoVagueButtonLabel));
    assert!(
        design_rules
            .iter()
            .all(|r| r.metadata().tags.contains(&RuleTag::Design))
    );
    assert!(
        design_rules
            .iter()
            .all(|r| !r.metadata().tags.contains(&RuleTag::ProjectAnalysis))
    );

    let dir = unique_temp_dir("design-audit");
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "design-app", "dependencies": { "react": "^19.0.0" } }"#,
    )
    .unwrap();

    // Component has BOTH a non-design bug (`no-derived-state`) AND an opt-in `design` issue (`<button>Click here</button>`)
    let comp_src = r#"import { useState, useEffect } from 'react';
export function Hero({ title }: { title: string }) {
  const [upper, setUpper] = useState('');
  useEffect(() => {
    setUpper(title.toUpperCase());
  }, [title]);
  return (
    <section>
      <h1>{upper}</h1>
      <button>Click here</button>
    </section>
  );
}
"#;
    fs::write(src_dir.join("Hero.tsx"), comp_src).unwrap();

    // 1. Standard scan finds `no-derived-state` and skips opt-in `design-no-vague-button-label`
    let (std_report, _) = scan_workspace(&ScanOptions {
        paths: vec![dir.clone()],
        ..Default::default()
    })
    .unwrap();
    assert!(
        std_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::NoDerivedState)
    );
    assert!(
        !std_report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::DesignNoVagueButtonLabel)
    );

    // 2. `scan_design` enables `design`-tagged rules and skips `no-derived-state` and health score display
    let (design_report, _) = scan_design(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides::default(),
    )
    .unwrap();
    assert_eq!(design_report.diagnostics.len(), 1);
    assert_eq!(
        design_report.diagnostics[0].rule,
        RuleId::DesignNoVagueButtonLabel
    );

    let design_text = format_design_report(&design_report);
    assert!(design_text.contains("dotore design"));
    assert!(design_text.contains("design-no-vague-button-label"));
    assert!(
        !design_text.contains("score:"),
        "Design audit terminal report should omit health score pass"
    );

    // 3. CLI `dotore design <dir> --no-fail` and `--json`
    let cli_out = Command::new(dotore_bin())
        .args(["design", "--no-fail"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(cli_out.status.success());
    let stdout_str = String::from_utf8_lossy(&cli_out.stdout);
    assert!(stdout_str.contains("design-no-vague-button-label"));
    assert!(!stdout_str.contains("no-derived-state"));
    assert!(!stdout_str.contains("score:"));

    // 4. `scan_design` respects `test-noise` suppression in `.test.tsx` files
    fs::write(
        src_dir.join("Hero.test.tsx"),
        r#"export function HeroTest() { return <div className="px-4 py-4">Loading...</div>; }"#,
    )
    .unwrap();
    let (with_test_report, _) = scan_design(
        &ScanOptions {
            paths: vec![dir.clone()],
            include_tests: true,
            ..Default::default()
        },
        &CliOverrides::default(),
    )
    .unwrap();
    assert_eq!(
        with_test_report.diagnostics.len(),
        1,
        "test-noise tagged design rules should not fire in Hero.test.tsx"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ci_and_install_subcommands_scaffold_workflows_skills_and_hooks() {
    let dir = unique_temp_dir("ci-and-install");
    fs::create_dir_all(dir.join(".git").join("hooks")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{
  "name": "setup-app",
  "scripts": {
    "test": "vitest"
  }
}
"#,
    )
    .unwrap();

    // 1. `dotore ci install`, `ci config`, and `ci upgrade` for GitHub Actions
    let install_ci_res = ci_install(&CiOptions {
        cwd: dir.clone(),
        provider: Some(CiProviderKind::GithubActions),
        blocking: None,
        scope: None,
    })
    .unwrap();
    assert_eq!(install_ci_res.status, "created");
    assert_eq!(install_ci_res.scope, "changed");
    let wf_path = dir.join(".github").join("workflows").join("dotore.yml");
    assert!(wf_path.is_file());
    let wf_content = fs::read_to_string(&wf_path).unwrap();
    assert!(wf_content.contains("dotore check --scope changed"));

    // Update via `dotore ci config` CLI
    let cfg_ci_out = Command::new(dotore_bin())
        .args([
            "ci",
            "config",
            "--blocking",
            "error",
            "--scope",
            "contextual",
            "--cwd",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(cfg_ci_out.status.success());
    let wf_after_cfg = fs::read_to_string(&wf_path).unwrap();
    assert!(wf_after_cfg.contains("--scope contextual"));
    assert!(wf_after_cfg.contains("--blocking error"));

    // Simulate a v1 workflow and upgrade it via `dotore ci upgrade`
    fs::write(
        &wf_path,
        wf_after_cfg.replace("# dotore workflow v2", "# dotore workflow v1"),
    )
    .unwrap();
    let upg_res = ci_upgrade(&CiOptions {
        cwd: dir.clone(),
        provider: Some(CiProviderKind::GithubActions),
        blocking: None,
        scope: None,
    })
    .unwrap();
    assert_eq!(upg_res.status, "upgraded");
    let wf_after_upg = fs::read_to_string(&wf_path).unwrap();
    assert!(wf_after_upg.contains("# dotore workflow v2"));
    assert!(wf_after_upg.contains("--scope contextual"));

    // Also verify GitLab CI provider via `ci_install` and `ci_config`
    let gl_res = ci_install(&CiOptions {
        cwd: dir.clone(),
        provider: Some(CiProviderKind::GitlabCi),
        blocking: Some("warning".to_string()),
        scope: Some("lines".to_string()),
    })
    .unwrap();
    assert_eq!(gl_res.status, "created");
    let gl_path = dir.join(".gitlab-ci.yml");
    assert!(gl_path.is_file());
    assert!(
        fs::read_to_string(&gl_path)
            .unwrap()
            .contains("--scope lines")
    );
    let gl_cfg_res = ci_config(&CiOptions {
        cwd: dir.clone(),
        provider: Some(CiProviderKind::GitlabCi),
        blocking: Some("error".to_string()),
        scope: Some("changed".to_string()),
    })
    .unwrap();
    assert_eq!(gl_cfg_res.status, "updated");
    assert!(
        fs::read_to_string(&gl_path)
            .unwrap()
            .contains("--scope changed")
    );

    // 2. `dotore install --dry-run --yes --agent-hooks` does not write files to disk
    let dry_res = install_dotore(&InstallOptions {
        cwd: dir.clone(),
        yes: true,
        dry_run: true,
        agent_hooks: true,
    })
    .unwrap();
    assert!(dry_res.dry_run);
    assert!(!dry_res.skill_files.is_empty());
    assert!(!dir.join(".claude/skills/dotore/SKILL.md").exists());
    assert!(!dir.join(".git/hooks/pre-commit").exists());
    let dry_text = format_install_report(&dry_res);
    assert!(dry_text.contains("[dry-run]"));

    // 3. `dotore install --yes --agent-hooks --cwd <dir>` via CLI writes skill, script, git hook, and agent hooks
    let inst_out = Command::new(dotore_bin())
        .args(["install", "--yes", "--agent-hooks", "--cwd"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(inst_out.status.success());

    let skill_path = dir.join(".claude/skills/dotore/SKILL.md");
    assert!(skill_path.is_file());
    let skill_content = fs::read_to_string(&skill_path).unwrap();
    assert!(skill_content.contains("name: dotore"));
    assert!(skill_content.contains("dotore check"));
    assert!(skill_content.contains("dotore fix"));
    assert!(skill_content.contains("dotore plan"));
    assert!(skill_content.contains("dotore search"));
    assert!(skill_content.contains("dotore why"));

    let pkg_after = fs::read_to_string(dir.join("package.json")).unwrap();
    assert!(pkg_after.contains("\"test\": \"vitest\""));
    assert!(pkg_after.contains("\"dotore\": \"dotore check\""));

    let git_hook_path = dir.join(".git/hooks/pre-commit");
    assert!(git_hook_path.is_file());
    let git_hook_content = fs::read_to_string(&git_hook_path).unwrap();
    assert!(git_hook_content.contains("# dotore hook start"));
    assert!(git_hook_content.contains("dotore check --staged"));

    let claude_settings_path = dir.join(".claude/settings.json");
    assert!(claude_settings_path.is_file());
    let claude_settings = fs::read_to_string(&claude_settings_path).unwrap();
    assert!(claude_settings.contains(".claude/hooks/dotore.mjs"));
    assert!(dir.join(".claude/hooks/dotore.mjs").is_file());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn modular_cli_progress_and_tui_explorer_render_via_ui_kit() {
    use clap::Parser as _;
    use dotore::{
        Cli, ColorMode, Commands, TuiGroupMode, TuiState, build_filter_tabs, build_score_gauge,
        current_scan_progress, diagnostic_matches_tab_and_search, format_spinner_frame,
        handle_tui_search_key, render_tui_body_lines, render_tui_frame, run_cli,
        set_progress_phase, strip_ansi_codes, tick_progress_file, visible_char_width,
    };

    // 1. Progress module delegates to dotore_core::ui
    set_progress_phase(3, 10);
    tick_progress_file(std::path::Path::new("src/UserForm.tsx"));
    let snap = current_scan_progress();
    assert_eq!(snap.phase, "Extracting AST & IR (parallel)");
    assert_eq!(snap.completed_files, 1);
    assert_eq!(snap.total_files, 10);
    let spinner_plain = format_spinner_frame(&snap, 0, 1.2, ColorMode::Plain);
    assert!(spinner_plain.contains("DOTORE"));
    assert!(spinner_plain.contains("(1/10)"));

    // 2. Build a real report with a Render Cascade diagnostic and an Autofix diagnostic
    let report = dotore::analyze_project_sources(
        vec![(
            PathBuf::from("src/Form.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function Form({ first, last }: { first: string; last: string }) {
                const [full, setFull] = useState('');
                const [ready, setReady] = useState();
                useEffect(() => {
                    setFull(first + ' ' + last);
                }, [first, last]);
                useEffect(() => {
                    setReady(true);
                }, []);
                return <div>{full}{String(ready)}</div>;
            }
            "#
            .to_string(),
        )],
        None,
    );
    assert!(report.diagnostics.len() >= 2);

    // 3. TUI filter tabs, body rendering across all 3 grouping modes, and frame rendering
    let tabs = build_filter_tabs(&report);
    assert!(tabs.len() >= 3);
    assert_eq!(tabs[0].label, "ALL");

    let all_refs: Vec<&dotore::Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| diagnostic_matches_tab_and_search(d, &tabs[0], ""))
        .collect();
    assert_eq!(all_refs.len(), report.diagnostics.len());

    let by_rule_lines = render_tui_body_lines(&all_refs, TuiGroupMode::ByRuleStyle);
    let by_rule_plain = strip_ansi_codes(&by_rule_lines.join("\n"));
    assert!(by_rule_plain.contains("[EFFECTS & STATE]"));
    assert!(by_rule_plain.contains("no-derived-state"));
    assert!(by_rule_plain.contains("┌─►"));

    let by_file_lines = render_tui_body_lines(&all_refs, TuiGroupMode::ByFile);
    let by_file_plain = strip_ansi_codes(&by_file_lines.join("\n"));
    assert!(by_file_plain.contains("src/Form.tsx"));

    let card_lines = render_tui_body_lines(&all_refs, TuiGroupMode::DetailedCards);
    let card_plain = strip_ansi_codes(&card_lines.join("\n"));
    assert!(card_plain.contains("flow:    ┌─►"));
    assert!(card_plain.contains("docs:    https://react.dev/learn/you-might-not-need-an-effect"));

    let empty_lines = render_tui_body_lines(&[], TuiGroupMode::ByRuleStyle);
    let empty_plain = strip_ansi_codes(&empty_lines.join("\n"));
    assert!(empty_plain.contains("Zero findings match this filter!"));

    let gauge = build_score_gauge(92, 18);
    assert_eq!(visible_char_width(&gauge), 27);

    let frame = render_tui_frame(
        &report,
        &tabs,
        0,
        TuiGroupMode::ByRuleStyle,
        "",
        false,
        &by_rule_lines,
        0,
        28,
        120,
        false,
    );
    let frame_plain = strip_ansi_codes(&frame);
    assert!(frame_plain.contains("╔══ DOTORE · Polyglot Static Analyzer"));
    assert!(frame_plain.contains("╠══ FILTER TABS"));
    assert!(frame_plain.contains("▶ ALL"));
    assert!(frame_plain.contains("[h/l or ←/→] Filter Tab"));

    // 4. TUI interactive state machine: hjkl, tab switch, group mode `v`, `/` search, ESC exit
    let mut state = TuiState::new(tabs.len());
    assert!(!state.handle_key(b"l", 10, 5));
    assert_eq!(state.active_tab_idx, 1);
    assert!(!state.handle_key(b"h", 10, 5));
    assert_eq!(state.active_tab_idx, 0);
    assert!(!state.handle_key(b"j", 10, 5));
    assert_eq!(state.scroll_offset, 1);
    assert!(!state.handle_key(b"k", 10, 5));
    assert_eq!(state.scroll_offset, 0);
    assert!(!state.handle_key(b"v", 10, 5));
    assert_eq!(state.group_mode, TuiGroupMode::ByFile);
    assert!(!state.handle_key(b"/", 10, 5));
    assert!(state.in_search_input);
    handle_tui_search_key(
        b"derived",
        &mut state.search_query,
        &mut state.in_search_input,
        &mut state.scroll_offset,
    );
    assert_eq!(state.search_query, "derived");
    handle_tui_search_key(
        b"\n",
        &mut state.search_query,
        &mut state.in_search_input,
        &mut state.scroll_offset,
    );
    assert!(!state.in_search_input);
    assert!(state.handle_key(&[0x1b], 10, 5));

    // 5. CLI parser & runner seam
    let parsed = Cli::try_parse_from(["dotore", "score", "--no-fail"]).expect("valid CLI args");
    assert!(matches!(parsed.command, Some(Commands::Score(_))));
    let dir = unique_temp_dir("modular-cli-run");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("index.ts"), "export const x = 1;\n").unwrap();
    let check_cli =
        Cli::try_parse_from(["dotore", "score", dir.to_str().unwrap(), "--no-fail"]).unwrap();
    assert_eq!(run_cli(check_cli), std::process::ExitCode::SUCCESS);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tui_frame_and_progress_bar_fit_any_terminal_width_and_align_borders() {
    use dotore::{
        ColorMode, FilterTabItem, LiveScanProgressSnapshot, RuleId, TuiFilterKind, TuiGroupMode,
        build_filter_tabs, diagnostic_matches_tab_and_search, format_spinner_frame_with_width,
        render_tui_body_lines_for_width, render_tui_frame, strip_ansi_codes, visible_char_width,
    };

    // 1. Multi-width spinner frame formatting (80, 100, 120 cols) preserves file counter and current file name
    let snap = LiveScanProgressSnapshot {
        phase: "Evaluating ProjectGraph & Rules",
        completed_files: 145,
        total_files: 322,
        current_file: "src/components/UserProfileDashboard.tsx".to_string(),
    };
    for cols in [80usize, 100, 120] {
        let spinner_line =
            format_spinner_frame_with_width(&snap, 2, 0.8, ColorMode::Plain, cols - 2);
        assert!(
            visible_char_width(&spinner_line) <= cols - 2,
            "Spinner frame exceeded {} cols: {} ({spinner_line})",
            cols - 2,
            visible_char_width(&spinner_line)
        );
        assert!(spinner_line.contains("(145/322)"));
        assert!(
            spinner_line.contains("Dashboard.tsx"),
            "Spinner frame must display the current file name at {cols} cols: {spinner_line}"
        );
    }

    let mut report = dotore::analyze_project_sources(
        vec![(
            PathBuf::from("src/App.tsx"),
            "import { useState, useEffect } from 'react';\nexport function App({ a }: { a: string }) { const [v, setV] = useState(''); useEffect(() => { setV(a); }, [a]); return <div>{v}</div>; }\n".to_string(),
        )],
        None,
    );

    // 2. Build a large tab list like the user's 38-tab screenshot and verify 80, 100, and 120 col TUI frames
    report.summary.files_scanned = 322;
    report.summary.subjects_scanned = 45;
    report.summary.affected_file_count = 287;
    report.summary.warning_count = 582;
    report.summary.surgical_count = 293;
    report.summary.refactor_count = 289;
    report.summary.health_score = 39;
    report.summary.score_label = "Critical".to_string();

    let mut tabs = build_filter_tabs(&report);
    for extra in [
        ("UNUSED", 256),
        ("ASYNC & STREAMS", 19),
        ("PERF & LOOPS", 27),
        ("SAFETY & GUARDS", 84),
        ("JSX & A11Y", 1),
        ("SECURITY", 39),
        ("IMPORTS & ARCH", 44),
    ] {
        tabs.push(FilterTabItem::new(
            extra.0,
            extra.1,
            "\x1b[38;5;75;1m",
            TuiFilterKind::StyleBucket(extra.0),
        ));
    }
    for i in 0..30 {
        tabs.push(FilterTabItem::new(
            format!("#rule-{i}"),
            5,
            "\x1b[38;5;117;1m",
            TuiFilterKind::Rule(RuleId::NoDerivedState),
        ));
    }

    let filtered: Vec<&dotore::Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| diagnostic_matches_tab_and_search(d, &tabs[0], ""))
        .collect();

    for cols in [80usize, 100, 120] {
        let body_lines =
            render_tui_body_lines_for_width(&filtered, TuiGroupMode::ByRuleStyle, cols);
        let frame = render_tui_frame(
            &report,
            &tabs,
            0,
            TuiGroupMode::ByRuleStyle,
            "",
            false,
            &body_lines,
            0,
            26,
            cols,
            false,
        );
        let plain = strip_ansi_codes(&frame)
            .replace("\x1b[H", "")
            .replace("\x1b[2K", "");
        if cols == 100 {
            println!("=== 100-COL TUI FRAME ===\n{plain}\n=========================");
        }
        let frame_lines: Vec<&str> = plain.lines().collect();
        // Header box is the first 7 lines (top border, 2 summary rows, titled divider, tab row, search row, bottom border)
        for (idx, line) in frame_lines.iter().enumerate() {
            let w = visible_char_width(line);
            assert!(
                w < cols,
                "Line {idx} at cols={cols} has width {w} >= {cols}: {line:?}"
            );
        }
        for header_line in &frame_lines[..7] {
            assert_eq!(
                visible_char_width(header_line),
                cols - 1,
                "Header box line must have exact width {}: {header_line:?}",
                cols - 1
            );
            let trimmed = header_line.trim_end();
            assert!(
                trimmed.ends_with('╗')
                    || trimmed.ends_with('║')
                    || trimmed.ends_with('╣')
                    || trimmed.ends_with('╝'),
                "Header box line missing right border at cols={cols}: {header_line:?}"
            );
        }
    }
}
