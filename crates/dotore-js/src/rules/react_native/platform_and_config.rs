//! Project-level React Native and Expo manifest (`package.json`, `app.json`),
//! Babel, Metro, Android Gradle, lockfile, and `.gitignore` rule detectors.
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{
    config::{Capability, WorkspacePackage, strip_jsonc},
    graph::ProjectGraph,
    ir::{ByteSpan, SourceLoc},
    rules::{Diagnostic, RuleId, RuleSeverity},
};

/// Evaluates all React Native and Expo project-level configuration checks across [`WorkspacePackage`]s.
pub(crate) fn evaluate_react_native_and_expo_project_checks(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if !graph.has_manifests {
        return;
    }

    for pkg in packages {
        let is_rule_enabled = |rule: RuleId| -> Option<RuleSeverity> {
            if let Some(explicit) = enabled_rules
                && !explicit.contains(&rule)
            {
                return None;
            }
            let has_explicit = enabled_rules.is_some_and(|list| list.contains(&rule));
            if !has_explicit && !pkg.capability_gate.allows_rule(rule.metadata()) {
                return None;
            }
            if has_explicit {
                Some(
                    pkg.config
                        .effective_severity(rule)
                        .unwrap_or(rule.metadata().default_severity),
                )
            } else {
                pkg.config.effective_severity(rule)
            }
        };

        if pkg.capability_gate.has(Capability::ReactNative) {
            check_rn_package_configs(graph, pkg, &is_rule_enabled, out);
        }
        if pkg.capability_gate.has(Capability::Expo) {
            check_expo_package_configs(graph, pkg, &is_rule_enabled, out);
        }
    }
}

fn find_manifest_in_pkg<'a>(
    graph: &'a ProjectGraph,
    pkg_root: &Path,
    rel_name: &str,
) -> Option<(PathBuf, &'a str)> {
    let candidate = if pkg_root == Path::new(".") || pkg_root.as_os_str().is_empty() {
        PathBuf::from(rel_name)
    } else {
        pkg_root.join(rel_name)
    };
    if let Some((k, v)) = graph.manifests.get_key_value(&candidate) {
        return Some((k.clone(), v.as_str()));
    }
    graph
        .manifests
        .iter()
        .find(|(p, _)| {
            p.ends_with(rel_name) && (pkg_root == Path::new(".") || p.starts_with(pkg_root))
        })
        .map(|(k, v)| (k.clone(), v.as_str()))
}

fn check_rn_package_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let pkg_json_entry = find_manifest_in_pkg(graph, &pkg.root_dir, "package.json");
    let pkg_json_val: Option<Value> = pkg_json_entry
        .as_ref()
        .and_then(|(_, txt)| serde_json::from_str::<Value>(&strip_jsonc(txt)).ok());
    let pkg_json_path = pkg_json_entry
        .map(|(p, _)| p)
        .unwrap_or_else(|| pkg.root_dir.join("package.json"));

    check_rn_library_react_in_dependencies(
        pkg_json_val.as_ref(),
        &pkg_json_path,
        is_rule_enabled,
        out,
    );
    check_rn_babel_configs(graph, pkg, is_rule_enabled, out);
    check_rn_android_gradle_configs(graph, pkg, is_rule_enabled, out);
}

fn check_rn_library_react_in_dependencies<F>(
    pkg_json_val: Option<&Value>,
    pkg_json_path: &Path,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let Some(sev) = is_rule_enabled(RuleId::RnLibraryReactInDependencies) else {
        return;
    };
    let Some(val) = pkg_json_val else {
        return;
    };
    if !val
        .get("react-native-builder-bob")
        .is_some_and(Value::is_object)
    {
        return;
    }
    let Some(deps) = val.get("dependencies").and_then(Value::as_object) else {
        return;
    };
    let misplaced: Vec<String> = ["react", "react-native"]
        .into_iter()
        .filter(|name| deps.contains_key(*name))
        .map(|name| format!("\"{name}\""))
        .collect();
    if !misplaced.is_empty() {
        push_project_diagnostic(
            out,
            pkg_json_path.to_path_buf(),
            RuleId::RnLibraryReactInDependencies,
            sev,
            "rnLibraryReactInDependencies",
            "dependencies",
            format!(
                "This react-native-builder-bob library lists {} in `dependencies` — move them to `peerDependencies` so a second copy is not bundled into consumer apps.",
                misplaced.join(" and ")
            ),
        );
    }
}

fn check_rn_babel_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let babel_files = [
        "babel.config.js",
        "babel.config.cjs",
        "babel.config.mjs",
        "babel.config.ts",
        "babel.config.json",
        ".babelrc",
        ".babelrc.js",
        ".babelrc.json",
    ];
    for babel_name in babel_files {
        let Some((babel_path, babel_src)) = find_manifest_in_pkg(graph, &pkg.root_dir, babel_name)
        else {
            continue;
        };
        check_single_rn_babel_config(pkg, &babel_path, babel_src, is_rule_enabled, out);
        break;
    }
}

fn check_single_rn_babel_config<F>(
    pkg: &WorkspacePackage,
    babel_path: &Path,
    babel_src: &str,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let rn_minor = pkg
        .capability_gate
        .dependencies
        .get("react-native")
        .and_then(|v| parse_rn_minor_version(v));
    let has_legacy_preset_dep = pkg
        .capability_gate
        .dependencies
        .contains_key("metro-react-native-babel-preset");

    if rn_minor.is_some_and(|m| m >= 73)
        && !has_legacy_preset_dep
        && (babel_src.contains("'module:metro-react-native-babel-preset'")
            || babel_src.contains("\"module:metro-react-native-babel-preset\""))
        && let Some(sev) = is_rule_enabled(RuleId::RnNoMetroBabelPreset)
    {
        push_project_diagnostic(
            out,
            babel_path.to_path_buf(),
            RuleId::RnNoMetroBabelPreset,
            sev,
            "rnNoMetroBabelPreset",
            "module:metro-react-native-babel-preset",
            "`module:metro-react-native-babel-preset` was renamed to `@react-native/babel-preset` and is no longer installed by React Native 0.73+.".to_string(),
        );
    }

    if (babel_src.contains("'module:@react-native/babel-preset'")
        || babel_src.contains("\"module:@react-native/babel-preset\""))
        && !has_enable_babel_runtime_version(babel_src)
        && let Some(sev) = is_rule_enabled(RuleId::RnNoMetroBabelRuntimeVersion)
    {
        push_project_diagnostic(
            out,
            babel_path.to_path_buf(),
            RuleId::RnNoMetroBabelRuntimeVersion,
            sev,
            "rnNoMetroBabelRuntimeVersion",
            "enableBabelRuntime",
            "`module:@react-native/babel-preset` has no `enableBabelRuntime` version, so Babel runtime helpers can be duplicated across files.".to_string(),
        );
    }

    if let Some(plugins) = extract_static_babel_plugins(babel_src) {
        check_rn_babel_plugin_order(pkg, babel_path, &plugins, is_rule_enabled, out);
    }
}

fn check_rn_babel_plugin_order<F>(
    pkg: &WorkspacePackage,
    babel_path: &Path,
    plugins: &[String],
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if let Some(compiler_idx) = plugins
        .iter()
        .position(|p| p == "babel-plugin-react-compiler" || p == "react-compiler")
        && compiler_idx > 0
        && let Some(sev) = is_rule_enabled(RuleId::RnReactCompilerPluginFirst)
    {
        push_project_diagnostic(
            out,
            babel_path.to_path_buf(),
            RuleId::RnReactCompilerPluginFirst,
            sev,
            "rnReactCompilerPluginFirst",
            "babel-plugin-react-compiler",
            "The React Compiler Babel plugin is not first in `plugins`, so an earlier transform can alter component code before the compiler analyzes it.".to_string(),
        );
    }

    let reanimated_major = pkg
        .capability_gate
        .dependencies
        .get("react-native-reanimated")
        .and_then(|v| parse_major_version(v));
    if reanimated_major.is_some_and(|m| m >= 4)
        && let Some(sev) = is_rule_enabled(RuleId::RnReanimatedWorkletsPluginLast)
    {
        if plugins
            .iter()
            .any(|p| p == "react-native-reanimated/plugin")
        {
            push_project_diagnostic(
                out,
                babel_path.to_path_buf(),
                RuleId::RnReanimatedWorkletsPluginLast,
                sev,
                "rnReanimatedWorkletsPluginLast",
                "react-native-reanimated/plugin",
                "This Reanimated 4 project still uses `react-native-reanimated/plugin`, which was renamed to `react-native-worklets/plugin`.".to_string(),
            );
        }
        if let Some(worklets_idx) = plugins
            .iter()
            .rposition(|p| p == "react-native-worklets/plugin")
            && worklets_idx + 1 != plugins.len()
        {
            push_project_diagnostic(
                out,
                babel_path.to_path_buf(),
                RuleId::RnReanimatedWorkletsPluginLast,
                sev,
                "rnReanimatedWorkletsPluginLast",
                "react-native-worklets/plugin",
                "`react-native-worklets/plugin` is not last in the Babel `plugins` array."
                    .to_string(),
            );
        }
    }
}

fn check_rn_android_gradle_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    for gradle_rel in ["android/app/build.gradle", "android/app/build.gradle.kts"] {
        let Some((gradle_path, gradle_src)) =
            find_manifest_in_pkg(graph, &pkg.root_dir, gradle_rel)
        else {
            continue;
        };
        let (disabled_minify, disabled_shrink) = check_gradle_release_shrinking(gradle_src);
        if (disabled_minify || disabled_shrink)
            && let Some(sev) = is_rule_enabled(RuleId::RnAndroidReleaseShrinkingDisabled)
        {
            let mut features = Vec::new();
            if disabled_minify {
                features.push("code minification");
            }
            if disabled_shrink {
                features.push("resource shrinking");
            }
            push_project_diagnostic(
                out,
                gradle_path,
                RuleId::RnAndroidReleaseShrinkingDisabled,
                sev,
                "rnAndroidReleaseShrinkingDisabled",
                "release",
                format!(
                    "The Android release build explicitly disables {}, leaving unreachable code or resources in the shipped app.",
                    features.join(" and ")
                ),
            );
            break;
        }
    }
}

fn check_expo_package_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let pkg_json_entry = find_manifest_in_pkg(graph, &pkg.root_dir, "package.json");
    let pkg_json_val: Option<Value> = pkg_json_entry
        .as_ref()
        .and_then(|(_, txt)| serde_json::from_str::<Value>(&strip_jsonc(txt)).ok());
    let pkg_json_path = pkg_json_entry
        .map(|(p, _)| p)
        .unwrap_or_else(|| pkg.root_dir.join("package.json"));
    let expo_sdk_major = pkg
        .capability_gate
        .dependencies
        .get("expo")
        .and_then(|v| parse_major_version(v));

    check_expo_dependency_tables(pkg, &pkg_json_path, expo_sdk_major, is_rule_enabled, out);
    check_expo_package_json_conflicts_and_overrides(
        pkg,
        pkg_json_val.as_ref(),
        &pkg_json_path,
        expo_sdk_major,
        is_rule_enabled,
        out,
    );
    check_expo_lockfile_and_metro(graph, pkg, &pkg_json_path, is_rule_enabled, out);
    check_expo_app_json_configs(graph, pkg, is_rule_enabled, out);
    check_expo_gitignore_and_env_local(graph, pkg, &pkg_json_path, is_rule_enabled, out);
}

fn check_expo_dependency_tables<F>(
    pkg: &WorkspacePackage,
    pkg_json_path: &Path,
    expo_sdk_major: Option<u32>,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let deps = &pkg.capability_gate.dependencies;
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoUnimodulesPackages) {
        for unimod in [
            "@unimodules/core",
            "@unimodules/react-native-adapter",
            "react-native-unimodules",
        ] {
            if deps.contains_key(unimod) {
                let msg = format!("\"{unimod}\" is a legacy unimodules package that is incompatible with Expo SDK 44+ and will break native builds.");
                push_project_diagnostic(out, pkg_json_path.to_path_buf(), RuleId::ExpoNoUnimodulesPackages, sev, "expoNoUnimodulesPackages", unimod, msg);
            }
        }
    }
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoCliDependencies) {
        for cli_pkg in ["expo-cli", "eas-cli"] {
            if deps.contains_key(cli_pkg) {
                let msg = format!("`{cli_pkg}` should not be installed as a project dependency.");
                push_project_diagnostic(out, pkg_json_path.to_path_buf(), RuleId::ExpoNoCliDependencies, sev, "expoNoCliDependencies", cli_pkg, msg);
            }
        }
    }

    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoRedundantDependency) {
        let redundant_table: &[(&str, Option<u32>)] = &[
            ("expo-modules-autolinking", None),
            ("expo-dev-launcher", None),
            ("expo-dev-menu", None),
            ("expo-modules-core", None),
            ("@expo/metro-config", None),
            ("@types/react-native", Some(48)),
            ("@expo/config-plugins", Some(48)),
            ("@expo/prebuild-config", Some(53)),
            ("expo-permissions", Some(50)),
            ("expo-app-loading", Some(49)),
            ("expo-firebase-analytics", Some(48)),
            ("expo-firebase-recaptcha", Some(48)),
            ("expo-firebase-core", Some(48)),
        ];
        for &(pkg_name, min_sdk) in redundant_table {
            if deps.contains_key(pkg_name)
                && min_sdk.is_none_or(|min| expo_sdk_major.is_some_and(|sdk| sdk >= min))
            {
                let msg = format!("\"{pkg_name}\" should not be a direct dependency in this Expo project.");
                push_project_diagnostic(out, pkg_json_path.to_path_buf(), RuleId::ExpoNoRedundantDependency, sev, "expoNoRedundantDependency", pkg_name, msg);
            }
        }
    }
}

fn check_expo_package_json_conflicts_and_overrides<F>(
    pkg: &WorkspacePackage,
    pkg_json_val: Option<&Value>,
    pkg_json_path: &Path,
    expo_sdk_major: Option<u32>,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let deps = &pkg.capability_gate.dependencies;

    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoConflictingDependencyOverride)
        && let Some(val) = pkg_json_val
    {
        let overridden = collect_overridden_sdk_packages(val);
        if !overridden.is_empty() {
            push_project_diagnostic(
                out,
                pkg_json_path.to_path_buf(),
                RuleId::ExpoNoConflictingDependencyOverride,
                sev,
                "expoNoConflictingDependencyOverride",
                "overrides",
                format!(
                    "package.json pins SDK-critical packages via overrides/resolutions ({}).",
                    overridden.join(", ")
                ),
            );
        }
    }

    if expo_sdk_major == Some(56)
        && deps.contains_key("expo-router")
        && deps.keys().any(|k| k.starts_with("@react-navigation/"))
        && let Some(sev) = is_rule_enabled(RuleId::ExpoRouterNoReactNavigation)
    {
        push_project_diagnostic(
            out,
            pkg_json_path.to_path_buf(),
            RuleId::ExpoRouterNoReactNavigation,
            sev,
            "expoRouterNoReactNavigation",
            "expo-router",
            "As of SDK 56, expo-router is no longer compatible with directly installed @react-navigation packages.".to_string(),
        );
    }

    if expo_sdk_major.is_some_and(|sdk| sdk >= 56)
        && deps
            .keys()
            .any(|k| k.starts_with("@react-native-vector-icons/"))
        && (deps.contains_key("@expo/vector-icons")
            || deps.contains_key("react-native-vector-icons"))
        && let Some(sev) = is_rule_enabled(RuleId::ExpoVectorIconsConflict)
    {
        push_project_diagnostic(
            out,
            pkg_json_path.to_path_buf(),
            RuleId::ExpoVectorIconsConflict,
            sev,
            "expoVectorIconsConflict",
            "@expo/vector-icons",
            "This project installs both scoped `@react-native-vector-icons/*` packages and `@expo/vector-icons`.".to_string(),
        );
    }

    if let Some(sev) = is_rule_enabled(RuleId::ExpoPackageJsonConflict)
        && let Some(val) = pkg_json_val
    {
        check_expo_package_json_script_and_name_conflict(val, deps, pkg_json_path, sev, out);
    }
}

fn check_expo_package_json_script_and_name_conflict(
    val: &Value,
    deps: &std::collections::HashMap<String, String>,
    pkg_json_path: &Path,
    sev: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    if let Some(scripts) = val.get("scripts").and_then(Value::as_object)
        && (scripts.contains_key("expo") || scripts.contains_key("react-native"))
    {
        push_project_diagnostic(
            out,
            pkg_json_path.to_path_buf(),
            RuleId::ExpoPackageJsonConflict,
            sev,
            "expoPackageJsonConflict",
            "scripts",
            "package.json defines a script named \"expo\" or \"react-native\" that shadows the CLI binary in node_modules/.bin.".to_string(),
        );
    }
    if let Some(pkg_name) = val.get("name").and_then(Value::as_str)
        && deps.contains_key(pkg_name)
    {
        push_project_diagnostic(
            out,
            pkg_json_path.to_path_buf(),
            RuleId::ExpoPackageJsonConflict,
            sev,
            "expoPackageJsonConflict",
            pkg_name,
            format!(
                "package.json \"name\" is \"{pkg_name}\", which collides with a dependency of the same name."
            ),
        );
    }
}

fn collect_overridden_sdk_packages(val: &Value) -> Vec<String> {
    let mut overridden = Vec::new();
    for obj_opt in [
        val.get("overrides").and_then(Value::as_object),
        val.get("resolutions").and_then(Value::as_object),
        val.pointer("/pnpm/overrides").and_then(Value::as_object),
    ]
    .into_iter()
    .flatten()
    {
        for k in obj_opt.keys() {
            if matches!(
                k.as_str(),
                "@expo/cli"
                    | "@expo/config"
                    | "@expo/metro-config"
                    | "@expo/metro-runtime"
                    | "@expo/metro"
                    | "metro"
            ) || k.starts_with("metro-")
            {
                overridden.push(format!("\"{k}\""));
            }
        }
    }
    overridden.sort();
    overridden.dedup();
    overridden
}

fn check_expo_lockfile_and_metro<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    pkg_json_path: &Path,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if let Some(sev) = is_rule_enabled(RuleId::ExpoLockfile) {
        let lockfile_names = [
            "pnpm-lock.yaml",
            "yarn.lock",
            "package-lock.json",
            "bun.lockb",
            "bun.lock",
        ];
        let present_lockfiles: Vec<&str> = lockfile_names
            .into_iter()
            .filter(|name| find_manifest_in_pkg(graph, &pkg.root_dir, name).is_some())
            .collect();
        if present_lockfiles.len() != 1 {
            let msg = if present_lockfiles.is_empty() {
                "No lock file detected at the project root — installs are not reproducible, and EAS Build cannot infer your package manager.".to_string()
            } else {
                format!(
                    "Multiple lock files detected ({}) — EAS Build infers the package manager from the lock file, so this is ambiguous.",
                    present_lockfiles.join(", ")
                )
            };
            push_project_diagnostic(
                out,
                pkg_json_path.to_path_buf(),
                RuleId::ExpoLockfile,
                sev,
                "expoLockfile",
                "lockfile",
                msg,
            );
        }
    }

    if let Some(sev) = is_rule_enabled(RuleId::ExpoMetroConfig) {
        for metro_name in [
            "metro.config.js",
            "metro.config.cjs",
            "metro.config.mjs",
            "metro.config.ts",
        ] {
            let Some((metro_path, metro_src)) =
                find_manifest_in_pkg(graph, &pkg.root_dir, metro_name)
            else {
                continue;
            };
            let has_expo_signal = [
                "expo/metro-config",
                "@sentry/react-native/metro",
                "getSentryExpoConfig",
                "posthog-react-native/metro",
                "getPostHogExpoConfig",
            ]
            .iter()
            .any(|sig| metro_src.contains(sig));
            if !has_expo_signal {
                push_project_diagnostic(
                    out,
                    metro_path,
                    RuleId::ExpoMetroConfig,
                    sev,
                    "expoMetroConfig",
                    metro_name,
                    "Your metro.config does not extend `expo/metro-config`.".to_string(),
                );
            }
            break;
        }
    }
}

fn check_expo_app_json_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let has_dynamic_app_config = [
        "app.config.ts",
        "app.config.js",
        "app.config.cjs",
        "app.config.mjs",
    ]
    .iter()
    .any(|n| find_manifest_in_pkg(graph, &pkg.root_dir, n).is_some());
    if has_dynamic_app_config {
        return;
    }

    let deps = &pkg.capability_gate.dependencies;
    let is_reanimated_v4 = deps
        .get("react-native-reanimated")
        .and_then(|v| parse_major_version(v))
        .is_some_and(|m| m >= 4)
        || deps.contains_key("react-native-worklets");

    for app_cfg_name in ["app.config.json", "app.json"] {
        let Some((app_path, app_src)) = find_manifest_in_pkg(graph, &pkg.root_dir, app_cfg_name)
        else {
            continue;
        };
        let Ok(app_val) = serde_json::from_str::<Value>(&strip_jsonc(app_src)) else {
            continue;
        };
        let Some(expo_obj) = app_val.get("expo").and_then(Value::as_object) else {
            continue;
        };

        if is_reanimated_v4
            && expo_obj.get("newArchEnabled").and_then(Value::as_bool) == Some(false)
            && let Some(sev) = is_rule_enabled(RuleId::ExpoReanimatedV4RequiresNewArch)
        {
            push_project_diagnostic(
                out,
                app_path.clone(),
                RuleId::ExpoReanimatedV4RequiresNewArch,
                sev,
                "expoReanimatedV4RequiresNewArch",
                "newArchEnabled",
                "react-native-reanimated v4 supports only the New Architecture, but `newArchEnabled: false` is set in your app config.".to_string(),
            );
        }

        if expo_obj
            .get("updates")
            .and_then(Value::as_object)
            .and_then(|u| u.get("disableAntiBrickingMeasures"))
            .and_then(Value::as_bool)
            == Some(true)
            && let Some(sev) = is_rule_enabled(RuleId::ExpoUpdatesNoUnsafeProductionConfig)
        {
            push_project_diagnostic(
                out,
                app_path,
                RuleId::ExpoUpdatesNoUnsafeProductionConfig,
                sev,
                "expoUpdatesNoUnsafeProductionConfig",
                "disableAntiBrickingMeasures",
                "`updates.disableAntiBrickingMeasures: true` disables expo-updates' recovery safeguards and can permanently brick installed apps.".to_string(),
            );
        }
        break;
    }
}

fn check_expo_gitignore_and_env_local<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    pkg_json_path: &Path,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let gitignore_src = find_manifest_in_pkg(graph, &pkg.root_dir, ".gitignore")
        .map(|(_, s)| s)
        .unwrap_or("");
    if let Some(sev) = is_rule_enabled(RuleId::ExpoEnvLocalNotGitignored) {
        let has_env_local = [
            ".env.local",
            ".env.development.local",
            ".env.production.local",
            ".env.test.local",
        ]
        .iter()
        .any(|n| find_manifest_in_pkg(graph, &pkg.root_dir, n).is_some());
        if has_env_local
            && !gitignore_src.contains(".env*.local")
            && !gitignore_src.contains(".env.local")
        {
            push_project_diagnostic(
                out,
                pkg_json_path.to_path_buf(),
                RuleId::ExpoEnvLocalNotGitignored,
                sev,
                "expoEnvLocalNotGitignored",
                ".env.local",
                "Local environment file (.env*.local) is not ignored by Git.".to_string(),
            );
        }
    }

    if let Some(sev) = is_rule_enabled(RuleId::ExpoGitignore)
        && !gitignore_src.is_empty()
    {
        let ignores_expo_dir = gitignore_src
            .lines()
            .any(|l| matches!(l.trim(), ".expo" | ".expo/" | "/.expo" | "/.expo/"));
        let unanchored_native_dirs = gitignore_src
            .lines()
            .any(|l| matches!(l.trim(), "android" | "ios" | "android/" | "ios/"))
            && graph.manifests.keys().any(|p| {
                let s = p.to_string_lossy();
                s.contains("modules/") && (s.contains("/android/") || s.contains("/ios/"))
            });
        if !ignores_expo_dir || unanchored_native_dirs {
            let msg = if unanchored_native_dirs {
                "The native `ios`/`android` directories of a local Expo module under `modules/` are gitignored; anchor `/ios` and `/android` in .gitignore.".to_string()
            } else {
                "`.expo/` state directory is not ignored in `.gitignore`; add `.expo/` to `.gitignore`.".to_string()
            };
            push_project_diagnostic(
                out,
                pkg.root_dir.join(".gitignore"),
                RuleId::ExpoGitignore,
                sev,
                "expoGitignore",
                ".gitignore",
                msg,
            );
        }
    }
}

fn push_project_diagnostic(
    out: &mut Vec<Diagnostic>,
    file: PathBuf,
    rule: RuleId,
    severity: RuleSeverity,
    message_id: &'static str,
    target_name: &str,
    message: String,
) {
    out.push(
        Diagnostic::new(
            rule,
            file,
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
            target_name,
            message,
        )
        .with_severity(severity)
        .with_message_id(message_id),
    );
}

fn parse_major_version(spec: &str) -> Option<u32> {
    let trimmed = spec.trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']);
    let major_str = trimmed.split('.').next()?;
    major_str.parse::<u32>().ok()
}

fn parse_rn_minor_version(spec: &str) -> Option<u32> {
    let trimmed = spec.trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']);
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    if major != 0 {
        return Some(100);
    }
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some(minor)
}

fn has_enable_babel_runtime_version(babel_src: &str) -> bool {
    for line in babel_src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(idx) = trimmed.find("enableBabelRuntime") {
            let after = trimmed
                .get(idx + "enableBabelRuntime".len()..)
                .unwrap_or_default();
            let after_colon = after.trim_start_matches(['"', '\'', ' ', ':']);
            if after_colon.starts_with('\'') || after_colon.starts_with('"') {
                return true;
            }
        }
    }
    false
}

fn extract_static_babel_plugins(babel_src: &str) -> Option<Vec<String>> {
    let plugins_idx = babel_src.find("plugins")?;
    let after = &babel_src[plugins_idx..];
    let open_bracket = after.find('[')?;
    let inside = &after[open_bracket + 1..];
    if inside.contains("...") {
        return None;
    }
    let mut out = Vec::new();
    let mut depth = 1_i32;
    let mut bytes = inside.as_bytes().iter().copied().enumerate();
    let mut item_has_pushed = false;

    while let Some((idx, b)) = bytes.next() {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            b',' if depth == 1 => {
                item_has_pushed = false;
            }
            b'\'' | b'"' if !item_has_pushed => {
                let quote = b;
                let start = idx + 1;
                let mut end = start;
                for (next_idx, next_b) in bytes.by_ref() {
                    if next_b == quote {
                        end = next_idx;
                        break;
                    }
                }
                if end > start
                    && let Some(s) = inside.get(start..end)
                {
                    out.push(s.to_string());
                    item_has_pushed = true;
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn check_gradle_release_shrinking(gradle_src: &str) -> (bool, bool) {
    let mut in_release = false;
    let mut minify: Option<bool> = None;
    let mut shrink: Option<bool> = None;

    for raw_line in gradle_src.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.contains("println(") {
            continue;
        }
        if is_gradle_release_block_opener(line) {
            in_release = true;
        }
        if !in_release {
            continue;
        }
        if line.contains("minifyEnabled") || line.contains("isMinifyEnabled") {
            minify = parse_trailing_gradle_bool(line);
        }
        if line.contains("shrinkResources") || line.contains("isShrinkResources") {
            shrink = parse_trailing_gradle_bool(line);
        }
    }

    (minify == Some(false), shrink == Some(false))
}

fn is_gradle_release_block_opener(line: &str) -> bool {
    line.starts_with("release")
        || line.contains("release {")
        || line.contains("getByName(\"release\")")
        || line.contains("named(\"release\")")
}

fn parse_trailing_gradle_bool(line: &str) -> Option<bool> {
    if line.ends_with("false") {
        Some(false)
    } else if line.ends_with("true") {
        Some(true)
    } else {
        None
    }
}
