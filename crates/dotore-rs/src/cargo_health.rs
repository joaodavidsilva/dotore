//! Cargo manifest (`Cargo.toml`), lockfile (`Cargo.lock`), and `.cargo/config.toml` health detectors (`#57`).

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use dotore_core::{
    ByteSpan, Diagnostic, ExtractedFile, RuleId, SourceLoc, WorkspacePackage,
    compute_line_starts, map_rust_allow_lint_to_rules,
};
use toml::Value;

use crate::{
    cargo_health_refs::inspect_dependency_truth_for_package,
    matchers::loc_at,
    structure_package::resolve_package_manifest_path,
};

type TomlMap = toml::map::Map<String, Value>;

/// Evaluates all 11 `rs-cargo-*` rules for `package` and appends [`Diagnostic`]s to `out`.
pub(crate) fn evaluate_cargo_health_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let deps_map = &package.capability_gate.dependencies;
    let cargo_toml_opt = deps_map.get("__manifest:Cargo.toml");
    let cargo_lock_opt = deps_map.get("__manifest:Cargo.lock");
    let cargo_cfg_opt = deps_map.get("__manifest:.cargo/config.toml");

    if let Some(cargo_toml_src) = cargo_toml_opt {
        let manifest_path = resolve_package_manifest_path(package);
        evaluate_manifest_rules(
            package,
            &manifest_path,
            cargo_toml_src,
            cargo_lock_opt.is_some(),
            files,
            enabled_rules,
            out,
        );
    }

    let owns_workspace_files = deps_map
        .get("__owns_workspace_manifests")
        .is_none_or(|v| v == "true");

    if owns_workspace_files {
        if let Some(lock_src) = cargo_lock_opt {
            let lock_path = resolve_special_manifest_path(package, "__manifest_path:Cargo.lock", "Cargo.lock");
            evaluate_cargo_lock_rules(package, &lock_path, lock_src, enabled_rules, out);
        }
        if let Some(cfg_src) = cargo_cfg_opt {
            let cfg_path = resolve_special_manifest_path(
                package,
                "__manifest_path:.cargo/config.toml",
                ".cargo/config.toml",
            );
            evaluate_cargo_config_rustflags(package, &cfg_path, cfg_src, enabled_rules, out);
        }
    }
}

fn resolve_special_manifest_path(
    package: &WorkspacePackage,
    key: &str,
    default_rel: &str,
) -> PathBuf {
    if let Some(p) = package.capability_gate.dependencies.get(key) {
        return PathBuf::from(p);
    }
    if package.root_dir == Path::new(".") {
        PathBuf::from(default_rel)
    } else {
        package.root_dir.join(default_rel)
    }
}

/// Locates the 1-based [`SourceLoc`] and 0-based [`ByteSpan`] of a TOML key in `source`.
#[must_use]
pub(crate) fn find_toml_key_span(source: &str, starts: &[u32], key: &str) -> (SourceLoc, ByteSpan) {
    let mut byte_offset = 0_usize;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#')
            && let Some(after) = trimmed.strip_prefix(key)
            && after.trim_start().starts_with('=')
        {
            let lead_ws = line.len().saturating_sub(trimmed.len());
            let start = u32::try_from(byte_offset + lead_ws).unwrap_or(0);
            let end = start + u32::try_from(key.len()).unwrap_or(0);
            return (loc_at(starts, start), ByteSpan { start, end });
        }
        byte_offset += line.len() + 1;
    }
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan {
            start: 0,
            end: u32::try_from(source.lines().next().map_or(0, str::len)).unwrap_or(0),
        },
    )
}

#[derive(Clone, Copy)]
struct ReleaseProfileContext {
    produces_binary: bool,
    is_virtual_only: bool,
    has_bin_section: bool,
}

fn has_main_or_bin_source_file(package: &WorkspacePackage, files: &[ExtractedFile], is_virtual_only: bool) -> bool {
    files.iter().any(|f| {
        let s = f.path.to_string_lossy().replace('\\', "/");
        s == "src/main.rs" || s.ends_with("/src/main.rs") || s == "main.rs" || s.contains("/src/bin/")
    }) || (!is_virtual_only && package.root_dir.join("src/main.rs").is_file())
}

fn collect_all_manifest_dep_tables(root: &TomlMap) -> Vec<&TomlMap> {
    let mut all_dep_tables: Vec<&TomlMap> = Vec::new();
    for sec in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = root.get(sec).and_then(Value::as_table) {
            all_dep_tables.push(t);
        }
    }
    if let Some(ws_deps) = root
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|w| w.get("dependencies"))
        .and_then(Value::as_table)
    {
        all_dep_tables.push(ws_deps);
    }
    if let Some(targets) = root.get("target").and_then(Value::as_table) {
        for target_sec in targets.values().filter_map(Value::as_table) {
            for sec in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(t) = target_sec.get(sec).and_then(Value::as_table) {
                    all_dep_tables.push(t);
                }
            }
        }
    }
    all_dep_tables
}

fn evaluate_manifest_rules(
    package: &WorkspacePackage,
    manifest_path: &Path,
    cargo_toml_src: &str,
    has_lockfile: bool,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let Ok(doc) = toml::from_str::<Value>(cargo_toml_src) else {
        return;
    };
    let Some(root) = doc.as_table() else {
        return;
    };
    let starts = compute_line_starts(cargo_toml_src);
    let pkg_name = root
        .get("package")
        .and_then(Value::as_table)
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or(&package.name);

    let is_virtual_only = package
        .capability_gate
        .dependencies
        .get("__virtual_only")
        .is_some_and(|v| v == "true");
    let has_bin_section = root
        .get("bin")
        .and_then(Value::as_array)
        .is_some_and(|b| !b.is_empty());
    let produces_binary =
        has_bin_section || has_main_or_bin_source_file(package, files, is_virtual_only);
    let explicit_missing_lock = enabled_rules
        .is_some_and(|l| l.contains(&RuleId::RsCargoMissingLockfile))
        || package
            .config
            .explicit_rule_override(RuleId::RsCargoMissingLockfile)
            .is_some();
    if produces_binary
        && !has_lockfile
        && (!is_virtual_only || has_bin_section || explicit_missing_lock)
    {
        emit_manifest_diagnostic_if_active(
            package,
            manifest_path,
            cargo_toml_src,
            RuleId::RsCargoMissingLockfile,
            "Cargo.lock".to_string(),
            "rsCargoMissingLockfile",
            format!(
                "Package \"{pkg_name}\" produces a binary but no `Cargo.lock` exists at the workspace root."
            ),
            SourceLoc { line: 1, column: 1 },
            ByteSpan {
                start: 0,
                end: u32::try_from(cargo_toml_src.lines().next().map_or(0, str::len)).unwrap_or(0),
            },
            enabled_rules,
            out,
        );
    }

    for lints_tbl in [
        root.get("lints").and_then(Value::as_table),
        root.get("workspace")
            .and_then(Value::as_table)
            .and_then(|w| w.get("lints"))
            .and_then(Value::as_table),
    ]
    .into_iter()
    .flatten()
    {
        inspect_lints_table(package, manifest_path, cargo_toml_src, &starts, lints_tbl, enabled_rules, out);
    }

    inspect_release_profile_section(
        package,
        manifest_path,
        cargo_toml_src,
        &starts,
        root,
        ReleaseProfileContext {
            produces_binary,
            is_virtual_only,
            has_bin_section,
        },
        enabled_rules,
        out,
    );

    for table in collect_all_manifest_dep_tables(root) {
        for (key, val) in table {
            let (loc, span) = find_toml_key_span(cargo_toml_src, &starts, key);
            inspect_single_dep_declaration(
                package,
                manifest_path,
                cargo_toml_src,
                key,
                val,
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }

    if let Some(normal_deps) = root.get("dependencies").and_then(Value::as_table) {
        let dev_deps = root.get("dev-dependencies").and_then(Value::as_table);
        inspect_dependency_truth_for_package(
            package,
            manifest_path,
            cargo_toml_src,
            &starts,
            pkg_name,
            normal_deps,
            dev_deps,
            files,
            enabled_rules,
            out,
        );
    }
}

fn extract_lint_level(val: &Value) -> Option<&str> {
    val.as_str().or_else(|| {
        val.as_table()
            .and_then(|t| t.get("level"))
            .and_then(Value::as_str)
    })
}

fn inspect_lints_table(
    package: &WorkspacePackage,
    manifest_path: &Path,
    source: &str,
    starts: &[u32],
    lints_tbl: &TomlMap,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if let Some(clippy_map) = lints_tbl.get("clippy").and_then(Value::as_table) {
        for (key, setting) in clippy_map {
            if extract_lint_level(setting) != Some("allow") {
                continue;
            }
            let qualified = format!("clippy::{key}");
            let is_catalogued = !map_rust_allow_lint_to_rules(&qualified).is_empty()
                || RuleId::parse(&qualified).is_some()
                || matches!(
                    key.as_str(),
                    "all"
                        | "warnings"
                        | "correctness"
                        | "suspicious"
                        | "complexity"
                        | "perf"
                        | "style"
                        | "pedantic"
                        | "restriction"
                        | "cargo"
                );
            if !is_catalogued {
                continue;
            }
            let (loc, span) = find_toml_key_span(source, starts, key);
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoPermissiveLintTable,
                qualified.clone(),
                "rsCargoPermissiveLintTable",
                format!("Manifest lint table sets rule \"{qualified}\" to \"allow\"."),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }

    if let Some(rust_map) = lints_tbl.get("rust").and_then(Value::as_table) {
        for (key, setting) in rust_map {
            if extract_lint_level(setting) != Some("allow") {
                continue;
            }
            if !matches!(
                key.as_str(),
                "unsafe_code" | "unsafe_op_in_unsafe_fn" | "warnings" | "unused"
            ) {
                continue;
            }
            let (loc, span) = find_toml_key_span(source, starts, key);
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoPermissiveLintTable,
                key.clone(),
                "rsCargoPermissiveLintTable",
                format!("Manifest lint table sets rustc lint \"{key}\" to \"allow\"."),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Release profile inspector checks both debug symbols and overflow-checks settings"
)]
fn inspect_release_profile_section(
    package: &WorkspacePackage,
    manifest_path: &Path,
    source: &str,
    starts: &[u32],
    root: &TomlMap,
    ctx: ReleaseProfileContext,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let release_tbl = root
        .get("profile")
        .and_then(Value::as_table)
        .and_then(|p| p.get("release"))
        .and_then(Value::as_table);

    if let Some(settings) = release_tbl {
        let full_debug = settings.get("debug").is_some_and(|dbg| {
            dbg.as_bool() == Some(true)
                || dbg.as_integer() == Some(2)
                || dbg.as_str() == Some("full")
        });
        let stripped = settings.get("strip").is_some_and(|st| {
            st.as_bool() == Some(true)
                || matches!(st.as_str(), Some("symbols" | "debuginfo"))
        });
        if full_debug && !stripped {
            let (loc, span) = find_toml_key_span(source, starts, "debug");
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoReleaseDebugSymbols,
                "profile.release.debug".to_string(),
                "rsCargoReleaseDebugSymbols",
                "Release profile ships full debug info unstripped (`debug = true | 2 | \"full\"`), embedding build paths in the shipped binary.".to_string(),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }

    let explicit_overflow = enabled_rules
        .is_some_and(|l| l.contains(&RuleId::RsCargoUncheckedReleaseOverflow))
        || package
            .config
            .explicit_rule_override(RuleId::RsCargoUncheckedReleaseOverflow)
            .is_some();
    let has_release_section = release_tbl.is_some();
    if ctx.produces_binary
        && (!ctx.is_virtual_only || ctx.has_bin_section || has_release_section || explicit_overflow)
    {
        let enabled = release_tbl.is_some_and(|s| {
            s.get("overflow-checks").and_then(Value::as_bool) == Some(true)
        });
        let ws_enabled = package
            .capability_gate
            .dependencies
            .get("__workspace_release_overflow_checks")
            .is_some_and(|v| v == "true");

        if !enabled && !ws_enabled {
            let (loc, span) = find_toml_key_span(source, starts, "overflow-checks");
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoUncheckedReleaseOverflow,
                "profile.release.overflow-checks".to_string(),
                "rsCargoUncheckedReleaseOverflow",
                "Release profile compiles without `overflow-checks = true`, allowing integer overflow to wrap silently in the shipped binary.".to_string(),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Dependency declaration inspector checks path, wildcard, and git rules in one pass"
)]
fn inspect_single_dep_declaration(
    package: &WorkspacePackage,
    manifest_path: &Path,
    source: &str,
    key: &str,
    val: &Value,
    loc: SourceLoc,
    span: ByteSpan,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    match val {
        Value::String(ver_str) => {
            if ver_str.trim() == "*" {
                emit_manifest_diagnostic_if_active(
                    package,
                    manifest_path,
                    source,
                    RuleId::RsCargoUnboundedWildcardDependency,
                    key.to_string(),
                    "rsCargoUnboundedWildcardDependency",
                    format!(
                        "Registry dependency \"{key}\" uses an unbounded \"*\" wildcard version requirement."
                    ),
                    loc,
                    span,
                    enabled_rules,
                    out,
                );
            }
        }
        Value::Table(spec) => {
            if spec.get("workspace").and_then(Value::as_bool) == Some(true) {
                return;
            }
            let path_opt = spec.get("path").and_then(Value::as_str);
            let git_opt = spec.get("git").and_then(Value::as_str);
            let ver_opt = spec.get("version").and_then(Value::as_str);

            if let Some(dep_path) = path_opt
                && path_dep_leaves_workspace(package, dep_path)
            {
                emit_manifest_diagnostic_if_active(
                    package,
                    manifest_path,
                    source,
                    RuleId::RsCargoPathDepOutsideWorkspace,
                    key.to_string(),
                    "rsCargoPathDepOutsideWorkspace",
                    format!("Path dependency \"{key}\" resolves outside the workspace."),
                    loc,
                    span,
                    enabled_rules,
                    out,
                );
            }

            if path_opt.is_none()
                && git_opt.is_none()
                && ver_opt.is_some_and(|v| v.trim() == "*")
            {
                emit_manifest_diagnostic_if_active(
                    package,
                    manifest_path,
                    source,
                    RuleId::RsCargoUnboundedWildcardDependency,
                    key.to_string(),
                    "rsCargoUnboundedWildcardDependency",
                    format!(
                        "Registry dependency \"{key}\" uses an unbounded \"*\" wildcard version requirement."
                    ),
                    loc,
                    span,
                    enabled_rules,
                    out,
                );
            }

            if path_opt.is_none()
                && let Some(git_url) = git_opt
            {
                let rev_opt = spec.get("rev").and_then(Value::as_str);
                let has_branch_or_tag = spec.get("branch").is_some() || spec.get("tag").is_some();
                let valid_rev_field = !has_branch_or_tag
                    && rev_opt.is_some_and(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()));
                let valid_url_rev = !has_branch_or_tag && url_has_full_git_rev(git_url);
                if !valid_rev_field && !valid_url_rev {
                    emit_manifest_diagnostic_if_active(
                        package,
                        manifest_path,
                        source,
                        RuleId::RsCargoUnpinnedGitDependency,
                        key.to_string(),
                        "rsCargoUnpinnedGitDependency",
                        format!(
                            "Git dependency \"{key}\" is not pinned to a full 40-character commit revision SHA (`rev = \"...\"`)."
                        ),
                        loc,
                        span,
                        enabled_rules,
                        out,
                    );
                }
            }
        }
        Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_) | Value::Array(_) => {}
    }
}

fn path_dep_leaves_workspace(package: &WorkspacePackage, dep_path: &str) -> bool {
    let package_root = &package.root_dir;
    let ws_root = package
        .capability_gate
        .dependencies
        .get("__workspace_root")
        .map(PathBuf::from);
    let p = Path::new(dep_path);
    if p.is_absolute() {
        let root_to_check = ws_root.as_deref().unwrap_or(package_root);
        return !root_to_check.is_absolute() || !p.starts_with(root_to_check);
    }

    let rel_pkg = ws_root
        .as_deref()
        .and_then(|ws| package_root.strip_prefix(ws).ok())
        .unwrap_or(package_root.as_path());

    let mut pkg_depth = 0_isize;
    if !rel_pkg.is_absolute() && rel_pkg != Path::new(".") {
        for comp in rel_pkg.components() {
            if let Component::Normal(_) = comp {
                pkg_depth += 1;
            }
        }
    }

    let mut depth = pkg_depth;
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    false
}

fn url_has_full_git_rev(url: &str) -> bool {
    let Some((_, query_and_frag)) = url.split_once('?') else {
        return false;
    };
    let query = query_and_frag.split('#').next().unwrap_or_default();
    let mut params = query.split('&');
    let Some(first) = params.next() else {
        return false;
    };
    if params.next().is_some() {
        return false;
    }
    let Some(("rev", rev)) = first.split_once('=') else {
        return false;
    };
    rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

fn evaluate_cargo_lock_rules(
    package: &WorkspacePackage,
    lock_path: &Path,
    lock_src: &str,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let Ok(doc) = toml::from_str::<Value>(lock_src) else {
        return;
    };
    let Some(entries) = doc.get("package").and_then(Value::as_array) else {
        return;
    };
    let starts = compute_line_starts(lock_src);
    let explicit_rule = enabled_rules
        .is_some_and(|l| l.contains(&RuleId::RsCargoDuplicateMajorVersions))
        || package
            .config
            .explicit_rule_override(RuleId::RsCargoDuplicateMajorVersions)
            .is_some();

    let mut incoming_by_name_ver: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut incoming_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in entries.iter().filter_map(Value::as_table) {
        let Some(req_name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        if let Some(deps) = entry.get("dependencies").and_then(Value::as_array) {
            for dep in deps.iter().filter_map(Value::as_str) {
                let mut words = dep.split_whitespace();
                let Some(dep_name) = words.next() else {
                    continue;
                };
                incoming_by_name
                    .entry(dep_name.to_string())
                    .or_default()
                    .push(req_name.to_string());
                if let Some(ver) = words.next()
                    && ver.starts_with(|c: char| c.is_ascii_digit())
                {
                    incoming_by_name_ver
                        .entry((dep_name.to_string(), ver.to_string()))
                        .or_default()
                        .push(req_name.to_string());
                }
            }
        }
    }

    let mut by_crate: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in entries.iter().filter_map(Value::as_table) {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        if !explicit_rule
            && is_proc_macro_only_version(name, version, &incoming_by_name_ver, &incoming_by_name)
        {
            continue;
        }
        let versions = by_crate.entry(name.to_string()).or_default();
        if !versions.iter().any(|v| v == version) {
            versions.push(version.to_string());
        }
    }

    for (name, mut versions) in by_crate {
        if versions.len() < 2 {
            continue;
        }
        versions.sort();
        let buckets: BTreeSet<String> = versions
            .iter()
            .filter_map(|ver| semver_compatibility_bucket(ver))
            .collect();
        if buckets.len() < 2 {
            continue;
        }
        let (loc, span) = find_toml_key_span(lock_src, &starts, "name");
        emit_manifest_diagnostic_if_active(
            package,
            lock_path,
            lock_src,
            RuleId::RsCargoDuplicateMajorVersions,
            name.clone(),
            "rsCargoDuplicateMajorVersions",
            format!(
                "Crate \"{name}\" is resolved with incompatible major versions {} in `Cargo.lock`.",
                versions.join(", ")
            ),
            loc,
            span,
            enabled_rules,
            out,
        );
    }
}

fn is_proc_macro_only_version(
    name: &str,
    version: &str,
    incoming_by_name_ver: &BTreeMap<(String, String), Vec<String>>,
    incoming_by_name: &BTreeMap<String, Vec<String>>,
) -> bool {
    let Some(requirers) = incoming_by_name_ver
        .get(&(name.to_string(), version.to_string()))
        .or_else(|| incoming_by_name.get(name))
    else {
        return false;
    };
    !requirers.is_empty()
        && requirers.iter().all(|req| {
            req.ends_with("-derive")
                || req.ends_with("_derive")
                || req.ends_with("-derive2")
                || req.ends_with("-macro")
                || req.ends_with("-macros")
                || req.ends_with("_macros")
                || req.ends_with("-impl")
                || matches!(
                    req.as_str(),
                    "attribute-derive" | "displaydoc" | "manyhow" | "synstructure"
                )
        })
}

fn semver_compatibility_bucket(version: &str) -> Option<String> {
    let core = version.split(['+', '-']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?;
    if major.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if major != "0" {
        return Some(major.to_string());
    }
    let minor = parts.next().unwrap_or("0");
    if minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if minor != "0" {
        return Some(format!("0.{minor}"));
    }
    let patch = parts.next().unwrap_or("0");
    Some(format!("0.0.{patch}"))
}

fn evaluate_cargo_config_rustflags(
    package: &WorkspacePackage,
    cfg_path: &Path,
    cfg_src: &str,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let Ok(doc) = toml::from_str::<Value>(cfg_src) else {
        return;
    };
    let Some(root) = doc.as_table() else {
        return;
    };
    let starts = compute_line_starts(cfg_src);
    let mut carriers = Vec::new();
    if let Some(build_tbl) = root.get("build").and_then(Value::as_table)
        && let Some(rf) = build_tbl.get("rustflags")
    {
        carriers.push(rf);
    }
    if let Some(targets_tbl) = root.get("target").and_then(Value::as_table) {
        for t in targets_tbl.values().filter_map(Value::as_table) {
            if let Some(rf) = t.get("rustflags") {
                carriers.push(rf);
            }
        }
    }

    let (loc, span) = find_toml_key_span(cfg_src, &starts, "rustflags");
    for rf_val in carriers {
        let args = extract_rustflag_arguments(rf_val);
        for flag in match_neutralizing_rustflags(&args) {
            emit_manifest_diagnostic_if_active(
                package,
                cfg_path,
                cfg_src,
                RuleId::RsCargoPermissiveRustflags,
                flag.to_string(),
                "rsCargoPermissiveRustflags",
                format!(
                    "Workspace rustflags carry \"{flag}\", which disables compiler or lint checks across builds."
                ),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }
}

fn extract_rustflag_arguments(val: &Value) -> Vec<&str> {
    match val {
        Value::Array(entries) => entries.iter().filter_map(Value::as_str).collect(),
        Value::String(joined) => joined.split_whitespace().collect(),
        Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_) | Value::Table(_) => Vec::new(),
    }
}

fn match_neutralizing_rustflags(arguments: &[&str]) -> Vec<&'static str> {
    let mut matched = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        let next = arguments.get(index + 1).copied().unwrap_or_default();
        let (flag, consumed) = match argument {
            "--cap-lints" if next == "allow" => (Some("--cap-lints allow"), 2),
            "--cap-lints=allow" => (Some("--cap-lints allow"), 1),
            "-A" | "--allow" if next == "warnings" => (Some("-A warnings"), 2),
            "-Awarnings" | "--allow=warnings" => (Some("-A warnings"), 1),
            "-C" | "--codegen" if disables_overflow_checks(next) => {
                (Some("-C overflow-checks=off"), 2)
            }
            _ => {
                let joined = argument
                    .strip_prefix("-C")
                    .or_else(|| argument.strip_prefix("--codegen="));
                match joined {
                    Some(setting) if disables_overflow_checks(setting) => {
                        (Some("-C overflow-checks=off"), 1)
                    }
                    _ => (None, 1),
                }
            }
        };
        if let Some(flag) = flag {
            matched.push(flag);
        }
        index += consumed;
    }
    matched
}

fn disables_overflow_checks(setting: &str) -> bool {
    setting.split_once('=').is_some_and(|(key, value)| {
        key == "overflow-checks" && matches!(value, "off" | "false" | "no" | "n" | "0")
    })
}

/// Emits a manifest/lockfile/config [`Diagnostic`] if `rule` is active and not suppressed.
#[expect(
    clippy::too_many_arguments,
    reason = "Manifest diagnostic builder takes package context, file path, source, rule metadata, span, and output buffer"
)]
pub(crate) fn emit_manifest_diagnostic_if_active(
    package: &WorkspacePackage,
    manifest_path: &Path,
    manifest_source: &str,
    rule: RuleId,
    target_name: String,
    message_id: &'static str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if package.config.is_file_ignored(manifest_path, &package.root_dir) {
        return;
    }
    if let Some(explicit_list) = enabled_rules
        && !explicit_list.contains(&rule)
    {
        return;
    }
    let has_explicit_cli_rule = enabled_rules.is_some_and(|list| list.contains(&rule));
    if package
        .config
        .is_overridden_for_file(rule, manifest_path, &package.root_dir)
        && !has_explicit_cli_rule
    {
        return;
    }
    let meta = rule.metadata();
    if !has_explicit_cli_rule && !package.capability_gate.allows_rule(meta) {
        return;
    }
    let Some(severity) = (if has_explicit_cli_rule {
        Some(package.config.effective_severity(rule).unwrap_or(meta.default_severity))
    } else {
        package.config.effective_severity(rule)
    }) else {
        return;
    };

    if package.config.respect_inline_disables
        && is_toml_line_suppressed(manifest_source, loc.line, rule)
    {
        return;
    }

    if out
        .iter()
        .any(|d| d.file == manifest_path && d.rule == rule && d.span == span && d.target_name == target_name)
    {
        return;
    }

    out.push(
        Diagnostic::builder(rule, manifest_path, loc, span, target_name, message)
            .with_severity(severity)
            .with_message_id(message_id),
    );
}

fn is_toml_line_suppressed(source: &str, line_1based: u32, rule: RuleId) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let idx = (line_1based.saturating_sub(1)) as usize;
    for check_idx in [Some(idx), idx.checked_sub(1)].into_iter().flatten() {
        let Some(line) = lines.get(check_idx) else {
            continue;
        };
        let Some((_, comment)) = line.split_once('#') else {
            continue;
        };
        let trimmed = comment.trim();
        if (trimmed.contains("dotore-disable") || trimmed.contains("rust-doctor-disable"))
            && (trimmed.contains(rule.as_str())
                || rule
                    .metadata()
                    .legacy_aliases
                    .iter()
                    .any(|alias| trimmed.contains(alias))
                || (!trimmed.contains("rs-") && !trimmed.contains("rust_doctor::")))
        {
            return true;
        }
    }
    false
}
