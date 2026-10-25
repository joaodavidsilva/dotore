//! Package-level structural evaluators (`rs-structure-orphan-module-file`,
//! `rs-structure-unreferenced-feature`, and `rs-structure-near-duplicate-function`).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Component, Path, PathBuf},
};

use dotore_core::{
    ByteSpan, Diagnostic, ExtractedFile, FileContext, RuleId, SourceLoc, WorkspacePackage,
    compute_line_starts,
};
use toml::Value;

use crate::{
    cargo_health::find_toml_key_span,
    matchers::RsCandidateFinding,
    structure::{CfgFeatureRefIr, ExternalModDeclIr},
};

/// Evaluates package-level structural rules (`rs-structure-orphan-module-file`,
/// `rs-structure-unreferenced-feature`, and `rs-structure-near-duplicate-function`).
pub(crate) fn evaluate_package_structure_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let _ = Option::<CfgFeatureRefIr>::None;
    for (file_path, finding) in collect_orphan_module_findings(package, files) {
        if let Some(file) = files.iter().find(|f| f.path == file_path) {
            crate::rules::emit_rs_finding_if_active_pub(
                file,
                &finding,
                &package.root_dir,
                &package.capability_gate,
                &package.config,
                enabled_rules,
                out,
            );
        }
    }

    evaluate_unreferenced_feature_rules(package, files, enabled_rules, out);

    for (file_path, finding) in
        crate::structure_duplication::collect_near_duplicate_function_findings(
            package,
            files,
            enabled_rules,
        )
    {
        if let Some(file) = files.iter().find(|f| f.path == file_path) {
            crate::rules::emit_rs_finding_if_active_pub(
                file,
                &finding,
                &package.root_dir,
                &package.capability_gate,
                &package.config,
                enabled_rules,
                out,
            );
        }
    }
}

fn collect_orphan_module_findings(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
) -> Vec<(PathBuf, RsCandidateFinding)> {
    let mut file_map: HashMap<String, (&ExtractedFile, &crate::ir::RsFileIr)> = HashMap::new();
    let mut scripted_names: HashSet<String> = HashSet::new();
    let mut included_rel_paths: HashSet<String> = HashSet::new();

    for file in files {
        let Some(rs_ir) = file.downcast_payload::<crate::ir::RsFileIr>() else {
            continue;
        };
        if !rs_ir.valid_syntax || rs_ir.structure_ir.has_macro_mod_decl {
            return Vec::new();
        }
        for s in &rs_ir.structure_ir.scripted_rs_filenames {
            scripted_names.insert(s.clone());
        }
        let norm_path = normalize_rel_path(&file.path, &package.root_dir);
        for inc in &rs_ir.structure_ir.included_paths {
            if let Some(resolved_inc) = resolve_relative_file(&norm_path, inc) {
                included_rel_paths.insert(resolved_inc);
            }
        }
        file_map.insert(norm_path, (file, rs_ir));
    }

    let mut roots: Vec<String> = file_map
        .keys()
        .filter(|p| {
            *p == "src/lib.rs"
                || *p == "src/main.rs"
                || *p == "lib.rs"
                || *p == "main.rs"
                || p.starts_with("src/bin/")
        })
        .cloned()
        .collect();
    if roots.is_empty() {
        return Vec::new();
    }

    let mut reached: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for r in roots.drain(..) {
        if reached.insert(r.clone()) {
            queue.push_back(r);
        }
    }

    while let Some(curr) = queue.pop_front() {
        let Some((_, rs_ir)) = file_map.get(&curr) else {
            continue;
        };
        for decl in &rs_ir.structure_ir.external_mod_decls {
            let candidates = resolve_mod_decl_candidates(&curr, decl);
            let mut matched_any = false;
            for cand in candidates {
                if file_map.contains_key(&cand) {
                    matched_any = true;
                    enqueue_if_unreached(cand, &mut reached, &mut queue);
                }
            }
            if !matched_any {
                return Vec::new();
            }
        }
    }

    let mut out = Vec::new();
    let mut sorted_keys: Vec<&String> = file_map.keys().collect();
    sorted_keys.sort();
    for norm_path in sorted_keys {
        if !norm_path.starts_with("src/") || norm_path.starts_with("src/bin/") {
            continue;
        }
        if reached.contains(norm_path) || included_rel_paths.contains(norm_path) {
            continue;
        }
        let Some((file, _)) = file_map.get(norm_path) else {
            continue;
        };
        if file.file_context != FileContext::Production {
            continue;
        }
        if let Some(fname) = file.path.file_name().and_then(|n| n.to_str())
            && scripted_names.contains(fname)
        {
            continue;
        }
        let finding = RsCandidateFinding::new(
            RuleId::RsStructureOrphanModuleFile,
            None,
            norm_path.clone(),
            "rsStructureOrphanModuleFile",
            format!(
                "`{norm_path}` is not reached by any `mod` declaration in package `{}`; declare the module or remove the dead file.",
                package.name
            ),
            SourceLoc { line: 1, column: 1 },
            ByteSpan {
                start: 0,
                end: u32::try_from(file.source.len()).unwrap_or(0),
            },
        );
        out.push((file.path.clone(), finding));
    }
    out
}

fn normalize_rel_path(path: &Path, pkg_root: &Path) -> String {
    let stripped = if pkg_root != Path::new(".")
        && let Ok(rel) = path.strip_prefix(pkg_root)
    {
        rel
    } else {
        path
    };
    stripped
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

fn enqueue_if_unreached(
    cand: String,
    reached: &mut HashSet<String>,
    queue: &mut VecDeque<String>,
) {
    if reached.insert(cand.clone()) {
        queue.push_back(cand);
    }
}

fn resolve_relative_file(from_file: &str, rel_target: &str) -> Option<String> {
    let parent = Path::new(from_file).parent()?;
    Some(normalize_lexical_components(&parent.join(rel_target)))
}

fn normalize_lexical_components(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(os) => parts.push(os.to_string_lossy().into_owned()),
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    parts.join("/")
}

fn resolve_mod_decl_candidates(curr_file: &str, decl: &ExternalModDeclIr) -> Vec<String> {
    let curr_path = Path::new(curr_file);
    let file_name = curr_path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let stem = curr_path.file_stem().and_then(|n| n.to_str()).unwrap_or_default();
    let parent_dir = curr_path.parent().unwrap_or_else(|| Path::new(""));

    let mut base_dir = if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs") {
        parent_dir.to_path_buf()
    } else {
        parent_dir.join(stem)
    };
    for inline_seg in &decl.inline_mod_stack {
        base_dir = base_dir.join(inline_seg);
    }

    if let Some(explicit) = &decl.explicit_path {
        let mut out = vec![normalize_lexical_components(&base_dir.join(explicit))];
        let from_parent = normalize_lexical_components(&parent_dir.join(explicit));
        if !out.contains(&from_parent) {
            out.push(from_parent);
        }
        return out;
    }

    vec![
        normalize_lexical_components(&base_dir.join(format!("{}.rs", decl.name))),
        normalize_lexical_components(&base_dir.join(&decl.name).join("mod.rs")),
    ]
}

fn evaluate_unreferenced_feature_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let cargo_toml_src = package.capability_gate.dependencies.get("__manifest:Cargo.toml");
    let explicit_rule = enabled_rules
        .is_some_and(|list| list.contains(&RuleId::RsStructureUnreferencedFeature))
        || package
            .config
            .explicit_rule_override(RuleId::RsStructureUnreferencedFeature)
            .is_some();

    if cargo_toml_src.is_none() && !explicit_rule {
        return;
    }

    let mut read_features: HashSet<String> = HashSet::new();
    for file in files {
        if let Some(rs_ir) = file.downcast_payload::<crate::ir::RsFileIr>() {
            for r in &rs_ir.structure_ir.cfg_feature_refs {
                read_features.insert(r.feature.clone());
            }
        }
    }

    let mut declared_valid_features: HashSet<String> = HashSet::from(["default".to_string()]);
    if let Some(toml_str) = cargo_toml_src
        && let Ok(doc) = toml::from_str::<Value>(toml_str)
        && let Some(root_tbl) = doc.as_table()
    {
        let mut optional_deps: HashSet<String> = HashSet::new();
        if let Some(deps) = root_tbl.get("dependencies").and_then(Value::as_table) {
            for (dep_key, val) in deps {
                if val.as_table().and_then(|t| t.get("optional")).and_then(Value::as_bool)
                    == Some(true)
                {
                    optional_deps.insert(dep_key.clone());
                    declared_valid_features.insert(dep_key.clone());
                }
            }
        }

        if let Some(features_map) = root_tbl.get("features").and_then(Value::as_table) {
            let mut listed_by_other: HashSet<String> = HashSet::new();
            for (feat_name, activates_val) in features_map {
                declared_valid_features.insert(feat_name.clone());
                if let Some(arr) = activates_val.as_array() {
                    collect_plain_activated_features(arr, &mut listed_by_other);
                }
            }

            let manifest_path = resolve_package_manifest_path(package);
            let starts = compute_line_starts(toml_str);
            for (feat_name, activates_val) in features_map {
                let is_empty_activates = activates_val.as_array().is_none_or(Vec::is_empty);
                if feat_name == "default"
                    || optional_deps.contains(feat_name)
                    || !is_empty_activates
                    || listed_by_other.contains(feat_name)
                    || read_features.contains(feat_name)
                {
                    continue;
                }
                let (loc, span) = find_toml_key_span(toml_str, &starts, feat_name);
                crate::cargo_health::emit_manifest_diagnostic_if_active(
                    package,
                    &manifest_path,
                    toml_str,
                    RuleId::RsStructureUnreferencedFeature,
                    feat_name.clone(),
                    "rsStructureUnreferencedFeature",
                    format!(
                        "Package `{}` declares feature `{feat_name}` in [features], which no `cfg(feature = ...)` reads and which activates nothing.",
                        package.name
                    ),
                    loc,
                    span,
                    enabled_rules,
                    out,
                );
            }
        }
    }

    for file in files {
        let Some(rs_ir) = file.downcast_payload::<crate::ir::RsFileIr>() else {
            continue;
        };
        for r in &rs_ir.structure_ir.cfg_feature_refs {
            if !declared_valid_features.contains(&r.feature) {
                let finding = RsCandidateFinding::new(
                    RuleId::RsStructureUnreferencedFeature,
                    r.subject_name.clone(),
                    r.feature.clone(),
                    "rsStructureUnreferencedFeature",
                    format!(
                        "`cfg(feature = \"{}\")` references a feature not declared in `Cargo.toml` `[features]`.",
                        r.feature
                    ),
                    r.loc,
                    r.span,
                );
                crate::rules::emit_rs_finding_if_active_pub(
                    file,
                    &finding,
                    &package.root_dir,
                    &package.capability_gate,
                    &package.config,
                    enabled_rules,
                    out,
                );
            }
        }
    }
}

pub(crate) fn resolve_package_manifest_path(package: &WorkspacePackage) -> PathBuf {
    if let Some(p) = package
        .capability_gate
        .dependencies
        .get("__manifest_path:Cargo.toml")
    {
        return PathBuf::from(p);
    }
    if package.root_dir == Path::new(".") {
        PathBuf::from("Cargo.toml")
    } else {
        package.root_dir.join("Cargo.toml")
    }
}

fn collect_plain_activated_features(arr: &[Value], out: &mut HashSet<String>) {
    for entry in arr.iter().filter_map(Value::as_str) {
        if !entry.contains('/') && !entry.starts_with("dep:") {
            out.insert(entry.to_string());
        }
    }
}
