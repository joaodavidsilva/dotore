//! Cross-file `no-barrel-import` evaluation and barrel re-export path resolution.
use std::{
    collections::{BTreeSet, HashSet},
    path::{Component, Path, PathBuf},
};

use crate::{
    config::{Capability, CapabilityGate},
    graph::ProjectGraph,
    ir::{FileIr, types::ImportBindingIr},
    matchers::make_diag_for_subject,
    rules::{Diagnostic, RuleId, RuleSeverity},
};

/// Evaluates `no-barrel-import` across the [`ProjectGraph`] module graph.
pub(crate) fn evaluate_barrel_imports<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    gate: &CapabilityGate,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if is_active(RuleId::NoBarrelImport).is_none() || is_barrel_import_exempt_file(file) {
        return;
    }
    let path_str = file.path.to_string_lossy().replace('\\', "/");
    let is_rn_target = (gate.has(Capability::ReactNative) || gate.has(Capability::Expo))
        && !path_str.contains(".web.");

    for imp in &file.module.imports {
        if let Some(diag) = check_single_barrel_import(graph, file, imp, is_rn_target) {
            out.push(diag);
            return;
        }
    }
}

fn is_barrel_import_exempt_file(file: &FileIr) -> bool {
    if file.module.is_aggregation_barrel {
        return true;
    }
    let path_str = file.path.to_string_lossy().replace('\\', "/");
    path_str.ends_with(".d.ts")
        || path_str.ends_with(".d.mts")
        || path_str.ends_with(".d.cts")
        || path_str.contains(".server.")
}

fn check_single_barrel_import(
    graph: &ProjectGraph,
    file: &FileIr,
    imp: &crate::ir::types::ImportDeclIr,
    is_rn_target: bool,
) -> Option<Diagnostic> {
    if imp.is_type_only || !imp.source.starts_with('.') {
        return None;
    }
    let runtime_bindings: Vec<_> = imp
        .bindings
        .iter()
        .filter(|b| !b.is_type_only && !b.is_namespace)
        .collect();
    if runtime_bindings.is_empty()
        || !runtime_bindings
            .iter()
            .any(|b| b.has_runtime_value_reference)
    {
        return None;
    }

    let barrel_idx = graph.resolve_relative_import(&file.path, &imp.source)?;
    let barrel_file = graph.files.get(barrel_idx)?;
    if !is_barrel_index_file(barrel_file)
        || distinct_barrel_sources(barrel_file) <= 1
        || consumes_every_runtime_export(barrel_file, &runtime_bindings)
    {
        return None;
    }

    let mut direct_sources = BTreeSet::new();
    for b in &runtime_bindings {
        if let Some(target_path) = resolve_barrel_export_file_path(
            graph,
            barrel_idx,
            &b.imported_name,
            &mut HashSet::new(),
        ) {
            direct_sources.insert(create_relative_import_source(&file.path, &target_path));
        }
    }

    let message = format_barrel_import_message(&direct_sources, is_rn_target);
    Some(make_diag_for_subject(
        RuleId::NoBarrelImport,
        file.path.clone(),
        None,
        "noBarrelImport",
        imp.source.clone(),
        message,
        imp.loc,
        imp.span,
    ))
}

fn format_barrel_import_message(direct_sources: &BTreeSet<String>, is_rn_target: bool) -> String {
    let cost_sentence = if is_rn_target {
        "This ships extra code in your app bundle & slows startup."
    } else {
        "This ships extra code to your users & slows page load."
    };

    if direct_sources.len() == 1 {
        let only = direct_sources.iter().next().map_or("", String::as_str);
        format!("{cost_sentence} Import directly from \"{only}\".")
    } else if direct_sources.len() > 1 {
        let joined = direct_sources
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{cost_sentence} Import directly from: {joined}.")
    } else {
        "Importing from an index file pulls in extra code. Import directly from the source file instead.".to_string()
    }
}

fn is_barrel_index_file(file: &FileIr) -> bool {
    let Some(file_name) = file.path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        file_name,
        "index.ts"
            | "index.tsx"
            | "index.js"
            | "index.jsx"
            | "index.mts"
            | "index.mjs"
            | "index.cts"
            | "index.cjs"
    ) && file.module.is_aggregation_barrel
        && !file.module.exports.is_empty()
}

fn distinct_barrel_sources(barrel_file: &FileIr) -> usize {
    let mut sources = HashSet::new();
    for exp in &barrel_file.module.exports {
        if let Some(src) = &exp.from_source {
            sources.insert(src.as_str());
        } else {
            let local = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
            for imp in &barrel_file.module.imports {
                if imp.bindings.iter().any(|b| b.local_name == local) {
                    sources.insert(imp.source.as_str());
                }
            }
        }
    }
    sources.len()
}

fn consumes_every_runtime_export(
    barrel_file: &FileIr,
    runtime_bindings: &[&ImportBindingIr],
) -> bool {
    if barrel_file
        .module
        .exports
        .iter()
        .any(|e| e.is_namespace_re_export && e.name == "*")
    {
        return false;
    }
    let imported_names: HashSet<&str> = runtime_bindings
        .iter()
        .map(|b| b.imported_name.as_str())
        .collect();
    barrel_file
        .module
        .exports
        .iter()
        .all(|exp| exp.is_type_only || imported_names.contains(exp.name.as_str()))
}

fn resolve_barrel_export_file_path(
    graph: &ProjectGraph,
    barrel_idx: usize,
    exported_name: &str,
    visited: &mut HashSet<usize>,
) -> Option<PathBuf> {
    if !visited.insert(barrel_idx) {
        return None;
    }
    let barrel_file = graph.files.get(barrel_idx)?;

    for exp in &barrel_file.module.exports {
        if exp.name == exported_name {
            return resolve_named_barrel_export_target(graph, barrel_file, exp, visited);
        }
    }

    if exported_name == "default" {
        return None;
    }

    resolve_star_barrel_export_path(graph, barrel_file, exported_name, visited)
}

fn resolve_named_barrel_export_target(
    graph: &ProjectGraph,
    barrel_file: &FileIr,
    exp: &crate::ir::types::ExportDeclIr,
    visited: &mut HashSet<usize>,
) -> Option<PathBuf> {
    let (target_spec, target_imported_name) = if let Some(src) = &exp.from_source {
        let orig = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
        (src.as_str(), orig)
    } else {
        let local = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
        barrel_file.module.imports.iter().find_map(|imp| {
            imp.bindings
                .iter()
                .find(|b| b.local_name == local)
                .map(|b| (imp.source.as_str(), b.imported_name.as_str()))
        })?
    };

    let target_idx = graph.resolve_relative_import(&barrel_file.path, target_spec)?;
    let target_file = graph.files.get(target_idx)?;
    if is_barrel_index_file(target_file)
        && let Some(nested) =
            resolve_barrel_export_file_path(graph, target_idx, target_imported_name, visited)
    {
        return Some(nested);
    }
    Some(target_file.path.clone())
}

fn resolve_star_barrel_export_path(
    graph: &ProjectGraph,
    barrel_file: &FileIr,
    exported_name: &str,
    visited: &HashSet<usize>,
) -> Option<PathBuf> {
    let mut star_matches = Vec::new();
    for exp in &barrel_file.module.exports {
        if !exp.is_namespace_re_export || exp.name != "*" {
            continue;
        }
        let Some(src) = &exp.from_source else {
            continue;
        };
        let Some(target_idx) = graph.resolve_relative_import(&barrel_file.path, src) else {
            continue;
        };
        let Some(target_file) = graph.files.get(target_idx) else {
            continue;
        };
        if is_barrel_index_file(target_file) {
            let mut sub_visited: HashSet<usize> = visited.iter().copied().collect();
            if let Some(nested) =
                resolve_barrel_export_file_path(graph, target_idx, exported_name, &mut sub_visited)
            {
                star_matches.push(nested);
            }
        } else if target_file
            .module
            .exports
            .iter()
            .any(|e| e.name == exported_name)
        {
            star_matches.push(target_file.path.clone());
        }
    }

    star_matches.dedup();
    (star_matches.len() == 1).then(|| star_matches.remove(0))
}

fn create_relative_import_source(from_file: &Path, target_file: &Path) -> String {
    let from_dir = from_file.parent().unwrap_or_else(|| Path::new(""));
    let stripped_target = strip_module_extension_and_index(target_file);
    let rel = relative_path_between_dirs(from_dir, &stripped_target);
    if rel.starts_with("../") || rel.starts_with("./") {
        rel
    } else {
        format!("./{rel}")
    }
}

fn strip_module_extension_and_index(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy().replace('\\', "/");
    let without_ext = [
        ".d.ts", ".d.mts", ".d.cts", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts",
    ]
    .iter()
    .find_map(|ext| raw.strip_suffix(ext))
    .unwrap_or(&raw);
    let without_index = without_ext.strip_suffix("/index").unwrap_or(without_ext);
    PathBuf::from(without_index)
}

fn relative_path_between_dirs(from_dir: &Path, to_path: &Path) -> String {
    let from_comps: Vec<_> = from_dir
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    let to_comps: Vec<_> = to_path
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();

    let common = from_comps
        .iter()
        .zip(to_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut parts = Vec::with_capacity((from_comps.len() - common) + (to_comps.len() - common));
    for _ in common..from_comps.len() {
        parts.push("..".to_string());
    }
    for comp in to_comps.get(common..).unwrap_or_default() {
        parts.push(comp.as_os_str().to_string_lossy().to_string());
    }
    parts.join("/")
}
