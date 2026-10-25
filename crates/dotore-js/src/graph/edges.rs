//! Module edge construction and external package consumption tracking for [`super::ProjectGraph`].

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::ir::FileIr;

use super::resolution::{
    CompiledPathMapping, EdgeSymbol, IndexedTargetFile, ModuleEdge, PackageManifestInfo,
    resolve_specifier_to_target_indices,
};

const BUILTIN_MODULES: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

pub(super) fn build_module_edges(
    files: &[FileIr],
    targets: &[IndexedTargetFile],
    platform_siblings: &HashMap<usize, Vec<usize>>,
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
    expo_plugin_specs: &[(PathBuf, String)],
) -> (Vec<ModuleEdge>, HashSet<String>) {
    let mut edges = Vec::new();
    let mut consumed_packages = HashSet::new();

    for (source_idx, file) in files.iter().enumerate() {
        for imp in &file.module.imports {
            let resolved = resolve_specifier_to_target_indices(
                &file.path,
                &imp.source,
                targets,
                ts_mappings,
                pkg_manifests,
            );
            if resolved.is_empty() {
                if let Some(pkg) = extract_external_package_name(&imp.source) {
                    consumed_packages.insert(pkg);
                }
            } else {
                record_package_if_workspace_specifier(
                    &imp.source,
                    pkg_manifests,
                    &mut consumed_packages,
                );
                let symbols: Vec<EdgeSymbol> = imp
                    .bindings
                    .iter()
                    .map(|b| EdgeSymbol {
                        imported_name: b.imported_name.clone(),
                        local_name: b.local_name.clone(),
                        is_default: b.is_default,
                        is_namespace: b.is_namespace,
                        is_type_only: b.is_type_only,
                    })
                    .collect();
                let is_side_effect = symbols.is_empty() && !imp.is_type_only;
                for target_idx in expand_with_platform_siblings(&resolved, platform_siblings) {
                    edges.push(ModuleEdge {
                        source: source_idx,
                        target: target_idx,
                        is_dynamic: false,
                        is_type_only: imp.is_type_only,
                        is_re_export: false,
                        is_side_effect,
                        imported_symbols: symbols.clone(),
                        re_export_mappings: Vec::new(),
                    });
                }
            }
        }

        let mut re_exports_by_source: HashMap<String, Vec<(String, String, bool)>> = HashMap::new();
        for exp in &file.module.exports {
            let Some(from_src) = &exp.from_source else {
                continue;
            };
            let orig = exp
                .local_name
                .as_deref()
                .unwrap_or(exp.name.as_str())
                .to_string();
            re_exports_by_source
                .entry(from_src.clone())
                .or_default()
                .push((orig, exp.name.clone(), exp.is_type_only));
        }
        for (from_src, mappings) in re_exports_by_source {
            let resolved = resolve_specifier_to_target_indices(
                &file.path,
                &from_src,
                targets,
                ts_mappings,
                pkg_manifests,
            );
            if resolved.is_empty() {
                if let Some(pkg) = extract_external_package_name(&from_src) {
                    consumed_packages.insert(pkg);
                }
            } else {
                record_package_if_workspace_specifier(
                    &from_src,
                    pkg_manifests,
                    &mut consumed_packages,
                );
                let all_type_only = mappings.iter().all(|(_, _, is_type)| *is_type);
                for target_idx in expand_with_platform_siblings(&resolved, platform_siblings) {
                    edges.push(ModuleEdge {
                        source: source_idx,
                        target: target_idx,
                        is_dynamic: false,
                        is_type_only: all_type_only,
                        is_re_export: true,
                        is_side_effect: false,
                        imported_symbols: Vec::new(),
                        re_export_mappings: mappings.clone(),
                    });
                }
            }
        }

        for spec in file
            .module
            .dynamic_imports
            .iter()
            .chain(file.module.require_sources.iter())
        {
            let resolved = resolve_specifier_to_target_indices(
                &file.path,
                spec,
                targets,
                ts_mappings,
                pkg_manifests,
            );
            if resolved.is_empty() {
                if let Some(pkg) = extract_external_package_name(spec) {
                    consumed_packages.insert(pkg);
                }
            } else {
                record_package_if_workspace_specifier(spec, pkg_manifests, &mut consumed_packages);
                for target_idx in expand_with_platform_siblings(&resolved, platform_siblings) {
                    edges.push(ModuleEdge {
                        source: source_idx,
                        target: target_idx,
                        is_dynamic: true,
                        is_type_only: false,
                        is_re_export: false,
                        is_side_effect: false,
                        imported_symbols: Vec::new(),
                        re_export_mappings: Vec::new(),
                    });
                }
            }
        }

        for (spec, qualifier) in &file.module.type_import_sources {
            let resolved = resolve_specifier_to_target_indices(
                &file.path,
                spec,
                targets,
                ts_mappings,
                pkg_manifests,
            );
            if resolved.is_empty() {
                if let Some(pkg) = extract_external_package_name(spec) {
                    consumed_packages.insert(pkg);
                }
            } else {
                record_package_if_workspace_specifier(spec, pkg_manifests, &mut consumed_packages);
                let symbols = match qualifier {
                    Some(name) => vec![EdgeSymbol {
                        imported_name: name.clone(),
                        local_name: name.clone(),
                        is_default: false,
                        is_namespace: false,
                        is_type_only: true,
                    }],
                    None => vec![EdgeSymbol {
                        imported_name: "*".to_string(),
                        local_name: "*".to_string(),
                        is_default: false,
                        is_namespace: true,
                        is_type_only: true,
                    }],
                };
                for target_idx in expand_with_platform_siblings(&resolved, platform_siblings) {
                    edges.push(ModuleEdge {
                        source: source_idx,
                        target: target_idx,
                        is_dynamic: false,
                        is_type_only: true,
                        is_re_export: false,
                        is_side_effect: false,
                        imported_symbols: symbols.clone(),
                        re_export_mappings: Vec::new(),
                    });
                }
            }
        }
    }

    for (_dir, spec) in expo_plugin_specs {
        if let Some(pkg) = extract_external_package_name(spec) {
            consumed_packages.insert(pkg);
        }
    }

    (edges, consumed_packages)
}

fn expand_with_platform_siblings(
    indices: &[usize],
    platform_siblings: &HashMap<usize, Vec<usize>>,
) -> Vec<usize> {
    let mut out = Vec::new();
    for &idx in indices {
        if !out.contains(&idx) {
            out.push(idx);
        }
        if let Some(sibs) = platform_siblings.get(&idx) {
            for &sib in sibs {
                if !out.contains(&sib) {
                    out.push(sib);
                }
            }
        }
    }
    out
}

fn record_package_if_workspace_specifier(
    specifier: &str,
    pkg_manifests: &[PackageManifestInfo],
    consumed_packages: &mut HashSet<String>,
) {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return;
    }
    if let Some(pkg_name) = extract_external_package_name(specifier)
        && pkg_manifests
            .iter()
            .any(|p| p.name.as_deref() == Some(pkg_name.as_str()))
    {
        consumed_packages.insert(pkg_name);
    }
}

fn extract_external_package_name(specifier: &str) -> Option<String> {
    let clean = specifier
        .split(['?', '#'])
        .next()
        .unwrap_or(specifier)
        .trim();
    if clean.is_empty()
        || clean.starts_with('.')
        || clean.starts_with('/')
        || clean.starts_with('\0')
        || clean.starts_with("node:")
        || clean.starts_with("bun:")
        || clean.starts_with("deno:")
        || clean.starts_with("virtual:")
        || clean.starts_with("http:")
        || clean.starts_with("https:")
        || clean.starts_with("data:")
    {
        return None;
    }
    if let Some(rest) = clean.strip_prefix('@') {
        let mut parts = rest.split('/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if scope.is_empty() || name.is_empty() {
            return None;
        }
        Some(format!("@{scope}/{name}"))
    } else {
        let root = clean.split('/').next()?;
        if BUILTIN_MODULES.contains(&root) {
            return None;
        }
        Some(root.to_string())
    }
}
