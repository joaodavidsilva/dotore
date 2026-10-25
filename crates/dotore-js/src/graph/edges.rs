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

struct EdgeBuilderContext<'a> {
    targets: &'a [IndexedTargetFile],
    platform_siblings: &'a HashMap<usize, Vec<usize>>,
    ts_mappings: &'a [CompiledPathMapping],
    pkg_manifests: &'a [PackageManifestInfo],
}

impl EdgeBuilderContext<'_> {
    fn resolve_or_record_external(
        &self,
        importer_path: & std::path::Path,
        specifier: &str,
        consumed_packages: &mut HashSet<String>,
    ) -> Vec<usize> {
        let resolved = resolve_specifier_to_target_indices(
            importer_path,
            specifier,
            self.targets,
            self.ts_mappings,
            self.pkg_manifests,
        );
        if resolved.is_empty() {
            if let Some(pkg) = extract_external_package_name(specifier) {
                consumed_packages.insert(pkg);
            }
            Vec::new()
        } else {
            record_package_if_workspace_specifier(specifier, self.pkg_manifests, consumed_packages);
            expand_with_platform_siblings(&resolved, self.platform_siblings)
        }
    }
}

pub(super) fn build_module_edges(
    files: &[FileIr],
    targets: &[IndexedTargetFile],
    platform_siblings: &HashMap<usize, Vec<usize>>,
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
    expo_plugin_specs: &[(PathBuf, String)],
) -> (Vec<ModuleEdge>, HashSet<String>) {
    let ctx = EdgeBuilderContext {
        targets,
        platform_siblings,
        ts_mappings,
        pkg_manifests,
    };
    let mut edges = Vec::new();
    let mut consumed_packages = HashSet::new();

    for (source_idx, file) in files.iter().enumerate() {
        append_static_import_edges(source_idx, file, &ctx, &mut edges, &mut consumed_packages);
        append_re_export_edges(source_idx, file, &ctx, &mut edges, &mut consumed_packages);
        append_dynamic_and_require_edges(
            source_idx,
            file,
            &ctx,
            &mut edges,
            &mut consumed_packages,
        );
        append_type_import_edges(source_idx, file, &ctx, &mut edges, &mut consumed_packages);
    }

    for (_dir, spec) in expo_plugin_specs {
        if let Some(pkg) = extract_external_package_name(spec) {
            consumed_packages.insert(pkg);
        }
    }

    (edges, consumed_packages)
}

fn append_static_import_edges(
    source_idx: usize,
    file: &FileIr,
    ctx: &EdgeBuilderContext<'_>,
    edges: &mut Vec<ModuleEdge>,
    consumed_packages: &mut HashSet<String>,
) {
    for imp in &file.module.imports {
        let target_indices =
            ctx.resolve_or_record_external(&file.path, &imp.source, consumed_packages);
        if target_indices.is_empty() {
            continue;
        }
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
        for target_idx in target_indices {
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

fn append_re_export_edges(
    source_idx: usize,
    file: &FileIr,
    ctx: &EdgeBuilderContext<'_>,
    edges: &mut Vec<ModuleEdge>,
    consumed_packages: &mut HashSet<String>,
) {
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
        let target_indices =
            ctx.resolve_or_record_external(&file.path, &from_src, consumed_packages);
        if target_indices.is_empty() {
            continue;
        }
        let all_type_only = mappings.iter().all(|(_, _, is_type)| *is_type);
        for target_idx in target_indices {
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

fn append_dynamic_and_require_edges(
    source_idx: usize,
    file: &FileIr,
    ctx: &EdgeBuilderContext<'_>,
    edges: &mut Vec<ModuleEdge>,
    consumed_packages: &mut HashSet<String>,
) {
    for spec in file
        .module
        .dynamic_imports
        .iter()
        .chain(file.module.require_sources.iter())
    {
        for target_idx in ctx.resolve_or_record_external(&file.path, spec, consumed_packages) {
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

fn append_type_import_edges(
    source_idx: usize,
    file: &FileIr,
    ctx: &EdgeBuilderContext<'_>,
    edges: &mut Vec<ModuleEdge>,
    consumed_packages: &mut HashSet<String>,
) {
    for (spec, qualifier) in &file.module.type_import_sources {
        let target_indices = ctx.resolve_or_record_external(&file.path, spec, consumed_packages);
        if target_indices.is_empty() {
            continue;
        }
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
        for target_idx in target_indices {
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
