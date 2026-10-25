//! Entrypoint discovery, reachability BFS, orphan file (`unused-file`), dead export (`unused-export`),
//! unused dependency (`unused-dependency`), and Tarjan SCC circular dependency (`circular-dependency`) analysis.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
};

use crate::ir::{FileContext, FileIr};

use super::{
    UnusedExportFinding,
    resolution::{
        CompiledPathMapping, EdgeSymbol, IndexedTargetFile, ModuleEdge, PackageManifestInfo,
        SOURCE_SUFFIXES, match_stem_against_targets, normalize_module_stem,
        resolve_package_entry_indices, resolve_specifier_to_target_indices, strip_platform_suffix,
        strip_source_extension,
    },
};

const ROUTE_CONVENTION_EXPORTS: &[&str] = &[
    "metadata",
    "generateMetadata",
    "generateStaticParams",
    "viewport",
    "generateViewport",
    "dynamic",
    "dynamicParams",
    "revalidate",
    "fetchCache",
    "runtime",
    "preferredRegion",
    "maxDuration",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "loader",
    "clientLoader",
    "action",
    "clientAction",
    "ErrorBoundary",
    "HydrateFallback",
    "headers",
    "links",
    "meta",
    "handle",
    "shouldRevalidate",
    "middleware",
    "config",
    "getStaticProps",
    "getStaticPaths",
    "getServerSideProps",
    "Route",
];

pub(super) const IMPLICIT_DEPENDENCIES: &[&str] = &[
    "typescript",
    "@types/node",
    "@types/react",
    "@types/react-dom",
    "@types/jest",
    "react",
    "react-dom",
    "react-native",
    "expo",
    "next",
    "vite",
    "vitest",
    "jest",
    "eslint",
    "prettier",
    "husky",
    "lint-staged",
    "tslib",
    "@babel/core",
    "@babel/runtime",
    "@babel/preset-env",
    "@babel/preset-react",
    "@babel/preset-typescript",
    "babel-core",
    "babel-jest",
    "babel-loader",
    "babel-plugin-react-compiler",
    "postcss",
    "cross-env",
    "node-sass",
    "sass",
    "less",
    "patch-package",
    "simple-git-hooks",
    "lefthook",
    "ts-node",
    "ts-jest",
    "tsx",
    "jsdom",
    "happy-dom",
    "rimraf",
    "concurrently",
    "npm-run-all",
    "npm-run-all2",
    "dotenv-cli",
    "webpack",
    "rollup",
    "terser",
    "autoprefixer",
    "tailwindcss",
    "@tailwindcss/postcss",
    "@tailwindcss/vite",
    "react-test-renderer",
    "esbuild",
    "typedoc",
    "commitizen",
    "cz-conventional-changelog",
    "dotore",
    "@angular/animations",
    "@angular/common",
    "@angular/compiler",
    "@angular/compiler-cli",
    "@angular/cli",
    "@angular/core",
    "@angular/forms",
    "@angular/language-service",
    "@angular/platform-browser",
    "@angular/platform-browser-dynamic",
    "@angular/platform-server",
    "@angular/router",
    "@angular/build",
    "@angular-devkit/build-angular",
    "@angular-devkit/core",
    "@angular-devkit/schematics",
    "rxjs",
    "zone.js",
];
pub(super) fn discover_entrypoints_and_roots(
    files: &[FileIr],
    targets: &[IndexedTargetFile],
    pkg_manifests: &[PackageManifestInfo],
    expo_plugin_specs: &[(PathBuf, String)],
    ts_mappings: &[CompiledPathMapping],
) -> (Vec<bool>, Vec<bool>, HashSet<String>) {
    let n = files.len();
    let mut is_entry_point = vec![false; n];
    let mut is_root_or_excluded = vec![false; n];
    let mut packages_with_entrypoints = HashSet::new();

    for pkg in pkg_manifests {
        for idx in resolve_package_entry_indices(pkg, targets) {
            if let Some(slot) = is_entry_point.get_mut(idx) {
                *slot = true;
                packages_with_entrypoints.insert(pkg.norm_root.clone());
            }
        }
        for token in pkg
            .script_commands
            .iter()
            .flat_map(|cmd| extract_script_file_tokens(cmd))
        {
            let stem = normalize_module_stem(&pkg.root_dir.join(&token));
            for idx in match_stem_against_targets(&stem, targets) {
                if let Some(slot) = is_entry_point.get_mut(idx) {
                    *slot = true;
                    packages_with_entrypoints.insert(pkg.norm_root.clone());
                }
            }
        }
    }

    for (dir, spec) in expo_plugin_specs {
        if spec.starts_with('.') || spec.starts_with('/') {
            let stem = normalize_module_stem(&dir.join(spec));
            for idx in match_stem_against_targets(&stem, targets) {
                if let Some(slot) = is_entry_point.get_mut(idx) {
                    *slot = true;
                }
                if let Some(target) = targets.get(idx) {
                    let pkg_root = find_enclosing_package_root(&target.norm_path, pkg_manifests);
                    packages_with_entrypoints.insert(pkg_root);
                }
            }
        }
    }

    for file in files {
        for route_mod in &file.module.route_module_entries {
            let rel_spec: Cow<'_, str> = if route_mod.starts_with('.') {
                Cow::Borrowed(route_mod.as_str())
            } else {
                Cow::Owned(format!("./{route_mod}"))
            };
            for idx in resolve_specifier_to_target_indices(
                &file.path,
                &rel_spec,
                targets,
                ts_mappings,
                pkg_manifests,
            ) {
                if let Some(slot) = is_entry_point.get_mut(idx) {
                    *slot = true;
                }
                if let Some(target) = targets.get(idx) {
                    let pkg_root = find_enclosing_package_root(&target.norm_path, pkg_manifests);
                    packages_with_entrypoints.insert(pkg_root);
                }
            }
        }
    }

    for (idx, file) in files.iter().enumerate() {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        let pkg_root = find_enclosing_package_root(&target.norm_path, pkg_manifests);
        let rel_path = strip_package_root_prefix(&target.norm_path, &pkg_root);
        let rel_stem = strip_source_extension(&rel_path);
        let (base_rel_stem, _) = strip_platform_suffix(&rel_stem);

        if is_framework_or_default_entrypoint(&base_rel_stem) {
            is_entry_point[idx] = true;
            packages_with_entrypoints.insert(pkg_root.clone());
        }

        if file.file_context != FileContext::Production || is_excluded_support_file(&rel_path) {
            is_root_or_excluded[idx] = true;
        }
    }

    (
        is_entry_point,
        is_root_or_excluded,
        packages_with_entrypoints,
    )
}

fn find_enclosing_package_root(norm_file: &str, pkg_manifests: &[PackageManifestInfo]) -> String {
    pkg_manifests
        .iter()
        .filter(|pkg| {
            pkg.norm_root.is_empty()
                || pkg.norm_root == "."
                || norm_file == pkg.norm_root
                || norm_file.starts_with(&format!("{}/", pkg.norm_root))
        })
        .max_by_key(|pkg| pkg.norm_root.len())
        .map(|pkg| pkg.norm_root.clone())
        .unwrap_or_default()
}

fn strip_package_root_prefix(norm_file: &str, pkg_root: &str) -> String {
    if pkg_root.is_empty() || pkg_root == "." {
        return norm_file.to_string();
    }
    norm_file
        .strip_prefix(&format!("{pkg_root}/"))
        .unwrap_or(norm_file)
        .to_string()
}

fn is_framework_or_default_entrypoint(base_rel_stem: &str) -> bool {
    if matches!(
        base_rel_stem,
        "index"
            | "main"
            | "app"
            | "App"
            | "server"
            | "client"
            | "middleware"
            | "instrumentation"
            | "src/index"
            | "src/main"
            | "src/app"
            | "src/App"
            | "src/server"
            | "src/client"
            | "src/middleware"
            | "src/instrumentation"
            | "src/router"
            | "src/routeTree.gen"
            | "src/entry-client"
            | "src/entry-server"
            | "src/entry.client"
            | "src/entry.server"
            | "app/root"
            | "app/routes"
            | "app/entry.client"
            | "app/entry.server"
    ) {
        return true;
    }
    if matches!(
        base_rel_stem,
        "main.server"
            | "src/main.server"
            | "polyfills"
            | "src/polyfills"
            | "public-api"
            | "src/public-api"
            | "app.component"
            | "src/app/app.component"
    ) || base_rel_stem.ends_with(".module")
        || base_rel_stem.ends_with(".routes")
        || base_rel_stem.ends_with(".config")
        || base_rel_stem.ends_with("/public-api")
    {
        return true;
    }

    for prefix in [
        "pages/",
        "src/pages/",
        "routes/",
        "src/routes/",
        "app/routes/",
    ] {
        if let Some(after) = base_rel_stem.strip_prefix(prefix)
            && !after.split('/').any(|seg| seg.starts_with("_components"))
        {
            return true;
        }
    }

    for app_prefix in ["app/", "src/app/"] {
        if let Some(after) = base_rel_stem.strip_prefix(app_prefix) {
            let leaf = after.rsplit('/').next().unwrap_or(after);
            if matches!(
                leaf,
                "page"
                    | "layout"
                    | "route"
                    | "default"
                    | "loading"
                    | "error"
                    | "not-found"
                    | "template"
                    | "global-error"
                    | "opengraph-image"
                    | "twitter-image"
                    | "icon"
                    | "apple-icon"
                    | "manifest"
                    | "sitemap"
                    | "robots"
                    | "_layout"
                    | "_sitemap"
                    | "+html"
                    | "+not-found"
                    | "index"
            ) {
                return true;
            }
        }
    }

    false
}

fn is_excluded_support_file(rel_path: &str) -> bool {
    let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    if file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.mts")
        || file_name.ends_with(".d.cts")
        || file_name.ends_with(".html")
        || file_name.ends_with(".htm")
        || file_name.ends_with(".css")
        || file_name.ends_with(".scss")
        || file_name.contains(".config.")
        || file_name.contains(".setup.")
        || file_name.starts_with("setupTests.")
        || file_name.contains(".stories.")
        || file_name.contains(".story.")
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
        || file_name.contains(".test-d.")
        || file_name.contains(".cy.")
    {
        return true;
    }

    for seg in rel_path.split('/') {
        if matches!(
            seg,
            "__tests__"
                | "__test__"
                | "tests"
                | "test"
                | "__mocks__"
                | "__fixtures__"
                | "__snapshots__"
                | "e2e"
                | "cypress"
                | "playwright"
                | "scripts"
                | ".storybook"
        ) {
            return true;
        }
    }
    false
}

fn extract_script_file_tokens(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw_tok in cmd.split_whitespace() {
        let tok = raw_tok.trim_matches(['"', '\'', ';', '&', '|']);
        if tok.is_empty() || tok.starts_with('-') {
            continue;
        }
        let has_source_ext = SOURCE_SUFFIXES
            .iter()
            .any(|ext| *ext != ".json" && tok.ends_with(ext));
        if has_source_ext
            || tok.starts_with("./")
            || tok.starts_with("../")
            || tok.starts_with("scripts/")
        {
            out.push(tok.to_string());
        }
    }
    out
}

pub(super) fn trace_reachability(
    total_modules: usize,
    edges: &[ModuleEdge],
    platform_siblings: &HashMap<usize, Vec<usize>>,
    is_entry_point: &[bool],
    is_root_or_excluded: &[bool],
) -> Vec<bool> {
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); total_modules];
    for edge in edges {
        if edge.target < total_modules
            && let Some(edges_out) = adj.get_mut(edge.source)
        {
            edges_out.push(edge.target);
        }
    }

    let mut visited = vec![false; total_modules];
    let mut queue = VecDeque::new();

    for idx in 0..total_modules {
        let is_entry = is_entry_point.get(idx).copied().unwrap_or(false);
        let is_root = is_root_or_excluded.get(idx).copied().unwrap_or(false);
        if (is_entry || is_root)
            && let Some(slot) = visited.get_mut(idx)
        {
            *slot = true;
            queue.push_back(idx);
        }
    }

    while let Some(curr) = queue.pop_front() {
        if let Some(neighbors) = adj.get(curr) {
            for &next in neighbors {
                if let Some(slot) = visited.get_mut(next)
                    && !*slot
                {
                    *slot = true;
                    queue.push_back(next);
                }
            }
        }
        if let Some(sibs) = platform_siblings.get(&curr) {
            for &sib in sibs {
                if let Some(slot) = visited.get_mut(sib)
                    && !*slot
                {
                    *slot = true;
                    queue.push_back(sib);
                }
            }
        }
    }

    visited
}

#[expect(
    clippy::too_many_arguments,
    reason = "Orphan file detection inspects precomputed reachability, entrypoint, and package tables directly"
)]
pub(super) fn detect_orphan_files(
    files: &[FileIr],
    targets: &[IndexedTargetFile],
    pkg_manifests: &[PackageManifestInfo],
    packages_with_entrypoints: &HashSet<String>,
    has_any_entrypoint: bool,
    is_entry_point: &[bool],
    is_root_or_excluded: &[bool],
    is_reachable: &[bool],
) -> Vec<usize> {
    if !has_any_entrypoint {
        return Vec::new();
    }
    let mut orphans = Vec::new();
    for idx in 0..files.len() {
        if is_reachable.get(idx).copied().unwrap_or(false)
            || is_entry_point.get(idx).copied().unwrap_or(false)
            || is_root_or_excluded.get(idx).copied().unwrap_or(false)
        {
            continue;
        }
        if !pkg_manifests.is_empty()
            && let Some(target) = targets.get(idx)
        {
            let pkg_root = find_enclosing_package_root(&target.norm_path, pkg_manifests);
            if !packages_with_entrypoints.contains(&pkg_root) {
                continue;
            }
        }
        orphans.push(idx);
    }
    orphans
}

#[expect(
    clippy::too_many_arguments,
    reason = "Dead export detection propagates usage across edges, re-exports, and platform sibling groups"
)]
pub(super) fn detect_dead_exports(
    files: &[FileIr],
    targets: &[IndexedTargetFile],
    edges: &[ModuleEdge],
    platform_siblings: &HashMap<usize, Vec<usize>>,
    pkg_manifests: &[PackageManifestInfo],
    packages_with_entrypoints: &HashSet<String>,
    has_any_entrypoint: bool,
    is_entry_point: &[bool],
    is_root_or_excluded: &[bool],
    is_reachable: &[bool],
) -> Vec<UnusedExportFinding> {
    if !has_any_entrypoint {
        return Vec::new();
    }

    let mut re_export_edges_by_source: HashMap<usize, Vec<&ModuleEdge>> = HashMap::new();
    for edge in edges {
        if edge.is_re_export {
            re_export_edges_by_source
                .entry(edge.source)
                .or_default()
                .push(edge);
        }
    }

    let mut used_exports: HashMap<usize, HashSet<String>> = HashMap::new();
    for (idx, &is_entry) in is_entry_point.iter().enumerate().take(files.len()) {
        if !is_entry {
            continue;
        }
        let Some(re_edges) = re_export_edges_by_source.get(&idx) else {
            continue;
        };
        for edge in re_edges {
            propagate_re_export_edge(
                edge,
                files,
                &re_export_edges_by_source,
                platform_siblings,
                &mut used_exports,
                &mut HashSet::new(),
            );
        }
    }

    for edge in edges {
        if edge.is_re_export {
            continue;
        }
        let Some(source_file) = files.get(edge.source) else {
            continue;
        };

        if edge.is_dynamic || edge.is_side_effect || edge.imported_symbols.is_empty() {
            mark_all_exports_used_recursive(
                edge.target,
                files,
                &re_export_edges_by_source,
                platform_siblings,
                &mut used_exports,
                &mut HashSet::new(),
            );
            continue;
        }

        for sym in &edge.imported_symbols {
            mark_imported_symbol_used(
                sym,
                source_file,
                edge.target,
                files,
                &re_export_edges_by_source,
                platform_siblings,
                &mut used_exports,
            );
        }
    }

    let mut findings = Vec::new();
    for (idx, file) in files.iter().enumerate() {
        if !is_reachable.get(idx).copied().unwrap_or(false)
            || is_entry_point.get(idx).copied().unwrap_or(false)
            || is_root_or_excluded.get(idx).copied().unwrap_or(false)
        {
            continue;
        }
        if !pkg_manifests.is_empty()
            && let Some(target) = targets.get(idx)
        {
            let pkg_root = find_enclosing_package_root(&target.norm_path, pkg_manifests);
            if !packages_with_entrypoints.contains(&pkg_root) {
                continue;
            }
        }
        let file_used_exports = used_exports.get(&idx);
        if file_used_exports.is_some_and(|s| s.contains("*")) {
            continue;
        }

        let default_is_used = file_used_exports.is_some_and(|s| s.contains("default"));
        let mut default_linked_locals: HashSet<&str> = HashSet::new();
        if default_is_used {
            for exp in &file.module.exports {
                if exp.name == "default"
                    && let Some(local) = &exp.local_name
                {
                    default_linked_locals.insert(local.as_str());
                }
            }
        }

        for exp in &file.module.exports {
            if exp.is_namespace_re_export && exp.name == "*" {
                continue;
            }
            if exp.from_source.is_some() {
                continue;
            }
            if ROUTE_CONVENTION_EXPORTS.contains(&exp.name.as_str()) {
                continue;
            }
            if file_used_exports.is_some_and(|s| s.contains(exp.name.as_str())) {
                continue;
            }
            if file
                .module
                .local_references
                .binary_search(&exp.name)
                .is_ok()
            {
                continue;
            }
            if exp.name != "default" && default_linked_locals.contains(exp.name.as_str()) {
                continue;
            }
            if exp.name == "default"
                && let Some(local) = &exp.local_name
                && (file_used_exports.is_some_and(|s| s.contains(local.as_str()))
                    || file.module.local_references.binary_search(local).is_ok())
            {
                continue;
            }
            findings.push(UnusedExportFinding {
                file_index: idx,
                name: exp.name.clone(),
                is_type_only: exp.is_type_only,
                loc: exp.loc,
                span: exp.span,
            });
        }
    }

    findings
}

fn mark_all_exports_used_recursive(
    module_idx: usize,
    files: &[FileIr],
    re_export_edges_by_source: &HashMap<usize, Vec<&ModuleEdge>>,
    platform_siblings: &HashMap<usize, Vec<usize>>,
    used_exports: &mut HashMap<usize, HashSet<String>>,
    visited: &mut HashSet<usize>,
) {
    let single_group = [module_idx];
    let group = platform_siblings
        .get(&module_idx)
        .map_or(&single_group[..], Vec::as_slice);
    for &idx in group {
        if !visited.insert(idx) {
            continue;
        }
        let entry = used_exports.entry(idx).or_default();
        entry.insert("*".to_string());
        if let Some(f) = files.get(idx) {
            for exp in &f.module.exports {
                entry.insert(exp.name.clone());
            }
        }
        let Some(re_edges) = re_export_edges_by_source.get(&idx) else {
            continue;
        };
        for edge in re_edges {
            propagate_re_export_edge(
                edge,
                files,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                visited,
            );
        }
    }
}

fn propagate_re_export_edge(
    edge: &ModuleEdge,
    files: &[FileIr],
    re_export_edges_by_source: &HashMap<usize, Vec<&ModuleEdge>>,
    platform_siblings: &HashMap<usize, Vec<usize>>,
    used_exports: &mut HashMap<usize, HashSet<String>>,
    visited: &mut HashSet<usize>,
) {
    for (orig_name, _, _) in &edge.re_export_mappings {
        if orig_name == "*" {
            mark_all_exports_used_recursive(
                edge.target,
                files,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                visited,
            );
        } else {
            mark_export_used_recursive(
                edge.target,
                orig_name,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                &mut HashSet::new(),
            );
        }
    }
}

fn mark_imported_symbol_used(
    sym: &EdgeSymbol,
    source_file: &FileIr,
    target_idx: usize,
    files: &[FileIr],
    re_export_edges_by_source: &HashMap<usize, Vec<&ModuleEdge>>,
    platform_siblings: &HashMap<usize, Vec<usize>>,
    used_exports: &mut HashMap<usize, HashSet<String>>,
) {
    if !sym.is_namespace {
        let export_name = if sym.is_default {
            "default"
        } else {
            sym.imported_name.as_str()
        };
        mark_export_used_recursive(
            target_idx,
            export_name,
            re_export_edges_by_source,
            platform_siblings,
            used_exports,
            &mut HashSet::new(),
        );
        return;
    }

    let whole_use = source_file
        .module
        .whole_namespace_uses
        .contains(&sym.local_name)
        || source_file.module.exports.iter().any(|e| {
            e.name == sym.local_name || e.local_name.as_deref() == Some(sym.local_name.as_str())
        });
    let accessed: Vec<&str> = source_file
        .module
        .namespace_member_accesses
        .iter()
        .filter(|(ns, _)| ns == &sym.local_name)
        .map(|(_, mem)| mem.as_str())
        .collect();

    if whole_use || accessed.is_empty() {
        mark_all_exports_used_recursive(
            target_idx,
            files,
            re_export_edges_by_source,
            platform_siblings,
            used_exports,
            &mut HashSet::new(),
        );
    } else {
        for mem in accessed {
            mark_export_used_recursive(
                target_idx,
                mem,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                &mut HashSet::new(),
            );
        }
    }
}

fn mark_export_used_recursive(
    module_idx: usize,
    export_name: &str,
    re_export_edges_by_source: &HashMap<usize, Vec<&ModuleEdge>>,
    platform_siblings: &HashMap<usize, Vec<usize>>,
    used_exports: &mut HashMap<usize, HashSet<String>>,
    visited: &mut HashSet<(usize, String)>,
) {
    let single_group = [module_idx];
    let group = platform_siblings
        .get(&module_idx)
        .map_or(&single_group[..], Vec::as_slice);
    for &idx in group {
        if !visited.insert((idx, export_name.to_string())) {
            continue;
        }
        used_exports
            .entry(idx)
            .or_default()
            .insert(export_name.to_string());
        let Some(re_edges) = re_export_edges_by_source.get(&idx) else {
            continue;
        };
        for edge in re_edges {
            propagate_single_export_across_edge(
                edge,
                export_name,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                visited,
            );
        }
    }
}

fn propagate_single_export_across_edge(
    edge: &ModuleEdge,
    export_name: &str,
    re_export_edges_by_source: &HashMap<usize, Vec<&ModuleEdge>>,
    platform_siblings: &HashMap<usize, Vec<usize>>,
    used_exports: &mut HashMap<usize, HashSet<String>>,
    visited: &mut HashSet<(usize, String)>,
) {
    for (orig_name, exported_name, _) in &edge.re_export_mappings {
        if exported_name == export_name {
            let target_sym = if orig_name == "*" {
                export_name
            } else {
                orig_name.as_str()
            };
            mark_export_used_recursive(
                edge.target,
                target_sym,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                visited,
            );
        } else if orig_name == "*" && exported_name == "*" {
            mark_export_used_recursive(
                edge.target,
                export_name,
                re_export_edges_by_source,
                platform_siblings,
                used_exports,
                visited,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{graph::ProjectGraph, ir::parse_file_ir};

    #[test]
    fn detects_orphan_files_unused_exports_and_circular_dependencies() {
        let entry = parse_file_ir(
            Path::new("src/index.ts"),
            "import { usedFn } from './a'; export const root = usedFn();",
        );
        let mod_a = parse_file_ir(
            Path::new("src/a.ts"),
            "import { helperB } from './b'; export const usedFn = () => helperB(); export const deadExport = 42;",
        );
        let mod_b = parse_file_ir(
            Path::new("src/b.ts"),
            "import { usedFn } from './a'; export const helperB = () => usedFn;",
        );
        let orphan = parse_file_ir(Path::new("src/orphan.ts"), "export const lonely = 1;");

        let graph = ProjectGraph::build(vec![entry, mod_a, mod_b, orphan]);
        assert_eq!(graph.unused_file_indices.len(), 1);
        assert_eq!(
            graph.files[graph.unused_file_indices[0]].path,
            PathBuf::from("src/orphan.ts")
        );
        assert!(graph.unused_exports.iter().any(|e| e.name == "deadExport"));
        assert_eq!(graph.circular_dependencies.len(), 1);
        assert_eq!(
            graph.circular_dependencies[0].cycle_paths,
            vec![
                PathBuf::from("src/a.ts"),
                PathBuf::from("src/b.ts"),
                PathBuf::from("src/a.ts"),
            ]
        );
    }
}
