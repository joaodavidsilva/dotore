//! Entrypoint discovery, reachability BFS, orphan file (`unused-file`), dead export (`unused-export`),
//! unused dependency (`unused-dependency`), and Tarjan SCC circular dependency (`circular-dependency`) analysis.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
};

use crate::ir::{ByteSpan, FileContext, FileIr, SourceLoc};

use super::{
    CircularDependencyFinding, UnusedDependencyFinding, UnusedExportFinding,
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

const IMPLICIT_DEPENDENCIES: &[&str] = &[
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
];

const MAX_CYCLES_PER_SCC: usize = 20;
const MAX_TOTAL_CYCLES: usize = 200;

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
            is_entry_point[idx] = true;
            packages_with_entrypoints.insert(pkg.norm_root.clone());
        }
        for cmd in &pkg.script_commands {
            for token in extract_script_file_tokens(cmd) {
                let candidate = pkg.root_dir.join(&token);
                let stem = normalize_module_stem(&candidate);
                for idx in match_stem_against_targets(&stem, targets) {
                    is_entry_point[idx] = true;
                    packages_with_entrypoints.insert(pkg.norm_root.clone());
                }
            }
        }
    }

    for (dir, spec) in expo_plugin_specs {
        if spec.starts_with('.') || spec.starts_with('/') {
            let stem = normalize_module_stem(&dir.join(spec));
            for idx in match_stem_against_targets(&stem, targets) {
                is_entry_point[idx] = true;
            }
        }
    }

    for file in files {
        for route_mod in &file.module.route_module_entries {
            let rel_spec = if route_mod.starts_with('.') {
                route_mod.clone()
            } else {
                format!("./{route_mod}")
            };
            for idx in resolve_specifier_to_target_indices(
                &file.path,
                &rel_spec,
                targets,
                ts_mappings,
                pkg_manifests,
            ) {
                is_entry_point[idx] = true;
            }
        }
    }

    for (idx, file) in files.iter().enumerate() {
        let pkg_root = find_enclosing_package_root(&targets[idx].norm_path, pkg_manifests);
        let rel_path = strip_package_root_prefix(&targets[idx].norm_path, &pkg_root);
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
        if edge.source < total_modules && edge.target < total_modules {
            adj[edge.source].push(edge.target);
        }
    }

    let mut visited = vec![false; total_modules];
    let mut queue = VecDeque::new();

    for idx in 0..total_modules {
        if is_entry_point[idx] || is_root_or_excluded[idx] {
            visited[idx] = true;
            queue.push_back(idx);
        }
    }

    while let Some(curr) = queue.pop_front() {
        for &next in &adj[curr] {
            if !visited[next] {
                visited[next] = true;
                queue.push_back(next);
            }
        }
        if let Some(sibs) = platform_siblings.get(&curr) {
            for &sib in sibs {
                if !visited[sib] {
                    visited[sib] = true;
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
        if is_reachable[idx] || is_entry_point[idx] || is_root_or_excluded[idx] {
            continue;
        }
        if !pkg_manifests.is_empty() {
            let pkg_root = find_enclosing_package_root(&targets[idx].norm_path, pkg_manifests);
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

    let mut used_exports: HashSet<(usize, String)> = HashSet::new();

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
        let source_file = &files[edge.source];

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
        if !is_reachable[idx] || is_entry_point[idx] || is_root_or_excluded[idx] {
            continue;
        }
        if !pkg_manifests.is_empty() {
            let pkg_root = find_enclosing_package_root(&targets[idx].norm_path, pkg_manifests);
            if !packages_with_entrypoints.contains(&pkg_root) {
                continue;
            }
        }
        if used_exports.contains(&(idx, "*".to_string())) {
            continue;
        }

        let mut default_linked_locals = HashSet::new();
        for exp in &file.module.exports {
            if exp.name == "default"
                && let Some(local) = &exp.local_name
                && used_exports.contains(&(idx, "default".to_string()))
            {
                default_linked_locals.insert(local.clone());
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
            if used_exports.contains(&(idx, exp.name.clone())) {
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
            if exp.name != "default" && default_linked_locals.contains(&exp.name) {
                continue;
            }
            if exp.name == "default"
                && let Some(local) = &exp.local_name
                && (used_exports.contains(&(idx, local.clone()))
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
    used_exports: &mut HashSet<(usize, String)>,
    visited: &mut HashSet<usize>,
) {
    let group = platform_siblings
        .get(&module_idx)
        .cloned()
        .unwrap_or_else(|| vec![module_idx]);
    for idx in group {
        if !visited.insert(idx) {
            continue;
        }
        used_exports.insert((idx, "*".to_string()));
        for exp in &files[idx].module.exports {
            used_exports.insert((idx, exp.name.clone()));
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
    used_exports: &mut HashSet<(usize, String)>,
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
    used_exports: &mut HashSet<(usize, String)>,
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
    used_exports: &mut HashSet<(usize, String)>,
    visited: &mut HashSet<(usize, String)>,
) {
    let group = platform_siblings
        .get(&module_idx)
        .cloned()
        .unwrap_or_else(|| vec![module_idx]);
    for idx in group {
        if !visited.insert((idx, export_name.to_string())) {
            continue;
        }
        used_exports.insert((idx, export_name.to_string()));
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
    used_exports: &mut HashSet<(usize, String)>,
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

pub(super) fn detect_unused_dependencies(
    files: &[FileIr],
    pkg_manifests: &[PackageManifestInfo],
    packages_with_entrypoints: &HashSet<String>,
    manifests: &HashMap<PathBuf, String>,
    consumed_external_packages: &HashSet<String>,
) -> Vec<UnusedDependencyFinding> {
    let mut findings = Vec::new();
    if pkg_manifests.is_empty() {
        return findings;
    }

    let mut all_used_packages = consumed_external_packages.clone();
    for &implicit in IMPLICIT_DEPENDENCIES {
        all_used_packages.insert(implicit.to_string());
    }

    for pkg in pkg_manifests {
        for peer in &pkg.peer_and_optional_dependencies {
            all_used_packages.insert(peer.clone());
        }
        for cmd in &pkg.script_commands {
            for candidate in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
                let short_bin = candidate.rsplit('/').next().unwrap_or(candidate.as_str());
                if command_mentions_token(cmd, candidate) || command_mentions_token(cmd, short_bin)
                {
                    all_used_packages.insert(candidate.clone());
                }
            }
        }
    }

    for content in manifests.values() {
        for pkg in pkg_manifests {
            for candidate in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
                if content_mentions_quoted_package(content, candidate) {
                    all_used_packages.insert(candidate.clone());
                }
            }
        }
    }

    let _ = files;

    for pkg in pkg_manifests {
        for (dep_list, is_dev) in [(&pkg.dependencies, false), (&pkg.dev_dependencies, true)] {
            for dep_name in dep_list {
                if is_package_considered_used(dep_name, &all_used_packages) {
                    continue;
                }
                let (loc, span) = find_json_key_loc(&pkg.raw_content, dep_name);
                findings.push(UnusedDependencyFinding {
                    manifest_path: pkg.manifest_path.clone(),
                    package_root: pkg.root_dir.clone(),
                    package_name: dep_name.clone(),
                    is_dev_dependency: is_dev,
                    has_package_entrypoint: packages_with_entrypoints.contains(&pkg.norm_root),
                    loc,
                    span,
                });
            }
        }
    }

    findings
}

fn is_package_considered_used(dep_name: &str, used: &HashSet<String>) -> bool {
    if used.contains(dep_name) || IMPLICIT_DEPENDENCIES.contains(&dep_name) {
        return true;
    }
    if dep_name.starts_with("@babel/")
        || dep_name.starts_with("eslint-")
        || dep_name.starts_with("@eslint/")
        || dep_name.starts_with("prettier-plugin-")
        || dep_name.starts_with("@vitejs/plugin-")
        || dep_name.starts_with("vite-plugin-")
    {
        return true;
    }
    if let Some(typed_pkg) = dep_name.strip_prefix("@types/") {
        let unscoped = if let Some((scope, rest)) = typed_pkg.split_once("__") {
            format!("@{scope}/{rest}")
        } else {
            typed_pkg.to_string()
        };
        if used.contains(&unscoped) || IMPLICIT_DEPENDENCIES.contains(&unscoped.as_str()) {
            return true;
        }
    }
    false
}

fn command_mentions_token(cmd: &str, token: &str) -> bool {
    cmd.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '@' && c != '/')
        .any(|part| part == token)
}

fn content_mentions_quoted_package(content: &str, pkg_name: &str) -> bool {
    let dq = format!("\"{pkg_name}\"");
    let sq = format!("'{pkg_name}'");
    let sub_dq = format!("\"{pkg_name}/");
    let sub_sq = format!("'{pkg_name}/");
    for pat in [&sub_dq, &sub_sq] {
        if content.contains(pat) {
            return true;
        }
    }
    for (idx, _) in content.match_indices(&dq).chain(content.match_indices(&sq)) {
        let after = content[idx + dq.len()..].trim_start();
        if !after.starts_with(':') {
            return true;
        }
    }
    false
}

fn find_json_key_loc(raw_json: &str, key: &str) -> (SourceLoc, ByteSpan) {
    let needle = format!("\"{key}\"");
    if let Some(byte_idx) = raw_json.find(&needle) {
        let before = &raw_json[..byte_idx];
        let line = u32::try_from(before.bytes().filter(|&b| b == b'\n').count() + 1).unwrap_or(1);
        let last_nl = before.rfind('\n').map_or(0, |p| p + 1);
        let column = u32::try_from(byte_idx.saturating_sub(last_nl) + 1).unwrap_or(1);
        let start = u32::try_from(byte_idx).unwrap_or(0);
        let end = u32::try_from(byte_idx + needle.len()).unwrap_or(start);
        return (SourceLoc { line, column }, ByteSpan { start, end });
    }
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan { start: 0, end: 0 },
    )
}

pub(super) fn detect_circular_dependencies(
    files: &[FileIr],
    edges: &[ModuleEdge],
) -> Vec<CircularDependencyFinding> {
    let n = files.len();
    if n < 2 {
        return Vec::new();
    }

    let mut adj_sets: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for edge in edges {
        if edge.is_dynamic || edge.is_type_only {
            continue;
        }
        if !edge.imported_symbols.is_empty() && edge.imported_symbols.iter().all(|s| s.is_type_only)
        {
            continue;
        }
        if is_compile_time_erased_edge(edge, files) {
            continue;
        }
        if edge.source < n && edge.target < n && edge.source != edge.target {
            adj_sets[edge.source].insert(edge.target);
        }
    }

    let adj: Vec<Vec<usize>> = adj_sets
        .into_iter()
        .map(|s| {
            let mut v: Vec<usize> = s.into_iter().collect();
            v.sort_unstable();
            v
        })
        .collect();

    let sccs = tarjan_sccs(&adj);
    let mut all_cycles: Vec<Vec<usize>> = Vec::new();
    let mut seen_keys: HashSet<Vec<usize>> = HashSet::new();

    for mut scc in sccs {
        if scc.len() < 2 {
            continue;
        }
        scc.sort_unstable();
        for cycle in enumerate_elementary_cycles(&scc, &adj, files) {
            if seen_keys.insert(cycle.clone()) {
                all_cycles.push(cycle);
                if all_cycles.len() >= MAX_TOTAL_CYCLES {
                    break;
                }
            }
        }
        if all_cycles.len() >= MAX_TOTAL_CYCLES {
            break;
        }
    }

    all_cycles.sort_by(|a, b| {
        a.len()
            .cmp(&b.len())
            .then_with(|| files[a[0]].path.cmp(&files[b[0]].path))
    });

    all_cycles
        .into_iter()
        .map(|cycle| {
            let primary_file_index = cycle[0];
            let mut cycle_paths: Vec<PathBuf> =
                cycle.iter().map(|&idx| files[idx].path.clone()).collect();
            cycle_paths.push(files[primary_file_index].path.clone());
            CircularDependencyFinding {
                primary_file_index,
                cycle_paths,
            }
        })
        .collect()
}

fn is_compile_time_erased_edge(edge: &ModuleEdge, files: &[FileIr]) -> bool {
    if edge.is_re_export || edge.imported_symbols.is_empty() {
        return false;
    }
    let Some(target_file) = files.get(edge.target) else {
        return false;
    };
    edge.imported_symbols.iter().all(|sym| {
        if sym.is_type_only {
            return true;
        }
        if sym.is_namespace {
            return false;
        }
        let exp_name = if sym.is_default {
            "default"
        } else {
            sym.imported_name.as_str()
        };
        let matching: Vec<_> = target_file
            .module
            .exports
            .iter()
            .filter(|e| e.name == exp_name)
            .collect();
        !matching.is_empty() && matching.iter().all(|e| e.is_type_only)
    })
}

fn tarjan_sccs(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct TarjanState {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    fn strongconnect(v: usize, adj: &[Vec<usize>], state: &mut TarjanState) {
        let v_idx = state.index;
        state.indices[v] = Some(v_idx);
        state.lowlink[v] = v_idx;
        state.index += 1;
        state.stack.push(v);
        state.on_stack[v] = true;

        for &w in &adj[v] {
            if state.indices[w].is_none() {
                strongconnect(w, adj, state);
                state.lowlink[v] = state.lowlink[v].min(state.lowlink[w]);
            } else if state.on_stack[w]
                && let Some(w_idx) = state.indices[w]
            {
                state.lowlink[v] = state.lowlink[v].min(w_idx);
            }
        }

        if state.lowlink[v] == v_idx {
            let mut scc = Vec::new();
            while let Some(w) = state.stack.pop() {
                state.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            state.sccs.push(scc);
        }
    }

    let n = adj.len();
    let mut state = TarjanState {
        index: 0,
        indices: vec![None; n],
        lowlink: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    for v in 0..n {
        if state.indices[v].is_none() {
            strongconnect(v, adj, &mut state);
        }
    }
    state.sccs
}

fn enumerate_elementary_cycles(
    scc_nodes: &[usize],
    adj: &[Vec<usize>],
    files: &[FileIr],
) -> Vec<Vec<usize>> {
    if scc_nodes.len() == 2 {
        let a = scc_nodes[0];
        let b = scc_nodes[1];
        return if files[a].path <= files[b].path {
            vec![vec![a, b]]
        } else {
            vec![vec![b, a]]
        };
    }

    let scc_set: HashSet<usize> = scc_nodes.iter().copied().collect();
    let mut cycles = Vec::new();
    let mut seen = HashSet::new();

    for &start in scc_nodes {
        if cycles.len() >= MAX_CYCLES_PER_SCC {
            break;
        }
        let mut path = vec![start];
        let mut visited: HashSet<usize> = HashSet::from([start]);
        dfs_cycles(
            start,
            start,
            &scc_set,
            adj,
            files,
            &mut path,
            &mut visited,
            &mut seen,
            &mut cycles,
        );
    }

    cycles
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bounded DFS cycle enumerator threads recursion stack, visited set, and canonical output"
)]
fn dfs_cycles(
    start: usize,
    curr: usize,
    scc_set: &HashSet<usize>,
    adj: &[Vec<usize>],
    files: &[FileIr],
    path: &mut Vec<usize>,
    visited: &mut HashSet<usize>,
    seen: &mut HashSet<Vec<usize>>,
    out: &mut Vec<Vec<usize>>,
) {
    if out.len() >= MAX_CYCLES_PER_SCC {
        return;
    }
    for &next in &adj[curr] {
        if !scc_set.contains(&next) {
            continue;
        }
        if next == start && path.len() >= 2 {
            let canonical = canonicalize_cycle(path, files);
            if seen.insert(canonical.clone()) {
                out.push(canonical);
                if out.len() >= MAX_CYCLES_PER_SCC {
                    return;
                }
            }
        } else if !visited.contains(&next) {
            visited.insert(next);
            path.push(next);
            dfs_cycles(start, next, scc_set, adj, files, path, visited, seen, out);
            path.pop();
            visited.remove(&next);
        }
    }
}

fn canonicalize_cycle(cycle: &[usize], files: &[FileIr]) -> Vec<usize> {
    let mut min_pos = 0;
    for (idx, &node) in cycle.iter().enumerate().skip(1) {
        if files[node].path < files[cycle[min_pos]].path {
            min_pos = idx;
        }
    }
    let mut out = Vec::with_capacity(cycle.len());
    out.extend_from_slice(&cycle[min_pos..]);
    out.extend_from_slice(&cycle[..min_pos]);
    out
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
