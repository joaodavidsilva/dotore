//! Project-level graph of parsed [`FileIr`]s, cross-file module resolution,
//! entrypoint reachability, dead-code/unused-dependency analysis, circular dependency
//! SCC detection, JSX **Caller Sites**, and **Render Cascades**.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Component, Path, PathBuf},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    config::strip_jsonc,
    ir::{
        ByteSpan, CallerSite, DepsSpec, EffectNode, FileContext, FileIr, SourceLoc, SubjectIr,
        SubjectKind,
    },
};

pub use dotore_core::ir::ResolvedCallerSite;

/// An unused value or type export detected in the module graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnusedExportFinding {
    pub file_index: usize,
    pub name: String,
    pub is_type_only: bool,
    pub loc: SourceLoc,
    pub span: ByteSpan,
}

/// An unused `dependencies` or `devDependencies` entry in a `package.json` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnusedDependencyFinding {
    pub manifest_path: PathBuf,
    pub package_root: PathBuf,
    pub package_name: String,
    pub is_dev_dependency: bool,
    pub has_package_entrypoint: bool,
    pub loc: SourceLoc,
    pub span: ByteSpan,
}

/// A canonicalized runtime import cycle across participating module indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CircularDependencyFinding {
    pub primary_file_index: usize,
    pub cycle_paths: Vec<PathBuf>,
}

/// A single occurrence of a duplicated JSX subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DuplicateJsxOccurrence {
    pub file_index: usize,
    pub path: PathBuf,
    pub root_name: String,
    pub enclosing_subject: Option<String>,
    pub composition_root_offset: Option<u32>,
    pub composition_path: Vec<String>,
    pub span: ByteSpan,
    pub loc: SourceLoc,
    pub end_line: u32,
}

/// A maximal duplicated JSX subtree family across **Subjects** or files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DuplicateJsxFamilyFinding {
    pub fingerprint: String,
    pub node_count: usize,
    pub depth: usize,
    pub occurrence_count: usize,
    pub distinct_file_count: usize,
    pub estimated_removable_line_count: u32,
    pub occurrences: Vec<DuplicateJsxOccurrence>,
}

/// A cross-file 60fps `useFrame` or `requestAnimationFrame` call-graph hazard traced by [`ProjectGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CrossFileFrameLoopFinding {
    pub root_file_index: usize,
    pub root_kind: crate::ir::types::FrameLoopRootKind,
    pub root_subject_name: Option<String>,
    pub root_loc: SourceLoc,
    pub root_span: ByteSpan,
    pub call_loc: SourceLoc,
    pub call_span: ByteSpan,
    pub helper_file_index: usize,
    pub helper_name: String,
    pub helper_loc: SourceLoc,
    pub helper_span: ByteSpan,
    pub hazard: crate::ir::types::FrameHelperHazard,
    pub call_chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ComponentTarget {
    file: PathBuf,
    component_name: String,
}

#[derive(Debug, Clone)]
struct IndexedTargetFile {
    index: usize,
    path: PathBuf,
    norm_path: String,
    stem: String,
    base_stem: String,
    index_stem: Option<String>,
    base_index_stem: Option<String>,
    has_platform_suffix: bool,
    component_names: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledPathMapping {
    base_dir: String,
    prefix: String,
    suffix: String,
    is_wildcard: bool,
    targets: Vec<String>,
}

#[derive(Debug, Clone)]
struct PackageManifestInfo {
    manifest_path: PathBuf,
    root_dir: PathBuf,
    norm_root: String,
    name: Option<String>,
    entry_specifiers: Vec<String>,
    script_commands: Vec<String>,
    dependencies: Vec<String>,
    dev_dependencies: Vec<String>,
    peer_and_optional_dependencies: HashSet<String>,
    raw_content: String,
}

#[derive(Debug, Clone)]
struct ModuleEdge {
    source: usize,
    target: usize,
    is_dynamic: bool,
    is_type_only: bool,
    is_re_export: bool,
    is_side_effect: bool,
    imported_symbols: Vec<EdgeSymbol>,
    re_export_mappings: Vec<(String, String, bool)>,
}

#[derive(Debug, Clone)]
struct EdgeSymbol {
    imported_name: String,
    local_name: String,
    is_default: bool,
    is_namespace: bool,
    is_type_only: bool,
}

const SOURCE_SUFFIXES: &[&str] = &[
    ".d.ts", ".d.mts", ".d.cts", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts",
    ".json",
];

const PLATFORM_SUFFIXES: &[&str] = &[
    ".react-native",
    ".react-server",
    ".android",
    ".desktop",
    ".windows",
    ".native",
    ".client",
    ".server",
    ".macos",
    ".web",
    ".ios",
    ".any",
    ".rn",
];

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

/// Whole-project graph wrapping parsed [`FileIr`]s.
#[derive(Debug, Default)]
pub struct ProjectGraph {
    /// Parsed IR for every file in scope.
    pub files: Vec<FileIr>,
    /// Raw manifest contents (`package.json`, `tsconfig.json`, `pnpm-workspace.yaml`, lockfiles, etc.).
    pub manifests: HashMap<PathBuf, String>,
    /// Resolved JSX **Caller Sites** indexed by target `(file, component_name)`.
    callers_by_target: HashMap<ComponentTarget, Vec<ResolvedCallerSite>>,
    targets: Vec<IndexedTargetFile>,
    ts_mappings: Vec<CompiledPathMapping>,
    pkg_manifests: Vec<PackageManifestInfo>,
    /// Whether any `package.json` or `tsconfig.json` manifests were supplied.
    pub has_manifests: bool,
    /// Indices into `files` that are unreachable orphan files (`unused-file`).
    pub(crate) unused_file_indices: Vec<usize>,
    /// Unused value and type exports (`unused-export`, `unused-type`).
    pub(crate) unused_exports: Vec<UnusedExportFinding>,
    /// Unused dependencies and devDependencies (`unused-dependency`, `unused-dev-dependency`).
    pub(crate) unused_dependencies: Vec<UnusedDependencyFinding>,
    /// Canonicalized runtime import cycles (`circular-dependency`).
    pub(crate) circular_dependencies: Vec<CircularDependencyFinding>,
    /// Maximal duplicated JSX subtree families (`duplicate-jsx-subtree`).
    pub(crate) duplicate_jsx_families: Vec<DuplicateJsxFamilyFinding>,
    /// Cross-file 60fps `useFrame` and `requestAnimationFrame` helper call-graph findings.
    pub(crate) frame_loop_findings: Vec<CrossFileFrameLoopFinding>,
}

impl ProjectGraph {
    /// Builds a [`ProjectGraph`] from a list of parsed [`FileIr`]s.
    #[must_use]
    pub fn build(files: Vec<FileIr>) -> Self {
        Self::build_with_manifests(files, HashMap::new())
    }

    /// Builds a [`ProjectGraph`] from parsed [`FileIr`]s and raw manifest contents (`package.json`, `tsconfig.json`, etc.).
    #[must_use]
    pub fn build_with_manifests(
        mut files: Vec<FileIr>,
        manifests: HashMap<PathBuf, String>,
    ) -> Self {
        files.sort_by(|a, b| a.path.cmp(&b.path));

        let has_manifests = !manifests.is_empty();
        let targets = collect_indexed_targets(&files);
        let platform_siblings = build_platform_sibling_index(&targets);
        let ts_mappings = compile_tsconfig_mappings(&manifests);
        let pkg_manifests = parse_package_manifests(&manifests);
        let expo_plugin_specs = extract_expo_plugin_specifiers(&manifests, &files);

        let mut callers_by_target: HashMap<ComponentTarget, Vec<ResolvedCallerSite>> =
            HashMap::new();
        for caller_file in &files {
            index_file_caller_sites(
                caller_file,
                &targets,
                &ts_mappings,
                &pkg_manifests,
                &mut callers_by_target,
            );
        }
        for list in callers_by_target.values_mut() {
            list.sort_by(|a, b| {
                (&a.caller_file, a.loc.line, a.loc.column).cmp(&(
                    &b.caller_file,
                    b.loc.line,
                    b.loc.column,
                ))
            });
        }

        let (edges, consumed_external_packages) = build_module_edges(
            &files,
            &targets,
            &platform_siblings,
            &ts_mappings,
            &pkg_manifests,
            &expo_plugin_specs,
        );

        let (is_entry_point, is_root_or_excluded, packages_with_entrypoints) =
            discover_entrypoints_and_roots(
                &files,
                &targets,
                &pkg_manifests,
                &expo_plugin_specs,
                &ts_mappings,
            );

        let is_reachable = trace_reachability(
            files.len(),
            &edges,
            &platform_siblings,
            &is_entry_point,
            &is_root_or_excluded,
        );

        let has_any_entrypoint = is_entry_point.iter().any(|&b| b);
        let unused_file_indices = detect_orphan_files(
            &files,
            &targets,
            &pkg_manifests,
            &packages_with_entrypoints,
            has_any_entrypoint,
            &is_entry_point,
            &is_root_or_excluded,
            &is_reachable,
        );

        let unused_exports = detect_dead_exports(
            &files,
            &targets,
            &edges,
            &platform_siblings,
            &pkg_manifests,
            &packages_with_entrypoints,
            has_any_entrypoint,
            &is_entry_point,
            &is_root_or_excluded,
            &is_reachable,
        );

        let unused_dependencies = detect_unused_dependencies(
            &files,
            &pkg_manifests,
            &packages_with_entrypoints,
            &manifests,
            &consumed_external_packages,
        );

        let circular_dependencies = detect_circular_dependencies(&files, &edges);
        let duplicate_jsx_families = detect_duplicate_jsx_families(&files);
        let frame_loop_findings =
            crate::rules::r3f::trace_cross_file_frame_loops(&files, |importer_path, specifier| {
                resolve_specifier_to_target_indices(
                    importer_path,
                    specifier,
                    &targets,
                    &ts_mappings,
                    &pkg_manifests,
                )
            });

        Self {
            files,
            manifests,
            callers_by_target,
            targets,
            ts_mappings,
            pkg_manifests,
            has_manifests,
            unused_file_indices,
            unused_exports,
            unused_dependencies,
            circular_dependencies,
            duplicate_jsx_families,
            frame_loop_findings,
        }
    }

    /// Returns all resolved JSX **Caller Sites** rendering `component_name` declared in `target_file`.
    #[must_use]
    pub fn callers_of(
        &self,
        target_file: &Path,
        component_name: &str,
    ) -> Vec<ResolvedCallerSite> {
        let key = ComponentTarget {
            file: target_file.to_path_buf(),
            component_name: component_name.to_string(),
        };
        self.callers_by_target
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Resolves a component's transitive `children`-forwarding JSX target across same-file and imported declarations.
    #[must_use]
    pub(crate) fn resolve_children_forwarding_target(
        &self,
        start_file: &FileIr,
        component_name: &str,
        is_imported: bool,
    ) -> Option<String> {
        let mut current_file = start_file;
        let mut current_name = component_name.to_string();
        let mut must_follow_import = is_imported;

        for _ in 0..8 {
            if !must_follow_import {
                let Some((_, next_target)) = current_file
                    .module
                    .component_children_targets
                    .iter()
                    .find(|(c, _)| c == &current_name)
                else {
                    break;
                };
                current_name = next_target.clone();
                must_follow_import = current_file
                    .module
                    .imports
                    .iter()
                    .any(|imp| imp.specifiers.contains(&current_name));
                continue;
            }
            // Check if `current_name` is imported from another file in `self.files`
            let resolved_import = current_file
                .module
                .imports
                .iter()
                .flat_map(|imp| imp.bindings.iter().map(move |b| (imp, b)))
                .find(|(_, b)| b.local_name == current_name && !b.is_namespace && !b.is_type_only)
                .map(|(imp, b)| (imp.source.as_str(), b.imported_name.as_str()));

            let Some((specifier, exported_name)) = resolved_import else {
                break;
            };
            if !specifier.starts_with('.') && !specifier.starts_with('/') {
                break;
            }

            let Some(target_file) = self.find_imported_file(&current_file.path, specifier) else {
                break;
            };
            current_file = target_file;
            if exported_name != "default" {
                current_name = exported_name.to_string();
            }
            must_follow_import = false;
        }

        (current_name != component_name).then_some(current_name)
    }

    /// Resolves a JSX element (`caller_file`, `jsx_span`, `component_name`) to its target
    /// `(&FileIr, &SubjectIr)` in the [`ProjectGraph`], if declared in the analyzed files.
    #[must_use]
    pub(crate) fn resolve_target_subject(
        &self,
        caller_file: &Path,
        jsx_span: ByteSpan,
        component_name: &str,
    ) -> Option<(&FileIr, &SubjectIr)> {
        for (target_key, callers) in &self.callers_by_target {
            if callers
                .iter()
                .any(|c| c.caller_file == caller_file && c.span == jsx_span)
                && let Some(target_file) = self.files.iter().find(|f| f.path == target_key.file)
                && let Some(target_subj) = target_file
                    .subjects
                    .iter()
                    .find(|s| s.name.as_deref() == Some(target_key.component_name.as_str()))
            {
                return Some((target_file, target_subj));
            }
        }

        let same_file = self.files.iter().find(|f| f.path == caller_file)?;
        let same_subj = same_file
            .subjects
            .iter()
            .find(|s| s.name.as_deref() == Some(component_name))?;
        Some((same_file, same_subj))
    }

    fn find_imported_file(&self, importer_path: &Path, specifier: &str) -> Option<&FileIr> {
        let base_dir = importer_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let joined = normalize_path_components(&base_dir.join(specifier));
        let joined_stem = strip_source_extension(&joined);
        self.files.iter().find(|f| {
            let f_norm = normalize_path_components(&f.path);
            let f_stem = strip_source_extension(&f_norm);
            f_norm == joined || f_stem == joined_stem || f_stem == format!("{joined_stem}/index")
        })
    }

    /// Resolves a relative module specifier (`./...` or `../...`) from `importer_path`
    /// to the matching file index in `self.files`.
    #[must_use]
    pub(crate) fn resolve_relative_import(
        &self,
        importer_path: &Path,
        specifier: &str,
    ) -> Option<usize> {
        let targets = collect_indexed_targets(&self.files);
        resolve_specifier_to_target_indices(importer_path, specifier, &targets, &[], &[])
            .into_iter()
            .next()
    }

    /// Resolves `specifier` imported from `importer_path` to matching [`FileIr`] entries in the graph.
    #[must_use]
    pub(crate) fn resolve_imported_module_files(
        &self,
        importer_path: &Path,
        specifier: &str,
    ) -> Vec<&FileIr> {
        resolve_specifier_to_target_indices(
            importer_path,
            specifier,
            &self.targets,
            &self.ts_mappings,
            &self.pkg_manifests,
        )
        .into_iter()
        .filter_map(|idx| self.files.get(idx))
        .collect()
    }

    /// Resolves an imported symbol `(importer_path, specifier, exported_name)` across module boundaries
    /// and barrel re-exports (`export { a as b } from ...`, `export * from ...`) to `(defining_file, local_name)`.
    #[must_use]
    pub(crate) fn resolve_exported_symbol(
        &self,
        importer_path: &Path,
        specifier: &str,
        exported_name: &str,
    ) -> Option<(&FileIr, String)> {
        self.resolve_exported_symbol_depth(importer_path, specifier, exported_name, 0)
    }

    fn resolve_exported_symbol_depth(
        &self,
        importer_path: &Path,
        specifier: &str,
        exported_name: &str,
        depth: usize,
    ) -> Option<(&FileIr, String)> {
        if depth > 8 {
            return None;
        }
        for target_file in self.resolve_imported_module_files(importer_path, specifier) {
            if let Some(found) = self.resolve_export_in_file(target_file, exported_name, depth) {
                return Some(found);
            }
        }
        None
    }

    fn resolve_export_in_file<'a>(
        &'a self,
        target_file: &'a FileIr,
        exported_name: &str,
        depth: usize,
    ) -> Option<(&'a FileIr, String)> {
        // 1. Direct export (`export const foo`, `export default bar`, `export { local as exported }`)
        for exp in &target_file.module.exports {
            if !exp.is_type_only && exp.from_source.is_none() && exp.name == exported_name {
                let local = exp.local_name.clone().unwrap_or_else(|| exp.name.clone());
                return Some((target_file, local));
            }
        }
        // 2. Named re-export (`export { orig as alias } from './other'`)
        for exp in &target_file.module.exports {
            if exp.is_type_only || exp.is_namespace_re_export || exp.name != exported_name {
                continue;
            }
            if let Some(re_spec) = &exp.from_source {
                let upstream_name = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
                if let Some(found) = self.resolve_exported_symbol_depth(
                    &target_file.path,
                    re_spec,
                    upstream_name,
                    depth + 1,
                ) {
                    return Some(found);
                }
            }
        }
        // 3. Wildcard barrel re-export (`export * from './other'`)
        if exported_name == "default" {
            return None;
        }
        for exp in &target_file.module.exports {
            if exp.is_type_only || !exp.is_namespace_re_export || exp.name != "*" {
                continue;
            }
            if let Some(re_spec) = &exp.from_source
                && let Some(found) = self.resolve_exported_symbol_depth(
                    &target_file.path,
                    re_spec,
                    exported_name,
                    depth + 1,
                )
            {
                return Some(found);
            }
        }
        None
    }
}

/// Intra-**Subject** multi-effect **Render Cascade** where one **Effect Node** writes to an
/// intermediate **State Slot** that triggers a second **Effect Node** to update another **State Slot**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MultiEffectCascade {
    /// Index of the upstream **Effect Node** within `SubjectIr::effect_nodes`.
    pub first_effect_index: usize,
    /// Index of the downstream **Effect Node** within `SubjectIr::effect_nodes`.
    pub second_effect_index: usize,
    /// Index of the intermediate **State Slot** written by the first effect.
    pub intermediate_slot_index: usize,
    /// Display name of the intermediate **State Slot**.
    pub intermediate_state_name: String,
    /// Index of the final **State Slot** written by the second effect.
    pub final_slot_index: usize,
    /// Display name of the final **State Slot**.
    pub final_state_name: String,
    /// 1-based source location of the downstream setter call.
    pub loc: SourceLoc,
    /// Byte span of the downstream setter call.
    pub span: ByteSpan,
    /// Ordered **Render Cascade** flow steps across both effects.
    pub steps: Vec<String>,
}

/// Finds all multi-effect **Render Cascades** inside `subject`.
#[must_use]
pub(crate) fn find_multi_effect_cascades(subject: &SubjectIr) -> Vec<MultiEffectCascade> {
    let mut cascades = Vec::new();
    for first in &subject.effect_nodes {
        if first.has_cleanup {
            continue;
        }
        for second in &subject.effect_nodes {
            if second.has_cleanup || first.index == second.index {
                continue;
            }
            collect_cascades_between_effects(first, second, &mut cascades);
        }
    }
    cascades
}

fn collect_cascades_between_effects(
    first: &EffectNode,
    second: &EffectNode,
    out: &mut Vec<MultiEffectCascade>,
) {
    let DepsSpec::Tracked(deps) = &second.deps else {
        return;
    };
    for first_call in &first.sync_setter_calls {
        let Some(mid_idx) = first_call.state_slot_index else {
            continue;
        };
        if !deps
            .iter()
            .any(|d| d.upstream_state_indices.contains(&mid_idx))
        {
            continue;
        }
        for second_call in &second.sync_setter_calls {
            let Some(final_idx) = second_call.state_slot_index else {
                continue;
            };
            if final_idx == mid_idx {
                continue;
            }
            out.push(MultiEffectCascade {
                first_effect_index: first.index,
                second_effect_index: second.index,
                intermediate_slot_index: mid_idx,
                intermediate_state_name: first_call.state_name.clone(),
                final_slot_index: final_idx,
                final_state_name: second_call.state_name.clone(),
                loc: second_call.loc,
                span: second_call.call_span,
                steps: vec![
                    "Render #1 (initial render)".to_string(),
                    format!(
                        "Effect #{} sets intermediate state {:?}",
                        first.index + 1,
                        first_call.state_name
                    ),
                    format!("Render #2 ({:?} updated)", first_call.state_name),
                    format!(
                        "Effect #{} tracks {:?} -> sets {:?}",
                        second.index + 1,
                        first_call.state_name,
                        second_call.state_name
                    ),
                    format!("Render #3 ({:?} updated)", second_call.state_name),
                ],
            });
        }
    }
}

fn collect_indexed_targets(files: &[FileIr]) -> Vec<IndexedTargetFile> {
    files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let norm_path = normalize_path_components(&file.path);
            let stem = strip_source_extension(&norm_path);
            let (base_stem, has_platform_suffix) = strip_platform_suffix(&stem);
            let index_stem = stem.strip_suffix("/index").map(str::to_string);
            let base_index_stem = base_stem.strip_suffix("/index").map(str::to_string);
            let component_names = file
                .subjects
                .iter()
                .filter(|s| s.kind == SubjectKind::Component)
                .filter_map(|s| s.name.clone())
                .collect();
            IndexedTargetFile {
                index,
                path: file.path.clone(),
                norm_path,
                stem,
                base_stem,
                index_stem,
                base_index_stem,
                has_platform_suffix,
                component_names,
            }
        })
        .collect()
}

fn build_platform_sibling_index(targets: &[IndexedTargetFile]) -> HashMap<usize, Vec<usize>> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut suffixed_bases: HashSet<String> = HashSet::new();

    for t in targets {
        if t.has_platform_suffix {
            suffixed_bases.insert(t.base_stem.clone());
        }
    }

    for t in targets {
        if suffixed_bases.contains(&t.base_stem) {
            groups.entry(t.base_stem.clone()).or_default().push(t.index);
        }
    }

    let mut out = HashMap::new();
    for indices in groups.values() {
        if indices.len() < 2 {
            continue;
        }
        for &idx in indices {
            out.insert(idx, indices.clone());
        }
    }
    out
}

fn compile_tsconfig_mappings(manifests: &HashMap<PathBuf, String>) -> Vec<CompiledPathMapping> {
    let mut mappings = Vec::new();
    for (path, content) in manifests {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name == "tsconfig.json"
            || name == "jsconfig.json"
            || (name.starts_with("tsconfig.") && name.ends_with(".json")))
        {
            continue;
        }
        let tsconfig_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let norm_tsconfig_dir = normalize_path_components(tsconfig_dir);
        let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(content)) else {
            continue;
        };
        let Some(compiler_options) = json.get("compilerOptions").and_then(Value::as_object) else {
            continue;
        };
        let base_url = compiler_options
            .get("baseUrl")
            .and_then(Value::as_str)
            .unwrap_or(".");
        let base_dir_path = if norm_tsconfig_dir.is_empty() || norm_tsconfig_dir == "." {
            PathBuf::from(base_url)
        } else {
            tsconfig_dir.join(base_url)
        };
        let base_dir = normalize_path_components(&base_dir_path);

        if let Some(paths_obj) = compiler_options.get("paths").and_then(Value::as_object) {
            for (pattern, target_arr) in paths_obj {
                let Some(arr) = target_arr.as_array() else {
                    continue;
                };
                let targets: Vec<String> = arr
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                if targets.is_empty() {
                    continue;
                }
                if let Some(star_idx) = pattern.find('*') {
                    mappings.push(CompiledPathMapping {
                        base_dir: base_dir.clone(),
                        prefix: pattern[..star_idx].to_string(),
                        suffix: pattern[star_idx + 1..].to_string(),
                        is_wildcard: true,
                        targets,
                    });
                } else {
                    mappings.push(CompiledPathMapping {
                        base_dir: base_dir.clone(),
                        prefix: pattern.clone(),
                        suffix: String::new(),
                        is_wildcard: false,
                        targets,
                    });
                }
            }
        }
        if compiler_options.get("baseUrl").is_some() {
            mappings.push(CompiledPathMapping {
                base_dir,
                prefix: String::new(),
                suffix: String::new(),
                is_wildcard: true,
                targets: vec!["*".to_string()],
            });
        }
    }

    mappings.sort_by(|a, b| {
        let spec_a = if a.is_wildcard {
            a.prefix.len() + a.suffix.len()
        } else {
            usize::MAX
        };
        let spec_b = if b.is_wildcard {
            b.prefix.len() + b.suffix.len()
        } else {
            usize::MAX
        };
        spec_b.cmp(&spec_a)
    });
    mappings
}

fn parse_package_manifests(manifests: &HashMap<PathBuf, String>) -> Vec<PackageManifestInfo> {
    let mut pkgs = Vec::new();
    for (path, content) in manifests {
        if path.file_name().and_then(|n| n.to_str()) != Some("package.json") {
            continue;
        }
        let root_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let norm_root = normalize_path_components(&root_dir);
        let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(content)) else {
            continue;
        };
        let name = json.get("name").and_then(Value::as_str).map(str::to_string);
        let mut entry_specifiers = Vec::new();
        for field in [
            "main", "module", "types", "typings", "browser", "source", "style",
        ] {
            if let Some(val) = json.get(field) {
                collect_string_leaves(val, &mut entry_specifiers);
            }
        }
        if let Some(bin_val) = json.get("bin") {
            collect_string_leaves(bin_val, &mut entry_specifiers);
        }
        if let Some(exports_val) = json.get("exports") {
            collect_string_leaves(exports_val, &mut entry_specifiers);
        }

        let mut script_commands = Vec::new();
        if let Some(scripts_obj) = json.get("scripts").and_then(Value::as_object) {
            for val in scripts_obj.values() {
                if let Some(cmd) = val.as_str() {
                    script_commands.push(cmd.to_string());
                }
            }
        }

        let dependencies = json
            .get("dependencies")
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let dev_dependencies = json
            .get("devDependencies")
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();

        let mut peer_and_optional_dependencies = HashSet::new();
        for field in ["peerDependencies", "optionalDependencies"] {
            if let Some(obj) = json.get(field).and_then(Value::as_object) {
                for k in obj.keys() {
                    peer_and_optional_dependencies.insert(k.clone());
                }
            }
        }

        pkgs.push(PackageManifestInfo {
            manifest_path: path.clone(),
            root_dir,
            norm_root,
            name,
            entry_specifiers,
            script_commands,
            dependencies,
            dev_dependencies,
            peer_and_optional_dependencies,
            raw_content: content.clone(),
        });
    }
    pkgs.sort_by(|a, b| a.manifest_path.cmp(&b.manifest_path));
    pkgs
}

fn collect_string_leaves(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                collect_string_leaves(item, out);
            }
        }
        Value::Object(obj) => {
            for v in obj.values() {
                collect_string_leaves(v, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn extract_expo_plugin_specifiers(
    manifests: &HashMap<PathBuf, String>,
    files: &[FileIr],
) -> Vec<(PathBuf, String)> {
    let mut specs = Vec::new();
    for (path, content) in manifests {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        if name == "app.json"
            && let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(content))
            && let Some(Value::Array(arr)) = json
                .pointer("/expo/plugins")
                .or_else(|| json.get("plugins"))
        {
            for item in arr {
                let spec_str = item.as_str().or_else(|| {
                    item.as_array()
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                });
                if let Some(s) = spec_str {
                    specs.push((parent.clone(), s.to_string()));
                }
            }
        } else if name.starts_with("app.config.") {
            for literal in extract_plugins_array_string_literals(content) {
                specs.push((parent.clone(), literal));
            }
        }
    }
    let _ = files;
    specs
}

fn extract_plugins_array_string_literals(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(plugins_idx) = content.find("plugins") else {
        return out;
    };
    let after = &content[plugins_idx..];
    let Some(open_bracket) = after.find('[') else {
        return out;
    };
    let inside = &after[open_bracket + 1..];
    let mut depth = 1_i32;
    let mut bytes = inside.as_bytes().iter().copied().enumerate();
    while let Some((idx, b)) = bytes.next() {
        if b == b'[' {
            depth += 1;
        } else if b == b']' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        } else if b == b'"' || b == b'\'' {
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
                && let Some(slice) = inside.get(start..end)
            {
                out.push(slice.to_string());
            }
        }
    }
    out
}

fn index_file_caller_sites(
    caller_file: &FileIr,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
    out: &mut HashMap<ComponentTarget, Vec<ResolvedCallerSite>>,
) {
    for site in &caller_file.caller_sites {
        let resolved = ResolvedCallerSite {
            caller_file: caller_file.path.clone(),
            parent_subject_name: site.parent_subject_name.clone(),
            component_name: site.component_name.clone(),
            loc: site.loc,
            span: site.span,
            has_key: site.has_key,
            passed_props: site.passed_props.clone(),
        };

        for target in
            resolve_caller_targets(&caller_file.path, site, targets, ts_mappings, pkg_manifests)
        {
            out.entry(target).or_default().push(resolved.clone());
        }
    }
}

fn resolve_caller_targets(
    caller_path: &Path,
    site: &CallerSite,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<ComponentTarget> {
    if let Some(specifier) = &site.import_source {
        let matched = match_targets_by_specifier(
            caller_path,
            specifier,
            &site.component_name,
            targets,
            ts_mappings,
            pkg_manifests,
        );
        if !matched.is_empty() {
            return matched;
        }
    } else if let Some(same_file) = targets
        .iter()
        .find(|t| t.path == caller_path && t.component_names.contains(&site.component_name))
    {
        return vec![ComponentTarget {
            file: same_file.path.clone(),
            component_name: site.component_name.clone(),
        }];
    }

    targets
        .iter()
        .filter(|t| t.component_names.contains(&site.component_name))
        .map(|t| ComponentTarget {
            file: t.path.clone(),
            component_name: site.component_name.clone(),
        })
        .collect()
}

fn match_targets_by_specifier(
    caller_path: &Path,
    specifier: &str,
    component_name: &str,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<ComponentTarget> {
    let resolved_indices = resolve_specifier_to_target_indices(
        caller_path,
        specifier,
        targets,
        ts_mappings,
        pkg_manifests,
    );
    let mut out = Vec::new();
    for idx in resolved_indices {
        let target = &targets[idx];
        if target.component_names.iter().any(|p| p == component_name) {
            out.push(ComponentTarget {
                file: target.path.clone(),
                component_name: component_name.to_string(),
            });
        } else if let [single_name] = target.component_names.as_slice() {
            out.push(ComponentTarget {
                file: target.path.clone(),
                component_name: single_name.clone(),
            });
        }
    }
    out
}

fn resolve_specifier_to_target_indices(
    importer_path: &Path,
    specifier: &str,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<usize> {
    let clean_spec = specifier
        .split(['?', '#'])
        .next()
        .unwrap_or(specifier)
        .trim();
    if clean_spec.is_empty() {
        return Vec::new();
    }

    // 1. Relative specifier (`./...`, `../...`)
    if clean_spec.starts_with("./")
        || clean_spec.starts_with("../")
        || clean_spec == "."
        || clean_spec == ".."
    {
        let parent = importer_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(""));
        let joined = parent.join(clean_spec);
        let stem = normalize_module_stem(&joined);
        let matched = match_stem_against_targets(&stem, targets);
        if !matched.is_empty() {
            return matched;
        }
        // Build output fallback (`./dist/foo.js` -> `./src/foo.ts`)
        if let Some(src_stem) = replace_output_dir_with_src(&stem) {
            let fallback = match_stem_against_targets(&src_stem, targets);
            if !fallback.is_empty() {
                return fallback;
            }
        }
        return Vec::new();
    }

    // 2. tsconfig.json `paths` & `baseUrl`
    for mapping in ts_mappings {
        let wildcard_slice = if mapping.is_wildcard {
            if !clean_spec.starts_with(&mapping.prefix) || !clean_spec.ends_with(&mapping.suffix) {
                continue;
            }
            let end = clean_spec.len().saturating_sub(mapping.suffix.len());
            if end < mapping.prefix.len() {
                continue;
            }
            &clean_spec[mapping.prefix.len()..end]
        } else {
            if clean_spec != mapping.prefix {
                continue;
            }
            ""
        };

        for target_pat in &mapping.targets {
            let substituted = target_pat.replace('*', wildcard_slice);
            let full_path = if mapping.base_dir.is_empty() || mapping.base_dir == "." {
                PathBuf::from(&substituted)
            } else {
                Path::new(&mapping.base_dir).join(&substituted)
            };
            let candidate_stem = normalize_module_stem(&full_path);
            let matched = match_stem_against_targets(&candidate_stem, targets);
            if !matched.is_empty() {
                return matched;
            }
        }
    }

    // 3. Default `@/` alias fallback
    if let Some(alias_rest) = clean_spec.strip_prefix("@/") {
        let clean_rest = strip_source_extension(&normalize_path_components(Path::new(alias_rest)));
        let src_rest = format!("src/{clean_rest}");
        let mut matched = match_stem_or_suffix_against_targets(&clean_rest, targets);
        if matched.is_empty() {
            matched = match_stem_or_suffix_against_targets(&src_rest, targets);
        }
        if !matched.is_empty() {
            return matched;
        }
    }

    // 4. Monorepo workspace package (`@scope/pkg` or `@scope/pkg/subpath`)
    for ws_pkg in pkg_manifests {
        let Some(pkg_name) = &ws_pkg.name else {
            continue;
        };
        if clean_spec == pkg_name {
            let entry_matches = resolve_package_entry_indices(ws_pkg, targets);
            if !entry_matches.is_empty() {
                return entry_matches;
            }
        } else if let Some(subpath) = clean_spec.strip_prefix(&format!("{pkg_name}/")) {
            let sub_joined = ws_pkg.root_dir.join(subpath);
            let sub_stem = normalize_module_stem(&sub_joined);
            let matched = match_stem_against_targets(&sub_stem, targets);
            if !matched.is_empty() {
                return matched;
            }
            let src_joined = ws_pkg.root_dir.join("src").join(subpath);
            let src_stem = normalize_module_stem(&src_joined);
            let src_matched = match_stem_against_targets(&src_stem, targets);
            if !src_matched.is_empty() {
                return src_matched;
            }
        }
    }

    Vec::new()
}

fn resolve_package_entry_indices(
    pkg: &PackageManifestInfo,
    targets: &[IndexedTargetFile],
) -> Vec<usize> {
    let mut indices = Vec::new();
    for spec in &pkg.entry_specifiers {
        if spec.contains('*') {
            continue;
        }
        let candidate_path = pkg.root_dir.join(spec);
        let stem = normalize_module_stem(&candidate_path);
        for idx in match_stem_against_targets(&stem, targets) {
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }
        if let Some(src_stem) = replace_output_dir_with_src(&stem) {
            for idx in match_stem_against_targets(&src_stem, targets) {
                if !indices.contains(&idx) {
                    indices.push(idx);
                }
            }
        }
    }
    if indices.is_empty() {
        for fallback in ["src/index", "src/main", "index", "main"] {
            let stem = normalize_module_stem(&pkg.root_dir.join(fallback));
            for idx in match_stem_against_targets(&stem, targets) {
                if !indices.contains(&idx) {
                    indices.push(idx);
                }
            }
            if !indices.is_empty() {
                break;
            }
        }
    }
    indices
}

fn match_stem_against_targets(stem: &str, targets: &[IndexedTargetFile]) -> Vec<usize> {
    let (base_stem, _) = strip_platform_suffix(stem);
    let mut out = Vec::new();
    for t in targets {
        if t.stem == stem
            || t.base_stem == base_stem
            || t.index_stem.as_deref() == Some(stem)
            || t.base_index_stem.as_deref() == Some(base_stem.as_str())
        {
            out.push(t.index);
        }
    }
    out
}

fn match_stem_or_suffix_against_targets(stem: &str, targets: &[IndexedTargetFile]) -> Vec<usize> {
    let direct = match_stem_against_targets(stem, targets);
    if !direct.is_empty() {
        return direct;
    }
    let slash_stem = format!("/{stem}");
    let mut out = Vec::new();
    for t in targets {
        if t.stem.ends_with(&slash_stem)
            || t.base_stem.ends_with(&slash_stem)
            || t.index_stem
                .as_deref()
                .is_some_and(|idx| idx.ends_with(&slash_stem))
        {
            out.push(t.index);
        }
    }
    out
}

fn replace_output_dir_with_src(stem: &str) -> Option<String> {
    for out_dir in ["dist", "build", "lib", "esm", "cjs", "out"] {
        let mid = format!("/{out_dir}/");
        if let Some(pos) = stem.rfind(&mid) {
            return Some(format!("{}/src/{}", &stem[..pos], &stem[pos + mid.len()..]));
        }
        let prefix = format!("{out_dir}/");
        if let Some(rest) = stem.strip_prefix(&prefix) {
            return Some(format!("src/{rest}"));
        }
    }
    None
}

fn build_module_edges(
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
        // 1. Static imports
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

        // 2. Re-exports (`export { ... } from '...'` and `export * from '...'`)
        let mut re_exports_by_source: HashMap<String, Vec<(String, String, bool)>> = HashMap::new();
        for exp in &file.module.exports {
            let Some(from_src) = &exp.from_source else {
                continue;
            };
            let orig = exp.local_name.clone().unwrap_or_else(|| exp.name.clone());
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

        // 3. Dynamic `import("...")` and CommonJS `require("...")`
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

        // 4. TypeScript `import("./mod").Type`
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

fn discover_entrypoints_and_roots(
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

    // 1. Explicit package.json entrypoints & script file references
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

    // 2. Expo config plugin local files
    for (dir, spec) in expo_plugin_specs {
        if spec.starts_with('.') || spec.starts_with('/') {
            let stem = normalize_module_stem(&dir.join(spec));
            for idx in match_stem_against_targets(&stem, targets) {
                is_entry_point[idx] = true;
            }
        }
    }

    // 3. React Router route module entries (`route(..., "file")`)
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

    // 4. Framework conventions, default entry globs, and test/config/script exclusions
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

    // Next.js Pages Router, React Router, TanStack Start, Remix routes
    for prefix in [
        "pages/",
        "src/pages/",
        "routes/",
        "src/routes/",
        "app/routes/",
    ] {
        if let Some(after) = base_rel_stem.strip_prefix(prefix) {
            // Exclude private helper folders like `pages/_components/...`
            if !after.split('/').any(|seg| seg.starts_with("_components")) {
                return true;
            }
        }
    }

    // Next.js App Router & Expo Router route segment files under `app/` or `src/app/`
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

fn trace_reachability(
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
fn detect_orphan_files(
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
fn detect_dead_exports(
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

    // 1. Entrypoints propagate usage through any `export *` or `export { x } from` re-export chains
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

    // 2. Consumed symbols across all module edges
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

    // 3. Emit findings for reachable non-entry, non-excluded modules
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

fn detect_unused_dependencies(
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

    // Collect package references in scripts, configs, and peerDependencies
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
    // Only count in non-package.json or outside dependencies declarations; note that in package.json,
    // `"pkg_name": "version"` is followed by `:`, whereas in config arrays/extends it is not a dependency version map.
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

fn detect_circular_dependencies(
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

fn normalize_module_stem(path: &Path) -> String {
    strip_source_extension(&normalize_path_components(path))
}

fn normalize_path_components(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut has_leading_root = false;

    for comp in path.components() {
        match comp {
            Component::RootDir => has_leading_root = true,
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|last| last != "..") {
                    parts.pop();
                } else if !has_leading_root {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(seg) => {
                if let Some(s) = seg.to_str() {
                    parts.push(s.to_string());
                }
            }
        }
    }

    let joined = parts.join("/");
    if has_leading_root {
        format!("/{joined}")
    } else {
        joined
    }
}

fn strip_source_extension(path_str: &str) -> String {
    for suffix in SOURCE_SUFFIXES {
        if let Some(stripped) = path_str.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    path_str.to_string()
}

fn strip_platform_suffix(stem_str: &str) -> (String, bool) {
    for suffix in PLATFORM_SUFFIXES {
        if let Some(stripped) = stem_str.strip_suffix(suffix) {
            return (stripped.to_string(), true);
        }
    }
    (stem_str.to_string(), false)
}

const JSX_DUP_MIN_NODE_COUNT: usize = 5;
const JSX_DUP_MIN_DEPTH: usize = 2;
const JSX_DUP_MIN_OCCURRENCES: usize = 2;

fn detect_duplicate_jsx_families(files: &[FileIr]) -> Vec<DuplicateJsxFamilyFinding> {
    let mut buckets: HashMap<String, (usize, usize, Vec<DuplicateJsxOccurrence>)> = HashMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production {
            continue;
        }
        for sub in &file.jsx_subtrees {
            if sub.node_count < JSX_DUP_MIN_NODE_COUNT || sub.depth < JSX_DUP_MIN_DEPTH {
                continue;
            }
            let entry = buckets
                .entry(sub.fingerprint.clone())
                .or_insert_with(|| (sub.node_count, sub.depth, Vec::new()));
            entry.2.push(DuplicateJsxOccurrence {
                file_index: file_idx,
                path: file.path.clone(),
                root_name: sub.root_name.clone(),
                enclosing_subject: sub.enclosing_subject.clone(),
                composition_root_offset: sub.composition_root_offset,
                composition_path: sub.composition_path.clone(),
                span: sub.span,
                loc: sub.loc,
                end_line: sub.end_line,
            });
        }
    }

    let mut families = Vec::new();
    for (fingerprint, (node_count, depth, mut occurrences)) in buckets {
        if occurrences.len() < JSX_DUP_MIN_OCCURRENCES {
            continue;
        }
        occurrences.sort_by(|a, b| {
            (&a.path, a.span.start, a.span.end).cmp(&(&b.path, b.span.start, b.span.end))
        });
        let distinct_files: HashSet<&PathBuf> = occurrences.iter().map(|o| &o.path).collect();
        let distinct_file_count = distinct_files.len();
        if distinct_file_count == 1 {
            let distinct_roots: HashSet<u32> = occurrences
                .iter()
                .filter_map(|o| o.composition_root_offset)
                .collect();
            if distinct_roots.len() < 2 {
                continue;
            }
        }

        let total_lines: u32 = occurrences
            .iter()
            .map(|o| o.end_line.saturating_sub(o.loc.line) + 1)
            .sum();
        let max_single_lines: u32 = occurrences
            .iter()
            .map(|o| o.end_line.saturating_sub(o.loc.line) + 1)
            .max()
            .unwrap_or(0);
        let estimated_removable_line_count = total_lines.saturating_sub(max_single_lines);
        let occurrence_count = occurrences.len();

        families.push(DuplicateJsxFamilyFinding {
            fingerprint,
            node_count,
            depth,
            occurrence_count,
            distinct_file_count,
            estimated_removable_line_count,
            occurrences,
        });
    }

    suppress_nested_jsx_families(&mut families);
    families.sort_by(|a, b| {
        let rem_a = a.node_count * (a.occurrence_count.saturating_sub(1));
        let rem_b = b.node_count * (b.occurrence_count.saturating_sub(1));
        rem_b
            .cmp(&rem_a)
            .then_with(|| {
                b.estimated_removable_line_count
                    .cmp(&a.estimated_removable_line_count)
            })
            .then_with(|| b.occurrence_count.cmp(&a.occurrence_count))
            .then_with(|| b.distinct_file_count.cmp(&a.distinct_file_count))
            .then_with(|| b.node_count.cmp(&a.node_count))
            .then_with(|| {
                let oa = &a.occurrences[0];
                let ob = &b.occurrences[0];
                (&oa.path, oa.span.start).cmp(&(&ob.path, ob.span.start))
            })
    });
    families
}

fn suppress_nested_jsx_families(families: &mut Vec<DuplicateJsxFamilyFinding>) {
    families.sort_by(|a, b| {
        b.node_count
            .cmp(&a.node_count)
            .then_with(|| b.depth.cmp(&a.depth))
    });
    let mut maximal: Vec<DuplicateJsxFamilyFinding> = Vec::with_capacity(families.len());
    for candidate in families.drain(..) {
        let is_nested = maximal
            .iter()
            .any(|outer| jsx_family_is_nested_within(&candidate, outer));
        if !is_nested {
            maximal.push(candidate);
        }
    }
    *families = maximal;
}

fn jsx_family_is_nested_within(
    candidate: &DuplicateJsxFamilyFinding,
    outer: &DuplicateJsxFamilyFinding,
) -> bool {
    candidate.occurrences.iter().all(|inner_occ| {
        outer.occurrences.iter().any(|outer_occ| {
            inner_occ.file_index == outer_occ.file_index
                && inner_occ.span.start >= outer_occ.span.start
                && inner_occ.span.end <= outer_occ.span.end
        })
    })
}
