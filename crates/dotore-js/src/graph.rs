//! Project-level graph of parsed [`FileIr`]s, cross-file module resolution,
//! entrypoint reachability, dead-code/unused-dependency analysis, circular dependency
//! SCC detection, JSX **Caller Sites**, and **Render Cascades**.

pub(crate) mod callers_and_cascades;
pub(crate) mod dead_code;
pub(crate) mod duplicate_jsx;
pub(crate) mod resolution;

use std::{collections::HashMap, path::PathBuf};

pub use dotore_core::ir::ResolvedCallerSite;
pub(crate) use callers_and_cascades::{MultiEffectCascade, find_multi_effect_cascades};

use crate::ir::{ByteSpan, FileIr, SourceLoc};

use callers_and_cascades::{ComponentTarget, index_file_caller_sites};
use dead_code::{
    detect_circular_dependencies, detect_dead_exports, detect_orphan_files,
    detect_unused_dependencies, discover_entrypoints_and_roots, trace_reachability,
};
use duplicate_jsx::detect_duplicate_jsx_families;
use resolution::{
    CompiledPathMapping, IndexedTargetFile, PackageManifestInfo, build_module_edges,
    build_platform_sibling_index, collect_indexed_targets, compile_tsconfig_mappings,
    extract_expo_plugin_specifiers, parse_package_manifests, resolve_specifier_to_target_indices,
};

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
}
