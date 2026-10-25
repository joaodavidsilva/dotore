//! Module, `tsconfig.json`, workspace package, platform sibling, and barrel re-export resolution for [`ProjectGraph`].

use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
};

use serde_json::Value;

use crate::{
    config::strip_jsonc,
    ir::{FileIr, SubjectKind},
};

use super::ProjectGraph;

#[derive(Debug, Clone)]
pub(super) struct IndexedTargetFile {
    pub index: usize,
    pub path: PathBuf,
    pub norm_path: String,
    pub stem: String,
    pub base_stem: String,
    pub index_stem: Option<String>,
    pub base_index_stem: Option<String>,
    pub has_platform_suffix: bool,
    pub component_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledPathMapping {
    pub base_dir: String,
    pub prefix: String,
    pub suffix: String,
    pub is_wildcard: bool,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct PackageManifestInfo {
    pub manifest_path: PathBuf,
    pub root_dir: PathBuf,
    pub norm_root: String,
    pub name: Option<String>,
    pub entry_specifiers: Vec<String>,
    pub script_commands: Vec<String>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    pub peer_and_optional_dependencies: HashSet<String>,
    pub raw_content: String,
}

#[derive(Debug, Clone)]
pub(super) struct ModuleEdge {
    pub source: usize,
    pub target: usize,
    pub is_dynamic: bool,
    pub is_type_only: bool,
    pub is_re_export: bool,
    pub is_side_effect: bool,
    pub imported_symbols: Vec<EdgeSymbol>,
    pub re_export_mappings: Vec<(String, String, bool)>,
}

#[derive(Debug, Clone)]
pub(super) struct EdgeSymbol {
    pub imported_name: String,
    pub local_name: String,
    pub is_default: bool,
    pub is_namespace: bool,
    pub is_type_only: bool,
}

pub(super) const SOURCE_SUFFIXES: &[&str] = &[
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

impl ProjectGraph {
    pub(super) fn find_imported_file(
        &self,
        importer_path: &Path,
        specifier: &str,
    ) -> Option<&FileIr> {
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
    fn resolve_imported_module_files(&self, importer_path: &Path, specifier: &str) -> Vec<&FileIr> {
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
        for exp in &target_file.module.exports {
            if !exp.is_type_only && exp.from_source.is_none() && exp.name == exported_name {
                let local = exp
                    .local_name
                    .as_deref()
                    .unwrap_or(exp.name.as_str())
                    .to_string();
                return Some((target_file, local));
            }
        }
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

pub(super) fn collect_indexed_targets(files: &[FileIr]) -> Vec<IndexedTargetFile> {
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

pub(super) fn build_platform_sibling_index(
    targets: &[IndexedTargetFile],
) -> HashMap<usize, Vec<usize>> {
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

pub(super) fn compile_tsconfig_mappings(
    manifests: &HashMap<PathBuf, String>,
) -> Vec<CompiledPathMapping> {
    let mut mappings = Vec::new();
    for (path, content) in manifests {
        if is_tsconfig_path(path) {
            compile_single_tsconfig_mappings(path, content, &mut mappings);
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

fn is_tsconfig_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name == "tsconfig.json"
        || name == "jsconfig.json"
        || (name.starts_with("tsconfig.") && name.ends_with(".json"))
}

fn compile_single_tsconfig_mappings(
    path: &Path,
    content: &str,
    mappings: &mut Vec<CompiledPathMapping>,
) {
    let tsconfig_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let norm_tsconfig_dir = normalize_path_components(tsconfig_dir);
    let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(content)) else {
        return;
    };
    let Some(compiler_options) = json.get("compilerOptions").and_then(Value::as_object) else {
        return;
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
            if let Some(mapping) = compile_path_pattern(&base_dir, pattern, target_arr) {
                mappings.push(mapping);
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

fn compile_path_pattern(
    base_dir: &str,
    pattern: &str,
    target_arr: &Value,
) -> Option<CompiledPathMapping> {
    let targets: Vec<String> = target_arr
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    if targets.is_empty() {
        return None;
    }
    if let Some(star_idx) = pattern.find('*') {
        Some(CompiledPathMapping {
            base_dir: base_dir.to_string(),
            prefix: pattern[..star_idx].to_string(),
            suffix: pattern[star_idx + 1..].to_string(),
            is_wildcard: true,
            targets,
        })
    } else {
        Some(CompiledPathMapping {
            base_dir: base_dir.to_string(),
            prefix: pattern.to_string(),
            suffix: String::new(),
            is_wildcard: false,
            targets,
        })
    }
}

pub(super) fn parse_package_manifests(
    manifests: &HashMap<PathBuf, String>,
) -> Vec<PackageManifestInfo> {
    let mut pkgs: Vec<PackageManifestInfo> = manifests
        .iter()
        .filter_map(|(path, content)| parse_single_package_manifest(path, content))
        .collect();
    pkgs.sort_by(|a, b| a.manifest_path.cmp(&b.manifest_path));
    pkgs
}

fn parse_single_package_manifest(path: &Path, content: &str) -> Option<PackageManifestInfo> {
    if path.file_name().and_then(|n| n.to_str()) != Some("package.json") {
        return None;
    }
    let root_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let norm_root = normalize_path_components(&root_dir);
    let json = serde_json::from_str::<Value>(&strip_jsonc(content)).ok()?;
    let name = json.get("name").and_then(Value::as_str).map(str::to_string);

    let mut entry_specifiers = Vec::new();
    for field in [
        "main", "module", "types", "typings", "browser", "source", "style", "bin", "exports",
    ] {
        if let Some(val) = json.get(field) {
            collect_string_leaves(val, &mut entry_specifiers);
        }
    }

    let script_commands = json
        .get("scripts")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.values()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let dependencies = collect_json_object_keys(&json, "dependencies");
    let dev_dependencies = collect_json_object_keys(&json, "devDependencies");
    let mut peer_and_optional_dependencies: HashSet<String> =
        collect_json_object_keys(&json, "peerDependencies")
            .into_iter()
            .collect();
    peer_and_optional_dependencies.extend(collect_json_object_keys(&json, "optionalDependencies"));

    Some(PackageManifestInfo {
        manifest_path: path.to_path_buf(),
        root_dir,
        norm_root,
        name,
        entry_specifiers,
        script_commands,
        dependencies,
        dev_dependencies,
        peer_and_optional_dependencies,
        raw_content: content.to_string(),
    })
}

fn collect_json_object_keys(json: &Value, field: &str) -> Vec<String> {
    json.get(field)
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
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

pub(super) fn extract_expo_plugin_specifiers(
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
        } else if name == "angular.json" {
            collect_angular_json_entrypoint_specs(&parent, content, &mut specs);
        }
    }
    let _ = files;
    specs
}

fn collect_angular_json_entrypoint_specs(
    parent: &Path,
    content: &str,
    specs: &mut Vec<(PathBuf, String)>,
) {
    for proj in dotore_core::config::parse_angular_workspace_projects(content) {
        let proj_dir = if proj.root_rel.is_empty() {
            parent.to_path_buf()
        } else {
            parent.join(&proj.root_rel)
        };
        for ep in proj.entrypoints {
            let ep_str = ep.to_string_lossy();
            let rel_spec = if ep_str.starts_with('.') || ep_str.starts_with('/') {
                ep_str.into_owned()
            } else {
                format!("./{ep_str}")
            };
            specs.push((parent.to_path_buf(), rel_spec.clone()));
            if proj_dir != parent {
                specs.push((proj_dir.clone(), rel_spec));
            }
        }
    }
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

pub(super) fn resolve_specifier_to_target_indices(
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

    if is_relative_specifier(clean_spec) {
        return resolve_relative_specifier(importer_path, clean_spec, targets);
    }

    let mapped = resolve_tsconfig_mapped_specifier(clean_spec, targets, ts_mappings);
    if !mapped.is_empty() {
        return mapped;
    }

    if let Some(alias_rest) = clean_spec.strip_prefix("@/") {
        let matched = resolve_at_slash_alias(alias_rest, targets);
        if !matched.is_empty() {
            return matched;
        }
    }

    resolve_workspace_package_specifier(clean_spec, targets, pkg_manifests)
}

fn is_relative_specifier(clean_spec: &str) -> bool {
    clean_spec.starts_with("./")
        || clean_spec.starts_with("../")
        || clean_spec == "."
        || clean_spec == ".."
}

fn resolve_relative_specifier(
    importer_path: &Path,
    clean_spec: &str,
    targets: &[IndexedTargetFile],
) -> Vec<usize> {
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
    if let Some(src_stem) = replace_output_dir_with_src(&stem) {
        return match_stem_against_targets(&src_stem, targets);
    }
    Vec::new()
}

fn resolve_tsconfig_mapped_specifier(
    clean_spec: &str,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
) -> Vec<usize> {
    for mapping in ts_mappings {
        let Some(wildcard_slice) = match_tsconfig_mapping_pattern(clean_spec, mapping) else {
            continue;
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
    Vec::new()
}

fn match_tsconfig_mapping_pattern<'a>(
    clean_spec: &'a str,
    mapping: &CompiledPathMapping,
) -> Option<&'a str> {
    if mapping.is_wildcard {
        if !clean_spec.starts_with(&mapping.prefix) || !clean_spec.ends_with(&mapping.suffix) {
            return None;
        }
        let end = clean_spec.len().saturating_sub(mapping.suffix.len());
        if end < mapping.prefix.len() {
            return None;
        }
        clean_spec.get(mapping.prefix.len()..end)
    } else {
        (clean_spec == mapping.prefix).then_some("")
    }
}

fn resolve_at_slash_alias(alias_rest: &str, targets: &[IndexedTargetFile]) -> Vec<usize> {
    let clean_rest = strip_source_extension(&normalize_path_components(Path::new(alias_rest)));
    let matched = match_stem_or_suffix_against_targets(&clean_rest, targets);
    if !matched.is_empty() {
        return matched;
    }
    let src_rest = format!("src/{clean_rest}");
    match_stem_or_suffix_against_targets(&src_rest, targets)
}

fn resolve_workspace_package_specifier(
    clean_spec: &str,
    targets: &[IndexedTargetFile],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<usize> {
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
            for candidate in [
                ws_pkg.root_dir.join(subpath),
                ws_pkg.root_dir.join("src").join(subpath),
            ] {
                let matched = match_stem_against_targets(&normalize_module_stem(&candidate), targets);
                if !matched.is_empty() {
                    return matched;
                }
            }
        }
    }
    Vec::new()
}

pub(super) fn resolve_package_entry_indices(
    pkg: &PackageManifestInfo,
    targets: &[IndexedTargetFile],
) -> Vec<usize> {
    let mut indices = Vec::new();
    for spec in &pkg.entry_specifiers {
        if spec.contains('*') {
            continue;
        }
        let stem = normalize_module_stem(&pkg.root_dir.join(spec));
        extend_unique_indices(&mut indices, match_stem_against_targets(&stem, targets));
        if let Some(src_stem) = replace_output_dir_with_src(&stem) {
            extend_unique_indices(&mut indices, match_stem_against_targets(&src_stem, targets));
        }
    }
    if indices.is_empty() {
        for fallback in ["src/index", "src/main", "index", "main"] {
            let stem = normalize_module_stem(&pkg.root_dir.join(fallback));
            extend_unique_indices(&mut indices, match_stem_against_targets(&stem, targets));
            if !indices.is_empty() {
                break;
            }
        }
    }
    indices
}

fn extend_unique_indices(out: &mut Vec<usize>, candidates: Vec<usize>) {
    for idx in candidates {
        if !out.contains(&idx) {
            out.push(idx);
        }
    }
}

pub(super) fn match_stem_against_targets(stem: &str, targets: &[IndexedTargetFile]) -> Vec<usize> {
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

pub(super) fn normalize_module_stem(path: &Path) -> String {
    strip_source_extension(&normalize_path_components(path))
}

pub(crate) fn normalize_path_components(path: &Path) -> String {
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

pub(super) fn strip_source_extension(path_str: &str) -> String {
    for suffix in SOURCE_SUFFIXES {
        if let Some(stripped) = path_str.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    path_str.to_string()
}

pub(super) fn strip_platform_suffix(stem_str: &str) -> (String, bool) {
    for suffix in PLATFORM_SUFFIXES {
        if let Some(stripped) = stem_str.strip_suffix(suffix) {
            return (stripped.to_string(), true);
        }
    }
    (stem_str.to_string(), false)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    use crate::{graph::ProjectGraph, ir::parse_file_ir};

    #[test]
    fn resolves_exported_symbols_through_tsconfig_aliases_and_barrels() {
        let mut manifests = HashMap::new();
        manifests.insert(
            PathBuf::from("tsconfig.json"),
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@ui/*": ["src/ui/*"] } } }"#
                .to_string(),
        );
        let button = parse_file_ir(
            Path::new("src/ui/Button.tsx"),
            "export function PrimaryButton() { return <button />; }",
        );
        let barrel = parse_file_ir(
            Path::new("src/ui/index.ts"),
            "export { PrimaryButton as Button } from './Button';",
        );
        let app = parse_file_ir(
            Path::new("src/App.tsx"),
            "import { Button } from '@ui/index'; export function App() { return <Button />; }",
        );

        let graph = ProjectGraph::build_with_manifests(vec![button, barrel, app], manifests);
        let (defining_file, local_name) = graph
            .resolve_exported_symbol(Path::new("src/App.tsx"), "@ui/index", "Button")
            .expect("resolved symbol");
        assert_eq!(defining_file.path, Path::new("src/ui/Button.tsx"));
        assert_eq!(local_name, "PrimaryButton");
    }
}
