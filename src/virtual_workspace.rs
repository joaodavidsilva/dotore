//! In-memory virtual workspace package and manifest extraction for `analyze_project_sources`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(feature = "js")]
use dotore_js::JsLanguageAnalyzer;
#[cfg(feature = "py")]
use dotore_py::PyLanguageAnalyzer;
#[cfg(feature = "rs")]
use dotore_rs::RsLanguageAnalyzer;

#[cfg(any(feature = "js", feature = "py", feature = "rs"))]
use crate::LanguageAnalyzer;
use crate::{CapabilityGate, DotoreConfig, WorkspacePackage};

pub(super) struct VirtualWorkspaceSplit {
    pub packages: Vec<WorkspacePackage>,
    pub manifests: HashMap<PathBuf, String>,
    pub source_files: Vec<(PathBuf, String)>,
}

#[derive(Default)]
struct VirtualManifestInventory {
    pkg_jsons: Vec<(PathBuf, PathBuf)>,
    angular_jsons: Vec<(PathBuf, PathBuf)>,
    py_manifests: Vec<(PathBuf, PathBuf, String)>,
    py_typed_paths: Vec<PathBuf>,
    cargo_tomls: Vec<(PathBuf, PathBuf)>,
    config_files: Vec<(PathBuf, PathBuf, String)>,
    compiler_configs: Vec<(PathBuf, PathBuf)>,
    manifests: HashMap<PathBuf, String>,
    source_files: Vec<(PathBuf, String)>,
}

fn is_py_manifest_filename(file_name: &str) -> bool {
    matches!(file_name, "pyproject.toml" | "requirements.txt")
        || (file_name.starts_with("requirements") && file_name.ends_with(".txt"))
        || (file_name.starts_with("constraints") && file_name.ends_with(".txt"))
}

fn is_rust_lock_or_cargo_config(file_name: &str, path: &Path) -> bool {
    if file_name == "Cargo.lock" {
        return true;
    }
    let norm = path.to_string_lossy().replace('\\', "/");
    norm.ends_with(".cargo/config.toml") || norm.ends_with(".cargo/config")
}

fn record_fallback_virtual_file_entry(
    inv: &mut VirtualManifestInventory,
    file_name: &str,
    parent_dir: PathBuf,
    path: PathBuf,
    content: String,
) {
    if is_py_manifest_filename(file_name) {
        inv.py_manifests.push((parent_dir, path, content));
    } else if is_rust_lock_or_cargo_config(file_name, &path) {
        inv.manifests.insert(path, content);
    } else if is_non_js_manifest_filename(file_name) {
        if is_compiler_config_name(file_name) {
            inv.compiler_configs.push((parent_dir, path.clone()));
        }
        inv.manifests.insert(path, content);
    } else if file_name.starts_with("dotore.config.") {
        inv.config_files.push((parent_dir, path, content));
    } else {
        if is_compiler_config_name(file_name) {
            inv.compiler_configs.push((parent_dir, path.clone()));
            inv.manifests.insert(path.clone(), content.clone());
        } else if file_name.contains(".config.") || file_name.contains(".setup.") {
            inv.manifests.insert(path.clone(), content.clone());
        }
        inv.source_files.push((path, content));
    }
}

fn record_virtual_file_entry(
    inv: &mut VirtualManifestInventory,
    path: PathBuf,
    content: String,
) {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    let parent_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let is_in_node_modules = path
        .to_string_lossy()
        .replace('\\', "/")
        .contains("node_modules/");

    match file_name.as_str() {
        "package.json" => {
            if !is_in_node_modules {
                inv.pkg_jsons.push((parent_dir, path.clone()));
            }
            inv.manifests.insert(path, content);
        }
        "angular.json" => {
            if !is_in_node_modules {
                inv.angular_jsons.push((parent_dir, path.clone()));
            }
            inv.manifests.insert(path, content);
        }
        "py.typed" => inv.py_typed_paths.push(path),
        "Cargo.toml" => {
            inv.cargo_tomls.push((parent_dir, path.clone()));
            inv.manifests.insert(path, content);
        }
        _ => record_fallback_virtual_file_entry(inv, &file_name, parent_dir, path, content),
    }
}

fn collect_virtual_manifest_inventory(files: Vec<(PathBuf, String)>) -> VirtualManifestInventory {
    let mut inv = VirtualManifestInventory::default();
    for (path, content) in files {
        record_virtual_file_entry(&mut inv, path, content);
    }
    inv
}

fn resolve_virtual_root_config(inv: &VirtualManifestInventory) -> DotoreConfig {
    inv.config_files
        .iter()
        .find(|(dir, _, _)| dir == Path::new("."))
        .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
        .or_else(|| {
            inv.pkg_jsons
                .iter()
                .find(|(dir, _)| dir == Path::new("."))
                .and_then(|(_, p)| inv.manifests.get(p))
                .and_then(|c| DotoreConfig::from_package_json_str(c))
        })
        .or_else(|| find_pyproject_config_in_dir(&inv.py_manifests, Path::new(".")))
        .or_else(|| {
            inv.config_files
                .first()
                .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
        })
        .unwrap_or_default()
}

#[cfg(feature = "js")]
fn populate_virtual_js_and_angular_packages(
    inv: &VirtualManifestInventory,
    root_config: &DotoreConfig,
    packages: &mut Vec<WorkspacePackage>,
) {
    let js_analyzer = JsLanguageAnalyzer;
    for (dir, pkg_path) in &inv.pkg_jsons {
        let pkg_content = inv.manifests.get(pkg_path).map_or("", String::as_str);
        let mut dir_manifest_sources: Vec<(PathBuf, &str)> =
            vec![(dir.join("package.json"), pkg_content)];
        for (ng_dir, ng_path) in &inv.angular_jsons {
            if (ng_dir == dir || ng_dir == Path::new("."))
                && let Some(ng_text) = inv.manifests.get(ng_path)
            {
                dir_manifest_sources.push((ng_path.clone(), ng_text.as_str()));
            }
        }
        for (c_dir, c_path) in &inv.compiler_configs {
            if c_dir == dir
                && let Some(c_text) = inv.manifests.get(c_path)
            {
                dir_manifest_sources.push((c_path.clone(), c_text.as_str()));
            }
        }
        let gate = js_analyzer.infer_capability_gate(dir, &dir_manifest_sources);
        let local_cfg = inv
            .config_files
            .iter()
            .find(|(c_dir, _, _)| c_dir == dir)
            .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
            .or_else(|| DotoreConfig::from_package_json_str(pkg_content))
            .unwrap_or_else(|| root_config.clone());

        let name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string();
        packages.push(WorkspacePackage {
            name,
            root_dir: dir.clone(),
            capability_gate: gate,
            config: local_cfg,
        });
    }

    for (ng_dir, ng_path) in &inv.angular_jsons {
        populate_single_angular_workspace(inv, ng_dir, ng_path, root_config, packages);
    }
}

#[cfg(feature = "js")]
fn populate_single_angular_workspace(
    inv: &VirtualManifestInventory,
    ng_dir: &PathBuf,
    ng_path: &PathBuf,
    root_config: &DotoreConfig,
    packages: &mut Vec<WorkspacePackage>,
) {
    let js_analyzer = JsLanguageAnalyzer;
    let ng_text = inv.manifests.get(ng_path).map_or("", String::as_str);
    if !packages.iter().any(|p| &p.root_dir == ng_dir) {
        let dir_manifest_sources: Vec<(PathBuf, &str)> = vec![(ng_path.clone(), ng_text)];
        let gate = js_analyzer.infer_capability_gate(ng_dir, &dir_manifest_sources);
        let local_cfg = inv
            .config_files
            .iter()
            .find(|(c_dir, _, _)| c_dir == ng_dir)
            .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
            .unwrap_or_else(|| root_config.clone());
        let name = ng_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string();
        packages.push(WorkspacePackage {
            name,
            root_dir: ng_dir.clone(),
            capability_gate: gate,
            config: local_cfg,
        });
    }

    let ng_projects = dotore_core::parse_angular_workspace_projects(ng_text);
    if ng_projects.is_empty() {
        return;
    }
    let (base_gate, base_cfg) = packages
        .iter()
        .find(|p| &p.root_dir == ng_dir)
        .map_or_else(
            || {
                let dir_manifest_sources: Vec<(PathBuf, &str)> = vec![(ng_path.clone(), ng_text)];
                (
                    js_analyzer.infer_capability_gate(ng_dir, &dir_manifest_sources),
                    root_config.clone(),
                )
            },
            |p| (p.capability_gate.clone(), p.config.clone()),
        );
    let has_root_project = ng_projects.iter().any(|p| p.root_rel.is_empty());
    let sub_dirs: Vec<PathBuf> = ng_projects
        .iter()
        .filter(|p| !p.root_rel.is_empty())
        .map(|p| {
            if ng_dir == Path::new(".") {
                PathBuf::from(&p.root_rel)
            } else {
                ng_dir.join(&p.root_rel)
            }
        })
        .collect();
    let has_non_js_at_ng_dir = inv.py_manifests.iter().any(|(d, _, _)| d == ng_dir)
        || inv.cargo_tomls.iter().any(|(d, _)| d == ng_dir);
    let has_root_only_source = inv.source_files.iter().any(|(p, _)| {
        let in_ng_dir = ng_dir == Path::new(".") || p.starts_with(ng_dir);
        in_ng_dir && !sub_dirs.iter().any(|sd| p.starts_with(sd))
    });
    if !has_root_project && !has_non_js_at_ng_dir && !has_root_only_source {
        packages.retain(|p| &p.root_dir != ng_dir);
    }
    for spec in ng_projects {
        apply_virtual_angular_project_spec(
            ng_dir,
            &base_gate,
            &base_cfg,
            &inv.config_files,
            spec,
            packages,
        );
    }
}

#[cfg(feature = "py")]
fn populate_virtual_py_packages(
    inv: &VirtualManifestInventory,
    root_config: &DotoreConfig,
    packages: &mut Vec<WorkspacePackage>,
) {
    let py = PyLanguageAnalyzer::new();
    let mut py_dirs: Vec<&Path> = Vec::new();
    for (dir, _, _) in &inv.py_manifests {
        if !py_dirs.contains(&dir.as_path()) {
            py_dirs.push(dir.as_path());
        }
    }
    for dir in py_dirs {
        let mut dir_manifests: Vec<(PathBuf, &str)> = inv
            .py_manifests
            .iter()
            .filter(|(d, _, _)| d.as_path() == dir)
            .map(|(_, p, c)| (p.clone(), c.as_str()))
            .collect();
        for pt in &inv.py_typed_paths {
            if dir == Path::new(".") || pt.starts_with(dir) {
                dir_manifests.push((pt.clone(), ""));
            }
        }
        let py_gate = py.infer_capability_gate(dir, &dir_manifests);
        if let Some(existing) = packages.iter_mut().find(|p| p.root_dir == dir) {
            existing.capability_gate.merge(&py_gate);
        } else {
            let local_cfg = inv
                .config_files
                .iter()
                .find(|(c_dir, _, _)| c_dir.as_path() == dir)
                .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
                .or_else(|| find_pyproject_config_in_dir(&inv.py_manifests, dir))
                .unwrap_or_else(|| root_config.clone());
            let name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("root")
                .to_string();
            packages.push(WorkspacePackage {
                name,
                root_dir: dir.to_path_buf(),
                capability_gate: py_gate,
                config: local_cfg,
            });
        }
    }
}

#[cfg(feature = "rs")]
fn populate_virtual_rs_packages(
    inv: &VirtualManifestInventory,
    root_config: &DotoreConfig,
    packages: &mut Vec<WorkspacePackage>,
) {
    let rs_extra_manifests: Vec<(PathBuf, &str)> = inv
        .manifests
        .iter()
        .filter(|(p, _)| {
            let s = p.to_string_lossy().replace('\\', "/");
            s.ends_with("Cargo.lock")
                || s.ends_with(".cargo/config.toml")
                || s.ends_with(".cargo/config")
        })
        .map(|(p, c)| (p.clone(), c.as_str()))
        .collect();
    for (idx, (dir, cargo_path)) in inv.cargo_tomls.iter().enumerate() {
        let cargo_content = inv.manifests.get(cargo_path).map_or("", String::as_str);
        let mut rs_sources = vec![
            (cargo_path.clone(), cargo_content),
            (PathBuf::from("__virtual__"), ""),
        ];
        rs_sources.extend(rs_extra_manifests.iter().cloned());
        let mut rs_gate = RsLanguageAnalyzer.infer_capability_gate(dir, &rs_sources);
        if idx > 0 {
            rs_gate
                .dependencies
                .insert("__owns_workspace_manifests".to_string(), "false".to_string());
        }
        if let Some(existing) = packages.iter_mut().find(|p| &p.root_dir == dir) {
            existing.capability_gate.merge(&rs_gate);
        } else {
            let local_cfg = inv
                .config_files
                .iter()
                .find(|(c_dir, _, _)| c_dir == dir)
                .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
                .unwrap_or_else(|| root_config.clone());
            let name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("root")
                .to_string();
            packages.push(WorkspacePackage {
                name,
                root_dir: dir.clone(),
                capability_gate: rs_gate,
                config: local_cfg,
            });
        }
    }
    if inv.cargo_tomls.is_empty() && !rs_extra_manifests.is_empty() {
        let mut rs_sources = vec![(PathBuf::from("__virtual__"), "")];
        rs_sources.extend(rs_extra_manifests.iter().cloned());
        let rs_gate = RsLanguageAnalyzer.infer_capability_gate(Path::new("."), &rs_sources);
        if let Some(existing) = packages.iter_mut().find(|p| p.root_dir == Path::new(".")) {
            existing.capability_gate.merge(&rs_gate);
        } else {
            packages.push(WorkspacePackage {
                name: "root".to_string(),
                root_dir: PathBuf::from("."),
                capability_gate: rs_gate,
                config: root_config.clone(),
            });
        }
    }
}

fn ensure_default_virtual_package_capabilities(
    inv: &VirtualManifestInventory,
    root_config: DotoreConfig,
    packages: &mut Vec<WorkspacePackage>,
) {
    #[cfg(feature = "py")]
    let has_py_files = inv
        .source_files
        .iter()
        .any(|(p, _)| PyLanguageAnalyzer.supports_path(p));
    #[cfg(not(feature = "py"))]
    let has_py_files = false;

    #[cfg(feature = "rs")]
    let has_rs_files = inv
        .source_files
        .iter()
        .any(|(p, _)| RsLanguageAnalyzer.supports_path(p));
    #[cfg(not(feature = "rs"))]
    let has_rs_files = false;

    if packages.is_empty() {
        let mut default_gate = CapabilityGate::default_react();
        if has_py_files {
            let mut py_default = CapabilityGate::default_python();
            if !inv.py_typed_paths.is_empty() {
                py_default.entrypoints.insert(PathBuf::from("py.typed"));
            }
            default_gate.merge(&py_default);
        }
        if has_rs_files {
            default_gate.merge(&CapabilityGate::default_rust());
        }
        packages.push(WorkspacePackage {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: default_gate,
            config: root_config,
        });
    } else {
        if inv.py_manifests.is_empty() && has_py_files {
            let py_default = CapabilityGate::default_python();
            for pkg in &mut *packages {
                pkg.capability_gate.merge(&py_default);
            }
        }
        if inv.cargo_tomls.is_empty() && has_rs_files {
            let rs_default = CapabilityGate::default_rust();
            for pkg in &mut *packages {
                pkg.capability_gate.merge(&rs_default);
            }
        }
    }
}

pub(crate) fn extract_virtual_workspace_packages(
    files: Vec<(PathBuf, String)>,
) -> VirtualWorkspaceSplit {
    let inv = collect_virtual_manifest_inventory(files);
    let root_config = resolve_virtual_root_config(&inv);
    let mut packages: Vec<WorkspacePackage> = Vec::new();

    #[cfg(feature = "js")]
    populate_virtual_js_and_angular_packages(&inv, &root_config, &mut packages);
    #[cfg(feature = "py")]
    populate_virtual_py_packages(&inv, &root_config, &mut packages);
    #[cfg(feature = "rs")]
    populate_virtual_rs_packages(&inv, &root_config, &mut packages);

    ensure_default_virtual_package_capabilities(&inv, root_config, &mut packages);

    VirtualWorkspaceSplit {
        packages,
        manifests: inv.manifests,
        source_files: inv.source_files,
    }
}

fn find_pyproject_config_in_dir(
    py_manifests: &[(PathBuf, PathBuf, String)],
    dir: &Path,
) -> Option<DotoreConfig> {
    py_manifests
        .iter()
        .find(|(d, p, _)| {
            d.as_path() == dir && p.file_name().and_then(|n| n.to_str()) == Some("pyproject.toml")
        })
        .and_then(|(_, _, c)| DotoreConfig::from_pyproject_toml_str(c))
}

#[cfg(feature = "js")]
fn apply_virtual_angular_project_spec(
    ng_dir: &Path,
    base_gate: &CapabilityGate,
    base_cfg: &DotoreConfig,
    config_files: &[(PathBuf, PathBuf, String)],
    spec: dotore_core::AngularWorkspaceProject,
    packages: &mut Vec<WorkspacePackage>,
) {
    let proj_dir = spec.resolve_project_dir(ng_dir);
    if let Some(existing) = packages.iter_mut().find(|p| p.root_dir == proj_dir) {
        spec.apply_to_package(base_gate, existing);
    } else {
        let mut gate = CapabilityGate::empty();
        spec.apply_to_gate(base_gate, &mut gate);
        let local_cfg = config_files
            .iter()
            .find(|(c_dir, _, _)| c_dir == &proj_dir)
            .and_then(|(_, p, c)| DotoreConfig::from_config_file_str(p, c).ok())
            .unwrap_or_else(|| base_cfg.clone());
        packages.push(WorkspacePackage {
            name: spec.name,
            root_dir: proj_dir,
            capability_gate: gate,
            config: local_cfg,
        });
    }
}

fn is_compiler_config_name(file_name: &str) -> bool {
    file_name == "app.json"
        || [
            "next.config.",
            "babel.config.",
            ".babelrc",
            "vite.config.",
            "app.config.",
        ]
        .iter()
        .any(|prefix| file_name.starts_with(prefix))
}

fn is_non_js_manifest_filename(file_name: &str) -> bool {
    matches!(
        file_name,
        "angular.json"
            | "tsconfig.json"
            | "jsconfig.json"
            | "app.json"
            | "app.config.json"
            | "babel.config.json"
            | ".babelrc"
            | ".babelrc.json"
            | "build.gradle"
            | "build.gradle.kts"
            | ".gitignore"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "package-lock.json"
            | "bun.lockb"
            | "bun.lock"
            | "pnpm-workspace.yaml"
    ) || (file_name.starts_with("tsconfig.") && file_name.ends_with(".json"))
        || file_name.starts_with(".env")
}
