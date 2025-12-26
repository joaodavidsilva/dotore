//! Project configuration loader (`dotore.config.*` and `package.json#dotore`),
//! workspace package discovery, and automatic **Capability Gate** inference.

pub(crate) mod capability_gate;
pub(crate) mod loader;

pub(crate) use capability_gate::content_enables_react_compiler;
pub use capability_gate::{Capability, CapabilityGate, CapabilityPredicate, PackageRole};
pub use loader::{
    ConfigMutation, ConfigTargetKind, DotoreConfig, IgnoreConfig, IgnoreOverride,
    MutateConfigResult, load_config_from_dir, mutate_config_in_dir,
};

use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use loader::load_local_config_in_dir;

const IGNORED_DISCOVERY_DIRS: &[&str] = &[
    "node_modules",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".output",
    "coverage",
    "target",
    ".git",
    ".turbo",
    "vendor",
    "docs",
    "AppData",
    "Library",
];

/// A discovered workspace package in a repository or monorepo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspacePackage {
    /// Package name (`package.json#name` or directory basename).
    pub name: String,
    /// Root directory of this package.
    pub root_dir: PathBuf,
    /// Inferred **Capability Gate** for this package.
    pub capability_gate: CapabilityGate,
    /// Resolved configuration for this package.
    pub config: DotoreConfig,
}

/// Discovers all workspace packages under `root_dir`, computing each package's [`CapabilityGate`] and [`DotoreConfig`].
#[must_use]
pub fn discover_workspace_packages(root_dir: &Path) -> Vec<WorkspacePackage> {
    let (mut dirs, mut seen) = (Vec::new(), HashSet::new());
    if root_dir.join("package.json").is_file() {
        seen.insert(normalize_path_buf(root_dir));
        dirs.push(root_dir.to_path_buf());
    }
    walk_nested_package_dirs(root_dir, 0, 5, &mut seen, &mut dirs);
    if dirs.is_empty() {
        dirs.push(root_dir.to_path_buf());
    }
    let root_config = load_config_from_dir(root_dir);
    dirs.into_iter()
        .map(|dir| {
            let name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("root")
                .to_string();
            let capability_gate = CapabilityGate::discover(&dir);
            let config = if dir == root_dir {
                root_config.clone()
            } else {
                load_local_config_in_dir(&dir).unwrap_or_else(|| root_config.clone())
            };
            WorkspacePackage {
                name,
                root_dir: dir,
                capability_gate,
                config,
            }
        })
        .collect()
}

/// Resolves the most specific enclosing [`WorkspacePackage`] for `file_path` (longest directory prefix match).
#[must_use]
pub fn resolve_package_for_file<'a>(
    file_path: &Path,
    packages: &'a [WorkspacePackage],
) -> Option<&'a WorkspacePackage> {
    let norm_file = normalize_path_buf(file_path);
    packages
        .iter()
        .filter(|pkg| {
            let norm_pkg = normalize_path_buf(&pkg.root_dir);
            norm_file.starts_with(&norm_pkg) || file_path.starts_with(&pkg.root_dir)
        })
        .max_by_key(|pkg| normalize_path_buf(&pkg.root_dir).components().count())
        .or_else(|| packages.first())
}

fn walk_nested_package_dirs(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
) {
    if depth >= max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| !n.starts_with('.') && !IGNORED_DISCOVERY_DIRS.contains(&n))
        })
        .collect();
    subdirs.sort();
    for subdir in subdirs {
        if subdir.join("package.json").is_file() && seen.insert(normalize_path_buf(&subdir)) {
            out.push(subdir.clone());
        }
        walk_nested_package_dirs(&subdir, depth + 1, max_depth, seen, out);
    }
}

pub(crate) fn strip_jsonc(input: &str) -> String {
    let mut no_comments = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            no_comments.push(c);
            if c == '\\'
                && let Some(next) = chars.next()
            {
                no_comments.push(next);
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            no_comments.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for ch in chars.by_ref() {
                if ch == '\n' {
                    no_comments.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            while let Some(ch) = chars.next() {
                if ch == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    break;
                }
                if ch == '\n' {
                    no_comments.push('\n');
                }
            }
        } else {
            no_comments.push(c);
        }
    }

    let mut out = String::with_capacity(no_comments.len());
    let mut it = no_comments.chars().peekable();
    let mut in_string = false;
    while let Some(c) = it.next() {
        if in_string {
            out.push(c);
            if c == '\\'
                && let Some(n) = it.next()
            {
                out.push(n);
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let ws_count = it.clone().take_while(|ch| ch.is_whitespace()).count();
            if !matches!(it.clone().nth(ws_count), Some('}' | ']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn find_nearest_ancestor_file(start_dir: &Path, file_name: &str) -> Option<PathBuf> {
    let temp_root = normalize_path_buf(&std::env::temp_dir());
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        if normalize_path_buf(dir) == temp_root {
            break;
        }
        let candidate = dir.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            break;
        }
        current = dir.parent();
    }
    None
}

pub(crate) fn relative_forward_slash(file_path: &Path, root_dir: &Path) -> String {
    let norm_file = normalize_path_buf(file_path);
    let norm_root = normalize_path_buf(root_dir);
    let rel = norm_file
        .strip_prefix(&norm_root)
        .or_else(|_| file_path.strip_prefix(root_dir))
        .unwrap_or(file_path);
    normalize_rel_path_str(rel)
}

pub(crate) fn normalize_rel_path_str(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

pub(crate) fn strip_source_extension(path: &str) -> &str {
    for ext in [".tsx", ".ts", ".jsx", ".js", ".mts", ".mjs", ".cts", ".cjs"] {
        if let Some(stem) = path.strip_suffix(ext) {
            return stem;
        }
    }
    path
}

pub(crate) fn normalize_path_buf(path: &Path) -> PathBuf {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let mut out = PathBuf::new();
    for comp in raw.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(comp.as_os_str());
            }
        }
    }
    out
}
