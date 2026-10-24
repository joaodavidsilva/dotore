//! Workspace package discovery and path/JSONC normalization helpers.

use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use crate::ir::LanguageAnalyzer;

use super::{
    CapabilityGate, DotoreConfig,
    loader::{load_config_from_dir, load_local_config_in_dir},
};

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
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "site-packages",
];

/// A discovered workspace package in a repository or monorepo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspacePackage {
    /// Package name (`package.json#name`, `pyproject.toml`, `Cargo.toml`, or directory basename).
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
    discover_workspace_packages_with_analyzers(root_dir, &[])
}

/// Discovers all workspace packages under `root_dir` using `analyzers` for multi-manifest capability inference.
#[must_use]
pub fn discover_workspace_packages_with_analyzers(
    root_dir: &Path,
    analyzers: &[&dyn LanguageAnalyzer],
) -> Vec<WorkspacePackage> {
    let manifest_names: Vec<&str> = if analyzers.is_empty() {
        vec!["package.json", "angular.json"]
    } else {
        let mut names = vec!["package.json", "angular.json"];
        for analyzer in analyzers {
            for &m in analyzer.manifest_filenames() {
                if !names.contains(&m) {
                    names.push(m);
                }
            }
        }
        names
    };

    let (mut dirs, mut seen) = (Vec::new(), HashSet::new());
    if manifest_names.iter().any(|m| root_dir.join(m).is_file()) {
        seen.insert(normalize_path_buf(root_dir));
        dirs.push(root_dir.to_path_buf());
    }
    walk_nested_package_dirs(root_dir, 0, 5, &manifest_names, &mut seen, &mut dirs);
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
            let mut capability_gate = if analyzers.is_empty()
                || dir.join("package.json").is_file()
                || dir.join("angular.json").is_file()
            {
                CapabilityGate::discover(&dir)
            } else {
                CapabilityGate::empty()
            };
            if !analyzers.is_empty() {
                let mut manifest_sources = Vec::new();
                for &m in &manifest_names {
                    let m_path = dir.join(m);
                    if let Ok(src) = fs::read_to_string(&m_path) {
                        manifest_sources.push((m_path, src));
                    }
                }
                let borrowed_refs: Vec<(PathBuf, &str)> = manifest_sources
                    .iter()
                    .map(|(p, s)| (p.clone(), s.as_str()))
                    .collect();
                for analyzer in analyzers {
                    let has_matching_manifest = analyzer
                        .manifest_filenames()
                        .iter()
                        .any(|m| dir.join(m).is_file());
                    if has_matching_manifest {
                        let inferred = analyzer.infer_capability_gate(&dir, &borrowed_refs);
                        capability_gate.merge(&inferred);
                    }
                }
                if capability_gate.capabilities.is_empty() {
                    capability_gate = CapabilityGate::discover(&dir);
                }
            }
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
    manifest_names: &[&str],
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
        if manifest_names.iter().any(|m| subdir.join(m).is_file())
            && seen.insert(normalize_path_buf(&subdir))
        {
            out.push(subdir.clone());
        }
        walk_nested_package_dirs(&subdir, depth + 1, max_depth, manifest_names, seen, out);
    }
}

/// Strips single-line `//`, block `/* ... */` comments, and trailing commas from JSONC text.
#[must_use]
pub fn strip_jsonc(input: &str) -> String {
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

/// Walks upward from `start_dir` to find `file_name`, stopping at `.git` or the system temp root.
#[must_use]
pub fn find_nearest_ancestor_file(start_dir: &Path, file_name: &str) -> Option<PathBuf> {
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

/// Returns `file_path` relative to `root_dir` using forward slashes.
#[must_use]
pub fn relative_forward_slash(file_path: &Path, root_dir: &Path) -> String {
    let norm_file = normalize_path_buf(file_path);
    let norm_root = normalize_path_buf(root_dir);
    let rel = norm_file
        .strip_prefix(&norm_root)
        .or_else(|_| file_path.strip_prefix(root_dir))
        .unwrap_or(file_path);
    normalize_rel_path_str(rel)
}

/// Normalizes a relative path into forward-slash form without a leading `./`.
#[must_use]
pub fn normalize_rel_path_str(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

/// Strips a known JS/TS/Python/Rust source extension from `path`.
#[must_use]
pub fn strip_source_extension(path: &str) -> &str {
    for ext in [
        ".tsx", ".ts", ".jsx", ".js", ".mts", ".mjs", ".cts", ".cjs", ".pyi", ".py", ".rs",
    ] {
        if let Some(stem) = path.strip_suffix(ext) {
            return stem;
        }
    }
    path
}

/// Lexically normalizes `path` against the current working directory.
#[must_use]
pub fn normalize_path_buf(path: &Path) -> PathBuf {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
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
