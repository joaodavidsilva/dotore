//! Parallel gitignore-aware file discovery across JavaScript/TypeScript, Python, Rust, and stylesheets.

use std::{
    env,
    path::{Component, Path, PathBuf},
};

use ignore::{WalkBuilder, gitignore::GitignoreBuilder};

use crate::ir::LanguageAnalyzer;

/// Default JavaScript/TypeScript source extensions.
pub const JS_SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "mts", "cjs", "cts"];

/// All polyglot source extensions supported across `dotore-js`, `dotore-py`, and `dotore-rs`.
pub const POLYGLOT_SOURCE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "mts", "cjs", "cts", "html", "htm", "py", "pyi", "rs",
    "yml", "yaml",
];

const STYLE_EXTENSIONS: &[&str] = &["css", "scss"];

const IGNORED_DIRS: &[&str] = &[
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
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "site-packages",
];

/// Collects all supported JS/TS/JSX/TSX source files under `paths`.
#[must_use]
pub fn collect_source_files(paths: &[PathBuf], include_tests: bool) -> Vec<PathBuf> {
    collect_source_files_with_extensions(paths, include_tests, JS_SOURCE_EXTENSIONS)
}

/// Collects all supported source files matching `extensions` under `paths`.
#[must_use]
pub fn collect_source_files_with_extensions(
    paths: &[PathBuf],
    include_tests: bool,
    extensions: &[&str],
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };

    for root in roots {
        if root.is_file() {
            if is_supported_file_with_extensions(&root, true, extensions)
                && !is_explicit_file_ignored(&root)
            {
                crate::ui::tick_discovery_file(&root);
                files.push(root);
            }
            continue;
        }

        let mut builder = WalkBuilder::new(&root);
        builder
            .hidden(true)
            .parents(true)
            .ignore(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .require_git(false);
        builder.filter_entry(|entry| {
            if entry.file_type().is_some_and(|ft| ft.is_dir())
                && let Some(name) = entry.file_name().to_str()
            {
                return !IGNORED_DIRS.contains(&name);
            }
            true
        });

        for result in builder.build().flatten() {
            let path = result.path();
            if path.is_file() && is_supported_file_with_extensions(path, include_tests, extensions)
            {
                crate::ui::tick_discovery_file(path);
                files.push(path.to_path_buf());
            }
        }

        if extensions.contains(&"yml") || extensions.contains(&"yaml") {
            collect_github_workflow_files(&root, include_tests, extensions, &mut files);
        }
    }

    files.sort();
    files.dedup();
    files
}

fn collect_github_workflow_files(
    root: &Path,
    include_tests: bool,
    extensions: &[&str],
    files: &mut Vec<PathBuf>,
) {
    let wf_dir = root.join(".github").join("workflows");
    let Ok(entries) = std::fs::read_dir(&wf_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let wf_path = entry.path();
        if wf_path.is_file() && is_supported_file_with_extensions(&wf_path, include_tests, extensions) {
            crate::ui::tick_discovery_file(&wf_path);
            files.push(wf_path);
        }
    }
}

/// Collects all source files under `paths` supported by at least one registered [`LanguageAnalyzer`].
#[must_use]
pub fn collect_source_files_for_analyzers(
    paths: &[PathBuf],
    include_tests: bool,
    analyzers: &[&dyn LanguageAnalyzer],
) -> Vec<PathBuf> {
    let candidates =
        collect_source_files_with_extensions(paths, include_tests, POLYGLOT_SOURCE_EXTENSIONS);
    if analyzers.is_empty() {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|path| analyzers.iter().any(|a| a.supports_path(path)))
        .collect()
}

/// Collects all `.css` and `.scss` stylesheets under `paths` for reduced-motion analysis.
#[must_use]
pub fn collect_style_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };

    for root in roots {
        if root.is_file() {
            if root
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| STYLE_EXTENSIONS.contains(&ext))
                && !is_explicit_file_ignored(&root)
            {
                files.push(root);
            }
            continue;
        }

        let mut builder = WalkBuilder::new(&root);
        builder
            .hidden(true)
            .parents(true)
            .ignore(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .require_git(false);
        builder.filter_entry(|entry| {
            if entry.file_type().is_some_and(|ft| ft.is_dir())
                && let Some(name) = entry.file_name().to_str()
            {
                return !IGNORED_DIRS.contains(&name);
            }
            true
        });

        for result in builder.build().flatten() {
            let path = result.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| STYLE_EXTENSIONS.contains(&ext))
            {
                files.push(path.to_path_buf());
            }
        }
    }

    files.sort();
    files.dedup();
    files
}

/// Returns `true` if `path` is a supported JS/TS source file (and passes `include_tests`).
#[must_use]
pub fn is_supported_file(path: &Path, include_tests: bool) -> bool {
    is_supported_file_with_extensions(path, include_tests, JS_SOURCE_EXTENSIONS)
}

/// Returns `true` if `path` matches `extensions`, is not a `.d.ts` or `dotore.config.*` file,
/// and satisfies `include_tests`.
#[must_use]
pub fn is_supported_file_with_extensions(
    path: &Path,
    include_tests: bool,
    extensions: &[&str],
) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if !extensions.contains(&ext) {
        return false;
    }
    if matches!(ext, "yml" | "yaml") {
        let norm = path.to_string_lossy().replace('\\', "/");
        if !norm.starts_with(".github/workflows/") && !norm.contains("/.github/workflows/") {
            return false;
        }
    }

    let Some(file_name) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    if file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.mts")
        || file_name.ends_with(".d.cts")
        || file_name.starts_with("dotore.config.")
    {
        return false;
    }

    if !include_tests {
        let is_py_test = (ext == "py" || ext == "pyi")
            && (file_name == "conftest.py"
                || file_name.starts_with("test_")
                || file_name.ends_with("_test.py")
                || file_name.ends_with("_test.pyi"));
        let is_test = is_py_test
            || file_name.contains(".test.")
            || file_name.contains(".spec.")
            || path.components().any(|c| {
                matches!(
                    c.as_os_str().to_str(),
                    Some("__tests__" | "__mocks__" | "test" | "tests" | "benches")
                )
            });
        if is_test {
            return false;
        }
    }

    true
}

/// Returns `true` if an explicit file path sits inside an ignored directory or matches ancestor `.gitignore`/`.ignore` rules.
#[must_use]
pub fn is_explicit_file_ignored(path: &Path) -> bool {
    let abs_path = normalize_path(path);
    if has_ignored_dir_component(&abs_path) {
        return true;
    }

    let Some(parent) = abs_path.parent() else {
        return false;
    };

    let mut ancestors: Vec<&Path> = Vec::new();
    for ancestor in parent.ancestors() {
        ancestors.push(ancestor);
        if ancestor.join(".git").exists() {
            break;
        }
    }
    ancestors.reverse();

    for (idx, &dir) in ancestors.iter().enumerate() {
        if idx > 0 && is_entry_ignored_by_ancestors(dir, true, &ancestors[..idx]) {
            return true;
        }
    }

    is_entry_ignored_by_ancestors(&abs_path, false, &ancestors)
}

fn normalize_path(path: &Path) -> PathBuf {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = env::current_dir() {
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

fn has_ignored_dir_component(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    parent.components().any(|comp| {
        matches!(comp, Component::Normal(os) if os.to_str().is_some_and(|name| IGNORED_DIRS.contains(&name)))
    })
}

fn is_entry_ignored_by_ancestors(entry: &Path, is_dir: bool, ancestors: &[&Path]) -> bool {
    for &dir in ancestors.iter().rev() {
        if let Some(ignored) = match_dir_ignore_files(dir, entry, is_dir) {
            return ignored;
        }
    }
    false
}

fn match_dir_ignore_files(dir: &Path, target: &Path, is_dir: bool) -> Option<bool> {
    let gitignore_path = dir.join(".gitignore");
    let ignore_path = dir.join(".ignore");
    let git_exclude_path = dir.join(".git/info/exclude");

    let has_gitignore = gitignore_path.is_file();
    let has_ignore = ignore_path.is_file();
    let has_exclude = git_exclude_path.is_file();

    if !has_gitignore && !has_ignore && !has_exclude {
        return None;
    }

    let mut builder = GitignoreBuilder::new(dir);
    if has_exclude {
        let _ = builder.add(git_exclude_path);
    }
    if has_gitignore {
        let _ = builder.add(gitignore_path);
    }
    if has_ignore {
        let _ = builder.add(ignore_path);
    }

    let matcher = builder.build().ok()?;
    let matched = matcher.matched(target, is_dir);
    if matched.is_ignore() {
        Some(true)
    } else if matched.is_whitelist() {
        Some(false)
    } else {
        None
    }
}
