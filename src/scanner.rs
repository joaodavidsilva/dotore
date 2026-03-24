use std::{
    env,
    path::{Component, Path, PathBuf},
};

use ignore::{WalkBuilder, gitignore::GitignoreBuilder};

const SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "mts", "cjs", "cts"];

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
];

/// Collects all supported JS/TS/JSX/TSX source files under `paths`.
#[must_use]
pub(crate) fn collect_source_files(paths: &[PathBuf], include_tests: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };

    for root in roots {
        if root.is_file() {
            if is_supported_file(&root, true) && !is_explicit_file_ignored(&root) {
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
            if path.is_file() && is_supported_file(path, include_tests) {
                files.push(path.to_path_buf());
            }
        }
    }

    files.sort();
    files.dedup();
    files
}

/// Collects all `.css` and `.scss` stylesheets under `paths` for reduced-motion analysis.
#[must_use]
pub(crate) fn collect_style_files(paths: &[PathBuf]) -> Vec<PathBuf> {
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

fn is_supported_file(path: &Path, include_tests: bool) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if !SOURCE_EXTENSIONS.contains(&ext) {
        return false;
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
        let is_test = file_name.contains(".test.")
            || file_name.contains(".spec.")
            || path.components().any(|c| {
                matches!(
                    c.as_os_str().to_str(),
                    Some("__tests__" | "__mocks__" | "test" | "tests")
                )
            });
        if is_test {
            return false;
        }
    }

    true
}

fn is_explicit_file_ignored(path: &Path) -> bool {
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

    // Step from highest ancestor down to immediate parent so an ignored directory
    // short-circuits before any nested ignore files inside it are consulted.
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
