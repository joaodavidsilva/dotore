//! Git revision validation, unified diff patch parsing (`git diff --unified=0`),
//! diff collection (`--base`, `--staged`), and CI exit-code resolution.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::rules::{Diagnostic, RuleSeverity};

/// Scope of a `dotore check` scan (`--scope full|changed|contextual|lines`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffScope {
    /// Analyze and report all diagnostics across target paths.
    #[default]
    Full,
    /// Report only diagnostics in files modified in the git diff (or staged index).
    Changed,
    /// Report only diagnostics whose **Contextual Owner** intersects modified line ranges in the git diff.
    Contextual,
    /// Report only diagnostics whose primary span intersects modified line ranges in the git diff.
    Lines,
}

impl DiffScope {
    /// Returns the canonical kebab-case scope string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Changed => "changed",
            Self::Contextual => "contextual",
            Self::Lines => "lines",
        }
    }

    /// Parses a scope identifier (`"full"`, `"changed"`, `"contextual"`, `"lines"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "changed" => Some(Self::Changed),
            "contextual" => Some(Self::Contextual),
            "lines" => Some(Self::Lines),
            _ => None,
        }
    }
}

/// Active scan mode recorded in [`crate::JsonReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanMode {
    /// Standard full-workspace or path-targeted scan.
    #[default]
    Full,
    /// Git diff-scoped scan (`--scope changed|contextual|lines` or degraded baseline).
    Diff,
    /// Git staged index scan (`--staged`).
    Staged,
    /// Multiset comparison against a baseline report or revision (`--baseline`).
    Baseline,
}

impl ScanMode {
    /// Returns the canonical kebab-case mode string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Diff => "diff",
            Self::Staged => "staged",
            Self::Baseline => "baseline",
        }
    }
}

/// Severity threshold that causes `dotore check` to exit with code `1` (`--blocking error|warning|none`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockingLevel {
    /// Exit `1` only when at least one `error`-severity diagnostic is reported (default).
    #[default]
    Error,
    /// Exit `1` when any `error`- or `warning`-severity diagnostic is reported.
    Warning,
    /// Never exit `1` due to reported diagnostics (`--blocking none` / `--no-fail`).
    None,
}

impl BlockingLevel {
    /// Returns the canonical kebab-case blocking level string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::None => "none",
        }
    }

    /// Parses a `--blocking` value (`"error"`, `"warning"`, `"warn"`, `"none"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warning" | "warn" => Some(Self::Warning),
            "none" | "off" => Some(Self::None),
            _ => None,
        }
    }
}

/// Validates that `--warning-exit-code` is within the allowed `2..=255` range.
///
/// # Errors
/// Returns a descriptive error string if `code` is `< 2` or `> 255`.
pub fn validate_warning_exit_code(code: u32) -> Result<u8, String> {
    if (2..=255).contains(&code)
        && let Ok(valid) = u8::try_from(code)
    {
        Ok(valid)
    } else {
        Err(format!(
            "Invalid --warning-exit-code {code}: expected an integer from 2 to 255."
        ))
    }
}

/// Resolves the process exit code (`0`, `1`, or custom `warning_exit_code`) for a completed scan.
#[must_use]
pub fn resolve_scan_exit_code(
    diagnostics: &[Diagnostic],
    blocking: BlockingLevel,
    warning_exit_code: Option<u8>,
) -> u8 {
    if blocking == BlockingLevel::None {
        return 0;
    }

    let has_errors = diagnostics
        .iter()
        .any(|d| d.severity == RuleSeverity::Error);
    let has_warnings = diagnostics
        .iter()
        .any(|d| d.severity == RuleSeverity::Warning);

    match blocking {
        BlockingLevel::Error if has_errors => return 1,
        BlockingLevel::Warning if has_errors || has_warnings => return 1,
        BlockingLevel::Error | BlockingLevel::Warning | BlockingLevel::None => {}
    }

    if has_warnings && let Some(code) = warning_exit_code {
        return code;
    }

    0
}

/// Validates a git revision or revision range (`A..B`, `A...B`) against option injection and invalid syntax.
///
/// # Errors
/// Returns an error message if `rev` is empty, starts with `-`, starts/ends with `.`, contains `@{`,
/// or contains disallowed characters.
pub fn validate_git_revision(rev: &str) -> Result<(), String> {
    let trimmed = rev.trim();
    if trimmed.is_empty() {
        return Err("Git revision cannot be empty.".to_string());
    }
    if let Some((left, right)) = trimmed.split_once("...") {
        validate_single_git_ref(left)?;
        validate_single_git_ref(right)?;
        return Ok(());
    }
    if let Some((left, right)) = trimmed.split_once("..") {
        validate_single_git_ref(left)?;
        validate_single_git_ref(right)?;
        return Ok(());
    }
    validate_single_git_ref(trimmed)
}

fn validate_single_git_ref(candidate: &str) -> Result<(), String> {
    if candidate.is_empty() {
        return Err("Git revision endpoint cannot be empty.".to_string());
    }
    if candidate.starts_with('-') {
        return Err(format!(
            "Invalid git revision {candidate:?}: must not start with '-'."
        ));
    }
    if candidate.starts_with('.') || candidate.ends_with('.') {
        return Err(format!(
            "Invalid git revision {candidate:?}: must not start or end with '.'."
        ));
    }
    if candidate.contains("..") || candidate.contains("@{") {
        return Err(format!(
            "Invalid git revision {candidate:?}: must not contain '..' or '@{{'."
        ));
    }
    let valid_chars = candidate
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-' | b'~' | b'^'));
    if !valid_chars {
        return Err(format!(
            "Invalid git revision {candidate:?}: contains unsupported characters."
        ));
    }
    Ok(())
}

/// Modified 1-based inclusive line ranges `(start_line, end_line)` and 1-based deletion anchor lines for a file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChangedFileLineRanges {
    /// File path (relative to the repository or workspace root).
    pub file: PathBuf,
    /// 1-based inclusive modified line ranges `(start_line, end_line)`.
    pub ranges: Vec<(u32, u32)>,
    /// 1-based line numbers where a zero-line deletion hunk (`@@ -a,b +line,0 @@`) occurred.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deletion_lines: Vec<u32>,
}

/// Parses unified diff output (`git diff --unified=0`) into per-file [`ChangedFileLineRanges`].
#[must_use]
pub fn parse_changed_line_ranges(
    patch: &str,
    include_deletions: bool,
) -> Vec<ChangedFileLineRanges> {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut map: HashMap<PathBuf, ChangedFileLineRanges> = HashMap::new();
    let mut current_file: Option<PathBuf> = None;

    for raw_line in patch.lines() {
        let line = raw_line.trim_end_matches('\r');
        if include_deletions && let Some(renamed_to) = line.strip_prefix("rename to ") {
            let file_path = PathBuf::from(renamed_to.trim());
            map.entry(file_path.clone()).or_insert_with(|| {
                order.push(file_path.clone());
                ChangedFileLineRanges {
                    file: file_path,
                    ranges: Vec::new(),
                    deletion_lines: Vec::new(),
                }
            });
            continue;
        }

        if let Some(target_raw) = line.strip_prefix("+++ ") {
            let target = target_raw.trim();
            if target == "/dev/null" {
                current_file = None;
                continue;
            }
            let stripped = target.strip_prefix("b/").unwrap_or(target);
            let file_path = PathBuf::from(stripped);
            map.entry(file_path.clone()).or_insert_with(|| {
                order.push(file_path.clone());
                ChangedFileLineRanges {
                    file: file_path.clone(),
                    ranges: Vec::new(),
                    deletion_lines: Vec::new(),
                }
            });
            current_file = Some(file_path);
            continue;
        }

        let Some(active_file) = &current_file else {
            continue;
        };

        if let Some((start, count)) = parse_unified_hunk_header(line)
            && let Some(entry) = map.get_mut(active_file)
        {
            if count == 0 {
                if include_deletions {
                    entry.deletion_lines.push(start);
                }
            } else {
                let end = start.saturating_add(count.saturating_sub(1));
                entry.ranges.push((start, end));
            }
        }
    }

    order
        .into_iter()
        .filter_map(|f| map.remove(&f))
        .filter(|entry| {
            !entry.ranges.is_empty() || (include_deletions && !entry.deletion_lines.is_empty())
        })
        .collect()
}

fn parse_unified_hunk_header(line: &str) -> Option<(u32, u32)> {
    let rest = line.strip_prefix("@@ -")?;
    let plus_idx = rest.find(" +")?;
    let after_plus = &rest[plus_idx + 2..];
    let end_idx = after_plus.find(" @@")?;
    let new_spec = &after_plus[..end_idx];

    if let Some((start_str, count_str)) = new_spec.split_once(',') {
        let start = start_str.parse::<u32>().ok()?;
        let count = count_str.parse::<u32>().ok()?;
        Some((start, count))
    } else {
        let start = new_spec.parse::<u32>().ok()?;
        Some((start, 1))
    }
}

/// Git diff summary metadata attached to [`crate::JsonReport`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GitDiffInfo {
    /// Base revision or branch compared against (`"HEAD"`, `"main"`, `"index"`, etc.).
    pub base_ref: String,
    /// Current branch name (`None` when on detached `HEAD`).
    pub current_branch: Option<String>,
    /// Number of modified/added files in the diff.
    pub changed_file_count: usize,
    /// Whether the diff includes uncommitted working-tree or staged changes.
    pub is_current_changes: bool,
    /// Whether `--staged` (`git diff --cached`) was used.
    pub staged: bool,
}

/// Complete git diff snapshot for filtering workspace diagnostics.
#[derive(Debug, Clone, Default)]
pub struct GitDiffSnapshot {
    /// Repository root directory discovered from `git rev-parse --show-toplevel`.
    pub repo_root: PathBuf,
    /// Public diff metadata for `JsonReport`.
    pub info: GitDiffInfo,
    /// Modified/added files (relative to `repo_root`).
    pub changed_files: Vec<PathBuf>,
    /// Per-file changed line ranges and deletion anchors (relative to `repo_root`).
    pub line_ranges: Vec<ChangedFileLineRanges>,
}

/// Collects git diff changed files and hunk line ranges for `workspace_root`.
///
/// # Errors
/// Returns an error string if `base_ref` fails validation or `git` fails in a non-git directory.
pub fn collect_git_diff(
    workspace_root: &Path,
    base_ref: Option<&str>,
    staged: bool,
) -> Result<GitDiffSnapshot, String> {
    if let Some(rev) = base_ref {
        validate_git_revision(rev)?;
    }

    let repo_root_out = run_git(workspace_root, &["rev-parse", "--show-toplevel"])?;
    let repo_root = PathBuf::from(repo_root_out.trim());
    let current_branch = run_git(&repo_root, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if staged {
        let names_out = run_git(
            &repo_root,
            &["diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
        )?;
        let mut changed_files: Vec<PathBuf> = names_out
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();

        let patch_out = run_git(
            &repo_root,
            &["diff", "--cached", "--unified=0", "--no-color"],
        )?;
        let line_ranges = parse_changed_line_ranges(&patch_out, true);
        for entry in &line_ranges {
            if !changed_files.contains(&entry.file) {
                changed_files.push(entry.file.clone());
            }
        }

        return Ok(GitDiffSnapshot {
            repo_root,
            info: GitDiffInfo {
                base_ref: "index".to_string(),
                current_branch,
                changed_file_count: changed_files.len(),
                is_current_changes: true,
                staged: true,
            },
            changed_files,
            line_ranges,
        });
    }

    let (resolved_base, is_range) = resolve_effective_base(&repo_root, base_ref)?;
    let names_out = run_git(
        &repo_root,
        &["diff", "--name-only", "--diff-filter=ACMRT", &resolved_base],
    )?;
    let mut changed_files: Vec<PathBuf> = names_out
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();

    let patch_out = run_git(
        &repo_root,
        &["diff", "--unified=0", "--no-color", &resolved_base],
    )?;
    let mut line_ranges = parse_changed_line_ranges(&patch_out, true);

    if !is_range
        && let Ok(untracked_out) =
            run_git(&repo_root, &["ls-files", "--others", "--exclude-standard"])
    {
        for raw in untracked_out
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let p = PathBuf::from(raw);
            if !line_ranges.iter().any(|r| r.file == p) {
                line_ranges.push(ChangedFileLineRanges {
                    file: p.clone(),
                    ranges: vec![(1, u32::MAX)],
                    deletion_lines: Vec::new(),
                });
            }
            if !changed_files.contains(&p) {
                changed_files.push(p);
            }
        }
    }

    for entry in &line_ranges {
        if !changed_files.contains(&entry.file) {
            changed_files.push(entry.file.clone());
        }
    }

    Ok(GitDiffSnapshot {
        repo_root,
        info: GitDiffInfo {
            base_ref: base_ref.unwrap_or(&resolved_base).to_string(),
            current_branch,
            changed_file_count: changed_files.len(),
            is_current_changes: !is_range,
            staged: false,
        },
        changed_files,
        line_ranges,
    })
}

fn resolve_effective_base(
    repo_root: &Path,
    explicit_base: Option<&str>,
) -> Result<(String, bool), String> {
    if let Some(base) = explicit_base {
        let trimmed = base.trim();
        if trimmed.contains("..") {
            return Ok((trimmed.to_string(), true));
        }
        if run_git(repo_root, &["rev-parse", "--verify", trimmed]).is_err() {
            return Err(format!("Unknown or unavailable git revision: {trimmed:?}"));
        }
        if trimmed != "HEAD"
            && let Ok(mb) = run_git(repo_root, &["merge-base", trimmed, "HEAD"])
        {
            let mb_trimmed = mb.trim();
            if !mb_trimmed.is_empty() {
                return Ok((mb_trimmed.to_string(), false));
            }
        }
        return Ok((trimmed.to_string(), false));
    }

    let head_dirty =
        run_git(repo_root, &["status", "--porcelain"]).is_ok_and(|out| !out.trim().is_empty());
    if head_dirty {
        return Ok(("HEAD".to_string(), false));
    }

    for candidate in ["origin/HEAD", "main", "master"] {
        if run_git(repo_root, &["rev-parse", "--verify", candidate]).is_ok()
            && let Ok(mb) = run_git(repo_root, &["merge-base", candidate, "HEAD"])
        {
            let mb_trimmed = mb.trim();
            if !mb_trimmed.is_empty() {
                let head_sha = run_git(repo_root, &["rev-parse", "HEAD"]).unwrap_or_default();
                if mb_trimmed != head_sha.trim() {
                    return Ok((mb_trimmed.to_string(), false));
                }
            }
        }
    }

    Ok(("HEAD".to_string(), false))
}

pub(super) fn run_git(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("Failed to execute git: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
