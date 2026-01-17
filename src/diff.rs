//! Git diff execution (`--base`, `--staged`), unified diff hunk line-range parsing,
//! **Contextual Owner** span resolution (`--scope full|changed|contextual|lines`),
//! `--baseline <report.json>` multiset fingerprint comparison, and CI exit-code resolution.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; contextual owner resolution matches only relevant JSX/function/hook AST node kinds"
)]

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use oxc_allocator::Allocator;
use oxc_ast::{
    AstKind,
    ast::{CallExpression, Expression},
};
use oxc_parser::Parser;
use oxc_semantic::{NodeId, Semantic, SemanticBuilder};
use oxc_span::{SourceType, Span};
use serde::{Deserialize, Serialize};

use crate::{
    ir::{
        ByteSpan, FileIr,
        types::{compute_line_starts, loc_from_line_starts},
    },
    rules::{ContextualOwnerPolicy, Diagnostic, RuleId, RuleSeverity},
};

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
            if !map.contains_key(&file_path) {
                order.push(file_path.clone());
                map.insert(
                    file_path.clone(),
                    ChangedFileLineRanges {
                        file: file_path,
                        ranges: Vec::new(),
                        deletion_lines: Vec::new(),
                    },
                );
            }
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
            if !map.contains_key(&file_path) {
                order.push(file_path.clone());
                map.insert(
                    file_path.clone(),
                    ChangedFileLineRanges {
                        file: file_path.clone(),
                        ranges: Vec::new(),
                        deletion_lines: Vec::new(),
                    },
                );
            }
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
pub(crate) struct GitDiffSnapshot {
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
pub(crate) fn collect_git_diff(
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

    // Include untracked files when comparing working tree (not a closed commit range `A..B`)
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
            if !changed_files.contains(&p) {
                changed_files.push(p.clone());
            }
            if !line_ranges.iter().any(|r| r.file == p) {
                line_ranges.push(ChangedFileLineRanges {
                    file: p,
                    ranges: vec![(1, u32::MAX)],
                    deletion_lines: Vec::new(),
                });
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
        // Verify revision exists
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

    // Auto-detect base when `--base` is omitted:
    // 1. If there are uncommitted or untracked changes against HEAD, diff against HEAD.
    let head_dirty =
        run_git(repo_root, &["status", "--porcelain"]).is_ok_and(|out| !out.trim().is_empty());
    if head_dirty {
        return Ok(("HEAD".to_string(), false));
    }

    // 2. Otherwise check default branch candidates (`origin/HEAD`, `main`, `master`)
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

fn run_git(cwd: &Path, args: &[&str]) -> Result<String, String> {
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

/// Filters `diagnostics` according to `scope` (`Full`, `Changed`, `Lines`, `Contextual`) and
/// the given changed files / hunk line ranges.
#[must_use]
pub fn filter_diagnostics_by_scope(
    diagnostics: Vec<Diagnostic>,
    scope: DiffScope,
    repo_root: &Path,
    changed_files: &[PathBuf],
    line_ranges: &[ChangedFileLineRanges],
    files: &[FileIr],
    sources: &HashMap<PathBuf, String>,
) -> Vec<Diagnostic> {
    if scope == DiffScope::Full {
        return diagnostics;
    }

    let normalized_changed_files: HashSet<PathBuf> = changed_files
        .iter()
        .flat_map(|p| candidate_path_keys(repo_root, p))
        .collect();

    if scope == DiffScope::Changed {
        return diagnostics
            .into_iter()
            .filter(|diag| {
                candidate_path_keys(repo_root, &diag.file)
                    .iter()
                    .any(|k| normalized_changed_files.contains(k))
            })
            .collect();
    }

    let mut ranges_by_key: HashMap<PathBuf, &ChangedFileLineRanges> = HashMap::new();
    for entry in line_ranges {
        for key in candidate_path_keys(repo_root, &entry.file) {
            ranges_by_key.insert(key, entry);
        }
    }

    let contextual = scope == DiffScope::Contextual;

    diagnostics
        .into_iter()
        .filter(|diag| {
            let diag_keys = candidate_path_keys(repo_root, &diag.file);
            let Some(file_changes) = diag_keys.iter().find_map(|k| ranges_by_key.get(k).copied())
            else {
                return false;
            };
            let file_ir = files.iter().find(|f| f.path == diag.file);
            let source = sources.get(&diag.file).map(String::as_str);
            diagnostic_intersects_changed_lines(diag, file_ir, source, file_changes, contextual)
        })
        .collect()
}

fn candidate_path_keys(root: &Path, path: &Path) -> Vec<PathBuf> {
    let mut keys = Vec::with_capacity(3);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let lex = lexical_normalize(&joined);
    keys.push(lex.clone());
    if let Ok(canon) = fs::canonicalize(&joined)
        && !keys.contains(&canon)
    {
        keys.push(canon);
    }
    let rel_lex = lexical_normalize(path);
    if !keys.contains(&rel_lex) {
        keys.push(rel_lex);
    }
    keys
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[derive(Debug, Clone)]
struct OwnedLineContext {
    range: (u32, u32),
    excluded_ranges: Vec<(u32, u32)>,
}

/// Returns `true` if `diag` (or its **Contextual Owner** when `contextual` is `true`) intersects
/// `changes` (`ranges` or `deletion_lines`).
#[must_use]
pub fn diagnostic_intersects_changed_lines(
    diag: &Diagnostic,
    file_ir: Option<&FileIr>,
    source: Option<&str>,
    changes: &ChangedFileLineRanges,
    contextual: bool,
) -> bool {
    let (diag_start, diag_end) = diagnostic_line_span(diag, source);
    if ranges_intersect_any((diag_start, diag_end), &changes.ranges) {
        return true;
    }
    if !contextual {
        return false;
    }

    let policy = diag.rule.metadata().contextual_owner;
    match policy {
        ContextualOwnerPolicy::Line => false,
        ContextualOwnerPolicy::File => {
            !changes.ranges.is_empty() || !changes.deletion_lines.is_empty()
        }
        ContextualOwnerPolicy::JsxElement => {
            let Some(src) = source else {
                return false;
            };
            let contexts = resolve_jsx_owner_contexts(&diag.file, src, diag.span);
            does_context_intersect_changes(&contexts, changes)
        }
        ContextualOwnerPolicy::Subject => {
            let Some(src) = source else {
                return false;
            };
            let contexts = resolve_subject_owner_contexts(&diag.file, src, file_ir, diag.span);
            does_context_intersect_changes(&contexts, changes)
        }
        ContextualOwnerPolicy::RelatedNodes => {
            let Some(src) = source else {
                return false;
            };
            let contexts = resolve_related_node_contexts(&diag.file, src, diag.span);
            does_context_intersect_changes(&contexts, changes)
        }
    }
}

fn diagnostic_line_span(diag: &Diagnostic, source: Option<&str>) -> (u32, u32) {
    let Some(src) = source else {
        return (diag.loc.line, diag.loc.line);
    };
    if src.is_empty() || diag.span.start >= diag.span.end || (diag.span.end as usize) > src.len() {
        return (diag.loc.line, diag.loc.line);
    }
    let line_starts = compute_line_starts(src);
    let start_line = loc_from_line_starts(&line_starts, diag.span.start).line;
    let end_line = loc_from_line_starts(
        &line_starts,
        diag.span.end.saturating_sub(1).max(diag.span.start),
    )
    .line;
    (start_line, end_line.max(start_line))
}

fn ranges_intersect_any(target: (u32, u32), ranges: &[(u32, u32)]) -> bool {
    let (t_start, t_end) = target;
    ranges
        .iter()
        .any(|&(r_start, r_end)| t_start <= r_end && r_start <= t_end)
}

fn does_context_intersect_changes(
    contexts: &[OwnedLineContext],
    changes: &ChangedFileLineRanges,
) -> bool {
    contexts.iter().any(|ctx| {
        let (start_line, end_line) = ctx.range;
        for &(changed_start, changed_end) in &changes.ranges {
            let mut rem_start = start_line.max(changed_start);
            let rem_end = end_line.min(changed_end);
            for &(ex_start, ex_end) in &ctx.excluded_ranges {
                if ex_end < rem_start {
                    continue;
                }
                if ex_start > rem_end {
                    break;
                }
                if ex_start > rem_start {
                    return true;
                }
                rem_start = rem_start.max(ex_end.saturating_add(1));
            }
            if rem_start <= rem_end {
                return true;
            }
        }

        changes.deletion_lines.iter().any(|&del_line| {
            del_line >= start_line
                && del_line < end_line
                && !ctx
                    .excluded_ranges
                    .iter()
                    .any(|&(ex_start, ex_end)| del_line >= ex_start && del_line < ex_end)
        })
    })
}

fn resolve_jsx_owner_contexts(
    path: &Path,
    source: &str,
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let line_starts = compute_line_starts(source);
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        return Vec::new();
    }
    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program)
        .semantic;

    let target_offset = diag_span.start;
    let mut best_node: Option<(NodeId, Span)> = None;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let span = match node.kind() {
            AstKind::JSXElement(el) => el.span,
            AstKind::JSXFragment(frag) => frag.span,
            _ => continue,
        };
        if span.start <= target_offset && target_offset < span.end {
            match best_node {
                None => best_node = Some((node_id, span)),
                Some((_, prev_span))
                    if (span.end - span.start) <= (prev_span.end - prev_span.start) =>
                {
                    best_node = Some((node_id, span));
                }
                Some(_) => {}
            }
        }
    }

    let Some((owner_id, owner_span)) = best_node else {
        return Vec::new();
    };

    let owner_range = span_to_line_range(&line_starts, owner_span);
    let mut excluded_ranges = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if node_id == owner_id {
            continue;
        }
        let child_span = match node.kind() {
            AstKind::JSXElement(el) => el.span,
            AstKind::JSXFragment(frag) => frag.span,
            _ => continue,
        };
        if child_span.start >= owner_span.start
            && child_span.end <= owner_span.end
            && semantic
                .nodes()
                .ancestor_ids(node_id)
                .any(|anc| anc == owner_id)
        {
            excluded_ranges.push(span_to_line_range(&line_starts, child_span));
        }
    }
    excluded_ranges.sort_unstable();

    vec![OwnedLineContext {
        range: owner_range,
        excluded_ranges,
    }]
}

fn resolve_subject_owner_contexts(
    path: &Path,
    source: &str,
    file_ir: Option<&FileIr>,
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let line_starts = compute_line_starts(source);
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        if let Some(ir) = file_ir
            && let Some(subj) = ir
                .subjects
                .iter()
                .find(|s| s.span.start <= diag_span.start && diag_span.start < s.span.end)
        {
            return vec![OwnedLineContext {
                range: span_to_line_range(&line_starts, Span::new(subj.span.start, subj.span.end)),
                excluded_ranges: Vec::new(),
            }];
        }
        return Vec::new();
    }

    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program)
        .semantic;

    let target_offset = diag_span.start;
    let mut best_fn: Option<(NodeId, Span)> = None;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let Some(fn_span) = non_hook_function_boundary_span(&semantic, node_id, node.kind()) else {
            continue;
        };
        if fn_span.start <= target_offset && target_offset < fn_span.end {
            match best_fn {
                None => best_fn = Some((node_id, fn_span)),
                Some((_, prev_span))
                    if (fn_span.end - fn_span.start) <= (prev_span.end - prev_span.start) =>
                {
                    best_fn = Some((node_id, fn_span));
                }
                Some(_) => {}
            }
        }
    }

    let Some((owner_id, owner_span)) = best_fn else {
        return Vec::new();
    };

    let owner_range = span_to_line_range(&line_starts, owner_span);
    let mut excluded_ranges = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if node_id == owner_id {
            continue;
        }
        let Some(child_span) = non_hook_function_boundary_span(&semantic, node_id, node.kind())
        else {
            continue;
        };
        if child_span.start >= owner_span.start
            && child_span.end <= owner_span.end
            && semantic
                .nodes()
                .ancestor_ids(node_id)
                .any(|anc| anc == owner_id)
        {
            excluded_ranges.push(span_to_line_range(&line_starts, child_span));
        }
    }
    excluded_ranges.sort_unstable();

    vec![OwnedLineContext {
        range: owner_range,
        excluded_ranges,
    }]
}

fn non_hook_function_boundary_span(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
) -> Option<Span> {
    let raw_span = match kind {
        AstKind::Function(f) => f.span,
        AstKind::ArrowFunctionExpression(arrow) => arrow.span,
        _ => return None,
    };

    let parent_id = semantic.nodes().parent_id(node_id);
    match semantic.nodes().kind(parent_id) {
        AstKind::CallExpression(call) if is_hook_or_frame_call(call) => None,
        AstKind::VariableDeclarator(decl) => {
            let grand_id = semantic.nodes().parent_id(parent_id);
            if let AstKind::VariableDeclaration(var_decl) = semantic.nodes().kind(grand_id)
                && var_decl.declarations.len() == 1
            {
                let great_id = semantic.nodes().parent_id(grand_id);
                if let AstKind::ExportNamedDeclaration(exp) = semantic.nodes().kind(great_id) {
                    return Some(exp.span);
                }
                return Some(var_decl.span);
            }
            Some(decl.span)
        }
        AstKind::ExportNamedDeclaration(exp) => Some(exp.span),
        AstKind::ExportDefaultDeclaration(exp) => Some(exp.span),
        _ => Some(raw_span),
    }
}

fn is_hook_or_frame_call(call: &CallExpression<'_>) -> bool {
    let name = match call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    let Some(callee) = name else {
        return false;
    };
    callee == "useFrame"
        || callee == "requestAnimationFrame"
        || (callee.starts_with("use")
            && callee.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase))
}

fn resolve_related_node_contexts(
    path: &Path,
    source: &str,
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let line_starts = compute_line_starts(source);
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        return Vec::new();
    }
    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program)
        .semantic;

    let mut owned_spans: Vec<Span> = Vec::new();
    if diag_span.start < diag_span.end && (diag_span.end as usize) <= source.len() {
        owned_spans.push(Span::new(diag_span.start, diag_span.end));
    }

    // Find any enclosing or overlapping hook CallExpression (`useEffect`, `useLayoutEffect`, `useMemo`, `useCallback`)
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !is_hook_or_frame_call(call) {
            continue;
        }
        if call.span.start <= diag_span.start && diag_span.end <= call.span.end {
            owned_spans.push(call.span);
            collect_referenced_local_declarations(&semantic, node_id, call.span, &mut owned_spans);
        }
    }

    owned_spans
        .into_iter()
        .map(|sp| OwnedLineContext {
            range: span_to_line_range(&line_starts, sp),
            excluded_ranges: Vec::new(),
        })
        .collect()
}

fn collect_referenced_local_declarations(
    semantic: &Semantic<'_>,
    hook_node_id: NodeId,
    hook_span: Span,
    out: &mut Vec<Span>,
) {
    let enclosing_fn_span = semantic
        .nodes()
        .ancestor_ids(hook_node_id)
        .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => Some(f.span),
            AstKind::ArrowFunctionExpression(a) => Some(a.span),
            _ => None,
        });

    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::IdentifierReference(ident) = node.kind() else {
            continue;
        };
        if ident.span.start < hook_span.start || ident.span.end > hook_span.end {
            continue;
        }
        let Some(ref_id) = ident.reference_id.get() else {
            continue;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
            continue;
        };
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        match semantic.nodes().kind(decl_id) {
            AstKind::VariableDeclarator(decl) => {
                // Only attach local callback/variable declarations inside the component body, not useState bindings
                let is_fn_like = decl.init.as_ref().is_some_and(|init| {
                    matches!(
                        init.without_parentheses(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
                if is_fn_like
                    && enclosing_fn_span.is_none_or(|fn_sp| {
                        decl.span.start >= fn_sp.start && decl.span.end <= fn_sp.end
                    })
                {
                    let parent_id = semantic.nodes().parent_id(decl_id);
                    if let AstKind::VariableDeclaration(var_decl) = semantic.nodes().kind(parent_id)
                    {
                        out.push(var_decl.span);
                    } else {
                        out.push(decl.span);
                    }
                }
            }
            AstKind::Function(func)
                if enclosing_fn_span.is_none_or(|fn_sp| {
                    func.span.start > fn_sp.start && func.span.end <= fn_sp.end
                }) =>
            {
                out.push(func.span);
            }
            _ => {}
        }
    }
}

fn span_to_line_range(line_starts: &[u32], span: Span) -> (u32, u32) {
    let start_line = loc_from_line_starts(line_starts, span.start).line;
    let end_line =
        loc_from_line_starts(line_starts, span.end.saturating_sub(1).max(span.start)).line;
    (start_line, end_line.max(start_line))
}

/// Computes the deterministic occurrence identity for `diag` (`<rel_file>::<line>:<col>::dotore/<rule>::<digest>`).
#[must_use]
pub fn compute_diagnostic_id(diag: &Diagnostic, root_dir: Option<&Path>) -> String {
    let rel_file = normalize_display_path(&diag.file, root_dir);
    let digest = fnv1a_128_hex(&[
        diag.severity.as_str(),
        "\0",
        &diag.message,
        "\0",
        &diag.target_name,
    ]);
    format!(
        "{rel_file}::{}:{}::dotore/{}::{digest}",
        diag.loc.line,
        diag.loc.column,
        diag.rule.as_str()
    )
}

/// Computes a rename- and formatting-resilient fingerprint for `diag` from its rule ID,
/// normalized message (independent of enclosing component name), and normalized AST/source tokens
/// (independent of file path and line number).
#[must_use]
pub fn compute_diagnostic_fingerprint(diag: &Diagnostic, source: Option<&str>) -> String {
    let norm_msg = normalize_message_for_fingerprint(&diag.message, diag.subject_name.as_deref());
    let norm_target = normalize_ast_tokens(&diag.target_name);
    let span_tokens = source
        .and_then(|src| {
            let start = diag.span.start as usize;
            let end = diag.span.end as usize;
            if start < end && end <= src.len() {
                src.get(start..end)
            } else {
                None
            }
        })
        .map(normalize_ast_tokens)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| norm_target.clone());

    let digest = fnv1a_128_hex(&[
        diag.rule.as_str(),
        "\0",
        &norm_msg,
        "\0",
        &norm_target,
        "\0",
        &span_tokens,
    ]);
    format!("fp::{}::{digest}", diag.rule.as_str())
}

/// Computes the structural `(rule, normalized_message, normalized_target)` fingerprint without source span text.
#[must_use]
pub fn compute_structural_fingerprint(diag: &Diagnostic) -> String {
    let norm_msg = normalize_message_for_fingerprint(&diag.message, diag.subject_name.as_deref());
    let norm_target = normalize_ast_tokens(&diag.target_name);
    let digest = fnv1a_128_hex(&[diag.rule.as_str(), "\0", &norm_msg, "\0", &norm_target]);
    format!("fp::{}::{digest}", diag.rule.as_str())
}

fn normalize_message_for_fingerprint(message: &str, subject_name: Option<&str>) -> String {
    let mut cleaned = message.to_string();
    if let Some(subj) = subject_name
        && !subj.is_empty()
    {
        let backticked = format!("`{subj}`");
        cleaned = cleaned.replace(&backticked, "`<subject>`");
    }
    normalize_ast_tokens(&cleaned)
}

/// Normalizes JS/TS/message text into a formatting-invariant token stream (stripping comments,
/// unifying quote delimiters, and collapsing whitespace around punctuation and identifiers).
#[must_use]
pub fn normalize_ast_tokens(input: &str) -> String {
    let mut tokens: Vec<String> = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Skip single-line comments `// ...`
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Skip block comments `/* ... */`
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Normalize string literals (`'...'` and `"..."` -> `"..."`)
        if b == b'\'' || b == b'"' {
            let quote = b;
            i += 1;
            let mut content = String::new();
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                content.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            tokens.push(format!(
                "{:?}",
                content.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
            continue;
        }
        // Identifier or number
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            if let Some(word) = input.get(start..i) {
                tokens.push(word.to_string());
            }
            continue;
        }
        // Skip optional trailing semicolons so formatting differences (`a()` vs `a();`) don't split fingerprints
        if b == b';' {
            i += 1;
            continue;
        }
        // Multi-char operators (`=>`, `===`, `!==`, `==`, `!=`, `<=`, `>=`, `&&`, `||`, `??`, `...`)
        if let Some(op3) = input.get(i..i + 3)
            && matches!(op3, "===" | "!==" | "...")
        {
            tokens.push(op3.to_string());
            i += 3;
            continue;
        }
        if let Some(op2) = input.get(i..i + 2)
            && matches!(op2, "=>" | "==" | "!=" | "<=" | ">=" | "&&" | "||" | "??")
        {
            tokens.push(op2.to_string());
            i += 2;
            continue;
        }
        // Single char punctuation or UTF-8 char
        if let Some(ch) = input[i..].chars().next() {
            tokens.push(ch.to_string());
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }

    tokens.join(" ")
}

fn normalize_display_path(path: &Path, root_dir: Option<&Path>) -> String {
    let stripped = if let Some(root) = root_dir {
        path.strip_prefix(root).unwrap_or(path)
    } else {
        path
    };
    let raw = stripped.to_string_lossy().replace('\\', "/");
    raw.strip_prefix("./").unwrap_or(&raw).to_string()
}

fn fnv1a_128_hex(parts: &[&str]) -> String {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    let prime: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    for part in parts {
        for &byte in part.as_bytes() {
            hash ^= u128::from(byte);
            hash = hash.wrapping_mul(prime);
        }
    }
    format!("{hash:032x}")
}

/// Summary of a `--baseline` multiset comparison attached to [`crate::JsonReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSummary {
    /// Path or reference of the baseline source.
    pub baseline_source: String,
    /// Count of net-new diagnostics introduced since the baseline.
    pub introduced_count: usize,
    /// Count of baseline diagnostics that were resolved/fixed.
    pub fixed_count: usize,
    /// Count of pre-existing diagnostics matched and suppressed from active findings.
    pub preexisting_count: usize,
    /// Total diagnostics present in the baseline report.
    pub baseline_total_count: usize,
}

/// Result of comparing current diagnostics against a baseline report as a multiset.
#[derive(Debug, Clone)]
pub struct BaselineDeltaResult {
    /// Net-new (introduced) diagnostics retained after multiset subtraction.
    pub introduced_diagnostics: Vec<Diagnostic>,
    /// Delta counts (`introduced_count`, `fixed_count`, `preexisting_count`, `baseline_total_count`).
    pub summary: BaselineSummary,
}

/// A minimal baseline diagnostic entry deserialized from a saved JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiagnosticEntry {
    /// Rule identifier.
    pub rule: RuleId,
    /// File path in the baseline report.
    #[serde(default)]
    pub file: PathBuf,
    /// Enclosing **Subject** name in the baseline report, if any.
    #[serde(default)]
    pub subject_name: Option<String>,
    /// Target identifier name.
    #[serde(default)]
    pub target_name: String,
    /// Diagnostic message.
    #[serde(default)]
    pub message: String,
    /// Precomputed normalized AST/source token fingerprint from the saved report.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Precomputed structural `(rule, message, target)` fingerprint.
    #[serde(default)]
    pub structural_fingerprint: Option<String>,
    /// 1-based line number in the baseline report (`0` if omitted).
    #[serde(default)]
    pub line: u32,
}

impl BaselineDiagnosticEntry {
    /// Creates a [`BaselineDiagnosticEntry`] from a live [`Diagnostic`] and optional file source.
    #[must_use]
    pub fn from_diagnostic(diag: &Diagnostic, source: Option<&str>) -> Self {
        Self {
            rule: diag.rule,
            file: diag.file.clone(),
            subject_name: diag.subject_name.clone(),
            target_name: diag.target_name.clone(),
            message: diag.message.clone(),
            fingerprint: Some(compute_diagnostic_fingerprint(diag, source)),
            structural_fingerprint: Some(compute_structural_fingerprint(diag)),
            line: diag.loc.line,
        }
    }

    fn effective_primary_fingerprint(&self) -> String {
        if let Some(fp) = &self.fingerprint
            && !fp.is_empty()
        {
            return fp.clone();
        }
        self.effective_structural_fingerprint()
    }

    fn effective_structural_fingerprint(&self) -> String {
        if let Some(sfp) = &self.structural_fingerprint
            && !sfp.is_empty()
        {
            return sfp.clone();
        }
        let norm_msg =
            normalize_message_for_fingerprint(&self.message, self.subject_name.as_deref());
        let norm_target = normalize_ast_tokens(&self.target_name);
        let digest = fnv1a_128_hex(&[self.rule.as_str(), "\0", &norm_msg, "\0", &norm_target]);
        format!("fp::{}::{digest}", self.rule.as_str())
    }
}

/// Compares `current_diagnostics` against `baseline_entries` as a multiset of normalized
/// `rule + message + AST-token` fingerprints (independent of file path and line number),
/// returning only net-new (`introduced_diagnostics`) findings and the [`BaselineSummary`].
#[must_use]
pub fn compare_baseline_diagnostics(
    current_diagnostics: &[Diagnostic],
    current_sources: &HashMap<PathBuf, String>,
    baseline_entries: &[BaselineDiagnosticEntry],
    baseline_source: &str,
) -> BaselineDeltaResult {
    let mut unmatched_head: BTreeSet<usize> = (0..current_diagnostics.len()).collect();
    let mut unmatched_base: BTreeSet<usize> = (0..baseline_entries.len()).collect();

    let head_primary_fps: Vec<String> = current_diagnostics
        .iter()
        .map(|d| {
            let src = current_sources.get(&d.file).map(String::as_str);
            compute_diagnostic_fingerprint(d, src)
        })
        .collect();
    let head_struct_fps: Vec<String> = current_diagnostics
        .iter()
        .map(compute_structural_fingerprint)
        .collect();

    let base_primary_fps: Vec<String> = baseline_entries
        .iter()
        .map(BaselineDiagnosticEntry::effective_primary_fingerprint)
        .collect();
    let base_struct_fps: Vec<String> = baseline_entries
        .iter()
        .map(BaselineDiagnosticEntry::effective_structural_fingerprint)
        .collect();

    // Pass 1: Match by exact primary AST-token fingerprint `(rule, fingerprint)`
    match_multiset_by_key(
        current_diagnostics,
        baseline_entries,
        &head_primary_fps,
        &base_primary_fps,
        &mut unmatched_head,
        &mut unmatched_base,
    );

    // Pass 2: Match remaining diagnostics by structural `(rule, normalized_message, normalized_target)` fingerprint
    // so formatting changes, component extractions, or source span shifts inside the same rule+target still match.
    match_multiset_by_key(
        current_diagnostics,
        baseline_entries,
        &head_struct_fps,
        &base_struct_fps,
        &mut unmatched_head,
        &mut unmatched_base,
    );

    let baseline_total_count = baseline_entries.len();
    let preexisting_count = baseline_total_count.saturating_sub(unmatched_base.len());
    let fixed_count = unmatched_base.len();
    let introduced_diagnostics: Vec<Diagnostic> = unmatched_head
        .into_iter()
        .map(|idx| current_diagnostics[idx].clone())
        .collect();
    let introduced_count = introduced_diagnostics.len();

    BaselineDeltaResult {
        introduced_diagnostics,
        summary: BaselineSummary {
            baseline_source: baseline_source.to_string(),
            introduced_count,
            fixed_count,
            preexisting_count,
            baseline_total_count,
        },
    }
}

fn match_multiset_by_key(
    current_diagnostics: &[Diagnostic],
    baseline_entries: &[BaselineDiagnosticEntry],
    head_keys: &[String],
    base_keys: &[String],
    unmatched_head: &mut BTreeSet<usize>,
    unmatched_base: &mut BTreeSet<usize>,
) {
    let mut base_buckets: HashMap<(RuleId, &str), Vec<usize>> = HashMap::new();
    for &b_idx in unmatched_base.iter() {
        let entry = &baseline_entries[b_idx];
        base_buckets
            .entry((entry.rule, base_keys[b_idx].as_str()))
            .or_default()
            .push(b_idx);
    }

    let mut head_buckets: HashMap<(RuleId, &str), Vec<usize>> = HashMap::new();
    for &h_idx in unmatched_head.iter() {
        let diag = &current_diagnostics[h_idx];
        head_buckets
            .entry((diag.rule, head_keys[h_idx].as_str()))
            .or_default()
            .push(h_idx);
    }

    for ((rule, key), mut b_indices) in base_buckets {
        let Some(mut h_indices) = head_buckets.remove(&(rule, key)) else {
            continue;
        };

        // First pair entries in the same file with minimum line distance
        let mut b_pos = 0;
        while b_pos < b_indices.len() && !h_indices.is_empty() {
            let b_idx = b_indices[b_pos];
            let b_entry = &baseline_entries[b_idx];
            if let Some((best_h_pos, _)) = h_indices
                .iter()
                .enumerate()
                .filter(|&(_, &h_idx)| {
                    paths_match_loosely(&current_diagnostics[h_idx].file, &b_entry.file)
                })
                .min_by_key(|&(_, &h_idx)| {
                    current_diagnostics[h_idx].loc.line.abs_diff(b_entry.line)
                })
            {
                let matched_h = h_indices.remove(best_h_pos);
                b_indices.remove(b_pos);
                unmatched_head.remove(&matched_h);
                unmatched_base.remove(&b_idx);
            } else {
                b_pos += 1;
            }
        }

        // Next pair remaining occurrences across renamed/moved/extracted files by closest line
        for b_idx in b_indices {
            if h_indices.is_empty() {
                break;
            }
            let b_line = baseline_entries[b_idx].line;
            let (best_h_pos, _) = h_indices
                .iter()
                .enumerate()
                .min_by_key(|&(_, &h_idx)| current_diagnostics[h_idx].loc.line.abs_diff(b_line))
                .unwrap_or((0, &h_indices[0]));
            let matched_h = h_indices.remove(best_h_pos);
            unmatched_head.remove(&matched_h);
            unmatched_base.remove(&b_idx);
        }
    }
}

fn paths_match_loosely(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let a_str = a.to_string_lossy().replace('\\', "/");
    let b_str = b.to_string_lossy().replace('\\', "/");
    let a_clean = a_str.strip_prefix("./").unwrap_or(&a_str);
    let b_clean = b_str.strip_prefix("./").unwrap_or(&b_str);
    a_clean == b_clean
        || a_clean.ends_with(&format!("/{b_clean}"))
        || b_clean.ends_with(&format!("/{a_clean}"))
}

/// Parses a baseline JSON report string into [`BaselineDiagnosticEntry`] records.
///
/// # Errors
/// Returns an error string if `json_str` is not valid JSON or lacks a `"diagnostics"` array.
pub fn parse_baseline_report_str(json_str: &str) -> Result<Vec<BaselineDiagnosticEntry>, String> {
    let root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid baseline JSON: {e}"))?;

    let diag_array = if let Some(arr) = root
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
    {
        arr
    } else if let Some(arr) = root.as_array() {
        arr
    } else {
        return Err("Baseline JSON does not contain a `diagnostics` array.".to_string());
    };

    let fp_map = root
        .get("diagnostic_fingerprints")
        .and_then(serde_json::Value::as_object);
    let mut entries = Vec::with_capacity(diag_array.len());
    for item in diag_array {
        let Some(rule_str) = item.get("rule").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(rule) = RuleId::parse(rule_str) else {
            continue;
        };
        let file = item
            .get("file")
            .or_else(|| item.get("filePath"))
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_default();
        let subject_name = item
            .get("subject_name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let target_name = item
            .get("target_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let message = item
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let item_id = item.get("id").and_then(serde_json::Value::as_str);
        let item_fp = item
            .get("fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let source_fp = item_id
            .and_then(|id| fp_map.and_then(|m| m.get(id)))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let fingerprint = source_fp.or_else(|| item_fp.clone());
        let structural_fingerprint = item
            .get("structural_fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or(item_fp);
        let line = item
            .get("loc")
            .and_then(|l| l.get("line"))
            .or_else(|| item.get("line"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);

        entries.push(BaselineDiagnosticEntry {
            rule,
            file,
            subject_name,
            target_name,
            message,
            fingerprint,
            structural_fingerprint,
            line,
        });
    }

    Ok(entries)
}

/// Attempts to load baseline diagnostic entries from a JSON file path or a git revision's base blobs.
///
/// If the JSON file is missing/unreadable or git base blobs are unavailable (e.g. shallow clone),
/// returns `Err(...)` so the caller can degrade gracefully to diff mode (`baseline_degraded: true`).
pub(crate) fn load_baseline_entries(
    workspace_root: &Path,
    baseline_arg: &Path,
    enabled_rules: Option<&[RuleId]>,
) -> Result<Vec<BaselineDiagnosticEntry>, String> {
    if baseline_arg.is_file() {
        let content = fs::read_to_string(baseline_arg).map_err(|e| {
            format!(
                "Failed to read baseline file {}: {e}",
                baseline_arg.display()
            )
        })?;
        return parse_baseline_report_str(&content);
    }

    // If not a file on disk, check if `baseline_arg` is a git revision whose base blobs are available
    let rev_str = baseline_arg.to_string_lossy();
    validate_git_revision(&rev_str)?;
    let repo_root_out = run_git(workspace_root, &["rev-parse", "--show-toplevel"])?;
    let repo_root = PathBuf::from(repo_root_out.trim());

    // Verify commit object and tree are present in local git object store
    let tree_spec = format!("{rev_str}^{{tree}}");
    if run_git(&repo_root, &["cat-file", "-e", &tree_spec]).is_err()
        && run_git(&repo_root, &["rev-parse", "--verify", &tree_spec]).is_err()
    {
        return Err(format!(
            "Base git tree for {rev_str:?} is unavailable (shallow clone or missing object)."
        ));
    }

    let ls_tree = run_git(&repo_root, &["ls-tree", "-r", "--name-only", &rev_str])?;
    let mut base_files: Vec<(PathBuf, String)> = Vec::new();
    for rel_line in ls_tree.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let is_source = [".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts"]
            .iter()
            .any(|ext| rel_line.ends_with(ext))
            || rel_line.ends_with("package.json")
            || rel_line.contains("dotore.config.");
        if !is_source {
            continue;
        }
        let blob_spec = format!("{rev_str}:{rel_line}");
        let blob_content = run_git(&repo_root, &["show", &blob_spec])?;
        base_files.push((PathBuf::from(rel_line), blob_content));
    }

    let base_sources: HashMap<PathBuf, String> = base_files.iter().cloned().collect();
    let base_report = crate::analyze_project_sources(base_files, enabled_rules);
    Ok(base_report
        .diagnostics
        .iter()
        .map(|d| {
            let src = base_sources.get(&d.file).map(String::as_str);
            BaselineDiagnosticEntry::from_diagnostic(d, src)
        })
        .collect())
}
