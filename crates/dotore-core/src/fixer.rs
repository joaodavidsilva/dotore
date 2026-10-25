//! Surgical source auto-fixer applying single-file and cross-file `Autofix`-tier byte-range
//! edits in reverse offset order with pluggable syntax verification.

use std::{
    cmp::Reverse,
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::RwLock,
};

use serde::Serialize;

use crate::{
    ir::LanguageAnalyzer,
    rules::{ByteEdit, Diagnostic, PrescriptionTier},
};

type SyntaxValidatorFn = fn(&Path, &str) -> bool;

static DEFAULT_SYNTAX_VALIDATOR: RwLock<Option<SyntaxValidatorFn>> = RwLock::new(None);

/// Registers the default process-wide syntax validator function used by [`apply_autofixes`]
/// and [`apply_patches_to_source`] when called without an explicit validator callback.
pub fn register_default_syntax_validator(validator: SyntaxValidatorFn) {
    if let Ok(mut guard) = DEFAULT_SYNTAX_VALIDATOR.write() {
        *guard = Some(validator);
    }
}

fn default_validate_syntax(path: &Path, source: &str) -> bool {
    if let Ok(guard) = DEFAULT_SYNTAX_VALIDATOR.read()
        && let Some(validator) = *guard
    {
        return validator(path, source);
    }
    has_balanced_delimiters(source)
}

/// Result of applying `Autofix` patches to a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileFixResult {
    /// Path of the modified file.
    pub file: PathBuf,
    /// Number of `Autofix` diagnostics resolved in this file.
    pub patches_applied: usize,
    /// Human-readable descriptions of each applied patch.
    pub descriptions: Vec<String>,
    /// Rewritten source code.
    pub new_source: String,
}

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace
/// using the registered default syntax validator.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
) -> io::Result<Vec<FileFixResult>> {
    apply_autofixes_with_validator(diagnostics, sources, dry_run, default_validate_syntax)
}

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace,
/// dispatching syntax validation to the matching [`LanguageAnalyzer`] for each modified file.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes_with_analyzers(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
    analyzers: &[&dyn LanguageAnalyzer],
) -> io::Result<Vec<FileFixResult>> {
    apply_autofixes_with_validator(diagnostics, sources, dry_run, |path, src| {
        validate_with_analyzers(path, src, analyzers)
    })
}

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace,
/// validating every candidate rewrite with `validate_syntax(path, rewritten_source)`.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes_with_validator<F>(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
    validate_syntax: F,
) -> io::Result<Vec<FileFixResult>>
where
    F: Fn(&Path, &str) -> bool,
{
    let mut accepted_edits_by_file: HashMap<PathBuf, Vec<ByteEdit>> = HashMap::new();
    let mut descriptions_by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for diag in diagnostics {
        if diag.tier != PrescriptionTier::Autofix || diag.rule.is_architecture_soc_or_reuse_rule() {
            continue;
        }
        let Some(patch) = &diag.autofix else {
            continue;
        };
        if patch.edits.is_empty() {
            continue;
        }

        let mut edits_by_target: HashMap<PathBuf, Vec<ByteEdit>> = HashMap::new();
        for edit in &patch.edits {
            let target_path = edit
                .file
                .as_deref()
                .unwrap_or(diag.file.as_path())
                .to_path_buf();
            edits_by_target
                .entry(target_path)
                .or_default()
                .push(edit.clone());
        }

        let all_targets_valid = edits_by_target.iter().all(|(target_path, new_edits)| {
            let Some(orig_source) = sources.get(target_path) else {
                return false;
            };
            let existing = accepted_edits_by_file
                .get(target_path)
                .map_or(&[][..], Vec::as_slice);
            candidate_edits_are_valid(
                target_path,
                orig_source,
                existing,
                new_edits,
                &validate_syntax,
            )
        });

        if !all_targets_valid {
            continue;
        }

        for (target_path, new_edits) in edits_by_target {
            accepted_edits_by_file
                .entry(target_path.clone())
                .or_default()
                .extend(new_edits);
            descriptions_by_file
                .entry(target_path)
                .or_default()
                .push(patch.description.clone());
        }
    }

    let mut file_paths: Vec<PathBuf> = accepted_edits_by_file.keys().cloned().collect();
    file_paths.sort();

    let mut results = Vec::new();
    for path in file_paths {
        let Some(orig_source) = sources.get(&path) else {
            continue;
        };
        let Some(edits) = accepted_edits_by_file.remove(&path) else {
            continue;
        };
        let descriptions = descriptions_by_file.remove(&path).unwrap_or_default();
        if edits.is_empty() || descriptions.is_empty() {
            continue;
        }

        let new_source = rewrite_source_with_edits(orig_source, edits);
        if !validate_syntax(&path, &new_source) {
            continue;
        }

        if !dry_run {
            fs::write(&path, &new_source)?;
        }
        results.push(FileFixResult {
            file: path,
            patches_applied: descriptions.len(),
            descriptions,
            new_source,
        });
    }

    Ok(results)
}

/// Applies non-overlapping `Autofix` patches to an in-memory source string,
/// returning `(new_source, applied_descriptions)`.
#[must_use]
pub fn apply_patches_to_source(source: &str, diagnostics: &[Diagnostic]) -> (String, Vec<String>) {
    apply_patches_to_source_with_validator(source, diagnostics, default_validate_syntax)
}

/// Applies non-overlapping `Autofix` patches to an in-memory source string,
/// validating candidate rewrites with the matching [`LanguageAnalyzer`] from `analyzers`.
#[must_use]
pub fn apply_patches_to_source_with_analyzers(
    source: &str,
    diagnostics: &[Diagnostic],
    analyzers: &[&dyn LanguageAnalyzer],
) -> (String, Vec<String>) {
    apply_patches_to_source_with_validator(source, diagnostics, |path, src| {
        validate_with_analyzers(path, src, analyzers)
    })
}

/// Applies non-overlapping `Autofix` patches to an in-memory source string,
/// validating candidate rewrites with `validate_syntax(path, rewritten_source)`.
#[must_use]
pub fn apply_patches_to_source_with_validator<F>(
    source: &str,
    diagnostics: &[Diagnostic],
    validate_syntax: F,
) -> (String, Vec<String>)
where
    F: Fn(&Path, &str) -> bool,
{
    let mut accepted_edits: Vec<ByteEdit> = Vec::new();
    let mut descriptions: Vec<String> = Vec::new();

    for diag in diagnostics {
        if diag.tier != PrescriptionTier::Autofix || diag.rule.is_architecture_soc_or_reuse_rule() {
            continue;
        }
        let Some(patch) = &diag.autofix else {
            continue;
        };
        let local_edits: Vec<ByteEdit> = patch
            .edits
            .iter()
            .filter(|e| e.file.as_ref().is_none_or(|f| f == &diag.file))
            .cloned()
            .collect();
        if local_edits.is_empty() {
            continue;
        }

        if !candidate_edits_are_valid(
            &diag.file,
            source,
            &accepted_edits,
            &local_edits,
            &validate_syntax,
        ) {
            continue;
        }

        accepted_edits.extend(local_edits);
        descriptions.push(patch.description.clone());
    }

    let rewritten = rewrite_source_with_edits(source, accepted_edits);
    (rewritten, descriptions)
}

fn validate_with_analyzers(path: &Path, source: &str, analyzers: &[&dyn LanguageAnalyzer]) -> bool {
    for analyzer in analyzers {
        if analyzer.supports_path(path) {
            return analyzer.validate_syntax(path, source);
        }
    }
    default_validate_syntax(path, source)
}

fn candidate_edits_are_valid<F>(
    path: &Path,
    orig_source: &str,
    existing_edits: &[ByteEdit],
    candidate_edits: &[ByteEdit],
    validate_syntax: &F,
) -> bool
where
    F: Fn(&Path, &str) -> bool,
{
    for (idx, candidate) in candidate_edits.iter().enumerate() {
        let start = candidate.span.start as usize;
        let end = candidate.span.end as usize;
        if start > end
            || end > orig_source.len()
            || !orig_source.is_char_boundary(start)
            || !orig_source.is_char_boundary(end)
        {
            return false;
        }
        if existing_edits
            .iter()
            .any(|existing| spans_overlap(candidate, existing))
        {
            return false;
        }
        if candidate_edits[..idx]
            .iter()
            .any(|prior| spans_overlap(candidate, prior))
        {
            return false;
        }
    }

    let mut combined = Vec::with_capacity(existing_edits.len() + candidate_edits.len());
    combined.extend_from_slice(existing_edits);
    combined.extend_from_slice(candidate_edits);

    let preview = rewrite_source_with_edits(orig_source, combined);
    validate_syntax(path, &preview)
}

fn rewrite_source_with_edits(source: &str, mut edits: Vec<ByteEdit>) -> String {
    edits.sort_by_key(|a| Reverse((a.span.start, a.span.end)));

    let mut rewritten = source.to_string();
    for edit in edits {
        let start = edit.span.start as usize;
        let end = edit.span.end as usize;
        if start <= end
            && end <= rewritten.len()
            && rewritten.is_char_boundary(start)
            && rewritten.is_char_boundary(end)
        {
            rewritten.replace_range(start..end, &edit.replacement);
        }
    }
    rewritten
}

fn spans_overlap(a: &ByteEdit, b: &ByteEdit) -> bool {
    if a.span.start == a.span.end && b.span.start == b.span.end {
        return a.span.start == b.span.start && a.replacement == b.replacement;
    }
    if a.span.start == a.span.end {
        return a.span.start > b.span.start && a.span.start < b.span.end;
    }
    if b.span.start == b.span.end {
        return b.span.start > a.span.start && b.span.start < a.span.end;
    }
    a.span.start < b.span.end && b.span.start < a.span.end
}

fn has_balanced_delimiters(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0;

    while let Some(&b) = bytes.get(i) {
        if skip_delimiter_comment(bytes, &mut i) {
            continue;
        }
        if matches!(b, b'\'' | b'"' | b'`') {
            if !skip_quoted_literal(bytes, &mut i, b) {
                return false;
            }
            continue;
        }
        if !update_delimiter_stack(b, &mut stack) {
            return false;
        }
        i += 1;
    }

    stack.is_empty()
}

fn skip_delimiter_comment(bytes: &[u8], i: &mut usize) -> bool {
    let Some(&b) = bytes.get(*i) else {
        return false;
    };
    if b == b'#' || (b == b'/' && bytes.get(*i + 1) == Some(&b'/')) {
        while bytes.get(*i).is_some_and(|&c| c != b'\n') {
            *i += 1;
        }
        return true;
    }
    if b == b'/' && bytes.get(*i + 1) == Some(&b'*') {
        *i += 2;
        while *i + 1 < bytes.len()
            && !(bytes.get(*i) == Some(&b'*') && bytes.get(*i + 1) == Some(&b'/'))
        {
            *i += 1;
        }
        *i = (*i + 2).min(bytes.len());
        return true;
    }
    false
}

fn skip_quoted_literal(bytes: &[u8], i: &mut usize, quote: u8) -> bool {
    *i += 1;
    while let Some(&cur) = bytes.get(*i) {
        if cur == b'\\' {
            *i += 2;
            continue;
        }
        *i += 1;
        if cur == quote {
            return true;
        }
    }
    false
}

fn update_delimiter_stack(b: u8, stack: &mut Vec<u8>) -> bool {
    match b {
        b'(' => stack.push(b')'),
        b'[' => stack.push(b']'),
        b'{' => stack.push(b'}'),
        b')' | b']' | b'}' => return stack.pop() == Some(b),
        _ => {}
    }
    true
}
