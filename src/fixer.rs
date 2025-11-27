//! Surgical source auto-fixer applying single-file and cross-file `Autofix`-tier byte-range
//! edits in reverse offset order with `oxc_parser` syntax verification.

use std::{
    cmp::Reverse,
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use crate::rules::{ByteEdit, Diagnostic, PrescriptionTier};

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

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace.
///
/// Every candidate patch is validated atomically across all target files and verified to parse
/// without syntax errors via `oxc_parser`. When `dry_run` is `false`, modified files are written
/// back to disk.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
) -> io::Result<Vec<FileFixResult>> {
    let mut accepted_edits_by_file: HashMap<PathBuf, Vec<ByteEdit>> = HashMap::new();
    let mut descriptions_by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for diag in diagnostics {
        if diag.tier != PrescriptionTier::Autofix {
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
            let target_path = edit.file.clone().unwrap_or_else(|| diag.file.clone());
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
            candidate_edits_are_valid(target_path, orig_source, existing, new_edits)
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
        if !source_parses_cleanly(&path, &new_source) {
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
    let mut accepted_edits: Vec<ByteEdit> = Vec::new();
    let mut descriptions: Vec<String> = Vec::new();

    for diag in diagnostics {
        if diag.tier != PrescriptionTier::Autofix {
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

        if !candidate_edits_are_valid(&diag.file, source, &accepted_edits, &local_edits) {
            continue;
        }

        accepted_edits.extend(local_edits);
        descriptions.push(patch.description.clone());
    }

    let rewritten = rewrite_source_with_edits(source, accepted_edits);
    (rewritten, descriptions)
}

fn candidate_edits_are_valid(
    path: &Path,
    orig_source: &str,
    existing_edits: &[ByteEdit],
    candidate_edits: &[ByteEdit],
) -> bool {
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
    source_parses_cleanly(path, &preview)
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

fn source_parses_cleanly(path: &Path, source: &str) -> bool {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    parsed.diagnostics.is_empty()
}

const fn spans_overlap(a: &ByteEdit, b: &ByteEdit) -> bool {
    if a.span.start == a.span.end && b.span.start == b.span.end {
        return a.span.start == b.span.start;
    }
    if a.span.start == a.span.end {
        return a.span.start > b.span.start && a.span.start < b.span.end;
    }
    if b.span.start == b.span.end {
        return b.span.start > a.span.start && b.span.start < a.span.end;
    }
    a.span.start < b.span.end && b.span.start < a.span.end
}
