//! Surgical source auto-fixer applying `Autofix`-tier byte-range edits in reverse offset order.

use std::{cmp::Reverse, collections::HashMap, fs, io, path::PathBuf};

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

/// Applies all non-overlapping `Autofix` patches across the workspace.
///
/// When `dry_run` is `false`, modified files are written back to disk.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
) -> io::Result<Vec<FileFixResult>> {
    let mut by_file: HashMap<&PathBuf, Vec<&Diagnostic>> = HashMap::new();
    for diag in diagnostics {
        if diag.tier == PrescriptionTier::Autofix && diag.autofix.is_some() {
            by_file.entry(&diag.file).or_default().push(diag);
        }
    }

    let mut file_paths: Vec<&PathBuf> = by_file.keys().copied().collect();
    file_paths.sort();

    let mut results = Vec::new();
    for path in file_paths {
        let Some(orig_source) = sources.get(path) else {
            continue;
        };
        let Some(file_diags) = by_file.get(path) else {
            continue;
        };
        let (new_source, descriptions) =
            apply_patches_from_iter(orig_source, file_diags.iter().copied());
        if descriptions.is_empty() {
            continue;
        }
        if !dry_run {
            fs::write(path, &new_source)?;
        }
        results.push(FileFixResult {
            file: path.clone(),
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
    apply_patches_from_iter(source, diagnostics.iter())
}

fn apply_patches_from_iter<'a, I>(source: &str, diagnostics: I) -> (String, Vec<String>)
where
    I: IntoIterator<Item = &'a Diagnostic>,
{
    let mut accepted_edits: Vec<ByteEdit> = Vec::new();
    let mut descriptions: Vec<String> = Vec::new();

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
        let overlaps = patch.edits.iter().any(|candidate| {
            let start = candidate.span.start as usize;
            let end = candidate.span.end as usize;
            if start > end || end > source.len() {
                return true;
            }
            accepted_edits
                .iter()
                .any(|existing| spans_overlap(candidate, existing))
        });
        if overlaps {
            continue;
        }
        accepted_edits.extend(patch.edits.iter().cloned());
        descriptions.push(patch.description.clone());
    }

    accepted_edits.sort_by_key(|a| Reverse(a.span.start));

    let mut rewritten = source.to_string();
    for edit in accepted_edits {
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

    (rewritten, descriptions)
}

const fn spans_overlap(a: &ByteEdit, b: &ByteEdit) -> bool {
    a.span.start < b.span.end && b.span.start < a.span.end
}
