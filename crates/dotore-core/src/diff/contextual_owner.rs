//! **Contextual Owner** span resolution and `--scope full|changed|contextual|lines` diff filtering.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    ir::{
        ByteSpan, ContextualOwnerSpansIr, ExtractedFile, compute_line_starts, loc_from_line_starts,
    },
    rules::{ContextualOwnerPolicy, Diagnostic},
};

use super::patch::{ChangedFileLineRanges, DiffScope};

/// Provides AST byte spans needed by `--scope contextual` diff filtering across any language IR.
pub trait ContextualSpanProvider {
    /// File path of the analyzed file.
    fn file_path(&self) -> &Path;
    /// Verbatim source text of the file.
    fn file_source(&self) -> &str;
    /// Calls `f` for each JSX element or template/block subtree span (`ContextualOwnerPolicy::JsxElement`).
    fn for_each_element_span(&self, f: &mut dyn FnMut(ByteSpan));
    /// Calls `f` for each **Subject** span (`ContextualOwnerPolicy::Subject` fallback).
    fn for_each_subject_span(&self, f: &mut dyn FnMut(ByteSpan));
    /// Function/method boundary spans and related hook spans (`Subject` and `RelatedNodes`).
    fn contextual_owner_spans(&self) -> &ContextualOwnerSpansIr;
}

impl ContextualSpanProvider for ExtractedFile {
    fn file_path(&self) -> &Path {
        &self.path
    }

    fn file_source(&self) -> &str {
        &self.source
    }

    fn for_each_element_span(&self, f: &mut dyn FnMut(ByteSpan)) {
        for &span in &self.contextual_owner_spans.element_spans {
            f(span);
        }
    }

    fn for_each_subject_span(&self, f: &mut dyn FnMut(ByteSpan)) {
        for &(_, span, _) in &self.subject_spans {
            f(span);
        }
    }

    fn contextual_owner_spans(&self) -> &ContextualOwnerSpansIr {
        &self.contextual_owner_spans
    }
}

/// Filters `diagnostics` according to `scope` (`Full`, `Changed`, `Lines`, `Contextual`) and
/// the given changed files / hunk line ranges.
#[must_use]
pub fn filter_diagnostics_by_scope<F: ContextualSpanProvider>(
    diagnostics: Vec<Diagnostic>,
    scope: DiffScope,
    repo_root: &Path,
    changed_files: &[PathBuf],
    line_ranges: &[ChangedFileLineRanges],
    files: &[F],
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
            let file_ir = files.iter().find(|f| f.file_path() == diag.file);
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
    let lex = crate::config::workspace::clean_lexical_components(&joined);
    keys.push(lex.clone());
    if let Ok(canon) = fs::canonicalize(&joined)
        && !keys.contains(&canon)
    {
        keys.push(canon);
    }
    let rel_lex = crate::config::workspace::clean_lexical_components(path);
    if !keys.contains(&rel_lex) {
        keys.push(rel_lex);
    }
    keys
}

#[derive(Debug, Clone)]
struct OwnedLineContext {
    range: (u32, u32),
    excluded_ranges: Vec<(u32, u32)>,
}

/// Returns `true` if `diag` (or its **Contextual Owner** when `contextual` is `true`) intersects
/// `changes` (`ranges` or `deletion_lines`).
#[must_use]
pub fn diagnostic_intersects_changed_lines<F: ContextualSpanProvider>(
    diag: &Diagnostic,
    file_ir: Option<&F>,
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
            let Some(ir) = file_ir else {
                return false;
            };
            let src = source.unwrap_or_else(|| ir.file_source());
            let line_starts = compute_line_starts(src);
            let contexts = resolve_jsx_owner_contexts(ir, &line_starts, diag.span);
            does_context_intersect_changes(&contexts, changes)
        }
        ContextualOwnerPolicy::Subject => {
            let Some(ir) = file_ir else {
                return false;
            };
            let src = source.unwrap_or_else(|| ir.file_source());
            let line_starts = compute_line_starts(src);
            let contexts = resolve_subject_owner_contexts(ir, &line_starts, diag.span);
            does_context_intersect_changes(&contexts, changes)
        }
        ContextualOwnerPolicy::RelatedNodes => {
            let Some(ir) = file_ir else {
                return false;
            };
            let src = source.unwrap_or_else(|| ir.file_source());
            let line_starts = compute_line_starts(src);
            let contexts = resolve_related_node_contexts(ir, &line_starts, src.len(), diag.span);
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

fn resolve_jsx_owner_contexts<F: ContextualSpanProvider>(
    file_ir: &F,
    line_starts: &[u32],
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let target_offset = diag_span.start;
    let mut best_span: Option<ByteSpan> = None;

    file_ir.for_each_element_span(&mut |span| {
        if span.start <= target_offset && target_offset < span.end {
            match best_span {
                None => best_span = Some(span),
                Some(prev_span) if (span.end - span.start) <= (prev_span.end - prev_span.start) => {
                    best_span = Some(span);
                }
                Some(_) => {}
            }
        }
    });

    let Some(owner_span) = best_span else {
        return Vec::new();
    };

    let owner_range = span_to_line_range(line_starts, owner_span);
    let mut excluded_ranges = Vec::new();

    file_ir.for_each_element_span(&mut |child_span| {
        if child_span != owner_span
            && child_span.start >= owner_span.start
            && child_span.end <= owner_span.end
        {
            excluded_ranges.push(span_to_line_range(line_starts, child_span));
        }
    });
    excluded_ranges.sort_unstable();

    vec![OwnedLineContext {
        range: owner_range,
        excluded_ranges,
    }]
}

fn resolve_subject_owner_contexts<F: ContextualSpanProvider>(
    file_ir: &F,
    line_starts: &[u32],
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let target_offset = diag_span.start;
    let fn_spans = &file_ir.contextual_owner_spans().function_boundary_spans;
    if fn_spans.is_empty() {
        let mut found_subj: Option<ByteSpan> = None;
        file_ir.for_each_subject_span(&mut |span| {
            if found_subj.is_none() && span.start <= target_offset && target_offset < span.end {
                found_subj = Some(span);
            }
        });
        if let Some(subj_span) = found_subj {
            return vec![OwnedLineContext {
                range: span_to_line_range(line_starts, subj_span),
                excluded_ranges: Vec::new(),
            }];
        }
        return Vec::new();
    }

    let mut best_fn: Option<ByteSpan> = None;
    for &fn_span in fn_spans {
        if fn_span.start <= target_offset && target_offset < fn_span.end {
            match best_fn {
                None => best_fn = Some(fn_span),
                Some(prev_span)
                    if (fn_span.end - fn_span.start) <= (prev_span.end - prev_span.start) =>
                {
                    best_fn = Some(fn_span);
                }
                Some(_) => {}
            }
        }
    }

    let Some(owner_span) = best_fn else {
        return Vec::new();
    };

    let owner_range = span_to_line_range(line_starts, owner_span);
    let mut excluded_ranges = Vec::new();
    for &child_span in fn_spans {
        if child_span == owner_span {
            continue;
        }
        if child_span.start >= owner_span.start && child_span.end <= owner_span.end {
            excluded_ranges.push(span_to_line_range(line_starts, child_span));
        }
    }
    excluded_ranges.sort_unstable();

    vec![OwnedLineContext {
        range: owner_range,
        excluded_ranges,
    }]
}

fn resolve_related_node_contexts<F: ContextualSpanProvider>(
    file_ir: &F,
    line_starts: &[u32],
    source_len: usize,
    diag_span: ByteSpan,
) -> Vec<OwnedLineContext> {
    let mut owned_spans: Vec<ByteSpan> = Vec::new();
    if diag_span.start < diag_span.end && (diag_span.end as usize) <= source_len {
        owned_spans.push(diag_span);
    }

    for hook in &file_ir.contextual_owner_spans().related_hook_spans {
        if hook.call_span.start <= diag_span.start && diag_span.end <= hook.call_span.end {
            owned_spans.push(hook.call_span);
            owned_spans.extend(hook.referenced_decl_spans.iter().copied());
        }
    }

    owned_spans
        .into_iter()
        .map(|sp| OwnedLineContext {
            range: span_to_line_range(line_starts, sp),
            excluded_ranges: Vec::new(),
        })
        .collect()
}

fn span_to_line_range(line_starts: &[u32], span: ByteSpan) -> (u32, u32) {
    let start_line = loc_from_line_starts(line_starts, span.start).line;
    let end_line =
        loc_from_line_starts(line_starts, span.end.saturating_sub(1).max(span.start)).line;
    (start_line, end_line.max(start_line))
}
