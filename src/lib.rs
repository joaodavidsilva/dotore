//! Pure-Rust React and TypeScript static analyzer, deterministic auto-fixer,
//! and visual **Render Cascade** remediation engine.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

use rayon::prelude::*;

/// Surgical auto-fixer for `Autofix`-tier diagnostics.
pub(crate) mod fixer;
/// Cross-file JSX caller index and multi-effect **Render Cascade** solver.
pub(crate) mod graph;
/// React **Subject**, **State Slot**, **Effect Node**, and **Caller Site** IR.
pub(crate) mod ir;
/// Terminal and JSON reporters.
pub(crate) mod report;
/// Diagnostic rules engine over `SubjectIr` and `ProjectGraph`.
pub(crate) mod rules;
/// Parallel gitignore-aware file discovery.
pub(crate) mod scanner;

pub use fixer::{FileFixResult, apply_autofixes, apply_patches_to_source};
pub use graph::ResolvedCallerSite;
pub use ir::{ByteSpan, SourceLoc, SubjectKind};
pub use report::{
    JsonReport, ReportSummary, format_fix_report, format_terminal_report, render_html_report,
    write_and_open_html_report,
};
pub use rules::{AutofixPatch, ByteEdit, Diagnostic, PrescriptionTier, RuleId};

use graph::ProjectGraph;
use ir::parse_file_ir;
use report::build_report;
use rules::evaluate_project;
use scanner::collect_source_files;
/// Options for scanning a project or file list.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Paths (files or directories) to analyze. Empty defaults to `"."`.
    pub paths: Vec<PathBuf>,
    /// Whether to include `.test.*` / `.spec.*` files when walking directories.
    pub include_tests: bool,
    /// Optional filter of enabled [`RuleId`]s (`None` enables all rules).
    pub rules: Option<Vec<RuleId>>,
    /// Optional filter of [`PrescriptionTier`]s (`None` includes all tiers).
    pub tiers: Option<Vec<PrescriptionTier>>,
}

/// Analyzes a single in-memory source file and returns its [`Diagnostic`]s.
#[must_use]
pub fn analyze_source(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let file_ir = parse_file_ir(path, source);
    let graph = ProjectGraph::build(vec![file_ir]);
    evaluate_project(&graph, enabled_rules)
}

/// Analyzes multiple in-memory `(PathBuf, String)` files with full cross-file [`ProjectGraph`] resolution.
#[must_use]
pub fn analyze_project_sources(
    files: Vec<(PathBuf, String)>,
    enabled_rules: Option<&[RuleId]>,
) -> JsonReport {
    let file_irs: Vec<_> = files
        .into_par_iter()
        .map(|(path, source)| parse_file_ir(&path, &source))
        .collect();
    let graph = ProjectGraph::build(file_irs);
    let diagnostics = evaluate_project(&graph, enabled_rules);
    build_report(&graph, diagnostics)
}

/// Scans the filesystem according to [`ScanOptions`], returning the [`JsonReport`] and source map.
///
/// # Errors
/// Returns an `io::Error` if reading discovered files fails.
pub fn scan_workspace(options: &ScanOptions) -> io::Result<(JsonReport, HashMap<PathBuf, String>)> {
    let paths = collect_source_files(&options.paths, options.include_tests);
    let mut sources = HashMap::with_capacity(paths.len());
    let mut pairs = Vec::with_capacity(paths.len());

    for path in paths {
        if let Ok(content) = fs::read_to_string(&path) {
            sources.insert(path.clone(), content.clone());
            pairs.push((path, content));
        }
    }

    let file_irs: Vec<_> = pairs
        .into_par_iter()
        .map(|(path, source)| parse_file_ir(&path, &source))
        .collect();

    let graph = ProjectGraph::build(file_irs);
    let mut diagnostics = evaluate_project(&graph, options.rules.as_deref());

    if let Some(allowed_tiers) = &options.tiers {
        diagnostics.retain(|d| allowed_tiers.contains(&d.tier));
    }

    Ok((build_report(&graph, diagnostics), sources))
}
