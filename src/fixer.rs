//! Surgical source auto-fixer applying single-file and cross-file `Autofix`-tier byte-range
//! edits in reverse offset order with `oxc_parser` syntax verification.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

pub use dotore_core::fixer::{
    FileFixResult, apply_autofixes_with_analyzers, apply_autofixes_with_validator,
    apply_patches_to_source_with_analyzers, apply_patches_to_source_with_validator,
};

use crate::rules::Diagnostic;

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace.
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
) -> io::Result<Vec<FileFixResult>> {
    apply_autofixes_with_validator(diagnostics, sources, dry_run, source_parses_cleanly)
}

/// Applies non-overlapping `Autofix` patches to an in-memory source string,
/// returning `(new_source, applied_descriptions)`.
#[must_use]
pub fn apply_patches_to_source(source: &str, diagnostics: &[Diagnostic]) -> (String, Vec<String>) {
    apply_patches_to_source_with_validator(source, diagnostics, source_parses_cleanly)
}

pub(crate) fn source_parses_cleanly(path: &Path, source: &str) -> bool {
    use dotore_core::LanguageAnalyzer as _;
    let py = dotore_py::PyLanguageAnalyzer::new();
    if py.supports_path(path) {
        return py.validate_syntax(path, source);
    }
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    parsed.diagnostics.is_empty()
}
