//! Surgical source auto-fixer applying single-file and cross-file `Autofix`-tier byte-range
//! edits in reverse offset order with [`dotore_js::JsLanguageAnalyzer`] syntax verification.

use std::{collections::HashMap, io, path::PathBuf};

pub use dotore_core::fixer::{
    FileFixResult, apply_autofixes_with_analyzers, apply_autofixes_with_validator,
    apply_patches_to_source_with_analyzers, apply_patches_to_source_with_validator,
};
use dotore_core::{ir::LanguageAnalyzer, rules::Diagnostic};
use dotore_js::JsLanguageAnalyzer;

/// Applies all non-overlapping single-file and cross-file `Autofix` patches across the workspace,
/// validating rewritten JS/TS files with [`JsLanguageAnalyzer`].
///
/// # Errors
/// Returns an `io::Error` if writing a modified file fails.
pub fn apply_autofixes(
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    dry_run: bool,
) -> io::Result<Vec<FileFixResult>> {
    JsLanguageAnalyzer::register_core_hooks();
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    apply_autofixes_with_analyzers(diagnostics, sources, dry_run, analyzers)
}

/// Applies non-overlapping `Autofix` patches to an in-memory source string,
/// validating candidate rewrites with [`JsLanguageAnalyzer`] and returning `(new_source, applied_descriptions)`.
#[must_use]
pub fn apply_patches_to_source(source: &str, diagnostics: &[Diagnostic]) -> (String, Vec<String>) {
    JsLanguageAnalyzer::register_core_hooks();
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    apply_patches_to_source_with_analyzers(source, diagnostics, analyzers)
}
