//! Native fuzzy **Symbol Outline** search (`dotore search`).

use std::{collections::HashMap, io, path::PathBuf};

use dotore_core::ir::{LanguageAnalyzer, SymbolKind};
pub use dotore_core::search::{
    SearchJsonLocation, SearchJsonReport, SearchJsonResult, SearchOptions, SymbolSearchResult,
    format_search_json, format_search_text, score_fuzzy, search_extracted_files,
    search_project_sources_with, search_project_sources_with_analyzers, search_symbols_with,
    search_symbols_with_analyzers, should_highlight_search, should_highlight_stdout,
};
use dotore_js::JsLanguageAnalyzer;

/// Searches in-memory `(PathBuf, String)` files for **Symbol Outlines** matching `query`.
#[must_use]
pub fn search_project_sources(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    JsLanguageAnalyzer::register_core_hooks();
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    search_project_sources_with_analyzers(query, files, kinds, limit, analyzers)
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines**.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols(
    query: &str,
    options: &SearchOptions,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    JsLanguageAnalyzer::register_core_hooks();
    let js_analyzer = JsLanguageAnalyzer;
    let analyzers: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    search_symbols_with_analyzers(query, options, analyzers)
}
