//! Native fuzzy **Symbol Outline** search (`dotore search`).

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};

pub use dotore_core::search::{
    SearchJsonLocation, SearchJsonReport, SearchJsonResult, SearchOptions, SymbolSearchResult,
    format_search_json, format_search_text, score_fuzzy, search_extracted_files,
    search_project_sources_with, search_project_sources_with_analyzers, search_symbols_with,
    search_symbols_with_analyzers, should_highlight_search, should_highlight_stdout,
};

use crate::ir::{SymbolKind, SymbolOutline, parse_file_ir};

fn extract_js_symbol_outlines(path: &Path, source: &str) -> Vec<SymbolOutline> {
    use dotore_core::LanguageAnalyzer as _;
    let py = dotore_py::PyLanguageAnalyzer::new();
    if py.supports_path(path) {
        return py.extract_file(path, source).symbol_outlines;
    }
    parse_file_ir(path, source).symbol_outlines
}

/// Searches in-memory `(PathBuf, String)` files for **Symbol Outlines** matching `query`.
#[must_use]
pub fn search_project_sources(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    search_project_sources_with(query, files, kinds, limit, extract_js_symbol_outlines)
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines**.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols(
    query: &str,
    options: &SearchOptions,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    search_symbols_with(query, options, extract_js_symbol_outlines)
}
