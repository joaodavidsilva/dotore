//! Native fuzzy **Symbol Outline** search (`dotore search`).

use std::{collections::HashMap, io, path::PathBuf};

use dotore_core::ir::SymbolKind;
pub use dotore_core::search::{
    SearchJsonLocation, SearchJsonReport, SearchJsonResult, SearchOptions, SymbolSearchResult,
    format_search_json, format_search_text, score_fuzzy, search_extracted_files,
    search_project_sources_with, search_project_sources_with_analyzers, search_symbols_with,
    search_symbols_with_analyzers, should_highlight_search, should_highlight_stdout,
};

/// Searches in-memory `(PathBuf, String)` files for **Symbol Outlines** matching `query`.
#[must_use]
pub fn search_project_sources(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    crate::register_active_core_hooks();
    search_project_sources_with_analyzers(query, files, kinds, limit, crate::default_analyzers())
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines**.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols(
    query: &str,
    options: &SearchOptions,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    crate::register_active_core_hooks();
    search_symbols_with_analyzers(query, options, crate::default_analyzers())
}
