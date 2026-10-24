//! Native fuzzy **Symbol Outline** search (`dotore search`).

use std::{collections::HashMap, io, path::PathBuf};

use dotore_core::ir::SymbolKind;
pub use dotore_core::search::{
    CachedFileSymbols, SYMBOL_INDEX_SCHEMA_VERSION, SearchJsonLocation, SearchJsonReport,
    SearchJsonResult, SearchOptions, SymbolIndexCache, SymbolSearchResult, format_search_json,
    format_search_text, load_symbol_index_cache, resolve_symbol_cache_path,
    save_symbol_index_cache, score_fuzzy, search_extracted_files, search_project_sources_with,
    search_project_sources_with_analyzers, search_symbols_with, search_symbols_with_analyzers,
    search_symbols_with_analyzers_and_cache, search_symbols_with_extractor_and_cache,
    should_highlight_search, should_highlight_stdout,
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
    search_symbols_with_cache(query, options, false)
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines**,
/// bypassing the persistent disk index when `no_cache` is `true` or `DOTORE_NO_CACHE=1`.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols_with_cache(
    query: &str,
    options: &SearchOptions,
    no_cache: bool,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    crate::register_active_core_hooks();
    search_symbols_with_analyzers_and_cache(query, options, crate::default_analyzers(), no_cache)
}
