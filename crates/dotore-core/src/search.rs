//! Native fuzzy **Symbol Outline** search (`dotore search`).

mod formatter;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
    sync::RwLock,
    time::UNIX_EPOCH,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        is_cache_disabled, normalize_path_buf, relative_forward_slash, resolve_dotore_home_dir,
        write_file_atomically,
    },
    ir::{
        ExtractedFile, FNV1A_64_OFFSET_BASIS, LanguageAnalyzer, SymbolKind, SymbolOutline,
        fnv1a_64_step,
    },
    scanner::{
        POLYGLOT_SOURCE_EXTENSIONS, collect_source_files_for_analyzers,
        collect_source_files_with_extensions,
    },
};

pub use self::formatter::{
    format_search_json, format_search_text, should_highlight_search, should_highlight_stdout,
};

type SymbolExtractorFn = fn(&Path, &str) -> Vec<SymbolOutline>;

static DEFAULT_SYMBOL_EXTRACTOR: RwLock<Option<SymbolExtractorFn>> = RwLock::new(None);

/// Registers the default process-wide symbol outline extractor used by [`search_project_sources`]
/// and [`search_symbols`] when called without an explicit analyzer list or extractor callback.
pub fn register_default_symbol_extractor(extractor: SymbolExtractorFn) {
    if let Ok(mut guard) = DEFAULT_SYMBOL_EXTRACTOR.write() {
        *guard = Some(extractor);
    }
}

fn default_extract_symbols(path: &Path, source: &str) -> Vec<SymbolOutline> {
    if let Ok(guard) = DEFAULT_SYMBOL_EXTRACTOR.read()
        && let Some(extractor) = *guard
    {
        return extractor(path, source);
    }
    Vec::new()
}

/// Current schema version for `symbols.json`.
pub const SYMBOL_INDEX_SCHEMA_VERSION: u32 = 1;

/// Cached Symbol Outline entry for a single source file inside [`SymbolIndexCache`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedFileSymbols {
    /// Modification timestamp in milliseconds since `UNIX_EPOCH`.
    pub mtime_ms: u64,
    /// File byte length.
    pub size: u64,
    /// 64-bit FNV-1a content hash formatted as 16-char lowercase hex.
    pub content_hash: String,
    /// Extracted **Symbol Outlines** for this file.
    pub outlines: Vec<SymbolOutline>,
}

/// Persistent per-project **Symbol Outline** disk index stored at
/// `~/.dotore/projects/<project-slug>-<hash>/symbols.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolIndexCache {
    /// Schema version (`1`).
    pub version: u32,
    /// Canonicalized project root path string.
    pub project_root: String,
    /// Cached per-file symbol outlines keyed by project-relative (or normalized) file path.
    pub files: BTreeMap<String, CachedFileSymbols>,
}

/// Resolves the persistent per-project **Symbol Outline** cache path
/// (`~/.dotore/projects/<project-slug>-<hash>/symbols.json`) for `project_root`.
#[must_use]
pub fn resolve_symbol_cache_path(project_root: &Path) -> Option<PathBuf> {
    let home = resolve_dotore_home_dir()?;
    let canonical = canonicalize_or_normalize(project_root);
    let slug = sanitize_project_slug(&canonical);
    let canonical_str = canonical.to_string_lossy();
    let hash = fnv1a_64_step(FNV1A_64_OFFSET_BASIS, canonical_str.as_bytes());
    Some(
        home.join("projects")
            .join(format!("{slug}-{hash:016x}"))
            .join("symbols.json"),
    )
}

/// Loads a [`SymbolIndexCache`] from `cache_path`, returning `None` if missing,
/// unreadable, or incompatible with [`SYMBOL_INDEX_SCHEMA_VERSION`].
#[must_use]
pub fn load_symbol_index_cache(cache_path: &Path) -> Option<SymbolIndexCache> {
    let raw = fs::read_to_string(cache_path).ok()?;
    let parsed: SymbolIndexCache = serde_json::from_str(&raw).ok()?;
    if parsed.version != SYMBOL_INDEX_SCHEMA_VERSION {
        return None;
    }
    Some(parsed)
}

/// Persists `cache` to `cache_path` atomically using a temporary sibling file.
///
/// # Errors
/// Returns an `io::Error` if creating parent directories, serializing, or writing fails.
pub fn save_symbol_index_cache(cache_path: &Path, cache: &SymbolIndexCache) -> io::Result<()> {
    let json = serde_json::to_string_pretty(cache).map_err(io::Error::other)?;
    write_file_atomically(cache_path, json.as_bytes())
}

fn canonicalize_or_normalize(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| normalize_path_buf(path))
}

fn sanitize_project_slug(project_root: &Path) -> String {
    let raw = project_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project");
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.to_string()
    }
}

fn file_mtime_ms(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn compute_content_hash(content: &str) -> String {
    let hash = fnv1a_64_step(FNV1A_64_OFFSET_BASIS, content.as_bytes());
    format!("{hash:016x}")
}
/// Options for searching **Symbol Outlines** across files or directories.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Target files or directories to search (empty defaults to `"."`).
    pub paths: Vec<PathBuf>,
    /// Optional subset of [`SymbolKind`]s to include (`None` uses [`SymbolKind::DEFAULT_SEARCH_KINDS`]).
    pub kinds: Option<Vec<SymbolKind>>,
    /// Maximum number of ranked results to return (defaults to `50`).
    pub limit: usize,
    /// Whether to include test files when walking directories (defaults to `true` for symbol search).
    pub include_tests: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            kinds: None,
            limit: 50,
            include_tests: true,
        }
    }
}

/// A fuzzy-matched **Symbol Outline** ranked by relevance score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SymbolSearchResult {
    /// Source file containing the symbol.
    pub file: PathBuf,
    /// Extracted **Symbol Outline**.
    pub outline: SymbolOutline,
    /// Deterministic fuzzy match score.
    pub score: f64,
    /// 0-based character indices in `outline.name` that matched the query.
    pub matches: Vec<usize>,
}

/// Machine-readable JSON output for `dotore search --format json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchJsonReport {
    /// Raw search query string.
    pub query: String,
    /// Search root path display string.
    pub root: String,
    /// Number of returned results.
    pub count: usize,
    /// Ranked Symbol Outline results.
    pub results: Vec<SearchJsonResult>,
}

/// A single symbol record in [`SearchJsonReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchJsonResult {
    /// Symbol identifier name.
    pub name: String,
    /// Symbol kind (`function`, `class`, `interface`, etc.).
    pub kind: SymbolKind,
    /// 1-based file, line, and column location.
    pub location: SearchJsonLocation,
    /// Normalized declaration signature header.
    pub signature: String,
    /// Enclosing class, interface, enum, function, or object container name.
    pub container: Option<String>,
    /// Adjacent leading comment lines (truncated past 10 lines).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<Vec<String>>,
    /// Fuzzy match score rounded to 4 decimal places.
    pub score: f64,
    /// 0-based matched character indices in `name`.
    pub matches: Vec<usize>,
}

/// 1-based source location in [`SearchJsonResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchJsonLocation {
    /// Relative or display file path.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
}

/// Scores `candidate` against `query` using subsequence, prefix, camelCase, and word-boundary bonuses.
#[must_use]
pub fn score_fuzzy(query: &str, candidate: &str) -> Option<(f64, Vec<usize>)> {
    let raw = query.trim();
    let normalized = raw.to_lowercase();
    if normalized.is_empty() || candidate.is_empty() {
        return None;
    }

    let raw_chars: Vec<char> = raw.chars().collect();
    let norm_query_chars: Vec<char> = normalized.chars().collect();
    let cand_chars: Vec<char> = candidate.chars().collect();
    let norm_cand_chars: Vec<char> = candidate.to_lowercase().chars().collect();

    let mut matches = Vec::with_capacity(norm_query_chars.len());
    let mut query_idx = 0usize;
    let mut last_match_idx: Option<usize> = None;
    let mut score = 0.0_f64;

    for cand_idx in 0..cand_chars.len() {
        if query_idx >= norm_query_chars.len() {
            break;
        }
        if norm_cand_chars.get(cand_idx) != norm_query_chars.get(query_idx) {
            continue;
        }

        let gap = match last_match_idx {
            None => cand_idx,
            Some(last) => cand_idx.saturating_sub(last + 1),
        };
        let is_contiguous = last_match_idx.is_some_and(|last| last + 1 == cand_idx);

        score += 10.0;
        if cand_idx == 0 {
            score += 14.0;
        }
        if is_word_boundary(&cand_chars, cand_idx) {
            score += 8.0;
        }
        if is_contiguous {
            score += 6.0;
        } else {
            score -= (gap.min(8) as f64) * 0.6;
        }
        if cand_chars.get(cand_idx) == raw_chars.get(query_idx) {
            score += 1.0;
        }

        matches.push(cand_idx);
        last_match_idx = Some(cand_idx);
        query_idx += 1;
    }

    if query_idx != norm_query_chars.len() {
        return None;
    }

    score += (norm_query_chars.len() as f64 / cand_chars.len() as f64) * 8.0;
    score -= (cand_chars.len() as f64) * 0.04;

    Some((score, matches))
}

fn is_word_boundary(cand_chars: &[char], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let Some(&prev) = cand_chars.get(idx - 1) else {
        return false;
    };
    let Some(&curr) = cand_chars.get(idx) else {
        return false;
    };

    !prev.is_ascii_alphanumeric()
        || (prev.is_ascii_lowercase() && curr.is_ascii_uppercase())
        || (prev.is_ascii_digit() && !curr.is_ascii_digit())
        || (!prev.is_ascii_digit() && curr.is_ascii_digit())
}

/// Searches already-extracted [`ExtractedFile`] records for **Symbol Outlines** matching `query`.
#[must_use]
pub fn search_extracted_files(
    query: &str,
    files: &[ExtractedFile],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    if query.trim().is_empty() || limit == 0 {
        return Vec::new();
    }

    let allowed_kinds: HashSet<SymbolKind> = kinds
        .unwrap_or(SymbolKind::DEFAULT_SEARCH_KINDS)
        .iter()
        .copied()
        .collect();

    let mut results: Vec<SymbolSearchResult> = files
        .iter()
        .flat_map(|file| {
            let file_path = file.path.clone();
            file.symbol_outlines
                .iter()
                .filter(|outline| allowed_kinds.contains(&outline.kind))
                .filter_map(move |outline| {
                    let (score, matches) = score_fuzzy(query, &outline.name)?;
                    Some(SymbolSearchResult {
                        file: file_path.clone(),
                        outline: outline.clone(),
                        score,
                        matches,
                    })
                })
        })
        .collect();

    sort_and_truncate_results(&mut results, limit);
    results
}

/// Searches in-memory `(PathBuf, String)` files for **Symbol Outlines** matching `query`.
#[must_use]
pub fn search_project_sources(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    search_project_sources_with(query, files, kinds, limit, default_extract_symbols)
}

/// Searches in-memory `(PathBuf, String)` files using `analyzers` to extract **Symbol Outlines**.
#[must_use]
pub fn search_project_sources_with_analyzers(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
    analyzers: &[&dyn LanguageAnalyzer],
) -> Vec<SymbolSearchResult> {
    search_project_sources_with(query, files, kinds, limit, |path, source| {
        for analyzer in analyzers {
            if analyzer.supports_path(path) {
                return analyzer.extract_file(path, source).symbol_outlines;
            }
        }
        default_extract_symbols(path, source)
    })
}

/// Searches in-memory `(PathBuf, String)` files using `extract_symbols(path, source)` to extract **Symbol Outlines**.
#[must_use]
pub fn search_project_sources_with<F>(
    query: &str,
    files: &[(PathBuf, String)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
    extract_symbols: F,
) -> Vec<SymbolSearchResult>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    if query.trim().is_empty() || limit == 0 {
        return Vec::new();
    }

    let allowed_kinds: HashSet<SymbolKind> = kinds
        .unwrap_or(SymbolKind::DEFAULT_SEARCH_KINDS)
        .iter()
        .copied()
        .collect();

    let mut results: Vec<SymbolSearchResult> = files
        .par_iter()
        .flat_map_iter(|(path, source)| {
            let outlines = extract_symbols(path, source);
            let file_path = path.clone();
            outlines
                .into_iter()
                .filter(|outline| allowed_kinds.contains(&outline.kind))
                .filter_map(move |outline| {
                    let (score, matches) = score_fuzzy(query, &outline.name)?;
                    Some(SymbolSearchResult {
                        file: file_path.clone(),
                        outline,
                        score,
                        matches,
                    })
                })
        })
        .collect();

    sort_and_truncate_results(&mut results, limit);
    results
}

fn sort_and_truncate_results(results: &mut Vec<SymbolSearchResult>, limit: usize) {
    results.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.outline.name.len().cmp(&right.outline.name.len()))
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.outline.name.cmp(&right.outline.name))
            .then_with(|| left.outline.loc.line.cmp(&right.outline.loc.line))
    });
    results.truncate(limit);
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
    search_symbols_with_extractor_and_cache(query, options, no_cache, default_extract_symbols)
}

/// Discovers source files under `options.paths` using `analyzers` and fuzzy-searches their **Symbol Outlines**.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols_with_analyzers(
    query: &str,
    options: &SearchOptions,
    analyzers: &[&dyn LanguageAnalyzer],
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    search_symbols_with_analyzers_and_cache(query, options, analyzers, false)
}

/// Discovers source files under `options.paths` using `analyzers` and fuzzy-searches their **Symbol Outlines**,
/// bypassing the persistent disk index when `no_cache` is `true` or `DOTORE_NO_CACHE=1`.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols_with_analyzers_and_cache(
    query: &str,
    options: &SearchOptions,
    analyzers: &[&dyn LanguageAnalyzer],
    no_cache: bool,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)> {
    let discovered =
        collect_source_files_for_analyzers(&options.paths, options.include_tests, analyzers);
    search_discovered_files_with_cache(query, options, discovered, no_cache, |path, source| {
        for analyzer in analyzers {
            if analyzer.supports_path(path) {
                return analyzer.extract_file(path, source).symbol_outlines;
            }
        }
        default_extract_symbols(path, source)
    })
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines** using `extract_symbols`.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols_with<F>(
    query: &str,
    options: &SearchOptions,
    extract_symbols: F,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    search_symbols_with_extractor_and_cache(query, options, false, extract_symbols)
}

/// Discovers source files under `options.paths` and fuzzy-searches their **Symbol Outlines**
/// using `extract_symbols`, bypassing the persistent disk index when `no_cache` is `true` or `DOTORE_NO_CACHE=1`.
///
/// # Errors
/// Returns an `io::Error` if reading discovered source files fails.
pub fn search_symbols_with_extractor_and_cache<F>(
    query: &str,
    options: &SearchOptions,
    no_cache: bool,
    extract_symbols: F,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    let discovered = collect_source_files_with_extensions(
        &options.paths,
        options.include_tests,
        POLYGLOT_SOURCE_EXTENSIONS,
    );
    search_discovered_files_with_cache(query, options, discovered, no_cache, extract_symbols)
}

fn search_discovered_files_with_cache<F>(
    query: &str,
    options: &SearchOptions,
    discovered: Vec<PathBuf>,
    no_cache: bool,
    extract_symbols: F,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    let search_root = resolve_search_root(&options.paths);
    let cache_path_opt = (!is_cache_disabled(no_cache))
        .then(|| resolve_symbol_cache_path(&search_root))
        .flatten();
    let Some(cache_path) = cache_path_opt else {
        return search_uncached_discovered_files(query, options, discovered, extract_symbols);
    };

    let canonical_root = canonicalize_or_normalize(&search_root);
    let root_str = canonical_root.to_string_lossy().to_string();
    let existing_cache = load_symbol_index_cache(&cache_path)
        .filter(|c| c.version == SYMBOL_INDEX_SCHEMA_VERSION && c.project_root == root_str);

    let mut cache_dirty = existing_cache.is_none();
    let mut new_files = seed_partial_file_cache(
        &options.paths,
        &canonical_root,
        existing_cache.as_ref(),
        &mut cache_dirty,
    );
    let mut file_outlines = Vec::with_capacity(discovered.len());
    let mut sources = HashMap::new();

    for path in discovered {
        let rel_key =
            relative_forward_slash(&canonicalize_or_normalize(&path), &canonical_root);
        let metadata = fs::metadata(&path)?;
        let cached_entry = existing_cache.as_ref().and_then(|c| c.files.get(&rel_key));
        let entry = resolve_cached_or_extract_file(
            &path,
            metadata.len(),
            file_mtime_ms(&metadata),
            cached_entry,
            &extract_symbols,
            &mut sources,
            &mut cache_dirty,
        )?;
        file_outlines.push((path, entry.outlines.clone()));
        new_files.insert(rel_key, entry);
    }

    if existing_cache
        .as_ref()
        .is_some_and(|prev| prev.files.len() != new_files.len())
    {
        cache_dirty = true;
    }
    if cache_dirty {
        let updated = SymbolIndexCache {
            version: SYMBOL_INDEX_SCHEMA_VERSION,
            project_root: root_str,
            files: new_files,
        };
        let _ = save_symbol_index_cache(&cache_path, &updated);
    }

    let results = score_cached_outlines(
        query,
        &file_outlines,
        options.kinds.as_deref(),
        options.limit,
    );
    for res in &results {
        if !sources.contains_key(&res.file) {
            sources.insert(res.file.clone(), fs::read_to_string(&res.file)?);
        }
    }
    Ok((results, sources))
}

fn resolve_search_root(paths: &[PathBuf]) -> PathBuf {
    match paths.first() {
        None => PathBuf::from("."),
        Some(first) if first.is_dir() => first.clone(),
        Some(first) => first
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    }
}

fn search_uncached_discovered_files<F>(
    query: &str,
    options: &SearchOptions,
    discovered: Vec<PathBuf>,
    extract_symbols: F,
) -> io::Result<(Vec<SymbolSearchResult>, HashMap<PathBuf, String>)>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    let mut files = Vec::with_capacity(discovered.len());
    let mut sources = HashMap::with_capacity(discovered.len());
    for path in discovered {
        let content = fs::read_to_string(&path)?;
        sources.insert(path.clone(), content.clone());
        files.push((path, content));
    }
    let results = search_project_sources_with(
        query,
        &files,
        options.kinds.as_deref(),
        options.limit,
        extract_symbols,
    );
    Ok((results, sources))
}

fn seed_partial_file_cache(
    paths: &[PathBuf],
    canonical_root: &Path,
    existing_cache: Option<&SymbolIndexCache>,
    cache_dirty: &mut bool,
) -> BTreeMap<String, CachedFileSymbols> {
    let mut new_files = BTreeMap::new();
    if paths.iter().any(|p| p.is_file())
        && let Some(prev) = existing_cache
    {
        for (rel_key, cached_entry) in &prev.files {
            if canonical_root.join(rel_key).is_file() {
                new_files.insert(rel_key.clone(), cached_entry.clone());
            } else {
                *cache_dirty = true;
            }
        }
    }
    new_files
}

fn resolve_cached_or_extract_file<F>(
    path: &Path,
    size: u64,
    mtime_ms: u64,
    cached: Option<&CachedFileSymbols>,
    extract_symbols: &F,
    sources: &mut HashMap<PathBuf, String>,
    cache_dirty: &mut bool,
) -> io::Result<CachedFileSymbols>
where
    F: Fn(&Path, &str) -> Vec<SymbolOutline> + Sync,
{
    if let Some(hit) = cached
        && hit.mtime_ms == mtime_ms
        && hit.size == size
    {
        return Ok(hit.clone());
    }

    let content = fs::read_to_string(path)?;
    let content_hash = compute_content_hash(&content);
    if let Some(hit) = cached
        && hit.size == size
        && hit.content_hash == content_hash
    {
        sources.insert(path.to_path_buf(), content);
        *cache_dirty = true;
        return Ok(CachedFileSymbols {
            mtime_ms,
            size,
            content_hash,
            outlines: hit.outlines.clone(),
        });
    }

    let outlines = extract_symbols(path, &content);
    sources.insert(path.to_path_buf(), content);
    *cache_dirty = true;
    Ok(CachedFileSymbols {
        mtime_ms,
        size,
        content_hash,
        outlines,
    })
}

fn score_cached_outlines(
    query: &str,
    file_outlines: &[(PathBuf, Vec<SymbolOutline>)],
    kinds: Option<&[SymbolKind]>,
    limit: usize,
) -> Vec<SymbolSearchResult> {
    if query.trim().is_empty() || limit == 0 {
        return Vec::new();
    }
    let allowed_kinds: HashSet<SymbolKind> = kinds
        .unwrap_or(SymbolKind::DEFAULT_SEARCH_KINDS)
        .iter()
        .copied()
        .collect();

    let mut results: Vec<SymbolSearchResult> = file_outlines
        .iter()
        .flat_map(|(path, outlines)| {
            let file_path = path.clone();
            outlines
                .iter()
                .filter(|outline| allowed_kinds.contains(&outline.kind))
                .filter_map(move |outline| {
                    let (score, matches) = score_fuzzy(query, &outline.name)?;
                    Some(SymbolSearchResult {
                        file: file_path.clone(),
                        outline: outline.clone(),
                        score,
                        matches,
                    })
                })
        })
        .collect();

    sort_and_truncate_results(&mut results, limit);
    results
}

