//! Native fuzzy **Symbol Outline** search (`dotore search`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    io::{self, IsTerminal},
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
        compute_line_starts, fnv1a_64_step, loc_from_line_starts,
    },
    scanner::{
        POLYGLOT_SOURCE_EXTENSIONS, collect_source_files_for_analyzers,
        collect_source_files_with_extensions,
    },
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

const MAX_COMMENT_LINES: usize = 10;
const MAX_INTERFACE_PROPERTIES: usize = 15;
const MAX_LINE_CHARS: usize = 120;

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
    let search_root = match options.paths.first() {
        None => PathBuf::from("."),
        Some(first) if first.is_dir() => first.clone(),
        Some(first) => first
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    };
    let cache_path_opt = if is_cache_disabled(no_cache) {
        None
    } else {
        resolve_symbol_cache_path(&search_root)
    };

    let Some(cache_path) = cache_path_opt else {
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
        return Ok((results, sources));
    };

    let canonical_root = canonicalize_or_normalize(&search_root);
    let root_str = canonical_root.to_string_lossy().to_string();
    let existing_cache = load_symbol_index_cache(&cache_path)
        .filter(|c| c.version == SYMBOL_INDEX_SCHEMA_VERSION && c.project_root == root_str);

    let mut cache_dirty = existing_cache.is_none();
    let mut new_files = BTreeMap::new();
    if options.paths.iter().any(|p| p.is_file())
        && let Some(prev) = &existing_cache
    {
        for (rel_key, cached_entry) in &prev.files {
            if canonical_root.join(rel_key).is_file() {
                new_files.insert(rel_key.clone(), cached_entry.clone());
            } else {
                cache_dirty = true;
            }
        }
    }
    let mut file_outlines = Vec::with_capacity(discovered.len());
    let mut sources = HashMap::new();

    for path in discovered {
        let canonical_file = canonicalize_or_normalize(&path);
        let rel_key = relative_forward_slash(&canonical_file, &canonical_root);
        let metadata = fs::metadata(&path)?;
        let size = metadata.len();
        let mtime_ms = file_mtime_ms(&metadata);

        let cached_entry = existing_cache.as_ref().and_then(|c| c.files.get(&rel_key));
        let entry = resolve_cached_or_extract_file(
            &path,
            size,
            mtime_ms,
            cached_entry,
            &extract_symbols,
            &mut sources,
            &mut cache_dirty,
        )?;
        file_outlines.push((path, entry.outlines.clone()));
        new_files.insert(rel_key, entry);
    }

    if let Some(prev) = &existing_cache
        && prev.files.len() != new_files.len()
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
            let content = fs::read_to_string(&res.file)?;
            sources.insert(res.file.clone(), content);
        }
    }
    Ok((results, sources))
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

/// Formats ranked search results into a machine-readable [`SearchJsonReport`].
#[must_use]
pub fn format_search_json(
    query: &str,
    root: &str,
    results: &[SymbolSearchResult],
) -> SearchJsonReport {
    let cwd = env::current_dir().ok();
    let json_results = results
        .iter()
        .map(|res| {
            let file_str = format_display_path(&res.file, cwd.as_deref());
            let comments = res
                .outline
                .doc_comment
                .as_deref()
                .map(truncate_comment_strings);
            let rounded_score = (res.score * 10_000.0).round() / 10_000.0;
            SearchJsonResult {
                name: res.outline.name.clone(),
                kind: res.outline.kind,
                location: SearchJsonLocation {
                    file: file_str,
                    line: res.outline.loc.line,
                    column: res.outline.loc.column,
                },
                signature: res.outline.signature.clone(),
                container: res.outline.parent_name.clone(),
                comments,
                score: rounded_score,
                matches: res.matches.clone(),
            }
        })
        .collect();

    SearchJsonReport {
        query: query.to_string(),
        root: root.to_string(),
        count: results.len(),
        results: json_results,
    }
}

fn truncate_comment_strings(doc_comment: &str) -> Vec<String> {
    let all_lines: Vec<&str> = doc_comment.lines().collect();
    if all_lines.len() <= MAX_COMMENT_LINES {
        return all_lines.into_iter().map(str::to_string).collect();
    }
    let mut out: Vec<String> = all_lines[..MAX_COMMENT_LINES]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let hidden = all_lines.len() - MAX_COMMENT_LINES;
    out.push(format!("(...and {hidden} more comment lines)"));
    out
}

/// Renders ranked search results as grouped file outlines (`--format text`).
#[must_use]
pub fn format_search_text(
    results: &[SymbolSearchResult],
    sources: &HashMap<PathBuf, String>,
    highlight: bool,
) -> String {
    if results.is_empty() {
        return String::new();
    }

    let cwd = env::current_dir().ok();
    let grouped = group_results_by_file(results);
    let mut blocks = Vec::with_capacity(grouped.len());

    for (file_path, file_results) in grouped {
        let Some(source) = sources.get(&file_path) else {
            continue;
        };
        let lines: Vec<&str> = source.lines().collect();
        let line_starts = compute_line_starts(source);
        let display_file = format_display_path(&file_path, cwd.as_deref());
        let lang = markdown_language(&display_file);

        let mut outline_lines: Vec<String> = Vec::new();
        for (idx, res) in file_results.iter().enumerate() {
            if idx > 0 {
                outline_lines.push(String::new());
            }
            outline_lines.extend(create_outline_lines(res, &lines, &line_starts));
        }

        let mut block = String::new();
        if highlight {
            block.push_str(&format!("\x1b[1m\x1b[36m{display_file}\x1b[0m\n"));
            block.push_str(&format!("\x1b[2m```{lang}\x1b[0m\n"));
            for line in &outline_lines {
                block.push_str(&highlight_outline_line(line));
                block.push('\n');
            }
            block.push_str("\x1b[2m```\x1b[0m");
        } else {
            block.push_str(&display_file);
            block.push('\n');
            block.push_str(&format!("```{lang}\n"));
            block.push_str(&outline_lines.join("\n"));
            block.push_str("\n```");
        }
        blocks.push(block);
    }

    if blocks.is_empty() {
        String::new()
    } else {
        format!("{}\n", blocks.join("\n\n"))
    }
}

fn group_results_by_file(
    results: &[SymbolSearchResult],
) -> Vec<(PathBuf, Vec<&SymbolSearchResult>)> {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut map: HashMap<PathBuf, Vec<&SymbolSearchResult>> = HashMap::new();

    for res in results {
        if let Some(group) = map.get_mut(&res.file) {
            group.push(res);
        } else {
            order.push(res.file.clone());
            map.insert(res.file.clone(), vec![res]);
        }
    }

    order
        .into_iter()
        .filter_map(|file| {
            let mut group = map.remove(&file)?;
            group.sort_by_key(|r| r.outline.loc.line);
            Some((file, group))
        })
        .collect()
}

fn create_outline_lines(
    result: &SymbolSearchResult,
    lines: &[&str],
    line_starts: &[u32],
) -> Vec<String> {
    let decl_start_line = loc_from_line_starts(line_starts, result.outline.span.start).line;
    let start_line = result.outline.comment_start_line.unwrap_or(decl_start_line);
    let sig_end_line = result.outline.signature_end_line.max(decl_start_line);
    let end_line = result.outline.end_line.max(decl_start_line);

    let sig_lines = create_signature_lines(start_line, decl_start_line, sig_end_line, lines);

    if end_line <= decl_start_line {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_line,
            lines,
        )
        .unwrap_or(sig_lines);
    }

    let Some((end_text_line, end_text)) = find_last_non_empty_line(lines, start_line, end_line)
    else {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_line,
            lines,
        )
        .unwrap_or(sig_lines);
    };

    if end_text_line <= sig_end_line {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_text_line,
            lines,
        )
        .unwrap_or(sig_lines);
    }

    let decl_outline =
        create_declaration_outline_lines(&sig_lines, sig_end_line, end_text_line, end_text, lines);
    if let Some(member_outline) = create_member_outline_if_needed(
        result.outline.kind,
        &decl_outline,
        start_line,
        end_text_line,
        lines,
    ) {
        return member_outline;
    }

    if result.outline.kind == SymbolKind::Interface {
        return create_interface_outline_lines(
            &sig_lines,
            sig_end_line,
            end_text_line,
            end_text,
            lines,
        );
    }

    decl_outline
}

fn create_declaration_outline_lines(
    sig_lines: &[String],
    sig_end_line: u32,
    end_text_line: u32,
    end_text: &str,
    lines: &[&str],
) -> Vec<String> {
    let mut out = sig_lines.to_vec();
    let sig_line_text = lines
        .get((sig_end_line as usize).saturating_sub(1))
        .copied()
        .unwrap_or("");
    let indent = leading_whitespace(sig_line_text);
    out.push(format_code_line(
        sig_end_line + 1,
        &format!("{indent}  ..."),
    ));
    out.push(format_code_line(end_text_line, end_text));
    out
}

fn create_member_outline_if_needed(
    kind: SymbolKind,
    member_lines: &[String],
    member_start_line: u32,
    member_end_line: u32,
    lines: &[&str],
) -> Option<Vec<String>> {
    if kind != SymbolKind::Method && kind != SymbolKind::Property {
        return None;
    }

    let (open_line, open_text, close) = find_enclosing_block(lines, member_start_line)?;
    let body_indent = format!("{}  ", leading_whitespace(open_text));
    let mut output = vec![format_code_line(open_line, open_text)];

    if open_line + 1 < member_start_line {
        output.push(format_synthetic_line(&format!("{body_indent}...")));
    }

    output.extend_from_slice(member_lines);

    if let Some((close_line, close_text)) = close {
        if member_end_line + 1 < close_line {
            output.push(format_synthetic_line(&format!("{body_indent}...")));
        }
        if close_line > member_end_line {
            output.push(format_code_line(close_line, close_text));
        }
    }

    Some(output)
}

fn create_interface_outline_lines(
    sig_lines: &[String],
    sig_end_line: u32,
    end_text_line: u32,
    end_text: &str,
    lines: &[&str],
) -> Vec<String> {
    let mut prop_lines: Vec<(u32, &str)> = Vec::new();
    if sig_end_line < end_text_line.saturating_sub(1) {
        for line in (sig_end_line + 1)..=(end_text_line - 1) {
            if let Some(&text) = lines.get((line as usize).saturating_sub(1))
                && !text.trim().is_empty()
            {
                prop_lines.push((line, text));
            }
        }
    }

    if prop_lines.is_empty() {
        let mut out = sig_lines.to_vec();
        out.push(format_code_line(end_text_line, end_text));
        return out;
    }

    let visible_count = prop_lines.len().min(MAX_INTERFACE_PROPERTIES);
    let visible = &prop_lines[..visible_count];
    let hidden_count = prop_lines.len() - visible_count;
    let summary_indent = leading_whitespace(visible[0].1);

    let mut out = sig_lines.to_vec();
    for &(line, text) in visible {
        out.push(format_code_line(line, text));
    }
    if hidden_count > 0 {
        out.push(format_synthetic_line(&format!(
            "{summary_indent}(...and {hidden_count} more properties)"
        )));
    }
    out.push(format_code_line(end_text_line, end_text));
    out
}

#[expect(
    clippy::type_complexity,
    reason = "Returns enclosing block opening line/text and optional closing line/text tuple"
)]
fn find_enclosing_block<'a>(
    lines: &'a [&'a str],
    member_start_line: u32,
) -> Option<(u32, &'a str, Option<(u32, &'a str)>)> {
    let mut stack: Vec<(u32, &'a str)> = Vec::new();
    for line in 1..member_start_line {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        for ch in text.chars() {
            if ch == '{' {
                stack.push((line, text));
            } else if ch == '}' {
                stack.pop();
            }
        }
    }

    let &(open_line, open_text) = stack.last()?;
    let close = find_closing_brace_line(lines, open_line);
    Some((open_line, open_text, close))
}

fn find_closing_brace_line<'a>(lines: &'a [&'a str], open_line: u32) -> Option<(u32, &'a str)> {
    let mut depth = 0i32;
    for line in open_line..=u32::try_from(lines.len()).unwrap_or(u32::MAX) {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        for ch in text.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some((line, text));
                }
            }
        }
    }
    None
}

fn create_signature_lines(
    start_line: u32,
    decl_start_line: u32,
    sig_end_line: u32,
    lines: &[&str],
) -> Vec<String> {
    let mut output = if start_line < decl_start_line {
        create_comment_lines(start_line, decl_start_line - 1, lines)
    } else {
        Vec::new()
    };

    for line in decl_start_line..=sig_end_line {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        output.push(format_code_line(line, text));
    }
    output
}

fn create_comment_lines(start_line: u32, end_line: u32, lines: &[&str]) -> Vec<String> {
    let line_count = (end_line - start_line + 1) as usize;
    let visible_count = line_count.min(MAX_COMMENT_LINES);
    let mut output = Vec::with_capacity(visible_count + 1);

    for idx in 0..visible_count {
        let line = start_line + u32::try_from(idx).unwrap_or(0);
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        output.push(format_code_line(line, text));
    }

    let hidden_count = line_count - visible_count;
    if hidden_count > 0 {
        let last_visible_line = start_line + u32::try_from(visible_count).unwrap_or(0) - 1;
        let last_text = lines
            .get((last_visible_line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        let indent = leading_whitespace(last_text);
        output.push(format_synthetic_line(&format!(
            "{indent}(...and {hidden_count} more comment lines)"
        )));
    }

    output
}

fn find_last_non_empty_line<'a>(
    lines: &'a [&'a str],
    start_line: u32,
    end_line: u32,
) -> Option<(u32, &'a str)> {
    let mut line = end_line;
    while line > start_line {
        if let Some(&text) = lines.get((line as usize).saturating_sub(1))
            && !text.trim().is_empty()
        {
            return Some((line, text));
        }
        line -= 1;
    }
    None
}

fn format_code_line(line: u32, text: &str) -> String {
    format!("{line:>4} | {}", truncate_line(text))
}

fn format_synthetic_line(text: &str) -> String {
    format!("     | {}", truncate_line(text))
}

fn truncate_line(text: &str) -> String {
    let trimmed = text.trim_end();
    if trimmed.chars().count() <= MAX_LINE_CHARS {
        return trimmed.to_string();
    }
    let prefix: String = trimmed.chars().take(MAX_LINE_CHARS - 1).collect();
    format!("{prefix}…")
}

fn leading_whitespace(text: &str) -> &str {
    let non_ws = text
        .find(|c: char| !c.is_whitespace())
        .unwrap_or(text.len());
    &text[..non_ws]
}

fn markdown_language(file: &str) -> &'static str {
    if file.ends_with(".tsx") {
        "tsx"
    } else if file.ends_with(".ts") || file.ends_with(".mts") || file.ends_with(".cts") {
        "ts"
    } else if file.ends_with(".jsx") {
        "jsx"
    } else if file.ends_with(".py") || file.ends_with(".pyi") {
        "py"
    } else if file.ends_with(".rs") {
        "rs"
    } else {
        "js"
    }
}

fn format_display_path(path: &Path, cwd: Option<&Path>) -> String {
    let rel = cwd
        .and_then(|base| path.strip_prefix(base).ok())
        .unwrap_or(path);
    let rendered = rel.to_string_lossy().replace('\\', "/");
    let stripped = rendered.strip_prefix("./").unwrap_or(&rendered);
    if stripped.is_empty() {
        path.to_string_lossy().replace('\\', "/")
    } else {
        stripped.to_string()
    }
}

fn highlight_outline_line(line: &str) -> String {
    if let Some((prefix, code)) = split_outline_prefix(line) {
        let trimmed = code.trim_start();
        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('#')
        {
            format!("\x1b[2m{prefix}{code}\x1b[0m")
        } else {
            format!("\x1b[2m{prefix}\x1b[0m{code}")
        }
    } else {
        line.to_string()
    }
}

fn split_outline_prefix(line: &str) -> Option<(&str, &str)> {
    if line.len() >= 7 && &line.as_bytes()[4..7] == b" | " {
        Some(line.split_at(7))
    } else {
        None
    }
}

/// Determines whether ANSI highlighting should be enabled for `dotore search` text output.
#[must_use]
pub fn should_highlight_search(
    no_color_flag: bool,
    is_tty: bool,
    env_vars: &[(String, String)],
) -> bool {
    if no_color_flag {
        return false;
    }

    let get_env = |key: &str| -> Option<&str> {
        env_vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    if get_env("NO_COLOR").is_some_and(|v| !v.is_empty())
        || is_truthy_env(get_env("NODE_DISABLE_COLORS"))
        || get_env("FORCE_COLOR") == Some("0")
        || get_env("CLICOLOR") == Some("0")
    {
        return false;
    }

    if has_ci_or_agent_env(env_vars, get_env) {
        return false;
    }

    if is_truthy_env(get_env("FORCE_COLOR")) || is_truthy_env(get_env("CLICOLOR_FORCE")) {
        return true;
    }

    is_tty && get_env("TERM") != Some("dumb")
}

/// Checks current process environment and stdout terminal state for ANSI highlighting.
#[must_use]
pub fn should_highlight_stdout(no_color_flag: bool) -> bool {
    let vars: Vec<(String, String)> = env::vars().collect();
    should_highlight_search(no_color_flag, io::stdout().is_terminal(), &vars)
}

fn is_truthy_env(val: Option<&str>) -> bool {
    let Some(v) = val else {
        return false;
    };
    if v.is_empty() {
        return false;
    }
    !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
}

fn has_ci_or_agent_env<'a>(
    env_vars: &'a [(String, String)],
    get_env: impl Fn(&str) -> Option<&'a str>,
) -> bool {
    const CI_AND_AGENT_VARS: &[&str] = &[
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "BUILDKITE",
        "TF_BUILD",
        "TRAVIS",
        "VERCEL",
        "NETLIFY",
        "AGENT",
        "AI_AGENT",
        "CLAUDE_CODE",
        "CLAUDECODE",
        "CODEX_CI",
        "CODEX_SANDBOX",
        "CURSOR_AGENT",
        "GEMINI_CLI",
        "OPENCODE",
    ];
    const PREFIXES: &[&str] = &[
        "CI_",
        "GITHUB_ACTIONS_",
        "GITLAB_",
        "CLAUDE_CODE_",
        "CODEX_",
        "COPILOT_",
        "GEMINI_CLI_",
        "OPENCODE_",
    ];

    if CI_AND_AGENT_VARS.iter().any(|k| is_truthy_env(get_env(k))) {
        return true;
    }

    env_vars.iter().any(|(k, v)| {
        PREFIXES.iter().any(|prefix| k.starts_with(prefix)) && is_truthy_env(Some(v.as_str()))
    })
}
