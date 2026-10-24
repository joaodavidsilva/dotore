//! Machine-readable [`JsonReport`] schema, builders, and JSON file serializer.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{Capability, PackageRole, WorkspacePackage, resolve_package_for_file},
    diff::{BaselineSummary, GitDiffInfo, ScanMode},
    ir::ExtractedFile,
    planner::{PlannerContext, build_root_cause_groups_and_capsules},
    rules::{Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup, RuleSeverity},
    score::compute_local_health_score,
};

/// Current version of the machine-readable [`JsonReport`] schema.
pub const JSON_REPORT_SCHEMA_VERSION: u32 = 3;

/// Per-project (workspace package) coverage and health score metadata in [`JsonReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCoverageMetadata {
    /// Package name (`package.json#name` or `"root"`).
    pub name: String,
    /// Root directory of the package.
    pub root_dir: PathBuf,
    /// Inferred package role (`application` or `library`).
    pub role: PackageRole,
    /// Active capabilities detected by the **Capability Gate**.
    pub capabilities: Vec<Capability>,
    /// Sorted list of analyzed file paths belonging to this package.
    pub analyzed_files: Vec<PathBuf>,
    /// Total number of analyzed files in this package.
    pub analyzed_file_count: usize,
    /// Total number of analyzed React **Subjects** in this package.
    pub subjects_scanned: usize,
    /// Number of diagnostics reported in this package.
    pub diagnostic_count: usize,
    /// Local `0..=100` Health Score for this package.
    pub health_score: u32,
    /// Human-readable score label (`"Excellent"`, `"Good"`, `"Needs Attention"`, `"Critical"`).
    pub score_label: String,
    /// Whether the scan of this package completed without skipped checks.
    pub complete: bool,
}

/// Aggregate metrics for a `dotore` scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total source files scanned.
    pub files_scanned: usize,
    /// Total React **Subjects** (components and custom hooks) analyzed.
    pub subjects_scanned: usize,
    /// Total `useEffect` **Effect Nodes** analyzed.
    pub effects_scanned: usize,
    /// Total diagnostics found.
    pub total_diagnostics: usize,
    /// Count of `Error`-severity diagnostics.
    pub error_count: usize,
    /// Count of `Warning`-severity diagnostics.
    pub warning_count: usize,
    /// Count of distinct files with at least one reported diagnostic.
    pub affected_file_count: usize,
    /// Count of `Autofix` diagnostics (`dotore fix`).
    pub autofix_count: usize,
    /// Count of `Surgical` single-**Subject** diagnostics.
    pub surgical_count: usize,
    /// Count of `Refactor` state-model / cross-**Subject** diagnostics.
    pub refactor_count: usize,
    /// Overall React Effect & State health score (`0..=100`).
    pub health_score: u32,
    /// Human-readable health score rating (`"Excellent"`, `"Good"`, `"Needs Attention"`, `"Critical"`).
    pub score_label: String,
}

/// Complete machine-readable report emitted by `dotore check --json` and `--json-out <path>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonReport {
    /// Version of the machine-readable JSON report schema (`3`).
    pub schema_version: u32,
    /// Active scan mode (`full`, `diff`, `staged`, `baseline`).
    #[serde(default)]
    pub mode: ScanMode,
    /// Aggregate metrics and local health score.
    pub summary: ReportSummary,
    /// Per-project coverage and capability metadata.
    #[serde(default)]
    pub projects: Vec<ProjectCoverageMetadata>,
    /// Individual diagnostics.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// Clustered **Root-Cause Groups** ordered by static **Blast Radius** descending.
    #[serde(default)]
    pub root_cause_groups: Vec<RootCauseGroup>,
    /// Self-contained **Fix Capsules** for `Surgical` and `Refactor` **Root-Cause Groups**.
    #[serde(default)]
    pub fix_capsules: Vec<FixCapsule>,
    /// Source-token-enriched fingerprints keyed by diagnostic `id`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub diagnostic_fingerprints: BTreeMap<String, String>,
    /// Optional git diff metadata when running a diff or staged scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<GitDiffInfo>,
    /// Optional baseline multiset delta summary when `--baseline` succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineSummary>,
    /// `true` when `--baseline` degraded gracefully to diff mode because base blobs/files were unavailable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub baseline_degraded: bool,
}

/// Writes `report` as pretty-printed JSON to `path`, creating parent directories if needed.
///
/// # Errors
/// Returns an `io::Error` if serializing or writing the file fails.
pub fn write_json_report(report: &JsonReport, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, format!("{json}\n"))
}

/// Reads and deserializes a [`JsonReport`] from `path`.
///
/// # Errors
/// Returns an `io::Error` if reading or parsing the JSON file fails.
pub fn read_json_report(path: &Path) -> io::Result<JsonReport> {
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Builds a [`JsonReport`] from extracted files, evaluated [`Diagnostic`]s, and file sources.
#[must_use]
pub fn build_extracted_report(
    files: &[ExtractedFile],
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
) -> JsonReport {
    build_extracted_report_with_packages(files, diagnostics, sources, &[])
}

/// Builds a [`JsonReport`] from extracted files and discovered [`WorkspacePackage`]s.
#[must_use]
pub fn build_extracted_report_with_packages(
    files: &[ExtractedFile],
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
    packages: &[WorkspacePackage],
) -> JsonReport {
    let file_subject_counts: Vec<(PathBuf, usize)> = files
        .iter()
        .map(|f| (f.path.clone(), f.subjects_count))
        .collect();
    let effects_scanned: usize = files.iter().map(|f| f.effects_count).sum();
    build_report_from_planner_context(
        files,
        &file_subject_counts,
        effects_scanned,
        diagnostics,
        sources,
        packages,
    )
}

/// Builds a [`JsonReport`] using any [`PlannerContext`] implementation.
#[must_use]
pub fn build_report_from_planner_context<C: PlannerContext + ?Sized>(
    ctx: &C,
    file_subject_counts: &[(PathBuf, usize)],
    effects_scanned: usize,
    mut diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
    packages: &[WorkspacePackage],
) -> JsonReport {
    for diag in &mut diagnostics {
        diag.message_id = "";
        diag.docs_url = diag.rule.metadata().docs_url;
    }
    let files_scanned = file_subject_counts
        .iter()
        .filter(|(path, _)| {
            !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("css" | "scss" | "html" | "htm")
            )
        })
        .count();
    let subjects_scanned: usize = file_subject_counts.iter().map(|(_, c)| *c).sum();

    let mut error_count = 0;
    let mut warning_count = 0;
    let mut autofix_count = 0;
    let mut surgical_count = 0;
    let mut refactor_count = 0;
    let mut affected_files: BTreeSet<&Path> = BTreeSet::new();
    let mut diagnostic_fingerprints = BTreeMap::new();

    for diag in &diagnostics {
        affected_files.insert(&diag.file);
        match diag.severity {
            RuleSeverity::Error => error_count += 1,
            RuleSeverity::Warning => warning_count += 1,
        }
        match diag.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
        let src = sources.get(&diag.file).map(String::as_str);
        diagnostic_fingerprints.insert(diag.id(), diag.fingerprint_with_source(src));
    }

    let (root_cause_groups, fix_capsules) =
        build_root_cause_groups_and_capsules(ctx, &diagnostics, sources);

    let health = compute_local_health_score(&root_cause_groups, files_scanned, subjects_scanned);
    let projects = build_project_coverage_metadata(
        file_subject_counts,
        &diagnostics,
        &root_cause_groups,
        packages,
    );

    JsonReport {
        schema_version: JSON_REPORT_SCHEMA_VERSION,
        mode: ScanMode::Full,
        summary: ReportSummary {
            files_scanned,
            subjects_scanned,
            effects_scanned,
            total_diagnostics: diagnostics.len(),
            error_count,
            warning_count,
            affected_file_count: affected_files.len(),
            autofix_count,
            surgical_count,
            refactor_count,
            health_score: health.score,
            score_label: health.label,
        },
        projects,
        diagnostics,
        root_cause_groups,
        fix_capsules,
        diagnostic_fingerprints,
        diff: None,
        baseline: None,
        baseline_degraded: false,
    }
}

fn build_project_coverage_metadata(
    file_subject_counts: &[(PathBuf, usize)],
    diagnostics: &[Diagnostic],
    root_cause_groups: &[RootCauseGroup],
    packages: &[WorkspacePackage],
) -> Vec<ProjectCoverageMetadata> {
    if packages.is_empty() {
        let mut analyzed_files: Vec<PathBuf> =
            file_subject_counts.iter().map(|(p, _)| p.clone()).collect();
        analyzed_files.sort();
        let analyzed_file_count = analyzed_files.len();
        let subjects_scanned: usize = file_subject_counts.iter().map(|(_, c)| *c).sum();
        let health =
            compute_local_health_score(root_cause_groups, analyzed_file_count, subjects_scanned);
        return vec![ProjectCoverageMetadata {
            name: "root".to_string(),
            root_dir: PathBuf::from("."),
            role: PackageRole::Application,
            capabilities: vec![Capability::React],
            analyzed_files,
            analyzed_file_count,
            subjects_scanned,
            diagnostic_count: diagnostics.len(),
            health_score: health.score,
            score_label: health.label,
            complete: true,
        }];
    }

    let mut file_to_pkg_idx: HashMap<&Path, usize> =
        HashMap::with_capacity(file_subject_counts.len());
    let mut pkg_files: Vec<Vec<PathBuf>> = (0..packages.len()).map(|_| Vec::new()).collect();
    let mut pkg_subjects: Vec<usize> = vec![0; packages.len()];
    let mut pkg_diag_counts: Vec<usize> = vec![0; packages.len()];
    let mut pkg_groups: Vec<Vec<RootCauseGroup>> =
        (0..packages.len()).map(|_| Vec::new()).collect();

    let resolve_idx = |path: &Path| -> Option<usize> {
        let resolved = resolve_package_for_file(path, packages)?;
        packages
            .iter()
            .position(|p| p.root_dir == resolved.root_dir)
    };

    for (file_path, subj_count) in file_subject_counts {
        if let Some(idx) = resolve_idx(file_path) {
            file_to_pkg_idx.insert(file_path.as_path(), idx);
            pkg_files[idx].push(file_path.to_path_buf());
            pkg_subjects[idx] += *subj_count;
        }
    }

    for diag in diagnostics {
        let idx_opt = file_to_pkg_idx
            .get(diag.file.as_path())
            .copied()
            .or_else(|| resolve_idx(&diag.file));
        if let Some(idx) = idx_opt {
            file_to_pkg_idx.entry(diag.file.as_path()).or_insert(idx);
            pkg_diag_counts[idx] += 1;
        }
    }

    for group in root_cause_groups {
        let idx_opt = file_to_pkg_idx
            .get(group.file.as_path())
            .copied()
            .or_else(|| resolve_idx(&group.file));
        if let Some(idx) = idx_opt {
            file_to_pkg_idx.entry(group.file.as_path()).or_insert(idx);
            pkg_groups[idx].push(RootCauseGroup {
                id: group.id.clone(),
                rule: group.rule,
                category: group.category,
                severity: group.severity,
                tier: group.tier,
                file: group.file.clone(),
                subject_name: group.subject_name.clone(),
                target_name: group.target_name.clone(),
                loc: group.loc,
                message: group.message.clone(),
                blast_radius: group.blast_radius.clone(),
                diagnostic_indices: group.diagnostic_indices.clone(),
            });
        }
    }

    packages
        .iter()
        .enumerate()
        .map(|(idx, pkg)| {
            let mut analyzed_files = std::mem::take(&mut pkg_files[idx]);
            analyzed_files.sort();
            let analyzed_file_count = analyzed_files.len();
            let subjects_scanned = pkg_subjects[idx];
            let diagnostic_count = pkg_diag_counts[idx];
            let health =
                compute_local_health_score(&pkg_groups[idx], analyzed_file_count, subjects_scanned);
            let mut capabilities: Vec<Capability> =
                pkg.capability_gate.capabilities.iter().copied().collect();
            capabilities.sort_by_key(|c| c.as_str());

            ProjectCoverageMetadata {
                name: pkg.name.clone(),
                root_dir: pkg.root_dir.clone(),
                role: pkg.capability_gate.package_role,
                capabilities,
                analyzed_files,
                analyzed_file_count,
                subjects_scanned,
                diagnostic_count,
                health_score: health.score,
                score_label: health.label,
                complete: true,
            }
        })
        .collect()
}

/// Current schema version for `scan-results.json`.
pub const SCAN_CACHE_SCHEMA_VERSION: u32 = 1;

/// Maximum number of workspace scan result entries retained in `scan-results.json`.
pub const MAX_SCAN_CACHE_ENTRIES: usize = 16;

/// A single cached workspace scan entry in `~/.dotore/cache/scan-results.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCacheEntry {
    /// Deterministic composite cache key (`scan::<hash>`).
    pub key: String,
    /// Canonical workspace root path.
    pub workspace_root: String,
    /// Git HEAD commit SHA (`"uncommitted"` or `"no-git"` when unavailable).
    pub head_sha: String,
    /// Tool version string (`env!("CARGO_PKG_VERSION")`).
    pub tool_version: String,
    /// Unix epoch timestamp (milliseconds) when this entry was last accessed/stored.
    pub updated_at_ms: u64,
    /// Cached full [`JsonReport`].
    pub report: JsonReport,
}

/// Bounded LRU workspace scan cache stored at `~/.dotore/cache/scan-results.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResultCacheFile {
    /// Cache format version (`1`).
    pub version: u32,
    /// Most-recently-used ordered cache entries (capped at [`MAX_SCAN_CACHE_ENTRIES`]).
    pub entries: Vec<ScanCacheEntry>,
}

/// Resolves the persistent workspace scan result cache path (`~/.dotore/cache/scan-results.json`),
/// honoring `DOTORE_HOME`.
#[must_use]
pub fn resolve_scan_cache_path() -> Option<PathBuf> {
    crate::config::resolve_dotore_home_dir()
        .map(|home| home.join("cache").join("scan-results.json"))
}

/// Loads the bounded LRU scan result cache from `cache_path`, returning an empty cache if
/// the file is missing, unreadable, malformed, or uses a different schema version.
#[must_use]
pub fn load_scan_result_cache(cache_path: &Path) -> ScanResultCacheFile {
    let Ok(raw) = fs::read_to_string(cache_path) else {
        return ScanResultCacheFile {
            version: SCAN_CACHE_SCHEMA_VERSION,
            entries: Vec::new(),
        };
    };
    let Ok(parsed) = serde_json::from_str::<ScanResultCacheFile>(&raw) else {
        return ScanResultCacheFile {
            version: SCAN_CACHE_SCHEMA_VERSION,
            entries: Vec::new(),
        };
    };
    if parsed.version != SCAN_CACHE_SCHEMA_VERSION {
        return ScanResultCacheFile {
            version: SCAN_CACHE_SCHEMA_VERSION,
            entries: Vec::new(),
        };
    }
    parsed
}

/// Looks up `key` in the workspace scan cache at `cache_path`.
///
/// On a cache hit, moves the matching [`ScanCacheEntry`] to index `0` (most-recently-used),
/// updates `updated_at_ms`, persists the updated LRU order atomically, and returns the cached [`JsonReport`].
#[must_use]
pub fn lookup_scan_cache(cache_path: &Path, key: &str) -> Option<JsonReport> {
    let mut cache = load_scan_result_cache(cache_path);
    let pos = cache.entries.iter().position(|e| e.key == key)?;
    let mut entry = cache.entries.remove(pos);
    entry.updated_at_ms = current_unix_ms();
    let report = entry.report.clone();
    cache.entries.insert(0, entry);
    cache.entries.truncate(MAX_SCAN_CACHE_ENTRIES);
    let _ = write_scan_result_cache_atomic(cache_path, &cache);
    Some(report)
}

/// Stores `entry` at the front of the bounded LRU workspace scan cache at `cache_path`,
/// removing any prior entry with the same `key`, truncating to [`MAX_SCAN_CACHE_ENTRIES`],
/// and writing the cache file atomically.
///
/// # Errors
/// Returns an `io::Error` if serializing or writing the cache file fails.
pub fn store_scan_cache(cache_path: &Path, entry: ScanCacheEntry) -> io::Result<()> {
    let mut cache = load_scan_result_cache(cache_path);
    cache.version = SCAN_CACHE_SCHEMA_VERSION;
    cache.entries.retain(|e| e.key != entry.key);
    cache.entries.insert(0, entry);
    cache.entries.truncate(MAX_SCAN_CACHE_ENTRIES);
    write_scan_result_cache_atomic(cache_path, &cache)
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn write_scan_result_cache_atomic(
    cache_path: &Path,
    cache: &ScanResultCacheFile,
) -> io::Result<()> {
    let mut bytes =
        serde_json::to_vec(cache).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    crate::config::write_file_atomically(cache_path, &bytes)
}
