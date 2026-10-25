//! Diagnostic fingerprinting and `--baseline <report.json | rev>` multiset comparison.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::rules::{Diagnostic, RuleId};

use super::patch::{run_git, validate_git_revision};

/// Computes the deterministic occurrence identity for `diag` (`<rel_file>::<line>:<col>::dotore/<rule>::<digest>`).
#[must_use]
pub fn compute_diagnostic_id(diag: &Diagnostic, root_dir: Option<&Path>) -> String {
    let rel_file = normalize_display_path(&diag.file, root_dir);
    let digest = fnv1a_128_hex(&[
        diag.severity.as_str(),
        "\0",
        &diag.message,
        "\0",
        &diag.target_name,
    ]);
    format!(
        "{rel_file}::{}:{}::dotore/{}::{digest}",
        diag.loc.line,
        diag.loc.column,
        diag.rule.as_str()
    )
}

/// Computes a rename- and formatting-resilient fingerprint for `diag` from its rule ID,
/// normalized message (independent of enclosing component name), and normalized AST/source tokens
/// (independent of file path and line number).
#[must_use]
pub fn compute_diagnostic_fingerprint(diag: &Diagnostic, source: Option<&str>) -> String {
    let norm_msg = normalize_message_for_fingerprint(&diag.message, diag.subject_name.as_deref());
    let norm_target = normalize_ast_tokens(&diag.target_name);
    let span_tokens = source
        .and_then(|src| {
            let start = diag.span.start as usize;
            let end = diag.span.end as usize;
            if start < end && end <= src.len() {
                src.get(start..end)
            } else {
                None
            }
        })
        .map(normalize_ast_tokens)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| norm_target.clone());

    let digest = fnv1a_128_hex(&[
        diag.rule.as_str(),
        "\0",
        &norm_msg,
        "\0",
        &norm_target,
        "\0",
        &span_tokens,
    ]);
    format!("fp::{}::{digest}", diag.rule.as_str())
}

/// Computes the structural `(rule, normalized_message, normalized_target)` fingerprint without source span text.
#[must_use]
pub fn compute_structural_fingerprint(diag: &Diagnostic) -> String {
    let norm_msg = normalize_message_for_fingerprint(&diag.message, diag.subject_name.as_deref());
    let norm_target = normalize_ast_tokens(&diag.target_name);
    let digest = fnv1a_128_hex(&[diag.rule.as_str(), "\0", &norm_msg, "\0", &norm_target]);
    format!("fp::{}::{digest}", diag.rule.as_str())
}

fn normalize_message_for_fingerprint(message: &str, subject_name: Option<&str>) -> String {
    let mut cleaned = message.to_string();
    if let Some(subj) = subject_name
        && !subj.is_empty()
    {
        let backticked = format!("`{subj}`");
        cleaned = cleaned.replace(&backticked, "`<subject>`");
    }
    normalize_ast_tokens(&cleaned)
}

/// Normalizes source/message text into a formatting-invariant token stream (stripping comments,
/// unifying quote delimiters, and collapsing whitespace around punctuation and identifiers).
#[must_use]
pub fn normalize_ast_tokens(input: &str) -> String {
    let mut tokens: Vec<String> = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while let Some(&b) = bytes.get(i) {
        if b.is_ascii_whitespace() || b == b';' {
            i += 1;
        } else if skip_token_comment(bytes, &mut i) {
            // comment skipped
        } else if b == b'\'' || b == b'"' {
            tokens.push(consume_quoted_token(bytes, &mut i, b));
        } else if is_ident_byte(b) {
            if let Some(word) = consume_ident_token(input, bytes, &mut i) {
                tokens.push(word.to_string());
            }
        } else {
            tokens.push(consume_operator_or_char(input, &mut i));
        }
    }

    tokens.join(" ")
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn skip_token_comment(bytes: &[u8], i: &mut usize) -> bool {
    if bytes.get(*i) == Some(&b'/') && bytes.get(*i + 1) == Some(&b'/') {
        *i += 2;
        while bytes.get(*i).is_some_and(|&c| c != b'\n') {
            *i += 1;
        }
        return true;
    }
    if bytes.get(*i) == Some(&b'/') && bytes.get(*i + 1) == Some(&b'*') {
        *i += 2;
        while *i + 1 < bytes.len()
            && !(bytes.get(*i) == Some(&b'*') && bytes.get(*i + 1) == Some(&b'/'))
        {
            *i += 1;
        }
        *i = (*i + 2).min(bytes.len());
        return true;
    }
    false
}

fn consume_quoted_token(bytes: &[u8], i: &mut usize, quote: u8) -> String {
    *i += 1;
    let mut content = String::new();
    while let Some(&cur) = bytes.get(*i) {
        if cur == quote {
            *i += 1;
            break;
        }
        if cur == b'\\' && *i + 1 < bytes.len() {
            *i += 1;
        }
        if let Some(&ch_byte) = bytes.get(*i) {
            content.push(ch_byte as char);
        }
        *i += 1;
    }
    format!(
        "{:?}",
        content.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

fn consume_ident_token<'a>(input: &'a str, bytes: &[u8], i: &mut usize) -> Option<&'a str> {
    let start = *i;
    *i += 1;
    while bytes.get(*i).is_some_and(|&c| is_ident_byte(c)) {
        *i += 1;
    }
    input.get(start..*i)
}

fn consume_operator_or_char(input: &str, i: &mut usize) -> String {
    if let Some(op3) = input.get(*i..*i + 3)
        && matches!(op3, "===" | "!==" | "...")
    {
        *i += 3;
        return op3.to_string();
    }
    if let Some(op2) = input.get(*i..*i + 2)
        && matches!(op2, "=>" | "==" | "!=" | "<=" | ">=" | "&&" | "||" | "??")
    {
        *i += 2;
        return op2.to_string();
    }
    if let Some(ch) = input.get(*i..).and_then(|s| s.chars().next()) {
        *i += ch.len_utf8();
        ch.to_string()
    } else {
        *i += 1;
        String::new()
    }
}

fn normalize_display_path(path: &Path, root_dir: Option<&Path>) -> String {
    let stripped = if let Some(root) = root_dir {
        path.strip_prefix(root).unwrap_or(path)
    } else {
        path
    };
    let raw = stripped.to_string_lossy().replace('\\', "/");
    raw.strip_prefix("./").unwrap_or(&raw).to_string()
}

fn fnv1a_128_hex(parts: &[&str]) -> String {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    let prime: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    for part in parts {
        for &byte in part.as_bytes() {
            hash ^= u128::from(byte);
            hash = hash.wrapping_mul(prime);
        }
    }
    format!("{hash:032x}")
}

/// Summary of a `--baseline` multiset comparison attached to [`crate::JsonReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSummary {
    /// Path or reference of the baseline source.
    pub baseline_source: String,
    /// Count of net-new diagnostics introduced since the baseline.
    pub introduced_count: usize,
    /// Count of baseline diagnostics that were resolved/fixed.
    pub fixed_count: usize,
    /// Count of pre-existing diagnostics matched and suppressed from active findings.
    pub preexisting_count: usize,
    /// Total diagnostics present in the baseline report.
    pub baseline_total_count: usize,
}

/// Result of comparing current diagnostics against a baseline report as a multiset.
#[derive(Debug, Clone)]
pub struct BaselineDeltaResult {
    /// Net-new (introduced) diagnostics retained after multiset subtraction.
    pub introduced_diagnostics: Vec<Diagnostic>,
    /// Delta counts (`introduced_count`, `fixed_count`, `preexisting_count`, `baseline_total_count`).
    pub summary: BaselineSummary,
}

/// A minimal baseline diagnostic entry deserialized from a saved JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiagnosticEntry {
    /// Rule identifier.
    pub rule: RuleId,
    /// File path in the baseline report.
    #[serde(default)]
    pub file: PathBuf,
    /// Enclosing **Subject** name in the baseline report, if any.
    #[serde(default)]
    pub subject_name: Option<String>,
    /// Target identifier name.
    #[serde(default)]
    pub target_name: String,
    /// Diagnostic message.
    #[serde(default)]
    pub message: String,
    /// Precomputed normalized AST/source token fingerprint from the saved report.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Precomputed structural `(rule, message, target)` fingerprint.
    #[serde(default)]
    pub structural_fingerprint: Option<String>,
    /// 1-based line number in the baseline report (`0` if omitted).
    #[serde(default)]
    pub line: u32,
}

impl BaselineDiagnosticEntry {
    /// Creates a [`BaselineDiagnosticEntry`] from a live [`Diagnostic`] and optional file source.
    #[must_use]
    pub fn from_diagnostic(diag: &Diagnostic, source: Option<&str>) -> Self {
        Self {
            rule: diag.rule,
            file: diag.file.clone(),
            subject_name: diag.subject_name.clone(),
            target_name: diag.target_name.clone(),
            message: diag.message.clone(),
            fingerprint: Some(compute_diagnostic_fingerprint(diag, source)),
            structural_fingerprint: Some(compute_structural_fingerprint(diag)),
            line: diag.loc.line,
        }
    }

    fn effective_primary_fingerprint(&self) -> String {
        if let Some(fp) = &self.fingerprint
            && !fp.is_empty()
        {
            return fp.clone();
        }
        self.effective_structural_fingerprint()
    }

    fn effective_structural_fingerprint(&self) -> String {
        if let Some(sfp) = &self.structural_fingerprint
            && !sfp.is_empty()
        {
            return sfp.clone();
        }
        let norm_msg =
            normalize_message_for_fingerprint(&self.message, self.subject_name.as_deref());
        let norm_target = normalize_ast_tokens(&self.target_name);
        let digest = fnv1a_128_hex(&[self.rule.as_str(), "\0", &norm_msg, "\0", &norm_target]);
        format!("fp::{}::{digest}", self.rule.as_str())
    }
}

/// Compares `current_diagnostics` against `baseline_entries` as a multiset of normalized
/// `rule + message + AST-token` fingerprints (independent of file path and line number),
/// returning only net-new (`introduced_diagnostics`) findings and the [`BaselineSummary`].
#[must_use]
pub fn compare_baseline_diagnostics(
    current_diagnostics: &[Diagnostic],
    current_sources: &HashMap<PathBuf, String>,
    baseline_entries: &[BaselineDiagnosticEntry],
    baseline_source: &str,
) -> BaselineDeltaResult {
    let mut unmatched_head: BTreeSet<usize> = (0..current_diagnostics.len()).collect();
    let mut unmatched_base: BTreeSet<usize> = (0..baseline_entries.len()).collect();

    let head_primary_fps: Vec<String> = current_diagnostics
        .iter()
        .map(|d| {
            let src = current_sources.get(&d.file).map(String::as_str);
            compute_diagnostic_fingerprint(d, src)
        })
        .collect();
    let head_struct_fps: Vec<String> = current_diagnostics
        .iter()
        .map(compute_structural_fingerprint)
        .collect();

    let base_primary_fps: Vec<String> = baseline_entries
        .iter()
        .map(BaselineDiagnosticEntry::effective_primary_fingerprint)
        .collect();
    let base_struct_fps: Vec<String> = baseline_entries
        .iter()
        .map(BaselineDiagnosticEntry::effective_structural_fingerprint)
        .collect();

    match_multiset_by_key(
        current_diagnostics,
        baseline_entries,
        &head_primary_fps,
        &base_primary_fps,
        &mut unmatched_head,
        &mut unmatched_base,
    );

    match_multiset_by_key(
        current_diagnostics,
        baseline_entries,
        &head_struct_fps,
        &base_struct_fps,
        &mut unmatched_head,
        &mut unmatched_base,
    );

    let baseline_total_count = baseline_entries.len();
    let preexisting_count = baseline_total_count.saturating_sub(unmatched_base.len());
    let fixed_count = unmatched_base.len();
    let introduced_diagnostics: Vec<Diagnostic> = unmatched_head
        .into_iter()
        .filter_map(|idx| current_diagnostics.get(idx).cloned())
        .collect();
    let introduced_count = introduced_diagnostics.len();

    BaselineDeltaResult {
        introduced_diagnostics,
        summary: BaselineSummary {
            baseline_source: baseline_source.to_string(),
            introduced_count,
            fixed_count,
            preexisting_count,
            baseline_total_count,
        },
    }
}

fn match_multiset_by_key(
    current_diagnostics: &[Diagnostic],
    baseline_entries: &[BaselineDiagnosticEntry],
    head_keys: &[String],
    base_keys: &[String],
    unmatched_head: &mut BTreeSet<usize>,
    unmatched_base: &mut BTreeSet<usize>,
) {
    let mut base_buckets: HashMap<(RuleId, &str), Vec<usize>> = HashMap::new();
    for &b_idx in unmatched_base.iter() {
        if let Some(entry) = baseline_entries.get(b_idx)
            && let Some(key) = base_keys.get(b_idx)
        {
            base_buckets
                .entry((entry.rule, key.as_str()))
                .or_default()
                .push(b_idx);
        }
    }

    let mut head_buckets: HashMap<(RuleId, &str), Vec<usize>> = HashMap::new();
    for &h_idx in unmatched_head.iter() {
        if let Some(diag) = current_diagnostics.get(h_idx)
            && let Some(key) = head_keys.get(h_idx)
        {
            head_buckets
                .entry((diag.rule, key.as_str()))
                .or_default()
                .push(h_idx);
        }
    }

    for ((rule, key), mut b_indices) in base_buckets {
        let Some(mut h_indices) = head_buckets.remove(&(rule, key)) else {
            continue;
        };

        let mut b_pos = 0;
        while b_pos < b_indices.len() && !h_indices.is_empty() {
            let b_idx = b_indices[b_pos];
            let Some(b_entry) = baseline_entries.get(b_idx) else {
                b_indices.remove(b_pos);
                continue;
            };
            if let Some((best_h_pos, _)) = h_indices
                .iter()
                .enumerate()
                .filter(|&(_, &h_idx)| {
                    current_diagnostics
                        .get(h_idx)
                        .is_some_and(|d| paths_match_loosely(&d.file, &b_entry.file))
                })
                .min_by_key(|&(_, &h_idx)| {
                    current_diagnostics
                        .get(h_idx)
                        .map_or(u32::MAX, |d| d.loc.line.abs_diff(b_entry.line))
                })
            {
                let matched_h = h_indices.remove(best_h_pos);
                b_indices.remove(b_pos);
                unmatched_head.remove(&matched_h);
                unmatched_base.remove(&b_idx);
            } else {
                b_pos += 1;
            }
        }

        for b_idx in b_indices {
            if h_indices.is_empty() {
                break;
            }
            let Some(b_entry) = baseline_entries.get(b_idx) else {
                continue;
            };
            let b_line = b_entry.line;
            let best_h_pos = h_indices
                .iter()
                .enumerate()
                .min_by_key(|&(_, &h_idx)| {
                    current_diagnostics
                        .get(h_idx)
                        .map_or(u32::MAX, |d| d.loc.line.abs_diff(b_line))
                })
                .map_or(0, |(pos, _)| pos);
            let matched_h = h_indices.remove(best_h_pos);
            unmatched_head.remove(&matched_h);
            unmatched_base.remove(&b_idx);
        }
    }
}

fn paths_match_loosely(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let a_str = a.to_string_lossy().replace('\\', "/");
    let b_str = b.to_string_lossy().replace('\\', "/");
    let a_clean = a_str.strip_prefix("./").unwrap_or(&a_str);
    let b_clean = b_str.strip_prefix("./").unwrap_or(&b_str);
    a_clean == b_clean
        || a_clean.ends_with(&format!("/{b_clean}"))
        || b_clean.ends_with(&format!("/{a_clean}"))
}

/// Parses a baseline JSON report string into [`BaselineDiagnosticEntry`] records.
///
/// # Errors
/// Returns an error string if `json_str` is not valid JSON or lacks a `"diagnostics"` array.
pub fn parse_baseline_report_str(json_str: &str) -> Result<Vec<BaselineDiagnosticEntry>, String> {
    let root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid baseline JSON: {e}"))?;

    let diag_array = if let Some(arr) = root
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
    {
        arr
    } else if let Some(arr) = root.as_array() {
        arr
    } else {
        return Err("Baseline JSON does not contain a `diagnostics` array.".to_string());
    };

    let fp_map = root
        .get("diagnostic_fingerprints")
        .and_then(serde_json::Value::as_object);
    let mut entries = Vec::with_capacity(diag_array.len());
    for item in diag_array {
        let Some(rule_str) = item.get("rule").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(rule) = RuleId::parse(rule_str) else {
            continue;
        };
        let file = item
            .get("file")
            .or_else(|| item.get("filePath"))
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_default();
        let subject_name = item
            .get("subject_name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let target_name = item
            .get("target_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let message = item
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let item_id = item.get("id").and_then(serde_json::Value::as_str);
        let item_fp = item
            .get("fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let source_fp = item_id
            .and_then(|id| fp_map.and_then(|m| m.get(id)))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let fingerprint = source_fp.or_else(|| item_fp.clone());
        let structural_fingerprint = item
            .get("structural_fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or(item_fp);
        let line = item
            .get("loc")
            .and_then(|l| l.get("line"))
            .or_else(|| item.get("line"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);

        entries.push(BaselineDiagnosticEntry {
            rule,
            file,
            subject_name,
            target_name,
            message,
            fingerprint,
            structural_fingerprint,
            line,
        });
    }

    Ok(entries)
}

/// Attempts to load baseline diagnostic entries from a JSON file path or a git revision's base blobs.
///
/// # Errors
/// Returns an error string if the JSON file is missing/unreadable or git base blobs are unavailable.
pub fn load_baseline_entries_with<F>(
    workspace_root: &Path,
    baseline_arg: &Path,
    enabled_rules: Option<&[RuleId]>,
    analyze_project: F,
) -> Result<Vec<BaselineDiagnosticEntry>, String>
where
    F: FnOnce(Vec<(PathBuf, String)>, Option<&[RuleId]>) -> Vec<Diagnostic>,
{
    if baseline_arg.is_file() {
        let content = fs::read_to_string(baseline_arg).map_err(|e| {
            format!(
                "Failed to read baseline file {}: {e}",
                baseline_arg.display()
            )
        })?;
        return parse_baseline_report_str(&content);
    }

    let rev_str = baseline_arg.to_string_lossy();
    validate_git_revision(&rev_str)?;
    let repo_root_out = run_git(workspace_root, &["rev-parse", "--show-toplevel"])?;
    let repo_root = PathBuf::from(repo_root_out.trim());

    let tree_spec = format!("{rev_str}^{{tree}}");
    if run_git(&repo_root, &["cat-file", "-e", &tree_spec]).is_err()
        && run_git(&repo_root, &["rev-parse", "--verify", &tree_spec]).is_err()
    {
        return Err(format!(
            "Base git tree for {rev_str:?} is unavailable (shallow clone or missing object)."
        ));
    }

    let ls_tree = run_git(&repo_root, &["ls-tree", "-r", "--name-only", &rev_str])?;
    let mut base_files: Vec<(PathBuf, String)> = Vec::new();
    for rel_line in ls_tree.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let is_source = [
            ".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".py", ".pyi", ".rs",
        ]
        .iter()
        .any(|ext| rel_line.ends_with(ext))
            || rel_line.ends_with("package.json")
            || rel_line.ends_with("angular.json")
            || rel_line.ends_with("pyproject.toml")
            || rel_line.ends_with("requirements.txt")
            || rel_line.ends_with("Cargo.toml")
            || rel_line.contains("dotore.config.");
        if !is_source {
            continue;
        }
        let blob_spec = format!("{rev_str}:{rel_line}");
        let blob_content = run_git(&repo_root, &["show", &blob_spec])?;
        base_files.push((PathBuf::from(rel_line), blob_content));
    }

    let base_sources: HashMap<PathBuf, String> = base_files.iter().cloned().collect();
    let diagnostics = analyze_project(base_files, enabled_rules);
    Ok(diagnostics
        .iter()
        .map(|d| {
            let src = base_sources.get(&d.file).map(String::as_str);
            BaselineDiagnosticEntry::from_diagnostic(d, src)
        })
        .collect())
}
