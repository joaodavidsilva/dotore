//! Coding-agent handoff bundle writer, prompt synthesis, clipboard support, and CLI launcher.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{resolve_dotore_home_dir, write_file_atomically},
    report::{JsonReport, write_json_report},
    rules::{
        FixCapsule, PrescriptionTier, RootCauseGroup, RuleCategory, RuleId, RuleMetadata,
    },
};
use super::{
    capsules::invariants_for_rule, compute_root_cause_group_id, group_prescription_tier,
    markdown::excerpt_code_fence_lang,
};

/// Minimum distinct affected files for a rule to be classified as a migration-scale bucket.
pub const MIGRATION_BUCKET_MIN_FILES: usize = 3;

/// Summary of a migration-scale rule bucket spanning multiple files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRuleBucket {
    /// Rule identifier.
    pub rule: RuleId,
    /// Rule category.
    pub category: RuleCategory,
    /// Prescription tier (`Autofix`, `Surgical`, `Refactor`).
    pub tier: PrescriptionTier,
    /// Total diagnostic occurrences for this rule.
    pub diagnostic_count: usize,
    /// Distinct affected file paths in deterministic order.
    pub affected_files: Vec<PathBuf>,
    /// Path to the generated per-rule `.txt` breakdown file in the bundle directory, if written.
    pub summary_file: Option<PathBuf>,
}

/// Result of writing a diagnostics bundle directory for a coding agent handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsBundle {
    /// Directory where the bundle files were written.
    pub bundle_dir: PathBuf,
    /// Path to `diagnostics.json` inside `bundle_dir`.
    pub diagnostics_json_path: PathBuf,
    /// Paths to per-rule `<rule-id>.txt` breakdown files in deterministic order.
    pub rule_summary_files: Vec<(RuleId, PathBuf)>,
    /// Detected migration-scale rule buckets.
    pub migration_buckets: Vec<MigrationRuleBucket>,
    /// Self-contained Markdown handoff prompt referencing the bundle files.
    pub prompt_markdown: String,
}

/// Identifies migration-scale rule buckets spanning multiple files in `report`.
#[must_use]
pub fn detect_migration_rule_buckets(report: &JsonReport) -> Vec<MigrationRuleBucket> {
    let mut grouped: BTreeMap<&'static str, (RuleId, Vec<usize>, BTreeSet<PathBuf>)> =
        BTreeMap::new();

    for (idx, diag) in report.diagnostics.iter().enumerate() {
        let entry = grouped
            .entry(diag.rule.as_str())
            .or_insert_with(|| (diag.rule, Vec::new(), BTreeSet::new()));
        entry.1.push(idx);
        entry.2.insert(diag.file.clone());
    }

    let mut buckets: Vec<MigrationRuleBucket> = grouped
        .into_values()
        .filter(|(_, _, files)| files.len() >= MIGRATION_BUCKET_MIN_FILES)
        .map(|(rule, indices, files)| {
            let meta = rule.metadata();
            let tier = group_prescription_tier(&indices, &report.diagnostics);
            MigrationRuleBucket {
                rule,
                category: meta.category,
                tier,
                diagnostic_count: indices.len(),
                affected_files: files.into_iter().collect(),
                summary_file: None,
            }
        })
        .collect();

    buckets.sort_by(|a, b| {
        (
            Reverse(a.affected_files.len()),
            Reverse(a.diagnostic_count),
            a.rule.as_str(),
        )
            .cmp(&(
                Reverse(b.affected_files.len()),
                Reverse(b.diagnostic_count),
                b.rule.as_str(),
            ))
    });

    buckets
}

/// Renders the per-rule `.txt` summary breakdown for `rule` across `report`.
#[must_use]
pub fn render_rule_bundle_summary_text(rule: RuleId, report: &JsonReport) -> String {
    let meta = rule.metadata();
    let mut matching_indices: Vec<usize> = report
        .diagnostics
        .iter()
        .enumerate()
        .filter(|(_, d)| d.rule == rule)
        .map(|(idx, _)| idx)
        .collect();
    matching_indices.sort_by(|&a, &b| {
        let (Some(da), Some(db)) = (report.diagnostics.get(a), report.diagnostics.get(b)) else {
            return std::cmp::Ordering::Equal;
        };
        (
            &da.file,
            da.loc.line,
            da.loc.column,
            &da.target_name,
            &da.message,
        )
            .cmp(&(
                &db.file,
                db.loc.line,
                db.loc.column,
                &db.target_name,
                &db.message,
            ))
    });

    let distinct_files: BTreeSet<&Path> = matching_indices
        .iter()
        .filter_map(|&idx| report.diagnostics.get(idx).map(|d| d.file.as_path()))
        .collect();
    let effective_tier = if matching_indices.is_empty() {
        meta.default_tier
    } else {
        group_prescription_tier(&matching_indices, &report.diagnostics)
    };

    let mut out = String::new();
    let _ = writeln!(out, "Rule: {} ({})", rule.as_str(), meta.title);
    let _ = writeln!(out, "Category: {}", meta.category.as_str());
    let _ = writeln!(out, "Prescription Tier: {}", effective_tier.as_str());
    let _ = writeln!(out, "Default Severity: {}", meta.default_severity.as_str());
    let _ = writeln!(out, "Docs: {}", meta.docs_url);
    let _ = writeln!(
        out,
        "Findings: {} across {} file(s)\n",
        matching_indices.len(),
        distinct_files.len()
    );
    let _ = writeln!(out, "Transformation Recipe:\n{}\n", meta.recipe_markdown);

    let matching_groups: Vec<&RootCauseGroup> = report
        .root_cause_groups
        .iter()
        .filter(|g| g.rule == rule)
        .collect();
    if !matching_groups.is_empty() {
        let _ = writeln!(out, "Root-Cause Groups ({}):", matching_groups.len());
        for group in matching_groups {
            let subject = group.subject_name.as_deref().unwrap_or("<module>");
            let _ = writeln!(
                out,
                "  - {} [{} | score {} | tier {}] {}:{} ({}) — {} site(s)",
                group.id,
                group.blast_radius.tier.as_str(),
                group.blast_radius.score,
                group.tier.as_str(),
                group.file.display(),
                group.loc.line,
                subject,
                group.diagnostic_indices.len()
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "Affected Sites ({}):", matching_indices.len());
    for idx in matching_indices {
        let Some(d) = report.diagnostics.get(idx) else {
            continue;
        };
        let group_id = compute_root_cause_group_id(d);
        let subject = d.subject_name.as_deref().unwrap_or("<module>");
        let _ = writeln!(
            out,
            "  - {}:{}:{} [{} | {} | {}] ({}) — {}",
            d.file.display(),
            d.loc.line,
            d.loc.column,
            d.severity.as_str(),
            d.tier.as_str(),
            group_id,
            subject,
            crate::report::mask_credentials(&d.message)
        );
        if !d.cascade_steps.is_empty() {
            let _ = writeln!(out, "    Render Cascade: {}", d.cascade_steps.join(" -> "));
        }
    }

    out
}

/// Synthesizes a self-contained coding-agent handoff prompt from `report` and optional `bundle_dir`.
#[must_use]
pub fn build_agent_handoff_prompt(report: &JsonReport, bundle_dir: Option<&Path>) -> String {
    let mut md = String::new();
    let s = &report.summary;
    let migration_buckets = detect_migration_rule_buckets(report);
    let distinct_rules = ordered_distinct_rules_in_report(report);

    let _ = writeln!(md, "# Dotore Coding Agent Remediation Handoff\n");
    let _ = writeln!(
        md,
        "You are remediating static analysis findings reported by `dotore`."
    );
    let _ = writeln!(
        md,
        "- **Health Score**: `{}/100` (`{}`)",
        s.health_score, s.score_label
    );
    let _ = writeln!(
        md,
        "- **Scanned**: `{}` file(s), `{}` Subject(s), `{}` Effect Node(s)",
        s.files_scanned, s.subjects_scanned, s.effects_scanned
    );
    let _ = writeln!(
        md,
        "- **Findings**: `{}` total (`{}` error, `{}` warning) across `{}` affected file(s)",
        s.total_diagnostics, s.error_count, s.warning_count, s.affected_file_count
    );
    let _ = writeln!(
        md,
        "- **Prescription Tiers**: `{}` autofix, `{}` surgical, `{}` refactor",
        s.autofix_count, s.surgical_count, s.refactor_count
    );
    let _ = writeln!(
        md,
        "- **Root-Cause Groups**: `{}` (`{}` Fix Capsules)\n",
        report.root_cause_groups.len(),
        report.fix_capsules.len()
    );

    if report.diagnostics.is_empty() && report.root_cause_groups.is_empty() {
        let _ = writeln!(
            md,
            "No diagnostics were found. The workspace is clean (`100/100`)."
        );
        return md;
    }

    render_handoff_instructions_section(&mut md, bundle_dir, &distinct_rules);

    if !migration_buckets.is_empty() {
        render_handoff_migration_section(&mut md, &migration_buckets, bundle_dir);
    }

    render_handoff_groups_section(&mut md, report, bundle_dir);
    md
}

fn ordered_distinct_rules_in_report(report: &JsonReport) -> Vec<RuleId> {
    let mut seen: BTreeMap<&'static str, RuleId> = BTreeMap::new();
    for d in &report.diagnostics {
        seen.entry(d.rule.as_str()).or_insert(d.rule);
    }
    for g in &report.root_cause_groups {
        seen.entry(g.rule.as_str()).or_insert(g.rule);
    }
    seen.into_values().collect()
}

fn render_handoff_instructions_section(
    md: &mut String,
    bundle_dir: Option<&Path>,
    distinct_rules: &[RuleId],
) {
    let _ = writeln!(md, "## Agent Execution Instructions\n");
    let _ = writeln!(
        md,
        "1. **Shared `root_cause_group_id` Resolution**: Diagnostics that share the same `root_cause_group_id` stem from a single underlying flaw in a **Subject** or cross-file contract. Resolve all sites sharing a `root_cause_group_id` together in one cohesive edit rather than patching individual lines in isolation."
    );
    let _ = writeln!(
        md,
        "2. **Respect Prescription Tiers**:\n   - `autofix`: Deterministic single- or cross-file rewrite (run `dotore fix` first or apply the exact recipe).\n   - `surgical`: Localized single-**Subject** transformation following the canonical recipe.\n   - `refactor`: State-model or cross-**Subject** contract redesign; verify all parent **Caller Sites** remain consistent."
    );
    let _ = writeln!(
        md,
        "3. **No Inline Suppressions**: Never add `// dotore-disable`, `// eslint-disable`, or `// oxlint-disable` comments. Fix the underlying root cause."
    );
    let _ = writeln!(
        md,
        "4. **Verify**: Re-run `dotore check` after applying changes to confirm all targeted **Root-Cause Groups** are resolved.\n"
    );

    if let Some(dir) = bundle_dir {
        let diag_json = dir.join("diagnostics.json");
        let _ = writeln!(md, "## Diagnostics Bundle Files\n");
        let _ = writeln!(md, "- **Bundle Directory**: `{}`", dir.display());
        let _ = writeln!(
            md,
            "- **Full Machine-Readable Report**: `{}` (`diagnostics.json`)",
            diag_json.display()
        );
        if !distinct_rules.is_empty() {
            let _ = writeln!(md, "- **Per-Rule Breakdown Summaries**:");
            for &rule in distinct_rules {
                let rule_path = dir.join(format!("{}.txt", rule.as_str()));
                let _ = writeln!(
                    md,
                    "  - `{}` (`{}.txt`)",
                    rule_path.display(),
                    rule.as_str()
                );
            }
        }
        let _ = writeln!(md);
    }
}

fn render_handoff_migration_section(
    md: &mut String,
    migration_buckets: &[MigrationRuleBucket],
    bundle_dir: Option<&Path>,
) {
    let _ = writeln!(
        md,
        "## Migration-Scale Rule Buckets ({})\n",
        migration_buckets.len()
    );
    let _ = writeln!(
        md,
        "The following rules affect `{MIGRATION_BUCKET_MIN_FILES}` or more files across the workspace:\n"
    );
    for bucket in migration_buckets {
        let summary_ref = bundle_dir.map_or_else(
            || format!("{}.txt", bucket.rule.as_str()),
            |dir| {
                dir.join(format!("{}.txt", bucket.rule.as_str()))
                    .display()
                    .to_string()
            },
        );
        let files_preview: Vec<String> = bucket
            .affected_files
            .iter()
            .map(|p| format!("`{}`", p.display()))
            .collect();
        let _ = writeln!(
            md,
            "- **`{}`** (Category: `{}`, Prescription Tier: `{}`): `{}` finding(s) across `{}` file(s) — breakdown: `{}`\n  - Affected files: {}",
            bucket.rule.as_str(),
            bucket.category.as_str(),
            bucket.tier.as_str(),
            bucket.diagnostic_count,
            bucket.affected_files.len(),
            summary_ref,
            files_preview.join(", ")
        );
    }
    let _ = writeln!(md, "\n### Staged Remediation Guidance\n");
    let _ = writeln!(
        md,
        "1. **Stage 1 (Deterministic Autofixes)**: If a migration bucket has Prescription Tier `autofix`, run `dotore fix` or batch-apply the canonical transformation across the listed files first."
    );
    let _ = writeln!(
        md,
        "2. **Stage 2 (Representative Exemplar First)**: For `surgical` or `refactor` migration buckets, remediate the highest-Blast-Radius **Subject** first, verify with `dotore check`, and use that change as the local convention for the remaining files in the per-rule `.txt` summary."
    );
    let _ = writeln!(
        md,
        "3. **Stage 3 (Incremental Batch Verification)**: Apply the pattern package-by-package or module-by-module, running `dotore check --rule <rule-id>` after each batch to prevent regressions.\n"
    );
}

fn render_handoff_groups_section(md: &mut String, report: &JsonReport, bundle_dir: Option<&Path>) {
    let _ = writeln!(
        md,
        "## Top Root-Cause Groups ({})\n",
        report.root_cause_groups.len()
    );

    for (idx, group) in report.root_cause_groups.iter().enumerate() {
        render_handoff_single_group(md, idx + 1, group, report, bundle_dir);
    }
}

fn render_handoff_single_group(
    md: &mut String,
    ordinal: usize,
    group: &RootCauseGroup,
    report: &JsonReport,
    bundle_dir: Option<&Path>,
) {
    let meta = group.rule.metadata();
    let subject = group
        .subject_name
        .as_deref()
        .unwrap_or(group.target_name.as_str());
    let subject_label = if subject.is_empty() { "<module>" } else { subject };
    let capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.root_cause_group_id == group.id);

    let _ = writeln!(
        md,
        "### {ordinal}. `{}` in `{subject_label}` (`{}:{}`)\n",
        group.rule.as_str(),
        group.file.display(),
        group.loc.line
    );
    let _ = writeln!(md, "- **`root_cause_group_id`**: `{}`", group.id);
    let _ = writeln!(
        md,
        "- **Rule**: `{}` ({}) — Category: `{}`",
        group.rule.as_str(),
        meta.title,
        group.category.as_str()
    );
    let _ = writeln!(
        md,
        "- **Prescription Tier**: `{}` (Severity: `{}`)",
        group.tier.as_str(),
        group.severity.as_str()
    );
    let _ = writeln!(
        md,
        "- **Blast Radius**: `{}` (score `{}`, frequency `{}`, fan-out `{}`, cascade depth `{}`, sites `{}`, files `{}`)",
        group.blast_radius.tier.as_str(),
        group.blast_radius.score,
        group.blast_radius.render_frequency.as_str(),
        group.blast_radius.fan_out,
        group.blast_radius.cascade_depth,
        group.blast_radius.site_count,
        group.blast_radius.file_count
    );
    if let Some(dir) = bundle_dir {
        let rule_file = dir.join(format!("{}.txt", group.rule.as_str()));
        let _ = writeln!(md, "- **Rule Breakdown File**: `{}`", rule_file.display());
    }
    let _ = writeln!(md, "- **Affected `file:line` Sites**:");
    for &diag_idx in &group.diagnostic_indices {
        if let Some(d) = report.diagnostics.get(diag_idx) {
            let _ = writeln!(
                md,
                "  - `{}:{}:{}` (`root_cause_group_id`: `{}`) — {}",
                d.file.display(),
                d.loc.line,
                d.loc.column,
                group.id,
                crate::report::mask_credentials(&d.message)
            );
            if !d.cascade_steps.is_empty() {
                let _ = writeln!(
                    md,
                    "    - Render Cascade: `{}`",
                    d.cascade_steps.join(" -> ")
                );
            }
        }
    }
    let _ = writeln!(md);

    render_handoff_capsule_details(md, group, meta, capsule);
}

fn render_handoff_capsule_details(
    md: &mut String,
    group: &RootCauseGroup,
    meta: &RuleMetadata,
    capsule: Option<&FixCapsule>,
) {
    if let Some(cap) = capsule
        && !cap.subject_excerpt.source.is_empty()
    {
        let lang = excerpt_code_fence_lang(&cap.subject_excerpt.file);
        let _ = writeln!(
            md,
            "#### Subject Excerpt (`{}:{}-{}`)\n\n```{lang}\n{}\n```\n",
            cap.subject_excerpt.file.display(),
            cap.subject_excerpt.start_line,
            cap.subject_excerpt.end_line,
            crate::report::mask_credentials(&cap.subject_excerpt.source)
        );
    }

    if let Some(cap) = capsule
        && !cap.caller_site_excerpts.is_empty()
    {
        let _ = writeln!(
            md,
            "#### Caller Site Excerpts ({})\n",
            cap.caller_site_excerpts.len()
        );
        for caller_ex in &cap.caller_site_excerpts {
            let caller_lang = excerpt_code_fence_lang(&caller_ex.file);
            let _ = writeln!(
                md,
                "- `{}:{}-{}`:\n```{caller_lang}\n{}\n```",
                caller_ex.file.display(),
                caller_ex.start_line,
                caller_ex.end_line,
                crate::report::mask_credentials(&caller_ex.source)
            );
        }
        let _ = writeln!(md);
    }

    let recipe = capsule.map_or(meta.recipe_markdown, |c| c.recipe_markdown);
    let _ = writeln!(md, "#### Canonical Transformation Recipe\n\n{recipe}\n");

    let invariants = capsule.map_or_else(
        || invariants_for_rule(group.rule, group.tier),
        |c| c.invariants.clone(),
    );
    if !invariants.is_empty() {
        let _ = writeln!(md, "#### Invariants to Preserve\n");
        for inv in invariants {
            let _ = writeln!(md, "- {inv}");
        }
        let _ = writeln!(md);
    }

    if let Some(cap) = capsule
        && let Some(exemplar) = &cap.exemplar
        && !exemplar.source.is_empty()
    {
        let ex_lang = excerpt_code_fence_lang(&exemplar.file);
        let _ = writeln!(
            md,
            "#### Repository Exemplar (`{}:{}-{}`)\n\n```{ex_lang}\n{}\n```\n",
            exemplar.file.display(),
            exemplar.start_line,
            exemplar.end_line,
            crate::report::mask_credentials(&exemplar.source)
        );
    }
}

/// Writes `diagnostics.json` and per-rule `<rule-id>.txt` breakdown files into `bundle_dir`
/// and returns the resulting [`DiagnosticsBundle`] with its synthesized `prompt_markdown`.
///
/// # Errors
/// Returns an `io::Error` if creating `bundle_dir` or writing any bundle file fails.
pub fn write_diagnostics_bundle(
    report: &JsonReport,
    bundle_dir: &Path,
) -> io::Result<DiagnosticsBundle> {
    fs::create_dir_all(bundle_dir)?;

    let diagnostics_json_path = bundle_dir.join("diagnostics.json");
    write_json_report(report, &diagnostics_json_path)?;

    let distinct_rules = ordered_distinct_rules_in_report(report);
    let mut rule_summary_files = Vec::with_capacity(distinct_rules.len());
    for rule in distinct_rules {
        let file_path = bundle_dir.join(format!("{}.txt", rule.as_str()));
        let summary_text = render_rule_bundle_summary_text(rule, report);
        fs::write(&file_path, summary_text)?;
        rule_summary_files.push((rule, file_path));
    }

    let mut migration_buckets = detect_migration_rule_buckets(report);
    for bucket in &mut migration_buckets {
        let candidate = bundle_dir.join(format!("{}.txt", bucket.rule.as_str()));
        bucket.summary_file = Some(candidate);
    }

    let prompt_markdown = build_agent_handoff_prompt(report, Some(bundle_dir));

    Ok(DiagnosticsBundle {
        bundle_dir: bundle_dir.to_path_buf(),
        diagnostics_json_path,
        rule_summary_files,
        migration_buckets,
        prompt_markdown,
    })
}

/// Supported coding agent or output targets for `--handoff` and TUI handoff actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffTarget {
    /// Print the handoff prompt to stdout.
    Print,
    /// Copy the handoff prompt to the system clipboard.
    Clipboard,
    /// Anthropic Claude Code CLI (`claude`).
    Claude,
    /// OpenAI Codex CLI (`codex`).
    Codex,
    /// Cursor Agent CLI (`cursor`).
    Cursor,
    /// Sourcegraph Amp CLI (`amp`).
    Amp,
    /// OpenCode CLI (`opencode`).
    Opencode,
}

impl HandoffTarget {
    /// All coding agent CLI targets in detection priority order.
    pub const AGENT_CLIS: &'static [Self] = &[
        Self::Claude,
        Self::Codex,
        Self::Cursor,
        Self::Amp,
        Self::Opencode,
    ];

    /// Parses a handoff target identifier (`"print"`, `"clipboard"`, `"claude"`, `"codex"`, `"cursor"`, `"amp"`, `"opencode"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "print" | "stdout" => Some(Self::Print),
            "clipboard" | "copy" | "pbcopy" => Some(Self::Clipboard),
            "claude" | "claude-code" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "cursor" | "cursor-agent" => Some(Self::Cursor),
            "amp" => Some(Self::Amp),
            "opencode" | "open-code" => Some(Self::Opencode),
            _ => None,
        }
    }

    /// Canonical kebab-case target name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Print => "print",
            Self::Clipboard => "clipboard",
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Amp => "amp",
            Self::Opencode => "opencode",
        }
    }

    /// Binary name on `PATH` for agent CLI targets (`None` for `Print` and `Clipboard`).
    #[must_use]
    pub const fn binary_name(self) -> Option<&'static str> {
        match self {
            Self::Print | Self::Clipboard => None,
            Self::Claude => Some("claude"),
            Self::Codex => Some("codex"),
            Self::Cursor => Some("cursor"),
            Self::Amp => Some("amp"),
            Self::Opencode => Some("opencode"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct UserPreferencesFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preferred_handoff_target: Option<HandoffTarget>,
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_executable_in_dir(dir: &Path, bin_name: &str) -> Option<PathBuf> {
    let direct = dir.join(bin_name);
    if is_executable_file(&direct) {
        return Some(direct);
    }
    #[cfg(windows)]
    {
        for ext in [".exe", ".cmd", ".bat"] {
            let candidate = dir.join(format!("{bin_name}{ext}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolves the executable binary path for a coding agent [`HandoffTarget`], checking
/// `DOTORE_AGENT_BIN_DIR` when set, or `PATH` otherwise.
#[must_use]
pub fn resolve_agent_binary_path(target: HandoffTarget) -> Option<PathBuf> {
    let bin_name = target.binary_name()?;
    if let Some(custom_dirs) = std::env::var_os("DOTORE_AGENT_BIN_DIR")
        && !custom_dirs.is_empty()
    {
        for dir in std::env::split_paths(&custom_dirs) {
            if let Some(found) = find_executable_in_dir(&dir, bin_name) {
                return Some(found);
            }
        }
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if let Some(found) = find_executable_in_dir(&dir, bin_name) {
            return Some(found);
        }
    }
    None
}

/// Detects which coding agent CLIs (`claude`, `codex`, `cursor`, `amp`, `opencode`) are executable
/// in `DOTORE_AGENT_BIN_DIR` or `PATH`.
#[must_use]
pub fn detect_available_coding_agents() -> Vec<HandoffTarget> {
    HandoffTarget::AGENT_CLIS
        .iter()
        .copied()
        .filter(|&target| resolve_agent_binary_path(target).is_some())
        .collect()
}

/// Loads the user's saved preferred [`HandoffTarget`] from `~/.dotore/preferences.json`.
#[must_use]
pub fn load_preferred_handoff_target() -> Option<HandoffTarget> {
    let prefs_path = resolve_dotore_home_dir()?.join("preferences.json");
    let raw = fs::read_to_string(prefs_path).ok()?;
    let parsed: UserPreferencesFile = serde_json::from_str(&raw).ok()?;
    parsed.preferred_handoff_target
}

/// Saves the user's preferred [`HandoffTarget`] to `~/.dotore/preferences.json`.
///
/// # Errors
/// Returns an `io::Error` if writing the preferences file fails.
pub fn save_preferred_handoff_target(target: HandoffTarget) -> io::Result<()> {
    let Some(home_dir) = resolve_dotore_home_dir() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not resolve ~/.dotore home directory",
        ));
    };
    let prefs_path = home_dir.join("preferences.json");
    let prefs = UserPreferencesFile {
        preferred_handoff_target: Some(target),
    };
    let payload = serde_json::to_string_pretty(&prefs)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_file_atomically(&prefs_path, format!("{payload}\n").as_bytes())
}

fn pipe_stdin_to_command(prog: &str, args: &[&str], text: &str) -> Result<(), String> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn clipboard command '{prog}': {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("Failed to write to clipboard command '{prog}': {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed waiting for clipboard command '{prog}': {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Clipboard command '{prog}' exited with {}: {}",
            output.status,
            stderr.trim()
        ))
    }
}

/// Copies `text` to the system clipboard (or pipes to `DOTORE_CLIPBOARD_CMD` when set).
///
/// # Errors
/// Returns an error message if no clipboard utility is available or the command fails.
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    if let Ok(custom_cmd) = std::env::var("DOTORE_CLIPBOARD_CMD") {
        let trimmed = custom_cmd.trim();
        if !trimmed.is_empty() {
            if Path::new(trimmed).is_file() {
                return pipe_stdin_to_command(trimmed, &[], text);
            }
            #[cfg(windows)]
            {
                return pipe_stdin_to_command("cmd", &["/C", trimmed], text);
            }
            #[cfg(not(windows))]
            {
                return pipe_stdin_to_command("sh", &["-c", trimmed], text);
            }
        }
    }

    let candidates: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("clip", &[]),
        ("clip.exe", &[]),
    ];
    for &(prog, args) in candidates {
        if pipe_stdin_to_command(prog, args, text).is_ok() {
            return Ok(());
        }
    }
    Err(
        "No system clipboard utility available (tried pbcopy, wl-copy, xclip, xsel, clip)"
            .to_string(),
    )
}


/// Executes a handoff of `report` to `target`, writing the diagnostics bundle to `bundle_dir`.
///
/// # Errors
/// Returns an error message if bundle writing, clipboard copy, or agent CLI invocation fails.
pub fn execute_handoff(
    report: &JsonReport,
    target: HandoffTarget,
    bundle_dir: &Path,
) -> Result<String, String> {
    let bundle = write_diagnostics_bundle(report, bundle_dir).map_err(|e| {
        format!(
            "Failed to write diagnostics bundle to {}: {e}",
            bundle_dir.display()
        )
    })?;
    let _ = save_preferred_handoff_target(target);

    match target {
        HandoffTarget::Print => Ok(bundle.prompt_markdown),
        HandoffTarget::Clipboard => {
            copy_to_clipboard(&bundle.prompt_markdown)?;
            Ok(format!(
                "Copied handoff prompt ({} findings, bundle: {}) to clipboard.\n",
                report.diagnostics.len(),
                bundle_dir.display()
            ))
        }
        HandoffTarget::Claude
        | HandoffTarget::Codex
        | HandoffTarget::Cursor
        | HandoffTarget::Amp
        | HandoffTarget::Opencode => launch_agent_cli_handoff(
            target,
            bundle_dir,
            &bundle.prompt_markdown,
            report.diagnostics.len(),
        ),
    }
}

fn launch_agent_cli_handoff(
    target: HandoffTarget,
    bundle_dir: &Path,
    prompt_markdown: &str,
    diagnostic_count: usize,
) -> Result<String, String> {
    let Some(bin_path) = resolve_agent_binary_path(target) else {
        return Err(format!(
            "Coding agent CLI '{}' was not found on PATH",
            target.as_str()
        ));
    };
    let pipe_stdin = std::env::var("DOTORE_AGENT_STDIN")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let mut cmd = Command::new(&bin_path);
    cmd.arg(prompt_markdown)
        .env("DOTORE_BUNDLE_DIR", bundle_dir)
        .stdin(if pipe_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to launch '{}': {e}", bin_path.display()))?;
    if pipe_stdin && let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(prompt_markdown.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed waiting for '{}': {e}", target.as_str()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Coding agent '{}' exited with {}: {}",
            target.as_str(),
            output.status,
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if stdout.trim().is_empty() {
        Ok(format!(
            "Handed off {diagnostic_count} findings to {} (bundle: {}).\n",
            target.as_str(),
            bundle_dir.display()
        ))
    } else {
        Ok(stdout)
    }
}
