//! Location diagnosis (`dotore why <file:line>`), suppression/gate explanation, and code frames.

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{
        CapabilityGate, DotoreConfig, IgnoreConfig, WorkspacePackage,
        discover_workspace_packages_with_analyzers, load_config_from_dir, resolve_package_for_file,
    },
    ir::{
        ArchitectureFileFacets, ExtractedFile, FileContext, LanguageAnalyzer, compute_line_starts,
        loc_from_line_starts,
    },
    planner::{build_fix_capsule, build_root_cause_groups_and_capsules},
    rules::{
        BlastRadius, Diagnostic, FixCapsule, PrescriptionTier, RuleCategory, RuleId, RuleSeverity,
        RuleSeverityOverride, RuleTag, rule_registry,
    },
    scanner::collect_source_files_for_analyzers,
    ui::{AsciiBox, Badge, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH, FlowDiagram},
};

/// Parsed `<file>:<line>` (and optional `:<column>`) argument for `dotore why`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyLocation {
    /// File path component.
    pub file: PathBuf,
    /// 1-based line number.
    pub line: u32,
    /// Optional 1-based column number.
    pub column: Option<u32>,
}

/// Single diagnostic or suppression/gate explanation produced by `dotore why <file:line>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhyEntry {
    /// Status of the finding at this location (`"active"`, `"suppressed"`, `"disabled"`, or `"gated"`).
    pub status: String,
    /// Qualified rule key (`"dotore/no-derived-state"`).
    pub rule: String,
    /// Rule category.
    pub category: RuleCategory,
    /// Severity (`error` or `warning`).
    pub severity: RuleSeverity,
    /// **Prescription Tier** (`autofix`, `surgical`, `refactor`).
    pub tier: PrescriptionTier,
    /// Diagnostic message.
    pub message: String,
    /// Human-readable explanation of why the diagnostic fired or why a suppression/config/Capability Gate applied or did not apply.
    pub explanation: String,
    /// Numbered source code frame around the target line.
    pub code_frame: String,
    /// **Render Cascade** steps, if any.
    pub cascade_steps: Vec<String>,
    /// Static **Blast Radius** score and priority tier.
    pub blast_radius: BlastRadius,
    /// Complete self-contained **Fix Capsule** for this finding.
    pub fix_capsule: FixCapsule,
}

/// Complete report returned by [`explain_location`] (`dotore why <file:line>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhyReport {
    /// Requested file path.
    pub file: PathBuf,
    /// Requested 1-based line number.
    pub line: u32,
    /// Optional requested 1-based column number.
    pub column: Option<u32>,
    /// Matched active, suppressed, disabled, or capability-gated findings at `<file:line>`.
    pub entries: Vec<WhyEntry>,
    /// High-level summary note when no entries matched or when explaining line status.
    pub summary_note: String,
}

/// Parses a `<file:line>` or `<file:line:column>` CLI location string.
///
/// # Errors
/// Returns an error message if `input` does not contain a valid `<file>:<line>` pair.
pub fn parse_why_location(input: &str) -> Result<WhyLocation, String> {
    let trimmed = input.trim();
    let Some((prefix1, last_seg)) = trimmed.rsplit_once(':') else {
        return Err(format!(
            "Invalid location {input:?}; expected `<file:line>` or `<file:line:column>`."
        ));
    };
    let Ok(last_num) = last_seg.parse::<u32>() else {
        return Err(format!(
            "Invalid line number in {input:?}; expected `<file:line>`."
        ));
    };
    if last_num == 0 || prefix1.is_empty() {
        return Err(format!(
            "Invalid location {input:?}; line number must be >= 1."
        ));
    }

    if let Some((file_part, mid_seg)) = prefix1.rsplit_once(':')
        && !file_part.is_empty()
        && let Ok(line_num) = mid_seg.parse::<u32>()
        && line_num >= 1
    {
        return Ok(WhyLocation {
            file: PathBuf::from(file_part),
            line: line_num,
            column: Some(last_num),
        });
    }

    Ok(WhyLocation {
        file: PathBuf::from(prefix1),
        line: last_num,
        column: None,
    })
}

/// Explains why a diagnostic fired (or why a rule, inline suppression, config, or **Capability Gate**
/// did or did not apply) at `location_arg` (`<file:line>`) under `cwd`, including its complete [`FixCapsule`].
///
/// # Errors
/// Returns an error string if `location_arg` is malformed or the target file cannot be read.
pub fn explain_location(location_arg: &str, cwd: &Path) -> Result<WhyReport, String> {
    explain_location_with_analyzers(location_arg, cwd, &[])
}

/// Explains `<file:line>` under `cwd` using the provided [`LanguageAnalyzer`]s.
///
/// # Errors
/// Returns an error string if `location_arg` is malformed or the target file cannot be read.
pub fn explain_location_with_analyzers(
    location_arg: &str,
    cwd: &Path,
    analyzers: &[&dyn LanguageAnalyzer],
) -> Result<WhyReport, String> {
    let parsed_loc = parse_why_location(location_arg)?;
    let resolved_file = resolve_why_target_file(&parsed_loc.file, cwd)?;
    let Some(&analyzer) = analyzers.iter().find(|a| a.supports_path(&resolved_file)) else {
        return Err(format!(
            "No registered LanguageAnalyzer supports `{}`.",
            resolved_file.display()
        ));
    };

    let packages = discover_workspace_packages_with_analyzers(cwd, analyzers);
    let default_pkg;
    let pkg = if let Some(found) = resolve_package_for_file(&resolved_file, &packages) {
        found
    } else {
        default_pkg = WorkspacePackage {
            name: "root".to_string(),
            root_dir: cwd.to_path_buf(),
            capability_gate: analyzer.infer_capability_gate(cwd, &[]),
            config: load_config_from_dir(cwd),
        };
        &default_pkg
    };

    let (extracted_files, sources) =
        extract_package_files_for_why(analyzer, pkg, &packages, &resolved_file);
    let Some(target_extracted) = extracted_files.iter().find(|f| f.path == resolved_file) else {
        return Err(format!(
            "Failed to parse target file `{}`.",
            resolved_file.display()
        ));
    };
    let target_source = sources.get(&resolved_file).cloned().unwrap_or_default();
    let line_starts = compute_line_starts(&target_source);

    let active_at_line = collect_matching_diagnostics(
        analyzer.analyze_package(pkg, &extracted_files, None).diagnostics,
        &resolved_file,
        &line_starts,
        parsed_loc.line,
    );
    let entries = if !active_at_line.is_empty() {
        build_active_why_entries(
            &parsed_loc.file,
            target_extracted,
            &target_source,
            &extracted_files,
            &active_at_line,
            &sources,
        )
    } else {
        let all_rules: Vec<RuleId> = rule_registry().iter().map(|m| m.id).collect();
        let permissive_pkg = build_permissive_probe_package(pkg);
        let probe_at_line = collect_matching_diagnostics(
            analyzer
                .analyze_package(&permissive_pkg, &extracted_files, Some(&all_rules))
                .diagnostics,
            &resolved_file,
            &line_starts,
            parsed_loc.line,
        );
        build_inactive_why_entries(
            pkg,
            target_extracted,
            &target_source,
            &extracted_files,
            &probe_at_line,
            &sources,
        )
    };
    let summary_note = build_why_summary_note(&parsed_loc, target_extracted, entries.len());

    Ok(WhyReport {
        file: parsed_loc.file,
        line: parsed_loc.line,
        column: parsed_loc.column,
        entries,
        summary_note,
    })
}

fn resolve_why_target_file(file: &Path, cwd: &Path) -> Result<PathBuf, String> {
    let resolved = if file.is_absolute() {
        file.to_path_buf()
    } else {
        cwd.join(file)
    };
    if !resolved.is_file() {
        return Err(format!("Target file `{}` does not exist.", resolved.display()));
    }
    Ok(resolved)
}

fn extract_package_files_for_why(
    analyzer: &dyn LanguageAnalyzer,
    pkg: &WorkspacePackage,
    packages: &[WorkspacePackage],
    resolved_file: &Path,
) -> (Vec<ExtractedFile>, HashMap<PathBuf, String>) {
    let mut discovered =
        collect_source_files_for_analyzers(std::slice::from_ref(&pkg.root_dir), true, &[analyzer]);
    if !discovered.iter().any(|p| p == resolved_file) {
        discovered.push(resolved_file.to_path_buf());
    }
    let mut sources = HashMap::new();
    let mut extracted = Vec::new();
    for path in discovered {
        if path != resolved_file
            && resolve_package_for_file(&path, packages)
                .is_some_and(|resolved| resolved.root_dir != pkg.root_dir)
        {
            continue;
        }
        if let Ok(src) = fs::read_to_string(&path) {
            extracted.push(analyzer.extract_file(&path, &src));
            sources.insert(path, src);
        }
    }
    (extracted, sources)
}

fn build_permissive_probe_package(pkg: &WorkspacePackage) -> WorkspacePackage {
    let mut permissive_cfg = pkg.config.clone();
    permissive_cfg.respect_inline_disables = false;
    permissive_cfg.custom_rules_only = false;
    permissive_cfg.warnings = true;
    permissive_cfg.rules.clear();
    permissive_cfg.categories.clear();
    permissive_cfg.ignore = IgnoreConfig::default();
    let mut permissive_gate = pkg.capability_gate.clone();
    permissive_gate.merge(&CapabilityGate::default_react());
    permissive_gate.merge(&CapabilityGate::default_angular());
    permissive_gate.merge(&CapabilityGate::default_python());
    permissive_gate.merge(&CapabilityGate::default_rust());
    WorkspacePackage {
        name: pkg.name.clone(),
        root_dir: pkg.root_dir.clone(),
        capability_gate: permissive_gate,
        config: permissive_cfg,
    }
}

fn collect_matching_diagnostics(
    diags: Vec<Diagnostic>,
    resolved_file: &Path,
    line_starts: &[u32],
    target_line: u32,
) -> Vec<Diagnostic> {
    diags
        .into_iter()
        .filter(|d| {
            d.file == resolved_file && diagnostic_matches_extracted_line(d, line_starts, target_line)
        })
        .collect()
}

fn build_active_why_entries(
    display_file: &Path,
    target_extracted: &ExtractedFile,
    target_source: &str,
    extracted_files: &[ExtractedFile],
    active_at_line: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Vec<WhyEntry> {
    let (groups, _) =
        build_root_cause_groups_and_capsules(extracted_files, active_at_line, sources);
    let mut entries = Vec::new();
    for (idx, diag) in active_at_line.iter().enumerate() {
        let Some(group) = groups
            .iter()
            .find(|g| g.diagnostic_indices.contains(&idx))
            .or_else(|| groups.first())
        else {
            continue;
        };
        let explanation = format!(
            "Diagnostic `{}` fired at {}:{} because `{}` triggered rule `{}`.",
            diag.rule.metadata().qualified_key,
            display_file.display(),
            diag.loc.line,
            diag.target_name,
            diag.rule.as_str()
        );
        entries.push(build_why_entry(
            "active".to_string(),
            explanation,
            diag,
            target_extracted,
            target_source,
            group,
            build_fix_capsule(extracted_files, group, active_at_line, sources),
        ));
    }
    entries
}

fn build_inactive_why_entries(
    pkg: &WorkspacePackage,
    target_extracted: &ExtractedFile,
    target_source: &str,
    extracted_files: &[ExtractedFile],
    probe_at_line: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Vec<WhyEntry> {
    if probe_at_line.is_empty() {
        return Vec::new();
    }
    let (groups, _) = build_root_cause_groups_and_capsules(extracted_files, probe_at_line, sources);
    let mut entries = Vec::new();
    for (idx, diag) in probe_at_line.iter().enumerate() {
        let Some(group) = groups
            .iter()
            .find(|g| g.diagnostic_indices.contains(&idx))
            .or_else(|| groups.first())
        else {
            continue;
        };
        let is_suppressed = pkg.config.respect_inline_disables
            && (target_extracted.is_suppressed(diag.rule, diag.loc.line, diag.span)
                || target_extracted
                    .suppressions
                    .matches_line_or_block(diag.rule, diag.loc.line));
        let (status, explanation) = diagnose_why_not_active_common(
            diag,
            &target_extracted.path,
            target_extracted.file_context,
            is_suppressed,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
        );
        entries.push(build_why_entry(
            status,
            explanation,
            diag,
            target_extracted,
            target_source,
            group,
            build_fix_capsule(extracted_files, group, probe_at_line, sources),
        ));
    }
    entries
}

fn build_why_entry(
    status: String,
    mut explanation: String,
    diag: &Diagnostic,
    target_extracted: &ExtractedFile,
    target_source: &str,
    group: &crate::rules::RootCauseGroup,
    fix_capsule: crate::rules::FixCapsule,
) -> WhyEntry {
    if diag.rule.is_architecture_soc_or_reuse_rule()
        && let Some(arch_exp) = format_architecture_signal_explanation(
            diag,
            Some(&target_extracted.architecture_facets),
        )
    {
        let _ = write!(explanation, " Structural signals: {arch_exp}");
    }
    WhyEntry {
        status,
        rule: diag.rule.metadata().qualified_key.to_string(),
        category: diag.category,
        severity: diag.severity,
        tier: diag.tier,
        message: super::mask_credentials(&diag.message),
        explanation,
        code_frame: render_code_frame(target_source, diag.loc.line),
        cascade_steps: architecture_or_existing_cascade_steps(
            diag,
            Some(&target_extracted.architecture_facets),
        ),
        blast_radius: group.blast_radius.clone(),
        fix_capsule,
    }
}

fn build_why_summary_note(
    parsed_loc: &WhyLocation,
    target_extracted: &ExtractedFile,
    entry_count: usize,
) -> String {
    if entry_count > 0 {
        format!(
            "{entry_count} finding(s) explained at {}:{}.",
            parsed_loc.file.display(),
            parsed_loc.line
        )
    } else if let Some(unused_dir) = target_extracted
        .suppressions
        .line_directives
        .iter()
        .find(|d| d.target_line == parsed_loc.line || d.target_line == parsed_loc.line + 1)
    {
        format!(
            "No diagnostic fired at {}:{}; inline suppression comment (rules: {:?}) had no matching finding to suppress.",
            parsed_loc.file.display(),
            parsed_loc.line,
            unused_dir.rules
        )
    } else {
        format!(
            "No diagnostics fired (and no suppressed or gated rules matched) at {}:{}.",
            parsed_loc.file.display(),
            parsed_loc.line
        )
    }
}

/// Formats a [`WhyReport`] (`dotore why <file:line>`) for terminal output.
#[must_use]
pub fn format_why_report_text(report: &WhyReport) -> String {
    let mut out = String::new();
    if report.entries.is_empty() {
        let _ = writeln!(out, "{}", report.summary_note);
        return out;
    }

    let mode = ColorMode::Plain;
    for entry in &report.entries {
        let sev_badge = Badge::severity(entry.severity).render(mode);
        let tier_badge = Badge::tier(entry.tier).render(mode);
        let br_badge = Badge::blast_radius(entry.blast_radius.tier).render(mode);
        let mut entry_box =
            AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH).with_title(format!(
                "[{}] {} ({} {}, tier: {}, category: {})",
                entry.status,
                entry.rule,
                sev_badge,
                entry.severity.as_str(),
                tier_badge,
                entry.category.as_str()
            ));
        entry_box.add_open_row(format!("  Message:     {}", entry.message));
        entry_box.add_open_row(format!("  Explanation: {}", entry.explanation));
        entry_box.add_open_row(format!(
            "  Blast Radius: {br_badge} (score: {}, frequency: {}, fan-out: {}, cascade depth: {})",
            entry.blast_radius.score,
            entry.blast_radius.render_frequency.as_str(),
            entry.blast_radius.fan_out,
            entry.blast_radius.cascade_depth
        ));
        if !entry.cascade_steps.is_empty() {
            let flow = FlowDiagram::new(&entry.cascade_steps);
            entry_box.add_open_row(format!("  Cascade:     {}", flow.render_arrow_chain()));
            entry_box.add_open_row(format!("  Flow:        {}", flow.render(mode)));
        }
        if !entry.code_frame.is_empty() {
            entry_box.add_titled_divider("Code Frame");
            for line in entry.code_frame.lines() {
                entry_box.add_open_row(format!("    {line}"));
            }
        }
        append_fix_capsule_rows(&mut entry_box, &entry.fix_capsule);
        out.push_str(&entry_box.render(mode));
        let _ = writeln!(out);
    }
    out
}

fn append_fix_capsule_rows(entry_box: &mut AsciiBox, capsule: &crate::rules::FixCapsule) {
    entry_box.add_titled_divider(format!("Fix Capsule ({})", capsule.root_cause_group_id));
    entry_box.add_open_row(format!(
        "    Subject Excerpt ({}:{}-{}):",
        capsule.subject_excerpt.file.display(),
        capsule.subject_excerpt.start_line,
        capsule.subject_excerpt.end_line
    ));
    for line in capsule.subject_excerpt.source.lines() {
        entry_box.add_open_row(format!("      {line}"));
    }
    if !capsule.caller_site_excerpts.is_empty() {
        entry_box.add_open_row("    Caller Site Excerpts:");
        for caller in &capsule.caller_site_excerpts {
            entry_box.add_open_row(format!(
                "      {}:{}-{}: {}",
                caller.file.display(),
                caller.start_line,
                caller.end_line,
                caller.source.trim()
            ));
        }
    }
    entry_box.add_open_row("    Recipe:");
    for line in capsule.recipe_markdown.lines() {
        entry_box.add_open_row(format!("      {line}"));
    }
    if !capsule.invariants.is_empty() {
        entry_box.add_open_row(format!("    Invariants: {}", capsule.invariants.join("; ")));
    }
    if let Some(ex) = &capsule.exemplar {
        entry_box.add_open_row(format!(
            "    Repository Exemplar ({}:{}-{}):",
            ex.file.display(),
            ex.start_line,
            ex.end_line
        ));
        for line in ex.source.lines() {
            entry_box.add_open_row(format!("      {line}"));
        }
    }
}

fn diagnostic_matches_extracted_line(
    diag: &Diagnostic,
    line_starts: &[u32],
    target_line: u32,
) -> bool {
    if diag.loc.line == target_line {
        return true;
    }
    let start_line = loc_from_line_starts(line_starts, diag.span.start).line;
    let end_line = loc_from_line_starts(line_starts, diag.span.end.saturating_sub(1)).line;
    start_line <= target_line && target_line <= end_line
}

/// Diagnoses why `diag` was suppressed, disabled, or capability-gated.
#[must_use]
pub fn diagnose_why_not_active_common(
    diag: &Diagnostic,
    file_path: &Path,
    file_context: FileContext,
    is_inline_suppressed: bool,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
) -> (String, String) {
    let meta = diag.rule.metadata();

    if is_inline_suppressed {
        return (
            "suppressed".to_string(),
            format!(
                "Rule `{}` matched at line {}, but was suppressed by an inline disable comment (`// dotore-disable-next-line` or block directive).",
                meta.qualified_key, diag.loc.line
            ),
        );
    }

    if config.is_file_ignored(file_path, package_root) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` was skipped because `{}` matches `ignore.files` in configuration.",
                meta.qualified_key,
                file_path.display()
            ),
        );
    }

    if file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && config.explicit_rule_override(diag.rule).is_none()
    {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` carries the `test-noise` tag and is automatically suppressed in {:?} files.",
                meta.qualified_key, file_context
            ),
        );
    }

    if meta.capability_gate.app_only
        && gate.is_library_entrypoint(file_path, package_root)
        && config.explicit_rule_override(diag.rule).is_none()
    {
        return (
            "gated".to_string(),
            format!(
                "Rule `{}` is application-only and is skipped on library package entrypoints.",
                meta.qualified_key
            ),
        );
    }

    if config.is_overridden_for_file(diag.rule, file_path, package_root) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is suppressed for `{}` by `ignore.overrides` in configuration.",
                meta.qualified_key,
                file_path.display()
            ),
        );
    }

    if !gate.allows_rule(meta) {
        let req: Vec<&str> = meta
            .capability_gate
            .requires
            .iter()
            .map(|c| c.as_str())
            .collect();
        let dis: Vec<&str> = meta
            .capability_gate
            .disabled_when
            .iter()
            .map(|c| c.as_str())
            .collect();
        return (
            "gated".to_string(),
            format!(
                "Rule `{}` was gated off by the package's Capability Gate (requires: [{}], disabled_when: [{}]).",
                meta.qualified_key,
                req.join(", "),
                dis.join(", ")
            ),
        );
    }

    diagnose_config_rule_disable(diag.rule, meta, config)
}

fn diagnose_config_rule_disable(
    rule: RuleId,
    meta: & crate::rules::RuleMetadata,
    config: &DotoreConfig,
) -> (String, String) {
    if let Some(&ignored_tag) = meta.tags.iter().find(|&&t| config.is_tag_ignored(t)) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled because tag `{}` is listed in `ignore.tags`.",
                meta.qualified_key,
                ignored_tag.as_str()
            ),
        );
    }
    if config
        .ignore
        .rules
        .iter()
        .any(|r| RuleId::parse(r) == Some(rule))
    {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled via `ignore.rules` in configuration.",
                meta.qualified_key
            ),
        );
    }
    if config.explicit_rule_override(rule) == Some(RuleSeverityOverride::Off) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is explicitly set to `\"off\"` in `rules` configuration.",
                meta.qualified_key
            ),
        );
    }
    if config.category_override(meta.category) == Some(RuleSeverityOverride::Off) {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is disabled because category `{}` is set to `\"off\"` in configuration.",
                meta.qualified_key,
                meta.category.as_str()
            ),
        );
    }
    if !meta.default_enabled {
        return (
            "disabled".to_string(),
            format!(
                "Rule `{}` is opt-in (`default_enabled: false`) and is not enabled in configuration.",
                meta.qualified_key
            ),
        );
    }
    (
        "disabled".to_string(),
        format!(
            "Rule `{}` is disabled by the current configuration.",
            meta.qualified_key
        ),
    )
}

/// Renders a 5-line numbered source code frame centered on `target_line`.
#[must_use]
pub fn render_code_frame(source: &str, target_line: u32) -> String {
    let redacted = super::mask_credentials(source);
    let lines: Vec<&str> = redacted.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = (target_line.saturating_sub(1) as usize).min(lines.len().saturating_sub(1));
    let start = idx.saturating_sub(2);
    let end = (idx + 2).min(lines.len().saturating_sub(1));
    let mut out = String::new();
    for (i, line_text) in lines.iter().enumerate().take(end + 1).skip(start) {
        let line_no = i + 1;
        let marker = if line_no == target_line as usize {
            ">"
        } else {
            " "
        };
        let _ = writeln!(out, "{marker} {line_no:>4} | {line_text}");
    }
    out.trim_end().to_string()
}

/// Formats the multi-signal structural evidence explaining why an architectural, Separation of
/// Concerns, or reuse [`Diagnostic`] fired, using the file's [`ArchitectureFileFacets`] when available.
#[must_use]
pub fn format_architecture_signal_explanation(
    diag: &Diagnostic,
    facets: Option<&ArchitectureFileFacets>,
) -> Option<String> {
    let facets_summary = facets.and_then(ArchitectureFileFacets::explain_signals_summary);
    if !diag.rule.is_architecture_soc_or_reuse_rule() && facets_summary.is_none() {
        return None;
    }

    let mut segments = Vec::new();
    if let Some(summary) = facets_summary {
        segments.push(summary);
    }
    if !diag.cascade_steps.is_empty() {
        segments.push(format!("signals=[{}]", diag.cascade_steps.join(" -> ")));
    }
    if !diag.caller_sites.is_empty() {
        let peers: Vec<String> = diag
            .caller_sites
            .iter()
            .take(4)
            .map(|c| format!("{}:{}", c.caller_file.display(), c.loc.line))
            .collect();
        segments.push(format!("peer_sites=[{}]", peers.join(", ")));
    }
    if segments.is_empty() {
        segments.push(format!(
            "rule={} target={}",
            diag.rule.as_str(),
            diag.target_name
        ));
    }
    Some(segments.join("; "))
}

fn architecture_or_existing_cascade_steps(
    diag: &Diagnostic,
    facets: Option<&ArchitectureFileFacets>,
) -> Vec<String> {
    if !diag.cascade_steps.is_empty() {
        return diag.cascade_steps.clone();
    }
    if !diag.rule.is_architecture_soc_or_reuse_rule() {
        return Vec::new();
    }
    let Some(facets) = facets else {
        return Vec::new();
    };
    let mut steps = Vec::with_capacity(
        facets.concern_signals.len()
            + facets.static_catalog_sites.len()
            + facets.inline_terminal_ui_sites.len()
            + facets.struct_literal_sites.len()
            + facets.helper_fingerprints.len(),
    );
    for sig in &facets.concern_signals {
        let step = format!("{}: {}", sig.bucket.as_str(), sig.detail);
        if !steps.contains(&step) {
            steps.push(step);
        }
    }
    for cat in &facets.static_catalog_sites {
        steps.push(format!(
            "static-catalog {}: {} entries ({}B)",
            cat.name, cat.entry_count, cat.byte_len
        ));
    }
    for ui in &facets.inline_terminal_ui_sites {
        steps.push(format!("inline-ui {}: {}", ui.kind, ui.snippet));
    }
    for lit in &facets.struct_literal_sites {
        steps.push(format!(
            "struct-literal {}: {} fields",
            lit.type_name,
            lit.field_names.len()
        ));
    }
    for helper in &facets.helper_fingerprints {
        steps.push(format!(
            "helper {}: hash=0x{:08x} ({} stmts)",
            helper.name, helper.normalized_hash, helper.statement_count
        ));
    }
    if steps.is_empty()
        && let Some(arch_exp) = format_architecture_signal_explanation(diag, Some(facets))
    {
        steps.push(arch_exp);
    }
    steps
}
