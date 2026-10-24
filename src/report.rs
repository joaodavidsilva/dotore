//! Terminal, JSON, and self-contained HTML cascade reporters for `dotore`.

use std::path::Path;
#[cfg(feature = "js")]
use std::{collections::HashMap, fs, path::PathBuf};

pub use dotore_core::report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, MAX_SCAN_CACHE_ENTRIES, PR_COMMENT_MARKER,
    PrCommentEnv, PrCommentRepoContext, ProjectCoverageMetadata, ReportSummary, RuleCatalogEntry,
    RulesListOptions, SCAN_CACHE_SCHEMA_VERSION, ScanCacheEntry, ScanResultCacheFile, WhyEntry,
    WhyLocation, WhyReport, build_extracted_report, build_extracted_report_with_packages,
    build_rule_catalog, ci_config, ci_install, ci_upgrade, explain_location_with_analyzers,
    explain_rule, format_architecture_signal_explanation, format_design_report,
    format_design_report_pretty, format_fix_report, format_install_report,
    format_rule_catalog_text, format_rule_explanation_text, format_terminal_report,
    format_terminal_report_pretty, format_why_report_text, generate_ci_comment, install_dotore,
    load_scan_result_cache, lookup_scan_cache, parse_why_location, read_json_report,
    render_ci_workflow, render_github_actions_workflow, render_github_pr_comment,
    render_github_pr_comment_from_env, render_gitlab_ci_snippet, render_html_report,
    render_pr_comment_markdown, render_pr_comment_markdown_with_env, resolve_scan_cache_path,
    store_scan_cache, write_and_open_html_report, write_github_pr_comment, write_json_report,
};
#[cfg(feature = "js")]
use dotore_core::report::{
    build_report_from_planner_context, diagnose_why_not_active_common, render_code_frame,
};
#[cfg(feature = "js")]
use dotore_core::{
    config::{
        CapabilityGate, IgnoreConfig, WorkspacePackage, discover_workspace_packages_with_analyzers,
        load_config_from_dir, resolve_package_for_file,
    },
    ir::{
        ExtractedFile, LanguageAnalyzer, SubjectEffectOwner, compute_line_starts,
        loc_from_line_starts,
    },
    planner::{build_fix_capsule, build_root_cause_groups_and_capsules},
    rules::{Diagnostic, RuleId, rule_registry},
    scanner::{collect_source_files_for_analyzers, collect_style_files},
};
#[cfg(feature = "js")]
use dotore_js::{
    FileIr, JsLanguageAnalyzer, ProjectGraph, enrich_cross_file_autofixes,
    evaluate_file_in_package, evaluate_project_graph_rules, evaluate_project_reduced_motion,
};

#[cfg(feature = "js")]
use crate::load_disk_manifests;

/// Builds a [`JsonReport`] from a [`ProjectGraph`], its evaluated [`Diagnostic`]s, and file sources.
#[cfg(feature = "js")]
#[must_use]
pub fn build_report(
    graph: &ProjectGraph,
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
) -> JsonReport {
    build_report_with_packages(graph, diagnostics, sources, &[])
}

/// Builds a [`JsonReport`] including per-project coverage metadata for discovered [`WorkspacePackage`]s.
#[cfg(feature = "js")]
#[must_use]
pub fn build_report_with_packages(
    graph: &ProjectGraph,
    mut diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
    packages: &[WorkspacePackage],
) -> JsonReport {
    enrich_cross_file_autofixes(graph, &mut diagnostics, sources);

    let file_subject_counts: Vec<(PathBuf, usize)> = graph
        .files
        .iter()
        .map(|f| (f.path.clone(), f.subjects.len()))
        .collect();
    let effects_scanned: usize = graph
        .files
        .iter()
        .flat_map(|f| &f.subjects)
        .map(|s| s.effect_nodes.len())
        .sum();

    build_report_from_planner_context(
        graph,
        &file_subject_counts,
        effects_scanned,
        diagnostics,
        sources,
        packages,
    )
}

/// Explains why a diagnostic fired (or why a rule, inline suppression, config, or **Capability Gate**
/// did or did not apply) at `location_arg` (`<file:line>`) under `cwd`, including its complete [`crate::FixCapsule`].
///
/// # Errors
/// Returns an error string if `location_arg` is malformed or the target file cannot be read.
pub fn explain_location(location_arg: &str, cwd: &Path) -> Result<WhyReport, String> {
    crate::register_active_core_hooks();
    let parsed_loc = parse_why_location(location_arg)?;
    let resolved_file = if parsed_loc.file.is_absolute() {
        parsed_loc.file.clone()
    } else {
        cwd.join(&parsed_loc.file)
    };
    if !resolved_file.is_file() {
        return Err(format!(
            "Target file `{}` does not exist.",
            resolved_file.display()
        ));
    }

    #[cfg(feature = "js")]
    {
        let js_analyzer = JsLanguageAnalyzer;
        let is_js_or_style = js_analyzer.supports_path(&resolved_file)
            || matches!(
                resolved_file.extension().and_then(|e| e.to_str()),
                Some("css" | "scss" | "html" | "htm")
            );
        if is_js_or_style {
            return explain_js_location(&parsed_loc, &resolved_file, cwd);
        }
    }

    explain_location_with_analyzers(location_arg, cwd, crate::default_analyzers())
}

#[cfg(feature = "js")]
fn explain_js_location(
    parsed_loc: &WhyLocation,
    resolved_file: &Path,
    cwd: &Path,
) -> Result<WhyReport, String> {
    let resolved_file = resolved_file.to_path_buf();
    let js_analyzer = JsLanguageAnalyzer;
    let js_only: &[&dyn LanguageAnalyzer] = &[&js_analyzer];
    let packages = discover_workspace_packages_with_analyzers(cwd, crate::default_analyzers());
    let mut discovered_files =
        collect_source_files_for_analyzers(&[cwd.to_path_buf()], true, js_only);
    for style_path in collect_style_files(&[cwd.to_path_buf()]) {
        if !discovered_files.contains(&style_path) {
            discovered_files.push(style_path);
        }
    }
    if !discovered_files.contains(&resolved_file) {
        discovered_files.push(resolved_file.clone());
    }

    let mut sources: HashMap<PathBuf, String> = HashMap::new();
    let mut extracted_files: Vec<ExtractedFile> = Vec::new();
    for path in discovered_files {
        if let Ok(src) = fs::read_to_string(&path) {
            extracted_files.push(js_analyzer.extract_file(&path, &src));
            sources.insert(path, src);
        }
    }

    let manifests = load_disk_manifests(cwd, &packages, &sources);
    let graph = js_analyzer.build_graph_from_extracted(&extracted_files, manifests);
    let Some(target_file_ir) = graph.files.iter().find(|f| f.path == resolved_file) else {
        return Err(format!(
            "Failed to parse target file `{}`.",
            resolved_file.display()
        ));
    };
    let target_source = sources.get(&resolved_file).cloned().unwrap_or_default();
    let line_starts = compute_line_starts(&target_source);

    let default_pkg;
    let pkg = if let Some(found) = resolve_package_for_file(&resolved_file, &packages) {
        found
    } else {
        default_pkg = WorkspacePackage {
            name: "root".to_string(),
            root_dir: cwd.to_path_buf(),
            capability_gate: CapabilityGate::discover(cwd),
            config: load_config_from_dir(cwd),
        };
        &default_pkg
    };

    let mut active_diags = Vec::new();
    evaluate_file_in_package(
        &graph,
        target_file_ir,
        &pkg.root_dir,
        &pkg.capability_gate,
        &pkg.config,
        None,
        &mut active_diags,
    );
    let active_pkgs = if packages.is_empty() {
        vec![pkg.clone()]
    } else {
        packages.clone()
    };
    let mut active_graph_diags = Vec::new();
    evaluate_project_graph_rules(&graph, &active_pkgs, None, &mut active_graph_diags);
    evaluate_project_reduced_motion(&graph, &active_pkgs, None, &mut active_graph_diags);
    active_diags.extend(
        active_graph_diags
            .into_iter()
            .filter(|d| d.file == resolved_file),
    );
    enrich_cross_file_autofixes(&graph, &mut active_diags, &sources);

    let all_rules: Vec<RuleId> = rule_registry().iter().map(|m| m.id).collect();
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
    let mut probe_diags = Vec::new();
    evaluate_file_in_package(
        &graph,
        target_file_ir,
        &pkg.root_dir,
        &permissive_gate,
        &permissive_cfg,
        Some(&all_rules),
        &mut probe_diags,
    );
    let permissive_pkg = WorkspacePackage {
        name: pkg.name.clone(),
        root_dir: pkg.root_dir.clone(),
        capability_gate: permissive_gate,
        config: permissive_cfg,
    };
    let mut probe_graph_diags = Vec::new();
    evaluate_project_graph_rules(
        &graph,
        std::slice::from_ref(&permissive_pkg),
        Some(&all_rules),
        &mut probe_graph_diags,
    );
    evaluate_project_reduced_motion(
        &graph,
        std::slice::from_ref(&permissive_pkg),
        Some(&all_rules),
        &mut probe_graph_diags,
    );
    probe_diags.extend(
        probe_graph_diags
            .into_iter()
            .filter(|d| d.file == resolved_file),
    );
    enrich_cross_file_autofixes(&graph, &mut probe_diags, &sources);

    let active_at_line: Vec<Diagnostic> = active_diags
        .into_iter()
        .filter(|d| diagnostic_matches_line(target_file_ir, d, &line_starts, parsed_loc.line))
        .collect();

    let mut entries = Vec::new();
    if !active_at_line.is_empty() {
        let (groups, _) = build_root_cause_groups_and_capsules(&graph, &active_at_line, &sources);
        for (idx, diag) in active_at_line.iter().enumerate() {
            let group = groups
                .iter()
                .find(|g| g.diagnostic_indices.contains(&idx))
                .unwrap_or(&groups[0]);
            let capsule = build_fix_capsule(&graph, group, &active_at_line, &sources);
            let mismatch_note = detect_mismatched_inline_suppression(target_file_ir, diag);
            let mut explanation = if let Some(note) = mismatch_note {
                format!(
                    "Diagnostic `{}` fired at {}:{}. {note}",
                    diag.rule.metadata().qualified_key,
                    parsed_loc.file.display(),
                    diag.loc.line
                )
            } else {
                format!(
                    "Diagnostic `{}` fired at {}:{} because `{}` triggered rule `{}`.",
                    diag.rule.metadata().qualified_key,
                    parsed_loc.file.display(),
                    diag.loc.line,
                    diag.target_name,
                    diag.rule.as_str()
                )
            };
            let mut cascade_steps = diag.cascade_steps.clone();
            append_js_architecture_signals(
                target_file_ir,
                diag,
                &mut explanation,
                &mut cascade_steps,
            );
            entries.push(WhyEntry {
                status: "active".to_string(),
                rule: diag.rule.metadata().qualified_key.to_string(),
                category: diag.category,
                severity: diag.severity,
                tier: diag.tier,
                message: diag.message.clone(),
                explanation,
                code_frame: render_code_frame(&target_source, diag.loc.line),
                cascade_steps,
                blast_radius: group.blast_radius.clone(),
                fix_capsule: capsule,
            });
        }
    } else {
        let probe_at_line: Vec<Diagnostic> = probe_diags
            .into_iter()
            .filter(|d| diagnostic_matches_line(target_file_ir, d, &line_starts, parsed_loc.line))
            .collect();
        if !probe_at_line.is_empty() {
            let (groups, _) =
                build_root_cause_groups_and_capsules(&graph, &probe_at_line, &sources);
            for (idx, diag) in probe_at_line.iter().enumerate() {
                let group = groups
                    .iter()
                    .find(|g| g.diagnostic_indices.contains(&idx))
                    .unwrap_or(&groups[0]);
                let capsule = build_fix_capsule(&graph, group, &probe_at_line, &sources);
                let is_suppressed = pkg.config.respect_inline_disables
                    && target_file_ir.suppressions.is_suppressed(
                        diag.rule,
                        diag.loc.line,
                        diag.span,
                        &target_file_ir.jsx_elements,
                        &target_file_ir.subjects,
                    );
                let (status, mut explanation) = diagnose_why_not_active_common(
                    diag,
                    &target_file_ir.path,
                    target_file_ir.file_context,
                    is_suppressed,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
                );
                let mut cascade_steps = diag.cascade_steps.clone();
                append_js_architecture_signals(
                    target_file_ir,
                    diag,
                    &mut explanation,
                    &mut cascade_steps,
                );
                entries.push(WhyEntry {
                    status,
                    rule: diag.rule.metadata().qualified_key.to_string(),
                    category: diag.category,
                    severity: diag.severity,
                    tier: diag.tier,
                    message: diag.message.clone(),
                    explanation,
                    code_frame: render_code_frame(&target_source, diag.loc.line),
                    cascade_steps,
                    blast_radius: group.blast_radius.clone(),
                    fix_capsule: capsule,
                });
            }
        }
    }

    let summary_note = if !entries.is_empty() {
        format!(
            "{} finding(s) explained at {}:{}.",
            entries.len(),
            parsed_loc.file.display(),
            parsed_loc.line
        )
    } else if let Some(unused_dir) = target_file_ir
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
    };

    Ok(WhyReport {
        file: parsed_loc.file.clone(),
        line: parsed_loc.line,
        column: parsed_loc.column,
        entries,
        summary_note,
    })
}

#[cfg(feature = "js")]
fn diagnostic_matches_line(
    file_ir: &FileIr,
    diag: &Diagnostic,
    line_starts: &[u32],
    target_line: u32,
) -> bool {
    if diag.loc.line == target_line {
        return true;
    }
    let start_line = loc_from_line_starts(line_starts, diag.span.start).line;
    let end_line = loc_from_line_starts(line_starts, diag.span.end.saturating_sub(1)).line;
    if start_line <= target_line && target_line <= end_line {
        return true;
    }
    for subject in &file_ir.subjects {
        let mut matched_eff = false;
        subject.for_each_effect_span(&mut |eff_span, _eff_line| {
            if !matched_eff && eff_span.start <= diag.span.start && diag.span.end <= eff_span.end {
                let eff_start = loc_from_line_starts(line_starts, eff_span.start).line;
                let eff_end =
                    loc_from_line_starts(line_starts, eff_span.end.saturating_sub(1)).line;
                if eff_start <= target_line && target_line <= eff_end {
                    matched_eff = true;
                }
            }
        });
        if matched_eff {
            return true;
        }
    }
    false
}

#[cfg(feature = "js")]
fn detect_mismatched_inline_suppression(file_ir: &FileIr, diag: &Diagnostic) -> Option<String> {
    let mut candidate_lines = vec![diag.loc.line];
    for subject in &file_ir.subjects {
        if subject.span.start <= diag.span.start && diag.span.end <= subject.span.end {
            candidate_lines.push(subject.loc.line);
        }
        subject.for_each_effect_span(&mut |eff_span, eff_line| {
            if eff_span.start <= diag.span.start && diag.span.end <= eff_span.end {
                candidate_lines.push(eff_line);
            }
        });
    }
    for dir in &file_ir.suppressions.line_directives {
        if candidate_lines.contains(&dir.target_line)
            && !dir.rules.is_empty()
            && !dir.rules.iter().any(|r| diag.rule.matches_key(r))
        {
            return Some(format!(
                "Inline suppression comment targeting line {} listed {:?}, which did not match `{}`.",
                dir.target_line,
                dir.rules,
                diag.rule.metadata().qualified_key
            ));
        }
    }
    None
}

#[cfg(feature = "js")]
fn append_js_architecture_signals(
    file_ir: &FileIr,
    diag: &Diagnostic,
    explanation: &mut String,
    cascade_steps: &mut Vec<String>,
) {
    if !diag.rule.is_architecture_soc_or_reuse_rule() {
        return;
    }
    let Some(arch_exp) =
        format_architecture_signal_explanation(diag, Some(&file_ir.architecture_facets))
    else {
        return;
    };
    explanation.push_str(&format!(" Structural signals: {arch_exp}"));
    if !cascade_steps.contains(&arch_exp) {
        cascade_steps.push(arch_exp);
    }
}
