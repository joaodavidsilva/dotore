//! Terminal, JSON, and self-contained HTML cascade reporters for `dotore`.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub use dotore_core::report::{
    CiActionResult, CiOptions, CiProviderKind, InstallOptions, InstallResult,
    JSON_REPORT_SCHEMA_VERSION, JsonReport, ProjectCoverageMetadata, ReportSummary,
    RuleCatalogEntry, RulesListOptions, WhyEntry, WhyLocation, WhyReport, build_extracted_report,
    build_extracted_report_with_packages, build_report_from_planner_context, build_rule_catalog,
    ci_config, ci_install, ci_upgrade, diagnose_why_not_active_common,
    explain_location_with_analyzers, explain_rule, format_design_report, format_fix_report,
    format_install_report, format_rule_catalog_text, format_rule_explanation_text,
    format_terminal_report, format_why_report_text, install_dotore, parse_why_location,
    render_code_frame, render_html_report, write_and_open_html_report, write_json_report,
};

use crate::{
    config::{
        CapabilityGate, IgnoreConfig, WorkspacePackage, discover_workspace_packages,
        load_config_from_dir, resolve_package_for_file,
    },
    graph::ProjectGraph,
    ir::{
        FileIr, parse_file_ir,
        types::{compute_line_starts, loc_from_line_starts},
    },
    load_disk_manifests,
    planner::{
        build_fix_capsule, build_root_cause_groups_and_capsules, enrich_cross_file_autofixes,
    },
    rules::{
        Diagnostic, RuleId, evaluate_file_in_package, evaluate_project_graph_rules,
        reduced_motion::evaluate_project_reduced_motion, rule_registry,
    },
    scanner::{collect_source_files, collect_style_files},
};

/// Builds a [`JsonReport`] from a [`ProjectGraph`], its evaluated [`Diagnostic`]s, and file sources.
#[must_use]
pub(crate) fn build_report(
    graph: &ProjectGraph,
    diagnostics: Vec<Diagnostic>,
    sources: &HashMap<PathBuf, String>,
) -> JsonReport {
    build_report_with_packages(graph, diagnostics, sources, &[])
}

/// Builds a [`JsonReport`] including per-project coverage metadata for discovered [`WorkspacePackage`]s.
#[must_use]
pub(crate) fn build_report_with_packages(
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
/// did or did not apply) at `location_arg` (`<file:line>`) under `cwd`, including its complete [` crate::FixCapsule`].
///
/// # Errors
/// Returns an error string if `location_arg` is malformed or the target file cannot be read.
pub fn explain_location(location_arg: &str, cwd: &Path) -> Result<WhyReport, String> {
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

    let packages = discover_workspace_packages(cwd);
    let mut discovered_files = collect_source_files(&[cwd.to_path_buf()], true);
    for style_path in collect_style_files(&[cwd.to_path_buf()]) {
        if !discovered_files.contains(&style_path) {
            discovered_files.push(style_path);
        }
    }
    if !discovered_files.contains(&resolved_file) {
        discovered_files.push(resolved_file.clone());
    }

    let mut sources: HashMap<PathBuf, String> = HashMap::new();
    let mut file_irs: Vec<FileIr> = Vec::new();
    for path in discovered_files {
        if let Ok(src) = fs::read_to_string(&path) {
            file_irs.push(parse_file_ir(&path, &src));
            sources.insert(path, src);
        }
    }

    let manifests = load_disk_manifests(cwd, &packages, &sources);
    let graph = ProjectGraph::build_with_manifests(file_irs, manifests);
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
    let permissive_gate = CapabilityGate::default_react();
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
            let explanation = if let Some(note) = mismatch_note {
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
            entries.push(WhyEntry {
                status: "active".to_string(),
                rule: diag.rule.metadata().qualified_key.to_string(),
                category: diag.category,
                severity: diag.severity,
                tier: diag.tier,
                message: diag.message.clone(),
                explanation,
                code_frame: render_code_frame(&target_source, diag.loc.line),
                cascade_steps: diag.cascade_steps.clone(),
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
                let (status, explanation) = diagnose_why_not_active_common(
                    diag,
                    &target_file_ir.path,
                    target_file_ir.file_context,
                    is_suppressed,
                    &pkg.root_dir,
                    &pkg.capability_gate,
                    &pkg.config,
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
                    cascade_steps: diag.cascade_steps.clone(),
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
        file: parsed_loc.file,
        line: parsed_loc.line,
        column: parsed_loc.column,
        entries,
        summary_note,
    })
}

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
        for effect in &subject.effect_nodes {
            if effect.call_span.start <= diag.span.start && diag.span.end <= effect.call_span.end {
                let eff_start = loc_from_line_starts(line_starts, effect.call_span.start).line;
                let eff_end =
                    loc_from_line_starts(line_starts, effect.call_span.end.saturating_sub(1)).line;
                if eff_start <= target_line && target_line <= eff_end {
                    return true;
                }
            }
        }
    }
    false
}

fn detect_mismatched_inline_suppression(file_ir: &FileIr, diag: &Diagnostic) -> Option<String> {
    let mut candidate_lines = vec![diag.loc.line];
    for subject in &file_ir.subjects {
        if subject.span.start <= diag.span.start && diag.span.end <= subject.span.end {
            candidate_lines.push(subject.loc.line);
        }
        for effect in &subject.effect_nodes {
            if effect.call_span.start <= diag.span.start && diag.span.end <= effect.call_span.end {
                candidate_lines.push(effect.loc.line);
            }
        }
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
