//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, cross-file **Caller Site** autofix enrichment, repository **Exemplar**
//! discovery, **Fix Capsule** assembly, and Markdown execution plan generation (`dotore plan`).

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Serialize;

use crate::{
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, DepsSpec, FileIr, SubjectIr,
        types::{compute_line_starts, loc_from_line_starts},
    },
    report::JsonReport,
    rules::{
        AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, Diagnostic, FixCapsule,
        PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId, RuleSeverity,
        RuleTag, SourceExcerpt,
    },
};

/// Result of running `dotore plan` (`plan_project`) to write deterministic Markdown execution plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanResult {
    /// Output directory where `README.md` and `NNN-<slug>.md` files were written.
    pub output_dir: PathBuf,
    /// Short git commit SHA stamped into the plan index (`"uncommitted"` if unavailable).
    pub commit_sha: String,
    /// Path to the generated `README.md` index file.
    pub index_file: PathBuf,
    /// Generated `(filename, path)` entries in priority order (`001-...`, `002-...`).
    pub plan_files: Vec<PathBuf>,
}

/// Computes the deterministic **Root-Cause Group** identifier (`rcg::...`) for `diag`.
#[must_use]
pub fn compute_root_cause_group_id(diag: &Diagnostic) -> String {
    if let Some(ctx_name) = extract_context_provider_name(diag) {
        return format!(
            "rcg::{}::context::{}",
            diag.rule.as_str(),
            normalize_slug(&ctx_name)
        );
    }

    if diag.rule.as_str() == "duplicate-jsx-subtree" {
        return format!(
            "rcg::{}::{}",
            diag.rule.as_str(),
            normalize_slug(&diag.target_name)
        );
    }

    let file_key = normalize_path_key(&diag.file);
    if let Some(subject) = &diag.subject_name {
        format!(
            "rcg::{}::{}::{}",
            diag.rule.as_str(),
            file_key,
            normalize_slug(subject)
        )
    } else {
        format!(
            "rcg::{}::{}::{}",
            diag.rule.as_str(),
            file_key,
            normalize_slug(&diag.target_name)
        )
    }
}

/// Upgrades unambiguous cross-file `no-reset-all-state-on-prop-change` diagnostics to `Autofix`
/// when all resolved **Caller Sites** lack `key={...}` and pass the prop value explicitly.
pub(crate) fn enrich_cross_file_autofixes(
    graph: &ProjectGraph,
    diagnostics: &mut [Diagnostic],
    sources: &HashMap<PathBuf, String>,
) {
    for diag in diagnostics.iter_mut() {
        if diag.rule != RuleId::NoResetAllStateOnPropChange || diag.autofix.is_some() {
            continue;
        }
        if let Some(patch) = build_cross_file_prop_reset_autofix(graph, diag, sources) {
            diag.tier = PrescriptionTier::Autofix;
            diag.autofix = Some(patch);
        }
    }
}

fn build_cross_file_prop_reset_autofix(
    graph: &ProjectGraph,
    diag: &Diagnostic,
    sources: &HashMap<PathBuf, String>,
) -> Option<AutofixPatch> {
    if diag.caller_sites.is_empty() || diag.caller_sites.iter().any(|c| c.has_key) {
        return None;
    }

    let file_ir = graph.files.iter().find(|f| f.path == diag.file)?;
    let subject_name = diag.subject_name.as_deref()?;
    let subject = file_ir
        .subjects
        .iter()
        .find(|s| s.name.as_deref() == Some(subject_name))?;
    let effect = subject
        .effect_nodes
        .iter()
        .find(|e| e.call_span == diag.span)?;
    let eff_stmt_span = effect.stmt_span?;

    // Only auto-remove the reset effect when every top-level statement in the effect is one of the state resets
    // and only a single prop is tracked in the dependency array.
    if effect.top_level_stmt_count != subject.state_slots.len() {
        return None;
    }
    let DepsSpec::Tracked(deps) = &effect.deps else {
        return None;
    };
    let mut tracked_props: BTreeSet<&str> = BTreeSet::new();
    for dep in deps {
        for prop in &dep.upstream_prop_names {
            tracked_props.insert(prop.as_str());
        }
    }
    if tracked_props.len() != 1 || !tracked_props.contains(diag.target_name.as_str()) {
        return None;
    }

    let mut edits = Vec::with_capacity(1 + diag.caller_sites.len());
    edits.push(ByteEdit {
        file: Some(diag.file.clone()),
        span: eff_stmt_span,
        replacement: String::new(),
    });

    for caller in &diag.caller_sites {
        if !caller.passed_props.contains(&diag.target_name) {
            return None;
        }
        let caller_source = sources.get(&caller.caller_file)?;
        let (insert_offset, key_attr_text) = extract_caller_key_injection(
            caller_source,
            caller.span,
            &caller.component_name,
            &diag.target_name,
        )?;
        edits.push(ByteEdit {
            file: Some(caller.caller_file.clone()),
            span: ByteSpan {
                start: insert_offset,
                end: insert_offset,
            },
            replacement: format!(" {key_attr_text}"),
        });
    }

    Some(AutofixPatch {
        description: format!(
            "Pass `key={{{}}}` at {} caller site(s) of `<{subject_name} />` and remove state-reset useEffect",
            diag.target_name,
            diag.caller_sites.len()
        ),
        edits,
    })
}

fn extract_caller_key_injection(
    caller_source: &str,
    opening_span: ByteSpan,
    component_name: &str,
    prop_name: &str,
) -> Option<(u32, String)> {
    let start = opening_span.start as usize;
    let end = opening_span.end as usize;
    if start >= end || end > caller_source.len() {
        return None;
    }
    let opening_text = caller_source.get(start..end)?;
    let expected_prefix = format!("<{component_name}");
    if !opening_text.starts_with(&expected_prefix) {
        return None;
    }
    // Reject if opening element uses JSX spread attributes (`{...props}`)
    if opening_text.contains("{...") {
        return None;
    }

    let prop_value_raw = extract_jsx_prop_raw_value(opening_text, prop_name)?;
    let insert_offset = opening_span.start + u32::try_from(expected_prefix.len()).ok()?;
    Some((insert_offset, format!("key={prop_value_raw}")))
}

fn extract_jsx_prop_raw_value(opening_text: &str, prop_name: &str) -> Option<String> {
    let bytes = opening_text.as_bytes();
    let needle = prop_name.as_bytes();
    let mut pos = 0;

    while pos + needle.len() < bytes.len() {
        let Some(rel) = opening_text[pos..].find(prop_name) else {
            break;
        };
        let idx = pos + rel;
        let before_ok = idx == 0 || bytes[idx - 1].is_ascii_whitespace();
        let after_idx = idx + needle.len();
        if before_ok && bytes.get(after_idx) == Some(&b'=') {
            let rest = opening_text.get(after_idx + 1..)?;
            return parse_jsx_attr_value_slice(rest);
        }
        pos = after_idx;
    }
    None
}

fn parse_jsx_attr_value_slice(rest: &str) -> Option<String> {
    if rest.starts_with('{') {
        let mut depth = 0_usize;
        for (offset, ch) in rest.char_indices() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(rest[..=offset].to_string());
                }
            }
        }
        return None;
    }
    let quote = rest.chars().next().filter(|&c| c == '"' || c == '\'')?;
    let end_quote = rest[1..].find(quote)?;
    Some(rest[..=end_quote + 1].to_string())
}

/// Builds deterministic [`RootCauseGroup`]s (sorted by [`BlastRadius`] descending) and
/// self-contained [`FixCapsule`]s for all `Surgical` and `Refactor` groups.
#[must_use]
pub(crate) fn build_root_cause_groups_and_capsules(
    graph: &ProjectGraph,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> (Vec<RootCauseGroup>, Vec<FixCapsule>) {
    let mut grouped_indices: HashMap<String, Vec<usize>> = HashMap::new();
    let mut group_order: Vec<String> = Vec::new();

    for (idx, diag) in diagnostics.iter().enumerate() {
        let group_id = compute_root_cause_group_id(diag);
        let entry = grouped_indices.entry(group_id.clone()).or_insert_with(|| {
            group_order.push(group_id);
            Vec::new()
        });
        entry.push(idx);
    }

    let mut groups: Vec<RootCauseGroup> = group_order
        .into_iter()
        .filter_map(|id| {
            let indices = grouped_indices.remove(&id)?;
            let first = diagnostics.get(*indices.first()?)?;
            let severity = if indices
                .iter()
                .any(|&i| diagnostics[i].severity == RuleSeverity::Error)
            {
                RuleSeverity::Error
            } else {
                RuleSeverity::Warning
            };
            let tier = group_prescription_tier(&indices, diagnostics);
            let blast_radius = compute_blast_radius(graph, &indices, diagnostics, sources);
            let message = if indices.len() > 1 {
                format!(
                    "{} ({} related sites in Root-Cause Group)",
                    first.message,
                    indices.len()
                )
            } else {
                first.message.clone()
            };

            Some(RootCauseGroup {
                id,
                rule: first.rule,
                category: first.category,
                severity,
                tier,
                file: first.file.clone(),
                subject_name: first.subject_name.clone(),
                target_name: first.target_name.clone(),
                loc: first.loc,
                message,
                blast_radius,
                diagnostic_indices: indices,
            })
        })
        .collect();

    groups.sort_by(|a, b| {
        (Reverse(a.blast_radius.score), &a.id).cmp(&(Reverse(b.blast_radius.score), &b.id))
    });

    let capsules: Vec<FixCapsule> = groups
        .iter()
        .filter(|g| {
            matches!(
                g.tier,
                PrescriptionTier::Surgical | PrescriptionTier::Refactor
            )
        })
        .map(|group| build_fix_capsule(graph, group, diagnostics, sources))
        .collect();

    (groups, capsules)
}

fn group_prescription_tier(indices: &[usize], diagnostics: &[Diagnostic]) -> PrescriptionTier {
    if indices
        .iter()
        .any(|&i| diagnostics[i].tier == PrescriptionTier::Refactor)
    {
        PrescriptionTier::Refactor
    } else if indices
        .iter()
        .any(|&i| diagnostics[i].tier == PrescriptionTier::Surgical)
    {
        PrescriptionTier::Surgical
    } else {
        PrescriptionTier::Autofix
    }
}

fn compute_blast_radius(
    graph: &ProjectGraph,
    indices: &[usize],
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> BlastRadius {
    let first = &diagnostics[indices[0]];
    let meta = first.rule.metadata();

    let render_frequency = detect_render_frequency(graph, indices, diagnostics, sources);
    let fan_out = compute_group_fan_out(graph, indices, diagnostics, sources);
    let cascade_depth = indices
        .iter()
        .map(|&i| diagnostics[i].cascade_steps.len())
        .max()
        .unwrap_or(0);

    let site_count = if first.rule.as_str() == "duplicate-jsx-subtree"
        && !first.caller_sites.is_empty()
        && indices.len() == 1
    {
        first.caller_sites.len()
    } else {
        indices.len()
    };

    let mut touched_files: BTreeSet<&Path> = BTreeSet::new();
    for &idx in indices {
        let d = &diagnostics[idx];
        touched_files.insert(d.file.as_path());
        for caller in &d.caller_sites {
            touched_files.insert(caller.caller_file.as_path());
        }
    }
    let file_count = touched_files.len().max(1);

    let severity = if indices
        .iter()
        .any(|&i| diagnostics[i].severity == RuleSeverity::Error)
    {
        RuleSeverity::Error
    } else {
        RuleSeverity::Warning
    };

    let is_minor_design_warning = meta.tags.contains(&RuleTag::Design)
        && severity == RuleSeverity::Warning
        && fan_out == 0
        && cascade_depth == 0;

    let severity_pts: u32 = match severity {
        RuleSeverity::Error => 30,
        RuleSeverity::Warning => 10,
    };

    let category_pts: u32 = if is_minor_design_warning {
        5
    } else {
        match first.category {
            RuleCategory::Security => 35,
            RuleCategory::Bugs => 30,
            RuleCategory::Performance => 20,
            RuleCategory::Accessibility => 15,
            RuleCategory::Maintainability => 5,
        }
    };

    let freq_pts: u32 = match render_frequency {
        RenderFrequency::FrameLoop60Fps => 45,
        RenderFrequency::ListLoop => 20,
        RenderFrequency::Standard => 0,
    };

    let cascade_pts = u32::try_from(cascade_depth).unwrap_or(0).saturating_mul(8);
    let fan_out_pts = u32::try_from(fan_out).unwrap_or(0).saturating_mul(12);
    let site_pts = u32::try_from(site_count.saturating_sub(1))
        .unwrap_or(0)
        .saturating_mul(6);
    let file_pts = u32::try_from(file_count.saturating_sub(1))
        .unwrap_or(0)
        .saturating_mul(5);

    let base_score =
        severity_pts + category_pts + freq_pts + cascade_pts + fan_out_pts + site_pts + file_pts;
    let raw_score = match render_frequency {
        RenderFrequency::FrameLoop60Fps => base_score.saturating_mul(2),
        RenderFrequency::ListLoop => (base_score.saturating_mul(3)) / 2,
        RenderFrequency::Standard => base_score,
    };

    let tier = if render_frequency == RenderFrequency::FrameLoop60Fps
        || (first.category == RuleCategory::Security && severity == RuleSeverity::Error)
        || (severity == RuleSeverity::Error
            && first.category == RuleCategory::Bugs
            && (fan_out >= 2 || cascade_depth >= 3))
        || raw_score >= 100
    {
        BlastRadiusTier::P0
    } else if !is_minor_design_warning
        && (severity == RuleSeverity::Error
            || render_frequency == RenderFrequency::ListLoop
            || cascade_depth >= 3
            || fan_out >= 2
            || raw_score >= 55)
    {
        BlastRadiusTier::P1
    } else if !is_minor_design_warning
        && (raw_score >= 25
            || cascade_depth > 0
            || fan_out >= 1
            || first.category != RuleCategory::Maintainability)
    {
        BlastRadiusTier::P2
    } else {
        BlastRadiusTier::P3
    };

    let score = match tier {
        BlastRadiusTier::P0 => raw_score.max(100),
        BlastRadiusTier::P1 => raw_score.clamp(55, 99),
        BlastRadiusTier::P2 => raw_score.clamp(25, 54),
        BlastRadiusTier::P3 => raw_score.clamp(1, 24),
    };

    BlastRadius {
        score,
        tier,
        render_frequency,
        fan_out,
        cascade_depth,
        site_count,
        file_count,
    }
}

fn detect_render_frequency(
    graph: &ProjectGraph,
    indices: &[usize],
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> RenderFrequency {
    let mut has_list_loop = false;

    for &idx in indices {
        let diag = &diagnostics[idx];
        let meta = diag.rule.metadata();

        if matches!(
            diag.rule,
            RuleId::R3fNoNewInUseFrame | RuleId::ThreeNoGeometryInFrameLoop
        ) || meta.tags.contains(&RuleTag::R3f)
            || meta.tags.contains(&RuleTag::Three)
            || meta.tags.contains(&RuleTag::Webgl)
        {
            return RenderFrequency::FrameLoop60Fps;
        }

        if matches!(
            diag.rule,
            RuleId::JsxKey | RuleId::NoArrayIndexAsKey | RuleId::AsyncAwaitInLoop
        ) {
            has_list_loop = true;
        }

        let Some(file_ir) = graph.files.iter().find(|f| f.path == diag.file) else {
            continue;
        };
        if file_ir
            .jsx_elements
            .iter()
            .any(|jsx| jsx.in_array_map && spans_intersect(jsx.span, diag.span))
        {
            has_list_loop = true;
        }

        let Some(subj_name) = &diag.subject_name else {
            continue;
        };
        if subject_uses_frame_loop(file_ir, subj_name, sources) {
            return RenderFrequency::FrameLoop60Fps;
        }
        if subject_rendered_in_list_loop(graph, &diag.file, subj_name) {
            has_list_loop = true;
        }
    }

    if has_list_loop {
        RenderFrequency::ListLoop
    } else {
        RenderFrequency::Standard
    }
}

fn subject_uses_frame_loop(
    file_ir: &FileIr,
    subj_name: &str,
    sources: &HashMap<PathBuf, String>,
) -> bool {
    let Some(subj) = file_ir
        .subjects
        .iter()
        .find(|s| s.name.as_deref() == Some(subj_name))
    else {
        return false;
    };
    let Some(src) = sources.get(&file_ir.path) else {
        return false;
    };
    let Some(subj_src) = slice_span(src, subj.span) else {
        return false;
    };
    subj_src.contains("useFrame(") || subj_src.contains("requestAnimationFrame(")
}

fn subject_rendered_in_list_loop(
    graph: &ProjectGraph,
    target_file: &Path,
    subj_name: &str,
) -> bool {
    graph
        .callers_of(target_file, subj_name)
        .iter()
        .any(|caller| {
            graph
                .files
                .iter()
                .find(|f| f.path == caller.caller_file)
                .is_some_and(|caller_file| {
                    caller_file
                        .jsx_elements
                        .iter()
                        .any(|jsx| jsx.in_array_map && spans_intersect(jsx.span, caller.span))
                })
        })
}

fn compute_group_fan_out(
    graph: &ProjectGraph,
    indices: &[usize],
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> usize {
    let mut caller_keys: BTreeSet<(PathBuf, u32, u32)> = BTreeSet::new();
    let mut context_names: BTreeSet<String> = BTreeSet::new();
    let mut child_components: BTreeSet<String> = BTreeSet::new();

    for &idx in indices {
        let diag = &diagnostics[idx];
        for caller in &diag.caller_sites {
            caller_keys.insert((
                caller.caller_file.clone(),
                caller.loc.line,
                caller.loc.column,
            ));
        }

        if diag.caller_sites.is_empty()
            && let Some(subj_name) = &diag.subject_name
        {
            for caller in graph.callers_of(&diag.file, subj_name) {
                caller_keys.insert((
                    caller.caller_file.clone(),
                    caller.loc.line,
                    caller.loc.column,
                ));
            }
        }

        if let Some(ctx_name) = extract_context_provider_name(diag) {
            context_names.insert(ctx_name);
        }

        if !diag.cascade_steps.is_empty()
            && let Some(subj_name) = &diag.subject_name
            && let Some(file_ir) = graph.files.iter().find(|f| f.path == diag.file)
        {
            for site in &file_ir.caller_sites {
                if site.parent_subject_name.as_deref() == Some(subj_name.as_str()) {
                    child_components.insert(site.component_name.clone());
                }
            }
        }
    }

    let mut context_consumers = 0_usize;
    for ctx_name in &context_names {
        context_consumers += count_context_consumers(graph, sources, ctx_name);
    }

    caller_keys.len() + context_consumers + child_components.len()
}

fn count_context_consumers(
    graph: &ProjectGraph,
    sources: &HashMap<PathBuf, String>,
    context_name: &str,
) -> usize {
    let use_ctx_pat = format!("useContext({context_name})");
    let use_pat = format!("use({context_name})");
    let mut count = 0_usize;

    for file in &graph.files {
        if let Some(src) = sources.get(&file.path) {
            let matches_in_file = src.matches(&use_ctx_pat).count() + src.matches(&use_pat).count();
            if matches_in_file > 0 {
                count += matches_in_file;
                continue;
            }
        }
        // Fallback if source text is not present: check module imports for both `useContext` and `context_name`
        let imports_use_context = file.module.imports.iter().any(|imp| {
            imp.specifiers
                .iter()
                .any(|s| s == "useContext" || s == "use")
        });
        let imports_context = file
            .module
            .imports
            .iter()
            .any(|imp| imp.specifiers.iter().any(|s| s == context_name));
        if imports_use_context && imports_context {
            count += 1;
        }
    }

    count
}

fn extract_context_provider_name(diag: &Diagnostic) -> Option<String> {
    if let Some(start) = diag.message.find('<')
        && let Some(end_rel) = diag.message[start + 1..].find(".Provider>")
    {
        let candidate = diag.message[start + 1..start + 1 + end_rel].trim();
        if !candidate.is_empty() {
            return Some(candidate.to_string());
        }
    }
    if diag.target_name.ends_with("Context") {
        return Some(diag.target_name.clone());
    }
    if let Some(stripped) = diag.target_name.strip_suffix(".Provider") {
        return Some(stripped.to_string());
    }
    None
}

pub(crate) fn build_fix_capsule(
    graph: &ProjectGraph,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> FixCapsule {
    let primary_diag = &diagnostics[group.diagnostic_indices[0]];
    let subject_excerpt = build_subject_excerpt(graph, primary_diag, sources);

    let mut caller_site_excerpts = Vec::new();
    let mut seen_callers: BTreeSet<(PathBuf, u32, u32)> = BTreeSet::new();
    for &idx in &group.diagnostic_indices {
        for caller in &diagnostics[idx].caller_sites {
            if seen_callers.insert((
                caller.caller_file.clone(),
                caller.loc.line,
                caller.loc.column,
            )) {
                caller_site_excerpts.push(build_caller_site_excerpt(caller, sources));
            }
        }
    }
    if caller_site_excerpts.is_empty()
        && let Some(subj_name) = &group.subject_name
    {
        for caller in graph.callers_of(&group.file, subj_name) {
            if seen_callers.insert((
                caller.caller_file.clone(),
                caller.loc.line,
                caller.loc.column,
            )) {
                caller_site_excerpts.push(build_caller_site_excerpt(&caller, sources));
            }
        }
    }

    let exemplar = find_repository_exemplar(graph, group, diagnostics, sources);
    let invariants = invariants_for_rule(group.rule, group.tier);

    FixCapsule {
        root_cause_group_id: group.id.clone(),
        rule: group.rule,
        tier: group.tier,
        blast_radius: group.blast_radius.clone(),
        subject_excerpt,
        caller_site_excerpts,
        recipe_markdown: group.rule.metadata().recipe_markdown,
        exemplar,
        invariants,
    }
}

fn build_subject_excerpt(
    graph: &ProjectGraph,
    diag: &Diagnostic,
    sources: &HashMap<PathBuf, String>,
) -> SourceExcerpt {
    let Some(source) = sources.get(&diag.file) else {
        return SourceExcerpt {
            file: diag.file.clone(),
            start_line: diag.loc.line,
            end_line: diag.loc.line,
            source: String::new(),
        };
    };

    if let Some(file_ir) = graph.files.iter().find(|f| f.path == diag.file) {
        if let Some(subj_name) = &diag.subject_name
            && let Some(subj) = file_ir
                .subjects
                .iter()
                .find(|s| s.name.as_deref() == Some(subj_name.as_str()))
        {
            return excerpt_from_span(&diag.file, source, subj.span);
        }
        if let Some(subj) = file_ir
            .subjects
            .iter()
            .find(|s| spans_intersect(s.span, diag.span))
        {
            return excerpt_from_span(&diag.file, source, subj.span);
        }
    }

    excerpt_from_span(&diag.file, source, diag.span)
}

fn build_caller_site_excerpt(
    caller: &ResolvedCallerSite,
    sources: &HashMap<PathBuf, String>,
) -> SourceExcerpt {
    if let Some(source) = sources.get(&caller.caller_file) {
        excerpt_from_span(&caller.caller_file, source, caller.span)
    } else {
        SourceExcerpt {
            file: caller.caller_file.clone(),
            start_line: caller.loc.line,
            end_line: caller.loc.line,
            source: format!("<{} />", caller.component_name),
        }
    }
}

fn excerpt_from_span(file: &Path, source: &str, span: ByteSpan) -> SourceExcerpt {
    let line_starts = compute_line_starts(source);
    let start_loc = loc_from_line_starts(&line_starts, span.start);
    let end_loc = loc_from_line_starts(&line_starts, span.end.saturating_sub(1).max(span.start));

    let lines: Vec<&str> = source.lines().collect();
    let start_idx = (start_loc.line as usize).saturating_sub(1);
    let end_idx = (end_loc.line as usize).min(lines.len());

    let sliced = if start_idx < end_idx && start_idx < lines.len() {
        lines[start_idx..end_idx].join("\n")
    } else {
        slice_span(source, span).unwrap_or_default().to_string()
    };

    SourceExcerpt {
        file: file.to_path_buf(),
        start_line: start_loc.line,
        end_line: end_loc.line.max(start_loc.line),
        source: sliced,
    }
}

fn find_repository_exemplar(
    graph: &ProjectGraph,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    let flagged_subjects: BTreeSet<(&Path, Option<&str>)> = diagnostics
        .iter()
        .map(|d| (d.file.as_path(), d.subject_name.as_deref()))
        .collect();

    // 1. For `no-reset-all-state-on-prop-change`, check if any resolved caller site already passes `key={...}`
    if group.rule == RuleId::NoResetAllStateOnPropChange {
        for &idx in &group.diagnostic_indices {
            if let Some(valid_caller) = diagnostics[idx].caller_sites.iter().find(|c| c.has_key) {
                return Some(build_caller_site_excerpt(valid_caller, sources));
            }
        }
    }

    // 2. Search across all files in deterministic path order for a Subject or JSX element matching the rule's target idiom
    let mut sorted_files: Vec<&FileIr> = graph.files.iter().collect();
    sorted_files.sort_by(|a, b| a.path.cmp(&b.path));

    for file in &sorted_files {
        let Some(src) = sources.get(&file.path) else {
            continue;
        };

        for subj in &file.subjects {
            if (file.path.as_path(), subj.name.as_deref())
                == (group.file.as_path(), group.subject_name.as_deref())
            {
                continue;
            }
            let Some(subj_src) = slice_span(src, subj.span) else {
                continue;
            };
            if subject_matches_rule_exemplar(group.rule, subj, subj_src) {
                return Some(excerpt_from_span(&file.path, src, subj.span));
            }
        }

        if matches!(group.rule, RuleId::JsxKey | RuleId::NoArrayIndexAsKey)
            && let Some(valid_jsx) = file
                .jsx_elements
                .iter()
                .find(|j| j.in_array_map && j.has_key && !j.key_is_array_index)
        {
            return Some(excerpt_from_span(&file.path, src, valid_jsx.span));
        }
    }

    // 3. Fallback: any clean Subject in the repository with zero diagnostics
    for file in &sorted_files {
        let Some(src) = sources.get(&file.path) else {
            continue;
        };
        for subj in &file.subjects {
            if subj.name.is_some()
                && !flagged_subjects.contains(&(file.path.as_path(), subj.name.as_deref()))
            {
                return Some(excerpt_from_span(&file.path, src, subj.span));
            }
        }
    }

    None
}

fn subject_matches_rule_exemplar(rule: RuleId, subj: &SubjectIr, subj_src: &str) -> bool {
    match rule {
        RuleId::NoExternalStoreSubscription => subj_src.contains("useSyncExternalStore("),
        RuleId::NoFetchInEffect | RuleId::QueryNoVoidQueryFn => {
            subj_src.contains("useQuery(") || subj_src.contains("useSuspenseQuery(")
        }
        RuleId::NoDerivedState
        | RuleId::NoChainStateUpdates
        | RuleId::NoAdjustStateOnPropChange => {
            subj.effect_nodes.is_empty() && subj_src.contains("const ")
        }
        RuleId::NoInitializeState => {
            subj.effect_nodes.is_empty()
                && subj.state_slots.iter().any(|s| s.init_arg_text.is_some())
        }
        RuleId::JsxNoNewObjectAsProp | RuleId::JotaiSelectAtomInRenderBody => {
            subj_src.contains("useMemo(")
        }
        RuleId::ZustandNoWholeStoreDestructure => {
            subj_src.contains("Store((s") || subj_src.contains("Store((state")
        }
        RuleId::MobxReactionDisposerDiscarded => {
            subj.effect_nodes.iter().any(|e| e.has_cleanup)
                && (subj_src.contains("autorun(") || subj_src.contains("reaction("))
        }
        RuleId::NoEventHandler
        | RuleId::NoResetAllStateOnPropChange
        | RuleId::NoPassLiveStateToParent
        | RuleId::NoPassDataToParent
        | RuleId::JsxKey
        | RuleId::NoArrayIndexAsKey
        | RuleId::JsxNoUndef
        | RuleId::ExhaustiveDeps
        | RuleId::OnlyExportComponents
        | RuleId::NoDirectMutationState
        | RuleId::AltText
        | RuleId::RequireReducedMotion
        | RuleId::DesignNoVagueButtonLabel
        | RuleId::NoDanger
        | RuleId::ServerAuthActions
        | RuleId::AsyncAwaitInLoop
        | RuleId::NoRenderPropChildren
        | RuleId::UnusedFile
        | RuleId::UnusedExport
        | RuleId::UnusedType
        | RuleId::UnusedDependency
        | RuleId::UnusedDevDependency
        | RuleId::CircularDependency
        | RuleId::DuplicateJsxSubtree
        | RuleId::NextjsNoImgElement
        | RuleId::RnNoRawText
        | RuleId::ExpoNoNonInlinedEnv
        | RuleId::TanstackStartServerFnValidateInput
        | RuleId::ThreeNoGeometryInFrameLoop
        | RuleId::R3fNoNewInUseFrame
        | RuleId::ValtioNoSnapshotInCallback
        | RuleId::PreactNoReactImport
        | RuleId::InkNoRawText
        | RuleId::ZodV4DeprecatedParse => false,
    }
}

fn invariants_for_rule(rule: RuleId, tier: PrescriptionTier) -> Vec<&'static str> {
    let mut inv = vec![
        "Do not introduce inline suppression comments (`dotore-disable`, `eslint-disable`, `oxlint-disable`).",
        "Preserve existing TypeScript types, component props contract, and observable DOM/UI output.",
    ];

    match rule {
        RuleId::NoResetAllStateOnPropChange => {
            inv.push("Ensure every parent Caller Site passes the identifying prop as `key={...}` before removing the reset `useEffect`.");
        }
        RuleId::NoAdjustStateOnPropChange | RuleId::NoDerivedState => {
            inv.push("Compute derived values purely during render without mutating refs or triggering state setters during render.");
        }
        RuleId::NoChainStateUpdates => {
            inv.push("Collapse chained state transitions into a single render-phase derivation or a single event-handler state update.");
        }
        RuleId::NoEventHandler | RuleId::NoPassLiveStateToParent | RuleId::NoPassDataToParent => {
            inv.push("Invoke parent callbacks directly inside the originating user event handler or lift state to the parent Subject.");
        }
        RuleId::NoExternalStoreSubscription => {
            inv.push("Provide stable `subscribe` and `getSnapshot` functions (plus `getServerSnapshot` if SSR-rendered) to `useSyncExternalStore`.");
        }
        RuleId::NoFetchInEffect => {
            inv.push("Ensure in-flight requests are canceled or deduplicated so stale responses never overwrite newer state.");
        }
        RuleId::NoInitializeState
        | RuleId::JsxKey
        | RuleId::NoArrayIndexAsKey
        | RuleId::JsxNoUndef
        | RuleId::ExhaustiveDeps
        | RuleId::OnlyExportComponents
        | RuleId::NoDirectMutationState
        | RuleId::JsxNoNewObjectAsProp
        | RuleId::AltText
        | RuleId::RequireReducedMotion
        | RuleId::DesignNoVagueButtonLabel
        | RuleId::NoDanger
        | RuleId::ServerAuthActions
        | RuleId::AsyncAwaitInLoop
        | RuleId::NoRenderPropChildren
        | RuleId::UnusedFile
        | RuleId::UnusedExport
        | RuleId::UnusedType
        | RuleId::UnusedDependency
        | RuleId::UnusedDevDependency
        | RuleId::CircularDependency
        | RuleId::DuplicateJsxSubtree
        | RuleId::NextjsNoImgElement
        | RuleId::RnNoRawText
        | RuleId::ExpoNoNonInlinedEnv
        | RuleId::QueryNoVoidQueryFn
        | RuleId::TanstackStartServerFnValidateInput
        | RuleId::ThreeNoGeometryInFrameLoop
        | RuleId::R3fNoNewInUseFrame
        | RuleId::ZustandNoWholeStoreDestructure
        | RuleId::JotaiSelectAtomInRenderBody
        | RuleId::MobxReactionDisposerDiscarded
        | RuleId::ValtioNoSnapshotInCallback
        | RuleId::PreactNoReactImport
        | RuleId::InkNoRawText
        | RuleId::ZodV4DeprecatedParse => match tier {
            PrescriptionTier::Refactor => {
                inv.push("Verify all cross-file Caller Sites and consumers remain consistent after updating the Subject contract.");
            }
            PrescriptionTier::Surgical | PrescriptionTier::Autofix => {
                inv.push("Keep the transformation localized to the owning Subject without altering sibling components.");
            }
        },
    }

    inv
}

/// Generates deterministic `NNN-<slug>.md` execution plans and a prioritized `README.md` index
/// inside `output_dir`, stamped with the current git commit SHA.
///
/// # Errors
/// Returns an `io::Error` if creating `output_dir` or writing any Markdown file fails.
pub fn plan_project(report: &JsonReport, output_dir: &Path) -> io::Result<PlanResult> {
    fs::create_dir_all(output_dir)?;
    let commit_sha = resolve_git_commit_sha(output_dir);

    let mut plan_files = Vec::with_capacity(report.fix_capsules.len());
    let mut index_rows = Vec::with_capacity(report.fix_capsules.len());

    for (idx, capsule) in report.fix_capsules.iter().enumerate() {
        let ordinal = idx + 1;
        let slug = build_capsule_filename_slug(capsule, report);
        let file_name = format!("{ordinal:03}-{slug}.md");
        let file_path = output_dir.join(&file_name);
        let markdown = render_capsule_plan_markdown(ordinal, capsule, report, &commit_sha);
        fs::write(&file_path, markdown)?;
        plan_files.push(file_path);
        index_rows.push((ordinal, file_name, capsule));
    }

    let index_file = output_dir.join("README.md");
    let readme_md = render_plan_readme_markdown(report, &commit_sha, &index_rows);
    fs::write(&index_file, readme_md)?;

    Ok(PlanResult {
        output_dir: output_dir.to_path_buf(),
        commit_sha,
        index_file,
        plan_files,
    })
}

/// Formats a human-readable terminal summary for `dotore plan`.
#[must_use]
pub fn format_plan_report(result: &PlanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "dotore plan  commit: {}  plans: {}  index: {}",
        result.commit_sha,
        result.plan_files.len(),
        result.index_file.display()
    );
    for path in &result.plan_files {
        let _ = writeln!(out, "  - {}", path.display());
    }
    out
}

fn build_capsule_filename_slug(capsule: &FixCapsule, report: &JsonReport) -> String {
    let group = report
        .root_cause_groups
        .iter()
        .find(|g| g.id == capsule.root_cause_group_id);
    let subject_or_target = group
        .and_then(|g| g.subject_name.as_deref())
        .or_else(|| group.map(|g| g.target_name.as_str()))
        .unwrap_or("root");
    format!(
        "{}-{}",
        capsule.rule.as_str(),
        normalize_slug(subject_or_target)
    )
}

fn render_capsule_plan_markdown(
    ordinal: usize,
    capsule: &FixCapsule,
    report: &JsonReport,
    commit_sha: &str,
) -> String {
    let mut md = String::new();
    let meta = capsule.rule.metadata();
    let group = report
        .root_cause_groups
        .iter()
        .find(|g| g.id == capsule.root_cause_group_id);

    let title_target = group
        .and_then(|g| g.subject_name.as_deref())
        .or_else(|| group.map(|g| g.target_name.as_str()))
        .unwrap_or("module");

    let _ = writeln!(
        md,
        "# Plan {ordinal:03}: `{}` in `{title_target}`\n",
        capsule.rule.as_str()
    );
    let _ = writeln!(
        md,
        "- **Root-Cause Group**: `{}`",
        capsule.root_cause_group_id
    );
    let _ = writeln!(
        md,
        "- **Rule**: `{}` ({})",
        capsule.rule.as_str(),
        meta.title
    );
    let _ = writeln!(md, "- **Category**: `{}`", meta.category.as_str());
    let _ = writeln!(md, "- **Prescription Tier**: `{}`", capsule.tier.as_str());
    let _ = writeln!(
        md,
        "- **Blast Radius**: `{}` (score `{}`, frequency `{}`, fan-out `{}`, cascade depth `{}`, sites `{}`, files `{}`)",
        capsule.blast_radius.tier.as_str(),
        capsule.blast_radius.score,
        capsule.blast_radius.render_frequency.as_str(),
        capsule.blast_radius.fan_out,
        capsule.blast_radius.cascade_depth,
        capsule.blast_radius.site_count,
        capsule.blast_radius.file_count,
    );
    let _ = writeln!(md, "- **Commit SHA**: `{commit_sha}`");
    let _ = writeln!(md, "- **Docs**: {}\n", meta.docs_url);

    if let Some(g) = group {
        let _ = writeln!(md, "## Findings ({})\n", g.diagnostic_indices.len());
        for &diag_idx in &g.diagnostic_indices {
            if let Some(d) = report.diagnostics.get(diag_idx) {
                let _ = writeln!(
                    md,
                    "- `{}:{}:{}` — {}",
                    d.file.display(),
                    d.loc.line,
                    d.loc.column,
                    d.message
                );
                if !d.cascade_steps.is_empty() {
                    let _ = writeln!(md, "  - Render Cascade: `{}`", d.cascade_steps.join(" -> "));
                }
            }
        }
        let _ = writeln!(md);
    }

    let _ = writeln!(
        md,
        "## Subject Excerpt (`{}:{}-{}`)\n",
        capsule.subject_excerpt.file.display(),
        capsule.subject_excerpt.start_line,
        capsule.subject_excerpt.end_line
    );
    let _ = writeln!(md, "```tsx\n{}\n```\n", capsule.subject_excerpt.source);

    if !capsule.caller_site_excerpts.is_empty() {
        let _ = writeln!(
            md,
            "## Caller Site Excerpts ({})\n",
            capsule.caller_site_excerpts.len()
        );
        for caller_ex in &capsule.caller_site_excerpts {
            let _ = writeln!(
                md,
                "### `{}:{}-{}`\n",
                caller_ex.file.display(),
                caller_ex.start_line,
                caller_ex.end_line
            );
            let _ = writeln!(md, "```tsx\n{}\n```\n", caller_ex.source);
        }
    }

    let _ = writeln!(md, "## Transformation Recipe\n");
    let _ = writeln!(md, "{}\n", capsule.recipe_markdown);

    let _ = writeln!(md, "## Invariants to Preserve\n");
    for inv in &capsule.invariants {
        let _ = writeln!(md, "- {inv}");
    }
    let _ = writeln!(md);

    if let Some(exemplar) = &capsule.exemplar {
        let _ = writeln!(
            md,
            "## Repository Exemplar (`{}:{}-{}`)\n",
            exemplar.file.display(),
            exemplar.start_line,
            exemplar.end_line
        );
        let _ = writeln!(md, "```tsx\n{}\n```\n", exemplar.source);
    }

    md
}

fn render_plan_readme_markdown(
    report: &JsonReport,
    commit_sha: &str,
    rows: &[(usize, String, &FixCapsule)],
) -> String {
    let mut md = String::new();
    let s = &report.summary;

    let _ = writeln!(md, "# Dotore Deterministic Remediation Plan\n");
    let _ = writeln!(md, "- **Commit SHA**: `{commit_sha}`");
    let _ = writeln!(md, "- **Health Score**: `{}/100`", s.health_score);
    let _ = writeln!(
        md,
        "- **Scanned**: `{}` file(s), `{}` Subject(s), `{}` Effect Node(s)",
        s.files_scanned, s.subjects_scanned, s.effects_scanned
    );
    let _ = writeln!(
        md,
        "- **Diagnostics**: `{}` total (`{}` autofix, `{}` surgical, `{}` refactor)",
        s.total_diagnostics, s.autofix_count, s.surgical_count, s.refactor_count
    );
    let _ = writeln!(md, "- **Actionable Fix Capsules**: `{}`\n", rows.len());

    if rows.is_empty() {
        let _ = writeln!(
            md,
            "No `Surgical` or `Refactor` Root-Cause Groups require manual or agent remediation."
        );
        return md;
    }

    let _ = writeln!(
        md,
        "## Prioritized Execution Queue (Ordered by Blast Radius)\n"
    );
    let _ = writeln!(
        md,
        "| # | Priority | Blast Score | Rule | Tier | Subject / File | Plan |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|---|");

    for (ordinal, file_name, capsule) in rows {
        let group = report
            .root_cause_groups
            .iter()
            .find(|g| g.id == capsule.root_cause_group_id);
        let subject_label = group
            .and_then(|g| g.subject_name.as_deref())
            .unwrap_or("<module>");
        let _ = writeln!(
            md,
            "| {:03} | `{}` | `{}` | `{}` | `{}` | `{}` (`{}:{}`) | [{}](./{}) |",
            ordinal,
            capsule.blast_radius.tier.as_str(),
            capsule.blast_radius.score,
            capsule.rule.as_str(),
            capsule.tier.as_str(),
            subject_label,
            capsule.subject_excerpt.file.display(),
            capsule.subject_excerpt.start_line,
            file_name,
            file_name
        );
    }

    md
}

fn resolve_git_commit_sha(dir: &Path) -> String {
    let cwd = if dir.exists() { dir } else { Path::new(".") };
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(cwd)
        .output()
        && output.status.success()
    {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        && output.status.success()
    {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }
    "uncommitted".to_string()
}

fn normalize_path_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_slug(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    let mut prev_dash = false;
    for (idx, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 && !prev_dash {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "root".to_string()
    } else {
        trimmed.to_string()
    }
}

fn spans_intersect(a: ByteSpan, b: ByteSpan) -> bool {
    a.start <= b.end && b.start <= a.end
}

fn slice_span(source: &str, span: ByteSpan) -> Option<&str> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start <= end
        && end <= source.len()
        && source.is_char_boundary(start)
        && source.is_char_boundary(end)
    {
        source.get(start..end)
    } else {
        None
    }
}
