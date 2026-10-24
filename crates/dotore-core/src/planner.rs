//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, repository **Exemplar** discovery, **Fix Capsule** assembly, and
//! Markdown execution plan generation (`dotore plan`).

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
    ir::{
        ArchitectureFileFacets, ByteSpan, ExtractedFile, LanguageId, ResolvedCallerSite,
        compute_line_starts, loc_from_line_starts,
    },
    report::JsonReport,
    rules::{
        BlastRadius, BlastRadiusTier, Diagnostic, FixCapsule, PrescriptionTier, RenderFrequency,
        RootCauseGroup, RuleCategory, RuleId, RuleSeverity, RuleTag, SourceExcerpt,
    },
};

/// Provides project/language graph context for **Blast Radius**, **Subject** excerpt,
/// and repository **Exemplar** lookup during **Fix Capsule** planning.
pub trait PlannerContext {
    /// Returns all analyzed file paths in deterministic order.
    fn analyzed_files(&self) -> Vec<PathBuf>;

    /// Returns subject `(name, span)` pairs extracted for `file`.
    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)>;

    /// Returns resolved caller sites for `(target_file, subject_name)` when not already attached to a `Diagnostic`.
    fn callers_of(&self, _target_file: &Path, _subject_name: &str) -> Vec<ResolvedCallerSite> {
        Vec::new()
    }

    /// Returns child component names rendered inside `(file, subject_name)`.
    fn child_components_of(&self, _file: &Path, _subject_name: &str) -> Vec<String> {
        Vec::new()
    }

    /// Returns `true` if `span` in `file` sits inside a list-loop (`.map(...)`, `@for`, `for` loop) element.
    fn span_in_list_loop(&self, _file: &Path, _span: ByteSpan) -> bool {
        false
    }

    /// Returns `true` if `(target_file, subject_name)` is rendered inside a list loop at any caller site.
    fn subject_rendered_in_list_loop(&self, _target_file: &Path, _subject_name: &str) -> bool {
        false
    }

    /// Counts consumers of `context_name` across the project.
    fn count_context_consumers(
        &self,
        context_name: &str,
        sources: &HashMap<PathBuf, String>,
    ) -> usize {
        let use_ctx_pat = format!("useContext({context_name})");
        let use_pat = format!("use({context_name})");
        sources
            .values()
            .map(|src| src.matches(&use_ctx_pat).count() + src.matches(&use_pat).count())
            .sum()
    }

    /// Finds a rule-specific repository **Exemplar** across the project, if any.
    fn find_rule_exemplar(
        &self,
        _group: &RootCauseGroup,
        _diagnostics: &[Diagnostic],
        _sources: &HashMap<PathBuf, String>,
    ) -> Option<SourceExcerpt> {
        None
    }

    /// Returns the extracted [`ArchitectureFileFacets`] for `file`, if available.
    fn architecture_facets_for_file(&self, _file: &Path) -> Option<&ArchitectureFileFacets> {
        None
    }
}

impl PlannerContext for [ExtractedFile] {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self
            .iter()
            .filter(|f| {
                !matches!(
                    f.path.extension().and_then(|e| e.to_str()),
                    Some("css" | "scss" | "html" | "htm")
                )
            })
            .map(|f| f.path.clone())
            .collect();
        files.sort();
        files
    }

    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        self.iter()
            .find(|f| f.path == file)
            .map(|f| {
                f.subject_spans
                    .iter()
                    .map(|(name, span, _)| (name.clone(), *span))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn architecture_facets_for_file(&self, file: &Path) -> Option<&ArchitectureFileFacets> {
        self.iter()
            .find(|f| f.path == file)
            .map(|f| &f.architecture_facets)
    }

    fn find_rule_exemplar(
        &self,
        group: &RootCauseGroup,
        diagnostics: &[Diagnostic],
        sources: &HashMap<PathBuf, String>,
    ) -> Option<SourceExcerpt> {
        find_architecture_exemplar_in_extracted_files(self, group, diagnostics, sources)
    }
}

impl PlannerContext for Vec<ExtractedFile> {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        self.as_slice().analyzed_files()
    }

    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        self.as_slice().subject_spans_for_file(file)
    }

    fn architecture_facets_for_file(&self, file: &Path) -> Option<&ArchitectureFileFacets> {
        self.as_slice().architecture_facets_for_file(file)
    }

    fn find_rule_exemplar(
        &self,
        group: &RootCauseGroup,
        diagnostics: &[Diagnostic],
        sources: &HashMap<PathBuf, String>,
    ) -> Option<SourceExcerpt> {
        self.as_slice()
            .find_rule_exemplar(group, diagnostics, sources)
    }
}

impl PlannerContext for () {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn subject_spans_for_file(&self, _file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        Vec::new()
    }
}

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

    if matches!(
        diag.rule,
        RuleId::DuplicateJsxSubtree
            | RuleId::ArchNoDuplicatedHelperLogic
            | RuleId::ArchPreferFluentBuilder
    ) {
        return format!(
            "rcg::{}::{}",
            diag.rule.as_str(),
            normalize_slug(&diag.target_name)
        );
    }

    let file_key = normalize_path_key(&diag.file);
    if diag.rule.is_architecture_soc_or_reuse_rule() {
        let slug_source = if diag.target_name.is_empty() {
            diag.subject_name.as_deref().unwrap_or(diag.rule.as_str())
        } else {
            &diag.target_name
        };
        return format!(
            "rcg::{}::{}::{}",
            diag.rule.as_str(),
            file_key,
            normalize_slug(slug_source)
        );
    }
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

/// Builds deterministic [`RootCauseGroup`]s (sorted by [`BlastRadius`] descending) and
/// self-contained [`FixCapsule`]s for all `Surgical` and `Refactor` groups.
#[must_use]
pub fn build_root_cause_groups_and_capsules<C: PlannerContext + ?Sized>(
    ctx: &C,
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
            let blast_radius = compute_blast_radius(ctx, &indices, diagnostics, sources);
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
        .map(|group| build_fix_capsule(ctx, group, diagnostics, sources))
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

fn compute_blast_radius<C: PlannerContext + ?Sized>(
    ctx: &C,
    indices: &[usize],
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> BlastRadius {
    let first = &diagnostics[indices[0]];
    let meta = first.rule.metadata();

    let render_frequency = detect_render_frequency(ctx, indices, diagnostics, sources);
    let fan_out = compute_group_fan_out(ctx, indices, diagnostics, sources);
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

fn detect_render_frequency<C: PlannerContext + ?Sized>(
    ctx: &C,
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

        if ctx.span_in_list_loop(&diag.file, diag.span) {
            has_list_loop = true;
        }

        let Some(subj_name) = &diag.subject_name else {
            continue;
        };
        if subject_uses_frame_loop(ctx, &diag.file, subj_name, sources) {
            return RenderFrequency::FrameLoop60Fps;
        }
        if ctx.subject_rendered_in_list_loop(&diag.file, subj_name) {
            has_list_loop = true;
        }
    }

    if has_list_loop {
        RenderFrequency::ListLoop
    } else {
        RenderFrequency::Standard
    }
}

fn subject_uses_frame_loop<C: PlannerContext + ?Sized>(
    ctx: &C,
    file_path: &Path,
    subj_name: &str,
    sources: &HashMap<PathBuf, String>,
) -> bool {
    let Some((_, subj_span)) = ctx
        .subject_spans_for_file(file_path)
        .into_iter()
        .find(|(name, _)| name.as_deref() == Some(subj_name))
    else {
        return false;
    };
    let Some(src) = sources.get(file_path) else {
        return false;
    };
    let Some(subj_src) = slice_span(src, subj_span) else {
        return false;
    };
    subj_src.contains("useFrame(") || subj_src.contains("requestAnimationFrame(")
}

fn compute_group_fan_out<C: PlannerContext + ?Sized>(
    ctx: &C,
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
            for caller in ctx.callers_of(&diag.file, subj_name) {
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
        {
            for child in ctx.child_components_of(&diag.file, subj_name) {
                child_components.insert(child);
            }
        }
    }

    let mut context_consumers = 0_usize;
    for ctx_name in &context_names {
        context_consumers += ctx.count_context_consumers(ctx_name, sources);
    }

    caller_keys.len() + context_consumers + child_components.len()
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

/// Builds a self-contained [`FixCapsule`] for a [`RootCauseGroup`].
#[must_use]
pub fn build_fix_capsule<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> FixCapsule {
    let primary_diag = &diagnostics[group.diagnostic_indices[0]];
    let subject_excerpt = build_subject_excerpt(ctx, primary_diag, sources);

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
        for caller in ctx.callers_of(&group.file, subj_name) {
            if seen_callers.insert((
                caller.caller_file.clone(),
                caller.loc.line,
                caller.loc.column,
            )) {
                caller_site_excerpts.push(build_caller_site_excerpt(&caller, sources));
            }
        }
    }
    if caller_site_excerpts.is_empty()
        && group.rule.is_architecture_soc_or_reuse_rule()
        && let Some(facets) = ctx.architecture_facets_for_file(&group.file)
        && let Some(source) = sources.get(&group.file)
    {
        for span in collect_architecture_signal_spans(facets) {
            let excerpt = excerpt_from_span(&group.file, source, span);
            if seen_callers.insert((group.file.clone(), excerpt.start_line, 1)) {
                caller_site_excerpts.push(excerpt);
            }
        }
    }

    let exemplar = find_repository_exemplar(ctx, group, diagnostics, sources);
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

fn build_subject_excerpt<C: PlannerContext + ?Sized>(
    ctx: &C,
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

    let subj_spans = ctx.subject_spans_for_file(&diag.file);
    if let Some(subj_name) = &diag.subject_name
        && let Some((_, span)) = subj_spans
            .iter()
            .find(|(name, _)| name.as_deref() == Some(subj_name.as_str()))
    {
        return excerpt_from_span(&diag.file, source, *span);
    }
    if let Some((_, span)) = subj_spans
        .iter()
        .find(|(_, span)| spans_intersect(*span, diag.span))
    {
        return excerpt_from_span(&diag.file, source, *span);
    }

    excerpt_from_span(&diag.file, source, diag.span)
}

/// Builds a [`SourceExcerpt`] for a resolved [`ResolvedCallerSite`].
#[must_use]
pub fn build_caller_site_excerpt(
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

/// Extracts a 1-based line-bounded [`SourceExcerpt`] covering `span` in `source`.
#[must_use]
pub fn excerpt_from_span(file: &Path, source: &str, span: ByteSpan) -> SourceExcerpt {
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

fn find_repository_exemplar<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    if group.rule == RuleId::NoResetAllStateOnPropChange {
        for &idx in &group.diagnostic_indices {
            if let Some(valid_caller) = diagnostics[idx].caller_sites.iter().find(|c| c.has_key) {
                return Some(build_caller_site_excerpt(valid_caller, sources));
            }
        }
    }

    if let Some(rule_ex) = ctx.find_rule_exemplar(group, diagnostics, sources) {
        return Some(rule_ex);
    }

    let flagged_subjects: BTreeSet<(&Path, Option<&str>)> = diagnostics
        .iter()
        .map(|d| (d.file.as_path(), d.subject_name.as_deref()))
        .collect();

    let mut sorted_files = ctx.analyzed_files();
    sorted_files.sort();

    for same_lang_pass in [true, false] {
        for file_path in &sorted_files {
            if same_lang_pass != same_language_family(&group.file, file_path) {
                continue;
            }
            let Some(src) = sources.get(file_path) else {
                continue;
            };
            for (subj_name, subj_span) in ctx.subject_spans_for_file(file_path) {
                if subj_name.is_some()
                    && !flagged_subjects.contains(&(file_path.as_path(), subj_name.as_deref()))
                {
                    return Some(excerpt_from_span(file_path, src, subj_span));
                }
            }
        }
    }

    None
}

fn collect_architecture_signal_spans(facets: &ArchitectureFileFacets) -> Vec<ByteSpan> {
    let mut spans = Vec::new();
    for sig in &facets.concern_signals {
        if sig.span.end > sig.span.start {
            spans.push(sig.span);
        }
    }
    for cat in &facets.static_catalog_sites {
        if cat.span.end > cat.span.start {
            spans.push(cat.span);
        }
    }
    for ui in &facets.inline_terminal_ui_sites {
        if ui.span.end > ui.span.start {
            spans.push(ui.span);
        }
    }
    for lit in &facets.struct_literal_sites {
        if lit.span.end > lit.span.start {
            spans.push(lit.span);
        }
    }
    for helper in &facets.helper_fingerprints {
        if helper.span.end > helper.span.start {
            spans.push(helper.span);
        }
    }
    spans
}

fn find_architecture_exemplar_in_extracted_files(
    files: &[ExtractedFile],
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    if !group.rule.is_architecture_soc_or_reuse_rule() {
        return None;
    }

    let flagged_for_rule: BTreeSet<&Path> = diagnostics
        .iter()
        .filter(|d| d.rule == group.rule)
        .map(|d| d.file.as_path())
        .collect();

    let mut ordered: Vec<&ExtractedFile> = files
        .iter()
        .filter(|f| f.path != group.file && !flagged_for_rule.contains(f.path.as_path()))
        .collect();
    ordered.sort_by(|a, b| {
        let a_same = same_language_family(&group.file, &a.path);
        let b_same = same_language_family(&group.file, &b.path);
        b_same.cmp(&a_same).then_with(|| a.path.cmp(&b.path))
    });

    if group.rule == RuleId::ArchNoInlineTerminalUiPrimitives {
        if let Some(ui_file) = ordered.iter().copied().find(|f| {
            f.architecture_facets.is_ui_kit_module
                || f.path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s == "ui" || s.ends_with("_ui"))
        }) && let Some(ex) = excerpt_for_extracted_file(ui_file, sources)
        {
            return Some(ex);
        }
    } else if group.rule == RuleId::ArchPreferFluentBuilder
        && let Some(builder_file) = ordered
            .iter()
            .copied()
            .find(|f| {
                f.architecture_facets
                    .defined_builder_types
                    .iter()
                    .any(|t| t == &group.target_name)
            })
            .or_else(|| {
                ordered
                    .iter()
                    .copied()
                    .find(|f| !f.architecture_facets.defined_builder_types.is_empty())
            })
        && let Some(ex) = excerpt_for_extracted_file(builder_file, sources)
    {
        return Some(ex);
    }

    if let Some(cohesive) = ordered
        .iter()
        .copied()
        .find(|f| f.architecture_facets.distinct_concern_buckets().len() == 1)
        && let Some(ex) = excerpt_for_extracted_file(cohesive, sources)
    {
        return Some(ex);
    }

    for candidate in ordered {
        if let Some(ex) = excerpt_for_extracted_file(candidate, sources) {
            return Some(ex);
        }
    }

    None
}

fn excerpt_for_extracted_file(
    file: &ExtractedFile,
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    let src = sources
        .get(&file.path)
        .map_or(file.source.as_str(), String::as_str);
    if src.is_empty() {
        return None;
    }
    if let Some((_, span, _)) = file.subject_spans.iter().find(|(n, _, _)| n.is_some()) {
        return Some(excerpt_from_span(&file.path, src, *span));
    }
    if let Some(sym) = file.symbol_outlines.first() {
        return Some(excerpt_from_span(&file.path, src, sym.span));
    }
    let end = u32::try_from(src.len()).unwrap_or(0);
    Some(excerpt_from_span(
        &file.path,
        src,
        ByteSpan { start: 0, end },
    ))
}

fn same_language_family(a: &Path, b: &Path) -> bool {
    match (LanguageId::from_path(a), LanguageId::from_path(b)) {
        (
            Some(LanguageId::JavaScript | LanguageId::TypeScript),
            Some(LanguageId::JavaScript | LanguageId::TypeScript),
        ) => true,
        (Some(la), Some(lb)) => la == lb,
        _ => true,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only state/effect rules add custom invariants beyond the tier-based default"
)]
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
        RuleId::ArchThinEntrypoint => {
            inv.push("Keep the entrypoint as a thin adapter that parses CLI/HTTP inputs, delegates to library modules, and maps results to exit/status codes.");
        }
        RuleId::ArchNoMixedIoAndPresentation => {
            inv.push("Separate data/network/filesystem I/O functions from terminal/UI presentation into dedicated modules with pure data transfer structs at the boundary.");
        }
        RuleId::ArchSeparateStaticCatalogFromTypes => {
            inv.push("Move large static data tables and constant registries into a dedicated catalog submodule while keeping core domain type definitions in a focused types module.");
        }
        RuleId::ArchNoMixedDomainMonolith => {
            inv.push("Decompose unrelated domain symbol clusters into focused domain submodules and re-export the public contract at the package/module boundary.");
        }
        RuleId::ArchNoInlineTerminalUiPrimitives => {
            inv.push("Route all ANSI escape sequences and Unicode box-drawing output through the shared terminal UI component kit instead of inline string literals.");
        }
        RuleId::ArchPreferFluentBuilder => {
            inv.push("Provide a constructor or fluent `with_*` builder on the type and replace repetitive multi-field literal construction sites across modules.");
        }
        RuleId::ArchNoDuplicatedHelperLogic => {
            inv.push("Extract duplicated private helper logic with identical AST structure into a shared internal utility or matcher module.");
        }
        RuleId::RsArchPreferPubCrateModules => {
            inv.push("Narrow internal submodule declarations from `pub mod` to `pub(crate) mod` (or private `mod`) when the crate root already re-exports the public API surface.");
        }
        RuleId::RsArchNoLegacyModRs => {
            inv.push("Replace `<dir>/mod.rs` with a sibling `<dir>.rs` module file alongside the `<dir>/` submodule directory.");
        }
        _ => match tier {
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

fn excerpt_code_fence_lang(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py" | "pyi") => "python",
        Some("rs") => "rust",
        _ => "tsx",
    }
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

    let subj_lang = excerpt_code_fence_lang(&capsule.subject_excerpt.file);
    let _ = writeln!(
        md,
        "## Subject Excerpt (`{}:{}-{}`)\n",
        capsule.subject_excerpt.file.display(),
        capsule.subject_excerpt.start_line,
        capsule.subject_excerpt.end_line
    );
    let _ = writeln!(
        md,
        "```{subj_lang}\n{}\n```\n",
        capsule.subject_excerpt.source
    );

    if !capsule.caller_site_excerpts.is_empty() {
        let _ = writeln!(
            md,
            "## Caller Site Excerpts ({})\n",
            capsule.caller_site_excerpts.len()
        );
        for caller_ex in &capsule.caller_site_excerpts {
            let caller_lang = excerpt_code_fence_lang(&caller_ex.file);
            let _ = writeln!(
                md,
                "### `{}:{}-{}`\n",
                caller_ex.file.display(),
                caller_ex.start_line,
                caller_ex.end_line
            );
            let _ = writeln!(md, "```{caller_lang}\n{}\n```\n", caller_ex.source);
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
        let ex_lang = excerpt_code_fence_lang(&exemplar.file);
        let _ = writeln!(
            md,
            "## Repository Exemplar (`{}:{}-{}`)\n",
            exemplar.file.display(),
            exemplar.start_line,
            exemplar.end_line
        );
        let _ = writeln!(md, "```{ex_lang}\n{}\n```\n", exemplar.source);
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

/// Returns `true` if byte spans `a` and `b` overlap or touch.
#[must_use]
pub const fn spans_intersect(a: ByteSpan, b: ByteSpan) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// Safely slices `source` at UTF-8 char boundaries `[span.start, span.end)`.
#[must_use]
pub fn slice_span(source: &str, span: ByteSpan) -> Option<&str> {
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
