//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, repository **Exemplar** discovery, **Fix Capsule** assembly, and
//! Markdown execution plan generation (`dotore plan`).

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{resolve_dotore_home_dir, write_file_atomically},
    ir::{
        ArchitectureFileFacets, ByteSpan, ExtractedFile, LanguageId, ResolvedCallerSite,
        compute_line_starts, loc_from_line_starts,
    },
    report::{JsonReport, ReportSummary, write_json_report},
    rules::{
        BlastRadius, BlastRadiusTier, Diagnostic, FixCapsule, PrescriptionTier, RenderFrequency,
        RootCauseGroup, RuleCategory, RuleId, RuleSeverity, RuleTag, SourceExcerpt,
    },
    score::compute_local_health_score,
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

    let mut sorted_files = ctx.analyzed_files();
    sorted_files.sort();
    let subject_spans_by_file: HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>> = sorted_files
        .iter()
        .map(|p| (p.clone(), ctx.subject_spans_for_file(p)))
        .collect();
    let flagged_subjects: BTreeSet<(&Path, Option<&str>)> = diagnostics
        .iter()
        .map(|d| (d.file.as_path(), d.subject_name.as_deref()))
        .collect();
    let mut fallback_exemplar_cache: HashMap<u8, Option<SourceExcerpt>> = HashMap::new();

    let capsules: Vec<FixCapsule> = groups
        .iter()
        .filter(|g| {
            matches!(
                g.tier,
                PrescriptionTier::Surgical | PrescriptionTier::Refactor
            )
        })
        .map(|group| {
            build_fix_capsule_cached(
                ctx,
                group,
                diagnostics,
                sources,
                &sorted_files,
                &subject_spans_by_file,
                &flagged_subjects,
                &mut fallback_exemplar_cache,
            )
        })
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
    let mut sorted_files = ctx.analyzed_files();
    sorted_files.sort();
    let subject_spans_by_file: HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>> = sorted_files
        .iter()
        .map(|p| (p.clone(), ctx.subject_spans_for_file(p)))
        .collect();
    let flagged_subjects: BTreeSet<(&Path, Option<&str>)> = diagnostics
        .iter()
        .map(|d| (d.file.as_path(), d.subject_name.as_deref()))
        .collect();
    let mut fallback_exemplar_cache: HashMap<u8, Option<SourceExcerpt>> = HashMap::new();
    build_fix_capsule_cached(
        ctx,
        group,
        diagnostics,
        sources,
        &sorted_files,
        &subject_spans_by_file,
        &flagged_subjects,
        &mut fallback_exemplar_cache,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Passes precomputed file index, subject spans, and exemplar cache across groups"
)]
fn build_fix_capsule_cached<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    sorted_files: &[PathBuf],
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
    flagged_subjects: &BTreeSet<(&Path, Option<&str>)>,
    fallback_exemplar_cache: &mut HashMap<u8, Option<SourceExcerpt>>,
) -> FixCapsule {
    let primary_diag = &diagnostics[group.diagnostic_indices[0]];
    let subject_excerpt =
        build_subject_excerpt_cached(ctx, primary_diag, sources, subject_spans_by_file);

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

    let exemplar = find_repository_exemplar_cached(
        ctx,
        group,
        diagnostics,
        sources,
        sorted_files,
        subject_spans_by_file,
        flagged_subjects,
        fallback_exemplar_cache,
    );
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

fn build_subject_excerpt_cached<C: PlannerContext + ?Sized>(
    ctx: &C,
    diag: &Diagnostic,
    sources: &HashMap<PathBuf, String>,
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
) -> SourceExcerpt {
    let Some(source) = sources.get(&diag.file) else {
        return SourceExcerpt {
            file: diag.file.clone(),
            start_line: diag.loc.line,
            end_line: diag.loc.line,
            source: String::new(),
        };
    };

    let owned_fallback;
    let subj_spans = if let Some(cached) = subject_spans_by_file.get(&diag.file) {
        cached.as_slice()
    } else {
        owned_fallback = ctx.subject_spans_for_file(&diag.file);
        owned_fallback.as_slice()
    };
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

    let start_line_idx = (start_loc.line as usize).saturating_sub(1);
    let end_line_idx = end_loc.line as usize;
    let sliced = if let Some(&start_byte_u32) = line_starts.get(start_line_idx) {
        let start_byte = start_byte_u32 as usize;
        let mut end_byte = line_starts
            .get(end_line_idx)
            .map_or(source.len(), |&b| (b as usize).saturating_sub(1));
        if end_byte > start_byte
            && source.as_bytes().get(end_byte.saturating_sub(1)) == Some(&b'\r')
        {
            end_byte -= 1;
        }
        source
            .get(start_byte..end_byte.max(start_byte))
            .unwrap_or_default()
            .replace("\r\n", "\n")
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

fn language_family_bucket(path: &Path) -> u8 {
    match LanguageId::from_path(path) {
        Some(LanguageId::JavaScript | LanguageId::TypeScript) => 1,
        Some(LanguageId::Python) => 2,
        Some(LanguageId::Rust) => 3,
        _ => 0,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Uses precomputed file/subject maps and language-family exemplar cache"
)]
fn find_repository_exemplar_cached<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    sorted_files: &[PathBuf],
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
    flagged_subjects: &BTreeSet<(&Path, Option<&str>)>,
    fallback_exemplar_cache: &mut HashMap<u8, Option<SourceExcerpt>>,
) -> Option<SourceExcerpt> {
    if group.rule == RuleId::NoResetAllStateOnPropChange {
        for &idx in &group.diagnostic_indices {
            if let Some(valid_caller) = diagnostics[idx].caller_sites.iter().find(|c| c.has_key) {
                return Some(build_caller_site_excerpt(valid_caller, sources));
            }
        }
    }

    let lang_bucket = language_family_bucket(&group.file);
    if group.rule.is_architecture_soc_or_reuse_rule() {
        let cache_key = 0x80 | lang_bucket;
        if let Some(cached) = fallback_exemplar_cache.get(&cache_key)
            && let Some(ex) = cached
            && ex.file != group.file
        {
            return Some(ex.clone());
        }
        if let Some(rule_ex) = ctx.find_rule_exemplar(group, diagnostics, sources) {
            fallback_exemplar_cache.insert(cache_key, Some(rule_ex.clone()));
            return Some(rule_ex);
        }
    } else if let Some(rule_ex) = ctx.find_rule_exemplar(group, diagnostics, sources) {
        return Some(rule_ex);
    }
    let lang_bucket = language_family_bucket(&group.file);
    if let Some(cached) = fallback_exemplar_cache.get(&lang_bucket) {
        return cached.clone();
    }

    let mut resolved = None;
    for same_lang_pass in [true, false] {
        if resolved.is_some() {
            break;
        }
        for file_path in sorted_files {
            if same_lang_pass != same_language_family(&group.file, file_path) {
                continue;
            }
            let Some(src) = sources.get(file_path) else {
                continue;
            };
            let Some(spans) = subject_spans_by_file.get(file_path) else {
                continue;
            };
            if let Some((_, subj_span)) = spans.iter().find(|(subj_name, _)| {
                subj_name.is_some()
                    && !flagged_subjects.contains(&(file_path.as_path(), subj_name.as_deref()))
            }) {
                resolved = Some(excerpt_from_span(file_path, src, *subj_span));
                break;
            }
        }
    }

    fallback_exemplar_cache.insert(lang_bucket, resolved.clone());
    resolved
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

    let candidates = ordered.into_iter().map(|f| {
        let primary_span = f
            .subject_spans
            .iter()
            .find(|(n, _, _)| n.is_some())
            .map(|(_, span, _)| *span)
            .or_else(|| f.symbol_outlines.first().map(|sym| sym.span));
        (
            f.path.as_path(),
            f.source.as_str(),
            &f.architecture_facets,
            primary_span,
        )
    });

    find_architecture_exemplar_from_facets(group.rule, &group.file, candidates, sources)
}

/// Selects the best repository **Exemplar** [`SourceExcerpt`] for an architecture/SoC/reuse rule
/// from an ordered iterator of unflagged candidate files `(path, fallback_source, facets, primary_span)`.
#[must_use]
pub fn find_architecture_exemplar_from_facets<'a, I>(
    rule: RuleId,
    group_file: &Path,
    files: I,
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt>
where
    I: IntoIterator<
        Item = (
            &'a Path,
            &'a str,
            &'a ArchitectureFileFacets,
            Option<ByteSpan>,
        ),
    >,
{
    if !rule.is_architecture_soc_or_reuse_rule() {
        return None;
    }

    let candidates: Vec<(
        &'a Path,
        &'a str,
        &'a ArchitectureFileFacets,
        Option<ByteSpan>,
    )> = files
        .into_iter()
        .filter(|(p, _, _, _)| *p != group_file)
        .collect();

    let build_excerpt = |path: &Path,
                         fallback_src: &str,
                         primary_span: Option<ByteSpan>|
     -> Option<SourceExcerpt> {
        let src = sources.get(path).map_or(fallback_src, String::as_str);
        if src.is_empty() {
            return None;
        }
        if let Some(span) = primary_span {
            return Some(excerpt_from_span(path, src, span));
        }
        let end = u32::try_from(src.len()).unwrap_or(0);
        Some(excerpt_from_span(path, src, ByteSpan { start: 0, end }))
    };

    if rule == RuleId::ArchNoInlineTerminalUiPrimitives {
        if let Some(&(path, src, _, span)) = candidates.iter().find(|(path, _, facets, _)| {
            facets.is_ui_kit_module
                || path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s == "ui" || s.ends_with("_ui") || s.ends_with("-ui"))
        }) && let Some(ex) = build_excerpt(path, src, span)
        {
            return Some(ex);
        }
    } else if rule == RuleId::ArchPreferFluentBuilder
        && let Some(&(path, src, _, span)) = candidates
            .iter()
            .find(|(_, _, facets, _)| !facets.defined_builder_types.is_empty())
        && let Some(ex) = build_excerpt(path, src, span)
    {
        return Some(ex);
    }

    if let Some(&(path, src, _, span)) = candidates
        .iter()
        .find(|(_, _, facets, _)| facets.distinct_concern_buckets().len() == 1)
        && let Some(ex) = build_excerpt(path, src, span)
    {
        return Some(ex);
    }

    for (path, src, _, span) in candidates {
        if let Some(ex) = build_excerpt(path, src, span) {
            return Some(ex);
        }
    }

    None
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
pub(crate) fn invariants_for_rule(rule: RuleId, tier: PrescriptionTier) -> Vec<&'static str> {
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
        let da = &report.diagnostics[a];
        let db = &report.diagnostics[b];
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
        .map(|&idx| report.diagnostics[idx].file.as_path())
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
        "Findings: {} across {} file(s)",
        matching_indices.len(),
        distinct_files.len()
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "Transformation Recipe:");
    let _ = writeln!(out, "{}", meta.recipe_markdown);
    let _ = writeln!(out);

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
        let d = &report.diagnostics[idx];
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
            d.message
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
        let ordinal = idx + 1;
        let meta = group.rule.metadata();
        let subject = group
            .subject_name
            .as_deref()
            .unwrap_or(group.target_name.as_str());
        let capsule = report
            .fix_capsules
            .iter()
            .find(|c| c.root_cause_group_id == group.id);

        let _ = writeln!(
            md,
            "### {ordinal}. `{}` in `{}` (`{}:{}`)\n",
            group.rule.as_str(),
            if subject.is_empty() {
                "<module>"
            } else {
                subject
            },
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
                    d.message
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

        if let Some(cap) = capsule
            && !cap.subject_excerpt.source.is_empty()
        {
            let lang = excerpt_code_fence_lang(&cap.subject_excerpt.file);
            let _ = writeln!(
                md,
                "#### Subject Excerpt (`{}:{}-{}`)\n",
                cap.subject_excerpt.file.display(),
                cap.subject_excerpt.start_line,
                cap.subject_excerpt.end_line
            );
            let _ = writeln!(md, "```{lang}\n{}\n```\n", cap.subject_excerpt.source);
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
                    caller_ex.source
                );
            }
            let _ = writeln!(md);
        }

        let recipe = capsule.map_or(meta.recipe_markdown, |c| c.recipe_markdown);
        let _ = writeln!(md, "#### Canonical Transformation Recipe\n");
        let _ = writeln!(md, "{recipe}\n");

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
                "#### Repository Exemplar (`{}:{}-{}`)\n",
                exemplar.file.display(),
                exemplar.start_line,
                exemplar.end_line
            );
            let _ = writeln!(md, "```{ex_lang}\n{}\n```\n", exemplar.source);
        }
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

/// Builds a filtered [`JsonReport`] containing only `selected_diagnostics` and their corresponding
/// [`RootCauseGroup`]s, [`FixCapsule`]s, and summary counts (used by TUI `y`/`a` handoff).
#[must_use]
pub fn filter_report_for_diagnostics(
    report: &JsonReport,
    selected_diagnostics: &[&Diagnostic],
) -> JsonReport {
    let mut diagnostics = Vec::with_capacity(selected_diagnostics.len());
    let mut old_to_new: HashMap<usize, usize> = HashMap::with_capacity(selected_diagnostics.len());

    for &sel in selected_diagnostics {
        let new_idx = diagnostics.len();
        if let Some(old_idx) = report
            .diagnostics
            .iter()
            .position(|d| std::ptr::eq(d, sel) || d == sel)
        {
            old_to_new.entry(old_idx).or_insert(new_idx);
        }
        diagnostics.push(sel.clone());
    }

    let mut root_cause_groups = Vec::new();
    let mut kept_group_ids: BTreeSet<String> = BTreeSet::new();
    for group in &report.root_cause_groups {
        let remapped: Vec<usize> = group
            .diagnostic_indices
            .iter()
            .filter_map(|old_idx| old_to_new.get(old_idx).copied())
            .collect();
        if !remapped.is_empty() {
            let mut cloned_group = group.clone();
            cloned_group.blast_radius.site_count = remapped.len();
            cloned_group.diagnostic_indices = remapped;
            kept_group_ids.insert(cloned_group.id.clone());
            root_cause_groups.push(cloned_group);
        }
    }

    let fix_capsules: Vec<FixCapsule> = report
        .fix_capsules
        .iter()
        .filter(|c| kept_group_ids.contains(&c.root_cause_group_id))
        .cloned()
        .collect();

    let mut error_count = 0usize;
    let mut warning_count = 0usize;
    let mut autofix_count = 0usize;
    let mut surgical_count = 0usize;
    let mut refactor_count = 0usize;
    let mut affected_files: BTreeSet<&Path> = BTreeSet::new();

    for d in &diagnostics {
        match d.severity {
            RuleSeverity::Error => error_count += 1,
            RuleSeverity::Warning => warning_count += 1,
        }
        match d.tier {
            PrescriptionTier::Autofix => autofix_count += 1,
            PrescriptionTier::Surgical => surgical_count += 1,
            PrescriptionTier::Refactor => refactor_count += 1,
        }
        affected_files.insert(d.file.as_path());
    }

    let hs = compute_local_health_score(
        &root_cause_groups,
        report.summary.files_scanned,
        report.summary.subjects_scanned,
    );

    let summary = ReportSummary {
        files_scanned: report.summary.files_scanned,
        subjects_scanned: report.summary.subjects_scanned,
        effects_scanned: report.summary.effects_scanned,
        total_diagnostics: diagnostics.len(),
        error_count,
        warning_count,
        affected_file_count: affected_files.len(),
        autofix_count,
        surgical_count,
        refactor_count,
        health_score: hs.score,
        score_label: hs.label,
    };

    JsonReport {
        schema_version: report.schema_version,
        mode: report.mode,
        summary,
        projects: report.projects.clone(),
        diagnostics,
        root_cause_groups,
        fix_capsules,
        diagnostic_fingerprints: report.diagnostic_fingerprints.clone(),
        diff: report.diff.clone(),
        baseline: report.baseline.clone(),
        baseline_degraded: report.baseline_degraded,
    }
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
        | HandoffTarget::Opencode => {
            let Some(bin_path) = resolve_agent_binary_path(target) else {
                return Err(format!(
                    "Coding agent CLI '{}' was not found on PATH",
                    target.as_str()
                ));
            };
            let pipe_stdin = std::env::var("DOTORE_AGENT_STDIN")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
            let mut cmd = Command::new(&bin_path);
            cmd.arg(&bundle.prompt_markdown)
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
                let _ = stdin.write_all(bundle.prompt_markdown.as_bytes());
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
                    "Handed off {} findings to {} (bundle: {}).\n",
                    report.diagnostics.len(),
                    target.as_str(),
                    bundle_dir.display()
                ))
            } else {
                Ok(stdout)
            }
        }
    }
}
