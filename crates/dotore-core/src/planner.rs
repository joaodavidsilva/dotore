//! Deterministic remediation planner: **Root-Cause Grouping**, static **Blast Radius**
//! calculation, repository **Exemplar** discovery, **Fix Capsule** assembly, and
//! Markdown execution plan generation (`dotore plan`).

mod capsules;
mod handoff;
mod markdown;

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use crate::{
    ir::{ArchitectureFileFacets, ByteSpan, ExtractedFile, ResolvedCallerSite},
    rules::{
        BlastRadius, BlastRadiusTier, Diagnostic, FixCapsule, PrescriptionTier, RenderFrequency,
        RootCauseGroup, RuleCategory, RuleId, RuleSeverity, RuleTag, SourceExcerpt,
    },
};

use self::capsules::{build_fix_capsule_cached, find_architecture_exemplar_in_extracted_files};
pub(crate) use self::capsules::invariants_for_rule;
pub use self::{
    capsules::{
        build_caller_site_excerpt, build_fix_capsule, excerpt_from_span,
        find_architecture_exemplar_from_facets,
    },
    handoff::*,
    markdown::*,
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
                    Some("css" | "scss" | "html" | "htm" | "yml" | "yaml")
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

    let mut sorted_files = ctx.analyzed_files();
    sorted_files.sort();
    let subject_spans_by_file: HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>> = sorted_files
        .iter()
        .map(|p| (p.clone(), ctx.subject_spans_for_file(p)))
        .collect();

    let mut groups: Vec<RootCauseGroup> = group_order
        .into_iter()
        .filter_map(|id| {
            let indices = grouped_indices.remove(&id)?;
            let first = diagnostics.get(*indices.first()?)?;
            let severity = if indices
                .iter()
                .any(|&i| diagnostics.get(i).is_some_and(|d| d.severity == RuleSeverity::Error))
            {
                RuleSeverity::Error
            } else {
                RuleSeverity::Warning
            };
            let tier = group_prescription_tier(&indices, diagnostics);
            let blast_radius =
                compute_blast_radius(ctx, &indices, diagnostics, sources, &subject_spans_by_file);
            let first_msg = crate::report::mask_credentials(&first.message);
            let message = if indices.len() > 1 {
                format!(
                    "{first_msg} ({} related sites in Root-Cause Group)",
                    indices.len()
                )
            } else {
                first_msg
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

    let flagged_subjects: BTreeSet<(&Path, Option<&str>)> = diagnostics
        .iter()
        .map(|d| (d.file.as_path(), d.subject_name.as_deref()))
        .collect();
    let mut fallback_exemplar_cache: HashMap<u8, Option<SourceExcerpt>> = HashMap::new();
    let mut rule_exemplar_cache: HashMap<(RuleId, u8), Option<SourceExcerpt>> = HashMap::new();

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
                &mut rule_exemplar_cache,
            )
        })
        .collect();

    (groups, capsules)
}

fn group_prescription_tier(indices: &[usize], diagnostics: &[Diagnostic]) -> PrescriptionTier {
    if indices
        .iter()
        .any(|&i| diagnostics.get(i).is_some_and(|d| d.tier == PrescriptionTier::Refactor))
    {
        PrescriptionTier::Refactor
    } else if indices
        .iter()
        .any(|&i| diagnostics.get(i).is_some_and(|d| d.tier == PrescriptionTier::Surgical))
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
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
) -> BlastRadius {
    let Some(first) = indices.first().and_then(|&i| diagnostics.get(i)) else {
        return empty_blast_radius();
    };
    let render_frequency =
        detect_render_frequency(ctx, indices, diagnostics, sources, subject_spans_by_file);
    let fan_out = compute_group_fan_out(ctx, indices, diagnostics, sources);
    let cascade_depth = indices
        .iter()
        .filter_map(|&i| diagnostics.get(i).map(|d| d.cascade_steps.len()))
        .max()
        .unwrap_or(0);
    let site_count = if first.rule == RuleId::DuplicateJsxSubtree
        && !first.caller_sites.is_empty()
        && indices.len() == 1
    {
        first.caller_sites.len()
    } else {
        indices.len()
    };
    let file_count = count_touched_files(indices, diagnostics);
    let severity = group_max_severity(indices, diagnostics);
    let is_minor_design_warning = first.rule.metadata().tags.contains(&RuleTag::Design)
        && severity == RuleSeverity::Warning
        && fan_out == 0
        && cascade_depth == 0;

    let raw_score = compute_raw_blast_score(
        severity,
        first.category,
        is_minor_design_warning,
        render_frequency,
        cascade_depth,
        fan_out,
        site_count,
        file_count,
    );
    let tier = classify_blast_radius_tier(
        severity,
        first.category,
        is_minor_design_warning,
        render_frequency,
        fan_out,
        cascade_depth,
        raw_score,
    );
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

const fn empty_blast_radius() -> BlastRadius {
    BlastRadius {
        score: 0,
        tier: BlastRadiusTier::P3,
        fan_out: 0,
        cascade_depth: 0,
        render_frequency: RenderFrequency::Standard,
        site_count: 0,
        file_count: 0,
    }
}

fn count_touched_files(indices: &[usize], diagnostics: &[Diagnostic]) -> usize {
    let mut touched_files: BTreeSet<&Path> = BTreeSet::new();
    for &idx in indices {
        if let Some(d) = diagnostics.get(idx) {
            touched_files.insert(d.file.as_path());
            for caller in &d.caller_sites {
                touched_files.insert(caller.caller_file.as_path());
            }
        }
    }
    touched_files.len().max(1)
}

fn group_max_severity(indices: &[usize], diagnostics: &[Diagnostic]) -> RuleSeverity {
    if indices
        .iter()
        .any(|&i| diagnostics.get(i).is_some_and(|d| d.severity == RuleSeverity::Error))
    {
        RuleSeverity::Error
    } else {
        RuleSeverity::Warning
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Combines all static Blast Radius dimensions into the raw score (#50)"
)]
fn compute_raw_blast_score(
    severity: RuleSeverity,
    category: RuleCategory,
    is_minor_design_warning: bool,
    render_frequency: RenderFrequency,
    cascade_depth: usize,
    fan_out: usize,
    site_count: usize,
    file_count: usize,
) -> u32 {
    let severity_pts: u32 = match severity {
        RuleSeverity::Error => 30,
        RuleSeverity::Warning => 10,
    };
    let category_pts: u32 = if is_minor_design_warning {
        5
    } else {
        match category {
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
    match render_frequency {
        RenderFrequency::FrameLoop60Fps => base_score.saturating_mul(2),
        RenderFrequency::ListLoop => (base_score.saturating_mul(3)) / 2,
        RenderFrequency::Standard => base_score,
    }
}

fn classify_blast_radius_tier(
    severity: RuleSeverity,
    category: RuleCategory,
    is_minor_design_warning: bool,
    render_frequency: RenderFrequency,
    fan_out: usize,
    cascade_depth: usize,
    raw_score: u32,
) -> BlastRadiusTier {
    if is_p0_blast_radius(severity, category, render_frequency, fan_out, cascade_depth, raw_score) {
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
            || category != RuleCategory::Maintainability)
    {
        BlastRadiusTier::P2
    } else {
        BlastRadiusTier::P3
    }
}

const fn is_p0_blast_radius(
    severity: RuleSeverity,
    category: RuleCategory,
    render_frequency: RenderFrequency,
    fan_out: usize,
    cascade_depth: usize,
    raw_score: u32,
) -> bool {
    matches!(render_frequency, RenderFrequency::FrameLoop60Fps)
        || (matches!(category, RuleCategory::Security) && matches!(severity, RuleSeverity::Error))
        || (matches!(severity, RuleSeverity::Error)
            && matches!(category, RuleCategory::Bugs)
            && (fan_out >= 2 || cascade_depth >= 3))
        || raw_score >= 100
}

fn detect_render_frequency<C: PlannerContext + ?Sized>(
    ctx: &C,
    indices: &[usize],
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
) -> RenderFrequency {
    let mut has_list_loop = false;

    for &idx in indices {
        let Some(diag) = diagnostics.get(idx) else {
            continue;
        };
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
        if subject_uses_frame_loop(ctx, &diag.file, subj_name, sources, subject_spans_by_file) {
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
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
) -> bool {
    let owned_fallback;
    let spans = if let Some(cached) = subject_spans_by_file.get(file_path) {
        cached.as_slice()
    } else {
        owned_fallback = ctx.subject_spans_for_file(file_path);
        owned_fallback.as_slice()
    };
    let Some((_, subj_span)) = spans
        .iter()
        .find(|(name, _)| name.as_deref() == Some(subj_name))
    else {
        return false;
    };
    let Some(src) = sources.get(file_path) else {
        return false;
    };
    let Some(subj_src) = slice_span(src, *subj_span) else {
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
        let Some(diag) = diagnostics.get(idx) else {
            continue;
        };
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

