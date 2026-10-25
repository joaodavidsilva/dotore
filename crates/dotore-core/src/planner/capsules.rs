//! **Fix Capsule** assembly, subject/caller source excerpts, and repository **Exemplar** discovery.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use crate::{
    ir::{
        ArchitectureFileFacets, ByteSpan, ExtractedFile, LanguageId, ResolvedCallerSite,
        compute_line_starts, loc_from_line_starts,
    },
    rules::{Diagnostic, FixCapsule, PrescriptionTier, RootCauseGroup, RuleId, SourceExcerpt},
};

use super::{PlannerContext, slice_span, spans_intersect};

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
    let mut rule_exemplar_cache: HashMap<(RuleId, u8), Option<SourceExcerpt>> = HashMap::new();
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
}

#[expect(
    clippy::too_many_arguments,
    reason = "Passes precomputed file index, subject spans, and exemplar cache across groups (#50)"
)]
pub(super) fn build_fix_capsule_cached<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    sorted_files: &[PathBuf],
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
    flagged_subjects: &BTreeSet<(&Path, Option<&str>)>,
    fallback_exemplar_cache: &mut HashMap<u8, Option<SourceExcerpt>>,
    rule_exemplar_cache: &mut HashMap<(RuleId, u8), Option<SourceExcerpt>>,
) -> FixCapsule {
    let primary_idx = group.diagnostic_indices.first().copied().unwrap_or(0);
    let subject_excerpt = diagnostics.get(primary_idx).map_or_else(
        || SourceExcerpt {
            file: group.file.clone(),
            start_line: group.loc.line,
            end_line: group.loc.line,
            source: String::new(),
        },
        |d| build_subject_excerpt_cached(ctx, d, sources, subject_spans_by_file),
    );

    let caller_site_excerpts = collect_group_caller_site_excerpts(ctx, group, diagnostics, sources);
    let exemplar = find_repository_exemplar_cached(
        ctx,
        group,
        diagnostics,
        sources,
        sorted_files,
        subject_spans_by_file,
        flagged_subjects,
        fallback_exemplar_cache,
        rule_exemplar_cache,
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

fn collect_group_caller_site_excerpts<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Vec<SourceExcerpt> {
    let mut caller_site_excerpts = Vec::new();
    let mut seen_callers: BTreeSet<(PathBuf, u32, u32)> = BTreeSet::new();
    for &idx in &group.diagnostic_indices {
        if let Some(diag) = diagnostics.get(idx) {
            for caller in &diag.caller_sites {
                if seen_callers.insert((
                    caller.caller_file.clone(),
                    caller.loc.line,
                    caller.loc.column,
                )) {
                    caller_site_excerpts.push(build_caller_site_excerpt(caller, sources));
                }
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
    caller_site_excerpts
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
        source: crate::report::mask_credentials(&sliced),
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
    reason = "Uses precomputed file/subject maps and language-family exemplar cache (#50)"
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
    rule_exemplar_cache: &mut HashMap<(RuleId, u8), Option<SourceExcerpt>>,
) -> Option<SourceExcerpt> {
    if group.rule == RuleId::NoResetAllStateOnPropChange
        && let Some(ex) = find_keyed_caller_exemplar(group, diagnostics, sources)
    {
        return Some(ex);
    }

    let lang_bucket = language_family_bucket(&group.file);
    if let Some(ex) = lookup_or_compute_rule_exemplar(
        ctx,
        group,
        diagnostics,
        sources,
        (group.rule, lang_bucket),
        rule_exemplar_cache,
    ) {
        return Some(ex);
    }

    if let Some(cached) = fallback_exemplar_cache.get(&lang_bucket) {
        return cached.clone();
    }

    let resolved = find_unflagged_subject_exemplar(
        &group.file,
        sorted_files,
        sources,
        subject_spans_by_file,
        flagged_subjects,
    );
    fallback_exemplar_cache.insert(lang_bucket, resolved.clone());
    resolved
}

fn find_keyed_caller_exemplar(
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    for &idx in &group.diagnostic_indices {
        if let Some(diag) = diagnostics.get(idx)
            && let Some(valid_caller) = diag.caller_sites.iter().find(|c| c.has_key)
        {
            return Some(build_caller_site_excerpt(valid_caller, sources));
        }
    }
    None
}

fn lookup_or_compute_rule_exemplar<C: PlannerContext + ?Sized>(
    ctx: &C,
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
    rule_key: (RuleId, u8),
    rule_exemplar_cache: &mut HashMap<(RuleId, u8), Option<SourceExcerpt>>,
) -> Option<SourceExcerpt> {
    if let Some(cached_opt) = rule_exemplar_cache.get(&rule_key) {
        return match cached_opt {
            None => None,
            Some(ex) if ex.file != group.file => Some(ex.clone()),
            Some(_) => ctx.find_rule_exemplar(group, diagnostics, sources),
        };
    }
    let rule_ex = ctx.find_rule_exemplar(group, diagnostics, sources);
    rule_exemplar_cache.insert(rule_key, rule_ex.clone());
    rule_ex
}

fn find_unflagged_subject_exemplar(
    group_file: &Path,
    sorted_files: &[PathBuf],
    sources: &HashMap<PathBuf, String>,
    subject_spans_by_file: &HashMap<PathBuf, Vec<(Option<String>, ByteSpan)>>,
    flagged_subjects: &BTreeSet<(&Path, Option<&str>)>,
) -> Option<SourceExcerpt> {
    for same_lang_pass in [true, false] {
        for file_path in sorted_files {
            if same_lang_pass != same_language_family(group_file, file_path) {
                continue;
            }
            let (Some(src), Some(spans)) =
                (sources.get(file_path), subject_spans_by_file.get(file_path))
            else {
                continue;
            };
            if let Some((_, subj_span)) = spans.iter().find(|(subj_name, _)| {
                subj_name.is_some()
                    && !flagged_subjects.contains(&(file_path.as_path(), subj_name.as_deref()))
            }) {
                return Some(excerpt_from_span(file_path, src, *subj_span));
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

pub(super) fn find_architecture_exemplar_in_extracted_files(
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
    reason = "Only state/effect rules add custom invariants beyond the tier-based default (#50)"
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
