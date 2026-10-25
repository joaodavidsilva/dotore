//! Python architecture, SoC, structural reuse, and PEP 561 / type-hint package structure rules.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use dotore_core::{
    ByteSpan, ConcernBucket, Diagnostic, ExtractedFile, FileContext, HelperFingerprintIr,
    PackageRole, ResolvedCallerSite, RuleId, RuleSeverity, SourceLoc,
    StructLiteralConstructionSiteIr, WorkspacePackage,
};

use crate::{PyFileIr, matchers::resolve_active_py_rule_severity};

pub(super) fn evaluate_architecture_file_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for file in files {
        if package
            .config
            .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        evaluate_thin_entrypoint_rule(package, file, enabled_rules, diagnostics);
        evaluate_mixed_io_and_presentation_rule(package, file, enabled_rules, diagnostics);
        evaluate_separate_static_catalog_from_types_rule(package, file, enabled_rules, diagnostics);
        evaluate_mixed_domain_monolith_rule(package, file, enabled_rules, diagnostics);
        evaluate_inline_terminal_ui_primitives_rule(package, file, enabled_rules, diagnostics);
    }
}

fn evaluate_thin_entrypoint_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    if !facets.is_entrypoint {
        return;
    }
    let has_domain_types = facets.has_bucket(ConcernBucket::TypeDefinitions);
    let has_io = facets.has_bucket(ConcernBucket::DataOrNetworkIo);
    let has_entrypoint_loop = facets
        .signals_for_bucket(ConcernBucket::EntrypointAdapter)
        .iter()
        .any(|s| s.detail == "entrypoint-domain-loop");
    let max_stmts = package.config.architecture.max_entrypoint_statements;
    let exceeds_statements = facets.entrypoint_statement_count > max_stmts;
    let embeds_loop_queries = has_entrypoint_loop && has_io && max_stmts <= 25;

    if !(has_domain_types && has_io) && !embeds_loop_queries && !exceeds_statements {
        return;
    }

    let (subject_name, span, loc) = resolve_entrypoint_anchor(file);
    if is_file_level_rule_suppressed(package, file, RuleId::ArchThinEntrypoint, loc, span) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchThinEntrypoint,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("main.py")
        .to_string();
    let mut cascade_steps = Vec::new();
    if has_domain_types && has_io {
        cascade_steps
            .push("concern: type-definitions + data-or-network-io in entrypoint".to_string());
    }
    if embeds_loop_queries {
        cascade_steps.push("concern: entrypoint-domain-loop + data-or-network-io".to_string());
    }
    if exceeds_statements {
        cascade_steps.push(format!(
            "entrypoint_statements={} > max_entrypoint_statements={max_stmts}",
            facets.entrypoint_statement_count
        ));
    }
    let msg = if has_domain_types && has_io {
        format!(
            "Python entrypoint `{target_name}` defines domain/ORM/Pydantic classes and executes direct I/O queries instead of delegating to an imported library runner function."
        )
    } else if embeds_loop_queries {
        format!(
            "Python entrypoint `{target_name}` embeds a domain loop executing direct I/O queries instead of delegating to an imported library runner function."
        )
    } else {
        format!(
            "Python entrypoint `{target_name}` contains {} statements (threshold: {max_stmts}) instead of delegating to a thin library runner function.",
            facets.entrypoint_statement_count
        )
    };

    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchThinEntrypoint,
            file.path.clone(),
            loc,
            span,
            msg,
        )
        .with_subject(subject_name)
        .with_severity(effective_sev)
        .with_message_id("archThinEntrypoint")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_mixed_io_and_presentation_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let respect_disables = package.config.respect_inline_disables;
    let io_signals: Vec<_> = facets
        .signals_for_bucket(ConcernBucket::DataOrNetworkIo)
        .into_iter()
        .filter(|s| {
            !respect_disables
                || !file.is_suppressed(RuleId::ArchNoMixedIoAndPresentation, s.loc.line, s.span)
        })
        .collect();
    let ui_signals: Vec<_> = facets
        .signals_for_bucket(ConcernBucket::TerminalOrUiPresentation)
        .into_iter()
        .filter(|s| {
            !s.detail.starts_with("import ")
                && (!respect_disables
                    || !file.is_suppressed(
                        RuleId::ArchNoMixedIoAndPresentation,
                        s.loc.line,
                        s.span,
                    ))
        })
        .collect();
    let (Some(&first_io), Some(&primary_sig)) = (io_signals.first(), ui_signals.first()) else {
        return;
    };

    let span = primary_sig.span;
    let loc = primary_sig.loc;
    let subject_name = enclosing_subject_for_span(file, span);

    if is_file_level_rule_suppressed(
        package,
        file,
        RuleId::ArchNoMixedIoAndPresentation,
        loc,
        span,
    ) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchNoMixedIoAndPresentation,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("module.py")
        .to_string();
    let io_detail = &first_io.detail;
    let ui_detail = &primary_sig.detail;
    let cascade_steps = vec![
        format!("data-or-network-io: {io_detail}"),
        format!("terminal-or-ui-presentation: {ui_detail}"),
    ];

    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchNoMixedIoAndPresentation,
            file.path.clone(),
            loc,
            span,
            format!(
                "Module `{target_name}` mixes data/network/file I/O (`{io_detail}`) with terminal or UI presentation (`{ui_detail}`); separate I/O adapters from presentation rendering."
            ),
        )
        .with_subject(subject_name)
        .with_severity(effective_sev)
        .with_message_id("archNoMixedIoAndPresentation")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_separate_static_catalog_from_types_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let min_types = package.config.architecture.min_types_with_catalog;
    let min_entries = package.config.architecture.min_static_catalog_entries;
    if facets.public_type_count < min_types {
        return;
    }
    let Some(catalog) = facets
        .static_catalog_sites
        .iter()
        .find(|c| c.entry_count >= min_entries)
    else {
        return;
    };

    if is_file_level_rule_suppressed(
        package,
        file,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        catalog.loc,
        catalog.span,
    ) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        enabled_rules,
        catalog.loc.line,
        catalog.span,
    ) else {
        return;
    };

    let cascade_steps = vec![
        format!("public_types={} >= {min_types}", facets.public_type_count),
        format!(
            "static_catalog={}: {} entries >= {min_entries}",
            catalog.name, catalog.entry_count
        ),
    ];
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchSeparateStaticCatalogFromTypes,
            file.path.clone(),
            catalog.loc,
            catalog.span,
            format!(
                "Module declares {} domain classes alongside static catalog `{}` ({} entries); extract static catalog data into a dedicated module.",
                facets.public_type_count, catalog.name, catalog.entry_count
            ),
        )
        .with_severity(effective_sev)
        .with_message_id("archSeparateStaticCatalogFromTypes")
        .with_target_name(catalog.name.clone())
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_mixed_domain_monolith_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let top_level_symbols = file
        .symbol_outlines
        .iter()
        .filter(|s| s.parent_name.is_none())
        .count();
    let min_symbols = package.config.architecture.min_monolith_symbols;
    let min_clusters = package.config.architecture.min_monolith_domain_clusters;
    let buckets = facets.distinct_concern_buckets();
    if top_level_symbols < min_symbols || buckets.len() < min_clusters {
        return;
    }

    let (span, loc) = file.symbol_outlines.first().map_or(
        (
            ByteSpan {
                start: 0,
                end: u32::try_from(file.source.len()).unwrap_or(0),
            },
            SourceLoc { line: 1, column: 1 },
        ),
        |sym| (sym.span, sym.loc),
    );
    if is_file_level_rule_suppressed(package, file, RuleId::ArchNoMixedDomainMonolith, loc, span) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchNoMixedDomainMonolith,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("module.py")
        .to_string();
    let bucket_names: Vec<&str> = buckets.iter().map(|b| b.as_str()).collect();
    let cascade_steps = vec![
        format!("top_level_symbols={top_level_symbols} >= {min_symbols}"),
        format!("concern_buckets=[{}]", bucket_names.join(", ")),
    ];
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchNoMixedDomainMonolith,
            file.path.clone(),
            loc,
            span,
            format!(
                "Monolithic module `{target_name}` combines {top_level_symbols} top-level symbols across {} orthogonal concern buckets ({}); decompose into focused domain submodules.",
                buckets.len(),
                bucket_names.join(", ")
            ),
        )
        .with_severity(effective_sev)
        .with_message_id("archNoMixedDomainMonolith")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_inline_terminal_ui_primitives_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production || file.architecture_facets.is_ui_kit_module {
        return;
    }
    for site in &file.architecture_facets.inline_terminal_ui_sites {
        let Some(effective_sev) = resolve_active_py_rule_severity(
            package,
            file,
            RuleId::ArchNoInlineTerminalUiPrimitives,
            enabled_rules,
            site.loc.line,
            site.span,
        ) else {
            continue;
        };
        let subject_name = enclosing_subject_for_span(file, site.span);
        diagnostics.push(
            Diagnostic::for_rule(
                RuleId::ArchNoInlineTerminalUiPrimitives,
                file.path.clone(),
                site.loc,
                site.span,
                format!(
                    "Inline terminal UI primitive (`{}`) used outside a dedicated `ui.py` / `console.py` / `terminal.py` module; extract into a shared terminal UI helper.",
                    site.kind
                ),
            )
            .with_subject(subject_name)
            .with_severity(effective_sev)
            .with_message_id("archNoInlineTerminalUiPrimitives")
            .with_target_name(site.kind.as_str().to_string()),
        );
    }
}

pub(super) fn evaluate_duplicated_helper_logic_rule(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let min_stmts = package.config.architecture.min_helper_statements;
    let min_modules = package.config.architecture.min_duplicated_helper_modules;

    let mut by_hash: BTreeMap<u64, Vec<(usize, &HelperFingerprintIr, RuleSeverity)>> =
        BTreeMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for helper in &file.architecture_facets.helper_fingerprints {
            if !helper.is_private || helper.statement_count < min_stmts {
                continue;
            }
            let Some(sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::ArchNoDuplicatedHelperLogic,
                enabled_rules,
                helper.loc.line,
                helper.span,
            ) else {
                continue;
            };
            by_hash
                .entry(helper.normalized_hash)
                .or_default()
                .push((file_idx, helper, sev));
        }
    }

    for (hash, sites) in by_hash {
        let distinct_modules: BTreeSet<usize> = sites.iter().map(|(idx, _, _)| *idx).collect();
        if distinct_modules.len() < min_modules {
            continue;
        }
        let Some(first_site) = sites.first() else {
            continue;
        };
        let primary_target_name = first_site.1.name.as_str();
        for (site_pos, &(file_idx, helper, sev)) in sites.iter().enumerate() {
            let Some(file) = files.get(file_idx) else {
                continue;
            };
            let caller_sites: Vec<ResolvedCallerSite> = sites
                .iter()
                .enumerate()
                .filter(|&(other_pos, _)| other_pos != site_pos)
                .filter_map(|(_, &(other_file_idx, other_helper, _))| {
                    let other_file = files.get(other_file_idx)?;
                    Some(ResolvedCallerSite {
                        caller_file: other_file.path.clone(),
                        parent_subject_name: Some(other_helper.name.clone()),
                        component_name: other_helper.name.clone(),
                        loc: other_helper.loc,
                        span: other_helper.span,
                        has_key: false,
                        passed_props: Vec::new(),
                    })
                })
                .collect();
            let peer_files: Vec<String> = caller_sites
                .iter()
                .map(|c| format!("{}:{}", c.caller_file.display(), c.loc.line))
                .collect();
            let cascade_steps = vec![
                format!(
                    "normalized_hash=0x{hash:08x}, statements={} >= {min_stmts}",
                    helper.statement_count
                ),
                format!("peer_modules=[{}]", peer_files.join(", ")),
            ];
            diagnostics.push(
                Diagnostic::for_rule(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    file.path.clone(),
                    helper.loc,
                    helper.span,
                    format!(
                        "Private helper `{}` ({} statements, hash `0x{hash:08x}`) duplicates normalized AST logic across {} sibling modules ({}); extract into a shared internal utility module.",
                        helper.name,
                        helper.statement_count,
                        distinct_modules.len(),
                        peer_files.join(", ")
                    ),
                )
                .with_subject(Some(helper.name.clone()))
                .with_severity(sev)
                .with_message_id("archNoDuplicatedHelperLogic")
                .with_target_name(primary_target_name)
                .with_caller_sites(caller_sites)
                .with_cascade_steps(cascade_steps),
            );
        }
    }
}

pub(super) fn evaluate_prefer_fluent_builder_rule(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let min_fields = package.config.architecture.min_builder_fields;
    let min_sites = package.config.architecture.min_builder_sites;
    let by_type = collect_builder_candidates_by_type(package, files, enabled_rules, min_fields);

    for (type_name, sites) in by_type {
        emit_fluent_builder_diagnostics_for_type(
            &type_name,
            sites,
            files,
            min_fields,
            min_sites,
            diagnostics,
        );
    }
}

fn collect_builder_candidates_by_type<'a>(
    package: &WorkspacePackage,
    files: &'a [ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    min_fields: usize,
) -> BTreeMap<String, Vec<(usize, &'a StructLiteralConstructionSiteIr, RuleSeverity)>> {
    let defined_builders: HashSet<&str> = files
        .iter()
        .flat_map(|f| {
            f.architecture_facets
                .defined_builder_types
                .iter()
                .map(String::as_str)
        })
        .collect();
    let mut by_type: BTreeMap<
        String,
        Vec<(usize, &'a StructLiteralConstructionSiteIr, RuleSeverity)>,
    > = BTreeMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for site in &file.architecture_facets.struct_literal_sites {
            if defined_builders.contains(site.type_name.as_str())
                || site.field_names.len() < min_fields
                || site.default_or_literal_fields.is_empty()
            {
                continue;
            }
            if let Some(sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::ArchPreferFluentBuilder,
                enabled_rules,
                site.loc.line,
                site.span,
            ) {
                by_type
                    .entry(site.type_name.clone())
                    .or_default()
                    .push((file_idx, site, sev));
            }
        }
    }
    by_type
}

fn emit_fluent_builder_diagnostics_for_type(
    type_name: &str,
    sites: Vec<(usize, &StructLiteralConstructionSiteIr, RuleSeverity)>,
    files: &[ExtractedFile],
    min_fields: usize,
    min_sites: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if sites.len() < min_sites {
        return;
    }
    let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for &(_, site, _) in &sites {
        let unique_defaults: BTreeSet<&str> = site
            .default_or_literal_fields
            .iter()
            .map(String::as_str)
            .collect();
        for field in unique_defaults {
            *default_field_counts.entry(field).or_insert(0) += 1;
        }
    }
    let overlapping_defaults: Vec<&str> = default_field_counts
        .into_iter()
        .filter_map(|(field, count)| (count >= 2).then_some(field))
        .collect();
    if overlapping_defaults.len() < 2 {
        return;
    }
    let qualifying_sites: Vec<(usize, &StructLiteralConstructionSiteIr, RuleSeverity)> = sites
        .into_iter()
        .filter(|(_, s, _)| {
            s.default_or_literal_fields
                .iter()
                .filter(|f| overlapping_defaults.contains(&f.as_str()))
                .count()
                >= 2
        })
        .collect();
    if qualifying_sites.len() < min_sites {
        return;
    }
    for (site_pos, &(file_idx, site, sev)) in qualifying_sites.iter().enumerate() {
        let Some(file) = files.get(file_idx) else {
            continue;
        };
        let subject_name = enclosing_subject_for_span(file, site.span);
        let caller_sites: Vec<ResolvedCallerSite> = qualifying_sites
            .iter()
            .enumerate()
            .filter(|&(other_pos, _)| other_pos != site_pos)
            .filter_map(|(_, &(other_file_idx, other_site, _))| {
                let other_file = files.get(other_file_idx)?;
                Some(ResolvedCallerSite {
                    caller_file: other_file.path.clone(),
                    parent_subject_name: enclosing_subject_for_span(other_file, other_site.span),
                    component_name: type_name.to_string(),
                    loc: other_site.loc,
                    span: other_site.span,
                    has_key: false,
                    passed_props: other_site.field_names.clone(),
                })
            })
            .collect();
        let cascade_steps = vec![
            format!(
                "type={type_name}, fields={} >= {min_fields}, sites={} >= {min_sites}",
                site.field_names.len(),
                qualifying_sites.len()
            ),
            format!(
                "default_or_literal_fields=[{}]",
                site.default_or_literal_fields.join(", ")
            ),
        ];
        diagnostics.push(
            Diagnostic::for_rule(
                RuleId::ArchPreferFluentBuilder,
                file.path.clone(),
                site.loc,
                site.span,
                format!(
                    "`{type_name}(...)` is constructed across {} call sites with {} keyword arguments including boilerplate defaults (`{}`); define a `{type_name}Builder`, `{type_name}.from_defaults(...)`, or `build_*` factory.",
                    qualifying_sites.len(),
                    site.field_names.len(),
                    overlapping_defaults.join(", ")
                ),
            )
            .with_subject(subject_name)
            .with_severity(sev)
            .with_message_id("archPreferFluentBuilder")
            .with_target_name(type_name)
            .with_caller_sites(caller_sites)
            .with_cascade_steps(cascade_steps),
        );
    }
}

fn resolve_entrypoint_anchor(file: &ExtractedFile) -> (Option<String>, ByteSpan, SourceLoc) {
    if let Some((subj, span, loc)) = file
        .subject_spans
        .iter()
        .find(|(name, _, _)| matches!(name.as_deref(), Some("main" | "cli" | "run")))
    {
        return (subj.clone(), *span, *loc);
    }
    if let Some(sig) = file
        .architecture_facets
        .signals_for_bucket(ConcernBucket::EntrypointAdapter)
        .first()
    {
        return (None, sig.span, sig.loc);
    }
    if let Some(first_sym) = file.symbol_outlines.first() {
        return (None, first_sym.span, first_sym.loc);
    }
    (
        None,
        ByteSpan {
            start: 0,
            end: u32::try_from(file.source.len()).unwrap_or(0),
        },
        SourceLoc { line: 1, column: 1 },
    )
}

fn enclosing_subject_for_span(file: &ExtractedFile, span: ByteSpan) -> Option<String> {
    file.subject_spans
        .iter()
        .filter(|(_, s, _)| s.start <= span.start && span.end <= s.end)
        .min_by_key(|(_, s, _)| s.end.saturating_sub(s.start))
        .and_then(|(name, _, _)| name.clone())
}

fn is_file_level_rule_suppressed(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    rule: RuleId,
    loc: SourceLoc,
    span: ByteSpan,
) -> bool {
    if !package.config.respect_inline_disables {
        return false;
    }
    let first_code_line = file.symbol_outlines.first().map_or(1, |s| s.loc.line);
    if file.suppressions.matches_line_or_block(rule, 1)
        || file.suppressions.matches_line_or_block(rule, 2)
        || file.suppressions.matches_line_or_block(rule, 3)
        || file
            .suppressions
            .matches_line_or_block(rule, first_code_line)
        || file.is_suppressed(rule, loc.line, span)
    {
        return true;
    }
    let enclosing_subj_span = file
        .subject_spans
        .iter()
        .filter(|(_, s, _)| s.start <= span.start && span.end <= s.end)
        .min_by_key(|(_, s, _)| s.end.saturating_sub(s.start))
        .map(|(_, s, _)| *s);
    file.suppressions.line_directives.iter().any(|d| {
        if d.rules.is_empty() || !dotore_core::rule_list_matches(&d.rules, rule) {
            return false;
        }
        if d.target_line <= 3 {
            return true;
        }
        if let Some(subj_span) = enclosing_subj_span
            && let Some(ir) = file.downcast_payload::<PyFileIr>()
        {
            let subj_start =
                dotore_core::loc_from_line_starts(&ir.line_starts, subj_span.start).line;
            let subj_end = dotore_core::loc_from_line_starts(
                &ir.line_starts,
                subj_span.end.saturating_sub(1).max(subj_span.start),
            )
            .line;
            return d.target_line >= subj_start && d.target_line <= subj_end;
        }
        false
    })
}

pub(super) fn evaluate_package_structure_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let source_files: Vec<&ExtractedFile> = files
        .iter()
        .filter(|f| {
            f.file_context == FileContext::Production
                && f.path.extension().and_then(|e| e.to_str()) == Some("py")
                && !package.config.is_file_ignored(&f.path, &package.root_dir)
        })
        .collect();
    if source_files.is_empty() {
        return;
    }

    let has_init_py = source_files
        .iter()
        .any(|f| f.path.file_name().and_then(|n| n.to_str()) == Some("__init__.py"));
    let is_script_profile = package
        .capability_gate
        .dependencies
        .get("__python_profile")
        .is_some_and(|p| p == "script")
        || (package.capability_gate.package_role == PackageRole::Unknown
            && source_files.len() <= 5
            && !has_init_py);
    let typed_files: Vec<&ExtractedFile> = source_files
        .iter()
        .copied()
        .filter(|f| {
            f.downcast_payload::<PyFileIr>()
                .is_some_and(|ir| ir.module_graph.has_type_annotations)
        })
        .collect();

    check_missing_py_typed_rule(
        package,
        &source_files,
        &typed_files,
        is_script_profile,
        enabled_rules,
        diagnostics,
    );
    check_low_type_hint_coverage_rule(
        package,
        &source_files,
        &typed_files,
        is_script_profile,
        enabled_rules,
        diagnostics,
    );
}

fn check_missing_py_typed_rule(
    package: &WorkspacePackage,
    source_files: &[&ExtractedFile],
    typed_files: &[&ExtractedFile],
    is_script_profile: bool,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let explicit_missing_py_typed = enabled_rules
        .is_some_and(|r| r.contains(&RuleId::PyStructureMissingPyTyped))
        || package
            .config
            .explicit_rule_override(RuleId::PyStructureMissingPyTyped)
            .is_some();
    let check_missing_py_typed = (!is_script_profile
        && package.capability_gate.package_role == PackageRole::Library)
        || explicit_missing_py_typed;
    let has_py_typed = package
        .capability_gate
        .entrypoints
        .iter()
        .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("py.typed"));
    if !check_missing_py_typed || typed_files.is_empty() || has_py_typed {
        return;
    }
    let Some(file) = source_files
        .iter()
        .copied()
        .find(|f| f.path.file_name().and_then(|n| n.to_str()) == Some("__init__.py"))
        .or_else(|| typed_files.first().copied())
    else {
        return;
    };
    let (span, loc) = first_line_span_and_loc(file);
    if is_file_level_rule_suppressed(package, file, RuleId::PyStructureMissingPyTyped, loc, span) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::PyStructureMissingPyTyped,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::PyStructureMissingPyTyped,
            file.path.clone(),
            loc,
            span,
            "Python library package uses inline type annotations but is missing a PEP 561 `py.typed` marker file in the package tree.",
        )
        .with_severity(effective_sev)
        .with_message_id("pyStructureMissingPyTyped")
        .with_target_name("py.typed"),
    );
}

fn check_low_type_hint_coverage_rule(
    package: &WorkspacePackage,
    source_files: &[&ExtractedFile],
    typed_files: &[&ExtractedFile],
    is_script_profile: bool,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let explicit_low_coverage = enabled_rules
        .is_some_and(|r| r.contains(&RuleId::PyStructureLowTypeHintCoverage))
        || package
            .config
            .explicit_rule_override(RuleId::PyStructureLowTypeHintCoverage)
            .is_some();
    let check_low_coverage =
        (!is_script_profile && source_files.len() >= 2) || explicit_low_coverage;
    if !check_low_coverage || typed_files.len() * 2 >= source_files.len() {
        return;
    }
    let Some(file) = source_files.iter().copied().find(|f| {
        !f.downcast_payload::<PyFileIr>()
            .is_some_and(|ir| ir.module_graph.has_type_annotations)
    }) else {
        return;
    };
    let (span, loc) = first_line_span_and_loc(file);
    if is_file_level_rule_suppressed(
        package,
        file,
        RuleId::PyStructureLowTypeHintCoverage,
        loc,
        span,
    ) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::PyStructureLowTypeHintCoverage,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };
    let hinted = typed_files.len();
    let total = source_files.len();
    let pct = (hinted * 100) / total;
    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("module.py")
        .to_string();
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::PyStructureLowTypeHintCoverage,
            file.path.clone(),
            loc,
            span,
            format!(
                "Only {hinted} of {total} production Python modules ({pct}%) contain type annotations (< 50% coverage); add parameter and return type hints across modules."
            ),
        )
        .with_severity(effective_sev)
        .with_message_id("pyStructureLowTypeHintCoverage")
        .with_target_name(target_name),
    );
}

fn first_line_span_and_loc(file: &ExtractedFile) -> (ByteSpan, SourceLoc) {
    let first_line_end = u32::try_from(
        file.source
            .lines()
            .next()
            .map_or(0, str::len)
            .min(file.source.len()),
    )
    .unwrap_or(0);
    (
        ByteSpan {
            start: 0,
            end: first_line_end,
        },
        SourceLoc { line: 1, column: 1 },
    )
}
