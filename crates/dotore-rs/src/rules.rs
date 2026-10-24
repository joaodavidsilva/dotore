//! Rule activation gating and evaluation dispatcher for `dotore-rs`.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use dotore_core::{
    ByteSpan, CapabilityGate, ConcernBucket, Diagnostic, DotoreConfig, ExtractedFile, FileContext,
    HelperFingerprintIr, PackageAnalysisResult, ResolvedCallerSite, RuleId, RuleSeverity, RuleTag,
    SourceLoc, StructLiteralConstructionSiteIr, WorkspacePackage,
};

use crate::{ir::RsFileIr, matchers::RsCandidateFinding};

/// All 5 core Rust safety rules evaluated by `dotore-rs`.
pub const CORE_RUST_SAFETY_RULES: &[RuleId] = &[
    RuleId::RsNoUnwrapInProduction,
    RuleId::RsNoUnguardedSliceIndex,
    RuleId::RsNoLossyNumericAsCast,
    RuleId::RsRequireSafetyCommentOnUnsafe,
    RuleId::RsNoMemForget,
];

/// Evaluates all enabled Rust rules across `files` for `package`.
#[must_use]
pub fn evaluate_rs_package(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
) -> PackageAnalysisResult {
    let mut diagnostics = Vec::new();
    let mut subjects_scanned = 0;
    let mut effects_scanned = 0;

    for file in files {
        subjects_scanned += file.subjects_count;
        effects_scanned += file.effects_count;
        evaluate_rs_file(
            file,
            &package.root_dir,
            &package.capability_gate,
            &package.config,
            enabled_rules,
            &mut diagnostics,
        );
    }

    evaluate_rs_package_graph_rules(package, files, enabled_rules, &mut diagnostics);

    PackageAnalysisResult {
        diagnostics,
        subjects_scanned,
        effects_scanned,
    }
}

/// Evaluates all enabled Rust rules on a single [`ExtractedFile`] under an explicit [`DotoreConfig`] and [`CapabilityGate`].
pub fn evaluate_rs_file(
    file: &ExtractedFile,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if config.is_file_ignored(&file.path, package_root) {
        return;
    }
    let Some(rs_ir) = file.downcast_payload::<RsFileIr>() else {
        return;
    };

    for finding in &rs_ir.findings {
        if !is_evaluated_rust_rule(finding.rule) {
            continue;
        }
        let Some(severity) = resolve_rs_rule_activation(
            finding.rule,
            file,
            package_root,
            gate,
            config,
            enabled_rules,
        ) else {
            continue;
        };
        if is_finding_suppressed(file, finding, config) {
            continue;
        }
        out.push(finding.to_diagnostic(&file.path, severity));
    }

    evaluate_rs_file_soc_rules(file, rs_ir, package_root, gate, config, enabled_rules, out);
}

fn evaluate_rs_package_graph_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if files.is_empty() {
        return;
    }
    let graph_findings = crate::graph::collect_unused_pub_crate_findings_for_package(files);
    for (file_path, finding) in &graph_findings {
        let Some(file) = files.iter().find(|f| &f.path == file_path) else {
            continue;
        };
        if package
            .config
            .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        emit_rs_finding_if_active(
            file,
            finding,
            &package.root_dir,
            &package.capability_gate,
            &package.config,
            enabled_rules,
            out,
        );
    }

    evaluate_rs_package_reuse_rules(package, files, enabled_rules, out);
}

fn emit_rs_finding_if_active(
    file: &ExtractedFile,
    finding: &RsCandidateFinding,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let Some(severity) = resolve_rs_rule_activation(
        finding.rule,
        file,
        package_root,
        gate,
        config,
        enabled_rules,
    ) else {
        return;
    };
    if is_finding_suppressed(file, finding, config) {
        return;
    }
    if out
        .iter()
        .any(|d| d.file == file.path && d.rule == finding.rule && d.span == finding.span)
    {
        return;
    }
    out.push(finding.to_diagnostic(&file.path, severity));
}

fn is_finding_suppressed(
    file: &ExtractedFile,
    finding: &RsCandidateFinding,
    config: &DotoreConfig,
) -> bool {
    config.respect_inline_disables
        && (file.is_suppressed(finding.rule, finding.loc.line, finding.span)
            || file
                .suppressions
                .matches_line_or_block(finding.rule, finding.loc.line)
            || (finding.rule.is_architecture_soc_or_reuse_rule()
                && file.suppressions.matches_line_or_block(finding.rule, 1)))
}

const fn is_evaluated_rust_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::RsNoUnwrapInProduction
            | RuleId::RsNoUnguardedSliceIndex
            | RuleId::RsNoLossyNumericAsCast
            | RuleId::RsRequireSafetyCommentOnUnsafe
            | RuleId::RsNoMemForget
            | RuleId::RsSqlxNoFormattedQueryString
            | RuleId::RsSqlxNoQueryInLoop
            | RuleId::RsAxumNoContendedMutexState
            | RuleId::RsUiNoDerivedSignalInEffect
            | RuleId::RsArchNoManyBooleanParams
            | RuleId::RsArchNoUnusedPubCrateItems
            | RuleId::RsArchPreferPubCrateModules
            | RuleId::RsArchNoLegacyModRs
            | RuleId::RsTokioNoStdLockAcrossAwait
            | RuleId::RsTokioNoBlockingInAsync
            | RuleId::RsTokioPreferBoundedChannel
            | RuleId::RsPerfNoCloneInLoop
            | RuleId::RsPerfHoistRegexToLazylock
            | RuleId::RsPerfPreferVecWithCapacity
            | RuleId::RsPerfNoUnnecessaryFormat
            | RuleId::ArchThinEntrypoint
            | RuleId::ArchNoMixedIoAndPresentation
            | RuleId::ArchSeparateStaticCatalogFromTypes
            | RuleId::ArchNoMixedDomainMonolith
            | RuleId::ArchNoInlineTerminalUiPrimitives
            | RuleId::ArchPreferFluentBuilder
            | RuleId::ArchNoDuplicatedHelperLogic
    )
}

fn resolve_rs_rule_activation(
    rule: RuleId,
    file: &ExtractedFile,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
) -> Option<RuleSeverity> {
    if let Some(explicit_list) = enabled_rules
        && !explicit_list.contains(&rule)
    {
        return None;
    }

    let meta = rule.metadata();
    let has_explicit_cli_rule = enabled_rules.is_some_and(|list| list.contains(&rule));
    let explicit_config_override = config.explicit_rule_override(rule);

    if file.file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && !has_explicit_cli_rule
        && explicit_config_override.is_none()
    {
        return None;
    }

    if config.is_overridden_for_file(rule, &file.path, package_root) && !has_explicit_cli_rule {
        return None;
    }

    if !has_explicit_cli_rule && !gate.allows_rule(meta) {
        return None;
    }

    if has_explicit_cli_rule {
        Some(
            config
                .effective_severity(rule)
                .unwrap_or(meta.default_severity),
        )
    } else {
        config.effective_severity(rule)
    }
}

fn evaluate_rs_file_soc_rules(
    file: &ExtractedFile,
    rs_ir: &RsFileIr,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    let arch_cfg = &config.architecture;
    let file_len = u32::try_from(file.source.len()).unwrap_or(0);

    // 1. `arch-thin-entrypoint`
    if facets.is_entrypoint {
        let has_io = facets.has_bucket(ConcernBucket::DataOrNetworkIo);
        let has_ui = facets.has_bucket(ConcernBucket::TerminalOrUiPresentation);
        let has_domain_types_and_helpers = facets.public_type_count >= 1
            && facets.has_bucket(ConcernBucket::AstOrValidationHelper);
        let exceeds_stmts = facets.entrypoint_statement_count > arch_cfg.max_entrypoint_statements;

        if has_io || has_ui || has_domain_types_and_helpers || exceeds_stmts {
            let (loc, span, subj_name) = rs_ir
                .subjects
                .iter()
                .find(|s| s.name == "main" && !s.is_test)
                .map_or(
                    (
                        SourceLoc { line: 1, column: 1 },
                        ByteSpan {
                            start: 0,
                            end: file_len,
                        },
                        Some("main".to_string()),
                    ),
                    |s| (s.loc, s.span, Some(s.name.clone())),
                );

            let mut steps = Vec::new();
            if exceeds_stmts {
                steps.push(format!(
                    "entrypoint statements: {} > max {}",
                    facets.entrypoint_statement_count, arch_cfg.max_entrypoint_statements
                ));
            }
            if has_domain_types_and_helpers {
                steps.push(format!(
                    "domain types ({}) + helper functions in entrypoint",
                    facets.public_type_count
                ));
            }
            for sig in &facets.concern_signals {
                if matches!(
                    sig.bucket,
                    ConcernBucket::DataOrNetworkIo | ConcernBucket::TerminalOrUiPresentation
                ) {
                    steps.push(format!(
                        "{}: `{}` (line {})",
                        sig.bucket.as_str(),
                        sig.detail,
                        sig.loc.line
                    ));
                }
            }

            let finding = RsCandidateFinding::new(
                RuleId::ArchThinEntrypoint,
                subj_name,
                "main",
                "archThinEntrypoint",
                format!(
                    "Binary entrypoint `{}` embeds domain logic or direct I/O ({} statements, {} public types); keep `main.rs` as a thin adapter delegating to a library runner.",
                    file.path.display(),
                    facets.entrypoint_statement_count,
                    facets.public_type_count
                ),
                loc,
                span,
            )
            .with_cascade_steps(steps);

            emit_rs_finding_if_active(
                file,
                &finding,
                package_root,
                gate,
                config,
                enabled_rules,
                out,
            );
        }
    }

    // 2. `arch-no-mixed-io-and-presentation`
    let io_signals = facets.signals_for_bucket(ConcernBucket::DataOrNetworkIo);
    let ui_signals = facets.signals_for_bucket(ConcernBucket::TerminalOrUiPresentation);
    let is_exempt_report_adapter = is_report_or_cli_adapter_path(&file.path)
        && facets.inline_terminal_ui_sites.is_empty()
        && !io_signals.iter().any(|s| {
            s.detail.starts_with("sqlx")
                || s.detail.starts_with("reqwest")
                || s.detail.contains("Tcp")
                || s.detail.contains("Pool")
        });

    if !io_signals.is_empty() && !ui_signals.is_empty() && !is_exempt_report_adapter {
        let first_io = io_signals[0];
        let first_ui = ui_signals[0];
        let primary_loc = if first_io.loc.line <= first_ui.loc.line {
            first_io.loc
        } else {
            first_ui.loc
        };
        let primary_span = ByteSpan {
            start: first_io.span.start.min(first_ui.span.start),
            end: first_io.span.end.max(first_ui.span.end),
        };
        let subj_name = find_enclosing_subject_name(rs_ir, primary_span);
        let target = subj_name.clone().unwrap_or_else(|| {
            file.path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("module")
                .to_string()
        });

        let finding = RsCandidateFinding::new(
            RuleId::ArchNoMixedIoAndPresentation,
            subj_name,
            target,
            "archNoMixedIoAndPresentation",
            format!(
                "Module `{}` mixes data/filesystem/network I/O (`{}`) with terminal/UI presentation (`{}`); split I/O and rendering into separate modules.",
                file.path.display(),
                first_io.detail,
                first_ui.detail
            ),
            primary_loc,
            primary_span,
        )
        .with_cascade_steps(vec![
            format!("data-or-network-io: `{}` (line {})", first_io.detail, first_io.loc.line),
            format!(
                "terminal-or-ui-presentation: `{}` (line {})",
                first_ui.detail, first_ui.loc.line
            ),
        ]);

        emit_rs_finding_if_active(
            file,
            &finding,
            package_root,
            gate,
            config,
            enabled_rules,
            out,
        );
    }

    // 3. `arch-separate-static-catalog-from-types`
    if facets.public_type_count >= arch_cfg.min_types_with_catalog {
        for cat in &facets.static_catalog_sites {
            if cat.entry_count >= arch_cfg.min_static_catalog_entries {
                let finding = RsCandidateFinding::new(
                    RuleId::ArchSeparateStaticCatalogFromTypes,
                    Some(cat.name.clone()),
                    cat.name.clone(),
                    "archSeparateStaticCatalogFromTypes",
                    format!(
                        "Module `{}` declares {} public domain types alongside static catalog `{}` ({} entries); extract the static catalog into a dedicated `catalog` or `data` submodule.",
                        file.path.display(),
                        facets.public_type_count,
                        cat.name,
                        cat.entry_count
                    ),
                    cat.loc,
                    cat.span,
                )
                .with_cascade_steps(vec![
                    format!("public domain types: {}", facets.public_type_count),
                    format!("static catalog `{}`: {} entries ({}B)", cat.name, cat.entry_count, cat.byte_len),
                ]);

                emit_rs_finding_if_active(
                    file,
                    &finding,
                    package_root,
                    gate,
                    config,
                    enabled_rules,
                    out,
                );
            }
        }
    }

    // 4. `arch-no-inline-terminal-ui-primitives`
    if !facets.is_ui_kit_module {
        for site in &facets.inline_terminal_ui_sites {
            let subj_name = find_enclosing_subject_name(rs_ir, site.span);
            let finding = RsCandidateFinding::new(
                RuleId::ArchNoInlineTerminalUiPrimitives,
                subj_name,
                site.kind.clone(),
                "archNoInlineTerminalUiPrimitives",
                format!(
                    "Inline `{}` literal (`{}`) used outside designated terminal UI modules; delegate rendering to the shared UI primitive kit.",
                    site.kind, site.snippet
                ),
                site.loc,
                site.span,
            )
            .with_cascade_steps(vec![format!(
                "inline {}: `{}` at {}:{}",
                site.kind,
                site.snippet,
                file.path.display(),
                site.loc.line
            )]);

            emit_rs_finding_if_active(
                file,
                &finding,
                package_root,
                gate,
                config,
                enabled_rules,
                out,
            );
        }
    }

    // 5. `arch-no-mixed-domain-monolith`
    let distinct_buckets = facets.distinct_concern_buckets();
    let cluster_count = distinct_buckets.len().max(facets.domain_clusters.len());
    let symbol_count = file.symbol_outlines.len().max(file.subjects_count);
    if !io_signals.is_empty()
        && !ui_signals.is_empty()
        && !is_exempt_report_adapter
        && cluster_count >= arch_cfg.min_monolith_domain_clusters
        && symbol_count >= arch_cfg.min_monolith_symbols
    {
        let mod_name = file
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("monolith")
            .to_string();
        let bucket_names: Vec<&str> = distinct_buckets.iter().map(|b| b.as_str()).collect();
        let finding = RsCandidateFinding::new(
            RuleId::ArchNoMixedDomainMonolith,
            Some(mod_name.clone()),
            mod_name,
            "archNoMixedDomainMonolith",
            format!(
                "Monolithic module `{}` combines {} incompatible concern clusters ([{}]) across {} symbols; decompose into focused domain submodules.",
                file.path.display(),
                cluster_count,
                bucket_names.join(", "),
                symbol_count
            ),
            SourceLoc { line: 1, column: 1 },
            ByteSpan {
                start: 0,
                end: file_len,
            },
        )
        .with_cascade_steps(
            bucket_names
                .into_iter()
                .map(|b| format!("concern cluster: {b}"))
                .collect(),
        );

        emit_rs_finding_if_active(
            file,
            &finding,
            package_root,
            gate,
            config,
            enabled_rules,
            out,
        );
    }
}

fn evaluate_rs_package_reuse_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let arch_cfg = &package.config.architecture;

    // 1. `arch-no-duplicated-helper-logic`
    let mut helpers_by_key: BTreeMap<(u64, usize), Vec<(&ExtractedFile, &HelperFingerprintIr)>> =
        BTreeMap::new();
    for file in files {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for helper in &file.architecture_facets.helper_fingerprints {
            if helper.is_private && helper.statement_count >= arch_cfg.min_helper_statements {
                helpers_by_key
                    .entry((helper.normalized_hash, helper.param_count))
                    .or_default()
                    .push((file, helper));
            }
        }
    }

    for ((norm_hash, param_count), occurrences) in helpers_by_key {
        let distinct_files: BTreeSet<&Path> =
            occurrences.iter().map(|(f, _)| f.path.as_path()).collect();
        if distinct_files.len() < arch_cfg.min_duplicated_helper_modules {
            continue;
        }
        let target_key = format!("fn::arity{param_count}::hash_{norm_hash:08x}");
        for (idx, (file, helper)) in occurrences.iter().enumerate() {
            let peer_sites: Vec<ResolvedCallerSite> = occurrences
                .iter()
                .enumerate()
                .filter(|(other_idx, _)| *other_idx != idx)
                .map(|(_, (peer_file, peer_helper))| ResolvedCallerSite {
                    caller_file: peer_file.path.clone(),
                    parent_subject_name: Some(peer_helper.name.clone()),
                    component_name: peer_helper.name.clone(),
                    loc: peer_helper.loc,
                    span: peer_helper.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            let peer_labels: Vec<String> = peer_sites
                .iter()
                .map(|p| format!("`{}` in `{}`", p.component_name, p.caller_file.display()))
                .collect();

            let finding = RsCandidateFinding::new(
                RuleId::ArchNoDuplicatedHelperLogic,
                Some(helper.name.clone()),
                target_key.clone(),
                "archNoDuplicatedHelperLogic",
                format!(
                    "Private helper `{}` ({} statements, arity {}) duplicates normalized AST logic of {}; extract a shared helper function.",
                    helper.name,
                    helper.statement_count,
                    helper.param_count,
                    peer_labels.join(", ")
                ),
                helper.loc,
                helper.span,
            )
            .with_caller_sites(peer_sites)
            .with_cascade_steps(vec![
                format!(
                    "helper `{}` at {}:{} (hash 0x{norm_hash:08x})",
                    helper.name,
                    file.path.display(),
                    helper.loc.line
                ),
                format!("duplicated across {} modules", distinct_files.len()),
            ]);

            emit_rs_finding_if_active(
                file,
                &finding,
                &package.root_dir,
                &package.capability_gate,
                &package.config,
                enabled_rules,
                out,
            );
        }
    }

    // 2. `arch-prefer-fluent-builder`
    let mut crate_builder_types: HashSet<&str> = HashSet::new();
    for file in files {
        for t in &file.architecture_facets.defined_builder_types {
            crate_builder_types.insert(t.as_str());
        }
    }

    let mut sites_by_type: BTreeMap<
        String,
        Vec<(&ExtractedFile, &StructLiteralConstructionSiteIr)>,
    > = BTreeMap::new();
    for file in files {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for site in &file.architecture_facets.struct_literal_sites {
            if site.field_names.len() >= arch_cfg.min_builder_fields
                && site.default_or_literal_fields.len() >= 3
                && !crate_builder_types.contains(site.type_name.as_str())
            {
                sites_by_type
                    .entry(site.type_name.clone())
                    .or_default()
                    .push((file, site));
            }
        }
    }

    let min_distinct_files = arch_cfg.min_builder_sites.clamp(1, 2);
    for (type_name, sites) in sites_by_type {
        if sites.len() < arch_cfg.min_builder_sites {
            continue;
        }
        let distinct_files: BTreeSet<&Path> = sites.iter().map(|(f, _)| f.path.as_path()).collect();
        if distinct_files.len() < min_distinct_files {
            continue;
        }

        let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, site) in &sites {
            for f in &site.default_or_literal_fields {
                *default_field_counts.entry(f.as_str()).or_insert(0) += 1;
            }
        }
        let shared_defaults: Vec<&str> = default_field_counts
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(name, _)| name)
            .collect();
        if shared_defaults.len() < 3 {
            continue;
        }

        for (idx, (file, site)) in sites.iter().enumerate() {
            let rs_ir = file.downcast_payload::<RsFileIr>();
            let subj_name = rs_ir.and_then(|ir| find_enclosing_subject_name(ir, site.span));
            let peer_sites: Vec<ResolvedCallerSite> = sites
                .iter()
                .enumerate()
                .filter(|(other_idx, _)| *other_idx != idx)
                .map(|(_, (peer_file, peer_site))| {
                    let peer_subj = peer_file
                        .downcast_payload::<RsFileIr>()
                        .and_then(|ir| find_enclosing_subject_name(ir, peer_site.span));
                    ResolvedCallerSite {
                        caller_file: peer_file.path.clone(),
                        parent_subject_name: peer_subj,
                        component_name: type_name.clone(),
                        loc: peer_site.loc,
                        span: peer_site.span,
                        has_key: false,
                        passed_props: peer_site.default_or_literal_fields.clone(),
                    }
                })
                .collect();

            let finding = RsCandidateFinding::new(
                RuleId::ArchPreferFluentBuilder,
                subj_name,
                type_name.clone(),
                "archPreferFluentBuilder",
                format!(
                    "`{type_name}` ({}-field struct literal) is constructed at {} sites across {} modules with repeated boilerplate defaults (`{}`); add `{}::new(...)` and fluent `with_*` builder methods.",
                    site.field_names.len(),
                    sites.len(),
                    distinct_files.len(),
                    shared_defaults.join("`, `"),
                    type_name
                ),
                site.loc,
                site.span,
            )
            .with_caller_sites(peer_sites)
            .with_cascade_steps(vec![
                format!(
                    "`{type_name}` literal with {} fields ({} defaults)",
                    site.field_names.len(),
                    site.default_or_literal_fields.len()
                ),
                format!(
                    "{} construction sites across {} files",
                    sites.len(),
                    distinct_files.len()
                ),
            ]);

            emit_rs_finding_if_active(
                file,
                &finding,
                &package.root_dir,
                &package.capability_gate,
                &package.config,
                enabled_rules,
                out,
            );
        }
    }
}

fn find_enclosing_subject_name(rs_ir: &RsFileIr, span: ByteSpan) -> Option<String> {
    rs_ir
        .subjects
        .iter()
        .filter(|s| s.span.start <= span.start && span.end <= s.span.end)
        .min_by_key(|s| s.span.end.saturating_sub(s.span.start))
        .map(|s| s.name.clone())
}

fn is_report_or_cli_adapter_path(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && matches!(name, "cli.rs" | "report.rs" | "why.rs")
    {
        return true;
    }
    path.parent().is_some_and(|parent| {
        parent
            .components()
            .any(|c| c.as_os_str().to_str() == Some("report"))
    })
}
