//! JavaScript/TypeScript/React/Angular Separation of Concerns (SoC) single-pass
//! [`ArchitectureFileFacets`] extraction and rule detectors:
//! - [`RuleId::ArchThinEntrypoint`] (`arch-thin-entrypoint`)
//! - [`RuleId::ArchNoMixedIoAndPresentation`] (`arch-no-mixed-io-and-presentation`)
//! - [`RuleId::ArchSeparateStaticCatalogFromTypes`] (`arch-separate-static-catalog-from-types`)
//! - [`RuleId::ArchNoMixedDomainMonolith`] (`arch-no-mixed-domain-monolith`)
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; SoC extractors match only relevant node kinds"
)]

use std::{collections::BTreeSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, BindingPattern, CallExpression, Expression, ObjectPropertyKind,
        Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::{
    config::DotoreConfig,
    ir::{
        ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, FileContext, FileIr,
        InlineTerminalUiPrimitiveSiteIr, JsxElementIr, SourceLoc, StaticCatalogSiteIr, SubjectIr,
        SymbolKind, SymbolOutline, loc_from_line_starts, react_ast::classify_jsx_element_name,
        types::ModuleIr,
    },
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, PrescriptionTier, RuleId, RuleSeverity},
};

/// Minimum static collection entries recorded in [`ArchitectureFileFacets::static_catalog_sites`]
/// during single-pass extraction so custom `config.architecture.min_static_catalog_entries`
/// overrides (including lowered thresholds in tests) can be evaluated without re-parsing.
const MIN_CANDIDATE_CATALOG_ENTRIES: usize = 3;

/// Entry threshold above which a static catalog also registers a [`ConcernBucket::StaticDataCatalog`]
/// signal in [`ArchitectureFileFacets::concern_signals`].
const DEFAULT_SIGNAL_CATALOG_ENTRIES: usize = 15;

/// Extracts single-pass [`ArchitectureFileFacets`] for Separation of Concerns rules.
#[expect(
    clippy::too_many_arguments,
    reason = "Single-pass facet extractor consumes already-extracted AST, semantic, module, JSX, and outline slices"
)]
pub(crate) fn extract_soc_architecture_facets(
    path: &Path,
    source: &str,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    subjects: &[SubjectIr],
    jsx_elements: &[JsxElementIr],
    symbol_outlines: &[SymbolOutline],
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    facets.is_entrypoint = is_js_entrypoint_path(path, source, module);
    facets.is_ui_kit_module = is_js_ui_kit_path(path);
    facets.entrypoint_statement_count = count_executable_statements_in_program(program);

    let mut seen_signals: BTreeSet<(ConcernBucket, u32, u32)> = BTreeSet::new();

    // 1. Classify module imports for DataOrNetworkIo and EntrypointAdapter
    for imp in &module.imports {
        if imp.is_type_only {
            continue;
        }
        let raw_span = Span::new(imp.span.start, imp.span.end);
        if is_io_import_source(&imp.source) {
            push_concern_signal(
                facets,
                &mut seen_signals,
                line_starts,
                ConcernBucket::DataOrNetworkIo,
                format!("import '{}'", imp.source),
                raw_span,
            );
        } else if is_entrypoint_adapter_import_source(&imp.source) {
            push_concern_signal(
                facets,
                &mut seen_signals,
                line_starts,
                ConcernBucket::EntrypointAdapter,
                format!("import '{}'", imp.source),
                raw_span,
            );
        }
    }

    // 2. Count domain type definitions (`interface`, `type`, `enum`, domain `class`)
    let top_level_types: Vec<&SymbolOutline> = symbol_outlines
        .iter()
        .filter(|sym| {
            sym.parent_name.is_none()
                && matches!(
                    sym.kind,
                    SymbolKind::Interface | SymbolKind::Type | SymbolKind::Enum | SymbolKind::Class
                )
                && !is_ui_component_class(sym, jsx_elements, source)
        })
        .collect();
    facets.public_type_count = top_level_types.len();

    for sym in &top_level_types {
        let is_single_component_props = top_level_types.len() == 1
            && (sym.name.ends_with("Props") || sym.name == "Props")
            && !subjects.is_empty();
        if !is_single_component_props {
            push_concern_signal(
                facets,
                &mut seen_signals,
                line_starts,
                ConcernBucket::TypeDefinitions,
                format!("{} {}", sym.kind.as_str(), sym.name),
                Span::new(sym.span.start, sym.span.end),
            );
        }
    }

    // 3. Extract static catalog sites from top-level variable declarations
    extract_static_catalog_sites(program, line_starts, facets, &mut seen_signals);
    // 4. Walk semantic AST nodes in a single pass for I/O calls, UI/terminal signals,
    //    entrypoint adapter calls, and pure AST/validation helpers.
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                if let Some(detail) = classify_io_call_expression(call, semantic, node_id) {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::DataOrNetworkIo,
                        detail,
                        call.span,
                    );
                } else if let Some(detail) = classify_entrypoint_adapter_call(call) {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::EntrypointAdapter,
                        detail,
                        call.span,
                    );
                } else if let Some(detail) = classify_dom_or_terminal_ui_call(call) {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::TerminalOrUiPresentation,
                        detail,
                        call.span,
                    );
                }
            }
            AstKind::NewExpression(new_expr) => {
                if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                    && matches!(id.name.as_str(), "WebSocket" | "XMLHttpRequest" | "Pool")
                {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::DataOrNetworkIo,
                        format!("new {}()", id.name),
                        new_expr.span,
                    );
                }
            }
            AstKind::TaggedTemplateExpression(tagged) => {
                let tag_name = match tagged.tag.without_parentheses() {
                    Expression::Identifier(id) => Some(id.name.as_str()),
                    Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
                    _ => None,
                };
                if tag_name.is_some_and(|n| matches!(n, "sql" | "$queryRaw" | "$executeRaw")) {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::DataOrNetworkIo,
                        "sql`...`".to_string(),
                        tagged.span,
                    );
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                if let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && obj.name == "process"
                    && mem.property.name == "argv"
                {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::EntrypointAdapter,
                        "process.argv".to_string(),
                        mem.span,
                    );
                }
            }
            AstKind::JSXOpeningElement(opening) => {
                let (tag_name, _, _, _) = classify_jsx_element_name(semantic, &opening.name);
                if !is_root_mount_wrapper_jsx(semantic, node_id, &tag_name) {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::TerminalOrUiPresentation,
                        format!("<{tag_name}>"),
                        opening.span,
                    );
                }
            }
            AstKind::Decorator(dec) => {
                if let Expression::CallExpression(call) = dec.expression.without_parentheses()
                    && let Expression::Identifier(id) = call.callee.without_parentheses()
                    && id.name == "Component"
                    && slice_contains_inline_template(source, dec.span)
                {
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::TerminalOrUiPresentation,
                        "@Component(template)".to_string(),
                        dec.span,
                    );
                }
            }
            AstKind::StringLiteral(lit) => {
                let cooked = lit.value.as_str().unwrap_or("");
                let raw = source
                    .get(lit.span.start as usize..lit.span.end as usize)
                    .unwrap_or(cooked);
                if let Some((kind, snippet)) = classify_terminal_ui_literal(cooked, raw) {
                    let loc = loc_from_line_starts(line_starts, lit.span.start);
                    let span = ByteSpan {
                        start: lit.span.start,
                        end: lit.span.end,
                    };
                    if !facets.is_ui_kit_module {
                        facets
                            .inline_terminal_ui_sites
                            .push(InlineTerminalUiPrimitiveSiteIr {
                                kind: kind.to_string(),
                                snippet: snippet.clone(),
                                loc,
                                span,
                            });
                    }
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::TerminalOrUiPresentation,
                        format!("{kind}: {snippet}"),
                        lit.span,
                    );
                }
            }
            AstKind::TemplateElement(tpl) => {
                let cooked = tpl
                    .value
                    .cooked
                    .as_ref()
                    .and_then(|c| c.as_str())
                    .unwrap_or(tpl.value.raw.as_str());
                if let Some((kind, snippet)) =
                    classify_terminal_ui_literal(cooked, tpl.value.raw.as_str())
                {
                    let loc = loc_from_line_starts(line_starts, tpl.span.start);
                    let span = ByteSpan {
                        start: tpl.span.start,
                        end: tpl.span.end,
                    };
                    if !facets.is_ui_kit_module {
                        facets
                            .inline_terminal_ui_sites
                            .push(InlineTerminalUiPrimitiveSiteIr {
                                kind: kind.to_string(),
                                snippet: snippet.clone(),
                                loc,
                                span,
                            });
                    }
                    push_concern_signal(
                        facets,
                        &mut seen_signals,
                        line_starts,
                        ConcernBucket::TerminalOrUiPresentation,
                        format!("{kind}: {snippet}"),
                        tpl.span,
                    );
                }
            }
            _ => {}
        }
    }

    // 5. Classify pure AST/validation/transformation helper functions at module scope
    for sym in symbol_outlines {
        if sym.parent_name.is_some() || sym.kind != SymbolKind::Function {
            continue;
        }
        let is_subject = subjects.iter().any(|s| {
            s.name.as_deref() == Some(sym.name.as_str()) || spans_overlap(s.span, sym.span)
        });
        if is_subject {
            continue;
        }
        let has_io_or_ui_inside = facets.concern_signals.iter().any(|sig| {
            matches!(
                sig.bucket,
                ConcernBucket::DataOrNetworkIo
                    | ConcernBucket::TerminalOrUiPresentation
                    | ConcernBucket::EntrypointAdapter
            ) && sig.span.start >= sym.span.start
                && sig.span.end <= sym.span.end
        });
        if !has_io_or_ui_inside && is_helper_or_validator_function(&sym.name, source, sym.span) {
            push_concern_signal(
                facets,
                &mut seen_signals,
                line_starts,
                ConcernBucket::AstOrValidationHelper,
                format!("fn {}", sym.name),
                Span::new(sym.span.start, sym.span.end),
            );
        }
    }

    // 6. Populate distinct domain clusters
    let mut clusters = Vec::new();
    for bucket in facets.distinct_concern_buckets() {
        if bucket != ConcernBucket::EntrypointAdapter {
            clusters.push(bucket.as_str().to_string());
        }
    }
    facets.domain_clusters = clusters;
}

fn push_concern_signal(
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
    line_starts: &[u32],
    bucket: ConcernBucket,
    detail: String,
    span: Span,
) {
    if span.end > span.start && seen_signals.insert((bucket, span.start, span.end)) {
        facets.concern_signals.push(ConcernSignalSite {
            bucket,
            detail,
            loc: loc_from_line_starts(line_starts, span.start),
            span: ByteSpan {
                start: span.start,
                end: span.end,
            },
        });
    }
}

/// Evaluates the 4 JS/TS Separation of Concerns rules on `file` using `config.architecture` thresholds.
pub(crate) fn evaluate_file_soc_rules<F>(
    file: &FileIr,
    config: &DotoreConfig,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if file.file_context != FileContext::Production {
        return;
    }

    if let Some(sev) = is_active(RuleId::ArchThinEntrypoint) {
        check_arch_thin_entrypoint(file, config, sev, out);
    }
    if let Some(sev) = is_active(RuleId::ArchNoMixedIoAndPresentation) {
        check_arch_no_mixed_io_and_presentation(file, config, sev, out);
    }
    if let Some(sev) = is_active(RuleId::ArchSeparateStaticCatalogFromTypes) {
        check_arch_separate_static_catalog_from_types(file, config, sev, out);
    }
    if let Some(sev) = is_active(RuleId::ArchNoMixedDomainMonolith) {
        check_arch_no_mixed_domain_monolith(file, config, sev, out);
    }
}

fn check_arch_thin_entrypoint(
    file: &FileIr,
    config: &DotoreConfig,
    sev: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    if !facets.is_entrypoint || file.module.is_aggregation_barrel {
        return;
    }

    let io_signals = facets.signals_for_bucket(ConcernBucket::DataOrNetworkIo);
    let ui_signals = facets.signals_for_bucket(ConcernBucket::TerminalOrUiPresentation);
    let max_stmts = config.architecture.max_entrypoint_statements;

    let has_direct_io = !io_signals.is_empty();
    let has_inline_ui_and_types = !ui_signals.is_empty() && facets.public_type_count >= 1;
    let has_inline_terminal_primitives = !facets.inline_terminal_ui_sites.is_empty();
    let exceeds_statement_budget = facets.entrypoint_statement_count > max_stmts;

    if !has_direct_io
        && !has_inline_ui_and_types
        && !has_inline_terminal_primitives
        && !exceeds_statement_budget
    {
        return;
    }

    let (loc, span, target_name, subject_name) = select_entrypoint_owner_site(file);
    if is_soc_rule_suppressed(file, config, RuleId::ArchThinEntrypoint, loc.line, span) {
        return;
    }

    let mut reasons = Vec::new();
    let mut cascade_steps = Vec::new();
    if let Some(first_io) = io_signals.first() {
        reasons.push(format!("direct I/O (`{}`)", first_io.detail));
        cascade_steps.push(format!("data-or-network-io: {}", first_io.detail));
    }
    if has_inline_ui_and_types {
        if let Some(first_ui) = ui_signals.first() {
            reasons.push(format!(
                "{} domain type(s) + inline presentation (`{}`)",
                facets.public_type_count, first_ui.detail
            ));
            cascade_steps.push(format!(
                "type-definitions: {} types",
                facets.public_type_count
            ));
            cascade_steps.push(format!("terminal-or-ui-presentation: {}", first_ui.detail));
        }
    } else if has_inline_terminal_primitives
        && let Some(first_term) = facets.inline_terminal_ui_sites.first()
    {
        reasons.push(format!(
            "inline terminal UI primitive (`{}`)",
            first_term.snippet
        ));
        cascade_steps.push(format!(
            "inline-terminal-ui: {} ({})",
            first_term.kind, first_term.snippet
        ));
    }
    if exceeds_statement_budget {
        reasons.push(format!(
            "{} executable statements (max {max_stmts})",
            facets.entrypoint_statement_count
        ));
        cascade_steps.push(format!(
            "entrypoint-statements: {} > {max_stmts}",
            facets.entrypoint_statement_count
        ));
    }

    let message = format!(
        "Entrypoint `{}` embeds {} instead of delegating to a library runner module.",
        file.path.display(),
        reasons.join(", ")
    );

    out.push(
        make_diag_for_subject(
            RuleId::ArchThinEntrypoint,
            file.path.clone(),
            subject_name,
            "archThinEntrypoint",
            target_name,
            message,
            loc,
            span,
        )
        .with_severity(sev)
        .with_tier(PrescriptionTier::Refactor)
        .with_cascade_steps(cascade_steps),
    );
}

fn check_arch_no_mixed_io_and_presentation(
    file: &FileIr,
    config: &DotoreConfig,
    sev: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    let io_signals = facets.signals_for_bucket(ConcernBucket::DataOrNetworkIo);
    let ui_signals = facets.signals_for_bucket(ConcernBucket::TerminalOrUiPresentation);
    if io_signals.is_empty() || ui_signals.is_empty() {
        return;
    }

    if is_thin_route_loader_module(file, &io_signals)
        || is_single_input_unexported_local_storage_sync(file, &io_signals)
    {
        return;
    }

    let first_io = io_signals[0];
    let first_ui = ui_signals[0];
    let (loc, span, target_name, subject_name) =
        select_mixed_io_presentation_owner_site(file, first_io, first_ui);

    if is_soc_rule_suppressed(
        file,
        config,
        RuleId::ArchNoMixedIoAndPresentation,
        loc.line,
        span,
    ) {
        return;
    }

    let cascade_steps = vec![
        format!("data-or-network-io: {}", first_io.detail),
        format!("terminal-or-ui-presentation: {}", first_ui.detail),
    ];
    let message = format!(
        "Module `{}` mixes data/network I/O (`{}`) with UI or terminal presentation (`{}`); extract I/O into a dedicated data-access module.",
        file.path.display(),
        first_io.detail,
        first_ui.detail
    );

    out.push(
        make_diag_for_subject(
            RuleId::ArchNoMixedIoAndPresentation,
            file.path.clone(),
            subject_name,
            "archNoMixedIoAndPresentation",
            target_name,
            message,
            loc,
            span,
        )
        .with_severity(sev)
        .with_tier(PrescriptionTier::Refactor)
        .with_cascade_steps(cascade_steps),
    );
}

fn check_arch_separate_static_catalog_from_types(
    file: &FileIr,
    config: &DotoreConfig,
    sev: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    let min_types = config.architecture.min_types_with_catalog;
    let min_entries = config.architecture.min_static_catalog_entries;

    if facets.public_type_count < min_types {
        return;
    }

    let Some(catalog) = facets
        .static_catalog_sites
        .iter()
        .filter(|c| c.entry_count >= min_entries)
        .max_by_key(|c| c.entry_count)
    else {
        return;
    };

    if is_soc_rule_suppressed(
        file,
        config,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        catalog.loc.line,
        catalog.span,
    ) {
        return;
    }

    let cascade_steps = vec![
        format!(
            "type-definitions: {} domain types (min {min_types})",
            facets.public_type_count
        ),
        format!(
            "static-data-catalog: {} ({} entries, {}B, min {min_entries})",
            catalog.name, catalog.entry_count, catalog.byte_len
        ),
    ];
    let message = format!(
        "Module `{}` declares {} domain types alongside static catalog `{}` ({} entries); move bulk static data into a dedicated catalog module.",
        file.path.display(),
        facets.public_type_count,
        catalog.name,
        catalog.entry_count
    );

    out.push(
        make_diag_for_subject(
            RuleId::ArchSeparateStaticCatalogFromTypes,
            file.path.clone(),
            None,
            "archSeparateStaticCatalogFromTypes",
            catalog.name.clone(),
            message,
            catalog.loc,
            catalog.span,
        )
        .with_severity(sev)
        .with_tier(PrescriptionTier::Refactor)
        .with_cascade_steps(cascade_steps),
    );
}

fn check_arch_no_mixed_domain_monolith(
    file: &FileIr,
    config: &DotoreConfig,
    sev: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    let min_clusters = config.architecture.min_monolith_domain_clusters;
    let min_symbols = config.architecture.min_monolith_symbols;
    let min_catalog_entries = config.architecture.min_static_catalog_entries;

    let top_level_symbols: Vec<&SymbolOutline> = file
        .symbol_outlines
        .iter()
        .filter(|sym| {
            sym.parent_name.is_none()
                && !matches!(
                    sym.kind,
                    SymbolKind::Import | SymbolKind::Export | SymbolKind::EnumMember
                )
        })
        .collect();

    if top_level_symbols.len() < min_symbols {
        return;
    }

    // Verify symbol outlines span at least 2 distinct top-level symbol categories
    let mut symbol_categories: BTreeSet<u8> = BTreeSet::new();
    for sym in &top_level_symbols {
        let cat = match sym.kind {
            SymbolKind::Interface | SymbolKind::Type | SymbolKind::Enum => 1,
            SymbolKind::Class => 2,
            SymbolKind::Function | SymbolKind::Method => 3,
            SymbolKind::Constant | SymbolKind::Variable | SymbolKind::Property => 4,
            SymbolKind::EnumMember | SymbolKind::Export | SymbolKind::Import => 0,
        };
        if cat > 0 {
            symbol_categories.insert(cat);
        }
    }
    if symbol_categories.len() < 2 {
        return;
    }

    let mut active_domain_buckets: Vec<ConcernBucket> = Vec::new();
    for bucket in [
        ConcernBucket::DataOrNetworkIo,
        ConcernBucket::TerminalOrUiPresentation,
        ConcernBucket::TypeDefinitions,
        ConcernBucket::StaticDataCatalog,
        ConcernBucket::AstOrValidationHelper,
    ] {
        let present = if bucket == ConcernBucket::StaticDataCatalog {
            facets
                .static_catalog_sites
                .iter()
                .any(|c| c.entry_count >= min_catalog_entries)
        } else {
            facets.has_bucket(bucket)
        };
        if present {
            active_domain_buckets.push(bucket);
        }
    }

    if active_domain_buckets.len() < min_clusters {
        return;
    }

    let primary_sym = top_level_symbols[0];
    let loc = primary_sym.loc;
    let span = primary_sym.span;
    if is_soc_rule_suppressed(
        file,
        config,
        RuleId::ArchNoMixedDomainMonolith,
        loc.line,
        span,
    ) {
        return;
    }

    let bucket_names: Vec<&str> = active_domain_buckets.iter().map(|b| b.as_str()).collect();
    let cascade_steps: Vec<String> = active_domain_buckets
        .iter()
        .map(|&b| {
            let sample = facets
                .signals_for_bucket(b)
                .first()
                .map_or("active", |s| s.detail.as_str());
            format!("{}: {sample}", b.as_str())
        })
        .collect();
    let target_name = file
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_string();

    let message = format!(
        "Monolithic module `{}` combines {} concern buckets (`{}`) across {} top-level symbols; decompose into focused domain submodules.",
        file.path.display(),
        active_domain_buckets.len(),
        bucket_names.join("`, `"),
        top_level_symbols.len()
    );

    out.push(
        make_diag_for_subject(
            RuleId::ArchNoMixedDomainMonolith,
            file.path.clone(),
            None,
            "archNoMixedDomainMonolith",
            target_name,
            message,
            loc,
            span,
        )
        .with_severity(sev)
        .with_tier(PrescriptionTier::Refactor)
        .with_cascade_steps(cascade_steps),
    );
}

fn is_soc_rule_suppressed(
    file: &FileIr,
    config: &DotoreConfig,
    rule: RuleId,
    line: u32,
    span: ByteSpan,
) -> bool {
    if !config.respect_inline_disables {
        return false;
    }
    if file
        .suppressions
        .is_suppressed(rule, line, span, &file.jsx_elements, &file.subjects)
    {
        return true;
    }
    if file.suppressions.matches_line(rule, 1) || file.suppressions.matches_line(rule, 2) {
        return true;
    }
    for sym in &file.symbol_outlines {
        if sym.span.start <= span.start
            && span.end <= sym.span.end
            && file.suppressions.matches_line(rule, sym.loc.line)
        {
            return true;
        }
    }
    false
}

fn select_entrypoint_owner_site(file: &FileIr) -> (SourceLoc, ByteSpan, String, Option<String>) {
    if let Some(sym) = file.symbol_outlines.iter().find(|s| {
        s.parent_name.is_none()
            && s.kind == SymbolKind::Function
            && matches!(
                s.name.as_str(),
                "main" | "run" | "cli" | "bootstrap" | "start" | "serve"
            )
    }) {
        let subj = file
            .subjects
            .iter()
            .find(|sub| sub.name.as_deref() == Some(sym.name.as_str()))
            .and_then(|sub| sub.name.clone());
        return (sym.loc, sym.span, sym.name.clone(), subj);
    }
    if let Some(first_fn) = file
        .symbol_outlines
        .iter()
        .find(|s| s.parent_name.is_none() && s.kind == SymbolKind::Function)
    {
        return (
            first_fn.loc,
            first_fn.span,
            first_fn.name.clone(),
            Some(first_fn.name.clone()),
        );
    }
    if let Some(first_io) = file
        .architecture_facets
        .signals_for_bucket(ConcernBucket::DataOrNetworkIo)
        .first()
    {
        return (first_io.loc, first_io.span, first_io.detail.clone(), None);
    }
    let end = u32::try_from(file.source.len()).unwrap_or(0);
    let target = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("entrypoint")
        .to_string();
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan { start: 0, end },
        target,
        None,
    )
}

fn select_mixed_io_presentation_owner_site(
    file: &FileIr,
    first_io: &ConcernSignalSite,
    first_ui: &ConcernSignalSite,
) -> (SourceLoc, ByteSpan, String, Option<String>) {
    if let Some(subj) = file
        .subjects
        .iter()
        .find(|s| spans_contain(s.span, first_io.span) || spans_contain(s.span, first_ui.span))
    {
        let name = subj.name.clone().unwrap_or_else(|| "Component".to_string());
        return (subj.loc, subj.span, name, subj.name.clone());
    }
    if let Some(sym) = file.symbol_outlines.iter().find(|s| {
        s.parent_name.is_none()
            && matches!(s.kind, SymbolKind::Function | SymbolKind::Class)
            && (spans_contain(s.span, first_io.span) || spans_contain(s.span, first_ui.span))
    }) {
        return (sym.loc, sym.span, sym.name.clone(), Some(sym.name.clone()));
    }
    let start = first_io.span.start.min(first_ui.span.start);
    let end = first_io.span.end.max(first_ui.span.end);
    (
        first_io.loc,
        ByteSpan { start, end },
        first_io.detail.clone(),
        None,
    )
}

fn is_thin_route_loader_module(file: &FileIr, io_signals: &[&ConcernSignalSite]) -> bool {
    let loader_fns: Vec<&SymbolOutline> = file
        .symbol_outlines
        .iter()
        .filter(|sym| {
            sym.parent_name.is_none()
                && sym.kind == SymbolKind::Function
                && matches!(
                    sym.name.as_str(),
                    "loader"
                        | "clientLoader"
                        | "action"
                        | "clientAction"
                        | "getServerSideProps"
                        | "getStaticProps"
                        | "generateStaticParams"
                )
        })
        .collect();
    if loader_fns.is_empty() {
        return false;
    }

    // All non-import I/O signals must reside inside the route loader/action functions,
    // not inside the rendered component body.
    io_signals
        .iter()
        .filter(|sig| !sig.detail.starts_with("import "))
        .all(|sig| {
            loader_fns
                .iter()
                .any(|loader| spans_contain(loader.span, sig.span))
        })
}

fn is_single_input_unexported_local_storage_sync(
    file: &FileIr,
    io_signals: &[&ConcernSignalSite],
) -> bool {
    file.module.exports.is_empty()
        && file.module.imports.is_empty()
        && file.jsx_elements.len() <= 1
        && io_signals
            .iter()
            .all(|sig| sig.detail.starts_with("localStorage."))
}

fn is_js_entrypoint_path(path: &Path, source: &str, module: &ModuleIr) -> bool {
    if module.is_aggregation_barrel {
        return false;
    }
    if source.starts_with("#!") {
        return true;
    }

    let components: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => os.to_str(),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return false;
    }
    if components.iter().any(|&c| {
        matches!(
            c,
            "test"
                | "tests"
                | "__tests__"
                | "__mocks__"
                | "fixtures"
                | "stories"
                | "node_modules"
                | "dist"
                | "build"
        )
    }) {
        return false;
    }

    if components[..components.len() - 1].contains(&"bin") {
        return true;
    }

    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let parent_dir = components
        .len()
        .checked_sub(2)
        .and_then(|i| components.get(i).copied());

    match stem {
        "main" | "cli" | "server" => {
            parent_dir.is_none_or(|p| matches!(p, "src" | "app") || components.len() <= 2)
        }
        "index" | "app" => match parent_dir {
            None => true,
            Some("src") => {
                // Allow `src/index.ts` and `packages/foo/src/index.ts`, but reject `src/src/index.ts`
                !components[..components.len() - 2].contains(&"src")
            }
            Some(_) => components.len() == 2,
        },
        _ => false,
    }
}

fn is_js_ui_kit_path(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = stem.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "ui" | "terminal_ui" | "terminal-ui" | "ascii_box" | "primitives" | "box" | "theme"
    ) || lower.ends_with("_ui")
        || lower.ends_with("-ui")
    {
        return true;
    }
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| matches!(s, "ui" | "primitives"))
    })
}

fn count_executable_statements_in_program(program: &Program<'_>) -> usize {
    let mut count = 0;
    for stmt in &program.body {
        count += count_executable_in_statement(stmt);
    }
    count
}

fn count_executable_in_statement(stmt: &Statement<'_>) -> usize {
    match stmt {
        Statement::ImportDeclaration(_)
        | Statement::ExportAllDeclaration(_)
        | Statement::EmptyStatement(_)
        | Statement::TSInterfaceDeclaration(_)
        | Statement::TSTypeAliasDeclaration(_)
        | Statement::TSEnumDeclaration(_) => 0,
        Statement::BlockStatement(block) => {
            block.body.iter().map(count_executable_in_statement).sum()
        }
        Statement::FunctionDeclaration(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        Statement::VariableDeclaration(var_decl) => {
            if var_decl.declare {
                return 0;
            }
            let mut inner = 1;
            for decl in &var_decl.declarations {
                if let Some(init) = &decl.init {
                    inner += count_executable_in_function_expr(init.without_parentheses());
                }
            }
            inner
        }
        Statement::ExportDeclaration(exp) => count_executable_in_declaration(&exp.declaration),
        Statement::ExportNamedDeclaration(_) | Statement::ExportFromDeclaration(_) => 0,
        Statement::ExportDefaultDeclaration(exp) => match &exp.declaration {
            oxc_ast::ast::ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
                func.body.as_ref().map_or(0, |b| {
                    b.statements.iter().map(count_executable_in_statement).sum()
                })
            }
            oxc_ast::ast::ExportDefaultDeclarationKind::ClassDeclaration(_)
            | oxc_ast::ast::ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => 0,
            _ => 1,
        },
        Statement::IfStatement(if_stmt) => {
            1 + count_executable_in_statement(&if_stmt.consequent)
                + if_stmt
                    .alternate
                    .as_ref()
                    .map_or(0, count_executable_in_statement)
        }
        Statement::ForStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::ForInStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::ForOfStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::WhileStatement(w) => 1 + count_executable_in_statement(&w.body),
        Statement::DoWhileStatement(d) => 1 + count_executable_in_statement(&d.body),
        Statement::SwitchStatement(sw) => {
            1 + sw
                .cases
                .iter()
                .flat_map(|c| &c.consequent)
                .map(count_executable_in_statement)
                .sum::<usize>()
        }
        Statement::TryStatement(tr) => {
            let try_cnt: usize = tr
                .block
                .body
                .iter()
                .map(count_executable_in_statement)
                .sum();
            let catch_cnt: usize = tr.handler.as_ref().map_or(0, |h| {
                h.body.body.iter().map(count_executable_in_statement).sum()
            });
            let fin_cnt: usize = tr.finalizer.as_ref().map_or(0, |f| {
                f.body.iter().map(count_executable_in_statement).sum()
            });
            1 + try_cnt + catch_cnt + fin_cnt
        }
        _ => 1,
    }
}

fn count_executable_in_declaration(decl: &oxc_ast::ast::Declaration<'_>) -> usize {
    match decl {
        oxc_ast::ast::Declaration::FunctionDeclaration(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        oxc_ast::ast::Declaration::VariableDeclaration(var_decl) => {
            if var_decl.declare {
                return 0;
            }
            let mut inner = 1;
            for d in &var_decl.declarations {
                if let Some(init) = &d.init {
                    inner += count_executable_in_function_expr(init.without_parentheses());
                }
            }
            inner
        }
        _ => 0,
    }
}

fn count_executable_in_function_expr(expr: &Expression<'_>) -> usize {
    match expr {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            oxc_ast::ast::ArrowFunctionBody::FunctionBody(b) => {
                b.statements.iter().map(count_executable_in_statement).sum()
            }
            _ => 0,
        },
        Expression::FunctionExpression(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        _ => 0,
    }
}

fn extract_static_catalog_sites(
    program: &Program<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
    for stmt in &program.body {
        let (var_decl, outer_span) = match stmt {
            Statement::VariableDeclaration(v) => (v.as_ref(), v.span),
            Statement::ExportDeclaration(exp) => {
                if let oxc_ast::ast::Declaration::VariableDeclaration(v) = &exp.declaration {
                    (v.as_ref(), exp.span)
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        for decl in &var_decl.declarations {
            let BindingPattern::BindingIdentifier(id) = &decl.id else {
                continue;
            };
            let Some(init) = &decl.init else {
                continue;
            };
            let unwrapped = unwrap_type_and_freeze_wrappers(init);
            let Some((entry_count, expr_span)) = count_static_collection_entries(unwrapped) else {
                continue;
            };
            if entry_count < MIN_CANDIDATE_CATALOG_ENTRIES {
                continue;
            }

            let site_span = if var_decl.declarations.len() == 1 {
                outer_span
            } else {
                decl.span
            };
            let byte_len = (expr_span.end.saturating_sub(expr_span.start)) as usize;
            let loc = loc_from_line_starts(line_starts, site_span.start);
            let span = ByteSpan {
                start: site_span.start,
                end: site_span.end,
            };

            facets.static_catalog_sites.push(StaticCatalogSiteIr {
                name: id.name.to_string(),
                entry_count,
                byte_len,
                loc,
                span,
            });

            if entry_count >= DEFAULT_SIGNAL_CATALOG_ENTRIES || byte_len >= 1024 {
                push_concern_signal(
                    facets,
                    seen_signals,
                    line_starts,
                    ConcernBucket::StaticDataCatalog,
                    format!("{} ({entry_count} entries)", id.name),
                    site_span,
                );
            }
        }
    }
}

fn unwrap_type_and_freeze_wrappers<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::TSAsExpression(ts_as) => {
                curr = ts_as.expression.without_parentheses();
            }
            Expression::TSSatisfiesExpression(sat) => {
                curr = sat.expression.without_parentheses();
            }
            Expression::TSTypeAssertion(assert_expr) => {
                curr = assert_expr.expression.without_parentheses();
            }
            Expression::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && obj.name == "Object"
                    && mem.property.name == "freeze"
                    && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                {
                    curr = first_arg.without_parentheses();
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    curr
}

fn count_static_collection_entries(expr: &Expression<'_>) -> Option<(usize, Span)> {
    match expr {
        Expression::ArrayExpression(arr) => {
            let non_spread = arr
                .elements
                .iter()
                .filter(|el| !matches!(el, ArrayExpressionElement::SpreadElement(_)))
                .count();
            Some((non_spread, arr.span))
        }
        Expression::ObjectExpression(obj) => {
            let prop_count = obj
                .properties
                .iter()
                .filter(|p| {
                    matches!(p, ObjectPropertyKind::ObjectProperty(prop) if !prop.method && !matches!(
                        prop.value.without_parentheses(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    ))
                })
                .count();
            Some((prop_count, obj.span))
        }
        Expression::NewExpression(new_expr) => {
            if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                && matches!(id.name.as_str(), "Map" | "Set")
                && let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression())
                && let Expression::ArrayExpression(arr) = unwrap_type_and_freeze_wrappers(first_arg)
            {
                return Some((arr.elements.len(), new_expr.span));
            }
            None
        }
        _ => None,
    }
}

fn is_io_import_source(source: &str) -> bool {
    matches!(
        source,
        "fs" | "node:fs"
            | "fs/promises"
            | "node:fs/promises"
            | "net"
            | "node:net"
            | "http"
            | "node:http"
            | "https"
            | "node:https"
            | "dgram"
            | "node:dgram"
            | "child_process"
            | "node:child_process"
            | "pg"
            | "mysql"
            | "mysql2"
            | "mysql2/promise"
            | "sqlite3"
            | "better-sqlite3"
            | "drizzle-orm"
            | "@prisma/client"
            | "typeorm"
            | "knex"
            | "kysely"
            | "mongoose"
            | "mongodb"
            | "redis"
            | "ioredis"
            | "axios"
            | "undici"
            | "node-fetch"
            | "@supabase/supabase-js"
            | "firebase/firestore"
    )
}

fn is_entrypoint_adapter_import_source(source: &str) -> bool {
    matches!(
        source,
        "react-dom/client"
            | "@angular/platform-browser"
            | "commander"
            | "yargs"
            | "cac"
            | "minimist"
            | "node:util"
    )
}

fn classify_io_call_expression(
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
) -> Option<String> {
    let _ = (semantic, call_node_id);
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => match id.name.as_str() {
            "fetch" | "axios" => Some(format!("{}(...)", id.name)),
            "readFile" | "readFileSync" | "writeFile" | "writeFileSync" | "appendFile"
            | "appendFileSync" | "readdir" | "readdirSync" => Some(format!("{}(...)", id.name)),
            _ => None,
        },
        Expression::StaticMemberExpression(mem) => {
            let prop = mem.property.name.as_str();
            match mem.object.without_parentheses() {
                Expression::Identifier(obj) => {
                    let obj_name = obj.name.as_str();
                    if matches!(obj_name, "window" | "globalThis") && prop == "fetch" {
                        return Some(format!("{obj_name}.fetch(...)"));
                    }
                    if obj_name == "axios"
                        && matches!(
                            prop,
                            "get" | "post" | "put" | "delete" | "patch" | "request" | "head"
                        )
                    {
                        return Some(format!("axios.{prop}(...)"));
                    }
                    if matches!(obj_name, "fs" | "fsPromises")
                        && (prop.starts_with("read")
                            || prop.starts_with("write")
                            || prop.starts_with("append")
                            || prop.starts_with("mkdir")
                            || prop.starts_with("rm")
                            || prop.starts_with("unlink")
                            || prop.starts_with("stat")
                            || prop == "existsSync"
                            || prop == "createReadStream"
                            || prop == "createWriteStream")
                    {
                        return Some(format!("{obj_name}.{prop}(...)"));
                    }
                    if matches!(
                        obj_name,
                        "db" | "pool" | "client" | "conn" | "connection" | "sql" | "knex"
                    ) && matches!(
                        prop,
                        "query"
                            | "execute"
                            | "select"
                            | "insert"
                            | "update"
                            | "delete"
                            | "prepare"
                            | "transaction"
                            | "raw"
                    ) {
                        return Some(format!("{obj_name}.{prop}(...)"));
                    }
                    if obj_name == "prisma" && prop.starts_with('$') {
                        return Some(format!("prisma.{prop}(...)"));
                    }
                    if obj_name == "supabase" && matches!(prop, "from" | "rpc") {
                        return Some(format!("supabase.{prop}(...)"));
                    }
                    if matches!(obj_name, "localStorage" | "sessionStorage")
                        && matches!(prop, "getItem" | "setItem" | "removeItem" | "clear")
                    {
                        return Some(format!("{obj_name}.{prop}(...)"));
                    }
                    if obj_name == "indexedDB" && matches!(prop, "open" | "deleteDatabase") {
                        return Some(format!("indexedDB.{prop}(...)"));
                    }
                    if matches!(obj_name, "http" | "https") && matches!(prop, "get" | "request") {
                        return Some(format!("{obj_name}.{prop}(...)"));
                    }
                    if obj_name == "net" && matches!(prop, "connect" | "createConnection") {
                        return Some(format!("net.{prop}(...)"));
                    }
                    if obj_name == "Bun"
                        && matches!(prop, "file" | "write" | "serve")
                        && prop != "serve"
                    {
                        return Some(format!("Bun.{prop}(...)"));
                    }
                    if obj_name == "Deno" && (prop.starts_with("read") || prop.starts_with("write"))
                    {
                        return Some(format!("Deno.{prop}(...)"));
                    }
                    None
                }
                Expression::StaticMemberExpression(inner_mem) => {
                    if let Expression::Identifier(root_obj) = inner_mem.object.without_parentheses()
                    {
                        let root_name = root_obj.name.as_str();
                        let mid_name = inner_mem.property.name.as_str();
                        if root_name == "prisma"
                            && matches!(
                                prop,
                                "findMany"
                                    | "findUnique"
                                    | "findFirst"
                                    | "findUniqueOrThrow"
                                    | "findFirstOrThrow"
                                    | "create"
                                    | "createMany"
                                    | "update"
                                    | "updateMany"
                                    | "upsert"
                                    | "delete"
                                    | "deleteMany"
                                    | "count"
                                    | "aggregate"
                                    | "groupBy"
                            )
                        {
                            return Some(format!("prisma.{mid_name}.{prop}(...)"));
                        }
                        if root_name == "fs" && mid_name == "promises" {
                            return Some(format!("fs.promises.{prop}(...)"));
                        }
                    }
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn classify_entrypoint_adapter_call(call: &CallExpression<'_>) -> Option<String> {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => match id.name.as_str() {
            "createRoot" | "hydrateRoot" | "bootstrapApplication" | "parseArgs" => {
                Some(format!("{}(...)", id.name))
            }
            _ => None,
        },
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                if obj.name == "process" && mem.property.name == "exit" {
                    return Some("process.exit(...)".to_string());
                }
                if obj.name == "ReactDOM"
                    && matches!(mem.property.name.as_str(), "render" | "createRoot")
                {
                    return Some(format!("ReactDOM.{}(...)", mem.property.name));
                }
            }
            None
        }
        _ => None,
    }
}

fn classify_dom_or_terminal_ui_call(call: &CallExpression<'_>) -> Option<String> {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return None;
    };
    let Expression::Identifier(obj) = mem.object.without_parentheses() else {
        return None;
    };
    let obj_name = obj.name.as_str();
    let prop = mem.property.name.as_str();
    if obj_name == "document" && matches!(prop, "createElement" | "createDocumentFragment") {
        return Some(format!("document.{prop}(...)"));
    }
    if matches!(obj_name, "chalk" | "kleur" | "picocolors" | "pc") {
        return Some(format!("{obj_name}.{prop}(...)"));
    }
    None
}

fn is_root_mount_wrapper_jsx(semantic: &Semantic<'_>, jsx_node_id: NodeId, tag_name: &str) -> bool {
    let is_uppercase_component = tag_name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_uppercase);
    if !is_uppercase_component {
        return false;
    }
    // Check if this JSX opening element is inside a `createRoot(...).render(...)` or `hydrateRoot(...)` call
    semantic.nodes().ancestor_ids(jsx_node_id).any(|anc_id| {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id) {
            match call.callee.without_parentheses() {
                Expression::Identifier(id) => {
                    matches!(id.name.as_str(), "createRoot" | "hydrateRoot")
                }
                Expression::StaticMemberExpression(mem) => mem.property.name == "render",
                _ => false,
            }
        } else {
            false
        }
    })
}

fn classify_terminal_ui_literal(cooked: &str, raw: &str) -> Option<(&'static str, String)> {
    if cooked.contains('\x1b')
        || raw.contains("\\x1b[")
        || raw.contains("\\u001b[")
        || raw.contains("\\033[")
    {
        return Some(("ansi-escape", "\\x1b[".to_string()));
    }
    for ch in cooked.chars() {
        if matches!(
            ch,
            '┌' | '─'
                | '┐'
                | '│'
                | '└'
                | '┘'
                | '├'
                | '┤'
                | '┬'
                | '┴'
                | '┼'
                | '╭'
                | '╮'
                | '╯'
                | '╰'
                | '═'
                | '║'
                | '╔'
                | '╗'
                | '╚'
                | '╝'
        ) {
            let preview: String = cooked.chars().take(12).collect();
            return Some(("box-drawing", preview));
        }
    }
    None
}

fn is_ui_component_class(sym: &SymbolOutline, jsx_elements: &[JsxElementIr], source: &str) -> bool {
    if sym.kind != SymbolKind::Class {
        return false;
    }
    if jsx_elements
        .iter()
        .any(|jsx| spans_contain(sym.span, jsx.span))
    {
        return true;
    }
    let slice = source
        .get(sym.span.start as usize..(sym.span.end as usize).min(source.len()))
        .unwrap_or("");
    slice.contains("@Component")
        || slice.contains("@Directive")
        || slice.contains("extends Component")
        || slice.contains("extends PureComponent")
        || slice.contains("extends React.Component")
}

fn slice_contains_inline_template(source: &str, span: Span) -> bool {
    let slice = source
        .get(span.start as usize..(span.end as usize).min(source.len()))
        .unwrap_or("");
    slice.contains("template:") && slice.contains('<')
}

fn is_helper_or_validator_function(name: &str, source: &str, span: ByteSpan) -> bool {
    let lower = name.to_ascii_lowercase();
    for prefix in [
        "parse",
        "validate",
        "normalize",
        "compute",
        "format",
        "check",
        "is",
        "has",
        "trim",
        "extract",
        "match",
        "resolve",
        "tokenize",
        "visit",
        "build",
        "convert",
        "transform",
        "sanitize",
        "serialize",
        "deserialize",
        "encode",
        "decode",
        "make",
        "filter",
        "sort",
        "merge",
        "split",
    ] {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    let slice = source
        .get(span.start as usize..(span.end as usize).min(source.len()))
        .unwrap_or("");
    slice.contains("if (")
        || slice.contains("switch (")
        || slice.contains("for (")
        || slice.contains("while (")
        || slice.contains(".split(")
        || slice.contains(".trim(")
        || slice.contains(".replace(")
        || slice.contains(".match(")
}

const fn spans_contain(outer: ByteSpan, inner: ByteSpan) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

const fn spans_overlap(a: ByteSpan, b: ByteSpan) -> bool {
    a.start < b.end && b.start < a.end
}
