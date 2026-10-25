//! JavaScript/TypeScript/React/Angular Separation of Concerns (SoC) and Reuse single-pass
//! [`ArchitectureFileFacets`] extraction and rule detectors:
//! - [`RuleId::ArchThinEntrypoint`] (`arch-thin-entrypoint`)
//! - [`RuleId::ArchNoMixedIoAndPresentation`] (`arch-no-mixed-io-and-presentation`)
//! - [`RuleId::ArchSeparateStaticCatalogFromTypes`] (`arch-separate-static-catalog-from-types`)
//! - [`RuleId::ArchNoMixedDomainMonolith`] (`arch-no-mixed-domain-monolith`)
//! - [`RuleId::ArchNoDuplicatedHelperLogic`] (`arch-no-duplicated-helper-logic`)
//! - [`RuleId::ArchPreferFluentBuilder`] (`arch-prefer-fluent-builder`)
//! - [`RuleId::ArchNoInlineTerminalUiPrimitives`] (`arch-no-inline-terminal-ui-primitives`)
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; SoC and reuse extractors match only relevant node kinds"
)]

mod builder_and_terminal_ui;
mod classifiers;
mod helper_duplication;

use std::{collections::BTreeSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{Expression, Program},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

pub(crate) use self::helper_duplication::{
    evaluate_reuse_architecture_rules, extract_reuse_architecture_facets,
};

use self::classifiers::{
    classify_dom_or_terminal_ui_call, classify_entrypoint_adapter_call,
    classify_io_call_expression, classify_terminal_ui_literal,
    count_executable_statements_in_program, extract_static_catalog_sites,
    is_entrypoint_adapter_import_source, is_helper_or_validator_function, is_io_import_source,
    is_js_entrypoint_path, is_js_ui_kit_path, is_root_mount_wrapper_jsx, is_ui_component_class,
    slice_contains_inline_template, spans_contain, spans_overlap,
};
use crate::{
    config::DotoreConfig,
    ir::{
        ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, FileContext, FileIr,
        JsxElementIr, SourceLoc, SubjectIr, SymbolKind, SymbolOutline, loc_from_line_starts,
        react_ast::classify_jsx_element_name, types::ModuleIr,
    },
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, PrescriptionTier, RuleId, RuleSeverity},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MonolithSymbolCategory {
    TypeDefinition,
    Class,
    Callable,
    ValueBinding,
}

/// Minimum static collection entries recorded in [`ArchitectureFileFacets::static_catalog_sites`]
/// during single-pass extraction so custom `config.architecture.min_static_catalog_entries`
/// overrides (including lowered thresholds in tests) can be evaluated without re-parsing.
pub(super) const MIN_CANDIDATE_CATALOG_ENTRIES: usize = 3;

/// Entry threshold above which a static catalog also registers a [`ConcernBucket::StaticDataCatalog`]
/// signal in [`ArchitectureFileFacets::concern_signals`].
pub(super) const DEFAULT_SIGNAL_CATALOG_ENTRIES: usize = 15;

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

    collect_import_concern_signals(module, line_starts, facets, &mut seen_signals);
    collect_top_level_type_signals(
        source,
        subjects,
        jsx_elements,
        symbol_outlines,
        line_starts,
        facets,
        &mut seen_signals,
    );
    extract_static_catalog_sites(program, line_starts, facets, &mut seen_signals);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        collect_ast_node_concern_signal(
            source,
            semantic,
            node_id,
            node.kind(),
            line_starts,
            facets,
            &mut seen_signals,
        );
    }

    collect_helper_function_signals(
        source,
        subjects,
        symbol_outlines,
        line_starts,
        facets,
        &mut seen_signals,
    );

    facets.domain_clusters = facets
        .distinct_concern_buckets()
        .into_iter()
        .filter(|&bucket| bucket != ConcernBucket::EntrypointAdapter)
        .map(|bucket| bucket.as_str().to_string())
        .collect();
}

fn collect_import_concern_signals(
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
    for imp in &module.imports {
        if imp.is_type_only {
            continue;
        }
        let raw_span = Span::new(imp.span.start, imp.span.end);
        if is_io_import_source(&imp.source) {
            push_concern_signal(
                facets,
                seen_signals,
                line_starts,
                ConcernBucket::DataOrNetworkIo,
                format!("import '{}'", imp.source),
                raw_span,
            );
        } else if is_entrypoint_adapter_import_source(&imp.source) {
            push_concern_signal(
                facets,
                seen_signals,
                line_starts,
                ConcernBucket::EntrypointAdapter,
                format!("import '{}'", imp.source),
                raw_span,
            );
        }
    }
}

fn collect_top_level_type_signals(
    source: &str,
    subjects: &[SubjectIr],
    jsx_elements: &[JsxElementIr],
    symbol_outlines: &[SymbolOutline],
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
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
                seen_signals,
                line_starts,
                ConcernBucket::TypeDefinitions,
                format!("{} {}", sym.kind.as_str(), sym.name),
                Span::new(sym.span.start, sym.span.end),
            );
        }
    }
}

fn collect_ast_node_concern_signal(
    source: &str,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
    if let Some((bucket, detail, span)) =
        classify_primary_concern_node(source, semantic, node_id, kind)
    {
        push_concern_signal(facets, seen_signals, line_starts, bucket, detail, span);
        return;
    }
    if let Some((bucket, detail, span)) = classify_literal_or_template_concern_node(source, kind) {
        push_concern_signal(facets, seen_signals, line_starts, bucket, detail, span);
    }
}

fn classify_primary_concern_node(
    source: &str,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
) -> Option<(ConcernBucket, String, Span)> {
    match kind {
        AstKind::CallExpression(call) => {
            let (bucket, detail) = classify_call_concern_signal(call, semantic, node_id)?;
            Some((bucket, detail, call.span))
        }
        AstKind::NewExpression(new_expr) => {
            if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                && matches!(id.name.as_str(), "WebSocket" | "XMLHttpRequest" | "Pool")
            {
                return Some((
                    ConcernBucket::DataOrNetworkIo,
                    format!("new {}()", id.name),
                    new_expr.span,
                ));
            }
            None
        }
        AstKind::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses()
                && obj.name == "process"
                && mem.property.name == "argv"
            {
                return Some((
                    ConcernBucket::EntrypointAdapter,
                    "process.argv".to_string(),
                    mem.span,
                ));
            }
            None
        }
        AstKind::JSXOpeningElement(opening) => {
            let (tag_name, _, _, _) = classify_jsx_element_name(semantic, &opening.name);
            if !is_root_mount_wrapper_jsx(semantic, node_id, &tag_name) {
                return Some((
                    ConcernBucket::TerminalOrUiPresentation,
                    format!("<{tag_name}>"),
                    opening.span,
                ));
            }
            None
        }
        AstKind::Decorator(dec) => {
            if let Expression::CallExpression(call) = dec.expression.without_parentheses()
                && let Expression::Identifier(id) = call.callee.without_parentheses()
                && id.name == "Component"
                && slice_contains_inline_template(source, dec.span)
            {
                return Some((
                    ConcernBucket::TerminalOrUiPresentation,
                    "@Component(template)".to_string(),
                    dec.span,
                ));
            }
            None
        }
        _ => None,
    }
}

fn classify_literal_or_template_concern_node(
    source: &str,
    kind: AstKind<'_>,
) -> Option<(ConcernBucket, String, Span)> {
    match kind {
        AstKind::TaggedTemplateExpression(tagged) => {
            let tag_name = match tagged.tag.without_parentheses() {
                Expression::Identifier(id) => Some(id.name.as_str()),
                Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
                _ => None,
            };
            tag_name
                .is_some_and(|n| matches!(n, "sql" | "$queryRaw" | "$executeRaw"))
                .then(|| (ConcernBucket::DataOrNetworkIo, "sql`...`".to_string(), tagged.span))
        }
        AstKind::StringLiteral(lit) => {
            let cooked = lit.value.as_str().unwrap_or("");
            let raw = source
                .get(lit.span.start as usize..lit.span.end as usize)
                .unwrap_or(cooked);
            let (kind, snippet) = classify_terminal_ui_literal(cooked, raw)?;
            Some((
                ConcernBucket::TerminalOrUiPresentation,
                format!("{kind}: {snippet}"),
                lit.span,
            ))
        }
        AstKind::TemplateElement(tpl) => {
            let cooked = tpl
                .value
                .cooked
                .as_ref()
                .and_then(|c| c.as_str())
                .unwrap_or(tpl.value.raw.as_str());
            let (kind, snippet) = classify_terminal_ui_literal(cooked, tpl.value.raw.as_str())?;
            Some((
                ConcernBucket::TerminalOrUiPresentation,
                format!("{kind}: {snippet}"),
                tpl.span,
            ))
        }
        _ => None,
    }
}

fn classify_call_concern_signal(
    call: &oxc_ast::ast::CallExpression<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<(ConcernBucket, String)> {
    if let Some(detail) = classify_io_call_expression(call, semantic, node_id) {
        return Some((ConcernBucket::DataOrNetworkIo, detail));
    }
    if let Some(detail) = classify_entrypoint_adapter_call(call) {
        return Some((ConcernBucket::EntrypointAdapter, detail));
    }
    classify_dom_or_terminal_ui_call(call)
        .map(|detail| (ConcernBucket::TerminalOrUiPresentation, detail))
}

fn collect_helper_function_signals(
    source: &str,
    subjects: &[SubjectIr],
    symbol_outlines: &[SymbolOutline],
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
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
                seen_signals,
                line_starts,
                ConcernBucket::AstOrValidationHelper,
                format!("fn {}", sym.name),
                Span::new(sym.span.start, sym.span.end),
            );
        }
    }
}

pub(super) fn push_concern_signal(
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

    let mut symbol_categories: BTreeSet<MonolithSymbolCategory> = BTreeSet::new();
    for sym in &top_level_symbols {
        let cat = match sym.kind {
            SymbolKind::Interface | SymbolKind::Type | SymbolKind::Enum => {
                Some(MonolithSymbolCategory::TypeDefinition)
            }
            SymbolKind::Class => Some(MonolithSymbolCategory::Class),
            SymbolKind::Function | SymbolKind::Method => Some(MonolithSymbolCategory::Callable),
            SymbolKind::Constant | SymbolKind::Variable | SymbolKind::Property => {
                Some(MonolithSymbolCategory::ValueBinding)
            }
            SymbolKind::EnumMember | SymbolKind::Export | SymbolKind::Import => None,
        };
        if let Some(cat) = cat {
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

    let Some(&primary_sym) = top_level_symbols.first() else {
        return;
    };
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
        || file.suppressions.matches_line(rule, 1)
        || file.suppressions.matches_line(rule, 2)
    {
        return true;
    }
    file.symbol_outlines.iter().any(|sym| {
        sym.span.start <= span.start
            && span.end <= sym.span.end
            && file.suppressions.matches_line(rule, sym.loc.line)
    })
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
