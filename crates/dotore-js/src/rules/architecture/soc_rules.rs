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

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use dotore_core::ir::{FNV1A_64_OFFSET_BASIS, fnv1a_64_step};
use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, BindingPattern, CallExpression, ClassElement, Expression,
        ObjectPropertyKind, Program, Statement, TSSignature, TSType, TSTypeName,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, FileContext, FileIr,
        HelperFingerprintIr, InlineTerminalUiPrimitiveSiteIr, JsxElementIr, SourceLoc,
        StaticCatalogSiteIr, StructLiteralConstructionSiteIr, SubjectIr, SymbolKind, SymbolOutline,
        TerminalUiPrimitiveKind, classify_file_context, loc_from_line_starts,
        react_ast::classify_jsx_element_name, types::ModuleIr,
    },
    matchers::{make_diag_for_subject, resolve_ident_symbol},
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
    let norm = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if norm.contains("components/ui")
        || norm.contains("terminal_ui")
        || norm.contains("terminal-ui")
        || norm.contains("ascii_box")
    {
        return true;
    }
    norm.split(['/', '_', '-', '.']).any(|seg| {
        matches!(
            seg,
            "ui" | "primitives" | "theme" | "themes" | "box" | "boxes" | "ansi" | "tui"
        )
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

const BOX_DRAWING_CHARS: &[char] = &[
    '┌', '─', '┐', '│', '└', '┘', '╭', '╮', '╰', '╯', '├', '┤', '┬', '┴', '┼', '═', '║', '╔', '╗',
    '╚', '╝',
];

fn classify_terminal_ui_literal(
    cooked: &str,
    raw: &str,
) -> Option<(TerminalUiPrimitiveKind, String)> {
    let raw_lower = raw.to_ascii_lowercase();
    if cooked.contains('\x1b')
        || raw_lower.contains("\\x1b[")
        || raw_lower.contains("\\u001b[")
        || raw_lower.contains("\\u{1b}[")
        || raw_lower.contains("\\u{001b}[")
        || raw.contains("\\033[")
    {
        return Some((
            TerminalUiPrimitiveKind::AnsiEscape,
            "\\x1b[...]".to_string(),
        ));
    }
    if let Some(ch) = BOX_DRAWING_CHARS
        .iter()
        .copied()
        .find(|&c| cooked.contains(c) || raw.contains(c))
    {
        return Some((TerminalUiPrimitiveKind::BoxDrawing, ch.to_string()));
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

/// Extracts single-pass structural facets for helper duplication (`HelperFingerprintIr`),
/// builder candidates (`StructLiteralConstructionSiteIr`, `defined_builder_types`),
/// and inline terminal UI primitives (`InlineTerminalUiPrimitiveSiteIr`, `is_ui_kit_module`).
pub(crate) fn extract_reuse_architecture_facets(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    extract_helper_fingerprints_in_file(semantic, subjects, module, line_starts, facets);
    extract_builder_facets_in_file(semantic, line_starts, facets);
    extract_inline_terminal_ui_sites_in_file(path, source, semantic, line_starts, facets);
}

fn extract_helper_fingerprints_in_file(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let exported_names: HashSet<&str> = module
        .exports
        .iter()
        .flat_map(|e| std::iter::once(e.name.as_str()).chain(e.local_name.as_deref()))
        .collect();
    let subject_names: HashSet<&str> = subjects.iter().filter_map(|s| s.name.as_deref()).collect();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let Some(body) = &func.body else {
                    continue;
                };
                if !is_module_scope_helper_decl(semantic, node_id) {
                    continue;
                }
                let fn_name = id.name.as_str();
                if subject_names.contains(fn_name) || span_contains_jsx(semantic, body.span) {
                    continue;
                }
                let is_exported =
                    exported_names.contains(fn_name) || has_export_ancestor(semantic, node_id);
                if is_exported {
                    continue;
                }
                let param_count = func.params.items.len();
                let has_rest = func.params.rest.is_some();
                let (normalized_hash, statement_count) = compute_helper_body_fingerprint(
                    semantic,
                    node_id,
                    func.span,
                    body.span,
                    param_count,
                    has_rest,
                );
                if statement_count >= 2 {
                    facets.helper_fingerprints.push(HelperFingerprintIr {
                        name: fn_name.to_string(),
                        normalized_hash,
                        statement_count,
                        param_count,
                        is_private: true,
                        loc: loc_from_line_starts(line_starts, func.span.start),
                        span: ByteSpan {
                            start: func.span.start,
                            end: func.span.end,
                        },
                    });
                }
            }
            AstKind::VariableDeclarator(decl) => {
                let BindingPattern::BindingIdentifier(id) = &decl.id else {
                    continue;
                };
                let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
                    continue;
                };
                if !is_module_scope_helper_decl(semantic, node_id) {
                    continue;
                }
                let fn_name = id.name.as_str();
                if subject_names.contains(fn_name) {
                    continue;
                }
                let is_exported =
                    exported_names.contains(fn_name) || has_export_ancestor(semantic, node_id);
                if is_exported {
                    continue;
                }
                let (fn_span, body_span, param_count, has_rest) = match init {
                    Expression::ArrowFunctionExpression(arrow) => (
                        arrow.span,
                        arrow.body.span(),
                        arrow.params.items.len(),
                        arrow.params.rest.is_some(),
                    ),
                    Expression::FunctionExpression(func) => {
                        let Some(body) = &func.body else {
                            continue;
                        };
                        (
                            func.span,
                            body.span,
                            func.params.items.len(),
                            func.params.rest.is_some(),
                        )
                    }
                    _ => continue,
                };
                if span_contains_jsx(semantic, body_span) {
                    continue;
                }
                let (normalized_hash, statement_count) = compute_helper_body_fingerprint(
                    semantic,
                    node_id,
                    fn_span,
                    body_span,
                    param_count,
                    has_rest,
                );
                if statement_count >= 2 {
                    let parent_id = semantic.nodes().parent_id(node_id);
                    let full_span = if let AstKind::VariableDeclaration(var_decl) =
                        semantic.nodes().kind(parent_id)
                        && var_decl.declarations.len() == 1
                    {
                        var_decl.span
                    } else {
                        decl.span
                    };
                    facets.helper_fingerprints.push(HelperFingerprintIr {
                        name: fn_name.to_string(),
                        normalized_hash,
                        statement_count,
                        param_count,
                        is_private: true,
                        loc: loc_from_line_starts(line_starts, full_span.start),
                        span: ByteSpan {
                            start: full_span.start,
                            end: full_span.end,
                        },
                    });
                }
            }
            _ => {}
        }
    }
}

fn is_module_scope_helper_decl(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    !semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_)
                | AstKind::ArrowFunctionExpression(_)
                | AstKind::Class(_)
                | AstKind::ObjectExpression(_)
        )
    })
}

fn has_export_ancestor(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ExportNamedDeclaration(_)
                | AstKind::ExportDefaultDeclaration(_)
                | AstKind::TSExportAssignment(_)
        )
    })
}

fn span_contains_jsx(semantic: &Semantic<'_>, span: Span) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        let s = n.span();
        s.start >= span.start
            && s.end <= span.end
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn compute_helper_body_fingerprint(
    semantic: &Semantic<'_>,
    _owner_id: NodeId,
    fn_span: Span,
    body_span: Span,
    param_count: usize,
    has_rest: bool,
) -> (u64, usize) {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    hash = fnv1a_64_step(hash, b"HelperArity");
    hash = fnv1a_64_step(hash, &param_count.to_le_bytes());
    hash = fnv1a_64_step(hash, &[u8::from(has_rest)]);

    let mut statement_count = 0_usize;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let sp = node.span();
        if sp.start < body_span.start || sp.end > body_span.end {
            continue;
        }
        match node.kind() {
            AstKind::VariableDeclaration(decl) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"VarDecl");
                hash = fnv1a_64_step(hash, decl.kind.as_str().as_bytes());
            }
            AstKind::VariableDeclarator(_) => {
                hash = fnv1a_64_step(hash, b"VarDeclarator");
            }
            AstKind::BindingIdentifier(_) => {
                hash = fnv1a_64_step(hash, b"BindIdent");
            }
            AstKind::ObjectPattern(_) => {
                hash = fnv1a_64_step(hash, b"ObjPat");
            }
            AstKind::ArrayPattern(_) => {
                hash = fnv1a_64_step(hash, b"ArrPat");
            }
            AstKind::ExpressionStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"ExprStmt");
            }
            AstKind::ReturnStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Return");
            }
            AstKind::IfStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"If");
            }
            AstKind::ForStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"For");
            }
            AstKind::ForInStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"ForIn");
            }
            AstKind::ForOfStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"ForOf");
            }
            AstKind::WhileStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"While");
            }
            AstKind::DoWhileStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"DoWhile");
            }
            AstKind::SwitchStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Switch");
            }
            AstKind::SwitchCase(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"SwitchCase");
            }
            AstKind::TryStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Try");
            }
            AstKind::CatchClause(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Catch");
            }
            AstKind::ThrowStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Throw");
            }
            AstKind::BreakStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Break");
            }
            AstKind::ContinueStatement(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"Continue");
            }
            AstKind::ConditionalExpression(_) => {
                statement_count += 1;
                hash = fnv1a_64_step(hash, b"CondExpr");
            }
            AstKind::BinaryExpression(e) => {
                hash = fnv1a_64_step(hash, b"BinOp");
                hash = fnv1a_64_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::LogicalExpression(e) => {
                hash = fnv1a_64_step(hash, b"LogOp");
                hash = fnv1a_64_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::UnaryExpression(e) => {
                hash = fnv1a_64_step(hash, b"UnOp");
                hash = fnv1a_64_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::UpdateExpression(e) => {
                hash = fnv1a_64_step(hash, b"UpdOp");
                hash = fnv1a_64_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::AssignmentExpression(e) => {
                hash = fnv1a_64_step(hash, b"AssignOp");
                hash = fnv1a_64_step(hash, e.operator.as_str().as_bytes());
            }
            AstKind::CallExpression(call) => {
                hash = fnv1a_64_step(hash, b"Call");
                hash = fnv1a_64_step(hash, &call.arguments.len().to_le_bytes());
                match call.callee.without_parentheses() {
                    Expression::Identifier(ident) => {
                        let is_local =
                            resolve_ident_symbol(semantic, ident).is_some_and(|sym_id| {
                                let decl_span = semantic
                                    .nodes()
                                    .get_node(semantic.scoping().symbol_declaration(sym_id))
                                    .span();
                                decl_span.start >= fn_span.start && decl_span.end <= fn_span.end
                            });
                        if is_local {
                            hash = fnv1a_64_step(hash, b"local_fn");
                        } else {
                            hash = fnv1a_64_step(hash, ident.name.as_bytes());
                        }
                    }
                    Expression::StaticMemberExpression(mem) => {
                        hash = fnv1a_64_step(hash, mem.property.name.as_bytes());
                    }
                    _ => {}
                }
            }
            AstKind::NewExpression(new_e) => {
                hash = fnv1a_64_step(hash, b"New");
                hash = fnv1a_64_step(hash, &new_e.arguments.len().to_le_bytes());
                if let Expression::Identifier(ident) = new_e.callee.without_parentheses() {
                    hash = fnv1a_64_step(hash, ident.name.as_bytes());
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                hash = fnv1a_64_step(hash, b"Member");
                hash = fnv1a_64_step(hash, mem.property.name.as_bytes());
            }
            AstKind::ComputedMemberExpression(_) => {
                hash = fnv1a_64_step(hash, b"ComputedMember");
            }
            AstKind::IdentifierReference(_) => {
                let parent_kind = semantic.nodes().kind(semantic.nodes().parent_id(node_id));
                if !matches!(
                    parent_kind,
                    AstKind::CallExpression(_) | AstKind::NewExpression(_)
                ) {
                    hash = fnv1a_64_step(hash, b"IdentRef");
                }
            }
            AstKind::StringLiteral(_) => {
                hash = fnv1a_64_step(hash, b"StrLit");
            }
            AstKind::NumericLiteral(_) => {
                hash = fnv1a_64_step(hash, b"NumLit");
            }
            AstKind::BooleanLiteral(b) => {
                hash = fnv1a_64_step(hash, if b.value { b"BoolTrue" } else { b"BoolFalse" });
            }
            AstKind::NullLiteral(_) => {
                hash = fnv1a_64_step(hash, b"NullLit");
            }
            AstKind::RegExpLiteral(r) => {
                hash = fnv1a_64_step(hash, b"RegexLit");
                hash = fnv1a_64_step(hash, r.regex.pattern.text.as_bytes());
            }
            AstKind::TemplateLiteral(t) => {
                hash = fnv1a_64_step(hash, b"TplLit");
                hash = fnv1a_64_step(hash, &t.expressions.len().to_le_bytes());
            }
            AstKind::ArrayExpression(a) => {
                hash = fnv1a_64_step(hash, b"ArrExpr");
                hash = fnv1a_64_step(hash, &a.elements.len().to_le_bytes());
            }
            AstKind::ObjectExpression(o) => {
                hash = fnv1a_64_step(hash, b"ObjExpr");
                hash = fnv1a_64_step(hash, &o.properties.len().to_le_bytes());
            }
            AstKind::AwaitExpression(_) => {
                hash = fnv1a_64_step(hash, b"Await");
            }
            AstKind::SpreadElement(_) => {
                hash = fnv1a_64_step(hash, b"Spread");
            }
            _ => {}
        }
    }

    (hash, statement_count)
}

pub(super) fn evaluate_reuse_architecture_rules<F>(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    if packages.is_empty() {
        return;
    }
    let mut buckets: Vec<Vec<&FileIr>> = (0..packages.len()).map(|_| Vec::new()).collect();
    for f in &graph.files {
        if f.file_context != FileContext::Production {
            continue;
        }
        let Some(resolved) = resolve_package_for_file(&f.path, packages) else {
            continue;
        };
        if let Some(idx) = packages
            .iter()
            .position(|p| p.root_dir == resolved.root_dir)
            && !packages[idx]
                .config
                .is_file_ignored(&f.path, &packages[idx].root_dir)
        {
            buckets[idx].push(f);
        }
    }

    for (pkg, pkg_files) in packages.iter().zip(buckets) {
        if pkg_files.is_empty() {
            continue;
        }
        evaluate_duplicated_helpers_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_prefer_fluent_builder_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_inline_terminal_ui_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
    }
}

fn evaluate_duplicated_helpers_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    let min_stmts = pkg.config.architecture.min_helper_statements;
    let min_modules = pkg.config.architecture.min_duplicated_helper_modules;

    let mut by_fingerprint: BTreeMap<(u64, usize), Vec<(&FileIr, &HelperFingerprintIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for helper in &file.architecture_facets.helper_fingerprints {
            if !helper.is_private || helper.statement_count < min_stmts {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    helper.loc.line,
                    helper.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            by_fingerprint
                .entry((helper.normalized_hash, helper.param_count))
                .or_default()
                .push((file, helper));
        }
    }

    for ((hash, param_count), occurrences) in by_fingerprint {
        let distinct_files: BTreeSet<&Path> =
            occurrences.iter().map(|(f, _)| f.path.as_path()).collect();
        if distinct_files.len() < min_modules {
            continue;
        }

        let first_name = &occurrences[0].1.name;
        let all_same_name = occurrences.iter().all(|(_, h)| &h.name == first_name);
        let shared_target_name = if all_same_name {
            first_name.clone()
        } else {
            format!(
                "{}::arity{}::hash_{:08x}",
                first_name,
                param_count,
                (hash & 0xffff_ffff) as u32
            )
        };

        let cascade_steps: Vec<String> = occurrences
            .iter()
            .map(|(f, h)| {
                format!(
                    "{}:{} (`{}`: {} stmts, arity {})",
                    f.path.to_string_lossy().replace('\\', "/"),
                    h.loc.line,
                    h.name,
                    h.statement_count,
                    h.param_count
                )
            })
            .collect();

        for (idx, &(file, helper)) in occurrences.iter().enumerate() {
            let Some(sev) = resolve_activation(
                RuleId::ArchNoDuplicatedHelperLogic,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };

            let peer_caller_sites: Vec<ResolvedCallerSite> = occurrences
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_helper))| ResolvedCallerSite {
                    caller_file: peer_file.path.clone(),
                    parent_subject_name: Some(peer_helper.name.clone()),
                    component_name: helper.name.clone(),
                    loc: peer_helper.loc,
                    span: peer_helper.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            let peer_files_summary: Vec<String> = occurrences
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_helper))| {
                    format!(
                        "`{}` in `{}:{}`",
                        peer_helper.name,
                        peer_file.path.to_string_lossy().replace('\\', "/"),
                        peer_helper.loc.line
                    )
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    file.path.clone(),
                    Some(helper.name.clone()),
                    "archNoDuplicatedHelperLogic",
                    shared_target_name.clone(),
                    format!(
                        "Private helper `{}` ({} statements, arity {}) duplicates normalized AST structure across {} modules ({}); extract a shared helper module.",
                        helper.name,
                        helper.statement_count,
                        helper.param_count,
                        distinct_files.len(),
                        peer_files_summary.join(", ")
                    ),
                    helper.loc,
                    helper.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}

fn extract_builder_facets_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let mut defined_builders: BTreeSet<String> = BTreeSet::new();
    let mut builder_body_spans: Vec<Span> = Vec::new();
    let mut local_type_shapes: Vec<(String, BTreeSet<String>)> = Vec::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Class(cls) => {
                let Some(id) = &cls.id else {
                    continue;
                };
                let cls_name = id.name.as_str();
                let mut is_builder_cls = false;
                if let Some(base) = cls_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(cls_name.to_string());
                    defined_builders.insert(base.to_string());
                    is_builder_cls = true;
                }
                let has_fluent_methods = cls.body.body.iter().any(|el| {
                    let ClassElement::MethodDefinition(m) = el else {
                        return false;
                    };
                    let Some(m_key) = m.key.static_name() else {
                        return false;
                    };
                    let Some(m_name) = m_key.as_str() else {
                        return false;
                    };
                    m_name == "builder"
                        || (m_name.starts_with("with")
                            && m_name.as_bytes().get(4).is_some_and(u8::is_ascii_uppercase))
                });
                if has_fluent_methods {
                    defined_builders.insert(cls_name.to_string());
                    is_builder_cls = true;
                }
                if is_builder_cls {
                    builder_body_spans.push(cls.span);
                }
            }
            AstKind::TSInterfaceDeclaration(iface) => {
                let iface_name = iface.id.name.as_str();
                if let Some(base) = iface_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(iface_name.to_string());
                    defined_builders.insert(base.to_string());
                }
                let prop_names = collect_ts_property_names(&iface.body.body);
                if prop_names.len() >= 3 {
                    local_type_shapes.push((iface_name.to_string(), prop_names));
                }
            }
            AstKind::TSTypeAliasDeclaration(alias) => {
                let alias_name = alias.id.name.as_str();
                if let Some(base) = alias_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    defined_builders.insert(alias_name.to_string());
                    defined_builders.insert(base.to_string());
                }
                if let TSType::TSTypeLiteral(lit) = &alias.type_annotation {
                    let prop_names = collect_ts_property_names(&lit.members);
                    if prop_names.len() >= 3 {
                        local_type_shapes.push((alias_name.to_string(), prop_names));
                    }
                }
            }
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && let Some(target_type) = extract_factory_target_type(
                        id.name.as_str(),
                        func.return_type.as_ref().map(|r| &r.type_annotation),
                    )
                {
                    defined_builders.insert(target_type);
                    builder_body_spans.push(func.span);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let BindingPattern::BindingIdentifier(id) = &decl.id
                    && let Some(init) = decl.init.as_ref().map(Expression::without_parentheses)
                {
                    let ret_type = match init {
                        Expression::ArrowFunctionExpression(a) => {
                            a.return_type.as_ref().map(|r| &r.type_annotation)
                        }
                        Expression::FunctionExpression(f) => {
                            f.return_type.as_ref().map(|r| &r.type_annotation)
                        }
                        _ => None,
                    };
                    if matches!(
                        init,
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    ) && let Some(target_type) =
                        extract_factory_target_type(id.name.as_str(), ret_type)
                    {
                        defined_builders.insert(target_type);
                        builder_body_spans.push(decl.span);
                    }
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && mem.property.name == "builder"
                    && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                {
                    defined_builders.insert(obj_id.name.to_string());
                }
            }
            _ => {}
        }
    }

    facets.defined_builder_types.extend(defined_builders);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ObjectExpression(obj) = node.kind() else {
            continue;
        };
        if builder_body_spans
            .iter()
            .any(|sp| obj.span.start >= sp.start && obj.span.end <= sp.end)
        {
            continue;
        }
        let mut field_names = Vec::new();
        let mut default_or_literal_fields = Vec::new();
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Some(key_name) = prop.key.static_name() else {
                continue;
            };
            let Some(key_s) = key_name.as_str() else {
                continue;
            };
            if is_default_or_boilerplate_literal(&prop.value) {
                default_or_literal_fields.push(key_s.to_string());
            }
            field_names.push(key_s.to_string());
        }

        if field_names.len() < 3 || default_or_literal_fields.is_empty() {
            continue;
        }

        let (type_name, site_span) = resolve_object_literal_type_and_span(
            semantic,
            node_id,
            obj.span,
            &field_names,
            &local_type_shapes,
        );
        let Some(resolved_type) = type_name else {
            continue;
        };

        facets
            .struct_literal_sites
            .push(StructLiteralConstructionSiteIr {
                type_name: resolved_type,
                field_names,
                default_or_literal_fields,
                loc: loc_from_line_starts(line_starts, site_span.start),
                span: ByteSpan {
                    start: site_span.start,
                    end: site_span.end,
                },
            });
    }
}

fn extract_factory_target_type(fn_name: &str, return_type: Option<&TSType<'_>>) -> Option<String> {
    for prefix in ["create", "build", "make"] {
        if let Some(rest) = fn_name.strip_prefix(prefix)
            && rest.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        {
            if let Some(ret) = return_type.and_then(extract_ts_type_ref_name) {
                if ret == rest {
                    return Some(ret);
                }
            } else {
                return Some(rest.to_string());
            }
        }
    }
    if let Some(base) = fn_name.strip_suffix("Builder")
        && !base.is_empty()
    {
        let mut chars = base.chars();
        if let Some(first) = chars.next() {
            let mut pascal = first.to_ascii_uppercase().to_string();
            pascal.push_str(chars.as_str());
            return Some(pascal);
        }
    }
    None
}

fn extract_ts_type_ref_name(ts_type: &TSType<'_>) -> Option<String> {
    match ts_type {
        TSType::TSTypeReference(type_ref) => match &type_ref.type_name {
            TSTypeName::IdentifierReference(ident) => {
                if matches!(ident.name.as_str(), "Array" | "ReadonlyArray") {
                    type_ref
                        .type_arguments
                        .as_ref()
                        .and_then(|args| args.params.first())
                        .and_then(extract_ts_type_ref_name)
                } else {
                    Some(ident.name.to_string())
                }
            }
            TSTypeName::QualifiedName(q) => Some(q.right.name.to_string()),
            TSTypeName::ThisExpression(_) => None,
        },
        TSType::TSArrayType(arr) => extract_ts_type_ref_name(&arr.element_type),
        TSType::TSParenthesizedType(p) => extract_ts_type_ref_name(&p.type_annotation),
        _ => None,
    }
}

fn is_default_or_boilerplate_literal(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => u.operator.as_str() == "void",
        Expression::BooleanLiteral(b) => !b.value,
        Expression::NumericLiteral(n) => n.value == 0.0,
        Expression::BigIntLiteral(b) => b.value == "0",
        Expression::StringLiteral(s) => s.value.is_empty(),
        Expression::TemplateLiteral(t) => {
            t.expressions.is_empty() && t.quasis.iter().all(|q| q.value.raw.is_empty())
        }
        Expression::ArrayExpression(arr) => arr.elements.is_empty(),
        Expression::ObjectExpression(obj) => obj.properties.is_empty(),
        _ => false,
    }
}

fn resolve_object_literal_type_and_span(
    semantic: &Semantic<'_>,
    obj_node_id: NodeId,
    obj_span: Span,
    field_names: &[String],
    local_type_shapes: &[(String, BTreeSet<String>)],
) -> (Option<String>, Span) {
    for anc_id in semantic.nodes().ancestor_ids(obj_node_id) {
        if anc_id == obj_node_id {
            continue;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_) => {}
            AstKind::TSTypeAssertion(ta) => {
                if let Some(name) = extract_ts_type_ref_name(&ta.type_annotation) {
                    return (Some(name), ta.span);
                }
            }
            AstKind::TSAsExpression(as_e) => {
                if let Some(name) = extract_ts_type_ref_name(&as_e.type_annotation) {
                    return (Some(name), as_e.span);
                }
            }
            AstKind::TSSatisfiesExpression(sat_e) => {
                if let Some(name) = extract_ts_type_ref_name(&sat_e.type_annotation) {
                    return (Some(name), sat_e.span);
                }
            }
            AstKind::NewExpression(new_e) => {
                let name_opt = match new_e.callee.without_parentheses() {
                    Expression::Identifier(id) => Some(id.name.to_string()),
                    Expression::StaticMemberExpression(mem) => Some(mem.property.name.to_string()),
                    _ => None,
                };
                if let Some(name) = name_opt {
                    return (Some(name), new_e.span);
                }
                break;
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(ann) = &decl.type_annotation
                    && let Some(name) = extract_ts_type_ref_name(&ann.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::PropertyDefinition(prop) => {
                if let Some(ann) = &prop.type_annotation
                    && let Some(name) = extract_ts_type_ref_name(&ann.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ReturnStatement(_) => {
                if let Some(name) = enclosing_function_return_type_name(semantic, anc_id) {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                if let Some(ret) = &arrow.return_type
                    && let Some(name) = extract_ts_type_ref_name(&ret.type_annotation)
                {
                    return (Some(name), obj_span);
                }
                break;
            }
            AstKind::ObjectExpression(_) | AstKind::CallExpression(_) | AstKind::Function(_) => {
                break;
            }
            _ => {}
        }
    }

    let field_set: BTreeSet<String> = field_names.iter().cloned().collect();
    if let Some((matched_type, _)) = local_type_shapes
        .iter()
        .find(|(_, props)| props == &field_set)
    {
        return (Some(matched_type.clone()), obj_span);
    }

    if field_names.len() >= 5 {
        let sorted: Vec<&str> = field_set.iter().map(String::as_str).collect();
        return (Some(format!("ObjectShape<{}>", sorted.join(","))), obj_span);
    }

    (None, obj_span)
}

fn collect_ts_property_names(signatures: &[TSSignature<'_>]) -> BTreeSet<String> {
    let mut prop_names = BTreeSet::new();
    for sig in signatures {
        if let TSSignature::TSPropertySignature(prop) = sig
            && let Some(key) = prop.key.static_name()
            && let Some(key_str) = key.as_str()
        {
            prop_names.insert(key_str.to_string());
        }
    }
    prop_names
}

fn enclosing_function_return_type_name(
    semantic: &Semantic<'_>,
    start_id: NodeId,
) -> Option<String> {
    for fn_anc_id in semantic.nodes().ancestor_ids(start_id) {
        match semantic.nodes().kind(fn_anc_id) {
            AstKind::Function(func) => {
                return func
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                return arrow
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            _ => {}
        }
    }
    None
}

fn evaluate_prefer_fluent_builder_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    let min_fields = pkg.config.architecture.min_builder_fields;
    let min_sites = pkg.config.architecture.min_builder_sites;

    let defined_builders: HashSet<&str> = pkg_files
        .iter()
        .flat_map(|f| {
            f.architecture_facets
                .defined_builder_types
                .iter()
                .map(String::as_str)
        })
        .collect();

    let mut sites_by_type: BTreeMap<&str, Vec<(&FileIr, &StructLiteralConstructionSiteIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for site in &file.architecture_facets.struct_literal_sites {
            if site.field_names.len() < min_fields {
                continue;
            }
            if defined_builders.contains(site.type_name.as_str()) {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchPreferFluentBuilder,
                    site.loc.line,
                    site.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            sites_by_type
                .entry(site.type_name.as_str())
                .or_default()
                .push((file, site));
        }
    }

    for (type_name, sites) in sites_by_type {
        if sites.len() < min_sites {
            continue;
        }

        let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for &(_, site) in &sites {
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
            continue;
        }

        let qualifying_sites: Vec<(&FileIr, &StructLiteralConstructionSiteIr)> = sites
            .into_iter()
            .filter(|(_, s)| {
                s.default_or_literal_fields
                    .iter()
                    .filter(|f| overlapping_defaults.contains(&f.as_str()))
                    .count()
                    >= 2
            })
            .collect();
        if qualifying_sites.len() < min_sites {
            continue;
        }

        let cascade_steps: Vec<String> = qualifying_sites
            .iter()
            .map(|(f, s)| {
                format!(
                    "{}:{} (`{}`: {} fields, defaults=[{}])",
                    f.path.to_string_lossy().replace('\\', "/"),
                    s.loc.line,
                    s.type_name,
                    s.field_names.len(),
                    s.default_or_literal_fields.join(", ")
                )
            })
            .collect();

        for (idx, &(file, site)) in qualifying_sites.iter().enumerate() {
            let Some(sev) = resolve_activation(
                RuleId::ArchPreferFluentBuilder,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };

            let peer_caller_sites: Vec<ResolvedCallerSite> = qualifying_sites
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &(peer_file, peer_site))| ResolvedCallerSite {
                    caller_file: peer_file.path.clone(),
                    parent_subject_name: None,
                    component_name: type_name.to_string(),
                    loc: peer_site.loc,
                    span: peer_site.span,
                    has_key: false,
                    passed_props: peer_site.default_or_literal_fields.clone(),
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchPreferFluentBuilder,
                    file.path.clone(),
                    None,
                    "archPreferFluentBuilder",
                    type_name.to_string(),
                    format!(
                        "`{type_name}` ({} fields) is initialized across {} call sites with overlapping default/boilerplate fields (`{}`); introduce a fluent `{type_name}Builder` or `create{type_name}` factory.",
                        site.field_names.len(),
                        qualifying_sites.len(),
                        overlapping_defaults.join("`, `")
                    ),
                    site.loc,
                    site.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}

fn extract_inline_terminal_ui_sites_in_file(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let is_ui_kit = is_js_ui_kit_path(path);
    facets.is_ui_kit_module = is_ui_kit;

    if is_ui_kit || classify_file_context(path) != FileContext::Production {
        return;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::StringLiteral(str_lit) => {
                let cooked_str = str_lit.value.as_str().unwrap_or_default();
                let raw_slice = source
                    .get(str_lit.span.start as usize..str_lit.span.end as usize)
                    .unwrap_or(cooked_str);
                if let Some((kind, snippet)) = classify_terminal_ui_literal(cooked_str, raw_slice) {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, str_lit.span.start),
                            span: ByteSpan {
                                start: str_lit.span.start,
                                end: str_lit.span.end,
                            },
                        });
                }
            }
            AstKind::TemplateLiteral(tpl) => {
                let raw_slice = source
                    .get(tpl.span.start as usize..tpl.span.end as usize)
                    .unwrap_or_default();
                let mut matched: Option<(TerminalUiPrimitiveKind, String)> = None;
                for quasi in &tpl.quasis {
                    let cooked = quasi
                        .value
                        .cooked
                        .and_then(|c| c.as_str())
                        .unwrap_or(quasi.value.raw.as_str());
                    if let Some(hit) =
                        classify_terminal_ui_literal(cooked, quasi.value.raw.as_str())
                    {
                        matched = Some(hit);
                        break;
                    }
                }
                if matched.is_none() {
                    matched = classify_terminal_ui_literal(raw_slice, raw_slice);
                }
                if let Some((kind, snippet)) = matched {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, tpl.span.start),
                            span: ByteSpan {
                                start: tpl.span.start,
                                end: tpl.span.end,
                            },
                        });
                }
            }
            _ => {}
        }
    }
}

fn evaluate_inline_terminal_ui_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    for &file in pkg_files {
        if file.architecture_facets.is_ui_kit_module
            || file.architecture_facets.inline_terminal_ui_sites.is_empty()
        {
            continue;
        }
        let Some(sev) = resolve_activation(
            RuleId::ArchNoInlineTerminalUiPrimitives,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        let active_sites: Vec<&InlineTerminalUiPrimitiveSiteIr> = file
            .architecture_facets
            .inline_terminal_ui_sites
            .iter()
            .filter(|site| {
                !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::ArchNoInlineTerminalUiPrimitives,
                        site.loc.line,
                        site.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            })
            .collect();
        if active_sites.is_empty() {
            continue;
        }

        let file_stem = file
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();
        let cascade_steps: Vec<String> = active_sites
            .iter()
            .map(|s| {
                format!(
                    "{}:{} ({}: `{}`)",
                    file.path.to_string_lossy().replace('\\', "/"),
                    s.loc.line,
                    s.kind,
                    s.snippet
                )
            })
            .collect();

        for (idx, &site) in active_sites.iter().enumerate() {
            let peer_caller_sites: Vec<ResolvedCallerSite> = active_sites
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &peer)| ResolvedCallerSite {
                    caller_file: file.path.clone(),
                    parent_subject_name: None,
                    component_name: peer.kind.as_str().to_string(),
                    loc: peer.loc,
                    span: peer.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchNoInlineTerminalUiPrimitives,
                    file.path.clone(),
                    None,
                    "archNoInlineTerminalUiPrimitives",
                    file_stem.clone(),
                    format!(
                        "Inline `{}` literal (`{}`) used in `{}` outside the terminal UI component kit; delegate to shared UI primitives.",
                        site.kind,
                        site.snippet,
                        file.path.to_string_lossy().replace('\\', "/")
                    ),
                    site.loc,
                    site.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}
