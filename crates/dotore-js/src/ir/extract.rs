//! Builds `FileIr` and `SubjectIr` from a single pass of `oxc_parser` and `oxc_semantic`.

use std::path::Path;

use oxc_allocator::Allocator;
use oxc_ast::{
    AstKind,
    ast::{CallExpression, Expression},
};
use oxc_parser::Parser;
use oxc_semantic::{NodeId, Semantic, SemanticBuilder};
use oxc_span::{SourceType, Span};

use crate::rules::{a11y::extract_a11y_sites_and_dom_ids, design::extract_design_sites};

pub(crate) use super::outlines_and_suppressions::extract_file_suppressions;

use super::{
    dataflow::{
        extract_async_flows, extract_mutations, extract_security_sinks, extract_semantic_rule_sites,
    },
    jsx_subtree::extract_jsx_subtrees,
    module_ir::extract_module_ir,
    motion_and_frame_loop::{extract_script_motion_ir, extract_stylesheet_motion_ir},
    outlines_and_suppressions::extract_symbol_outlines,
    react_ast::{RefEntry, extract_caller_sites, extract_jsx_elements},
    subject::extract_subjects,
    types::{
        ArchitectureFileFacets, ByteSpan, ContextualOwnerSpansIr, FileIr,
        ModuleIr, MotionFileIr, RelatedHookOwnerSpanIr, classify_file_context, compute_line_starts,
    },
};

/// Parses a JS/TS/JSX/TSX file from `source` once via `oxc_parser` and `oxc_semantic`,
/// extracting its complete [`FileIr`].
#[must_use]
pub fn parse_file_ir(path: &Path, source: &str) -> FileIr {
    inspect_file_semantic(path, source, |file_ir, _semantic| file_ir.clone())
}

/// Parses `source` once with `oxc_parser` and `oxc_semantic`, constructs [`FileIr`],
/// and invokes `f(&FileIr, &Semantic<'_>)` while the semantic AST and scope tree are live.
#[must_use]
pub fn inspect_file_semantic<F, R>(path: &Path, source: &str, f: F) -> R
where
    F: FnOnce(&FileIr, &Semantic<'_>) -> R,
{
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if matches!(ext, "css" | "scss" | "yml" | "yaml" | "html" | "htm") {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, "", SourceType::default()).parse();
        let semantic_ret = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program);
        let file_ir = build_non_script_file_ir(path, ext, source);
        return f(&file_ir, &semantic_ret.semantic);
    }

    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);

    let mut parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() && matches!(ext, "ts" | "mts" | "cts") {
        let ts_no_jsx = SourceType::from_path(path)
            .unwrap_or_default()
            .with_jsx(false)
            .with_module(true);
        let reparsed = Parser::new(&allocator, source, ts_no_jsx).parse();
        if reparsed.diagnostics.len() < parsed.diagnostics.len() {
            parsed = reparsed;
        }
    }
    let semantic_ret = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program);
    let semantic = semantic_ret.semantic;
    let file_ir = build_script_file_ir(path, source, &parsed.program, &semantic);
    f(&file_ir, &semantic)
}

fn build_non_script_file_ir(path: &Path, ext: &str, source: &str) -> FileIr {
    let line_starts = compute_line_starts(source);
    let mut semantic_sites = Vec::new();
    let motion = if matches!(ext, "css" | "scss") {
        crate::rules::angular::extract_angular_stylesheet_sites(
            source,
            0,
            None,
            &line_starts,
            &mut semantic_sites,
        );
        extract_stylesheet_motion_ir(source)
    } else if matches!(ext, "html" | "htm") {
        crate::rules::angular::extract_angular_html_template_sites(
            source,
            0,
            None,
            &line_starts,
            &mut semantic_sites,
        );
        MotionFileIr::default()
    } else {
        MotionFileIr::default()
    };

    FileIr {
        path: path.to_path_buf(),
        source: source.to_string(),
        file_context: classify_file_context(path),
        subjects: Vec::new(),
        caller_sites: Vec::new(),
        jsx_elements: Vec::new(),
        jsx_subtrees: Vec::new(),
        module: ModuleIr::default(),
        symbol_outlines: Vec::new(),
        mutations: Vec::new(),
        async_flows: Vec::new(),
        security_sinks: Vec::new(),
        suppressions: extract_file_suppressions(source),
        semantic_sites,
        motion,
        static_dom_ids: Vec::new(),
        has_unresolved_id_spread: false,
        frame_loop_roots: Vec::new(),
        frame_helpers: Vec::new(),
        context_providers: Vec::new(),
        context_consumers: Vec::new(),
        contextual_owner_spans: ContextualOwnerSpansIr::default(),
        architecture_facets: ArchitectureFileFacets::default(),
    }
}

fn build_script_file_ir(
    path: &Path,
    source: &str,
    program: &oxc_ast::ast::Program<'_>,
    semantic: &Semantic<'_>,
) -> FileIr {
    let line_starts = compute_line_starts(source);
    let ref_entries = collect_ref_entries(semantic);
    let subjects = extract_subjects(semantic, &ref_entries, &line_starts);
    let caller_sites = extract_caller_sites(semantic, &line_starts);
    let jsx_elements = extract_jsx_elements(semantic, &line_starts);
    let jsx_subtrees = extract_jsx_subtrees(semantic, &line_starts);
    let module = extract_module_ir(program, semantic, &jsx_elements, &line_starts);
    let symbol_outlines = extract_symbol_outlines(semantic, source, &line_starts);
    let mutations = extract_mutations(semantic, &ref_entries, &line_starts);
    let async_flows = extract_async_flows(semantic, &line_starts);
    let security_sinks = extract_security_sinks(program, semantic, &module, &line_starts);
    let suppressions = extract_file_suppressions(source);
    let mut semantic_sites =
        extract_semantic_rule_sites(path, program, semantic, &ref_entries, &line_starts);
    let (a11y_sites, static_dom_ids, has_unresolved_id_spread) =
        extract_a11y_sites_and_dom_ids(path, program, semantic, &line_starts);
    semantic_sites.extend(a11y_sites);
    semantic_sites.extend(extract_design_sites(path, program, semantic, &line_starts));
    let motion = extract_script_motion_ir(program, semantic);
    let (frame_loop_roots, frame_helpers) = crate::rules::r3f::extract_r3f_webgl_file_ir(
        program,
        semantic,
        &module,
        &line_starts,
        &mut semantic_sites,
    );
    let mut context_providers = Vec::new();
    let mut context_consumers = Vec::new();
    populate_script_rule_sites(
        path,
        semantic,
        &module,
        &subjects,
        &jsx_elements,
        &line_starts,
        &mut semantic_sites,
        &mut context_providers,
        &mut context_consumers,
    );
    let mut contextual_owner_spans = extract_contextual_owner_spans(semantic);
    contextual_owner_spans.element_spans = jsx_subtrees.iter().map(|s| s.span).collect();
    let mut architecture_facets = ArchitectureFileFacets::default();
    crate::rules::architecture::extract_soc_architecture_facets(
        path,
        source,
        program,
        semantic,
        &module,
        &subjects,
        &jsx_elements,
        &symbol_outlines,
        &line_starts,
        &mut architecture_facets,
    );
    crate::rules::architecture::extract_reuse_architecture_facets(
        path,
        source,
        semantic,
        &subjects,
        &module,
        &line_starts,
        &mut architecture_facets,
    );
    for cat in &architecture_facets.static_catalog_sites {
        contextual_owner_spans
            .function_boundary_spans
            .push(cat.span);
    }

    FileIr {
        path: path.to_path_buf(),
        source: source.to_string(),
        file_context: classify_file_context(path),
        subjects,
        caller_sites,
        jsx_elements,
        jsx_subtrees,
        module,
        symbol_outlines,
        mutations,
        async_flows,
        security_sinks,
        suppressions,
        semantic_sites,
        motion,
        static_dom_ids,
        has_unresolved_id_spread,
        frame_loop_roots,
        frame_helpers,
        context_providers,
        context_consumers,
        contextual_owner_spans,
        architecture_facets,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Aggregates single-pass domain rule site extraction into semantic_sites and context buffers (#50)"
)]
fn populate_script_rule_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    subjects: &[super::types::SubjectIr],
    jsx_elements: &[super::types::JsxElementIr],
    line_starts: &[u32],
    semantic_sites: &mut Vec<super::types::SemanticRuleSite>,
    context_providers: &mut Vec<super::types::ContextProviderSiteIr>,
    context_consumers: &mut Vec<super::types::ContextConsumerSiteIr>,
) {
    crate::rules::bundle_size::extract_bundle_size_sites(
        path,
        semantic,
        module,
        jsx_elements,
        line_starts,
        semantic_sites,
    );
    crate::rules::js_performance::extract_js_performance_sites(
        path,
        semantic,
        module,
        line_starts,
        semantic_sites,
    );
    crate::rules::performance::extract_performance_sites(
        path,
        semantic,
        module,
        line_starts,
        semantic_sites,
    );
    crate::rules::state_and_effects::extract_state_and_effects_sites(
        semantic,
        line_starts,
        semantic_sites,
    );
    crate::rules::react_builtins::extract_react_builtins_sites(
        semantic,
        path,
        line_starts,
        semantic_sites,
    );
    crate::rules::correctness::extract_correctness_sites(semantic, line_starts, semantic_sites);
    crate::rules::architecture::extract_architecture_sites(
        semantic,
        subjects,
        line_starts,
        semantic_sites,
        context_providers,
        context_consumers,
    );
    crate::rules::effect_teardown::extract_effect_teardown_sites(
        path,
        semantic,
        subjects,
        line_starts,
        semantic_sites,
    );
    crate::rules::defensive_js::extract_defensive_js_sites(
        semantic,
        subjects,
        line_starts,
        semantic_sites,
    );
    crate::rules::angular::extract_angular_sites(semantic, line_starts, semantic_sites);
}

fn collect_ref_entries(semantic: &Semantic<'_>) -> Vec<RefEntry> {
    let mut entries = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if let AstKind::IdentifierReference(ident) = node.kind()
            && let Some(ref_id) = ident.reference_id.get()
        {
            entries.push(RefEntry {
                node_id,
                ref_id,
                span: ident.span,
            });
        }
    }
    entries
}

fn extract_contextual_owner_spans(semantic: &Semantic<'_>) -> ContextualOwnerSpansIr {
    let mut function_boundary_spans = Vec::new();
    let mut related_hook_spans = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if let Some(fn_span) = non_hook_function_boundary_span(semantic, node_id, node.kind()) {
            function_boundary_spans.push(ByteSpan {
                start: fn_span.start,
                end: fn_span.end,
            });
        }
        if let AstKind::CallExpression(call) = node.kind()
            && is_hook_or_frame_call(call)
        {
            let mut referenced_decl_spans = Vec::new();
            collect_referenced_local_declarations(
                semantic,
                node_id,
                call.span,
                &mut referenced_decl_spans,
            );
            related_hook_spans.push(RelatedHookOwnerSpanIr {
                call_span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                referenced_decl_spans,
            });
        }
    }

    ContextualOwnerSpansIr {
        function_boundary_spans,
        related_hook_spans,
        element_spans: Vec::new(),
    }
}

fn non_hook_function_boundary_span(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
) -> Option<Span> {
    let raw_span = match kind {
        AstKind::Function(f) => f.span,
        AstKind::ArrowFunctionExpression(arrow) => arrow.span,
        _ => return None,
    };

    let parent_id = semantic.nodes().parent_id(node_id);
    match semantic.nodes().kind(parent_id) {
        AstKind::CallExpression(call) if is_hook_or_frame_call(call) => None,
        AstKind::VariableDeclarator(decl) => {
            let grand_id = semantic.nodes().parent_id(parent_id);
            if let AstKind::VariableDeclaration(var_decl) = semantic.nodes().kind(grand_id)
                && var_decl.declarations.len() == 1
            {
                let great_id = semantic.nodes().parent_id(grand_id);
                if let AstKind::ExportNamedDeclaration(exp) = semantic.nodes().kind(great_id) {
                    return Some(exp.span);
                }
                return Some(var_decl.span);
            }
            Some(decl.span)
        }
        AstKind::ExportNamedDeclaration(exp) => Some(exp.span),
        AstKind::ExportDefaultDeclaration(exp) => Some(exp.span),
        _ => Some(raw_span),
    }
}

fn is_hook_or_frame_call(call: &CallExpression<'_>) -> bool {
    let name = match call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    let Some(callee) = name else {
        return false;
    };
    callee == "useFrame"
        || callee == "requestAnimationFrame"
        || (callee.starts_with("use")
            && callee.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase))
}

fn collect_referenced_local_declarations(
    semantic: &Semantic<'_>,
    hook_node_id: NodeId,
    hook_span: Span,
    out: &mut Vec<ByteSpan>,
) {
    let enclosing_fn_span = semantic
        .nodes()
        .ancestor_ids(hook_node_id)
        .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => Some(f.span),
            AstKind::ArrowFunctionExpression(a) => Some(a.span),
            _ => None,
        });

    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::IdentifierReference(ident) = node.kind() else {
            continue;
        };
        if ident.span.start < hook_span.start || ident.span.end > hook_span.end {
            continue;
        }
        let Some(ref_id) = ident.reference_id.get() else {
            continue;
        };
        let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
            continue;
        };
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        match semantic.nodes().kind(decl_id) {
            AstKind::VariableDeclarator(decl) => {
                let is_fn_like = decl.init.as_ref().is_some_and(|init| {
                    matches!(
                        init.without_parentheses(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
                if is_fn_like
                    && enclosing_fn_span.is_none_or(|fn_sp| {
                        decl.span.start >= fn_sp.start && decl.span.end <= fn_sp.end
                    })
                {
                    let parent_id = semantic.nodes().parent_id(decl_id);
                    let sp = if let AstKind::VariableDeclaration(var_decl) =
                        semantic.nodes().kind(parent_id)
                    {
                        var_decl.span
                    } else {
                        decl.span
                    };
                    out.push(ByteSpan {
                        start: sp.start,
                        end: sp.end,
                    });
                }
            }
            AstKind::Function(func)
                if enclosing_fn_span.is_none_or(|fn_sp| {
                    func.span.start > fn_sp.start && func.span.end <= fn_sp.end
                }) =>
            {
                out.push(ByteSpan {
                    start: func.span.start,
                    end: func.span.end,
                });
            }
            _ => {}
        }
    }
}
