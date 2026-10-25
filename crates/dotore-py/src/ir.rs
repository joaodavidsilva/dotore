//! Single-pass Python intermediate representation (`PyFileIr`), **Subject**, **Symbol Outline**,
//! **Contextual Owner**, and inline suppression extraction.

use std::path::Path;

use dotore_core::{
    ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, ContextualOwnerSpansIr,
    Diagnostic, ExtractedFile, FNV1A_64_OFFSET_BASIS, FileSuppressions, HelperFingerprintIr,
    InlineTerminalUiPrimitiveSiteIr, LanguageId, SourceLoc, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, SuppressionDirectiveKind, SymbolKind, SymbolOutline,
    TerminalUiPrimitiveKind, compute_line_starts, fnv1a_64_byte, fnv1a_64_str,
    loc_from_line_starts, parse_python_suppression_directive,
};
use ruff_python_ast::{
    BoolOp, CmpOp, Expr, ExprCall, ExprFString, ExprStringLiteral, ModModule, Operator,
    PySourceType, Stmt, StmtAnnAssign, StmtAssign, StmtClassDef, StmtFunctionDef, StmtIf, UnaryOp,
    token::TokenKind,
};
use ruff_python_parser::{Parsed, parse_unchecked_source};
use ruff_text_size::Ranged;

use crate::{
    asyncio::extract_asyncio_diagnostics,
    fastapi_pydantic::extract_fastapi_pydantic_diagnostics,
    graph::{self, PyModuleGraphInfo},
    matchers::{PyScopeTracker, annotation_is_final, is_upper_snake_case, text_range_to_byte_span},
    orm::extract_orm_diagnostics,
    perf::extract_perf_diagnostics,
    safety::extract_safety_diagnostics,
    security::extract_security_diagnostics,
    zen::extract_zen_diagnostics,
};

/// Single-pass intermediate representation for a Python source file (`.py` or `.pyi`).
#[derive(Debug, Clone)]
pub struct PyFileIr {
    /// Whether the file parsed without syntax errors.
    pub valid_syntax: bool,
    /// Precomputed 0-based byte offsets of each line start.
    pub line_starts: Vec<u32>,
    /// Pre-evaluated candidate rule diagnostics for all single-file Python rules.
    pub candidate_diagnostics: Vec<Diagnostic>,
    /// Cross-file module import/export graph metadata for `py-arch-*` rules.
    pub(crate) module_graph: PyModuleGraphInfo,
}

/// Parses `source` at `path` in a single pass and extracts its [`ExtractedFile`] and [`PyFileIr`].
#[must_use]
pub(crate) fn extract_python_file(path: &Path, source: &str) -> ExtractedFile {
    let source_type = PySourceType::from(path);
    let parsed: Parsed<ModModule> = parse_unchecked_source(source, source_type);
    let valid_syntax = parsed.has_valid_syntax();
    let line_starts = compute_line_starts(source);
    let lines: Vec<&str> = source.lines().collect();

    let suppressions = extract_python_suppressions(source, &lines, &line_starts, &parsed);
    let is_stub_file = path.extension().and_then(|e| e.to_str()) == Some("pyi");
    let suite = parsed.suite();

    let mut ir_extractor = PyIrExtractor {
        source,
        lines: &lines,
        line_starts: &line_starts,
        symbol_outlines: Vec::new(),
        subject_spans: Vec::new(),
        contextual_owner_spans: ContextualOwnerSpansIr::default(),
        scope: PyScopeTracker::new(),
    };
    ir_extractor.extract_suite(suite, true);

    let mut candidate_diagnostics = Vec::new();
    extract_safety_diagnostics(
        path,
        source,
        &lines,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );
    extract_fastapi_pydantic_diagnostics(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );
    extract_orm_diagnostics(
        path,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );
    extract_security_diagnostics(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );
    let mut potential_unawaited_calls = Vec::new();
    extract_asyncio_diagnostics(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
        &mut potential_unawaited_calls,
    );
    extract_perf_diagnostics(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );
    extract_zen_diagnostics(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &mut candidate_diagnostics,
    );

    let subjects_count = ir_extractor.subject_spans.len();
    let symbol_outlines = ir_extractor.symbol_outlines;
    let subject_spans = ir_extractor.subject_spans;
    let mut contextual_owner_spans = ir_extractor.contextual_owner_spans;

    let mut module_graph = graph::extract_module_graph_info(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &symbol_outlines,
    );
    module_graph.potential_unawaited_calls = potential_unawaited_calls;

    let architecture_facets = extract_python_architecture_facets(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &symbol_outlines,
        &module_graph.dunder_all,
    );
    for lit_site in &architecture_facets.struct_literal_sites {
        contextual_owner_spans.element_spans.push(lit_site.span);
    }
    for cat_site in &architecture_facets.static_catalog_sites {
        contextual_owner_spans
            .function_boundary_spans
            .push(cat_site.span);
    }
    for sig in &architecture_facets.concern_signals {
        if sig.bucket == ConcernBucket::EntrypointAdapter
            && sig.detail == "if __name__ == \"__main__\""
        {
            contextual_owner_spans
                .function_boundary_spans
                .push(sig.span);
        }
    }
    let ir = PyFileIr {
        valid_syntax,
        line_starts,
        candidate_diagnostics,
        module_graph,
    };

    let mut extracted =
        ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Python);
    extracted.symbol_outlines = symbol_outlines;
    extracted.contextual_owner_spans = contextual_owner_spans;
    extracted.suppressions = suppressions;
    extracted.subjects_count = subjects_count;
    extracted.subject_spans = subject_spans;
    extracted
        .with_architecture_facets(architecture_facets)
        .with_payload(ir)
}

struct PyIrExtractor<'a> {
    source: &'a str,
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    symbol_outlines: Vec<SymbolOutline>,
    subject_spans: Vec<(Option<String>, ByteSpan, SourceLoc)>,
    contextual_owner_spans: ContextualOwnerSpansIr,
    scope: PyScopeTracker,
}

impl<'a> PyIrExtractor<'a> {
    fn extract_suite(&mut self, suite: &[Stmt], is_module_or_class_scope: bool) {
        for stmt in suite {
            self.extract_stmt(stmt, is_module_or_class_scope);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Python Stmt enum has many variants; IR extractor inspects structural declarations and recurses into compound statements"
    )]
    fn extract_stmt(&mut self, stmt: &Stmt, is_module_or_class_scope: bool) {
        match stmt {
            Stmt::ClassDef(class_def) => self.extract_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.extract_function_def(func_def),
            Stmt::Assign(assign) => {
                if is_module_or_class_scope {
                    self.record_assign_symbol_outlines(assign);
                }
            }
            Stmt::AnnAssign(ann_assign) => {
                if is_module_or_class_scope
                    && let Expr::Name(name_expr) = ann_assign.target.as_ref()
                {
                    let span = text_range_to_byte_span(ann_assign.range());
                    let start_loc = loc_from_line_starts(self.line_starts, span.start);
                    let end_loc = loc_from_line_starts(
                        self.line_starts,
                        span.end.saturating_sub(1).max(span.start),
                    );
                    let sig = self
                        .lines
                        .get((start_loc.line.saturating_sub(1)) as usize)
                        .map(|l| l.trim().to_string())
                        .unwrap_or_default();
                    let (doc_comment, comment_start_line) =
                        extract_leading_hash_comment(self.lines, start_loc.line);
                    let parent_name = self.scope.current_class();
                    let name = name_expr.id.to_string();
                    let is_final = annotation_is_final(&ann_assign.annotation);
                    let kind = if is_upper_snake_case(&name) || is_final {
                        SymbolKind::Constant
                    } else {
                        SymbolKind::Variable
                    };
                    let name_span = text_range_to_byte_span(name_expr.range());
                    let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
                    let exported = !name.starts_with('_');
                    self.symbol_outlines.push(
                        SymbolOutline::new(name, kind, sig, span, name_loc, end_loc.line)
                            .with_exported(exported)
                            .with_parent(parent_name)
                            .with_doc_comment(doc_comment, comment_start_line)
                            .with_signature_end_line(start_loc.line),
                    );
                }
            }
            Stmt::If(if_stmt) => {
                self.extract_suite(&if_stmt.body, false);
                for clause in &if_stmt.elif_else_clauses {
                    self.extract_suite(&clause.body, false);
                }
            }
            Stmt::For(for_stmt) => {
                self.extract_suite(&for_stmt.body, false);
                self.extract_suite(&for_stmt.orelse, false);
            }
            Stmt::While(while_stmt) => {
                self.extract_suite(&while_stmt.body, false);
                self.extract_suite(&while_stmt.orelse, false);
            }
            Stmt::With(with_stmt) => {
                let span = text_range_to_byte_span(with_stmt.range());
                self.contextual_owner_spans.element_spans.push(span);
                self.extract_suite(&with_stmt.body, false);
            }
            Stmt::Try(try_stmt) => {
                let span = text_range_to_byte_span(try_stmt.range());
                self.contextual_owner_spans.element_spans.push(span);
                self.extract_suite(&try_stmt.body, false);
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
                    self.extract_suite(&h.body, false);
                }
                self.extract_suite(&try_stmt.orelse, false);
                self.extract_suite(&try_stmt.finalbody, false);
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    self.extract_suite(&case.body, false);
                }
            }
            _ => {}
        }
    }

    fn record_assign_symbol_outlines(&mut self, assign: &StmtAssign) {
        let span = text_range_to_byte_span(assign.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let end_loc =
            loc_from_line_starts(self.line_starts, span.end.saturating_sub(1).max(span.start));
        let sig = self
            .lines
            .get((start_loc.line.saturating_sub(1)) as usize)
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        let (doc_comment, comment_start_line) =
            extract_leading_hash_comment(self.lines, start_loc.line);
        let parent_name = self.scope.current_class();

        for target in &assign.targets {
            let Expr::Name(name_expr) = target else {
                continue;
            };
            let name = name_expr.id.to_string();
            let kind = if is_upper_snake_case(&name) {
                SymbolKind::Constant
            } else {
                SymbolKind::Variable
            };
            let name_span = text_range_to_byte_span(name_expr.range());
            let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
            let exported = !name.starts_with('_');
            self.symbol_outlines.push(
                SymbolOutline::new(name, kind, sig.clone(), span, name_loc, end_loc.line)
                    .with_exported(exported)
                    .with_parent(parent_name.clone())
                    .with_doc_comment(doc_comment.clone(), comment_start_line)
                    .with_signature_end_line(start_loc.line),
            );
        }
    }

    fn extract_class_def(&mut self, class_def: &StmtClassDef) {
        let span = text_range_to_byte_span(class_def.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let name_span = text_range_to_byte_span(class_def.name.range());
        let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
        let end_loc =
            loc_from_line_starts(self.line_starts, span.end.saturating_sub(1).max(span.start));

        let class_name = class_def.name.to_string();
        let parent_name = self.scope.current_class();
        let qualified_subject = self.scope.enter_class(class_name.clone());

        self.subject_spans
            .push((Some(qualified_subject), span, start_loc));
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);
        self.contextual_owner_spans.element_spans.push(span);

        let body_start = class_def
            .body
            .first()
            .map_or(span.end, |s| s.range().start().to_u32());
        let (signature, signature_end_line) = extract_header_signature(
            self.source,
            self.line_starts,
            name_span.start,
            span.start,
            body_start,
        );
        let (doc_comment, comment_start_line) =
            extract_docstring_or_leading_comment(&class_def.body, self.lines, start_loc.line);
        let exported = !class_name.starts_with('_');

        self.symbol_outlines.push(
            SymbolOutline::new(
                class_name,
                SymbolKind::Class,
                signature,
                span,
                name_loc,
                end_loc.line,
            )
            .with_exported(exported)
            .with_parent(parent_name)
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        self.extract_suite(&class_def.body, true);
        self.scope.exit_class();
    }

    fn extract_function_def(&mut self, func_def: &StmtFunctionDef) {
        let span = text_range_to_byte_span(func_def.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let name_span = text_range_to_byte_span(func_def.name.range());
        let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
        let end_loc =
            loc_from_line_starts(self.line_starts, span.end.saturating_sub(1).max(span.start));

        let fn_name = func_def.name.to_string();
        let saved = self.scope.enter_function(&fn_name, func_def.is_async);
        let subject_name = saved.subject_name.clone();
        let enclosing_class = saved.enclosing_class.clone();

        self.subject_spans
            .push((Some(subject_name), span, start_loc));
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        let body_start = func_def
            .body
            .first()
            .map_or(span.end, |s| s.range().start().to_u32());
        let def_header_start = func_def
            .decorator_list
            .last()
            .map_or(span.start, |d| d.range().end().to_u32());
        let (signature, signature_end_line) = extract_header_signature(
            self.source,
            self.line_starts,
            name_span.start,
            def_header_start,
            body_start,
        );
        let (doc_comment, comment_start_line) =
            extract_docstring_or_leading_comment(&func_def.body, self.lines, start_loc.line);

        let kind = if enclosing_class.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        };
        let exported = if enclosing_class.is_some() {
            !fn_name.starts_with('_') || fn_name == "__init__"
        } else {
            !fn_name.starts_with('_')
        };

        self.symbol_outlines.push(
            SymbolOutline::new(fn_name, kind, signature, span, name_loc, end_loc.line)
                .with_exported(exported)
                .with_parent(enclosing_class)
                .with_doc_comment(doc_comment, comment_start_line)
                .with_signature_end_line(signature_end_line),
        );

        self.extract_suite(&func_def.body, false);
        self.scope.exit_function(saved);
    }
}

/// Extracts a normalized Python declaration signature header and its 1-based end line.
#[must_use]
pub(crate) fn extract_header_signature(
    source: &str,
    line_starts: &[u32],
    name_start: u32,
    header_search_start: u32,
    body_start: u32,
) -> (String, u32) {
    let start = header_search_start as usize;
    let end = (body_start as usize).min(source.len());
    if start >= end {
        let loc = loc_from_line_starts(line_starts, name_start);
        return (String::new(), loc.line);
    }
    let raw_slice = source.get(start..end).unwrap_or("");
    let trimmed = raw_slice.trim();
    let without_colon = strip_trailing_colon(trimmed);
    let collapsed = without_colon
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let sig_end_offset = header_search_start
        .saturating_add(u32::try_from(without_colon.len()).unwrap_or(0))
        .max(name_start);
    let sig_end_loc = loc_from_line_starts(line_starts, sig_end_offset);
    (collapsed, sig_end_loc.line)
}

fn strip_trailing_colon(header: &str) -> &str {
    let mut lines: Vec<&str> = header.lines().collect();
    while let Some(last) = lines.last() {
        let code_part = last.split('#').next().unwrap_or("").trim_end();
        if let Some(before_colon) = code_part.strip_suffix(':') {
            let prefix_len = header.len() - last.len() + before_colon.len();
            return header.get(..prefix_len).unwrap_or(header).trim_end();
        }
        if code_part.is_empty() {
            lines.pop();
        } else {
            break;
        }
    }
    header.trim_end_matches(':').trim_end()
}

fn extract_docstring_or_leading_comment(
    body: &[Stmt],
    lines: &[&str],
    decl_start_line: u32,
) -> (Option<String>, Option<u32>) {
    if let Some(Stmt::Expr(expr_stmt)) = body.first()
        && let Expr::StringLiteral(str_lit) = expr_stmt.value.as_ref()
    {
        let value = str_lit.value.to_str().trim().to_string();
        if !value.is_empty() {
            return (Some(value), None);
        }
    }
    extract_leading_hash_comment(lines, decl_start_line)
}

fn extract_leading_hash_comment(
    lines: &[&str],
    decl_start_line: u32,
) -> (Option<String>, Option<u32>) {
    if decl_start_line <= 1 {
        return (None, None);
    }
    let mut idx = (decl_start_line - 1) as usize;
    let mut collected = Vec::new();
    let mut first_line = None;
    while idx > 0 {
        idx -= 1;
        let trimmed = lines.get(idx).copied().unwrap_or_default().trim();
        if let Some(comment_body) = trimmed.strip_prefix('#') {
            let text = comment_body.trim();
            if is_suppression_comment_body(text) {
                continue;
            }
            first_line = Some(u32::try_from(idx + 1).unwrap_or(1));
            collected.push(text);
        } else {
            break;
        }
    }
    if collected.is_empty() {
        (None, None)
    } else {
        collected.reverse();
        (Some(collected.join("\n")), first_line)
    }
}

fn is_suppression_comment_body(text: &str) -> bool {
    text.starts_with("dotore-disable")
        || text.starts_with("dotore-enable")
        || text.starts_with("noqa")
        || text.starts_with("ruff:")
        || text.starts_with("type:")
        || text.starts_with("pragma:")
}

fn extract_python_suppressions(
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    parsed: &Parsed<ModModule>,
) -> FileSuppressions {
    let mut suppressions = FileSuppressions::default();

    for token in parsed.tokens() {
        if token.kind() != TokenKind::Comment {
            continue;
        }
        let range = token.range();
        let start = range.start().to_usize();
        let end = range.end().to_usize().min(source.len());
        if start >= end {
            continue;
        }
        let comment_loc = loc_from_line_starts(line_starts, range.start().to_u32());
        let line_num = comment_loc.line;
        let raw_comment = source.get(start..end).unwrap_or("");
        let body = raw_comment.trim_start_matches('#').trim();

        let Some((kind, rules)) = parse_python_suppression_directive(body) else {
            continue;
        };

        match kind {
            SuppressionDirectiveKind::DisableLine => {
                let line_idx = (line_num.saturating_sub(1)) as usize;
                let is_standalone_comment = lines
                    .get(line_idx)
                    .is_some_and(|l| l.trim_start().starts_with('#'));
                suppressions.add_line_disable(line_num, rules.clone());
                if is_standalone_comment {
                    let target_line = resolve_next_python_code_line(lines, line_idx);
                    suppressions.add_line_disable(target_line, rules);
                }
            }
            SuppressionDirectiveKind::DisableNextLine => {
                let target_line =
                    resolve_next_python_code_line(lines, (line_num.saturating_sub(1)) as usize);
                suppressions.add_line_disable(target_line, rules);
            }
            SuppressionDirectiveKind::BlockDisable => {
                suppressions.add_block_disable(line_num, u32::MAX, rules);
            }
            SuppressionDirectiveKind::BlockEnable => {
                suppressions.close_block_ranges(&rules, line_num);
            }
        }
    }

    suppressions
}

fn resolve_next_python_code_line(lines: &[&str], comment_line_idx: usize) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while candidate < lines.len() {
        let text = lines[candidate].trim();
        if text.is_empty() {
            candidate += 1;
            continue;
        }
        if let Some(comment_body) = text.strip_prefix('#')
            && matches!(
                parse_python_suppression_directive(comment_body),
                Some((SuppressionDirectiveKind::DisableNextLine, _))
            )
        {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}

fn extract_python_architecture_facets(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    symbol_outlines: &[SymbolOutline],
    dunder_all: &std::collections::HashSet<String>,
) -> ArchitectureFileFacets {
    if is_stub_file {
        return ArchitectureFileFacets::default();
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let is_named_entrypoint = matches!(
        file_name,
        "main.py" | "__main__.py" | "app.py" | "cli.py" | "manage.py"
    );
    let has_main_guard = suite
        .iter()
        .any(|stmt| matches!(stmt, Stmt::If(if_stmt) if is_dunder_main_guard(&if_stmt.test)));
    let is_entrypoint = is_named_entrypoint || has_main_guard;

    let is_ui_kit_module = matches!(
        file_name,
        "ui.py" | "console.py" | "terminal.py" | "tui.py" | "terminal_ui.py"
    ) || path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| matches!(s, "ui" | "tui" | "terminal_ui"))
    });

    let public_type_count = symbol_outlines
        .iter()
        .filter(|o| o.parent_name.is_none() && o.exported && o.kind == SymbolKind::Class)
        .count();

    let mut facets = ArchitectureFileFacets {
        is_entrypoint,
        is_ui_kit_module,
        public_type_count,
        ..ArchitectureFileFacets::default()
    };

    let mut walker = PyArchFacetWalker {
        source,
        line_starts,
        dunder_all,
        facets: &mut facets,
        in_entrypoint_body: false,
    };
    walker.walk_module_suite(suite);

    facets.domain_clusters = facets
        .distinct_concern_buckets()
        .into_iter()
        .map(|b| b.as_str().to_string())
        .collect();

    facets
}

struct PyArchFacetWalker<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    dunder_all: &'a std::collections::HashSet<String>,
    facets: &'a mut ArchitectureFileFacets,
    in_entrypoint_body: bool,
}
impl<'a> PyArchFacetWalker<'a> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Top-level module walker dispatches declarations and forwards remaining statements to walk_stmt"
    )]
    fn walk_module_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            match stmt {
                Stmt::ClassDef(cls) => {
                    let span = text_range_to_byte_span(cls.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::TypeDefinitions,
                        detail: format!("class {}", cls.name),
                        loc,
                        span,
                    });
                    self.record_class_builder_definitions(cls);
                    self.walk_suite(&cls.body);
                }
                Stmt::FunctionDef(func_def) => {
                    let fn_name = func_def.name.as_str();
                    if is_ast_or_validation_helper_name(fn_name) {
                        let span = text_range_to_byte_span(func_def.range());
                        let loc = loc_from_line_starts(self.line_starts, span.start);
                        self.facets.concern_signals.push(ConcernSignalSite {
                            bucket: ConcernBucket::AstOrValidationHelper,
                            detail: format!("def {fn_name}"),
                            loc,
                            span,
                        });
                    }
                    self.record_top_level_helper_fingerprint(func_def);
                    self.record_top_level_factory_function(func_def);
                    let is_entry_fn =
                        self.facets.is_entrypoint && matches!(fn_name, "main" | "cli" | "run");
                    let prev = self.in_entrypoint_body;
                    if is_entry_fn {
                        self.in_entrypoint_body = true;
                    }
                    self.walk_suite(&func_def.body);
                    self.in_entrypoint_body = prev;
                }
                Stmt::If(if_stmt) if is_dunder_main_guard(&if_stmt.test) => {
                    let span = text_range_to_byte_span(if_stmt.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::EntrypointAdapter,
                        detail: "if __name__ == \"__main__\"".to_string(),
                        loc,
                        span,
                    });
                    let prev = self.in_entrypoint_body;
                    self.in_entrypoint_body = true;
                    self.walk_suite(&if_stmt.body);
                    self.in_entrypoint_body = prev;
                }
                Stmt::Import(imp) => {
                    let span = text_range_to_byte_span(imp.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    for alias in &imp.names {
                        self.record_import_signal(alias.name.as_str(), loc, span);
                    }
                }
                Stmt::ImportFrom(imp_from) => self.inspect_import_from(imp_from),
                Stmt::Assign(assign) => {
                    self.inspect_top_level_assign(assign);
                    self.walk_expr(&assign.value);
                }
                Stmt::AnnAssign(ann) => {
                    self.inspect_top_level_ann_assign(ann);
                    if let Some(val) = &ann.value {
                        self.walk_expr(val);
                    }
                }
                other => {
                    let prev = self.in_entrypoint_body;
                    if self.facets.is_entrypoint {
                        self.in_entrypoint_body = true;
                    }
                    self.walk_stmt(other);
                    self.in_entrypoint_body = prev;
                }
            }
        }
    }

    fn inspect_import_from(&mut self, imp_from: &ruff_python_ast::StmtImportFrom) {
        let Some(module) = &imp_from.module else {
            return;
        };
        let span = text_range_to_byte_span(imp_from.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let mod_str = module.as_str();
        for alias in &imp_from.names {
            let combined = format!("{mod_str}.{}", alias.name);
            self.record_import_signal(&combined, loc, span);
        }
    }

    fn record_import_signal(&mut self, imported: &str, loc: SourceLoc, span: ByteSpan) {
        if imported.starts_with("rich.console")
            || imported.starts_with("rich.table")
            || imported.starts_with("rich.panel")
            || imported.starts_with("streamlit")
            || imported.ends_with(".render_template")
            || imported.ends_with(".Jinja2Templates")
        {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: format!("import {imported}"),
                loc,
                span,
            });
        } else if imported.starts_with("argparse")
            || imported.starts_with("typer")
            || imported.starts_with("fastapi")
        {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::EntrypointAdapter,
                detail: format!("import {imported}"),
                loc,
                span,
            });
        }
    }

    fn inspect_top_level_assign(&mut self, assign: &StmtAssign) {
        let Some(Expr::Name(target)) = assign.targets.first() else {
            return;
        };
        if target.id.as_str() == "__all__" {
            return;
        }
        let span = text_range_to_byte_span(assign.range());
        self.record_static_catalog_if_applicable(target.id.as_str(), &assign.value, span);
    }

    fn inspect_top_level_ann_assign(&mut self, ann: &StmtAnnAssign) {
        let Expr::Name(target) = ann.target.as_ref() else {
            return;
        };
        if target.id.as_str() == "__all__" {
            return;
        }
        if let Some(val) = &ann.value {
            let span = text_range_to_byte_span(ann.range());
            self.record_static_catalog_if_applicable(target.id.as_str(), val, span);
        }
    }

    fn record_static_catalog_if_applicable(&mut self, name: &str, value: &Expr, span: ByteSpan) {
        let Some(entry_count) = static_collection_entry_count(value) else {
            return;
        };
        if entry_count < 3 {
            return;
        }
        let val_span = text_range_to_byte_span(value.range());
        let byte_len = val_span.end.saturating_sub(val_span.start) as usize;
        let loc = loc_from_line_starts(self.line_starts, span.start);
        self.facets.static_catalog_sites.push(StaticCatalogSiteIr {
            name: name.to_string(),
            entry_count,
            byte_len,
            loc,
            span,
        });
        if entry_count >= 10 {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::StaticDataCatalog,
                detail: format!("{name} ({entry_count} entries)"),
                loc,
                span,
            });
        }
    }

    fn record_class_builder_definitions(&mut self, cls: &StmtClassDef) {
        let cls_name = cls.name.as_str();
        if let Some(target_type) = cls_name.strip_suffix("Builder")
            && !target_type.is_empty()
        {
            push_unique_string(&mut self.facets.defined_builder_types, target_type);
        }
        for stmt in &cls.body {
            let Stmt::FunctionDef(method_def) = stmt else {
                continue;
            };
            let m_name = method_def.name.as_str();
            if matches!(
                m_name,
                "from_defaults" | "builder" | "default" | "create" | "build"
            ) || m_name.starts_with("from_")
                || m_name.starts_with("with_")
                || m_name.starts_with("build_")
            {
                push_unique_string(&mut self.facets.defined_builder_types, cls_name);
                break;
            }
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Inspects Name and StringLiteral return type annotations for builder factories"
    )]
    fn record_top_level_factory_function(&mut self, func_def: &StmtFunctionDef) {
        let fn_name = func_def.name.as_str();
        if !(fn_name == "from_defaults"
            || fn_name.starts_with("build_")
            || fn_name.starts_with("make_"))
        {
            return;
        }
        if let Some(suffix) = fn_name
            .strip_prefix("build_")
            .or_else(|| fn_name.strip_prefix("make_"))
        {
            let pascal = snake_to_pascal_case(suffix);
            if is_pascal_case_class_name(&pascal) {
                push_unique_string(&mut self.facets.defined_builder_types, &pascal);
            }
        }
        if let Some(ret) = &func_def.returns {
            match ret.as_ref() {
                Expr::Name(n) if is_pascal_case_class_name(n.id.as_str()) => {
                    push_unique_string(&mut self.facets.defined_builder_types, n.id.as_str());
                }
                Expr::StringLiteral(s) if is_pascal_case_class_name(s.value.to_str()) => {
                    push_unique_string(&mut self.facets.defined_builder_types, s.value.to_str());
                }
                _ => {}
            }
        }
        for stmt in &func_def.body {
            if let Stmt::Return(ret_stmt) = stmt
                && let Some(Expr::Call(call)) = ret_stmt.value.as_deref()
            {
                let callee = crate::matchers::callee_qualified_name(&call.func);
                let tail = callee.rsplit('.').next().unwrap_or(&callee);
                if is_pascal_case_class_name(tail) {
                    push_unique_string(&mut self.facets.defined_builder_types, tail);
                }
            }
        }
    }

    fn record_top_level_helper_fingerprint(&mut self, func_def: &StmtFunctionDef) {
        let fn_name = func_def.name.as_str();
        let is_dunder = fn_name.starts_with("__") && fn_name.ends_with("__");
        if is_dunder {
            return;
        }
        let is_private = fn_name.starts_with('_')
            || (!self.dunder_all.is_empty() && !self.dunder_all.contains(fn_name));
        let statement_count = count_non_docstring_statements(&func_def.body);
        if statement_count < 2 {
            return;
        }
        let param_count = crate::matchers::all_function_parameters(func_def).count();
        let normalized_hash = compute_function_structural_hash(func_def, param_count);
        let span = crate::matchers::function_def_header_span(self.source, func_def);
        let loc = loc_from_line_starts(self.line_starts, span.start);
        self.facets.helper_fingerprints.push(HelperFingerprintIr {
            name: fn_name.to_string(),
            normalized_hash,
            statement_count,
            param_count,
            is_private,
            loc,
            span,
        });
    }

    fn walk_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.walk_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Walks statements and expressions for architectural facet extraction"
    )]
    fn walk_stmt(&mut self, stmt: &Stmt) {
        if self.in_entrypoint_body && !is_docstring_stmt(stmt) {
            self.facets.entrypoint_statement_count += 1;
        }
        match stmt {
            Stmt::ClassDef(cls) => {
                let span = text_range_to_byte_span(cls.range());
                let loc = loc_from_line_starts(self.line_starts, span.start);
                self.facets.concern_signals.push(ConcernSignalSite {
                    bucket: ConcernBucket::TypeDefinitions,
                    detail: format!("class {}", cls.name),
                    loc,
                    span,
                });
                self.walk_suite(&cls.body);
            }
            Stmt::FunctionDef(func_def) => {
                self.walk_suite(&func_def.body);
            }
            Stmt::Assign(assign) => {
                self.walk_expr(&assign.value);
            }
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    self.walk_expr(val);
                }
            }
            Stmt::AugAssign(aug) => self.walk_expr(&aug.value),
            Stmt::Expr(expr_stmt) => self.walk_expr(&expr_stmt.value),
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    self.walk_expr(val);
                }
            }
            Stmt::Raise(r) => {
                if let Some(exc) = &r.exc {
                    self.walk_expr(exc);
                }
            }
            Stmt::If(if_stmt) => self.walk_if(if_stmt),
            Stmt::For(for_stmt) => {
                if self.in_entrypoint_body {
                    let span = text_range_to_byte_span(for_stmt.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::EntrypointAdapter,
                        detail: "entrypoint-domain-loop".to_string(),
                        loc,
                        span,
                    });
                }
                self.walk_expr(&for_stmt.iter);
                self.walk_suite(&for_stmt.body);
                self.walk_suite(&for_stmt.orelse);
            }
            Stmt::While(while_stmt) => {
                if self.in_entrypoint_body {
                    let span = text_range_to_byte_span(while_stmt.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::EntrypointAdapter,
                        detail: "entrypoint-domain-loop".to_string(),
                        loc,
                        span,
                    });
                }
                self.walk_expr(&while_stmt.test);
                self.walk_suite(&while_stmt.body);
                self.walk_suite(&while_stmt.orelse);
            }
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    self.walk_expr(&item.context_expr);
                }
                self.walk_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                self.walk_suite(&try_stmt.body);
                for h in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                    self.walk_suite(&handler.body);
                }
                self.walk_suite(&try_stmt.orelse);
                self.walk_suite(&try_stmt.finalbody);
            }
            _ => {}
        }
    }

    fn walk_if(&mut self, if_stmt: &StmtIf) {
        self.walk_expr(&if_stmt.test);
        self.walk_suite(&if_stmt.body);
        for clause in &if_stmt.elif_else_clauses {
            if let Some(test) = &clause.test {
                self.walk_expr(test);
            }
            self.walk_suite(&clause.body);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Inspects calls and string literals for I/O and presentation signals"
    )]
    fn walk_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                self.inspect_call(call);
                self.walk_expr(&call.func);
                for arg in &call.arguments.args {
                    self.walk_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.walk_expr(&kw.value);
                }
            }
            Expr::StringLiteral(str_lit) => self.inspect_string_literal(str_lit),
            Expr::FString(fstr) => self.inspect_fstring(fstr),
            Expr::Await(aw) => self.walk_expr(&aw.value),
            Expr::BinOp(b) => {
                self.walk_expr(&b.left);
                self.walk_expr(&b.right);
            }
            Expr::UnaryOp(u) => self.walk_expr(&u.operand),
            Expr::BoolOp(b) => {
                for v in &b.values {
                    self.walk_expr(v);
                }
            }
            Expr::Compare(cmp) => {
                for op in &cmp.operands {
                    self.walk_expr(op);
                }
            }
            Expr::List(l) => {
                for e in &l.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Tuple(t) => {
                for e in &t.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Set(s) => {
                for e in &s.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Dict(d) => {
                for item in &d.items {
                    if let Some(k) = &item.key {
                        self.walk_expr(k);
                    }
                    self.walk_expr(&item.value);
                }
            }
            _ => {}
        }
    }

    fn inspect_call(&mut self, call: &ExprCall) {
        let callee = crate::matchers::callee_qualified_name(&call.func);
        if callee.is_empty() {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);

        if is_verified_python_io_call(&callee, call) {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::DataOrNetworkIo,
                detail: format!("{callee}(...)"),
                loc,
                span,
            });
        } else if is_verified_python_presentation_call(&callee) {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: format!("{callee}(...)"),
                loc,
                span,
            });
        }
        self.inspect_struct_literal_call(&callee, call, loc, span);
    }

    fn inspect_struct_literal_call(
        &mut self,
        callee: &str,
        call: &ExprCall,
        loc: SourceLoc,
        span: ByteSpan,
    ) {
        let tail = callee.rsplit('.').next().unwrap_or(callee);
        if !is_pascal_case_class_name(tail) {
            return;
        }
        let mut field_names = Vec::new();
        let mut default_or_literal_fields = Vec::new();
        for kw in &call.arguments.keywords {
            let Some(arg_id) = &kw.arg else {
                continue;
            };
            let key_str = arg_id.as_str();
            if is_default_or_literal_expr(&kw.value) {
                default_or_literal_fields.push(key_str.to_string());
            }
            field_names.push(key_str.to_string());
        }
        if field_names.len() >= 3 {
            self.facets
                .struct_literal_sites
                .push(StructLiteralConstructionSiteIr {
                    type_name: tail.to_string(),
                    field_names,
                    default_or_literal_fields,
                    loc,
                    span,
                });
        }
    }

    fn inspect_string_literal(&mut self, str_lit: &ExprStringLiteral) {
        let span = text_range_to_byte_span(str_lit.range());
        let raw = crate::matchers::slice_source(self.source, span);
        let val = str_lit.value.to_str();
        self.check_terminal_ui_text(val, raw, span);
    }

    fn inspect_fstring(&mut self, fstr: &ExprFString) {
        let span = text_range_to_byte_span(fstr.range());
        let raw = crate::matchers::slice_source(self.source, span);
        let mut combined = String::new();
        for part in fstr.value.elements() {
            if let Some(lit) = part.as_literal() {
                combined.push_str(&lit.value);
            } else if let Some(interp) = part.as_interpolation() {
                self.walk_expr(&interp.expression);
            }
        }
        self.check_terminal_ui_text(&combined, raw, span);
    }

    fn check_terminal_ui_text(&mut self, decoded: &str, raw: &str, span: ByteSpan) {
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let has_ansi = decoded.contains("\x1b[")
            || raw.contains("\\x1b[")
            || raw.contains("\\u001b[")
            || raw.contains("\\033[");
        let has_box = decoded.chars().any(is_box_drawing_char);

        if has_ansi {
            self.facets
                .inline_terminal_ui_sites
                .push(InlineTerminalUiPrimitiveSiteIr {
                    kind: TerminalUiPrimitiveKind::AnsiEscape,
                    snippet: "\\x1b[".to_string(),
                    loc,
                    span,
                });
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: "ANSI escape sequence".to_string(),
                loc,
                span,
            });
        } else if has_box {
            self.facets
                .inline_terminal_ui_sites
                .push(InlineTerminalUiPrimitiveSiteIr {
                    kind: TerminalUiPrimitiveKind::BoxDrawing,
                    snippet: "box-drawing literal".to_string(),
                    loc,
                    span,
                });
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: "Unicode box-drawing literal".to_string(),
                loc,
                span,
            });
        }
    }
}

fn is_dunder_main_guard(test: &Expr) -> bool {
    let Expr::Compare(cmp) = test else {
        return false;
    };
    if cmp.ops.len() != 1 || cmp.operands.len() != 2 || !matches!(cmp.ops[0], CmpOp::Eq) {
        return false;
    }
    let left_is_name = matches!(&cmp.operands[0], Expr::Name(n) if n.id.as_str() == "__name__");
    let right_is_main = matches!(
        &cmp.operands[1],
        Expr::StringLiteral(s) if s.value.to_str() == "__main__"
    );
    let left_is_main = matches!(
        &cmp.operands[0],
        Expr::StringLiteral(s) if s.value.to_str() == "__main__"
    );
    let right_is_name = matches!(&cmp.operands[1], Expr::Name(n) if n.id.as_str() == "__name__");
    (left_is_name && right_is_main) || (left_is_main && right_is_name)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Counts entries in top-level static list, tuple, set, dict, or frozenset literals"
)]
fn static_collection_entry_count(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::List(l) => Some(l.elts.len()),
        Expr::Tuple(t) => Some(t.elts.len()),
        Expr::Set(s) => Some(s.elts.len()),
        Expr::Dict(d) => Some(d.items.len()),
        Expr::Call(call) => {
            let callee = crate::matchers::callee_qualified_name(&call.func);
            if matches!(
                callee.as_str(),
                "frozenset" | "tuple" | "list" | "set" | "dict"
            ) && let Some(first_arg) = call.arguments.args.first()
            {
                static_collection_entry_count(first_arg)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_ast_or_validation_helper_name(fn_name: &str) -> bool {
    let trimmed = fn_name.trim_start_matches('_');
    trimmed.starts_with("parse_")
        || trimmed.starts_with("validate_")
        || trimmed.starts_with("visit_")
        || trimmed.starts_with("walk_")
        || trimmed.starts_with("extract_")
        || trimmed.starts_with("check_")
        || trimmed.starts_with("normalize_")
        || trimmed.starts_with("transform_")
        || trimmed.starts_with("compute_")
}

fn is_docstring_stmt(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Expr(expr_stmt) if matches!(expr_stmt.value.as_ref(), Expr::StringLiteral(_))
    )
}

fn is_box_drawing_char(ch: char) -> bool {
    matches!(ch, '\u{2500}'..='\u{257F}')
}

fn is_verified_python_io_call(callee: &str, call: &ExprCall) -> bool {
    if callee == "open" {
        if call.arguments.args.len() >= 2
            && let Expr::StringLiteral(mode) = &call.arguments.args[1]
        {
            let m = mode.value.to_str();
            if m.contains('w') || m.contains('a') || m.contains('+') || m.contains('x') {
                return true;
            }
        }
        return true;
    }
    if callee.starts_with("httpx.")
        || callee.starts_with("requests.")
        || callee.starts_with("aiohttp.")
        || callee.starts_with("urllib.request.")
        || matches!(
            callee,
            "urlopen" | "write_text" | "write_bytes" | "read_text" | "read_bytes"
        )
    {
        return true;
    }
    if let Some((prefix, method)) = callee.rsplit_once('.') {
        let receiver = prefix.rsplit('.').next().unwrap_or(prefix);
        if matches!(
            method,
            "write_text" | "write_bytes" | "read_text" | "read_bytes"
        ) {
            return true;
        }
        if matches!(
            receiver,
            "session"
                | "db"
                | "cursor"
                | "cur"
                | "conn"
                | "connection"
                | "engine"
                | "objects"
                | "client"
                | "http"
        ) && matches!(
            method,
            "query"
                | "execute"
                | "executemany"
                | "fetchall"
                | "fetchone"
                | "scalars"
                | "scalar"
                | "filter"
                | "get"
                | "post"
                | "put"
                | "delete"
                | "patch"
                | "request"
                | "create"
                | "bulk_create"
        ) {
            return true;
        }
    }
    false
}

fn is_verified_python_presentation_call(callee: &str) -> bool {
    if matches!(
        callee,
        "Console"
            | "rich.console.Console"
            | "click.style"
            | "click.secho"
            | "click.echo"
            | "typer.secho"
            | "typer.echo"
            | "render_template"
            | "flask.render_template"
            | "Jinja2Templates"
    ) || callee.starts_with("streamlit.")
        || callee.starts_with("st.")
        || callee.starts_with("rich.")
    {
        return true;
    }
    if let Some((prefix, method)) = callee.rsplit_once('.') {
        let receiver = prefix.rsplit('.').next().unwrap_or(prefix);
        if matches!(receiver, "console" | "Console") && matches!(method, "print" | "log" | "rule") {
            return true;
        }
        if method == "TemplateResponse" {
            return true;
        }
    }
    false
}

fn push_unique_string(vec: &mut Vec<String>, item: &str) {
    if !vec.iter().any(|s| s == item) {
        vec.push(item.to_string());
    }
}

fn snake_to_pascal_case(snake: &str) -> String {
    let mut out = String::new();
    for part in snake.split('_').filter(|p| !p.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            for ch in chars {
                out.push(ch);
            }
        }
    }
    out
}

fn is_pascal_case_class_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    if !name.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    !matches!(
        name,
        "Path"
            | "PurePath"
            | "PosixPath"
            | "WindowsPath"
            | "Console"
            | "Jinja2Templates"
            | "Exception"
            | "ValueError"
            | "TypeError"
            | "RuntimeError"
            | "KeyError"
            | "SystemExit"
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks default/boilerplate literals (None, bool, numbers, strings, empty collections)"
)]
fn is_default_or_literal_expr(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) => true,
        Expr::BooleanLiteral(b) => !b.value,
        Expr::NumberLiteral(num) => match &num.value {
            ruff_python_ast::Number::Int(i) => i.as_u64() == Some(0),
            ruff_python_ast::Number::Float(f) => *f == 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real == 0.0 && *imag == 0.0,
        },
        Expr::StringLiteral(s) => {
            let text = s.value.to_str();
            text.is_empty()
                || matches!(
                    text.to_ascii_lowercase().as_str(),
                    "default" | "none" | "auto" | "utf-8" | "utf8"
                )
        }
        Expr::BytesLiteral(b) => b.value.is_empty(),
        Expr::List(l) => l.elts.is_empty(),
        Expr::Tuple(t) => t.elts.is_empty(),
        Expr::Set(s) => s.elts.is_empty(),
        Expr::Dict(d) => d.items.is_empty(),
        Expr::Call(call) => {
            let callee = crate::matchers::callee_qualified_name(&call.func);
            matches!(callee.as_str(), "list" | "dict" | "set" | "tuple")
                && call.arguments.args.is_empty()
                && call.arguments.keywords.is_empty()
        }
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Counts statements recursively across compound Python AST nodes"
)]
fn count_non_docstring_statements(suite: &[Stmt]) -> usize {
    let mut total = 0;
    for (idx, stmt) in suite.iter().enumerate() {
        if idx == 0 && is_docstring_stmt(stmt) {
            continue;
        }
        total += 1;
        match stmt {
            Stmt::If(if_stmt) => {
                total += count_non_docstring_statements(&if_stmt.body);
                for clause in &if_stmt.elif_else_clauses {
                    total += count_non_docstring_statements(&clause.body);
                }
            }
            Stmt::For(for_stmt) => {
                total += count_non_docstring_statements(&for_stmt.body);
                total += count_non_docstring_statements(&for_stmt.orelse);
            }
            Stmt::While(while_stmt) => {
                total += count_non_docstring_statements(&while_stmt.body);
                total += count_non_docstring_statements(&while_stmt.orelse);
            }
            Stmt::With(with_stmt) => {
                total += count_non_docstring_statements(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                total += count_non_docstring_statements(&try_stmt.body);
                for h in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                    total += count_non_docstring_statements(&handler.body);
                }
                total += count_non_docstring_statements(&try_stmt.orelse);
                total += count_non_docstring_statements(&try_stmt.finalbody);
            }
            _ => {}
        }
    }
    total
}

fn compute_function_structural_hash(func_def: &StmtFunctionDef, param_count: usize) -> u64 {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    fnv1a_64_byte(&mut hash, u8::from(func_def.is_async));
    fnv1a_64_byte(&mut hash, u8::try_from(param_count).unwrap_or(u8::MAX));
    let body_without_docstring = match func_def.body.split_first() {
        Some((first, rest)) if is_docstring_stmt(first) => rest,
        _ => &func_def.body,
    };
    hash_suite(&mut hash, body_without_docstring);
    hash
}

fn hash_suite(hash: &mut u64, suite: &[Stmt]) {
    for stmt in suite {
        hash_stmt(hash, stmt);
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes structural Python AST statement variants normalized across local variable names"
)]
fn hash_stmt(hash: &mut u64, stmt: &Stmt) {
    match stmt {
        Stmt::Assign(assign) => {
            fnv1a_64_str(hash, "Stmt::Assign");
            for target in &assign.targets {
                hash_assign_target_shape(hash, target);
            }
            hash_expr(hash, &assign.value);
        }
        Stmt::AnnAssign(ann) => {
            if let Some(val) = &ann.value {
                fnv1a_64_str(hash, "Stmt::Assign");
                hash_assign_target_shape(hash, &ann.target);
                hash_expr(hash, val);
            } else {
                fnv1a_64_str(hash, "Stmt::AnnDecl");
            }
        }
        Stmt::AugAssign(aug) => {
            fnv1a_64_str(hash, "Stmt::AugAssign");
            hash_assign_target_shape(hash, &aug.target);
            hash_operator(hash, aug.op);
            hash_expr(hash, &aug.value);
        }
        Stmt::Return(ret) => {
            fnv1a_64_str(hash, "Stmt::Return");
            if let Some(val) = &ret.value {
                hash_expr(hash, val);
            }
        }
        Stmt::Expr(expr_stmt) => {
            fnv1a_64_str(hash, "Stmt::Expr");
            hash_expr(hash, &expr_stmt.value);
        }
        Stmt::If(if_stmt) => {
            fnv1a_64_str(hash, "Stmt::If");
            hash_expr(hash, &if_stmt.test);
            hash_suite(hash, &if_stmt.body);
            for clause in &if_stmt.elif_else_clauses {
                fnv1a_64_str(hash, "Stmt::ElifElse");
                if let Some(t) = &clause.test {
                    hash_expr(hash, t);
                }
                hash_suite(hash, &clause.body);
            }
        }
        Stmt::For(for_stmt) => {
            fnv1a_64_str(hash, "Stmt::For");
            hash_assign_target_shape(hash, &for_stmt.target);
            hash_expr(hash, &for_stmt.iter);
            hash_suite(hash, &for_stmt.body);
            hash_suite(hash, &for_stmt.orelse);
        }
        Stmt::While(while_stmt) => {
            fnv1a_64_str(hash, "Stmt::While");
            hash_expr(hash, &while_stmt.test);
            hash_suite(hash, &while_stmt.body);
            hash_suite(hash, &while_stmt.orelse);
        }
        Stmt::With(with_stmt) => {
            fnv1a_64_str(hash, "Stmt::With");
            for item in &with_stmt.items {
                hash_expr(hash, &item.context_expr);
            }
            hash_suite(hash, &with_stmt.body);
        }
        Stmt::Try(try_stmt) => {
            fnv1a_64_str(hash, "Stmt::Try");
            hash_suite(hash, &try_stmt.body);
            for h in &try_stmt.handlers {
                let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                fnv1a_64_str(hash, "Stmt::Except");
                hash_suite(hash, &handler.body);
            }
            hash_suite(hash, &try_stmt.orelse);
            hash_suite(hash, &try_stmt.finalbody);
        }
        Stmt::Raise(r) => {
            fnv1a_64_str(hash, "Stmt::Raise");
            if let Some(exc) = &r.exc {
                hash_expr(hash, exc);
            }
        }
        Stmt::Break(_) => fnv1a_64_str(hash, "Stmt::Break"),
        Stmt::Continue(_) => fnv1a_64_str(hash, "Stmt::Continue"),
        Stmt::Pass(_) => fnv1a_64_str(hash, "Stmt::Pass"),
        _ => fnv1a_64_str(hash, "Stmt::Other"),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes target shape for assignments and loop variables"
)]
fn hash_assign_target_shape(hash: &mut u64, target: &Expr) {
    match target {
        Expr::Name(_) => fnv1a_64_str(hash, "Target::Name"),
        Expr::Subscript(s) => {
            fnv1a_64_str(hash, "Target::Subscript");
            hash_expr(hash, &s.value);
            hash_expr(hash, &s.slice);
        }
        Expr::Attribute(a) => {
            fnv1a_64_str(hash, "Target::Attr");
            fnv1a_64_str(hash, a.attr.as_str());
            hash_expr(hash, &a.value);
        }
        Expr::Tuple(t) => {
            fnv1a_64_str(hash, "Target::Tuple");
            fnv1a_64_byte(hash, u8::try_from(t.elts.len()).unwrap_or(u8::MAX));
            for elt in &t.elts {
                hash_assign_target_shape(hash, elt);
            }
        }
        _ => fnv1a_64_str(hash, "Target::Other"),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes structural Python AST expressions normalized over local identifier names"
)]
fn hash_expr(hash: &mut u64, expr: &Expr) {
    match expr {
        Expr::Name(_) => fnv1a_64_str(hash, "Expr::Name"),
        Expr::Attribute(attr) => {
            fnv1a_64_str(hash, "Expr::Attr");
            fnv1a_64_str(hash, attr.attr.as_str());
            hash_expr(hash, &attr.value);
        }
        Expr::Call(call) => {
            fnv1a_64_str(hash, "Expr::Call");
            if let Expr::Name(n) = call.func.as_ref() {
                fnv1a_64_str(hash, n.id.as_str());
            } else {
                hash_expr(hash, &call.func);
            }
            fnv1a_64_byte(
                hash,
                u8::try_from(call.arguments.args.len()).unwrap_or(u8::MAX),
            );
            fnv1a_64_byte(
                hash,
                u8::try_from(call.arguments.keywords.len()).unwrap_or(u8::MAX),
            );
            for arg in &call.arguments.args {
                hash_expr(hash, arg);
            }
            for kw in &call.arguments.keywords {
                if let Some(k) = &kw.arg {
                    fnv1a_64_str(hash, k.as_str());
                }
                hash_expr(hash, &kw.value);
            }
        }
        Expr::BinOp(b) => {
            fnv1a_64_str(hash, "Expr::BinOp");
            hash_operator(hash, b.op);
            hash_expr(hash, &b.left);
            hash_expr(hash, &b.right);
        }
        Expr::UnaryOp(u) => {
            fnv1a_64_str(hash, "Expr::UnaryOp");
            hash_unary_op(hash, u.op);
            hash_expr(hash, &u.operand);
        }
        Expr::BoolOp(b) => {
            fnv1a_64_str(hash, "Expr::BoolOp");
            match b.op {
                BoolOp::And => fnv1a_64_str(hash, "And"),
                BoolOp::Or => fnv1a_64_str(hash, "Or"),
            }
            for v in &b.values {
                hash_expr(hash, v);
            }
        }
        Expr::Compare(cmp) => {
            fnv1a_64_str(hash, "Expr::Compare");
            for op in &cmp.ops {
                hash_cmp_op(hash, *op);
            }
            for operand in &cmp.operands {
                hash_expr(hash, operand);
            }
        }
        Expr::Subscript(s) => {
            fnv1a_64_str(hash, "Expr::Subscript");
            hash_expr(hash, &s.value);
            hash_expr(hash, &s.slice);
        }
        Expr::List(l) => {
            fnv1a_64_str(hash, "Expr::List");
            fnv1a_64_byte(hash, u8::try_from(l.elts.len()).unwrap_or(u8::MAX));
            for e in &l.elts {
                hash_expr(hash, e);
            }
        }
        Expr::Tuple(t) => {
            fnv1a_64_str(hash, "Expr::Tuple");
            fnv1a_64_byte(hash, u8::try_from(t.elts.len()).unwrap_or(u8::MAX));
            for e in &t.elts {
                hash_expr(hash, e);
            }
        }
        Expr::Set(s) => {
            fnv1a_64_str(hash, "Expr::Set");
            fnv1a_64_byte(hash, u8::try_from(s.elts.len()).unwrap_or(u8::MAX));
            for e in &s.elts {
                hash_expr(hash, e);
            }
        }
        Expr::Dict(d) => {
            fnv1a_64_str(hash, "Expr::Dict");
            fnv1a_64_byte(hash, u8::try_from(d.items.len()).unwrap_or(u8::MAX));
            for item in &d.items {
                if let Some(k) = &item.key {
                    hash_expr(hash, k);
                }
                hash_expr(hash, &item.value);
            }
        }
        Expr::If(if_expr) => {
            fnv1a_64_str(hash, "Expr::If");
            hash_expr(hash, &if_expr.test);
            hash_expr(hash, &if_expr.body);
            hash_expr(hash, &if_expr.orelse);
        }
        Expr::Await(aw) => {
            fnv1a_64_str(hash, "Expr::Await");
            hash_expr(hash, &aw.value);
        }
        Expr::StringLiteral(s) => {
            fnv1a_64_str(hash, "Expr::Str");
            fnv1a_64_str(hash, s.value.to_str());
        }
        Expr::FString(fstr) => {
            fnv1a_64_str(hash, "Expr::FString");
            for part in fstr.value.elements() {
                if let Some(lit) = part.as_literal() {
                    fnv1a_64_str(hash, &lit.value);
                } else if let Some(interp) = part.as_interpolation() {
                    hash_expr(hash, &interp.expression);
                }
            }
        }
        Expr::ListComp(comp) => {
            fnv1a_64_str(hash, "Expr::ListComp");
            hash_expr(hash, &comp.elt);
            for g in &comp.generators {
                hash_expr(hash, &g.iter);
                for cond in &g.ifs {
                    hash_expr(hash, cond);
                }
            }
        }
        Expr::SetComp(comp) => {
            fnv1a_64_str(hash, "Expr::SetComp");
            hash_expr(hash, &comp.elt);
            for g in &comp.generators {
                hash_expr(hash, &g.iter);
                for cond in &g.ifs {
                    hash_expr(hash, cond);
                }
            }
        }
        Expr::DictComp(comp) => {
            fnv1a_64_str(hash, "Expr::DictComp");
            if let Some(k) = &comp.key {
                hash_expr(hash, k);
            }
            hash_expr(hash, &comp.value);
            for g in &comp.generators {
                hash_expr(hash, &g.iter);
                for cond in &g.ifs {
                    hash_expr(hash, cond);
                }
            }
        }
        Expr::NumberLiteral(_) => fnv1a_64_str(hash, "Expr::Num"),
        Expr::BooleanLiteral(b) => {
            fnv1a_64_str(hash, "Expr::Bool");
            fnv1a_64_byte(hash, u8::from(b.value));
        }
        Expr::NoneLiteral(_) => fnv1a_64_str(hash, "Expr::None"),
        _ => fnv1a_64_str(hash, "Expr::Other"),
    }
}

fn hash_operator(hash: &mut u64, op: Operator) {
    let label = match op {
        Operator::Add => "+",
        Operator::Sub => "-",
        Operator::Mult => "*",
        Operator::MatMult => "@",
        Operator::Div => "/",
        Operator::Mod => "%",
        Operator::Pow => "**",
        Operator::LShift => "<<",
        Operator::RShift => ">>",
        Operator::BitOr => "|",
        Operator::BitXor => "^",
        Operator::BitAnd => "&",
        Operator::FloorDiv => "//",
    };
    fnv1a_64_str(hash, label);
}

fn hash_unary_op(hash: &mut u64, op: UnaryOp) {
    let label = match op {
        UnaryOp::Invert => "~",
        UnaryOp::Not => "not",
        UnaryOp::UAdd => "+u",
        UnaryOp::USub => "-u",
    };
    fnv1a_64_str(hash, label);
}

fn hash_cmp_op(hash: &mut u64, op: CmpOp) {
    let label = match op {
        CmpOp::Eq => "==",
        CmpOp::NotEq => "!=",
        CmpOp::Lt => "<",
        CmpOp::LtE => "<=",
        CmpOp::Gt => ">",
        CmpOp::GtE => ">=",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
    };
    fnv1a_64_str(hash, label);
}
