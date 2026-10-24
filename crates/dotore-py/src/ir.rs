//! Single-pass Python intermediate representation (`PyFileIr`), **Subject**, **Symbol Outline**,
//! **Contextual Owner**, and inline suppression extraction.

use std::path::Path;

use dotore_core::{
    ByteSpan, ContextualOwnerSpansIr, Diagnostic, ExtractedFile, FileSuppressions, LanguageId,
    SourceLoc, SuppressionDirectiveKind, SymbolKind, SymbolOutline, compute_line_starts,
    loc_from_line_starts, parse_python_suppression_directive,
};
use ruff_python_ast::{
    Expr, ModModule, PySourceType, Stmt, StmtAssign, StmtClassDef, StmtFunctionDef,
    token::TokenKind,
};
use ruff_python_parser::{Parsed, parse_unchecked_source};
use ruff_text_size::Ranged;

use crate::{
    asyncio::extract_asyncio_diagnostics,
    fastapi_pydantic::extract_fastapi_pydantic_diagnostics,
    graph::{self, PyModuleGraphInfo},
    matchers::{
        PyScopeTracker, annotation_is_final, is_upper_snake_case, text_range_to_byte_span,
    },
    orm::extract_orm_diagnostics,
    perf::extract_perf_diagnostics,
    safety::extract_safety_diagnostics,
    security::extract_security_diagnostics,
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

    let subjects_count = ir_extractor.subject_spans.len();
    let symbol_outlines = ir_extractor.symbol_outlines;
    let subject_spans = ir_extractor.subject_spans;
    let contextual_owner_spans = ir_extractor.contextual_owner_spans;

    let mut module_graph = graph::extract_module_graph_info(
        path,
        source,
        &line_starts,
        is_stub_file,
        suite,
        &symbol_outlines,
    );
    module_graph.potential_unawaited_calls = potential_unawaited_calls;

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
    extracted.with_payload(ir)
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
        let end_loc = loc_from_line_starts(
            self.line_starts,
            span.end.saturating_sub(1).max(span.start),
        );

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
        let end_loc = loc_from_line_starts(
            self.line_starts,
            span.end.saturating_sub(1).max(span.start),
        );

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
    let raw_slice = &source[start..end];
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
            return header[..prefix_len].trim_end();
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
        let raw_comment = &source[start..end];
        let body = raw_comment.trim_start_matches('#').trim();

        let Some((kind, rules)) = parse_python_suppression_directive(body) else {
            continue;
        };

        match kind {
            SuppressionDirectiveKind::DisableLine => {
                suppressions.add_line_disable(line_num, rules);
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
