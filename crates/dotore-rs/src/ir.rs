//! Single-pass `syn` AST and lexical scope extractor for Rust (`.rs`) files.
//!
//! Extracts [`RsFileIr`], Rust **Subjects** (functions, methods, `impl` blocks, modules),
//! **Symbol Outlines** with `///` doc comments, **Contextual Owner** byte spans,
//! and inline `// dotore-disable*` and `#[allow(...)]` / `#[expect(...)]` suppressions.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, ContextualOwnerSpansIr,
    ExtractedFile, FNV1A_64_OFFSET_BASIS, FileContext, FileSuppressions, HelperFingerprintIr,
    InlineTerminalUiPrimitiveSiteIr, LanguageId, SourceLoc, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, SymbolKind, SymbolOutline, TerminalUiPrimitiveKind,
    classify_file_context, compute_line_starts, extract_c_style_comment_suppressions,
    fnv1a_64_step, map_rust_allow_lint_to_rules,
};
use proc_macro2::TokenTree;
use syn::{
    Attribute, BinOp, Block, Expr, ExprBinary, ExprCall, ExprField, ExprLit, ExprMethodCall,
    ExprPath, ExprStruct, ExprUnary, ExprUnsafe, File, FnArg, ImplItem, ImplItemFn, ItemConst,
    ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemStruct, ItemTrait, ItemType, Lit, LitStr,
    Macro, Member, Pat, ReturnType, Stmt, TraitItemFn, Type, UnOp, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

pub use crate::matchers::RsCandidateFinding;
use crate::matchers::{
    RsScopeTracker, extract_pat_ident, extract_type_name, is_pub, loc_at, path_to_string,
    slice_source, span_to_bytes,
};

/// Kind of Rust **Subject** extracted from a `.rs` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsSubjectKind {
    /// Free function (`fn name(...)`).
    Function,
    /// Method inside an `impl` or `trait` block.
    Method,
    /// `impl` block (`impl Type` or `impl Trait for Type`).
    Impl,
    /// Inline module (`mod name { ... }`).
    Module,
}

/// A Rust **Subject** (function, method, `impl` block, or module) extracted in a single pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsSubjectIr {
    /// Subject identifier or qualified name (e.g. `"process_order"`, `"Order::new"`).
    pub name: String,
    /// Kind of Rust subject.
    pub kind: RsSubjectKind,
    /// 0-based byte span of the subject item.
    pub span: ByteSpan,
    /// 1-based start location of the subject item.
    pub loc: SourceLoc,
    /// Whether this subject is inside a `#[cfg(test)]` module or annotated as a test function.
    pub is_test: bool,
}

/// Single-pass intermediate representation for a Rust source file (`.rs`).
#[derive(Debug, Clone)]
pub struct RsFileIr {
    /// Path to the `.rs` file.
    pub path: PathBuf,
    /// Classification of the file (`Production`, `Test`, or `Story`).
    pub file_context: FileContext,
    /// Whether `syn::parse_file` succeeded without syntax errors.
    pub valid_syntax: bool,
    /// Extracted Rust **Subjects** (functions, methods, `impl` blocks, modules).
    pub subjects: Vec<RsSubjectIr>,
    /// Extracted **Symbol Outlines** for `dotore search`.
    pub symbol_outlines: Vec<SymbolOutline>,
    /// Extracted **Contextual Owner** spans for `--scope contextual` diff filtering.
    pub contextual_owner_spans: ContextualOwnerSpansIr,
    /// Extracted inline comment and `#[allow]` / `#[expect]` attribute suppressions.
    pub suppressions: FileSuppressions,
    /// Candidate rule findings collected during the single-pass AST walk.
    pub findings: Vec<RsCandidateFinding>,
    /// Per-file crate graph metadata (`pub(crate)` items and referenced identifiers).
    pub(crate) graph_ir: crate::graph::RsFileGraphIr,
}

/// Parses a Rust source file once with `syn::parse_file` and extracts its [`ExtractedFile`] and [`RsFileIr`].
#[must_use]
pub fn extract_rs_file(path: &Path, source: &str) -> ExtractedFile {
    let line_starts = compute_line_starts(source);
    let lines: Vec<&str> = source.lines().collect();
    let file_context = classify_file_context(path);
    let mut suppressions = extract_c_style_comment_suppressions(source, &["dotore"]);

    let parsed = syn::parse_file(source);
    let valid_syntax = parsed.is_ok();

    let mut extractor = IrAstExtractor {
        source,
        line_starts: &line_starts,
        subjects: Vec::new(),
        symbol_outlines: Vec::new(),
        contextual_owner_spans: ContextualOwnerSpansIr::default(),
        suppressions: &mut suppressions,
        scope: RsScopeTracker::new(),
    };
    let mut findings = Vec::new();

    let (graph_ir, architecture_facets) = if let Ok(ast) = &parsed {
        extractor.extract_crate_file(ast);
        crate::safety::extract_safety_findings(ast, &lines, &line_starts, &mut findings);
        crate::axum_sqlx::extract_axum_sqlx_findings(ast, &line_starts, &mut findings);
        crate::ui_signals::extract_ui_and_arch_findings(ast, &line_starts, &mut findings);
        crate::tokio_async::extract_tokio_async_findings(ast, source, &line_starts, &mut findings);
        crate::perf::extract_perf_findings(ast, &line_starts, &mut findings);
        let g = crate::graph::extract_file_graph_ir(ast, source, &line_starts);
        let facets = extract_architecture_facets(path, ast, source, &line_starts);
        (g, facets)
    } else {
        (
            crate::graph::RsFileGraphIr::default(),
            extract_empty_architecture_facets(path),
        )
    };

    let subjects = extractor.subjects;
    let symbol_outlines = extractor.symbol_outlines;
    let contextual_owner_spans = extractor.contextual_owner_spans;

    let subjects_count = subjects.len();
    let subject_spans: Vec<(Option<String>, ByteSpan, SourceLoc)> = subjects
        .iter()
        .map(|s| (Some(s.name.clone()), s.span, s.loc))
        .collect();

    let rs_ir = RsFileIr {
        path: path.to_path_buf(),
        file_context,
        valid_syntax,
        subjects,
        symbol_outlines: symbol_outlines.clone(),
        contextual_owner_spans: contextual_owner_spans.clone(),
        suppressions: suppressions.clone(),
        findings,
        graph_ir,
    };

    let mut extracted =
        ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Rust);
    extracted.file_context = file_context;
    extracted.symbol_outlines = symbol_outlines;
    extracted.contextual_owner_spans = contextual_owner_spans;
    extracted.suppressions = suppressions;
    extracted.subjects_count = subjects_count;
    extracted.effects_count = 0;
    extracted.subject_spans = subject_spans;
    extracted
        .with_architecture_facets(architecture_facets)
        .with_payload(rs_ir)
}

struct IrAstExtractor<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    subjects: Vec<RsSubjectIr>,
    symbol_outlines: Vec<SymbolOutline>,
    contextual_owner_spans: ContextualOwnerSpansIr,
    suppressions: &'a mut FileSuppressions,
    scope: RsScopeTracker,
}

impl IrAstExtractor<'_> {
    fn extract_crate_file(&mut self, file: &File) {
        let crate_rules = extract_attribute_suppressed_rules(&file.attrs);
        if !crate_rules.is_empty() {
            self.suppressions
                .add_block_disable(1, u32::MAX, crate_rules);
        }
        self.scope = RsScopeTracker::for_file(file);
        self.visit_file(file);
    }

    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn record_attr_suppressions(&mut self, attrs: &[Attribute], item_span: ByteSpan) {
        let rules = extract_attribute_suppressed_rules(attrs);
        if !rules.is_empty() {
            let start_line = self.loc_at(item_span.start).line;
            let end_line = self
                .loc_at(item_span.end.saturating_sub(1))
                .line
                .max(start_line);
            self.suppressions
                .add_block_disable(start_line, end_line, rules);
        }
    }

    fn extract_signature_header(
        &self,
        item_span: ByteSpan,
        body_start: Option<u32>,
    ) -> (String, u32) {
        let end_byte = body_start.unwrap_or(item_span.end);
        let raw_slice = slice_source(
            self.source,
            ByteSpan {
                start: item_span.start,
                end: end_byte,
            },
        );
        // Strip leading attributes and doc comments from the signature slice
        let cleaned_lines: Vec<&str> = raw_slice
            .lines()
            .map(str::trim)
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with("///")
                    && !l.starts_with("//!")
                    && !l.starts_with("//")
                    && !l.starts_with("#[")
            })
            .collect();
        let joined = cleaned_lines.join(" ");
        let sig = joined
            .trim_end_matches('{')
            .trim_end_matches(';')
            .trim()
            .to_string();
        let sig_end_line = self.loc_at(end_byte.saturating_sub(1)).line;
        (sig, sig_end_line)
    }

    fn extract_doc_comment(&self, attrs: &[Attribute]) -> (Option<String>, Option<u32>) {
        let mut doc_lines = Vec::new();
        let mut first_line: Option<u32> = None;
        for attr in attrs {
            if !attr.path().is_ident("doc") {
                continue;
            }
            if let syn::Meta::NameValue(nv) = &attr.meta
                && let Expr::Lit(expr_lit) = &nv.value
                && let Lit::Str(lit_str) = &expr_lit.lit
            {
                let span_bytes = self.span_to_bytes(attr.span());
                let line = self.loc_at(span_bytes.start).line;
                if first_line.is_none() {
                    first_line = Some(line);
                }
                let val = lit_str.value();
                let trimmed = val.strip_prefix(' ').unwrap_or(&val).trim_end().to_string();
                doc_lines.push(trimmed);
            }
        }
        if doc_lines.is_empty() {
            (None, None)
        } else {
            (Some(doc_lines.join("\n")), first_line)
        }
    }
}

impl<'ast> Visit<'ast> for IrAstExtractor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let span = self.span_to_bytes(i.span());
        let loc = self.loc_at(span.start);
        self.record_attr_suppressions(&i.attrs, span);

        let snap = self.scope.enter_mod(i);
        let mod_name = i.ident.to_string();
        self.subjects.push(RsSubjectIr {
            name: mod_name,
            kind: RsSubjectKind::Module,
            span,
            loc,
            is_test: self.scope.in_test(),
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.sig.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let parent_name = self.scope.subject_name();
        let snap = self.scope.enter_fn(i);
        let fn_name = i.sig.ident.to_string();
        let body_start = self.span_to_bytes(i.block.brace_token.span.open()).start;
        let (signature, signature_end_line) = self.extract_signature_header(span, Some(body_start));
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.subjects.push(RsSubjectIr {
            name: fn_name.clone(),
            kind: RsSubjectKind::Function,
            span,
            loc,
            is_test: self.scope.in_test(),
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(
            SymbolOutline::new(
                fn_name,
                SymbolKind::Function,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(&i.vis))
            .with_parent(parent_name)
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        visit::visit_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);
        let exported = is_pub(&i.vis);
        let vis_prefix = if exported { "pub " } else { "" };
        let signature = format!("{vis_prefix}struct {}", i.ident);

        self.symbol_outlines.push(
            SymbolOutline::new(
                i.ident.to_string(),
                SymbolKind::Struct,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(exported)
            .with_doc_comment(doc_comment, comment_start_line),
        );

        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);
        let exported = is_pub(&i.vis);
        let vis_prefix = if exported { "pub " } else { "" };
        let signature = format!("{vis_prefix}enum {}", i.ident);

        self.symbol_outlines.push(
            SymbolOutline::new(
                i.ident.to_string(),
                SymbolKind::Enum,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(exported)
            .with_doc_comment(doc_comment, comment_start_line),
        );

        visit::visit_item_enum(self, i);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let trait_name = i.ident.to_string();
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);
        let exported = is_pub(&i.vis);
        let vis_prefix = if exported { "pub " } else { "" };
        let signature = format!("{vis_prefix}trait {trait_name}");

        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(
            SymbolOutline::new(
                trait_name,
                SymbolKind::Trait,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(exported)
            .with_doc_comment(doc_comment, comment_start_line),
        );

        let snap = self.scope.enter_trait(i);
        visit::visit_item_trait(self, i);
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.sig.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let method_name = i.sig.ident.to_string();
        let body_start = i
            .default
            .as_ref()
            .map(|b| self.span_to_bytes(b.brace_token.span.open()).start);
        let (signature, signature_end_line) = self.extract_signature_header(span, body_start);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.symbol_outlines.push(
            SymbolOutline::new(
                method_name,
                SymbolKind::Method,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(true)
            .with_parent(self.scope.current_parent_type.clone())
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        let snap = self.scope.enter_trait_fn(i);
        visit::visit_trait_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_type(&mut self, i: &'ast ItemType) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (signature, signature_end_line) = self.extract_signature_header(span, None);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.symbol_outlines.push(
            SymbolOutline::new(
                i.ident.to_string(),
                SymbolKind::Type,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(&i.vis))
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        visit::visit_item_type(self, i);
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (signature, signature_end_line) = self.extract_signature_header(span, None);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.symbol_outlines.push(
            SymbolOutline::new(
                i.ident.to_string(),
                SymbolKind::Constant,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(&i.vis))
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);
        visit::visit_item_const(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (signature, signature_end_line) = self.extract_signature_header(span, None);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.symbol_outlines.push(
            SymbolOutline::new(
                i.ident.to_string(),
                SymbolKind::Constant,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(&i.vis))
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);
        visit::visit_item_static(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let span = self.span_to_bytes(i.span());
        let loc = self.loc_at(span.start);
        self.record_attr_suppressions(&i.attrs, span);

        let snap = self.scope.enter_impl(i);
        let impl_subject_name = self
            .scope
            .subject_name()
            .unwrap_or_else(|| "Impl".to_string());

        self.subjects.push(RsSubjectIr {
            name: impl_subject_name,
            kind: RsSubjectKind::Impl,
            span,
            loc,
            is_test: self.scope.in_test(),
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.sig.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let parent_name = self.scope.current_parent_type.clone();
        let snap = self.scope.enter_method(i);
        let method_name = i.sig.ident.to_string();
        let qualified_subject = self
            .scope
            .subject_name()
            .unwrap_or_else(|| method_name.clone());

        let body_start = self.span_to_bytes(i.block.brace_token.span.open()).start;
        let (signature, signature_end_line) = self.extract_signature_header(span, Some(body_start));
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.subjects.push(RsSubjectIr {
            name: qualified_subject,
            kind: RsSubjectKind::Method,
            span,
            loc,
            is_test: self.scope.in_test(),
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(
            SymbolOutline::new(
                method_name,
                SymbolKind::Method,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(&i.vis))
            .with_parent(parent_name)
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );

        visit::visit_impl_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let block_span = self.span_to_bytes(b.span());
        self.contextual_owner_spans.element_spans.push(block_span);
        visit::visit_block(self, b);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Local(local) = s {
            let span = self.span_to_bytes(local.span());
            self.record_attr_suppressions(&local.attrs, span);
        }
        visit::visit_stmt(self, s);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let span = self.span_to_bytes(node.span());
        self.contextual_owner_spans.element_spans.push(span);
        self.record_attr_suppressions(&node.attrs, span);
        visit::visit_expr_unsafe(self, node);
    }
}

fn extract_attribute_suppressed_rules(attrs: &[Attribute]) -> Vec<String> {
    let mut rules = Vec::new();
    for attr in attrs {
        let is_allow_or_expect = attr.path().is_ident("allow") || attr.path().is_ident("expect");
        if !is_allow_or_expect {
            continue;
        }
        let Ok(list) = attr.meta.require_list() else {
            continue;
        };
        let raw = list.tokens.to_string();
        for part in raw.split(',') {
            let trimmed = part.trim();
            if trimmed.starts_with("reason") {
                continue;
            }
            let normalized = trimmed.replace(' ', "");
            for mapped in map_rust_allow_lint_to_rules(&normalized) {
                if !rules.contains(&mapped) {
                    rules.push(mapped);
                }
            }
        }
    }
    rules
}

fn extract_empty_architecture_facets(path: &Path) -> ArchitectureFileFacets {
    ArchitectureFileFacets {
        is_entrypoint: is_rust_entrypoint_path(path),
        is_ui_kit_module: is_rust_ui_kit_module_path(path),
        ..ArchitectureFileFacets::default()
    }
}

fn is_rust_entrypoint_path(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some("main.rs")
        || path.components().any(|c| c.as_os_str() == "bin")
}

fn is_rust_ui_kit_module_path(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && matches!(
            name,
            "ui.rs"
                | "tui.rs"
                | "progress.rs"
                | "terminal.rs"
                | "theme.rs"
                | "ansi.rs"
                | "report.rs"
                | "terminal_ui.rs"
        )
    {
        return true;
    }
    path.parent().is_some_and(|parent| {
        parent.components().any(|c| {
            c.as_os_str()
                .to_str()
                .is_some_and(|s| matches!(s, "ui" | "report" | "tui" | "terminal"))
        })
    })
}

fn extract_architecture_facets(
    path: &Path,
    ast: &File,
    source: &str,
    line_starts: &[u32],
) -> ArchitectureFileFacets {
    let is_entrypoint = is_rust_entrypoint_path(path);
    let is_ui_kit_module = is_rust_ui_kit_module_path(path);

    let mut visitor = ArchitectureFacetsVisitor {
        source,
        line_starts,
        scope: RsScopeTracker::for_file(ast),
        is_entrypoint,
        is_ui_kit_module,
        in_equality_comparison: 0,
        in_syntax_highlighter_fn: false,
        facets: ArchitectureFileFacets {
            is_entrypoint,
            is_ui_kit_module,
            ..ArchitectureFileFacets::default()
        },
    };
    visitor.visit_file(ast);

    let mut domain_clusters = Vec::new();
    for bucket in visitor.facets.distinct_concern_buckets() {
        let label = match bucket {
            ConcernBucket::EntrypointAdapter => "entrypoint",
            ConcernBucket::DataOrNetworkIo => "io",
            ConcernBucket::TerminalOrUiPresentation => "ui",
            ConcernBucket::TypeDefinitions => "types",
            ConcernBucket::StaticDataCatalog => "catalog",
            ConcernBucket::AstOrValidationHelper => "helper",
        };
        if !domain_clusters.iter().any(|c| c == label) {
            domain_clusters.push(label.to_string());
        }
    }
    visitor.facets.domain_clusters = domain_clusters;
    visitor.facets
}

struct ArchitectureFacetsVisitor<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    scope: RsScopeTracker,
    is_entrypoint: bool,
    is_ui_kit_module: bool,
    in_equality_comparison: usize,
    in_syntax_highlighter_fn: bool,
    facets: ArchitectureFileFacets,
}

impl ArchitectureFacetsVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn push_concern(&mut self, bucket: ConcernBucket, detail: impl Into<String>, span: ByteSpan) {
        let detail = detail.into();
        let loc = self.loc_at(span.start);
        if !self
            .facets
            .concern_signals
            .iter()
            .any(|s| s.bucket == bucket && s.span == span && s.detail == detail)
        {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket,
                detail,
                loc,
                span,
            });
        }
    }

    fn add_builder_type(&mut self, type_name: impl Into<String>) {
        let name = type_name.into();
        if !name.is_empty() && !self.facets.defined_builder_types.contains(&name) {
            self.facets.defined_builder_types.push(name);
        }
    }

    fn inspect_string_literal(&mut self, val: &str, span: ByteSpan) {
        if self.scope.in_test()
            || self.scope.in_executable_body == 0
            || self.in_equality_comparison > 0
        {
            return;
        }
        let loc = self.loc_at(span.start);

        if let Some(snippet) = detect_box_drawing_border(val) {
            if !self
                .facets
                .inline_terminal_ui_sites
                .iter()
                .any(|s| s.span == span && s.kind == TerminalUiPrimitiveKind::BoxDrawing)
            {
                self.facets
                    .inline_terminal_ui_sites
                    .push(InlineTerminalUiPrimitiveSiteIr {
                        kind: TerminalUiPrimitiveKind::BoxDrawing,
                        snippet,
                        loc,
                        span,
                    });
            }
            self.push_concern(ConcernBucket::TerminalOrUiPresentation, "box-drawing", span);
        }

        if !self.in_syntax_highlighter_fn
            && let Some(snippet) = detect_ansi_escape_sequence(val)
        {
            if !self
                .facets
                .inline_terminal_ui_sites
                .iter()
                .any(|s| s.span == span && s.kind == TerminalUiPrimitiveKind::AnsiEscape)
            {
                self.facets
                    .inline_terminal_ui_sites
                    .push(InlineTerminalUiPrimitiveSiteIr {
                        kind: TerminalUiPrimitiveKind::AnsiEscape,
                        snippet,
                        loc,
                        span,
                    });
            }
            self.push_concern(ConcernBucket::TerminalOrUiPresentation, "ansi-escape", span);
        }
    }

    fn inspect_token_stream_literals(&mut self, tokens: &proc_macro2::TokenStream) {
        for tt in tokens.clone() {
            match tt {
                TokenTree::Group(g) => self.inspect_token_stream_literals(&g.stream()),
                TokenTree::Literal(lit) => {
                    let span = self.span_to_bytes(lit.span());
                    if let Ok(lit_str) = syn::parse2::<LitStr>(proc_macro2::TokenStream::from(
                        TokenTree::Literal(lit),
                    )) {
                        self.inspect_string_literal(&lit_str.value(), span);
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }

    fn record_static_catalog_if_large(
        &mut self,
        vis: &Visibility,
        ident: &syn::Ident,
        expr: &Expr,
        item_span: ByteSpan,
    ) {
        if self.scope.in_test() {
            return;
        }
        let Some(elems) = extract_array_or_slice_elements(expr) else {
            return;
        };
        let entry_count = elems.len();
        if entry_count < 5 {
            return;
        }
        if elems.iter().all(is_numeric_or_bool_literal) {
            return;
        }
        if matches!(vis, Visibility::Inherited)
            && (elems.iter().all(is_private_dep_capability_tuple)
                || elems.iter().all(|e| {
                    matches!(
                        e,
                        Expr::Lit(ExprLit {
                            lit: Lit::Str(_),
                            ..
                        })
                    )
                }))
        {
            return;
        }
        let ident_span = self.span_to_bytes(ident.span());
        let loc = self.loc_at(ident_span.start);
        let expr_span = self.span_to_bytes(expr.span());
        let byte_len = expr_span.end.saturating_sub(expr_span.start) as usize;
        let name = ident.to_string();
        self.facets.static_catalog_sites.push(StaticCatalogSiteIr {
            name: name.clone(),
            entry_count,
            byte_len,
            loc,
            span: item_span,
        });
        if entry_count >= 15 {
            self.push_concern(ConcernBucket::StaticDataCatalog, name, item_span);
        }
    }
}

impl<'ast> Visit<'ast> for ArchitectureFacetsVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        if !self.scope.in_test() {
            let name = i.ident.to_string();
            let span = self.span_to_bytes(i.span());
            if is_pub(&i.vis) && !has_clap_derive(&i.attrs) {
                self.facets.public_type_count += 1;
                self.push_concern(ConcernBucket::TypeDefinitions, name.clone(), span);
            }
            if let Some(base) = name.strip_suffix("Builder")
                && !base.is_empty()
            {
                self.add_builder_type(name.clone());
                self.add_builder_type(base.to_string());
            }
            if has_builder_or_default_derive(&i.attrs) {
                self.add_builder_type(name);
            }
        }
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        if !self.scope.in_test() && is_pub(&i.vis) && !has_clap_derive(&i.attrs) {
            let span = self.span_to_bytes(i.span());
            self.facets.public_type_count += 1;
            self.push_concern(ConcernBucket::TypeDefinitions, i.ident.to_string(), span);
        }
        visit::visit_item_enum(self, i);
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        let span = self.span_to_bytes(i.span());
        self.record_static_catalog_if_large(&i.vis, &i.ident, &i.expr, span);
        visit::visit_item_const(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        let span = self.span_to_bytes(i.span());
        self.record_static_catalog_if_large(&i.vis, &i.ident, &i.expr, span);
        visit::visit_item_static(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        if !self.scope.in_test()
            && let Some(type_name) = extract_type_name(&i.self_ty)
        {
            if let Some((_, trait_path, _)) = &i.trait_ {
                if trait_path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "Default")
                {
                    self.add_builder_type(type_name);
                }
            } else if impl_items_have_builder_method(&i.items) {
                if let Some(base) = type_name.strip_suffix("Builder")
                    && !base.is_empty()
                {
                    self.add_builder_type(base.to_string());
                }
                self.add_builder_type(type_name);
            }
        }
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_hl = self.in_syntax_highlighter_fn;
        let fn_name = i.sig.ident.to_string();
        self.in_syntax_highlighter_fn =
            prev_hl || is_syntax_highlighting_fn(&fn_name, &i.sig.inputs);

        if !self.scope.in_test() {
            let span = self.span_to_bytes(i.span());
            let ident_span = self.span_to_bytes(i.sig.ident.span());
            let loc = self.loc_at(ident_span.start);

            if fn_name == "main" || self.is_entrypoint {
                let stmts = count_statements_in_block(&i.block);
                self.facets.entrypoint_statement_count += stmts;
                if self.is_entrypoint && fn_name != "main" {
                    self.push_concern(
                        ConcernBucket::AstOrValidationHelper,
                        format!("fn {fn_name}"),
                        span,
                    );
                }
            }

            if matches!(i.vis, Visibility::Inherited)
                && self.scope.current_parent_type.is_none()
                && fn_name != "main"
                && i.block.stmts.len() >= 2
            {
                let (stmt_count, has_logic, normalized_hash) = compute_helper_fingerprint(i);
                if stmt_count >= 2 && has_logic {
                    self.facets.helper_fingerprints.push(HelperFingerprintIr {
                        name: fn_name,
                        normalized_hash,
                        statement_count: stmt_count,
                        param_count: i.sig.inputs.len(),
                        is_private: true,
                        loc,
                        span,
                    });
                }
            }
        }

        visit::visit_item_fn(self, i);
        self.in_syntax_highlighter_fn = prev_hl;
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_hl = self.in_syntax_highlighter_fn;
        let fn_name = i.sig.ident.to_string();
        self.in_syntax_highlighter_fn =
            prev_hl || is_syntax_highlighting_fn(&fn_name, &i.sig.inputs);
        visit::visit_impl_item_fn(self, i);
        self.in_syntax_highlighter_fn = prev_hl;
        self.scope.exit(snap);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if !self.scope.in_test()
            && let Expr::Path(ep) = &*node.func
        {
            let callee = path_to_string(&ep.path);
            let span = self.span_to_bytes(node.span());
            if is_data_or_network_io_call(&callee, &node.args, self.is_ui_kit_module, self.source) {
                self.push_concern(ConcernBucket::DataOrNetworkIo, callee, span);
            } else if is_ui_presentation_call(&callee) {
                self.push_concern(ConcernBucket::TerminalOrUiPresentation, callee, span);
            } else if is_entrypoint_adapter_call(&callee) {
                self.push_concern(ConcernBucket::EntrypointAdapter, callee, span);
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if !self.scope.in_test() {
            let method = node.method.to_string();
            let span = self.span_to_bytes(node.span());
            if matches!(
                method.as_str(),
                "fetch_one" | "fetch_all" | "fetch_optional" | "execute"
            ) {
                let recv_src = slice_source(self.source, self.span_to_bytes(node.receiver.span()));
                if recv_src.contains("sqlx::") || recv_src.contains("query") {
                    self.push_concern(
                        ConcernBucket::DataOrNetworkIo,
                        format!("sqlx::{method}"),
                        span,
                    );
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if !self.scope.in_test() {
            let mac_path = path_to_string(&mac.path);
            let span = self.span_to_bytes(mac.span());
            if matches!(
                mac_path.as_str(),
                "sqlx::query"
                    | "sqlx::query_as"
                    | "sqlx::query_scalar"
                    | "query"
                    | "query_as"
                    | "query_scalar"
            ) {
                self.push_concern(ConcernBucket::DataOrNetworkIo, format!("{mac_path}!"), span);
            } else if matches!(
                mac_path.as_str(),
                "crossterm::execute"
                    | "crossterm::queue"
                    | "execute"
                    | "queue"
                    | "view"
                    | "leptos::view"
                    | "rsx"
                    | "dioxus::rsx"
            ) {
                self.push_concern(
                    ConcernBucket::TerminalOrUiPresentation,
                    format!("{mac_path}!"),
                    span,
                );
            }
            self.inspect_token_stream_literals(&mac.tokens);
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let is_eq = matches!(node.op, BinOp::Eq(_) | BinOp::Ne(_));
        if is_eq {
            self.in_equality_comparison += 1;
        }
        visit::visit_expr_binary(self, node);
        if is_eq {
            self.in_equality_comparison = self.in_equality_comparison.saturating_sub(1);
        }
    }

    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        if !self.scope.in_test()
            && let Lit::Str(lit_str) = &node.lit
        {
            let span = self.span_to_bytes(node.span());
            self.inspect_string_literal(&lit_str.value(), span);
        }
        visit::visit_expr_lit(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast ExprStruct) {
        if !self.scope.in_test()
            && node.fields.len() >= 3
            && let Some(seg) = node.path.segments.last()
        {
            let type_name = seg.ident.to_string();
            let is_self_or_enclosing = type_name == "Self"
                || self.scope.current_parent_type.as_deref() == Some(type_name.as_str());
            if !is_self_or_enclosing {
                let (field_names, default_or_literal_fields) =
                    extract_struct_literal_fields(&node.fields);
                let span = self.span_to_bytes(node.span());
                let loc = self.loc_at(span.start);
                self.facets
                    .struct_literal_sites
                    .push(StructLiteralConstructionSiteIr {
                        type_name,
                        field_names,
                        default_or_literal_fields,
                        loc,
                        span,
                    });
            }
        }
        visit::visit_expr_struct(self, node);
    }
}

fn has_clap_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && attr.meta.require_list().is_ok_and(|list| {
                let s = list.tokens.to_string();
                s.contains("Parser") || s.contains("Subcommand") || s.contains("Args")
            })
    })
}

fn has_builder_or_default_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && attr.meta.require_list().is_ok_and(|list| {
                let s = list.tokens.to_string();
                s.contains("Default") || s.contains("Builder")
            })
    })
}

fn is_syntax_highlighting_fn(
    fn_name: &str,
    inputs: &syn::punctuated::Punctuated<FnArg, syn::Token![,]>,
) -> bool {
    if fn_name.starts_with("highlight_") {
        return true;
    }
    inputs.iter().any(|arg| {
        if let FnArg::Typed(pt) = arg {
            extract_pat_ident(&pt.pat).as_deref() == Some("highlight")
        } else {
            false
        }
    })
}

fn detect_ansi_escape_sequence(val: &str) -> Option<String> {
    if let Some(idx) = val.find("\x1b[") {
        let rest = &val[idx + 2..];
        if rest.is_empty() {
            return None;
        }
        let end = rest
            .find(|c: char| c.is_ascii_alphabetic())
            .map_or_else(|| rest.len().min(8), |i| (i + 1).min(12));
        return Some(format!("\\x1b[{}", &rest[..end]));
    }
    None
}

fn detect_box_drawing_border(val: &str) -> Option<String> {
    if val.chars().count() < 4 {
        return None;
    }
    const BOX_PATTERNS: &[&str] = &[
        "┌─",
        "╭─",
        "│ ",
        "└─",
        "╰─",
        "├─",
        "┤",
        "──┐",
        "──╮",
        "──┘",
        "──╯",
        "╔═",
        "╚═",
        "╠═",
    ];
    for &pat in BOX_PATTERNS {
        if val.contains(pat) {
            return Some(pat.to_string());
        }
    }
    None
}

fn is_data_or_network_io_call(
    callee: &str,
    args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    is_ui_kit_module: bool,
    source: &str,
) -> bool {
    if is_ui_kit_module && callee.ends_with("OpenOptions::new") && source.contains("/dev/tty") {
        return false;
    }
    if let Some(first_arg) = args.first()
        && let Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) = first_arg
        && s.value() == "/dev/tty"
    {
        return false;
    }
    if callee.starts_with("sqlx::query")
        || callee.starts_with("reqwest::")
        || callee.starts_with("std::fs::")
        || callee.starts_with("tokio::fs::")
        || callee.starts_with("std::net::Tcp")
        || callee.starts_with("tokio::net::Tcp")
    {
        return true;
    }
    matches!(
        callee,
        "fs::write"
            | "fs::read_to_string"
            | "fs::read"
            | "fs::create_dir_all"
            | "fs::remove_file"
            | "fs::remove_dir_all"
            | "File::create"
            | "File::open"
            | "OpenOptions::new"
            | "TcpStream::connect"
            | "TcpStream::connect_timeout"
            | "TcpListener::bind"
            | "UdpSocket::bind"
            | "Pool::connect"
            | "PgPool::connect"
            | "SqlitePool::connect"
            | "PgPoolOptions::new"
            | "SqlitePoolOptions::new"
    )
}

fn is_ui_presentation_call(callee: &str) -> bool {
    callee.starts_with("ratatui::")
        || callee.starts_with("crossterm::")
        || matches!(
            callee,
            "AsciiBox::new"
                | "GaugeBar::new"
                | "FlowDiagram::new"
                | "FilterTabBar::new"
                | "StatusBar::new"
                | "Terminal::new"
        )
}

fn is_entrypoint_adapter_call(callee: &str) -> bool {
    matches!(
        callee,
        "Cli::parse" | "Parser::parse" | "Router::new" | "axum::Router::new"
    )
}

fn impl_items_have_builder_method(items: &[ImplItem]) -> bool {
    items.iter().any(|item| {
        let ImplItem::Fn(m) = item else {
            return false;
        };
        let mname = m.sig.ident.to_string();
        matches!(mname.as_str(), "new" | "builder" | "default" | "for_rule")
            || mname.starts_with("with_")
            || mname.starts_with("build")
    })
}

fn extract_struct_literal_fields(
    fields: &syn::punctuated::Punctuated<syn::FieldValue, syn::Token![,]>,
) -> (Vec<String>, Vec<String>) {
    let mut field_names = Vec::with_capacity(fields.len());
    let mut default_or_literal_fields = Vec::new();
    for fv in fields {
        if fv.colon_token.is_some() && is_boilerplate_default_expr(&fv.expr) {
            let fname = match &fv.member {
                Member::Named(id) => id.to_string(),
                Member::Unnamed(idx) => idx.index.to_string(),
            };
            default_or_literal_fields.push(fname);
        }
        let fname = match &fv.member {
            Member::Named(id) => id.to_string(),
            Member::Unnamed(idx) => idx.index.to_string(),
        };
        field_names.push(fname);
    }
    (field_names, default_or_literal_fields)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Expr has dozens of variants; array extraction only unwraps Array, Reference, Group, and Paren"
)]
fn extract_array_or_slice_elements(
    expr: &Expr,
) -> Option<&syn::punctuated::Punctuated<Expr, syn::Token![,]>> {
    match expr {
        Expr::Array(arr) => Some(&arr.elems),
        Expr::Reference(r) => extract_array_or_slice_elements(&r.expr),
        Expr::Group(g) => extract_array_or_slice_elements(&g.expr),
        Expr::Paren(p) => extract_array_or_slice_elements(&p.expr),
        _ => None,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Expr has dozens of variants; only numeric/boolean literals and unary negations represent scalar numeric values"
)]
fn is_numeric_or_bool_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit { lit, .. }) => {
            matches!(lit, Lit::Int(_) | Lit::Float(_) | Lit::Bool(_))
        }
        Expr::Unary(ExprUnary {
            op: UnOp::Neg(_),
            expr: inner,
            ..
        }) => is_numeric_or_bool_literal(inner),
        _ => false,
    }
}

fn is_private_dep_capability_tuple(expr: &Expr) -> bool {
    if let Expr::Tuple(t) = expr
        && t.elems.len() == 2
    {
        matches!(&t.elems[1], Expr::Reference(r) if matches!(&*r.expr, Expr::Array(_)))
    } else {
        false
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Expr and syn::Lit have many variants; checks common default boilerplate literals and constructors"
)]
fn is_boilerplate_default_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::Bool(b) => !b.value,
            Lit::Int(i) => i.base10_digits() == "0",
            Lit::Float(f) => f.base10_digits() == "0" || f.base10_digits() == "0.0",
            Lit::Str(s) => s.value().is_empty(),
            _ => false,
        },
        Expr::Path(ep) => path_to_string(&ep.path) == "None",
        Expr::Call(call) => {
            if !call.args.is_empty() {
                if call.args.len() == 1
                    && let Expr::Path(ep) = &*call.func
                    && path_to_string(&ep.path) == "String::from"
                    && let Some(Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    })) = call.args.first()
                {
                    return s.value().is_empty();
                }
                return false;
            }
            if let Expr::Path(ep) = &*call.func {
                let p = path_to_string(&ep.path);
                matches!(
                    p.as_str(),
                    "Vec::new"
                        | "String::new"
                        | "Default::default"
                        | "HashMap::new"
                        | "BTreeMap::new"
                        | "HashSet::new"
                        | "BTreeSet::new"
                )
            } else {
                false
            }
        }
        Expr::MethodCall(mc) => {
            mc.args.is_empty()
                && (mc.method == "to_string" || mc.method == "to_owned")
                && matches!(
                    &*mc.receiver,
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(s),
                        ..
                    }) if s.value().is_empty()
                )
        }
        Expr::Macro(m) => path_to_string(&m.mac.path) == "vec" && m.mac.tokens.is_empty(),
        _ => false,
    }
}

fn count_statements_in_block(block: &Block) -> usize {
    struct StmtCounter(usize);
    impl<'ast> Visit<'ast> for StmtCounter {
        fn visit_stmt(&mut self, s: &'ast Stmt) {
            self.0 += 1;
            visit::visit_stmt(self, s);
        }
    }
    let mut counter = StmtCounter(0);
    counter.visit_block(block);
    counter.0
}

fn compute_helper_fingerprint(item_fn: &ItemFn) -> (usize, bool, u64) {
    let mut hasher = FnvHasher::new();
    let mut local_map: HashMap<String, String> = HashMap::new();

    hasher.write_str("arity:");
    hasher.write_usize(item_fn.sig.inputs.len());
    for (idx, arg) in item_fn.sig.inputs.iter().enumerate() {
        match arg {
            FnArg::Receiver(_) => hasher.write_str("param:self"),
            FnArg::Typed(pt) => {
                if let Some(id) = extract_pat_ident(&pt.pat) {
                    local_map.insert(id, format!("$p{idx}"));
                }
                hasher.write_str("param_ty:");
                hasher.write_str(&normalize_type_signature(&pt.ty));
            }
        }
    }
    hasher.write_str("ret:");
    match &item_fn.sig.output {
        ReturnType::Default => hasher.write_str("()"),
        ReturnType::Type(_, ty) => hasher.write_str(&normalize_type_signature(ty)),
    }

    let mut visitor = HelperAstHasher {
        hasher,
        local_map,
        next_local_idx: 0,
        stmt_count: 0,
        call_count: 0,
        control_flow_count: 0,
    };
    visitor.visit_block(&item_fn.block);
    let has_logic = visitor.control_flow_count > 0 || visitor.call_count >= 2;
    (visitor.stmt_count, has_logic, visitor.hasher.finish())
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Type has many variants; normalizes Reference, Slice, Path, and Tuple signatures"
)]
fn normalize_type_signature(ty: &Type) -> String {
    match ty {
        Type::Reference(r) => {
            let mut_prefix = if r.mutability.is_some() { "&mut " } else { "&" };
            format!("{mut_prefix}{}", normalize_type_signature(&r.elem))
        }
        Type::Slice(s) => format!("[{}]", normalize_type_signature(&s.elem)),
        Type::Path(tp) => {
            let segs: Vec<String> = tp
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            segs.join("::")
        }
        Type::Tuple(t) => {
            let inner: Vec<String> = t.elems.iter().map(normalize_type_signature).collect();
            format!("({})", inner.join(","))
        }
        _ => "ty".to_string(),
    }
}

struct FnvHasher(u64);

impl FnvHasher {
    const fn new() -> Self {
        Self(FNV1A_64_OFFSET_BASIS)
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.0 = fnv1a_64_step(self.0, bytes);
    }
    fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    fn write_usize(&mut self, val: usize) {
        self.write_bytes(&val.to_le_bytes());
    }

    const fn finish(&self) -> u64 {
        self.0
    }
}

struct HelperAstHasher {
    hasher: FnvHasher,
    local_map: HashMap<String, String>,
    next_local_idx: usize,
    stmt_count: usize,
    call_count: usize,
    control_flow_count: usize,
}

impl HelperAstHasher {
    fn bind_pat(&mut self, pat: &Pat) {
        if let Some(id) = extract_pat_ident(pat) {
            let slot = format!("$l{}", self.next_local_idx);
            self.next_local_idx += 1;
            self.local_map.insert(id, slot);
        }
    }
}

impl<'ast> Visit<'ast> for HelperAstHasher {
    fn visit_stmt(&mut self, s: &'ast Stmt) {
        self.stmt_count += 1;
        match s {
            Stmt::Local(local) => {
                self.hasher.write_str("stmt:local");
                if let Some(init) = &local.init {
                    self.visit_expr(&init.expr);
                    if let Some((_, div)) = &init.diverge {
                        self.control_flow_count += 1;
                        self.visit_expr(div);
                    }
                }
                self.bind_pat(&local.pat);
                return;
            }
            Stmt::Item(_) => self.hasher.write_str("stmt:item"),
            Stmt::Expr(_, semi) => {
                if semi.is_some() {
                    self.hasher.write_str("stmt:semi");
                } else {
                    self.hasher.write_str("stmt:tail");
                }
            }
            Stmt::Macro(_) => self.hasher.write_str("stmt:macro"),
        }
        visit::visit_stmt(self, s);
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has dozens of variants; only control-flow expressions increment control_flow_count before delegating to visit::visit_expr"
    )]
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::If(_) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:if");
            }
            Expr::Match(m) => {
                self.control_flow_count += 1;
                self.stmt_count += m.arms.len();
                self.hasher.write_str("expr:match:");
                self.hasher.write_usize(m.arms.len());
            }
            Expr::ForLoop(fl) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:for");
                self.bind_pat(&fl.pat);
            }
            Expr::While(_) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:while");
            }
            Expr::Loop(_) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:loop");
            }
            Expr::Return(_) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:return");
            }
            Expr::Try(_) => {
                self.control_flow_count += 1;
                self.hasher.write_str("expr:try");
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.call_count += 1;
        self.hasher.write_str("call:");
        self.hasher.write_usize(node.args.len());
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.call_count += 1;
        self.hasher.write_str("mcall:");
        self.hasher.write_str(&node.method.to_string());
        self.hasher.write_usize(node.args.len());
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast ExprField) {
        self.hasher.write_str("field:");
        match &node.member {
            Member::Named(id) => self.hasher.write_str(&id.to_string()),
            Member::Unnamed(idx) => self.hasher.write_usize(idx.index as usize),
        }
        visit::visit_expr_field(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let p = path_to_string(&node.path);
        if let Some(slot) = self.local_map.get(&p) {
            self.hasher.write_str("var:");
            self.hasher.write_str(slot);
        } else {
            self.hasher.write_str("path:");
            self.hasher.write_str(&p);
        }
        visit::visit_expr_path(self, node);
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::BinOp is non-exhaustive; arithmetic, logical, bitwise, and comparison operators are hashed explicitly"
    )]
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let op_str = match node.op {
            BinOp::Add(_) => "+",
            BinOp::Sub(_) => "-",
            BinOp::Mul(_) => "*",
            BinOp::Div(_) => "/",
            BinOp::Rem(_) => "%",
            BinOp::And(_) => "&&",
            BinOp::Or(_) => "||",
            BinOp::BitXor(_) => "^",
            BinOp::BitAnd(_) => "&",
            BinOp::BitOr(_) => "|",
            BinOp::Shl(_) => "<<",
            BinOp::Shr(_) => ">>",
            BinOp::Eq(_) => "==",
            BinOp::Lt(_) => "<",
            BinOp::Le(_) => "<=",
            BinOp::Ne(_) => "!=",
            BinOp::Ge(_) => ">=",
            BinOp::Gt(_) => ">",
            _ => "binop",
        };
        self.hasher.write_str("bin:");
        self.hasher.write_str(op_str);
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_unary(&mut self, node: &'ast ExprUnary) {
        let op_str = match node.op {
            UnOp::Deref(_) => "*",
            UnOp::Not(_) => "!",
            UnOp::Neg(_) => "-",
            _ => "unop",
        };
        self.hasher.write_str("un:");
        self.hasher.write_str(op_str);
        visit::visit_expr_unary(self, node);
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Lit has many variants; string, integer, boolean, and char literals are hashed with their values"
    )]
    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        match &node.lit {
            Lit::Str(s) => {
                self.hasher.write_str("str:");
                self.hasher.write_str(&s.value());
            }
            Lit::Int(i) => {
                self.hasher.write_str("int:");
                self.hasher.write_str(i.base10_digits());
            }
            Lit::Bool(b) => {
                self.hasher
                    .write_str(if b.value { "bool:1" } else { "bool:0" });
            }
            Lit::Char(c) => {
                let mut buf = [0u8; 4];
                self.hasher.write_str("char:");
                self.hasher.write_str(c.value().encode_utf8(&mut buf));
            }
            _ => self.hasher.write_str("lit"),
        }
        visit::visit_expr_lit(self, node);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.call_count += 1;
        self.hasher.write_str("mac:");
        self.hasher.write_str(&path_to_string(&mac.path));
        visit::visit_macro(self, mac);
    }
}
