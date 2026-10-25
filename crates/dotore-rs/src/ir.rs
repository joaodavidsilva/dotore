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
    ByteSpan, ContextualOwnerSpansIr, ExtractedFile, FNV1A_64_OFFSET_BASIS, FileContext,
    FileSuppressions, LanguageId, SourceLoc, SymbolKind, SymbolOutline, classify_file_context,
    compute_line_starts, extract_c_style_comment_suppressions, fnv1a_64_step,
    map_rust_allow_lint_to_rules,
};
use syn::{
    Attribute, Block, Expr, ExprBinary, ExprCall, ExprField, ExprLit, ExprMethodCall, ExprPath,
    ExprUnary, ExprUnsafe, File, FnArg, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, ItemTrait, ItemType, Lit, Macro, Member, Pat, ReturnType, Stmt,
    TraitItemFn, UnOp, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::ir_facets::{
    extract_architecture_facets, extract_empty_architecture_facets, helper_bin_op_str,
    normalize_type_signature,
};
pub use crate::matchers::RsCandidateFinding;
use crate::matchers::{
    RsScopeTracker, extract_pat_ident, is_pub, loc_at, path_to_string, slice_source, span_to_bytes,
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
    /// Per-file structural metadata (`mod` declarations, `cfg(feature)` sites, and normalized functions).
    pub(crate) structure_ir: crate::structure::RsStructureFileIr,
    /// Per-file crate reference identifiers and `#[cfg(test)]` byte spans (`#50`).
    pub(crate) crate_ref_ir: crate::cargo_health_refs::RsCrateRefFileIr,
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

    let (graph_ir, structure_ir, crate_ref_ir, architecture_facets) = if let Ok(ast) = &parsed {
        extractor.extract_crate_file(ast);
        let aliases = crate::source_kernel::RsAliasMap::build(ast);
        crate::safety::extract_safety_findings(ast, &lines, &line_starts, &mut findings);
        crate::axum_sqlx::extract_axum_sqlx_findings(ast, &line_starts, &mut findings);
        crate::ui_signals::extract_ui_and_arch_findings(ast, &line_starts, &mut findings);
        crate::tokio_async::extract_tokio_async_findings(ast, source, &line_starts, &mut findings);
        crate::perf::extract_perf_findings(ast, &line_starts, &mut findings);
        crate::source_kernel_detectors::extract_source_kernel_findings(
            ast,
            &aliases,
            &line_starts,
            &mut findings,
        );
        crate::clippy_rules::extract_clippy_ast_findings(
            ast,
            &aliases,
            &line_starts,
            &mut findings,
        );
        let s_ir = crate::structure::extract_structure_findings_and_ir(
            path,
            ast,
            source,
            &line_starts,
            file_context,
            &mut findings,
        );
        let g = crate::graph::extract_file_graph_ir(ast, source, &line_starts);
        let c_refs = crate::cargo_health_refs::extract_file_crate_refs(ast, file_context);
        let facets = extract_architecture_facets(path, ast, source, &line_starts);
        (g, s_ir, c_refs, facets)
    } else {
        (
            crate::graph::RsFileGraphIr::default(),
            crate::structure::RsStructureFileIr::default(),
            crate::cargo_health_refs::RsCrateRefFileIr::default(),
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
        structure_ir,
        crate_ref_ir,
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
        self.record_named_type_outline(&i.attrs, &i.vis, &i.ident, "struct", SymbolKind::Struct, i.span());
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        self.record_named_type_outline(&i.attrs, &i.vis, &i.ident, "enum", SymbolKind::Enum, i.span());
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
        self.record_const_or_static_outline(&i.attrs, &i.vis, &i.ident, i.span());
        visit::visit_item_const(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        self.record_const_or_static_outline(&i.attrs, &i.vis, &i.ident, i.span());
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

impl IrAstExtractor<'_> {
    fn record_named_type_outline(
        &mut self,
        attrs: &[Attribute],
        vis: &Visibility,
        ident: &syn::Ident,
        kw: &str,
        kind: SymbolKind,
        raw_span: proc_macro2::Span,
    ) {
        let span = self.span_to_bytes(raw_span);
        let loc = self.loc_at(self.span_to_bytes(ident.span()).start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(attrs, span);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(attrs);
        let exported = is_pub(vis);
        let vis_prefix = if exported { "pub " } else { "" };
        self.symbol_outlines.push(
            SymbolOutline::new(
                ident.to_string(),
                kind,
                format!("{vis_prefix}{kw} {ident}"),
                span,
                loc,
                end_line,
            )
            .with_exported(exported)
            .with_doc_comment(doc_comment, comment_start_line),
        );
    }

    fn record_const_or_static_outline(
        &mut self,
        attrs: &[Attribute],
        vis: &Visibility,
        ident: &syn::Ident,
        raw_span: proc_macro2::Span,
    ) {
        let span = self.span_to_bytes(raw_span);
        let loc = self.loc_at(self.span_to_bytes(ident.span()).start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(attrs, span);
        let (signature, signature_end_line) = self.extract_signature_header(span, None);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(attrs);
        self.symbol_outlines.push(
            SymbolOutline::new(
                ident.to_string(),
                SymbolKind::Constant,
                signature,
                span,
                loc,
                end_line,
            )
            .with_exported(is_pub(vis))
            .with_doc_comment(doc_comment, comment_start_line)
            .with_signature_end_line(signature_end_line),
        );
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);
    }
}

fn extract_attribute_suppressed_rules(attrs: &[Attribute]) -> Vec<String> {
    let mut rules = Vec::new();
    for attr in attrs {
        let is_allow = attr.path().is_ident("allow");
        let is_expect = attr.path().is_ident("expect");
        if !is_allow && !is_expect {
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
                if is_allow
                    && matches!(
                        mapped.as_str(),
                        "rs-structure-crate-level-allow"
                            | "rs-structure-unreasoned-allow"
                            | "rs-structure-stacked-allow"
                    )
                {
                    continue;
                }
                if !rules.contains(&mapped) {
                    rules.push(mapped);
                }
            }
        }
    }
    rules
}

pub(crate) fn compute_helper_fingerprint(item_fn: &ItemFn) -> (usize, bool, u64) {
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
                self.hasher
                    .write_str(if semi.is_some() { "stmt:semi" } else { "stmt:tail" });
            }
            Stmt::Macro(_) => self.hasher.write_str("stmt:macro"),
        }
        visit::visit_stmt(self, s);
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has dozens of variants; only control-flow expressions increment control_flow_count (#50)"
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

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        self.hasher.write_str("bin:");
        self.hasher.write_str(helper_bin_op_str(&node.op));
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
        reason = "syn::Lit has many variants; string, integer, boolean, and char literals are hashed with their values (#50)"
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

