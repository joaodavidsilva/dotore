//! Single-pass `syn` AST and lexical scope extractor for Rust (`.rs`) files.
//!
//! Extracts [`RsFileIr`], Rust **Subjects** (functions, methods, `impl` blocks, modules),
//! **Symbol Outlines** with `///` doc comments, **Contextual Owner** byte spans,
//! inline `// dotore-disable*` and `#[allow(...)]` / `#[expect(...)]` suppressions,
//! and single-pass candidate findings for core Rust safety rules.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    AutofixPatch, BlockDisableRange, ByteSpan, ContextualOwnerSpansIr, ExtractedFile, FileContext,
    FileSuppressions, LanguageId, LineDisableDirective, RuleId, SourceLoc, SymbolKind,
    SymbolOutline, classify_file_context, compute_line_starts, loc_from_line_starts,
};
use syn::{
    Attribute, BinOp, Block, Expr, ExprCall, ExprCast, ExprIf, ExprIndex, ExprMethodCall,
    ExprUnsafe, File, ImplItemFn, Item, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, ItemTrait, ItemType, Lit, Pat, Signature, Stmt, TraitItemFn, Type,
    UnOp, UseTree, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
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

/// A candidate diagnostic site discovered during the single-pass `syn` AST traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsCandidateFinding {
    /// Rule identifier for this candidate finding.
    pub rule: RuleId,
    /// Enclosing **Subject** name, if any.
    pub subject_name: Option<String>,
    /// Short target expression or symbol name.
    pub target_name: String,
    /// Static camelCase message identifier.
    pub message_id: &'static str,
    /// Human-readable diagnostic message.
    pub message: String,
    /// 1-based source location of the finding.
    pub loc: SourceLoc,
    /// 0-based byte span of the finding.
    pub span: ByteSpan,
    /// Optional deterministic [`AutofixPatch`] attached to this finding.
    pub autofix: Option<AutofixPatch>,
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
    pub graph_ir: crate::graph::RsFileGraphIr,
}

/// Parses a Rust source file once with `syn::parse_file` and extracts its [`ExtractedFile`] and [`RsFileIr`].
#[must_use]
pub fn extract_rs_file(path: &Path, source: &str) -> ExtractedFile {
    let line_starts = compute_line_starts(source);
    let lines: Vec<&str> = source.lines().collect();
    let file_context = classify_file_context(path);
    let mut suppressions = extract_comment_suppressions(source, &lines);

    let parsed = syn::parse_file(source);
    let valid_syntax = parsed.is_ok();

    let mut visitor = RsAstExtractor {
        source,
        lines: &lines,
        line_starts: &line_starts,
        subjects: Vec::new(),
        symbol_outlines: Vec::new(),
        contextual_owner_spans: ContextualOwnerSpansIr::default(),
        suppressions: &mut suppressions,
        findings: Vec::new(),
        in_test_context: false,
        current_subject_name: None,
        current_parent_type: None,
        has_imported_mem_forget: false,
        local_types: HashMap::new(),
        fixed_array_lengths: HashMap::new(),
        active_guards: Vec::new(),
        block_guards: Vec::new(),
    };

    let graph_ir = if let Ok(ast) = &parsed {
        visitor.extract_crate_file(ast);
        crate::axum_sqlx_ui_arch::extract_axum_sqlx_ui_arch_findings(
            ast,
            source,
            &line_starts,
            &mut visitor.findings,
        );
        crate::tokio_perf::extract_tokio_perf_findings(
            ast,
            source,
            &line_starts,
            &mut visitor.findings,
        );
        crate::graph::extract_file_graph_ir(path, ast, source, &line_starts)
    } else {
        crate::graph::RsFileGraphIr::default()
    };

    let subjects = visitor.subjects;
    let symbol_outlines = visitor.symbol_outlines;
    let contextual_owner_spans = visitor.contextual_owner_spans;
    let findings = visitor.findings;

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

    let mut extracted = ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Rust);
    extracted.file_context = file_context;
    extracted.symbol_outlines = symbol_outlines;
    extracted.contextual_owner_spans = contextual_owner_spans;
    extracted.suppressions = suppressions;
    extracted.subjects_count = subjects_count;
    extracted.effects_count = 0;
    extracted.subject_spans = subject_spans;
    extracted.with_payload(rs_ir)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericType {
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    F32,
    F64,
    Bool,
    Char,
    UnsuffixedInt(i128),
}

impl NumericType {
    fn from_type_name(name: &str) -> Option<Self> {
        match name {
            "u8" => Some(Self::U8),
            "u16" => Some(Self::U16),
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "u128" => Some(Self::U128),
            "usize" => Some(Self::Usize),
            "i8" => Some(Self::I8),
            "i16" => Some(Self::I16),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "i128" => Some(Self::I128),
            "isize" => Some(Self::Isize),
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "bool" => Some(Self::Bool),
            "char" => Some(Self::Char),
            _ => None,
        }
    }

    const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    const fn is_signed_int(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::Isize
        )
    }

    const fn is_unsigned_int(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::Usize
        )
    }

    const fn bit_width_rank(self) -> u8 {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 8,
            Self::U16 | Self::I16 => 16,
            Self::Char | Self::U32 | Self::I32 | Self::F32 => 32,
            // Treat pointer-sized integers conservatively as potentially 64-bit when narrowing to 32-bit,
            // and potentially 32-bit when narrowing from u64/i64.
            Self::Usize | Self::Isize => 48,
            Self::U64 | Self::I64 | Self::F64 => 64,
            Self::U128 | Self::I128 | Self::UnsuffixedInt(_) => 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SliceGuard {
    collection: String,
    index: Option<String>,
    non_empty: bool,
    inclusive_upper_bound: bool,
}

struct RsAstExtractor<'a> {
    source: &'a str,
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    subjects: Vec<RsSubjectIr>,
    symbol_outlines: Vec<SymbolOutline>,
    contextual_owner_spans: ContextualOwnerSpansIr,
    suppressions: &'a mut FileSuppressions,
    findings: Vec<RsCandidateFinding>,
    in_test_context: bool,
    current_subject_name: Option<String>,
    current_parent_type: Option<String>,
    has_imported_mem_forget: bool,
    local_types: HashMap<String, NumericType>,
    fixed_array_lengths: HashMap<String, usize>,
    active_guards: Vec<SliceGuard>,
    block_guards: Vec<SliceGuard>,
}

impl<'a> RsAstExtractor<'a> {
    fn extract_crate_file(&mut self, file: &File) {
        let crate_rules = extract_attribute_suppressed_rules(&file.attrs);
        if !crate_rules.is_empty() {
            self.suppressions.block_ranges.push(BlockDisableRange {
                start_line: 1,
                end_line: u32::MAX,
                rules: crate_rules,
            });
        }
        if attrs_indicate_test_context(&file.attrs) {
            self.in_test_context = true;
        }
        for item in &file.items {
            if let Item::Use(item_use) = item
                && use_tree_imports_mem_forget(&item_use.tree, "")
            {
                self.has_imported_mem_forget = true;
            }
        }
        self.visit_file(file);
    }

    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        let range = span.byte_range();
        let start = u32::try_from(range.start).unwrap_or(0);
        let end = u32::try_from(range.end).unwrap_or(start);
        ByteSpan { start, end }
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_from_line_starts(self.line_starts, byte_offset)
    }

    fn record_attr_suppressions(&mut self, attrs: &[Attribute], item_span: ByteSpan) {
        let rules = extract_attribute_suppressed_rules(attrs);
        if !rules.is_empty() {
            let start_line = self.loc_at(item_span.start).line;
            let end_line = self
                .loc_at(item_span.end.saturating_sub(1))
                .line
                .max(start_line);
            self.suppressions.block_ranges.push(BlockDisableRange {
                start_line,
                end_line,
                rules,
            });
        }
    }

    fn extract_signature_header(&self, item_span: ByteSpan, body_start: Option<u32>) -> (String, u32) {
        let end_byte = body_start.unwrap_or(item_span.end);
        let start_idx = usize::try_from(item_span.start).unwrap_or(0);
        let end_idx = usize::try_from(end_byte)
            .unwrap_or(start_idx)
            .min(self.source.len());
        let raw_slice = if start_idx <= end_idx && end_idx <= self.source.len() {
            &self.source[start_idx..end_idx]
        } else {
            ""
        };
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

    fn populate_sig_param_types(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input
                && let Some(ident) = extract_pat_ident(&pat_type.pat)
                && let Some(num_ty) = extract_numeric_type(&pat_type.ty)
            {
                self.local_types.insert(ident, num_ty);
            }
        }
    }

    fn infer_expr_numeric_type(&self, expr: &Expr) -> Option<NumericType> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; numeric inference inspects literals, paths, calls, casts, and unary/paren expressions"
        )]
        match expr {
            Expr::Paren(paren) => self.infer_expr_numeric_type(&paren.expr),
            Expr::Group(group) => self.infer_expr_numeric_type(&group.expr),
            Expr::Path(expr_path) => {
                if expr_path.qself.is_none()
                    && let Some(ident) = expr_path.path.get_ident()
                {
                    return self.local_types.get(&ident.to_string()).copied();
                }
                None
            }
            Expr::Lit(expr_lit) => match &expr_lit.lit {
                Lit::Int(lit_int) => {
                    let suffix = lit_int.suffix();
                    if !suffix.is_empty() {
                        return NumericType::from_type_name(suffix);
                    }
                    lit_int
                        .base10_parse::<i128>()
                        .ok()
                        .map(NumericType::UnsuffixedInt)
                }
                Lit::Float(lit_float) => {
                    let suffix = lit_float.suffix();
                    if suffix == "f32" {
                        Some(NumericType::F32)
                    } else {
                        Some(NumericType::F64)
                    }
                }
                Lit::Bool(_) => Some(NumericType::Bool),
                Lit::Char(_) => Some(NumericType::Char),
                _ => None,
            },
            Expr::Unary(expr_unary) => {
                if matches!(expr_unary.op, UnOp::Neg(_)) {
                    match self.infer_expr_numeric_type(&expr_unary.expr) {
                        Some(NumericType::UnsuffixedInt(v)) => {
                            Some(NumericType::UnsuffixedInt(-v))
                        }
                        Some(other) => Some(other),
                        None => Some(NumericType::I64),
                    }
                } else {
                    self.infer_expr_numeric_type(&expr_unary.expr)
                }
            }
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                if matches!(
                    method_name.as_str(),
                    "len" | "count" | "capacity" | " saturating_sub" | "wrapping_add"
                ) {
                    Some(NumericType::Usize)
                } else {
                    None
                }
            }
            Expr::Cast(inner_cast) => extract_numeric_type(&inner_cast.ty),
            _ => None,
        }
    }

    fn has_safety_comment_near(&self, start_line: u32, end_line: u32) -> bool {
        if start_line == 0 || self.lines.is_empty() {
            return false;
        }
        let start_idx = usize::try_from(start_line - 1).unwrap_or(0);
        // 1. Check the `unsafe` opening line and first non-empty line inside the block
        let max_inner_idx = usize::try_from(end_line.saturating_sub(1))
            .unwrap_or(start_idx)
            .min(self.lines.len().saturating_sub(1));
        for idx in start_idx..=max_inner_idx.min(start_idx + 2) {
            if let Some(&line_str) = self.lines.get(idx)
                && line_has_safety_comment(line_str)
            {
                return true;
            }
        }

        // 2. Walk backwards above `start_line` through comments, attributes, or multi-line statement headers
        let mut cursor = start_idx;
        let mut blank_budget = 1usize;
        while cursor > 0 {
            cursor -= 1;
            let prev = self.lines[cursor].trim();
            if line_has_safety_comment(prev) {
                return true;
            }
            if prev.is_empty() {
                if blank_budget == 0 {
                    break;
                }
                blank_budget -= 1;
                continue;
            }
            if prev.starts_with("//")
                || prev.starts_with("/*")
                || prev.starts_with('*')
                || prev.starts_with("#[")
                || prev.ends_with('=')
            {
                continue;
            }
            break;
        }

        false
    }

    fn is_slice_index_guarded(&self, expr_index: &ExprIndex) -> bool {
        // Unbounded full range `&slice[..]` never panics
        if let Expr::Range(range) = expr_index.index.as_ref()
            && range.start.is_none()
            && range.end.is_none()
        {
            return true;
        }

        let coll_key = normalize_expr_key(&expr_index.expr);
        if coll_key.is_empty() {
            return false;
        }

        // Check fixed-size local array literal bounds: `let arr = [1, 2, 3]; arr[0]`
        if let Some(&known_len) = self.fixed_array_lengths.get(&coll_key)
            && let Some(NumericType::UnsuffixedInt(idx_val)) =
                self.infer_expr_numeric_type(&expr_index.index)
            && idx_val >= 0
            && usize::try_from(idx_val).is_ok_and(|u| u < known_len)
        {
            return true;
        }

        let all_guards = self.active_guards.iter().chain(self.block_guards.iter());

        if let Expr::Range(range) = expr_index.index.as_ref() {
            let end_key = range.end.as_ref().map(|e| normalize_expr_key(e));
            let start_key = range.start.as_ref().map(|e| normalize_expr_key(e));
            for g in all_guards {
                if g.collection != coll_key {
                    continue;
                }
                if let Some(ek) = &end_key
                    && g.index.as_deref() == Some(ek.as_str())
                {
                    return true;
                }
                if end_key.is_none()
                    && let Some(sk) = &start_key
                    && g.index.as_deref() == Some(sk.as_str())
                {
                    return true;
                }
            }
            return false;
        }

        let idx_key = normalize_expr_key(&expr_index.index);
        for g in all_guards {
            if g.collection != coll_key {
                continue;
            }
            if !g.inclusive_upper_bound && g.index.as_deref() == Some(idx_key.as_str()) {
                return true;
            }
            if idx_key == "0" && (g.non_empty || (!g.inclusive_upper_bound && g.index.is_some())) {
                return true;
            }
        }

        false
    }
}

impl<'ast> Visit<'ast> for RsAstExtractor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let span = self.span_to_bytes(i.span());
        let loc = self.loc_at(span.start);
        self.record_attr_suppressions(&i.attrs, span);

        let prev_test = self.in_test_context;
        let is_test_mod = prev_test || attrs_indicate_test_context(&i.attrs) || i.ident == "tests";
        self.in_test_context = is_test_mod;

        let mod_name = i.ident.to_string();
        self.subjects.push(RsSubjectIr {
            name: mod_name.clone(),
            kind: RsSubjectKind::Module,
            span,
            loc,
            is_test: is_test_mod,
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        let prev_subj = self.current_subject_name.replace(mod_name);
        visit::visit_item_mod(self, i);
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.sig.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let prev_test = self.in_test_context;
        let is_test_fn = prev_test || attrs_indicate_test_context(&i.attrs);
        self.in_test_context = is_test_fn;

        let fn_name = i.sig.ident.to_string();
        let body_start = self.span_to_bytes(i.block.brace_token.span.open()).start;
        let (signature, signature_end_line) = self.extract_signature_header(span, Some(body_start));
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.subjects.push(RsSubjectIr {
            name: fn_name.clone(),
            kind: RsSubjectKind::Function,
            span,
            loc,
            is_test: is_test_fn,
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(SymbolOutline {
            name: fn_name.clone(),
            kind: SymbolKind::Function,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: self.current_subject_name.clone(),
            exported: is_pub(&i.vis),
            span,
            signature_end_line,
            loc,
            end_line,
        });

        let prev_subj = self.current_subject_name.replace(fn_name);
        let prev_types = std::mem::take(&mut self.local_types);
        let prev_arrays = std::mem::take(&mut self.fixed_array_lengths);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
        self.block_guards = prev_block_guards;
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);
        let vis_prefix = if is_pub(&i.vis) { "pub " } else { "" };
        let signature = format!("{vis_prefix}struct {}", i.ident);

        self.symbol_outlines.push(SymbolOutline {
            name: i.ident.to_string(),
            kind: SymbolKind::Struct,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line: loc.line,
            loc,
            end_line,
        });

        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);
        let vis_prefix = if is_pub(&i.vis) { "pub " } else { "" };
        let signature = format!("{vis_prefix}enum {}", i.ident);

        self.symbol_outlines.push(SymbolOutline {
            name: i.ident.to_string(),
            kind: SymbolKind::Enum,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line: loc.line,
            loc,
            end_line,
        });

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
        let vis_prefix = if is_pub(&i.vis) { "pub " } else { "" };
        let signature = format!("{vis_prefix}trait {trait_name}");

        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(SymbolOutline {
            name: trait_name.clone(),
            kind: SymbolKind::Trait,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line: loc.line,
            loc,
            end_line,
        });

        let prev_parent = self.current_parent_type.replace(trait_name);
        visit::visit_item_trait(self, i);
        self.current_parent_type = prev_parent;
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

        self.symbol_outlines.push(SymbolOutline {
            name: method_name.clone(),
            kind: SymbolKind::Method,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: self.current_parent_type.clone(),
            exported: true,
            span,
            signature_end_line,
            loc,
            end_line,
        });

        let prev_subj = self.current_subject_name.replace(method_name);
        let prev_types = std::mem::take(&mut self.local_types);
        self.populate_sig_param_types(&i.sig);
        visit::visit_trait_item_fn(self, i);
        self.local_types = prev_types;
        self.current_subject_name = prev_subj;
    }

    fn visit_item_type(&mut self, i: &'ast ItemType) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let (signature, signature_end_line) = self.extract_signature_header(span, None);
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.symbol_outlines.push(SymbolOutline {
            name: i.ident.to_string(),
            kind: SymbolKind::Type,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line,
            loc,
            end_line,
        });

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

        self.symbol_outlines.push(SymbolOutline {
            name: i.ident.to_string(),
            kind: SymbolKind::Constant,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line,
            loc,
            end_line,
        });

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

        self.symbol_outlines.push(SymbolOutline {
            name: i.ident.to_string(),
            kind: SymbolKind::Constant,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: None,
            exported: is_pub(&i.vis),
            span,
            signature_end_line,
            loc,
            end_line,
        });

        visit::visit_item_static(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let span = self.span_to_bytes(i.span());
        let loc = self.loc_at(span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let prev_test = self.in_test_context;
        let is_test_impl = prev_test || attrs_indicate_test_context(&i.attrs);
        self.in_test_context = is_test_impl;

        let self_ty_name = extract_type_name(&i.self_ty).unwrap_or_else(|| "Impl".to_string());
        let impl_subject_name = if let Some((_, trait_path, _)) = &i.trait_ {
            let trait_name = trait_path
                .segments
                .last()
                .map_or_else(|| "Trait".to_string(), |s| s.ident.to_string());
            format!("{trait_name} for {self_ty_name}")
        } else {
            self_ty_name.clone()
        };

        // Rule 4: `unsafe impl` requires a `// SAFETY:` comment
        if let Some(unsafe_token) = &i.unsafety
            && !self.in_test_context
        {
            let unsafe_span = self.span_to_bytes(unsafe_token.span);
            let unsafe_loc = self.loc_at(unsafe_span.start);
            if !self.has_safety_comment_near(unsafe_loc.line, end_line) {
                self.findings.push(RsCandidateFinding {
                    rule: RuleId::RsRequireSafetyCommentOnUnsafe,
                    subject_name: Some(impl_subject_name.clone()),
                    target_name: format!("unsafe impl {impl_subject_name}"),
                    message_id: "rsRequireSafetyCommentOnUnsafe",
                    message: format!(
                        "`unsafe impl {impl_subject_name}` is missing a preceding `// SAFETY:` invariant comment explaining why the trait's safety contract holds."
                    ),
                    loc: unsafe_loc,
                    span,
                    autofix: None,
                });
            }
        }

        self.subjects.push(RsSubjectIr {
            name: impl_subject_name.clone(),
            kind: RsSubjectKind::Impl,
            span,
            loc,
            is_test: is_test_impl,
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        let prev_parent = self.current_parent_type.replace(self_ty_name);
        let prev_subj = self.current_subject_name.replace(impl_subject_name);
        visit::visit_item_impl(self, i);
        self.current_subject_name = prev_subj;
        self.current_parent_type = prev_parent;
        self.in_test_context = prev_test;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let span = self.span_to_bytes(i.span());
        let ident_span = self.span_to_bytes(i.sig.ident.span());
        let loc = self.loc_at(ident_span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
        self.record_attr_suppressions(&i.attrs, span);

        let prev_test = self.in_test_context;
        let is_test_method = prev_test || attrs_indicate_test_context(&i.attrs);
        self.in_test_context = is_test_method;

        let method_name = i.sig.ident.to_string();
        let qualified_subject = if let Some(parent) = &self.current_parent_type {
            format!("{parent}::{method_name}")
        } else {
            method_name.clone()
        };

        let body_start = self.span_to_bytes(i.block.brace_token.span.open()).start;
        let (signature, signature_end_line) = self.extract_signature_header(span, Some(body_start));
        let (doc_comment, comment_start_line) = self.extract_doc_comment(&i.attrs);

        self.subjects.push(RsSubjectIr {
            name: qualified_subject.clone(),
            kind: RsSubjectKind::Method,
            span,
            loc,
            is_test: is_test_method,
        });
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        self.symbol_outlines.push(SymbolOutline {
            name: method_name,
            kind: SymbolKind::Method,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: self.current_parent_type.clone(),
            exported: is_pub(&i.vis),
            span,
            signature_end_line,
            loc,
            end_line,
        });

        let prev_subj = self.current_subject_name.replace(qualified_subject);
        let prev_types = std::mem::take(&mut self.local_types);
        let prev_arrays = std::mem::take(&mut self.fixed_array_lengths);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
        self.block_guards = prev_block_guards;
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let block_span = self.span_to_bytes(b.span());
        self.contextual_owner_spans.element_spans.push(block_span);
        let saved_block_guards_len = self.block_guards.len();

        for stmt in &b.stmts {
            self.visit_stmt(stmt);
            // If this statement is an `assert!(...)` or an `if cond { return/continue/break }` early guard,
            // record the post-statement bounds guard for subsequent statements in this block.
            extract_post_stmt_bounds_guards(stmt, &mut self.block_guards);
        }

        self.block_guards.truncate(saved_block_guards_len);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Local(local) = s {
            let span = self.span_to_bytes(local.span());
            self.record_attr_suppressions(&local.attrs, span);

            let pat_ident = extract_local_ident_and_type(&local.pat);
            if let Some((name, Some(explicit_ty))) = &pat_ident {
                self.local_types.insert(name.clone(), *explicit_ty);
            } else if let Some((name, None)) = &pat_ident
                && let Some(init) = &local.init
            {
                if let Some(inferred_ty) = self.infer_expr_numeric_type(&init.expr) {
                    self.local_types.insert(name.clone(), inferred_ty);
                }
                if let Expr::Array(arr) = init.expr.as_ref() {
                    self.fixed_array_lengths
                        .insert(name.clone(), arr.elems.len());
                } else if let Expr::Reference(expr_ref) = init.expr.as_ref()
                    && let Expr::Array(arr) = expr_ref.expr.as_ref()
                {
                    self.fixed_array_lengths
                        .insert(name.clone(), arr.elems.len());
                }
            }
        }
        visit::visit_stmt(self, s);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.visit_expr(&i.cond);

        let mut cond_guards = Vec::new();
        extract_cond_bounds_guards(&i.cond, false, &mut cond_guards);
        let saved_len = self.active_guards.len();
        self.active_guards.extend(cond_guards);
        self.visit_block(&i.then_branch);
        self.active_guards.truncate(saved_len);

        if let Some((_, else_expr)) = &i.else_branch {
            let mut else_guards = Vec::new();
            extract_cond_bounds_guards(&i.cond, true, &mut else_guards);
            let saved_else_len = self.active_guards.len();
            self.active_guards.extend(else_guards);
            self.visit_expr(else_expr);
            self.active_guards.truncate(saved_else_len);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if !self.in_test_context {
            let is_unwrap = method_name == "unwrap" && node.args.is_empty();
            let is_expect = method_name == "expect" && node.args.len() == 1;
            if is_unwrap || is_expect {
                let full_span = self.span_to_bytes(node.span());
                let method_span = self.span_to_bytes(node.method.span());
                let loc = self.loc_at(method_span.start);
                self.findings.push(RsCandidateFinding {
                    rule: RuleId::RsNoUnwrapInProduction,
                    subject_name: self.current_subject_name.clone(),
                    target_name: method_name.clone(),
                    message_id: "rsNoUnwrapInProduction",
                    message: format!(
                        "Avoid `.{method_name}()` in production Rust code; propagate errors with `?`, match with `let ... else`, or use `.unwrap_or_default()`."
                    ),
                    loc,
                    span: full_span,
                    autofix: None,
                });
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        if !self.in_test_context && !self.is_slice_index_guarded(node) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let coll_key = normalize_expr_key(&node.expr);
            let idx_key = normalize_expr_key(&node.index);
            let target = if coll_key.is_empty() {
                "slice[idx]".to_string()
            } else {
                format!("{coll_key}[{idx_key}]")
            };
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsNoUnguardedSliceIndex,
                subject_name: self.current_subject_name.clone(),
                target_name: target.clone(),
                message_id: "rsNoUnguardedSliceIndex",
                message: format!(
                    "Direct indexing `{target}` can panic out of bounds; prefer `{coll_key}.get({idx_key})` or guard `{idx_key} < {coll_key}.len()` first."
                ),
                loc,
                span,
                autofix: None,
            });
        }
        visit::visit_expr_index(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast ExprCast) {
        if !self.in_test_context
            && let Some(target_ty) = extract_numeric_type(&node.ty)
        {
            let src_ty = self.infer_expr_numeric_type(&node.expr);
            if is_lossy_or_sign_changing_cast(src_ty, target_ty) {
                let span = self.span_to_bytes(node.span());
                let loc = self.loc_at(span.start);
                let target_ty_str = extract_type_name(&node.ty).unwrap_or_else(|| "numeric".to_string());
                self.findings.push(RsCandidateFinding {
                    rule: RuleId::RsNoLossyNumericAsCast,
                    subject_name: self.current_subject_name.clone(),
                    target_name: format!("as {target_ty_str}"),
                    message_id: "rsNoLossyNumericAsCast",
                    message: format!(
                        "Potentially lossy or sign-changing `as {target_ty_str}` cast; prefer `{target_ty_str}::try_from(...)` / `.try_into()` or lossless `{target_ty_str}::from(...)`."
                    ),
                    loc,
                    span,
                    autofix: None,
                });
            }
        }
        visit::visit_expr_cast(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let span = self.span_to_bytes(node.span());
        self.contextual_owner_spans.element_spans.push(span);
        self.record_attr_suppressions(&node.attrs, span);

        if !self.in_test_context {
            let unsafe_token_span = self.span_to_bytes(node.unsafe_token.span);
            let loc = self.loc_at(unsafe_token_span.start);
            let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
            if !self.has_safety_comment_near(loc.line, end_line) {
                self.findings.push(RsCandidateFinding {
                    rule: RuleId::RsRequireSafetyCommentOnUnsafe,
                    subject_name: self.current_subject_name.clone(),
                    target_name: "unsafe".to_string(),
                    message_id: "rsRequireSafetyCommentOnUnsafe",
                    message: "`unsafe` block is missing a preceding `// SAFETY:` invariant comment explaining why all unsafe preconditions hold.".to_string(),
                    loc,
                    span,
                    autofix: None,
                });
            }
        }
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if !self.in_test_context
            && let Expr::Path(expr_path) = node.func.as_ref()
            && is_mem_forget_path(&expr_path.path, self.has_imported_mem_forget)
        {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsNoMemForget,
                subject_name: self.current_subject_name.clone(),
                target_name: "mem::forget".to_string(),
                message_id: "rsNoMemForget",
                message: "Avoid `mem::forget(...)`, which leaks resources and skips `Drop` destructors; use `std::mem::ManuallyDrop` if ownership transfer requires suppressing drop.".to_string(),
                loc,
                span,
                autofix: None,
            });
        }
        visit::visit_expr_call(self, node);
    }
}

fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn attrs_indicate_test_context(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        let path_str = attr
            .path()
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if matches!(
            path_str.as_str(),
            "test" | "tokio::test" | "sqlx::test" | "actix_rt::test" | "rstest" | "bench"
        ) || path_str.ends_with("::test")
        {
            return true;
        }
        if path_str == "cfg"
            && let Ok(tokens) = attr.meta.require_list()
        {
            let token_str = tokens.tokens.to_string();
            if token_str
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|tok| tok == "test")
            {
                return true;
            }
        }
    }
    false
}

fn extract_attribute_suppressed_rules(attrs: &[Attribute]) -> Vec<String> {
    let mut rules = Vec::new();
    for attr in attrs {
        let is_allow_or_expect =
            attr.path().is_ident("allow") || attr.path().is_ident("expect");
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
            for mapped in map_rust_lint_to_rule_keys(&normalized) {
                if !rules.contains(&mapped) {
                    rules.push(mapped);
                }
            }
        }
    }
    rules
}

fn map_rust_lint_to_rule_keys(lint: &str) -> Vec<String> {
    let stripped = lint
        .strip_prefix("dotore::")
        .or_else(|| lint.strip_prefix("dotore/"))
        .unwrap_or(lint);
    match stripped {
        "rs_no_unwrap_in_production"
        | "rs-no-unwrap-in-production"
        | "clippy::unwrap_used"
        | "clippy::expect_used"
        | "unwrap_used"
        | "expect_used" => vec!["rs-no-unwrap-in-production".to_string()],
        "rs_no_unguarded_slice_index"
        | "rs-no-unguarded-slice-index"
        | "clippy::indexing_slicing"
        | "indexing_slicing" => vec!["rs-no-unguarded-slice-index".to_string()],
        "rs_no_lossy_numeric_as_cast"
        | "rs-no-lossy-numeric-as-cast"
        | "clippy::cast_possible_truncation"
        | "clippy::cast_sign_loss"
        | "clippy::cast_possible_wrap"
        | "clippy::as_conversions"
        | "cast_possible_truncation"
        | "cast_sign_loss"
        | "cast_possible_wrap" => vec!["rs-no-lossy-numeric-as-cast".to_string()],
        "rs_require_safety_comment_on_unsafe"
        | "rs-require-safety-comment-on-unsafe"
        | "clippy::undocumented_unsafe_blocks"
        | "undocumented_unsafe_blocks"
        | "unsafe_code" => vec!["rs-require-safety-comment-on-unsafe".to_string()],
        "rs_no_mem_forget" | "rs-no-mem-forget" | "clippy::mem_forget" | "mem_forget" => {
            vec!["rs-no-mem-forget".to_string()]
        }
        "rs_tokio_no_std_lock_across_await"
        | "rs-tokio-no-std-lock-across-await"
        | "clippy::await_holding_lock"
        | "await_holding_lock" => vec!["rs-tokio-no-std-lock-across-await".to_string()],
        "rs_tokio_no_blocking_in_async" | "rs-tokio-no-blocking-in-async" => {
            vec!["rs-tokio-no-blocking-in-async".to_string()]
        }
        "rs_tokio_prefer_bounded_channel" | "rs-tokio-prefer-bounded-channel" => {
            vec!["rs-tokio-prefer-bounded-channel".to_string()]
        }
        "rs_perf_no_clone_in_loop" | "rs-perf-no-clone-in-loop" => {
            vec!["rs-perf-no-clone-in-loop".to_string()]
        }
        "rs_perf_hoist_regex_to_lazylock" | "rs-perf-hoist-regex-to-lazylock" => {
            vec!["rs-perf-hoist-regex-to-lazylock".to_string()]
        }
        "rs_perf_prefer_vec_with_capacity" | "rs-perf-prefer-vec-with-capacity" => {
            vec!["rs-perf-prefer-vec-with-capacity".to_string()]
        }
        "rs_perf_no_unnecessary_format"
        | "rs-perf-no-unnecessary-format"
        | "clippy::useless_format"
        | "useless_format" => vec!["rs-perf-no-unnecessary-format".to_string()],
        other => {
            if let Some(rule_id) =
                RuleId::parse(other).or_else(|| RuleId::parse(&other.replace('_', "-")))
            {
                vec![rule_id.as_str().to_string()]
            } else {
                Vec::new()
            }
        }
    }
}

fn use_tree_imports_mem_forget(tree: &UseTree, prefix: &str) -> bool {
    match tree {
        UseTree::Path(use_path) => {
            let next_prefix = if prefix.is_empty() {
                use_path.ident.to_string()
            } else {
                format!("{prefix}::{}", use_path.ident)
            };
            use_tree_imports_mem_forget(&use_path.tree, &next_prefix)
        }
        UseTree::Name(use_name) => {
            let full = if prefix.is_empty() {
                use_name.ident.to_string()
            } else {
                format!("{prefix}::{}", use_name.ident)
            };
            matches!(
                full.as_str(),
                "std::mem::forget" | "core::mem::forget" | "mem::forget"
            )
        }
        UseTree::Rename(use_rename) => {
            let full = if prefix.is_empty() {
                use_rename.ident.to_string()
            } else {
                format!("{prefix}::{}", use_rename.ident)
            };
            matches!(
                full.as_str(),
                "std::mem::forget" | "core::mem::forget" | "mem::forget"
            )
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_imports_mem_forget(item, prefix)),
        UseTree::Glob(_) => matches!(prefix, "std::mem" | "core::mem"),
    }
}

fn is_mem_forget_path(path: &syn::Path, has_imported_mem_forget: bool) -> bool {
    let joined = path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    matches!(
        joined.as_str(),
        "std::mem::forget" | "core::mem::forget" | "mem::forget"
    ) || (has_imported_mem_forget && joined == "forget")
}

fn extract_type_name(ty: &Type) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; only path and reference types carry named identifiers"
    )]
    match ty {
        Type::Path(type_path) => type_path.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(type_ref) => extract_type_name(&type_ref.elem),
        Type::Paren(paren) => extract_type_name(&paren.elem),
        Type::Group(group) => extract_type_name(&group.elem),
        _ => None,
    }
}

fn extract_numeric_type(ty: &Type) -> Option<NumericType> {
    let name = extract_type_name(ty)?;
    NumericType::from_type_name(&name)
}

fn extract_pat_ident(pat: &Pat) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; only ident, type, and reference patterns bind a single local name"
    )]
    match pat {
        Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
        Pat::Type(pat_type) => extract_pat_ident(&pat_type.pat),
        Pat::Reference(pat_ref) => extract_pat_ident(&pat_ref.pat),
        _ => None,
    }
}

fn extract_local_ident_and_type(pat: &Pat) -> Option<(String, Option<NumericType>)> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; only ident and typed patterns bind a single local variable"
    )]
    match pat {
        Pat::Ident(pat_ident) => Some((pat_ident.ident.to_string(), None)),
        Pat::Type(pat_type) => {
            let name = extract_pat_ident(&pat_type.pat)?;
            let num_ty = extract_numeric_type(&pat_type.ty);
            Some((name, num_ty))
        }
        _ => None,
    }
}

fn is_lossy_or_sign_changing_cast(src_ty: Option<NumericType>, target_ty: NumericType) -> bool {
    match src_ty {
        Some(NumericType::UnsuffixedInt(val)) => {
            if val < 0 && target_ty.is_unsigned_int() {
                return true;
            }
            match target_ty {
                NumericType::U8 => !(0..=i128::from(u8::MAX)).contains(&val),
                NumericType::U16 => !(0..=i128::from(u16::MAX)).contains(&val),
                NumericType::U32 => !(0..=i128::from(u32::MAX)).contains(&val),
                NumericType::I8 => !(i128::from(i8::MIN)..=i128::from(i8::MAX)).contains(&val),
                NumericType::I16 => !(i128::from(i16::MIN)..=i128::from(i16::MAX)).contains(&val),
                NumericType::I32 => !(i128::from(i32::MIN)..=i128::from(i32::MAX)).contains(&val),
                NumericType::U64
                | NumericType::U128
                | NumericType::Usize
                | NumericType::I64
                | NumericType::I128
                | NumericType::Isize
                | NumericType::F32
                | NumericType::F64
                | NumericType::Bool
                | NumericType::Char
                | NumericType::UnsuffixedInt(_) => false,
            }
        }
        Some(NumericType::Bool | NumericType::Char) => false,
        Some(src) => {
            if src == target_ty {
                return false;
            }
            // Float-to-int or f64-to-f32 is always potentially lossy
            if src.is_float() {
                return !matches!((src, target_ty), (NumericType::F32, NumericType::F64));
            }
            if target_ty.is_float() {
                // Large integers (64-bit / 128-bit / usize / isize) lose precision in f32 (or f64 for 64/128-bit)
                return src.bit_width_rank() >= target_ty.bit_width_rank();
            }
            // Signed -> Unsigned always risks sign loss
            if src.is_signed_int() && target_ty.is_unsigned_int() {
                return true;
            }
            // Unsigned -> Signed risks wrap when unsigned width >= signed width
            if src.is_unsigned_int() && target_ty.is_signed_int() {
                return src.bit_width_rank() >= target_ty.bit_width_rank();
            }
            // Same-signedness narrowing (`u64 as u32`, `usize as u32`, `u64 as usize`, `i64 as i32`, etc.)
            src.bit_width_rank() > target_ty.bit_width_rank()
        }
        None => {
            // Unknown source expression type: flag casts to narrower or sign-changing integer targets
            matches!(
                target_ty,
                NumericType::U8
                    | NumericType::U16
                    | NumericType::U32
                    | NumericType::Usize
                    | NumericType::I8
                    | NumericType::I16
                    | NumericType::I32
                    | NumericType::Isize
            )
        }
    }
}

fn line_has_safety_comment(line: &str) -> bool {
    let Some(comment_pos) = line.find("//").or_else(|| line.find("/*")) else {
        return false;
    };
    let comment_part = line[comment_pos..].to_ascii_lowercase();
    comment_part.contains("safety:") || comment_part.contains("# safety")
}

fn normalize_expr_key(expr: &Expr) -> String {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; fallback formats tokens compactly"
    )]
    match expr {
        Expr::Paren(p) => normalize_expr_key(&p.expr),
        Expr::Group(g) => normalize_expr_key(&g.expr),
        Expr::Reference(r) => normalize_expr_key(&r.expr),
        Expr::Path(path) => path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Field(field) => {
            let base = normalize_expr_key(&field.base);
            let member = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(idx) => idx.index.to_string(),
            };
            format!("{base}.{member}")
        }
        Expr::Lit(expr_lit) => match &expr_lit.lit {
            Lit::Int(i) => i.base10_digits().to_string(),
            _ => quote_compact(expr),
        },
        _ => quote_compact(expr),
    }
}

fn quote_compact(expr: &Expr) -> String {
    use syn::spanned::Spanned as _;
    let _ = expr.span();
    quote_like_expr(expr)
}

fn quote_like_expr(expr: &Expr) -> String {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Compact expression key formatter handles common indexing expressions"
    )]
    match expr {
        Expr::Index(idx) => {
            format!(
                "{}[{}]",
                normalize_expr_key(&idx.expr),
                normalize_expr_key(&idx.index)
            )
        }
        Expr::MethodCall(mc) => {
            format!("{}.{}()", normalize_expr_key(&mc.receiver), mc.method)
        }
        Expr::Binary(bin) => {
            format!(
                "{}+{}",
                normalize_expr_key(&bin.left),
                normalize_expr_key(&bin.right)
            )
        }
        _ => String::new(),
    }
}

fn extract_cond_bounds_guards(cond: &Expr, negated: bool, out: &mut Vec<SliceGuard>) {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Condition guard extraction inspects logical connectives, unary negation, method calls, and comparisons"
    )]
    match cond {
        Expr::Paren(p) => extract_cond_bounds_guards(&p.expr, negated, out),
        Expr::Group(g) => extract_cond_bounds_guards(&g.expr, negated, out),
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => {
            extract_cond_bounds_guards(&u.expr, !negated, out);
        }
        Expr::Binary(bin) => match bin.op {
            BinOp::And(_) if !negated => {
                extract_cond_bounds_guards(&bin.left, false, out);
                extract_cond_bounds_guards(&bin.right, false, out);
            }
            BinOp::Or(_) if negated => {
                extract_cond_bounds_guards(&bin.left, true, out);
                extract_cond_bounds_guards(&bin.right, true, out);
            }
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Ne(_)
            | BinOp::Eq(_) => {
                extract_comparison_guard(&bin.left, &bin.op, &bin.right, negated, out);
            }
            _ => {}
        },
        Expr::Let(expr_let) if !negated => {
            extract_cond_bounds_guards(&expr_let.expr, false, out);
        }
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            let recv = normalize_expr_key(&mc.receiver);
            if recv.is_empty() {
                return;
            }
            // `!slice.is_empty()` (when `negated == true` on `slice.is_empty()`)
            if method == "is_empty" && mc.args.is_empty() && negated {
                out.push(SliceGuard {
                    collection: recv,
                    index: Some("0".to_string()),
                    non_empty: true,
                    inclusive_upper_bound: false,
                });
            } else if method == "is_char_boundary"
                && !negated
                && let Some(first_arg) = mc.args.first()
            {
                let idx_key = normalize_expr_key(first_arg);
                if !idx_key.is_empty() {
                    out.push(SliceGuard {
                        collection: recv,
                        index: Some(idx_key),
                        non_empty: false,
                        inclusive_upper_bound: true,
                    });
                }
            }
        }
        _ => {}
    }
}

fn extract_comparison_guard(
    left: &Expr,
    op: &BinOp,
    right: &Expr,
    negated: bool,
    out: &mut Vec<SliceGuard>,
) {
    let Some(cmp) = resolve_effective_cmp(op, negated) else {
        return;
    };

    // Case 1: `idx < coll.len()` or `idx <= coll.len()`
    if let Some(coll) = extract_len_receiver(right) {
        let idx_key = normalize_expr_key(left);
        if !idx_key.is_empty() {
            match cmp {
                EffectiveCmp::Lt => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Le => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: false,
                        inclusive_upper_bound: true,
                    });
                }
                EffectiveCmp::Gt | EffectiveCmp::Ge | EffectiveCmp::Ne => {}
            }
        }
    }

    // Case 2: `coll.len() > idx` or `coll.len() >= 1` or `coll.len() != 0`
    if let Some(coll) = extract_len_receiver(left) {
        let idx_key = normalize_expr_key(right);
        if !idx_key.is_empty() {
            match cmp {
                EffectiveCmp::Gt => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Ge => {
                    let is_positive_lit = idx_key.parse::<usize>().is_ok_and(|n| n >= 1);
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(if is_positive_lit {
                            "0".to_string()
                        } else {
                            idx_key
                        }),
                        non_empty: is_positive_lit,
                        inclusive_upper_bound: !is_positive_lit,
                    });
                }
                EffectiveCmp::Ne if idx_key == "0" => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some("0".to_string()),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Lt | EffectiveCmp::Le | EffectiveCmp::Ne => {}
            }
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::BinOp is non-exhaustive and includes arithmetic/bitwise operators; only comparison operators form bounds guards"
)]
const fn resolve_effective_cmp(op: &BinOp, negated: bool) -> Option<EffectiveCmp> {
    if negated {
        match op {
            BinOp::Ge(_) => Some(EffectiveCmp::Lt),
            BinOp::Gt(_) => Some(EffectiveCmp::Le),
            BinOp::Le(_) => Some(EffectiveCmp::Gt),
            BinOp::Lt(_) => Some(EffectiveCmp::Ge),
            BinOp::Eq(_) => Some(EffectiveCmp::Ne),
            _ => None,
        }
    } else {
        match op {
            BinOp::Lt(_) => Some(EffectiveCmp::Lt),
            BinOp::Le(_) => Some(EffectiveCmp::Le),
            BinOp::Gt(_) => Some(EffectiveCmp::Gt),
            BinOp::Ge(_) => Some(EffectiveCmp::Ge),
            BinOp::Ne(_) => Some(EffectiveCmp::Ne),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveCmp {
    Lt,
    Le,
    Gt,
    Ge,
    Ne,
}

fn extract_len_receiver(expr: &Expr) -> Option<String> {
    if let Expr::MethodCall(mc) = expr
        && mc.method == "len"
        && mc.args.is_empty()
    {
        let recv = normalize_expr_key(&mc.receiver);
        if !recv.is_empty() {
            return Some(recv);
        }
    }
    None
}

fn extract_post_stmt_bounds_guards(stmt: &Stmt, block_guards: &mut Vec<SliceGuard>) {
    match stmt {
        Stmt::Expr(Expr::If(expr_if), _) => {
            if block_always_diverges(&expr_if.then_branch) {
                extract_cond_bounds_guards(&expr_if.cond, true, block_guards);
            }
        }
        Stmt::Macro(stmt_macro) => {
            if stmt_macro.mac.path.is_ident("assert")
                && let Ok(cond_expr) = syn::parse2::<Expr>(stmt_macro.mac.tokens.clone())
            {
                extract_cond_bounds_guards(&cond_expr, false, block_guards);
            }
        }
        Stmt::Local(_) | Stmt::Item(_) | Stmt::Expr(..) => {}
    }
}

fn block_always_diverges(block: &Block) -> bool {
    let Some(last) = block.stmts.last() else {
        return false;
    };
    match last {
        Stmt::Expr(expr, _) => expr_diverges(expr),
        Stmt::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map_or_else(String::new, |s| s.ident.to_string());
            matches!(name.as_str(), "panic" | "unreachable" | "todo" | "bail")
        }
        Stmt::Local(_) | Stmt::Item(_) => false,
    }
}

fn expr_diverges(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_)
    )
}

fn extract_comment_suppressions(source: &str, lines: &[&str]) -> FileSuppressions {
    let _ = source;
    let mut line_directives = Vec::new();
    let mut block_ranges: Vec<BlockDisableRange> = Vec::new();

    for (idx, &line) in lines.iter().enumerate() {
        let line_num = u32::try_from(idx + 1).unwrap_or(1);
        for comment in extract_comments_on_line(line) {
            let Some((kind, rules)) = parse_disable_comment(comment) else {
                continue;
            };
            match kind {
                DirectiveKind::DisableLine => {
                    line_directives.push(LineDisableDirective {
                        target_line: line_num,
                        rules,
                    });
                }
                DirectiveKind::DisableNextLine => {
                    let target_line = resolve_next_code_line(lines, idx);
                    line_directives.push(LineDisableDirective { target_line, rules });
                }
                DirectiveKind::BlockDisable => {
                    block_ranges.push(BlockDisableRange {
                        start_line: line_num,
                        end_line: u32::MAX,
                        rules,
                    });
                }
                DirectiveKind::BlockEnable => {
                    close_open_block_ranges(&mut block_ranges, line_num);
                }
            }
        }
    }

    FileSuppressions {
        line_directives,
        block_ranges,
    }
}

fn close_open_block_ranges(block_ranges: &mut [BlockDisableRange], line_num: u32) {
    for range in block_ranges {
        if range.end_line == u32::MAX {
            range.end_line = line_num;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectiveKind {
    DisableNextLine,
    DisableLine,
    BlockDisable,
    BlockEnable,
}

fn extract_comments_on_line(line: &str) -> Vec<&str> {
    let mut comments = Vec::new();
    if let Some(pos) = line.find("//") {
        comments.push(line[pos + 2..].trim());
    }
    if let Some(start) = line.find("/*") {
        let after = &line[start + 2..];
        if let Some(end) = after.find("*/") {
            comments.push(after[..end].trim());
        } else {
            comments.push(after.trim());
        }
    }
    comments
}

fn parse_disable_comment(comment: &str) -> Option<(DirectiveKind, Vec<String>)> {
    let trimmed = comment.trim();
    for (prefix, kind) in [
        ("dotore-disable-next-line", DirectiveKind::DisableNextLine),
        ("dotore-disable-line", DirectiveKind::DisableLine),
        ("dotore-disable", DirectiveKind::BlockDisable),
        ("dotore-enable", DirectiveKind::BlockEnable),
    ] {
        if let Some(after) = trimmed.strip_prefix(prefix) {
            if !after.is_empty()
                && !after.starts_with(char::is_whitespace)
                && !after.starts_with(',')
            {
                continue;
            }
            let before_desc = after.split(" -- ").next().unwrap_or(after);
            let rules = before_desc
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "--")
                .map(str::to_string)
                .collect();
            return Some((kind, rules));
        }
    }
    None
}

fn resolve_next_code_line(lines: &[&str], comment_line_idx: usize) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while candidate < lines.len() {
        let text = lines[candidate].trim();
        let is_stacked = extract_comments_on_line(text).into_iter().any(|c| {
            matches!(
                parse_disable_comment(c),
                Some((DirectiveKind::DisableNextLine, _))
            )
        });
        if is_stacked {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}
