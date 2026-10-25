//! Per-file Rust structural and `#[allow]` hygiene AST detectors (`#57`):
//!
//! 1. `rs-structure-crate-level-allow` ([`RuleId::RsStructureCrateLevelAllow`])
//! 2. `rs-structure-unreasoned-allow` ([`RuleId::RsStructureUnreasonedAllow`], `Autofix`)
//! 3. `rs-structure-stacked-allow` ([`RuleId::RsStructureStackedAllow`])
//! 4. `rs-structure-complex-function` ([`RuleId::RsStructureComplexFunction`])
//! 5. `rs-structure-oversized-unit` ([`RuleId::RsStructureOversizedUnit`])

use std::{collections::HashSet, path::Path};

use dotore_core::{AutofixPatch, ByteSpan, FileContext, RuleId, SourceLoc};
use proc_macro2::{TokenStream, TokenTree};
use syn::{
    Arm, AttrStyle, Attribute, BinOp, Block, Expr, ExprBreak, ExprContinue, ExprIf, ExprLit,
    ExprMacro, Field, File, ImplItem, ImplItemFn, Item, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStruct, ItemTrait, Lit, Macro, Stmt, TraitItem, TraitItemFn, Variant,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::{RsCandidateFinding, RsScopeTracker, loc_at, span_to_bytes},
    structure_duplication::{NormalizedFnIr, extract_normalized_functions},
};

/// File line threshold for `rs-structure-oversized-unit`.
pub const FILE_LINES_THRESHOLD: usize = 1_000;
/// `impl` and inline `mod` block line threshold for `rs-structure-oversized-unit`.
pub const BLOCK_LINES_THRESHOLD: usize = 500;
/// Function and method line threshold for `rs-structure-oversized-unit`.
pub const FUNCTION_LINES_THRESHOLD: usize = 150;
/// Cyclomatic complexity threshold for `rs-structure-complex-function`.
pub const CYCLOMATIC_THRESHOLD: u32 = 20;
/// SonarSource cognitive complexity threshold for `rs-structure-complex-function`.
pub const COGNITIVE_THRESHOLD: u32 = 25;

/// An external `mod <name>;` declaration extracted from a `.rs` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalModDeclIr {
    pub name: String,
    pub inline_mod_stack: Vec<String>,
    pub explicit_path: Option<String>,
}

/// A `cfg(feature = "...")` reference site in a `.rs` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CfgFeatureRefIr {
    pub feature: String,
    pub subject_name: Option<String>,
    pub loc: SourceLoc,
    pub span: ByteSpan,
}

/// Per-file structural metadata extracted in a single pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct RsStructureFileIr {
    pub external_mod_decls: Vec<ExternalModDeclIr>,
    pub included_paths: Vec<String>,
    pub scripted_rs_filenames: Vec<String>,
    pub has_macro_mod_decl: bool,
    pub cfg_feature_refs: Vec<CfgFeatureRefIr>,
    pub normalized_functions: Vec<NormalizedFnIr>,
}

/// Extracts per-file structural findings and [`RsStructureFileIr`] from `ast`.
pub(crate) fn extract_structure_findings_and_ir(
    path: &Path,
    ast: &File,
    source: &str,
    line_starts: &[u32],
    file_context: FileContext,
    out: &mut Vec<RsCandidateFinding>,
) -> RsStructureFileIr {
    let mut visitor = StructureAstVisitor {
        path,
        source,
        line_starts,
        file_context,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        inline_mod_stack: Vec::new(),
        seen_unreasoned_spans: HashSet::new(),
        seen_stacked_spans: HashSet::new(),
        external_mod_decls: Vec::new(),
        included_paths: Vec::new(),
        scripted_rs_filenames: Vec::new(),
        has_macro_mod_decl: false,
        cfg_feature_refs: Vec::new(),
    };
    visitor.inspect_file_root(ast);
    visitor.visit_file(ast);

    let normalized_functions = extract_normalized_functions(ast, line_starts);
    RsStructureFileIr {
        external_mod_decls: visitor.external_mod_decls,
        included_paths: visitor.included_paths,
        scripted_rs_filenames: visitor.scripted_rs_filenames,
        has_macro_mod_decl: visitor.has_macro_mod_decl,
        cfg_feature_refs: visitor.cfg_feature_refs,
        normalized_functions,
    }
}

struct AllowReading {
    lints: Vec<String>,
    has_reason: bool,
    is_inner: bool,
}

fn parse_allow_attribute(attr: &Attribute) -> Option<AllowReading> {
    if !attr.path().is_ident("allow") {
        return None;
    }
    let list = attr.meta.require_list().ok()?;
    let args = split_top_level_token_args(list.tokens.clone());
    let has_reason = args.iter().any(|arg| is_reason_arg(arg));
    let mut lints: Vec<String> = args
        .into_iter()
        .filter(|arg| {
            !arg.is_empty()
                && !is_reason_arg(arg)
                && !arg.starts_with("dotore::")
                && arg != "clippy::mod_module_files"
                && arg != "mod_module_files"
        })
        .collect();
    if lints.is_empty() {
        return None;
    }
    lints.sort_unstable();
    lints.dedup();
    Some(AllowReading {
        lints,
        has_reason,
        is_inner: matches!(attr.style, AttrStyle::Inner(_)),
    })
}

fn is_reason_arg(arg: &str) -> bool {
    arg.split_once('=').is_some_and(|(k, v)| {
        k.trim() == "reason" && (v.trim().starts_with('"') || v.trim().starts_with("r\""))
    })
}

fn split_top_level_token_args(tokens: TokenStream) -> Vec<String> {
    let mut args = vec![String::new()];
    for tt in tokens {
        match tt {
            TokenTree::Punct(p) if p.as_char() == ',' => args.push(String::new()),
            TokenTree::Group(g) => {
                if let Some(last) = args.last_mut() {
                    last.push_str(&g.to_string());
                }
            }
            other @ (TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_)) => {
                if let Some(last) = args.last_mut() {
                    let s = other.to_string();
                    if s == "=" && !last.is_empty() {
                        last.push_str(" = ");
                    } else {
                        last.push_str(&s);
                    }
                }
            }
        }
    }
    args.into_iter()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

struct StructureAstVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    file_context: FileContext,
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    inline_mod_stack: Vec<String>,
    seen_unreasoned_spans: HashSet<(u32, u32)>,
    seen_stacked_spans: HashSet<(u32, u32)>,
    external_mod_decls: Vec<ExternalModDeclIr>,
    included_paths: Vec<String>,
    scripted_rs_filenames: Vec<String>,
    has_macro_mod_decl: bool,
    cfg_feature_refs: Vec<CfgFeatureRefIr>,
}

impl StructureAstVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn lines_of_span(&self, span: ByteSpan) -> usize {
        if span.end <= span.start {
            return 1;
        }
        let first = span.start;
        let last = span.end.saturating_sub(1).max(first);
        let start_line = self.loc_at(first).line;
        let end_line = self.loc_at(last).line;
        end_line.saturating_sub(start_line).saturating_add(1) as usize
    }

    fn inspect_file_root(&mut self, file: &File) {
        self.inspect_attrs_on_node(&file.attrs, None);

        if !self.scope.in_test() {
            for attr in &file.attrs {
                if let Some(reading) = parse_allow_attribute(attr)
                    && reading.is_inner
                {
                    let span = self.span_to_bytes(attr.span());
                    let loc = self.loc_at(span.start);
                    let lints = reading.lints.join(", ");
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsStructureCrateLevelAllow,
                        None,
                        format!("#![allow({lints})]"),
                        "rsStructureCrateLevelAllow",
                        format!(
                            "`#![allow({lints})]` suppresses lints across this entire file; use item-scoped `#[expect(..., reason = \"...\")]` instead."
                        ),
                        loc,
                        span,
                    ));
                }
            }
        }

        if !self.scope.in_test()
            && self.file_context == FileContext::Production
            && !self.source.is_empty()
        {
            let last_byte =
                u32::try_from(self.source.trim_end_matches('\n').len().saturating_sub(1))
                    .unwrap_or(0);
            let total_lines = self.loc_at(last_byte).line as usize;
            if total_lines >= FILE_LINES_THRESHOLD {
                let file_label = self.path.to_string_lossy().to_string();
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsStructureOversizedUnit,
                    None,
                    file_label.clone(),
                    "rsStructureOversizedUnit",
                    format!(
                        "File `{file_label}` is {total_lines} lines long (>= {FILE_LINES_THRESHOLD} lines); split it into focused submodules."
                    ),
                    SourceLoc { line: 1, column: 1 },
                    ByteSpan {
                        start: 0,
                        end: u32::try_from(self.source.len()).unwrap_or(0),
                    },
                ));
            }
        }
    }

    fn inspect_attrs_on_node(&mut self, attrs: &[Attribute], inline_mod_name: Option<&str>) {
        for attr in attrs {
            if (attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
                && let Ok(list) = attr.meta.require_list()
            {
                let span = self.span_to_bytes(attr.span());
                let loc = self.loc_at(span.start);
                let mut feats = Vec::new();
                collect_cfg_features_from_tokens(list.tokens.clone(), &mut feats);
                for feat in feats {
                    self.cfg_feature_refs.push(CfgFeatureRefIr {
                        feature: feat,
                        subject_name: self.scope.subject_name(),
                        loc,
                        span,
                    });
                }
            }
        }

        if self.scope.in_test() {
            return;
        }

        let mut outer_allow_count = 0_usize;
        let mut widest_outer_lints = 0_usize;
        let mut all_outer_lints = Vec::new();
        let mut first_outer_span: Option<ByteSpan> = None;

        for attr in attrs {
            let Some(reading) = parse_allow_attribute(attr) else {
                continue;
            };
            let span = self.span_to_bytes(attr.span());
            let loc = self.loc_at(span.start);
            let lints_joined = reading.lints.join(", ");

            if reading.is_inner
                && let Some(mod_name) = inline_mod_name
            {
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsStructureCrateLevelAllow,
                    Some(mod_name.to_string()),
                    format!("#![allow({lints_joined})]"),
                    "rsStructureCrateLevelAllow",
                    format!(
                        "`#![allow({lints_joined})]` covers the entire inline module `{mod_name}`; use item-scoped `#[expect(..., reason = \"...\")]` instead."
                    ),
                    loc,
                    span,
                ));
            }

            if !reading.has_reason && self.seen_unreasoned_spans.insert((span.start, span.end)) {
                let bang = if reading.is_inner { "!" } else { "" };
                let written = format!("#{bang}[allow({lints_joined})]");
                let replacement = format!(
                    "#{bang}[expect({lints_joined}, reason = \"explain lint suppression\")]"
                );
                let patch = AutofixPatch::replace(
                    format!("Replace `{written}` with `{replacement}`"),
                    span,
                    replacement,
                );
                self.findings.push(
                    RsCandidateFinding::new(
                        RuleId::RsStructureUnreasonedAllow,
                        self.scope.subject_name(),
                        written.clone(),
                        "rsStructureUnreasonedAllow",
                        format!(
                            "`{written}` suppresses a lint without a `reason = \"...\"` justification."
                        ),
                        loc,
                        span,
                    )
                    .with_patch(patch),
                );
            }

            if !reading.is_inner {
                outer_allow_count += 1;
                widest_outer_lints = widest_outer_lints.max(reading.lints.len());
                all_outer_lints.extend(reading.lints);
                if first_outer_span.is_none() {
                    first_outer_span = Some(span);
                }
            }
        }

        if (outer_allow_count >= 2 || widest_outer_lints >= 4)
            && let Some(span) = first_outer_span
            && self.seen_stacked_spans.insert((span.start, span.end))
        {
            all_outer_lints.sort_unstable();
            all_outer_lints.dedup();
            let loc = self.loc_at(span.start);
            let lints_joined = all_outer_lints.join(", ");
            let message = if outer_allow_count >= 2 {
                format!(
                    "{outer_allow_count} `#[allow]` attributes stack {} lint suppressions on a single item.",
                    all_outer_lints.len()
                )
            } else {
                format!(
                    "`#[allow({lints_joined})]` stacks {} lint suppressions on a single item.",
                    all_outer_lints.len()
                )
            };
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsStructureStackedAllow,
                self.scope.subject_name(),
                format!("#[allow({lints_joined})]"),
                "rsStructureStackedAllow",
                message,
                loc,
                span,
            ));
        }
    }

    fn inspect_fn_complexity_and_size(&mut self, fn_label: &str, block: &Block, item_span: ByteSpan) {
        if self.scope.in_test() || self.file_context != FileContext::Production {
            return;
        }
        let loc = self.loc_at(item_span.start);
        let lines = self.lines_of_span(item_span);
        if lines >= FUNCTION_LINES_THRESHOLD {
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsStructureOversizedUnit,
                Some(fn_label.to_string()),
                fn_label.to_string(),
                "rsStructureOversizedUnit",
                format!(
                    "Function `{fn_label}` spans {lines} lines (>= {FUNCTION_LINES_THRESHOLD} lines); extract focused helper functions."
                ),
                loc,
                item_span,
            ));
        }

        let (cyclomatic, cognitive) = compute_function_complexity(block);
        if cyclomatic >= CYCLOMATIC_THRESHOLD || cognitive >= COGNITIVE_THRESHOLD {
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsStructureComplexFunction,
                Some(fn_label.to_string()),
                fn_label.to_string(),
                "rsStructureComplexFunction",
                format!(
                    "Function `{fn_label}` reaches cyclomatic complexity {cyclomatic} and cognitive complexity {cognitive}."
                ),
                loc,
                item_span,
            ));
        }
    }

    fn check_macro_for_structure(&mut self, mac: &Macro, span: ByteSpan) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if name == "include" {
            if let Some(first_str) = extract_first_string_literal_from_tokens(mac.tokens.clone()) {
                self.included_paths.push(first_str);
            }
        } else if name == "cfg" {
            let loc = self.loc_at(span.start);
            let mut feats = Vec::new();
            collect_cfg_features_from_tokens(mac.tokens.clone(), &mut feats);
            for feat in feats {
                self.cfg_feature_refs.push(CfgFeatureRefIr {
                    feature: feat,
                    subject_name: self.scope.subject_name(),
                    loc,
                    span,
                });
            }
        }
        if tokens_contain_mod_keyword(mac.tokens.clone()) {
            self.has_macro_mod_decl = true;
        }
    }
}

impl<'ast> Visit<'ast> for StructureAstVisitor<'_> {
    fn visit_item(&mut self, i: &'ast Item) {
        if !matches!(i, Item::Mod(_)) {
            self.inspect_attrs_on_node(item_attrs(i), None);
        }
        visit::visit_item(self, i);
    }

    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        let mod_name = i.ident.to_string();
        if i.content.is_some() {
            self.inspect_attrs_on_node(&i.attrs, Some(&mod_name));
            let span = self.span_to_bytes(i.span());
            if !self.scope.in_test() && self.file_context == FileContext::Production {
                let lines = self.lines_of_span(span);
                if lines >= BLOCK_LINES_THRESHOLD {
                    let loc = self.loc_at(span.start);
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsStructureOversizedUnit,
                        Some(mod_name.clone()),
                        format!("mod {mod_name}"),
                        "rsStructureOversizedUnit",
                        format!(
                            "Inline module `{mod_name}` spans {lines} lines (>= {BLOCK_LINES_THRESHOLD} lines); move it to a dedicated submodule file."
                        ),
                        loc,
                        span,
                    ));
                }
            }
            self.inline_mod_stack.push(mod_name);
            visit::visit_item_mod(self, i);
            self.inline_mod_stack.pop();
        } else {
            self.inspect_attrs_on_node(&i.attrs, None);
            let explicit_path = extract_path_attr_value(&i.attrs);
            self.external_mod_decls.push(ExternalModDeclIr {
                name: mod_name,
                inline_mod_stack: self.inline_mod_stack.clone(),
                explicit_path,
            });
            visit::visit_item_mod(self, i);
        }
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        let span = self.span_to_bytes(i.span());
        if !self.scope.in_test() && self.file_context == FileContext::Production {
            let lines = self.lines_of_span(span);
            if lines >= BLOCK_LINES_THRESHOLD {
                let label = self.scope.subject_name().unwrap_or_else(|| "Impl".to_string());
                let loc = self.loc_at(span.start);
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsStructureOversizedUnit,
                    Some(label.clone()),
                    format!("impl {label}"),
                    "rsStructureOversizedUnit",
                    format!(
                        "Impl block `{label}` spans {lines} lines (>= {BLOCK_LINES_THRESHOLD} lines); split cohesive method groups into separate `impl` blocks."
                    ),
                    loc,
                    span,
                ));
            }
        }
        for item in &i.items {
            self.inspect_attrs_on_node(impl_item_attrs(item), None);
        }
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        let snap = self.scope.enter_trait(i);
        for item in &i.items {
            self.inspect_attrs_on_node(trait_item_attrs(item), None);
        }
        visit::visit_item_trait(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        for field in &i.fields {
            self.inspect_attrs_on_node(&field.attrs, None);
        }
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        for variant in &i.variants {
            self.inspect_attrs_on_node(&variant.attrs, None);
        }
        visit::visit_item_enum(self, i);
    }

    fn visit_field(&mut self, i: &'ast Field) {
        self.inspect_attrs_on_node(&i.attrs, None);
        visit::visit_field(self, i);
    }

    fn visit_variant(&mut self, i: &'ast Variant) {
        self.inspect_attrs_on_node(&i.attrs, None);
        visit::visit_variant(self, i);
    }

    fn visit_arm(&mut self, i: &'ast Arm) {
        self.inspect_attrs_on_node(&i.attrs, None);
        visit::visit_arm(self, i);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let label = self.scope.subject_name().unwrap_or_else(|| i.sig.ident.to_string());
        let span = self.span_to_bytes(i.span());
        self.inspect_fn_complexity_and_size(&label, &i.block, span);
        visit::visit_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let label = self.scope.subject_name().unwrap_or_else(|| i.sig.ident.to_string());
        let span = self.span_to_bytes(i.span());
        self.inspect_fn_complexity_and_size(&label, &i.block, span);
        visit::visit_impl_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        if let Some(block) = &i.default {
            let label = self.scope.subject_name().unwrap_or_else(|| i.sig.ident.to_string());
            let span = self.span_to_bytes(i.span());
            self.inspect_fn_complexity_and_size(&label, block, span);
        }
        visit::visit_trait_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        match s {
            Stmt::Local(local) => self.inspect_attrs_on_node(&local.attrs, None),
            Stmt::Macro(stmt_mac) => {
                self.inspect_attrs_on_node(&stmt_mac.attrs, None);
                let span = self.span_to_bytes(stmt_mac.span());
                self.check_macro_for_structure(&stmt_mac.mac, span);
            }
            Stmt::Item(_) | Stmt::Expr(_, _) => {}
        }
        visit::visit_stmt(self, s);
    }

    fn visit_expr_macro(&mut self, i: &'ast ExprMacro) {
        self.inspect_attrs_on_node(&i.attrs, None);
        let span = self.span_to_bytes(i.span());
        self.check_macro_for_structure(&i.mac, span);
        visit::visit_expr_macro(self, i);
    }

    fn visit_lit(&mut self, i: &'ast Lit) {
        if self.path.file_name().and_then(|n| n.to_str()) == Some("build.rs")
            && let Lit::Str(lit_str) = i
        {
            let val = lit_str.value();
            if val.ends_with(".rs")
                && let Some(fname) = Path::new(&val).file_name().and_then(|n| n.to_str())
            {
                self.scripted_rs_filenames.push(fname.to_string());
            }
        }
        visit::visit_lit(self, i);
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    #[expect(clippy::wildcard_enum_match_arm, reason = "syn::Item is non-exhaustive")]
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    #[expect(clippy::wildcard_enum_match_arm, reason = "syn::ImplItem is non-exhaustive")]
    match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    #[expect(clippy::wildcard_enum_match_arm, reason = "syn::TraitItem is non-exhaustive")]
    match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

fn compute_function_complexity(block: &Block) -> (u32, u32) {
    struct ComplexityWalker {
        cyclomatic: u32,
        cognitive: u32,
        nesting: u32,
    }

    impl ComplexityWalker {
        fn visit_if_chain(&mut self, expr_if: &ExprIf, is_chained_else_if: bool) {
            self.cyclomatic += 1;
            self.cognitive += if is_chained_else_if { 1 } else { 1 + self.nesting };
            self.visit_expr(&expr_if.cond);

            self.nesting += 1;
            self.visit_block(&expr_if.then_branch);
            self.nesting -= 1;

            if let Some((_, else_expr)) = &expr_if.else_branch {
                #[expect(clippy::wildcard_enum_match_arm, reason = "else branch is either If or Block")]
                match else_expr.as_ref() {
                    Expr::If(chained_if) => self.visit_if_chain(chained_if, true),
                    Expr::Block(else_block) => {
                        self.cognitive += 1;
                        self.nesting += 1;
                        self.visit_block(&else_block.block);
                        self.nesting -= 1;
                    }
                    other => {
                        self.nesting += 1;
                        self.visit_expr(other);
                        self.nesting -= 1;
                    }
                }
            }
        }

        fn visit_logical_bin(&mut self, bin: &syn::ExprBinary, parent_op: Option<bool>) {
            #[expect(clippy::wildcard_enum_match_arm, reason = "only And and Or are logical boolean operators")]
            let is_and_or = match bin.op {
                BinOp::And(_) => Some(true),
                BinOp::Or(_) => Some(false),
                _ => None,
            };
            if let Some(cur_op) = is_and_or {
                self.cyclomatic += 1;
                if parent_op != Some(cur_op) {
                    self.cognitive += 1;
                }
                if let Expr::Binary(left_bin) = strip_parens(&bin.left) {
                    self.visit_logical_bin(left_bin, Some(cur_op));
                } else {
                    self.visit_expr(&bin.left);
                }
                if let Expr::Binary(right_bin) = strip_parens(&bin.right) {
                    self.visit_logical_bin(right_bin, Some(cur_op));
                } else {
                    self.visit_expr(&bin.right);
                }
            } else {
                self.visit_expr(&bin.left);
                self.visit_expr(&bin.right);
            }
        }

        fn visit_match_arm_for_complexity(&mut self, arm: &Arm) {
            self.cyclomatic += 1;
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
        }
    }

    impl<'ast> Visit<'ast> for ComplexityWalker {
        fn visit_item_fn(&mut self, _i: &'ast ItemFn) {}

        fn visit_expr(&mut self, i: &'ast Expr) {
            #[expect(
                clippy::wildcard_enum_match_arm,
                reason = "Complexity walker handles branches, loops, closures, ?, and jumps"
            )]
            match i {
                Expr::If(expr_if) => self.visit_if_chain(expr_if, false),
                Expr::Match(expr_match) => {
                    self.cognitive += 1 + self.nesting;
                    self.visit_expr(&expr_match.expr);
                    self.nesting += 1;
                    for arm in &expr_match.arms {
                        self.visit_match_arm_for_complexity(arm);
                    }
                    self.nesting -= 1;
                }
                Expr::ForLoop(fl) => {
                    self.cyclomatic += 1;
                    self.cognitive += 1 + self.nesting;
                    self.visit_expr(&fl.expr);
                    self.nesting += 1;
                    self.visit_block(&fl.body);
                    self.nesting -= 1;
                }
                Expr::While(w) => {
                    self.cyclomatic += 1;
                    self.cognitive += 1 + self.nesting;
                    self.visit_expr(&w.cond);
                    self.nesting += 1;
                    self.visit_block(&w.body);
                    self.nesting -= 1;
                }
                Expr::Loop(l) => {
                    self.cyclomatic += 1;
                    self.cognitive += 1 + self.nesting;
                    self.nesting += 1;
                    self.visit_block(&l.body);
                    self.nesting -= 1;
                }
                Expr::Closure(c) => {
                    self.nesting += 1;
                    self.visit_expr(&c.body);
                    self.nesting -= 1;
                }
                Expr::Binary(bin) => self.visit_logical_bin(bin, None),
                Expr::Try(t) => {
                    self.cyclomatic += 1;
                    self.visit_expr(&t.expr);
                }
                Expr::Break(ExprBreak { label, expr, .. }) => {
                    if label.is_some() {
                        self.cognitive += 1;
                    }
                    if let Some(e) = expr {
                        self.visit_expr(e);
                    }
                }
                Expr::Continue(ExprContinue { label, .. }) => {
                    if label.is_some() {
                        self.cognitive += 1;
                    }
                }
                _ => visit::visit_expr(self, i),
            }
        }
    }

    let mut walker = ComplexityWalker {
        cyclomatic: 1,
        cognitive: 0,
        nesting: 0,
    };
    walker.visit_block(block);
    (walker.cyclomatic, walker.cognitive)
}

fn strip_parens(mut expr: &Expr) -> &Expr {
    while let Expr::Paren(p) = expr {
        expr = &p.expr;
    }
    expr
}

fn collect_cfg_features_from_tokens(tokens: TokenStream, out: &mut Vec<String>) {
    let flat: Vec<TokenTree> = tokens.into_iter().collect();
    for (idx, tt) in flat.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            collect_cfg_features_from_tokens(g.stream(), out);
            continue;
        }
        if let TokenTree::Ident(id) = tt
            && id == "feature"
            && let Some(TokenTree::Punct(p)) = flat.get(idx + 1)
            && p.as_char() == '='
            && let Some(TokenTree::Literal(lit)) = flat.get(idx + 2)
            && let Ok(lit_str) = syn::parse_str::<syn::LitStr>(&lit.to_string())
        {
            out.push(lit_str.value());
        }
    }
}

fn extract_first_string_literal_from_tokens(tokens: TokenStream) -> Option<String> {
    for tt in tokens {
        match tt {
            TokenTree::Literal(lit) => {
                if let Ok(lit_str) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                    return Some(lit_str.value());
                }
            }
            TokenTree::Group(g) => {
                if let Some(s) = extract_first_string_literal_from_tokens(g.stream()) {
                    return Some(s);
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
    None
}

fn tokens_contain_mod_keyword(tokens: TokenStream) -> bool {
    for tt in tokens {
        match tt {
            TokenTree::Ident(id) if id == "mod" => return true,
            TokenTree::Group(g) if tokens_contain_mod_keyword(g.stream()) => return true,
            TokenTree::Group(_) | TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
    false
}

fn extract_path_attr_value(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("path")
            && let syn::Meta::NameValue(nv) = &attr.meta
            && let Expr::Lit(ExprLit {
                lit: Lit::Str(lit_str),
                ..
            }) = &nv.value
        {
            return Some(lit_str.value());
        }
        if attr.path().is_ident("cfg_attr")
            && let Ok(list) = attr.meta.require_list()
            && let Some(val) = extract_cfg_attr_path_tokens(&list.tokens)
        {
            return Some(val);
        }
    }
    None
}

fn extract_cfg_attr_path_tokens(tokens: &TokenStream) -> Option<String> {
    let flat: Vec<TokenTree> = tokens.clone().into_iter().collect();
    for (idx, tt) in flat.iter().enumerate() {
        if let TokenTree::Ident(id) = tt
            && id == "path"
            && let Some(TokenTree::Punct(p)) = flat.get(idx + 1)
            && p.as_char() == '='
            && let Some(TokenTree::Literal(lit)) = flat.get(idx + 2)
            && let Ok(lit_str) = syn::parse_str::<syn::LitStr>(&lit.to_string())
        {
            return Some(lit_str.value());
        }
    }
    None
}
