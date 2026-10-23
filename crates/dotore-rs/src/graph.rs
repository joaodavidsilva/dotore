//! Crate-level `ProjectGraph` analysis for `dotore-rs` (`rs-arch-no-unused-pub-crate-items`).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use dotore_core::{ByteSpan, ExtractedFile, FileContext, RuleId, SourceLoc, loc_from_line_starts};
use syn::{
    File, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemStruct,
    ItemTrait, ItemType, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::ir::{RsCandidateFinding, attrs_indicate_test_context, span_to_bytes};

/// A `pub(crate)` item extracted from a Rust file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PubCrateItemIr {
    /// Item name (`fn`, `struct`, `enum`, `trait`, `const`, `static`, `type`).
    pub name: String,
    /// Kind label (`"fn"`, `"struct"`, `"enum"`, `"trait"`, `"const"`, `"static"`, `"type"`).
    pub kind_label: &'static str,
    /// Enclosing subject or module name, if any.
    pub subject_name: Option<String>,
    /// Inline module path inside the file (`None` if at file root).
    pub inline_module: Option<String>,
    /// 1-based source location of the item identifier.
    pub loc: SourceLoc,
    /// 0-based byte span of the item.
    pub span: ByteSpan,
}

/// Per-file crate graph metadata extracted in a single pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct RsFileGraphIr {
    /// All non-test `pub(crate)` items declared in this file.
    pub pub_crate_items: Vec<PubCrateItemIr>,
    /// All identifier tokens referenced in this file outside each item's own declaration.
    pub referenced_idents: HashSet<String>,
    /// Identifier tokens referenced at the root of this file (outside inline submodules).
    pub root_referenced_idents: HashSet<String>,
}

/// Extracts [`RsFileGraphIr`] from a parsed `syn::File`.
#[must_use]
pub(crate) fn extract_file_graph_ir(
    ast: &File,
    source: &str,
    line_starts: &[u32],
) -> RsFileGraphIr {
    let mut visitor = GraphIrExtractor {
        line_starts,
        in_test_context: false,
        current_subject_name: None,
        current_inline_module: None,
        pub_crate_items: Vec::new(),
    };
    visitor.visit_file(ast);

    let referenced_idents = tokenize_identifiers_in_range(source, 0, source.len());
    let root_referenced_idents = collect_non_inline_mod_identifiers(ast, source);

    RsFileGraphIr {
        pub_crate_items: visitor.pub_crate_items,
        referenced_idents,
        root_referenced_idents,
    }
}

/// Evaluates `rs-arch-no-unused-pub-crate-items` across all extracted files in a Rust package.
#[must_use]
pub(crate) fn collect_unused_pub_crate_findings_for_package(
    files: &[ExtractedFile],
) -> Vec<(PathBuf, RsCandidateFinding)> {
    let mut out = Vec::new();
    let multi_file = files.len() > 1;

    let file_graphs: Vec<(&ExtractedFile, &RsFileGraphIr)> = files
        .iter()
        .filter_map(|f| {
            let ir = f.downcast_payload::<crate::ir::RsFileIr>()?;
            Some((f, &ir.graph_ir))
        })
        .collect();

    for (file_idx, (file, graph_ir)) in file_graphs.iter().enumerate() {
        if file.file_context != FileContext::Production {
            continue;
        }
        let is_entrypoint = is_crate_entrypoint_path(&file.path);

        for item in &graph_ir.pub_crate_items {
            let used_in_other_file = file_graphs
                .iter()
                .enumerate()
                .any(|(other_idx, (_, other_graph))| {
                    other_idx != file_idx && other_graph.referenced_idents.contains(&item.name)
                });

            if used_in_other_file {
                continue;
            }

            if item.inline_module.is_some() {
                if !graph_ir.root_referenced_idents.contains(&item.name)
                    && !is_ident_referenced_outside_span(&file.source, &item.name, item.span)
                {
                    out.push((file.path.clone(), build_unused_pub_crate_finding(item)));
                }
            } else if multi_file
                || !is_entrypoint
                || !is_ident_referenced_outside_span(&file.source, &item.name, item.span)
            {
                out.push((file.path.clone(), build_unused_pub_crate_finding(item)));
            }
        }
    }

    out
}

fn build_unused_pub_crate_finding(item: &PubCrateItemIr) -> RsCandidateFinding {
    RsCandidateFinding {
        rule: RuleId::RsArchNoUnusedPubCrateItems,
        subject_name: item
            .subject_name
            .clone()
            .or_else(|| Some(item.name.clone())),
        target_name: item.name.clone(),
        message_id: "rsArchNoUnusedPubCrateItems",
        message: format!(
            "`pub(crate) {} {}` is never referenced or imported by any other module in the crate; remove it or narrow its visibility to private.",
            item.kind_label, item.name
        ),
        loc: item.loc,
        span: item.span,
        autofix: None,
    }
}

fn is_crate_entrypoint_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("lib.rs" | "main.rs")
    )
}

fn is_ident_referenced_outside_span(source: &str, ident: &str, item_span: ByteSpan) -> bool {
    let start = usize::try_from(item_span.start).unwrap_or(0).min(source.len());
    let end = usize::try_from(item_span.end).unwrap_or(start).min(source.len());
    let before = tokenize_identifiers_in_range(source, 0, start);
    if before.contains(ident) {
        return true;
    }
    let after = tokenize_identifiers_in_range(source, end, source.len());
    after.contains(ident)
}

fn collect_non_inline_mod_identifiers(ast: &File, source: &str) -> HashSet<String> {
    let mut mod_ranges = Vec::new();
    for item in &ast.items {
        if let syn::Item::Mod(m) = item
            && m.content.is_some()
        {
            let r = m.span().byte_range();
            mod_ranges.push((r.start, r.end));
        }
    }
    let mut idents = HashSet::new();
    let mut cursor = 0usize;
    for (start, end) in mod_ranges {
        if start > cursor {
            idents.extend(tokenize_identifiers_in_range(source, cursor, start));
        }
        cursor = cursor.max(end);
    }
    if cursor < source.len() {
        idents.extend(tokenize_identifiers_in_range(source, cursor, source.len()));
    }
    idents
}

fn tokenize_identifiers_in_range(source: &str, start: usize, end: usize) -> HashSet<String> {
    let mut out = HashSet::new();
    let slice = source.get(start..end).unwrap_or("");
    for line in slice.lines() {
        let code_part = line.split("//").next().unwrap_or(line);
        for token in code_part.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if !token.is_empty()
                && token
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                out.insert(token.to_string());
            }
        }
    }
    out
}

struct GraphIrExtractor<'a> {
    line_starts: &'a [u32],
    in_test_context: bool,
    current_subject_name: Option<String>,
    current_inline_module: Option<String>,
    pub_crate_items: Vec<PubCrateItemIr>,
}

impl GraphIrExtractor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_from_line_starts(self.line_starts, byte_offset)
    }

    fn record_if_pub_crate(
        &mut self,
        vis: &Visibility,
        ident: &syn::Ident,
        item_span: proc_macro2::Span,
        kind_label: &'static str,
        subject_override: Option<String>,
    ) {
        if self.in_test_context || !is_pub_crate_visibility(vis) {
            return;
        }
        let span = self.span_to_bytes(item_span);
        let ident_span = self.span_to_bytes(ident.span());
        let loc = self.loc_at(ident_span.start);
        let name = ident.to_string();
        self.pub_crate_items.push(PubCrateItemIr {
            subject_name: subject_override
                .or_else(|| self.current_subject_name.clone())
                .or_else(|| Some(name.clone())),
            name,
            kind_label,
            inline_module: self.current_inline_module.clone(),
            loc,
            span,
        });
    }
}

impl<'ast> Visit<'ast> for GraphIrExtractor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let prev_test = self.in_test_context;
        self.in_test_context =
            prev_test || attrs_indicate_test_context(&i.attrs) || i.ident == "tests";
        let mod_name = i.ident.to_string();
        let prev_mod = self.current_inline_module.replace(mod_name.clone());
        let prev_subj = self.current_subject_name.replace(mod_name);
        visit::visit_item_mod(self, i);
        self.current_subject_name = prev_subj;
        self.current_inline_module = prev_mod;
        self.in_test_context = prev_test;
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        let fn_name = i.sig.ident.to_string();
        self.record_if_pub_crate(&i.vis, &i.sig.ident, i.span(), "fn", Some(fn_name.clone()));
        let prev_subj = self.current_subject_name.replace(fn_name);
        visit::visit_item_fn(self, i);
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "struct",
            Some(i.ident.to_string()),
        );
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "enum",
            Some(i.ident.to_string()),
        );
        visit::visit_item_enum(self, i);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "trait",
            Some(i.ident.to_string()),
        );
        visit::visit_item_trait(self, i);
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "const",
            Some(i.ident.to_string()),
        );
        visit::visit_item_const(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "static",
            Some(i.ident.to_string()),
        );
        visit::visit_item_static(self, i);
    }

    fn visit_item_type(&mut self, i: &'ast ItemType) {
        self.record_if_pub_crate(
            &i.vis,
            &i.ident,
            i.span(),
            "type",
            Some(i.ident.to_string()),
        );
        visit::visit_item_type(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        visit::visit_item_impl(self, i);
        self.in_test_context = prev_test;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        self.record_if_pub_crate(
            &i.vis,
            &i.sig.ident,
            i.span(),
            "fn",
            Some(i.sig.ident.to_string()),
        );
        visit::visit_impl_item_fn(self, i);
        self.in_test_context = prev_test;
    }
}

fn is_pub_crate_visibility(vis: &Visibility) -> bool {
    if let Visibility::Restricted(restr) = vis {
        restr.path.is_ident("crate") || restr.path.is_ident("super")
    } else {
        false
    }
}

