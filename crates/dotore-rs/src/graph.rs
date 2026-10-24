//! Crate-level `ProjectGraph` analysis for `dotore-rs` (`rs-arch-no-unused-pub-crate-items`,
//! `rs-arch-prefer-pub-crate-modules`, and `rs-arch-no-legacy-mod-rs`).

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use dotore_core::{ByteSpan, ExtractedFile, FileContext, RuleId, SourceLoc};
use syn::{
    Attribute, Expr, File, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic,
    ItemStruct, ItemTrait, ItemType, ItemUse, Lit, UseTree, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, attrs_indicate_test_context, is_pub,
    is_pub_crate_visibility, loc_at, span_to_bytes,
};
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

/// An external `pub mod <name>;` declaration extracted from a Rust file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PubModDeclIr {
    /// Submodule identifier (`<name>` in `pub mod <name>;`).
    pub name: String,
    /// Whether the `pub mod <name>;` declaration carries an explicit `///` / `#[doc = ...]` attribute.
    pub has_doc_comment: bool,
    /// 1-based source location of the `pub mod <name>;` declaration.
    pub loc: SourceLoc,
    /// 0-based byte span of the `pub mod <name>;` declaration.
    pub span: ByteSpan,
}

/// Per-file crate graph metadata extracted in a single pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct RsFileGraphIr {
    /// All non-test `pub(crate)` items declared in this file.
    pub pub_crate_items: Vec<PubCrateItemIr>,
    /// All non-test external `pub mod <name>;` declarations in this file.
    pub pub_mod_decls: Vec<PubModDeclIr>,
    /// Top-level `pub` item names (`fn`, `struct`, `enum`, `trait`, `type`, `const`, `static`) declared in this file.
    pub pub_item_names: HashSet<String>,
    /// Module names and item names re-exported via `pub use <mod>::...` at the root of this file.
    pub pub_use_reexports: HashMap<String, HashSet<String>>,
    /// Location and byte span at the top of the file (first item or first line) for file-level layout rules.
    pub top_file_site: Option<(SourceLoc, ByteSpan)>,
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
        scope: RsScopeTracker::for_file(ast),
        pub_crate_items: Vec::new(),
        pub_mod_decls: Vec::new(),
        pub_item_names: HashSet::new(),
        pub_use_reexports: HashMap::new(),
    };
    visitor.visit_file(ast);

    let referenced_idents = tokenize_identifiers_in_range(source, 0, source.len());
    let root_referenced_idents = collect_non_inline_mod_identifiers(ast, source);
    let top_file_site = Some(compute_top_file_site(ast, source, line_starts));

    RsFileGraphIr {
        pub_crate_items: visitor.pub_crate_items,
        pub_mod_decls: visitor.pub_mod_decls,
        pub_item_names: visitor.pub_item_names,
        pub_use_reexports: visitor.pub_use_reexports,
        top_file_site,
        referenced_idents,
        root_referenced_idents,
    }
}

/// Evaluates crate-level module graph and layout rules (`rs-arch-no-unused-pub-crate-items`,
/// `rs-arch-prefer-pub-crate-modules`, and `rs-arch-no-legacy-mod-rs`) across all extracted files in a Rust package.
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

        if let Some(mod_rs_finding) = check_legacy_mod_rs_file(&file.path, graph_ir) {
            out.push((file.path.clone(), mod_rs_finding));
        }

        collect_prefer_pub_crate_module_findings(
            file,
            graph_ir,
            &file_graphs,
            multi_file,
            &mut out,
        );

        for item in &graph_ir.pub_crate_items {
            let used_in_other_file =
                file_graphs
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
            } else if !is_ident_referenced_outside_span(&file.source, &item.name, item.span) {
                out.push((file.path.clone(), build_unused_pub_crate_finding(item)));
            }
        }
    }

    out
}

fn check_legacy_mod_rs_file(path: &Path, graph_ir: &RsFileGraphIr) -> Option<RsCandidateFinding> {
    let path_str = path.to_string_lossy();
    if !path_str.ends_with("/mod.rs") && !path_str.ends_with("\\mod.rs") {
        return None;
    }
    let dir_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("module");
    let (loc, span) = graph_ir
        .top_file_site
        .unwrap_or((SourceLoc { line: 1, column: 1 }, ByteSpan::default()));
    Some(RsCandidateFinding::new(
        RuleId::RsArchNoLegacyModRs,
        Some(dir_name.to_string()),
        format!("{dir_name}/mod.rs"),
        "rsArchNoLegacyModRs",
        format!(
            "Legacy `{dir_name}/mod.rs` module layout used; replace `{dir_name}/mod.rs` with `{dir_name}.rs` + `{dir_name}/<sub.rs>` (Rust 2018+ module layout)."
        ),
        loc,
        span,
    ))
}

fn collect_prefer_pub_crate_module_findings(
    file: &ExtractedFile,
    graph_ir: &RsFileGraphIr,
    file_graphs: &[(&ExtractedFile, &RsFileGraphIr)],
    multi_file: bool,
    out: &mut Vec<(PathBuf, RsCandidateFinding)>,
) {
    let is_main_rs = file.path.file_name().and_then(|n| n.to_str()) == Some("main.rs");

    for decl in &graph_ir.pub_mod_decls {
        if is_main_rs {
            out.push((
                file.path.clone(),
                RsCandidateFinding::new(
                    RuleId::RsArchPreferPubCrateModules,
                    Some(decl.name.clone()),
                    decl.name.clone(),
                    "rsArchPreferPubCrateModules",
                    format!(
                        "`pub mod {}` in binary entrypoint `main.rs` leaks internal module hierarchy; use `pub(crate) mod {};` or private `mod {};` instead.",
                        decl.name, decl.name, decl.name
                    ),
                    decl.loc,
                    decl.span,
                ),
            ));
            continue;
        }

        if decl.has_doc_comment {
            continue;
        }

        let Some(reexported_items) = graph_ir.pub_use_reexports.get(&decl.name) else {
            continue;
        };
        if reexported_items.is_empty() {
            continue;
        }

        let should_flag = if multi_file {
            if let Some(target_graph) =
                resolve_child_module_graph(&file.path, &decl.name, file_graphs)
            {
                target_graph.pub_mod_decls.is_empty()
                    && !target_graph.pub_item_names.is_empty()
                    && (reexported_items.contains("*")
                        || target_graph
                            .pub_item_names
                            .iter()
                            .any(|item| reexported_items.contains(item)))
            } else {
                false
            }
        } else {
            true
        };

        if should_flag {
            out.push((
                file.path.clone(),
                RsCandidateFinding::new(
                    RuleId::RsArchPreferPubCrateModules,
                    Some(decl.name.clone()),
                    decl.name.clone(),
                    "rsArchPreferPubCrateModules",
                    format!(
                        "`pub mod {}` unnecessarily exposes an internal module whose public API is already re-exported via `pub use {}::...`; narrow visibility to `pub(crate) mod {};` (or private `mod {};`) or add a `///` doc comment if `{}` is an intentional public namespace.",
                        decl.name, decl.name, decl.name, decl.name, decl.name
                    ),
                    decl.loc,
                    decl.span,
                ),
            ));
        }
    }
}

fn resolve_child_module_graph<'a>(
    decl_path: &Path,
    mod_name: &str,
    file_graphs: &[(&'a ExtractedFile, &'a RsFileGraphIr)],
) -> Option<&'a RsFileGraphIr> {
    let decl_dir = decl_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = decl_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    let candidates: Vec<PathBuf> = if matches!(stem, "lib" | "main" | "mod") {
        vec![
            decl_dir.join(format!("{mod_name}.rs")),
            decl_dir.join(mod_name).join("mod.rs"),
        ]
    } else {
        vec![
            decl_dir.join(stem).join(format!("{mod_name}.rs")),
            decl_dir.join(stem).join(mod_name).join("mod.rs"),
            decl_dir.join(format!("{mod_name}.rs")),
        ]
    };

    for candidate in &candidates {
        if let Some((_, graph)) = file_graphs.iter().find(|(f, _)| &f.path == candidate) {
            return Some(graph);
        }
    }

    let mod_rs_suffix_slash = format!("/{mod_name}/mod.rs");
    let mod_rs_suffix_backslash = format!("\\{mod_name}\\mod.rs");
    file_graphs.iter().find_map(|(f, graph)| {
        if f.path == decl_path {
            return None;
        }
        let f_stem = f.path.file_stem().and_then(|s| s.to_str());
        let path_str = f.path.to_string_lossy();
        if f_stem == Some(mod_name)
            || path_str.ends_with(&mod_rs_suffix_slash)
            || path_str.ends_with(&mod_rs_suffix_backslash)
        {
            Some(*graph)
        } else {
            None
        }
    })
}

fn compute_top_file_site(ast: &File, source: &str, line_starts: &[u32]) -> (SourceLoc, ByteSpan) {
    if let Some(first_item) = ast.items.first() {
        let item_span = span_to_bytes(first_item.span());
        let loc = loc_at(line_starts, item_span.start);
        return (
            loc,
            ByteSpan {
                start: 0,
                end: item_span.end,
            },
        );
    }
    let first_line_end = u32::try_from(source.lines().next().map_or(0, str::len)).unwrap_or(0);
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan {
            start: 0,
            end: first_line_end,
        },
    )
}

fn build_unused_pub_crate_finding(item: &PubCrateItemIr) -> RsCandidateFinding {
    RsCandidateFinding::new(
        RuleId::RsArchNoUnusedPubCrateItems,
        item.subject_name
            .clone()
            .or_else(|| Some(item.name.clone())),
        item.name.clone(),
        "rsArchNoUnusedPubCrateItems",
        format!(
            "`pub(crate) {} {}` is never referenced or imported by any other module in the crate; remove it or narrow its visibility to private.",
            item.kind_label, item.name
        ),
        item.loc,
        item.span,
    )
}

fn is_ident_referenced_outside_span(source: &str, ident: &str, item_span: ByteSpan) -> bool {
    let start = usize::try_from(item_span.start)
        .unwrap_or(0)
        .min(source.len());
    let end = usize::try_from(item_span.end)
        .unwrap_or(start)
        .min(source.len());
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
    scope: RsScopeTracker,
    pub_crate_items: Vec<PubCrateItemIr>,
    pub_mod_decls: Vec<PubModDeclIr>,
    pub_item_names: HashSet<String>,
    pub_use_reexports: HashMap<String, HashSet<String>>,
}

impl GraphIrExtractor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn record_if_pub_crate(
        &mut self,
        vis: &Visibility,
        ident: &syn::Ident,
        item_span: proc_macro2::Span,
        kind_label: &'static str,
        subject_override: Option<String>,
    ) {
        if self.scope.in_test() || !is_pub_crate_visibility(vis) {
            return;
        }
        let span = self.span_to_bytes(item_span);
        let ident_span = self.span_to_bytes(ident.span());
        let loc = self.loc_at(ident_span.start);
        let name = ident.to_string();
        self.pub_crate_items.push(PubCrateItemIr {
            subject_name: subject_override
                .or_else(|| self.scope.subject_name())
                .or_else(|| Some(name.clone())),
            name,
            kind_label,
            inline_module: self.scope.current_inline_module.clone(),
            loc,
            span,
        });
    }

    fn record_if_pub_item(&mut self, vis: &Visibility, attrs: &[Attribute], ident: &syn::Ident) {
        if self.scope.in_test()
            || self.scope.current_inline_module.is_some()
            || attrs_indicate_test_context(attrs)
            || !is_pub(vis)
        {
            return;
        }
        self.pub_item_names.insert(ident.to_string());
    }
}

fn has_doc_attribute(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("doc") {
            return false;
        }
        match &attr.meta {
            syn::Meta::NameValue(nv) => {
                if let Expr::Lit(expr_lit) = &nv.value
                    && let Lit::Str(lit_str) = &expr_lit.lit
                {
                    !lit_str.value().trim().is_empty()
                } else {
                    false
                }
            }
            syn::Meta::List(_) => true,
            syn::Meta::Path(_) => false,
        }
    })
}

fn collect_pub_use_tree(
    tree: &UseTree,
    prefix: &[String],
    reexports: &mut HashMap<String, HashSet<String>>,
) {
    match tree {
        UseTree::Path(use_path) => {
            let ident = use_path.ident.to_string();
            if prefix.is_empty() && matches!(ident.as_str(), "self" | "crate") {
                collect_pub_use_tree(&use_path.tree, prefix, reexports);
            } else {
                let mut next_prefix = prefix.to_vec();
                next_prefix.push(ident);
                collect_pub_use_tree(&use_path.tree, &next_prefix, reexports);
            }
        }
        UseTree::Name(use_name) => {
            let Some(first_mod) = prefix.first() else {
                return;
            };
            let item_ident = use_name.ident.to_string();
            if item_ident == "self" {
                return;
            }
            let exported_item = if prefix.len() == 1 {
                item_ident
            } else {
                prefix[1].clone()
            };
            reexports
                .entry(first_mod.clone())
                .or_default()
                .insert(exported_item);
        }
        UseTree::Rename(use_rename) => {
            let Some(first_mod) = prefix.first() else {
                return;
            };
            let orig_ident = use_rename.ident.to_string();
            if orig_ident == "self" {
                return;
            }
            let exported_item = if prefix.len() == 1 {
                orig_ident
            } else {
                prefix[1].clone()
            };
            reexports
                .entry(first_mod.clone())
                .or_default()
                .insert(exported_item);
        }
        UseTree::Glob(_) => {
            if let Some(first_mod) = prefix.first() {
                reexports
                    .entry(first_mod.clone())
                    .or_default()
                    .insert("*".to_string());
            }
        }
        UseTree::Group(use_group) => {
            for item in &use_group.items {
                collect_pub_use_tree(item, prefix, reexports);
            }
        }
    }
}

impl<'ast> Visit<'ast> for GraphIrExtractor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        if !self.scope.in_test()
            && self.scope.current_inline_module.is_none()
            && !attrs_indicate_test_context(&i.attrs)
            && i.ident != "tests"
            && i.content.is_none()
            && is_pub(&i.vis)
        {
            let item_span = self.span_to_bytes(i.span());
            let vis_span = self.span_to_bytes(i.vis.span());
            let decl_start = if vis_span.start > 0 {
                vis_span.start
            } else {
                item_span.start
            };
            let loc = self.loc_at(decl_start);
            let span = ByteSpan {
                start: decl_start,
                end: item_span.end,
            };
            self.pub_mod_decls.push(PubModDeclIr {
                name: i.ident.to_string(),
                has_doc_comment: has_doc_attribute(&i.attrs),
                loc,
                span,
            });
        }
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_use(&mut self, i: &'ast ItemUse) {
        if !self.scope.in_test()
            && self.scope.current_inline_module.is_none()
            && !attrs_indicate_test_context(&i.attrs)
            && is_pub(&i.vis)
        {
            collect_pub_use_tree(&i.tree, &[], &mut self.pub_use_reexports);
        }
        visit::visit_item_use(self, i);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_test = self.scope.in_test_context;
        self.scope.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        let fn_name = i.sig.ident.to_string();
        self.record_if_pub_item(&i.vis, &i.attrs, &i.sig.ident);
        self.record_if_pub_crate(&i.vis, &i.sig.ident, i.span(), "fn", Some(fn_name.clone()));
        let prev_subj = self.scope.current_subject_name.replace(fn_name);
        visit::visit_item_fn(self, i);
        self.scope.current_subject_name = prev_subj;
        self.scope.in_test_context = prev_test;
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        self.record_if_pub_item(&i.vis, &i.attrs, &i.ident);
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
        let prev_test = self.scope.in_test_context;
        self.scope.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        visit::visit_item_impl(self, i);
        self.scope.in_test_context = prev_test;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let prev_test = self.scope.in_test_context;
        self.scope.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);
        self.record_if_pub_crate(
            &i.vis,
            &i.sig.ident,
            i.span(),
            "fn",
            Some(i.sig.ident.to_string()),
        );
        visit::visit_impl_item_fn(self, i);
        self.scope.in_test_context = prev_test;
    }
}
