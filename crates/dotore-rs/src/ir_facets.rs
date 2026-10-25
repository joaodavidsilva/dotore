//! Single-pass architecture facet extraction (`ArchitectureFileFacets`) and helper AST
//! fingerprinting (`HelperAstHasher`) for Rust (`.rs`) files.

use std::path::Path;

use dotore_core::{
    ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, HelperFingerprintIr,
    InlineTerminalUiPrimitiveSiteIr, SourceLoc, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, TerminalUiPrimitiveKind,
};
use proc_macro2::TokenTree;
use syn::{
    Attribute, BinOp, Block, Expr, ExprBinary, ExprCall, ExprLit, ExprMethodCall, ExprStruct,
    ExprUnary, File, FnArg, ImplItem, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, Lit, LitStr, Macro, Member, Stmt, Type, UnOp, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    ir::compute_helper_fingerprint,
    matchers::{
        RsScopeTracker, extract_pat_ident, extract_type_name, is_pub, loc_at, path_to_string,
        slice_source, span_to_bytes,
    },
};
pub(crate) fn extract_empty_architecture_facets(path: &Path) -> ArchitectureFileFacets {
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
            "ui.rs" | "tui.rs" | "progress.rs" | "terminal.rs" | "theme.rs" | "ansi.rs" | "report.rs" | "terminal_ui.rs"
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

pub(crate) fn extract_architecture_facets(
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
            self.record_terminal_ui_site(TerminalUiPrimitiveKind::BoxDrawing, snippet, loc, span);
            self.push_concern(ConcernBucket::TerminalOrUiPresentation, "box-drawing", span);
        }

        if !self.in_syntax_highlighter_fn
            && let Some(snippet) = detect_ansi_escape_sequence(val)
        {
            self.record_terminal_ui_site(TerminalUiPrimitiveKind::AnsiEscape, snippet, loc, span);
            self.push_concern(ConcernBucket::TerminalOrUiPresentation, "ansi-escape", span);
        }
    }

    fn record_terminal_ui_site(
        &mut self,
        kind: TerminalUiPrimitiveKind,
        snippet: String,
        loc: SourceLoc,
        span: ByteSpan,
    ) {
        if !self
            .facets
            .inline_terminal_ui_sites
            .iter()
            .any(|s| s.span == span && s.kind == kind)
        {
            self.facets
                .inline_terminal_ui_sites
                .push(InlineTerminalUiPrimitiveSiteIr {
                    kind,
                    snippet,
                    loc,
                    span,
                });
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
        if entry_count < 5 || elems.iter().all(is_numeric_or_bool_literal) {
            return;
        }
        let is_private_str_or_tuple_table = matches!(vis, Visibility::Inherited)
            && (elems.iter().all(is_private_dep_capability_tuple)
                || elems
                    .iter()
                    .all(|e| matches!(e, Expr::Lit(ExprLit { lit: Lit::Str(_), .. })))
                || elems
                    .iter()
                    .all(|e| matches!(e, Expr::Path(_))));
        if is_private_str_or_tuple_table {
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
    let idx = val.find("\x1b[")?;
    let rest = &val[idx + 2..];
    if rest.is_empty() {
        return None;
    }
    let end = rest
        .find(|c: char| c.is_ascii_alphabetic())
        .map_or_else(|| rest.len().min(8), |i| (i + 1).min(12));
    Some(format!("\\x1b[{}", &rest[..end]))
}

fn detect_box_drawing_border(val: &str) -> Option<String> {
    if val.chars().count() < 4 {
        return None;
    }
    const BOX_PATTERNS: &[&str] = &[
        "┌─", "╭─", "│ ", "└─", "╰─", "├─", "┤", "──┐", "──╮", "──┘", "──╯", "╔═", "╚═", "╠═",
    ];
    BOX_PATTERNS
        .iter()
        .find(|&&pat| val.contains(pat))
        .map(|&pat| pat.to_string())
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
    if let Some(Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    })) = args.first()
        && s.value() == "/dev/tty"
    {
        return false;
    }
    const IO_PREFIXES: &[&str] = &[
        "sqlx::query",
        "reqwest::",
        "std::fs::",
        "tokio::fs::",
        "std::net::Tcp",
        "tokio::net::Tcp",
    ];
    if IO_PREFIXES.iter().any(|p| callee.starts_with(p)) {
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
        let fname = match &fv.member {
            Member::Named(id) => id.to_string(),
            Member::Unnamed(idx) => idx.index.to_string(),
        };
        if fv.colon_token.is_some() && is_boilerplate_default_expr(&fv.expr) {
            default_or_literal_fields.push(fname.clone());
        }
        field_names.push(fname);
    }
    (field_names, default_or_literal_fields)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Expr has dozens of variants; array extraction only unwraps Array, Reference, Group, and Paren (#50)"
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
    reason = "syn::Expr has dozens of variants; only numeric/boolean literals and unary negations represent scalar numeric values (#50)"
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
        && let (Some(first), Some(second)) = (t.elems.first(), t.elems.get(1))
        && t.elems.len() == 2
    {
        let first_ok = matches!(first, Expr::Lit(ExprLit { lit: Lit::Str(_), .. }))
            || matches!(first, Expr::Reference(r) if matches!(&*r.expr, Expr::Array(_)));
        let second_ok = matches!(second, Expr::Lit(ExprLit { lit: Lit::Str(_), .. }))
            || matches!(second, Expr::Reference(r) if matches!(&*r.expr, Expr::Array(_)));
        first_ok && second_ok
    } else {
        false
    }
}

fn is_default_constructor_call(call: &ExprCall) -> bool {
    let Expr::Path(ep) = &*call.func else {
        return false;
    };
    let callee = path_to_string(&ep.path);
    if call.args.is_empty() {
        return matches!(
            callee.as_str(),
            "Vec::new"
                | "String::new"
                | "Default::default"
                | "HashMap::new"
                | "BTreeMap::new"
                | "HashSet::new"
                | "BTreeSet::new"
        );
    }
    if call.args.len() == 1
        && callee == "String::from"
        && let Some(Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        })) = call.args.first()
    {
        return s.value().is_empty();
    }
    false
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Expr and syn::Lit have many variants; checks common default boilerplate literals and constructors (#50)"
)]
fn is_boilerplate_default_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::Bool(b) => !b.value,
            Lit::Int(i) => i.base10_digits() == "0",
            Lit::Float(f) => matches!(f.base10_digits(), "0" | "0.0"),
            Lit::Str(s) => s.value().is_empty(),
            _ => false,
        },
        Expr::Path(ep) => path_to_string(&ep.path) == "None",
        Expr::Call(call) => is_default_constructor_call(call),
        Expr::MethodCall(mc) => {
            mc.args.is_empty()
                && matches!(mc.method.to_string().as_str(), "to_string" | "to_owned")
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

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::Type has many variants; normalizes Reference, Slice, Path, and Tuple signatures (#50)"
)]
pub(crate) fn normalize_type_signature(ty: &Type) -> String {
    match ty {
        Type::Reference(r) => {
            let mut_prefix = if r.mutability.is_some() { "&mut " } else { "&" };
            format!("{mut_prefix}{}", normalize_type_signature(&r.elem))
        }
        Type::Slice(s) => format!("[{}]", normalize_type_signature(&s.elem)),
        Type::Path(tp) => tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Type::Tuple(t) => {
            let inner: Vec<String> = t.elems.iter().map(normalize_type_signature).collect();
            format!("({})", inner.join(","))
        }
        _ => "ty".to_string(),
    }
}

pub(crate) const fn helper_bin_op_str(op: &BinOp) -> &'static str {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::BinOp is non-exhaustive; delegates comparison and bitwise ops (#50)"
    )]
    match op {
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
        _ => helper_shift_or_cmp_op_str(op),
    }
}

const fn helper_shift_or_cmp_op_str(op: &BinOp) -> &'static str {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::BinOp is non-exhaustive; shift and comparison operators are hashed explicitly (#50)"
    )]
    match op {
        BinOp::Shl(_) => "<<",
        BinOp::Shr(_) => ">>",
        BinOp::Eq(_) => "==",
        BinOp::Lt(_) => "<",
        BinOp::Le(_) => "<=",
        BinOp::Ne(_) => "!=",
        BinOp::Ge(_) => ">=",
        BinOp::Gt(_) => ">",
        _ => "binop",
    }
}

