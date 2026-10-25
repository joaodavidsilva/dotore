//! Lexical `use`-alias and 8-hop local `let`/`const` binding resolver (`SourceKernel`) for `dotore-rs`.
//!
//! Resolves `use` declarations (including `as` renames, nested use trees, `self`, globs, and
//! local item/type shadowing) and unwinds receiver chains and call arguments through up to 8 hops
//! of local `let`/`const` bindings while abstaining safely when a binding is mutably reassigned,
//! bound via a ref/subpattern/let-else, or shadowed.

use std::collections::BTreeMap;

use dotore_core::ByteSpan;
use syn::{
    Block, Expr, ExprAsync, ExprCall, ExprClosure, ExprMethodCall, File, GenericParam, ImplItem,
    Item, ItemConst, ItemFn, ItemMod, Path, PathArguments, Signature, Stmt, Type, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::span_to_bytes,
    tokio_async::{is_offloading_method_call, is_resolved_blocking_item, is_spawn_blocking_call},
};
pub(crate) use crate::source_kernel_bindings::{
    FnBodyResolver, IdentUsageKind, KernelContext, LocalBinding, bare_identifier,
    into_stripped_wrappers, literal_bool, literal_string, strip_parens, strip_wrappers,
};

/// Maximum number of local `let`/`const` hops followed from one expression.
pub(crate) const BINDING_DEPTH: usize = 8;

/// Maximum method-chain links unwound to reach the root call of a receiver.
pub(crate) const CHAIN_DEPTH: usize = 64;

/// Maximum number of scope bindings retained per source file before switching to indeterminate mode.
const BINDING_LIMIT: usize = 1_024;

/// Crates always available in the sysroot without a dependency declaration.
pub(crate) const SYSROOT_CRATES: [&str; 3] = ["alloc", "core", "std"];

/// Known ecosystem crates recognized by `SourceKernel` detectors.
pub(crate) const KNOWN_EXTERNAL_CRATES: [&str; 15] = [
    "actix_cors",
    "cookie",
    "diesel",
    "futures",
    "http",
    "jsonwebtoken",
    "postgres",
    "reqwest",
    "rusqlite",
    "sea_orm",
    "serde",
    "sqlx",
    "tokio",
    "tokio_postgres",
    "tower_http",
];

/// Primitive numeric, boolean, and character types whose `Display` formatting cannot carry injection payloads.
pub(crate) const NUMERIC_PRIMITIVES: [&str; 16] = [
    "bool", "char", "f32", "f64", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32",
    "u64", "u128", "usize",
];

/// Scope key identified by `(start_byte, end_byte)` of a `syn::File`, `ItemMod`, or `Block`.
type ScopeKey = (u32, u32);
type SyncMethodMap = BTreeMap<String, Option<(Signature, Block)>>;

/// Provenance of an identifier at a given byte offset in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Provenance<'a> {
    /// Bound by a visible `use` declaration to this canonical path.
    Item(&'a [String]),
    /// Masked by one or more glob imports in scope (`Some(crate_head)` or `None` for relative globs).
    GlobMasked(Vec<Option<&'a str>>),
    /// Bound locally by a shadowing item/generic parameter or saturated map: provenance is undecidable.
    Indeterminate,
    /// No visible `use` or shadowing item carries this identifier.
    Unbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AliasBinding {
    Item(Vec<String>),
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Block,
}

/// Lexical `use`-alias and item-shadowing map for a parsed `syn::File`.
#[derive(Debug, Default, Clone)]
pub(crate) struct RsAliasMap {
    scopes: BTreeMap<ScopeKey, BTreeMap<String, AliasBinding>>,
    globs: BTreeMap<ScopeKey, Vec<Option<String>>>,
    scope_kinds: BTreeMap<ScopeKey, ScopeKind>,
    generic_shadow_scopes: Vec<(ScopeKey, Vec<String>)>,
    consts: BTreeMap<ScopeKey, BTreeMap<String, Option<Expr>>>,
    type_aliases: BTreeMap<ScopeKey, BTreeMap<String, Type>>,
    sync_fns: BTreeMap<ScopeKey, SyncMethodMap>,
    impl_sync_methods: Vec<(ByteSpan, SyncMethodMap)>,
    bindings_count: usize,
    saturated: bool,
}

impl RsAliasMap {
    /// Builds the lexical [`RsAliasMap`] for a parsed [`syn::File`].
    #[must_use]
    pub(crate) fn build(file: &File) -> Self {
        let mut map = Self::default();
        let root_span = span_to_bytes(file.span());
        let root_key = (root_span.start, root_span.end.max(root_span.start));
        map.scope_kinds.insert(root_key, ScopeKind::Module);
        map.populate_items(&file.items, root_key);
        map
    }

    fn populate_items(&mut self, items: &[Item], scope: ScopeKey) {
        for item in items {
            if self.saturated {
                break;
            }
            #[expect(
                clippy::wildcard_enum_match_arm,
                reason = "syn::Item has many variants; only items that bind names or contain nested scopes are indexed"
            )]
            match item {
                Item::Use(item_use) => {
                    self.record_use_tree(&item_use.tree, Some(Vec::new()), scope);
                }
                Item::ExternCrate(ext) => {
                    self.record_extern_crate(scope, ext);
                }
                Item::Mod(item_mod) => {
                    self.insert_binding(
                        scope,
                        item_mod.ident.to_string(),
                        AliasBinding::Opaque,
                    );
                    if let Some((_, mod_items)) = &item_mod.content {
                        let sp = span_to_bytes(item_mod.span());
                        let mod_key = (sp.start, sp.end);
                        self.scope_kinds.insert(mod_key, ScopeKind::Module);
                        self.populate_items(mod_items, mod_key);
                    }
                }
                Item::Struct(s) => {
                    self.insert_binding(scope, s.ident.to_string(), AliasBinding::Opaque);
                    self.record_generics(s.span(), &s.generics);
                }
                Item::Enum(e) => {
                    self.insert_binding(scope, e.ident.to_string(), AliasBinding::Opaque);
                    self.record_generics(e.span(), &e.generics);
                }
                Item::Union(u) => {
                    self.insert_binding(scope, u.ident.to_string(), AliasBinding::Opaque);
                    self.record_generics(u.span(), &u.generics);
                }
                Item::Trait(t) => {
                    self.insert_binding(scope, t.ident.to_string(), AliasBinding::Opaque);
                    self.record_generics(t.span(), &t.generics);
                    self.record_trait_items(&t.items);
                }
                Item::Type(ty) => {
                    let name = ty.ident.to_string();
                    self.insert_binding(scope, name.clone(), AliasBinding::Opaque);
                    self.type_aliases
                        .entry(scope)
                        .or_default()
                        .insert(name, (*ty.ty).clone());
                    self.record_generics(ty.span(), &ty.generics);
                }
                Item::Const(item_const) => {
                    self.record_const(scope, item_const);
                }
                Item::Fn(item_fn) => {
                    self.record_sync_fn(scope, item_fn);
                    self.record_generics(item_fn.span(), &item_fn.sig.generics);
                    self.populate_block(&item_fn.block);
                }
                Item::Impl(item_impl) => {
                    self.record_impl_item(item_impl);
                }
                _ => {}
            }
        }
    }

    fn populate_block(&mut self, block: &Block) {
        let sp = span_to_bytes(block.span());
        let block_key = (sp.start, sp.end);
        self.scope_kinds.insert(block_key, ScopeKind::Block);

        let mut block_items = Vec::new();
        for stmt in &block.stmts {
            if let Stmt::Item(item) = stmt {
                block_items.push(item.clone());
            }
        }
        if !block_items.is_empty() {
            self.populate_items(&block_items, block_key);
        }

        struct BlockVisitor<'a> {
            map: &'a mut RsAliasMap,
        }
        impl<'ast> Visit<'ast> for BlockVisitor<'_> {
            fn visit_item_fn(&mut self, i: &'ast ItemFn) {
                self.map.record_generics(i.span(), &i.sig.generics);
                self.map.populate_block(&i.block);
            }
            fn visit_item_mod(&mut self, _i: &'ast ItemMod) {
                // Already handled by populate_items
            }
            fn visit_block(&mut self, b: &'ast Block) {
                let sp = span_to_bytes(b.span());
                let key = (sp.start, sp.end);
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.map.scope_kinds.entry(key)
                {
                    entry.insert(ScopeKind::Block);
                    self.map.populate_block_items(&b.stmts, key);
                }
                visit::visit_block(self, b);
            }
        }

        let mut v = BlockVisitor { map: self };
        for stmt in &block.stmts {
            if !matches!(stmt, Stmt::Item(_)) {
                v.visit_stmt(stmt);
            }
        }
    }

    fn record_generics(&mut self, span: proc_macro2::Span, generics: &syn::Generics) {
        let names: Vec<String> = generics
            .params
            .iter()
            .filter_map(|p| match p {
                GenericParam::Type(tp) => Some(tp.ident.to_string()),
                GenericParam::Lifetime(_) | GenericParam::Const(_) => None,
            })
            .collect();
        if !names.is_empty() {
            let sp = span_to_bytes(span);
            self.generic_shadow_scopes.push(((sp.start, sp.end), names));
        }
    }

    fn record_extern_crate(&mut self, scope: ScopeKey, ext: &syn::ItemExternCrate) {
        let Some((_, rename)) = &ext.rename else {
            self.insert_binding(scope, ext.ident.to_string(), AliasBinding::Opaque);
            return;
        };
        let name = rename.to_string();
        if name != "_" {
            self.insert_binding(scope, name, AliasBinding::Opaque);
        }
    }

    fn record_trait_items(&mut self, items: &[syn::TraitItem]) {
        for trait_item in items {
            let syn::TraitItem::Fn(tf) = trait_item else {
                continue;
            };
            self.record_generics(tf.span(), &tf.sig.generics);
            if let Some(block) = &tf.default {
                self.populate_block(block);
            }
        }
    }

    fn record_impl_item(&mut self, item_impl: &syn::ItemImpl) {
        self.record_generics(item_impl.span(), &item_impl.generics);
        let impl_sp = span_to_bytes(item_impl.span());
        let mut methods = BTreeMap::new();
        for impl_item in &item_impl.items {
            let ImplItem::Fn(method) = impl_item else {
                continue;
            };
            let name = method.sig.ident.to_string();
            if method.sig.asyncness.is_some() {
                methods.insert(name, None);
            } else {
                match methods.entry(name) {
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        e.insert(None);
                    }
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(Some((method.sig.clone(), method.block.clone())));
                    }
                }
            }
            self.record_generics(method.span(), &method.sig.generics);
            self.populate_block(&method.block);
        }
        if !methods.is_empty() {
            self.impl_sync_methods.push((impl_sp, methods));
        }
    }

    fn populate_block_items(&mut self, stmts: &[Stmt], key: ScopeKey) {
        let items: Vec<Item> = stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Item(item) => Some(item.clone()),
                Stmt::Local(_) | Stmt::Expr(_, _) | Stmt::Macro(_) => None,
            })
            .collect();
        if !items.is_empty() {
            self.populate_items(&items, key);
        }
    }

    fn record_const(&mut self, scope: ScopeKey, item_const: &ItemConst) {
        let name = item_const.ident.to_string();
        if name == "_" {
            return;
        }
        match self.consts.entry(scope).or_default().entry(name) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                e.insert(None);
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(Some((*item_const.expr).clone()));
            }
        }
    }

    fn record_sync_fn(&mut self, scope: ScopeKey, item_fn: &ItemFn) {
        let name = item_fn.sig.ident.to_string();
        let scope_fns = self.sync_fns.entry(scope).or_default();
        if item_fn.sig.asyncness.is_some() {
            scope_fns.insert(name, None);
        } else {
            match scope_fns.entry(name) {
                std::collections::btree_map::Entry::Occupied(mut e) => {
                    e.insert(None);
                }
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(Some((item_fn.sig.clone(), (*item_fn.block).clone())));
                }
            }
        }
    }

    fn record_use_tree(
        &mut self,
        tree: &UseTree,
        prefix: Option<Vec<String>>,
        scope: ScopeKey,
    ) {
        if self.saturated {
            return;
        }
        match tree {
            UseTree::Path(use_path) => {
                let ident = use_path.ident.to_string();
                let next = if matches!(ident.as_str(), "crate" | "super" | "self") {
                    None
                } else {
                    prefix.map(|mut p| {
                        p.push(ident);
                        p
                    })
                };
                self.record_use_tree(&use_path.tree, next, scope);
            }
            UseTree::Name(use_name) => {
                self.record_use_name(use_name.ident.to_string(), prefix, scope);
            }
            UseTree::Rename(use_rename) => {
                self.record_use_rename(use_rename, prefix, scope);
            }
            UseTree::Group(group) => {
                for child in &group.items {
                    self.record_use_tree(child, prefix.clone(), scope);
                }
            }
            UseTree::Glob(_) => {
                let head = prefix.and_then(|p| p.first().cloned());
                self.insert_glob(scope, head);
            }
        }
    }

    fn record_use_name(&mut self, ident: String, prefix: Option<Vec<String>>, scope: ScopeKey) {
        if ident == "self" {
            let Some(name) = prefix.as_ref().and_then(|p| p.last().cloned()) else {
                return;
            };
            self.insert_binding(scope, name, Self::binding_from_prefix(prefix));
            return;
        }
        let resolved = if matches!(ident.as_str(), "crate" | "super") {
            None
        } else {
            prefix.map(|mut p| {
                p.push(ident.clone());
                p
            })
        };
        self.insert_binding(scope, ident, Self::binding_from_prefix(resolved));
    }

    fn record_use_rename(
        &mut self,
        use_rename: &syn::UseRename,
        prefix: Option<Vec<String>>,
        scope: ScopeKey,
    ) {
        let alias = use_rename.rename.to_string();
        if alias == "_" {
            return;
        }
        let orig = use_rename.ident.to_string();
        let resolved = if orig == "self" {
            prefix
        } else if matches!(orig.as_str(), "crate" | "super") {
            None
        } else {
            prefix.map(|mut p| {
                p.push(orig);
                p
            })
        };
        self.insert_binding(scope, alias, Self::binding_from_prefix(resolved));
    }

    fn binding_from_prefix(prefix: Option<Vec<String>>) -> AliasBinding {
        match prefix {
            Some(path) if !path.is_empty() => AliasBinding::Item(path),
            _ => AliasBinding::Opaque,
        }
    }

    fn insert_binding(&mut self, scope: ScopeKey, name: String, binding: AliasBinding) {
        if self.reserve() {
            self.scopes.entry(scope).or_default().insert(name, binding);
        }
    }

    fn insert_glob(&mut self, scope: ScopeKey, head: Option<String>) {
        if self.reserve() {
            self.globs.entry(scope).or_default().push(head);
        }
    }

    fn reserve(&mut self) -> bool {
        if self.bindings_count >= BINDING_LIMIT {
            self.saturated = true;
            return false;
        }
        self.bindings_count += 1;
        true
    }
}

impl RsAliasMap {
    /// Returns visible scopes from `site` (innermost first), stopping at the nearest enclosing module.
    #[must_use]
    fn visible_scopes(&self, site: ByteSpan) -> Vec<ScopeKey> {
        let mut enclosing: Vec<(ScopeKey, ScopeKind)> = self
            .scope_kinds
            .iter()
            .filter(|((start, end), _)| *start <= site.start && site.end <= *end)
            .map(|(k, kind)| (*k, kind.clone()))
            .collect();
        // Sort innermost first: largest start, or smallest end if starts equal
        enclosing.sort_by(|(a, _), (b, _)| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let mut result = Vec::new();
        for (key, kind) in enclosing {
            result.push(key);
            if kind == ScopeKind::Module {
                break;
            }
        }
        result
    }

    fn shadowed_by_generic(&self, site: ByteSpan, name: &str) -> bool {
        self.generic_shadow_scopes.iter().any(|((start, end), params)| {
            *start <= site.start && site.end <= *end && params.iter().any(|p| p == name)
        })
    }

    /// Resolves the [`Provenance`] of `name` at `site`.
    #[must_use]
    pub(crate) fn provenance(&self, site: ByteSpan, name: &str) -> Provenance<'_> {
        if self.saturated || self.shadowed_by_generic(site, name) {
            return Provenance::Indeterminate;
        }
        let mut masking = Vec::new();
        for scope in self.visible_scopes(site) {
            if let Some(binding) = self.scopes.get(&scope).and_then(|s| s.get(name)) {
                if !masking.is_empty() {
                    return Provenance::Indeterminate;
                }
                return match binding {
                    AliasBinding::Item(path) => Provenance::Item(path),
                    AliasBinding::Opaque => Provenance::Indeterminate,
                };
            }
            if let Some(globs) = self.globs.get(&scope) {
                masking.extend(globs.iter().map(Option::as_deref));
            }
        }
        if masking.is_empty() {
            Provenance::Unbound
        } else {
            Provenance::GlobMasked(masking)
        }
    }

    /// Returns `true` if `scope` has any glob imports or if the alias map is saturated.
    #[must_use]
    fn is_scope_globbed(&self, scope: ScopeKey) -> bool {
        self.saturated || self.globs.contains_key(&scope)
    }

    /// Resolves a `const` item named `name` in the visible scopes around `site`.
    #[must_use]
    pub(crate) fn resolve_const(&self, site: ByteSpan, name: &str) -> LocalBinding {
        match self.provenance(site, name) {
            Provenance::Unbound => {}
            Provenance::Item(_) => return LocalBinding::Unbound,
            Provenance::GlobMasked(_) | Provenance::Indeterminate => {
                return LocalBinding::Indeterminate;
            }
        }
        for scope in self.visible_scopes(site) {
            if let Some(scope_consts) = self.consts.get(&scope)
                && let Some(entry) = scope_consts.get(name)
            {
                return match entry {
                    Some(expr) => LocalBinding::Value(Box::new((expr.clone(), None))),
                    None => LocalBinding::Indeterminate,
                };
            }
        }
        LocalBinding::Unbound
    }

    /// Resolves a synchronous helper `fn` or `Self::method` called by `path` at `site`.
    #[must_use]
    fn resolve_local_sync_fn(
        &self,
        body: Option<&FnBodyResolver>,
        site: ByteSpan,
        path: &Path,
    ) -> Option<(String, Signature, Block)> {
        if path.leading_colon.is_some() {
            return None;
        }
        if path.segments.len() == 2 {
            let first = &path.segments[0];
            let second = &path.segments[1];
            if first.ident == "Self"
                && matches!(first.arguments, PathArguments::None)
                && matches!(second.arguments, PathArguments::None)
            {
                let name = second.ident.to_string();
                return self.resolve_impl_sync_method(site, &name);
            }
            return None;
        }
        if path.segments.len() != 1 {
            return None;
        }
        let seg = path.segments.first()?;
        if !matches!(seg.arguments, PathArguments::None) {
            return None;
        }
        let name = seg.ident.to_string();
        if !matches!(
            self.provenance(site, &name),
            Provenance::Unbound | Provenance::GlobMasked(_)
        ) {
            return None;
        }
        if body.is_some_and(|b| b.is_bound_locally(site, &name)) {
            return None;
        }
        for scope in self.visible_scopes(site) {
            if let Some(scope_fns) = self.sync_fns.get(&scope)
                && let Some(entry) = scope_fns.get(&name)
            {
                let (sig, blk) = entry.as_ref()?;
                return Some((name, sig.clone(), blk.clone()));
            }
            if self.is_scope_globbed(scope) {
                return None;
            }
        }
        None
    }

    /// Resolves a synchronous method `name` on the enclosing `impl` block around `site`.
    #[must_use]
    fn resolve_impl_sync_method(
        &self,
        site: ByteSpan,
        name: &str,
    ) -> Option<(String, Signature, Block)> {
        let (_, methods) = self
            .impl_sync_methods
            .iter()
            .find(|(sp, _)| sp.start <= site.start && site.end <= sp.end)?;
        let (sig, blk) = methods.get(name)?.as_ref()?;
        Some((name.to_string(), sig.clone(), blk.clone()))
    }
}
const HELPER_DEPTH: usize = 4;

pub(crate) fn match_waiting_command_method(
    ctx: &KernelContext<'_>,
    call: &ExprMethodCall,
) -> Option<String> {
    let method_name = call.method.to_string();
    if !matches!(method_name.as_str(), "output" | "status") {
        return None;
    }
    let Expr::Call(ctor) = ctx.chain_root(&call.receiver)? else {
        return None;
    };
    ctx.matches_call_path(&ctor.func, "std", &["process", "Command"], "new")?;
    Some(format!("std::process::Command::{method_name}"))
}

pub(crate) fn check_sync_helper_call(
    aliases: &RsAliasMap,
    body: Option<&FnBodyResolver>,
    call_site: ByteSpan,
    path: &Path,
) -> Option<(String, String)> {
    let (helper_name, helper_sig, helper_block) =
        aliases.resolve_local_sync_fn(body, call_site, path)?;
    let mut visited = Vec::new();
    let blocking_target = find_hidden_blocking_in_helper(
        aliases,
        &helper_sig,
        &helper_block,
        HELPER_DEPTH,
        &mut visited,
    )?;
    Some((helper_name, blocking_target))
}

pub(crate) fn check_sync_self_method_call(
    aliases: &RsAliasMap,
    site: ByteSpan,
    receiver: &Expr,
    method_name: &str,
) -> Option<(String, String)> {
    if !is_self_receiver(receiver) {
        return None;
    }
    let (helper_name, helper_sig, helper_block) =
        aliases.resolve_impl_sync_method(site, method_name)?;
    let mut visited = Vec::new();
    let blocking_target = find_hidden_blocking_in_helper(
        aliases,
        &helper_sig,
        &helper_block,
        HELPER_DEPTH,
        &mut visited,
    )?;
    Some((helper_name, blocking_target))
}

fn is_self_receiver(expr: &Expr) -> bool {
    if let Expr::Path(ep) = strip_wrappers(expr) {
        ep.qself.is_none() && ep.path.is_ident("self")
    } else {
        false
    }
}

fn find_hidden_blocking_in_helper(
    aliases: &RsAliasMap,
    sig: &Signature,
    block: &Block,
    depth: usize,
    visited: &mut Vec<ByteSpan>,
) -> Option<String> {
    let span = span_to_bytes(block.span());
    if depth == 0 || visited.contains(&span) || sig.asyncness.is_some() {
        return None;
    }
    visited.push(span);
    let body_resolver = FnBodyResolver::build(sig, block);
    let ctx = KernelContext::new(aliases, Some(&body_resolver));

    struct HelperScan<'a> {
        aliases: &'a RsAliasMap,
        body: &'a FnBodyResolver,
        ctx: KernelContext<'a>,
        direct_blocking: Option<String>,
        nested_helpers: Vec<(Signature, Block)>,
    }

    impl<'ast> Visit<'ast> for HelperScan<'_> {
        fn visit_item(&mut self, _i: &'ast Item) {}
        fn visit_expr_async(&mut self, _i: &'ast ExprAsync) {}
        fn visit_expr_closure(&mut self, i: &'ast ExprClosure) {
            if i.asyncness.is_some() {
                return;
            }
            visit::visit_expr_closure(self, i);
        }
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if self.direct_blocking.is_some() || is_spawn_blocking_call(node) {
                return;
            }
            if let Expr::Path(ep) = strip_parens(&node.func)
                && ep.qself.is_none()
            {
                if let Some((resolved, _)) = self.ctx.resolve_item_path(&ep.path)
                    && is_resolved_blocking_item(&resolved)
                {
                    self.direct_blocking = Some(resolved.join("::"));
                    return;
                }
                let site = span_to_bytes(node.span());
                if let Some((_, h_sig, h_blk)) =
                    self.aliases
                        .resolve_local_sync_fn(Some(self.body), site, &ep.path)
                {
                    self.nested_helpers.push((h_sig, h_blk));
                }
            }
            visit::visit_expr_call(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if self.direct_blocking.is_some() || is_offloading_method_call(node) {
                return;
            }
            if let Some(waiting) = match_waiting_command_method(&self.ctx, node) {
                self.direct_blocking = Some(waiting);
                return;
            }
            if is_self_receiver(&node.receiver) {
                let site = span_to_bytes(node.span());
                if let Some((_, h_sig, h_blk)) = self
                    .aliases
                    .resolve_impl_sync_method(site, &node.method.to_string())
                {
                    self.nested_helpers.push((h_sig, h_blk));
                }
            }
            visit::visit_expr_method_call(self, node);
        }
    }

    let mut scan = HelperScan {
        aliases,
        body: &body_resolver,
        ctx,
        direct_blocking: None,
        nested_helpers: Vec::new(),
    };
    scan.visit_block(block);
    if let Some(direct) = scan.direct_blocking {
        return Some(direct);
    }
    scan.nested_helpers
        .into_iter()
        .find_map(|(next_sig, next_blk)| {
            find_hidden_blocking_in_helper(aliases, &next_sig, &next_blk, depth - 1, visited)
        })
}

const SECRET_WORDS: [&str; 6] = [
    "API_KEY",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "SIGNING_KEY",
    "TOKEN",
];
const NOT_SECRET_SUFFIXES: [&str; 5] = ["_ENDPOINT", "_HEADER", "_ID", "_NAME", "_URL"];
const PLACEHOLDERS: [&str; 5] = ["changeme", "example", "your_", "xxx", "0000"];

pub(crate) fn secret_fallback_message(
    ctx: &KernelContext<'_>,
    call: &ExprMethodCall,
) -> Option<&'static str> {
    let fallback_expr = match call.method.to_string().as_str() {
        "unwrap_or_default" => {
            return call.args.is_empty().then_some(
                "A secret environment variable falls back to an empty value, so the service runs without the secret.",
            );
        }
        "unwrap_or" => {
            if call.args.len() != 1 {
                return None;
            }
            call.args.first()?.clone()
        }
        "unwrap_or_else" => {
            if call.args.len() != 1 {
                return None;
            }
            let Expr::Closure(closure) = call.args.first()? else {
                return None;
            };
            extract_closure_tail_expr(&closure.body)?
        }
        _ => return None,
    };
    let text = extract_fallback_literal_text(ctx, &fallback_expr)?;
    if text.is_empty() {
        Some(
            "A secret environment variable falls back to an empty value, so the service runs without the secret.",
        )
    } else if is_real_secret_fallback(&text) {
        Some(
            "A secret environment variable falls back to a literal, which ships in the binary and runs the service without the secret.",
        )
    } else {
        None
    }
}

pub(crate) fn reads_secret_env_var(ctx: &KernelContext<'_>, receiver: &Expr) -> bool {
    let Some(Expr::Call(read_call)) = ctx.resolve_value(strip_wrappers(receiver)) else {
        return false;
    };
    if read_call.args.len() != 1 {
        return false;
    }
    let is_env_var = ctx
        .matches_any_path(
            &read_call.func,
            &[&["std", "env", "var"], &["std", "env", "var_os"]],
        )
        .is_some();
    if !is_env_var {
        return false;
    }
    let Some(first_arg) = read_call.args.first() else {
        return false;
    };
    let Some(resolved_arg) = ctx.resolve_value(first_arg) else {
        return false;
    };
    let Some(var_name) = literal_string(&resolved_arg) else {
        return false;
    };
    let upper = var_name.to_ascii_uppercase();
    SECRET_WORDS.iter().any(|w| upper.contains(w))
        && !NOT_SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
}

fn is_real_secret_fallback(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value.is_empty() && !PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

fn extract_closure_tail_expr(body: &Expr) -> Option<Expr> {
    if let Expr::Block(blk) = body {
        if let Some(Stmt::Expr(expr, None)) = blk.block.stmts.last() {
            Some(expr.clone())
        } else {
            None
        }
    } else {
        Some(body.clone())
    }
}

fn extract_fallback_literal_text(ctx: &KernelContext<'_>, expr: &Expr) -> Option<String> {
    let resolved = ctx.resolve_value(strip_wrappers(expr))?;
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Fallback string literals may be bare or wrapped in .into() / .to_owned() / .to_string() / String::from(...)"
    )]
    match strip_wrappers(&resolved) {
        Expr::MethodCall(mc) => {
            if matches!(
                mc.method.to_string().as_str(),
                "into" | "to_owned" | "to_string"
            ) && mc.args.is_empty()
            {
                literal_string(strip_wrappers(&mc.receiver))
            } else {
                None
            }
        }
        Expr::Call(call) => {
            let Expr::Path(ep) = strip_wrappers(&call.func) else {
                return None;
            };
            let segs: Vec<String> = ep.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if matches!(
                segs.as_slice(),
                [.., ty, from] if (ty == "String" || ty == "OsString") && from == "from"
            ) && call.args.len() == 1
            {
                literal_string(call.args.first()?)
            } else {
                None
            }
        }
        other => literal_string(other),
    }
}

