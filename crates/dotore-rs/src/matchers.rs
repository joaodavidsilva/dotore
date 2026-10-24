//! Shared `syn` AST, type, attribute, span/line, and lexical-scope matchers and
//! diagnostic builder helpers for `dotore-rs`.

use std::path::Path;

use dotore_core::{
    AutofixPatch, ByteSpan, Diagnostic, ResolvedCallerSite, RuleId, RuleSeverity, SourceLoc,
    loc_from_line_starts,
};
use syn::{
    Attribute, Expr, ExprClosure, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemTrait, Lit, Macro,
    Pat, TraitItemFn, Type, Visibility,
};

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
    /// Optional cross-file **Caller Sites** or peer occurrence sites.
    pub caller_sites: Vec<ResolvedCallerSite>,
    /// Optional multi-step cascade or signal chain steps.
    pub cascade_steps: Vec<String>,
}

impl RsCandidateFinding {
    /// Creates a new [`RsCandidateFinding`] without an autofix patch.
    #[must_use]
    pub fn new(
        rule: RuleId,
        subject_name: Option<String>,
        target_name: impl Into<String>,
        message_id: &'static str,
        message: impl Into<String>,
        loc: SourceLoc,
        span: ByteSpan,
    ) -> Self {
        Self {
            rule,
            subject_name,
            target_name: target_name.into(),
            message_id,
            message: message.into(),
            loc,
            span,
            autofix: None,
            caller_sites: Vec::new(),
            cascade_steps: Vec::new(),
        }
    }

    /// Attaches an optional [`AutofixPatch`] to this candidate finding.
    #[must_use]
    pub fn with_autofix(mut self, autofix: Option<AutofixPatch>) -> Self {
        self.autofix = autofix;
        self
    }

    /// Attaches a deterministic [`AutofixPatch`] to this candidate finding.
    #[must_use]
    pub fn with_patch(mut self, patch: AutofixPatch) -> Self {
        self.autofix = Some(patch);
        self
    }

    /// Attaches resolved cross-file [`ResolvedCallerSite`]s to this candidate finding.
    #[must_use]
    pub fn with_caller_sites(mut self, caller_sites: Vec<ResolvedCallerSite>) -> Self {
        self.caller_sites = caller_sites;
        self
    }

    /// Attaches cascade or structural signal steps to this candidate finding.
    #[must_use]
    pub fn with_cascade_steps(mut self, cascade_steps: Vec<String>) -> Self {
        self.cascade_steps = cascade_steps;
        self
    }

    /// Converts this candidate finding into a [`Diagnostic`] using [`Diagnostic::builder`].
    #[must_use]
    pub fn to_diagnostic(&self, file_path: &Path, severity: RuleSeverity) -> Diagnostic {
        Diagnostic::builder(
            self.rule,
            file_path,
            self.loc,
            self.span,
            self.target_name.clone(),
            self.message.clone(),
        )
        .with_subject(self.subject_name.clone())
        .with_severity(severity)
        .with_message_id(self.message_id)
        .with_caller_sites(self.caller_sites.clone())
        .with_cascade_steps(self.cascade_steps.clone())
        .with_autofix(self.autofix.clone())
    }
}

/// Saved lexical-scope state restored when exiting a nested `syn` item or expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsScopeSnapshot {
    pub in_test_context: bool,
    pub current_subject_name: Option<String>,
    pub current_parent_type: Option<String>,
    pub current_inline_module: Option<String>,
    pub async_depth: usize,
    pub loop_depth: usize,
    pub in_executable_body: usize,
    pub in_static_or_lazy_init: usize,
}

/// Reusable lexical-scope tracker for `syn::Visit` traversals across `dotore-rs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RsScopeTracker {
    /// Whether the visitor is currently inside a `#[cfg(test)]` module or test function.
    pub in_test_context: bool,
    /// Enclosing Rust **Subject** name (`fn_name`, `Type::method`, `Trait for Type`, or `mod_name`).
    pub current_subject_name: Option<String>,
    /// Enclosing `impl` or `trait` type identifier (`Order`, `OrderRepository`).
    pub current_parent_type: Option<String>,
    /// Enclosing inline `mod` identifier, if any.
    pub current_inline_module: Option<String>,
    /// Nesting depth inside `async fn`, `async { ... }`, or `async ||` closures.
    pub async_depth: usize,
    /// Nesting depth inside `for`, `while`, or `loop` bodies within the current function.
    pub loop_depth: usize,
    /// Nesting depth inside executable function/method bodies.
    pub in_executable_body: usize,
    /// Nesting depth inside `static`, `const`, or `LazyLock::new` / `OnceLock::get_or_init` initializers.
    pub in_static_or_lazy_init: usize,
}

impl RsScopeTracker {
    /// Creates a new [`RsScopeTracker`] at the crate/file root.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates a [`RsScopeTracker`] initialized from crate/file attributes (`#![cfg(test)]`).
    #[must_use]
    pub(crate) fn for_file(file: &syn::File) -> Self {
        Self {
            in_test_context: attrs_indicate_test_context(&file.attrs),
            ..Self::default()
        }
    }

    /// Captures a snapshot of the current lexical scope state.
    #[must_use]
    fn snapshot(&self) -> RsScopeSnapshot {
        RsScopeSnapshot {
            in_test_context: self.in_test_context,
            current_subject_name: self.current_subject_name.clone(),
            current_parent_type: self.current_parent_type.clone(),
            current_inline_module: self.current_inline_module.clone(),
            async_depth: self.async_depth,
            loop_depth: self.loop_depth,
            in_executable_body: self.in_executable_body,
            in_static_or_lazy_init: self.in_static_or_lazy_init,
        }
    }

    /// Restores the lexical scope state from a previously captured [`RsScopeSnapshot`].
    pub(crate) fn exit(&mut self, snapshot: RsScopeSnapshot) {
        self.in_test_context = snapshot.in_test_context;
        self.current_subject_name = snapshot.current_subject_name;
        self.current_parent_type = snapshot.current_parent_type;
        self.current_inline_module = snapshot.current_inline_module;
        self.async_depth = snapshot.async_depth;
        self.loop_depth = snapshot.loop_depth;
        self.in_executable_body = snapshot.in_executable_body;
        self.in_static_or_lazy_init = snapshot.in_static_or_lazy_init;
    }

    /// Returns `true` if currently inside a test module or test function.
    #[must_use]
    pub(crate) const fn in_test(&self) -> bool {
        self.in_test_context
    }

    /// Returns `true` if currently inside an `async` function, block, or closure.
    #[must_use]
    pub(crate) const fn in_async(&self) -> bool {
        self.async_depth > 0
    }

    /// Returns `true` if currently inside a `for`, `while`, or `loop` body.
    #[must_use]
    pub(crate) const fn in_loop(&self) -> bool {
        self.loop_depth > 0
    }

    /// Returns a clone of the current enclosing **Subject** name.
    #[must_use]
    pub(crate) fn subject_name(&self) -> Option<String> {
        self.current_subject_name.clone()
    }

    /// Enters an inline `mod` item (`mod name { ... }`).
    #[must_use]
    pub(crate) fn enter_mod(&mut self, item: &ItemMod) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context
            || attrs_indicate_test_context(&item.attrs)
            || item.ident == "tests";
        let mod_name = item.ident.to_string();
        self.current_inline_module = Some(mod_name.clone());
        self.current_subject_name = Some(mod_name);
        snap
    }

    /// Enters an `impl` block (`impl Type` or `impl Trait for Type`).
    #[must_use]
    pub(crate) fn enter_impl(&mut self, item: &ItemImpl) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context || attrs_indicate_test_context(&item.attrs);
        let self_ty_name = extract_type_name(&item.self_ty).unwrap_or_else(|| "Impl".to_string());
        let impl_subject_name = if let Some((_, trait_path, _)) = &item.trait_ {
            let trait_name = trait_path
                .segments
                .last()
                .map_or_else(|| "Trait".to_string(), |s| s.ident.to_string());
            format!("{trait_name} for {self_ty_name}")
        } else {
            self_ty_name.clone()
        };
        self.current_parent_type = Some(self_ty_name);
        self.current_subject_name = Some(impl_subject_name);
        snap
    }

    /// Enters a `trait` item (`trait Name { ... }`).
    #[must_use]
    pub(crate) fn enter_trait(&mut self, item: &ItemTrait) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context || attrs_indicate_test_context(&item.attrs);
        self.current_parent_type = Some(item.ident.to_string());
        snap
    }

    /// Enters a free function (`fn name(...)`).
    #[must_use]
    pub(crate) fn enter_fn(&mut self, item: &ItemFn) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context || attrs_indicate_test_context(&item.attrs);
        self.current_subject_name = Some(item.sig.ident.to_string());
        self.async_depth = usize::from(item.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        snap
    }

    /// Enters an inherent or trait `impl` method (`fn method(...)`).
    #[must_use]
    pub(crate) fn enter_method(&mut self, item: &ImplItemFn) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context || attrs_indicate_test_context(&item.attrs);
        let method_name = item.sig.ident.to_string();
        let qualified = if let Some(parent) = &self.current_parent_type {
            format!("{parent}::{method_name}")
        } else {
            method_name
        };
        self.current_subject_name = Some(qualified);
        self.async_depth = usize::from(item.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        snap
    }

    /// Enters a `trait` method declaration or default implementation.
    #[must_use]
    pub(crate) fn enter_trait_fn(&mut self, item: &TraitItemFn) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_test_context = self.in_test_context || attrs_indicate_test_context(&item.attrs);
        self.current_subject_name = Some(item.sig.ident.to_string());
        self.async_depth = usize::from(item.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        snap
    }

    /// Enters a `for`, `while`, or `loop` body.
    #[must_use]
    pub(crate) fn enter_loop(&mut self) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.loop_depth += 1;
        snap
    }

    /// Enters an `async { ... }` block.
    #[must_use]
    pub(crate) fn enter_async(&mut self) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.async_depth += 1;
        snap
    }

    /// Enters a closure expression (`|| ...` or `async move || ...`).
    #[must_use]
    pub(crate) fn enter_closure(&mut self, closure: &ExprClosure) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.async_depth += usize::from(closure.asyncness.is_some());
        snap
    }

    /// Enters a `static` or `const` item initializer.
    #[must_use]
    pub(crate) fn enter_static_or_const(&mut self) -> RsScopeSnapshot {
        let snap = self.snapshot();
        self.in_static_or_lazy_init += 1;
        snap
    }
}

/// Converts a `proc_macro2::Span` into a 0-based [`ByteSpan`].
#[must_use]
pub(crate) fn span_to_bytes(span: proc_macro2::Span) -> ByteSpan {
    let range = span.byte_range();
    let start = u32::try_from(range.start).unwrap_or(0);
    let end = u32::try_from(range.end).unwrap_or(start);
    ByteSpan { start, end }
}

/// Converts a 0-based byte offset into a 1-based [`SourceLoc`] using precomputed `line_starts`.
#[must_use]
pub(crate) fn loc_at(line_starts: &[u32], byte_offset: u32) -> SourceLoc {
    loc_from_line_starts(line_starts, byte_offset)
}

/// Safely slices `source` by a 0-based [`ByteSpan`], returning `""` if out of bounds.
#[must_use]
pub(crate) fn slice_source(source: &str, span: ByteSpan) -> &str {
    let start = usize::try_from(span.start).unwrap_or(0);
    let end = usize::try_from(span.end).unwrap_or(start).min(source.len());
    if start <= end && end <= source.len() {
        &source[start..end]
    } else {
        ""
    }
}

/// Joins a `syn::Path`'s segments with `"::"` (e.g. `"std::mem::forget"`).
#[must_use]
pub(crate) fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Extracts the terminal type identifier from a `syn::Type`, unwrapping references, parens, and groups.
#[must_use]
pub(crate) fn extract_type_name(ty: &Type) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; only path, reference, paren, and group types carry named identifiers"
    )]
    match ty {
        Type::Path(type_path) => type_path.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(type_ref) => extract_type_name(&type_ref.elem),
        Type::Paren(paren) => extract_type_name(&paren.elem),
        Type::Group(group) => extract_type_name(&group.elem),
        _ => None,
    }
}

/// Returns `true` if `ty` is a direct `bool` type annotation.
#[must_use]
pub(crate) fn is_bool_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        tp.qself.is_none() && tp.path.is_ident("bool")
    } else {
        false
    }
}

/// Returns `true` if `vis` is `pub` (`Visibility::Public`).
#[must_use]
pub(crate) const fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

/// Returns `true` if `vis` is `pub(crate)` or `pub(super)`.
#[must_use]
pub(crate) fn is_pub_crate_visibility(vis: &Visibility) -> bool {
    if let Visibility::Restricted(restr) = vis {
        restr.path.is_ident("crate") || restr.path.is_ident("super")
    } else {
        false
    }
}

/// Returns `true` if `path` refers to the `format!` macro (`format` or `std::fmt::format`).
#[must_use]
pub(crate) fn is_format_macro_path(path: &syn::Path) -> bool {
    path.is_ident("format")
        || path_to_string(path) == "std::fmt::format"
        || path.segments.last().is_some_and(|s| s.ident == "format")
}

/// Returns `true` if `mac` is a `format!(...)` macro invocation.
#[must_use]
pub(crate) fn is_format_macro(mac: &Macro) -> bool {
    is_format_macro_path(&mac.path)
}

/// Extracts a bound local identifier name from a `syn::Pat` (handling `ident`, `ident: Ty`,
/// `&ident`, and single-field tuple struct patterns like `State(state)`).
#[must_use]
pub(crate) fn extract_pat_ident(pat: &Pat) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; ident, type, reference, and single-element tuple struct patterns bind local names"
    )]
    match pat {
        Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
        Pat::Type(pat_type) => extract_pat_ident(&pat_type.pat),
        Pat::Reference(pat_ref) => extract_pat_ident(&pat_ref.pat),
        Pat::TupleStruct(ts) if ts.elems.len() == 1 => ts.elems.first().and_then(extract_pat_ident),
        _ => None,
    }
}

/// Extracts a single local identifier from an expression (`ident`, `(ident)`, `&ident`).
#[must_use]
pub(crate) fn extract_expr_ident(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; only path/reference/paren expressions resolve to a single local identifier"
    )]
    match expr {
        Expr::Paren(p) => extract_expr_ident(&p.expr),
        Expr::Group(g) => extract_expr_ident(&g.expr),
        Expr::Reference(r) => extract_expr_ident(&r.expr),
        Expr::Path(ep) if ep.qself.is_none() => ep.path.get_ident().map(ToString::to_string),
        _ => None,
    }
}

/// Extracts the trailing segment identifier from a path/reference/paren receiver expression.
#[must_use]
pub(crate) fn extract_receiver_ident(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; extracts trailing identifier from path or wrapped receiver"
    )]
    match expr {
        Expr::Paren(p) => extract_receiver_ident(&p.expr),
        Expr::Group(g) => extract_receiver_ident(&g.expr),
        Expr::Reference(r) => extract_receiver_ident(&r.expr),
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// Extracts a human-readable receiver label (`ident`, `a::b`, `self.field`, `tuple.0`) for diagnostics.
#[must_use]
pub(crate) fn extract_receiver_label(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; extracts concise receiver label for diagnostics"
    )]
    match expr {
        Expr::Paren(p) => extract_receiver_label(&p.expr),
        Expr::Group(g) => extract_receiver_label(&g.expr),
        Expr::Reference(r) => extract_receiver_label(&r.expr),
        Expr::Path(ep) => Some(path_to_string(&ep.path)),
        Expr::Field(field) => {
            let base = extract_receiver_label(&field.base)?;
            match &field.member {
                syn::Member::Named(ident) => Some(format!("{base}.{ident}")),
                syn::Member::Unnamed(idx) => Some(format!("{base}.{}", idx.index)),
            }
        }
        _ => None,
    }
}

/// Normalizes an expression into a compact structural key for bounds-guard matching (`arr[i]`, `s.len()`, `a+b`).
#[must_use]
pub(crate) fn normalize_expr_key(expr: &Expr) -> String {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; fallback formats indexing, method calls, and binary expressions compactly"
    )]
    match expr {
        Expr::Paren(p) => normalize_expr_key(&p.expr),
        Expr::Group(g) => normalize_expr_key(&g.expr),
        Expr::Reference(r) => normalize_expr_key(&r.expr),
        Expr::Path(path) => path_to_string(&path.path),
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
            _ => quote_like_expr(expr),
        },
        _ => quote_like_expr(expr),
    }
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

/// Returns `true` if `ty` is a `Copy` primitive, shared reference, or cheap reference-counted handle (`Arc`, `Rc`, `Pool`, `Client`, `Sender`, etc.).
#[must_use]
pub(crate) fn is_cheap_clone_type(ty: &Type) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; checks path, reference, pointer, and tuple types for Copy primitives and cheap reference-counted handles"
    )]
    match ty {
        Type::Reference(tr) => tr.mutability.is_none() || is_cheap_clone_type(&tr.elem),
        Type::Ptr(_) => true,
        Type::Paren(p) => is_cheap_clone_type(&p.elem),
        Type::Group(g) => is_cheap_clone_type(&g.elem),
        Type::Tuple(t) => t.elems.iter().all(is_cheap_clone_type),
        Type::Path(tp) => tp.path.segments.iter().any(|seg| {
            matches!(
                seg.ident.to_string().as_str(),
                "u8" | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "f32"
                    | "f64"
                    | "bool"
                    | "char"
                    | "Duration"
                    | "Instant"
                    | "Uuid"
                    | "IpAddr"
                    | "Ipv4Addr"
                    | "Ipv6Addr"
                    | "SocketAddr"
                    | "NonZeroU8"
                    | "NonZeroU16"
                    | "NonZeroU32"
                    | "NonZeroU64"
                    | "NonZeroU128"
                    | "NonZeroUsize"
                    | "NonZeroI8"
                    | "NonZeroI16"
                    | "NonZeroI32"
                    | "NonZeroI64"
                    | "NonZeroI128"
                    | "NonZeroIsize"
                    | "Arc"
                    | "Rc"
                    | "Weak"
                    | "Sender"
                    | "UnboundedSender"
                    | "Client"
                    | "Pool"
                    | "PgPool"
                    | "SqlitePool"
                    | "MySqlPool"
                    | "Handle"
                    | "CancellationToken"
                    | "Span"
                    | "Channel"
                    | "Router"
            )
        }),
        _ => false,
    }
}

/// Returns `true` if `expr` constructs a `Copy` value, shared reference, or `Arc`/`Rc`/`Client`/`Duration`.
#[must_use]
pub(crate) fn is_cheap_clone_ctor(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Checks primitive Copy literals, shared references, casts to Copy types, and Arc/Rc/Client constructors"
    )]
    match expr {
        Expr::Lit(expr_lit) => matches!(
            expr_lit.lit,
            Lit::Int(_) | Lit::Float(_) | Lit::Bool(_) | Lit::Char(_) | Lit::Byte(_)
        ),
        Expr::Reference(r) => r.mutability.is_none(),
        Expr::Cast(c) => is_cheap_clone_type(&c.ty),
        Expr::Unary(u) => is_cheap_clone_ctor(&u.expr),
        Expr::Binary(b) => is_cheap_clone_ctor(&b.left) && is_cheap_clone_ctor(&b.right),
        Expr::Paren(p) => is_cheap_clone_ctor(&p.expr),
        Expr::Call(call) => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let full = path_to_string(&ep.path);
                return full.ends_with("Arc::new")
                    || full.ends_with("Arc::clone")
                    || full.ends_with("Rc::new")
                    || full.ends_with("Rc::clone")
                    || full.ends_with("Client::new")
                    || full.starts_with("Duration::");
            }
            false
        }
        _ => false,
    }
}

/// Returns `true` if `ident` follows conventional naming for cheap reference-counted handles (`arc`, `pool`, `client`, `tx`, `sender`, `handle`, `token`, `span`).
#[must_use]
pub(crate) fn is_cheap_handle_ident(ident: &str) -> bool {
    let lower = ident.to_ascii_lowercase();
    lower.split('_').any(|part| {
        matches!(
            part,
            "arc"
                | "rc"
                | "weak"
                | "client"
                | "pool"
                | "tx"
                | "sender"
                | "handle"
                | "token"
                | "channel"
                | "span"
        )
    })
}

/// Returns `true` if `attr` is a `#[cfg(test)]` attribute (or `#[cfg(all(..., test))]`).
#[must_use]
fn is_cfg_test_attr(attr: &Attribute) -> bool {
    if !attr.path().is_ident("cfg") {
        return false;
    }
    let Ok(tokens) = attr.meta.require_list() else {
        return false;
    };
    let token_str = tokens.tokens.to_string();
    token_str
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == "test")
}

/// Returns `true` if `attrs` contains a test runner attribute (`#[test]`, `#[tokio::test]`, `#[sqlx::test]`, `#[rstest]`, `#[bench]`).
#[must_use]
fn has_test_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path_str = path_to_string(attr.path());
        matches!(
            path_str.as_str(),
            "test" | "tokio::test" | "sqlx::test" | "actix_rt::test" | "rstest" | "bench"
        ) || path_str.ends_with("::test")
    })
}

/// Returns `true` if `attrs` marks an item as test-only (`#[test]`, `#[tokio::test]`, `#[cfg(test)]`, etc.).
#[must_use]
pub(crate) fn attrs_indicate_test_context(attrs: &[Attribute]) -> bool {
    has_test_attr(attrs) || attrs.iter().any(is_cfg_test_attr)
}

#[cfg(test)]
mod tests {
    use dotore_core::{
        ByteSpan, PrescriptionTier, RuleId, RuleSeverity, SourceLoc, compute_line_starts,
    };
    use syn::parse_quote;

    use super::*;

    #[test]
    fn syn_path_type_and_format_macro_matchers_normalize_paths_and_types() {
        let path: syn::Path = parse_quote!(std::mem::forget);
        assert_eq!(path_to_string(&path), "std::mem::forget");

        let ref_ty: Type = parse_quote!(&mut Vec<String>);
        assert_eq!(extract_type_name(&ref_ty).as_deref(), Some("Vec"));

        let bool_ty: Type = parse_quote!(bool);
        assert!(is_bool_type(&bool_ty));
        assert!(!is_bool_type(&ref_ty));

        let fmt_mac: Macro = parse_quote!(format!("hello {}", name));
        assert!(is_format_macro(&fmt_mac));
        let vec_mac: Macro = parse_quote!(vec![1, 2, 3]);
        assert!(!is_format_macro(&vec_mac));
    }

    #[test]
    fn pattern_and_expression_ident_matchers_extract_bindings_and_receivers() {
        let state_pat: Pat = parse_quote!(State(app_state));
        assert_eq!(extract_pat_ident(&state_pat).as_deref(), Some("app_state"));

        let ref_pat: Pat = parse_quote!(&count);
        assert_eq!(extract_pat_ident(&ref_pat).as_deref(), Some("count"));
        let local_stmt: syn::Stmt = parse_quote!(let total: usize = 0;);
        if let syn::Stmt::Local(local) = &local_stmt {
            assert_eq!(extract_pat_ident(&local.pat).as_deref(), Some("total"));
        }

        let expr: Expr = parse_quote!((&self.shared.items));
        assert_eq!(
            extract_receiver_label(&expr).as_deref(),
            Some("self.shared.items")
        );
        assert_eq!(normalize_expr_key(&expr), "self.shared.items");

        let ident_expr: Expr = parse_quote!((&guard));
        assert_eq!(extract_expr_ident(&ident_expr).as_deref(), Some("guard"));
        assert_eq!(
            extract_receiver_ident(&ident_expr).as_deref(),
            Some("guard")
        );
    }

    #[test]
    fn cheap_clone_and_test_attribute_matchers_classify_types_and_test_scopes() {
        let arc_ty: Type = parse_quote!(std::sync::Arc<AppState>);
        let pool_ty: Type = parse_quote!(sqlx::PgPool);
        let string_ty: Type = parse_quote!(String);
        assert!(is_cheap_clone_type(&arc_ty));
        assert!(is_cheap_clone_type(&pool_ty));
        assert!(!is_cheap_clone_type(&string_ty));

        let arc_ctor: Expr = parse_quote!(Arc::new(vec![1, 2, 3]));
        let string_ctor: Expr = parse_quote!(String::from("expensive"));
        assert!(is_cheap_clone_ctor(&arc_ctor));
        assert!(!is_cheap_clone_ctor(&string_ctor));
        assert!(is_cheap_handle_ident("db_pool"));
        assert!(!is_cheap_handle_ident("user_records"));

        let fn_with_tokio_test: ItemFn = parse_quote! {
            #[tokio::test]
            async fn my_async_test() {}
        };
        assert!(has_test_attr(&fn_with_tokio_test.attrs));
        assert!(attrs_indicate_test_context(&fn_with_tokio_test.attrs));

        let mod_with_cfg_test: ItemMod = parse_quote! {
            #[cfg(test)]
            mod unit_suite {}
        };
        assert!(is_cfg_test_attr(&mod_with_cfg_test.attrs[0]));
        assert!(attrs_indicate_test_context(&mod_with_cfg_test.attrs));
    }

    #[test]
    fn rs_scope_tracker_tracks_nested_impl_method_async_loop_and_test_contexts() {
        let mut scope = RsScopeTracker::new();
        assert!(!scope.in_test());
        assert!(!scope.in_async());
        assert!(!scope.in_loop());

        let item_impl: ItemImpl = parse_quote! {
            impl OrderService {
                pub async fn process(&self) {}
            }
        };
        let impl_snap = scope.enter_impl(&item_impl);
        assert_eq!(scope.subject_name().as_deref(), Some("OrderService"));
        assert_eq!(scope.current_parent_type.as_deref(), Some("OrderService"));

        let syn::ImplItem::Fn(method) = &item_impl.items[0] else {
            panic!("Expected ImplItem::Fn");
        };
        let method_snap = scope.enter_method(method);
        assert_eq!(
            scope.subject_name().as_deref(),
            Some("OrderService::process")
        );
        assert!(scope.in_async());
        assert!(!scope.in_loop());

        let loop_snap = scope.enter_loop();
        assert!(scope.in_loop());
        scope.exit(loop_snap);
        assert!(!scope.in_loop());

        scope.exit(method_snap);
        assert_eq!(scope.subject_name().as_deref(), Some("OrderService"));
        assert!(!scope.in_async());

        scope.exit(impl_snap);
        assert_eq!(scope.subject_name(), None);
    }

    #[test]
    fn candidate_finding_builder_converts_to_diagnostic_with_autofix_tier_promotion() {
        let src = "fn demo() {\n    std::thread::sleep(dur);\n}\n";
        let starts = compute_line_starts(src);
        let loc = loc_at(&starts, 16);
        assert_eq!(loc, SourceLoc { line: 2, column: 5 });

        let span = ByteSpan { start: 16, end: 39 };
        assert_eq!(slice_source(src, span), "std::thread::sleep(dur)");

        let patch = AutofixPatch::replace(
            "Replace with tokio::time::sleep",
            span,
            "tokio::time::sleep(dur).await",
        );
        let finding = RsCandidateFinding::new(
            RuleId::RsTokioNoBlockingInAsync,
            Some("demo".to_string()),
            "std::thread::sleep",
            "rsTokioNoBlockingInAsync",
            "Blocking sleep in async",
            loc,
            span,
        )
        .with_patch(patch);

        let diag = finding.to_diagnostic(Path::new("src/demo.rs"), RuleSeverity::Warning);
        assert_eq!(diag.rule, RuleId::RsTokioNoBlockingInAsync);
        assert_eq!(diag.subject_name.as_deref(), Some("demo"));
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert!(diag.autofix.is_some());
    }
}
