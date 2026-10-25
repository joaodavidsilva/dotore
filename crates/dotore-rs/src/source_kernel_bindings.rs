//! 8-hop local `let`/`const` binding resolver (`FnBodyResolver`, `KernelContext`) for `dotore-rs`.

use std::collections::BTreeMap;

use dotore_core::ByteSpan;
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprLit, ExprMethodCall, FnArg, Lit, Macro, Pat,
    Path, PathArguments, Signature, Stmt, Type,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::span_to_bytes,
    source_kernel::{
        BINDING_DEPTH, CHAIN_DEPTH, KNOWN_EXTERNAL_CRATES, NUMERIC_PRIMITIVES, Provenance,
        RsAliasMap, SYSROOT_CRATES,
    },
};

/// What a local identifier holds at a specific site in a function body.
#[derive(Debug, Clone)]
pub(crate) enum LocalBinding {
    /// Initialized by a `let` binding (with optional declared type) or a `const` item.
    Value(Box<(Expr, Option<Type>)>),
    /// Bound by a parameter or `let` whose runtime value is unknown, but whose written `Type` is known.
    Typed(Box<Type>),
    /// Bound locally, but reassigned, shadowed, or destructured via a non-plain pattern.
    Indeterminate,
    /// Neither bound locally nor by a `const` item in the enclosing module.
    Unbound,
}

#[derive(Debug, Clone)]
struct RecordedPat {
    ident_span: ByteSpan,
    is_plain: bool,
    kind: RecordedPatKind,
}

#[derive(Debug, Clone)]
struct RecordedLetPat {
    stmt_span: ByteSpan,
    enclosing_block_span: ByteSpan,
    init: Option<Expr>,
    has_let_else: bool,
    ty: Option<Type>,
}

#[derive(Debug, Clone)]
enum RecordedPatKind {
    Let(Box<RecordedLetPat>),
    Param {
        owner_span: ByteSpan,
        ty: Option<Box<Type>>,
    },
    Other,
}

/// Index of all pattern bindings and assignments inside a single function/method body.
#[derive(Debug, Clone, Default)]
pub(crate) struct FnBodyResolver {
    patterns: BTreeMap<String, Vec<RecordedPat>>,
    assignments: BTreeMap<String, Vec<u32>>,
    pub(crate) macro_writes: Vec<(ByteSpan, Macro)>,
    pub(crate) push_str_calls: Vec<(ByteSpan, String, Expr)>,
    pub(crate) ident_usages: Vec<(String, ByteSpan, IdentUsageKind)>,
}

#[derive(Debug, Clone)]
pub(crate) enum IdentUsageKind {
    PassedAsArg,
    MethodReceiver(String),
}

impl FnBodyResolver {
    /// Indexes a function or method signature and block, skipping nested `Item::Fn` items.
    #[must_use]
    pub(crate) fn build(sig: &Signature, block: &Block) -> Self {
        let mut resolver = Self::default();
        let fn_span = {
            let sig_sp = span_to_bytes(sig.span());
            let blk_sp = span_to_bytes(block.span());
            ByteSpan {
                start: sig_sp.start,
                end: blk_sp.end,
            }
        };

        for input in &sig.inputs {
            if let FnArg::Typed(pat_type) = input {
                let is_top_ident = matches!(
                    pat_type.pat.as_ref(),
                    Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none()
                );
                resolver.collect_pat(
                    &pat_type.pat,
                    &RecordedPatKind::Param {
                        owner_span: fn_span,
                        ty: is_top_ident.then(|| Box::new((*pat_type.ty).clone())),
                    },
                );
            }
        }

        resolver.visit_block_with_enclosing(block);
        resolver
    }

    fn collect_pat(&mut self, pat: &Pat, kind: &RecordedPatKind) {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Pat has many variants; walks nested pattern structures to record all bound identifiers"
        )]
        match pat {
            Pat::Ident(pi) => {
                let is_plain = pi.by_ref.is_none() && pi.subpat.is_none();
                let sp = span_to_bytes(pi.ident.span());
                self.patterns
                    .entry(pi.ident.to_string())
                    .or_default()
                    .push(RecordedPat {
                        ident_span: sp,
                        is_plain,
                        kind: kind.clone(),
                    });
                if let Some((_, sub)) = &pi.subpat {
                    self.collect_pat(sub, &RecordedPatKind::Other);
                }
            }
            Pat::Type(pt) => {
                self.collect_pat(&pt.pat, kind);
            }
            Pat::Tuple(t) => {
                for elem in &t.elems {
                    self.collect_pat(elem, &RecordedPatKind::Other);
                }
            }
            Pat::TupleStruct(ts) => {
                for elem in &ts.elems {
                    self.collect_pat(elem, &RecordedPatKind::Other);
                }
            }
            Pat::Struct(ps) => {
                for f in &ps.fields {
                    self.collect_pat(&f.pat, &RecordedPatKind::Other);
                }
            }
            Pat::Slice(sl) => {
                for elem in &sl.elems {
                    self.collect_pat(elem, &RecordedPatKind::Other);
                }
            }
            Pat::Reference(r) => {
                self.collect_pat(&r.pat, &RecordedPatKind::Other);
            }
            Pat::Or(or_pat) => {
                for case in &or_pat.cases {
                    self.collect_pat(case, &RecordedPatKind::Other);
                }
            }
            Pat::Paren(p) => {
                self.collect_pat(&p.pat, kind);
            }
            _ => {}
        }
    }

    fn visit_block_with_enclosing(&mut self, block: &Block) {
        let block_span = span_to_bytes(block.span());
        for stmt in &block.stmts {
            match stmt {
                Stmt::Local(local) => {
                    self.visit_local_stmt(local, block_span);
                }
                Stmt::Item(_) => {
                    // Nested fn/struct/mod items have their own scope; skip
                }
                Stmt::Expr(expr, _) => {
                    self.visit_expr(expr);
                }
                Stmt::Macro(stmt_mac) => {
                    let sp = span_to_bytes(stmt_mac.span());
                    self.macro_writes.push((sp, stmt_mac.mac.clone()));
                }
            }
        }
    }
    fn visit_local_stmt(&mut self, local: &syn::Local, block_span: ByteSpan) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, div)) = &init.diverge {
                self.visit_expr(div);
            }
        }
        let (inner_pat, ty) = if let Pat::Type(pt) = &local.pat {
            (pt.pat.as_ref(), Some((*pt.ty).clone()))
        } else {
            (&local.pat, None)
        };
        let is_top_plain =
            matches!(inner_pat, Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none());
        let stmt_span = span_to_bytes(local.span());
        let kind = if is_top_plain {
            RecordedPatKind::Let(Box::new(RecordedLetPat {
                stmt_span,
                enclosing_block_span: block_span,
                init: local.init.as_ref().map(|i| (*i.expr).clone()),
                has_let_else: local
                    .init
                    .as_ref()
                    .is_some_and(|i| i.diverge.is_some()),
                ty,
            }))
        } else {
            RecordedPatKind::Other
        };
        self.collect_pat(inner_pat, &kind);
    }

    fn nearest_pat(&self, site: ByteSpan, name: &str) -> Option<&RecordedPat> {
        self.patterns.get(name)?.iter().rev().find(|pat| {
            pat.ident_span.start < site.start
                && !matches!(
                    &pat.kind,
                    RecordedPatKind::Let(let_pat)
                        if let_pat.stmt_span.start <= site.start && site.end <= let_pat.stmt_span.end
                )
        })
    }

    /// Returns `true` if `name` is bound by any local `let`, parameter, or closure parameter before `site`.
    #[must_use]
    pub(crate) fn is_bound_locally(&self, site: ByteSpan, name: &str) -> bool {
        self.nearest_pat(site, name).is_some()
    }

    /// Resolves the [`LocalBinding`] of `name` at `site`.
    #[must_use]
    pub(crate) fn resolve_binding(
        &self,
        aliases: &RsAliasMap,
        site: ByteSpan,
        name: &str,
    ) -> LocalBinding {
        let Some(pat) = self.nearest_pat(site, name) else {
            return aliases.resolve_const(site, name);
        };
        let typed_fallback = |ty: Option<Type>| {
            if pat.is_plain
                && let Some(t) = ty
            {
                LocalBinding::Typed(Box::new(t))
            } else {
                LocalBinding::Indeterminate
            }
        };
        match &pat.kind {
            RecordedPatKind::Let(let_pat) => {
                if !(let_pat.enclosing_block_span.start <= site.start
                    && site.end <= let_pat.enclosing_block_span.end)
                {
                    return LocalBinding::Indeterminate;
                }
                let Some(init_expr) = &let_pat.init else {
                    return typed_fallback(let_pat.ty.clone());
                };
                let reassigned = self
                    .assignments
                    .get(name)
                    .is_some_and(|starts| starts.iter().any(|&s| s >= let_pat.stmt_span.end));
                if !pat.is_plain || let_pat.has_let_else || reassigned {
                    return typed_fallback(let_pat.ty.clone());
                }
                LocalBinding::Value(Box::new((init_expr.clone(), let_pat.ty.clone())))
            }
            RecordedPatKind::Param { owner_span, ty } => {
                if owner_span.start <= site.start && site.end <= owner_span.end {
                    typed_fallback(ty.as_deref().cloned())
                } else {
                    LocalBinding::Indeterminate
                }
            }
            RecordedPatKind::Other => LocalBinding::Indeterminate,
        }
    }
}

impl<'ast> Visit<'ast> for FnBodyResolver {
    fn visit_item(&mut self, _i: &'ast syn::Item) {
        // Do not descend into nested items inside a function body
    }

    fn visit_block(&mut self, b: &'ast Block) {
        self.visit_block_with_enclosing(b);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let closure_span = span_to_bytes(node.span());
        for input in &node.inputs {
            let (inner_pat, ty) = if let Pat::Type(pt) = input {
                (pt.pat.as_ref(), Some(Box::new((*pt.ty).clone())))
            } else {
                (input, None)
            };
            let is_top_plain =
                matches!(inner_pat, Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none());
            self.collect_pat(
                inner_pat,
                &RecordedPatKind::Param {
                    owner_span: closure_span,
                    ty: is_top_plain.then_some(ty).flatten(),
                },
            );
        }
        self.visit_expr(&node.body);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.visit_expr(&node.expr);
        self.collect_pat(&node.pat, &RecordedPatKind::Other);
        self.visit_block_with_enclosing(&node.body);
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        self.visit_expr(&node.expr);
        self.collect_pat(&node.pat, &RecordedPatKind::Other);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        self.collect_pat(&node.pat, &RecordedPatKind::Other);
        if let Some((_, guard)) = &node.guard {
            self.visit_expr(guard);
        }
        self.visit_expr(&node.body);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(ident) = bare_identifier(&node.left) {
            let sp = span_to_bytes(node.span());
            self.assignments.entry(ident).or_default().push(sp.start);
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if is_compound_assignment_op(&node.op)
            && let Some(ident) = bare_identifier(&node.left)
        {
            let sp = span_to_bytes(node.span());
            self.assignments.entry(ident).or_default().push(sp.start);
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        for arg in &node.args {
            if let Some(ident) = bare_identifier(strip_wrappers(arg)) {
                let sp = span_to_bytes(arg.span());
                self.ident_usages
                    .push((ident, sp, IdentUsageKind::PassedAsArg));
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if let Some(recv_ident) = bare_identifier(strip_wrappers(&node.receiver)) {
            let recv_sp = span_to_bytes(node.receiver.span());
            self.ident_usages.push((
                recv_ident.clone(),
                recv_sp,
                IdentUsageKind::MethodReceiver(method_name.clone()),
            ));
            if method_name == "push_str"
                && node.args.len() == 1
                && let Some(arg) = node.args.first()
            {
                let call_sp = span_to_bytes(node.span());
                self.push_str_calls
                    .push((call_sp, recv_ident, arg.clone()));
            }
        }
        for arg in &node.args {
            if let Some(ident) = bare_identifier(strip_wrappers(arg)) {
                let sp = span_to_bytes(arg.span());
                self.ident_usages
                    .push((ident, sp, IdentUsageKind::PassedAsArg));
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let sp = span_to_bytes(node.span());
        self.macro_writes.push((sp, node.mac.clone()));
        visit::visit_expr_macro(self, node);
    }
}

fn is_compound_assignment_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::BitXorAssign(_)
            | BinOp::BitAndAssign(_)
            | BinOp::BitOrAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

/// Unwraps parentheses, groups, and shared/mutable reference wrappers from `expr`.
#[must_use]
pub(crate) fn strip_wrappers(mut expr: &Expr) -> &Expr {
    loop {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only Paren, Group, and Reference expressions wrap an inner expression transparently"
        )]
        match expr {
            Expr::Paren(p) => expr = &p.expr,
            Expr::Group(g) => expr = &g.expr,
            Expr::Reference(r) => expr = &r.expr,
            _ => return expr,
        }
    }
}

/// Unwraps parentheses and groups from `expr`.
#[must_use]
pub(crate) fn strip_parens(mut expr: &Expr) -> &Expr {
    loop {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only Paren and Group expressions are unwrapped here"
        )]
        match expr {
            Expr::Paren(p) => expr = &p.expr,
            Expr::Group(g) => expr = &g.expr,
            _ => return expr,
        }
    }
}

/// Extracts a bare single-segment identifier from `expr` (no path qualifier, no generic arguments).
#[must_use]
pub(crate) fn bare_identifier(expr: &Expr) -> Option<String> {
    let Expr::Path(ep) = expr else {
        return None;
    };
    if ep.qself.is_some() || ep.path.leading_colon.is_some() || ep.path.segments.len() != 1 {
        return None;
    }
    let seg = ep.path.segments.first()?;
    if !matches!(seg.arguments, PathArguments::None) {
        return None;
    }
    Some(seg.ident.to_string())
}

/// Extracts the segment identifiers of `path` when every segment is a plain identifier
/// (allowing angle-bracketed generic arguments on segments, e.g. `query_as::<_, User>`).
#[must_use]
fn item_segments(path: &Path) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(path.segments.len());
    for seg in &path.segments {
        let name = seg.ident.to_string();
        if matches!(name.as_str(), "self" | "super" | "crate" | "Self") {
            return None;
        }
        if matches!(seg.arguments, PathArguments::Parenthesized(_)) {
            return None;
        }
        out.push(name);
    }
    (!out.is_empty()).then_some(out)
}

/// Extracts the segment identifiers of `path` only when no segment carries generic arguments.
#[must_use]
fn plain_segments(path: &Path) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(path.segments.len());
    for seg in &path.segments {
        if !matches!(seg.arguments, PathArguments::None) {
            return None;
        }
        let name = seg.ident.to_string();
        if matches!(name.as_str(), "self" | "super" | "crate" | "Self") {
            return None;
        }
        out.push(name);
    }
    (!out.is_empty()).then_some(out)
}

/// Returns `true` if `name` is `SCREAMING_SNAKE_CASE` (at least one ASCII uppercase letter, all chars uppercase/digit/`_`).
#[must_use]
fn is_screaming_snake_case(name: &str) -> bool {
    name.chars().any(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Extracts a literal `bool` value if `expr` is `true` or `false`.
#[must_use]
pub(crate) fn literal_bool(expr: &Expr, expected: bool) -> bool {
    matches!(
        strip_wrappers(expr),
        Expr::Lit(ExprLit {
            lit: Lit::Bool(b),
            ..
        }) if b.value == expected
    )
}

/// Extracts a string literal value if `expr` is a `Lit::Str`.
#[must_use]
pub(crate) fn literal_string(expr: &Expr) -> Option<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = strip_wrappers(expr)
    {
        Some(s.value())
    } else {
        None
    }
}

/// Context combining [`RsAliasMap`] and an optional active [`FnBodyResolver`] for a function/method body.
pub(crate) struct KernelContext<'a> {
    pub aliases: &'a RsAliasMap,
    pub body: Option<&'a FnBodyResolver>,
}

impl<'a> KernelContext<'a> {
    /// Creates a [`KernelContext`] with `aliases` and an optional [`FnBodyResolver`].
    #[must_use]
    pub(crate) const fn new(aliases: &'a RsAliasMap, body: Option<&'a FnBodyResolver>) -> Self {
        Self { aliases, body }
    }

    /// Resolves a `syn::Path` at `site` to `(canonical_segments, optional_written_crate_root_if_potentially_renamed)`.
    #[must_use]
    pub(crate) fn resolve_item_path(&self, path: &Path) -> Option<(Vec<String>, Option<String>)> {
        let written = item_segments(path)?;
        let (first, tail) = written.split_first()?;
        let site = span_to_bytes(path.span());
        let resolved: Vec<String> = match self.aliases.provenance(site, first) {
            Provenance::Item(item) => item.iter().chain(tail).cloned().collect(),
            Provenance::Unbound => written.clone(),
            Provenance::GlobMasked(heads)
                if is_known_crate(first) && heads.iter().all(|h| h.is_some_and(is_known_crate)) =>
            {
                written.clone()
            }
            Provenance::GlobMasked(_) | Provenance::Indeterminate => return None,
        };
        let (root, _) = resolved.split_first()?;
        let normalized_root = root.replace('-', "_");
        if SYSROOT_CRATES.contains(&normalized_root.as_str())
            || KNOWN_EXTERNAL_CRATES.contains(&normalized_root.as_str())
        {
            Some((resolved, None))
        } else {
            Some((resolved.clone(), Some(root.clone())))
        }
    }

    /// Checks whether `callee` resolves to `expected_crate::expected_segments::expected_member`.
    #[must_use]
    pub(crate) fn matches_call_path(
        &self,
        callee: &Expr,
        expected_crate: &str,
        expected_segments: &[&str],
        expected_member: &str,
    ) -> Option<Option<(String, String)>> {
        let Expr::Path(ep) = strip_parens(callee) else {
            return None;
        };
        if ep.qself.is_some() {
            return None;
        }
        let (resolved, maybe_renamed_root) = self.resolve_item_path(&ep.path)?;
        let (krate, rest) = resolved.split_first()?;
        let (last, mid) = rest.split_last()?;
        if last != expected_member || mid != expected_segments {
            return None;
        }
        if krate == expected_crate {
            Some(None)
        } else if !SYSROOT_CRATES.contains(&expected_crate)
            && let Some(written_root) = maybe_renamed_root
        {
            Some(Some((written_root, expected_crate.to_string())))
        } else {
            None
        }
    }

    /// Checks whether `callee` resolves to any of `paths` (where each path is `[crate, seg1, ..., member]`).
    #[must_use]
    pub(crate) fn matches_any_path(
        &self,
        callee: &Expr,
        paths: &[&[&str]],
    ) -> Option<Option<(String, String)>> {
        for path in paths {
            let Some((expected_crate, rest)) = path.split_first() else {
                continue;
            };
            let Some((expected_member, expected_mid)) = rest.split_last() else {
                continue;
            };
            if let Some(rename_req) =
                self.matches_call_path(callee, expected_crate, expected_mid, expected_member)
            {
                return Some(rename_req);
            }
        }
        None
    }

    /// Follows local `let` and `const` bindings up to `BINDING_DEPTH = 8` hops from `expr`.
    #[must_use]
    pub(crate) fn resolve_value(&self, expr: &Expr) -> Option<Expr> {
        let mut current = expr.clone();
        for _ in 0..BINDING_DEPTH {
            current = strip_parens(&current).clone();
            let Some(name) = bare_identifier(&current) else {
                return Some(current);
            };
            let site = span_to_bytes(current.span());
            let binding = if let Some(body) = self.body {
                body.resolve_binding(self.aliases, site, &name)
            } else {
                self.aliases.resolve_const(site, &name)
            };
            match binding {
                LocalBinding::Value(boxed) => current = boxed.0,
                LocalBinding::Unbound => return Some(current),
                LocalBinding::Typed(_) | LocalBinding::Indeterminate => return None,
            }
        }
        None
    }

    /// Unwinds `.method(...)`, `?`, and `.await` links through up to 8 local `let` bindings to find the chain root expression.
    #[must_use]
    pub(crate) fn chain_root(&self, expr: &Expr) -> Option<Expr> {
        let mut current = expr.clone();
        for _ in 0..CHAIN_DEPTH {
            let unwrapped = strip_wrappers(&current).clone();
            let resolved = self.resolve_value(&unwrapped)?;
            #[expect(
                clippy::wildcard_enum_match_arm,
                reason = "Unwinds MethodCall, Try (`?`), and Await (`.await`) links; any other expression is the chain root"
            )]
            match strip_wrappers(&resolved) {
                Expr::MethodCall(mc) => current = (*mc.receiver).clone(),
                Expr::Try(tr) => current = (*tr.expr).clone(),
                Expr::Await(aw) => current = (*aw.base).clone(),
                other => return Some(other.clone()),
            }
        }
        None
    }

    /// Returns `true` if `expr` is a compile-time constant.
    #[must_use]
    fn is_constant(&self, expr: &Expr) -> bool {
        let Some(resolved) = self.resolve_value(strip_wrappers(expr)) else {
            return false;
        };
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only literals, constant + concatenations, string conversions on constants, and SCREAMING_SNAKE_CASE paths are compile-time constants"
        )]
        match strip_wrappers(&resolved) {
            Expr::Lit(_) => true,
            Expr::Binary(bin) => {
                matches!(bin.op, BinOp::Add(_))
                    && self.is_constant(&bin.left)
                    && self.is_constant(&bin.right)
            }
            Expr::MethodCall(mc) => {
                matches!(
                    mc.method.to_string().as_str(),
                    "to_owned" | "to_string" | "into"
                ) && mc.args.is_empty()
                    && self.is_constant(&mc.receiver)
            }
            Expr::Path(ep) if ep.qself.is_none() => plain_segments(&ep.path)
                .and_then(|segs| segs.last().cloned())
                .is_some_and(|name| is_screaming_snake_case(&name)),
            _ => false,
        }
    }

    /// Returns `true` if `ty` at `site` is a non-shadowed numeric/boolean/char primitive or `std::num::NonZero*`.
    #[must_use]
    fn is_numeric_type(&self, ty: &Type, site: ByteSpan) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Checks Reference, Paren, Group, and Path types for unshadowed primitive numeric types and NonZero*"
        )]
        match ty {
            Type::Reference(r) => self.is_numeric_type(&r.elem, site),
            Type::Paren(p) => self.is_numeric_type(&p.elem, site),
            Type::Group(g) => self.is_numeric_type(&g.elem, site),
            Type::Path(tp) if tp.qself.is_none() => {
                if let Some(segs) = plain_segments(&tp.path)
                    && let [name] = segs.as_slice()
                    && NUMERIC_PRIMITIVES.contains(&name.as_str())
                {
                    return self.aliases.provenance(site, name) == Provenance::Unbound;
                }
                self.resolve_item_path(&tp.path)
                    .is_some_and(|(resolved, _)| {
                        matches!(
                            resolved.as_slice(),
                            [krate, module, kind]
                                if matches!(krate.as_str(), "core" | "std")
                                    && module == "num"
                                    && kind.starts_with("NonZero")
                        )
                    })
            }
            _ => false,
        }
    }

    /// Returns `true` if `expr` is known by syntax/type annotations to be a numeric/boolean primitive.
    #[must_use]
    fn is_numeric_expr(&self, expr: &Expr, site: ByteSpan) -> bool {
        let mut current = strip_wrappers(expr).clone();
        for _ in 0..BINDING_DEPTH {
            if let Expr::Cast(cast) = &current {
                return self.is_numeric_type(&cast.ty, site);
            }
            let Some(name) = bare_identifier(&current) else {
                return false;
            };
            let lookup_site = {
                let sp = span_to_bytes(current.span());
                if sp.start == 0 && sp.end == 0 {
                    site
                } else {
                    sp
                }
            };
            let binding = if let Some(body) = self.body {
                body.resolve_binding(self.aliases, lookup_site, &name)
            } else {
                self.aliases.resolve_const(lookup_site, &name)
            };
            match binding {
                LocalBinding::Value(boxed) => {
                    if let Some(ty) = &boxed.1 {
                        return self.is_numeric_type(ty, site);
                    }
                    current = strip_wrappers(&boxed.0).clone();
                }
                LocalBinding::Typed(ty) => return self.is_numeric_type(&ty, site),
                LocalBinding::Unbound | LocalBinding::Indeterminate => return false,
            }
        }
        false
    }

    /// Returns `true` if `expr` can carry attacker-controlled non-numeric text into a formatted string.
    #[must_use]
    fn is_injectable(&self, expr: &Expr, site: ByteSpan) -> bool {
        !self.is_constant(expr) && !self.is_numeric_expr(expr, site)
    }

    /// Returns `true` if a captured identifier `{name}` inside a format string at `site` is injectable.
    #[must_use]
    fn is_injectable_capture(&self, site: ByteSpan, name: &str) -> bool {
        let binding = if let Some(body) = self.body {
            body.resolve_binding(self.aliases, site, name)
        } else {
            self.aliases.resolve_const(site, name)
        };
        match binding {
            LocalBinding::Value(boxed) => {
                self.is_injectable(&boxed.0, site)
                    && !boxed.1.as_ref().is_some_and(|ty| self.is_numeric_type(ty, site))
            }
            LocalBinding::Typed(ty) => !self.is_numeric_type(&ty, site),
            LocalBinding::Unbound => !is_screaming_snake_case(name),
            LocalBinding::Indeterminate => true,
        }
    }

    /// Returns `true` if `expr` (resolved through `let` bindings) is dynamically assembled via `format!` or `+`
    /// with at least one injectable operand.
    #[must_use]
    pub(crate) fn is_dynamic_text(&self, expr: &Expr) -> bool {
        let Some(resolved) = self.resolve_value(strip_wrappers(expr)) else {
            return false;
        };
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Dynamic text is assembled either via binary `+` or `format!(...)` macro calls"
        )]
        match strip_wrappers(&resolved) {
            Expr::Binary(bin) => {
                let site = span_to_bytes(bin.span());
                matches!(bin.op, BinOp::Add(_)) && self.is_injectable(&resolved, site)
            }
            Expr::Macro(expr_mac) => self.is_format_macro_dynamic(&expr_mac.mac),
            _ => false,
        }
    }

    /// Returns `true` if `mac` is a `format!(...)` invocation that interpolates at least one injectable value.
    #[must_use]
    fn is_format_macro_dynamic(&self, mac: &Macro) -> bool {
        if !mac.path.is_ident("format") {
            return false;
        }
        let site = span_to_bytes(mac.span());
        let Some(args) = parse_macro_expr_args(mac) else {
            return false;
        };
        self.formats_dynamic_args(site, args.into_iter())
    }

    /// If `mac` is `write!(dest, ...)` or `writeln!(dest, ...)` with dynamic injectable arguments,
    /// returns `Some(dest_ident)`.
    #[must_use]
    fn written_dynamic_dest(&self, mac: &Macro) -> Option<String> {
        if !mac.path.is_ident("write") && !mac.path.is_ident("writeln") {
            return None;
        }
        let site = span_to_bytes(mac.span());
        let mut args = parse_macro_expr_args(mac)?.into_iter();
        let dest = bare_identifier(strip_wrappers(&args.next()?))?;
        self.formats_dynamic_args(site, args).then_some(dest)
    }

    fn formats_dynamic_args(
        &self,
        site: ByteSpan,
        mut args: impl Iterator<Item = Expr>,
    ) -> bool {
        let Some(fmt_str) = args.next().and_then(|e| literal_string(&e)) else {
            return false;
        };
        let fields = extract_format_fields(&fmt_str);
        if fields.is_empty() {
            return false;
        }

        let is_arg_constant = |arg: &Expr| match bare_identifier(strip_wrappers(arg)) {
            Some(name) => !self.is_injectable_capture(site, &name),
            None => !self.is_injectable(arg, site),
        };

        let mut positional = Vec::new();
        let mut named = BTreeMap::new();
        for arg in args {
            if let Some((name, val)) = extract_named_format_arg(&arg) {
                named.insert(name, is_arg_constant(&val));
            } else {
                positional.push(is_arg_constant(&arg));
            }
        }

        let mut next_pos = 0;
        fields.into_iter().any(|field| {
            let key = field.split(':').next().unwrap_or_default();
            if key.is_empty() {
                let is_const = positional.get(next_pos).copied().unwrap_or(true);
                next_pos += 1;
                !is_const
            } else if let Ok(idx) = key.parse::<usize>() {
                !positional.get(idx).copied().unwrap_or(true)
            } else {
                !named
                    .get(key)
                    .copied()
                    .unwrap_or_else(|| !self.is_injectable_capture(site, key))
            }
        })
    }

    /// Returns `true` if `text` is a local variable that had dynamic text appended to it via `.push_str(...)`
    /// or `write!(...)` / `writeln!(...)` prior to being read.
    #[must_use]
    pub(crate) fn is_pushed_or_written_dynamic(&self, text: &Expr) -> bool {
        let Some(name) = bare_identifier(text) else {
            return false;
        };
        if self.resolve_value(text).is_none() {
            return false;
        }
        let Some(body) = self.body else {
            return false;
        };
        let read_start = span_to_bytes(text.span()).start;
        let site = span_to_bytes(text.span());

        let written = body.macro_writes.iter().any(|(mac_span, mac)| {
            mac_span.end <= read_start
                && self
                    .written_dynamic_dest(mac)
                    .is_some_and(|dest| dest == name)
        });
        let grown = body
            .push_str_calls
            .iter()
            .any(|(call_span, recv_name, arg)| {
                call_span.end <= read_start
                    && *recv_name == name
                    && self.is_injectable(arg, site)
            });
        written || grown
    }
}

fn is_known_crate(name: &str) -> bool {
    let norm = name.replace('-', "_");
    SYSROOT_CRATES.contains(&norm.as_str()) || KNOWN_EXTERNAL_CRATES.contains(&norm.as_str())
}

fn parse_macro_expr_args(mac: &Macro) -> Option<Vec<Expr>> {
    let tokens = &mac.tokens;
    let wrapped = format!("__dotore_fmt_call({tokens})");
    let Expr::Call(call) = syn::parse_str::<Expr>(&wrapped).ok()? else {
        return None;
    };
    Some(call.args.into_iter().collect())
}

fn extract_named_format_arg(expr: &Expr) -> Option<(String, Expr)> {
    if let Expr::Assign(assign) = expr
        && let Some(name) = bare_identifier(&assign.left)
    {
        return Some((name, (*assign.right).clone()));
    }
    None
}

fn extract_format_fields(format_str: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = format_str.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '{' {
            continue;
        }
        if chars.peek().is_some_and(|(_, next)| *next == '{') {
            chars.next();
            continue;
        }
        let mut field = String::new();
        for (_, inner) in chars.by_ref() {
            if inner == '}' {
                fields.push(field);
                break;
            }
            field.push(inner);
        }
    }
    fields
}
