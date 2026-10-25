//! Canonical AST subtree normalization and Sørensen-Dice near-duplicate function detection
//! (`rs-structure-near-duplicate-function`, [`RuleId::RsStructureNearDuplicateFunction`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use dotore_core::{
    ByteSpan, ExtractedFile, FileContext, ResolvedCallerSite, RuleId, SourceLoc, WorkspacePackage,
};
use syn::{
    Arm, BinOp, Block, Expr, File, FnArg, GenericArgument, ImplItemFn, ItemFn, ItemImpl, ItemMod,
    ItemTrait, Lit, Member, Pat, PathArguments, ReturnType, Signature, Stmt, TraitItemFn, Type,
    UnOp,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{RsCandidateFinding, RsScopeTracker, loc_at, path_to_string, span_to_bytes};

/// Minimum number of normalized AST subtree nodes required before a function is eligible for duplication analysis.
const MINIMUM_NODES: usize = 30;

/// Minimum number of top-level statements in a function body required for duplication analysis.
const MINIMUM_STATEMENTS: usize = 3;

/// Sørensen-Dice similarity threshold in basis points (`8000` = `80.00%`).
const NEAR_DUPLICATE_THRESHOLD_BPS: u16 = 8_000;

/// Number of rarest subtree shingle hashes indexed per representative shape.
const HEAD_TOKENS: usize = 16;

/// Seed for 64-bit subtree shingle hashing.
const SEED: u64 = 0xcbf2_9ce4_8422_2325;

/// Normalized representation of a single non-test function or method in a `.rs` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFnIr {
    /// Function or qualified method name (`foo` or `Order::validate`).
    pub name: String,
    /// Whether this method is inside a trait implementation (`impl Trait for Type`).
    pub is_trait_impl_method: bool,
    /// 1-based start location of the function item.
    pub loc: SourceLoc,
    /// 0-based byte span of the function item.
    pub span: ByteSpan,
    /// Number of top-level statements in the function body.
    pub statements: usize,
    /// 128-bit digest of the canonical text representation.
    pub digest: u128,
    /// Sorted multiset of 64-bit subtree shingle hashes (length == normalized node count).
    pub shingles: Vec<u64>,
}

/// Extracts all eligible [`NormalizedFnIr`] entries from `ast`.
#[must_use]
pub(crate) fn extract_normalized_functions(ast: &File, line_starts: &[u32]) -> Vec<NormalizedFnIr> {
    let mut collector = DuplicationAstCollector {
        line_starts,
        scope: RsScopeTracker::for_file(ast),
        in_trait_impl: false,
        functions: Vec::new(),
    };
    collector.visit_file(ast);
    collector.functions
}

struct DuplicationAstCollector<'a> {
    line_starts: &'a [u32],
    scope: RsScopeTracker,
    in_trait_impl: bool,
    functions: Vec<NormalizedFnIr>,
}

impl DuplicationAstCollector<'_> {
    fn record_fn(
        &mut self,
        name: String,
        sig: &Signature,
        block: &Block,
        item_span: proc_macro2::Span,
    ) {
        if self.scope.in_test() {
            return;
        }
        let statements = block.stmts.len();
        if statements < MINIMUM_STATEMENTS {
            return;
        }
        let normalized = normalize_syn_function(sig, block);
        if normalized.shingles.len() < MINIMUM_NODES {
            return;
        }
        let span = span_to_bytes(item_span);
        let loc = loc_at(self.line_starts, span.start);
        self.functions.push(NormalizedFnIr {
            name,
            is_trait_impl_method: self.in_trait_impl,
            loc,
            span,
            statements,
            digest: normalized.digest,
            shingles: normalized.shingles,
        });
    }
}

impl<'ast> Visit<'ast> for DuplicationAstCollector<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        let snap = self.scope.enter_trait(i);
        visit::visit_item_trait(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        let prev_trait = std::mem::replace(&mut self.in_trait_impl, i.trait_.is_some());
        visit::visit_item_impl(self, i);
        self.in_trait_impl = prev_trait;
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let name = self
            .scope
            .subject_name()
            .unwrap_or_else(|| i.sig.ident.to_string());
        self.record_fn(name, &i.sig, &i.block, i.span());
        visit::visit_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let name = self
            .scope
            .subject_name()
            .unwrap_or_else(|| i.sig.ident.to_string());
        self.record_fn(name, &i.sig, &i.block, i.span());
        visit::visit_impl_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        if let Some(block) = &i.default {
            let name = self
                .scope
                .subject_name()
                .unwrap_or_else(|| i.sig.ident.to_string());
            self.record_fn(name, &i.sig, block, i.span());
        }
        visit::visit_trait_item_fn(self, i);
        self.scope.exit(snap);
    }
}

struct CanonicalOutput {
    digest: u128,
    shingles: Vec<u64>,
}

#[derive(Default)]
struct SynCanonicalNormalizer {
    text: String,
    placeholders: HashMap<String, usize>,
    shingles: Vec<u64>,
}

impl SynCanonicalNormalizer {
    fn placeholder(&mut self, ident: &str, hash: u64) -> u64 {
        let next = self.placeholders.len();
        let idx = *self.placeholders.entry(ident.to_owned()).or_insert(next);
        self.text.push_str(&format!(" ${idx}"));
        mix(hash, idx as u64)
    }

    fn record_node(&mut self, tag: &'static str, build_children: impl FnOnce(&mut Self, u64) -> u64) -> u64 {
        self.text.push('(');
        self.text.push_str(tag);
        let base = mix_text(SEED, tag);
        let hash = build_children(self, base);
        self.text.push(')');
        self.shingles.push(hash);
        hash
    }

    fn norm_sig(&mut self, sig: &Signature) -> u64 {
        self.record_node("Sig", |this, mut h| {
            let fn_name = sig.ident.to_string();
            h = this.placeholder(&fn_name, h);
            if sig.asyncness.is_some() {
                this.text.push_str(" async");
                h = mix_text(h, "async");
            }
            if sig.unsafety.is_some() {
                this.text.push_str(" unsafe");
                h = mix_text(h, "unsafe");
            }
            for input in &sig.inputs {
                let ch = this.norm_fn_arg(input);
                h = mix(h, ch);
            }
            match &sig.output {
                ReturnType::Default => {
                    this.text.push_str(" ->()");
                    h = mix_text(h, "->()");
                }
                ReturnType::Type(_, ty) => {
                    let ch = this.norm_type(ty);
                    h = mix(h, ch);
                }
            }
            h
        })
    }

    fn norm_fn_arg(&mut self, arg: &FnArg) -> u64 {
        match arg {
            FnArg::Receiver(recv) => self.record_node("Recv", |this, mut h| {
                if recv.reference.is_some() {
                    this.text.push_str(" &");
                    h = mix_text(h, "&");
                }
                if recv.mutability.is_some() {
                    this.text.push_str(" mut");
                    h = mix_text(h, "mut");
                }
                this.placeholder("self", h)
            }),
            FnArg::Typed(pt) => self.record_node("Param", |this, mut h| {
                let ph = this.norm_pat(&pt.pat);
                let th = this.norm_type(&pt.ty);
                h = mix(h, ph);
                mix(h, th)
            }),
        }
    }

    fn norm_type(&mut self, ty: &Type) -> u64 {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Type has many variants; normalizes structural type constructors and identifiers"
        )]
        match ty {
            Type::Reference(r) => self.record_node("TyRef", |this, mut h| {
                if r.mutability.is_some() {
                    this.text.push_str(" mut");
                    h = mix_text(h, "mut");
                }
                let inner = this.norm_type(&r.elem);
                mix(h, inner)
            }),
            Type::Slice(s) => self.record_node("TySlice", |this, h| {
                let inner = this.norm_type(&s.elem);
                mix(h, inner)
            }),
            Type::Array(a) => self.record_node("TyArray", |this, mut h| {
                let inner = this.norm_type(&a.elem);
                let len_h = this.norm_expr(&a.len);
                h = mix(h, inner);
                mix(h, len_h)
            }),
            Type::Tuple(t) => self.record_node("TyTuple", |this, mut h| {
                for elem in &t.elems {
                    let ch = this.norm_type(elem);
                    h = mix(h, ch);
                }
                h
            }),
            Type::Path(tp) => self.record_node("TyPath", |this, mut h| {
                for seg in &tp.path.segments {
                    let name = seg.ident.to_string();
                    h = this.placeholder(&name, h);
                    if let PathArguments::AngleBracketed(ab) = &seg.arguments {
                        h = this.norm_angle_bracketed_args(ab, h);
                    }
                }
                h
            }),
            _ => self.record_node("TyOther", |_, h| h),
        }
    }

    fn norm_angle_bracketed_args(
        &mut self,
        ab: &syn::AngleBracketedGenericArguments,
        mut h: u64,
    ) -> u64 {
        for arg in &ab.args {
            if let GenericArgument::Type(inner_ty) = arg {
                let ch = self.norm_type(inner_ty);
                h = mix(h, ch);
            }
        }
        h
    }

    fn norm_pat(&mut self, pat: &Pat) -> u64 {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Pat has many variants; normalizes bindings, tuples, slices, structs, and literals"
        )]
        match pat {
            Pat::Ident(pi) => self.record_node("PatIdent", |this, mut h| {
                if pi.mutability.is_some() {
                    this.text.push_str(" mut");
                    h = mix_text(h, "mut");
                }
                let name = pi.ident.to_string();
                this.placeholder(&name, h)
            }),
            Pat::Wild(_) => self.record_node("PatWild", |_, h| mix_text(h, "_")),
            Pat::Tuple(pt) => self.record_node("PatTuple", |this, mut h| {
                for el in &pt.elems {
                    let ch = this.norm_pat(el);
                    h = mix(h, ch);
                }
                h
            }),
            Pat::TupleStruct(pts) => self.record_node("PatTupleStruct", |this, mut h| {
                for seg in &pts.path.segments {
                    h = this.placeholder(&seg.ident.to_string(), h);
                }
                for el in &pts.elems {
                    let ch = this.norm_pat(el);
                    h = mix(h, ch);
                }
                h
            }),
            Pat::Struct(ps) => self.record_node("PatStruct", |this, mut h| {
                for seg in &ps.path.segments {
                    h = this.placeholder(&seg.ident.to_string(), h);
                }
                for f in &ps.fields {
                    let ch = this.norm_pat(&f.pat);
                    h = mix(h, ch);
                }
                h
            }),
            Pat::Reference(pr) => self.record_node("PatRef", |this, h| {
                let ch = this.norm_pat(&pr.pat);
                mix(h, ch)
            }),
            Pat::Type(pt) => self.record_node("PatType", |this, mut h| {
                let ph = this.norm_pat(&pt.pat);
                let th = this.norm_type(&pt.ty);
                h = mix(h, ph);
                mix(h, th)
            }),
            Pat::Lit(pl) => self.record_node("PatLit", |this, h| {
                let tag = literal_tag(&pl.lit);
                this.text.push(' ');
                this.text.push_str(tag);
                mix_text(h, tag)
            }),
            _ => self.record_node("PatOther", |_, h| h),
        }
    }

    fn norm_block(&mut self, block: &Block) -> u64 {
        self.record_node("Block", |this, mut h| {
            for stmt in &block.stmts {
                let ch = this.norm_stmt(stmt);
                h = mix(h, ch);
            }
            h
        })
    }

    fn norm_stmt(&mut self, stmt: &Stmt) -> u64 {
        match stmt {
            Stmt::Local(local) => self.record_node("Local", |this, mut h| {
                let ph = this.norm_pat(&local.pat);
                h = mix(h, ph);
                if let Some(init) = &local.init {
                    let eh = this.norm_expr(&init.expr);
                    h = mix(h, eh);
                    if let Some((_, div)) = &init.diverge {
                        let dh = this.norm_expr(div);
                        h = mix(h, dh);
                    }
                }
                h
            }),
            Stmt::Item(_) => self.record_node("StmtItem", |_, h| h),
            Stmt::Expr(expr, semi) => {
                if semi.is_some() {
                    self.record_node("StmtExprSemi", |this, h| {
                        let eh = this.norm_expr(expr);
                        mix(h, eh)
                    })
                } else {
                    self.norm_expr(expr)
                }
            }
            Stmt::Macro(stmt_mac) => self.record_node("MacroCall", |this, h| {
                let p = path_to_string(&stmt_mac.mac.path);
                this.text.push(' ');
                this.text.push_str(&p);
                this.text.push('!');
                mix_text(h, &p)
            }),
        }
    }

    fn norm_arm(&mut self, arm: &Arm) -> u64 {
        self.record_node("MatchArm", |this, mut h| {
            let ph = this.norm_pat(&arm.pat);
            h = mix(h, ph);
            if let Some((_, guard)) = &arm.guard {
                let gh = this.norm_expr(guard);
                h = mix(h, gh);
            }
            let bh = this.norm_expr(&arm.body);
            mix(h, bh)
        })
    }

    fn norm_expr(&mut self, expr: &Expr) -> u64 {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; normalizes control flow, operators, calls, paths, and literals"
        )]
        match expr {
            Expr::Lit(el) => self.record_node("Literal", |this, h| {
                let tag = literal_tag(&el.lit);
                this.text.push(' ');
                this.text.push_str(tag);
                mix_text(h, tag)
            }),
            Expr::Path(ep) => self.record_node("PathExpr", |this, mut h| {
                for seg in &ep.path.segments {
                    let seg_h = this.record_node("NameRef", |inner, inner_h| {
                        inner.placeholder(&seg.ident.to_string(), inner_h)
                    });
                    h = mix(h, seg_h);
                }
                h
            }),
            Expr::Binary(eb) => self.record_node("BinExpr", |this, mut h| {
                let lh = this.norm_expr(&eb.left);
                let op = bin_op_str(&eb.op);
                this.text.push(' ');
                this.text.push_str(op);
                h = mix(h, lh);
                h = mix_text(h, op);
                let rh = this.norm_expr(&eb.right);
                mix(h, rh)
            }),
            Expr::Unary(eu) => self.record_node("PrefixExpr", |this, mut h| {
                let op = match eu.op {
                    UnOp::Deref(_) => "*",
                    UnOp::Not(_) => "!",
                    UnOp::Neg(_) => "-",
                    _ => "unop",
                };
                this.text.push(' ');
                this.text.push_str(op);
                h = mix_text(h, op);
                let eh = this.norm_expr(&eu.expr);
                mix(h, eh)
            }),
            Expr::Assign(ea) => self.record_node("AssignExpr", |this, mut h| {
                let lh = this.norm_expr(&ea.left);
                let rh = this.norm_expr(&ea.right);
                h = mix(h, lh);
                mix(h, rh)
            }),
            Expr::Call(ec) => self.record_node("CallExpr", |this, mut h| {
                let fh = this.norm_expr(&ec.func);
                h = mix(h, fh);
                for arg in &ec.args {
                    let ah = this.norm_expr(arg);
                    h = mix(h, ah);
                }
                h
            }),
            Expr::MethodCall(emc) => self.record_node("MethodCallExpr", |this, mut h| {
                let rh = this.norm_expr(&emc.receiver);
                h = mix(h, rh);
                let mh = this.record_node("NameRef", |inner, inner_h| {
                    inner.placeholder(&emc.method.to_string(), inner_h)
                });
                h = mix(h, mh);
                for arg in &emc.args {
                    let ah = this.norm_expr(arg);
                    h = mix(h, ah);
                }
                h
            }),
            Expr::Field(ef) => self.record_node("FieldExpr", |this, mut h| {
                let bh = this.norm_expr(&ef.base);
                h = mix(h, bh);
                let fname = match &ef.member {
                    Member::Named(id) => id.to_string(),
                    Member::Unnamed(idx) => idx.index.to_string(),
                };
                this.placeholder(&fname, h)
            }),
            Expr::Index(ei) => self.record_node("IndexExpr", |this, mut h| {
                let bh = this.norm_expr(&ei.expr);
                let ih = this.norm_expr(&ei.index);
                h = mix(h, bh);
                mix(h, ih)
            }),
            Expr::If(eif) => self.record_node("IfExpr", |this, mut h| {
                let ch = this.norm_expr(&eif.cond);
                let th = this.norm_block(&eif.then_branch);
                h = mix(h, ch);
                h = mix(h, th);
                if let Some((_, else_expr)) = &eif.else_branch {
                    let eh = this.norm_expr(else_expr);
                    h = mix(h, eh);
                }
                h
            }),
            Expr::Match(em) => self.record_node("MatchExpr", |this, mut h| {
                let eh = this.norm_expr(&em.expr);
                h = mix(h, eh);
                for arm in &em.arms {
                    let ah = this.norm_arm(arm);
                    h = mix(h, ah);
                }
                h
            }),
            Expr::ForLoop(efl) => self.record_node("ForExpr", |this, mut h| {
                let ph = this.norm_pat(&efl.pat);
                let eh = this.norm_expr(&efl.expr);
                let bh = this.norm_block(&efl.body);
                h = mix(h, ph);
                h = mix(h, eh);
                mix(h, bh)
            }),
            Expr::While(ew) => self.record_node("WhileExpr", |this, mut h| {
                let ch = this.norm_expr(&ew.cond);
                let bh = this.norm_block(&ew.body);
                h = mix(h, ch);
                mix(h, bh)
            }),
            Expr::Loop(el) => self.record_node("LoopExpr", |this, h| {
                let bh = this.norm_block(&el.body);
                mix(h, bh)
            }),
            Expr::Block(eb) => self.norm_block(&eb.block),
            Expr::Return(er) => self.record_node("ReturnExpr", |this, mut h| {
                if let Some(inner) = &er.expr {
                    let ch = this.norm_expr(inner);
                    h = mix(h, ch);
                }
                h
            }),
            Expr::Try(et) => self.record_node("TryExpr", |this, h| {
                let ch = this.norm_expr(&et.expr);
                mix(h, ch)
            }),
            Expr::Await(ea) => self.record_node("AwaitExpr", |this, h| {
                let ch = this.norm_expr(&ea.base);
                mix(h, ch)
            }),
            Expr::Reference(er) => self.record_node("RefExpr", |this, mut h| {
                if er.mutability.is_some() {
                    this.text.push_str(" mut");
                    h = mix_text(h, "mut");
                }
                let ch = this.norm_expr(&er.expr);
                mix(h, ch)
            }),
            Expr::Paren(ep) => self.record_node("ParenExpr", |this, h| {
                let ch = this.norm_expr(&ep.expr);
                mix(h, ch)
            }),
            Expr::Tuple(et) => self.record_node("TupleExpr", |this, mut h| {
                for el in &et.elems {
                    let ch = this.norm_expr(el);
                    h = mix(h, ch);
                }
                h
            }),
            Expr::Array(ea) => self.record_node("ArrayExpr", |this, mut h| {
                for el in &ea.elems {
                    let ch = this.norm_expr(el);
                    h = mix(h, ch);
                }
                h
            }),
            Expr::Struct(es) => self.record_node("StructExpr", |this, mut h| {
                for seg in &es.path.segments {
                    h = this.placeholder(&seg.ident.to_string(), h);
                }
                for f in &es.fields {
                    let fh = this.norm_expr(&f.expr);
                    h = mix(h, fh);
                }
                h
            }),
            Expr::Closure(ec) => self.record_node("ClosureExpr", |this, mut h| {
                for p in &ec.inputs {
                    let ph = this.norm_pat(p);
                    h = mix(h, ph);
                }
                let bh = this.norm_expr(&ec.body);
                mix(h, bh)
            }),
            Expr::Cast(ec) => self.record_node("CastExpr", |this, mut h| {
                let eh = this.norm_expr(&ec.expr);
                let th = this.norm_type(&ec.ty);
                h = mix(h, eh);
                mix(h, th)
            }),
            Expr::Let(el) => self.record_node("LetExpr", |this, mut h| {
                let ph = this.norm_pat(&el.pat);
                let eh = this.norm_expr(&el.expr);
                h = mix(h, ph);
                mix(h, eh)
            }),
            Expr::Macro(em) => self.record_node("MacroCall", |this, h| {
                let p = path_to_string(&em.mac.path);
                this.text.push(' ');
                this.text.push_str(&p);
                this.text.push('!');
                mix_text(h, &p)
            }),
            _ => self.record_node("ExprOther", |_, h| h),
        }
    }
}

fn normalize_syn_function(sig: &Signature, block: &Block) -> CanonicalOutput {
    let mut norm = SynCanonicalNormalizer::default();
    norm.record_node("Fn", |this, mut h| {
        let sh = this.norm_sig(sig);
        let bh = this.norm_block(block);
        h = mix(h, sh);
        mix(h, bh)
    });
    norm.shingles.sort_unstable();
    let h1 = mix_text(SEED, &norm.text);
    let h2 = mix_text(0x9e37_79b9_7f4a_7c15, &norm.text);
    let digest = (u128::from(h1) << 64) | u128::from(h2);
    CanonicalOutput {
        digest,
        shingles: norm.shingles,
    }
}

const fn literal_tag(lit: &Lit) -> &'static str {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Lit is non-exhaustive; covers all standard Rust literal kinds"
    )]
    match lit {
        Lit::Str(_) => "#str",
        Lit::ByteStr(_) => "#bstr",
        Lit::CStr(_) => "#cstr",
        Lit::Byte(_) => "#byte",
        Lit::Char(_) => "#char",
        Lit::Int(_) => "#int",
        Lit::Float(_) => "#float",
        Lit::Bool(_) => "#bool",
        _ => "#lit",
    }
}

const fn bin_op_str(op: &BinOp) -> &'static str {
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
        BinOp::Shl(_) => "<<",
        BinOp::Shr(_) => ">>",
        BinOp::Eq(_) => "==",
        BinOp::Lt(_) => "<",
        BinOp::Le(_) => "<=",
        BinOp::Ne(_) => "!=",
        BinOp::Ge(_) => ">=",
        BinOp::Gt(_) => ">",
        BinOp::AddAssign(_) => "+=",
        BinOp::SubAssign(_) => "-=",
        BinOp::MulAssign(_) => "*=",
        BinOp::DivAssign(_) => "/=",
        BinOp::RemAssign(_) => "%=",
        BinOp::BitXorAssign(_) => "^=",
        BinOp::BitAndAssign(_) => "&=",
        BinOp::BitOrAssign(_) => "|=",
        BinOp::ShlAssign(_) => "<<=",
        BinOp::ShrAssign(_) => ">>=",
        _ => "op",
    }
}

const fn mix(state: u64, value: u64) -> u64 {
    let mut mixed = (state ^ value).wrapping_mul(0x0100_0000_01b3);
    mixed ^= mixed >> 29;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^ (mixed >> 32)
}

fn mix_text(state: u64, text: &str) -> u64 {
    text.bytes()
        .fold(state, |acc, byte| mix(acc, u64::from(byte)))
}

/// Computes Sørensen-Dice similarity of two sorted shingle multisets in basis points (`0..=10000`).
fn similarity_bps(left: &[u64], right: &[u64]) -> u16 {
    let total = left.len().saturating_add(right.len());
    if total == 0 {
        return 0;
    }
    let mut shared = 0_usize;
    let (mut i, mut j) = (0_usize, 0_usize);
    while let (Some(l), Some(r)) = (left.get(i), right.get(j)) {
        match l.cmp(r) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let score = 2_u64
        .saturating_mul(shared as u64)
        .saturating_mul(10_000)
        / total as u64;
    u16::try_from(score).unwrap_or(u16::MAX)
}

const fn largest_comparable(size: usize, threshold: u16) -> usize {
    if threshold == 0 {
        return usize::MAX;
    }
    let bound = (20_000_u64.saturating_sub(threshold as u64)).saturating_mul(size as u64)
        / (threshold as u64);
    #[expect(clippy::cast_possible_truncation, reason = "clamped on 32-bit targets")]
    let out = bound as usize;
    out
}

/// Collects `rs-structure-near-duplicate-function` findings across `files` for `package`.
#[must_use]
pub(crate) fn collect_near_duplicate_function_findings(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
) -> Vec<(std::path::PathBuf, RsCandidateFinding)> {
    let is_disk_workspace_allow = !package.capability_gate.dependencies.contains_key("__virtual_only");
    let explicitly_requested = (enabled_rules
        .is_some_and(|list| list.contains(&RuleId::RsStructureNearDuplicateFunction))
        && !is_disk_workspace_allow)
        || package
            .config
            .explicit_rule_override(RuleId::RsStructureNearDuplicateFunction)
            .is_some();
    if !explicitly_requested
        && package
            .capability_gate
            .dependencies
            .contains_key("__allow_clippy:too_many_lines")
    {
        return Vec::new();
    }

    let mut items: Vec<(&ExtractedFile, &NormalizedFnIr)> = Vec::new();
    for file in files {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        let Some(rs_ir) = file.downcast_payload::<crate::ir::RsFileIr>() else {
            continue;
        };
        for fn_ir in &rs_ir.structure_ir.normalized_functions {
            if !explicitly_requested && fn_ir.is_trait_impl_method {
                continue;
            }
            items.push((file, fn_ir));
        }
    }

    if items.len() < 2 {
        return Vec::new();
    }

    let mut by_digest: BTreeMap<u128, Vec<(&ExtractedFile, &NormalizedFnIr)>> = BTreeMap::new();
    for (file, fn_ir) in items {
        by_digest.entry(fn_ir.digest).or_default().push((file, fn_ir));
    }

    let mut out = Vec::new();
    let mut representatives: Vec<(&ExtractedFile, &NormalizedFnIr)> = Vec::new();

    for (digest, mut group) in by_digest {
        group.sort_by(|(fa, a), (fb, b)| (&fa.path, a.span.start).cmp(&(&fb.path, b.span.start)));
        if group.len() > 1 {
            emit_duplicate_family(&group, 10_000, digest, &mut out);
        }
        if let Some(first) = group.first().copied() {
            representatives.push(first);
        }
    }

    if representatives.len() < 2 {
        return out;
    }

    representatives.sort_by(|(_, a), (_, b)| {
        (a.shingles.len(), a.digest).cmp(&(b.shingles.len(), b.digest))
    });

    let heads = compute_rare_heads(&representatives);
    let mut postings: Vec<(u64, usize)> = heads
        .iter()
        .enumerate()
        .flat_map(|(pos, head)| head.iter().map(move |&tok| (tok, pos)))
        .collect();
    postings.sort_unstable();

    let rep_len = representatives.len();
    let mut parents: Vec<usize> = (0..rep_len).collect();
    let mut weakest: Vec<u16> = vec![u16::MAX; rep_len];
    let mut nominated = vec![usize::MAX; rep_len];
    let mut partners = Vec::new();

    for (pos, (_, rep)) in representatives.iter().enumerate() {
        let bound = largest_comparable(rep.shingles.len(), NEAR_DUPLICATE_THRESHOLD_BPS);
        partners.clear();
        for &tok in heads.get(pos).map_or(&[][..], Vec::as_slice) {
            let start = postings.partition_point(|(c, _)| *c < tok);
            let end = postings.partition_point(|(c, _)| *c <= tok);
            for &(_, cand) in postings.get(start..end).unwrap_or_default() {
                if cand <= pos {
                    continue;
                }
                let Some((_, other)) = representatives.get(cand) else {
                    continue;
                };
                if other.shingles.len() > bound {
                    break;
                }
                if nominated.get(cand) == Some(&pos) {
                    continue;
                }
                if let Some(slot) = nominated.get_mut(cand) {
                    *slot = pos;
                }
                partners.push(cand);
            }
        }

        for &cand in &partners {
            let Some((_, other)) = representatives.get(cand) else {
                continue;
            };
            let score = similarity_bps(&rep.shingles, &other.shingles);
            if score >= NEAR_DUPLICATE_THRESHOLD_BPS {
                union_link(&mut parents, &mut weakest, pos, cand, score);
            }
        }
    }

    let mut components: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for idx in 0..rep_len {
        let r = union_find(&mut parents, idx);
        components.entry(r).or_default().push(idx);
    }

    for (root, members) in components {
        if members.len() < 2 {
            continue;
        }
        let group: Vec<(&ExtractedFile, &NormalizedFnIr)> = members
            .iter()
            .filter_map(|&idx| representatives.get(idx).copied())
            .collect();
        let min_digest = group.iter().map(|(_, f)| f.digest).min().unwrap_or(0);
        let sim = weakest.get(root).copied().unwrap_or(NEAR_DUPLICATE_THRESHOLD_BPS);
        emit_duplicate_family(&group, sim, min_digest, &mut out);
    }

    out
}

fn emit_duplicate_family(
    group: &[(&ExtractedFile, &NormalizedFnIr)],
    similarity: u16,
    family_digest: u128,
    out: &mut Vec<(std::path::PathBuf, RsCandidateFinding)>,
) {
    let Some((anchor_file, anchor_fn)) = group.first().copied() else {
        return;
    };
    let peer_sites: Vec<ResolvedCallerSite> = group
        .iter()
        .skip(1)
        .map(|(peer_file, peer_fn)| ResolvedCallerSite {
            caller_file: peer_file.path.clone(),
            parent_subject_name: Some(peer_fn.name.clone()),
            component_name: peer_fn.name.clone(),
            loc: peer_fn.loc,
            span: peer_fn.span,
            has_key: false,
            passed_props: Vec::new(),
        })
        .collect();
    let peer_names: Vec<String> = group
        .iter()
        .skip(1)
        .map(|(pf, pfn)| format!("`{}` ({})", pfn.name, pf.path.display()))
        .collect();
    let pct = similarity / 100;
    let message = if similarity == 10_000 {
        format!(
            "{} functions (`{}` and {}) share an identical {}-node normalized AST body once identifiers and literals are erased.",
            group.len(),
            anchor_fn.name,
            peer_names.join(", "),
            anchor_fn.shingles.len()
        )
    } else {
        format!(
            "{} functions (`{}` and {}) are at least {pct}% structurally similar ({}-node AST body) once identifiers and literals are erased.",
            group.len(),
            anchor_fn.name,
            peer_names.join(", "),
            anchor_fn.shingles.len()
        )
    };
    let finding = RsCandidateFinding::new(
        RuleId::RsStructureNearDuplicateFunction,
        Some(anchor_fn.name.clone()),
        format!("fn_dup_{:016x}", u64::try_from(family_digest & u128::from(u64::MAX)).unwrap_or(0)),
        "rsStructureNearDuplicateFunction",
        message,
        anchor_fn.loc,
        anchor_fn.span,
    )
    .with_caller_sites(peer_sites);
    out.push((anchor_file.path.clone(), finding));
}

fn compute_rare_heads(representatives: &[(&ExtractedFile, &NormalizedFnIr)]) -> Vec<Vec<u64>> {
    let mut freqs = HashMap::<u64, u32>::new();
    for (_, rep) in representatives {
        for &tok in &rep.shingles {
            *freqs.entry(tok).or_default() += 1;
        }
    }
    let _ = BTreeSet::<u64>::new();
    representatives
        .iter()
        .map(|(_, rep)| {
            let mut ordered = rep.shingles.clone();
            ordered.sort_unstable_by_key(|tok| (freqs.get(tok).copied().unwrap_or(0), *tok));
            ordered.truncate(HEAD_TOKENS);
            ordered.sort_unstable();
            ordered.dedup();
            ordered
        })
        .collect()
}

fn union_find(parents: &mut [usize], mut idx: usize) -> usize {
    while let Some(p) = parents.get(idx).copied() {
        if p == idx {
            break;
        }
        let gp = parents.get(p).copied().unwrap_or(p);
        if let Some(slot) = parents.get_mut(idx) {
            *slot = gp;
        }
        idx = gp;
    }
    idx
}

fn union_link(parents: &mut [usize], weakest: &mut [u16], left: usize, right: usize, score: u16) {
    let (l, r) = (union_find(parents, left), union_find(parents, right));
    let w = weakest.get(l).copied().unwrap_or(u16::MAX).min(weakest.get(r).copied().unwrap_or(u16::MAX)).min(score);
    let (kept, merged) = if l <= r { (l, r) } else { (r, l) };
    if let Some(slot) = parents.get_mut(merged) { *slot = kept; }
    if let Some(slot) = weakest.get_mut(kept) { *slot = w; }
}
