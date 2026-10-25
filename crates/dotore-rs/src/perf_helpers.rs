//! AST helper matchers for `perf.rs` (`rs-perf-*` and `rs-no-unordered-collection-in-serialize`).

use std::collections::HashSet;

use syn::{
    Attribute, Block, Expr, ExprCall, ExprField, ExprForLoop, ExprLoop, ExprWhile, GenericArgument,
    Lit, Pat, PathArguments, Stmt, Token, Type,
    parse::Parser,
    punctuated::Punctuated,
    visit::Visit,
};

use crate::matchers::{extract_expr_ident, path_to_string};

pub(crate) fn collect_pat_idents(pat: &Pat, out: &mut HashSet<String>) {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; recursively extracts bound local identifiers (#50)"
    )]
    match pat {
        Pat::Ident(pi) => {
            out.insert(pi.ident.to_string());
            if let Some((_, sub)) = &pi.subpat {
                collect_pat_idents(sub, out);
            }
        }
        Pat::Reference(r) => collect_pat_idents(&r.pat, out),
        Pat::Type(t) => collect_pat_idents(&t.pat, out),
        Pat::Tuple(t) => {
            for elem in &t.elems {
                collect_pat_idents(elem, out);
            }
        }
        Pat::TupleStruct(ts) => {
            for elem in &ts.elems {
                collect_pat_idents(elem, out);
            }
        }
        Pat::Struct(s) => {
            for field in &s.fields {
                collect_pat_idents(&field.pat, out);
            }
        }
        Pat::Slice(sl) => {
            for elem in &sl.elems {
                collect_pat_idents(elem, out);
            }
        }
        Pat::Or(or_pat) => {
            for case in &or_pat.cases {
                collect_pat_idents(case, out);
            }
        }
        Pat::Paren(p) => collect_pat_idents(&p.pat, out),
        _ => {}
    }
}

pub(crate) fn collect_let_cond_idents(expr: &Expr, out: &mut HashSet<String>) {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; inspects Let and && chains in while-let conditions (#50)"
    )]
    match expr {
        Expr::Let(expr_let) => collect_pat_idents(&expr_let.pat, out),
        Expr::Binary(bin) => {
            collect_let_cond_idents(&bin.left, out);
            collect_let_cond_idents(&bin.right, out);
        }
        Expr::Paren(p) => collect_let_cond_idents(&p.expr, out),
        Expr::Group(g) => collect_let_cond_idents(&g.expr, out),
        _ => {}
    }
}

pub(crate) fn extract_root_ident(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; walks receiver chain to find root local variable (#50)"
    )]
    match expr {
        Expr::Paren(p) => extract_root_ident(&p.expr),
        Expr::Group(g) => extract_root_ident(&g.expr),
        Expr::Reference(r) => extract_root_ident(&r.expr),
        Expr::Path(ep) if ep.qself.is_none() => ep.path.get_ident().map(ToString::to_string),
        Expr::Field(ExprField { base, .. }) => extract_root_ident(base),
        Expr::Index(idx) => extract_root_ident(&idx.expr),
        Expr::MethodCall(mc) => extract_root_ident(&mc.receiver),
        Expr::Try(t) => extract_root_ident(&t.expr),
        Expr::Unary(u) => extract_root_ident(&u.expr),
        _ => None,
    }
}

pub(crate) fn is_bare_ident_receiver(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks whether receiver is a bare identifier without field/index projection (#50)"
    )]
    match expr {
        Expr::Paren(p) => is_bare_ident_receiver(&p.expr),
        Expr::Group(g) => is_bare_ident_receiver(&g.expr),
        Expr::Reference(r) => is_bare_ident_receiver(&r.expr),
        Expr::Path(ep) => ep.qself.is_none() && ep.path.get_ident().is_some(),
        _ => false,
    }
}

pub(crate) fn is_bare_clone_call(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks direct `.clone()` calls (#50)"
    )]
    match expr {
        Expr::Paren(p) => is_bare_clone_call(&p.expr),
        Expr::Group(g) => is_bare_clone_call(&g.expr),
        Expr::MethodCall(mc) => mc.method == "clone" && mc.args.is_empty(),
        _ => false,
    }
}

pub(crate) fn is_bare_loop_item_clone(expr: &Expr, loop_scoped_vars: &[HashSet<String>]) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks `item.clone()` on a bare loop variable (#50)"
    )]
    match expr {
        Expr::Paren(p) => is_bare_loop_item_clone(&p.expr, loop_scoped_vars),
        Expr::Group(g) => is_bare_loop_item_clone(&g.expr, loop_scoped_vars),
        Expr::MethodCall(mc) if mc.method == "clone" && mc.args.is_empty() => {
            is_bare_ident_receiver(&mc.receiver)
                && extract_root_ident(&mc.receiver)
                    .is_some_and(|id| loop_scoped_vars.iter().any(|set| set.contains(&id)))
        }
        _ => false,
    }
}

pub(crate) fn expr_has_branch_bare_clone(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks whether an if/match/block initializer has a bare `.clone()` tail expression (#50)"
    )]
    match expr {
        Expr::Paren(p) => expr_has_branch_bare_clone(&p.expr),
        Expr::Group(g) => expr_has_branch_bare_clone(&g.expr),
        Expr::Block(b) => block_tail_is_bare_clone(&b.block),
        Expr::If(expr_if) => {
            block_tail_is_bare_clone(&expr_if.then_branch)
                || expr_if
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, eb)| is_bare_clone_call(eb) || expr_has_branch_bare_clone(eb))
        }
        Expr::Match(expr_match) => expr_match
            .arms
            .iter()
            .any(|arm| is_bare_clone_call(&arm.body) || expr_has_branch_bare_clone(&arm.body)),
        _ => false,
    }
}

fn block_tail_is_bare_clone(block: &Block) -> bool {
    matches!(
        block.stmts.last(),
        Some(Stmt::Expr(tail, None)) if is_bare_clone_call(tail) || expr_has_branch_bare_clone(tail)
    )
}

pub(crate) fn is_lazy_lock_init_call(node: &ExprCall) -> bool {
    if let Expr::Path(ep) = node.func.as_ref() {
        let full = path_to_string(&ep.path);
        return full.ends_with("LazyLock::new") || full.ends_with("Lazy::new");
    }
    false
}

pub(crate) fn is_empty_vec_init(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks Vec::new() calls and empty vec![] macros (#50)"
    )]
    match expr {
        Expr::Paren(p) => is_empty_vec_init(&p.expr),
        Expr::Group(g) => is_empty_vec_init(&g.expr),
        Expr::Call(call) if call.args.is_empty() => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let full = path_to_string(&ep.path);
                matches!(
                    full.as_str(),
                    "Vec::new" | "std::vec::Vec::new" | "alloc::vec::Vec::new"
                )
            } else {
                false
            }
        }
        Expr::Macro(expr_macro) => {
            expr_macro.mac.path.is_ident("vec") && expr_macro.mac.tokens.is_empty()
        }
        _ => false,
    }
}

pub(crate) fn is_unsized_loop_iterator(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; inspects method call chains for unsized/filter iterators (#50)"
    )]
    match expr {
        Expr::Paren(p) => is_unsized_loop_iterator(&p.expr),
        Expr::Group(g) => is_unsized_loop_iterator(&g.expr),
        Expr::Reference(r) => is_unsized_loop_iterator(&r.expr),
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if matches!(
                method.as_str(),
                "ancestors"
                    | "split"
                    | "split_whitespace"
                    | "split_ascii_whitespace"
                    | "split_terminator"
                    | "split_inclusive"
                    | "rsplit"
                    | "lines"
                    | "chars"
                    | "char_indices"
                    | "filter"
                    | "filter_map"
                    | "flat_map"
                    | "flatten"
                    | "take_while"
                    | "skip_while"
            ) {
                return true;
            }
            is_unsized_loop_iterator(&mc.receiver)
        }
        _ => false,
    }
}

struct LoopControlFlowChecker {
    has_continue: bool,
    has_break: bool,
}

impl<'ast> Visit<'ast> for LoopControlFlowChecker {
    fn visit_expr_for_loop(&mut self, _i: &'ast ExprForLoop) {}
    fn visit_expr_while(&mut self, _i: &'ast ExprWhile) {}
    fn visit_expr_loop(&mut self, _i: &'ast ExprLoop) {}
    fn visit_expr_closure(&mut self, _i: &'ast syn::ExprClosure) {}
    fn visit_item(&mut self, _i: &'ast syn::Item) {}

    fn visit_expr_continue(&mut self, _i: &'ast syn::ExprContinue) {
        self.has_continue = true;
    }

    fn visit_expr_break(&mut self, _i: &'ast syn::ExprBreak) {
        self.has_break = true;
    }
}

fn stmt_has_continue_or_break(stmt: &Stmt) -> (bool, bool) {
    let mut checker = LoopControlFlowChecker {
        has_continue: false,
        has_break: false,
    };
    checker.visit_stmt(stmt);
    (checker.has_continue, checker.has_break)
}

pub(crate) fn collect_unconditional_pushed_vecs(block: &Block, out: &mut Vec<String>) {
    if block.stmts.iter().any(|s| stmt_has_continue_or_break(s).1) {
        return;
    }
    for stmt in &block.stmts {
        let (has_continue, has_break) = stmt_has_continue_or_break(stmt);
        if has_continue || has_break {
            break;
        }
        if let Stmt::Expr(expr, _) = stmt
            && let Expr::MethodCall(mc) = expr
            && mc.method == "push"
            && mc.args.len() == 1
            && let Some(recv) = extract_expr_ident(&mc.receiver)
            && !out.contains(&recv)
        {
            out.push(recv);
        }
    }
}

pub(crate) fn is_unnecessary_format_tokens(tokens: &proc_macro2::TokenStream) -> bool {
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    let Ok(args) = parser.parse2(tokens.clone()) else {
        return false;
    };
    let Some(Expr::Lit(expr_lit)) = args.first() else {
        return false;
    };
    let Lit::Str(lit_str) = &expr_lit.lit else {
        return false;
    };
    let val = lit_str.value();
    match args.len() {
        1 => !has_format_placeholder(&val) || is_single_trivial_placeholder(&val),
        2 => val == "{}" || val == "{0}",
        _ => false,
    }
}

fn has_format_placeholder(s: &str) -> bool {
    let cleaned = s.replace("{{", "").replace("}}", "");
    cleaned.contains('{') && cleaned.contains('}')
}

fn is_single_trivial_placeholder(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('{').and_then(|rest| rest.strip_suffix('}')) else {
        return false;
    };
    if inner.is_empty() {
        return true;
    }
    !inner.contains('{')
        && !inner.contains('}')
        && !inner.contains(':')
        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(crate) fn attrs_derive_serialize(attrs: &[Attribute]) -> bool {
    let mut has_serialize = false;
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta
                .path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "Serialize")
            {
                has_serialize = true;
            }
            Ok(())
        });
    }
    has_serialize
}

pub(crate) fn field_has_deterministic_or_skip_serde_attr(attrs: &[Attribute]) -> bool {
    let mut safe = false;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("serialize_with")
                || meta.path.is_ident("with")
                || meta.path.is_ident("skip")
                || meta.path.is_ident("skip_serializing")
                || meta.path.is_ident("into")
            {
                safe = true;
            }
            if meta.input.peek(Token![=]) {
                let _: Token![=] = meta.input.parse()?;
                let _: syn::Expr = meta.input.parse()?;
            }
            Ok(())
        });
    }
    safe
}

pub(crate) fn unordered_collection_type_name(ty: &Type) -> Option<&'static str> {
    let Type::Path(tp) = ty else {
        return None;
    };
    let last = tp.path.segments.last()?;
    let ident_str = last.ident.to_string();
    if ident_str == "HashSet" {
        return Some("HashSet");
    }
    if ident_str == "HashMap" {
        return Some("HashMap");
    }
    if matches!(ident_str.as_str(), "Option" | "Vec" | "Box" | "Arc" | "Rc")
        && let PathArguments::AngleBracketed(args) = &last.arguments
    {
        for arg in &args.args {
            if let GenericArgument::Type(inner_ty) = arg
                && let Some(found) = unordered_collection_type_name(inner_ty)
            {
                return Some(found);
            }
        }
    }
    None
}
