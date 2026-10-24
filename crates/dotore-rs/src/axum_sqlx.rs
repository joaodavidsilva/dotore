//! Single-pass detectors for Axum shared state contention and SQLx query hazards:
//!
//! 1. `rs-sqlx-no-formatted-query-string` ([`RuleId::RsSqlxNoFormattedQueryString`])
//! 2. `rs-sqlx-no-query-in-loop` ([`RuleId::RsSqlxNoQueryInLoop`])
//! 3. `rs-axum-no-contended-mutex-state` ([`RuleId::RsAxumNoContendedMutexState`])

use std::collections::{HashMap, HashSet};

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    BinOp, Expr, ExprAssign, ExprCall, ExprForLoop, ExprLoop, ExprMacro, ExprMethodCall, ExprWhile,
    File, FnArg, GenericArgument, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemStruct, Local, Macro,
    PathArguments, Signature, TraitItemFn, Type,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_pat_ident, is_format_macro, loc_at, span_to_bytes,
};

/// Extracts candidate findings for Axum and SQLx rules from `ast`.
pub(crate) fn extract_axum_sqlx_findings(
    ast: &File,
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut struct_mutex_fields = HashMap::new();
    collect_struct_mutex_fields(ast, &mut struct_mutex_fields);

    let mut extractor = AxumSqlxVisitor {
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        formatted_vars: HashSet::new(),
        reported_loop_query_spans: Vec::new(),
        struct_mutex_fields,
    };
    extractor.visit_file(ast);
}

fn collect_struct_mutex_fields(ast: &File, out: &mut HashMap<String, Vec<String>>) {
    struct StructCollector<'a> {
        out: &'a mut HashMap<String, Vec<String>>,
    }
    impl<'ast> Visit<'ast> for StructCollector<'_> {
        fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
            let mut mutex_fields = Vec::new();
            for field in &i.fields {
                if type_contains_contended_mutex(&field.ty) {
                    let name = field
                        .ident
                        .as_ref()
                        .map_or_else(|| "0".to_string(), ToString::to_string);
                    mutex_fields.push(name);
                }
            }
            if !mutex_fields.is_empty() {
                self.out.insert(i.ident.to_string(), mutex_fields);
            }
            visit::visit_item_struct(self, i);
        }
    }
    let mut collector = StructCollector { out };
    collector.visit_file(ast);
}

struct AxumSqlxVisitor<'a> {
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    formatted_vars: HashSet<String>,
    reported_loop_query_spans: Vec<ByteSpan>,
    struct_mutex_fields: HashMap<String, Vec<String>>,
}

impl AxumSqlxVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn is_inside_reported_loop_query(&self, span: ByteSpan) -> bool {
        self.reported_loop_query_spans
            .iter()
            .any(|s| span.start >= s.start && span.end <= s.end)
    }

    fn check_sqlx_formatted_query_call(&mut self, node: &ExprCall) {
        let Some(func_name) = extract_sqlx_query_fn_name(&node.func) else {
            return;
        };
        let Some(first_arg) = node.args.first() else {
            return;
        };
        if self.expr_is_formatted_sql(first_arg) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsSqlxNoFormattedQueryString,
                self.scope.subject_name(),
                func_name.clone(),
                "rsSqlxNoFormattedQueryString",
                format!(
                    "SQLx query `{func_name}(...)` is constructed with `format!(...)` string interpolation; use parameterized `$1` / `?` placeholders with `.bind(...)` instead."
                ),
                loc,
                span,
            ));
        }
    }

    fn expr_is_formatted_sql(&self, expr: &Expr) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; formatted SQL detection inspects references, macros, method calls, paths, and binary ops"
        )]
        match expr {
            Expr::Reference(r) => self.expr_is_formatted_sql(&r.expr),
            Expr::Paren(p) => self.expr_is_formatted_sql(&p.expr),
            Expr::Group(g) => self.expr_is_formatted_sql(&g.expr),
            Expr::Unary(u) => self.expr_is_formatted_sql(&u.expr),
            Expr::Macro(expr_macro) => is_format_macro(&expr_macro.mac),
            Expr::MethodCall(mc) => {
                let m = mc.method.to_string();
                if matches!(m.as_str(), "as_str" | "as_ref" | "into_boxed_str" | "leak") {
                    self.expr_is_formatted_sql(&mc.receiver)
                } else {
                    false
                }
            }
            Expr::Path(expr_path) => {
                if expr_path.qself.is_none()
                    && let Some(ident) = expr_path.path.get_ident()
                {
                    return self.formatted_vars.contains(&ident.to_string());
                }
                false
            }
            Expr::Binary(bin) => {
                matches!(bin.op, BinOp::Add(_))
                    && (self.expr_is_formatted_sql(&bin.left)
                        || self.expr_is_formatted_sql(&bin.right)
                        || is_string_lit_or_to_string(&bin.left))
            }
            _ => false,
        }
    }

    fn check_axum_contended_mutex_state(&mut self, sig: &Signature, body: Option<&syn::Block>) {
        if self.scope.in_test() {
            return;
        }
        for input in &sig.inputs {
            let FnArg::Typed(pat_type) = input else {
                continue;
            };
            let is_axum_state =
                is_axum_state_type(&pat_type.ty) || is_axum_state_pattern(&pat_type.pat);
            if !is_axum_state {
                continue;
            }

            let direct_mutex = type_contains_contended_mutex(&pat_type.ty);
            let struct_with_mutex = extract_inner_state_struct_names(&pat_type.ty)
                .into_iter()
                .any(|name| self.struct_mutex_fields.contains_key(&name));
            let body_locks_state = extract_pat_ident(&pat_type.pat)
                .zip(body)
                .is_some_and(|(binding, blk)| block_calls_mutex_lock_on_binding(blk, &binding));

            if direct_mutex || struct_with_mutex || body_locks_state {
                let span = self.span_to_bytes(pat_type.span());
                let loc = self.loc_at(span.start);
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsAxumNoContendedMutexState,
                    self.scope.subject_name(),
                    "State<Mutex<...>>",
                    "rsAxumNoContendedMutexState",
                    "Axum `State` wraps a contended `Mutex`, serializing concurrent HTTP requests; prefer `DashMap`, `RwLock`, actor channels (`mpsc::Sender`), or database pool state.",
                    loc,
                    span,
                ));
            }
        }
    }
}

impl<'ast> Visit<'ast> for AxumSqlxVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_vars = std::mem::take(&mut self.formatted_vars);

        self.check_axum_contended_mutex_state(&i.sig, Some(&i.block));

        visit::visit_item_fn(self, i);

        self.formatted_vars = prev_vars;
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_vars = std::mem::take(&mut self.formatted_vars);

        self.check_axum_contended_mutex_state(&i.sig, Some(&i.block));
        visit::visit_impl_item_fn(self, i);

        self.formatted_vars = prev_vars;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        visit::visit_trait_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(ident) = extract_pat_ident(&node.pat)
            && let Some(init) = &node.init
        {
            if self.expr_is_formatted_sql(&init.expr) {
                self.formatted_vars.insert(ident);
            } else {
                self.formatted_vars.remove(&ident);
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        if let Expr::Path(p) = node.left.as_ref()
            && let Some(ident) = p.path.get_ident()
            && self.expr_is_formatted_sql(&node.right)
        {
            self.formatted_vars.insert(ident.to_string());
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.visit_expr(&node.expr);
        let snap = self.scope.enter_loop();
        self.visit_block(&node.body);
        self.scope.exit(snap);
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        let snap = self.scope.enter_loop();
        self.visit_expr(&node.cond);
        self.visit_block(&node.body);
        self.scope.exit(snap);
    }

    fn visit_expr_loop(&mut self, node: &'ast ExprLoop) {
        let snap = self.scope.enter_loop();
        self.visit_block(&node.body);
        self.scope.exit(snap);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if !self.scope.in_test() {
            let method = node.method.to_string();
            if method == "push_str"
                && let Expr::Path(p) = node.receiver.as_ref()
                && let Some(ident) = p.path.get_ident()
            {
                self.formatted_vars.insert(ident.to_string());
            }

            if self.scope.in_loop()
                && is_sqlx_terminal_method(&method)
                && receiver_chain_is_sqlx_query(&node.receiver)
            {
                let span = self.span_to_bytes(node.span());
                if !self.is_inside_reported_loop_query(span) {
                    let loc = self.loc_at(span.start);
                    self.reported_loop_query_spans.push(span);
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsSqlxNoQueryInLoop,
                        self.scope.subject_name(),
                        format!("sqlx::{method}"),
                        "rsSqlxNoQueryInLoop",
                        format!(
                            "SQLx query `.{method}(...)` executed inside a loop causes N+1 database round-trips; batch queries before the loop with `ANY($1)` or `QueryBuilder::push_tuples`."
                        ),
                        loc,
                        span,
                    ));
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if !self.scope.in_test() {
            self.check_sqlx_formatted_query_call(node);

            if self.scope.in_loop()
                && let Some(func_name) = extract_sqlx_query_fn_name(&node.func)
            {
                let span = self.span_to_bytes(node.span());
                if !self.is_inside_reported_loop_query(span) {
                    let loc = self.loc_at(span.start);
                    self.reported_loop_query_spans.push(span);
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsSqlxNoQueryInLoop,
                        self.scope.subject_name(),
                        func_name.clone(),
                        "rsSqlxNoQueryInLoop",
                        format!(
                            "SQLx query `{func_name}(...)` executed inside a loop causes N+1 database round-trips; batch queries outside the loop."
                        ),
                        loc,
                        span,
                    ));
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        if !self.scope.in_test() && self.scope.in_loop() && is_sqlx_query_macro(&node.mac) {
            let span = self.span_to_bytes(node.span());
            if !self.is_inside_reported_loop_query(span) {
                let loc = self.loc_at(span.start);
                self.reported_loop_query_spans.push(span);
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsSqlxNoQueryInLoop,
                    self.scope.subject_name(),
                    "sqlx::query!",
                    "rsSqlxNoQueryInLoop",
                    "SQLx query macro executed inside a loop causes N+1 database round-trips; batch queries outside the loop.",
                    loc,
                    span,
                ));
            }
        }
        visit::visit_expr_macro(self, node);
    }
}

fn is_sqlx_terminal_method(method: &str) -> bool {
    matches!(
        method,
        "fetch_one" | "fetch_all" | "fetch_optional" | "fetch_many" | "fetch" | "execute"
    )
}

fn receiver_chain_is_sqlx_query(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; SQLx receiver chain inspection walks method calls, calls, macros, awaits, and tries"
    )]
    match expr {
        Expr::Call(call) => extract_sqlx_query_fn_name(&call.func).is_some(),
        Expr::Macro(mac) => is_sqlx_query_macro(&mac.mac),
        Expr::MethodCall(mc) => {
            let m = mc.method.to_string();
            matches!(m.as_str(), "bind" | "persistent" | "try_map" | "map")
                || receiver_chain_is_sqlx_query(&mc.receiver)
        }
        Expr::Await(aw) => receiver_chain_is_sqlx_query(&aw.base),
        Expr::Try(tr) => receiver_chain_is_sqlx_query(&tr.expr),
        Expr::Paren(p) => receiver_chain_is_sqlx_query(&p.expr),
        Expr::Group(g) => receiver_chain_is_sqlx_query(&g.expr),
        _ => false,
    }
}

fn extract_sqlx_query_fn_name(func: &Expr) -> Option<String> {
    let Expr::Path(expr_path) = func else {
        return None;
    };
    let segments: Vec<String> = expr_path
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let last = segments.last()?.as_str();
    let is_query_fn = matches!(
        last,
        "query"
            | "query_as"
            | "query_scalar"
            | "raw_sql"
            | "query_with"
            | "query_as_with"
            | "query_scalar_with"
    );
    if !is_query_fn {
        return None;
    }
    if segments.len() >= 2 && segments.iter().any(|s| s == "sqlx") {
        return Some(format!("sqlx::{last}"));
    }
    if segments.len() == 1 && matches!(last, "query" | "query_as" | "query_scalar" | "raw_sql") {
        return Some(format!("sqlx::{last}"));
    }
    None
}

fn is_sqlx_query_macro(mac: &Macro) -> bool {
    let segs: Vec<String> = mac
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let Some(last) = segs.last().map(String::as_str) else {
        return false;
    };
    if !matches!(
        last,
        "query" | "query_as" | "query_scalar" | "query_file" | "query_file_as" | "query_file_scalar"
    ) {
        return false;
    }
    segs.len() == 1 || segs.iter().any(|s| s == "sqlx")
}

fn is_string_lit_or_to_string(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Checks only string literals and .to_string() / String::from calls"
    )]
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        }) => true,
        Expr::MethodCall(mc) => mc.method == "to_string" || mc.method == "to_owned",
        _ => false,
    }
}

fn type_contains_contended_mutex(ty: &Type) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; Mutex detection walks Path, Reference, Tuple, Paren, Group"
    )]
    match ty {
        Type::Path(tp) => tp.path.segments.iter().any(segment_contains_contended_mutex),
        Type::Reference(tr) => type_contains_contended_mutex(&tr.elem),
        Type::Paren(tp) => type_contains_contended_mutex(&tp.elem),
        Type::Group(tg) => type_contains_contended_mutex(&tg.elem),
        Type::Tuple(tt) => tt.elems.iter().any(type_contains_contended_mutex),
        _ => false,
    }
}

fn segment_contains_contended_mutex(seg: &syn::PathSegment) -> bool {
    let ident = seg.ident.to_string();
    if matches!(ident.as_str(), "Mutex" | "FairMutex") {
        return true;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    args.args.iter().any(|arg| {
        matches!(arg, GenericArgument::Type(inner_ty) if type_contains_contended_mutex(inner_ty))
    })
}

fn is_axum_state_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        tp.path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "State")
    } else {
        false
    }
}

fn is_axum_state_pattern(pat: &syn::Pat) -> bool {
    if let syn::Pat::TupleStruct(ts) = pat {
        ts.path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "State")
    } else {
        false
    }
}

fn extract_inner_state_struct_names(ty: &Type) -> Vec<String> {
    let mut out = Vec::new();
    collect_inner_type_idents(ty, &mut out);
    out
}

fn collect_inner_type_idents(ty: &Type, out: &mut Vec<String>) {
    let Type::Path(tp) = ty else {
        return;
    };
    for seg in &tp.path.segments {
        let name = seg.ident.to_string();
        if !matches!(name.as_str(), "State" | "Arc" | "Box" | "Rc") {
            out.push(name);
        }
        let PathArguments::AngleBracketed(args) = &seg.arguments else {
            continue;
        };
        for arg in &args.args {
            if let GenericArgument::Type(inner_ty) = arg {
                collect_inner_type_idents(inner_ty, out);
            }
        }
    }
}

fn block_calls_mutex_lock_on_binding(block: &syn::Block, binding: &str) -> bool {
    struct LockFinder<'a> {
        binding: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for LockFinder<'_> {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            let m = node.method.to_string();
            if matches!(m.as_str(), "lock" | "try_lock" | "blocking_lock")
                && expr_starts_with_ident(&node.receiver, self.binding)
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut finder = LockFinder {
        binding,
        found: false,
    };
    finder.visit_block(block);
    finder.found
}

fn expr_starts_with_ident(expr: &Expr, ident: &str) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Walks path, field, method-call, reference, and paren expressions to find root identifier"
    )]
    match expr {
        Expr::Path(p) => p.path.is_ident(ident),
        Expr::Field(f) => expr_starts_with_ident(&f.base, ident),
        Expr::MethodCall(mc) => expr_starts_with_ident(&mc.receiver, ident),
        Expr::Reference(r) => expr_starts_with_ident(&r.expr, ident),
        Expr::Paren(p) => expr_starts_with_ident(&p.expr, ident),
        _ => false,
    }
}
