//! Single-pass detectors for Axum shared state contention and SQLx query hazards:
//!
//! 1. `rs-sqlx-no-formatted-query-string` ([`RuleId::RsSqlxNoFormattedQueryString`])
//! 2. `rs-sqlx-no-query-in-loop` ([`RuleId::RsSqlxNoQueryInLoop`])
//! 3. `rs-axum-no-contended-mutex-state` ([`RuleId::RsAxumNoContendedMutexState`])

use std::collections::HashMap;

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Expr, ExprCall, ExprForLoop, ExprLoop, ExprMacro, ExprMethodCall, ExprWhile, File, FnArg,
    GenericArgument, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemStruct, Macro, PathArguments,
    Signature, Stmt, TraitItemFn, Type,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::{RsCandidateFinding, RsScopeTracker, extract_pat_ident, loc_at, span_to_bytes},
    source_kernel::{
        FnBodyResolver, KernelContext, RsAliasMap, bare_identifier, strip_parens, strip_wrappers,
    },
};

/// Extracts candidate findings for Axum and SQLx rules from `ast`.
pub(crate) fn extract_axum_sqlx_findings(
    ast: &File,
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut struct_mutex_fields = HashMap::new();
    collect_struct_mutex_fields(ast, &mut struct_mutex_fields);

    let aliases = RsAliasMap::build(ast);
    let mut extractor = AxumSqlxVisitor {
        aliases: &aliases,
        current_body: None,
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
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
    aliases: &'a RsAliasMap,
    current_body: Option<FnBodyResolver>,
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
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

    fn ctx(&self) -> KernelContext<'_> {
        KernelContext::new(self.aliases, self.current_body.as_ref())
    }

    fn is_inside_reported_loop_query(&self, span: ByteSpan) -> bool {
        self.reported_loop_query_spans
            .iter()
            .any(|s| span.start >= s.start && span.end <= s.end)
    }

    fn check_sqlx_formatted_query_call(&mut self, node: &ExprCall) {
        let ctx = self.ctx();
        let Some((func_name, arg_pos, alias_req)) =
            match_sql_query_call_function(&ctx, &node.func)
        else {
            return;
        };
        let Some(sql_arg) = node.args.iter().nth(arg_pos) else {
            return;
        };
        if is_assembled_dynamic_sql(&ctx, sql_arg) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let mut finding = RsCandidateFinding::new(
                RuleId::RsSqlxNoFormattedQueryString,
                self.scope.subject_name(),
                func_name.clone(),
                "rsSqlxNoFormattedQueryString",
                format!(
                    "SQL query `{func_name}(...)` is constructed with runtime string interpolation; use parameterized `$1` / `?` placeholders with `.bind(...)` instead."
                ),
                loc,
                span,
            );
            if let Some((w, c)) = alias_req {
                finding = finding.with_required_crate_alias(w, c);
            }
            self.findings.push(finding);
        }
    }

    fn check_sql_formatted_query_method(&mut self, node: &ExprMethodCall) {
        let method = node.method.to_string();
        let Some(first_arg) = node.args.first() else {
            return;
        };
        let ctx = self.ctx();
        if method == "push" {
            let text = strip_transparent_sql_methods(first_arg);
            if !ctx.is_dynamic_text(&text) && bare_identifier(&text).is_none() {
                return;
            }
            let Some(Expr::Call(ctor)) = ctx.chain_root(&node.receiver) else {
                return;
            };
            let Some(alias_req) =
                ctx.matches_call_path(&ctor.func, "sqlx", &["QueryBuilder"], "new")
            else {
                return;
            };
            if is_assembled_dynamic_sql(&ctx, first_arg) {
                let span = self.span_to_bytes(first_arg.span());
                let loc = self.loc_at(span.start);
                let mut finding = RsCandidateFinding::new(
                    RuleId::RsSqlxNoFormattedQueryString,
                    self.scope.subject_name(),
                    "sqlx::QueryBuilder::push",
                    "rsSqlxNoFormattedQueryString",
                    "SQL text is assembled from a runtime value instead of bound as a parameter.",
                    loc,
                    span,
                );
                if let Some((w, c)) = alias_req {
                    finding = finding.with_required_crate_alias(w, c);
                }
                self.findings.push(finding);
            }
            return;
        }

        if !matches!(
            method.as_str(),
            "execute" | "prepare" | "query_row" | "batch_execute" | "query"
        ) {
            return;
        }
        if !is_assembled_dynamic_sql(&ctx, first_arg) {
            return;
        }
        let Some(Expr::Call(ctor)) = ctx.chain_root(&node.receiver) else {
            return;
        };
        let Expr::Path(ep) = strip_parens(&ctor.func) else {
            return;
        };
        let Some((resolved, maybe_renamed)) = ctx.resolve_item_path(&ep.path) else {
            return;
        };
        let [krate, kind, _] = resolved.as_slice() else {
            return;
        };
        let matched_crate = if is_sql_connection_method("rusqlite", kind, &method)
            && (krate == "rusqlite" || maybe_renamed.is_some())
        {
            Some("rusqlite")
        } else if is_sql_connection_method("postgres", kind, &method)
            && (krate == "postgres" || maybe_renamed.is_some())
        {
            Some("postgres")
        } else if is_sql_connection_method("tokio_postgres", kind, &method)
            && (krate == "tokio_postgres" || maybe_renamed.is_some())
        {
            Some("tokio_postgres")
        } else {
            None
        };
        let Some(canonical_crate) = matched_crate else {
            return;
        };
        let span = self.span_to_bytes(first_arg.span());
        let loc = self.loc_at(span.start);
        let mut finding = RsCandidateFinding::new(
            RuleId::RsSqlxNoFormattedQueryString,
            self.scope.subject_name(),
            format!("{canonical_crate}::{kind}::{method}"),
            "rsSqlxNoFormattedQueryString",
            "SQL text is assembled from a runtime value instead of bound as a parameter.",
            loc,
            span,
        );
        if let Some(written) = maybe_renamed
            && written != canonical_crate
        {
            finding = finding.with_required_crate_alias(written, canonical_crate);
        }
        self.findings.push(finding);
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
        let prev_body = self
            .current_body
            .replace(FnBodyResolver::build(&i.sig, &i.block));

        self.check_axum_contended_mutex_state(&i.sig, Some(&i.block));

        for stmt in &i.block.stmts {
            if !matches!(stmt, Stmt::Item(_)) {
                self.visit_stmt(stmt);
            }
        }
        self.current_body = prev_body;
        for stmt in &i.block.stmts {
            if let Stmt::Item(item) = stmt {
                self.visit_item(item);
            }
        }
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_body = self
            .current_body
            .replace(FnBodyResolver::build(&i.sig, &i.block));

        self.check_axum_contended_mutex_state(&i.sig, Some(&i.block));

        for stmt in &i.block.stmts {
            if !matches!(stmt, Stmt::Item(_)) {
                self.visit_stmt(stmt);
            }
        }
        self.current_body = prev_body;
        for stmt in &i.block.stmts {
            if let Stmt::Item(item) = stmt {
                self.visit_item(item);
            }
        }
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        if let Some(block) = &i.default {
            let prev_body = self
                .current_body
                .replace(FnBodyResolver::build(&i.sig, block));
            for stmt in &block.stmts {
                if !matches!(stmt, Stmt::Item(_)) {
                    self.visit_stmt(stmt);
                }
            }
            self.current_body = prev_body;
            for stmt in &block.stmts {
                if let Stmt::Item(item) = stmt {
                    self.visit_item(item);
                }
            }
        }
        self.scope.exit(snap);
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
            self.check_sql_formatted_query_method(node);
            let method = node.method.to_string();
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
        "query"
            | "query_as"
            | "query_scalar"
            | "query_file"
            | "query_file_as"
            | "query_file_scalar"
    ) {
        return false;
    }
    segs.len() == 1 || segs.iter().any(|s| s == "sqlx")
}

const QUERY_FUNCTIONS: [(&[&str], usize); 11] = [
    (&["sqlx", "query"], 0),
    (&["sqlx", "query_as"], 0),
    (&["sqlx", "query_scalar"], 0),
    (&["sqlx", "raw_sql"], 0),
    (&["sqlx", "query_with"], 0),
    (&["sqlx", "query_as_with"], 0),
    (&["sqlx", "query_scalar_with"], 0),
    (&["sqlx", "QueryBuilder", "new"], 0),
    (&["diesel", "sql_query"], 0),
    (&["diesel", "dsl", "sql"], 0),
    (&["sea_orm", "Statement", "from_string"], 1),
];

const SQL_CONNECTIONS: [(&str, &str, &[&str]); 3] = [
    ("rusqlite", "Connection", &["execute", "prepare", "query_row"]),
    ("postgres", "Client", &["batch_execute", "execute", "query"]),
    (
        "tokio_postgres",
        "Client",
        &["batch_execute", "execute", "query"],
    ),
];

fn is_sql_connection_method(krate: &str, kind: &str, method: &str) -> bool {
    SQL_CONNECTIONS
        .iter()
        .any(|(c, k, methods)| *c == krate && *k == kind && methods.contains(&method))
}

type SqlCallMatch = (String, usize, Option<(String, String)>);

fn match_sql_query_call_function(ctx: &KernelContext<'_>, callee: &Expr) -> Option<SqlCallMatch> {
    for (path, pos) in QUERY_FUNCTIONS {
        let Some((expected_crate, rest)) = path.split_first() else {
            continue;
        };
        let Some((expected_member, expected_mid)) = rest.split_last() else {
            continue;
        };
        if let Some(alias_req) =
            ctx.matches_call_path(callee, expected_crate, expected_mid, expected_member)
        {
            return Some((path.join("::"), pos, alias_req));
        }
    }

    let Expr::Path(ep) = strip_parens(callee) else {
        return None;
    };
    if ep.qself.is_some() {
        return None;
    }
    let (resolved, maybe_renamed) = ctx.resolve_item_path(&ep.path)?;
    if let [krate, kind, method] = resolved.as_slice() {
        for &(listed_crate, listed_kind, methods) in &SQL_CONNECTIONS {
            if kind == listed_kind
                && methods.contains(&method.as_str())
                && (krate == listed_crate || maybe_renamed.is_some())
            {
                let req = maybe_renamed
                    .filter(|w| w != listed_crate)
                    .map(|w| (w, listed_crate.to_string()));
                return Some((format!("{listed_crate}::{kind}::{method}"), 1, req));
            }
        }
    }

    if let [single] = resolved.as_slice()
        && matches!(
            single.as_str(),
            "query" | "query_as" | "query_scalar" | "raw_sql"
        )
    {
        return Some((format!("sqlx::{single}"), 0, None));
    }
    None
}

fn strip_transparent_sql_methods(expr: &Expr) -> Expr {
    let mut current = expr.clone();
    loop {
        current = strip_wrappers(&current).clone();
        let Expr::MethodCall(mc) = &current else {
            return current;
        };
        if matches!(
            mc.method.to_string().as_str(),
            "as_ref" | "as_str" | "clone" | "into_boxed_str" | "leak"
        ) && mc.args.is_empty()
        {
            current = (*mc.receiver).clone();
        } else {
            return current;
        }
    }
}

fn is_assembled_dynamic_sql(ctx: &KernelContext<'_>, arg: &Expr) -> bool {
    let text = strip_transparent_sql_methods(arg);
    ctx.is_dynamic_text(&text) || ctx.is_pushed_or_written_dynamic(&text)
}

fn type_contains_contended_mutex(ty: &Type) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; Mutex detection walks Path, Reference, Tuple, Paren, Group"
    )]
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .iter()
            .any(segment_contains_contended_mutex),
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
