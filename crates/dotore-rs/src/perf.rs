//! Single-pass detectors for Rust allocation and hot-loop performance rules:
//!
//! 1. `rs-perf-no-clone-in-loop` ([`RuleId::RsPerfNoCloneInLoop`])
//! 2. `rs-perf-hoist-regex-to-lazylock` ([`RuleId::RsPerfHoistRegexToLazylock`])
//! 3. `rs-perf-prefer-vec-with-capacity` ([`RuleId::RsPerfPreferVecWithCapacity`])
//! 4. `rs-perf-no-unnecessary-format` ([`RuleId::RsPerfNoUnnecessaryFormat`])

use std::collections::{HashMap, HashSet};

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Block, Expr, ExprBreak, ExprCall, ExprForLoop, ExprIf, ExprLet, ExprLoop, ExprMatch,
    ExprMethodCall, ExprReturn, ExprStruct, ExprTuple, ExprWhile, Fields, File, FnArg, ImplItemFn,
    ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemStruct, Lit, Local, Macro, Pat,
    Signature, Stmt, TraitItemFn,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::{
        RsCandidateFinding, RsScopeTracker, extract_expr_ident, extract_pat_ident,
        extract_receiver_label, is_cheap_clone_ctor, is_cheap_clone_type, is_cheap_handle_ident,
        is_format_macro_path, loc_at, path_to_string, span_to_bytes,
    },
    perf_helpers::{
        attrs_derive_serialize, collect_let_cond_idents, collect_pat_idents,
        collect_unconditional_pushed_vecs, expr_has_branch_bare_clone, extract_root_ident,
        field_has_deterministic_or_skip_serde_attr, is_bare_clone_call, is_bare_ident_receiver,
        is_bare_loop_item_clone, is_empty_vec_init, is_lazy_lock_init_call,
        is_unnecessary_format_tokens, is_unsized_loop_iterator, unordered_collection_type_name,
    },
};

/// All 9 Tokio async hazard, Rust allocation performance, and deterministic serialization rules.
pub const TOKIO_AND_PERF_RULES: &[RuleId] = &[
    RuleId::RsTokioNoStdLockAcrossAwait,
    RuleId::RsTokioNoBlockingInAsync,
    RuleId::RsTokioPreferBoundedChannel,
    RuleId::RsPerfNoCloneInLoop,
    RuleId::RsPerfHoistRegexToLazylock,
    RuleId::RsPerfPreferVecWithCapacity,
    RuleId::RsPerfNoUnnecessaryFormat,
    RuleId::RsPerfNoSyscallInLoop,
    RuleId::RsNoUnorderedCollectionInSerialize,
];

/// Runs single-pass Rust allocation performance detectors on the parsed [`syn::File`].
pub(crate) fn extract_perf_findings(
    file: &File,
    line_starts: &[u32],
    findings: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = PerfVisitor {
        line_starts,
        findings,
        scope: RsScopeTracker::for_file(file),
        cheap_clone_vars: HashSet::new(),
        loop_scoped_vars: Vec::new(),
        direct_for_loop_vars: Vec::new(),
        in_iter_closure: 0,
        in_diverging_expr: 0,
        in_owned_record_sink: 0,
        in_record_assembly_sink: 0,
        in_conditional_guard: 0,
        in_borrow_query_arg: 0,
    };
    visitor.visit_file(file);
}

struct PerfVisitor<'a> {
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    cheap_clone_vars: HashSet<String>,
    loop_scoped_vars: Vec<HashSet<String>>,
    direct_for_loop_vars: Vec<HashSet<String>>,
    in_iter_closure: u32,
    in_diverging_expr: u32,
    in_owned_record_sink: u32,
    in_record_assembly_sink: u32,
    in_conditional_guard: u32,
    in_borrow_query_arg: u32,
}

impl PerfVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn populate_sig_vars(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            if let FnArg::Typed(pat_type) = input
                && let Some(ident) = extract_pat_ident(&pat_type.pat)
                && is_cheap_clone_type(&pat_type.ty)
            {
                self.cheap_clone_vars.insert(ident);
            }
        }
    }

    fn is_cheap_clone_receiver(&self, receiver: &Expr) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has many variants; receiver classification inspects paths, field accesses, references, and calls"
        )]
        match receiver {
            Expr::Paren(p) => self.is_cheap_clone_receiver(&p.expr),
            Expr::Group(g) => self.is_cheap_clone_receiver(&g.expr),
            Expr::Reference(r) => self.is_cheap_clone_receiver(&r.expr),
            Expr::Path(expr_path) => {
                if let Some(ident) = expr_path.path.segments.last() {
                    let name = ident.ident.to_string();
                    if self.cheap_clone_vars.contains(&name) || is_cheap_handle_ident(&name) {
                        return true;
                    }
                }
                false
            }
            Expr::Field(field) => {
                if let syn::Member::Named(member_ident) = &field.member {
                    let member_name = member_ident.to_string();
                    if is_cheap_handle_ident(&member_name) {
                        return true;
                    }
                }
                self.is_cheap_clone_receiver(&field.base)
            }
            Expr::Call(call) => {
                if let Expr::Path(ep) = call.func.as_ref() {
                    let path_str = path_to_string(&ep.path);
                    if path_str.ends_with("Arc::new")
                        || path_str.ends_with("Rc::new")
                        || path_str.ends_with("Weak::new")
                    {
                        return true;
                    }
                }
                false
            }
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if matches!(
                    method.as_str(),
                    "peekable" | "fuse" | "enumerate" | "copied" | "cloned"
                ) {
                    return self.is_cheap_clone_receiver(&mc.receiver);
                }
                is_cheap_clone_ctor(receiver)
            }
            _ => false,
        }
    }

    fn is_per_element_ownership_transfer(&self, receiver: &Expr) -> bool {
        if self.in_borrow_query_arg > 0 {
            return false;
        }
        if self.in_record_assembly_sink > 0 {
            return true;
        }
        if self.in_owned_record_sink == 0 {
            return false;
        }
        self.in_conditional_guard > 0 || self.receiver_depends_on_loop_var(receiver)
    }

    fn receiver_depends_on_loop_var(&self, receiver: &Expr) -> bool {
        let Some(root) = extract_root_ident(receiver) else {
            return true;
        };
        self.loop_scoped_vars
            .iter()
            .any(|vars| vars.contains(&root))
    }

    fn check_regex_new_in_fn(&mut self, node: &ExprCall) {
        if self.scope.in_test()
            || self.scope.in_executable_body == 0
            || self.scope.in_static_or_lazy_init > 0
        {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        if matches!(
            path_str.as_str(),
            "Regex::new"
                | "regex::Regex::new"
                | "regex::bytes::Regex::new"
                | "RegexBuilder::new"
                | "regex::RegexBuilder::new"
                | "RegexSet::new"
                | "regex::RegexSet::new"
        ) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfHoistRegexToLazylock,
                self.scope.subject_name(),
                path_str.clone(),
                "rsPerfHoistRegexToLazylock",
                format!(
                    "`{path_str}(...)` compiles a regular expression on every execution; hoist static patterns into `std::sync::LazyLock<Regex>`."
                ),
                loc,
                span,
            ));
        }
    }

    fn check_syscall_in_loop(&mut self, node: &ExprCall) {
        if self.scope.in_test()
            || (!self.scope.in_loop() && self.in_iter_closure == 0)
            || self.scope.in_static_or_lazy_init > 0
        {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        let is_zero_arg_env_syscall = node.args.is_empty()
            && matches!(
                path_str.as_str(),
                "env::current_dir"
                    | "std::env::current_dir"
                    | "env::temp_dir"
                    | "std::env::temp_dir"
                    | "env::current_exe"
                    | "std::env::current_exe"
            );
        let is_const_env_var_syscall = node.args.len() == 1
            && matches!(
                path_str.as_str(),
                "env::var" | "std::env::var" | "env::var_os" | "std::env::var_os"
            )
            && matches!(
                node.args.first(),
                Some(Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(_),
                    ..
                }))
            );
        if is_zero_arg_env_syscall || is_const_env_var_syscall {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfNoSyscallInLoop,
                self.scope.subject_name(),
                path_str.clone(),
                "rsPerfNoSyscallInLoop",
                format!(
                    "`{path_str}(...)` queries OS process/environment state inside a loop or iterator closure; hoist the lookup once before the loop and reuse the cached value."
                ),
                loc,
                span,
            ));
        }
    }

    fn check_serializable_fields(&mut self, type_name: &str, fields: &Fields) {
        if self.scope.in_test() {
            return;
        }
        for field in fields {
            if field_has_deterministic_or_skip_serde_attr(&field.attrs) {
                continue;
            }
            let Some(coll_kind) = unordered_collection_type_name(&field.ty) else {
                continue;
            };
            let replacement = if coll_kind == "HashSet" {
                "BTreeSet"
            } else {
                "BTreeMap"
            };
            let field_label = field
                .ident
                .as_ref()
                .map_or_else(|| type_name.to_string(), ToString::to_string);
            let span = self.span_to_bytes(field.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsNoUnorderedCollectionInSerialize,
                Some(type_name.to_string()),
                field_label.clone(),
                "rsNoUnorderedCollectionInSerialize",
                format!(
                    "`{type_name}.{field_label}` serializes `{coll_kind}` with non-deterministic per-process `RandomState` iteration order; use `{replacement}` or annotate with `#[serde(serialize_with = ...)]` for deterministic output."
                ),
                loc,
                span,
            ));
        }
    }

    fn inspect_stmt_for_vec_capacity(
        &mut self,
        stmt: &Stmt,
        unreserved_vecs: &mut HashMap<String, (SourceLoc, ByteSpan)>,
    ) {
        if self.scope.in_test() {
            return;
        }
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init
                    && is_empty_vec_init(&init.expr)
                    && let Some(ident) = extract_pat_ident(&local.pat)
                {
                    let span = self.span_to_bytes(local.span());
                    let loc = self.loc_at(span.start);
                    unreserved_vecs.insert(ident, (loc, span));
                }
            }
            Stmt::Expr(Expr::MethodCall(mc), _) => {
                let method = mc.method.to_string();
                if matches!(method.as_str(), "reserve" | "reserve_exact" | "try_reserve")
                    && let Some(recv) = extract_expr_ident(&mc.receiver)
                {
                    unreserved_vecs.remove(&recv);
                }
            }
            Stmt::Expr(Expr::ForLoop(for_loop), _) => {
                if is_unsized_loop_iterator(&for_loop.expr) {
                    return;
                }
                let mut pushed_vars = Vec::new();
                collect_unconditional_pushed_vecs(&for_loop.body, &mut pushed_vars);
                for vec_name in pushed_vars {
                    let Some((loc, span)) = unreserved_vecs.remove(&vec_name) else {
                        continue;
                    };
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsPerfPreferVecWithCapacity,
                        self.scope.subject_name(),
                        vec_name.clone(),
                        "rsPerfPreferVecWithCapacity",
                        format!(
                            "`{vec_name}` is initialized with `Vec::new()` and populated unconditionally in a `for` loop; prefer `Vec::with_capacity(...)` to avoid repeated reallocations."
                        ),
                        loc,
                        span,
                    ));
                }
            }
            Stmt::Item(_) | Stmt::Expr(..) | Stmt::Macro(_) => {}
        }
    }

    fn record_local_stmt_bindings(&mut self, local: &syn::Local) {
        if let Some(loop_vars) = self.loop_scoped_vars.last_mut() {
            collect_pat_idents(&local.pat, loop_vars);
        }
        if let Pat::Type(pat_type) = &local.pat
            && let Some(ident) = extract_pat_ident(&pat_type.pat)
            && is_cheap_clone_type(&pat_type.ty)
        {
            self.cheap_clone_vars.insert(ident);
        }

        let Some(init) = &local.init else {
            return;
        };
        let Some(ident) = extract_pat_ident(&local.pat) else {
            return;
        };
        if is_cheap_clone_ctor(&init.expr) || self.is_cheap_clone_receiver(&init.expr) {
            self.cheap_clone_vars.insert(ident);
        }
    }

    fn check_clone_in_loop_method(&mut self, node: &ExprMethodCall, method_name: &str) {
        if self.scope.in_test()
            || !self.scope.in_loop()
            || self.in_diverging_expr > 0
            || method_name != "clone"
            || !node.args.is_empty()
            || self.is_cheap_clone_receiver(&node.receiver)
            || self.is_per_element_ownership_transfer(&node.receiver)
        {
            return;
        }
        let span = self.span_to_bytes(node.span());
        let loc = self.loc_at(span.start);
        let recv_label =
            extract_receiver_label(&node.receiver).unwrap_or_else(|| "value".to_string());
        self.findings.push(RsCandidateFinding::new(
            RuleId::RsPerfNoCloneInLoop,
            self.scope.subject_name(),
            format!("{recv_label}.clone()"),
            "rsPerfNoCloneInLoop",
            format!(
                "Heap `.clone()` on `{recv_label}` inside a loop allocates on every iteration; borrow `&{recv_label}`, hoist the clone outside the loop, or wrap shared data in `Arc`."
            ),
            loc,
            span,
        ));
    }

    fn classify_method_call_sink(&self, node: &ExprMethodCall, method_name: &str) -> (bool, bool, bool) {
        let is_collection_whole_item_push =
            matches!(method_name, "push" | "push_back" | "push_front")
                && node.args.len() == 1
                && is_bare_ident_receiver(&node.receiver)
                && node
                    .args
                    .first()
                    .is_some_and(|arg| is_bare_loop_item_clone(arg, &self.direct_for_loop_vars));
        let is_borrow_query_method = matches!(
            method_name,
            "contains"
                | "contains_key"
                | "get"
                | "get_mut"
                | "get_key_value"
                | "remove"
                | "remove_entry"
        );
        let is_record_assembly = (node.args.len() >= 2
            || method_name.starts_with("with_")
            || matches!(method_name, "unwrap_or_else" | "map_or_else"))
            && !is_borrow_query_method;
        let is_owned_sink = !is_collection_whole_item_push && !is_borrow_query_method;
        (is_owned_sink, is_record_assembly, is_borrow_query_method)
    }
}

impl<'ast> Visit<'ast> for PerfVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        if !self.scope.in_test()
            && !crate::matchers::attrs_indicate_test_context(&i.attrs)
            && attrs_derive_serialize(&i.attrs)
        {
            self.check_serializable_fields(&i.ident.to_string(), &i.fields);
        }
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        if !self.scope.in_test()
            && !crate::matchers::attrs_indicate_test_context(&i.attrs)
            && attrs_derive_serialize(&i.attrs)
        {
            let enum_name = i.ident.to_string();
            for variant in &i.variants {
                if !field_has_deterministic_or_skip_serde_attr(&variant.attrs) {
                    self.check_serializable_fields(&enum_name, &variant.fields);
                }
            }
        }
        visit::visit_item_enum(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_static(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_const(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_loop_vars = std::mem::take(&mut self.loop_scoped_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.loop_scoped_vars = prev_loop_vars;
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_loop_vars = std::mem::take(&mut self.loop_scoped_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.loop_scoped_vars = prev_loop_vars;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_loop_vars = std::mem::take(&mut self.loop_scoped_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_trait_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.loop_scoped_vars = prev_loop_vars;
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let mut unreserved_vecs: HashMap<String, (SourceLoc, ByteSpan)> = HashMap::new();

        for stmt in &b.stmts {
            self.inspect_stmt_for_vec_capacity(stmt, &mut unreserved_vecs);
            if let Stmt::Local(local) = stmt {
                self.record_local_stmt_bindings(local);
            }
            self.visit_stmt(stmt);
        }
    }

    fn visit_local(&mut self, i: &'ast Local) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_pat(&i.pat);
        if let Some(init) = &i.init {
            let prev_sink = self.in_owned_record_sink;
            let prev_borrow = self.in_borrow_query_arg;
            if is_bare_clone_call(&init.expr) || expr_has_branch_bare_clone(&init.expr) {
                self.in_owned_record_sink = 0;
                self.in_borrow_query_arg = 0;
            }
            self.visit_expr(&init.expr);
            self.in_owned_record_sink = prev_sink;
            self.in_borrow_query_arg = prev_borrow;
            if let Some((_, diverge)) = &init.diverge {
                self.in_diverging_expr += 1;
                self.visit_expr(diverge);
                self.in_diverging_expr -= 1;
            }
        }
    }

    fn visit_expr_return(&mut self, i: &'ast ExprReturn) {
        self.in_diverging_expr += 1;
        visit::visit_expr_return(self, i);
        self.in_diverging_expr -= 1;
    }

    fn visit_expr_break(&mut self, i: &'ast ExprBreak) {
        self.in_diverging_expr += 1;
        visit::visit_expr_break(self, i);
        self.in_diverging_expr -= 1;
    }

    fn visit_expr_struct(&mut self, i: &'ast ExprStruct) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        if let Some(qself) = &i.qself {
            self.visit_qself(qself);
        }
        self.visit_path(&i.path);
        self.in_owned_record_sink += 1;
        self.in_record_assembly_sink += 1;
        for field in &i.fields {
            self.visit_field_value(field);
        }
        self.in_record_assembly_sink -= 1;
        self.in_owned_record_sink -= 1;
        if let Some(rest) = &i.rest {
            self.visit_expr(rest);
        }
    }

    fn visit_expr_tuple(&mut self, i: &'ast ExprTuple) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.in_owned_record_sink += 1;
        self.in_record_assembly_sink += 1;
        for elem in &i.elems {
            self.visit_expr(elem);
        }
        self.in_record_assembly_sink -= 1;
        self.in_owned_record_sink -= 1;
    }

    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_pat(&i.pat);
        self.visit_expr(&i.expr);
        let mut loop_vars = HashSet::new();
        let mut direct_loop_vars = HashSet::new();
        collect_pat_idents(&i.pat, &mut loop_vars);
        collect_pat_idents(&i.pat, &mut direct_loop_vars);
        self.loop_scoped_vars.push(loop_vars);
        self.direct_for_loop_vars.push(direct_loop_vars);
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
        self.direct_for_loop_vars.pop();
        self.loop_scoped_vars.pop();
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        let mut loop_vars = HashSet::new();
        collect_let_cond_idents(&i.cond, &mut loop_vars);
        self.visit_expr(&i.cond);
        self.loop_scoped_vars.push(loop_vars);
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
        self.loop_scoped_vars.pop();
    }

    fn visit_expr_loop(&mut self, i: &'ast ExprLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.loop_scoped_vars.push(HashSet::new());
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
        self.loop_scoped_vars.pop();
    }

    fn visit_expr_let(&mut self, i: &'ast ExprLet) {
        if let Some(loop_vars) = self.loop_scoped_vars.last_mut() {
            collect_pat_idents(&i.pat, loop_vars);
        }
        visit::visit_expr_let(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&i.cond);
        self.in_conditional_guard += 1;
        self.visit_block(&i.then_branch);
        if let Some((_, else_expr)) = &i.else_branch {
            self.visit_expr(else_expr);
        }
        self.in_conditional_guard -= 1;
    }

    fn visit_expr_match(&mut self, i: &'ast ExprMatch) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&i.expr);
        for arm in &i.arms {
            if let Some(loop_vars) = self.loop_scoped_vars.last_mut() {
                collect_pat_idents(&arm.pat, loop_vars);
            }
            for attr in &arm.attrs {
                self.visit_attribute(attr);
            }
            self.visit_pat(&arm.pat);
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.in_conditional_guard += 1;
            self.visit_expr(&arm.body);
            self.in_conditional_guard -= 1;
        }
    }

    fn visit_expr_closure(&mut self, i: &'ast syn::ExprClosure) {
        if let Some(loop_vars) = self.loop_scoped_vars.last_mut() {
            for input in &i.inputs {
                collect_pat_idents(input, loop_vars);
            }
        }
        visit::visit_expr_closure(self, i);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_regex_new_in_fn(node);
        self.check_syscall_in_loop(node);

        let is_lazy_init = is_lazy_lock_init_call(node);
        if is_lazy_init {
            self.scope.in_static_or_lazy_init += 1;
        }
        for attr in &node.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&node.func);
        let is_record_assembly = node.args.len() >= 2;
        self.in_owned_record_sink += 1;
        if is_record_assembly {
            self.in_record_assembly_sink += 1;
        }
        for arg in &node.args {
            self.visit_expr(arg);
        }
        if is_record_assembly {
            self.in_record_assembly_sink -= 1;
        }
        self.in_owned_record_sink -= 1;
        if is_lazy_init {
            self.scope.in_static_or_lazy_init -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        self.check_clone_in_loop_method(node, &method_name);

        let is_once_init = matches!(
            method_name.as_str(),
            "get_or_init" | "get_or_try_init" | "call_once"
        );
        let is_iter_adapter = is_iter_closure_adapter_method(&method_name, node);
        if is_once_init {
            self.scope.in_static_or_lazy_init += 1;
        }
        for attr in &node.attrs {
            self.visit_attribute(attr);
        }
        let is_option_fallback = matches!(
            method_name.as_str(),
            "unwrap_or_else" | "unwrap_or" | "map_or_else" | "map_or" | "or_else"
        );
        self.in_owned_record_sink += u32::from(is_option_fallback);
        self.visit_expr(&node.receiver);
        self.in_owned_record_sink -= u32::from(is_option_fallback);
        self.in_iter_closure += u32::from(is_iter_adapter);

        let (owned_sink, record_assembly, borrow_query) =
            self.classify_method_call_sink(node, &method_name);
        self.in_owned_record_sink += u32::from(owned_sink);
        self.in_record_assembly_sink += u32::from(record_assembly);
        self.in_borrow_query_arg += u32::from(borrow_query);
        for arg in &node.args {
            self.visit_expr(arg);
        }
        self.in_borrow_query_arg -= u32::from(borrow_query);
        self.in_record_assembly_sink -= u32::from(record_assembly);
        self.in_owned_record_sink -= u32::from(owned_sink);
        self.in_iter_closure -= u32::from(is_iter_adapter);
        if is_once_init {
            self.scope.in_static_or_lazy_init -= 1;
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if !self.scope.in_test()
            && is_format_macro_path(&mac.path)
            && is_unnecessary_format_tokens(&mac.tokens)
        {
            let span = self.span_to_bytes(mac.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfNoUnnecessaryFormat,
                self.scope.subject_name(),
                "format!",
                "rsPerfNoUnnecessaryFormat",
                "Unnecessary `format!(...)` call allocates a formatted `String` without formatting; use `.to_string()`, `String::from(...)`, or a borrowed `&str`.",
                loc,
                span,
            ));
        }
        visit::visit_macro(self, mac);
    }
}

fn is_iter_closure_adapter_method(method_name: &str, node: &ExprMethodCall) -> bool {
    matches!(
        method_name,
        "map"
            | "filter"
            | "filter_map"
            | "flat_map"
            | "for_each"
            | "any"
            | "all"
            | "find"
            | "find_map"
            | "position"
            | "max_by_key"
            | "min_by_key"
            | "sort_by"
            | "sort_by_key"
    ) && node.args.iter().any(|arg| matches!(arg, Expr::Closure(_)))
}
