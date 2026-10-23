//! Single-pass detectors for Tokio async concurrency hazards and Rust hot-loop allocation
//! performance rules (`Ticket #16`):
//!
//! 1. `rs-tokio-no-std-lock-across-await` ([`RuleId::RsTokioNoStdLockAcrossAwait`])
//! 2. `rs-tokio-no-blocking-in-async` ([`RuleId::RsTokioNoBlockingInAsync`], `Autofix`)
//! 3. `rs-tokio-prefer-bounded-channel` ([`RuleId::RsTokioPreferBoundedChannel`])
//! 4. `rs-perf-no-clone-in-loop` ([`RuleId::RsPerfNoCloneInLoop`])
//! 5. `rs-perf-hoist-regex-to-lazylock` ([`RuleId::RsPerfHoistRegexToLazylock`])
//! 6. `rs-perf-prefer-vec-with-capacity` ([`RuleId::RsPerfPreferVecWithCapacity`])
//! 7. `rs-perf-no-unnecessary-format` ([`RuleId::RsPerfNoUnnecessaryFormat`])

use std::collections::{HashMap, HashSet};

use dotore_core::{AutofixPatch, ByteEdit, ByteSpan, RuleId, SourceLoc, loc_from_line_starts};
use syn::{
    Attribute, Block, Expr, ExprAsync, ExprAwait, ExprCall, ExprClosure, ExprForLoop, ExprIf,
    ExprLoop, ExprMethodCall, ExprWhile, File, FnArg, ImplItemFn, Item, ItemConst, ItemFn,
    ItemImpl, ItemMod, ItemStatic, Lit, Macro, Pat, ReturnType, Signature, Stmt, Token,
    TraitItemFn, Type, UseTree,
    parse::Parser,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::ir::RsCandidateFinding;

/// All 7 Tokio async hazard and Rust allocation performance rules implemented in this module.
pub const TOKIO_AND_PERF_RULES: &[RuleId] = &[
    RuleId::RsTokioNoStdLockAcrossAwait,
    RuleId::RsTokioNoBlockingInAsync,
    RuleId::RsTokioPreferBoundedChannel,
    RuleId::RsPerfNoCloneInLoop,
    RuleId::RsPerfHoistRegexToLazylock,
    RuleId::RsPerfPreferVecWithCapacity,
    RuleId::RsPerfNoUnnecessaryFormat,
];

/// Runs single-pass Tokio async and Rust performance detectors on the parsed [`syn::File`].
pub fn extract_tokio_perf_findings(
    file: &File,
    source: &str,
    line_starts: &[u32],
    findings: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = TokioPerfVisitor {
        source,
        line_starts,
        findings,
        in_test_context: attrs_indicate_test_context(&file.attrs),
        current_subject_name: None,
        current_parent_type: None,
        tokio_sync_type_names: HashSet::new(),
        tokio_sync_vars: HashSet::new(),
        cheap_clone_vars: HashSet::new(),
        std_thread_sleep_imported: false,
        tokio_time_sleep_imported: false,
        tokio_fs_imported: false,
        std_fs_file_imported: false,
        std_net_imported: false,
        tokio_unbounded_channel_imported: false,
        async_depth: 0,
        spawn_blocking_depth: 0,
        loop_depth: 0,
        in_executable_body: 0,
        in_static_or_lazy_init: 0,
        active_sync_guards: Vec::new(),
    };

    for item in &file.items {
        if let Item::Use(item_use) = item {
            visitor.collect_use_tree(&item_use.tree, "");
        }
    }

    visitor.visit_file(file);
}

#[derive(Debug, Clone)]
struct ActiveSyncGuard {
    guard_name: String,
    lock_target: String,
    acq_loc: SourceLoc,
    acq_span: ByteSpan,
    dropped: bool,
    reported: bool,
}

struct TokioPerfVisitor<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    in_test_context: bool,
    current_subject_name: Option<String>,
    current_parent_type: Option<String>,
    tokio_sync_type_names: HashSet<String>,
    tokio_sync_vars: HashSet<String>,
    cheap_clone_vars: HashSet<String>,
    std_thread_sleep_imported: bool,
    tokio_time_sleep_imported: bool,
    tokio_fs_imported: bool,
    std_fs_file_imported: bool,
    std_net_imported: bool,
    tokio_unbounded_channel_imported: bool,
    async_depth: usize,
    spawn_blocking_depth: usize,
    loop_depth: usize,
    in_executable_body: usize,
    in_static_or_lazy_init: usize,
    active_sync_guards: Vec<ActiveSyncGuard>,
}

impl TokioPerfVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        let range = span.byte_range();
        let start = u32::try_from(range.start).unwrap_or(0);
        let end = u32::try_from(range.end).unwrap_or(start);
        ByteSpan { start, end }
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_from_line_starts(self.line_starts, byte_offset)
    }

    fn slice_source(&self, span: ByteSpan) -> &str {
        let start = usize::try_from(span.start).unwrap_or(0);
        let end = usize::try_from(span.end)
            .unwrap_or(start)
            .min(self.source.len());
        if start <= end && end <= self.source.len() {
            &self.source[start..end]
        } else {
            ""
        }
    }

    fn collect_use_tree(&mut self, tree: &UseTree, prefix: &str) {
        match tree {
            UseTree::Path(use_path) => {
                let next = if prefix.is_empty() {
                    use_path.ident.to_string()
                } else {
                    format!("{prefix}::{}", use_path.ident)
                };
                self.collect_use_tree(&use_path.tree, &next);
            }
            UseTree::Name(use_name) => {
                let ident = use_name.ident.to_string();
                let full = if prefix.is_empty() {
                    ident.clone()
                } else {
                    format!("{prefix}::{ident}")
                };
                self.register_imported_symbol(&full, &ident);
            }
            UseTree::Rename(use_rename) => {
                let orig = use_rename.ident.to_string();
                let alias = use_rename.rename.to_string();
                let full = if prefix.is_empty() {
                    orig
                } else {
                    format!("{prefix}::{orig}")
                };
                self.register_imported_symbol(&full, &alias);
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use_tree(item, prefix);
                }
            }
            UseTree::Glob(_) => {
                if prefix == "tokio::sync" {
                    self.tokio_sync_type_names.insert("Mutex".to_string());
                    self.tokio_sync_type_names.insert("RwLock".to_string());
                } else if prefix == "std::sync" {
                    self.tokio_sync_type_names.remove("Mutex");
                    self.tokio_sync_type_names.remove("RwLock");
                }
            }
        }
    }

    fn register_imported_symbol(&mut self, full_path: &str, bound_name: &str) {
        match full_path {
            "tokio::sync::Mutex" | "sync::Mutex" => {
                self.tokio_sync_type_names.insert(bound_name.to_string());
            }
            "tokio::sync::RwLock" | "sync::RwLock" => {
                self.tokio_sync_type_names.insert(bound_name.to_string());
            }
            "std::sync::Mutex" | "parking_lot::Mutex" => {
                self.tokio_sync_type_names.remove(bound_name);
            }
            "std::sync::RwLock" | "parking_lot::RwLock" => {
                self.tokio_sync_type_names.remove(bound_name);
            }
            "std::thread::sleep" | "core::thread::sleep" | "thread::sleep" => {
                self.std_thread_sleep_imported = true;
            }
            "tokio::time::sleep" | "time::sleep" => {
                self.tokio_time_sleep_imported = true;
            }
            "tokio::fs" => {
                self.tokio_fs_imported = true;
            }
            "std::fs::File" => {
                self.std_fs_file_imported = true;
            }
            "std::net::TcpStream" | "std::net::TcpListener" | "std::net::UdpSocket"
            | "std::net" => {
                self.std_net_imported = true;
            }
            "tokio::sync::mpsc::unbounded_channel" | "mpsc::unbounded_channel" => {
                self.tokio_unbounded_channel_imported = true;
            }
            _ => {}
        }
    }

    fn populate_sig_vars(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            if let FnArg::Typed(pat_type) = input
                && let Some(ident) = extract_pat_ident(&pat_type.pat)
            {
                if is_tokio_sync_type(&pat_type.ty, &self.tokio_sync_type_names) {
                    self.tokio_sync_vars.insert(ident.clone());
                }
                if is_cheap_clone_type(&pat_type.ty) {
                    self.cheap_clone_vars.insert(ident);
                }
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
            _ => false,
        }
    }

    fn extract_sync_lock_acquisition(&self, expr: &Expr) -> Option<String> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Unwrapping lock result chains inspects try (`?`), method chains (`.unwrap()`/`.expect()`), and parens"
        )]
        match expr {
            Expr::Await(_) => None,
            Expr::Paren(p) => self.extract_sync_lock_acquisition(&p.expr),
            Expr::Group(g) => self.extract_sync_lock_acquisition(&g.expr),
            Expr::Try(expr_try) => self.extract_sync_lock_acquisition(&expr_try.expr),
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if matches!(
                    method.as_str(),
                    "unwrap" | "expect" | "unwrap_or_else" | "ok"
                ) {
                    return self.extract_sync_lock_acquisition(&mc.receiver);
                }
                if matches!(
                    method.as_str(),
                    "lock" | "read" | "write" | "try_lock" | "try_read" | "try_write"
                ) && mc.args.is_empty()
                {
                    if self.is_tokio_sync_receiver(&mc.receiver) {
                        return None;
                    }
                    let recv_name = extract_receiver_label(&mc.receiver)
                        .unwrap_or_else(|| "mutex".to_string());
                    return Some(format!("{recv_name}.{method}()"));
                }
                None
            }
            _ => None,
        }
    }

    fn is_tokio_sync_receiver(&self, expr: &Expr) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Tokio sync receiver check inspects paths, references, and field accesses"
        )]
        match expr {
            Expr::Paren(p) => self.is_tokio_sync_receiver(&p.expr),
            Expr::Group(g) => self.is_tokio_sync_receiver(&g.expr),
            Expr::Reference(r) => self.is_tokio_sync_receiver(&r.expr),
            Expr::Path(ep) => {
                let full = path_to_string(&ep.path);
                if full.starts_with("tokio::sync::") {
                    return true;
                }
                if let Some(ident) = ep.path.get_ident() {
                    let name = ident.to_string();
                    if self.tokio_sync_vars.contains(&name) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn check_blocking_call_in_async(&mut self, node: &ExprCall) {
        if self.in_test_context || self.async_depth == 0 || self.spawn_blocking_depth > 0 {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        if expr_path.qself.is_some() {
            return;
        }
        let path_str = path_to_string(&expr_path.path);

        // 1. `std::thread::sleep(dur)` / `thread::sleep(dur)` -> Autofix to `tokio::time::sleep(dur).await`
        let is_std_sleep = matches!(
            path_str.as_str(),
            "std::thread::sleep" | "core::thread::sleep" | "thread::sleep"
        ) || (path_str == "sleep"
            && self.std_thread_sleep_imported
            && !self.tokio_time_sleep_imported);

        if is_std_sleep {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let autofix = if node.args.len() == 1
                && let Some(first_arg) = node.args.first()
            {
                let arg_span = self.span_to_bytes(first_arg.span());
                let arg_src = self.slice_source(arg_span);
                if !arg_src.is_empty() {
                    Some(AutofixPatch {
                        description: format!(
                            "Replace blocking `{path_str}({arg_src})` with `tokio::time::sleep({arg_src}).await`"
                        ),
                        edits: vec![ByteEdit {
                            file: None,
                            span,
                            replacement: format!("tokio::time::sleep({arg_src}).await"),
                        }],
                    })
                } else {
                    None
                }
            } else {
                None
            };

            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsTokioNoBlockingInAsync,
                subject_name: self.current_subject_name.clone(),
                target_name: path_str.clone(),
                message_id: "rsTokioNoBlockingInAsync",
                message: format!(
                    "Blocking call `{path_str}(...)` inside an async context parks the Tokio worker thread; use `tokio::time::sleep(...).await` instead."
                ),
                loc,
                span,
                autofix,
            });
            return;
        }

        // 2. Synchronous `std::fs::*` and `std::net::*` calls inside async
        if is_blocking_std_fs_or_net_path(
            &path_str,
            self.tokio_fs_imported,
            self.std_fs_file_imported,
            self.std_net_imported,
        ) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsTokioNoBlockingInAsync,
                subject_name: self.current_subject_name.clone(),
                target_name: path_str.clone(),
                message_id: "rsTokioNoBlockingInAsync",
                message: format!(
                    "Synchronous I/O call `{path_str}(...)` blocks the async runtime thread; use `tokio::fs` / `tokio::net` or wrap in `tokio::task::spawn_blocking(...)`."
                ),
                loc,
                span,
                autofix: None,
            });
        }
    }

    fn check_unbounded_channel_call(&mut self, node: &ExprCall) {
        if self.in_test_context || !node.args.is_empty() {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        let is_unbounded = matches!(
            path_str.as_str(),
            "tokio::sync::mpsc::unbounded_channel"
                | "sync::mpsc::unbounded_channel"
                | "mpsc::unbounded_channel"
        ) || (path_str == "unbounded_channel"
            && self.tokio_unbounded_channel_imported);

        if is_unbounded {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsTokioPreferBoundedChannel,
                subject_name: self.current_subject_name.clone(),
                target_name: path_str.clone(),
                message_id: "rsTokioPreferBoundedChannel",
                message: format!(
                    "`{path_str}()` disables channel backpressure and risks unbounded memory growth under load; prefer bounded `tokio::sync::mpsc::channel(capacity)`."
                ),
                loc,
                span,
                autofix: None,
            });
        }
    }

    fn check_regex_new_in_fn(&mut self, node: &ExprCall) {
        if self.in_test_context
            || self.in_executable_body == 0
            || self.in_static_or_lazy_init > 0
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
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsPerfHoistRegexToLazylock,
                subject_name: self.current_subject_name.clone(),
                target_name: path_str.clone(),
                message_id: "rsPerfHoistRegexToLazylock",
                message: format!(
                    "`{path_str}(...)` compiles a regular expression on every execution; hoist static patterns into `std::sync::LazyLock<Regex>`."
                ),
                loc,
                span,
                autofix: None,
            });
        }
    }

    fn check_drop_call(&mut self, node: &ExprCall) {
        if node.args.len() != 1 {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        if matches!(
            path_str.as_str(),
            "drop" | "std::mem::drop" | "core::mem::drop" | "mem::drop"
        ) && let Some(first_arg) = node.args.first()
            && let Some(ident) = extract_expr_ident(first_arg)
        {
            for guard in &mut self.active_sync_guards {
                if guard.guard_name == ident {
                    guard.dropped = true;
                }
            }
        }
    }

    fn inspect_stmt_for_vec_capacity(
        &mut self,
        stmt: &Stmt,
        unreserved_vecs: &mut HashMap<String, (SourceLoc, ByteSpan)>,
    ) {
        if self.in_test_context {
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
                if matches!(
                    method.as_str(),
                    "reserve" | "reserve_exact" | "try_reserve"
                ) && let Some(recv) = extract_expr_ident(&mc.receiver)
                {
                    unreserved_vecs.remove(&recv);
                }
            }
            Stmt::Expr(Expr::ForLoop(for_loop), _) => {
                let mut pushed_vars = Vec::new();
                collect_unconditional_pushed_vecs(&for_loop.body, &mut pushed_vars);
                for vec_name in pushed_vars {
                    let Some((loc, span)) = unreserved_vecs.remove(&vec_name) else {
                        continue;
                    };
                    self.findings.push(RsCandidateFinding {
                        rule: RuleId::RsPerfPreferVecWithCapacity,
                        subject_name: self.current_subject_name.clone(),
                        target_name: vec_name.clone(),
                        message_id: "rsPerfPreferVecWithCapacity",
                        message: format!(
                            "`{vec_name}` is initialized with `Vec::new()` and populated unconditionally in a `for` loop; prefer `Vec::with_capacity(...)` to avoid repeated reallocations."
                        ),
                        loc,
                        span,
                        autofix: None,
                    });
                }
            }
            Stmt::Item(_) | Stmt::Expr(..) | Stmt::Macro(_) => {}
        }
    }

    fn record_local_stmt_bindings(&mut self, local: &syn::Local) {
        if let Pat::Type(pat_type) = &local.pat
            && let Some(ident) = extract_pat_ident(&pat_type.pat)
        {
            if is_tokio_sync_type(&pat_type.ty, &self.tokio_sync_type_names) {
                self.tokio_sync_vars.insert(ident.clone());
            }
            if is_cheap_clone_type(&pat_type.ty) {
                self.cheap_clone_vars.insert(ident);
            }
        }

        let Some(init) = &local.init else {
            return;
        };
        let Some(ident) = extract_pat_ident(&local.pat) else {
            return;
        };
        if is_tokio_sync_ctor(&init.expr, &self.tokio_sync_type_names) {
            self.tokio_sync_vars.insert(ident.clone());
        }
        if is_cheap_clone_ctor(&init.expr) {
            self.cheap_clone_vars.insert(ident.clone());
        }
        if !self.in_test_context
            && let Some(lock_target) = self.extract_sync_lock_acquisition(&init.expr)
        {
            let span = self.span_to_bytes(local.span());
            let loc = self.loc_at(span.start);
            self.active_sync_guards.push(ActiveSyncGuard {
                guard_name: ident,
                lock_target,
                acq_loc: loc,
                acq_span: span,
                dropped: false,
                reported: false,
            });
        }
    }
}

impl<'ast> Visit<'ast> for TokioPerfVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let prev_test = self.in_test_context;
        let is_test_mod =
            prev_test || attrs_indicate_test_context(&i.attrs) || i.ident == "tests";
        self.in_test_context = is_test_mod;

        let prev_subj = self.current_subject_name.replace(i.ident.to_string());
        visit::visit_item_mod(self, i);
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        self.in_static_or_lazy_init += 1;
        visit::visit_item_static(self, i);
        self.in_static_or_lazy_init -= 1;
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        self.in_static_or_lazy_init += 1;
        visit::visit_item_const(self, i);
        self.in_static_or_lazy_init -= 1;
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);

        let prev_subj = self.current_subject_name.replace(i.sig.ident.to_string());
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        let prev_async = self.async_depth;
        let prev_loop = self.loop_depth;

        self.async_depth = usize::from(i.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        self.populate_sig_vars(&i.sig);

        visit::visit_item_fn(self, i);

        self.in_executable_body -= 1;
        self.async_depth = prev_async;
        self.loop_depth = prev_loop;
        self.active_sync_guards = prev_guards;
        self.cheap_clone_vars = prev_cheap_vars;
        self.tokio_sync_vars = prev_tokio_vars;
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);

        let self_ty = extract_type_last_ident(&i.self_ty).unwrap_or_else(|| "Impl".to_string());
        let prev_parent = self.current_parent_type.replace(self_ty.clone());
        let prev_subj = self.current_subject_name.replace(self_ty);

        visit::visit_item_impl(self, i);

        self.current_subject_name = prev_subj;
        self.current_parent_type = prev_parent;
        self.in_test_context = prev_test;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let prev_test = self.in_test_context;
        self.in_test_context = prev_test || attrs_indicate_test_context(&i.attrs);

        let method_name = i.sig.ident.to_string();
        let qualified = if let Some(parent) = &self.current_parent_type {
            format!("{parent}::{method_name}")
        } else {
            method_name
        };

        let prev_subj = self.current_subject_name.replace(qualified);
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        let prev_async = self.async_depth;
        let prev_loop = self.loop_depth;

        self.async_depth = usize::from(i.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        self.populate_sig_vars(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.in_executable_body -= 1;
        self.async_depth = prev_async;
        self.loop_depth = prev_loop;
        self.active_sync_guards = prev_guards;
        self.cheap_clone_vars = prev_cheap_vars;
        self.tokio_sync_vars = prev_tokio_vars;
        self.current_subject_name = prev_subj;
        self.in_test_context = prev_test;
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let prev_subj = self.current_subject_name.replace(i.sig.ident.to_string());
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        let prev_async = self.async_depth;
        let prev_loop = self.loop_depth;

        self.async_depth = usize::from(i.sig.asyncness.is_some());
        self.loop_depth = 0;
        self.in_executable_body += 1;
        self.populate_sig_vars(&i.sig);

        visit::visit_trait_item_fn(self, i);

        self.in_executable_body -= 1;
        self.async_depth = prev_async;
        self.loop_depth = prev_loop;
        self.active_sync_guards = prev_guards;
        self.cheap_clone_vars = prev_cheap_vars;
        self.tokio_sync_vars = prev_tokio_vars;
        self.current_subject_name = prev_subj;
    }

    fn visit_expr_async(&mut self, i: &'ast ExprAsync) {
        self.async_depth += 1;
        visit::visit_expr_async(self, i);
        self.async_depth -= 1;
    }

    fn visit_expr_closure(&mut self, i: &'ast ExprClosure) {
        let added_async = usize::from(i.asyncness.is_some());
        self.async_depth += added_async;
        visit::visit_expr_closure(self, i);
        self.async_depth -= added_async;
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let saved_guards_len = self.active_sync_guards.len();
        let mut unreserved_vecs: HashMap<String, (SourceLoc, ByteSpan)> = HashMap::new();

        for stmt in &b.stmts {
            self.inspect_stmt_for_vec_capacity(stmt, &mut unreserved_vecs);
            self.visit_stmt(stmt);
            if let Stmt::Local(local) = stmt {
                self.record_local_stmt_bindings(local);
            }
        }

        self.active_sync_guards.truncate(saved_guards_len);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.visit_expr(&i.cond);

        let saved_guards_len = self.active_sync_guards.len();
        if !self.in_test_context
            && let Expr::Let(expr_let) = i.cond.as_ref()
            && let Some(ident) = extract_pat_ident(&expr_let.pat)
            && let Some(lock_target) = self.extract_sync_lock_acquisition(&expr_let.expr)
        {
            let span = self.span_to_bytes(expr_let.span());
            let loc = self.loc_at(span.start);
            self.active_sync_guards.push(ActiveSyncGuard {
                guard_name: ident,
                lock_target,
                acq_loc: loc,
                acq_span: span,
                dropped: false,
                reported: false,
            });
        }

        self.visit_block(&i.then_branch);
        self.active_sync_guards.truncate(saved_guards_len);

        if let Some((_, else_expr)) = &i.else_branch {
            self.visit_expr(else_expr);
        }
    }

    fn visit_expr_await(&mut self, i: &'ast ExprAwait) {
        // First visit the awaited expression (e.g. `tokio_mu.lock()` in `tokio_mu.lock().await`)
        self.visit_expr(&i.base);

        if !self.in_test_context {
            for guard in &mut self.active_sync_guards {
                if !guard.dropped && !guard.reported {
                    guard.reported = true;
                    self.findings.push(RsCandidateFinding {
                        rule: RuleId::RsTokioNoStdLockAcrossAwait,
                        subject_name: self.current_subject_name.clone(),
                        target_name: guard.guard_name.clone(),
                        message_id: "rsTokioNoStdLockAcrossAwait",
                        message: format!(
                            "Synchronous lock guard `{}` (from `{}`) is held across an `.await` point; drop `{}` before `.await` or use `tokio::sync::Mutex` / `RwLock`.",
                            guard.guard_name, guard.lock_target, guard.guard_name
                        ),
                        loc: guard.acq_loc,
                        span: guard.acq_span,
                        autofix: None,
                    });
                }
            }
        }
    }

    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_pat(&i.pat);
        self.visit_expr(&i.expr);
        self.loop_depth += 1;
        self.visit_block(&i.body);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&i.cond);
        self.loop_depth += 1;
        self.visit_block(&i.body);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, i: &'ast ExprLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.loop_depth += 1;
        self.visit_block(&i.body);
        self.loop_depth -= 1;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_drop_call(node);
        self.check_blocking_call_in_async(node);
        self.check_unbounded_channel_call(node);
        self.check_regex_new_in_fn(node);

        let is_spawn_blocking = is_spawn_blocking_call(node);
        let is_lazy_init = is_lazy_lock_init_call(node);

        if is_spawn_blocking {
            self.spawn_blocking_depth += 1;
        }
        if is_lazy_init {
            self.in_static_or_lazy_init += 1;
        }

        visit::visit_expr_call(self, node);

        if is_lazy_init {
            self.in_static_or_lazy_init -= 1;
        }
        if is_spawn_blocking {
            self.spawn_blocking_depth -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();

        if !self.in_test_context
            && self.loop_depth > 0
            && method_name == "clone"
            && node.args.is_empty()
            && !self.is_cheap_clone_receiver(&node.receiver)
        {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let recv_label =
                extract_receiver_label(&node.receiver).unwrap_or_else(|| "value".to_string());
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsPerfNoCloneInLoop,
                subject_name: self.current_subject_name.clone(),
                target_name: format!("{recv_label}.clone()"),
                message_id: "rsPerfNoCloneInLoop",
                message: format!(
                    "Heap `.clone()` on `{recv_label}` inside a loop allocates on every iteration; borrow `&{recv_label}`, hoist the clone outside the loop, or wrap shared data in `Arc`."
                ),
                loc,
                span,
                autofix: None,
            });
        }

        let is_once_init = matches!(
            method_name.as_str(),
            "get_or_init" | "get_or_try_init" | "call_once"
        );
        if is_once_init {
            self.in_static_or_lazy_init += 1;
        }
        visit::visit_expr_method_call(self, node);
        if is_once_init {
            self.in_static_or_lazy_init -= 1;
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if !self.in_test_context
            && is_format_macro(&mac.path)
            && is_unnecessary_format_tokens(&mac.tokens)
        {
            let span = self.span_to_bytes(mac.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding {
                rule: RuleId::RsPerfNoUnnecessaryFormat,
                subject_name: self.current_subject_name.clone(),
                target_name: "format!".to_string(),
                message_id: "rsPerfNoUnnecessaryFormat",
                message: "Unnecessary `format!(...)` call allocates a formatted `String` without formatting; use `.to_string()`, `String::from(...)`, or a borrowed `&str`.".to_string(),
                loc,
                span,
                autofix: None,
            });
        }
        visit::visit_macro(self, mac);
    }
}

fn attrs_indicate_test_context(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        let path_str = path_to_string(attr.path());
        if matches!(
            path_str.as_str(),
            "test" | "tokio::test" | "sqlx::test" | "actix_rt::test" | "rstest" | "bench"
        ) || path_str.ends_with("::test")
        {
            return true;
        }
        if path_str == "cfg"
            && let Ok(tokens) = attr.meta.require_list()
        {
            let token_str = tokens.tokens.to_string();
            if token_str
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|tok| tok == "test")
            {
                return true;
            }
        }
    }
    false
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn extract_pat_ident(pat: &Pat) -> Option<String> {
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

fn extract_expr_ident(expr: &Expr) -> Option<String> {
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

fn extract_receiver_label(expr: &Expr) -> Option<String> {
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

fn extract_type_last_ident(ty: &Type) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; inspects path and reference types"
    )]
    match ty {
        Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(tr) => extract_type_last_ident(&tr.elem),
        Type::Paren(p) => extract_type_last_ident(&p.elem),
        Type::Group(g) => extract_type_last_ident(&g.elem),
        _ => None,
    }
}

fn is_tokio_sync_type(ty: &Type, tokio_sync_type_names: &HashSet<String>) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; inspects path and reference types for Tokio sync primitives"
    )]
    match ty {
        Type::Reference(tr) => is_tokio_sync_type(&tr.elem, tokio_sync_type_names),
        Type::Paren(p) => is_tokio_sync_type(&p.elem, tokio_sync_type_names),
        Type::Group(g) => is_tokio_sync_type(&g.elem, tokio_sync_type_names),
        Type::Path(tp) => {
            let full = path_to_string(&tp.path);
            if full.contains("tokio::sync::Mutex") || full.contains("tokio::sync::RwLock") {
                return true;
            }
            if let Some(last) = tp.path.segments.last() {
                let name = last.ident.to_string();
                if tokio_sync_type_names.contains(&name) {
                    return true;
                }
                if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                    return args.args.iter().any(|arg| {
                        matches!(
                            arg,
                            syn::GenericArgument::Type(inner_ty)
                                if is_tokio_sync_type(inner_ty, tokio_sync_type_names)
                        )
                    });
                }
            }
            false
        }
        _ => false,
    }
}

fn is_tokio_sync_ctor(expr: &Expr, tokio_sync_type_names: &HashSet<String>) -> bool {
    if let Expr::Call(call) = expr
        && let Expr::Path(ep) = call.func.as_ref()
    {
        let full = path_to_string(&ep.path);
        if full.starts_with("tokio::sync::Mutex::") || full.starts_with("tokio::sync::RwLock::") {
            return true;
        }
        if ep.path.segments.len() == 2 {
            let ty_name = ep.path.segments[0].ident.to_string();
            return tokio_sync_type_names.contains(&ty_name);
        }
    }
    false
}

fn is_cheap_clone_type(ty: &Type) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Type has many variants; checks path and reference types for cheap reference-counted handles"
    )]
    match ty {
        Type::Reference(tr) => is_cheap_clone_type(&tr.elem),
        Type::Paren(p) => is_cheap_clone_type(&p.elem),
        Type::Group(g) => is_cheap_clone_type(&g.elem),
        Type::Path(tp) => tp.path.segments.iter().any(|seg| {
            matches!(
                seg.ident.to_string().as_str(),
                "Arc"
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

fn is_cheap_clone_ctor(expr: &Expr) -> bool {
    if let Expr::Call(call) = expr
        && let Expr::Path(ep) = call.func.as_ref()
    {
        let full = path_to_string(&ep.path);
        return full.ends_with("Arc::new")
            || full.ends_with("Arc::clone")
            || full.ends_with("Rc::new")
            || full.ends_with("Rc::clone")
            || full.ends_with("Client::new");
    }
    false
}

fn is_cheap_handle_ident(ident: &str) -> bool {
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

fn is_spawn_blocking_call(node: &ExprCall) -> bool {
    if let Expr::Path(ep) = node.func.as_ref() {
        let full = path_to_string(&ep.path);
        return matches!(
            full.as_str(),
            "tokio::task::spawn_blocking"
                | "task::spawn_blocking"
                | "spawn_blocking"
                | "tokio::runtime::Handle::spawn_blocking"
        );
    }
    false
}

fn is_lazy_lock_init_call(node: &ExprCall) -> bool {
    if let Expr::Path(ep) = node.func.as_ref() {
        let full = path_to_string(&ep.path);
        return full.ends_with("LazyLock::new") || full.ends_with("Lazy::new");
    }
    false
}

fn is_blocking_std_fs_or_net_path(
    path_str: &str,
    tokio_fs_imported: bool,
    std_fs_file_imported: bool,
    std_net_imported: bool,
) -> bool {
    if path_str.starts_with("tokio::") {
        return false;
    }
    if let Some(op) = path_str.strip_prefix("std::fs::") {
        return is_std_fs_blocking_op(op);
    }
    if !tokio_fs_imported && let Some(op) = path_str.strip_prefix("fs::") {
        return is_std_fs_blocking_op(op);
    }
    if std_fs_file_imported && matches!(path_str, "File::open" | "File::create") {
        return true;
    }
    if let Some(op) = path_str.strip_prefix("std::net::") {
        return is_std_net_blocking_op(op);
    }
    if let Some(op) = path_str.strip_prefix("net::") {
        return is_std_net_blocking_op(op);
    }
    if std_net_imported && is_std_net_blocking_op(path_str) {
        return true;
    }
    false
}

fn is_std_fs_blocking_op(op: &str) -> bool {
    matches!(
        op,
        "read_to_string"
            | "read"
            | "write"
            | "remove_file"
            | "remove_dir"
            | "remove_dir_all"
            | "create_dir"
            | "create_dir_all"
            | "copy"
            | "rename"
            | "metadata"
            | "symlink_metadata"
            | "read_dir"
            | "canonicalize"
            | "hard_link"
            | "set_permissions"
            | "File::open"
            | "File::create"
            | "OpenOptions::new"
    )
}

fn is_std_net_blocking_op(op: &str) -> bool {
    matches!(
        op,
        "TcpStream::connect"
            | "TcpStream::connect_timeout"
            | "TcpListener::bind"
            | "UdpSocket::bind"
    )
}

fn is_empty_vec_init(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks Vec::new() calls and empty vec![] macros"
    )]
    match expr {
        Expr::Paren(p) => is_empty_vec_init(&p.expr),
        Expr::Group(g) => is_empty_vec_init(&g.expr),
        Expr::Call(call) if call.args.is_empty() => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let full = path_to_string(&ep.path);
                matches!(full.as_str(), "Vec::new" | "std::vec::Vec::new" | "alloc::vec::Vec::new")
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

fn collect_unconditional_pushed_vecs(block: &Block, out: &mut Vec<String>) {
    for stmt in &block.stmts {
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

fn is_format_macro(path: &syn::Path) -> bool {
    path.is_ident("format") || path_to_string(path) == "std::fmt::format"
}

fn is_unnecessary_format_tokens(tokens: &proc_macro2::TokenStream) -> bool {
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
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// Keep unused ReturnType import check clean if needed
const _: Option<ReturnType> = None;
