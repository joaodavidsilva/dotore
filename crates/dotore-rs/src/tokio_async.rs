//! Single-pass detectors for Tokio async concurrency hazards:
//!
//! 1. `rs-tokio-no-std-lock-across-await` ([`RuleId::RsTokioNoStdLockAcrossAwait`])
//! 2. `rs-tokio-no-blocking-in-async` ([`RuleId::RsTokioNoBlockingInAsync`], `Autofix`)
//! 3. `rs-tokio-prefer-bounded-channel` ([`RuleId::RsTokioPreferBoundedChannel`])

use std::collections::HashSet;

use dotore_core::{AutofixPatch, ByteSpan, RuleId, SourceLoc};
use syn::{
    Block, Expr, ExprAsync, ExprAwait, ExprCall, ExprClosure, ExprIf, File, FnArg, ImplItemFn,
    Item, ItemFn, ItemImpl, ItemMod, Pat, Signature, Stmt, TraitItemFn, Type, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_expr_ident, extract_pat_ident,
    extract_receiver_label, loc_at, path_to_string, slice_source, span_to_bytes,
};

/// Runs single-pass Tokio async concurrency hazard detectors on the parsed [`syn::File`].
pub(crate) fn extract_tokio_async_findings(
    file: &File,
    source: &str,
    line_starts: &[u32],
    findings: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = TokioAsyncVisitor {
        source,
        line_starts,
        findings,
        scope: RsScopeTracker::for_file(file),
        tokio_sync_type_names: HashSet::new(),
        tokio_sync_vars: HashSet::new(),
        std_thread_sleep_imported: false,
        tokio_time_sleep_imported: false,
        tokio_fs_imported: false,
        std_fs_file_imported: false,
        std_net_imported: false,
        tokio_unbounded_channel_imported: false,
        spawn_blocking_depth: 0,
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

struct TokioAsyncVisitor<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    tokio_sync_type_names: HashSet<String>,
    tokio_sync_vars: HashSet<String>,
    std_thread_sleep_imported: bool,
    tokio_time_sleep_imported: bool,
    tokio_fs_imported: bool,
    std_fs_file_imported: bool,
    std_net_imported: bool,
    tokio_unbounded_channel_imported: bool,
    spawn_blocking_depth: usize,
    active_sync_guards: Vec<ActiveSyncGuard>,
}

impl TokioAsyncVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
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
            "std::net::TcpStream"
            | "std::net::TcpListener"
            | "std::net::UdpSocket"
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
                && is_tokio_sync_type(&pat_type.ty, &self.tokio_sync_type_names)
            {
                self.tokio_sync_vars.insert(ident);
            }
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
                    let recv_name =
                        extract_receiver_label(&mc.receiver).unwrap_or_else(|| "mutex".to_string());
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
        if self.scope.in_test() || !self.scope.in_async() || self.spawn_blocking_depth > 0 {
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
                let arg_src = slice_source(self.source, arg_span);
                if !arg_src.is_empty() {
                    Some(AutofixPatch::replace(
                        format!(
                            "Replace blocking `{path_str}({arg_src})` with `tokio::time::sleep({arg_src}).await`"
                        ),
                        span,
                        format!("tokio::time::sleep({arg_src}).await"),
                    ))
                } else {
                    None
                }
            } else {
                None
            };

            self.findings.push(
                RsCandidateFinding::new(
                    RuleId::RsTokioNoBlockingInAsync,
                    self.scope.subject_name(),
                    path_str.clone(),
                    "rsTokioNoBlockingInAsync",
                    format!(
                        "Blocking call `{path_str}(...)` inside an async context parks the Tokio worker thread; use `tokio::time::sleep(...).await` instead."
                    ),
                    loc,
                    span,
                )
                .with_autofix(autofix),
            );
            return;
        }

        // 2. Synchronous `std::fs::*` and `std::net::*` calls inside async
        if is_blocking_std_fs_or_net_path(
            &path_str,
            StdIoImports {
                tokio_fs_imported: self.tokio_fs_imported,
                std_fs_file_imported: self.std_fs_file_imported,
                std_net_imported: self.std_net_imported,
            },
        ) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsTokioNoBlockingInAsync,
                self.scope.subject_name(),
                path_str.clone(),
                "rsTokioNoBlockingInAsync",
                format!(
                    "Synchronous I/O call `{path_str}(...)` blocks the async runtime thread; use `tokio::fs` / `tokio::net` or wrap in `tokio::task::spawn_blocking(...)`."
                ),
                loc,
                span,
            ));
        }
    }

    fn check_unbounded_channel_call(&mut self, node: &ExprCall) {
        if self.scope.in_test() || !node.args.is_empty() {
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
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsTokioPreferBoundedChannel,
                self.scope.subject_name(),
                path_str.clone(),
                "rsTokioPreferBoundedChannel",
                format!(
                    "`{path_str}()` disables channel backpressure and risks unbounded memory growth under load; prefer bounded `tokio::sync::mpsc::channel(capacity)`."
                ),
                loc,
                span,
            ));
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

    fn record_local_stmt_bindings(&mut self, local: &syn::Local) {
        if let Pat::Type(pat_type) = &local.pat
            && let Some(ident) = extract_pat_ident(&pat_type.pat)
            && is_tokio_sync_type(&pat_type.ty, &self.tokio_sync_type_names)
        {
            self.tokio_sync_vars.insert(ident);
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
        if !self.scope.in_test()
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

impl<'ast> Visit<'ast> for TokioAsyncVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        self.populate_sig_vars(&i.sig);

        visit::visit_item_fn(self, i);

        self.active_sync_guards = prev_guards;
        self.tokio_sync_vars = prev_tokio_vars;
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        self.populate_sig_vars(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.active_sync_guards = prev_guards;
        self.tokio_sync_vars = prev_tokio_vars;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        let prev_tokio_vars = std::mem::take(&mut self.tokio_sync_vars);
        let prev_guards = std::mem::take(&mut self.active_sync_guards);
        self.populate_sig_vars(&i.sig);

        visit::visit_trait_item_fn(self, i);

        self.active_sync_guards = prev_guards;
        self.tokio_sync_vars = prev_tokio_vars;
        self.scope.exit(snap);
    }

    fn visit_expr_async(&mut self, i: &'ast ExprAsync) {
        let snap = self.scope.enter_async();
        visit::visit_expr_async(self, i);
        self.scope.exit(snap);
    }

    fn visit_expr_closure(&mut self, i: &'ast ExprClosure) {
        let snap = self.scope.enter_closure(i);
        visit::visit_expr_closure(self, i);
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let saved_guards_len = self.active_sync_guards.len();

        for stmt in &b.stmts {
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
        if !self.scope.in_test()
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

        if !self.scope.in_test() {
            let subject_name = self.scope.subject_name();
            for guard in &mut self.active_sync_guards {
                if !guard.dropped && !guard.reported {
                    guard.reported = true;
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsTokioNoStdLockAcrossAwait,
                        subject_name.clone(),
                        guard.guard_name.clone(),
                        "rsTokioNoStdLockAcrossAwait",
                        format!(
                            "Synchronous lock guard `{}` (from `{}`) is held across an `.await` point; drop `{}` before `.await` or use `tokio::sync::Mutex` / `RwLock`.",
                            guard.guard_name, guard.lock_target, guard.guard_name
                        ),
                        guard.acq_loc,
                        guard.acq_span,
                    ));
                }
            }
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_drop_call(node);
        self.check_blocking_call_in_async(node);
        self.check_unbounded_channel_call(node);

        let is_spawn_blocking = is_spawn_blocking_call(node);
        if is_spawn_blocking {
            self.spawn_blocking_depth += 1;
        }
        visit::visit_expr_call(self, node);
        if is_spawn_blocking {
            self.spawn_blocking_depth -= 1;
        }
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

#[derive(Clone, Copy)]
struct StdIoImports {
    tokio_fs_imported: bool,
    std_fs_file_imported: bool,
    std_net_imported: bool,
}

fn is_blocking_std_fs_or_net_path(path_str: &str, imports: StdIoImports) -> bool {
    let StdIoImports {
        tokio_fs_imported,
        std_fs_file_imported,
        std_net_imported,
    } = imports;
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
