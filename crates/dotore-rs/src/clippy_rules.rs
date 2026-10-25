//! Single-pass detectors for the 7 Clippy-grade AST correctness and reliability rules (`#57`):
//!
//! 1. `rs-no-await-holding-refcell` ([`RuleId::RsNoAwaitHoldingRefcell`])
//! 2. `rs-no-panic-or-todo-in-production` ([`RuleId::RsNoPanicOrTodoInProduction`])
//! 3. `rs-no-dbg-or-print-in-library` ([`RuleId::RsNoDbgOrPrintInLibrary`])
//! 4. `rs-security-no-world-writable-permissions` ([`RuleId::RsSecurityNoWorldWritablePermissions`])
//! 5. `rs-no-zombie-child-process` ([`RuleId::RsNoZombieChildProcess`])
//! 6. `rs-no-transmute-without-type-annotations` ([`RuleId::RsNoTransmuteWithoutTypeAnnotations`])
//! 7. `rs-require-safety-doc-on-pub-unsafe-fn` ([`RuleId::RsRequireSafetyDocOnPubUnsafeFn`])

use std::collections::HashSet;

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Attribute, Block, Expr, ExprAsync, ExprAwait, ExprCall, ExprClosure, ExprIf, ExprLit,
    ExprMacro, ExprMethodCall, File, GenericArgument, ImplItemFn, ItemFn, ItemImpl, ItemMod,
    ItemTrait, Lit, Macro, Pat, PathArguments, Signature, Stmt, TraitItemFn, Type, Visibility,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::{
        RsCandidateFinding, RsScopeTracker, extract_expr_ident, extract_pat_ident,
        extract_receiver_label, is_pub, loc_at, path_to_string, span_to_bytes,
    },
    source_kernel::{
        FnBodyResolver, KernelContext, RsAliasMap, literal_bool, strip_parens, strip_wrappers,
    },
};

/// Evaluates the 7 Clippy-grade AST rules on `ast` and appends candidate findings to `out`.
pub(crate) fn extract_clippy_ast_findings(
    ast: &File,
    aliases: &RsAliasMap,
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = ClippyAstVisitor {
        aliases,
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        current_body: None,
        in_main_fn: false,
        in_pub_trait: false,
        in_trait_impl: false,
        active_refcell_guards: Vec::new(),
        recorded_macro_spans: HashSet::new(),
        recorded_spawn_spans: HashSet::new(),
    };
    visitor.visit_file(ast);
}

#[derive(Debug, Clone)]
struct ActiveRefCellGuard {
    guard_name: String,
    borrow_target: String,
    acq_loc: SourceLoc,
    acq_span: ByteSpan,
    dropped: bool,
    reported: bool,
}

struct ClippyAstVisitor<'a> {
    aliases: &'a RsAliasMap,
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    current_body: Option<FnBodyResolver>,
    in_main_fn: bool,
    in_pub_trait: bool,
    in_trait_impl: bool,
    active_refcell_guards: Vec<ActiveRefCellGuard>,
    recorded_macro_spans: HashSet<(u32, u32)>,
    recorded_spawn_spans: HashSet<(u32, u32)>,
}

impl ClippyAstVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn ctx(&self) -> KernelContext<'_> {
        KernelContext::new(self.aliases, self.current_body.as_ref())
    }

    fn push_finding(
        &mut self,
        rule: RuleId,
        target_name: impl Into<String>,
        message_id: &'static str,
        message: impl Into<String>,
        span: ByteSpan,
    ) {
        let loc = self.loc_at(span.start);
        self.findings.push(RsCandidateFinding::new(
            rule,
            self.scope.subject_name(),
            target_name,
            message_id,
            message,
            loc,
            span,
        ));
    }

    // 1. `rs-no-await-holding-refcell`
    fn extract_refcell_borrow_acquisition(expr: &Expr) -> Option<String> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "RefCell borrow extraction unwraps ?, .unwrap()/.expect(), parens, groups, and borrow/borrow_mut calls"
        )]
        match expr {
            Expr::Await(_) => None,
            Expr::Paren(p) => Self::extract_refcell_borrow_acquisition(&p.expr),
            Expr::Group(g) => Self::extract_refcell_borrow_acquisition(&g.expr),
            Expr::Try(t) => Self::extract_refcell_borrow_acquisition(&t.expr),
            Expr::Reference(r) => Self::extract_refcell_borrow_acquisition(&r.expr),
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if matches!(
                    method.as_str(),
                    "unwrap" | "expect" | "unwrap_or_else" | "ok"
                ) {
                    return Self::extract_refcell_borrow_acquisition(&mc.receiver);
                }
                if matches!(
                    method.as_str(),
                    "borrow" | "borrow_mut" | "try_borrow" | "try_borrow_mut"
                ) && mc.args.is_empty()
                {
                    let recv = extract_receiver_label(&mc.receiver)
                        .unwrap_or_else(|| "refcell".to_string());
                    return Some(format!("{recv}.{method}()"));
                }
                None
            }
            Expr::Call(call) => {
                if let Expr::Path(ep) = strip_parens(&call.func) {
                    let path_str = path_to_string(&ep.path);
                    if matches!(
                        path_str.as_str(),
                        "RefCell::borrow"
                            | "RefCell::borrow_mut"
                            | "RefCell::try_borrow"
                            | "RefCell::try_borrow_mut"
                            | "std::cell::RefCell::borrow"
                            | "std::cell::RefCell::borrow_mut"
                            | "core::cell::RefCell::borrow"
                            | "core::cell::RefCell::borrow_mut"
                    ) {
                        return Some(format!("{path_str}(...)"));
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn record_local_refcell_guard(&mut self, local: &syn::Local) {
        if self.scope.in_test() {
            return;
        }
        let Some(init) = &local.init else {
            return;
        };
        let Some(ident) = extract_pat_ident(&local.pat) else {
            return;
        };
        if let Some(borrow_target) = Self::extract_refcell_borrow_acquisition(&init.expr) {
            let span = self.span_to_bytes(local.span());
            let loc = self.loc_at(span.start);
            self.active_refcell_guards.push(ActiveRefCellGuard {
                guard_name: ident,
                borrow_target,
                acq_loc: loc,
                acq_span: span,
                dropped: false,
                reported: false,
            });
        }
    }

    fn check_drop_refcell_guard(&mut self, node: &ExprCall) {
        if node.args.len() != 1 {
            return;
        }
        let Expr::Path(expr_path) = strip_parens(&node.func) else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        if matches!(
            path_str.as_str(),
            "drop" | "std::mem::drop" | "core::mem::drop" | "mem::drop"
        ) && let Some(first_arg) = node.args.first()
            && let Some(ident) = extract_expr_ident(first_arg)
        {
            for guard in &mut self.active_refcell_guards {
                if guard.guard_name == ident {
                    guard.dropped = true;
                }
            }
        }
    }

    // 2. `rs-no-panic-or-todo-in-production` & 3. `rs-no-dbg-or-print-in-library`
    fn check_macro_invocation(&mut self, mac: &Macro, outer_span: proc_macro2::Span) {
        if self.scope.in_test() {
            return;
        }
        let span = self.span_to_bytes(outer_span);
        if !self.recorded_macro_spans.insert((span.start, span.end)) {
            return;
        }
        let Some(last_seg) = mac.path.segments.last() else {
            return;
        };
        let name = last_seg.ident.to_string();
        let full_path = path_to_string(&mac.path);
        if !matches!(
            full_path.as_str(),
            "panic"
                | "std::panic"
                | "core::panic"
                | "todo"
                | "std::todo"
                | "core::todo"
                | "unimplemented"
                | "std::unimplemented"
                | "core::unimplemented"
                | "dbg"
                | "std::dbg"
                | "println"
                | "std::println"
                | "eprintln"
                | "std::eprintln"
        ) {
            return;
        }

        match name.as_str() {
            "panic" | "todo" | "unimplemented" => {
                self.push_finding(
                    RuleId::RsNoPanicOrTodoInProduction,
                    format!("{name}!"),
                    "rsNoPanicOrTodoInProduction",
                    format!(
                        "`{name}!(...)` in production code terminates the thread or aborts on reach; return a typed `Result` or `Option` error instead."
                    ),
                    span,
                );
            }
            "dbg" => {
                self.push_finding(
                    RuleId::RsNoDbgOrPrintInLibrary,
                    "dbg!",
                    "rsNoDbgOrPrintInLibrary",
                    "`dbg!(...)` macro left in production code writes debug output to stderr on every call; remove it or use structured `tracing::debug!`.",
                    span,
                );
            }
            "println" | "eprintln" => {
                self.push_finding(
                    RuleId::RsNoDbgOrPrintInLibrary,
                    format!("{name}!"),
                    "rsNoDbgOrPrintInLibrary",
                    format!(
                        "`{name}!(...)` in a library crate writes directly to standard streams; use structured `tracing` events or accept an `impl std::io::Write`."
                    ),
                    span,
                );
            }
            _ => {}
        }
    }

    fn check_process_exit_call(&mut self, node: &ExprCall) {
        if self.scope.in_test() || self.in_main_fn {
            return;
        }
        let Expr::Path(ep) = strip_parens(&node.func) else {
            return;
        };
        let path_str = path_to_string(&ep.path);
        let ctx = self.ctx();
        let is_exit = matches!(path_str.as_str(), "std::process::exit" | "process::exit")
            || ctx
                .matches_call_path(&node.func, "std", &["process"], "exit")
                .is_some();
        if is_exit {
            let span = self.span_to_bytes(node.span());
            self.push_finding(
                RuleId::RsNoPanicOrTodoInProduction,
                "std::process::exit",
                "rsNoPanicOrTodoInProduction",
                "`std::process::exit(...)` outside `fn main` immediately terminates the process without running destructors; return an error to `main` instead.",
                span,
            );
        }
    }

    // 4. `rs-security-no-world-writable-permissions`
    fn check_world_writable_method(&mut self, node: &ExprMethodCall) {
        if self.scope.in_test() {
            return;
        }
        let method = node.method.to_string();
        if method == "set_readonly" && node.args.len() == 1 {
            if let Some(arg) = node.args.first() {
                let ctx = self.ctx();
                let resolved = ctx.resolve_value(arg).unwrap_or_else(|| arg.clone());
                if literal_bool(&resolved, false) {
                    let span = self.span_to_bytes(node.span());
                    self.push_finding(
                        RuleId::RsSecurityNoWorldWritablePermissions,
                        "set_readonly(false)",
                        "rsSecurityNoWorldWritablePermissions",
                        "`Permissions::set_readonly(false)` grants world-writable permissions (0o666) on Unix; set explicit mode bits with `PermissionsExt::from_mode` instead.",
                        span,
                    );
                }
            }
            return;
        }

        if matches!(method.as_str(), "from_mode" | "set_mode" | "mode")
            && node.args.len() == 1
            && let Some(arg) = node.args.first()
        {
            self.check_mode_arg_world_writable(arg, self.span_to_bytes(node.span()), &method);
        }
    }

    fn check_world_writable_call(&mut self, node: &ExprCall) {
        if self.scope.in_test() {
            return;
        }
        let Expr::Path(ep) = strip_parens(&node.func) else {
            return;
        };
        let path_str = path_to_string(&ep.path);
        if path_str.ends_with("set_readonly")
            && node.args.len() == 2
            && let Some(arg) = node.args.get(1)
        {
            let ctx = self.ctx();
            let resolved = ctx.resolve_value(arg).unwrap_or_else(|| arg.clone());
            if literal_bool(&resolved, false) {
                let span = self.span_to_bytes(node.span());
                self.push_finding(
                    RuleId::RsSecurityNoWorldWritablePermissions,
                    "set_readonly(false)",
                    "rsSecurityNoWorldWritablePermissions",
                    "`Permissions::set_readonly(false)` grants world-writable permissions (0o666) on Unix; set explicit mode bits with `PermissionsExt::from_mode` instead.",
                    span,
                );
            }
            return;
        }

        let is_from_mode = path_str.ends_with("::from_mode") || path_str == "from_mode";
        let is_set_mode =
            (path_str.ends_with("::set_mode") || path_str.ends_with("::mode")) && node.args.len() == 2;
        if is_from_mode && node.args.len() == 1 {
            if let Some(arg) = node.args.first() {
                self.check_mode_arg_world_writable(arg, self.span_to_bytes(node.span()), "from_mode");
            }
        } else if is_set_mode && let Some(arg) = node.args.get(1) {
            self.check_mode_arg_world_writable(arg, self.span_to_bytes(node.span()), "set_mode");
        }
    }

    fn check_mode_arg_world_writable(&mut self, arg: &Expr, span: ByteSpan, target: &str) {
        let ctx = self.ctx();
        let resolved = ctx.resolve_value(arg).unwrap_or_else(|| arg.clone());
        if let Expr::Lit(ExprLit {
            lit: Lit::Int(lit_int),
            ..
        }) = strip_wrappers(&resolved)
            && let Ok(mode) = lit_int.base10_parse::<u32>()
            && (mode & 0o002) != 0
        {
            self.push_finding(
                RuleId::RsSecurityNoWorldWritablePermissions,
                target.to_string(),
                "rsSecurityNoWorldWritablePermissions",
                format!(
                    "Unix permission mode `{}` sets the world-writable bit (`0o002`); restrict permissions to owner/group (e.g. `0o600` or `0o644`).",
                    lit_int.token()
                ),
                span,
            );
        }
    }

    // 5. `rs-no-zombie-child-process`
    fn is_command_spawn_expr(&self, expr: &Expr) -> Option<ByteSpan> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Command::spawn detection unwraps ?, .unwrap()/.expect()/.ok(), parens, and groups"
        )]
        match expr {
            Expr::Paren(p) => self.is_command_spawn_expr(&p.expr),
            Expr::Group(g) => self.is_command_spawn_expr(&g.expr),
            Expr::Try(t) => self.is_command_spawn_expr(&t.expr),
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if matches!(
                    method.as_str(),
                    "unwrap" | "expect" | "unwrap_or_else" | "ok"
                ) && mc.args.is_empty()
                    || (method == "expect" && mc.args.len() == 1)
                {
                    return self.is_command_spawn_expr(&mc.receiver);
                }
                if method == "spawn" && mc.args.is_empty() && self.is_command_spawn_receiver(&mc.receiver) {
                    return Some(self.span_to_bytes(mc.span()));
                }
                None
            }
            _ => None,
        }
    }

    fn is_command_spawn_receiver(&self, receiver: &Expr) -> bool {
        let ctx = self.ctx();
        if let Some(Expr::Call(root)) = ctx.chain_root(receiver) {
            let Expr::Path(ep) = strip_parens(&root.func) else {
                return false;
            };
            let p = path_to_string(&ep.path);
            return p.ends_with("Command::new")
                || ctx
                    .matches_call_path(&root.func, "std", &["process", "Command"], "new")
                    .is_some();
        }
        if let Some(recv) = extract_receiver_label(receiver) {
            let lower = recv.to_ascii_lowercase();
            return lower == "cmd" || lower == "command" || lower.ends_with("_cmd");
        }
        false
    }

    fn inspect_block_for_zombie_children(&mut self, block: &Block) {
        if self.scope.in_test() {
            return;
        }
        let stmt_count = block.stmts.len();
        for (idx, stmt) in block.stmts.iter().enumerate() {
            let is_tail_expr = idx + 1 == stmt_count && matches!(stmt, Stmt::Expr(_, None));
            if is_tail_expr {
                continue;
            }
            match stmt {
                Stmt::Expr(expr, _) => {
                    self.inspect_discarded_spawn_expr(expr);
                }
                Stmt::Local(local) => {
                    self.inspect_local_spawn_stmt(local, &block.stmts[idx + 1..]);
                }
                Stmt::Item(_) | Stmt::Macro(_) => {}
            }
        }
    }

    fn inspect_discarded_spawn_expr(&mut self, expr: &Expr) {
        let Some(spawn_span) = self.is_command_spawn_expr(expr) else {
            return;
        };
        if !self.recorded_spawn_spans.insert((spawn_span.start, spawn_span.end)) {
            return;
        }
        self.push_finding(
            RuleId::RsNoZombieChildProcess,
            "Command::spawn",
            "rsNoZombieChildProcess",
            "Spawned `Child` handle from `Command::spawn()` is immediately dropped without `.wait()` or `.wait_with_output()`, leaving a zombie process.",
            spawn_span,
        );
    }

    fn inspect_local_spawn_stmt(&mut self, local: &syn::Local, remaining: &[Stmt]) {
        let Some(init) = &local.init else {
            return;
        };
        let Some(spawn_span) = self.is_command_spawn_expr(&init.expr) else {
            return;
        };
        if matches!(local.pat, Pat::Wild(_)) {
            if self.recorded_spawn_spans.insert((spawn_span.start, spawn_span.end)) {
                self.push_finding(
                    RuleId::RsNoZombieChildProcess,
                    "Command::spawn",
                    "rsNoZombieChildProcess",
                    "Spawned `Child` handle from `Command::spawn()` is bound to `_` and immediately dropped without `.wait()`, leaving a zombie process.",
                    spawn_span,
                );
            }
            return;
        }
        let Some(ident) = extract_pat_ident(&local.pat) else {
            return;
        };
        if ident.starts_with('_') {
            if self.recorded_spawn_spans.insert((spawn_span.start, spawn_span.end)) {
                self.push_finding(
                    RuleId::RsNoZombieChildProcess,
                    ident,
                    "rsNoZombieChildProcess",
                    "Spawned `Child` handle from `Command::spawn()` is never waited on before going out of scope, leaving a zombie process.",
                    spawn_span,
                );
            }
            return;
        }
        if !child_var_is_reaped_or_escaped(&ident, remaining)
            && self.recorded_spawn_spans.insert((spawn_span.start, spawn_span.end))
        {
            let local_span = self.span_to_bytes(local.span());
            self.push_finding(
                RuleId::RsNoZombieChildProcess,
                ident.clone(),
                "rsNoZombieChildProcess",
                format!(
                    "Spawned `Child` process `{ident}` is dropped without calling `.wait()` or `.wait_with_output()`, leaving a zombie process."
                ),
                local_span,
            );
        }
    }

    // 6. `rs-no-transmute-without-type-annotations`
    fn check_transmute_call(&mut self, node: &ExprCall) {
        if self.scope.in_test() {
            return;
        }
        let Expr::Path(ep) = strip_parens(&node.func) else {
            return;
        };
        let Some(last_seg) = ep.path.segments.last() else {
            return;
        };
        if last_seg.ident != "transmute" {
            return;
        }
        let full_path = path_to_string(&ep.path);
        if !matches!(
            full_path.as_str(),
            "transmute" | "mem::transmute" | "std::mem::transmute" | "core::mem::transmute"
        ) {
            return;
        }
        let has_both_explicit_types = match &last_seg.arguments {
            PathArguments::AngleBracketed(ab) => {
                let type_args: Vec<&Type> = ab
                    .args
                    .iter()
                    .filter_map(|arg| {
                        if let GenericArgument::Type(ty) = arg {
                            Some(ty)
                        } else {
                            None
                        }
                    })
                    .collect();
                type_args.len() == 2
                    && !type_args.iter().any(|ty| matches!(ty, Type::Infer(_)))
            }
            PathArguments::None | PathArguments::Parenthesized(_) => false,
        };
        if !has_both_explicit_types {
            let span = self.span_to_bytes(node.span());
            self.push_finding(
                RuleId::RsNoTransmuteWithoutTypeAnnotations,
                "transmute",
                "rsNoTransmuteWithoutTypeAnnotations",
                "Call to `std::mem::transmute` is missing explicit source and destination turbofish type annotations (`transmute::<Src, Dst>(...)`).",
                span,
            );
        }
    }

    // 7. `rs-require-safety-doc-on-pub-unsafe-fn`
    fn check_pub_unsafe_fn_safety_doc(
        &mut self,
        attrs: &[Attribute],
        vis: Option<&Visibility>,
        sig: &Signature,
    ) {
        if self.scope.in_test() || self.in_trait_impl || sig.unsafety.is_none() {
            return;
        }
        let is_public = vis.map_or(self.in_pub_trait, is_pub);
        if !is_public || attrs_have_doc_hidden(attrs) {
            return;
        }
        if !attrs_have_safety_doc_section(attrs) {
            let span = self.span_to_bytes(sig.span());
            let fn_name = sig.ident.to_string();
            self.push_finding(
                RuleId::RsRequireSafetyDocOnPubUnsafeFn,
                fn_name.clone(),
                "rsRequireSafetyDocOnPubUnsafeFn",
                format!(
                    "Public `unsafe fn {fn_name}` is missing a `# Safety` documentation section explaining the invariants callers must uphold."
                ),
                span,
            );
        }
    }
}

impl<'ast> Visit<'ast> for ClippyAstVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        let snap = self.scope.enter_trait(i);
        let prev_pub_trait = std::mem::replace(&mut self.in_pub_trait, is_pub(&i.vis));
        visit::visit_item_trait(self, i);
        self.in_pub_trait = prev_pub_trait;
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        let prev_trait_impl = std::mem::replace(&mut self.in_trait_impl, i.trait_.is_some());
        visit::visit_item_impl(self, i);
        self.in_trait_impl = prev_trait_impl;
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        self.check_pub_unsafe_fn_safety_doc(&i.attrs, Some(&i.vis), &i.sig);
        let prev_main = std::mem::replace(&mut self.in_main_fn, i.sig.ident == "main");
        let prev_guards = std::mem::take(&mut self.active_refcell_guards);
        let prev_body = self
            .current_body
            .replace(FnBodyResolver::build(&i.sig, &i.block));

        visit::visit_item_fn(self, i);

        self.current_body = prev_body;
        self.active_refcell_guards = prev_guards;
        self.in_main_fn = prev_main;
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        self.check_pub_unsafe_fn_safety_doc(&i.attrs, Some(&i.vis), &i.sig);
        let prev_main = std::mem::replace(&mut self.in_main_fn, false);
        let prev_guards = std::mem::take(&mut self.active_refcell_guards);
        let prev_body = self
            .current_body
            .replace(FnBodyResolver::build(&i.sig, &i.block));

        visit::visit_impl_item_fn(self, i);

        self.current_body = prev_body;
        self.active_refcell_guards = prev_guards;
        self.in_main_fn = prev_main;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        self.check_pub_unsafe_fn_safety_doc(&i.attrs, None, &i.sig);
        let prev_main = std::mem::replace(&mut self.in_main_fn, false);
        let prev_guards = std::mem::take(&mut self.active_refcell_guards);
        let prev_body = i
            .default
            .as_ref()
            .map(|b| FnBodyResolver::build(&i.sig, b));
        let saved_body = std::mem::replace(&mut self.current_body, prev_body);

        visit::visit_trait_item_fn(self, i);

        self.current_body = saved_body;
        self.active_refcell_guards = prev_guards;
        self.in_main_fn = prev_main;
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
        let saved_guards_len = self.active_refcell_guards.len();
        self.inspect_block_for_zombie_children(b);

        for stmt in &b.stmts {
            self.visit_stmt(stmt);
            if let Stmt::Local(local) = stmt {
                self.record_local_refcell_guard(local);
            }
        }

        self.active_refcell_guards.truncate(saved_guards_len);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.visit_expr(&i.cond);
        let saved_guards_len = self.active_refcell_guards.len();
        if !self.scope.in_test()
            && let Expr::Let(expr_let) = i.cond.as_ref()
            && let Some(ident) = extract_pat_ident(&expr_let.pat)
            && let Some(borrow_target) = Self::extract_refcell_borrow_acquisition(&expr_let.expr)
        {
            let span = self.span_to_bytes(expr_let.span());
            let loc = self.loc_at(span.start);
            self.active_refcell_guards.push(ActiveRefCellGuard {
                guard_name: ident,
                borrow_target,
                acq_loc: loc,
                acq_span: span,
                dropped: false,
                reported: false,
            });
        }

        self.visit_block(&i.then_branch);
        self.active_refcell_guards.truncate(saved_guards_len);

        if let Some((_, else_expr)) = &i.else_branch {
            self.visit_expr(else_expr);
        }
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Macro(stmt_mac) = s {
            self.check_macro_invocation(&stmt_mac.mac, stmt_mac.span());
        }
        visit::visit_stmt(self, s);
    }

    fn visit_expr_macro(&mut self, i: &'ast ExprMacro) {
        self.check_macro_invocation(&i.mac, i.span());
        visit::visit_expr_macro(self, i);
    }

    fn visit_expr_await(&mut self, i: &'ast ExprAwait) {
        self.visit_expr(&i.base);
        if self.scope.in_test() {
            return;
        }
        let subject_name = self.scope.subject_name();
        for guard in &mut self.active_refcell_guards {
            if !guard.dropped && !guard.reported {
                guard.reported = true;
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsNoAwaitHoldingRefcell,
                    subject_name.clone(),
                    guard.guard_name.clone(),
                    "rsNoAwaitHoldingRefcell",
                    format!(
                        "`RefCell` borrow guard `{}` (from `{}`) is held across an `.await` point; drop `{}` before `.await` so concurrent borrows cannot panic.",
                        guard.guard_name, guard.borrow_target, guard.guard_name
                    ),
                    guard.acq_loc,
                    guard.acq_span,
                ));
            }
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_drop_refcell_guard(node);
        self.check_process_exit_call(node);
        self.check_world_writable_call(node);
        self.check_transmute_call(node);
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.check_world_writable_method(node);
        visit::visit_expr_method_call(self, node);
    }
}

fn attrs_have_doc_hidden(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("doc")
            && let Ok(list) = attr.meta.require_list()
            && list
                .tokens
                .to_string()
                .split(',')
                .any(|part| part.trim() == "hidden")
        {
            return true;
        }
    }
    false
}

fn attrs_have_safety_doc_section(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(lit_str),
            ..
        }) = &nv.value
        else {
            continue;
        };
        if lit_str.value().lines().any(line_is_safety_heading) {
            return true;
        }
    }
    false
}

fn line_is_safety_heading(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(after_hashes) = trimmed
        .strip_prefix("###")
        .or_else(|| trimmed.strip_prefix("##"))
        .or_else(|| trimmed.strip_prefix('#'))
    else {
        return false;
    };
    let heading = after_hashes.trim().trim_end_matches(':').trim();
    heading.eq_ignore_ascii_case("safety")
        || heading.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("safety"))
}

fn child_var_is_reaped_or_escaped(child_ident: &str, remaining_stmts: &[Stmt]) -> bool {
    struct ChildReapDetector<'a> {
        ident: &'a str,
        reaped_or_escaped: bool,
    }

    impl<'ast> Visit<'ast> for ChildReapDetector<'_> {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if extract_expr_ident(&node.receiver).as_deref() == Some(self.ident) {
                let method = node.method.to_string();
                if matches!(
                    method.as_str(),
                    "wait" | "wait_with_output" | "try_wait" | "kill"
                ) {
                    self.reaped_or_escaped = true;
                    return;
                }
            }
            for arg in &node.args {
                if expr_passes_ident(arg, self.ident) {
                    self.reaped_or_escaped = true;
                    return;
                }
            }
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            for arg in &node.args {
                if expr_passes_ident(arg, self.ident) {
                    self.reaped_or_escaped = true;
                    return;
                }
            }
            visit::visit_expr_call(self, node);
        }

        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            if let Some(ret_expr) = &node.expr
                && expr_mentions_ident(ret_expr, self.ident)
            {
                self.reaped_or_escaped = true;
                return;
            }
            visit::visit_expr_return(self, node);
        }
    }

    let mut detector = ChildReapDetector {
        ident: child_ident,
        reaped_or_escaped: false,
    };
    let len = remaining_stmts.len();
    for (idx, stmt) in remaining_stmts.iter().enumerate() {
        if idx + 1 == len
            && let Stmt::Expr(tail_expr, None) = stmt
            && expr_mentions_ident(tail_expr, child_ident)
        {
            return true;
        }
        detector.visit_stmt(stmt);
        if detector.reaped_or_escaped {
            return true;
        }
    }
    false
}

fn expr_passes_ident(expr: &Expr, ident: &str) -> bool {
    let stripped = strip_parens(expr);
    if extract_expr_ident(stripped).as_deref() == Some(ident) {
        return true;
    }
    if let Expr::Reference(r) = stripped {
        return extract_expr_ident(&r.expr).as_deref() == Some(ident);
    }
    false
}

fn expr_mentions_ident(expr: &Expr, ident: &str) -> bool {
    struct IdentFinder<'a> {
        ident: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for IdentFinder<'_> {
        fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
            if i.qself.is_none() && i.path.is_ident(self.ident) {
                self.found = true;
            }
        }
    }
    let mut finder = IdentFinder {
        ident,
        found: false,
    };
    finder.visit_expr(expr);
    finder.found
}
