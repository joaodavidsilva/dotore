//! Single-pass `SourceKernel` detectors for Rust HTTP, TLS, shell command, secret fallback,
//! CORS, auth cookie, and JWT validation rules (`#56`).
//!
//! - `rs-security-no-disabled-tls-verification` ([`RuleId::RsSecurityNoDisabledTlsVerification`])
//! - `rs-security-no-dynamic-shell-command` ([`RuleId::RsSecurityNoDynamicShellCommand`])
//! - `rs-http-no-unchecked-response-status` ([`RuleId::RsHttpNoUncheckedResponseStatus`])
//! - `rs-security-no-secret-env-fallback` ([`RuleId::RsSecurityNoSecretEnvFallback`])
//! - `rs-security-no-permissive-cors` ([`RuleId::RsSecurityNoPermissiveCors`])
//! - `rs-security-no-insecure-auth-cookie` ([`RuleId::RsSecurityNoInsecureAuthCookie`])
//! - `rs-security-no-disabled-jwt-validation` ([`RuleId::RsSecurityNoDisabledJwtValidation`])

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Attribute, Expr, ExprAsync, ExprCall, ExprClosure, ExprMethodCall, File, ImplItemFn, ItemConst,
    ItemFn, ItemImpl, ItemMod, ItemStatic, Stmt, TraitItemFn,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::{
    matchers::{RsCandidateFinding, RsScopeTracker, loc_at, path_to_string, span_to_bytes},
    source_kernel::{
        CHAIN_DEPTH, FnBodyResolver, IdentUsageKind, KernelContext, LocalBinding, RsAliasMap,
        bare_identifier, into_stripped_wrappers, literal_bool, literal_string,
        reads_secret_env_var, secret_fallback_message, strip_wrappers,
    },
    tokio_async::{is_offloading_method_call, is_spawn_blocking_call},
};

/// Runs the 7 security and HTTP `SourceKernel` detectors on `ast`.
pub(crate) fn extract_source_kernel_findings(
    ast: &File,
    aliases: &RsAliasMap,
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = SourceKernelDetectorsVisitor {
        aliases,
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        current_body: None,
        current_method_chain_stack: Vec::new(),
        in_current_thread_runtime: false,
        spawn_blocking_depth: 0,
    };
    visitor.visit_file(ast);
}

struct SourceKernelDetectorsVisitor<'a> {
    aliases: &'a RsAliasMap,
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    current_body: Option<FnBodyResolver>,
    current_method_chain_stack: Vec<ExprMethodCall>,
    in_current_thread_runtime: bool,
    spawn_blocking_depth: usize,
}

impl SourceKernelDetectorsVisitor<'_> {
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
        crate_alias_req: Option<(String, String)>,
    ) {
        let loc = self.loc_at(span.start);
        let mut finding = RsCandidateFinding::new(
            rule,
            self.scope.subject_name(),
            target_name,
            message_id,
            message,
            loc,
            span,
        );
        if let Some((written, canonical)) = crate_alias_req {
            finding = finding.with_required_crate_alias(written, canonical);
        }
        self.findings.push(finding);
    }

    fn check_block_in_place_on_current_thread(&mut self, node: &ExprCall) {
        if !self.in_current_thread_runtime {
            return;
        }
        let ctx = self.ctx();
        let Some(alias_req) =
            ctx.matches_call_path(&node.func, "tokio", &["task"], "block_in_place")
        else {
            return;
        };
        let span = self.span_to_bytes(node.span());
        self.push_finding(
            RuleId::RsTokioNoBlockInPlaceOnCurrentThread,
            "tokio::task::block_in_place",
            "rsTokioNoBlockInPlaceOnCurrentThread",
            "tokio::task::block_in_place panics on the current-thread runtime this function runs on.",
            span,
            alias_req,
        );
    }

    fn check_block_on_call_in_async(&mut self, node: &ExprCall) {
        if !self.scope.in_async() || self.spawn_blocking_depth > 0 {
            return;
        }
        let ctx = self.ctx();
        let Some(alias_req) =
            ctx.matches_call_path(&node.func, "futures", &["executor"], "block_on")
        else {
            return;
        };
        let span = self.span_to_bytes(node.span());
        self.push_finding(
            RuleId::RsAsyncNoBlockOnInAsync,
            "futures::executor::block_on",
            "rsAsyncNoBlockOnInAsync",
            "block_on inside async code panics under tokio and deadlocks the futures executor.",
            span,
            alias_req,
        );
    }

    fn check_block_on_method_in_async(&mut self, node: &ExprMethodCall) {
        if !self.scope.in_async() || self.spawn_blocking_depth > 0 || node.method != "block_on" {
            return;
        }
        let ctx = self.ctx();
        let Some(Expr::Call(root)) = ctx.chain_root(&node.receiver) else {
            return;
        };
        let Some(alias_req) = ctx.matches_any_path(
            &root.func,
            &[
                &["tokio", "runtime", "Runtime", "new"],
                &["tokio", "runtime", "Builder", "new_current_thread"],
                &["tokio", "runtime", "Builder", "new_multi_thread"],
                &["tokio", "runtime", "Handle", "current"],
            ],
        ) else {
            return;
        };
        let span = self.span_to_bytes(node.span());
        self.push_finding(
            RuleId::RsAsyncNoBlockOnInAsync,
            "block_on",
            "rsAsyncNoBlockOnInAsync",
            "block_on inside async code panics under tokio and deadlocks the futures executor.",
            span,
            alias_req,
        );
    }

    // 1. `rs-security-no-disabled-tls-verification`
    fn check_disabled_tls(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() {
            return;
        }
        let method_name = call.method.to_string();
        let message = match method_name.as_str() {
            "tls_danger_accept_invalid_certs" | "danger_accept_invalid_certs" => {
                "Reqwest client builder disables TLS certificate verification."
            }
            "tls_danger_accept_invalid_hostnames" | "danger_accept_invalid_hostnames" => {
                "Reqwest client builder disables TLS hostname verification."
            }
            _ => return,
        };
        if call.args.len() != 1 {
            return;
        }
        let Some(arg) = call.args.first() else {
            return;
        };
        let ctx = self.ctx();
        let Some(arg_val) = ctx.resolve_value(arg) else {
            return;
        };
        if !literal_bool(&arg_val, true) {
            return;
        }
        let Some(Expr::Call(builder)) = ctx.chain_root(&call.receiver) else {
            return;
        };
        if !builder.args.is_empty() {
            return;
        }
        let Some(alias_req) = ctx.matches_any_path(
            &builder.func,
            &[
                &["reqwest", "Client", "builder"],
                &["reqwest", "blocking", "Client", "builder"],
                &["reqwest", "ClientBuilder", "new"],
                &["reqwest", "blocking", "ClientBuilder", "new"],
            ],
        ) else {
            return;
        };
        let span = self.span_to_bytes(arg.span());
        self.push_finding(
            RuleId::RsSecurityNoDisabledTlsVerification,
            method_name,
            "rsSecurityNoDisabledTlsVerification",
            message,
            span,
            alias_req,
        );
    }

    // 2a. `rs-security-no-dynamic-shell-command` (method `.arg(script)` / `.args([...])`)
    // Note: Intentionally fires in test code too.
    fn check_dynamic_shell_method(&mut self, call: &ExprMethodCall) {
        let Some(own_args) = extract_command_arg_elements(call) else {
            return;
        };
        let ctx = self.ctx();
        if !own_args.iter().any(|elem| ctx.is_dynamic_text(elem)) {
            return;
        }
        let Some((flags, before)) = resolve_shell_argv(&ctx, &call.receiver) else {
            return;
        };
        let Some(payload) = own_args.iter().enumerate().find_map(|(idx, elem)| {
            let prev = match idx.checked_sub(1) {
                Some(p) => own_args.get(p),
                None => before.last(),
            }?;
            let flag = literal_string(strip_wrappers(prev))?;
            (flags.contains(&flag.as_str()) && ctx.is_dynamic_text(elem)).then_some(elem)
        }) else {
            return;
        };
        let span = self.span_to_bytes(payload.span());
        self.push_finding(
            RuleId::RsSecurityNoDynamicShellCommand,
            call.method.to_string(),
            "rsSecurityNoDynamicShellCommand",
            "A dynamic value is interpolated into a shell command string.",
            span,
            None,
        );
    }

    // 2b. `rs-security-no-dynamic-shell-command` (`Command::new(dynamic_prog)`)
    fn check_tainted_shell_program(&mut self, call: &ExprCall) {
        if call.args.len() != 1 {
            return;
        }
        let Some(prog) = call.args.first() else {
            return;
        };
        let ctx = self.ctx();
        if !ctx.is_dynamic_text(prog) {
            return;
        }
        if ctx
            .matches_call_path(&call.func, "std", &["process", "Command"], "new")
            .is_none()
        {
            return;
        }
        let span = self.span_to_bytes(prog.span());
        self.push_finding(
            RuleId::RsSecurityNoDynamicShellCommand,
            "Command::new",
            "rsSecurityNoDynamicShellCommand",
            "The program a command runs is assembled from a runtime value.",
            span,
            None,
        );
    }

    // 3. `rs-http-no-unchecked-response-status`
    fn check_unchecked_http_status(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() || !call.args.is_empty() {
            return;
        }
        let method_name = call.method.to_string();
        if !matches!(
            method_name.as_str(),
            "bytes" | "bytes_stream" | "chunk" | "json" | "text"
        ) {
            return;
        }
        let read_span = self.span_to_bytes(call.span());
        let ctx = self.ctx();
        let Some((root_call, sent)) =
            resolve_unchecked_response_root(&ctx, &call.receiver, read_span)
        else {
            return;
        };
        let Some(alias_req) = match_reqwest_response_root(&ctx, &root_call, sent) else {
            return;
        };
        let span = self.span_to_bytes(call.method.span());
        self.push_finding(
            RuleId::RsHttpNoUncheckedResponseStatus,
            method_name,
            "rsHttpNoUncheckedResponseStatus",
            "The response body is read without checking the HTTP status.",
            span,
            alias_req,
        );
    }

    // 4. `rs-security-no-secret-env-fallback`
    fn check_secret_env_fallback(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() {
            return;
        }
        let ctx = self.ctx();
        let Some(message) = secret_fallback_message(&ctx, call) else {
            return;
        };
        let mut receiver = strip_wrappers(&call.receiver).clone();
        if let Expr::MethodCall(ok_mc) = &receiver
            && ok_mc.method == "ok"
            && ok_mc.args.is_empty()
        {
            receiver = (*ok_mc.receiver).clone();
        }
        if !reads_secret_env_var(&ctx, &receiver) {
            return;
        }
        let span = self.span_to_bytes(call.method.span());
        self.push_finding(
            RuleId::RsSecurityNoSecretEnvFallback,
            call.method.to_string(),
            "rsSecurityNoSecretEnvFallback",
            message,
            span,
            None,
        );
    }

    // 5a. `rs-security-no-permissive-cors` (constructor call)
    fn check_permissive_cors_call(&mut self, call: &ExprCall) {
        self.check_matched_path_call(
            call,
            &[
                &["tower_http", "cors", "CorsLayer", "very_permissive"],
                &["actix_cors", "Cors", "permissive"],
            ],
            RuleId::RsSecurityNoPermissiveCors,
            "permissive_cors",
            "rsSecurityNoPermissiveCors",
            "The CORS policy accepts any origin, method and header, credentials included.",
            self.span_to_bytes(call.span()),
        );
    }

    // 5b. `rs-security-no-permissive-cors` (`.allow_credentials(true)` combined with `Any` / `AllowOrigin::any()` / `AllowOrigin::mirror_request()`)
    fn check_permissive_cors_credentials(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() || call.method != "allow_credentials" || call.args.len() != 1 {
            return;
        }
        let Some(arg) = call.args.first() else {
            return;
        };
        let ctx = self.ctx();
        let Some(arg_val) = ctx.resolve_value(arg) else {
            return;
        };
        if !literal_bool(&arg_val, true) {
            return;
        }

        // Check both outer method calls on the current chain and inner receiver links (across `let` bindings)
        let mut any_origin_alias_req: Option<Option<(String, String)>> = None;
        for outer in &self.current_method_chain_stack {
            if outer.method == "allow_origin"
                && outer.args.len() == 1
                && let Some(origin_arg) = outer.args.first()
                && let Some(req) = is_any_cors_origin(&ctx, origin_arg)
            {
                any_origin_alias_req = Some(req);
                break;
            }
        }

        if any_origin_alias_req.is_none() {
            let mut expr = Expr::MethodCall(call.clone());
            for _ in 0..CHAIN_DEPTH {
                let Some(resolved) = ctx.resolve_value(strip_wrappers(&expr)) else {
                    break;
                };
                let Expr::MethodCall(link) = into_stripped_wrappers(resolved) else {
                    break;
                };
                if link.method == "allow_origin"
                    && link.args.len() == 1
                    && let Some(origin_arg) = link.args.first()
                    && let Some(req) = is_any_cors_origin(&ctx, origin_arg)
                {
                    any_origin_alias_req = Some(req);
                    break;
                }
                expr = *link.receiver;
            }
        }

        let Some(alias_req) = any_origin_alias_req else {
            return;
        };
        let span = self.span_to_bytes(arg.span());
        self.push_finding(
            RuleId::RsSecurityNoPermissiveCors,
            "allow_credentials",
            "rsSecurityNoPermissiveCors",
            "The CORS layer lets any origin send credentialed requests.",
            span,
            alias_req,
        );
    }

    // 6. `rs-security-no-insecure-auth-cookie`
    fn check_insecure_auth_cookie(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() || call.args.len() != 1 {
            return;
        }
        let method_name = call.method.to_string();
        if !matches!(method_name.as_str(), "http_only" | "set_http_only") {
            return;
        }
        let Some(arg) = call.args.first() else {
            return;
        };
        let ctx = self.ctx();
        let Some(arg_val) = ctx.resolve_value(arg) else {
            return;
        };
        if !literal_bool(&arg_val, false) {
            return;
        }
        let Some((cookie_name, alias_req)) = extract_cookie_name(&ctx, &call.receiver) else {
            return;
        };
        if !is_auth_cookie_name(&cookie_name) {
            return;
        }
        let span = self.span_to_bytes(arg.span());
        let loc = self.loc_at(span.start);
        let mut finding = RsCandidateFinding::new(
            RuleId::RsSecurityNoInsecureAuthCookie,
            self.scope.subject_name(),
            method_name.clone(),
            "rsSecurityNoInsecureAuthCookie",
            "An auth cookie is readable by page scripts.",
            loc,
            span,
        );
        if matches!(arg, syn::Expr::Lit(_)) {
            finding = finding.with_patch(dotore_core::AutofixPatch::replace(
                format!("Set `.{method_name}(true)` on authentication cookie"),
                span,
                "true",
            ));
        }
        if let Some((written, canonical)) = alias_req {
            finding = finding.with_required_crate_alias(written, canonical);
        }
        self.findings.push(finding);
    }

    // 7a. `rs-security-no-disabled-jwt-validation` (method `.insecure_disable_signature_validation()`)
    fn check_disabled_jwt_method(&mut self, call: &ExprMethodCall) {
        if self.scope.in_test() || call.method != "insecure_disable_signature_validation" {
            return;
        }
        let ctx = self.ctx();
        let Some(Expr::Call(ctor)) = ctx.chain_root(&call.receiver) else {
            return;
        };
        let Some(alias_req) = ctx.matches_any_path(
            &ctor.func,
            &[
                &["jsonwebtoken", "Validation", "new"],
                &["jsonwebtoken", "Validation", "default"],
            ],
        ) else {
            return;
        };
        let span = self.span_to_bytes(call.method.span());
        self.push_finding(
            RuleId::RsSecurityNoDisabledJwtValidation,
            "insecure_disable_signature_validation",
            "rsSecurityNoDisabledJwtValidation",
            "JWT signature validation is turned off.",
            span,
            alias_req,
        );
    }

    // 7b. `rs-security-no-disabled-jwt-validation` (`jsonwebtoken::dangerous::insecure_decode`)
    fn check_disabled_jwt_call(&mut self, call: &ExprCall) {
        self.check_matched_path_call(
            call,
            &[
                &["jsonwebtoken", "dangerous", "insecure_decode"],
                &["jsonwebtoken", "dangerous_insecure_decode"],
            ],
            RuleId::RsSecurityNoDisabledJwtValidation,
            "insecure_decode",
            "rsSecurityNoDisabledJwtValidation",
            "The JWT is decoded without checking its signature.",
            self.span_to_bytes(call.func.span()),
        );
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Shared path-matched ExprCall detector helper takes rule metadata and span"
    )]
    fn check_matched_path_call(
        &mut self,
        call: &ExprCall,
        paths: &[&[&str]],
        rule: RuleId,
        target_name: &str,
        group_key: &'static str,
        message: &'static str,
        span: ByteSpan,
    ) {
        if self.scope.in_test() {
            return;
        }
        let ctx = self.ctx();
        let Some(alias_req) = ctx.matches_any_path(&call.func, paths) else {
            return;
        };
        self.push_finding(rule, target_name, group_key, message, span, alias_req);
    }
}

impl<'ast> Visit<'ast> for SourceKernelDetectorsVisitor<'_> {
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
        let prev_ct = self.in_current_thread_runtime;
        self.in_current_thread_runtime = attrs_indicate_current_thread_runtime(&i.attrs);
        for stmt in &i.block.stmts {
            if !matches!(stmt, Stmt::Item(_)) {
                self.visit_stmt(stmt);
            }
        }
        self.in_current_thread_runtime = prev_ct;
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
        let prev_ct = self.in_current_thread_runtime;
        self.in_current_thread_runtime = attrs_indicate_current_thread_runtime(&i.attrs);
        for stmt in &i.block.stmts {
            if !matches!(stmt, Stmt::Item(_)) {
                self.visit_stmt(stmt);
            }
        }
        self.in_current_thread_runtime = prev_ct;
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

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_const(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_static(self, i);
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

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_block_in_place_on_current_thread(node);
        self.check_block_on_call_in_async(node);
        self.check_tainted_shell_program(node);
        self.check_permissive_cors_call(node);
        self.check_disabled_jwt_call(node);

        let is_offload = is_spawn_blocking_call(node);
        if is_offload {
            self.spawn_blocking_depth += 1;
        }
        visit::visit_expr_call(self, node);
        if is_offload {
            self.spawn_blocking_depth -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.check_block_on_method_in_async(node);
        self.check_disabled_tls(node);
        self.check_dynamic_shell_method(node);
        self.check_unchecked_http_status(node);
        self.check_secret_env_fallback(node);
        self.check_permissive_cors_credentials(node);
        self.check_insecure_auth_cookie(node);
        self.check_disabled_jwt_method(node);

        let is_offload = is_offloading_method_call(node);
        if is_offload {
            self.spawn_blocking_depth += 1;
        }
        self.current_method_chain_stack.push(node.clone());
        self.visit_expr(&node.receiver);
        self.current_method_chain_stack.pop();

        for arg in &node.args {
            self.visit_expr(arg);
        }
        if is_offload {
            self.spawn_blocking_depth -= 1;
        }
    }
}

const POSIX_FLAGS: &[&str] = &["-c"];
const CMD_FLAGS: &[&str] = &["/C", "/c"];
const POWERSHELL_FLAGS: &[&str] = &["-Command", "-c"];

const SHELLS: [(&str, &[&str]); 10] = [
    ("bash", POSIX_FLAGS),
    ("cmd", CMD_FLAGS),
    ("cmd.exe", CMD_FLAGS),
    ("dash", POSIX_FLAGS),
    ("ksh", POSIX_FLAGS),
    ("powershell", POWERSHELL_FLAGS),
    ("powershell.exe", POWERSHELL_FLAGS),
    ("pwsh", POWERSHELL_FLAGS),
    ("sh", POSIX_FLAGS),
    ("zsh", POSIX_FLAGS),
];

fn extract_command_arg_elements(call: &ExprMethodCall) -> Option<Vec<Expr>> {
    if call.args.len() != 1 {
        return None;
    }
    let first = call.args.first()?;
    match call.method.to_string().as_str() {
        "arg" => Some(vec![first.clone()]),
        "args" => {
            if let Expr::Array(arr) = strip_wrappers(first) {
                Some(arr.elems.iter().cloned().collect())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn resolve_shell_argv(
    ctx: &KernelContext<'_>,
    receiver: &Expr,
) -> Option<(&'static [&'static str], Vec<Expr>)> {
    let mut calls = Vec::new();
    let mut current = receiver.clone();
    for _ in 0..CHAIN_DEPTH {
        let resolved = ctx.resolve_value(strip_wrappers(&current))?;
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Walks method chain links back to the root Command::new(shell) constructor"
        )]
        match into_stripped_wrappers(resolved) {
            Expr::MethodCall(mc) => {
                if matches!(mc.method.to_string().as_str(), "arg" | "args") {
                    calls.push(extract_command_arg_elements(&mc)?);
                }
                current = *mc.receiver;
            }
            Expr::Call(cmd_call) => {
                ctx.matches_call_path(&cmd_call.func, "std", &["process", "Command"], "new")?;
                if cmd_call.args.len() != 1 {
                    return None;
                }
                let prog_expr = cmd_call.args.first()?;
                let prog = literal_string(&ctx.resolve_value(prog_expr)?)?;
                let bin_name = prog
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&prog)
                    .to_ascii_lowercase();
                let (_, flags) = SHELLS.iter().find(|(sh, _)| *sh == bin_name)?;
                let mut elements = Vec::new();
                for chunk in calls.into_iter().rev() {
                    elements.extend(chunk);
                }
                return Some((flags, elements));
            }
            _ => return None,
        }
    }
    None
}

fn resolve_unchecked_response_root(
    ctx: &KernelContext<'_>,
    receiver: &Expr,
    read_span: ByteSpan,
) -> Option<(ExprCall, bool)> {
    let mut current = receiver.clone();
    let mut sent = false;
    for _ in 0..CHAIN_DEPTH {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Unwinds method calls, `?`, `.await`, and response bindings back to the reqwest root call"
        )]
        match into_stripped_wrappers(current) {
            Expr::MethodCall(link) => {
                sent |= is_unchecked_http_link(&link)?;
                current = *link.receiver;
            }
            Expr::Try(tr) => current = *tr.expr,
            Expr::Await(aw) => current = *aw.base,
            Expr::Call(root) => return Some((root, sent)),
            bound => {
                current = resolve_unchecked_response_binding(ctx, &bound, read_span)?;
            }
        }
    }
    None
}

fn is_unchecked_http_link(link: &ExprMethodCall) -> Option<bool> {
    let name = link.method.to_string();
    if matches!(name.as_str(), "error_for_status" | "error_for_status_ref") {
        return None;
    }
    let checked_in_combinator = link.args.iter().any(expr_mentions_error_for_status);
    if checked_in_combinator {
        return None;
    }
    Some(name == "send")
}

fn expr_mentions_error_for_status(expr: &Expr) -> bool {
    struct Finder(bool);
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if matches!(
                node.method.to_string().as_str(),
                "error_for_status" | "error_for_status_ref"
            ) {
                self.0 = true;
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut f = Finder(false);
    f.visit_expr(expr);
    f.0
}

fn resolve_unchecked_response_binding(
    ctx: &KernelContext<'_>,
    bound: &Expr,
    read_span: ByteSpan,
) -> Option<Expr> {
    let name = bare_identifier(bound)?;
    let body = ctx.body?;
    if is_response_checked_or_handed_over(body, &name, read_span) {
        return None;
    }
    let site = span_to_bytes(bound.span());
    match body.resolve_binding(ctx.aliases, site, &name) {
        LocalBinding::Value(boxed) => Some(boxed.0),
        LocalBinding::Typed(_) | LocalBinding::Indeterminate | LocalBinding::Unbound => None,
    }
}

fn is_response_checked_or_handed_over(
    body: &FnBodyResolver,
    binding_name: &str,
    read_span: ByteSpan,
) -> bool {
    body.ident_usages.iter().any(|(ident, span, kind)| {
        if ident != binding_name {
            return false;
        }
        match kind {
            IdentUsageKind::PassedAsArg => true,
            IdentUsageKind::MethodReceiver(method) => {
                matches!(
                    method.as_str(),
                    "error_for_status" | "error_for_status_ref" | "is_success" | "status"
                ) && span.start < read_span.start
            }
        }
    })
}

fn match_reqwest_response_root(
    ctx: &KernelContext<'_>,
    root: &ExprCall,
    sent: bool,
) -> Option<Option<(String, String)>> {
    if let Some(req) = ctx.matches_any_path(
        &root.func,
        &[&["reqwest", "get"], &["reqwest", "blocking", "get"]],
    ) {
        return Some(req);
    }
    if sent {
        return ctx.matches_any_path(
            &root.func,
            &[
                &["reqwest", "Client", "new"],
                &["reqwest", "Client", "builder"],
                &["reqwest", "blocking", "Client", "new"],
                &["reqwest", "blocking", "Client", "builder"],
            ],
        );
    }
    None
}

fn is_any_cors_origin(ctx: &KernelContext<'_>, origin: &Expr) -> Option<Option<(String, String)>> {
    let resolved = ctx.resolve_value(strip_wrappers(origin))?;
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Wildcard CORS origins are either AllowOrigin::any()/mirror_request() calls or the unit struct path tower_http::cors::Any"
    )]
    match strip_wrappers(&resolved) {
        Expr::Call(call) => ctx.matches_any_path(
            &call.func,
            &[
                &["tower_http", "cors", "AllowOrigin", "any"],
                &["tower_http", "cors", "AllowOrigin", "mirror_request"],
            ],
        ),
        path @ Expr::Path(_) => {
            ctx.matches_any_path(path, &[&["tower_http", "cors", "Any"]])
        }
        _ => None,
    }
}

const AUTH_COOKIE_WORDS: [&str; 4] = ["access_token", "auth", "jwt", "session"];
const CSRF_WORDS: [&str; 2] = ["csrf", "xsrf"];

fn is_auth_cookie_name(name: &str) -> bool {
    AUTH_COOKIE_WORDS.iter().any(|w| name.contains(w))
        && !CSRF_WORDS.iter().any(|w| name.contains(w))
}

fn extract_cookie_name(
    ctx: &KernelContext<'_>,
    receiver: &Expr,
) -> Option<(String, Option<(String, String)>)> {
    let Expr::Call(ctor) = ctx.chain_root(receiver)? else {
        return None;
    };
    let alias_req = ctx.matches_any_path(
        &ctor.func,
        &[
            &["cookie", "Cookie", "build"],
            &["cookie", "Cookie", "new"],
            &["cookie", "CookieBuilder", "new"],
        ],
    )?;
    let first = ctor.args.first()?;
    let resolved_first = ctx.resolve_value(strip_wrappers(first))?;
    let raw_name = if let Expr::Tuple(pair) = strip_wrappers(&resolved_first) {
        literal_string(pair.elems.first()?)?
    } else {
        literal_string(strip_wrappers(&resolved_first))?
    };
    Some((raw_name.to_ascii_lowercase(), alias_req))
}

fn attrs_indicate_current_thread_runtime(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path_str = path_to_string(attr.path());
        let raw_tokens = match &attr.meta {
            syn::Meta::List(list) => list.tokens.to_string().replace(' ', ""),
            syn::Meta::Path(_) | syn::Meta::NameValue(_) => String::new(),
        };
        let multi = raw_tokens.contains("flavor=\"multi_thread\"");
        let current = raw_tokens.contains("flavor=\"current_thread\"");
        (path_str == "tokio::test" && !multi) || (path_str == "tokio::main" && current)
    })
}
