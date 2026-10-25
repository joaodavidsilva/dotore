//! Core Python runtime and resource safety rules:
//! - `py-no-mutable-default-arg` (`Capability::Python`, `Autofix`)
//! - `py-no-silent-broad-except` (`Capability::Python`)
//! - `py-require-context-manager-for-resource` (`Capability::Python`)
//! - `py-no-unguarded-parse-or-key-access` (`Capability::Python`)
//! - `py-require-timezone-aware-datetime` (`Capability::Python`, `Autofix`)

mod helpers;

use std::{collections::HashSet, path::Path};

use dotore_core::{AutofixPatch, ByteSpan, Diagnostic, RuleId};
use ruff_python_ast::{Expr, ExprCall, ExprSubscript, Stmt, StmtClassDef, StmtFunctionDef, UnaryOp};
use ruff_text_size::Ranged;

use crate::{
    ir::extract_header_signature,
    matchers::{
        PyScopeTracker, all_function_parameters, build_py_diagnostic,
        build_py_diagnostic_with_autofix, build_py_diagnostic_with_patch, callee_qualified_name,
        extract_target_var_name, slice_source, text_range_to_byte_span,
    },
};

use self::helpers::{
    build_mutable_default_autofix, collect_caught_exceptions, collect_finally_closed_vars,
    expr_contains_broad_exception, extract_if_guards, is_dict_or_external_mapping_receiver,
    is_ellipsis_only_body, is_fallback_try_stmt, is_mutable_default_expr,
    is_resource_acquisition_callee, is_safe_numeric_parse_arg, is_silent_handler_body,
    is_typing_generic_receiver, suite_terminates_early,
};
/// Evaluates the 5 core Python runtime and resource safety rules over `suite`.
pub(crate) fn extract_safety_diagnostics(
    path: &Path,
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if is_stub_file {
        return;
    }
    let mut visitor = SafetyRuleVisitor {
        path,
        source,
        lines,
        line_starts,
        out,
        scope: PyScopeTracker::new(),
        finally_closed_vars: vec![collect_finally_closed_vars(suite)],
        caught_exception_stack: Vec::new(),
        guarded_numeric_vars: vec![HashSet::new()],
        guarded_dict_keys: vec![HashSet::new()],
        assigned_var_name: None,
        in_fallback_try_chain: false,
    };
    visitor.visit_suite(suite);
}

struct SafetyRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    finally_closed_vars: Vec<HashSet<String>>,
    caught_exception_stack: Vec<HashSet<String>>,
    guarded_numeric_vars: Vec<HashSet<String>>,
    guarded_dict_keys: Vec<HashSet<(String, String)>>,
    assigned_var_name: Option<String>,
    in_fallback_try_chain: bool,
}

impl<'a> SafetyRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        self.guarded_numeric_vars.push(HashSet::new());
        self.guarded_dict_keys.push(HashSet::new());
        for (idx, stmt) in suite.iter().enumerate() {
            let prev_fallback = self.in_fallback_try_chain;
            self.in_fallback_try_chain = is_fallback_try_stmt(stmt)
                && ((idx > 0 && suite.get(idx - 1).is_some_and(is_fallback_try_stmt))
                    || suite.get(idx + 1).is_some_and(is_fallback_try_stmt));
            self.visit_stmt(stmt);
            self.in_fallback_try_chain = prev_fallback;
        }
        self.guarded_dict_keys.pop();
        self.guarded_numeric_vars.pop();
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Python Stmt enum has many variants; safety visitor inspects structural declarations and recurses into compound statements (#50)"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::Assign(assign) => {
                let prev_assigned = self.assigned_var_name.take();
                self.assigned_var_name = assign.targets.first().and_then(extract_target_var_name);
                self.visit_expr(&assign.value);
                self.assigned_var_name = prev_assigned;
            }
            Stmt::AnnAssign(ann_assign) => {
                if let Some(val) = &ann_assign.value {
                    let prev_assigned = self.assigned_var_name.take();
                    self.assigned_var_name = extract_target_var_name(&ann_assign.target);
                    self.visit_expr(val);
                    self.assigned_var_name = prev_assigned;
                }
            }
            Stmt::Return(ret_stmt) => {
                if let Some(val) = &ret_stmt.value {
                    let prev = self.scope.in_return_or_yield;
                    self.scope.in_return_or_yield = true;
                    self.visit_expr(val);
                    self.scope.in_return_or_yield = prev;
                }
            }
            Stmt::If(if_stmt) => self.visit_if_stmt(if_stmt),
            Stmt::For(for_stmt) => {
                self.visit_expr(&for_stmt.iter);
                self.scope.enter_loop();
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
                self.scope.exit_loop();
            }
            Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.scope.enter_loop();
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
                self.scope.exit_loop();
            }
            Stmt::With(with_stmt) => {
                let prev_with = self.scope.in_with_context_expr;
                self.scope.in_with_context_expr = true;
                for item in &with_stmt.items {
                    self.visit_expr(&item.context_expr);
                }
                self.scope.in_with_context_expr = prev_with;
                self.visit_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => self.visit_try_stmt(try_stmt),
            _ => {
                crate::matchers::walk_stmt_exprs(stmt, |e| self.visit_expr(e));
                crate::matchers::walk_stmt_sub_stmts(stmt, |s| self.visit_stmt(s));
            }
        }
    }

    fn visit_if_stmt(&mut self, if_stmt: &ruff_python_ast::StmtIf) {
        self.visit_expr(&if_stmt.test);
        let (pos_num, pos_keys, neg_num, neg_keys) = extract_if_guards(self.source, &if_stmt.test);
        self.guarded_numeric_vars.push(pos_num);
        self.guarded_dict_keys.push(pos_keys);
        self.visit_suite(&if_stmt.body);
        self.guarded_dict_keys.pop();
        self.guarded_numeric_vars.pop();

        for clause in &if_stmt.elif_else_clauses {
            if let Some(test) = &clause.test {
                self.visit_expr(test);
                let (c_pos_num, c_pos_keys, _, _) = extract_if_guards(self.source, test);
                self.guarded_numeric_vars.push(c_pos_num);
                self.guarded_dict_keys.push(c_pos_keys);
                self.visit_suite(&clause.body);
                self.guarded_dict_keys.pop();
                self.guarded_numeric_vars.pop();
            } else {
                self.guarded_numeric_vars.push(neg_num.clone());
                self.guarded_dict_keys.push(neg_keys.clone());
                self.visit_suite(&clause.body);
                self.guarded_dict_keys.pop();
                self.guarded_numeric_vars.pop();
            }
        }

        if suite_terminates_early(&if_stmt.body) {
            if let Some(top_num) = self.guarded_numeric_vars.last_mut() {
                top_num.extend(neg_num);
            }
            if let Some(top_keys) = self.guarded_dict_keys.last_mut() {
                top_keys.extend(neg_keys);
            }
        }
    }

    fn visit_try_stmt(&mut self, try_stmt: &ruff_python_ast::StmtTry) {
        let skip_silent_handlers = self.in_fallback_try_chain;
        let caught = collect_caught_exceptions(&try_stmt.handlers);
        self.caught_exception_stack.push(caught);
        self.visit_suite(&try_stmt.body);
        self.caught_exception_stack.pop();
        for ruff_python_ast::ExceptHandler::ExceptHandler(h) in &try_stmt.handlers {
            if !skip_silent_handlers {
                self.check_except_handler(h);
            }
            self.visit_suite(&h.body);
        }
        self.visit_suite(&try_stmt.orelse);
        self.visit_suite(&try_stmt.finalbody);
    }

    fn visit_class_def(&mut self, class_def: &StmtClassDef) {
        for dec in &class_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        let _ = self.scope.enter_class(class_def.name.as_str());
        for stmt in &class_def.body {
            self.visit_stmt(stmt);
        }
        self.scope.exit_class();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        let span = text_range_to_byte_span(func_def.range());
        let name_span = text_range_to_byte_span(func_def.name.range());
        let body_start = func_def
            .body
            .first()
            .map_or(span.end, |s| s.range().start().to_u32());
        let def_header_start = func_def
            .decorator_list
            .last()
            .map_or(span.start, |d| d.range().end().to_u32());
        let (_, signature_end_line) = extract_header_signature(
            self.source,
            self.line_starts,
            name_span.start,
            def_header_start,
            body_start,
        );

        let saved = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        let subject_name = saved.subject_name.clone();
        self.check_mutable_default_args(func_def, &subject_name, signature_end_line);

        self.finally_closed_vars
            .push(collect_finally_closed_vars(&func_def.body));
        self.visit_suite(&func_def.body);
        self.finally_closed_vars.pop();
        self.scope.exit_function(saved);
    }

    fn check_mutable_default_args(
        &mut self,
        func_def: &StmtFunctionDef,
        subject_name: &str,
        signature_end_line: u32,
    ) {
        if is_ellipsis_only_body(&func_def.body) {
            return;
        }

        for param in all_function_parameters(func_def) {
            let Some(default_expr) = param.default.as_deref() else {
                continue;
            };
            if !is_mutable_default_expr(default_expr) {
                continue;
            }

            let param_name = param.parameter.name.to_string();
            let param_span = text_range_to_byte_span(param.range());
            let default_span = text_range_to_byte_span(default_expr.range());
            let default_text = slice_source(self.source, default_span);

            let autofix = build_mutable_default_autofix(
                self.source,
                self.lines,
                self.line_starts,
                &func_def.body,
                signature_end_line,
                &param_name,
                default_span,
                default_text,
            );

            self.out.push(build_py_diagnostic_with_autofix(
                self.path,
                self.line_starts,
                param_span,
                Some(subject_name.to_string()),
                RuleId::PyNoMutableDefaultArg,
                "pyNoMutableDefaultArg",
                param_name.clone(),
                format!(
                    "Parameter `{param_name}` uses mutable default `{default_text}` which is shared across all calls to `{subject_name}`; default to `None` and initialize inside the function body."
                ),
                autofix,
            ));
        }
    }

    fn check_except_handler(&mut self, handler: &ruff_python_ast::ExceptHandlerExceptHandler) {
        if !is_silent_handler_body(&handler.body, self.scope.in_loop()) {
            return;
        }
        let target_name = match handler.type_.as_deref() {
            None => "except".to_string(),
            Some(type_expr) if expr_contains_broad_exception(type_expr) => {
                slice_source(self.source, text_range_to_byte_span(type_expr.range())).to_string()
            }
            Some(_) => return,
        };

        let span = text_range_to_byte_span(handler.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyNoSilentBroadExcept,
            "pyNoSilentBroadExcept",
            target_name.clone(),
            format!(
                "Broad exception handler `{target_name}` silently swallows errors without logging, re-raising, or returning a fallback value."
            ),
        ));
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python expression kinds for single-pass safety rule detection (#50)"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => self.visit_call_expr(call),
            Expr::Attribute(attr) => {
                let prev_with = self.scope.in_with_context_expr;
                self.scope.in_with_context_expr = false;
                self.visit_expr(&attr.value);
                self.scope.in_with_context_expr = prev_with;
            }
            Expr::Yield(yield_expr) => {
                if let Some(val) = &yield_expr.value {
                    let prev = self.scope.in_return_or_yield;
                    self.scope.in_return_or_yield = true;
                    self.visit_expr(val);
                    self.scope.in_return_or_yield = prev;
                }
            }
            Expr::YieldFrom(yield_from) => {
                let prev = self.scope.in_return_or_yield;
                self.scope.in_return_or_yield = true;
                self.visit_expr(&yield_from.value);
                self.scope.in_return_or_yield = prev;
            }
            Expr::Subscript(sub) => {
                self.check_unguarded_subscript(sub);
                self.visit_expr(&sub.value);
                self.visit_expr(&sub.slice);
            }
            Expr::Named(named) => {
                let prev_assigned = self.assigned_var_name.take();
                self.assigned_var_name = extract_target_var_name(&named.target);
                self.visit_expr(&named.value);
                self.assigned_var_name = prev_assigned;
            }
            _ => crate::matchers::walk_expr_children(expr, |child| self.visit_expr(child)),
        }
    }

    fn visit_call_expr(&mut self, call: &ExprCall) {
        let callee = callee_qualified_name(&call.func);
        let is_cm_wrapper = matches!(
            callee.as_str(),
            "closing" | "contextlib.closing" | "nullcontext" | "contextlib.nullcontext"
        ) || callee.ends_with(".enter_context")
            || callee.ends_with(".enter_async_context");

        if !is_cm_wrapper {
            self.check_resource_context_manager(call, &callee);
        }
        self.check_unguarded_parse_call(call, &callee);
        self.check_timezone_aware_datetime(call);
        let prev_assigned = self.assigned_var_name.take();
        self.visit_expr(&call.func);
        self.assigned_var_name = prev_assigned;

        let prev_with = self.scope.in_with_context_expr;
        self.scope.in_with_context_expr = is_cm_wrapper;
        for arg in &call.arguments.args {
            self.visit_expr(arg);
        }
        for kw in &call.arguments.keywords {
            self.visit_expr(&kw.value);
        }
        self.scope.in_with_context_expr = prev_with;
    }
}

impl SafetyRuleVisitor<'_> {
    fn check_resource_context_manager(&mut self, call: &ExprCall, callee: &str) {
        if self.scope.in_with_context_expr || self.scope.in_return_or_yield {
            return;
        }
        if self
            .scope
            .current_subject_str()
            .is_some_and(|s| s.ends_with(".__enter__") || s.ends_with(".__aenter__"))
        {
            return;
        }
        if !is_resource_acquisition_callee(callee, &call.func) {
            return;
        }
        if let Some(var_name) = &self.assigned_var_name
            && self
                .finally_closed_vars
                .last()
                .is_some_and(|closed| closed.contains(var_name))
        {
            return;
        }

        let span = text_range_to_byte_span(call.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyRequireContextManagerForResource,
            "pyRequireContextManagerForResource",
            callee.to_string(),
            format!(
                "Resource `{callee}(...)` is acquired outside a `with` or `async with` context manager and may leak file descriptors or database connections."
            ),
        ));
    }

    fn check_unguarded_parse_call(&mut self, call: &ExprCall, callee: &str) {
        let is_json_loads = matches!(
            callee,
            "json.loads" | "orjson.loads" | "ujson.loads" | "tomllib.loads" | "loads"
        );
        if is_json_loads {
            let first_arg = call.arguments.args.first();
            if matches!(
                first_arg,
                Some(Expr::StringLiteral(_) | Expr::BytesLiteral(_))
            ) {
                return;
            }
            if self.is_caught(&[
                "ValueError",
                "JSONDecodeError",
                "TOMLDecodeError",
                "DecodeError",
            ]) {
                return;
            }
            self.push_unguarded_parse_or_key_diag(
                text_range_to_byte_span(call.range()),
                callee.to_string(),
                format!(
                    "Call to `{callee}(...)` on untrusted input is not wrapped in `try/except (json.JSONDecodeError, ValueError)`."
                ),
            );
            return;
        }

        if matches!(callee, "int" | "float") {
            let Some(first_arg) = call.arguments.args.first() else {
                return;
            };
            if is_safe_numeric_parse_arg(first_arg) {
                return;
            }
            if self.is_caught(&["ValueError", "TypeError"]) {
                return;
            }
            if let Expr::Name(n) = first_arg
                && self.is_numeric_var_guarded(n.id.as_str())
            {
                return;
            }
            self.push_unguarded_parse_or_key_diag(
                text_range_to_byte_span(call.range()),
                callee.to_string(),
                format!(
                    "Call to `{callee}(...)` on non-literal input can raise `ValueError` at runtime; wrap in `try/except ValueError` or guard with `.isdigit()`."
                ),
            );
        }
    }

    fn check_unguarded_subscript(&mut self, sub: &ExprSubscript) {
        if !sub.ctx.is_load() {
            return;
        }
        if matches!(
            sub.slice.as_ref(),
            Expr::Slice(_) | Expr::NumberLiteral(_) | Expr::Tuple(_)
        ) {
            return;
        }
        if let Expr::UnaryOp(un) = sub.slice.as_ref()
            && matches!(un.op, UnaryOp::USub | UnaryOp::UAdd)
            && matches!(un.operand.as_ref(), Expr::NumberLiteral(_))
        {
            return;
        }
        let recv_name = callee_qualified_name(&sub.value);
        if recv_name.is_empty() || is_typing_generic_receiver(&recv_name) {
            return;
        }
        if !is_dict_or_external_mapping_receiver(&recv_name)
            && !matches!(sub.slice.as_ref(), Expr::StringLiteral(_))
        {
            return;
        }
        if self.is_caught(&["KeyError", "LookupError", "IndexError"]) {
            return;
        }
        let key_span = text_range_to_byte_span(sub.slice.range());
        let key_text = slice_source(self.source, key_span).trim();
        if self.is_dict_key_guarded(&recv_name, key_text) {
            return;
        }
        let span = text_range_to_byte_span(sub.range());
        let expr_text = slice_source(self.source, span);
        self.push_unguarded_parse_or_key_diag(
            span,
            recv_name.clone(),
            format!(
                "Direct key access `{expr_text}` can raise `KeyError` on missing keys; use `{recv_name}.get({key_text})`, check `if {key_text} in {recv_name}:`, or wrap in `try/except KeyError`."
            ),
        );
    }

    fn push_unguarded_parse_or_key_diag(
        &mut self,
        span: ByteSpan,
        target_name: String,
        message: String,
    ) {
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyNoUnguardedParseOrKeyAccess,
            "pyNoUnguardedParseOrKeyAccess",
            target_name,
            message,
        ));
    }

    fn is_caught(&self, accepted: &[&str]) -> bool {
        self.caught_exception_stack.iter().any(|frame| {
            frame.contains("Exception")
                || frame.contains("BaseException")
                || accepted.iter().any(|&name| frame.contains(name))
        })
    }

    fn is_numeric_var_guarded(&self, var_name: &str) -> bool {
        self.guarded_numeric_vars
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    fn is_dict_key_guarded(&self, recv_name: &str, key_text: &str) -> bool {
        let target = (recv_name.to_string(), key_text.to_string());
        self.guarded_dict_keys
            .iter()
            .any(|frame| frame.contains(&target))
    }

    fn check_timezone_aware_datetime(&mut self, call: &ExprCall) {
        let Expr::Attribute(attr) = call.func.as_ref() else {
            return;
        };
        let method = attr.attr.as_str();
        if !matches!(
            method,
            "now" | "utcnow" | "fromtimestamp" | "utcfromtimestamp"
        ) {
            return;
        }
        let recv = callee_qualified_name(&attr.value);
        let tz_utc = if recv == "datetime" {
            "timezone.utc".to_string()
        } else if let Some(mod_prefix) = recv.strip_suffix(".datetime") {
            format!("{mod_prefix}.timezone.utc")
        } else {
            return;
        };

        let has_tz_kw = call.arguments.keywords.iter().any(|kw| {
            kw.arg.as_ref().is_some_and(|k| k.as_str() == "tz")
                && !matches!(kw.value, Expr::NoneLiteral(_))
        });

        let replacement = match method {
            "utcnow" => format!("{recv}.now({tz_utc})"),
            "now" => {
                let has_pos_tz = call
                    .arguments
                    .args
                    .first()
                    .is_some_and(|a| !matches!(a, Expr::NoneLiteral(_)));
                if has_pos_tz || has_tz_kw {
                    return;
                }
                format!("{recv}.now({tz_utc})")
            }
            "utcfromtimestamp" => {
                let Some(ts_arg) = call.arguments.args.first() else {
                    return;
                };
                let ts_text = slice_source(self.source, text_range_to_byte_span(ts_arg.range()));
                format!("{recv}.fromtimestamp({ts_text}, tz={tz_utc})")
            }
            "fromtimestamp" => {
                let has_pos_tz = call
                    .arguments
                    .args
                    .get(1)
                    .is_some_and(|a| !matches!(a, Expr::NoneLiteral(_)));
                if has_pos_tz || has_tz_kw {
                    return;
                }
                let Some(ts_arg) = call.arguments.args.first() else {
                    return;
                };
                let ts_text = slice_source(self.source, text_range_to_byte_span(ts_arg.range()));
                format!("{recv}.fromtimestamp({ts_text}, tz={tz_utc})")
            }
            _ => return,
        };

        let span = text_range_to_byte_span(call.range());
        let callee_display = format!("{recv}.{method}");
        let patch = AutofixPatch::replace(
            format!("Rewrite `{callee_display}(...)` to `{replacement}`"),
            span,
            replacement.clone(),
        );
        self.out.push(build_py_diagnostic_with_patch(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyRequireTimezoneAwareDatetime,
            "pyRequireTimezoneAwareDatetime",
            callee_display.clone(),
            format!(
                "Call to `{callee_display}(...)` produces a timezone-naive `datetime`; use `{replacement}` with an explicit timezone."
            ),
            patch,
        ));
    }
}

