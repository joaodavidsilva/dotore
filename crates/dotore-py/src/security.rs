//! Python SQL injection and unsafe deserialization / shell command detectors:
//! - `py-security-no-raw-sql-interpolation` (`Capability::Python`)
//! - `py-security-no-unsafe-deserialization-or-shell` (`Capability::Python`, `Autofix`)

use std::{collections::HashSet, path::Path};

use dotore_core::{AutofixPatch, ByteSpan, Diagnostic, RuleId};
use ruff_python_ast::{
    Expr, ExprCall, Operator, Stmt, StmtAnnAssign, StmtAssign, StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, build_py_diagnostic, build_py_diagnostic_with_autofix, callee_qualified_name,
    is_subprocess_callee, slice_source, text_range_to_byte_span,
};

/// Evaluates `py-security-no-raw-sql-interpolation` and `py-security-no-unsafe-deserialization-or-shell` over `suite`.
pub(crate) fn extract_security_diagnostics(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if !is_stub_file && !suite.is_empty() {
        let mut visitor = SecurityRuleVisitor {
            path,
            source,
            line_starts,
            out,
            scope: PyScopeTracker::new(),
            interpolated_sql_vars: HashSet::new(),
        };
        visitor.visit_suite(suite);
    }
}

struct SecurityRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    interpolated_sql_vars: HashSet<String>,
}

impl<'a> SecurityRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python statement variants for SQL injection and deserialization/shell rules (#50)"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::AnnAssign(ann_assign) => {
                self.record_interpolated_sql_from_ann_assign(ann_assign);
                self.visit_expr(&ann_assign.annotation);
                if let Some(val) = &ann_assign.value {
                    self.visit_expr(val);
                }
            }
            Stmt::Assign(assign) => {
                self.record_interpolated_sql_from_assign(assign);
                self.visit_expr(&assign.value);
            }
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
            _ => {
                crate::matchers::walk_stmt_exprs(stmt, |e| self.visit_expr(e));
                crate::matchers::walk_stmt_sub_stmts(stmt, |s| self.visit_stmt(s));
            }
        }
    }

    fn visit_class_def(&mut self, class_def: &StmtClassDef) {
        self.scope.enter_class(class_def.name.as_str());
        self.visit_suite(&class_def.body);
        self.scope.exit_class();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        for dec in &func_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        if let Some(ret) = &func_def.returns {
            self.visit_expr(ret);
        }

        let saved_sql_vars = self.interpolated_sql_vars.clone();
        let saved_scope = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        self.visit_suite(&func_def.body);
        self.scope.exit_function(saved_scope);
        self.interpolated_sql_vars = saved_sql_vars;
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Call(call) = expr {
            let callee = callee_qualified_name(&call.func);
            self.check_raw_sql_interpolation(call, &callee);
            self.check_unsafe_deserialization_or_shell(call, &callee);
        }
        crate::matchers::walk_expr_children(expr, |child| self.visit_expr(child));
    }

    fn record_interpolated_sql_from_assign(&mut self, assign: &StmtAssign) {
        let Some(Expr::Name(target)) = assign.targets.first() else {
            return;
        };
        if is_interpolated_sql_expr(&assign.value, &self.interpolated_sql_vars) {
            self.interpolated_sql_vars.insert(target.id.to_string());
        } else {
            self.interpolated_sql_vars.remove(target.id.as_str());
        }
    }

    fn record_interpolated_sql_from_ann_assign(&mut self, ann_assign: &StmtAnnAssign) {
        let Expr::Name(target) = ann_assign.target.as_ref() else {
            return;
        };
        if let Some(val) = &ann_assign.value {
            if is_interpolated_sql_expr(val, &self.interpolated_sql_vars) {
                self.interpolated_sql_vars.insert(target.id.to_string());
            } else {
                self.interpolated_sql_vars.remove(target.id.as_str());
            }
        }
    }

    fn check_raw_sql_interpolation(&mut self, call: &ExprCall, callee: &str) {
        if !is_sql_execution_sink_callee(callee) {
            return;
        }
        let sql_arg = call.arguments.args.first().or_else(|| {
            call.arguments.keywords.iter().find_map(|kw| {
                kw.arg
                    .as_ref()
                    .is_some_and(|a| matches!(a.as_str(), "sql" | "statement" | "stmt" | "query"))
                    .then_some(&kw.value)
            })
        });
        let Some(sql_expr) = sql_arg else {
            return;
        };
        // Avoid double-reporting when `session.execute(text(f"..."))` wraps `text(...)`
        if let Expr::Call(inner_call) = sql_expr {
            let inner_callee = callee_qualified_name(&inner_call.func);
            if is_sql_execution_sink_callee(&inner_callee) {
                return;
            }
        }
        if !is_interpolated_sql_expr(sql_expr, &self.interpolated_sql_vars) {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PySecurityNoRawSqlInterpolation,
            "pySecurityNoRawSqlInterpolation",
            callee.to_string(),
            format!(
                "SQL execution sink `{callee}(...)` receives a dynamically interpolated SQL string; use parameterized bind parameters instead."
            ),
        ));
    }

    fn check_unsafe_deserialization_or_shell(&mut self, call: &ExprCall, callee: &str) {
        if is_subprocess_callee(callee) {
            let has_shell_true = call.arguments.keywords.iter().any(|kw| {
                kw.arg.as_ref().is_some_and(|a| a.as_str() == "shell")
                    && !matches!(
                        &kw.value,
                        Expr::BooleanLiteral(b) if !b.value
                    )
                    && !matches!(&kw.value, Expr::NoneLiteral(_))
            });
            if has_shell_true {
                self.push_unsafe_deserialization_or_shell_diag(
                    text_range_to_byte_span(call.range()),
                    callee.to_string(),
                    format!(
                        "Subprocess call `{callee}(..., shell=True)` executes commands through the system shell; pass an argument list with `shell=False`."
                    ),
                    None,
                );
            }
            return;
        }

        if matches!(
            callee,
            "os.system"
                | "os.popen"
                | "eval"
                | "builtins.eval"
                | "exec"
                | "builtins.exec"
                | "pickle.loads"
                | "pickle.load"
                | "_pickle.loads"
                | "_pickle.load"
                | "cPickle.loads"
                | "cPickle.load"
                | "dill.loads"
                | "dill.load"
                | "marshal.loads"
                | "marshal.load"
                | "shelve.open"
                | "jsonpickle.decode"
        ) {
            self.push_unsafe_deserialization_or_shell_diag(
                text_range_to_byte_span(call.range()),
                callee.to_string(),
                format!(
                    "Unsafe code execution or deserialization sink `{callee}(...)` can execute arbitrary code on untrusted input."
                ),
                None,
            );
            return;
        }

        if let Some(yaml_recv) = yaml_unsafe_load_receiver(callee) {
            if callee.ends_with(".load") && yaml_call_has_safe_loader(call) {
                return;
            }
            let span = text_range_to_byte_span(call.range());
            let autofix = call.arguments.args.first().map(|first_arg| {
                let arg_text =
                    slice_source(self.source, text_range_to_byte_span(first_arg.range()));
                let replacement = format!("{yaml_recv}.safe_load({arg_text})");
                AutofixPatch::replace(
                    format!("Rewrite `{callee}(...)` to `{replacement}`"),
                    span,
                    replacement,
                )
            });
            self.push_unsafe_deserialization_or_shell_diag(
                span,
                callee.to_string(),
                format!(
                    "`{callee}(...)` without `SafeLoader` allows arbitrary Python object instantiation; use `{yaml_recv}.safe_load(...)` instead."
                ),
                autofix,
            );
        }
    }

    fn push_unsafe_deserialization_or_shell_diag(
        &mut self,
        span: ByteSpan,
        target_name: String,
        message: String,
        autofix: Option<AutofixPatch>,
    ) {
        self.out.push(build_py_diagnostic_with_autofix(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PySecurityNoUnsafeDeserializationOrShell,
            "pySecurityNoUnsafeDeserializationOrShell",
            target_name,
            message,
            autofix,
        ));
    }
}

fn is_sql_execution_sink_callee(callee: &str) -> bool {
    if matches!(
        callee,
        "text"
            | "sqlalchemy.text"
            | "sqlalchemy.sql.text"
            | "RawSQL"
            | "django.db.models.expressions.RawSQL"
    ) {
        return true;
    }
    let Some((recv, method)) = callee.rsplit_once('.') else {
        return false;
    };
    if method == "raw" && (recv == "objects" || recv.ends_with(".objects")) {
        return true;
    }
    if !matches!(
        method,
        "execute"
            | "executemany"
            | "executescript"
            | "exec_driver_sql"
            | "fetch"
            | "fetchrow"
            | "fetchval"
    ) {
        return false;
    }
    let recv_lower = recv.to_ascii_lowercase();
    matches!(
        recv_lower.as_str(),
        "cursor"
            | "cur"
            | "session"
            | "async_session"
            | "db"
            | "db_session"
            | "conn"
            | "connection"
            | "engine"
            | "db_engine"
            | "async_engine"
            | "self.cursor"
            | "self.session"
            | "self.db"
            | "self.conn"
            | "self.connection"
            | "self.engine"
    ) || recv_lower.ends_with("_cursor")
        || recv_lower.ends_with("_session")
        || recv_lower.ends_with("_conn")
        || recv_lower.ends_with("_connection")
        || recv_lower.ends_with("_engine")
        || recv_lower.ends_with("_db")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Detects f-strings, .format(), % formatting, and + string concatenation on SQL strings"
)]
fn is_interpolated_sql_expr(expr: &Expr, interpolated_vars: &HashSet<String>) -> bool {
    match expr {
        Expr::FString(fstr) => fstr.value.elements().any(|e| e.is_interpolation()),
        Expr::Call(call) => {
            if let Expr::Attribute(attr) = call.func.as_ref()
                && attr.attr.as_str() == "format"
            {
                return true;
            }
            false
        }
        Expr::BinOp(bin) => match bin.op {
            Operator::Mod => true,
            Operator::Add => {
                !is_pure_string_literal(&bin.left) || !is_pure_string_literal(&bin.right)
            }
            _ => false,
        },
        Expr::Name(n) => interpolated_vars.contains(n.id.as_str()),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an expression is composed solely of static string literals"
)]
fn is_pure_string_literal(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) => true,
        Expr::BinOp(bin) if bin.op == Operator::Add => {
            is_pure_string_literal(&bin.left) && is_pure_string_literal(&bin.right)
        }
        _ => false,
    }
}

fn yaml_unsafe_load_receiver(callee: &str) -> Option<&str> {
    for suffix in [".load", ".unsafe_load", ".full_load"] {
        if let Some(recv) = callee.strip_suffix(suffix)
            && (recv == "yaml" || recv.ends_with(".yaml"))
        {
            return Some(recv);
        }
    }
    None
}

fn yaml_call_has_safe_loader(call: &ExprCall) -> bool {
    let loader_expr = call
        .arguments
        .keywords
        .iter()
        .find_map(|kw| {
            kw.arg
                .as_ref()
                .is_some_and(|a| a.as_str() == "Loader")
                .then_some(&kw.value)
        })
        .or_else(|| call.arguments.args.get(1));

    let Some(loader) = loader_expr else {
        return false;
    };
    let name = callee_qualified_name(loader);
    let tail = name.rsplit('.').next().unwrap_or(&name);
    matches!(
        tail,
        "SafeLoader" | "CSafeLoader" | "BaseLoader" | "CBaseLoader"
    )
}
