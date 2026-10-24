//! SQLAlchemy and Django ORM N+1 query detector (`py-orm-no-query-in-loop`).

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use dotore_core::{ByteSpan, Diagnostic, RuleId};
use ruff_python_ast::{
    Expr, ExprAttribute, ExprCall, Stmt, StmtAnnAssign, StmtAssign, StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, build_py_diagnostic, callee_qualified_name, text_range_to_byte_span,
};

/// Evaluates `py-orm-no-query-in-loop` over `suite`.
pub(crate) fn extract_orm_diagnostics(
    path: &Path,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if is_stub_file {
        return;
    }
    let mut visitor = OrmRuleVisitor {
        path,
        line_starts,
        out,
        scope: PyScopeTracker::new(),
        eager_query_vars: HashSet::new(),
        orm_collection_vars: HashMap::new(),
        orm_loop_iter_vars: Vec::new(),
        reported_lazy_rel_spans: Vec::new(),
    };
    visitor.visit_suite(suite);
}

struct OrmRuleVisitor<'a> {
    path: &'a Path,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    eager_query_vars: HashSet<String>,
    orm_collection_vars: HashMap<String, bool>,
    orm_loop_iter_vars: Vec<(String, bool)>,
    reported_lazy_rel_spans: Vec<ByteSpan>,
}

impl<'a> OrmRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python statement variants for ORM N+1 query detection"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::AnnAssign(ann_assign) => {
                self.record_orm_query_binding_from_ann_assign(ann_assign);
                self.visit_expr(&ann_assign.annotation);
                if let Some(val) = &ann_assign.value {
                    self.visit_expr(val);
                }
            }
            Stmt::Assign(assign) => {
                self.record_orm_query_binding_from_assign(assign);
                self.visit_expr(&assign.value);
            }
            Stmt::AugAssign(aug) => self.visit_expr(&aug.value),
            Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    self.visit_expr(val);
                }
            }
            Stmt::Raise(raise_stmt) => {
                if let Some(exc) = &raise_stmt.exc {
                    self.visit_expr(exc);
                }
            }
            Stmt::Assert(assert_stmt) => {
                self.visit_expr(&assert_stmt.test);
                if let Some(msg) = &assert_stmt.msg {
                    self.visit_expr(msg);
                }
            }
            Stmt::If(if_stmt) => {
                self.visit_expr(&if_stmt.test);
                self.visit_suite(&if_stmt.body);
                for clause in &if_stmt.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.visit_expr(test);
                    }
                    self.visit_suite(&clause.body);
                }
            }
            Stmt::For(for_stmt) => {
                self.visit_expr(&for_stmt.iter);
                let pushed_orm_var = if let Expr::Name(target_name) = for_stmt.target.as_ref()
                    && let Some(is_eager) = self.classify_orm_iterable(&for_stmt.iter)
                {
                    self.orm_loop_iter_vars
                        .push((target_name.id.to_string(), is_eager));
                    true
                } else {
                    false
                };
                self.scope.enter_loop();
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
                self.scope.exit_loop();
                if pushed_orm_var {
                    self.orm_loop_iter_vars.pop();
                }
            }
            Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.scope.enter_loop();
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
                self.scope.exit_loop();
            }
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    self.visit_expr(&item.context_expr);
                }
                self.visit_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                self.visit_suite(&try_stmt.body);
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
                    self.visit_suite(&h.body);
                }
                self.visit_suite(&try_stmt.orelse);
                self.visit_suite(&try_stmt.finalbody);
            }
            Stmt::Match(match_stmt) => {
                self.visit_expr(&match_stmt.subject);
                for case in &match_stmt.cases {
                    if let Some(guard) = &case.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_suite(&case.body);
                }
            }
            _ => {}
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

        let saved_eager_vars = std::mem::take(&mut self.eager_query_vars);
        let saved_orm_colls = std::mem::take(&mut self.orm_collection_vars);
        let saved_orm_loop_vars = std::mem::take(&mut self.orm_loop_iter_vars);
        let saved_scope = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        self.visit_suite(&func_def.body);
        self.scope.exit_function(saved_scope);
        self.orm_loop_iter_vars = saved_orm_loop_vars;
        self.orm_collection_vars = saved_orm_colls;
        self.eager_query_vars = saved_eager_vars;
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses Python expression nodes for ORM call and attribute inspection"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                self.check_orm_query_in_loop(call, &callee);
                self.check_orm_relationship_call_in_loop(call);
                self.visit_expr(&call.func);
                for arg in &call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.visit_expr(&kw.value);
                }
            }
            Expr::Attribute(attr) => {
                self.check_lazy_orm_relationship_attr_in_loop(attr);
                self.visit_expr(&attr.value);
            }
            Expr::Await(aw) => self.visit_expr(&aw.value),
            Expr::Yield(y) => {
                if let Some(v) = &y.value {
                    self.visit_expr(v);
                }
            }
            Expr::YieldFrom(yf) => self.visit_expr(&yf.value),
            Expr::BinOp(bin) => {
                self.visit_expr(&bin.left);
                self.visit_expr(&bin.right);
            }
            Expr::UnaryOp(un) => self.visit_expr(&un.operand),
            Expr::BoolOp(b) => {
                for v in &b.values {
                    self.visit_expr(v);
                }
            }
            Expr::Compare(cmp) => {
                for op_expr in &cmp.operands {
                    self.visit_expr(op_expr);
                }
            }
            Expr::Subscript(sub) => {
                self.visit_expr(&sub.value);
                self.visit_expr(&sub.slice);
            }
            Expr::If(if_expr) => {
                self.visit_expr(&if_expr.test);
                self.visit_expr(&if_expr.body);
                self.visit_expr(&if_expr.orelse);
            }
            Expr::List(l) => {
                for e in &l.elts {
                    self.visit_expr(e);
                }
            }
            Expr::Tuple(t) => {
                for e in &t.elts {
                    self.visit_expr(e);
                }
            }
            Expr::Set(s) => {
                for e in &s.elts {
                    self.visit_expr(e);
                }
            }
            Expr::Dict(d) => {
                for item in &d.items {
                    if let Some(k) = &item.key {
                        self.visit_expr(k);
                    }
                    self.visit_expr(&item.value);
                }
            }
            Expr::Named(n) => self.visit_expr(&n.value),
            _ => {}
        }
    }

    fn check_orm_query_in_loop(&mut self, call: &ExprCall, callee: &str) {
        if !self.scope.in_loop() || !is_orm_query_callee(callee) {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyOrmNoQueryInLoop,
            "pyOrmNoQueryInLoop",
            callee.to_string(),
            format!(
                "ORM query `{callee}(...)` is executed inside a loop (N+1 query); batch-fetch records before the loop or eager-load relationships."
            ),
        ));
    }

    fn record_orm_query_binding_from_assign(&mut self, assign: &StmtAssign) {
        let Some(Expr::Name(target)) = assign.targets.first() else {
            return;
        };
        let name = target.id.to_string();
        if expr_contains_eager_load(&assign.value, &self.eager_query_vars) {
            self.eager_query_vars.insert(name.clone());
        }
        if let Some(is_eager) = self.classify_orm_iterable(&assign.value) {
            self.orm_collection_vars.insert(name, is_eager);
        }
    }

    fn record_orm_query_binding_from_ann_assign(&mut self, ann_assign: &StmtAnnAssign) {
        let Expr::Name(target) = ann_assign.target.as_ref() else {
            return;
        };
        let Some(val) = &ann_assign.value else {
            return;
        };
        let name = target.id.to_string();
        if expr_contains_eager_load(val, &self.eager_query_vars) {
            self.eager_query_vars.insert(name.clone());
        }
        if let Some(is_eager) = self.classify_orm_iterable(val) {
            self.orm_collection_vars.insert(name, is_eager);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Matches Name, Await, and Call expressions representing ORM query iterables"
    )]
    fn classify_orm_iterable(&self, expr: &Expr) -> Option<bool> {
        match expr {
            Expr::Name(n) => self.orm_collection_vars.get(n.id.as_str()).copied(),
            Expr::Await(aw) => self.classify_orm_iterable(&aw.value),
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                if matches!(callee.as_str(), "list" | "tuple" | "set")
                    && let Some(first) = call.arguments.args.first()
                {
                    return self.classify_orm_iterable(first);
                }
                if is_orm_query_callee(&callee) || expr_contains_orm_query(expr) {
                    return Some(expr_contains_eager_load(expr, &self.eager_query_vars));
                }
                if let Expr::Attribute(attr) = call.func.as_ref()
                    && let Some(inner_eager) = self.classify_orm_iterable(&attr.value)
                {
                    return Some(
                        inner_eager || expr_contains_eager_load(expr, &self.eager_query_vars),
                    );
                }
                None
            }
            _ => None,
        }
    }

    fn is_unedited_lazy_orm_loop_var(&self, name: &str) -> bool {
        self.orm_loop_iter_vars
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .is_some_and(|(_, is_eager)| !*is_eager)
    }

    fn is_inside_reported_lazy_rel(&self, span: ByteSpan) -> bool {
        self.reported_lazy_rel_spans
            .iter()
            .any(|s| span.start >= s.start && span.end <= s.end)
    }

    fn check_orm_relationship_call_in_loop(&mut self, call: &ExprCall) {
        if !self.scope.in_loop() {
            return;
        }
        let Expr::Attribute(method_attr) = call.func.as_ref() else {
            return;
        };
        let method = method_attr.attr.as_str();
        if !matches!(
            method,
            "all" | "filter" | "exclude" | "count" | "first" | "last" | "exists" | "get"
        ) {
            return;
        }
        let Expr::Attribute(rel_attr) = method_attr.value.as_ref() else {
            return;
        };
        let Expr::Name(base_var) = rel_attr.value.as_ref() else {
            return;
        };
        if !self.is_unedited_lazy_orm_loop_var(base_var.id.as_str()) {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        if self.is_inside_reported_lazy_rel(span) {
            return;
        }
        self.reported_lazy_rel_spans.push(span);
        let target = format!("{}.{}.{method}", base_var.id, rel_attr.attr);
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyOrmNoQueryInLoop,
            "pyOrmNoQueryInLoop",
            target.clone(),
            format!(
                "Lazy ORM relationship query `{target}(...)` inside a loop triggers an N+1 query; eager-load `{}` before iterating.",
                rel_attr.attr
            ),
        ));
    }

    fn check_lazy_orm_relationship_attr_in_loop(&mut self, attr: &ExprAttribute) {
        if !self.scope.in_loop() {
            return;
        }
        let span = text_range_to_byte_span(attr.range());
        if self.is_inside_reported_lazy_rel(span) {
            return;
        }

        // Case 1: Chained attribute access `user.profile.bio` (`<loop_var>.<rel>.<field>`)
        if let Expr::Attribute(inner_attr) = attr.value.as_ref()
            && let Expr::Name(base_var) = inner_attr.value.as_ref()
            && self.is_unedited_lazy_orm_loop_var(base_var.id.as_str())
        {
            let rel_name = inner_attr.attr.as_str();
            let leaf_name = attr.attr.as_str();
            if !is_non_relationship_method_or_attr(rel_name)
                && !is_non_relationship_method_or_attr(leaf_name)
            {
                self.reported_lazy_rel_spans.push(span);
                let target = format!("{}.{rel_name}.{leaf_name}", base_var.id);
                self.out.push(build_py_diagnostic(
                    self.path,
                    self.line_starts,
                    span,
                    self.scope.current_subject(),
                    RuleId::PyOrmNoQueryInLoop,
                    "pyOrmNoQueryInLoop",
                    target.clone(),
                    format!(
                        "Lazy ORM relationship access `{target}` inside a loop triggers an N+1 query; eager-load `{rel_name}` with `selectinload` / `joinedload` / `select_related`.",
                    ),
                ));
                return;
            }
        }

        // Case 2: Direct collection relationship access `user.orders` (`<loop_var>.<plural_rel>`)
        if let Expr::Name(base_var) = attr.value.as_ref()
            && self.is_unedited_lazy_orm_loop_var(base_var.id.as_str())
        {
            let rel_name = attr.attr.as_str();
            if is_plural_relationship_attr(rel_name) {
                self.reported_lazy_rel_spans.push(span);
                let target = format!("{}.{rel_name}", base_var.id);
                self.out.push(build_py_diagnostic(
                    self.path,
                    self.line_starts,
                    span,
                    self.scope.current_subject(),
                    RuleId::PyOrmNoQueryInLoop,
                    "pyOrmNoQueryInLoop",
                    target.clone(),
                    format!(
                        "Lazy ORM relationship access `{target}` inside a loop triggers an N+1 query; eager-load `{rel_name}` with `selectinload` / `prefetch_related`.",
                    ),
                ));
            }
        }
    }
}

fn is_orm_query_callee(callee: &str) -> bool {
    let Some((recv, method)) = callee.rsplit_once('.') else {
        return false;
    };

    // Django ORM: `<Model>.objects.<method>(...)`
    if (recv == "objects" || recv.ends_with(".objects"))
        && matches!(
            method,
            "filter"
                | "get"
                | "all"
                | "exclude"
                | "first"
                | "last"
                | "count"
                | "exists"
                | "create"
                | "get_or_create"
                | "update_or_create"
                | "values"
                | "values_list"
                | "annotate"
                | "aggregate"
                | "raw"
                | "select_related"
                | "prefetch_related"
        )
    {
        return true;
    }

    // SQLAlchemy: `session.query(...)`, `session.execute(...)`, `session.scalars(...)`, `session.get(...)`, `db.query(...)`, `db.execute(...)`
    let recv_lower = recv.to_ascii_lowercase();
    let is_session_or_db = matches!(
        recv_lower.as_str(),
        "session"
            | "db"
            | "async_session"
            | "db_session"
            | "self.session"
            | "self.db"
            | "cls.session"
            | "cls.db"
    ) || recv_lower.ends_with("_session")
        || recv_lower.ends_with("_db")
        || recv_lower.ends_with(".session")
        || recv_lower.ends_with(".db");

    is_session_or_db
        && matches!(
            method,
            "query" | "execute" | "scalars" | "scalar" | "get" | "scalar_one" | "scalar_one_or_none"
        )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Walks call and attribute chains to detect ORM queries"
)]
fn expr_contains_orm_query(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            if is_orm_query_callee(&callee) {
                return true;
            }
            expr_contains_orm_query(&call.func)
                || call.arguments.args.iter().any(expr_contains_orm_query)
        }
        Expr::Attribute(attr) => expr_contains_orm_query(&attr.value),
        Expr::Await(aw) => expr_contains_orm_query(&aw.value),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Walks call, attribute, and identifier nodes to detect eager-loading options"
)]
fn expr_contains_eager_load(expr: &Expr, eager_query_vars: &HashSet<String>) -> bool {
    match expr {
        Expr::Name(n) => eager_query_vars.contains(n.id.as_str()),
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            let tail = callee.rsplit('.').next().unwrap_or(callee.as_str());
            if matches!(
                tail,
                "selectinload"
                    | "joinedload"
                    | "subqueryload"
                    | "immediateload"
                    | "contains_eager"
                    | "select_related"
                    | "prefetch_related"
            ) {
                return true;
            }
            expr_contains_eager_load(&call.func, eager_query_vars)
                || call
                    .arguments
                    .args
                    .iter()
                    .any(|a| expr_contains_eager_load(a, eager_query_vars))
                || call
                    .arguments
                    .keywords
                    .iter()
                    .any(|kw| expr_contains_eager_load(&kw.value, eager_query_vars))
        }
        Expr::Attribute(attr) => expr_contains_eager_load(&attr.value, eager_query_vars),
        Expr::Await(aw) => expr_contains_eager_load(&aw.value, eager_query_vars),
        Expr::List(l) => l
            .elts
            .iter()
            .any(|e| expr_contains_eager_load(e, eager_query_vars)),
        Expr::Tuple(t) => t
            .elts
            .iter()
            .any(|e| expr_contains_eager_load(e, eager_query_vars)),
        _ => false,
    }
}

fn is_non_relationship_method_or_attr(name: &str) -> bool {
    name.starts_with('_')
        || matches!(
            name,
            "id"
                | "pk"
                | "uuid"
                | "name"
                | "title"
                | "email"
                | "username"
                | "slug"
                | "status"
                | "created_at"
                | "updated_at"
                | "deleted_at"
                | "is_active"
                | "is_staff"
                | "is_superuser"
                | "strip"
                | "lower"
                | "upper"
                | "split"
                | "replace"
                | "startswith"
                | "endswith"
                | "encode"
                | "decode"
                | "isoformat"
                | "strftime"
                | "date"
                | "time"
                | "timestamp"
                | "keys"
                | "values"
                | "items"
                | "get"
                | "model_dump"
                | "dict"
                | "json"
        )
}

fn is_plural_relationship_attr(name: &str) -> bool {
    matches!(
        name,
        "orders"
            | "items"
            | "posts"
            | "comments"
            | "tags"
            | "roles"
            | "permissions"
            | "members"
            | "users"
            | "groups"
            | "children"
            | "entries"
            | "invoices"
            | "payments"
            | "subscriptions"
            | "notifications"
            | "messages"
            | "reviews"
            | "attachments"
            | "addresses"
            | "accounts"
            | "projects"
            | "tasks"
            | "events"
            | "logs"
            | "records"
            | "lines"
            | "transactions"
    ) || name.ends_with("_set")
}
