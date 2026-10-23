//! Single-pass Python detectors for Ticket #14:
//! - `py-pydantic-prefer-default-factory` (`Capability::Pydantic`, `Autofix`)
//! - `py-fastapi-require-response-model` (`Capability::FastApi`)
//! - `py-fastapi-mutating-route-requires-auth` (`Capability::FastApi`)
//! - `py-orm-no-query-in-loop` (`Capability::SqlAlchemy` / `Capability::Django`)
//! - `py-security-no-raw-sql-interpolation` (`Capability::Python`)
//! - `py-security-no-unsafe-deserialization-or-shell` (`Capability::Python`, `Autofix`)

use std::{collections::HashSet, path::Path};

use dotore_core::{
    AutofixPatch, ByteEdit, ByteSpan, Diagnostic, RuleId, loc_from_line_starts,
};
use ruff_python_ast::{
    Decorator, Expr, ExprCall, Keyword, Operator, ParameterWithDefault, Stmt, StmtAnnAssign,
    StmtAssign, StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

pub(crate) fn extract_web_orm_security_diagnostics(
    path: &Path,
    source: &str,
    _lines: &[&str],
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if is_stub_file {
        return;
    }
    let mut visitor = WebOrmSecurityExtractor {
        path,
        source,
        line_starts,
        out,
        class_stack: Vec::new(),
        subject_stack: Vec::new(),
        authenticated_routers: HashSet::new(),
        loop_depth: 0,
        interpolated_sql_vars: HashSet::new(),
    };
    visitor.visit_suite(suite);
}

#[derive(Debug, Clone)]
struct ClassContext {
    name: String,
    is_pydantic_or_dataclass: bool,
}

struct WebOrmSecurityExtractor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    class_stack: Vec<ClassContext>,
    subject_stack: Vec<String>,
    authenticated_routers: HashSet<String>,
    loop_depth: usize,
    interpolated_sql_vars: HashSet<String>,
}

impl<'a> WebOrmSecurityExtractor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python statement variants for web, ORM, and security rules"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::AnnAssign(ann_assign) => {
                self.record_router_auth_from_ann_assign(ann_assign);
                self.record_interpolated_sql_from_ann_assign(ann_assign);
                let handled_pydantic = self.check_class_ann_assign_pydantic(ann_assign);
                self.visit_expr(&ann_assign.annotation);
                if !handled_pydantic && let Some(val) = &ann_assign.value {
                    self.visit_expr(val);
                }
            }
            Stmt::Assign(assign) => {
                self.record_router_auth_from_assign(assign);
                self.record_interpolated_sql_from_assign(assign);
                let handled_pydantic = self.check_class_assign_pydantic(assign);
                if !handled_pydantic {
                    self.visit_expr(&assign.value);
                }
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
                self.loop_depth += 1;
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
                self.loop_depth -= 1;
            }
            Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.loop_depth += 1;
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
                self.loop_depth -= 1;
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
        let class_name = class_def.name.to_string();
        let qualified = if let Some(parent) = self.class_stack.last() {
            format!("{}.{class_name}", parent.name)
        } else {
            class_name.clone()
        };
        let is_pydantic_or_dataclass = is_pydantic_or_dataclass_model(class_def);
        self.class_stack.push(ClassContext {
            name: class_name,
            is_pydantic_or_dataclass,
        });
        self.subject_stack.push(qualified);
        self.visit_suite(&class_def.body);
        self.subject_stack.pop();
        self.class_stack.pop();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        let fn_name = func_def.name.to_string();
        let subject_name = if let Some(cls) = self.class_stack.last() {
            format!("{}.{fn_name}", cls.name)
        } else {
            fn_name
        };

        self.check_fastapi_response_model(func_def, &subject_name);
        self.check_fastapi_mutating_route_auth(func_def, &subject_name);
        for dec in &func_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        if let Some(ret) = &func_def.returns {
            self.visit_expr(ret);
        }

        let saved_classes = std::mem::take(&mut self.class_stack);
        let saved_loop_depth = std::mem::replace(&mut self.loop_depth, 0);
        let saved_sql_vars = self.interpolated_sql_vars.clone();
        self.subject_stack.push(subject_name);
        self.visit_suite(&func_def.body);
        self.subject_stack.pop();
        self.interpolated_sql_vars = saved_sql_vars;
        self.loop_depth = saved_loop_depth;
        self.class_stack = saved_classes;
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses Python expression nodes for call and subscript inspection"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                if is_pydantic_field_callee(&callee) {
                    self.check_pydantic_field_call(call, None);
                }
                self.check_orm_query_in_loop(call, &callee);
                self.check_raw_sql_interpolation(call, &callee);
                self.check_unsafe_deserialization_or_shell(call, &callee);
                self.visit_expr(&call.func);
                for arg in &call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.visit_expr(&kw.value);
                }
            }
            Expr::Attribute(attr) => self.visit_expr(&attr.value),
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

    fn check_class_ann_assign_pydantic(&mut self, ann_assign: &StmtAnnAssign) -> bool {
        let Some(cls) = self.class_stack.last() else {
            return false;
        };
        if annotation_is_classvar_or_final(&ann_assign.annotation) {
            return true;
        }
        let Some(val) = ann_assign.value.as_deref() else {
            return false;
        };
        let field_name = if let Expr::Name(n) = ann_assign.target.as_ref() {
            n.id.as_str()
        } else {
            return false;
        };
        if is_ignored_model_attr_name(field_name) {
            return true;
        }

        if let Expr::Call(call) = val {
            let callee = callee_qualified_name(&call.func);
            if is_pydantic_field_callee(&callee) {
                return self.check_pydantic_field_call(call, Some(field_name));
            }
        }

        if !cls.is_pydantic_or_dataclass {
            return false;
        }

        if let Some(factory_expr) = default_factory_for_expr(self.source, val) {
            let val_span = text_range_to_byte_span(val.range());
            let stmt_span = text_range_to_byte_span(ann_assign.range());
            let loc = loc_from_line_starts(self.line_starts, stmt_span.start);
            let val_text = slice_source(self.source, val_span);
            let replacement = format!("Field(default_factory={factory_expr})");
            let meta = RuleId::PyPydanticPreferDefaultFactory.metadata();
            self.out.push(Diagnostic {
                file: self.path.to_path_buf(),
                subject_name: self.subject_stack.last().cloned(),
                rule: RuleId::PyPydanticPreferDefaultFactory,
                category: meta.category,
                severity: meta.default_severity,
                message_id: "pyPydanticPreferDefaultFactory",
                tier: meta.default_tier,
                target_name: field_name.to_string(),
                message: format!(
                    "Field `{field_name}` uses mutable or import-time evaluated default `{val_text}`; use `{replacement}` so each model instance receives a fresh value."
                ),
                docs_url: meta.docs_url,
                loc,
                span: stmt_span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: Some(AutofixPatch {
                    description: format!("Replace `{val_text}` with `{replacement}`"),
                    edits: vec![ByteEdit {
                        file: None,
                        span: val_span,
                        replacement,
                    }],
                }),
            });
            return true;
        }
        false
    }

    fn check_class_assign_pydantic(&mut self, assign: &StmtAssign) -> bool {
        let Some(cls) = self.class_stack.last() else {
            return false;
        };
        let Some(Expr::Name(target_name)) = assign.targets.first() else {
            return false;
        };
        let field_name = target_name.id.as_str();
        if is_ignored_model_attr_name(field_name) || is_upper_snake_case(field_name) {
            return false;
        }
        if let Expr::Call(call) = assign.value.as_ref() {
            let callee = callee_qualified_name(&call.func);
            if is_pydantic_field_callee(&callee) {
                return self.check_pydantic_field_call(call, Some(field_name));
            }
        }
        if !cls.is_pydantic_or_dataclass {
            return false;
        }
        if let Some(factory_expr) = default_factory_for_expr(self.source, &assign.value) {
            let val_span = text_range_to_byte_span(assign.value.range());
            let stmt_span = text_range_to_byte_span(assign.range());
            let loc = loc_from_line_starts(self.line_starts, stmt_span.start);
            let val_text = slice_source(self.source, val_span);
            let replacement = format!("Field(default_factory={factory_expr})");
            let meta = RuleId::PyPydanticPreferDefaultFactory.metadata();
            self.out.push(Diagnostic {
                file: self.path.to_path_buf(),
                subject_name: self.subject_stack.last().cloned(),
                rule: RuleId::PyPydanticPreferDefaultFactory,
                category: meta.category,
                severity: meta.default_severity,
                message_id: "pyPydanticPreferDefaultFactory",
                tier: meta.default_tier,
                target_name: field_name.to_string(),
                message: format!(
                    "Field `{field_name}` uses mutable or import-time evaluated default `{val_text}`; use `{replacement}` so each model instance receives a fresh value."
                ),
                docs_url: meta.docs_url,
                loc,
                span: stmt_span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: Some(AutofixPatch {
                    description: format!("Replace `{val_text}` with `{replacement}`"),
                    edits: vec![ByteEdit {
                        file: None,
                        span: val_span,
                        replacement,
                    }],
                }),
            });
            return true;
        }
        false
    }

    fn check_pydantic_field_call(&mut self, call: &ExprCall, field_name: Option<&str>) -> bool {
        let has_default_factory = call
            .arguments
            .keywords
            .iter()
            .any(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "default_factory"));
        if has_default_factory {
            return true;
        }

        // Check `default=...` keyword argument first
        let default_kw: Option<&Keyword> = call
            .arguments
            .keywords
            .iter()
            .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "default"));

        if let Some(kw) = default_kw {
            if let Some(factory_expr) = default_factory_for_expr(self.source, &kw.value) {
                let kw_span = text_range_to_byte_span(kw.range());
                let call_span = text_range_to_byte_span(call.range());
                let loc = loc_from_line_starts(self.line_starts, call_span.start);
                let val_text = slice_source(self.source, text_range_to_byte_span(kw.value.range()));
                let replacement = format!("default_factory={factory_expr}");
                let target = field_name.unwrap_or("Field").to_string();
                let meta = RuleId::PyPydanticPreferDefaultFactory.metadata();
                self.out.push(Diagnostic {
                    file: self.path.to_path_buf(),
                    subject_name: self.subject_stack.last().cloned(),
                    rule: RuleId::PyPydanticPreferDefaultFactory,
                    category: meta.category,
                    severity: meta.default_severity,
                    message_id: "pyPydanticPreferDefaultFactory",
                    tier: meta.default_tier,
                    target_name: target.clone(),
                    message: format!(
                        "`Field(default={val_text})` on `{target}` evaluates once at class definition time; use `Field({replacement})` instead."
                    ),
                    docs_url: meta.docs_url,
                    loc,
                    span: call_span,
                    cascade_steps: Vec::new(),
                    caller_sites: Vec::new(),
                    autofix: Some(AutofixPatch {
                        description: format!(
                            "Rewrite `default={val_text}` to `{replacement}` in `Field(...)`"
                        ),
                        edits: vec![ByteEdit {
                            file: None,
                            span: kw_span,
                            replacement,
                        }],
                    }),
                });
                return true;
            }
            return false;
        }

        // Check positional `Field([...])` first argument
        if let Some(first_arg) = call.arguments.args.first()
            && let Some(factory_expr) = default_factory_for_expr(self.source, first_arg)
        {
            let arg_span = text_range_to_byte_span(first_arg.range());
            let call_span = text_range_to_byte_span(call.range());
            let loc = loc_from_line_starts(self.line_starts, call_span.start);
            let val_text = slice_source(self.source, arg_span);
            let replacement = format!("default_factory={factory_expr}");
            let target = field_name.unwrap_or("Field").to_string();
            let meta = RuleId::PyPydanticPreferDefaultFactory.metadata();
            self.out.push(Diagnostic {
                file: self.path.to_path_buf(),
                subject_name: self.subject_stack.last().cloned(),
                rule: RuleId::PyPydanticPreferDefaultFactory,
                category: meta.category,
                severity: meta.default_severity,
                message_id: "pyPydanticPreferDefaultFactory",
                tier: meta.default_tier,
                target_name: target.clone(),
                message: format!(
                    "`Field({val_text})` on `{target}` evaluates once at class definition time; use `Field({replacement})` instead."
                ),
                docs_url: meta.docs_url,
                loc,
                span: call_span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: Some(AutofixPatch {
                    description: format!(
                        "Rewrite `{val_text}` to `{replacement}` in `Field(...)`"
                    ),
                    edits: vec![ByteEdit {
                        file: None,
                        span: arg_span,
                        replacement,
                    }],
                }),
            });
            return true;
        }

        false
    }

    fn check_fastapi_response_model(&mut self, func_def: &StmtFunctionDef, subject_name: &str) {
        let Some(route_dec) = func_def
            .decorator_list
            .iter()
            .find_map(extract_fastapi_route_decorator)
        else {
            return;
        };

        if route_dec.has_response_model || route_dec.is_no_content_or_hidden {
            return;
        }

        let missing_or_untyped_return = match func_def.returns.as_deref() {
            None => true,
            Some(ret_expr) => is_untyped_fastapi_return_annotation(ret_expr),
        };
        if !missing_or_untyped_return {
            return;
        }

        let span = function_def_header_span(self.source, func_def);
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let fn_name = func_def.name.as_str();
        let meta = RuleId::PyFastapiRequireResponseModel.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: Some(subject_name.to_string()),
            rule: RuleId::PyFastapiRequireResponseModel,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyFastapiRequireResponseModel",
            tier: meta.default_tier,
            target_name: fn_name.to_string(),
            message: format!(
                "FastAPI route `{fn_name}` (`@{}`) lacks both `response_model=...` and a typed return model annotation.",
                route_dec.decorator_callee
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn record_router_auth_from_assign(&mut self, assign: &StmtAssign) {
        let Some(Expr::Name(target)) = assign.targets.first() else {
            return;
        };
        if is_authenticated_router_constructor(&assign.value) {
            self.authenticated_routers.insert(target.id.to_string());
        }
    }

    fn record_router_auth_from_ann_assign(&mut self, ann_assign: &StmtAnnAssign) {
        let Expr::Name(target) = ann_assign.target.as_ref() else {
            return;
        };
        if let Some(val) = &ann_assign.value
            && is_authenticated_router_constructor(val)
        {
            self.authenticated_routers.insert(target.id.to_string());
        }
    }

    fn check_fastapi_mutating_route_auth(&mut self, func_def: &StmtFunctionDef, subject_name: &str) {
        let Some(route_dec) = func_def
            .decorator_list
            .iter()
            .find_map(extract_fastapi_route_decorator)
        else {
            return;
        };

        if !matches!(route_dec.method, "post" | "put" | "patch" | "delete") {
            return;
        }

        if route_dec.has_decorator_auth_dep
            || self
                .authenticated_routers
                .contains(&route_dec.receiver_name)
        {
            return;
        }

        let fn_name = func_def.name.as_str();
        if is_public_fastapi_endpoint(route_dec.path_arg, fn_name) {
            return;
        }

        let params: Vec<&ParameterWithDefault> = func_def
            .parameters
            .posonlyargs
            .iter()
            .chain(func_def.parameters.args.iter())
            .chain(func_def.parameters.kwonlyargs.iter())
            .collect();

        if params.into_iter().any(parameter_satisfies_fastapi_auth) {
            return;
        }

        let span = function_def_header_span(self.source, func_def);
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyFastapiMutatingRouteRequiresAuth.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: Some(subject_name.to_string()),
            rule: RuleId::PyFastapiMutatingRouteRequiresAuth,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyFastapiMutatingRouteRequiresAuth",
            tier: meta.default_tier,
            target_name: fn_name.to_string(),
            message: format!(
                "State-mutating FastAPI route `{fn_name}` (`@{}`) lacks an authentication or security dependency (`Depends(...)` / `Security(...)`).",
                route_dec.decorator_callee
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn check_orm_query_in_loop(&mut self, call: &ExprCall, callee: &str) {
        if self.loop_depth == 0 || !is_orm_query_callee(callee) {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyOrmNoQueryInLoop.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyOrmNoQueryInLoop,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyOrmNoQueryInLoop",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "ORM query `{callee}(...)` is executed inside a loop (N+1 query); batch-fetch records before the loop or eager-load relationships."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
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
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PySecurityNoRawSqlInterpolation.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PySecurityNoRawSqlInterpolation,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pySecurityNoRawSqlInterpolation",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "SQL execution sink `{callee}(...)` receives a dynamically interpolated SQL string; use parameterized bind parameters instead."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
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
                let arg_text = slice_source(self.source, text_range_to_byte_span(first_arg.range()));
                let replacement = format!("{yaml_recv}.safe_load({arg_text})");
                AutofixPatch {
                    description: format!("Rewrite `{callee}(...)` to `{replacement}`"),
                    edits: vec![ByteEdit {
                        file: None,
                        span,
                        replacement,
                    }],
                }
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
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PySecurityNoUnsafeDeserializationOrShell.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PySecurityNoUnsafeDeserializationOrShell,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pySecurityNoUnsafeDeserializationOrShell",
            tier: meta.default_tier,
            target_name,
            message,
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix,
        });
    }
}

fn is_pydantic_or_dataclass_model(class_def: &StmtClassDef) -> bool {
    if matches!(class_def.name.as_str(), "Config" | "Meta") {
        return false;
    }
    let has_model_base = class_def.bases().iter().any(|base| {
        let name = base_type_name(base);
        let tail = name.rsplit('.').next().unwrap_or(&name);
        matches!(
            tail,
            "BaseModel"
                | "SQLModel"
                | "BaseSettings"
                | "RootModel"
                | "GenericModel"
                | "Schema"
                | " APIModel"
                | "APIModel"
        ) || tail.ends_with("Model")
            || tail.ends_with("Schema")
            || tail.ends_with("Settings")
    });
    if has_model_base {
        return true;
    }
    class_def.decorator_list.iter().any(is_dataclass_decorator)
}

fn is_dataclass_decorator(dec: &Decorator) -> bool {
    let expr = if let Expr::Call(c) = &dec.expression {
        c.func.as_ref()
    } else {
        &dec.expression
    };
    let name = callee_qualified_name(expr);
    let tail = name.rsplit('.').next().unwrap_or(&name);
    tail == "dataclass"
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts base class name from Name, Attribute, or Subscript"
)]
fn base_type_name(expr: &Expr) -> String {
    match expr {
        Expr::Name(_) | Expr::Attribute(_) => callee_qualified_name(expr),
        Expr::Subscript(sub) => base_type_name(&sub.value),
        _ => String::new(),
    }
}

fn is_pydantic_field_callee(callee: &str) -> bool {
    matches!(
        callee,
        "Field" | "pydantic.Field" | "sqlmodel.Field" | "field" | "dataclasses.field"
    )
}

fn is_ignored_model_attr_name(name: &str) -> bool {
    name.starts_with('_')
        || matches!(
            name,
            "model_config" | "Config" | "Meta" | "objects"
        )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks ClassVar and Final annotations across Name, Attribute, and Subscript"
)]
fn annotation_is_classvar_or_final(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "ClassVar" | "Final"),
        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "ClassVar" | "Final"),
        Expr::Subscript(sub) => annotation_is_classvar_or_final(&sub.value),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches mutable literals, collection constructors, and runtime clock/UUID calls"
)]
fn default_factory_for_expr(source: &str, expr: &Expr) -> Option<String> {
    match expr {
        Expr::List(list) => {
            if list.elts.is_empty() {
                Some("list".to_string())
            } else {
                let raw = slice_source(source, text_range_to_byte_span(expr.range()));
                Some(format!("lambda: {raw}"))
            }
        }
        Expr::Dict(dict) => {
            if dict.items.is_empty() {
                Some("dict".to_string())
            } else {
                let raw = slice_source(source, text_range_to_byte_span(expr.range()));
                Some(format!("lambda: {raw}"))
            }
        }
        Expr::Set(_) | Expr::ListComp(_) | Expr::DictComp(_) | Expr::SetComp(_) => {
            let raw = slice_source(source, text_range_to_byte_span(expr.range()));
            Some(format!("lambda: {raw}"))
        }
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            let no_args = call.arguments.args.is_empty() && call.arguments.keywords.is_empty();
            match callee.as_str() {
                "list" if no_args => Some("list".to_string()),
                "dict" if no_args => Some("dict".to_string()),
                "set" if no_args => Some("set".to_string()),
                "list"
                | "dict"
                | "set"
                | "bytearray"
                | "deque"
                | "collections.deque"
                | "defaultdict"
                | "collections.defaultdict"
                | "OrderedDict"
                | "collections.OrderedDict"
                | "Counter"
                | "collections.Counter"
                | "datetime.now"
                | "datetime.utcnow"
                | "dt.datetime.now"
                | "dt.datetime.utcnow"
                | "date.today"
                | "datetime.date.today"
                | "time.time"
                | "time.monotonic"
                | "uuid4"
                | "uuid.uuid4"
                | "uuid1"
                | "uuid.uuid1"
                | "secrets.token_hex"
                | "secrets.token_urlsafe"
                | "secrets.token_bytes"
                | "token_hex"
                | "token_urlsafe" => {
                    let raw = slice_source(source, text_range_to_byte_span(expr.range()));
                    Some(format!("lambda: {raw}"))
                }
                _ => {
                    if callee.ends_with(".now")
                        || callee.ends_with(".utcnow")
                        || callee.ends_with(".today")
                        || callee.ends_with(".uuid4")
                        || callee.ends_with(".uuid1")
                    {
                        let raw = slice_source(source, text_range_to_byte_span(expr.range()));
                        Some(format!("lambda: {raw}"))
                    } else {
                        None
                    }
                }
            }
        }
        _ => None,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only Name and Attribute expressions form dotted callee names"
)]
fn callee_qualified_name(func: &Expr) -> String {
    match func {
        Expr::Name(n) => n.id.to_string(),
        Expr::Attribute(attr) => {
            let prefix = callee_qualified_name(&attr.value);
            if prefix.is_empty() {
                attr.attr.to_string()
            } else {
                format!("{prefix}.{}", attr.attr)
            }
        }
        _ => String::new(),
    }
}

fn text_range_to_byte_span(range: ruff_text_size::TextRange) -> ByteSpan {
    ByteSpan {
        start: range.start().to_u32(),
        end: range.end().to_u32(),
    }
}

fn slice_source(source: &str, span: ByteSpan) -> &str {
    let start = (span.start as usize).min(source.len());
    let end = (span.end as usize).min(source.len());
    if start <= end && source.is_char_boundary(start) && source.is_char_boundary(end) {
        &source[start..end]
    } else {
        ""
    }
}

fn is_upper_snake_case(name: &str) -> bool {
    let trimmed = name.trim_start_matches('_');
    !trimmed.is_empty()
        && trimmed.chars().any(|c| c.is_ascii_uppercase())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

struct FastapiRouteDecorator<'a> {
    decorator_callee: String,
    method: &'a str,
    path_arg: Option<&'a str>,
    has_response_model: bool,
    is_no_content_or_hidden: bool,
    has_decorator_auth_dep: bool,
    receiver_name: String,
}

fn extract_fastapi_route_decorator(dec: &Decorator) -> Option<FastapiRouteDecorator<'_>> {
    let Expr::Call(call) = &dec.expression else {
        return None;
    };
    let Expr::Attribute(attr) = call.func.as_ref() else {
        return None;
    };
    let method = attr.attr.as_str();
    if !matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "options" | "head" | "trace" | "api_route"
    ) {
        return None;
    }
    let receiver_name = callee_qualified_name(&attr.value);
    if !is_fastapi_router_or_app_receiver(&receiver_name) {
        return None;
    }
    let decorator_callee = format!("{receiver_name}.{method}");
    let path_arg = call.arguments.args.first().and_then(|arg| {
        if let Expr::StringLiteral(s) = arg {
            Some(s.value.to_str())
        } else {
            None
        }
    });

    let has_response_model = call.arguments.keywords.iter().any(|kw| {
        kw.arg.as_ref().is_some_and(|a| a.as_str() == "response_model")
            && !matches!(kw.value, Expr::NoneLiteral(_))
    });

    let is_no_content_or_hidden = call.arguments.keywords.iter().any(|kw| {
        let Some(k) = kw.arg.as_ref() else {
            return false;
        };
        if k.as_str() == "include_in_schema"
            && let Expr::BooleanLiteral(b) = &kw.value
        {
            return !b.value;
        }
        if k.as_str() == "status_code" {
            if let Expr::NumberLiteral(num) = &kw.value
                && let ruff_python_ast::Number::Int(i) = &num.value
            {
                return i.as_u64() == Some(204);
            }
            let name = callee_qualified_name(&kw.value);
            if name.contains("204") {
                return true;
            }
        }
        false
    });

    let has_decorator_auth_dep = call.arguments.keywords.iter().any(|kw| {
        kw.arg.as_ref().is_some_and(|a| a.as_str() == "dependencies")
            && expr_contains_auth_dependency(&kw.value)
    });

    Some(FastapiRouteDecorator {
        decorator_callee,
        method,
        path_arg,
        has_response_model,
        is_no_content_or_hidden,
        has_decorator_auth_dep,
        receiver_name,
    })
}

fn is_fastapi_router_or_app_receiver(recv: &str) -> bool {
    if recv.is_empty() {
        return false;
    }
    let lower = recv.to_ascii_lowercase();
    matches!(lower.as_str(), "app" | "router" | "api" | "v1" | "v2")
        || lower.ends_with("app")
        || lower.ends_with("router")
        || lower.ends_with("_api")
        || lower.starts_with("app.")
        || lower.starts_with("router.")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether a FastAPI return annotation is untyped dict, Dict, or Any"
)]
fn is_untyped_fastapi_return_annotation(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "dict" | "Dict" | "Any" | "object"),
        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "Dict" | "Any"),
        Expr::Subscript(sub) => {
            let base = callee_qualified_name(&sub.value);
            let base_tail = base.rsplit('.').next().unwrap_or(&base);
            if matches!(base_tail, "dict" | "Dict") {
                if let Expr::Tuple(t) = sub.slice.as_ref()
                    && let Some(val_ty) = t.elts.get(1)
                {
                    return is_any_or_object_type(val_ty);
                }
                return false;
            }
            if matches!(base_tail, "list" | "List" | "Sequence") {
                return is_untyped_fastapi_return_annotation(&sub.slice);
            }
            false
        }
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches Any or object type expressions"
)]
fn is_any_or_object_type(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "Any" | "object"),
        Expr::Attribute(attr) => attr.attr.as_str() == "Any",
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches Depends/Security calls inside decorator dependencies lists/tuples"
)]
fn expr_contains_auth_dependency(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            let tail = callee.rsplit('.').next().unwrap_or(&callee);
            if matches!(tail, "Depends" | "Security") {
                return true;
            }
            call.arguments.args.iter().any(expr_contains_auth_dependency)
                || call
                    .arguments
                    .keywords
                    .iter()
                    .any(|kw| expr_contains_auth_dependency(&kw.value))
        }
        Expr::List(l) => l.elts.iter().any(expr_contains_auth_dependency),
        Expr::Tuple(t) => t.elts.iter().any(expr_contains_auth_dependency),
        _ => false,
    }
}

fn is_authenticated_router_constructor(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let callee = callee_qualified_name(&call.func);
    let tail = callee.rsplit('.').next().unwrap_or(&callee);
    if !matches!(tail, "APIRouter" | "FastAPI") {
        return false;
    }
    call.arguments.keywords.iter().any(|kw| {
        kw.arg.as_ref().is_some_and(|a| a.as_str() == "dependencies")
            && expr_contains_auth_dependency(&kw.value)
    })
}

fn is_public_fastapi_endpoint(path_arg: Option<&str>, fn_name: &str) -> bool {
    let fn_lower = fn_name.to_ascii_lowercase();
    if matches!(
        fn_lower.as_str(),
        "login"
            | "signin"
            | "sign_in"
            | "signup"
            | "sign_up"
            | "register"
            | "token"
            | "refresh_token"
            | "logout"
            | "webhook"
            | "health"
            | "health_check"
            | "healthcheck"
    ) || fn_lower.ends_with("_webhook")
        || fn_lower.starts_with("webhook_")
    {
        return true;
    }
    let Some(path) = path_arg else {
        return false;
    };
    let lower = path.to_ascii_lowercase();
    [
        "/login",
        "/signin",
        "/sign-in",
        "/signup",
        "/sign-up",
        "/register",
        "/token",
        "/oauth",
        "/callback",
        "/webhook",
        "/health",
        "/ready",
        "/ping",
        "/forgot-password",
        "/reset-password",
        "/verify-email",
    ]
    .iter()
    .any(|segment| lower.contains(segment))
}

fn parameter_satisfies_fastapi_auth(param: &ParameterWithDefault) -> bool {
    let name = param.parameter.name.as_str();
    let lower = name.to_ascii_lowercase();
    let is_auth_param_name = matches!(
        lower.as_str(),
        "current_user"
            | "user"
            | "active_user"
            | "admin_user"
            | "admin"
            | "request_user"
            | "session_user"
            | "authenticated_user"
            | "auth"
            | "token"
            | "access_token"
            | "api_key"
            | "credentials"
            | "principal"
            | "claims"
            | "permissions"
            | "_user"
            | "_auth"
    ) || lower.ends_with("_user")
        || lower.ends_with("_token")
        || lower.ends_with("_auth");

    if let Some(default_expr) = param.default.as_deref()
        && expr_contains_security_or_auth_depends(default_expr, is_auth_param_name)
    {
        return true;
    }
    if let Some(ann_expr) = param.parameter.annotation.as_deref()
        && expr_contains_security_or_auth_depends(ann_expr, is_auth_param_name)
    {
        return true;
    }
    is_auth_param_name && param.default.is_none() && param.parameter.annotation.is_some()
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Inspects Call, Subscript, and Tuple AST nodes for Depends/Security auth dependencies"
)]
fn expr_contains_security_or_auth_depends(expr: &Expr, is_auth_param_name: bool) -> bool {
    match expr {
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            let tail = callee.rsplit('.').next().unwrap_or(&callee);
            if tail == "Security" {
                return true;
            }
            if tail == "Depends" {
                if is_auth_param_name {
                    return true;
                }
                if let Some(dep_arg) = call.arguments.args.first() {
                    let dep_name = callee_qualified_name(dep_arg).to_ascii_lowercase();
                    if dep_name.contains("user")
                        || dep_name.contains("auth")
                        || dep_name.contains("token")
                        || dep_name.contains("admin")
                        || dep_name.contains("verify")
                        || dep_name.contains("require")
                        || dep_name.contains("permission")
                        || dep_name.contains("role")
                        || dep_name.contains("scope")
                        || dep_name.contains("key")
                        || dep_name.contains("credential")
                        || dep_name.contains("oauth")
                        || dep_name.contains("bearer")
                        || dep_name.contains("jwt")
                        || dep_name.contains("guard")
                    {
                        return true;
                    }
                }
            }
            call.arguments
                .args
                .iter()
                .any(|a| expr_contains_security_or_auth_depends(a, is_auth_param_name))
        }
        Expr::Subscript(sub) => {
            expr_contains_security_or_auth_depends(&sub.value, is_auth_param_name)
                || expr_contains_security_or_auth_depends(&sub.slice, is_auth_param_name)
        }
        Expr::Tuple(t) => t
            .elts
            .iter()
            .any(|e| expr_contains_security_or_auth_depends(e, is_auth_param_name)),
        _ => false,
    }
}

fn function_def_header_span(source: &str, func_def: &StmtFunctionDef) -> ByteSpan {
    let full_span = text_range_to_byte_span(func_def.range());
    let search_start = func_def
        .decorator_list
        .last()
        .map_or(full_span.start as usize, |d| d.range().end().to_usize());
    let bytes = source.as_bytes();
    let mut start = search_start.min(bytes.len());
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let start_u32 = u32::try_from(start).unwrap_or(full_span.start);
    ByteSpan {
        start: start_u32,
        end: full_span.end.max(start_u32),
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
            Operator::Add => !is_pure_string_literal(&bin.left) || !is_pure_string_literal(&bin.right),
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

fn is_subprocess_callee(callee: &str) -> bool {
    matches!(
        callee,
        "subprocess.run"
            | "subprocess.Popen"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "Popen"
            | "check_output"
            | "check_call"
    )
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
