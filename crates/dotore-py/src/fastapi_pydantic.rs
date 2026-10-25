//! FastAPI and Pydantic single-pass rule detectors:
//! - `py-pydantic-prefer-default-factory` (`Capability::Pydantic`, `Autofix`)
//! - `py-fastapi-require-response-model` (`Capability::FastApi`)
//! - `py-fastapi-mutating-route-requires-auth` (`Capability::FastApi`)

use std::{collections::HashSet, path::Path};

use dotore_core::{AutofixPatch, Diagnostic, RuleId};
use ruff_python_ast::{
    Decorator, Expr, ExprCall, Keyword, ParameterWithDefault, Stmt, StmtAnnAssign, StmtAssign,
    StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, all_function_parameters, annotation_is_classvar_or_final, build_py_diagnostic,
    build_py_diagnostic_with_patch, callee_qualified_name, function_def_header_span,
    is_upper_snake_case, slice_source, text_range_to_byte_span,
};

/// Evaluates the 3 FastAPI and Pydantic rules over `suite`.
pub(crate) fn extract_fastapi_pydantic_diagnostics(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if is_stub_file {
        return;
    }
    let mut visitor = FastapiPydanticVisitor {
        path,
        source,
        line_starts,
        out,
        scope: PyScopeTracker::new(),
        pydantic_class_stack: Vec::new(),
        authenticated_routers: HashSet::new(),
    };
    visitor.visit_suite(suite);
}

struct FastapiPydanticVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    pydantic_class_stack: Vec<bool>,
    authenticated_routers: HashSet<String>,
}

impl<'a> FastapiPydanticVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python statement variants for FastAPI and Pydantic rules (#50)"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::AnnAssign(ann_assign) => {
                self.record_router_auth_from_ann_assign(ann_assign);
                let handled_pydantic = self.check_class_ann_assign_pydantic(ann_assign);
                self.visit_expr(&ann_assign.annotation);
                if !handled_pydantic && let Some(val) = &ann_assign.value {
                    self.visit_expr(val);
                }
            }
            Stmt::Assign(assign) => {
                self.record_router_auth_from_assign(assign);
                if !self.check_class_assign_pydantic(assign) {
                    self.visit_expr(&assign.value);
                }
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
        self.pydantic_class_stack
            .push(is_pydantic_or_dataclass_model(class_def));
        self.visit_suite(&class_def.body);
        self.pydantic_class_stack.pop();
        self.scope.exit_class();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        let (subject_name, _) = self.scope.compute_function_subject(func_def.name.as_str());
        self.check_fastapi_response_model(func_def, &subject_name);
        self.check_fastapi_mutating_route_auth(func_def, &subject_name);
        for dec in &func_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        if let Some(ret) = &func_def.returns {
            self.visit_expr(ret);
        }

        let saved_pydantic = std::mem::take(&mut self.pydantic_class_stack);
        let saved_scope = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        self.visit_suite(&func_def.body);
        self.scope.exit_function(saved_scope);
        self.pydantic_class_stack = saved_pydantic;
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Call(call) = expr {
            let callee = callee_qualified_name(&call.func);
            if is_pydantic_field_callee(&callee) {
                self.check_pydantic_field_call(call, None);
            }
        }
        crate::matchers::walk_expr_children(expr, |child| self.visit_expr(child));
    }

    fn check_class_ann_assign_pydantic(&mut self, ann_assign: &StmtAnnAssign) -> bool {
        let Some(&is_pydantic_or_dataclass) = self.pydantic_class_stack.last() else {
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

        if !is_pydantic_or_dataclass {
            return false;
        }

        if let Some(factory_expr) = default_factory_for_expr(self.source, val) {
            let val_span = text_range_to_byte_span(val.range());
            let stmt_span = text_range_to_byte_span(ann_assign.range());
            let val_text = slice_source(self.source, val_span);
            let replacement = format!("Field(default_factory={factory_expr})");
            let patch = AutofixPatch::replace(
                format!("Replace `{val_text}` with `{replacement}`"),
                val_span,
                replacement.clone(),
            );
            self.out.push(build_py_diagnostic_with_patch(
                self.path,
                self.line_starts,
                stmt_span,
                self.scope.current_subject(),
                RuleId::PyPydanticPreferDefaultFactory,
                "pyPydanticPreferDefaultFactory",
                field_name.to_string(),
                format!(
                    "Field `{field_name}` uses mutable or import-time evaluated default `{val_text}`; use `{replacement}` so each model instance receives a fresh value."
                ),
                patch,
            ));
            return true;
        }
        false
    }

    fn check_class_assign_pydantic(&mut self, assign: &StmtAssign) -> bool {
        let Some(&is_pydantic_or_dataclass) = self.pydantic_class_stack.last() else {
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
        if !is_pydantic_or_dataclass {
            return false;
        }
        if let Some(factory_expr) = default_factory_for_expr(self.source, &assign.value) {
            let val_span = text_range_to_byte_span(assign.value.range());
            let stmt_span = text_range_to_byte_span(assign.range());
            let val_text = slice_source(self.source, val_span);
            let replacement = format!("Field(default_factory={factory_expr})");
            let patch = AutofixPatch::replace(
                format!("Replace `{val_text}` with `{replacement}`"),
                val_span,
                replacement.clone(),
            );
            self.out.push(build_py_diagnostic_with_patch(
                self.path,
                self.line_starts,
                stmt_span,
                self.scope.current_subject(),
                RuleId::PyPydanticPreferDefaultFactory,
                "pyPydanticPreferDefaultFactory",
                field_name.to_string(),
                format!(
                    "Field `{field_name}` uses mutable or import-time evaluated default `{val_text}`; use `{replacement}` so each model instance receives a fresh value."
                ),
                patch,
            ));
            return true;
        }
        false
    }

    fn check_pydantic_field_call(&mut self, call: &ExprCall, field_name: Option<&str>) -> bool {
        let has_default_factory = call.arguments.keywords.iter().any(|kw| {
            kw.arg
                .as_ref()
                .is_some_and(|a| a.as_str() == "default_factory")
        });
        if has_default_factory {
            return true;
        }

        let default_kw: Option<&Keyword> = call
            .arguments
            .keywords
            .iter()
            .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "default"));

        if let Some(kw) = default_kw {
            if let Some(factory_expr) = default_factory_for_expr(self.source, &kw.value) {
                let kw_span = text_range_to_byte_span(kw.range());
                let call_span = text_range_to_byte_span(call.range());
                let val_text = slice_source(self.source, text_range_to_byte_span(kw.value.range()));
                let replacement = format!("default_factory={factory_expr}");
                let target = field_name.unwrap_or("Field").to_string();
                let patch = AutofixPatch::replace(
                    format!("Rewrite `default={val_text}` to `{replacement}` in `Field(...)`"),
                    kw_span,
                    replacement.clone(),
                );
                self.out.push(build_py_diagnostic_with_patch(
                    self.path,
                    self.line_starts,
                    call_span,
                    self.scope.current_subject(),
                    RuleId::PyPydanticPreferDefaultFactory,
                    "pyPydanticPreferDefaultFactory",
                    target.clone(),
                    format!(
                        "`Field(default={val_text})` on `{target}` evaluates once at class definition time; use `Field({replacement})` instead."
                    ),
                    patch,
                ));
                return true;
            }
            return false;
        }

        if let Some(first_arg) = call.arguments.args.first()
            && let Some(factory_expr) = default_factory_for_expr(self.source, first_arg)
        {
            let arg_span = text_range_to_byte_span(first_arg.range());
            let call_span = text_range_to_byte_span(call.range());
            let val_text = slice_source(self.source, arg_span);
            let replacement = format!("default_factory={factory_expr}");
            let target = field_name.unwrap_or("Field").to_string();
            let patch = AutofixPatch::replace(
                format!("Rewrite `{val_text}` to `{replacement}` in `Field(...)`"),
                arg_span,
                replacement.clone(),
            );
            self.out.push(build_py_diagnostic_with_patch(
                self.path,
                self.line_starts,
                call_span,
                self.scope.current_subject(),
                RuleId::PyPydanticPreferDefaultFactory,
                "pyPydanticPreferDefaultFactory",
                target.clone(),
                format!(
                    "`Field({val_text})` on `{target}` evaluates once at class definition time; use `Field({replacement})` instead."
                ),
                patch,
            ));
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
        let fn_name = func_def.name.as_str();
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            Some(subject_name.to_string()),
            RuleId::PyFastapiRequireResponseModel,
            "pyFastapiRequireResponseModel",
            fn_name.to_string(),
            format!(
                "FastAPI route `{fn_name}` (`@{}`) lacks both `response_model=...` and a typed return model annotation.",
                route_dec.decorator_callee
            ),
        ));
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

    fn check_fastapi_mutating_route_auth(
        &mut self,
        func_def: &StmtFunctionDef,
        subject_name: &str,
    ) {
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

        if all_function_parameters(func_def).any(parameter_satisfies_fastapi_auth) {
            return;
        }

        let span = function_def_header_span(self.source, func_def);
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            Some(subject_name.to_string()),
            RuleId::PyFastapiMutatingRouteRequiresAuth,
            "pyFastapiMutatingRouteRequiresAuth",
            fn_name.to_string(),
            format!(
                "State-mutating FastAPI route `{fn_name}` (`@{}`) lacks an authentication or security dependency (`Depends(...)` / `Security(...)`).",
                route_dec.decorator_callee
            ),
        ));
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
    name.starts_with('_') || matches!(name, "model_config" | "Config" | "Meta" | "objects")
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
        kw.arg
            .as_ref()
            .is_some_and(|a| a.as_str() == "response_model")
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
        kw.arg
            .as_ref()
            .is_some_and(|a| a.as_str() == "dependencies")
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
            call.arguments
                .args
                .iter()
                .any(expr_contains_auth_dependency)
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
        kw.arg
            .as_ref()
            .is_some_and(|a| a.as_str() == "dependencies")
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

const AUTH_DEP_KEYWORDS: &[&str] = &[
    "user",
    "auth",
    "token",
    "admin",
    "verify",
    "require",
    "permission",
    "role",
    "scope",
    "key",
    "credential",
    "oauth",
    "bearer",
    "jwt",
    "guard",
];

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Inspects Call, Subscript, and Tuple AST nodes for Depends/Security auth dependencies (#50)"
)]
fn expr_contains_security_or_auth_depends(expr: &Expr, is_auth_param_name: bool) -> bool {
    match expr {
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            let tail = callee.rsplit('.').next().unwrap_or(&callee);
            if tail == "Security" {
                return true;
            }
            if tail == "Depends"
                && (is_auth_param_name || call_first_arg_matches_auth_dep(call))
            {
                return true;
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

fn call_first_arg_matches_auth_dep(call: &ExprCall) -> bool {
    let Some(dep_arg) = call.arguments.args.first() else {
        return false;
    };
    let dep_name = callee_qualified_name(dep_arg).to_ascii_lowercase();
    AUTH_DEP_KEYWORDS.iter().any(|kw| dep_name.contains(kw))
}
