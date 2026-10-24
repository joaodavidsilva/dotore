//! Python hot-loop performance detectors:
//! - `py-perf-hoist-regex` (`Capability::Python`, `Autofix`)
//! - `py-perf-no-linear-membership-in-loop` (`Capability::Python`)

use std::{collections::HashSet, path::Path};

use dotore_core::{AutofixPatch, ByteEdit, Diagnostic, RuleId, loc_from_line_starts};
use ruff_python_ast::{CmpOp, Expr, ExprCall, Operator, Stmt};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, build_py_diagnostic, build_py_diagnostic_with_patch, callee_qualified_name,
    is_upper_snake_case, slice_source, text_range_to_byte_span,
};

/// Evaluates `py-perf-hoist-regex` and `py-perf-no-linear-membership-in-loop` over `suite`.
pub(crate) fn extract_perf_diagnostics(
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
    let module_hoist_insert_offset = compute_module_hoist_insert_offset(suite, line_starts);
    let mut visitor = PerfRuleVisitor {
        path,
        source,
        line_starts,
        out,
        scope: PyScopeTracker::new(),
        module_hoist_insert_offset,
        hoisted_regex_count: 0,
        re_compile_aliases: HashSet::new(),
        list_vars_stack: vec![HashSet::new()],
    };
    visitor.visit_suite(suite);
}

struct PerfRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    module_hoist_insert_offset: u32,
    hoisted_regex_count: usize,
    re_compile_aliases: HashSet<String>,
    list_vars_stack: Vec<HashSet<String>>,
}

impl<'a> PerfRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Visitor inspects relevant statement variants and recurses into nested blocks"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ImportFrom(import_from) => {
                let module = import_from
                    .module
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                for alias in &import_from.names {
                    let orig = alias.name.as_str();
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| orig.to_string(), ToString::to_string);
                    if matches!(module.as_str(), "re" | "regex") && orig == "compile" {
                        self.re_compile_aliases.insert(bound);
                    }
                }
            }
            Stmt::ClassDef(class_def) => {
                self.scope.enter_class(class_def.name.as_str());
                self.visit_suite(&class_def.body);
                self.scope.exit_class();
            }
            Stmt::FunctionDef(func_def) => {
                for dec in &func_def.decorator_list {
                    self.visit_expr(&dec.expression);
                }
                let saved_scope = self
                    .scope
                    .enter_function(func_def.name.as_str(), func_def.is_async);
                self.list_vars_stack.push(HashSet::new());
                self.visit_suite(&func_def.body);
                self.list_vars_stack.pop();
                self.scope.exit_function(saved_scope);
            }
            Stmt::Assign(assign) => {
                if let Some(Expr::Name(n)) = assign.targets.first() {
                    self.record_var_init(n.id.as_str(), &assign.value);
                }
                self.visit_expr(&assign.value);
            }
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    if let Expr::Name(n) = ann.target.as_ref() {
                        self.record_var_init(n.id.as_str(), val);
                    }
                    self.visit_expr(val);
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
                for item in &with_stmt.items {
                    if let Some(Expr::Name(target)) = item.optional_vars.as_deref() {
                        self.record_var_init(target.id.as_str(), &item.context_expr);
                    }
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

    fn record_var_init(&mut self, var_name: &str, value: &Expr) {
        if is_list_init_expr(value) {
            if let Some(frame) = self.list_vars_stack.last_mut() {
                frame.insert(var_name.to_string());
            }
        } else if is_set_or_dict_init_expr(value) {
            for frame in &mut self.list_vars_stack {
                frame.remove(var_name);
            }
        }
    }

    fn is_list_var(&self, var_name: &str) -> bool {
        self.list_vars_stack
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses Python expression nodes to inspect regex compilation and membership checks"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                self.check_hoist_regex(call, &callee);
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
                if let Some(val) = &y.value {
                    self.visit_expr(val);
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
                self.check_linear_membership_in_loop(cmp);
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
            Expr::List(list) => {
                for elt in &list.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Tuple(tuple) => {
                for elt in &tuple.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Set(set) => {
                for elt in &set.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Dict(dict) => {
                for item in &dict.items {
                    if let Some(k) = &item.key {
                        self.visit_expr(k);
                    }
                    self.visit_expr(&item.value);
                }
            }
            Expr::ListComp(comp) => {
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                self.visit_expr(&comp.elt);
                self.scope.exit_loop();
            }
            Expr::SetComp(comp) => {
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                self.visit_expr(&comp.elt);
                self.scope.exit_loop();
            }
            Expr::DictComp(comp) => {
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                if let Some(k) = &comp.key {
                    self.visit_expr(k);
                }
                self.visit_expr(&comp.value);
                self.scope.exit_loop();
            }
            Expr::Generator(comp) => {
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                self.visit_expr(&comp.elt);
                self.scope.exit_loop();
            }
            Expr::Named(named) => self.visit_expr(&named.value),
            _ => {}
        }
    }

    fn check_hoist_regex(&mut self, call: &ExprCall, callee: &str) {
        if self.scope.fn_depth() == 0 && !self.scope.in_loop() {
            return;
        }
        if !matches!(callee, "re.compile" | "regex.compile")
            && !self.re_compile_aliases.contains(callee)
        {
            return;
        }
        let Some((first_arg, rest_args)) = call.arguments.args.split_first() else {
            return;
        };
        if !matches!(first_arg, Expr::StringLiteral(_) | Expr::BytesLiteral(_)) {
            return;
        }
        if !rest_args
            .iter()
            .all(is_constant_regex_flag_expr)
            || !call
                .arguments
                .keywords
                .iter()
                .all(|kw| is_constant_regex_flag_expr(&kw.value))
        {
            return;
        }

        self.hoisted_regex_count += 1;
        let const_name = if self.hoisted_regex_count == 1 && !self.source.contains("_COMPILED_RE") {
            "_COMPILED_RE".to_string()
        } else {
            format!("_COMPILED_RE_{}", self.hoisted_regex_count)
        };

        let span = text_range_to_byte_span(call.range());
        let call_text = slice_source(self.source, span);
        let insert_pos = self.module_hoist_insert_offset;

        let patch = AutofixPatch::new(format!(
            "Hoist `{call_text}` to module-level `{const_name}`"
        ))
        .with_byte_edit(ByteEdit::insert(
            insert_pos,
            format!("{const_name} = {call_text}\n\n"),
        ))
        .with_byte_edit(ByteEdit::replace(span, const_name.clone()));

        self.out.push(build_py_diagnostic_with_patch(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyPerfHoistRegex,
            "pyPerfHoistRegex",
            callee.to_string(),
            format!(
                "Constant regular expression `{call_text}` is compiled repeatedly inside a function or loop; hoist `{const_name} = {call_text}` to module scope."
            ),
            patch,
        ));
    }

    fn check_linear_membership_in_loop(&mut self, cmp: &ruff_python_ast::ExprCompare) {
        if !self.scope.in_loop() {
            return;
        }
        for (op, comparator) in cmp.ops.iter().zip(cmp.comparators()) {
            if !matches!(op, CmpOp::In | CmpOp::NotIn) {
                continue;
            }
            if !self.is_list_collection_expr(comparator) {
                continue;
            }
            let span = text_range_to_byte_span(cmp.range());
            let rhs_text =
                slice_source(self.source, text_range_to_byte_span(comparator.range())).trim();
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PyPerfNoLinearMembershipInLoop,
                "pyPerfNoLinearMembershipInLoop",
                rhs_text.to_string(),
                format!(
                    "Linear O(n) membership check against list `{rhs_text}` inside a loop; convert `{rhs_text}` to a `set` before the loop for O(1) lookup."
                ),
            ));
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Matches list literals, list comprehensions, list(...) calls, and variables bound to lists"
    )]
    fn is_list_collection_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::List(_) | Expr::ListComp(_) => true,
            Expr::Call(call) => callee_qualified_name(&call.func) == "list",
            Expr::Name(n) => self.is_list_var(n.id.as_str()),
            _ => false,
        }
    }
}

fn compute_module_hoist_insert_offset(suite: &[Stmt], line_starts: &[u32]) -> u32 {
    for (idx, stmt) in suite.iter().enumerate() {
        if idx == 0
            && let Stmt::Expr(expr_stmt) = stmt
            && matches!(expr_stmt.value.as_ref(), Expr::StringLiteral(_))
        {
            continue;
        }
        if matches!(stmt, Stmt::Import(_) | Stmt::ImportFrom(_)) {
            continue;
        }
        let start = stmt.range().start().to_u32();
        let loc = loc_from_line_starts(line_starts, start);
        return line_starts
            .get((loc.line.saturating_sub(1)) as usize)
            .copied()
            .unwrap_or(start);
    }
    0
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether a regex flag expression is a compile-time constant"
)]
fn is_constant_regex_flag_expr(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(_) => true,
        Expr::Attribute(attr) => matches!(
            callee_qualified_name(&attr.value).as_str(),
            "re" | "regex" | "RegexFlag" | "re.RegexFlag"
        ),
        Expr::Name(n) => is_upper_snake_case(n.id.as_str()),
        Expr::BinOp(bin) if bin.op == Operator::BitOr => {
            is_constant_regex_flag_expr(&bin.left) && is_constant_regex_flag_expr(&bin.right)
        }
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an initializer expression constructs a Python list"
)]
fn is_list_init_expr(expr: &Expr) -> bool {
    match expr {
        Expr::List(_) | Expr::ListComp(_) => true,
        Expr::Call(call) => callee_qualified_name(&call.func) == "list",
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an initializer expression constructs a set or dict"
)]
fn is_set_or_dict_init_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Set(_) | Expr::SetComp(_) | Expr::Dict(_) | Expr::DictComp(_) => true,
        Expr::Call(call) => matches!(
            callee_qualified_name(&call.func).as_str(),
            "set" | "frozenset" | "dict"
        ),
        _ => false,
    }
}
