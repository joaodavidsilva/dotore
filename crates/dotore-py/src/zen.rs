//! Python Zen of Python, Cyclomatic & Cognitive Complexity, and Wildcard Import detectors:
//! - `py-zen-complex-function` (`Capability::Python`, `TestNoise`)
//! - `py-zen-deep-nesting` (`Capability::Python`, `TestNoise`)
//! - `py-zen-long-function` (`Capability::Python`, `TestNoise`)
//! - `py-zen-too-many-params` (`Capability::Python`, `TestNoise`)
//! - `py-zen-large-class` (`Capability::Python`, `TestNoise`)
//! - `py-zen-no-dense-semicolon-statements` (`Capability::Python`, `TestNoise`, `Autofix`)
//! - `py-no-wildcard-import` (`Capability::Python`, `TestNoise`)

use std::path::Path;

use dotore_core::{AutofixPatch, ByteSpan, Diagnostic, RuleId, loc_from_line_starts};
use ruff_python_ast::{
    Comprehension, ExceptHandler, Expr, Pattern, Stmt, StmtClassDef, StmtFunctionDef, StmtImportFrom,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, build_py_diagnostic, build_py_diagnostic_with_autofix, function_def_header_span,
    slice_source, text_range_to_byte_span,
};

/// Maximum allowed cyclomatic complexity per function before `py-zen-complex-function` fires.
const MAX_CYCLOMATIC_COMPLEXITY: usize = 15;

/// Maximum allowed cognitive complexity per function before `py-zen-complex-function` fires.
const MAX_COGNITIVE_COMPLEXITY: usize = 25;

/// Maximum allowed control-flow nesting depth per function before `py-zen-deep-nesting` fires.
const MAX_NESTING_DEPTH: usize = 5;

/// Maximum allowed line span for a function body before `py-zen-long-function` fires.
const MAX_FUNCTION_BODY_LINES: u32 = 75;

/// Maximum allowed parameter count (excluding leading `self`/`cls`) before `py-zen-too-many-params` fires.
const MAX_FUNCTION_PARAMS: usize = 10;

/// Maximum allowed direct method definitions in a class before `py-zen-large-class` fires.
const MAX_CLASS_METHODS: usize = 20;

/// Evaluates all 6 `py-zen-*` rules and `py-no-wildcard-import` over `suite` in a single AST pass.
pub(crate) fn extract_zen_diagnostics(
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
    let is_init_py = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "__init__.py");

    let mut visitor = ZenRuleVisitor {
        path,
        source,
        line_starts,
        is_init_py,
        out,
        scope: PyScopeTracker::new(),
    };
    visitor.visit_suite(suite);
}

struct ZenRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    is_init_py: bool,
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
}

impl<'a> ZenRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        self.check_dense_semicolon_statements(suite);
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Zen visitor inspects functions, classes, imports, and compound statement blocks"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ImportFrom(import_from) => self.check_wildcard_import(import_from),
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::If(if_stmt) => {
                self.visit_suite(&if_stmt.body);
                for clause in &if_stmt.elif_else_clauses {
                    self.visit_suite(&clause.body);
                }
            }
            Stmt::For(for_stmt) => {
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
            }
            Stmt::While(while_stmt) => {
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
            }
            Stmt::With(with_stmt) => {
                self.visit_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                self.visit_suite(&try_stmt.body);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(h) = handler;
                    self.visit_suite(&h.body);
                }
                self.visit_suite(&try_stmt.orelse);
                self.visit_suite(&try_stmt.finalbody);
            }
            Stmt::Match(match_stmt) => {
                for case in &match_stmt.cases {
                    self.visit_suite(&case.body);
                }
            }
            _ => {}
        }
    }

    fn check_wildcard_import(&mut self, import_from: &StmtImportFrom) {
        if self.is_init_py {
            return;
        }
        if !import_from.names.iter().any(|alias| alias.name.as_str() == "*") {
            return;
        }
        let dots = ".".repeat(import_from.level as usize);
        let mod_name = import_from
            .module
            .as_ref()
            .map_or_else(String::new, ToString::to_string);
        let full_module = if dots.is_empty() && mod_name.is_empty() {
            "?".to_string()
        } else {
            format!("{dots}{mod_name}")
        };
        let target_stmt = format!("from {full_module} import *");
        let span = text_range_to_byte_span(import_from.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyNoWildcardImport,
            "pyNoWildcardImport",
            target_stmt.clone(),
            format!(
                "Wildcard import `{target_stmt}` pollutes the module namespace; import explicit symbol names instead."
            ),
        ));
    }

    fn visit_class_def(&mut self, class_def: &StmtClassDef) {
        let subject_name = self.scope.enter_class(class_def.name.as_str());
        let method_count = class_def
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::FunctionDef(_)))
            .count();

        if method_count > MAX_CLASS_METHODS {
            let span = class_def_header_span(self.source, class_def);
            let cls_name = class_def.name.to_string();
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                Some(subject_name),
                RuleId::PyZenLargeClass,
                "pyZenLargeClass",
                cls_name.clone(),
                format!(
                    "Class `{cls_name}` declares {method_count} methods (max {MAX_CLASS_METHODS}); split responsibilities into smaller collaborating classes."
                ),
            ));
        }

        self.visit_suite(&class_def.body);
        self.scope.exit_class();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        let saved = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        let subject_name = saved.subject_name.clone();
        let fn_name = func_def.name.to_string();
        let header_span = function_def_header_span(self.source, func_def);

        // 1. `py-zen-complex-function`
        let (cyclomatic, cognitive) = compute_function_complexity(&func_def.body);
        if cyclomatic > MAX_CYCLOMATIC_COMPLEXITY || cognitive > MAX_COGNITIVE_COMPLEXITY {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                header_span,
                Some(subject_name.clone()),
                RuleId::PyZenComplexFunction,
                "pyZenComplexFunction",
                fn_name.clone(),
                format!(
                    "Function `{fn_name}` has cyclomatic complexity {cyclomatic} (max {MAX_CYCLOMATIC_COMPLEXITY}) and cognitive complexity {cognitive} (max {MAX_COGNITIVE_COMPLEXITY}); decompose branching logic into smaller helper functions."
                ),
            ));
        }

        // 2. `py-zen-deep-nesting`
        let max_depth = compute_control_flow_nesting_depth(&func_def.body, 0);
        if max_depth > MAX_NESTING_DEPTH {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                header_span,
                Some(subject_name.clone()),
                RuleId::PyZenDeepNesting,
                "pyZenDeepNesting",
                fn_name.clone(),
                format!(
                    "Function `{fn_name}` has control-flow nesting depth {max_depth} (max {MAX_NESTING_DEPTH}); flatten nested blocks using early guard clauses or helper functions."
                ),
            ));
        }

        // 3. `py-zen-long-function`
        let body_lines = compute_function_body_lines(self.line_starts, &func_def.body);
        if body_lines > MAX_FUNCTION_BODY_LINES {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                header_span,
                Some(subject_name.clone()),
                RuleId::PyZenLongFunction,
                "pyZenLongFunction",
                fn_name.clone(),
                format!(
                    "Function `{fn_name}` body spans {body_lines} lines (max {MAX_FUNCTION_BODY_LINES}); split into smaller single-responsibility helper functions."
                ),
            ));
        }

        // 4. `py-zen-too-many-params`
        let param_count = count_effective_parameters(func_def);
        if param_count > MAX_FUNCTION_PARAMS
            && !matches!(fn_name.as_str(), "__init__" | "__init_subclass__")
        {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                header_span,
                Some(subject_name),
                RuleId::PyZenTooManyParams,
                "pyZenTooManyParams",
                fn_name.clone(),
                format!(
                    "Function `{fn_name}` declares {param_count} parameters (max {MAX_FUNCTION_PARAMS}); group related parameters into a dataclass, TypedDict, or Pydantic model."
                ),
            ));
        }

        self.visit_suite(&func_def.body);
        self.scope.exit_function(saved);
    }

    fn check_dense_semicolon_statements(&mut self, suite: &[Stmt]) {
        let mut idx = 0;
        while idx < suite.len() {
            let mut end_idx = idx;
            while end_idx + 1 < suite.len()
                && are_semicolon_chained_on_same_line(
                    self.source,
                    self.line_starts,
                    &suite[end_idx],
                    &suite[end_idx + 1],
                )
            {
                end_idx += 1;
            }
            if end_idx > idx {
                let run = &suite[idx..=end_idx];
                let first_span = text_range_to_byte_span(run[0].range());
                let last_span = text_range_to_byte_span(run[run.len() - 1].range());
                let full_span = ByteSpan {
                    start: first_span.start,
                    end: last_span.end,
                };
                let autofix = build_dense_semicolon_autofix(self.source, self.line_starts, run, full_span);
                let count = run.len();
                self.out.push(build_py_diagnostic_with_autofix(
                    self.path,
                    self.line_starts,
                    full_span,
                    self.scope.current_subject(),
                    RuleId::PyZenNoDenseSemicolonStatements,
                    "pyZenNoDenseSemicolonStatements",
                    ";",
                    format!(
                        "Line contains {count} semicolon-separated statements; place each Python statement on its own line."
                    ),
                    autofix,
                ));
            }
            idx = end_idx + 1;
        }
    }
}

fn are_semicolon_chained_on_same_line(
    source: &str,
    line_starts: &[u32],
    left: &Stmt,
    right: &Stmt,
) -> bool {
    let left_end = left
        .range()
        .end()
        .to_u32()
        .saturating_sub(1)
        .max(left.range().start().to_u32());
    let right_start = right.range().start().to_u32();
    let left_end_line = loc_from_line_starts(line_starts, left_end).line;
    let right_start_line = loc_from_line_starts(line_starts, right_start).line;
    if left_end_line != right_start_line {
        return false;
    }
    let between = slice_source(
        source,
        ByteSpan {
            start: left.range().end().to_u32(),
            end: right_start,
        },
    );
    between.contains(';')
}

fn build_dense_semicolon_autofix(
    source: &str,
    line_starts: &[u32],
    run: &[Stmt],
    full_span: ByteSpan,
) -> Option<AutofixPatch> {
    let line_num = loc_from_line_starts(line_starts, full_span.start).line;
    let line_start_offset = line_starts.get((line_num - 1) as usize).copied()?;
    let prefix = slice_source(
        source,
        ByteSpan {
            start: line_start_offset,
            end: full_span.start,
        },
    );
    if !prefix.chars().all(|c| c == ' ' || c == '\t') {
        return None;
    }
    for stmt in run {
        let s_start = loc_from_line_starts(line_starts, stmt.range().start().to_u32()).line;
        let s_end_off = stmt
            .range()
            .end()
            .to_u32()
            .saturating_sub(1)
            .max(stmt.range().start().to_u32());
        let s_end = loc_from_line_starts(line_starts, s_end_off).line;
        if s_start != s_end {
            return None;
        }
    }
    let replacement = run
        .iter()
        .map(|s| {
            slice_source(source, text_range_to_byte_span(s.range()))
                .trim_end_matches(';')
                .trim_end()
        })
        .collect::<Vec<_>>()
        .join(&format!("\n{prefix}"));
    Some(AutofixPatch::replace(
        "Split semicolon-separated statements onto separate lines",
        full_span,
        replacement,
    ))
}

fn class_def_header_span(source: &str, class_def: &StmtClassDef) -> ByteSpan {
    let full_span = text_range_to_byte_span(class_def.range());
    let search_start = class_def
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

fn compute_function_body_lines(line_starts: &[u32], body: &[Stmt]) -> u32 {
    let (Some(first), Some(last)) = (body.first(), body.last()) else {
        return 0;
    };
    let first_line = loc_from_line_starts(line_starts, first.range().start().to_u32()).line;
    let last_end = last
        .range()
        .end()
        .to_u32()
        .saturating_sub(1)
        .max(last.range().start().to_u32());
    let last_line = loc_from_line_starts(line_starts, last_end).line;
    last_line.saturating_sub(first_line) + 1
}

fn count_effective_parameters(func_def: &StmtFunctionDef) -> usize {
    let params = &func_def.parameters;
    let mut total = params.posonlyargs.len()
        + params.args.len()
        + params.kwonlyargs.len()
        + usize::from(params.vararg.is_some())
        + usize::from(params.kwarg.is_some());

    let first_positional = params.posonlyargs.first().or_else(|| params.args.first());
    if let Some(first) = first_positional
        && matches!(first.parameter.name.as_str(), "self" | "cls")
    {
        total = total.saturating_sub(1);
    }
    total
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only control-flow compound statements (if, for, while, with, try) increase nesting depth"
)]
fn compute_control_flow_nesting_depth(suite: &[Stmt], current_depth: usize) -> usize {
    let mut max_depth = current_depth;
    for stmt in suite {
        let stmt_max = match stmt {
            Stmt::If(if_stmt) => {
                let next_depth = current_depth + 1;
                let mut m = compute_control_flow_nesting_depth(&if_stmt.body, next_depth);
                for clause in &if_stmt.elif_else_clauses {
                    m = m.max(compute_control_flow_nesting_depth(&clause.body, next_depth));
                }
                m
            }
            Stmt::For(for_stmt) => {
                let next_depth = current_depth + 1;
                compute_control_flow_nesting_depth(&for_stmt.body, next_depth).max(
                    compute_control_flow_nesting_depth(&for_stmt.orelse, next_depth),
                )
            }
            Stmt::While(while_stmt) => {
                let next_depth = current_depth + 1;
                compute_control_flow_nesting_depth(&while_stmt.body, next_depth).max(
                    compute_control_flow_nesting_depth(&while_stmt.orelse, next_depth),
                )
            }
            Stmt::With(with_stmt) => {
                compute_control_flow_nesting_depth(&with_stmt.body, current_depth + 1)
            }
            Stmt::Try(try_stmt) => {
                let next_depth = current_depth + 1;
                let mut m = compute_control_flow_nesting_depth(&try_stmt.body, next_depth)
                    .max(compute_control_flow_nesting_depth(&try_stmt.orelse, next_depth))
                    .max(compute_control_flow_nesting_depth(&try_stmt.finalbody, next_depth));
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(h) = handler;
                    m = m.max(compute_control_flow_nesting_depth(&h.body, next_depth));
                }
                m
            }
            Stmt::Match(match_stmt) => {
                let next_depth = current_depth + 1;
                let mut m = next_depth;
                for case in &match_stmt.cases {
                    m = m.max(compute_control_flow_nesting_depth(&case.body, next_depth));
                }
                m
            }
            _ => current_depth,
        };
        max_depth = max_depth.max(stmt_max);
    }
    max_depth
}

struct ComplexityAccumulator {
    cyclomatic: usize,
    cognitive: usize,
}

fn compute_function_complexity(body: &[Stmt]) -> (usize, usize) {
    let mut acc = ComplexityAccumulator {
        cyclomatic: 1,
        cognitive: 0,
    };
    acc.walk_suite(body, 0);
    (acc.cyclomatic, acc.cognitive)
}

impl ComplexityAccumulator {
    fn walk_suite(&mut self, suite: &[Stmt], nesting: usize) {
        for stmt in suite {
            self.walk_stmt(stmt, nesting);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Complexity visitor walks branching statements and expressions while skipping nested def/class bodies"
    )]
    fn walk_stmt(&mut self, stmt: &Stmt, nesting: usize) {
        match stmt {
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            Stmt::If(if_stmt) => {
                self.cyclomatic += 1;
                self.cognitive += 1 + nesting;
                self.walk_expr(&if_stmt.test, nesting);
                self.walk_suite(&if_stmt.body, nesting + 1);
                for clause in &if_stmt.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.cyclomatic += 1;
                        self.cognitive += 1;
                        self.walk_expr(test, nesting);
                    } else {
                        self.cognitive += 1;
                    }
                    self.walk_suite(&clause.body, nesting + 1);
                }
            }
            Stmt::For(for_stmt) => {
                self.cyclomatic += 1;
                self.cognitive += 1 + nesting;
                self.walk_expr(&for_stmt.iter, nesting);
                self.walk_suite(&for_stmt.body, nesting + 1);
                self.walk_suite(&for_stmt.orelse, nesting + 1);
            }
            Stmt::While(while_stmt) => {
                self.cyclomatic += 1;
                self.cognitive += 1 + nesting;
                self.walk_expr(&while_stmt.test, nesting);
                self.walk_suite(&while_stmt.body, nesting + 1);
                self.walk_suite(&while_stmt.orelse, nesting + 1);
            }
            Stmt::With(with_stmt) => {
                self.cyclomatic += with_stmt.items.len();
                for item in &with_stmt.items {
                    self.walk_expr(&item.context_expr, nesting);
                }
                self.walk_suite(&with_stmt.body, nesting);
            }
            Stmt::Try(try_stmt) => {
                self.walk_suite(&try_stmt.body, nesting);
                for handler in &try_stmt.handlers {
                    let ExceptHandler::ExceptHandler(h) = handler;
                    self.cyclomatic += 1;
                    self.cognitive += 1 + nesting;
                    self.walk_suite(&h.body, nesting + 1);
                }
                self.walk_suite(&try_stmt.orelse, nesting);
                self.walk_suite(&try_stmt.finalbody, nesting);
            }
            Stmt::Assert(assert_stmt) => {
                self.cyclomatic += 1;
                self.walk_expr(&assert_stmt.test, nesting);
                if let Some(msg) = &assert_stmt.msg {
                    self.walk_expr(msg, nesting);
                }
            }
            Stmt::Match(match_stmt) => {
                self.cognitive += 1 + nesting;
                self.walk_expr(&match_stmt.subject, nesting);
                for case in &match_stmt.cases {
                    let is_wildcard = matches!(
                        &case.pattern,
                        Pattern::MatchAs(m) if m.pattern.is_none()
                    );
                    if !is_wildcard || case.guard.is_some() {
                        self.cyclomatic += 1;
                    }
                    if let Some(guard) = &case.guard {
                        self.walk_expr(guard, nesting + 1);
                    }
                    self.walk_suite(&case.body, nesting + 1);
                }
            }
            Stmt::Assign(assign) => self.walk_expr(&assign.value, nesting),
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    self.walk_expr(val, nesting);
                }
            }
            Stmt::AugAssign(aug) => self.walk_expr(&aug.value, nesting),
            Stmt::Expr(expr_stmt) => self.walk_expr(&expr_stmt.value, nesting),
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    self.walk_expr(val, nesting);
                }
            }
            Stmt::Raise(raise_stmt) => {
                if let Some(exc) = &raise_stmt.exc {
                    self.walk_expr(exc, nesting);
                }
            }
            _ => {}
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Complexity visitor inspects boolean operators, ternaries, comprehensions, and container expressions"
    )]
    fn walk_expr(&mut self, expr: &Expr, nesting: usize) {
        match expr {
            Expr::BoolOp(bool_op) => {
                let extra = bool_op.values.len().saturating_sub(1);
                self.cyclomatic += extra;
                self.cognitive += 1;
                for val in &bool_op.values {
                    self.walk_expr(val, nesting);
                }
            }
            Expr::If(if_expr) => {
                self.cyclomatic += 1;
                self.cognitive += 1 + nesting;
                self.walk_expr(&if_expr.test, nesting);
                self.walk_expr(&if_expr.body, nesting + 1);
                self.walk_expr(&if_expr.orelse, nesting + 1);
            }
            Expr::ListComp(comp) => {
                self.walk_expr(&comp.elt, nesting);
                self.walk_comprehensions(&comp.generators, nesting);
            }
            Expr::SetComp(comp) => {
                self.walk_expr(&comp.elt, nesting);
                self.walk_comprehensions(&comp.generators, nesting);
            }
            Expr::Generator(comp) => {
                self.walk_expr(&comp.elt, nesting);
                self.walk_comprehensions(&comp.generators, nesting);
            }
            Expr::DictComp(comp) => {
                if let Some(k) = &comp.key {
                    self.walk_expr(k, nesting);
                }
                self.walk_expr(&comp.value, nesting);
                self.walk_comprehensions(&comp.generators, nesting);
            }
            Expr::Call(call) => {
                self.walk_expr(&call.func, nesting);
                for arg in &call.arguments.args {
                    self.walk_expr(arg, nesting);
                }
                for kw in &call.arguments.keywords {
                    self.walk_expr(&kw.value, nesting);
                }
            }
            Expr::BinOp(bin) => {
                self.walk_expr(&bin.left, nesting);
                self.walk_expr(&bin.right, nesting);
            }
            Expr::UnaryOp(un) => self.walk_expr(&un.operand, nesting),
            Expr::Compare(cmp) => {
                for op in &cmp.operands {
                    self.walk_expr(op, nesting);
                }
            }
            Expr::Await(aw) => self.walk_expr(&aw.value, nesting),
            Expr::Yield(y) => {
                if let Some(val) = &y.value {
                    self.walk_expr(val, nesting);
                }
            }
            Expr::YieldFrom(yf) => self.walk_expr(&yf.value, nesting),
            Expr::Named(named) => self.walk_expr(&named.value, nesting),
            Expr::List(l) => {
                for e in &l.elts {
                    self.walk_expr(e, nesting);
                }
            }
            Expr::Tuple(t) => {
                for e in &t.elts {
                    self.walk_expr(e, nesting);
                }
            }
            Expr::Set(s) => {
                for e in &s.elts {
                    self.walk_expr(e, nesting);
                }
            }
            Expr::Dict(d) => {
                for item in &d.items {
                    if let Some(k) = &item.key {
                        self.walk_expr(k, nesting);
                    }
                    self.walk_expr(&item.value, nesting);
                }
            }
            _ => {}
        }
    }

    fn walk_comprehensions(&mut self, generators: &[Comprehension], nesting: usize) {
        for comp_gen in generators {
            self.cyclomatic += 1 + comp_gen.ifs.len();
            self.cognitive += 1 + nesting + comp_gen.ifs.len();
            self.walk_expr(&comp_gen.iter, nesting);
            for cond in &comp_gen.ifs {
                self.walk_expr(cond, nesting + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use dotore_core::{RuleId, compute_line_starts};
    use ruff_python_ast::PySourceType;
    use ruff_python_parser::parse_unchecked_source;

    use super::{compute_control_flow_nesting_depth, compute_function_complexity, extract_zen_diagnostics};

    #[test]
    fn computes_cyclomatic_cognitive_and_nesting_metrics_accurately() {
        let src = r#"def sample(x, items):
    if x > 0 and x < 10:
        for item in items:
            if item:
                return 1
    return 0
"#;
        let parsed = parse_unchecked_source(src, PySourceType::Python);
        let ruff_python_ast::Stmt::FunctionDef(func) = &parsed.suite()[0] else {
            panic!("expected FunctionDef");
        };
        let (cc, cog) = compute_function_complexity(&func.body);
        assert_eq!(cc, 5);
        assert!(cog >= 6);
        let depth = compute_control_flow_nesting_depth(&func.body, 0);
        assert_eq!(depth, 3);
    }

    #[test]
    fn skips_stub_files_cleanly() {
        let src = "from math import *\na = 1; b = 2\n";
        let parsed = parse_unchecked_source(src, PySourceType::Stub);
        let line_starts = compute_line_starts(src);
        let mut out = Vec::new();
        extract_zen_diagnostics(
            Path::new("types.pyi"),
            src,
            &line_starts,
            true,
            parsed.suite(),
            &mut out,
        );
        assert!(out.is_empty());

        extract_zen_diagnostics(
            Path::new("module.py"),
            src,
            &line_starts,
            false,
            parsed.suite(),
            &mut out,
        );
        let rules: Vec<RuleId> = out.iter().map(|d| d.rule).collect();
        assert!(rules.contains(&RuleId::PyNoWildcardImport));
        assert!(rules.contains(&RuleId::PyZenNoDenseSemicolonStatements));
    }
}
