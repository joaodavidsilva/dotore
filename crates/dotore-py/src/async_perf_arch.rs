//! Single-pass Python AST/semantic detectors for `asyncio` concurrency rules
//! (`py-async-no-blocking-call`, `py-async-no-sequential-await-in-loop`,
//! `py-async-no-unawaited-coroutine`, `py-async-no-fire-and-forget-task`) and
//! hot-loop performance rules (`py-perf-hoist-regex`, `py-perf-no-linear-membership-in-loop`).

use std::{collections::HashSet, path::Path};

use dotore_core::{
    AutofixPatch, ByteEdit, ByteSpan, Diagnostic, RuleId, loc_from_line_starts,
};
use ruff_python_ast::{CmpOp, Expr, ExprCall, Operator, Stmt};
use ruff_text_size::Ranged;

use crate::{
    callee_qualified_name, graph::PyUnawaitedCallCandidate, slice_source, text_range_to_byte_span,
};

pub(crate) fn extract_async_and_perf_diagnostics(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
    unawaited_calls: &mut Vec<PyUnawaitedCallCandidate>,
) {
    if is_stub_file {
        return;
    }
    let (async_functions, async_methods) = collect_file_async_defs(suite);
    let (root_consumed_coro_vars, root_retained_task_vars) = collect_consumed_async_vars(suite);
    let module_hoist_insert_offset = compute_module_hoist_insert_offset(suite, line_starts);
    let mut visitor = AsyncPerfVisitor {
        path,
        source,
        line_starts,
        out,
        unawaited_calls,
        class_stack: Vec::new(),
        subject_stack: Vec::new(),
        async_fn_stack: Vec::new(),
        in_executor_offload: false,
        in_coroutine_consumer: false,
        in_task_consumer: false,
        sync_sleep_aliases: HashSet::new(),
        sync_urlopen_aliases: HashSet::new(),
        sync_http_session_vars: HashSet::new(),
        async_http_client_vars: HashSet::new(),
        task_group_vars: HashSet::new(),
        path_vars: HashSet::new(),
        sync_for_chained_vars_stack: Vec::new(),
        async_functions,
        async_methods,
        consumed_coro_vars_stack: vec![root_consumed_coro_vars],
        retained_task_vars_stack: vec![root_retained_task_vars],
        fn_depth: 0,
        loop_depth: 0,
        module_hoist_insert_offset,
        hoisted_regex_count: 0,
        re_compile_aliases: HashSet::new(),
        list_vars_stack: vec![HashSet::new()],
    };
    visitor.visit_suite(suite);
}

struct AsyncPerfVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    unawaited_calls: &'a mut Vec<PyUnawaitedCallCandidate>,
    class_stack: Vec<String>,
    subject_stack: Vec<String>,
    /// Stack recording whether each enclosing function scope is `async def` (`true`) or `def` (`false`).
    async_fn_stack: Vec<bool>,
    /// True when visiting arguments of `asyncio.to_thread`, `loop.run_in_executor`, `anyio.to_thread.run_sync`, etc.
    in_executor_offload: bool,
    /// True when visiting an expression directly consumed by `await`, `return`, `yield`, or an async scheduler.
    in_coroutine_consumer: bool,
    /// True when visiting an expression whose `Task` result is awaited, returned, stored on an attribute/subscript, or passed to a call.
    in_task_consumer: bool,
    /// Local aliases imported from `time` for `sleep` (e.g. `from time import sleep`).
    sync_sleep_aliases: HashSet<String>,
    /// Local aliases imported from `urllib.request` for `urlopen` / `urlretrieve`.
    sync_urlopen_aliases: HashSet<String>,
    /// Variables assigned `requests.Session()` or `httpx.Client()`.
    sync_http_session_vars: HashSet<String>,
    /// Variables assigned `httpx.AsyncClient(...)` or `aiohttp.ClientSession(...)`.
    async_http_client_vars: HashSet<String>,
    /// Variables bound via `async with asyncio.TaskGroup() as tg:`.
    task_group_vars: HashSet<String>,
    /// Variables assigned `Path(...)` or `pathlib.Path(...)`.
    path_vars: HashSet<String>,
    /// Stack of active synchronous `for` loop frames recording cross-iteration awaited variables.
    sync_for_chained_vars_stack: Vec<HashSet<String>>,
    /// Top-level or nested `async def` function names defined in this file.
    async_functions: HashSet<String>,
    /// `async def` method names defined on classes in this file.
    async_methods: HashSet<String>,
    /// Per-function-scope local variables whose coroutine value is awaited, returned, or scheduled.
    consumed_coro_vars_stack: Vec<HashSet<String>>,
    /// Per-function-scope local variables whose `asyncio.Task` value is strongly retained, awaited, or returned.
    retained_task_vars_stack: Vec<HashSet<String>>,
    /// Current nesting depth inside `def` / `async def` functions.
    fn_depth: usize,
    /// Current nesting depth inside `for` / `while` loops or comprehensions.
    loop_depth: usize,
    /// 0-based byte offset at module scope where hoisted `_COMPILED_RE` constants are inserted.
    module_hoist_insert_offset: u32,
    /// Counter of hoisted `re.compile(...)` constants in this file.
    hoisted_regex_count: usize,
    /// Local aliases imported from `re` / `regex` for `compile`.
    re_compile_aliases: HashSet<String>,
    /// Stack of lexical scopes tracking variables known to hold `list` values.
    list_vars_stack: Vec<HashSet<String>>,
}

impl<'a> AsyncPerfVisitor<'a> {
    fn is_in_async_fn(&self) -> bool {
        self.async_fn_stack.last().copied().unwrap_or(false)
    }

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
                    if module == "time" && orig == "sleep" {
                        self.sync_sleep_aliases.insert(bound);
                    } else if module == "urllib.request"
                        && matches!(orig, "urlopen" | "urlretrieve")
                    {
                        self.sync_urlopen_aliases.insert(bound);
                    } else if module == "asyncio" && orig == "sleep" {
                        self.async_functions.insert(bound);
                    } else if matches!(module.as_str(), "re" | "regex") && orig == "compile" {
                        self.re_compile_aliases.insert(bound);
                    }
                }
            }
            Stmt::ClassDef(class_def) => {
                let class_name = class_def.name.to_string();
                let qualified = if let Some(parent) = self.class_stack.last() {
                    format!("{parent}.{class_name}")
                } else {
                    class_name.clone()
                };
                self.class_stack.push(class_name);
                self.subject_stack.push(qualified);
                self.visit_suite(&class_def.body);
                self.subject_stack.pop();
                self.class_stack.pop();
            }
            Stmt::FunctionDef(func_def) => {
                let fn_name = func_def.name.to_string();
                let subject_name = if let Some(cls) = self.class_stack.last() {
                    format!("{cls}.{fn_name}")
                } else {
                    fn_name
                };
                for dec in &func_def.decorator_list {
                    self.visit_expr(&dec.expression);
                }
                let saved_classes = std::mem::take(&mut self.class_stack);
                let saved_for_stack = std::mem::take(&mut self.sync_for_chained_vars_stack);
                let saved_loop_depth = self.loop_depth;
                self.loop_depth = 0;
                self.fn_depth += 1;
                let (fn_consumed_coros, fn_retained_tasks) =
                    collect_consumed_async_vars(&func_def.body);
                self.subject_stack.push(subject_name);
                self.async_fn_stack.push(func_def.is_async);
                self.consumed_coro_vars_stack.push(fn_consumed_coros);
                self.retained_task_vars_stack.push(fn_retained_tasks);
                self.list_vars_stack.push(HashSet::new());
                self.visit_suite(&func_def.body);
                self.list_vars_stack.pop();
                self.retained_task_vars_stack.pop();
                self.consumed_coro_vars_stack.pop();
                self.async_fn_stack.pop();
                self.subject_stack.pop();
                self.fn_depth -= 1;
                self.loop_depth = saved_loop_depth;
                self.sync_for_chained_vars_stack = saved_for_stack;
                self.class_stack = saved_classes;
            }
            Stmt::Assign(assign) => {
                let (coro_consumed, task_retained) = assign
                    .targets
                    .first()
                    .map_or((false, false), |t| self.inspect_assign_target(t, &assign.value));
                let prev_coro = self.in_coroutine_consumer;
                let prev_task = self.in_task_consumer;
                self.in_coroutine_consumer = coro_consumed;
                self.in_task_consumer = task_retained;
                self.visit_expr(&assign.value);
                self.in_coroutine_consumer = prev_coro;
                self.in_task_consumer = prev_task;
            }
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    let (coro_consumed, task_retained) =
                        self.inspect_assign_target(&ann.target, val);
                    let prev_coro = self.in_coroutine_consumer;
                    let prev_task = self.in_task_consumer;
                    self.in_coroutine_consumer = coro_consumed;
                    self.in_task_consumer = task_retained;
                    self.visit_expr(val);
                    self.in_coroutine_consumer = prev_coro;
                    self.in_task_consumer = prev_task;
                }
            }
            Stmt::AugAssign(aug) => {
                self.visit_expr(&aug.value);
            }
            Stmt::Expr(expr_stmt) => {
                self.visit_expr(&expr_stmt.value);
            }
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    let prev_coro = self.in_coroutine_consumer;
                    let prev_task = self.in_task_consumer;
                    self.in_coroutine_consumer = true;
                    self.in_task_consumer = true;
                    self.visit_expr(val);
                    self.in_coroutine_consumer = prev_coro;
                    self.in_task_consumer = prev_task;
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
                if for_stmt.is_async {
                    self.visit_suite(&for_stmt.body);
                } else {
                    let chained_vars = collect_chained_await_vars(&for_stmt.body);
                    self.sync_for_chained_vars_stack.push(chained_vars);
                    self.visit_suite(&for_stmt.body);
                    self.sync_for_chained_vars_stack.pop();
                }
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

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Inspects Name, Attribute, and Subscript assignment targets"
    )]
    fn inspect_assign_target(&mut self, target: &Expr, value: &Expr) -> (bool, bool) {
        match target {
            Expr::Name(n) => {
                let var = n.id.as_str();
                self.record_var_init(var, value);
                if var == "_" {
                    (false, false)
                } else {
                    (self.is_coro_var_consumed(var), self.is_task_var_retained(var))
                }
            }
            Expr::Attribute(_) | Expr::Subscript(_) => (true, true),
            _ => (false, false),
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
        if let Expr::Call(call) = value {
            let callee = callee_qualified_name(&call.func);
            if matches!(callee.as_str(), "requests.Session" | "httpx.Client") {
                self.sync_http_session_vars.insert(var_name.to_string());
            } else if matches!(
                callee.as_str(),
                "httpx.AsyncClient"
                    | "AsyncClient"
                    | "aiohttp.ClientSession"
                    | "ClientSession"
            ) {
                self.async_http_client_vars.insert(var_name.to_string());
            } else if matches!(
                callee.as_str(),
                "asyncio.TaskGroup"
                    | "TaskGroup"
                    | "anyio.create_task_group"
                    | "create_task_group"
            ) {
                self.task_group_vars.insert(var_name.to_string());
            } else if matches!(
                callee.as_str(),
                "Path" | "pathlib.Path" | "PurePath" | "PosixPath" | "WindowsPath"
            ) {
                self.path_vars.insert(var_name.to_string());
            }
        }
    }

    fn is_list_var(&self, var_name: &str) -> bool {
        self.list_vars_stack
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    fn is_coro_var_consumed(&self, var_name: &str) -> bool {
        self.consumed_coro_vars_stack
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    fn is_task_var_retained(&self, var_name: &str) -> bool {
        self.retained_task_vars_stack
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses Python expression nodes to inspect calls and subexpressions"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                let is_offload = is_executor_offload_callee(&callee);
                if !self.in_executor_offload && !is_offload {
                    self.check_blocking_call_in_async(call, &callee);
                }
                self.check_fire_and_forget_task(call, &callee);
                self.check_unawaited_coroutine_call(call, &callee);
                self.check_hoist_regex(call, &callee);
                let prev_offload = self.in_executor_offload;
                let prev_coro = self.in_coroutine_consumer;
                let prev_task = self.in_task_consumer;
                if is_offload {
                    self.in_executor_offload = true;
                }
                self.in_coroutine_consumer = false;
                self.in_task_consumer = false;
                self.visit_expr(&call.func);

                let args_consume_coro = is_coroutine_scheduler_callee(&callee);
                self.in_coroutine_consumer = args_consume_coro;
                self.in_task_consumer = true;
                for arg in &call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.visit_expr(&kw.value);
                }
                self.in_executor_offload = prev_offload;
                self.in_coroutine_consumer = prev_coro;
                self.in_task_consumer = prev_task;
            }
            Expr::Attribute(attr) => {
                let prev_coro = self.in_coroutine_consumer;
                let prev_task = self.in_task_consumer;
                self.in_coroutine_consumer = false;
                self.in_task_consumer = false;
                self.visit_expr(&attr.value);
                self.in_coroutine_consumer = prev_coro;
                self.in_task_consumer = prev_task;
            }
            Expr::Await(aw) => {
                self.check_sequential_await_in_loop(aw);
                let prev_coro = self.in_coroutine_consumer;
                let prev_task = self.in_task_consumer;
                self.in_coroutine_consumer = true;
                self.in_task_consumer = true;
                self.visit_expr(&aw.value);
                self.in_coroutine_consumer = prev_coro;
                self.in_task_consumer = prev_task;
            }
            Expr::Yield(y) => {
                if let Some(val) = &y.value {
                    let prev_coro = self.in_coroutine_consumer;
                    let prev_task = self.in_task_consumer;
                    self.in_coroutine_consumer = true;
                    self.in_task_consumer = true;
                    self.visit_expr(val);
                    self.in_coroutine_consumer = prev_coro;
                    self.in_task_consumer = prev_task;
                }
            }
            Expr::YieldFrom(yf) => {
                let prev_coro = self.in_coroutine_consumer;
                let prev_task = self.in_task_consumer;
                self.in_coroutine_consumer = true;
                self.in_task_consumer = true;
                self.visit_expr(&yf.value);
                self.in_coroutine_consumer = prev_coro;
                self.in_task_consumer = prev_task;
            }
            Expr::BinOp(bin) => {
                self.visit_expr(&bin.left);
                self.visit_expr(&bin.right);
            }
            Expr::UnaryOp(un) => {
                self.visit_expr(&un.operand);
            }
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
                let has_sync_gen = comp.generators.iter().any(|g| !g.is_async);
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.loop_depth += 1;
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.loop_depth -= 1;
                    }
                    self.loop_depth += 1;
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.loop_depth -= 1;
                }
                self.loop_depth += 1;
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.push(HashSet::new());
                }
                self.visit_expr(&comp.elt);
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.pop();
                }
                self.loop_depth -= 1;
            }
            Expr::SetComp(comp) => {
                let has_sync_gen = comp.generators.iter().any(|g| !g.is_async);
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.loop_depth += 1;
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.loop_depth -= 1;
                    }
                    self.loop_depth += 1;
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.loop_depth -= 1;
                }
                self.loop_depth += 1;
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.push(HashSet::new());
                }
                self.visit_expr(&comp.elt);
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.pop();
                }
                self.loop_depth -= 1;
            }
            Expr::DictComp(comp) => {
                let has_sync_gen = comp.generators.iter().any(|g| !g.is_async);
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.loop_depth += 1;
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.loop_depth -= 1;
                    }
                    self.loop_depth += 1;
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.loop_depth -= 1;
                }
                self.loop_depth += 1;
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.push(HashSet::new());
                }
                if let Some(k) = &comp.key {
                    self.visit_expr(k);
                }
                self.visit_expr(&comp.value);
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.pop();
                }
                self.loop_depth -= 1;
            }
            Expr::Generator(comp) => {
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.loop_depth += 1;
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.loop_depth -= 1;
                    }
                    self.loop_depth += 1;
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    self.loop_depth -= 1;
                }
                self.loop_depth += 1;
                self.visit_expr(&comp.elt);
                self.loop_depth -= 1;
            }
            Expr::Named(named) => {
                self.visit_expr(&named.value);
            }
            _ => {}
        }
    }

    fn check_blocking_call_in_async(&mut self, call: &ExprCall, callee: &str) {
        if !self.is_in_async_fn() {
            return;
        }
        let Some((target_display, suggestion)) = self.classify_blocking_call(call, callee) else {
            return;
        };
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyAsyncNoBlockingCall.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyAsyncNoBlockingCall,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyAsyncNoBlockingCall",
            tier: meta.default_tier,
            target_name: target_display.clone(),
            message: format!(
                "Synchronous blocking call `{target_display}(...)` inside `async def` stalls the event loop; {suggestion}."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn classify_blocking_call(
        &self,
        call: &ExprCall,
        callee: &str,
    ) -> Option<(String, &'static str)> {
        if callee == "time.sleep" || self.sync_sleep_aliases.contains(callee) {
            return Some((
                callee.to_string(),
                "use `await asyncio.sleep(...)` instead",
            ));
        }
        if matches!(
            callee,
            "requests.get"
                | "requests.post"
                | "requests.put"
                | "requests.delete"
                | "requests.patch"
                | "requests.head"
                | "requests.options"
                | "requests.request"
                | "httpx.get"
                | "httpx.post"
                | "httpx.put"
                | "httpx.delete"
                | "httpx.patch"
                | "httpx.head"
                | "httpx.options"
                | "httpx.request"
        ) {
            return Some((
                callee.to_string(),
                "use `httpx.AsyncClient` / `aiohttp.ClientSession` or offload with `await asyncio.to_thread(...)`",
            ));
        }
        if matches!(
            callee,
            "urllib.request.urlopen" | "urllib.request.urlretrieve" | "urlopen" | "urlretrieve"
        ) || self.sync_urlopen_aliases.contains(callee)
        {
            return Some((
                callee.to_string(),
                "use an async HTTP client (`httpx.AsyncClient`, `aiohttp`) or `await asyncio.to_thread(...)`",
            ));
        }
        if matches!(
            callee,
            "subprocess.run"
                | "subprocess.call"
                | "subprocess.check_call"
                | "subprocess.check_output"
                | "subprocess.Popen"
                | "os.system"
                | "os.popen"
        ) {
            return Some((
                callee.to_string(),
                "use `await asyncio.create_subprocess_exec(...)` or `await asyncio.to_thread(...)`",
            ));
        }
        if matches!(
            callee,
            "open" | "io.open" | "builtins.open" | "codecs.open"
        ) {
            return Some((
                callee.to_string(),
                "use `aiofiles.open(...)` or offload file I/O with `await asyncio.to_thread(...)`",
            ));
        }
        if matches!(
            callee,
            "socket.create_connection" | "socket.getaddrinfo" | "socket.gethostbyname"
        ) {
            return Some((
                callee.to_string(),
                "use `asyncio.open_connection(...)` or `await loop.getaddrinfo(...)`",
            ));
        }

        if let Expr::Attribute(attr) = call.func.as_ref() {
            let method = attr.attr.as_str();
            let recv = callee_qualified_name(&attr.value);
            if matches!(
                method,
                "get" | "post" | "put" | "delete" | "patch" | "head" | "options" | "request"
            ) && self.sync_http_session_vars.contains(&recv)
            {
                return Some((
                    format!("{recv}.{method}"),
                    "use `httpx.AsyncClient` or `aiohttp.ClientSession` instead of a synchronous HTTP session",
                ));
            }
            if matches!(
                method,
                "read_text" | "write_text" | "read_bytes" | "write_bytes"
            ) && (is_path_constructor_expr(&attr.value)
                || self.path_vars.contains(&recv)
                || recv.ends_with("_path")
                || recv == "path")
            {
                let recv_text = if recv.is_empty() {
                    slice_source(self.source, text_range_to_byte_span(attr.value.range()))
                        .to_string()
                } else {
                    recv
                };
                return Some((
                    format!("{recv_text}.{method}"),
                    "offload synchronous `Path` file I/O with `await asyncio.to_thread(...)` or `aiofiles`",
                ));
            }
        }

        None
    }

    fn check_sequential_await_in_loop(&mut self, aw: &ruff_python_ast::ExprAwait) {
        if !self.is_in_async_fn() || self.sync_for_chained_vars_stack.is_empty() {
            return;
        }
        let Expr::Call(call) = aw.value.as_ref() else {
            return;
        };
        let callee = callee_qualified_name(&call.func);
        if matches!(
            callee.as_str(),
            "asyncio.gather"
                | "gather"
                | "asyncio.wait"
                | "wait"
                | "asyncio.as_completed"
                | "as_completed"
        ) {
            return;
        }

        let mut arg_names = HashSet::new();
        for arg in &call.arguments.args {
            collect_expr_load_names(arg, &mut arg_names);
        }
        for kw in &call.arguments.keywords {
            collect_expr_load_names(&kw.value, &mut arg_names);
        }
        if self
            .sync_for_chained_vars_stack
            .iter()
            .any(|frame| arg_names.iter().any(|n| frame.contains(n)))
        {
            return;
        }

        let span = text_range_to_byte_span(aw.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let target_display = if callee.is_empty() {
            "await".to_string()
        } else {
            callee
        };
        let meta = RuleId::PyAsyncNoSequentialAwaitInLoop.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyAsyncNoSequentialAwaitInLoop,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyAsyncNoSequentialAwaitInLoop",
            tier: meta.default_tier,
            target_name: target_display.clone(),
            message: format!(
                "Sequential `await {target_display}(...)` inside a `for` loop serializes independent coroutines; run concurrently with `await asyncio.gather(...)` or `async with asyncio.TaskGroup() as tg:`."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn check_unawaited_coroutine_call(&mut self, call: &ExprCall, callee: &str) {
        if self.in_coroutine_consumer || callee.is_empty() {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        if !self.is_coroutine_callee(call, callee) {
            self.unawaited_calls.push(PyUnawaitedCallCandidate {
                callee: callee.to_string(),
                subject_name: self.subject_stack.last().cloned(),
                span,
                loc,
            });
            return;
        }
        let meta = RuleId::PyAsyncNoUnawaitedCoroutine.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyAsyncNoUnawaitedCoroutine,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyAsyncNoUnawaitedCoroutine",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "Coroutine `{callee}(...)` is called without `await`, `asyncio.gather(...)`, or `TaskGroup.create_task(...)` and will never execute."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn is_coroutine_callee(&self, call: &ExprCall, callee: &str) -> bool {
        if callee.is_empty() {
            return false;
        }
        if self.async_functions.contains(callee) || self.async_methods.contains(callee) {
            return true;
        }
        if let Some(method) = callee
            .strip_prefix("self.")
            .or_else(|| callee.strip_prefix("cls."))
            && self.async_methods.contains(method)
        {
            return true;
        }
        if matches!(
            callee,
            "asyncio.sleep"
                | "asyncio.gather"
                | "asyncio.wait_for"
                | "asyncio.shield"
                | "asyncio.wait"
                | "asyncio.open_connection"
                | "asyncio.start_server"
                | "asyncio.create_subprocess_exec"
                | "asyncio.create_subprocess_shell"
                | "anyio.sleep"
                | "trio.sleep"
        ) {
            return true;
        }
        if let Expr::Attribute(attr) = call.func.as_ref() {
            let recv = callee_qualified_name(&attr.value);
            let method = attr.attr.as_str();
            if self.async_http_client_vars.contains(&recv)
                && matches!(
                    method,
                    "get" | "post" | "put" | "delete" | "patch" | "head" | "options" | "request" | "aclose"
                )
            {
                return true;
            }
        }
        false
    }

    fn check_fire_and_forget_task(&mut self, call: &ExprCall, callee: &str) {
        if self.in_task_consumer || !self.is_weak_task_creation_call(callee) {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyAsyncNoFireAndForgetTask.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyAsyncNoFireAndForgetTask,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyAsyncNoFireAndForgetTask",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "Task created by `{callee}(...)` has no strong reference retained (`background_tasks.add(task)`), `await`, or `TaskGroup` ownership and may be garbage-collected mid-execution."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn is_weak_task_creation_call(&self, callee: &str) -> bool {
        if matches!(
            callee,
            "asyncio.create_task" | "asyncio.ensure_future" | "create_task" | "ensure_future"
        ) {
            return true;
        }
        if let Some(recv) = callee.strip_suffix(".create_task") {
            if self.task_group_vars.contains(recv)
                || recv == "tg"
                || recv == "task_group"
                || recv.ends_with("_tg")
                || recv.ends_with("_group")
            {
                return false;
            }
            return true;
        }
        false
    }

    fn check_hoist_regex(&mut self, call: &ExprCall, callee: &str) {
        if self.fn_depth == 0 && self.loop_depth == 0 {
            return;
        }
        if !matches!(callee, "re.compile" | "regex.compile")
            && !self.re_compile_aliases.contains(callee)
        {
            return;
        }
        let Some(first_arg) = call.arguments.args.first() else {
            return;
        };
        if !matches!(first_arg, Expr::StringLiteral(_) | Expr::BytesLiteral(_)) {
            return;
        }
        if !call.arguments.args[1..]
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
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let call_text = slice_source(self.source, span);
        let insert_pos = self.module_hoist_insert_offset;

        let meta = RuleId::PyPerfHoistRegex.metadata();
        self.out.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyPerfHoistRegex,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyPerfHoistRegex",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "Constant regular expression `{call_text}` is compiled repeatedly inside a function or loop; hoist `{const_name} = {call_text}` to module scope."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: Some(AutofixPatch {
                description: format!("Hoist `{call_text}` to module-level `{const_name}`"),
                edits: vec![
                    ByteEdit {
                        file: None,
                        span: ByteSpan {
                            start: insert_pos,
                            end: insert_pos,
                        },
                        replacement: format!("{const_name} = {call_text}\n\n"),
                    },
                    ByteEdit {
                        file: None,
                        span,
                        replacement: const_name,
                    },
                ],
            }),
        });
    }

    fn check_linear_membership_in_loop(&mut self, cmp: &ruff_python_ast::ExprCompare) {
        if self.loop_depth == 0 {
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
            let loc = loc_from_line_starts(self.line_starts, span.start);
            let rhs_text =
                slice_source(self.source, text_range_to_byte_span(comparator.range())).trim();
            let meta = RuleId::PyPerfNoLinearMembershipInLoop.metadata();
            self.out.push(Diagnostic {
                file: self.path.to_path_buf(),
                subject_name: self.subject_stack.last().cloned(),
                rule: RuleId::PyPerfNoLinearMembershipInLoop,
                category: meta.category,
                severity: meta.default_severity,
                message_id: "pyPerfNoLinearMembershipInLoop",
                tier: meta.default_tier,
                target_name: rhs_text.to_string(),
                message: format!(
                    "Linear O(n) membership check against list `{rhs_text}` inside a loop; convert `{rhs_text}` to a `set` before the loop for O(1) lookup."
                ),
                docs_url: meta.docs_url,
                loc,
                span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
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

fn is_executor_offload_callee(callee: &str) -> bool {
    matches!(
        callee,
        "asyncio.to_thread"
            | "to_thread"
            | "anyio.to_thread.run_sync"
            | "to_thread.run_sync"
            | "run_sync"
            | "sync_to_async"
            | "asgiref.sync.sync_to_async"
    ) || callee.ends_with(".run_in_executor")
        || callee.ends_with(".run_sync")
}

fn is_path_constructor_expr(expr: &Expr) -> bool {
    if let Expr::Call(call) = expr {
        let callee = callee_qualified_name(&call.func);
        return matches!(
            callee.as_str(),
            "Path"
                | "pathlib.Path"
                | "PurePath"
                | "pathlib.PurePath"
                | "PosixPath"
                | "WindowsPath"
        );
    }
    false
}

fn is_coroutine_scheduler_callee(callee: &str) -> bool {
    matches!(
        callee,
        "asyncio.create_task"
            | "create_task"
            | "asyncio.ensure_future"
            | "ensure_future"
            | "asyncio.gather"
            | "gather"
            | "asyncio.wait"
            | "wait"
            | "asyncio.wait_for"
            | "wait_for"
            | "asyncio.shield"
            | "shield"
            | "asyncio.run"
            | "anyio.run"
            | "trio.run"
            | "asyncio.as_completed"
            | "as_completed"
    ) || callee.ends_with(".create_task")
        || callee.ends_with(".run_until_complete")
        || callee.ends_with(".start_soon")
}

fn collect_file_async_defs(suite: &[Stmt]) -> (HashSet<String>, HashSet<String>) {
    let mut async_fns = HashSet::new();
    let mut async_methods = HashSet::new();
    collect_async_defs_in_suite(suite, None, &mut async_fns, &mut async_methods);
    (async_fns, async_methods)
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
        Expr::Name(n) => {
            n.id.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
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

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans function and class declarations for async def definitions"
)]
fn collect_async_defs_in_suite(
    suite: &[Stmt],
    enclosing_class: Option<&str>,
    async_fns: &mut HashSet<String>,
    async_methods: &mut HashSet<String>,
) {
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(func_def) => {
                if func_def.is_async {
                    let name = func_def.name.to_string();
                    if let Some(cls) = enclosing_class {
                        async_methods.insert(name.clone());
                        async_methods.insert(format!("{cls}.{name}"));
                    } else {
                        async_fns.insert(name);
                    }
                }
                collect_async_defs_in_suite(&func_def.body, None, async_fns, async_methods);
            }
            Stmt::ClassDef(class_def) => {
                let cls_name = class_def.name.to_string();
                collect_async_defs_in_suite(
                    &class_def.body,
                    Some(&cls_name),
                    async_fns,
                    async_methods,
                );
            }
            Stmt::If(if_stmt) => {
                collect_async_defs_in_suite(&if_stmt.body, enclosing_class, async_fns, async_methods);
                for clause in &if_stmt.elif_else_clauses {
                    collect_async_defs_in_suite(
                        &clause.body,
                        enclosing_class,
                        async_fns,
                        async_methods,
                    );
                }
            }
            Stmt::With(with_stmt) => {
                collect_async_defs_in_suite(
                    &with_stmt.body,
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
            }
            Stmt::Try(try_stmt) => {
                collect_async_defs_in_suite(
                    &try_stmt.body,
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
                for h in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                    collect_async_defs_in_suite(
                        &handler.body,
                        enclosing_class,
                        async_fns,
                        async_methods,
                    );
                }
                collect_async_defs_in_suite(
                    &try_stmt.orelse,
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
                collect_async_defs_in_suite(
                    &try_stmt.finalbody,
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
            }
            _ => {}
        }
    }
}

fn collect_consumed_async_vars(suite: &[Stmt]) -> (HashSet<String>, HashSet<String>) {
    let mut consumed_coros = HashSet::new();
    let mut retained_tasks = HashSet::new();
    for stmt in suite {
        collect_consumed_vars_in_stmt(stmt, &mut consumed_coros, &mut retained_tasks);
    }
    (consumed_coros, retained_tasks)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans statements in a function scope for awaited, returned, or scheduled variables"
)]
fn collect_consumed_vars_in_stmt(
    stmt: &Stmt,
    consumed_coros: &mut HashSet<String>,
    retained_tasks: &mut HashSet<String>,
) {
    match stmt {
        Stmt::Return(ret) => {
            if let Some(val) = &ret.value {
                collect_expr_load_names(val, consumed_coros);
                collect_expr_load_names(val, retained_tasks);
            }
        }
        Stmt::Assign(assign) => {
            if assign
                .targets
                .iter()
                .any(|t| matches!(t, Expr::Attribute(_) | Expr::Subscript(_)))
            {
                collect_expr_load_names(&assign.value, consumed_coros);
                collect_expr_load_names(&assign.value, retained_tasks);
            }
            collect_consumed_vars_in_expr(&assign.value, consumed_coros, retained_tasks);
        }
        Stmt::AnnAssign(ann) => {
            if let Some(val) = &ann.value {
                if matches!(ann.target.as_ref(), Expr::Attribute(_) | Expr::Subscript(_)) {
                    collect_expr_load_names(val, consumed_coros);
                    collect_expr_load_names(val, retained_tasks);
                }
                collect_consumed_vars_in_expr(val, consumed_coros, retained_tasks);
            }
        }
        Stmt::AugAssign(aug) => {
            collect_consumed_vars_in_expr(&aug.value, consumed_coros, retained_tasks);
        }
        Stmt::Expr(expr_stmt) => {
            collect_consumed_vars_in_expr(&expr_stmt.value, consumed_coros, retained_tasks);
        }
        Stmt::If(if_stmt) => {
            collect_consumed_vars_in_expr(&if_stmt.test, consumed_coros, retained_tasks);
            for s in &if_stmt.body {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
            for clause in &if_stmt.elif_else_clauses {
                if let Some(test) = &clause.test {
                    collect_consumed_vars_in_expr(test, consumed_coros, retained_tasks);
                }
                for s in &clause.body {
                    collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
                }
            }
        }
        Stmt::For(for_stmt) => {
            collect_consumed_vars_in_expr(&for_stmt.iter, consumed_coros, retained_tasks);
            for s in &for_stmt.body {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
            for s in &for_stmt.orelse {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
        }
        Stmt::While(while_stmt) => {
            collect_consumed_vars_in_expr(&while_stmt.test, consumed_coros, retained_tasks);
            for s in &while_stmt.body {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
            for s in &while_stmt.orelse {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
        }
        Stmt::With(with_stmt) => {
            for item in &with_stmt.items {
                collect_consumed_vars_in_expr(&item.context_expr, consumed_coros, retained_tasks);
            }
            for s in &with_stmt.body {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
        }
        Stmt::Try(try_stmt) => {
            for s in &try_stmt.body {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
            for h in &try_stmt.handlers {
                let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                for s in &handler.body {
                    collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
                }
            }
            for s in &try_stmt.orelse {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
            for s in &try_stmt.finalbody {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans expressions for await, yield, and function call arguments that consume coroutines or tasks"
)]
fn collect_consumed_vars_in_expr(
    expr: &Expr,
    consumed_coros: &mut HashSet<String>,
    retained_tasks: &mut HashSet<String>,
) {
    match expr {
        Expr::Await(aw) => {
            collect_expr_load_names(&aw.value, consumed_coros);
            collect_expr_load_names(&aw.value, retained_tasks);
            collect_consumed_vars_in_expr(&aw.value, consumed_coros, retained_tasks);
        }
        Expr::Yield(y) => {
            if let Some(val) = &y.value {
                collect_expr_load_names(val, consumed_coros);
                collect_expr_load_names(val, retained_tasks);
                collect_consumed_vars_in_expr(val, consumed_coros, retained_tasks);
            }
        }
        Expr::YieldFrom(yf) => {
            collect_expr_load_names(&yf.value, consumed_coros);
            collect_expr_load_names(&yf.value, retained_tasks);
            collect_consumed_vars_in_expr(&yf.value, consumed_coros, retained_tasks);
        }
        Expr::Call(call) => {
            collect_consumed_vars_in_expr(&call.func, consumed_coros, retained_tasks);
            for arg in &call.arguments.args {
                collect_expr_load_names(arg, consumed_coros);
                collect_expr_load_names(arg, retained_tasks);
                collect_consumed_vars_in_expr(arg, consumed_coros, retained_tasks);
            }
            for kw in &call.arguments.keywords {
                collect_expr_load_names(&kw.value, consumed_coros);
                collect_expr_load_names(&kw.value, retained_tasks);
                collect_consumed_vars_in_expr(&kw.value, consumed_coros, retained_tasks);
            }
        }
        Expr::Starred(starred) => {
            collect_expr_load_names(&starred.value, consumed_coros);
            collect_expr_load_names(&starred.value, retained_tasks);
        }
        Expr::Attribute(a) => collect_consumed_vars_in_expr(&a.value, consumed_coros, retained_tasks),
        Expr::BinOp(b) => {
            collect_consumed_vars_in_expr(&b.left, consumed_coros, retained_tasks);
            collect_consumed_vars_in_expr(&b.right, consumed_coros, retained_tasks);
        }
        Expr::UnaryOp(u) => collect_consumed_vars_in_expr(&u.operand, consumed_coros, retained_tasks),
        Expr::BoolOp(b) => {
            for v in &b.values {
                collect_consumed_vars_in_expr(v, consumed_coros, retained_tasks);
            }
        }
        Expr::List(l) => {
            for e in &l.elts {
                collect_consumed_vars_in_expr(e, consumed_coros, retained_tasks);
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                collect_consumed_vars_in_expr(e, consumed_coros, retained_tasks);
            }
        }
        Expr::Set(s) => {
            for e in &s.elts {
                collect_consumed_vars_in_expr(e, consumed_coros, retained_tasks);
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans loop body statements for variables updated from awaited results across iterations"
)]
fn collect_chained_await_vars(suite: &[Stmt]) -> HashSet<String> {
    let mut awaited_vars = HashSet::new();
    let mut assigns: Vec<(String, &Expr, bool)> = Vec::new();

    for stmt in suite {
        match stmt {
            Stmt::Assign(assign) => {
                record_loop_assign_targets(
                    &assign.targets,
                    &assign.value,
                    &mut awaited_vars,
                    &mut assigns,
                );
            }
            Stmt::AnnAssign(ann) => {
                if let (Expr::Name(n), Some(val)) = (ann.target.as_ref(), ann.value.as_deref()) {
                    let is_await = expr_contains_await(val);
                    let name = n.id.to_string();
                    if is_await {
                        awaited_vars.insert(name.clone());
                    }
                    assigns.push((name, val, is_await));
                }
            }
            _ => {}
        }
    }

    let mut chained = HashSet::new();
    for (lhs, rhs, is_await) in assigns {
        let mut rhs_names = HashSet::new();
        collect_expr_load_names(rhs, &mut rhs_names);
        if (is_await && rhs_names.contains(&lhs))
            || (!is_await && rhs_names.iter().any(|n| awaited_vars.contains(n)))
        {
            chained.insert(lhs);
        }
    }
    chained
}

fn record_loop_assign_targets<'a>(
    targets: &[Expr],
    value: &'a Expr,
    awaited_vars: &mut HashSet<String>,
    assigns: &mut Vec<(String, &'a Expr, bool)>,
) {
    let is_await = expr_contains_await(value);
    for target in targets {
        if let Expr::Name(n) = target {
            let name = n.id.to_string();
            if is_await {
                awaited_vars.insert(name.clone());
            }
            assigns.push((name, value, is_await));
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an expression tree contains an Await node"
)]
fn expr_contains_await(expr: &Expr) -> bool {
    match expr {
        Expr::Await(_) => true,
        Expr::Call(c) => {
            expr_contains_await(&c.func)
                || c.arguments.args.iter().any(expr_contains_await)
                || c.arguments
                    .keywords
                    .iter()
                    .any(|kw| expr_contains_await(&kw.value))
        }
        Expr::Attribute(a) => expr_contains_await(&a.value),
        Expr::BinOp(b) => expr_contains_await(&b.left) || expr_contains_await(&b.right),
        Expr::UnaryOp(u) => expr_contains_await(&u.operand),
        Expr::BoolOp(b) => b.values.iter().any(expr_contains_await),
        Expr::If(i) => {
            expr_contains_await(&i.test)
                || expr_contains_await(&i.body)
                || expr_contains_await(&i.orelse)
        }
        Expr::Subscript(s) => expr_contains_await(&s.value) || expr_contains_await(&s.slice),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Collects identifier names referenced inside an expression"
)]
fn collect_expr_load_names(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Name(n) => {
            out.insert(n.id.to_string());
        }
        Expr::Attribute(a) => {
            collect_expr_load_names(&a.value, out);
        }
        Expr::Call(c) => {
            collect_expr_load_names(&c.func, out);
            for arg in &c.arguments.args {
                collect_expr_load_names(arg, out);
            }
            for kw in &c.arguments.keywords {
                collect_expr_load_names(&kw.value, out);
            }
        }
        Expr::Await(aw) => collect_expr_load_names(&aw.value, out),
        Expr::BinOp(b) => {
            collect_expr_load_names(&b.left, out);
            collect_expr_load_names(&b.right, out);
        }
        Expr::UnaryOp(u) => collect_expr_load_names(&u.operand, out),
        Expr::BoolOp(b) => {
            for v in &b.values {
                collect_expr_load_names(v, out);
            }
        }
        Expr::Compare(cmp) => {
            for op in &cmp.operands {
                collect_expr_load_names(op, out);
            }
        }
        Expr::Subscript(s) => {
            collect_expr_load_names(&s.value, out);
            collect_expr_load_names(&s.slice, out);
        }
        Expr::List(l) => {
            for e in &l.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Set(s) => {
            for e in &s.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Dict(d) => {
            for item in &d.items {
                if let Some(k) = &item.key {
                    collect_expr_load_names(k, out);
                }
                collect_expr_load_names(&item.value, out);
            }
        }
        Expr::If(i) => {
            collect_expr_load_names(&i.test, out);
            collect_expr_load_names(&i.body, out);
            collect_expr_load_names(&i.orelse, out);
        }
        _ => {}
    }
}
