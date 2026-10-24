//! Python `asyncio` concurrency hazard detectors:
//! - `py-async-no-blocking-call` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-sequential-await-in-loop` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-unawaited-coroutine` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-fire-and-forget-task` (`Capability::Asyncio` / `Capability::FastApi`)

use std::{collections::HashSet, path::Path};

use dotore_core::{Diagnostic, RuleId, loc_from_line_starts};
use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_text_size::Ranged;

use crate::{
    graph::PyUnawaitedCallCandidate,
    matchers::{
        PyScopeTracker, build_py_diagnostic, callee_qualified_name, collect_expr_load_names,
        is_path_constructor_expr, slice_source, text_range_to_byte_span,
    },
};

/// Evaluates the 4 `asyncio` concurrency rules over `suite` and collects cross-file unawaited call candidates.
pub(crate) fn extract_asyncio_diagnostics(
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
    let mut visitor = AsyncioRuleVisitor {
        path,
        source,
        line_starts,
        out,
        unawaited_calls,
        scope: PyScopeTracker::new(),
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
    };
    visitor.visit_suite(suite);
}

struct AsyncioRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    unawaited_calls: &'a mut Vec<PyUnawaitedCallCandidate>,
    scope: PyScopeTracker,
    in_executor_offload: bool,
    in_coroutine_consumer: bool,
    in_task_consumer: bool,
    sync_sleep_aliases: HashSet<String>,
    sync_urlopen_aliases: HashSet<String>,
    sync_http_session_vars: HashSet<String>,
    async_http_client_vars: HashSet<String>,
    task_group_vars: HashSet<String>,
    path_vars: HashSet<String>,
    sync_for_chained_vars_stack: Vec<HashSet<String>>,
    async_functions: HashSet<String>,
    async_methods: HashSet<String>,
    consumed_coro_vars_stack: Vec<HashSet<String>>,
    retained_task_vars_stack: Vec<HashSet<String>>,
}

impl<'a> AsyncioRuleVisitor<'a> {
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
                let saved_for_stack = std::mem::take(&mut self.sync_for_chained_vars_stack);
                let (fn_consumed_coros, fn_retained_tasks) =
                    collect_consumed_async_vars(&func_def.body);
                let saved_scope = self
                    .scope
                    .enter_function(func_def.name.as_str(), func_def.is_async);
                self.consumed_coro_vars_stack.push(fn_consumed_coros);
                self.retained_task_vars_stack.push(fn_retained_tasks);
                self.visit_suite(&func_def.body);
                self.retained_task_vars_stack.pop();
                self.consumed_coro_vars_stack.pop();
                self.scope.exit_function(saved_scope);
                self.sync_for_chained_vars_stack = saved_for_stack;
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
            Stmt::AugAssign(aug) => self.visit_expr(&aug.value),
            Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
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
                self.scope.enter_loop();
                if for_stmt.is_async {
                    self.visit_suite(&for_stmt.body);
                } else {
                    let chained_vars = collect_chained_await_vars(&for_stmt.body);
                    self.sync_for_chained_vars_stack.push(chained_vars);
                    self.visit_suite(&for_stmt.body);
                    self.sync_for_chained_vars_stack.pop();
                }
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
        reason = "Traverses Python expression nodes to inspect asyncio calls and awaits"
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
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.push(HashSet::new());
                }
                self.visit_expr(&comp.elt);
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.pop();
                }
                self.scope.exit_loop();
            }
            Expr::SetComp(comp) => {
                let has_sync_gen = comp.generators.iter().any(|g| !g.is_async);
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.push(HashSet::new());
                }
                self.visit_expr(&comp.elt);
                if has_sync_gen {
                    self.sync_for_chained_vars_stack.pop();
                }
                self.scope.exit_loop();
            }
            Expr::DictComp(comp) => {
                let has_sync_gen = comp.generators.iter().any(|g| !g.is_async);
                for (idx, generator) in comp.generators.iter().enumerate() {
                    if idx > 0 {
                        self.scope.enter_loop();
                    }
                    self.visit_expr(&generator.iter);
                    if idx > 0 {
                        self.scope.exit_loop();
                    }
                    self.scope.enter_loop();
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.push(HashSet::new());
                    }
                    for if_clause in &generator.ifs {
                        self.visit_expr(if_clause);
                    }
                    if has_sync_gen {
                        self.sync_for_chained_vars_stack.pop();
                    }
                    self.scope.exit_loop();
                }
                self.scope.enter_loop();
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

    fn check_blocking_call_in_async(&mut self, call: &ExprCall, callee: &str) {
        if !self.scope.is_in_async_fn() {
            return;
        }
        let Some((target_display, suggestion)) = self.classify_blocking_call(call, callee) else {
            return;
        };
        let span = text_range_to_byte_span(call.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyAsyncNoBlockingCall,
            "pyAsyncNoBlockingCall",
            target_display.clone(),
            format!(
                "Synchronous blocking call `{target_display}(...)` inside `async def` stalls the event loop; {suggestion}."
            ),
        ));
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
        if !self.scope.is_in_async_fn() || self.sync_for_chained_vars_stack.is_empty() {
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
        let target_display = if callee.is_empty() {
            "await".to_string()
        } else {
            callee
        };
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyAsyncNoSequentialAwaitInLoop,
            "pyAsyncNoSequentialAwaitInLoop",
            target_display.clone(),
            format!(
                "Sequential `await {target_display}(...)` inside a `for` loop serializes independent coroutines; run concurrently with `await asyncio.gather(...)` or `async with asyncio.TaskGroup() as tg:`."
            ),
        ));
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
                subject_name: self.scope.current_subject(),
                span,
                loc,
            });
            return;
        }
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyAsyncNoUnawaitedCoroutine,
            "pyAsyncNoUnawaitedCoroutine",
            callee.to_string(),
            format!(
                "Coroutine `{callee}(...)` is called without `await`, `asyncio.gather(...)`, or `TaskGroup.create_task(...)` and will never execute."
            ),
        ));
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
                    "get"
                        | "post"
                        | "put"
                        | "delete"
                        | "patch"
                        | "head"
                        | "options"
                        | "request"
                        | "aclose"
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
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PyAsyncNoFireAndForgetTask,
            "pyAsyncNoFireAndForgetTask",
            callee.to_string(),
            format!(
                "Task created by `{callee}(...)` has no strong reference retained (`background_tasks.add(task)`), `await`, or `TaskGroup` ownership and may be garbage-collected mid-execution."
            ),
        ));
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
                collect_async_defs_in_suite(
                    &if_stmt.body,
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
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
        Expr::Attribute(a) => {
            collect_consumed_vars_in_expr(&a.value, consumed_coros, retained_tasks);
        }
        Expr::BinOp(b) => {
            collect_consumed_vars_in_expr(&b.left, consumed_coros, retained_tasks);
            collect_consumed_vars_in_expr(&b.right, consumed_coros, retained_tasks);
        }
        Expr::UnaryOp(u) => {
            collect_consumed_vars_in_expr(&u.operand, consumed_coros, retained_tasks);
        }
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
