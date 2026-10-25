//! Python `asyncio` concurrency hazard detectors:
//! - `py-async-no-blocking-call` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-sequential-await-in-loop` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-unawaited-coroutine` (`Capability::Asyncio` / `Capability::FastApi`)
//! - `py-async-no-fire-and-forget-task` (`Capability::Asyncio` / `Capability::FastApi`)

mod helpers;

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

use self::helpers::{
    collect_chained_await_vars, collect_consumed_async_vars, collect_file_async_defs,
    is_coroutine_scheduler_callee, is_executor_offload_callee,
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
        reason = "Visitor inspects relevant statement variants and recurses into nested blocks (#50)"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::ImportFrom(import_from) => self.visit_import_from(import_from),
            Stmt::ClassDef(class_def) => {
                self.scope.enter_class(class_def.name.as_str());
                self.visit_suite(&class_def.body);
                self.scope.exit_class();
            }
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::Assign(assign) => {
                let (coro_consumed, task_retained) =
                    assign.targets.first().map_or((false, false), |t| {
                        self.inspect_assign_target(t, &assign.value)
                    });
                self.visit_expr_with_consumer_flags(&assign.value, coro_consumed, task_retained);
            }
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    let (coro_consumed, task_retained) =
                        self.inspect_assign_target(&ann.target, val);
                    self.visit_expr_with_consumer_flags(val, coro_consumed, task_retained);
                }
            }
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    self.visit_expr_with_consumer_flags(val, true, true);
                }
            }
            Stmt::For(for_stmt) => self.visit_for_stmt(for_stmt),
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
            _ => {
                crate::matchers::walk_stmt_exprs(stmt, |e| self.visit_expr(e));
                crate::matchers::walk_stmt_sub_stmts(stmt, |s| self.visit_stmt(s));
            }
        }
    }

    fn visit_import_from(&mut self, import_from: &ruff_python_ast::StmtImportFrom) {
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
            } else if module == "urllib.request" && matches!(orig, "urlopen" | "urlretrieve") {
                self.sync_urlopen_aliases.insert(bound);
            } else if module == "asyncio" && orig == "sleep" {
                self.async_functions.insert(bound);
            }
        }
    }

    fn visit_function_def(&mut self, func_def: &ruff_python_ast::StmtFunctionDef) {
        for dec in &func_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        let saved_for_stack = std::mem::take(&mut self.sync_for_chained_vars_stack);
        let (fn_consumed_coros, fn_retained_tasks) = collect_consumed_async_vars(&func_def.body);
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

    fn visit_for_stmt(&mut self, for_stmt: &ruff_python_ast::StmtFor) {
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

    fn visit_expr_with_consumer_flags(
        &mut self,
        expr: &Expr,
        coro_consumed: bool,
        task_retained: bool,
    ) {
        let prev_coro = self.in_coroutine_consumer;
        let prev_task = self.in_task_consumer;
        self.in_coroutine_consumer = coro_consumed;
        self.in_task_consumer = task_retained;
        self.visit_expr(expr);
        self.in_coroutine_consumer = prev_coro;
        self.in_task_consumer = prev_task;
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
                    (
                        self.is_coro_var_consumed(var),
                        self.is_task_var_retained(var),
                    )
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
                "httpx.AsyncClient" | "AsyncClient" | "aiohttp.ClientSession" | "ClientSession"
            ) {
                self.async_http_client_vars.insert(var_name.to_string());
            } else if matches!(
                callee.as_str(),
                "asyncio.TaskGroup" | "TaskGroup" | "anyio.create_task_group" | "create_task_group"
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
        reason = "Traverses Python expression nodes to inspect asyncio calls and awaits (#50)"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => self.visit_call_expr(call),
            Expr::Attribute(attr) => {
                self.visit_expr_with_consumer_flags(&attr.value, false, false);
            }
            Expr::Await(aw) => {
                self.check_sequential_await_in_loop(aw);
                self.visit_expr_with_consumer_flags(&aw.value, true, true);
            }
            Expr::Yield(y) => {
                if let Some(val) = &y.value {
                    self.visit_expr_with_consumer_flags(val, true, true);
                }
            }
            Expr::YieldFrom(yf) => {
                self.visit_expr_with_consumer_flags(&yf.value, true, true);
            }
            Expr::ListComp(comp) => {
                self.visit_comprehension(None, &comp.elt, &comp.generators, true);
            }
            Expr::SetComp(comp) => {
                self.visit_comprehension(None, &comp.elt, &comp.generators, true);
            }
            Expr::DictComp(comp) => {
                self.visit_comprehension(comp.key.as_deref(), &comp.value, &comp.generators, true);
            }
            Expr::Generator(comp) => {
                self.visit_comprehension(None, &comp.elt, &comp.generators, false);
            }
            _ => crate::matchers::walk_expr_children(expr, |child| self.visit_expr(child)),
        }
    }

    fn visit_call_expr(&mut self, call: &ExprCall) {
        let callee = callee_qualified_name(&call.func);
        let is_offload = is_executor_offload_callee(&callee);
        if !self.in_executor_offload && !is_offload {
            self.check_blocking_call_in_async(call, &callee);
        }
        self.check_fire_and_forget_task(call, &callee);
        self.check_unawaited_coroutine_call(call, &callee);
        let prev_offload = self.in_executor_offload;
        if is_offload {
            self.in_executor_offload = true;
        }
        self.visit_expr_with_consumer_flags(&call.func, false, false);
        let args_consume_coro = is_coroutine_scheduler_callee(&callee);
        for arg in &call.arguments.args {
            self.visit_expr_with_consumer_flags(arg, args_consume_coro, true);
        }
        for kw in &call.arguments.keywords {
            self.visit_expr_with_consumer_flags(&kw.value, args_consume_coro, true);
        }
        self.in_executor_offload = prev_offload;
    }

    fn visit_comprehension(
        &mut self,
        key: Option<&Expr>,
        elt: &Expr,
        generators: &[ruff_python_ast::Comprehension],
        track_sync_gen: bool,
    ) {
        let push_sync_frame = track_sync_gen && generators.iter().any(|g| !g.is_async);
        for (idx, generator) in generators.iter().enumerate() {
            if idx > 0 {
                self.scope.enter_loop();
            }
            self.visit_expr(&generator.iter);
            if idx > 0 {
                self.scope.exit_loop();
            }
            self.scope.enter_loop();
            if push_sync_frame {
                self.sync_for_chained_vars_stack.push(HashSet::new());
            }
            for if_clause in &generator.ifs {
                self.visit_expr(if_clause);
            }
            if push_sync_frame {
                self.sync_for_chained_vars_stack.pop();
            }
            self.scope.exit_loop();
        }
        self.scope.enter_loop();
        if push_sync_frame {
            self.sync_for_chained_vars_stack.push(HashSet::new());
        }
        if let Some(k) = key {
            self.visit_expr(k);
        }
        self.visit_expr(elt);
        if push_sync_frame {
            self.sync_for_chained_vars_stack.pop();
        }
        self.scope.exit_loop();
    }
}

impl AsyncioRuleVisitor<'_> {
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
            return Some((callee.to_string(), "use `await asyncio.sleep(...)` instead"));
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
        if matches!(callee, "open" | "io.open" | "builtins.open" | "codecs.open") {
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

