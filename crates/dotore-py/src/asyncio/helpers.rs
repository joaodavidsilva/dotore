//! Helper predicates and variable-consumption scanners for Python `asyncio` rules.

use std::collections::HashSet;

use ruff_python_ast::{Expr, Stmt};

use crate::matchers::{
    collect_expr_load_names, walk_expr_children, walk_stmt_exprs, walk_stmt_sub_stmts,
};

pub(super) fn is_executor_offload_callee(callee: &str) -> bool {
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

pub(super) fn is_coroutine_scheduler_callee(callee: &str) -> bool {
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

pub(super) fn collect_file_async_defs(suite: &[Stmt]) -> (HashSet<String>, HashSet<String>) {
    if suite.is_empty() {
        return (HashSet::new(), HashSet::new());
    }
    let mut async_fns = HashSet::new();
    let mut async_methods = HashSet::new();
    collect_async_defs_in_suite(suite, None, &mut async_fns, &mut async_methods);
    (async_fns, async_methods)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans function and class declarations for async def definitions (#50)"
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
            _ => walk_stmt_sub_stmts(stmt, |child| {
                collect_async_defs_in_suite(
                    std::slice::from_ref(child),
                    enclosing_class,
                    async_fns,
                    async_methods,
                );
            }),
        }
    }
}

pub(super) fn collect_consumed_async_vars(suite: &[Stmt]) -> (HashSet<String>, HashSet<String>) {
    let mut consumed_coros = HashSet::new();
    let mut retained_tasks = HashSet::new();
    for stmt in suite {
        collect_consumed_vars_in_stmt(stmt, &mut consumed_coros, &mut retained_tasks);
    }
    (consumed_coros, retained_tasks)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans statements in a function scope for awaited, returned, or scheduled variables (#50)"
)]
fn collect_consumed_vars_in_stmt(
    stmt: &Stmt,
    consumed_coros: &mut HashSet<String>,
    retained_tasks: &mut HashSet<String>,
) {
    match stmt {
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
        Stmt::Return(ret) => {
            if let Some(val) = &ret.value {
                collect_expr_load_names(val, consumed_coros);
                collect_expr_load_names(val, retained_tasks);
                collect_consumed_vars_in_expr(val, consumed_coros, retained_tasks);
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
        _ => {
            walk_stmt_exprs(stmt, |e| {
                collect_consumed_vars_in_expr(e, consumed_coros, retained_tasks);
            });
            walk_stmt_sub_stmts(stmt, |s| {
                collect_consumed_vars_in_stmt(s, consumed_coros, retained_tasks);
            });
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans expressions for await, yield, and function call arguments that consume coroutines or tasks (#50)"
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
        _ => walk_expr_children(expr, |child| {
            collect_consumed_vars_in_expr(child, consumed_coros, retained_tasks);
        }),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans loop body statements for variables updated from awaited results across iterations (#50)"
)]
pub(super) fn collect_chained_await_vars(suite: &[Stmt]) -> HashSet<String> {
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

fn expr_contains_await(expr: &Expr) -> bool {
    if matches!(expr, Expr::Await(_)) {
        return true;
    }
    let mut found = false;
    walk_expr_children(expr, |child| {
        if !found && expr_contains_await(child) {
            found = true;
        }
    });
    found
}
