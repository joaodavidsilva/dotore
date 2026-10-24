//! Async waterfall, loop-await, deferred-await, and async-reducer rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; async waterfall detectors match only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentTarget, BinaryOperator, BindingPattern, CallExpression, Expression,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    CANCELLATION_FRAGMENTS, CANCELLATION_GUARD_NAMES, INTENTIONAL_SEQUENCING_CALLEES,
    ORDERED_UI_FLOW_CALLEES, SEQUENTIAL_AWAIT_THRESHOLD, belongs_directly_to_loop,
    collect_callee_identifier_trail, collections_and_loops,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::{
        collect_pattern_bound_names, push_semantic_site, resolve_ident_symbol, unwrap_expr,
    },
    rules::RuleId,
};

// ---------------------------------------------------------------------------
// 1. `async-parallel`
// ---------------------------------------------------------------------------

pub(super) fn check_async_parallel_in_block(
    block_node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if is_inside_transaction_callback(semantic, block_node_id) {
        return;
    }

    let mut run: Vec<&Statement<'_>> = Vec::new();
    for stmt in statements {
        if get_awaited_call_from_stmt(stmt).is_some() {
            run.push(stmt);
        } else {
            flush_async_parallel_run(block_node_id, &run, semantic, line_starts, out);
            run.clear();
        }
    }
    flush_async_parallel_run(block_node_id, &run, semantic, line_starts, out);
}

fn flush_async_parallel_run(
    block_node_id: NodeId,
    run: &[&Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if run.len() < SEQUENTIAL_AWAIT_THRESHOLD {
        return;
    }
    if sequence_contains_serialization_signal(run, semantic) {
        return;
    }

    let mut bound_names: HashSet<String> = HashSet::new();
    for stmt in run {
        let Some(awaited_arg) = get_awaited_call_from_stmt(stmt) else {
            continue;
        };
        if expr_reads_any_bound_name(awaited_arg, &bound_names, semantic) {
            return;
        }
        if let Statement::VariableDeclaration(var_decl) = stmt
            && let Some(decl) = var_decl.declarations.first()
        {
            bound_names.extend(collect_pattern_bound_names(&decl.id));
        }
    }

    let Some(first_stmt) = run.first() else {
        return;
    };
    let first_span = first_stmt.span();
    let subject_name = find_enclosing_react_node(semantic, block_node_id)
        .and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::AsyncParallel,
        subject_name,
        "asyncParallel",
        "Promise.all",
        format!(
            "These {} sequential await statements run one after another even though they look independent, so the page waits longer than it needs to. Run them together with Promise.all() instead",
            run.len()
        ),
        line_starts,
        first_span,
    );
}

fn get_awaited_call_from_stmt<'a>(stmt: &'a Statement<'a>) -> Option<&'a Expression<'a>> {
    match stmt {
        Statement::VariableDeclaration(var_decl) if var_decl.declarations.len() == 1 => {
            let init = var_decl.declarations[0].init.as_ref()?;
            if let Expression::AwaitExpression(aw) = unwrap_expr(init) {
                Some(unwrap_expr(&aw.argument))
            } else {
                None
            }
        }
        Statement::ExpressionStatement(expr_stmt) => {
            if let Expression::AwaitExpression(aw) = unwrap_expr(&expr_stmt.expression) {
                Some(unwrap_expr(&aw.argument))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn sequence_contains_serialization_signal(run: &[&Statement<'_>], semantic: &Semantic<'_>) -> bool {
    for stmt in run {
        let Some(awaited) = get_awaited_call_from_stmt(stmt) else {
            return true;
        };
        if !matches!(
            awaited,
            Expression::CallExpression(_)
                | Expression::NewExpression(_)
                | Expression::ImportExpression(_)
        ) {
            return true;
        }
        let is_bare = matches!(stmt, Statement::ExpressionStatement(_));
        if let Expression::CallExpression(call) = awaited {
            let trail = collect_callee_identifier_trail(&call.callee);
            if trail.iter().any(|name| {
                ORDERED_UI_FLOW_CALLEES.contains(&name.as_str())
                    || name.starts_with("findBy")
                    || name.starts_with("findAllBy")
            }) {
                return true;
            }
            let local_pure = is_order_independent_local_call(call, semantic);
            if is_bare && !local_pure {
                return true;
            }
            if trail
                .iter()
                .any(|name| INTENTIONAL_SEQUENCING_CALLEES.contains(&name.as_str()))
                && !local_pure
            {
                return true;
            }
            if is_sync_local_function_call(call, semantic) {
                return true;
            }
        } else if is_bare {
            return true;
        }
    }
    false
}

fn is_order_independent_local_call(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::Identifier(ident) = unwrap_expr(&call.callee) else {
        return false;
    };
    let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    match semantic.nodes().kind(decl_id) {
        AstKind::Function(func) => func.r#async,
        AstKind::VariableDeclarator(decl) => {
            let Some(init) = &decl.init else {
                return false;
            };
            match unwrap_expr(init) {
                Expression::ArrowFunctionExpression(arrow) => {
                    arrow.r#async
                        || arrow
                            .body
                            .span()
                            .source_text(semantic.source_text())
                            .contains("Promise.resolve")
                }
                Expression::FunctionExpression(func) => func.r#async,
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_sync_local_function_call(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::Identifier(ident) = unwrap_expr(&call.callee) else {
        return false;
    };
    let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
        && let Some(Expression::ArrowFunctionExpression(arrow)) =
            decl.init.as_ref().map(unwrap_expr)
        && !arrow.r#async
    {
        let body_src = arrow.body.span().source_text(semantic.source_text());
        if !body_src.contains("Promise") && !body_src.contains("await") {
            return true;
        }
    }
    false
}

fn is_inside_transaction_callback(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) && let AstKind::CallExpression(call) = semantic.nodes().parent_kind(anc_id)
        {
            let trail = collect_callee_identifier_trail(&call.callee);
            if trail
                .first()
                .is_some_and(|n| n == "transaction" || n == "$transaction")
            {
                return true;
            }
        }
    }
    false
}

fn expr_reads_any_bound_name(
    expr: &Expression<'_>,
    bound_names: &HashSet<String>,
    semantic: &Semantic<'_>,
) -> bool {
    if bound_names.is_empty() {
        return false;
    }
    let span = expr.span();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::IdentifierReference(ident) = node.kind() else {
            continue;
        };
        if !bound_names.contains(ident.name.as_str()) {
            continue;
        }
        if let Some(ref_id) = ident.reference_id.get() {
            let reference = semantic.scoping().get_reference(ref_id);
            if reference.is_write() && !reference.is_read() {
                continue;
            }
            if let Some(sym_id) = reference.symbol_id() {
                let decl_span = semantic
                    .nodes()
                    .get_node(semantic.scoping().symbol_declaration(sym_id))
                    .span();
                if span.contains_inclusive(decl_span) {
                    continue;
                }
            }
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 2. `async-await-in-loop` & loop-based JS performance rules
// ---------------------------------------------------------------------------

pub(super) fn check_loop_rules(
    loop_node_id: NodeId,
    loop_body_span: Span,
    has_test_import: bool,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let loop_span = semantic.nodes().get_node(loop_node_id).span();

    if !has_test_import {
        check_async_await_in_loop(
            loop_node_id,
            loop_span,
            loop_body_span,
            semantic,
            line_starts,
            out,
        );
    }
    collections_and_loops::check_js_index_maps_in_loop(
        loop_node_id,
        loop_span,
        loop_body_span,
        semantic,
        line_starts,
        out,
    );
    collections_and_loops::check_js_set_map_lookups_in_loop(
        loop_node_id,
        loop_span,
        loop_body_span,
        semantic,
        line_starts,
        out,
    );
    collections_and_loops::check_js_cache_property_access_in_loop(
        loop_node_id,
        loop_body_span,
        semantic,
        line_starts,
        out,
    );
}

fn check_async_await_in_loop(
    loop_node_id: NodeId,
    loop_span: Span,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut first_reportable: Option<(Span, String)> = None;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::AwaitExpression(await_expr) = node.kind() else {
            continue;
        };
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id) {
            continue;
        }
        if should_skip_loop_await(node_id, await_expr, loop_node_id, loop_span, semantic) {
            continue;
        }
        let expr_text = await_expr
            .argument
            .span()
            .source_text(semantic.source_text())
            .trim()
            .to_string();
        first_reportable = Some((await_expr.span, expr_text));
        break;
    }

    if let Some((span, awaited_expr)) = first_reportable {
        let subject_name = find_enclosing_react_node(semantic, loop_node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::AsyncAwaitInLoop,
            subject_name,
            "asyncAwaitInLoop",
            &awaited_expr,
            format!(
                "Avoid sequential `await {awaited_expr}` inside a loop; collect promises and use `await Promise.all(...)`."
            ),
            line_starts,
            span,
        );
    }
}

fn should_skip_loop_await(
    await_node_id: NodeId,
    await_expr: &oxc_ast::ast::AwaitExpression<'_>,
    loop_node_id: NodeId,
    loop_span: Span,
    semantic: &Semantic<'_>,
) -> bool {
    let arg = unwrap_expr(&await_expr.argument);
    let Expression::CallExpression(call) = arg else {
        return false;
    };

    // Check scheduler argument (e.g. `await job(scheduler)`)
    for call_arg in &call.arguments {
        if let Some(expr) = call_arg.as_expression()
            && let Expression::Identifier(id) = unwrap_expr(expr)
            && id.name.to_ascii_lowercase().contains("sched")
        {
            return true;
        }
    }

    let trail = collect_callee_identifier_trail(&call.callee);
    if let Some(leaf) = trail.first() {
        if leaf == "check"
            && trail
                .get(1)
                .is_some_and(|recv| recv.to_ascii_lowercase().contains("sched"))
        {
            return true;
        }
        if INTENTIONAL_SEQUENCING_CALLEES.contains(&leaf.as_str())
            && !is_order_independent_local_call(call, semantic)
        {
            return true;
        }
    }

    // Check if local function yields to host (e.g. `setTimeout` inside `new Promise`)
    if let Expression::Identifier(ident) = unwrap_expr(&call.callee)
        && let Some(sym_id) = resolve_ident_symbol(semantic, ident)
    {
        let decl_node = semantic
            .nodes()
            .get_node(semantic.scoping().symbol_declaration(sym_id));
        let decl_text = decl_node.span().source_text(semantic.source_text());
        if (decl_text.contains("setTimeout")
            || decl_text.contains("requestAnimationFrame")
            || decl_text.contains("queueMicrotask")
            || decl_text.contains("setImmediate"))
            && !decl_text.contains("void new Promise")
        {
            return true;
        }
    }

    // Check loop-carried dependency:
    // 1. `dir = await dir.getDirectoryHandle(p)` where LHS is read inside the awaited call
    if let AstKind::AssignmentExpression(assign) = semantic.nodes().parent_kind(await_node_id)
        && let AssignmentTarget::AssignmentTargetIdentifier(lhs_id) = &assign.left
    {
        let mut names = HashSet::new();
        names.insert(lhs_id.name.to_string());
        if expr_reads_any_bound_name(arg, &names, semantic) {
            return true;
        }
    }

    // 2. `results.push(await fetchNext(id, prev))` where `results` is also read inside the loop before the push
    for anc_id in semantic.nodes().ancestor_ids(await_node_id) {
        if anc_id == loop_node_id {
            break;
        }
        if let AstKind::CallExpression(outer_call) = semantic.nodes().kind(anc_id)
            && let Expression::StaticMemberExpression(mem) = unwrap_expr(&outer_call.callee)
            && (mem.property.name == "push" || mem.property.name == "unshift")
            && let Expression::Identifier(arr_id) = unwrap_expr(&mem.object)
        {
            let arr_name = arr_id.name.as_str();
            let loop_text = loop_span.source_text(semantic.source_text());
            if loop_text.contains(&format!("{arr_name}[")) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// 3. `async-defer-await`
// ---------------------------------------------------------------------------

pub(super) fn is_inside_async_function(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => return f.r#async,
            AstKind::ArrowFunctionExpression(a) => return a.r#async,
            _ => {}
        }
    }
    false
}

pub(super) fn check_async_defer_await_in_statements(
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut i = 0;
    while i + 1 < statements.len() {
        let stmt = &statements[i];
        let Statement::VariableDeclaration(var_decl) = stmt else {
            i += 1;
            continue;
        };
        let mut awaited_bindings: HashSet<String> = HashSet::new();
        let mut has_await = false;
        for decl in &var_decl.declarations {
            if let Some(init) = &decl.init
                && span_contains_direct_await(init.span(), semantic)
            {
                has_await = true;
                awaited_bindings.extend(collect_pattern_bound_names(&decl.id));
            }
        }
        if !has_await || awaited_bindings.is_empty() {
            i += 1;
            continue;
        }

        let mut guard_idx = i + 1;
        while guard_idx < statements.len() {
            let Statement::VariableDeclaration(next_var) = &statements[guard_idx] else {
                break;
            };
            let mut derives_from_awaited = false;
            for decl in &next_var.declarations {
                if let Some(init) = &decl.init
                    && (span_contains_direct_await(init.span(), semantic)
                        || expr_reads_any_bound_name(init, &awaited_bindings, semantic))
                {
                    derives_from_awaited = true;
                    awaited_bindings.extend(collect_pattern_bound_names(&decl.id));
                }
            }
            if derives_from_awaited {
                guard_idx += 1;
                continue;
            }
            break;
        }

        if guard_idx >= statements.len() {
            break;
        }

        if let Statement::IfStatement(if_stmt) = &statements[guard_idx]
            && if_stmt.alternate.is_none()
            && is_early_exit_consequent(&if_stmt.consequent)
            && !expr_reads_any_bound_name(&if_stmt.test, &awaited_bindings, semantic)
            && !stmt_reads_any_bound_name(&if_stmt.consequent, &awaited_bindings, semantic)
            && !is_cancellation_or_freshness_guard(&if_stmt.test, semantic)
        {
            push_semantic_site(
                out,
                RuleId::AsyncDeferAwait,
                None,
                "asyncDeferAwait",
                "await",
                "This await blocks the function before an early-return that doesn't use the awaited value, so the skip path waits for nothing. Move the await below the guard so it only runs when you need the data".to_string(),
                line_starts,
                stmt.span(),
            );
            i = guard_idx + 1;
            continue;
        }

        i += 1;
    }
}

fn span_contains_direct_await(span: Span, semantic: &Semantic<'_>) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if span.contains_inclusive(node.span())
            && matches!(node.kind(), AstKind::AwaitExpression(_))
        {
            return true;
        }
    }
    false
}

fn is_early_exit_consequent(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_)
        | Statement::BreakStatement(_)
        | Statement::ContinueStatement(_) => true,
        Statement::BlockStatement(block) => {
            block.body.len() == 1 && is_early_exit_consequent(&block.body[0])
        }
        _ => false,
    }
}

fn stmt_reads_any_bound_name(
    stmt: &Statement<'_>,
    bound_names: &HashSet<String>,
    semantic: &Semantic<'_>,
) -> bool {
    let span = stmt.span();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::IdentifierReference(ident) = node.kind()
            && bound_names.contains(ident.name.as_str())
        {
            return true;
        }
    }
    false
}

fn is_cancellation_or_freshness_guard(test: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let span = test.span();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(_) | AstKind::ThisExpression(_) => return true,
            AstKind::IdentifierReference(id) => {
                if is_cancellation_identifier(id.name.as_str()) {
                    return true;
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                let prop = mem.property.name.as_str();
                if prop == "current"
                    && let Expression::Identifier(obj) = unwrap_expr(&mem.object)
                    && obj.name.ends_with("Ref")
                {
                    return true;
                }
                if is_cancellation_identifier(prop) {
                    return true;
                }
            }
            _ => {}
        }
    }

    // Check non-literal equality comparison (`if (refreshId !== latestRefreshId) return`)
    if let Expression::BinaryExpression(bin) = unwrap_expr(test)
        && matches!(
            bin.operator,
            BinaryOperator::StrictEquality
                | BinaryOperator::StrictInequality
                | BinaryOperator::Equality
                | BinaryOperator::Inequality
        )
        && !is_literal_expr(unwrap_expr(&bin.left))
        && !is_literal_expr(unwrap_expr(&bin.right))
    {
        return true;
    }

    false
}

fn is_cancellation_identifier(name: &str) -> bool {
    if CANCELLATION_GUARD_NAMES.contains(&name) {
        return true;
    }
    let lower = name.trim_start_matches(['_', '#']).to_ascii_lowercase();
    if lower == "current" {
        return false;
    }
    CANCELLATION_FRAGMENTS
        .iter()
        .any(|frag| lower.contains(frag))
}

fn is_literal_expr(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => is_literal_expr(unwrap_expr(&u.argument)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 4. `js-async-reduce-without-awaited-acc`
// ---------------------------------------------------------------------------

pub(super) fn check_js_async_reduce_without_awaited_acc(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let method_name = match unwrap_expr(&call.callee) {
        Expression::StaticMemberExpression(mem)
            if mem.property.name == "reduce" || mem.property.name == "reduceRight" =>
        {
            mem.property.name.as_str()
        }
        Expression::ComputedMemberExpression(comp) => {
            if let Expression::StringLiteral(s) = unwrap_expr(&comp.expression)
                && let Some(val) = s.value.as_str()
                && (val == "reduce" || val == "reduceRight")
            {
                val
            } else {
                return;
            }
        }
        _ => return,
    };

    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let (params, body_span, reducer_span) = match unwrap_expr(first_arg) {
        Expression::ArrowFunctionExpression(arrow) if arrow.r#async => {
            (&arrow.params.items, arrow.body.span(), arrow.span)
        }
        Expression::FunctionExpression(func) if func.r#async => {
            let Some(b) = &func.body else {
                return;
            };
            (&func.params.items, b.span, func.span)
        }
        _ => return,
    };

    if !span_contains_direct_await(body_span, semantic) {
        return;
    }
    let Some(first_param) = params.first() else {
        return;
    };
    let pat = match &first_param.pattern {
        BindingPattern::AssignmentPattern(a) => &a.left,
        other => other,
    };

    match pat {
        BindingPattern::ArrayPattern(_) | BindingPattern::ObjectPattern(_) => {
            let subject_name = find_enclosing_react_node(semantic, node_id)
                .and_then(|id| get_subject_name(semantic, id));
            push_semantic_site(
                out,
                RuleId::JsAsyncReduceWithoutAwaitedAcc,
                subject_name,
                "jsAsyncReduceWithoutAwaitedAcc",
                method_name,
                format!(
                    "This async `.{method_name}` reducer destructures its accumulator, but every run after the first gets a Promise, so the pieces come out empty & the work is lost. Await it first: `async (previous, item) => {{ const [...] = await previous; ...; return [...]; }}`, & seed with `Promise.resolve([...])`"
                ),
                line_starts,
                reducer_span,
            );
        }
        BindingPattern::BindingIdentifier(acc_id) => {
            let acc_name = acc_id.name.as_str();
            let awaits_acc = semantic.nodes().iter_enumerated().any(|(_, n)| {
                if !body_span.contains_inclusive(n.span()) {
                    return false;
                }
                if let AstKind::AwaitExpression(aw) = n.kind()
                    && let Expression::Identifier(id) = unwrap_expr(&aw.argument)
                {
                    id.name == acc_name
                } else {
                    false
                }
            });
            if !awaits_acc {
                let subject_name = find_enclosing_react_node(semantic, node_id)
                    .and_then(|id| get_subject_name(semantic, id));
                push_semantic_site(
                    out,
                    RuleId::JsAsyncReduceWithoutAwaitedAcc,
                    subject_name,
                    "jsAsyncReduceWithoutAwaitedAcc",
                    acc_name,
                    format!(
                        "This async `.{method_name}` reducer never awaits its accumulator \"{acc_name}\", so each run gets a Promise instead of the real value & the work is lost."
                    ),
                    line_starts,
                    reducer_span,
                );
            }
        }
        BindingPattern::AssignmentPattern(_) => {}
    }
}
