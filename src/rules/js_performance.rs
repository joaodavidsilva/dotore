//! JavaScript runtime performance, client DOM, and View Transitions rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JS performance rule detectors match only relevant AST node kinds"
)]

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, AssignmentTarget, BinaryOperator, BindingPattern,
        CallExpression, Expression, ImportDeclarationSpecifier, LogicalOperator,
        ObjectPropertyKind, Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{find_enclosing_react_node, get_subject_name, is_component_name},
        types::{ModuleIr, SemanticRuleSite, loc_from_line_starts},
    },
    rules::{AutofixPatch, ByteEdit, RuleId},
};

const SEQUENTIAL_AWAIT_THRESHOLD: usize = 3;

const PASSIVE_EVENT_NAMES: &[&str] = &["wheel", "mousewheel", "touchstart", "touchmove"];

const ORDERED_UI_FLOW_CALLEES: &[&str] = &[
    "render",
    "rerender",
    "renderHook",
    "renderToString",
    "renderToStaticMarkup",
    "act",
    "click",
    "dblClick",
    "dblclick",
    "tripleClick",
    "tap",
    "press",
    "longPress",
    "type",
    "clear",
    "fill",
    "focus",
    "blur",
    "hover",
    "unhover",
    "check",
    "uncheck",
    "selectOption",
    "selectOptions",
    "setChecked",
    "setInputFiles",
    "scrollIntoViewIfNeeded",
    "dragTo",
    "dragAndDrop",
    "drop",
    "evaluate",
    "evaluateHandle",
    "waitFor",
    "waitForLoadState",
    "waitForSelector",
    "waitForURL",
    "waitForResponse",
    "waitForRequest",
    "waitForEvent",
    "waitForFunction",
    "waitForElementToBeRemoved",
    "goto",
    "goBack",
    "goForward",
    "reload",
    "screenshot",
    "snapshot",
    "toMatchSnapshot",
    "toMatchInlineSnapshot",
    "expect",
    "expectTypeOf",
    "step",
    "describe",
    "test",
    "it",
    "beforeAll",
    "beforeEach",
    "afterAll",
    "afterEach",
    "play",
    "userEvent",
    "screen",
    "within",
];

const INTENTIONAL_SEQUENCING_CALLEES: &[&str] = &[
    "sleep",
    "delay",
    "wait",
    "pause",
    "throttle",
    "debounce",
    "tick",
    "nextTick",
    "advanceTimersByTime",
    "advanceTimersByTimeAsync",
    "runAllTimers",
    "runAllTimersAsync",
    "runOnlyPendingTimers",
    "runOnlyPendingTimersAsync",
    "setTimeout",
    "setInterval",
    "setImmediate",
    "queueMicrotask",
    "requestAnimationFrame",
    "requestIdleCallback",
    "yieldNow",
    "yieldTo",
    "yieldToBrowser",
    "slice",
    "sliceYield",
    "nextFrame",
    "breathe",
    "onYield",
    "onProgress",
    "progress",
    "onStep",
    "step",
    "stage",
    "runStage",
    "animate",
    "transition",
    "spring",
    "tween",
    "stagger",
    "sequence",
    "timeline",
    "scrub",
    "query",
    "execute",
    "exec",
    "raw",
    "transaction",
    "$transaction",
    "$executeRaw",
    "$queryRaw",
    "$executeRawUnsafe",
    "$queryRawUnsafe",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "lock",
    "unlock",
    "spawn",
    "spawnSync",
    "execSync",
    "execFile",
    "execFileSync",
    "fork",
    "$",
    "sh",
    "mkdir",
    "rmdir",
    "rename",
    "rm",
    "unlink",
    "writeFile",
    "appendFile",
    "copyFile",
    "navigate",
    "goto",
    "waitForNavigation",
    "waitForURL",
    "waitForLoadState",
    "waitForResponse",
    "waitForRequest",
    "waitForSelector",
    "waitForFunction",
    "waitForEvent",
];

const TEST_LIBRARY_IMPORTS: &[&str] = &[
    "vitest",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "expect",
    "ava",
    "uvu",
    "node:test",
    "bun:test",
    "playwright",
    "playwright-core",
    "@playwright/test",
    "cypress",
    "puppeteer",
    "puppeteer-core",
    "webdriverio",
];

const CANCELLATION_GUARD_NAMES: &[&str] = &[
    "cancelled",
    "canceled",
    "isCancelled",
    "isCanceled",
    "aborted",
    "isAborted",
    "disposed",
    "isDisposed",
    "destroyed",
    "isDestroyed",
    "stopped",
    "isStopped",
    "mounted",
    "isMounted",
    "unmounted",
    "isUnmounted",
    "active",
    "isActive",
    "stale",
    "isStale",
    "live",
    "isLive",
    "ignore",
    "signal",
    "abortSignal",
    "abortController",
];

const CANCELLATION_FRAGMENTS: &[&str] = &[
    "cancel",
    "abort",
    "dispos",
    "destroy",
    "stale",
    "alive",
    "mounted",
    "stopped",
    "settled",
    "cleanedup",
    "generation",
    "current",
    "token",
    "signal",
];

const DOM_MEASUREMENT_NAMES: &[&str] = &[
    "getBoundingClientRect",
    "getClientRects",
    "getComputedStyle",
    "getAnimations",
    "scrollIntoView",
    "elementFromPoint",
    "offsetWidth",
    "offsetHeight",
    "offsetTop",
    "offsetLeft",
    "clientWidth",
    "clientHeight",
    "scrollTop",
    "scrollLeft",
    "scrollWidth",
    "scrollHeight",
];

const IMPERATIVE_DOM_MUTATION_NAMES: &[&str] = &[
    "blur",
    "focus",
    "restoreSelection",
    "scroll",
    "scrollBy",
    "scrollIntoView",
    "scrollTo",
    "setRangeText",
    "setSelectionRange",
];

const INTL_CLASSES: &[&str] = &[
    "NumberFormat",
    "DateTimeFormat",
    "Collator",
    "RelativeTimeFormat",
    "ListFormat",
    "PluralRules",
    "Segmenter",
    "DisplayNames",
];

const CHAINABLE_ITERATION_METHODS: &[&str] = &["map", "filter", "forEach", "flatMap"];

/// Extracts JS performance, client DOM, and View Transitions rule sites during the single OXC pass.
pub(crate) fn extract_js_performance_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let has_test_import = module.imports.iter().any(|imp| {
        TEST_LIBRARY_IMPORTS.contains(&imp.source.as_str())
            || imp.source.starts_with("@testing-library/")
            || imp.source.starts_with("@playwright/")
            || imp.source.starts_with("vitest/")
            || imp.source.starts_with("@vitest/")
            || imp.source.starts_with("@storybook/")
    });
    let path_str = path.to_string_lossy().replace('\\', "/");
    let is_browser_test_file = path_str.contains(".browser.");
    let is_public_asset = path_str.starts_with("public/") || path_str.contains("/public/");

    let imports_react_view_transition = module.imports.iter().any(|imp| {
        imp.source == "react"
            && !imp.is_type_only
            && imp.bindings.iter().any(|b| {
                !b.is_type_only
                    && (b.imported_name == "ViewTransition"
                        || b.imported_name == "unstable_ViewTransition")
            })
    });

    check_no_flush_sync(semantic, module, line_starts, out);
    check_js_cache_storage(semantic, line_starts, out);
    check_no_create_object_url_without_revoke(semantic, line_starts, out);

    let mut covered_chain_spans: HashSet<Span> = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::BlockStatement(block) => {
                if !has_test_import && !is_browser_test_file {
                    check_async_parallel_in_block(node_id, &block.body, semantic, line_starts, out);
                }
                if is_inside_async_function(semantic, node_id) {
                    check_async_defer_await_in_statements(&block.body, semantic, line_starts, out);
                }
                check_js_batch_dom_css_in_block(node_id, &block.body, semantic, line_starts, out);
            }
            AstKind::FunctionBody(body) => {
                let is_block_body = body
                    .span
                    .source_text(semantic.source_text())
                    .trim_start()
                    .starts_with('{');
                if is_block_body {
                    if !has_test_import && !is_browser_test_file {
                        check_async_parallel_in_block(
                            node_id,
                            &body.statements,
                            semantic,
                            line_starts,
                            out,
                        );
                    }
                    if is_inside_async_function(semantic, node_id) {
                        check_async_defer_await_in_statements(
                            &body.statements,
                            semantic,
                            line_starts,
                            out,
                        );
                    }
                    check_js_batch_dom_css_in_block(
                        node_id,
                        &body.statements,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::SwitchCase(case) => {
                if is_inside_async_function(semantic, node_id) {
                    check_async_defer_await_in_statements(
                        &case.consequent,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::ForStatement(s) => {
                check_loop_rules(
                    node_id,
                    s.body.span(),
                    has_test_import,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::ForOfStatement(s) => {
                if !s.r#await {
                    check_loop_rules(
                        node_id,
                        s.body.span(),
                        has_test_import,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::ForInStatement(s) => {
                check_loop_rules(
                    node_id,
                    s.body.span(),
                    has_test_import,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::WhileStatement(s) => {
                check_loop_rules(
                    node_id,
                    s.body.span(),
                    has_test_import,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::DoWhileStatement(s) => {
                check_loop_rules(
                    node_id,
                    s.body.span(),
                    has_test_import,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::CallExpression(call) => {
                check_no_json_parse_stringify_clone(
                    path,
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                if !is_public_asset {
                    check_no_sync_xhr(node_id, call, semantic, line_starts, out);
                }
                check_no_document_write(node_id, call, semantic, line_starts, out);
                check_no_spread_accumulator_in_reduce(node_id, call, semantic, line_starts, out);
                check_js_async_reduce_without_awaited_acc(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                check_client_passive_event_listeners(node_id, call, semantic, line_starts, out);
                if imports_react_view_transition {
                    check_no_document_start_view_transition(
                        node_id,
                        call,
                        semantic,
                        line_starts,
                        out,
                    );
                }
                check_js_flatmap_filter(node_id, call, semantic, line_starts, out);
                check_js_combine_iterations(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    &mut covered_chain_spans,
                    out,
                );
                check_js_min_max_loop(node_id, call, semantic, line_starts, out);
                check_js_length_check_first(node_id, call, semantic, line_starts, out);
                check_js_hoist_regexp_call(
                    node_id,
                    call.span,
                    &call.callee,
                    &call.arguments,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::NewExpression(new_expr) => {
                check_js_hoist_intl(node_id, new_expr, semantic, line_starts, out);
                check_js_hoist_regexp_call(
                    node_id,
                    new_expr.span,
                    &new_expr.callee,
                    &new_expr.arguments,
                    semantic,
                    line_starts,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn unwrap_expr<'a>(mut expr: &'a Expression<'a>) -> &'a Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(ts) => expr = &ts.expression,
            Expression::TSSatisfiesExpression(ts) => expr = &ts.expression,
            Expression::TSNonNullExpression(ts) => expr = &ts.expression,
            Expression::TSTypeAssertion(ts) => expr = &ts.expression,
            Expression::ChainExpression(_) => return expr,
            _ => return expr,
        }
    }
}

fn is_global_ident(semantic: &Semantic<'_>, ident: &oxc_ast::ast::IdentifierReference<'_>) -> bool {
    ident.reference_id.get().is_none_or(|ref_id| {
        semantic
            .scoping()
            .get_reference(ref_id)
            .symbol_id()
            .is_none()
    })
}

fn resolve_ident_symbol(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    let ref_id = ident.reference_id.get()?;
    semantic.scoping().get_reference(ref_id).symbol_id()
}

// ---------------------------------------------------------------------------
// 1. `async-parallel`
// ---------------------------------------------------------------------------

fn check_async_parallel_in_block(
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
            collect_pattern_bound_names(&decl.id, &mut bound_names);
        }
    }

    let first_span = run[0].span();
    let subject_name = find_enclosing_react_node(semantic, block_node_id)
        .and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::AsyncParallel,
        subject_name,
        message_id: "asyncParallel",
        target_name: "Promise.all".to_string(),
        message: format!(
            "These {} sequential await statements run one after another even though they look independent, so the page waits longer than it needs to. Run them together with Promise.all() instead",
            run.len()
        ),
        loc: loc_from_line_starts(line_starts, first_span.start),
        span: ByteSpan {
            start: first_span.start,
            end: first_span.end,
        },
        autofix: None,
    });
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

fn collect_callee_identifier_trail(expr: &Expression<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = unwrap_expr(expr);
    loop {
        match cur {
            Expression::Identifier(id) => {
                out.push(id.name.to_string());
                break;
            }
            Expression::StaticMemberExpression(mem) => {
                out.push(mem.property.name.to_string());
                cur = unwrap_expr(&mem.object);
            }
            Expression::CallExpression(call) => {
                cur = unwrap_expr(&call.callee);
            }
            _ => break,
        }
    }
    out
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

fn collect_pattern_bound_names(pat: &BindingPattern<'_>, out: &mut HashSet<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => {
            out.insert(id.name.to_string());
        }
        BindingPattern::ObjectPattern(obj) => {
            for prop in &obj.properties {
                collect_pattern_bound_names(&prop.value, out);
            }
            if let Some(rest) = &obj.rest {
                collect_pattern_bound_names(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter().flatten() {
                collect_pattern_bound_names(elem, out);
            }
            if let Some(rest) = &arr.rest {
                collect_pattern_bound_names(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(assign) => {
            collect_pattern_bound_names(&assign.left, out);
        }
    }
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

fn check_loop_rules(
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
    check_js_index_maps_in_loop(
        loop_node_id,
        loop_span,
        loop_body_span,
        semantic,
        line_starts,
        out,
    );
    check_js_set_map_lookups_in_loop(
        loop_node_id,
        loop_span,
        loop_body_span,
        semantic,
        line_starts,
        out,
    );
    check_js_cache_property_access_in_loop(
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
        out.push(SemanticRuleSite {
            rule: RuleId::AsyncAwaitInLoop,
            subject_name,
            message_id: "asyncAwaitInLoop",
            target_name: awaited_expr.clone(),
            message: format!(
                "Avoid sequential `await {awaited_expr}` inside a loop; collect promises and use `await Promise.all(...)`."
            ),
            loc: loc_from_line_starts(line_starts, span.start),
            span: ByteSpan {
                start: span.start,
                end: span.end,
            },
            autofix: None,
        });
    }
}

fn belongs_directly_to_loop(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    target_loop_id: NodeId,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        if anc_id == target_loop_id {
            return true;
        }
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::ForStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::WhileStatement(_)
            | AstKind::DoWhileStatement(_) => return false,
            _ => {}
        }
    }
    false
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

fn is_inside_async_function(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => return f.r#async,
            AstKind::ArrowFunctionExpression(a) => return a.r#async,
            _ => {}
        }
    }
    false
}

fn check_async_defer_await_in_statements(
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
                collect_pattern_bound_names(&decl.id, &mut awaited_bindings);
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
                    collect_pattern_bound_names(&decl.id, &mut awaited_bindings);
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
            let span = stmt.span();
            out.push(SemanticRuleSite {
                rule: RuleId::AsyncDeferAwait,
                subject_name: None,
                message_id: "asyncDeferAwait",
                target_name: "await".to_string(),
                message: "This await blocks the function before an early-return that doesn't use the awaited value, so the skip path waits for nothing. Move the await below the guard so it only runs when you need the data".to_string(),
                loc: loc_from_line_starts(line_starts, span.start),
                span: ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                autofix: None,
            });
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
// 4. `no-spread-accumulator-in-reduce`
// ---------------------------------------------------------------------------

fn check_no_spread_accumulator_in_reduce(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(callee_mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let method = callee_mem.property.name.as_str();
    if method != "reduce" && method != "reduceRight" {
        return;
    }
    // Skip small inline literal array receiver (`[1, 2, 3].reduce(...)`)
    if let Expression::ArrayExpression(arr) = unwrap_expr(&callee_mem.object)
        && arr.elements.len() <= 8
        && arr
            .elements
            .iter()
            .all(|e| !matches!(e, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)))
    {
        return;
    }

    let Some(seed_expr) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    if !matches!(
        unwrap_expr(seed_expr),
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
    ) {
        return;
    }

    let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let (acc_name, body_span) = match unwrap_expr(cb_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            if arrow.r#async {
                return;
            }
            let Some(first_param) = arrow.params.items.first() else {
                return;
            };
            let Some(id) = first_param.pattern.get_binding_identifier() else {
                return;
            };
            (id.name.as_str(), arrow.body.span())
        }
        Expression::FunctionExpression(func) => {
            if func.r#async || func.generator {
                return;
            }
            let Some(first_param) = func.params.items.first() else {
                return;
            };
            let Some(id) = first_param.pattern.get_binding_identifier() else {
                return;
            };
            let Some(body) = &func.body else {
                return;
            };
            (id.name.as_str(), body.span)
        }
        _ => return,
    };

    for (_, inner_node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        match inner_node.kind() {
            AstKind::ObjectExpression(obj) => {
                let spreads_acc = obj.properties.iter().any(|p| {
                    if let ObjectPropertyKind::SpreadProperty(sp) = p
                        && let Expression::Identifier(id) = unwrap_expr(&sp.argument)
                    {
                        id.name == acc_name
                    } else {
                        false
                    }
                });
                let grows_keys = obj.properties.iter().any(|p| match p {
                    ObjectPropertyKind::ObjectProperty(prop) => prop.computed,
                    ObjectPropertyKind::SpreadProperty(sp) => {
                        !matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
                            && !matches!(unwrap_expr(&sp.argument), Expression::ObjectExpression(_))
                    }
                });
                if spreads_acc && grows_keys {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|id| get_subject_name(semantic, id));
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoSpreadAccumulatorInReduce,
                        subject_name,
                        message_id: "noSpreadAccumulatorInReduce",
                        target_name: acc_name.to_string(),
                        message: "This is O(n²) because spreading the accumulator copies the entire growing collection every step. Mutate and return the accumulator instead (acc[key] = value; return acc).".to_string(),
                        loc: loc_from_line_starts(line_starts, obj.span.start),
                        span: ByteSpan {
                            start: obj.span.start,
                            end: obj.span.end,
                        },
                        autofix: None,
                    });
                    return;
                }
            }
            AstKind::ArrayExpression(arr) => {
                let spreads_acc = arr.elements.iter().any(|e| {
                    if let oxc_ast::ast::ArrayExpressionElement::SpreadElement(sp) = e
                        && let Expression::Identifier(id) = unwrap_expr(&sp.argument)
                    {
                        id.name == acc_name
                    } else {
                        false
                    }
                });
                let grows_elems = arr.elements.iter().any(|e| match e {
                    oxc_ast::ast::ArrayExpressionElement::SpreadElement(sp) => {
                        !matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
                    }
                    oxc_ast::ast::ArrayExpressionElement::Elision(_) => false,
                    _ => true,
                });
                if spreads_acc && grows_elems {
                    let subject_name = find_enclosing_react_node(semantic, node_id)
                        .and_then(|id| get_subject_name(semantic, id));
                    out.push(SemanticRuleSite {
                        rule: RuleId::NoSpreadAccumulatorInReduce,
                        subject_name,
                        message_id: "noSpreadAccumulatorInReduce",
                        target_name: acc_name.to_string(),
                        message: "This is O(n²) because spreading the accumulator copies the entire growing collection every step. Mutate and return the accumulator instead (acc[key] = value; return acc).".to_string(),
                        loc: loc_from_line_starts(line_starts, arr.span.start),
                        span: ByteSpan {
                            start: arr.span.start,
                            end: arr.span.end,
                        },
                        autofix: None,
                    });
                    return;
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 5. `no-json-parse-stringify-clone` (with `Autofix` -> `structuredClone(x)`)
// ---------------------------------------------------------------------------

fn check_no_json_parse_stringify_clone(
    path: &Path,
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_json_method_call(call, "parse") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::CallExpression(stringify_call) = unwrap_expr(first_arg) else {
        return;
    };
    if !is_json_method_call(stringify_call, "stringify") {
        return;
    }

    // Skip if replacer is a function or array expression
    if let Some(replacer) = stringify_call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)
        && matches!(
            unwrap_expr(replacer),
            Expression::ArrowFunctionExpression(_)
                | Expression::FunctionExpression(_)
                | Expression::ArrayExpression(_)
        )
    {
        return;
    }
    // Skip if reviver is a function expression
    if let Some(reviver) = call.arguments.get(1).and_then(Argument::as_expression)
        && matches!(
            unwrap_expr(reviver),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        )
    {
        return;
    }

    if is_inside_snapshot_or_serialize_helper(semantic, node_id) {
        return;
    }
    if is_assigned_to_normalization_binding(semantic, node_id) {
        return;
    }
    if is_catch_param_round_trip(semantic, node_id, stringify_call) {
        return;
    }
    if is_inside_nextjs_page_props(path, semantic, node_id) {
        return;
    }

    let Some(cloned_arg) = stringify_call
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return;
    };
    let cloned_text = cloned_arg.span().source_text(semantic.source_text()).trim();

    let span = ByteSpan {
        start: call.span.start,
        end: call.span.end,
    };
    let has_custom_replacer_or_reviver = call.arguments.len() > 1
        || stringify_call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(|r| !matches!(unwrap_expr(r), Expression::NullLiteral(_)));

    let autofix =
        (!has_custom_replacer_or_reviver && !cloned_text.is_empty()).then(|| AutofixPatch {
            description: format!(
                "Replace `JSON.parse(JSON.stringify(...))` with `structuredClone({cloned_text})`"
            ),
            edits: vec![ByteEdit {
                file: None,
                span,
                replacement: format!("structuredClone({cloned_text})"),
            }],
        });

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoJsonParseStringifyClone,
        subject_name,
        message_id: "noJsonParseStringifyClone",
        target_name: "JSON.parse".to_string(),
        message: "`JSON.parse(JSON.stringify(x))` deep-clones by re-serializing: it is slow on large objects and silently drops `undefined`, functions, `Date`/`Map`/`Set`, and cyclic references. Use `structuredClone(x)`.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span,
        autofix,
    });
}

fn is_json_method_call(call: &CallExpression<'_>, method: &str) -> bool {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return false;
    };
    mem.property.name == method
        && matches!(
            unwrap_expr(&mem.object),
            Expression::Identifier(id) if id.name == "JSON"
        )
}

fn is_inside_snapshot_or_serialize_helper(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let bound_name: Option<String> = match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                func.id.as_ref().map(|id| id.name.to_string()).or_else(|| {
                    if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(anc_id)
                    {
                        decl.id
                            .get_binding_identifier()
                            .map(|id| id.name.to_string())
                    } else {
                        None
                    }
                })
            }
            AstKind::ArrowFunctionExpression(_) => {
                if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(anc_id) {
                    decl.id
                        .get_binding_identifier()
                        .map(|id| id.name.to_string())
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(name) = bound_name {
            if is_component_name(&name) {
                return false;
            }
            let lower = name.to_ascii_lowercase();
            return lower.contains("snapshot")
                || lower.contains("serializ")
                || lower.contains("tojson")
                || lower.contains("jsonsafe");
        }
    }
    false
}

fn is_assigned_to_normalization_binding(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(node_id)
        && let Some(id) = decl.id.get_binding_identifier()
    {
        let lower = id.name.to_ascii_lowercase();
        return lower.contains("normaliz") || lower.contains("normalis");
    }
    false
}

fn is_catch_param_round_trip(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    stringify_call: &CallExpression<'_>,
) -> bool {
    let Some(arg) = stringify_call
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return false;
    };
    let Expression::Identifier(arg_id) = unwrap_expr(arg) else {
        return false;
    };
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => {
                if f.params.items.iter().any(|p| {
                    p.pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                }) {
                    return false;
                }
            }
            AstKind::ArrowFunctionExpression(a) => {
                if a.params.items.iter().any(|p| {
                    p.pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                }) {
                    return false;
                }
            }
            AstKind::CatchClause(catch_clause) => {
                if let Some(param) = &catch_clause.param
                    && param
                        .pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_inside_nextjs_page_props(path: &Path, semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let norm = path.to_string_lossy().replace('\\', "/");
    if (!norm.contains("/pages/") && !norm.starts_with("pages/")) || norm.contains("pages/api") {
        return false;
    }
    is_inside_nextjs_server_data_function(semantic, node_id)
}

fn is_inside_nextjs_server_data_function(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => {
                if let Some(id) = &f.id
                    && matches!(
                        id.name.as_str(),
                        "getServerSideProps" | "getStaticProps" | "getStaticPaths"
                    )
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && matches!(
                        id.name.as_str(),
                        "getServerSideProps" | "getStaticProps" | "getStaticPaths"
                    )
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 6. `no-sync-xhr` & `no-document-write` & `no-create-object-url-without-revoke`
// ---------------------------------------------------------------------------

fn check_no_sync_xhr(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "open" {
        return;
    }
    let Some(third_arg) = call.arguments.get(2).and_then(Argument::as_expression) else {
        return;
    };
    let Expression::BooleanLiteral(b) = unwrap_expr(third_arg) else {
        return;
    };
    if b.value {
        return;
    }
    if !is_proven_xhr_receiver(&mem.object, semantic) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoSyncXhr,
        subject_name,
        message_id: "noSyncXhr",
        target_name: "XMLHttpRequest.open".to_string(),
        message: "A synchronous `XMLHttpRequest` (`.open(method, url, false)`) freezes the main thread until the request finishes, blocking all rendering and input. Use `fetch()` or an async XHR (`open(method, url, true)`).".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn is_proven_xhr_receiver(expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::NewExpression(new_expr) => {
            matches!(
                unwrap_expr(&new_expr.callee),
                Expression::Identifier(id) if id.name == "XMLHttpRequest" && is_global_ident(semantic, id)
            )
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
                && let Some(init) = &decl.init
            {
                return is_proven_xhr_receiver(init, semantic);
            }
            let decl_text = semantic
                .nodes()
                .get_node(decl_id)
                .span()
                .source_text(semantic.source_text());
            decl_text.contains("XMLHttpRequest")
        }
        _ => false,
    }
}

fn check_no_document_write(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let method = mem.property.name.as_str();
    if method != "write" && method != "writeln" {
        return;
    }
    let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if recv_id.name != "document" || !is_global_ident(semantic, recv_id) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoDocumentWrite,
        subject_name,
        message_id: "noDocumentWrite",
        target_name: format!("document.{method}"),
        message: "`document.write()` blocks parsing, is ignored (or wipes the page) after load, and is flagged by browsers as a performance anti-pattern. Build DOM nodes or set `innerHTML`/`textContent` on a target element instead.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_no_create_object_url_without_revoke(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let src = semantic.source_text();
    if !src.contains("createObjectURL") || src.contains("revokeObjectURL") {
        return;
    }
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        if mem.property.name != "createObjectURL" {
            continue;
        }
        let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        if obj_id.name != "URL" || !is_global_ident(semantic, obj_id) {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::NoCreateObjectUrlWithoutRevoke,
            subject_name,
            message_id: "noCreateObjectUrlWithoutRevoke",
            target_name: "URL.createObjectURL".to_string(),
            message: "`URL.createObjectURL()` without a matching `URL.revokeObjectURL()` keeps the Blob/File in memory for the lifetime of the document.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

// ---------------------------------------------------------------------------
// 7. `client-passive-event-listeners` (with `Autofix`)
// ---------------------------------------------------------------------------

fn check_client_passive_event_listeners(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "addEventListener" {
        return;
    }
    if call.arguments.len() < 2 {
        return;
    }
    let Some(event_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::StringLiteral(event_lit) = unwrap_expr(event_arg) else {
        return;
    };
    let Some(event_name) = event_lit.value.as_str() else {
        return;
    };
    if !PASSIVE_EVENT_NAMES.contains(&event_name) {
        return;
    }

    let Some(handler_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    if handler_calls_prevent_default_or_forwards_event(handler_arg, semantic) {
        return;
    }

    let mut autofix: Option<AutofixPatch> = None;
    let call_span = ByteSpan {
        start: call.span.start,
        end: call.span.end,
    };

    if let Some(opts_arg) = call.arguments.get(2) {
        let Some(opts_expr) = opts_arg.as_expression() else {
            return;
        };
        let Expression::ObjectExpression(obj) = unwrap_expr(opts_expr) else {
            return;
        };
        let has_explicit_passive = obj.properties.iter().any(|prop| {
            if let ObjectPropertyKind::ObjectProperty(p) = prop
                && p.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("passive")
                && matches!(unwrap_expr(&p.value), Expression::BooleanLiteral(_))
            {
                true
            } else {
                false
            }
        });
        if has_explicit_passive {
            return;
        }
    } else {
        let raw_call = call.span.source_text(semantic.source_text());
        if let Some(before_close) = raw_call
            .strip_suffix(')')
            .map(|s| s.trim_end().trim_end_matches(','))
        {
            let replacement = format!("{before_close}, {{ passive: true }})");
            autofix = Some(AutofixPatch {
                description: format!("Add `{{ passive: true }}` to `{event_name}` event listener"),
                edits: vec![ByteEdit {
                    file: None,
                    span: call_span,
                    replacement,
                }],
            });
        }
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::ClientPassiveEventListeners,
        subject_name,
        message_id: "clientPassiveEventListeners",
        target_name: event_name.to_string(),
        message: format!(
            "\"{event_name}\" listener without {{ passive: true }} makes scrolling janky for your users. Only add it if the handler doesn't call event.preventDefault(), since passive listeners silently ignore preventDefault()."
        ),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: call_span,
        autofix,
    });
}

fn handler_calls_prevent_default_or_forwards_event(
    handler_expr: &Expression<'_>,
    semantic: &Semantic<'_>,
) -> bool {
    match unwrap_expr(handler_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            let ev_param = arrow.params.items.first().and_then(|p| {
                p.pattern
                    .get_binding_identifier()
                    .map(|id| id.name.as_str())
            });
            function_body_calls_prevent_default_or_forwards(arrow.body.span(), ev_param, semantic)
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            let ev_param = func.params.items.first().and_then(|p| {
                p.pattern
                    .get_binding_identifier()
                    .map(|id| id.name.as_str())
            });
            function_body_calls_prevent_default_or_forwards(body.span, ev_param, semantic)
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(func) => {
                    let Some(body) = &func.body else {
                        return false;
                    };
                    let ev_param = func.params.items.first().and_then(|p| {
                        p.pattern
                            .get_binding_identifier()
                            .map(|id| id.name.as_str())
                    });
                    function_body_calls_prevent_default_or_forwards(body.span, ev_param, semantic)
                }
                AstKind::VariableDeclarator(decl) => {
                    if let Some(init) = &decl.init
                        && handler_calls_prevent_default_or_forwards_event(init, semantic)
                    {
                        return true;
                    }
                    // Also check reassignments (`onTouchMove = (e) => e.preventDefault()`)
                    for reference in semantic.scoping().get_resolved_references(sym_id) {
                        if let AstKind::AssignmentExpression(assign) =
                            semantic.nodes().parent_kind(reference.node_id())
                            && handler_calls_prevent_default_or_forwards_event(
                                &assign.right,
                                semantic,
                            )
                        {
                            return true;
                        }
                    }
                    false
                }
                _ => false,
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if matches!(unwrap_expr(&mem.object), Expression::ThisExpression(_)) {
                let method_name = mem.property.name.as_str();
                return class_or_object_method_calls_prevent_default(method_name, semantic);
            }
            false
        }
        Expression::PrivateFieldExpression(priv_mem) => {
            if matches!(unwrap_expr(&priv_mem.object), Expression::ThisExpression(_)) {
                let method_name = priv_mem.field.name.as_str();
                return class_or_object_method_calls_prevent_default(method_name, semantic);
            }
            false
        }
        _ => false,
    }
}

fn class_or_object_method_calls_prevent_default(
    method_name: &str,
    semantic: &Semantic<'_>,
) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::MethodDefinition(m) => {
                let matches_key = m
                    .key
                    .static_name()
                    .as_ref()
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n == method_name)
                    || matches!(&m.key, oxc_ast::ast::PropertyKey::PrivateIdentifier(p) if p.name == method_name);
                if matches_key && let Some(body) = &m.value.body {
                    let ev_param = m.value.params.items.first().and_then(|p| {
                        p.pattern
                            .get_binding_identifier()
                            .map(|id| id.name.as_str())
                    });
                    if function_body_calls_prevent_default_or_forwards(
                        body.span, ev_param, semantic,
                    ) {
                        return true;
                    }
                }
            }
            AstKind::ObjectProperty(prop)
                if prop
                    .key
                    .static_name()
                    .as_ref()
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n == method_name)
                    && handler_calls_prevent_default_or_forwards_event(&prop.value, semantic) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn function_body_calls_prevent_default_or_forwards(
    body_span: Span,
    ev_param: Option<&str>,
    semantic: &Semantic<'_>,
) -> bool {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        // Skip nested functions (except when checking if event param is forwarded)
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(node_id)
            .skip(1)
            .take_while(|&anc_id| {
                body_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
            })
            .any(|anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_nested_fn {
            continue;
        }
        if let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
            && mem.property.name == "preventDefault"
        {
            return true;
        }
        if let Some(param_name) = ev_param
            && matches!(unwrap_expr(&call.callee), Expression::Identifier(_))
            && call.arguments.iter().any(|arg| {
                arg.as_expression().is_some_and(|e| {
                    matches!(unwrap_expr(e), Expression::Identifier(id) if id.name == param_name)
                })
            })
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 8. `no-flush-sync` & `no-document-start-view-transition`
// ---------------------------------------------------------------------------

fn check_no_flush_sync(
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let imports_imperative_dom_lib = module.imports.iter().any(|imp| {
        imp.source.starts_with("@floating-ui/")
            || imp.source.starts_with("@popperjs/")
            || imp.source == "react-popper"
            || imp.source == "popper.js"
            || imp.source.starts_with("shaka-player")
            || (!imp.is_type_only && imp.source.starts_with("@softmaple/awareness/"))
    });
    if imports_imperative_dom_lib {
        return;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ImportDeclaration(imp) = node.kind() else {
            continue;
        };
        if imp.import_kind.is_type() || imp.source.value != "react-dom" {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            let ImportDeclarationSpecifier::ImportSpecifier(s) = spec else {
                continue;
            };
            if s.import_kind.is_type() || s.imported.name() != "flushSync" {
                continue;
            }
            let local_name = s.local.name.as_str();
            if has_exempt_flush_sync_call(semantic, local_name) {
                return;
            }
            out.push(SemanticRuleSite {
                rule: RuleId::NoFlushSync,
                subject_name: None,
                message_id: "noFlushSync",
                target_name: "flushSync".to_string(),
                message: "`flushSync` forces an immediate update, which skips View Transitions and concurrent rendering.".to_string(),
                loc: loc_from_line_starts(line_starts, s.span.start),
                span: ByteSpan {
                    start: s.span.start,
                    end: s.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn has_exempt_flush_sync_call(semantic: &Semantic<'_>, local_name: &str) -> bool {
    let measuring_helpers = collect_dom_helper_names(semantic, true);
    let mutating_helpers = collect_dom_helper_names(semantic, false);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
            continue;
        };
        if callee_id.name != local_name {
            continue;
        }

        for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
            match semantic.nodes().kind(anc_id) {
                AstKind::CallExpression(anc_call) => {
                    let trail = collect_callee_identifier_trail(&anc_call.callee);
                    if trail.first().is_some_and(|n| n == "startViewTransition") {
                        return true;
                    }
                }
                AstKind::Function(func) => {
                    if let Some(body) = &func.body
                        && (span_has_dom_measurement_or_mutation(body.span, semantic)
                            || span_calls_any_helper(body.span, &measuring_helpers, semantic)
                            || span_calls_any_helper(body.span, &mutating_helpers, semantic))
                    {
                        return true;
                    }
                }
                AstKind::ArrowFunctionExpression(arrow) => {
                    let span = arrow.body.span();
                    if span_has_dom_measurement_or_mutation(span, semantic)
                        || span_calls_any_helper(span, &measuring_helpers, semantic)
                        || span_calls_any_helper(span, &mutating_helpers, semantic)
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn collect_dom_helper_names(semantic: &Semantic<'_>, measure: bool) -> HashSet<String> {
    let mut names = HashSet::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(f) => {
                if let (Some(id), Some(body)) = (&f.id, &f.body)
                    && (if measure {
                        span_has_dom_measurement(body.span, semantic)
                    } else {
                        span_has_dom_mutation(body.span, semantic)
                    })
                {
                    names.insert(id.name.to_string());
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let (Some(id), Some(init)) = (decl.id.get_binding_identifier(), &decl.init) {
                    let span = init.span();
                    if if measure {
                        span_has_dom_measurement(span, semantic)
                    } else {
                        span_has_dom_mutation(span, semantic)
                    } {
                        names.insert(id.name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    names
}

fn span_has_dom_measurement_or_mutation(span: Span, semantic: &Semantic<'_>) -> bool {
    span_has_dom_measurement(span, semantic) || span_has_dom_mutation(span, semantic)
}

fn span_has_dom_measurement(span: Span, semantic: &Semantic<'_>) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::StaticMemberExpression(mem) => {
                if DOM_MEASUREMENT_NAMES.contains(&mem.property.name.as_str()) {
                    return true;
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::Identifier(id) = unwrap_expr(&call.callee) {
                    let name = id.name.as_str();
                    if (name.starts_with("get")
                        || name.starts_with("measure")
                        || name.starts_with("read"))
                        && (name.ends_with("Width")
                            || name.ends_with("Height")
                            || name.ends_with("Rect")
                            || name.ends_with("Rects")
                            || name.ends_with("Size")
                            || name.ends_with("Bounds")
                            || name.ends_with("Position"))
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn span_has_dom_mutation(span: Span, semantic: &Semantic<'_>) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::CallExpression(call) = node.kind()
            && let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
            && IMPERATIVE_DOM_MUTATION_NAMES.contains(&mem.property.name.as_str())
        {
            return true;
        }
    }
    false
}

fn span_calls_any_helper(span: Span, helpers: &HashSet<String>, semantic: &Semantic<'_>) -> bool {
    if helpers.is_empty() {
        return false;
    }
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::CallExpression(call) = node.kind()
            && let Expression::Identifier(id) = unwrap_expr(&call.callee)
            && helpers.contains(id.name.as_str())
        {
            return true;
        }
    }
    false
}

fn check_no_document_start_view_transition(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "startViewTransition" {
        return;
    }
    let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if recv_id.name != "document" || !is_global_ident(semantic, recv_id) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::NoDocumentStartViewTransition,
        subject_name,
        message_id: "noDocumentStartViewTransition",
        target_name: "document.startViewTransition".to_string(),
        message: "Calling `document.startViewTransition()` directly can bypass React's `<ViewTransition>` animation lifecycle.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

// ---------------------------------------------------------------------------
// 9. Remaining `js-*` runtime performance rules
// ---------------------------------------------------------------------------

fn check_js_async_reduce_without_awaited_acc(
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
            out.push(SemanticRuleSite {
                rule: RuleId::JsAsyncReduceWithoutAwaitedAcc,
                subject_name,
                message_id: "jsAsyncReduceWithoutAwaitedAcc",
                target_name: method_name.to_string(),
                message: format!(
                    "This async `.{method_name}` reducer destructures its accumulator, but every run after the first gets a Promise, so the pieces come out empty & the work is lost. Await it first: `async (previous, item) => {{ const [...] = await previous; ...; return [...]; }}`, & seed with `Promise.resolve([...])`"
                ),
                loc: loc_from_line_starts(line_starts, reducer_span.start),
                span: ByteSpan {
                    start: reducer_span.start,
                    end: reducer_span.end,
                },
                autofix: None,
            });
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
                out.push(SemanticRuleSite {
                    rule: RuleId::JsAsyncReduceWithoutAwaitedAcc,
                    subject_name,
                    message_id: "jsAsyncReduceWithoutAwaitedAcc",
                    target_name: acc_name.to_string(),
                    message: format!(
                        "This async `.{method_name}` reducer never awaits its accumulator \"{acc_name}\", so each run gets a Promise instead of the real value & the work is lost."
                    ),
                    loc: loc_from_line_starts(line_starts, reducer_span.start),
                    span: ByteSpan {
                        start: reducer_span.start,
                        end: reducer_span.end,
                    },
                    autofix: None,
                });
            }
        }
        BindingPattern::AssignmentPattern(_) => {}
    }
}

fn check_js_cache_storage(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut counts_by_scope: HashMap<Option<NodeId>, HashMap<(String, String), usize>> =
        HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        if mem.property.name != "getItem" {
            continue;
        }
        let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        let storage_name = recv_id.name.as_str();
        if storage_name != "localStorage" && storage_name != "sessionStorage" {
            continue;
        }
        let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let Expression::StringLiteral(key_lit) = unwrap_expr(first_arg) else {
            continue;
        };
        let Some(key) = key_lit.value.as_str() else {
            continue;
        };

        let scope_fn = find_non_iterator_enclosing_fn(semantic, node_id);
        let scope_map = counts_by_scope.entry(scope_fn).or_default();
        let entry = scope_map
            .entry((storage_name.to_string(), key.to_string()))
            .or_insert(0);
        *entry += 1;
        if *entry == 2 {
            let subject_name = find_enclosing_react_node(semantic, node_id)
                .and_then(|id| get_subject_name(semantic, id));
            out.push(SemanticRuleSite {
                rule: RuleId::JsCacheStorage,
                subject_name,
                message_id: "jsCacheStorage",
                target_name: format!("{storage_name}.getItem"),
                message: format!(
                    "This is slow because {storage_name}.getItem(\"{key}\") runs several times & re-parses the data each call, so read it once & reuse the value"
                ),
                loc: loc_from_line_starts(line_starts, call.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn find_non_iterator_enclosing_fn(semantic: &Semantic<'_>, node_id: NodeId) -> Option<NodeId> {
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            if let AstKind::CallExpression(call) = semantic.nodes().parent_kind(anc_id)
                && let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
                && matches!(
                    mem.property.name.as_str(),
                    "forEach" | "map" | "filter" | "reduce" | "some" | "every"
                )
            {
                continue;
            }
            return Some(anc_id);
        }
    }
    None
}

fn check_js_flatmap_filter(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(outer_mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if outer_mem.property.name != "filter" {
        return;
    }
    let Some(filter_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    if !is_boolean_or_identity_filter(unwrap_expr(filter_arg)) {
        return;
    }
    let Expression::CallExpression(inner_call) = unwrap_expr(&outer_mem.object) else {
        return;
    };
    let Expression::StaticMemberExpression(inner_mem) = unwrap_expr(&inner_call.callee) else {
        return;
    };
    if inner_mem.property.name != "map" {
        return;
    }
    if is_small_or_bounded_array_receiver(unwrap_expr(&inner_mem.object)) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsFlatmapFilter,
        subject_name,
        message_id: "jsFlatmapFilter",
        target_name: "map.filter".to_string(),
        message: "This .map().filter(Boolean) chain creates an intermediate array and traverses it again; if this is a measured hot path, combine the transform and truthy check with .reduce() or for...of".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn is_boolean_or_identity_filter(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == "Boolean",
        Expression::ArrowFunctionExpression(arrow) => {
            let Some(first_param) = arrow.params.items.first() else {
                return false;
            };
            let Some(param_id) = first_param.pattern.get_binding_identifier() else {
                return false;
            };
            match &arrow.body {
                ArrowFunctionBody::FunctionBody(body) => {
                    if body.statements.len() != 1 {
                        return false;
                    }
                    match &body.statements[0] {
                        Statement::ReturnStatement(ret) => {
                            ret.argument.as_ref().is_some_and(|arg| {
                                is_identity_expr(unwrap_expr(arg), param_id.name.as_str())
                            })
                        }
                        Statement::ExpressionStatement(expr_stmt) => is_identity_expr(
                            unwrap_expr(&expr_stmt.expression),
                            param_id.name.as_str(),
                        ),
                        _ => false,
                    }
                }
                ArrowFunctionBody::Identifier(id) => id.name == param_id.name,
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_identity_expr(expr: &Expression<'_>, param_name: &str) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == param_name,
        Expression::UnaryExpression(u1) if u1.operator == UnaryOperator::LogicalNot => {
            if let Expression::UnaryExpression(u2) = unwrap_expr(&u1.argument)
                && u2.operator == UnaryOperator::LogicalNot
                && let Expression::Identifier(id) = unwrap_expr(&u2.argument)
            {
                id.name == param_name
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_small_or_bounded_array_receiver(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::ArrayExpression(arr) => {
            !arr.elements.is_empty()
                && arr.elements.len() <= 9
                && arr
                    .elements
                    .iter()
                    .all(|e| !matches!(e, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)))
        }
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
                && matches!(
                    mem.property.name.as_str(),
                    "split" | "slice" | "values" | "keys" | "entries"
                )
                && !matches!(unwrap_expr(&mem.object), Expression::Identifier(id) if id.name == "Object")
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

fn check_js_combine_iterations(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    covered_chain_spans: &mut HashSet<Span>,
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(outer_mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let outer_method = outer_mem.property.name.as_str();
    if !CHAINABLE_ITERATION_METHODS.contains(&outer_method) {
        return;
    }
    let Expression::CallExpression(inner_call) = unwrap_expr(&outer_mem.object) else {
        return;
    };
    let Expression::StaticMemberExpression(inner_mem) = unwrap_expr(&inner_call.callee) else {
        return;
    };
    let inner_method = inner_mem.property.name.as_str();
    if !CHAINABLE_ITERATION_METHODS.contains(&inner_method) {
        return;
    }

    if covered_chain_spans.contains(&call.span) {
        covered_chain_spans.insert(inner_call.span);
        return;
    }
    if outer_method == "filter"
        && call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|e| is_boolean_or_identity_filter(unwrap_expr(e)))
    {
        return;
    }
    if inner_method == "filter"
        && inner_call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|e| is_boolean_or_identity_filter(unwrap_expr(e)))
    {
        return;
    }
    if is_small_or_bounded_array_receiver(unwrap_expr(&inner_mem.object)) {
        return;
    }

    covered_chain_spans.insert(inner_call.span);
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsCombineIterations,
        subject_name,
        message_id: "jsCombineIterations",
        target_name: format!("{inner_method}.{outer_method}"),
        message: format!(
            "This loops over your list twice because .{inner_method}().{outer_method}() makes two passes, so do it in one pass with .reduce() or a for...of loop"
        ),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_js_min_max_loop(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "sort" && mem.property.name != "toSorted" {
        return;
    }
    let Some(comp_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    if !is_numeric_sort_comparator(unwrap_expr(comp_arg), semantic.source_text()) {
        return;
    }

    let parent_kind = semantic.nodes().parent_kind(node_id);
    let is_indexed_zero = match parent_kind {
        AstKind::ComputedMemberExpression(comp) => {
            matches!(unwrap_expr(&comp.expression), Expression::NumericLiteral(n) if n.value == 0.0)
        }
        AstKind::CallExpression(parent_call) => {
            if let Expression::StaticMemberExpression(parent_mem) = unwrap_expr(&parent_call.callee)
                && parent_mem.property.name == "at"
                && let Some(arg) = parent_call
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
            {
                matches!(unwrap_expr(arg), Expression::NumericLiteral(n) if n.value == 0.0)
            } else {
                false
            }
        }
        _ => false,
    };
    if !is_indexed_zero {
        return;
    }

    let parent_span = semantic
        .nodes()
        .get_node(semantic.nodes().parent_id(node_id))
        .span();
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsMinMaxLoop,
        subject_name,
        message_id: "jsMinMaxLoop",
        target_name: mem.property.name.to_string(),
        message: "Sorting the entire array just to read the minimum or maximum element is O(n log n); use `Math.min`/`Math.max` or a single-pass loop instead.".to_string(),
        loc: loc_from_line_starts(line_starts, parent_span.start),
        span: ByteSpan {
            start: parent_span.start,
            end: parent_span.end,
        },
        autofix: None,
    });
}

fn is_numeric_sort_comparator(expr: &Expression<'_>, source: &str) -> bool {
    let Expression::ArrowFunctionExpression(arrow) = expr else {
        return false;
    };
    if arrow.params.items.len() != 2 {
        return false;
    }
    let body_text = arrow.body.span().source_text(source);
    body_text.contains('-')
}

fn check_js_length_check_first(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "every" {
        return;
    }
    let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::ArrowFunctionExpression(arrow) = unwrap_expr(cb_arg) else {
        return;
    };
    if arrow.params.items.len() < 2 {
        return;
    }
    let Some(idx_param) = arrow.params.items[1].pattern.get_binding_identifier() else {
        return;
    };
    let body_text = arrow.body.span().source_text(semantic.source_text());
    if !body_text.contains(&format!("[{}]", idx_param.name))
        || (!body_text.contains("===") && !body_text.contains("=="))
    {
        return;
    }

    // Check if an enclosing logical `&&` or earlier `if` in the function already checks `.length`
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        match semantic.nodes().kind(anc_id) {
            AstKind::LogicalExpression(log) if log.operator == LogicalOperator::And => {
                if log
                    .left
                    .span()
                    .source_text(semantic.source_text())
                    .contains(".length")
                {
                    return;
                }
            }
            AstKind::Function(f) => {
                if let Some(b) = &f.body
                    && b.span.source_text(semantic.source_text())
                        [..(call.span.start - b.span.start) as usize]
                        .contains(".length")
                {
                    return;
                }
                break;
            }
            AstKind::ArrowFunctionExpression(a) => {
                let b_span = a.body.span();
                if call.span.start >= b_span.start
                    && b_span.source_text(semantic.source_text())
                        [..(call.span.start - b_span.start) as usize]
                        .contains(".length")
                {
                    return;
                }
                break;
            }
            _ => {}
        }
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsLengthCheckFirst,
        subject_name,
        message_id: "jsLengthCheckFirst",
        target_name: "every".to_string(),
        message: "Comparing arrays element-by-element with `.every()` without checking `a.length === b.length` first does unnecessary work when lengths differ.".to_string(),
        loc: loc_from_line_starts(line_starts, call.span.start),
        span: ByteSpan {
            start: call.span.start,
            end: call.span.end,
        },
        autofix: None,
    });
}

fn check_js_hoist_intl(
    node_id: NodeId,
    new_expr: &oxc_ast::ast::NewExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&new_expr.callee) else {
        return;
    };
    let class_name = mem.property.name.as_str();
    if !INTL_CLASSES.contains(&class_name) {
        return;
    }
    let Expression::Identifier(intl_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if intl_id.name != "Intl" || !is_global_ident(semantic, intl_id) {
        return;
    }

    let mut in_fn = false;
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                in_fn = true;
                if let AstKind::CallExpression(call) = semantic.nodes().parent_kind(anc_id) {
                    let trail = collect_callee_identifier_trail(&call.callee);
                    if trail
                        .first()
                        .is_some_and(|n| matches!(n.as_str(), "useMemo" | "useCallback" | "useRef"))
                    {
                        return;
                    }
                }
                break;
            }
            AstKind::TryStatement(_) => return,
            _ => {}
        }
    }
    if !in_fn {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsHoistIntl,
        subject_name,
        message_id: "jsHoistIntl",
        target_name: format!("Intl.{class_name}"),
        message: format!(
            "This is slow because new Intl.{class_name}() rebuilds on every call inside a function, so move it to the top of the file, or wrap it in useMemo"
        ),
        loc: loc_from_line_starts(line_starts, new_expr.span.start),
        span: ByteSpan {
            start: new_expr.span.start,
            end: new_expr.span.end,
        },
        autofix: None,
    });
}

fn check_js_hoist_regexp_call(
    node_id: NodeId,
    span: Span,
    callee: &Expression<'_>,
    arguments: &[Argument<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(callee) else {
        return;
    };
    if callee_id.name != "RegExp" || !is_global_ident(semantic, callee_id) {
        return;
    }
    let Some(first_arg) = arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let is_static_pat = match unwrap_expr(first_arg) {
        Expression::StringLiteral(_) | Expression::RegExpLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        _ => false,
    };
    if !is_static_pat {
        return;
    }
    if let Some(flags_arg) = arguments.get(1).and_then(Argument::as_expression) {
        if let Expression::StringLiteral(flags_lit) = unwrap_expr(flags_arg) {
            let f = flags_lit.value.as_str().unwrap_or_default();
            if f.contains('g') || f.contains('y') {
                return;
            }
        } else {
            return;
        }
    }

    let in_loop = semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::ForStatement(_)
                    | AstKind::ForOfStatement(_)
                    | AstKind::ForInStatement(_)
                    | AstKind::WhileStatement(_)
                    | AstKind::DoWhileStatement(_)
            )
        });
    if !in_loop {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    out.push(SemanticRuleSite {
        rule: RuleId::JsHoistRegexp,
        subject_name,
        message_id: "jsHoistRegexp",
        target_name: "RegExp".to_string(),
        message: "`new RegExp()` rebuilds the pattern on every loop pass. Move it to a constant outside the loop.".to_string(),
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix: None,
    });
}

fn check_js_index_maps_in_loop(
    loop_node_id: NodeId,
    loop_span: Span,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id) {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        let method = mem.property.name.as_str();
        if method != "find" && method != "findIndex" {
            continue;
        }
        let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        // Skip SCREAMING_SNAKE_CASE constant tables
        if recv_id
            .name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        // Skip if receiver is declared inside the loop
        if let Some(sym_id) = resolve_ident_symbol(semantic, recv_id) {
            let decl_span = semantic
                .nodes()
                .get_node(semantic.scoping().symbol_declaration(sym_id))
                .span();
            if loop_span.contains_inclusive(decl_span) {
                continue;
            }
        }
        let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let Expression::ArrowFunctionExpression(arrow) = unwrap_expr(cb_arg) else {
            continue;
        };
        let body_src = arrow.body.span().source_text(semantic.source_text());
        if !body_src.contains("===") && !body_src.contains("==") {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::JsIndexMaps,
            subject_name,
            message_id: "jsIndexMaps",
            target_name: method.to_string(),
            message: format!(
                "This gets slow as your list grows because array.{method}() runs inside a loop, so build a Map once before the loop for instant lookups"
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_js_set_map_lookups_in_loop(
    loop_node_id: NodeId,
    loop_span: Span,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id) {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        let method = mem.property.name.as_str();
        if method != "includes" && method != "indexOf" {
            continue;
        }
        if call.arguments.len() != 1 {
            continue;
        }
        let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        if recv_id
            .name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        if let Some(sym_id) = resolve_ident_symbol(semantic, recv_id) {
            let decl_span = semantic
                .nodes()
                .get_node(semantic.scoping().symbol_declaration(sym_id))
                .span();
            if loop_span.contains_inclusive(decl_span) {
                continue;
            }
        }
        if let Some(arg) = call.arguments.first().and_then(Argument::as_expression)
            && matches!(unwrap_expr(arg), Expression::StringLiteral(_))
        {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::JsSetMapLookups,
            subject_name,
            message_id: "jsSetMapLookups",
            target_name: format!("{}.{method}", recv_id.name),
            message: format!(
                "Calling `{}.{method}()` inside a loop scans the array on every iteration; convert `{}` to a `Set` before the loop for O(1) lookups.",
                recv_id.name, recv_id.name
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_js_cache_property_access_in_loop(
    loop_node_id: NodeId,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut counts: HashMap<String, (usize, Span)> = HashMap::new();
    let mut written: HashSet<String> = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id) {
            continue;
        }
        match node.kind() {
            AstKind::AssignmentExpression(assign) => {
                let lhs = assign
                    .left
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                written.insert(lhs.to_string());
            }
            AstKind::UpdateExpression(upd) => {
                let arg = upd
                    .argument
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                written.insert(arg.to_string());
            }
            AstKind::StaticMemberExpression(mem) => {
                let parent_kind = semantic.nodes().parent_kind(node_id);
                if matches!(
                    parent_kind,
                    AstKind::StaticMemberExpression(_) | AstKind::CallExpression(_)
                ) {
                    continue;
                }
                if let AstKind::AssignmentExpression(assign) = parent_kind
                    && assign.left.span() == mem.span
                {
                    continue;
                }
                let raw = mem.span.source_text(semantic.source_text()).trim();
                if raw.contains('(') || raw.contains('[') || raw.contains(' ') {
                    continue;
                }
                if raw.split('.').count() < 3 || raw.ends_with(".length") {
                    continue;
                }
                let entry = counts.entry(raw.to_string()).or_insert((0, mem.span));
                entry.0 += 1;
            }
            _ => {}
        }
    }

    for (key, (count, first_span)) in counts {
        if count < 3 {
            continue;
        }
        if written
            .iter()
            .any(|w| key == *w || key.starts_with(&format!("{w}.")))
        {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, loop_node_id)
            .and_then(|id| get_subject_name(semantic, id));
        out.push(SemanticRuleSite {
            rule: RuleId::JsCachePropertyAccess,
            subject_name,
            message_id: "jsCachePropertyAccess",
            target_name: key.clone(),
            message: format!(
                "This may slow the loop because {key} is read {count} times inside it; if the value stays unchanged between those reads, cache it immediately before the first read"
            ),
            loc: loc_from_line_starts(line_starts, first_span.start),
            span: ByteSpan {
                start: first_span.start,
                end: first_span.end,
            },
            autofix: None,
        });
    }
}

fn check_js_batch_dom_css_in_block(
    block_node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let in_loop = semantic.nodes().ancestor_ids(block_node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ForStatement(_)
                | AstKind::ForOfStatement(_)
                | AstKind::ForInStatement(_)
                | AstKind::WhileStatement(_)
                | AstKind::DoWhileStatement(_)
        )
    });
    if !in_loop || statements.len() < 2 {
        return;
    }

    let block_span = semantic.nodes().get_node(block_node_id).span();
    if !span_has_dom_measurement(block_span, semantic) {
        return;
    }

    for idx in 1..statements.len() {
        if is_style_write_stmt(&statements[idx], semantic.source_text())
            && is_style_write_stmt(&statements[idx - 1], semantic.source_text())
        {
            let span = statements[idx].span();
            let subject_name = find_enclosing_react_node(semantic, block_node_id)
                .and_then(|id| get_subject_name(semantic, id));
            out.push(SemanticRuleSite {
                rule: RuleId::JsBatchDomCss,
                subject_name,
                message_id: "jsBatchDomCss",
                target_name: "style".to_string(),
                message: "This makes the browser recalculate layout again & again because element.style writes are interleaved with layout reads inside a loop, so do all reads first, then set the styles at once with cssText or a CSS class".to_string(),
                loc: loc_from_line_starts(line_starts, span.start),
                span: ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                autofix: None,
            });
            return;
        }
    }
}

fn is_style_write_stmt(stmt: &Statement<'_>, source: &str) -> bool {
    let Statement::ExpressionStatement(expr_stmt) = stmt else {
        return false;
    };
    let Expression::AssignmentExpression(assign) = unwrap_expr(&expr_stmt.expression) else {
        return false;
    };
    let lhs = assign.left.span().source_text(source);
    lhs.contains(".style.")
}
