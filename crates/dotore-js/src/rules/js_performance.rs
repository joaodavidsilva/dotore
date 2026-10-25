//! JavaScript runtime performance, client DOM, and View Transitions rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JS performance rule detectors match only relevant AST node kinds"
)]

mod async_waterfalls;
mod collections_and_loops;
mod dom_and_browser;
mod loop_hoisting_and_lookups;
use std::{collections::HashSet, path::Path};

use oxc_ast::{AstKind, ast::Expression};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::types::{ModuleIr, SemanticRuleSite},
    matchers::unwrap_expr,
};

pub(super) const SEQUENTIAL_AWAIT_THRESHOLD: usize = 3;

pub(super) const PASSIVE_EVENT_NAMES: &[&str] = &["wheel", "mousewheel", "touchstart", "touchmove"];

pub(super) const ORDERED_UI_FLOW_CALLEES: &[&str] = &[
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

pub(super) const INTENTIONAL_SEQUENCING_CALLEES: &[&str] = &[
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

pub(super) const CANCELLATION_GUARD_NAMES: &[&str] = &[
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

pub(super) const CANCELLATION_FRAGMENTS: &[&str] = &[
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

pub(super) const DOM_MEASUREMENT_NAMES: &[&str] = &[
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

pub(super) const IMPERATIVE_DOM_MUTATION_NAMES: &[&str] = &[
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

pub(super) const INTL_CLASSES: &[&str] = &[
    "NumberFormat",
    "DateTimeFormat",
    "Collator",
    "RelativeTimeFormat",
    "ListFormat",
    "PluralRules",
    "Segmenter",
    "DisplayNames",
];

pub(super) const CHAINABLE_ITERATION_METHODS: &[&str] = &["map", "filter", "forEach", "flatMap"];

/// Extracts JS performance, client DOM, and View Transitions rule sites during the single OXC pass.
pub(crate) fn extract_js_performance_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let has_test_import = module_has_test_import(module);
    let path_str = path.to_string_lossy().replace('\\', "/");
    let is_browser_test_file = path_str.contains(".browser.");
    let is_public_asset = path_str.starts_with("public/") || path_str.contains("/public/");
    let imports_react_view_transition = module_imports_react_view_transition(module);

    dom_and_browser::check_no_flush_sync(semantic, module, line_starts, out);
    dom_and_browser::check_js_cache_storage(semantic, line_starts, out);
    dom_and_browser::check_no_create_object_url_without_revoke(semantic, line_starts, out);

    let mut covered_chain_spans: HashSet<Span> = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        check_js_performance_ast_node(
            path,
            node_id,
            node.kind(),
            (has_test_import, is_browser_test_file, is_public_asset, imports_react_view_transition),
            semantic,
            line_starts,
            &mut covered_chain_spans,
            out,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Dispatches single-pass JS performance AST node checks (#50)"
)]
fn check_js_performance_ast_node(
    path: &Path,
    node_id: NodeId,
    kind: AstKind<'_>,
    flags: (bool, bool, bool, bool),
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    covered_chain_spans: &mut HashSet<Span>,
    out: &mut Vec<SemanticRuleSite>,
) {
    let (has_test_import, is_browser_test_file, is_public_asset, imports_react_view_transition) =
        flags;
    if let Some(loop_body_span) = extract_non_await_loop_body_span(kind) {
        async_waterfalls::check_loop_rules(
            node_id,
            loop_body_span,
            has_test_import,
            semantic,
            line_starts,
            out,
        );
        return;
    }
    match kind {
        AstKind::BlockStatement(block) => {
            check_statement_block_performance_rules(
                node_id,
                &block.body,
                has_test_import,
                is_browser_test_file,
                semantic,
                line_starts,
                out,
            );
        }
        AstKind::FunctionBody(body)
            if body
                .span
                .source_text(semantic.source_text())
                .trim_start()
                .starts_with('{') =>
        {
            check_statement_block_performance_rules(
                node_id,
                &body.statements,
                has_test_import,
                is_browser_test_file,
                semantic,
                line_starts,
                out,
            );
        }
        AstKind::SwitchCase(case)
            if async_waterfalls::is_inside_async_function(semantic, node_id) =>
        {
            async_waterfalls::check_async_defer_await_in_statements(
                &case.consequent,
                semantic,
                line_starts,
                out,
            );
        }
        AstKind::CallExpression(call) => {
            check_call_performance_rules(
                path,
                node_id,
                call,
                is_public_asset,
                imports_react_view_transition,
                semantic,
                line_starts,
                covered_chain_spans,
                out,
            );
        }
        AstKind::NewExpression(new_expr) => {
            collections_and_loops::check_js_hoist_intl(
                node_id,
                new_expr,
                semantic,
                line_starts,
                out,
            );
            collections_and_loops::check_js_hoist_regexp_call(
                node_id,
                new_expr.span,
                &new_expr.callee,
                &new_expr.arguments,
                semantic,
                line_starts,
                out,
            );
        }
        AstKind::IfStatement(if_stmt) => {
            collections_and_loops::check_js_early_exit(
                node_id,
                if_stmt,
                semantic,
                line_starts,
                out,
            );
        }
        _ => {}
    }
}

fn extract_non_await_loop_body_span(kind: AstKind<'_>) -> Option<Span> {
    match kind {
        AstKind::ForStatement(s) => Some(s.body.span()),
        AstKind::ForOfStatement(s) if !s.r#await => Some(s.body.span()),
        AstKind::ForInStatement(s) => Some(s.body.span()),
        AstKind::WhileStatement(s) => Some(s.body.span()),
        AstKind::DoWhileStatement(s) => Some(s.body.span()),
        _ => None,
    }
}

fn module_has_test_import(module: &ModuleIr) -> bool {
    module.imports.iter().any(|imp| {
        TEST_LIBRARY_IMPORTS.contains(&imp.source.as_str())
            || [
                "@testing-library/",
                "@playwright/",
                "vitest/",
                "@vitest/",
                "@storybook/",
            ]
            .iter()
            .any(|prefix| imp.source.starts_with(prefix))
    })
}

fn module_imports_react_view_transition(module: &ModuleIr) -> bool {
    module.imports.iter().any(|imp| {
        imp.source == "react"
            && !imp.is_type_only
            && imp.bindings.iter().any(|b| {
                !b.is_type_only
                    && matches!(
                        b.imported_name.as_str(),
                        "ViewTransition" | "unstable_ViewTransition"
                    )
            })
    })
}

fn check_statement_block_performance_rules(
    node_id: NodeId,
    statements: &[oxc_ast::ast::Statement<'_>],
    has_test_import: bool,
    is_browser_test_file: bool,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !has_test_import && !is_browser_test_file {
        async_waterfalls::check_async_parallel_in_block(
            node_id,
            statements,
            semantic,
            line_starts,
            out,
        );
    }
    if async_waterfalls::is_inside_async_function(semantic, node_id) {
        async_waterfalls::check_async_defer_await_in_statements(
            statements,
            semantic,
            line_starts,
            out,
        );
    }
    dom_and_browser::check_js_batch_dom_css_in_block(
        node_id,
        statements,
        semantic,
        line_starts,
        out,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Dispatches all CallExpression JS performance detectors in a single AST pass (#50)"
)]
fn check_call_performance_rules(
    path: &Path,
    node_id: NodeId,
    call: &oxc_ast::ast::CallExpression<'_>,
    is_public_asset: bool,
    imports_react_view_transition: bool,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    covered_chain_spans: &mut HashSet<Span>,
    out: &mut Vec<SemanticRuleSite>,
) {
    collections_and_loops::check_no_json_parse_stringify_clone(
        path,
        node_id,
        call,
        semantic,
        line_starts,
        out,
    );
    if !is_public_asset {
        dom_and_browser::check_no_sync_xhr(node_id, call, semantic, line_starts, out);
    }
    dom_and_browser::check_no_document_write(node_id, call, semantic, line_starts, out);
    collections_and_loops::check_no_spread_accumulator_in_reduce(
        node_id,
        call,
        semantic,
        line_starts,
        out,
    );
    async_waterfalls::check_js_async_reduce_without_awaited_acc(
        node_id,
        call,
        semantic,
        line_starts,
        out,
    );
    dom_and_browser::check_client_passive_event_listeners(
        node_id,
        call,
        semantic,
        line_starts,
        out,
    );
    if imports_react_view_transition {
        dom_and_browser::check_no_document_start_view_transition(
            node_id,
            call,
            semantic,
            line_starts,
            out,
        );
    }
    collections_and_loops::check_js_flatmap_filter(node_id, call, semantic, line_starts, out);
    collections_and_loops::check_js_combine_iterations(
        node_id,
        call,
        semantic,
        line_starts,
        covered_chain_spans,
        out,
    );
    collections_and_loops::check_js_min_max_loop(node_id, call, semantic, line_starts, out);
    collections_and_loops::check_js_length_check_first(node_id, call, semantic, line_starts, out);
    collections_and_loops::check_js_hoist_regexp_call(
        node_id,
        call.span,
        &call.callee,
        &call.arguments,
        semantic,
        line_starts,
        out,
    );
    collections_and_loops::check_js_tosorted_immutable(node_id, call, semantic, line_starts, out);
    dom_and_browser::check_client_localstorage_no_version(
        node_id,
        call,
        semantic,
        line_starts,
        out,
    );
}

pub(super) fn collect_callee_identifier_trail(expr: &Expression<'_>) -> Vec<String> {
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

pub(super) fn belongs_directly_to_loop(
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::*;
    use crate::{
        ir::{compute_line_starts, parse_file_ir, types::SemanticRuleSite},
        rules::RuleId,
    };

    fn run_js_perf(path: &str, src: &str) -> Vec<SemanticRuleSite> {
        let line_starts = compute_line_starts(src);
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let sem = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let file = parse_file_ir(Path::new(path), src);
        let mut sites = Vec::new();
        extract_js_performance_sites(
            Path::new(path),
            &sem,
            &file.module,
            &line_starts,
            &mut sites,
        );
        sites
    }

    #[test]
    fn extracts_async_waterfalls_rules() {
        let src = r#"
export async function loadDashboard(items: string[], skip: boolean) {
    const a = await fetchA();
    const b = await fetchB();
    const c = await fetchC();

    const deferred = await fetchDeferred();
    if (skip) {
        return null;
    }

    for (const item of items) {
        await fetchItem(item);
    }

    await items.reduce(async (acc, item) => {
        const res = await fetchItem(item);
        return [...acc, res];
    }, []);

    return [a, b, c, deferred];
}
"#;
        let sites = run_js_perf("src/dashboard.ts", src);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::AsyncParallel));
        assert!(rules.contains(&RuleId::AsyncDeferAwait));
        assert!(rules.contains(&RuleId::AsyncAwaitInLoop));
        assert!(rules.contains(&RuleId::JsAsyncReduceWithoutAwaitedAcc));
    }

    #[test]
    fn extracts_dom_and_browser_rules() {
        let src = r#"
import { ViewTransition } from "react";
import { flushSync } from "react-dom";

export function FlushOnly() {
    flushSync(() => {});
    return null;
}

export function BrowserView(blob: Blob, items: HTMLElement[]) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", "/api", false);
    document.write("<p>hi</p>");
    const url = URL.createObjectURL(blob);
    window.addEventListener("wheel", (e) => {
        console.log(e);
    });
    document.startViewTransition(() => {});
    const t1 = localStorage.getItem("theme");
    const t2 = localStorage.getItem("theme");
    for (const el of items) {
        const h = el.offsetHeight;
        el.style.width = `${h}px`;
        el.style.height = `${h}px`;
    }
    return <ViewTransition>{url}{t1}{t2}</ViewTransition>;
}
"#;
        let sites = run_js_perf("src/BrowserView.tsx", src);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::NoSyncXhr));
        assert!(rules.contains(&RuleId::NoDocumentWrite));
        assert!(rules.contains(&RuleId::NoCreateObjectUrlWithoutRevoke));
        assert!(rules.contains(&RuleId::ClientPassiveEventListeners));
        assert!(rules.contains(&RuleId::NoFlushSync));
        assert!(rules.contains(&RuleId::NoDocumentStartViewTransition));
        assert!(rules.contains(&RuleId::JsCacheStorage));
        assert!(rules.contains(&RuleId::JsBatchDomCss));
        assert!(rules.contains(&RuleId::ClientLocalstorageNoVersion));

        let passive_site = sites
            .iter()
            .find(|s| s.rule == RuleId::ClientPassiveEventListeners)
            .expect("passive listener site");
        assert!(passive_site.autofix.is_some());
    }

    #[test]
    fn extracts_collections_and_loops_rules() {
        let src = r#"
export function processList(
    items: Array<{ id: string; val: number }>,
    lookup: Array<{ id: string }>,
    allowed: string[],
    other: string[],
    config: { nested: { limit: number } },
    a: boolean,
    b: boolean,
    c: boolean,
) {
    const cloned = JSON.parse(JSON.stringify(items));
    const grouped = items.reduce((acc, item) => ({ ...acc, [item.id]: item.val }), {});
    const truthy = items.map((x) => x.id).filter(Boolean);
    const chained = items.map((x) => x.val).filter((v) => v > 0);
    const smallest = items.sort((x, y) => x.val - y.val)[0];
    const same = allowed.every((v, idx) => v === other[idx]);
    const fmt = new Intl.NumberFormat("en-US");
    const sorted = [...items].sort();

    for (const item of items) {
        const re = new RegExp("^a");
        const found = lookup.find((x) => x.id === item.id);
        const ok = allowed.includes(item.id);
        const total = config.nested.limit + config.nested.limit + config.nested.limit;
        if (re.test(item.id) && found && ok && total > 0) {
            console.log(fmt.format(total));
        }
    }

    if (a) {
        if (b) {
            if (c) {
                console.log(cloned, grouped, truthy, chained, smallest, same, sorted);
            }
        }
    }
}
"#;
        let sites = run_js_perf("src/collections.ts", src);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::NoJsonParseStringifyClone));
        assert!(rules.contains(&RuleId::NoSpreadAccumulatorInReduce));
        assert!(rules.contains(&RuleId::JsFlatmapFilter));
        assert!(rules.contains(&RuleId::JsCombineIterations));
        assert!(rules.contains(&RuleId::JsMinMaxLoop));
        assert!(rules.contains(&RuleId::JsLengthCheckFirst));
        assert!(rules.contains(&RuleId::JsHoistIntl));
        assert!(rules.contains(&RuleId::JsHoistRegexp));
        assert!(rules.contains(&RuleId::JsIndexMaps));
        assert!(rules.contains(&RuleId::JsSetMapLookups));
        assert!(rules.contains(&RuleId::JsCachePropertyAccess));
        assert!(rules.contains(&RuleId::JsTosortedImmutable));
        assert!(rules.contains(&RuleId::JsEarlyExit));

        let clone_site = sites
            .iter()
            .find(|s| s.rule == RuleId::NoJsonParseStringifyClone)
            .expect("json clone site");
        assert!(clone_site.autofix.is_some());

        let tosorted_site = sites
            .iter()
            .find(|s| s.rule == RuleId::JsTosortedImmutable)
            .expect("toSorted site");
        assert!(tosorted_site.autofix.is_some());
    }
}
