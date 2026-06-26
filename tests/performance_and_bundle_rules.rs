//! Integration tests for Ticket #08: Performance, JS Performance, Client, View Transitions,
//! and Bundle Size rule families, including deterministic `Autofix` patches and adversarial
//! regression coverage.

use std::path::{Path, PathBuf};

use dotore::{
    PrescriptionTier, RuleId, analyze_project_sources, analyze_source, apply_patches_to_source,
};

#[test]
fn bundle_size_rules_detect_invalid_and_autofix_and_preserve_adversarial_valid_cases() {
    // 1. no-barrel-import across ProjectGraph
    let barrel_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/components/Button.tsx"),
                "export const Button = () => null;\nexport interface ButtonProps { label: string }\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/components/Card.tsx"),
                "export const Card = () => null;\n".to_string(),
            ),
            (
                PathBuf::from("src/components/index.ts"),
                "export { Button } from './Button';\nexport type { ButtonProps } from './Button';\nexport { Card } from './Card';\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/App.tsx"),
                "import { Button } from './components';\nexport const App = () => <Button />;\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/TypeOnlyConsumer.tsx"),
                "import { ButtonProps } from './components';\nconst props: ButtonProps = { label: 'x' };\nexport { props };\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/AllExportsConsumer.tsx"),
                "import { Button, Card } from './components';\nexport const Both = () => <><Button /><Card /></>;\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/NamespaceConsumer.ts"),
                "import * as components from './components';\nexport const all = components;\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/index.ts"),
                "import { Button } from './components';\nexport { Button };\n".to_string(),
            ),
        ],
        Some(&[RuleId::NoBarrelImport]),
    );

    assert_eq!(
        barrel_report.diagnostics.len(),
        1,
        "Only App.tsx should be flagged for no-barrel-import, got: {:?}",
        barrel_report.diagnostics
    );
    assert_eq!(barrel_report.diagnostics[0].file, Path::new("src/App.tsx"));
    assert_eq!(barrel_report.diagnostics[0].rule, RuleId::NoBarrelImport);
    assert!(
        barrel_report.diagnostics[0]
            .message
            .contains("./components/Button"),
        "Diagnostic message should suggest direct source path, got: {}",
        barrel_report.diagnostics[0].message
    );

    // 2. no-full-lodash-import + deterministic Autofix subpath rewrites
    let lodash_src = "import { debounce, throttle as thr } from \"lodash\";\nexport const d = debounce(() => {}, 100);\nexport const t = thr(() => {}, 100);\n";
    let lodash_diags = analyze_source(
        Path::new("src/search.ts"),
        lodash_src,
        Some(&[RuleId::NoFullLodashImport]),
    );
    assert_eq!(lodash_diags.len(), 1);
    assert_eq!(lodash_diags[0].rule, RuleId::NoFullLodashImport);
    assert_eq!(lodash_diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten_lodash, descriptions) = apply_patches_to_source(lodash_src, &lodash_diags);
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten_lodash.contains("import debounce from \"lodash/debounce\";"));
    assert!(rewritten_lodash.contains("import thr from \"lodash/throttle\";"));
    let reanalyzed_lodash = analyze_source(
        Path::new("src/search.ts"),
        &rewritten_lodash,
        Some(&[RuleId::NoFullLodashImport]),
    );
    assert!(reanalyzed_lodash.is_empty());

    // Adversarial valid cases for no-full-lodash-import: type-only, node builtin CLI script, getStaticPaths-only
    for valid_lodash in [
        "import type { Dictionary } from 'lodash';",
        "import { DebouncedFunc } from 'lodash';\nexport const track = (fn: DebouncedFunc<() => void>) => fn;",
        "import { isEqual } from 'lodash';\nimport * as fs from 'fs-extra';\nexport const check = (p: string, n: object) => !isEqual(JSON.parse(fs.readFileSync(p, 'utf8')), n);",
        "import { flatten } from 'lodash';\nexport const getStaticPaths = async () => ({ paths: flatten([['a']]), fallback: false });\nexport default function Page() { return <div>page</div>; }",
    ] {
        let diags = analyze_source(
            Path::new("src/page.tsx"),
            valid_lodash,
            Some(&[RuleId::NoFullLodashImport]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-full-lodash-import to stay silent on: {valid_lodash}, got: {diags:?}"
        );
    }

    // 3. no-moment
    let moment_diags = analyze_source(
        Path::new("src/date.ts"),
        "import moment from 'moment';\nexport const now = moment();",
        Some(&[RuleId::NoMoment]),
    );
    assert_eq!(moment_diags.len(), 1);
    assert!(
        analyze_source(
            Path::new("src/date.ts"),
            "import type { Moment } from 'moment';",
            Some(&[RuleId::NoMoment]),
        )
        .is_empty()
    );

    // 4. prefer-dynamic-import
    let heavy_diags = analyze_source(
        Path::new("src/ChartView.tsx"),
        "import { Chart } from 'chart.js';\nChart.register();",
        Some(&[RuleId::PreferDynamicImport]),
    );
    assert_eq!(heavy_diags.len(), 1);
    assert!(
        analyze_source(
            Path::new("src/ChartView.tsx"),
            "import { ChartConfiguration } from 'chart.js';\nexport const cfg = (): ChartConfiguration => ({ type: 'bar', data: { datasets: [] } });",
            Some(&[RuleId::PreferDynamicImport]),
        )
        .is_empty()
    );

    // 5. no-dynamic-import-path
    assert_eq!(
        analyze_source(
            Path::new("src/loader.ts"),
            "export const load = (p: string) => import(p);",
            Some(&[RuleId::NoDynamicImportPath]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/loader.ts"),
            "export const load = (pkg: string) => import(`./${pkg}/index.js`);",
            Some(&[RuleId::NoDynamicImportPath]),
        )
        .len(),
        1
    );
    for valid_dyn in [
        "export const load = (lang: string) => import(`./locales/${lang}.js`);",
        "export const load = (lang: string) => require(`./locales/${lang}.js`);",
        "export const load = (locale: string) => import(`@/locales/${locale}/common.json`);",
        "export const load = () => import(`../useArea?v=${Math.random()}`);",
        "const loadSharp = async () => { const name = 'sharp'; return await import(name); };",
        "export const runBlob = (s: string) => { const url = URL.createObjectURL(new Blob([s])); return import(url); };",
        "import { resolve } from 'node:path';\nexport const load = (p: string) => import(resolve(p));",
    ] {
        let diags = analyze_source(
            Path::new("src/loader.ts"),
            valid_dyn,
            Some(&[RuleId::NoDynamicImportPath]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-dynamic-import-path to stay silent on: {valid_dyn}, got: {diags:?}"
        );
    }

    // 6. no-undeferred-third-party
    assert_eq!(
        analyze_source(
            Path::new("src/Widget.tsx"),
            "export const W = () => <script src=\"https://cdn.example.com/w.js\" />;",
            Some(&[RuleId::NoUndeferredThirdParty]),
        )
        .len(),
        1
    );
    for valid_script in [
        "export const W = () => <script src=\"https://cdn.example.com/w.js\" defer />;",
        "export const W = () => <script src=\"https://cdn.example.com/w.js\" async />;",
        "export const W = () => <script type=\"module\" src=\"https://cdn.example.com/w.js\" />;",
        "export const W = () => <script src=\"/theme-init.js\" />;",
        "export const W = () => <script src=\"./env.js\" />;",
        "export const W = ({ path }) => <script src={path} noModule />;",
    ] {
        assert!(
            analyze_source(
                Path::new("src/Widget.tsx"),
                valid_script,
                Some(&[RuleId::NoUndeferredThirdParty]),
            )
            .is_empty(),
            "Expected no-undeferred-third-party to stay silent on: {valid_script}"
        );
    }

    // 7. use-lazy-motion
    assert_eq!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "import { motion } from 'framer-motion';\nexport const A = () => <motion.div />;",
            Some(&[RuleId::UseLazyMotion]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "import { LazyMotion, m } from 'framer-motion';\nexport const A = () => <LazyMotion><m.div /></LazyMotion>;",
            Some(&[RuleId::UseLazyMotion]),
        )
        .is_empty()
    );
    assert!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "import type { motion } from 'framer-motion';",
            Some(&[RuleId::UseLazyMotion]),
        )
        .is_empty()
    );
}

#[test]
fn js_performance_client_and_view_transition_rules_detect_invalid_and_autofix_and_preserve_adversarial_valid_cases()
 {
    // 1. async-parallel
    assert_eq!(
        analyze_source(
            Path::new("src/api.ts"),
            r#"
async function loadDashboard() {
  const user = await fetchUser();
  const posts = await fetchPosts();
  const stats = await fetchStats();
  return { user, posts, stats };
}
"#,
            Some(&[RuleId::AsyncParallel]),
        )
        .len(),
        1
    );
    for valid_parallel in [
        // Dependent await
        r#"
async function loadDashboard() {
  const user = await fetchUser();
  const posts = await fetchPosts(user.id);
  const stats = await fetchStats();
  return { user, posts, stats };
}
"#,
        // Inside db.transaction
        r#"
async function runTx(db) {
  await db.transaction(async (tx) => {
    const a = await tx.insertA();
    const b = await tx.insertB();
    const c = await tx.insertC();
    return [a, b, c];
  });
}
"#,
        // Ordered UI flow (click/render)
        r#"
async function drive(page) {
  const a = await page.goto('/login');
  const b = await page.click('#submit');
  const c = await page.waitForSelector('.home');
  return [a, b, c];
}
"#,
    ] {
        let diags = analyze_source(
            Path::new("src/api.ts"),
            valid_parallel,
            Some(&[RuleId::AsyncParallel]),
        );
        assert!(
            diags.is_empty(),
            "Expected async-parallel to stay silent on: {valid_parallel}, got: {diags:?}"
        );
    }

    // 2. async-await-in-loop
    assert_eq!(
        analyze_source(
            Path::new("src/loop.ts"),
            r#"
async function loadAll(ids: string[]) {
  const out = [];
  for (const id of ids) {
    out.push(await fetchItem(id));
  }
  return out;
}
"#,
            Some(&[RuleId::AsyncAwaitInLoop]),
        )
        .len(),
        1
    );
    for valid_loop_await in [
        // Intentional pacing (sleep / yieldNow)
        "async function poll(items: string[]) { for (const item of items) { await sleep(100); } }",
        "async function build(items: string[]) { for (const item of items) { await yieldToBrowser(item); } }",
        // Loop-carried dependency (pagination / directory walk)
        "async function descend(root: any, parts: string[]) { let dir = root; for (const p of parts) { dir = await dir.getDirectoryHandle(p); } return dir; }",
        "async function chain(ids: string[], results: any[]) { for (const id of ids) { const prev = results[results.length - 1]; results.push(await fetchNext(id, prev)); } }",
    ] {
        let diags = analyze_source(
            Path::new("src/loop.ts"),
            valid_loop_await,
            Some(&[RuleId::AsyncAwaitInLoop]),
        );
        assert!(
            diags.is_empty(),
            "Expected async-await-in-loop to stay silent on: {valid_loop_await}, got: {diags:?}"
        );
    }

    // 3. async-defer-await
    assert_eq!(
        analyze_source(
            Path::new("src/defer.ts"),
            r#"
export const load = async (shouldSkip: boolean) => {
  const rows = await fetchRows();
  if (shouldSkip) return [];
  return rows;
};
"#,
            Some(&[RuleId::AsyncDeferAwait]),
        )
        .len(),
        1
    );
    for valid_defer in [
        // Guard uses awaited binding
        "export const load = async () => { const rows = await fetchRows(); if (rows.length === 0) return []; return rows; };",
        // Cancellation / staleness guards after await
        "export const load = async () => { const rows = await fetchRows(); if (cancelled) return []; return rows; };",
        "export const load = async (aliveRef: { current: boolean }) => { const rows = await fetchRows(); if (!aliveRef.current) return []; return rows; };",
        "export const load = async (controller: AbortController) => { const rows = await fetchRows(); if (controller.signal.aborted) return []; return rows; };",
        "export const load = async (refreshId: number, latestRefreshId: number) => { const rows = await fetchRows(); if (refreshId !== latestRefreshId) return []; return rows; };",
        // Bare side-effect await before state guard
        "class Store { db: any = null; async get(id: string) { await this.init(); if (!this.db) throw new Error('no'); return id; } }",
    ] {
        let diags = analyze_source(
            Path::new("src/defer.ts"),
            valid_defer,
            Some(&[RuleId::AsyncDeferAwait]),
        );
        assert!(
            diags.is_empty(),
            "Expected async-defer-await to stay silent on: {valid_defer}, got: {diags:?}"
        );
    }

    // 4. no-spread-accumulator-in-reduce
    assert_eq!(
        analyze_source(
            Path::new("src/reduce.ts"),
            "export const indexById = (items: { id: string }[]) => items.reduce((acc, item) => ({ ...acc, [item.id]: item }), {});",
            Some(&[RuleId::NoSpreadAccumulatorInReduce]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/reduce.ts"),
            "export const flat = (items: number[]) => items.reduce((acc, item) => [...acc, item], []);",
            Some(&[RuleId::NoSpreadAccumulatorInReduce]),
        )
        .len(),
        1
    );
    for valid_reduce in [
        "export const indexById = (items: { id: string }[]) => items.reduce((acc, item) => { acc[item.id] = item; return acc; }, {});",
        // Fixed-shape object overwrite (does not grow keys per iteration)
        "export const sumBounds = (items: { min: number; max: number }[]) => items.reduce((acc, item) => ({ ...acc, min: Math.min(acc.min, item.min) }), { min: 0, max: 0 });",
        // Small literal array source
        "export const tiny = [1, 2, 3].reduce((acc, x) => ({ ...acc, [x]: true }), {});",
    ] {
        let diags = analyze_source(
            Path::new("src/reduce.ts"),
            valid_reduce,
            Some(&[RuleId::NoSpreadAccumulatorInReduce]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-spread-accumulator-in-reduce to stay silent on: {valid_reduce}, got: {diags:?}"
        );
    }

    // 5. no-json-parse-stringify-clone + deterministic Autofix -> structuredClone(x)
    let clone_src = "export const copy = JSON.parse(JSON.stringify(state));\n";
    let clone_diags = analyze_source(
        Path::new("src/clone.ts"),
        clone_src,
        Some(&[RuleId::NoJsonParseStringifyClone]),
    );
    assert_eq!(clone_diags.len(), 1);
    assert_eq!(clone_diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten_clone, clone_descs) = apply_patches_to_source(clone_src, &clone_diags);
    assert_eq!(clone_descs.len(), 1);
    assert_eq!(
        rewritten_clone,
        "export const copy = structuredClone(state);\n"
    );
    assert!(
        analyze_source(
            Path::new("src/clone.ts"),
            &rewritten_clone,
            Some(&[RuleId::NoJsonParseStringifyClone]),
        )
        .is_empty()
    );

    for valid_clone in [
        "const clean = JSON.parse(JSON.stringify(obj, (k, v) => (keep(k) ? v : undefined)));",
        "const picked = JSON.parse(JSON.stringify(obj, ['id', 'name']));",
        "const revived = JSON.parse(JSON.stringify(payload), (k, v) => v);",
        "function snapshotState(state: any) { return JSON.parse(JSON.stringify(state)); }",
        "const serializeState = (state: any) => JSON.parse(JSON.stringify(state));",
        "function causeToJson(cause: any) { return JSON.parse(JSON.stringify(cause)); }",
        "const normalizedDate = JSON.parse(JSON.stringify(date));",
        "try { run(); } catch (err) { const safe = JSON.parse(JSON.stringify(err)); postMessage(safe); }",
    ] {
        let diags = analyze_source(
            Path::new("src/clone.ts"),
            valid_clone,
            Some(&[RuleId::NoJsonParseStringifyClone]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-json-parse-stringify-clone to stay silent on: {valid_clone}, got: {diags:?}"
        );
    }

    // 6. no-sync-xhr & no-document-write
    assert_eq!(
        analyze_source(
            Path::new("src/xhr.ts"),
            "const xhr = new XMLHttpRequest();\nxhr.open('GET', '/api', false);",
            Some(&[RuleId::NoSyncXhr]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/xhr.ts"),
            "const xhr = new XMLHttpRequest();\nxhr.open('GET', '/api', true);",
            Some(&[RuleId::NoSyncXhr]),
        )
        .is_empty()
    );
    assert!(
        analyze_source(
            Path::new("src/xhr.ts"),
            "window.open('/popup', '_blank', false);",
            Some(&[RuleId::NoSyncXhr]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/doc.ts"),
            "document.write('<h1>Hello</h1>');",
            Some(&[RuleId::NoDocumentWrite]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/doc.ts"),
            "function render(document: { write: (s: string) => void }) { document.write('ok'); }",
            Some(&[RuleId::NoDocumentWrite]),
        )
        .is_empty()
    );

    // 7. client-passive-event-listeners + deterministic Autofix
    let passive_src =
        "function attach(el: HTMLElement) {\n  el.addEventListener('wheel', onWheel);\n}\n";
    let passive_diags = analyze_source(
        Path::new("src/scroll.ts"),
        passive_src,
        Some(&[RuleId::ClientPassiveEventListeners]),
    );
    assert_eq!(passive_diags.len(), 1);
    assert_eq!(passive_diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten_passive, passive_descs) = apply_patches_to_source(passive_src, &passive_diags);
    assert_eq!(passive_descs.len(), 1);
    assert!(
        rewritten_passive.contains("el.addEventListener('wheel', onWheel, { passive: true });")
    );
    assert!(
        analyze_source(
            Path::new("src/scroll.ts"),
            &rewritten_passive,
            Some(&[RuleId::ClientPassiveEventListeners]),
        )
        .is_empty()
    );

    for valid_passive in [
        "function attach(el: HTMLElement) { el.addEventListener('touchmove', (e) => { e.preventDefault(); }); }",
        "function attach(el: HTMLElement) { const onMove = (e: TouchEvent) => { e.preventDefault(); }; el.addEventListener('touchmove', onMove); }",
        "function attach(el: HTMLElement) { el.addEventListener('touchmove', onMove, { passive: true }); }",
        "function attach(el: HTMLElement) { el.addEventListener('touchmove', onMove, { passive: false }); }",
        "function attach(el: HTMLElement) { el.addEventListener('click', onClick); }",
    ] {
        let diags = analyze_source(
            Path::new("src/scroll.ts"),
            valid_passive,
            Some(&[RuleId::ClientPassiveEventListeners]),
        );
        assert!(
            diags.is_empty(),
            "Expected client-passive-event-listeners to stay silent on: {valid_passive}, got: {diags:?}"
        );
    }

    // 8. no-flush-sync & no-document-start-view-transition
    assert_eq!(
        analyze_source(
            Path::new("src/View.tsx"),
            "import { flushSync } from 'react-dom';\nexport function C() { return <button onClick={() => flushSync(() => setOpen(true))} />; }",
            Some(&[RuleId::NoFlushSync]),
        )
        .len(),
        1
    );
    for valid_flush in [
        "import { flushSync } from 'react-dom';\nexport const wrap = (fn: () => void) => document.startViewTransition(() => { flushSync(fn); });",
        "import { flushSync } from 'react-dom';\nexport const measure = (el: HTMLElement) => { flushSync(() => setOpen(true)); return el.getBoundingClientRect(); };",
        "import { Popper } from 'react-popper';\nimport { flushSync } from 'react-dom';\nexport const P = () => <Popper />;",
    ] {
        let diags = analyze_source(
            Path::new("src/View.tsx"),
            valid_flush,
            Some(&[RuleId::NoFlushSync]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-flush-sync to stay silent on: {valid_flush}, got: {diags:?}"
        );
    }

    assert_eq!(
        analyze_source(
            Path::new("src/Gallery.tsx"),
            "import { ViewTransition } from 'react';\nexport const swap = () => document.startViewTransition(() => {});",
            Some(&[RuleId::NoDocumentStartViewTransition]),
        )
        .len(),
        1
    );
    for valid_vt in [
        "export const swap = () => document.startViewTransition(() => {});",
        "import { ViewTransition } from 'react';\nexport function f(document: { startViewTransition: (cb: () => void) => void }) { document.startViewTransition(() => {}); }",
    ] {
        let diags = analyze_source(
            Path::new("src/Gallery.tsx"),
            valid_vt,
            Some(&[RuleId::NoDocumentStartViewTransition]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-document-start-view-transition to stay silent on: {valid_vt}, got: {diags:?}"
        );
    }
}

#[test]
fn performance_rules_detect_invalid_and_preserve_adversarial_valid_cases() {
    // 1. rerender-memo-with-default-value
    assert_eq!(
        analyze_source(
            Path::new("src/List.tsx"),
            "const Child = memo(Inner);\nexport function List({ items = [] }) { return <Child items={items} />; }",
            Some(&[RuleId::RerenderMemoWithDefaultValue]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/List.tsx"),
            "export function List({ config = {} }) { useEffect(() => { run(config); }, [config]); return <div />; }",
            Some(&[RuleId::RerenderMemoWithDefaultValue]),
        )
        .len(),
        1
    );
    for valid_default in [
        "export function List({ items = [] }) { return <ul>{items.map((x) => <li key={x}>{x}</li>)}</ul>; }",
        "function PlainChild({ items }) { return <div />; }\nexport function List({ items = [] }) { return <PlainChild items={items} />; }",
    ] {
        let diags = analyze_source(
            Path::new("src/List.tsx"),
            valid_default,
            Some(&[RuleId::RerenderMemoWithDefaultValue]),
        );
        assert!(
            diags.is_empty(),
            "Expected rerender-memo-with-default-value to stay silent on: {valid_default}, got: {diags:?}"
        );
    }

    // 2. rerender-memo-before-early-return
    assert_eq!(
        analyze_source(
            Path::new("src/Panel.tsx"),
            "export function Panel({ cond }) { const content = useMemo(() => <Heavy />, []); if (cond) { return null; } return <div>{content}</div>; }",
            Some(&[RuleId::RerenderMemoBeforeEarlyReturn]),
        )
        .len(),
        1
    );
    for valid_memo_early in [
        "export function Panel({ cond }) { const content = useMemo(() => <Heavy />, []); if (cond) { return content; } return <div>{content}</div>; }",
        "export function FieldError({ children, errors }) { const content = useMemo(() => children ? <span>{children}</span> : null, [children, errors]); if (!content) { return null; } return <div>{content}</div>; }",
        "export function ViewItem({ view, aiEnabled }) { const renderItem = useMemo(() => { if (!aiEnabled) return null; return <Heavy view={view} />; }, [view, aiEnabled]); if (!aiEnabled) return null; return <div>{renderItem}</div>; }",
    ] {
        let diags = analyze_source(
            Path::new("src/Panel.tsx"),
            valid_memo_early,
            Some(&[RuleId::RerenderMemoBeforeEarlyReturn]),
        );
        assert!(
            diags.is_empty(),
            "Expected rerender-memo-before-early-return to stay silent on: {valid_memo_early}, got: {diags:?}"
        );
    }

    // 3. rerender-derived-state-from-hook
    assert_eq!(
        analyze_source(
            Path::new("src/App.tsx"),
            "export function App() { const width = useWindowWidth(); const isMobile = width < 768; return <div>{isMobile ? 'm' : 'd'}</div>; }",
            Some(&[RuleId::RerenderDerivedStateFromHook]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/App.tsx"),
            "export function App() { const width = useWindowWidth(); const isMobile = width < 768; return <div>{width}px {isMobile ? 'm' : 'd'}</div>; }",
            Some(&[RuleId::RerenderDerivedStateFromHook]),
        )
        .is_empty()
    );

    // 4. rerender-transitions-scroll
    assert_eq!(
        analyze_source(
            Path::new("src/Scroll.tsx"),
            "export function ScrollTracker() { const [, setScrollY] = useState(0); useEffect(() => { window.addEventListener('scroll', () => { setScrollY(window.scrollY); }); }, []); return null; }",
            Some(&[RuleId::RerenderTransitionsScroll]),
        )
        .len(),
        1
    );
    for valid_scroll in [
        "export function Chat() { const [, setShow] = useState(false); useEffect(() => { window.addEventListener('scroll', () => { setShow(false); }); }, []); return null; }",
        "export function Flamegraph() { const [, setTip] = useState(null); const ref = useRef(null); useEffect(() => { window.addEventListener('mousemove', (e) => { if (e.target === ref.current) return; ref.current = e.target; setTip({ x: e.clientX }); }); }, []); return null; }",
        "export function SmoothScroll() { const [, setY] = useState(0); useEffect(() => { window.addEventListener('scroll', () => { startTransition(() => setY(window.scrollY)); }); }, []); return null; }",
    ] {
        let diags = analyze_source(
            Path::new("src/Scroll.tsx"),
            valid_scroll,
            Some(&[RuleId::RerenderTransitionsScroll]),
        );
        assert!(
            diags.is_empty(),
            "Expected rerender-transitions-scroll to stay silent on: {valid_scroll}, got: {diags:?}"
        );
    }

    // 5. no-match-media-in-state-initializer
    assert_eq!(
        analyze_source(
            Path::new("src/Media.tsx"),
            "import { useState } from 'react';\nexport const [isMobile] = useState(window.matchMedia('(max-width: 768px)').matches);",
            Some(&[RuleId::NoMatchMediaInStateInitializer]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/Media.tsx"),
            "import { useState } from 'react';\nexport const [isMobile] = useState(() => matchMedia('(max-width: 768px)').matches);",
            Some(&[RuleId::NoMatchMediaInStateInitializer]),
        )
        .len(),
        1
    );
    for valid_mm in [
        "const [isMobile] = useState(matchMedia('(max-width: 768px)').matches);",
        "import { useState } from 'react';\nconst matchMedia = (q: string) => ({ matches: true });\nconst [isMobile] = useState(matchMedia('(max-width: 768px)').matches);",
        "import { useState } from 'react';\nconst [isMobile] = useState(async () => matchMedia('(max-width: 768px)').matches);",
    ] {
        let diags = analyze_source(
            Path::new("src/Media.tsx"),
            valid_mm,
            Some(&[RuleId::NoMatchMediaInStateInitializer]),
        );
        assert!(
            diags.is_empty(),
            "Expected no-match-media-in-state-initializer to stay silent on: {valid_mm}, got: {diags:?}"
        );
    }

    // 6. no-transition-all & no-layout-property-animation
    assert_eq!(
        analyze_source(
            Path::new("src/Box.tsx"),
            "export const Box = () => <div className=\"transition-all duration-200\" />;",
            Some(&[RuleId::NoTransitionAll]),
        )
        .len(),
        1
    );
    assert_eq!(
        analyze_source(
            Path::new("src/Box.tsx"),
            "export const Box = () => <div style={{ transition: 'all 200ms ease' }} />;",
            Some(&[RuleId::NoTransitionAll]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Box.tsx"),
            "export const Box = () => <div className=\"transition-opacity duration-200\" />;",
            Some(&[RuleId::NoTransitionAll]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "export const X = () => <motion.div animate={{ width: 200, height: 100, opacity: 1 }} />;",
            Some(&[RuleId::NoLayoutPropertyAnimation]),
        )
        .len(),
        2
    );
    assert!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "export const X = () => <motion.div animate={{ x: 100, scale: 1.2, opacity: 0.5 }} />;",
            Some(&[RuleId::NoLayoutPropertyAnimation]),
        )
        .is_empty()
    );
    assert!(
        analyze_source(
            Path::new("src/Anim.tsx"),
            "export const X = () => <div animate={{ width: 200 }} />;",
            Some(&[RuleId::NoLayoutPropertyAnimation]),
        )
        .is_empty()
    );

    // 7. no-inline-prop-on-memo-component & prefer-stable-empty-fallback & context-provider-value-from-unmemoized-local-literal
    assert_eq!(
        analyze_source(
            Path::new("src/Memo.tsx"),
            "const Row = memo(Inner);\nexport function List() { return <Row onClick={() => doThing()} config={Object.freeze({ a: 1 })} />; }",
            Some(&[RuleId::NoInlinePropOnMemoComponent]),
        )
        .len(),
        2
    );
    for valid_memo_prop in [
        "const Row = memo(Inner, (a, b) => a.id === b.id);\nexport function List() { return <Row onClick={() => doThing()} />; }",
        "const Row = memo(Inner);\nexport function List({ items }) { return items.map((item) => <Row key={[item.id]} />); }",
    ] {
        assert!(
            analyze_source(
                Path::new("src/Memo.tsx"),
                valid_memo_prop,
                Some(&[RuleId::NoInlinePropOnMemoComponent]),
            )
            .is_empty()
        );
    }

    assert_eq!(
        analyze_source(
            Path::new("src/Fallback.tsx"),
            "const List = memo(Inner);\nexport function Page({ items }) { return <List items={items ?? []} />; }",
            Some(&[RuleId::PreferStableEmptyFallback]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Fallback.tsx"),
            "function List({ items }) { return <div />; }\nexport function Page({ items }) { return <List items={items ?? []} />; }",
            Some(&[RuleId::PreferStableEmptyFallback]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Ctx.tsx"),
            "const ThemeCtx = createContext(null);\nexport function App({ theme }) { const val = { theme }; return <ThemeCtx.Provider value={val}><Child /></ThemeCtx.Provider>; }",
            Some(&[RuleId::ContextProviderValueFromUnmemoizedLocalLiteral]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Ctx.tsx"),
            "const ThemeCtx = createContext(null);\nexport function App({ theme }) { const val = useMemo(() => ({ theme }), [theme]); return <ThemeCtx.Provider value={val}><Child /></ThemeCtx.Provider>; }",
            Some(&[RuleId::ContextProviderValueFromUnmemoizedLocalLiteral]),
        )
        .is_empty()
    );
}

#[test]
fn extended_performance_and_js_performance_rules_and_cli_autofix_work_end_to_end() {
    // 1. no-usememo-simple-expression & no-eager-new-in-use-state-initializer
    assert_eq!(
        analyze_source(
            Path::new("src/Cheap.tsx"),
            "export function Comp({ a, b }) { const sum = useMemo(() => a + b, [a, b]); return <div>{sum}</div>; }",
            Some(&[RuleId::NoUsememoSimpleExpression]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Cheap.tsx"),
            "export function Comp({ items }) { const sorted = useMemo(() => items.slice().sort(), [items]); return <div>{sorted.length}</div>; }",
            Some(&[RuleId::NoUsememoSimpleExpression]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/StateInit.tsx"),
            "export function Comp() { const [client] = useState(new ExpensiveClient()); return <div />; }",
            Some(&[RuleId::NoEagerNewInUseStateInitializer]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/StateInit.tsx"),
            "export function Comp() { const [client] = useState(() => new ExpensiveClient()); return <div />; }",
            Some(&[RuleId::NoEagerNewInUseStateInitializer]),
        )
        .is_empty()
    );

    // 2. no-permanent-will-change, no-unbounded-animation-frame-loop, no-unthrottled-scroll-mutation
    assert_eq!(
        analyze_source(
            Path::new("src/Gpu.tsx"),
            "export const Box = () => <div className=\"will-change-transform\" />;",
            Some(&[RuleId::NoPermanentWillChange]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Gpu.tsx"),
            "export const Box = ({ active }) => <div style={{ willChange: active ? 'transform' : 'auto' }} />;",
            Some(&[RuleId::NoPermanentWillChange]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Raf.ts"),
            "function tick() { updateScene(); requestAnimationFrame(tick); }",
            Some(&[RuleId::NoUnboundedAnimationFrameLoop]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Raf.ts"),
            "function tick() { if (!running) return; updateScene(); rafId = requestAnimationFrame(tick); }",
            Some(&[RuleId::NoUnboundedAnimationFrameLoop]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/ScrollDom.ts"),
            "window.addEventListener('scroll', () => { header.style.transform = `translateY(${window.scrollY}px)`; });",
            Some(&[RuleId::NoUnthrottledScrollMutation]),
        )
        .len(),
        1
    );

    // 3. no-srcset-without-sizes, no-img-lazy-with-high-fetchpriority, rendering-hoist-jsx, rendering-script-defer-async
    assert_eq!(
        analyze_source(
            Path::new("src/Img.tsx"),
            "export const Hero = () => <img src=\"/a.jpg\" srcSet=\"/a-400.jpg 400w, /a-800.jpg 800w\" alt=\"hero\" />;",
            Some(&[RuleId::NoSrcsetWithoutSizes]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Img.tsx"),
            "export const Hero = () => <img src=\"/a.jpg\" srcSet=\"/a-400.jpg 400w, /a-800.jpg 800w\" sizes=\"100vw\" alt=\"hero\" />;",
            Some(&[RuleId::NoSrcsetWithoutSizes]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Img.tsx"),
            "export const Hero = () => <img src=\"/a.jpg\" loading=\"lazy\" fetchPriority=\"high\" alt=\"hero\" />;",
            Some(&[RuleId::NoImgLazyWithHighFetchpriority]),
        )
        .len(),
        1
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Hoist.tsx"),
            "export function Card() { const icon = <svg><path /></svg>; return <div>{icon}</div>; }",
            Some(&[RuleId::RenderingHoistJsx]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Hoist.tsx"),
            "export function Card({ color }) { const icon = <svg fill={color}><path /></svg>; return <div>{icon}</div>; }",
            Some(&[RuleId::RenderingHoistJsx]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Script.tsx"),
            "export const Head = () => <script src=\"/analytics.js\" />;",
            Some(&[RuleId::RenderingScriptDeferAsync]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Script.tsx"),
            "export const Head = () => <script src=\"/theme-init.js\" />;",
            Some(&[RuleId::RenderingScriptDeferAsync]),
        )
        .is_empty()
    );

    // 4. Hydration & Motion rules
    assert_eq!(
        analyze_source(
            Path::new("src/Clock.tsx"),
            "export function Clock() { return <span>{Date.now()}</span>; }",
            Some(&[RuleId::RenderingHydrationMismatchTime]),
        )
        .len(),
        1
    );
    assert!(
        analyze_source(
            Path::new("src/Clock.tsx"),
            "export function Clock() { return <span suppressHydrationWarning>{Date.now()}</span>; }",
            Some(&[RuleId::RenderingHydrationMismatchTime]),
        )
        .is_empty()
    );

    assert_eq!(
        analyze_source(
            Path::new("src/Motion.tsx"),
            "export function Box() { const x = motionValue(0); return <motion.div transition={{ stiffness: 100, duration: 0.5, staggerChildren: 0.25 }} animate={{ x: 10, filter: 'blur(24px)' }} />; }",
            Some(&[
                RuleId::MotionValueConstructorInRender,
                RuleId::NoConflictingSpringOptions,
                RuleId::NoExcessiveMotionStagger,
                RuleId::NoLargeAnimatedBlur,
                RuleId::PreferMotionTransformProperty,
            ]),
        )
        .len(),
        5
    );

    // 5. Additional js-performance rules
    assert_eq!(
        analyze_source(
            Path::new("src/Iter.ts"),
            r#"
export function run(items: { id: string; val: number }[], targets: string[]) {
  const urls = URL.createObjectURL(new Blob(['x']));
  const a = localStorage.getItem('token');
  const b = localStorage.getItem('token');
  const chained = items.map((x) => x.val).filter(Boolean);
  const combined = items.filter((x) => x.val > 0).map((x) => x.val * 2);
  const minVal = items.sort((x, y) => x.val - y.val)[0];
  const eq = items.every((x, i) => x === items[i]);
  for (const t of targets) {
    const re = new RegExp('^foo$');
    const fmt = new Intl.NumberFormat('en-US');
    const found = items.find((x) => x.id === t);
    const has = targets.includes(x);
  }
  return { urls, a, b, chained, combined, minVal, eq };
}
"#,
            Some(&[
                RuleId::NoCreateObjectUrlWithoutRevoke,
                RuleId::JsCacheStorage,
                RuleId::JsFlatmapFilter,
                RuleId::JsCombineIterations,
                RuleId::JsMinMaxLoop,
                RuleId::JsLengthCheckFirst,
                RuleId::JsHoistRegexp,
                RuleId::JsHoistIntl,
                RuleId::JsIndexMaps,
                RuleId::JsSetMapLookups,
            ]),
        )
        .len(),
        10
    );

    assert_eq!(
        analyze_source(
            Path::new("src/AsyncReduce.ts"),
            "export const sum = (items: number[]) => items.reduce(async (acc, item) => { const v = await fetchVal(item); return acc + v; }, Promise.resolve(0));",
            Some(&[RuleId::JsAsyncReduceWithoutAwaitedAcc]),
        )
        .len(),
        1
    );
}
