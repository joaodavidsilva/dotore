# 08: Performance, JS Performance, Client, View Transitions, and Bundle Size Rule Families

**What to build:** Port all React re-render performance, JavaScript runtime performance, client DOM, View Transitions, and bundle-size rules into the single-pass Rust engine with deterministic `Autofix` support and full adversarial regression test coverage.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline, 04: Module Graph, Dead Code, Circular Dependencies, and Duplicate JSX Subtrees

**Status:** ready-for-agent

- [ ] All rules in the `performance` family (`rerender-memo-with-default-value`, `rerender-memo-before-early-return`, `rerender-derived-state-from-hook`, `rerender-transitions-scroll`, `no-match-media-in-state-initializer`, `no-transition-all`, `no-layout-property-animation`, and related re-render rules) are implemented in Rust.
- [ ] All rules in the `js-performance`, `client`, and `view-transitions` families (`async-parallel`, `async-await-in-loop`, `async-defer-await`, `no-spread-accumulator-in-reduce`, `no-json-parse-stringify-clone`, `no-sync-xhr`, `no-document-write`, `client-passive-event-listeners`, `client-localstorage-no-version`, `no-flush-sync`, `no-document-start-view-transition`) are implemented in Rust.
- [ ] All rules in the `bundle-size` family (`no-barrel-import`, `no-full-lodash-import`, `no-moment`, `prefer-dynamic-import`, `no-dynamic-import-path`, `no-undeferred-third-party`, `use-lazy-motion`) are implemented in Rust using `ProjectGraph` module resolution where cross-file barrel awareness is required.
- [ ] Rules with unambiguous transformations (such as `no-json-parse-stringify-clone` → `structuredClone`, `no-full-lodash-import` subpath rewrites, and passive event listener options) provide deterministic `Autofix` patches.
- [ ] Integration tests cover both invalid and adversarial valid cases from the reference regression suites.
