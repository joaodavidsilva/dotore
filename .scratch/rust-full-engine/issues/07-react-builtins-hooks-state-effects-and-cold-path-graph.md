# 07: React Builtins, Hooks, State & Effects Rule Families + Cold-Path ProjectGraph Gating

**What to build:** Port the complete `state-and-effects`, `react-builtins`, `correctness`, and `architecture` rule families into the single-pass Rust engine, including cross-file `ProjectGraph` cold-path suppression for inline prop rules, `Context.Provider` fan-out analysis, and ancestral `<Suspense>`/`<ErrorBoundary>` verification.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline, 04: Module Graph, Dead Code, Circular Dependencies, and Duplicate JSX Subtrees

**Status:** ready-for-agent

- [ ] All rules in the `state-and-effects`, `react-builtins`, `correctness`, and `architecture` families (including `exhaustive-deps` with local callback ownership, `jsx-key`, `no-array-index-as-key`, `no-random-key`, `no-set-state-in-render`, `no-self-updating-effect`, `rendering-conditional-render`, `checked-requires-onchange-or-readonly`, `button-has-type`, `radio-input-missing-name`, `only-export-components`, `no-nested-component-definition`, `prefer-module-scope-static-value`, `prefer-module-scope-pure-function`, and React Compiler compatibility rules) are implemented in Rust.
- [ ] Inline prop reference rules (`jsx-no-new-object-as-prop`, `jsx-no-new-array-as-prop`, `jsx-no-new-function-as-prop`, `no-inline-prop-on-memo-component`) query `ProjectGraph` to suppress cold-path noise when the target child **Subject** is not memoized, not rendered inside a list/loop, and does not feed the prop into an **Effect Node** dependency list.
- [ ] `ProjectGraph` flags unstable `Context.Provider` values and overloaded providers where frequently mutated **State Slots** trigger re-renders across consumers that only read static properties.
- [ ] `ProjectGraph` verifies that **Subjects** invoking suspending hooks/APIs or throwing boundaries have an ancestral `<Suspense>` or `<ErrorBoundary>` across their **Caller Sites**.
- [ ] Mechanical rules in these families (such as `button-has-type`, module-scope hoisting of static values/pure functions, and derived-state rewrites) provide deterministic `Autofix` patches verified by round-trip re-analysis.
- [ ] Integration tests port the valid and adversarial invalid regression cases from the reference suite with zero false positives.
