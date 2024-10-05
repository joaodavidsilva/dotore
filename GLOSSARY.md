# Dotore

Static dataflow doctor for React codebases, diagnosing unnecessary effects, state cascades, and cross-component state ownership flaws.

## Language

**Subject**:
A React functional component or custom hook analyzed as a self-contained hook scope.
_Avoid_: Component, hook, unit, function

**State Slot**:
A reactive state pair `(value, setter)` declared via `useState` or `useReducer` inside a **Subject**.
_Avoid_: State variable, hook state, local variable

**Effect Node**:
A `useEffect` registration inside a **Subject**, defined by its dependency list, upstream reads, synchronous state/prop calls, and cleanup return.
_Avoid_: Hook call, side effect, effect callback

**Caller Site**:
A JSX element in a parent **Subject** that renders a child **Subject**, recording the passed props and whether a `key` attribute is present.
_Avoid_: Parent call, JSX node, usage site

**Render Cascade**:
One or more extra render passes triggered after the initial render because **Effect Nodes** mutate **State Slots** or notify a parent **Subject**.
_Avoid_: Effect chain, re-render loop

**Prescription Tier**:
The level of intervention required to resolve a diagnostic: `Autofix` (deterministic single-**Subject** rewrite applied by `dotore fix`), `Surgical` (localized single-**Subject** change with a direct recipe), or `Refactor` (state-model or cross-**Subject** contract redesign).
_Avoid_: Severity, fix type, priority
