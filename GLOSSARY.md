# Dotore

Static React and TypeScript codebase analyzer and deterministic remediation engine that diagnoses correctness, performance, accessibility, security, and architecture flaws and produces automatic rewrites or self-contained remediation capsules.

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
The level of intervention required to resolve a diagnostic: `Autofix` (unambiguous single- or cross-file rewrite applied deterministically), `Surgical` (localized single-**Subject** change with a direct recipe), or `Refactor` (state-model or cross-**Subject** contract redesign).
_Avoid_: Severity, fix type, priority

**Capability Gate**:
A project-level technology profile inferred from declared dependencies and configuration that controls which rule families are active.
_Avoid_: Feature flag, plugin preset, framework filter

**Root-Cause Group**:
One or more diagnostics that stem from a single underlying flaw and are resolved together by one intervention.
_Avoid_: Fix group, issue batch, duplicate finding

**Blast Radius**:
The static runtime impact of a flaw, determined by render frequency (list loops, animation frames), provider consumer fan-out, subtree depth, and **Render Cascade** length.
_Avoid_: Leverage score, priority weight, hotness

**Fix Capsule**:
A self-contained remediation unit emitted for a **Root-Cause Group**, bundling the affected **Subject** and **Caller Site** excerpts, canonical transformation recipe, and repository **Exemplar** so an agent can apply the fix without codebase exploration.
_Avoid_: Prompt, markdown plan, work packet

**Exemplar**:
An existing valid usage in the same repository that demonstrates the project's local convention for a prescribed fix.
_Avoid_: Sample code, reference file, template

**Contextual Owner**:
The smallest enclosing syntax unit (line, JSX element, **Subject**, or explicit related AST nodes) that owns a diagnostic during contextual diff filtering.
_Avoid_: Diff scope, blame range, touched node

**Symbol Outline**:
A declared function, **Subject**, class, interface, type alias, enum, or constant extracted with its signature and adjacent doc comment for fuzzy symbol search.
_Avoid_: Declaration snippet, AST symbol, search hit
