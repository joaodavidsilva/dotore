# Dotore: Full-Catalog Deterministic Rust Static Analyzer & Remediation Engine

Status: resolved

## Problem Statement

React and TypeScript engineering teams and AI coding agents currently suffer from slow, fragmented, and overly probabilistic code health workflows:

1. **Multi-pass runtime overhead and toolchain complexity**: Legacy JavaScript/TypeScript static analysis pipelines parse the same source files four to five separate times across multiple Node.js worker processes (lint workers serializing ASTs across JS/Rust bridges, separate module-graph workers for dead code and circular dependencies, separate JSX subtree hashing workers, separate TypeScript compiler passes for motion/accessibility checks, and separate CLI invocations for symbol search). This adds tens of thousands of lines of orchestration plumbing and seconds or minutes of latency.
2. **Excessive probabilistic workload placed on LLM agents**: Traditional linters emit flat `file:line:column` messages and rely on LLM agents to fetch remote Markdown recipes over HTTP, manually grep and read dozens of files to trace **Caller Sites** and component hierarchies, launch sub-agents to guess whether a **Subject** sits on a hot render path or a cold modal, search for local repository conventions by hand, and manually edit files even when the required transformation is 100% mechanical.
3. **Cold-path false positives and single-file blindness**: Rules evaluated without a cross-file project graph flag inline props or suggest memoization on cold paths where children are not memoized, while missing true cross-file architectural defects such as overloaded `Context.Provider` fan-out, 60fps `useFrame`/`requestAnimationFrame` allocations across helper modules, and missing ancestral `<Suspense>` or `<ErrorBoundary>` wrappers.
4. **External network fragility**: Relying on remote HTTP endpoints to compute a project health score, fetch rule remediation prompts, or stream telemetry causes scans to degrade or fail in offline, air-gapped, or firewalled environments.

## Solution

Consolidate the entire static analysis, graph linking, auto-fixing, remediation planning, symbol search, diff/baseline filtering, local health scoring, and runtime profiling workflow into `dotore` — a single, zero-telemetry, 100% deterministic Rust binary and library crate:

1. **Single-pass OXC extraction and unified in-memory ProjectGraph**: Parse each source file once in parallel via `oxc_parser` and `oxc_semantic`, extracting a multi-facet intermediate representation (**Subject**, **State Slot**, **Effect Node**, **Caller Site**, JSX elements and subtree hashes, module imports/exports, **Symbol Outlines**, state/store mutations, async flows, and security sinks) and linking all files into a global in-memory `ProjectGraph`.
2. **Full 24-family rule catalog gated by Capability Gate**: Automatically infer the project's **Capability Gate** from its declared dependencies and configuration (`dotore.config.*` or `package.json#dotore`) to evaluate all 900+ rules across React hooks/state/effects, correctness, re-render performance, JS performance, accessibility, UI design, security, module dead-code/cycles, duplicate JSX subtrees, Next.js, React Server Components, TanStack Query/Start, React Native/Expo, Three.js/React Three Fiber/WebGL/WebGPU, Zustand, Jotai, MobX, Valtio, Preact, Ink, View Transitions, and Zod — while using `ProjectGraph` to suppress cold-path noise and detect cross-file architectural flaws.
3. **Maximum deterministic execution (`Autofix` + `Fix Capsule` + `plan`)**:
   - Execute all unambiguous single-file and cross-file **Caller Site** rewrites directly in Rust (`dotore fix`) in milliseconds with zero LLM involvement.
   - Cluster remaining `Surgical` and `Refactor` diagnostics into **Root-Cause Groups**, rank them statically by **Blast Radius**, and emit self-contained **Fix Capsules** (or deterministic Markdown execution plans via `dotore plan`) bundling exact **Subject** and **Caller Site** source excerpts, embedded canonical transformation recipes, and a real repository **Exemplar** so an LLM agent can apply the final edit in one step without network fetches or codebase exploration.
4. **Complete unified CLI surface**: Provide `check` (default), `fix`, `plan`, `search` (native fuzzy **Symbol Outline** search), `design`, `why`, `rules`, `report` (self-contained interactive HTML), `scan` (native Chrome DevTools Protocol WebSocket runtime profiler), `ci`, and `install`, backed by local deterministic health scoring (`0..=100` and `P0`–`P3` tiers) and git diff / **Contextual Owner** / baseline multiset comparison.

## User Stories

### Single-Pass Engine, Capability Gate & Configuration

1. As a developer, I want `dotore` to parse each TypeScript, JavaScript, JSX, or TSX file at most once per run in parallel across CPU cores, so that full-repository scans complete orders of magnitude faster than multi-worker Node.js pipelines.
2. As a developer, I want `dotore` to automatically infer a **Capability Gate** from `package.json` dependencies and workspace manifests, so that framework-specific rule families (Next.js, React Native, Expo, TanStack Query, TanStack Start, Three.js/R3F, Zustand, Jotai, MobX, Valtio, Preact, Ink, Zod) only execute when those libraries are actually used in the project.
3. As a monorepo maintainer, I want `dotore` to discover nested workspace packages and compute a per-package **Capability Gate**, so that a Next.js web app and a React Native mobile app in the same repository each receive only their relevant diagnostics.
4. As a developer, I want `dotore` to load configuration from `dotore.config.json`, `dotore.config.ts`, `dotore.config.js`, `dotore.config.mjs`, or the `"dotore"` field in `package.json`, so that I can customize rule severities, categories, ignored paths, ignored tags, and custom text/wrapper components without command-line boilerplate.
5. As a developer, I want CLI flags to deterministically override values in `dotore.config.*` and `package.json#dotore`, so that one-off CI or terminal invocations can adjust behavior without editing tracked files.
6. As a developer, I want inline suppression comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`) to be respected by default and controllable via `--no-inline-disables`, so that intentional local exceptions are honored while remaining auditable.
7. As a developer, I want rules tagged as `test-noise` to be automatically suppressed in test and story files (`.test.*`, `.spec.*`, `.stories.*`, `__tests__/`), while rules tagged `migration-hint` still run in tests, so that test suites do not generate false-positive noise.
8. As a library author, I want `dotore` to detect package role (application vs. published library) and skip application-only rules on library entrypoints, so that reusable component libraries are not penalized for app-level concerns.

### Core React Dataflow, Hooks, and Render Cascade Rules

9. As a React developer, I want `dotore` to flag **State Slots** updated inside an **Effect Node** purely from props or existing **State Slots** (`no-derived-state`), so that derived values are computed during render without triggering a **Render Cascade**.
10. As a React developer, I want `dotore` to detect multi-step state update chains across one or more **Effect Nodes** (`no-chain-state-updates`), so that I can collapse multi-pass **Render Cascades** into single-render computations or event-handler updates.
11. As a React developer, I want `dotore` to flag **Effect Nodes** that act as disguised event handlers gated by a state/prop flag (`no-event-handler`), so that user action logic executes directly inside the event handler with full event context.
12. As a React developer, I want `dotore` to flag **Effect Nodes** that partially mutate **State Slots** when a prop changes (`no-adjust-state-on-prop-change`), so that I replace error-prone effect synchronization with derived state or explicit render-phase state transitions.
13. As a React developer, I want `dotore` to flag **Effect Nodes** that reset all **State Slots** in a **Subject** when an identifying prop changes (`no-reset-all-state-on-prop-change`) and automatically locate every parent **Caller Site** across the codebase, so that state resets are solved cleanly by passing `key={prop}` at the parent **Caller Site**.
14. As a React developer, I want `dotore` to flag **Effect Nodes** that push live local **State Slots** (`no-pass-live-state-to-parent`) or external query/hook data (`no-pass-data-to-parent`) upward via parent callback props, so that state is lifted to the owning parent **Subject** instead of synchronized after render.
15. As a React developer, I want `dotore` to flag manual external store subscriptions inside **Effect Nodes** (`no-external-store-subscription`), so that concurrent-safe `useSyncExternalStore` is used instead.
16. As a React developer, I want `dotore` to flag mount-only **Effect Nodes** (`useEffect(..., [])`) that synchronously initialize **State Slots** (`no-initialize-state`), so that initial state is passed directly to `useState(init)` or `useState(() => init)`.
17. As a React developer, I want `dotore` to flag data fetching inside **Effect Nodes** (`no-fetch-in-effect`), distinguishing between unguarded fetches that cause race conditions and guarded fetches that can migrate to suspense/query hooks, so that stale responses never overwrite newer state.
18. As a React developer, I want `dotore` to verify `exhaustive-deps` across `useEffect`, `useLayoutEffect`, `useMemo`, `useCallback`, and custom hooks configured with dependency arrays, including local callbacks in the same file, so that closures never capture stale **State Slots** or props.
19. As a React developer, I want `dotore` to detect self-updating effects (`no-self-updating-effect`), `setState` calls during render (`no-set-state-in-render`), conditional or looped hook invocations, and direct mutations of `useState` or `useReducer` state, so that React's rendering invariants cannot be broken at runtime.

### Cross-File ProjectGraph & "Beyond-the-Scan" Architectural Rules

20. As a senior engineer, I want `dotore` to suppress inline reference rules (`jsx-no-new-object-as-prop`, `jsx-no-new-array-as-prop`, `jsx-no-new-function-as-prop`) on cold paths where the target child **Subject** in `ProjectGraph` is neither wrapped in `React.memo` nor rendered inside a hot loop/list nor passing that prop into an **Effect Node** dependency list, so that developers and LLM agents never waste time on premature memoization.
21. As a senior engineer, I want `dotore` to analyze `Context.Provider` values and all cross-file `useContext` consumers in `ProjectGraph`, flagging unstable provider values and overloaded contexts where high-frequency **State Slots** force re-renders on consumers that only read static fields, so that tree-wide re-render storms are eliminated.
22. As a senior engineer, I want `dotore` to trace the cross-file call graph starting from `useFrame` (React Three Fiber) and `requestAnimationFrame` callbacks to detect transitive object allocations (`new Vector3`, `new Color`, fresh arrays/closures) and `setState` calls running at 60fps, so that frame-loop jank is caught statically even when helper functions live in separate modules.
23. As a senior engineer, I want `dotore` to verify in `ProjectGraph` that every **Subject** using suspending APIs (`use()`, `useSuspenseQuery`, `React.lazy`, Next.js `useSearchParams`) or throwing boundaries is covered by an ancestral `<Suspense>` or `<ErrorBoundary>` across its **Caller Sites**, so that unhandled suspense/error crashes are prevented before runtime.
24. As a developer, I want `dotore` to build the full module dependency graph in `ProjectGraph` (honoring `tsconfig.json` `paths`, workspace packages, barrel re-exports, dynamic `import()`, and platform suffixes `.ios`, `.android`, `.native`, `.web`) to report `unused-file`, `unused-export`, `unused-type`, `unused-dependency`, `unused-dev-dependency`, and `circular-dependency`, so that dead code and import cycles are detected in the same single pass.
25. As a developer, I want `dotore` to compute normalized structural hashes of JSX subtrees across all **Subjects** and report `duplicate-jsx-subtree` when identical or near-identical UI blocks are copy-pasted across components, so that shared UI primitives can be extracted cleanly.

### Full Ecosystem & Domain Rule Families

26. As a developer, I want `dotore` to run all React built-in and correctness rules (`jsx-key`, `no-array-index-as-key`, `no-random-key`, `rendering-conditional-render` stray `0`, `checked-requires-onchange-or-readonly`, `button-has-type`, `radio-input-missing-name`, `only-export-components`, `no-nested-component-definition`, `prefer-module-scope-static-value`, `prefer-module-scope-pure-function`), preserving all adversarial regression cases so valid idioms never trigger false positives.
27. As a developer, I want `dotore` to run JavaScript and bundle performance rules (`async-parallel`, `async-await-in-loop`, `async-defer-await`, `no-spread-accumulator-in-reduce`, `no-json-parse-stringify-clone`, `no-barrel-import`, `no-full-lodash-import`, `no-moment`, `prefer-dynamic-import`, `client-passive-event-listeners`, `no-transition-all`, `no-layout-property-animation`), so that CPU, network, layout, and bundle bottlenecks are caught statically.
28. As a developer, I want `dotore` to run the complete accessibility (`a11y`) rule suite (`alt-text`, `aria-role`, `no-redundant-roles`, `control-has-associated-label`, `click-events-have-key-events`, `mouse-events-have-key-events`, `no-static-element-interactions`, `no-noninteractive-element-to-interactive-role`, `no-autofocus`, `html-has-lang`, `anchor-is-valid`, `anchor-has-content`, `anchor-ambiguous-text`, `anchor-target-exists`, `no-outline-none`, `no-disabled-zoom`, and project-wide `require-reduced-motion` across CSS and motion libraries), so that WCAG compliance is enforced automatically.
29. As a UI engineer, I want `dotore` to support the `design` rule family (typography scale, icon button touch targets, image dimensions, redundant padding/size axes, flex/space layout conflicts, decorative pulse/spotlight anti-patterns, smooth-scroll reduced-motion guards, vague button labels) as opt-in during standard scans and active via `dotore design`, so that teams can run focused UI polish audits on demand.
30. As a security engineer, I want `dotore` to run all static security and trust-boundary rules (`no-danger`, `dangerous-html-sink` with cross-file sanitizer awareness, `unsafe-json-in-html`, `window-open-without-noopener`, `no-secrets-in-client-code`, `public-env-secret-name`, `artifact-secret-leak`, `artifact-env-leak`, `auth-token-in-web-storage`, `raw-sql-injection-risk`, `nosql-injection-risk`, `command-execution-input-risk`, `path-traversal-risk`, `untrusted-redirect-following`, `jwt-insecure-verification`, `webhook-signature-risk`, `postmessage-origin-risk`, `cors-cookie-trust-risk`, `supabase-table-missing-rls`, `supabase-rls-policy-risk`, `supabase-client-owned-authzField`, `firebase-permissive-rules`, `firebase-client-owned-authz-field`, `mcp-tool-capability-risk`, `agent-tool-capability-risk`, `require-pnpm-hardening`, and vulnerable React Server Components advisories), so that exploitable vulnerabilities and secret leaks are blocked before commit.
31. As a Next.js or React Server Components developer, I want `dotore` to run server and Next.js rules (`server-auth-actions`, `server-sequential-independent-await` including cross-file cached async awareness, `server-no-mutable-module-state`, `server-hoist-static-io`, `nextjs-async-dynamic-api-not-awaited`, `nextjs-no-img-element` with custom wrapper awareness, `nextjs-no-side-effect-in-get-handler`, `nextjs-async-client-component`), so that server/client boundary bugs and server waterfalls are caught early.
32. As a TanStack developer, I want `dotore` to run TanStack Query and TanStack Start rules (`query-no-query-in-effect`, `query-no-mutation-in-effect-as-read`, `query-no-use-query-for-mutation`, `query-stable-query-client`, `query-no-void-query-fn`, `query-no-rest-destructuring`, `tanstack-start-server-fn-validate-input`, `tanstack-start-redirect-in-try-catch`, `tanstack-start-no-use-server-in-handler`), so that data-fetching and server-function anti-patterns are prevented.
33. As a React Native or Expo developer, I want `dotore` to run all mobile rules (`rn-no-raw-text` honoring configured `textComponents` and `rawTextWrapperComponents`, `rn-list-recyclable-without-types`, `rn-list-missing-estimated-item-size`, `rn-scrollview-flex-in-content-container`, `rn-scrollview-dynamic-padding`, `rn-prefer-expo-image`, `rn-style-prefer-box-shadow`, `expo-no-non-inlined-env`, and native project config checks), so that mobile crashes and FlashList/ScrollView performance regressions are avoided.
34. As a Three.js or React Three Fiber developer, I want `dotore` to run the 180+ WebGL, WebGPU, Three.js, and R3F rules (geometry/material/texture/postprocessing disposal, `useFrame` allocations and sync readbacks, instancing, color-space configuration, shadow camera/bias checks, WebGPU initialization and legacy material APIs), so that GPU memory leaks and frame drops are caught statically.
35. As a developer using Zustand, Jotai, MobX, Valtio, Preact, Ink, View Transitions, or Zod, I want `dotore` to run the respective state-store, terminal-UI, and schema rules (`zustand-no-mutating-state`, `zustand-no-fresh-selector-result`, `zustand-no-whole-store-destructure`, `jotai-select-atom-in-render-body`, `jotai-derived-atom-returns-fresh-object`, `mobx-reaction-disposer-discarded`, `valtio-no-proxy-read-in-render`, `valtio-no-snapshot-in-callback`, `ink-*`, `preact-*`, `zod-v4-*`), so that library-specific footguns are caught automatically when those packages are present in the **Capability Gate**.

### Deterministic Auto-Fixer (`dotore fix`), Fix Capsules, and Planner (`dotore plan`)

36. As a developer or AI agent, I want `dotore fix` to apply all `Autofix`-tier `ByteEdit` patches directly in Rust across single files and unambiguous cross-file **Caller Sites** (with `--dry-run` preview support), so that mechanical fixes are completed in milliseconds without invoking an LLM.
37. As a developer, I want `dotore fix` to resolve overlapping or adjacent byte spans safely and guarantee that re-analyzing the modified files produces valid syntax and clears the targeted diagnostics, so that automated rewrites never corrupt source code.
38. As an AI agent, I want `dotore` to group related findings into a single **Root-Cause Group** (such as multiple **State Slots** reset on the same prop change, all consumers of one unstable context, or all sites of a duplicated JSX subtree), so that I execute one cohesive intervention instead of redundant piecemeal edits.
39. As an AI agent, I want `dotore` to compute a deterministic **Blast Radius** for every **Root-Cause Group** based on static `ProjectGraph` evidence (presence inside `.map()`/lists or 60fps `useFrame`/RAF loops, subtree depth, `Context.Provider` consumer count, and **Render Cascade** length), so that findings are prioritized by real runtime leverage without spawning auditing sub-agents.
40. As an AI agent, I want every `Surgical` and `Refactor` **Root-Cause Group** in `dotore check --json` and `dotore why <file:line>` to include a complete **Fix Capsule** containing the verbatim source excerpt of the owning **Subject**, verbatim excerpts of all cross-file **Caller Sites**, the embedded canonical transformation recipe, and a discovered repository **Exemplar**, so that I can apply the fix immediately without running `curl`, `grep`, or exploratory file reads.
41. As a tech lead or AI agent, I want `dotore plan [paths...] [--out plans/]` to deterministically generate self-contained `plans/NNN-<slug>.md` files and a prioritized `plans/README.md` index stamped with the current git commit SHA, so that teams or downstream coding agents can execute high-leverage refactoring roadmaps without spending LLM tokens on planning.

### Native Symbol Search (`dotore search`), Diff Scopes, Baseline, Score & Runtime Scan

42. As an AI agent or developer, I want `dotore search <query> [paths...] [--kind ...] [--limit ...] [--format text|json]` to perform fast fuzzy search over **Symbol Outlines** (`function`, `class`, `interface`, `type`, `enum`, `constant`, `method`, `property`, `export`) extracted natively by the OXC pass, rendering signatures, adjacent doc comments, and enclosing class/object context, so that I can discover reusable helpers and types in milliseconds before writing new code.
43. As a developer, I want `dotore check` to support `--scope full`, `--scope changed`, `--scope contextual`, and `--scope lines` (plus `--base <ref>` and `--staged`), using each rule's **Contextual Owner** (line, JSX element, **Subject**, file, or explicit related AST nodes) so that editing a component or dependency array surfaces relevant findings in the touched unit without noise from untouched areas.
44. As a CI engineer, I want `dotore check --baseline <report.json>` to compare findings as a multiset of normalized AST/content fingerprints independent of file renames or line-number shifts, so that refactored or moved files only fail CI when net-new issues are introduced.
45. As a developer or CI pipeline, I want `dotore` to compute the `0..=100` Health Score, human label, and per-rule priority tiers (`P0`–`P3`) 100% locally and deterministically in Rust (with `--score` printing only the numeric score and `--blocking error|warning|none` / `--warning-exit-code <N>` controlling exit status), so that scoring works offline in sub-millisecond time.
46. As a developer, I want `dotore rules list | explain | enable | disable | set | category | ignore-tag | unignore-tag` and `dotore why <file:line>` to query the compiled-in rule catalog and update `dotore.config.*` or `package.json#dotore` in place, so that understanding and tuning rules requires zero internet access.
47. As a performance engineer, I want `dotore scan [url] [--cdp <ws-or-http-url>] [--trace-out <path>] [--format text|json|jsonl]` to connect directly to Chrome via the Chrome DevTools Protocol in Rust, inject the embedded runtime render probe, record Long Animation Frames, script hotspots, interactions, and React component render counts, and save the compressed `.json.gz` trace locally, so that live interaction profiling works from the same single Rust binary without Node.js or Playwright dependencies.
48. As a developer, I want `dotore report` to generate a self-contained offline HTML report visualizing **Render Cascades**, **Blast Radius** rankings, **Root-Cause Groups**, and cross-file **Caller Sites**, and `dotore ci` / `dotore install` to set up GitHub Actions workflows and the unified `/dotore` agent skill.

## Implementation Decisions

1. **Single-Crate Pure-Rust Architecture with Language-Agnostic Remediation Core**:
   - The system remains a single Rust library and binary crate (`dotore`) with zero Node.js, V8, or external runtime dependencies.
   - Internal domain modules are cleanly separated between the React/TypeScript frontend (`scanner`, `config`, `ir`, `graph`, `rules`, `search`) and the language-agnostic remediation and reporting core (`fixer`, `planner`, `diff`, `score`, `report`), enabling the remediation/planning/scoring engine to be reused directly in a future Rust-target analyzer.
2. **Single-Pass OXC Parsing with Pragmatic Semantic Access**:
   - Each discovered source file is parsed once per run on a `rayon` thread pool using `oxc_parser` and `oxc_semantic`.
   - The extraction pass builds a unified `FileIr` containing:
     - `SubjectIr` (functional components and custom hooks, props, **State Slots**, **Effect Nodes**, memo/callback/ref bindings, context providers/consumers, and frame-loop registrations),
     - `JsxElementIr` (JSX elements, resolved attributes, key provenance, event handlers, inline style/class metadata, and structural subtree hashes),
     - `ModuleIr` (static/dynamic imports, exports, re-exports, and **Symbol Outlines** with adjacent comments),
     - `FlowAndMutationIr` (direct mutations on state/reducers/stores, loop-nested `await` vs. parallel async flows, and render-path allocations),
     - `SecurityAndServerIr` (trust boundaries, `"use server"` / `"use client"` directives, environment variable reads, and HTML/SQL/command/redirect sinks).
   - While rules consume `FileIr` and `ProjectGraph` for shared facts and cross-file relationships, individual rule detectors may inspect `oxc_semantic::Semantic` AST and scope nodes directly during the per-file pass whenever fine-grained syntax or control-flow checks are required to preserve 100% edge-case parity with the reference test suites.
3. **In-Memory `ProjectGraph` and Cross-File Resolution**:
   - After parallel per-file extraction, `ProjectGraph` links all `FileIr` instances in memory:
     - Resolves module specifiers across relative paths, `tsconfig.json` `paths`/`baseUrl`, workspace packages, barrel `export *` / named re-exports, and platform suffixes (`.ios`, `.android`, `.native`, `.web`).
     - Indexes all JSX **Caller Sites** to their target child **Subjects**, tracking passed props, `key` attributes, `React.memo` wrapping, list/loop nesting, and ancestral `<Suspense>` and `<ErrorBoundary>` components.
     - Computes strongly connected components (Tarjan's algorithm) for `circular-dependency` and reachability from entrypoints for `unused-file`, `unused-export`, `unused-type`, `unused-dependency`, and `unused-dev-dependency`.
     - Indexes structural JSX subtree hashes across files to emit `duplicate-jsx-subtree`.
     - Traces cross-file function calls originating inside 60fps `useFrame` and `requestAnimationFrame` callbacks to detect transitive allocations and state updates.
4. **Capability Gate and Rule Registry**:
   - Every rule in the catalog carries static metadata: canonical ID, legacy aliases, category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`), default severity (`error` or `warning`), default enabled state, tags (`test-noise`, `design`, `migration-hint`, `react-jsx-only`, `webgl`, `three`, `r3f`, `react-native`, `security-scan`, `ink`, `server-action`, `project-analysis`, `opt-in`), **Capability Gate** predicate, **Contextual Owner** policy, **Prescription Tier**, and embedded remediation recipe.
   - Rules are filtered before evaluation by the package's resolved **Capability Gate** and user configuration (`dotore.config.*` or `package.json#dotore`).
5. **Root-Cause Grouping, Static Blast Radius, and Fix Capsules**:
   - Diagnostics sharing a single underlying defect (for example, multiple **State Slots** reset on the same prop change in a **Subject**, multiple consumers of an unstable context provider, or sibling occurrences of a root-cause-groupable rule) are assigned a deterministic `root_cause_group_id` (**Root-Cause Group**).
   - Each **Root-Cause Group** receives a deterministic **Blast Radius** score and tier (`P0`–`P3`) derived from:
     - Render frequency multiplier (inside `useFrame`/RAF 60fps loop > inside `.map()` list > standard render),
     - Cross-file fan-out (number of **Caller Sites**, child **Subjects**, or `Context` consumers affected),
     - **Render Cascade** depth (number of extra post-render passes triggered),
     - Rule category and severity weight.
   - Every `Surgical` and `Refactor` **Root-Cause Group** produces a self-contained **Fix Capsule**:
     ```rust
     // Decision-encoding type shape for FixCapsule
     pub struct FixCapsule {
         pub root_cause_group_id: String,
         pub rule: RuleId,
         pub tier: PrescriptionTier,
         pub blast_radius: BlastRadius,
         pub subject_excerpt: SourceExcerpt,
         pub caller_site_excerpts: Vec<SourceExcerpt>,
         pub recipe_markdown: &'static str,
         pub exemplar: Option<SourceExcerpt>,
         pub invariants: Vec<&'static str>,
     }
     ```
   - `exemplar` is populated deterministically by querying `ProjectGraph` for an existing valid usage of the prescribed pattern (e.g., an existing `useSyncExternalStore`, `useQuery`, or `React.memo` component in the same repository).
6. **Multi-File Deterministic Auto-Fixer (`dotore fix`) and Plan Generator (`dotore plan`)**:
   - `dotore fix` applies `AutofixPatch` byte edits across both single-file rules and unambiguous cross-file **Caller Site** rewrites (such as injecting `key={prop}` at parent **Caller Sites** while removing the child reset `useEffect`). Edits within each file are sorted in reverse byte-offset order and validated by re-parsing with `oxc_parser`.
   - `dotore plan` renders each `Surgical` and `Refactor` **Fix Capsule** into deterministic `plans/NNN-<slug>.md` files plus a `plans/README.md` table ordered by **Blast Radius**, stamped with the current `git rev-parse --short HEAD` commit.
7. **Native Fuzzy Symbol Search (`dotore search`)**:
   - Written from scratch in Rust over the `ModuleIr` **Symbol Outlines** extracted by `oxc_parser`.
   - Ranks symbols (`function`, `class`, `interface`, `type`, `enum`, `enum-member`, `constant`, `variable`, `method`, `property`, `export`, `import`) against the query using fuzzy subsequence + camelCase/kebab-case boundary scoring.
   - Renders grouped file outlines with line numbers, adjacent doc comments (truncated past 10 lines), enclosing class/object headers for methods/properties, and interface property summaries (capping large interfaces at 15 properties).
8. **Contextual Diff Filtering (`--scope`), Baseline Multiset Comparison, and Local Health Score**:
   - Git integration computes changed files and changed line ranges against `--base <ref>` or `--staged`.
   - Under `--scope contextual`, a diagnostic is included if any changed line intersects its **Contextual Owner** span (the owning **Subject**, JSX element, file, or explicit related AST nodes such as `[callback, dependency_array]`).
   - Under `--baseline <report.json>`, diagnostics are fingerprinted by rule identity, message, and normalized AST token slice (independent of file path and line number) and compared as multisets per rule so moved files or line shifts never report false regressions.
   - The `0..=100` Health Score is computed locally in Rust from the density and **Blast Radius** of active **Root-Cause Groups** normalized by analyzed **Subject** and file count.
9. **Native CDP Runtime Profiler (`dotore scan`)**:
   - Implemented directly in Rust over Chrome DevTools Protocol WebSocket (`--cdp <url>` or launching an isolated system Chrome process with `--remote-debugging-port=0`).
   - Injects the embedded runtime probe script via `Page.addScriptToEvaluateOnNewDocument`, records performance tracing (`Tracing.start` / `Tracing.end`), aggregates Long Animation Frames, script hotspots, user interactions, and React component render counts, and writes the `.json.gz` trace locally.

## Testing Decisions

1. **What Makes a Good Test**:
   - Tests assert only observable external behavior at public boundaries: emitted `Diagnostic` records, `Root-Cause Group` and `Blast Radius` rankings, `FixCapsule` contents, rewritten source strings from `dotore fix`, generated Markdown plans from `dotore plan`, symbol outlines from `dotore search`, and JSON/HTML/terminal output from CLI invocations.
   - Every rule test suite must include both **invalid** cases (verifying exact diagnostic count, rule ID, line/column, and `PrescriptionTier`) and **adversarial valid** cases (verifying zero false positives on look-alike valid idioms, aliased React imports, custom wrappers, and cold paths).
   - Auto-fix tests must re-run the analyzer on the rewritten output (`apply_patches_to_source` / `apply_autofixes`) and assert that the resulting code parses cleanly with zero remaining diagnostics.
2. **Primary Testing Seam (Single High-Level Library Seam + CLI Smoke Seam)**:
   - **Seam 1 (Primary — Crate Root Library API)**: All single-file rules, cross-file `ProjectGraph` rules, **Capability Gate** filtering, **Contextual Owner** diff scopes, baseline comparison, local scoring, `Autofix` rewrites, **Fix Capsule** generation, and `search` queries are tested through the top-level library entrypoints (`analyze_source`, `analyze_project_sources`, `apply_patches_to_source`, `plan_project`, `search_symbols`). This exercises the full `oxc_parser` → `FileIr` → `ProjectGraph` → `rules` → `fixer`/`planner`/`report` pipeline in memory without filesystem overhead.
   - **Seam 2 (Secondary — CLI Binary Smoke Tests)**: End-to-end `std::process::Command` tests on temporary workspaces verify CLI flag parsing, `dotore.config.*` / `package.json#dotore` loading, `dotore fix` on-disk file mutation, `dotore plan` directory output, `dotore report` HTML generation, and exit codes (`0`, `1`, `--warning-exit-code`).
3. **Prior Art in the Codebase**:
   - `tests/rules_parity.rs`, `tests/callbacks_store_and_fetch.rs`, `tests/cascades_and_guards.rs`, and `tests/caller_sites_and_prop_reset.rs` establish the table-driven `ValidCase` / `InvalidCase` harness over `analyze_source` and `analyze_project_sources`.
   - `tests/autofix.rs` establishes the round-trip rewrite + re-analyze invariant (`apply_patches_to_source` followed by `analyze_source(...).is_empty()`).
   - `tests/html_report.rs` establishes the self-contained HTML report and CLI integration pattern.
   - The local reference directory `react-docs/` (gitignored) provides the corpus of rule fixtures and `*.regressions.test.ts` edge cases to port into Rust integration test suites.

## Out of Scope

1. **External Telemetry and Crash Reporting Infrastructure**: No OTLP/Axiom span exporters, Sentry crash reporters, or analytics pings will be built; `dotore` runs with zero telemetry by design.
2. **Cloud Score API and Remote Prompt Hosting**: No remote HTTP service for health score calculation or Markdown prompt fetching; all scoring formulas and remediation recipes are compiled into the Rust binary.
3. **Published JavaScript/TypeScript Plugin Packages**: No ESLint JS plugin or Oxlint JS plugin wrappers will be published; `dotore` executes natively in Rust.
4. **Rust-Target Static Analyzer Rules**: While internal remediation, planning, scoring, and diff modules are designed to be language-agnostic for the upcoming Rust analyzer project, rules targeting `.rs` source files belong to the next project after `dotore`'s React/TypeScript catalog is complete.

## Further Notes

- The gitignored `react-docs/` folder serves strictly as a local behavioral and regression-fixture oracle during migration and will be removed once all rule families, CLI subcommands, and regression suites are verified in Rust.
- Never reference external competitor tool names anywhere in source code, comments, documentation, configuration keys, or CLI output; the sole canonical name across the entire surface is `dotore`.
