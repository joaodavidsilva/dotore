# 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**What to build:** Establish the unified rule registry, project configuration loader, automatic **Capability Gate** inference, inline suppression pipeline, and single-pass OXC extraction + semantic access so that all 900+ rules and downstream analyzers can plug into a single parallel pass per file without redundant parsing or regression in existing **Subject** dataflow rules.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Every registered rule exposes structured metadata: canonical identifier, legacy aliases, category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`), default severity (`error` or `warning`), default enabled state, tags (`test-noise`, `design`, `migration-hint`, `react-jsx-only`, `webgl`, `three`, `r3f`, `react-native`, `security-scan`, `ink`, `server-action`, `project-analysis`, `opt-in`), **Capability Gate** predicate, **Contextual Owner** policy, **Prescription Tier**, and compiled-in remediation recipe.
- [x] Scanning a workspace automatically discovers nested packages and computes each package's **Capability Gate** from its declared dependencies (`react`, `next`, `react-native`, `expo`, `@tanstack/react-query`, `@tanstack/react-start`, `three`, `@react-three/fiber`, `zustand`, `jotai`, `mobx`, `valtio`, `preact`, `ink`, `zod`, motion libraries, and React Compiler configuration), enabling only rules whose **Capability Gate** is satisfied.
- [x] User configuration is loaded from `dotore.config.*` or the `"dotore"` key in `package.json`, supporting rule-level and category-level severity overrides (`"off"`, `"warn"`, `"error"`), ignored file globs, per-path override blocks, ignored tags, `customRulesOnly`, `textComponents`, `rawTextWrapperComponents`, and `runtimeGlobals`, with CLI flags taking precedence.
- [x] Inline suppression comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`) and file-level disable directives are honored by default and bypassed when `--no-inline-disables` is passed.
- [x] Rules tagged `test-noise` are automatically suppressed in test and story files unless also tagged `migration-hint`, and library packages skip application-only rules on library entrypoints.
- [x] Each source file is parsed once per run via `oxc_parser` and `oxc_semantic`, providing both extracted intermediate representation facts (**Subject**, **State Slot**, **Effect Node**, **Caller Site**, JSX elements, module imports/exports, **Symbol Outlines**, mutations, async flows, and security sinks) and direct semantic AST/scope access during per-file rule evaluation.
- [x] All existing **Effect Node** and **State Slot** dataflow rules, **Render Cascade** checks, and `Autofix` tests continue to pass with zero regressions.
