# Layout: Multi-Crate Cargo Workspace and CLI Facade

Basis: Cargo Book ("Package Layout") and Rust API Guidelines.

## Folder tree

```
crates/
  dotore-core/
    src/
      lib.rs              # language-agnostic core crate root and re-exports
      ir.rs               # SourceLoc, ByteSpan, SymbolOutline, ExtractedFile, LanguageAnalyzer
      config.rs           # workspace package discovery and config utilities
      config/
        capability_gate.rs # Capability, CapabilityPredicate, CapabilityGate across JS/Angular/Python/Rust
        loader.rs         # DotoreConfig loader and in-place mutator
      rules.rs            # unified rule registry module root
      rules/
        types.rs          # RuleId, RuleMetadata, PrescriptionTier, Diagnostic, AutofixPatch, FixCapsule
      scanner.rs          # parallel gitignore-aware file discovery
      fixer.rs            # surgical single- and cross-file byte-range auto-fixer with syntax validation
      diff.rs             # git diff, Contextual Owner filtering, and baseline multiset comparison
      planner.rs          # Root-Cause Grouping, Blast Radius, Exemplar lookup, Fix Capsules (dotore plan)
      score.rs            # deterministic local 0-100 health score and P0-P3 tier calculation
      search.rs           # native fuzzy Symbol Outline search (dotore search)
      report.rs           # terminal, JSON, why/explain, CI, install, and HTML reporters
  dotore-js/
    src/
      lib.rs              # JsLanguageAnalyzer (LanguageAnalyzer) and dotore-js crate root
      ir.rs               # IR module root re-exporting FileIr and SubjectIr
      ir/
        types.rs          # FileIr, SubjectIr, StateSlot, EffectNode, CallerSite, JsxElementIr
        extract.rs        # single-pass oxc AST + semantic extraction
        dataflow.rs       # dependency tracking, mutations, async flows, store/fetch sites
        react_ast.rs      # React Subject, hook, and JSX classification
      graph.rs            # ProjectGraph: Caller Sites, Render Cascades, module graph, JSX hashes
      planner.rs          # PlannerContext for ProjectGraph and cross-file autofix enrichment
      rules.rs            # rules engine dispatcher gated by Capability Gate
      rules/
        derived_state.rs  # derived state, chained state updates, mount initialization
        prop_sync.rs      # full state reset and partial state adjustment on prop change
        parent_flow.rs    # event-handler effects and upward parent callback notifications
        external_sync.rs  # external store subscriptions and effect data fetching
        a11y.rs           # WCAG and ARIA accessibility rules
        angular.rs        # Angular Signals, RxJS teardown, OnPush autofix, @for track, lifecycle, and DOM rules
        architecture.rs   # Subject size/complexity, props, inline HOCs, hoisting, and context/boundary rules
        bundle_size.rs    # barrel imports, heavy packages, and dynamic import rules
        correctness.rs    # unstable keys, numeric && render, DOM nesting, and input rules
        defensive_js.rs   # defensive JS/TS/DOM runtime safety, optional chaining, and parse guards
        design.rs         # opt-in UI design, aesthetic heuristics, and Tailwind layout rules
        ecosystem_ui.rs   # Preact, Ink terminal UI, and Zod v4 rules
        effect_teardown.rs# Effect Node listener/observer/RAF/timer teardown and React correctness rules
        js_performance.rs # loop, hot-path JavaScript allocation, and immutable sort/early-exit rules
        performance.rs    # React re-render, transition loading, hydration, and CSS/SVG motion performance rules
        r3f.rs            # Three.js, WebGL, and React Three Fiber 60fps frame-loop rules
        react_native.rs   # React Native and Expo AST, animation/style, and project configuration rules
        react_builtins.rs # exhaustive-deps, rules-of-hooks, JSX/fragment built-ins, class lifecycles, and inline prop gating
        react_router.rs   # React Router v7/v8 route tree, loader/action/middleware, and navigation rules
        reduced_motion.rs # cross-file motion library and CSS prefers-reduced-motion rules
        remotion.rs       # Motion, Remotion, TanStack Form/Table/Virtual, Redux, and UI primitive rules
        security.rs       # XSS, eval, SSRF, and trust-boundary security rules
        server_nextjs.rs  # Server Actions, RSC, and Next.js App Router rules
        state_and_effects.rs # state/effect loop, render setState, async/timer refs, and lazy init rules
        stores.rs         # Zustand, Jotai, MobX, and Valtio state-store rules
        supply_chain.rs   # pnpm hardening, RSC advisory, and Socket supply-chain rules
        tanstack.rs       # TanStack Query and TanStack Start loader/query rules
  dotore-py/
    src/
      lib.rs              # PyLanguageAnalyzer (LanguageAnalyzer), pyproject.toml capability gate, and Python safety rules
      web_orm_security.rs # Pydantic, FastAPI, SQLAlchemy/Django ORM N+1, and SQL/shell/deserialization security rules
      async_perf_arch.rs  # asyncio concurrency hazards, regex hoisting autofix, and loop membership performance rules
      graph.rs            # Python package ProjectGraph analysis (circular imports, unused exports, unawaited coroutines)
  dotore-rs/
    src/
      lib.rs              # RsLanguageAnalyzer and Cargo.toml Capability Gate discovery
      ir.rs               # single-pass syn AST, Subject, SymbolOutline, and suppression extraction
      rules.rs            # Rust rule activation gating and core safety rule evaluation
      axum_sqlx_ui_arch.rs# single-pass detectors for Axum, SQLx, Leptos/Dioxus UI signals, and boolean params
      graph.rs            # Rust crate ProjectGraph analysis (rs-arch-no-unused-pub-crate-items)
      tokio_perf.rs       # single-pass Tokio async hazard and Rust allocation performance detectors
src/
  main.rs                 # thin CLI entrypoint: parses args and dispatches subcommands
  lib.rs                  # root workspace facade: dispatches through LanguageAnalyzers and re-exports API
  scanner.rs              # parallel gitignore-aware file discovery facade
  config.rs               # dotore.config.* / package.json loader and Capability Gate facade
  fixer.rs                # surgical single- and cross-file byte-range auto-fixer facade (dotore fix)
  planner.rs              # Root-Cause Grouping, Blast Radius, Exemplar lookup, Fix Capsules facade (dotore plan)
  search.rs               # native fuzzy AST Symbol Outline search facade (dotore search)
  diff.rs                 # git diff, Contextual Owner filtering, and baseline multiset comparison facade
  score.rs                # deterministic local 0-100 health score and P0-P3 tier calculation facade
  runtime_scan.rs         # native CDP WebSocket runtime profiler (dotore scan)
  report.rs               # terminal, JSON, why/explain, and self-contained HTML reporters facade
docs/
  adr/                    # architecture decision records
  agents/                 # issue-tracker, triage-labels, domain conventions
  architecture/
    layout.md             # this file
```

## Layout rules in force

| # | Rule | Enforced by |
|---|---|---|
| 1 | `src/main.rs` is a thin adapter (CLI parsing and exit code only); all analysis, rules, fixing, and reporting live under `src/lib.rs` and its internal modules. | `review` |
| 2 | Group internal modules by domain responsibility (`scanner`, `ir`, `graph`, `rules`, `fixer`, `report`). When a module splits into submodules, use Rust 2018+ layout (`src/rules.rs` + `src/rules/<sub.rs>`), never `mod.rs`. | `review` |
| 3 | Mark internal cross-module items `pub(crate)`; expose `pub` only on `src/lib.rs` entry types and functions needed by the binary and integration tests. | `missing_docs` (`Cargo.toml`) + `review` |
| 4 | Parse each file once with `oxc_parser` + `oxc_semantic`; rules consume `FileIr`, `ProjectGraph`, and `oxc_semantic` directly when needed to preserve full edge-case precision without artificial indirection. | `review` |
| 5 | Write clear, idiomatic Rust readable by both junior and senior engineers; never split cohesive logic solely to satisfy arbitrary line-count thresholds. | `review` |
| 6 | Lint suppressions must use `#[expect(lint, reason = "...")]`, never `#[allow(...)]`. | `clippy::allow_attributes`, `clippy::allow_attributes_without_reason` |
