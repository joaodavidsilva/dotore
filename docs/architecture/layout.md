# Layout: Multi-Crate Cargo Workspace and CLI Facade

Basis: Cargo Book ("Package Layout") and Rust API Guidelines.

## Folder tree

```
crates/
  dotore-core/
    src/
      lib.rs              # language-agnostic core crate root and re-exports
      ir.rs               # SourceLoc, ByteSpan, SymbolOutline, FileSuppressions, ExtractedFile, LanguageAnalyzer
      config.rs           # configuration module root and re-exports
      config/
        workspace.rs      # WorkspacePackage discovery and path/JSONC normalization helpers
        capability_gate.rs # Capability, CapabilityPredicate, CapabilityGate across JS/Angular/Python/Rust
        loader.rs         # DotoreConfig loader and static JS/TS/JSONC parser
        mutator.rs        # in-place configuration mutator (dotore rules)
      rules.rs            # unified rule registry module root
      rules/
        types.rs          # RuleId, RuleMetadata, PrescriptionTier, Diagnostic, AutofixPatch, FixCapsule
        catalog.rs        # 965-rule static metadata catalog assembled across domain submodules
        catalog/
          react_core.rs   # React Effect Node, State Slot, hooks, lifecycle, and architecture rule metadata
          three_r3f_webgl.rs # Three.js, WebGL, and React Three Fiber 60fps frame-loop rule metadata
          a11y_and_design.rs # WCAG accessibility, ARIA, and UI design polish rule metadata
          performance_and_bundle.rs # React re-render, hydration, bundle size, and motion performance rule metadata
          security_and_server.rs # XSS, SSRF, Next.js App Router, Server Actions, RSC, and supply-chain rule metadata
          react_native_and_expo.rs # React Native and Expo mobile rule metadata
          ecosystem.rs    # Zustand, Jotai, MobX, Valtio, Preact, Ink, TanStack, Redux, and Zod v4 rule metadata
          defensive_and_correctness.rs # Defensive JS/TS/DOM safety, React Router, Remotion, and correctness rule metadata
          polyglot.rs     # Angular Signals/RxJS, Python, and Rust rule metadata
      scanner.rs          # parallel gitignore-aware file discovery
      fixer.rs            # surgical single- and cross-file byte-range auto-fixer with syntax validation
      diff.rs             # git diff, Contextual Owner, and baseline module root
      diff/
        patch.rs          # git revision validation, unified diff patch parsing, and git diff execution
        contextual_owner.rs # Contextual Owner span intersection and scope filtering
        baseline.rs       # diagnostic fingerprinting and baseline multiset comparison
      planner.rs          # Root-Cause Grouping, Blast Radius, Exemplar lookup, Fix Capsules (dotore plan)
      score.rs            # deterministic local 0-100 health score and P0-P3 tier calculation
      search.rs           # native fuzzy Symbol Outline search (dotore search)
      report.rs           # reporting module root and re-exports
      report/
        json.rs           # JsonReport schema, builders, and JSON file serializer
        terminal.rs       # terminal/ASCII report rendering built on crate::ui
        html.rs           # self-contained visual HTML cascade report renderer
        rules.rs          # rule catalog listing and rule explanation (dotore rules)
        why.rs            # location diagnosis and suppression/gate explanation (dotore why)
        ci_install.rs     # CI workflow automation (dotore ci) and skill/hook installer (dotore install)
      ui.rs               # reusable terminal UI kit (AsciiBox, GaugeBar, Badge, FlowDiagram, FilterTabBar, StatusBar, LiveSpinner)
  dotore-js/
    src/
      lib.rs              # JsLanguageAnalyzer (LanguageAnalyzer) and dotore-js crate root
      matchers.rs         # shared oxc AST/semantic matchers, JSX attribute inspectors, and Diagnostic builders
      ir.rs               # IR module root re-exporting FileIr and SubjectIr
      ir/
        types.rs          # FileIr, SubjectIr, StateSlot, EffectNode, CallerSite, JsxElementIr, MotionFileIr
        extract.rs        # single-pass oxc AST + semantic extraction orchestrator
        subject.rs        # Subject, StateSlot, and EffectNode single-pass extraction
        module_ir.rs      # module import, export, barrel, directive, route, and call extraction
        outlines_and_suppressions.rs # Symbol Outline and inline suppression extraction
        motion_and_frame_loop.rs # MotionFileIr and 60fps FrameLoopRootIr/FrameHelperIr extraction
        dataflow.rs       # dependency tracking, mutations, async flows, store/fetch sites
        react_ast.rs      # React Subject, hook, and JSX classification
        jsx_subtree.rs    # structural JSX subtree extraction and FNV-1a fingerprinting
      graph.rs            # ProjectGraph root: Caller Sites, Render Cascades, module graph, JSX hashes
      graph/
        resolution.rs     # module, tsconfig, workspace package, platform sibling, and barrel resolution
        callers_and_cascades.rs # cross-file Caller Site indexing and MultiEffectCascade linking
        dead_code.rs      # entrypoint reachability, orphan files, dead exports, unused deps, circular deps
        duplicate_jsx.rs  # duplicate JSX subtree family clustering and nested-subtree suppression
      planner.rs          # PlannerContext for ProjectGraph and cross-file autofix enrichment
      rules.rs            # rules engine dispatcher gated by Capability Gate
      rules/
        derived_state.rs  # derived state, chained state updates, mount initialization
        prop_sync.rs      # full state reset and partial state adjustment on prop change
        parent_flow.rs    # event-handler effects and upward parent callback notifications
        external_sync.rs  # external store subscriptions and effect data fetching
        a11y.rs           # WCAG and ARIA accessibility rules root and cross-file anchor verification
        a11y/
          tables.rs       # ARIA roles, properties, HTML tag classifications, autofill, and BCP-47 tables
          aria_and_roles.rs # ARIA attributes, roles, landmarks, dialogs, and semantic element rules
          keyboard_and_focus.rs # keyboard activation, focusability, tabindex, outline, and focus effect rules
          forms_media_and_content.rs # labels, form controls, alt text, anchors, media, headings, tables, and UI primitives
        angular.rs        # Angular Signals, RxJS teardown, OnPush autofix, @for track, lifecycle, and DOM rules
        architecture.rs   # Subject architecture rules root and cross-file ProjectGraph context/boundary dispatcher
        architecture/
          hoisting_and_compiler.rs # module-scope static/pure hoisting autofixes, nested components, and React Compiler memoization
          context_and_boundaries.rs # Context.Provider/useContext extraction, overloaded providers, and ancestral Suspense/ErrorBoundary checks
          component_contracts.rs # Subject size/complexity, boolean props, handler names, inline HOCs, and deprecated React APIs
        bundle_size.rs    # barrel imports, heavy packages, and dynamic import rules
        correctness.rs    # unstable keys, numeric && render, DOM nesting, and input rules
        defensive_js.rs   # defensive JS/TS/DOM runtime safety rules root and shared guard inspectors
        defensive_js/
          nullish_and_collections.rs # optional chaining, array bounds/find, non-null assertions, and object/template guards
          async_and_events.rs # async event handler re-entry, IME guards, request error collapse, finally resets, and predicates
          parsing_and_selectors.rs # querySelector, dynamic RegExp, numeric input parse, JSON.parse, and throwing URL/URI guards
        design.rs         # opt-in UI design and aesthetic heuristics rules root
        design/
          tailwind_and_styles.rs # Tailwind class fragments/shorthands, inline style heuristics, and WCAG contrast helpers
          typography_and_controls.rs # button labels, typography scale, touch targets, and media control rules
          surfaces_and_interactions.rs # card/surface composition, shadows, dark mode, and interaction state rules
          page_composition.rs # page-level landmark composition, hero/section hierarchy, and marketing copy anti-patterns
        ecosystem_ui.rs   # Preact, Ink terminal UI, and Zod v4 rules
        effect_teardown.rs# Effect Node teardown and React correctness rules root
        effect_teardown/
          dom_and_timer_teardown.rs # DOM listener, observer, RAF, timer, and promise cleanup verification
          hook_and_state_correctness.rs # hook dependency purity, reducer mutation, render-phase calls, and functional state updates
          jsx_and_lint_parity.rs # module-scope purity, class lifecycles, TypeScript JSX types, and JSX DOM attribute rules
        js_performance.rs # JavaScript runtime performance rules root
        js_performance/
          async_waterfalls.rs # sequential await waterfalls, loop awaits, deferred awaits, and async reduce rules
          dom_and_browser.rs # sync XHR, passive listeners, flushSync, View Transitions, storage caching, and DOM CSS batching
          collections_and_loops.rs # reduce spread, JSON clone, loop hoisting (Intl/RegExp/Map/Set), and immutable sort/early-exit rules
        performance.rs    # React re-render, hydration, and motion performance rules root
        performance/
          rerender_and_hooks.rs # memoization, derived hook state, JSX hoisting, state initializers, and useTransition loading
          animation_and_jsx.rs # SVG wrapper animation, layout property transitions, WAAPI/RAF/scroll loops, and motion springs
          hydration_and_routing.rs # hydration mismatch/flicker, SSR browser globals, locale formatting, and React Router loader fetches
        r3f.rs            # Three.js, WebGL, and React Three Fiber 60fps frame-loop rules
        react_native.rs   # React Native and Expo AST, animation/style, and project configuration rules
        react_builtins.rs # React built-in rules root and cross-file ProjectGraph inline prop gating
        react_builtins/
          hooks.rs        # exhaustive-deps, rules-of-hooks, and useState naming symmetry rules
          jsx_props_and_fragments.rs # button type, controlled inputs, target=_blank, fragments, PascalCase, JSX depth, and inline props
          components_and_classes.rs # Fast Refresh only-export-components, nested components, and legacy class component rules
        react_router.rs   # React Router v7/v8 route tree, loader/action/middleware, and navigation rules
        reduced_motion.rs # cross-file motion library and CSS prefers-reduced-motion rules
        remotion.rs       # Motion, Remotion, TanStack Form/Table/Virtual, Redux, and UI primitive rules
        security.rs       # XSS, eval, SSRF, and trust-boundary security rules root
        security/
          dom_and_client.rs # dangerous HTML sinks, window.open, client secrets, web storage tokens, eval, and CSP/sandbox rules
          injection_and_baas.rs # SQL/NoSQL/command/path injection, redirects, JWT/crypto/cookies, Supabase RLS, Firebase, and MCP/agent rules
          artifacts_and_runtime.rs # build artifact leaks, RPC/native bridges, SSR/MDX execution, and repository secret rules
        server_nextjs.rs  # Server Actions, RSC, and Next.js App Router rules
        state_and_effects.rs # state/effect loop, render setState, async/timer refs, and lazy init rules
        stores.rs         # Zustand, Jotai, MobX, and Valtio state-store rules
        supply_chain.rs   # pnpm hardening, RSC advisory, and Socket supply-chain rules
        tanstack.rs       # TanStack Query and TanStack Start loader/query rules
  dotore-py/
    src/
      lib.rs              # PyLanguageAnalyzer (LanguageAnalyzer) facade and dotore-py crate root
      matchers.rs         # shared Python AST matchers, PyScopeTracker, rule gating, and Diagnostic/Autofix builders
      manifest.rs         # pyproject.toml and requirements.txt Capability Gate inference
      ir.rs               # PyFileIr, single-pass Subject, SymbolOutline, ContextualOwnerSpansIr, and suppression extraction
      graph.rs            # Python package ProjectGraph analysis (circular imports, unused exports, unawaited coroutines)
      safety.rs           # Python runtime and resource safety rules
      asyncio.rs          # asyncio concurrency hazard rules
      perf.rs             # hot-loop regex hoisting autofix and linear membership performance rules
      fastapi_pydantic.rs # FastAPI route/auth and Pydantic default_factory rules
      orm.rs              # SQLAlchemy and Django ORM N+1 loop query rule
      security.rs         # Python SQL injection and unsafe deserialization/shell rules
  dotore-rs/
    src/
      lib.rs              # RsLanguageAnalyzer (LanguageAnalyzer) and dotore-rs crate root
      matchers.rs         # shared syn AST, type, attribute, and lexical-scope matchers (RsScopeTracker)
      manifest.rs         # Cargo.toml Capability Gate discovery and package role classification
      ir.rs               # single-pass syn AST, Subject, SymbolOutline, and suppression extraction
      graph.rs            # Rust crate ProjectGraph analysis (rs-arch-no-unused-pub-crate-items)
      rules.rs            # Rust rule activation gating and rule pipeline dispatcher
      safety.rs           # single-pass detectors for the 5 core production Rust safety rules
      tokio_async.rs      # single-pass detectors for Tokio async concurrency hazards
      perf.rs             # single-pass detectors for Rust allocation and hot-loop performance rules
      axum_sqlx.rs        # single-pass detectors for Axum shared state contention and SQLx query hazards
      ui_signals.rs       # single-pass detectors for Leptos/Dioxus reactive signals and boolean params
src/
  main.rs                 # thin CLI adapter: parses args and returns process exit code
  lib.rs                  # root workspace facade: dispatches through LanguageAnalyzers and re-exports API
  cli.rs                  # Clap CLI definitions and subcommand execution runners
  progress.rs             # live terminal progress bar and 30fps spinner animation (dotore_core::ui::LiveSpinner)
  tui.rs                  # interactive TUI explorer (hjkl/arrows, filter tabs, grouping modes, / search, ESC exit)
  scanner.rs              # parallel gitignore-aware file discovery facade
  config.rs               # dotore.config.* / package.json loader and Capability Gate facade
  fixer.rs                # surgical single- and cross-file byte-range auto-fixer facade (dotore fix)
  planner.rs              # Root-Cause Grouping, Blast Radius, Exemplar lookup, Fix Capsules facade (dotore plan)
  search.rs               # native fuzzy AST Symbol Outline search facade (dotore search)
  diff.rs                 # git diff, Contextual Owner filtering, and baseline multiset comparison facade
  score.rs                # deterministic local 0-100 health score and P0-P3 tier calculation facade
  runtime_scan.rs         # native CDP WebSocket runtime profiler root (dotore scan)
  runtime_scan/
    transport.rs          # TCP, HTTP /json/version, RFC 6455 WebSocket transport, JSON-RPC multiplexing, and GzipStoredWriter
    probe.rs              # local HTTP port discovery, interactive URL prompt, browser probe, and snapshot relay scripts
    capture.rs            # Chrome binary discovery, isolated process launcher, CDP target selection, and trace capture
    analysis.rs           # snapshot validation, multi-navigation merging, React/LoAF/interaction hotspot aggregation, and report builder
    report.rs             # terminal, JSON, and JSONL report formatters for RuntimeScanReport
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
