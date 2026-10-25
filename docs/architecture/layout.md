# Layout: Multi-Crate Cargo Workspace and CLI Facade

Basis: Cargo Book ("Package Layout") and Rust API Guidelines.

## Folder tree

```
crates/
  dotore-core/
    src/
      lib.rs              # language-agnostic core crate root and re-exports
      ir.rs               # SourceLoc, ByteSpan, SymbolOutline, ExtractedFile, LanguageAnalyzer
      ir/
        facets.rs         # ConcernBucket, ConcernSignalSite, HelperFingerprintIr, ArchitectureFileFacets
        suppressions.rs   # FileSuppressions, inline comment/attribute suppression parsers, and Rust lint mapping
      config.rs           # configuration module root and re-exports
      config/
        workspace.rs      # WorkspacePackage discovery and path/JSONC normalization helpers
        capability_gate.rs # Capability, CapabilityPredicate, CapabilityGate across JS/Angular/Python/Rust
        loader.rs         # DotoreConfig loader and JSON/JSONC parser
        loader/
          js_parser.rs    # zero-dependency static JS/TS object config parser (ConfigCursor)
        mutator.rs        # in-place configuration mutator (dotore rules)
        pyproject.rs      # [tool.dotore] pyproject.toml loader and profile inference
      rules.rs            # unified rule registry module root
      rules/
        types.rs          # RuleId, RuleMetadata, PrescriptionTier, RuleCategory, RuleSeverity, RuleTag
        types/
          diagnostics.rs  # Diagnostic, AutofixPatch, RootCauseGroup, BlastRadius, FixCapsule
        catalog.rs        # 1076-rule static metadata catalog assembled across domain submodules
        catalog/
          react_core.rs   # React Effect Node, State Slot, hooks, lifecycle, and architecture rule metadata
          react_core/
            extended_part_1.rs # extended React core and built-in rule metadata (part 1)
            extended_part_2.rs # extended React core and built-in rule metadata (part 2)
          three_r3f_webgl.rs # Three.js, WebGL, and React Three Fiber 60fps frame-loop rule metadata
          three_r3f_webgl/
            part_2.rs     # Three.js and WebGL rule metadata (part 2)
            part_3.rs     # R3F and GLSL shader rule metadata (part 3)
            part_4.rs     # WebGPU and TSL rule metadata (part 4)
          a11y_and_design.rs # WCAG accessibility, ARIA, and UI design polish rule metadata
          a11y_and_design/
            part_2.rs     # WCAG accessibility and ARIA rule metadata (part 2)
            part_3.rs     # UI design polish rule metadata (part 3)
            part_4.rs     # extended UI design and typography rule metadata (part 4)
          performance_and_bundle.rs # React re-render, hydration, bundle size, and motion performance rule metadata
          performance_and_bundle/
            part_2.rs     # bundle size and JS runtime performance rule metadata (part 2)
          security_and_server.rs # XSS, SSRF, Next.js App Router, Server Actions, RSC, and supply-chain rule metadata
          security_and_server/
            part_2.rs     # Next.js App Router and Server Actions rule metadata (part 2)
            part_3.rs     # security-scan and supply-chain rule metadata (part 3)
          react_native_and_expo.rs # React Native and Expo mobile rule metadata
          react_native_and_expo/
            part_2.rs     # Expo config and platform rule metadata (part 2)
          ecosystem.rs    # Zustand, Jotai, MobX, Valtio, Preact, Ink, TanStack, Redux, and Zod v4 rule metadata
          defensive_and_correctness.rs # Defensive JS/TS/DOM safety, React Router, Remotion, and correctness rule metadata
          defensive_and_correctness/
            part_2.rs     # React Router v7/v8 rule metadata (part 2)
            part_3.rs     # Remotion, Motion, TanStack Form/Table/Virtual, and UI primitive rule metadata (part 3)
          polyglot.rs     # Core Angular Signals/RxJS, Python, Rust, and architecture rule metadata
          angular_extended.rs # Extended Angular Signals, lifecycle, decorator, template a11y, NgRx, and Material rule metadata
          python_extended.rs # Extended Python Zen, complexity, wildcard import, Bandit security, and PEP 561 rule metadata
          rust_extended.rs # Extended Rust SourceKernel, Cargo manifest/lockfile health, structural, and Clippy-grade rule metadata
          trust_boundary_security.rs # Deterministic trust-boundary security rule metadata
      fixer.rs            # surgical single- and cross-file byte-range auto-fixer with syntax validation
      diff.rs             # git diff, Contextual Owner, and baseline module root
      diff/
        patch.rs          # git revision validation, unified diff patch parsing, and git diff execution
        contextual_owner.rs # Contextual Owner span intersection and scope filtering
        baseline.rs       # diagnostic fingerprinting and baseline multiset comparison
      planner.rs          # Root-Cause Grouping, Blast Radius, and PlannerContext (dotore plan)
      planner/
        capsules.rs       # Fix Capsule and Exemplar synthesis
        markdown.rs       # Plan and Fix Capsule Markdown/terminal formatting
        handoff.rs        # coding-agent handoff bundle writer, prompt synthesis, and CLI launcher
      score.rs            # deterministic local 0-100 health score and P0-P3 tier calculation
      search.rs           # native fuzzy Symbol Outline search (dotore search)
      search/
        formatter.rs      # terminal and JSON symbol search output formatters
      report.rs           # reporting module root and re-exports
      report/
        json.rs           # JsonReport schema, builders, and JSON file serializer
        terminal.rs       # terminal/ASCII report rendering built on crate::ui
        html.rs           # self-contained visual HTML cascade report renderer
        rules.rs          # rule catalog listing and rule explanation (dotore rules)
        why.rs            # location diagnosis and suppression/gate explanation (dotore why)
        ci_install.rs     # CI workflow automation (dotore ci) and skill/hook installer (dotore install)
        redaction.rs      # automatic credential redaction (mask_credentials) across reports, why frames, and Fix Capsules
      ui.rs               # reusable terminal UI kit root (AsciiBox, ansi helpers, HighlightMode)
      ui/
        widgets.rs        # GaugeBar, Badge, FlowDiagram, FilterTabBar, StatusBar
        spinner.rs        # LiveSpinner 30fps background progress renderer
  dotore-js/
    src/
      lib.rs              # JsLanguageAnalyzer (LanguageAnalyzer) and dotore-js crate root
      matchers.rs         # shared oxc AST/semantic matchers, import resolvers, and Diagnostic builders
      matchers/
        jsx.rs            # shared JSX element, attribute, style, and subtree matchers
      ir.rs               # IR module root re-exporting FileIr and SubjectIr
      ir/
        types.rs          # FileIr, SubjectIr, StateSlot, EffectNode, CallerSite, JsxElementIr, MotionFileIr
        extract.rs        # single-pass oxc AST + semantic extraction orchestrator
        subject.rs        # Subject, StateSlot, and EffectNode single-pass extraction
        module_ir.rs      # module import, export, barrel, directive, route, and call extraction
        outlines_and_suppressions.rs # Symbol Outline and inline suppression extraction
        motion_and_frame_loop.rs # MotionFileIr and CSS @media (prefers-reduced-motion) extraction
        frame_loop.rs     # 60fps FrameLoopRootIr and FrameHelperIr extraction
        dataflow.rs       # dependency tracking, mutations, async flows, store/fetch sites
        react_ast.rs      # React Subject, hook, and JSX classification
        react_ast_subject.rs # Subject return-JSX, HOC, and suspense/throw body analysis
        jsx_subtree.rs    # structural JSX subtree extraction and FNV-1a fingerprinting
      graph/
        resolution.rs     # module, tsconfig, workspace package, platform sibling, and barrel resolution
        callers_and_cascades.rs # cross-file Caller Site indexing and MultiEffectCascade linking
        edges.rs          # module graph edge construction and cross-file dependency linking
        dead_code.rs      # entrypoint reachability, orphan files, dead exports
        cycles_and_deps.rs# unused package dependencies and circular module dependency detection
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
          forms_media_and_content.rs # labels, form controls, alt text, anchors, media, headings, and tables
          custom_and_ui_a11y.rs # custom component, motion/responsive, Radix, Base UI, React Aria, and shadcn a11y rules
        angular/
          signals_and_lifecycle.rs # Angular Signals, lifecycle hooks, and decorator contract rules
          metadata_and_arch.rs # @Component/@Directive/@Injectable/@Pipe metadata, DI, and architecture rules
          rxjs_and_dom.rs # RxJS subscription teardown, OnPush autofix, and direct DOM access rules
          template_a11y.rs# Angular HTML template @for track and WCAG/ARIA accessibility rules
          ngrx_and_material.rs # NgRx Store/Effects and Angular Material theme/directive conflict rules
        architecture.rs   # Subject architecture rules root and cross-file ProjectGraph context/boundary dispatcher
        architecture/
          hoisting_and_compiler.rs # module-scope static/pure hoisting autofixes, nested components, and React Compiler memoization
          context_and_boundaries.rs # Context.Provider/useContext extraction, overloaded providers, and ancestral Suspense/ErrorBoundary checks
          component_contracts.rs # Subject size/complexity, boolean props, handler names, inline HOCs, and deprecated React APIs
          soc_rules.rs    # JS/TS Separation of Concerns and reuse facets and detectors root
          soc_rules/
            classifiers.rs # entrypoint, I/O, presentation, and static catalog AST classifiers
            helper_duplication.rs # private helper structural fingerprinting and duplicate helper evaluation
            builder_and_terminal_ui.rs # multi-field object construction, fluent builders, and inline terminal UI detectors
        bundle_size.rs    # heavy packages, Moment/Lodash, and undeferred third-party script rules
        bundle_size/
          barrel_imports.rs # cross-file barrel import resolution and deep-import autofix synthesis
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
          typography_and_hero_patterns.rs # extended typography, label, SVG/navigation chrome, and hero/section layout rules
          page_composition.rs # page-level landmark composition, hero/section hierarchy, and marketing copy anti-patterns
        ecosystem_ui.rs   # Preact and Zod v4 rules root
        ecosystem_ui/
          ink.rs          # Ink terminal UI component, layout, and input rules
        effect_teardown.rs# Effect Node teardown and React correctness rules root
        effect_teardown/
          dom_and_timer_teardown.rs # DOM listener, observer, RAF, timer, and promise cleanup verification
          hook_and_state_correctness.rs # hook dependency purity, reducer mutation, render-phase calls, and functional state updates
          jsx_and_lint_parity.rs # module-scope purity, class lifecycles, and TypeScript JSX type rules
          jsx_element_parity.rs # JSX DOM attribute, anchor, iframe, and dangerouslySetInnerHTML parity rules
        js_performance.rs # JavaScript runtime performance rules root
        js_performance/
          async_waterfalls.rs # sequential await waterfalls, loop awaits, deferred awaits, and async reduce rules
          dom_and_browser.rs # sync XHR, passive listeners, flushSync, View Transitions, storage caching, and DOM CSS batching
          collections_and_loops.rs # reduce spread, JSON clone, immutable sort, and early-exit rules
          loop_hoisting_and_lookups.rs # loop hoisting (Intl/RegExp) and Set/Map lookup rules
        performance.rs    # React re-render, hydration, and motion performance rules root
        performance/
          rerender_and_hooks.rs # memoization, derived hook state, JSX hoisting, and useTransition loading
          hook_initializers.rs # lazy useState initializers, passive scroll listeners, and imperative animation rules
          animation_and_jsx.rs # SVG wrapper animation, layout property transitions, WAAPI/RAF/scroll loops, and motion springs
          hydration_and_routing.rs # hydration mismatch/flicker, SSR browser globals, locale formatting, and React Router loader fetches
        r3f.rs            # Three.js, WebGL, and React Three Fiber 60fps frame-loop module root
        r3f/
          analysis_ctx.rs # FileAnalysisCtx single-pass R3F/Three.js binding and static expression evaluator
          three_lifecycle.rs # Three.js geometry/material/texture constructors and JSX light/camera/material rules
          scene_and_contracts.rs # resource disposal lifecycle, assignments, Canvas/scene contracts, and imperative Three.js rules
          use_frame_and_hooks.rs # React Three Fiber JSX element and loader/helper call rules
          frame_loop_checks.rs # useFrame, setAnimationLoop/requestAnimationFrame, and useThree selector rules
          webgl_and_shaders.rs # WebGL and GLSL ShaderMaterial/RawShaderMaterial stage and uniform rules
          webgpu.rs       # WebGPU renderer, Canvas compatibility, and TSL uniform branch rules
        react_native.rs   # React Native and Expo module root
        react_native/
          lists_and_layout.rs # ScrollView, FlatList/FlashList/LegendList, and host JSX layout rules
          animations_and_styles.rs # Reanimated 4, StyleSheet, Dimensions, Detox, and Pressable/GestureDetector rules
          navigation_and_expo.rs # React Native and Expo module imports, bottom sheets, and process.env/Platform rules
          platform_and_config.rs # package.json, Babel, Metro, Gradle, app.json, lockfile, and .gitignore rules
        react_builtins.rs # React built-in rules root and cross-file ProjectGraph inline prop gating
        react_builtins/
          hooks.rs        # exhaustive-deps, rules-of-hooks, and useState naming symmetry rules
          jsx_props_and_fragments.rs # button type, controlled inputs, target=_blank, fragments, PascalCase, JSX depth, and inline props
          components_and_classes.rs # Fast Refresh only-export-components, nested components, and legacy class component rules
        react_router.rs   # React Router v7/v8 module root
        react_router/
          loaders_and_actions.rs # loaders, actions, sessions, cookies, handleError, meta, and error UI rules
          routes_and_middleware.rs # route tree, JSX <Route>, lazy routes, middleware, and v8 migration rules
          navigation_and_links.rs # navigation, <Link>, <a>, useSearchParams, useBlocker, and startTransition rules
        reduced_motion.rs # cross-file motion library and CSS prefers-reduced-motion rules
        remotion.rs       # Motion, Remotion, TanStack Form/Table/Virtual, Redux, and UI primitive module root
        remotion/
          motion.rs       # Framer Motion / motion/react AnimatePresence, layout, drag, keyframe, and render rules
          remotion_video.rs # Remotion media elements, CSS animation/transition/url, calculateMetadata, and delayRender rules
          tanstack_form_table_virtual.rs # TanStack Form, Table, and Virtual rules
          redux_and_ui_primitives.rs # Redux useSelector and Radix/Base UI/shadcn/styled-components primitive rules
        security.rs       # XSS, eval, SSRF, and trust-boundary security rules root
        security/
          dom_and_client.rs # dangerous HTML sinks, window.open, client secrets, web storage tokens, eval, and CSP/sandbox rules
          client_and_jsx.rs # JSX security attributes, iframe sandbox, and client-side sink inspectors
          injection_and_baas.rs # SQL/NoSQL/command/path injection, redirects, cookies, Supabase RLS, Firebase, and MCP/agent rules
          auth_and_origin.rs # JWT verification, cryptographic primitives, postMessage origin validation, and CORS credential trust rules
          artifacts_and_runtime.rs # build artifact leaks, RPC/native bridges, SSR/MDX execution, and repository secret rules
          workflows.rs    # GitHub Actions workflow injection, untrusted pull_request_target checkout, and secret-in-build-step scanner
          trust_boundaries.rs # Electron/WebView bridges, untrusted Host headers, private-response public caching, LLM/MCP sinks, and unscoped Supabase service-role queries
        server_nextjs.rs  # Server Actions and RSC rules root
        server_nextjs/
          nextjs_rules.rs # Next.js App Router async dynamic APIs, <Image>, <Script>, and route handler rules
          nextjs_metadata_and_jsx.rs # Next.js metadata, font, Link, Suspense, and redirect/notFound rules
        state_and_effects.rs # state/effect loop, render setState, and lazy init rules root
        state_and_effects/
          effects_and_async.rs # useEffect guard, async/timer ref, and error-clear rules
        stores.rs         # Zustand, Jotai, MobX, and Valtio state-store rules
        supply_chain.rs   # pnpm hardening and RSC advisory rules root
        supply_chain/
          socket_scoring.rs # Socket supply-chain artifact cache and scoring rules
        tanstack/
          query.rs        # TanStack Query hooks, QueryClient stability, destructuring, queryFn, and refetch rules
          start.rs        # TanStack Start server functions, loaders, and __root route rules
          router_and_invalidation.rs # TanStack Query mutation invalidation and TanStack Router route/loader/anchor rules
  dotore-py/
    src/
      lib.rs              # PyLanguageAnalyzer (LanguageAnalyzer) facade and dotore-py crate root
      matchers.rs         # shared Python AST matchers, PyScopeTracker, rule gating, and Diagnostic/Autofix builders
      manifest.rs         # pyproject.toml and requirements.txt Capability Gate inference
      ir.rs               # PyFileIr, single-pass Subject, SymbolOutline, ContextualOwnerSpansIr, and suppression extraction
      ir/
        facets.rs         # Python ArchitectureFileFacets single-pass extractor
        hasher.rs         # structural FNV-1a AST hashing for Python helper functions
      graph.rs            # Python package ProjectGraph analysis (circular imports, unused exports, unawaited coroutines)
      graph/
        architecture.rs   # Python SoC, fluent builder, duplicated helper, and PEP 561 package structure evaluators
      safety.rs           # Python runtime and resource safety rules
      safety/
        helpers.rs        # Python exception, resource context-manager, and guard helper predicates
      asyncio.rs          # asyncio concurrency hazard rules
      asyncio/
        helpers.rs        # asyncio blocking-call tables and coroutine/task variable consumption scanners
      perf.rs             # hot-loop regex hoisting autofix and linear membership performance rules
      fastapi_pydantic.rs # FastAPI route/auth and Pydantic default_factory rules
      orm.rs              # SQLAlchemy and Django ORM N+1 loop query rule
      security.rs         # Python SQL injection and unsafe deserialization/shell rules
      zen.rs              # Python Zen, cyclomatic/cognitive complexity, deep nesting, function/class size, dense semicolon, and wildcard import rules
      bandit.rs           # Native Bandit security rules (HTTP timeouts, TLS verification, weak crypto/random, XXE/archive extraction, hardcoded secrets/tmp paths)
  dotore-rs/
    src/
      lib.rs              # RsLanguageAnalyzer (LanguageAnalyzer) and dotore-rs crate root
      matchers.rs         # shared syn AST, type, attribute, and lexical-scope matchers (RsScopeTracker)
      manifest.rs         # Cargo.toml Capability Gate discovery and package role classification
      ir.rs               # single-pass syn AST, Subject, SymbolOutline, and suppression extraction
      ir_facets.rs        # single-pass Rust ArchitectureFileFacets and HelperAstHasher extraction
      graph.rs            # Rust crate ProjectGraph analysis (rs-arch-no-unused-pub-crate-items)
      rules.rs            # Rust rule activation gating and rule pipeline dispatcher
      safety.rs           # single-pass detectors for the 5 core production Rust safety rules
      safety/
        bounds.rs         # slice bounds-guard verification and loop/array length equivalence
        casts.rs          # numeric type inference, lossy as-cast detection, and unsafe comment checks
        guards.rs         # condition, comparison, let-pattern, and post-statement bounds-guard extractors
        tests.rs          # unit tests for Rust safety rules
      tokio_async.rs      # single-pass detectors for Tokio async concurrency hazards
      perf.rs             # single-pass detectors for Rust allocation and hot-loop performance rules
      perf_helpers.rs     # shared AST helper matchers for Rust performance rules
      ui_signals.rs       # single-pass detectors for Leptos/Dioxus reactive signals and boolean params
      source_kernel.rs    # lexical use-alias and 8-hop local let/const binding resolver (SourceKernel)
      source_kernel_bindings.rs # local let/const binding resolver and KernelContext for SourceKernel
      source_kernel_detectors.rs # single-pass SourceKernel detectors for async runtime, HTTP, TLS, shell, secret, CORS, cookie, and JWT rules
      cargo_health.rs     # Cargo.toml, Cargo.lock, and .cargo/config.toml manifest/lockfile health detectors
      cargo_health_refs.rs# crate reference collector and dependency-truth evaluators (unused and test-only dependencies)
      structure.rs        # per-file Rust structural and #[allow] hygiene AST detectors
      structure_duplication.rs # canonical AST normalization and Sørensen-Dice near-duplicate function detector
      structure_package.rs# package-level structural evaluators (orphan module files, unreferenced features, near-duplicate functions)
      clippy_rules.rs     # single-pass detectors for the 7 Clippy-grade AST correctness and reliability rules
src/
  main.rs                 # thin CLI adapter: parses args and returns process exit code
  lib.rs                  # root workspace facade: dispatches through LanguageAnalyzers and re-exports API
  virtual_workspace.rs    # in-memory virtual workspace package and manifest extraction
  workspace_scan.rs       # filesystem workspace scanning, scan cache key computation, and design audit orchestration
  cli.rs                  # Clap CLI subcommand execution runners
  cli/
    args.rs               # Clap CLI argument definitions, subcommand enums, and option resolvers
  progress.rs             # live terminal progress bar and 30fps spinner animation (dotore_core::ui::LiveSpinner)
  tui.rs                  # interactive TUI explorer state machine and terminal event loop
  tui/
    render.rs             # TUI viewport body, header metrics, package picker overlay, and frame rendering
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
assets/
  readme/
    hero-dark.png         # composed dark-theme README hero (SVG layout + surgical robot mascot)
    hero-light.png        # composed light-theme README hero (SVG layout + surgical robot mascot)
    source/
      hero-layout-dark.svg  # editable dark SVG layout source
      hero-layout-light.svg # editable light SVG layout source
      hero-subject.png      # transparent surgical robot mascot cutout
      hero-prompt.txt       # Gemini generation prompt and model record
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
