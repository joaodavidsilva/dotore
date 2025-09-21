# Layout: Single-Crate Rust CLI and Library

Basis: Cargo Book ("Package Layout") and Rust API Guidelines.

## Folder tree

```
src/
  main.rs                 # thin CLI entrypoint: parses args and dispatches subcommands
  lib.rs                  # crate root: narrow public surface, wires internal modules
  scanner.rs              # parallel gitignore-aware file discovery
  config.rs               # dotore.config.* / package.json loader and Capability Gate
  ir.rs                   # IR module root re-exporting FileIr and SubjectIr
  ir/
    types.rs              # FileIr, SubjectIr, StateSlot, EffectNode, CallerSite, SymbolOutline
    extract.rs            # single-pass oxc AST + semantic extraction
    dataflow.rs           # dependency tracking, mutations, async flows, store/fetch sites
    react_ast.rs          # React Subject, hook, and JSX classification
  graph.rs                # ProjectGraph: Caller Sites, Render Cascades, module graph, JSX hashes
  rules.rs                # rules engine dispatcher gated by Capability Gate
  rules/
    types.rs              # RuleId, PrescriptionTier, Diagnostic, AutofixPatch, FixCapsule
    derived_state.rs      # derived state, chained state updates, mount initialization
    prop_sync.rs          # full state reset and partial state adjustment on prop change
    parent_flow.rs        # event-handler effects and upward parent callback notifications
    external_sync.rs      # external store subscriptions and effect data fetching
  fixer.rs                # surgical single- and cross-file byte-range auto-fixer (dotore fix)
  planner.rs              # Root-Cause Grouping, Blast Radius, Exemplar lookup, Fix Capsules (dotore plan)
  search.rs               # native fuzzy AST Symbol Outline search (dotore search)
  diff.rs                 # git diff, Contextual Owner filtering, and baseline multiset comparison
  score.rs                # deterministic local 0-100 health score and P0-P3 tier calculation
  runtime_scan.rs         # native CDP WebSocket runtime profiler (dotore scan)
  report.rs               # terminal, JSON, why/explain, and self-contained HTML reporters
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
