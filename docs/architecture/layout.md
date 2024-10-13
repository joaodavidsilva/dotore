# Layout: Single-Crate Rust CLI and Library

Basis: Cargo Book ("Package Layout") and Rust API Guidelines.

## Folder tree

```
src/
  main.rs                 # thin CLI entrypoint: parses args and calls dotore library
  lib.rs                  # crate root: narrow public surface, wires internal modules
  scanner.rs              # parallel gitignore-aware file discovery
  ir.rs                   # IR module root re-exporting SubjectIr and FileIr
  ir/
    types.rs              # FileIr, SubjectIr, StateSlot, EffectNode, CallerSite
    extract.rs            # oxc AST + semantic pass producing FileIr
    dataflow.rs           # dependency tracking, setter calls, store/fetch sites
    react_ast.rs          # React component and hook AST classification
  graph.rs                # cross-file JSX caller index and Subject cascade graph
  rules.rs                # rules engine dispatcher over SubjectIr / ProjectGraph
  rules/
    types.rs              # RuleId, PrescriptionTier, Diagnostic, AutofixPatch
    derived_state.rs      # derived state, chained state updates, mount initialization
    prop_sync.rs          # full state reset and partial state adjustment on prop change
    parent_flow.rs        # event-handler effects and upward parent callback notifications
    external_sync.rs      # external store subscriptions and effect data fetching
  fixer.rs                # surgical byte-range auto-fixer for Autofix-tier diagnostics
  report.rs               # terminal, JSON, and self-contained HTML cascade reporters
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
| 4 | Only `src/ir.rs` (and `src/graph.rs` for cross-file indexing) walks `oxc` AST/semantic nodes; `src/rules.rs` and `src/fixer.rs` consume typed IR structs. | `review` |
| 5 | Size and complexity triggers are enforced per function (`too-many-lines-threshold = 80`, `cognitive-complexity-threshold = 15`, `excessive-nesting-threshold = 4`, `too-many-arguments-threshold = 6`). | `clippy::too_many_lines`, `clippy::cognitive_complexity`, `clippy::excessive_nesting`, `clippy::too_many_arguments` |
| 6 | Lint suppressions must use `#[expect(lint, reason = "...")]`, never `#[allow(...)]`. | `clippy::allow_attributes`, `clippy::allow_attributes_without_reason` |
