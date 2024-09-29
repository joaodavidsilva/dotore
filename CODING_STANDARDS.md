# Coding standards

Read at review. Mechanical rules live in the checks (`cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`), not here. Folder layout and import rules: `docs/architecture/layout.md`. For CSS, HTML and JS platform choices, call the Skill tool with `platform-first`; reviewers and implementers both use it.

## Architecture and IR

### Build the component IR once; rules only query the IR

**Rule.** Parse and walk the `oxc` AST and semantic table only inside `src/ir.rs` (and cross-file indexing in `src/graph.rs`). Diagnostic rules in `src/rules.rs` and auto-fixes in `src/fixer.rs` operate strictly on `SubjectIr` and `ProjectGraph` data structures, never walking raw AST nodes.
**Why.** Per-rule AST visitors duplicate traversal logic and grow into brittle 100 KB heuristics (the exact failure mode of ESLint/oxlint JS plugins).
**Applies when.** A diff adds or modifies a diagnostic rule, cascade detector, or auto-fix.

### Parse into domain types at the boundary

**Rule.** Convert raw AST strings, CLI arguments, and file paths into validated enums and structs (`RuleId`, `PrescriptionTier`, `DepsSpec`, `SubjectKind`) at the parser/CLI boundary rather than passing raw strings or booleans inward.
**Why.** Typed domain values let the compiler enforce exhaustive handling when a new rule or tier is added.
**Applies when.** A function outside `src/main.rs` or `src/ir.rs` accepts raw string identifiers for rules, tiers, or hook kinds.

## Modules and Ownership

### Keep module surfaces small and `pub(crate)` by default

**Rule.** Expose only the top-level runner and report types from `src/lib.rs`; mark cross-module internals `pub(crate)` and keep helpers private to their module.
**Why.** A narrow public interface maximizes module depth and lets internal representations change without cascading edits.
**Applies when.** A diff adds `pub` items outside `src/lib.rs` that callers of the crate do not need.

### Borrow slices at function boundaries

**Rule.** Accept `&str`, `&[T]`, and `&Path` in parameters when the callee does not need ownership; allocate or `.clone()` only when storing owned data in an IR struct or crossing thread boundaries.
**Why.** Avoidable allocations in AST and graph passes degrade throughput across thousands of files.
**Applies when.** A function takes `String`, `Vec<T>`, or `PathBuf` by value and only reads from it.

### Extract a helper at the third call site

**Rule.** Duplicate small logic until a third call site exists or a single domain rule needs one authoritative home. When a shared helper gains a boolean flag to switch behavior between callers, inline it back and split.
**Why.** Premature helpers with mode flags couple unrelated rules together.
**Applies when.** A diff extracts a one-off helper or adds a boolean mode parameter to an existing one.

### Document `unsafe` invariants with `// SAFETY:`

**Rule.** Every `unsafe` block must be preceded by a `// SAFETY:` comment stating the exact invariant that makes the operation sound.
**Why.** `unsafe_op_in_unsafe_fn` is denied mechanically, but only a human-readable invariant explains why the precondition holds.
**Applies when.** Any `unsafe` block or `unsafe fn` appears in a diff.

## Deviations

- None recorded yet.
