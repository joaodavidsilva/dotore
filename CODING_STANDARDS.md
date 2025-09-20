# Coding standards

Read at review. Mechanical rules live in the checks (`cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`), not here. Folder layout and import rules: `docs/architecture/layout.md`. For CSS, HTML and JS platform choices, call the Skill tool with `platform-first`; reviewers and implementers both use it.

## Architecture and Precision

### Parse once per file; combine shared IR with direct semantic precision

**Rule.** Parse each source file once via `oxc_parser` and `oxc_semantic` inside `src/ir/` and link cross-file relationships in `src/graph.rs` (`ProjectGraph`). Rules in `src/rules/` query `FileIr` and `ProjectGraph` for shared facts (`SubjectIr`, **Caller Sites**, **Render Cascades**, module reachability, **Capability Gates**) and may inspect `oxc_semantic` AST/scope nodes directly whenever fine-grained syntax or control-flow checks are required to preserve 100% edge-case accuracy.
**Why.** A single parse eliminates redundant file I/O and AST construction, while allowing direct semantic inspection prevents lossy abstractions and preserves every adversarial regression case.
**Applies when.** A diff adds or modifies a diagnostic rule, graph pass, or auto-fix.

### Parse into domain types at the boundary

**Rule.** Convert CLI arguments, configuration (`dotore.config.*` / `package.json#dotore`), and rule identifiers into typed Rust enums and structs (`RuleId`, `PrescriptionTier`, `CapabilityGate`, `SubjectKind`) at the boundary rather than passing raw strings inward.
**Why.** Typed domain values let the compiler enforce exhaustive handling across rules, fixers, and reporters.
**Applies when.** A function outside boundary parsers accepts raw string identifiers for rules, tiers, or scopes.

### Favor readable, idiomatic Rust over bureaucratic splitting

**Rule.** Write straightforward, self-contained functions that a junior developer can follow top-to-bottom and a senior engineer can audit for zero-copy performance. Do not fragment cohesive rule or graph logic into tiny helpers just to hit an arbitrary line count.
**Why.** Premature splitting scatters control flow and obscures invariants.
**Applies when.** Reviewing or refactoring any Rust module.
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
