# 02: Deterministic Remediation Core — Root-Cause Groups, Blast Radius, Fix Capsules, Cross-File Autofix, and Plan Generator

**What to build:** Deliver the complete deterministic remediation pipeline that groups related findings into **Root-Cause Groups**, ranks them statically by **Blast Radius**, expands `dotore fix` to execute both single-file and unambiguous cross-file **Caller Site** rewrites in Rust, emits self-contained **Fix Capsules** with repository **Exemplars**, and provides `dotore plan` to generate deterministic refactoring plans without LLM involvement.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**Status:** resolved

- [x] Related diagnostics that share a single underlying defect (such as multiple **State Slots** reset on the same prop change in a **Subject**, multiple consumers of one unstable context provider, or sibling occurrences of a root-cause-groupable rule) are clustered under a deterministic **Root-Cause Group** identifier.
- [x] Every **Root-Cause Group** is assigned a deterministic **Blast Radius** score and priority tier (`P0`–`P3`) computed from static graph evidence: render frequency (60fps frame loop vs. list `.map()` vs. normal render), cross-file fan-out (**Caller Sites**, child **Subjects**, or context consumers), **Render Cascade** depth, and rule severity/category.
- [x] `dotore fix` applies `Autofix`-tier byte-range edits across both single-file rules and unambiguous cross-file **Caller Site** rewrites (including injecting `key={prop}` at parent **Caller Sites** while removing child reset **Effect Nodes**), supports `--dry-run`, resolves overlapping spans safely, and guarantees that re-analyzing patched sources yields valid syntax and clears the targeted diagnostics.
- [x] Every `Surgical` and `Refactor` **Root-Cause Group** in `dotore check --json` includes a complete **Fix Capsule** bundling the verbatim **Subject** excerpt, verbatim cross-file **Caller Site** excerpts, compiled-in transformation recipe, invariants to preserve, and a repository **Exemplar** discovered from the project graph when a matching valid pattern already exists in the codebase.
- [x] Running `dotore plan [paths...] [--out <dir>]` deterministically writes self-contained `NNN-<slug>.md` execution plans and a prioritized `README.md` index ordered by **Blast Radius** and stamped with the current git commit SHA, requiring zero network access or LLM calls.
