# 05: Git Diff Scopes, Contextual Owner Filtering, Baseline Multiset Comparison, and Local Health Score

**What to build:** Deliver git-aware scan scopes (`full`, `changed`, `contextual`, `lines`, `--staged`), rename-resilient `--baseline` multiset comparison, local `0..=100` Health Score computation, and CI exit-code controls (`--blocking`, `--warning-exit-code`).

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline, 02: Deterministic Remediation Core — Root-Cause Groups, Blast Radius, Fix Capsules, Cross-File Autofix, and Plan Generator

**Status:** resolved

- [x] `--scope changed` (with optional `--base <ref>`) and `--staged` restrict reported diagnostics to files modified against the target git revision or index while still resolving cross-file `ProjectGraph` context against the full workspace.
- [x] `--scope lines` restricts reported diagnostics to findings whose primary span intersects modified line ranges in the git diff.
- [x] `--scope contextual` surfaces any diagnostic whose **Contextual Owner** (line, enclosing JSX element, enclosing **Subject**, file, or explicit related AST nodes such as a hook callback and its dependency array) intersects a modified line range.
- [x] `--baseline <report.json>` compares the current scan against a saved JSON report as a multiset of normalized rule + message + AST-token fingerprints independent of file path and line number, reporting only net-new occurrences across file renames, formatting changes, or component extractions, and degrading gracefully to diff mode when base blobs are unavailable.
- [x] Every scan computes a deterministic local `0..=100` Health Score and label from the active **Root-Cause Groups**, their **Blast Radius** weights, and the total analyzed **Subjects** and files; `--score` outputs only the numeric score.
- [x] Exit codes honor `--blocking error|warning|none` and `--warning-exit-code <2..=255>` (returning the custom exit code when warnings are present and no blocking errors occurred).
- [x] `--json` and `--json-out <path>` emit the versioned machine-readable report including deterministic diagnostic identities, per-project coverage metadata, **Root-Cause Groups**, **Blast Radius**, **Fix Capsules**, and optional baseline delta summary.
