# Single-pass OXC analysis, global ProjectGraph, and deterministic Fix Capsules

We parse each source file once in parallel via `oxc_parser` and `oxc_semantic`, extracting a multi-facet `FileIr` (`SubjectIr`, JSX elements, module imports/exports, symbol outlines, mutations, async flows, and security sinks) and linking all files into an in-memory `ProjectGraph` (cross-file **Caller Sites**, **Render Cascades**, module reachability/cycles, JSX subtree hashes, `Context` fan-out, and 60fps frame-loop call graphs). Rules query `FileIr`, `ProjectGraph`, and `oxc_semantic` directly as needed to preserve 100% edge-case precision without redundant file parsing.

To minimize probabilistic LLM work, every finding is grouped into a **Root-Cause Group**, ranked statically by **Blast Radius**, and assigned a **Prescription Tier**:
- `Autofix`: unambiguous single-file or cross-file **Caller Site** byte-span rewrites executed natively in Rust by `dotore fix`.
- `Surgical` and `Refactor`: emitted as self-contained **Fix Capsules** (and rendered into deterministic execution plans by `dotore plan`) containing exact affected source slices, cross-file **Caller Sites**, embedded transformation recipes, and a repository **Exemplar** so agents never need network fetches or exploratory file reads.
