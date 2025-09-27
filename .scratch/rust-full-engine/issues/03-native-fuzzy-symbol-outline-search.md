# 03: Native Fuzzy Symbol Outline Search (`dotore search`)

**What to build:** Provide fast, zero-config fuzzy symbol search (`dotore search`) written from scratch in Rust over **Symbol Outlines** extracted by the OXC pass so developers and AI agents can discover existing functions, **Subjects**, classes, interfaces, types, enums, and constants before writing new code.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**Status:** ready-for-agent

- [ ] During OXC extraction, every declared `class`, `constant`, `enum`, `enum-member`, `export`, `function`, `import`, `interface`, `method`, `property`, `type`, and `variable` is indexed as a **Symbol Outline** with its signature, line range, adjacent leading comment, and enclosing class or object context.
- [ ] Running `dotore search <query> [paths...]` fuzzy-matches and ranks **Symbol Outlines** across the target files or directories using subsequence, prefix, camelCase, and kebab-case boundary scoring.
- [ ] `--kind <kinds>` filters results to a comma-separated subset of symbol kinds (defaulting to `class,enum,function,interface,method,property,type`), and `--limit <N>` caps the number of returned matches (defaulting to `50`).
- [ ] `--format text` groups matches by file and renders compact code outlines with 1-based line numbers, truncating adjacent comments longer than 10 lines with a summary line, showing enclosing class/object headers for matched methods and properties, and summarizing interfaces with more than 15 properties.
- [ ] `--format json` emits structured machine-readable **Symbol Outline** records, and ANSI syntax highlighting is enabled only on color-capable interactive terminals (`--no-color` and `NO_COLOR` are respected).
