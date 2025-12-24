# 04: Module Graph, Dead Code, Circular Dependencies, and Duplicate JSX Subtrees

**What to build:** Extend the in-memory `ProjectGraph` with full cross-file module linking, entrypoint reachability, cycle detection, and structural JSX subtree hashing to deliver all project-wide dead-code, circular-dependency, and duplicated-JSX diagnostics in the same single-pass scan.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**Status:** resolved

- [x] Module specifiers across static `import`/`export`, `export *`, dynamic `import()`, and `require()` are resolved in `ProjectGraph`, honoring relative paths, `tsconfig.json` `baseUrl` and `paths`, monorepo workspace packages, framework entrypoint conventions (Next.js, Expo, React Router, TanStack Start, Vite), build-script references, and platform-specific file suffixes (`.ios`, `.android`, `.native`, `.web`).
- [x] Reachability analysis from discovered package entrypoints accurately reports `unused-file`, `unused-export`, and `unused-type` without flagging framework route files, platform sibling files, or public library exports.
- [x] Package manifest dependency cross-referencing reports `unused-dependency` and `unused-dev-dependency` while accounting for peer/config/toolchain packages and virtual or build-time plugins.
- [x] Strongly connected component analysis on the module graph reports `circular-dependency` with the deterministic cycle path across participating files.
- [x] Structural normalization and hashing of JSX subtrees across **Subjects** detects repeated UI markup and reports `duplicate-jsx-subtree` with all participating locations grouped into a single **Root-Cause Group**.
