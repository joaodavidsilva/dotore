<p align="center">
  <img src="./assets/readme/hero-dark.png#gh-dark-mode-only" width="100%" alt="dotore — Pure-Rust polyglot static analyzer, deterministic auto-fixer, and remediation engine for JS/TS, React, Angular, Python, and Rust">
  <img src="./assets/readme/hero-light.png#gh-light-mode-only" width="100%" alt="dotore — Pure-Rust polyglot static analyzer, deterministic auto-fixer, and remediation engine for JS/TS, React, Angular, Python, and Rust">
</p>

# dotore

Pure-Rust polyglot static analyzer, deterministic auto-fixer, and remediation engine for **JavaScript/TypeScript, React, Angular, Python, and Rust**.

`dotore` parses each file once, builds a cross-file project graph, gates its **1,076 rules** automatically from your project manifests (`package.json`, `angular.json`, `pyproject.toml`, `Cargo.toml`), and groups findings by root cause with a `0–100` Health Score.

**Website:** [joaodavidsilva.github.io/dotore](https://joaodavidsilva.github.io/dotore/)

## Quickstart

```bash
# Build and install from source
cargo install --path .

# Scan the current workspace (launches interactive TUI in a terminal)
dotore

# Apply safe, syntax-verified Autofix patches (add --dry-run to preview)
dotore fix

# Generate a root-cause remediation plan with Fix Capsules
dotore plan
```

## Core Commands

| Command | Purpose |
|---|---|
| `dotore check [paths...]` | Run static analysis across the workspace (`--json`, `--score`, `--no-pager`). |
| `dotore fix [paths...]` | Apply deterministic single- and cross-file `autofix` patches (`--dry-run`). |
| `dotore plan [paths...]` | Group findings into **Root-Cause Groups** and **Fix Capsules** ranked by **Blast Radius** (`P0`–`P3`). |
| `dotore score [paths...]` | Print the deterministic `0–100` workspace Health Score. |
| `dotore report [paths...]` | Generate a self-contained visual HTML cascade report. |
| `dotore search <query>` | Fuzzy search across extracted AST **Symbol Outlines** (`--kind`, `--json`). |
| `dotore why <file:line>` | Explain why a rule fired, was suppressed, or was skipped by a **Capability Gate**. |
| `dotore rules <subcommand>` | List, explain, enable, disable, or configure rules (`list`, `explain`, `enable`, `disable`, `set`). |
| `dotore design [paths...]` | Run the opt-in UI design, typography, contrast, and layout polish audit. |
| `dotore scan [url]` | Capture a live Chrome CDP runtime trace (React commits, LoAF, interaction hotspots). |
| `dotore ci <subcommand>` | Scaffold CI workflows (`install`, `config`, `upgrade`) or render PR comments (`comment`). |
| `dotore install` | Install agent skills and git pre-commit hooks for `dotore`. |

## Diff-Aware Workflows & Agent Handoff

```bash
# Scan only changed files, contextual owners (functions/components), or changed lines
dotore check --scope changed --base origin/main
dotore check --scope contextual --staged

# Compare against a saved baseline report (fails only on newly introduced findings)
dotore check --baseline baseline.json

# Hand off findings and Fix Capsules directly to a coding agent
dotore check --handoff          # auto-detects claude, codex, cursor, amp, opencode, clipboard, or print
```

## Ecosystems & Rule Catalog (1,076 Rules)

Rules activate automatically via **Capability Gates** inferred from your manifests—React rules never run on Angular or Rust packages, and library crates skip application-only checks.

| Domain | Coverage |
|---|---|
| **React & Next.js** | Derived state, **Render Cascades**, effect teardown, hooks purity, React Compiler, RSC, Server Actions, App Router. |
| **UI, A11y & Design** | WCAG accessibility, ARIA roles/landmarks, keyboard focus, `prefers-reduced-motion`, Tailwind & UI design polish. |
| **Web Ecosystem** | TanStack Query/Start/Router/Form/Table/Virtual, React Router, Zustand, Jotai, MobX, Valtio, Redux, Preact, Ink, Zod v4. |
| **React Native & 3D** | React Native, Expo, Reanimated, Three.js, React Three Fiber (`useFrame` 60fps loop), WebGL shaders, WebGPU/TSL. |
| **Angular** | Signals, lifecycle contracts, RxJS subscription teardown, `OnPush`, HTML template a11y, NgRx, Angular Material. |
| **Python** | Runtime/resource safety, `asyncio` hazards, FastAPI, Pydantic, SQLAlchemy/Django N+1, Bandit security, PEP 561, Zen complexity. |
| **Rust** | Production safety (`unwrap`/`panic`, slice bounds, lossy casts, `unsafe`), Tokio async, Axum, SQLx, `Cargo.toml`/`Cargo.lock` health, Clippy-grade AST checks. |
| **Security & Architecture** | XSS/SSRF/injection, trust boundaries, GitHub Actions workflows, supply-chain scoring, dead code, circular deps, Separation of Concerns (SoC). |

## Remediation Tiers

Every diagnostic carries one of three **Prescription Tiers**:

- **`autofix`** — Safe, deterministic AST byte-range rewrite applied by `dotore fix` and verified by re-parsing.
- **`surgical`** — Localized single-function/component edit guided by a **Fix Capsule**.
- **`refactor`** — Cross-component or architectural change with **Caller Sites** and **Blast Radius** context.

## Configuration

`dotore` works with zero configuration out of the box and reads optional overrides from `dotore.config.{json,ts,js,mjs}`, `package.json#dotore`, or `pyproject.toml` (`[tool.dotore]`):

```json
{
  "rules": {
    "no-derived-state": "error",
    "rs-no-unwrap-in-production": "warn"
  },
  "ignore": {
    "files": ["generated/**"],
    "tags": ["design"]
  }
}
```
