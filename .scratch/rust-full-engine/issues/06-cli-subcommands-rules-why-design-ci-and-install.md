# 06: Rule Catalog and Setup CLI Subcommands (`rules`, `why`, `design`, `ci`, `install`)

**What to build:** Provide the interactive and non-interactive CLI subcommands for inspecting and configuring rules (`dotore rules`), explaining findings at a specific source location (`dotore why`), running focused UI design audits (`dotore design`), and setting up CI workflows and agent skills (`dotore ci`, `dotore install`).

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline, 02: Deterministic Remediation Core — Root-Cause Groups, Blast Radius, Fix Capsules, Cross-File Autofix, and Plan Generator

**Status:** ready-for-agent

- [ ] `dotore rules list` lists all available rules with their effective severities, supporting `--category`, `--tag`, `--framework`, `--configured`, and `--json` filters.
- [ ] `dotore rules explain <rule>` renders the compiled-in rationale, runtime problem description, before/after examples, configuration snippet, and **Prescription Tier** for any rule key or alias (in text or `--json`).
- [ ] `dotore rules enable`, `disable`, `set <rule> <off|warn|error>`, `category <cat> <off|warn|error>`, `ignore-tag <tag>`, and `unignore-tag <tag>` update `dotore.config.*` or `package.json#dotore` in place while preserving unrelated fields and formatting (or creating `dotore.config.json` when no config exists).
- [ ] `dotore why <file:line>` explains why a diagnostic fired (or why a rule or inline suppression did or did not apply) at that exact location and outputs its complete **Fix Capsule**.
- [ ] `dotore design [paths...]` runs a focused UI audit enabling all `design`-tagged rules while skipping unrelated project-analysis, supply-chain, and health-score passes.
- [ ] `dotore ci install | upgrade | config` and `dotore install [--yes] [--dry-run] [--agent-hooks]` generate and update CI pull-request workflows and install the unified `/dotore` agent skill and git hooks.
