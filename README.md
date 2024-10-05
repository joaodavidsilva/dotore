# dotore

Pure-Rust React doctor starting with Effect and State dataflow diagnostics, deterministic surgical auto-fixes, and visual **Render Cascade** reports.

## Commands

```bash
# Scan current workspace (or specific files/folders)
dotore check [paths...]

# Emit structured JSON with Subject IR, Render Cascades, and cross-file JSX Caller Sites
dotore check --json [paths...]

# Apply deterministic Autofix rewrites in Rust (use --dry-run to preview)
dotore fix [paths...]

# Generate and open a self-contained visual HTML report
dotore report [paths...]
```

## Rules

| Rule ID | Default Tier | Description |
|---|---|---|
| `no-derived-state` | `autofix` / `surgical` | Updating state from props or state inside `useEffect` instead of computing during render. |
| `no-chain-state-updates` | `refactor` | Chaining state updates across one or multiple `useEffect`s (**Render Cascade**). |
| `no-event-handler` | `surgical` / `refactor` | Using state or props plus `useEffect` (`if (flag)`) as an event handler. |
| `no-adjust-state-on-prop-change` | `refactor` | Adjusting partial state in `useEffect` when a prop changes. |
| `no-reset-all-state-on-prop-change` | `refactor` | Resetting all state slots when a prop changes instead of passing `key={prop}` at parent **Caller Sites**. |
| `no-pass-live-state-to-parent` | `refactor` | Calling a parent callback prop with live local state inside `useEffect`. |
| `no-pass-data-to-parent` | `refactor` | Calling a parent callback prop with external hook/query data inside `useEffect`. |
| `no-external-store-subscription` | `surgical` | Subscribing to an external store in `useEffect` instead of `useSyncExternalStore`. |
| `no-initialize-state` | `autofix` / `surgical` | Initializing state synchronously in a mount-only `useEffect(..., [])`. |
| `no-fetch-in-effect` | `surgical` / `refactor` | Fetching data inside `useEffect` (flags race conditions when cancellation cleanup is missing). |
