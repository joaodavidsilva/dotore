# 13: Native Chrome CDP Runtime Profiler (`dotore scan`)

**What to build:** Implement `dotore scan [url]` in pure Rust speaking the Chrome DevTools Protocol (CDP) directly over WebSocket to profile live React interactions, highlight component renders, aggregate Long Animation Frames, script hotspots, and React component render counts, and save the compressed `.json.gz` trace locally without Node.js or Playwright dependencies.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**Status:** ready-for-agent

- [ ] `dotore scan [url]` launches an isolated system Chrome/Chromium profile with remote debugging enabled (or connects to an existing debug-enabled browser via `--cdp <url>`, rejecting `--cdp` profiles that have other non-blank tabs open so browser-wide tracing stays uncontaminated).
- [ ] When `url` is omitted in an interactive terminal, `dotore scan` detects running localhost development/production servers and prompts the user to select or enter a target URL.
- [ ] The embedded runtime probe and visual purple component-render overlay are injected via CDP `Page.addScriptToEvaluateOnNewDocument`, and browser tracing (`Tracing.start` / `Tracing.end`) records until the user presses Enter or the 5-minute timeout elapses.
- [ ] Trace and probe snapshots across documents are merged in Rust to compute worst interaction timing (INP/Event Timing), total blocking duration, LCP, CLS, Long Animation Frame script hotspots (including forced style/layout thrash ratios), and React component render counts and self/max durations.
- [ ] The raw trace is streamed to a local `.json.gz` file (honoring `--trace-out <path>` and restrictive file permissions) and the structured summary is rendered in `text`, `json`, or `jsonl` (`--format`).
