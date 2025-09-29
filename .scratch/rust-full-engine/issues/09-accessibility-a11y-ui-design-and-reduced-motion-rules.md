# 09: Accessibility (`a11y`) and UI Design (`design` / `react-ui`) Rule Families + Reduced Motion

**What to build:** Port all 102 accessibility (`a11y`) rules, the project-wide `require-reduced-motion` check across CSS and motion libraries, and all 112 UI design (`design` and `react-ui`) rules into the single-pass Rust engine.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline

**Status:** ready-for-agent

- [ ] All 102 `a11y` rules (`alt-text`, `aria-role`, `no-redundant-roles`, `control-has-associated-label`, `click-events-have-key-events`, `mouse-events-have-key-events`, `no-static-element-interactions`, `no-noninteractive-element-to-interactive-role`, `no-autofocus`, `html-has-lang`, `anchor-is-valid`, `anchor-has-content`, `anchor-ambiguous-text`, `anchor-target-exists`, `no-distracting-elements`, `no-outline-none`, `no-disabled-zoom`, and remaining ARIA/WCAG checks) are implemented in Rust.
- [ ] Project-wide `require-reduced-motion` analysis inspects motion library imports/usages (`framer-motion`, `motion`, `useReducedMotion`, `MotionConfig`) and CSS/SCSS `@media (prefers-reduced-motion: reduce)` rules in a single pass without invoking an external TypeScript compiler.
- [ ] All 112 `design` and `react-ui` rules (`no-undersized-icon-button`, `no-img-without-dimensions`, `no-redundant-padding-axes`, `no-redundant-size-axes`, `no-space-on-flex-children`, `no-vague-button-label`, `no-emoji-heading-decoration`, `no-decorative-pulse`, `no-decorative-radial-spotlight`, `no-side-tab-border`, `no-smooth-scroll-without-reduced-motion`, `no-repeated-container-text`, `no-flat-page-type-scale`, `no-three-period-ellipsis`, `no-em-dash-in-jsx-text`, and remaining UI composition/typography rules) are implemented in Rust and tagged with `design`.
- [ ] Unambiguous single-element fixes (such as redundant Tailwind/CSS axis classes or typography punctuation replacements) emit deterministic `Autofix` patches.
- [ ] Integration tests validate all `a11y`, `require-reduced-motion`, and `design` regression cases.
