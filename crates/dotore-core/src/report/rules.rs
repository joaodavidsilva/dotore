//! Rule catalog listing (`dotore rules list`) and rule explanation (`dotore rules explain`).

use std::{collections::HashMap, fmt::Write as _};

use serde::{Deserialize, Serialize};

use crate::{
    config::{Capability, DotoreConfig},
    rules::{
        PrescriptionTier, RuleCategory, RuleId, RuleMetadata, RuleSeverity, RuleSeverityOverride,
        rule_registry,
    },
    ui::{AsciiBox, Badge, BoxBorderStyle, ColorMode, DEFAULT_BOX_WIDTH},
};

/// Filter options for `dotore rules list` ([`build_rule_catalog`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesListOptions {
    /// Optional category filter (case-insensitive, e.g. `"Performance"`, `"Bugs"`).
    pub category: Option<String>,
    /// Optional behavioral tag filter (e.g. `"design"`, `"test-noise"`, `"r3f"`).
    pub tag: Option<String>,
    /// Optional framework/capability filter (e.g. `"react"`, `"nextjs"`, `"global"`).
    pub framework: Option<String>,
    /// When `true`, include only rules with an active configuration override (`source != "default"` and `source != "opt-in"`).
    pub configured: bool,
}

/// Machine-readable catalog and explanation entry for a single rule in `dotore rules list` and `dotore rules explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCatalogEntry {
    /// Qualified rule key (`"dotore/no-derived-state"`).
    pub key: String,
    /// Canonical short rule identifier (`"no-derived-state"`).
    pub id: String,
    /// Legacy rule aliases accepted in config and inline suppressions.
    pub aliases: Vec<String>,
    /// Short human-readable headline.
    pub title: String,
    /// Display category (`"Bugs"`, `"Performance"`, `"Accessibility"`, `"Security"`, `"Maintainability"`).
    pub category: String,
    /// Framework or capability gate (`"react"`, `"nextjs"`, `"tanstack-query"`, `"global"`, etc.).
    pub framework: String,
    /// Behavioral tags attached to this rule.
    pub tags: Vec<String>,
    /// Default **Prescription Tier** (`autofix`, `surgical`, `refactor`).
    pub tier: PrescriptionTier,
    /// Default severity in config vocabulary (`"error"` or `"warn"`).
    pub default_severity: String,
    /// Whether the rule is enabled by default in standard scans.
    pub default_enabled: bool,
    /// Effective severity under the active [`DotoreConfig`] (`"error"`, `"warn"`, or `"off"`).
    pub severity: String,
    /// Configuration layer that determined `severity` (`"default"`, `"rules"`, `"categories"`, `"ignore.rules"`, `"ignore.tags"`, `"opt-in"`, `"custom-rules-only"`, `"warnings"`).
    pub source: String,
    /// Runtime problem description and rationale.
    pub rationale: String,
    /// Compiled-in remediation recipe in Markdown.
    pub recipe_markdown: String,
    /// Problematic "Before" code example.
    pub before_example: String,
    /// Idiomatic "After" code example.
    pub after_example: String,
    /// Ready-to-paste `dotore.config.json` configuration snippet.
    pub config_snippet: String,
    /// Official documentation URL.
    pub docs_url: String,
}

/// Builds the filtered [`RuleCatalogEntry`] list for `dotore rules list`.
#[must_use]
pub fn build_rule_catalog(
    config: &DotoreConfig,
    filter: &RulesListOptions,
) -> Vec<RuleCatalogEntry> {
    let cat_filter = filter
        .category
        .as_deref()
        .and_then(RuleCategory::parse)
        .map(RuleCategory::as_str);
    let raw_cat_lower = filter
        .category
        .as_ref()
        .map(|c| c.trim().to_ascii_lowercase());
    let tag_filter = filter.tag.as_ref().map(|t| t.trim().to_ascii_lowercase());
    let fw_filter = filter
        .framework
        .as_ref()
        .map(|f| f.trim().to_ascii_lowercase());

    let mut out = Vec::new();
    for meta in rule_registry() {
        if let Some(expected_cat) = cat_filter {
            if meta.category.as_str() != expected_cat {
                continue;
            }
        } else if let Some(raw_cat) = &raw_cat_lower
            && meta.category.as_str().to_ascii_lowercase() != *raw_cat
        {
            continue;
        }

        if let Some(tag_q) = &tag_filter
            && !meta
                .tags
                .iter()
                .any(|t| t.as_str().eq_ignore_ascii_case(tag_q))
        {
            continue;
        }

        let fw_label = framework_label(meta);
        if let Some(fw_q) = &fw_filter {
            let matches_fw = fw_label.eq_ignore_ascii_case(fw_q)
                || (fw_q == "global" && meta.capability_gate.requires.is_empty())
                || (fw_q == "rxjs"
                    && matches!(
                        meta.id,
                        RuleId::AngularRxjsSubscribeRequiresTeardown
                            | RuleId::AngularNoNestedSubscribe
                    ))
                || meta
                    .capability_gate
                    .requires
                    .iter()
                    .any(|cap| cap.as_str().eq_ignore_ascii_case(fw_q));
            if !matches_fw {
                continue;
            }
        }

        let entry = build_catalog_entry(meta, config);
        if filter.configured && (entry.source == "default" || entry.source == "opt-in") {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Resolves a rule by canonical ID (`"no-derived-state"`), qualified key (`"dotore/no-derived-state"`),
/// or legacy alias (`"effect/no-derived-state"`, `"react/jsx-key"`) and returns its [`RuleCatalogEntry`].
#[must_use]
pub fn explain_rule(rule_query: &str, config: &DotoreConfig) -> Option<RuleCatalogEntry> {
    let rule_id = RuleId::parse(rule_query)?;
    Some(build_catalog_entry(rule_id.metadata(), config))
}

/// Formats the terminal output for `dotore rules list`.
#[must_use]
pub fn format_rule_catalog_text(entries: &[RuleCatalogEntry]) -> String {
    if entries.is_empty() {
        return "No rules match the given filters.\n".to_string();
    }

    let mut by_category: HashMap<&str, Vec<&RuleCatalogEntry>> = HashMap::new();
    for entry in entries {
        by_category
            .entry(entry.category.as_str())
            .or_default()
            .push(entry);
    }

    let mut categories: Vec<&str> = by_category.keys().copied().collect();
    categories.sort_unstable();

    let mode = ColorMode::Plain;
    let mut out = String::new();
    for cat in categories {
        let Some(mut rows) = by_category.remove(cat) else {
            continue;
        };
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        let mut cat_box = AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH)
            .with_title(format!("{cat} ({})", rows.len()));
        for row in rows {
            let tags_suffix = if row.tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", row.tags.join(", "))
            };
            let sev_badge = match row.severity.as_str() {
                "error" => Badge::severity(RuleSeverity::Error).render(mode),
                "warn" => Badge::severity(RuleSeverity::Warning).render(mode),
                _ => Badge::custom("○ OFF  ", "\x1b[2m").render(mode),
            };
            let tier_badge = Badge::tier(row.tier).render(mode);
            cat_box.add_open_row(format!(
                "  {sev_badge}  {:<6} {} ({}) [tier: {tier_badge}]{tags_suffix}",
                row.severity, row.key, row.source
            ));
        }
        out.push_str(&cat_box.render(mode));
        let _ = writeln!(out);
    }
    let plural = if entries.len() == 1 { "" } else { "s" };
    let _ = writeln!(out, "{} rule{plural} shown.", entries.len());
    out
}

/// Formats the terminal output for `dotore rules explain <rule>`.
#[must_use]
pub fn format_rule_explanation_text(entry: &RuleCatalogEntry) -> String {
    let mode = ColorMode::Plain;
    let tier_badge = Badge::tier(entry.tier).render(mode);
    let rule_badge = RuleId::parse(&entry.id).map_or_else(
        || format!("[{}]", entry.id),
        |id| Badge::rule(id).render(mode),
    );
    let tags_display = if entry.tags.is_empty() {
        "none".to_string()
    } else {
        entry.tags.join(", ")
    };
    let enabled_display = if entry.default_enabled {
        "yes"
    } else {
        "no (opt-in)"
    };

    let mut header_box = AsciiBox::new(BoxBorderStyle::Rounded, DEFAULT_BOX_WIDTH)
        .with_title(format!("{} — {}", entry.key, entry.title));
    header_box.add_open_row(format!("  {:<18}{} {rule_badge}", "Category", entry.category));
    header_box.add_open_row(format!("  {:<18}{}", "Default severity", entry.default_severity));
    header_box.add_open_row(format!(
        "  {:<18}{} ({})",
        "Current severity", entry.severity, entry.source
    ));
    header_box.add_open_row(format!(
        "  {:<18}{} {tier_badge}",
        "Prescription Tier",
        entry.tier.as_str()
    ));
    header_box.add_open_row(format!("  {:<18}{}", "Framework", entry.framework));
    header_box.add_open_row(format!("  {:<18}{tags_display}", "Tags"));
    if !entry.aliases.is_empty() {
        header_box.add_open_row(format!("  {:<18}{}", "Aliases", entry.aliases.join(", ")));
    }
    header_box.add_open_row(format!("  {:<18}{enabled_display}", "Default enabled"));
    header_box.add_titled_divider("Why it matters");
    for line in entry.rationale.lines() {
        header_box.add_open_row(format!("  {line}"));
    }

    let mut out = header_box.render(mode);

    let _ = writeln!(out, "\nBefore (anti-pattern)");
    for line in entry.before_example.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nAfter (recommended)");
    for line in entry.after_example.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nConfiguration snippet (dotore.config.json)");
    for line in entry.config_snippet.lines() {
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(out, "\nConfigure via CLI");
    let _ = writeln!(out, "  dotore rules disable {}", entry.key);
    let _ = writeln!(out, "  dotore rules enable {} --severity error", entry.key);
    let _ = writeln!(out, "  dotore rules set {} warn", entry.key);

    let _ = writeln!(out, "\nLearn more");
    let _ = writeln!(out, "  {}", entry.docs_url);
    out
}

fn build_catalog_entry(meta: &RuleMetadata, config: &DotoreConfig) -> RuleCatalogEntry {
    let default_sev_str = match meta.default_severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warn",
    };
    let (eff_sev, source) = resolve_catalog_severity_and_source(meta, config);
    let (before_example, after_example) = rule_before_after_examples(meta);
    let rationale = format!("{}: {}", meta.title, meta.recipe_markdown);
    let config_snippet = format!(
        "{{\n  \"rules\": {{\n    \"{}\": \"{}\"\n  }}\n}}",
        meta.qualified_key, default_sev_str
    );

    RuleCatalogEntry {
        key: meta.qualified_key.to_string(),
        id: meta.canonical_id.to_string(),
        aliases: meta
            .legacy_aliases
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        title: meta.title.to_string(),
        category: meta.category.as_str().to_string(),
        framework: framework_label(meta).to_string(),
        tags: meta.tags.iter().map(|t| t.as_str().to_string()).collect(),
        tier: meta.default_tier,
        default_severity: default_sev_str.to_string(),
        default_enabled: meta.default_enabled,
        severity: eff_sev.to_string(),
        source: source.to_string(),
        rationale,
        recipe_markdown: meta.recipe_markdown.to_string(),
        before_example,
        after_example,
        config_snippet,
        docs_url: meta.docs_url.to_string(),
    }
}

fn framework_label(meta: &RuleMetadata) -> &'static str {
    if meta.capability_gate.requires.is_empty() {
        return "global";
    }
    for &cap in meta.capability_gate.requires {
        if !matches!(
            cap,
            Capability::React | Capability::Python | Capability::Rust
        ) {
            return cap.as_str();
        }
    }
    meta.capability_gate.requires[0].as_str()
}

fn resolve_catalog_severity_and_source(
    meta: &RuleMetadata,
    config: &DotoreConfig,
) -> (&'static str, &'static str) {
    if meta.tags.iter().any(|&t| config.is_tag_ignored(t)) {
        return ("off", "ignore.tags");
    }
    if config
        .ignore
        .rules
        .iter()
        .any(|r| RuleId::parse(r) == Some(meta.id))
    {
        return ("off", "ignore.rules");
    }
    if let Some(ov) = config.explicit_rule_override(meta.id) {
        let sev = match ov {
            RuleSeverityOverride::Error => "error",
            RuleSeverityOverride::Warn => "warn",
            RuleSeverityOverride::Off => "off",
        };
        return (sev, "rules");
    }
    if config.custom_rules_only && meta.originally_external {
        return ("off", "custom-rules-only");
    }
    if !meta.default_enabled {
        return ("off", "opt-in");
    }
    if let Some(cat_ov) = config.category_override(meta.category) {
        let sev = match cat_ov {
            RuleSeverityOverride::Error => "error",
            RuleSeverityOverride::Warn => "warn",
            RuleSeverityOverride::Off => "off",
        };
        return (sev, "categories");
    }
    let default_sev = match meta.default_severity {
        RuleSeverity::Error => "error",
        RuleSeverity::Warning => "warn",
    };
    if !config.warnings && meta.default_severity == RuleSeverity::Warning {
        return ("off", "warnings");
    }
    (default_sev, "default")
}

fn rule_before_after_examples(meta: &RuleMetadata) -> (String, String) {
    match meta.canonical_id {
        "no-derived-state" => (
            "const [fullName, setFullName] = useState('');\nuseEffect(() => {\n  setFullName(`${firstName} ${lastName}`);\n}, [firstName, lastName]);".to_string(),
            "const fullName = `${firstName} ${lastName}`;".to_string(),
        ),
        "no-chain-state-updates" => (
            "useEffect(() => {\n  setStep2(step1 + 1);\n}, [step1]);".to_string(),
            "const step2 = step1 + 1;".to_string(),
        ),
        "no-event-handler" => (
            "useEffect(() => {\n  if (submitted) submitOrder(cart);\n}, [submitted, cart]);".to_string(),
            "function handleCheckout() {\n  submitOrder(cart);\n}".to_string(),
        ),
        "no-reset-all-state-on-prop-change" => (
            "function Profile({ userId }: { userId: string }) {\n  const [draft, setDraft] = useState('');\n  useEffect(() => { setDraft(''); }, [userId]);\n}".to_string(),
            "<Profile key={userId} userId={userId} />".to_string(),
        ),
        "no-adjust-state-on-prop-change" => (
            "useEffect(() => {\n  setSelected(null);\n}, [items]);".to_string(),
            "const selected = items.find(i => i.id === selectedId) ?? null;".to_string(),
        ),
        "no-initialize-state" => (
            "const [count, setCount] = useState(0);\nuseEffect(() => {\n  setCount(initialCount);\n}, []);".to_string(),
            "const [count, setCount] = useState(initialCount);".to_string(),
        ),
        "no-pass-live-state-to-parent" | "no-pass-data-to-parent" => (
            "useEffect(() => {\n  onChange(value);\n}, [value, onChange]);".to_string(),
            "function updateValue(next: string) {\n  setValue(next);\n  onChange(next);\n}".to_string(),
        ),
        "no-external-store-subscription" => (
            "useEffect(() => {\n  const onResize = () => setWidth(window.innerWidth);\n  window.addEventListener('resize', onResize);\n  return () => window.removeEventListener('resize', onResize);\n}, []);".to_string(),
            "const width = useSyncExternalStore(subscribeResize, () => window.innerWidth, () => 0);".to_string(),
        ),
        "no-fetch-in-effect" => (
            "useEffect(() => {\n  fetch(url).then(r => r.json()).then(setData);\n}, [url]);".to_string(),
            "useEffect(() => {\n  const ctrl = new AbortController();\n  fetch(url, { signal: ctrl.signal }).then(r => r.json()).then(setData);\n  return () => ctrl.abort();\n}, [url]);".to_string(),
        ),
        _ => (
            format!("// Anti-pattern triggering `{}`:\n// {}", meta.qualified_key, meta.title),
            format!("// Recommended fix ({}):\n// {}", meta.default_tier.as_str(), meta.recipe_markdown),
        ),
    }
}
