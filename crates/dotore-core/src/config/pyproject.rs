//! `pyproject.toml` `[tool.dotore]` configuration and
//! Python project profile (`web`, `cli`, `library`, `script`) inference.

use crate::rules::{RuleId, RuleSeverityOverride};

use super::loader::{DotoreConfig, IgnoreOverride};

const WEB_PACKAGES: &[&str] = &[
    "flask",
    "django",
    "fastapi",
    "starlette",
    "tornado",
    "aiohttp",
    "sanic",
    "bottle",
    "litestar",
    "quart",
    "djangorestframework",
    "django-ninja",
];

const CLI_PACKAGES: &[&str] = &["click", "typer", "fire", "cement", "cliff"];

const CLI_SUPPRESSED_RULES: &[&str] = &[
    "bandit/B404",
    "bandit/B110",
    "bandit/B112",
    "bandit/B603",
    "bandit/B607",
];

// Library-only structure rules (`py-structure-missing-py-typed`, `py-structure-low-type-hint-coverage`)
// are suppressed in `dotore-py` when `__python_profile == "script"` (or explicit `"script"` profile in `[tool.dotore]`).
const SCRIPT_SUPPRESSED_RULES: &[&str] = &[
    "py-structure-missing-py-typed",
    "py-structure-low-type-hint-coverage",
];

impl DotoreConfig {
    /// Extracts a [`DotoreConfig`] from `[tool.dotore]` in a
    /// `pyproject.toml` string (including Python `cli`/`script` profile rule suppressions).
    #[must_use]
    pub fn from_pyproject_toml_str(toml_str: &str) -> Option<Self> {
        let doc = toml::from_str::<toml::Value>(toml_str).ok()?;
        let tool = doc.get("tool").and_then(toml::Value::as_table);
        let dotore_tbl = tool
            .and_then(|t| t.get("dotore"))
            .and_then(toml::Value::as_table);

        let profile = infer_python_profile_from_pyproject_doc(&doc);
        if dotore_tbl.is_none() && profile != Some("cli") {
            return None;
        }

        let mut cfg = Self::default();
        if let Some(tbl) = dotore_tbl {
            apply_pyproject_tool_table(tbl, &mut cfg);
        }

        if profile == Some("cli") {
            for &rule_key in CLI_SUPPRESSED_RULES {
                let is_explicitly_enabled = RuleId::parse(rule_key)
                    .and_then(|id| cfg.explicit_rule_override(id))
                    .is_some();
                if !is_explicitly_enabled && !cfg.ignore.rules.iter().any(|r| r == rule_key) {
                    cfg.ignore.rules.push(rule_key.to_string());
                }
            }
        }
        if profile == Some("script") {
            for &rule_key in SCRIPT_SUPPRESSED_RULES {
                let is_explicitly_enabled = RuleId::parse(rule_key)
                    .and_then(|id| cfg.explicit_rule_override(id))
                    .is_some();
                if !is_explicitly_enabled && !cfg.ignore.rules.iter().any(|r| r == rule_key) {
                    cfg.ignore.rules.push(rule_key.to_string());
                }
            }
        }

        Some(cfg)
    }
}

/// Infers the Python project profile (`"web"`, `"cli"`, `"library"`, or `"script"`) from a
/// parsed `pyproject.toml` document.
#[must_use]
pub fn infer_python_profile_from_pyproject_doc(doc: &toml::Value) -> Option<&'static str> {
    if let Some(tool) = doc.get("tool").and_then(toml::Value::as_table)
        && let Some(profile_str) = tool
            .get("dotore")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("profile"))
            .and_then(toml::Value::as_str)
        && let Some(normalized) = normalize_profile_kind(profile_str)
    {
        return Some(normalized);
    }

    let deps = collect_pyproject_dep_names(doc);
    if deps.iter().any(|d| WEB_PACKAGES.contains(&d.as_str())) {
        return Some("web");
    }
    if deps.iter().any(|d| CLI_PACKAGES.contains(&d.as_str())) || has_pyproject_scripts(doc) {
        return Some("cli");
    }
    if doc
        .get("build-system")
        .and_then(toml::Value::as_table)
        .is_some()
    {
        return Some("library");
    }
    if doc
        .get("project")
        .and_then(toml::Value::as_table)
        .is_some()
        || doc
            .get("tool")
            .and_then(toml::Value::as_table)
            .is_some_and(|t| t.contains_key("poetry"))
    {
        return Some("script");
    }
    None
}

fn normalize_profile_kind(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "web" | "app" | "application" => Some("web"),
        "cli" => Some("cli"),
        "library" | "lib" => Some("library"),
        "script" | "scripts" => Some("script"),
        _ => None,
    }
}

fn has_pyproject_scripts(doc: &toml::Value) -> bool {
    if let Some(project) = doc.get("project").and_then(toml::Value::as_table) {
        for key in ["scripts", "gui-scripts"] {
            if project
                .get(key)
                .and_then(toml::Value::as_table)
                .is_some_and(|t| !t.is_empty())
            {
                return true;
            }
        }
    }
    doc.get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("scripts"))
        .and_then(toml::Value::as_table)
        .is_some_and(|t| !t.is_empty())
}

fn collect_pyproject_dep_names(doc: &toml::Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(project) = doc.get("project").and_then(toml::Value::as_table)
        && let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array)
    {
        for dep in deps.iter().filter_map(toml::Value::as_str) {
            let bare = extract_bare_pep508_name(dep);
            if !bare.is_empty() {
                names.push(bare);
            }
        }
    }
    if let Some(poetry_deps) = doc
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for key in poetry_deps.keys() {
            let bare = normalize_python_dep_name(key);
            if !bare.is_empty() && bare != "python" {
                names.push(bare);
            }
        }
    }
    names
}

fn extract_bare_pep508_name(raw: &str) -> String {
    let end = raw
        .find(['>', '<', '=', '!', '~', '[', ';', '@', ' ', '\t'])
        .unwrap_or(raw.len());
    normalize_python_dep_name(&raw[..end])
}

/// Normalizes a PEP 508 / Python distribution package name to lowercase hyphen-separated form.
#[must_use]
pub fn normalize_python_dep_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.trim().chars() {
        if ch == '_' || ch == '-' || ch == '.' {
            if !prev_dash && !out.is_empty() {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn apply_pyproject_tool_table(
    tbl: &toml::map::Map<String, toml::Value>,
    cfg: &mut DotoreConfig,
) {
    if let Some(suppress_arr) = tbl.get("suppress").and_then(toml::Value::as_array) {
        push_unique_toml_strings(&mut cfg.ignore.rules, suppress_arr, true);
    }
    apply_pyproject_per_file_suppress(tbl, cfg);
    apply_pyproject_severity_tables(tbl, cfg);
    if let Some(ignore_tbl) = tbl.get("ignore").and_then(toml::Value::as_table) {
        if let Some(rules) = ignore_tbl.get("rules").and_then(toml::Value::as_array) {
            push_unique_toml_strings(&mut cfg.ignore.rules, rules, false);
        }
        if let Some(files) = ignore_tbl.get("files").and_then(toml::Value::as_array) {
            push_unique_toml_strings(&mut cfg.ignore.files, files, false);
        }
        if let Some(tags) = ignore_tbl.get("tags").and_then(toml::Value::as_array) {
            push_unique_toml_strings(&mut cfg.ignore.tags, tags, false);
        }
    }
    apply_pyproject_boolean_flags(tbl, cfg);
}

fn push_unique_toml_strings(target: &mut Vec<String>, arr: &[toml::Value], trim: bool) {
    for raw in arr.iter().filter_map(toml::Value::as_str) {
        let item = if trim { raw.trim() } else { raw };
        if (!trim || !item.is_empty()) && !target.iter().any(|existing| existing == item) {
            target.push(item.to_string());
        }
    }
}

fn apply_pyproject_per_file_suppress(
    tbl: &toml::map::Map<String, toml::Value>,
    cfg: &mut DotoreConfig,
) {
    for key in ["per-file-suppress", "per_file_suppress", "perFileSuppress"] {
        let Some(per_file_tbl) = tbl.get(key).and_then(toml::Value::as_table) else {
            continue;
        };
        for (pat, val) in per_file_tbl {
            if !pat.trim().is_empty() {
                cfg.ignore.overrides.push(IgnoreOverride {
                    files: vec![pat.clone()],
                    rules: extract_string_or_array(val),
                });
            }
        }
    }
}

fn apply_pyproject_severity_tables(
    tbl: &toml::map::Map<String, toml::Value>,
    cfg: &mut DotoreConfig,
) {
    if let Some(rules_tbl) = tbl.get("rules").and_then(toml::Value::as_table) {
        for (rule_key, val) in rules_tbl {
            if let Some(sev) = val.as_str().and_then(parse_severity_override_str) {
                cfg.rules.insert(rule_key.clone(), sev);
            }
        }
    }
    if let Some(cats_tbl) = tbl.get("categories").and_then(toml::Value::as_table) {
        for (cat_key, val) in cats_tbl {
            if let Some(sev) = val.as_str().and_then(parse_severity_override_str) {
                cfg.categories.insert(cat_key.clone(), sev);
            }
        }
    }
}

fn apply_pyproject_boolean_flags(
    tbl: &toml::map::Map<String, toml::Value>,
    cfg: &mut DotoreConfig,
) {
    if let Some(warnings) = tbl.get("warnings").and_then(toml::Value::as_bool) {
        cfg.warnings = warnings;
    }
    for key in [
        "respect-inline-disables",
        "respect_inline_disables",
        "respectInlineDisables",
    ] {
        if let Some(val) = tbl.get(key).and_then(toml::Value::as_bool) {
            cfg.respect_inline_disables = val;
        }
    }
    for key in ["custom-rules-only", "custom_rules_only", "customRulesOnly"] {
        if let Some(val) = tbl.get(key).and_then(toml::Value::as_bool) {
            cfg.custom_rules_only = val;
        }
    }
}

fn extract_string_or_array(val: &toml::Value) -> Vec<String> {
    if let Some(s) = val.as_str() {
        vec![s.trim().to_string()]
    } else if let Some(arr) = val.as_array() {
        arr.iter()
            .filter_map(toml::Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    }
}

fn parse_severity_override_str(raw: &str) -> Option<RuleSeverityOverride> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "false" | "disable" | "disabled" => Some(RuleSeverityOverride::Off),
        "warn" | "warning" => Some(RuleSeverityOverride::Warn),
        "error" | "err" => Some(RuleSeverityOverride::Error),
        _ => None,
    }
}
