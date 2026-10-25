//! `pyproject.toml` configuration (`[tool.dotore]` and `[tool.python-doctor]`) and
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

impl DotoreConfig {
    /// Extracts a [`DotoreConfig`] from `[tool.dotore]` and `[tool.python-doctor]` in a
    /// `pyproject.toml` string (including Python `cli`/`script` profile rule suppressions).
    #[must_use]
    pub fn from_pyproject_toml_str(toml_str: &str) -> Option<Self> {
        let doc = toml::from_str::<toml::Value>(toml_str).ok()?;
        let tool = doc.get("tool").and_then(toml::Value::as_table);
        let dotore_tbl = tool
            .and_then(|t| t.get("dotore"))
            .and_then(toml::Value::as_table);
        let py_doctor_tbl = tool
            .and_then(|t| t.get("python-doctor").or_else(|| t.get("python_doctor")))
            .and_then(toml::Value::as_table);

        let profile = infer_python_profile_from_pyproject_doc(&doc);
        if dotore_tbl.is_none()
            && py_doctor_tbl.is_none()
            && !matches!(profile, Some("cli" | "script"))
        {
            return None;
        }

        let mut cfg = Self::default();
        if let Some(tbl) = py_doctor_tbl {
            apply_pyproject_tool_table(tbl, &mut cfg);
        }
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

        Some(cfg)
    }
}

/// Infers the Python project profile (`"web"`, `"cli"`, `"library"`, or `"script"`) from a
/// parsed `pyproject.toml` document.
#[must_use]
pub fn infer_python_profile_from_pyproject_doc(doc: &toml::Value) -> Option<&'static str> {
    if let Some(tool) = doc.get("tool").and_then(toml::Value::as_table) {
        for section_name in ["dotore", "python-doctor", "python_doctor"] {
            if let Some(profile_str) = tool
                .get(section_name)
                .and_then(toml::Value::as_table)
                .and_then(|t| t.get("profile"))
                .and_then(toml::Value::as_str)
                && let Some(normalized) = normalize_profile_kind(profile_str)
            {
                return Some(normalized);
            }
        }
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
            let bare = normalize_dep_name(key);
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
    normalize_dep_name(&raw[..end])
}

fn normalize_dep_name(raw: &str) -> String {
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
        for rule in suppress_arr.iter().filter_map(toml::Value::as_str) {
            let trimmed = rule.trim();
            if !trimmed.is_empty() && !cfg.ignore.rules.iter().any(|r| r == trimmed) {
                cfg.ignore.rules.push(trimmed.to_string());
            }
        }
    }

    for key in ["per-file-suppress", "per_file_suppress", "perFileSuppress"] {
        if let Some(per_file_tbl) = tbl.get(key).and_then(toml::Value::as_table) {
            for (pat, val) in per_file_tbl {
                let rules = extract_string_or_array(val);
                if !pat.trim().is_empty() {
                    cfg.ignore.overrides.push(IgnoreOverride {
                        files: vec![pat.clone()],
                        rules,
                    });
                }
            }
        }
    }

    if let Some(rules_tbl) = tbl.get("rules").and_then(toml::Value::as_table) {
        for (rule_key, val) in rules_tbl {
            if let Some(sev_str) = val.as_str()
                && let Some(sev) = parse_severity_override_str(sev_str)
            {
                cfg.rules.insert(rule_key.clone(), sev);
            }
        }
    }

    if let Some(cats_tbl) = tbl.get("categories").and_then(toml::Value::as_table) {
        for (cat_key, val) in cats_tbl {
            if let Some(sev_str) = val.as_str()
                && let Some(sev) = parse_severity_override_str(sev_str)
            {
                cfg.categories.insert(cat_key.clone(), sev);
            }
        }
    }

    if let Some(ignore_tbl) = tbl.get("ignore").and_then(toml::Value::as_table) {
        if let Some(rules) = ignore_tbl.get("rules").and_then(toml::Value::as_array) {
            for r in rules.iter().filter_map(toml::Value::as_str) {
                if !cfg.ignore.rules.iter().any(|existing| existing == r) {
                    cfg.ignore.rules.push(r.to_string());
                }
            }
        }
        if let Some(files) = ignore_tbl.get("files").and_then(toml::Value::as_array) {
            for f in files.iter().filter_map(toml::Value::as_str) {
                if !cfg.ignore.files.iter().any(|existing| existing == f) {
                    cfg.ignore.files.push(f.to_string());
                }
            }
        }
        if let Some(tags) = ignore_tbl.get("tags").and_then(toml::Value::as_array) {
            for t in tags.iter().filter_map(toml::Value::as_str) {
                if !cfg.ignore.tags.iter().any(|existing| existing == t) {
                    cfg.ignore.tags.push(t.to_string());
                }
            }
        }
    }

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
