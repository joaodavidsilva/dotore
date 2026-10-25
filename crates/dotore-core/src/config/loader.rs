//! User configuration loader for `dotore.config.*` (TS, JS, MJS, CJS, JSON, JSONC)
//! and the `"dotore"` key in `package.json`.

mod js_parser;

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::rules::{RuleCategory, RuleId, RuleSeverity, RuleSeverityOverride, RuleTag};

pub(super) use self::js_parser::{ConfigCursor, ParsedObject, parse_exported_module_object};
pub use super::mutator::{
    ConfigMutation, ConfigTargetKind, MutateConfigResult, mutate_config_in_dir,
};
use super::workspace::{normalize_path_buf, relative_forward_slash, strip_jsonc};
pub(super) const CONFIG_EXTENSIONS: &[&str] =
    &["ts", "mts", "cts", "js", "mjs", "cjs", "json", "jsonc"];

/// Per-path rule suppression block inside `ignore.overrides`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IgnoreOverride {
    /// Glob patterns matching files this override applies to (e.g. `["src/legacy/**"]`).
    #[serde(default)]
    pub files: Vec<String>,
    /// Rule keys to suppress for the matched files (empty suppresses all rules for those files).
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Ignore block inside [`DotoreConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IgnoreConfig {
    /// Rule keys whose diagnostics are suppressed.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Glob patterns of files excluded from scanning.
    #[serde(default)]
    pub files: Vec<String>,
    /// Per-path rule suppression overrides.
    #[serde(default)]
    pub overrides: Vec<IgnoreOverride>,
    /// Rule tags whose rules are disabled (e.g. `["design", "test-noise"]`).
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Supply-chain Socket.dev PURL scoring configuration inside [`DotoreConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupplyChainConfig {
    /// Whether the supply-chain check is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum acceptable Socket security-axis score (`0..=100`). Defaults to `50`.
    #[serde(default = "default_supply_chain_min_score")]
    pub min_score: u32,
    /// Diagnostic severity (`"error"` or `"warning"`). Defaults to `RuleSeverity::Error`.
    #[serde(default = "default_supply_chain_severity")]
    pub severity: RuleSeverity,
    /// Whether `devDependencies` are scored (gated on `supplyChain` axis only). Defaults to `true`.
    #[serde(default = "default_true")]
    pub include_dev_dependencies: bool,
    /// Optional local cache directory for per-PURL Socket artifacts.
    #[serde(default)]
    pub cache_dir: Option<String>,
    /// Optional custom Socket PURL API base URL (defaults to `"https://firewall-api.socket.dev/purl"`).
    #[serde(default)]
    pub api_base_url: Option<String>,
}

const fn default_supply_chain_min_score() -> u32 {
    50
}

const fn default_supply_chain_severity() -> RuleSeverity {
    RuleSeverity::Error
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_score: 50,
            severity: RuleSeverity::Error,
            include_dev_dependencies: true,
            cache_dir: None,
            api_base_url: None,
        }
    }
}

/// Multi-signal structural thresholds for Architecture, Separation of Concerns & Reuse rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchitectureThresholdsConfig {
    /// Minimum statements in a private helper function before computing duplication fingerprints (`arch-no-duplicated-helper-logic`). Defaults to `4`.
    #[serde(
        default = "default_min_helper_statements",
        alias = "min_helper_statements"
    )]
    pub min_helper_statements: usize,
    /// Minimum distinct modules containing an identical helper fingerprint (`arch-no-duplicated-helper-logic`). Defaults to `2`.
    #[serde(
        default = "default_min_duplicated_helper_modules",
        alias = "min_duplicated_helper_modules"
    )]
    pub min_duplicated_helper_modules: usize,
    /// Minimum fields in a struct/object literal before requiring a fluent builder (`arch-prefer-fluent-builder`). Defaults to `5`.
    #[serde(default = "default_min_builder_fields", alias = "min_builder_fields")]
    pub min_builder_fields: usize,
    /// Minimum construction sites sharing boilerplate/default fields (`arch-prefer-fluent-builder`). Defaults to `3`.
    #[serde(default = "default_min_builder_sites", alias = "min_builder_sites")]
    pub min_builder_sites: usize,
    /// Minimum public/exported domain types in a file alongside a static catalog (`arch-separate-static-catalog-from-types`). Defaults to `3`.
    #[serde(
        default = "default_min_types_with_catalog",
        alias = "min_types_with_catalog"
    )]
    pub min_types_with_catalog: usize,
    /// Minimum static catalog entries in a file alongside domain types (`arch-separate-static-catalog-from-types`). Defaults to `25`.
    #[serde(
        default = "default_min_static_catalog_entries",
        alias = "min_static_catalog_entries"
    )]
    pub min_static_catalog_entries: usize,
    /// Maximum statements allowed in a thin binary/application entrypoint (`arch-thin-entrypoint`). Defaults to `25`.
    #[serde(
        default = "default_max_entrypoint_statements",
        alias = "max_entrypoint_statements"
    )]
    pub max_entrypoint_statements: usize,
    /// Minimum distinct domain clusters in a monolith file (`arch-no-mixed-domain-monolith`). Defaults to `3`.
    #[serde(
        default = "default_min_monolith_domain_clusters",
        alias = "min_monolith_domain_clusters"
    )]
    pub min_monolith_domain_clusters: usize,
    /// Minimum top-level symbols in a monolith file (`arch-no-mixed-domain-monolith`). Defaults to `12`.
    #[serde(
        default = "default_min_monolith_symbols",
        alias = "min_monolith_symbols"
    )]
    pub min_monolith_symbols: usize,
}

const fn default_min_helper_statements() -> usize {
    4
}
const fn default_min_duplicated_helper_modules() -> usize {
    2
}
const fn default_min_builder_fields() -> usize {
    5
}
const fn default_min_builder_sites() -> usize {
    3
}
const fn default_min_types_with_catalog() -> usize {
    3
}
const fn default_min_static_catalog_entries() -> usize {
    25
}
const fn default_max_entrypoint_statements() -> usize {
    25
}
const fn default_min_monolith_domain_clusters() -> usize {
    3
}
const fn default_min_monolith_symbols() -> usize {
    12
}

impl Default for ArchitectureThresholdsConfig {
    fn default() -> Self {
        Self {
            min_helper_statements: default_min_helper_statements(),
            min_duplicated_helper_modules: default_min_duplicated_helper_modules(),
            min_builder_fields: default_min_builder_fields(),
            min_builder_sites: default_min_builder_sites(),
            min_types_with_catalog: default_min_types_with_catalog(),
            min_static_catalog_entries: default_min_static_catalog_entries(),
            max_entrypoint_statements: default_max_entrypoint_statements(),
            min_monolith_domain_clusters: default_min_monolith_domain_clusters(),
            min_monolith_symbols: default_min_monolith_symbols(),
        }
    }
}

/// Project configuration loaded from `dotore.config.*` or `package.json#dotore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DotoreConfig {
    /// Per-rule severity overrides (`"off"`, `"warn"`, `"error"`).
    #[serde(default, serialize_with = "serialize_sorted_map")]
    pub rules: HashMap<String, RuleSeverityOverride>,
    /// Per-category severity overrides (`"Bugs"`, `"Performance"`, `"Accessibility"`, `"Security"`, `"Maintainability"`).
    #[serde(default, serialize_with = "serialize_sorted_map")]
    pub categories: HashMap<String, RuleSeverityOverride>,
    /// File, rule, tag, and per-path ignore settings.
    #[serde(default)]
    pub ignore: IgnoreConfig,
    /// When `true`, rules originally ported from external plugins are disabled unless explicitly enabled in `rules`.
    #[serde(default)]
    pub custom_rules_only: bool,
    /// Custom React Native text components that safely render raw text children (suppressing `rn-no-raw-text`).
    #[serde(default)]
    pub text_components: Vec<String>,
    /// Wrapper components that route string-only children into `<Text>` (suppressing `rn-no-raw-text` when no sibling JSX elements exist).
    #[serde(default)]
    pub raw_text_wrapper_components: Vec<String>,
    /// Capitalized component identifiers injected at runtime (suppressing `jsx-no-undef`).
    #[serde(default)]
    pub runtime_globals: Vec<String>,
    /// Custom server authentication guard function names for `server-auth-actions`.
    #[serde(default)]
    pub server_auth_function_names: Vec<String>,
    /// Supply-chain Socket.dev PURL dependency scoring configuration.
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,
    /// Whether inline disable comments (`// dotore-disable-next-line`, etc.) are respected. Defaults to `true`.
    #[serde(default = "default_true")]
    pub respect_inline_disables: bool,
    /// Whether warning-severity diagnostics are surfaced. Defaults to `true`.
    #[serde(default = "default_true")]
    pub warnings: bool,
    /// Configurable multi-signal thresholds for Architecture, Separation of Concerns & Reuse rules.
    #[serde(default)]
    pub architecture: ArchitectureThresholdsConfig,
}

const fn default_true() -> bool {
    true
}

impl Default for DotoreConfig {
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            categories: HashMap::new(),
            ignore: IgnoreConfig::default(),
            custom_rules_only: false,
            text_components: Vec::new(),
            raw_text_wrapper_components: Vec::new(),
            runtime_globals: Vec::new(),
            server_auth_function_names: Vec::new(),
            supply_chain: SupplyChainConfig::default(),
            respect_inline_disables: true,
            warnings: true,
            architecture: ArchitectureThresholdsConfig::default(),
        }
    }
}

impl DotoreConfig {
    /// Parses a [`DotoreConfig`] from a JSON or JSONC string.
    ///
    /// # Errors
    /// Returns a human-readable error message if the JSON is invalid.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        serde_json::from_str::<Self>(&strip_jsonc(json)).map_err(|e| e.to_string())
    }

    /// Extracts a [`DotoreConfig`] from the `"dotore"` field of a `package.json` string, if present.
    #[must_use]
    pub fn from_package_json_str(json: &str) -> Option<Self> {
        let val = serde_json::from_str::<Value>(&strip_jsonc(json)).ok()?;
        let dotore_obj = val.get("dotore")?.as_object()?;
        serde_json::from_value::<Self>(Value::Object(dotore_obj.clone())).ok()
    }

    /// Parses a [`DotoreConfig`] from a JS/TS/JSON config file (`dotore.config.*`).
    ///
    /// # Errors
    /// Returns an error string if the config module or JSON cannot be parsed into a [`DotoreConfig`].
    pub fn from_config_file_str(path: &Path, source: &str) -> Result<Self, String> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("json");
        if ext == "json" || ext == "jsonc" {
            return Self::from_json_str(source);
        }
        let val = extract_config_value_from_module(path, source)?;
        serde_json::from_value::<Self>(val).map_err(|e| e.to_string())
    }

    /// Looks up the explicit per-rule [`RuleSeverityOverride`] in `self.rules`.
    #[must_use]
    pub fn explicit_rule_override(&self, rule: RuleId) -> Option<RuleSeverityOverride> {
        self.rules
            .iter()
            .find(|(k, _)| RuleId::parse(k) == Some(rule))
            .map(|(_, &v)| v)
    }

    /// Looks up the category-level [`RuleSeverityOverride`] in `self.categories`.
    #[must_use]
    pub fn category_override(&self, category: RuleCategory) -> Option<RuleSeverityOverride> {
        self.categories
            .iter()
            .find(|(k, _)| RuleCategory::parse(k) == Some(category))
            .map(|(_, &v)| v)
    }

    /// Returns `true` if `tag` is listed in `self.ignore.tags`.
    #[must_use]
    pub fn is_tag_ignored(&self, tag: RuleTag) -> bool {
        self.ignore
            .tags
            .iter()
            .any(|t| RuleTag::parse(t) == Some(tag))
    }

    /// Resolves the effective [`RuleSeverity`] for `rule` under this config, or `None` if disabled.
    #[must_use]
    pub fn effective_severity(&self, rule: RuleId) -> Option<RuleSeverity> {
        let meta = rule.metadata();
        if meta.tags.iter().any(|&t| self.is_tag_ignored(t))
            || self
                .ignore
                .rules
                .iter()
                .any(|r| RuleId::parse(r) == Some(rule))
        {
            return None;
        }
        let explicit_rule = self.explicit_rule_override(rule);
        if self.custom_rules_only
            && meta.originally_external
            && !matches!(
                explicit_rule,
                Some(RuleSeverityOverride::Error | RuleSeverityOverride::Warn)
            )
        {
            return None;
        }
        if !meta.default_enabled && explicit_rule.is_none() {
            return None;
        }
        let resolved = explicit_rule.or_else(|| self.category_override(meta.category));
        let severity = match resolved {
            Some(RuleSeverityOverride::Off) => return None,
            Some(RuleSeverityOverride::Error) => RuleSeverity::Error,
            Some(RuleSeverityOverride::Warn) => RuleSeverity::Warning,
            None => meta.default_severity,
        };
        if !self.warnings
            && severity == RuleSeverity::Warning
            && resolved != Some(RuleSeverityOverride::Warn)
        {
            return None;
        }
        Some(severity)
    }

    /// Returns `true` if `file_path` matches any glob in `self.ignore.files`.
    #[must_use]
    pub fn is_file_ignored(&self, file_path: &Path, root_dir: &Path) -> bool {
        if self.ignore.files.is_empty() {
            return false;
        }
        let rel = relative_forward_slash(file_path, root_dir);
        self.ignore.files.iter().any(|pat| glob_matches(pat, &rel))
    }

    /// Returns `true` if `rule` is suppressed on `file_path` by `self.ignore.overrides`.
    #[must_use]
    pub fn is_overridden_for_file(&self, rule: RuleId, file_path: &Path, root_dir: &Path) -> bool {
        if self.ignore.overrides.is_empty() {
            return false;
        }
        let rel = relative_forward_slash(file_path, root_dir);
        self.ignore.overrides.iter().any(|ov| {
            ov.files.iter().any(|pat| glob_matches(pat, &rel))
                && (ov.rules.is_empty() || ov.rules.iter().any(|r| RuleId::parse(r) == Some(rule)))
        })
    }
}

fn serialize_sorted_map<S, V>(map: &HashMap<String, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    V: Serialize,
{
    let mut sorted: Vec<(&String, &V)> = map.iter().collect();
    sorted.sort_by_key(|(a, _)| *a);
    serializer.collect_map(sorted)
}

/// Loads [`DotoreConfig`] from `dir` or its nearest ancestor containing `dotore.config.*` or `package.json#dotore`.
#[must_use]
pub fn load_config_from_dir(dir: &Path) -> DotoreConfig {
    let start = if dir.is_file() {
        dir.parent().unwrap_or(dir)
    } else {
        dir
    };
    let temp_root = normalize_path_buf(&std::env::temp_dir());
    let mut current = Some(start);
    while let Some(d) = current {
        if normalize_path_buf(d) == temp_root {
            break;
        }
        if let Some(cfg) = load_local_config_in_dir(d) {
            return cfg;
        }
        if d.join(".git").exists() {
            break;
        }
        current = d.parent();
    }
    DotoreConfig::default()
}

/// Loads [`DotoreConfig`] directly inside `dir` (without walking ancestors).
#[must_use]
pub fn load_local_config_in_dir(dir: &Path) -> Option<DotoreConfig> {
    for &ext in CONFIG_EXTENSIONS {
        let candidate = dir.join(format!("dotore.config.{ext}"));
        if let Ok(content) = fs::read_to_string(&candidate)
            && let Ok(cfg) = DotoreConfig::from_config_file_str(&candidate, &content)
        {
            return Some(cfg);
        }
    }
    if let Some(cfg) = fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|c| DotoreConfig::from_package_json_str(&c))
    {
        return Some(cfg);
    }
    fs::read_to_string(dir.join("pyproject.toml"))
        .ok()
        .and_then(|c| DotoreConfig::from_pyproject_toml_str(&c))
}

fn extract_config_value_from_module(path: &Path, source: &str) -> Result<Value, String> {
    let parsed_obj = parse_exported_module_object(source).map_err(|_| {
        format!(
            "No static configuration object export found in {}",
            path.display()
        )
    })?;
    Ok(Value::Object(parsed_obj.map))
}
fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let clean_pat = pattern
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();
    let clean_cand = candidate
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();
    if clean_pat.is_empty() {
        return false;
    }
    if !clean_pat.contains('/') && !clean_pat.contains("**") {
        let base = clean_cand.rsplit('/').next().unwrap_or(clean_cand.as_str());
        if segment_wildcard_match(&clean_pat, base) {
            return true;
        }
    }
    let pat_segs: Vec<&str> = clean_pat.split('/').filter(|s| !s.is_empty()).collect();
    let cand_segs: Vec<&str> = clean_cand.split('/').filter(|s| !s.is_empty()).collect();
    glob_segments_match(&pat_segs, &cand_segs)
}

fn glob_segments_match(pat: &[&str], cand: &[&str]) -> bool {
    match (pat, cand) {
        ([], []) => true,
        (["**", pat_rest @ ..], _) => {
            glob_segments_match(pat_rest, cand)
                || (cand.split_first().is_some_and(|(_, cand_rest)| glob_segments_match(pat, cand_rest)))
        }
        ([p, pat_rest @ ..], [c, cand_rest @ ..]) if segment_wildcard_match(p, c) => {
            glob_segments_match(pat_rest, cand_rest)
        }
        _ => false,
    }
}

fn segment_wildcard_match(pat: &str, text: &str) -> bool {
    let (p, t) = (pat.as_bytes(), text.as_bytes());
    let (mut pi, mut ti, mut star_pi, mut star_ti) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
