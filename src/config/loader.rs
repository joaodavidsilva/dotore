//! User configuration loader for `dotore.config.*` (TS, JS, MJS, CJS, JSON, JSONC)
//! and the `"dotore"` key in `package.json`.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast expression and statement enums have dozens of variants; config AST evaluation matches only literal/object/export forms"
)]

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpressionElement, AssignmentTarget, Declaration, ExportDefaultDeclarationKind,
    Expression, ObjectExpression, ObjectPropertyKind, PropertyKey, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::rules::{RuleCategory, RuleId, RuleSeverity, RuleSeverityOverride, RuleTag};

use super::{normalize_path_buf, relative_forward_slash, strip_jsonc};

const CONFIG_EXTENSIONS: &[&str] = &["ts", "mts", "cts", "js", "mjs", "cjs", "json", "jsonc"];

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

/// Project configuration loaded from `dotore.config.*` or `package.json#dotore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DotoreConfig {
    /// Per-rule severity overrides (`"off"`, `"warn"`, `"error"`).
    #[serde(default)]
    pub rules: HashMap<String, RuleSeverityOverride>,
    /// Per-category severity overrides (`"Bugs"`, `"Performance"`, `"Accessibility"`, `"Security"`, `"Maintainability"`).
    #[serde(default)]
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
        let rel = relative_forward_slash(file_path, root_dir);
        self.ignore.files.iter().any(|pat| glob_matches(pat, &rel))
    }

    /// Returns `true` if `rule` is suppressed on `file_path` by `self.ignore.overrides`.
    #[must_use]
    pub fn is_overridden_for_file(&self, rule: RuleId, file_path: &Path, root_dir: &Path) -> bool {
        let rel = relative_forward_slash(file_path, root_dir);
        self.ignore.overrides.iter().any(|ov| {
            ov.files.iter().any(|pat| glob_matches(pat, &rel))
                && (ov.rules.is_empty() || ov.rules.iter().any(|r| RuleId::parse(r) == Some(rule)))
        })
    }
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

pub(crate) fn load_local_config_in_dir(dir: &Path) -> Option<DotoreConfig> {
    for &ext in CONFIG_EXTENSIONS {
        let candidate = dir.join(format!("dotore.config.{ext}"));
        if let Ok(content) = fs::read_to_string(&candidate)
            && let Ok(cfg) = DotoreConfig::from_config_file_str(&candidate, &content)
        {
            return Some(cfg);
        }
    }
    fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|c| DotoreConfig::from_package_json_str(&c))
}

/// Mutation operation applied to `dotore.config.*` or `package.json#dotore` by `dotore rules`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigMutation {
    /// Set or override a rule's severity (`enable`, `disable`, `set`).
    SetRuleSeverity {
        /// Canonical rule identifier.
        rule: RuleId,
        /// Target severity override (`error`, `warn`, `off`).
        severity: RuleSeverityOverride,
    },
    /// Set or override an entire rule category's severity (`category`).
    SetCategorySeverity {
        /// Target rule category.
        category: RuleCategory,
        /// Target severity override (`error`, `warn`, `off`).
        severity: RuleSeverityOverride,
    },
    /// Add a rule tag to `ignore.tags` (`ignore-tag`).
    IgnoreTag {
        /// Rule tag to ignore.
        tag: RuleTag,
    },
    /// Remove a rule tag from `ignore.tags` (`unignore-tag`).
    UnignoreTag {
        /// Rule tag to unignore.
        tag: RuleTag,
    },
}

/// Format of the configuration file targeted by [`mutate_config_in_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigTargetKind {
    /// Dedicated JSON/JSONC file (`dotore.config.json` or `dotore.config.jsonc`).
    JsonFile,
    /// Embedded `"dotore"` object inside `package.json`.
    PackageJson,
    /// JavaScript or TypeScript module (`dotore.config.{ts,mts,cts,js,mjs,cjs}`).
    ModuleFile,
}

/// Outcome of applying a [`ConfigMutation`] via [`mutate_config_in_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutateConfigResult {
    /// Path to the updated (or created) configuration file.
    pub target_path: PathBuf,
    /// Kind of configuration file targeted.
    pub target_kind: ConfigTargetKind,
    /// Whether a new `dotore.config.json` file was created.
    pub created: bool,
    /// Whether the file content changed on disk.
    pub changed: bool,
    /// Updated [`DotoreConfig`] after applying the mutation.
    pub config: DotoreConfig,
}

/// Applies `mutation` to the nearest `dotore.config.*` or `package.json#dotore` in `dir`
/// (or creates `dotore.config.json` if none exists), preserving unrelated fields and formatting.
///
/// # Errors
/// Returns a human-readable error if an existing config is dynamic or cannot be updated on disk.
pub fn mutate_config_in_dir(
    dir: &Path,
    mutation: ConfigMutation,
) -> Result<MutateConfigResult, String> {
    let start = if dir.is_file() {
        dir.parent().unwrap_or(dir)
    } else {
        dir
    };

    if let Some((target_path, target_kind)) = resolve_existing_config_target(start) {
        let raw = fs::read_to_string(&target_path)
            .map_err(|e| format!("Failed to read {}: {e}", target_path.display()))?;
        let (updated_source, changed) = match target_kind {
            ConfigTargetKind::JsonFile => mutate_json_or_module_object(&raw, true, mutation)?,
            ConfigTargetKind::ModuleFile => mutate_json_or_module_object(&raw, false, mutation)?,
            ConfigTargetKind::PackageJson => mutate_package_json_dotore(&raw, mutation)?,
        };
        if changed {
            fs::write(&target_path, &updated_source)
                .map_err(|e| format!("Failed to write {}: {e}", target_path.display()))?;
        }
        let config = match target_kind {
            ConfigTargetKind::PackageJson => {
                DotoreConfig::from_package_json_str(&updated_source).unwrap_or_default()
            }
            ConfigTargetKind::JsonFile | ConfigTargetKind::ModuleFile => {
                DotoreConfig::from_config_file_str(&target_path, &updated_source)
                    .unwrap_or_default()
            }
        };
        return Ok(MutateConfigResult {
            target_path,
            target_kind,
            created: false,
            changed,
            config,
        });
    }

    let target_path = start.join("dotore.config.json");
    if matches!(mutation, ConfigMutation::UnignoreTag { .. }) {
        return Ok(MutateConfigResult {
            target_path,
            target_kind: ConfigTargetKind::JsonFile,
            created: false,
            changed: false,
            config: DotoreConfig::default(),
        });
    }

    let mut map = Map::new();
    let changed = apply_mutation_to_config_map(&mut map, mutation);
    let serialized = serde_json::to_string_pretty(&Value::Object(map))
        .map_err(|e| format!("Failed to serialize config JSON: {e}"))?;
    let content = format!("{serialized}\n");
    fs::write(&target_path, &content)
        .map_err(|e| format!("Failed to create {}: {e}", target_path.display()))?;
    let config = DotoreConfig::from_json_str(&content).unwrap_or_default();
    Ok(MutateConfigResult {
        target_path,
        target_kind: ConfigTargetKind::JsonFile,
        created: true,
        changed,
        config,
    })
}

fn resolve_existing_config_target(start_dir: &Path) -> Option<(PathBuf, ConfigTargetKind)> {
    let temp_root = normalize_path_buf(&std::env::temp_dir());
    let mut current = Some(start_dir);
    while let Some(d) = current {
        if normalize_path_buf(d) == temp_root {
            break;
        }
        for &ext in CONFIG_EXTENSIONS {
            let candidate = d.join(format!("dotore.config.{ext}"));
            if candidate.is_file() {
                let kind = if ext == "json" || ext == "jsonc" {
                    ConfigTargetKind::JsonFile
                } else {
                    ConfigTargetKind::ModuleFile
                };
                return Some((candidate, kind));
            }
        }
        let pkg_json = d.join("package.json");
        if let Ok(content) = fs::read_to_string(&pkg_json)
            && DotoreConfig::from_package_json_str(&content).is_some()
        {
            return Some((pkg_json, ConfigTargetKind::PackageJson));
        }
        if d.join(".git").exists() {
            break;
        }
        current = d.parent();
    }
    None
}

fn apply_mutation_to_config_map(map: &mut Map<String, Value>, mutation: ConfigMutation) -> bool {
    match mutation {
        ConfigMutation::SetRuleSeverity { rule, severity } => {
            let rules_val = map
                .entry("rules".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !rules_val.is_object() {
                *rules_val = Value::Object(Map::new());
            }
            let Some(rules_obj) = rules_val.as_object_mut() else {
                return false;
            };
            let keys_to_remove: Vec<String> = rules_obj
                .keys()
                .filter(|k| RuleId::parse(k) == Some(rule))
                .cloned()
                .collect();
            for k in keys_to_remove {
                rules_obj.remove(&k);
            }
            rules_obj.insert(
                rule.metadata().qualified_key.to_string(),
                Value::String(severity.as_str().to_string()),
            );
            true
        }
        ConfigMutation::SetCategorySeverity { category, severity } => {
            let cat_val = map
                .entry("categories".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !cat_val.is_object() {
                *cat_val = Value::Object(Map::new());
            }
            let Some(cat_obj) = cat_val.as_object_mut() else {
                return false;
            };
            let keys_to_remove: Vec<String> = cat_obj
                .keys()
                .filter(|k| RuleCategory::parse(k) == Some(category))
                .cloned()
                .collect();
            for k in keys_to_remove {
                cat_obj.remove(&k);
            }
            cat_obj.insert(
                category.as_str().to_string(),
                Value::String(severity.as_str().to_string()),
            );
            true
        }
        ConfigMutation::IgnoreTag { tag } => {
            let ignore_val = map
                .entry("ignore".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !ignore_val.is_object() {
                *ignore_val = Value::Object(Map::new());
            }
            let Some(ignore_obj) = ignore_val.as_object_mut() else {
                return false;
            };
            let mut tags_set: BTreeSet<String> = ignore_obj
                .get("tags")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let inserted = tags_set.insert(tag.as_str().to_string());
            ignore_obj.insert(
                "tags".to_string(),
                Value::Array(tags_set.into_iter().map(Value::String).collect()),
            );
            inserted
        }
        ConfigMutation::UnignoreTag { tag } => {
            let Some(ignore_obj) = map.get_mut("ignore").and_then(Value::as_object_mut) else {
                return false;
            };
            let Some(tags_arr) = ignore_obj.get("tags").and_then(Value::as_array) else {
                return false;
            };
            let remaining: Vec<Value> = tags_arr
                .iter()
                .filter(|v| {
                    v.as_str()
                        .is_none_or(|s| s != tag.as_str() && RuleTag::parse(s) != Some(tag))
                })
                .cloned()
                .collect();
            if remaining.len() == tags_arr.len() {
                return false;
            }
            if remaining.is_empty() {
                ignore_obj.remove("tags");
            } else {
                ignore_obj.insert("tags".to_string(), Value::Array(remaining));
            }
            if ignore_obj.is_empty() {
                map.remove("ignore");
            }
            true
        }
    }
}

const fn mutation_managed_key(mutation: ConfigMutation) -> &'static str {
    match mutation {
        ConfigMutation::SetRuleSeverity { .. } => "rules",
        ConfigMutation::SetCategorySeverity { .. } => "categories",
        ConfigMutation::IgnoreTag { .. } | ConfigMutation::UnignoreTag { .. } => "ignore",
    }
}

fn mutate_json_or_module_object(
    raw_source: &str,
    is_json_file: bool,
    mutation: ConfigMutation,
) -> Result<(String, bool), String> {
    let (parse_input, byte_offset) = if is_json_file {
        (format!("(\n{raw_source}\n)"), 2_u32)
    } else {
        (raw_source.to_string(), 0_u32)
    };

    let allocator = Allocator::default();
    let source_type = SourceType::ts().with_module(true);
    let parsed = Parser::new(&allocator, &parse_input, source_type).parse();

    let mut bindings: HashMap<&str, &Expression<'_>> = HashMap::new();
    for stmt in &parsed.program.body {
        match stmt {
            Statement::VariableDeclaration(v) => collect_var_decl_bindings(v, &mut bindings),
            Statement::ExportDeclaration(exp) => {
                if let Declaration::VariableDeclaration(v) = &exp.declaration {
                    collect_var_decl_bindings(v, &mut bindings);
                }
            }
            _ => {}
        }
    }

    let target_obj = if is_json_file {
        parsed.program.body.first().and_then(|stmt| {
            if let Statement::ExpressionStatement(es) = stmt
                && let Expression::ObjectExpression(obj) = unwrap_ts_expr(&es.expression)
            {
                Some(obj.as_ref())
            } else {
                None
            }
        })
    } else {
        find_exported_object_expr(&parsed.program.body, &bindings)
    };

    let Some(obj_expr) = target_obj else {
        return Err(
            "Could not statically edit configuration object (dynamic config export)".to_string(),
        );
    };

    let Some(Value::Object(mut config_map)) = eval_object_expr(obj_expr, &bindings) else {
        return Err(
            "Could not evaluate static configuration properties for in-place edit".to_string(),
        );
    };

    let changed = apply_mutation_to_config_map(&mut config_map, mutation);
    if !changed {
        return Ok((raw_source.to_string(), false));
    }

    let managed_key = mutation_managed_key(mutation);
    let updated = splice_object_property_in_source(
        raw_source,
        obj_expr,
        byte_offset,
        managed_key,
        config_map.get(managed_key),
    )?;
    Ok((updated, true))
}

fn mutate_package_json_dotore(
    raw_source: &str,
    mutation: ConfigMutation,
) -> Result<(String, bool), String> {
    let parse_input = format!("(\n{raw_source}\n)");
    let byte_offset = 2_u32;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &parse_input, SourceType::ts()).parse();

    let Some(Statement::ExpressionStatement(es)) = parsed.program.body.first() else {
        return Err("Invalid package.json structure".to_string());
    };
    let Expression::ObjectExpression(root_obj) = unwrap_ts_expr(&es.expression) else {
        return Err("package.json root is not a JSON object".to_string());
    };

    let bindings = HashMap::new();
    let mut dotore_obj_expr: Option<&ObjectExpression<'_>> = None;
    for prop_kind in &root_obj.properties {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
            && property_key_name(&prop.key).as_deref() == Some("dotore")
            && let Expression::ObjectExpression(inner) = unwrap_ts_expr(&prop.value)
        {
            dotore_obj_expr = Some(inner.as_ref());
            break;
        }
    }

    let Some(obj_expr) = dotore_obj_expr else {
        return Err("package.json does not contain a static \"dotore\" object".to_string());
    };
    let Some(Value::Object(mut config_map)) = eval_object_expr(obj_expr, &bindings) else {
        return Err("Failed to evaluate package.json#dotore object".to_string());
    };

    let changed = apply_mutation_to_config_map(&mut config_map, mutation);
    if !changed {
        return Ok((raw_source.to_string(), false));
    }
    let managed_key = mutation_managed_key(mutation);
    let updated = splice_object_property_in_source(
        raw_source,
        obj_expr,
        byte_offset,
        managed_key,
        config_map.get(managed_key),
    )?;
    Ok((updated, true))
}

fn find_exported_object_expr<'a>(
    body: &'a [Statement<'a>],
    bindings: &HashMap<&str, &'a Expression<'a>>,
) -> Option<&'a ObjectExpression<'a>> {
    for stmt in body {
        match stmt {
            Statement::ExportDefaultDeclaration(exp) => {
                if let Some(expr) = exp.declaration.as_expression()
                    && let Some(obj) = resolve_expr_to_object(expr, bindings)
                {
                    return Some(obj);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                if let Expression::AssignmentExpression(assign) =
                    unwrap_ts_expr(&expr_stmt.expression)
                    && is_module_exports_target(&assign.left)
                    && let Some(obj) = resolve_expr_to_object(&assign.right, bindings)
                {
                    return Some(obj);
                }
            }
            _ => {}
        }
    }
    None
}

fn resolve_expr_to_object<'a>(
    expr: &'a Expression<'a>,
    bindings: &HashMap<&str, &'a Expression<'a>>,
) -> Option<&'a ObjectExpression<'a>> {
    match unwrap_ts_expr(expr) {
        Expression::ObjectExpression(obj) => Some(obj.as_ref()),
        Expression::CallExpression(call) => {
            resolve_expr_to_object(call.arguments.first()?.as_expression()?, bindings)
        }
        Expression::Identifier(ident) => {
            resolve_expr_to_object(bindings.get(ident.name.as_str())?, bindings)
        }
        _ => None,
    }
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.as_str()?.to_string()),
        _ => None,
    }
}

fn eval_object_expr<'a>(
    obj: &ObjectExpression<'a>,
    bindings: &HashMap<&str, &Expression<'a>>,
) -> Option<Value> {
    let mut map = Map::new();
    for prop_kind in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind {
            let key = property_key_name(&prop.key)?;
            map.insert(key, eval_config_expr(&prop.value, bindings)?);
        }
    }
    Some(Value::Object(map))
}

fn splice_object_property_in_source(
    raw_source: &str,
    obj_expr: &ObjectExpression<'_>,
    byte_offset: u32,
    managed_key: &str,
    new_val: Option<&Value>,
) -> Result<String, String> {
    let obj_start = (obj_expr.span.start - byte_offset) as usize;
    let obj_end = (obj_expr.span.end - byte_offset) as usize;
    let mut props: Vec<(String, Span, Span)> = Vec::new();
    for prop_kind in &obj_expr.properties {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind {
            let Some(k) = property_key_name(&prop.key) else {
                continue;
            };
            let p_span = Span::new(prop.span.start - byte_offset, prop.span.end - byte_offset);
            let v_span = Span::new(
                prop.value.span().start - byte_offset,
                prop.value.span().end - byte_offset,
            );
            props.push((k, p_span, v_span));
        }
    }

    if let Some((idx, (_, prop_span, val_span))) = props
        .iter()
        .enumerate()
        .find(|(_, (k, _, _))| k == managed_key)
    {
        if let Some(val) = new_val {
            let prop_indent = line_indent_at(raw_source, prop_span.start as usize);
            let formatted = format_value_with_indent(val, &prop_indent)?;
            let mut out = String::with_capacity(raw_source.len() + formatted.len());
            out.push_str(&raw_source[..val_span.start as usize]);
            out.push_str(&formatted);
            out.push_str(&raw_source[val_span.end as usize..]);
            return Ok(out);
        }

        if props.len() == 1 {
            let mut out = String::with_capacity(raw_source.len());
            out.push_str(&raw_source[..obj_start]);
            out.push_str("{}");
            out.push_str(&raw_source[obj_end..]);
            return Ok(out);
        }

        let (remove_start, remove_end) = if idx + 1 < props.len() {
            (prop_span.start as usize, props[idx + 1].1.start as usize)
        } else {
            let prev_end = props[idx - 1].1.end as usize;
            let mut end = prop_span.end as usize;
            let after = &raw_source[end..obj_end];
            if let Some(stripped) = after.trim_start().strip_prefix(',') {
                end = obj_end - stripped.len();
            }
            (prev_end, end)
        };

        let mut out = String::with_capacity(raw_source.len());
        out.push_str(&raw_source[..remove_start]);
        out.push_str(&raw_source[remove_end..]);
        return Ok(out);
    }

    let Some(val) = new_val else {
        return Ok(raw_source.to_string());
    };

    if props.is_empty() {
        let obj_indent = line_indent_at(raw_source, obj_start);
        let prop_indent = format!("{obj_indent}  ");
        let formatted = format_value_with_indent(val, &prop_indent)?;
        let replacement =
            format!("{{\n{prop_indent}\"{managed_key}\": {formatted}\n{obj_indent}}}");
        let mut out = String::with_capacity(raw_source.len() + replacement.len());
        out.push_str(&raw_source[..obj_start]);
        out.push_str(&replacement);
        out.push_str(&raw_source[obj_end..]);
        return Ok(out);
    }

    let last_prop_span = props[props.len() - 1].1;
    let prop_indent = line_indent_at(raw_source, last_prop_span.start as usize);
    let formatted = format_value_with_indent(val, &prop_indent)?;
    let tail = &raw_source[last_prop_span.end as usize..obj_end];
    let mut out = String::with_capacity(raw_source.len() + formatted.len() + 32);
    if let Some(comma_rel) = tail.find(',')
        && tail[..comma_rel].chars().all(char::is_whitespace)
    {
        let insert_at = last_prop_span.end as usize + comma_rel + 1;
        out.push_str(&raw_source[..insert_at]);
        out.push_str(&format!("\n{prop_indent}\"{managed_key}\": {formatted},"));
        out.push_str(&raw_source[insert_at..]);
    } else {
        let insert_at = last_prop_span.end as usize;
        out.push_str(&raw_source[..insert_at]);
        out.push_str(&format!(",\n{prop_indent}\"{managed_key}\": {formatted}"));
        out.push_str(&raw_source[insert_at..]);
    }
    Ok(out)
}

fn line_indent_at(source: &str, byte_pos: usize) -> String {
    let prefix = &source[..byte_pos.min(source.len())];
    let line_start = prefix.rfind('\n').map_or(0, |idx| idx + 1);
    source[line_start..byte_pos.min(source.len())]
        .chars()
        .take_while(|&c| c == ' ' || c == '\t')
        .collect()
}

fn format_value_with_indent(val: &Value, base_indent: &str) -> Result<String, String> {
    let pretty = serde_json::to_string_pretty(val).map_err(|e| e.to_string())?;
    let mut lines = pretty.lines();
    let Some(first) = lines.next() else {
        return Ok(String::new());
    };
    let mut out = first.to_string();
    for line in lines {
        out.push('\n');
        out.push_str(base_indent);
        out.push_str(line);
    }
    Ok(out)
}

fn extract_config_value_from_module(path: &Path, source: &str) -> Result<Value, String> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();

    let mut bindings: HashMap<&str, &Expression<'_>> = HashMap::new();
    for stmt in &parsed.program.body {
        match stmt {
            Statement::VariableDeclaration(v) => collect_var_decl_bindings(v, &mut bindings),
            Statement::ExportDeclaration(exp) => {
                if let Declaration::VariableDeclaration(v) = &exp.declaration {
                    collect_var_decl_bindings(v, &mut bindings);
                }
            }
            _ => {}
        }
    }
    for stmt in &parsed.program.body {
        match stmt {
            Statement::ExportDefaultDeclaration(exp) => match &exp.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(_)
                | ExportDefaultDeclarationKind::ClassDeclaration(_)
                | ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => {}
                expr_kind => {
                    if let Some(expr) = expr_kind.as_expression()
                        && let Some(val) = eval_config_expr(expr, &bindings)
                    {
                        return Ok(val);
                    }
                }
            },
            Statement::ExpressionStatement(expr_stmt) => {
                if let Expression::AssignmentExpression(assign) =
                    unwrap_ts_expr(&expr_stmt.expression)
                    && is_module_exports_target(&assign.left)
                    && let Some(val) = eval_config_expr(&assign.right, &bindings)
                {
                    return Ok(val);
                }
            }
            _ => {}
        }
    }
    Err(format!(
        "No static configuration object export found in {}",
        path.display()
    ))
}

fn collect_var_decl_bindings<'a>(
    var_decl: &'a oxc_ast::ast::VariableDeclaration<'a>,
    bindings: &mut HashMap<&'a str, &'a Expression<'a>>,
) {
    for decl in &var_decl.declarations {
        if let Some(ident) = decl.id.get_binding_identifier()
            && let Some(init) = &decl.init
        {
            bindings.insert(ident.name.as_str(), init);
        }
    }
}

fn is_module_exports_target(target: &AssignmentTarget<'_>) -> bool {
    let Some(member) = target.as_member_expression() else {
        return false;
    };
    let Some(prop_name) = member.static_property_name() else {
        return false;
    };
    matches!(
        unwrap_ts_expr(member.object()),
        Expression::Identifier(obj)
            if (obj.name == "module" && prop_name == "exports")
                || (obj.name == "exports" && prop_name == "default")
    )
}

fn unwrap_ts_expr<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(e) => expr = &e.expression,
            Expression::TSSatisfiesExpression(e) => expr = &e.expression,
            Expression::TSNonNullExpression(e) => expr = &e.expression,
            Expression::TSTypeAssertion(e) => expr = &e.expression,
            _ => return expr,
        }
    }
}

fn eval_config_expr<'a>(
    expr: &Expression<'a>,
    bindings: &HashMap<&str, &Expression<'a>>,
) -> Option<Value> {
    match unwrap_ts_expr(expr) {
        Expression::ObjectExpression(obj) => {
            let mut map = serde_json::Map::new();
            for prop_kind in &obj.properties {
                if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind {
                    let key = match &prop.key {
                        PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                        PropertyKey::StringLiteral(s) => s.value.as_str()?.to_string(),
                        _ => return None,
                    };
                    map.insert(key, eval_config_expr(&prop.value, bindings)?);
                }
            }
            Some(Value::Object(map))
        }
        Expression::ArrayExpression(arr) => Some(Value::Array(
            arr.elements
                .iter()
                .filter_map(|el| match el {
                    ArrayExpressionElement::SpreadElement(_)
                    | ArrayExpressionElement::Elision(_) => None,
                    _ => eval_config_expr(el.as_expression()?, bindings),
                })
                .collect(),
        )),
        Expression::StringLiteral(s) => Some(Value::String(s.value.as_str()?.to_string())),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => Some(Value::String(
            tpl.quasis.iter().map(|q| q.value.raw.as_str()).collect(),
        )),
        Expression::BooleanLiteral(b) => Some(Value::Bool(b.value)),
        Expression::NumericLiteral(n) => serde_json::Number::from_f64(n.value).map(Value::Number),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            let Expression::NumericLiteral(n) = unwrap_ts_expr(&u.argument) else {
                return None;
            };
            serde_json::Number::from_f64(-n.value).map(Value::Number)
        }
        Expression::NullLiteral(_) => Some(Value::Null),
        Expression::CallExpression(call) => {
            eval_config_expr(call.arguments.first()?.as_expression()?, bindings)
        }
        Expression::Identifier(ident) => {
            if ident.name == "undefined" {
                return Some(Value::Null);
            }
            eval_config_expr(bindings.get(ident.name.as_str())?, bindings)
        }
        _ => None,
    }
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
    match (pat.first(), cand.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            glob_segments_match(&pat[1..], cand)
                || (!cand.is_empty() && glob_segments_match(pat, &cand[1..]))
        }
        (Some(p), Some(c)) if segment_wildcard_match(p, c) => {
            glob_segments_match(&pat[1..], &cand[1..])
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
