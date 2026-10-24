//! In-place configuration mutator (`dotore rules set | enable | disable | category | ignore-tag | unignore-tag`).

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::rules::{RuleCategory, RuleId, RuleSeverityOverride, RuleTag};

use super::{
    loader::{
        CONFIG_EXTENSIONS, ConfigCursor, DotoreConfig, ParsedObject, parse_exported_module_object,
    },
    workspace::normalize_path_buf,
};

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
    let parsed_obj = if is_json_file {
        let mut cursor = ConfigCursor::new(raw_source, HashMap::new());
        cursor.skip_ws_and_comments();
        cursor.parse_object()?
    } else {
        parse_exported_module_object(raw_source)?
    };

    let mut config_map = parsed_obj.map.clone();
    let changed = apply_mutation_to_config_map(&mut config_map, mutation);
    if !changed {
        return Ok((raw_source.to_string(), false));
    }

    let managed_key = mutation_managed_key(mutation);
    let updated = splice_object_property_in_source(
        raw_source,
        &parsed_obj,
        managed_key,
        config_map.get(managed_key),
    )?;
    Ok((updated, true))
}

fn mutate_package_json_dotore(
    raw_source: &str,
    mutation: ConfigMutation,
) -> Result<(String, bool), String> {
    let mut cursor = ConfigCursor::new(raw_source, HashMap::new());
    cursor.skip_ws_and_comments();
    let root_obj = cursor
        .parse_object()
        .map_err(|_| "package.json root is not a JSON object".to_string())?;

    let Some((_, _, dotore_val_span)) = root_obj.properties.iter().find(|(k, _, _)| k == "dotore")
    else {
        return Err("package.json does not contain a static \"dotore\" object".to_string());
    };

    let mut inner_cursor =
        ConfigCursor::with_pos(raw_source, dotore_val_span.start as usize, HashMap::new());
    inner_cursor.skip_ws_and_comments();
    let dotore_obj = inner_cursor
        .parse_object()
        .map_err(|_| "Failed to evaluate package.json#dotore object".to_string())?;

    let mut config_map = dotore_obj.map.clone();
    let changed = apply_mutation_to_config_map(&mut config_map, mutation);
    if !changed {
        return Ok((raw_source.to_string(), false));
    }
    let managed_key = mutation_managed_key(mutation);
    let updated = splice_object_property_in_source(
        raw_source,
        &dotore_obj,
        managed_key,
        config_map.get(managed_key),
    )?;
    Ok((updated, true))
}

fn splice_object_property_in_source(
    raw_source: &str,
    obj: &ParsedObject,
    managed_key: &str,
    new_val: Option<&Value>,
) -> Result<String, String> {
    let obj_start = obj.span.start as usize;
    let obj_end = obj.span.end as usize;
    let props = &obj.properties;

    if let Some((idx, (_, prop_span, val_span))) = props
        .iter()
        .enumerate()
        .find(|(_, (k, _, _))| k == managed_key)
    {
        if let Some(val) = new_val {
            let prop_indent = line_indent_at(raw_source, prop_span.start as usize);
            let formatted = format_value_with_indent(val, &prop_indent)?;
            let mut out = String::with_capacity(raw_source.len() + formatted.len());
            out.push_str(raw_source.get(..val_span.start as usize).unwrap_or_default());
            out.push_str(&formatted);
            out.push_str(raw_source.get(val_span.end as usize..).unwrap_or_default());
            return Ok(out);
        }

        if props.len() == 1 {
            let mut out = String::with_capacity(raw_source.len());
            out.push_str(raw_source.get(..obj_start).unwrap_or_default());
            out.push_str("{}");
            out.push_str(raw_source.get(obj_end..).unwrap_or_default());
            return Ok(out);
        }

        let (remove_start, remove_end) = if idx + 1 < props.len() {
            (prop_span.start as usize, props[idx + 1].1.start as usize)
        } else {
            let prev_end = props
                .get(idx.saturating_sub(1))
                .map_or(prop_span.start as usize, |p| p.1.end as usize);
            let mut end = prop_span.end as usize;
            let after = raw_source.get(end..obj_end).unwrap_or_default();
            if let Some(stripped) = after.trim_start().strip_prefix(',') {
                end = obj_end - stripped.len();
            }
            (prev_end, end)
        };

        let mut out = String::with_capacity(raw_source.len());
        out.push_str(raw_source.get(..remove_start).unwrap_or_default());
        out.push_str(raw_source.get(remove_end..).unwrap_or_default());
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
        out.push_str(raw_source.get(..obj_start).unwrap_or_default());
        out.push_str(&replacement);
        out.push_str(raw_source.get(obj_end..).unwrap_or_default());
        return Ok(out);
    }

    let Some(last_prop) = props.last() else {
        return Ok(raw_source.to_string());
    };
    let last_prop_span = last_prop.1;
    let prop_indent = line_indent_at(raw_source, last_prop_span.start as usize);
    let formatted = format_value_with_indent(val, &prop_indent)?;
    let tail = raw_source
        .get(last_prop_span.end as usize..obj_end)
        .unwrap_or_default();
    let mut out = String::with_capacity(raw_source.len() + formatted.len() + 32);
    if let Some(comma_rel) = tail.find(',')
        && tail[..comma_rel].chars().all(char::is_whitespace)
    {
        let insert_at = last_prop_span.end as usize + comma_rel + 1;
        out.push_str(raw_source.get(..insert_at).unwrap_or_default());
        out.push_str(&format!("\n{prop_indent}\"{managed_key}\": {formatted},"));
        out.push_str(raw_source.get(insert_at..).unwrap_or_default());
    } else {
        let insert_at = last_prop_span.end as usize;
        out.push_str(raw_source.get(..insert_at).unwrap_or_default());
        out.push_str(&format!(",\n{prop_indent}\"{managed_key}\": {formatted}"));
        out.push_str(raw_source.get(insert_at..).unwrap_or_default());
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
