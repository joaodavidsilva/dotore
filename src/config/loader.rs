//! User configuration loader for `dotore.config.*` (TS, JS, MJS, CJS, JSON, JSONC)
//! and the `"dotore"` key in `package.json`.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast expression and statement enums have dozens of variants; config AST evaluation matches only literal/object/export forms"
)]

use std::{collections::HashMap, fs, path::Path};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpressionElement, AssignmentTarget, Declaration, ExportDefaultDeclarationKind,
    Expression, ObjectPropertyKind, PropertyKey, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
