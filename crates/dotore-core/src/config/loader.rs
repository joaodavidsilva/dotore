//! User configuration loader for `dotore.config.*` (TS, JS, MJS, CJS, JSON, JSONC)
//! and the `"dotore"` key in `package.json`.

use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    ir::ByteSpan,
    rules::{RuleCategory, RuleId, RuleSeverity, RuleSeverityOverride, RuleTag},
};

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
    fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|c| DotoreConfig::from_package_json_str(&c))
}

#[derive(Debug, Clone)]
pub(super) struct ParsedObject {
    pub(super) span: ByteSpan,
    pub(super) properties: Vec<(String, ByteSpan, ByteSpan)>,
    pub(super) map: Map<String, Value>,
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

pub(super) fn parse_exported_module_object(source: &str) -> Result<ParsedObject, String> {
    let mut bindings: HashMap<String, usize> = HashMap::new();
    let mut export_expr_starts: Vec<usize> = Vec::new();

    let mut scanner = ConfigCursor::new(source, HashMap::new());
    while scanner.pos < source.len() {
        scanner.skip_ws_and_comments();
        if scanner.pos >= source.len() {
            break;
        }
        if scanner.consume_keyword("import") {
            scanner.skip_statement();
            continue;
        }
        let is_export = scanner.consume_keyword("export");
        scanner.skip_ws_and_comments();
        if is_export && scanner.consume_keyword("default") {
            scanner.skip_ws_and_comments();
            if scanner.peek_keyword("function")
                || scanner.peek_keyword("class")
                || scanner.peek_keyword("interface")
            {
                return Err(
                    "Could not statically edit configuration object (dynamic config export)"
                        .to_string(),
                );
            }
            export_expr_starts.push(scanner.pos);
            scanner.skip_statement();
            continue;
        }
        if scanner.consume_keyword("const")
            || scanner.consume_keyword("let")
            || scanner.consume_keyword("var")
        {
            scanner.skip_ws_and_comments();
            if let Some(ident) = scanner.parse_identifier() {
                scanner.skip_ws_and_comments();
                if scanner.peek_byte() == Some(b':') {
                    scanner.pos += 1;
                    scanner.skip_type_annotation_before_eq();
                }
                scanner.skip_ws_and_comments();
                if scanner.peek_byte() == Some(b'=') {
                    scanner.pos += 1;
                    scanner.skip_ws_and_comments();
                    bindings.insert(ident, scanner.pos);
                }
            }
            scanner.skip_statement();
            continue;
        }
        if let Some(rhs_pos) = scanner.try_consume_cjs_exports_assignment() {
            export_expr_starts.push(rhs_pos);
            scanner.skip_statement();
            continue;
        }
        scanner.advance_token_or_char();
    }

    for start_pos in export_expr_starts {
        let mut eval_cursor = ConfigCursor::with_pos(source, start_pos, bindings.clone());
        if let Ok(obj) = eval_cursor.resolve_to_object(0) {
            return Ok(obj);
        }
    }

    Err("Could not statically edit configuration object (dynamic config export)".to_string())
}

pub(super) struct ConfigCursor<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    bindings: HashMap<String, usize>,
}

impl<'a> ConfigCursor<'a> {
    pub(super) const fn new(src: &'a str, bindings: HashMap<String, usize>) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            bindings,
        }
    }

    pub(super) const fn with_pos(
        src: &'a str,
        pos: usize,
        bindings: HashMap<String, usize>,
    ) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos,
            bindings,
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub(super) fn skip_ws_and_comments(&mut self) {
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_whitespace() {
                self.pos += 1;
                continue;
            }
            if b == b'/' && self.bytes.get(self.pos + 1) == Some(&b'/') {
                self.pos += 2;
                while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                    self.pos += 1;
                }
                continue;
            }
            if b == b'/' && self.bytes.get(self.pos + 1) == Some(&b'*') {
                self.pos += 2;
                while self.pos + 1 < self.bytes.len()
                    && !(self.bytes[self.pos] == b'*' && self.bytes[self.pos + 1] == b'/')
                {
                    self.pos += 1;
                }
                self.pos = (self.pos + 2).min(self.bytes.len());
                continue;
            }
            break;
        }
    }

    fn peek_keyword(&self, kw: &str) -> bool {
        let kw_bytes = kw.as_bytes();
        if self.pos + kw_bytes.len() > self.bytes.len() {
            return false;
        }
        if &self.bytes[self.pos..self.pos + kw_bytes.len()] != kw_bytes {
            return false;
        }
        let next = self.bytes.get(self.pos + kw_bytes.len()).copied();
        !next.is_some_and(is_ident_continue)
    }

    fn consume_keyword(&mut self, kw: &str) -> bool {
        if self.peek_keyword(kw) {
            self.pos += kw.len();
            true
        } else {
            false
        }
    }

    fn parse_identifier(&mut self) -> Option<String> {
        self.skip_ws_and_comments();
        let first = self.peek_byte()?;
        if !is_ident_start(first) {
            return None;
        }
        let start = self.pos;
        self.pos += 1;
        while let Some(b) = self.peek_byte() {
            if is_ident_continue(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.src.get(start..self.pos).map(str::to_string)
    }

    fn try_consume_cjs_exports_assignment(&mut self) -> Option<usize> {
        let save = self.pos;
        let first = self.parse_identifier()?;
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'.') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        let second = self.parse_identifier()?;
        let valid_target = (first == "module" && second == "exports")
            || (first == "exports" && second == "default");
        if !valid_target {
            self.pos = save;
            return None;
        }
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'=') || self.bytes.get(self.pos + 1) == Some(&b'=') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        self.skip_ws_and_comments();
        Some(self.pos)
    }

    fn skip_type_annotation_before_eq(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            if depth == 0 && b == b'=' {
                break;
            }
            match b {
                b'<' | b'(' | b'[' | b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'>' | b')' | b']' | b'}' => {
                    depth = (depth - 1).max(0);
                    self.pos += 1;
                }
                b'\'' | b'"' | b'`' => {
                    let _ = self.parse_string_literal();
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    fn skip_statement(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            match b {
                b'{' | b'(' | b'[' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'}' | b')' | b']' => {
                    depth -= 1;
                    self.pos += 1;
                    if depth <= 0 && b == b'}' {
                        self.consume_optional_semicolon();
                        break;
                    }
                }
                b';' if depth <= 0 => {
                    self.pos += 1;
                    break;
                }
                b'\'' | b'"' | b'`' => {
                    let _ = self.parse_string_literal();
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    fn consume_optional_semicolon(&mut self) {
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b';') {
            self.pos += 1;
        }
    }

    fn advance_token_or_char(&mut self) {
        self.skip_ws_and_comments();
        let Some(b) = self.peek_byte() else {
            return;
        };
        if matches!(b, b'\'' | b'"' | b'`') {
            if self.parse_string_literal().is_err() {
                self.pos += 1;
            }
            return;
        }
        if let Some(ch) = self.src[self.pos..].chars().next() {
            self.pos += ch.len_utf8();
        } else {
            self.pos += 1;
        }
    }

    fn resolve_to_object(&mut self, depth: usize) -> Result<ParsedObject, String> {
        if depth > 16 {
            return Err("Config reference recursion limit exceeded".to_string());
        }
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b'<') {
            self.skip_angle_bracket_type_assertion();
            self.skip_ws_and_comments();
        }
        match self.peek_byte() {
            Some(b'(') => {
                self.pos += 1;
                let obj = self.resolve_to_object(depth + 1)?;
                self.skip_ts_postfix_assertions();
                if self.peek_byte() == Some(b')') {
                    self.pos += 1;
                }
                self.skip_ts_postfix_assertions();
                Ok(obj)
            }
            Some(b'{') => {
                let obj = self.parse_object()?;
                self.skip_ts_postfix_assertions();
                Ok(obj)
            }
            _ => {
                let ident = self
                    .parse_identifier()
                    .ok_or_else(|| "Expected object or config helper".to_string())?;
                self.skip_ws_and_comments();
                if self.peek_byte() == Some(b'<') {
                    self.skip_angle_bracket_type_assertion();
                    self.skip_ws_and_comments();
                }
                if self.peek_byte() == Some(b'(') {
                    self.pos += 1;
                    let obj = self.resolve_to_object(depth + 1)?;
                    self.skip_ts_postfix_assertions();
                    if self.peek_byte() == Some(b')') {
                        self.pos += 1;
                    }
                    self.skip_ts_postfix_assertions();
                    return Ok(obj);
                }
                let target_pos = *self
                    .bindings
                    .get(&ident)
                    .ok_or_else(|| format!("Unresolved config identifier {ident}"))?;
                let mut sub = ConfigCursor::with_pos(self.src, target_pos, self.bindings.clone());
                sub.resolve_to_object(depth + 1)
            }
        }
    }

    pub(super) fn parse_object(&mut self) -> Result<ParsedObject, String> {
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'{') {
            return Err("Expected '{'".to_string());
        }
        let obj_start = u32::try_from(self.pos).unwrap_or(0);
        self.pos += 1;

        let mut properties = Vec::new();
        let mut map = Map::new();

        loop {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                return Err("Unterminated object literal".to_string());
            };
            if b == b'}' {
                self.pos += 1;
                let obj_end = u32::try_from(self.pos).unwrap_or(obj_start);
                return Ok(ParsedObject {
                    span: ByteSpan {
                        start: obj_start,
                        end: obj_end,
                    },
                    properties,
                    map,
                });
            }
            if b == b',' {
                self.pos += 1;
                continue;
            }

            let prop_start = u32::try_from(self.pos).unwrap_or(0);
            let key = if b == b'\'' || b == b'"' {
                self.parse_string_literal()?
            } else {
                self.parse_identifier()
                    .ok_or_else(|| "Unsupported dynamic or spread object property".to_string())?
            };

            self.skip_ws_and_comments();
            if self.peek_byte() != Some(b':') {
                return Err("Expected ':' after object property key".to_string());
            }
            self.pos += 1;
            self.skip_ws_and_comments();

            let val_start = u32::try_from(self.pos).unwrap_or(0);
            let val = self.parse_value_expr(0)?;
            let val_end = u32::try_from(self.pos).unwrap_or(val_start);
            self.skip_ts_postfix_assertions();
            let prop_end = u32::try_from(self.pos).unwrap_or(val_end);

            properties.push((
                key.clone(),
                ByteSpan {
                    start: prop_start,
                    end: prop_end,
                },
                ByteSpan {
                    start: val_start,
                    end: val_end,
                },
            ));
            map.insert(key, val);

            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b',') {
                self.pos += 1;
            }
        }
    }

    fn parse_value_expr(&mut self, depth: usize) -> Result<Value, String> {
        if depth > 24 {
            return Err("Config expression nesting limit exceeded".to_string());
        }
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b'<') {
            self.skip_angle_bracket_type_assertion();
            self.skip_ws_and_comments();
        }
        let Some(b) = self.peek_byte() else {
            return Err("Unexpected end of config expression".to_string());
        };
        match b {
            b'{' => {
                let obj = self.parse_object()?;
                Ok(Value::Object(obj.map))
            }
            b'[' => self.parse_array(depth + 1),
            b'\'' | b'"' | b'`' => self.parse_string_literal().map(Value::String),
            b'(' => {
                self.pos += 1;
                let v = self.parse_value_expr(depth + 1)?;
                self.skip_ts_postfix_assertions();
                if self.peek_byte() == Some(b')') {
                    self.pos += 1;
                }
                Ok(v)
            }
            b'-' | b'0'..=b'9' => self.parse_number_literal(),
            _ => self.parse_ident_or_call_expr(depth),
        }
    }

    fn parse_ident_or_call_expr(&mut self, depth: usize) -> Result<Value, String> {
        let ident = self
            .parse_identifier()
            .ok_or_else(|| "Unsupported config expression".to_string())?;
        match ident.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            "null" | "undefined" => Ok(Value::Null),
            _ => {
                self.skip_ws_and_comments();
                if self.peek_byte() == Some(b'<') {
                    self.skip_angle_bracket_type_assertion();
                    self.skip_ws_and_comments();
                }
                if self.peek_byte() == Some(b'(') {
                    self.pos += 1;
                    let v = self.parse_value_expr(depth + 1)?;
                    self.skip_ts_postfix_assertions();
                    if self.peek_byte() == Some(b')') {
                        self.pos += 1;
                    }
                    return Ok(v);
                }
                let target_pos = *self
                    .bindings
                    .get(&ident)
                    .ok_or_else(|| format!("Unresolved identifier {ident}"))?;
                let mut sub = ConfigCursor::with_pos(self.src, target_pos, self.bindings.clone());
                sub.parse_value_expr(depth + 1)
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                return Err("Unterminated array literal".to_string());
            };
            if b == b']' {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            if b == b',' {
                self.pos += 1;
                continue;
            }
            let item = self.parse_value_expr(depth)?;
            self.skip_ts_postfix_assertions();
            items.push(item);
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b',') {
                self.pos += 1;
            }
        }
    }

    fn parse_string_literal(&mut self) -> Result<String, String> {
        let quote = self.peek_byte().ok_or("Expected string quote")?;
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == quote {
                self.pos += 1;
                return Ok(out);
            }
            if quote == b'`' && b == b'$' && self.bytes.get(self.pos + 1) == Some(&b'{') {
                return Err("Dynamic template literal interpolation in config".to_string());
            }
            if b == b'\\' {
                self.pos += 1;
                let Some(esc) = self.peek_byte() else {
                    break;
                };
                self.pos += 1;
                match esc {
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'\\' => out.push('\\'),
                    b'\'' => out.push('\''),
                    b'"' => out.push('"'),
                    b'`' => out.push('`'),
                    other => out.push(other as char),
                }
                continue;
            }
            if let Some(ch) = self.src[self.pos..].chars().next() {
                out.push(ch);
                self.pos += ch.len_utf8();
            } else {
                self.pos += 1;
            }
        }
        Err("Unterminated string literal".to_string())
    }

    fn parse_number_literal(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek_byte() == Some(b'-') {
            self.pos += 1;
            self.skip_ws_and_comments();
        }
        let num_start = self.pos;
        while let Some(b) = self.peek_byte() {
            if b.is_ascii_digit() || b == b'.' || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == num_start {
            return Err("Invalid numeric literal".to_string());
        }
        let raw = self.src[start..self.pos].replace(['_', ' '], "");
        let parsed = raw
            .parse::<f64>()
            .map_err(|e| format!("Invalid number {raw}: {e}"))?;
        serde_json::Number::from_f64(parsed)
            .map(Value::Number)
            .ok_or_else(|| "Non-finite number in config".to_string())
    }

    fn skip_angle_bracket_type_assertion(&mut self) {
        if self.peek_byte() != Some(b'<') {
            return;
        }
        let mut depth = 0_i32;
        while let Some(b) = self.peek_byte() {
            self.pos += 1;
            if b == b'<' {
                depth += 1;
            } else if b == b'>' {
                depth -= 1;
                if depth <= 0 {
                    break;
                }
            }
        }
    }

    fn skip_ts_postfix_assertions(&mut self) {
        loop {
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b'!') {
                self.pos += 1;
                continue;
            }
            if self.consume_keyword("as") || self.consume_keyword("satisfies") {
                self.skip_ts_type_until_delimiter();
                continue;
            }
            break;
        }
    }

    fn skip_ts_type_until_delimiter(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            if depth == 0 && matches!(b, b',' | b'}' | b']' | b')' | b';') {
                break;
            }
            match b {
                b'<' | b'(' | b'[' | b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'>' | b')' | b']' | b'}' => {
                    depth = (depth - 1).max(0);
                    self.pos += 1;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }
}

const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

const fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
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
