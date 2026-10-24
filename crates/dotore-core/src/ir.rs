//! Language-agnostic intermediate representation (`SourceLoc`, `ByteSpan`, `FileContext`,
//! `SymbolKind`, `SymbolOutline`, `FileSuppressions`, `ContextualOwnerSpansIr`,
//! `ResolvedCallerSite`, `ExtractedFile`, `PackageAnalysisResult`, and `LanguageAnalyzer`).

use std::{
    any::Any,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{CapabilityGate, WorkspacePackage},
    rules::{Diagnostic, RuleId},
};

/// 1-based line and column in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLoc {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (UTF-8 byte offset on line + 1).
    pub column: u32,
}

/// 0-based byte span `[start, end)` in a source file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    /// Inclusive start byte offset.
    pub start: u32,
    /// Exclusive end byte offset.
    pub end: u32,
}

/// Classification of a source file relative to production code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileContext {
    /// Production application or library code.
    Production,
    /// Test or fixture file (`.test.*`, `.spec.*`, `test_*.py`, `*_test.py`, `__tests__/`, `tests/`, `benches/`).
    Test,
    /// Storybook story file (`.stories.*`, `.story.*`).
    Story,
}

/// Classifies a file path into [`FileContext::Production`], [`FileContext::Test`], or [`FileContext::Story`].
#[must_use]
pub fn classify_file_context(path: &Path) -> FileContext {
    let raw = path.to_string_lossy().replace('\\', "/");
    let file_name = raw.rsplit('/').next().unwrap_or(raw.as_str());

    if is_story_file_name(file_name) {
        return FileContext::Story;
    }
    if is_test_file_name(file_name) {
        return FileContext::Test;
    }

    // Strip above fixture roots (`/fixtures/` or `/__fixtures__/`) so fixture app files
    // inside a test harness directory are classified by their inner path.
    let scoped = strip_above_fixture_root(&raw);
    for seg in scoped
        .split('/')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .skip(1)
    {
        if matches!(
            seg,
            "__tests__"
                | "__test__"
                | "tests"
                | "test"
                | "__mocks__"
                | "cypress"
                | "e2e"
                | "playwright"
                | "benches"
        ) {
            return FileContext::Test;
        }
    }

    FileContext::Production
}

fn is_story_file_name(file_name: &str) -> bool {
    let Some(stem) = strip_js_ts_ext(file_name) else {
        return false;
    };
    stem.ends_with(".stories") || stem.ends_with(".story")
}

fn is_test_file_name(file_name: &str) -> bool {
    if let Some(stem) = strip_js_ts_ext(file_name) {
        return stem.ends_with(".test")
            || stem.ends_with(".spec")
            || stem.ends_with(".fixture")
            || stem.ends_with(".fixtures");
    }
    if let Some(py_stem) = file_name
        .strip_suffix(".py")
        .or_else(|| file_name.strip_suffix(".pyi"))
    {
        return py_stem == "conftest" || py_stem.starts_with("test_") || py_stem.ends_with("_test");
    }
    false
}

fn strip_js_ts_ext(file_name: &str) -> Option<&str> {
    for ext in [".tsx", ".ts", ".jsx", ".js", ".mts", ".mjs", ".cts", ".cjs"] {
        if let Some(stem) = file_name.strip_suffix(ext) {
            return Some(stem);
        }
    }
    None
}

fn strip_above_fixture_root(forward_slashed: &str) -> &str {
    for marker in ["/fixtures/", "/__fixtures__/"] {
        if let Some(pos) = forward_slashed.rfind(marker) {
            let after = &forward_slashed[pos + marker.len()..];
            for src_root in ["/src/", "/app/", "/lib/", "/packages/", "/apps/"] {
                if let Some(src_pos) = after.rfind(src_root) {
                    return &after[src_pos + 1..];
                }
            }
            return after;
        }
    }
    forward_slashed
}

/// Kind of **Symbol Outline** extracted for fuzzy symbol search (`dotore search`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    /// Function or React **Subject** declaration.
    Function,
    /// Class or struct declaration.
    Class,
    /// TypeScript interface or Rust trait declaration.
    Interface,
    /// TypeScript or Rust type alias declaration.
    Type,
    /// Enum declaration.
    Enum,
    /// Enum member or variant.
    EnumMember,
    /// `const` or `static` declaration.
    Constant,
    /// `let` or `var` declaration.
    Variable,
    /// Class, object, trait, or `impl` method.
    Method,
    /// Class, struct, or interface property/field.
    Property,
    /// Module export entry.
    Export,
    /// Module import binding.
    Import,
}

#[expect(
    non_upper_case_globals,
    reason = "Rust struct and trait symbols map into Class and Interface outlines for unified search"
)]
impl SymbolKind {
    /// Alias for [`SymbolKind::Class`] used by Rust `struct` items.
    pub const Struct: Self = Self::Class;
    /// Alias for [`SymbolKind::Interface`] used by Rust `trait` items.
    pub const Trait: Self = Self::Interface;

    /// All 12 supported symbol kinds in canonical alphabetical order.
    pub const ALL: &'static [Self] = &[
        Self::Class,
        Self::Constant,
        Self::Enum,
        Self::EnumMember,
        Self::Export,
        Self::Function,
        Self::Import,
        Self::Interface,
        Self::Method,
        Self::Property,
        Self::Type,
        Self::Variable,
    ];

    /// Default symbol kinds queried by `dotore search` when `--kind` is omitted.
    pub const DEFAULT_SEARCH_KINDS: &'static [Self] = &[
        Self::Class,
        Self::Enum,
        Self::Function,
        Self::Interface,
        Self::Method,
        Self::Property,
        Self::Type,
    ];

    /// Parses a kebab-case symbol kind identifier.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "class" | "struct" => Some(Self::Class),
            "constant" | "const" => Some(Self::Constant),
            "enum" => Some(Self::Enum),
            "enum-member" => Some(Self::EnumMember),
            "export" => Some(Self::Export),
            "function" | "fn" => Some(Self::Function),
            "import" => Some(Self::Import),
            "interface" | "trait" => Some(Self::Interface),
            "method" => Some(Self::Method),
            "property" | "field" => Some(Self::Property),
            "type" => Some(Self::Type),
            "variable" | "var" => Some(Self::Variable),
            _ => None,
        }
    }

    /// Returns the canonical kebab-case string for this symbol kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Constant => "constant",
            Self::Enum => "enum",
            Self::EnumMember => "enum-member",
            Self::Export => "export",
            Self::Function => "function",
            Self::Import => "import",
            Self::Interface => "interface",
            Self::Method => "method",
            Self::Property => "property",
            Self::Type => "type",
            Self::Variable => "variable",
        }
    }
}

/// A declared symbol extracted with its signature and adjacent doc comment (see `GLOSSARY.md`: **Symbol Outline**).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolOutline {
    /// Symbol identifier name.
    pub name: String,
    /// Symbol kind (`Function`, `Class`, `Interface`, `Type`, `Enum`, `Constant`, etc.).
    pub kind: SymbolKind,
    /// Compact declaration signature header.
    pub signature: String,
    /// Adjacent leading comment text, if any.
    pub doc_comment: Option<String>,
    /// 1-based start line of the adjacent leading comment block, if any.
    pub comment_start_line: Option<u32>,
    /// Enclosing class, interface, enum, function, or object container name for members/nested symbols.
    pub parent_name: Option<String>,
    /// Whether the symbol is exported from the module.
    pub exported: bool,
    /// Byte span of the declaration.
    pub span: ByteSpan,
    /// 1-based line where the declaration signature header ends.
    pub signature_end_line: u32,
    /// 1-based start line and column of the symbol identifier.
    pub loc: SourceLoc,
    /// 1-based inclusive end line of the declaration.
    pub end_line: u32,
}

impl SymbolOutline {
    /// Creates a new [`SymbolOutline`] with `exported: false`, no doc comment, no parent name,
    /// and `signature_end_line` defaulted to `loc.line`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: SymbolKind,
        signature: impl Into<String>,
        span: ByteSpan,
        loc: SourceLoc,
        end_line: u32,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            signature: signature.into(),
            doc_comment: None,
            comment_start_line: None,
            parent_name: None,
            exported: false,
            span,
            signature_end_line: loc.line,
            loc,
            end_line,
        }
    }

    /// Sets whether this symbol is exported from its module.
    #[must_use]
    pub const fn with_exported(mut self, exported: bool) -> Self {
        self.exported = exported;
        self
    }

    /// Sets the optional enclosing container name (`Some(...)` or `None`).
    #[must_use]
    pub fn with_parent(mut self, parent_name: Option<String>) -> Self {
        self.parent_name = parent_name;
        self
    }

    /// Sets the enclosing container name.
    #[must_use]
    pub fn with_parent_name(mut self, parent_name: impl Into<String>) -> Self {
        self.parent_name = Some(parent_name.into());
        self
    }

    /// Attaches an adjacent doc comment and its 1-based start line.
    #[must_use]
    pub fn with_doc_comment(
        mut self,
        doc_comment: Option<String>,
        comment_start_line: Option<u32>,
    ) -> Self {
        self.doc_comment = doc_comment;
        self.comment_start_line = comment_start_line;
        self
    }

    /// Sets the 1-based line where the declaration signature header ends.
    #[must_use]
    pub const fn with_signature_end_line(mut self, signature_end_line: u32) -> Self {
        self.signature_end_line = signature_end_line;
        self
    }
}

/// A single-line inline suppression directive (`// dotore-disable-next-line`, `# dotore-disable-next-line`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineDisableDirective {
    /// 1-based source line number suppressed by this directive.
    pub target_line: u32,
    /// Rule keys listed on the directive (empty suppresses all rules on `target_line`).
    pub rules: Vec<String>,
}

/// A file-level or block-range disable directive (`/* dotore-disable ... */` ... `/* dotore-enable ... */`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockDisableRange {
    /// 1-based inclusive start line of the suppression range.
    pub start_line: u32,
    /// 1-based inclusive end line of the suppression range (`u32::MAX` through end of file).
    pub end_line: u32,
    /// Rule keys listed on the directive (empty suppresses all rules in the range).
    pub rules: Vec<String>,
}

/// Parsed inline suppression directives (`dotore-disable*`, `# noqa`, `#[allow]` / `#[expect]`) for a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileSuppressions {
    /// Line-targeted disable directives (`*-disable-next-line` and `*-disable-line`).
    pub line_directives: Vec<LineDisableDirective>,
    /// File-wide or block-range disable directives (`/* *-disable */`).
    pub block_ranges: Vec<BlockDisableRange>,
}

/// Kind of inline comment suppression directive (`*-disable-next-line`, `*-disable-line`, `*-disable`, `*-enable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionDirectiveKind {
    /// Suppresses the next non-directive code line (`*-disable-next-line` / `*-ignore-next-line`).
    DisableNextLine,
    /// Suppresses the current line (`*-disable-line` / `*-ignore-line` / `# noqa`).
    DisableLine,
    /// Opens a block or file-wide suppression range (`*-disable` / `*-ignore` / `# ruff: noqa`).
    BlockDisable,
    /// Closes open block suppression range(s) (`*-enable`).
    BlockEnable,
}

/// Element with a 1-based start and end line for its opening tag (`<Comp ...>`).
pub trait OpenerLineRange {
    /// 1-based start line of the opening element.
    fn opener_start_line(&self) -> u32;
    /// 1-based end line of the opening element.
    fn opener_end_line(&self) -> u32;
}

impl OpenerLineRange for (u32, u32) {
    fn opener_start_line(&self) -> u32 {
        self.0
    }
    fn opener_end_line(&self) -> u32 {
        self.1
    }
}

/// Subject or function owner span and nested effect spans for inline suppression inheritance.
pub trait SubjectEffectOwner {
    /// Byte span of the subject or function declaration.
    fn subject_span(&self) -> ByteSpan;
    /// 1-based start line of the subject or function declaration.
    fn subject_line(&self) -> u32;
    /// Invokes `f(effect_span, effect_line)` for each nested effect or callback registration.
    fn for_each_effect_span(&self, f: &mut dyn FnMut(ByteSpan, u32));
}

impl SubjectEffectOwner for (ByteSpan, u32) {
    fn subject_span(&self) -> ByteSpan {
        self.0
    }
    fn subject_line(&self) -> u32 {
        self.1
    }
    fn for_each_effect_span(&self, _f: &mut dyn FnMut(ByteSpan, u32)) {}
}

impl FileSuppressions {
    /// Appends a single-line suppression directive for 1-based `target_line`.
    pub fn add_line_disable(&mut self, target_line: u32, rules: Vec<String>) {
        self.line_directives.push(LineDisableDirective {
            target_line,
            rules,
        });
    }

    /// Appends a block or file-wide suppression range `[start_line, end_line]`.
    pub fn add_block_disable(&mut self, start_line: u32, end_line: u32, rules: Vec<String>) {
        self.block_ranges.push(BlockDisableRange {
            start_line,
            end_line,
            rules,
        });
    }

    /// Closes open (`end_line == u32::MAX`) block suppression ranges at 1-based `enable_line`.
    /// When `enable_rules` is non-empty, only matching rules are closed and any remaining rules
    /// on a multi-rule block range continue from `enable_line..=u32::MAX`.
    pub fn close_block_ranges(&mut self, enable_rules: &[String], enable_line: u32) {
        let mut split_additions = Vec::new();
        for range in &mut self.block_ranges {
            if range.end_line != u32::MAX {
                continue;
            }
            if enable_rules.is_empty() {
                range.end_line = enable_line;
                continue;
            }
            if range.rules.is_empty() {
                continue;
            }
            let overlaps = range
                .rules
                .iter()
                .any(|r| rule_token_matches_enable_list(r, enable_rules));
            if overlaps {
                let remaining: Vec<String> = range
                    .rules
                    .iter()
                    .filter(|r| !rule_token_matches_enable_list(r, enable_rules))
                    .cloned()
                    .collect();
                range.end_line = enable_line;
                if !remaining.is_empty() {
                    split_additions.push(BlockDisableRange {
                        start_line: enable_line,
                        end_line: u32::MAX,
                        rules: remaining,
                    });
                }
            }
        }
        self.block_ranges.extend(split_additions);
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` by a line directive or block range.
    #[must_use]
    pub fn matches_line_or_block(&self, rule: RuleId, line: u32) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }
        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `rule` is suppressed at 1-based `target_line` by a line directive.
    #[must_use]
    pub fn matches_line(&self, rule: RuleId, target_line: u32) -> bool {
        self.line_directives
            .iter()
            .any(|d| d.target_line == target_line && rule_list_matches(&d.rules, rule))
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` or `span` (including via an enclosing
    /// `EffectNode`, `SubjectIr`, or multi-line JSX opening element).
    #[must_use]
    pub fn is_suppressed<E: OpenerLineRange, S: SubjectEffectOwner>(
        &self,
        rule: RuleId,
        line: u32,
        span: ByteSpan,
        elements: &[E],
        subjects: &[S],
    ) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }

        for el in elements {
            let opener_start = el.opener_start_line();
            if opener_start < line
                && line <= el.opener_end_line()
                && self.matches_line(rule, opener_start)
            {
                return true;
            }
        }

        for subject in subjects {
            let subj_span = subject.subject_span();
            if subj_span.start <= span.start
                && span.end <= subj_span.end
                && self.matches_line(rule, subject.subject_line())
            {
                return true;
            }
            let mut effect_matched = false;
            subject.for_each_effect_span(&mut |eff_span, eff_line| {
                if !effect_matched
                    && eff_span.start <= span.start
                    && span.end <= eff_span.end
                    && self.matches_line(rule, eff_line)
                {
                    effect_matched = true;
                }
            });
            if effect_matched {
                return true;
            }
        }

        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }

        false
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` or `span`, including via enclosing
    /// multi-line element openers `(opener_start_line, opener_end_line)` or owner `(span, header_line)` pairs.
    #[must_use]
    pub fn is_suppressed_with_owners(
        &self,
        rule: RuleId,
        line: u32,
        span: ByteSpan,
        opener_line_ranges: &[(u32, u32)],
        owner_spans: &[(ByteSpan, u32)],
    ) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }

        for &(opener_start, opener_end) in opener_line_ranges {
            if opener_start < line && line <= opener_end && self.matches_line(rule, opener_start) {
                return true;
            }
        }

        for &(owner_span, owner_line) in owner_spans {
            if owner_span.start <= span.start
                && span.end <= owner_span.end
                && self.matches_line(rule, owner_line)
            {
                return true;
            }
        }

        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }

        false
    }
}

/// Checks whether a parsed rule key list on a suppression directive matches `target`.
#[must_use]
pub fn rule_list_matches(rules: &[String], target: RuleId) -> bool {
    if rules.is_empty() {
        return true;
    }
    rules.iter().any(|token| target.matches_key(token))
}

fn rule_token_matches_enable_list(rule_key: &str, enable_rules: &[String]) -> bool {
    enable_rules.iter().any(|en| {
        rule_key == en || RuleId::parse(rule_key).is_some_and(|rule_id| rule_id.matches_key(en))
    })
}

/// Tokenizes the rule list tail of an inline suppression comment, stripping any trailing
/// `-- explanation` description and splitting on commas and whitespace.
#[must_use]
pub fn tokenize_suppression_rules(raw_tail: &str) -> Vec<String> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let before_desc = if let Some(idx) = trimmed.find(" -- ") {
        &trimmed[..idx]
    } else if trimmed.starts_with("-- ") || trimmed == "--" {
        ""
    } else {
        trimmed
    };

    before_desc
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "--")
        .map(str::to_string)
        .collect()
}

/// Parses a single comment body against `tool_prefixes` (such as `&["dotore", "eslint", "oxlint"]`
/// or `&["dotore"]`), supporting `-disable*`, `-ignore*`, and `-enable` directives.
#[must_use]
pub fn parse_comment_disable_directive(
    comment: &str,
    tool_prefixes: &[&str],
) -> Option<(SuppressionDirectiveKind, Vec<String>)> {
    let trimmed = comment.trim().trim_end_matches('}').trim();
    for &tool in tool_prefixes {
        for (suffix, kind) in [
            ("-disable-next-line", SuppressionDirectiveKind::DisableNextLine),
            ("-ignore-next-line", SuppressionDirectiveKind::DisableNextLine),
            ("-disable-line", SuppressionDirectiveKind::DisableLine),
            ("-ignore-line", SuppressionDirectiveKind::DisableLine),
            ("-disable", SuppressionDirectiveKind::BlockDisable),
            ("-ignore", SuppressionDirectiveKind::BlockDisable),
            ("-enable", SuppressionDirectiveKind::BlockEnable),
        ] {
            let Some(after_tool) = trimmed.strip_prefix(tool) else {
                continue;
            };
            let Some(after) = after_tool.strip_prefix(suffix) else {
                continue;
            };
            if !after.is_empty()
                && !after.starts_with(char::is_whitespace)
                && !after.starts_with(',')
                && !after.starts_with(':')
            {
                continue;
            }
            let cleaned = after.strip_prefix(':').unwrap_or(after);
            return Some((kind, tokenize_suppression_rules(cleaned)));
        }
    }
    None
}

/// Parses a Python `#` comment body for `dotore-disable*`, `dotore-ignore*`, `# noqa`,
/// or file-wide `# ruff: noqa` / `# flake8: noqa` directives.
#[must_use]
pub fn parse_python_suppression_directive(
    comment_body: &str,
) -> Option<(SuppressionDirectiveKind, Vec<String>)> {
    let trimmed = comment_body.trim();
    if let Some(directive) = parse_comment_disable_directive(trimmed, &["dotore"]) {
        return Some(directive);
    }

    // File-wide `# <tool>: noqa` suppression directive (e.g. `# ruff: noqa`, `# flake8: noqa`)
    if let Some((prefix, rest)) = trimmed.split_once(':')
        && !prefix.trim().is_empty()
        && prefix
            .trim()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && let Some(after) = rest.trim().strip_prefix("noqa")
    {
        let cleaned = after.trim().strip_prefix(':').unwrap_or(after);
        return Some((
            SuppressionDirectiveKind::BlockDisable,
            tokenize_suppression_rules(cleaned),
        ));
    }

    // `# noqa` or `# noqa: B006, E722`
    if let Some(after) = trimmed
        .strip_prefix("noqa")
        .or_else(|| trimmed.strip_prefix("NOQA"))
    {
        if after.is_empty() {
            return Some((SuppressionDirectiveKind::DisableLine, Vec::new()));
        }
        if let Some(codes) = after.strip_prefix(':') {
            return Some((
                SuppressionDirectiveKind::DisableLine,
                tokenize_suppression_rules(codes),
            ));
        }
        if after.starts_with(char::is_whitespace) {
            return Some((SuppressionDirectiveKind::DisableLine, Vec::new()));
        }
    }

    None
}

/// Maps a Rust `#[allow(...)]` or `#[expect(...)]` lint identifier (including `dotore::*`,
/// `clippy::*`, and standard `rustc` lint names) to canonical `dotore` rule keys.
#[must_use]
pub fn map_rust_allow_lint_to_rules(lint: &str) -> Vec<String> {
    let stripped = lint
        .strip_prefix("dotore::")
        .or_else(|| lint.strip_prefix("dotore/"))
        .or_else(|| {
            lint.split_once("::")
                .map(|(_, after)| after)
                .filter(|after| !after.is_empty())
        })
        .unwrap_or(lint);
    match stripped {
        "rs_no_unwrap_in_production"
        | "rs-no-unwrap-in-production"
        | "unwrap_used"
        | "expect_used" => vec!["rs-no-unwrap-in-production".to_string()],
        "rs_no_unguarded_slice_index" | "rs-no-unguarded-slice-index" | "indexing_slicing" => {
            vec!["rs-no-unguarded-slice-index".to_string()]
        }
        "rs_no_lossy_numeric_as_cast"
        | "rs-no-lossy-numeric-as-cast"
        | "cast_possible_truncation"
        | "cast_sign_loss"
        | "cast_possible_wrap"
        | "as_conversions" => vec!["rs-no-lossy-numeric-as-cast".to_string()],
        "rs_require_safety_comment_on_unsafe"
        | "rs-require-safety-comment-on-unsafe"
        | "undocumented_unsafe_blocks"
        | "unsafe_code" => vec!["rs-require-safety-comment-on-unsafe".to_string()],
        "rs_no_mem_forget" | "rs-no-mem-forget" | "mem_forget" => {
            vec!["rs-no-mem-forget".to_string()]
        }
        "rs_tokio_no_std_lock_across_await"
        | "rs-tokio-no-std-lock-across-await"
        | "await_holding_lock" => vec!["rs-tokio-no-std-lock-across-await".to_string()],
        "rs_tokio_no_blocking_in_async" | "rs-tokio-no-blocking-in-async" => {
            vec!["rs-tokio-no-blocking-in-async".to_string()]
        }
        "rs_tokio_prefer_bounded_channel" | "rs-tokio-prefer-bounded-channel" => {
            vec!["rs-tokio-prefer-bounded-channel".to_string()]
        }
        "rs_perf_no_clone_in_loop" | "rs-perf-no-clone-in-loop" => {
            vec!["rs-perf-no-clone-in-loop".to_string()]
        }
        "rs_perf_hoist_regex_to_lazylock" | "rs-perf-hoist-regex-to-lazylock" => {
            vec!["rs-perf-hoist-regex-to-lazylock".to_string()]
        }
        "rs_perf_prefer_vec_with_capacity" | "rs-perf-prefer-vec-with-capacity" => {
            vec!["rs-perf-prefer-vec-with-capacity".to_string()]
        }
        "rs_perf_no_unnecessary_format" | "rs-perf-no-unnecessary-format" | "useless_format" => {
            vec!["rs-perf-no-unnecessary-format".to_string()]
        }
        "rs_arch_no_many_boolean_params"
        | "rs-arch-no-many-boolean-params"
        | "fn_params_excessive_bools" => vec!["rs-arch-no-many-boolean-params".to_string()],
        "rs_arch_no_unused_pub_crate_items"
        | "rs-arch-no-unused-pub-crate-items"
        | "redundant_pub_crate" => vec!["rs-arch-no-unused-pub-crate-items".to_string()],
        other => {
            if let Some(rule_id) =
                RuleId::parse(other).or_else(|| RuleId::parse(&other.replace('_', "-")))
            {
                vec![rule_id.as_str().to_string()]
            } else {
                Vec::new()
            }
        }
    }
}

/// Extracts inline disable/enable directives from C-style `//` and `/* ... */` comments in `source`,
/// ignoring comment tokens inside string literals (`"`, `'`, `` ` ``) and resolving stacked
/// `*-disable-next-line` directives.
#[must_use]
pub fn extract_c_style_comment_suppressions(
    source: &str,
    tool_prefixes: &[&str],
) -> FileSuppressions {
    let lines: Vec<&str> = source.lines().collect();
    let mut suppressions = FileSuppressions::default();

    for (idx, &line) in lines.iter().enumerate() {
        let line_num = u32::try_from(idx + 1).unwrap_or(1);
        for comment in extract_c_style_comments_on_line(line) {
            let Some((kind, rules)) = parse_comment_disable_directive(comment, tool_prefixes)
            else {
                continue;
            };
            match kind {
                SuppressionDirectiveKind::DisableLine => {
                    suppressions.add_line_disable(line_num, rules);
                }
                SuppressionDirectiveKind::DisableNextLine => {
                    let target_line = resolve_next_c_style_code_line(&lines, idx, tool_prefixes);
                    suppressions.add_line_disable(target_line, rules);
                }
                SuppressionDirectiveKind::BlockDisable => {
                    suppressions.add_block_disable(line_num, u32::MAX, rules);
                }
                SuppressionDirectiveKind::BlockEnable => {
                    suppressions.close_block_ranges(&rules, line_num);
                }
            }
        }
    }

    suppressions
}

fn extract_c_style_comments_on_line(line: &str) -> Vec<&str> {
    let mut comments = Vec::new();
    let mut rest = line;

    while let Some((idx, is_block)) = find_next_c_style_comment_start(rest) {
        let after_open = &rest[idx + 2..];
        if is_block {
            if let Some(end_idx) = after_open.find("*/") {
                comments.push(after_open[..end_idx].trim());
                rest = &after_open[end_idx + 2..];
            } else {
                comments.push(after_open.trim());
                break;
            }
        } else {
            comments.push(after_open.trim());
            break;
        }
    }

    comments
}

fn find_next_c_style_comment_start(s: &str) -> Option<(usize, bool)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                return Some((i, false));
            }
            if bytes[i + 1] == b'*' {
                return Some((i, true));
            }
        }
        i += 1;
    }
    None
}

fn resolve_next_c_style_code_line(
    lines: &[&str],
    comment_line_idx: usize,
    tool_prefixes: &[&str],
) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while candidate < lines.len() {
        let text = lines[candidate].trim();
        let is_stacked_disable = extract_c_style_comments_on_line(text).into_iter().any(|c| {
            matches!(
                parse_comment_disable_directive(c, tool_prefixes),
                Some((SuppressionDirectiveKind::DisableNextLine, _))
            )
        });
        if is_stacked_disable {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}

/// Related AST spans for a hook, effect, or frame-loop call expression (`useEffect`, `useMemo`, `useCallback`, `useFrame`, `effect`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RelatedHookOwnerSpanIr {
    /// Byte span of the hook/frame call expression.
    pub call_span: ByteSpan,
    /// Byte spans of local function/arrow-function declarations referenced inside the call.
    pub referenced_decl_spans: Vec<ByteSpan>,
}

/// Single-pass AST owner spans extracted for `--scope contextual` diff filtering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContextualOwnerSpansIr {
    /// Function, method, class, or `impl` boundary spans (including outer wrapper spans).
    pub function_boundary_spans: Vec<ByteSpan>,
    /// Hook, effect, and frame-loop call spans paired with their referenced local callback/function declaration spans.
    pub related_hook_spans: Vec<RelatedHookOwnerSpanIr>,
    /// JSX element or template/block owner spans for `ContextualOwnerPolicy::JsxElement`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub element_spans: Vec<ByteSpan>,
}

/// A resolved cross-file **Caller Site** rendering or invoking a target **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCallerSite {
    /// File containing the caller site.
    pub caller_file: PathBuf,
    /// Enclosing parent **Subject** name, if any.
    pub parent_subject_name: Option<String>,
    /// Rendered or invoked component/subject name.
    pub component_name: String,
    /// 1-based location of the caller site.
    pub loc: SourceLoc,
    /// Byte span of the caller site.
    pub span: ByteSpan,
    /// Whether `key={...}` is present on the JSX element.
    pub has_key: bool,
    /// Props or arguments passed at this **Caller Site**.
    pub passed_props: Vec<String>,
}

/// Canonical identifier for a language analyzer registered in a `dotore` workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LanguageId {
    /// JavaScript and TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`).
    JavaScript,
    /// TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`).
    TypeScript,
    /// Python (`.py`, `.pyi`).
    Python,
    /// Rust (`.rs`).
    Rust,
    /// Stylesheet (`.css`, `.scss`).
    Stylesheet,
    /// HTML or Angular component template (`.html`, `.htm`).
    Html,
}

#[expect(
    non_upper_case_globals,
    reason = "Provides short crate-aligned aliases Js, Py, and Rs alongside full language names"
)]
impl LanguageId {
    /// Alias for [`LanguageId::JavaScript`] representing the `dotore-js` analyzer family.
    pub const Js: Self = Self::JavaScript;
    /// Alias for [`LanguageId::Python`] representing the `dotore-py` analyzer family.
    pub const Py: Self = Self::Python;
    /// Alias for [`LanguageId::Rust`] representing the `dotore-rs` analyzer family.
    pub const Rs: Self = Self::Rust;

    /// Returns the canonical kebab-case identifier for this language.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Stylesheet => "stylesheet",
            Self::Html => "html",
        }
    }

    /// Infers a [`LanguageId`] from a file path's extension.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Self::TypeScript),
            "py" | "pyi" => Some(Self::Python),
            "rs" => Some(Self::Rust),
            "css" | "scss" => Some(Self::Stylesheet),
            "html" | "htm" => Some(Self::Html),
            _ => None,
        }
    }
}

/// Language-agnostic single-pass file extraction result produced by [`LanguageAnalyzer::extract_file`].
#[derive(Debug)]
pub struct ExtractedFile {
    /// Path to the source file.
    pub path: PathBuf,
    /// Verbatim source text of the file.
    pub source: String,
    /// Language identifier for this file.
    pub language_id: LanguageId,
    /// Classification of the file (`Production`, `Test`, or `Story`).
    pub file_context: FileContext,
    /// Extracted **Symbol Outlines** for fuzzy symbol search (`dotore search`).
    pub symbol_outlines: Vec<SymbolOutline>,
    /// Single-pass AST owner spans for `--scope contextual` diff filtering.
    pub contextual_owner_spans: ContextualOwnerSpansIr,
    /// Inline suppression directives (`dotore-disable*`, `# noqa`, `#[allow]` / `#[expect]`).
    pub suppressions: FileSuppressions,
    /// Total **Subjects** (components, hooks, functions, handlers, or items) extracted in this file.
    pub subjects_count: usize,
    /// Total **Effect Nodes** or reactive effects extracted in this file.
    pub effects_count: usize,
    /// Extracted **Subject** spans `(name, span, loc)` for **Fix Capsule** excerpts and inline suppressions.
    pub subject_spans: Vec<(Option<String>, ByteSpan, SourceLoc)>,
    /// Opaque language-specific IR payload downcast by the owning [`LanguageAnalyzer::analyze_package`].
    pub payload: Box<dyn Any + Send + Sync>,
}

impl ExtractedFile {
    /// Creates a new [`ExtractedFile`] with empty collections and a unit `()` payload.
    #[must_use]
    pub fn new(path: PathBuf, source: String, language_id: LanguageId) -> Self {
        let file_context = classify_file_context(&path);
        Self {
            path,
            source,
            language_id,
            file_context,
            symbol_outlines: Vec::new(),
            contextual_owner_spans: ContextualOwnerSpansIr::default(),
            suppressions: FileSuppressions::default(),
            subjects_count: 0,
            effects_count: 0,
            subject_spans: Vec::new(),
            payload: Box::new(()),
        }
    }

    /// Attaches a typed language-specific IR payload to this [`ExtractedFile`].
    #[must_use]
    pub fn with_payload<T: Any + Send + Sync>(mut self, payload: T) -> Self {
        self.payload = Box::new(payload);
        self
    }

    /// Downcasts the opaque language-specific payload to `T`, if it matches.
    #[must_use]
    pub fn downcast_payload<T: Any>(&self) -> Option<&T> {
        self.payload.downcast_ref::<T>()
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` or `span` in this file.
    #[must_use]
    pub fn is_suppressed(&self, rule: RuleId, line: u32, span: ByteSpan) -> bool {
        let owner_spans: Vec<(ByteSpan, u32)> = self
            .subject_spans
            .iter()
            .map(|&(_, sp, loc)| (sp, loc.line))
            .collect();
        self.suppressions
            .is_suppressed_with_owners(rule, line, span, &[], &owner_spans)
    }
}

/// Result of analyzing a [`WorkspacePackage`] via [`LanguageAnalyzer::analyze_package`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PackageAnalysisResult {
    /// Diagnostics emitted for the package.
    pub diagnostics: Vec<Diagnostic>,
    /// Total **Subjects** scanned across the package.
    pub subjects_scanned: usize,
    /// Total **Effect Nodes** scanned across the package.
    pub effects_scanned: usize,
}

/// Formal boundary between `dotore-core` and language analyzer crates (`dotore-js`, `dotore-py`, `dotore-rs`).
pub trait LanguageAnalyzer: Send + Sync {
    /// Returns the canonical [`LanguageId`] handled by this analyzer.
    fn language_id(&self) -> LanguageId;

    /// Returns `true` if this analyzer supports analyzing `path` (by file extension/name).
    fn supports_path(&self, path: &Path) -> bool;

    /// Returns the manifest filenames inspected by this analyzer to discover packages and infer capabilities
    /// (e.g. `&["package.json", "angular.json"]`, `&["pyproject.toml", "requirements.txt"]`, `&["Cargo.toml"]`).
    fn manifest_filenames(&self) -> &'static [&'static str];

    /// Infers a [`CapabilityGate`] for `package_dir` from its discovered `(manifest_path, manifest_source)` pairs.
    fn infer_capability_gate(
        &self,
        package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate;

    /// Parses `source` at `path` in a single pass and returns its [`ExtractedFile`] summary and language payload.
    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile;

    /// Evaluates single-file and cross-file package rules over `files` for `package`.
    fn analyze_package(
        &self,
        package: &WorkspacePackage,
        files: &[ExtractedFile],
        enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult;

    /// Verifies that `source` at `path` is syntactically valid (used before committing `Autofix` edits).
    fn validate_syntax(&self, path: &Path, source: &str) -> bool;
}

/// Computes 0-based line start byte offsets for `source`.
#[must_use]
pub fn compute_line_starts(source: &str) -> Vec<u32> {
    let mut starts = vec![0];
    for (idx, byte) in source.bytes().enumerate() {
        if byte == b'\n'
            && let Ok(next_pos) = u32::try_from(idx + 1)
        {
            starts.push(next_pos);
        }
    }
    starts
}

/// Converts a 0-based byte offset into a 1-based [`SourceLoc`].
#[must_use]
pub fn loc_from_line_starts(line_starts: &[u32], byte_offset: u32) -> SourceLoc {
    let line_idx = match line_starts.binary_search(&byte_offset) {
        Ok(exact) => exact,
        Err(insert) => insert.saturating_sub(1),
    };
    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
    let line = u32::try_from(line_idx + 1).unwrap_or(1);
    let column = byte_offset.saturating_sub(line_start) + 1;
    SourceLoc { line, column }
}

/// Extracts a normalized single-line declaration signature header and its 1-based end line
/// from `source[decl_start..sig_end]`, collapsing whitespace and stripping trailing `{` or `;`.
#[must_use]
pub fn extract_normalized_signature_header(
    source: &str,
    line_starts: &[u32],
    decl_start: u32,
    decl_end: u32,
    body_start: Option<u32>,
) -> (String, u32) {
    let sig_end_offset = if let Some(bs) = body_start
        && bs > decl_start
    {
        bs.min(decl_end)
    } else {
        let start_usize = usize::try_from(decl_start)
            .unwrap_or(0)
            .min(source.len());
        let fallback_end = source[start_usize..].find('\n').map_or(decl_end, |rel| {
            decl_start.saturating_add(u32::try_from(rel).unwrap_or(0))
        });
        decl_end.min(fallback_end)
    };
    let sig_end_loc = loc_from_line_starts(
        line_starts,
        sig_end_offset.saturating_sub(1).max(decl_start),
    );
    let start_idx = usize::try_from(decl_start).unwrap_or(0);
    let end_idx = usize::try_from(sig_end_offset)
        .unwrap_or(start_idx)
        .min(source.len());
    let raw_sig = source.get(start_idx..end_idx).unwrap_or("");
    let cleaned_lines: Vec<&str> = raw_sig
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("///")
                && !trimmed.starts_with("//!")
                && !trimmed.starts_with("#[")
        })
        .collect();
    let collapsed = cleaned_lines
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let signature = collapsed
        .trim_end_matches('{')
        .trim_end_matches(';')
        .trim()
        .to_string();
    (signature, sig_end_loc.line)
}
