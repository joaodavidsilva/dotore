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

/// Parsed inline suppression directives (`dotore-disable*`, `eslint-disable*`, `oxlint-disable*`, `noqa`) for a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileSuppressions {
    /// Line-targeted disable directives (`*-disable-next-line` and `*-disable-line`).
    pub line_directives: Vec<LineDisableDirective>,
    /// File-wide or block-range disable directives (`/* *-disable */`).
    pub block_ranges: Vec<BlockDisableRange>,
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
    /// Inline suppression directives (`dotore-disable*`, `eslint-disable*`, `oxlint-disable*`, `noqa`).
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
