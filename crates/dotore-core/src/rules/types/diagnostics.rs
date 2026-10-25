//! Diagnostic, autofix patch, Blast Radius, Root-Cause Group, and Fix Capsule models.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ir::{ByteSpan, ResolvedCallerSite, SourceLoc};

use super::{PrescriptionTier, RuleCategory, RuleId, RuleSeverity};

/// A single byte-range replacement in a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteEdit {
    /// Optional target file path for cross-file rewrites (`None` targets the diagnostic's own file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Byte span in the original file to replace.
    pub span: ByteSpan,
    /// Replacement source text.
    pub replacement: String,
}

impl ByteEdit {
    /// Creates a byte-range replacement edit in the diagnostic's own file (`file: None`).
    #[must_use]
    pub fn new(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self::replace(span, replacement)
    }

    /// Creates a byte-range replacement edit in the diagnostic's own file (`file: None`).
    #[must_use]
    pub fn replace(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self {
            file: None,
            span,
            replacement: replacement.into(),
        }
    }

    /// Creates a byte-range deletion edit (`replacement: ""`) in the diagnostic's own file.
    #[must_use]
    pub fn delete(span: ByteSpan) -> Self {
        Self {
            file: None,
            span,
            replacement: String::new(),
        }
    }

    /// Creates a zero-length insertion edit at `offset` in the diagnostic's own file.
    #[must_use]
    pub fn insert(offset: u32, text: impl Into<String>) -> Self {
        Self {
            file: None,
            span: ByteSpan {
                start: offset,
                end: offset,
            },
            replacement: text.into(),
        }
    }

    /// Targets this byte edit at a specific file path for cross-file rewrites.
    #[must_use]
    pub fn in_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Sets an optional target file path for this byte edit.
    #[must_use]
    pub fn with_file(mut self, file: Option<PathBuf>) -> Self {
        self.file = file;
        self
    }
}

/// Deterministic patch for an `Autofix`-tier diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofixPatch {
    /// Summary of the transformation.
    pub description: String,
    /// Non-overlapping byte edits to apply to the file(s).
    pub edits: Vec<ByteEdit>,
}

impl AutofixPatch {
    /// Creates an empty [`AutofixPatch`] with the given `description`.
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            edits: Vec::new(),
        }
    }

    /// Alias for [`AutofixPatch::new`] starting a fluent patch builder.
    #[must_use]
    pub fn builder(description: impl Into<String>) -> Self {
        Self::new(description)
    }

    /// Creates a single-edit [`AutofixPatch`] replacing `span` with `replacement`.
    #[must_use]
    pub fn replace(
        description: impl Into<String>,
        span: ByteSpan,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::replace(span, replacement)],
        }
    }

    /// Creates a single-edit [`AutofixPatch`] deleting `span`.
    #[must_use]
    pub fn delete(description: impl Into<String>, span: ByteSpan) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::delete(span)],
        }
    }

    /// Creates a single-edit [`AutofixPatch`] inserting `text` at `offset`.
    #[must_use]
    pub fn insert(description: impl Into<String>, offset: u32, text: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::insert(offset, text)],
        }
    }

    /// Appends a same-file byte replacement edit to this patch.
    #[must_use]
    pub fn with_edit(mut self, span: ByteSpan, replacement: impl Into<String>) -> Self {
        self.edits.push(ByteEdit::replace(span, replacement));
        self
    }

    /// Appends a cross-file byte replacement edit to this patch.
    #[must_use]
    pub fn with_file_edit(
        mut self,
        file: impl Into<PathBuf>,
        span: ByteSpan,
        replacement: impl Into<String>,
    ) -> Self {
        self.edits
            .push(ByteEdit::replace(span, replacement).in_file(file));
        self
    }

    /// Appends a pre-constructed [`ByteEdit`] to this patch.
    #[must_use]
    pub fn with_byte_edit(mut self, edit: ByteEdit) -> Self {
        self.edits.push(edit);
        self
    }

    /// Appends multiple [`ByteEdit`] items to this patch.
    #[must_use]
    pub fn with_edits(mut self, edits: impl IntoIterator<Item = ByteEdit>) -> Self {
        self.edits.extend(edits);
        self
    }
}

/// Priority tier (`P0`–`P3`) derived from static **Blast Radius** evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlastRadiusTier {
    /// Critical runtime bugs, security flaws, 60fps frame-loop allocations/state updates, or deep **Render Cascades** with high fan-out.
    P0,
    /// High-impact `Error` diagnostics, multi-pass **Render Cascades**, or list/loop performance flaws.
    P1,
    /// Moderate `Surgical` or `Refactor` warnings or localized component issues.
    P2,
    /// Minor polish, dead-code cleanup, or low-fan-out maintainability hints.
    P3,
}

impl BlastRadiusTier {
    /// Canonical string representation (`"P0"`..=`"P3"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }
}

/// Static render frequency context of a **Subject** or JSX site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderFrequency {
    /// Standard component render pass (`1x`).
    Standard,
    /// Rendered inside a `.map()` or loop (`2x`).
    ListLoop,
    /// Executed inside a 60fps `useFrame` or `requestAnimationFrame` callback (`4x`).
    FrameLoop60Fps,
}

impl RenderFrequency {
    /// Canonical kebab-case string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::ListLoop => "list-loop",
            Self::FrameLoop60Fps => "frame-loop-60-fps",
        }
    }
}

/// Deterministic static runtime impact of a **Root-Cause Group** (see `GLOSSARY.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Deterministic composite score (`>= 1`).
    pub score: u32,
    /// Priority tier (`P0`–`P3`).
    pub tier: BlastRadiusTier,
    /// Render frequency classification (`standard`, `list-loop`, `frame-loop-60-fps`).
    pub render_frequency: RenderFrequency,
    /// Cross-file or cross-component fan-out (**Caller Sites**, child **Subjects**, or context consumers).
    pub fan_out: usize,
    /// Number of extra post-render passes or steps in the **Render Cascade**.
    pub cascade_depth: usize,
    /// Number of individual diagnostic sites clustered in this **Root-Cause Group**.
    pub site_count: usize,
    /// Number of distinct files touched by this **Root-Cause Group** (including **Caller Sites**).
    pub file_count: usize,
}

/// Verbatim source slice with 1-based line bounds attached to a [`FixCapsule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceExcerpt {
    /// File path of the excerpt.
    pub file: PathBuf,
    /// 1-based inclusive start line.
    pub start_line: u32,
    /// 1-based inclusive end line.
    pub end_line: u32,
    /// Verbatim source slice.
    pub source: String,
}

/// Self-contained remediation unit emitted for a `Surgical` or `Refactor` **Root-Cause Group** (see `GLOSSARY.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixCapsule {
    /// Deterministic **Root-Cause Group** identifier.
    pub root_cause_group_id: String,
    /// Rule identifier.
    pub rule: RuleId,
    /// **Prescription Tier** (`Surgical` or `Refactor`).
    pub tier: PrescriptionTier,
    /// Static **Blast Radius** score and priority tier.
    pub blast_radius: BlastRadius,
    /// Verbatim source excerpt of the owning **Subject** (or diagnostic site).
    pub subject_excerpt: SourceExcerpt,
    /// Verbatim source excerpts of resolved cross-file **Caller Sites**.
    pub caller_site_excerpts: Vec<SourceExcerpt>,
    /// Compiled-in canonical transformation recipe in Markdown.
    pub recipe_markdown: &'static str,
    /// Discovered valid usage in the same repository, if available.
    pub exemplar: Option<SourceExcerpt>,
    /// Invariants that must be preserved when applying the transformation.
    pub invariants: Vec<&'static str>,
}

/// Clustered group of related diagnostics sharing a single underlying defect (see `GLOSSARY.md`: **Root-Cause Group**).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCauseGroup {
    /// Deterministic **Root-Cause Group** identifier (`rcg::...`).
    pub id: String,
    /// Primary rule identifier.
    pub rule: RuleId,
    /// Rule category.
    pub category: RuleCategory,
    /// Highest severity among clustered diagnostics.
    pub severity: RuleSeverity,
    /// **Prescription Tier** for the group.
    pub tier: PrescriptionTier,
    /// Primary file path of the root cause.
    pub file: PathBuf,
    /// Enclosing **Subject** name, if any.
    pub subject_name: Option<String>,
    /// Primary target name (prop, state slot, context, or component).
    pub target_name: String,
    /// Primary 1-based location.
    pub loc: SourceLoc,
    /// Summary message for the group.
    pub message: String,
    /// Static **Blast Radius** score and priority tier (`P0`–`P3`).
    pub blast_radius: BlastRadius,
    /// Indices into `JsonReport::diagnostics` belonging to this group.
    pub diagnostic_indices: Vec<usize>,
}

/// A single diagnostic emitted by `dotore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// File path where the diagnostic occurred.
    pub file: PathBuf,
    /// Enclosing **Subject** name (`"Form"`, `"useOnlineStatus"`, or `None` if anonymous/module-level).
    pub subject_name: Option<String>,
    /// Rule identifier.
    pub rule: RuleId,
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    pub category: RuleCategory,
    /// Effective severity (`Error` or `Warning`).
    pub severity: RuleSeverity,
    /// Message identifier (for compatibility with rule tests).
    pub message_id: &'static str,
    /// Prescription tier (`Autofix`, `Surgical`, `Refactor`).
    pub tier: PrescriptionTier,
    /// Primary target name (state name, prop name, component name, or data source).
    pub target_name: String,
    /// Human-readable diagnostic message.
    pub message: String,
    /// Official documentation link.
    pub docs_url: &'static str,
    /// 1-based line and column.
    pub loc: SourceLoc,
    /// Byte span of the flagged AST node.
    pub span: ByteSpan,
    /// Steps of the **Render Cascade** eliminated by fixing this diagnostic.
    pub cascade_steps: Vec<String>,
    /// Cross-file JSX **Caller Sites** relevant to this diagnostic (e.g. missing `key`).
    pub caller_sites: Vec<ResolvedCallerSite>,
    /// Optional deterministic auto-fix patch.
    pub autofix: Option<AutofixPatch>,
}

impl Diagnostic {
    /// Creates a [`Diagnostic`] for `rule`, automatically populating `category`, `severity`,
    /// `tier`, and `docs_url` from [`RuleId::metadata`].
    #[must_use]
    pub fn new(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        target_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let meta = rule.metadata();
        Self {
            file: file.into(),
            subject_name: None,
            rule,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "",
            tier: meta.default_tier,
            target_name: target_name.into(),
            message: message.into(),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }
    }

    /// Alias for [`Diagnostic::new`] starting a fluent diagnostic builder.
    #[must_use]
    pub fn builder(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        target_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(rule, file, loc, span, target_name, message)
    }

    /// Creates a [`Diagnostic`] for `rule` with `target_name` defaulted to `rule.as_str()`.
    #[must_use]
    pub fn for_rule(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        message: impl Into<String>,
    ) -> Self {
        Self::new(rule, file, loc, span, rule.as_str(), message)
    }

    /// Sets the optional enclosing **Subject** name (`Some(...)` or `None`).
    #[must_use]
    pub fn with_subject(mut self, subject_name: Option<String>) -> Self {
        self.subject_name = subject_name;
        self
    }

    /// Sets the enclosing **Subject** name.
    #[must_use]
    pub fn with_subject_name(mut self, subject_name: impl Into<String>) -> Self {
        self.subject_name = Some(subject_name.into());
        self
    }

    /// Overrides the effective [`RuleSeverity`] (`Error` or `Warning`).
    #[must_use]
    pub const fn with_severity(mut self, severity: RuleSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Overrides the [`PrescriptionTier`] (`Autofix`, `Surgical`, or `Refactor`).
    #[must_use]
    pub const fn with_tier(mut self, tier: PrescriptionTier) -> Self {
        self.tier = tier;
        self
    }

    /// Overrides the [`RuleCategory`].
    #[must_use]
    pub const fn with_category(mut self, category: RuleCategory) -> Self {
        self.category = category;
        self
    }

    /// Sets the static `message_id` token.
    #[must_use]
    pub const fn with_message_id(mut self, message_id: &'static str) -> Self {
        self.message_id = message_id;
        self
    }

    /// Overrides the primary `target_name`.
    #[must_use]
    pub fn with_target_name(mut self, target_name: impl Into<String>) -> Self {
        self.target_name = target_name.into();
        self
    }

    /// Overrides the documentation URL.
    #[must_use]
    pub const fn with_docs_url(mut self, docs_url: &'static str) -> Self {
        self.docs_url = docs_url;
        self
    }

    /// Replaces the **Render Cascade** step list.
    #[must_use]
    pub fn with_cascade_steps(mut self, steps: Vec<String>) -> Self {
        self.cascade_steps = steps;
        self
    }

    /// Appends a single step to the **Render Cascade** step list.
    #[must_use]
    pub fn with_cascade_step(mut self, step: impl Into<String>) -> Self {
        self.cascade_steps.push(step.into());
        self
    }

    /// Replaces the resolved cross-file **Caller Sites** list.
    #[must_use]
    pub fn with_caller_sites(mut self, caller_sites: Vec<ResolvedCallerSite>) -> Self {
        self.caller_sites = caller_sites;
        self
    }

    /// Appends a single resolved cross-file **Caller Site**.
    #[must_use]
    pub fn with_caller_site(mut self, caller_site: ResolvedCallerSite) -> Self {
        self.caller_sites.push(caller_site);
        self
    }

    /// Sets the optional [`AutofixPatch`] (`Some(patch)` or `None`).
    /// When `autofix` is `Some(...)`, also sets `tier` to [`PrescriptionTier::Autofix`].
    #[must_use]
    pub fn with_autofix(mut self, autofix: Option<AutofixPatch>) -> Self {
        if autofix.is_some() {
            self.tier = PrescriptionTier::Autofix;
        }
        self.autofix = autofix;
        self
    }

    /// Attaches a deterministic [`AutofixPatch`] and promotes `tier` to [`PrescriptionTier::Autofix`].
    #[must_use]
    pub fn with_patch(mut self, patch: AutofixPatch) -> Self {
        self.tier = PrescriptionTier::Autofix;
        self.autofix = Some(patch);
        self
    }

    /// Computes the deterministic occurrence identity (`<file>::<line>:<col>::dotore/<rule>::<digest>`).
    #[must_use]
    pub fn id(&self) -> String {
        crate::diff::compute_diagnostic_id(self, None)
    }

    /// Computes the rename- and formatting-resilient fingerprint (`fp::<rule>::<digest>`) for this diagnostic.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::diff::compute_structural_fingerprint(self)
    }

    /// Computes the normalized AST-token fingerprint (`fp::<rule>::<digest>`) using the file's source text when available.
    #[must_use]
    pub fn fingerprint_with_source(&self, source: Option<&str>) -> String {
        crate::diff::compute_diagnostic_fingerprint(self, source)
    }

    /// Computes the deterministic **Root-Cause Group** identifier (`rcg::...`) for this diagnostic.
    #[must_use]
    pub fn root_cause_group_id(&self) -> String {
        crate::planner::compute_root_cause_group_id(self)
    }
}

#[derive(Serialize)]
#[serde(rename = "Diagnostic")]
struct DiagnosticSer<'a> {
    id: String,
    fingerprint: String,
    root_cause_group_id: String,
    file: &'a PathBuf,
    subject_name: &'a Option<String>,
    rule: RuleId,
    category: RuleCategory,
    severity: RuleSeverity,
    message_id: &'static str,
    tier: PrescriptionTier,
    target_name: &'a str,
    message: &'a str,
    docs_url: &'static str,
    loc: SourceLoc,
    span: ByteSpan,
    cascade_steps: &'a [String],
    caller_sites: &'a [ResolvedCallerSite],
    autofix: &'a Option<AutofixPatch>,
}

impl Serialize for Diagnostic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        DiagnosticSer {
            id: self.id(),
            fingerprint: self.fingerprint(),
            root_cause_group_id: self.root_cause_group_id(),
            file: &self.file,
            subject_name: &self.subject_name,
            rule: self.rule,
            category: self.category,
            severity: self.severity,
            message_id: self.message_id,
            tier: self.tier,
            target_name: &self.target_name,
            message: &self.message,
            docs_url: self.docs_url,
            loc: self.loc,
            span: self.span,
            cascade_steps: &self.cascade_steps,
            caller_sites: &self.caller_sites,
            autofix: &self.autofix,
        }
        .serialize(serializer)
    }
}

const fn default_source_loc() -> SourceLoc {
    SourceLoc { line: 1, column: 1 }
}

impl<'de> Deserialize<'de> for Diagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DiagnosticDe {
            file: PathBuf,
            #[serde(default)]
            subject_name: Option<String>,
            rule: RuleId,
            #[serde(default)]
            category: Option<RuleCategory>,
            #[serde(default)]
            severity: Option<RuleSeverity>,
            #[serde(default)]
            tier: Option<PrescriptionTier>,
            #[serde(default)]
            target_name: String,
            #[serde(default)]
            message: String,
            #[serde(default = "default_source_loc")]
            loc: SourceLoc,
            #[serde(default)]
            span: ByteSpan,
            #[serde(default)]
            cascade_steps: Vec<String>,
            #[serde(default)]
            caller_sites: Vec<ResolvedCallerSite>,
            #[serde(default)]
            autofix: Option<AutofixPatch>,
        }
        let raw = DiagnosticDe::deserialize(deserializer)?;
        let meta = raw.rule.metadata();
        Ok(Self {
            file: raw.file,
            subject_name: raw.subject_name,
            rule: raw.rule,
            category: raw.category.unwrap_or(meta.category),
            severity: raw.severity.unwrap_or(meta.default_severity),
            message_id: "",
            tier: raw.tier.unwrap_or(meta.default_tier),
            target_name: raw.target_name,
            message: raw.message,
            docs_url: meta.docs_url,
            loc: raw.loc,
            span: raw.span,
            cascade_steps: raw.cascade_steps,
            caller_sites: raw.caller_sites,
            autofix: raw.autofix,
        })
    }
}

impl<'de> Deserialize<'de> for FixCapsule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct FixCapsuleDe {
            root_cause_group_id: String,
            rule: RuleId,
            tier: PrescriptionTier,
            blast_radius: BlastRadius,
            subject_excerpt: SourceExcerpt,
            #[serde(default)]
            caller_site_excerpts: Vec<SourceExcerpt>,
            #[serde(default)]
            exemplar: Option<SourceExcerpt>,
        }
        let raw = FixCapsuleDe::deserialize(deserializer)?;
        Ok(Self {
            root_cause_group_id: raw.root_cause_group_id,
            rule: raw.rule,
            tier: raw.tier,
            blast_radius: raw.blast_radius,
            subject_excerpt: raw.subject_excerpt,
            caller_site_excerpts: raw.caller_site_excerpts,
            recipe_markdown: raw.rule.metadata().recipe_markdown,
            exemplar: raw.exemplar,
            invariants: crate::planner::invariants_for_rule(raw.rule, raw.tier),
        })
    }
}
