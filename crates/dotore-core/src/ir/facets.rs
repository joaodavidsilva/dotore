//! Language-agnostic multi-signal structural facets for architecture, SoC, and reuse rules.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ByteSpan, SourceLoc};

/// Orthogonal architectural responsibility bucket classified during single-pass file extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConcernBucket {
    /// CLI argument, HTTP route, or process bootstrap adapter logic.
    EntrypointAdapter,
    /// Database queries, filesystem reads/writes, or network/socket I/O.
    DataOrNetworkIo,
    /// Terminal ANSI/box formatting or UI component/DOM presentation.
    TerminalOrUiPresentation,
    /// Core domain `struct`, `enum`, `interface`, `type`, or `class` declarations.
    TypeDefinitions,
    /// Large static data tables, registries, or constant array catalogs.
    StaticDataCatalog,
    /// Pure AST traversal, structural matching, or validation helpers.
    AstOrValidationHelper,
}

impl ConcernBucket {
    /// Returns the canonical kebab-case identifier for this concern bucket.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntrypointAdapter => "entrypoint-adapter",
            Self::DataOrNetworkIo => "data-or-network-io",
            Self::TerminalOrUiPresentation => "terminal-or-ui-presentation",
            Self::TypeDefinitions => "type-definitions",
            Self::StaticDataCatalog => "static-data-catalog",
            Self::AstOrValidationHelper => "ast-or-validation-helper",
        }
    }
}

/// A single AST site (import, call, declaration, or literal) contributing to a [`ConcernBucket`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcernSignalSite {
    /// Architectural responsibility bucket.
    pub bucket: ConcernBucket,
    /// Human-readable evidence token (e.g. `"std::fs::write"`, `"AsciiBox::new"`, `"fetch(...)"`).
    pub detail: String,
    /// 1-based source location of the signal.
    pub loc: SourceLoc,
    /// Byte span of the signal.
    pub span: ByteSpan,
}

/// Normalized structural AST fingerprint for a helper function extracted in a single pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperFingerprintIr {
    /// Function or helper identifier.
    pub name: String,
    /// Deterministic 64-bit hash over normalized AST node kinds and arity.
    pub normalized_hash: u64,
    /// Number of non-trivial statements/expressions in the helper body.
    pub statement_count: usize,
    /// Number of parameters accepted by the helper.
    pub param_count: usize,
    /// Whether the helper is module-private (not exported / not `pub`).
    pub is_private: bool,
    /// 1-based source location of the helper declaration.
    pub loc: SourceLoc,
    /// Byte span of the helper declaration.
    pub span: ByteSpan,
}

/// Multi-field struct, class, or object literal construction site recorded for builder reuse analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructLiteralConstructionSiteIr {
    /// Constructed type or struct/class identifier.
    pub type_name: String,
    /// Initialized field keys in source order.
    pub field_names: Vec<String>,
    /// Subset of field keys initialized with default/boilerplate literals (`None`, `Vec::new()`, `false`, `""`, `0`, `null`, `[]`, `{}`).
    pub default_or_literal_fields: Vec<String>,
    /// 1-based source location of the construction site.
    pub loc: SourceLoc,
    /// Byte span of the construction expression.
    pub span: ByteSpan,
}

/// Classification of an inline terminal UI primitive literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalUiPrimitiveKind {
    /// Raw ANSI SGR or control escape sequence (`\x1b[...`, `\u001b[...`, `\033[...`).
    AnsiEscape,
    /// Unicode box-drawing border or frame character (`┌`, `─`, `│`, `╭`, `═`, etc.).
    BoxDrawing,
}

impl TerminalUiPrimitiveKind {
    /// Returns the canonical kebab-case identifier (`"ansi-escape"` or `"box-drawing"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnsiEscape => "ansi-escape",
            Self::BoxDrawing => "box-drawing",
        }
    }
}

impl fmt::Display for TerminalUiPrimitiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inline ANSI escape sequence or Unicode box-drawing literal detected in a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineTerminalUiPrimitiveSiteIr {
    /// Classification of the primitive (`AnsiEscape` or `BoxDrawing`).
    pub kind: TerminalUiPrimitiveKind,
    /// Short representative snippet or token.
    pub snippet: String,
    /// 1-based source location of the literal.
    pub loc: SourceLoc,
    /// Byte span of the literal or enclosing expression.
    pub span: ByteSpan,
}

/// Large static array, slice, or lookup table declaration recorded for data-vs-types separation analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCatalogSiteIr {
    /// Identifier of the static/const catalog binding.
    pub name: String,
    /// Number of top-level entries in the static collection.
    pub entry_count: usize,
    /// Byte length of the initializer expression.
    pub byte_len: usize,
    /// 1-based source location of the declaration.
    pub loc: SourceLoc,
    /// Byte span of the declaration.
    pub span: ByteSpan,
}

/// Language-agnostic multi-signal structural facets extracted in a single pass per [`super::ExtractedFile`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchitectureFileFacets {
    /// Architectural responsibility signals observed in this file.
    pub concern_signals: Vec<ConcernSignalSite>,
    /// Normalized structural fingerprints for helper functions in this file.
    pub helper_fingerprints: Vec<HelperFingerprintIr>,
    /// Multi-field struct/class/object literal construction sites in this file.
    pub struct_literal_sites: Vec<StructLiteralConstructionSiteIr>,
    /// Inline terminal ANSI or box-drawing literals in this file.
    pub inline_terminal_ui_sites: Vec<InlineTerminalUiPrimitiveSiteIr>,
    /// Static data catalog declarations in this file.
    pub static_catalog_sites: Vec<StaticCatalogSiteIr>,
    /// Type names for which this file defines a fluent builder or constructor (`with_*`, `Builder`, `new`, `for_rule`).
    pub defined_builder_types: Vec<String>,
    /// Distinct domain cluster prefixes or namespaces represented by symbols in this file.
    pub domain_clusters: Vec<String>,
    /// Number of public/exported domain types (`struct`, `enum`, `interface`, `class`, `type`) declared in this file.
    pub public_type_count: usize,
    /// Statement count inside the primary binary/service entrypoint (`main` / bootstrap), if any.
    pub entrypoint_statement_count: usize,
    /// Whether this file is a binary/service entrypoint (`main.rs`, `__main__.py`, CLI bin, etc.).
    pub is_entrypoint: bool,
    /// Whether this file is a designated UI primitive kit module (`ui.rs`, `ui/*`, `terminal_ui.*`).
    pub is_ui_kit_module: bool,
}

impl ArchitectureFileFacets {
    /// Returns `true` if at least one signal in `bucket` was observed in this file.
    #[must_use]
    pub fn has_bucket(&self, bucket: ConcernBucket) -> bool {
        self.concern_signals.iter().any(|s| s.bucket == bucket)
    }

    /// Returns the deduplicated [`ConcernBucket`]s observed in this file in deterministic order.
    #[must_use]
    pub fn distinct_concern_buckets(&self) -> Vec<ConcernBucket> {
        let mut buckets = Vec::new();
        for sig in &self.concern_signals {
            if !buckets.contains(&sig.bucket) {
                buckets.push(sig.bucket);
            }
        }
        buckets
    }

    /// Returns all [`ConcernSignalSite`]s belonging to `bucket`.
    #[must_use]
    pub fn signals_for_bucket(&self, bucket: ConcernBucket) -> Vec<&ConcernSignalSite> {
        self.concern_signals
            .iter()
            .filter(|s| s.bucket == bucket)
            .collect()
    }

    /// Formats a concise human-readable summary of the active structural signals in this file,
    /// or `None` if no structural signals were recorded.
    #[must_use]
    pub fn explain_signals_summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        let buckets = self.distinct_concern_buckets();
        if !buckets.is_empty() {
            let bucket_labels: Vec<String> = buckets
                .into_iter()
                .map(|b| {
                    let details: Vec<&str> = self
                        .concern_signals
                        .iter()
                        .filter(|s| s.bucket == b)
                        .take(3)
                        .map(|s| s.detail.as_str())
                        .collect();
                    if details.is_empty() {
                        b.as_str().to_string()
                    } else {
                        format!("{} ({})", b.as_str(), details.join(", "))
                    }
                })
                .collect();
            parts.push(format!("concern_buckets=[{}]", bucket_labels.join("; ")));
        }
        if !self.static_catalog_sites.is_empty() {
            let cat_labels: Vec<String> = self
                .static_catalog_sites
                .iter()
                .map(|c| format!("{}: {} entries ({}B)", c.name, c.entry_count, c.byte_len))
                .collect();
            parts.push(format!(
                "public_types={}, static_catalogs=[{}]",
                self.public_type_count,
                cat_labels.join(", ")
            ));
        }
        if !self.inline_terminal_ui_sites.is_empty() {
            let ui_labels: Vec<String> = self
                .inline_terminal_ui_sites
                .iter()
                .take(3)
                .map(|u| format!("{}: {}", u.kind, u.snippet))
                .collect();
            parts.push(format!("inline_terminal_ui=[{}]", ui_labels.join(", ")));
        }
        if !self.struct_literal_sites.is_empty() {
            let lit_labels: Vec<String> = self
                .struct_literal_sites
                .iter()
                .take(3)
                .map(|s| format!("{} ({} fields)", s.type_name, s.field_names.len()))
                .collect();
            parts.push(format!("struct_literals=[{}]", lit_labels.join(", ")));
        }
        if !self.helper_fingerprints.is_empty() {
            let helper_labels: Vec<String> = self
                .helper_fingerprints
                .iter()
                .take(3)
                .map(|h| {
                    format!(
                        "{} (hash=0x{:08x}, stmts={})",
                        h.name, h.normalized_hash, h.statement_count
                    )
                })
                .collect();
            parts.push(format!(
                "helper_fingerprints=[{}]",
                helper_labels.join(", ")
            ));
        }
        if !self.domain_clusters.is_empty() {
            parts.push(format!(
                "domain_clusters=[{}]",
                self.domain_clusters.join(", ")
            ));
        }
        if self.is_entrypoint || self.entrypoint_statement_count > 0 {
            parts.push(format!(
                "entrypoint_statements={}",
                self.entrypoint_statement_count
            ));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}
