//! Intermediate representation for React **Subjects** (`SubjectIr` and `FileIr`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; IR extraction matches only relevant AST node kinds"
)]

pub(crate) mod dataflow;
pub(crate) mod extract;
pub(crate) mod jsx_subtree;
pub(crate) mod module_ir;
pub(crate) mod motion_and_frame_loop;
pub(crate) mod outlines_and_suppressions;
pub(crate) mod react_ast;
pub(crate) mod subject;
pub(crate) mod types;
pub use extract::{inspect_file_semantic, parse_file_ir};
pub use types::{
    BlockDisableRange, ByteSpan, CallerSite, ContextualOwnerSpansIr, DepRef, DepsSpec, EffectNode,
    ExtractedFile, FileContext, FileIr, FileSuppressions, JsxElementIr, LanguageAnalyzer,
    LanguageId, LineDisableDirective, OpenerLineRange, PackageAnalysisResult,
    RelatedHookOwnerSpanIr, SecuritySinkKind, SetterCallSite, SourceLoc, SubjectEffectOwner,
    SubjectIr, SubjectKind, SymbolKind, SymbolOutline, classify_file_context, compute_line_starts,
    loc_from_line_starts,
};
pub(crate) use types::{ContextConsumerSiteIr, ContextProviderSiteIr, SemanticRuleSite};
