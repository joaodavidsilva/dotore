//! Intermediate representation for React **Subjects** (`SubjectIr` and `FileIr`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; IR extraction matches only relevant AST node kinds"
)]

pub(crate) mod dataflow;
pub(crate) mod extract;
pub(crate) mod react_ast;
pub(crate) mod types;

pub use extract::{inspect_file_semantic, parse_file_ir};
pub use types::{
    ByteSpan, CallerSite, DepRef, DepsSpec, EffectNode, FileContext, FileIr, JsxElementIr,
    SecuritySinkKind, SetterCallSite, SourceLoc, SubjectIr, SubjectKind, SymbolKind, SymbolOutline,
};
pub(crate) use types::{ContextConsumerSiteIr, ContextProviderSiteIr, SemanticRuleSite};
