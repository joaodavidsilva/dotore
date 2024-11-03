//! Intermediate representation for React **Subjects** (`SubjectIr` and `FileIr`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; IR extraction matches only relevant AST node kinds"
)]

pub(crate) mod dataflow;
pub(crate) mod extract;
pub(crate) mod react_ast;
pub(crate) mod types;

pub(crate) use extract::parse_file_ir;
pub use types::{ByteSpan, SourceLoc, SubjectKind};
pub(crate) use types::{
    CallerSite, DepRef, DepsSpec, EffectNode, FileIr, SetterCallSite, SubjectIr,
};
