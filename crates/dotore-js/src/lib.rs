//! JavaScript, TypeScript, and React single-pass static analyzer (`JsLanguageAnalyzer`)
//! implementing [`dotore_core::LanguageAnalyzer`].

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

pub use dotore_core::config;
use dotore_core::{
    config::{
        Capability, CapabilityGate, DotoreConfig, WorkspacePackage, content_enables_react_compiler,
    },
    ir::{ExtractedFile, LanguageAnalyzer, LanguageId, PackageAnalysisResult, SymbolOutline},
    rules::{Diagnostic, RuleId},
    scanner::JS_SOURCE_EXTENSIONS,
};

/// Cross-file JSX caller index and multi-effect **Render Cascade** solver.
pub mod graph;
/// React **Subject**, **State Slot**, **Effect Node**, and **Caller Site** IR.
pub mod ir;
/// [`dotore_core::PlannerContext`] implementation for [`ProjectGraph`] and cross-file autofix enrichment.
pub mod planner;
/// Diagnostic rules engine over [`SubjectIr`] and [`ProjectGraph`].
pub mod rules;

pub use graph::{ProjectGraph, ResolvedCallerSite};
pub use ir::{
    BlockDisableRange, ByteSpan, CallerSite, ContextualOwnerSpansIr, DepRef, DepsSpec, EffectNode,
    FileContext, FileIr, FileSuppressions, JsxElementIr, LineDisableDirective, OpenerLineRange,
    RelatedHookOwnerSpanIr, SecuritySinkKind, SetterCallSite, SourceLoc, SubjectEffectOwner,
    SubjectIr, SubjectKind, SymbolKind, classify_file_context, compute_line_starts,
    inspect_file_semantic, loc_from_line_starts, parse_file_ir,
};
pub use planner::enrich_cross_file_autofixes;
pub use rules::{
    AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, FixCapsule,
    PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleMetadata, RuleSeverity,
    RuleSeverityOverride, RuleTag, SourceExcerpt, evaluate_file_in_package, evaluate_project,
    evaluate_project_graph_rules, evaluate_project_with_packages,
    reduced_motion::evaluate_project_reduced_motion, rule_registry, supply_chain_purl_hash,
};

/// Single-pass JavaScript, TypeScript, and React [`LanguageAnalyzer`] powered by `oxc_parser` and `oxc_semantic`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsLanguageAnalyzer;

impl JsLanguageAnalyzer {
    /// Creates a new [`JsLanguageAnalyzer`] instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Registers `dotore-js` syntax validation and symbol outline extraction hooks with `dotore-core`.
    pub fn register_core_hooks() {
        dotore_core::fixer::register_default_syntax_validator(source_parses_cleanly);
        dotore_core::search::register_default_symbol_extractor(extract_js_symbol_outlines);
    }

    /// Reconstructs a [`ProjectGraph`] from already-extracted [`ExtractedFile`] payloads and raw manifests
    /// without re-parsing JS/TS sources.
    #[must_use]
    pub fn build_graph_from_extracted(
        &self,
        files: &[ExtractedFile],
        manifests: HashMap<PathBuf, String>,
    ) -> ProjectGraph {
        let mut file_irs = Vec::with_capacity(files.len());
        for file in files {
            if let Some(ir) = file.downcast_payload::<FileIr>() {
                file_irs.push(ir.clone());
            } else if self.supports_path(&file.path)
                || matches!(
                    file.path.extension().and_then(|e| e.to_str()),
                    Some("css" | "scss" | "html" | "htm")
                )
            {
                file_irs.push(parse_file_ir(&file.path, &file.source));
            }
        }
        ProjectGraph::build_with_manifests(file_irs, manifests)
    }

    /// Evaluates a single [`ExtractedFile`] under an explicit [`DotoreConfig`] and [`CapabilityGate`].
    #[must_use]
    pub fn analyze_single_file(
        &self,
        file: &ExtractedFile,
        package_root: &Path,
        gate: &CapabilityGate,
        config: &DotoreConfig,
        enabled_rules: Option<&[RuleId]>,
    ) -> Vec<Diagnostic> {
        let file_ir = file
            .downcast_payload::<FileIr>()
            .cloned()
            .unwrap_or_else(|| parse_file_ir(&file.path, &file.source));
        let graph = ProjectGraph::build(vec![file_ir]);
        let mut diagnostics = Vec::new();
        if let Some(first_file) = graph.files.first() {
            evaluate_file_in_package(
                &graph,
                first_file,
                package_root,
                gate,
                config,
                enabled_rules,
                &mut diagnostics,
            );
        }
        diagnostics
    }
}

impl LanguageAnalyzer for JsLanguageAnalyzer {
    fn language_id(&self) -> LanguageId {
        LanguageId::JavaScript
    }

    fn supports_path(&self, path: &Path) -> bool {
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            return false;
        };
        if !JS_SOURCE_EXTENSIONS.contains(&ext) {
            return false;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        !file_name.ends_with(".d.ts")
            && !file_name.ends_with(".d.mts")
            && !file_name.ends_with(".d.cts")
            && !file_name.starts_with("dotore.config.")
    }

    fn manifest_filenames(&self) -> &'static [&'static str] {
        &["package.json", "angular.json"]
    }

    fn infer_capability_gate(
        &self,
        package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        let has_angular_json = package_dir.join("angular.json").is_file()
            || manifest_sources
                .iter()
                .any(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some("angular.json"));
        let pkg_json_source = manifest_sources.iter().find_map(|(path, src)| {
            let name = path.file_name().and_then(|n| n.to_str())?;
            (name == "package.json").then_some(*src)
        });
        let mut gate = if let Some(json) = pkg_json_source {
            CapabilityGate::from_package_json_str(json)
        } else if has_angular_json && !package_dir.join("package.json").is_file() {
            CapabilityGate::default_angular()
        } else {
            CapabilityGate::discover(package_dir)
        };

        if package_dir.join("tsconfig.json").is_file()
            || manifest_sources
                .iter()
                .any(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some("tsconfig.json"))
        {
            gate.capabilities.insert(Capability::TypeScript);
        }
        if has_angular_json {
            gate.capabilities.insert(Capability::Angular);
            gate.capabilities.insert(Capability::Rxjs);
            gate.capabilities.insert(Capability::TypeScript);
        }
        if manifest_sources.iter().any(|(p, src)| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_compiler_config_filename)
                && content_enables_react_compiler(src)
        }) {
            gate.has_react_compiler = true;
            gate.capabilities.insert(Capability::ReactCompiler);
        }
        gate
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        parse_file_ir(path, source).into_extracted_file()
    }

    fn analyze_package(
        &self,
        package: &WorkspacePackage,
        files: &[ExtractedFile],
        enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult {
        let mut file_irs = Vec::with_capacity(files.len());
        let mut sources = HashMap::with_capacity(files.len());
        for file in files {
            sources.insert(file.path.clone(), file.source.clone());
            if let Some(ir) = file.downcast_payload::<FileIr>() {
                file_irs.push(ir.clone());
            } else if self.supports_path(&file.path)
                || matches!(
                    file.path.extension().and_then(|e| e.to_str()),
                    Some("css" | "scss" | "html" | "htm")
                )
            {
                file_irs.push(parse_file_ir(&file.path, &file.source));
            }
        }
        let subjects_scanned: usize = file_irs.iter().map(|f| f.subjects.len()).sum();
        let effects_scanned: usize = file_irs
            .iter()
            .flat_map(|f| &f.subjects)
            .map(|s| s.effect_nodes.len())
            .sum();
        let graph = ProjectGraph::build(file_irs);
        let mut diagnostics = evaluate_project_with_packages(
            &graph,
            std::slice::from_ref(package),
            enabled_rules,
        );
        enrich_cross_file_autofixes(&graph, &mut diagnostics, &sources);
        PackageAnalysisResult {
            diagnostics,
            subjects_scanned,
            effects_scanned,
        }
    }

    fn validate_syntax(&self, path: &Path, source: &str) -> bool {
        source_parses_cleanly(path, source)
    }
}

/// Returns `true` if `source` at `path` parses with zero syntax diagnostics under `oxc_parser`.
#[must_use]
pub fn source_parses_cleanly(path: &Path, source: &str) -> bool {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_default()
        .with_jsx(true)
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    parsed.diagnostics.is_empty()
}

/// Extracts **Symbol Outlines** for a JS/TS file using single-pass `oxc` extraction.
#[must_use]
pub fn extract_js_symbol_outlines(path: &Path, source: &str) -> Vec<SymbolOutline> {
    parse_file_ir(path, source).symbol_outlines
}

/// Returns `true` if `file_name` is a bundler/compiler configuration file that may enable React Compiler.
#[must_use]
pub fn is_compiler_config_filename(file_name: &str) -> bool {
    file_name.starts_with("next.config.")
        || file_name.starts_with("babel.config.")
        || file_name.starts_with(".babelrc")
        || file_name.starts_with("vite.config.")
        || file_name == "app.json"
        || file_name.starts_with("app.config.")
}
