//! Single-pass Rust (`syn`) analyzer (`RsLanguageAnalyzer`), `Cargo.toml` **Capability Gate**
//! discovery, and Rust rule detectors for `dotore`.

use std::path::{Path, PathBuf};

use dotore_core::{
    CapabilityGate, Diagnostic, DotoreConfig, ExtractedFile, LanguageAnalyzer, LanguageId,
    PackageAnalysisResult, RuleId, WorkspacePackage,
};

/// Single-pass detectors for Axum shared state contention and SQLx query hazards.
pub(crate) mod axum_sqlx;
/// Crate-level `ProjectGraph` analysis for `dotore-rs` (`rs-arch-no-unused-pub-crate-items`).
pub(crate) mod graph;
/// Single-pass `syn` AST, **Subject**, **Symbol Outline**, and suppression extraction for `.rs` files.
pub(crate) mod ir;
/// `Cargo.toml` **Capability Gate** inference and package role classification.
pub(crate) mod manifest;
/// Shared `syn` AST, type, attribute, span/line, and lexical-scope matchers and diagnostic helpers.
pub(crate) mod matchers;
/// Single-pass detectors for Rust allocation and hot-loop performance rules.
pub(crate) mod perf;
/// Rule activation gating and evaluation dispatcher for Rust rules.
pub(crate) mod rules;
/// Single-pass detectors for the 5 core production Rust safety rules.
pub(crate) mod safety;
/// Lexical `use`-alias and 8-hop local `let`/`const` binding resolver (`SourceKernel`).
pub(crate) mod source_kernel;
/// Local `let`/`const` binding resolver and `KernelContext` for `SourceKernel`.
pub(crate) mod source_kernel_bindings;
/// Single-pass `SourceKernel` detectors for async runtime, HTTP, TLS, shell, secret, CORS, cookie, and JWT rules.
pub(crate) mod source_kernel_detectors;
/// Single-pass detectors for Tokio async concurrency hazards.
pub(crate) mod tokio_async;
/// Single-pass detectors for Leptos/Dioxus reactive signals and boolean parameter rules.
pub(crate) mod ui_signals;

pub use ir::{RsCandidateFinding, RsFileIr, RsSubjectIr, RsSubjectKind, extract_rs_file};
pub use manifest::infer_cargo_toml_capability_gate;
pub use perf::TOKIO_AND_PERF_RULES;
pub use rules::{CORE_RUST_SAFETY_RULES, evaluate_rs_file, evaluate_rs_package};

/// Rust language analyzer implementing [`LanguageAnalyzer`] for `.rs` files and `Cargo.toml` manifests.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsLanguageAnalyzer;

impl LanguageAnalyzer for RsLanguageAnalyzer {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn supports_path(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    }

    fn manifest_filenames(&self) -> &'static [&'static str] {
        &["Cargo.toml"]
    }

    fn infer_capability_gate(
        &self,
        package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        infer_cargo_toml_capability_gate(package_dir, manifest_sources)
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        extract_rs_file(path, source)
    }

    fn analyze_package(
        &self,
        package: &WorkspacePackage,
        files: &[ExtractedFile],
        enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult {
        evaluate_rs_package(package, files, enabled_rules)
    }

    fn validate_syntax(&self, _path: &Path, source: &str) -> bool {
        syn::parse_file(source).is_ok()
    }
}

/// Analyzes a single in-memory Rust `.rs` source file and returns its [`Diagnostic`]s.
#[must_use]
pub fn analyze_rs_source(
    path: &Path,
    source: &str,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let config = DotoreConfig::default();
    let gate = CapabilityGate::default_rust();
    analyze_rs_source_with_config(path, source, &config, &gate, enabled_rules)
}

/// Analyzes a single in-memory Rust `.rs` source file under an explicit [`DotoreConfig`] and [`CapabilityGate`].
#[must_use]
pub fn analyze_rs_source_with_config(
    path: &Path,
    source: &str,
    config: &DotoreConfig,
    gate: &CapabilityGate,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let extracted = extract_rs_file(path, source);
    let pkg_root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let pkg = WorkspacePackage {
        name: "default".to_string(),
        root_dir: pkg_root.to_path_buf(),
        capability_gate: gate.clone(),
        config: config.clone(),
    };
    evaluate_rs_package(&pkg, &[extracted], enabled_rules).diagnostics
}

#[cfg(test)]
mod tests {
    use dotore_core::{compute_line_starts, fixer::apply_patches_to_source_with_analyzers};

    use super::*;

    #[test]
    fn dedicated_rule_submodules_extract_their_domain_findings_independently() {
        let source = r#"
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use regex::Regex;
use axum::extract::State;

pub struct SharedState {
    pub lock: Mutex<Vec<String>>,
}

pub(crate) fn unused_helper() {}

pub async fn handler(
    State(state): State<Arc<SharedState>>,
    pool: &sqlx::PgPool,
    items: &[String],
    flag_a: bool,
    flag_b: bool,
    flag_c: bool,
) {
    let _ = items[0];
    let (_tx, _rx) = mpsc::unbounded_channel::<u32>();
    let _re = Regex::new("^a+$").unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let mut out = Vec::new();
    for item in items {
        out.push(item.clone());
        let q = format!("SELECT * FROM t WHERE id = '{item}'");
        let _ = sqlx::query(&q).fetch_all(pool).await;
    }
    create_effect(move |_| {
        let v = count.get();
        doubled.set(v * 2);
    });
}
"#;
        let ast = syn::parse_file(source).unwrap_or_else(|e| panic!("valid syn parse: {e}"));
        let lines: Vec<&str> = source.lines().collect();
        let starts = compute_line_starts(source);

        let mut safety_out = Vec::new();
        safety::extract_safety_findings(&ast, &lines, &starts, &mut safety_out);
        assert!(
            safety_out
                .iter()
                .any(|f| f.rule == RuleId::RsNoUnguardedSliceIndex)
        );
        assert!(
            safety_out
                .iter()
                .any(|f| f.rule == RuleId::RsNoUnwrapInProduction)
        );

        let mut tokio_out = Vec::new();
        tokio_async::extract_tokio_async_findings(&ast, source, &starts, &mut tokio_out);
        assert!(
            tokio_out
                .iter()
                .any(|f| f.rule == RuleId::RsTokioNoBlockingInAsync && f.autofix.is_some())
        );
        assert!(
            tokio_out
                .iter()
                .any(|f| f.rule == RuleId::RsTokioPreferBoundedChannel)
        );

        let mut perf_out = Vec::new();
        perf::extract_perf_findings(&ast, &starts, &mut perf_out);
        assert!(
            perf_out
                .iter()
                .any(|f| f.rule == RuleId::RsPerfHoistRegexToLazylock)
        );
        assert!(
            perf_out
                .iter()
                .any(|f| f.rule == RuleId::RsPerfPreferVecWithCapacity)
        );
        assert!(
            perf_out
                .iter()
                .any(|f| f.rule == RuleId::RsPerfNoCloneInLoop)
        );

        let mut axum_sqlx_out = Vec::new();
        axum_sqlx::extract_axum_sqlx_findings(&ast, &starts, &mut axum_sqlx_out);
        assert!(
            axum_sqlx_out
                .iter()
                .any(|f| f.rule == RuleId::RsAxumNoContendedMutexState)
        );
        assert!(
            axum_sqlx_out
                .iter()
                .any(|f| f.rule == RuleId::RsSqlxNoFormattedQueryString)
        );
        assert!(
            axum_sqlx_out
                .iter()
                .any(|f| f.rule == RuleId::RsSqlxNoQueryInLoop)
        );

        let mut ui_out = Vec::new();
        ui_signals::extract_ui_and_arch_findings(&ast, &starts, &mut ui_out);
        assert!(
            ui_out
                .iter()
                .any(|f| f.rule == RuleId::RsUiNoDerivedSignalInEffect)
        );
        assert!(
            ui_out
                .iter()
                .any(|f| f.rule == RuleId::RsArchNoManyBooleanParams)
        );

        let graph_ir = graph::extract_file_graph_ir(&ast, source, &starts);
        let first_pub_crate: &graph::PubCrateItemIr = &graph_ir.pub_crate_items[0];
        assert_eq!(graph_ir.pub_crate_items.len(), 1);
        assert_eq!(first_pub_crate.name, "unused_helper");

        // Verify Autofix round-trip on RsTokioNoBlockingInAsync
        let diags = analyze_rs_source(
            Path::new("src/handler.rs"),
            source,
            Some(&[RuleId::RsTokioNoBlockingInAsync]),
        );
        assert_eq!(diags.len(), 1);
        let analyzers: [&dyn LanguageAnalyzer; 1] = [&RsLanguageAnalyzer];
        let (fixed, applied) = apply_patches_to_source_with_analyzers(source, &diags, &analyzers);
        assert_eq!(applied.len(), 1);
        assert!(fixed.contains("tokio::time::sleep(Duration::from_millis(5)).await"));
    }
}
