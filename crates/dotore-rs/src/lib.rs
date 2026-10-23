//! Single-pass Rust (`syn`) analyzer (`RsLanguageAnalyzer`), `Cargo.toml` **Capability Gate**
//! discovery, and core Rust safety rule detectors for `dotore`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use dotore_core::{
    Capability, CapabilityGate, Diagnostic, DotoreConfig, ExtractedFile, LanguageAnalyzer,
    LanguageId, PackageAnalysisResult, PackageRole, RuleId, WorkspacePackage,
};
use toml::Value;

/// Single-pass `syn` AST and scope extraction for `.rs` files.
pub mod ir;
/// Rule activation and evaluation for Rust rules.
pub mod rules;
/// Single-pass detectors for Axum, SQLx, Leptos/Dioxus UI signals, and boolean parameter architecture rules.
pub mod axum_sqlx_ui_arch;
/// Crate-level `ProjectGraph` analysis for `dotore-rs` (`rs-arch-no-unused-pub-crate-items`).
pub mod graph;

pub use ir::{RsCandidateFinding, RsFileIr, RsSubjectIr, RsSubjectKind, extract_rs_file};
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

/// Infers a Rust [`CapabilityGate`] from `Cargo.toml` manifest sources.
#[must_use]
pub fn infer_cargo_toml_capability_gate(
    package_dir: &Path,
    manifest_sources: &[(PathBuf, &str)],
) -> CapabilityGate {
    let mut loaded_from_disk = Vec::new();

    let has_cargo_manifest = manifest_sources.iter().any(|(p, _)| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "Cargo.toml")
    });
    if !has_cargo_manifest {
        let disk_cargo = package_dir.join("Cargo.toml");
        if let Ok(content) = fs::read_to_string(&disk_cargo) {
            loaded_from_disk.push((disk_cargo, content));
        }
    }

    // Check ancestor directories on disk for workspace root `[workspace.dependencies]`
    if !has_cargo_manifest || package_dir.is_absolute() {
        let mut ancestor_opt = package_dir.parent();
        while let Some(anc) = ancestor_opt {
            if anc.as_os_str().is_empty() {
                break;
            }
            let anc_cargo = anc.join("Cargo.toml");
            if anc_cargo.is_file()
                && !manifest_sources.iter().any(|(p, _)| p == &anc_cargo)
                && let Ok(content) = fs::read_to_string(&anc_cargo)
            {
                loaded_from_disk.push((anc_cargo, content));
            }
            ancestor_opt = anc.parent();
        }
    }

    if !has_cargo_manifest && loaded_from_disk.is_empty() {
        return CapabilityGate::default_rust();
    }

    let mut gate = CapabilityGate::with_capabilities([Capability::Rust]);

    for (path, src) in manifest_sources {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "Cargo.toml")
        {
            apply_cargo_toml_str(&mut gate, src);
        }
    }
    for (_, src) in &loaded_from_disk {
        apply_cargo_toml_str(&mut gate, src);
    }

    gate
}

fn apply_cargo_toml_str(gate: &mut CapabilityGate, cargo_toml_str: &str) {
    let Ok(doc) = toml::from_str::<Value>(cargo_toml_str) else {
        return;
    };
    let Some(root_table) = doc.as_table() else {
        return;
    };

    if root_table.contains_key("bin") {
        gate.package_role = PackageRole::Application;
    } else if root_table.contains_key("lib") && gate.package_role == PackageRole::Unknown {
        gate.package_role = PackageRole::Library;
    }

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(Value::Table(dep_table)) = root_table.get(section) {
            collect_cargo_dep_table(gate, dep_table);
        }
    }

    if let Some(Value::Table(ws_table)) = root_table.get("workspace")
        && let Some(Value::Table(ws_deps)) = ws_table.get("dependencies")
    {
        collect_cargo_dep_table(gate, ws_deps);
    }

    if let Some(Value::Table(targets_table)) = root_table.get("target") {
        for target_cfg in targets_table.values().filter_map(Value::as_table) {
            collect_target_cfg_deps(gate, target_cfg);
        }
    }
}

fn collect_target_cfg_deps(gate: &mut CapabilityGate, target_cfg: &toml::map::Map<String, Value>) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(Value::Table(dep_table)) = target_cfg.get(section) {
            collect_cargo_dep_table(gate, dep_table);
        }
    }
}

fn collect_cargo_dep_table(gate: &mut CapabilityGate, dep_table: &toml::map::Map<String, Value>) {
    for (dep_key, dep_val) in dep_table {
        let mut version = "*".to_string();
        let mut actual_pkg: Option<&str> = None;

        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Cargo dependency entries are either version strings or inline specification tables"
        )]
        match dep_val {
            Value::String(ver_str) => {
                version.clone_from(ver_str);
            }
            Value::Table(spec) => {
                if let Some(Value::String(ver_str)) = spec.get("version") {
                    version.clone_from(ver_str);
                }
                if let Some(Value::String(pkg_name)) = spec.get("package") {
                    actual_pkg = Some(pkg_name.as_str());
                }
            }
            _ => {}
        }

        record_rust_dep_and_capabilities(gate, dep_key, &version);
        if let Some(pkg_name) = actual_pkg {
            record_rust_dep_and_capabilities(gate, pkg_name, &version);
        }
    }
}

fn record_rust_dep_and_capabilities(gate: &mut CapabilityGate, raw_name: &str, version: &str) {
    let normalized = raw_name.trim().to_ascii_lowercase().replace('_', "-");
    if !gate.dependencies.contains_key(raw_name) || version != "*" {
        gate.dependencies
            .insert(raw_name.to_string(), version.to_string());
    }

    let caps: &[Capability] = match normalized.as_str() {
        "tokio" | "tokio-util" | "tokio-stream" => &[Capability::Tokio],
        "axum" | "axum-extra" | "axum-core" => &[Capability::Axum],
        "sqlx" | "sqlx-core" | "sqlx-postgres" | "sqlx-mysql" | "sqlx-sqlite" => {
            &[Capability::Sqlx]
        }
        "serde" | "serde-json" | "serde-derive" => &[Capability::Serde],
        "tracing" | "tracing-subscriber" | "tracing-futures" | "tracing-appender" => {
            &[Capability::Tracing]
        }
        "leptos" | "leptos-reactive" | "leptos-router" | "leptos-meta" => &[Capability::Leptos],
        "dioxus" | "dioxus-hooks" | "dioxus-web" | "dioxus-desktop" | "dioxus-fullstack" => {
            &[Capability::Dioxus]
        }
        "actix-web" => &[Capability::ActixWeb],
        "clap" => &[Capability::Clap],
        "tauri" => &[Capability::Tauri],
        _ => &[],
    };

    for &cap in caps {
        gate.capabilities.insert(cap);
    }
}
