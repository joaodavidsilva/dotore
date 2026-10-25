//! `Cargo.toml` **Capability Gate** inference (`Rust`, `Tokio`, `Axum`, `Sqlx`, `Serde`,
//! `Tracing`, `Leptos`, `Dioxus`) and package role classification for `dotore-rs`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use dotore_core::{Capability, CapabilityGate, PackageRole};
use toml::Value;

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
    let has_any_rust_manifest = has_cargo_manifest
        || manifest_sources.iter().any(|(p, _)| {
            let s = p.to_string_lossy().replace('\\', "/");
            s.ends_with("Cargo.lock")
                || s.ends_with(".cargo/config.toml")
                || s.ends_with(".cargo/config")
        });
    let disk_cargo = package_dir.join("Cargo.toml");
    let matches_disk_cargo = manifest_sources.iter().any(|(p, src)| {
        p.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml")
            && fs::read_to_string(&disk_cargo).ok().as_deref() == Some(*src)
    });
    let is_virtual_only = manifest_sources
        .iter()
        .any(|(p, _)| p == Path::new("__virtual__"))
        || (has_any_rust_manifest && !package_dir.is_absolute() && !matches_disk_cargo);
    if !has_cargo_manifest
        && !is_virtual_only
        && let Ok(content) = fs::read_to_string(&disk_cargo)
    {
        loaded_from_disk.push((disk_cargo.clone(), content));
    }

    let own_has_workspace = manifest_sources.iter().any(|(p, src)| {
        p.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml")
            && src.contains("[workspace]")
    }) || loaded_from_disk
        .iter()
        .any(|(_, src)| src.contains("[workspace]"));

    let mut ancestor_cargos = Vec::new();
    if !is_virtual_only
        && !own_has_workspace
        && (!has_cargo_manifest || package_dir.is_absolute() || matches_disk_cargo)
    {
        let mut ancestor_opt = package_dir.parent();
        let mut visited_dot = false;
        while let Some(raw_anc) = ancestor_opt {
            let anc = if raw_anc.as_os_str().is_empty() {
                if visited_dot {
                    break;
                }
                visited_dot = true;
                Path::new(".")
            } else {
                if raw_anc == Path::new(".") {
                    visited_dot = true;
                }
                raw_anc
            };
            let anc_cargo = anc.join("Cargo.toml");
            if anc_cargo.is_file()
                && !manifest_sources.iter().any(|(p, _)| p == &anc_cargo)
                && let Ok(content) = fs::read_to_string(&anc_cargo)
            {
                let found_ws = content.contains("[workspace]");
                ancestor_cargos.push((anc.to_path_buf(), anc_cargo, content));
                if found_ws {
                    break;
                }
            }
            ancestor_opt = if visited_dot && raw_anc.as_os_str().is_empty() {
                None
            } else {
                raw_anc.parent()
            };
        }
    }

    if !has_any_rust_manifest && loaded_from_disk.is_empty() && ancestor_cargos.is_empty() {
        return CapabilityGate::default_rust();
    }

    let mut gate = CapabilityGate::with_capabilities([Capability::Rust]);
    if is_virtual_only {
        gate.dependencies
            .insert("__virtual_only".to_string(), "true".to_string());
    }

    for (path, src) in manifest_sources {
        let norm_p = path.to_string_lossy().replace('\\', "/");
        if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml") {
            apply_cargo_toml_str(&mut gate, src, false);
            let is_pkg_manifest = path.parent().unwrap_or_else(|| Path::new(".")) == package_dir
                || (package_dir == Path::new(".") && path == Path::new("Cargo.toml"))
                || !gate.dependencies.contains_key("__manifest:Cargo.toml");
            if is_pkg_manifest {
                gate.dependencies
                    .insert("__manifest:Cargo.toml".to_string(), (*src).to_string());
                gate.dependencies
                    .insert("__manifest_path:Cargo.toml".to_string(), norm_p);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock") {
            gate.dependencies
                .insert("__manifest:Cargo.lock".to_string(), (*src).to_string());
            gate.dependencies
                .insert("__manifest_path:Cargo.lock".to_string(), norm_p);
        } else if norm_p.ends_with(".cargo/config.toml") || norm_p.ends_with(".cargo/config") {
            gate.dependencies.insert(
                "__manifest:.cargo/config.toml".to_string(),
                (*src).to_string(),
            );
            gate.dependencies
                .insert("__manifest_path:.cargo/config.toml".to_string(), norm_p);
        }
    }

    for (path, src) in &loaded_from_disk {
        apply_cargo_toml_str(&mut gate, src, false);
        if !gate.dependencies.contains_key("__manifest:Cargo.toml") {
            gate.dependencies
                .insert("__manifest:Cargo.toml".to_string(), src.clone());
            gate.dependencies.insert(
                "__manifest_path:Cargo.toml".to_string(),
                path.to_string_lossy().to_string(),
            );
        }
    }

    for (_, _, src) in &ancestor_cargos {
        apply_cargo_toml_str(&mut gate, src, true);
    }

    populate_disk_lockfile_and_cargo_config(package_dir, &ancestor_cargos, is_virtual_only, &mut gate);

    if gate.package_role == PackageRole::Unknown
        && gate.dependencies.contains_key("__manifest:Cargo.toml")
    {
        if !is_virtual_only && package_dir.join("src/main.rs").is_file() {
            gate.package_role = PackageRole::Application;
        } else {
            gate.package_role = PackageRole::Library;
        }
    }

    gate
}

fn populate_disk_lockfile_and_cargo_config(
    package_dir: &Path,
    ancestor_cargos: &[(PathBuf, PathBuf, String)],
    is_virtual_only: bool,
    gate: &mut CapabilityGate,
) {
    if is_virtual_only {
        return;
    }
    let ws_root = ancestor_cargos
        .last()
        .map_or(package_dir, |(anc_dir, _, _)| anc_dir.as_path());
    let owns_ws = ws_root == package_dir;
    gate.dependencies.insert(
        "__owns_workspace_manifests".to_string(),
        if owns_ws { "true" } else { "false" }.to_string(),
    );
    gate.dependencies.insert(
        "__workspace_root".to_string(),
        ws_root.to_string_lossy().to_string(),
    );

    if !gate.dependencies.contains_key("__manifest:Cargo.lock") {
        for candidate in [package_dir.join("Cargo.lock"), ws_root.join("Cargo.lock")] {
            if let Ok(lock_str) = fs::read_to_string(&candidate) {
                gate.dependencies
                    .insert("__manifest:Cargo.lock".to_string(), lock_str);
                gate.dependencies.insert(
                    "__manifest_path:Cargo.lock".to_string(),
                    candidate.to_string_lossy().to_string(),
                );
                break;
            }
        }
    }

    if !gate
        .dependencies
        .contains_key("__manifest:.cargo/config.toml")
    {
        for candidate in [
            package_dir.join(".cargo/config.toml"),
            package_dir.join(".cargo/config"),
            ws_root.join(".cargo/config.toml"),
            ws_root.join(".cargo/config"),
        ] {
            if let Ok(cfg_str) = fs::read_to_string(&candidate) {
                gate.dependencies
                    .insert("__manifest:.cargo/config.toml".to_string(), cfg_str);
                gate.dependencies.insert(
                    "__manifest_path:.cargo/config.toml".to_string(),
                    candidate.to_string_lossy().to_string(),
                );
                break;
            }
        }
    }
}

fn apply_cargo_toml_str(gate: &mut CapabilityGate, cargo_toml_str: &str, is_ancestor_ws: bool) {
    let Ok(doc) = toml::from_str::<Value>(cargo_toml_str) else {
        return;
    };
    let Some(root_table) = doc.as_table() else {
        return;
    };

    if !is_ancestor_ws {
        if root_table.contains_key("bin") {
            gate.package_role = PackageRole::Application;
        } else if root_table.contains_key("lib") && gate.package_role == PackageRole::Unknown {
            gate.package_role = PackageRole::Library;
        }
    }

    record_manifest_clippy_allows_and_profile(gate, root_table);

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

fn record_manifest_clippy_allows_and_profile(
    gate: &mut CapabilityGate,
    root_table: &toml::map::Map<String, Value>,
) {
    for clippy_table in [
        root_table
            .get("lints")
            .and_then(Value::as_table)
            .and_then(|t| t.get("clippy"))
            .and_then(Value::as_table),
        root_table
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|w| w.get("lints"))
            .and_then(Value::as_table)
            .and_then(|l| l.get("clippy"))
            .and_then(Value::as_table),
    ]
    .into_iter()
    .flatten()
    {
        for key in ["too_many_lines", "cognitive_complexity"] {
            let is_allow = clippy_table.get(key).is_some_and(|v| {
                v.as_str() == Some("allow")
                    || v.as_table()
                        .and_then(|t| t.get("level"))
                        .and_then(Value::as_str)
                        == Some("allow")
            });
            if is_allow {
                gate.dependencies
                    .insert(format!("__allow_clippy:{key}"), "true".to_string());
            }
        }
    }

    if let Some(release_tbl) = root_table
        .get("profile")
        .and_then(Value::as_table)
        .and_then(|p| p.get("release"))
        .and_then(Value::as_table)
        && release_tbl
            .get("overflow-checks")
            .and_then(Value::as_bool)
            == Some(true)
    {
        gate.dependencies.insert(
            "__workspace_release_overflow_checks".to_string(),
            "true".to_string(),
        );
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
            if pkg_name != dep_key {
                gate.dependencies
                    .insert(format!("alias:{dep_key}"), pkg_name.to_string());
            }
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
        "reqwest" => &[Capability::Reqwest],
        "diesel" | "diesel-async" => &[Capability::Diesel],
        "sea-orm" | "sea-query" => &[Capability::SeaOrm],
        "rusqlite" => &[Capability::Rusqlite],
        "postgres" | "tokio-postgres" | "deadpool-postgres" => &[Capability::Postgres],
        "futures" | "futures-util" | "futures-executor" | "futures-core" => &[Capability::Futures],
        "tower-http" => &[Capability::TowerHttp],
        "actix-cors" => &[Capability::ActixCors],
        "cookie" | "tower-cookies" => &[Capability::Cookie],
        "jsonwebtoken" => &[Capability::Jsonwebtoken],
        _ => &[],
    };

    for &cap in caps {
        gate.capabilities.insert(cap);
    }
}
