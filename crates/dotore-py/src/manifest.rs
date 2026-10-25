//! Python manifest (`pyproject.toml` and `requirements.txt`) **Capability Gate** inference.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use dotore_core::{
    Capability, CapabilityGate, PackageRole, config::infer_python_profile_from_pyproject_doc,
};

/// Infers a Python [`CapabilityGate`] for `package_dir` from `pyproject.toml` and `requirements.txt` manifests.
#[must_use]
pub(crate) fn infer_python_capability_gate(
    package_dir: &Path,
    manifest_sources: &[(PathBuf, &str)],
) -> CapabilityGate {
    if manifest_sources.is_empty() {
        return CapabilityGate::default_python();
    }
    let mut gate = CapabilityGate::with_capabilities([Capability::Python]);
    let mut visited_req_files = HashSet::new();

    let mut has_disk_manifest = false;
    for (manifest_path, content) in manifest_sources {
        if manifest_path.is_file() {
            has_disk_manifest = true;
        }
        let file_name = manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if file_name == "pyproject.toml" {
            infer_from_pyproject_toml(content, &mut gate);
        } else if file_name == "py.typed" {
            gate.entrypoints.insert(PathBuf::from("py.typed"));
        } else if file_name == "requirements.txt" || file_name.ends_with(".txt") {
            visited_req_files.insert(manifest_path.clone());
            infer_from_requirements_txt(
                package_dir,
                content,
                manifest_sources,
                &mut visited_req_files,
                &mut gate,
            );
        }
    }

    if has_disk_manifest && directory_contains_py_typed(package_dir, 0) {
        gate.entrypoints.insert(PathBuf::from("py.typed"));
    }
    gate
}

fn infer_from_pyproject_toml(content: &str, gate: &mut CapabilityGate) {
    let Ok(doc) = toml::from_str::<toml::Value>(content) else {
        return;
    };
    match infer_python_profile_from_pyproject_doc(&doc) {
        Some("library") => gate.package_role = PackageRole::Library,
        Some("web" | "cli" | "script") => gate.package_role = PackageRole::Application,
        _ => {}
    }

    // [project]
    if let Some(project) = doc.get("project").and_then(toml::Value::as_table) {
        if let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array) {
            for dep in deps.iter().filter_map(toml::Value::as_str) {
                record_pep508_dependency(dep, gate);
            }
        }
        if let Some(opt_deps) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for group_deps in opt_deps.values().filter_map(toml::Value::as_array) {
                for dep in group_deps.iter().filter_map(toml::Value::as_str) {
                    record_pep508_dependency(dep, gate);
                }
            }
        }
    }

    // [dependency-groups] (PEP 735)
    if let Some(dep_groups) = doc.get("dependency-groups").and_then(toml::Value::as_table) {
        for group_deps in dep_groups.values().filter_map(toml::Value::as_array) {
            for item in group_deps {
                if let Some(dep_str) = item.as_str() {
                    record_pep508_dependency(dep_str, gate);
                }
            }
        }
    }

    // [build-system.requires]
    if let Some(requires) = doc
        .get("build-system")
        .and_then(toml::Value::as_table)
        .and_then(|bs| bs.get("requires"))
        .and_then(toml::Value::as_array)
    {
        for dep in requires.iter().filter_map(toml::Value::as_str) {
            record_pep508_dependency(dep, gate);
        }
    }

    // [tool.*]
    if let Some(tool) = doc.get("tool").and_then(toml::Value::as_table) {
        if let Some(pytest_tbl) = tool.get("pytest").and_then(toml::Value::as_table) {
            gate.capabilities.insert(Capability::Pytest);
            if pytest_tbl
                .get("ini_options")
                .and_then(toml::Value::as_table)
                .is_some_and(|ini| ini.contains_key("asyncio_mode"))
            {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        if tool.contains_key("django") {
            gate.capabilities.insert(Capability::Django);
        }
        if let Some(poetry) = tool.get("poetry").and_then(toml::Value::as_table) {
            infer_from_poetry_table(poetry, gate);
        }
        if let Some(uv) = tool.get("uv").and_then(toml::Value::as_table)
            && let Some(dev_deps) = uv.get("dev-dependencies").and_then(toml::Value::as_array)
        {
            for dep in dev_deps.iter().filter_map(toml::Value::as_str) {
                record_pep508_dependency(dep, gate);
            }
        }
        if let Some(pdm) = tool.get("pdm").and_then(toml::Value::as_table)
            && let Some(dev_deps) = pdm.get("dev-dependencies").and_then(toml::Value::as_table)
        {
            for group_deps in dev_deps.values().filter_map(toml::Value::as_array) {
                for dep in group_deps.iter().filter_map(toml::Value::as_str) {
                    record_pep508_dependency(dep, gate);
                }
            }
        }
    }
}

fn directory_contains_py_typed(dir: &Path, depth: usize) -> bool {
    if depth > 2 {
        return false;
    }
    if dir.join("py.typed").is_file() {
        return true;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.')
                && !matches!(name, "venv" | "node_modules" | "__pycache__" | "tests" | "test" | "docs")
                && directory_contains_py_typed(&path, depth + 1)
            {
                return true;
            }
        }
    }
    false
}

fn infer_from_poetry_table(
    poetry: &toml::map::Map<String, toml::Value>,
    gate: &mut CapabilityGate,
) {
    for section in ["dependencies", "dev-dependencies"] {
        if let Some(deps_tbl) = poetry.get(section).and_then(toml::Value::as_table) {
            for (pkg_name, spec) in deps_tbl {
                record_poetry_dependency(pkg_name, spec, gate);
            }
        }
    }
    let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) else {
        return;
    };
    for group_val in groups.values().filter_map(toml::Value::as_table) {
        let Some(deps_tbl) = group_val
            .get("dependencies")
            .and_then(toml::Value::as_table)
        else {
            continue;
        };
        for (pkg_name, spec) in deps_tbl {
            record_poetry_dependency(pkg_name, spec, gate);
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only string and table dependency specifications carry version/extras metadata"
)]
fn record_poetry_dependency(pkg_name: &str, spec: &toml::Value, gate: &mut CapabilityGate) {
    let mut extras = Vec::new();
    let version = match spec {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(tbl) => {
            if let Some(ext_arr) = tbl.get("extras").and_then(toml::Value::as_array) {
                for ext in ext_arr.iter().filter_map(toml::Value::as_str) {
                    extras.push(ext.to_ascii_lowercase());
                }
            }
            tbl.get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("*")
                .to_string()
        }
        _ => "*".to_string(),
    };
    apply_python_dependency_capabilities(pkg_name, &extras, &version, gate);
}

fn infer_from_requirements_txt(
    package_dir: &Path,
    content: &str,
    manifest_sources: &[(PathBuf, &str)],
    visited: &mut HashSet<PathBuf>,
    gate: &mut CapabilityGate,
) {
    for raw_line in content.lines() {
        let without_comment = raw_line.split('#').next().unwrap_or("").trim();
        if without_comment.is_empty() {
            continue;
        }
        if let Some(included_rel) = without_comment
            .strip_prefix("-r ")
            .or_else(|| without_comment.strip_prefix("--requirement "))
            .map(str::trim)
        {
            let inc_path = package_dir.join(included_rel);
            if visited.insert(inc_path.clone()) {
                if let Some((_, inc_src)) = manifest_sources
                    .iter()
                    .find(|(p, _)| p == &inc_path || p.ends_with(included_rel))
                {
                    infer_from_requirements_txt(
                        package_dir,
                        inc_src,
                        manifest_sources,
                        visited,
                        gate,
                    );
                } else if let Ok(disk_src) = fs::read_to_string(&inc_path) {
                    infer_from_requirements_txt(
                        package_dir,
                        &disk_src,
                        manifest_sources,
                        visited,
                        gate,
                    );
                }
            }
            continue;
        }
        if without_comment.starts_with('-') {
            if let Some(idx) = without_comment.find("#egg=") {
                let egg = &without_comment[idx + 5..];
                record_pep508_dependency(egg, gate);
            }
            continue;
        }
        record_pep508_dependency(without_comment, gate);
    }
}

fn record_pep508_dependency(raw_spec: &str, gate: &mut CapabilityGate) {
    let before_marker = raw_spec.split(';').next().unwrap_or("").trim();
    if before_marker.is_empty() {
        return;
    }

    let (name_and_extras, version_part) = split_pep508_name_and_version(before_marker);
    let (raw_name, extras) = if let Some(bracket_start) = name_and_extras.find('[') {
        let name = name_and_extras[..bracket_start].trim();
        let extras_str = name_and_extras[bracket_start + 1..]
            .split(']')
            .next()
            .unwrap_or("");
        let parsed_extras: Vec<String> = extras_str
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        (name, parsed_extras)
    } else {
        (name_and_extras.trim(), Vec::new())
    };

    if raw_name.is_empty() {
        return;
    }
    let version = if version_part.is_empty() {
        "*"
    } else {
        version_part
    };
    apply_python_dependency_capabilities(raw_name, &extras, version, gate);
}

fn split_pep508_name_and_version(spec: &str) -> (&str, &str) {
    let mut in_brackets = false;
    for (idx, ch) in spec.char_indices() {
        match ch {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            '=' | '<' | '>' | '!' | '~' | '@' | ' ' | '\t' if !in_brackets => {
                return (spec[..idx].trim(), spec[idx..].trim());
            }
            _ => {}
        }
    }
    (spec.trim(), "")
}

fn normalize_python_pkg_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        if ch == '_' || ch == '-' || ch == '.' {
            if !prev_dash && !normalized.is_empty() {
                normalized.push('-');
                prev_dash = true;
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    while normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

fn apply_python_dependency_capabilities(
    raw_name: &str,
    extras: &[String],
    version: &str,
    gate: &mut CapabilityGate,
) {
    let norm = normalize_python_pkg_name(raw_name);
    if norm.is_empty() || norm == "python" {
        return;
    }
    gate.dependencies
        .insert(norm.clone(), version.trim().to_string());

    match norm.as_str() {
        "fastapi" => {
            gate.capabilities.insert(Capability::FastApi);
            gate.capabilities.insert(Capability::Pydantic);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "pydantic" | "pydantic-settings" | "pydantic-core" | "pydantic-extra-types" => {
            gate.capabilities.insert(Capability::Pydantic);
        }
        "sqlmodel" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            gate.capabilities.insert(Capability::Pydantic);
        }
        "sqlalchemy" | "flask-sqlalchemy" | "alembic" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            if extras.iter().any(|e| e == "asyncio") {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        "asyncpg" | "aiosqlite" | "aiomysql" | "aiopg" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "django" | "djangorestframework" | "django-ninja" | "django-environ" | "channels" => {
            gate.capabilities.insert(Capability::Django);
            if norm == "channels" || norm == "django-ninja" {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        "pytest" | "pytest-cov" | "pytest-mock" | "pytest-xdist" => {
            gate.capabilities.insert(Capability::Pytest);
        }
        "pytest-asyncio" | "pytest-trio" => {
            gate.capabilities.insert(Capability::Pytest);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "pytest-django" => {
            gate.capabilities.insert(Capability::Pytest);
            gate.capabilities.insert(Capability::Django);
        }
        "asyncio" | "aiohttp" | "httpx" | "uvicorn" | "starlette" | "anyio" | "trio" | "quart"
        | "sanic" | "litestar" | "motor" => {
            gate.capabilities.insert(Capability::Asyncio);
        }
        _ => {}
    }
}
