//! CI workflow automation (`dotore ci`) and `/dotore` agent skill / git hook installer (`dotore install`).

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// Supported CI provider backends for `dotore ci`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiProviderKind {
    /// GitHub Actions (`.github/workflows/dotore.yml`).
    GithubActions,
    /// GitLab CI/CD (`.gitlab-ci.yml`).
    GitlabCi,
}

impl CiProviderKind {
    /// Canonical kebab-case identifier (`"github-actions"` or `"gitlab-ci"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubActions => "github-actions",
            Self::GitlabCi => "gitlab-ci",
        }
    }

    /// Parses a CI provider identifier string.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "github-actions" | "github" | "gha" => Some(Self::GithubActions),
            "gitlab-ci" | "gitlab" => Some(Self::GitlabCi),
            _ => None,
        }
    }
}

/// Options for `dotore ci install | upgrade | config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiOptions {
    /// Target repository directory.
    pub cwd: PathBuf,
    /// Explicit CI provider override (`None` auto-detects or defaults to GitHub Actions).
    pub provider: Option<CiProviderKind>,
    /// Optional gate blocking level (`"none"`, `"warning"`, or `"error"`).
    pub blocking: Option<String>,
    /// Optional diff scope (`"changed"`, `"contextual"`, `"lines"`, or `"full"`).
    pub scope: Option<String>,
}

/// Outcome of running `ci_install`, `ci_upgrade`, or `ci_config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiActionResult {
    /// Selected CI provider.
    pub provider: CiProviderKind,
    /// Path to the workflow configuration file.
    pub workflow_path: PathBuf,
    /// Action status (`"created"`, `"exists"`, `"updated"`, `"upgraded"`, `"unchanged"`, `"not-needed"`).
    pub status: String,
    /// Effective `--blocking` level in the workflow.
    pub blocking: String,
    /// Effective `--scope` setting in the workflow.
    pub scope: String,
}

/// Generates a CI pull-request workflow (`.github/workflows/dotore.yml` or `.gitlab-ci.yml`).
///
/// # Errors
/// Returns an error message if `--blocking` or `--scope` is invalid or writing the workflow fails.
pub fn ci_install(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let blocking = validate_ci_blocking(options.blocking.as_deref().unwrap_or("none"))?;
    let scope = validate_ci_scope(options.scope.as_deref().unwrap_or("changed"))?;
    let wf_path = ci_workflow_path(&options.cwd, provider);

    if wf_path.is_file() {
        return Ok(CiActionResult {
            provider,
            workflow_path: wf_path,
            status: "exists".to_string(),
            blocking,
            scope,
        });
    }

    if let Some(parent) = wf_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let content = render_ci_workflow(provider, &blocking, &scope);
    fs::write(&wf_path, content)
        .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;

    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: "created".to_string(),
        blocking,
        scope,
    })
}

/// Upgrades an existing CI workflow file in place to the latest `dotore` v2 configuration.
///
/// # Errors
/// Returns an error message if no workflow file exists or writing fails.
pub fn ci_upgrade(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let wf_path = ci_workflow_path(&options.cwd, provider);
    if !wf_path.is_file() {
        return Err(format!(
            "No CI workflow found at {}. Run `dotore ci install` first.",
            wf_path.display()
        ));
    }
    let existing = fs::read_to_string(&wf_path)
        .map_err(|e| format!("Failed to read {}: {e}", wf_path.display()))?;
    let (cur_blocking, cur_scope) = parse_ci_gate_from_workflow(&existing);
    let next_content = render_ci_workflow(provider, &cur_blocking, &cur_scope);
    let needs_upgrade = existing.contains("# dotore workflow v1")
        || existing.contains("@v1")
        || existing != next_content;
    if !needs_upgrade {
        return Ok(CiActionResult {
            provider,
            workflow_path: wf_path,
            status: "not-needed".to_string(),
            blocking: cur_blocking,
            scope: cur_scope,
        });
    }
    fs::write(&wf_path, &next_content)
        .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;
    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: "upgraded".to_string(),
        blocking: cur_blocking,
        scope: cur_scope,
    })
}

/// Updates the `blocking` and `scope` gate settings in an existing CI workflow file.
///
/// # Errors
/// Returns an error message if no workflow exists, gate values are invalid, or writing fails.
pub fn ci_config(options: &CiOptions) -> Result<CiActionResult, String> {
    let provider = resolve_ci_provider(options);
    let wf_path = ci_workflow_path(&options.cwd, provider);
    if !wf_path.is_file() {
        return Err(format!(
            "No CI workflow found at {}. Run `dotore ci install` first.",
            wf_path.display()
        ));
    }
    let existing = fs::read_to_string(&wf_path)
        .map_err(|e| format!("Failed to read {}: {e}", wf_path.display()))?;
    let (cur_blocking, cur_scope) = parse_ci_gate_from_workflow(&existing);
    let blocking = match &options.blocking {
        Some(b) => validate_ci_blocking(b)?,
        None => cur_blocking,
    };
    let scope = match &options.scope {
        Some(s) => validate_ci_scope(s)?,
        None => cur_scope,
    };
    let next_content = render_ci_workflow(provider, &blocking, &scope);
    let changed = next_content != existing;
    if changed {
        fs::write(&wf_path, &next_content)
            .map_err(|e| format!("Failed to write {}: {e}", wf_path.display()))?;
    }
    Ok(CiActionResult {
        provider,
        workflow_path: wf_path,
        status: if changed { "updated" } else { "unchanged" }.to_string(),
        blocking,
        scope,
    })
}

fn resolve_ci_provider(options: &CiOptions) -> CiProviderKind {
    if let Some(p) = options.provider {
        return p;
    }
    if options.cwd.join(".gitlab-ci.yml").is_file()
        && !options.cwd.join(".github").join("workflows").is_dir()
    {
        return CiProviderKind::GitlabCi;
    }
    CiProviderKind::GithubActions
}

fn ci_workflow_path(cwd: &Path, provider: CiProviderKind) -> PathBuf {
    match provider {
        CiProviderKind::GithubActions => cwd.join(".github").join("workflows").join("dotore.yml"),
        CiProviderKind::GitlabCi => cwd.join(".gitlab-ci.yml"),
    }
}

fn validate_ci_blocking(raw: &str) -> Result<String, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "none" | "warning" | "error" => Ok(raw.trim().to_ascii_lowercase()),
        _ => Err(format!(
            "Invalid --blocking value {raw:?}. Expected one of: none, warning, error."
        )),
    }
}

fn validate_ci_scope(raw: &str) -> Result<String, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "changed" | "contextual" | "lines" | "full" => Ok(raw.trim().to_ascii_lowercase()),
        _ => Err(format!(
            "Invalid --scope value {raw:?}. Expected one of: changed, contextual, lines, full."
        )),
    }
}

fn render_ci_workflow(provider: CiProviderKind, blocking: &str, scope: &str) -> String {
    match provider {
        CiProviderKind::GithubActions => format!(
            r#"# dotore workflow v2
# Static React & TypeScript analysis and deterministic remediation gate.
name: dotore

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  push:
    branches: ["main"]

permissions:
  contents: read

concurrency:
  group: dotore-${{{{ github.event.pull_request.number || github.ref }}}}
  cancel-in-progress: true

jobs:
  dotore:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - name: Run dotore
        run: dotore check --scope {scope} --blocking {blocking}
"#
        ),
        CiProviderKind::GitlabCi => format!(
            r#"# dotore workflow v2
dotore:
  stage: test
  script:
    - dotore check --scope {scope} --blocking {blocking}
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"#
        ),
    }
}

fn parse_ci_gate_from_workflow(content: &str) -> (String, String) {
    let mut blocking = "none".to_string();
    let mut scope = "changed".to_string();
    let tokens: Vec<&str> = content.split_whitespace().collect();
    for window in tokens.windows(2) {
        if window[0] == "--blocking" {
            blocking = window[1].trim_matches(&['"', '\''][..]).to_string();
        } else if window[0] == "--scope" {
            scope = window[1].trim_matches(&['"', '\''][..]).to_string();
        }
    }
    (blocking, scope)
}

/// Options for `dotore install` ([`install_dotore`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallOptions {
    /// Target project root directory.
    pub cwd: PathBuf,
    /// Non-interactive mode enabling full setup (skill, package.json script, git pre-commit hook, agent hooks).
    pub yes: bool,
    /// Preview planned file operations without writing to disk.
    pub dry_run: bool,
    /// Install agent stop hooks (`.claude/settings.json` and `.claude/hooks/dotore.mjs`).
    pub agent_hooks: bool,
}

/// Result of running [`install_dotore`] (`dotore install`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallResult {
    /// Installed (or planned) `/dotore` agent skill files.
    pub skill_files: Vec<PathBuf>,
    /// Whether `package.json#scripts.dotore` was added or updated.
    pub package_json_updated: bool,
    /// Path to the installed (or planned) git pre-commit hook file, if any.
    pub git_hook_path: Option<PathBuf>,
    /// Installed (or planned) agent hook configuration and script files.
    pub agent_hook_files: Vec<PathBuf>,
    /// Whether this run was a dry run (`--dry-run`).
    pub dry_run: bool,
}

const DOTORE_SKILL_CONTENT: &str = r#"---
name: dotore
description: Use when finishing a feature, fixing a bug, before committing React or TypeScript code, or when the user types `/dotore`. Runs static correctness, performance, accessibility, security, and architecture analysis and applies deterministic remediation.
version: "1.0.0"
---

# /dotore — Deterministic React & TypeScript Analysis and Remediation

`dotore` is a pure-Rust static analyzer, deterministic auto-fixer, and remediation engine for React and TypeScript codebases.

## Workflow

1. **Check (`dotore check`)**:
   - Run `dotore check --scope changed` after edits (or `dotore check --json` for structured machine output with **Root-Cause Groups**, **Blast Radius**, and **Fix Capsules**).
2. **Auto-fix (`dotore fix`)**:
   - Run `dotore fix` to deterministically apply all `Autofix`-tier single- and cross-file rewrites directly in Rust.
3. **Inspect Root Cause (`dotore why <file:line>`)**:
   - Run `dotore why <file:line>` to inspect why a diagnostic fired (or why a rule, inline suppression, or **Capability Gate** did or did not apply) and read its self-contained **Fix Capsule**.
4. **Search Symbols (`dotore search <query>`)**:
   - Run `dotore search <query>` to fuzzy-search AST **Symbol Outlines** across the repository without reading whole files.
5. **Generate Execution Plans (`dotore plan`)**:
   - Run `dotore plan --out plans` to emit prioritized `plans/NNN-<slug>.md` remediation plans and `plans/README.md`.
6. **Configure & Explain Rules (`dotore rules`)**:
   - Run `dotore rules list` or `dotore rules explain <rule>` to inspect rules offline, and `dotore rules set | enable | disable | category | ignore-tag` to update `dotore.config.*` or `package.json#dotore` in place.
7. **UI Design Audit (`dotore design`)**:
   - Run `dotore design` to run a focused UI polish audit enabling all `design`-tagged rules.
8. **Live Runtime Profiling (`dotore scan <url>`)**:
   - Run `dotore scan <url> --format json` to capture a Chrome DevTools Protocol (CDP) trace and React component render hotspots.
"#;

const GIT_HOOK_BLOCK_START: &str = "# dotore hook start";
const GIT_HOOK_BLOCK_END: &str = "# dotore hook end";

/// Installs the unified `/dotore` agent skill, `package.json` script, git pre-commit hook,
/// and optional agent hooks under `options.cwd` (or previews operations when `options.dry_run` is `true`).
///
/// # Errors
/// Returns an error message if reading or writing target files fails.
pub fn install_dotore(options: &InstallOptions) -> Result<InstallResult, String> {
    let cwd = if options.cwd.as_os_str().is_empty() {
        Path::new(".")
    } else {
        options.cwd.as_path()
    };

    let claude_skill = cwd
        .join(".claude")
        .join("skills")
        .join("dotore")
        .join("SKILL.md");
    let agents_skill = cwd
        .join(".agents")
        .join("skills")
        .join("dotore")
        .join("SKILL.md");
    let skill_files = vec![claude_skill, agents_skill];

    let pkg_json_path = cwd.join("package.json");
    let package_json_updated = if pkg_json_path.is_file() {
        let raw = fs::read_to_string(&pkg_json_path)
            .map_err(|e| format!("Failed to read {}: {e}", pkg_json_path.display()))?;
        !raw.contains("\"dotore\":")
    } else {
        false
    };

    let git_hook_path = if cwd.join(".husky").is_dir() {
        Some(cwd.join(".husky").join("pre-commit"))
    } else if cwd.join(".git").exists() || options.yes {
        Some(cwd.join(".git").join("hooks").join("pre-commit"))
    } else {
        None
    };

    let agent_hook_files = if options.agent_hooks || options.yes {
        vec![
            cwd.join(".claude").join("settings.json"),
            cwd.join(".claude").join("hooks").join("dotore.mjs"),
        ]
    } else {
        Vec::new()
    };

    if options.dry_run {
        return Ok(InstallResult {
            skill_files,
            package_json_updated,
            git_hook_path,
            agent_hook_files,
            dry_run: true,
        });
    }

    for skill_path in &skill_files {
        if let Some(parent) = skill_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        fs::write(skill_path, DOTORE_SKILL_CONTENT)
            .map_err(|e| format!("Failed to write {}: {e}", skill_path.display()))?;
    }

    if package_json_updated {
        add_dotore_script_to_package_json(&pkg_json_path)?;
    }

    if let Some(hook_path) = &git_hook_path {
        write_git_pre_commit_hook(hook_path)?;
    }

    if !agent_hook_files.is_empty() {
        write_claude_agent_hooks(cwd)?;
    }

    Ok(InstallResult {
        skill_files,
        package_json_updated,
        git_hook_path,
        agent_hook_files,
        dry_run: false,
    })
}

/// Formats the terminal summary for [`install_dotore`] (`dotore install`).
#[must_use]
pub fn format_install_report(result: &InstallResult) -> String {
    let mut out = String::new();
    let prefix = if result.dry_run { "[dry-run] " } else { "" };
    for skill in &result.skill_files {
        let _ = writeln!(out, "{prefix}Installed /dotore skill: {}", skill.display());
    }
    if result.package_json_updated {
        let _ = writeln!(
            out,
            "{prefix}Added \"dotore\": \"dotore check\" to package.json scripts."
        );
    }
    if let Some(hook) = &result.git_hook_path {
        let _ = writeln!(
            out,
            "{prefix}Installed pre-commit git hook: {}",
            hook.display()
        );
    }
    for ah in &result.agent_hook_files {
        let _ = writeln!(out, "{prefix}Installed agent hook file: {}", ah.display());
    }
    out
}

fn add_dotore_script_to_package_json(pkg_json_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(pkg_json_path)
        .map_err(|e| format!("Failed to read {}: {e}", pkg_json_path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid JSON in {}: {e}", pkg_json_path.display()))?;
    let Some(obj) = root.as_object_mut() else {
        return Err(format!(
            "{} root is not a JSON object",
            pkg_json_path.display()
        ));
    };
    let scripts_val = obj
        .entry("scripts".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(scripts_obj) = scripts_val.as_object_mut() {
        scripts_obj
            .entry("dotore".to_string())
            .or_insert_with(|| serde_json::Value::String("dotore check".to_string()));
    }
    let serialized = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    fs::write(pkg_json_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", pkg_json_path.display()))
}

fn write_git_pre_commit_hook(hook_path: &Path) -> Result<(), String> {
    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let existing = fs::read_to_string(hook_path).unwrap_or_default();
    let block = format!(
        "{GIT_HOOK_BLOCK_START}\nif command -v dotore >/dev/null 2>&1; then\n  dotore check --staged\nfi\n{GIT_HOOK_BLOCK_END}\n"
    );
    let next = if let Some(start_idx) = existing.find(GIT_HOOK_BLOCK_START)
        && let Some(end_rel) = existing[start_idx..].find(GIT_HOOK_BLOCK_END)
    {
        let end_idx = start_idx + end_rel + GIT_HOOK_BLOCK_END.len();
        let mut updated = String::new();
        updated.push_str(&existing[..start_idx]);
        updated.push_str(block.trim_end());
        updated.push_str(&existing[end_idx..]);
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated
    } else if existing.trim().is_empty() {
        format!("#!/bin/sh\n\n{block}")
    } else if existing.starts_with("#!") {
        format!("{}\n{block}", existing.trim_end())
    } else {
        format!("#!/bin/sh\n\n{}\n{block}", existing.trim_end())
    };
    fs::write(hook_path, next)
        .map_err(|e| format!("Failed to write {}: {e}", hook_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(hook_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(hook_path, perms);
        }
    }
    Ok(())
}

fn write_claude_agent_hooks(cwd: &Path) -> Result<(), String> {
    let claude_dir = cwd.join(".claude");
    let hooks_dir = claude_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)
        .map_err(|e| format!("Failed to create {}: {e}", hooks_dir.display()))?;

    let hook_script_path = hooks_dir.join("dotore.mjs");
    let hook_script = r#"import { spawnSync } from 'node:child_process';
const res = spawnSync('dotore', ['check', '--scope', 'changed'], { encoding: 'utf8', shell: true });
if (res.status !== 0 && res.stdout) {
  process.stderr.write(res.stdout);
}
process.exit(0);
"#;
    fs::write(&hook_script_path, hook_script)
        .map_err(|e| format!("Failed to write {}: {e}", hook_script_path.display()))?;

    let settings_path = claude_dir.join("settings.json");
    let mut settings: serde_json::Value = if settings_path.is_file() {
        let raw = fs::read_to_string(&settings_path)
            .map_err(|e| format!("Failed to read {}: {e}", settings_path.display()))?;
        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let cmd = "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/dotore.mjs\"";
    if let Some(obj) = settings.as_object_mut() {
        let hooks_val = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(hooks_obj) = hooks_val.as_object_mut() {
            hooks_obj.insert(
                "Stop".to_string(),
                serde_json::json!([
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": cmd
                            }
                        ]
                    }
                ]),
            );
        }
    }
    let serialized = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&settings_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", settings_path.display()))
}
