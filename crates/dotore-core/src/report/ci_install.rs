//! CI workflow automation (`dotore ci`) and `/dotore` agent skill / git hook installer (`dotore install`).

use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    report::{JsonReport, read_json_report},
    rules::{Diagnostic, RuleSeverity},
};
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

/// Renders the GitHub Actions workflow YAML (`.github/workflows/dotore.yml`) for `blocking` and `scope`.
#[must_use]
pub fn render_github_actions_workflow(blocking: &str, scope: &str) -> String {
    format!(
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
  pull-requests: write

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
        run: dotore check --scope {scope} --blocking {blocking} --json-out dotore-report.json
      - name: Render PR comment
        if: always() && github.event_name == 'pull_request'
        run: dotore ci comment dotore-report.json -o dotore-comment.md
"#
    )
}

/// Renders the GitLab CI snippet (`.gitlab-ci.yml`) for `blocking` and `scope`.
#[must_use]
pub fn render_gitlab_ci_snippet(blocking: &str, scope: &str) -> String {
    format!(
        r#"# dotore workflow v2
dotore:
  stage: test
  script:
    - dotore check --scope {scope} --blocking {blocking} --json-out dotore-report.json
    - dotore ci comment dotore-report.json -o dotore-comment.md
  artifacts:
    when: always
    paths:
      - dotore-report.json
      - dotore-comment.md
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
"#
    )
}

/// Renders the CI workflow configuration for `provider`, `blocking`, and `scope`.
#[must_use]
pub fn render_ci_workflow(provider: CiProviderKind, blocking: &str, scope: &str) -> String {
    match provider {
        CiProviderKind::GithubActions => render_github_actions_workflow(blocking, scope),
        CiProviderKind::GitlabCi => render_gitlab_ci_snippet(blocking, scope),
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
    let skill_files = vec![
        cwd.join(".claude/skills/dotore/SKILL.md"),
        cwd.join(".agents/skills/dotore/SKILL.md"),
    ];
    let pkg_json_path = cwd.join("package.json");
    let package_json_updated = needs_dotore_script_in_package_json(&pkg_json_path)?;
    let git_hook_path = resolve_git_pre_commit_hook_path(cwd, options.yes);
    let agent_hook_files = if options.agent_hooks || options.yes {
        vec![
            cwd.join(".claude/settings.json"),
            cwd.join(".claude/hooks/dotore.mjs"),
        ]
    } else {
        Vec::new()
    };
    let result = InstallResult {
        skill_files,
        package_json_updated,
        git_hook_path,
        agent_hook_files,
        dry_run: options.dry_run,
    };
    if !options.dry_run {
        apply_install_plan(cwd, &pkg_json_path, &result)?;
    }
    Ok(result)
}

fn needs_dotore_script_in_package_json(pkg_json_path: &Path) -> Result<bool, String> {
    if !pkg_json_path.is_file() {
        return Ok(false);
    }
    let raw = fs::read_to_string(pkg_json_path)
        .map_err(|e| format!("Failed to read {}: {e}", pkg_json_path.display()))?;
    Ok(!raw.contains("\"dotore\":"))
}

fn resolve_git_pre_commit_hook_path(cwd: &Path, force_git_hook: bool) -> Option<PathBuf> {
    if cwd.join(".husky").is_dir() {
        Some(cwd.join(".husky/pre-commit"))
    } else if cwd.join(".git").exists() || force_git_hook {
        Some(cwd.join(".git/hooks/pre-commit"))
    } else {
        None
    }
}

fn apply_install_plan(
    cwd: &Path,
    pkg_json_path: &Path,
    result: &InstallResult,
) -> Result<(), String> {
    for skill_path in &result.skill_files {
        if let Some(parent) = skill_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        fs::write(skill_path, DOTORE_SKILL_CONTENT)
            .map_err(|e| format!("Failed to write {}: {e}", skill_path.display()))?;
    }
    if result.package_json_updated {
        add_dotore_script_to_package_json(pkg_json_path)?;
    }
    if let Some(hook_path) = &result.git_hook_path {
        write_git_pre_commit_hook(hook_path)?;
    }
    if !result.agent_hook_files.is_empty() {
        write_claude_agent_hooks(cwd)?;
    }
    Ok(())
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
                serde_json::json!([{ "hooks": [{ "type": "command", "command": cmd }] }]),
            );
        }
    }
    let serialized = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&settings_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", settings_path.display()))
}

/// Canonical HTML comment marker at the top of every generated pull-request summary comment.
pub const PR_COMMENT_MARKER: &str = "<!-- dotore:summary -->";

/// Repository and CI environment context for rendering blob links and warnings in a PR comment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrCommentRepoContext {
    /// GitHub repository slug (`owner/repo` from `GITHUB_REPOSITORY`).
    pub github_repository: Option<String>,
    /// GitHub server base URL (`GITHUB_SERVER_URL`, defaults to `"https://github.com"`).
    pub github_server_url: Option<String>,
    /// Commit SHA (`GITHUB_SHA` or `CI_COMMIT_SHA`).
    pub commit_sha: Option<String>,
    /// GitLab project URL (`CI_PROJECT_URL`).
    pub gitlab_project_url: Option<String>,
    /// Whether `DOTORE_SILENCE_MISSING_BASELINE_WARNING` is truthy (`true`, `1`, or `yes`).
    pub silence_missing_baseline_warning: bool,
}

/// Alias for [`PrCommentRepoContext`] representing CI environment variables for PR comments.
pub type PrCommentEnv = PrCommentRepoContext;

impl PrCommentRepoContext {
    /// Reads [`PrCommentRepoContext`] from the current process environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let non_empty_env = |key: &str| {
            std::env::var(key)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let silence_missing_baseline_warning =
            std::env::var("DOTORE_SILENCE_MISSING_BASELINE_WARNING").is_ok_and(|v| {
                let trimmed = v.trim();
                trimmed == "1"
                    || trimmed.eq_ignore_ascii_case("true")
                    || trimmed.eq_ignore_ascii_case("yes")
            });
        Self {
            github_repository: non_empty_env("GITHUB_REPOSITORY"),
            github_server_url: non_empty_env("GITHUB_SERVER_URL"),
            commit_sha: non_empty_env("GITHUB_SHA").or_else(|| non_empty_env("CI_COMMIT_SHA")),
            gitlab_project_url: non_empty_env("CI_PROJECT_URL"),
            silence_missing_baseline_warning,
        }
    }

    /// Alias for [`PrCommentRepoContext::from_env`].
    #[must_use]
    pub fn from_process_env() -> Self {
        Self::from_env()
    }

    /// Constructs a GitHub repository context for `repository` (`owner/repo`) and `commit_sha`.
    #[must_use]
    pub fn github(repository: impl Into<String>, commit_sha: impl Into<String>) -> Self {
        Self {
            github_repository: Some(repository.into()),
            github_server_url: None,
            commit_sha: Some(commit_sha.into()),
            gitlab_project_url: None,
            silence_missing_baseline_warning: false,
        }
    }

    /// Constructs a GitLab project context for `project_url` and `commit_sha`.
    #[must_use]
    pub fn gitlab(project_url: impl Into<String>, commit_sha: impl Into<String>) -> Self {
        Self {
            github_repository: None,
            github_server_url: None,
            commit_sha: Some(commit_sha.into()),
            gitlab_project_url: Some(project_url.into()),
            silence_missing_baseline_warning: false,
        }
    }

    /// Overrides the GitHub server base URL (`GITHUB_SERVER_URL`).
    #[must_use]
    pub fn with_server_url(mut self, server_url: impl Into<String>) -> Self {
        self.github_server_url = Some(server_url.into());
        self
    }

    /// Sets whether the shallow-checkout `baseline_degraded` warning is silenced.
    #[must_use]
    pub const fn with_silence_missing_baseline_warning(mut self, silence: bool) -> Self {
        self.silence_missing_baseline_warning = silence;
        self
    }

    /// Formats `file` and 1-based `line` as a clickable GitHub/GitLab blob URL, if repo metadata is present.
    #[must_use]
    pub fn blob_url(&self, file: &Path, line: u32) -> Option<String> {
        let norm_file = normalize_comment_file_path(file);
        let sha = self
            .commit_sha
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        if let Some(repo) = self
            .github_repository
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let server = self
                .github_server_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("https://github.com")
                .trim_end_matches('/');
            let clean_repo = repo.trim_matches('/');
            return Some(format!(
                "{server}/{clean_repo}/blob/{sha}/{norm_file}#L{line}"
            ));
        }

        if let Some(proj_url) = self
            .gitlab_project_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let proj = proj_url.trim_end_matches('/');
            return Some(format!("{proj}/-/blob/{sha}/{norm_file}#L{line}"));
        }

        None
    }

    /// Formats `file:line` as a Markdown link when repository metadata is available, or `` `file:line` `` locally.
    #[must_use]
    pub fn format_file_line(&self, file: &Path, line: u32) -> String {
        let norm_file = normalize_comment_file_path(file);
        if let Some(url) = self.blob_url(file, line) {
            format!("[{norm_file}:{line}]({url})")
        } else {
            format!("`{norm_file}:{line}`")
        }
    }
}

fn normalize_comment_file_path(file: &Path) -> String {
    let raw = file.to_string_lossy().replace('\\', "/");
    raw.strip_prefix("./").unwrap_or(&raw).to_string()
}

fn format_pr_diagnostic_bullet(diag: &Diagnostic, ctx: &PrCommentRepoContext) -> String {
    let loc_md = ctx.format_file_line(&diag.file, diag.loc.line);
    let subject_part = diag
        .subject_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map_or_else(String::new, |s| format!(" in `{s}`"));
    format!(
        "- **`{}`** ({} · {}) at {}{}: {}",
        diag.rule.as_str(),
        diag.tier.as_str(),
        diag.category.as_str(),
        loc_md,
        subject_part,
        diag.message
    )
}

/// Renders a deterministic `<!-- dotore:summary -->` pull-request Markdown comment for `report`
/// under an explicit [`PrCommentRepoContext`].
#[must_use]
pub fn render_github_pr_comment(report: &JsonReport, ctx: &PrCommentRepoContext) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{PR_COMMENT_MARKER}");

    let status_badge = if report.summary.error_count > 0 {
        "❌ Action Required"
    } else if report.summary.warning_count > 0 {
        "⚠️ Warnings Found"
    } else {
        "✅ Passed"
    };

    let _ = writeln!(out, "## 🩺 dotore Pull Request Summary — {status_badge}\n");
    let _ = writeln!(
        out,
        "| Metric | Value |\n| :--- | :--- |\n| **Health Score** | **{}/100** ({}) |\n| **Diagnostics** | **{}** ({} errors, {} warnings) across {}/{} files ({} Subjects) |\n| **Prescription Tiers** | {} Autofix · {} Surgical · {} Refactor |",
        report.summary.health_score,
        report.summary.score_label,
        report.summary.total_diagnostics,
        report.summary.error_count,
        report.summary.warning_count,
        report.summary.affected_file_count,
        report.summary.files_scanned,
        report.summary.subjects_scanned,
        report.summary.autofix_count,
        report.summary.surgical_count,
        report.summary.refactor_count,
    );

    if let Some(baseline) = &report.baseline {
        let _ = writeln!(
            out,
            "| **Baseline (`{}`)** | **+{}** introduced, **-{}** fixed ({} pre-existing suppressed, {} total in baseline) |",
            baseline.baseline_source,
            baseline.introduced_count,
            baseline.fixed_count,
            baseline.preexisting_count,
            baseline.baseline_total_count,
        );
    }
    out.push('\n');

    if report.baseline_degraded && !ctx.silence_missing_baseline_warning {
        let _ = writeln!(
            out,
            "<details>\n<summary>⚠️ Shallow checkout detected — baseline comparison degraded to diff mode</summary>\n\n`dotore` could not read the baseline git revision because the repository was checked out with a shallow history. Update your CI workflow to fetch full history (`fetch-depth: 0`):\n\n```diff\n - uses: actions/checkout@v5\n+  with:\n+    fetch-depth: 0\n```\n\nTo silence this warning, set `DOTORE_SILENCE_MISSING_BASELINE_WARNING=true`.\n</details>\n"
        );
    }

    if report.diagnostics.is_empty() {
        if let Some(baseline) = &report.baseline
            && baseline.fixed_count > 0
        {
            let _ = writeln!(
                out,
                "✅ **No new issues introduced!** (-{} fixed vs `{}`.)",
                baseline.fixed_count, baseline.baseline_source
            );
        } else {
            let _ = writeln!(
                out,
                "✅ **No issues found.** All analyzed files passed `dotore` checks."
            );
        }
        return out;
    }

    let errors: Vec<&Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Error)
        .collect();
    let warnings: Vec<&Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Warning)
        .collect();

    if !errors.is_empty() {
        let _ = writeln!(out, "### ❌ Errors ({})\n", errors.len());
        for diag in &errors {
            let _ = writeln!(out, "{}", format_pr_diagnostic_bullet(diag, ctx));
        }
        out.push('\n');
    }

    if !warnings.is_empty() {
        let _ = writeln!(
            out,
            "<details>\n<summary>⚠️ Warnings ({})</summary>\n",
            warnings.len()
        );
        for diag in &warnings {
            let _ = writeln!(out, "{}", format_pr_diagnostic_bullet(diag, ctx));
        }
        let _ = writeln!(out, "\n</details>\n");
    }

    if report.summary.autofix_count > 0 {
        let _ = writeln!(
            out,
            "💡 Run `dotore fix` to automatically apply **{}** deterministic `Autofix` rewrite(s).",
            report.summary.autofix_count
        );
    }

    out
}

/// Renders a deterministic `<!-- dotore:summary -->` pull-request Markdown comment for `report`
/// using the current process environment variables.
#[must_use]
pub fn render_github_pr_comment_from_env(report: &JsonReport) -> String {
    render_github_pr_comment(report, &PrCommentRepoContext::from_env())
}

/// Alias for [`render_github_pr_comment`] rendering a pull-request Markdown comment with explicit [`PrCommentEnv`].
#[must_use]
pub fn render_pr_comment_markdown_with_env(report: &JsonReport, env: &PrCommentEnv) -> String {
    render_github_pr_comment(report, env)
}

/// Alias for [`render_github_pr_comment_from_env`] rendering a pull-request Markdown comment from process env.
#[must_use]
pub fn render_pr_comment_markdown(report: &JsonReport) -> String {
    render_github_pr_comment_from_env(report)
}

/// Renders the PR Markdown comment for `report` under `ctx` and writes it to `output_path`.
///
/// # Errors
/// Returns an `io::Error` if creating parent directories or writing `output_path` fails.
pub fn write_github_pr_comment(
    report: &JsonReport,
    output_path: &Path,
    ctx: &PrCommentRepoContext,
) -> io::Result<String> {
    let markdown = render_github_pr_comment(report, ctx);
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, &markdown)?;
    Ok(markdown)
}

/// Loads a serialized [`JsonReport`] from `report_path` and renders its PR Markdown comment,
/// optionally writing it to `output_path`.
///
/// # Errors
/// Returns an error string if reading/parsing `report_path` or writing `output_path` fails.
pub fn generate_ci_comment(
    report_path: &Path,
    output_path: Option<&Path>,
) -> Result<String, String> {
    let report = read_json_report(report_path)
        .map_err(|e| format!("Failed to read JSON report {}: {e}", report_path.display()))?;
    let ctx = PrCommentRepoContext::from_env();
    if let Some(out) = output_path {
        write_github_pr_comment(&report, out, &ctx)
            .map_err(|e| format!("Failed to write PR comment to {}: {e}", out.display()))
    } else {
        Ok(render_github_pr_comment(&report, &ctx))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        diff::{BaselineSummary, ScanMode},
        ir::{ByteSpan, SourceLoc},
        report::build_extracted_report,
        rules::{Diagnostic, RuleId},
    };

    use super::*;

    #[test]
    fn pr_comment_formats_blob_urls_baseline_delta_and_degraded_warning() {
        let mut report = build_extracted_report(
            &[],
            vec![
                Diagnostic::new(
                    RuleId::NoDerivedState,
                    "./src/components/Cart.tsx",
                    SourceLoc { line: 14, column: 5 },
                    ByteSpan { start: 10, end: 30 },
                    "total",
                    "Compute derived value during render.",
                )
                .with_subject_name("Cart"),
            ],
            &HashMap::new(),
        );
        report.mode = ScanMode::Baseline;
        report.baseline = Some(BaselineSummary {
            baseline_source: "main".to_string(),
            introduced_count: 1,
            fixed_count: 4,
            preexisting_count: 2,
            baseline_total_count: 6,
        });
        report.baseline_degraded = true;

        let gh_ctx = PrCommentRepoContext::github("org/shop", "abc12345");
        let md = render_github_pr_comment(&report, &gh_ctx);
        assert!(md.starts_with(PR_COMMENT_MARKER));
        assert!(md.contains(
            "[src/components/Cart.tsx:14](https://github.com/org/shop/blob/abc12345/src/components/Cart.tsx#L14)"
        ));
        assert!(md.contains("**+1** introduced, **-4** fixed"));
        assert!(md.contains("fetch-depth: 0"));

        let silenced = gh_ctx.with_silence_missing_baseline_warning(true);
        let md_silenced = render_github_pr_comment(&report, &silenced);
        assert!(!md_silenced.contains("fetch-depth: 0"));
    }
}
