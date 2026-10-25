//! GitHub Actions workflow scanner (`.github/workflows/*.{yml,yaml}`) for `ci-workflow-security-risk`:
//! 1. `pull_request_target` workflows checking out untrusted PR head refs (`github.event.pull_request.head.sha` / `head.ref`).
//! 2. `run:` shell blocks interpolating untrusted `${{ github.event.* }}` fields directly instead of via `env:`.
//! 3. Compiling `cargo` / `npm` / `pnpm` / `yarn` steps executing while `${{ secrets.* }}` or `CARGO_REGISTRY_TOKEN` is in `env:`.

use std::path::Path;

use crate::{
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId},
};

use super::{emit_line_diag, push_sec_diag};

const CARGO_COMPILING_SUBCOMMANDS: [&str; 9] = [
    "bench", "build", "check", "clippy", "doc", "install", "publish", "run", "test",
];

const UNTRUSTED_GITHUB_EXPRESSIONS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
];

/// Returns `true` if `path` is a GitHub Actions workflow YAML file (`.github/workflows/*.{yml,yaml}`).
#[must_use]
pub fn is_github_workflow_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if !matches!(ext, "yml" | "yaml") {
        return false;
    }
    let norm = path.to_string_lossy().replace('\\', "/");
    norm.starts_with(".github/workflows/") || norm.contains("/.github/workflows/")
}

pub(super) fn check_ci_workflow_security_risk(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let is_yml = path_str.ends_with(".yml") || path_str.ends_with(".yaml");
    if !is_yml {
        return;
    }

    let src = &file.source;
    check_pull_request_target_head_checkout(file, src, line_starts, out);
    check_run_untrusted_interpolation_and_secrets_in_build(file, src, line_starts, out);
}

fn check_pull_request_target_head_checkout(
    file: &FileIr,
    src: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    if !workflow_has_pull_request_target(src) {
        return;
    }
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let is_untrusted_ref = (trimmed.starts_with("ref:") || trimmed.starts_with("pr:"))
            && (trimmed.contains("github.event.pull_request.head.sha")
                || trimmed.contains("github.event.pull_request.head.ref")
                || trimmed.contains("github.head_ref")
                || trimmed.contains("refs/pull/")
                || trimmed.contains("github.event.pull_request.number"));
        let is_gh_pr_checkout = trimmed.contains("gh pr checkout");
        if is_untrusted_ref || is_gh_pr_checkout {
            emit_line_diag(
                out,
                file,
                RuleId::CiWorkflowSecurityRisk,
                "ciWorkflowSecurityRisk",
                "pull_request_target",
                "`pull_request_target` workflow checks out the untrusted PR head ref, allowing fork PR code to execute with base-repo secrets and write permissions.",
                idx,
                line,
                line_starts,
            );
        }
    }
}

fn workflow_has_pull_request_target(src: &str) -> bool {
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("pull_request_target:")
            || trimmed == "pull_request_target"
            || (trimmed.starts_with("on:") && trimmed.contains("pull_request_target"))
        {
            return true;
        }
    }
    false
}

struct Entry<'a> {
    line: usize,
    column: usize,
    key: &'a str,
    value: &'a str,
    item: bool,
    block: Vec<(usize, &'a str)>,
}

fn parse_yaml_entries(source: &str) -> Option<Vec<Entry<'_>>> {
    let lines: Vec<&str> = source.lines().collect();
    let mut entries: Vec<Entry<'_>> = Vec::new();
    let mut index = 0;
    while let Some(raw) = lines.get(index) {
        index += 1;
        let trimmed = raw.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - trimmed.len();
        let (item, column, text) = match trimmed.strip_prefix("- ") {
            Some(rest) => {
                let rest_trimmed = rest.trim_start();
                (
                    true,
                    indent + 2 + rest.len() - rest_trimmed.len(),
                    rest_trimmed,
                )
            }
            None => (false, indent, trimmed),
        };
        if is_yaml_anchored(text) {
            return None;
        }
        let Some((key, value)) = split_yaml_key(text) else {
            continue;
        };
        if key == "<<" || is_yaml_anchored(value) {
            return None;
        }
        let mut block = Vec::new();
        if value.starts_with('|') || value.starts_with('>') {
            while let Some(next) = lines.get(index) {
                let next_trimmed = next.trim_start();
                if !next_trimmed.is_empty() && next.len() - next_trimmed.len() <= column {
                    break;
                }
                block.push((index + 1, *next));
                index += 1;
            }
        }
        entries.push(Entry {
            line: index - block.len(),
            column,
            key,
            value,
            item,
            block,
        });
    }
    Some(entries)
}

fn split_yaml_key(text: &str) -> Option<(&str, &str)> {
    let (key, value) = match text.split_once(": ") {
        Some((key, value)) => (key, value.trim()),
        None => (text.strip_suffix(':')?, ""),
    };
    let key = key.trim().trim_matches(|q| q == '"' || q == '\'');
    (!key.is_empty() && !key.contains(' ')).then_some((key, value))
}

fn is_yaml_anchored(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('&' | '*'))
        && chars
            .next()
            .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_')
}

fn is_secret_env_variable(key: &str, value: &str) -> bool {
    value.contains("secrets.")
        || key == "CARGO_REGISTRY_TOKEN"
        || (key.starts_with("CARGO_REGISTRIES_") && key.ends_with("_TOKEN"))
        || key == "NPM_TOKEN"
        || key == "NODE_AUTH_TOKEN"
}

#[derive(Default)]
struct Step {
    secret: Option<String>,
    runs: Vec<RunLine>,
    raw_run_lines: Vec<(usize, String)>,
}

struct RunLine {
    line: usize,
    column: usize,
    width: usize,
    command: String,
}

#[derive(Default)]
struct Job {
    secret: Option<String>,
    reusable: bool,
    steps: Vec<Step>,
}

#[derive(Default)]
struct WorkflowWalk {
    workflow_secret: Option<String>,
    jobs: Vec<Job>,
}

impl WorkflowWalk {
    fn record(&mut self, source: &str, path: &[&str], entry: &Entry<'_>) {
        let secret = |key: &str| is_secret_env_variable(key, entry.value).then(|| key.to_owned());
        match path {
            [] if entry.key == "env" => remember_secret(&mut self.workflow_secret, secret("env")),
            ["env"] => remember_secret(&mut self.workflow_secret, secret(entry.key)),
            ["jobs"] => self.jobs.push(Job::default()),
            ["jobs", _] => {
                if let Some(job) = self.jobs.last_mut() {
                    job.reusable |= entry.key == "uses";
                    if entry.key == "env" {
                        remember_secret(&mut job.secret, secret("env"));
                    }
                }
            }
            ["jobs", _, "env"] => {
                if let Some(job) = self.jobs.last_mut() {
                    remember_secret(&mut job.secret, secret(entry.key));
                }
            }
            ["jobs", _, "steps"] => self.record_step(source, entry),
            ["jobs", _, "steps", "env"] => {
                if let Some(step) = self.jobs.last_mut().and_then(|job| job.steps.last_mut()) {
                    remember_secret(&mut step.secret, secret(entry.key));
                }
            }
            _ => {}
        }
    }

    fn record_step(&mut self, source: &str, entry: &Entry<'_>) {
        let Some(job) = self.jobs.last_mut() else {
            return;
        };
        if entry.item || job.steps.is_empty() {
            job.steps.push(Step::default());
        }
        let Some(step) = job.steps.last_mut() else {
            return;
        };
        if entry.key == "env" && is_secret_env_variable("", entry.value) {
            remember_secret(&mut step.secret, Some("env".to_owned()));
        }
        if entry.key != "run" {
            return;
        }
        if entry.block.is_empty() {
            step.raw_run_lines
                .push((entry.line, entry.value.to_owned()));
            step.runs.push(RunLine {
                line: entry.line,
                column: value_column(source, entry),
                width: entry.value.chars().count(),
                command: entry.value.to_owned(),
            });
        }
        let mut continued: Option<RunLine> = None;
        for (line, text) in &entry.block {
            step.raw_run_lines.push((*line, (*text).to_owned()));
            let trimmed = text.trim_start();
            let mut run = match continued.take() {
                Some(mut run) => {
                    run.command.push(' ');
                    run.command.push_str(trimmed);
                    run
                }
                None => RunLine {
                    line: *line,
                    column: text.len() - trimmed.len() + 1,
                    width: trimmed.chars().count(),
                    command: trimmed.to_owned(),
                },
            };
            if run.command.ends_with('\\') {
                run.command.pop();
                continued = Some(run);
            } else {
                step.runs.push(run);
            }
        }
        step.runs.extend(continued);
    }
}

fn remember_secret(slot: &mut Option<String>, secret: Option<String>) {
    if slot.is_none() {
        *slot = secret;
    }
}

fn value_column(source: &str, entry: &Entry<'_>) -> usize {
    source
        .lines()
        .nth(entry.line.saturating_sub(1))
        .and_then(|line| line.rfind(entry.value))
        .map_or(entry.column + 1, |offset| offset + 1)
}

fn check_run_untrusted_interpolation_and_secrets_in_build(
    file: &FileIr,
    src: &str,
    line_starts: &[u32],
    out: &mut Vec<Diagnostic>,
) {
    let Some(entries) = parse_yaml_entries(src) else {
        return;
    };
    let mut walk = WorkflowWalk::default();
    let mut stack: Vec<(usize, &str)> = Vec::with_capacity(8);
    for entry in &entries {
        while stack.last().is_some_and(|(col, _)| *col >= entry.column) {
            stack.pop();
        }
        let path: Vec<&str> = stack.iter().map(|(_, key)| *key).collect();
        stack.push((entry.column, entry.key));
        walk.record(src, &path, entry);
    }

    for job in walk.jobs.iter().filter(|j| !j.reusable) {
        for step in &job.steps {
            // (b) Untrusted ${{ github.event.* }} interpolation inside `run:`
            for (line_num, raw_text) in &step.raw_run_lines {
                if let Some(expr) = find_untrusted_github_interpolation(raw_text) {
                    let line_idx = line_num.saturating_sub(1);
                    let src_line = src.lines().nth(line_idx).unwrap_or(raw_text);
                    emit_line_diag(
                        out,
                        file,
                        RuleId::CiWorkflowSecurityRisk,
                        "ciWorkflowSecurityRisk",
                        expr,
                        &format!(
                            "`run:` shell script interpolates untrusted `${{{{ {expr} }}}}` directly; bind it to a step `env:` variable and reference `\"$VAR\"` in shell."
                        ),
                        line_idx,
                        src_line,
                        line_starts,
                    );
                }
            }

            // (c) Secret in compiling build step
            let Some((scope, variable)) = step
                .secret
                .as_ref()
                .map(|v| ("step", v))
                .or(job.secret.as_ref().map(|v| ("job", v)))
                .or(walk.workflow_secret.as_ref().map(|v| ("workflow", v)))
            else {
                continue;
            };
            for run in &step.runs {
                if let Some(cmd_desc) = find_compiling_build_command(&run.command) {
                    let line_idx = run.line.saturating_sub(1);
                    let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
                    let col_offset = u32::try_from(run.column.saturating_sub(1)).unwrap_or(0);
                    let width = u32::try_from(run.width.max(1)).unwrap_or(1);
                    let byte_start = line_start + col_offset;
                    let byte_end = byte_start + width;
                    push_sec_diag(
                        out,
                        file,
                        RuleId::CiWorkflowSecurityRisk,
                        "ciWorkflowSecurityRisk",
                        &cmd_desc,
                        &format!(
                            "`{cmd_desc}` compiles or runs lifecycle scripts while the {scope} `env` holds secret `{variable}`, which any dependency build script can read."
                        ),
                        offset_to_loc(line_starts, byte_start),
                        ByteSpan {
                            start: byte_start,
                            end: byte_end,
                        },
                    );
                }
            }
        }
    }
}

fn find_untrusted_github_interpolation(text: &str) -> Option<&'static str> {
    let mut rest = text;
    while let Some(open) = rest.find("${{") {
        let after = &rest[open + 3..];
        let Some(close) = after.find("}}") else {
            break;
        };
        let expr = after[..close].trim();
        for &untrusted in UNTRUSTED_GITHUB_EXPRESSIONS {
            if expr.contains(untrusted) {
                return Some(untrusted);
            }
        }
        rest = &after[close + 2..];
    }
    None
}

fn find_compiling_build_command(line: &str) -> Option<String> {
    let comment = line
        .char_indices()
        .find(|(at, ch)| {
            *ch == '#'
                && line
                    .get(..*at)
                    .is_some_and(|head| head.is_empty() || head.ends_with(char::is_whitespace))
        })
        .map_or(line.len(), |(at, _)| at);
    line.get(..comment)?
        .split([';', '&', '|', '(', ')'])
        .find_map(|command| {
            let tokens: Vec<&str> = command
                .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '`'))
                .filter(|t| !t.is_empty())
                .collect();
            if let Some(start) = tokens
                .iter()
                .position(|t| *t == "cargo" || t.ends_with("/cargo"))
                && let Some(&sub) = tokens
                    .get(start + 1..)
                    .and_then(|rest| rest.iter().find(|t| !t.starts_with(['+', '-'])))
                && CARGO_COMPILING_SUBCOMMANDS.contains(&sub)
                && !(sub == "publish" && tokens.contains(&"--no-verify"))
            {
                return Some(format!("cargo {sub}"));
            }
            for pm in ["npm", "pnpm", "yarn"] {
                if let Some(start) = tokens.iter().position(|t| *t == pm)
                    && let Some(&sub) = tokens
                        .get(start + 1..)
                        .and_then(|rest| rest.iter().find(|t| !t.starts_with('-')))
                {
                    let is_lifecycle = matches!(sub, "install" | "ci" | "build" | "test")
                        || (sub == "run" && tokens.get(start + 2) == Some(&"build"));
                    if is_lifecycle && !tokens.contains(&"--ignore-scripts") {
                        return Some(format!("{pm} {sub}"));
                    }
                }
            }
            None
        })
}
