//! Output formatters (`--format json` and `--format text`) and ANSI highlighting detection
//! for `dotore search`.

use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use crate::ir::{SymbolKind, compute_line_starts, loc_from_line_starts};

use super::{SearchJsonLocation, SearchJsonReport, SearchJsonResult, SymbolSearchResult};

const MAX_COMMENT_LINES: usize = 10;
const MAX_INTERFACE_PROPERTIES: usize = 15;
const MAX_LINE_CHARS: usize = 120;

/// Formats ranked search results into a machine-readable [`SearchJsonReport`].
#[must_use]
pub fn format_search_json(
    query: &str,
    root: &str,
    results: &[SymbolSearchResult],
) -> SearchJsonReport {
    let cwd = env::current_dir().ok();
    let json_results = results
        .iter()
        .map(|res| {
            let file_str = format_display_path(&res.file, cwd.as_deref());
            let comments = res
                .outline
                .doc_comment
                .as_deref()
                .map(truncate_comment_strings);
            let rounded_score = (res.score * 10_000.0).round() / 10_000.0;
            SearchJsonResult {
                name: res.outline.name.clone(),
                kind: res.outline.kind,
                location: SearchJsonLocation {
                    file: file_str,
                    line: res.outline.loc.line,
                    column: res.outline.loc.column,
                },
                signature: res.outline.signature.clone(),
                container: res.outline.parent_name.clone(),
                comments,
                score: rounded_score,
                matches: res.matches.clone(),
            }
        })
        .collect();

    SearchJsonReport {
        query: query.to_string(),
        root: root.to_string(),
        count: results.len(),
        results: json_results,
    }
}

fn truncate_comment_strings(doc_comment: &str) -> Vec<String> {
    let all_lines: Vec<&str> = doc_comment.lines().collect();
    if all_lines.len() <= MAX_COMMENT_LINES {
        return all_lines.into_iter().map(str::to_string).collect();
    }
    let mut out: Vec<String> = all_lines
        .get(..MAX_COMMENT_LINES)
        .unwrap_or(&all_lines)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let hidden = all_lines.len() - MAX_COMMENT_LINES;
    out.push(format!("(...and {hidden} more comment lines)"));
    out
}

/// Renders ranked search results as grouped file outlines (`--format text`).
#[must_use]
pub fn format_search_text(
    results: &[SymbolSearchResult],
    sources: &HashMap<PathBuf, String>,
    highlight: bool,
) -> String {
    if results.is_empty() {
        return String::new();
    }

    let cwd = env::current_dir().ok();
    let grouped = group_results_by_file(results);
    let mut blocks = Vec::with_capacity(grouped.len());

    for (file_path, file_results) in grouped {
        let Some(source) = sources.get(&file_path) else {
            continue;
        };
        let lines: Vec<&str> = source.lines().collect();
        let line_starts = compute_line_starts(source);
        let display_file = format_display_path(&file_path, cwd.as_deref());
        let lang = markdown_language(&display_file);

        let mut outline_lines: Vec<String> = Vec::new();
        for (idx, res) in file_results.iter().enumerate() {
            if idx > 0 {
                outline_lines.push(String::new());
            }
            outline_lines.extend(create_outline_lines(res, &lines, &line_starts));
        }

        let mut block = String::new();
        if highlight {
            block.push_str(&format!("\x1b[1m\x1b[36m{display_file}\x1b[0m\n"));
            block.push_str(&format!("\x1b[2m```{lang}\x1b[0m\n"));
            for line in &outline_lines {
                block.push_str(&highlight_outline_line(line));
                block.push('\n');
            }
            block.push_str("\x1b[2m```\x1b[0m");
        } else {
            block.push_str(&display_file);
            block.push('\n');
            block.push_str(&format!("```{lang}\n"));
            block.push_str(&outline_lines.join("\n"));
            block.push_str("\n```");
        }
        blocks.push(block);
    }

    if blocks.is_empty() {
        String::new()
    } else {
        format!("{}\n", blocks.join("\n\n"))
    }
}

fn group_results_by_file(
    results: &[SymbolSearchResult],
) -> Vec<(PathBuf, Vec<&SymbolSearchResult>)> {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut map: HashMap<PathBuf, Vec<&SymbolSearchResult>> = HashMap::new();

    for res in results {
        if let Some(group) = map.get_mut(&res.file) {
            group.push(res);
        } else {
            order.push(res.file.clone());
            map.insert(res.file.clone(), vec![res]);
        }
    }

    order
        .into_iter()
        .filter_map(|file| {
            let mut group = map.remove(&file)?;
            group.sort_by_key(|r| r.outline.loc.line);
            Some((file, group))
        })
        .collect()
}

fn create_outline_lines(
    result: &SymbolSearchResult,
    lines: &[&str],
    line_starts: &[u32],
) -> Vec<String> {
    let decl_start_line = loc_from_line_starts(line_starts, result.outline.span.start).line;
    let start_line = result.outline.comment_start_line.unwrap_or(decl_start_line);
    let sig_end_line = result.outline.signature_end_line.max(decl_start_line);
    let end_line = result.outline.end_line.max(decl_start_line);

    let sig_lines = create_signature_lines(start_line, decl_start_line, sig_end_line, lines);

    if end_line <= decl_start_line {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_line,
            lines,
        )
        .unwrap_or(sig_lines);
    }

    let Some((end_text_line, end_text)) = find_last_non_empty_line(lines, start_line, end_line)
    else {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_line,
            lines,
        )
        .unwrap_or(sig_lines);
    };

    if end_text_line <= sig_end_line {
        return create_member_outline_if_needed(
            result.outline.kind,
            &sig_lines,
            start_line,
            end_text_line,
            lines,
        )
        .unwrap_or(sig_lines);
    }

    let decl_outline =
        create_declaration_outline_lines(&sig_lines, sig_end_line, end_text_line, end_text, lines);
    if let Some(member_outline) = create_member_outline_if_needed(
        result.outline.kind,
        &decl_outline,
        start_line,
        end_text_line,
        lines,
    ) {
        return member_outline;
    }

    if result.outline.kind == SymbolKind::Interface {
        return create_interface_outline_lines(
            &sig_lines,
            sig_end_line,
            end_text_line,
            end_text,
            lines,
        );
    }

    decl_outline
}

fn create_declaration_outline_lines(
    sig_lines: &[String],
    sig_end_line: u32,
    end_text_line: u32,
    end_text: &str,
    lines: &[&str],
) -> Vec<String> {
    let mut out = sig_lines.to_vec();
    let sig_line_text = lines
        .get((sig_end_line as usize).saturating_sub(1))
        .copied()
        .unwrap_or("");
    let indent = leading_whitespace(sig_line_text);
    out.push(format_code_line(
        sig_end_line + 1,
        &format!("{indent}  ..."),
    ));
    out.push(format_code_line(end_text_line, end_text));
    out
}

fn create_member_outline_if_needed(
    kind: SymbolKind,
    member_lines: &[String],
    member_start_line: u32,
    member_end_line: u32,
    lines: &[&str],
) -> Option<Vec<String>> {
    if kind != SymbolKind::Method && kind != SymbolKind::Property {
        return None;
    }

    let (open_line, open_text, close) = find_enclosing_block(lines, member_start_line)?;
    let body_indent = format!("{}  ", leading_whitespace(open_text));
    let mut output = vec![format_code_line(open_line, open_text)];

    if open_line + 1 < member_start_line {
        output.push(format_synthetic_line(&format!("{body_indent}...")));
    }

    output.extend_from_slice(member_lines);

    if let Some((close_line, close_text)) = close {
        if member_end_line + 1 < close_line {
            output.push(format_synthetic_line(&format!("{body_indent}...")));
        }
        if close_line > member_end_line {
            output.push(format_code_line(close_line, close_text));
        }
    }

    Some(output)
}

fn create_interface_outline_lines(
    sig_lines: &[String],
    sig_end_line: u32,
    end_text_line: u32,
    end_text: &str,
    lines: &[&str],
) -> Vec<String> {
    let mut prop_lines: Vec<(u32, &str)> = Vec::new();
    if sig_end_line < end_text_line.saturating_sub(1) {
        for line in (sig_end_line + 1)..=(end_text_line - 1) {
            if let Some(&text) = lines.get((line as usize).saturating_sub(1))
                && !text.trim().is_empty()
            {
                prop_lines.push((line, text));
            }
        }
    }

    if prop_lines.is_empty() {
        let mut out = sig_lines.to_vec();
        out.push(format_code_line(end_text_line, end_text));
        return out;
    }

    let visible_count = prop_lines.len().min(MAX_INTERFACE_PROPERTIES);
    let visible = prop_lines.get(..visible_count).unwrap_or(&prop_lines);
    let hidden_count = prop_lines.len() - visible.len();
    let summary_indent = visible
        .first()
        .map_or("", |&(_, text)| leading_whitespace(text));

    let mut out = sig_lines.to_vec();
    for &(line, text) in visible {
        out.push(format_code_line(line, text));
    }
    if hidden_count > 0 {
        out.push(format_synthetic_line(&format!(
            "{summary_indent}(...and {hidden_count} more properties)"
        )));
    }
    out.push(format_code_line(end_text_line, end_text));
    out
}

#[expect(
    clippy::type_complexity,
    reason = "Returns enclosing block opening line/text and optional closing line/text tuple (#50)"
)]
fn find_enclosing_block<'a>(
    lines: &'a [&'a str],
    member_start_line: u32,
) -> Option<(u32, &'a str, Option<(u32, &'a str)>)> {
    let mut stack: Vec<(u32, &'a str)> = Vec::new();
    for line in 1..member_start_line {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        for ch in text.chars() {
            if ch == '{' {
                stack.push((line, text));
            } else if ch == '}' {
                stack.pop();
            }
        }
    }

    let &(open_line, open_text) = stack.last()?;
    let close = find_closing_brace_line(lines, open_line);
    Some((open_line, open_text, close))
}

fn find_closing_brace_line<'a>(lines: &'a [&'a str], open_line: u32) -> Option<(u32, &'a str)> {
    let mut depth = 0i32;
    for line in open_line..=u32::try_from(lines.len()).unwrap_or(u32::MAX) {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        for ch in text.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some((line, text));
                }
            }
        }
    }
    None
}

fn create_signature_lines(
    start_line: u32,
    decl_start_line: u32,
    sig_end_line: u32,
    lines: &[&str],
) -> Vec<String> {
    let mut output = if start_line < decl_start_line {
        create_comment_lines(start_line, decl_start_line - 1, lines)
    } else {
        Vec::new()
    };

    for line in decl_start_line..=sig_end_line {
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        output.push(format_code_line(line, text));
    }
    output
}

fn create_comment_lines(start_line: u32, end_line: u32, lines: &[&str]) -> Vec<String> {
    let line_count = (end_line - start_line + 1) as usize;
    let visible_count = line_count.min(MAX_COMMENT_LINES);
    let mut output = Vec::with_capacity(visible_count + 1);

    for idx in 0..visible_count {
        let line = start_line + u32::try_from(idx).unwrap_or(0);
        let text = lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        output.push(format_code_line(line, text));
    }

    let hidden_count = line_count - visible_count;
    if hidden_count > 0 {
        let last_visible_line = start_line + u32::try_from(visible_count).unwrap_or(0) - 1;
        let last_text = lines
            .get((last_visible_line as usize).saturating_sub(1))
            .copied()
            .unwrap_or("");
        let indent = leading_whitespace(last_text);
        output.push(format_synthetic_line(&format!(
            "{indent}(...and {hidden_count} more comment lines)"
        )));
    }

    output
}

fn find_last_non_empty_line<'a>(
    lines: &'a [&'a str],
    start_line: u32,
    end_line: u32,
) -> Option<(u32, &'a str)> {
    let mut line = end_line;
    while line > start_line {
        if let Some(&text) = lines.get((line as usize).saturating_sub(1))
            && !text.trim().is_empty()
        {
            return Some((line, text));
        }
        line -= 1;
    }
    None
}

fn format_code_line(line: u32, text: &str) -> String {
    format!("{line:>4} | {}", truncate_line(text))
}

fn format_synthetic_line(text: &str) -> String {
    format!("     | {}", truncate_line(text))
}

fn truncate_line(text: &str) -> String {
    let trimmed = text.trim_end();
    if trimmed.chars().count() <= MAX_LINE_CHARS {
        return trimmed.to_string();
    }
    let prefix: String = trimmed.chars().take(MAX_LINE_CHARS - 1).collect();
    format!("{prefix}…")
}

fn leading_whitespace(text: &str) -> &str {
    let non_ws = text
        .find(|c: char| !c.is_whitespace())
        .unwrap_or(text.len());
    text.get(..non_ws).unwrap_or("")
}

fn markdown_language(file: &str) -> &'static str {
    if file.ends_with(".tsx") {
        "tsx"
    } else if file.ends_with(".ts") || file.ends_with(".mts") || file.ends_with(".cts") {
        "ts"
    } else if file.ends_with(".jsx") {
        "jsx"
    } else if file.ends_with(".py") || file.ends_with(".pyi") {
        "py"
    } else if file.ends_with(".rs") {
        "rs"
    } else {
        "js"
    }
}

fn format_display_path(path: &Path, cwd: Option<&Path>) -> String {
    let rel = cwd
        .and_then(|base| path.strip_prefix(base).ok())
        .unwrap_or(path);
    let rendered = rel.to_string_lossy().replace('\\', "/");
    let stripped = rendered.strip_prefix("./").unwrap_or(&rendered);
    if stripped.is_empty() {
        path.to_string_lossy().replace('\\', "/")
    } else {
        stripped.to_string()
    }
}

fn highlight_outline_line(line: &str) -> String {
    if let Some((prefix, code)) = split_outline_prefix(line) {
        let trimmed = code.trim_start();
        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('#')
        {
            format!("\x1b[2m{prefix}{code}\x1b[0m")
        } else {
            format!("\x1b[2m{prefix}\x1b[0m{code}")
        }
    } else {
        line.to_string()
    }
}

fn split_outline_prefix(line: &str) -> Option<(&str, &str)> {
    if line.as_bytes().get(4..7) == Some(b" | ") {
        Some(line.split_at(7))
    } else {
        None
    }
}

/// Determines whether ANSI highlighting should be enabled for `dotore search` text output.
#[must_use]
pub fn should_highlight_search(
    no_color_flag: bool,
    is_tty: bool,
    env_vars: &[(String, String)],
) -> bool {
    if no_color_flag {
        return false;
    }

    let get_env = |key: &str| -> Option<&str> {
        env_vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    if get_env("NO_COLOR").is_some_and(|v| !v.is_empty())
        || is_truthy_env(get_env("NODE_DISABLE_COLORS"))
        || get_env("FORCE_COLOR") == Some("0")
        || get_env("CLICOLOR") == Some("0")
    {
        return false;
    }

    if has_ci_or_agent_env(env_vars, get_env) {
        return false;
    }

    if is_truthy_env(get_env("FORCE_COLOR")) || is_truthy_env(get_env("CLICOLOR_FORCE")) {
        return true;
    }

    is_tty && get_env("TERM") != Some("dumb")
}

/// Checks current process environment and stdout terminal state for ANSI highlighting.
#[must_use]
pub fn should_highlight_stdout(no_color_flag: bool) -> bool {
    let vars: Vec<(String, String)> = env::vars().collect();
    should_highlight_search(no_color_flag, io::stdout().is_terminal(), &vars)
}

fn is_truthy_env(val: Option<&str>) -> bool {
    let Some(v) = val else {
        return false;
    };
    !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
}

fn has_ci_or_agent_env<'a>(
    env_vars: &'a [(String, String)],
    get_env: impl Fn(&str) -> Option<&'a str>,
) -> bool {
    const CI_AND_AGENT_VARS: &[&str] = &[
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "BUILDKITE",
        "TF_BUILD",
        "TRAVIS",
        "VERCEL",
        "NETLIFY",
        "AGENT",
        "AI_AGENT",
        "CLAUDE_CODE",
        "CLAUDECODE",
        "CODEX_CI",
        "CODEX_SANDBOX",
        "CURSOR_AGENT",
        "GEMINI_CLI",
        "OPENCODE",
    ];
    const PREFIXES: &[&str] = &[
        "CI_",
        "GITHUB_ACTIONS_",
        "GITLAB_",
        "CLAUDE_CODE_",
        "CODEX_",
        "COPILOT_",
        "GEMINI_CLI_",
        "OPENCODE_",
    ];

    CI_AND_AGENT_VARS.iter().any(|k| is_truthy_env(get_env(k)))
        || env_vars.iter().any(|(k, v)| {
            PREFIXES.iter().any(|prefix| k.starts_with(prefix)) && is_truthy_env(Some(v.as_str()))
        })
}
