//! Inline suppression directive models and parsers (`dotore-disable*`, `# noqa`, `#[allow]` / `#[expect]`).

use serde::{Deserialize, Serialize};

use crate::rules::RuleId;

use super::ByteSpan;

/// A single-line inline suppression directive (`// dotore-disable-next-line`, `# dotore-disable-next-line`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineDisableDirective {
    /// 1-based source line number suppressed by this directive.
    pub target_line: u32,
    /// Rule keys listed on the directive (empty suppresses all rules on `target_line`).
    pub rules: Vec<String>,
}

/// A file-level or block-range disable directive (`/* dotore-disable ... */` ... `/* dotore-enable ... */`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockDisableRange {
    /// 1-based inclusive start line of the suppression range.
    pub start_line: u32,
    /// 1-based inclusive end line of the suppression range (`u32::MAX` through end of file).
    pub end_line: u32,
    /// Rule keys listed on the directive (empty suppresses all rules in the range).
    pub rules: Vec<String>,
}

/// Parsed inline suppression directives (`dotore-disable*`, `# noqa`, `#[allow]` / `#[expect]`) for a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileSuppressions {
    /// Line-targeted disable directives (`*-disable-next-line` and `*-disable-line`).
    pub line_directives: Vec<LineDisableDirective>,
    /// File-wide or block-range disable directives (`/* *-disable */`).
    pub block_ranges: Vec<BlockDisableRange>,
}

/// Kind of inline comment suppression directive (`*-disable-next-line`, `*-disable-line`, `*-disable`, `*-enable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionDirectiveKind {
    /// Suppresses the next non-directive code line (`*-disable-next-line` / `*-ignore-next-line`).
    DisableNextLine,
    /// Suppresses the current line (`*-disable-line` / `*-ignore-line` / `# noqa`).
    DisableLine,
    /// Opens a block or file-wide suppression range (`*-disable` / `*-ignore` / `# ruff: noqa`).
    BlockDisable,
    /// Closes open block suppression range(s) (`*-enable`).
    BlockEnable,
}

/// Element with a 1-based start and end line for its opening tag (`<Comp ...>`).
pub trait OpenerLineRange {
    /// 1-based start line of the opening element.
    fn opener_start_line(&self) -> u32;
    /// 1-based end line of the opening element.
    fn opener_end_line(&self) -> u32;
}

impl OpenerLineRange for (u32, u32) {
    fn opener_start_line(&self) -> u32 {
        self.0
    }
    fn opener_end_line(&self) -> u32 {
        self.1
    }
}

/// Subject or function owner span and nested effect spans for inline suppression inheritance.
pub trait SubjectEffectOwner {
    /// Byte span of the subject or function declaration.
    fn subject_span(&self) -> ByteSpan;
    /// 1-based start line of the subject or function declaration.
    fn subject_line(&self) -> u32;
    /// Invokes `f(effect_span, effect_line)` for each nested effect or callback registration.
    fn for_each_effect_span(&self, f: &mut dyn FnMut(ByteSpan, u32));
}

impl SubjectEffectOwner for (ByteSpan, u32) {
    fn subject_span(&self) -> ByteSpan {
        self.0
    }
    fn subject_line(&self) -> u32 {
        self.1
    }
    fn for_each_effect_span(&self, _f: &mut dyn FnMut(ByteSpan, u32)) {}
}

impl FileSuppressions {
    /// Appends a single-line suppression directive for 1-based `target_line`.
    pub fn add_line_disable(&mut self, target_line: u32, rules: Vec<String>) {
        self.line_directives
            .push(LineDisableDirective { target_line, rules });
    }

    /// Appends a block or file-wide suppression range `[start_line, end_line]`.
    pub fn add_block_disable(&mut self, start_line: u32, end_line: u32, rules: Vec<String>) {
        self.block_ranges.push(BlockDisableRange {
            start_line,
            end_line,
            rules,
        });
    }

    /// Closes open (`end_line == u32::MAX`) block suppression ranges at 1-based `enable_line`.
    /// When `enable_rules` is non-empty, only matching rules are closed and any remaining rules
    /// on a multi-rule block range continue from `enable_line..=u32::MAX`.
    pub fn close_block_ranges(&mut self, enable_rules: &[String], enable_line: u32) {
        let mut split_additions = Vec::new();
        for range in &mut self.block_ranges {
            if range.end_line != u32::MAX {
                continue;
            }
            if enable_rules.is_empty() {
                range.end_line = enable_line;
                continue;
            }
            if range.rules.is_empty() {
                continue;
            }
            let overlaps = range
                .rules
                .iter()
                .any(|r| rule_token_matches_enable_list(r, enable_rules));
            if overlaps {
                let remaining: Vec<String> = range
                    .rules
                    .iter()
                    .filter(|r| !rule_token_matches_enable_list(r, enable_rules))
                    .cloned()
                    .collect();
                range.end_line = enable_line;
                if !remaining.is_empty() {
                    split_additions.push(BlockDisableRange {
                        start_line: enable_line,
                        end_line: u32::MAX,
                        rules: remaining,
                    });
                }
            }
        }
        self.block_ranges.extend(split_additions);
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` by a line directive or block range.
    #[must_use]
    pub fn matches_line_or_block(&self, rule: RuleId, line: u32) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }
        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }
        false
    }

    /// Returns `true` if `rule` is suppressed at 1-based `target_line` by a line directive.
    #[must_use]
    pub fn matches_line(&self, rule: RuleId, target_line: u32) -> bool {
        self.line_directives
            .iter()
            .any(|d| d.target_line == target_line && rule_list_matches(&d.rules, rule))
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` or `span` (including via an enclosing
    /// `EffectNode`, `SubjectIr`, or multi-line JSX opening element).
    #[must_use]
    pub fn is_suppressed<E: OpenerLineRange, S: SubjectEffectOwner>(
        &self,
        rule: RuleId,
        line: u32,
        span: ByteSpan,
        elements: &[E],
        subjects: &[S],
    ) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }

        for el in elements {
            let opener_start = el.opener_start_line();
            if opener_start < line
                && line <= el.opener_end_line()
                && self.matches_line(rule, opener_start)
            {
                return true;
            }
        }

        for subject in subjects {
            let subj_span = subject.subject_span();
            if subj_span.start <= span.start
                && span.end <= subj_span.end
                && self.matches_line(rule, subject.subject_line())
            {
                return true;
            }
            let mut effect_matched = false;
            subject.for_each_effect_span(&mut |eff_span, eff_line| {
                if !effect_matched
                    && eff_span.start <= span.start
                    && span.end <= eff_span.end
                    && self.matches_line(rule, eff_line)
                {
                    effect_matched = true;
                }
            });
            if effect_matched {
                return true;
            }
        }

        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }

        false
    }

    /// Returns `true` if `rule` is suppressed at 1-based `line` or `span`, including via enclosing
    /// multi-line element openers `(opener_start_line, opener_end_line)` or owner `(span, header_line)` pairs.
    #[must_use]
    pub fn is_suppressed_with_owners(
        &self,
        rule: RuleId,
        line: u32,
        span: ByteSpan,
        opener_line_ranges: &[(u32, u32)],
        owner_spans: &[(ByteSpan, u32)],
    ) -> bool {
        if self.matches_line(rule, line) {
            return true;
        }

        for &(opener_start, opener_end) in opener_line_ranges {
            if opener_start < line && line <= opener_end && self.matches_line(rule, opener_start) {
                return true;
            }
        }

        for &(owner_span, owner_line) in owner_spans {
            if owner_span.start <= span.start
                && span.end <= owner_span.end
                && self.matches_line(rule, owner_line)
            {
                return true;
            }
        }

        for range in &self.block_ranges {
            if range.start_line <= line
                && line <= range.end_line
                && rule_list_matches(&range.rules, rule)
            {
                return true;
            }
        }

        false
    }
}

/// Checks whether a parsed rule key list on a suppression directive matches `target`.
#[must_use]
pub fn rule_list_matches(rules: &[String], target: RuleId) -> bool {
    if rules.is_empty() {
        return true;
    }
    rules.iter().any(|token| target.matches_key(token))
}

fn rule_token_matches_enable_list(rule_key: &str, enable_rules: &[String]) -> bool {
    enable_rules.iter().any(|en| {
        rule_key == en || RuleId::parse(rule_key).is_some_and(|rule_id| rule_id.matches_key(en))
    })
}

/// Tokenizes the rule list tail of an inline suppression comment, stripping any trailing
/// `-- explanation` description and splitting on commas and whitespace.
#[must_use]
pub fn tokenize_suppression_rules(raw_tail: &str) -> Vec<String> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let before_desc = if let Some(idx) = trimmed.find(" -- ") {
        &trimmed[..idx]
    } else if trimmed.starts_with("-- ") || trimmed == "--" {
        ""
    } else {
        trimmed
    };

    before_desc
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "--")
        .map(str::to_string)
        .collect()
}

/// Parses a single comment body against `tool_prefixes` (such as `&["dotore", "eslint", "oxlint"]`
/// or `&["dotore"]`), supporting `-disable*`, `-ignore*`, and `-enable` directives.
#[must_use]
pub fn parse_comment_disable_directive(
    comment: &str,
    tool_prefixes: &[&str],
) -> Option<(SuppressionDirectiveKind, Vec<String>)> {
    let trimmed = comment.trim().trim_end_matches('}').trim();
    for &tool in tool_prefixes {
        for (suffix, kind) in [
            (
                "-disable-next-line",
                SuppressionDirectiveKind::DisableNextLine,
            ),
            (
                "-ignore-next-line",
                SuppressionDirectiveKind::DisableNextLine,
            ),
            ("-disable-line", SuppressionDirectiveKind::DisableLine),
            ("-ignore-line", SuppressionDirectiveKind::DisableLine),
            ("-disable", SuppressionDirectiveKind::BlockDisable),
            ("-ignore", SuppressionDirectiveKind::BlockDisable),
            ("-enable", SuppressionDirectiveKind::BlockEnable),
        ] {
            let Some(after_tool) = trimmed.strip_prefix(tool) else {
                continue;
            };
            let Some(after) = after_tool.strip_prefix(suffix) else {
                continue;
            };
            if !after.is_empty()
                && !after.starts_with(char::is_whitespace)
                && !after.starts_with(',')
                && !after.starts_with(':')
            {
                continue;
            }
            let cleaned = after.strip_prefix(':').unwrap_or(after);
            return Some((kind, tokenize_suppression_rules(cleaned)));
        }
    }
    None
}

/// Parses a Python `#` comment body for `dotore-disable*`, `dotore-ignore*`, `# noqa`,
/// or file-wide `# ruff: noqa` / `# flake8: noqa` directives.
#[must_use]
pub fn parse_python_suppression_directive(
    comment_body: &str,
) -> Option<(SuppressionDirectiveKind, Vec<String>)> {
    let trimmed = comment_body.trim();
    if let Some(directive) = parse_comment_disable_directive(trimmed, &["dotore"]) {
        return Some(directive);
    }

    if let Some((prefix, rest)) = trimmed.split_once(':')
        && !prefix.trim().is_empty()
        && prefix
            .trim()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && let Some(after) = rest.trim().strip_prefix("noqa")
    {
        let cleaned = after.trim().strip_prefix(':').unwrap_or(after);
        return Some((
            SuppressionDirectiveKind::BlockDisable,
            tokenize_suppression_rules(cleaned),
        ));
    }

    if let Some(after) = trimmed
        .strip_prefix("noqa")
        .or_else(|| trimmed.strip_prefix("NOQA"))
    {
        if after.is_empty() || after.starts_with(char::is_whitespace) {
            return Some((SuppressionDirectiveKind::DisableLine, Vec::new()));
        }
        if let Some(codes) = after.strip_prefix(':') {
            return Some((
                SuppressionDirectiveKind::DisableLine,
                tokenize_suppression_rules(codes),
            ));
        }
    }

    if let Some(after) = trimmed
        .strip_prefix("nosec")
        .or_else(|| trimmed.strip_prefix("NOSEC"))
    {
        if after.is_empty() {
            return Some((SuppressionDirectiveKind::DisableLine, Vec::new()));
        }
        if let Some(codes) = after.strip_prefix(':') {
            return Some((
                SuppressionDirectiveKind::DisableLine,
                tokenize_suppression_rules(codes),
            ));
        }
        if after.starts_with(char::is_whitespace) {
            return Some((
                SuppressionDirectiveKind::DisableLine,
                tokenize_suppression_rules(after),
            ));
        }
    }

    None
}

const RUST_LINT_RULE_TABLE: &[(&[&str], &str)] = &[
    (
        &[
            "rs_no_unwrap_in_production",
            "rs-no-unwrap-in-production",
            "unwrap_used",
            "expect_used",
        ],
        "rs-no-unwrap-in-production",
    ),
    (
        &[
            "rs_no_unguarded_slice_index",
            "rs-no-unguarded-slice-index",
            "indexing_slicing",
            "string_slice",
        ],
        "rs-no-unguarded-slice-index",
    ),
    (
        &[
            "rs_no_lossy_numeric_as_cast",
            "rs-no-lossy-numeric-as-cast",
            "cast_possible_truncation",
            "cast_sign_loss",
            "cast_possible_wrap",
            "as_conversions",
        ],
        "rs-no-lossy-numeric-as-cast",
    ),
    (
        &[
            "rs_require_safety_comment_on_unsafe",
            "rs-require-safety-comment-on-unsafe",
            "undocumented_unsafe_blocks",
            "unsafe_code",
        ],
        "rs-require-safety-comment-on-unsafe",
    ),
    (
        &["rs_no_mem_forget", "rs-no-mem-forget", "mem_forget"],
        "rs-no-mem-forget",
    ),
    (
        &[
            "rs_tokio_no_std_lock_across_await",
            "rs-tokio-no-std-lock-across-await",
            "await_holding_lock",
        ],
        "rs-tokio-no-std-lock-across-await",
    ),
    (
        &[
            "rs_tokio_no_blocking_in_async",
            "rs-tokio-no-blocking-in-async",
            "blocking_call_in_async",
        ],
        "rs-tokio-no-blocking-in-async",
    ),
    (
        &[
            "rs_tokio_prefer_bounded_channel",
            "rs-tokio-prefer-bounded-channel",
        ],
        "rs-tokio-prefer-bounded-channel",
    ),
    (
        &[
            "rs_perf_no_clone_in_loop",
            "rs-perf-no-clone-in-loop",
            "unnecessary_to_owned",
        ],
        "rs-perf-no-clone-in-loop",
    ),
    (
        &[
            "rs_perf_hoist_regex_to_lazylock",
            "rs-perf-hoist-regex-to-lazylock",
        ],
        "rs-perf-hoist-regex-to-lazylock",
    ),
    (
        &[
            "rs_perf_prefer_vec_with_capacity",
            "rs-perf-prefer-vec-with-capacity",
            "vec_init_then_push",
        ],
        "rs-perf-prefer-vec-with-capacity",
    ),
    (
        &[
            "rs_perf_no_unnecessary_format",
            "rs-perf-no-unnecessary-format",
            "useless_format",
            "format_collect",
        ],
        "rs-perf-no-unnecessary-format",
    ),
    (
        &[
            "rs_arch_no_many_boolean_params",
            "rs-arch-no-many-boolean-params",
            "fn_params_excessive_bools",
        ],
        "rs-arch-no-many-boolean-params",
    ),
    (
        &[
            "rs_arch_no_unused_pub_crate_items",
            "rs-arch-no-unused-pub-crate-items",
            "redundant_pub_crate",
        ],
        "rs-arch-no-unused-pub-crate-items",
    ),
    (
        &[
            "rs_arch_prefer_pub_crate_modules",
            "rs-arch-prefer-pub-crate-modules",
        ],
        "rs-arch-prefer-pub-crate-modules",
    ),
    (
        &[
            "rs_arch_no_legacy_mod_rs",
            "rs-arch-no-legacy-mod-rs",
            "mod_module_files",
        ],
        "rs-arch-no-legacy-mod-rs",
    ),
    (
        &["await_holding_refcell_ref"],
        "rs-no-await-holding-refcell",
    ),
    (
        &["panic", "todo", "unimplemented", "exit", "panic_in_result_fn"],
        "rs-no-panic-or-todo-in-production",
    ),
    (
        &["dbg_macro", "print_stdout", "print_stderr"],
        "rs-no-dbg-or-print-in-library",
    ),
    (
        &["permissions_set_readonly_false"],
        "rs-security-no-world-writable-permissions",
    ),
    (&["zombie_processes"], "rs-no-zombie-child-process"),
    (
        &["missing_transmute_annotations", "crosspointer_transmute"],
        "rs-no-transmute-without-type-annotations",
    ),
    (
        &["missing_safety_doc"],
        "rs-require-safety-doc-on-pub-unsafe-fn",
    ),
    (
        &["allow_attributes_without_reason", "unreasoned_allow_attribute"],
        "rs-structure-unreasoned-allow",
    ),
    (
        &["cognitive_complexity", "complex_function"],
        "rs-structure-complex-function",
    ),
    (
        &["too_many_lines", "oversized_unit"],
        "rs-structure-oversized-unit",
    ),
];

/// Maps a Rust `#[allow(...)]` or `#[expect(...)]` lint identifier (including `dotore::*`,
/// `clippy::*`, and standard `rustc` lint names) to canonical `dotore` rule keys.
#[must_use]
pub fn map_rust_allow_lint_to_rules(lint: &str) -> Vec<String> {
    if let Some(rule_id) = RuleId::parse(lint) {
        return vec![rule_id.as_str().to_string()];
    }
    let stripped = lint
        .strip_prefix("dotore::")
        .or_else(|| lint.strip_prefix("dotore/"))
        .or_else(|| {
            lint.rsplit_once("::")
                .map(|(_, after)| after)
                .filter(|after| !after.is_empty())
        })
        .unwrap_or(lint);
    for &(aliases, canonical) in RUST_LINT_RULE_TABLE {
        if aliases.contains(&stripped) {
            return vec![canonical.to_string()];
        }
    }
    if let Some(rule_id) =
        RuleId::parse(stripped).or_else(|| RuleId::parse(&stripped.replace('_', "-")))
    {
        vec![rule_id.as_str().to_string()]
    } else {
        Vec::new()
    }
}

/// Extracts inline disable/enable directives from C-style `//` and `/* ... */` comments in `source`,
/// ignoring comment tokens inside string literals (`"`, `'`, `` ` ``) and resolving stacked
/// `*-disable-next-line` directives.
#[must_use]
pub fn extract_c_style_comment_suppressions(
    source: &str,
    tool_prefixes: &[&str],
) -> FileSuppressions {
    let lines: Vec<&str> = source.lines().collect();
    let mut suppressions = FileSuppressions::default();

    for (idx, &line) in lines.iter().enumerate() {
        let line_num = u32::try_from(idx + 1).unwrap_or(1);
        for comment in extract_c_style_comments_on_line(line) {
            let Some((kind, rules)) = parse_comment_disable_directive(comment, tool_prefixes)
            else {
                continue;
            };
            match kind {
                SuppressionDirectiveKind::DisableLine => {
                    suppressions.add_line_disable(line_num, rules);
                }
                SuppressionDirectiveKind::DisableNextLine => {
                    let target_line = resolve_next_c_style_code_line(&lines, idx, tool_prefixes);
                    suppressions.add_line_disable(target_line, rules);
                }
                SuppressionDirectiveKind::BlockDisable => {
                    suppressions.add_block_disable(line_num, u32::MAX, rules);
                }
                SuppressionDirectiveKind::BlockEnable => {
                    suppressions.close_block_ranges(&rules, line_num);
                }
            }
        }
    }

    suppressions
}

fn extract_c_style_comments_on_line(line: &str) -> Vec<&str> {
    let mut comments = Vec::new();
    let mut rest = line;

    while let Some((idx, is_block)) = find_next_c_style_comment_start(rest) {
        let after_open = rest.get(idx + 2..).unwrap_or_default();
        if is_block {
            if let Some(end_idx) = after_open.find("*/") {
                if let Some(comment) = after_open.get(..end_idx) {
                    comments.push(comment.trim());
                }
                rest = after_open.get(end_idx + 2..).unwrap_or_default();
            } else {
                comments.push(after_open.trim());
                break;
            }
        } else {
            comments.push(after_open.trim());
            break;
        }
    }

    comments
}

fn find_next_c_style_comment_start(s: &str) -> Option<(usize, bool)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while let Some(&b) = bytes.get(i) {
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if b == b'/' {
            if bytes.get(i + 1) == Some(&b'/') {
                return Some((i, false));
            }
            if bytes.get(i + 1) == Some(&b'*') {
                return Some((i, true));
            }
        }
        i += 1;
    }
    None
}

fn resolve_next_c_style_code_line(
    lines: &[&str],
    comment_line_idx: usize,
    tool_prefixes: &[&str],
) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while let Some(&line_str) = lines.get(candidate) {
        let text = line_str.trim();
        let is_stacked_disable = extract_c_style_comments_on_line(text).into_iter().any(|c| {
            matches!(
                parse_comment_disable_directive(c, tool_prefixes),
                Some((SuppressionDirectiveKind::DisableNextLine, _))
            )
        });
        if is_stacked_disable {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}
