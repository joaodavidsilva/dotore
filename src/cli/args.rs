//! Clap command-line argument structs and subcommand enums for `dotore`.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::{
    BlockingLevel, DiffScope, HandoffTarget, PrescriptionTier, RuleCategory, RuleId, ScanOptions,
    detect_available_coding_agents, load_preferred_handoff_target, validate_warning_exit_code,
};

/// Top-level `dotore` CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "dotore",
    version,
    about = "Pure-Rust React and TypeScript static analyzer, deterministic auto-fixer, and remediation engine."
)]
pub struct Cli {
    /// Optional subcommand (`check`, `fix`, `plan`, `score`, `report`, `search`, `scan`, `rules`, `why`, `design`, `ci`, `install`).
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Default `check` arguments when no explicit subcommand is passed.
    #[command(flatten)]
    pub(crate) check_args: CheckArgs,
}

/// Subcommands supported by the `dotore` binary.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan files or directories and report unnecessary effects and state cascades.
    Check(CheckArgs),
    /// Apply safe deterministic (`Autofix`-tier) rewrites directly in Rust.
    Fix(FixArgs),
    /// Generate deterministic `NNN-<slug>.md` execution plans and a prioritized `README.md` index.
    Plan(PlanArgs),
    /// Compute and print the local `0..=100` Health Score across files or directories.
    Score(CheckArgs),
    /// Generate a self-contained visual HTML report with Render Cascade diagrams.
    Report(ReportArgs),
    /// Fuzzy-search declared Symbol Outlines across files or directories.
    Search(SearchArgs),
    /// Profile live React interactions in Chrome via CDP and save a `.json.gz` trace.
    Scan(ScanArgs),
    /// Inspect and configure the compiled-in rule catalog (`list`, `explain`, `enable`, `disable`, `set`, `category`, `ignore-tag`, `unignore-tag`).
    Rules(RulesArgs),
    /// Explain why a diagnostic fired (or why a rule or suppression did or did not apply) at `<file:line>` and output its Fix Capsule.
    Why(WhyArgs),
    /// Run a focused UI design audit enabling all `design`-tagged rules while skipping unrelated passes.
    Design(CheckArgs),
    /// Generate, upgrade, and configure CI pull-request workflows (`install`, `upgrade`, `config`).
    Ci(CiArgs),
    /// Install the unified `/dotore` agent skill, `package.json` script, and git/agent hooks.
    #[command(alias = "init")]
    Install(InstallArgs),
}

/// Output format for `dotore check`, `dotore design`, and `dotore report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum OutputFormat {
    /// Human-readable terminal output.
    Text,
    /// Machine-readable JSON report.
    Json,
    /// Self-contained visual HTML report (`dotore report`).
    Html,
    /// Deterministic pull-request Markdown summary comment (`<!-- dotore:summary -->`).
    #[value(
        name = "github-pr-comment",
        alias = "pr-comment",
        alias = "github-pr",
        alias = "markdown"
    )]
    GithubPrComment,
}

/// CLI arguments for `dotore check`, `dotore score`, and `dotore design`.
#[derive(Debug, Clone, Args)]
pub struct CheckArgs {
    /// Files or directories to scan (defaults to current directory).
    #[arg(value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    /// Emit machine-readable JSON output for agents and skills.
    #[arg(long)]
    pub(crate) json: bool,

    /// Output format (`text`, `json`, `html`, or `github-pr-comment` / `pr-comment`).
    #[arg(long = "format", value_enum, value_name = "FORMAT")]
    pub(super) format: Option<OutputFormat>,

    /// Write the versioned machine-readable JSON report to a file on disk.
    #[arg(long = "json-out", value_name = "FILE")]
    pub(crate) json_out: Option<PathBuf>,

    /// Print only the numeric `0..=100` Health Score to stdout.
    #[arg(long)]
    pub(crate) score: bool,

    /// Git diff scan scope (`full`, `changed`, `contextual`, `lines`).
    #[arg(long, default_value = "full", value_name = "SCOPE")]
    pub(crate) scope: String,

    /// Base git branch, revision, or commit range (`A..B`, `A...B`) for diff scopes.
    #[arg(long = "base", value_name = "REF")]
    pub(crate) base_ref: Option<String>,

    /// Restrict scan to staged git index changes (`git diff --cached`).
    #[arg(long)]
    pub(crate) staged: bool,

    /// Compare against a saved baseline JSON report or git revision as a fingerprint multiset.
    #[arg(long, value_name = "REPORT_JSON")]
    pub(crate) baseline: Option<PathBuf>,

    /// Severity threshold that blocks CI (`error`, `warning`, `none`).
    #[arg(long, value_name = "LEVEL")]
    pub(crate) blocking: Option<String>,

    /// Custom exit code (`2..=255`) returned when warnings are present and no blocking errors occurred.
    #[arg(long = "warning-exit-code", value_name = "CODE")]
    pub(crate) warning_exit_code: Option<u32>,

    /// Exit with code 0 even when diagnostics are found (alias for `--blocking none`).
    #[arg(long)]
    pub(crate) no_fail: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    pub(crate) include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    pub(crate) no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    pub(crate) custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable or comma-separated, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG", value_delimiter = ',')]
    pub(crate) ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Filter by rule ID or legacy alias (repeatable or comma-separated, e.g. `--rule no-derived-state`).
    #[arg(long = "rule", value_name = "RULE_ID", value_delimiter = ',')]
    pub(crate) rules: Vec<String>,

    /// Filter by rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability` / `architecture`).
    #[arg(long = "category", value_name = "CATEGORY", value_delimiter = ',')]
    pub(crate) categories: Vec<String>,

    /// Filter by rule ID, prefix, or category (`arch`, `architecture`, `py-`, `rs-`, etc.; repeatable or comma-separated).
    #[arg(long = "only", value_name = "FILTER", value_delimiter = ',')]
    pub(crate) only: Vec<String>,

    /// Filter by Prescription Tier (`autofix`, `surgical`, `refactor`; repeatable or comma-separated).
    #[arg(long = "tier", value_name = "TIER", value_delimiter = ',')]
    pub(crate) tiers: Vec<String>,

    /// Disable the interactive TUI explorer when running in a terminal.
    #[arg(long = "no-pager")]
    pub(crate) no_pager: bool,

    /// Bypass the persistent workspace scan result cache (`~/.dotore/cache/scan-results.json`).
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,

    /// Filter to specific workspace package(s) by name or relative path (repeatable or comma-separated).
    #[arg(long = "project", value_name = "PROJECT", value_delimiter = ',')]
    pub(crate) projects: Vec<String>,

    /// Hand off findings to a coding agent or output (`print`, `clipboard`, `claude`, `codex`, `cursor`, `amp`, `opencode`).
    #[arg(
        long = "handoff",
        value_name = "TARGET",
        num_args = 0..=1,
        default_missing_value = "auto"
    )]
    pub(crate) handoff: Option<String>,
}

/// CLI arguments for `dotore fix`.
#[derive(Debug, Clone, Args)]
pub struct FixArgs {
    /// Files or directories to scan and fix (defaults to current directory).
    #[arg(value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    /// Preview planned fixes without writing to disk.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    pub(crate) include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    pub(crate) no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    pub(crate) custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    pub(crate) ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Bypass the persistent workspace scan result cache (`~/.dotore/cache/scan-results.json`).
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,

    /// Filter to specific workspace package(s) by name or relative path (repeatable or comma-separated).
    #[arg(long = "project", value_name = "PROJECT", value_delimiter = ',')]
    pub(crate) projects: Vec<String>,
}

/// CLI arguments for `dotore plan`.
#[derive(Debug, Clone, Args)]
pub struct PlanArgs {
    /// Files or directories to scan and plan (defaults to current directory).
    #[arg(value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    /// Output directory for generated `NNN-<slug>.md` plans and `README.md` index.
    #[arg(short, long = "out", default_value = "plans", value_name = "DIR")]
    pub(crate) out: PathBuf,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    pub(crate) include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    pub(crate) no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    pub(crate) custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    pub(crate) ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Bypass the persistent workspace scan result cache (`~/.dotore/cache/scan-results.json`).
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,

    /// Filter to specific workspace package(s) by name or relative path (repeatable or comma-separated).
    #[arg(long = "project", value_name = "PROJECT", value_delimiter = ',')]
    pub(crate) projects: Vec<String>,

    /// Synthesize a coding-agent handoff prompt and write a diagnostics bundle (`diagnostics.json` + `<rule-id>.txt`).
    #[arg(long)]
    pub(crate) handoff: bool,

    /// Explicit directory for the diagnostics bundle (`diagnostics.json` + `<rule-id>.txt`, defaults to `--out`).
    #[arg(long = "bundle-dir", value_name = "DIR")]
    pub(crate) bundle_dir: Option<PathBuf>,
}

/// CLI arguments for `dotore report`.
#[derive(Debug, Clone, Args)]
pub struct ReportArgs {
    /// Files or directories to scan (defaults to current directory).
    #[arg(value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    /// Output HTML file path (defaults to a fresh temp directory).
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Output format (`html`, `json`, `text`, or `github-pr-comment` / `pr-comment`).
    #[arg(long = "format", value_enum, value_name = "FORMAT")]
    pub(super) format: Option<OutputFormat>,

    /// Do not open the generated HTML file in the system browser.
    #[arg(long)]
    pub(crate) no_open: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    pub(crate) include_tests: bool,

    /// Bypass inline disable comments.
    #[arg(long)]
    pub(crate) no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    pub(crate) custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable or comma-separated, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG", value_delimiter = ',')]
    pub(crate) ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Filter by rule ID or legacy alias (repeatable or comma-separated).
    #[arg(long = "rule", value_name = "RULE_ID", value_delimiter = ',')]
    pub(crate) rules: Vec<String>,

    /// Filter by rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability` / `architecture`).
    #[arg(long = "category", value_name = "CATEGORY", value_delimiter = ',')]
    pub(crate) categories: Vec<String>,

    /// Filter by rule ID, prefix, or category (`arch`, `architecture`, `py-`, `rs-`, etc.; repeatable or comma-separated).
    #[arg(long = "only", value_name = "FILTER", value_delimiter = ',')]
    pub(crate) only: Vec<String>,

    /// Filter by Prescription Tier (`autofix`, `surgical`, `refactor`; repeatable or comma-separated).
    #[arg(long = "tier", value_name = "TIER", value_delimiter = ',')]
    pub(crate) tiers: Vec<String>,

    /// Bypass the persistent workspace scan result cache (`~/.dotore/cache/scan-results.json`).
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,

    /// Filter to specific workspace package(s) by name or relative path (repeatable or comma-separated).
    #[arg(long = "project", value_name = "PROJECT", value_delimiter = ',')]
    pub(crate) projects: Vec<String>,
}

/// Output format for `dotore search`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum SearchFormat {
    /// Human-readable terminal output.
    Text,
    /// Machine-readable JSON report.
    Json,
}

/// CLI arguments for `dotore search`.
#[derive(Debug, Clone, Args)]
pub struct SearchArgs {
    /// Fuzzy query string matched against symbol names.
    #[arg(value_name = "QUERY")]
    pub(crate) query: String,

    /// Files or directories to search (defaults to current directory).
    #[arg(value_name = "PATH")]
    pub(crate) paths: Vec<PathBuf>,

    /// Comma-separated symbol kinds to include (default: class,enum,function,interface,method,property,type).
    #[arg(short = 'k', long = "kind", value_name = "KINDS")]
    pub(crate) kind: Option<String>,

    /// Maximum number of ranked matches to return.
    #[arg(short = 'l', long = "limit", default_value_t = 50, value_name = "N")]
    pub(crate) limit: usize,

    /// Output format (`text` or `json`).
    #[arg(short = 'f', long = "format", value_enum, default_value_t = SearchFormat::Text, value_name = "FORMAT")]
    pub(super) format: SearchFormat,

    /// Disable ANSI syntax highlighting in text output.
    #[arg(long)]
    pub(crate) no_color: bool,

    /// Bypass reading and writing the persistent per-project Symbol Outline disk cache.
    #[arg(long = "no-cache")]
    pub(crate) no_cache: bool,
}

/// CLI arguments for `dotore scan`.
#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// Target `http://` or `https://` URL to profile (optional in interactive terminals).
    #[arg(value_name = "URL")]
    pub(crate) url: Option<String>,

    /// Connect to an existing debug-enabled Chrome instance (`ws://...` or `http://...`).
    #[arg(long, value_name = "URL")]
    pub(crate) cdp: Option<String>,

    /// Output path for the compressed `.json.gz` DevTools trace.
    #[arg(long = "trace-out", value_name = "FILE")]
    pub(crate) trace_out: Option<PathBuf>,

    /// Output format (`text`, `json`, or `jsonl`).
    #[arg(long, value_name = "FORMAT")]
    pub(crate) format: Option<String>,
}

/// CLI arguments for `dotore rules`.
#[derive(Debug, Clone, Args)]
pub struct RulesArgs {
    /// Rules subcommand (`list`, `explain`, `enable`, `disable`, `set`, `category`, `ignore-tag`, `unignore-tag`).
    #[command(subcommand)]
    pub(super) command: RulesSubcommand,
}

/// Subcommands under `dotore rules`.
#[derive(Debug, Clone, Subcommand)]
pub(super) enum RulesSubcommand {
    /// List all available rules with their effective severities.
    List(RulesListArgs),
    /// Render the rationale, examples, configuration snippet, and Prescription Tier for a rule.
    Explain(RulesExplainArgs),
    /// Enable a rule in `dotore.config.*` or `package.json#dotore`.
    Enable(RulesEnableArgs),
    /// Disable a rule (`"off"`) in `dotore.config.*` or `package.json#dotore`.
    Disable(RulesDisableArgs),
    /// Set a rule's severity (`off`, `warn`, `error`) in `dotore.config.*` or `package.json#dotore`.
    Set(RulesSetArgs),
    /// Set a category's severity (`off`, `warn`, `error`) in `dotore.config.*` or `package.json#dotore`.
    Category(RulesCategoryArgs),
    /// Add a rule tag to `ignore.tags` in `dotore.config.*` or `package.json#dotore`.
    #[command(name = "ignore-tag")]
    IgnoreTag(RulesTagArgs),
    /// Remove a rule tag from `ignore.tags` in `dotore.config.*` or `package.json#dotore`.
    #[command(name = "unignore-tag")]
    UnignoreTag(RulesTagArgs),
}

/// CLI arguments for `dotore rules list`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesListArgs {
    /// Filter by category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    #[arg(long, value_name = "CATEGORY")]
    pub category: Option<String>,

    /// Filter by behavioral tag (`design`, `test-noise`, `r3f`, etc.).
    #[arg(long, value_name = "TAG")]
    pub tag: Option<String>,

    /// Filter by capability or framework (`react`, `nextjs`, `tanstack-query`, `three`, `global`, etc.).
    #[arg(long, value_name = "FRAMEWORK")]
    pub framework: Option<String>,

    /// Only show rules with explicit configuration overrides.
    #[arg(long)]
    pub configured: bool,

    /// Emit machine-readable JSON array.
    #[arg(long)]
    pub json: bool,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules explain`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesExplainArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias (`effect/<id>`, `react/<id>`).
    #[arg(value_name = "RULE")]
    pub rule: String,

    /// Emit machine-readable JSON object.
    #[arg(long)]
    pub json: bool,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules enable`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesEnableArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    pub rule: String,

    /// Severity to enable the rule at (`warn` or `error`; defaults to the rule's default severity).
    #[arg(long, value_name = "SEVERITY")]
    pub severity: Option<String>,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules disable`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesDisableArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    pub rule: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules set`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesSetArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    pub rule: String,

    /// Target severity (`off`, `warn`, or `error`).
    #[arg(value_name = "SEVERITY")]
    pub severity: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules category`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesCategoryArgs {
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    #[arg(value_name = "CATEGORY")]
    pub category: String,

    /// Target severity (`off`, `warn`, or `error`).
    #[arg(value_name = "SEVERITY")]
    pub severity: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore rules ignore-tag` and `dotore rules unignore-tag`.
#[derive(Debug, Clone, Args)]
pub(super) struct RulesTagArgs {
    /// Behavioral tag (`design`, `test-noise`, `r3f`, etc.).
    #[arg(value_name = "TAG")]
    pub tag: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore why`.
#[derive(Debug, Clone, Args)]
pub struct WhyArgs {
    /// Source location (`<file:line>` or `<file:line:column>`).
    #[arg(value_name = "FILE:LINE")]
    pub(crate) location: String,

    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,

    /// Working directory for resolving project configuration and cross-file callers.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub(crate) cwd: PathBuf,
}

/// CLI arguments for `dotore ci`.
#[derive(Debug, Clone, Args)]
pub struct CiArgs {
    /// CI workflow subcommand (`install`, `upgrade`, `config`, `comment`).
    #[command(subcommand)]
    pub(super) command: Option<CiSubcommand>,

    /// Default `install` arguments when no explicit subcommand is passed.
    #[command(flatten)]
    pub(super) action_args: CiActionArgs,
}

/// Subcommands under `dotore ci`.
#[derive(Debug, Clone, Subcommand)]
pub(super) enum CiSubcommand {
    /// Generate a CI pull-request workflow (`.github/workflows/dotore.yml` or `.gitlab-ci.yml`).
    Install(CiActionArgs),
    /// Upgrade an existing CI workflow to the latest `dotore` v2 configuration.
    Upgrade(CiActionArgs),
    /// Update `blocking` or `scope` settings in an existing CI workflow.
    Config(CiActionArgs),
    /// Render a deterministic `<!-- dotore:summary -->` pull-request Markdown comment from a saved JSON report.
    Comment(CiCommentArgs),
}

/// CLI arguments for `dotore ci comment`.
#[derive(Debug, Clone, Args)]
pub(super) struct CiCommentArgs {
    /// Path to the saved JSON report file (`report.json`).
    #[arg(value_name = "REPORT_JSON")]
    pub report: PathBuf,

    /// Optional output Markdown file path (`-o comment.md`).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// CLI arguments for `dotore ci install`, `dotore ci upgrade`, and `dotore ci config`.
#[derive(Debug, Clone, Args)]
pub(super) struct CiActionArgs {
    /// CI provider (`github-actions` or `gitlab-ci`).
    #[arg(long, value_name = "PROVIDER")]
    pub provider: Option<String>,

    /// Gate blocking level (`none`, `warning`, or `error`).
    #[arg(long, value_name = "LEVEL")]
    pub blocking: Option<String>,

    /// Diff scope (`changed`, `contextual`, `lines`, or `full`).
    #[arg(long, value_name = "SCOPE")]
    pub scope: Option<String>,

    /// Non-interactive confirmation flag.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Target repository directory.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub cwd: PathBuf,
}

/// CLI arguments for `dotore install`.
#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Accept all setup steps non-interactively (skill, script, git hook, agent hooks).
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,

    /// Print planned file operations without writing to disk.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Install agent stop hooks (`.claude/settings.json` and `.claude/hooks/dotore.mjs`).
    #[arg(long)]
    pub(crate) agent_hooks: bool,

    /// Target project root directory.
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub(crate) cwd: PathBuf,
}

fn push_unique_rule(rules: &mut Vec<RuleId>, rule: RuleId) {
    if !rules.contains(&rule) {
        rules.push(rule);
    }
}

fn append_category_rules(trimmed: &str, rules: &mut Vec<RuleId>) -> Result<(), String> {
    if trimmed.eq_ignore_ascii_case("arch") || trimmed.eq_ignore_ascii_case("architecture") {
        for meta in crate::rule_registry() {
            if meta.category == RuleCategory::Maintainability
                || meta.id.is_architecture_soc_or_reuse_rule()
            {
                push_unique_rule(rules, meta.id);
            }
        }
        return Ok(());
    }
    let Some(parsed_cat) = RuleCategory::parse(trimmed) else {
        return Err(format!(
            "Unknown rule category: {trimmed:?} (expected Bugs, Performance, Accessibility, Security, Maintainability, or Architecture)"
        ));
    };
    for meta in crate::rule_registry() {
        if meta.category == parsed_cat {
            push_unique_rule(rules, meta.id);
        }
    }
    Ok(())
}

fn append_only_filter_rules(trimmed: &str, rules: &mut Vec<RuleId>) -> Result<(), String> {
    if let Some(exact) = RuleId::parse(trimmed) {
        push_unique_rule(rules, exact);
        return Ok(());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "arch" || lower == "architecture" {
        for meta in crate::rule_registry() {
            if meta.id.is_architecture_soc_or_reuse_rule()
                || meta.canonical_id.contains("arch")
                || meta.category == RuleCategory::Maintainability
            {
                push_unique_rule(rules, meta.id);
            }
        }
        return Ok(());
    }
    if let Some(parsed_cat) = RuleCategory::parse(trimmed) {
        for meta in crate::rule_registry() {
            if meta.category == parsed_cat {
                push_unique_rule(rules, meta.id);
            }
        }
        return Ok(());
    }
    let mut matched_prefix = false;
    for meta in crate::rule_registry() {
        if meta.canonical_id.starts_with(&lower) {
            matched_prefix = true;
            push_unique_rule(rules, meta.id);
        }
    }
    if !matched_prefix {
        return Err(format!("Unknown --only filter: {trimmed:?}"));
    }
    Ok(())
}

fn split_non_empty_csv(items: &[String]) -> impl Iterator<Item = &str> {
    items
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

pub(super) fn resolve_enabled_rules(
    rule_strs: &[String],
    category_strs: &[String],
    only_strs: &[String],
) -> Result<Option<Vec<RuleId>>, String> {
    let mut rules: Vec<RuleId> = Vec::new();
    for r in split_non_empty_csv(rule_strs) {
        let Some(parsed) = RuleId::parse(r) else {
            return Err(format!("Unknown rule ID: {r:?}"));
        };
        push_unique_rule(&mut rules, parsed);
    }
    for cat in split_non_empty_csv(category_strs) {
        append_category_rules(cat, &mut rules)?;
    }
    for only in split_non_empty_csv(only_strs) {
        append_only_filter_rules(only, &mut rules)?;
    }
    Ok((!rules.is_empty()).then_some(rules))
}

pub(super) fn build_scan_options(
    paths: &[PathBuf],
    include_tests: bool,
    rule_strs: &[String],
    category_strs: &[String],
    only_strs: &[String],
    tier_strs: &[String],
) -> Result<ScanOptions, String> {
    let rules = resolve_enabled_rules(rule_strs, category_strs, only_strs)?;

    let mut tiers = Vec::with_capacity(tier_strs.len());
    for t in tier_strs {
        let Some(parsed) = PrescriptionTier::parse(t) else {
            return Err(format!(
                "Unknown prescription tier: {t:?} (expected autofix, surgical, or refactor)"
            ));
        };
        tiers.push(parsed);
    }

    Ok(ScanOptions {
        paths: paths.to_vec(),
        include_tests,
        rules,
        tiers: (!tiers.is_empty()).then_some(tiers),
    })
}

fn resolve_auto_handoff_target() -> HandoffTarget {
    let available = detect_available_coding_agents();
    let preferred = load_preferred_handoff_target();
    if let Some(pref) = preferred
        && pref.binary_name().is_some()
        && available.contains(&pref)
    {
        return pref;
    }
    if let Some(&first_agent) = available.first() {
        return first_agent;
    }
    preferred.unwrap_or(HandoffTarget::Print)
}

pub(super) fn resolve_check_handoff_and_paths(
    args: &CheckArgs,
) -> Result<(Option<HandoffTarget>, Vec<PathBuf>), String> {
    let mut effective_paths = args.paths.clone();
    let Some(raw_target) = args.handoff.as_deref() else {
        return Ok((None, effective_paths));
    };
    if raw_target.eq_ignore_ascii_case("auto") {
        return Ok((Some(resolve_auto_handoff_target()), effective_paths));
    }
    if let Some(parsed) = HandoffTarget::parse(raw_target) {
        return Ok((Some(parsed), effective_paths));
    }
    let candidate_path = Path::new(raw_target);
    if candidate_path.exists() {
        effective_paths.insert(0, candidate_path.to_path_buf());
        return Ok((Some(resolve_auto_handoff_target()), effective_paths));
    }
    Err(format!(
        "Unknown --handoff target {raw_target:?} (expected print, clipboard, claude, codex, cursor, amp, or opencode)"
    ))
}

pub(super) fn resolve_check_gate_params(
    args: &CheckArgs,
) -> Result<(DiffScope, BlockingLevel, Option<u8>), String> {
    let Some(scope) = DiffScope::parse(&args.scope) else {
        return Err(format!(
            "Unknown --scope {:?} (expected full, changed, contextual, or lines)",
            args.scope
        ));
    };

    let blocking = if args.no_fail {
        BlockingLevel::None
    } else if let Some(raw_blocking) = &args.blocking {
        BlockingLevel::parse(raw_blocking).ok_or_else(|| {
            format!("Unknown --blocking {raw_blocking:?} (expected error, warning, or none)")
        })?
    } else if args.warning_exit_code.is_some() {
        BlockingLevel::Error
    } else {
        BlockingLevel::Warning
    };

    let warning_exit_code = match args.warning_exit_code {
        Some(raw) => Some(validate_warning_exit_code(raw)?),
        None => None,
    };

    Ok((scope, blocking, warning_exit_code))
}
