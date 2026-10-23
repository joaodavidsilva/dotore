//! CLI entrypoint for `dotore`.

use std::{
    collections::BTreeMap,
    env,
    fmt::Write as _,
    fs::OpenOptions,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand};
use dotore::{
    BlastRadiusTier, BlockingLevel, BuildRuntimeScanReportInput, CiOptions, CiProviderKind,
    CliOverrides, ConfigMutation, Diagnostic, DiffScope, InstallOptions, JsonReport,
    PrescriptionTier, RUNTIME_SCAN_LOCAL_DEV_PORTS, RecordRuntimeTraceInput, RuleCategory, RuleId,
    RuleSeverity, RuleSeverityOverride, RuleTag, RulesListOptions, RuntimeScanFormat, ScanOptions,
    SearchOptions, SymbolKind, apply_autofixes, build_rule_catalog, build_runtime_scan_report,
    ci_config, ci_install, ci_upgrade, current_scan_progress, detect_local_runtime_urls,
    explain_location, explain_rule, format_design_report,
    format_design_report_pretty, format_fix_report, format_install_report, format_plan_report,
    format_rule_catalog_text, format_rule_explanation_text, format_runtime_scan_error_report,
    format_runtime_scan_report, format_search_json, format_search_text, format_terminal_report,
    format_terminal_report_pretty, format_why_report_text, install_dotore, load_config_from_dir,
    mutate_config_in_dir, plan_project, prompt_runtime_scan_url_with_io, record_runtime_trace,
    resolve_runtime_scan_format, resolve_scan_exit_code, scan_design,
    scan_workspace_with_overrides, search_symbols,
    should_highlight_stdout, validate_warning_exit_code, write_and_open_html_report,
    write_json_report,
};

#[derive(Debug, Parser)]
#[command(
    name = "dotore",
    version,
    about = "Pure-Rust React and TypeScript static analyzer, deterministic auto-fixer, and remediation engine."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    check_args: CheckArgs,
}

#[derive(Debug, Subcommand)]
enum Commands {
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
    Install(InstallArgs),
}
#[derive(Debug, Clone, Args)]
struct CheckArgs {
    /// Files or directories to scan (defaults to current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Emit machine-readable JSON output for agents and skills.
    #[arg(long)]
    json: bool,

    /// Write the versioned machine-readable JSON report to a file on disk.
    #[arg(long = "json-out", value_name = "FILE")]
    json_out: Option<PathBuf>,

    /// Print only the numeric `0..=100` Health Score to stdout.
    #[arg(long)]
    score: bool,

    /// Git diff scan scope (`full`, `changed`, `contextual`, `lines`).
    #[arg(long, default_value = "full", value_name = "SCOPE")]
    scope: String,

    /// Base git branch, revision, or commit range (`A..B`, `A...B`) for diff scopes.
    #[arg(long = "base", value_name = "REF")]
    base_ref: Option<String>,

    /// Restrict scan to staged git index changes (`git diff --cached`).
    #[arg(long)]
    staged: bool,

    /// Compare against a saved baseline JSON report or git revision as a fingerprint multiset.
    #[arg(long, value_name = "REPORT_JSON")]
    baseline: Option<PathBuf>,

    /// Severity threshold that blocks CI (`error`, `warning`, `none`).
    #[arg(long, value_name = "LEVEL")]
    blocking: Option<String>,
    /// Custom exit code (`2..=255`) returned when warnings are present and no blocking errors occurred.
    #[arg(long = "warning-exit-code", value_name = "CODE")]
    warning_exit_code: Option<u32>,

    /// Exit with code 0 even when diagnostics are found (alias for `--blocking none`).
    #[arg(long)]
    no_fail: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Filter by rule ID or legacy alias (repeatable, e.g. `--rule no-derived-state`).
    #[arg(long = "rule", value_name = "RULE_ID")]
    rules: Vec<String>,

    /// Filter by Prescription Tier (`autofix`, `surgical`, `refactor`).
    #[arg(long = "tier", value_name = "TIER")]
    tiers: Vec<String>,

    /// Disable the interactive `less` pager when running in a terminal.
    #[arg(long = "no-pager")]
    no_pager: bool,
}

#[derive(Debug, Clone, Args)]
struct FixArgs {
    /// Files or directories to scan and fix (defaults to current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Preview planned fixes without writing to disk.
    #[arg(long)]
    dry_run: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct PlanArgs {
    /// Files or directories to scan and plan (defaults to current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Output directory for generated `NNN-<slug>.md` plans and `README.md` index.
    #[arg(short, long = "out", default_value = "plans", value_name = "DIR")]
    out: PathBuf,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    include_tests: bool,

    /// Bypass inline disable comments (`// dotore-disable-next-line`, `// eslint-disable-next-line`, `// oxlint-disable-next-line`).
    #[arg(long)]
    no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}
#[derive(Debug, Clone, Args)]
struct ReportArgs {
    /// Files or directories to scan (defaults to current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Output HTML file path (defaults to a fresh temp directory).
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Do not open the generated HTML file in the system browser.
    #[arg(long)]
    no_open: bool,

    /// Include test files (`.test.*`, `.spec.*`, `__tests__`).
    #[arg(long)]
    include_tests: bool,

    /// Bypass inline disable comments.
    #[arg(long)]
    no_inline_disables: bool,

    /// Disable rules originally ported from external plugins unless explicitly enabled in config.
    #[arg(long)]
    custom_rules_only: bool,

    /// Ignore rules carrying the specified tag (repeatable, e.g. `--ignore-tag design`).
    #[arg(long = "ignore-tag", value_name = "TAG")]
    ignore_tags: Vec<String>,

    /// Explicit path to a `dotore.config.*` file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SearchFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Args)]
struct SearchArgs {
    /// Fuzzy query string matched against symbol names.
    #[arg(value_name = "QUERY")]
    query: String,

    /// Files or directories to search (defaults to current directory).
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Comma-separated symbol kinds to include (default: class,enum,function,interface,method,property,type).
    #[arg(short = 'k', long = "kind", value_name = "KINDS")]
    kind: Option<String>,

    /// Maximum number of ranked matches to return.
    #[arg(short = 'l', long = "limit", default_value_t = 50, value_name = "N")]
    limit: usize,

    /// Output format (`text` or `json`).
    #[arg(short = 'f', long = "format", value_enum, default_value_t = SearchFormat::Text, value_name = "FORMAT")]
    format: SearchFormat,

    /// Disable ANSI syntax highlighting in text output.
    #[arg(long)]
    no_color: bool,
}

#[derive(Debug, Clone, Args)]
struct ScanArgs {
    /// Target `http://` or `https://` URL to profile (optional in interactive terminals).
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Connect to an existing debug-enabled Chrome instance (`ws://...` or `http://...`).
    #[arg(long, value_name = "URL")]
    cdp: Option<String>,

    /// Output path for the compressed `.json.gz` DevTools trace.
    #[arg(long = "trace-out", value_name = "FILE")]
    trace_out: Option<PathBuf>,

    /// Output format (`text`, `json`, or `jsonl`).
    #[arg(long, value_name = "FORMAT")]
    format: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesSubcommand,
}

#[derive(Debug, Clone, Subcommand)]
enum RulesSubcommand {
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

#[derive(Debug, Clone, Args)]
struct RulesListArgs {
    /// Filter by category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    #[arg(long, value_name = "CATEGORY")]
    category: Option<String>,

    /// Filter by behavioral tag (`design`, `test-noise`, `r3f`, etc.).
    #[arg(long, value_name = "TAG")]
    tag: Option<String>,

    /// Filter by capability or framework (`react`, `nextjs`, `tanstack-query`, `three`, `global`, etc.).
    #[arg(long, value_name = "FRAMEWORK")]
    framework: Option<String>,

    /// Only show rules with explicit configuration overrides.
    #[arg(long)]
    configured: bool,

    /// Emit machine-readable JSON array.
    #[arg(long)]
    json: bool,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesExplainArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias (`effect/<id>`, `react/<id>`).
    #[arg(value_name = "RULE")]
    rule: String,

    /// Emit machine-readable JSON object.
    #[arg(long)]
    json: bool,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesEnableArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    rule: String,

    /// Severity to enable the rule at (`warn` or `error`; defaults to the rule's default severity).
    #[arg(long, value_name = "SEVERITY")]
    severity: Option<String>,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesDisableArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    rule: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesSetArgs {
    /// Rule ID, qualified key (`dotore/<id>`), or legacy alias.
    #[arg(value_name = "RULE")]
    rule: String,

    /// Target severity (`off`, `warn`, or `error`).
    #[arg(value_name = "SEVERITY")]
    severity: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesCategoryArgs {
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    #[arg(value_name = "CATEGORY")]
    category: String,

    /// Target severity (`off`, `warn`, or `error`).
    #[arg(value_name = "SEVERITY")]
    severity: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct RulesTagArgs {
    /// Behavioral tag (`design`, `test-noise`, `r3f`, etc.).
    #[arg(value_name = "TAG")]
    tag: String,

    /// Working directory for resolving `dotore.config.*` or `package.json#dotore`.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct WhyArgs {
    /// Source location (`<file:line>` or `<file:line:column>`).
    #[arg(value_name = "FILE:LINE")]
    location: String,

    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,

    /// Working directory for resolving project configuration and cross-file callers.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct CiArgs {
    #[command(subcommand)]
    command: CiSubcommand,
}

#[derive(Debug, Clone, Subcommand)]
enum CiSubcommand {
    /// Generate a CI pull-request workflow (`.github/workflows/dotore.yml` or `.gitlab-ci.yml`).
    Install(CiActionArgs),
    /// Upgrade an existing CI workflow to the latest `dotore` v2 configuration.
    Upgrade(CiActionArgs),
    /// Update `blocking` or `scope` settings in an existing CI workflow.
    Config(CiActionArgs),
}

#[derive(Debug, Clone, Args)]
struct CiActionArgs {
    /// CI provider (`github-actions` or `gitlab-ci`).
    #[arg(long, value_name = "PROVIDER")]
    provider: Option<String>,

    /// Gate blocking level (`none`, `warning`, or `error`).
    #[arg(long, value_name = "LEVEL")]
    blocking: Option<String>,

    /// Diff scope (`changed`, `contextual`, `lines`, or `full`).
    #[arg(long, value_name = "SCOPE")]
    scope: Option<String>,

    /// Non-interactive confirmation flag.
    #[arg(short = 'y', long)]
    yes: bool,

    /// Target repository directory.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct InstallArgs {
    /// Accept all setup steps non-interactively (skill, script, git hook, agent hooks).
    #[arg(short = 'y', long)]
    yes: bool,

    /// Print planned file operations without writing to disk.
    #[arg(long)]
    dry_run: bool,

    /// Install agent stop hooks (`.claude/settings.json` and `.claude/hooks/dotore.mjs`).
    #[arg(long)]
    agent_hooks: bool,

    /// Target project root directory.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cwd: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Check(args)) => run_check(&args),
        Some(Commands::Fix(args)) => run_fix(&args),
        Some(Commands::Plan(args)) => run_plan(&args),
        Some(Commands::Score(mut args)) => {
            args.score = true;
            run_check(&args)
        }
        Some(Commands::Report(args)) => run_report(&args),
        Some(Commands::Search(args)) => run_search(&args),
        Some(Commands::Scan(args)) => run_scan(&args),
        Some(Commands::Rules(args)) => run_rules(&args),
        Some(Commands::Why(args)) => run_why(&args),
        Some(Commands::Design(args)) => run_design(&args),
        Some(Commands::Ci(args)) => run_ci(&args),
        Some(Commands::Install(args)) => run_install(&args),
        None => run_check(&cli.check_args),
    }
}

fn build_scan_options(
    paths: &[PathBuf],
    include_tests: bool,
    rule_strs: &[String],
    tier_strs: &[String],
) -> Result<ScanOptions, String> {
    let mut rules = Vec::new();
    for r in rule_strs {
        let Some(parsed) = RuleId::parse(r) else {
            return Err(format!("Unknown rule ID: {r:?}"));
        };
        rules.push(parsed);
    }

    let mut tiers = Vec::new();
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
        rules: (!rules.is_empty()).then_some(rules),
        tiers: (!tiers.is_empty()).then_some(tiers),
    })
}

fn run_check(args: &CheckArgs) -> ExitCode {
    let Some(scope) = DiffScope::parse(&args.scope) else {
        eprintln!(
            "error: Unknown --scope {:?} (expected full, changed, contextual, or lines)",
            args.scope
        );
        return ExitCode::from(2);
    };

    let blocking = if args.no_fail {
        BlockingLevel::None
    } else if let Some(raw_blocking) = &args.blocking {
        let Some(parsed) = BlockingLevel::parse(raw_blocking) else {
            eprintln!(
                "error: Unknown --blocking {raw_blocking:?} (expected error, warning, or none)"
            );
            return ExitCode::from(2);
        };
        parsed
    } else if args.warning_exit_code.is_some() {
        BlockingLevel::Error
    } else {
        BlockingLevel::Warning
    };

    let warning_exit_code = match args.warning_exit_code {
        Some(raw) => match validate_warning_exit_code(raw) {
            Ok(valid) => Some(valid),
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let options =
        match build_scan_options(&args.paths, args.include_tests, &args.rules, &args.tiers) {
            Ok(opts) => opts,
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(2);
            }
        };

    let overrides = CliOverrides {
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: args.ignore_tags.clone(),
        config_path: args.config.clone(),
        scope,
        base_ref: args.base_ref.clone(),
        staged: args.staged,
        baseline_path: args.baseline.clone(),
    };

    let show_live_spinner = !args.score && !args.json && should_launch_tui(args.no_pager);
    let spinner_guard = if show_live_spinner {
        LiveProgressBar::start()
    } else {
        None
    };
    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            drop(spinner_guard);
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };
    drop(spinner_guard);

    if let Some(out_path) = &args.json_out
        && let Err(err) = write_json_report(&report, out_path)
    {
        eprintln!("error writing JSON report to {}: {err}", out_path.display());
        return ExitCode::from(2);
    }

    if args.score {
        println!("{}", report.summary.health_score);
    } else if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing JSON: {err}");
                return ExitCode::from(2);
            }
        }
    } else if should_launch_tui(args.no_pager) {
        let color = should_highlight_stdout(false);
        if !run_interactive_tui(&report, false) {
            print!("{}", format_terminal_report_pretty(&report, color));
        }
    } else if io::stdout().is_terminal() {
        let color = should_highlight_stdout(false);
        print!("{}", format_terminal_report_pretty(&report, color));
    } else {
        print!("{}", format_terminal_report(&report));
    }

    let code = resolve_scan_exit_code(&report.diagnostics, blocking, warning_exit_code);
    ExitCode::from(code)
}

fn run_fix(args: &FixArgs) -> ExitCode {
    let options = ScanOptions {
        paths: args.paths.clone(),
        include_tests: args.include_tests,
        rules: None,
        tiers: Some(vec![PrescriptionTier::Autofix]),
    };
    let overrides = CliOverrides {
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: args.ignore_tags.clone(),
        config_path: args.config.clone(),
        ..Default::default()
    };

    let (report, sources) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };

    let results = match apply_autofixes(&report.diagnostics, &sources, args.dry_run) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error applying autofixes: {err}");
            return ExitCode::from(2);
        }
    };

    print!("{}", format_fix_report(&results, args.dry_run));
    ExitCode::SUCCESS
}

fn run_plan(args: &PlanArgs) -> ExitCode {
    let options = ScanOptions {
        paths: args.paths.clone(),
        include_tests: args.include_tests,
        rules: None,
        tiers: None,
    };
    let overrides = CliOverrides {
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: args.ignore_tags.clone(),
        config_path: args.config.clone(),
        ..Default::default()
    };

    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };

    match plan_project(&report, &args.out) {
        Ok(result) => {
            print!("{}", format_plan_report(&result));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error writing remediation plans: {err}");
            ExitCode::from(2)
        }
    }
}
fn run_report(args: &ReportArgs) -> ExitCode {
    let options = ScanOptions {
        paths: args.paths.clone(),
        include_tests: args.include_tests,
        rules: None,
        tiers: None,
    };
    let overrides = CliOverrides {
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: args.ignore_tags.clone(),
        config_path: args.config.clone(),
        ..Default::default()
    };

    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };

    match write_and_open_html_report(&report, args.output.as_deref(), !args.no_open) {
        Ok(path) => {
            println!("HTML report written to {}", path.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error writing HTML report: {err}");
            ExitCode::from(2)
        }
    }
}

fn parse_symbol_kinds_arg(raw: &str) -> Result<Vec<SymbolKind>, String> {
    let mut kinds = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(kind) = SymbolKind::parse(trimmed) else {
            let all_options = SymbolKind::ALL
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(",");
            return Err(format!(
                "Unsupported symbol kind \"{trimmed}\". Options: {all_options}."
            ));
        };
        kinds.push(kind);
    }
    if kinds.is_empty() {
        return Err("Symbol kind filter cannot be empty.".to_string());
    }
    Ok(kinds)
}

fn run_search(args: &SearchArgs) -> ExitCode {
    let kinds = match args.kind.as_deref() {
        Some(raw) => match parse_symbol_kinds_arg(raw) {
            Ok(parsed) => Some(parsed),
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let options = SearchOptions {
        paths: args.paths.clone(),
        kinds,
        limit: args.limit,
        include_tests: true,
    };

    let (results, sources) = match search_symbols(&args.query, &options) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error searching symbols: {err}");
            return ExitCode::from(2);
        }
    };

    let root_display = args.paths.first().map_or_else(
        || ".".to_string(),
        |p| p.to_string_lossy().replace('\\', "/"),
    );

    match args.format {
        SearchFormat::Json => {
            let report = format_search_json(&args.query, &root_display, &results);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("error serializing search JSON: {err}");
                    return ExitCode::from(2);
                }
            }
        }
        SearchFormat::Text => {
            let highlight = should_highlight_stdout(args.no_color);
            let rendered = format_search_text(&results, &sources, highlight);
            if !rendered.is_empty() {
                print!("{rendered}");
            }
        }
    }

    ExitCode::SUCCESS
}

fn run_scan(args: &ScanArgs) -> ExitCode {
    use std::io::IsTerminal;

    let format = match resolve_runtime_scan_format(args.format.as_deref()) {
        Ok(fmt) => fmt,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };

    let emit_error = |message: &str| -> ExitCode {
        if format == RuntimeScanFormat::Text {
            eprintln!("{message}");
        } else {
            print!("{}", format_runtime_scan_error_report(format, message));
        }
        ExitCode::from(1)
    };

    let resolved_url = if let Some(explicit_url) = &args.url {
        explicit_url.clone()
    } else {
        let force_interactive = std::env::var("DOTORE_FORCE_INTERACTIVE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        if !std::io::stdin().is_terminal() && !force_interactive {
            return emit_error(
                "A URL is required outside an interactive terminal. Run `dotore scan <url>`.",
            );
        }
        let ports: Vec<u16> = if let Ok(custom_ports) = std::env::var("DOTORE_SCAN_PORTS") {
            custom_ports
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect()
        } else {
            RUNTIME_SCAN_LOCAL_DEV_PORTS.to_vec()
        };
        let suggestions = detect_local_runtime_urls(&ports);
        let stdin = std::io::stdin();
        let mut stdin_lock = stdin.lock();
        let mut stderr = std::io::stderr();
        match prompt_runtime_scan_url_with_io(&suggestions, &mut stdin_lock, &mut stderr) {
            Ok(Some(chosen)) => chosen,
            Ok(None) => return ExitCode::SUCCESS,
            Err(err) => return emit_error(&err),
        }
    };

    if format == RuntimeScanFormat::Text {
        eprintln!(
            "Recording runtime performance. Interact with the page, then press Enter to stop."
        );
    }

    let capture = match record_runtime_trace(&RecordRuntimeTraceInput {
        url: resolved_url.clone(),
        trace_out: args.trace_out.clone(),
        cdp_url: args.cdp.clone(),
        max_recording_duration_ms: None,
    }) {
        Ok(c) => c,
        Err(err) => return emit_error(&err),
    };

    let report = match build_runtime_scan_report(&BuildRuntimeScanReportInput {
        requested_url: resolved_url,
        trace_path: capture.trace_path,
        captured_at: capture.captured_at,
        duration_ms: capture.duration_ms,
        snapshot: capture.snapshot,
        connection: capture.connection,
    }) {
        Ok(r) => r,
        Err(err) => return emit_error(&err),
    };

    print!("{}", format_runtime_scan_report(&report, format));
    ExitCode::SUCCESS
}

fn run_rules(args: &RulesArgs) -> ExitCode {
    match &args.command {
        RulesSubcommand::List(list_args) => {
            let config = load_config_from_dir(&list_args.cwd);
            let entries = build_rule_catalog(
                &config,
                &RulesListOptions {
                    category: list_args.category.clone(),
                    tag: list_args.tag.clone(),
                    framework: list_args.framework.clone(),
                    configured: list_args.configured,
                },
            );
            if list_args.json {
                match serde_json::to_string_pretty(&entries) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("error serializing rules JSON: {err}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                print!("{}", format_rule_catalog_text(&entries));
            }
            ExitCode::SUCCESS
        }
        RulesSubcommand::Explain(explain_args) => {
            let config = load_config_from_dir(&explain_args.cwd);
            let Some(entry) = explain_rule(&explain_args.rule, &config) else {
                eprintln!(
                    "Unknown rule {:?}. Run `dotore rules list` to see every available rule.",
                    explain_args.rule
                );
                return ExitCode::from(1);
            };
            if explain_args.json {
                match serde_json::to_string_pretty(&entry) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("error serializing rule explanation JSON: {err}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                print!("{}", format_rule_explanation_text(&entry));
            }
            ExitCode::SUCCESS
        }
        RulesSubcommand::Enable(enable_args) => {
            let Some(rule) = RuleId::parse(&enable_args.rule) else {
                eprintln!(
                    "Unknown rule {:?}. Run `dotore rules list` to see every available rule.",
                    enable_args.rule
                );
                return ExitCode::from(1);
            };
            let severity = if let Some(raw_sev) = &enable_args.severity {
                let Some(parsed) = RuleSeverityOverride::parse(raw_sev) else {
                    eprintln!("Invalid severity {raw_sev:?}. Expected one of: off, warn, error.");
                    return ExitCode::from(1);
                };
                if parsed == RuleSeverityOverride::Off {
                    eprintln!(
                        "`enable` cannot set a rule to off. Use `dotore rules disable` instead."
                    );
                    return ExitCode::from(1);
                }
                parsed
            } else {
                match rule.metadata().default_severity {
                    RuleSeverity::Error => RuleSeverityOverride::Error,
                    RuleSeverity::Warning => RuleSeverityOverride::Warn,
                }
            };
            apply_cli_config_mutation(
                &enable_args.cwd,
                ConfigMutation::SetRuleSeverity { rule, severity },
                &format!(
                    "Set {} -> {}",
                    rule.metadata().qualified_key,
                    severity.as_str()
                ),
            )
        }
        RulesSubcommand::Disable(disable_args) => {
            let Some(rule) = RuleId::parse(&disable_args.rule) else {
                eprintln!(
                    "Unknown rule {:?}. Run `dotore rules list` to see every available rule.",
                    disable_args.rule
                );
                return ExitCode::from(1);
            };
            apply_cli_config_mutation(
                &disable_args.cwd,
                ConfigMutation::SetRuleSeverity {
                    rule,
                    severity: RuleSeverityOverride::Off,
                },
                &format!("Set {} -> off", rule.metadata().qualified_key),
            )
        }
        RulesSubcommand::Set(set_args) => {
            let Some(rule) = RuleId::parse(&set_args.rule) else {
                eprintln!(
                    "Unknown rule {:?}. Run `dotore rules list` to see every available rule.",
                    set_args.rule
                );
                return ExitCode::from(1);
            };
            let Some(severity) = RuleSeverityOverride::parse(&set_args.severity) else {
                eprintln!(
                    "Invalid severity {:?}. Expected one of: off, warn, error.",
                    set_args.severity
                );
                return ExitCode::from(1);
            };
            apply_cli_config_mutation(
                &set_args.cwd,
                ConfigMutation::SetRuleSeverity { rule, severity },
                &format!(
                    "Set {} -> {}",
                    rule.metadata().qualified_key,
                    severity.as_str()
                ),
            )
        }
        RulesSubcommand::Category(cat_args) => {
            let Some(category) = RuleCategory::parse(&cat_args.category) else {
                eprintln!(
                    "Unknown category {:?}. Known categories: Bugs, Performance, Accessibility, Security, Maintainability.",
                    cat_args.category
                );
                return ExitCode::from(1);
            };
            let Some(severity) = RuleSeverityOverride::parse(&cat_args.severity) else {
                eprintln!(
                    "Invalid severity {:?}. Expected one of: off, warn, error.",
                    cat_args.severity
                );
                return ExitCode::from(1);
            };
            apply_cli_config_mutation(
                &cat_args.cwd,
                ConfigMutation::SetCategorySeverity { category, severity },
                &format!(
                    "Set category {:?} -> {}",
                    category.as_str(),
                    severity.as_str()
                ),
            )
        }
        RulesSubcommand::IgnoreTag(tag_args) => {
            let Some(tag) = RuleTag::parse(&tag_args.tag) else {
                eprintln!("Unknown tag {:?}.", tag_args.tag);
                return ExitCode::from(1);
            };
            apply_cli_config_mutation(
                &tag_args.cwd,
                ConfigMutation::IgnoreTag { tag },
                &format!("Ignoring tag {:?}", tag.as_str()),
            )
        }
        RulesSubcommand::UnignoreTag(tag_args) => {
            let Some(tag) = RuleTag::parse(&tag_args.tag) else {
                eprintln!("Unknown tag {:?}.", tag_args.tag);
                return ExitCode::from(1);
            };
            apply_cli_config_mutation(
                &tag_args.cwd,
                ConfigMutation::UnignoreTag { tag },
                &format!("Tag {:?} is no longer ignored", tag.as_str()),
            )
        }
    }
}

fn apply_cli_config_mutation(cwd: &Path, mutation: ConfigMutation, summary: &str) -> ExitCode {
    match mutate_config_in_dir(cwd, mutation) {
        Ok(res) => {
            if !res.changed {
                println!("No changes needed in {}.", res.target_path.display());
            } else {
                let suffix = if res.created { " (created)" } else { "" };
                println!("{summary}\n  Updated {}{suffix}", res.target_path.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run_why(args: &WhyArgs) -> ExitCode {
    match explain_location(&args.location, &args.cwd) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("error serializing why JSON: {err}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                print!("{}", format_why_report_text(&report));
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run_design(args: &CheckArgs) -> ExitCode {
    let options =
        match build_scan_options(&args.paths, args.include_tests, &args.rules, &args.tiers) {
            Ok(opts) => opts,
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(2);
            }
        };
    let overrides = CliOverrides {
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: args.ignore_tags.clone(),
        config_path: args.config.clone(),
        ..Default::default()
    };
    let show_live_spinner = !args.json && should_launch_tui(args.no_pager);
    let spinner_guard = if show_live_spinner {
        LiveProgressBar::start()
    } else {
        None
    };
    let (report, _) = match scan_design(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            drop(spinner_guard);
            eprintln!("error running design audit: {err}");
            return ExitCode::from(2);
        }
    };
    drop(spinner_guard);
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing design JSON: {err}");
                return ExitCode::from(2);
            }
        }
    } else if should_launch_tui(args.no_pager) {
        let color = should_highlight_stdout(false);
        if !run_interactive_tui(&report, true) {
            print!("{}", format_design_report_pretty(&report, color));
        }
    } else if io::stdout().is_terminal() {
        let color = should_highlight_stdout(false);
        print!("{}", format_design_report_pretty(&report, color));
    } else {
        print!("{}", format_design_report(&report));
    }
    if !args.no_fail && report.summary.total_diagnostics > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_ci(args: &CiArgs) -> ExitCode {
    let (sub_name, act_args) = match &args.command {
        CiSubcommand::Install(a) => ("install", a),
        CiSubcommand::Upgrade(a) => ("upgrade", a),
        CiSubcommand::Config(a) => ("config", a),
    };
    let provider = if let Some(raw_prov) = &act_args.provider {
        let Some(parsed) = CiProviderKind::parse(raw_prov) else {
            eprintln!(
                "Unknown --provider {raw_prov:?}. Expected one of: github-actions, gitlab-ci."
            );
            return ExitCode::from(1);
        };
        Some(parsed)
    } else {
        None
    };
    let ci_opts = CiOptions {
        cwd: act_args.cwd.clone(),
        provider,
        blocking: act_args.blocking.clone(),
        scope: act_args.scope.clone(),
    };
    let res = match sub_name {
        "install" => ci_install(&ci_opts),
        "upgrade" => ci_upgrade(&ci_opts),
        _ => ci_config(&ci_opts),
    };
    match res {
        Ok(outcome) => {
            println!(
                "dotore ci {sub_name}: {} ({}) [blocking: {}, scope: {}]",
                outcome.workflow_path.display(),
                outcome.status,
                outcome.blocking,
                outcome.scope
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run_install(args: &InstallArgs) -> ExitCode {
    match install_dotore(&InstallOptions {
        cwd: args.cwd.clone(),
        yes: args.yes,
        dry_run: args.dry_run,
        agent_hooks: args.agent_hooks,
    }) {
        Ok(result) => {
            print!("{}", format_install_report(&result));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}


struct LiveProgressBar {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LiveProgressBar {
    fn start() -> Option<Self> {
        let mut tty = OpenOptions::new().write(true).open("/dev/tty").ok()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let start = Instant::now();
            let mut tick = 0usize;
            let _ = write!(tty, "\x1b[?25l");
            let _ = tty.flush();
            while !stop_clone.load(Ordering::Relaxed) {
                let snap = current_scan_progress();
                let frame_ch = SPINNER[tick % SPINNER.len()];
                let elapsed = start.elapsed().as_secs_f32();
                let total = snap.total_files.max(1);
                let done = snap.completed_files.min(snap.total_files);
                let pct = if snap.total_files > 0 {
                    (done * 100) / total
                } else {
                    0
                };
                let bar_width = 22usize;
                let filled = if snap.total_files > 0 {
                    ((done * bar_width) + (total / 2)) / total
                } else {
                    (tick % bar_width).min(bar_width)
                };
                let filled = filled.min(bar_width);
                let empty = bar_width.saturating_sub(filled);
                let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

                let short_file = if snap.current_file.chars().count() > 48 {
                    let tail: String = snap
                        .current_file
                        .chars()
                        .rev()
                        .take(45)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    format!("…{tail}")
                } else {
                    snap.current_file.clone()
                };

                let _ = write!(
                    tty,
                    "\r\x1b[2K \x1b[38;5;51;1m{frame_ch} DOTORE\x1b[0m  \x1b[38;5;48;1m[{bar}]\x1b[0m \x1b[38;5;255;1m{pct:>3}%\x1b[0m \x1b[38;5;245m({done}/{})\x1b[0m · \x1b[38;5;220;1m{elapsed:.1}s\x1b[0m · \x1b[38;5;141;1m{}\x1b[0m  \x1b[38;5;243m{}\x1b[0m",
                    snap.total_files,
                    snap.phase,
                    short_file
                );
                let _ = tty.flush();
                tick += 1;
                thread::sleep(Duration::from_millis(30));
            }
            let _ = write!(tty, "\r\x1b[2K\x1b[?25h");
            let _ = tty.flush();
        });
        Some(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for LiveProgressBar {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
fn should_launch_tui(no_pager: bool) -> bool {
    !no_pager
        && io::stdout().is_terminal()
        && io::stdin().is_terminal()
        && env::var_os("DOTORE_NO_PAGER").is_none()
        && env::var_os("CI").is_none()
        && !env::var("TERM").is_ok_and(|t| t == "dumb")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiFilterKind {
    All,
    Autofix,
    Errors,
    Warnings,
    StyleBucket(&'static str),
    Rule(RuleId),
}

#[derive(Debug, Clone)]
struct TuiFilterTab {
    label: String,
    badge_ansi: &'static str,
    kind: TuiFilterKind,
    count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiGroupMode {
    ByRuleStyle,
    ByFile,
    DetailedCards,
}

impl TuiGroupMode {
    const fn next(self) -> Self {
        match self {
            Self::ByRuleStyle => Self::ByFile,
            Self::ByFile => Self::DetailedCards,
            Self::DetailedCards => Self::ByRuleStyle,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ByRuleStyle => "By Error Style / Rule",
            Self::ByFile => "By File",
            Self::DetailedCards => "Detailed Cascade Cards",
        }
    }
}

fn classify_style_bucket(diag: &Diagnostic) -> &'static str {
    let id = diag.rule.as_str();
    if id.contains("unused") || id.contains("dead") || id.contains("orphan") {
        "UNUSED"
    } else if id.contains("derived-state")
        || id.contains("effect")
        || id.contains("state")
        || id.contains("signal")
        || id.contains("prop-change")
        || id.contains("hook")
        || !diag.cascade_steps.is_empty()
    {
        "EFFECTS & STATE"
    } else if id.contains("async")
        || id.contains("await")
        || id.contains("tokio")
        || id.contains("subscribe")
        || id.contains("rxjs")
        || id.contains("promise")
    {
        "ASYNC & STREAMS"
    } else if id.contains("unwrap")
        || id.contains("guard")
        || id.contains("optional-chain")
        || id.contains("parse")
        || id.contains("except")
        || id.contains("unsafe")
        || id.contains("cast")
        || id.contains("context-manager")
        || id.contains("mutable-default")
    {
        "SAFETY & GUARDS"
    } else if diag.category == RuleCategory::Security
        || id.contains("security")
        || id.contains("sql")
        || id.contains("xss")
        || id.contains("auth")
        || id.contains("eval")
    {
        "SECURITY"
    } else if diag.category == RuleCategory::Accessibility
        || id.contains("a11y")
        || id.contains("aria")
        || id.contains("jsx")
        || id.contains("key")
        || id.contains("track")
        || id.contains("dom")
    {
        "JSX & A11Y"
    } else if diag.category == RuleCategory::Performance
        || id.contains("perf")
        || id.contains("loop")
        || id.contains("clone")
        || id.contains("memo")
        || id.contains("on-push")
        || id.contains("bundle")
        || id.contains("capacity")
    {
        "PERF & LOOPS"
    } else if id.contains("import")
        || id.contains("circular")
        || id.contains("barrel")
        || id.contains("arch")
        || id.contains("export")
    {
        "IMPORTS & ARCH"
    } else if diag.rule.metadata().tags.contains(&RuleTag::Design) || id.contains("design") {
        "UI DESIGN"
    } else {
        "CORRECTNESS"
    }
}

const fn style_bucket_color(bucket: &str) -> &'static str {
    match bucket.as_bytes() {
        b"UNUSED" => "\x1b[38;5;214;1m",
        b"EFFECTS & STATE" => "\x1b[38;5;201;1m",
        b"ASYNC & STREAMS" => "\x1b[38;5;45;1m",
        b"SAFETY & GUARDS" => "\x1b[38;5;208;1m",
        b"SECURITY" => "\x1b[38;5;196;1m",
        b"JSX & A11Y" => "\x1b[38;5;141;1m",
        b"PERF & LOOPS" => "\x1b[38;5;220;1m",
        b"IMPORTS & ARCH" => "\x1b[38;5;75;1m",
        b"UI DESIGN" => "\x1b[38;5;219;1m",
        _ => "\x1b[38;5;81;1m",
    }
}

fn build_filter_tabs(report: &JsonReport) -> Vec<TuiFilterTab> {
    let mut tabs = Vec::new();
    tabs.push(TuiFilterTab {
        label: "ALL".to_string(),
        badge_ansi: "\x1b[38;5;51;1m",
        kind: TuiFilterKind::All,
        count: report.diagnostics.len(),
    });

    let autofix_count = report
        .diagnostics
        .iter()
        .filter(|d| d.tier == PrescriptionTier::Autofix || d.autofix.is_some())
        .count();
    if autofix_count > 0 {
        tabs.push(TuiFilterTab {
            label: "⚙ AUTOFIX".to_string(),
            badge_ansi: "\x1b[38;5;48;1m",
            kind: TuiFilterKind::Autofix,
            count: autofix_count,
        });
    }

    let err_count = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Error)
        .count();
    if err_count > 0 && err_count < report.diagnostics.len() {
        tabs.push(TuiFilterTab {
            label: "✖ ERRORS".to_string(),
            badge_ansi: "\x1b[38;5;196;1m",
            kind: TuiFilterKind::Errors,
            count: err_count,
        });
    }

    let warn_count = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == RuleSeverity::Warning)
        .count();
    if warn_count > 0 && warn_count < report.diagnostics.len() {
        tabs.push(TuiFilterTab {
            label: "▲ WARNINGS".to_string(),
            badge_ansi: "\x1b[38;5;220;1m",
            kind: TuiFilterKind::Warnings,
            count: warn_count,
        });
    }

    let ordered_buckets = [
        "UNUSED",
        "EFFECTS & STATE",
        "ASYNC & STREAMS",
        "PERF & LOOPS",
        "SAFETY & GUARDS",
        "JSX & A11Y",
        "SECURITY",
        "IMPORTS & ARCH",
        "UI DESIGN",
        "CORRECTNESS",
    ];
    for bucket in ordered_buckets {
        let c = report
            .diagnostics
            .iter()
            .filter(|d| classify_style_bucket(d) == bucket)
            .count();
        if c > 0 {
            tabs.push(TuiFilterTab {
                label: bucket.to_string(),
                badge_ansi: style_bucket_color(bucket),
                kind: TuiFilterKind::StyleBucket(bucket),
                count: c,
            });
        }
    }

    let mut rule_counts: BTreeMap<&'static str, (RuleId, usize)> = BTreeMap::new();
    for d in &report.diagnostics {
        let entry = rule_counts.entry(d.rule.as_str()).or_insert((d.rule, 0));
        entry.1 += 1;
    }
    let mut sorted_rules: Vec<(RuleId, &'static str, usize)> = rule_counts
        .into_iter()
        .map(|(name, (id, count))| (id, name, count))
        .collect();
    sorted_rules.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(b.1)));

    for (rule_id, rule_name, count) in sorted_rules {
        tabs.push(TuiFilterTab {
            label: format!("#{rule_name}"),
            badge_ansi: "\x1b[38;5;117;1m",
            kind: TuiFilterKind::Rule(rule_id),
            count,
        });
    }

    tabs
}

fn diagnostic_matches_tab_and_search(
    diag: &Diagnostic,
    tab: &TuiFilterTab,
    search_query: &str,
) -> bool {
    let matches_tab = match &tab.kind {
        TuiFilterKind::All => true,
        TuiFilterKind::Autofix => diag.tier == PrescriptionTier::Autofix || diag.autofix.is_some(),
        TuiFilterKind::Errors => diag.severity == RuleSeverity::Error,
        TuiFilterKind::Warnings => diag.severity == RuleSeverity::Warning,
        TuiFilterKind::StyleBucket(bucket) => classify_style_bucket(diag) == *bucket,
        TuiFilterKind::Rule(r) => diag.rule == *r,
    };
    if !matches_tab {
        return false;
    }
    if search_query.is_empty() {
        return true;
    }
    let q = search_query.to_ascii_lowercase();
    diag.rule.as_str().to_ascii_lowercase().contains(&q)
        || diag
            .file
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(&q)
        || diag
            .subject_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(&q)
        || diag.message.to_ascii_lowercase().contains(&q)
}

struct TtyRawGuard {
    saved_stty: Option<String>,
}

impl TtyRawGuard {
    fn enter() -> Option<Self> {
        let tty_for_get = OpenOptions::new().read(true).open("/dev/tty").ok()?;
        let stty_out = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::from(tty_for_get))
            .output()
            .ok()?;
        let saved_stty = if stty_out.status.success() {
            Some(String::from_utf8_lossy(&stty_out.stdout).trim().to_string())
        } else {
            None
        };

        let tty_in = OpenOptions::new().read(true).open("/dev/tty").ok()?;
        let status = Command::new("stty")
            .args(["-icanon", "-echo", "min", "1", "time", "0"])
            .stdin(Stdio::from(tty_in))
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }

        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        let _ = stdout.flush();

        Some(Self { saved_stty })
    }
}

impl Drop for TtyRawGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved_stty
            && let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty")
        {
            let _ = Command::new("stty")
                .arg(saved)
                .stdin(Stdio::from(tty_in))
                .status();
        } else if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty") {
            let _ = Command::new("stty")
                .arg("sane")
                .stdin(Stdio::from(tty_in))
                .status();
        }
        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[?25h\x1b[?1049l");
        let _ = stdout.flush();
    }
}

fn query_terminal_size() -> (usize, usize) {
    if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty")
        && let Ok(out) = Command::new("stty")
            .arg("size")
            .stdin(Stdio::from(tty_in))
            .output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut parts = s.split_whitespace();
        if let (Some(r), Some(c)) = (parts.next(), parts.next())
            && let (Ok(rows), Ok(cols)) = (r.parse::<usize>(), c.parse::<usize>())
            && rows >= 12
            && cols >= 40
        {
            return (rows, cols);
        }
    }
    (36, 120)
}

fn render_tui_body_lines(
    filtered: &[&Diagnostic],
    group_mode: TuiGroupMode,
) -> Vec<String> {
    let mut lines = Vec::new();
    if filtered.is_empty() {
        lines.push(String::new());
        lines.push("  \x1b[38;5;48;1m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m".to_string());
        lines.push("  \x1b[38;5;48;1m║  ✔  Zero findings match this filter!                                     ║\x1b[0m".to_string());
        lines.push("  \x1b[38;5;48;1m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m".to_string());
        return lines;
    }

    match group_mode {
        TuiGroupMode::ByRuleStyle => {
            let mut by_rule: BTreeMap<&'static str, Vec<&Diagnostic>> = BTreeMap::new();
            for d in filtered {
                by_rule.entry(d.rule.as_str()).or_default().push(*d);
            }
            let mut groups: Vec<(&'static str, Vec<&Diagnostic>)> = by_rule.into_iter().collect();
            groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

            for (rule_name, items) in groups {
                let Some(first) = items.first() else {
                    continue;
                };
                let bucket = classify_style_bucket(first);
                let bucket_col = style_bucket_color(bucket);
                let tier_badge = match first.tier {
                    PrescriptionTier::Autofix => "\x1b[48;5;22;38;5;48;1m ⚙ AUTOFIX \x1b[0m",
                    PrescriptionTier::Surgical => "\x1b[48;5;58;38;5;220;1m ✎ SURGICAL \x1b[0m",
                    PrescriptionTier::Refactor => "\x1b[48;5;52;38;5;203;1m ⇄ REFACTOR \x1b[0m",
                };
                let sev_badge = match first.severity {
                    RuleSeverity::Error => "\x1b[38;5;196;1m✖ ERROR\x1b[0m",
                    RuleSeverity::Warning => "\x1b[38;5;220;1m▲ WARN \x1b[0m",
                };
                lines.push(format!(
                    " \x1b[38;5;240m╭───\x1b[0m {bucket_col}[{bucket}]\x1b[0m \x1b[38;5;51;1m{rule_name}\x1b[0m  {tier_badge}  {sev_badge}  \x1b[38;5;252;1m({} finding{})\x1b[0m",
                    items.len(),
                    if items.len() == 1 { "" } else { "s" }
                ));
                lines.push(format!(
                    " \x1b[38;5;240m│\x1b[0m    \x1b[38;5;245m{}\x1b[0m",
                    first.rule.metadata().title
                ));
                for d in &items {
                    let subj = d.subject_name.as_deref().unwrap_or("<module>");
                    lines.push(format!(
                        " \x1b[38;5;240m├─►\x1b[0m \x1b[38;5;153;1m{}:{}:{}\x1b[0m \x1b[38;5;244min\x1b[0m \x1b[38;5;219m`{subj}`\x1b[0m",
                        d.file.display(),
                        d.loc.line,
                        d.loc.column
                    ));
                    lines.push(format!(
                        " \x1b[38;5;240m│\x1b[0m      \x1b[38;5;254m{}\x1b[0m",
                        d.message
                    ));
                    if !d.cascade_steps.is_empty() {
                        let flow: Vec<String> =
                            d.cascade_steps.iter().map(|s| format!("[{s}]")).collect();
                        lines.push(format!(
                            " \x1b[38;5;240m│\x1b[0m      \x1b[38;5;201m┌─► {} ──► ↻ re-render\x1b[0m",
                            flow.join(" ──► ")
                        ));
                    }
                    if let Some(fix) = &d.autofix {
                        lines.push(format!(
                            " \x1b[38;5;240m│\x1b[0m      \x1b[38;5;48;1m⚙ autofix:\x1b[0m \x1b[38;5;121m{}\x1b[0m",
                            fix.description
                        ));
                    }
                }
                lines.push(" \x1b[38;5;240m╰──────────────────────────────────────────────────────────────────────────────\x1b[0m".to_string());
                lines.push(String::new());
            }
        }
        TuiGroupMode::ByFile => {
            let mut by_file: BTreeMap<String, Vec<&Diagnostic>> = BTreeMap::new();
            for d in filtered {
                by_file
                    .entry(d.file.display().to_string())
                    .or_default()
                    .push(*d);
            }
            for (file_path, items) in by_file {
                lines.push(format!(
                    " \x1b[38;5;240m╭───\x1b[0m \x1b[38;5;117;1m📁 {file_path}\x1b[0m  \x1b[38;5;252;1m({} finding{})\x1b[0m",
                    items.len(),
                    if items.len() == 1 { "" } else { "s" }
                ));
                for d in items {
                    let bucket = classify_style_bucket(d);
                    let bucket_col = style_bucket_color(bucket);
                    let subj = d.subject_name.as_deref().unwrap_or("<module>");
                    lines.push(format!(
                        " \x1b[38;5;240m├─►\x1b[0m \x1b[38;5;228;1mL{}:{}\x1b[0m {bucket_col}[{bucket}]\x1b[0m \x1b[38;5;51;1m[{}]\x1b[0m \x1b[38;5;244min\x1b[0m \x1b[38;5;219m`{subj}`\x1b[0m",
                        d.loc.line,
                        d.loc.column,
                        d.rule.as_str()
                    ));
                    lines.push(format!(
                        " \x1b[38;5;240m│\x1b[0m      \x1b[38;5;254m{}\x1b[0m",
                        d.message
                    ));
                    if let Some(fix) = &d.autofix {
                        lines.push(format!(
                            " \x1b[38;5;240m│\x1b[0m      \x1b[38;5;48;1m⚙ autofix:\x1b[0m \x1b[38;5;121m{}\x1b[0m",
                            fix.description
                        ));
                    }
                }
                lines.push(" \x1b[38;5;240m╰──────────────────────────────────────────────────────────────────────────────\x1b[0m".to_string());
                lines.push(String::new());
            }
        }
        TuiGroupMode::DetailedCards => {
            for d in filtered {
                let bucket = classify_style_bucket(d);
                let bucket_col = style_bucket_color(bucket);
                let subj = d.subject_name.as_deref().unwrap_or("<module>");
                lines.push(format!(
                    " \x1b[38;5;240m╭──\x1b[0m {bucket_col}[{bucket}]\x1b[0m \x1b[38;5;51;1m[{}]\x1b[0m ({}) \x1b[38;5;153;1m{}:{}:{}\x1b[0m in \x1b[38;5;219m`{subj}`\x1b[0m",
                    d.rule.as_str(),
                    d.tier.as_str(),
                    d.file.display(),
                    d.loc.line,
                    d.loc.column
                ));
                lines.push(format!(" \x1b[38;5;240m│\x1b[0m  {}", d.message));
                if !d.cascade_steps.is_empty() {
                    let flow: Vec<String> =
                        d.cascade_steps.iter().map(|s| format!("[{s}]")).collect();
                    lines.push(format!(
                        " \x1b[38;5;240m│\x1b[0m  \x1b[38;5;201mflow:    ┌─► {} ──► ↻ re-render\x1b[0m",
                        flow.join(" ──► ")
                    ));
                }
                if let Some(fix) = &d.autofix {
                    lines.push(format!(
                        " \x1b[38;5;240m│\x1b[0m  \x1b[38;5;48;1mautofix:\x1b[0m {}",
                        fix.description
                    ));
                }
                lines.push(format!(
                    " \x1b[38;5;240m╰──\x1b[0m \x1b[38;5;244mdocs:    {}\x1b[0m",
                    d.docs_url
                ));
                lines.push(String::new());
            }
        }
    }

    lines
}

fn build_score_gauge(score: u32, width: usize) -> String {
    let filled = ((score as usize).min(100) * width + 50) / 100;
    let empty = width.saturating_sub(filled);
    let col = if score >= 85 {
        "\x1b[38;5;48;1m"
    } else if score >= 60 {
        "\x1b[38;5;220;1m"
    } else {
        "\x1b[38;5;196;1m"
    };
    format!(
        "{col}[{}{}] {score}/100\x1b[0m",
        "█".repeat(filled),
        "░".repeat(empty)
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "TUI frame renderer takes viewport dimensions and current UI state directly"
)]
fn draw_tui_frame(
    report: &JsonReport,
    tabs: &[TuiFilterTab],
    active_tab_idx: usize,
    group_mode: TuiGroupMode,
    search_query: &str,
    in_search_input: bool,
    body_lines: &[String],
    scroll_offset: usize,
    rows: usize,
    cols: usize,
    design_mode: bool,
) {
    let s = &report.summary;
    let header_rows = 8usize;
    let footer_rows = 2usize;
    let viewport_height = rows.saturating_sub(header_rows + footer_rows).max(4);

    let p0 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P0)
        .count();
    let p1 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P1)
        .count();
    let p2 = report
        .root_cause_groups
        .iter()
        .filter(|g| g.blast_radius.tier == BlastRadiusTier::P2)
        .count();

    let mut frame = String::with_capacity(16384);
    frame.push_str("\x1b[H");

    let score_gauge = if design_mode {
        "\x1b[38;5;219;1mUI DESIGN AUDIT\x1b[0m".to_string()
    } else {
        format!(
            "{} \x1b[38;5;248m({})\x1b[0m",
            build_score_gauge(s.health_score, 18),
            s.score_label
        )
    };

    let _ = writeln!(
        frame,
        "\x1b[2K \x1b[38;5;51;1m╔══ DOTORE\x1b[0m \x1b[38;5;245m· Polyglot Static Analyzer\x1b[0m   {score_gauge}   \x1b[38;5;196;1m✖ {} err\x1b[0m  \x1b[38;5;220;1m▲ {} warn\x1b[0m  \x1b[38;5;48;1m⚙ {} autofix\x1b[0m  \x1b[38;5;220;1m✎ {} surgical\x1b[0m  \x1b[38;5;203;1m⇄ {} refactor\x1b[0m",
        s.error_count, s.warning_count, s.autofix_count, s.surgical_count, s.refactor_count
    );
    let _ = writeln!(
        frame,
        "\x1b[2K \x1b[38;5;51;1m║\x1b[0m  \x1b[38;5;250mScope:\x1b[0m {} files · {} subjects · {} effects · {} affected files   \x1b[38;5;250mBlast Radius:\x1b[0m \x1b[38;5;196;1mP0:{p0}\x1b[0m \x1b[38;5;208;1mP1:{p1}\x1b[0m \x1b[38;5;51;1mP2:{p2}\x1b[0m   \x1b[38;5;250mView:\x1b[0m \x1b[38;5;219;1m{}\x1b[0m",
        s.files_scanned,
        s.subjects_scanned,
        s.effects_scanned,
        s.affected_file_count,
        group_mode.label()
    );
    let _ = writeln!(
        frame,
        "\x1b[2K \x1b[38;5;51;1m╠══ FILTER TABS (h/l or ←/→ or Tab to switch) ═══════════════════════════════════════════════════\x1b[0m"
    );

    // Render primary style tabs on row 4 and rule tabs on row 5, centered around `active_tab_idx`
    let window_start = active_tab_idx.saturating_sub(3);
    let window_end = (window_start + 8).min(tabs.len());
    let mut tab_bar = String::from(" \x1b[38;5;51;1m║\x1b[0m ");
    if window_start > 0 {
        tab_bar.push_str("\x1b[38;5;244m« \x1b[0m");
    }
    for (idx, tab) in tabs
        .iter()
        .enumerate()
        .take(window_end)
        .skip(window_start)
    {
        if idx == active_tab_idx {
            let _ = write!(
                tab_bar,
                "\x1b[48;5;51;38;5;16;1m ▶ {} ({}) \x1b[0m ",
                tab.label, tab.count
            );
        } else {
            let _ = write!(
                tab_bar,
                "{}[ {} ({}) ]\x1b[0m ",
                tab.badge_ansi, tab.label, tab.count
            );
        }
    }
    if window_end < tabs.len() {
        let _ = write!(
            tab_bar,
            "\x1b[38;5;244m» (+{} more)\x1b[0m",
            tabs.len() - window_end
        );
    }
    let _ = writeln!(frame, "\x1b[2K{tab_bar}");

    let search_line = if in_search_input {
        format!(
            " \x1b[38;5;51;1m║\x1b[0m \x1b[48;5;236;38;5;226;1m SEARCH / \x1b[0m \x1b[38;5;255;1m{search_query}█\x1b[0m  \x1b[38;5;244m(Enter to lock, ESC to clear)\x1b[0m"
        )
    } else if !search_query.is_empty() {
        format!(
            " \x1b[38;5;51;1m║\x1b[0m \x1b[48;5;236;38;5;48;1m FILTER / \x1b[0m \x1b[38;5;255;1m\"{search_query}\"\x1b[0m  \x1b[38;5;244m(press / to edit, c to clear search)\x1b[0m"
        )
    } else {
        let active = &tabs[active_tab_idx];
        format!(
            " \x1b[38;5;51;1m║\x1b[0m \x1b[38;5;245mActive Filter:\x1b[0m {}{} ({} matching)\x1b[0m   \x1b[38;5;244mPress `/` to search by file, rule, or component\x1b[0m",
            active.badge_ansi, active.label, active.count
        )
    };
    let _ = writeln!(frame, "\x1b[2K{search_line}");
    let _ = writeln!(
        frame,
        "\x1b[2K \x1b[38;5;51;1m╚════════════════════════════════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    let _ = writeln!(frame, "\x1b[2K");

    let total_lines = body_lines.len().max(1);
    for row_idx in 0..viewport_height {
        let line_idx = scroll_offset + row_idx;
        if let Some(line) = body_lines.get(line_idx) {
            let _ = writeln!(frame, "\x1b[2K{line}");
        } else {
            let _ = writeln!(frame, "\x1b[2K \x1b[38;5;237m~\x1b[0m");
        }
    }

    let end_line = (scroll_offset + viewport_height).min(total_lines);
    let pct = (end_line * 100) / total_lines;
    let active_tab = &tabs[active_tab_idx];
    let _ = writeln!(
        frame,
        "\x1b[2K\x1b[48;5;235;38;5;255;1m DOTORE \x1b[48;5;238;38;5;51;1m {} ({}) \x1b[48;5;235;38;5;250m  Mode: {}  │  Lines {}-{} / {} ({pct}%)  │  Score: {}/100 ({}) \x1b[0m",
        active_tab.label,
        active_tab.count,
        group_mode.label(),
        (scroll_offset + 1).min(total_lines),
        end_line,
        total_lines,
        s.health_score,
        s.score_label
    );
    let _ = write!(
        frame,
        "\x1b[2K\x1b[48;5;234;38;5;252m \x1b[38;5;51;1m[h/l or ←/→]\x1b[38;5;252m Filter Tab  \x1b[38;5;51;1m[j/k or ↑/↓]\x1b[38;5;252m Scroll  \x1b[38;5;51;1m[Space/b]\x1b[38;5;252m Page  \x1b[38;5;51;1m[g/G]\x1b[38;5;252m Top/End  \x1b[38;5;51;1m[v]\x1b[38;5;252m Group Mode  \x1b[38;5;51;1m[/]\x1b[38;5;252m Search  \x1b[38;5;196;1m[ESC / q]\x1b[38;5;252m Quit \x1b[0m"
    );
    let _ = cols;

    let mut stdout = io::stdout();
    let _ = stdout.write_all(frame.as_bytes());
    let _ = stdout.flush();
}

fn run_interactive_tui(report: &JsonReport, design_mode: bool) -> bool {
    let Ok(mut tty) = OpenOptions::new().read(true).open("/dev/tty") else {
        return false;
    };
    let Some(_guard) = TtyRawGuard::enter() else {
        return false;
    };

    let tabs = build_filter_tabs(report);
    let mut active_tab_idx = 0usize;
    let mut group_mode = TuiGroupMode::ByRuleStyle;
    let mut search_query = String::new();
    let mut in_search_input = false;
    let mut scroll_offset = 0usize;

    loop {
        let (rows, cols) = query_terminal_size();
        let viewport_height = rows.saturating_sub(10).max(4);
        let active_tab = &tabs[active_tab_idx];
        let filtered: Vec<&Diagnostic> = report
            .diagnostics
            .iter()
            .filter(|d| diagnostic_matches_tab_and_search(d, active_tab, &search_query))
            .collect();
        let body_lines = render_tui_body_lines(&filtered, group_mode);
        let max_scroll = body_lines.len().saturating_sub(viewport_height);
        if scroll_offset > max_scroll {
            scroll_offset = max_scroll;
        }

        draw_tui_frame(
            report,
            &tabs,
            active_tab_idx,
            group_mode,
            &search_query,
            in_search_input,
            &body_lines,
            scroll_offset,
            rows,
            cols,
            design_mode,
        );

        let mut buf = [0u8; 16];
        let Ok(n) = tty.read(&mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }

        if in_search_input {
            handle_tui_search_key(&buf[..n], &mut search_query, &mut in_search_input, &mut scroll_offset);
            continue;
        }

        match &buf[..n] {
            // Bare ESC or 'q' or 'Q' or Ctrl+C -> exit TUI cleanly!
            [0x1b] | [b'q'] | [b'Q'] | [0x03] => break,
            // Up arrow or 'k'
            [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] | [b'k'] => {
                scroll_offset = scroll_offset.saturating_sub(1);
            }
            // Down arrow or 'j' or Enter
            [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] | [b'j'] | [b'\r'] | [b'\n'] => {
                scroll_offset = (scroll_offset + 1).min(max_scroll);
            }
            // Right arrow or 'l' or Tab -> next filter tab
            [0x1b, b'[', b'C'] | [0x1b, b'O', b'C'] | [b'l'] | [b'\t'] => {
                active_tab_idx = (active_tab_idx + 1) % tabs.len();
                scroll_offset = 0;
            }
            // Left arrow or 'h' or Shift+Tab -> previous filter tab
            [0x1b, b'[', b'D'] | [0x1b, b'O', b'D'] | [0x1b, b'[', b'Z'] | [b'h'] => {
                active_tab_idx = if active_tab_idx == 0 {
                    tabs.len() - 1
                } else {
                    active_tab_idx - 1
                };
                scroll_offset = 0;
            }
            // PageDown or Space or 'd' or Ctrl+D
            [0x1b, b'[', b'6', b'~'] | [b' '] | [b'd'] | [0x04] => {
                scroll_offset = (scroll_offset + viewport_height.saturating_sub(2)).min(max_scroll);
            }
            // PageUp or 'b' or 'u' or Ctrl+U
            [0x1b, b'[', b'5', b'~'] | [b'b'] | [b'u'] | [0x15] => {
                scroll_offset = scroll_offset.saturating_sub(viewport_height.saturating_sub(2));
            }
            // Home or 'g' or '0' -> top
            [0x1b, b'[', b'H'] | [b'g'] | [b'0'] => {
                scroll_offset = 0;
            }
            // End or 'G' -> bottom
            [0x1b, b'[', b'F'] | [b'G'] => {
                scroll_offset = max_scroll;
            }
            // 'v' -> toggle grouping mode (By Error Style / By File / Detailed Cards)
            [b'v'] | [b'V'] => {
                group_mode = group_mode.next();
                scroll_offset = 0;
            }
            // '/' -> start search filter
            [b'/'] => {
                in_search_input = true;
            }
            // 'c' -> clear search filter
            [b'c'] | [b'C'] => {
                search_query.clear();
                scroll_offset = 0;
            }
            // '1'..'9' quick filter tab jump
            [ch @ b'1'..=b'9'] => {
                let idx = (ch - b'1') as usize;
                if idx < tabs.len() {
                    active_tab_idx = idx;
                    scroll_offset = 0;
                }
            }
            _ => {}
        }
    }

    true
}

fn handle_tui_search_key(
    key_bytes: &[u8],
    search_query: &mut String,
    in_search_input: &mut bool,
    scroll_offset: &mut usize,
) {
    if key_bytes == [0x1b] {
        search_query.clear();
        *in_search_input = false;
        *scroll_offset = 0;
        return;
    }
    if matches!(key_bytes, [b'\r' | b'\n']) {
        *in_search_input = false;
        return;
    }
    if matches!(key_bytes, [0x7f | 0x08]) {
        search_query.pop();
        *scroll_offset = 0;
        return;
    }
    let Ok(s) = std::str::from_utf8(key_bytes) else {
        return;
    };
    for ch in s.chars().filter(|c| !c.is_control()) {
        search_query.push(ch);
        *scroll_offset = 0;
    }
}
