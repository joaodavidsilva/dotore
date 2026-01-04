//! CLI entrypoint for `dotore`.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use dotore::{
    BuildRuntimeScanReportInput, CiOptions, CiProviderKind, CliOverrides, ConfigMutation,
    InstallOptions, PrescriptionTier, RUNTIME_SCAN_LOCAL_DEV_PORTS, RecordRuntimeTraceInput,
    RuleCategory, RuleId, RuleSeverity, RuleSeverityOverride, RuleTag, RulesListOptions,
    RuntimeScanFormat, ScanOptions, SearchOptions, SymbolKind, apply_autofixes, build_rule_catalog,
    build_runtime_scan_report, ci_config, ci_install, ci_upgrade, detect_local_runtime_urls,
    explain_location, explain_rule, format_design_report, format_fix_report, format_install_report,
    format_plan_report, format_rule_catalog_text, format_rule_explanation_text,
    format_runtime_scan_error_report, format_runtime_scan_report, format_search_json,
    format_search_text, format_terminal_report, format_why_report_text, install_dotore,
    load_config_from_dir, mutate_config_in_dir, plan_project, prompt_runtime_scan_url_with_io,
    record_runtime_trace, resolve_runtime_scan_format, scan_design, scan_workspace_with_overrides,
    search_symbols, should_highlight_stdout, write_and_open_html_report,
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

    /// Exit with code 0 even when diagnostics are found.
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
    };

    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing JSON: {err}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", format_terminal_report(&report));
    }

    if !args.no_fail && report.summary.total_diagnostics > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
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
    };
    let (report, _) = match scan_design(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("error running design audit: {err}");
            return ExitCode::from(2);
        }
    };
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing design JSON: {err}");
                return ExitCode::from(2);
            }
        }
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
