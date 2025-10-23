//! CLI entrypoint for `dotore`.

use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use dotore::{
    CliOverrides, PrescriptionTier, RuleId, ScanOptions, apply_autofixes, format_fix_report,
    format_terminal_report, scan_workspace_with_overrides, write_and_open_html_report,
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
    /// Generate a self-contained visual HTML report with Render Cascade diagrams.
    Report(ReportArgs),
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Check(args)) => run_check(&args),
        Some(Commands::Fix(args)) => run_fix(&args),
        Some(Commands::Report(args)) => run_report(&args),
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
