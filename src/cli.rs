//! Clap command-line argument definitions and subcommand runners (`check`, `design`, `fix`,
//! `plan`, `score`, `report`, `search`, `scan`, `rules`, `why`, `ci`, `install`).

mod args;

use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

pub use self::args::{
    CheckArgs, CiArgs, Cli, Commands, FixArgs, InstallArgs, PlanArgs, ReportArgs, RulesArgs,
    ScanArgs, SearchArgs, WhyArgs,
};
use self::args::{
    CiSubcommand, OutputFormat, RulesEnableArgs, RulesExplainArgs, RulesListArgs, RulesSubcommand,
    SearchFormat, build_scan_options, resolve_check_gate_params, resolve_check_handoff_and_paths,
};
use crate::{
    BuildRuntimeScanReportInput, CiOptions, CiProviderKind, CliOverrides, ConfigMutation,
    DiffScope, HandoffTarget, InstallOptions, PrCommentRepoContext, PrescriptionTier,
    RUNTIME_SCAN_LOCAL_DEV_PORTS, RecordRuntimeTraceInput, RuleCategory, RuleId, RuleSeverity,
    RuleSeverityOverride, RuleTag, RulesListOptions, RuntimeScanFormat, ScanOptions, SearchOptions,
    SymbolKind, apply_autofixes, build_rule_catalog, build_runtime_scan_report, ci_config,
    ci_install, ci_upgrade, detect_local_runtime_urls, execute_handoff, explain_location,
    explain_rule, format_design_report, format_design_report_pretty, format_fix_report,
    format_install_report, format_plan_report, format_rule_catalog_text,
    format_rule_explanation_text, format_runtime_scan_error_report, format_runtime_scan_report,
    format_search_json, format_search_text, format_terminal_report, format_terminal_report_pretty,
    format_why_report_text, generate_ci_comment, install_dotore, load_config_from_dir,
    mutate_config_in_dir, plan_project, progress::LiveSpinner, prompt_runtime_scan_url_with_io,
    record_runtime_trace, render_github_pr_comment_from_env, render_html_report,
    resolve_dotore_home_dir, resolve_runtime_scan_format, resolve_scan_exit_code, scan_design,
    scan_workspace_with_overrides, search_symbols_with_cache, should_highlight_stdout,
    tui::{run_interactive_tui, should_launch_tui},
    write_and_open_html_report, write_diagnostics_bundle, write_github_pr_comment,
    write_json_report,
};

/// Dispatches a parsed [`Cli`] invocation to its corresponding subcommand runner and returns the process [`ExitCode`].
#[must_use]
pub fn run_cli(cli: Cli) -> ExitCode {
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


fn emit_check_output(
    args: &CheckArgs,
    report: &crate::JsonReport,
    resolved_handoff: Option<HandoffTarget>,
) -> Result<(), String> {
    if let Some(out_path) = &args.json_out {
        write_json_report(report, out_path)
            .map_err(|err| format!("writing JSON report to {}: {err}", out_path.display()))?;
    }

    let is_json = args.json || args.format == Some(OutputFormat::Json);
    if let Some(target) = resolved_handoff {
        let bundle_dir = resolve_dotore_home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("handoff-bundle");
        let output = execute_handoff(report, target, &bundle_dir)
            .map_err(|err| format!("executing handoff: {err}"))?;
        print!("{output}");
    } else if args.score {
        println!("{}", report.summary.health_score);
    } else if is_json {
        let json = serde_json::to_string_pretty(report)
            .map_err(|err| format!("serializing JSON: {err}"))?;
        println!("{json}");
    } else if args.format == Some(OutputFormat::GithubPrComment) {
        print!("{}", render_github_pr_comment_from_env(report));
    } else if args.format == Some(OutputFormat::Html) {
        print!("{}", render_html_report(report));
    } else if args.format != Some(OutputFormat::Text) && should_launch_tui(args.no_pager) {
        let color = should_highlight_stdout(false);
        if !run_interactive_tui(report, false) {
            print!("{}", format_terminal_report_pretty(report, color));
        }
    } else if io::stdout().is_terminal() {
        let color = should_highlight_stdout(false);
        print!("{}", format_terminal_report_pretty(report, color));
    } else {
        print!("{}", format_terminal_report(report));
    }
    Ok(())
}

/// Runs `dotore check` (or `dotore score` when `args.score` is `true`).
#[must_use]
fn run_check(args: &CheckArgs) -> ExitCode {
    let (scope, blocking, warning_exit_code) = match resolve_check_gate_params(args) {
        Ok(params) => params,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    let (resolved_handoff, effective_paths) = match resolve_check_handoff_and_paths(args) {
        Ok(pair) => pair,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    let options = match build_scan_options(
        &effective_paths,
        args.include_tests,
        &args.rules,
        &args.categories,
        &args.only,
        &args.tiers,
    ) {
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
        no_cache: args.no_cache,
        projects: args.projects.clone(),
    };

    let show_live_spinner = !args.score
        && !args.json
        && args.format.is_none()
        && resolved_handoff.is_none()
        && should_launch_tui(args.no_pager);
    let spinner_guard = show_live_spinner.then(LiveSpinner::start).flatten();
    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            drop(spinner_guard);
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };
    drop(spinner_guard);

    if let Err(err) = emit_check_output(args, &report, resolved_handoff) {
        eprintln!("error {err}");
        return ExitCode::from(2);
    }

    let code = resolve_scan_exit_code(&report.diagnostics, blocking, warning_exit_code);
    ExitCode::from(code)
}

struct SubcommandScanRequest<'a> {
    paths: &'a [PathBuf],
    include_tests: bool,
    tiers: Option<Vec<PrescriptionTier>>,
    no_inline_disables: bool,
    custom_rules_only: bool,
    ignore_tags: &'a [String],
    config_path: Option<&'a PathBuf>,
    no_cache: bool,
    projects: &'a [String],
}

fn scan_workspace_for_subcommand(
    req: &SubcommandScanRequest<'_>,
) -> Result<
    (
        crate::JsonReport,
        std::collections::HashMap<PathBuf, String>,
    ),
    ExitCode,
> {
    let options = ScanOptions {
        paths: req.paths.to_vec(),
        include_tests: req.include_tests,
        rules: None,
        tiers: req.tiers.clone(),
    };
    let overrides = CliOverrides {
        no_inline_disables: req.no_inline_disables,
        custom_rules_only: req.custom_rules_only,
        ignore_tags: req.ignore_tags.to_vec(),
        config_path: req.config_path.cloned(),
        no_cache: req.no_cache,
        projects: req.projects.to_vec(),
        ..Default::default()
    };
    scan_workspace_with_overrides(&options, &overrides).map_err(|err| {
        eprintln!("error scanning workspace: {err}");
        ExitCode::from(2)
    })
}

/// Runs `dotore fix`.
#[must_use]
fn run_fix(args: &FixArgs) -> ExitCode {
    let (report, sources) = match scan_workspace_for_subcommand(&SubcommandScanRequest {
        paths: &args.paths,
        include_tests: args.include_tests,
        tiers: Some(vec![PrescriptionTier::Autofix]),
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: &args.ignore_tags,
        config_path: args.config.as_ref(),
        no_cache: args.no_cache,
        projects: &args.projects,
    }) {
        Ok(res) => res,
        Err(code) => return code,
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

/// Runs `dotore plan`.
#[must_use]
fn run_plan(args: &PlanArgs) -> ExitCode {
    let (report, _) = match scan_workspace_for_subcommand(&SubcommandScanRequest {
        paths: &args.paths,
        include_tests: args.include_tests,
        tiers: None,
        no_inline_disables: args.no_inline_disables,
        custom_rules_only: args.custom_rules_only,
        ignore_tags: &args.ignore_tags,
        config_path: args.config.as_ref(),
        no_cache: args.no_cache,
        projects: &args.projects,
    }) {
        Ok(res) => res,
        Err(code) => return code,
    };

    let plan_result = match plan_project(&report, &args.out) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("error writing remediation plans: {err}");
            return ExitCode::from(2);
        }
    };

    if args.handoff || args.bundle_dir.is_some() {
        let target_bundle_dir = args.bundle_dir.as_deref().unwrap_or(&args.out);
        match write_diagnostics_bundle(&report, target_bundle_dir) {
            Ok(bundle) => {
                print!("{}", bundle.prompt_markdown);
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("error writing diagnostics bundle: {err}");
                return ExitCode::from(2);
            }
        }
    }

    print!("{}", format_plan_report(&plan_result));
    ExitCode::SUCCESS
}

fn emit_pr_comment_report(output: Option<&Path>, report: &crate::JsonReport) -> ExitCode {
    let ctx = PrCommentRepoContext::from_env();
    if let Some(out_path) = output {
        match write_github_pr_comment(report, out_path, &ctx) {
            Ok(md) => {
                print!("{md}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error writing PR comment: {err}");
                ExitCode::from(2)
            }
        }
    } else {
        print!("{}", render_github_pr_comment_from_env(report));
        ExitCode::SUCCESS
    }
}

fn emit_json_report_output(output: Option<&Path>, report: &crate::JsonReport) -> ExitCode {
    if let Some(out_path) = output {
        if let Err(err) = write_json_report(report, out_path) {
            eprintln!("error writing JSON report: {err}");
            return ExitCode::from(2);
        }
    } else {
        match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing JSON: {err}");
                return ExitCode::from(2);
            }
        }
    }
    ExitCode::SUCCESS
}

/// Runs `dotore report`.
#[must_use]
fn run_report(args: &ReportArgs) -> ExitCode {
    let options = match build_scan_options(
        &args.paths,
        args.include_tests,
        &args.rules,
        &args.categories,
        &args.only,
        &args.tiers,
    ) {
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
        scope: DiffScope::Full,
        base_ref: None,
        staged: false,
        baseline_path: None,
        no_cache: args.no_cache,
        projects: args.projects.clone(),
    };
    let spinner_guard = should_launch_tui(false).then(LiveSpinner::start).flatten();
    let (report, _) = match scan_workspace_with_overrides(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            drop(spinner_guard);
            eprintln!("error scanning workspace: {err}");
            return ExitCode::from(2);
        }
    };
    drop(spinner_guard);

    match args.format {
        Some(OutputFormat::GithubPrComment) => {
            emit_pr_comment_report(args.output.as_deref(), &report)
        }
        Some(OutputFormat::Json) => emit_json_report_output(args.output.as_deref(), &report),
        Some(OutputFormat::Text) => {
            let text = format_terminal_report(&report);
            if let Some(out_path) = &args.output
                && let Err(err) = std::fs::write(out_path, &text)
            {
                eprintln!("error writing text report: {err}");
                return ExitCode::from(2);
            }
            print!("{text}");
            ExitCode::SUCCESS
        }
        Some(OutputFormat::Html) | None => {
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

/// Runs `dotore search`.
#[must_use]
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

    let (results, sources) = match search_symbols_with_cache(&args.query, &options, args.no_cache) {
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

/// Runs `dotore scan`.
#[must_use]
fn run_scan(args: &ScanArgs) -> ExitCode {
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

fn run_rules_list(list_args: &RulesListArgs) -> ExitCode {
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

fn run_rules_explain(explain_args: &RulesExplainArgs) -> ExitCode {
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

fn run_rules_enable(enable_args: &RulesEnableArgs) -> ExitCode {
    let Some(rule) = parse_rule_or_print_error(&enable_args.rule) else {
        return ExitCode::from(1);
    };
    let severity = if let Some(raw_sev) = &enable_args.severity {
        let Some(parsed) = parse_severity_or_print_error(raw_sev) else {
            return ExitCode::from(1);
        };
        if parsed == RuleSeverityOverride::Off {
            eprintln!("`enable` cannot set a rule to off. Use `dotore rules disable` instead.");
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

fn parse_rule_or_print_error(raw_rule: &str) -> Option<RuleId> {
    let parsed = RuleId::parse(raw_rule);
    if parsed.is_none() {
        eprintln!("Unknown rule {raw_rule:?}. Run `dotore rules list` to see every available rule.");
    }
    parsed
}

fn parse_severity_or_print_error(raw_sev: &str) -> Option<RuleSeverityOverride> {
    let parsed = RuleSeverityOverride::parse(raw_sev);
    if parsed.is_none() {
        eprintln!("Invalid severity {raw_sev:?}. Expected one of: off, warn, error.");
    }
    parsed
}

/// Runs `dotore rules`.
#[must_use]
fn run_rules(args: &RulesArgs) -> ExitCode {
    match &args.command {
        RulesSubcommand::List(list_args) => run_rules_list(list_args),
        RulesSubcommand::Explain(explain_args) => run_rules_explain(explain_args),
        RulesSubcommand::Enable(enable_args) => run_rules_enable(enable_args),
        RulesSubcommand::Disable(disable_args) => {
            let Some(rule) = parse_rule_or_print_error(&disable_args.rule) else {
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
            let Some(rule) = parse_rule_or_print_error(&set_args.rule) else {
                return ExitCode::from(1);
            };
            let Some(severity) = parse_severity_or_print_error(&set_args.severity) else {
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
            let Some(severity) = parse_severity_or_print_error(&cat_args.severity) else {
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

/// Runs `dotore why <file:line>`.
#[must_use]
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

/// Runs `dotore design`.
#[must_use]
fn run_design(args: &CheckArgs) -> ExitCode {
    let options = match build_scan_options(
        &args.paths,
        args.include_tests,
        &args.rules,
        &args.categories,
        &args.only,
        &args.tiers,
    ) {
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
        projects: args.projects.clone(),
        ..Default::default()
    };
    let is_json = args.json || args.format == Some(OutputFormat::Json);
    let is_pr_comment = args.format == Some(OutputFormat::GithubPrComment);
    let show_live_spinner = !is_json && !is_pr_comment && should_launch_tui(args.no_pager);
    let spinner_guard = show_live_spinner.then(LiveSpinner::start).flatten();
    let (report, _) = match scan_design(&options, &overrides) {
        Ok(res) => res,
        Err(err) => {
            drop(spinner_guard);
            eprintln!("error running design audit: {err}");
            return ExitCode::from(2);
        }
    };
    drop(spinner_guard);
    if is_json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("error serializing design JSON: {err}");
                return ExitCode::from(2);
            }
        }
    } else if is_pr_comment {
        print!("{}", render_github_pr_comment_from_env(&report));
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

/// Runs `dotore ci`.
#[must_use]
fn run_ci(args: &CiArgs) -> ExitCode {
    if let Some(CiSubcommand::Comment(comment_args)) = &args.command {
        return match generate_ci_comment(&comment_args.report, comment_args.output.as_deref()) {
            Ok(markdown) => {
                print!("{markdown}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        };
    }

    let (sub_name, act_args) = match &args.command {
        Some(CiSubcommand::Install(a)) => ("install", a),
        Some(CiSubcommand::Upgrade(a)) => ("upgrade", a),
        Some(CiSubcommand::Config(a)) => ("config", a),
        Some(CiSubcommand::Comment(_)) => unreachable!(),
        None => ("install", &args.action_args),
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
    let res = match &args.command {
        Some(CiSubcommand::Install(_)) | None => ci_install(&ci_opts),
        Some(CiSubcommand::Upgrade(_)) => ci_upgrade(&ci_opts),
        Some(CiSubcommand::Config(_)) => ci_config(&ci_opts),
        Some(CiSubcommand::Comment(_)) => unreachable!(),
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

/// Runs `dotore install`.
#[must_use]
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
