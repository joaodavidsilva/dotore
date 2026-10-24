//! Integration tests for CLI `--handoff` and interactive TUI `y`/`a` coding agent handoff.

use std::{
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    HandoffTarget, RuleId, analyze_project_sources, copy_to_clipboard,
    detect_available_coding_agents, execute_handoff, filter_report_for_diagnostics,
    load_preferred_handoff_target, save_preferred_handoff_target,
};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dotore-{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(unix)]
#[expect(clippy::expect_used, reason = "test fixture script helper")]
fn write_executable_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::write(path, body).expect("write script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set executable permissions");
}

#[test]
fn handoff_target_detection_preferences_clipboard_and_execution_work_end_to_end() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = unique_temp_dir("handoff-core-seam");
    let home_dir = temp_dir.join("dotore-home");
    let bin_dir = temp_dir.join("bin");
    let bundle_dir = temp_dir.join("bundle");
    let clip_out = temp_dir.join("clipboard.txt");
    let agent_out = temp_dir.join("agent-arg.txt");
    let agent_bundle_env = temp_dir.join("agent-bundle-env.txt");
    fs::create_dir_all(&home_dir).expect("create home dir");
    fs::create_dir_all(&bin_dir).expect("create bin dir");

    // 1. HandoffTarget parsing and metadata
    assert_eq!(HandoffTarget::parse("print"), Some(HandoffTarget::Print));
    assert_eq!(
        HandoffTarget::parse("clipboard"),
        Some(HandoffTarget::Clipboard)
    );
    assert_eq!(HandoffTarget::parse("claude"), Some(HandoffTarget::Claude));
    assert_eq!(HandoffTarget::parse("codex"), Some(HandoffTarget::Codex));
    assert_eq!(HandoffTarget::parse("cursor"), Some(HandoffTarget::Cursor));
    assert_eq!(HandoffTarget::parse("amp"), Some(HandoffTarget::Amp));
    assert_eq!(
        HandoffTarget::parse("opencode"),
        Some(HandoffTarget::Opencode)
    );
    assert_eq!(HandoffTarget::parse("unknown"), None);
    assert_eq!(HandoffTarget::Print.binary_name(), None);
    assert_eq!(HandoffTarget::Clipboard.binary_name(), None);
    assert_eq!(HandoffTarget::Claude.binary_name(), Some("claude"));
    assert_eq!(HandoffTarget::Codex.binary_name(), Some("codex"));
    assert_eq!(HandoffTarget::AGENT_CLIS.len(), 5);

    // 2. Agent binary detection via DOTORE_AGENT_BIN_DIR
    #[cfg(unix)]
    {
        // Non-executable file should be ignored
        fs::write(bin_dir.join("claude"), "#!/bin/sh\necho claude\n").expect("write non-exec");
        write_executable_script(
            &bin_dir.join("codex"),
            &format!(
                "#!/bin/sh\nprintf '%s' \"$1\" > \"{}\"\nprintf '%s' \"$DOTORE_BUNDLE_DIR\" > \"{}\"\necho \"codex received handoff\"\n",
                agent_out.display(),
                agent_bundle_env.display()
            ),
        );
        write_executable_script(&bin_dir.join("amp"), "#!/bin/sh\necho amp\n");
    }

    let clip_script = temp_dir.join("clip.sh");
    #[cfg(unix)]
    write_executable_script(
        &clip_script,
        &format!("#!/bin/sh\ncat > \"{}\"\n", clip_out.display()),
    );

    // Set isolated env vars for this test
    // SAFETY: serialized via ENV_MUTEX in this integration test binary.
    unsafe {
        std::env::set_var("DOTORE_HOME", &home_dir);
        std::env::set_var("DOTORE_AGENT_BIN_DIR", &bin_dir);
        std::env::set_var("DOTORE_CLIPBOARD_CMD", &clip_script);
    }

    let detected = detect_available_coding_agents();
    assert_eq!(detected, vec![HandoffTarget::Codex, HandoffTarget::Amp]);

    // 3. Preferences persistence
    assert_eq!(load_preferred_handoff_target(), None);
    save_preferred_handoff_target(HandoffTarget::Codex).expect("save preferred target");
    assert_eq!(load_preferred_handoff_target(), Some(HandoffTarget::Codex));
    assert!(home_dir.join("preferences.json").is_file());

    // 4. Clipboard helper
    copy_to_clipboard("hello clipboard payload").expect("copy to clipboard");
    assert_eq!(
        fs::read_to_string(&clip_out).expect("read clipboard file"),
        "hello clipboard payload"
    );

    // 5. Build a report with two rules and test filter_report_for_diagnostics
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/Form.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function Form({ a, b }: { a: number; b: number }) {
                    const [sum, setSum] = useState(0);
                    useEffect(() => {
                        setSum(a + b);
                    }, [a, b]);
                    return <div>{sum}</div>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/Editor.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function Editor({ userId }: { userId: string }) {
                    const [draft, setDraft] = useState('');
                    const [saved, setSaved] = useState(false);
                    useEffect(() => {
                        setDraft('');
                    }, [userId]);
                    return <div>{draft}{String(saved)}</div>;
                }
                "#
                .to_string(),
            ),
        ],
        None,
    );
    assert!(report.diagnostics.len() >= 2);
    let derived_only: Vec<&dotore::Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::NoDerivedState)
        .collect();
    assert_eq!(derived_only.len(), 1);
    let filtered_report = filter_report_for_diagnostics(&report, &derived_only);
    assert_eq!(filtered_report.diagnostics.len(), 1);
    assert_eq!(filtered_report.summary.total_diagnostics, 1);
    assert_eq!(filtered_report.root_cause_groups.len(), 1);
    assert_eq!(
        filtered_report.root_cause_groups[0].rule,
        RuleId::NoDerivedState
    );

    // 6. execute_handoff for Print, Clipboard, and Codex
    let printed =
        execute_handoff(&filtered_report, HandoffTarget::Print, &bundle_dir).expect("print");
    assert!(printed.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(printed.contains("no-derived-state"));
    assert!(!printed.contains("no-adjust-state-on-prop-change"));
    assert!(bundle_dir.join("diagnostics.json").is_file());
    assert_eq!(load_preferred_handoff_target(), Some(HandoffTarget::Print));

    let clip_msg = execute_handoff(&filtered_report, HandoffTarget::Clipboard, &bundle_dir)
        .expect("clipboard");
    assert!(clip_msg.contains("clipboard"));
    let clip_contents = fs::read_to_string(&clip_out).expect("read clip_out");
    assert!(clip_contents.contains("# Dotore Coding Agent Remediation Handoff"));
    assert_eq!(
        load_preferred_handoff_target(),
        Some(HandoffTarget::Clipboard)
    );

    let agent_res =
        execute_handoff(&filtered_report, HandoffTarget::Codex, &bundle_dir).expect("codex");
    assert!(agent_res.contains("codex received handoff"));
    let received_prompt = fs::read_to_string(&agent_out).expect("read agent_out");
    assert!(received_prompt.contains("# Dotore Coding Agent Remediation Handoff"));
    assert_eq!(
        fs::read_to_string(&agent_bundle_env).expect("read agent_bundle_env"),
        bundle_dir.display().to_string()
    );
    assert_eq!(load_preferred_handoff_target(), Some(HandoffTarget::Codex));

    unsafe {
        std::env::remove_var("DOTORE_HOME");
        std::env::remove_var("DOTORE_AGENT_BIN_DIR");
        std::env::remove_var("DOTORE_CLIPBOARD_CMD");
    }
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn cli_check_handoff_supports_print_clipboard_agents_and_remembers_preferred_target() {
    use std::process::Command;

    let temp_dir = unique_temp_dir("cli-check-handoff");
    let src_dir = temp_dir.join("src");
    let home_dir = temp_dir.join("dotore-home");
    let bin_dir = temp_dir.join("bin");
    let empty_bin_dir = temp_dir.join("empty-bin");
    let clip_out = temp_dir.join("clip-out.txt");
    let agent_log = temp_dir.join("agent-invocations.log");
    fs::create_dir_all(&src_dir).expect("create src");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&bin_dir).expect("create bin");
    fs::create_dir_all(&empty_bin_dir).expect("create empty bin");

    fs::write(
        src_dir.join("Widget.tsx"),
        r#"import { useState, useEffect } from 'react';
export function Widget({ x, y }: { x: number; y: number }) {
    const [total, setTotal] = useState(0);
    useEffect(() => {
        setTotal(x + y);
    }, [x, y]);
    return <span>{total}</span>;
}
"#,
    )
    .expect("write Widget.tsx");

    let clip_script = temp_dir.join("clip.sh");
    #[cfg(unix)]
    {
        write_executable_script(
            &clip_script,
            &format!("#!/bin/sh\ncat > \"{}\"\n", clip_out.display()),
        );
        for agent in ["claude", "codex", "cursor", "amp", "opencode"] {
            write_executable_script(
                &bin_dir.join(agent),
                &format!(
                    "#!/bin/sh\necho \"{agent}:$(printf '%s' \"$1\" | head -n 1)\" >> \"{}\"\necho \"agent-{agent}-ok\"\n",
                    agent_log.display()
                ),
            );
        }
    }

    let bin = env!("CARGO_BIN_EXE_dotore");

    // 1. `--handoff print` prints prompt to stdout and saves preference
    let out_print = Command::new(bin)
        .args([
            "check",
            src_dir.to_str().expect("path"),
            "--handoff",
            "print",
            "--no-fail",
        ])
        .env("DOTORE_HOME", &home_dir)
        .env("DOTORE_AGENT_BIN_DIR", &bin_dir)
        .env("DOTORE_CLIPBOARD_CMD", &clip_script)
        .output()
        .expect("run check --handoff print");
    assert!(
        out_print.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_print.stderr)
    );
    let stdout_print = String::from_utf8_lossy(&out_print.stdout);
    assert!(stdout_print.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(stdout_print.contains("no-derived-state"));

    // 2. `--handoff clipboard` copies prompt via DOTORE_CLIPBOARD_CMD
    let out_clip = Command::new(bin)
        .args([
            "check",
            src_dir.to_str().expect("path"),
            "--handoff",
            "clipboard",
            "--no-fail",
        ])
        .env("DOTORE_HOME", &home_dir)
        .env("DOTORE_AGENT_BIN_DIR", &bin_dir)
        .env("DOTORE_CLIPBOARD_CMD", &clip_script)
        .output()
        .expect("run check --handoff clipboard");
    assert!(
        out_clip.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_clip.stderr)
    );
    let clip_text = fs::read_to_string(&clip_out).expect("read clip_out");
    assert!(clip_text.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(clip_text.contains("Widget.tsx"));

    // 3. `--handoff cursor` launches cursor CLI and saves preference
    let out_cursor = Command::new(bin)
        .args([
            "check",
            src_dir.to_str().expect("path"),
            "--handoff",
            "cursor",
            "--no-fail",
        ])
        .env("DOTORE_HOME", &home_dir)
        .env("DOTORE_AGENT_BIN_DIR", &bin_dir)
        .env("DOTORE_CLIPBOARD_CMD", &clip_script)
        .output()
        .expect("run check --handoff cursor");
    assert!(
        out_cursor.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_cursor.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cursor.stdout).contains("agent-cursor-ok"));

    // 4. Bare `--handoff` (both before and after path) remembers the saved preferred target (`cursor`)
    let out_auto = Command::new(bin)
        .args([
            "check",
            "--handoff",
            src_dir.to_str().expect("path"),
            "--no-fail",
        ])
        .env("DOTORE_HOME", &home_dir)
        .env("DOTORE_AGENT_BIN_DIR", &bin_dir)
        .env("DOTORE_CLIPBOARD_CMD", &clip_script)
        .output()
        .expect("run check --handoff <path>");
    assert!(
        out_auto.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_auto.stderr)
    );
    assert!(String::from_utf8_lossy(&out_auto.stdout).contains("agent-cursor-ok"));
    let log_lines = fs::read_to_string(&agent_log).expect("read agent_log");
    assert_eq!(log_lines.lines().count(), 2);
    assert!(
        log_lines
            .lines()
            .all(|l| l.starts_with("cursor:# Dotore Coding Agent Remediation Handoff"))
    );

    // 5. Unknown `--handoff` target exits with code 2
    let out_bad = Command::new(bin)
        .args([
            "check",
            src_dir.to_str().expect("path"),
            "--handoff",
            "not-an-agent",
        ])
        .env("DOTORE_HOME", &home_dir)
        .env("DOTORE_AGENT_BIN_DIR", &bin_dir)
        .output()
        .expect("run check --handoff not-an-agent");
    assert_eq!(out_bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out_bad.stderr).contains("Unknown --handoff target"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn tui_y_and_a_keys_copy_filtered_handoff_prompt_and_launch_coding_agent() {
    use dotore::{
        TuiGroupMode, TuiState, build_filter_tabs, diagnostic_matches_tab_and_search,
        render_tui_body_lines, render_tui_frame_with_state, strip_ansi_codes,
    };

    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = unique_temp_dir("tui-handoff-keys");
    let home_dir = temp_dir.join("dotore-home");
    let bin_dir = temp_dir.join("bin");
    let empty_bin_dir = temp_dir.join("empty-bin");
    let clip_out = temp_dir.join("tui-clipboard.txt");
    let agent_out = temp_dir.join("tui-agent-prompt.txt");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&bin_dir).expect("create bin");
    fs::create_dir_all(&empty_bin_dir).expect("create empty bin");

    let clip_script = temp_dir.join("clip.sh");
    #[cfg(unix)]
    {
        write_executable_script(
            &clip_script,
            &format!("#!/bin/sh\ncat > \"{}\"\n", clip_out.display()),
        );
        write_executable_script(
            &bin_dir.join("claude"),
            &format!(
                "#!/bin/sh\nprintf '%s' \"$1\" > \"{}\"\necho \"claude done\"\n",
                agent_out.display()
            ),
        );
    }

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/Form.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function Form({ first, last }: { first: string; last: string }) {
                    const [full, setFull] = useState('');
                    useEffect(() => {
                        setFull(first + ' ' + last);
                    }, [first, last]);
                    return <div>{full}</div>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/Editor.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function Editor({ userId }: { userId: string }) {
                    const [draft, setDraft] = useState('');
                    const [saved, setSaved] = useState(false);
                    useEffect(() => {
                        setDraft('');
                    }, [userId]);
                    return <div>{draft}{String(saved)}</div>;
                }
                "#
                .to_string(),
            ),
        ],
        None,
    );
    let tabs = build_filter_tabs(&report);
    let mut state = TuiState::from_report(&report, &tabs);

    // Filter to Form.tsx using search query so only 1 finding (`no-derived-state`) is active
    state.search_query = "Form.tsx".to_string();

    unsafe {
        std::env::set_var("DOTORE_HOME", &home_dir);
        std::env::set_var("DOTORE_CLIPBOARD_CMD", &clip_script);
        std::env::set_var("DOTORE_AGENT_BIN_DIR", &empty_bin_dir);
    }

    // 1. Pressing `y` copies the active filter's handoff prompt (1 finding) to clipboard and sets status message
    assert!(!state.handle_key(b"y", 20, 10));
    let status_after_y = state
        .status_message
        .clone()
        .expect("status message after y");
    assert!(
        status_after_y.contains("Copied handoff prompt (1 findings) to clipboard")
            || status_after_y.contains("Copied handoff prompt (1 finding) to clipboard"),
        "unexpected status after y: {status_after_y}"
    );
    let copied = fs::read_to_string(&clip_out).expect("read tui-clipboard.txt");
    assert!(copied.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(copied.contains("src/Form.tsx"));
    assert!(!copied.contains("src/Editor.tsx"));

    let filtered: Vec<&dotore::Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| {
            diagnostic_matches_tab_and_search(d, &tabs[state.active_tab_idx], &state.search_query)
        })
        .collect();
    let body_lines = render_tui_body_lines(&filtered, TuiGroupMode::ByRuleStyle);
    let frame = render_tui_frame_with_state(&report, &tabs, &state, &body_lines, 28, 120, false);
    let plain_frame = strip_ansi_codes(&frame);
    assert!(plain_frame.contains("Copied handoff prompt"));
    assert!(plain_frame.contains("[y] Copy Handoff"));
    assert!(plain_frame.contains("[a] Launch Agent"));

    // 2. Pressing `a` when no coding agent is detected sets a status bar prompt
    assert!(!state.handle_key(b"a", 20, 10));
    let status_no_agent = state
        .status_message
        .clone()
        .expect("status message after a (none)");
    assert!(
        status_no_agent.contains("No coding agent CLI detected"),
        "unexpected status when no agent: {status_no_agent}"
    );

    // 3. Pressing `a` when `claude` is detected in DOTORE_AGENT_BIN_DIR launches `claude` with the filtered prompt
    unsafe {
        std::env::set_var("DOTORE_AGENT_BIN_DIR", &bin_dir);
    }
    assert!(!state.handle_key(b"a", 20, 10));
    let status_agent_ok = state
        .status_message
        .clone()
        .expect("status message after a (claude)");
    assert!(
        status_agent_ok.contains("Handed off 1 finding") && status_agent_ok.contains("claude"),
        "unexpected status after agent launch: {status_agent_ok}"
    );
    let agent_received = fs::read_to_string(&agent_out).expect("read tui-agent-prompt.txt");
    assert!(agent_received.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(agent_received.contains("src/Form.tsx"));
    assert!(!agent_received.contains("src/Editor.tsx"));

    // 4. When multiple coding agents (`claude` and `cursor`) are available and no preference is stored,
    // pressing `a` includes the available agent choices in `status_message`.
    let _ = fs::remove_file(home_dir.join("preferences.json"));
    #[cfg(unix)]
    write_executable_script(&bin_dir.join("cursor"), "#!/bin/sh\necho cursor\n");
    assert!(!state.handle_key(b"a", 20, 10));
    let status_multi = state
        .status_message
        .clone()
        .expect("status message with multiple agents");
    assert!(
        status_multi.contains("available: claude, cursor")
            && status_multi.contains("--handoff <agent>"),
        "unexpected multi-agent status: {status_multi}"
    );
    unsafe {
        std::env::remove_var("DOTORE_HOME");
        std::env::remove_var("DOTORE_CLIPBOARD_CMD");
        std::env::remove_var("DOTORE_AGENT_BIN_DIR");
    }
    let _ = fs::remove_dir_all(&temp_dir);
}
