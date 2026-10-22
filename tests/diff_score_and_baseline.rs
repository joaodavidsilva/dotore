//! Integration tests for Ticket #05:
//! - Git diff scopes (`--scope full|changed|contextual|lines`, `--base <ref>`, `--staged`)
//! - **Contextual Owner** policies (`Line`, `JsxElement`, `Subject`, `RelatedNodes`, `File`)
//! - `--baseline <report.json>` multiset fingerprint comparison and graceful degradation
//! - Deterministic local `0..=100` Health Score, labels, and `--score` CLI flag
//! - Exit-code controls (`--blocking error|warning|none`, `--warning-exit-code <2..=255>`)
//! - Versioned `JsonReport` (`--json`, `--json-out <path>`)
#![expect(
    clippy::expect_used,
    reason = "Integration tests assert on expected Ok/Some values"
)]

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use dotore::{
    BaselineDiagnosticEntry, BlastRadius, BlastRadiusTier, BlockingLevel, ChangedFileLineRanges,
    CliOverrides, ContextualOwnerPolicy, DiffScope, JSON_REPORT_SCHEMA_VERSION, PrescriptionTier,
    RenderFrequency, RootCauseGroup, RuleCategory, RuleId, RuleSeverity, ScanMode, ScanOptions,
    SourceLoc, analyze_source, compare_baseline_diagnostics, compute_local_health_score,
    diagnostic_intersects_changed_lines, parse_baseline_report_str, parse_changed_line_ranges,
    parse_file_ir, resolve_scan_exit_code, scan_workspace_with_overrides, score_label,
    validate_git_revision, validate_warning_exit_code,
};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(1);

fn create_temp_dir(prefix: &str) -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dotore-ticket05-{prefix}-{}-{id}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn init_git_repo(dir: &Path) {
    run_git_cmd(dir, &["init"]);
    run_git_cmd(dir, &["config", "user.email", "test@dotore.dev"]);
    run_git_cmd(dir, &["config", "user.name", "Dotore Test"]);
}

fn run_git_cmd(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn dummy_group(
    id: &str,
    tier: BlastRadiusTier,
    severity: RuleSeverity,
    score: u32,
) -> RootCauseGroup {
    RootCauseGroup {
        id: id.to_string(),
        rule: RuleId::NoDerivedState,
        category: RuleCategory::Performance,
        severity,
        tier: PrescriptionTier::Surgical,
        file: PathBuf::from("src/App.tsx"),
        subject_name: Some("App".to_string()),
        target_name: "state".to_string(),
        loc: SourceLoc { line: 1, column: 1 },
        message: "Test finding".to_string(),
        blast_radius: BlastRadius {
            score,
            tier,
            render_frequency: RenderFrequency::Standard,
            fan_out: 1,
            cascade_depth: 1,
            site_count: 1,
            file_count: 1,
        },
        diagnostic_indices: vec![0],
    }
}

#[test]
fn local_health_score_computes_deterministic_score_and_labels_from_groups_blast_radius_and_density()
{
    // 1. Zero findings -> 100 ("Excellent")
    let clean = compute_local_health_score(&[], 5, 10);
    assert_eq!(clean.score, 100);
    assert_eq!(clean.label, "Excellent");
    assert_eq!(clean.p0_groups, 0);

    // 2. Rating label boundaries
    assert_eq!(score_label(100), "Excellent");
    assert_eq!(score_label(90), "Excellent");
    assert_eq!(score_label(89), "Good");
    assert_eq!(score_label(75), "Good");
    assert_eq!(score_label(74), "Needs Attention");
    assert_eq!(score_label(50), "Needs Attention");
    assert_eq!(score_label(49), "Critical");
    assert_eq!(score_label(0), "Critical");

    // 3. Blast Radius tier ordering: P0 penalizes more than P1 > P2 > P3
    let p3_score = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P3,
            RuleSeverity::Warning,
            5,
        )],
        2,
        2,
    );
    let p2_score = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P2,
            RuleSeverity::Warning,
            15,
        )],
        2,
        2,
    );
    let p1_score = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P1,
            RuleSeverity::Warning,
            30,
        )],
        2,
        2,
    );
    let p0_score = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P0,
            RuleSeverity::Warning,
            60,
        )],
        2,
        2,
    );

    assert!(p3_score.score > p2_score.score);
    assert!(p2_score.score > p1_score.score);
    assert!(p1_score.score > p0_score.score);
    assert_eq!(p0_score.p0_groups, 1);

    // 4. Error severity penalizes more than Warning of the same tier
    let p1_err = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P1,
            RuleSeverity::Error,
            30,
        )],
        2,
        2,
    );
    assert!(p1_err.score < p1_score.score);

    // 5. Density normalization: same finding in a 40-Subject / 20-file repo scores higher than in a 1-Subject / 1-file repo
    let small_repo = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P0,
            RuleSeverity::Error,
            50,
        )],
        1,
        1,
    );
    let large_repo = compute_local_health_score(
        &[dummy_group(
            "g1",
            BlastRadiusTier::P0,
            RuleSeverity::Error,
            50,
        )],
        20,
        40,
    );
    assert!(large_repo.score > small_repo.score);

    // 6. CLI `--score` outputs only the numeric score
    let dir = create_temp_dir("score-cli");
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("Form.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function Form({ firstName, lastName }) {
            const [fullName, setFullName] = useState('');
            useEffect(() => {
                setFullName(firstName + ' ' + lastName);
            }, [firstName, lastName]);
            return <div>{fullName}</div>;
        }
        "#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");
    let out = Command::new(bin)
        .args(["check", "--score", "--blocking", "none"])
        .arg(&dir)
        .output()
        .expect("run dotore --score");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed_score: u32 = stdout
        .trim()
        .parse()
        .expect("stdout must be a single integer");
    assert!((1..100).contains(&parsed_score));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn exit_codes_honor_blocking_level_and_warning_exit_code_validation() {
    // 1. Validation of `--warning-exit-code <2..=255>`
    assert!(validate_warning_exit_code(0).is_err());
    assert!(validate_warning_exit_code(1).is_err());
    assert!(validate_warning_exit_code(256).is_err());
    assert_eq!(validate_warning_exit_code(2), Ok(2));
    assert_eq!(validate_warning_exit_code(42), Ok(42));
    assert_eq!(validate_warning_exit_code(255), Ok(255));

    // 2. Library exit code resolution
    let err_diags = analyze_source(
        Path::new("src/Err.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function ErrComp({ a }) {
            const [b, setB] = useState(0);
            useEffect(() => { setB(a + 1); }, [a]);
            return <div>{b}</div>;
        }
        "#,
        None,
    );
    assert!(err_diags.iter().any(|d| d.severity == RuleSeverity::Error));

    // `no-event-handler` has default severity Warning
    let warn_diags = analyze_source(
        Path::new("src/Warn.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function WarnComp({ submit }) {
            const [submitted, setSubmitted] = useState(false);
            useEffect(() => {
                if (submitted) {
                    submit();
                }
            }, [submitted, submit]);
            return <button onClick={() => setSubmitted(true)}>Send</button>;
        }
        "#,
        None,
    );
    assert!(!warn_diags.is_empty());
    assert!(
        warn_diags
            .iter()
            .all(|d| d.severity == RuleSeverity::Warning)
    );

    // Clean scan
    assert_eq!(
        resolve_scan_exit_code(&[], BlockingLevel::Error, Some(42)),
        0
    );

    // Warnings-only scan
    assert_eq!(
        resolve_scan_exit_code(&warn_diags, BlockingLevel::Error, None),
        0
    );
    assert_eq!(
        resolve_scan_exit_code(&warn_diags, BlockingLevel::Error, Some(42)),
        42
    );
    assert_eq!(
        resolve_scan_exit_code(&warn_diags, BlockingLevel::Warning, Some(42)),
        1
    );
    assert_eq!(
        resolve_scan_exit_code(&warn_diags, BlockingLevel::None, Some(42)),
        0
    );

    // Errors present: blocking Error returns 1 even when warning_exit_code is set
    let mut mixed = err_diags.clone();
    mixed.extend(warn_diags.clone());
    assert_eq!(
        resolve_scan_exit_code(&mixed, BlockingLevel::Error, Some(42)),
        1
    );
    assert_eq!(
        resolve_scan_exit_code(&mixed, BlockingLevel::None, Some(42)),
        0
    );

    // 3. End-to-end CLI binary verification
    let dir = create_temp_dir("exit-codes-cli");
    let warn_file = dir.join("Warn.tsx");
    fs::write(
        &warn_file,
        r#"
        import { useState, useEffect } from 'react';
        export function WarnComp({ submit }) {
            const [submitted, setSubmitted] = useState(false);
            useEffect(() => {
                if (submitted) {
                    submit();
                }
            }, [submitted, submit]);
            return <button onClick={() => setSubmitted(true)}>Send</button>;
        }
        "#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");

    // Default `--blocking error` with `--warning-exit-code 77` returns 77 on warnings-only
    let out_77 = Command::new(bin)
        .args(["check", "--warning-exit-code", "77"])
        .arg(&warn_file)
        .output()
        .unwrap();
    assert_eq!(out_77.status.code(), Some(77));

    // `--blocking warning` returns 1 on warnings
    let out_warn_block = Command::new(bin)
        .args([
            "check",
            "--blocking",
            "warning",
            "--warning-exit-code",
            "77",
        ])
        .arg(&warn_file)
        .output()
        .unwrap();
    assert_eq!(out_warn_block.status.code(), Some(1));

    // `--blocking none` returns 0
    let out_none = Command::new(bin)
        .args(["check", "--blocking", "none", "--warning-exit-code", "77"])
        .arg(&warn_file)
        .output()
        .unwrap();
    assert_eq!(out_none.status.code(), Some(0));

    // Out-of-range `--warning-exit-code 1` is rejected with exit code 2
    let out_bad = Command::new(bin)
        .args(["check", "--warning-exit-code", "1"])
        .arg(&warn_file)
        .output()
        .unwrap();
    assert_eq!(out_bad.status.code(), Some(2));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn json_and_json_out_emit_versioned_report_with_identities_coverage_groups_blast_radius_and_capsules()
 {
    let dir = create_temp_dir("json-out");
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "web-app", "dependencies": { "react": "^19.0.0", "next": "^15.0.0" } }"#,
    )
    .unwrap();
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("Profile.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function Profile({ userId }) {
            const [comment, setComment] = useState('');
            const [draft, setDraft] = useState('');
            useEffect(() => {
                setComment('');
                setDraft('');
            }, [userId]);
            return <div>{comment}{draft}</div>;
        }
        "#,
    )
    .unwrap();

    let json_path = dir.join("artifacts/report.json");
    let bin = env!("CARGO_BIN_EXE_dotore");
    let out = Command::new(bin)
        .args(["check", "--json", "--json-out"])
        .arg(&json_path)
        .args(["--blocking", "none"])
        .arg(&dir)
        .output()
        .expect("run dotore --json --json-out");

    assert_eq!(out.status.code(), Some(0));
    assert!(json_path.is_file());

    let disk_json = fs::read_to_string(&json_path).unwrap();
    let stdout_json = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&disk_json).expect("valid JSON on disk");
    let parsed_stdout: serde_json::Value =
        serde_json::from_str(&stdout_json).expect("valid JSON on stdout");
    assert_eq!(parsed, parsed_stdout);

    assert_eq!(
        parsed["schema_version"].as_u64(),
        Some(u64::from(JSON_REPORT_SCHEMA_VERSION))
    );
    assert_eq!(parsed["mode"].as_str(), Some("full"));
    assert!(parsed["summary"]["score_label"].as_str().is_some());
    assert!(parsed["summary"]["health_score"].as_u64().is_some());

    // Per-project coverage metadata
    let projects = parsed["projects"].as_array().expect("projects array");
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0]["analyzed_file_count"].as_u64(), Some(1));
    assert_eq!(projects[0]["subjects_scanned"].as_u64(), Some(1));
    assert_eq!(projects[0]["complete"].as_bool(), Some(true));

    // Deterministic diagnostic identity & fingerprint
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(diags.len(), 1);
    let diag_id = diags[0]["id"].as_str().expect("diagnostic id");
    assert!(diag_id.contains("::dotore/no-reset-all-state-on-prop-change::"));
    let diag_fp = diags[0]["fingerprint"]
        .as_str()
        .expect("diagnostic fingerprint");
    assert!(diag_fp.starts_with("fp::no-reset-all-state-on-prop-change::"));

    // Root-Cause Groups, Blast Radius, and Fix Capsules
    let groups = parsed["root_cause_groups"]
        .as_array()
        .expect("root_cause_groups");
    assert_eq!(groups.len(), 1);
    assert!(groups[0]["blast_radius"]["score"].as_u64().is_some());
    assert!(groups[0]["blast_radius"]["tier"].as_str().is_some());

    let capsules = parsed["fix_capsules"].as_array().expect("fix_capsules");
    assert_eq!(capsules.len(), 1);
    assert!(capsules[0]["subject_excerpt"]["source"].as_str().is_some());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn baseline_multiset_comparison_handles_renames_formatting_extractions_duplicates_and_degradation()
{
    let dir = create_temp_dir("baseline-multiset");
    init_git_repo(&dir);
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Initial workspace with 2 findings:
    // 1. `no-derived-state` in `src/OldForm.tsx`
    // 2. `no-array-index-as-key` in `src/Dashboard.tsx`
    fs::write(
        src_dir.join("OldForm.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function OldForm({ firstName, lastName }) {
            const [fullName, setFullName] = useState('');
            useEffect(() => {
                setFullName(firstName + ' ' + lastName);
            }, [firstName, lastName]);
            return <div>{fullName}</div>;
        }
        "#,
    )
    .unwrap();
    fs::write(
        src_dir.join("Dashboard.tsx"),
        r#"
        export function Dashboard({ items }) {
            return <ul>{items.map((item, idx) => <li key={idx}>{item}</li>)}</ul>;
        }
        "#,
    )
    .unwrap();
    run_git_cmd(&dir, &["add", "."]);
    run_git_cmd(&dir, &["commit", "-m", "initial baseline"]);

    // Save baseline report to `baseline.json`
    let baseline_json_path = dir.join("baseline.json");
    let bin = env!("CARGO_BIN_EXE_dotore");
    let save_out = Command::new(bin)
        .args(["check", "--json-out"])
        .arg(&baseline_json_path)
        .args(["--blocking", "none"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(save_out.status.code(), Some(0));
    let baseline_entries =
        parse_baseline_report_str(&fs::read_to_string(&baseline_json_path).unwrap()).unwrap();
    assert_eq!(baseline_entries.len(), 2);

    // Now:
    // 1. Rename `src/OldForm.tsx` -> `src/nested/RenamedForm.tsx`, shift line numbers by adding comments,
    //    change single quotes to double quotes, and reformat whitespace across multiple lines.
    // 2. Extract the list from `Dashboard` into a new component `ExtractedList` in `src/ExtractedList.tsx`.
    fs::remove_file(src_dir.join("OldForm.tsx")).unwrap();
    fs::create_dir_all(src_dir.join("nested")).unwrap();
    fs::write(
        src_dir.join("nested/RenamedForm.tsx"),
        r#"
        // Header comment 1
        // Header comment 2
        // Header comment 3
        import { useState, useEffect } from "react";

        export function RenamedForm({ firstName, lastName }) {
            const [fullName, setFullName] = useState("");

            useEffect(() => {
                // formatting comment
                setFullName(
                    firstName +
                    " " +
                    lastName
                );
            }, [firstName, lastName]);

            return <section>{fullName}</section>;
        }
        "#,
    )
    .unwrap();

    fs::write(
        src_dir.join("Dashboard.tsx"),
        r#"
        export function Dashboard() {
            return <div>Clean dashboard shell</div>;
        }
        "#,
    )
    .unwrap();
    fs::write(
        src_dir.join("ExtractedList.tsx"),
        r#"
        // Extracted component in a brand new file at different lines
        export function ExtractedList({ rows }) {
            return (
                <ul>
                    {rows.map((row, idx) => (
                        <li key={idx}>{row}</li>
                    ))}
                </ul>
            );
        }
        "#,
    )
    .unwrap();

    // Run with `--baseline baseline.json` -> 0 net-new diagnostics!
    let (report_after_move, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            baseline_path: Some(baseline_json_path.clone()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(report_after_move.mode, ScanMode::Baseline);
    assert_eq!(report_after_move.diagnostics.len(), 0);
    let base_sum = report_after_move
        .baseline
        .as_ref()
        .expect("baseline summary");
    assert_eq!(base_sum.introduced_count, 0);
    assert_eq!(base_sum.preexisting_count, 2);
    assert_eq!(base_sum.fixed_count, 0);
    assert_eq!(base_sum.baseline_total_count, 2);

    // Now add a second duplicate `no-array-index-as-key` on `<li>` in `ExtractedList.tsx` (k=1 -> m=2)
    fs::write(
        src_dir.join("ExtractedList.tsx"),
        r#"
        export function ExtractedList({ rows, extras }) {
            return (
                <div>
                    <ul>{rows.map((row, idx) => <li key={idx}>{row}</li>)}</ul>
                    <ul>{extras.map((extra, idx) => <li key={idx}>{extra}</li>)}</ul>
                </div>
            );
        }
        "#,
    )
    .unwrap();

    let (report_with_dup, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            baseline_path: Some(baseline_json_path.clone()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(report_with_dup.diagnostics.len(), 1);
    assert_eq!(
        report_with_dup.diagnostics[0].rule,
        RuleId::NoArrayIndexAsKey
    );
    let dup_sum = report_with_dup.baseline.as_ref().unwrap();
    assert_eq!(dup_sum.introduced_count, 1);
    assert_eq!(dup_sum.preexisting_count, 2);
    assert_eq!(dup_sum.fixed_count, 0);

    // Now fix all findings in `ExtractedList.tsx` so 1 baseline finding is fixed (k=2 -> m=1)
    fs::write(
        src_dir.join("ExtractedList.tsx"),
        r#"
        export function ExtractedList({ rows }) {
            return <ul>{rows.map((row) => <li key={row.id}>{row.label}</li>)}</ul>;
        }
        "#,
    )
    .unwrap();

    let (report_after_fix, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            baseline_path: Some(baseline_json_path.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report_after_fix.diagnostics.len(), 0);
    let fix_sum = report_after_fix.baseline.as_ref().unwrap();
    assert_eq!(fix_sum.introduced_count, 0);
    assert_eq!(fix_sum.preexisting_count, 1);
    assert_eq!(fix_sum.fixed_count, 1);

    // Graceful degradation to diff mode when baseline file / base git blobs are unavailable
    let (degraded_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            baseline_path: Some(dir.join("missing-baseline-report.json")),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(degraded_report.mode, ScanMode::Diff);
    assert!(degraded_report.baseline_degraded);
    assert!(degraded_report.baseline.is_none());

    // Also test in-memory `compare_baseline_diagnostics` directly
    let direct_delta = compare_baseline_diagnostics(
        &[],
        &HashMap::new(),
        &[BaselineDiagnosticEntry {
            rule: RuleId::NoDerivedState,
            file: PathBuf::from("src/Old.tsx"),
            subject_name: Some("Old".to_string()),
            target_name: "fullName".to_string(),
            message: "Derived state".to_string(),
            fingerprint: None,
            structural_fingerprint: None,
            line: 5,
        }],
        "memory",
    );
    assert_eq!(direct_delta.introduced_diagnostics.len(), 0);
    assert_eq!(direct_delta.summary.fixed_count, 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scope_changed_and_staged_filter_diagnostics_while_preserving_full_project_graph_context() {
    // Also verify git revision validation rejects flag injection
    assert!(validate_git_revision("--upload-pack=evil").is_err());
    assert!(validate_git_revision("HEAD@{1}").is_err());
    assert!(validate_git_revision("main..feature..extra").is_err());
    assert!(validate_git_revision("main").is_ok());
    assert!(validate_git_revision("main..HEAD").is_ok());
    assert!(validate_git_revision("main...HEAD").is_ok());

    let dir = create_temp_dir("scope-changed-staged");
    init_git_repo(&dir);
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // 1. `UnchangedBad.tsx` has a `no-derived-state` diagnostic committed in HEAD
    fs::write(
        src_dir.join("UnchangedBad.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function UnchangedBad({ x }) {
            const [y, setY] = useState(0);
            useEffect(() => {
                setY(x * 2);
            }, [x]);
            return <div>{y}</div>;
        }
        "#,
    )
    .unwrap();

    // 2. `App.tsx` renders `<ProfilePage userId={id} />` WITHOUT a `key` prop, committed in HEAD
    fs::write(
        src_dir.join("App.tsx"),
        r#"
        import { ProfilePage } from './ProfilePage';
        export function App({ id }) {
            return <ProfilePage userId={id} />;
        }
        "#,
    )
    .unwrap();

    // 3. `ProfilePage.tsx` starts clean in HEAD
    fs::write(
        src_dir.join("ProfilePage.tsx"),
        r#"
        export function ProfilePage({ userId }) {
            return <div>{userId}</div>;
        }
        "#,
    )
    .unwrap();

    run_git_cmd(&dir, &["add", "."]);
    run_git_cmd(&dir, &["commit", "-m", "initial commit"]);

    // Modify ONLY `ProfilePage.tsx` to introduce `no-reset-all-state-on-prop-change`
    fs::write(
        src_dir.join("ProfilePage.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function ProfilePage({ userId }) {
            const [comment, setComment] = useState('');
            useEffect(() => {
                setComment('');
            }, [userId]);
            return <div>{userId}{comment}</div>;
        }
        "#,
    )
    .unwrap();

    // Full scan reports both `UnchangedBad.tsx` and `ProfilePage.tsx` (2 findings)
    let (full_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            scope: DiffScope::Full,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(full_report.diagnostics.len(), 2);

    // `--scope changed` (with `--base HEAD`) reports ONLY `ProfilePage.tsx`,
    // while still resolving `App.tsx` as its cross-file Caller Site and upgrading to cross-file Autofix!
    let (changed_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            scope: DiffScope::Changed,
            base_ref: Some("HEAD".to_string()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(changed_report.mode, ScanMode::Diff);
    assert_eq!(changed_report.diagnostics.len(), 1);
    let diag = &changed_report.diagnostics[0];
    assert_eq!(diag.rule, RuleId::NoResetAllStateOnPropChange);
    assert_eq!(diag.caller_sites.len(), 1);
    assert_eq!(diag.caller_sites[0].component_name, "ProfilePage");
    assert_eq!(diag.tier, PrescriptionTier::Autofix);
    assert!(diag.autofix.is_some());

    // Now test `--staged`: before `git add`, staged diff is empty -> 0 diagnostics
    let (unstaged_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            staged: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(unstaged_report.mode, ScanMode::Staged);
    assert_eq!(unstaged_report.diagnostics.len(), 0);

    // Stage `src/ProfilePage.tsx` -> `--staged` reports `ProfilePage.tsx` with full `ProjectGraph` caller site
    run_git_cmd(&dir, &["add", "src/ProfilePage.tsx"]);
    let (staged_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![dir.clone()],
            ..Default::default()
        },
        &CliOverrides {
            staged: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(staged_report.mode, ScanMode::Staged);
    assert_eq!(staged_report.diagnostics.len(), 1);
    assert_eq!(
        staged_report.diagnostics[0].rule,
        RuleId::NoResetAllStateOnPropChange
    );
    assert_eq!(staged_report.diagnostics[0].caller_sites.len(), 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scope_lines_and_scope_contextual_enforce_all_five_contextual_owner_policies() {
    // 1. Unit verification of unified diff parser (`parse_changed_line_ranges`)
    let patch = "\
diff --git a/src/App.tsx b/src/App.tsx
--- a/src/App.tsx
+++ b/src/App.tsx
@@ -3,0 +4,2 @@
+line4
+line5
@@ -10,2 +12,0 @@
-deleted1
-deleted2
";
    let parsed_ranges = parse_changed_line_ranges(patch, true);
    assert_eq!(parsed_ranges.len(), 1);
    assert_eq!(parsed_ranges[0].file, PathBuf::from("src/App.tsx"));
    assert_eq!(parsed_ranges[0].ranges, vec![(4, 5)]);
    assert_eq!(parsed_ranges[0].deletion_lines, vec![12]);

    // 2. Policy 1: `ContextualOwnerPolicy::Line` (`no-direct-mutation-state`)
    let line_src = [
        "import { useState } from 'react';",
        "export function Counter() {",
        "  const [state, setState] = useState({ count: 0 });",
        "  state.count = 1;",
        "  const label = 'hello';",
        "  return <div>{label}</div>;",
        "}",
    ]
    .join("\n");
    let line_path = Path::new("src/Counter.tsx");
    let line_ir = parse_file_ir(line_path, &line_src);
    let line_diags = analyze_source(line_path, &line_src, Some(&[RuleId::NoDirectMutationState]));
    assert_eq!(line_diags.len(), 1);
    assert_eq!(
        line_diags[0].rule.metadata().contextual_owner,
        ContextualOwnerPolicy::Line
    );
    // Edit on line 5 (sibling line in same Subject) does NOT match Line policy even in contextual mode
    assert!(!diagnostic_intersects_changed_lines(
        &line_diags[0],
        Some(&line_ir),
        Some(&line_src),
        &ChangedFileLineRanges {
            file: line_path.to_path_buf(),
            ranges: vec![(5, 5)],
            deletion_lines: vec![],
        },
        true,
    ));
    // Edit on line 4 (exact mutation line) matches both lines and contextual mode
    assert!(diagnostic_intersects_changed_lines(
        &line_diags[0],
        Some(&line_ir),
        Some(&line_src),
        &ChangedFileLineRanges {
            file: line_path.to_path_buf(),
            ranges: vec![(4, 4)],
            deletion_lines: vec![],
        },
        false,
    ));

    // 3. Policy 2: `ContextualOwnerPolicy::JsxElement` (`alt-text`)
    let jsx_src = [
        "export function Gallery() {",
        "  return (",
        "    <section>",
        "      <img",
        "        className=\"hero\"",
        "        src=\"/photo.jpg\"",
        "      />",
        "      <p>Caption</p>",
        "    </section>",
        "  );",
        "}",
    ]
    .join("\n");
    let jsx_path = Path::new("src/Gallery.tsx");
    let jsx_ir = parse_file_ir(jsx_path, &jsx_src);
    let jsx_diags = analyze_source(jsx_path, &jsx_src, Some(&[RuleId::AltText]));
    assert_eq!(jsx_diags.len(), 1);
    assert_eq!(
        jsx_diags[0].rule.metadata().contextual_owner,
        ContextualOwnerPolicy::JsxElement
    );
    // Deletion inside `<img ... />` (line 5) matches JsxElement owner in contextual mode, but not sibling `<p>` (line 8)
    assert!(diagnostic_intersects_changed_lines(
        &jsx_diags[0],
        Some(&jsx_ir),
        Some(&jsx_src),
        &ChangedFileLineRanges {
            file: jsx_path.to_path_buf(),
            ranges: vec![],
            deletion_lines: vec![5],
        },
        true,
    ));
    assert!(!diagnostic_intersects_changed_lines(
        &jsx_diags[0],
        Some(&jsx_ir),
        Some(&jsx_src),
        &ChangedFileLineRanges {
            file: jsx_path.to_path_buf(),
            ranges: vec![(8, 8)],
            deletion_lines: vec![],
        },
        true,
    ));

    // 4. Policy 3: `ContextualOwnerPolicy::Subject` (`no-derived-state`)
    let subj_src = [
        "import { useState, useEffect } from 'react';",
        "export function App({ a }) {",
        "  const [b, setB] = useState(0);",
        "  useEffect(() => {",
        "    setB(a + 1);",
        "  }, [a]);",
        "  const helper = () => {",
        "    return 42;",
        "  };",
        "  return <div>{b}{helper()}</div>;",
        "}",
        "export function Other() {",
        "  return <span />;",
        "}",
    ]
    .join("\n");
    let subj_path = Path::new("src/App.tsx");
    let subj_ir = parse_file_ir(subj_path, &subj_src);
    let subj_diags = analyze_source(subj_path, &subj_src, Some(&[RuleId::NoDerivedState]));
    assert_eq!(subj_diags.len(), 1);
    assert_eq!(
        subj_diags[0].rule.metadata().contextual_owner,
        ContextualOwnerPolicy::Subject
    );
    // Editing line 10 (`return <div>...` in `App`) does NOT match `--scope lines`, DOES match `--scope contextual`
    assert!(!diagnostic_intersects_changed_lines(
        &subj_diags[0],
        Some(&subj_ir),
        Some(&subj_src),
        &ChangedFileLineRanges {
            file: subj_path.to_path_buf(),
            ranges: vec![(10, 10)],
            deletion_lines: vec![],
        },
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        &subj_diags[0],
        Some(&subj_ir),
        Some(&subj_src),
        &ChangedFileLineRanges {
            file: subj_path.to_path_buf(),
            ranges: vec![(10, 10)],
            deletion_lines: vec![],
        },
        true,
    ));
    // Editing line 8 (inside nested non-hook `helper`) or line 13 (inside sibling `Other`) does NOT match
    assert!(!diagnostic_intersects_changed_lines(
        &subj_diags[0],
        Some(&subj_ir),
        Some(&subj_src),
        &ChangedFileLineRanges {
            file: subj_path.to_path_buf(),
            ranges: vec![(8, 8)],
            deletion_lines: vec![],
        },
        true,
    ));
    assert!(!diagnostic_intersects_changed_lines(
        &subj_diags[0],
        Some(&subj_ir),
        Some(&subj_src),
        &ChangedFileLineRanges {
            file: subj_path.to_path_buf(),
            ranges: vec![(13, 13)],
            deletion_lines: vec![],
        },
        true,
    ));

    // 5. Policy 4: `ContextualOwnerPolicy::RelatedNodes` (`exhaustive-deps`)
    let rel_src = [
        "import { useEffect } from 'react';",
        "export const App = ({ value }) => {",
        "  const callback = () => {",
        "    console.log(value);",
        "    console.log('editing here');",
        "  };",
        "  useEffect(callback, []);",
        "  useEffect(() => {",
        "    console.log(value);",
        "  }, []);",
        "  return <div />;",
        "};",
    ]
    .join("\n");
    let rel_path = Path::new("src/Rel.tsx");
    let rel_ir = parse_file_ir(rel_path, &rel_src);
    let rel_diags = analyze_source(rel_path, &rel_src, Some(&[RuleId::ExhaustiveDeps]));
    assert_eq!(rel_diags.len(), 2);
    assert_eq!(
        rel_diags[0].rule.metadata().contextual_owner,
        ContextualOwnerPolicy::RelatedNodes
    );
    // Edit on line 5 (inside `callback`):
    // - `--scope lines` matches neither finding (they are on lines 7 and 10)
    // - `--scope contextual` matches ONLY `rel_diags[0]` (`useEffect(callback, [])` at line 7)
    //   and does NOT match `rel_diags[1]` (`useEffect(..., [])` at line 10)!
    let line_5_change = ChangedFileLineRanges {
        file: rel_path.to_path_buf(),
        ranges: vec![(5, 5)],
        deletion_lines: vec![],
    };
    assert!(!diagnostic_intersects_changed_lines(
        &rel_diags[0],
        Some(&rel_ir),
        Some(&rel_src),
        &line_5_change,
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        &rel_diags[0],
        Some(&rel_ir),
        Some(&rel_src),
        &line_5_change,
        true,
    ));
    assert!(!diagnostic_intersects_changed_lines(
        &rel_diags[1],
        Some(&rel_ir),
        Some(&rel_src),
        &line_5_change,
        true,
    ));

    // 6. Policy 5: `ContextualOwnerPolicy::File` (`only-export-components`)
    let file_src = [
        "export const formatLabel = (s: string) => s.trim();",
        "export function Button() {",
        "  return <button>Click</button>;",
        "}",
    ]
    .join("\n");
    let file_path = Path::new("src/Button.tsx");
    let file_ir = parse_file_ir(file_path, &file_src);
    let file_diags = analyze_source(file_path, &file_src, Some(&[RuleId::OnlyExportComponents]));
    assert_eq!(file_diags.len(), 1);
    assert_eq!(
        file_diags[0].rule.metadata().contextual_owner,
        ContextualOwnerPolicy::File
    );
    // Edit on line 3 (inside `Button`, far from line 1 `MAGIC_NUMBER`) does NOT match `--scope lines`,
    // DOES match `--scope contextual`!
    let line_3_change = ChangedFileLineRanges {
        file: file_path.to_path_buf(),
        ranges: vec![(3, 3)],
        deletion_lines: vec![],
    };
    assert!(!diagnostic_intersects_changed_lines(
        &file_diags[0],
        Some(&file_ir),
        Some(&file_src),
        &line_3_change,
        false,
    ));
    assert!(diagnostic_intersects_changed_lines(
        &file_diags[0],
        Some(&file_ir),
        Some(&file_src),
        &line_3_change,
        true,
    ));

    // 7. End-to-end git repository test comparing `--scope lines` vs `--scope contextual` via CLI
    let dir = create_temp_dir("scope-lines-vs-contextual");
    init_git_repo(&dir);
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let app_file = src_dir.join("App.tsx");
    fs::write(
        &app_file,
        [
            "import { useState, useEffect } from 'react';",
            "export function App({ firstName, lastName }) {",
            "  const [fullName, setFullName] = useState('');",
            "  useEffect(() => {",
            "    setFullName(firstName + ' ' + lastName);",
            "  }, [firstName, lastName]);",
            "  return <div>Before: {fullName}</div>;",
            "}",
            "export function Untouched({ a }) {",
            "  const [b, setB] = useState(0);",
            "  useEffect(() => {",
            "    setB(a + 1);",
            "  }, [a]);",
            "  return <span>{b}</span>;",
            "}",
            "",
        ]
        .join("\n"),
    )
    .unwrap();
    run_git_cmd(&dir, &["add", "."]);
    run_git_cmd(&dir, &["commit", "-m", "initial"]);

    // Modify ONLY line 7 (`return <div>After: {fullName}</div>;`) inside `App`
    fs::write(
        &app_file,
        [
            "import { useState, useEffect } from 'react';",
            "export function App({ firstName, lastName }) {",
            "  const [fullName, setFullName] = useState('');",
            "  useEffect(() => {",
            "    setFullName(firstName + ' ' + lastName);",
            "  }, [firstName, lastName]);",
            "  return <div>After: {fullName}</div>;",
            "}",
            "export function Untouched({ a }) {",
            "  const [b, setB] = useState(0);",
            "  useEffect(() => {",
            "    setB(a + 1);",
            "  }, [a]);",
            "  return <span>{b}</span>;",
            "}",
            "",
        ]
        .join("\n"),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");

    // `--scope lines` -> 0 findings (line 5 was not modified)
    let lines_out = Command::new(bin)
        .args(["check", "--scope", "lines", "--json", "--blocking", "none"])
        .arg(&dir)
        .output()
        .unwrap();
    let lines_json: serde_json::Value = serde_json::from_slice(&lines_out.stdout).unwrap();
    assert_eq!(lines_json["diagnostics"].as_array().unwrap().len(), 0);

    // `--scope contextual` -> 1 finding (`App` on line 5 is surfaced because line 7 in `App` changed; `Untouched` is excluded!)
    let ctx_out = Command::new(bin)
        .args([
            "check",
            "--scope",
            "contextual",
            "--json",
            "--blocking",
            "none",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    let ctx_json: serde_json::Value = serde_json::from_slice(&ctx_out.stdout).unwrap();
    let ctx_diags = ctx_json["diagnostics"].as_array().unwrap();
    assert_eq!(ctx_diags.len(), 1);
    assert_eq!(ctx_diags[0]["subject_name"].as_str(), Some("App"));

    let _ = fs::remove_dir_all(&dir);
}
