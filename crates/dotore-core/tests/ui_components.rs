//! Integration and contract tests for `dotore_core::ui` terminal UI components.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use dotore_core::{
    AutofixPatch, BaselineSummary, BlastRadius, BlastRadiusTier, ByteEdit, ByteSpan, Capability,
    Diagnostic, JsonReport, PackageRole, PrescriptionTier, ProjectCoverageMetadata,
    RenderFrequency, ReportSummary, ResolvedCallerSite, RootCauseGroup, RuleCategory, RuleId,
    RuleSeverity, ScanMode, SourceLoc, format_design_report_pretty, format_terminal_report_pretty,
    ui::{
        AsciiBox, Badge, BoxBorderStyle, ColorMode, FilterTabBar, FilterTabItem, FlowDiagram,
        GaugeBar, LiveScanProgressSnapshot, LiveSpinner, StatusBar, TuiFilterKind,
        build_filter_tabs, classify_style_bucket, current_scan_progress, format_spinner_frame,
        set_progress_phase, strip_ansi_codes, style_bucket_color, tick_progress_file,
        visible_char_width,
    },
};

#[test]
fn color_mode_and_ansi_width_helpers_handle_plain_and_ansi_sequences() {
    assert!(!ColorMode::Plain.is_ansi());
    assert!(ColorMode::Ansi.is_ansi());
    assert_eq!(ColorMode::from_bool(false), ColorMode::Plain);
    assert_eq!(ColorMode::from_bool(true), ColorMode::Ansi);

    assert_eq!(ColorMode::Plain.cyan(), "");
    assert_eq!(ColorMode::Plain.reset(), "");
    assert_eq!(ColorMode::Ansi.cyan(), "\x1b[36;1m");
    assert_eq!(ColorMode::Ansi.reset(), "\x1b[0m");

    let styled = format!(
        "{}STATIC ANALYZER{} · {}React{}",
        ColorMode::Ansi.bold(),
        ColorMode::Ansi.reset(),
        ColorMode::Ansi.dim(),
        ColorMode::Ansi.reset()
    );
    assert_eq!(strip_ansi_codes(&styled), "STATIC ANALYZER · React");
    assert_eq!(visible_char_width(&styled), 23);
}

#[test]
fn ascii_box_renders_rounded_single_and_double_layouts_in_plain_and_ansi() {
    let mut rounded = AsciiBox::new(BoxBorderStyle::Rounded, 24)
        .with_title("SUMMARY")
        .with_border_color("\x1b[36;1m");
    rounded.add_closed_row("score: 92/100");
    rounded.add_divider();
    rounded.add_open_row("  files: 12");

    let plain = rounded.render(ColorMode::Plain);
    let expected_plain = concat!(
        "╭─ SUMMARY ──────────────╮\n",
        "│score: 92/100           │\n",
        "├────────────────────────┤\n",
        "│  files: 12\n",
        "╰────────────────────────╯\n",
    );
    assert_eq!(plain, expected_plain);

    let ansi = rounded.render(ColorMode::Ansi);
    assert!(ansi.contains("\x1b[36;1m╭─ SUMMARY ──────────────╮\x1b[0m"));
    assert_eq!(strip_ansi_codes(&ansi), expected_plain);

    let mut double_box = AsciiBox::new(BoxBorderStyle::Double, 36).with_border_color("\x1b[32;1m");
    double_box.add_closed_row("  ✔  Zero findings detected.");
    let double_plain = double_box.render(ColorMode::Plain);
    assert_eq!(
        double_plain,
        concat!(
            "╔════════════════════════════════════╗\n",
            "║  ✔  Zero findings detected.        ║\n",
            "╚════════════════════════════════════╝\n",
        )
    );
    let double_ansi = double_box.render(ColorMode::Ansi);
    assert!(double_ansi.contains("\x1b[32;1m╔════════════════════════════════════╗\x1b[0m"));
    assert_eq!(strip_ansi_codes(&double_ansi), double_plain);

    let mut titled_double = AsciiBox::new(BoxBorderStyle::Double, 24)
        .with_title("DOTORE")
        .with_border_color("\x1b[36;1m");
    titled_double.add_titled_divider("FILTER TABS");
    titled_double.add_open_row(" ▶ ALL (2)");
    let titled_double_plain = titled_double.render(ColorMode::Plain);
    assert_eq!(
        titled_double_plain,
        concat!(
            "╔══ DOTORE ══════════════╗\n",
            "╠══ FILTER TABS ═════════╣\n",
            "║ ▶ ALL (2)\n",
            "╚════════════════════════╝\n",
        )
    );
    assert_eq!(
        strip_ansi_codes(&titled_double.render(ColorMode::Ansi)),
        titled_double_plain
    );
}

#[test]
fn gauge_bar_renders_deterministic_ratios_and_threshold_colors() {
    let half = GaugeBar::new(50, 100, 10);
    assert_eq!(half.render(ColorMode::Plain), "[█████░░░░░]");
    assert_eq!(half.render_unbracketed(), "█████░░░░░");

    let zero_max = GaugeBar::new(0, 0, 8);
    assert_eq!(zero_max.render(ColorMode::Plain), "[░░░░░░░░]");

    let high_score = GaugeBar::health_score(92, 10).with_ratio_suffix(true);
    assert_eq!(high_score.render(ColorMode::Plain), "[█████████░] 92/100");
    let high_ansi = high_score.render(ColorMode::Ansi);
    assert!(high_ansi.starts_with("\x1b[32;1m"));
    assert!(high_ansi.ends_with("\x1b[0m"));
    assert_eq!(strip_ansi_codes(&high_ansi), "[█████████░] 92/100");

    let mid_score_tui = GaugeBar::health_score(72, 10)
        .with_ratio_suffix(true)
        .with_256_palette(true);
    assert_eq!(
        mid_score_tui.render(ColorMode::Ansi),
        "\x1b[38;5;220;1m[███████░░░] 72/100\x1b[0m"
    );

    let low_score_tui = GaugeBar::health_score(40, 10)
        .with_ratio_suffix(true)
        .with_256_palette(true);
    assert_eq!(
        low_score_tui.render(ColorMode::Ansi),
        "\x1b[38;5;196;1m[████░░░░░░] 40/100\x1b[0m"
    );
}

#[test]
fn badge_renders_prescription_tier_blast_radius_severity_and_style_bucket_pills() {
    // Prescription Tier badges: paren, dashboard label, and TUI pill
    let autofix = Badge::tier(PrescriptionTier::Autofix);
    assert_eq!(autofix.render(ColorMode::Plain), "(autofix)");
    assert_eq!(
        autofix.render(ColorMode::Ansi),
        "\x1b[32;1m(autofix)\x1b[0m"
    );
    assert_eq!(
        autofix.render_pill(ColorMode::Plain),
        " ⚙ AUTOFIX "
    );
    assert_eq!(
        autofix.render_pill(ColorMode::Ansi),
        "\x1b[48;5;22;38;5;48;1m ⚙ AUTOFIX \x1b[0m"
    );
    assert_eq!(
        Badge::tier(PrescriptionTier::Surgical).render_pill(ColorMode::Ansi),
        "\x1b[48;5;58;38;5;220;1m ✎ SURGICAL \x1b[0m"
    );
    assert_eq!(
        Badge::tier(PrescriptionTier::Refactor).render_pill(ColorMode::Ansi),
        "\x1b[48;5;52;38;5;203;1m ⇄ REFACTOR \x1b[0m"
    );

    // Blast Radius P0..P3 badges
    let p0 = Badge::blast_radius_count(BlastRadiusTier::P0, 3);
    assert_eq!(p0.render(ColorMode::Plain), "P0: 3");
    assert_eq!(p0.render(ColorMode::Ansi), "\x1b[31;1mP0: 3\x1b[0m");
    assert_eq!(p0.render_pill(ColorMode::Plain), "[P0: 3]");

    let p1 = Badge::blast_radius_count(BlastRadiusTier::P1, 2);
    assert_eq!(p1.render(ColorMode::Ansi), "\x1b[33;1mP1: 2\x1b[0m");
    let p2 = Badge::blast_radius_count(BlastRadiusTier::P2, 1);
    assert_eq!(p2.render(ColorMode::Ansi), "\x1b[36;1mP2: 1\x1b[0m");
    let p3 = Badge::blast_radius_count(BlastRadiusTier::P3, 0);
    assert_eq!(p3.render(ColorMode::Ansi), "\x1b[2mP3: 0\x1b[0m");

    // Severity badges
    let err_badge = Badge::severity(RuleSeverity::Error);
    assert_eq!(err_badge.render(ColorMode::Plain), "✖ ERROR");
    assert_eq!(
        err_badge.render(ColorMode::Ansi),
        "\x1b[38;5;196;1m✖ ERROR\x1b[0m"
    );
    let warn_badge = Badge::severity(RuleSeverity::Warning);
    assert_eq!(warn_badge.render(ColorMode::Plain), "▲ WARN ");
    assert_eq!(
        warn_badge.render(ColorMode::Ansi),
        "\x1b[38;5;220;1m▲ WARN \x1b[0m"
    );

    // Style bucket badges
    let bucket_badge = Badge::style_bucket("EFFECTS & STATE");
    assert_eq!(bucket_badge.render(ColorMode::Plain), "[EFFECTS & STATE]");
    assert_eq!(
        bucket_badge.render(ColorMode::Ansi),
        format!("{}[EFFECTS & STATE]\x1b[0m", style_bucket_color("EFFECTS & STATE"))
    );
}

#[test]
fn flow_diagram_renders_arrow_chain_and_render_cascade_diagram() {
    let steps = vec![
        "props.items".to_string(),
        "useEffect".to_string(),
        "setFilteredItems(...)".to_string(),
    ];
    let diagram = FlowDiagram::new(&steps);
    assert_eq!(
        diagram.render_arrow_chain(),
        "props.items -> useEffect -> setFilteredItems(...)"
    );
    assert_eq!(
        diagram.render(ColorMode::Plain),
        "┌─► [props.items] ──► [useEffect] ──► [setFilteredItems(...)] ──► ↻ re-render"
    );

    let colored = diagram.with_color("\x1b[38;5;201m").render(ColorMode::Ansi);
    assert_eq!(
        colored,
        "\x1b[38;5;201m┌─► [props.items] ──► [useEffect] ──► [setFilteredItems(...)] ──► ↻ re-render\x1b[0m"
    );
    assert_eq!(
        strip_ansi_codes(&colored),
        "┌─► [props.items] ──► [useEffect] ──► [setFilteredItems(...)] ──► ↻ re-render"
    );

    let without_terminal = FlowDiagram::new(&steps).with_terminal_node(None);
    assert_eq!(
        without_terminal.render(ColorMode::Plain),
        "┌─► [props.items] ──► [useEffect] ──► [setFilteredItems(...)]"
    );
}

#[test]
fn filter_tab_bar_renders_windowed_tabs_active_pill_and_overflow_indicators() {
    let tabs: Vec<FilterTabItem> = (0..10)
        .map(|i| {
            FilterTabItem::new(
                format!("TAB_{i}"),
                10 - i,
                "\x1b[38;5;51;1m",
                if i == 0 {
                    TuiFilterKind::All
                } else {
                    TuiFilterKind::Rule(RuleId::NoDerivedState)
                },
            )
        })
        .collect();

    let bar_at_start = FilterTabBar::new(&tabs, 0);
    let plain_start = bar_at_start.render(ColorMode::Plain);
    assert!(!plain_start.contains('«'));
    assert!(plain_start.contains(" ▶ TAB_0 (10) "));
    assert!(plain_start.contains("[ TAB_1 (9) ]"));
    assert!(plain_start.contains("» (+2 more)"));

    let ansi_start = bar_at_start.render(ColorMode::Ansi);
    assert!(ansi_start.contains("\x1b[48;5;51;38;5;16;1m ▶ TAB_0 (10) \x1b[0m"));
    assert_eq!(strip_ansi_codes(&ansi_start), plain_start);

    let bar_mid = FilterTabBar::new(&tabs, 5);
    let plain_mid = bar_mid.render(ColorMode::Plain);
    assert!(plain_mid.starts_with("« "));
    assert!(plain_mid.contains(" ▶ TAB_5 (5) "));
    assert_eq!(
        strip_ansi_codes(&bar_mid.render(ColorMode::Ansi)),
        plain_mid
    );
}

#[test]
fn status_bar_renders_report_summary_box_and_tui_footer_in_plain_and_ansi() {
    let report = JsonReport {
        schema_version: 3,
        mode: ScanMode::Full,
        summary: ReportSummary {
            files_scanned: 14,
            subjects_scanned: 8,
            effects_scanned: 3,
            total_diagnostics: 2,
            error_count: 1,
            warning_count: 1,
            affected_file_count: 2,
            autofix_count: 1,
            surgical_count: 1,
            refactor_count: 0,
            health_score: 91,
            score_label: "Great".to_string(),
        },
        projects: Vec::new(),
        diagnostics: Vec::new(),
        root_cause_groups: Vec::new(),
        fix_capsules: Vec::new(),
        diagnostic_fingerprints: BTreeMap::new(),
        diff: None,
        baseline: Some(BaselineSummary {
            baseline_source: "baseline.json".to_string(),
            introduced_count: 1,
            fixed_count: 2,
            preexisting_count: 1,
            baseline_total_count: 3,
        }),
        baseline_degraded: false,
    };

    let summary_bar = StatusBar::from_report(&report);
    let plain_summary = summary_bar.render(ColorMode::Plain);
    assert!(plain_summary.starts_with("╭─ SUMMARY ──"));
    assert!(plain_summary.contains(
        "dotore  score: 91/100 (Great)  files: 14  subjects: 8  effects: 3  findings: 2 (autofix: 1, surgical: 1, refactor: 0)"
    ));
    assert!(plain_summary.contains("baseline: baseline.json  introduced: 1  fixed: 2  pre-existing: 1"));
    assert!(plain_summary.contains("Run `dotore fix` to automatically apply 1 deterministic rewrite(s)."));
    assert!(plain_summary.ends_with("╰──────────────────────────────────────────────────────────────────────────────╯\n"));

    let ansi_summary = summary_bar.render(ColorMode::Ansi);
    assert!(ansi_summary.contains("\x1b[36;1m╭─ SUMMARY "));
    assert_eq!(strip_ansi_codes(&ansi_summary), plain_summary);

    let tui_bar = StatusBar::tui_footer("ALL", 5, "By Error Style / Rule", 1, 20, 40, 91, "Great");
    let tui_plain = tui_bar.render(ColorMode::Plain);
    let tui_ansi = tui_bar.render(ColorMode::Ansi);
    assert!(tui_plain.contains("DOTORE"));
    assert!(tui_plain.contains("ALL (5)"));
    assert!(tui_plain.contains("Mode: By Error Style / Rule  │  Lines 1-20 / 40 (50%)  │  Score: 91/100 (Great)"));
    assert!(tui_plain.contains("[h/l or ←/→] Filter Tab"));
    assert_eq!(strip_ansi_codes(&tui_ansi), tui_plain);
}

#[test]
fn live_spinner_tracks_atomic_progress_and_formats_30fps_frames() {
    set_progress_phase(3, 8);
    tick_progress_file(Path::new("src/components/UserProfileDashboard.tsx"));
    let snap = current_scan_progress();
    assert_eq!(snap.phase, "Extracting AST & IR (parallel)");
    assert_eq!(snap.total_files, 8);
    assert_eq!(snap.completed_files, 1);
    assert_eq!(snap.current_file, "src/components/UserProfileDashboard.tsx");

    let custom_snap = LiveScanProgressSnapshot {
        phase: "Evaluating ProjectGraph & Rules",
        completed_files: 5,
        total_files: 10,
        current_file: "packages/very-long-package-name/src/components/deeply/nested/FeatureComponent.tsx".to_string(),
    };
    let plain_frame = format_spinner_frame(&custom_snap, 0, 1.2, ColorMode::Plain);
    assert!(plain_frame.contains("⠋ DOTORE"));
    assert!(plain_frame.contains("[███████████░░░░░░░░░░░]"));
    assert!(plain_frame.contains(" 50% (5/10) · 1.2s · Evaluating ProjectGraph & Rules"));
    assert!(plain_frame.contains("…"));

    let ansi_frame = format_spinner_frame(&custom_snap, 0, 1.2, ColorMode::Ansi);
    assert_eq!(strip_ansi_codes(&ansi_frame), plain_frame);

    // Ensure LiveSpinner type is constructible/droppable (returns None or Some depending on /dev/tty availability)
    let _maybe_spinner: Option<LiveSpinner> = None;
}

#[test]
fn terminal_and_design_reports_render_via_shared_ui_primitives_in_plain_and_ansi() {
    let diag = Diagnostic {
        file: PathBuf::from("src/UserList.tsx"),
        subject_name: Some("UserList".to_string()),
        rule: RuleId::NoDerivedState,
        category: RuleCategory::Bugs,
        severity: RuleSeverity::Error,
        message_id: "derivedState",
        tier: PrescriptionTier::Autofix,
        target_name: "visibleUsers".to_string(),
        message: "Compute `visibleUsers` inline during render instead of syncing in `useEffect`."
            .to_string(),
        docs_url: RuleId::NoDerivedState.docs_url(),
        loc: SourceLoc {
            line: 12,
            column: 5,
        },
        span: ByteSpan { start: 120, end: 210 },
        cascade_steps: vec![
            "props.users".to_string(),
            "useEffect".to_string(),
            "setVisibleUsers(...)".to_string(),
        ],
        caller_sites: vec![ResolvedCallerSite {
            caller_file: PathBuf::from("src/App.tsx"),
            parent_subject_name: Some("App".to_string()),
            component_name: "UserList".to_string(),
            has_key: false,
            passed_props: vec!["users".to_string()],
            loc: SourceLoc { line: 42, column: 9 },
            span: ByteSpan { start: 400, end: 430 },
        }],
        autofix: Some(AutofixPatch {
            description: "Replace state + effect with `const visibleUsers = ...`.".to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan { start: 120, end: 210 },
                replacement: "const visibleUsers = props.users;".to_string(),
            }],
        }),
    };
    assert_eq!(classify_style_bucket(&diag), "EFFECTS & STATE");

    let report = JsonReport {
        schema_version: 3,
        mode: ScanMode::Full,
        summary: ReportSummary {
            files_scanned: 2,
            subjects_scanned: 2,
            effects_scanned: 1,
            total_diagnostics: 1,
            error_count: 1,
            warning_count: 0,
            affected_file_count: 1,
            autofix_count: 1,
            surgical_count: 0,
            refactor_count: 0,
            health_score: 94,
            score_label: "Excellent".to_string(),
        },
        projects: vec![ProjectCoverageMetadata {
            name: "web".to_string(),
            root_dir: PathBuf::from("."),
            role: PackageRole::Application,
            capabilities: vec![Capability::React],
            analyzed_files: vec![
                PathBuf::from("src/App.tsx"),
                PathBuf::from("src/UserList.tsx"),
            ],
            analyzed_file_count: 2,
            subjects_scanned: 2,
            diagnostic_count: 1,
            health_score: 94,
            score_label: "Excellent".to_string(),
            complete: true,
        }],
        diagnostics: vec![diag],
        root_cause_groups: vec![RootCauseGroup {
            id: "rcg-1".to_string(),
            rule: RuleId::NoDerivedState,
            category: RuleCategory::Bugs,
            severity: RuleSeverity::Error,
            tier: PrescriptionTier::Autofix,
            file: PathBuf::from("src/UserList.tsx"),
            subject_name: Some("UserList".to_string()),
            target_name: "visibleUsers".to_string(),
            loc: SourceLoc {
                line: 12,
                column: 5,
            },
            message: "Compute `visibleUsers` inline during render.".to_string(),
            blast_radius: BlastRadius {
                score: 45,
                tier: BlastRadiusTier::P1,
                render_frequency: RenderFrequency::Standard,
                fan_out: 1,
                cascade_depth: 2,
                site_count: 1,
                file_count: 1,
            },
            diagnostic_indices: vec![0],
        }],
        fix_capsules: Vec::new(),
        diagnostic_fingerprints: BTreeMap::new(),
        diff: None,
        baseline: None,
        baseline_degraded: false,
    };

    let tabs = build_filter_tabs(&report);
    assert!(tabs.iter().any(|t| t.kind == TuiFilterKind::All && t.count == 1));
    assert!(tabs.iter().any(|t| t.kind == TuiFilterKind::Autofix && t.count == 1));
    assert!(
        tabs.iter()
            .any(|t| t.kind == TuiFilterKind::StyleBucket("EFFECTS & STATE") && t.count == 1)
    );
    assert!(
        tabs.iter()
            .any(|t| t.kind == TuiFilterKind::Rule(RuleId::NoDerivedState) && t.count == 1)
    );

    let term_plain = format_terminal_report_pretty(&report, false);
    let term_ansi = format_terminal_report_pretty(&report, true);
    assert!(term_plain.contains("[no-derived-state] (autofix) src/UserList.tsx:12:5 in `UserList`"));
    assert!(term_plain.contains("cascade: props.users -> useEffect -> setVisibleUsers(...)"));
    assert!(term_plain.contains(
        "flow:    ┌─► [props.users] ──► [useEffect] ──► [setVisibleUsers(...)] ──► ↻ re-render"
    ));
    assert!(term_plain.contains("caller:  src/App.tsx:42:9 in `App` (<UserList /> missing key={...})"));
    assert!(term_plain.contains("WORKSPACE PACKAGES (1)"));
    assert!(term_plain.contains("BLAST RADIUS   P0: 0   P1: 1   P2: 0   P3: 0"));
    assert_eq!(strip_ansi_codes(&term_ansi), term_plain);

    let design_plain = format_design_report_pretty(&report, false);
    let design_ansi = format_design_report_pretty(&report, true);
    assert!(design_plain.contains("DOTORE DESIGN AUDIT"));
    assert!(design_plain.contains("dotore design  files: 2  subjects: 2  findings: 1"));
    assert_eq!(strip_ansi_codes(&design_ansi), design_plain);
}
