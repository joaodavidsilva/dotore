//! Integration tests for Ticket #41: Interactive TUI Workspace Package Picker & Switcher (`p`).

use std::path::PathBuf;

use dotore::{
    Capability, Diagnostic, JsonReport, PackageRole, PrescriptionTier, ProjectCoverageMetadata,
    ReportSummary, RootCauseGroup, RuleCategory, RuleId, RuleSeverity, ScanMode, SourceLoc,
    TuiGroupMode, TuiPackageItem, TuiState, build_filter_tabs, diagnostic_matches_tab_and_search,
    highlight_fuzzy_matches, render_package_picker_lines, render_tui_body_lines,
    render_tui_frame_with_state, strip_ansi_codes,
};
use dotore_core::{
    ir::ByteSpan,
    rules::{BlastRadius, BlastRadiusTier, RenderFrequency},
};

fn make_diagnostic(
    file: &str,
    subject: &str,
    rule: RuleId,
    severity: RuleSeverity,
    tier: PrescriptionTier,
    line: u32,
) -> Diagnostic {
    Diagnostic {
        file: PathBuf::from(file),
        subject_name: Some(subject.to_string()),
        rule,
        category: RuleCategory::Bugs,
        severity,
        tier,
        target_name: "state".to_string(),
        message: format!("Finding in {file} ({subject})"),
        message_id: "",
        docs_url: rule.metadata().docs_url,
        loc: SourceLoc { line, column: 5 },
        span: ByteSpan { start: 10, end: 30 },
        cascade_steps: vec!["render()".to_string(), "useEffect()".to_string()],
        caller_sites: Vec::new(),
        autofix: None,
    }
}

fn make_monorepo_report() -> JsonReport {
    let d1 = make_diagnostic(
        "apps/web-react/src/App.tsx",
        "App",
        RuleId::NoDerivedState,
        RuleSeverity::Error,
        PrescriptionTier::Autofix,
        12,
    );
    let d2 = make_diagnostic(
        "apps/web-react/src/Feed.tsx",
        "Feed",
        RuleId::NoFetchInEffect,
        RuleSeverity::Warning,
        PrescriptionTier::Refactor,
        24,
    );
    let d3 = make_diagnostic(
        "services/api/src/handler.ts",
        "handle_request",
        RuleId::NoResetAllStateOnPropChange,
        RuleSeverity::Error,
        PrescriptionTier::Surgical,
        18,
    );

    let g1 = RootCauseGroup {
        id: "rcg-web-1".to_string(),
        rule: RuleId::NoDerivedState,
        category: RuleCategory::Bugs,
        severity: RuleSeverity::Error,
        tier: PrescriptionTier::Autofix,
        file: PathBuf::from("apps/web-react/src/App.tsx"),
        subject_name: Some("App".to_string()),
        target_name: "state".to_string(),
        loc: SourceLoc {
            line: 12,
            column: 5,
        },
        message: "Finding in apps/web-react/src/App.tsx".to_string(),
        blast_radius: BlastRadius {
            score: 45,
            tier: BlastRadiusTier::P0,
            render_frequency: RenderFrequency::Standard,
            fan_out: 0,
            cascade_depth: 2,
            site_count: 1,
            file_count: 1,
        },
        diagnostic_indices: vec![0],
    };
    let g2 = RootCauseGroup {
        id: "rcg-web-2".to_string(),
        rule: RuleId::NoFetchInEffect,
        category: RuleCategory::Bugs,
        severity: RuleSeverity::Warning,
        tier: PrescriptionTier::Refactor,
        file: PathBuf::from("apps/web-react/src/Feed.tsx"),
        subject_name: Some("Feed".to_string()),
        target_name: "state".to_string(),
        loc: SourceLoc {
            line: 24,
            column: 5,
        },
        message: "Finding in apps/web-react/src/Feed.tsx".to_string(),
        blast_radius: BlastRadius {
            score: 30,
            tier: BlastRadiusTier::P1,
            render_frequency: RenderFrequency::Standard,
            fan_out: 0,
            cascade_depth: 2,
            site_count: 1,
            file_count: 1,
        },
        diagnostic_indices: vec![1],
    };
    let g3 = RootCauseGroup {
        id: "rcg-api-1".to_string(),
        rule: RuleId::NoResetAllStateOnPropChange,
        category: RuleCategory::Bugs,
        severity: RuleSeverity::Error,
        tier: PrescriptionTier::Surgical,
        file: PathBuf::from("services/api/src/handler.ts"),
        subject_name: Some("handle_request".to_string()),
        target_name: "state".to_string(),
        loc: SourceLoc {
            line: 18,
            column: 5,
        },
        message: "Finding in services/api/src/handler.ts".to_string(),
        blast_radius: BlastRadius {
            score: 25,
            tier: BlastRadiusTier::P1,
            render_frequency: RenderFrequency::Standard,
            fan_out: 0,
            cascade_depth: 0,
            site_count: 1,
            file_count: 1,
        },
        diagnostic_indices: vec![2],
    };
    let projects = vec![
        ProjectCoverageMetadata {
            name: "web-react".to_string(),
            root_dir: PathBuf::from("apps/web-react"),
            role: PackageRole::Application,
            capabilities: vec![Capability::React, Capability::TypeScript],
            analyzed_files: vec![
                PathBuf::from("apps/web-react/src/App.tsx"),
                PathBuf::from("apps/web-react/src/Feed.tsx"),
            ],
            analyzed_file_count: 2,
            subjects_scanned: 2,
            diagnostic_count: 2,
            health_score: 78,
            score_label: "Good".to_string(),
            complete: true,
        },
        ProjectCoverageMetadata {
            name: "api".to_string(),
            root_dir: PathBuf::from("services/api"),
            role: PackageRole::Application,
            capabilities: vec![Capability::TypeScript],
            analyzed_files: vec![PathBuf::from("services/api/src/handler.ts")],
            analyzed_file_count: 1,
            subjects_scanned: 1,
            diagnostic_count: 1,
            health_score: 88,
            score_label: "Good".to_string(),
            complete: true,
        },
        ProjectCoverageMetadata {
            name: "shared-ui".to_string(),
            root_dir: PathBuf::from("packages/shared-ui"),
            role: PackageRole::Library,
            capabilities: vec![Capability::React, Capability::TypeScript],
            analyzed_files: vec![PathBuf::from("packages/shared-ui/src/Button.tsx")],
            analyzed_file_count: 1,
            subjects_scanned: 1,
            diagnostic_count: 0,
            health_score: 100,
            score_label: "Excellent".to_string(),
            complete: true,
        },
    ];

    JsonReport {
        schema_version: 3,
        mode: ScanMode::Full,
        summary: ReportSummary {
            files_scanned: 4,
            subjects_scanned: 4,
            effects_scanned: 2,
            total_diagnostics: 3,
            error_count: 2,
            warning_count: 1,
            affected_file_count: 3,
            autofix_count: 1,
            surgical_count: 1,
            refactor_count: 1,
            health_score: 84,
            score_label: "Good".to_string(),
        },
        projects,
        diagnostics: vec![d1, d2, d3],
        root_cause_groups: vec![g1, g2, g3],
        fix_capsules: Vec::new(),
        diagnostic_fingerprints: Default::default(),
        diff: None,
        baseline: None,
        baseline_degraded: false,
    }
}

#[test]
fn tui_package_picker_fuzzy_filters_highlights_toggles_and_applies_package_filter() {
    let report = make_monorepo_report();
    let tabs = build_filter_tabs(&report);
    let mut state = TuiState::from_report(&report, &tabs);

    assert_eq!(state.packages.len(), 3);
    assert_eq!(
        state.packages[0],
        TuiPackageItem::from_metadata(&report.projects[0])
    );
    assert_eq!(state.packages[0].name, "web-react");
    assert_eq!(state.packages[0].rel_path, "apps/web-react");
    assert_eq!(state.packages[0].health_score, 78);
    assert_eq!(state.packages[0].diagnostic_count, 2);
    assert!(!state.in_package_picker);
    assert!(!state.has_active_package_filter());

    // 1. Pressing `p` opens the package picker overlay
    assert!(!state.handle_key(b"p", 20, 10));
    assert!(state.in_package_picker);
    assert_eq!(state.picker_cursor, 0);
    assert_eq!(state.picker_selected, vec![true, true, true]);

    // 2. Render frame while picker is open -> overlay box appears with package rows, relative paths, findings, and Health Scores
    let all_refs: Vec<&Diagnostic> = report.diagnostics.iter().collect();
    let body_lines = render_tui_body_lines(&all_refs, TuiGroupMode::ByRuleStyle);
    let picker_frame =
        render_tui_frame_with_state(&report, &tabs, &state, &body_lines, 32, 120, false);
    let picker_plain = strip_ansi_codes(&picker_frame);
    assert!(picker_plain.contains("WORKSPACE PACKAGE PICKER"));
    assert!(picker_plain.contains("web-react"));
    assert!(picker_plain.contains("apps/web-react"));
    assert!(picker_plain.contains("78/100 (Good)"));
    assert!(picker_plain.contains("services/api"));
    assert!(picker_plain.contains("88/100 (Good)"));
    assert!(picker_plain.contains("packages/shared-ui"));
    assert!(picker_plain.contains("100/100 (Excellent)"));

    // 3. Typing fuzzy query filters packages and records character match indices
    assert!(!state.handle_key(b"w", 20, 10));
    assert!(!state.handle_key(b"r", 20, 10));
    assert_eq!(state.picker_query, "wr");
    let filtered_rows = state.filtered_picker_packages();
    assert_eq!(filtered_rows.len(), 1);
    assert_eq!(filtered_rows[0].package_idx, 0);
    assert_eq!(filtered_rows[0].name_matches, vec![0, 4]); // 'w' and 'r' in "web-react"

    // Verify highlight_fuzzy_matches wraps matched indices in match_ansi
    let highlighted = highlight_fuzzy_matches(
        "web-react",
        &filtered_rows[0].name_matches,
        "\x1b[38;5;255m",
        "\x1b[38;5;226;1;4m",
    );
    assert!(highlighted.contains("\x1b[38;5;226;1;4mw\x1b[0m"));
    assert!(highlighted.contains("\x1b[38;5;226;1;4mr\x1b[0m"));
    assert_eq!(strip_ansi_codes(&highlighted), "web-react");

    // Verify rendered picker lines contain highlighted match ANSI sequences
    let picker_lines = render_package_picker_lines(&state, 120);
    let joined_picker_ansi = picker_lines.join("\n");
    assert!(joined_picker_ansi.contains("\x1b[38;5;226;1;4mw\x1b[0m"));
    assert!(joined_picker_ansi.contains("\x1b[38;5;226;1;4mr\x1b[0m"));

    // 4. Clear query with Backspace twice, then press `a` to deselect all, then `Space` to select only `web-react`
    assert!(!state.handle_key(&[0x7f], 20, 10));
    assert!(!state.handle_key(&[0x7f], 20, 10));
    assert_eq!(state.picker_query, "");
    assert_eq!(state.filtered_picker_packages().len(), 3);

    // `a` toggles all from all-true -> all-false
    assert!(!state.handle_key(b"a", 20, 10));
    assert_eq!(state.picker_selected, vec![false, false, false]);

    // `Space` toggles row 0 (`web-react`) -> true
    assert!(!state.handle_key(b" ", 20, 10));
    assert_eq!(state.picker_selected, vec![true, false, false]);

    // 5. `Enter` applies the package filter and closes the picker
    assert!(!state.handle_key(b"\n", 20, 10));
    assert!(!state.in_package_picker);
    assert!(state.has_active_package_filter());
    assert_eq!(state.active_packages, vec![true, false, false]);
    assert!(state.is_file_in_active_packages(std::path::Path::new("apps/web-react/src/App.tsx")));
    assert!(!state.is_file_in_active_packages(std::path::Path::new("services/api/src/handler.ts")));

    // 6. Render frame with active package filter -> header metrics & viewport reflect only `web-react`
    let pkg_filtered: Vec<&Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| {
            state.is_file_in_active_packages(&d.file)
                && diagnostic_matches_tab_and_search(
                    d,
                    &tabs[state.active_tab_idx],
                    &state.search_query,
                )
        })
        .collect();
    assert_eq!(pkg_filtered.len(), 2);
    let filtered_body = render_tui_body_lines(&pkg_filtered, TuiGroupMode::ByRuleStyle);
    let filtered_frame =
        render_tui_frame_with_state(&report, &tabs, &state, &filtered_body, 32, 120, false);
    let filtered_plain = strip_ansi_codes(&filtered_frame);
    // Header health score reflects web-react (78/100) rather than overall (84/100)
    assert!(filtered_plain.contains("78/100"));
    assert!(filtered_plain.contains("✖ 1 err"));
    assert!(filtered_plain.contains("▲ 1 warn"));
    assert!(filtered_plain.contains("2 files · 2 subjects"));
    assert!(filtered_plain.contains("web-react"));
    assert!(!filtered_plain.contains("services/api/src/handler.ts"));
    assert!(filtered_plain.contains("Packages: 1/3 (web-react)"));

    // 7. Re-open picker (`p`), toggle all (`a`), then cancel with `ESC` -> does NOT exit TUI and preserves previous active filter
    assert!(!state.handle_key(b"p", 20, 10));
    assert!(state.in_package_picker);
    assert!(!state.handle_key(b"a", 20, 10));
    assert_eq!(state.picker_selected, vec![true, true, true]);
    assert!(!state.handle_key(&[0x1b], 20, 10)); // ESC cancels picker without exiting TUI
    assert!(!state.in_package_picker);
    assert_eq!(state.active_packages, vec![true, false, false]);
}

#[test]
fn tui_package_picker_arrow_navigation_path_matching_and_resizable_overlay_widths() {
    use dotore::visible_char_width;

    let report = make_monorepo_report();
    let tabs = build_filter_tabs(&report);
    let mut state = TuiState::from_report(&report, &tabs);

    // Open picker with `P`
    assert!(!state.handle_key(b"P", 20, 10));
    assert!(state.in_package_picker);
    assert_eq!(state.picker_cursor, 0);

    // Down arrow moves cursor 0 -> 1 -> 2, and clamps at 2
    assert!(!state.handle_key(b"\x1b[B", 20, 10));
    assert_eq!(state.picker_cursor, 1);
    assert!(!state.handle_key(b"\x1b[B", 20, 10));
    assert_eq!(state.picker_cursor, 2);
    assert!(!state.handle_key(b"\x1b[B", 20, 10));
    assert_eq!(state.picker_cursor, 2);

    // Up arrow moves cursor 2 -> 1
    assert!(!state.handle_key(b"\x1b[A", 20, 10));
    assert_eq!(state.picker_cursor, 1);

    // Space toggles index 1 (`api`) -> false
    assert!(!state.handle_key(b" ", 20, 10));
    assert_eq!(state.picker_selected, vec![true, false, true]);

    // Fuzzy filter by relative directory path (`services`) -> matches `services/api` via `path_matches`
    assert!(!state.handle_key(b"services", 20, 10));
    let path_rows = state.filtered_picker_packages();
    assert_eq!(path_rows.len(), 1);
    assert_eq!(path_rows[0].package_idx, 1);
    assert_eq!(path_rows[0].path_matches, vec![0, 1, 2, 3, 4, 5, 6, 7]);

    // Verify resizable picker overlay renders cleanly across 80, 100, and 120 columns
    for cols in [80usize, 100, 120] {
        let lines = render_package_picker_lines(&state, cols);
        assert!(!lines.is_empty());
        for line in &lines {
            assert!(
                visible_char_width(line) <= cols,
                "picker line exceeded {cols} cols: {}",
                strip_ansi_codes(line)
            );
        }
    }

    // Apply the 2-package selection (`web-react` + `shared-ui`) via Enter
    assert!(!state.handle_key(b"\r", 20, 10));
    assert!(!state.in_package_picker);
    assert_eq!(state.active_packages, vec![true, false, true]);

    let pkg_filtered: Vec<&Diagnostic> = report
        .diagnostics
        .iter()
        .filter(|d| state.is_file_in_active_packages(&d.file))
        .collect();
    assert_eq!(pkg_filtered.len(), 2);
    let body_lines = render_tui_body_lines(&pkg_filtered, TuiGroupMode::ByRuleStyle);
    let frame = render_tui_frame_with_state(&report, &tabs, &state, &body_lines, 30, 120, false);
    let plain = strip_ansi_codes(&frame);
    assert!(plain.contains("3 files · 3 subjects"));
    assert!(plain.contains("Packages: 2/3 (web-react, shared-ui)"));
}
