//! Integration tests for Ticket #02:
//! - Deterministic **Root-Cause Groups** (`root_cause_group_id` and `RootCauseGroup`)
//! - Static **Blast Radius** calculation (`BlastRadius`, `BlastRadiusTier::P0..=P3`, `RenderFrequency`)
//! - Single-file and cross-file **Caller Site** `Autofix` (`dotore fix` and `apply_autofixes`)
//! - Self-contained **Fix Capsules** with repository **Exemplars** (`FixCapsule`, `SourceExcerpt`)
//! - Deterministic Markdown plan generator (`dotore plan` and `plan_project`)

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    AutofixPatch, BlastRadiusTier, ByteEdit, ByteSpan, MIGRATION_BUCKET_MIN_FILES,
    PrescriptionTier, RenderFrequency, RuleCategory, RuleId, analyze_project_sources,
    analyze_source, apply_autofixes, apply_patches_to_source, build_agent_handoff_prompt,
    detect_migration_rule_buckets, plan_project, render_rule_bundle_summary_text,
    write_diagnostics_bundle,
};

#[test]
fn clusters_related_diagnostics_into_deterministic_root_cause_groups_and_ranks_blast_radius() {
    let files = vec![
        (
            PathBuf::from("package.json"),
            r#"{
                "name": "test-app",
                "private": true,
                "dependencies": {
                    "react": "^19.0.0",
                    "@react-three/fiber": "^9.0.0",
                    "three": "^0.170.0"
                }
            }"#
            .to_string(),
        ),
        // 1. Multiple State Slots adjusted on the same prop change in a single Subject -> 1 Root-Cause Group
        (
            PathBuf::from("src/UserEditor.tsx"),
            r#"
            import { useState, useEffect } from 'react';

            export function UserEditor({ userId }) {
                const [draftName, setDraftName] = useState('');
                const [draftBio, setDraftBio] = useState('');
                const [isDirty, setIsDirty] = useState(false);

                useEffect(() => {
                    if (userId) {
                        setDraftName('default');
                        setDraftBio('bio');
                    }
                }, [userId]);

                return <div>{draftName}{draftBio}{String(isDirty)}</div>;
            }
            "#
            .to_string(),
        ),
        // 2. Unstable Context.Provider value with multiple cross-file useContext consumers
        (
            PathBuf::from("src/ThemeContext.tsx"),
            r#"
            import { createContext, useContext } from 'react';

            export const ThemeContext = createContext({ mode: 'dark', accent: 'blue' });

            export function ThemeProvider({ mode, accent, children }) {
                return (
                    <ThemeContext.Provider value={{ mode, accent }}>
                        {children}
                    </ThemeContext.Provider>
                );
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/Header.tsx"),
            r#"
            import { useContext } from 'react';
            import { ThemeContext } from './ThemeContext';

            export function Header() {
                const theme = useContext(ThemeContext);
                return <header>{theme.mode}</header>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/Footer.tsx"),
            r#"
            import { useContext } from 'react';
            import { ThemeContext } from './ThemeContext';

            export function Footer() {
                const theme = useContext(ThemeContext);
                return <footer>{theme.accent}</footer>;
            }
            "#
            .to_string(),
        ),
        // 3. 60fps useFrame allocation -> P0 BlastRadius with FrameLoop60Fps render frequency
        (
            PathBuf::from("src/Scene.tsx"),
            r#"
            import { useFrame } from '@react-three/fiber';

            export function RotatingCube() {
                useFrame(() => {
                    const v = new Vector3(1, 2, 3);
                    console.log(v);
                });
                return <mesh />;
            }
            "#
            .to_string(),
        ),
        // 4. List .map() missing key -> ListLoop render frequency
        (
            PathBuf::from("src/Feed.tsx"),
            r#"
            export function Feed({ posts }) {
                return (
                    <ul>
                        {posts.map((post) => (
                            <li>{post.title}</li>
                        ))}
                    </ul>
                );
            }
            "#
            .to_string(),
        ),
        // 5. Minor design warning (when enabled) -> P3 BlastRadius
        (
            PathBuf::from("dotore.config.json"),
            r#"{
                "rules": {
                    "design-no-vague-button-label": "warn"
                }
            }"#
            .to_string(),
        ),
        (
            PathBuf::from("src/Modal.tsx"),
            r#"
            export function Modal() {
                return <button type="button">Click here</button>;
            }
            "#
            .to_string(),
        ),
    ];

    let report_a = analyze_project_sources(files.clone(), None);
    let report_b = analyze_project_sources(files, None);

    // Determinism across runs
    assert_eq!(report_a.root_cause_groups, report_b.root_cause_groups);

    // UserEditor has 2 diagnostics (`draftName` and `draftBio`) clustered into 1 Root-Cause Group
    let editor_diags: Vec<_> = report_a
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::NoAdjustStateOnPropChange)
        .collect();
    assert_eq!(editor_diags.len(), 2);
    assert!(!editor_diags[0].root_cause_group_id().is_empty());
    assert_eq!(
        editor_diags[0].root_cause_group_id(),
        editor_diags[1].root_cause_group_id()
    );

    let editor_group = report_a
        .root_cause_groups
        .iter()
        .find(|g| g.id == editor_diags[0].root_cause_group_id())
        .expect("Expected Root-Cause Group for UserEditor");
    assert_eq!(editor_group.blast_radius.site_count, 2);
    assert!(editor_group.blast_radius.cascade_depth >= 2);

    // ThemeContext.Provider unstable value has fan_out >= 2 from cross-file useContext(ThemeContext) consumers
    let theme_group = report_a
        .root_cause_groups
        .iter()
        .find(|g| g.file == Path::new("src/ThemeContext.tsx"))
        .expect("Expected Root-Cause Group for ThemeContext.Provider");
    assert!(
        theme_group.blast_radius.fan_out >= 2,
        "Expected fan_out >= 2 for ThemeContext consumers, got {}",
        theme_group.blast_radius.fan_out
    );

    // 60fps useFrame allocation gets FrameLoop60Fps and P0 tier
    let scene_group = report_a
        .root_cause_groups
        .iter()
        .find(|g| g.rule == RuleId::R3fNoNewInUseFrame)
        .expect("Expected Root-Cause Group for R3fNoNewInUseFrame");
    assert_eq!(
        scene_group.blast_radius.render_frequency,
        RenderFrequency::FrameLoop60Fps
    );
    assert_eq!(scene_group.blast_radius.tier, BlastRadiusTier::P0);

    // List .map() missing key gets ListLoop render frequency
    let feed_group = report_a
        .root_cause_groups
        .iter()
        .find(|g| g.rule == RuleId::JsxKey)
        .expect("Expected Root-Cause Group for JsxKey");
    assert_eq!(
        feed_group.blast_radius.render_frequency,
        RenderFrequency::ListLoop
    );

    // Minor vague button label warning gets P3 tier
    let modal_group = report_a
        .root_cause_groups
        .iter()
        .find(|g| g.rule == RuleId::DesignNoVagueButtonLabel)
        .expect("Expected Root-Cause Group for DesignNoVagueButtonLabel");
    assert_eq!(modal_group.blast_radius.tier, BlastRadiusTier::P3);

    // Root-cause groups are sorted by BlastRadius score descending
    for pair in report_a.root_cause_groups.windows(2) {
        assert!(
            pair[0].blast_radius.score >= pair[1].blast_radius.score,
            "Expected root_cause_groups sorted by blast_radius.score descending: {:?} vs {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn cross_file_autofix_injects_key_at_parent_callers_removes_reset_effect_and_reanalyzes_clean() {
    let profile_src = r#"import { useState, useEffect } from 'react';

export function ProfilePage({ userId }) {
    const [user, setUser] = useState(null);
    const [comment, setComment] = useState('initial');

    useEffect(() => {
        setUser(null);
        setComment('initial');
    }, [userId]);

    return <div>{user}{comment}</div>;
}
"#;
    let app_src = r#"import { ProfilePage } from './ProfilePage';

export function App({ activeUserId }) {
    return <ProfilePage userId={activeUserId} />;
}
"#;
    let dashboard_src = r#"import { ProfilePage } from './ProfilePage';

export function Dashboard({ selected }) {
    return <ProfilePage userId={selected.id} compact />;
}
"#;

    let files = vec![
        (
            PathBuf::from("src/ProfilePage.tsx"),
            profile_src.to_string(),
        ),
        (PathBuf::from("src/App.tsx"), app_src.to_string()),
        (
            PathBuf::from("src/Dashboard.tsx"),
            dashboard_src.to_string(),
        ),
    ];
    let sources: HashMap<PathBuf, String> = files.iter().cloned().collect();

    let report = analyze_project_sources(files, None);
    assert_eq!(report.diagnostics.len(), 1);
    let diag = &report.diagnostics[0];
    assert_eq!(diag.rule, RuleId::NoResetAllStateOnPropChange);
    assert_eq!(diag.tier, PrescriptionTier::Autofix);
    assert!(diag.autofix.is_some());

    let fix_results = apply_autofixes(&report.diagnostics, &sources, true)
        .expect("apply_autofixes dry-run should succeed");
    assert_eq!(fix_results.len(), 3);

    let fixed_map: HashMap<PathBuf, String> = fix_results
        .into_iter()
        .map(|r| (r.file, r.new_source))
        .collect();

    let fixed_profile = fixed_map
        .get(Path::new("src/ProfilePage.tsx"))
        .expect("ProfilePage.tsx should be modified");
    assert!(!fixed_profile.contains("useEffect("));

    let fixed_app = fixed_map
        .get(Path::new("src/App.tsx"))
        .expect("App.tsx should be modified");
    assert!(
        fixed_app.contains("<ProfilePage key={activeUserId} userId={activeUserId} />"),
        "Unexpected fixed App.tsx: {fixed_app}"
    );

    let fixed_dashboard = fixed_map
        .get(Path::new("src/Dashboard.tsx"))
        .expect("Dashboard.tsx should be modified");
    assert!(
        fixed_dashboard.contains("<ProfilePage key={selected.id} userId={selected.id} compact />"),
        "Unexpected fixed Dashboard.tsx: {fixed_dashboard}"
    );

    let reanalyzed = analyze_project_sources(fixed_map.into_iter().collect(), None);
    assert!(
        reanalyzed.diagnostics.is_empty(),
        "Expected 0 diagnostics after cross-file autofix, got: {:#?}",
        reanalyzed.diagnostics
    );
}

#[test]
fn fixer_resolves_overlapping_spans_and_rejects_syntax_corrupting_patches() {
    let source = r#"import { useState, useEffect } from 'react';
export function Form({ a }) {
    const [x, setX] = useState(0);
    useEffect(() => {
        setX(a + 1);
    }, [a]);
    return <div>{x}</div>;
}
"#;
    let mut diags = analyze_source(Path::new("Form.tsx"), source, None);
    assert_eq!(diags.len(), 1);

    // 1. Duplicate overlapping diagnostic should be skipped so the edit is applied only once
    let dup = diags[0].clone();
    diags.push(dup);
    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten.contains("const x = a + 1;"));

    // 2. A corrupted patch that would produce invalid syntax is rejected by oxc_parser validation
    let mut bad_diag = diags[0].clone();
    bad_diag.autofix = Some(AutofixPatch {
        description: "Broken syntax patch".to_string(),
        edits: vec![ByteEdit {
            file: None,
            span: ByteSpan { start: 0, end: 10 },
            replacement: "function ((( {{{{".to_string(),
        }],
    });
    let (untouched, bad_descriptions) = apply_patches_to_source(source, &[bad_diag]);
    assert!(bad_descriptions.is_empty());
    assert_eq!(untouched, source);
}

#[test]
fn fix_capsules_bundle_verbatim_subject_and_caller_excerpts_recipes_invariants_and_exemplars() {
    let store_bad_src = r#"import { useState, useEffect } from 'react';

export function LegacyOnlineBadge() {
    const [isOnline, setIsOnline] = useState(true);
    useEffect(() => {
        const handleStatus = () => setIsOnline(navigator.onLine);
        handleStatus();
        window.addEventListener('online', handleStatus);
        return () => window.removeEventListener('online', handleStatus);
    }, []);
    return <span>{String(isOnline)}</span>;
}
"#;
    let store_good_exemplar_src = r#"import { useSyncExternalStore } from 'react';

export function ModernOnlineBadge() {
    const isOnline = useSyncExternalStore(subscribeOnline, () => navigator.onLine);
    return <span>{String(isOnline)}</span>;
}
"#;
    let profile_src = r#"import { useState, useEffect } from 'react';

export function ProfileEditor({ userId }) {
    const [bio, setBio] = useState('');
    useEffect(() => {
        setBio('');
    }, [userId]);
    return <input value={bio} />;
}
"#;
    // Mixed caller sites (one missing key, one already having key={...}) keeps ProfileEditor in `Refactor` tier
    // and provides the valid keyed caller site as an Exemplar!
    let callers_src = r#"import { ProfileEditor } from './ProfileEditor';

export function AccountShell({ userId }) {
    return (
        <div>
            <ProfileEditor userId={userId} />
            <ProfileEditor key={userId} userId={userId} />
        </div>
    );
}
"#;

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/LegacyOnlineBadge.tsx"),
                store_bad_src.to_string(),
            ),
            (
                PathBuf::from("src/ModernOnlineBadge.tsx"),
                store_good_exemplar_src.to_string(),
            ),
            (
                PathBuf::from("src/ProfileEditor.tsx"),
                profile_src.to_string(),
            ),
            (
                PathBuf::from("src/AccountShell.tsx"),
                callers_src.to_string(),
            ),
        ],
        None,
    );

    assert_eq!(report.fix_capsules.len(), 2);

    // 1. Check `no-external-store-subscription` Surgical FixCapsule & discovered ModernOnlineBadge exemplar
    let store_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::NoExternalStoreSubscription)
        .expect("Expected FixCapsule for NoExternalStoreSubscription");
    assert_eq!(store_capsule.tier, PrescriptionTier::Surgical);
    assert_eq!(
        store_capsule.subject_excerpt.file,
        PathBuf::from("src/LegacyOnlineBadge.tsx")
    );
    assert!(
        store_capsule
            .subject_excerpt
            .source
            .contains("export function LegacyOnlineBadge()")
    );
    assert!(!store_capsule.recipe_markdown.is_empty());
    assert!(!store_capsule.invariants.is_empty());

    let store_exemplar = store_capsule
        .exemplar
        .as_ref()
        .expect("Expected discovered useSyncExternalStore repository exemplar");
    assert_eq!(
        store_exemplar.file,
        PathBuf::from("src/ModernOnlineBadge.tsx")
    );
    assert!(store_exemplar.source.contains("useSyncExternalStore("));

    // 2. Check `no-reset-all-state-on-prop-change` Refactor FixCapsule & caller site excerpts
    let reset_capsule = report
        .fix_capsules
        .iter()
        .find(|c| c.rule == RuleId::NoResetAllStateOnPropChange)
        .expect("Expected FixCapsule for NoResetAllStateOnPropChange");
    assert_eq!(reset_capsule.tier, PrescriptionTier::Refactor);
    assert_eq!(reset_capsule.caller_site_excerpts.len(), 2);
    assert!(
        reset_capsule
            .caller_site_excerpts
            .iter()
            .any(|e| e.source.contains("<ProfileEditor userId={userId} />"))
    );
    let reset_exemplar = reset_capsule
        .exemplar
        .as_ref()
        .expect("Expected valid keyed caller site exemplar");
    assert!(
        reset_exemplar
            .source
            .contains("<ProfileEditor key={userId} userId={userId} />")
    );

    // Verify JSON serialization of `dotore check --json` includes `root_cause_groups` and `fix_capsules`
    let json_text = serde_json::to_string_pretty(&report).expect("JsonReport should serialize");
    assert!(json_text.contains("\"root_cause_groups\""));
    assert!(json_text.contains("\"fix_capsules\""));
    assert!(json_text.contains("\"exemplar\""));
}

#[test]
fn dotore_plan_and_cli_write_deterministic_markdown_plans_and_readme_with_git_sha() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let temp_dir = std::env::temp_dir().join(format!("dotore-plan-test-{nanos}"));
    let src_dir = temp_dir.join("src");
    let plans_dir = temp_dir.join("plans");
    fs::create_dir_all(&src_dir).expect("create temp src dir");

    // Initialize a git repository with a known commit so `dotore plan` stamps the real short SHA
    let _ = Command::new("git")
        .args(["init"])
        .current_dir(&temp_dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&temp_dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&temp_dir)
        .output();

    fs::write(
        src_dir.join("ProfileEditor.tsx"),
        r#"import { useState, useEffect } from 'react';
export function ProfileEditor({ userId }) {
    const [bio, setBio] = useState('');
    const [dirty, setDirty] = useState(false);
    useEffect(() => {
        setBio('loaded');
    }, [userId]);
    return <div>{bio}{String(dirty)}</div>;
}
"#,
    )
    .expect("write ProfileEditor.tsx");

    fs::write(
        src_dir.join("OnlineStatus.tsx"),
        r#"import { useState, useEffect } from 'react';
export function OnlineStatus() {
    const [online, setOnline] = useState(true);
    useEffect(() => {
        const onChange = () => setOnline(navigator.onLine);
        onChange();
        window.addEventListener('online', onChange);
        return () => window.removeEventListener('online', onChange);
    }, []);
    return <span>{String(online)}</span>;
}
"#,
    )
    .expect("write OnlineStatus.tsx");

    let _ = Command::new("git")
        .args(["add", "."])
        .current_dir(&temp_dir)
        .output();
    let _ = Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(&temp_dir)
        .output();
    let head_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&temp_dir)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    assert!(!head_sha.is_empty(), "Expected git commit SHA in temp repo");

    // Run `dotore plan <src_dir> --out <plans_dir>` via CLI binary
    let bin = env!("CARGO_BIN_EXE_dotore");
    let output = Command::new(bin)
        .arg("plan")
        .arg(&src_dir)
        .arg("--out")
        .arg(&plans_dir)
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute dotore plan");

    assert!(
        output.status.success(),
        "Expected dotore plan to exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let readme_path = plans_dir.join("README.md");
    assert!(readme_path.exists(), "Expected plans/README.md to exist");
    let readme_content = fs::read_to_string(&readme_path).expect("read README.md");
    assert!(
        readme_content.contains(&head_sha),
        "Expected README.md to contain git commit SHA {head_sha}, got:\n{readme_content}"
    );
    assert!(readme_content.contains("001-"));
    assert!(readme_content.contains("002-"));

    // Verify generated NNN-<slug>.md files exist and contain required sections
    let plan_entries: Vec<PathBuf> = fs::read_dir(&plans_dir)
        .expect("read plans dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("README.md"))
        .collect();
    assert_eq!(plan_entries.len(), 2);

    for plan_file in &plan_entries {
        let content = fs::read_to_string(plan_file).expect("read plan file");
        assert!(content.contains("## Subject Excerpt"));
        assert!(content.contains("## Transformation Recipe"));
        assert!(content.contains("## Invariants to Preserve"));
        assert!(content.contains(&head_sha));
    }

    // Verify library entrypoint `plan_project` produces identical deterministic output
    let plans_dir_2 = temp_dir.join("plans_lib");
    let (report, _) = dotore::scan_workspace(&dotore::ScanOptions {
        paths: vec![src_dir],
        ..Default::default()
    })
    .expect("scan_workspace");
    let lib_plan = plan_project(&report, &plans_dir_2).expect("plan_project");
    assert_eq!(lib_plan.commit_sha, head_sha);
    assert_eq!(lib_plan.plan_files.len(), 2);

    let readme_lib = fs::read_to_string(&lib_plan.index_file).expect("read lib README.md");
    assert_eq!(readme_content, readme_lib);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn cli_fix_executes_cross_file_caller_site_rewrites_and_supports_dry_run() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let temp_dir = std::env::temp_dir().join(format!("dotore-cross-fix-test-{nanos}"));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let profile_path = temp_dir.join("ProfilePage.tsx");
    let app_path = temp_dir.join("App.tsx");
    let orig_profile = r#"import { useState, useEffect } from 'react';
export function ProfilePage({ userId }) {
    const [comment, setComment] = useState('');
    useEffect(() => {
        setComment('');
    }, [userId]);
    return <div>{comment}</div>;
}
"#;
    let orig_app = r#"import { ProfilePage } from './ProfilePage';
export function App({ currentUserId }) {
    return <ProfilePage userId={currentUserId} />;
}
"#;
    fs::write(&profile_path, orig_profile).expect("write ProfilePage.tsx");
    fs::write(&app_path, orig_app).expect("write App.tsx");

    let bin = env!("CARGO_BIN_EXE_dotore");

    // 1. `--dry-run` previews both files without modifying disk
    let dry_out = Command::new(bin)
        .arg("fix")
        .arg("--dry-run")
        .arg(&temp_dir)
        .output()
        .expect("run dotore fix --dry-run");
    assert!(dry_out.status.success());
    let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
    assert!(dry_stdout.contains("[dry-run]"));
    assert_eq!(fs::read_to_string(&profile_path).unwrap(), orig_profile);
    assert_eq!(fs::read_to_string(&app_path).unwrap(), orig_app);

    // 2. Real `dotore fix` rewrites both ProfilePage.tsx and App.tsx
    let fix_out = Command::new(bin)
        .arg("fix")
        .arg(&temp_dir)
        .output()
        .expect("run dotore fix");
    assert!(fix_out.status.success());

    let fixed_profile = fs::read_to_string(&profile_path).unwrap();
    let fixed_app = fs::read_to_string(&app_path).unwrap();
    assert!(!fixed_profile.contains("useEffect("));
    assert!(fixed_app.contains("<ProfilePage key={currentUserId} userId={currentUserId} />"));

    // 3. Re-running `dotore check` exits 0 with zero findings
    let check_out = Command::new(bin)
        .arg("check")
        .arg(&temp_dir)
        .output()
        .expect("run dotore check");
    assert!(
        check_out.status.success(),
        "Expected 0 findings after dotore fix, stdout: {}",
        String::from_utf8_lossy(&check_out.stdout)
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn detects_migration_rule_buckets_and_renders_per_rule_summary_text() {
    assert_eq!(MIGRATION_BUCKET_MIN_FILES, 3);

    let files = vec![
        // Rule `no-derived-state` across 4 distinct files -> migration bucket (>= 3 files)
        (
            PathBuf::from("src/CartSummary.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function CartSummary({ price, qty }) {
                const [total, setTotal] = useState(0);
                useEffect(() => {
                    setTotal(price * qty);
                }, [price, qty]);
                return <div>{total}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/OrderRow.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function OrderRow({ subtotal, tax }) {
                const [grandTotal, setGrandTotal] = useState(0);
                useEffect(() => {
                    setGrandTotal(subtotal + tax);
                }, [subtotal, tax]);
                return <div>{grandTotal}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/InvoiceHeader.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function InvoiceHeader({ first, last }) {
                const [fullName, setFullName] = useState('');
                useEffect(() => {
                    setFullName(first + ' ' + last);
                }, [first, last]);
                return <h1>{fullName}</h1>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/ReceiptFooter.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function ReceiptFooter({ items, discount }) {
                const [net, setNet] = useState(0);
                useEffect(() => {
                    setNet(items - discount);
                }, [items, discount]);
                return <footer>{net}</footer>;
            }
            "#
            .to_string(),
        ),
        // Rule `no-adjust-state-on-prop-change` in only 1 file -> NOT a migration bucket (< 3 files)
        (
            PathBuf::from("src/UserEditor.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function UserEditor({ userId }) {
                const [draft, setDraft] = useState('');
                const [dirty, setDirty] = useState(false);
                useEffect(() => {
                    if (userId) {
                        setDraft('reset');
                    }
                }, [userId]);
                return <div>{draft}{String(dirty)}</div>;
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(files, None);
    let buckets = detect_migration_rule_buckets(&report);
    assert_eq!(
        buckets.len(),
        1,
        "Expected exactly 1 migration bucket, got {buckets:?}"
    );

    let bucket = &buckets[0];
    assert_eq!(bucket.rule, RuleId::NoDerivedState);
    assert_eq!(bucket.category, RuleCategory::Performance);
    assert_eq!(bucket.tier, PrescriptionTier::Autofix);
    assert_eq!(bucket.diagnostic_count, 4);
    assert_eq!(
        bucket.affected_files,
        vec![
            PathBuf::from("src/CartSummary.tsx"),
            PathBuf::from("src/InvoiceHeader.tsx"),
            PathBuf::from("src/OrderRow.tsx"),
            PathBuf::from("src/ReceiptFooter.tsx"),
        ]
    );
    assert!(bucket.summary_file.is_none());

    let summary_txt = render_rule_bundle_summary_text(RuleId::NoDerivedState, &report);
    assert!(summary_txt.contains("no-derived-state"));
    assert!(summary_txt.contains("Performance"));
    assert!(summary_txt.contains("autofix"));
    assert!(summary_txt.contains("src/CartSummary.tsx"));
    assert!(summary_txt.contains("src/InvoiceHeader.tsx"));
    assert!(summary_txt.contains("src/OrderRow.tsx"));
    assert!(summary_txt.contains("src/ReceiptFooter.tsx"));
    assert!(summary_txt.contains("rcg::no-derived-state::"));
}

#[test]
fn synthesizes_self_contained_agent_handoff_prompt_and_writes_diagnostics_bundle() {
    let files = vec![
        // 1. Multiple State Slots adjusted on prop change in UserEditor -> shared root_cause_group_id (`Surgical` tier)
        (
            PathBuf::from("src/UserEditor.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function UserEditor({ userId }) {
                const [draftName, setDraftName] = useState('');
                const [draftBio, setDraftBio] = useState('');
                const [isDirty, setIsDirty] = useState(false);
                useEffect(() => {
                    if (userId) {
                        setDraftName('default');
                        setDraftBio('bio');
                    }
                }, [userId]);
                return <div>{draftName}{draftBio}{String(isDirty)}</div>;
            }
            "#
            .to_string(),
        ),
        // 2. Migration-scale rule (`no-derived-state`) across 3 distinct files
        (
            PathBuf::from("src/CartSummary.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function CartSummary({ price, qty }) {
                const [total, setTotal] = useState(0);
                useEffect(() => {
                    setTotal(price * qty);
                }, [price, qty]);
                return <div>{total}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/OrderRow.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function OrderRow({ subtotal, tax }) {
                const [grandTotal, setGrandTotal] = useState(0);
                useEffect(() => {
                    setGrandTotal(subtotal + tax);
                }, [subtotal, tax]);
                return <div>{grandTotal}</div>;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/InvoiceHeader.tsx"),
            r#"
            import { useState, useEffect } from 'react';
            export function InvoiceHeader({ first, last }) {
                const [fullName, setFullName] = useState('');
                useEffect(() => {
                    setFullName(first + ' ' + last);
                }, [first, last]);
                return <h1>{fullName}</h1>;
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(files, None);

    // 1. Prompt without bundle_dir
    let standalone_prompt = build_agent_handoff_prompt(&report, None);
    assert!(standalone_prompt.contains("Root-Cause Group"));
    assert!(standalone_prompt.contains("Prescription Tier"));
    assert!(standalone_prompt.contains("root_cause_group_id"));
    assert!(
        standalone_prompt
            .contains("rcg::no-adjust-state-on-prop-change::src/UserEditor.tsx::user-editor")
    );
    assert!(standalone_prompt.contains("surgical"));
    assert!(standalone_prompt.contains("autofix"));
    assert!(standalone_prompt.contains("src/UserEditor.tsx:"));
    assert!(standalone_prompt.contains("Transformation Recipe"));
    assert!(standalone_prompt.contains("Migration-Scale Rule Buckets"));
    assert!(standalone_prompt.contains("Staged Remediation Guidance"));
    assert!(standalone_prompt.contains("no-derived-state"));

    // 2. Write diagnostics bundle directory
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let bundle_dir = std::env::temp_dir().join(format!("dotore-bundle-test-{nanos}"));
    let bundle = write_diagnostics_bundle(&report, &bundle_dir).expect("write_diagnostics_bundle");

    assert_eq!(bundle.bundle_dir, bundle_dir);
    assert_eq!(
        bundle.diagnostics_json_path,
        bundle_dir.join("diagnostics.json")
    );
    assert!(
        bundle.diagnostics_json_path.exists(),
        "diagnostics.json must exist"
    );

    let diag_json_str =
        fs::read_to_string(&bundle.diagnostics_json_path).expect("read diagnostics.json");
    let diag_json: serde_json::Value =
        serde_json::from_str(&diag_json_str).expect("parse diagnostics.json");
    assert_eq!(
        diag_json["diagnostics"].as_array().map(Vec::len),
        Some(report.diagnostics.len())
    );
    assert_eq!(
        diag_json["root_cause_groups"].as_array().map(Vec::len),
        Some(report.root_cause_groups.len())
    );

    // Verify per-rule .txt files exist for every distinct rule in the report and are referenced in prompt_markdown
    assert!(bundle.rule_summary_files.len() >= 2);
    assert!(
        bundle
            .rule_summary_files
            .iter()
            .any(|(r, _)| *r == RuleId::NoDerivedState)
    );
    assert!(
        bundle
            .rule_summary_files
            .iter()
            .any(|(r, _)| *r == RuleId::NoAdjustStateOnPropChange)
    );
    for (rule, rule_txt_path) in &bundle.rule_summary_files {
        assert!(
            rule_txt_path.exists(),
            "Expected {} to exist",
            rule_txt_path.display()
        );
        assert_eq!(
            rule_txt_path.file_name().and_then(|n| n.to_str()),
            Some(format!("{}.txt", rule.as_str()).as_str())
        );
        let txt_content = fs::read_to_string(rule_txt_path).expect("read rule .txt");
        assert!(txt_content.contains(rule.as_str()));
        assert!(
            bundle
                .prompt_markdown
                .contains(&format!("{}.txt", rule.as_str())),
            "Expected prompt_markdown to reference {}.txt",
            rule.as_str()
        );
    }

    assert_eq!(bundle.migration_buckets.len(), 1);
    assert_eq!(bundle.migration_buckets[0].rule, RuleId::NoDerivedState);
    assert_eq!(
        bundle.migration_buckets[0].summary_file,
        Some(bundle_dir.join("no-derived-state.txt"))
    );
    assert!(bundle.prompt_markdown.contains("diagnostics.json"));

    let _ = fs::remove_dir_all(&bundle_dir);
}

#[test]
fn cli_plan_handoff_writes_diagnostics_bundle_and_prints_handoff_prompt() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let temp_dir = std::env::temp_dir().join(format!("dotore-cli-plan-handoff-{nanos}"));
    let src_dir = temp_dir.join("src");
    let plans_dir = temp_dir.join("plans");
    let custom_bundle_dir = temp_dir.join("custom-bundle");
    fs::create_dir_all(&src_dir).expect("create temp src dir");

    for (name, comp) in [
        ("One.tsx", "One"),
        ("Two.tsx", "Two"),
        ("Three.tsx", "Three"),
    ] {
        fs::write(
            src_dir.join(name),
            format!(
                r#"import {{ useState, useEffect }} from 'react';
export function {comp}({{ a, b }}) {{
    const [sum, setSum] = useState(0);
    useEffect(() => {{
        setSum(a + b);
    }}, [a, b]);
    return <div>{{sum}}</div>;
}}
"#
            ),
        )
        .expect("write fixture file");
    }

    let bin = env!("CARGO_BIN_EXE_dotore");

    // 1. `dotore plan <src_dir> --out <plans_dir> --handoff`
    let output = Command::new(bin)
        .arg("plan")
        .arg(&src_dir)
        .arg("--out")
        .arg(&plans_dir)
        .arg("--handoff")
        .current_dir(&temp_dir)
        .output()
        .expect("run dotore plan --handoff");

    assert!(
        output.status.success(),
        "Expected dotore plan --handoff to exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# Dotore Coding Agent Remediation Handoff"));
    assert!(stdout.contains("Migration-Scale Rule Buckets"));
    assert!(stdout.contains("Staged Remediation Guidance"));
    assert!(stdout.contains("no-derived-state"));
    assert!(stdout.contains("diagnostics.json"));
    assert!(stdout.contains("no-derived-state.txt"));
    assert!(plans_dir.join("diagnostics.json").exists());
    assert!(plans_dir.join("no-derived-state.txt").exists());
    assert!(plans_dir.join("README.md").exists());

    // 2. `dotore plan <src_dir> --out <plans_dir> --handoff --bundle-dir <custom_bundle_dir>`
    let output_custom = Command::new(bin)
        .arg("plan")
        .arg(&src_dir)
        .arg("--out")
        .arg(&plans_dir)
        .arg("--handoff")
        .arg("--bundle-dir")
        .arg(&custom_bundle_dir)
        .current_dir(&temp_dir)
        .output()
        .expect("run dotore plan --handoff --bundle-dir");
    assert!(output_custom.status.success());
    assert!(custom_bundle_dir.join("diagnostics.json").exists());
    assert!(custom_bundle_dir.join("no-derived-state.txt").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}
