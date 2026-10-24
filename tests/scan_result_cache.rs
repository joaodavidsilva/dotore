//! Integration tests for Ticket #39: Persistent Workspace Scan Result Cache (`dotore check`).

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    CliOverrides, Diagnostic, DiffScope, FixCapsule, JsonReport, MAX_SCAN_CACHE_ENTRIES,
    PrescriptionTier, RootCauseGroup, RuleId, SCAN_CACHE_SCHEMA_VERSION, ScanCacheEntry,
    ScanOptions, analyze_project_sources, is_cache_disabled, load_scan_result_cache,
    lookup_scan_cache, resolve_dotore_home_dir, resolve_scan_cache_path,
    scan_workspace_with_overrides, store_scan_cache,
};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn create_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "dotore-scan-cache-{prefix}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("failed to create temp dir: {e}"));
    dir
}

#[test]
fn json_report_deserialization_and_lru_cache_store_lookup_preserve_full_report_and_bound_entries() {
    let temp_dir = create_temp_dir("lru-unit");
    let cache_path = temp_dir.join("cache").join("scan-results.json");

    // Build a rich JsonReport with Diagnostics (including Caller Sites and Render Cascade),
    // Root-Cause Groups, and Fix Capsules (with Subject Excerpt, Caller Site Excerpts, Exemplar, and Invariants).
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/App.tsx"),
                r#"
                import { ProfilePage } from './ProfilePage';
                export function App({ userId }: { userId: string }) {
                    return <ProfilePage userId={userId} />;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/ProfilePage.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function ProfilePage({ userId }: { userId: string }) {
                    const [draft, setDraft] = useState('');
                    const [saved, setSaved] = useState(false);
                    useEffect(() => {
                        setDraft('');
                        setSaved(false);
                    }, [userId]);
                    return <div>{userId}{draft}{String(saved)}</div>;
                }
                "#
                .to_string(),
            ),
            (
                PathBuf::from("src/Feed.tsx"),
                r#"
                import { useState, useEffect } from 'react';
                export function Feed({ endpoint }: { endpoint: string }) {
                    const [items, setItems] = useState<string[]>([]);
                    useEffect(() => {
                        fetch(endpoint).then((r) => r.json()).then((d) => setItems(d));
                    }, [endpoint]);
                    return <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>;
                }
                "#
                .to_string(),
            ),
        ],
        None,
    );

    assert!(!report.diagnostics.is_empty());
    assert!(!report.root_cause_groups.is_empty());
    assert!(!report.fix_capsules.is_empty());

    // Roundtrip through JSON and verify Diagnostic, RootCauseGroup, and FixCapsule fidelity
    let encoded = serde_json::to_string_pretty(&report).unwrap();
    let decoded: JsonReport = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, report);
    let _: &[Diagnostic] = &decoded.diagnostics;
    let _: &[RootCauseGroup] = &decoded.root_cause_groups;
    let _: &[FixCapsule] = &decoded.fix_capsules;

    // Missing cache file returns empty versioned cache
    let initial = load_scan_result_cache(&cache_path);
    assert_eq!(initial.version, SCAN_CACHE_SCHEMA_VERSION);
    assert!(initial.entries.is_empty());
    assert!(lookup_scan_cache(&cache_path, "scan::missing").is_none());

    // Insert MAX_SCAN_CACHE_ENTRIES + 4 entries and verify LRU bounding at 16
    for i in 0..(MAX_SCAN_CACHE_ENTRIES + 4) {
        let mut r = report.clone();
        r.summary.health_score = u32::try_from(i).unwrap();
        store_scan_cache(
            &cache_path,
            ScanCacheEntry {
                key: format!("scan::{i:016x}"),
                workspace_root: "/tmp/workspace".to_string(),
                head_sha: "abc1234".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                updated_at_ms: u64::try_from(1000 + i).unwrap(),
                report: r,
            },
        )
        .unwrap();
    }

    let loaded = load_scan_result_cache(&cache_path);
    assert_eq!(loaded.version, SCAN_CACHE_SCHEMA_VERSION);
    assert_eq!(loaded.entries.len(), MAX_SCAN_CACHE_ENTRIES);
    // Most recently inserted entry (index 19) is at front (index 0); oldest 0..4 were evicted
    assert_eq!(
        loaded.entries[0].key,
        format!("scan::{:016x}", MAX_SCAN_CACHE_ENTRIES + 3)
    );
    assert!(lookup_scan_cache(&cache_path, &format!("scan::{:016x}", 0)).is_none());
    assert!(lookup_scan_cache(&cache_path, &format!("scan::{:016x}", 3)).is_none());

    // Looking up an older retained entry (e.g. index 4) moves it to the front (index 0)
    let key_4 = format!("scan::{:016x}", 4);
    let hit_4 = lookup_scan_cache(&cache_path, &key_4).expect("entry 4 should be present");
    assert_eq!(hit_4.summary.health_score, 4);
    assert_eq!(hit_4.root_cause_groups, report.root_cause_groups);
    assert_eq!(hit_4.fix_capsules, report.fix_capsules);

    let after_hit = load_scan_result_cache(&cache_path);
    assert_eq!(after_hit.entries.len(), MAX_SCAN_CACHE_ENTRIES);
    assert_eq!(after_hit.entries[0].key, key_4);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn dotore_home_and_cache_disable_env_helpers_work() {
    let _guard = ENV_MUTEX.lock().unwrap();
    let temp_dir = create_temp_dir("env-helpers");

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_HOME", &temp_dir);
        std::env::remove_var("DOTORE_NO_CACHE");
    }

    assert_eq!(resolve_dotore_home_dir(), Some(temp_dir.clone()));
    assert_eq!(
        resolve_scan_cache_path(),
        Some(temp_dir.join("cache").join("scan-results.json"))
    );
    assert!(!is_cache_disabled(false));
    assert!(is_cache_disabled(true));

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_NO_CACHE", "1");
    }
    assert!(is_cache_disabled(false));

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_NO_CACHE", "true");
    }
    assert!(is_cache_disabled(false));

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_NO_CACHE", "0");
    }
    assert!(!is_cache_disabled(false));

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::remove_var("DOTORE_NO_CACHE");
        std::env::remove_var("DOTORE_HOME");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

fn run_git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("git command should run: {e}"));
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_git_repo(dir: &Path) {
    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test User"]);
}

#[test]
fn scan_workspace_cache_hit_parity_and_invalidation_on_tracked_untracked_config_and_filter_changes()
{
    let _guard = ENV_MUTEX.lock().unwrap();
    let root = create_temp_dir("workspace-cache");
    let dotore_home = root.join("dotore-home");
    let repo_dir = root.join("repo");
    let src_dir = repo_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_HOME", &dotore_home);
        std::env::remove_var("DOTORE_NO_CACHE");
    }

    init_git_repo(&repo_dir);
    fs::write(
        repo_dir.join("package.json"),
        r#"{"name": "cache-test-app", "dependencies": {"react": "^19.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("App.tsx"),
        r#"
        import { UserEditor } from './UserEditor';
        export function App({ userId }: { userId: string }) {
            return <UserEditor userId={userId} />;
        }
        "#,
    )
    .unwrap();
    fs::write(
        src_dir.join("UserEditor.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function UserEditor({ userId }: { userId: string }) {
            const [draft, setDraft] = useState('');
            const [dirty, setDirty] = useState(false);
            useEffect(() => {
                setDraft('');
                setDirty(false);
            }, [userId]);
            return <div>{userId}{draft}{String(dirty)}</div>;
        }
        "#,
    )
    .unwrap();
    fs::write(
        src_dir.join("Feed.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function Feed({ endpoint }: { endpoint: string }) {
            const [items, setItems] = useState<string[]>([]);
            useEffect(() => {
                fetch(endpoint).then((r) => r.json()).then((d) => setItems(d));
            }, [endpoint]);
            return <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>;
        }
        "#,
    )
    .unwrap();
    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "initial commit"]);
    let head_sha = run_git(&repo_dir, &["rev-parse", "HEAD"]);

    let cache_path = resolve_scan_cache_path().unwrap();
    assert!(!cache_path.exists());

    let base_options = ScanOptions {
        paths: vec![repo_dir.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    };
    let base_overrides = CliOverrides::default();

    // 1. Cold scan populates `~/.dotore/cache/scan-results.json`
    let (cold_report, cold_sources) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert!(!cold_report.diagnostics.is_empty());
    assert!(!cold_report.root_cause_groups.is_empty());
    assert!(!cold_report.fix_capsules.is_empty());
    assert!(cache_path.is_file());

    let cache_file_1 = load_scan_result_cache(&cache_path);
    assert_eq!(cache_file_1.entries.len(), 1);
    assert_eq!(cache_file_1.entries[0].head_sha, head_sha);
    let initial_key = cache_file_1.entries[0].key.clone();

    // 2. Warm scan hits the cache and returns identical diagnostics, Root-Cause Groups, and Fix Capsules
    let (warm_report, warm_sources) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert_eq!(warm_report, cold_report);
    assert_eq!(warm_report.diagnostics, cold_report.diagnostics);
    assert_eq!(warm_report.root_cause_groups, cold_report.root_cause_groups);
    assert_eq!(warm_report.fix_capsules, cold_report.fix_capsules);
    assert_eq!(warm_sources.len(), cold_sources.len());

    // Prove the warm scan actually served from disk cache by mutating the cached entry's score_label on disk
    let mut tampered = load_scan_result_cache(&cache_path);
    tampered.entries[0].report.summary.score_label = "FromDiskCacheSentinel".to_string();
    store_scan_cache(&cache_path, tampered.entries.remove(0)).unwrap();
    let (sentinel_report, _) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert_eq!(sentinel_report.summary.score_label, "FromDiskCacheSentinel");
    // Restore clean cached entry
    let mut restored_entry = load_scan_result_cache(&cache_path).entries.remove(0);
    restored_entry.report = cold_report.clone();
    store_scan_cache(&cache_path, restored_entry).unwrap();

    // 3. Modifying a tracked source file invalidates the cache key and triggers a fresh scan
    fs::write(
        src_dir.join("UserEditor.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function UserEditor({ userId }: { userId: string }) {
            const [draft, setDraft] = useState('');
            const [dirty, setDirty] = useState(false);
            const [upper, setUpper] = useState('');
            useEffect(() => {
                setDraft('');
                setDirty(false);
            }, [userId]);
            useEffect(() => {
                setUpper(userId.toUpperCase());
            }, [userId]);
            return <div>{userId}{draft}{String(dirty)}{upper}</div>;
        }
        "#,
    )
    .unwrap();
    let (tracked_edit_report, _) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert!(tracked_edit_report.diagnostics.len() > cold_report.diagnostics.len());
    let cache_after_tracked = load_scan_result_cache(&cache_path);
    assert_eq!(cache_after_tracked.entries.len(), 2);
    assert_ne!(cache_after_tracked.entries[0].key, initial_key);
    let tracked_edit_key = cache_after_tracked.entries[0].key.clone();

    // 4. Adding an untracked source file invalidates the cache key and triggers a fresh scan
    fs::write(
        src_dir.join("UntrackedWidget.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function UntrackedWidget({ count }: { count: number }) {
            const [double, setDouble] = useState(0);
            useEffect(() => {
                setDouble(count * 2);
            }, [count]);
            return <span>{double}</span>;
        }
        "#,
    )
    .unwrap();
    let (untracked_report, _) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert!(untracked_report.diagnostics.len() > tracked_edit_report.diagnostics.len());
    let cache_after_untracked = load_scan_result_cache(&cache_path);
    assert_eq!(cache_after_untracked.entries.len(), 3);
    assert_ne!(cache_after_untracked.entries[0].key, tracked_edit_key);
    let untracked_key = cache_after_untracked.entries[0].key.clone();

    // 5. Adding or modifying `dotore.config.json` invalidates the cache key and triggers a fresh scan
    fs::write(
        repo_dir.join("dotore.config.json"),
        r#"{"rules": {"no-derived-state": "off"}}"#,
    )
    .unwrap();
    let (config_edit_report, _) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert!(config_edit_report.diagnostics.len() < untracked_report.diagnostics.len());
    let cache_after_config = load_scan_result_cache(&cache_path);
    assert_eq!(cache_after_config.entries.len(), 4);
    assert_ne!(cache_after_config.entries[0].key, untracked_key);
    let config_key = cache_after_config.entries[0].key.clone();

    // 6. Changing CLI filter options (rules / tiers / overrides) invalidates the cache key
    let filtered_options = ScanOptions {
        paths: vec![repo_dir.clone()],
        include_tests: false,
        rules: Some(vec![RuleId::NoResetAllStateOnPropChange]),
        tiers: Some(vec![PrescriptionTier::Surgical, PrescriptionTier::Refactor]),
    };
    let (filtered_report, _) =
        scan_workspace_with_overrides(&filtered_options, &base_overrides).unwrap();
    assert!(
        filtered_report
            .diagnostics
            .iter()
            .all(|d| d.rule == RuleId::NoResetAllStateOnPropChange)
    );
    let cache_after_filter = load_scan_result_cache(&cache_path);
    assert_eq!(cache_after_filter.entries.len(), 5);
    assert_ne!(cache_after_filter.entries[0].key, config_key);

    // 7. Changing diff scope (`--scope changed`) produces a distinct cache key
    let diff_overrides = CliOverrides {
        scope: DiffScope::Changed,
        base_ref: Some("HEAD".to_string()),
        ..Default::default()
    };
    let (diff_report, _) = scan_workspace_with_overrides(&base_options, &diff_overrides).unwrap();
    let cache_after_diff = load_scan_result_cache(&cache_path);
    assert_eq!(cache_after_diff.entries.len(), 6);
    assert_eq!(diff_report.mode, dotore::ScanMode::Diff);

    // 8. `no_cache: true` and `DOTORE_NO_CACHE=1` bypass cache reads and writes
    fs::remove_file(&cache_path).unwrap();
    let no_cache_overrides = CliOverrides {
        no_cache: true,
        ..Default::default()
    };
    let (bypass_report, _) =
        scan_workspace_with_overrides(&base_options, &no_cache_overrides).unwrap();
    assert_eq!(bypass_report, config_edit_report);
    assert!(
        !cache_path.exists(),
        "no_cache: true must not write scan-results.json"
    );

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::set_var("DOTORE_NO_CACHE", "1");
    }
    let (env_bypass_report, _) =
        scan_workspace_with_overrides(&base_options, &base_overrides).unwrap();
    assert_eq!(env_bypass_report, config_edit_report);
    assert!(
        !cache_path.exists(),
        "DOTORE_NO_CACHE=1 must not write scan-results.json"
    );

    // SAFETY: serialized via ENV_MUTEX in this test binary.
    unsafe {
        std::env::remove_var("DOTORE_NO_CACHE");
        std::env::remove_var("DOTORE_HOME");
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cli_subcommands_use_scan_cache_and_honor_no_cache_flag_and_env() {
    let root = create_temp_dir("cli-cache");
    let dotore_home = root.join("dotore-home");
    let repo_dir = root.join("repo");
    let src_dir = repo_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    init_git_repo(&repo_dir);
    fs::write(
        repo_dir.join("package.json"),
        r#"{"name": "cli-cache-app", "dependencies": {"react": "^19.0.0"}}"#,
    )
    .unwrap();
    fs::write(repo_dir.join(".gitignore"), "ignored-vendor-pkg/\n").unwrap();
    let ignored_pkg_dir = repo_dir.join("ignored-vendor-pkg");
    fs::create_dir_all(&ignored_pkg_dir).unwrap();
    fs::write(
        ignored_pkg_dir.join("package.json"),
        r#"{"name": "ignored-vendor-pkg", "dependencies": {"react": "^19.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        repo_dir.join("dotore.config.json"),
        r#"{"rules": {"no-console": "warn", "prefer-const": "warn"}, "categories": {"Bugs": "error", "Performance": "warn"}}"#,
    )
    .unwrap();
    fs::write(
        src_dir.join("Widget.tsx"),
        r#"
        import { useState, useEffect } from 'react';
        export function Widget({ userId }: { userId: string }) {
            const [draft, setDraft] = useState('');
            const [saved, setSaved] = useState(false);
            useEffect(() => {
                setDraft('');
                setSaved(false);
            }, [userId]);
            return <div>{userId}{draft}{String(saved)}</div>;
        }
        "#,
    )
    .unwrap();
    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "initial"]);

    let bin = env!("CARGO_BIN_EXE_dotore");
    let cache_path = dotore_home.join("cache").join("scan-results.json");

    // 1. `dotore check --no-cache` does not create `scan-results.json`
    let out_no_cache = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .env_remove("DOTORE_NO_CACHE")
        .args(["check", "--json", "--no-fail", "--no-cache"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_no_cache.status.success());
    assert!(!cache_path.exists());

    // 2. `DOTORE_NO_CACHE=1 dotore check` does not create `scan-results.json`
    let out_env_no_cache = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .env("DOTORE_NO_CACHE", "1")
        .args(["check", "--json", "--no-fail"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_env_no_cache.status.success());
    assert!(!cache_path.exists());

    // 3. Normal `dotore check` populates `scan-results.json`, and repeat `dotore check` + `dotore score` return identical results
    let out_cold = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .env_remove("DOTORE_NO_CACHE")
        .args(["check", "--json", "--no-fail"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_cold.status.success());
    assert!(cache_path.is_file());
    let cold_report: JsonReport = serde_json::from_slice(&out_cold.stdout).unwrap();

    let out_warm = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .env_remove("DOTORE_NO_CACHE")
        .args(["check", "--json", "--no-fail"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_warm.status.success());
    let warm_report: JsonReport = serde_json::from_slice(&out_warm.stdout).unwrap();
    assert_eq!(warm_report, cold_report);
    assert_eq!(out_warm.stdout, out_cold.stdout);
    let warm_cache = load_scan_result_cache(&cache_path);
    assert_eq!(
        warm_cache.entries.len(),
        1,
        "separate CLI child processes must compute an identical deterministic cache key"
    );
    assert_eq!(
        warm_report.projects.len(),
        1,
        "gitignored nested package directories must not pollute discovered workspace packages"
    );

    // `dotore score` also accepts `--no-cache`
    let out_score = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .env_remove("DOTORE_NO_CACHE")
        .args(["score", "--no-fail", "--no-cache"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_score.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out_score.stdout).trim(),
        cold_report.summary.health_score.to_string()
    );

    // `dotore plan`, `dotore report`, and `dotore fix --dry-run` accept `--no-cache`
    let plans_dir = root.join("plans");
    let out_plan = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .args(["plan", "--no-cache", "--out"])
        .arg(&plans_dir)
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_plan.status.success());

    let html_path = root.join("report.html");
    let out_report = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .args(["report", "--no-open", "--no-cache", "--output"])
        .arg(&html_path)
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_report.status.success());
    assert!(html_path.is_file());

    let out_fix = Command::new(bin)
        .env("DOTORE_HOME", &dotore_home)
        .args(["fix", "--dry-run", "--no-cache"])
        .arg(&repo_dir)
        .output()
        .unwrap();
    assert!(out_fix.status.success());

    let _ = fs::remove_dir_all(&root);
}
