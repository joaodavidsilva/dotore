//! Integration tests for the visual HTML `Render Cascade` report (`src/report.rs` and `dotore report`).

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{analyze_project_sources, render_html_report, write_and_open_html_report};

fn assert_contains_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "expected HTML report to contain {needle:?}"
        );
    }
}

#[test]
fn renders_html_report_with_score_tiers_cascades_caller_sites_and_autofix() {
    let form_code = r#"
        export function Form({ firstName, lastName }) {
          const [fullName, setFullName] = useState('');
          useEffect(() => {
            setFullName(firstName + ' ' + lastName);
          }, [firstName, lastName]);
          return <div>{fullName}</div>;
        }
    "#;

    let profile_code = r#"
        export function ProfilePage({ userId }) {
          const [comment, setComment] = useState('');
          useEffect(() => {
            setComment('');
          }, [userId]);
          return <div>{comment}</div>;
        }
    "#;

    let app_code = r#"
        import { ProfilePage } from './ProfilePage';

        export function App({ currentUserId }) {
          return (
            <main>
              <ProfilePage userId={currentUserId} />
              <ProfilePage key={currentUserId} userId={currentUserId} />
            </main>
          );
        }
    "#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("src/Form.tsx"), form_code.to_string()),
            (
                PathBuf::from("src/ProfilePage.tsx"),
                profile_code.to_string(),
            ),
            (PathBuf::from("src/App.tsx"), app_code.to_string()),
        ],
        None,
    );

    assert_eq!(report.summary.total_diagnostics, 2);
    assert_eq!(report.summary.autofix_count, 1);
    assert_eq!(report.summary.refactor_count, 1);

    let html = render_html_report(&report);
    let score_text = format!("{}/100", report.summary.health_score);
    let autofix_desc = report.diagnostics[0]
        .autofix
        .as_ref()
        .map_or("", |f| f.description.as_str());

    assert_contains_all(
        &html,
        &[
            "<!DOCTYPE html>",
            "React Effect &amp; State Report",
            &score_text,
            "Autofix: 1",
            "Surgical: 0",
            "Refactor: 1",
            "no-derived-state",
            "Form",
            "no-reset-all-state-on-prop-change",
            "ProfilePage",
            &report.diagnostics[0].cascade_steps[0],
            "src/App.tsx",
            "App",
            "missing key={...}",
            "has key={...}",
            autofix_desc,
            "Root-Cause Groups (2)",
            "Blast Radius:",
            &report.root_cause_groups[0].id,
            report.root_cause_groups[0].blast_radius.tier.as_str(),
            &format!("score {}", report.root_cause_groups[0].blast_radius.score),
            "frequency: standard, fan-out:",
        ],
    );
    assert!(html.contains("<style>"));
    assert!(!html.contains("cdn.tailwindcss.com"));
}

#[test]
fn renders_clean_html_report_when_no_diagnostics_found() {
    let clean_code = r#"
        export function Greeting({ name }) {
          const message = 'Hello ' + name;
          return <div>{message}</div>;
        }
    "#;

    let report = analyze_project_sources(
        vec![(PathBuf::from("src/Greeting.tsx"), clean_code.to_string())],
        None,
    );

    assert_eq!(report.summary.total_diagnostics, 0);
    assert_eq!(report.summary.health_score, 100);

    let html = render_html_report(&report);
    assert!(html.contains("100/100"));
    assert!(html.contains("No unnecessary effects or state cascades detected."));
}

#[test]
fn writes_html_report_to_explicit_path_and_isolated_temp_dir() {
    let code = r#"
        export function Greeting() {
          const [msg, setMsg] = useState();
          useEffect(() => {
            setMsg("Hi");
          }, []);
          return <div>{msg}</div>;
        }
    "#;
    let report = analyze_project_sources(
        vec![(PathBuf::from("src/Greeting.tsx"), code.to_string())],
        None,
    );

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let explicit_dir = std::env::temp_dir().join(format!("dotore-html-test-{nanos}"));
    let explicit_file = explicit_dir.join("nested").join("custom-report.html");

    let written_explicit =
        write_and_open_html_report(&report, Some(&explicit_file), false).unwrap();
    assert_eq!(written_explicit, explicit_file);
    let explicit_contents = fs::read_to_string(&written_explicit).unwrap();
    assert!(explicit_contents.contains("no-initialize-state"));
    assert!(explicit_contents.contains("Greeting"));
    let _ = fs::remove_dir_all(&explicit_dir);

    let written_temp = write_and_open_html_report(&report, None, false).unwrap();
    assert!(written_temp.exists());
    assert_eq!(
        written_temp.file_name().and_then(|s| s.to_str()),
        Some("dotore-report.html")
    );
    let temp_contents = fs::read_to_string(&written_temp).unwrap();
    assert!(temp_contents.contains("no-initialize-state"));
    if let Some(parent) = written_temp.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn cli_report_generates_self_contained_html_report_without_opening_browser() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-cli-report-{nanos}"));
    fs::create_dir_all(&root).unwrap();

    let form_file = root.join("Form.tsx");
    fs::write(
        &form_file,
        r#"export function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <div>{fullName}</div>;
}
"#,
    )
    .unwrap();

    let out_html = root.join("out.html");
    let bin = env!("CARGO_BIN_EXE_dotore");

    let res = Command::new(bin)
        .args(["report", "--no-open", "--output"])
        .arg(&out_html)
        .arg(&root)
        .output()
        .unwrap();

    assert_eq!(
        res.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let stdout = String::from_utf8_lossy(&res.stdout);
    assert!(stdout.contains(&out_html.display().to_string()));

    let html = fs::read_to_string(&out_html).unwrap();
    assert!(html.contains("React Effect &amp; State Report"));
    assert!(html.contains("no-derived-state"));
    assert!(html.contains("Autofix: 1"));

    let _ = fs::remove_dir_all(&root);
}
