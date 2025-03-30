//! Integration tests for deterministic Rust auto-fixes (`src/fixer.rs` and `dotore fix`).

use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{PrescriptionTier, RuleId, analyze_source, apply_patches_to_source};

#[test]
fn autofixes_derived_state_and_reanalyzes_clean() {
    let source = r#"import { useState, useEffect } from 'react';

function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <div>{fullName}</div>;
}
"#;

    let diags = analyze_source(Path::new("Form.tsx"), source, None);
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::NoDerivedState);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);

    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten.contains("const fullName = firstName + ' ' + lastName;"));
    assert!(!rewritten.contains("useState("));
    assert!(!rewritten.contains("useEffect("));

    let reanalyzed = analyze_source(Path::new("Form.tsx"), &rewritten, None);
    assert!(
        reanalyzed.is_empty(),
        "Re-analyzing rewritten source must produce 0 diagnostics, got: {reanalyzed:?}"
    );
}

#[test]
fn autofixes_initialize_state_and_reanalyzes_clean() {
    let source = r#"import { useState, useEffect } from 'react';

function Greeting() {
  const [message, setMessage] = useState();
  useEffect(() => {
    setMessage("Hello world");
  }, []);
  return <div>{message}</div>;
}
"#;

    let diags = analyze_source(Path::new("Greeting.tsx"), source, None);
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::NoInitializeState);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);

    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 1);
    assert!(rewritten.contains("const [message, setMessage] = useState(\"Hello world\");"));
    assert!(!rewritten.contains("useEffect("));

    let reanalyzed = analyze_source(Path::new("Greeting.tsx"), &rewritten, None);
    assert!(
        reanalyzed.is_empty(),
        "Re-analyzing rewritten source must produce 0 diagnostics, got: {reanalyzed:?}"
    );
}

#[test]
fn autofixes_multiple_diagnostics_in_reverse_offset_order() {
    let source = r#"import { useState, useEffect } from 'react';

function Profile({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  const [greeting, setGreeting] = useState();
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  useEffect(() => {
    setGreeting("Welcome");
  }, []);
  return <div>{greeting}, {fullName}</div>;
}
"#;

    let diags = analyze_source(Path::new("Profile.tsx"), source, None);
    assert_eq!(diags.len(), 2);
    assert!(diags.iter().all(|d| d.tier == PrescriptionTier::Autofix));

    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert_eq!(descriptions.len(), 2);
    assert!(rewritten.contains("const fullName = firstName + ' ' + lastName;"));
    assert!(rewritten.contains("const [greeting, setGreeting] = useState(\"Welcome\");"));
    assert!(!rewritten.contains("useEffect("));

    let reanalyzed = analyze_source(Path::new("Profile.tsx"), &rewritten, None);
    assert!(reanalyzed.is_empty());
}

fn assert_surgical_untouched(file_name: &str, source: &str) {
    let diags = analyze_source(Path::new(file_name), source, None);
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    let (rewritten, descriptions) = apply_patches_to_source(source, &diags);
    assert!(descriptions.is_empty());
    assert_eq!(rewritten, source);
}

#[test]
fn downgrades_unsafe_cases_to_surgical_and_leaves_source_untouched() {
    let handler_call = r#"
function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <button onClick={() => setFullName('Override')}>{fullName}</button>;
}
"#;
    assert_surgical_untouched("Form.tsx", handler_call);

    let escaped_setter = r#"
function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <Child onUpdate={setFullName} value={fullName} />;
}
"#;
    assert_surgical_untouched("Form.tsx", escaped_setter);

    let updater_callback = r#"
function Counter({ step }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    setCount(prev => prev + step);
  }, [step]);
  return <div>{count}</div>;
}
"#;
    assert_surgical_untouched("Counter.tsx", updater_callback);

    let shared_effect_statements = r#"
function Greeting() {
  const [message, setMessage] = useState();
  useEffect(() => {
    console.log("mounting");
    setMessage("Hello");
  }, []);
  return <div>{message}</div>;
}
"#;
    assert_surgical_untouched("Greeting.tsx", shared_effect_statements);
}

#[test]
fn cli_fix_and_dry_run_apply_patches_correctly() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-fix-test-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Form.tsx");
    let original = r#"function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <div>{fullName}</div>;
}
"#;
    fs::write(&file_path, original).unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");

    // 1. `--dry-run` prints planned patches without modifying disk
    let dry_out = Command::new(bin)
        .args(["fix", "--dry-run"])
        .arg(&file_path)
        .output()
        .unwrap();
    assert_eq!(dry_out.status.code(), Some(0));
    let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
    assert!(dry_stdout.contains("[dry-run]"));
    assert!(dry_stdout.contains("const fullName = firstName + ' ' + lastName;"));
    assert_eq!(fs::read_to_string(&file_path).unwrap(), original);

    // 2. `dotore fix` writes the updated file to disk and prints summary
    let fix_out = Command::new(bin)
        .arg("fix")
        .arg(&file_path)
        .output()
        .unwrap();
    assert_eq!(fix_out.status.code(), Some(0));
    let fix_stdout = String::from_utf8_lossy(&fix_out.stdout);
    assert!(fix_stdout.contains("[fixed]"));
    assert!(fix_stdout.contains("Applied 1 autofix(es) across 1 file(s)."));

    let updated = fs::read_to_string(&file_path).unwrap();
    assert!(updated.contains("const fullName = firstName + ' ' + lastName;"));
    assert!(!updated.contains("useEffect("));

    // 3. Re-running `dotore check` on the fixed file exits 0
    let check_out = Command::new(bin)
        .arg("check")
        .arg(&file_path)
        .output()
        .unwrap();
    assert_eq!(check_out.status.code(), Some(0));

    let _ = fs::remove_dir_all(&root);
}
