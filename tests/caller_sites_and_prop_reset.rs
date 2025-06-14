//! Parity tests for `no-reset-all-state-on-prop-change` and cross-file JSX `Caller Site` resolution.

use std::path::{Path, PathBuf};

use dotore::{
    JsonReport, PrescriptionTier, ResolvedCallerSite, RuleId, analyze_project_sources,
    analyze_source, format_terminal_report,
};

struct ValidCase {
    name: &'static str,
    code: &'static str,
}

struct InvalidCase {
    name: &'static str,
    code: &'static str,
    expected_id: &'static str,
    expected_prop: &'static str,
}

const NO_RESET_ALL_STATE_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Set state when a prop changes, but not to its default value",
        code: r###"
        function List({ items }) {
          const [selection, setSelection] = useState();

          useEffect(() => {
            setSelection(items[0]);
          }, [items]);
        }
      "###,
    },
    ValidCase {
        name: "Reset some state when a prop changes",
        code: r###"
        function ProfilePage({ userId }) {
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState('type something');
          const [catName, setCatName] = useState('Sparky');

          useEffect(() => {
            setUser(null);
            setComment('meow')
          }, [userId]);
        }
      "###,
    },
    ValidCase {
        name: "Undefined state initializer compared to state setter with literal null",
        code: r###"
        function List({ items }) {
          const [selectedItem, setSelectedItem] = useState();

          useEffect(() => {
            setSelectedItem(null);
          }, [items]);
        }
      "###,
    },
    ValidCase {
        name: "Reset all state when a prop changes inside lowercased function definition",
        code: r###"
        function buildComponent() {
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setComment('type something');
          }, [userId]);

          return <div>hi</div>;
        }
      "###,
    },
    ValidCase {
        name: "Reset all state when a prop changes in a custom hook",
        code: r###"
        function useCustomHook({ userId }) {
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setUser(null);
            setComment('type something');
          }, [userId]);
        }
      "###,
    },
    ValidCase {
        name: "Reset all state to derived initial state when a prop changes",
        code: r###"
        function ProfilePage({ userId }) {
          const initialState = 'meow meow'
          const [comment, setComment] = useState(initialState);

          useEffect(() => {
            const derivedInitialState = initialState + '!';
            setComment(derivedInitialState);
          }, [userId]);
        }
      "###,
    },
    ValidCase {
        name: "Set state differently in callback to state-like hook",
        code: r###"
        const Foo = () => {
          const [_0, setState] = useState(false);
          const [_1, startTransition] = useTransition();

          useEffect(() => {
            startTransition(() => {
              setState(true);
            });
          }, []);

          return null;
        };
      "###,
    },
];

const NO_RESET_ALL_STATE_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Reset all state when a prop changes",
        code: r###"
        function ProfilePage({ userId }) {
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setUser(null);
            setComment('type something');
          }, [userId]);
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "userId",
    },
    InvalidCase {
        name: "Reset all state when a prop changes in memoized component",
        code: r###"
        const ProfilePage = memo(({ userId }) => {
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setUser(null);
            setComment('type something');
          }, [userId]);
        })
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "userId",
    },
    InvalidCase {
        name: "Reset all state to shared var when a prop changes",
        code: r###"
        function ProfilePage({ userId }) {
          const initialState = 'meow meow'
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState(initialState);

          useEffect(() => {
            setUser(null);
            setComment(initialState);
          }, [userId]);
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "userId",
    },
    InvalidCase {
        name: "Reset all state when a prop member changes",
        code: r###"
        function ProfilePage({ user }) {
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setComment('type something');
          }, [user.id]);
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "user",
    },
    InvalidCase {
        name: "Reset all state when one of two props change",
        code: r###"
        function ProfilePage({ userId, friends }) {
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setComment('type something');
          }, [userId, friends]);
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "userId",
    },
    InvalidCase {
        name: "Undefined state initializer compared to state setter with literal undefined",
        code: r###"
        function List({ items }) {
          const [selectedItem, setSelectedItem] = useState();

          useEffect(() => {
            setSelectedItem(undefined);
          }, [items]);
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "items",
    },
    InvalidCase {
        name: "Reset all state to function call result when a prop changes",
        code: r###"
        function ProfilePage({ userId }) {
          const [comment, setComment] = useState(getInitialComment());

          useEffect(() => {
            setComment(getInitialComment());
          }, [userId]);
        }

        function getInitialComment() {
          return 'type something';
        }
      "###,
        expected_id: "avoidResettingAllStateWhenAPropChanges",
        expected_prop: "userId",
    },
];

#[test]
fn parity_no_reset_all_state_on_prop_change_valid() {
    for case in NO_RESET_ALL_STATE_VALID {
        let diags = analyze_source(
            Path::new("Test.tsx"),
            case.code,
            Some(&[RuleId::NoResetAllStateOnPropChange]),
        );
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for valid case [{}], got: {diags:#?}",
            case.name
        );
    }
}

#[test]
fn parity_no_reset_all_state_on_prop_change_invalid() {
    for case in NO_RESET_ALL_STATE_INVALID {
        let diags = analyze_source(
            Path::new("Test.tsx"),
            case.code,
            Some(&[RuleId::NoResetAllStateOnPropChange]),
        );
        assert_eq!(
            diags.len(),
            1,
            "Expected 1 diagnostic for invalid case [{}], got {}: {diags:#?}",
            case.name,
            diags.len()
        );
        assert_eq!(diags[0].rule, RuleId::NoResetAllStateOnPropChange);
        assert_eq!(diags[0].message_id, case.expected_id);
        assert_eq!(diags[0].target_name, case.expected_prop);
        assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    }
}

fn assert_caller_site(
    site: &ResolvedCallerSite,
    expected_file: &str,
    expected_parent: &str,
    expected_has_key: bool,
    expected_props: &[&str],
) {
    assert_eq!(site.caller_file, PathBuf::from(expected_file));
    assert_eq!(site.parent_subject_name.as_deref(), Some(expected_parent));
    assert_eq!(site.has_key, expected_has_key);
    let props: Vec<&str> = site.passed_props.iter().map(String::as_str).collect();
    assert_eq!(props, expected_props);
}

#[test]
fn resolves_cross_file_jsx_caller_sites_across_relative_alias_and_fallback_imports() {
    let profile_source = r#"export function ProfilePage({ userId }) {
        const [c, setC] = useState('');
        useEffect(() => { setC(''); }, [userId]);
        return <div>{userId}{c}</div>;
    }"#;
    let same_dir_caller = "import { ProfilePage } from './ProfilePage'; export function App({ activeUserId }) { return <ProfilePage userId={activeUserId} />; }";
    let parent_dir_caller = "import { ProfilePage } from '../components/ProfilePage'; export function UserRoute({ routeUserId }) { return <ProfilePage key={routeUserId} userId={routeUserId} />; }";
    let alias_caller = "import { ProfilePage } from '@/components/ProfilePage'; export function DashboardWidget({ widgetUserId }) { return <ProfilePage userId={widgetUserId} compact />; }";
    let fallback_caller = "export function LegacyShell({ legacyUserId }) { return <ProfilePage key=\"static-key\" userId={legacyUserId} />; }";

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/components/ProfilePage.tsx"),
                profile_source.to_string(),
            ),
            (
                PathBuf::from("src/components/App.tsx"),
                same_dir_caller.to_string(),
            ),
            (
                PathBuf::from("src/routes/UserRoute.tsx"),
                parent_dir_caller.to_string(),
            ),
            (
                PathBuf::from("src/features/DashboardWidget.tsx"),
                alias_caller.to_string(),
            ),
            (
                PathBuf::from("src/legacy/LegacyShell.tsx"),
                fallback_caller.to_string(),
            ),
        ],
        Some(&[RuleId::NoResetAllStateOnPropChange]),
    );
    assert_eq!(report.diagnostics.len(), 1);
    let callers = &report.diagnostics[0].caller_sites;

    assert_eq!(callers.len(), 4);
    assert_caller_site(
        &callers[0],
        "src/components/App.tsx",
        "App",
        false,
        &["userId"],
    );
    assert_caller_site(
        &callers[1],
        "src/features/DashboardWidget.tsx",
        "DashboardWidget",
        false,
        &["userId", "compact"],
    );
    assert_caller_site(
        &callers[2],
        "src/legacy/LegacyShell.tsx",
        "LegacyShell",
        true,
        &["userId"],
    );
    assert_caller_site(
        &callers[3],
        "src/routes/UserRoute.tsx",
        "UserRoute",
        true,
        &["userId"],
    );
}

#[test]
fn prop_reset_diagnostic_attaches_and_formats_cross_file_caller_sites() {
    let profile_code = r#"
        export function ProfilePage({ userId }) {
          const [user, setUser] = useState(null);
          const [comment, setComment] = useState('type something');

          useEffect(() => {
            setUser(null);
            setComment('type something');
          }, [userId]);

          return <div>{comment}</div>;
        }
    "#;
    let app_code = r#"
        import { ProfilePage } from './ProfilePage';

        export function App({ currentUserId }) {
          return <ProfilePage userId={currentUserId} />;
        }
    "#;
    let admin_code = r#"
        import { ProfilePage } from '../components/ProfilePage';

        export function AdminView({ selectedUserId }) {
          return <ProfilePage key={selectedUserId} userId={selectedUserId} />;
        }
    "#;

    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("src/components/ProfilePage.tsx"),
                profile_code.to_string(),
            ),
            (
                PathBuf::from("src/components/App.tsx"),
                app_code.to_string(),
            ),
            (
                PathBuf::from("src/admin/AdminView.tsx"),
                admin_code.to_string(),
            ),
        ],
        Some(&[RuleId::NoResetAllStateOnPropChange]),
    );

    assert_eq!(report.summary.total_diagnostics, 1);
    assert_eq!(report.summary.refactor_count, 1);

    let diag = &report.diagnostics[0];
    assert_eq!(diag.rule, RuleId::NoResetAllStateOnPropChange);
    assert_eq!(diag.subject_name.as_deref(), Some("ProfilePage"));
    assert_eq!(diag.target_name, "userId");
    assert_eq!(diag.caller_sites.len(), 2);
    assert_caller_site(
        &diag.caller_sites[0],
        "src/admin/AdminView.tsx",
        "AdminView",
        true,
        &["userId"],
    );
    assert_caller_site(
        &diag.caller_sites[1],
        "src/components/App.tsx",
        "App",
        false,
        &["userId"],
    );

    assert_caller_report_outputs(&report);
}

fn assert_caller_report_outputs(report: &JsonReport) {
    let terminal = format_terminal_report(report);
    assert!(terminal.contains("[no-reset-all-state-on-prop-change] (refactor)"));
    assert!(
        terminal.contains("src/admin/AdminView.tsx:5:18 in `AdminView` (<ProfilePage /> has key")
    );
    assert!(
        terminal
            .contains("src/components/App.tsx:5:18 in `App` (<ProfilePage /> missing key={...})")
    );

    let json = serde_json::to_string_pretty(report).unwrap_or_default();
    assert!(json.contains("\"caller_sites\""));
    assert!(json.contains("\"has_key\": true"));
    assert!(json.contains("\"has_key\": false"));
    assert!(json.contains("\"parent_subject_name\": \"AdminView\""));
    assert!(json.contains("\"parent_subject_name\": \"App\""));
}
