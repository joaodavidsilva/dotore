//! Parity and cascade tests for `no-chain-state-updates` (single-effect and multi-effect
//! **Render Cascades**), `no-event-handler` (`Surgical` state guards and `Refactor` prop guards),
//! and `no-adjust-state-on-prop-change`.

use std::path::Path;

use dotore::{PrescriptionTier, RuleId, analyze_source};

struct ValidCase {
    name: &'static str,
    code: &'static str,
}

struct InvalidCase {
    name: &'static str,
    code: &'static str,
    expected_count: usize,
    expected_ids: &'static [&'static str],
    expected_targets: &'static [&'static str],
}

fn run_valid_suite(rule: RuleId, cases: &[ValidCase]) {
    for case in cases {
        let diags = analyze_source(Path::new("Test.tsx"), case.code, Some(&[rule]));
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for valid case [{}] under {rule:?}, got: {diags:#?}",
            case.name
        );
    }
}

fn run_invalid_suite(rule: RuleId, cases: &[InvalidCase]) {
    for case in cases {
        let diags = analyze_source(Path::new("Test.tsx"), case.code, Some(&[rule]));
        assert_eq!(
            diags.len(),
            case.expected_count,
            "Expected {} diagnostic(s) for invalid case [{}] under {rule:?}, got {}: {diags:#?}",
            case.expected_count,
            case.name,
            diags.len()
        );
        for (idx, &expected_id) in case.expected_ids.iter().enumerate() {
            assert_eq!(
                diags[idx].message_id, expected_id,
                "Case [{}] diagnostic #{idx} message_id mismatch",
                case.name
            );
        }
        for (idx, &expected_target) in case.expected_targets.iter().enumerate() {
            assert_eq!(
                diags[idx].target_name, expected_target,
                "Case [{}] diagnostic #{idx} target_name mismatch",
                case.name
            );
        }
    }
}

const NO_CHAIN_STATE_UPDATES_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Set state to literal when props change",
        code: r###"
        function List({ items }) {
          const [selection, setSelection] = useState();

          useEffect(() => {
            setSelection(null);
          }, [items]);
        }
      "###,
    },
    ValidCase {
        name: "Set state to derived internal state when internal state changes",
        code: r###"
        function Counter() {
          const [count, setCount] = useState(0);
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => {
            setDoubleCount(count * 2);
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "Set state to literal when external state changes",
        code: r###"
        function Feed() {
          const { data: posts } = useQuery('/posts');
          const [scrollPosition, setScrollPosition] = useState(0);

          useEffect(() => {
            setScrollPosition(0);
          }, [posts]);
        }
      "###,
    },
    ValidCase {
        name: "Synchronize internal state with literal",
        code: r###"
        function Component() {
          const [isMounted, setIsMounted] = useState(false);

          useEffect(() => {
            setIsMounted(true);
            return () => setIsMounted(false);
          }, [setIsMounted]);
        }
      "###,
    },
    ValidCase {
        name: "Set state to internal plus external state",
        code: r###"
        function Game() {
          const [round, setRound] = useState(1);
          const [isGameOver, setIsGameOver] = useState(false);
          const { data: players } = useQuery('/players');

          useEffect(() => {
            setIsGameOver(round > 10 || players.length === 0);
          }, [round, players]);
        }
      "###,
    },
    ValidCase {
        name: "JSON.stringifying internal state in deps",
        code: r###"
        function Feed() {
          const [posts, setPosts] = useState([]);
          const [scrollPosition, setScrollPosition] = useState(0);

          useEffect(() => {
            setScrollPosition(0);
          }, [JSON.stringify(posts)]);
        }
      "###,
    },
];

const NO_CHAIN_STATE_UPDATES_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Set state to literal when internal state changes",
        code: r###"
        function Game() {
          const [round, setRound] = useState(1);
          const [isGameOver, setIsGameOver] = useState(false);

          useEffect(() => {
            if (round > 10) {
              setIsGameOver(true);
            }
          }, [round]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidChainingStateUpdates"],
        expected_targets: &["isGameOver"],
    },
    InvalidCase {
        name: "Set state to derived literal when internal state changes",
        code: r###"
        function Game() {
          const [round, setRound] = useState(1);
          const [isGameOver, setIsGameOver] = useState(false);

          useEffect(() => {
            if (round > 10) {
              const finalRound = true;
              setIsGameOver(finalRound);
            }
          }, [round]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidChainingStateUpdates"],
        expected_targets: &["isGameOver"],
    },
    InvalidCase {
        name: "Set state to literal when internal or external state changes",
        code: r###"
        function Game() {
          const [round, setRound] = useState(1);
          const [isGameOver, setIsGameOver] = useState(false);
          const { data: players } = useQuery('/players');

          useEffect(() => {
            if (round > 10 || players.length === 0) {
              setIsGameOver(true);
            }
          }, [round, players]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidChainingStateUpdates"],
        expected_targets: &["isGameOver"],
    },
    InvalidCase {
        name: "Set state to external state when internal state changes",
        code: r###"
        function Game() {
          const [round, setRound] = useState(1);
          const [isGameOver, setIsGameOver] = useState(false);
          const { data: players } = useQuery('/players');

          useEffect(() => {
            if (round > 10) {
              setIsGameOver(players.length === 0);
            }
          }, [round, players]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidChainingStateUpdates"],
        expected_targets: &["isGameOver"],
    },
    InvalidCase {
        name: "In an otherwise valid effect",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();
          const [otherState, setOtherState] = useState('Meow');

          useEffect(() => {
            console.log('Meow');
            setState('Hello World');
          }, [otherState]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidChainingStateUpdates"],
        expected_targets: &["state"],
    },
];

const NO_EVENT_HANDLER_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Synchronizing with external system",
        code: r###"
        function Search() {
          const [query, setQuery] = useState();
          const [results, setResults] = useState();

          useEffect(() => {
            fetch('/search?query=' + query).then((data) => {
              setResults(data);
            });
          }, [query]);

          return (
            <div>
              <input
                name="query"
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <ul>
                {results.map((result) => (
                  <li key={result.id}>{result.title}</li>
                ))}
              </ul>
            </div>
          )
        }
      "###,
    },
    ValidCase {
        name: "Respond to prop passed to fn",
        code: r###"
        import { useEffect } from 'react'

        // Captures an optional URL search param and persists it to localStorage + cookie.
        // First-touch attribution: never overwrites an existing code.
        export function useSaveReferralCode(refCode) {
          useEffect(() => {
            const valid = validateReferralCode(refCode)
            if (valid) saveReferredByCode(valid)
          }, [refCode])
        }
      "###,
    },
];

const NO_EVENT_HANDLER_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Using props to handle an event and call an external function",
        code: r###"
        function Form({ dataToSubmit }) {
          useEffect(() => {
            if (dataToSubmit) {
              submitData(dataToSubmit);
            }
          }, [dataToSubmit]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidPropHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Using state to handle an event and call an external function",
        code: r###"
        function Form() {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit) {
              submitData(dataToSubmit);
            }
          }, [dataToSubmit]);

          return (
            <div>
              <input
                name="name"
                type="text"
                onChange={(e) => setName(e.target.value)}
              />
              <button onClick={() => setDataToSubmit({ name })}>Submit</button>
            </div>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Using state to handle an event, no deps argument",
        code: r###"
        function Form() {
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit) {
              submitData(dataToSubmit);
            }
          });

          return (
            <button onClick={() => setDataToSubmit({ name: 'test' })}>Submit</button>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Using state to handle an event, empty deps",
        code: r###"
        function Form() {
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit) {
              submitData(dataToSubmit);
            }
          }, []);

          return (
            <button onClick={() => setDataToSubmit({ name: 'test' })}>Submit</button>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Using state to handle an event and call a prop",
        code: r###"
        function Form({ submitData }) {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit) {
              submitData(dataToSubmit);
            }
          }, [dataToSubmit]);

          return (
            <div>
              <input
                name="name"
                type="text"
                onChange={(e) => setName(e.target.value)}
              />
              <button onClick={() => setDataToSubmit({ name })}>Submit</button>
            </div>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Early return in if test",
        code: r###"
        function Form() {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (!dataToSubmit) return;

            submitData(dataToSubmit);
          }, [dataToSubmit]);

          return (
            <div>
              <input
                name="name"
                type="text"
                onChange={(e) => setName(e.target.value)}
              />
              <button onClick={() => setDataToSubmit({ name })}>Submit</button>
            </div>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Member access and double test in condition",
        code: r###"
        function Form() {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit.name && dataToSubmit.name.length > 0) {
              submitData(dataToSubmit);
            }
          }, [dataToSubmit]);

          return (
            <div>
              <input
                name="name"
                type="text"
                onChange={(e) => setName(e.target.value)}
              />
              <button onClick={() => setDataToSubmit({ name })}>Submit</button>
            </div>
          )
        }
      "###,
        expected_count: 2,
        expected_ids: &["avoidEventHandler", "avoidEventHandler"],
        expected_targets: &["dataToSubmit", "dataToSubmit"],
    },
    InvalidCase {
        name: "Derived prop in multiple if tests",
        code: r###"
        import { useEffect } from "react";

        function Form({ value }) {
          const derived = value + 2;

          useEffect(() => {
            if (derived === "a") return;
            if (derived === "b") return;
          }, [derived]);
        }
      "###,
        expected_count: 2,
        expected_ids: &["avoidPropHandler", "avoidPropHandler"],
        expected_targets: &["derived", "derived"],
    },
    InvalidCase {
        name: "If test includes non-state",
        code: r###"
        function Form() {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (dataToSubmit && Date.now() % 2 === 0) {
              submitData(dataToSubmit);
            }
          }, [dataToSubmit]);

          return (
            <div>
              <input
                name="name"
                type="text"
                onChange={(e) => setName(e.target.value)}
              />
              <button onClick={() => setDataToSubmit({ name })}>Submit</button>
            </div>
          )
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidEventHandler"],
        expected_targets: &["dataToSubmit"],
    },
];

const NO_ADJUST_STATE_ON_PROP_CHANGE_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Adjusting state directly during render",
        code: r###"
        function List({ items }) {
          const [isReverse, setIsReverse] = useState(false);
          const [selection, setSelection] = useState(null);

          const [prevItems, setPrevItems] = useState(items);
          if (items !== prevItems) {
            setPrevItems(items);
            setSelection(null);
          }
        }
      "###,
    },
    ValidCase {
        name: "Set state to literal when internal state changes",
        code: r###"
        function Counter() {
          const [count, setCount] = useState(0);
          const [otherState, setOtherState] = useState();

          useEffect(() => {
            setOtherState('Hello World');
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "Set state to a value derived from props",
        code: r###"
        function Counter({ count }) {
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => {
            setDoubleCount(count * 2);
          }, [count]);
        }
      "###,
    },
];

const NO_ADJUST_STATE_ON_PROP_CHANGE_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Set state to literal when prop changes",
        code: r###"
        function List({ items }) {
          const [selection, setSelection] = useState();

          useEffect(() => {
            setSelection(null);
          }, [items]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidAdjustingStateWhenAPropChanges"],
        expected_targets: &["selection"],
    },
    InvalidCase {
        name: "Set state to internal state when prop changes",
        code: r###"
        function List({ items }) {
          const [selection, setSelection] = useState();
          const [internalData, setInternalData] = useState();

          useEffect(() => {
            setSelection(internalData);
          }, [items, internalData]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidAdjustingStateWhenAPropChanges"],
        expected_targets: &["selection"],
    },
    InvalidCase {
        name: "Set state to external state when prop changes",
        code: r###"
        function List({ items }) {
          const [selection, setSelection] = useState();
          const { data: externalData } = useDataSource();

          useEffect(() => {
            setSelection(externalData);
          }, [items]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidAdjustingStateWhenAPropChanges"],
        expected_targets: &["selection"],
    },
    InvalidCase {
        name: "Conditionally set state to literal when prop changes",
        code: r###"
        function Form({ result }) {
          const [error, setError] = useState();

          useEffect(() => {
            if (result.data) {
              setError(null);
            }
          }, [result]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidAdjustingStateWhenAPropChanges"],
        expected_targets: &["error"],
    },
    InvalidCase {
        name: "Set state to literal when two props change",
        code: r###"
        function List({ items, user }) {
          const [selection, setSelection] = useState();

          useEffect(() => {
            setSelection(null);
          }, [items, user]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidAdjustingStateWhenAPropChanges"],
        expected_targets: &["selection"],
    },
];

#[test]
fn parity_no_chain_state_updates_valid() {
    run_valid_suite(RuleId::NoChainStateUpdates, NO_CHAIN_STATE_UPDATES_VALID);
}

#[test]
fn parity_no_chain_state_updates_invalid() {
    run_invalid_suite(RuleId::NoChainStateUpdates, NO_CHAIN_STATE_UPDATES_INVALID);
}

#[test]
fn parity_no_event_handler_valid() {
    run_valid_suite(RuleId::NoEventHandler, NO_EVENT_HANDLER_VALID);
}

#[test]
fn parity_no_event_handler_invalid() {
    run_invalid_suite(RuleId::NoEventHandler, NO_EVENT_HANDLER_INVALID);
}

#[test]
fn event_handler_distinguishes_surgical_state_from_refactor_prop_and_locs() {
    let prop_code = NO_EVENT_HANDLER_INVALID[0].code;
    let prop_diags = analyze_source(
        Path::new("Form.tsx"),
        prop_code,
        Some(&[RuleId::NoEventHandler]),
    );
    assert_eq!(prop_diags.len(), 1);
    assert_eq!(prop_diags[0].tier, PrescriptionTier::Refactor);
    assert_eq!(prop_diags[0].message_id, "avoidPropHandler");

    let state_code = NO_EVENT_HANDLER_INVALID[1].code;
    let state_diags = analyze_source(
        Path::new("Form.tsx"),
        state_code,
        Some(&[RuleId::NoEventHandler]),
    );
    assert_eq!(state_diags.len(), 1);
    assert_eq!(state_diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(state_diags[0].message_id, "avoidEventHandler");

    let double_test_code = NO_EVENT_HANDLER_INVALID[6].code;
    let double_diags = analyze_source(
        Path::new("Form.tsx"),
        double_test_code,
        Some(&[RuleId::NoEventHandler]),
    );
    assert_eq!(double_diags.len(), 2);
    assert_eq!(double_diags[0].loc.line, 7);
    assert_eq!(double_diags[0].loc.column, 17);
    assert_eq!(double_diags[1].loc.line, 7);
    assert_eq!(double_diags[1].loc.column, 38);

    let derived_prop_code = NO_EVENT_HANDLER_INVALID[7].code;
    let derived_diags = analyze_source(
        Path::new("Form.tsx"),
        derived_prop_code,
        Some(&[RuleId::NoEventHandler]),
    );
    assert_eq!(derived_diags.len(), 2);
    assert_eq!(derived_diags[0].loc.line, 8);
    assert_eq!(derived_diags[1].loc.line, 9);
}

#[test]
fn parity_no_adjust_state_on_prop_change_valid() {
    run_valid_suite(
        RuleId::NoAdjustStateOnPropChange,
        NO_ADJUST_STATE_ON_PROP_CHANGE_VALID,
    );
}

#[test]
fn parity_no_adjust_state_on_prop_change_invalid() {
    run_invalid_suite(
        RuleId::NoAdjustStateOnPropChange,
        NO_ADJUST_STATE_ON_PROP_CHANGE_INVALID,
    );

    let two_props_code = NO_ADJUST_STATE_ON_PROP_CHANGE_INVALID[4].code;
    let diags = analyze_source(
        Path::new("List.tsx"),
        two_props_code,
        Some(&[RuleId::NoAdjustStateOnPropChange]),
    );
    assert_eq!(diags.len(), 1);
    assert!(
        diags[0].message.contains("\"items\" and \"user\""),
        "Expected message to mention '\"items\" and \"user\"', got: {}",
        diags[0].message
    );
}

#[test]
fn detects_multi_effect_render_cascades_across_subject() {
    let code = r#"
        function CheckoutWizard({ cartItems }) {
          const [rawTotal, setRawTotal] = useState(0);
          const [discountTier, setDiscountTier] = useState('none');
          const [isFreeShipping, setIsFreeShipping] = useState(false);

          useEffect(() => {
            if (rawTotal > 100) {
              setDiscountTier('gold');
            }
          }, [rawTotal]);

          useEffect(() => {
            if (discountTier === 'gold') {
              setIsFreeShipping(true);
            }
          }, [discountTier]);

          return <div>{isFreeShipping ? 'Free' : 'Paid'}</div>;
        }
    "#;

    let diags = analyze_source(
        Path::new("CheckoutWizard.tsx"),
        code,
        Some(&[RuleId::NoChainStateUpdates]),
    );
    assert_eq!(diags.len(), 2);
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    assert_eq!(diags[0].target_name, "discountTier");
    assert_eq!(diags[1].tier, PrescriptionTier::Refactor);
    assert_eq!(diags[1].target_name, "isFreeShipping");
    let joined_steps = diags[1].cascade_steps.join(" -> ");
    assert!(
        joined_steps.contains("Effect #1")
            && joined_steps.contains("discountTier")
            && joined_steps.contains("Effect #2")
            && joined_steps.contains("isFreeShipping"),
        "Expected full multi-effect cascade path, got: {joined_steps}"
    );
}

#[test]
fn ignores_independent_effects_and_formats_three_props() {
    let independent_code = r#"
        function Dashboard() {
          const [a, setA] = useState(0);
          const [b, setB] = useState(0);
          const [c, setC] = useState(0);

          useEffect(() => {
            setB(1);
          }, [a]);

          useEffect(() => {
            setC(2);
          }, [a]);
        }
    "#;
    let ind_diags = analyze_source(
        Path::new("Dashboard.tsx"),
        independent_code,
        Some(&[RuleId::NoChainStateUpdates]),
    );
    assert_eq!(ind_diags.len(), 2);
    assert!(
        ind_diags
            .iter()
            .all(|d| !d.cascade_steps.iter().any(|s| s.contains("Effect #1")))
    );

    let three_props_code = r#"
        function List({ items, user, filter }) {
          const [selection, setSelection] = useState();

          useEffect(() => {
            setSelection(null);
          }, [items, user, filter]);
        }
    "#;
    let diags = analyze_source(
        Path::new("List.tsx"),
        three_props_code,
        Some(&[RuleId::NoAdjustStateOnPropChange]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    assert!(
        diags[0]
            .message
            .contains("\"items\", \"user\", and \"filter\""),
        "Expected message to mention three props, got: {}",
        diags[0].message
    );
}
