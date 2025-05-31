//! Parity and feature tests for `no-pass-live-state-to-parent`, `no-pass-data-to-parent`,
//! `no-external-store-subscription`, `no-fetch-in-effect`, and the 18 real-world valid cases.

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
            if !expected_id.is_empty() {
                assert_eq!(
                    diags[idx].message_id, expected_id,
                    "Case [{}] diagnostic #{idx} message_id mismatch",
                    case.name
                );
            }
        }
        for (idx, &expected_target) in case.expected_targets.iter().enumerate() {
            if !expected_target.is_empty() {
                assert_eq!(
                    diags[idx].target_name, expected_target,
                    "Case [{}] diagnostic #{idx} target_name mismatch",
                    case.name
                );
            }
        }
    }
}

const NO_PASS_LIVE_STATE_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Pass literal value to prop callback",
        code: r#"
        const Child = ({ onTextChanged }) => {
          useEffect(() => {
            onTextChanged("Hello World");
          }, [onTextChanged]);
        }
      "#,
    },
    ValidCase {
        name: "Pass live external state",
        code: r#"
        const Child = ({ onFetched }) => {
          const data = useSomeAPI();

          useEffect(() => {
            onFetched(data);
          }, [onFetched, data]);
        }
      "#,
    },
    ValidCase {
        name: "Pass prop to parent",
        code: r#"
        const Child = ({ text, onTextChanged }) => {
          useEffect(() => {
            onTextChanged(text);
          }, [text, onTextChanged]);
        }
      "#,
    },
    ValidCase {
        name: "No-arg prop callback",
        code: r#"
        function Form({ onClose }) {
          const [name, setName] = useState();
          const [isOpen, setIsOpen] = useState(true);

          useEffect(() => {
            if (!isOpen) {
              onClose();
            }
          }, [isOpen]);

          return (
            <button onClick={() => setIsOpen(false)}>Close</button>
          )
        }
      "#,
    },
    ValidCase {
        name: "Prop getter",
        code: r#"
        function Child({ getData }) {
          useEffect(() => {
            console.log(getData());
          }, [getData]);
        }
      "#,
    },
    ValidCase {
        name: "Pass internal state to HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = withRouter(({ history }) => {
          const [option, setOption] = useState();

          useEffect(() => {
            history.push(option);
          }, [option]);
        });
      "#,
    },
    ValidCase {
        name: "Pass internal state to weird HOC prop",
        code: r#"
        const MyComponent = inject('ourStore')(observer(({ ourStore }) => {
          const [option, setOption] = useState();

          useEffect(() => {
            ourStore.push(option);
          }, [option]);
        }));
      "#,
    },
    ValidCase {
        name: "Pass internal state to separately-wrapped HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = ({ history }) => {
          const [option, setOption] = useState();

          useEffect(() => {
            history.push(option);
          }, [option]);
        };

        const wrapped = withRouter(MyComponent);
      "#,
    },
    ValidCase {
        name: "Pass internal state to weirdly-separately-wrapped HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = ({ history }) => {
          const [option, setOption] = useState();

          useEffect(() => {
            history.push(option);
          }, [option]);
        };

        const EnhancedComponent = inject('ourStore')(observer(MyComponent))
        export default EnhancedComponent
      "#,
    },
    ValidCase {
        name: "Pass external state to HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = withRouter(({ history }) => {
          const data = useSomeAPI();

          useEffect(() => {
            if (data.error) {
              history.push(data.error);
            }
          }, [data]);
        });
      "#,
    },
    ValidCase {
        name: "Pass ref to parent",
        code: r#"
        const Child = ({ onRef }) => {
          const ref = useRef();

          useEffect(() => {
            onRef(ref.current);
          }, [onRef, ref.current]);

          return <div ref={ref}>Child</div>;
        }
      "#,
    },
];

const NO_PASS_LIVE_STATE_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Pass live internal state",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            onTextChanged(text);
          }, [onTextChanged, text]);

          return (
            <input
              type="text"
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live internal state, no deps argument",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            onTextChanged(text);
          });

          return (
            <input
              type="text"
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live internal state, empty deps",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            onTextChanged(text);
          }, []);

          return (
            <input
              type="text"
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live derived internal state in custom hook",
        code: r#"
        const useCustomHook = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            onTextChanged(text);
          }, [onTextChanged, text]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInHook"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live internal state AND external state",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();
          const data = useSomeAPI();

          useEffect(() => {
            onTextChanged(text, data);
          }, [onTextChanged, text, data]);

          return (
            <input
              type="text"
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live derived internal state",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            const firstChar = text[0];
            onTextChanged(firstChar);
          }, [onTextChanged, text]);

          return (
            <input
              type="text"
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text"],
    },
    InvalidCase {
        name: "Pass live internal state via derived prop",
        code: r#"
        const Child = ({ onFetched }) => {
          const [data, setData] = useState();
          const onFetchedWrapper = (v) => onFetched(v);

          useEffect(() => {
            onFetchedWrapper(data);
          }, [onFetched, data]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["data"],
    },
    InvalidCase {
        name: "Pass live internal state via later-destructured prop",
        code: r#"
        const Child = (props) => {
          const [data, setData] = useState();
          const { onFetched } = props;

          useEffect(() => {
            onFetched(data);
          }, [onFetched, data]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["data"],
    },
    InvalidCase {
        name: "Pass final internal state",
        code: r#"
        function Form({ onSubmit }) {
          const [name, setName] = useState();
          const [dataToSubmit, setDataToSubmit] = useState();

          useEffect(() => {
            if (!dataToSubmit) return;

            onSubmit(dataToSubmit);
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
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["dataToSubmit"],
    },
    InvalidCase {
        name: "Pass multiple live internal state",
        code: r#"
        const Child = ({ onChanged }) => {
          const [text, setText] = useState();
          const [count, setCount] = useState(0);

          useEffect(() => {
            onChanged(text, count);
          }, [onChanged, text, count]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingLiveStateToParentInComponent"],
        expected_targets: &["text, count"],
    },
];

#[test]
fn parity_no_pass_live_state_to_parent_valid() {
    run_valid_suite(RuleId::NoPassLiveStateToParent, NO_PASS_LIVE_STATE_VALID);
}

#[test]
fn parity_no_pass_live_state_to_parent_invalid() {
    run_invalid_suite(RuleId::NoPassLiveStateToParent, NO_PASS_LIVE_STATE_INVALID);
    let diags = analyze_source(
        Path::new("Test.tsx"),
        NO_PASS_LIVE_STATE_INVALID[0].code,
        Some(&[RuleId::NoPassLiveStateToParent]),
    );
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
}

const NO_PASS_DATA_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Pass literal value",
        code: r#"
        const Child = ({ onTextChanged }) => {
          useEffect(() => {
            onTextChanged("Hello World");
          }, [onTextChanged]);
        }
      "#,
    },
    ValidCase {
        name: "Pass derived literal value",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const hello = "Hello";
          const world = "World";
          const greeting = hello + " " + world;
          useEffect(() => {
            onTextChanged(greeting);
          }, [onTextChanged]);
        }
      "#,
    },
    ValidCase {
        name: "Pass internal state",
        code: r#"
        const Child = ({ onTextChanged }) => {
          const [text, setText] = useState();

          useEffect(() => {
            onTextChanged(text);
          }, [onTextChanged, text]);

          return (
            <input
              type="text"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
    },
    ValidCase {
        name: "Pass prop",
        code: r#"
        const Child = ({ text, onTextChanged }) => {
          useEffect(() => {
            onTextChanged(text);
          }, [onTextChanged, text]);

          return (
            <input
              type="text"
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          );
        }
      "#,
    },
    ValidCase {
        name: "No-arg prop callback",
        code: r#"
        function Form({ onClose }) {
          const [name, setName] = useState();
          const [isOpen, setIsOpen] = useState(true);

          useEffect(() => {
            if (!isOpen) {
              onClose();
            }
          }, [isOpen]);

          return (
            <button onClick={() => setIsOpen(false)}>Close</button>
          )
        }
      "#,
    },
    ValidCase {
        name: "Prop getter",
        code: r#"
        function Child({ getData }) {
          useEffect(() => {
            console.log(getData());
          }, [getData]);
        }
      "#,
    },
    ValidCase {
        name: "Pass internal state to HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = withRouter(({ history }) => {
          const [option, setOption] = useState();

          useEffect(() => {
            history.push(option);
          }, [option]);
        });
      "#,
    },
    ValidCase {
        name: "Pass external state to HOC prop",
        code: r#"
        import { withRouter } from 'react-router-dom';

        const MyComponent = withRouter(({ history }) => {
          const data = useSomeAPI();

          useEffect(() => {
            if (data.error) {
              history.push('/error');
            }
          }, [data]);
        });
      "#,
    },
    ValidCase {
        name: "Pass ref to parent",
        code: r#"
        const Child = ({ onRef }) => {
          const ref = useRef();

          useEffect(() => {
            onRef(ref.current);
          }, [onRef, ref.current]);
        }
      "#,
    },
    ValidCase {
        name: "Pass cleanup function that depends on ref",
        code: r#"
        import { dropTargetForElements } from "@atlaskit/pragmatic-drag-and-drop/element/adapter";

        function DeleteDropTarget({ onDelete }) {
          const ref = React.useRef(null);

          React.useEffect(() => {
            const element = ref.current;
            if (!element) {
              return;
            }

            const cleanup = dropTargetForElements({
              element,
              onDrop: ({ source }) => {
                onDelete(source.data);
              },
            });

            return cleanup;
          }, [onDelete]);

          return <div ref={ref}>Drop an item here to delete</div>;
        };
      "#,
    },
    ValidCase {
        name: "Effect inside custom hook returns MemberExpression cleanup",
        code: r#"
        function useActorLogger(actorRef) {
          useEffect(() => {
            return actorRef.system.inspect((next) => {
              if (next.type === '@xstate.snapshot') {
                console.log('ACTOR SNAPSHOT', next.snapshot);
              }
            }).unsubscribe;
          }, [actorRef]);
        }
      "#,
    },
    ValidCase {
        name: "Register callback on own ref to pass data to parent",
        code: r#"
        const Child = ({ onClicked }) => {
          const ref = useRef();

          useEffect(() => {
            ref.current.addEventListener('click', (event) => {
              onClicked(event);
            });
          }, [onClicked, ref]);
        }
      "#,
    },
    ValidCase {
        name: "Register external callback on ref prop",
        code: r#"
        const Child = ({ ref }) => {
          useEffect(() => {
            ref.current.addEventListener('click', (event) => {
              console.log('Clicked', event);
            });
          }, [ref]);
        }
      "#,
    },
    ValidCase {
        name: "Pass window event data to parent",
        code: r#"
        const Child = ({ onResized }) => {
          useEffect(() => {
            window.addEventListener('resize', (event) => {
              onResized({
                width: window.innerWidth,
                height: window.innerHeight,
              });
            });
            return () => window.removeEventListener('resize', handleResize);
          }, [onResized]);
        }
      "#,
    },
];

const NO_PASS_DATA_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Pass external state",
        code: r#"
        const Child = ({ onFetched }) => {
          const data = useSomeAPI();

          useEffect(() => {
            onFetched(data);
          }, [onFetched, data]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI"],
    },
    InvalidCase {
        name: "Pass external state, no deps argument",
        code: r#"
        const Child = ({ onFetched }) => {
          const data = useSomeAPI();

          useEffect(() => {
            onFetched(data);
          });
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI"],
    },
    InvalidCase {
        name: "Pass external state, empty deps",
        code: r#"
        const Child = ({ onFetched }) => {
          const data = useSomeAPI();

          useEffect(() => {
            onFetched(data);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI"],
    },
    InvalidCase {
        name: "Pass external state in custom hook",
        code: r#"
        const useCustomHook = ({ onFetched }) => {
          const data = useSomeAPI();

          useEffect(() => {
            onFetched(data);
          }, [onFetched, data]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInHook"],
        expected_targets: &["useSomeAPI"],
    },
    InvalidCase {
        name: "Pass derived external state",
        code: r#"
        const Child = ({ onFetched }) => {
          const data = useSomeAPI();
          const firstElement = data[0];

          useEffect(() => {
            onFetched(firstElement);
          }, [onFetched, firstElement]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI"],
    },
    InvalidCase {
        name: "Pass multiple external state",
        code: r#"
        const Child = ({ onResult }) => {
          const data = useSomeAPI();
          const meta = useOtherAPI();

          useEffect(() => {
            onResult(data, meta);
          }, [onResult, data, meta]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI, useOtherAPI"],
    },
    InvalidCase {
        name: "Pass external data and internal state (only data in message)",
        code: r#"
        const Child = ({ onChanged }) => {
          const [count, setCount] = useState(0);
          const data = useSomeAPI();

          useEffect(() => {
            onChanged(data, count);
          }, [onChanged, data, count]);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidPassingDataToParentInComponent"],
        expected_targets: &["useSomeAPI"],
    },
];

#[test]
fn parity_no_pass_data_to_parent_valid() {
    run_valid_suite(RuleId::NoPassDataToParent, NO_PASS_DATA_VALID);
}

#[test]
fn parity_no_pass_data_to_parent_invalid() {
    run_invalid_suite(RuleId::NoPassDataToParent, NO_PASS_DATA_INVALID);
    let diags = analyze_source(
        Path::new("Test.tsx"),
        NO_PASS_DATA_INVALID[0].code,
        Some(&[RuleId::NoPassDataToParent]),
    );
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
}

const NO_EXTERNAL_STORE_SUBSCRIPTION_VALID: &[ValidCase] = &[
    ValidCase {
        name: "No useEffect",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          return <div>{count}</div>;
        }
      "#,
    },
    ValidCase {
        name: "useEffect without cleanup, no state setter",
        code: r#"
        function C() {
          useEffect(() => {
            console.log('hello');
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "useEffect without cleanup, with state setter",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            setCount(1);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "useEffect with cleanup but no synchronous state setter (setter only in callback)",
        code: r#"
        function C() {
          const [value, setValue] = useState(0);
          useEffect(() => {
            const timer = setInterval(() => {
              setValue(Date.now());
            }, 1000);
            return () => clearInterval(timer);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "useEffect with cleanup and sync setter, but setter not referenced in cleanup",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            setCount(0);
            const timer = setInterval(() => {}, 1000);
            return () => clearInterval(timer);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Fetching data with cleanup (ignore pattern)",
        code: r#"
        function C({ query }) {
          const [results, setResults] = useState([]);
          useEffect(() => {
            let ignore = false;
            fetchResults(query).then((json) => {
              if (!ignore) setResults(json);
            });
            return () => { ignore = true; };
          }, [query]);
        }
      "#,
    },
    ValidCase {
        name: "ResizeObserver pattern (setter only in callback)",
        code: r#"
        function C({ ref }) {
          const [size, setSize] = useState();
          useEffect(() => {
            const observer = new ResizeObserver((entry) => {
              setSize(entry.contentRect.width);
            });
            observer.observe(ref.current);
            return () => observer.disconnect();
          }, [ref]);
        }
      "#,
    },
    ValidCase {
        name: "Store subscribe returns unsubscribe, no sync setter in body",
        code: r#"
        function useStoreValue(store) {
          const [value, setValue] = useState(store.get());
          useEffect(() => {
            const unsubscribe = store.subscribe((v) => setValue(v));
            return unsubscribe;
          }, [store]);
          return value;
        }
      "#,
    },
    ValidCase {
        name: "Empty deps with unrelated cleanup (timer id, not setter)",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            setCount(0);
            return () => console.log('cleanup');
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "State setter called synchronously, cleanup references something else entirely",
        code: r#"
        function C() {
          const [x, setX] = useState(0);
          useEffect(() => {
            setX(1);
            const id = setTimeout(() => {}, 0);
            return () => clearTimeout(id);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Multiple setters, none connected to cleanup",
        code: r#"
        function C() {
          const [a, setA] = useState(0);
          const [b, setB] = useState(0);
          useEffect(() => {
            setA(1);
            setB(2);
            const id = setInterval(() => {}, 0);
            return () => clearInterval(id);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Cleanup references a callback that doesn't touch the setter",
        code: r#"
        function C() {
          const [isOnline, setIsOnline] = useState(true);
          useEffect(() => {
            setIsOnline(navigator.onLine);
            const cb = () => console.log('no setter here');
            window.addEventListener('click', cb);
            return () => window.removeEventListener('click', cb);
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Synchronous setter via .then (async, not sync)",
        code: r#"
        function C() {
          const [data, setData] = useState(null);
          useEffect(() => {
            fetch('/data').then((res) => setData(res));
            return () => abortController.abort();
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Synchronous IIFE wrapping setter, cleanup not connected",
        code: r#"
        function C() {
          const [x, setX] = useState(0);
          useEffect(() => {
            (() => { setX(readExternal()); })();
            return () => console.log('cleanup');
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "void expression wrapping synchronous setter, cleanup not connected",
        code: r#"
        function C() {
          const [x, setX] = useState(0);
          useEffect(() => {
            void setX(readExternal());
            return () => console.log('cleanup');
          }, []);
        }
      "#,
    },
    ValidCase {
        name: "Body setter and cleanup reference different setters of same component",
        code: r#"
        function C() {
          const [a, setA] = useState(0);
          const [b, setB] = useState(0);
          useEffect(() => {
            setA(readExternal());
            const hb = (v) => setB(v);
            store.subscribe(hb);
            return () => store.unsubscribe(hb);
          }, []);
        }
      "#,
    },
];

const NO_EXTERNAL_STORE_SUBSCRIPTION_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Canonical useOnlineStatus pattern from docs",
        code: r#"
        function useOnlineStatus() {
          const [isOnline, setIsOnline] = useState(true);
          useEffect(() => {
            function updateState() {
              setIsOnline(navigator.onLine);
            }
            updateState();
            window.addEventListener('online', updateState);
            window.addEventListener('offline', updateState);
            return () => {
              window.removeEventListener('online', updateState);
              window.removeEventListener('offline', updateState);
            };
          }, []);
          return isOnline;
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["isOnline"],
    },
    InvalidCase {
        name: "Inline arrow cleanup with same closure chain",
        code: r#"
        function useOnlineStatus() {
          const [isOnline, setIsOnline] = useState(true);
          useEffect(() => {
            const update = () => setIsOnline(navigator.onLine);
            update();
            window.addEventListener('online', update);
            return () => window.removeEventListener('online', update);
          }, []);
          return isOnline;
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["isOnline"],
    },
    InvalidCase {
        name: "Setter referenced directly in cleanup",
        code: r#"
        function C() {
          const [isOnline, setIsOnline] = useState(true);
          useEffect(() => {
            setIsOnline(navigator.onLine);
            return () => setIsOnline(false);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["isOnline"],
    },
    InvalidCase {
        name: "Handler referenced in cleanup calls the setter",
        code: r#"
        function useStoreValue(store) {
          const [value, setValue] = useState(0);
          useEffect(() => {
            setValue(store.get());
            const handler = (v) => setValue(v);
            store.subscribe(handler);
            return () => store.unsubscribe(handler);
          }, [store]);
          return value;
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["value"],
    },
    InvalidCase {
        name: "Multiple setters, one matching cleanup",
        code: r#"
        function C() {
          const [x, setX] = useState(0);
          const [y, setY] = useState(0);
          useEffect(() => {
            setX(readStoreX());
            setY(readStoreY());
            const handlerX = (v) => setX(v);
            const handlerY = (v) => setY(v);
            storeX.subscribe(handlerX);
            storeY.subscribe(handlerY);
            return () => {
              storeX.unsubscribe(handlerX);
              storeY.unsubscribe(handlerY);
            };
          }, []);
        }
      "#,
        expected_count: 2,
        expected_ids: &[
            "avoidExternalStoreSubscription",
            "avoidExternalStoreSubscription",
        ],
        expected_targets: &["x", "y"],
    },
    InvalidCase {
        name: "Split handler and synchronous setter, handler in cleanup",
        code: r#"
        function C() {
          const [value, setValue] = useState(0);
          useEffect(() => {
            setValue(readExternal());
            const handler = (v) => setValue(v);
            const sub = external.subscribe(handler);
            return () => sub.unsubscribe(handler);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["value"],
    },
    InvalidCase {
        name: "Intermediate synchronous function call pattern",
        code: r#"
        function useStoreValue(store) {
          const [value, setValue] = useState(0);
          useEffect(() => {
            const update = () => setValue(store.get());
            update();
            store.onChange(update);
            return () => store.offChange(update);
          }, [store]);
          return value;
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["value"],
    },
    InvalidCase {
        name: "Multiple sync setters, cleanup references one via arrow body",
        code: r#"
        function C() {
          const [x, setX] = useState(0);
          const [y, setY] = useState(0);
          useEffect(() => {
            setX(readStoreX());
            setY(readStoreY());
            const hx = (v) => setX(v);
            storeX.onChange(hx);
            return () => storeX.offChange(hx);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["x"],
    },
    InvalidCase {
        name: "Setter via callback setter (setX(c => ...)) both in body and cleanup",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            setCount(readExternal());
            return () => setCount(c => c + 1);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["count"],
    },
    InvalidCase {
        name: "Body aliases setter directly, cleanup uses original name",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            const update = setCount;
            update(readExternal());
            return () => setCount(0);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["count"],
    },
    InvalidCase {
        name: "Body wraps setter in arrow function, cleanup uses original name",
        code: r#"
        function C() {
          const [count, setCount] = useState(0);
          useEffect(() => {
            const update = (v) => setCount(v);
            update(readExternal());
            return () => setCount(0);
          }, []);
        }
      "#,
        expected_count: 1,
        expected_ids: &["avoidExternalStoreSubscription"],
        expected_targets: &["count"],
    },
];

#[test]
fn parity_no_external_store_subscription_valid() {
    run_valid_suite(
        RuleId::NoExternalStoreSubscription,
        NO_EXTERNAL_STORE_SUBSCRIPTION_VALID,
    );
}

#[test]
fn parity_no_external_store_subscription_invalid() {
    run_invalid_suite(
        RuleId::NoExternalStoreSubscription,
        NO_EXTERNAL_STORE_SUBSCRIPTION_INVALID,
    );
    let diags = analyze_source(
        Path::new("Test.tsx"),
        NO_EXTERNAL_STORE_SUBSCRIPTION_INVALID[0].code,
        Some(&[RuleId::NoExternalStoreSubscription]),
    );
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
}

const REAL_WORLD_VALID: &[ValidCase] = &[
    ValidCase {
        name: "useLayoutEffect",
        code: r#"
          function Input({ count }) {
            const ref = useRef();

            useLayoutEffect(() => {
              if (count == 0) {
                ref.current?.focus();
              }
            }, [count]);

            return (
              <input ref={ref} value={count} />
            )
          }
        "#,
    },
    ValidCase {
        name: "Managing a timer",
        code: r#"
        function Timer() {
          const [seconds, setSeconds] = useState(0);

          useEffect(() => {
            const interval = setInterval(() => {
              setSeconds((s) => s + 1);
            }, 1000);

            return () => {
              clearInterval(interval);
            }
          }, []);

          return <div>{seconds}</div>;
        }
      "#,
    },
    ValidCase {
        name: "Debouncing",
        code: r#"
          function useDebouncedState(value, delay) {
            const [state, setState] = useState(value);
            const [debouncedState, setDebouncedState] = useState(value);

            useEffect(() => {
              const timeout = setTimeout(() => {
                setDebouncedState(state);
              }, delay);

              return () => {
                clearTimeout(timeout);
              };
            }, [delay, state]);

            return [state, debouncedState, setState];
          }
        "#,
    },
    ValidCase {
        name: "Debouncing via Lodash",
        code: r#"
          import { useState, useEffect } from 'react';
          import debounce from 'lodash/debounce';

          export const useDebouncedState = (delay) => {
            const [value] = useState(0);

            const debouncedFunction = debounce((newValue) => {
              console.log(newValue);
            }, delay);

            useEffect(() => {
              debouncedFunction(value);
            }, [value, debouncedFunction]);

            return [];
          };
        "#,
    },
    ValidCase {
        name: "Listening for window events",
        code: r#"
        function WindowSize() {
          const [size, setSize] = useState({ width: window.innerWidth, height: window.innerHeight });

          useEffect(() => {
            const handleResize = () => {
              setSize({ width: window.innerWidth, height: window.innerHeight });
            };

            window.addEventListener('resize', handleResize);

            return () => {
              window.removeEventListener('resize', handleResize);
            };
          }, []);

          return <div>{size.width} x {size.height}</div>;
        }
      "#,
    },
    ValidCase {
        name: "ResizeObserver",
        code: r#"
          function useHasOverflow({ contentRef, maxHeight }) {
            const [hasOverflow, setHasOverflow] = useState(false);

            useEffect(() => {
              const resizeObserver = new ResizeObserver((element) => {
                const hasContentOverflow = element.scrollHeight > maxHeight;
                setHasOverflow(hasContentOverflow);
              })

              if (contentRef.current != null) {
                resizeObserver.observe(contentRef.current);
              }

              return () => {
                resizeObserver.disconnect();
              };
            }, [contentRef, maxHeight]);

            return hasOverflow;
          }
        "#,
    },
    ValidCase {
        name: "Play/pausing DOM video",
        code: r#"
        function VideoPlayer() {
          const [isPlaying, setIsPlaying] = useState(false);
          const videoRef = useRef();

          useEffect(() => {
            if (isPlaying) {
              videoRef.current.play();
            } else {
              videoRef.current.pause();
            }
          }, [isPlaying]);

          return <div>
            <video ref={videoRef} />
            <button onClick={() => setIsPlaying((p) => !p)} />
          </div>
        }
      "#,
    },
    ValidCase {
        name: "Saving to LocalStorage",
        code: r#"
        function Notes() {
          const [notes, setNotes] = useState(() => {
            const savedNotes = localStorage.getItem('notes');
            return savedNotes ? JSON.parse(savedNotes) : [];
          });

          useEffect(() => {
            localStorage.setItem('notes', JSON.stringify(notes));
          }, [notes]);

          return <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        }
      "#,
    },
    ValidCase {
        name: "Logging/Analytics",
        code: r#"
        function Nav() {
          const [page, setPage] = useState('home');

          useEffect(() => {
            console.log("page viewed", page);
          }, [page]);

          return (
            <div>
              <button onClick={() => setPage('home')}>Home</button>
              <button onClick={() => setPage('about')}>About</button>
              <div>{page}</div>
            </div>
          )
        }
      "#,
    },
    ValidCase {
        name: "CountryPicker",
        code: r#"
        function CountryPicker({ withEmoji }) {
          const { translation, getCountries } = useContext();

          const [state, setState] = useState({
            countries: [],
            selectedCountry: null,
          });
          const setCountries = (countries) => setState({ ...state, countries });

          useEffect(() => {
            let cancel = false;
            getCountries(translation)
              .then((countries) => (cancel ? null : setCountries(countries)))
              .catch(console.warn);

            return () => {
              cancel = true;
            };
          }, [translation, withEmoji]);
        }
      "#,
    },
    ValidCase {
        name: "navigation.setOptions",
        code: r#"
        import { useNavigation } from '@react-navigation/native';
        import { useState, useLayoutEffect } from 'react';

        function ProfileScreen({ route }) {
          const navigation = useNavigation();
          const [value, onChangeText] = React.useState(route.params.title);

          React.useLayoutEffect(() => {
            navigation.setOptions({
              title: value === '' ? 'No title' : value,
            });
          }, [navigation, route]);
        }
      "#,
    },
    ValidCase {
        name: "Keyboard state listener",
        code: r#"
        import { useEffect, useState } from 'react';
        import keyboardReducer from './reducers';

        let globalKeyboardState = {
          recentlyUsed: []
        };

        export const keyboardStateListeners = new Set();

        const setKeyboardState = (action) => {
          globalKeyboardState = keyboardReducer(globalKeyboardState, action);
          keyboardStateListeners.forEach((listener) => listener(globalKeyboardState));
        };

        export const useKeyboardStore = () => {
          const [keyboardState, setState] = useState(globalKeyboardState);

          useEffect(() => {
            const listener = () => setState(globalKeyboardState);
            keyboardStateListeners.add(listener);
            return () => {
              keyboardStateListeners.delete(listener);
            };
          }, [keyboardState]);

          return { keyboardState, setKeyboardState };
        };

        useKeyboardStore.setKeyboardState = setKeyboardState;
      "#,
    },
    ValidCase {
        name: "Indexing ref state with internal state",
        code: r#"
          import { useEffect, useRef, useState } from "react";

          const someArray = [{ id: 1 }, { id: 2 }, { id: 3 }];

          const Component = ({ value }) => {
            const inputRefs = useRef([]);

            useEffect(() => {
              inputRefs.current?.[index]?.focus();
            }, [value, index]);

            return (
              <>
                {someArray.map((item, index) => (
                  <input
                    key={item.id}
                    ref={(el) => (inputRefs.current[index] = el)}
                  />
                ))}
              </>
            )
          }
        "#,
    },
    ValidCase {
        name: "Ref callback",
        code: r#"
          export const useOnScreen = () => {
              const [element, setElement] = useState(null);
              const [isIntersecting, setIntersecting] = useState(false);

              const ref = useCallback((element) => {
                  setElement(element);
              }, []);

              useEffect(() => {
                  if (!element) {
                      return;
                  }

                  const observer = new IntersectionObserver(([entry]) => {
                      setIntersecting(entry?.isIntersecting ?? false);
                  });

                  observer.observe(element);
                  return () => {
                      observer.disconnect();
                  };
              }, [element]);

              return { ref, isIntersecting };
          };
        "#,
    },
    ValidCase {
        name: "Effect with recursion",
        code: r#"
        function Component() {
          useEffect(() => {
            const container = ctnDom.current
            if (!container) return

            const renderer = new Renderer({ alpha: true, premultipliedAlpha: false })
            const gl = renderer.gl
            const program = new Program(gl, {
              vertex: vert,
              fragment: frag,
              uniforms: {
                iTime: { value: 0 },
                iResolution: { value: new Vec3(gl.canvas.width, gl.canvas.height, gl.canvas.width / gl.canvas.height) },
                hue: { value: hue },
                hover: { value: 0 },
                rot: { value: 0 },
                hoverIntensity: { value: hoverIntensity },
              },
            })
            const mesh = new Mesh(gl, { geometry, program })

            let rafId
            let lastTime = 0
            let currentRot = 0
            const rotationSpeed = 0.3

            const update = (t) => {
              rafId = requestAnimationFrame(update)
              const dt = (t - lastTime) * 0.001
              lastTime = t
              const currentTime = t * 0.001
              program.uniforms.iTime.value = currentTime

              if (cycleHue) {
                const cyclicHue = (hue + currentTime * hueCycleSpeed) % 360
                program.uniforms.hue.value = cyclicHue
              } else {
                program.uniforms.hue.value = hue
              }

              program.uniforms.hoverIntensity.value = hoverIntensity

              const effectiveHover = forceHoverState ? 1 : targetHover
              program.uniforms.hover.value += (effectiveHover - program.uniforms.hover.value) * 0.1

              if (rotateOnHover && effectiveHover > 0.5) {
                currentRot += dt * rotationSpeed
              }
              program.uniforms.rot.value = currentRot

              renderer.render({ scene: mesh })
            }
            rafId = requestAnimationFrame(update)

            return () => {
              cancelAnimationFrame(rafId)
              window.removeEventListener("resize", resize)
              container.removeEventListener("mousemove", handleMouseMove)
              container.removeEventListener("mouseleave", handleMouseLeave)
              container.removeChild(gl.canvas)
              gl.getExtension("WEBGL_lose_context")?.loseContext()
            }
          }, [
            hue,
            hoverIntensity,
            rotateOnHover,
            forceHoverState,
            cycleHue,
            hueCycleSpeed,
            size,
          ])
        }
      "#,
    },
    ValidCase {
        name: "TanStack useInfinityQuery useInView",
        code: r#"
          import React from 'react'
          import { useInView } from 'react-intersection-observer'
          import { useInfiniteQuery } from '@tanstack/react-query'

          function Example() {
            const { ref, inView } = useInView()

            const {
              status,
              data,
              error,
              isFetching,
              isFetchingNextPage,
              isFetchingPreviousPage,
              fetchNextPage,
              fetchPreviousPage,
              hasNextPage,
              hasPreviousPage,
            } = useInfiniteQuery({
              queryKey: ['projects'],
              queryFn: async ({
                pageParam,
              }) => {
                const response = await fetch('/api/projects?cursor=' + pageParam)
                return await response.json()
              },
              initialPageParam: 0,
              getPreviousPageParam: (firstPage) => firstPage.previousId,
              getNextPageParam: (lastPage) => lastPage.nextId,
            })

            React.useEffect(() => {
              if (inView && hasNextPage && !isFetchingNextPage) {
                fetchNextPage()
              }
            }, [inView, hasNextPage, isFetchingNextPage, fetchNextPage])
          }
        "#,
    },
    ValidCase {
        name: "React Query: fresh data synced to state",
        code: r#"
          import { useState, useEffect } from 'react'
          import { useQuery } from '@tanstack/react-query'

          function Items() {
            const [filter, setFilter] = useState('all')
            const { data } = useQuery({
              queryKey: ['items', filter],
              queryFn: () => fetchItems(filter),
            })
            const [items, setItems] = useState([])

            useEffect(() => {
              if (data) {
                setItems(data)
              }
            }, [data])

            return <div>{items}</div>
          }
        "#,
    },
    ValidCase {
        name: "TanStack useInfinityQuery useInView with state, prop and data in queryKey",
        code: r#"
          import React from 'react'
          import { useInView } from 'react-intersection-observer'
          import { useInfiniteQuery } from '@tanstack/react-query'

          function Example(props) {
            const { ref, inView } = useInView()
            const [state] = React.useState(0)
            const search = useSearchParams()

            const {
              status,
              data,
              error,
              isFetching,
              isFetchingNextPage,
              isFetchingPreviousPage,
              fetchNextPage,
              fetchPreviousPage,
              hasNextPage,
              hasPreviousPage,
            } = useInfiniteQuery({
              queryKey: ['projects', state, props, search],
              queryFn: async ({
                pageParam,
              }) => {
                const response = await fetch('/api/projects?cursor=' + pageParam)
                return await response.json()
              },
              initialPageParam: 0,
              getPreviousPageParam: (firstPage) => firstPage.previousId,
              getNextPageParam: (lastPage) => lastPage.nextId,
            })

            React.useEffect(() => {
              if (inView && hasNextPage && !isFetchingNextPage) {
                void fetchNextPage()
              }
            }, [inView, hasNextPage, isFetchingNextPage, fetchNextPage])
          }
        "#,
    },
];

#[test]
fn parity_real_world_valid_all_rules() {
    assert_eq!(REAL_WORLD_VALID.len(), 18);
    for case in REAL_WORLD_VALID {
        let diags = analyze_source(Path::new("RealWorld.tsx"), case.code, None);
        assert!(
            diags.is_empty(),
            "Expected 0 diagnostics for realWorldValid case [{}] with all rules enabled, got: {diags:#?}",
            case.name
        );
    }
}

#[test]
fn detects_no_fetch_in_effect_uncancelled_surgical() {
    let uncancelled = r#"
        function SearchResults({ query }) {
          const [results, setResults] = useState([]);

          useEffect(() => {
            fetch('/api/search?q=' + query)
              .then((res) => res.json())
              .then((data) => setResults(data));
          }, [query]);

          return <div>{results.length}</div>;
        }
    "#;
    let diags_uncancelled = analyze_source(
        Path::new("SearchResults.tsx"),
        uncancelled,
        Some(&[RuleId::NoFetchInEffect]),
    );
    assert_eq!(diags_uncancelled.len(), 1);
    assert_eq!(diags_uncancelled[0].rule, RuleId::NoFetchInEffect);
    assert_eq!(diags_uncancelled[0].target_name, "results");
    assert_eq!(diags_uncancelled[0].tier, PrescriptionTier::Surgical);

    let fetch_without_state = r#"
        function PingOnMount() {
          useEffect(() => {
            fetch('/api/ping');
          }, []);
          return <div />;
        }
    "#;
    let diags_no_state = analyze_source(
        Path::new("PingOnMount.tsx"),
        fetch_without_state,
        Some(&[RuleId::NoFetchInEffect]),
    );
    assert!(diags_no_state.is_empty());
}

#[test]
fn detects_no_fetch_in_effect_cancelled_refactor() {
    let cancelled_cleanup = r#"
        function SearchResults({ query }) {
          const [results, setResults] = useState([]);

          useEffect(() => {
            let ignore = false;
            fetch('/api/search?q=' + query)
              .then((res) => res.json())
              .then((data) => {
                if (!ignore) {
                  setResults(data);
                }
              });
            return () => {
              ignore = true;
            };
          }, [query]);

          return <div>{results.length}</div>;
        }
    "#;
    let diags_cleanup = analyze_source(
        Path::new("SearchResults.tsx"),
        cancelled_cleanup,
        Some(&[RuleId::NoFetchInEffect]),
    );
    assert_eq!(diags_cleanup.len(), 1);
    assert_eq!(diags_cleanup[0].rule, RuleId::NoFetchInEffect);
    assert_eq!(diags_cleanup[0].target_name, "results");
    assert_eq!(diags_cleanup[0].tier, PrescriptionTier::Refactor);

    let cancelled_abort = r#"
        function SearchResults({ query }) {
          const [results, setResults] = useState([]);

          useEffect(() => {
            const controller = new AbortController();
            fetch('/api/search?q=' + query, { signal: controller.signal })
              .then((res) => res.json())
              .then((data) => setResults(data));
          }, [query]);

          return <div>{results.length}</div>;
        }
    "#;
    let diags_abort = analyze_source(
        Path::new("SearchResults.tsx"),
        cancelled_abort,
        Some(&[RuleId::NoFetchInEffect]),
    );
    assert_eq!(diags_abort.len(), 1);
    assert_eq!(diags_abort[0].tier, PrescriptionTier::Refactor);

    let window_and_sync_guard = r#"
        function SearchResults({ query }) {
          const [loading, setLoading] = useState(false);
          const [results, setResults] = useState([]);

          useEffect(() => {
            setLoading(true);
            window.fetch('/api/search?q=' + query)
              .then((res) => res.json())
              .then((data) => setResults(data));
          }, [query]);

          return <div>{results.length}</div>;
        }
    "#;
    let diags_window = analyze_source(
        Path::new("SearchResults.tsx"),
        window_and_sync_guard,
        Some(&[RuleId::NoFetchInEffect]),
    );
    assert_eq!(diags_window.len(), 1);
    assert_eq!(diags_window[0].target_name, "results");
    assert_eq!(diags_window[0].tier, PrescriptionTier::Surgical);
}
