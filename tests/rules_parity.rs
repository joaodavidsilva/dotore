//! Parity tests for `no-derived-state`, `no-initialize-state`, and `syntax`,
//! plus renamed React imports and `Autofix` vs `Surgical` classification.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use dotore::{
    PrescriptionTier, RuleId, ScanOptions, analyze_project_sources, analyze_source,
    format_terminal_report, scan_workspace,
};

struct ValidCase {
    name: &'static str,
    code: &'static str,
}

struct InvalidCase {
    name: &'static str,
    code: &'static str,
    expected_count: usize,
    expected_ids: &'static [&'static str],
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
    }
}

const NO_DERIVED_STATE_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Compute in render from internal state",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');

          const fullName = firstName + ' ' + lastName;
        }
      "###,
    },
    ValidCase {
        name: "Compute in render from props",
        code: r###"
        function Form({ firstName, lastName }) {
          const fullName = firstName + ' ' + lastName;
        }
      "###,
    },
    ValidCase {
        name: "Set to literal on external state change",
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
        name: "Set to derived literal on external state change",
        code: r###"
        function Feed() {
          const { data: posts } = useQuery('/posts');
          const [scrollPosition, setScrollPosition] = useState(0);

          useEffect(() => {
            const initialPosition = 0;
            setScrollPosition(initialPosition);
          }, [posts]);
        }
      "###,
    },
    ValidCase {
        name: "Set to external state",
        code: r###"
        function Feed() {
          const { data: posts } = useQuery('/posts');
          const [selectedPost, setSelectedPost] = useState();

          useEffect(() => {
            setSelectedPost(posts[0]);
          }, [posts]);
        }
      "###,
    },
    ValidCase {
        name: "Fetch external state on mount",
        code: r###"
        function Todos() {
          const [todos, setTodos] = useState([]);

          useEffect(() => {
            fetch('/todos').then((todos) => {
              setTodos(todos);
            });
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "Sync external state",
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
        name: "Synchronize internal state",
        code: r###"
        function Component() {
          const [name, setName] = useState();
          const [model] = useState(
            () => new FormModel(props)
          );

          useEffect(() => {
            model.setFieldDescriptor(name);
            return () => model.removeField(name);
          }, [model, name]);
        }
      "###,
    },
    ValidCase {
        name: "Subscribe to external state",
        code: r###"
        import { subscribeToStatus } from 'library';

        function Status({ topic }) {
          const [status, setStatus] = useState();

          useEffect(() => {
            const unsubscribe = subscribeToStatus(topic, (status) => {
              setStatus(status);
            });

            return () => unsubscribe();
          }, [topic]);

          return <div>{status}</div>;
        }
      "###,
    },
    ValidCase {
        name: "From props via impure derived setter",
        code: r###"
        function DoubleCounter({ count }) {
          const [doubleCount, setDoubleCount] = useState(0);

          const derivedSetter = () => {
            const multipler = fetch('/multipler');
            setDoubleCount(multiplier);
          }

          useEffect(() => {
            derivedSetter();
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "Via impure promise global function",
        code: r###"
        function Counter({ count }) {
          const [multipliedCount, setMultipliedCount] = useState();

          useEffect(() => {
            fetch('/multiplier')
              .then((res) => res.json())
              .then((multiplier) => setMultipliedCount(count * multiplier));
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "Mutate internal state",
        code: r###"
        function DoubleList() {
          const [list, setList] = useState([]);
          const [doubleList, setDoubleList] = useState([]);

          useEffect(() => {
            doubleList.push(...list);
          }, [list]);
        }
      "###,
    },
    ValidCase {
        name: "Synchronous setter in anonymous callback",
        code: r###"
          function useHasOverflow({ contentRef, maxHeight }) {
            const [hasOverflow, setHasOverflow] = useState(false);

            useEffect(() => {
              const resizeObserver = createResizeObserver((element) => {
                const hasContentOverflow = element.scrollHeight > maxHeight;
                setHasOverflow(hasContentOverflow);
              })

              resizeObserver.observe(contentRef.current);
            }, [contentRef, maxHeight]);

            return hasOverflow;
          }
        "###,
    },
];

#[test]
fn parity_no_derived_state_valid() {
    run_valid_suite(RuleId::NoDerivedState, NO_DERIVED_STATE_VALID);
}

const NO_DERIVED_STATE_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "From internal state",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');

          const [fullName, setFullName] = useState('');
          useEffect(() => setFullName(firstName + ' ' + lastName), [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From derived internal state",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            const name = firstName + ' ' + lastName;
            setFullName(name)
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From derived internal state outside effect",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');
          const [fullName, setFullName] = useState('');
          const name = firstName + ' ' + lastName;

          useEffect(() => {
            setFullName(name)
          }, [name]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From internal state and external state",
        code: r###"
        import { usePrefix } from 'library';

        function Component() {
          const [name, setName] = useState();
          const [prefixedName, setPrefixedName] = useState();
          const prefix = usePrefix(name);

          useEffect(() => {
            const newValue = prefix + name;
            setPrefixedName(newValue);
          }, [prefix, name])
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props",
        code: r###"
        function Form({ firstName, lastName }) {
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            setFullName(firstName + ' ' + lastName);
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From intermediate prop",
        code: r###"
        function Form({ firstName, lastName }) {
          const [fullName, setFullName] = useState('');
          const prefixedName = 'Dr. ' + firstName;

          useEffect(() => {
            setFullName(prefixedName + ' ' + lastName);
          }, [prefixedName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props via method",
        code: r###"
        function DoubleList({ list }) {
          const [doubleList, setDoubleList] = useState([]);

          useEffect(() => {
            setDoubleList(list.concat(list));
          }, [list]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From internal state via method",
        code: r###"
        function DoubleList() {
          const [list, setList] = useState([]);
          const [doubleList, setDoubleList] = useState([]);

          useEffect(() => {
            setDoubleList(list.concat(list));
          }, [list]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props and internal state",
        code: r###"
        function Form({ title }) {
          const [name, setName] = useState('Dwayne');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            setFullName(title + ' ' + name);
          }, [title, name]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props and internal state via intermediate variable",
        code: r###"
        function Form({ title }) {
          const [name, setName] = useState('Dwayne');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            const newFullName = title + ' ' + name;
            setFullName(newFullName);
          }, [title, name]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From internal plus external state",
        code: r###"
        function Form() {
          const prefix = useQuery('/prefix');
          const [name, setName] = useState();
          const [prefixedName, setPrefixedName] = useState();

          useEffect(() => {
            setPrefixedName(prefix + name)
          }, [prefix, name]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props via callback setter",
        code: r###"
        import { useState, useEffect } from 'react';

        function CountAccumulator({ count }) {
          const [total, setTotal] = useState(count);

          useEffect(() => {
            setTotal((prev) => prev + count);
          }, [count]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "From props via pure derived setter",
        code: r###"
        function DoubleCounter({ count }) {
          const [doubleCount, setDoubleCount] = useState(0);

          const derivedSetter = (count) => setDoubleCount(count * 2);

          useEffect(() => {
            derivedSetter(count);
          }, [count]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Partially update complex state from props",
        code: r###"
        function Form({ firstName, lastName }) {
          const [formData, setFormData] = useState({
            title: 'Dr.',
            fullName: '',
          });

          useEffect(() => {
            setFormData({
              ...formData,
              fullName: firstName + ' ' + lastName,
            });
          }, [firstName, lastName, formData]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Partially update complex state from props via callback setter",
        code: r###"
        function Form({ firstName, lastName }) {
          const [formData, setFormData] = useState({
            title: 'Dr.',
            fullName: '',
          });

          useEffect(() => {
            setFormData((prev) => ({
              ...prev,
              fullName: firstName + ' ' + lastName,
            }));
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Partially update complex state from props via derived setter",
        code: r###"
        function Form({ firstName, lastName }) {
          const [formData, setFormData] = useState({
            title: 'Dr.',
            fullName: '',
          });

          const setFullName = (fullName) => setFormData({ ...formData, fullName });

          useEffect(() => {
            setFormData({
              ...formData,
              fullName: firstName + ' ' + lastName,
            });
          }, [firstName, lastName, formData]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Derived state in larger, otherwise legit effect",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            console.log(name);

            setFullName(firstName + ' ' + lastName);
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set to result of semi-pure local ArrowFunctionExpression",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            const computeName = () => firstName + ' ' + lastName;

            setFullName(computeName());
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set to result of semi-pure local FunctionDeclaration",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            function computeName() {
              return firstName + ' ' + lastName;
            }

            setFullName(computeName());
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set to result of semi-pure function defined outside effect",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          const computeName = () => firstName + ' ' + lastName;

          useEffect(() => {
            setFullName(computeName());
          }, [computeName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Via no-arg intermediate setter",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            const doSet = () => {
              setFullName(firstName + ' ' + lastName);
            }

            doSet();
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Bare return is not treated as a cleanup function",
        code: r###"
        function Form({ firstName, lastName }) {
          const [fullName, setFullName] = useState('');

          useEffect(() => {
            setFullName(firstName + ' ' + lastName);
            return;
          }, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
];

#[test]
fn parity_no_derived_state_invalid() {
    run_invalid_suite(RuleId::NoDerivedState, NO_DERIVED_STATE_INVALID);
}

const NO_INITIALIZE_STATE_VALID: &[ValidCase] = &[
    ValidCase {
        name: "To external data via Promise",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            fetch("https://api.example.com/data")
              .then(response => response.json())
              .then(data => setState(data));
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "To external data via async IIFE",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            (async () => {
              const response = await fetch("https://api.example.com/data");
              const data = await response.json();
              setState(data);
            })();
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "To literal inside synchronous IIFE",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            (() => {
              setState("Hello");
            })();
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "To literal inside IIFE inside callback",
        code: r###"
        import { useEffect, useState } from 'react';

        export const MyComponent = () => {
          const [state, setState] = useState();

          useEffect(() => {
            window.addEventListener('load', () => {
              (() => {
                setState('Loaded');
              })();
            });
          }, []);
        };
      "###,
    },
    ValidCase {
        name: "To literal inside callback inside IIFE",
        code: r###"
        import { useEffect, useState } from 'react';

        export const MyComponent = () => {
          const [state, setState] = useState();

          useEffect(() => {
            (() => {
              window.addEventListener('load', () => {
                setState('Loaded');
              });
            })();
          }, []);
        };
      "###,
    },
    ValidCase {
        name: "Setter with other dependency",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();
          const [other, setOther] = useState();

          useEffect(() => {
            setState("Hello");
          }, [other]);
        }
      "###,
    },
];

#[test]
fn parity_no_initialize_state_valid() {
    run_valid_suite(RuleId::NoInitializeState, NO_INITIALIZE_STATE_VALID);
}

const NO_INITIALIZE_STATE_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "To literal",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            setState("Hello");
          }, []);

          return <div>{state}</div>;
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
    InvalidCase {
        name: "To internal data",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();
          const [otherState, setOtherState] = useState('Meow');

          useEffect(() => {
            setState(otherState);
          }, []);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
    InvalidCase {
        name: "In an otherwise valid effect",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            console.log('Meow');
            setState('Hello World');
          }, []);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
    InvalidCase {
        name: "To undefined",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState('Meow');

          useEffect(() => {
            setState();
          }, []);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
    InvalidCase {
        name: "To equivalent derived literals",
        code: r###"
        function MyComponent() {
          const upstream = 'Meow';
          const [state, setState] = useState(upstream);

          useEffect(() => {
            const upstreamTwo = 'Meow';
            setState(upstreamTwo);
          }, []);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
    InvalidCase {
        name: "Only setter in deps",
        code: r###"
        function MyComponent() {
          const [state, setState] = useState();

          useEffect(() => {
            setState("Hello");
          }, [setState]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidInitializingState"],
    },
];

#[test]
fn parity_no_initialize_state_invalid() {
    run_invalid_suite(RuleId::NoInitializeState, NO_INITIALIZE_STATE_INVALID);
}

const SYNTAX_VALID: &[ValidCase] = &[
    ValidCase {
        name: "Two components with overlapping names",
        code: r###"
        function ComponentOne() {
          const [data, setData] = useState();
        }

        function ComponentTwo() {
          const setData = (data) => {
            console.log(data);
          }

          useEffect(() => {
            setData('hello');
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "Reacting to external state changes with member access in deps",
        code: r###"
        function Feed() {
          const { data } = useQuery('/posts');
          const [scrollPosition, setScrollPosition] = useState(0);

          useEffect(() => {
            setScrollPosition(0);
          }, [data.posts]);
        }
        "###,
    },
    ValidCase {
        name: "From external data retrieved in overly-complicated async IIFE",
        code: r###"
        import { useEffect, useState } from 'react';

        export const App = () => {
          const [response, setResponse] = useState(null);

          const fetchYesNoApi = () => {
            return (async () => {
              try {
                const response = await fetch('https://yesno.wtf/api');
                if (!response.ok) {
                  throw new Error('Network error');
                }
                const data = await response.json();
                setResponse(data);
              } catch (err) {
                console.error(err);
              }
            })();
          };

          useEffect(() => {
            (async () => {
              await fetchYesNoApi();
            })();
          }, []);

          return (
            <div>{response}</div>
          );
        };
      "###,
    },
    ValidCase {
        name: "Named function passed to event callback",
        code: r###"
        function Component() {
          const [count, setCount] = useState(0);
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => {
            function handleClick() {
              setDoubleCount(count * 2);
            }

            document.addEventListener('click', handleClick);
            return () => document.removeEventListener('click', handleClick);
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "Pass internal args to external local function",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          const doSet = (arg1, arg2) => {
            console.log(arg1, arg2);
          }

          useEffect(() => {
            doSet(firstName, lastName);
          }, [firstName, lastName]);
        }
      "###,
    },
    ValidCase {
        name: "From internal state via pure global function",
        code: r###"
        function Counter({ count }) {
          const [countJson, setCountJson] = useState();

          useEffect(() => {
            setCountJson(JSON.stringify(count));
          }, [count]);
        }
      "###,
    },
    ValidCase {
        name: "From internal state via local impure function",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          function computeName(firstName, lastName) {
            console.log('meow');
            return firstName + ' ' + lastName;
          }

          useEffect(() => {
            setFullName(computeName(firstName, lastName));
          }, [firstName, lastName]);
        }
      "###,
    },
    ValidCase {
        name: "Set to result of pure local ArrowFunctionExpression",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          const computeName = (firstName, lastName) => {
            return firstName + ' ' + lastName;
          }

          useEffect(() => {
            const newFullName = computeName(firstName, lastName);
            setFullName(newFullName);
          }, [firstName, lastName, computeName]);
        }
      "###,
    },
    ValidCase {
        name: "Set to result of internal useCallback; repeat references to a useState variable",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Dwayne');
          const [lastName, setLastName] = useState('The Rock');
          const [fullName, setFullName] = useState('');

          const computeName = useCallback(() => firstName + ' ' + lastName, [firstName, lastName]);

          useEffect(() => {
            setFullName(computeName());
          }, [computeName]);
        }
      "###,
    },
    ValidCase {
        name: "Defined-then-called async external global function",
        code: r###"
        function Component() {
          const api = useFetchWrapper();
          const [state, setState] = useState();

          useEffect(() => {
            async function fetchIt() {
              const response = await fetch('/endpoint');
              setState(response);
            }

            void fetchIt();
          }, []);
        }
      "###,
    },
    ValidCase {
        name: "Defined-then-called async function from API in deps",
        code: r###"
        function Component() {
          const api = useFetchWrapper();
          const [state, setState] = useState();

          useEffect(() => {
            async function fetchIt() {
              const response = await api.doFetch('/endpoint');
              setState(response);
            }

            void fetchIt();
          }, [api]);
        }
      "###,
    },
    ValidCase {
        name: "From external data retrieved in async IIFE with API in deps",
        code: r###"
        function Component() {
          const api = useFetchWrapper();
          const [state, setState] = useState();

          useEffect(() => {
            (async function fetchIt() {
              const response = await api.doFetch('/endpoint');
              setState(response);
            })();
          }, [api]);
        }
      "###,
    },
    ValidCase {
        name: "Synchronous setter in anonymous function passed to constructor",
        code: r###"
          function useHasOverflow({ contentRef, maxHeight }) {
            const [hasOverflow, setHasOverflow] = useState(false);

            useEffect(() => {
              const resizeObserver = new ResizeObserver((element) => {
                const hasContentOverflow = element.scrollHeight > maxHeight;
                setHasOverflow(hasContentOverflow);
              })

              resizeObserver.observe(contentRef.current);
              // In real-world, this effect would need a cleanup function that calls resizeObserver.disconnect.
              // So, not the most realistic example. But the concept holds.
            }, [contentRef, maxHeight]);

            return hasOverflow;
          }
        "###,
    },
    ValidCase {
        name: "Synchronous setter in named function passed to constructor",
        code: r###"
          function useHasOverflow({ contentRef, maxHeight }) {
            const [hasOverflow, setHasOverflow] = useState(false);

            useEffect(() => {
              const fn = (element) => {
                const hasContentOverflow = element.scrollHeight > maxHeight;
                setHasOverflow(hasContentOverflow);
              }
              const resizeObserver = new ResizeObserver(fn)

              resizeObserver.observe(contentRef.current);
            }, [contentRef, maxHeight]);

            return hasOverflow;
          }
        "###,
    },
    ValidCase {
        name: "Synchronous setter in named function passed to call expression",
        code: r###"
          function useHasOverflow({ contentRef, maxHeight }) {
            const [hasOverflow, setHasOverflow] = useState(false);

            useEffect(() => {
              const fn = (element) => {
                const hasContentOverflow = element.scrollHeight > maxHeight;
                setHasOverflow(hasContentOverflow);
              }
              const resizeObserver = createResizeObserver(fn)

              resizeObserver.observe(contentRef.current);
            }, [contentRef, maxHeight]);

            return hasOverflow;
          }
        "###,
    },
];

#[test]
fn parity_syntax_valid() {
    run_valid_suite(RuleId::NoDerivedState, SYNTAX_VALID);
}

const SYNTAX_INVALID: &[InvalidCase] = &[
    InvalidCase {
        name: "Derived state, with imports",
        code: r###"
        import { useState, useEffect } from 'react';

         function DoubleCounter() {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(count * 2), [count]);
         }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Derived state, without imports",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('Nick');
          const [lastName, setLastName] = useState('van Dyke');

          const [fullName, setFullName] = useState('');
          useEffect(() => setFullName(firstName + ' ' + lastName), [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Derived state, React.useEffect import",
        code: r###"
        import * as React from 'react';

        function DoubleCounter() {
          const [count, setCount] = React.useState(0);
          const [doubleCount, setDoubleCount] = React.useState(0);

          React.useEffect(() => {
            setDoubleCount(count * 2);
          }, [count]);
        }
      "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Function component",
        code: r###"
         function DoubleCounter() {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(count * 2), [count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Arrow function component",
        code: r###"
         const DoubleCounter = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(count * 2), [count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Memoized component, with props",
        code: r###"
        const DoubleCounter = memo(({ count }) => {
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => setDoubleCount(count), [count]);
        });
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Effect one-liner body",
        code: r###"
         const AvoidDuplicateTest = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(count * 2), [count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Effect single-statement body",
        code: r###"
         const DoubleCounter = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => { setDoubleCount(count * 2); }, [count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Effect multi-statement body",
        code: r###"
         const DoubleCounter = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => { setDoubleCount(count * 2); setDoubleCount(count * 2); }, [count]);
         }
       "###,
        expected_count: 2,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Effect anonymous function body",
        code: r###"
         const DoubleCounter = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(function() { setDoubleCount(count * 2); }, [count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Non-destructured props",
        code: r###"
         function DoubleCounter(props) {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(props.count * 2), [props.count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Destructured props",
        code: r###"
         function DoubleCounter({ propCount }) {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(propCount * 2), [propCount]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Renamed destructured props",
        code: r###"
         function DoubleCounter({ count: countProp }) {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(countProp * 2), [countProp]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Doubly deep MemberExpression in effect",
        code: r###"
         function DoubleCounter(props) {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(props.nested.count * 2), [props.nested.count]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Objects stored in state",
        code: r###"
          function DoubleCounter() {
            const [count, setCount] = useState({ value: 0 });
            const [doubleCount, setDoubleCount] = useState({ value: 0 });

            useEffect(() => {
              setDoubleCount({ value: count.value * 2 });
            }, [count]);
          }
        "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Optional chaining and nullish coalescing",
        code: r###"
        function DoubleCounter({ count }) {
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => {
            setDoubleCount((count?.value ?? 1) * 2);
          }, [count?.value]);
        }
      "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Member access in effect body but not in deps",
        code: r###"
         function DoubleCounter(props) {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => setDoubleCount(props.count * 2), [props]);
         }
       "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Doubly nested scopes in effect body",
        code: r###"
         const DoubleCounter = () => {
           const [count, setCount] = useState(0);
           const [doubleCount, setDoubleCount] = useState(0);

           useEffect(() => {
             if (count > 10) {
               if (count > 100) {
                 setDoubleCount(count * 4);
               } else {
                 setDoubleCount(count * 2);
               }
             } else {
               setDoubleCount(count);
             }
           }, [count]);
         }
       "###,
        expected_count: 3,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Destructured array skips element in variable declaration",
        code: r###"
        function SecondPost({ posts }) {
          const [secondPost, setSecondPost] = useState();

          useEffect(() => {
            const [, second] = posts;
            setSecondPost(second);
          }, [posts]);
        }
      "###,
        expected_count: 1,
        expected_ids: &[],
    },
    InvalidCase {
        name: "Value-less useState",
        code: r###"
        import { useState } from 'react';

        function AttemptCounter() {
          const [, setAttempts] = useState(0);
          const [count, setCount] = useState(0);

          useEffect(() => {
            setAttempts((prev) => {
              return prev + count;
            });
          }, [count]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Setter-less useState",
        code: r###"
        function AttemptCounter() {
          const [attempts, setAttempts] = useState(0);
          const [count] = useState(0);

          useEffect(() => {
            setAttempts(count);
          }, [count]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Custom hook with state",
        code: r###"
        function useCustomHook() {
          const [count, setCount] = useState(0);
          const [doubleCount, setDoubleCount] = useState(0);

          useEffect(() => {
            setDoubleCount(count * 2);
          }, [count]);

          return state;
        }

        function Component() {
          const customState = useCustomHook();
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "FunctionDeclaration custom hook with props",
        code: r###"
        function useCustomHook(prop) {
          const [state, setState] = useState(0);

          useEffect(() => {
            setState(prop);
          }, [prop]);

          return state;
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "VariableDeclarator custom hook with object props",
        code: r###"
        const useCustomHook = ({ prop }) => {
          const [state, setState] = useState(0);

          useEffect(() => {
            setState(prop);
          }, [prop]);

          return state;
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Conditional useEffect",
        code: r###"
        function DoubleCounter() {
          const [count, setCount] = useState(0);
          const [doubleCount, setDoubleCount] = useState(0);

          if (count > 10) {
            useEffect(() => {
              setDoubleCount(count * 2);
            }, [count]);
          }
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Passing non-anonymous function to effect",
        code: r###"
        function Form() {
          const [firstName, setFirstName] = useState('');
          const [lastName, setLastName] = useState('');
          const [name, setName] = useState('');

          function setDerivedName() {
            setName(firstName + ' ' + lastName);
          }

          useEffect(setDerivedName, [firstName, lastName]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Destructured array skips element in arrow function params",
        code: r###"
        function FilteredPosts({ posts }) {
          const [filteredPosts, setFilteredPosts] = useState([]);

          useEffect(() => {
            // Resulting AST node looks like:
            // {
            //   "type": "ArrayPattern",
            //   "elements": [
            //     null, <-- Must handle this!
            //     {
            //       "type": "Identifier",
            //       "name": "second"
            //     }
            //   ]
            // }
            setFilteredPosts(
              posts.filter(([, value]) => value !== "")
            );
          }, [posts]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set derived state via direct alias",
        code: r###"
        const Component = () => {
          const [data, setData] = useState();
          // No idea why someone would do this. But good to know we catch it.
          const setDataWrapper = setData;

          useEffect(() => {
            setDataWrapper(data);
          }, [data]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set derived state via destructured alias",
        code: r###"
        const Component = () => {
          const [data, setData] = useState();
          const { setData: setDataAlias } = { setData };

          useEffect(() => {
            setDataAlias(data);
          }, [data]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
    InvalidCase {
        name: "Set derived state via wrapped alias",
        code: r###"
        const Component = () => {
          const [data, setData] = useState();
          const setDataWrapper = (v) => setData(v);

          useEffect(() => {
            setDataWrapper(data);
          }, [data]);
        }
      "###,
        expected_count: 1,
        expected_ids: &["avoidDerivedState"],
    },
];

#[test]
fn parity_syntax_invalid() {
    run_invalid_suite(RuleId::NoDerivedState, SYNTAX_INVALID);
}

#[test]
fn detects_derived_state_with_renamed_react_imports() {
    let code = r#"
        import { useState as stateUser, useEffect as effectUser } from 'react';

        function Form() {
          const [firstName, setFirstName] = stateUser('Nick');
          const [lastName, setLastName] = stateUser('van Dyke');

          const [fullName, setFullName] = stateUser('');
          effectUser(() => setFullName(firstName + ' ' + lastName), [firstName, lastName]);
        }
    "#;

    let diags = analyze_source(Path::new("Form.tsx"), code, Some(&[RuleId::NoDerivedState]));
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].target_name, "fullName");
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);
    assert!(diags[0].autofix.is_some());
}

#[test]
fn classifies_derived_and_initialize_state_autofix_vs_surgical() {
    let surgical_derived = r#"
        function Form({ firstName, lastName }) {
          const [fullName, setFullName] = useState('');
          useEffect(() => {
            setFullName(firstName + ' ' + lastName);
          }, [firstName, lastName]);
          return <button onClick={() => setFullName('Custom')}>{fullName}</button>;
        }
    "#;
    let derived_diags = analyze_source(Path::new("Form.tsx"), surgical_derived, None);
    assert_eq!(derived_diags.len(), 1);
    assert_eq!(derived_diags[0].tier, PrescriptionTier::Surgical);
    assert!(derived_diags[0].autofix.is_none());

    let autofix_init = r#"
        function Greeting() {
          const [message, setMessage] = useState();
          useEffect(() => {
            setMessage("Hello");
          }, []);
          return <div>{message}</div>;
        }
    "#;
    let init_diags = analyze_source(Path::new("Greeting.tsx"), autofix_init, None);
    assert_eq!(init_diags.len(), 1);
    assert_eq!(init_diags[0].rule, RuleId::NoInitializeState);
    assert_eq!(init_diags[0].tier, PrescriptionTier::Autofix);
    assert!(init_diags[0].autofix.is_some());

    let surgical_init = r#"
        function Greeting() {
          const [message, setMessage] = useState();
          useEffect(() => {
            console.log("init");
            setMessage("Hello");
          }, []);
          return <div>{message}</div>;
        }
    "#;
    let surgical_init_diags = analyze_source(Path::new("Greeting.tsx"), surgical_init, None);
    assert_eq!(surgical_init_diags.len(), 1);
    assert_eq!(surgical_init_diags[0].rule, RuleId::NoInitializeState);
    assert_eq!(surgical_init_diags[0].tier, PrescriptionTier::Surgical);
    assert!(surgical_init_diags[0].autofix.is_none());
}

#[test]
fn no_initialize_state_avoids_duplicate_diagnostics_with_store_subscription_and_derived_state() {
    let mount_store = r#"
        function OnlineIndicator() {
          const [isOnline, setIsOnline] = useState(true);
          useEffect(() => {
            const update = () => setIsOnline(navigator.onLine);
            update();
            window.addEventListener('online', update);
            return () => window.removeEventListener('online', update);
          }, []);
          return <div>{isOnline ? 'Online' : 'Offline'}</div>;
        }
    "#;
    let store_diags = analyze_source(Path::new("OnlineIndicator.tsx"), mount_store, None);
    assert_eq!(store_diags.len(), 1);
    assert_eq!(store_diags[0].rule, RuleId::NoExternalStoreSubscription);

    let mount_derived = r#"
        function Greeting({ initialName }) {
          const [label, setLabel] = useState('');
          useEffect(() => {
            setLabel('Hello ' + initialName);
          }, []);
          return <div>{label}</div>;
        }
    "#;
    let derived_diags = analyze_source(Path::new("Greeting.tsx"), mount_derived, None);
    assert_eq!(derived_diags.len(), 1);
    assert_eq!(derived_diags[0].rule, RuleId::NoDerivedState);
}

#[test]
fn formats_terminal_report_with_cascade_and_score() {
    let source = r#"function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <div>{fullName}</div>;
}"#;

    let report = analyze_project_sources(
        vec![(PathBuf::from("src/Form.tsx"), source.to_string())],
        None,
    );
    assert_eq!(report.summary.total_diagnostics, 1);
    assert_eq!(report.summary.autofix_count, 1);

    let term = format_terminal_report(&report);
    assert!(term.contains("[no-derived-state] (autofix)"));
    assert!(term.contains("cascade:"));
}

#[test]
fn scanner_respects_gitignore_and_test_filters() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-scanner-test-{nanos}"));
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(root.join("ignored_dir")).unwrap();

    fs::write(root.join(".gitignore"), "ignored_dir/\n").unwrap();
    fs::write(root.join("src/App.tsx"), "export function App() {}").unwrap();
    fs::write(
        root.join("src/App.test.tsx"),
        "export function AppTest() {}",
    )
    .unwrap();
    fs::write(root.join("src/types.d.ts"), "export type X = number;").unwrap();
    fs::write(
        root.join("node_modules/pkg/index.js"),
        "export const x = 1;",
    )
    .unwrap();
    fs::write(
        root.join("ignored_dir/Hidden.tsx"),
        "export function Hidden() {}",
    )
    .unwrap();

    let (_, default_sources) = scan_workspace(&ScanOptions {
        paths: vec![root.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut default_files: Vec<PathBuf> = default_sources.into_keys().collect();
    default_files.sort();
    assert_eq!(default_files, vec![root.join("src/App.tsx")]);

    let (_, with_test_sources) = scan_workspace(&ScanOptions {
        paths: vec![root.clone()],
        include_tests: true,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut with_tests: Vec<PathBuf> = with_test_sources.into_keys().collect();
    with_tests.sort();
    assert_eq!(
        with_tests,
        vec![root.join("src/App.test.tsx"), root.join("src/App.tsx")]
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scanner_respects_gitignore_and_ignore_without_git_directory() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-scanner-nogit-{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("generated")).unwrap();
    fs::create_dir_all(root.join("scratch")).unwrap();

    fs::write(root.join(".gitignore"), "generated/\n*.gen.tsx\n").unwrap();
    fs::write(root.join(".ignore"), "scratch/\n").unwrap();
    fs::write(root.join("src/App.tsx"), "export function App() {}").unwrap();
    fs::write(root.join("src/ routes.gen.tsx"), "export function Gen() {}").unwrap();
    fs::write(
        root.join("generated/Types.tsx"),
        "export function Types() {}",
    )
    .unwrap();
    fs::write(
        root.join("scratch/Draft.tsx"),
        "export function Draft() {}",
    )
    .unwrap();

    let (_, sources) = scan_workspace(&ScanOptions {
        paths: vec![root.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut files: Vec<PathBuf> = sources.into_keys().collect();
    files.sort();
    assert_eq!(files, vec![root.join("src/App.tsx")]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scanner_respects_parent_gitignore_when_scanning_subdirectory() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-scanner-parent-{nanos}"));
    let sub = root.join("packages/web/src");
    fs::create_dir_all(sub.join("generated")).unwrap();
    fs::create_dir_all(sub.join("components")).unwrap();

    fs::write(
        root.join(".gitignore"),
        "*.generated.tsx\npackages/web/src/generated/\n",
    )
    .unwrap();
    fs::write(
        root.join("packages/.ignore"),
        "IgnoredByParentIgnore.tsx\n",
    )
    .unwrap();
    fs::write(
        sub.join("components/Button.tsx"),
        "export function Button() {}",
    )
    .unwrap();
    fs::write(
        sub.join("components/schema.generated.tsx"),
        "export function Schema() {}",
    )
    .unwrap();
    fs::write(
        sub.join("components/IgnoredByParentIgnore.tsx"),
        "export function Ignored() {}",
    )
    .unwrap();
    fs::write(
        sub.join("generated/Api.tsx"),
        "export function Api() {}",
    )
    .unwrap();

    let (_, sources) = scan_workspace(&ScanOptions {
        paths: vec![sub.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut files: Vec<PathBuf> = sources.into_keys().collect();
    files.sort();
    assert_eq!(files, vec![sub.join("components/Button.tsx")]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scanner_skips_gitignored_explicit_file_paths_and_globs() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-scanner-explicit-{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::create_dir_all(root.join("generated/nested")).unwrap();

    fs::write(
        root.join(".gitignore"),
        "generated/\n*.ignored.tsx\nsrc/Secret.tsx\n!src/Allowed.ignored.tsx\n",
    )
    .unwrap();
    fs::write(root.join("src/.ignore"), "LocalIgnored.tsx\n").unwrap();
    fs::write(root.join("generated/.gitignore"), "!**/Gen.tsx\n").unwrap();

    let app = root.join("src/App.tsx");
    let allowed_negated = root.join("src/Allowed.ignored.tsx");
    let ignored_ext = root.join("src/ Temp.ignored.tsx");
    let secret = root.join("src/Secret.tsx");
    let dotdot_secret = root.join("src/../src/Secret.tsx");
    let local_ignored = root.join("src/LocalIgnored.tsx");
    let in_generated = root.join("generated/nested/Gen.tsx");
    let in_dist = root.join("dist/Bundle.js");

    for p in [
        &app,
        &allowed_negated,
        &ignored_ext,
        &secret,
        &local_ignored,
        &in_generated,
        &in_dist,
    ] {
        fs::write(p, "export function Comp() {}").unwrap();
    }

    let (_, sources) = scan_workspace(&ScanOptions {
        paths: vec![
            app.clone(),
            allowed_negated.clone(),
            ignored_ext,
            secret,
            dotdot_secret,
            local_ignored,
            in_generated,
            in_dist,
        ],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut files: Vec<PathBuf> = sources.into_keys().collect();
    files.sort();
    assert_eq!(files, vec![allowed_negated, app]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scanner_excludes_vendor_and_docs_while_retaining_config_files() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-scanner-vendor-docs-{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("vendor/legacy")).unwrap();
    fs::create_dir_all(root.join("docs/examples")).unwrap();

    let app = root.join("src/App.tsx");
    let next_config = root.join("next.config.mjs");
    let vite_config = root.join("vite.config.ts");
    let vendor_file = root.join("vendor/legacy/Widget.tsx");
    let docs_file = root.join("docs/examples/Demo.tsx");

    for p in [&app, &next_config, &vite_config, &vendor_file, &docs_file] {
        fs::write(p, "export default {}").unwrap();
    }

    let (_, sources) = scan_workspace(&ScanOptions {
        paths: vec![root.clone()],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let mut files: Vec<PathBuf> = sources.into_keys().collect();
    files.sort();
    assert_eq!(files, vec![next_config, app.clone(), vite_config]);

    // Also verify explicit paths inside vendor/ or docs/ are skipped
    let (_, explicit_sources) = scan_workspace(&ScanOptions {
        paths: vec![app.clone(), vendor_file, docs_file],
        include_tests: false,
        rules: None,
        tiers: None,
    })
    .unwrap();
    let explicit_files: Vec<PathBuf> = explicit_sources.into_keys().collect();
    assert_eq!(explicit_files, vec![app]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cli_check_supports_json_no_fail_rule_and_tier_filters() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("dotore-cli-test-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Form.tsx");
    fs::write(
        &file_path,
        r#"function Form({ firstName, lastName }) {
  const [fullName, setFullName] = useState('');
  useEffect(() => {
    setFullName(firstName + ' ' + lastName);
  }, [firstName, lastName]);
  return <div>{fullName}</div>;
}"#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_dotore");

    let check_out = Command::new(bin).arg(&file_path).output().unwrap();
    assert_eq!(check_out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&check_out.stdout);
    assert!(stdout.contains("[no-derived-state] (autofix)"));

    let no_fail_out = Command::new(bin)
        .args(["check", "--no-fail", "--json"])
        .arg(&file_path)
        .output()
        .unwrap();
    assert_eq!(no_fail_out.status.code(), Some(0));
    let json_stdout = String::from_utf8_lossy(&no_fail_out.stdout);
    assert!(json_stdout.contains("\"total_diagnostics\": 1"));

    let filtered_out = Command::new(bin)
        .args([
            "check",
            "--rule",
            "no-initialize-state",
            "--tier",
            "surgical",
        ])
        .arg(&file_path)
        .output()
        .unwrap();
    assert_eq!(filtered_out.status.code(), Some(0));

    let _ = fs::remove_dir_all(&root);
}
