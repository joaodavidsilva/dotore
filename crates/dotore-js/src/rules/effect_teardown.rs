//! Effect Node teardown and React component, hook, and JSX correctness rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; rule dispatcher and shared helpers forward site metadata"
)]

mod dom_and_timer_teardown;
mod hook_and_state_correctness;
mod jsx_and_lint_parity;

use std::{collections::HashSet, path::Path};

use oxc_ast::AstKind;
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::{
    ir::{SemanticRuleSite, SubjectIr, react_ast::find_enclosing_react_node},
    matchers::{push_semantic_site, push_semantic_site_with_fix},
    rules::types::{AutofixPatch, RuleId},
};

pub(super) const EFFECT_HOOKS: &[&str] = &["useEffect", "useLayoutEffect", "useInsertionEffect"];

pub(super) const DEPS_HOOKS: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useInsertionEffect",
    "useMemo",
    "useCallback",
    "useImperativeHandle",
];

pub(super) const OBSERVER_CLASSES: &[&str] = &[
    "ResizeObserver",
    "IntersectionObserver",
    "MutationObserver",
    "PerformanceObserver",
];

pub(super) const VOID_DOM_TAGS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
    "source", "track", "wbr",
];

pub(super) const BOOLEAN_DOM_ATTRIBUTES: &[&str] = &[
    "allowFullScreen",
    "async",
    "autoFocus",
    "autoPlay",
    "checked",
    "controls",
    "defaultChecked",
    "defer",
    "disabled",
    "formNoValidate",
    "hidden",
    "inert",
    "ismap",
    "itemScope",
    "loop",
    "multiple",
    "muted",
    "noModule",
    "noValidate",
    "novalidate",
    "open",
    "playsInline",
    "readOnly",
    "readonly",
    "required",
    "reversed",
    "selected",
];

pub(super) const FORBIDDEN_ELEMENTS: &[&str] = &[
    "acronym",
    "applet",
    "basefont",
    "bgsound",
    "big",
    "blink",
    "center",
    "dir",
    "font",
    "frame",
    "frameset",
    "isindex",
    "keygen",
    "marquee",
    "multicol",
    "nextid",
    "nobr",
    "noembed",
    "noframes",
    "plaintext",
    "spacer",
    "strike",
    "tt",
    "xmp",
    "ForbiddenElement",
];

pub(super) const FORBIDDEN_DOM_PROPS: &[&str] = &[
    "alink",
    "background",
    "bgcolor",
    "border",
    "forbidProp",
    "forbiddenProp",
    "data-forbidden-prop",
    "frameborder",
    "marginheight",
    "marginwidth",
    "nowrap",
    "scrolling",
    "valign",
    "vlink",
];

pub(super) const INVALID_PARAGRAPH_CHILD_TAGS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "dd",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "search",
    "section",
    "table",
    "ul",
];

pub(super) const NATIVE_LABEL_CONTROLS: &[&str] = &[
    "button", "input", "meter", "output", "progress", "select", "textarea",
];

pub(super) const NONDETERMINISTIC_ID_CALLEES: &[&str] = &[
    "nanoid",
    "uuid",
    "uuidv4",
    "uuidV4",
    "v4",
    "uniqueId",
    "shortid",
    "cuid",
    "cuid2",
    "createId",
    "ulid",
];

pub(super) const BUILTIN_UPPERCASE_CALLS: &[&str] = &[
    "String",
    "Number",
    "Boolean",
    "BigInt",
    "Symbol",
    "Array",
    "Object",
    "Error",
    "TypeError",
    "RangeError",
    "SyntaxError",
    "Date",
    "RegExp",
    "Promise",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Int8Array",
    "Uint8Array",
    "Float32Array",
    "Float64Array",
];

pub(super) const ARRAY_MUTATING_METHODS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
    "set",
    "add",
    "delete",
    "clear",
];

/// Extracts all 68 Effect Node teardown and React correctness rule sites in a single pass.
pub(crate) fn extract_effect_teardown_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    jsx_and_lint_parity::check_file_level_rules(path, semantic, subjects, line_starts, sites);
    jsx_and_lint_parity::check_class_component_rules(semantic, line_starts, sites);

    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            hook_and_state_correctness::check_subject_effect_and_correctness_rules(
                semantic,
                subj_id,
                line_starts,
                sites,
            );
        }
    }

    jsx_and_lint_parity::check_ast_node_rules(semantic, subjects, line_starts, sites);
}

pub(super) fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl AsRef<str>,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    if autofix.is_some() {
        push_site_with_fix(
            sites,
            rule,
            subject_name,
            message_id,
            target_name.as_ref(),
            message,
            span,
            line_starts,
            autofix,
        );
    } else {
        push_semantic_site(
            sites,
            rule,
            subject_name,
            message_id,
            target_name.as_ref(),
            message,
            line_starts,
            span,
        );
    }
}

pub(super) fn push_site_with_fix(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl AsRef<str>,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    push_semantic_site_with_fix(
        sites,
        rule,
        subject_name,
        message_id,
        target_name.as_ref(),
        message,
        line_starts,
        span,
        autofix,
    );
}

pub(super) fn is_at_module_scope(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::MethodDefinition(_)
            | AstKind::PropertyDefinition(_)
            | AstKind::StaticBlock(_)
            | AstKind::TSTypeAnnotation(_)
            | AstKind::TSTypeReference(_)
            | AstKind::TSTypeQuery(_)
            | AstKind::TSInterfaceDeclaration(_)
            | AstKind::TSTypeAliasDeclaration(_) => return false,
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        ir::{extract::inspect_file_semantic, types::compute_line_starts},
        rules::RuleId,
    };

    use super::extract_effect_teardown_sites;

    fn run_effect_teardown(path_str: &str, source: &str) -> Vec<crate::ir::SemanticRuleSite> {
        let path = Path::new(path_str);
        inspect_file_semantic(path, source, |file_ir, semantic| {
            let line_starts = compute_line_starts(source);
            let mut sites = Vec::new();
            extract_effect_teardown_sites(
                path,
                semantic,
                &file_ir.subjects,
                &line_starts,
                &mut sites,
            );
            sites
        })
    }

    #[test]
    fn dom_and_timer_teardown_submodule_rules() {
        let source = r#"
import React, { useEffect, useMemo } from "react";

export function Widget() {
    const debounced = useMemo(() => debounce(() => {}, 100), []);
    useEffect(() => {
        const obs = new ResizeObserver(() => {});
        requestAnimationFrame(() => {});
        const onKey = () => {};
        window.addEventListener("keydown", onKey);
        return () => {
            window.removeEventListener("keyup", onKey);
        };
    }, []);
    return <div onClick={debounced} />;
}
"#;
        let sites = run_effect_teardown("Widget.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::DebounceNoCleanup));
        assert!(rules.contains(&RuleId::EffectObserverNeedsDisconnect));
        assert!(rules.contains(&RuleId::EffectRafLoopNeedsCancel));
        let mismatch = sites
            .iter()
            .find(|s| s.rule == RuleId::EffectListenerCleanupMismatch);
        assert!(mismatch.is_some());
        assert!(mismatch.is_some_and(|s| s.autofix.is_some()));
    }

    #[test]
    fn hook_and_state_correctness_submodule_rules() {
        let source = r#"
import React, { useEffect, useReducer, useState } from "react";

export function Counter({ refObj, blob }: { refObj: { current: number }; blob: Blob }) {
    const [open, setOpen] = useState(false);
    const [state, dispatch] = useReducer((prev, action) => {
        prev.count = action;
        return prev;
    }, { count: 0 });
    const url = URL.createObjectURL(blob);

    useEffect(() => {
        setOpen(!open);
    }, [NaN, refObj.current]);

    return <button onClick={() => dispatch(1)}>{url}{state.count}</button>;
}
"#;
        let sites = run_effect_teardown("Counter.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::HooksNoNanInDeps));
        assert!(rules.contains(&RuleId::NoMutableInDeps));
        assert!(rules.contains(&RuleId::NoMutatingReducerState));
        assert!(rules.contains(&RuleId::NoCreateObjectUrlInRender));
        assert!(rules.contains(&RuleId::NoBooleanToggleWithoutFunctionalUpdate));
    }

    #[test]
    fn jsx_and_lint_parity_submodule_rules() {
        let source = r#"
import React from "react";

const SEED = Math.random();

class LegacyBox extends React.PureComponent {
    componentDidMount() {
        window.addEventListener("resize", this.onResize);
    }
    shouldComponentUpdate() {
        return true;
    }
    render() {
        return (
            <div>
                <img src="/a.png">child</img>
                <button disabled="false">{SEED} unescaped ' quote</button>
            </div>
        );
    }
}
"#;
        let sites = run_effect_teardown("LegacyBox.tsx", source);
        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::NoImpureCallAtModuleScope));
        assert!(rules.contains(&RuleId::NoRedundantShouldComponentUpdate));
        assert!(rules.contains(&RuleId::ClassComponentMissingComponentWillUnmountTeardown));
        assert!(rules.contains(&RuleId::NoUnescapedEntities));

        let void_site = sites
            .iter()
            .find(|s| s.rule == RuleId::VoidDomElementsNoChildren);
        assert!(void_site.is_some_and(|s| s.autofix.is_some()));

        let bool_site = sites
            .iter()
            .find(|s| s.rule == RuleId::NoStringFalseOnBooleanAttribute);
        assert!(bool_site.is_some_and(|s| s.autofix.is_some()));
    }
}
