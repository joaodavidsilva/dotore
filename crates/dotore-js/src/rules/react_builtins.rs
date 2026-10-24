//! `react-builtins` rule family detectors (`exhaustive-deps` with local callback ownership,
//! `rules-of-hooks`, `button-has-type` with `Autofix`, `checked-requires-onchange-or-readonly`,
//! `only-export-components`, `jsx-no-target-blank`, `self-closing-comp`, `jsx-boolean-value`,
//! `jsx-curly-brace-presence`, `jsx-no-script-url`, `style-prop-object`, `no-unknown-property`,
//! `no-string-refs`, and cross-file `ProjectGraph` cold-path gating for inline prop rules).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

mod components_and_classes;
mod hooks;
mod jsx_props_and_fragments;

use std::path::Path;

use oxc_ast::ast::Expression;
use oxc_semantic::Semantic;

pub(crate) use jsx_props_and_fragments::evaluate_inline_prop_rules_with_graph;

use crate::{ir::SemanticRuleSite, matchers::unparenthesized};

use components_and_classes::{
    check_class_and_component_builtin_rules_in_file, check_only_export_components_in_file,
};
use hooks::{check_exhaustive_deps_in_file, check_rules_of_hooks_in_file};
use jsx_props_and_fragments::check_jsx_builtin_rules_in_file;

const DEPS_HOOK_NAMES: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useMemo",
    "useCallback",
    "useImperativeHandle",
    "useInsertionEffect",
];

const MAX_JSX_DEPTH: usize = 4;

const UNKNOWN_DOM_PROP_FIXES: &[(&str, &str)] = &[
    ("class", "className"),
    ("for", "htmlFor"),
    ("tabindex", "tabIndex"),
    ("autocomplete", "autoComplete"),
    ("autofocus", "autoFocus"),
    ("readonly", "readOnly"),
    ("maxlength", "maxLength"),
    ("minlength", "minLength"),
    ("colspan", "colSpan"),
    ("rowspan", "rowSpan"),
    ("stroke-width", "strokeWidth"),
    ("stroke-linecap", "strokeLinecap"),
    ("stroke-linejoin", "strokeLinejoin"),
    ("fill-rule", "fillRule"),
    ("clip-rule", "clipRule"),
];

pub(super) fn strip_ts_and_parens<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    unparenthesized(expr)
}

/// Extracts all single-pass `react-builtins` semantic rule sites and autofixes.
pub(crate) fn extract_react_builtins_sites(
    semantic: &Semantic<'_>,
    path: &Path,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_exhaustive_deps_in_file(semantic, line_starts, sites);
    check_rules_of_hooks_in_file(semantic, line_starts, sites);
    check_jsx_builtin_rules_in_file(semantic, line_starts, sites);
    check_only_export_components_in_file(semantic, path, line_starts, sites);
    check_class_and_component_builtin_rules_in_file(semantic, line_starts, sites);
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::*;
    use crate::{
        graph::ProjectGraph,
        ir::{compute_line_starts, parse_file_ir},
        rules::types::{Diagnostic, RuleId, RuleSeverity},
    };

    #[test]
    fn extract_react_builtins_sites_covers_hooks_jsx_and_components() {
        let src = r#"
import React, { useState, useEffect, memo } from "react";

export const helperFn = () => 42;

export function Dashboard({ count }: { count: number }) {
    const [val, updateVal] = useState(0);
    if (count > 0) {
        useEffect(() => {}, []);
    }
    useEffect(() => {
        console.log(count, val);
    }, []);
    function NestedWidget() {
        return <span />;
    }
    return (
        <form>
            <button>Submit</button>
            <a href="https://example.com" target="_blank">Link</a>
            <div class="box" disabled={true} title={"hi"} />
            <><NestedWidget></NestedWidget></>
        </form>
    );
}

export const AnonMemo = memo((props: { label: string }) => <div>{props.label}</div>);
"#;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let semantic = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let line_starts = compute_line_starts(src);
        let mut sites = Vec::new();

        extract_react_builtins_sites(&semantic, Path::new("src/Dashboard.tsx"), &line_starts, &mut sites);

        let rules: Vec<RuleId> = sites.iter().map(|s| s.rule).collect();
        // Hooks submodule
        assert!(rules.contains(&RuleId::HookUseState));
        assert!(rules.contains(&RuleId::RulesOfHooks));
        assert!(rules.contains(&RuleId::ExhaustiveDeps));
        // JSX props and fragments submodule
        assert!(rules.contains(&RuleId::ButtonHasType));
        assert!(rules.contains(&RuleId::JsxNoTargetBlank));
        assert!(rules.contains(&RuleId::NoUnknownProperty));
        assert!(rules.contains(&RuleId::JsxBooleanValue));
        assert!(rules.contains(&RuleId::JsxCurlyBracePresence));
        assert!(rules.contains(&RuleId::JsxNoUselessFragment));
        assert!(rules.contains(&RuleId::SelfClosingComp));
        // Components and classes submodule
        assert!(rules.contains(&RuleId::OnlyExportComponents));
        assert!(rules.contains(&RuleId::NoUnstableNestedComponents));
        assert!(rules.contains(&RuleId::DisplayName));
    }

    #[test]
    fn evaluate_inline_prop_rules_with_graph_flags_memoized_target() {
        let child_src = r#"
import { memo } from "react";
export const ChildCard = memo(function ChildCard(props: {
    config: { a: number };
    items: number[];
    onClick: () => void;
}) {
    return <div>{props.config.a + props.items.length}</div>;
});
"#;
        let parent_src = r#"
import { ChildCard } from "./ChildCard";
export function ParentView() {
    return (
        <ChildCard
            config={{ a: 1 }}
            items={[1, 2, 3]}
            onClick={() => {}}
        />
    );
}
"#;
        let child_ir = parse_file_ir(Path::new("src/ChildCard.tsx"), child_src);
        let parent_ir = parse_file_ir(Path::new("src/ParentView.tsx"), parent_src);
        let graph = ProjectGraph::build(vec![child_ir, parent_ir]);
        let parent_file = graph
            .files
            .iter()
            .find(|f| f.path == Path::new("src/ParentView.tsx"))
            .expect("ParentView.tsx should exist in graph");

        let mut diags: Vec<Diagnostic> = Vec::new();
        for jsx in &parent_file.jsx_elements {
            evaluate_inline_prop_rules_with_graph(
                &graph,
                parent_file,
                jsx,
                &|_| Some(RuleSeverity::Warning),
                &mut diags,
            );
        }

        let rules: Vec<RuleId> = diags.iter().map(|d| d.rule).collect();
        assert!(rules.contains(&RuleId::JsxNoNewObjectAsProp));
        assert!(rules.contains(&RuleId::JsxNoNewArrayAsProp));
        assert!(rules.contains(&RuleId::JsxNoNewFunctionAsProp));
        assert!(rules.contains(&RuleId::NoInlinePropOnMemoComponent));
    }
}
