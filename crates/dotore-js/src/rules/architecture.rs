//! `architecture` rule family detectors (`no-nested-component-definition`,
//! `prefer-module-scope-static-value` with `Autofix`, `prefer-module-scope-pure-function` with `Autofix`,
//! `react-compiler-no-manual-memoization`, `no-default-props`, `no-prop-types`,
//! `no-legacy-context-api`, `no-legacy-class-lifecycles`, `no-inline-hoc-on-component`,
//! `no-render-in-render`, `no-react-dom-deprecated-apis`) and cross-file `ProjectGraph` detectors
//! (`context-provider-value-from-unmemoized-local-literal`, `overloaded-context-provider`,
//! and `missing-suspense-or-error-boundary`).

mod component_contracts;
mod context_and_boundaries;
mod hoisting_and_compiler;

use std::collections::HashSet;

use oxc_ast::AstKind;
use oxc_semantic::{NodeId, Semantic};

pub(crate) use self::context_and_boundaries::evaluate_architecture_project_graph_rules;
use self::{
    component_contracts::check_module_and_expr_architecture_rules,
    context_and_boundaries::extract_context_sites_in_file,
    hoisting_and_compiler::check_subject_architecture_rules,
};
use crate::ir::{
    ContextConsumerSiteIr, ContextProviderSiteIr, SemanticRuleSite, SubjectIr,
    react_ast::find_enclosing_react_node,
};

/// Extracts single-pass `architecture` semantic rule sites, hoisting autofixes,
/// and `Context.Provider` / `useContext` IR records.
pub(crate) fn extract_architecture_sites(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
    context_providers: &mut Vec<ContextProviderSiteIr>,
    context_consumers: &mut Vec<ContextConsumerSiteIr>,
) {
    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            check_subject_architecture_rules(semantic, subj_id, line_starts, sites);
        }
    }

    check_module_and_expr_architecture_rules(semantic, line_starts, sites);
    extract_context_sites_in_file(
        semantic,
        subjects,
        line_starts,
        context_providers,
        context_consumers,
    );
}

pub(super) fn is_reference_in_jsx(semantic: &Semantic<'_>, ref_node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(ref_node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::JSXElement(_) | AstKind::JSXFragment(_) | AstKind::JSXExpressionContainer(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        graph::ProjectGraph,
        ir::parse_file_ir,
        rules::{RuleId, evaluate_project},
    };

    #[test]
    fn architecture_submodules_extract_hoisting_contracts_and_context_boundaries() {
        let src = r#"
import React, { createContext, useContext, useState } from "react";

const ThemeCtx = createContext({ mode: "dark", count: 0 });

export function App({
    isOpen = false,
    isAdmin = false,
    canEdit = false,
    shouldHighlight = false,
}: {
    isOpen?: boolean;
    isAdmin?: boolean;
    canEdit?: boolean;
    shouldHighlight?: boolean;
}) {
    const [count, setCount] = useState(0);
    const STATIC_OPTIONS = [{ label: "A" }, { label: "B" }];
    const formatTitle = (s: string) => s.toUpperCase();
    const handleClick = () => setCount((c) => c + 1);
    function NestedItem() {
        return <span />;
    }
    return (
        <ThemeCtx.Provider value={{ mode: "dark", count }}>
            <button onClick={handleClick}>{formatTitle("hi")}</button>
            <Select options={STATIC_OPTIONS} />
            <NestedItem />
        </ThemeCtx.Provider>
    );
}

App.defaultProps = { isOpen: false };

export function Consumer() {
    const { mode } = useContext(ThemeCtx);
    return <div>{mode}</div>;
}
"#;
        let file = parse_file_ir(Path::new("src/App.tsx"), src);
        let rules: Vec<RuleId> = file.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::PreferModuleScopeStaticValue));
        assert!(rules.contains(&RuleId::PreferModuleScopePureFunction));
        assert!(rules.contains(&RuleId::NoNestedComponentDefinition));
        assert!(rules.contains(&RuleId::NoManyBooleanProps));
        assert!(rules.contains(&RuleId::NoGenericHandlerNames));
        assert!(rules.contains(&RuleId::NoDefaultProps));
        assert_eq!(file.context_providers.len(), 1);
        assert_eq!(file.context_consumers.len(), 1);

        let graph = ProjectGraph::build(vec![file]);
        let diags = evaluate_project(
            &graph,
            Some(&[
                RuleId::ContextProviderValueFromUnmemoizedLocalLiteral,
                RuleId::OverloadedContextProvider,
            ]),
        );
        assert!(
            diags
                .iter()
                .any(|d| d.rule == RuleId::ContextProviderValueFromUnmemoizedLocalLiteral)
        );
        assert!(
            diags
                .iter()
                .any(|d| d.rule == RuleId::OverloadedContextProvider)
        );
    }
}
