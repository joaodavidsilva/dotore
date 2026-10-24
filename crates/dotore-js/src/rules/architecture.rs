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
mod soc_rules;

use std::collections::HashSet;

use oxc_ast::AstKind;
use oxc_semantic::{NodeId, Semantic};

pub(crate) use self::context_and_boundaries::evaluate_architecture_project_graph_rules;
pub(crate) use self::soc_rules::{
    evaluate_file_soc_rules, extract_reuse_architecture_facets, extract_soc_architecture_facets,
};
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

    #[test]
    fn reuse_rules_respect_thresholds_suppressions_and_project_graph_planner_exemplars() {
        use std::{collections::HashMap, path::PathBuf};

        use crate::{
            config::{CapabilityGate, DotoreConfig, WorkspacePackage},
            planner::{PlannerContext, build_root_cause_groups_and_capsules},
            rules::evaluate_project_with_packages,
        };

        let ui_src = r#"export const BOX_TOP = "┌────────┐";
export const ANSI_RESET = "\u001b[0m";
"#;
        let build_runner_src = r#"function parseEntry(line: string, sep: string): string {
    const trimmed = line.trim();
    if (!trimmed) {
        return sep;
    }
    const idx = trimmed.indexOf(sep);
    return idx >= 0 ? trimmed.slice(idx + 1) : trimmed;
}

export class SpanConfig {
    constructor(public opts: Record<string, unknown>) {}
}

export function runBuild(raw: string): SpanConfig {
    const msg = "\033[33m│ building │\033[0m";
    // dotore-disable-next-line arch-no-inline-terminal-ui-primitives
    const ignored = "\x1b[32mOK\x1b[0m";
    void msg;
    void ignored;
    return new SpanConfig({
        name: parseEntry(raw, ":"),
        timeout: 0,
        retries: 0,
        tags: [],
        metadata: {},
    });
}
"#;
        let deploy_runner_src = r#"function extractValue(input: string, delimiter: string): string {
    const clean = input.trim();
    if (!clean) {
        return delimiter;
    }
    const pos = clean.indexOf(delimiter);
    return pos >= 0 ? clean.slice(pos + 1) : clean;
}

import { SpanConfig } from "./build_runner";

export function runDeploy(raw: string): SpanConfig[] {
    const first = new SpanConfig({
        name: extractValue(raw, "="),
        timeout: 0,
        retries: 0,
        tags: [],
        metadata: {},
    });
    const second = new SpanConfig({
        name: "fallback",
        timeout: 0,
        retries: 0,
        tags: [],
        metadata: {},
    });
    return [first, second];
}
"#;

        let files = vec![
            parse_file_ir(Path::new("src/ui/ansi_box.ts"), ui_src),
            parse_file_ir(Path::new("src/build_runner.ts"), build_runner_src),
            parse_file_ir(Path::new("src/deploy_runner.ts"), deploy_runner_src),
        ];
        assert!(files[0].architecture_facets.is_ui_kit_module);
        // `build_runner.ts` contains "ui" inside "build", which must NOT be treated as a UI kit module
        assert!(!files[1].architecture_facets.is_ui_kit_module);

        let graph = ProjectGraph::build(files);
        assert!(
            graph
                .architecture_facets_for_file(Path::new("src/ui/ansi_box.ts"))
                .is_some_and(|f| f.is_ui_kit_module)
        );

        let pkg = WorkspacePackage {
            name: "cli".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: CapabilityGate::default_react(),
            config: DotoreConfig::default(),
        };

        let reuse_rules = [
            RuleId::ArchNoDuplicatedHelperLogic,
            RuleId::ArchPreferFluentBuilder,
            RuleId::ArchNoInlineTerminalUiPrimitives,
        ];
        let diags =
            evaluate_project_with_packages(&graph, std::slice::from_ref(&pkg), Some(&reuse_rules));

        assert!(
            diags
                .iter()
                .any(|d| d.rule == RuleId::ArchNoDuplicatedHelperLogic)
        );
        assert!(
            diags
                .iter()
                .any(|d| d.rule == RuleId::ArchPreferFluentBuilder && d.target_name == "SpanConfig")
        );
        let ui_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.rule == RuleId::ArchNoInlineTerminalUiPrimitives)
            .collect();
        // Only `msg` is flagged; `ignored` is suppressed by `// dotore-disable-next-line`
        assert_eq!(ui_diags.len(), 1);

        let mut sources = HashMap::new();
        sources.insert(PathBuf::from("src/ui/ansi_box.ts"), ui_src.to_string());
        sources.insert(
            PathBuf::from("src/build_runner.ts"),
            build_runner_src.to_string(),
        );
        sources.insert(
            PathBuf::from("src/deploy_runner.ts"),
            deploy_runner_src.to_string(),
        );

        let (groups, capsules) = build_root_cause_groups_and_capsules(&graph, &diags, &sources);
        assert_eq!(groups.len(), 3);
        assert_eq!(capsules.len(), 3);
        let ui_cap = capsules
            .iter()
            .find(|c| c.rule == RuleId::ArchNoInlineTerminalUiPrimitives)
            .expect("ui capsule");
        assert_eq!(
            ui_cap.exemplar.as_ref().map(|e| &e.file),
            Some(&PathBuf::from("src/ui/ansi_box.ts"))
        );

        // Raising thresholds in `config.architecture` suppresses helper & builder findings
        let mut high_threshold_pkg = pkg;
        high_threshold_pkg.config.architecture.min_helper_statements = 20;
        high_threshold_pkg.config.architecture.min_builder_sites = 10;
        let high_diags = evaluate_project_with_packages(
            &graph,
            std::slice::from_ref(&high_threshold_pkg),
            Some(&[
                RuleId::ArchNoDuplicatedHelperLogic,
                RuleId::ArchPreferFluentBuilder,
            ]),
        );
        assert!(high_diags.is_empty());
    }
}
