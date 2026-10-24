//! Deterministic remediation planner integration for `dotore-js`:
//! [`PlannerContext`] implementation for [`ProjectGraph`], cross-file **Caller Site**
//! autofix enrichment (`no-reset-all-state-on-prop-change`), and React/TypeScript
//! repository **Exemplar** discovery.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

pub use dotore_core::planner::{
    PlanResult, PlannerContext, build_fix_capsule, build_root_cause_groups_and_capsules,
    compute_root_cause_group_id, excerpt_from_span, find_architecture_exemplar_from_facets,
    format_plan_report, plan_project, slice_span, spans_intersect,
};

use crate::{
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{ArchitectureFileFacets, ByteSpan, DepsSpec, FileIr, SubjectIr},
    rules::{
        AutofixPatch, ByteEdit, Diagnostic, PrescriptionTier, RootCauseGroup, RuleId, SourceExcerpt,
    },
};

impl PlannerContext for ProjectGraph {
    fn analyzed_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self.files.iter().map(|f| f.path.clone()).collect();
        files.sort();
        files
    }

    fn subject_spans_for_file(&self, file: &Path) -> Vec<(Option<String>, ByteSpan)> {
        self.find_file_ir(file)
            .map(|f| {
                f.subjects
                    .iter()
                    .map(|s| (s.name.clone(), s.span))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn architecture_facets_for_file(&self, file: &Path) -> Option<&ArchitectureFileFacets> {
        self.find_file_ir(file).map(|f| &f.architecture_facets)
    }

    fn callers_of(&self, target_file: &Path, subject_name: &str) -> Vec<ResolvedCallerSite> {
        Self::callers_of(self, target_file, subject_name)
    }

    fn child_components_of(&self, file: &Path, subject_name: &str) -> Vec<String> {
        let Some(file_ir) = self.find_file_ir(file) else {
            return Vec::new();
        };
        file_ir
            .caller_sites
            .iter()
            .filter(|site| site.parent_subject_name.as_deref() == Some(subject_name))
            .map(|site| site.component_name.clone())
            .collect()
    }

    fn span_in_list_loop(&self, file: &Path, span: ByteSpan) -> bool {
        self.find_file_ir(file).is_some_and(|file_ir| {
            file_ir
                .jsx_elements
                .iter()
                .any(|jsx| jsx.in_array_map && spans_intersect(jsx.span, span))
        })
    }

    fn subject_rendered_in_list_loop(&self, target_file: &Path, subject_name: &str) -> bool {
        Self::callers_of(self, target_file, subject_name)
            .iter()
            .any(|caller| {
                self.find_file_ir(&caller.caller_file)
                    .is_some_and(|caller_file| {
                        caller_file
                            .jsx_elements
                            .iter()
                            .any(|jsx| jsx.in_array_map && spans_intersect(jsx.span, caller.span))
                    })
            })
    }
    fn count_context_consumers(
        &self,
        context_name: &str,
        sources: &HashMap<PathBuf, String>,
    ) -> usize {
        let use_ctx_pat = format!("useContext({context_name})");
        let use_pat = format!("use({context_name})");
        let mut count = 0_usize;

        for file in &self.files {
            if let Some(src) = sources.get(&file.path) {
                let matches_in_file =
                    src.matches(&use_ctx_pat).count() + src.matches(&use_pat).count();
                if matches_in_file > 0 {
                    count += matches_in_file;
                    continue;
                }
            }
            let imports_use_context = file.module.imports.iter().any(|imp| {
                imp.specifiers
                    .iter()
                    .any(|s| s == "useContext" || s == "use")
            });
            let imports_context = file
                .module
                .imports
                .iter()
                .any(|imp| imp.specifiers.iter().any(|s| s == context_name));
            if imports_use_context && imports_context {
                count += 1;
            }
        }

        count
    }

    fn find_rule_exemplar(
        &self,
        group: &RootCauseGroup,
        diagnostics: &[Diagnostic],
        sources: &HashMap<PathBuf, String>,
    ) -> Option<SourceExcerpt> {
        if group.rule.is_architecture_soc_or_reuse_rule() {
            if let Some(ex) =
                find_js_architecture_exemplar(&self.files, group, diagnostics, sources)
            {
                return Some(ex);
            }
            return None;
        }

        if !rule_has_js_subject_or_jsx_exemplar(group.rule) {
            return None;
        }

        for file in &self.files {
            let src = if !file.source.is_empty() {
                file.source.as_str()
            } else if let Some(s) = sources.get(&file.path) {
                s.as_str()
            } else {
                continue;
            };

            for subj in &file.subjects {
                if (file.path.as_path(), subj.name.as_deref())
                    == (group.file.as_path(), group.subject_name.as_deref())
                {
                    continue;
                }
                let Some(subj_src) = slice_span(src, subj.span) else {
                    continue;
                };
                if subject_matches_rule_exemplar(group.rule, subj, subj_src) {
                    return Some(excerpt_from_span(&file.path, src, subj.span));
                }
            }

            if matches!(group.rule, RuleId::JsxKey | RuleId::NoArrayIndexAsKey)
                && let Some(valid_jsx) = file
                    .jsx_elements
                    .iter()
                    .find(|j| j.in_array_map && j.has_key && !j.key_is_array_index)
            {
                return Some(excerpt_from_span(&file.path, src, valid_jsx.span));
            }
        }

        None
    }
}

const fn rule_has_js_subject_or_jsx_exemplar(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::JsxKey
            | RuleId::NoArrayIndexAsKey
            | RuleId::NoExternalStoreSubscription
            | RuleId::NoFetchInEffect
            | RuleId::QueryNoVoidQueryFn
            | RuleId::NoDerivedState
            | RuleId::NoChainStateUpdates
            | RuleId::NoAdjustStateOnPropChange
            | RuleId::NoInitializeState
            | RuleId::JsxNoNewObjectAsProp
            | RuleId::NoInlinePropOnMemoComponent
            | RuleId::ContextProviderValueFromUnmemoizedLocalLiteral
            | RuleId::JotaiSelectAtomInRenderBody
            | RuleId::ZustandNoWholeStoreDestructure
            | RuleId::MobxReactionDisposerDiscarded
    )
}

fn find_js_architecture_exemplar(
    sorted_files: &[FileIr],
    group: &RootCauseGroup,
    diagnostics: &[Diagnostic],
    sources: &HashMap<PathBuf, String>,
) -> Option<SourceExcerpt> {
    let flagged_for_rule: BTreeSet<&Path> = diagnostics
        .iter()
        .filter(|d| d.rule == group.rule)
        .map(|d| d.file.as_path())
        .collect();

    let candidates = sorted_files
        .iter()
        .filter(|f| f.path != group.file && !flagged_for_rule.contains(f.path.as_path()))
        .map(|f| {
            let primary_span = f
                .subjects
                .iter()
                .find(|s| s.name.is_some())
                .map(|s| s.span)
                .or_else(|| f.symbol_outlines.first().map(|sym| sym.span));
            (
                f.path.as_path(),
                f.source.as_str(),
                &f.architecture_facets,
                primary_span,
            )
        });

    find_architecture_exemplar_from_facets(group.rule, &group.file, candidates, sources)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only effect/memo/store rules have subject exemplar heuristics; remaining rules default to false"
)]
fn subject_matches_rule_exemplar(rule: RuleId, subj: &SubjectIr, subj_src: &str) -> bool {
    match rule {
        RuleId::NoExternalStoreSubscription => subj_src.contains("useSyncExternalStore("),
        RuleId::NoFetchInEffect | RuleId::QueryNoVoidQueryFn => {
            subj_src.contains("useQuery(") || subj_src.contains("useSuspenseQuery(")
        }
        RuleId::NoDerivedState
        | RuleId::NoChainStateUpdates
        | RuleId::NoAdjustStateOnPropChange => {
            subj.effect_nodes.is_empty() && subj_src.contains("const ")
        }
        RuleId::NoInitializeState => {
            subj.effect_nodes.is_empty()
                && subj.state_slots.iter().any(|s| s.init_arg_text.is_some())
        }
        RuleId::JsxNoNewObjectAsProp
        | RuleId::NoInlinePropOnMemoComponent
        | RuleId::ContextProviderValueFromUnmemoizedLocalLiteral
        | RuleId::JotaiSelectAtomInRenderBody => subj_src.contains("useMemo("),
        RuleId::ZustandNoWholeStoreDestructure => {
            subj_src.contains("Store((s") || subj_src.contains("Store((state")
        }
        RuleId::MobxReactionDisposerDiscarded => {
            subj.effect_nodes.iter().any(|e| e.has_cleanup)
                && (subj_src.contains("autorun(") || subj_src.contains("reaction("))
        }
        _ => false,
    }
}

/// Upgrades unambiguous cross-file `no-reset-all-state-on-prop-change` diagnostics to `Autofix`
/// when all resolved **Caller Sites** lack `key={...}` and pass the prop value explicitly.
pub fn enrich_cross_file_autofixes(
    graph: &ProjectGraph,
    diagnostics: &mut [Diagnostic],
    sources: &HashMap<PathBuf, String>,
) {
    for diag in diagnostics.iter_mut() {
        if diag.rule != RuleId::NoResetAllStateOnPropChange || diag.autofix.is_some() {
            continue;
        }
        if let Some(patch) = build_cross_file_prop_reset_autofix(graph, diag, sources) {
            diag.tier = PrescriptionTier::Autofix;
            diag.autofix = Some(patch);
        }
    }
}

fn build_cross_file_prop_reset_autofix(
    graph: &ProjectGraph,
    diag: &Diagnostic,
    sources: &HashMap<PathBuf, String>,
) -> Option<AutofixPatch> {
    if diag.caller_sites.is_empty() || diag.caller_sites.iter().any(|c| c.has_key) {
        return None;
    }

    let file_ir = graph.files.iter().find(|f| f.path == diag.file)?;
    let subject_name = diag.subject_name.as_deref()?;
    let subject = file_ir
        .subjects
        .iter()
        .find(|s| s.name.as_deref() == Some(subject_name))?;
    let effect = subject
        .effect_nodes
        .iter()
        .find(|e| e.call_span == diag.span)?;
    let eff_stmt_span = effect.stmt_span?;

    if effect.top_level_stmt_count != subject.state_slots.len() {
        return None;
    }
    let DepsSpec::Tracked(deps) = &effect.deps else {
        return None;
    };
    let mut tracked_props: BTreeSet<&str> = BTreeSet::new();
    for dep in deps {
        for prop in &dep.upstream_prop_names {
            tracked_props.insert(prop.as_str());
        }
    }
    if tracked_props.len() != 1 || !tracked_props.contains(diag.target_name.as_str()) {
        return None;
    }

    let mut edits = Vec::with_capacity(1 + diag.caller_sites.len());
    edits.push(ByteEdit {
        file: Some(diag.file.clone()),
        span: eff_stmt_span,
        replacement: String::new(),
    });

    for caller in &diag.caller_sites {
        if !caller.passed_props.contains(&diag.target_name) {
            return None;
        }
        let caller_source = sources.get(&caller.caller_file)?;
        let (insert_offset, key_attr_text) = extract_caller_key_injection(
            caller_source,
            caller.span,
            &caller.component_name,
            &diag.target_name,
        )?;
        edits.push(ByteEdit {
            file: Some(caller.caller_file.clone()),
            span: ByteSpan {
                start: insert_offset,
                end: insert_offset,
            },
            replacement: format!(" {key_attr_text}"),
        });
    }

    Some(
        AutofixPatch::new(format!(
            "Pass `key={{{}}}` at {} caller site(s) of `<{subject_name} />` and remove state-reset useEffect",
            diag.target_name,
            diag.caller_sites.len()
        ))
        .with_edits(edits),
    )
}

fn extract_caller_key_injection(
    caller_source: &str,
    opening_span: ByteSpan,
    component_name: &str,
    prop_name: &str,
) -> Option<(u32, String)> {
    let start = opening_span.start as usize;
    let end = opening_span.end as usize;
    if start >= end || end > caller_source.len() {
        return None;
    }
    let opening_text = caller_source.get(start..end)?;
    let expected_prefix = format!("<{component_name}");
    if !opening_text.starts_with(&expected_prefix) {
        return None;
    }
    if opening_text.contains("{...") {
        return None;
    }

    let prop_value_raw = extract_jsx_prop_raw_value(opening_text, prop_name)?;
    let insert_offset = opening_span.start + u32::try_from(expected_prefix.len()).ok()?;
    Some((insert_offset, format!("key={prop_value_raw}")))
}

fn extract_jsx_prop_raw_value(opening_text: &str, prop_name: &str) -> Option<String> {
    let bytes = opening_text.as_bytes();
    let needle = prop_name.as_bytes();
    let mut pos = 0;

    while pos + needle.len() < bytes.len() {
        let Some(rel) = opening_text[pos..].find(prop_name) else {
            break;
        };
        let idx = pos + rel;
        let before_ok = idx == 0 || bytes[idx - 1].is_ascii_whitespace();
        let after_idx = idx + needle.len();
        if before_ok && bytes.get(after_idx) == Some(&b'=') {
            let rest = opening_text.get(after_idx + 1..)?;
            return parse_jsx_attr_value_slice(rest);
        }
        pos = after_idx;
    }
    None
}

fn parse_jsx_attr_value_slice(rest: &str) -> Option<String> {
    if rest.starts_with('{') {
        let mut depth = 0_usize;
        for (offset, ch) in rest.char_indices() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(rest[..=offset].to_string());
                }
            }
        }
        return None;
    }
    let quote = rest.chars().next().filter(|&c| c == '"' || c == '\'')?;
    let end_quote = rest[1..].find(quote)?;
    Some(rest[..=end_quote + 1].to_string())
}
