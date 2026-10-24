//! Cross-file JSX **Caller Site** indexing and intra-**Subject** multi-effect **Render Cascade** linking.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::Serialize;

use dotore_core::ir::ResolvedCallerSite;

use crate::ir::{ByteSpan, CallerSite, DepsSpec, EffectNode, FileIr, SourceLoc, SubjectIr};

use super::{
    ProjectGraph,
    resolution::{
        CompiledPathMapping, IndexedTargetFile, PackageManifestInfo,
        resolve_specifier_to_target_indices,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ComponentTarget {
    pub file: PathBuf,
    pub component_name: String,
}

/// Intra-**Subject** multi-effect **Render Cascade** where one **Effect Node** writes to an
/// intermediate **State Slot** that triggers a second **Effect Node** to update another **State Slot**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MultiEffectCascade {
    /// Index of the upstream **Effect Node** within `SubjectIr::effect_nodes`.
    pub first_effect_index: usize,
    /// Index of the downstream **Effect Node** within `SubjectIr::effect_nodes`.
    pub second_effect_index: usize,
    /// Index of the intermediate **State Slot** written by the first effect.
    pub intermediate_slot_index: usize,
    /// Display name of the intermediate **State Slot**.
    pub intermediate_state_name: String,
    /// Index of the final **State Slot** written by the second effect.
    pub final_slot_index: usize,
    /// Display name of the final **State Slot**.
    pub final_state_name: String,
    /// 1-based source location of the downstream setter call.
    pub loc: SourceLoc,
    /// Byte span of the downstream setter call.
    pub span: ByteSpan,
    /// Ordered **Render Cascade** flow steps across both effects.
    pub steps: Vec<String>,
}

impl ProjectGraph {
    /// Returns all resolved JSX **Caller Sites** rendering `component_name` declared in `target_file`.
    #[must_use]
    pub fn callers_of(&self, target_file: &Path, component_name: &str) -> Vec<ResolvedCallerSite> {
        let key = ComponentTarget {
            file: target_file.to_path_buf(),
            component_name: component_name.to_string(),
        };
        self.callers_by_target
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Resolves a component's transitive `children`-forwarding JSX target across same-file and imported declarations.
    #[must_use]
    pub(crate) fn resolve_children_forwarding_target(
        &self,
        start_file: &FileIr,
        component_name: &str,
        is_imported: bool,
    ) -> Option<String> {
        let mut current_file = start_file;
        let mut current_name = component_name.to_string();
        let mut must_follow_import = is_imported;

        for _ in 0..8 {
            if !must_follow_import {
                let Some((_, next_target)) = current_file
                    .module
                    .component_children_targets
                    .iter()
                    .find(|(c, _)| c == &current_name)
                else {
                    break;
                };
                current_name = next_target.clone();
                must_follow_import = current_file
                    .module
                    .imports
                    .iter()
                    .any(|imp| imp.specifiers.contains(&current_name));
                continue;
            }
            let resolved_import = current_file
                .module
                .imports
                .iter()
                .flat_map(|imp| imp.bindings.iter().map(move |b| (imp, b)))
                .find(|(_, b)| b.local_name == current_name && !b.is_namespace && !b.is_type_only)
                .map(|(imp, b)| (imp.source.as_str(), b.imported_name.as_str()));

            let Some((specifier, exported_name)) = resolved_import else {
                break;
            };
            if !specifier.starts_with('.') && !specifier.starts_with('/') {
                break;
            }

            let Some(target_file) = self.find_imported_file(&current_file.path, specifier) else {
                break;
            };
            current_file = target_file;
            if exported_name != "default" {
                current_name = exported_name.to_string();
            }
            must_follow_import = false;
        }

        (current_name != component_name).then_some(current_name)
    }

    /// Resolves a JSX element (`caller_file`, `jsx_span`, `component_name`) to its target
    /// `(&FileIr, &SubjectIr)` in the [`ProjectGraph`], if declared in the analyzed files.
    #[must_use]
    pub(crate) fn resolve_target_subject(
        &self,
        caller_file: &Path,
        jsx_span: ByteSpan,
        component_name: &str,
    ) -> Option<(&FileIr, &SubjectIr)> {
        for (target_key, callers) in &self.callers_by_target {
            if callers
                .iter()
                .any(|c| c.caller_file == caller_file && c.span == jsx_span)
                && let Some(target_file) = self.files.iter().find(|f| f.path == target_key.file)
                && let Some(target_subj) = target_file
                    .subjects
                    .iter()
                    .find(|s| s.name.as_deref() == Some(target_key.component_name.as_str()))
            {
                return Some((target_file, target_subj));
            }
        }

        let same_file = self.files.iter().find(|f| f.path == caller_file)?;
        let same_subj = same_file
            .subjects
            .iter()
            .find(|s| s.name.as_deref() == Some(component_name))?;
        Some((same_file, same_subj))
    }
}

/// Finds all multi-effect **Render Cascades** inside `subject`.
#[must_use]
pub(crate) fn find_multi_effect_cascades(subject: &SubjectIr) -> Vec<MultiEffectCascade> {
    let mut cascades = Vec::new();
    for first in &subject.effect_nodes {
        if first.has_cleanup {
            continue;
        }
        for second in &subject.effect_nodes {
            if second.has_cleanup || first.index == second.index {
                continue;
            }
            collect_cascades_between_effects(first, second, &mut cascades);
        }
    }
    cascades
}

fn collect_cascades_between_effects(
    first: &EffectNode,
    second: &EffectNode,
    out: &mut Vec<MultiEffectCascade>,
) {
    let DepsSpec::Tracked(deps) = &second.deps else {
        return;
    };
    for first_call in &first.sync_setter_calls {
        let Some(mid_idx) = first_call.state_slot_index else {
            continue;
        };
        if !deps
            .iter()
            .any(|d| d.upstream_state_indices.contains(&mid_idx))
        {
            continue;
        }
        for second_call in &second.sync_setter_calls {
            let Some(final_idx) = second_call.state_slot_index else {
                continue;
            };
            if final_idx == mid_idx {
                continue;
            }
            out.push(MultiEffectCascade {
                first_effect_index: first.index,
                second_effect_index: second.index,
                intermediate_slot_index: mid_idx,
                intermediate_state_name: first_call.state_name.clone(),
                final_slot_index: final_idx,
                final_state_name: second_call.state_name.clone(),
                loc: second_call.loc,
                span: second_call.call_span,
                steps: vec![
                    "Render #1 (initial render)".to_string(),
                    format!(
                        "Effect #{} sets intermediate state {:?}",
                        first.index + 1,
                        first_call.state_name
                    ),
                    format!("Render #2 ({:?} updated)", first_call.state_name),
                    format!(
                        "Effect #{} tracks {:?} -> sets {:?}",
                        second.index + 1,
                        first_call.state_name,
                        second_call.state_name
                    ),
                    format!("Render #3 ({:?} updated)", second_call.state_name),
                ],
            });
        }
    }
}

pub(super) fn index_file_caller_sites(
    caller_file: &FileIr,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
    out: &mut HashMap<ComponentTarget, Vec<ResolvedCallerSite>>,
) {
    for site in &caller_file.caller_sites {
        let resolved = ResolvedCallerSite {
            caller_file: caller_file.path.clone(),
            parent_subject_name: site.parent_subject_name.clone(),
            component_name: site.component_name.clone(),
            loc: site.loc,
            span: site.span,
            has_key: site.has_key,
            passed_props: site.passed_props.clone(),
        };

        for target in
            resolve_caller_targets(&caller_file.path, site, targets, ts_mappings, pkg_manifests)
        {
            out.entry(target).or_default().push(resolved.clone());
        }
    }
}

fn resolve_caller_targets(
    caller_path: &Path,
    site: &CallerSite,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<ComponentTarget> {
    if let Some(specifier) = &site.import_source {
        let matched = match_targets_by_specifier(
            caller_path,
            specifier,
            &site.component_name,
            targets,
            ts_mappings,
            pkg_manifests,
        );
        if !matched.is_empty() {
            return matched;
        }
    } else if let Some(same_file) = targets
        .iter()
        .find(|t| t.path == caller_path && t.component_names.contains(&site.component_name))
    {
        return vec![ComponentTarget {
            file: same_file.path.clone(),
            component_name: site.component_name.clone(),
        }];
    }

    targets
        .iter()
        .filter(|t| t.component_names.contains(&site.component_name))
        .map(|t| ComponentTarget {
            file: t.path.clone(),
            component_name: site.component_name.clone(),
        })
        .collect()
}

fn match_targets_by_specifier(
    caller_path: &Path,
    specifier: &str,
    component_name: &str,
    targets: &[IndexedTargetFile],
    ts_mappings: &[CompiledPathMapping],
    pkg_manifests: &[PackageManifestInfo],
) -> Vec<ComponentTarget> {
    let resolved_indices = resolve_specifier_to_target_indices(
        caller_path,
        specifier,
        targets,
        ts_mappings,
        pkg_manifests,
    );
    let mut out = Vec::new();
    for idx in resolved_indices {
        let target = &targets[idx];
        if target.component_names.iter().any(|p| p == component_name) {
            out.push(ComponentTarget {
                file: target.path.clone(),
                component_name: component_name.to_string(),
            });
        } else if let [single_name] = target.component_names.as_slice() {
            out.push(ComponentTarget {
                file: target.path.clone(),
                component_name: single_name.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::ir::parse_file_ir;

    #[test]
    fn links_cross_file_caller_sites_and_multi_effect_cascades() {
        let child = parse_file_ir(
            Path::new("src/Editor.tsx"),
            r#"
import { useState, useEffect } from "react";
export function Editor({ docId }: { docId: string }) {
    const [raw, setRaw] = useState("");
    const [parsed, setParsed] = useState("");
    useEffect(() => { setRaw(docId); }, [docId]);
    useEffect(() => { setParsed(raw.trim()); }, [raw]);
    return <div>{parsed}</div>;
}
"#,
        );
        let parent = parse_file_ir(
            Path::new("src/Page.tsx"),
            r#"
import { Editor } from "./Editor";
export function Page() {
    return <Editor docId="abc" />;
}
"#,
        );

        let cascades = find_multi_effect_cascades(&child.subjects[0]);
        assert_eq!(cascades.len(), 1);
        assert_eq!(cascades[0].intermediate_state_name, "raw");
        assert_eq!(cascades[0].final_state_name, "parsed");

        let graph = ProjectGraph::build(vec![child, parent]);
        let callers = graph.callers_of(Path::new("src/Editor.tsx"), "Editor");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].caller_file, Path::new("src/Page.tsx"));
        assert_eq!(callers[0].parent_subject_name.as_deref(), Some("Page"));
        assert_eq!(callers[0].passed_props, vec!["docId".to_string()]);
    }
}
