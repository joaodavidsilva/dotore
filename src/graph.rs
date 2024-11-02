//! Project-level graph of parsed [`FileIr`]s and resolved JSX **Caller Sites**.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use crate::ir::{
    ByteSpan, CallerSite, DepsSpec, EffectNode, FileIr, SourceLoc, SubjectIr, SubjectKind,
};

/// A resolved cross-file JSX **Caller Site** rendering a target **Subject**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedCallerSite {
    /// File containing the JSX element.
    pub caller_file: PathBuf,
    /// Enclosing parent **Subject** name, if any.
    pub parent_subject_name: Option<String>,
    /// Rendered component name.
    pub component_name: String,
    /// 1-based location of the JSX element.
    pub loc: SourceLoc,
    /// Byte span of the JSX opening element.
    pub span: ByteSpan,
    /// Whether `key={...}` is present on the JSX element.
    pub has_key: bool,
    /// Props passed at this **Caller Site**.
    pub passed_props: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ComponentTarget {
    file: PathBuf,
    component_name: String,
}

#[derive(Debug, Clone)]
struct IndexedTargetFile {
    path: PathBuf,
    stem: String,
    index_stem: Option<String>,
    component_names: Vec<String>,
}

const SOURCE_SUFFIXES: &[&str] = &[".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts"];

/// Whole-project graph wrapping parsed [`FileIr`]s.
#[derive(Debug, Default)]
pub(crate) struct ProjectGraph {
    /// Parsed IR for every file in scope.
    pub files: Vec<FileIr>,
    /// Resolved JSX **Caller Sites** indexed by target `(file, component_name)`.
    callers_by_target: HashMap<ComponentTarget, Vec<ResolvedCallerSite>>,
}

impl ProjectGraph {
    /// Builds a [`ProjectGraph`] from a list of parsed [`FileIr`]s.
    #[must_use]
    pub(crate) fn build(files: Vec<FileIr>) -> Self {
        let targets = collect_indexed_targets(&files);
        let mut callers_by_target: HashMap<ComponentTarget, Vec<ResolvedCallerSite>> =
            HashMap::new();

        for caller_file in &files {
            index_file_caller_sites(caller_file, &targets, &mut callers_by_target);
        }

        for list in callers_by_target.values_mut() {
            list.sort_by(|a, b| {
                (&a.caller_file, a.loc.line, a.loc.column).cmp(&(
                    &b.caller_file,
                    b.loc.line,
                    b.loc.column,
                ))
            });
        }

        Self {
            files,
            callers_by_target,
        }
    }

    /// Returns all resolved JSX **Caller Sites** rendering `component_name` declared in `target_file`.
    #[must_use]
    pub(crate) fn callers_of(
        &self,
        target_file: &Path,
        component_name: &str,
    ) -> Vec<ResolvedCallerSite> {
        let key = ComponentTarget {
            file: target_file.to_path_buf(),
            component_name: component_name.to_string(),
        };
        self.callers_by_target
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }
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

fn collect_indexed_targets(files: &[FileIr]) -> Vec<IndexedTargetFile> {
    files
        .iter()
        .map(|file| {
            let stem = normalize_module_stem(&file.path);
            let index_stem = stem.strip_suffix("/index").map(str::to_string);
            let component_names = file
                .subjects
                .iter()
                .filter(|s| s.kind == SubjectKind::Component)
                .filter_map(|s| s.name.clone())
                .collect();
            IndexedTargetFile {
                path: file.path.clone(),
                stem,
                index_stem,
                component_names,
            }
        })
        .collect()
}

fn index_file_caller_sites(
    caller_file: &FileIr,
    targets: &[IndexedTargetFile],
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

        for target in resolve_caller_targets(&caller_file.path, site, targets) {
            out.entry(target).or_default().push(resolved.clone());
        }
    }
}

fn resolve_caller_targets(
    caller_path: &Path,
    site: &CallerSite,
    targets: &[IndexedTargetFile],
) -> Vec<ComponentTarget> {
    if let Some(specifier) = &site.import_source {
        let matched =
            match_targets_by_specifier(caller_path, specifier, &site.component_name, targets);
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
) -> Vec<ComponentTarget> {
    let mut out = Vec::new();
    for target in targets {
        if !specifier_matches_target(caller_path, specifier, target) {
            continue;
        }
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

fn specifier_matches_target(
    caller_path: &Path,
    specifier: &str,
    target: &IndexedTargetFile,
) -> bool {
    if specifier.starts_with("./") || specifier.starts_with("../") {
        let parent = caller_path.parent().unwrap_or_else(|| Path::new(""));
        let resolved_stem = normalize_module_stem(&parent.join(specifier));
        return target_matches_stem(target, &resolved_stem);
    }
    if let Some(alias_rest) = specifier.strip_prefix("@/") {
        let clean_rest = strip_source_extension(&normalize_path_components(Path::new(alias_rest)));
        let src_rest = format!("src/{clean_rest}");
        return target_matches_stem_or_suffix(target, &clean_rest)
            || target_matches_stem_or_suffix(target, &src_rest);
    }
    false
}

fn target_matches_stem(target: &IndexedTargetFile, stem: &str) -> bool {
    target.stem == stem || target.index_stem.as_deref() == Some(stem)
}

fn target_matches_stem_or_suffix(target: &IndexedTargetFile, stem: &str) -> bool {
    if target_matches_stem(target, stem) {
        return true;
    }
    let slash_stem = format!("/{stem}");
    target.stem.ends_with(&slash_stem)
        || target
            .index_stem
            .as_deref()
            .is_some_and(|idx| idx.ends_with(&slash_stem))
}

fn normalize_module_stem(path: &Path) -> String {
    strip_source_extension(&normalize_path_components(path))
}

fn normalize_path_components(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut has_leading_root = false;

    for comp in path.components() {
        match comp {
            Component::RootDir => has_leading_root = true,
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|last| last != "..") {
                    parts.pop();
                } else if !has_leading_root {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(seg) => {
                if let Some(s) = seg.to_str() {
                    parts.push(s.to_string());
                }
            }
        }
    }

    let joined = parts.join("/");
    if has_leading_root {
        format!("/{joined}")
    } else {
        joined
    }
}

fn strip_source_extension(path_str: &str) -> String {
    for suffix in SOURCE_SUFFIXES {
        if let Some(stripped) = path_str.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    path_str.to_string()
}
