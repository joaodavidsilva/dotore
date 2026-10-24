//! Duplicate JSX subtree family clustering and nested-subtree suppression (`duplicate-jsx-subtree`).

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::ir::{FileContext, FileIr};

use super::{DuplicateJsxFamilyFinding, DuplicateJsxOccurrence};

const JSX_DUP_MIN_NODE_COUNT: usize = 5;
const JSX_DUP_MIN_DEPTH: usize = 2;
const JSX_DUP_MIN_OCCURRENCES: usize = 2;

pub(super) fn detect_duplicate_jsx_families(files: &[FileIr]) -> Vec<DuplicateJsxFamilyFinding> {
    let mut buckets: HashMap<String, (usize, usize, Vec<DuplicateJsxOccurrence>)> = HashMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production {
            continue;
        }
        for sub in &file.jsx_subtrees {
            if sub.node_count < JSX_DUP_MIN_NODE_COUNT || sub.depth < JSX_DUP_MIN_DEPTH {
                continue;
            }
            let entry = buckets
                .entry(sub.fingerprint.clone())
                .or_insert_with(|| (sub.node_count, sub.depth, Vec::new()));
            entry.2.push(DuplicateJsxOccurrence {
                file_index: file_idx,
                path: file.path.clone(),
                root_name: sub.root_name.clone(),
                enclosing_subject: sub.enclosing_subject.clone(),
                composition_root_offset: sub.composition_root_offset,
                composition_path: sub.composition_path.clone(),
                span: sub.span,
                loc: sub.loc,
                end_line: sub.end_line,
            });
        }
    }

    let mut families = Vec::new();
    for (fingerprint, (node_count, depth, mut occurrences)) in buckets {
        if occurrences.len() < JSX_DUP_MIN_OCCURRENCES {
            continue;
        }
        occurrences.sort_by(|a, b| {
            (&a.path, a.span.start, a.span.end).cmp(&(&b.path, b.span.start, b.span.end))
        });
        let distinct_files: HashSet<&PathBuf> = occurrences.iter().map(|o| &o.path).collect();
        let distinct_file_count = distinct_files.len();
        if distinct_file_count == 1 {
            let distinct_roots: HashSet<u32> = occurrences
                .iter()
                .filter_map(|o| o.composition_root_offset)
                .collect();
            if distinct_roots.len() < 2 {
                continue;
            }
        }

        let total_lines: u32 = occurrences
            .iter()
            .map(|o| o.end_line.saturating_sub(o.loc.line) + 1)
            .sum();
        let max_single_lines: u32 = occurrences
            .iter()
            .map(|o| o.end_line.saturating_sub(o.loc.line) + 1)
            .max()
            .unwrap_or(0);
        let estimated_removable_line_count = total_lines.saturating_sub(max_single_lines);
        let occurrence_count = occurrences.len();

        families.push(DuplicateJsxFamilyFinding {
            fingerprint,
            node_count,
            depth,
            occurrence_count,
            distinct_file_count,
            estimated_removable_line_count,
            occurrences,
        });
    }

    suppress_nested_jsx_families(&mut families);
    families.sort_by(|a, b| {
        let rem_a = a.node_count * (a.occurrence_count.saturating_sub(1));
        let rem_b = b.node_count * (b.occurrence_count.saturating_sub(1));
        rem_b
            .cmp(&rem_a)
            .then_with(|| {
                b.estimated_removable_line_count
                    .cmp(&a.estimated_removable_line_count)
            })
            .then_with(|| b.occurrence_count.cmp(&a.occurrence_count))
            .then_with(|| b.distinct_file_count.cmp(&a.distinct_file_count))
            .then_with(|| b.node_count.cmp(&a.node_count))
            .then_with(|| {
                let Some(oa) = a.occurrences.first() else {
                    return std::cmp::Ordering::Equal;
                };
                let Some(ob) = b.occurrences.first() else {
                    return std::cmp::Ordering::Equal;
                };
                (&oa.path, oa.span.start).cmp(&(&ob.path, ob.span.start))
            })
    });
    families
}

fn suppress_nested_jsx_families(families: &mut Vec<DuplicateJsxFamilyFinding>) {
    families.sort_by(|a, b| {
        b.node_count
            .cmp(&a.node_count)
            .then_with(|| b.depth.cmp(&a.depth))
    });
    let mut maximal: Vec<DuplicateJsxFamilyFinding> = Vec::with_capacity(families.len());
    for candidate in families.drain(..) {
        let is_nested = maximal
            .iter()
            .any(|outer| jsx_family_is_nested_within(&candidate, outer));
        if !is_nested {
            maximal.push(candidate);
        }
    }
    *families = maximal;
}

fn jsx_family_is_nested_within(
    candidate: &DuplicateJsxFamilyFinding,
    outer: &DuplicateJsxFamilyFinding,
) -> bool {
    candidate.occurrences.iter().all(|inner_occ| {
        outer.occurrences.iter().any(|outer_occ| {
            inner_occ.file_index == outer_occ.file_index
                && inner_occ.span.start >= outer_occ.span.start
                && inner_occ.span.end <= outer_occ.span.end
        })
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{graph::ProjectGraph, ir::parse_file_ir};

    #[test]
    fn clusters_maximal_duplicate_jsx_subtree_families_and_suppresses_nested() {
        let card_a = parse_file_ir(
            Path::new("src/CardA.tsx"),
            r#"
export function CardA({ item }: any) {
    return (
        <article className="card">
            <header>
                <h3>{item.title}</h3>
                <span>{item.subtitle}</span>
            </header>
            <footer>{item.footer}</footer>
        </article>
    );
}
"#,
        );
        let card_b = parse_file_ir(
            Path::new("src/CardB.tsx"),
            r#"
export function CardB({ data }: any) {
    return (
        <article className="card">
            <header>
                <h3>{data.title}</h3>
                <span>{data.subtitle}</span>
            </header>
            <footer>{data.footer}</footer>
        </article>
    );
}
"#,
        );

        let graph = ProjectGraph::build(vec![card_a, card_b]);
        assert_eq!(graph.duplicate_jsx_families.len(), 1);
        let fam = &graph.duplicate_jsx_families[0];
        assert_eq!(fam.occurrence_count, 2);
        assert_eq!(fam.distinct_file_count, 2);
        assert_eq!(fam.node_count, 5);
    }
}
