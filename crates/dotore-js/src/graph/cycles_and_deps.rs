//! Unused dependency detection (`unused-dependency`, `unused-dev-dependency`) and
//! Tarjan SCC / bounded Johnson cycle enumeration (`circular-dependency`) for [`super::ProjectGraph`].

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::ir::{ByteSpan, FileIr, SourceLoc};

use super::{
    CircularDependencyFinding, UnusedDependencyFinding,
    dead_code::IMPLICIT_DEPENDENCIES,
    resolution::{ModuleEdge, PackageManifestInfo},
};

const MAX_CYCLES_PER_SCC: usize = 20;
const MAX_TOTAL_CYCLES: usize = 200;

pub(super) fn detect_unused_dependencies(
    files: &[FileIr],
    pkg_manifests: &[PackageManifestInfo],
    packages_with_entrypoints: &HashSet<String>,
    manifests: &HashMap<PathBuf, String>,
    consumed_external_packages: &HashSet<String>,
) -> Vec<UnusedDependencyFinding> {
    let _ = files;
    if pkg_manifests.is_empty() {
        return Vec::new();
    }

    let all_used_packages =
        collect_all_used_packages(pkg_manifests, manifests, consumed_external_packages);

    let mut findings = Vec::new();
    for pkg in pkg_manifests {
        collect_unused_findings_for_package(
            pkg,
            &all_used_packages,
            packages_with_entrypoints,
            &mut findings,
        );
    }
    findings
}

fn collect_all_used_packages(
    pkg_manifests: &[PackageManifestInfo],
    manifests: &HashMap<PathBuf, String>,
    consumed_external_packages: &HashSet<String>,
) -> HashSet<String> {
    let mut all_used_packages = consumed_external_packages.clone();
    for &implicit in IMPLICIT_DEPENDENCIES {
        all_used_packages.insert(implicit.to_string());
    }

    for pkg in pkg_manifests {
        all_used_packages.extend(pkg.peer_and_optional_dependencies.iter().cloned());
        collect_script_mentioned_packages(pkg, &mut all_used_packages);
    }

    for content in manifests.values() {
        collect_manifest_mentioned_packages(content, pkg_manifests, &mut all_used_packages);
    }
    all_used_packages
}

fn collect_script_mentioned_packages(
    pkg: &PackageManifestInfo,
    used_packages: &mut HashSet<String>,
) {
    for cmd in &pkg.script_commands {
        for candidate in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
            let short_bin = candidate.rsplit('/').next().unwrap_or(candidate.as_str());
            if command_mentions_token(cmd, candidate) || command_mentions_token(cmd, short_bin) {
                used_packages.insert(candidate.clone());
            }
        }
    }
}

fn collect_manifest_mentioned_packages(
    content: &str,
    pkg_manifests: &[PackageManifestInfo],
    used_packages: &mut HashSet<String>,
) {
    for pkg in pkg_manifests {
        for candidate in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
            if content_mentions_quoted_package(content, candidate) {
                used_packages.insert(candidate.clone());
            }
        }
    }
}

fn collect_unused_findings_for_package(
    pkg: &PackageManifestInfo,
    all_used_packages: &HashSet<String>,
    packages_with_entrypoints: &HashSet<String>,
    findings: &mut Vec<UnusedDependencyFinding>,
) {
    let has_package_entrypoint = packages_with_entrypoints.contains(&pkg.norm_root);
    for (dep_list, is_dev) in [(&pkg.dependencies, false), (&pkg.dev_dependencies, true)] {
        for dep_name in dep_list {
            if is_package_considered_used(dep_name, all_used_packages) {
                continue;
            }
            let (loc, span) = find_json_key_loc(&pkg.raw_content, dep_name);
            findings.push(UnusedDependencyFinding {
                manifest_path: pkg.manifest_path.clone(),
                package_root: pkg.root_dir.clone(),
                package_name: dep_name.clone(),
                is_dev_dependency: is_dev,
                has_package_entrypoint,
                loc,
                span,
            });
        }
    }
}

fn is_package_considered_used(dep_name: &str, used: &HashSet<String>) -> bool {
    if used.contains(dep_name) || IMPLICIT_DEPENDENCIES.contains(&dep_name) {
        return true;
    }
    if dep_name.starts_with("@babel/")
        || dep_name.starts_with("eslint-")
        || dep_name.starts_with("@eslint/")
        || dep_name.starts_with("prettier-plugin-")
        || dep_name.starts_with("@vitejs/plugin-")
        || dep_name.starts_with("vite-plugin-")
    {
        return true;
    }
    if let Some(typed_pkg) = dep_name.strip_prefix("@types/") {
        let unscoped = if let Some((scope, rest)) = typed_pkg.split_once("__") {
            format!("@{scope}/{rest}")
        } else {
            typed_pkg.to_string()
        };
        if used.contains(&unscoped) || IMPLICIT_DEPENDENCIES.contains(&unscoped.as_str()) {
            return true;
        }
    }
    false
}

fn command_mentions_token(cmd: &str, token: &str) -> bool {
    cmd.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '@' && c != '/')
        .any(|part| part == token)
}

fn content_mentions_quoted_package(content: &str, pkg_name: &str) -> bool {
    let dq = format!("\"{pkg_name}\"");
    let sq = format!("'{pkg_name}'");
    let sub_dq = format!("\"{pkg_name}/");
    let sub_sq = format!("'{pkg_name}/");
    for pat in [&sub_dq, &sub_sq] {
        if content.contains(pat) {
            return true;
        }
    }
    for (idx, _) in content.match_indices(&dq).chain(content.match_indices(&sq)) {
        let after = content.get(idx + dq.len()..).unwrap_or_default().trim_start();
        if !after.starts_with(':') {
            return true;
        }
    }
    false
}

fn find_json_key_loc(raw_json: &str, key: &str) -> (SourceLoc, ByteSpan) {
    let needle = format!("\"{key}\"");
    if let Some(byte_idx) = raw_json.find(&needle) {
        let before = &raw_json[..byte_idx];
        let line = u32::try_from(before.bytes().filter(|&b| b == b'\n').count() + 1).unwrap_or(1);
        let last_nl = before.rfind('\n').map_or(0, |p| p + 1);
        let column = u32::try_from(byte_idx.saturating_sub(last_nl) + 1).unwrap_or(1);
        let start = u32::try_from(byte_idx).unwrap_or(0);
        let end = u32::try_from(byte_idx + needle.len()).unwrap_or(start);
        return (SourceLoc { line, column }, ByteSpan { start, end });
    }
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan { start: 0, end: 0 },
    )
}

pub(super) fn detect_circular_dependencies(
    files: &[FileIr],
    edges: &[ModuleEdge],
) -> Vec<CircularDependencyFinding> {
    if files.len() < 2 {
        return Vec::new();
    }

    let adj = build_cycle_adjacency_list(files, edges);
    let sccs = tarjan_sccs(&adj);
    let mut all_cycles = collect_unique_cycles_from_sccs(sccs, &adj, files);

    all_cycles.sort_by(|a, b| {
        a.len().cmp(&b.len()).then_with(|| {
            let pa = a.first().and_then(|&i| files.get(i)).map(|f| &f.path);
            let pb = b.first().and_then(|&i| files.get(i)).map(|f| &f.path);
            pa.cmp(&pb)
        })
    });

    all_cycles
        .into_iter()
        .filter_map(|cycle| build_circular_dependency_finding(&cycle, files))
        .collect()
}

fn build_cycle_adjacency_list(files: &[FileIr], edges: &[ModuleEdge]) -> Vec<Vec<usize>> {
    let n = files.len();
    let mut adj_sets: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for edge in edges {
        if is_ignored_cycle_edge(edge, files) {
            continue;
        }
        if edge.target < n
            && edge.source != edge.target
            && let Some(set) = adj_sets.get_mut(edge.source)
        {
            set.insert(edge.target);
        }
    }
    adj_sets
        .into_iter()
        .map(|s| {
            let mut v: Vec<usize> = s.into_iter().collect();
            v.sort_unstable();
            v
        })
        .collect()
}

fn is_ignored_cycle_edge(edge: &ModuleEdge, files: &[FileIr]) -> bool {
    if edge.is_dynamic || edge.is_type_only {
        return true;
    }
    if !edge.imported_symbols.is_empty() && edge.imported_symbols.iter().all(|s| s.is_type_only) {
        return true;
    }
    is_compile_time_erased_edge(edge, files)
}

fn collect_unique_cycles_from_sccs(
    sccs: Vec<Vec<usize>>,
    adj: &[Vec<usize>],
    files: &[FileIr],
) -> Vec<Vec<usize>> {
    let mut all_cycles: Vec<Vec<usize>> = Vec::new();
    let mut seen_keys: HashSet<Vec<usize>> = HashSet::new();

    for mut scc in sccs {
        if scc.len() < 2 {
            continue;
        }
        scc.sort_unstable();
        for cycle in enumerate_elementary_cycles(&scc, adj, files) {
            if seen_keys.insert(cycle.clone()) {
                all_cycles.push(cycle);
                if all_cycles.len() >= MAX_TOTAL_CYCLES {
                    return all_cycles;
                }
            }
        }
    }
    all_cycles
}

fn build_circular_dependency_finding(
    cycle: &[usize],
    files: &[FileIr],
) -> Option<CircularDependencyFinding> {
    let &primary_file_index = cycle.first()?;
    let primary_file = files.get(primary_file_index)?;
    let mut cycle_paths: Vec<PathBuf> = cycle
        .iter()
        .filter_map(|&idx| files.get(idx).map(|f| f.path.clone()))
        .collect();
    cycle_paths.push(primary_file.path.clone());
    Some(CircularDependencyFinding {
        primary_file_index,
        cycle_paths,
    })
}

fn is_compile_time_erased_edge(edge: &ModuleEdge, files: &[FileIr]) -> bool {
    if edge.is_re_export || edge.imported_symbols.is_empty() {
        return false;
    }
    let Some(target_file) = files.get(edge.target) else {
        return false;
    };
    edge.imported_symbols.iter().all(|sym| {
        if sym.is_type_only {
            return true;
        }
        if sym.is_namespace {
            return false;
        }
        let exp_name = if sym.is_default {
            "default"
        } else {
            sym.imported_name.as_str()
        };
        let matching: Vec<_> = target_file
            .module
            .exports
            .iter()
            .filter(|e| e.name == exp_name)
            .collect();
        !matching.is_empty() && matching.iter().all(|e| e.is_type_only)
    })
}

fn tarjan_sccs(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct TarjanState {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    fn strongconnect(v: usize, adj: &[Vec<usize>], state: &mut TarjanState) {
        let v_idx = state.index;
        if let Some(slot) = state.indices.get_mut(v) {
            *slot = Some(v_idx);
        }
        if let Some(slot) = state.lowlink.get_mut(v) {
            *slot = v_idx;
        }
        state.index += 1;
        state.stack.push(v);
        if let Some(slot) = state.on_stack.get_mut(v) {
            *slot = true;
        }

        let neighbors = adj.get(v).map_or(&[][..], Vec::as_slice);
        for &w in neighbors {
            if state.indices.get(w).copied().flatten().is_none() {
                strongconnect(w, adj, state);
                let w_low = state.lowlink.get(w).copied().unwrap_or(v_idx);
                if let Some(v_low) = state.lowlink.get_mut(v) {
                    *v_low = (*v_low).min(w_low);
                }
            } else if state.on_stack.get(w).copied().unwrap_or(false)
                && let Some(w_idx) = state.indices.get(w).copied().flatten()
                && let Some(v_low) = state.lowlink.get_mut(v)
            {
                *v_low = (*v_low).min(w_idx);
            }
        }

        if state.lowlink.get(v).copied() == Some(v_idx) {
            let mut scc = Vec::new();
            while let Some(w) = state.stack.pop() {
                if let Some(slot) = state.on_stack.get_mut(w) {
                    *slot = false;
                }
                scc.push(w);
                if w == v {
                    break;
                }
            }
            state.sccs.push(scc);
        }
    }

    let n = adj.len();
    let mut state = TarjanState {
        index: 0,
        indices: vec![None; n],
        lowlink: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        sccs: Vec::new(),
    };

    for v in 0..n {
        if state.indices.get(v).copied().flatten().is_none() {
            strongconnect(v, adj, &mut state);
        }
    }
    state.sccs
}

fn enumerate_elementary_cycles(
    scc_nodes: &[usize],
    adj: &[Vec<usize>],
    files: &[FileIr],
) -> Vec<Vec<usize>> {
    if let [a, b] = *scc_nodes {
        let a_le_b = files
            .get(a)
            .zip(files.get(b))
            .is_none_or(|(fa, fb)| fa.path <= fb.path);
        return if a_le_b {
            vec![vec![a, b]]
        } else {
            vec![vec![b, a]]
        };
    }

    let scc_set: HashSet<usize> = scc_nodes.iter().copied().collect();
    let mut cycles = Vec::new();
    let mut seen = HashSet::new();

    for &start in scc_nodes {
        if cycles.len() >= MAX_CYCLES_PER_SCC {
            break;
        }
        let mut path = vec![start];
        let mut visited: HashSet<usize> = HashSet::from([start]);
        dfs_cycles(
            start,
            start,
            &scc_set,
            adj,
            files,
            &mut path,
            &mut visited,
            &mut seen,
            &mut cycles,
        );
    }

    cycles
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bounded DFS cycle enumerator threads recursion stack, visited set, and canonical output"
)]
fn dfs_cycles(
    start: usize,
    curr: usize,
    scc_set: &HashSet<usize>,
    adj: &[Vec<usize>],
    files: &[FileIr],
    path: &mut Vec<usize>,
    visited: &mut HashSet<usize>,
    seen: &mut HashSet<Vec<usize>>,
    out: &mut Vec<Vec<usize>>,
) {
    if out.len() >= MAX_CYCLES_PER_SCC {
        return;
    }
    let Some(neighbors) = adj.get(curr) else {
        return;
    };
    for &next in neighbors {
        if !scc_set.contains(&next) {
            continue;
        }
        if next == start && path.len() >= 2 {
            let canonical = canonicalize_cycle(path, files);
            if seen.insert(canonical.clone()) {
                out.push(canonical);
                if out.len() >= MAX_CYCLES_PER_SCC {
                    return;
                }
            }
        } else if !visited.contains(&next) {
            visited.insert(next);
            path.push(next);
            dfs_cycles(start, next, scc_set, adj, files, path, visited, seen, out);
            path.pop();
            visited.remove(&next);
        }
    }
}

fn canonicalize_cycle(cycle: &[usize], files: &[FileIr]) -> Vec<usize> {
    let mut min_pos = 0;
    for (idx, &node) in cycle.iter().enumerate().skip(1) {
        let min_node = cycle.get(min_pos).copied().unwrap_or(node);
        if files
            .get(node)
            .zip(files.get(min_node))
            .is_some_and(|(fa, fb)| fa.path < fb.path)
        {
            min_pos = idx;
        }
    }
    let (before, from_min) = cycle.split_at(min_pos.min(cycle.len()));
    let mut out = Vec::with_capacity(cycle.len());
    out.extend_from_slice(from_min);
    out.extend_from_slice(before);
    out
}
