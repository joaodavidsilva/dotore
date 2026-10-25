//! Single-pass motion library and CSS `@media (prefers-reduced-motion: reduce)` extraction
//! and cross-file [`ProjectGraph`] evaluation for `require-reduced-motion` (WCAG 2.3.3).

use std::{collections::HashSet, path::Path};

use crate::{
    config::{Capability, WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, resolution::normalize_path_components},
    ir::{
        ByteSpan, FileIr, SourceLoc,
        motion_and_frame_loop::{
            classify_motion_export, classify_motion_member, is_motion_module_source,
        },
        types::{MotionExpressionEvidence, PendingMotionRef, PendingMotionUsage},
    },
    matchers::make_diag_for_subject,
    rules::{Diagnostic, PrescriptionTier, RuleCategory, RuleId, RuleSeverity},
};

/// Evaluates project-wide `require-reduced-motion` across each [`WorkspacePackage`] in `graph`.
pub fn evaluate_project_reduced_motion(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if let Some(explicit) = enabled_rules
        && !explicit.contains(&RuleId::RequireReducedMotion)
    {
        return;
    }

    if !packages
        .iter()
        .any(|pkg| pkg.capability_gate.has(Capability::Motion))
    {
        return;
    }

    let mut buckets: Vec<Vec<&FileIr>> = (0..packages.len()).map(|_| Vec::new()).collect();
    for f in &graph.files {
        if let Some(resolved) = resolve_package_for_file(&f.path, packages)
            && let Some(idx) = packages
                .iter()
                .position(|p| p.root_dir == resolved.root_dir)
        {
            buckets[idx].push(f);
        }
    }

    for (pkg, pkg_files) in packages.iter().zip(buckets) {
        if !pkg.capability_gate.has(Capability::Motion) || pkg_files.is_empty() {
            continue;
        }
        let Some(effective_sev) = resolve_package_reduced_motion_severity(pkg, enabled_rules)
        else {
            continue;
        };

        let (has_motion_use, has_reduced_motion_handling) =
            resolve_package_motion_evidence(&pkg_files);

        if has_motion_use && !has_reduced_motion_handling {
            let pkg_json_path =
                if pkg.root_dir == Path::new(".") || pkg.root_dir.as_os_str().is_empty() {
                    std::path::PathBuf::from("package.json")
                } else {
                    pkg.root_dir.join("package.json")
                };
            out.push(
                make_diag_for_subject(
                    RuleId::RequireReducedMotion,
                    pkg_json_path,
                    None,
                    "requireReducedMotion",
                    "prefers-reduced-motion",
                    "Project uses a motion library but has no prefers-reduced-motion handling — required for accessibility (WCAG 2.3.3)",
                    SourceLoc { line: 1, column: 1 },
                    ByteSpan { start: 0, end: 0 },
                )
                .with_category(RuleCategory::Accessibility)
                .with_severity(effective_sev)
                .with_tier(PrescriptionTier::Surgical),
            );
        }
    }
}

fn resolve_package_reduced_motion_severity(
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
) -> Option<RuleSeverity> {
    let rule = RuleId::RequireReducedMotion;
    let meta = rule.metadata();
    let has_explicit_cli = enabled_rules.is_some_and(|list| list.contains(&rule));
    if !has_explicit_cli && !pkg.capability_gate.allows_rule(meta) {
        return None;
    }
    if has_explicit_cli {
        Some(
            pkg.config
                .effective_severity(rule)
                .unwrap_or(meta.default_severity),
        )
    } else {
        pkg.config.effective_severity(rule)
    }
}

fn resolve_package_motion_evidence(files: &[&FileIr]) -> (bool, bool) {
    let mut has_motion_use = files.iter().any(|f| f.motion.has_motion_use);
    let mut has_reduced_motion_handling =
        files.iter().any(|f| f.motion.has_reduced_motion_handling);

    for file in files {
        for pending in &file.motion.pending_refs {
            apply_pending_motion_ref(
                file,
                pending,
                files,
                &mut has_motion_use,
                &mut has_reduced_motion_handling,
            );
        }
    }

    (has_motion_use, has_reduced_motion_handling)
}

fn apply_pending_motion_ref(
    file: &FileIr,
    pending: &PendingMotionRef,
    files: &[&FileIr],
    has_motion_use: &mut bool,
    has_reduced_motion_handling: &mut bool,
) {
    match &pending.usage {
        PendingMotionUsage::ReExport { .. } => {}
        PendingMotionUsage::JsxTag {
            reduced_motion_prop,
        } => {
            let ev = resolve_pending_ref_evidence(file, pending, files);
            if ev.is_motion_component || ev.is_motion_component_factory {
                *has_motion_use = true;
            }
            if ev.is_motion_config
                && matches!(reduced_motion_prop.as_deref(), Some("user" | "always"))
            {
                *has_reduced_motion_handling = true;
            }
        }
        PendingMotionUsage::Call {
            value_consumed,
            via_call_or_apply,
        } => {
            let ev = resolve_pending_ref_evidence(file, pending, files);
            if ev.is_animation_function {
                *has_motion_use = true;
            }
            if ev.is_reduced_motion_hook && *value_consumed && !*via_call_or_apply {
                *has_reduced_motion_handling = true;
            }
        }
    }
}

fn resolve_pending_ref_evidence(
    from_file: &FileIr,
    pending: &PendingMotionRef,
    files: &[&FileIr],
) -> MotionExpressionEvidence {
    let Some(target_file) = find_local_module_file(&from_file.path, &pending.module_source, files)
    else {
        return MotionExpressionEvidence::default();
    };
    let mut visited = HashSet::new();
    let mut ev = if pending.imported_name == "*" {
        MotionExpressionEvidence {
            is_motion_namespace: true,
            ..MotionExpressionEvidence::default()
        }
    } else {
        resolve_module_export_evidence(target_file, &pending.imported_name, files, &mut visited)
    };
    for member in &pending.member_chain {
        if ev.is_motion_namespace {
            ev = resolve_module_export_evidence(target_file, member, files, &mut visited);
        } else {
            ev = classify_motion_member(ev, member);
        }
    }
    ev
}

fn resolve_module_export_evidence<'a>(
    file: &'a FileIr,
    export_name: &str,
    files: &[&'a FileIr],
    visited: &mut HashSet<(&'a Path, String)>,
) -> MotionExpressionEvidence {
    let key = (file.path.as_path(), export_name.to_string());
    if !visited.insert(key) {
        return MotionExpressionEvidence::default();
    }

    let mut combined = MotionExpressionEvidence::default();
    for (name, ev) in &file.motion.exported_evidence {
        if name == export_name {
            combined = combined.merge(*ev);
        }
    }
    if combined.has_any() {
        return combined;
    }

    if let Some(ev) = resolve_named_reexport_evidence(file, export_name, files, visited) {
        return ev;
    }

    if let Some(ev) = resolve_star_reexport_evidence(file, export_name, files, visited) {
        return ev;
    }

    combined
}

fn resolve_named_reexport_evidence<'a>(
    file: &'a FileIr,
    export_name: &str,
    files: &[&'a FileIr],
    visited: &mut HashSet<(&'a Path, String)>,
) -> Option<MotionExpressionEvidence> {
    for pending in &file.motion.pending_refs {
        let PendingMotionUsage::ReExport { exported_as } = &pending.usage else {
            continue;
        };
        if exported_as != export_name {
            continue;
        }
        let Some(target_file) = find_local_module_file(&file.path, &pending.module_source, files)
        else {
            continue;
        };
        let mut ev = if pending.imported_name == "*" {
            MotionExpressionEvidence {
                is_motion_namespace: true,
                ..MotionExpressionEvidence::default()
            }
        } else {
            resolve_module_export_evidence(target_file, &pending.imported_name, files, visited)
        };
        for member in &pending.member_chain {
            ev = classify_motion_member(ev, member);
        }
        if ev.has_any() {
            return Some(ev);
        }
    }
    None
}

fn resolve_star_reexport_evidence<'a>(
    file: &'a FileIr,
    export_name: &str,
    files: &[&'a FileIr],
    visited: &mut HashSet<(&'a Path, String)>,
) -> Option<MotionExpressionEvidence> {
    for star_src in &file.motion.star_reexports {
        if is_motion_module_source(star_src) {
            let ev = classify_motion_export(export_name);
            if ev.has_any() {
                return Some(ev);
            }
        } else if star_src.starts_with('.')
            && let Some(target_file) = find_local_module_file(&file.path, star_src, files)
        {
            let ev = resolve_module_export_evidence(target_file, export_name, files, visited);
            if ev.has_any() {
                return Some(ev);
            }
        }
    }
    None
}

fn find_local_module_file<'a>(
    importing_path: &Path,
    module_source: &str,
    files: &[&'a FileIr],
) -> Option<&'a FileIr> {
    if !module_source.starts_with('.') {
        return None;
    }
    let parent = importing_path.parent().unwrap_or_else(|| Path::new(""));
    let joined = parent.join(module_source);
    let joined_norm = normalize_path_components(&joined);
    let target_stem = strip_known_ext(&joined_norm);
    for candidate in files {
        let cand_norm = normalize_path_components(&candidate.path);
        let cand_stem = strip_known_ext(&cand_norm);
        if cand_stem == target_stem
            || cand_stem
                .strip_suffix("/index")
                .is_some_and(|idx_stem| idx_stem == target_stem)
        {
            return Some(*candidate);
        }
    }
    None
}

fn strip_known_ext(path: &str) -> &str {
    for ext in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts"] {
        if let Some(s) = path.strip_suffix(ext) {
            return s;
        }
    }
    path
}
