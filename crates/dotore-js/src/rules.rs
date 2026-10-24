//! Diagnostic rules engine gated by **Capability Gate**, user configuration (`dotore.config.*` / `package.json#dotore`),
//! file context (`test-noise` / `migration-hint`), library role, and inline suppression directives.

pub(crate) use crate::matchers::{make_diag, make_diag_for_subject, push_simple_diagnostic};

pub(crate) mod a11y;
pub(crate) mod angular;
pub(crate) mod architecture;
pub(crate) mod bundle_size;
pub(crate) mod correctness;
pub(crate) mod defensive_js;
pub(crate) mod derived_state;
pub(crate) mod design;
pub(crate) mod ecosystem_ui;
pub(crate) mod effect_teardown;
pub(crate) mod external_sync;
pub(crate) mod js_performance;
pub(crate) mod parent_flow;
pub(crate) mod performance;
pub(crate) mod prop_sync;
pub(crate) mod r3f;
pub(crate) mod react_builtins;
pub(crate) mod react_native;
pub(crate) mod react_router;
/// Single-pass motion library and CSS reduced-motion rules (`require-reduced-motion`).
pub mod reduced_motion;
pub(crate) mod remotion;
pub(crate) mod security;
pub(crate) mod server_nextjs;
pub(crate) mod state_and_effects;
pub(crate) mod stores;
pub(crate) mod supply_chain;
pub(crate) mod tanstack;
pub use dotore_core::rules::{
    AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
    FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
    RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry, types,
};
pub use supply_chain::supply_chain_purl_hash;

use std::path::Path;

use crate::{
    config::{CapabilityGate, DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::ProjectGraph,
    ir::{FileContext, FileIr, JsxElementIr, SecuritySinkKind, SubjectIr},
    rules::{
        a11y::check_anchor_target_exists,
        architecture::evaluate_architecture_project_graph_rules,
        derived_state::{
            check_no_chain_state_updates, check_no_derived_state, check_no_initialize_state,
        },
        external_sync::{check_no_external_store_subscription, check_no_fetch_in_effect},
        parent_flow::{
            check_no_event_handler, check_no_pass_data_to_parent,
            check_no_pass_live_state_to_parent,
        },
        prop_sync::{
            check_no_adjust_state_on_prop_change, check_no_reset_all_state_on_prop_change,
        },
        react_builtins::evaluate_inline_prop_rules_with_graph,
        reduced_motion::evaluate_project_reduced_motion,
    },
};
use rayon::prelude::*;

/// Evaluates all enabled rules across the [`ProjectGraph`] using default React capability gate and config.
#[must_use]
pub fn evaluate_project(graph: &ProjectGraph, enabled_rules: Option<&[RuleId]>) -> Vec<Diagnostic> {
    let default_pkg = WorkspacePackage {
        name: "default".to_string(),
        root_dir: std::path::PathBuf::from("."),
        capability_gate: CapabilityGate::default_react(),
        config: DotoreConfig::default(),
    };
    evaluate_project_with_packages(graph, &[default_pkg], enabled_rules)
}

/// Evaluates rules across the [`ProjectGraph`] resolving each file's nearest [`WorkspacePackage`]
/// (`CapabilityGate` + `DotoreConfig`) and optional CLI `enabled_rules` filter.
#[must_use]
pub fn evaluate_project_with_packages(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let per_file: Vec<Vec<Diagnostic>> = graph
        .files
        .par_iter()
        .map(|file| {
            dotore_core::ui::tick_progress_file(&file.path);
            let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
                return Vec::new();
            };
            let mut file_diags = Vec::new();
            evaluate_file_in_package(
                graph,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
                &mut file_diags,
            );
            file_diags
        })
        .collect();
    let mut diagnostics: Vec<Diagnostic> = per_file.into_iter().flatten().collect();
    evaluate_project_graph_rules(graph, packages, enabled_rules, &mut diagnostics);
    evaluate_project_reduced_motion(graph, packages, enabled_rules, &mut diagnostics);
    diagnostics
}

/// Evaluates a single [`FileIr`] under an explicit [`DotoreConfig`] and [`CapabilityGate`].
pub fn evaluate_file_in_package(
    graph: &ProjectGraph,
    file: &FileIr,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if config.is_file_ignored(&file.path, package_root) {
        return;
    }

    let is_active = |rule: RuleId| -> Option<RuleSeverity> {
        resolve_rule_activation(rule, file, package_root, gate, config, enabled_rules)
    };

    let start_idx = out.len();

    for subject in &file.subjects {
        if is_active(RuleId::NoResetAllStateOnPropChange).is_some() {
            check_no_reset_all_state_on_prop_change(graph, file, subject, out);
        }
        evaluate_subject(file, subject, &is_active, out);
    }
    check_anchor_target_exists(graph, file, &is_active, out);

    let core_effect_diag_spans: Vec<crate::ir::ByteSpan> =
        out[start_idx..].iter().map(|d| d.span).collect();

    evaluate_file_ir_facets(
        graph,
        file,
        config,
        enabled_rules.is_some(),
        &core_effect_diag_spans,
        &is_active,
        out,
    );
    bundle_size::evaluate_barrel_imports(graph, file, gate, &is_active, out);
    security::evaluate_security_rules(graph, file, &is_active, out);
    server_nextjs::evaluate_server_and_nextjs_rules(graph, file, config, &is_active, out);
    architecture::evaluate_file_soc_rules(file, config, &is_active, out);

    // Restamp severities and apply inline suppressions for diagnostics emitted on this file
    let mut retained = Vec::with_capacity(out.len().saturating_sub(start_idx));
    for mut diag in out.drain(start_idx..) {
        let Some(effective_sev) = is_active(diag.rule) else {
            continue;
        };
        diag.severity = effective_sev;

        if config.respect_inline_disables
            && file.suppressions.is_suppressed(
                diag.rule,
                diag.loc.line,
                diag.span,
                &file.jsx_elements,
                &file.subjects,
            )
        {
            continue;
        }
        retained.push(diag);
    }
    out.extend(retained);
}

/// Evaluates cross-file [`ProjectGraph`] rules (dead code, circular dependencies, duplicate JSX, R3F frame loops, supply chain, and architecture).
pub fn evaluate_project_graph_rules(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let run_dead_code = graph.has_manifests || enabled_rules.is_some();

    if run_dead_code {
        for &file_idx in &graph.unused_file_indices {
            let file = &graph.files[file_idx];
            let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
                continue;
            };
            if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
                continue;
            }
            let Some(sev) = resolve_rule_activation(
                RuleId::UnusedFile,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };
            let loc = crate::ir::SourceLoc { line: 1, column: 1 };
            let span = crate::ir::ByteSpan { start: 0, end: 0 };
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::UnusedFile,
                    loc.line,
                    span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            out.push(
                make_diag(
                    RuleId::UnusedFile,
                    file.path.clone(),
                    loc,
                    span,
                    "No discovered application, package, or framework entry point reaches this file.",
                )
                .with_severity(sev)
                .with_message_id("unusedFile")
                .with_target_name(file.path.to_string_lossy().to_string()),
            );
        }

        for unused_exp in &graph.unused_exports {
            let file = &graph.files[unused_exp.file_index];
            let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
                continue;
            };
            if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
                continue;
            }
            let rule = if unused_exp.is_type_only {
                RuleId::UnusedType
            } else {
                RuleId::UnusedExport
            };
            let Some(sev) = resolve_rule_activation(
                rule,
                file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    rule,
                    unused_exp.loc.line,
                    unused_exp.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            let (message_id, kind_label) = if unused_exp.is_type_only {
                ("unusedType", "type export")
            } else {
                ("unusedExport", "value export")
            };
            out.push(
                make_diag_for_subject(
                    rule,
                    file.path.clone(),
                    None,
                    message_id,
                    unused_exp.name.clone(),
                    format!(
                        "Unused {kind_label}: `{}` has no importer in the analyzed project graph.",
                        unused_exp.name
                    ),
                    unused_exp.loc,
                    unused_exp.span,
                )
                .with_severity(sev),
            );
        }

        for dep in &graph.unused_dependencies {
            let rule = if dep.is_dev_dependency {
                RuleId::UnusedDevDependency
            } else {
                RuleId::UnusedDependency
            };
            if let Some(explicit_list) = enabled_rules
                && !explicit_list.contains(&rule)
            {
                continue;
            }
            if enabled_rules.is_none() && !dep.has_package_entrypoint {
                continue;
            }
            let Some(pkg) = resolve_package_for_file(&dep.manifest_path, packages) else {
                continue;
            };
            if pkg
                .config
                .is_file_ignored(&dep.manifest_path, &pkg.root_dir)
            {
                continue;
            }
            let meta = rule.metadata();
            let has_explicit_cli = enabled_rules.is_some_and(|l| l.contains(&rule));
            let Some(sev) = (if has_explicit_cli {
                Some(
                    pkg.config
                        .effective_severity(rule)
                        .unwrap_or(meta.default_severity),
                )
            } else {
                pkg.config.effective_severity(rule)
            }) else {
                continue;
            };
            let (message_id, dep_label) = if dep.is_dev_dependency {
                ("unusedDevDependency", "devDependency")
            } else {
                ("unusedDependency", "dependency")
            };
            out.push(
                make_diag_for_subject(
                    rule,
                    dep.manifest_path.clone(),
                    None,
                    message_id,
                    dep.package_name.clone(),
                    format!("Unused {dep_label}: `{}`", dep.package_name),
                    dep.loc,
                    dep.span,
                )
                .with_severity(sev),
            );
        }
    }

    for cycle in &graph.circular_dependencies {
        let file = &graph.files[cycle.primary_file_index];
        let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
            continue;
        };
        if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
            continue;
        }
        let Some(sev) = resolve_rule_activation(
            RuleId::CircularDependency,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };
        let loc = crate::ir::SourceLoc { line: 1, column: 1 };
        let span = crate::ir::ByteSpan { start: 0, end: 0 };
        if pkg.config.respect_inline_disables
            && file.suppressions.is_suppressed(
                RuleId::CircularDependency,
                loc.line,
                span,
                &file.jsx_elements,
                &file.subjects,
            )
        {
            continue;
        }
        let cycle_str = cycle
            .cycle_paths
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>()
            .join(" → ");
        out.push(
            make_diag_for_subject(
                RuleId::CircularDependency,
                file.path.clone(),
                None,
                "circularDependency",
                cycle_str.clone(),
                format!(
                    "Runtime import cycle: {cycle_str}. Modules in the cycle can observe partially initialized exports."
                ),
                loc,
                span,
            )
            .with_severity(sev),
        );
    }

    for family in &graph.duplicate_jsx_families {
        let Some(primary) = family.occurrences.first() else {
            continue;
        };
        let file = &graph.files[primary.file_index];
        let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
            continue;
        };
        if pkg.config.is_file_ignored(&file.path, &pkg.root_dir) {
            continue;
        }
        let Some(sev) = resolve_rule_activation(
            RuleId::DuplicateJsxSubtree,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };
        if pkg.config.respect_inline_disables
            && file.suppressions.is_suppressed(
                RuleId::DuplicateJsxSubtree,
                primary.loc.line,
                primary.span,
                &file.jsx_elements,
                &file.subjects,
            )
        {
            continue;
        }
        let _ = RuleId::DuplicateJsxSubtree;
        let file_label = if family.distinct_file_count == 1 {
            "file"
        } else {
            "files"
        };
        let line_label = if family.estimated_removable_line_count == 1 {
            "line"
        } else {
            "lines"
        };
        let comp_path = primary.composition_path.join(" > ");
        let caller_sites = family
            .occurrences
            .iter()
            .map(|occ| crate::graph::ResolvedCallerSite {
                caller_file: occ.path.clone(),
                parent_subject_name: occ.enclosing_subject.clone(),
                component_name: occ.root_name.clone(),
                loc: occ.loc,
                span: occ.span,
                has_key: false,
                passed_props: Vec::new(),
            })
            .collect();

        out.push(
            make_diag_for_subject(
                RuleId::DuplicateJsxSubtree,
                primary.path.clone(),
                primary.enclosing_subject.clone(),
                "duplicateJsxSubtree",
                family.fingerprint.clone(),
                format!(
                    "{} copies of this {}-node JSX tree appear across {} {file_label}, repeating about {} {line_label}. Composition path: {comp_path}.",
                    family.occurrence_count,
                    family.node_count,
                    family.distinct_file_count,
                    family.estimated_removable_line_count
                ),
                primary.loc,
                primary.span,
            )
            .with_severity(sev)
            .with_caller_sites(caller_sites),
        );
    }

    r3f::evaluate_cross_file_frame_loop_findings(
        graph,
        packages,
        enabled_rules,
        resolve_rule_activation,
        out,
    );
    supply_chain::evaluate_project_supply_chain_rules(graph, packages, enabled_rules, out);
    react_native::evaluate_react_native_and_expo_project_checks(
        graph,
        packages,
        enabled_rules,
        out,
    );
    evaluate_architecture_project_graph_rules(
        graph,
        packages,
        enabled_rules,
        &resolve_rule_activation,
        out,
    );
}

fn resolve_rule_activation(
    rule: RuleId,
    file: &FileIr,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
) -> Option<RuleSeverity> {
    if let Some(explicit_list) = enabled_rules
        && !explicit_list.contains(&rule)
    {
        return None;
    }

    let meta = rule.metadata();
    let has_explicit_cli_rule = enabled_rules.is_some_and(|list| list.contains(&rule));
    let explicit_config_override = config.explicit_rule_override(rule);

    // 1. Automatic `test-noise` suppression in test and story files unless also tagged `migration-hint`
    if file.file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && !has_explicit_cli_rule
        && explicit_config_override.is_none()
    {
        return None;
    }

    // 2. Library packages skip application-only rules on library entrypoints unless explicitly opted in
    if meta.capability_gate.app_only
        && (rule == RuleId::PreferDynamicImport
            && gate.package_role == crate::config::PackageRole::Library
            || gate.is_library_entrypoint(&file.path, package_root)
                && !has_explicit_cli_rule
                && explicit_config_override.is_none())
    {
        return None;
    }
    if rule == RuleId::NoFullLodashImport
        && gate.package_role == crate::config::PackageRole::Library
        && file
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".page."))
    {
        return None;
    }

    // 3. Per-path `ignore.overrides` block in config
    if config.is_overridden_for_file(rule, &file.path, package_root) && !has_explicit_cli_rule {
        return None;
    }

    // 4. Capability Gate check (unless explicitly forced via CLI `--rule`)
    if !has_explicit_cli_rule && !gate.allows_rule(meta) {
        return None;
    }
    if !has_explicit_cli_rule
        && rule == RuleId::NoRefCallbackCleanupBeforeReact19
        && gate
            .dependencies
            .get("react")
            .is_some_and(|ver| ver.contains("19"))
    {
        return None;
    }

    // 5. Config severity / ignore.rules / ignore.tags / customRulesOnly / defaultEnabled
    if has_explicit_cli_rule {
        Some(
            config
                .effective_severity(rule)
                .unwrap_or(meta.default_severity),
        )
    } else {
        config.effective_severity(rule)
    }
}

fn evaluate_subject<F>(file: &FileIr, subject: &SubjectIr, is_active: &F, out: &mut Vec<Diagnostic>)
where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if is_active(RuleId::NoDerivedState).is_some() {
        check_no_derived_state(file, subject, out);
    }
    if is_active(RuleId::NoChainStateUpdates).is_some() {
        check_no_chain_state_updates(file, subject, out);
    }
    if is_active(RuleId::NoEventHandler).is_some() {
        check_no_event_handler(file, subject, out);
    }
    if is_active(RuleId::NoAdjustStateOnPropChange).is_some() {
        check_no_adjust_state_on_prop_change(file, subject, out);
    }
    if is_active(RuleId::NoInitializeState).is_some() {
        let derived_enabled = is_active(RuleId::NoDerivedState).is_some();
        check_no_initialize_state(file, subject, derived_enabled, out);
    }
    if is_active(RuleId::NoPassLiveStateToParent).is_some() {
        check_no_pass_live_state_to_parent(file, subject, out);
    }
    if is_active(RuleId::NoPassDataToParent).is_some() {
        check_no_pass_data_to_parent(file, subject, out);
    }
    if is_active(RuleId::NoExternalStoreSubscription).is_some() {
        check_no_external_store_subscription(file, subject, out);
    }
    if is_active(RuleId::NoFetchInEffect).is_some() {
        check_no_fetch_in_effect(file, subject, out);
    }
}

fn evaluate_file_ir_facets<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    config: &DotoreConfig,
    has_explicit_rule_filter: bool,
    core_effect_diag_spans: &[crate::ir::ByteSpan],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    // 1. JSX element rules
    for jsx in &file.jsx_elements {
        evaluate_jsx_element_rules(
            graph,
            file,
            jsx,
            config,
            has_explicit_rule_filter,
            is_active,
            out,
        );
    }

    // 2. Module import rules (e.g. `preact-no-react-import`)
    if is_active(RuleId::PreactNoReactImport).is_some() {
        for imp in &file.module.imports {
            if imp.source == "react" || imp.source == "react-dom" {
                push_simple_diagnostic(
                    out,
                    file,
                    None,
                    RuleId::PreactNoReactImport,
                    "noReactImportInPreact",
                    &imp.source,
                    format!(
                        "Importing from {:?} in a pure Preact package; import from 'preact' or 'preact/hooks' instead.",
                        imp.source
                    ),
                    imp.loc,
                    imp.span,
                );
            }
        }
    }

    // 3. Direct state mutations (`no-direct-mutation-state`)
    if is_active(RuleId::NoDirectMutationState).is_some() {
        for mutation in &file.mutations {
            if mutation.is_state_slot {
                push_simple_diagnostic(
                    out,
                    file,
                    mutation.subject_name.clone(),
                    RuleId::NoDirectMutationState,
                    "noDirectMutationState",
                    &mutation.target_name,
                    format!(
                        "Do not mutate React state {:?} directly (`{}`); pass a new value to its state setter.",
                        mutation.target_name, mutation.expression_text
                    ),
                    mutation.loc,
                    mutation.span,
                );
            }
        }
    }

    // 5. Security and trust-boundary sinks (`no-danger`, `expo-no-non-inlined-env`, `server-auth-actions`)
    for sink in &file.security_sinks {
        match sink.kind {
            SecuritySinkKind::DangerouslySetInnerHtml if is_active(RuleId::NoDanger).is_some() => {
                push_simple_diagnostic(
                    out,
                    file,
                    sink.subject_name.clone(),
                    RuleId::NoDanger,
                    "noDanger",
                    &sink.target_name,
                    "Avoid `dangerouslySetInnerHTML`; it exposes the DOM to XSS if fed unsanitized input.".to_string(),
                    sink.loc,
                    sink.span,
                );
            }
            SecuritySinkKind::DynamicProcessEnv
                if is_active(RuleId::ExpoNoNonInlinedEnv).is_some() =>
            {
                push_simple_diagnostic(
                    out,
                    file,
                    sink.subject_name.clone(),
                    RuleId::ExpoNoNonInlinedEnv,
                    "expoNoNonInlinedEnv",
                    &sink.target_name,
                    "Dynamic `process.env[key]` cannot be inlined by Expo Metro bundler; use static `process.env.EXPO_PUBLIC_*` property access.".to_string(),
                    sink.loc,
                    sink.span,
                );
            }
            SecuritySinkKind::DangerouslySetInnerHtml
            | SecuritySinkKind::InnerHtmlAssignment
            | SecuritySinkKind::DynamicCodeEval
            | SecuritySinkKind::DynamicProcessEnv
            | SecuritySinkKind::UnauthenticatedServerAction => {}
        }
    }

    // 7. Single-pass semantic AST sites
    for site in &file.semantic_sites {
        // When `enabled_rules` is `None`, suppress secondary `exhaustive-deps` or `no-self-updating-effect`
        // on an EffectNode that was already flagged by one of the 10 core effect anti-pattern rules.
        if !has_explicit_rule_filter
            && matches!(
                site.rule,
                RuleId::ExhaustiveDeps | RuleId::NoSelfUpdatingEffect
            )
            && core_effect_diag_spans.iter().any(|eff_span| {
                (site.span.start <= eff_span.start && eff_span.end <= site.span.end)
                    || (eff_span.start <= site.span.start && site.span.end <= eff_span.end)
            })
        {
            continue;
        }
        if !has_explicit_rule_filter
            && matches!(
                site.rule,
                RuleId::OnlyExportComponents | RuleId::ExhaustiveDeps
            )
            && config.explicit_rule_override(site.rule).is_none()
        {
            continue;
        }
        if is_active(site.rule).is_some() {
            let meta = site.rule.metadata();
            let tier = if site.autofix.is_some() {
                PrescriptionTier::Autofix
            } else if meta.default_tier == PrescriptionTier::Autofix {
                PrescriptionTier::Surgical
            } else {
                meta.default_tier
            };
            out.push(
                make_diag_for_subject(
                    site.rule,
                    file.path.clone(),
                    site.subject_name.clone(),
                    site.message_id,
                    site.target_name.clone(),
                    site.message.clone(),
                    site.loc,
                    site.span,
                )
                .with_autofix(site.autofix.clone())
                .with_tier(tier),
            );
        }
    }
}

fn evaluate_jsx_element_rules<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    jsx: &JsxElementIr,
    config: &DotoreConfig,
    has_explicit_rule_filter: bool,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    // 1. `rn-no-raw-text` (honoring `textComponents`, `rawTextWrapperComponents`, and cross-file wrappers)
    if is_active(RuleId::RnNoRawText).is_some()
        && react_native::is_rn_raw_text_violation(graph, file, jsx, config)
    {
        push_simple_diagnostic(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::RnNoRawText,
            "rnNoRawText",
            &jsx.name,
            format!(
                "Raw text {:?} inside `<{}>` crashes in React Native; wrap text strings in `<Text>`.",
                jsx.raw_text_preview.as_deref().unwrap_or(""),
                jsx.name
            ),
            jsx.loc,
            jsx.span,
        );
    }

    // 2. `ink-no-raw-text` (including cross-file wrappers)
    if is_active(RuleId::InkNoRawText).is_some()
        && ecosystem_ui::is_ink_raw_text_violation(graph, file, jsx)
    {
        push_simple_diagnostic(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::InkNoRawText,
            "inkNoRawText",
            &jsx.name,
            format!(
                "Raw text inside `<{}>` is not allowed in Ink; wrap terminal text in `<Text>`.",
                jsx.name
            ),
            jsx.loc,
            jsx.span,
        );
    }

    // 3. `jsx-no-undef` (honoring `runtimeGlobals`; active on modules with imports or when explicitly enabled/configured)
    let should_check_undef = has_explicit_rule_filter
        || !config.runtime_globals.is_empty()
        || config.explicit_rule_override(RuleId::JsxNoUndef).is_some();
    if jsx.is_unresolved_component
        && should_check_undef
        && is_active(RuleId::JsxNoUndef).is_some()
        && !config
            .runtime_globals
            .iter()
            .chain(config.text_components.iter())
            .chain(config.raw_text_wrapper_components.iter())
            .any(|g| g == &jsx.root_identifier)
    {
        push_simple_diagnostic(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::JsxNoUndef,
            "jsxNoUndef",
            &jsx.root_identifier,
            format!(
                "`{}` is not defined; import the component or add it to `runtimeGlobals`.",
                jsx.root_identifier
            ),
            jsx.loc,
            jsx.span,
        );
    }

    // 4. `jsx-key` and `no-array-index-as-key`
    if jsx.in_array_map {
        if !jsx.has_key && is_active(RuleId::JsxKey).is_some() {
            push_simple_diagnostic(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::JsxKey,
                "missingJsxKey",
                &jsx.name,
                format!(
                    "Missing `key` prop for `<{}>` in array `.map()` iterator.",
                    jsx.name
                ),
                jsx.loc,
                jsx.span,
            );
        } else if jsx.key_is_array_index && is_active(RuleId::NoArrayIndexAsKey).is_some() {
            push_simple_diagnostic(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::NoArrayIndexAsKey,
                "noArrayIndexAsKey",
                &jsx.name,
                format!(
                    "Do not use array index in `key` prop on `<{}>`; use a stable item ID.",
                    jsx.name
                ),
                jsx.loc,
                jsx.span,
            );
        }
    }

    // 6. Inline prop reference rules (`jsx-no-new-object-as-prop`, `jsx-no-new-array-as-prop`,
    //    `jsx-no-new-function-as-prop`, `no-inline-prop-on-memo-component`) gated by ProjectGraph cold-path analysis
    evaluate_inline_prop_rules_with_graph(graph, file, jsx, is_active, out);

    // 7. `no-render-prop-children` (app-only rule, skipped on library entrypoints)
    if jsx.is_component
        && jsx.has_render_prop_children
        && is_active(RuleId::NoRenderPropChildren).is_some()
    {
        push_simple_diagnostic(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::NoRenderPropChildren,
            "noRenderPropChildren",
            &jsx.name,
            format!(
                "Avoid passing an inline render-prop function as children to `<{}>`; prefer hooks or composition.",
                jsx.name
            ),
            jsx.loc,
            jsx.span,
        );
    }
}
