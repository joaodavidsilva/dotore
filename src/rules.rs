//! Diagnostic rules engine gated by **Capability Gate**, user configuration (`dotore.config.*` / `package.json#dotore`),
//! file context (`test-noise` / `migration-hint`), library role, and inline suppression directives.

pub(crate) mod a11y;
pub(crate) mod derived_state;
pub(crate) mod design;
pub(crate) mod external_sync;
pub(crate) mod parent_flow;
pub(crate) mod prop_sync;
pub(crate) mod r3f;
pub(crate) mod reduced_motion;
pub(crate) mod types;

pub use types::{
    AutofixPatch, BlastRadius, BlastRadiusTier, ByteEdit, ContextualOwnerPolicy, Diagnostic,
    FixCapsule, PrescriptionTier, RenderFrequency, RootCauseGroup, RuleCategory, RuleId,
    RuleMetadata, RuleSeverity, RuleSeverityOverride, RuleTag, SourceExcerpt, rule_registry,
};

use std::path::Path;

use crate::{
    config::{CapabilityGate, DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::ProjectGraph,
    ir::{FileContext, FileIr, JsxElementIr, SecuritySinkKind, SubjectIr},
    rules::{
        a11y::check_anchor_target_exists,
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
        reduced_motion::evaluate_project_reduced_motion,
    },
};

const BUILTIN_RN_TEXT_COMPONENTS: &[&str] = &["Text", "TSpan", "Animated.Text"];

/// Evaluates all enabled rules across the [`ProjectGraph`] using default React capability gate and config.
#[must_use]
pub(crate) fn evaluate_project(
    graph: &ProjectGraph,
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
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
pub(crate) fn evaluate_project_with_packages(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for file in &graph.files {
        let Some(pkg) = resolve_package_for_file(&file.path, packages) else {
            continue;
        };
        evaluate_file_in_package(
            graph,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
            &mut diagnostics,
        );
    }
    evaluate_project_graph_rules(graph, packages, enabled_rules, &mut diagnostics);
    evaluate_project_reduced_motion(graph, packages, enabled_rules, &mut diagnostics);
    diagnostics
}

/// Evaluates a single [`FileIr`] under an explicit [`DotoreConfig`] and [`CapabilityGate`].
pub(crate) fn evaluate_file_in_package(
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

    evaluate_file_ir_facets(file, config, enabled_rules.is_some(), &is_active, out);

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

fn evaluate_project_graph_rules(
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
            let meta = RuleId::UnusedFile.metadata();
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: None,
                rule: RuleId::UnusedFile,
                category: meta.category,
                severity: sev,
                message_id: "unusedFile",
                tier: meta.default_tier,
                target_name: file.path.to_string_lossy().to_string(),
                message:
                    "No discovered application, package, or framework entry point reaches this file."
                        .to_string(),
                docs_url: meta.docs_url,
                loc,
                span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
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
            let meta = rule.metadata();
            let (message_id, kind_label) = if unused_exp.is_type_only {
                ("unusedType", "type export")
            } else {
                ("unusedExport", "value export")
            };
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: None,
                rule,
                category: meta.category,
                severity: sev,
                message_id,
                tier: meta.default_tier,
                target_name: unused_exp.name.clone(),
                message: format!(
                    "Unused {kind_label}: `{}` has no importer in the analyzed project graph.",
                    unused_exp.name
                ),
                docs_url: meta.docs_url,
                loc: unused_exp.loc,
                span: unused_exp.span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
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
            out.push(Diagnostic {
                file: dep.manifest_path.clone(),
                subject_name: None,
                rule,
                category: meta.category,
                severity: sev,
                message_id,
                tier: meta.default_tier,
                target_name: dep.package_name.clone(),
                message: format!("Unused {dep_label}: `{}`", dep.package_name),
                docs_url: meta.docs_url,
                loc: dep.loc,
                span: dep.span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
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
        let meta = RuleId::CircularDependency.metadata();
        let cycle_str = cycle
            .cycle_paths
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>()
            .join(" → ");
        out.push(Diagnostic {
            file: file.path.clone(),
            subject_name: None,
            rule: RuleId::CircularDependency,
            category: meta.category,
            severity: sev,
            message_id: "circularDependency",
            tier: meta.default_tier,
            target_name: cycle_str.clone(),
            message: format!(
                "Runtime import cycle: {cycle_str}. Modules in the cycle can observe partially initialized exports."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
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
        let meta = RuleId::DuplicateJsxSubtree.metadata();
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

        out.push(Diagnostic {
            file: primary.path.clone(),
            subject_name: primary.enclosing_subject.clone(),
            rule: RuleId::DuplicateJsxSubtree,
            category: meta.category,
            severity: sev,
            message_id: "duplicateJsxSubtree",
            tier: meta.default_tier,
            target_name: family.fingerprint.clone(),
            message: format!(
                "{} copies of this {}-node JSX tree appear across {} {file_label}, repeating about {} {line_label}. Composition path: {comp_path}.",
                family.occurrence_count,
                family.node_count,
                family.distinct_file_count,
                family.estimated_removable_line_count
            ),
            docs_url: meta.docs_url,
            loc: primary.loc,
            span: primary.span,
            cascade_steps: Vec::new(),
            caller_sites,
            autofix: None,
        });
    }

    r3f::evaluate_cross_file_frame_loop_findings(
        graph,
        packages,
        enabled_rules,
        resolve_rule_activation,
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
        && gate.is_library_entrypoint(&file.path, package_root)
        && !has_explicit_cli_rule
        && explicit_config_override.is_none()
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
    file: &FileIr,
    config: &DotoreConfig,
    has_explicit_rule_filter: bool,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    // 1. JSX element rules
    for jsx in &file.jsx_elements {
        evaluate_jsx_element_rules(file, jsx, config, has_explicit_rule_filter, is_active, out);
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

    // 4. Async flows (`async-await-in-loop`)
    if is_active(RuleId::AsyncAwaitInLoop).is_some() {
        for flow in &file.async_flows {
            if flow.inside_loop {
                push_simple_diagnostic(
                    out,
                    file,
                    flow.enclosing_name.clone(),
                    RuleId::AsyncAwaitInLoop,
                    "asyncAwaitInLoop",
                    &flow.awaited_expr,
                    format!(
                        "Avoid sequential `await {}` inside a loop; collect promises and use `await Promise.all(...)`.",
                        flow.awaited_expr
                    ),
                    flow.loc,
                    flow.span,
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
            SecuritySinkKind::UnauthenticatedServerAction
                if is_active(RuleId::ServerAuthActions).is_some() =>
            {
                push_simple_diagnostic(
                    out,
                    file,
                    sink.subject_name.clone(),
                    RuleId::ServerAuthActions,
                    "serverAuthActions",
                    &sink.target_name,
                    format!(
                        "Exported Server Action {:?} performs operations without an authentication/authorization guard.",
                        sink.target_name
                    ),
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

    // 6. Fast Refresh `only-export-components` (ContextualOwnerPolicy::File)
    let is_subj_component = |name: &str| {
        file.subjects.iter().any(|s| {
            s.kind == crate::ir::types::SubjectKind::Component && s.name.as_deref() == Some(name)
        })
    };
    if (has_explicit_rule_filter
        || config
            .explicit_rule_override(RuleId::OnlyExportComponents)
            .is_some())
        && is_active(RuleId::OnlyExportComponents).is_some()
        && file
            .module
            .exports
            .iter()
            .any(|e| is_subj_component(&e.name))
    {
        for exp in &file.module.exports {
            if !is_subj_component(&exp.name) && !exp.is_type_only && exp.from_source.is_none() {
                push_simple_diagnostic(
                    out,
                    file,
                    None,
                    RuleId::OnlyExportComponents,
                    "onlyExportComponents",
                    &exp.name,
                    format!(
                        "Fast Refresh only works when a file only exports components. Move non-component export {:?} to a separate file.",
                        exp.name
                    ),
                    exp.loc,
                    exp.span,
                );
            }
        }
    }

    // 7. Single-pass semantic AST sites
    for site in &file.semantic_sites {
        if site.rule == RuleId::ExhaustiveDeps
            && !has_explicit_rule_filter
            && config
                .explicit_rule_override(RuleId::ExhaustiveDeps)
                .is_none()
        {
            continue;
        }
        if is_active(site.rule).is_some() {
            let meta = site.rule.metadata();
            out.push(Diagnostic {
                file: file.path.clone(),
                subject_name: site.subject_name.clone(),
                rule: site.rule,
                category: meta.category,
                severity: meta.default_severity,
                message_id: site.message_id,
                tier: if site.autofix.is_some() {
                    PrescriptionTier::Autofix
                } else {
                    meta.default_tier
                },
                target_name: site.target_name.clone(),
                message: site.message.clone(),
                docs_url: meta.docs_url,
                loc: site.loc,
                span: site.span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: site.autofix.clone(),
            });
        }
    }
}

fn evaluate_jsx_element_rules<F>(
    file: &FileIr,
    jsx: &JsxElementIr,
    config: &DotoreConfig,
    has_explicit_rule_filter: bool,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    // 1. `rn-no-raw-text` (honoring `textComponents` and `rawTextWrapperComponents`)
    if jsx.has_raw_text_child
        && is_active(RuleId::RnNoRawText).is_some()
        && !is_rn_raw_text_allowed(jsx, config)
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

    // 2. `ink-no-raw-text`
    if jsx.has_raw_text_child
        && is_active(RuleId::InkNoRawText).is_some()
        && jsx.name != "Text"
        && !jsx.ancestor_elements.iter().any(|a| a == "Text")
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

    // 5. `nextjs-no-img-element` (`alt-text` is evaluated by `src/rules/a11y.rs`)
    if jsx.name == "img" && is_active(RuleId::NextjsNoImgElement).is_some() {
        push_simple_diagnostic(
            out,
            file,
            jsx.enclosing_subject.clone(),
            RuleId::NextjsNoImgElement,
            "nextjsNoImgElement",
            "img",
            "Prefer `<Image />` from `next/image` over raw `<img>` in Next.js.".to_string(),
            jsx.loc,
            jsx.span,
        );
    }

    // 6. `jsx-no-new-object-as-prop` (on custom components, disabled when ReactCompiler is active)
    if jsx.is_component
        && !jsx.object_literal_props.is_empty()
        && is_active(RuleId::JsxNoNewObjectAsProp).is_some()
    {
        for prop_name in &jsx.object_literal_props {
            push_simple_diagnostic(
                out,
                file,
                jsx.enclosing_subject.clone(),
                RuleId::JsxNoNewObjectAsProp,
                "jsxNoNewObjectAsProp",
                prop_name,
                format!(
                    "Prop `{prop_name}` on `<{}>` receives a fresh object literal on every render.",
                    jsx.name
                ),
                jsx.loc,
                jsx.span,
            );
        }
    }

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

fn is_rn_raw_text_allowed(jsx: &JsxElementIr, config: &DotoreConfig) -> bool {
    let is_text_comp = |name: &str| {
        BUILTIN_RN_TEXT_COMPONENTS.contains(&name)
            || config.text_components.iter().any(|c| c == name)
    };

    if is_text_comp(&jsx.name) || jsx.ancestor_elements.iter().any(|a| is_text_comp(a)) {
        return true;
    }

    // `rawTextWrapperComponents` suppresses `rn-no-raw-text` ONLY when the wrapper's children
    // are purely stringifiable (no sibling JSX element children).
    if config
        .raw_text_wrapper_components
        .iter()
        .any(|w| w == &jsx.name)
        && !jsx.has_element_children
    {
        return true;
    }

    false
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a Diagnostic from rule metadata and site location without intermediate builder allocation"
)]
fn push_simple_diagnostic(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    subject_name: Option<String>,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: crate::ir::SourceLoc,
    span: crate::ir::ByteSpan,
) {
    let meta = rule.metadata();
    out.push(Diagnostic {
        file: file.path.clone(),
        subject_name,
        rule,
        category: meta.category,
        severity: meta.default_severity,
        message_id,
        tier: meta.default_tier,
        target_name: target_name.to_string(),
        message,
        docs_url: meta.docs_url,
        loc,
        span,
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: None,
    });
}
