//! Rule activation gating and evaluation for `dotore-rs` core safety rules.

use std::path::Path;

use dotore_core::{
    CapabilityGate, Diagnostic, DotoreConfig, ExtractedFile, FileContext, PackageAnalysisResult,
    PrescriptionTier, RuleId, RuleSeverity, RuleTag, WorkspacePackage,
};

use crate::ir::{RsCandidateFinding, RsFileIr};

/// All 5 core Rust safety rules evaluated by `dotore-rs`.
pub const CORE_RUST_SAFETY_RULES: &[RuleId] = &[
    RuleId::RsNoUnwrapInProduction,
    RuleId::RsNoUnguardedSliceIndex,
    RuleId::RsNoLossyNumericAsCast,
    RuleId::RsRequireSafetyCommentOnUnsafe,
    RuleId::RsNoMemForget,
];

/// Evaluates all enabled Rust rules across `files` for `package`.
#[must_use]
pub fn evaluate_rs_package(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
) -> PackageAnalysisResult {
    let mut diagnostics = Vec::new();
    let mut subjects_scanned = 0;
    let mut effects_scanned = 0;

    for file in files {
        subjects_scanned += file.subjects_count;
        effects_scanned += file.effects_count;
        evaluate_rs_file(
            file,
            &package.root_dir,
            &package.capability_gate,
            &package.config,
            enabled_rules,
            &mut diagnostics,
        );
    }

    evaluate_rs_package_graph_rules(package, files, enabled_rules, &mut diagnostics);

    PackageAnalysisResult {
        diagnostics,
        subjects_scanned,
        effects_scanned,
    }
}

/// Evaluates all enabled Rust rules on a single [`ExtractedFile`] under an explicit [`DotoreConfig`] and [`CapabilityGate`].
pub fn evaluate_rs_file(
    file: &ExtractedFile,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if config.is_file_ignored(&file.path, package_root) {
        return;
    }
    let Some(rs_ir) = file.downcast_payload::<RsFileIr>() else {
        return;
    };

    for finding in &rs_ir.findings {
        if !is_evaluated_rust_rule(finding.rule) {
            continue;
        }
        let Some(severity) = resolve_rs_rule_activation(
            finding.rule,
            file,
            package_root,
            gate,
            config,
            enabled_rules,
        ) else {
            continue;
        };
        if config.respect_inline_disables
            && (file.is_suppressed(finding.rule, finding.loc.line, finding.span)
                || file
                    .suppressions
                    .matches_line_or_block(finding.rule, finding.loc.line))
        {
            continue;
        }
        out.push(candidate_to_diagnostic(&file.path, finding, severity));
    }
}

fn evaluate_rs_package_graph_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if files.is_empty() {
        return;
    }
    let graph_findings = crate::graph::collect_unused_pub_crate_findings_for_package(files);
    for (file_path, finding) in &graph_findings {
        let Some(file) = files.iter().find(|f| &f.path == file_path) else {
            continue;
        };
        if package.config.is_file_ignored(&file.path, &package.root_dir) {
            continue;
        }
        emit_rs_finding_if_active(
            file,
            finding,
            &package.root_dir,
            &package.capability_gate,
            &package.config,
            enabled_rules,
            out,
        );
    }
}

fn emit_rs_finding_if_active(
    file: &ExtractedFile,
    finding: &RsCandidateFinding,
    package_root: &Path,
    gate: &CapabilityGate,
    config: &DotoreConfig,
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let Some(severity) =
        resolve_rs_rule_activation(finding.rule, file, package_root, gate, config, enabled_rules)
    else {
        return;
    };
    if config.respect_inline_disables
        && (file.is_suppressed(finding.rule, finding.loc.line, finding.span)
            || file
                .suppressions
                .matches_line_or_block(finding.rule, finding.loc.line))
    {
        return;
    }
    if out
        .iter()
        .any(|d| d.file == file.path && d.rule == finding.rule && d.span == finding.span)
    {
        return;
    }
    out.push(candidate_to_diagnostic(&file.path, finding, severity));
}

const fn is_evaluated_rust_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::RsNoUnwrapInProduction
            | RuleId::RsNoUnguardedSliceIndex
            | RuleId::RsNoLossyNumericAsCast
            | RuleId::RsRequireSafetyCommentOnUnsafe
            | RuleId::RsNoMemForget
            | RuleId::RsSqlxNoFormattedQueryString
            | RuleId::RsSqlxNoQueryInLoop
            | RuleId::RsAxumNoContendedMutexState
            | RuleId::RsUiNoDerivedSignalInEffect
            | RuleId::RsArchNoManyBooleanParams
            | RuleId::RsArchNoUnusedPubCrateItems
            | RuleId::RsTokioNoStdLockAcrossAwait
            | RuleId::RsTokioNoBlockingInAsync
            | RuleId::RsTokioPreferBoundedChannel
            | RuleId::RsPerfNoCloneInLoop
            | RuleId::RsPerfHoistRegexToLazylock
            | RuleId::RsPerfPreferVecWithCapacity
            | RuleId::RsPerfNoUnnecessaryFormat
    )
}

fn candidate_to_diagnostic(
    file_path: &Path,
    finding: &RsCandidateFinding,
    severity: RuleSeverity,
) -> Diagnostic {
    let meta = finding.rule.metadata();
    Diagnostic {
        file: file_path.to_path_buf(),
        subject_name: finding.subject_name.clone(),
        rule: finding.rule,
        category: meta.category,
        severity,
        message_id: finding.message_id,
        tier: if finding.autofix.is_some() {
            PrescriptionTier::Autofix
        } else {
            meta.default_tier
        },
        target_name: finding.target_name.clone(),
        message: finding.message.clone(),
        docs_url: meta.docs_url,
        loc: finding.loc,
        span: finding.span,
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: finding.autofix.clone(),
    }
}

fn resolve_rs_rule_activation(
    rule: RuleId,
    file: &ExtractedFile,
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

    if file.file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && !has_explicit_cli_rule
        && explicit_config_override.is_none()
    {
        return None;
    }

    if config.is_overridden_for_file(rule, &file.path, package_root) && !has_explicit_cli_rule {
        return None;
    }

    if !has_explicit_cli_rule && !gate.allows_rule(meta) {
        return None;
    }

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
