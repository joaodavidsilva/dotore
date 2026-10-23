//! Rule activation gating and evaluation for `dotore-rs` core safety rules.

use std::path::Path;

use dotore_core::{
    CapabilityGate, Diagnostic, DotoreConfig, ExtractedFile, FileContext, PackageAnalysisResult,
    RuleId, RuleSeverity, RuleTag, WorkspacePackage,
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
        if !is_supported_rust_rule(finding.rule) {
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

const fn is_supported_rust_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::RsNoUnwrapInProduction
            | RuleId::RsNoUnguardedSliceIndex
            | RuleId::RsNoLossyNumericAsCast
            | RuleId::RsRequireSafetyCommentOnUnsafe
            | RuleId::RsNoMemForget
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
        tier: meta.default_tier,
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
