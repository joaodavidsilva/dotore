//! Project-level supply-chain, pnpm workspace hardening (`require-pnpm-hardening`),
//! and React Server Components security advisory (`no-vulnerable-react-server-components`)
//! checks, plus fail-open Socket.dev PURL dependency scoring with local disk caching
//! (`low-supply-chain-score`).

mod socket_scoring;

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

use self::socket_scoring::check_supply_chain_scores;
use crate::{
    config::{WorkspacePackage, strip_jsonc},
    graph::ProjectGraph,
    ir::{ByteSpan, SourceLoc},
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

const PNPM_WORKSPACE_FILE: &str = "pnpm-workspace.yaml";
pub(super) const PNPM_LOCKFILE: &str = "pnpm-lock.yaml";
pub(super) const PACKAGE_JSON_FILE: &str = "package.json";
const RECOMMENDED_PNPM_MINIMUM_RELEASE_AGE_MINUTES: u32 = 10_080;

const REACT_SERVER_DOM_PACKAGES: &[&str] = &[
    "react-server-dom-webpack",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
];
const REACT_BLOG_RSC_ADVISORY_URL: &str =
    "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components";
const VERCEL_NEXTJS_SECURITY_RELEASE_URL: &str =
    "https://vercel.com/changelog/next-js-may-2026-security-release";
const NEXTJS_OLDEST_AFFECTED_MAJOR: u32 = 13;
const NEXTJS_SUPPORTED_UPGRADE_TARGETS: &str = "15.5.18 or 16.2.6";

pub use dotore_core::rules::supply_chain_purl_hash;

/// Evaluates project-level security and supply-chain checks across `graph` and `packages`.
pub(crate) fn evaluate_project_supply_chain_rules(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    let should_run_rule = |rule: RuleId, pkg: &WorkspacePackage| -> Option<RuleSeverity> {
        if let Some(explicit) = enabled_rules {
            if !explicit.contains(&rule) {
                return None;
            }
            return Some(
                pkg.config
                    .effective_severity(rule)
                    .unwrap_or_else(|| rule.metadata().default_severity),
            );
        }
        if !graph.has_manifests {
            return None;
        }
        pkg.config.effective_severity(rule)
    };

    if let Some(root_pkg) = packages.first() {
        if let Some(sev) = should_run_rule(RuleId::RequirePnpmHardening, root_pkg) {
            check_pnpm_hardening(graph, &root_pkg.root_dir, sev, out);
        }
        if should_run_rule(RuleId::NoVulnerableReactServerComponents, root_pkg).is_some() {
            check_react_server_components_advisory(graph, packages, out);
        }
        if let Some(sev) = should_run_rule(RuleId::LowSupplyChainScore, root_pkg) {
            check_supply_chain_scores(
                graph,
                &root_pkg.root_dir,
                &root_pkg.config,
                sev,
                enabled_rules.is_some(),
                out,
            );
        }
    }
}

#[derive(Debug, Clone)]
struct PnpmScalar {
    value: String,
    line: u32,
    column: u32,
}

#[derive(Debug, Default)]
struct PnpmHardeningSettings {
    minimum_release_age: Option<PnpmScalar>,
    block_exotic_subdeps: Option<PnpmScalar>,
    trust_policy: Option<PnpmScalar>,
}

fn check_pnpm_hardening(
    graph: &ProjectGraph,
    root_dir: &Path,
    severity: RuleSeverity,
    out: &mut Vec<Diagnostic>,
) {
    let ws_yaml = read_manifest(graph, root_dir, PNPM_WORKSPACE_FILE);
    let lock_yaml = read_manifest(graph, root_dir, PNPM_LOCKFILE);
    let pkg_json = read_manifest(graph, root_dir, PACKAGE_JSON_FILE);

    let is_pnpm = ws_yaml.is_some()
        || lock_yaml.is_some()
        || pkg_json.as_deref().is_some_and(|raw| {
            serde_json::from_str::<Value>(&strip_jsonc(raw))
                .ok()
                .and_then(|v| {
                    v.get("packageManager")
                        .and_then(Value::as_str)
                        .map(|s| s.starts_with("pnpm@"))
                })
                .unwrap_or(false)
        });
    if !is_pnpm {
        return;
    }

    let ws_content = ws_yaml.unwrap_or_default();
    let settings = parse_pnpm_hardening_settings(&ws_content);
    let file_path = if root_dir == Path::new(".") {
        PathBuf::from(PNPM_WORKSPACE_FILE)
    } else {
        root_dir.join(PNPM_WORKSPACE_FILE)
    };
    if settings.minimum_release_age.is_none() {
        out.push(
            make_diag_for_subject(
                RuleId::RequirePnpmHardening,
                file_path.clone(),
                None,
                "requirePnpmHardening",
                "minimumReleaseAge",
                format!(
                    "pnpm-workspace.yaml is missing `minimumReleaseAge` — newly published versions can ship malware that gets caught and unpublished within hours. Add `minimumReleaseAge: {RECOMMENDED_PNPM_MINIMUM_RELEASE_AGE_MINUTES}`."
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(severity),
        );
    }

    if let Some(exotic) = &settings.block_exotic_subdeps
        && exotic.value.eq_ignore_ascii_case("false")
    {
        out.push(
            make_diag_for_subject(
                RuleId::RequirePnpmHardening,
                file_path.clone(),
                None,
                "requirePnpmHardening",
                "blockExoticSubdeps",
                "`blockExoticSubdeps: false` allows transitive deps from `git:`, `file:`, or tarball URLs — a known supply-chain bypass of the npm registry",
                SourceLoc {
                    line: exotic.line,
                    column: exotic.column,
                },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(severity),
        );
    }

    match &settings.trust_policy {
        None => {
            out.push(
                make_diag_for_subject(
                    RuleId::RequirePnpmHardening,
                    file_path,
                    None,
                    "requirePnpmHardening",
                    "trustPolicy",
                    "pnpm-workspace.yaml is missing `trustPolicy` — without `no-downgrade`, pnpm silently accepts packages whose trust signals (provenance, signatures) weaken between updates",
                    SourceLoc { line: 1, column: 1 },
                    ByteSpan { start: 0, end: 0 },
                )
                .with_severity(severity),
            );
        }
        Some(tp) if tp.value != "no-downgrade" => {
            out.push(
                make_diag_for_subject(
                    RuleId::RequirePnpmHardening,
                    file_path,
                    None,
                    "requirePnpmHardening",
                    "trustPolicy",
                    format!(
                        "`trustPolicy: {}` is weaker than `no-downgrade` — packages may lose trust signals between updates without you noticing",
                        tp.value
                    ),
                    SourceLoc {
                        line: tp.line,
                        column: tp.column,
                    },
                    ByteSpan { start: 0, end: 0 },
                )
                .with_severity(severity),
            );
        }
        Some(_) => {}
    }
}

fn parse_pnpm_hardening_settings(content: &str) -> PnpmHardeningSettings {
    let mut settings = PnpmHardeningSettings::default();
    let stripped = content.strip_prefix('\u{feff}').unwrap_or(content);
    for (idx, raw_line) in stripped.lines().enumerate() {
        let Some(first_non_ws) = raw_line.find(|c: char| !c.is_whitespace()) else {
            continue;
        };
        // Only top-level keys (column 0) count; nested keys inside `catalog:` are ignored.
        if first_non_ws != 0 {
            continue;
        }
        let trimmed = raw_line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(colon_idx) = trimmed.find(':') else {
            continue;
        };
        if colon_idx == 0 {
            continue;
        }
        let key = unquote_yaml_scalar(trimmed[..colon_idx].trim());
        if !matches!(
            key,
            "minimumReleaseAge" | "blockExoticSubdeps" | "trustPolicy"
        ) {
            continue;
        }
        let value_part = strip_yaml_inline_comment(&trimmed[colon_idx + 1..]).trim();
        if value_part.is_empty() {
            continue;
        }
        let scalar = PnpmScalar {
            value: unquote_yaml_scalar(value_part).to_string(),
            line: u32::try_from(idx + 1).unwrap_or(1),
            column: u32::try_from(first_non_ws + 1).unwrap_or(1),
        };
        match key {
            "minimumReleaseAge" => settings.minimum_release_age = Some(scalar),
            "blockExoticSubdeps" => settings.block_exotic_subdeps = Some(scalar),
            "trustPolicy" => settings.trust_policy = Some(scalar),
            _ => {}
        }
    }
    settings
}

fn strip_yaml_inline_comment(raw_value: &str) -> &str {
    let mut active_quote: Option<u8> = None;
    let bytes = raw_value.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = active_quote {
            if b == q {
                active_quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            active_quote = Some(b);
        } else if b == b'#' && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            return &raw_value[..i];
        }
    }
    raw_value
}

pub(super) fn unquote_yaml_scalar(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|inner| inner.strip_suffix('\'')))
        .unwrap_or(s)
}

fn check_react_server_components_advisory(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    out: &mut Vec<Diagnostic>,
) {
    let mut seen_messages = HashSet::new();
    let mut candidate_dirs: Vec<PathBuf> = vec![PathBuf::from(".")];
    for pkg in packages {
        if !candidate_dirs.contains(&pkg.root_dir) {
            candidate_dirs.push(pkg.root_dir.clone());
        }
    }

    for dir in &candidate_dirs {
        check_rsc_advisory_in_dir(graph, dir, &mut seen_messages, out);
    }
}

fn check_rsc_advisory_in_dir(
    graph: &ProjectGraph,
    dir: &Path,
    seen_messages: &mut HashSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    let pkg_json_path = if dir == Path::new(".") {
        PathBuf::from(PACKAGE_JSON_FILE)
    } else {
        dir.join(PACKAGE_JSON_FILE)
    };
    let next_version = resolve_concrete_package_version(graph, dir, "next");
    if let Some(next_ver) = &next_version {
        for diag in evaluate_nextjs_rsc_advisory(&pkg_json_path, next_ver) {
            if seen_messages.insert(diag.message.clone()) {
                out.push(diag);
            }
        }
    }

    let next_governs_rsc = next_version
        .as_deref()
        .and_then(parse_semver)
        .is_some_and(|(major, _, _)| major >= NEXTJS_OLDEST_AFFECTED_MAJOR);
    if next_governs_rsc {
        return;
    }

    for &rsc_pkg in REACT_SERVER_DOM_PACKAGES {
        let Some(ver) = resolve_concrete_package_version(graph, dir, rsc_pkg) else {
            continue;
        };
        for diag in evaluate_react_server_dom_advisory(&pkg_json_path, rsc_pkg, &ver) {
            if seen_messages.insert(diag.message.clone()) {
                out.push(diag);
            }
        }
    }
}

fn resolve_concrete_package_version(
    graph: &ProjectGraph,
    dir: &Path,
    package_name: &str,
) -> Option<String> {
    let nm_rel = format!("node_modules/{package_name}/package.json");
    if let Some(nm_raw) = read_manifest(graph, dir, &nm_rel)
        && let Ok(val) = serde_json::from_str::<Value>(&strip_jsonc(&nm_raw))
        && let Some(ver_str) = val.get("version").and_then(Value::as_str)
        && let Some(clean) = normalize_exact_semver(ver_str)
    {
        return Some(clean);
    }

    let pkg_raw = read_manifest(graph, dir, PACKAGE_JSON_FILE)?;
    let val = serde_json::from_str::<Value>(&strip_jsonc(&pkg_raw)).ok()?;
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(spec) = val
            .get(section)
            .and_then(Value::as_object)
            .and_then(|o| o.get(package_name))
            .and_then(Value::as_str)
        {
            return normalize_exact_semver(spec);
        }
    }
    None
}

fn evaluate_react_server_dom_advisory(
    pkg_json_path: &Path,
    package_name: &str,
    version: &str,
) -> Vec<Diagnostic> {
    let Some(ver_tuple) = parse_semver(version) else {
        return Vec::new();
    };
    let (rce_fixed, latest_safe) = match (ver_tuple.0, ver_tuple.1) {
        (19, 0) => ("19.0.1", "19.0.6"),
        (19, 1) => ("19.1.2", "19.1.7"),
        (19, 2) => ("19.2.1", "19.2.6"),
        _ => return Vec::new(),
    };
    let Some(rce_tuple) = parse_semver(rce_fixed) else {
        return Vec::new();
    };
    let Some(safe_tuple) = parse_semver(latest_safe) else {
        return Vec::new();
    };
    let installed_display = format!("{package_name}@{version}");
    let line_display = format!("{}.{}", ver_tuple.0, ver_tuple.1);
    if ver_tuple < rce_tuple {
        return vec![
            make_diag_for_subject(
                RuleId::NoVulnerableReactServerComponents,
                pkg_json_path.to_path_buf(),
                None,
                "vulnerableReactServerComponents",
                installed_display.clone(),
                format!(
                    "{installed_display} has the critical React Server Components remote code execution vulnerability (CVE-2025-55182, CVSS 10.0) — an unauthenticated attacker can run arbitrary code on your server by sending a crafted payload to any Server Function endpoint. Upgrade to {latest_safe} within {line_display}. See {REACT_BLOG_RSC_ADVISORY_URL}"
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(RuleSeverity::Error),
        ];
    }

    if ver_tuple < safe_tuple {
        return vec![
            make_diag_for_subject(
                RuleId::NoVulnerableReactServerComponents,
                pkg_json_path.to_path_buf(),
                None,
                "vulnerableReactServerComponents",
                installed_display.clone(),
                format!(
                    "{installed_display} is affected by a high-severity React Server Components denial-of-service vulnerability (CVE-2026-23870) patched in {latest_safe}. Upgrade to {latest_safe} within {line_display}. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(RuleSeverity::Warning),
        ];
    }

    Vec::new()
}

fn evaluate_nextjs_rsc_advisory(pkg_json_path: &Path, version: &str) -> Vec<Diagnostic> {
    let Some(ver_tuple) = parse_semver(version) else {
        return Vec::new();
    };
    let major = ver_tuple.0;
    if major < NEXTJS_OLDEST_AFFECTED_MAJOR {
        return Vec::new();
    }
    let installed_display = format!("next@{version}");
    let _ = RuleId::NoVulnerableReactServerComponents;

    let latest_safe = match major {
        15 => Some("15.5.18"),
        16 => Some("16.2.6"),
        _ => None,
    };

    let Some(latest_safe_ver) = latest_safe else {
        if major >= 15 {
            return Vec::new();
        }
        return vec![
            make_diag_for_subject(
                RuleId::NoVulnerableReactServerComponents,
                pkg_json_path.to_path_buf(),
                None,
                "vulnerableReactServerComponents",
                installed_display.clone(),
                format!(
                    "{installed_display} is on an unsupported Next.js release line affected by the React Server Components security advisories — there is no patched {major}.x release. Upgrade to a patched Next.js release ({NEXTJS_SUPPORTED_UPGRADE_TARGETS}). Next.js bundles its own React Server Components runtime. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(RuleSeverity::Warning),
        ];
    };

    let rce_fixed = match (major, ver_tuple.1) {
        (15, 0) => Some("15.0.5"),
        (15, 1) => Some("15.1.9"),
        (15, 2) => Some("15.2.6"),
        (15, 3) => Some("15.3.6"),
        (15, 4) => Some("15.4.8"),
        (15, 5) => Some("15.5.7"),
        (16, 0) => Some("16.0.7"),
        _ => None,
    };

    if let Some(rce_str) = rce_fixed
        && let Some(rce_tuple) = parse_semver(rce_str)
        && ver_tuple < rce_tuple
    {
        return vec![
            make_diag_for_subject(
                RuleId::NoVulnerableReactServerComponents,
                pkg_json_path.to_path_buf(),
                None,
                "vulnerableReactServerComponents",
                installed_display.clone(),
                format!(
                    "{installed_display} bundles the React Server Components runtime affected by the critical remote code execution vulnerability (CVE-2025-55182, CVSS 10.0) — an unauthenticated attacker can run arbitrary code on your server by sending a crafted payload to any Server Function or Server Action endpoint. Upgrade Next.js to next@{latest_safe_ver} (bundles its own React Server Components runtime). See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(RuleSeverity::Error),
        ];
    }

    if let Some(safe_tuple) = parse_semver(latest_safe_ver)
        && ver_tuple < safe_tuple
    {
        return vec![
            make_diag_for_subject(
                RuleId::NoVulnerableReactServerComponents,
                pkg_json_path.to_path_buf(),
                None,
                "vulnerableReactServerComponents",
                installed_display.clone(),
                format!(
                    "{installed_display} bundles a React Server Components runtime affected by a high-severity denial-of-service vulnerability (CVE-2026-23870) patched in Next.js next@{latest_safe_ver}. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
                ),
                SourceLoc { line: 1, column: 1 },
                ByteSpan { start: 0, end: 0 },
            )
            .with_severity(RuleSeverity::Warning),
        ];
    }

    Vec::new()
}

pub(super) fn read_manifest(graph: &ProjectGraph, dir: &Path, rel_name: &str) -> Option<String> {
    let candidate = if dir == Path::new(".") {
        PathBuf::from(rel_name)
    } else {
        dir.join(rel_name)
    };
    if let Some(content) = graph.manifests.get(&candidate) {
        return Some(content.clone());
    }
    let norm = candidate.to_string_lossy().replace('\\', "/");
    let stripped = norm.strip_prefix("./").unwrap_or(&norm);
    for (k, v) in &graph.manifests {
        let kn = k.to_string_lossy().replace('\\', "/");
        let ks = kn.strip_prefix("./").unwrap_or(&kn);
        if ks == stripped {
            return Some(v.clone());
        }
    }
    fs::read_to_string(&candidate).ok()
}

pub(super) fn normalize_exact_semver(spec: &str) -> Option<String> {
    let trimmed = spec.trim().strip_prefix('v').unwrap_or(spec.trim());
    if trimmed.is_empty() || trimmed.contains(['^', '~', '>', '<', '=', '*', '|', ' ']) {
        return None;
    }
    let (core, _) = trimmed.split_once(['-', '+']).unwrap_or((trimmed, ""));
    let mut parts = core.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let _ = (major, minor, patch);
    Some(trimmed.to_string())
}

pub(super) fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let trimmed = ver.trim().strip_prefix('v').unwrap_or(ver.trim());
    let (core, _) = trimmed.split_once(['-', '+']).unwrap_or((trimmed, ""));
    let mut parts = core.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

