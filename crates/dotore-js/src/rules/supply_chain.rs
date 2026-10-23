//! Project-level supply-chain, pnpm workspace hardening (`require-pnpm-hardening`),
//! and React Server Components security advisory (`no-vulnerable-react-server-components`)
//! checks, plus fail-open Socket.dev PURL dependency scoring with local disk caching
//! (`low-supply-chain-score`).

use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    config::{DotoreConfig, SupplyChainConfig, WorkspacePackage, strip_jsonc},
    graph::ProjectGraph,
    ir::{
        ByteSpan, SourceLoc,
        types::{compute_line_starts, loc_from_line_starts},
    },
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

const PNPM_WORKSPACE_FILE: &str = "pnpm-workspace.yaml";
const PNPM_LOCKFILE: &str = "pnpm-lock.yaml";
const PACKAGE_JSON_FILE: &str = "package.json";
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

const SOCKET_FREE_PURL_API_BASE: &str = "https://firewall-api.socket.dev/purl";
const SOCKET_PACKAGE_PAGE_BASE: &str = "https://socket.dev/npm/package";
const SOCKET_FREE_USER_AGENT: &str = "dotore-supply-chain";
const SUPPLY_CHAIN_CACHE_SUBDIR: &str = "supply-chain";
const SUPPLY_CHAIN_CACHE_TTL_MS: u64 = 86_400_000;
const SUPPLY_CHAIN_MAX_ALERTS_SHOWN: usize = 3;
const SUPPLY_CHAIN_ALERT_NOTE_MAX_CHARS: usize = 160;

/// Computes the deterministic 16-hex-character cache filename key for a Socket PURL (`pkg:npm/<name>@<version>`).
#[must_use]
pub fn supply_chain_purl_hash(purl: &str) -> String {
    let digest = sha256_bytes(purl.as_bytes());
    let mut hex = String::with_capacity(16);
    for &b in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

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
    let meta = RuleId::RequirePnpmHardening.metadata();

    if settings.minimum_release_age.is_none() {
        out.push(Diagnostic {
            file: file_path.clone(),
            subject_name: None,
            rule: RuleId::RequirePnpmHardening,
            category: meta.category,
            severity,
            message_id: "requirePnpmHardening",
            tier: meta.default_tier,
            target_name: "minimumReleaseAge".to_string(),
            message: format!(
                "pnpm-workspace.yaml is missing `minimumReleaseAge` — newly published versions can ship malware that gets caught and unpublished within hours. Add `minimumReleaseAge: {RECOMMENDED_PNPM_MINIMUM_RELEASE_AGE_MINUTES}`."
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    if let Some(exotic) = &settings.block_exotic_subdeps
        && exotic.value.eq_ignore_ascii_case("false")
    {
        out.push(Diagnostic {
            file: file_path.clone(),
            subject_name: None,
            rule: RuleId::RequirePnpmHardening,
            category: meta.category,
            severity,
            message_id: "requirePnpmHardening",
            tier: meta.default_tier,
            target_name: "blockExoticSubdeps".to_string(),
            message: "`blockExoticSubdeps: false` allows transitive deps from `git:`, `file:`, or tarball URLs — a known supply-chain bypass of the npm registry".to_string(),
            docs_url: meta.docs_url,
            loc: SourceLoc {
                line: exotic.line,
                column: exotic.column,
            },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    match &settings.trust_policy {
        None => {
            out.push(Diagnostic {
                file: file_path,
                subject_name: None,
                rule: RuleId::RequirePnpmHardening,
                category: meta.category,
                severity,
                message_id: "requirePnpmHardening",
                tier: meta.default_tier,
                target_name: "trustPolicy".to_string(),
                message: "pnpm-workspace.yaml is missing `trustPolicy` — without `no-downgrade`, pnpm silently accepts packages whose trust signals (provenance, signatures) weaken between updates".to_string(),
                docs_url: meta.docs_url,
                loc: SourceLoc { line: 1, column: 1 },
                span: ByteSpan { start: 0, end: 0 },
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
        }
        Some(tp) if tp.value != "no-downgrade" => {
            out.push(Diagnostic {
                file: file_path,
                subject_name: None,
                rule: RuleId::RequirePnpmHardening,
                category: meta.category,
                severity,
                message_id: "requirePnpmHardening",
                tier: meta.default_tier,
                target_name: "trustPolicy".to_string(),
                message: format!(
                    "`trustPolicy: {}` is weaker than `no-downgrade` — packages may lose trust signals between updates without you noticing",
                    tp.value
                ),
                docs_url: meta.docs_url,
                loc: SourceLoc {
                    line: tp.line,
                    column: tp.column,
                },
                span: ByteSpan { start: 0, end: 0 },
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
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

fn unquote_yaml_scalar(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
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
            continue;
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
    let meta = RuleId::NoVulnerableReactServerComponents.metadata();

    if ver_tuple < rce_tuple {
        return vec![Diagnostic {
            file: pkg_json_path.to_path_buf(),
            subject_name: None,
            rule: RuleId::NoVulnerableReactServerComponents,
            category: meta.category,
            severity: RuleSeverity::Error,
            message_id: "vulnerableReactServerComponents",
            tier: meta.default_tier,
            target_name: installed_display.clone(),
            message: format!(
                "{installed_display} has the critical React Server Components remote code execution vulnerability (CVE-2025-55182, CVSS 10.0) — an unauthenticated attacker can run arbitrary code on your server by sending a crafted payload to any Server Function endpoint. Upgrade to {latest_safe} within {line_display}. See {REACT_BLOG_RSC_ADVISORY_URL}"
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }];
    }

    if ver_tuple < safe_tuple {
        return vec![Diagnostic {
            file: pkg_json_path.to_path_buf(),
            subject_name: None,
            rule: RuleId::NoVulnerableReactServerComponents,
            category: meta.category,
            severity: RuleSeverity::Warning,
            message_id: "vulnerableReactServerComponents",
            tier: meta.default_tier,
            target_name: installed_display.clone(),
            message: format!(
                "{installed_display} is affected by a high-severity React Server Components denial-of-service vulnerability (CVE-2026-23870) patched in {latest_safe}. Upgrade to {latest_safe} within {line_display}. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }];
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
    let meta = RuleId::NoVulnerableReactServerComponents.metadata();

    let latest_safe = match major {
        15 => Some("15.5.18"),
        16 => Some("16.2.6"),
        _ => None,
    };

    let Some(latest_safe_ver) = latest_safe else {
        if major >= 15 {
            return Vec::new();
        }
        return vec![Diagnostic {
            file: pkg_json_path.to_path_buf(),
            subject_name: None,
            rule: RuleId::NoVulnerableReactServerComponents,
            category: meta.category,
            severity: RuleSeverity::Warning,
            message_id: "vulnerableReactServerComponents",
            tier: meta.default_tier,
            target_name: installed_display.clone(),
            message: format!(
                "{installed_display} is on an unsupported Next.js release line affected by the React Server Components security advisories — there is no patched {major}.x release. Upgrade to a patched Next.js release ({NEXTJS_SUPPORTED_UPGRADE_TARGETS}). Next.js bundles its own React Server Components runtime. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }];
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
        return vec![Diagnostic {
            file: pkg_json_path.to_path_buf(),
            subject_name: None,
            rule: RuleId::NoVulnerableReactServerComponents,
            category: meta.category,
            severity: RuleSeverity::Error,
            message_id: "vulnerableReactServerComponents",
            tier: meta.default_tier,
            target_name: installed_display.clone(),
            message: format!(
                "{installed_display} bundles the React Server Components runtime affected by the critical remote code execution vulnerability (CVE-2025-55182, CVSS 10.0) — an unauthenticated attacker can run arbitrary code on your server by sending a crafted payload to any Server Function or Server Action endpoint. Upgrade Next.js to next@{latest_safe_ver} (bundles its own React Server Components runtime). See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }];
    }

    if let Some(safe_tuple) = parse_semver(latest_safe_ver)
        && ver_tuple < safe_tuple
    {
        return vec![Diagnostic {
            file: pkg_json_path.to_path_buf(),
            subject_name: None,
            rule: RuleId::NoVulnerableReactServerComponents,
            category: meta.category,
            severity: RuleSeverity::Warning,
            message_id: "vulnerableReactServerComponents",
            tier: meta.default_tier,
            target_name: installed_display.clone(),
            message: format!(
                "{installed_display} bundles a React Server Components runtime affected by a high-severity denial-of-service vulnerability (CVE-2026-23870) patched in Next.js next@{latest_safe_ver}. See {VERCEL_NEXTJS_SECURITY_RELEASE_URL}"
            ),
            docs_url: meta.docs_url,
            loc: SourceLoc { line: 1, column: 1 },
            span: ByteSpan { start: 0, end: 0 },
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }];
    }

    Vec::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepSection {
    Dependencies,
    DevDependencies,
}

impl DepSection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Dependencies => "dependencies",
            Self::DevDependencies => "devDependencies",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionResolution {
    Pin,
    Locked,
    Floor,
}

#[derive(Debug, Clone)]
struct DependencyToScore {
    name: String,
    version: String,
    spec: String,
    section: DepSection,
    resolution: VersionResolution,
    loc: SourceLoc,
    span: ByteSpan,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SocketScore {
    overall: f64,
    supply_chain: f64,
    vulnerability: f64,
    maintenance: f64,
    quality: f64,
    license: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct SocketAlertProps {
    note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SocketAlert {
    #[serde(rename = "type")]
    alert_type: String,
    severity: String,
    file: Option<String>,
    props: Option<SocketAlertProps>,
}

#[derive(Debug, Clone)]
struct SocketArtifact {
    score: SocketScore,
    alerts: Vec<SocketAlert>,
}

fn check_supply_chain_scores(
    graph: &ProjectGraph,
    root_dir: &Path,
    config: &DotoreConfig,
    default_severity: RuleSeverity,
    explicitly_requested: bool,
    out: &mut Vec<Diagnostic>,
) {
    let sc_cfg = &config.supply_chain;
    if !sc_cfg.enabled {
        return;
    }
    let Some(pkg_raw) = read_manifest(graph, root_dir, PACKAGE_JSON_FILE) else {
        return;
    };
    let Ok(pkg_json) = serde_json::from_str::<Value>(&strip_jsonc(&pkg_raw)) else {
        return;
    };

    let deps = collect_dependencies_to_score(
        graph,
        root_dir,
        &pkg_json,
        &pkg_raw,
        sc_cfg.include_dev_dependencies,
    );
    if deps.is_empty() {
        return;
    }

    let cache_dir = resolve_supply_chain_cache_dir(root_dir, sc_cfg);
    if let Some(cdir) = &cache_dir {
        prune_expired_socket_cache(cdir);
    }

    let allow_network = explicitly_requested || sc_cfg.api_base_url.is_some();
    let pkg_json_path = if root_dir == Path::new(".") {
        PathBuf::from(PACKAGE_JSON_FILE)
    } else {
        root_dir.join(PACKAGE_JSON_FILE)
    };
    let effective_sev = if config
        .explicit_rule_override(RuleId::LowSupplyChainScore)
        .is_some()
    {
        default_severity
    } else {
        sc_cfg.severity
    };
    let min_score = sc_cfg.min_score.clamp(0, 100);

    for dep in deps {
        let Some(artifact) =
            fetch_or_read_socket_artifact(&dep, cache_dir.as_deref(), sc_cfg, allow_network)
        else {
            continue;
        };

        let (failing_axis_key, failing_axis_label, failing_meaning, failing_remediation, raw_val) =
            match dep.section {
                DepSection::DevDependencies => (
                    "supplyChain",
                    "supply chain",
                    "risky install-time behavior — install scripts, obfuscated or native code, network/filesystem/shell access, or typosquatting",
                    "Confirm this is the package you meant to install, and prefer a more established, audited alternative",
                    artifact.score.supply_chain,
                ),
                DepSection::Dependencies => {
                    if artifact.score.vulnerability < artifact.score.supply_chain {
                        (
                            "vulnerability",
                            "vulnerability",
                            "known security vulnerabilities (CVEs) affecting this version",
                            "Upgrade to a version with no known advisories (run `npm audit` to find one), or replace it",
                            artifact.score.vulnerability,
                        )
                    } else {
                        (
                            "supplyChain",
                            "supply chain",
                            "risky install-time behavior — install scripts, obfuscated or native code, network/filesystem/shell access, or typosquatting",
                            "Confirm this is the package you meant to install, and prefer a more established, audited alternative",
                            artifact.score.supply_chain,
                        )
                    }
                }
            };

        let failing_score = to_hundred(raw_val);
        if failing_score >= min_score {
            continue;
        }

        let top_alerts = select_top_alerts(&artifact.alerts);
        let reason = if top_alerts.is_empty() {
            format!("This points to {failing_meaning}.")
        } else {
            format_alert_reason(&top_alerts, artifact.alerts.len())
        };
        let identity = format_dependency_identity(&dep);
        let other_axes = format_other_axis_scores(&artifact.score, failing_axis_key);
        let package_page_url = format!(
            "{SOCKET_PACKAGE_PAGE_BASE}/{}/overview/{}",
            dep.name, dep.version
        );
        let help = build_supply_chain_help(
            &dep,
            failing_remediation,
            &top_alerts,
            &package_page_url,
            min_score,
        );
        let meta = RuleId::LowSupplyChainScore.metadata();

        out.push(Diagnostic {
            file: pkg_json_path.clone(),
            subject_name: None,
            rule: RuleId::LowSupplyChainScore,
            category: meta.category,
            severity: effective_sev,
            message_id: "lowSupplyChainScore",
            tier: meta.default_tier,
            target_name: dep.name.clone(),
            message: format!(
                "`{identity}` scored {failing_score}/100 on Socket's {failing_axis_label} axis (minimum {min_score}). {reason} Other axes — {other_axes}. {help}"
            ),
            docs_url: meta.docs_url,
            loc: dep.loc,
            span: dep.span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }
}

fn collect_dependencies_to_score(
    graph: &ProjectGraph,
    root_dir: &Path,
    pkg_json: &Value,
    pkg_raw: &str,
    include_dev: bool,
) -> Vec<DependencyToScore> {
    let mut ordered: Vec<(String, String, DepSection)> = Vec::new();
    let mut seen = HashSet::new();

    if let Some(deps) = pkg_json.get("dependencies").and_then(Value::as_object) {
        for (name, val) in deps {
            if let Some(spec) = val.as_str()
                && seen.insert(name.clone())
            {
                ordered.push((name.clone(), spec.to_string(), DepSection::Dependencies));
            }
        }
    }
    if include_dev
        && let Some(dev_deps) = pkg_json.get("devDependencies").and_then(Value::as_object)
    {
        for (name, val) in dev_deps {
            if let Some(spec) = val.as_str()
                && seen.insert(name.clone())
            {
                ordered.push((name.clone(), spec.to_string(), DepSection::DevDependencies));
            }
        }
    }

    let npm_lock = read_manifest(graph, root_dir, "package-lock.json");
    let yarn_lock = read_manifest(graph, root_dir, "yarn.lock");
    let pnpm_lock = read_manifest(graph, root_dir, PNPM_LOCKFILE);
    let line_starts = compute_line_starts(pkg_raw);

    let mut out = Vec::new();
    for (name, spec, section) in ordered {
        if name == "next" {
            continue;
        }
        let Some(floor_version) = resolve_range_floor(&spec) else {
            continue;
        };
        let locked_version = npm_lock
            .as_deref()
            .and_then(|l| lookup_npm_lock_version(l, &name))
            .or_else(|| {
                yarn_lock
                    .as_deref()
                    .and_then(|l| lookup_yarn_lock_version(l, &name, &spec))
            })
            .or_else(|| {
                pnpm_lock
                    .as_deref()
                    .and_then(|l| lookup_pnpm_lock_version(l, &name))
            });

        let lock_satisfies = locked_version
            .as_deref()
            .is_some_and(|lv| semver_satisfies_range(lv, &spec));
        let is_exact_pin = normalize_exact_semver(&spec).is_some();

        let (version, resolution) = if is_exact_pin {
            (floor_version, VersionResolution::Pin)
        } else if let Some(lv) = locked_version
            && lock_satisfies
        {
            (lv, VersionResolution::Locked)
        } else {
            (floor_version, VersionResolution::Floor)
        };

        let (loc, span) = locate_dependency_key(pkg_raw, &line_starts, section.as_str(), &name);
        out.push(DependencyToScore {
            name,
            version,
            spec,
            section,
            resolution,
            loc,
            span,
        });
    }
    out
}

fn locate_dependency_key(
    pkg_raw: &str,
    line_starts: &[u32],
    section: &str,
    dep_name: &str,
) -> (SourceLoc, ByteSpan) {
    let section_needle = format!("\"{section}\"");
    let key_needle = format!("\"{dep_name}\"");
    let Some(sec_pos) = pkg_raw.find(&section_needle) else {
        return (
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
        );
    };
    let after_sec = &pkg_raw[sec_pos + section_needle.len()..];
    let Some(open_brace_rel) = after_sec.find('{') else {
        return (
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
        );
    };
    let block_start = sec_pos + section_needle.len() + open_brace_rel;
    let block_slice = &pkg_raw[block_start..];
    let end_rel = find_matching_close_brace(block_slice);
    let section_body = &block_slice[..end_rel];
    let mut search_from = 0;
    while let Some(rel) = section_body[search_from..].find(&key_needle) {
        let hit = search_from + rel;
        let after_key = &section_body[hit + key_needle.len()..];
        if after_key.trim_start().starts_with(':') {
            let byte_start = u32::try_from(block_start + hit).unwrap_or(0);
            let byte_end =
                u32::try_from(block_start + hit + key_needle.len()).unwrap_or(byte_start);
            return (
                loc_from_line_starts(line_starts, byte_start),
                ByteSpan {
                    start: byte_start,
                    end: byte_end,
                },
            );
        }
        search_from = hit + key_needle.len();
    }
    (
        SourceLoc { line: 1, column: 1 },
        ByteSpan { start: 0, end: 0 },
    )
}
fn find_matching_close_brace(block_slice: &str) -> usize {
    let mut depth = 0_i32;
    for (idx, b) in block_slice.bytes().enumerate() {
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return idx;
            }
        }
    }
    block_slice.len()
}

fn resolve_supply_chain_cache_dir(root_dir: &Path, cfg: &SupplyChainConfig) -> Option<PathBuf> {
    if let Ok(val) = env::var("DOTORE_NO_CACHE") {
        let lower = val.to_ascii_lowercase();
        if lower == "1" || lower == "true" {
            return None;
        }
    }
    if let Some(custom) = &cfg.cache_dir {
        return Some(PathBuf::from(custom));
    }
    let nm_dir = root_dir.join("node_modules");
    if nm_dir.is_dir() {
        return Some(nm_dir.join(".cache").join("dotore"));
    }
    let root_hash = supply_chain_purl_hash(&root_dir.to_string_lossy());
    Some(env::temp_dir().join(format!("dotore-cache-{root_hash}")))
}

fn prune_expired_socket_cache(cache_dir: &Path) {
    let sc_dir = cache_dir.join(SUPPLY_CHAIN_CACHE_SUBDIR);
    let Ok(entries) = fs::read_dir(&sc_dir) else {
        return;
    };
    let now_ms = current_epoch_ms();
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(meta) = fs::metadata(&path)
            && let Ok(modified) = meta.modified()
            && let Ok(dur) = modified.duration_since(UNIX_EPOCH)
        {
            let mtime_ms = u64::try_from(dur.as_millis()).unwrap_or(0);
            if now_ms.saturating_sub(mtime_ms) > SUPPLY_CHAIN_CACHE_TTL_MS {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

fn fetch_or_read_socket_artifact(
    dep: &DependencyToScore,
    cache_dir: Option<&Path>,
    cfg: &SupplyChainConfig,
    allow_network: bool,
) -> Option<SocketArtifact> {
    let purl = format!("pkg:npm/{}@{}", dep.name, dep.version);
    let cache_file = cache_dir.map(|dir| {
        dir.join(SUPPLY_CHAIN_CACHE_SUBDIR)
            .join(format!("{}.json", supply_chain_purl_hash(&purl)))
    });

    if let Some(cfile) = &cache_file
        && let Some(cached_body) = read_cached_socket_body(cfile)
        && let Some(artifact) = parse_socket_artifact_from_body(&cached_body)
    {
        return Some(artifact);
    }

    if !allow_network {
        return None;
    }

    let base_url = cfg
        .api_base_url
        .as_deref()
        .unwrap_or(SOCKET_FREE_PURL_API_BASE)
        .trim_end_matches('/');
    let encoded_purl = percent_encode_purl(&purl);
    let url = format!("{base_url}/{encoded_purl}");
    let body = fetch_url_fail_open(&url)?;
    let artifact = parse_socket_artifact_from_body(&body)?;
    if let Some(cfile) = &cache_file {
        write_cached_socket_body(cfile, &body);
    }
    Some(artifact)
}

fn read_cached_socket_body(cache_file: &Path) -> Option<String> {
    let raw = fs::read_to_string(cache_file).ok()?;
    let val = serde_json::from_str::<Value>(&raw).ok()?;
    let fetched_at = val.get("fetchedAtMs")?.as_u64()?;
    let body = val.get("body")?.as_str()?;
    let now_ms = current_epoch_ms();
    if now_ms.saturating_sub(fetched_at) <= SUPPLY_CHAIN_CACHE_TTL_MS {
        Some(body.to_string())
    } else {
        None
    }
}

fn write_cached_socket_body(cache_file: &Path, body: &str) {
    if let Some(parent) = cache_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let payload = serde_json::json!({
        "fetchedAtMs": current_epoch_ms(),
        "body": body,
    });
    let _ = fs::write(cache_file, payload.to_string());
}

fn fetch_url_fail_open(url: &str) -> Option<String> {
    if let Some(file_path) = url.strip_prefix("file://") {
        return fs::read_to_string(file_path).ok();
    }
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "2",
            "-A",
            SOCKET_FREE_USER_AGENT,
            url,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn parse_socket_artifact_from_body(body: &str) -> Option<SocketArtifact> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(score_val) = val.get("score") else {
            continue;
        };
        let Ok(score) = serde_json::from_value::<SocketScore>(score_val.clone()) else {
            continue;
        };
        let mut alerts = Vec::new();
        if let Some(Value::Array(raw_alerts)) = val.get("alerts") {
            for item in raw_alerts {
                if let Ok(alert) = serde_json::from_value::<SocketAlert>(item.clone()) {
                    alerts.push(alert);
                }
            }
        }
        return Some(SocketArtifact { score, alerts });
    }
    None
}

fn to_hundred(normalized: f64) -> u32 {
    if !normalized.is_finite() {
        return 50;
    }
    let scaled = (normalized * 100.0).round().clamp(0.0, 100.0);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Clamped to 0.0..=100.0 before converting to u32"
    )]
    let out = scaled as u32;
    out
}

fn format_other_axis_scores(score: &SocketScore, failing_key: &str) -> String {
    let axes = [
        ("supplyChain", "supply chain", score.supply_chain),
        ("vulnerability", "vulnerability", score.vulnerability),
        ("maintenance", "maintenance", score.maintenance),
        ("quality", "quality", score.quality),
        ("license", "license", score.license),
    ];
    let _ = score.overall;
    axes.iter()
        .filter(|(k, _, _)| *k != failing_key)
        .map(|(_, label, val)| format!("{label} {}", to_hundred(*val)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn alert_severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "middle" | "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn display_alert_severity(severity: &str) -> String {
    let lower = severity.to_ascii_lowercase();
    if lower == "middle" {
        "medium".to_string()
    } else {
        lower
    }
}

fn friendly_alert_type(alert_type: &str) -> String {
    match alert_type {
        "malware" => "known malware".to_string(),
        "gptMalware" => "AI-detected malware".to_string(),
        "gptSecurity" => "AI-detected security risk".to_string(),
        "gptAnomaly" => "AI-detected code anomaly".to_string(),
        "envVars" => "environment-variable access".to_string(),
        "usesEval" => "use of eval".to_string(),
        "troll" => "protestware".to_string(),
        "didYouMean" | "typosquat" => "possible typosquat".to_string(),
        other => {
            let mut out = String::new();
            let chars: Vec<char> = other.chars().collect();
            for (i, &c) in chars.iter().enumerate() {
                if c == '_' || c == '-' {
                    out.push(' ');
                } else if c.is_ascii_uppercase() && i > 0 && chars[i - 1].is_ascii_alphanumeric() {
                    out.push(' ');
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c.to_ascii_lowercase());
                }
            }
            out.trim().to_string()
        }
    }
}

fn select_top_alerts(alerts: &[SocketAlert]) -> Vec<SocketAlert> {
    let mut sorted = alerts.to_vec();
    sorted.sort_by_key(|a| std::cmp::Reverse(alert_severity_rank(&a.severity)));
    sorted.truncate(SUPPLY_CHAIN_MAX_ALERTS_SHOWN);
    sorted
}

fn format_alert_reason(top_alerts: &[SocketAlert], total_count: usize) -> String {
    if let [single] = top_alerts {
        let loc = single
            .file
            .as_deref()
            .map(|f| format!(" in `{f}`"))
            .unwrap_or_default();
        let detail = single
            .props
            .as_ref()
            .and_then(|p| p.note.as_deref())
            .map(summarize_alert_note)
            .filter(|s| !s.is_empty())
            .map(|n| format!(": \"{n}\""))
            .unwrap_or_default();
        return format!(
            "Socket flagged a {} {} alert{loc}{detail}.",
            display_alert_severity(&single.severity),
            friendly_alert_type(&single.alert_type)
        );
    }
    let labels = top_alerts
        .iter()
        .map(|a| friendly_alert_type(&a.alert_type))
        .collect::<Vec<_>>()
        .join(", ");
    let more = if total_count > top_alerts.len() {
        format!(" (+{} more)", total_count - top_alerts.len())
    } else {
        String::new()
    };
    let worst = top_alerts
        .first()
        .map(|a| display_alert_severity(&a.severity))
        .unwrap_or_default();
    format!("Socket flagged {total_count} alerts ({labels}{more}); most severe: {worst}.")
}

fn summarize_alert_note(note: &str) -> String {
    let collapsed = note.split_whitespace().collect::<Vec<_>>().join(" ");
    let first_sentence = collapsed
        .find(". ")
        .map_or(collapsed.as_str(), |idx| &collapsed[..idx]);
    let trimmed = first_sentence.trim_end_matches('.');
    if trimmed.len() <= SUPPLY_CHAIN_ALERT_NOTE_MAX_CHARS {
        trimmed.to_string()
    } else {
        format!(
            "{}…",
            trimmed[..SUPPLY_CHAIN_ALERT_NOTE_MAX_CHARS].trim_end()
        )
    }
}

fn format_dependency_identity(dep: &DependencyToScore) -> String {
    match dep.resolution {
        VersionResolution::Pin => format!("{}@{}", dep.name, dep.version),
        VersionResolution::Locked => format!(
            "{}@{} (lockfile resolution of \"{}\")",
            dep.name, dep.version, dep.spec
        ),
        VersionResolution::Floor => format!(
            "{}@{} (lowest version \"{}\" allows)",
            dep.name, dep.version, dep.spec
        ),
    }
}

fn build_supply_chain_help(
    dep: &DependencyToScore,
    remediation: &str,
    top_alerts: &[SocketAlert],
    package_page_url: &str,
    min_score: u32,
) -> String {
    let has_critical = top_alerts
        .iter()
        .any(|a| a.severity.eq_ignore_ascii_case("critical"));
    let entry = format!("`\"{}\": \"{}\"`", dep.name, dep.spec);
    let action = if has_critical {
        format!(
            "Treat {} as compromised — do not ship it. Remove {entry} from package.json and your lockfile, then audit anything it ran.",
            dep.name
        )
    } else {
        format!("{remediation}; update {entry} in package.json.")
    };
    let escape = if has_critical {
        "Only if you've confirmed this is a false positive, set `supplyChain.enabled: false`."
            .to_string()
    } else {
        format!(
            "If you've reviewed and accepted this package, raise `supplyChain.minScore` (currently {min_score}) or set `supplyChain.severity: \"warning\"`."
        )
    };
    format!("{action} Full report: {package_page_url}. {escape}")
}

fn read_manifest(graph: &ProjectGraph, dir: &Path, rel_name: &str) -> Option<String> {
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

fn normalize_exact_semver(spec: &str) -> Option<String> {
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

fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
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

fn resolve_range_floor(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.contains(':') {
        return None;
    }
    let mut best: Option<((u32, u32, u32), String)> = None;
    for branch in trimmed.split("||") {
        let mut branch_floor: Option<((u32, u32, u32), String)> = None;
        for token in branch.split_whitespace() {
            let cleaned = token.trim_start_matches(['^', '~', '>', '=', 'v']);
            if cleaned.starts_with('<') || cleaned.is_empty() {
                continue;
            }
            let normalized = match cleaned.split('.').count() {
                1 => format!("{cleaned}.0.0"),
                2 => format!("{cleaned}.0"),
                _ => cleaned.to_string(),
            };
            if let Some(tuple) = parse_semver(&normalized) {
                match &branch_floor {
                    None => branch_floor = Some((tuple, normalized)),
                    Some((prev, _)) if tuple > *prev => branch_floor = Some((tuple, normalized)),
                    Some(_) => {}
                }
            }
        }
        if let Some((t, s)) = branch_floor {
            match &best {
                None => best = Some((t, s)),
                Some((prev, _)) if t < *prev => best = Some((t, s)),
                Some(_) => {}
            }
        }
    }
    best.map(|(_, s)| s)
}

fn semver_satisfies_range(version: &str, spec: &str) -> bool {
    let Some(v) = parse_semver(version) else {
        return false;
    };
    let Some(floor_str) = resolve_range_floor(spec) else {
        return false;
    };
    let Some(f) = parse_semver(&floor_str) else {
        return false;
    };
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix('^') {
        let _ = rest;
        if f.0 > 0 {
            return v.0 == f.0 && v >= f;
        }
        return v.0 == 0 && v.1 == f.1 && v >= f;
    }
    if trimmed.starts_with('~') {
        return v.0 == f.0 && v.1 == f.1 && v >= f;
    }
    v >= f
}

fn lookup_npm_lock_version(lock_text: &str, name: &str) -> Option<String> {
    let val = serde_json::from_str::<Value>(lock_text).ok()?;
    let pkg_key = format!("node_modules/{name}");
    if let Some(ver) = val
        .get("packages")
        .and_then(Value::as_object)
        .and_then(|p| p.get(&pkg_key))
        .and_then(|e| e.get("version"))
        .and_then(Value::as_str)
    {
        return Some(ver.to_string());
    }
    val.get("dependencies")
        .and_then(Value::as_object)
        .and_then(|d| d.get(name))
        .and_then(|e| e.get("version"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn lookup_yarn_lock_version(lock_text: &str, name: &str, spec: &str) -> Option<String> {
    let descriptor = format!("{name}@{spec}");
    let berry_descriptor = format!("{name}@npm:{spec}");
    let lines: Vec<&str> = lock_text.lines().collect();
    for (i, &line) in lines.iter().enumerate() {
        if line.starts_with(' ') || line.starts_with('#') || !line.contains(':') {
            continue;
        }
        let header = line.trim_end().trim_end_matches(':');
        let matches = header.split(',').any(|part| {
            let p = part.trim().trim_matches('"');
            p == descriptor || p == berry_descriptor
        });
        if !matches {
            continue;
        }
        for &body_line in &lines[i + 1..] {
            if !body_line.starts_with(' ') && !body_line.is_empty() {
                break;
            }
            let t = body_line.trim();
            if let Some(rest) = t
                .strip_prefix("version:")
                .or_else(|| t.strip_prefix("version "))
            {
                let v = rest.trim().trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn lookup_pnpm_lock_version(lock_text: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = lock_text.lines().collect();
    for (i, &line) in lines.iter().enumerate() {
        let indent = line.len() - line.trim_start_matches(' ').len();
        if !(4..=8).contains(&indent) {
            continue;
        }
        let trimmed = line.trim();
        let Some(key_raw) = trimmed.strip_suffix(':') else {
            continue;
        };
        let key = unquote_yaml_scalar(key_raw.trim());
        if key != name {
            continue;
        }
        for &body_line in &lines[i + 1..] {
            let body_indent = body_line.len() - body_line.trim_start_matches(' ').len();
            if body_indent <= indent || body_line.trim().is_empty() {
                break;
            }
            if let Some(ver_raw) = body_line.trim().strip_prefix("version:") {
                let unquoted = unquote_yaml_scalar(ver_raw.trim());
                let clean = unquoted.split('(').next().unwrap_or(unquoted).trim();
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }
        }
    }
    None
}

fn percent_encode_purl(purl: &str) -> String {
    let mut out = String::with_capacity(purl.len() * 2);
    for b in purl.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0_u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0_u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
