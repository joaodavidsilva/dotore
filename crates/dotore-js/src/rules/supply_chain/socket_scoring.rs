//! Fail-open Socket.dev PURL dependency scoring, local disk caching, lockfile
//! version resolution, and alert formatting for `low-supply-chain-score`.

use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;

use super::{
    PACKAGE_JSON_FILE, PNPM_LOCKFILE, normalize_exact_semver, parse_semver, read_manifest,
    supply_chain_purl_hash, unquote_yaml_scalar,
};
use crate::{
    config::{DotoreConfig, SupplyChainConfig, strip_jsonc},
    graph::ProjectGraph,
    ir::{
        ByteSpan, SourceLoc,
        types::{compute_line_starts, loc_from_line_starts},
    },
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

const SOCKET_FREE_PURL_API_BASE: &str = "https://firewall-api.socket.dev/purl";
const SOCKET_PACKAGE_PAGE_BASE: &str = "https://socket.dev/npm/package";
const SOCKET_FREE_USER_AGENT: &str = "dotore-supply-chain";
const SUPPLY_CHAIN_CACHE_SUBDIR: &str = "supply-chain";
const SUPPLY_CHAIN_CACHE_TTL_MS: u64 = 86_400_000;
const SUPPLY_CHAIN_MAX_ALERTS_SHOWN: usize = 3;
const SUPPLY_CHAIN_ALERT_NOTE_MAX_CHARS: usize = 160;

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

pub(super) fn check_supply_chain_scores(
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
        if let Some(diag) = evaluate_dep_socket_score(
            &dep,
            &artifact,
            &pkg_json_path,
            min_score,
            effective_sev,
        ) {
            out.push(diag);
        }
    }
}

fn evaluate_dep_socket_score(
    dep: &DependencyToScore,
    artifact: &SocketArtifact,
    pkg_json_path: &Path,
    min_score: u32,
    effective_sev: RuleSeverity,
) -> Option<Diagnostic> {
    let (failing_axis_key, failing_axis_label, failing_meaning, failing_remediation, raw_val) =
        select_failing_axis(dep.section, &artifact.score);
    let failing_score = to_hundred(raw_val);
    if failing_score >= min_score {
        return None;
    }

    let top_alerts = select_top_alerts(&artifact.alerts);
    let reason = if top_alerts.is_empty() {
        format!("This points to {failing_meaning}.")
    } else {
        format_alert_reason(&top_alerts, artifact.alerts.len())
    };
    let identity = format_dependency_identity(dep);
    let other_axes = format_other_axis_scores(&artifact.score, failing_axis_key);
    let package_page_url = format!(
        "{SOCKET_PACKAGE_PAGE_BASE}/{}/overview/{}",
        dep.name, dep.version
    );
    let help = build_supply_chain_help(
        dep,
        failing_remediation,
        &top_alerts,
        &package_page_url,
        min_score,
    );
    Some(
        make_diag_for_subject(
            RuleId::LowSupplyChainScore,
            pkg_json_path.to_path_buf(),
            None,
            "lowSupplyChainScore",
            dep.name.clone(),
            format!(
                "`{identity}` scored {failing_score}/100 on Socket's {failing_axis_label} axis (minimum {min_score}). {reason} Other axes — {other_axes}. {help}"
            ),
            dep.loc,
            dep.span,
        )
        .with_severity(effective_sev),
    )
}

fn select_failing_axis(
    section: DepSection,
    score: &SocketScore,
) -> (&'static str, &'static str, &'static str, &'static str, f64) {
    if section == DepSection::Dependencies && score.vulnerability < score.supply_chain {
        (
            "vulnerability",
            "vulnerability",
            "known security vulnerabilities (CVEs) affecting this version",
            "Upgrade to a version with no known advisories (run `npm audit` to find one), or replace it",
            score.vulnerability,
        )
    } else {
        (
            "supplyChain",
            "supply chain",
            "risky install-time behavior — install scripts, obfuscated or native code, network/filesystem/shell access, or typosquatting",
            "Confirm this is the package you meant to install, and prefer a more established, audited alternative",
            score.supply_chain,
        )
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
    let block_slice = pkg_raw.get(block_start..).unwrap_or_default();
    let end_rel = find_matching_close_brace(block_slice);
    let section_body = block_slice.get(..end_rel).unwrap_or_default();
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
        reason = "Clamped to 0.0..=100.0 before converting to u32 (#50)"
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
    if trimmed.starts_with('^') {
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
