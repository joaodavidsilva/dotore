//! Artifact, build pipeline, RPC/plugin, SSR/MDX, and repository secret exposure
//! security-scan rules (`artifact-secret-leak`, `artifact-env-leak`,
//! `artifact-baas-authority-surface`, `build-pipeline-secret-boundary`,
//! `local-rpc-native-bridge-risk`, `plugin-update-trust-risk`,
//! `import-metadata-execution-risk`, `mdx-ssr-execution-risk`,
//! `git-provider-url-injection-risk`, `key-lifecycle-risk`,
//! `package-metadata-secret`, `public-debug-artifact`, `repository-secret-file`,
//! `tenant-static-proxy-risk`, `url-prefilled-privileged-action`,
//! `active-static-asset`).

use crate::{
    ir::{ByteSpan, FileIr},
    matchers::offset_to_loc,
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

use super::{
    dom_and_client::{find_secret_value_in_line, find_suspicious_public_env_in_line},
    emit_line_diag, push_sec_diag,
};

pub(super) fn evaluate_remaining_security_scan_rules<F>(
    file: &FileIr,
    path_str: &str,
    line_starts: &[u32],
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let src = &file.source;

    if is_active(RuleId::ArtifactSecretLeak).is_some()
        && let Some((col, _)) = find_secret_value_in_line(src)
    {
        let loc = offset_to_loc(line_starts, u32::try_from(col).unwrap_or(0));
        push_sec_diag(
            out,
            file,
            RuleId::ArtifactSecretLeak,
            "artifactSecretLeak",
            "artifact",
            "A browser-delivered artifact contains a secret-looking credential value.",
            loc,
            ByteSpan {
                start: u32::try_from(col).unwrap_or(0),
                end: u32::try_from(col + 16).unwrap_or(0),
            },
        );
    }

    if is_active(RuleId::ArtifactEnvLeak).is_some()
        && (find_suspicious_public_env_in_line(src).is_some()
            || (src.contains("DATABASE_URL") && src.contains("AWS_SECRET_ACCESS_KEY")))
    {
        emit_line_diag(
            out,
            file,
            RuleId::ArtifactEnvLeak,
            "artifactEnvLeak",
            "env",
            "A browser artifact contains server-secret environment names or a full environment dump shape.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::ArtifactBaasAuthoritySurface).is_some()
        && (src.contains("initializeApp") || src.contains("SUPABASE_URL"))
        && (src.contains("isAdmin") || src.contains("SuperAdmin") || src.contains("ownerId"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::ArtifactBaasAuthoritySurface,
            "artifactBaasAuthoritySurface",
            "baas",
            "A browser artifact exposes Firebase/Supabase config together with sensitive collections or authorization fields.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::BuildPipelineSecretBoundary).is_some()
        && (src.contains("npm install")
            || src.contains("pnpm install")
            || src.contains("yarn install")
            || src.contains("npm ci"))
        && !src.contains("--ignore-scripts")
        && src.contains("secrets.")
    {
        emit_line_diag(
            out,
            file,
            RuleId::BuildPipelineSecretBoundary,
            "buildPipelineSecretBoundary",
            "secrets",
            "The build or install pipeline can execute package lifecycle code while CI secrets may be present.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::LocalRpcNativeBridgeRisk).is_some()
        && (src.contains("127.0.0.1") || src.contains("localhost") || src.contains("WebSocket"))
        && (src.contains("UpdateApp") || src.contains("InstallApp") || src.contains("execSync("))
    {
        emit_line_diag(
            out,
            file,
            RuleId::LocalRpcNativeBridgeRisk,
            "localRpcNativeBridgeRisk",
            "localhost",
            "Code appears to bridge browser code to localhost/native capabilities with weak origin or update/install checks.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PluginUpdateTrustRisk).is_some()
        && ((src.contains("curl ") && (src.contains("| sh") || src.contains("| bash")))
            || (src.contains("updateUrl") && src.contains(".exe")))
        && !src.contains("sha256")
        && !src.contains("checksum")
    {
        emit_line_diag(
            out,
            file,
            RuleId::PluginUpdateTrustRisk,
            "pluginUpdateTrustRisk",
            "updater",
            "Code appears to download, install, update, or execute plugin/updater content across a trust boundary.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::ImportMetadataExecutionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("eval(")
                || line.contains("new Function(")
                || line.contains("execSync("))
                && [
                    "exif", "metadata", "manifest", "preset", "plugin", "archive",
                ]
                .iter()
                .any(|w| line.contains(w))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ImportMetadataExecutionRisk,
                    "importMetadataExecutionRisk",
                    "metadata",
                    "Imported metadata, uploads, or plugin manifests appear to reach code execution.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::MdxSsrExecutionRisk).is_some()
        && (src.contains("compileMDX") || src.contains("MDXRemote") || src.contains("evaluateMdx"))
        && (src.contains("rehypeRaw")
            || src.contains("allowDangerousHtml")
            || src.contains("untrusted")
            || src.contains("userContent")
            || src.contains("req."))
    {
        emit_line_diag(
            out,
            file,
            RuleId::MdxSsrExecutionRisk,
            "mdxSsrExecutionRisk",
            "MDX",
            "MDX/markdown rendering code may evaluate user or repository content during SSR or static generation.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::GitProviderUrlInjectionRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("api.github.com")
                || line.contains("github.com")
                || line.contains("gitlab.com"))
                && line.contains("${")
                && (line.contains("req.") || line.contains("params.") || line.contains("query."))
                && !line.contains("encodeURIComponent(")
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::GitProviderUrlInjectionRisk,
                    "gitProviderUrlInjectionRisk",
                    "github.com",
                    "GitHub/GitLab/Bitbucket URL construction interpolates path components that may be attacker-controlled.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::KeyLifecycleRisk).is_some()
        && (src.contains("-----BEGIN RSA PRIVATE KEY-----")
            || src.contains("-----BEGIN PRIVATE KEY-----")
            || src.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::KeyLifecycleRisk,
            "keyLifecycleRisk",
            "PRIVATE KEY",
            "Private or long-lived release key material appears in the repository.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PackageMetadataSecret).is_some()
        && path_str.ends_with("package.json")
        && (find_secret_value_in_line(src).is_some()
            || find_suspicious_public_env_in_line(src).is_some())
    {
        emit_line_diag(
            out,
            file,
            RuleId::PackageMetadataSecret,
            "packageMetadataSecret",
            "package.json",
            "Package metadata contains secret-like values or public env secret names.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::PublicDebugArtifact).is_some()
        && path_str.contains("public/")
        && (path_str.ends_with(".log")
            || path_str.ends_with(".sql")
            || path_str.ends_with(".env")
            || path_str.contains("debug"))
    {
        emit_line_diag(
            out,
            file,
            RuleId::PublicDebugArtifact,
            "publicDebugArtifact",
            path_str,
            "A browser-reachable debug, log, dump, report, or env artifact is present.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::RepositorySecretFile).is_some()
        && (path_str.contains(".env") || path_str.ends_with(".pem"))
        && !path_str.contains("example")
        && !path_str.contains("sample")
        && (find_secret_value_in_line(src).is_some()
            || find_suspicious_public_env_in_line(src).is_some())
    {
        emit_line_diag(
            out,
            file,
            RuleId::RepositorySecretFile,
            "repositorySecretFile",
            path_str,
            "A repository credential/config file contains secret-looking values.",
            0,
            src.lines().next().unwrap_or(""),
            line_starts,
        );
    }

    if is_active(RuleId::TenantStaticProxyRisk).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if (line.contains("fetch(")
                || line.contains("getObject(")
                || line.contains("GetObjectCommand("))
                && (line.contains("${tenant")
                    || line.contains("${subdomain")
                    || line.contains("${workspace"))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::TenantStaticProxyRisk,
                    "tenantStaticProxyRisk",
                    "tenant",
                    "Route code appears to compose tenant or subdomain input into a static/CDN/object-store fetch path.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::UrlPrefilledPrivilegedAction).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("searchParams.get(")
                && [
                    "\"role\"",
                    "'role'",
                    "\"admin\"",
                    "'admin'",
                    "\"invite\"",
                    "'invite'",
                    "\"redirect_uri\"",
                    "\"callbackUrl\"",
                ]
                .iter()
                .any(|p| line.contains(p))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::UrlPrefilledPrivilegedAction,
                    "urlPrefilledPrivilegedAction",
                    "searchParams",
                    "Client code reads sensitive action state from the URL, which can pre-fill invites, roles, redirects, or sharing flows with attacker values.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }

    if is_active(RuleId::ActiveStaticAsset).is_some() {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("dangerouslyAllowSVG: true")
                || (path_str.ends_with(".svg")
                    && (line.contains("<script") || line.contains("onload=")))
            {
                emit_line_diag(
                    out,
                    file,
                    RuleId::ActiveStaticAsset,
                    "activeStaticAsset",
                    "svg",
                    "The app enables or embeds SVG in an executable browser context.",
                    idx,
                    line,
                    line_starts,
                );
            }
        }
    }
}
