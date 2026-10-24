//! Bundle-size rule family detectors (`no-barrel-import`, `no-full-lodash-import`,
//! `no-moment`, `prefer-dynamic-import`, `no-dynamic-import-path`,
//! `no-undeferred-third-party`, `use-lazy-motion`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; bundle-size rule detectors match only relevant AST node kinds"
)]

use std::{
    collections::{BTreeSet, HashSet},
    path::{Component, Path, PathBuf},
};

use oxc_ast::{
    AstKind,
    ast::{
        CallExpression, Expression, ImportDeclaration, ImportDeclarationSpecifier,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName, TemplateLiteral,
        VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic};

use crate::{
    config::{Capability, CapabilityGate},
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr,
        types::{ImportBindingIr, ModuleIr, SemanticRuleSite, loc_from_line_starts},
    },
    matchers::make_diag_for_subject,
    rules::{AutofixPatch, Diagnostic, RuleId, RuleSeverity},
};

const HEAVY_LIBRARIES: &[&str] = &[
    "@monaco-editor/react",
    "monaco-editor",
    "recharts",
    "@react-pdf/renderer",
    "react-quill",
    "@codemirror/view",
    "@codemirror/state",
    "chart.js",
    "react-chartjs-2",
    "@toast-ui/editor",
    "draft-js",
    "mermaid",
];

const NODE_TOOLING_MODULES: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "dns",
    "events",
    "express",
    "fs",
    "fs-extra",
    "fs/promises",
    "gulp",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "repl",
    "stream",
    "stream/promises",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
];

const NEXTJS_SERVER_DATA_EXPORTS: &[&str] =
    &["getStaticProps", "getStaticPaths", "getServerSideProps"];

const EXECUTABLE_SCRIPT_TYPES: &[&str] = &["text/javascript", "application/javascript", "module"];

/// Extracts single-file bundle-size rule sites during the single OXC semantic pass.
pub(crate) fn extract_bundle_size_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    jsx_elements: &[JsxElementIr],
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let outside_browser = is_outside_browser_bundle(path, semantic, module);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) => {
                check_import_bundle_rules(
                    imp,
                    outside_browser,
                    semantic,
                    jsx_elements,
                    line_starts,
                    out,
                );
            }
            AstKind::ImportExpression(imp_expr) => {
                if !outside_browser {
                    check_dynamic_import_expression(
                        node_id,
                        imp_expr.span,
                        &imp_expr.source,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                if !outside_browser {
                    check_dynamic_require_call(node_id, call, semantic, line_starts, out);
                }
            }
            AstKind::JSXOpeningElement(opening) => {
                check_undeferred_third_party_script(opening, line_starts, out);
            }
            _ => {}
        }
    }
}

fn check_import_bundle_rules(
    imp: &ImportDeclaration<'_>,
    outside_browser: bool,
    semantic: &Semantic<'_>,
    jsx_elements: &[JsxElementIr],
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if imp.import_kind.is_type() {
        return;
    }
    let source_spec = imp.source.value.as_str().unwrap_or_default();
    let loc = loc_from_line_starts(line_starts, imp.span.start);
    let span = ByteSpan {
        start: imp.span.start,
        end: imp.span.end,
    };

    // 1. `no-full-lodash-import`
    if source_spec == "lodash"
        && !outside_browser
        && !is_import_absent_from_client_bundle(imp, semantic, jsx_elements, false)
    {
        let autofix = build_lodash_subpath_autofix(imp, semantic.source_text(), span);
        out.push(SemanticRuleSite {
            rule: RuleId::NoFullLodashImport,
            subject_name: None,
            message_id: "noFullLodashImport",
            target_name: "lodash".to_string(),
            message: "Importing all of lodash ships the whole library to your users & slows page load. Import from 'lodash/functionName' instead.".to_string(),
            loc,
            span,
            autofix,
        });
    }

    // 2. `no-moment`
    if source_spec == "moment" && has_non_type_import_specifier_or_bare(imp) {
        out.push(SemanticRuleSite {
            rule: RuleId::NoMoment,
            subject_name: None,
            message_id: "noMoment",
            target_name: "moment".to_string(),
            message: "moment.js ships 300 kb+ to your users & slows page load. Use \"date-fns\" or \"dayjs\" instead.".to_string(),
            loc,
            span,
            autofix: None,
        });
    }

    // 3. `prefer-dynamic-import`
    if HEAVY_LIBRARIES.contains(&source_spec)
        && has_non_type_import_specifier_or_bare(imp)
        && (imp.specifiers.as_ref().is_none_or(|s| s.is_empty())
            || !is_import_absent_from_client_bundle(imp, semantic, jsx_elements, true))
    {
        out.push(SemanticRuleSite {
            rule: RuleId::PreferDynamicImport,
            subject_name: None,
            message_id: "preferDynamicImport",
            target_name: source_spec.to_string(),
            message: format!(
                "\"{source_spec}\" ships extra code to your users up front & slows page load. Load it on demand with React.lazy() or next/dynamic."
            ),
            loc,
            span,
            autofix: None,
        });
    }

    // 4. `use-lazy-motion`
    if (source_spec == "framer-motion" || source_spec == "motion/react")
        && let Some(specs) = &imp.specifiers
    {
        let imports_full_motion = specs.iter().any(|spec| {
            if let ImportDeclarationSpecifier::ImportSpecifier(s) = spec {
                !s.import_kind.is_type() && s.imported.name() == "motion"
            } else {
                false
            }
        });
        if imports_full_motion {
            out.push(SemanticRuleSite {
                rule: RuleId::UseLazyMotion,
                subject_name: None,
                message_id: "useLazyMotion",
                target_name: "motion".to_string(),
                message: "Importing \"motion\" ships about 30 kb of extra code and slows page load. Use \"m\" with LazyMotion instead.".to_string(),
                loc,
                span,
                autofix: None,
            });
        }
    }
}

fn build_lodash_subpath_autofix(
    imp: &ImportDeclaration<'_>,
    source_text: &str,
    span: ByteSpan,
) -> Option<AutofixPatch> {
    let specs = imp.specifiers.as_ref()?;
    if specs.is_empty() {
        return None;
    }
    let quote = if imp.source.span.source_text(source_text).starts_with('\'') {
        '\''
    } else {
        '"'
    };
    let mut lines = Vec::with_capacity(specs.len());
    for spec in specs {
        match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s) => {
                if s.import_kind.is_type() {
                    return None;
                }
                let imported = s.imported.name().as_str();
                let local = s.local.name.as_str();
                if imported.is_empty() || local.is_empty() || imported == "default" {
                    return None;
                }
                lines.push(format!(
                    "import {local} from {quote}lodash/{imported}{quote};"
                ));
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(_)
            | ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => return None,
        }
    }
    Some(AutofixPatch::replace(
        "Rewrite full `lodash` import to per-function `lodash/<fn>` subpath imports",
        span,
        lines.join("\n"),
    ))
}

fn has_non_type_import_specifier_or_bare(imp: &ImportDeclaration<'_>) -> bool {
    let Some(specs) = &imp.specifiers else {
        return true;
    };
    if specs.is_empty() {
        return true;
    }
    specs.iter().any(|spec| match spec {
        ImportDeclarationSpecifier::ImportSpecifier(s) => !s.import_kind.is_type(),
        ImportDeclarationSpecifier::ImportDefaultSpecifier(_)
        | ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => true,
    })
}

fn is_import_absent_from_client_bundle(
    imp: &ImportDeclaration<'_>,
    semantic: &Semantic<'_>,
    jsx_elements: &[JsxElementIr],
    count_reexports_as_client: bool,
) -> bool {
    let Some(specs) = &imp.specifiers else {
        return false;
    };
    if specs.is_empty() {
        return false;
    }

    for spec in specs {
        let (local_name, sym_id, is_type) = match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s) => (
                s.local.name.as_str(),
                s.local.symbol_id.get(),
                s.import_kind.is_type(),
            ),
            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                (s.local.name.as_str(), s.local.symbol_id.get(), false)
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                (s.local.name.as_str(), s.local.symbol_id.get(), false)
            }
        };
        if is_type {
            continue;
        }
        if jsx_elements
            .iter()
            .any(|el| el.root_identifier == local_name)
        {
            return false;
        }
        let Some(sym) = sym_id else {
            continue;
        };
        for reference in semantic.scoping().get_resolved_references(sym) {
            if !reference.is_value() {
                continue;
            }
            let ref_node_id = reference.node_id();
            if is_inside_typescript_type(semantic, ref_node_id) {
                continue;
            }
            if matches!(
                semantic.nodes().parent_kind(ref_node_id),
                AstKind::ExportSpecifier(_)
            ) {
                if count_reexports_as_client {
                    return false;
                }
                continue;
            }
            if is_inside_nextjs_server_data_function(semantic, ref_node_id) {
                continue;
            }
            return false;
        }
    }

    true
}

fn is_inside_typescript_type(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::TSTypeAnnotation(_)
                | AstKind::TSTypeReference(_)
                | AstKind::TSTypeQuery(_)
                | AstKind::TSInterfaceDeclaration(_)
                | AstKind::TSTypeAliasDeclaration(_)
                | AstKind::TSTypeParameterInstantiation(_)
                | AstKind::TSAsExpression(_)
                | AstKind::TSSatisfiesExpression(_)
        )
    })
}

fn is_inside_nextjs_server_data_function(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && NEXTJS_SERVER_DATA_EXPORTS.contains(&id.name.as_str())
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && NEXTJS_SERVER_DATA_EXPORTS.contains(&id.name.as_str())
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_outside_browser_bundle(path: &Path, semantic: &Semantic<'_>, module: &ModuleIr) -> bool {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if file_name.starts_with("gulpfile.")
        || file_name.starts_with("webpack.config.")
        || file_name.starts_with("vite.config.")
        || file_name.starts_with("rollup.config.")
        || file_name.starts_with("next.config.")
    {
        return true;
    }

    for imp in &module.imports {
        if !imp.is_type_only && is_node_or_cli_specifier(&imp.source) {
            return true;
        }
    }
    for req in &module.require_sources {
        if is_node_or_cli_specifier(req) {
            return true;
        }
    }

    let src = semantic.source_text();
    src.contains("process.cwd()") || src.contains("require.cache")
}

fn is_node_or_cli_specifier(spec: &str) -> bool {
    if spec.starts_with("node:") {
        return true;
    }
    NODE_TOOLING_MODULES.contains(&spec)
}

fn unwrap_transparent_expr<'a>(mut expr: &'a Expression<'a>) -> &'a Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(ts) => expr = &ts.expression,
            Expression::TSSatisfiesExpression(ts) => expr = &ts.expression,
            Expression::TSNonNullExpression(ts) => expr = &ts.expression,
            Expression::TSTypeAssertion(ts) => expr = &ts.expression,
            _ => return expr,
        }
    }
}

fn check_dynamic_import_expression(
    _node_id: NodeId,
    import_span: oxc_span::Span,
    source_expr: &Expression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let raw_node_text = import_span.source_text(semantic.source_text());
    if has_bundler_ignore_comment(raw_node_text) {
        return;
    }

    let inner = unwrap_transparent_expr(source_expr);
    let loc = loc_from_line_starts(line_starts, import_span.start);
    let span = ByteSpan {
        start: import_span.start,
        end: import_span.end,
    };

    match inner {
        Expression::StringLiteral(_) => {}
        Expression::TemplateLiteral(tpl) => {
            if !tpl.expressions.is_empty()
                && !has_static_directory_prefix(tpl)
                && !interpolates_only_query_string(tpl)
                && !targets_package_manifest(tpl)
            {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoDynamicImportPath,
                    subject_name: None,
                    message_id: "noDynamicImportPath",
                    target_name: "import".to_string(),
                    message: "This can stay in the main bundle because the bundler cannot code-split a dynamic import path with `${dynamic_path}`. Use a plain string path instead.".to_string(),
                    loc,
                    span,
                    autofix: None,
                });
            }
        }
        _ => {
            if is_deliberate_static_indirection(inner, semantic) {
                return;
            }
            out.push(SemanticRuleSite {
                rule: RuleId::NoDynamicImportPath,
                subject_name: None,
                message_id: "noDynamicImportPath",
                target_name: "import".to_string(),
                message: "This can stay in the main bundle because the bundler cannot code-split a dynamic import path. Use a plain string path instead.".to_string(),
                loc,
                span,
                autofix: None,
            });
        }
    }
}

fn check_dynamic_require_call(
    _node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_transparent_expr(&call.callee) else {
        return;
    };
    if callee_id.name != "require" {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let inner = unwrap_transparent_expr(first_arg);
    let loc = loc_from_line_starts(line_starts, call.span.start);
    let span = ByteSpan {
        start: call.span.start,
        end: call.span.end,
    };

    match inner {
        Expression::StringLiteral(_) => {}
        Expression::TemplateLiteral(tpl) => {
            if !tpl.expressions.is_empty()
                && !has_static_directory_prefix(tpl)
                && !interpolates_only_query_string(tpl)
                && !targets_package_manifest(tpl)
            {
                out.push(SemanticRuleSite {
                    rule: RuleId::NoDynamicImportPath,
                    subject_name: None,
                    message_id: "noDynamicImportPath",
                    target_name: "require".to_string(),
                    message: "This ships in the main bundle & slows page load, since the bundler can't trace a dynamic require() path. Use a plain string path instead of one with `${...}`.".to_string(),
                    loc,
                    span,
                    autofix: None,
                });
            }
        }
        _ => {
            if is_deliberate_static_indirection(inner, semantic) {
                return;
            }
            out.push(SemanticRuleSite {
                rule: RuleId::NoDynamicImportPath,
                subject_name: None,
                message_id: "noDynamicImportPath",
                target_name: "require".to_string(),
                message: "This ships in the main bundle & slows page load, since the bundler can't trace a dynamic require() path. Use a plain string path instead.".to_string(),
                loc,
                span,
                autofix: None,
            });
        }
    }
}

fn has_bundler_ignore_comment(raw: &str) -> bool {
    raw.contains("webpackIgnore") || raw.contains("vite-ignore") || raw.contains("turbopackIgnore")
}

fn first_quasi_text<'a>(tpl: &'a TemplateLiteral<'a>) -> Option<&'a str> {
    let first = tpl.quasis.first()?;
    first
        .value
        .cooked
        .as_ref()
        .and_then(|c| c.as_str())
        .or_else(|| Some(first.value.raw.as_str()))
}

fn has_static_directory_prefix(tpl: &TemplateLiteral<'_>) -> bool {
    let Some(first) = first_quasi_text(tpl) else {
        return false;
    };
    if first.contains("://") || first.starts_with('/') {
        return false;
    }
    let after_prefix = if let Some(rest) = strip_relative_or_alias_prefix(first) {
        rest
    } else if let Some(rest) = strip_package_specifier_prefix(first) {
        rest
    } else {
        return false;
    };
    after_prefix.contains('/')
}

fn strip_relative_or_alias_prefix(mut s: &str) -> Option<&str> {
    if let Some(rest) = s.strip_prefix("@/").or_else(|| s.strip_prefix("~/")) {
        return Some(rest);
    }
    let mut matched = false;
    loop {
        if let Some(rest) = s.strip_prefix("../") {
            s = rest;
            matched = true;
        } else if let Some(rest) = s.strip_prefix("./") {
            s = rest;
            matched = true;
        } else {
            break;
        }
    }
    matched.then_some(s)
}

fn strip_package_specifier_prefix(s: &str) -> Option<&str> {
    if let Some(after_at) = s.strip_prefix('@') {
        let (scope, rest1) = after_at.split_once('/')?;
        if scope.is_empty() {
            return None;
        }
        let (pkg, rest2) = rest1.split_once('/')?;
        if pkg.is_empty() {
            return None;
        }
        return Some(rest2);
    }
    let first_byte = *s.as_bytes().first()?;
    if !first_byte.is_ascii_alphabetic() {
        return None;
    }
    let (pkg, rest) = s.split_once('/')?;
    if pkg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        Some(rest)
    } else {
        None
    }
}

fn interpolates_only_query_string(tpl: &TemplateLiteral<'_>) -> bool {
    first_quasi_text(tpl).is_some_and(|t| t.contains('?'))
}

fn targets_package_manifest(tpl: &TemplateLiteral<'_>) -> bool {
    tpl.quasis
        .last()
        .and_then(|q| {
            q.value
                .cooked
                .as_ref()
                .and_then(|c| c.as_str())
                .or_else(|| Some(q.value.raw.as_str()))
        })
        .is_some_and(|t| t.ends_with("package.json"))
}

fn is_deliberate_static_indirection(expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::Identifier(ident) = expr else {
        return false;
    };
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let AstKind::VariableDeclaration(var_decl) = semantic.nodes().parent_kind(decl_id) else {
        return false;
    };
    if var_decl.kind != VariableDeclarationKind::Const {
        return false;
    }
    let Some(init) = &decl.init else {
        return false;
    };
    match unwrap_transparent_expr(init) {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = unwrap_transparent_expr(&call.callee)
                && mem.property.name == "createObjectURL"
                && matches!(
                    unwrap_transparent_expr(&mem.object),
                    Expression::Identifier(id) if id.name == "URL"
                )
            {
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn check_undeferred_third_party_script(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let JSXElementName::Identifier(tag_id) = &opening.name else {
        return;
    };
    if tag_id.name != "script" {
        return;
    }

    let mut has_src = false;
    let mut src_literal: Option<&str> = None;
    let mut has_no_module = false;
    let mut type_literal: Option<&str> = None;
    let mut has_defer_or_async = false;

    for attr_item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = attr_item else {
            continue;
        };
        let JSXAttributeName::Identifier(name_id) = &attr.name else {
            continue;
        };
        match name_id.name.as_str() {
            "src" => {
                has_src = true;
                if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value {
                    src_literal = s.value.as_str();
                }
            }
            "noModule" => has_no_module = true,
            "type" => {
                if let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value {
                    type_literal = s.value.as_str();
                }
            }
            "defer" | "async" => has_defer_or_async = true,
            _ => {}
        }
    }

    if !has_src || has_no_module || has_defer_or_async {
        return;
    }
    if let Some(src_val) = src_literal {
        let lower = src_val.to_ascii_lowercase();
        let is_external = lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("//");
        if !is_external {
            return;
        }
    }
    if let Some(t) = type_literal
        && (t == "module" || !EXECUTABLE_SCRIPT_TYPES.contains(&t))
    {
        return;
    }

    out.push(SemanticRuleSite {
        rule: RuleId::NoUndeferredThirdParty,
        subject_name: None,
        message_id: "noUndeferredThirdParty",
        target_name: "script".to_string(),
        message: "This <script> blocks the page from showing to your users until it loads. Add defer or async so it loads in the background.".to_string(),
        loc: loc_from_line_starts(line_starts, opening.span.start),
        span: ByteSpan {
            start: opening.span.start,
            end: opening.span.end,
        },
        autofix: None,
    });
}

/// Evaluates `no-barrel-import` across the [`ProjectGraph`] module graph.
pub(crate) fn evaluate_barrel_imports<F>(
    graph: &ProjectGraph,
    file: &FileIr,
    gate: &CapabilityGate,
    is_active: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    if is_active(RuleId::NoBarrelImport).is_none() {
        return;
    }
    if file.module.is_aggregation_barrel {
        return;
    }
    let path_str = file.path.to_string_lossy().replace('\\', "/");
    if path_str.ends_with(".d.ts")
        || path_str.ends_with(".d.mts")
        || path_str.ends_with(".d.cts")
        || path_str.contains(".server.")
    {
        return;
    }

    let is_rn_target = (gate.has(Capability::ReactNative) || gate.has(Capability::Expo))
        && !path_str.contains(".web.");

    for imp in &file.module.imports {
        if imp.is_type_only || !imp.source.starts_with('.') {
            continue;
        }
        let runtime_bindings: Vec<_> = imp
            .bindings
            .iter()
            .filter(|b| !b.is_type_only && !b.is_namespace)
            .collect();
        if runtime_bindings.is_empty() {
            continue;
        }
        if !runtime_bindings
            .iter()
            .any(|b| b.has_runtime_value_reference)
        {
            continue;
        }

        let Some(barrel_idx) = graph.resolve_relative_import(&file.path, &imp.source) else {
            continue;
        };
        let Some(barrel_file) = graph.files.get(barrel_idx) else {
            continue;
        };
        if !is_barrel_index_file(barrel_file) {
            continue;
        }
        if distinct_barrel_sources(barrel_file) <= 1 {
            continue;
        }
        if consumes_every_runtime_export(barrel_file, &runtime_bindings) {
            continue;
        }

        let mut direct_sources = BTreeSet::new();
        for b in &runtime_bindings {
            if let Some(target_path) = resolve_barrel_export_file_path(
                graph,
                barrel_idx,
                &b.imported_name,
                &mut HashSet::new(),
            ) {
                direct_sources.insert(create_relative_import_source(&file.path, &target_path));
            }
        }

        let cost_sentence = if is_rn_target {
            "This ships extra code in your app bundle & slows startup."
        } else {
            "This ships extra code to your users & slows page load."
        };

        let message = if direct_sources.len() == 1 {
            let only = direct_sources.iter().next().map_or("", String::as_str);
            format!("{cost_sentence} Import directly from \"{only}\".")
        } else if direct_sources.len() > 1 {
            let joined = direct_sources
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{cost_sentence} Import directly from: {joined}.")
        } else {
            "Importing from an index file pulls in extra code. Import directly from the source file instead.".to_string()
        };

        out.push(make_diag_for_subject(
            RuleId::NoBarrelImport,
            file.path.clone(),
            None,
            "noBarrelImport",
            imp.source.clone(),
            message,
            imp.loc,
            imp.span,
        ));
        return;
    }
}

fn is_barrel_index_file(file: &FileIr) -> bool {
    let Some(file_name) = file.path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let is_index_name = matches!(
        file_name,
        "index.ts"
            | "index.tsx"
            | "index.js"
            | "index.jsx"
            | "index.mts"
            | "index.mjs"
            | "index.cts"
            | "index.cjs"
    );
    is_index_name && file.module.is_aggregation_barrel && !file.module.exports.is_empty()
}

fn distinct_barrel_sources(barrel_file: &FileIr) -> usize {
    let mut sources = HashSet::new();
    for exp in &barrel_file.module.exports {
        if let Some(src) = &exp.from_source {
            sources.insert(src.as_str());
        } else {
            let local = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
            for imp in &barrel_file.module.imports {
                if imp.bindings.iter().any(|b| b.local_name == local) {
                    sources.insert(imp.source.as_str());
                }
            }
        }
    }
    sources.len()
}

fn consumes_every_runtime_export(
    barrel_file: &FileIr,
    runtime_bindings: &[&ImportBindingIr],
) -> bool {
    if barrel_file
        .module
        .exports
        .iter()
        .any(|e| e.is_namespace_re_export && e.name == "*")
    {
        return false;
    }
    let imported_names: HashSet<&str> = runtime_bindings
        .iter()
        .map(|b| b.imported_name.as_str())
        .collect();
    for exp in &barrel_file.module.exports {
        if !exp.is_type_only && !imported_names.contains(exp.name.as_str()) {
            return false;
        }
    }
    true
}

fn resolve_barrel_export_file_path(
    graph: &ProjectGraph,
    barrel_idx: usize,
    exported_name: &str,
    visited: &mut HashSet<usize>,
) -> Option<PathBuf> {
    if !visited.insert(barrel_idx) {
        return None;
    }
    let barrel_file = graph.files.get(barrel_idx)?;

    for exp in &barrel_file.module.exports {
        if exp.name != exported_name {
            continue;
        }
        let (target_spec, target_imported_name) = if let Some(src) = &exp.from_source {
            let orig = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
            (src.as_str(), orig)
        } else {
            let local = exp.local_name.as_deref().unwrap_or(exp.name.as_str());
            let mut found = None;
            for imp in &barrel_file.module.imports {
                if let Some(b) = imp.bindings.iter().find(|b| b.local_name == local) {
                    found = Some((imp.source.as_str(), b.imported_name.as_str()));
                    break;
                }
            }
            found?
        };

        let target_idx = graph.resolve_relative_import(&barrel_file.path, target_spec)?;
        let target_file = graph.files.get(target_idx)?;
        if is_barrel_index_file(target_file)
            && let Some(nested) =
                resolve_barrel_export_file_path(graph, target_idx, target_imported_name, visited)
        {
            return Some(nested);
        }
        return Some(target_file.path.clone());
    }

    if exported_name == "default" {
        return None;
    }

    let mut star_matches = Vec::new();
    for exp in &barrel_file.module.exports {
        if exp.is_namespace_re_export
            && exp.name == "*"
            && let Some(src) = &exp.from_source
            && let Some(target_idx) = graph.resolve_relative_import(&barrel_file.path, src)
        {
            let Some(target_file) = graph.files.get(target_idx) else {
                continue;
            };
            if is_barrel_index_file(target_file) {
                let mut sub_visited: HashSet<usize> = visited.iter().copied().collect();
                if let Some(nested) = resolve_barrel_export_file_path(
                    graph,
                    target_idx,
                    exported_name,
                    &mut sub_visited,
                ) {
                    star_matches.push(nested);
                }
            } else if target_file
                .module
                .exports
                .iter()
                .any(|e| e.name == exported_name)
            {
                star_matches.push(target_file.path.clone());
            }
        }
    }

    star_matches.dedup();
    (star_matches.len() == 1).then(|| star_matches.remove(0))
}

fn create_relative_import_source(from_file: &Path, target_file: &Path) -> String {
    let from_dir = from_file.parent().unwrap_or_else(|| Path::new(""));
    let stripped_target = strip_module_extension_and_index(target_file);
    let rel = relative_path_between_dirs(from_dir, &stripped_target);
    if rel.starts_with("../") || rel.starts_with("./") {
        rel
    } else {
        format!("./{rel}")
    }
}

fn strip_module_extension_and_index(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy().replace('\\', "/");
    let without_ext = [
        ".d.ts", ".d.mts", ".d.cts", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts",
    ]
    .iter()
    .find_map(|ext| raw.strip_suffix(ext))
    .unwrap_or(&raw);
    let without_index = without_ext.strip_suffix("/index").unwrap_or(without_ext);
    PathBuf::from(without_index)
}

fn relative_path_between_dirs(from_dir: &Path, to_path: &Path) -> String {
    let from_comps: Vec<_> = from_dir
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    let to_comps: Vec<_> = to_path
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();

    let common = from_comps
        .iter()
        .zip(to_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut parts = Vec::with_capacity((from_comps.len() - common) + (to_comps.len() - common));
    for _ in common..from_comps.len() {
        parts.push("..".to_string());
    }
    for comp in to_comps.get(common..).unwrap_or_default() {
        parts.push(comp.as_os_str().to_string_lossy().to_string());
    }
    parts.join("/")
}
