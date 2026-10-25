//! Bundle-size rule family detectors (`no-barrel-import`, `no-full-lodash-import`,
//! `no-moment`, `prefer-dynamic-import`, `no-dynamic-import-path`,
//! `no-undeferred-third-party`, `use-lazy-motion`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; bundle-size rule detectors match only relevant AST node kinds"
)]

mod barrel_imports;

use std::path::Path;

use oxc_ast::{
    AstKind,
    ast::{
        CallExpression, Expression, ImportDeclaration, ImportDeclarationSpecifier,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName, TemplateLiteral,
        VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic};

pub(crate) use self::barrel_imports::evaluate_barrel_imports;
use crate::{
    ir::{
        ByteSpan, JsxElementIr,
        types::{ModuleIr, SemanticRuleSite, loc_from_line_starts},
    },
    matchers::unparenthesized,
    rules::{AutofixPatch, RuleId},
};

const HEAVY_LIBRARIES: &[&str] = &[
    "@monaco-editor/react", "monaco-editor", "recharts", "@react-pdf/renderer", "react-quill",
    "@codemirror/view", "@codemirror/state", "chart.js", "react-chartjs-2", "@toast-ui/editor",
    "draft-js", "mermaid",
];

const NODE_TOOLING_MODULES: &[&str] = &[
    "assert", "async_hooks", "buffer", "child_process", "cluster", "crypto", "dgram", "dns",
    "events", "express", "fs", "fs-extra", "fs/promises", "gulp", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks",
    "process", "querystring", "readline", "repl", "stream", "stream/promises", "tls", "tty",
    "url", "util", "v8", "vm", "worker_threads", "zlib",
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

    if source_spec == "lodash"
        && !outside_browser
        && !is_import_absent_from_client_bundle(imp, semantic, jsx_elements, false)
    {
        let autofix = build_lodash_subpath_autofix(imp, semantic.source_text(), span);
        push_bundle_site(
            out,
            RuleId::NoFullLodashImport,
            "noFullLodashImport",
            "lodash",
            "Importing all of lodash ships the whole library to your users & slows page load. Import from 'lodash/functionName' instead.".to_string(),
            loc,
            span,
            autofix,
        );
    }

    if source_spec == "moment" && has_non_type_import_specifier_or_bare(imp) {
        push_bundle_site(
            out,
            RuleId::NoMoment,
            "noMoment",
            "moment",
            "moment.js ships 300 kb+ to your users & slows page load. Use \"date-fns\" or \"dayjs\" instead.".to_string(),
            loc,
            span,
            None,
        );
    }

    if HEAVY_LIBRARIES.contains(&source_spec)
        && has_non_type_import_specifier_or_bare(imp)
        && (imp.specifiers.as_ref().is_none_or(|s| s.is_empty())
            || !is_import_absent_from_client_bundle(imp, semantic, jsx_elements, true))
    {
        push_bundle_site(
            out,
            RuleId::PreferDynamicImport,
            "preferDynamicImport",
            source_spec,
            format!(
                "\"{source_spec}\" ships extra code to your users up front & slows page load. Load it on demand with React.lazy() or next/dynamic."
            ),
            loc,
            span,
            None,
        );
    }

    if (source_spec == "framer-motion" || source_spec == "motion/react")
        && imp.specifiers.as_ref().is_some_and(|specs| {
            specs.iter().any(|spec| {
                matches!(
                    spec,
                    ImportDeclarationSpecifier::ImportSpecifier(s)
                        if !s.import_kind.is_type() && s.imported.name() == "motion"
                )
            })
        })
    {
        push_bundle_site(
            out,
            RuleId::UseLazyMotion,
            "useLazyMotion",
            "motion",
            "Importing \"motion\" ships about 30 kb of extra code and slows page load. Use \"m\" with LazyMotion instead.".to_string(),
            loc,
            span,
            None,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a module-level bundle-size SemanticRuleSite directly (#50)"
)]
fn push_bundle_site(
    out: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: crate::ir::SourceLoc,
    span: ByteSpan,
    autofix: Option<AutofixPatch>,
) {
    out.push(SemanticRuleSite {
        rule,
        subject_name: None,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix,
    });
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
    specs.iter().all(|spec| {
        !is_specifier_used_in_client_bundle(spec, semantic, jsx_elements, count_reexports_as_client)
    })
}

fn is_specifier_used_in_client_bundle(
    spec: &ImportDeclarationSpecifier<'_>,
    semantic: &Semantic<'_>,
    jsx_elements: &[JsxElementIr],
    count_reexports_as_client: bool,
) -> bool {
    let (local_name, sym_id) = match spec {
        ImportDeclarationSpecifier::ImportSpecifier(s) if s.import_kind.is_type() => return false,
        ImportDeclarationSpecifier::ImportSpecifier(s) => {
            (s.local.name.as_str(), s.local.symbol_id.get())
        }
        ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
            (s.local.name.as_str(), s.local.symbol_id.get())
        }
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
            (s.local.name.as_str(), s.local.symbol_id.get())
        }
    };
    if jsx_elements
        .iter()
        .any(|el| el.root_identifier == local_name)
    {
        return true;
    }
    let Some(sym) = sym_id else {
        return false;
    };
    semantic
        .scoping()
        .get_resolved_references(sym)
        .any(|reference| {
            is_reference_in_client_bundle(semantic, reference, count_reexports_as_client)
        })
}

fn is_reference_in_client_bundle(
    semantic: &Semantic<'_>,
    reference: &oxc_semantic::Reference,
    count_reexports_as_client: bool,
) -> bool {
    if !reference.is_value() {
        return false;
    }
    let ref_node_id = reference.node_id();
    if is_inside_typescript_type(semantic, ref_node_id)
        || is_inside_nextjs_server_data_function(semantic, ref_node_id)
    {
        return false;
    }
    if matches!(
        semantic.nodes().parent_kind(ref_node_id),
        AstKind::ExportSpecifier(_)
    ) {
        return count_reexports_as_client;
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
    if [
        "gulpfile.",
        "webpack.config.",
        "vite.config.",
        "rollup.config.",
        "next.config.",
    ]
    .iter()
    .any(|p| file_name.starts_with(p))
    {
        return true;
    }
    if module
        .imports
        .iter()
        .any(|imp| !imp.is_type_only && is_node_or_cli_specifier(&imp.source))
        || module
            .require_sources
            .iter()
            .any(|req| is_node_or_cli_specifier(req))
    {
        return true;
    }
    let src = semantic.source_text();
    src.contains("process.cwd()") || src.contains("require.cache")
}

fn is_node_or_cli_specifier(spec: &str) -> bool {
    spec.starts_with("node:") || NODE_TOOLING_MODULES.contains(&spec)
}

fn unwrap_transparent_expr<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    unparenthesized(expr)
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
    check_dynamic_module_specifier_expr(
        source_expr,
        import_span,
        "import",
        "This can stay in the main bundle because the bundler cannot code-split a dynamic import path with `${dynamic_path}`. Use a plain string path instead.",
        "This can stay in the main bundle because the bundler cannot code-split a dynamic import path. Use a plain string path instead.",
        semantic,
        line_starts,
        out,
    );
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
    check_dynamic_module_specifier_expr(
        first_arg,
        call.span,
        "require",
        "This ships in the main bundle & slows page load, since the bundler can't trace a dynamic require() path. Use a plain string path instead of one with `${...}`.",
        "This ships in the main bundle & slows page load, since the bundler can't trace a dynamic require() path. Use a plain string path instead.",
        semantic,
        line_starts,
        out,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates dynamic import() or require() specifier expression with caller-specific diagnostic messages (#50)"
)]
fn check_dynamic_module_specifier_expr(
    source_expr: &Expression<'_>,
    site_span: oxc_span::Span,
    target_name: &str,
    tpl_msg: &str,
    expr_msg: &str,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let inner = unwrap_transparent_expr(source_expr);
    let msg = match inner {
        Expression::StringLiteral(_) => return,
        Expression::TemplateLiteral(tpl) => {
            if tpl.expressions.is_empty()
                || has_static_directory_prefix(tpl)
                || interpolates_only_query_string(tpl)
                || targets_package_manifest(tpl)
            {
                return;
            }
            tpl_msg
        }
        _ => {
            if is_deliberate_static_indirection(inner, semantic) {
                return;
            }
            expr_msg
        }
    };
    out.push(SemanticRuleSite {
        rule: RuleId::NoDynamicImportPath,
        subject_name: None,
        message_id: "noDynamicImportPath",
        target_name: target_name.to_string(),
        message: msg.to_string(),
        loc: loc_from_line_starts(line_starts, site_span.start),
        span: ByteSpan {
            start: site_span.start,
            end: site_span.end,
        },
        autofix: None,
    });
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
    if !matches!(&opening.name, JSXElementName::Identifier(tag_id) if tag_id.name == "script") {
        return;
    }
    if !is_undeferred_external_executable_script(&opening.attributes) {
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

fn is_undeferred_external_executable_script(attrs: &[JSXAttributeItem<'_>]) -> bool {
    let mut has_src = false;
    let mut src_literal: Option<&str> = None;
    let mut has_no_module = false;
    let mut type_literal: Option<&str> = None;
    let mut has_defer_or_async = false;

    for attr_item in attrs {
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
        return false;
    }
    if let Some(src_val) = src_literal {
        let lower = src_val.to_ascii_lowercase();
        if !(lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("//"))
        {
            return false;
        }
    }
    !type_literal.is_some_and(|t| t == "module" || !EXECUTABLE_SCRIPT_TYPES.contains(&t))
}

