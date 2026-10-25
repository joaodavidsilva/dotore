//! Helper function body fingerprinting (`arch-no-duplicated-helper-logic`) and reuse facet orchestration.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; helper fingerprinting matches only relevant node kinds (#50)"
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use dotore_core::ir::{FNV1A_64_OFFSET_BASIS, fnv1a_64_step};
use oxc_ast::{
    AstKind,
    ast::{BindingPattern, Expression},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::{ProjectGraph, ResolvedCallerSite},
    ir::{
        ArchitectureFileFacets, ByteSpan, FileContext, FileIr, HelperFingerprintIr, SubjectIr,
        loc_from_line_starts, types::ModuleIr,
    },
    matchers::{make_diag_for_subject, resolve_ident_symbol},
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

use super::builder_and_terminal_ui::{
    evaluate_inline_terminal_ui_for_package, evaluate_prefer_fluent_builder_for_package,
    extract_builder_facets_in_file, extract_inline_terminal_ui_sites_in_file,
};

/// Extracts single-pass structural facets for helper duplication (`HelperFingerprintIr`),
/// builder candidates (`StructLiteralConstructionSiteIr`, `defined_builder_types`),
/// and inline terminal UI primitives (`InlineTerminalUiPrimitiveSiteIr`, `is_ui_kit_module`).
pub(crate) fn extract_reuse_architecture_facets(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    extract_helper_fingerprints_in_file(semantic, subjects, module, line_starts, facets);
    extract_builder_facets_in_file(semantic, line_starts, facets);
    extract_inline_terminal_ui_sites_in_file(path, source, semantic, line_starts, facets);
}

fn extract_helper_fingerprints_in_file(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    module: &ModuleIr,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let exported_names: HashSet<&str> = module
        .exports
        .iter()
        .flat_map(|e| std::iter::once(e.name.as_str()).chain(e.local_name.as_deref()))
        .collect();
    let subject_names: HashSet<&str> = subjects.iter().filter_map(|s| s.name.as_deref()).collect();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let Some((fn_name, fn_span, body_span, full_span, param_count, has_rest)) =
            extract_private_helper_candidate(
                semantic,
                node_id,
                node.kind(),
                &exported_names,
                &subject_names,
            )
        else {
            continue;
        };
        let (normalized_hash, statement_count) = compute_helper_body_fingerprint(
            semantic,
            node_id,
            fn_span,
            body_span,
            param_count,
            has_rest,
        );
        if statement_count >= 2 {
            facets.helper_fingerprints.push(HelperFingerprintIr {
                name: fn_name,
                normalized_hash,
                statement_count,
                param_count,
                is_private: true,
                loc: loc_from_line_starts(line_starts, full_span.start),
                span: ByteSpan {
                    start: full_span.start,
                    end: full_span.end,
                },
            });
        }
    }
}

fn extract_private_helper_candidate(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
    exported_names: &HashSet<&str>,
    subject_names: &HashSet<&str>,
) -> Option<(String, Span, Span, Span, usize, bool)> {
    if !is_module_scope_helper_decl(semantic, node_id) || has_export_ancestor(semantic, node_id) {
        return None;
    }
    match kind {
        AstKind::Function(func) => {
            extract_private_function_candidate(semantic, func, exported_names, subject_names)
        }
        AstKind::VariableDeclarator(decl) => {
            extract_private_declarator_candidate(semantic, node_id, decl, exported_names, subject_names)
        }
        _ => None,
    }
}

fn extract_private_function_candidate(
    semantic: &Semantic<'_>,
    func: &oxc_ast::ast::Function<'_>,
    exported_names: &HashSet<&str>,
    subject_names: &HashSet<&str>,
) -> Option<(String, Span, Span, Span, usize, bool)> {
    let id = func.id.as_ref()?;
    let body = func.body.as_ref()?;
    let fn_name = id.name.as_str();
    if subject_names.contains(fn_name)
        || exported_names.contains(fn_name)
        || span_contains_jsx(semantic, body.span)
    {
        return None;
    }
    Some((
        fn_name.to_string(),
        func.span,
        body.span,
        func.span,
        func.params.items.len(),
        func.params.rest.is_some(),
    ))
}

fn extract_private_declarator_candidate(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    exported_names: &HashSet<&str>,
    subject_names: &HashSet<&str>,
) -> Option<(String, Span, Span, Span, usize, bool)> {
    let BindingPattern::BindingIdentifier(id) = &decl.id else {
        return None;
    };
    let fn_name = id.name.as_str();
    if subject_names.contains(fn_name) || exported_names.contains(fn_name) {
        return None;
    }
    let init = decl.init.as_ref()?.without_parentheses();
    let (fn_span, body_span, param_count, has_rest) = match init {
        Expression::ArrowFunctionExpression(arrow) => (
            arrow.span,
            arrow.body.span(),
            arrow.params.items.len(),
            arrow.params.rest.is_some(),
        ),
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            (
                func.span,
                body.span,
                func.params.items.len(),
                func.params.rest.is_some(),
            )
        }
        _ => return None,
    };
    if span_contains_jsx(semantic, body_span) {
        return None;
    }
    let parent_id = semantic.nodes().parent_id(node_id);
    let full_span =
        if let AstKind::VariableDeclaration(var_decl) = semantic.nodes().kind(parent_id)
            && var_decl.declarations.len() == 1
        {
            var_decl.span
        } else {
            decl.span
        };
    Some((
        fn_name.to_string(),
        fn_span,
        body_span,
        full_span,
        param_count,
        has_rest,
    ))
}

fn is_module_scope_helper_decl(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    !semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_)
                | AstKind::ArrowFunctionExpression(_)
                | AstKind::Class(_)
                | AstKind::ObjectExpression(_)
        )
    })
}

fn has_export_ancestor(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ExportNamedDeclaration(_)
                | AstKind::ExportDefaultDeclaration(_)
                | AstKind::TSExportAssignment(_)
        )
    })
}

fn span_contains_jsx(semantic: &Semantic<'_>, span: Span) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        let s = n.span();
        s.start >= span.start
            && s.end <= span.end
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn compute_helper_body_fingerprint(
    semantic: &Semantic<'_>,
    _owner_id: NodeId,
    fn_span: Span,
    body_span: Span,
    param_count: usize,
    has_rest: bool,
) -> (u64, usize) {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    hash = fnv1a_64_step(hash, b"HelperArity");
    hash = fnv1a_64_step(hash, &param_count.to_le_bytes());
    hash = fnv1a_64_step(hash, &[u8::from(has_rest)]);

    let mut statement_count = 0_usize;

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let sp = node.span();
        if sp.start < body_span.start || sp.end > body_span.end {
            continue;
        }
        if step_statement_or_pattern_fingerprint(node.kind(), &mut hash, &mut statement_count) {
            continue;
        }
        step_expression_fingerprint(semantic, node_id, node.kind(), fn_span, &mut hash);
    }

    (hash, statement_count)
}

fn step_statement_or_pattern_fingerprint(
    kind: AstKind<'_>,
    hash: &mut u64,
    statement_count: &mut usize,
) -> bool {
    match kind {
        AstKind::VariableDeclaration(decl) => {
            *statement_count += 1;
            *hash = fnv1a_64_step(*hash, b"VarDecl");
            *hash = fnv1a_64_step(*hash, decl.kind.as_str().as_bytes());
            return true;
        }
        AstKind::VariableDeclarator(_) => {
            *hash = fnv1a_64_step(*hash, b"VarDeclarator");
            return true;
        }
        AstKind::BindingIdentifier(_) => {
            *hash = fnv1a_64_step(*hash, b"BindIdent");
            return true;
        }
        AstKind::ObjectPattern(_) => {
            *hash = fnv1a_64_step(*hash, b"ObjPat");
            return true;
        }
        AstKind::ArrayPattern(_) => {
            *hash = fnv1a_64_step(*hash, b"ArrPat");
            return true;
        }
        _ => {}
    }

    let stmt_tag = classify_statement_fingerprint_tag(kind);
    if let Some(tag) = stmt_tag {
        *statement_count += 1;
        *hash = fnv1a_64_step(*hash, tag);
        return true;
    }
    false
}

fn classify_statement_fingerprint_tag(kind: AstKind<'_>) -> Option<&'static [u8]> {
    match kind {
        AstKind::ExpressionStatement(_) => Some(b"ExprStmt"),
        AstKind::ReturnStatement(_) => Some(b"Return"),
        AstKind::IfStatement(_) => Some(b"If"),
        AstKind::ForStatement(_) => Some(b"For"),
        AstKind::ForInStatement(_) => Some(b"ForIn"),
        AstKind::ForOfStatement(_) => Some(b"ForOf"),
        AstKind::WhileStatement(_) => Some(b"While"),
        AstKind::DoWhileStatement(_) => Some(b"DoWhile"),
        other => classify_branch_or_jump_fingerprint_tag(other),
    }
}

fn classify_branch_or_jump_fingerprint_tag(kind: AstKind<'_>) -> Option<&'static [u8]> {
    match kind {
        AstKind::SwitchStatement(_) => Some(b"Switch"),
        AstKind::SwitchCase(_) => Some(b"SwitchCase"),
        AstKind::TryStatement(_) => Some(b"Try"),
        AstKind::CatchClause(_) => Some(b"Catch"),
        AstKind::ThrowStatement(_) => Some(b"Throw"),
        AstKind::BreakStatement(_) => Some(b"Break"),
        AstKind::ContinueStatement(_) => Some(b"Continue"),
        AstKind::ConditionalExpression(_) => Some(b"CondExpr"),
        _ => None,
    }
}

fn step_expression_fingerprint(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
    fn_span: Span,
    hash: &mut u64,
) {
    if step_operator_or_call_fingerprint(semantic, kind, fn_span, hash) {
        return;
    }
    match kind {
        AstKind::StaticMemberExpression(mem) => {
            *hash = fnv1a_64_step(*hash, b"Member");
            *hash = fnv1a_64_step(*hash, mem.property.name.as_bytes());
        }
        AstKind::ComputedMemberExpression(_) => {
            *hash = fnv1a_64_step(*hash, b"ComputedMember");
        }
        AstKind::IdentifierReference(_) => {
            let parent_kind = semantic.nodes().kind(semantic.nodes().parent_id(node_id));
            if !matches!(
                parent_kind,
                AstKind::CallExpression(_) | AstKind::NewExpression(_)
            ) {
                *hash = fnv1a_64_step(*hash, b"IdentRef");
            }
        }
        AstKind::StringLiteral(_) => *hash = fnv1a_64_step(*hash, b"StrLit"),
        AstKind::NumericLiteral(_) => *hash = fnv1a_64_step(*hash, b"NumLit"),
        AstKind::BooleanLiteral(b) => {
            *hash = fnv1a_64_step(*hash, if b.value { b"BoolTrue" } else { b"BoolFalse" });
        }
        AstKind::NullLiteral(_) => *hash = fnv1a_64_step(*hash, b"NullLit"),
        AstKind::RegExpLiteral(r) => {
            *hash = fnv1a_64_step(*hash, b"RegexLit");
            *hash = fnv1a_64_step(*hash, r.regex.pattern.text.as_bytes());
        }
        AstKind::TemplateLiteral(t) => {
            *hash = fnv1a_64_step(*hash, b"TplLit");
            *hash = fnv1a_64_step(*hash, &t.expressions.len().to_le_bytes());
        }
        AstKind::ArrayExpression(a) => {
            *hash = fnv1a_64_step(*hash, b"ArrExpr");
            *hash = fnv1a_64_step(*hash, &a.elements.len().to_le_bytes());
        }
        AstKind::ObjectExpression(o) => {
            *hash = fnv1a_64_step(*hash, b"ObjExpr");
            *hash = fnv1a_64_step(*hash, &o.properties.len().to_le_bytes());
        }
        AstKind::AwaitExpression(_) => *hash = fnv1a_64_step(*hash, b"Await"),
        AstKind::SpreadElement(_) => *hash = fnv1a_64_step(*hash, b"Spread"),
        _ => {}
    }
}

fn step_operator_or_call_fingerprint(
    semantic: &Semantic<'_>,
    kind: AstKind<'_>,
    fn_span: Span,
    hash: &mut u64,
) -> bool {
    match kind {
        AstKind::BinaryExpression(e) => {
            *hash = fnv1a_64_step(*hash, b"BinOp");
            *hash = fnv1a_64_step(*hash, e.operator.as_str().as_bytes());
        }
        AstKind::LogicalExpression(e) => {
            *hash = fnv1a_64_step(*hash, b"LogOp");
            *hash = fnv1a_64_step(*hash, e.operator.as_str().as_bytes());
        }
        AstKind::UnaryExpression(e) => {
            *hash = fnv1a_64_step(*hash, b"UnOp");
            *hash = fnv1a_64_step(*hash, e.operator.as_str().as_bytes());
        }
        AstKind::UpdateExpression(e) => {
            *hash = fnv1a_64_step(*hash, b"UpdOp");
            *hash = fnv1a_64_step(*hash, e.operator.as_str().as_bytes());
        }
        AstKind::AssignmentExpression(e) => {
            *hash = fnv1a_64_step(*hash, b"AssignOp");
            *hash = fnv1a_64_step(*hash, e.operator.as_str().as_bytes());
        }
        AstKind::CallExpression(call) => {
            *hash = fnv1a_64_step(*hash, b"Call");
            *hash = fnv1a_64_step(*hash, &call.arguments.len().to_le_bytes());
            match call.callee.without_parentheses() {
                Expression::Identifier(ident) => {
                    let is_local = resolve_ident_symbol(semantic, ident).is_some_and(|sym_id| {
                        let decl_span = semantic
                            .nodes()
                            .get_node(semantic.scoping().symbol_declaration(sym_id))
                            .span();
                        decl_span.start >= fn_span.start && decl_span.end <= fn_span.end
                    });
                    let token = if is_local {
                        b"local_fn".as_slice()
                    } else {
                        ident.name.as_bytes()
                    };
                    *hash = fnv1a_64_step(*hash, token);
                }
                Expression::StaticMemberExpression(mem) => {
                    *hash = fnv1a_64_step(*hash, mem.property.name.as_bytes());
                }
                _ => {}
            }
        }
        AstKind::NewExpression(new_e) => {
            *hash = fnv1a_64_step(*hash, b"New");
            *hash = fnv1a_64_step(*hash, &new_e.arguments.len().to_le_bytes());
            if let Expression::Identifier(ident) = new_e.callee.without_parentheses() {
                *hash = fnv1a_64_step(*hash, ident.name.as_bytes());
            }
        }
        _ => return false,
    }
    true
}

pub(crate) fn evaluate_reuse_architecture_rules<F>(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    if packages.is_empty() {
        return;
    }
    let mut buckets: Vec<Vec<&FileIr>> = (0..packages.len()).map(|_| Vec::new()).collect();
    for f in &graph.files {
        if f.file_context != FileContext::Production {
            continue;
        }
        let Some(resolved) = resolve_package_for_file(&f.path, packages) else {
            continue;
        };
        if let Some(idx) = packages
            .iter()
            .position(|p| p.root_dir == resolved.root_dir)
            && !packages[idx]
                .config
                .is_file_ignored(&f.path, &packages[idx].root_dir)
        {
            buckets[idx].push(f);
        }
    }

    for (pkg, pkg_files) in packages.iter().zip(buckets) {
        if pkg_files.is_empty() {
            continue;
        }
        evaluate_duplicated_helpers_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_prefer_fluent_builder_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
        evaluate_inline_terminal_ui_for_package(
            &pkg_files,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
    }
}

fn evaluate_duplicated_helpers_for_package<F>(
    pkg_files: &[&FileIr],
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    let min_stmts = pkg.config.architecture.min_helper_statements;
    let min_modules = pkg.config.architecture.min_duplicated_helper_modules;

    let mut by_fingerprint: BTreeMap<(u64, usize), Vec<(&FileIr, &HelperFingerprintIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for helper in &file.architecture_facets.helper_fingerprints {
            if !helper.is_private || helper.statement_count < min_stmts {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    helper.loc.line,
                    helper.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            by_fingerprint
                .entry((helper.normalized_hash, helper.param_count))
                .or_default()
                .push((file, helper));
        }
    }

    for ((hash, param_count), occurrences) in by_fingerprint {
        let distinct_files: BTreeSet<&Path> =
            occurrences.iter().map(|(f, _)| f.path.as_path()).collect();
        if distinct_files.len() < min_modules {
            continue;
        }
        emit_duplicated_helper_group(
            hash,
            param_count,
            distinct_files.len(),
            &occurrences,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Emits diagnostics for a single duplicated helper fingerprint cluster across package modules (#50)"
)]
fn emit_duplicated_helper_group<F>(
    hash: u64,
    param_count: usize,
    distinct_file_count: usize,
    occurrences: &[(&FileIr, &HelperFingerprintIr)],
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &crate::config::CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    let Some(first_occ) = occurrences.first() else {
        return;
    };
    let first_name = &first_occ.1.name;
    let all_same_name = occurrences.iter().all(|(_, h)| &h.name == first_name);
    let shared_target_name = if all_same_name {
        first_name.clone()
    } else {
        let low32 = u32::try_from(hash & 0xffff_ffff).unwrap_or(0);
        format!("{first_name}::arity{param_count}::hash_{low32:08x}")
    };

    let cascade_steps: Vec<String> = occurrences
        .iter()
        .map(|(f, h)| {
            format!(
                "{}:{} (`{}`: {} stmts, arity {})",
                f.path.to_string_lossy().replace('\\', "/"),
                h.loc.line,
                h.name,
                h.statement_count,
                h.param_count
            )
        })
        .collect();

    for (idx, &(file, helper)) in occurrences.iter().enumerate() {
        let Some(sev) = resolve_activation(
            RuleId::ArchNoDuplicatedHelperLogic,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        let peer_caller_sites: Vec<ResolvedCallerSite> = occurrences
            .iter()
            .enumerate()
            .filter(|&(peer_idx, _)| peer_idx != idx)
            .map(|(_, &(peer_file, peer_helper))| ResolvedCallerSite {
                caller_file: peer_file.path.clone(),
                parent_subject_name: Some(peer_helper.name.clone()),
                component_name: helper.name.clone(),
                loc: peer_helper.loc,
                span: peer_helper.span,
                has_key: false,
                passed_props: Vec::new(),
            })
            .collect();

        let peer_files_summary: Vec<String> = occurrences
            .iter()
            .enumerate()
            .filter(|&(peer_idx, _)| peer_idx != idx)
            .map(|(_, &(peer_file, peer_helper))| {
                format!(
                    "`{}` in `{}:{}`",
                    peer_helper.name,
                    peer_file.path.to_string_lossy().replace('\\', "/"),
                    peer_helper.loc.line
                )
            })
            .collect();

        out.push(
            make_diag_for_subject(
                RuleId::ArchNoDuplicatedHelperLogic,
                file.path.clone(),
                Some(helper.name.clone()),
                "archNoDuplicatedHelperLogic",
                shared_target_name.clone(),
                format!(
                    "Private helper `{}` ({} statements, arity {}) duplicates normalized AST structure across {} modules ({}); extract a shared helper module.",
                    helper.name,
                    helper.statement_count,
                    helper.param_count,
                    distinct_file_count,
                    peer_files_summary.join(", ")
                ),
                helper.loc,
                helper.span,
            )
            .with_severity(sev)
            .with_caller_sites(peer_caller_sites)
            .with_cascade_steps(cascade_steps.clone()),
        );
    }
}
