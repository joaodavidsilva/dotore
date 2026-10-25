//! Fluent builder (`arch-prefer-fluent-builder`) and inline terminal UI (`arch-no-inline-terminal-ui-primitives`) extractors and evaluators.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; builder and terminal UI extractors match only relevant node kinds (#50)"
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{BindingPattern, ClassElement, Expression, ObjectPropertyKind, TSSignature, TSType, TSTypeName},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::{
    config::{DotoreConfig, WorkspacePackage},
    graph::ResolvedCallerSite,
    ir::{
        ArchitectureFileFacets, ByteSpan, FileContext, FileIr, InlineTerminalUiPrimitiveSiteIr,
        StructLiteralConstructionSiteIr, TerminalUiPrimitiveKind, classify_file_context,
        loc_from_line_starts,
    },
    matchers::make_diag_for_subject,
    rules::types::{Diagnostic, RuleId, RuleSeverity},
};

use super::classifiers::{classify_terminal_ui_literal, is_js_ui_kit_path};

pub(super) fn extract_builder_facets_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let (defined_builders, builder_body_spans, local_type_shapes) =
        collect_builder_definitions_and_type_shapes(semantic);
    facets.defined_builder_types.extend(defined_builders);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ObjectExpression(obj) = node.kind() else {
            continue;
        };
        if builder_body_spans
            .iter()
            .any(|sp| obj.span.start >= sp.start && obj.span.end <= sp.end)
        {
            continue;
        }
        if let Some(site) = build_struct_literal_site_ir(
            semantic,
            node_id,
            obj,
            &local_type_shapes,
            line_starts,
        ) {
            facets.struct_literal_sites.push(site);
        }
    }
}

type BuilderDefsAndShapes = (
    BTreeSet<String>,
    Vec<Span>,
    Vec<(String, BTreeSet<String>)>,
);

fn collect_builder_definitions_and_type_shapes(
    semantic: &Semantic<'_>,
) -> BuilderDefsAndShapes {
    let mut defined_builders: BTreeSet<String> = BTreeSet::new();
    let mut builder_body_spans: Vec<Span> = Vec::new();
    let mut local_type_shapes: Vec<(String, BTreeSet<String>)> = Vec::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Class(cls) => {
                record_class_builder_definition(cls, &mut defined_builders, &mut builder_body_spans);
            }
            AstKind::TSInterfaceDeclaration(iface) => {
                record_builder_type_name(iface.id.name.as_str(), &mut defined_builders);
                let prop_names = collect_ts_property_names(&iface.body.body);
                if prop_names.len() >= 3 {
                    local_type_shapes.push((iface.id.name.to_string(), prop_names));
                }
            }
            AstKind::TSTypeAliasDeclaration(alias) => {
                record_builder_type_name(alias.id.name.as_str(), &mut defined_builders);
                if let TSType::TSTypeLiteral(lit) = &alias.type_annotation {
                    let prop_names = collect_ts_property_names(&lit.members);
                    if prop_names.len() >= 3 {
                        local_type_shapes.push((alias.id.name.to_string(), prop_names));
                    }
                }
            }
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && let Some(target_type) = extract_factory_target_type(
                        id.name.as_str(),
                        func.return_type.as_ref().map(|r| &r.type_annotation),
                    )
                {
                    defined_builders.insert(target_type);
                    builder_body_spans.push(func.span);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                record_declarator_builder_definition(
                    decl,
                    &mut defined_builders,
                    &mut builder_body_spans,
                );
            }
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && mem.property.name == "builder"
                    && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                {
                    defined_builders.insert(obj_id.name.to_string());
                }
            }
            _ => {}
        }
    }

    (defined_builders, builder_body_spans, local_type_shapes)
}

fn record_builder_type_name(type_name: &str, defined_builders: &mut BTreeSet<String>) {
    if let Some(base) = type_name.strip_suffix("Builder")
        && !base.is_empty()
    {
        defined_builders.insert(type_name.to_string());
        defined_builders.insert(base.to_string());
    }
}

fn record_class_builder_definition(
    cls: &oxc_ast::ast::Class<'_>,
    defined_builders: &mut BTreeSet<String>,
    builder_body_spans: &mut Vec<Span>,
) {
    let Some(id) = &cls.id else {
        return;
    };
    let cls_name = id.name.as_str();
    let mut is_builder_cls = false;
    if let Some(base) = cls_name.strip_suffix("Builder")
        && !base.is_empty()
    {
        defined_builders.insert(cls_name.to_string());
        defined_builders.insert(base.to_string());
        is_builder_cls = true;
    }
    let has_fluent_methods = cls.body.body.iter().any(|el| {
        let ClassElement::MethodDefinition(m) = el else {
            return false;
        };
        let Some(m_name) = m.key.static_name().and_then(|k| k.as_str().map(str::to_string)) else {
            return false;
        };
        m_name == "builder"
            || (m_name.starts_with("with")
                && m_name.as_bytes().get(4).is_some_and(u8::is_ascii_uppercase))
    });
    if has_fluent_methods {
        defined_builders.insert(cls_name.to_string());
        is_builder_cls = true;
    }
    if is_builder_cls {
        builder_body_spans.push(cls.span);
    }
}

fn record_declarator_builder_definition(
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    defined_builders: &mut BTreeSet<String>,
    builder_body_spans: &mut Vec<Span>,
) {
    let BindingPattern::BindingIdentifier(id) = &decl.id else {
        return;
    };
    let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
        return;
    };
    let ret_type = match init {
        Expression::ArrowFunctionExpression(a) => a.return_type.as_ref().map(|r| &r.type_annotation),
        Expression::FunctionExpression(f) => f.return_type.as_ref().map(|r| &r.type_annotation),
        _ => return,
    };
    if let Some(target_type) = extract_factory_target_type(id.name.as_str(), ret_type) {
        defined_builders.insert(target_type);
        builder_body_spans.push(decl.span);
    }
}

fn build_struct_literal_site_ir(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    obj: &oxc_ast::ast::ObjectExpression<'_>,
    local_type_shapes: &[(String, BTreeSet<String>)],
    line_starts: &[u32],
) -> Option<StructLiteralConstructionSiteIr> {
    let mut field_names = Vec::new();
    let mut default_or_literal_fields = Vec::new();
    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let Some(key_s) = prop.key.static_name().and_then(|k| k.as_str().map(str::to_string)) else {
            continue;
        };
        if is_default_or_boilerplate_literal(&prop.value) {
            default_or_literal_fields.push(key_s.clone());
        }
        field_names.push(key_s);
    }

    if field_names.len() < 3 || default_or_literal_fields.is_empty() {
        return None;
    }

    let (type_name, site_span) = resolve_object_literal_type_and_span(
        semantic,
        node_id,
        obj.span,
        &field_names,
        local_type_shapes,
    );
    let resolved_type = type_name?;

    Some(StructLiteralConstructionSiteIr {
        type_name: resolved_type,
        field_names,
        default_or_literal_fields,
        loc: loc_from_line_starts(line_starts, site_span.start),
        span: ByteSpan {
            start: site_span.start,
            end: site_span.end,
        },
    })
}

fn extract_factory_target_type(fn_name: &str, return_type: Option<&TSType<'_>>) -> Option<String> {
    for prefix in ["create", "build", "make"] {
        if let Some(rest) = fn_name.strip_prefix(prefix)
            && rest.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        {
            if let Some(ret) = return_type.and_then(extract_ts_type_ref_name) {
                if ret == rest {
                    return Some(ret);
                }
            } else {
                return Some(rest.to_string());
            }
        }
    }
    if let Some(base) = fn_name.strip_suffix("Builder")
        && !base.is_empty()
    {
        let mut chars = base.chars();
        if let Some(first) = chars.next() {
            let mut pascal = first.to_ascii_uppercase().to_string();
            pascal.push_str(chars.as_str());
            return Some(pascal);
        }
    }
    None
}

fn extract_ts_type_ref_name(ts_type: &TSType<'_>) -> Option<String> {
    match ts_type {
        TSType::TSTypeReference(type_ref) => match &type_ref.type_name {
            TSTypeName::IdentifierReference(ident) => {
                if matches!(ident.name.as_str(), "Array" | "ReadonlyArray") {
                    type_ref
                        .type_arguments
                        .as_ref()
                        .and_then(|args| args.params.first())
                        .and_then(extract_ts_type_ref_name)
                } else {
                    Some(ident.name.to_string())
                }
            }
            TSTypeName::QualifiedName(q) => Some(q.right.name.to_string()),
            TSTypeName::ThisExpression(_) => None,
        },
        TSType::TSArrayType(arr) => extract_ts_type_ref_name(&arr.element_type),
        TSType::TSParenthesizedType(p) => extract_ts_type_ref_name(&p.type_annotation),
        _ => None,
    }
}

fn is_default_or_boilerplate_literal(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::UnaryExpression(u) => u.operator.as_str() == "void",
        Expression::BooleanLiteral(b) => !b.value,
        Expression::NumericLiteral(n) => n.value == 0.0,
        Expression::BigIntLiteral(b) => b.value == "0",
        Expression::StringLiteral(s) => s.value.is_empty(),
        Expression::TemplateLiteral(t) => {
            t.expressions.is_empty() && t.quasis.iter().all(|q| q.value.raw.is_empty())
        }
        Expression::ArrayExpression(arr) => arr.elements.is_empty(),
        Expression::ObjectExpression(obj) => obj.properties.is_empty(),
        _ => false,
    }
}

fn resolve_object_literal_type_and_span(
    semantic: &Semantic<'_>,
    obj_node_id: NodeId,
    obj_span: Span,
    field_names: &[String],
    local_type_shapes: &[(String, BTreeSet<String>)],
) -> (Option<String>, Span) {
    for anc_id in semantic.nodes().ancestor_ids(obj_node_id) {
        if anc_id == obj_node_id {
            continue;
        }
        match resolve_type_from_ancestor_node(semantic, anc_id, obj_span) {
            AncestorTypeResolution::Found(name, span) => return (Some(name), span),
            AncestorTypeResolution::Stop => break,
            AncestorTypeResolution::Continue => {}
        }
    }

    let field_set: BTreeSet<String> = field_names.iter().cloned().collect();
    if let Some((matched_type, _)) = local_type_shapes
        .iter()
        .find(|(_, props)| props == &field_set)
    {
        return (Some(matched_type.clone()), obj_span);
    }

    if field_names.len() >= 5 {
        let sorted: Vec<&str> = field_set.iter().map(String::as_str).collect();
        return (Some(format!("ObjectShape<{}>", sorted.join(","))), obj_span);
    }

    (None, obj_span)
}

enum AncestorTypeResolution {
    Found(String, Span),
    Stop,
    Continue,
}

fn resolve_type_from_ancestor_node(
    semantic: &Semantic<'_>,
    anc_id: NodeId,
    obj_span: Span,
) -> AncestorTypeResolution {
    match semantic.nodes().kind(anc_id) {
        AstKind::TSTypeAssertion(ta) => extract_ts_type_ref_name(&ta.type_annotation)
            .map_or(AncestorTypeResolution::Continue, |n| {
                AncestorTypeResolution::Found(n, ta.span)
            }),
        AstKind::TSAsExpression(as_e) => extract_ts_type_ref_name(&as_e.type_annotation)
            .map_or(AncestorTypeResolution::Continue, |n| {
                AncestorTypeResolution::Found(n, as_e.span)
            }),
        AstKind::TSSatisfiesExpression(sat_e) => extract_ts_type_ref_name(&sat_e.type_annotation)
            .map_or(AncestorTypeResolution::Continue, |n| {
                AncestorTypeResolution::Found(n, sat_e.span)
            }),
        AstKind::NewExpression(new_e) => match new_e.callee.without_parentheses() {
            Expression::Identifier(id) => {
                AncestorTypeResolution::Found(id.name.to_string(), new_e.span)
            }
            Expression::StaticMemberExpression(mem) => {
                AncestorTypeResolution::Found(mem.property.name.to_string(), new_e.span)
            }
            _ => AncestorTypeResolution::Stop,
        },
        AstKind::VariableDeclarator(decl) => decl
            .type_annotation
            .as_ref()
            .and_then(|ann| extract_ts_type_ref_name(&ann.type_annotation))
            .map_or(AncestorTypeResolution::Stop, |n| {
                AncestorTypeResolution::Found(n, obj_span)
            }),
        AstKind::PropertyDefinition(prop) => prop
            .type_annotation
            .as_ref()
            .and_then(|ann| extract_ts_type_ref_name(&ann.type_annotation))
            .map_or(AncestorTypeResolution::Stop, |n| {
                AncestorTypeResolution::Found(n, obj_span)
            }),
        AstKind::ReturnStatement(_) => enclosing_function_return_type_name(semantic, anc_id)
            .map_or(AncestorTypeResolution::Stop, |n| {
                AncestorTypeResolution::Found(n, obj_span)
            }),
        AstKind::ArrowFunctionExpression(arrow) => arrow
            .return_type
            .as_ref()
            .and_then(|ret| extract_ts_type_ref_name(&ret.type_annotation))
            .map_or(AncestorTypeResolution::Stop, |n| {
                AncestorTypeResolution::Found(n, obj_span)
            }),
        AstKind::ObjectExpression(_) | AstKind::CallExpression(_) | AstKind::Function(_) => {
            AncestorTypeResolution::Stop
        }
        _ => AncestorTypeResolution::Continue,
    }
}

fn collect_ts_property_names(signatures: &[TSSignature<'_>]) -> BTreeSet<String> {
    let mut prop_names = BTreeSet::new();
    for sig in signatures {
        if let TSSignature::TSPropertySignature(prop) = sig
            && let Some(key) = prop.key.static_name()
            && let Some(key_str) = key.as_str()
        {
            prop_names.insert(key_str.to_string());
        }
    }
    prop_names
}

fn enclosing_function_return_type_name(
    semantic: &Semantic<'_>,
    start_id: NodeId,
) -> Option<String> {
    for fn_anc_id in semantic.nodes().ancestor_ids(start_id) {
        match semantic.nodes().kind(fn_anc_id) {
            AstKind::Function(func) => {
                return func
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            AstKind::ArrowFunctionExpression(arrow) => {
                return arrow
                    .return_type
                    .as_ref()
                    .and_then(|r| extract_ts_type_ref_name(&r.type_annotation));
            }
            _ => {}
        }
    }
    None
}

pub(super) fn evaluate_prefer_fluent_builder_for_package<F>(
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
    let min_fields = pkg.config.architecture.min_builder_fields;
    let min_sites = pkg.config.architecture.min_builder_sites;
    let sites_by_type = collect_candidate_builder_sites_by_type(pkg_files, pkg, min_fields);

    for (type_name, sites) in sites_by_type {
        if sites.len() < min_sites {
            continue;
        }
        let Some((overlapping_defaults, qualifying_sites)) =
            filter_qualifying_builder_sites(sites, min_sites)
        else {
            continue;
        };
        emit_fluent_builder_diagnostics_for_type(
            type_name,
            &overlapping_defaults,
            &qualifying_sites,
            pkg,
            enabled_rules,
            resolve_activation,
            out,
        );
    }
}

fn collect_candidate_builder_sites_by_type<'a>(
    pkg_files: &[&'a FileIr],
    pkg: &WorkspacePackage,
    min_fields: usize,
) -> BTreeMap<&'a str, Vec<(&'a FileIr, &'a StructLiteralConstructionSiteIr)>> {
    let defined_builders: HashSet<&str> = pkg_files
        .iter()
        .flat_map(|f| {
            f.architecture_facets
                .defined_builder_types
                .iter()
                .map(String::as_str)
        })
        .collect();

    let mut sites_by_type: BTreeMap<&str, Vec<(&FileIr, &StructLiteralConstructionSiteIr)>> =
        BTreeMap::new();

    for &file in pkg_files {
        for site in &file.architecture_facets.struct_literal_sites {
            if site.field_names.len() < min_fields
                || defined_builders.contains(site.type_name.as_str())
            {
                continue;
            }
            if pkg.config.respect_inline_disables
                && file.suppressions.is_suppressed(
                    RuleId::ArchPreferFluentBuilder,
                    site.loc.line,
                    site.span,
                    &file.jsx_elements,
                    &file.subjects,
                )
            {
                continue;
            }
            sites_by_type
                .entry(site.type_name.as_str())
                .or_default()
                .push((file, site));
        }
    }
    sites_by_type
}

type QualifyingBuilderSites<'a> = (
    Vec<&'a str>,
    Vec<(&'a FileIr, &'a StructLiteralConstructionSiteIr)>,
);

fn filter_qualifying_builder_sites<'a>(
    sites: Vec<(&'a FileIr, &'a StructLiteralConstructionSiteIr)>,
    min_sites: usize,
) -> Option<QualifyingBuilderSites<'a>> {
    let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for &(_, site) in &sites {
        let unique_defaults: BTreeSet<&str> = site
            .default_or_literal_fields
            .iter()
            .map(String::as_str)
            .collect();
        for field in unique_defaults {
            *default_field_counts.entry(field).or_insert(0) += 1;
        }
    }

    let overlapping_defaults: Vec<&str> = default_field_counts
        .into_iter()
        .filter_map(|(field, count)| (count >= 2).then_some(field))
        .collect();
    if overlapping_defaults.len() < 2 {
        return None;
    }

    let qualifying_sites: Vec<(&FileIr, &StructLiteralConstructionSiteIr)> = sites
        .into_iter()
        .filter(|(_, s)| {
            s.default_or_literal_fields
                .iter()
                .filter(|f| overlapping_defaults.contains(&f.as_str()))
                .count()
                >= 2
        })
        .collect();
    (qualifying_sites.len() >= min_sites).then_some((overlapping_defaults, qualifying_sites))
}

fn emit_fluent_builder_diagnostics_for_type<F>(
    type_name: &str,
    overlapping_defaults: &[&str],
    qualifying_sites: &[(&FileIr, &StructLiteralConstructionSiteIr)],
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
    let cascade_steps: Vec<String> = qualifying_sites
        .iter()
        .map(|(f, s)| {
            format!(
                "{}:{} (`{}`: {} fields, defaults=[{}])",
                f.path.to_string_lossy().replace('\\', "/"),
                s.loc.line,
                s.type_name,
                s.field_names.len(),
                s.default_or_literal_fields.join(", ")
            )
        })
        .collect();

    for (idx, &(file, site)) in qualifying_sites.iter().enumerate() {
        let Some(sev) = resolve_activation(
            RuleId::ArchPreferFluentBuilder,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        let peer_caller_sites: Vec<ResolvedCallerSite> = qualifying_sites
            .iter()
            .enumerate()
            .filter(|&(peer_idx, _)| peer_idx != idx)
            .map(|(_, &(peer_file, peer_site))| ResolvedCallerSite {
                caller_file: peer_file.path.clone(),
                parent_subject_name: None,
                component_name: type_name.to_string(),
                loc: peer_site.loc,
                span: peer_site.span,
                has_key: false,
                passed_props: peer_site.default_or_literal_fields.clone(),
            })
            .collect();

        out.push(
            make_diag_for_subject(
                RuleId::ArchPreferFluentBuilder,
                file.path.clone(),
                None,
                "archPreferFluentBuilder",
                type_name.to_string(),
                format!(
                    "`{type_name}` ({} fields) is initialized across {} call sites with overlapping default/boilerplate fields (`{}`); introduce a fluent `{type_name}Builder` or `create{type_name}` factory.",
                    site.field_names.len(),
                    qualifying_sites.len(),
                    overlapping_defaults.join("`, `")
                ),
                site.loc,
                site.span,
            )
            .with_severity(sev)
            .with_caller_sites(peer_caller_sites)
            .with_cascade_steps(cascade_steps.clone()),
        );
    }
}

pub(super) fn extract_inline_terminal_ui_sites_in_file(
    path: &Path,
    source: &str,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
) {
    let is_ui_kit = is_js_ui_kit_path(path);
    facets.is_ui_kit_module = is_ui_kit;

    if is_ui_kit || classify_file_context(path) != FileContext::Production {
        return;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::StringLiteral(str_lit) => {
                let cooked_str = str_lit.value.as_str().unwrap_or_default();
                let raw_slice = source
                    .get(str_lit.span.start as usize..str_lit.span.end as usize)
                    .unwrap_or(cooked_str);
                if let Some((kind, snippet)) = classify_terminal_ui_literal(cooked_str, raw_slice) {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, str_lit.span.start),
                            span: ByteSpan {
                                start: str_lit.span.start,
                                end: str_lit.span.end,
                            },
                        });
                }
            }
            AstKind::TemplateLiteral(tpl) => {
                if let Some((kind, snippet)) = extract_template_terminal_ui_hit(source, tpl) {
                    facets
                        .inline_terminal_ui_sites
                        .push(InlineTerminalUiPrimitiveSiteIr {
                            kind,
                            snippet,
                            loc: loc_from_line_starts(line_starts, tpl.span.start),
                            span: ByteSpan {
                                start: tpl.span.start,
                                end: tpl.span.end,
                            },
                        });
                }
            }
            _ => {}
        }
    }
}

fn extract_template_terminal_ui_hit(
    source: &str,
    tpl: &oxc_ast::ast::TemplateLiteral<'_>,
) -> Option<(TerminalUiPrimitiveKind, String)> {
    for quasi in &tpl.quasis {
        let cooked = quasi
            .value
            .cooked
            .and_then(|c| c.as_str())
            .unwrap_or(quasi.value.raw.as_str());
        if let Some(hit) = classify_terminal_ui_literal(cooked, quasi.value.raw.as_str()) {
            return Some(hit);
        }
    }
    let raw_slice = source
        .get(tpl.span.start as usize..tpl.span.end as usize)
        .unwrap_or_default();
    classify_terminal_ui_literal(raw_slice, raw_slice)
}

pub(super) fn evaluate_inline_terminal_ui_for_package<F>(
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
    for &file in pkg_files {
        if file.architecture_facets.is_ui_kit_module
            || file.architecture_facets.inline_terminal_ui_sites.is_empty()
        {
            continue;
        }
        let Some(sev) = resolve_activation(
            RuleId::ArchNoInlineTerminalUiPrimitives,
            file,
            &pkg.root_dir,
            &pkg.capability_gate,
            &pkg.config,
            enabled_rules,
        ) else {
            continue;
        };

        let active_sites: Vec<&InlineTerminalUiPrimitiveSiteIr> = file
            .architecture_facets
            .inline_terminal_ui_sites
            .iter()
            .filter(|site| {
                !(pkg.config.respect_inline_disables
                    && file.suppressions.is_suppressed(
                        RuleId::ArchNoInlineTerminalUiPrimitives,
                        site.loc.line,
                        site.span,
                        &file.jsx_elements,
                        &file.subjects,
                    ))
            })
            .collect();
        if active_sites.is_empty() {
            continue;
        }

        let file_stem = file
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("module")
            .to_string();
        let cascade_steps: Vec<String> = active_sites
            .iter()
            .map(|s| {
                format!(
                    "{}:{} ({}: `{}`)",
                    file.path.to_string_lossy().replace('\\', "/"),
                    s.loc.line,
                    s.kind,
                    s.snippet
                )
            })
            .collect();

        for (idx, &site) in active_sites.iter().enumerate() {
            let peer_caller_sites: Vec<ResolvedCallerSite> = active_sites
                .iter()
                .enumerate()
                .filter(|&(peer_idx, _)| peer_idx != idx)
                .map(|(_, &peer)| ResolvedCallerSite {
                    caller_file: file.path.clone(),
                    parent_subject_name: None,
                    component_name: peer.kind.as_str().to_string(),
                    loc: peer.loc,
                    span: peer.span,
                    has_key: false,
                    passed_props: Vec::new(),
                })
                .collect();

            out.push(
                make_diag_for_subject(
                    RuleId::ArchNoInlineTerminalUiPrimitives,
                    file.path.clone(),
                    None,
                    "archNoInlineTerminalUiPrimitives",
                    file_stem.clone(),
                    format!(
                        "Inline `{}` literal (`{}`) used in `{}` outside the terminal UI component kit; delegate to shared UI primitives.",
                        site.kind,
                        site.snippet,
                        file.path.to_string_lossy().replace('\\', "/")
                    ),
                    site.loc,
                    site.span,
                )
                .with_severity(sev)
                .with_caller_sites(peer_caller_sites)
                .with_cascade_steps(cascade_steps.clone()),
            );
        }
    }
}
