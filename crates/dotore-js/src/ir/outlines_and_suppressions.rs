//! Single-pass **Symbol Outline** and inline suppression directive extraction.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; outline extraction matches only relevant declaration kinds"
)]

use oxc_ast::{
    AstKind,
    ast::{Expression, TSEnumMemberName, VariableDeclarationKind},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use dotore_core::ir::extract_c_style_comment_suppressions;

use crate::matchers::{collect_binding_identifiers, property_key_name};

use super::types::{ByteSpan, FileSuppressions, SymbolKind, SymbolOutline, loc_from_line_starts};

struct OutlineTarget<'a> {
    name: String,
    kind: SymbolKind,
    id_span: Span,
    decl_span: Span,
    body_start: Option<u32>,
    parent_name: Option<String>,
    exported: bool,
    source: &'a str,
    lines: &'a [&'a str],
    line_starts: &'a [u32],
}

/// Extracts all **Symbol Outlines** (`Function`, `Class`, `Interface`, `Type`, `Enum`, `Constant`, `Variable`, `Method`, `Property`, `Import`, `Export`) in `semantic`.
pub(super) fn extract_symbol_outlines(
    semantic: &Semantic<'_>,
    source: &str,
    line_starts: &[u32],
) -> Vec<SymbolOutline> {
    let lines: Vec<&str> = source.lines().collect();
    let mut outlines = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let parent_id = semantic.nodes().parent_id(node_id);
        let parent_kind = semantic.nodes().kind(parent_id);
        let container = find_enclosing_container_name(semantic, node_id);

        match node.kind() {
            AstKind::Function(func) => {
                if matches!(
                    parent_kind,
                    AstKind::MethodDefinition(_)
                        | AstKind::ObjectProperty(_)
                        | AstKind::PropertyDefinition(_)
                ) {
                    continue;
                }
                if func.is_expression() && matches!(parent_kind, AstKind::VariableDeclarator(_)) {
                    continue;
                }
                if let Some(id) = &func.id {
                    let (decl_span, exported) =
                        resolve_decl_span_and_export(semantic, node_id, func.span);
                    push_symbol_outline(
                        &mut outlines,
                        OutlineTarget {
                            name: id.name.to_string(),
                            kind: SymbolKind::Function,
                            id_span: id.span,
                            decl_span,
                            body_start: func.body.as_ref().map(|b| b.span.start),
                            parent_name: container,
                            exported,
                            source,
                            lines: &lines,
                            line_starts,
                        },
                    );
                }
            }
            AstKind::Class(class) => {
                if class.is_expression() && matches!(parent_kind, AstKind::VariableDeclarator(_)) {
                    continue;
                }
                if let Some(id) = &class.id {
                    let (decl_span, exported) =
                        resolve_decl_span_and_export(semantic, node_id, class.span);
                    push_symbol_outline(
                        &mut outlines,
                        OutlineTarget {
                            name: id.name.to_string(),
                            kind: SymbolKind::Class,
                            id_span: id.span,
                            decl_span,
                            body_start: Some(class.body.span.start),
                            parent_name: container,
                            exported,
                            source,
                            lines: &lines,
                            line_starts,
                        },
                    );
                }
            }
            AstKind::TSInterfaceDeclaration(iface) => {
                let (decl_span, exported) =
                    resolve_decl_span_and_export(semantic, node_id, iface.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: iface.id.name.to_string(),
                        kind: SymbolKind::Interface,
                        id_span: iface.id.span,
                        decl_span,
                        body_start: Some(iface.body.span.start),
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::TSTypeAliasDeclaration(t) => {
                let (decl_span, exported) = resolve_decl_span_and_export(semantic, node_id, t.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: t.id.name.to_string(),
                        kind: SymbolKind::Type,
                        id_span: t.id.span,
                        decl_span,
                        body_start: None,
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::TSEnumDeclaration(e) => {
                let (decl_span, exported) = resolve_decl_span_and_export(semantic, node_id, e.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: e.id.name.to_string(),
                        kind: SymbolKind::Enum,
                        id_span: e.id.span,
                        decl_span,
                        body_start: Some(e.body.span.start),
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::TSEnumMember(member) => {
                let Some(member_name) = extract_enum_member_name(&member.id) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, member.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: member_name,
                        kind: SymbolKind::EnumMember,
                        id_span: member.id.span(),
                        decl_span: member.span,
                        body_start: None,
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::VariableDeclarator(decl) => {
                let AstKind::VariableDeclaration(var_decl) = parent_kind else {
                    continue;
                };
                let init_expr = decl.init.as_ref().map(Expression::without_parentheses);
                let is_fn_init = matches!(
                    init_expr,
                    Some(
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                );
                let kind = if is_fn_init {
                    SymbolKind::Function
                } else if var_decl.kind == VariableDeclarationKind::Const {
                    SymbolKind::Constant
                } else {
                    SymbolKind::Variable
                };
                let body_start = expr_body_start(init_expr);
                let (var_span, exported) =
                    resolve_decl_span_and_export(semantic, parent_id, var_decl.span);
                let decl_span = if var_decl.declarations.len() == 1 {
                    var_span
                } else {
                    decl.span
                };
                let mut bindings = Vec::new();
                collect_binding_identifiers(&decl.id, &mut bindings);
                for (name, id_span) in bindings {
                    push_symbol_outline(
                        &mut outlines,
                        OutlineTarget {
                            name,
                            kind,
                            id_span,
                            decl_span,
                            body_start,
                            parent_name: container.clone(),
                            exported,
                            source,
                            lines: &lines,
                            line_starts,
                        },
                    );
                }
            }
            AstKind::MethodDefinition(m) => {
                let Some(name) = property_key_name(&m.key) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, m.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Method,
                        id_span: m.key.span(),
                        decl_span: m.span,
                        body_start: m.value.body.as_ref().map(|b| b.span.start),
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::PropertyDefinition(p) => {
                let Some(name) = property_key_name(&p.key) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, p.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Property,
                        id_span: p.key.span(),
                        decl_span: p.span,
                        body_start: expr_body_start(
                            p.value.as_ref().map(Expression::without_parentheses),
                        ),
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::AccessorProperty(a) => {
                let Some(name) = property_key_name(&a.key) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, a.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Property,
                        id_span: a.key.span(),
                        decl_span: a.span,
                        body_start: None,
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::TSMethodSignature(m) => {
                let Some(name) = property_key_name(&m.key) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, m.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Method,
                        id_span: m.key.span(),
                        decl_span: m.span,
                        body_start: None,
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::TSPropertySignature(p) => {
                let Some(name) = property_key_name(&p.key) else {
                    continue;
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, p.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Property,
                        id_span: p.key.span(),
                        decl_span: p.span,
                        body_start: None,
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ObjectProperty(prop) => {
                if !matches!(parent_kind, AstKind::ObjectExpression(_)) {
                    continue;
                }
                let Some(name) = property_key_name(&prop.key) else {
                    continue;
                };
                let kind = if prop.method {
                    SymbolKind::Method
                } else {
                    SymbolKind::Property
                };
                let (_, exported) = resolve_decl_span_and_export(semantic, node_id, prop.span);
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind,
                        id_span: prop.key.span(),
                        decl_span: prop.span,
                        body_start: expr_body_start(Some(prop.value.without_parentheses())),
                        parent_name: container,
                        exported,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ImportSpecifier(spec) => {
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: spec.local.name.to_string(),
                        kind: SymbolKind::Import,
                        id_span: spec.local.span,
                        decl_span: spec.span,
                        body_start: None,
                        parent_name: container,
                        exported: false,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ImportDefaultSpecifier(spec) => {
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: spec.local.name.to_string(),
                        kind: SymbolKind::Import,
                        id_span: spec.local.span,
                        decl_span: spec.span,
                        body_start: None,
                        parent_name: container,
                        exported: false,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ImportNamespaceSpecifier(spec) => {
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: spec.local.name.to_string(),
                        kind: SymbolKind::Import,
                        id_span: spec.local.span,
                        decl_span: spec.span,
                        body_start: None,
                        parent_name: container,
                        exported: false,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ExportSpecifier(spec) => {
                let name = spec.exported.name().as_str().to_string();
                if name.is_empty() {
                    continue;
                }
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name,
                        kind: SymbolKind::Export,
                        id_span: spec.exported.span(),
                        decl_span: spec.span,
                        body_start: None,
                        parent_name: container,
                        exported: true,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ExportDefaultDeclaration(exp) => {
                push_symbol_outline(
                    &mut outlines,
                    OutlineTarget {
                        name: "default".to_string(),
                        kind: SymbolKind::Export,
                        id_span: exp.span,
                        decl_span: exp.span,
                        body_start: None,
                        parent_name: container,
                        exported: true,
                        source,
                        lines: &lines,
                        line_starts,
                    },
                );
            }
            AstKind::ExportAllDeclaration(exp) => {
                if let Some(exported_name) = &exp.exported {
                    let name = exported_name.name().as_str().to_string();
                    if !name.is_empty() {
                        push_symbol_outline(
                            &mut outlines,
                            OutlineTarget {
                                name,
                                kind: SymbolKind::Export,
                                id_span: exported_name.span(),
                                decl_span: exp.span,
                                body_start: None,
                                parent_name: container,
                                exported: true,
                                source,
                                lines: &lines,
                                line_starts,
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }

    outlines
}

fn find_enclosing_container_name(semantic: &Semantic<'_>, node_id: NodeId) -> Option<String> {
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Class(c) => {
                if let Some(id) = &c.id {
                    return Some(id.name.to_string());
                }
            }
            AstKind::TSInterfaceDeclaration(i) => return Some(i.id.name.to_string()),
            AstKind::TSEnumDeclaration(e) => return Some(e.id.name.to_string()),
            AstKind::TSTypeAliasDeclaration(t) => return Some(t.id.name.to_string()),
            AstKind::Function(f) => {
                if let Some(id) = &f.id {
                    return Some(id.name.to_string());
                }
            }
            AstKind::MethodDefinition(m) => {
                if let Some(name) = property_key_name(&m.key) {
                    return Some(name);
                }
            }
            AstKind::VariableDeclarator(v) => {
                if let Some(id) = v.id.get_binding_identifier() {
                    return Some(id.name.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn resolve_decl_span_and_export(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    own_span: Span,
) -> (Span, bool) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let decl_span = match semantic.nodes().kind(parent_id) {
        AstKind::ExportDeclaration(exp) => exp.span,
        AstKind::ExportNamedDeclaration(exp) => exp.span,
        AstKind::ExportDefaultDeclaration(exp) => exp.span,
        _ => own_span,
    };
    let exported = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ExportDeclaration(_)
                | AstKind::ExportNamedDeclaration(_)
                | AstKind::ExportDefaultDeclaration(_)
        )
    });
    (decl_span, exported)
}

fn expr_body_start(expr: Option<&Expression<'_>>) -> Option<u32> {
    match expr {
        Some(Expression::ArrowFunctionExpression(arrow)) => Some(arrow.body.span().start),
        Some(Expression::FunctionExpression(func)) => func.body.as_ref().map(|b| b.span.start),
        _ => None,
    }
}

fn extract_enum_member_name(id: &TSEnumMemberName<'_>) -> Option<String> {
    let s = id.static_name().as_str().unwrap_or_default();
    (!s.is_empty()).then(|| s.to_string())
}

fn push_symbol_outline(out: &mut Vec<SymbolOutline>, target: OutlineTarget<'_>) {
    let id_loc = loc_from_line_starts(target.line_starts, target.id_span.start);
    let decl_start_loc = loc_from_line_starts(target.line_starts, target.decl_span.start);
    let end_loc = loc_from_line_starts(
        target.line_starts,
        target
            .decl_span
            .end
            .saturating_sub(1)
            .max(target.decl_span.start),
    );
    let (doc_comment, comment_start_line) = extract_adjacent_comment(
        target.source,
        target.lines,
        target.line_starts,
        target.decl_span.start,
        decl_start_loc.line,
    );
    let sig_end_offset = compute_signature_end(
        target.source,
        target.decl_span.start,
        target.decl_span.end,
        target.body_start,
    );
    let sig_end_loc = loc_from_line_starts(
        target.line_starts,
        sig_end_offset.saturating_sub(1).max(target.decl_span.start),
    );
    let raw_sig = target
        .source
        .get(target.decl_span.start as usize..sig_end_offset as usize)
        .unwrap_or("");
    let signature = normalize_whitespace(raw_sig)
        .trim_end_matches('{')
        .trim()
        .to_string();

    out.push(
        SymbolOutline::new(
            target.name,
            target.kind,
            signature,
            ByteSpan {
                start: target.decl_span.start,
                end: target.decl_span.end,
            },
            id_loc,
            end_loc.line.max(decl_start_loc.line),
        )
        .with_exported(target.exported)
        .with_parent(target.parent_name)
        .with_doc_comment(doc_comment, comment_start_line)
        .with_signature_end_line(sig_end_loc.line),
    );
}

fn compute_signature_end(
    source: &str,
    decl_start: u32,
    decl_end: u32,
    body_start: Option<u32>,
) -> u32 {
    if let Some(bs) = body_start
        && bs > decl_start
    {
        return bs.min(decl_end);
    }
    let start_usize = (decl_start as usize).min(source.len());
    let fallback_end = source[start_usize..]
        .find('\n')
        .map_or(decl_end, |rel| decl_start + u32::try_from(rel).unwrap_or(0));
    decl_end.min(fallback_end)
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_adjacent_comment(
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    decl_start: u32,
    decl_line_1based: u32,
) -> (Option<String>, Option<u32>) {
    let mut collected: Vec<(u32, String)> = Vec::new();

    if decl_line_1based > 1 {
        let mut idx = (decl_line_1based as usize).saturating_sub(2);
        let mut in_block = false;
        while let Some(raw_line) = lines.get(idx) {
            let line = raw_line.trim();
            let line_num = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            if in_block {
                collected.push((line_num, line.to_string()));
                if line.starts_with("/*") {
                    in_block = false;
                }
            } else if line.starts_with("//") {
                collected.push((line_num, line.to_string()));
            } else if line.ends_with("*/") {
                collected.push((line_num, line.to_string()));
                if !line.starts_with("/*") {
                    in_block = true;
                }
            } else {
                break;
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        collected.reverse();
    }

    if let Some(inline_comment) =
        extract_inline_leading_block_comment(source, line_starts, decl_start, decl_line_1based)
    {
        collected.push((decl_line_1based, inline_comment));
    }

    if collected.is_empty() {
        return (None, None);
    }
    let first_line = collected.first().map(|(l, _)| *l);
    let joined = collected
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n");
    (Some(joined), first_line)
}

fn extract_inline_leading_block_comment(
    source: &str,
    line_starts: &[u32],
    decl_start: u32,
    decl_line_1based: u32,
) -> Option<String> {
    let line_start = *line_starts.get((decl_line_1based as usize).saturating_sub(1))?;
    if decl_start <= line_start {
        return None;
    }
    let prefix = source.get(line_start as usize..decl_start as usize)?;
    let comment_start = prefix.find("/*")?;
    let after_open = &prefix[comment_start..];
    let comment_end = after_open.find("*/")?;
    let comment = after_open[..comment_end + 2].trim();
    (!comment.is_empty()).then(|| comment.to_string())
}

/// Parses inline disable directives (`dotore-disable*`, `eslint-disable*`, `oxlint-disable*`) from `source`
/// using the shared C-style comment suppression parser in `dotore-core`.
#[must_use]
pub(crate) fn extract_file_suppressions(source: &str) -> FileSuppressions {
    extract_c_style_comment_suppressions(source, &["dotore", "eslint", "oxlint"])
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        ir::{SymbolKind, parse_file_ir},
        rules::RuleId,
    };

    #[test]
    fn extracts_symbol_outlines_and_c_style_suppressions() {
        let src = r#"
/** Renders a greeting banner. */
export function Banner({ title }: { title: string }) {
    // dotore-disable-next-line no-derived-state -- intentional
    return <h1>{title}</h1>;
}
/* eslint-disable jsx-key */
const items = [1, 2];
/* eslint-enable jsx-key */
"#;
        let file = parse_file_ir(Path::new("Banner.tsx"), src);
        let banner = file
            .symbol_outlines
            .iter()
            .find(|s| s.name == "Banner")
            .expect("Banner outline");
        assert_eq!(banner.kind, SymbolKind::Function);
        assert!(banner.exported);
        assert_eq!(
            banner.doc_comment.as_deref(),
            Some("/** Renders a greeting banner. */")
        );

        assert!(file.suppressions.matches_line(RuleId::NoDerivedState, 5));
        assert!(file.suppressions.matches_line_or_block(RuleId::JsxKey, 8));
        assert!(!file.suppressions.matches_line_or_block(RuleId::JsxKey, 10));
    }
}
