//! Structural JSX subtree extraction and FNV-1a fingerprinting (`JsxSubtreeIr`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JSX subtree hashing matches only relevant AST node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, Expression, JSXAttributeItem, JSXAttributeValue, JSXChild, JSXExpression,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{
    react_ast::{classify_jsx_element_name, find_enclosing_react_node, get_subject_name},
    types::{ByteSpan, JsxSubtreeIr, loc_from_line_starts},
};

/// Extracts all [`JsxSubtreeIr`] candidates (`JSXElement` and `JSXFragment`) with bottom-up structural hashes.
pub(crate) fn extract_jsx_subtrees(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<JsxSubtreeIr> {
    let mut jsx_nodes = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if matches!(
            node.kind(),
            AstKind::JSXElement(_) | AstKind::JSXFragment(_)
        ) {
            jsx_nodes.push(node_id);
        }
    }
    if jsx_nodes.is_empty() {
        return Vec::new();
    }

    let mut direct_children_by_parent: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for &node_id in &jsx_nodes {
        if let Some(parent_jsx_id) = semantic.nodes().ancestor_ids(node_id).find(|&anc| {
            matches!(
                semantic.nodes().kind(anc),
                AstKind::JSXElement(_) | AstKind::JSXFragment(_)
            )
        }) {
            direct_children_by_parent
                .entry(parent_jsx_id)
                .or_default()
                .push(node_id);
        }
    }

    let mut meta_by_node: HashMap<NodeId, (String, usize, usize)> =
        HashMap::with_capacity(jsx_nodes.len());
    let mut fingerprint_by_span: HashMap<(u32, u32), String> =
        HashMap::with_capacity(jsx_nodes.len());

    for &node_id in jsx_nodes.iter().rev() {
        let children = direct_children_by_parent
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let node_count = 1 + children
            .iter()
            .filter_map(|c| meta_by_node.get(c))
            .map(|(_, nc, _)| *nc)
            .sum::<usize>();
        let depth = 1 + children
            .iter()
            .filter_map(|c| meta_by_node.get(c))
            .map(|(_, _, d)| *d)
            .max()
            .unwrap_or(0);

        let fp = compute_jsx_node_fingerprint(node_id, semantic, &fingerprint_by_span);
        let span = semantic.nodes().get_node(node_id).span();
        fingerprint_by_span.insert((span.start, span.end), fp.clone());
        meta_by_node.insert(node_id, (fp, node_count, depth));
    }

    let mut subtrees = Vec::with_capacity(jsx_nodes.len());
    for node_id in jsx_nodes {
        let Some((fingerprint, node_count, depth)) = meta_by_node.remove(&node_id) else {
            continue;
        };
        let root_name = jsx_subtree_root_name(semantic, node_id);
        let (enclosing_subject, composition_root_offset) =
            find_enclosing_function_identity(semantic, node_id);

        let mut ancestor_names = Vec::new();
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            if matches!(
                semantic.nodes().kind(anc_id),
                AstKind::JSXElement(_) | AstKind::JSXFragment(_)
            ) {
                ancestor_names.push(jsx_subtree_root_name(semantic, anc_id));
            }
        }
        ancestor_names.reverse();

        let mut composition_path = Vec::new();
        if let Some(fn_name) = &enclosing_subject {
            composition_path.push(fn_name.clone());
        }
        composition_path.extend(ancestor_names);

        let span = semantic.nodes().get_node(node_id).span();
        let loc = loc_from_line_starts(line_starts, span.start);
        let end_loc = loc_from_line_starts(line_starts, span.end.saturating_sub(1));

        subtrees.push(JsxSubtreeIr {
            fingerprint,
            node_count,
            depth,
            root_name: root_name.clone(),
            enclosing_subject,
            composition_root_offset,
            composition_path: {
                composition_path.push(root_name);
                composition_path
            },
            span: ByteSpan {
                start: span.start,
                end: span.end,
            },
            loc,
            end_line: end_loc.line,
        });
    }

    subtrees
}

fn jsx_subtree_root_name(semantic: &Semantic<'_>, node_id: NodeId) -> String {
    match semantic.nodes().kind(node_id) {
        AstKind::JSXElement(el) => classify_jsx_element_name(semantic, &el.opening_element.name).0,
        AstKind::JSXFragment(_) => "Fragment".to_string(),
        _ => "Fragment".to_string(),
    }
}

fn find_enclosing_function_identity(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> (Option<String>, Option<u32>) {
    if let Some(subj_id) = find_enclosing_react_node(semantic, node_id) {
        let name =
            get_subject_name(semantic, subj_id).unwrap_or_else(|| "default export".to_string());
        let start = semantic.nodes().get_node(subj_id).span().start;
        return (Some(name), Some(start));
    }
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                let name = func
                    .id
                    .as_ref()
                    .map_or_else(|| "default export".to_string(), |id| id.name.to_string());
                return (Some(name), Some(func.span.start));
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier() {
                    return (Some(id.name.to_string()), Some(decl.span.start));
                }
            }
            AstKind::MethodDefinition(method) => {
                if let Some(name) = method
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                {
                    return (Some(name), Some(method.span.start));
                }
            }
            _ => {}
        }
    }
    (None, None)
}

fn compute_jsx_node_fingerprint(
    node_id: NodeId,
    semantic: &Semantic<'_>,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    let source = semantic.source_text();
    let mut parts = Vec::new();

    match semantic.nodes().kind(node_id) {
        AstKind::JSXElement(el) => {
            let kind_tag = if el.closing_element.is_none() {
                "JsxSelfClosingElement"
            } else {
                "JsxElement"
            };
            parts.push(kind_tag.to_string());
            let tag_name = classify_jsx_element_name(semantic, &el.opening_element.name).0;
            parts.push(tag_name);

            for attr_item in &el.opening_element.attributes {
                match attr_item {
                    JSXAttributeItem::Attribute(attr) => {
                        let attr_name = attr.name.span().source_text(source).trim();
                        let init_hash = match &attr.value {
                            None => "present".to_string(),
                            Some(JSXAttributeValue::StringLiteral(s)) => {
                                format!("string:{}", s.value.as_str().unwrap_or_default())
                            }
                            Some(JSXAttributeValue::Element(child_el)) => fingerprint_by_span
                                .get(&(child_el.span.start, child_el.span.end))
                                .cloned()
                                .unwrap_or_else(|| "jsx-el".to_string()),
                            Some(JSXAttributeValue::Fragment(child_frag)) => fingerprint_by_span
                                .get(&(child_frag.span.start, child_frag.span.end))
                                .cloned()
                                .unwrap_or_else(|| "jsx-frag".to_string()),
                            Some(JSXAttributeValue::ExpressionContainer(container)) => {
                                normalize_jsx_attr_expr(
                                    &container.expression,
                                    source,
                                    fingerprint_by_span,
                                )
                            }
                        };
                        parts.push(hash_framed_parts(&["attribute", attr_name, &init_hash]));
                    }
                    JSXAttributeItem::SpreadAttribute(spread) => {
                        let arg_hash =
                            normalize_ast_expr(&spread.argument, source, fingerprint_by_span);
                        parts.push(hash_framed_parts(&["spread", &arg_hash]));
                    }
                }
            }

            append_jsx_children_hashes(&el.children, source, fingerprint_by_span, &mut parts);
        }
        AstKind::JSXFragment(frag) => {
            parts.push("JsxFragment".to_string());
            parts.push("fragment".to_string());
            append_jsx_children_hashes(&frag.children, source, fingerprint_by_span, &mut parts);
        }
        _ => {}
    }

    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    format!("jsx:{}", hash_framed_parts(&refs))
}

fn append_jsx_children_hashes(
    children: &[JSXChild<'_>],
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
    parts: &mut Vec<String>,
) {
    for child in children {
        match child {
            JSXChild::Text(t) => {
                if !t.value.as_str().trim().is_empty() {
                    parts.push("jsx-text".to_string());
                }
            }
            JSXChild::Element(el) => {
                if let Some(fp) = fingerprint_by_span.get(&(el.span.start, el.span.end)) {
                    parts.push(fp.clone());
                }
            }
            JSXChild::Fragment(frag) => {
                if let Some(fp) = fingerprint_by_span.get(&(frag.span.start, frag.span.end)) {
                    parts.push(fp.clone());
                }
            }
            JSXChild::ExpressionContainer(container) => {
                if !matches!(container.expression, JSXExpression::EmptyExpression(_)) {
                    parts.push(normalize_jsx_expr(
                        &container.expression,
                        source,
                        fingerprint_by_span,
                    ));
                }
            }
            JSXChild::Spread(spread) => {
                let inner = normalize_ast_expr(&spread.expression, source, fingerprint_by_span);
                parts.push(hash_framed_parts(&["jsx-spread", &inner]));
            }
        }
    }
}

fn normalize_jsx_attr_expr(
    jsx_expr: &JSXExpression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    if let Some(expr) = jsx_expr.as_expression() {
        let inner = expr.without_parentheses();
        if matches!(
            inner,
            Expression::StringLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
        ) {
            return format!("static:{}", inner.span().source_text(source).trim());
        }
    }
    let inner_hash = normalize_jsx_expr(jsx_expr, source, fingerprint_by_span);
    hash_framed_parts(&["JsxExpression", &inner_hash])
}

fn normalize_jsx_expr(
    jsx_expr: &JSXExpression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    let Some(expr) = jsx_expr.as_expression() else {
        return "empty".to_string();
    };
    normalize_ast_expr(expr, source, fingerprint_by_span)
}

fn normalize_ast_expr(
    expr: &Expression<'_>,
    source: &str,
    fingerprint_by_span: &HashMap<(u32, u32), String>,
) -> String {
    match expr.without_parentheses() {
        Expression::JSXElement(el) => fingerprint_by_span
            .get(&(el.span.start, el.span.end))
            .cloned()
            .unwrap_or_else(|| "jsx-el".to_string()),
        Expression::JSXFragment(frag) => fingerprint_by_span
            .get(&(frag.span.start, frag.span.end))
            .cloned()
            .unwrap_or_else(|| "jsx-frag".to_string()),
        Expression::Identifier(_) => "identifier".to_string(),
        Expression::StringLiteral(_) => "StringLiteral".to_string(),
        Expression::NumericLiteral(_) => "NumericLiteral".to_string(),
        Expression::BooleanLiteral(b) => {
            if b.value {
                "TrueKeyword".to_string()
            } else {
                "FalseKeyword".to_string()
            }
        }
        Expression::NullLiteral(_) => "NullKeyword".to_string(),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
            "NoSubstitutionTemplateLiteral".to_string()
        }
        Expression::RegExpLiteral(_) => "RegularExpressionLiteral".to_string(),
        Expression::StaticMemberExpression(mem) => {
            let obj_hash = normalize_ast_expr(&mem.object, source, fingerprint_by_span);
            let opt = if mem.optional { "optional" } else { "required" };
            hash_framed_parts(&[
                "property-access",
                opt,
                &obj_hash,
                mem.property.name.as_str(),
            ])
        }
        Expression::ComputedMemberExpression(comp) => {
            let obj_hash = normalize_ast_expr(&comp.object, source, fingerprint_by_span);
            let opt = if comp.optional {
                "optional"
            } else {
                "required"
            };
            let arg_inner = comp.expression.without_parentheses();
            let arg_hash = match arg_inner {
                Expression::StringLiteral(s) => {
                    format!("StringLiteral:{}", s.value.as_str().unwrap_or_default())
                }
                Expression::NumericLiteral(n) => {
                    format!("NumericLiteral:{}", n.span.source_text(source).trim())
                }
                _ => normalize_ast_expr(arg_inner, source, fingerprint_by_span),
            };
            hash_framed_parts(&["element-access", opt, &obj_hash, &arg_hash])
        }
        Expression::BinaryExpression(bin) => {
            let left = normalize_ast_expr(&bin.left, source, fingerprint_by_span);
            let right = normalize_ast_expr(&bin.right, source, fingerprint_by_span);
            hash_framed_parts(&["binary-expression", bin.operator.as_str(), &left, &right])
        }
        Expression::LogicalExpression(log) => {
            let left = normalize_ast_expr(&log.left, source, fingerprint_by_span);
            let right = normalize_ast_expr(&log.right, source, fingerprint_by_span);
            hash_framed_parts(&["logical-expression", log.operator.as_str(), &left, &right])
        }
        Expression::UnaryExpression(un) => {
            let arg = normalize_ast_expr(&un.argument, source, fingerprint_by_span);
            hash_framed_parts(&["PrefixUnaryExpression", un.operator.as_str(), &arg])
        }
        Expression::ConditionalExpression(cond) => {
            let test = normalize_ast_expr(&cond.test, source, fingerprint_by_span);
            let cons = normalize_ast_expr(&cond.consequent, source, fingerprint_by_span);
            let alt = normalize_ast_expr(&cond.alternate, source, fingerprint_by_span);
            hash_framed_parts(&["ConditionalExpression", &test, &cons, &alt])
        }
        Expression::CallExpression(call) => {
            let mut parts = vec![
                "CallExpression".to_string(),
                normalize_ast_expr(&call.callee, source, fingerprint_by_span),
            ];
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    parts.push(normalize_ast_expr(e, source, fingerprint_by_span));
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let body_hash = if let Some(e) = arrow.body.as_expression() {
                normalize_ast_expr(e, source, fingerprint_by_span)
            } else if let ArrowFunctionBody::FunctionBody(b) = &arrow.body {
                format!("block:{}", b.statements.len())
            } else {
                "body".to_string()
            };
            hash_framed_parts(&["ArrowFunction", &body_hash])
        }
        Expression::ObjectExpression(obj) => {
            let mut parts = vec!["ObjectLiteralExpression".to_string()];
            for prop in &obj.properties {
                match prop {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                        let key = p.key.span().source_text(source).trim();
                        if p.shorthand {
                            parts.push(hash_framed_parts(&["shorthand-property", key]));
                        } else {
                            let val = normalize_ast_expr(&p.value, source, fingerprint_by_span);
                            parts.push(hash_framed_parts(&["property-assignment", key, &val]));
                        }
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(s) => {
                        let val = normalize_ast_expr(&s.argument, source, fingerprint_by_span);
                        parts.push(hash_framed_parts(&["spread", &val]));
                    }
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        Expression::ArrayExpression(arr) => {
            let mut parts = vec!["ArrayLiteralExpression".to_string()];
            for elem in &arr.elements {
                if let Some(e) = elem.as_expression() {
                    parts.push(normalize_ast_expr(e, source, fingerprint_by_span));
                }
            }
            let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
            hash_framed_parts(&refs)
        }
        _ => "expr".to_string(),
    }
}

fn hash_framed_parts(parts: &[&str]) -> String {
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
    for &part in parts {
        let header = format!("{}:", part.len());
        for &b in header.as_bytes().iter().chain(part.as_bytes().iter()) {
            h1 ^= u64::from(b);
            h1 = h1.wrapping_mul(0x0100_0000_01b3);
            h2 = h2
                .wrapping_add(u64::from(b))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    format!("{h1:016x}{h2:016x}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;

    #[test]
    fn computes_identical_jsx_subtree_fingerprints_across_identifier_renames() {
        let src_a = r#"
export function CardA({ user }: any) {
    return <section className="card"><header><h2>{user.name}</h2></header></section>;
}
"#;
        let src_b = r#"
export function CardB({ member }: any) {
    return <section className="card"><header><h2>{member.name}</h2></header></section>;
}
"#;
        let file_a = parse_file_ir(Path::new("CardA.tsx"), src_a);
        let file_b = parse_file_ir(Path::new("CardB.tsx"), src_b);
        let root_a = file_a
            .jsx_subtrees
            .iter()
            .find(|s| s.root_name == "section")
            .expect("section A");
        let root_b = file_b
            .jsx_subtrees
            .iter()
            .find(|s| s.root_name == "section")
            .expect("section B");
        assert_eq!(root_a.fingerprint, root_b.fingerprint);
        assert_eq!(root_a.node_count, 3);
        assert_eq!(root_a.depth, 3);
    }
}
