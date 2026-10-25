//! Loop-invariant `Intl`/`RegExp` hoisting and `Map`/`Set`/property-access loop lookup rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; hoisting and loop lookup detectors match only relevant AST node kinds (#50)"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{Argument, Expression, NewExpression},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{INTL_CLASSES, belongs_directly_to_loop, collect_callee_identifier_trail};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::{is_global_ident, push_semantic_site, resolve_ident_symbol, unwrap_expr},
    rules::RuleId,
};

// ---------------------------------------------------------------------------
// 4. `js-hoist-intl` & `js-hoist-regexp`
// ---------------------------------------------------------------------------

pub(super) fn check_js_hoist_intl(
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&new_expr.callee) else {
        return;
    };
    let class_name = mem.property.name.as_str();
    if !INTL_CLASSES.contains(&class_name) {
        return;
    }
    let Expression::Identifier(intl_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if intl_id.name != "Intl" || !is_global_ident(semantic, intl_id) {
        return;
    }

    let mut in_fn = false;
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                in_fn = true;
                if let AstKind::CallExpression(call) = semantic.nodes().parent_kind(anc_id) {
                    let trail = collect_callee_identifier_trail(&call.callee);
                    if trail
                        .first()
                        .is_some_and(|n| matches!(n.as_str(), "useMemo" | "useCallback" | "useRef"))
                    {
                        return;
                    }
                }
                break;
            }
            AstKind::TryStatement(_) => return,
            _ => {}
        }
    }
    if !in_fn {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsHoistIntl,
        subject_name,
        "jsHoistIntl",
        &format!("Intl.{class_name}"),
        format!(
            "This is slow because new Intl.{class_name}() rebuilds on every call inside a function, so move it to the top of the file, or wrap it in useMemo"
        ),
        line_starts,
        new_expr.span,
    );
}

pub(super) fn check_js_hoist_regexp_call(
    node_id: NodeId,
    span: Span,
    callee: &Expression<'_>,
    arguments: &[Argument<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(callee) else {
        return;
    };
    if callee_id.name != "RegExp" || !is_global_ident(semantic, callee_id) {
        return;
    }
    let Some(first_arg) = arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let is_static_pat = match unwrap_expr(first_arg) {
        Expression::StringLiteral(_) | Expression::RegExpLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        _ => false,
    };
    if !is_static_pat {
        return;
    }
    if let Some(flags_arg) = arguments.get(1).and_then(Argument::as_expression) {
        if let Expression::StringLiteral(flags_lit) = unwrap_expr(flags_arg) {
            let f = flags_lit.value.as_str().unwrap_or_default();
            if f.contains('g') || f.contains('y') {
                return;
            }
        } else {
            return;
        }
    }

    let in_loop = semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::ForStatement(_)
                    | AstKind::ForOfStatement(_)
                    | AstKind::ForInStatement(_)
                    | AstKind::WhileStatement(_)
                    | AstKind::DoWhileStatement(_)
            )
        });
    if !in_loop {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsHoistRegexp,
        subject_name,
        "jsHoistRegexp",
        "RegExp",
        "`new RegExp()` rebuilds the pattern on every loop pass. Move it to a constant outside the loop.".to_string(),
        line_starts,
        span,
    );
}

// ---------------------------------------------------------------------------
// 5. `js-index-maps`, `js-set-map-lookups`, `js-cache-property-access`
// ---------------------------------------------------------------------------

pub(super) fn check_js_index_maps_in_loop(
    loop_node_id: NodeId,
    loop_span: Span,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id) {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        let method = mem.property.name.as_str();
        if method != "find" && method != "findIndex" {
            continue;
        }
        if !is_external_non_constant_receiver(&mem.object, loop_span, semantic) {
            continue;
        }
        let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let Expression::ArrowFunctionExpression(arrow) = unwrap_expr(cb_arg) else {
            continue;
        };
        let body_src = arrow.body.span().source_text(semantic.source_text());
        if !body_src.contains("===") && !body_src.contains("==") {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::JsIndexMaps,
            subject_name,
            "jsIndexMaps",
            method,
            format!(
                "This gets slow as your list grows because array.{method}() runs inside a loop, so build a Map once before the loop for instant lookups"
            ),
            line_starts,
            call.span,
        );
    }
}

pub(super) fn check_js_set_map_lookups_in_loop(
    loop_node_id: NodeId,
    loop_span: Span,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !belongs_directly_to_loop(semantic, node_id, loop_node_id)
            || call.arguments.len() != 1
        {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        let method = mem.property.name.as_str();
        if method != "includes" && method != "indexOf" {
            continue;
        }
        let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        if !is_external_non_constant_receiver(&mem.object, loop_span, semantic) {
            continue;
        }
        if let Some(arg) = call.arguments.first().and_then(Argument::as_expression)
            && matches!(unwrap_expr(arg), Expression::StringLiteral(_))
        {
            continue;
        }

        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::JsSetMapLookups,
            subject_name,
            "jsSetMapLookups",
            &format!("{}.{method}", recv_id.name),
            format!(
                "Calling `{}.{method}()` inside a loop scans the array on every iteration; convert `{}` to a `Set` before the loop for O(1) lookups.",
                recv_id.name, recv_id.name
            ),
            line_starts,
            call.span,
        );
    }
}

fn is_external_non_constant_receiver(
    object_expr: &Expression<'_>,
    loop_span: Span,
    semantic: &Semantic<'_>,
) -> bool {
    let Expression::Identifier(recv_id) = unwrap_expr(object_expr) else {
        return false;
    };
    if recv_id
        .name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    if let Some(sym_id) = resolve_ident_symbol(semantic, recv_id) {
        let decl_span = semantic
            .nodes()
            .get_node(semantic.scoping().symbol_declaration(sym_id))
            .span();
        if loop_span.contains_inclusive(decl_span) {
            return false;
        }
    }
    true
}

pub(super) fn check_js_cache_property_access_in_loop(
    loop_node_id: NodeId,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let (counts, written) =
        collect_loop_property_reads_and_writes(loop_node_id, loop_body_span, semantic);

    for (key, (count, first_span)) in counts {
        if count < 3
            || written
                .iter()
                .any(|w| key == *w || key.starts_with(&format!("{w}.")))
        {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, loop_node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::JsCachePropertyAccess,
            subject_name,
            "jsCachePropertyAccess",
            &key,
            format!(
                "This may slow the loop because {key} is read {count} times inside it; if the value stays unchanged between those reads, cache it immediately before the first read"
            ),
            line_starts,
            first_span,
        );
    }
}

fn collect_loop_property_reads_and_writes(
    loop_node_id: NodeId,
    loop_body_span: Span,
    semantic: &Semantic<'_>,
) -> (HashMap<String, (usize, Span)>, HashSet<String>) {
    let mut counts: HashMap<String, (usize, Span)> = HashMap::new();
    let mut written: HashSet<String> = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !loop_body_span.contains_inclusive(node.span())
            || !belongs_directly_to_loop(semantic, node_id, loop_node_id)
        {
            continue;
        }
        match node.kind() {
            AstKind::AssignmentExpression(assign) => {
                let lhs = assign
                    .left
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                written.insert(lhs.to_string());
            }
            AstKind::UpdateExpression(upd) => {
                let arg = upd
                    .argument
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                written.insert(arg.to_string());
            }
            AstKind::StaticMemberExpression(mem) => {
                if let Some(raw) = extract_cacheable_member_chain(node_id, mem, semantic) {
                    let entry = counts.entry(raw.to_string()).or_insert((0, mem.span));
                    entry.0 += 1;
                }
            }
            _ => {}
        }
    }
    (counts, written)
}

fn extract_cacheable_member_chain<'a>(
    node_id: NodeId,
    mem: &oxc_ast::ast::StaticMemberExpression<'a>,
    semantic: &Semantic<'a>,
) -> Option<&'a str> {
    let parent_kind = semantic.nodes().parent_kind(node_id);
    if matches!(
        parent_kind,
        AstKind::StaticMemberExpression(_) | AstKind::CallExpression(_)
    ) {
        return None;
    }
    if let AstKind::AssignmentExpression(assign) = parent_kind
        && assign.left.span() == mem.span
    {
        return None;
    }
    let raw = mem.span.source_text(semantic.source_text()).trim();
    if raw.contains('(')
        || raw.contains('[')
        || raw.contains(' ')
        || raw.split('.').count() < 3
        || raw.ends_with(".length")
    {
        return None;
    }
    Some(raw)
}
