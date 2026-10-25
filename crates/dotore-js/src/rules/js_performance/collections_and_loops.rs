//! Collection allocation, cloning, array iteration, hoisting, and loop lookup rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; collection and loop detectors match only relevant AST node kinds"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, CallExpression, Expression, IfStatement, LogicalOperator,
        ObjectPropertyKind, Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

pub(super) use super::loop_hoisting_and_lookups::{
    check_js_cache_property_access_in_loop, check_js_hoist_intl, check_js_hoist_regexp_call,
    check_js_index_maps_in_loop, check_js_set_map_lookups_in_loop,
};

use super::CHAINABLE_ITERATION_METHODS;
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name, is_component_name},
        types::SemanticRuleSite,
    },
    matchers::{
        push_semantic_site, push_semantic_site_with_fix, span_to_byte_span, unwrap_expr,
    },
    rules::{AutofixPatch, RuleId},
};

// ---------------------------------------------------------------------------
// 1. `no-spread-accumulator-in-reduce`
// ---------------------------------------------------------------------------

pub(super) fn check_no_spread_accumulator_in_reduce(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some((acc_name, body_span)) = extract_reduce_accumulator_and_body(call) else {
        return;
    };

    for (_, inner_node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let spread_span = match inner_node.kind() {
            AstKind::ObjectExpression(obj)
                if object_spreads_and_grows_accumulator(obj, acc_name) =>
            {
                Some(obj.span)
            }
            AstKind::ArrayExpression(arr) if array_spreads_and_grows_accumulator(arr, acc_name) => {
                Some(arr.span)
            }
            _ => None,
        };
        if let Some(target_span) = spread_span {
            let subject_name = find_enclosing_react_node(semantic, node_id)
                .and_then(|id| get_subject_name(semantic, id));
            push_semantic_site(
                out,
                RuleId::NoSpreadAccumulatorInReduce,
                subject_name,
                "noSpreadAccumulatorInReduce",
                acc_name,
                "This is O(n²) because spreading the accumulator copies the entire growing collection every step. Mutate and return the accumulator instead (acc[key] = value; return acc).".to_string(),
                line_starts,
                target_span,
            );
            return;
        }
    }
}

fn extract_reduce_accumulator_and_body<'a>(
    call: &'a CallExpression<'a>,
) -> Option<(&'a str, Span)> {
    let Expression::StaticMemberExpression(callee_mem) = unwrap_expr(&call.callee) else {
        return None;
    };
    if !matches!(callee_mem.property.name.as_str(), "reduce" | "reduceRight") {
        return None;
    }
    if let Expression::ArrayExpression(arr) = unwrap_expr(&callee_mem.object)
        && arr.elements.len() <= 8
        && arr
            .elements
            .iter()
            .all(|e| !matches!(e, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)))
    {
        return None;
    }
    let seed_expr = call.arguments.get(1)?.as_expression()?;
    if !matches!(
        unwrap_expr(seed_expr),
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
    ) {
        return None;
    }
    let cb_expr = call.arguments.first()?.as_expression()?;
    match unwrap_expr(cb_expr) {
        Expression::ArrowFunctionExpression(arrow) if !arrow.r#async => {
            let id = arrow.params.items.first()?.pattern.get_binding_identifier()?;
            Some((id.name.as_str(), arrow.body.span()))
        }
        Expression::FunctionExpression(func) if !func.r#async && !func.generator => {
            let id = func.params.items.first()?.pattern.get_binding_identifier()?;
            let body = func.body.as_ref()?;
            Some((id.name.as_str(), body.span))
        }
        _ => None,
    }
}

fn object_spreads_and_grows_accumulator(
    obj: &oxc_ast::ast::ObjectExpression<'_>,
    acc_name: &str,
) -> bool {
    let spreads_acc = obj.properties.iter().any(|p| {
        matches!(
            p,
            ObjectPropertyKind::SpreadProperty(sp)
                if matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
        )
    });
    let grows_keys = obj.properties.iter().any(|p| match p {
        ObjectPropertyKind::ObjectProperty(prop) => prop.computed,
        ObjectPropertyKind::SpreadProperty(sp) => {
            !matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
                && !matches!(unwrap_expr(&sp.argument), Expression::ObjectExpression(_))
        }
    });
    spreads_acc && grows_keys
}

fn array_spreads_and_grows_accumulator(
    arr: &oxc_ast::ast::ArrayExpression<'_>,
    acc_name: &str,
) -> bool {
    let spreads_acc = arr.elements.iter().any(|e| {
        matches!(
            e,
            oxc_ast::ast::ArrayExpressionElement::SpreadElement(sp)
                if matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
        )
    });
    let grows_elems = arr.elements.iter().any(|e| match e {
        oxc_ast::ast::ArrayExpressionElement::SpreadElement(sp) => {
            !matches!(unwrap_expr(&sp.argument), Expression::Identifier(id) if id.name == acc_name)
        }
        oxc_ast::ast::ArrayExpressionElement::Elision(_) => false,
        _ => true,
    });
    spreads_acc && grows_elems
}

// ---------------------------------------------------------------------------
// 2. `no-json-parse-stringify-clone` (with `Autofix` -> `structuredClone(x)`)
// ---------------------------------------------------------------------------

pub(super) fn check_no_json_parse_stringify_clone(
    path: &Path,
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_json_method_call(call, "parse") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::CallExpression(stringify_call) = unwrap_expr(first_arg) else {
        return;
    };
    if !is_json_method_call(stringify_call, "stringify") {
        return;
    }

    // Skip if replacer is a function or array expression
    if let Some(replacer) = stringify_call
        .arguments
        .get(1)
        .and_then(Argument::as_expression)
        && matches!(
            unwrap_expr(replacer),
            Expression::ArrowFunctionExpression(_)
                | Expression::FunctionExpression(_)
                | Expression::ArrayExpression(_)
        )
    {
        return;
    }
    // Skip if reviver is a function expression
    if let Some(reviver) = call.arguments.get(1).and_then(Argument::as_expression)
        && matches!(
            unwrap_expr(reviver),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        )
    {
        return;
    }

    if is_inside_snapshot_or_serialize_helper(semantic, node_id) {
        return;
    }
    if is_assigned_to_normalization_binding(semantic, node_id) {
        return;
    }
    if is_catch_param_round_trip(semantic, node_id, stringify_call) {
        return;
    }
    if is_inside_nextjs_page_props(path, semantic, node_id) {
        return;
    }

    let Some(cloned_arg) = stringify_call
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return;
    };
    let cloned_text = cloned_arg.span().source_text(semantic.source_text()).trim();

    let span = span_to_byte_span(call.span);
    let has_custom_replacer_or_reviver = call.arguments.len() > 1
        || stringify_call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(|r| !matches!(unwrap_expr(r), Expression::NullLiteral(_)));

    let autofix = (!has_custom_replacer_or_reviver && !cloned_text.is_empty()).then(|| {
        AutofixPatch::replace(
            format!(
                "Replace `JSON.parse(JSON.stringify(...))` with `structuredClone({cloned_text})`"
            ),
            span,
            format!("structuredClone({cloned_text})"),
        )
    });

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site_with_fix(
        out,
        RuleId::NoJsonParseStringifyClone,
        subject_name,
        "noJsonParseStringifyClone",
        "JSON.parse",
        "`JSON.parse(JSON.stringify(x))` deep-clones by re-serializing: it is slow on large objects and silently drops `undefined`, functions, `Date`/`Map`/`Set`, and cyclic references. Use `structuredClone(x)`.".to_string(),
        line_starts,
        call.span,
        autofix,
    );
}

fn is_json_method_call(call: &CallExpression<'_>, method: &str) -> bool {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return false;
    };
    mem.property.name == method
        && matches!(
            unwrap_expr(&mem.object),
            Expression::Identifier(id) if id.name == "JSON"
        )
}

fn is_inside_snapshot_or_serialize_helper(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let bound_name: Option<String> = match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                func.id.as_ref().map(|id| id.name.to_string()).or_else(|| {
                    if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(anc_id)
                    {
                        decl.id
                            .get_binding_identifier()
                            .map(|id| id.name.to_string())
                    } else {
                        None
                    }
                })
            }
            AstKind::ArrowFunctionExpression(_) => {
                if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(anc_id) {
                    decl.id
                        .get_binding_identifier()
                        .map(|id| id.name.to_string())
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(name) = bound_name {
            if is_component_name(&name) {
                return false;
            }
            let lower = name.to_ascii_lowercase();
            return lower.contains("snapshot")
                || lower.contains("serializ")
                || lower.contains("tojson")
                || lower.contains("jsonsafe");
        }
    }
    false
}

fn is_assigned_to_normalization_binding(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().parent_kind(node_id)
        && let Some(id) = decl.id.get_binding_identifier()
    {
        let lower = id.name.to_ascii_lowercase();
        return lower.contains("normaliz") || lower.contains("normalis");
    }
    false
}

fn is_catch_param_round_trip(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    stringify_call: &CallExpression<'_>,
) -> bool {
    let Some(arg) = stringify_call
        .arguments
        .first()
        .and_then(Argument::as_expression)
    else {
        return false;
    };
    let Expression::Identifier(arg_id) = unwrap_expr(arg) else {
        return false;
    };
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => {
                if f.params.items.iter().any(|p| {
                    p.pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                }) {
                    return false;
                }
            }
            AstKind::ArrowFunctionExpression(a) => {
                if a.params.items.iter().any(|p| {
                    p.pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                }) {
                    return false;
                }
            }
            AstKind::CatchClause(catch_clause) => {
                if let Some(param) = &catch_clause.param
                    && param
                        .pattern
                        .get_binding_identifier()
                        .is_some_and(|id| id.name == arg_id.name)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_inside_nextjs_page_props(path: &Path, semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let norm = path.to_string_lossy().replace('\\', "/");
    if (!norm.contains("/pages/") && !norm.starts_with("pages/")) || norm.contains("pages/api") {
        return false;
    }
    is_inside_nextjs_server_data_function(semantic, node_id)
}

fn is_inside_nextjs_server_data_function(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(f) => {
                if let Some(id) = &f.id
                    && matches!(
                        id.name.as_str(),
                        "getServerSideProps" | "getStaticProps" | "getStaticPaths"
                    )
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && matches!(
                        id.name.as_str(),
                        "getServerSideProps" | "getStaticProps" | "getStaticPaths"
                    )
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 3. `js-flatmap-filter`, `js-combine-iterations`, `js-min-max-loop`, `js-length-check-first`
// ---------------------------------------------------------------------------

pub(super) fn check_js_flatmap_filter(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(outer_mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if outer_mem.property.name != "filter" {
        return;
    }
    let Some(filter_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    if !is_boolean_or_identity_filter(unwrap_expr(filter_arg)) {
        return;
    }
    let Expression::CallExpression(inner_call) = unwrap_expr(&outer_mem.object) else {
        return;
    };
    let Expression::StaticMemberExpression(inner_mem) = unwrap_expr(&inner_call.callee) else {
        return;
    };
    if inner_mem.property.name != "map" {
        return;
    }
    if is_small_or_bounded_array_receiver(unwrap_expr(&inner_mem.object)) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsFlatmapFilter,
        subject_name,
        "jsFlatmapFilter",
        "map.filter",
        "This .map().filter(Boolean) chain creates an intermediate array and traverses it again; if this is a measured hot path, combine the transform and truthy check with .reduce() or for...of".to_string(),
        line_starts,
        call.span,
    );
}

fn is_boolean_or_identity_filter(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == "Boolean",
        Expression::ArrowFunctionExpression(arrow) => {
            let Some(first_param) = arrow.params.items.first() else {
                return false;
            };
            let Some(param_id) = first_param.pattern.get_binding_identifier() else {
                return false;
            };
            match &arrow.body {
                ArrowFunctionBody::FunctionBody(body) => {
                    if body.statements.len() != 1 {
                        return false;
                    }
                    match &body.statements[0] {
                        Statement::ReturnStatement(ret) => {
                            ret.argument.as_ref().is_some_and(|arg| {
                                is_identity_expr(unwrap_expr(arg), param_id.name.as_str())
                            })
                        }
                        Statement::ExpressionStatement(expr_stmt) => is_identity_expr(
                            unwrap_expr(&expr_stmt.expression),
                            param_id.name.as_str(),
                        ),
                        _ => false,
                    }
                }
                ArrowFunctionBody::Identifier(id) => id.name == param_id.name,
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_identity_expr(expr: &Expression<'_>, param_name: &str) -> bool {
    match expr {
        Expression::Identifier(id) => id.name == param_name,
        Expression::UnaryExpression(u1) if u1.operator == UnaryOperator::LogicalNot => {
            if let Expression::UnaryExpression(u2) = unwrap_expr(&u1.argument)
                && u2.operator == UnaryOperator::LogicalNot
                && let Expression::Identifier(id) = unwrap_expr(&u2.argument)
            {
                id.name == param_name
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_small_or_bounded_array_receiver(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::ArrayExpression(arr) => {
            !arr.elements.is_empty()
                && arr.elements.len() <= 9
                && arr
                    .elements
                    .iter()
                    .all(|e| !matches!(e, oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)))
        }
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
                && matches!(
                    mem.property.name.as_str(),
                    "split" | "slice" | "values" | "keys" | "entries"
                )
                && !matches!(unwrap_expr(&mem.object), Expression::Identifier(id) if id.name == "Object")
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

pub(super) fn check_js_combine_iterations(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    covered_chain_spans: &mut HashSet<Span>,
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(outer_mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let outer_method = outer_mem.property.name.as_str();
    if !CHAINABLE_ITERATION_METHODS.contains(&outer_method) {
        return;
    }
    let Expression::CallExpression(inner_call) = unwrap_expr(&outer_mem.object) else {
        return;
    };
    let Expression::StaticMemberExpression(inner_mem) = unwrap_expr(&inner_call.callee) else {
        return;
    };
    let inner_method = inner_mem.property.name.as_str();
    if !CHAINABLE_ITERATION_METHODS.contains(&inner_method) {
        return;
    }

    if covered_chain_spans.contains(&call.span) {
        covered_chain_spans.insert(inner_call.span);
        return;
    }
    if outer_method == "filter"
        && call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|e| is_boolean_or_identity_filter(unwrap_expr(e)))
    {
        return;
    }
    if inner_method == "filter"
        && inner_call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|e| is_boolean_or_identity_filter(unwrap_expr(e)))
    {
        return;
    }
    if is_small_or_bounded_array_receiver(unwrap_expr(&inner_mem.object)) {
        return;
    }

    covered_chain_spans.insert(inner_call.span);
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsCombineIterations,
        subject_name,
        "jsCombineIterations",
        &format!("{inner_method}.{outer_method}"),
        format!(
            "This loops over your list twice because .{inner_method}().{outer_method}() makes two passes, so do it in one pass with .reduce() or a for...of loop"
        ),
        line_starts,
        call.span,
    );
}

pub(super) fn check_js_min_max_loop(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "sort" && mem.property.name != "toSorted" {
        return;
    }
    let Some(comp_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    if !is_numeric_sort_comparator(unwrap_expr(comp_arg), semantic.source_text()) {
        return;
    }

    let parent_kind = semantic.nodes().parent_kind(node_id);
    let is_indexed_zero = match parent_kind {
        AstKind::ComputedMemberExpression(comp) => {
            matches!(unwrap_expr(&comp.expression), Expression::NumericLiteral(n) if n.value == 0.0)
        }
        AstKind::CallExpression(parent_call) => {
            if let Expression::StaticMemberExpression(parent_mem) = unwrap_expr(&parent_call.callee)
                && parent_mem.property.name == "at"
                && let Some(arg) = parent_call
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
            {
                matches!(unwrap_expr(arg), Expression::NumericLiteral(n) if n.value == 0.0)
            } else {
                false
            }
        }
        _ => false,
    };
    if !is_indexed_zero {
        return;
    }

    let parent_span = semantic
        .nodes()
        .get_node(semantic.nodes().parent_id(node_id))
        .span();
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsMinMaxLoop,
        subject_name,
        "jsMinMaxLoop",
        mem.property.name.as_str(),
        "Sorting the entire array just to read the minimum or maximum element is O(n log n); use `Math.min`/`Math.max` or a single-pass loop instead.".to_string(),
        line_starts,
        parent_span,
    );
}

fn is_numeric_sort_comparator(expr: &Expression<'_>, source: &str) -> bool {
    let Expression::ArrowFunctionExpression(arrow) = expr else {
        return false;
    };
    if arrow.params.items.len() != 2 {
        return false;
    }
    let body_text = arrow.body.span().source_text(source);
    body_text.contains('-')
}

pub(super) fn check_js_length_check_first(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "every" {
        return;
    }
    let Some(cb_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::ArrowFunctionExpression(arrow) = unwrap_expr(cb_arg) else {
        return;
    };
    if arrow.params.items.len() < 2 {
        return;
    }
    let Some(idx_param) = arrow.params.items[1].pattern.get_binding_identifier() else {
        return;
    };
    let body_text = arrow.body.span().source_text(semantic.source_text());
    if !body_text.contains(&format!("[{}]", idx_param.name))
        || (!body_text.contains("===") && !body_text.contains("=="))
    {
        return;
    }

    // Check if an enclosing logical `&&` or earlier `if` in the function already checks `.length`
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        match semantic.nodes().kind(anc_id) {
            AstKind::LogicalExpression(log) if log.operator == LogicalOperator::And => {
                if log
                    .left
                    .span()
                    .source_text(semantic.source_text())
                    .contains(".length")
                {
                    return;
                }
            }
            AstKind::Function(f) => {
                if let Some(b) = &f.body
                    && b.span
                        .source_text(semantic.source_text())
                        .get(..(call.span.start.saturating_sub(b.span.start)) as usize)
                        .is_some_and(|s| s.contains(".length"))
                {
                    return;
                }
                break;
            }
            AstKind::ArrowFunctionExpression(a) => {
                let b_span = a.body.span();
                if call.span.start >= b_span.start
                    && b_span
                        .source_text(semantic.source_text())
                        .get(..(call.span.start - b_span.start) as usize)
                        .is_some_and(|s| s.contains(".length"))
                {
                    return;
                }
                break;
            }
            _ => {}
        }
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsLengthCheckFirst,
        subject_name,
        "jsLengthCheckFirst",
        "every",
        "Comparing arrays element-by-element with `.every()` without checking `a.length === b.length` first does unnecessary work when lengths differ.".to_string(),
        line_starts,
        call.span,
    );
}


// ---------------------------------------------------------------------------
// 6. `js-tosorted-immutable` & `js-early-exit`
// ---------------------------------------------------------------------------

pub(super) fn check_js_tosorted_immutable(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    let method = mem.property.name.as_str();
    let immutable_method = match method {
        "sort" => "toSorted",
        "reverse" => "toReversed",
        _ => return,
    };

    let receiver_expr: Option<&Expression<'_>> = match unwrap_expr(&mem.object) {
        Expression::ArrayExpression(arr) if arr.elements.len() == 1 => {
            if let oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) = &arr.elements[0] {
                Some(&spread.argument)
            } else {
                None
            }
        }
        Expression::CallExpression(inner_call) if inner_call.arguments.is_empty() => {
            match unwrap_expr(&inner_call.callee) {
                Expression::StaticMemberExpression(inner_mem)
                    if matches!(inner_mem.property.name.as_str(), "slice" | "concat") =>
                {
                    Some(&inner_mem.object)
                }
                _ => None,
            }
        }
        Expression::CallExpression(inner_call) if inner_call.arguments.len() == 1 => {
            if let Expression::StaticMemberExpression(inner_mem) = unwrap_expr(&inner_call.callee)
                && inner_mem.property.name == "from"
                && matches!(unwrap_expr(&inner_mem.object), Expression::Identifier(id) if id.name == "Array")
            {
                inner_call.arguments[0].as_expression()
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(recv) = receiver_expr else {
        return;
    };
    let source = semantic.source_text();
    let recv_text = recv.span().source_text(source).trim();
    let args_text = source
        .get(mem.property.span.end as usize..call.span.end as usize)
        .unwrap_or("()");
    let replacement = format!("{recv_text}.{immutable_method}{args_text}");
    let patch = AutofixPatch::replace(
        format!("Replace copy + `.{method}()` with `.{immutable_method}()`"),
        span_to_byte_span(call.span),
        replacement,
    );
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site_with_fix(
        out,
        RuleId::JsTosortedImmutable,
        subject_name,
        "jsTosortedImmutable",
        immutable_method,
        format!(
            "Prefer `{recv_text}.{immutable_method}(...)` over copying the array before `.{method}()`."
        ),
        line_starts,
        call.span,
        Some(patch),
    );
}

pub(super) fn check_js_early_exit(
    node_id: NodeId,
    if_stmt: &IfStatement<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    // Only report on the outermost `IfStatement` that contains >= 3 nested `if` levels
    if semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .any(|anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::IfStatement(_)))
    {
        return;
    }
    if nested_if_depth(if_stmt) < 3 {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::JsEarlyExit,
        subject_name,
        "jsEarlyExit",
        "if",
        "Deeply nested `if` statements can be flattened with guard clauses and early returns."
            .to_string(),
        line_starts,
        if_stmt.span,
    );
}

fn nested_if_depth(if_stmt: &IfStatement<'_>) -> usize {
    1 + statement_max_if_depth(&if_stmt.consequent)
}

fn statement_max_if_depth(stmt: &Statement<'_>) -> usize {
    match stmt {
        Statement::IfStatement(inner) => nested_if_depth(inner),
        Statement::BlockStatement(blk) => blk
            .body
            .iter()
            .map(statement_max_if_depth)
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}
