//! TanStack Form (`tanstack-form-*`), TanStack Table (`tanstack-table-*`), and
//! TanStack Virtual (`tanstack-virtual-*`) single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use oxc_ast::{
    AstKind,
    ast::{Argument, CallExpression, Expression, JSXAttributeValue, ObjectPropertyKind},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{
    extract_callee_name, find_jsx_attr, get_jsx_element_name, property_key_name, push_site,
};
use crate::{
    ir::{
        ByteSpan,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::jsx_has_spread_attr,
    rules::RuleId,
};

pub(crate) fn check_tanstack_jsx_opening(
    semantic: &Semantic<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);

    // 1. `tanstack-form-on-submit-requires-prevent-default`
    if tag_name == "form"
        && let Some(on_submit_attr) = find_jsx_attr(&opening.attributes, "onSubmit")
        && let Some(JSXAttributeValue::ExpressionContainer(cont)) = &on_submit_attr.value
        && let Some(expr) = cont.expression.as_expression()
        && is_tanstack_form_submit_without_prevent_default(semantic, expr)
    {
        push_site(
            sites,
            RuleId::TanstackFormOnSubmitRequiresPreventDefault,
            subject_name.clone(),
            "tanstackFormOnSubmitRequiresPreventDefault",
            "onSubmit",
            "`<form onSubmit>` calls `form.handleSubmit()` without `event.preventDefault()`, causing a full-page browser submit.".to_string(),
            loc_from_line_starts(line_starts, on_submit_attr.span.start),
            ByteSpan {
                start: on_submit_attr.span.start,
                end: on_submit_attr.span.end,
            },
        );
    }

    // 3. `tanstack-virtual-measure-element-requires-data-index`
    let has_spread = jsx_has_spread_attr(&opening.attributes);
    if !has_spread
        && let Some(ref_attr) = find_jsx_attr(&opening.attributes, "ref")
        && ref_is_virtualizer_measure_element(semantic, ref_attr)
        && find_jsx_attr(&opening.attributes, "data-index").is_none()
    {
        push_site(
            sites,
            RuleId::TanstackVirtualMeasureElementRequiresDataIndex,
            subject_name.clone(),
            "tanstackVirtualMeasureElementRequiresDataIndex",
            &tag_name,
            format!(
                "`<{tag_name}>` uses `measureElement` ref without `data-index={{virtualItem.index}}`."
            ),
            loc_from_line_starts(line_starts, opening.span.start),
            ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
        );
    }
}

fn is_tanstack_form_submit_without_prevent_default(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => mem.property.name == "handleSubmit",
        Expression::ArrowFunctionExpression(arrow) => {
            let span = arrow.body.span();
            let text = span.source_text(semantic.source_text());
            text.contains(".handleSubmit(") && !text.contains(".preventDefault(")
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            let text = body.span.source_text(semantic.source_text());
            text.contains(".handleSubmit(") && !text.contains(".preventDefault(")
        }
        Expression::Identifier(id) => {
            if let Some(ref_id) = id.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                let decl_span = semantic.nodes().get_node(decl_id).span();
                let text = decl_span.source_text(semantic.source_text());
                return text.contains(".handleSubmit(") && !text.contains(".preventDefault(");
            }
            false
        }
        _ => false,
    }
}

fn ref_is_virtualizer_measure_element(
    semantic: &Semantic<'_>,
    ref_attr: &oxc_ast::ast::JSXAttribute<'_>,
) -> bool {
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &ref_attr.value else {
        return false;
    };
    let Some(expr) = cont.expression.as_expression() else {
        return false;
    };
    let text = expr.span().source_text(semantic.source_text());
    text.contains("measureElement")
}

pub(crate) fn check_tanstack_table_call_expression(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subj_id: Option<NodeId>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(callee_name) = extract_callee_name(&call.callee) else {
        return;
    };

    // 2. `tanstack-table-no-unstable-data-or-columns`
    if matches!(callee_name, "useReactTable" | "createReactTable")
        && let Some(sid) = subj_id
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && let Expression::ObjectExpression(obj) = first_arg.without_parentheses()
    {
        let subj_span = semantic.nodes().get_node(sid).span();
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(key) = property_key_name(&p.key) else {
                continue;
            };
            if matches!(key.as_str(), "data" | "columns")
                && is_unstable_table_input(semantic, &p.value, subj_span)
            {
                push_site(
                    sites,
                    RuleId::TanstackTableNoUnstableDataOrColumns,
                    subject_name.clone(),
                    "tanstackTableNoUnstableDataOrColumns",
                    &key,
                    format!(
                        "`useReactTable` option `{key}` is recreated on every render; memoize `{key}` with `useMemo`/`useState` or hoist it to module scope."
                    ),
                    loc_from_line_starts(line_starts, p.span.start),
                    ByteSpan {
                        start: p.span.start,
                        end: p.span.end,
                    },
                );
                break;
            }
        }
    }
}

fn is_unstable_table_input(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    subj_span: oxc_span::Span,
) -> bool {
    match expr.without_parentheses() {
        Expression::ArrayExpression(_) => true,
        Expression::CallExpression(call) => {
            let Some(name) = extract_callee_name(&call.callee) else {
                return false;
            };
            matches!(
                name,
                "filter"
                    | "map"
                    | "flatMap"
                    | "slice"
                    | "concat"
                    | "toSorted"
                    | "values"
                    | "keys"
                    | "entries"
            )
        }
        Expression::Identifier(id) => {
            let Some(ref_id) = id.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let decl_node = semantic.nodes().get_node(decl_id);
            if !subj_span.contains_inclusive(decl_node.span()) {
                return false;
            }
            if let AstKind::VariableDeclarator(decl) = decl_node.kind()
                && let Some(init) = &decl.init
            {
                return match init.without_parentheses() {
                    Expression::ArrayExpression(_) => true,
                    Expression::CallExpression(c) => {
                        let Some(name) = extract_callee_name(&c.callee) else {
                            return false;
                        };
                        matches!(
                            name,
                            "filter" | "map" | "flatMap" | "slice" | "concat" | "toSorted"
                        )
                    }
                    _ => false,
                };
            }
            false
        }
        _ => false,
    }
}
