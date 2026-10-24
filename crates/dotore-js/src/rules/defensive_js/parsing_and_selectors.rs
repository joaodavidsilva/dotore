//! Throwing DOM selector, RegExp, numeric input, URL, and JSON parse rule detectors.

use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    SELECTOR_QUERY_METHODS, THROWING_PARSE_FUNCTIONS, enclosing_function_span,
    get_var_declarator_init, has_nullish_guard_before, is_inside_try_block, resolve_symbol_id,
};
use crate::{ir::SemanticRuleSite, matchers::push_semantic_site, rules::types::RuleId};

// ---------------------------------------------------------------------------
// 10. `no-non-literal-selector-query-without-try-catch`
// ---------------------------------------------------------------------------
pub(super) fn check_no_non_literal_selector_query_without_try_catch(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    if !SELECTOR_QUERY_METHODS.contains(&method) {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if is_safe_selector_argument(semantic, first_arg) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::NoNonLiteralSelectorQueryWithoutTryCatch,
        subj_name.clone(),
        "noNonLiteralSelectorQueryWithoutTryCatch",
        method,
        format!(
            "Calling `.{method}(...)` with a dynamic selector outside `try/catch` and without `CSS.escape(...)` throws a `DOMException` when the selector is malformed."
        ),
        line_starts,
        call.span,
    );
}

fn is_safe_selector_argument(semantic: &Semantic<'_>, arg: &Expression<'_>) -> bool {
    match arg.without_parentheses() {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => {
            if tpl.expressions.is_empty() {
                return true;
            }
            tpl.expressions.iter().all(|e| {
                let src = e.span().source_text(semantic.source_text());
                src.contains("CSS.escape")
            })
        }
        Expression::CallExpression(c) => {
            let src = c.callee.span().source_text(semantic.source_text());
            src.contains("CSS.escape")
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            is_safe_selector_argument(semantic, init)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 17. `no-unescaped-dynamic-string-in-regexp`
// ---------------------------------------------------------------------------
pub(super) fn check_no_unescaped_dynamic_string_in_regexp(
    semantic: &Semantic<'_>,
    new_expr: &NewExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = new_expr.callee.without_parentheses() else {
        return;
    };
    if callee_id.name != "RegExp" {
        return;
    }
    let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if is_escaped_or_static_regexp_arg(semantic, first_arg) {
        return;
    }

    let target = first_arg.span().source_text(semantic.source_text());
    push_semantic_site(
        sites,
        RuleId::NoUnescapedDynamicStringInRegexp,
        subj_name.clone(),
        "noUnescapedDynamicStringInRegexp",
        target,
        "Dynamic string passed to `new RegExp(...)` without escaping regex metacharacters (`escapeRegExp` / `.replace(...)`).".to_string(),
        line_starts,
        new_expr.span,
    );
}

fn is_escaped_or_static_regexp_arg(semantic: &Semantic<'_>, arg: &Expression<'_>) -> bool {
    match arg.without_parentheses() {
        Expression::StringLiteral(_) | Expression::RegExpLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => {
            if tpl.expressions.is_empty() {
                return true;
            }
            tpl.expressions
                .iter()
                .all(|e| is_escaped_or_static_regexp_arg(semantic, e))
        }
        Expression::CallExpression(call) => {
            let src = call.span.source_text(semantic.source_text());
            src.contains("escape") || src.contains(".replace(")
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return false;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return false;
            };
            is_escaped_or_static_regexp_arg(semantic, init)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 18. `no-unguarded-numeric-input-parse`
// ---------------------------------------------------------------------------
pub(super) fn check_no_unguarded_numeric_input_parse(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_numeric_parse = match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "Number" | "parseInt" | "parseFloat")
        }
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.object.without_parentheses(), Expression::Identifier(id) if id.name == "Number")
                && matches!(mem.property.name.as_str(), "parseInt" | "parseFloat")
        }
        _ => false,
    };
    if !is_numeric_parse {
        return;
    }

    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let arg_src = first_arg.span().source_text(semantic.source_text());
    let is_dom_input_value = arg_src.ends_with(".target.value")
        || arg_src.ends_with(".currentTarget.value")
        || matches!(first_arg.without_parentheses(), Expression::Identifier(ident) if {
            resolve_symbol_id(semantic, ident)
                .and_then(|sym_id| get_var_declarator_init(semantic, sym_id))
                .is_some_and(|init| {
                    let s = init.span().source_text(semantic.source_text());
                    s.ends_with(".target.value") || s.ends_with(".currentTarget.value")
                })
        });

    if !is_dom_input_value {
        return;
    }

    // Check if guarded against empty string and `isNaN` in enclosing handler/function
    let scope_span = enclosing_function_span(semantic, node_id);
    let scope_src = scope_span.source_text(semantic.source_text());
    let has_nan_or_empty_guard = scope_src.contains("isNaN(")
        || scope_src.contains("isFinite(")
        || scope_src.contains("=== ''")
        || scope_src.contains("=== \"\"")
        || scope_src.contains(".trim()");

    if !has_nan_or_empty_guard {
        let target = call.callee.span().source_text(semantic.source_text());
        push_semantic_site(
            sites,
            RuleId::NoUnguardedNumericInputParse,
            subj_name.clone(),
            "noUnguardedNumericInputParse",
            target,
            "Parsing `e.target.value` with `Number`/`parseInt`/`parseFloat` without guarding empty strings and `NaN` turns empty input into `0` or `NaN`.".to_string(),
            line_starts,
            call.span,
        );
    }
}

// ---------------------------------------------------------------------------
// 19. `no-unguarded-throwing-parse-call`
// ---------------------------------------------------------------------------
pub(super) fn check_no_unguarded_throwing_parse_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    let name = callee_id.name.as_str();
    if !THROWING_PARSE_FUNCTIONS.contains(&name) {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if matches!(first_arg.without_parentheses(), Expression::StringLiteral(_)) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }
    let scope_src = enclosing_function_span(semantic, node_id).source_text(semantic.source_text());
    if scope_src.contains("chroma.valid") || scope_src.contains("canParse") {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::NoUnguardedThrowingParseCall,
        subj_name.clone(),
        "noUnguardedThrowingParseCall",
        name,
        format!(
            "`{name}(...)` throws on malformed runtime input; wrap the call in `try/catch` or validate the input first."
        ),
        line_starts,
        call.span,
    );
}

pub(super) fn check_no_unguarded_throwing_new_url(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = new_expr.callee.without_parentheses() else {
        return;
    };
    if callee_id.name != "URL" {
        return;
    }
    let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    if matches!(first_arg.without_parentheses(), Expression::StringLiteral(_)) {
        return;
    }
    if is_inside_try_block(semantic, node_id) {
        return;
    }
    let scope_src = enclosing_function_span(semantic, node_id).source_text(semantic.source_text());
    if scope_src.contains("URL.canParse") {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::NoUnguardedThrowingParseCall,
        subj_name.clone(),
        "noUnguardedThrowingParseCall",
        "new URL",
        "`new URL(...)` throws a `TypeError` on malformed URLs; guard with `URL.canParse(...)` or wrap in `try/catch`.".to_string(),
        line_starts,
        new_expr.span,
    );
}

// ---------------------------------------------------------------------------
// 20. `no-unsafe-json-parse`
// ---------------------------------------------------------------------------
#[expect(
    clippy::too_many_arguments,
    reason = "Receives member access AST context and output accumulator"
)]
pub(super) fn check_no_unsafe_json_parse_member(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    access_span: Span,
    object: &Expression<'_>,
    is_optional: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_unguarded_json_parse = match object.without_parentheses() {
        Expression::CallExpression(call) => {
            is_json_parse_call(call) && !is_inside_try_block(semantic, node_id)
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_symbol_id(semantic, ident) else {
                return;
            };
            let Some(init) = get_var_declarator_init(semantic, sym_id) else {
                return;
            };
            let Expression::CallExpression(call) = init.without_parentheses() else {
                return;
            };
            if !is_json_parse_call(call) {
                return;
            }
            !is_inside_try_block(semantic, node_id)
                && !is_optional
                && !has_nullish_guard_before(semantic, access_span.start, ident.name.as_str())
        }
        _ => false,
    };

    if is_unguarded_json_parse {
        push_semantic_site(
            sites,
            RuleId::NoUnsafeJsonParse,
            subj_name.clone(),
            "noUnsafeJsonParse",
            "JSON.parse",
            "Dereferencing `JSON.parse(...)` outside `try/catch` without validating the parsed value throws on malformed JSON or `null` payloads.".to_string(),
            line_starts,
            access_span,
        );
    }
}

fn is_json_parse_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(mem.object.without_parentheses(), Expression::Identifier(id) if id.name == "JSON")
        && mem.property.name == "parse"
}
