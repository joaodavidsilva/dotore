//! `correctness` rule family detectors (`no-random-key`, `rendering-conditional-render` with `Autofix`,
//! `web-animation-offsets-valid`, `no-uncontrolled-input`,
//! `no-collapsed-literal-or-chain-as-value`, `no-mutating-array-method-on-prop-or-hook-result` with `Autofix`,
//! `html-no-nested-form`, and `html-no-invalid-table-nesting`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use oxc_ast::{
    AstKind,
    ast::{
        BinaryOperator, Expression, JSXAttributeItem, JSXAttributeValue, JSXOpeningElement,
        LogicalOperator, ObjectPropertyKind, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        dataflow::is_prop,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_custom_hook_name,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

const ALWAYS_FRESH_CALLEES: &[&str] = &[
    "nanoid", "uuid", "uuidv4", "uuidV4", "v4", "cuid", "cuid2", "createId", "ulid", "objectid",
    "ObjectId", "shortid",
];

const NUMERIC_NAME_HINTS: &[&str] = &["count", "length", "total", "size", "num"];

const BOOLEAN_NAME_PREFIXES: &[&str] = &[
    "is", "has", "had", "can", "could", "should", "shall", "will", "would", "did", "does", "was",
    "were", "show", "shows", "hide", "hidden", "allow", "allows", "auto", "enable", "enabled",
    "disable", "disabled", "with", "without",
];

/// Extracts all single-pass `correctness` semantic rule sites and autofixes.
pub(crate) fn extract_correctness_sites(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::JSXOpeningElement(opening) => {
                check_no_random_key(semantic, opening, &subj_name, line_starts, sites);
                check_no_uncontrolled_input(opening, &subj_name, line_starts, sites);
                check_html_nesting_rules(
                    semantic,
                    node_id,
                    opening,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::LogicalExpression(log) => {
                check_rendering_conditional_render(semantic, log, &subj_name, line_starts, sites);
                check_collapsed_literal_in_logical_chain(log, &subj_name, line_starts, sites);
            }
            AstKind::CallExpression(call) => {
                check_mutating_array_method_on_prop(semantic, call, &subj_name, line_starts, sites);
                check_web_animation_offsets(call, &subj_name, line_starts, sites);
                check_no_prevent_default(semantic, node_id, call, &subj_name, line_starts, sites);
                check_no_fetch_response_used_without_status_check(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

fn check_no_random_key(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let Some(ident) = attr.name.as_identifier() else {
            continue;
        };
        if ident.name != "key" {
            continue;
        }
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value else {
            continue;
        };
        let Some(expr) = container.expression.as_expression() else {
            continue;
        };

        if let Some(reason) = find_unstable_key_expression(semantic, expr) {
            sites.push(SemanticRuleSite {
                rule: RuleId::NoRandomKey,
                subject_name: subj_name.clone(),
                message_id: "noRandomKey",
                target_name: reason.clone(),
                message: format!(
                    "JSX `key` uses `{reason}`, which produces a fresh value on every render and forces React to unmount and remount the subtree."
                ),
                loc: loc_from_line_starts(line_starts, attr.span.start),
                span: ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn find_unstable_key_expression(semantic: &Semantic<'_>, expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => None,
        Expression::NewExpression(new_expr) => {
            if matches!(
                new_expr.callee.without_parentheses(),
                Expression::Identifier(id) if id.name == "Date"
            ) {
                Some("new Date()".to_string())
            } else {
                None
            }
        }
        Expression::UpdateExpression(upd) => {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(ident) =
                &upd.argument
                && !is_module_scoped_identifier(semantic, ident)
            {
                return None;
            }
            Some(
                upd.span
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            )
        }
        Expression::AssignmentExpression(assign) => {
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(ident) = &assign.left
                && !is_module_scoped_identifier(semantic, ident)
            {
                return None;
            }
            Some(
                assign
                    .span
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            )
        }
        Expression::CallExpression(call) => {
            if let Some(desc) = classify_always_fresh_call(semantic, call) {
                return Some(desc);
            }
            for arg in &call.arguments {
                if let Some(arg_expr) = arg.as_expression()
                    && let Some(desc) = find_unstable_key_expression(semantic, arg_expr)
                {
                    return Some(desc);
                }
            }
            None
        }
        Expression::BinaryExpression(bin) => find_unstable_key_expression(semantic, &bin.left)
            .or_else(|| find_unstable_key_expression(semantic, &bin.right)),
        Expression::LogicalExpression(log) => find_unstable_key_expression(semantic, &log.left)
            .or_else(|| find_unstable_key_expression(semantic, &log.right)),
        Expression::ConditionalExpression(cond) => {
            find_unstable_key_expression(semantic, &cond.consequent)
                .or_else(|| find_unstable_key_expression(semantic, &cond.alternate))
        }
        Expression::TemplateLiteral(tpl) => tpl
            .expressions
            .iter()
            .find_map(|e| find_unstable_key_expression(semantic, e)),
        _ => None,
    }
}

fn classify_always_fresh_call(
    semantic: &Semantic<'_>,
    call: &oxc_ast::ast::CallExpression<'_>,
) -> Option<String> {
    match call.callee.without_parentheses() {
        Expression::Identifier(ident) => {
            if !ALWAYS_FRESH_CALLEES.contains(&ident.name.as_str()) {
                return None;
            }
            // If `ident` resolves to a same-file non-import declaration (`function createId()`), skip!
            if let Some(ref_id) = ident.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
                && !semantic
                    .scoping()
                    .symbol_flags(sym_id)
                    .contains(SymbolFlags::Import)
            {
                return None;
            }
            Some(format!("{}()", ident.name))
        }
        Expression::StaticMemberExpression(mem) => {
            let Expression::Identifier(obj) = mem.object.without_parentheses() else {
                return None;
            };
            let prop = mem.property.name.as_str();
            let is_fresh = match obj.name.as_str() {
                "Math" => prop == "random",
                "Date" | "performance" => prop == "now",
                "crypto" => matches!(prop, "randomUUID" | "getRandomValues" | "randomBytes"),
                _ => false,
            };
            if is_fresh {
                Some(format!("{}.{prop}()", obj.name))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_module_scoped_identifier(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    !semantic.nodes().ancestor_ids(decl_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        )
    })
}

fn check_rendering_conditional_render(
    semantic: &Semantic<'_>,
    log: &oxc_ast::ast::LogicalExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if log.operator != LogicalOperator::And {
        return;
    }
    if !matches!(
        log.right.without_parentheses(),
        Expression::JSXElement(_) | Expression::JSXFragment(_)
    ) {
        return;
    }

    let left = log.left.without_parentheses();
    let is_length_access = matches!(
        left,
        Expression::StaticMemberExpression(mem) if mem.property.name == "length"
    );
    let is_numeric_ident = if let Expression::Identifier(ident) = left {
        is_numeric_identifier_name(&ident.name) && !resolves_to_boolean_initializer(semantic, ident)
    } else {
        false
    };

    if is_length_access || is_numeric_ident {
        let left_span = left.span();
        let left_text = left_span.source_text(semantic.source_text()).trim();
        let span = ByteSpan {
            start: log.span.start,
            end: log.span.end,
        };
        let loc = loc_from_line_starts(line_starts, log.span.start);
        let patch = AutofixPatch {
            description: format!("Replace `{left_text} &&` with `{left_text} > 0 &&`"),
            edits: vec![ByteEdit {
                file: None,
                span: ByteSpan {
                    start: left_span.start,
                    end: left_span.end,
                },
                replacement: format!("{left_text} > 0"),
            }],
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::RenderingConditionalRender,
            subject_name: subj_name.clone(),
            message_id: "renderingConditionalRender",
            target_name: left_text.to_string(),
            message: "Your users see a stray '0' on screen when a number before `&&` is zero, so use `value > 0`, `Boolean(value)`, or a ternary instead.".to_string(),
            loc,
            span,
            autofix: Some(patch),
        });
    }
}

fn is_numeric_identifier_name(name: &str) -> bool {
    if starts_with_boolean_prefix(name) {
        return false;
    }
    for &hint in NUMERIC_NAME_HINTS {
        if name == hint {
            return true;
        }
        let mut camel = String::with_capacity(hint.len());
        if let Some(first) = hint.chars().next() {
            camel.push(first.to_ascii_uppercase());
            camel.push_str(&hint[first.len_utf8()..]);
        }
        if name.ends_with(&camel)
            || name.ends_with(&format!("_{hint}"))
            || name.ends_with(&format!("_{}", hint.to_ascii_uppercase()))
        {
            return true;
        }
    }
    false
}

fn starts_with_boolean_prefix(name: &str) -> bool {
    for &prefix in BOOLEAN_NAME_PREFIXES {
        if let Some(rest) = name.strip_prefix(prefix)
            && rest
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return true;
        }
        if name.starts_with(&format!("{}_", prefix.to_ascii_uppercase())) {
            return true;
        }
    }
    false
}

fn resolves_to_boolean_initializer(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
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
    let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
        return false;
    };
    is_boolean_result_expr(init)
}

fn is_boolean_result_expr(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::BooleanLiteral(_) => true,
        Expression::UnaryExpression(un) => un.operator == UnaryOperator::LogicalNot,
        Expression::BinaryExpression(bin) => matches!(
            bin.operator,
            BinaryOperator::Equality
                | BinaryOperator::Inequality
                | BinaryOperator::StrictEquality
                | BinaryOperator::StrictInequality
                | BinaryOperator::LessThan
                | BinaryOperator::LessEqualThan
                | BinaryOperator::GreaterThan
                | BinaryOperator::GreaterEqualThan
                | BinaryOperator::In
                | BinaryOperator::Instanceof
        ),
        Expression::CallExpression(call) => {
            matches!(
                call.callee.without_parentheses(),
                Expression::Identifier(id) if id.name == "Boolean"
            )
        }
        _ => false,
    }
}

fn check_no_uncontrolled_input(
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(oxc_ast::ast::JSXElementName::Identifier(ident)) = Some(&opening.name) else {
        return;
    };
    if ident.name != "input" {
        return;
    }

    let mut has_value = false;
    let mut has_default_value = false;
    let mut both_forwarded = true;

    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let Some(name_id) = attr.name.as_identifier() else {
            continue;
        };
        if name_id.name == "value" {
            has_value = true;
            if !matches!(
                &attr.value,
                Some(JSXAttributeValue::ExpressionContainer(c))
                    if matches!(
                        c.expression.as_expression().map(Expression::without_parentheses),
                        Some(Expression::Identifier(_) | Expression::StaticMemberExpression(_))
                    )
            ) {
                both_forwarded = false;
            }
        } else if name_id.name == "defaultValue" {
            has_default_value = true;
            if !matches!(
                &attr.value,
                Some(JSXAttributeValue::ExpressionContainer(c))
                    if matches!(
                        c.expression.as_expression().map(Expression::without_parentheses),
                        Some(Expression::Identifier(_) | Expression::StaticMemberExpression(_))
                    )
            ) {
                both_forwarded = false;
            }
        }
    }

    if has_value && has_default_value && !both_forwarded {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoUncontrolledInput,
            subject_name: subj_name.clone(),
            message_id: "noUncontrolledInput",
            target_name: "input".to_string(),
            message: "`<input>` mixes controlled `value` and uncontrolled `defaultValue` props."
                .to_string(),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }
}

fn check_html_nesting_rules(
    semantic: &Semantic<'_>,
    opening_node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let (tag_name, _, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);
    if is_comp {
        return;
    }
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };
    let loc = loc_from_line_starts(line_starts, opening.span.start);

    // Collect ancestor HTML element names
    let mut parent_tags: Vec<String> = Vec::new();
    for anc_id in semantic.nodes().ancestor_ids(opening_node_id).skip(1) {
        if let AstKind::JSXElement(parent_jsx) = semantic.nodes().kind(anc_id) {
            let (p_name, _, p_comp, _) =
                classify_jsx_element_name(semantic, &parent_jsx.opening_element.name);
            if !p_comp {
                parent_tags.push(p_name);
            }
        }
    }

    // 1. `html-no-nested-form`: `<form>` inside `<form>`
    if tag_name == "form" && parent_tags.iter().any(|p| p == "form") {
        sites.push(SemanticRuleSite {
            rule: RuleId::HtmlNoNestedForm,
            subject_name: subj_name.clone(),
            message_id: "htmlNoNestedForm",
            target_name: "form".to_string(),
            message: "`<form>` cannot be nested inside another `<form>`.".to_string(),
            loc,
            span,
            autofix: None,
        });
    }

    // 2. `html-no-invalid-table-nesting`: `<tr>` whose immediate HTML parent is `<table>`
    if tag_name == "tr" && parent_tags.first().is_some_and(|p| p == "table") {
        sites.push(SemanticRuleSite {
            rule: RuleId::HtmlNoInvalidTableNesting,
            subject_name: subj_name.clone(),
            message_id: "htmlNoInvalidTableNesting",
            target_name: "tr".to_string(),
            message: "`<tr>` cannot be a direct child of `<table>`; wrap rows in `<thead>`, `<tbody>`, or `<tfoot>`.".to_string(),
            loc,
            span,
            autofix: None,
        });
    }
}

fn check_collapsed_literal_in_logical_chain(
    log: &oxc_ast::ast::LogicalExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if log.operator != LogicalOperator::Or {
        return;
    }
    let is_left_equality = matches!(
        log.left.without_parentheses(),
        Expression::BinaryExpression(bin)
            if matches!(
                bin.operator,
                BinaryOperator::Equality
                    | BinaryOperator::StrictEquality
                    | BinaryOperator::Inequality
                    | BinaryOperator::StrictInequality
            )
    );
    let right = log.right.without_parentheses();
    let is_right_non_bool_literal = matches!(
        right,
        Expression::StringLiteral(s) if !s.value.is_empty()
    ) || matches!(
        right,
        Expression::NumericLiteral(n) if n.value != 0.0
    );

    if is_left_equality && is_right_non_bool_literal {
        let r_span = right.span();
        sites.push(SemanticRuleSite {
            rule: RuleId::NoCollapsedLiteralOrChainAsValue,
            subject_name: subj_name.clone(),
            message_id: "noCollapsedLiteralOrChainAsValue",
            target_name: "||".to_string(),
            message:
                "Right-hand literal in `x === a || b` is always truthy; write `x === a || x === b`."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, r_span.start),
            span: ByteSpan {
                start: log.span.start,
                end: log.span.end,
            },
            autofix: None,
        });
    }
}

fn check_mutating_array_method_on_prop(
    semantic: &Semantic<'_>,
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    if !matches!(
        method,
        "sort" | "reverse" | "splice" | "push" | "pop" | "shift" | "unshift"
    ) {
        return;
    }
    let Expression::Identifier(obj_ident) = mem.object.without_parentheses() else {
        return;
    };
    let Some(ref_id) = obj_ident.reference_id.get() else {
        return;
    };
    if is_prop(semantic, ref_id) || is_hook_return_value(semantic, ref_id) {
        let autofix = if matches!(method, "sort" | "reverse") {
            let obj_span = mem.object.span();
            Some(AutofixPatch {
                description: format!(
                    "Clone `{}` (`[...{}].{method}(...)`) before calling `.{method}()`",
                    obj_ident.name, obj_ident.name
                ),
                edits: vec![ByteEdit {
                    file: None,
                    span: ByteSpan {
                        start: obj_span.start,
                        end: obj_span.end,
                    },
                    replacement: format!("[...{}]", obj_ident.name),
                }],
            })
        } else {
            None
        };
        sites.push(SemanticRuleSite {
            rule: RuleId::NoMutatingArrayMethodOnPropOrHookResult,
            subject_name: subj_name.clone(),
            message_id: "noMutatingArrayMethodOnProp",
            target_name: obj_ident.name.to_string(),
            message: format!(
                "Calling `.{method}()` directly on `{}` mutates the array in place; clone the array (`[...{}].{method}(...)`) first.",
                obj_ident.name, obj_ident.name
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix,
        });
    }
}

fn is_hook_return_value(semantic: &Semantic<'_>, ref_id: oxc_semantic::ReferenceId) -> bool {
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return false;
    };
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => is_custom_hook_name(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => is_custom_hook_name(mem.property.name.as_str()),
        _ => false,
    }
}

fn check_web_animation_offsets(
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    if mem.property.name != "animate" {
        return;
    }
    let Some(Expression::ArrayExpression(arr)) = call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
        .map(Expression::without_parentheses)
    else {
        return;
    };

    let mut prev_offset: Option<f64> = None;
    for elem in &arr.elements {
        let Some(Expression::ObjectExpression(obj)) =
            elem.as_expression().map(Expression::without_parentheses)
        else {
            continue;
        };
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("offset") {
                continue;
            }
            let offset_val = match prop.value.without_parentheses() {
                Expression::NumericLiteral(n) => Some(n.value),
                Expression::UnaryExpression(un) if un.operator == UnaryOperator::UnaryNegation => {
                    if let Expression::NumericLiteral(n) = un.argument.without_parentheses() {
                        Some(-n.value)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(val) = offset_val {
                if !(0.0..=1.0).contains(&val) || prev_offset.is_some_and(|prev| val < prev) {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::WebAnimationOffsetsValid,
                        subject_name: subj_name.clone(),
                        message_id: "webAnimationOffsetsValid",
                        target_name: "offset".to_string(),
                        message: "Web Animations keyframe `offset` must be in `[0, 1]` and monotonically non-decreasing.".to_string(),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
                prev_offset = Some(val);
            }
        }
    }
}

fn check_no_prevent_default(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    if mem.property.name != "preventDefault" {
        return;
    }

    let mut should_flag = false;
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::JSXAttribute(attr) => {
                let attr_name = attr.name.as_identifier().map(|id| id.name.as_str());
                if matches!(attr_name, Some("onWheel" | "onTouchStart" | "onTouchMove")) {
                    should_flag = true;
                    break;
                }
                let parent_id = semantic.nodes().parent_id(anc_id);
                if let AstKind::JSXOpeningElement(opening) = semantic.nodes().kind(parent_id) {
                    let (tag_name, _, _, _) = classify_jsx_element_name(semantic, &opening.name);
                    if matches!(tag_name.as_str(), "Link" | "NavLink" | "Form") {
                        should_flag = true;
                        break;
                    }
                }
            }
            AstKind::CallExpression(outer_call) if outer_call.span != call.span => {
                if let Expression::StaticMemberExpression(outer_mem) =
                    outer_call.callee.without_parentheses()
                    && outer_mem.property.name == "addEventListener"
                    && let Some(first_arg) =
                        outer_call.arguments.first().and_then(|a| a.as_expression())
                    && let Expression::StringLiteral(s) = first_arg.without_parentheses()
                    && matches!(
                        s.value.as_str(),
                        Some("wheel" | "mousewheel" | "touchstart" | "touchmove")
                    )
                {
                    let opts_text = outer_call
                        .arguments
                        .get(2)
                        .map(|a| a.span().source_text(semantic.source_text()))
                        .unwrap_or_default();
                    if !opts_text.contains("passive: false") && !opts_text.contains("passive:false")
                    {
                        should_flag = true;
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    if should_flag {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoPreventDefault,
            subject_name: subj_name.clone(),
            message_id: "noPreventDefault",
            target_name: "preventDefault".to_string(),
            message: "Avoid calling `preventDefault()` on framework navigation components or inside passive scroll/touch listeners.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_no_fetch_response_used_without_status_check(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &oxc_ast::ast::CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    if !matches!(method, "json" | "text" | "blob" | "arrayBuffer" | "formData") {
        return;
    }

    let is_unguarded_fetch_res = match mem.object.without_parentheses() {
        Expression::AwaitExpression(aw) => {
            matches!(
                aw.argument.without_parentheses(),
                Expression::CallExpression(c)
                    if matches!(c.callee.without_parentheses(), Expression::Identifier(id) if id.name == "fetch")
            )
        }
        Expression::Identifier(res_ident) => {
            let Some(ref_id) = res_ident.reference_id.get() else {
                return;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
                return;
            };
            let is_fetch_init = decl.init.as_ref().is_some_and(|init| {
                if let Expression::AwaitExpression(aw) = init.without_parentheses()
                    && let Expression::CallExpression(c) = aw.argument.without_parentheses()
                {
                    matches!(c.callee.without_parentheses(), Expression::Identifier(id) if id.name == "fetch")
                } else {
                    false
                }
            });
            if !is_fetch_init {
                return;
            }
            // Check if any enclosing function/block checks `res.ok` or `res.status` before `call.span.start`
            let scope_span = semantic
                .nodes()
                .ancestor_ids(node_id)
                .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
                    AstKind::Function(f) => f.body.as_ref().map(|b| b.span),
                    AstKind::ArrowFunctionExpression(a) => Some(a.body.span()),
                    _ => None,
                })
                .unwrap_or_else(|| Span::new(0, call.span.start));
            let prefix_src = semantic
                .source_text()
                .get(scope_span.start as usize..call.span.start as usize)
                .unwrap_or_default();
            let name = res_ident.name.as_str();
            !prefix_src.contains(&format!("{name}.ok"))
                && !prefix_src.contains(&format!("{name}.status"))
        }
        _ => false,
    };

    if is_unguarded_fetch_res {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoFetchResponseUsedWithoutStatusCheck,
            subject_name: subj_name.clone(),
            message_id: "noFetchResponseUsedWithoutStatusCheck",
            target_name: method.to_string(),
            message: format!(
                "`fetch()` response body is consumed via `.{method}()` without checking `response.ok` or `response.status` first."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}
