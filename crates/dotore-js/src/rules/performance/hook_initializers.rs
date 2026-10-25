//! React hook initializer, scroll transition, and motion value render-phase rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds (#50)"
)]

use oxc_ast::{
    AstKind,
    ast::{Argument, ArrowFunctionBody, CallExpression, Expression, ObjectPropertyKind, Statement},
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags};
use oxc_span::{GetSpan, Span};

use super::{
    CHEAP_CONSTRUCTORS, HIGH_FREQUENCY_DOM_EVENTS, LAYOUT_PROPERTIES, is_react_named_hook_call,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::{is_global_ident, push_semantic_site, resolve_ident_symbol, unwrap_expr},
    rules::RuleId,
};

pub(super) fn check_rerender_transitions_scroll(
    _node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Some((event_name, handler_span)) = extract_high_freq_event_handler(call) else {
        return;
    };
    if handler_has_ref_dedup_guard(handler_span, semantic) {
        return;
    }
    let Some((inner_id, name, set_span)) =
        find_unwrapped_set_state_in_handler(handler_span, semantic)
    else {
        return;
    };

    let subject_name =
        find_enclosing_react_node(semantic, inner_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::RerenderTransitionsScroll,
        subject_name,
        "rerenderTransitionsScroll",
        name,
        format!(
            "This can make scrolling stutter because setState in a \"{event_name}\" handler redraws on every event. Wrap it in startTransition, use useDeferredValue, or keep the value in a ref and throttle with requestAnimationFrame."
        ),
        line_starts,
        set_span,
    );
}

fn extract_high_freq_event_handler<'a>(call: &'a CallExpression<'a>) -> Option<(&'a str, Span)> {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return None;
    };
    if mem.property.name != "addEventListener" {
        return None;
    }
    let event_arg = call.arguments.first().and_then(Argument::as_expression)?;
    let Expression::StringLiteral(event_lit) = unwrap_expr(event_arg) else {
        return None;
    };
    let event_name = event_lit.value.as_str()?;
    if !HIGH_FREQUENCY_DOM_EVENTS.contains(&event_name) {
        return None;
    }
    let handler_arg = call.arguments.get(1).and_then(Argument::as_expression)?;
    let handler_span = match unwrap_expr(handler_arg) {
        Expression::ArrowFunctionExpression(a) => a.body.span(),
        Expression::FunctionExpression(f) => f.body.as_ref()?.span,
        _ => return None,
    };
    Some((event_name, handler_span))
}

fn handler_has_ref_dedup_guard(handler_span: Span, semantic: &Semantic<'_>) -> bool {
    let source = semantic.source_text();
    for (_, n) in semantic.nodes().iter_enumerated() {
        if !handler_span.contains_inclusive(n.span()) {
            continue;
        }
        if let AstKind::IfStatement(if_stmt) = n.kind()
            && if_stmt.test.span().source_text(source).contains(".current")
            && if_stmt
                .consequent
                .span()
                .source_text(source)
                .contains("return")
        {
            return true;
        }
    }
    false
}

fn find_unwrapped_set_state_in_handler<'a>(
    handler_span: Span,
    semantic: &'a Semantic<'a>,
) -> Option<(NodeId, &'a str, Span)> {
    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !handler_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let AstKind::CallExpression(set_call) = inner_node.kind() else {
            continue;
        };
        let Expression::Identifier(callee_id) = unwrap_expr(&set_call.callee) else {
            continue;
        };
        let name = callee_id.name.as_str();
        if !name.starts_with("set") || !name.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase) {
            continue;
        }
        if resolve_ident_symbol(semantic, callee_id).is_none() {
            continue;
        }
        if set_call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .is_none_or(is_constant_setter_arg)
        {
            continue;
        }
        if is_wrapped_in_transition_or_raf(inner_id, semantic) {
            continue;
        }
        return Some((inner_id, name, set_call.span));
    }
    None
}

fn is_wrapped_in_transition_or_raf(node_id: NodeId, semantic: &Semantic<'_>) -> bool {
    semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .any(|anc_id| {
            if let AstKind::CallExpression(anc_call) = semantic.nodes().kind(anc_id)
                && let Expression::Identifier(id) = unwrap_expr(&anc_call.callee)
            {
                matches!(
                    id.name.as_str(),
                    "startTransition" | "requestAnimationFrame" | "requestIdleCallback"
                )
            } else {
                false
            }
        })
}

fn is_constant_setter_arg(expr: &Expression<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::BooleanLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::UnaryExpression(u) => is_constant_setter_arg(&u.argument),
        _ => false,
    }
}

fn is_bound_react_hook_call(
    call: &CallExpression<'_>,
    hook_name: &str,
    semantic: &Semantic<'_>,
) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            if !semantic
                .scoping()
                .symbol_flags(sym_id)
                .contains(SymbolFlags::Import)
            {
                return false;
            }
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::ImportSpecifier(spec) = semantic.nodes().kind(decl_id) {
                spec.imported.name() == hook_name
            } else {
                false
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name != hook_name {
                return false;
            }
            let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) else {
                return false;
            };
            if let Some(sym_id) = resolve_ident_symbol(semantic, obj_id) {
                semantic
                    .scoping()
                    .symbol_flags(sym_id)
                    .contains(SymbolFlags::Import)
            } else {
                obj_id.name == "React"
            }
        }
        _ => false,
    }
}

pub(super) fn check_no_match_media_in_state_initializer(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_bound_react_hook_call(call, "useState", semantic) {
        return;
    }
    let Some(init_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let search_span = match unwrap_expr(init_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            if arrow.r#async {
                return;
            }
            arrow.body.span()
        }
        Expression::FunctionExpression(func) => {
            if func.r#async || func.generator {
                return;
            }
            let Some(b) = &func.body else {
                return;
            };
            b.span
        }
        other => other.span(),
    };

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        if !search_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        let AstKind::CallExpression(mm_call) = inner_node.kind() else {
            continue;
        };
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(inner_id)
            .skip(1)
            .take_while(|&anc_id| {
                search_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
            })
            .any(|anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_nested_fn || !is_global_match_media_call(mm_call, semantic) {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::NoMatchMediaInStateInitializer,
            subject_name,
            "noMatchMediaInStateInitializer",
            "matchMedia",
            "`matchMedia()` in a useState initializer can cause an SSR crash or seed different server and hydration state. Prefer CSS media queries for layout, or use `useSyncExternalStore` with a stable server snapshot.".to_string(),
            line_starts,
            mm_call.span,
        );
        return;
    }
}

fn is_global_match_media_call(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(id) => id.name == "matchMedia" && is_global_ident(semantic, id),
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name != "matchMedia" {
                return false;
            }
            if let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) {
                (obj_id.name == "window" || obj_id.name == "globalThis")
                    && is_global_ident(semantic, obj_id)
            } else {
                false
            }
        }
        _ => false,
    }
}

pub(super) fn check_no_eager_new_in_use_state_initializer(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_named_hook_call(call, "useState") {
        return;
    }
    let Some(init_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::NewExpression(new_expr) = unwrap_expr(init_expr) else {
        return;
    };
    let ctor_name = match unwrap_expr(&new_expr.callee) {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(mem) => mem.property.name.as_str(),
        _ => "constructor",
    };
    if CHEAP_CONSTRUCTORS.contains(&ctor_name) && new_expr.arguments.is_empty() {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    let target_name = format!("new {ctor_name}()");
    push_semantic_site(
        out,
        RuleId::NoEagerNewInUseStateInitializer,
        subject_name,
        "noEagerNewInUseStateInitializer",
        &target_name,
        format!(
            "`new {ctor_name}()` inside `useState(...)` runs on every render; pass a lazy initializer `useState(() => new {ctor_name}(...))` so it only runs on mount."
        ),
        line_starts,
        new_expr.span,
    );
}

pub(super) fn check_no_usememo_simple_expression(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_named_hook_call(call, "useMemo") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Some(expr) = extract_single_return_expr(first_arg).map(unwrap_expr) else {
        return;
    };
    if matches!(
        expr,
        Expression::Identifier(_) | Expression::StaticMemberExpression(_)
    ) {
        return;
    }
    if !is_simple_cheap_expr(expr) {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::NoUsememoSimpleExpression,
        subject_name,
        "noUsememoSimpleExpression",
        "useMemo",
        "This costs more than it saves because useMemo is wrapping a value that's already cheap, so remove the useMemo".to_string(),
        line_starts,
        call.span,
    );
}

fn extract_single_return_expr<'a>(cb_expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match unwrap_expr(cb_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                Some(expr)
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body
                && body.statements.len() == 1
                && let Statement::ReturnStatement(ret) = &body.statements[0]
            {
                ret.argument.as_ref()
            } else {
                None
            }
        }
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            if body.statements.len() == 1
                && let Statement::ReturnStatement(ret) = &body.statements[0]
            {
                ret.argument.as_ref()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_simple_cheap_expr(expr: &Expression<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::BinaryExpression(bin) => {
            is_simple_cheap_expr(&bin.left) && is_simple_cheap_expr(&bin.right)
        }
        Expression::UnaryExpression(u) => is_simple_cheap_expr(&u.argument),
        Expression::StaticMemberExpression(mem) => is_simple_cheap_expr(&mem.object),
        Expression::ConditionalExpression(cond) => {
            is_simple_cheap_expr(&cond.test)
                && is_simple_cheap_expr(&cond.consequent)
                && is_simple_cheap_expr(&cond.alternate)
        }
        _ => false,
    }
}

pub(super) fn check_motion_value_constructor_in_render(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
        return;
    };
    if callee_id.name != "motionValue" {
        return;
    }
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return;
    };
    let in_nested_hook_cb = semantic
        .nodes()
        .ancestor_ids(node_id)
        .skip(1)
        .take_while(|&anc_id| anc_id != subj_id)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        });
    if in_nested_hook_cb {
        return;
    }

    let subject_name = get_subject_name(semantic, subj_id);
    push_semantic_site(
        out,
        RuleId::MotionValueConstructorInRender,
        subject_name,
        "motionValueConstructorInRender",
        "motionValue",
        "motionValue() creates a fresh reactive object during this render. Use useMotionValue() so React preserves the value across renders.".to_string(),
        line_starts,
        call.span,
    );
}

pub(super) fn check_web_animation_keyframes(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "animate" {
        return;
    }
    let recv_text = mem.object.span().source_text(semantic.source_text());
    if !recv_text.contains("document.")
        && !recv_text.contains("querySelector")
        && !recv_text.contains("getElementById")
        && !recv_text.contains(".current")
    {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };

    let mut keyframe_objs = Vec::new();
    match unwrap_expr(first_arg) {
        Expression::ArrayExpression(arr) => {
            for elem in &arr.elements {
                if let Some(Expression::ObjectExpression(obj)) =
                    elem.as_expression().map(unwrap_expr)
                {
                    keyframe_objs.push(obj);
                }
            }
        }
        Expression::ObjectExpression(obj) => keyframe_objs.push(obj),
        _ => {}
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));

    for obj in keyframe_objs {
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Some(raw_name) = prop
                .key
                .static_name()
                .and_then(|n| n.as_str().map(str::to_string))
            else {
                continue;
            };
            let camel = kebab_to_camel(&raw_name);
            if LAYOUT_PROPERTIES.contains(&camel.as_str()) {
                push_semantic_site(
                    out,
                    RuleId::NoLayoutPropertyAnimation,
                    subject_name.clone(),
                    "noLayoutPropertyAnimation",
                    &raw_name,
                    format!(
                        "This Web Animation changes \"{raw_name}\" every frame, forcing layout work. Animate transform or opacity instead."
                    ),
                    line_starts,
                    prop.span,
                );
            }
        }
    }
}

fn kebab_to_camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper_next = false;
    for ch in s.chars() {
        if ch == '-' {
            upper_next = true;
        } else if upper_next {
            out.push(ch.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}
