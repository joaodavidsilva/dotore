//! Angular RxJS teardown, nested `.subscribe()`, `effect()` signal writes,
//! `ChangeDetectionStrategy.OnPush`, constructor purity, and `ElementRef.nativeElement` DOM mutation rules.

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; Angular rules match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentTarget, CallExpression, Class, ClassElement, Expression,
        MethodDefinitionKind, ObjectExpression, ObjectPropertyKind, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::SemanticRuleSite,
    rules::RuleId,
};

use super::{
    angular_class_decorator_kind, callee_ident_name, check_component_decorator_metadata,
    enclosing_subject_name, extract_signal_receiver_name, prop_key_str, push_angular_site,
};
pub(super) fn check_angular_class_decorators_and_constructor(
    semantic: &Semantic<'_>,
    cls: &Class<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(decorator_kind) = angular_class_decorator_kind(cls) else {
        return;
    };
    let class_name = cls.id.as_ref().map(|id| id.name.to_string());

    for dec in &cls.decorators {
        let Expression::CallExpression(call) = dec.expression.without_parentheses() else {
            continue;
        };
        if callee_ident_name(&call.callee) != Some("Component") {
            continue;
        }
        let Some(Argument::ObjectExpression(obj)) = call.arguments.first() else {
            continue;
        };
        check_component_decorator_metadata(
            dec.span,
            obj,
            class_name.as_deref(),
            source,
            line_starts,
            sites,
        );
    }

    if matches!(
        decorator_kind,
        "Component" | "Directive" | "Injectable" | "Pipe"
    ) {
        for elem in &cls.body.body {
            let ClassElement::MethodDefinition(method) = elem else {
                continue;
            };
            if method.kind == MethodDefinitionKind::Constructor
                && let Some(body) = &method.value.body
            {
                check_constructor_statements(
                    semantic,
                    &body.statements,
                    class_name.as_deref(),
                    source,
                    line_starts,
                    sites,
                );
            }
        }
    }
}

fn check_constructor_statements(
    semantic: &Semantic<'_>,
    statements: &[Statement<'_>],
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for stmt in statements {
        let stmt_span = stmt.span();
        if matches!(
            stmt,
            Statement::ForStatement(_)
                | Statement::ForOfStatement(_)
                | Statement::ForInStatement(_)
                | Statement::WhileStatement(_)
                | Statement::DoWhileStatement(_)
        ) {
            push_angular_site(
                sites,
                RuleId::AngularNoWorkInConstructor,
                class_name.map(ToOwned::to_owned),
                "angularNoWorkInConstructor",
                "constructor".to_string(),
                "Avoid heavy loops inside `constructor()`; move initialization logic to `ngOnInit()` or `computed()`.".to_string(),
                stmt_span,
                line_starts,
                None,
            );
            continue;
        }

        if let Some((call_span, target_name, reason)) =
            find_impure_constructor_call_in_span(semantic, stmt_span, source)
        {
            push_angular_site(
                sites,
                RuleId::AngularNoWorkInConstructor,
                class_name.map(ToOwned::to_owned),
                "angularNoWorkInConstructor",
                target_name,
                reason,
                call_span,
                line_starts,
                None,
            );
        }
    }
}

fn find_impure_constructor_call_in_span(
    semantic: &Semantic<'_>,
    stmt_span: Span,
    source: &str,
) -> Option<(Span, String, String)> {
    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if call.span.start < stmt_span.start || call.span.end > stmt_span.end {
            continue;
        }
        if let Some((target, reason)) = classify_impure_constructor_call(call, source) {
            return Some((call.span, target, reason));
        }
    }
    None
}

fn classify_impure_constructor_call(
    call: &CallExpression<'_>,
    source: &str,
) -> Option<(String, String)> {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            if matches!(id.name.as_str(), "fetch" | "setInterval" | "setTimeout") {
                return Some((
                    id.name.to_string(),
                    format!(
                        "Avoid calling `{}(...)` inside `constructor()`; move side effects and network requests to `ngOnInit()`.",
                        id.name
                    ),
                ));
            }
        }
        Expression::StaticMemberExpression(mem) => {
            let prop = mem.property.name.as_str();
            let obj_text = source
                .get(mem.object.span().start as usize..mem.object.span().end as usize)
                .unwrap_or_default()
                .trim();

            if prop == "subscribe" {
                let is_http_or_fetch = obj_text.contains("http.")
                    || obj_text.contains("Http")
                    || obj_text.contains(".get(")
                    || obj_text.contains(".post(")
                    || obj_text.contains(".put(")
                    || obj_text.contains(".delete(")
                    || obj_text.contains(".fetch");
                let has_take_until_destroyed = obj_text.contains("takeUntilDestroyed");
                if is_http_or_fetch || !has_take_until_destroyed {
                    let target = extract_stream_target_name(&mem.object, source);
                    return Some((
                        target,
                        "Avoid starting subscriptions or HTTP requests inside `constructor()`; move stream subscriptions to `ngOnInit()` or use `toSignal()`.".to_string(),
                    ));
                }
            }

            if (obj_text == "this.http" || obj_text.ends_with(".http") || obj_text == "http")
                && matches!(
                    prop,
                    "get" | "post" | "put" | "delete" | "patch" | "request" | "head"
                )
            {
                return Some((
                    format!("http.{prop}"),
                    format!(
                        "Avoid triggering `http.{prop}(...)` inside `constructor()`; move HTTP calls to `ngOnInit()` or a declarative data stream."
                    ),
                ));
            }

            if matches!(obj_text, "localStorage" | "sessionStorage" | "document")
                || (obj_text == "window" && prop == "addEventListener")
            {
                return Some((
                    format!("{obj_text}.{prop}"),
                    format!(
                        "Avoid `{obj_text}.{prop}(...)` inside `constructor()`; browser globals break SSR and belong in `ngOnInit()` or `afterNextRender()`."
                    ),
                ));
            }
        }
        _ => {}
    }
    None
}

pub(super) fn is_angular_effect_call(call: &CallExpression<'_>) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => id.name == "effect",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "effect"
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::ThisExpression(_)
                )
        }
        _ => false,
    }
}

pub(super) fn check_signal_write_in_effect(
    semantic: &Semantic<'_>,
    effect_node_id: NodeId,
    effect_call: &CallExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = effect_call.arguments.first() else {
        return;
    };
    let cb_span = first_arg.span();
    let subj = enclosing_subject_name(semantic, effect_node_id);
    let mut found_write = false;

    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(inner_call) = node.kind() else {
            continue;
        };
        if inner_call.span.start <= cb_span.start || inner_call.span.end > cb_span.end {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = inner_call.callee.without_parentheses()
        else {
            continue;
        };
        let method_name = mem.property.name.as_str();
        if !matches!(method_name, "set" | "update") || inner_call.arguments.len() != 1 {
            continue;
        }
        if is_non_signal_collection_receiver(semantic, &mem.object) {
            continue;
        }
        let Some(sig_name) = extract_signal_receiver_name(&mem.object) else {
            continue;
        };
        found_write = true;
        push_angular_site(
            sites,
            RuleId::AngularNoSignalWriteInEffect,
            subj.clone(),
            "angularNoSignalWriteInEffect",
            sig_name.clone(),
            format!(
                "Do not write to signal `{sig_name}` (`.{method_name}(...)`) inside `effect()`; derive reactive state with `computed(() => ...)` instead."
            ),
            inner_call.span,
            line_starts,
            None,
        );
    }

    if !found_write
        && let Some(Argument::ObjectExpression(opts)) = effect_call.arguments.get(1)
        && has_allow_signal_writes_true(opts)
    {
        push_angular_site(
            sites,
            RuleId::AngularNoSignalWriteInEffect,
            subj,
            "angularNoSignalWriteInEffect",
            "effect".to_string(),
            "Avoid `{ allowSignalWrites: true }` on `effect()`; derive dependent signals with `computed(() => ...)`.".to_string(),
            effect_call.span,
            line_starts,
            None,
        );
    }
}

fn has_allow_signal_writes_true(opts: &ObjectExpression<'_>) -> bool {
    opts.properties.iter().any(|p| {
        if let ObjectPropertyKind::ObjectProperty(prop) = p
            && prop_key_str(&prop.key) == Some("allowSignalWrites")
            && let Expression::BooleanLiteral(b) = prop.value.without_parentheses()
        {
            b.value
        } else {
            false
        }
    })
}

fn is_non_signal_collection_receiver(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    let source = semantic.source_text();
    let text = source
        .get(expr.span().start as usize..expr.span().end as usize)
        .unwrap_or_default()
        .trim();
    if matches!(
        text,
        "localStorage" | "sessionStorage" | "Reflect" | "Headers" | "params" | "headers"
    ) {
        return true;
    }
    let prop_name = match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    let Some(name) = prop_name else {
        return false;
    };
    for (_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::PropertyDefinition(prop) => {
                if prop_key_str(&prop.key) == Some(name)
                    && let Some(val) = &prop.value
                    && is_map_or_set_new_expr(val)
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if decl
                    .id
                    .get_binding_identifier()
                    .is_some_and(|b| b.name == name)
                    && let Some(init) = &decl.init
                    && is_map_or_set_new_expr(init)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_map_or_set_new_expr(expr: &Expression<'_>) -> bool {
    if let Expression::NewExpression(new_expr) = expr.without_parentheses()
        && let Some(name) = callee_ident_name(&new_expr.callee)
    {
        return matches!(
            name,
            "Map" | "Set" | "WeakMap" | "WeakSet" | "Headers" | "URLSearchParams" | "FormControl"
        );
    }
    false
}

pub(super) fn is_subscribe_call(call: &CallExpression<'_>) -> bool {
    matches!(
        call.callee.without_parentheses(),
        Expression::StaticMemberExpression(mem) if mem.property.name == "subscribe"
    )
}

pub(super) fn collect_class_teardown_identifiers(
    semantic: &Semantic<'_>,
) -> HashMap<NodeId, HashSet<String>> {
    let mut map: HashMap<NodeId, HashSet<String>> = HashMap::new();
    let source = semantic.source_text();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::Class(cls) = node.kind() else {
            continue;
        };
        let mut method_spans: HashMap<String, Span> = HashMap::new();
        for elem in &cls.body.body {
            if let ClassElement::MethodDefinition(method_def) = elem
                && let Some(name) = prop_key_str(&method_def.key)
            {
                method_spans.insert(name.to_string(), method_def.span);
            }
        }
        let Some(&ng_on_destroy_span) = method_spans.get("ngOnDestroy") else {
            map.insert(node_id, HashSet::new());
            continue;
        };

        let mut teardown_method_spans = vec![ng_on_destroy_span];
        for (_inner_id, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::CallExpression(call) = inner_node.kind() else {
                continue;
            };
            if call.span.start < ng_on_destroy_span.start || call.span.end > ng_on_destroy_span.end
            {
                continue;
            }
            if let Some(helper_name) = extract_this_method_call_name(&call.callee)
                && let Some(&helper_span) = method_spans.get(helper_name)
            {
                teardown_method_spans.push(helper_span);
            }
        }

        let mut torn_down = HashSet::new();
        for (_inner_id, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::CallExpression(call) = inner_node.kind() else {
                continue;
            };
            let in_teardown_method = teardown_method_spans
                .iter()
                .any(|sp| call.span.start >= sp.start && call.span.end <= sp.end);
            if !in_teardown_method {
                continue;
            }
            let Some(unsub_obj) = extract_unsubscribe_receiver(&call.callee) else {
                continue;
            };
            if let Some(name) = extract_signal_receiver_name(unsub_obj) {
                torn_down.insert(name);
            }
            let recv_text = source
                .get(unsub_obj.span().start as usize..unsub_obj.span().end as usize)
                .unwrap_or_default()
                .trim();
            torn_down.insert(recv_text.to_string());
        }
        map.insert(node_id, torn_down);
    }
    map
}

fn extract_this_method_call_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::StaticMemberExpression(mem)
            if matches!(
                mem.object.without_parentheses(),
                Expression::ThisExpression(_)
            ) =>
        {
            Some(mem.property.name.as_str())
        }
        _ => None,
    }
}

fn extract_unsubscribe_receiver<'a>(callee: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match callee.without_parentheses() {
        Expression::StaticMemberExpression(mem) if mem.property.name == "unsubscribe" => {
            Some(&mem.object)
        }
        Expression::ChainExpression(chain) => {
            if let oxc_ast::ast::ChainElement::StaticMemberExpression(mem) = &chain.expression
                && mem.property.name == "unsubscribe"
            {
                Some(&mem.object)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn check_subscribe_teardown_and_nesting(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    call: &CallExpression<'_>,
    class_teardowns: &HashMap<NodeId, HashSet<String>>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let subj = enclosing_subject_name(semantic, call_node_id);
    let target_name = extract_stream_target_name(&mem.object, source);

    let is_nested = semantic.nodes().ancestor_ids(call_node_id).any(|anc_id| {
        if let AstKind::CallExpression(outer_call) = semantic.nodes().kind(anc_id)
            && is_subscribe_call(outer_call)
        {
            outer_call.arguments.iter().any(|arg| {
                let sp = arg.span();
                call.span.start >= sp.start && call.span.end <= sp.end
            })
        } else {
            false
        }
    });

    if is_nested {
        push_angular_site(
            sites,
            RuleId::AngularNoNestedSubscribe,
            subj.clone(),
            "angularNoNestedSubscribe",
            target_name.clone(),
            format!(
                "Nested `.subscribe()` on `{target_name}`; compose streams with `switchMap`, `mergeMap`, `concatMap`, or `exhaustMap` instead."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    if let Some(enclosing_cls) = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
            AstKind::Class(cls) => Some(cls),
            _ => None,
        })
        && angular_class_decorator_kind(enclosing_cls).is_none()
    {
        return;
    }
    if has_pipe_teardown(&mem.object, source)
        || is_subscription_stored_and_torn_down(semantic, call_node_id, class_teardowns)
    {
        return;
    }
    push_angular_site(
        sites,
        RuleId::AngularRxjsSubscribeRequiresTeardown,
        subj,
        "angularRxjsSubscribeRequiresTeardown",
        target_name.clone(),
        format!(
            "Subscription to `{target_name}` lacks teardown; pipe through `takeUntilDestroyed()`, unsubscribe in `ngOnDestroy()`, or use the template `| async` pipe."
        ),
        call.span,
        line_starts,
        None,
    );
}

fn has_pipe_teardown(receiver: &Expression<'_>, source: &str) -> bool {
    let sp = receiver.span();
    let Some(text) = source.get(sp.start as usize..sp.end as usize) else {
        return false;
    };
    text.contains("takeUntilDestroyed(")
        || text.contains("takeUntil(")
        || text.contains("takeWhile(")
        || text.contains("first(")
        || text.contains("single(")
        || text.contains("last(")
        || text.contains("take(1)")
}

fn is_subscription_stored_and_torn_down(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    class_teardowns: &HashMap<NodeId, HashSet<String>>,
) -> bool {
    let enclosing_class_id = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find(|&anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::Class(_)));
    let Some(cls_id) = enclosing_class_id else {
        return false;
    };
    let Some(torn_down_names) = class_teardowns.get(&cls_id) else {
        return false;
    };
    if torn_down_names.is_empty() {
        return false;
    }

    for anc_id in semantic.nodes().ancestor_ids(call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::AssignmentExpression(assign) => {
                if let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                    && torn_down_names.contains(mem.property.name.as_str())
                {
                    return true;
                }
                if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
                    && torn_down_names.contains(id.name.as_str())
                {
                    return true;
                }
            }
            AstKind::PropertyDefinition(prop) => {
                if let Some(name) = prop_key_str(&prop.key)
                    && torn_down_names.contains(name)
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && torn_down_names.contains(id.name.as_str())
                {
                    return true;
                }
            }
            AstKind::CallExpression(parent_call) => {
                if let Expression::StaticMemberExpression(mem) =
                    parent_call.callee.without_parentheses()
                    && matches!(mem.property.name.as_str(), "add" | "push")
                    && let Some(holder_name) = extract_signal_receiver_name(&mem.object)
                    && torn_down_names.contains(holder_name.as_str())
                {
                    return true;
                }
            }
            AstKind::MethodDefinition(_) | AstKind::Class(_) => break,
            _ => {}
        }
    }
    false
}

fn extract_stream_target_name(expr: &Expression<'_>, source: &str) -> String {
    match expr.without_parentheses() {
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                if mem.property.name == "pipe" {
                    return extract_stream_target_name(&mem.object, source);
                }
                return mem.property.name.to_string();
            }
        }
        Expression::StaticMemberExpression(mem) => {
            return mem.property.name.to_string();
        }
        Expression::Identifier(id) => {
            return id.name.to_string();
        }
        _ => {}
    }
    source
        .get(expr.span().start as usize..expr.span().end as usize)
        .unwrap_or("stream")
        .trim()
        .to_string()
}

pub(super) fn collect_native_element_aliases(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut aliases = HashSet::new();
    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let Some(binding) = decl.id.get_binding_identifier() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if expr_contains_native_element_access(init) {
            aliases.insert(binding.name.to_string());
        }
    }
    aliases
}

fn expr_contains_native_element_access(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "nativeElement" || expr_contains_native_element_access(&mem.object)
        }
        Expression::ChainExpression(chain) => {
            if let oxc_ast::ast::ChainElement::StaticMemberExpression(mem) = &chain.expression {
                mem.property.name == "nativeElement"
                    || expr_contains_native_element_access(&mem.object)
            } else {
                false
            }
        }
        Expression::TSNonNullExpression(non_null) => {
            expr_contains_native_element_access(&non_null.expression)
        }
        Expression::TSAsExpression(ts_as) => expr_contains_native_element_access(&ts_as.expression),
        _ => false,
    }
}

pub(super) fn expr_targets_native_element(
    expr: &Expression<'_>,
    native_vars: &HashSet<String>,
) -> bool {
    if expr_contains_native_element_access(expr) {
        return true;
    }
    match expr.without_parentheses() {
        Expression::Identifier(id) => native_vars.contains(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
        }
        Expression::ComputedMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
        }
        Expression::TSNonNullExpression(non_null) => {
            expr_targets_native_element(&non_null.expression, native_vars)
        }
        Expression::TSAsExpression(ts_as) => {
            expr_targets_native_element(&ts_as.expression, native_vars)
        }
        _ => false,
    }
}

pub(super) fn check_native_element_assignment_mutation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    left: &AssignmentTarget<'_>,
    assign_span: Span,
    native_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let target_prop = match left {
        AssignmentTarget::StaticMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
                .then(|| mem.property.name.to_string())
        }
        AssignmentTarget::ComputedMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
                .then(|| "nativeElement".to_string())
        }
        _ => None,
    };

    if let Some(prop) = target_prop {
        let subj = enclosing_subject_name(semantic, node_id);
        push_angular_site(
            sites,
            RuleId::AngularNoDirectNativeElementMutation,
            subj,
            "angularNoDirectNativeElementMutation",
            prop.clone(),
            format!(
                "Direct DOM mutation on `nativeElement` (`{prop}`); use Angular template bindings, `@HostBinding`, or `Renderer2` instead."
            ),
            assign_span,
            line_starts,
            None,
        );
    }
}

pub(super) fn check_native_element_call_mutation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    native_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    let is_dom_mutating_method = matches!(
        method,
        "add"
            | "remove"
            | "toggle"
            | "replace"
            | "setProperty"
            | "removeProperty"
            | "setAttribute"
            | "removeAttribute"
            | "toggleAttribute"
            | "setAttributeNS"
            | "removeAttributeNS"
            | "appendChild"
            | "removeChild"
            | "insertBefore"
            | "replaceChild"
            | "append"
            | "prepend"
            | "replaceWith"
            | "replaceChildren"
            | "insertAdjacentHTML"
            | "insertAdjacentElement"
            | "insertAdjacentText"
    );
    if !is_dom_mutating_method || !expr_targets_native_element(&mem.object, native_vars) {
        return;
    }
    let subj = enclosing_subject_name(semantic, node_id);
    push_angular_site(
        sites,
        RuleId::AngularNoDirectNativeElementMutation,
        subj,
        "angularNoDirectNativeElementMutation",
        method.to_string(),
        format!(
            "Direct DOM mutation `nativeElement...{method}(...)`; use Angular template bindings or `Renderer2` methods instead."
        ),
        call.span,
        line_starts,
        None,
    );
}
