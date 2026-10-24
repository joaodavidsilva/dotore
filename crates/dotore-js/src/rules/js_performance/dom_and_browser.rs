//! Browser DOM, event listeners, storage caching/versioning, `flushSync`, and View Transition rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; DOM and browser detectors match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, ImportDeclarationSpecifier, ObjectPropertyKind,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    DOM_MEASUREMENT_NAMES, IMPERATIVE_DOM_MUTATION_NAMES, PASSIVE_EVENT_NAMES,
    collect_callee_identifier_trail,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{ModuleIr, SemanticRuleSite},
    },
    matchers::{
        is_global_ident, push_semantic_site, push_semantic_site_with_fix, resolve_ident_symbol,
        span_to_byte_span, unwrap_expr,
    },
    rules::{AutofixPatch, RuleId},
};

// ---------------------------------------------------------------------------
// 1. `no-sync-xhr` & `no-document-write` & `no-create-object-url-without-revoke`
// ---------------------------------------------------------------------------

pub(super) fn check_no_sync_xhr(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "open" {
        return;
    }
    let Some(third_arg) = call.arguments.get(2).and_then(Argument::as_expression) else {
        return;
    };
    let Expression::BooleanLiteral(b) = unwrap_expr(third_arg) else {
        return;
    };
    if b.value {
        return;
    }
    if !is_proven_xhr_receiver(&mem.object, semantic) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::NoSyncXhr,
        subject_name,
        "noSyncXhr",
        "XMLHttpRequest.open",
        "A synchronous `XMLHttpRequest` (`.open(method, url, false)`) freezes the main thread until the request finishes, blocking all rendering and input. Use `fetch()` or an async XHR (`open(method, url, true)`).".to_string(),
        line_starts,
        call.span,
    );
}

fn is_proven_xhr_receiver(expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    match unwrap_expr(expr) {
        Expression::NewExpression(new_expr) => {
            matches!(
                unwrap_expr(&new_expr.callee),
                Expression::Identifier(id) if id.name == "XMLHttpRequest" && is_global_ident(semantic, id)
            )
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
                && let Some(init) = &decl.init
            {
                return is_proven_xhr_receiver(init, semantic);
            }
            let decl_text = semantic
                .nodes()
                .get_node(decl_id)
                .span()
                .source_text(semantic.source_text());
            decl_text.contains("XMLHttpRequest")
        }
        _ => false,
    }
}

pub(super) fn check_no_document_write(
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
    if method != "write" && method != "writeln" {
        return;
    }
    let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if recv_id.name != "document" || !is_global_ident(semantic, recv_id) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::NoDocumentWrite,
        subject_name,
        "noDocumentWrite",
        &format!("document.{method}"),
        "`document.write()` blocks parsing, is ignored (or wipes the page) after load, and is flagged by browsers as a performance anti-pattern. Build DOM nodes or set `innerHTML`/`textContent` on a target element instead.".to_string(),
        line_starts,
        call.span,
    );
}

pub(super) fn check_no_create_object_url_without_revoke(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let src = semantic.source_text();
    if !src.contains("createObjectURL") || src.contains("revokeObjectURL") {
        return;
    }
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        if mem.property.name != "createObjectURL" {
            continue;
        }
        let Expression::Identifier(obj_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        if obj_id.name != "URL" || !is_global_ident(semantic, obj_id) {
            continue;
        }
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|id| get_subject_name(semantic, id));
        push_semantic_site(
            out,
            RuleId::NoCreateObjectUrlWithoutRevoke,
            subject_name,
            "noCreateObjectUrlWithoutRevoke",
            "URL.createObjectURL",
            "`URL.createObjectURL()` without a matching `URL.revokeObjectURL()` keeps the Blob/File in memory for the lifetime of the document.".to_string(),
            line_starts,
            call.span,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. `client-passive-event-listeners` (with `Autofix`)
// ---------------------------------------------------------------------------

pub(super) fn check_client_passive_event_listeners(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "addEventListener" {
        return;
    }
    if call.arguments.len() < 2 {
        return;
    }
    let Some(event_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::StringLiteral(event_lit) = unwrap_expr(event_arg) else {
        return;
    };
    let Some(event_name) = event_lit.value.as_str() else {
        return;
    };
    if !PASSIVE_EVENT_NAMES.contains(&event_name) {
        return;
    }

    let Some(handler_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    if handler_calls_prevent_default_or_forwards_event(handler_arg, semantic) {
        return;
    }

    let mut autofix: Option<AutofixPatch> = None;
    let call_span = span_to_byte_span(call.span);

    if let Some(opts_arg) = call.arguments.get(2) {
        let Some(opts_expr) = opts_arg.as_expression() else {
            return;
        };
        let Expression::ObjectExpression(obj) = unwrap_expr(opts_expr) else {
            return;
        };
        let has_explicit_passive = obj.properties.iter().any(|prop| {
            if let ObjectPropertyKind::ObjectProperty(p) = prop
                && p.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("passive")
                && matches!(unwrap_expr(&p.value), Expression::BooleanLiteral(_))
            {
                true
            } else {
                false
            }
        });
        if has_explicit_passive {
            return;
        }
    } else {
        let raw_call = call.span.source_text(semantic.source_text());
        if let Some(before_close) = raw_call
            .strip_suffix(')')
            .map(|s| s.trim_end().trim_end_matches(','))
        {
            let replacement = format!("{before_close}, {{ passive: true }})");
            autofix = Some(AutofixPatch::replace(
                format!("Add `{{ passive: true }}` to `{event_name}` event listener"),
                call_span,
                replacement,
            ));
        }
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site_with_fix(
        out,
        RuleId::ClientPassiveEventListeners,
        subject_name,
        "clientPassiveEventListeners",
        event_name,
        format!(
            "\"{event_name}\" listener without {{ passive: true }} makes scrolling janky for your users. Only add it if the handler doesn't call event.preventDefault(), since passive listeners silently ignore preventDefault()."
        ),
        line_starts,
        call.span,
        autofix,
    );
}

fn handler_calls_prevent_default_or_forwards_event(
    handler_expr: &Expression<'_>,
    semantic: &Semantic<'_>,
) -> bool {
    match unwrap_expr(handler_expr) {
        Expression::ArrowFunctionExpression(arrow) => {
            let ev_param = arrow.params.items.first().and_then(|p| {
                p.pattern
                    .get_binding_identifier()
                    .map(|id| id.name.as_str())
            });
            function_body_calls_prevent_default_or_forwards(arrow.body.span(), ev_param, semantic)
        }
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            let ev_param = func.params.items.first().and_then(|p| {
                p.pattern
                    .get_binding_identifier()
                    .map(|id| id.name.as_str())
            });
            function_body_calls_prevent_default_or_forwards(body.span, ev_param, semantic)
        }
        Expression::Identifier(ident) => {
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(func) => {
                    let Some(body) = &func.body else {
                        return false;
                    };
                    let ev_param = func.params.items.first().and_then(|p| {
                        p.pattern
                            .get_binding_identifier()
                            .map(|id| id.name.as_str())
                    });
                    function_body_calls_prevent_default_or_forwards(body.span, ev_param, semantic)
                }
                AstKind::VariableDeclarator(decl) => {
                    if let Some(init) = &decl.init
                        && handler_calls_prevent_default_or_forwards_event(init, semantic)
                    {
                        return true;
                    }
                    // Also check reassignments (`onTouchMove = (e) => e.preventDefault()`)
                    for reference in semantic.scoping().get_resolved_references(sym_id) {
                        if let AstKind::AssignmentExpression(assign) =
                            semantic.nodes().parent_kind(reference.node_id())
                            && handler_calls_prevent_default_or_forwards_event(
                                &assign.right,
                                semantic,
                            )
                        {
                            return true;
                        }
                    }
                    false
                }
                _ => false,
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if matches!(unwrap_expr(&mem.object), Expression::ThisExpression(_)) {
                let method_name = mem.property.name.as_str();
                return class_or_object_method_calls_prevent_default(method_name, semantic);
            }
            false
        }
        Expression::PrivateFieldExpression(priv_mem) => {
            if matches!(unwrap_expr(&priv_mem.object), Expression::ThisExpression(_)) {
                let method_name = priv_mem.field.name.as_str();
                return class_or_object_method_calls_prevent_default(method_name, semantic);
            }
            false
        }
        _ => false,
    }
}

fn class_or_object_method_calls_prevent_default(
    method_name: &str,
    semantic: &Semantic<'_>,
) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::MethodDefinition(m) => {
                let matches_key = m
                    .key
                    .static_name()
                    .as_ref()
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n == method_name)
                    || matches!(&m.key, oxc_ast::ast::PropertyKey::PrivateIdentifier(p) if p.name == method_name);
                if matches_key && let Some(body) = &m.value.body {
                    let ev_param = m.value.params.items.first().and_then(|p| {
                        p.pattern
                            .get_binding_identifier()
                            .map(|id| id.name.as_str())
                    });
                    if function_body_calls_prevent_default_or_forwards(
                        body.span, ev_param, semantic,
                    ) {
                        return true;
                    }
                }
            }
            AstKind::ObjectProperty(prop)
                if prop
                    .key
                    .static_name()
                    .as_ref()
                    .and_then(|n| n.as_str())
                    .is_some_and(|n| n == method_name)
                    && handler_calls_prevent_default_or_forwards_event(&prop.value, semantic) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn function_body_calls_prevent_default_or_forwards(
    body_span: Span,
    ev_param: Option<&str>,
    semantic: &Semantic<'_>,
) -> bool {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        // Skip nested functions (except when checking if event param is forwarded)
        let in_nested_fn = semantic
            .nodes()
            .ancestor_ids(node_id)
            .skip(1)
            .take_while(|&anc_id| {
                body_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
            })
            .any(|anc_id| {
                matches!(
                    semantic.nodes().kind(anc_id),
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )
            });
        if in_nested_fn {
            continue;
        }
        if let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
            && mem.property.name == "preventDefault"
        {
            return true;
        }
        if let Some(param_name) = ev_param
            && matches!(unwrap_expr(&call.callee), Expression::Identifier(_))
            && call.arguments.iter().any(|arg| {
                arg.as_expression().is_some_and(|e| {
                    matches!(unwrap_expr(e), Expression::Identifier(id) if id.name == param_name)
                })
            })
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 3. `no-flush-sync` & `no-document-start-view-transition`
// ---------------------------------------------------------------------------

pub(super) fn check_no_flush_sync(
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let imports_imperative_dom_lib = module.imports.iter().any(|imp| {
        imp.source.starts_with("@floating-ui/")
            || imp.source.starts_with("@popperjs/")
            || imp.source == "react-popper"
            || imp.source == "popper.js"
            || imp.source.starts_with("shaka-player")
            || (!imp.is_type_only && imp.source.starts_with("@softmaple/awareness/"))
    });
    if imports_imperative_dom_lib {
        return;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ImportDeclaration(imp) = node.kind() else {
            continue;
        };
        if imp.import_kind.is_type() || imp.source.value != "react-dom" {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            let ImportDeclarationSpecifier::ImportSpecifier(s) = spec else {
                continue;
            };
            if s.import_kind.is_type() || s.imported.name() != "flushSync" {
                continue;
            }
            let local_name = s.local.name.as_str();
            if has_exempt_flush_sync_call(semantic, local_name) {
                return;
            }
            push_semantic_site(
                out,
                RuleId::NoFlushSync,
                None,
                "noFlushSync",
                "flushSync",
                "`flushSync` forces an immediate update, which skips View Transitions and concurrent rendering.".to_string(),
                line_starts,
                s.span,
            );
        }
    }
}

fn has_exempt_flush_sync_call(semantic: &Semantic<'_>, local_name: &str) -> bool {
    let measuring_helpers = collect_dom_helper_names(semantic, true);
    let mutating_helpers = collect_dom_helper_names(semantic, false);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::Identifier(callee_id) = unwrap_expr(&call.callee) else {
            continue;
        };
        if callee_id.name != local_name {
            continue;
        }

        for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
            match semantic.nodes().kind(anc_id) {
                AstKind::CallExpression(anc_call) => {
                    let trail = collect_callee_identifier_trail(&anc_call.callee);
                    if trail.first().is_some_and(|n| n == "startViewTransition") {
                        return true;
                    }
                }
                AstKind::Function(func) => {
                    if let Some(body) = &func.body
                        && (span_has_dom_measurement_or_mutation(body.span, semantic)
                            || span_calls_any_helper(body.span, &measuring_helpers, semantic)
                            || span_calls_any_helper(body.span, &mutating_helpers, semantic))
                    {
                        return true;
                    }
                }
                AstKind::ArrowFunctionExpression(arrow) => {
                    let span = arrow.body.span();
                    if span_has_dom_measurement_or_mutation(span, semantic)
                        || span_calls_any_helper(span, &measuring_helpers, semantic)
                        || span_calls_any_helper(span, &mutating_helpers, semantic)
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn collect_dom_helper_names(semantic: &Semantic<'_>, measure: bool) -> HashSet<String> {
    let mut names = HashSet::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(f) => {
                if let (Some(id), Some(body)) = (&f.id, &f.body)
                    && (if measure {
                        span_has_dom_measurement(body.span, semantic)
                    } else {
                        span_has_dom_mutation(body.span, semantic)
                    })
                {
                    names.insert(id.name.to_string());
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let (Some(id), Some(init)) = (decl.id.get_binding_identifier(), &decl.init) {
                    let span = init.span();
                    if if measure {
                        span_has_dom_measurement(span, semantic)
                    } else {
                        span_has_dom_mutation(span, semantic)
                    } {
                        names.insert(id.name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    names
}

fn span_has_dom_measurement_or_mutation(span: Span, semantic: &Semantic<'_>) -> bool {
    span_has_dom_measurement(span, semantic) || span_has_dom_mutation(span, semantic)
}

fn span_has_dom_measurement(span: Span, semantic: &Semantic<'_>) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::StaticMemberExpression(mem) => {
                if DOM_MEASUREMENT_NAMES.contains(&mem.property.name.as_str()) {
                    return true;
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::Identifier(id) = unwrap_expr(&call.callee) {
                    let name = id.name.as_str();
                    if (name.starts_with("get")
                        || name.starts_with("measure")
                        || name.starts_with("read"))
                        && (name.ends_with("Width")
                            || name.ends_with("Height")
                            || name.ends_with("Rect")
                            || name.ends_with("Rects")
                            || name.ends_with("Size")
                            || name.ends_with("Bounds")
                            || name.ends_with("Position"))
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn span_has_dom_mutation(span: Span, semantic: &Semantic<'_>) -> bool {
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::CallExpression(call) = node.kind()
            && let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
            && IMPERATIVE_DOM_MUTATION_NAMES.contains(&mem.property.name.as_str())
        {
            return true;
        }
    }
    false
}

fn span_calls_any_helper(span: Span, helpers: &HashSet<String>, semantic: &Semantic<'_>) -> bool {
    if helpers.is_empty() {
        return false;
    }
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::CallExpression(call) = node.kind()
            && let Expression::Identifier(id) = unwrap_expr(&call.callee)
            && helpers.contains(id.name.as_str())
        {
            return true;
        }
    }
    false
}

pub(super) fn check_no_document_start_view_transition(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if mem.property.name != "startViewTransition" {
        return;
    }
    let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
        return;
    };
    if recv_id.name != "document" || !is_global_ident(semantic, recv_id) {
        return;
    }

    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::NoDocumentStartViewTransition,
        subject_name,
        "noDocumentStartViewTransition",
        "document.startViewTransition",
        "Calling `document.startViewTransition()` directly can bypass React's `<ViewTransition>` animation lifecycle.".to_string(),
        line_starts,
        call.span,
    );
}

// ---------------------------------------------------------------------------
// 4. `js-cache-storage`, `js-batch-dom-css`, `client-localstorage-no-version`
// ---------------------------------------------------------------------------

pub(super) fn check_js_cache_storage(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let mut counts_by_scope: HashMap<Option<NodeId>, HashMap<(String, String), usize>> =
        HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
            continue;
        };
        if mem.property.name != "getItem" {
            continue;
        }
        let Expression::Identifier(recv_id) = unwrap_expr(&mem.object) else {
            continue;
        };
        let storage_name = recv_id.name.as_str();
        if storage_name != "localStorage" && storage_name != "sessionStorage" {
            continue;
        }
        let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let Expression::StringLiteral(key_lit) = unwrap_expr(first_arg) else {
            continue;
        };
        let Some(key) = key_lit.value.as_str() else {
            continue;
        };

        let scope_fn = find_non_iterator_enclosing_fn(semantic, node_id);
        let scope_map = counts_by_scope.entry(scope_fn).or_default();
        let entry = scope_map
            .entry((storage_name.to_string(), key.to_string()))
            .or_insert(0);
        *entry += 1;
        if *entry == 2 {
            let subject_name = find_enclosing_react_node(semantic, node_id)
                .and_then(|id| get_subject_name(semantic, id));
            push_semantic_site(
                out,
                RuleId::JsCacheStorage,
                subject_name,
                "jsCacheStorage",
                &format!("{storage_name}.getItem"),
                format!(
                    "This is slow because {storage_name}.getItem(\"{key}\") runs several times & re-parses the data each call, so read it once & reuse the value"
                ),
                line_starts,
                call.span,
            );
        }
    }
}

fn find_non_iterator_enclosing_fn(semantic: &Semantic<'_>, node_id: NodeId) -> Option<NodeId> {
    for anc_id in semantic.nodes().ancestor_ids(node_id).skip(1) {
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            if let AstKind::CallExpression(call) = semantic.nodes().parent_kind(anc_id)
                && let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee)
                && matches!(
                    mem.property.name.as_str(),
                    "forEach" | "map" | "filter" | "reduce" | "some" | "every"
                )
            {
                continue;
            }
            return Some(anc_id);
        }
    }
    None
}

pub(super) fn check_js_batch_dom_css_in_block(
    block_node_id: NodeId,
    statements: &[Statement<'_>],
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let in_loop = semantic.nodes().ancestor_ids(block_node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ForStatement(_)
                | AstKind::ForOfStatement(_)
                | AstKind::ForInStatement(_)
                | AstKind::WhileStatement(_)
                | AstKind::DoWhileStatement(_)
        )
    });
    if !in_loop || statements.len() < 2 {
        return;
    }

    let block_span = semantic.nodes().get_node(block_node_id).span();
    if !span_has_dom_measurement(block_span, semantic) {
        return;
    }

    for idx in 1..statements.len() {
        if is_style_write_stmt(&statements[idx], semantic.source_text())
            && is_style_write_stmt(&statements[idx - 1], semantic.source_text())
        {
            let span = statements[idx].span();
            let subject_name = find_enclosing_react_node(semantic, block_node_id)
                .and_then(|id| get_subject_name(semantic, id));
            push_semantic_site(
                out,
                RuleId::JsBatchDomCss,
                subject_name,
                "jsBatchDomCss",
                "style",
                "This makes the browser recalculate layout again & again because element.style writes are interleaved with layout reads inside a loop, so do all reads first, then set the styles at once with cssText or a CSS class".to_string(),
                line_starts,
                span,
            );
            return;
        }
    }
}

fn is_style_write_stmt(stmt: &Statement<'_>, source: &str) -> bool {
    let Statement::ExpressionStatement(expr_stmt) = stmt else {
        return false;
    };
    let Expression::AssignmentExpression(assign) = unwrap_expr(&expr_stmt.expression) else {
        return false;
    };
    let lhs = assign.left.span().source_text(source);
    lhs.contains(".style.")
}

pub(super) fn check_client_localstorage_no_version(
    node_id: NodeId,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = unwrap_expr(&call.callee) else {
        return;
    };
    if !matches!(mem.property.name.as_str(), "getItem" | "setItem") {
        return;
    }
    let is_local_storage = match unwrap_expr(&mem.object) {
        Expression::Identifier(id) => id.name == "localStorage" && is_global_ident(semantic, id),
        Expression::StaticMemberExpression(inner) => {
            inner.property.name == "localStorage"
                && matches!(unwrap_expr(&inner.object), Expression::Identifier(id) if matches!(id.name.as_str(), "window" | "globalThis"))
        }
        _ => false,
    };
    if !is_local_storage {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::StringLiteral(key_lit) = unwrap_expr(first_arg) else {
        return;
    };
    let Some(key_str) = key_lit.value.as_str() else {
        return;
    };
    if has_storage_version_suffix(key_str) {
        return;
    }
    let subject_name =
        find_enclosing_react_node(semantic, node_id).and_then(|id| get_subject_name(semantic, id));
    push_semantic_site(
        out,
        RuleId::ClientLocalstorageNoVersion,
        subject_name,
        "clientLocalstorageNoVersion",
        key_str,
        format!(
            "`localStorage` key \"{key_str}\" has no schema version suffix (such as `{key_str}:v1`), so schema changes can crash on stale stored payloads."
        ),
        line_starts,
        key_lit.span,
    );
}

fn has_storage_version_suffix(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    for sep in [":v", "_v", "-v", ".v"] {
        if let Some((_, after)) = lower.rsplit_once(sep)
            && !after.is_empty()
            && after.bytes().all(|b| b.is_ascii_digit())
        {
            return true;
        }
    }
    false
}
