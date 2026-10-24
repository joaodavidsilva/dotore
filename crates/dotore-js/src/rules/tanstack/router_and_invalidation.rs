//! TanStack Query mutation/invalidation rules and TanStack Router route-options,
//! loader waterfall, redirect-in-try-catch, and anchor navigation rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, FunctionBody,
        JSXAttributeName, JSXAttributeValue, JSXElementName, ObjectExpression, ObjectPropertyKind,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use super::{
    ImportedBindingInfo, QUERY_CACHE_UPDATE_METHODS, READ_ONLY_MUTATION_WORDS,
    TANSTACK_MUTATION_HOOKS, TANSTACK_ROUTE_CREATION_FUNCTIONS, TANSTACK_ROUTE_PROPERTY_ORDER,
    WRITE_INTENT_WORDS, is_inside_use_effect_execution, is_tanstack_query_source,
    resolve_tanstack_callee_name, resolve_tanstack_hook_call,
};
use crate::{
    ir::types::SemanticRuleSite,
    matchers::{collect_pattern_bound_names, push_semantic_site, unwrap_expr},
    rules::RuleId,
};

pub(crate) fn check_mutation_in_effect_as_read(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(init) = &decl.init else {
        return;
    };
    let Some((mutation_call, _)) =
        resolve_tanstack_hook_call(semantic, init, imports, TANSTACK_MUTATION_HOOKS, true)
    else {
        return;
    };

    // Collect `mutate` / `mutateAsync` trigger symbols and check whether `data` is read or intent is read-like
    let mut trigger_syms: Vec<SymbolId> = Vec::new();
    let mut consumes_data = false;
    let mut binding_names: Vec<String> = Vec::new();

    match &decl.id {
        BindingPattern::ObjectPattern(pat) => {
            for prop in &pat.properties {
                let key_name = prop.key.static_name();
                let key_str = key_name.as_ref().and_then(|n| n.as_str());
                if matches!(key_str, Some("mutate" | "mutateAsync"))
                    && let BindingPattern::BindingIdentifier(id) = &prop.value
                    && let Some(sym) = id.symbol_id.get()
                {
                    trigger_syms.push(sym);
                    binding_names.push(id.name.to_string());
                }
                if key_str == Some("data") {
                    consumes_data = true;
                }
            }
        }
        BindingPattern::BindingIdentifier(id) => {
            binding_names.push(id.name.to_string());
            if let Some(sym) = id.symbol_id.get() {
                trigger_syms.push(sym);
                for r in semantic.scoping().get_resolved_references(sym) {
                    let p_id = semantic.nodes().parent_id(r.node_id());
                    if let AstKind::StaticMemberExpression(mem) = semantic.nodes().kind(p_id)
                        && mem.property.name == "data"
                    {
                        consumes_data = true;
                    }
                }
            }
        }
        _ => {}
    }

    if trigger_syms.is_empty() {
        return;
    }

    // Check mutationFn name intent
    if let Some(Argument::ObjectExpression(opts)) = mutation_call.arguments.first() {
        for prop_kind in &opts.properties {
            if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
                && prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("mutationFn")
            {
                let text = prop.value.span().source_text(semantic.source_text());
                binding_names.push(text.to_string());
            }
        }
    }

    let has_read_intent = binding_names
        .iter()
        .any(|n| has_word_in_set(n, READ_ONLY_MUTATION_WORDS));
    let has_write_intent = binding_names
        .iter()
        .any(|n| has_word_in_set(n, WRITE_INTENT_WORDS));

    if !consumes_data && (!has_read_intent || has_write_intent) {
        return;
    }

    for sym_id in trigger_syms {
        for reference in semantic.scoping().get_resolved_references(sym_id) {
            let ref_node_id = reference.node_id();
            let p_id = semantic.nodes().parent_id(ref_node_id);
            let call_span = match semantic.nodes().kind(p_id) {
                AstKind::CallExpression(c) => Some(c.span),
                AstKind::StaticMemberExpression(mem)
                    if matches!(mem.property.name.as_str(), "mutate" | "mutateAsync") =>
                {
                    let gp_id = semantic.nodes().parent_id(p_id);
                    if let AstKind::CallExpression(c) = semantic.nodes().kind(gp_id) {
                        Some(c.span)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(span) = call_span
                && is_inside_use_effect_execution(semantic, ref_node_id)
            {
                push_semantic_site(
                    sites,
                    RuleId::QueryNoMutationInEffectAsRead,
                    subject_name.clone(),
                    "queryNoMutationInEffectAsRead",
                    "useMutation",
                    "Triggering useMutation inside useEffect to load data bypasses caching and deduplication; use useQuery instead.".to_string(),
                    line_starts,
                    span,
                );
                return;
            }
        }
    }
}

pub(crate) fn check_mutation_missing_invalidation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    imports: &HashMap<String, ImportedBindingInfo>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let has_tanstack_import = imports
        .values()
        .any(|i| is_tanstack_query_source(&i.source));
    let has_query_signal_in_file = has_tanstack_import
        || source.contains("useQuery(")
        || source.contains("useQueryClient(")
        || source.contains("useSuspenseQuery(")
        || source.contains("useUtils(");

    if !has_query_signal_in_file {
        return;
    }

    let Some(_hook_name) = resolve_tanstack_callee_name(
        semantic,
        &call.callee,
        imports,
        TANSTACK_MUTATION_HOOKS,
        true,
    ) else {
        return;
    };

    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let Expression::ObjectExpression(opts_obj) = first_arg.without_parentheses() else {
        return;
    };

    // Skip read-only mutation names (check, download, estimate, export, generate, login, logout, verify, etc.)
    if let Some(subj) = subject_name
        && has_word_in_set(subj, READ_ONLY_MUTATION_WORDS)
    {
        return;
    }
    let parent_id = semantic.nodes().parent_id(node_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
        && let BindingPattern::BindingIdentifier(id) = &decl.id
        && has_word_in_set(id.name.as_str(), READ_ONLY_MUTATION_WORDS)
    {
        return;
    }

    for prop_kind in &opts_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("mutationFn") {
            let fn_text = prop.value.span().source_text(source);
            if has_word_in_set(fn_text, READ_ONLY_MUTATION_WORDS) {
                return;
            }
        }
    }

    // Check if any lifecycle callback or mutationFn updates/invalidates the query cache
    if span_has_query_cache_update(semantic, opts_obj.span, source) {
        return;
    }

    push_semantic_site(
        sites,
        RuleId::QueryMutationMissingInvalidation,
        subject_name.clone(),
        "queryMutationMissingInvalidation",
        "useMutation",
        "useMutation does not invalidate or update the query cache in onSuccess/onSettled, leaving cached queries stale.".to_string(),
        line_starts,
        call.span,
    );
}

fn span_has_query_cache_update(semantic: &Semantic<'_>, span: Span, source: &str) -> bool {
    let text = span.source_text(source);
    if text.contains("location.href")
        || text.contains("location.assign")
        || text.contains("location.replace")
        || text.contains("location.reload")
    {
        return true;
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(c) => {
                let callee = unwrap_expr(&c.callee);
                if let Expression::StaticMemberExpression(mem) = callee {
                    let prop_name = mem.property.name.as_str();
                    if QUERY_CACHE_UPDATE_METHODS.contains(&prop_name) {
                        return true;
                    }
                    if prop_name == "invalidate"
                        && !matches!(
                            mem.object.without_parentheses(),
                            Expression::Identifier(id) if id.name == "session"
                        )
                    {
                        return true;
                    }
                }
                if let Expression::Identifier(id) = callee {
                    let lower = id.name.to_ascii_lowercase();
                    if lower.contains("invalidat")
                        || lower.contains("refetch")
                        || lower.contains("querycache")
                    {
                        // Check if `id` resolves to a local function that does NOT update cache
                        if let Some(ref_id) = id.reference_id.get()
                            && let Some(sym_id) =
                                semantic.scoping().get_reference(ref_id).symbol_id()
                        {
                            let decl_id = semantic.scoping().symbol_declaration(sym_id);
                            if let AstKind::VariableDeclarator(d) = semantic.nodes().kind(decl_id)
                                && let Some(init) = &d.init
                                && matches!(
                                    init.without_parentheses(),
                                    Expression::ArrowFunctionExpression(_)
                                        | Expression::FunctionExpression(_)
                                )
                            {
                                if span_has_query_cache_update(semantic, init.span(), source) {
                                    return true;
                                }
                                continue;
                            }
                        }
                        return true;
                    }
                    if QUERY_CACHE_UPDATE_METHODS.contains(&id.name.as_str()) && id.name != "clear"
                    {
                        return true;
                    }
                }
                // Check if `queryClient` is passed as an argument to a helper
                if c.arguments.iter().any(|arg| {
                    arg.as_expression().is_some_and(|e| {
                        matches!(
                            e.without_parentheses(),
                            Expression::Identifier(id) if id.name == "queryClient"
                        )
                    })
                }) {
                    return true;
                }
            }
            AstKind::IdentifierReference(ident) => {
                // Callback reference like `onSuccess: invalidate`
                if let Some(ref_id) = ident.reference_id.get()
                    && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
                {
                    let decl_id = semantic.scoping().symbol_declaration(sym_id);
                    if let AstKind::Function(func) = semantic.nodes().kind(decl_id)
                        && func.span != span
                        && span_has_query_cache_update(semantic, func.span, source)
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

fn has_word_in_set(identifier: &str, words: &[&str]) -> bool {
    for token in tokenize_identifier_words(identifier) {
        if words.contains(&token.as_str()) {
            return true;
        }
    }
    false
}

fn tokenize_identifier_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(current.to_ascii_lowercase());
                current.clear();
            }
            continue;
        }
        if ch.is_ascii_uppercase() && !current.is_empty() {
            words.push(current.to_ascii_lowercase());
            current.clear();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

pub(crate) fn extract_route_options_object<'a>(
    call: &'a CallExpression<'a>,
) -> Option<&'a ObjectExpression<'a>> {
    let is_route_factory = match call.callee.without_parentheses() {
        Expression::Identifier(id) => TANSTACK_ROUTE_CREATION_FUNCTIONS.contains(&id.name.as_str()),
        Expression::CallExpression(inner) => matches!(
            inner.callee.without_parentheses(),
            Expression::Identifier(id) if TANSTACK_ROUTE_CREATION_FUNCTIONS.contains(&id.name.as_str())
        ),
        _ => false,
    };
    if !is_route_factory {
        return None;
    }
    let first_arg = call.arguments.first()?.as_expression()?;
    if let Expression::ObjectExpression(obj) = first_arg.without_parentheses() {
        Some(obj)
    } else {
        None
    }
}

pub(crate) fn check_route_property_order(
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut last_idx: Option<usize> = None;
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let key_name = prop.key.static_name();
        let Some(prop_name) = key_name.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(curr_idx) = TANSTACK_ROUTE_PROPERTY_ORDER
            .iter()
            .position(|&p| p == prop_name)
        else {
            continue;
        };
        if let Some(prev_idx) = last_idx
            && curr_idx < prev_idx
        {
            let expected_before = TANSTACK_ROUTE_PROPERTY_ORDER[prev_idx];
            push_semantic_site(
                sites,
                RuleId::TanstackStartRoutePropertyOrder,
                subject_name.clone(),
                "tanstackStartRoutePropertyOrder",
                prop_name,
                format!(
                    "Ordering route property \"{prop_name}\" after \"{expected_before}\" breaks type inference."
                ),
                line_starts,
                options_obj.span,
            );
            return;
        }
        last_idx = Some(curr_idx);
    }
}

pub(crate) fn check_loader_parallel_fetch(
    _semantic: &Semantic<'_>,
    options_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for prop_kind in &options_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        if prop.key.static_name().as_ref().and_then(|n| n.as_str()) != Some("loader") {
            continue;
        }
        let body_opt = match prop.value.without_parentheses() {
            Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
                ArrowFunctionBody::FunctionBody(b) => Some(b.as_ref()),
                _ => None,
            },
            Expression::FunctionExpression(func) => func.body.as_deref(),
            _ => None,
        };
        let Some(body) = body_opt else {
            continue;
        };

        if has_two_independent_top_level_awaits(body, source) {
            push_semantic_site(
                sites,
                RuleId::TanstackStartLoaderParallelFetch,
                subject_name.clone(),
                "tanstackStartLoaderParallelFetch",
                "loader",
                "Sequential awaits in this loader create a request waterfall that slows the route."
                    .to_string(),
                line_starts,
                prop.span,
            );
        }
    }
}

fn has_two_independent_top_level_awaits(body: &FunctionBody<'_>, source: &str) -> bool {
    let mut prior_bindings: Vec<String> = Vec::new();
    let mut independent_await_count = 0usize;

    for stmt in &body.statements {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    let Some(init) = &decl.init else {
                        continue;
                    };
                    let Expression::AwaitExpression(await_expr) = init.without_parentheses() else {
                        continue;
                    };
                    let arg_text = await_expr.argument.span().source_text(source);
                    let depends_on_prior = prior_bindings
                        .iter()
                        .any(|b| contains_identifier_token(arg_text, b));
                    if !depends_on_prior {
                        independent_await_count += 1;
                    }
                    prior_bindings.extend(collect_pattern_bound_names(&decl.id));
                }
            }
            Statement::ExpressionStatement(es) => {
                if let Expression::AwaitExpression(await_expr) = es.expression.without_parentheses()
                {
                    let arg_text = await_expr.argument.span().source_text(source);
                    let depends_on_prior = prior_bindings
                        .iter()
                        .any(|b| contains_identifier_token(arg_text, b));
                    if !depends_on_prior {
                        independent_await_count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    independent_await_count >= 2
}

fn contains_identifier_token(haystack: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(ident) {
        let before_ok = idx == 0
            || !haystack.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && haystack.as_bytes()[idx - 1] != b'_'
                && haystack.as_bytes()[idx - 1] != b'$';
        let after_idx = idx + ident.len();
        let after_ok = after_idx == haystack.len()
            || !haystack.as_bytes()[after_idx].is_ascii_alphanumeric()
                && haystack.as_bytes()[after_idx] != b'_'
                && haystack.as_bytes()[after_idx] != b'$';
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

pub(crate) fn check_redirect_in_try_catch(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    throw_stmt: &oxc_ast::ast::ThrowStatement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::CallExpression(call) = throw_stmt.argument.without_parentheses() else {
        return;
    };
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    if !matches!(callee_id.name.as_str(), "redirect" | "notFound") {
        return;
    }

    let source = semantic.source_text();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                // Stop at non-IIFE function boundary
                let is_iife = semantic.nodes().ancestor_ids(anc_id).take(3).any(|p_id| {
                    if let AstKind::CallExpression(c) = semantic.nodes().kind(p_id) {
                        c.callee
                            .span()
                            .contains_inclusive(semantic.nodes().get_node(anc_id).span())
                    } else {
                        false
                    }
                });
                if !is_iife {
                    break;
                }
            }
            AstKind::TryStatement(try_stmt) => {
                // Only applies if `throw` is inside the `try` block (`try_stmt.block`)
                if !try_stmt.block.span.contains_inclusive(throw_stmt.span) {
                    continue;
                }
                let Some(handler) = &try_stmt.handler else {
                    continue;
                };
                let catch_text = handler.body.span.source_text(source);
                let catch_rethrows = catch_text.contains("throw ");
                if !catch_rethrows {
                    push_semantic_site(
                        sites,
                        RuleId::TanstackStartRedirectInTryCatch,
                        subject_name.clone(),
                        "tanstackStartRedirectInTryCatch",
                        callee_id.name.as_str(),
                        format!(
                            "throw {}() inside a try block gets swallowed, so the redirect silently fails.",
                            callee_id.name
                        ),
                        line_starts,
                        throw_stmt.span,
                    );
                    return;
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn check_no_anchor_element(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let JSXElementName::Identifier(ident) = &opening.name else {
        return;
    };
    if ident.name != "a" {
        return;
    }

    let mut href_val: Option<&str> = None;
    let mut has_download = false;
    let mut is_target_blank = false;

    for attr_item in &opening.attributes {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        match attr_id.name.as_str() {
            "download" => has_download = true,
            "target" => {
                if extract_jsx_attr_string_value(attr.value.as_ref()) == Some("_blank") {
                    is_target_blank = true;
                }
            }
            "href" => {
                href_val = extract_jsx_attr_string_value(attr.value.as_ref());
            }
            _ => {}
        }
    }

    if has_download || is_target_blank {
        return;
    }
    let Some(href) = href_val else {
        return;
    };
    if !href.starts_with('/') || href.starts_with("//") {
        return;
    }
    let pathname = href.split(['?', '#']).next().unwrap_or(href);
    if pathname.starts_with("/api/") {
        return;
    }
    if let Some(last_dot) = pathname.rfind('.') {
        let ext = &pathname[last_dot + 1..];
        if !ext.is_empty() && ext.len() <= 8 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return;
        }
    }

    push_semantic_site(
        sites,
        RuleId::TanstackStartNoAnchorElement,
        subject_name.clone(),
        "tanstackStartNoAnchorElement",
        "a",
        "Plain <a> reloads the whole page for internal navigation, so TanStack Router loses client state and preloading.".to_string(),
        line_starts,
        opening.span,
    );
}

fn extract_jsx_attr_string_value<'a>(val: Option<&'a JSXAttributeValue<'a>>) -> Option<&'a str> {
    match val? {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
        JSXAttributeValue::ExpressionContainer(c) => match &c.expression {
            oxc_ast::ast::JSXExpression::StringLiteral(s) => s.value.as_str(),
            _ => None,
        },
        _ => None,
    }
}
