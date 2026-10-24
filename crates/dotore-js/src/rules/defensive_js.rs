//! Defensive JavaScript, TypeScript, and DOM runtime safety rule detectors (21 rules).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

mod async_and_events;
mod nullish_and_collections;
mod parsing_and_selectors;

use oxc_ast::{
    AstKind,
    ast::{Expression, IdentifierReference, LogicalOperator, UnaryOperator},
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use self::{
    async_and_events::{
        check_jsx_event_handler_defensive_rules, check_no_collapse_request_error_in_try_catch,
        check_no_collapse_request_error_to_empty_state_call,
        check_no_deprecated_keyboard_event_keycode_which,
        check_no_loading_flag_reset_outside_finally, check_no_passive_request_owner_ref,
        check_predicate_in_condition, check_predicate_in_logical,
    },
    nullish_and_collections::{
        check_no_arithmetic_on_optional_chained_operand,
        check_no_array_find_result_member_access_without_guard,
        check_no_array_index_deref_without_bounds_or_empty_guard,
        check_no_non_null_assertion_on_maybe_undefined_result,
        check_no_nullish_coalescing_arithmetic_precedence,
        check_no_object_keys_values_entries_on_maybe_undefined,
        check_no_object_or_array_coerced_to_string_in_template_literal,
        check_no_whole_object_default_losing_per_key_defaults,
    },
    parsing_and_selectors::{
        check_no_non_literal_selector_query_without_try_catch,
        check_no_unescaped_dynamic_string_in_regexp, check_no_unguarded_numeric_input_parse,
        check_no_unguarded_throwing_new_url, check_no_unguarded_throwing_parse_call,
        check_no_unsafe_json_parse_member,
    },
};
use crate::{
    ir::{
        SemanticRuleSite, SubjectIr,
        react_ast::{find_enclosing_react_node, get_subject_name},
    },
    matchers::resolve_ident_symbol,
};

const PREDICATE_PREFIXES: &[&str] = &["is", "has", "can", "should", "will"];

const SELECTOR_QUERY_METHODS: &[&str] =
    &["querySelector", "querySelectorAll", "matches", "closest"];

const MAYBE_UNDEFINED_METHODS: &[&str] = &[
    "find",
    "findLast",
    "match",
    "get",
    "pop",
    "shift",
    "at",
    "exec",
    "querySelector",
    "getElementById",
    "closest",
];

const THROWING_PARSE_FUNCTIONS: &[&str] = &[
    "decodeURIComponent",
    "decodeURI",
    "atob",
    "readableColor",
    "parseToRgb",
    "parseToHsl",
    "chroma",
];

/// Extracts all single-pass defensive JS/TS/DOM runtime safety rule sites and autofixes.
pub(crate) fn extract_defensive_js_sites(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::BinaryExpression(bin) => {
                check_no_arithmetic_on_optional_chained_operand(
                    semantic,
                    bin,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::LogicalExpression(log) => {
                check_no_nullish_coalescing_arithmetic_precedence(
                    log,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_predicate_in_logical(semantic, node_id, log, &subj_name, line_starts, sites);
            }
            AstKind::StaticMemberExpression(mem) => {
                check_no_array_find_result_member_access_without_guard(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_array_index_deref_without_bounds_or_empty_guard(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_deprecated_keyboard_event_keycode_which(
                    semantic,
                    node_id,
                    mem,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unsafe_json_parse_member(
                    semantic,
                    node_id,
                    mem.span,
                    &mem.object,
                    mem.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ComputedMemberExpression(comp) => {
                check_no_array_find_result_member_access_without_guard(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_array_index_deref_without_bounds_or_empty_guard(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unsafe_json_parse_member(
                    semantic,
                    node_id,
                    comp.span,
                    &comp.object,
                    comp.optional,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_no_object_keys_values_entries_on_maybe_undefined(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_non_literal_selector_query_without_try_catch(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_numeric_input_parse(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_throwing_parse_call(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_collapse_request_error_to_empty_state_call(
                    semantic,
                    call,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_loading_flag_reset_outside_finally(
                    semantic,
                    node_id,
                    call,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::NewExpression(new_expr) => {
                check_no_unescaped_dynamic_string_in_regexp(
                    semantic,
                    new_expr,
                    &subj_name,
                    line_starts,
                    sites,
                );
                check_no_unguarded_throwing_new_url(
                    semantic,
                    node_id,
                    new_expr,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TSNonNullExpression(non_null) => {
                check_no_non_null_assertion_on_maybe_undefined_result(
                    semantic,
                    non_null,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TemplateLiteral(tpl) => {
                check_no_object_or_array_coerced_to_string_in_template_literal(
                    semantic,
                    node_id,
                    tpl,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::IfStatement(if_stmt) => {
                check_predicate_in_condition(
                    semantic,
                    &if_stmt.test,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::ConditionalExpression(cond) => {
                check_predicate_in_condition(semantic, &cond.test, &subj_name, line_starts, sites);
            }
            AstKind::WhileStatement(while_stmt) => {
                check_predicate_in_condition(
                    semantic,
                    &while_stmt.test,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::UnaryExpression(un) if un.operator == UnaryOperator::LogicalNot => {
                check_predicate_in_condition(
                    semantic,
                    &un.argument,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::FormalParameter(param) => {
                check_no_whole_object_default_losing_per_key_defaults(
                    semantic,
                    node_id,
                    param,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_jsx_event_handler_defensive_rules(
                    semantic,
                    opening,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::TryStatement(try_stmt) => {
                check_no_collapse_request_error_in_try_catch(
                    semantic,
                    try_stmt,
                    subjects,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }

    check_no_passive_request_owner_ref(semantic, line_starts, sites);
}

// ---------------------------------------------------------------------------
// Shared AST / Scope Helpers
// ---------------------------------------------------------------------------
fn resolve_symbol_id(semantic: &Semantic<'_>, ident: &IdentifierReference<'_>) -> Option<SymbolId> {
    resolve_ident_symbol(semantic, ident)
}

fn get_var_declarator_init<'a>(
    semantic: &'a Semantic<'a>,
    sym_id: SymbolId,
) -> Option<&'a Expression<'a>> {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) {
        decl.init.as_ref()
    } else {
        None
    }
}

fn is_inside_optional_chain_parent(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let kind = semantic.nodes().kind(anc_id);
        if matches!(kind, AstKind::ChainExpression(_)) {
            return true;
        }
        if kind.is_statement() || kind.is_declaration() {
            break;
        }
    }
    false
}

fn is_inside_try_block(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let node_span = semantic.nodes().kind(node_id).span();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::TryStatement(try_stmt) => {
                if node_span.start >= try_stmt.block.span.start
                    && node_span.end <= try_stmt.block.span.end
                {
                    return true;
                }
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            _ => {}
        }
    }
    false
}

fn enclosing_function_or_program_start(semantic: &Semantic<'_>, node_id: NodeId) -> u32 {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                if let Some(body) = &func.body {
                    return body.span.start;
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => return arrow.body.span().start,
            _ => {}
        }
    }
    0
}

fn enclosing_function_span(semantic: &Semantic<'_>, node_id: NodeId) -> Span {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => {
                if let Some(body) = &func.body {
                    return body.span;
                }
            }
            AstKind::ArrowFunctionExpression(arrow) => return arrow.body.span(),
            _ => {}
        }
    }
    Span::new(0, semantic.source_text().len() as u32)
}

fn has_nullish_guard_before(semantic: &Semantic<'_>, before_offset: u32, var_name: &str) -> bool {
    let src = semantic
        .source_text()
        .get(..before_offset as usize)
        .unwrap_or_default();
    src.contains(&format!("if (!{var_name})"))
        || src.contains(&format!("if ({var_name})"))
        || src.contains(&format!("if ({var_name} == null)"))
        || src.contains(&format!("if ({var_name} != null)"))
        || src.contains(&format!("if ({var_name} === undefined)"))
        || src.contains(&format!("if ({var_name} !== undefined)"))
}

fn is_guarded_in_enclosing_short_circuit(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    var_name: &str,
) -> bool {
    let node_span = semantic.nodes().kind(node_id).span();
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::LogicalExpression(log) if log.operator == LogicalOperator::And => {
                if node_span.start >= log.right.span().start {
                    let left_src = log.left.span().source_text(semantic.source_text());
                    if left_src.contains(var_name) {
                        return true;
                    }
                }
            }
            AstKind::ConditionalExpression(cond) => {
                if node_span.start >= cond.consequent.span().start {
                    let test_src = cond.test.span().source_text(semantic.source_text());
                    if test_src.contains(var_name) {
                        return true;
                    }
                }
            }
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::*;
    use crate::{ir::compute_line_starts, rules::types::RuleId};

    fn run_defensive_js(src: &str) -> Vec<SemanticRuleSite> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let semantic = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let line_starts = compute_line_starts(src);
        let mut sites = Vec::new();
        extract_defensive_js_sites(&semantic, &[], &line_starts, &mut sites);
        sites
    }

    #[test]
    fn extracts_nullish_and_collection_sites() {
        let src = r#"
export function Cart({ items, user }: { items: any[]; user?: any }, config = { retries: 3 }) {
    const total = user?.count + 1;
    const matchName = items.find((x) => x.id === 1).name;
    const firstTitle = items[0].title;
    const forced = items.find((x) => x.active)!;
    const calc = user?.discount ?? 0 + 5;
    const keys = Object.keys(user?.prefs);
    const meta = { role: "admin" };
    const summary = `Meta: ${meta}`;
    return <div>{total}{matchName}{firstTitle}{String(forced)}{calc}{keys.length}{summary}{config.retries}</div>;
}
"#;
        let sites = run_defensive_js(src);
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoArithmeticOnOptionalChainedOperand)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoArrayFindResultMemberAccessWithoutGuard)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoArrayIndexDerefWithoutBoundsOrEmptyGuard)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoNonNullAssertionOnMaybeUndefinedResult)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoNullishCoalescingArithmeticPrecedence)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoObjectKeysValuesEntriesOnMaybeUndefined)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoObjectOrArrayCoercedToStringInTemplateLiteral)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoWholeObjectDefaultLosingPerKeyDefaults)
        );
    }

    #[test]
    fn extracts_async_and_event_sites_with_autofix() {
        let src = r#"
import { useEffect, useRef } from "react";

export function SearchForm({ query }: { query: string }) {
    const ownerRef = useRef(query);
    const isReady = () => true;

    useEffect(() => {
        ownerRef.current = query;
    }, [query]);

    useEffect(() => {
        fetch(`/api?q=${query}`).then((r) => {
            if (ownerRef.current === query) {
                console.log(r);
            }
        });
    }, [query]);

    const load = async () => {
        try {
            await fetch("/api");
        } catch {
            setItems([]);
        }
        setLoading(false);
    };

    if (isReady) {
        load();
    }

    return (
        <div>
            <input
                onKeyDown={(e) => {
                    if (e.keyCode === 13) {
                        console.log("Enter");
                    }
                    if (e.key === "Enter") {
                        console.log("submit");
                    }
                }}
            />
            <button
                onClick={async () => {
                    await fetch("/api");
                    setDone(true);
                }}
                onMouseEnter={() => {
                    fetch("/ping").then((r) => r.json());
                }}
            />
        </div>
    );
}
"#;
        let sites = run_defensive_js(src);
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoAsyncEventHandlerWithoutReentryGuard)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoEnterSubmitWithoutImeCompositionGuard)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoFloatingThenInJsxHandler)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoCollapseRequestErrorToEmptyState)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoLoadingFlagResetOutsideFinally)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoPassiveRequestOwnerRef)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoPredicateFunctionReferenceInBooleanPosition)
        );
        let keycode_site = sites
            .iter()
            .find(|s| s.rule == RuleId::NoDeprecatedKeyboardEventKeycodeWhich)
            .expect("expected NoDeprecatedKeyboardEventKeycodeWhich site");
        assert!(keycode_site.autofix.is_some());
    }

    #[test]
    fn extracts_parsing_and_selector_sites() {
        let src = r#"
export function Inspector({ selector, pattern, rawUrl, rawJson }: { selector: string; pattern: string; rawUrl: string; rawJson: string }) {
    const el = document.querySelector(selector);
    const re = new RegExp(pattern);
    const url = new URL(rawUrl);
    const decoded = decodeURIComponent(rawUrl);
    const parsedName = JSON.parse(rawJson).name;
    return (
        <input
            onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                console.log(el, re, url, decoded, parsedName, n);
            }}
        />
    );
}
"#;
        let sites = run_defensive_js(src);
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoNonLiteralSelectorQueryWithoutTryCatch)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoUnescapedDynamicStringInRegexp)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoUnguardedNumericInputParse)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoUnguardedThrowingParseCall
                    && s.target_name == "new URL")
        );
        assert!(sites.iter().any(|s| {
            s.rule == RuleId::NoUnguardedThrowingParseCall && s.target_name == "decodeURIComponent"
        }));
        assert!(sites.iter().any(|s| s.rule == RuleId::NoUnsafeJsonParse));
    }
}
