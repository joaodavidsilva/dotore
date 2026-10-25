//! Shared `oxc` AST/semantic matchers, JSX attribute inspectors, import binding resolvers,
//! and [`Diagnostic`] / [`SemanticRuleSite`] builders for `dotore-js` rule modules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; matcher helpers match only relevant AST node kinds"
)]

mod jsx;

use std::{
    collections::HashSet,
    path::PathBuf,
};

use oxc_ast::{
    AstKind,
    ast::{
        CallExpression, Expression, IdentifierReference, ImportDeclarationSpecifier, Program,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolFlags, SymbolId};
use oxc_span::Span;

pub(crate) use jsx::*;

use crate::{
    ir::{
        ByteSpan, FileIr, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::{AutofixPatch, Diagnostic, PrescriptionTier, RuleId},
};
// =============================================================================
// 1. Span, Line Offset & Diagnostic / SemanticRuleSite Builders
// =============================================================================

/// Converts an [`oxc_span::Span`] into a [`ByteSpan`].
#[must_use]
pub(crate) const fn span_to_byte_span(span: Span) -> ByteSpan {
    ByteSpan {
        start: span.start,
        end: span.end,
    }
}

/// Converts a 0-based byte offset into a 1-based [`SourceLoc`] using precomputed `line_starts`.
#[must_use]
pub(crate) fn offset_to_loc(line_starts: &[u32], byte_offset: u32) -> SourceLoc {
    loc_from_line_starts(line_starts, byte_offset)
}

/// Converts an [`oxc_span::Span`] into both a 1-based [`SourceLoc`] and a [`ByteSpan`].
#[must_use]
pub(crate) fn span_to_loc_and_byte_span(line_starts: &[u32], span: Span) -> (SourceLoc, ByteSpan) {
    (
        loc_from_line_starts(line_starts, span.start),
        span_to_byte_span(span),
    )
}

/// Constructs a [`Diagnostic`] for `rule` using `Diagnostic::for_rule` from `dotore-core`,
/// populating default category, severity, tier, docs URL, and setting `target_name` to `rule.as_str()`.
#[must_use]
pub(crate) fn make_diag(
    rule: RuleId,
    file: impl Into<PathBuf>,
    loc: SourceLoc,
    span: ByteSpan,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic::for_rule(rule, file, loc, span, message)
}

/// Constructs a [`Diagnostic`] for `rule` from an [`oxc_span::Span`] and `line_starts`.
#[must_use]
pub(crate) fn make_diag_at_offset(
    rule: RuleId,
    file: impl Into<PathBuf>,
    line_starts: &[u32],
    span: Span,
    message: impl Into<String>,
) -> Diagnostic {
    let (loc, byte_span) = span_to_loc_and_byte_span(line_starts, span);
    Diagnostic::for_rule(rule, file, loc, byte_span, message)
}

/// Constructs a [`Diagnostic`] scoped to an enclosing **Subject** with an explicit `target_name` and `message_id`.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a Subject-scoped Diagnostic directly from rule metadata and site location"
)]
pub(crate) fn make_diag_for_subject(
    rule: RuleId,
    file: impl Into<PathBuf>,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
    loc: SourceLoc,
    span: ByteSpan,
) -> Diagnostic {
    Diagnostic::new(rule, file, loc, span, target_name, message)
        .with_subject(subject_name)
        .with_message_id(message_id)
}

/// Constructs an `Autofix`-tier [`Diagnostic`] with the given [`AutofixPatch`].
#[must_use]
pub(crate) fn make_autofix_diag(
    rule: RuleId,
    file: impl Into<PathBuf>,
    loc: SourceLoc,
    span: ByteSpan,
    message: impl Into<String>,
    patch: AutofixPatch,
) -> Diagnostic {
    Diagnostic::for_rule(rule, file, loc, span, message)
        .with_tier(PrescriptionTier::Autofix)
        .with_patch(patch)
}

/// Appends a [`Diagnostic`] for `file` to `out` using [`Diagnostic::new`].
#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a Diagnostic from rule metadata and site location without intermediate allocation"
)]
pub(crate) fn push_simple_diagnostic(
    out: &mut Vec<Diagnostic>,
    file: &FileIr,
    subject_name: Option<String>,
    rule: RuleId,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
) {
    out.push(make_diag_for_subject(
        rule,
        file.path.clone(),
        subject_name,
        message_id,
        target_name,
        message,
        loc,
        span,
    ));
}

/// Constructs a [`SemanticRuleSite`] from an [`oxc_span::Span`] and `line_starts`.
#[must_use]
fn make_semantic_site(
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
    line_starts: &[u32],
    span: Span,
) -> SemanticRuleSite {
    let (loc, byte_span) = span_to_loc_and_byte_span(line_starts, span);
    SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.into(),
        message: message.into(),
        loc,
        span: byte_span,
        autofix: None,
    }
}

/// Appends a [`SemanticRuleSite`] (without autofix) to `sites`.
#[expect(
    clippy::too_many_arguments,
    reason = "Pushes a SemanticRuleSite directly to the output vector"
)]
pub(crate) fn push_semantic_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    line_starts: &[u32],
    span: Span,
) {
    sites.push(make_semantic_site(
        rule,
        subject_name,
        message_id,
        target_name,
        message,
        line_starts,
        span,
    ));
}

/// Appends a [`SemanticRuleSite`] with an optional [`AutofixPatch`] to `sites`.
#[expect(
    clippy::too_many_arguments,
    reason = "Pushes a SemanticRuleSite with optional AutofixPatch directly to the output vector"
)]
pub(crate) fn push_semantic_site_with_fix(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    line_starts: &[u32],
    span: Span,
    autofix: Option<AutofixPatch>,
) {
    let mut site = make_semantic_site(
        rule,
        subject_name,
        message_id,
        target_name,
        message,
        line_starts,
        span,
    );
    site.autofix = autofix;
    sites.push(site);
}

// =============================================================================
// 2. Expression Unwrapping & Hook / Callee / Member / Symbol Matching
// =============================================================================

/// Unwraps parentheses and TypeScript type-assertion wrappers (`as`, `satisfies`, `!`, `<T>`, instantiation).
#[must_use]
pub(crate) fn unparenthesized<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(e) => expr = &e.expression,
            Expression::TSSatisfiesExpression(e) => expr = &e.expression,
            Expression::TSNonNullExpression(e) => expr = &e.expression,
            Expression::TSTypeAssertion(e) => expr = &e.expression,
            Expression::TSInstantiationExpression(e) => expr = &e.expression,
            _ => return expr,
        }
    }
}

/// Alias for [`unparenthesized`].
#[must_use]
pub(crate) fn unwrap_expr<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    unparenthesized(expr)
}

/// Extracts the short identifier or static member property name of a `CallExpression` callee.
#[must_use]
pub(crate) fn callee_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match unparenthesized(callee) {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

/// Extracts `(receiver_object, property_name)` from a static or string-literal computed member expression.
#[must_use]
pub(crate) fn member_call_parts<'a>(
    expr: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a str)> {
    match unparenthesized(expr) {
        Expression::StaticMemberExpression(mem) => {
            Some((unparenthesized(&mem.object), mem.property.name.as_str()))
        }
        Expression::ComputedMemberExpression(comp) => {
            if let Expression::StringLiteral(lit) = unparenthesized(&comp.expression)
                && let Some(prop) = lit.value.as_str()
            {
                return Some((unparenthesized(&comp.object), prop));
            }
            None
        }
        _ => None,
    }
}

/// Returns `true` if `name` follows React's hook naming convention (`use` or `use<Uppercase>...`).
#[must_use]
pub(crate) fn is_hook_name(name: &str) -> bool {
    name == "use" || is_custom_hook_name(name)
}

/// Returns `true` if `name` is a valid custom/built-in hook identifier (`use<Uppercase>...`).
#[must_use]
pub(crate) fn is_custom_hook_name(name: &str) -> bool {
    name.starts_with("use") && name.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase)
}

/// Returns `true` if `name` is a PascalCase React component identifier (`MyComponent`).
#[must_use]
pub(crate) fn is_component_name(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
}

/// Checks if a callee expression invokes a specific React hook (`useState`, `useEffect`, `useRef`),
/// supporting direct calls, `React.<hook>`, and renamed imports (`import { useState as s } from 'react'`).
#[must_use]
pub(crate) fn is_react_hook_callee(
    semantic: &Semantic<'_>,
    callee: &Expression<'_>,
    hook_name: &str,
) -> bool {
    match unparenthesized(callee) {
        Expression::Identifier(ident) => {
            if ident.name == hook_name {
                return true;
            }
            let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
                return false;
            };
            is_imported_react_hook_symbol(semantic, sym_id, hook_name)
        }
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == hook_name
                && matches!(
                    unparenthesized(&mem.object),
                    Expression::Identifier(obj) if obj.name == "React"
                )
        }
        _ => false,
    }
}

fn is_imported_react_hook_symbol(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    hook_name: &str,
) -> bool {
    if !semantic
        .scoping()
        .symbol_flags(sym_id)
        .contains(SymbolFlags::Import)
    {
        return false;
    }
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::ImportSpecifier(spec) = semantic.nodes().kind(decl_id) {
        return spec.imported.name() == hook_name;
    }
    false
}

/// Checks if `node_id` (an identifier or call callee) refers to `hook_name` (`useState`, `useRef`).
#[must_use]
pub(crate) fn is_react_hook_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    hook_name: &str,
) -> bool {
    match semantic.nodes().kind(node_id) {
        AstKind::IdentifierReference(ident) => {
            if ident.name == hook_name {
                return true;
            }
            if let Some(sym_id) = resolve_ident_symbol(semantic, ident)
                && is_imported_react_hook_symbol(semantic, sym_id, hook_name)
            {
                return true;
            }
            if let AstKind::StaticMemberExpression(mem) = semantic.nodes().parent_kind(node_id) {
                return mem.property.name == hook_name
                    && matches!(
                        unparenthesized(&mem.object),
                        Expression::Identifier(obj) if obj.name == "React"
                    );
            }
            false
        }
        AstKind::CallExpression(call) => is_react_hook_callee(semantic, &call.callee, hook_name),
        _ => false,
    }
}

/// Checks if `call` is a `useEffect(...)` call (excluding `useLayoutEffect`).
#[must_use]
pub(crate) fn is_use_effect_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    is_react_hook_callee(semantic, &call.callee, "useEffect")
}

/// Checks if `call` invokes `hook_name` either directly (`hook_name(...)`) or as `<Obj>.<hook_name>(...)`.
#[must_use]
pub(crate) fn is_named_hook_call(call: &CallExpression<'_>, hook_name: &str) -> bool {
    callee_name(&call.callee) == Some(hook_name)
}

/// Checks if `call` is one of the standard React hooks accepting a dependency array (`useEffect`, `useLayoutEffect`, `useMemo`, `useCallback`).
#[must_use]
pub(crate) fn is_hook_with_deps_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    ["useEffect", "useLayoutEffect", "useMemo", "useCallback"]
        .iter()
        .any(|h| is_react_hook_callee(semantic, &call.callee, h))
}

/// Resolves an [`IdentifierReference`] to its declared [`SymbolId`] in `semantic`, if bound.
#[must_use]
pub(crate) fn resolve_ident_symbol(
    semantic: &Semantic<'_>,
    ident: &IdentifierReference<'_>,
) -> Option<SymbolId> {
    let ref_id = ident.reference_id.get()?;
    semantic.scoping().get_reference(ref_id).symbol_id()
}

/// Returns `true` if `ident` has no local lexical binding in `semantic` (i.e. refers to a global).
#[must_use]
pub(crate) fn is_global_ident(semantic: &Semantic<'_>, ident: &IdentifierReference<'_>) -> bool {
    resolve_ident_symbol(semantic, ident).is_none()
}

// =============================================================================
// 5. Import Binding Resolution Helpers
// =============================================================================

/// Checks if `program` contains a static `import` declaration from any module in `allowed_sources`.
#[must_use]
pub(crate) fn has_import_from(program: &Program<'_>, allowed_sources: &[&str]) -> bool {
    for stmt in &program.body {
        if let Statement::ImportDeclaration(imp) = stmt
            && let Some(src) = imp.source.value.as_str()
            && allowed_sources.contains(&src)
        {
            return true;
        }
    }
    false
}

/// Collects all local identifier names imported from any module in `allowed_sources`.
#[must_use]
pub(crate) fn imported_local_names_from(
    program: &Program<'_>,
    allowed_sources: &[&str],
) -> HashSet<String> {
    let mut names = HashSet::new();
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.import_kind.is_type() {
            continue;
        }
        let Some(src) = imp.source.value.as_str() else {
            continue;
        };
        if !allowed_sources.contains(&src) {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) if !s.import_kind.is_type() => {
                    names.insert(s.local.name.to_string());
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(d) => {
                    names.insert(d.local.name.to_string());
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                    names.insert(ns.local.name.to_string());
                }
                _ => {}
            }
        }
    }
    names
}

/// Resolves the module specifier string (`"react"`, `"./utils"`) for an imported [`SymbolId`].
#[must_use]
pub(crate) fn resolve_import_source(semantic: &Semantic<'_>, sym_id: SymbolId) -> Option<String> {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    for anc_id in std::iter::once(decl_id).chain(semantic.nodes().ancestor_ids(decl_id)) {
        if let AstKind::ImportDeclaration(import_decl) = semantic.nodes().kind(anc_id) {
            return import_decl.source.value.as_str().map(str::to_string);
        }
    }
    None
}

/// Returns `true` if `ident` resolves to an import binding from any module in `allowed_sources`.
#[must_use]
pub(crate) fn is_identifier_from_package(
    semantic: &Semantic<'_>,
    ident: &IdentifierReference<'_>,
    allowed_sources: &[&str],
) -> bool {
    let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
        return false;
    };
    let Some(src) = resolve_import_source(semantic, sym_id) else {
        return false;
    };
    allowed_sources.contains(&src.as_str())
}

/// Returns `true` if `sym_id` is a named import `imported_name` from any module in `allowed_sources`.
#[must_use]
pub(crate) fn is_named_import_from(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    imported_name: &str,
    allowed_sources: &[&str],
) -> bool {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let AstKind::ImportSpecifier(spec) = semantic.nodes().kind(decl_id) else {
        return false;
    };
    if spec.imported.name() != imported_name {
        return false;
    }
    resolve_import_source(semantic, sym_id)
        .is_some_and(|src| allowed_sources.contains(&src.as_str()))
}

/// Returns `true` if `sym_id` is a namespace import (`import * as ns`) from any module in `allowed_sources`.
#[must_use]
pub(crate) fn is_namespace_import_from(
    semantic: &Semantic<'_>,
    sym_id: SymbolId,
    allowed_sources: &[&str],
) -> bool {
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if !matches!(
        semantic.nodes().kind(decl_id),
        AstKind::ImportNamespaceSpecifier(_)
    ) {
        return false;
    }
    resolve_import_source(semantic, sym_id)
        .is_some_and(|src| allowed_sources.contains(&src.as_str()))
}


/// Extracts identifier names from the second (`deps`) array argument of a hook call (`useEffect(fn, [a, b])`).
#[must_use]
pub(crate) fn collect_effect_dep_ident_names(call: &CallExpression<'_>) -> HashSet<String> {
    let mut dep_names = HashSet::new();
    if let Some(deps_arg) = call.arguments.get(1).and_then(|a| a.as_expression())
        && let Expression::ArrayExpression(arr) = deps_arg.without_parentheses()
    {
        for elem in &arr.elements {
            if let Some(Expression::Identifier(id)) =
                elem.as_expression().map(Expression::without_parentheses)
            {
                dep_names.insert(id.name.to_string());
            }
        }
    }
    dep_names
}
#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::Path};

    use oxc_allocator::Allocator;
    use oxc_ast::ast::BindingPattern;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::*;
    use crate::ir::compute_line_starts;
    #[test]
    fn matchers_unwrap_callee_and_hook_predicates() {
        let src = r#"
import { useState as useLocalState, useEffect } from "react";
import * as R from "react";

export function Counter() {
    const [count, setCount] = (useLocalState as any)(0);
    useEffect(() => {}, [count]);
    R.useMemo(() => count + 1, [count]);
    window["requestAnimationFrame"](() => {});
    return null;
}
"#;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let sem = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;

        assert!(is_hook_name("use"));
        assert!(is_hook_name("useState"));
        assert!(!is_hook_name("use_state"));
        assert!(is_component_name("Counter"));
        assert!(!is_component_name("counter"));

        let mut saw_aliased_use_state = false;
        let mut saw_use_effect = false;
        let mut saw_named_memo = false;
        let mut saw_computed_member = false;

        for (node_id, node) in sem.nodes().iter_enumerated() {
            if let AstKind::CallExpression(call) = node.kind() {
                if is_react_hook_callee(&sem, &call.callee, "useState")
                    && is_react_hook_node(&sem, node_id, "useState")
                {
                    saw_aliased_use_state = true;
                }
                if is_use_effect_call(&sem, call) && is_hook_with_deps_call(&sem, call) {
                    saw_use_effect = true;
                }
                if is_named_hook_call(call, "useMemo")
                    && callee_name(&call.callee) == Some("useMemo")
                {
                    saw_named_memo = true;
                }
                if let Some((obj, prop)) = member_call_parts(&call.callee)
                    && prop == "requestAnimationFrame"
                    && let Expression::Identifier(id) = unwrap_expr(obj)
                {
                    assert!(is_global_ident(&sem, id));
                    saw_computed_member = true;
                }
            }
        }

        assert!(saw_aliased_use_state);
        assert!(saw_use_effect);
        assert!(saw_named_memo);
        assert!(saw_computed_member);
    }

    #[test]
    fn matchers_inspect_jsx_attributes_and_object_properties() {
        let src = r#"
const CLS = "px-4";
export function Card(props: any) {
    return (
        <Dialog.Content
            id="main-dialog"
            className={CLS}
            disabled
            aria-label={`Settings`}
            style={{ zIndex: 9999, position: "fixed", hidden: false }}
            {...props}
        >
            <span />
        </Dialog.Content>
    );
}
"#;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let sem = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;

        let mut const_strings = HashMap::new();
        for node in sem.nodes() {
            if let AstKind::VariableDeclarator(decl) = node.kind()
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && let Some(sym_id) = id.symbol_id.get()
                && let Some(init) = &decl.init
                && let Some(val) = eval_static_str(&sem, init, &const_strings)
            {
                const_strings.insert(sym_id, val);
            }
        }

        let mut checked_jsx = false;
        for node in sem.nodes() {
            if let AstKind::JSXElement(jsx_el) = node.kind() {
                let opening = &jsx_el.opening_element;
                if get_jsx_tag_name(&opening.name) != "Dialog.Content" {
                    continue;
                }
                checked_jsx = true;
                assert_eq!(jsx_opening_tag_name(opening).as_deref(), Some("Content"));
                assert!(has_jsx_attr(&opening.attributes, "id"));
                assert!(has_jsx_truthy_attr(&opening.attributes, "disabled"));
                assert!(jsx_has_spread_attr(&opening.attributes));
                assert!(find_jsx_attr_ignore_case(&opening.attributes, "ARIA-LABEL").is_some());
                assert!(find_last_attr(&opening.attributes, "id").is_some());

                let id_attr = find_attr(&opening.attributes, "id").expect("id attr");
                assert_eq!(jsx_attr_string_value(id_attr), Some("main-dialog"));
                assert_eq!(
                    get_class_name_str(opening, &sem, &const_strings).as_deref(),
                    Some("px-4")
                );
                assert_eq!(
                    get_style_prop_str(opening, "position", &sem, &const_strings).as_deref(),
                    Some("fixed")
                );
                assert_eq!(get_style_prop_number(opening, "zIndex"), Some(9999.0));

                if let Some(Expression::ObjectExpression(style_obj)) =
                    jsx_attr_expr(&opening.attributes, "style")
                {
                    assert_eq!(
                        get_object_prop_static_str(style_obj, "position"),
                        Some("fixed")
                    );
                    assert_eq!(get_object_prop_bool(style_obj, "hidden"), Some(false));
                    assert_eq!(get_object_prop_number(style_obj, "zIndex"), Some(9999.0));
                    let first_prop = get_object_prop(style_obj, "zIndex").expect("zIndex prop");
                    assert_eq!(
                        property_key_name(&first_prop.key).as_deref(),
                        Some("zIndex")
                    );
                } else {
                    panic!("expected style object expression");
                }

                assert!(subtree_has_tag_matching(jsx_el, |t| t == "span"));
            }
        }
        assert!(checked_jsx);
    }

    #[test]
    fn matchers_resolve_imports_and_build_diagnostics() {
        let src = r#"
import { motion as m } from "framer-motion";
import * as Router from "react-router";

export const Box = m.div;
export const nav = Router.useNavigate;
"#;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let sem = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;

        assert!(has_import_from(&parsed.program, &["framer-motion"]));
        let locals = imported_local_names_from(&parsed.program, &["framer-motion", "react-router"]);
        assert!(locals.contains("m"));
        assert!(locals.contains("Router"));

        for node in sem.nodes() {
            if let AstKind::IdentifierReference(ident) = node.kind() {
                if ident.name == "m" {
                    assert!(is_identifier_from_package(&sem, ident, &["framer-motion"]));
                    let sym_id = resolve_ident_symbol(&sem, ident).expect("m symbol");
                    assert!(is_named_import_from(
                        &sem,
                        sym_id,
                        "motion",
                        &["framer-motion"]
                    ));
                }
                if ident.name == "Router" {
                    let sym_id = resolve_ident_symbol(&sem, ident).expect("Router symbol");
                    assert!(is_namespace_import_from(&sem, sym_id, &["react-router"]));
                }
            }
        }

        let line_starts = compute_line_starts(src);
        let loc = offset_to_loc(&line_starts, 1);
        assert_eq!(loc.line, 2);

        let diag = make_diag(
            RuleId::NoDerivedState,
            Path::new("Box.tsx"),
            loc,
            ByteSpan { start: 1, end: 10 },
            "test message",
        );
        assert_eq!(diag.rule, RuleId::NoDerivedState);
        assert_eq!(diag.target_name, "no-derived-state");

        let offset_diag = make_diag_at_offset(
            RuleId::NoDerivedState,
            Path::new("Box.tsx"),
            &line_starts,
            Span::new(1, 10),
            "offset message",
        );
        assert_eq!(offset_diag.loc.line, 2);

        let fix_diag = make_autofix_diag(
            RuleId::NoDerivedState,
            Path::new("Box.tsx"),
            loc,
            ByteSpan { start: 1, end: 10 },
            "fix message",
            AutofixPatch::delete("remove node", ByteSpan { start: 1, end: 10 }),
        );
        assert_eq!(fix_diag.tier, PrescriptionTier::Autofix);
        assert!(fix_diag.autofix.is_some());

        let mut sites = Vec::new();
        push_semantic_site(
            &mut sites,
            RuleId::NoDerivedState,
            Some("Box".to_string()),
            "msgId",
            "target",
            "site msg".to_string(),
            &line_starts,
            Span::new(1, 5),
        );
        push_semantic_site_with_fix(
            &mut sites,
            RuleId::NoDerivedState,
            None,
            "msgId2",
            "target2",
            "site msg 2".to_string(),
            &line_starts,
            Span::new(6, 10),
            Some(AutofixPatch::delete("del", ByteSpan { start: 6, end: 10 })),
        );
        assert_eq!(sites.len(), 2);
        assert!(sites[1].autofix.is_some());
    }
}
