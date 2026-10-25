//! File-level, module-scope, class component, and legacy React API call lint parity rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; JSX and lint parity detectors match only relevant AST node kinds (#50)"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Class, ClassElement, Expression, IdentifierReference,
        ImportDeclarationSpecifier, ImportSpecifier, MethodDefinitionKind, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite, SubjectIr, SubjectKind,
        react_ast::{
            find_enclosing_react_node, get_subject_name, is_functional_component,
            is_react_component_class,
        },
    },
    matchers::{
        is_component_name, is_custom_hook_name, is_global_ident, is_hook_name,
        is_react_hook_callee, resolve_ident_symbol,
    },
    rules::types::RuleId,
};

use super::{
    BUILTIN_UPPERCASE_CALLS,
    dom_and_timer_teardown::{check_class_unmount_teardown, check_remove_listener_inline_handler},
    is_at_module_scope,
    jsx_element_parity::{check_jsx_element_rules, check_jsx_text_rules},
    push_site,
};

#[derive(Default)]
struct FileLevelScanState {
    first_jsx_span: Option<Span>,
    has_react_in_scope: bool,
    class_comp_spans: Vec<(String, Span)>,
}

pub(super) fn check_file_level_rules(
    path: &Path,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let mut state = FileLevelScanState::default();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        visit_file_level_node(semantic, node_id, node.kind(), &mut state, line_starts, sites);
    }

    if let Some(jsx_span) = state.first_jsx_span {
        if matches!(ext, "js" | "ts" | "mjs" | "cjs") {
            push_site(
                sites,
                RuleId::JsxFilenameExtension,
                None,
                "jsxFilenameExtension",
                ext,
                format!(
                    "JSX syntax is not allowed in `.{ext}` files; rename the file to `.jsx` or `.tsx`."
                ),
                jsx_span,
                line_starts,
                None,
            );
        }
        if !state.has_react_in_scope {
            push_site(
                sites,
                RuleId::ReactInJsxScope,
                None,
                "reactInJsxScope",
                "React",
                "`React` must be in scope when using JSX under the classic JSX transform."
                    .to_string(),
                jsx_span,
                line_starts,
                None,
            );
        }
    }

    emit_multi_component_findings(subjects, state.class_comp_spans, line_starts, sites);
}

fn visit_file_level_node(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    kind: AstKind<'_>,
    state: &mut FileLevelScanState,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match kind {
        AstKind::JSXElement(el) => {
            let _ = state.first_jsx_span.get_or_insert(el.span);
        }
        AstKind::JSXFragment(frag) => {
            let _ = state.first_jsx_span.get_or_insert(frag.span);
        }
        AstKind::ImportDeclaration(imp) => {
            if let Some(specs) = &imp.specifiers {
                for spec in specs {
                    record_file_import_specifier(spec, state, line_starts, sites);
                }
            }
        }
        AstKind::VariableDeclarator(decl) => {
            if decl
                .id
                .get_binding_identifier()
                .is_some_and(|id| id.name == "React")
            {
                state.has_react_in_scope = true;
            }
        }
        AstKind::Class(cls) => {
            if is_react_class_component(semantic, cls).is_some() {
                let name = cls
                    .id
                    .as_ref()
                    .map_or_else(|| "Component".to_string(), |id| id.name.to_string());
                state.class_comp_spans.push((name, cls.span));
            }
        }
        AstKind::CallExpression(call) if is_at_module_scope(semantic, node_id) => {
            check_module_scope_impure_call(semantic, call, line_starts, sites);
        }
        AstKind::NewExpression(new_expr)
            if is_at_module_scope(semantic, node_id)
                && matches!(
                    new_expr.callee.without_parentheses(),
                    Expression::Identifier(id) if id.name == "Date"
                )
                && new_expr.arguments.is_empty() =>
        {
            push_site(
                sites,
                RuleId::NoImpureCallAtModuleScope,
                None,
                "noImpureCallAtModuleScope",
                "new Date()",
                "`new Date()` at module scope runs once at module load and freezes the timestamp across requests.".to_string(),
                new_expr.span,
                line_starts,
                None,
            );
        }
        AstKind::IdentifierReference(ident) if is_at_module_scope(semantic, node_id) => {
            check_module_scope_browser_global(semantic, node_id, ident, line_starts, sites);
        }
        _ => {}
    }
}

fn record_file_import_specifier(
    spec: &ImportDeclarationSpecifier<'_>,
    state: &mut FileLevelScanState,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match spec {
        ImportDeclarationSpecifier::ImportDefaultSpecifier(def) if def.local.name == "React" => {
            state.has_react_in_scope = true;
        }
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) if ns.local.name == "React" => {
            state.has_react_in_scope = true;
        }
        ImportDeclarationSpecifier::ImportSpecifier(named) => {
            if named.local.name == "React" {
                state.has_react_in_scope = true;
            }
            check_hook_import_rename(named, line_starts, sites);
        }
        _ => {}
    }
}

fn emit_multi_component_findings(
    subjects: &[SubjectIr],
    class_comp_spans: Vec<(String, Span)>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut comp_entries: Vec<(String, Span)> = subjects
        .iter()
        .filter(|s| s.kind == SubjectKind::Component)
        .map(|s| {
            (
                s.name.clone().unwrap_or_else(|| "Component".to_string()),
                Span::new(s.span.start, s.span.end),
            )
        })
        .collect();
    comp_entries.extend(class_comp_spans);
    comp_entries.sort_by_key(|(_, span)| span.start);

    for (comp_name, comp_span) in comp_entries.iter().skip(1) {
        push_site(
            sites,
            RuleId::NoMultiComp,
            Some(comp_name.clone()),
            "noMultiComp",
            comp_name.clone(),
            format!(
                "Declare only one React component per file; `{comp_name}` is an additional component in this module."
            ),
            *comp_span,
            line_starts,
            None,
        );
        push_site(
            sites,
            RuleId::NoMultiComponentFile,
            Some(comp_name.clone()),
            "noMultiComponentFile",
            comp_name.clone(),
            format!("File declares multiple React components including `{comp_name}`."),
            *comp_span,
            line_starts,
            None,
        );
    }
}

fn check_hook_import_rename(
    named: &ImportSpecifier<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let imported = named.imported.name().as_str();
    let local = named.local.name.as_str();
    if imported == local || !is_hook_name(imported) {
        return;
    }
    let loses_prefix = !is_custom_hook_name(local);
    let renames_lint_specific_react_hook = matches!(
        imported,
        "useEffect"
            | "useLayoutEffect"
            | "useInsertionEffect"
            | "useImperativeHandle"
            | "useEffectEvent"
            | "experimental_useEffectEvent"
    );
    if loses_prefix || renames_lint_specific_react_hook {
        push_site(
            sites,
            RuleId::HookImportRenameLosesUsePrefix,
            None,
            "hookImportRenameLosesUsePrefix",
            local,
            format!(
                "Importing hook `{imported}` as `{local}` breaks hook lint semantics; keep a `use*` prefix and preserve built-in effect hook names."
            ),
            named.span,
            line_starts,
            None,
        );
    }
}

fn check_module_scope_impure_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_text = call
        .callee
        .without_parentheses()
        .span()
        .source_text(semantic.source_text());
    if matches!(
        callee_text,
        "Math.random"
            | "Date.now"
            | "performance.now"
            | "crypto.randomUUID"
            | "crypto.getRandomValues"
            | "nanoid"
            | "uuid"
            | "uuidv4"
            | "v4"
    ) {
        push_site(
            sites,
            RuleId::NoImpureCallAtModuleScope,
            None,
            "noImpureCallAtModuleScope",
            callee_text,
            format!(
                "`{callee_text}()` at module scope runs once at module load and freezes its value across SSR requests."
            ),
            call.span,
            line_starts,
            None,
        );
    }
}

fn check_module_scope_browser_global(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ident: &IdentifierReference<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let name = ident.name.as_str();
    if !matches!(
        name,
        "window" | "document" | "navigator" | "localStorage" | "sessionStorage" | "location"
    ) || !is_global_ident(semantic, ident)
    {
        return;
    }
    if let AstKind::UnaryExpression(un) = semantic.nodes().parent_kind(node_id)
        && un.operator == UnaryOperator::Typeof
    {
        return;
    }
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_span = semantic.nodes().get_node(anc_id).span();
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ConditionalExpression(_)
                | AstKind::LogicalExpression(_)
                | AstKind::IfStatement(_)
        ) {
            let text = anc_span.source_text(semantic.source_text());
            if text.contains("typeof window") || text.contains(&format!("typeof {name}")) {
                return;
            }
        }
    }

    push_site(
        sites,
        RuleId::NoUnguardedBrowserGlobalAtModuleScope,
        None,
        "noUnguardedBrowserGlobalAtModuleScope",
        name,
        format!(
            "Reading browser global `{name}` at module scope without a `typeof {name} !== \"undefined\"` guard throws during SSR."
        ),
        ident.span,
        line_starts,
        None,
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReactClassKind {
    Component,
    PureComponent,
}

fn is_react_class_component(semantic: &Semantic<'_>, cls: &Class<'_>) -> Option<ReactClassKind> {
    let source = semantic.source_text();
    if !is_react_component_class(cls, source) {
        return None;
    }
    let header = Span::new(cls.span.start, cls.body.span.start).source_text(source);
    if header.contains("PureComponent") {
        Some(ReactClassKind::PureComponent)
    } else {
        Some(ReactClassKind::Component)
    }
}

pub(super) fn check_class_component_rules(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::Class(cls) = node.kind() else {
            continue;
        };
        let Some(class_kind) = is_react_class_component(semantic, cls) else {
            continue;
        };
        let class_name = cls
            .id
            .as_ref()
            .map_or_else(|| "Component".to_string(), |id| id.name.to_string());

        let (mount_or_ctor_spans, unmount_span) =
            check_class_methods(semantic, cls, class_kind, &class_name, line_starts, sites);

        check_class_unmount_teardown(
            semantic,
            &class_name,
            &mount_or_ctor_spans,
            unmount_span,
            line_starts,
            sites,
        );
        check_class_this_set_state_and_is_mounted(semantic, cls, &class_name, line_starts, sites);
    }
}

fn check_class_methods(
    semantic: &Semantic<'_>,
    cls: &Class<'_>,
    class_kind: ReactClassKind,
    class_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) -> (Vec<Span>, Option<Span>) {
    let mut mount_or_ctor_spans: Vec<Span> = Vec::new();
    let mut unmount_span: Option<Span> = None;

    for elem in &cls.body.body {
        let ClassElement::MethodDefinition(method) = elem else {
            continue;
        };
        let static_key = method.key.static_name();
        let method_name = static_key
            .as_ref()
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        if method.kind == MethodDefinitionKind::Constructor || method_name == "componentDidMount" {
            mount_or_ctor_spans.push(method.value.span);
        } else if method_name == "componentWillUnmount" {
            unmount_span = Some(method.value.span);
        } else if method_name == "shouldComponentUpdate"
            && class_kind == ReactClassKind::PureComponent
        {
            push_site(
                sites,
                RuleId::NoRedundantShouldComponentUpdate,
                Some(class_name.to_string()),
                "noRedundantShouldComponentUpdate",
                class_name,
                format!(
                    "`{class_name}` extends `PureComponent` and defines `shouldComponentUpdate`, which is redundant."
                ),
                method.span,
                line_starts,
                None,
            );
        } else if method_name == "render"
            && let Some(body) = &method.value.body
            && !function_body_has_value_return(semantic, body.span)
        {
            push_site(
                sites,
                RuleId::RequireRenderReturn,
                Some(class_name.to_string()),
                "requireRenderReturn",
                class_name,
                format!("`render()` in `{class_name}` does not return JSX or `null`."),
                method.span,
                line_starts,
                None,
            );
        }
    }
    (mount_or_ctor_spans, unmount_span)
}

fn check_class_this_set_state_and_is_mounted(
    semantic: &Semantic<'_>,
    cls: &Class<'_>,
    class_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (_, inner) in semantic.nodes().iter_enumerated() {
        if !cls.span.contains_inclusive(inner.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = inner.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
            continue;
        };
        if !matches!(
            mem.object.without_parentheses(),
            Expression::ThisExpression(_)
        ) {
            continue;
        }
        if mem.property.name == "setState" {
            push_site(
                sites,
                RuleId::NoSetState,
                Some(class_name.to_string()),
                "noSetState",
                "setState",
                format!(
                    "Avoid `this.setState` in `{class_name}`; lift state up or use an external store."
                ),
                call.span,
                line_starts,
                None,
            );
        } else if mem.property.name == "isMounted" {
            push_site(
                sites,
                RuleId::NoIsMounted,
                Some(class_name.to_string()),
                "noIsMounted",
                "isMounted",
                "`this.isMounted()` is an anti-pattern and is removed in modern React.".to_string(),
                call.span,
                line_starts,
                None,
            );
        }
    }
}

fn function_body_has_value_return(semantic: &Semantic<'_>, body_span: Span) -> bool {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::ReturnStatement(ret) = node.kind() else {
            continue;
        };
        if ret.argument.is_none() {
            continue;
        }
        let mut inside_nested_fn = false;
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            let anc_span = semantic.nodes().get_node(anc_id).span();
            if anc_span.start < body_span.start || anc_span.end > body_span.end {
                break;
            }
            if matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            ) {
                inside_nested_fn = true;
                break;
            }
        }
        if !inside_nested_fn {
            return true;
        }
    }
    false
}

pub(super) fn check_ast_node_rules(
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let effectful_subject_names: HashSet<String> = subjects
        .iter()
        .filter(|s| !s.effect_nodes.is_empty())
        .filter_map(|s| s.name.clone())
        .collect();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|sid| get_subject_name(semantic, sid));

        match node.kind() {
            AstKind::CallExpression(call) => {
                check_global_call_rules(semantic, node_id, call, &subj_name, line_starts, sites);
            }
            AstKind::JSXElement(jsx_el) => {
                check_jsx_element_rules(
                    semantic,
                    node_id,
                    jsx_el,
                    &subj_name,
                    &effectful_subject_names,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXText(jsx_text) => {
                check_jsx_text_rules(jsx_text, &subj_name, line_starts, sites);
            }
            AstKind::TSTypeReference(type_ref) => {
                let raw = type_ref
                    .type_name
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                if matches!(raw, "JSX.Element" | "React.JSX.Element") {
                    push_site(
                        sites,
                        RuleId::NoJsxElementType,
                        subj_name,
                        "noJsxElementType",
                        raw,
                        format!(
                            "Avoid `{raw}` return type annotations; prefer `ReactNode` or inferred return types."
                        ),
                        type_ref.span,
                        line_starts,
                        None,
                    );
                }
            }
            _ => {}
        }
    }
}

fn check_global_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee = call.callee.without_parentheses();
    let callee_text = callee.span().source_text(semantic.source_text()).trim();

    check_remove_listener_inline_handler(call, callee, subj_name, line_starts, sites);
    check_forward_ref_uses_ref(semantic, call, callee, subj_name, line_starts, sites);
    check_legacy_react_and_dom_calls(
        semantic,
        node_id,
        call,
        callee,
        callee_text,
        subj_name,
        line_starts,
        sites,
    );
    check_fill_map_element_as_key(semantic, call, callee, subj_name, line_starts, sites);
    check_call_component_as_function(semantic, node_id, call, callee, subj_name, line_starts, sites);
}

fn check_forward_ref_uses_ref(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_hook_callee(semantic, callee, "forwardRef") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let params = match first_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arr) => Some(&arr.params),
        Expression::FunctionExpression(f) => Some(&f.params),
        _ => None,
    };
    let Some(p) = params else {
        return;
    };
    if p.items.len() < 2 {
        push_site(
            sites,
            RuleId::ForwardRefUsesRef,
            subj_name.clone(),
            "forwardRefUsesRef",
            "forwardRef",
            "`forwardRef` render function does not accept the second `ref` parameter.".to_string(),
            call.span,
            line_starts,
            None,
        );
    } else if let Some(second_param) = p.items.get(1)
        && let BindingPattern::BindingIdentifier(ref_ident) = &second_param.pattern
        && let Some(sym_id) = ref_ident.symbol_id.get()
        && semantic.scoping().get_resolved_references(sym_id).count() == 0
    {
        push_site(
            sites,
            RuleId::ForwardRefUsesRef,
            subj_name.clone(),
            "forwardRefUsesRef",
            "forwardRef",
            format!(
                "`forwardRef` render function accepts `{}` but never uses it.",
                ref_ident.name
            ),
            call.span,
            line_starts,
            None,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks cloneElement, findDOMNode, React.Children, and ReactDOM.render return value on a CallExpression (#50)"
)]
fn check_legacy_react_and_dom_calls(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    callee_text: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_react_hook_callee(semantic, callee, "cloneElement") {
        push_site(
            sites,
            RuleId::NoCloneElement,
            subj_name.clone(),
            "noCloneElement",
            "cloneElement",
            "Avoid `cloneElement`; pass explicit props or a render prop instead.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
    if callee_text == "findDOMNode" || callee_text == "ReactDOM.findDOMNode" {
        push_site(
            sites,
            RuleId::NoFindDomNode,
            subj_name.clone(),
            "noFindDomNode",
            callee_text,
            "`findDOMNode` is deprecated and removed in React 19; use `useRef` instead."
                .to_string(),
            call.span,
            line_starts,
            None,
        );
    }
    if callee_text.starts_with("React.Children.") || callee_text.starts_with("Children.") {
        push_site(
            sites,
            RuleId::NoReactChildren,
            subj_name.clone(),
            "noReactChildren",
            callee_text,
            format!("Avoid `{callee_text}`; pass array data or explicit props instead."),
            call.span,
            line_starts,
            None,
        );
    }
    if callee_text == "ReactDOM.render"
        && !matches!(
            semantic.nodes().parent_kind(node_id),
            AstKind::ExpressionStatement(_) | AstKind::ArrowFunctionExpression(_)
        )
    {
        push_site(
            sites,
            RuleId::NoRenderReturnValue,
            subj_name.clone(),
            "noRenderReturnValue",
            "ReactDOM.render",
            "Do not use the return value of `ReactDOM.render`; it is legacy and removed in React 19.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
}

fn check_fill_map_element_as_key(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = callee else {
        return;
    };
    if mem.property.name != "map" {
        return;
    }
    let Expression::CallExpression(fill_call) = mem.object.without_parentheses() else {
        return;
    };
    let Expression::StaticMemberExpression(fill_mem) = fill_call.callee.without_parentheses()
    else {
        return;
    };
    if fill_mem.property.name != "fill" {
        return;
    }
    let Some(map_cb) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let (first_param, param_count, cb_span) = match map_cb.without_parentheses() {
        Expression::ArrowFunctionExpression(arr) => (
            arr.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
            arr.params.items.len(),
            arr.span,
        ),
        Expression::FunctionExpression(f) => (
            f.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
            f.params.items.len(),
            f.span,
        ),
        _ => (None, 0, call.span),
    };
    if let Some(p_name) = first_param
        && param_count == 1
        && cb_span
            .source_text(semantic.source_text())
            .contains(&format!("key={{{p_name}}}"))
    {
        push_site(
            sites,
            RuleId::NoFillMapElementAsKey,
            subj_name.clone(),
            "noFillMapElementAsKey",
            &p_name,
            format!(
                "`.fill().map(({p_name}) => ...)` passes the identical fill value `{p_name}` as `key`; use the second index parameter `.map((_, index) => ...)`."
            ),
            call.span,
            line_starts,
            None,
        );
    }
}

fn check_call_component_as_function(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::Identifier(id) = callee else {
        return;
    };
    if !is_component_name(id.name.as_str()) || BUILTIN_UPPERCASE_CALLS.contains(&id.name.as_str())
    {
        return;
    }
    let is_local_component = resolve_ident_symbol(semantic, id).is_some_and(|sym_id| {
        let decl_id = semantic.scoping().symbol_declaration(sym_id);
        is_functional_component(semantic, decl_id)
    });
    let in_jsx_expr = matches!(
        semantic.nodes().parent_kind(node_id),
        AstKind::JSXExpressionContainer(_)
    );
    if is_local_component || in_jsx_expr {
        push_site(
            sites,
            RuleId::NoCallComponentAsFunction,
            subj_name.clone(),
            "noCallComponentAsFunction",
            id.name.as_str(),
            format!(
                "Render `<{} />` as JSX instead of calling `{}(...)` directly as a function.",
                id.name, id.name
            ),
            call.span,
            line_starts,
            None,
        );
    }
}
