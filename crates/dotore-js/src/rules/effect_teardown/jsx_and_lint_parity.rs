//! File-level, module-scope, class component, legacy React API, and JSX element/attribute/text lint parity rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants; JSX and lint parity detectors match only relevant AST node kinds"
)]

use std::{collections::HashSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, BindingPattern, CallExpression, Class, ClassElement, Expression,
        IdentifierReference, ImportDeclarationSpecifier, ImportSpecifier, JSXAttributeItem,
        JSXAttributeValue, JSXElement, JSXElementName, JSXOpeningElement, JSXText,
        MethodDefinitionKind, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        SemanticRuleSite, SubjectIr, SubjectKind,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_subject_name,
            is_functional_component, is_react_component_class,
        },
    },
    matchers::{
        is_component_name, is_custom_hook_name, is_global_ident, is_react_hook_callee,
        resolve_ident_symbol, span_to_byte_span,
    },
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

use super::{
    BOOLEAN_DOM_ATTRIBUTES, BUILTIN_UPPERCASE_CALLS, FORBIDDEN_DOM_PROPS, FORBIDDEN_ELEMENTS,
    INVALID_PARAGRAPH_CHILD_TAGS, NATIVE_LABEL_CONTROLS, VOID_DOM_TAGS,
    dom_and_timer_teardown::{
        check_class_unmount_teardown, check_remove_listener_inline_handler,
    },
    is_at_module_scope, push_site, push_site_with_fix,
};

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

    let mut first_jsx_span: Option<Span> = None;
    let mut has_react_in_scope = false;
    let mut class_comp_spans: Vec<(String, Span)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::JSXElement(el) => {
                if first_jsx_span.is_none() {
                    first_jsx_span = Some(el.span);
                }
            }
            AstKind::JSXFragment(frag) => {
                if first_jsx_span.is_none() {
                    first_jsx_span = Some(frag.span);
                }
            }
            AstKind::ImportDeclaration(imp) => {
                if let Some(specs) = &imp.specifiers {
                    for spec in specs {
                        match spec {
                            ImportDeclarationSpecifier::ImportDefaultSpecifier(def) => {
                                if def.local.name == "React" {
                                    has_react_in_scope = true;
                                }
                            }
                            ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                                if ns.local.name == "React" {
                                    has_react_in_scope = true;
                                }
                            }
                            ImportDeclarationSpecifier::ImportSpecifier(named) => {
                                if named.local.name == "React" {
                                    has_react_in_scope = true;
                                }
                                check_hook_import_rename(named, line_starts, sites);
                            }
                        }
                    }
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && id.name == "React"
                {
                    has_react_in_scope = true;
                }
            }
            AstKind::Class(cls) => {
                if is_react_class_component(semantic, cls).is_some() {
                    let name = cls
                        .id
                        .as_ref()
                        .map_or_else(|| "Component".to_string(), |id| id.name.to_string());
                    class_comp_spans.push((name, cls.span));
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

    if let Some(jsx_span) = first_jsx_span {
        if matches!(ext, "js" | "ts" | "mjs" | "cjs") {
            push_site(
                sites,
                RuleId::JsxFilenameExtension,
                None,
                "jsxFilenameExtension",
                ext,
                format!("JSX syntax is not allowed in `.{ext}` files; rename the file to `.jsx` or `.tsx`."),
                jsx_span,
                line_starts,
                None,
            );
        }
        if !has_react_in_scope {
            push_site(
                sites,
                RuleId::ReactInJsxScope,
                None,
                "reactInJsxScope",
                "React",
                "`React` must be in scope when using JSX under the classic JSX transform.".to_string(),
                jsx_span,
                line_starts,
                None,
            );
        }
    }

    // `no-multi-comp` and `no-multi-component-file`
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

    if comp_entries.len() >= 2 {
        for (comp_name, comp_span) in comp_entries.iter().skip(1) {
            push_site(
                sites,
                RuleId::NoMultiComp,
                Some(comp_name.clone()),
                "noMultiComp",
                comp_name.clone(),
                format!("Declare only one React component per file; `{comp_name}` is an additional component in this module."),
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
}

fn check_hook_import_rename(
    named: &ImportSpecifier<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let imported = named.imported.name().as_str();
    let local = named.local.name.as_str();
    if imported == local {
        return;
    }
    let is_imported_hook = is_custom_hook_name(imported) || imported == "use";
    if !is_imported_hook {
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
    let is_impure = matches!(
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
    );
    if is_impure {
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
    ) {
        return;
    }
    // Skip if locally declared
    if !is_global_ident(semantic, ident) {
        return;
    }
    // Skip `typeof window`
    if let AstKind::UnaryExpression(un) = semantic.nodes().parent_kind(node_id)
        && un.operator == UnaryOperator::Typeof
    {
        return;
    }
    // Skip if guarded by `typeof <name> !== "undefined"` or `typeof window !== "undefined"` in an enclosing conditional/logical/if expression
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_span = semantic.nodes().get_node(anc_id).span();
        match semantic.nodes().kind(anc_id) {
            AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::IfStatement(_) => {
                let text = anc_span.source_text(semantic.source_text());
                if text.contains("typeof window") || text.contains(&format!("typeof {name}")) {
                    return;
                }
            }
            _ => {}
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
            if method.kind == MethodDefinitionKind::Constructor
                || method_name == "componentDidMount"
            {
                mount_or_ctor_spans.push(method.value.span);
            } else if method_name == "componentWillUnmount" {
                unmount_span = Some(method.value.span);
            } else if method_name == "shouldComponentUpdate"
                && class_kind == ReactClassKind::PureComponent
            {
                push_site(
                    sites,
                    RuleId::NoRedundantShouldComponentUpdate,
                    Some(class_name.clone()),
                    "noRedundantShouldComponentUpdate",
                    &class_name,
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
                    Some(class_name.clone()),
                    "requireRenderReturn",
                    &class_name,
                    format!("`render()` in `{class_name}` does not return JSX or `null`."),
                    method.span,
                    line_starts,
                    None,
                );
            }
        }

        // `class-component-missing-component-will-unmount-teardown`
        check_class_unmount_teardown(
            semantic,
            &class_name,
            &mount_or_ctor_spans,
            unmount_span,
            line_starts,
            sites,
        );

        // `no-set-state` and `no-is-mounted` inside class body
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
                    Some(class_name.clone()),
                    "noSetState",
                    "setState",
                    format!("Avoid `this.setState` in `{class_name}`; lift state up or use an external store."),
                    call.span,
                    line_starts,
                    None,
                );
            } else if mem.property.name == "isMounted" {
                push_site(
                    sites,
                    RuleId::NoIsMounted,
                    Some(class_name.clone()),
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
        // Ensure this ReturnStatement belongs to the render method itself, not a nested function
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

    // 1. `effect-remove-listener-inline-handler`
    check_remove_listener_inline_handler(call, callee, subj_name, line_starts, sites);

    // 2. `forward-ref-uses-ref`
    if is_react_hook_callee(semantic, callee, "forwardRef")
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        let params = match first_arg.without_parentheses() {
            Expression::ArrowFunctionExpression(arr) => Some(&arr.params),
            Expression::FunctionExpression(f) => Some(&f.params),
            _ => None,
        };
        if let Some(p) = params {
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
    }

    // 3. `no-clone-element`
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

    // 4. `no-find-dom-node`
    if callee_text == "findDOMNode" || callee_text == "ReactDOM.findDOMNode" {
        push_site(
            sites,
            RuleId::NoFindDomNode,
            subj_name.clone(),
            "noFindDomNode",
            callee_text,
            "`findDOMNode` is deprecated and removed in React 19; use `useRef` instead.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // 5. `no-react-children`
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

    // 6. `no-render-return-value`
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

    // 7. `no-fill-map-element-as-key`: `<arr>.fill(...).map((n) => <... key={n} />)`
    if let Expression::StaticMemberExpression(mem) = callee
        && mem.property.name == "map"
        && let Expression::CallExpression(fill_call) = mem.object.without_parentheses()
        && let Expression::StaticMemberExpression(fill_mem) =
            fill_call.callee.without_parentheses()
        && fill_mem.property.name == "fill"
        && let Some(map_cb) = call.arguments.first().and_then(|a| a.as_expression())
    {
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
        {
            let key_pattern = format!("key={{{p_name}}}");
            if cb_span
                .source_text(semantic.source_text())
                .contains(&key_pattern)
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
    }

    // 8. `no-call-component-as-function`
    if let Expression::Identifier(id) = callee
        && is_component_name(id.name.as_str())
        && !BUILTIN_UPPERCASE_CALLS.contains(&id.name.as_str())
    {
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
}

fn check_jsx_element_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subj_name: &Option<String>,
    effectful_subject_names: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // 1. `no-namespace`
    if let JSXElementName::NamespacedName(ns) = &opening.name {
        let ns_text = ns.span.source_text(semantic.source_text());
        push_site(
            sites,
            RuleId::NoNamespace,
            subj_name.clone(),
            "noNamespace",
            ns_text,
            format!("Namespaced JSX element `<{ns_text}>` is not supported by React."),
            ns.span,
            line_starts,
            None,
        );
    }

    let (tag_name, _root_ident, is_comp, _) = classify_jsx_element_name(semantic, &opening.name);

    // 2. `forbid-elements`
    if FORBIDDEN_ELEMENTS.contains(&tag_name.as_str()) {
        push_site(
            sites,
            RuleId::ForbidElements,
            subj_name.clone(),
            "forbidElements",
            &tag_name,
            format!("Element `<{tag_name}>` is forbidden; use an approved semantic HTML or UI primitive instead."),
            opening.span,
            line_starts,
            None,
        );
    }

    // 3. `activity-wraps-effect-heavy-subtree`
    if matches!(
        tag_name.as_str(),
        "Activity" | "unstable_Activity" | "Offscreen"
    ) {
        let wraps_effectful = semantic.nodes().iter_enumerated().any(|(_, n)| {
            jsx_el.span.contains_inclusive(n.span())
                && n.span() != jsx_el.span
                && matches!(
                    n.kind(),
                    AstKind::JSXOpeningElement(child_open)
                        if effectful_subject_names.contains(
                            &classify_jsx_element_name(semantic, &child_open.name).0
                        )
                )
        });
        if wraps_effectful {
            push_site(
                sites,
                RuleId::ActivityWrapsEffectHeavySubtree,
                subj_name.clone(),
                "activityWrapsEffectHeavySubtree",
                &tag_name,
                format!("`<{tag_name}>` wraps an effect-heavy child subtree."),
                opening.span,
                line_starts,
                None,
            );
        }
    }

    // 4. `html-label-has-single-control`
    if tag_name == "label" {
        let mut control_count = 0_usize;
        for (_, inner) in semantic.nodes().iter_enumerated() {
            if !jsx_el.span.contains_inclusive(inner.span()) || inner.span() == jsx_el.span {
                continue;
            }
            if let AstKind::JSXOpeningElement(child_open) = inner.kind() {
                let (child_tag, _, child_is_comp, _) =
                    classify_jsx_element_name(semantic, &child_open.name);
                if !child_is_comp && NATIVE_LABEL_CONTROLS.contains(&child_tag.as_str()) {
                    control_count += 1;
                }
            }
        }
        if control_count >= 2 {
            push_site(
                sites,
                RuleId::HtmlLabelHasSingleControl,
                subj_name.clone(),
                "htmlLabelHasSingleControl",
                "label",
                "`<label>` wraps multiple native form controls; associate each `<label>` with a single control.".to_string(),
                opening.span,
                line_starts,
                None,
            );
        }
    }

    // 5. `html-no-invalid-paragraph-child`
    if !is_comp && INVALID_PARAGRAPH_CHILD_TAGS.contains(&tag_name.as_str()) {
        for anc_id in semantic.nodes().ancestor_ids(node_id) {
            if let AstKind::JSXElement(anc_el) = semantic.nodes().kind(anc_id) {
                let (anc_tag, _, anc_is_comp, _) =
                    classify_jsx_element_name(semantic, &anc_el.opening_element.name);
                if !anc_is_comp && anc_tag == "svg" {
                    break;
                }
                if !anc_is_comp && anc_tag == "p" {
                    push_site(
                        sites,
                        RuleId::HtmlNoInvalidParagraphChild,
                        subj_name.clone(),
                        "htmlNoInvalidParagraphChild",
                        &tag_name,
                        format!("Block element `<{tag_name}>` cannot be nested inside `<p>`."),
                        opening.span,
                        line_starts,
                        None,
                    );
                    break;
                }
            }
        }
    }

    // 6. `void-dom-elements-no-children` (with `Autofix`)
    if !is_comp && VOID_DOM_TAGS.contains(&tag_name.as_str()) {
        let has_children_attr = opening.attributes.iter().any(|item| {
            matches!(
                item,
                JSXAttributeItem::Attribute(attr)
                    if attr.name.as_identifier().is_some_and(|id| {
                        matches!(id.name.as_str(), "children" | "dangerouslySetInnerHTML")
                    })
            )
        });
        if !jsx_el.children.is_empty() || has_children_attr {
            let kept_attrs: Vec<&str> = opening
                .attributes
                .iter()
                .filter(|item| {
                    !matches!(
                        item,
                        JSXAttributeItem::Attribute(attr)
                            if attr.name.as_identifier().is_some_and(|id| {
                                matches!(id.name.as_str(), "children" | "dangerouslySetInnerHTML")
                            })
                    )
                })
                .map(|item| item.span().source_text(semantic.source_text()).trim())
                .collect();
            let replacement = if kept_attrs.is_empty() {
                format!("<{tag_name} />")
            } else {
                format!("<{tag_name} {} />", kept_attrs.join(" "))
            };
            let autofix = Some(AutofixPatch {
                description: format!("Remove children from void element `<{tag_name} />`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: span_to_byte_span(jsx_el.span),
                    replacement,
                }],
            });
            push_site_with_fix(
                sites,
                RuleId::VoidDomElementsNoChildren,
                subj_name.clone(),
                "voidDomElementsNoChildren",
                &tag_name,
                format!("Void DOM element `<{tag_name}>` cannot have children."),
                jsx_el.span,
                line_starts,
                autofix,
            );
        }
    }

    // 7. Attribute-level JSX rules
    check_jsx_opening_attributes(
        semantic,
        opening,
        &tag_name,
        is_comp,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_jsx_opening_attributes(
    semantic: &Semantic<'_>,
    opening: &JSXOpeningElement<'_>,
    tag_name: &str,
    is_comp: bool,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen_attr_names: HashSet<String> = HashSet::new();
    let mut spread_count = 0_usize;
    let mut has_set_pointer_capture = false;
    let mut has_pointer_cancel = false;

    for item in &opening.attributes {
        match item {
            JSXAttributeItem::SpreadAttribute(spread) => {
                spread_count += 1;
                if spread_count >= 2 {
                    push_site(
                        sites,
                        RuleId::JsxPropsNoSpreadMulti,
                        subj_name.clone(),
                        "jsxPropsNoSpreadMulti",
                        tag_name,
                        format!("Multiple prop spreads on `<{tag_name}>` can silently clobber earlier props."),
                        spread.span,
                        line_starts,
                        None,
                    );
                }
            }
            JSXAttributeItem::Attribute(attr) => {
                let Some(attr_ident) = attr.name.as_identifier() else {
                    continue;
                };
                let attr_name = attr_ident.name.as_str();

                // `jsx-no-duplicate-props`
                if !seen_attr_names.insert(attr_name.to_string()) {
                    push_site(
                        sites,
                        RuleId::JsxNoDuplicateProps,
                        subj_name.clone(),
                        "jsxNoDuplicateProps",
                        attr_name,
                        format!("Duplicate prop `{attr_name}` on `<{tag_name}>`."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `forbid-component-props`
                if is_comp && matches!(attr_name, "className" | "style") {
                    push_site(
                        sites,
                        RuleId::ForbidComponentProps,
                        subj_name.clone(),
                        "forbidComponentProps",
                        attr_name,
                        format!("Prop `{attr_name}` is forbidden on custom component `<{tag_name}>`."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `forbid-dom-props`
                if !is_comp && FORBIDDEN_DOM_PROPS.contains(&attr_name) {
                    push_site(
                        sites,
                        RuleId::ForbidDomProps,
                        subj_name.clone(),
                        "forbidDomProps",
                        attr_name,
                        format!("DOM prop `{attr_name}` is forbidden on `<{tag_name}>`."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `no-children-prop`
                if attr_name == "children" {
                    push_site(
                        sites,
                        RuleId::NoChildrenProp,
                        subj_name.clone(),
                        "noChildrenProp",
                        "children",
                        format!("Pass children as nested elements between `<{tag_name}>...</{tag_name}>` instead of a `children` prop."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `no-indeterminate-attribute`
                if !is_comp && tag_name == "input" && attr_name == "indeterminate" {
                    push_site(
                        sites,
                        RuleId::NoIndeterminateAttribute,
                        subj_name.clone(),
                        "noIndeterminateAttribute",
                        "indeterminate",
                        "HTML `<input>` has no `indeterminate` attribute; assign `el.indeterminate = true` via a ref instead.".to_string(),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `no-string-false-on-boolean-attribute` (with `Autofix`)
                if !is_comp && BOOLEAN_DOM_ATTRIBUTES.contains(&attr_name) {
                    let str_bool = match &attr.value {
                        Some(JSXAttributeValue::StringLiteral(s))
                            if matches!(s.value.as_str(), Some("false" | "true")) =>
                        {
                            s.value.as_str().map(|v| (v, s.span))
                        }
                        Some(JSXAttributeValue::ExpressionContainer(c)) => {
                            if let Some(Expression::StringLiteral(s)) =
                                c.expression.as_expression().map(Expression::without_parentheses)
                                && matches!(s.value.as_str(), Some("false" | "true"))
                            {
                                s.value.as_str().map(|v| (v, c.span))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some((bool_val, val_span)) = str_bool {
                        let autofix = Some(AutofixPatch {
                            description: format!(
                                "Replace string `{attr_name}=\"{bool_val}\"` with boolean `{attr_name}={{{bool_val}}}`"
                            ),
                            edits: vec![ByteEdit {
                                file: None,
                                span: span_to_byte_span(val_span),
                                replacement: format!("{{{bool_val}}}"),
                            }],
                        });
                        push_site_with_fix(
                            sites,
                            RuleId::NoStringFalseOnBooleanAttribute,
                            subj_name.clone(),
                            "noStringFalseOnBooleanAttribute",
                            attr_name,
                            format!(
                                "Boolean attribute `{attr_name}` on `<{tag_name}>` is given string `\"{bool_val}\"` instead of `{{{bool_val}}}`."
                            ),
                            attr.span,
                            line_starts,
                            autofix,
                        );
                    }
                }

                // `no-mixed-srcset-descriptors`
                if matches!(attr_name, "srcSet" | "srcset")
                    && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                    && let Some(val_str) = s.value.as_str()
                    && has_mixed_srcset_descriptors(val_str)
                {
                    push_site(
                        sites,
                        RuleId::NoMixedSrcsetDescriptors,
                        subj_name.clone(),
                        "noMixedSrcsetDescriptors",
                        attr_name,
                        "`srcSet` mixes width (`w`) and density (`x`) descriptors in the same attribute.".to_string(),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `rendering-svg-precision` (with `Autofix`)
                if matches!(attr_name, "d" | "points" | "transform")
                    && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
                    && let Some(val_str) = s.value.as_str()
                    && let Some(rounded) = round_svg_precision_string(val_str)
                {
                    let autofix = Some(AutofixPatch {
                        description: format!("Round `{attr_name}` coordinates to at most 2 decimal places"),
                        edits: vec![ByteEdit {
                            file: None,
                            span: span_to_byte_span(s.span),
                            replacement: format!("\"{rounded}\""),
                        }],
                    });
                    push_site_with_fix(
                        sites,
                        RuleId::RenderingSvgPrecision,
                        subj_name.clone(),
                        "renderingSvgPrecision",
                        attr_name,
                        format!("SVG `{attr_name}` attribute contains coordinates with more than 2 decimal places."),
                        attr.span,
                        line_starts,
                        autofix,
                    );
                }

                // `jsx-no-jsx-as-prop`
                if is_comp
                    && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
                    && let Some(expr) = c.expression.as_expression()
                    && matches!(
                        expr.without_parentheses(),
                        Expression::JSXElement(_) | Expression::JSXFragment(_)
                    )
                {
                    push_site(
                        sites,
                        RuleId::JsxNoJsxAsProp,
                        subj_name.clone(),
                        "jsxNoJsxAsProp",
                        attr_name,
                        format!("JSX element passed inline to prop `{attr_name}` on `<{tag_name}>` creates a new element on every render."),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `no-ref-callback-cleanup-before-react-19`
                if attr_name == "ref"
                    && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
                    && let Some(expr) = c.expression.as_expression()
                    && ref_callback_returns_cleanup_fn(semantic, expr.without_parentheses())
                {
                    push_site(
                        sites,
                        RuleId::NoRefCallbackCleanupBeforeReact19,
                        subj_name.clone(),
                        "noRefCallbackCleanupBeforeReact19",
                        "ref",
                        "Returning a cleanup function from a `ref` callback requires React 19+.".to_string(),
                        attr.span,
                        line_starts,
                        None,
                    );
                }

                // `pointer-capture-needs-cancel-handler`
                if matches!(attr_name, "onPointerCancel" | "onLostPointerCapture") {
                    has_pointer_cancel = true;
                }
                if attr_name == "onPointerDown"
                    && attr
                        .span
                        .source_text(semantic.source_text())
                        .contains("setPointerCapture(")
                {
                    has_set_pointer_capture = true;
                }
            }
        }
    }

    if has_set_pointer_capture && !has_pointer_cancel {
        push_site(
            sites,
            RuleId::PointerCaptureNeedsCancelHandler,
            subj_name.clone(),
            "pointerCaptureNeedsCancelHandler",
            tag_name,
            format!(
                "`<{tag_name}>` calls `setPointerCapture` in `onPointerDown` without an `onPointerCancel` or `onLostPointerCapture` handler."
            ),
            opening.span,
            line_starts,
            None,
        );
    }
}

fn has_mixed_srcset_descriptors(value: &str) -> bool {
    let mut has_w = false;
    let mut has_x = false;
    for candidate in value.split(',') {
        let Some(desc) = candidate.split_whitespace().nth(1) else {
            continue;
        };
        if desc.ends_with('w') && desc[..desc.len() - 1].chars().all(|c| c.is_ascii_digit()) {
            has_w = true;
        } else if desc.ends_with('x')
            && desc[..desc.len() - 1]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
        {
            has_x = true;
        }
    }
    has_w && has_x
}

fn round_svg_precision_string(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let int_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'.' {
                let dot_idx = i;
                i += 1;
                let frac_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let frac_len = i - frac_start;
                let num_slice = &input[int_start..i];
                if frac_len > 2
                    && let Ok(val) = num_slice.parse::<f64>()
                {
                    changed = true;
                    let formatted = format!("{val:.2}");
                    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
                    out.push_str(trimmed);
                    continue;
                }
                let _ = dot_idx;
                out.push_str(num_slice);
            } else {
                out.push_str(&input[int_start..i]);
            }
        } else {
            let ch = input[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }

    changed.then_some(out)
}

fn ref_callback_returns_cleanup_fn(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    let fn_span = match expr {
        Expression::ArrowFunctionExpression(arr) => match &arr.body {
            ArrowFunctionBody::FunctionBody(body) => body.span,
            ArrowFunctionBody::ArrowFunctionExpression(_)
            | ArrowFunctionBody::FunctionExpression(_) => return true,
            _ => return false,
        },
        Expression::FunctionExpression(f) => {
            let Some(body) = &f.body else {
                return false;
            };
            body.span
        }
        _ => return false,
    };
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        if let AstKind::ReturnStatement(ret) = node.kind()
            && let Some(arg) = &ret.argument
            && matches!(
                arg.without_parentheses(),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        {
            return true;
        }
    }
    false
}

fn check_jsx_text_rules(
    jsx_text: &JSXText<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let raw = jsx_text.value.as_str();

    // 1. `jsx-no-comment-textnodes`
    let has_comment_line = raw.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("//") || trimmed.starts_with("/*")
    });
    if has_comment_line {
        push_site(
            sites,
            RuleId::JsxNoCommentTextnodes,
            subj_name.clone(),
            "jsxNoCommentTextnodes",
            "comment",
            "Comment syntax inside JSX text will be rendered literally; wrap it in `{/* ... */}`.".to_string(),
            jsx_text.span,
            line_starts,
            None,
        );
    }

    // 2. `no-unescaped-entities`
    if let Some(ch) = raw
        .chars()
        .find(|&c| matches!(c, '\'' | '"' | '>' | '}'))
    {
        push_site(
            sites,
            RuleId::NoUnescapedEntities,
            subj_name.clone(),
            "noUnescapedEntities",
            ch.to_string(),
            format!("Unescaped `{ch}` in JSX text; escape it with an HTML entity or JSX expression."),
            jsx_text.span,
            line_starts,
            None,
        );
    }
}
