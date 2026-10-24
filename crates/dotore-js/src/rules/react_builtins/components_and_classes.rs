//! Fast Refresh (`only-export-components`), nested component (`no-unstable-nested-components`),
//! `display-name`, and React class component detectors for `react-builtins`.

use std::path::Path;

use oxc_ast::{
    AstKind,
    ast::{BindingPattern, CallExpression, Expression, JSXAttributeValue},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{hooks::check_hook_use_state_symmetry, strip_ts_and_parens};
use crate::{
    ir::{
        SemanticRuleSite,
        react_ast::{find_enclosing_react_node, get_subject_name, is_react_component_class},
    },
    matchers::{callee_name, is_component_name, is_custom_hook_name, push_semantic_site},
    rules::types::RuleId,
};

pub(super) fn check_only_export_components_in_file(
    semantic: &Semantic<'_>,
    path: &Path,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let path_str = path.to_string_lossy().replace('\\', "/");
    // Only check `.tsx` and `.jsx` component files; skip route convention files (`_layout.tsx`, `+not-found.tsx`, `layout.tsx`, `page.tsx`, `route.tsx`)
    let is_jsx_ext = path_str.ends_with(".tsx") || path_str.ends_with(".jsx");
    if !is_jsx_ext || is_framework_route_file(&path_str, semantic.source_text()) {
        return;
    }

    let mut has_exported_component = false;
    let mut non_component_exports: Vec<(String, Span)> = Vec::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::ExportDeclaration(exp) = node.kind() else {
            continue;
        };
        if exp.export_kind().is_type() {
            continue;
        }
        match &exp.declaration {
            oxc_ast::ast::Declaration::FunctionDeclaration(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let name = id.name.as_str();
                if is_component_name(name) {
                    has_exported_component = true;
                } else if !is_custom_hook_name(name) {
                    non_component_exports.push((name.to_string(), func.span));
                }
            }
            oxc_ast::ast::Declaration::VariableDeclaration(vd) => {
                collect_variable_exports_for_fast_refresh(
                    &vd.declarations,
                    &mut has_exported_component,
                    &mut non_component_exports,
                );
            }
            _ => {}
        }
    }

    if has_exported_component {
        for (export_name, span) in non_component_exports {
            push_semantic_site(
                sites,
                RuleId::OnlyExportComponents,
                None,
                "onlyExportComponents",
                &export_name,
                "This file exports non-components alongside components, so Fast Refresh can't safely preserve component state.".to_string(),
                line_starts,
                span,
            );
        }
    }
}

fn collect_variable_exports_for_fast_refresh(
    declarations: &[oxc_ast::ast::VariableDeclarator<'_>],
    has_exported_component: &mut bool,
    non_component_exports: &mut Vec<(String, Span)>,
) {
    for declarator in declarations {
        let BindingPattern::BindingIdentifier(id) = &declarator.id else {
            continue;
        };
        let name = id.name.as_str();
        if is_component_name(name) {
            if declarator.init.as_ref().is_some_and(is_create_context_call) {
                non_component_exports.push((name.to_string(), declarator.span));
            } else {
                *has_exported_component = true;
            }
        } else if !is_custom_hook_name(name)
            && declarator
                .init
                .as_ref()
                .is_some_and(|init| !is_allowed_constant_export_init(init))
        {
            non_component_exports.push((name.to_string(), declarator.span));
        }
    }
}

fn is_framework_route_file(path_str: &str, source: &str) -> bool {
    let file_name = path_str.rsplit('/').next().unwrap_or(path_str);
    if matches!(
        file_name,
        "_layout.tsx"
            | "_layout.jsx"
            | "+not-found.tsx"
            | "+not-found.jsx"
            | "layout.tsx"
            | "layout.jsx"
            | "page.tsx"
            | "page.jsx"
            | "loading.tsx"
            | "error.tsx"
            | "route.tsx"
    ) && (path_str.contains("/app/")
        || path_str.starts_with("app/")
        || path_str.contains("/routes/")
        || path_str.starts_with("routes/"))
    {
        return true;
    }
    source.contains("createFileRoute(")
        || source.contains("createRootRouteWithContext")
        || source.contains("createLazyFileRoute(")
}

fn is_create_context_call(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = strip_ts_and_parens(expr) else {
        return false;
    };
    callee_name(&call.callee) == Some("createContext")
}

fn is_allowed_constant_export_init(expr: &Expression<'_>) -> bool {
    let unwrapped = strip_ts_and_parens(expr);
    unwrapped.is_literal()
        || matches!(
            unwrapped,
            Expression::TemplateLiteral(_)
                | Expression::ArrayExpression(_)
                | Expression::ObjectExpression(_)
                | Expression::UnaryExpression(_)
                | Expression::BinaryExpression(_)
        )
}

pub(super) fn check_class_and_component_builtin_rules_in_file(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::VariableDeclarator(decl) => {
                check_hook_use_state_symmetry(semantic, decl, &subj_name, line_starts, sites);
                check_nested_component_declarator(
                    semantic,
                    node_id,
                    decl,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::Function(func) => {
                check_nested_component_function(
                    semantic,
                    node_id,
                    func,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXAttribute(attr) => {
                check_unstable_nested_component_prop(
                    semantic,
                    attr,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_display_name_and_create_class(
                    semantic,
                    node_id,
                    call,
                    &subj_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::Class(cls) => {
                check_react_class_component_rules(semantic, cls, line_starts, sites);
            }
            _ => {}
        }
    }
}

fn check_nested_component_declarator(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let Some(enclosing_id) = find_enclosing_react_node(semantic, parent_id) else {
        return;
    };
    let enclosing_subj_name =
        get_subject_name(semantic, enclosing_id).or_else(|| subj_name.clone());
    let Some(id) = decl.id.get_binding_identifier() else {
        return;
    };
    if !is_component_name(id.name.as_str()) {
        return;
    }
    let Some(init) = &decl.init else {
        return;
    };
    if matches!(
        init.without_parentheses(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) && span_contains_jsx(semantic, init.span())
    {
        push_semantic_site(
            sites,
            RuleId::NoUnstableNestedComponents,
            enclosing_subj_name,
            "noUnstableNestedComponents",
            id.name.as_str(),
            format!(
                "Do not declare component `{}` inside another component; React will recreate its type and reset its state on every render.",
                id.name
            ),
            line_starts,
            decl.span,
        );
    }
}

fn check_nested_component_function(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    func: &oxc_ast::ast::Function<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let parent_id = semantic.nodes().parent_id(node_id);
    let Some(enclosing_id) = find_enclosing_react_node(semantic, parent_id) else {
        return;
    };
    let enclosing_subj_name =
        get_subject_name(semantic, enclosing_id).or_else(|| subj_name.clone());
    let Some(id) = &func.id else {
        return;
    };
    if !is_component_name(id.name.as_str()) || !span_contains_jsx(semantic, func.span) {
        return;
    }
    push_semantic_site(
        sites,
        RuleId::NoUnstableNestedComponents,
        enclosing_subj_name,
        "noUnstableNestedComponents",
        id.name.as_str(),
        format!(
            "Do not declare component `{}` inside another component; React will recreate its type and reset its state on every render.",
            id.name
        ),
        line_starts,
        func.span,
    );
}

fn check_unstable_nested_component_prop(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(ident) = attr.name.as_identifier() else {
        return;
    };
    if ident.name.starts_with("on") || ident.name.starts_with("render") {
        return;
    }
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return;
    };
    let Some(expr) = c.expression.as_expression() else {
        return;
    };
    if matches!(
        expr.without_parentheses(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    ) && span_contains_jsx(semantic, expr.span())
    {
        push_semantic_site(
            sites,
            RuleId::NoUnstableNestedComponents,
            subj_name.clone(),
            "noUnstableNestedComponents",
            ident.name.as_str(),
            format!(
                "Inline function prop `{}` returns JSX and creates an unstable component on every render.",
                ident.name
            ),
            line_starts,
            expr.span(),
        );
    }
}

fn span_contains_jsx(semantic: &Semantic<'_>, span: Span) -> bool {
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        span.contains_inclusive(n.span())
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn check_display_name_and_create_class(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = match call.callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            if matches!(mem.object.without_parentheses(), Expression::Identifier(obj) if obj.name == "React")
            {
                Some(mem.property.name.as_str())
            } else {
                None
            }
        }
        _ => None,
    };
    let Some(c_name) = callee_name else {
        return;
    };

    // 1. `prefer-es6-class`: `createReactClass({...})` or `React.createClass({...})`
    if matches!(c_name, "createReactClass" | "createClass") {
        push_semantic_site(
            sites,
            RuleId::PreferEs6Class,
            subj_name.clone(),
            "preferEs6Class",
            c_name,
            format!(
                "`{c_name}({{...}})` is a legacy React class factory; use a function component or an ES6 `class` extending `React.Component`."
            ),
            line_starts,
            call.span,
        );
        return;
    }

    // 2. `display-name`: `forwardRef((props, ref) => ...)` or `memo((props) => ...)` without a named function or variable binding + displayName
    if !matches!(c_name, "forwardRef" | "memo") {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let is_anonymous_fn = match first_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::FunctionExpression(f) => f.id.is_none(),
        _ => false,
    };
    if !is_anonymous_fn {
        return;
    }
    let parent_kind = semantic.nodes().parent_kind(node_id);
    let assigned_var_name = if let AstKind::VariableDeclarator(decl) = parent_kind {
        decl.id.get_binding_identifier().map(|id| id.name.as_str())
    } else {
        None
    };
    if let Some(v_name) = assigned_var_name
        && semantic
            .source_text()
            .contains(&format!("{v_name}.displayName"))
    {
        return;
    }
    push_semantic_site(
        sites,
        RuleId::DisplayName,
        subj_name.clone(),
        "displayName",
        c_name,
        format!(
            "Component wrapped in `{c_name}(...)` is anonymous and has no `displayName`; pass a named function `function MyComponent(...)`."
        ),
        line_starts,
        call.span,
    );
}

fn check_react_class_component_rules(
    semantic: &Semantic<'_>,
    cls: &oxc_ast::ast::Class<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_react_component_class(cls, semantic.source_text()) {
        return;
    }
    let cls_name = cls
        .id
        .as_ref()
        .map_or_else(|| "Component".to_string(), |id| id.name.to_string());

    let mut has_state_or_lifecycle = false;

    for elem in &cls.body.body {
        match elem {
            oxc_ast::ast::ClassElement::PropertyDefinition(prop) if !prop.r#static => {
                if prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("state") {
                    has_state_or_lifecycle = true;
                    push_semantic_site(
                        sites,
                        RuleId::StateInConstructor,
                        Some(cls_name.clone()),
                        "stateInConstructor",
                        "state",
                        format!(
                            "Initialize `this.state` inside the constructor of `{cls_name}` instead of a class property."
                        ),
                        line_starts,
                        prop.span,
                    );
                }
            }
            oxc_ast::ast::ClassElement::MethodDefinition(method) if !method.r#static => {
                let Some(m_name) = method
                    .key
                    .static_name()
                    .and_then(|n| n.as_str().map(str::to_string))
                else {
                    continue;
                };
                if m_name != "render" {
                    has_state_or_lifecycle = true;
                }
                if matches!(
                    m_name.as_str(),
                    "UNSAFE_componentWillMount"
                        | "UNSAFE_componentWillReceiveProps"
                        | "UNSAFE_componentWillUpdate"
                ) {
                    push_semantic_site(
                        sites,
                        RuleId::NoUnsafe,
                        Some(cls_name.clone()),
                        "noUnsafe",
                        &m_name,
                        format!(
                            "Legacy lifecycle method `{m_name}` in `{cls_name}` is unsafe for concurrent rendering."
                        ),
                        line_starts,
                        method.key.span(),
                    );
                }

                if let Some(body) = &method.value.body {
                    check_lifecycle_set_state_calls(
                        semantic,
                        &cls_name,
                        &m_name,
                        body.span,
                        line_starts,
                        sites,
                    );
                }
            }
            _ => {}
        }
    }

    if !has_state_or_lifecycle {
        let cls_src = cls.body.span.source_text(semantic.source_text());
        if !cls_src.contains("this.state")
            && !cls_src.contains("this.setState")
            && !cls_src.contains("this.refs")
        {
            push_semantic_site(
                sites,
                RuleId::PreferFunctionComponent,
                Some(cls_name.clone()),
                "preferFunctionComponent",
                &cls_name,
                format!(
                    "Stateless class component `{cls_name}` has no state or lifecycle methods; convert it to a function component."
                ),
                line_starts,
                cls.span,
            );
        }
    }
}

fn check_lifecycle_set_state_calls(
    semantic: &Semantic<'_>,
    cls_name: &str,
    method_name: &str,
    body_span: Span,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let target_rule = match method_name {
        "componentDidMount" => Some((RuleId::NoDidMountSetState, "noDidMountSetState", false)),
        "componentDidUpdate" => Some((RuleId::NoDidUpdateSetState, "noDidUpdateSetState", true)),
        "componentWillUpdate" | "UNSAFE_componentWillUpdate" => {
            Some((RuleId::NoWillUpdateSetState, "noWillUpdateSetState", false))
        }
        _ => None,
    };
    let Some((rule, message_id, allow_if_guarded)) = target_rule else {
        return;
    };

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
            continue;
        };
        if mem.property.name != "setState"
            || !matches!(
                mem.object.without_parentheses(),
                Expression::ThisExpression(_)
            )
        {
            continue;
        }
        if allow_if_guarded
            && semantic
                .nodes()
                .ancestor_ids(node_id)
                .take_while(|&anc_id| {
                    body_span.contains_inclusive(semantic.nodes().get_node(anc_id).span())
                })
                .any(|anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::IfStatement(_)))
        {
            continue;
        }
        push_semantic_site(
            sites,
            rule,
            Some(cls_name.to_string()),
            message_id,
            method_name,
            format!("Do not call `this.setState` inside `{method_name}` in `{cls_name}`."),
            line_starts,
            call.span,
        );
    }
}
