//! Component contract, complexity, prop design, HOC, and deprecated React/ReactDOM API rules
//! (`no-giant-component`, `no-high-complexity-react-function`, `no-many-boolean-props`,
//! `no-generic-handler-names`, `no-inline-hoc-on-component`, `no-render-in-render`,
//! `no-default-props`, `no-prop-types`, `no-legacy-context-api`, `no-react-dom-deprecated-apis`,
//! `no-react19-deprecated-apis`, `no-legacy-class-lifecycles`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        AssignmentTarget, BindingPattern, CallExpression, Class, ClassElement,
        ExportDefaultDeclaration, Expression, IdentifierReference, JSXAttribute, JSXAttributeValue,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::is_reference_in_jsx;
use crate::{
    ir::{
        ByteSpan, SemanticRuleSite,
        react_ast::{
            find_enclosing_react_node, get_subject_name, is_component_name,
            is_react_component_class,
        },
        types::loc_from_line_starts,
    },
    matchers::{push_semantic_site, resolve_ident_symbol},
    rules::types::RuleId,
};

const MAX_COMPONENT_LINES: u32 = 180;
const MAX_CYCLOMATIC_COMPLEXITY: usize = 12;
const MAX_BOOLEAN_PROPS: usize = 4;

pub(super) fn check_module_and_expr_architecture_rules(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::AssignmentExpression(assign) => {
                if let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && is_component_name(&obj.name)
                {
                    let prop = mem.property.name.as_str();
                    if prop == "defaultProps" {
                        push_semantic_site(
                            sites,
                            RuleId::NoDefaultProps,
                            Some(obj.name.to_string()),
                            "noDefaultProps",
                            &format!("{}.defaultProps", obj.name),
                            format!(
                                "`{}.defaultProps` is deprecated in React 19; use JavaScript default parameters instead.",
                                obj.name
                            ),
                            line_starts,
                            assign.span,
                        );
                    } else if prop == "propTypes" {
                        push_semantic_site(
                            sites,
                            RuleId::NoPropTypes,
                            Some(obj.name.to_string()),
                            "noPropTypes",
                            &format!("{}.propTypes", obj.name),
                            format!(
                                "`{}.propTypes` is removed in React 19; use TypeScript types instead.",
                                obj.name
                            ),
                            line_starts,
                            assign.span,
                        );
                    } else if prop == "contextTypes" || prop == "childContextTypes" {
                        push_semantic_site(
                            sites,
                            RuleId::NoLegacyContextApi,
                            Some(obj.name.to_string()),
                            "noLegacyContextApi",
                            &format!("{}.{prop}", obj.name),
                            format!(
                                "Legacy `{}.{prop}` API was removed in React 19; migrate to `createContext` and `useContext`.",
                                obj.name
                            ),
                            line_starts,
                            assign.span,
                        );
                    }
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && obj.name == "ReactDOM"
                    && matches!(
                        mem.property.name.as_str(),
                        "render" | "hydrate" | "findDOMNode" | "unmountComponentAtNode"
                    )
                {
                    push_semantic_site(
                        sites,
                        RuleId::NoReactDomDeprecatedApis,
                        subj_name.clone(),
                        "noReactDomDeprecatedApis",
                        &format!("ReactDOM.{}", mem.property.name),
                        format!(
                            "`ReactDOM.{}` was removed in React 19; use `createRoot` or `hydrateRoot` from `react-dom/client`.",
                            mem.property.name
                        ),
                        line_starts,
                        call.span,
                    );
                }
                check_no_react19_deprecated_apis(call, &subj_name, line_starts, sites);
            }
            AstKind::ExportDefaultDeclaration(export_default) => {
                check_export_default_inline_hoc(export_default, line_starts, sites);
            }
            AstKind::Class(cls) => {
                check_no_legacy_class_lifecycles(semantic, cls, line_starts, sites);
            }
            _ => {}
        }
    }
}

pub(super) fn check_subject_size_complexity_and_props(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subject_node_id).span();
    let start_loc = loc_from_line_starts(line_starts, subj_span.start);
    let end_loc = loc_from_line_starts(line_starts, subj_span.end);
    let line_count = end_loc.line.saturating_sub(start_loc.line) + 1;
    let span = ByteSpan {
        start: subj_span.start,
        end: subj_span.end,
    };

    // 1. `no-giant-component`
    if line_count > MAX_COMPONENT_LINES {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoGiantComponent,
            subject_name: Some(subj_name.to_string()),
            message_id: "noGiantComponent",
            target_name: subj_name.to_string(),
            message: format!(
                "Component `{subj_name}` spans {line_count} lines (exceeding {MAX_COMPONENT_LINES} lines); split it into smaller focused components or custom hooks."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }

    // 2. `no-high-complexity-react-function`
    let mut branch_points = 1_usize;
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::IfStatement(_)
            | AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::SwitchCase(_)
            | AstKind::ForStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::WhileStatement(_)
            | AstKind::DoWhileStatement(_)
            | AstKind::CatchClause(_) => {
                branch_points += 1;
            }
            _ => {}
        }
    }
    if branch_points > MAX_CYCLOMATIC_COMPLEXITY {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoHighComplexityReactFunction,
            subject_name: Some(subj_name.to_string()),
            message_id: "noHighComplexityReactFunction",
            target_name: subj_name.to_string(),
            message: format!(
                "`{subj_name}` has a cyclomatic complexity of {branch_points} (exceeding {MAX_CYCLOMATIC_COMPLEXITY}); extract complex branching logic into helper functions or child components."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }

    // 3. `no-many-boolean-props`
    if count_boolean_props_on_subject(semantic, subject_node_id) >= MAX_BOOLEAN_PROPS {
        sites.push(SemanticRuleSite {
            rule: RuleId::NoManyBooleanProps,
            subject_name: Some(subj_name.to_string()),
            message_id: "noManyBooleanProps",
            target_name: subj_name.to_string(),
            message: format!(
                "Component `{subj_name}` accepts {MAX_BOOLEAN_PROPS} or more boolean flag props; consolidate mutually exclusive or related flags into an explicit `variant` union prop."
            ),
            loc: start_loc,
            span,
            autofix: None,
        });
    }
}

fn count_boolean_props_on_subject(semantic: &Semantic<'_>, subject_node_id: NodeId) -> usize {
    let params = match semantic.nodes().kind(subject_node_id) {
        AstKind::Function(f) => Some(&f.params.items),
        AstKind::ArrowFunctionExpression(a) => Some(&a.params.items),
        AstKind::VariableDeclarator(decl) => {
            match decl.init.as_ref().map(Expression::without_parentheses) {
                Some(Expression::ArrowFunctionExpression(a)) => Some(&a.params.items),
                Some(Expression::FunctionExpression(f)) => Some(&f.params.items),
                _ => None,
            }
        }
        _ => None,
    };
    let Some(items) = params else {
        return 0;
    };
    let Some(first_param) = items.first() else {
        return 0;
    };
    let mut bool_names: HashSet<String> = HashSet::new();
    if let BindingPattern::ObjectPattern(obj_pat) = &first_param.pattern {
        for prop in &obj_pat.properties {
            let key_opt = prop
                .key
                .static_name()
                .and_then(|n| n.as_str().map(str::to_string));
            let is_bool_default = matches!(
                &prop.value,
                BindingPattern::AssignmentPattern(assign)
                    if matches!(assign.right.without_parentheses(), Expression::BooleanLiteral(_))
            );
            if let Some(k) = key_opt
                && (is_bool_default || has_boolean_prop_prefix(&k))
            {
                bool_names.insert(k);
            }
        }
    }
    let param_src = first_param.span.source_text(semantic.source_text());
    let ts_bool_hits = param_src.matches(": boolean").count();
    bool_names.len().max(ts_bool_hits)
}

fn has_boolean_prop_prefix(name: &str) -> bool {
    for prefix in ["is", "has", "can", "should", "with"] {
        if let Some(rest) = name.strip_prefix(prefix)
            && rest.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        {
            return true;
        }
    }
    false
}

pub(super) fn check_generic_handler_name_attr(
    attr: &JSXAttribute<'_>,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    const GENERIC_HANDLER_NAMES: &[&str] = &[
        "handleClick",
        "handleChange",
        "handleSubmit",
        "handleInput",
        "handlePress",
        "handleEvent",
        "onClickHandler",
        "onChangeHandler",
        "onSubmitHandler",
    ];
    let Some(attr_id) = attr.name.as_identifier() else {
        return;
    };
    if !attr_id.name.starts_with("on") {
        return;
    }
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return;
    };
    let Some(Expression::Identifier(handler_id)) = c
        .expression
        .as_expression()
        .map(Expression::without_parentheses)
    else {
        return;
    };
    if GENERIC_HANDLER_NAMES.contains(&handler_id.name.as_str()) {
        push_semantic_site(
            sites,
            RuleId::NoGenericHandlerNames,
            Some(subj_name.to_string()),
            "noGenericHandlerNames",
            handler_id.name.as_str(),
            format!(
                "Event handler `{}` has a generic name; name it after its domain action (e.g. `handleSaveProfile`).",
                handler_id.name
            ),
            line_starts,
            handler_id.span,
        );
    }
}

pub(super) fn check_inline_hoc_and_render_in_render(
    semantic: &Semantic<'_>,
    subject_node_id: NodeId,
    call_node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Must belong to `subject_node_id` (not an unrelated outer subject when `subject_node_id` is a module-level VariableDeclarator)
    let enclosing_fn_subject = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find(|&anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            ) && find_enclosing_react_node(semantic, anc_id).is_some()
        })
        .and_then(|anc_id| find_enclosing_react_node(semantic, anc_id));
    if enclosing_fn_subject != Some(subject_node_id) {
        return;
    }
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

    // 1. `no-inline-hoc-on-component`: `with*(Comp)`, `memo(Comp)`, `forwardRef(...)`, `observer(Comp)`, `lazy(...)` called inside a component/hook render body
    let is_hoc_factory = matches!(c_name, "memo" | "forwardRef" | "observer" | "lazy")
        || (c_name.starts_with("with")
            && c_name.chars().nth(4).is_some_and(|c| c.is_ascii_uppercase())
            && call
                .arguments
                .first()
                .and_then(|a| a.as_expression())
                .is_some_and(|arg| match arg.without_parentheses() {
                    Expression::Identifier(id) => is_component_name(&id.name),
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
                        true
                    }
                    _ => false,
                }));
    if is_hoc_factory {
        push_semantic_site(
            sites,
            RuleId::NoInlineHocOnComponent,
            Some(subj_name.to_string()),
            "noInlineHocOnComponent",
            c_name,
            format!(
                "Higher-order component `{c_name}(...)` is called inside `{subj_name}`, creating a new component identity on every render; hoist it to module scope."
            ),
            line_starts,
            call.span,
        );
    }

    // 2. `no-render-in-render`: `renderFoo()` helper returning JSX called inside JSX
    if c_name.starts_with("render")
        && c_name.chars().nth(6).is_some_and(|c| c.is_ascii_uppercase())
        && let Expression::Identifier(ident) = call.callee.without_parentheses()
        && is_reference_in_jsx(semantic, find_call_node_id(semantic, subject_node_id, call.span))
        && render_helper_returns_jsx(semantic, ident)
    {
        push_semantic_site(
            sites,
            RuleId::NoRenderInRender,
            Some(subj_name.to_string()),
            "noRenderInRender",
            c_name,
            format!(
                "Calling `{c_name}()` inline in JSX bypasses React component boundaries; extract it as a standalone `<Component />`."
            ),
            line_starts,
            call.span,
        );
    }
}

fn check_export_default_inline_hoc(
    export_default: &ExportDefaultDeclaration<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(expr) = export_default.declaration.as_expression() else {
        return;
    };
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return;
    };
    let Expression::Identifier(callee_id) = call.callee.without_parentheses() else {
        return;
    };
    let c_name = callee_id.name.as_str();
    if !c_name.starts_with("with")
        || !c_name.chars().nth(4).is_some_and(|c| c.is_ascii_uppercase())
    {
        return;
    }
    let is_component_arg = call
        .arguments
        .first()
        .and_then(|a| a.as_expression())
        .is_some_and(|arg| match arg.without_parentheses() {
            Expression::Identifier(id) => is_component_name(&id.name),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
            _ => false,
        });
    if is_component_arg {
        push_semantic_site(
            sites,
            RuleId::NoInlineHocOnComponent,
            None,
            "noInlineHocOnComponent",
            c_name,
            format!(
                "Higher-order component `{c_name}(...)` is called inline in `export default`; assign the wrapped component to a named `const` before exporting."
            ),
            line_starts,
            call.span,
        );
    }
}

fn find_call_node_id(semantic: &Semantic<'_>, fallback: NodeId, target_span: Span) -> NodeId {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if matches!(node.kind(), AstKind::CallExpression(_)) && node.span() == target_span {
            return node_id;
        }
    }
    fallback
}

fn render_helper_returns_jsx(semantic: &Semantic<'_>, ident: &IdentifierReference<'_>) -> bool {
    let Some(sym_id) = resolve_ident_symbol(semantic, ident) else {
        return true;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    let decl_span = semantic.nodes().get_node(decl_id).span();
    semantic.nodes().iter_enumerated().any(|(_, n)| {
        decl_span.contains_inclusive(n.span())
            && matches!(n.kind(), AstKind::JSXElement(_) | AstKind::JSXFragment(_))
    })
}

fn check_no_react19_deprecated_apis(
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let deprecated = match call.callee.without_parentheses() {
        Expression::Identifier(id) => match id.name.as_str() {
            "createFactory" | "findDOMNode" | "unmountComponentAtNode" => Some(id.name.to_string()),
            _ => None,
        },
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                match (obj.name.as_str(), mem.property.name.as_str()) {
                    ("React", "createFactory") => Some("React.createFactory".to_string()),
                    (
                        "ReactDOM",
                        "render" | "hydrate" | "findDOMNode" | "unmountComponentAtNode",
                    ) => Some(format!("ReactDOM.{}", mem.property.name)),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(api_name) = deprecated {
        push_semantic_site(
            sites,
            RuleId::NoReact19DeprecatedApis,
            subj_name.clone(),
            "noReact19DeprecatedApis",
            &api_name,
            format!(
                "`{api_name}` is deprecated or removed in React 19; migrate to modern React 19 APIs."
            ),
            line_starts,
            call.span,
        );
    }
}

fn check_no_legacy_class_lifecycles(
    semantic: &Semantic<'_>,
    cls: &Class<'_>,
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

    for elem in &cls.body.body {
        let ClassElement::MethodDefinition(method) = elem else {
            continue;
        };
        if method.r#static {
            continue;
        }
        let Some(m_name) = method
            .key
            .static_name()
            .and_then(|n| n.as_str().map(str::to_string))
        else {
            continue;
        };
        if matches!(
            m_name.as_str(),
            "componentWillMount"
                | "componentWillReceiveProps"
                | "componentWillUpdate"
                | "UNSAFE_componentWillMount"
                | "UNSAFE_componentWillReceiveProps"
                | "UNSAFE_componentWillUpdate"
        ) {
            push_semantic_site(
                sites,
                RuleId::NoLegacyClassLifecycles,
                Some(cls_name.clone()),
                "noLegacyClassLifecycles",
                &m_name,
                format!(
                    "Legacy class lifecycle `{m_name}` in `{cls_name}` is unsafe in concurrent React; replace it with `componentDidMount`, `componentDidUpdate`, or hooks."
                ),
                line_starts,
                method.key.span(),
            );
        }
    }
}
