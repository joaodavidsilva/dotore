//! Ink terminal UI (`ink-*`) rule detectors and raw-text wrapper analysis.

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        CallExpression, Expression, ImportDeclarationSpecifier, JSXAttributeName,
        JSXAttributeValue, JSXChild, JSXElement, ObjectPropertyKind, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr,
        react_ast::{find_enclosing_react_node, get_subject_name, has_import_from},
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const INK_LAYOUT_COMPONENTS: &[&str] = &["Box", "Spacer", "Static"];
const INK_TEXT_COMPONENTS: &[&str] = &["Text", "Transform"];

const INK_ARIA_ROLES: &[&str] = &[
    "button",
    "checkbox",
    "combobox",
    "list",
    "listbox",
    "listitem",
    "menu",
    "menuitem",
    "option",
    "progressbar",
    "radio",
    "radiogroup",
    "tab",
    "tablist",
    "table",
    "textbox",
    "timer",
    "toolbar",
];

const INK_ARIA_STATES: &[&str] = &[
    "busy",
    "checked",
    "disabled",
    "expanded",
    "multiline",
    "multiselectable",
    "readonly",
    "required",
    "selected",
];

/// Returns `true` if `jsx` is an Ink raw-text violation under `graph` and `file`.
#[must_use]
pub(crate) fn is_ink_raw_text_violation(
    graph: &ProjectGraph,
    file: &FileIr,
    jsx: &JsxElementIr,
) -> bool {
    if !jsx.has_raw_text_child {
        return false;
    }

    let ink_bindings = collect_ink_component_bindings(file);
    let is_ink_text = |name: &str| {
        if let Some(imported) = ink_bindings.get(name) {
            return INK_TEXT_COMPONENTS.contains(&imported.as_str());
        }
        name == "Ink.Text" || name == "Ink.Transform"
    };
    let is_ink_non_text = |name: &str| {
        if let Some(imported) = ink_bindings.get(name) {
            return !INK_TEXT_COMPONENTS.contains(&imported.as_str());
        }
        name.starts_with("Ink.") && !is_ink_text(name)
    };

    if is_ink_text(&jsx.name) || jsx.ancestor_elements.iter().any(|a| is_ink_text(a)) {
        return false;
    }

    if is_ink_non_text(&jsx.name) && (jsx.is_imported_component || jsx.name.starts_with("Ink.")) {
        return true;
    }

    if jsx.is_component
        && let Some(target) =
            graph.resolve_children_forwarding_target(file, &jsx.name, jsx.is_imported_component)
    {
        if INK_TEXT_COMPONENTS.contains(&target.as_str()) || is_ink_text(&target) {
            return false;
        }
        if INK_LAYOUT_COMPONENTS.contains(&target.as_str()) || is_ink_non_text(&target) {
            return true;
        }
    }

    false
}

fn collect_ink_component_bindings(file: &FileIr) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for imp in &file.module.imports {
        if imp.source != "ink" {
            continue;
        }
        for b in &imp.bindings {
            if !b.is_namespace && !b.is_type_only {
                map.insert(b.local_name.clone(), b.imported_name.clone());
            }
        }
    }
    map
}

pub(super) fn collect_ink_program_imports(program: &Program<'_>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.source.value.as_str() != Some("ink") {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    map.insert(
                        s.local.name.to_string(),
                        s.imported.name().as_str().to_string(),
                    );
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                    map.insert(ns.local.name.to_string(), "*".to_string());
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(_) => {}
            }
        }
    }
    map
}

pub(super) fn resolve_ink_name<'a>(
    local_name: &'a str,
    ink_imports: &'a HashMap<String, String>,
) -> Option<&'a str> {
    if let Some(imp) = ink_imports.get(local_name) {
        return Some(imp.as_str());
    }
    if let Some((ns, prop)) = local_name.split_once('.')
        && ink_imports.get(ns).map(String::as_str) == Some("*")
    {
        return Some(prop);
    }
    None
}

#[derive(Default)]
struct InkRenderCallSummary {
    render_calls: Vec<(Option<NodeId>, Span)>,
    render_to_string_subjects: HashSet<String>,
    live_render_subjects: HashSet<String>,
    ctrl_c_safe_subjects: HashSet<String>,
}

pub(super) fn check_ink_program_level_rules(
    _program: &Program<'_>,
    semantic: &Semantic<'_>,
    ink_imports: &HashMap<String, String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ink_imports.is_empty() {
        return;
    }

    let summary = collect_ink_render_call_summary(semantic, ink_imports, source);
    check_ink_repeated_render(&summary.render_calls, source, line_starts, sites);
    check_ink_input_and_render_to_string_hooks(
        semantic,
        ink_imports,
        &summary,
        source,
        line_starts,
        sites,
    );
}

fn collect_ink_render_call_summary(
    semantic: &Semantic<'_>,
    ink_imports: &HashMap<String, String>,
    source: &str,
) -> InkRenderCallSummary {
    let mut summary = InkRenderCallSummary::default();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_text = call.callee.span().source_text(source).trim();
        let Some(ink_api) = resolve_ink_name(callee_text, ink_imports) else {
            continue;
        };

        if ink_api == "render" {
            if let Some(comp_name) = extract_rendered_component_name(call, source) {
                summary.live_render_subjects.insert(comp_name.clone());
                if render_call_has_exit_on_ctrl_c_false(call, source) {
                    summary.ctrl_c_safe_subjects.insert(comp_name);
                }
            }
            let is_conditional = semantic
                .nodes()
                .ancestor_ids(node_id)
                .any(|anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::IfStatement(_)));
            if !is_conditional {
                let owner_fn = semantic.nodes().ancestor_ids(node_id).find(|&anc_id| {
                    matches!(
                        semantic.nodes().kind(anc_id),
                        AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                    )
                });
                summary.render_calls.push((owner_fn, call.span));
            }
        } else if ink_api == "renderToString"
            && let Some(comp_name) = extract_rendered_component_name(call, source)
        {
            summary.render_to_string_subjects.insert(comp_name);
        }
    }
    summary
}

fn check_ink_repeated_render(
    render_calls: &[(Option<NodeId>, Span)],
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if render_calls.len() < 2 || source.contains(".unmount(") || source.contains("unmount:") {
        return;
    }
    for pair in render_calls.windows(2) {
        if let [(prev_owner, _), (curr_owner, span)] = *pair
            && prev_owner == curr_owner
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkNoRepeatedRender,
                subject_name: None,
                message_id: "inkNoRepeatedRender",
                target_name: "render".to_string(),
                message: "Calling Ink `render()` repeatedly on the same stream without unmounting corrupts terminal state; call `instance.rerender()` instead.".to_string(),
                loc: loc_from_line_starts(line_starts, span.start),
                span: ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                autofix: None,
            });
            break;
        }
    }
}

fn check_ink_input_and_render_to_string_hooks(
    semantic: &Semantic<'_>,
    ink_imports: &HashMap<String, String>,
    summary: &InkRenderCallSummary,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_text = call.callee.span().source_text(source).trim();
        let Some(ink_api) = resolve_ink_name(callee_text, ink_imports) else {
            continue;
        };
        let subj_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|s_id| get_subject_name(semantic, s_id));
        let Some(comp) = &subj_name else {
            continue;
        };

        if ink_api == "useInput"
            && let Some(first_arg) = call.arguments.first()
        {
            let handler_text = first_arg.span().source_text(source);
            let checks_ctrl_c = handler_text.contains(".ctrl")
                && (handler_text.contains("\"c\"") || handler_text.contains("'c'"));
            if checks_ctrl_c
                && summary.live_render_subjects.contains(comp)
                && !summary.ctrl_c_safe_subjects.contains(comp)
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::InkCtrlCHandlerRequiresExitOption,
                    subject_name: subj_name.clone(),
                    message_id: "inkCtrlCHandlerRequiresExitOption",
                    target_name: "useInput".to_string(),
                    message: "Ctrl-C handler in `useInput` is unreachable unless `render(<App />, { exitOnCtrlC: false })` is configured.".to_string(),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
            }
        }

        if matches!(ink_api, "useInput" | "usePaste")
            && summary.render_to_string_subjects.contains(comp)
            && !summary.live_render_subjects.contains(comp)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkNoLiveHooksInRenderToString,
                subject_name: subj_name.clone(),
                message_id: "inkNoLiveHooksInRenderToString",
                target_name: ink_api.to_string(),
                message: format!("Ink `{ink_api}` never receives input under `renderToString()`."),
                loc: loc_from_line_starts(line_starts, call.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn extract_rendered_component_name(call: &CallExpression<'_>, source: &str) -> Option<String> {
    let first_arg = call.arguments.first()?.as_expression()?;
    if let Expression::JSXElement(jsx) = first_arg.without_parentheses() {
        Some(
            jsx.opening_element
                .name
                .span()
                .source_text(source)
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

fn render_call_has_exit_on_ctrl_c_false(call: &CallExpression<'_>, source: &str) -> bool {
    let Some(second_arg) = call.arguments.get(1) else {
        return false;
    };
    let text = second_arg.span().source_text(source);
    text.contains("exitOnCtrlC: false") || text.contains("exitOnCtrlC:false")
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all Ink JSXOpeningElement rules in one pass (#50)"
)]
pub(super) fn check_ink_jsx_opening(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    ink_imports: &HashMap<String, String>,
    static_count_by_subject: &mut HashMap<String, usize>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ink_imports.is_empty() {
        return;
    }

    let raw_name = opening.name.span().source_text(source).trim();
    let ink_el = resolve_ink_name(raw_name, ink_imports);

    check_ink_jsx_hierarchy_and_suspense(
        program,
        semantic,
        node_id,
        opening,
        raw_name,
        ink_el,
        ink_imports,
        subject_name,
        source,
        line_starts,
        sites,
    );

    if ink_el == Some("Static") {
        check_ink_static_opening(
            semantic,
            node_id,
            opening,
            static_count_by_subject,
            subject_name,
            line_starts,
            sites,
        );
    }

    if ink_el.is_some() {
        check_ink_aria_attributes(opening, subject_name, line_starts, sites);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks DOM host elements, DOM routers, <Text> nesting, <Newline>, and <Suspense> in Ink JSX (#50)"
)]
fn check_ink_jsx_hierarchy_and_suspense(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    raw_name: &str,
    ink_el: Option<&str>,
    ink_imports: &HashMap<String, String>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };

    if raw_name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
        && has_ink_jsx_ancestor(semantic, node_id, ink_imports, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoDomHostElements,
            subject_name: subject_name.clone(),
            message_id: "inkNoDomHostElements",
            target_name: raw_name.to_string(),
            message: format!("DOM host `<{raw_name}>` cannot be rendered by Ink."),
            loc,
            span,
            autofix: None,
        });
    }

    if matches!(
        raw_name,
        "Link" | "NavLink" | "BrowserRouter" | "HashRouter"
    ) && has_import_from(program, &["react-router-dom"])
        && has_ink_jsx_ancestor(semantic, node_id, ink_imports, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoDomRouter,
            subject_name: subject_name.clone(),
            message_id: "inkNoDomRouter",
            target_name: raw_name.to_string(),
            message: format!("`{raw_name}` depends on DOM history; use a memory router with Ink."),
            loc,
            span,
            autofix: None,
        });
    }

    if let Some(el) = ink_el
        && INK_LAYOUT_COMPONENTS.contains(&el)
        && has_ink_text_ancestor(semantic, node_id, ink_imports, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoLayoutInsideText,
            subject_name: subject_name.clone(),
            message_id: "inkNoLayoutInsideText",
            target_name: el.to_string(),
            message: format!("Ink `<{el}>` cannot render inside `<Text>`."),
            loc,
            span,
            autofix: None,
        });
    }

    if ink_el == Some("Newline") && !has_ink_text_ancestor(semantic, node_id, ink_imports, source) {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNewlineInsideText,
            subject_name: subject_name.clone(),
            message_id: "inkNewlineInsideText",
            target_name: "Newline".to_string(),
            message: "Ink `<Newline>` must be rendered inside a `<Text>` component.".to_string(),
            loc,
            span,
            autofix: None,
        });
    }

    if matches!(raw_name, "Suspense" | "React.Suspense")
        && !source.contains("concurrent: true")
        && !source.contains("concurrent:true")
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkSuspenseRequiresConcurrent,
            subject_name: subject_name.clone(),
            message_id: "inkSuspenseRequiresConcurrent",
            target_name: "Suspense".to_string(),
            message: "Using `<Suspense>` in Ink requires `render(<App />, { concurrent: true })`."
                .to_string(),
            loc,
            span,
            autofix: None,
        });
    }
}

fn check_ink_static_opening(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    static_count_by_subject: &mut HashMap<String, usize>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        if let JSXAttributeName::Identifier(id) = &attr.name
            && id.name == "items"
            && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
            && let Some(expr) = c.expression.as_expression()
            && let Expression::CallExpression(call) = expr.without_parentheses()
            && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
            && matches!(
                mem.property.name.as_str(),
                "reverse" | "sort" | "toReversed" | "toSorted"
            )
            && !matches!(
                mem.object.without_parentheses(),
                Expression::ArrayExpression(_)
            )
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkStaticIsAppendOnly,
                subject_name: subject_name.clone(),
                message_id: "inkStaticIsAppendOnly",
                target_name: mem.property.name.to_string(),
                message: format!(
                    "`<Static>` never revises prior output, but `.{}()` can change existing item order.",
                    mem.property.name
                ),
                loc: loc_from_line_starts(line_starts, attr.span.start),
                span: ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
                autofix: None,
            });
        }
    }

    let is_conditional = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        matches!(
            semantic.nodes().kind(anc_id),
            AstKind::ConditionalExpression(_) | AstKind::LogicalExpression(_)
        )
    });
    if !is_conditional && let Some(subj) = subject_name {
        let count = static_count_by_subject.entry(subj.clone()).or_insert(0);
        *count += 1;
        if *count >= 2 {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkNoMultipleStatic,
                subject_name: subject_name.clone(),
                message_id: "inkNoMultipleStatic",
                target_name: "Static".to_string(),
                message:
                    "Ink tracks one `<Static>` node per root; combine these unconditional regions."
                        .to_string(),
                loc: loc_from_line_starts(line_starts, opening.span.start),
                span: ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_ink_aria_attributes(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(id) = &attr.name else {
            continue;
        };
        if id.name == "aria-role"
            && let Some(JSXAttributeValue::StringLiteral(s)) = &attr.value
            && let Some(role) = s.value.as_str()
            && !INK_ARIA_ROLES.contains(&role)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkValidAriaSemantics,
                subject_name: subject_name.clone(),
                message_id: "inkValidAriaSemantics",
                target_name: role.to_string(),
                message: format!(
                    "Ink does not support `aria-role=\"{role}\"`; use a supported terminal role."
                ),
                loc: loc_from_line_starts(line_starts, attr.span.start),
                span: ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
                autofix: None,
            });
        }
        if id.name == "aria-state"
            && let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
            && let Some(expr) = c.expression.as_expression()
            && let Expression::ObjectExpression(obj) = expr.without_parentheses()
        {
            for prop_kind in &obj.properties {
                let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                    continue;
                };
                if let Some(k) = prop.key.static_name().and_then(|n| n.as_str().map(str::to_string))
                    && !INK_ARIA_STATES.contains(&k.as_str())
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::InkValidAriaSemantics,
                        subject_name: subject_name.clone(),
                        message_id: "inkValidAriaSemantics",
                        target_name: k.clone(),
                        message: format!("Ink `aria-state` does not support `{k}`."),
                        loc: loc_from_line_starts(line_starts, prop.span.start),
                        span: ByteSpan {
                            start: prop.span.start,
                            end: prop.span.end,
                        },
                        autofix: None,
                    });
                }
            }
        }
    }
}

fn has_ink_jsx_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ink_imports: &HashMap<String, String>,
    source: &str,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(jsx_el) = semantic.nodes().kind(anc_id) {
            let name = jsx_el
                .opening_element
                .name
                .span()
                .source_text(source)
                .trim();
            if resolve_ink_name(name, ink_imports).is_some() {
                return true;
            }
        }
    }
    false
}

fn has_ink_text_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ink_imports: &HashMap<String, String>,
    source: &str,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(jsx_el) = semantic.nodes().kind(anc_id) {
            let name = jsx_el
                .opening_element
                .name
                .span()
                .source_text(source)
                .trim();
            if let Some(ink_name) = resolve_ink_name(name, ink_imports)
                && INK_TEXT_COMPONENTS.contains(&ink_name)
            {
                return true;
            }
        }
    }
    false
}

pub(super) fn check_ink_jsx_element(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    ink_imports: &HashMap<String, String>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let raw_name = jsx_el
        .opening_element
        .name
        .span()
        .source_text(source)
        .trim();
    if resolve_ink_name(raw_name, ink_imports) != Some("Static") {
        return;
    }

    for child in &jsx_el.children {
        let JSXChild::ExpressionContainer(c) = child else {
            continue;
        };
        let Some(expr) = c.expression.as_expression() else {
            continue;
        };
        let fn_span = expr.span();
        for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::JSXElement(ret_jsx) = inner_node.kind() else {
                continue;
            };
            if !fn_span.contains_inclusive(ret_jsx.span) {
                continue;
            }
            let has_jsx_parent = semantic.nodes().ancestor_ids(inner_id).any(|anc_id| {
                let anc_span = semantic.nodes().get_node(anc_id).span();
                fn_span.contains_inclusive(anc_span)
                    && matches!(semantic.nodes().kind(anc_id), AstKind::JSXElement(_))
            });
            if has_jsx_parent {
                continue;
            }
            let has_key = ret_jsx.opening_element.attributes.iter().any(|item| {
                item.as_attribute().is_some_and(
                    |a| matches!(&a.name, JSXAttributeName::Identifier(id) if id.name == "key"),
                )
            });
            if !has_key {
                sites.push(SemanticRuleSite {
                    rule: RuleId::InkStaticRequiresKey,
                    subject_name: subject_name.clone(),
                    message_id: "inkStaticRequiresKey",
                    target_name: "Static".to_string(),
                    message: "The root element returned by `<Static>` needs a `key`.".to_string(),
                    loc: loc_from_line_starts(line_starts, ret_jsx.opening_element.span.start),
                    span: ByteSpan {
                        start: ret_jsx.opening_element.span.start,
                        end: ret_jsx.opening_element.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}
