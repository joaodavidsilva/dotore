//! Preact (`preact-*`), Ink terminal UI (`ink-*`), and Zod v4 (`zod-v4-*`) rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, ImportDeclarationSpecifier, JSXAttributeName,
        JSXAttributeValue, JSXChild, JSXElement, JSXElementName, MethodDefinitionKind,
        ObjectPropertyKind, Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr,
        react_ast::{
            find_enclosing_react_node, get_subject_name, has_import_from,
            is_direct_render_phase_node, is_inside_use_effect,
        },
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const REACT_HOOK_NAMES: &[&str] = &[
    "useCallback",
    "useContext",
    "useDebugValue",
    "useDeferredValue",
    "useEffect",
    "useId",
    "useImperativeHandle",
    "useInsertionEffect",
    "useLayoutEffect",
    "useMemo",
    "useReducer",
    "useRef",
    "useState",
    "useSyncExternalStore",
    "useTransition",
];

const ARRAY_READ_METHODS: &[&str] = &[
    "length",
    "map",
    "forEach",
    "filter",
    "reduce",
    "some",
    "every",
    "find",
    "findIndex",
    "flatMap",
    "slice",
];

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

const ZOD_STRING_FORMAT_METHODS: &[&str] = &[
    "base64",
    "base64url",
    "cidr",
    "cidrv4",
    "cidrv6",
    "cuid",
    "cuid2",
    "date",
    "datetime",
    "duration",
    "email",
    "emoji",
    "ip",
    "ipv4",
    "ipv6",
    "jwt",
    "nanoid",
    "time",
    "ulid",
    "url",
    "uuid",
];

const ZOD_DEPRECATED_OBJECT_METHODS: &[&str] = &[
    "deepPartial",
    "merge",
    "nonstrict",
    "passthrough",
    "strict",
    "strip",
];

const ZOD_DEPRECATED_TOP_LEVEL_FACTORIES: &[&str] = &[
    "nativeEnum",
    "ostring",
    "onumber",
    "oboolean",
    "oarray",
    "promise",
];

const ZOD_ERROR_OPTION_KEYS: &[&str] = &["errorMap", "invalid_type_error", "required_error"];

const ZOD_ERROR_DEPRECATED_MEMBERS: &[&str] = &[
    "addIssue",
    "addIssues",
    "errors",
    "flatten",
    "formErrors",
    "format",
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

    // If `jsx` is a shadowed local parameter (not an imported component and not a same-file wrapper), skip
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

/// Extracts all Preact, Ink, and Zod semantic rule sites in a single pass.
pub(crate) fn extract_ecosystem_ui_sites(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let ink_imports = collect_ink_program_imports(program);
    let has_zod_import = has_import_from(program, &["zod", "zod/v4"]);

    check_preact_import_rules(program, line_starts, sites);
    check_ink_program_level_rules(program, semantic, &ink_imports, source, line_starts, sites);

    let mut static_count_by_subject: HashMap<String, usize> = HashMap::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::JSXOpeningElement(opening) => {
                check_preact_jsx_opening(opening, &subject_name, line_starts, sites);
                check_ink_jsx_opening(
                    program,
                    semantic,
                    node_id,
                    opening,
                    &ink_imports,
                    &mut static_count_by_subject,
                    &subject_name,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                check_ink_jsx_element(
                    semantic,
                    jsx_el,
                    &ink_imports,
                    &subject_name,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::MethodDefinition(method_def) => {
                check_preact_render_arguments(
                    semantic,
                    node_id,
                    method_def,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::StaticMemberExpression(mem) => {
                check_preact_children_length(
                    semantic,
                    node_id,
                    mem,
                    &subject_name,
                    line_starts,
                    sites,
                );
                check_ink_stdout_window_size(
                    semantic,
                    node_id,
                    mem,
                    &ink_imports,
                    &subject_name,
                    source,
                    line_starts,
                    sites,
                );
                if has_zod_import {
                    check_zod_member_rules(
                        semantic,
                        node_id,
                        mem,
                        &subject_name,
                        source,
                        line_starts,
                        sites,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                check_ink_call_rules(
                    program,
                    semantic,
                    node_id,
                    call,
                    &ink_imports,
                    &subject_name,
                    source,
                    line_starts,
                    sites,
                );
                if has_zod_import {
                    check_zod_call_rules(call, &subject_name, source, line_starts, sites);
                } else {
                    // Preserve `ZodV4DeprecatedParse` when `z.object(...).strict()` is called without an explicit import
                    check_zod_legacy_parse(call, &subject_name, source, line_starts, sites);
                }
            }
            _ => {}
        }
    }
}

fn collect_ink_program_imports(program: &Program<'_>) -> HashMap<String, String> {
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

fn resolve_ink_name<'a>(
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

// --- Preact rules ---

fn check_preact_import_rules(
    program: &Program<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.source.value.as_str() != Some("react") {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        let mut hook_names = Vec::new();
        for spec in specs {
            if let ImportDeclarationSpecifier::ImportSpecifier(s) = spec {
                let name = s.imported.name().as_str();
                if REACT_HOOK_NAMES.contains(&name) {
                    hook_names.push(format!("`{name}`"));
                }
            }
        }
        if !hook_names.is_empty() {
            sites.push(SemanticRuleSite {
                rule: RuleId::PreactNoReactHooksImport,
                subject_name: None,
                message_id: "preactNoReactHooksImport",
                target_name: "react".to_string(),
                message: format!(
                    "Your users hit `__H` undefined errors because importing {} from `react` in a pure-Preact project loads a second copy of the hook state, so import from `preact/hooks` (or `preact/compat`) instead.",
                    hook_names.join(", ")
                ),
                loc: loc_from_line_starts(line_starts, imp.span.start),
                span: ByteSpan {
                    start: imp.span.start,
                    end: imp.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn check_preact_jsx_opening(
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let JSXElementName::Identifier(tag_id) = &opening.name else {
        return;
    };
    let tag = tag_id.name.as_str();
    if !tag.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return;
    }

    // 1. `preact-prefer-ondblclick`
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        if let JSXAttributeName::Identifier(attr_id) = &attr.name
            && attr_id.name == "onDoubleClick"
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::PreactPreferOndblclick,
                subject_name: subject_name.clone(),
                message_id: "preactPreferOndblclick",
                target_name: "onDoubleClick".to_string(),
                message: "Your users get no response from `onDoubleClick` in Preact core, where it never fires, so use `onDblClick` instead, which matches the DOM event name.".to_string(),
                loc: loc_from_line_starts(line_starts, attr.span.start),
                span: ByteSpan {
                    start: attr.span.start,
                    end: attr.span.end,
                },
                autofix: None,
            });
        }
    }

    // 2. `preact-prefer-oninput`
    let is_text_like = if tag == "textarea" {
        true
    } else if tag == "input" {
        let input_type = opening.attributes.iter().find_map(|item| {
            let attr = item.as_attribute()?;
            let JSXAttributeName::Identifier(id) = &attr.name else {
                return None;
            };
            if id.name != "type" {
                return None;
            }
            match attr.value.as_ref()? {
                JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
                JSXAttributeValue::ExpressionContainer(c) => match &c.expression {
                    oxc_ast::ast::JSXExpression::StringLiteral(s) => s.value.as_str(),
                    _ => None,
                },
                _ => None,
            }
        });
        !matches!(input_type, Some("checkbox" | "radio" | "file"))
    } else {
        false
    };

    if is_text_like {
        for item in &opening.attributes {
            let Some(attr) = item.as_attribute() else {
                continue;
            };
            if let JSXAttributeName::Identifier(attr_id) = &attr.name
                && attr_id.name == "onChange"
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::PreactPreferOninput,
                    subject_name: subject_name.clone(),
                    message_id: "preactPreferOninput",
                    target_name: "onChange".to_string(),
                    message: "Your users see no live updates because `onChange` on text inputs in Preact core only fires on blur, so use `onInput` instead. `preact/compat` handles this for you.".to_string(),
                    loc: loc_from_line_starts(line_starts, attr.span.start),
                    span: ByteSpan {
                        start: attr.span.start,
                        end: attr.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }
}

fn check_preact_render_arguments(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    method_def: &oxc_ast::ast::MethodDefinition<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if method_def.r#static || method_def.kind != MethodDefinitionKind::Method {
        return;
    }
    if method_def
        .key
        .static_name()
        .as_ref()
        .and_then(|n| n.as_str())
        != Some("render")
    {
        return;
    }
    let Some(first_param) = method_def.value.params.items.first() else {
        return;
    };
    let is_component_class = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        if let AstKind::Class(cls) = semantic.nodes().kind(anc_id) {
            let header =
                Span::new(cls.span.start, cls.body.span.start).source_text(semantic.source_text());
            header.contains("extends ")
                && (header.contains("Component") || header.contains("PureComponent"))
        } else {
            false
        }
    });
    if !is_component_class {
        return;
    }

    sites.push(SemanticRuleSite {
        rule: RuleId::PreactNoRenderArguments,
        subject_name: subject_name.clone(),
        message_id: "preactNoRenderArguments",
        target_name: "render".to_string(),
        message: "Your users hit `undefined` props under `preact/compat` when you read `render(props, state)` from arguments, since compat uses React's parameterless render, so read from `this.props` & `this.state` instead.".to_string(),
        loc: loc_from_line_starts(line_starts, first_param.span.start),
        span: ByteSpan {
            start: first_param.span.start,
            end: first_param.span.end,
        },
        autofix: None,
    });
}

fn check_preact_children_length(
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if subject_name.is_none() {
        return;
    }
    if !ARRAY_READ_METHODS.contains(&mem.property.name.as_str()) {
        return;
    }
    let is_children_target = match mem.object.without_parentheses() {
        Expression::Identifier(id) => {
            id.name == "children" && !is_to_child_array_binding(semantic, id)
        }
        Expression::StaticMemberExpression(inner) => inner.property.name == "children",
        _ => false,
    };
    if is_children_target {
        sites.push(SemanticRuleSite {
            rule: RuleId::PreactNoChildrenLength,
            subject_name: subject_name.clone(),
            message_id: "preactNoChildrenLength",
            target_name: mem.property.name.to_string(),
            message: "Your users hit a crash when `props.children` is not an array in Preact, so use `toChildArray(children)` from `preact` before calling array methods or reading `.length`.".to_string(),
            loc: loc_from_line_starts(line_starts, mem.span.start),
            span: ByteSpan {
                start: mem.span.start,
                end: mem.span.end,
            },
            autofix: None,
        });
    }
}

fn is_to_child_array_binding(
    semantic: &Semantic<'_>,
    ident: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(ref_id) = ident.reference_id.get() else {
        return false;
    };
    let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
        return false;
    };
    let decl_id = semantic.scoping().symbol_declaration(sym_id);
    if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
        && let Some(init) = &decl.init
    {
        return init
            .span()
            .source_text(semantic.source_text())
            .contains("toChildArray(");
    }
    false
}

// --- Ink rules ---

fn check_ink_program_level_rules(
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

    // 1. `ink-no-repeated-render`: two unconditional `render(...)` calls in the same scope without `.unmount()`
    let mut render_calls: Vec<(Option<NodeId>, Span)> = Vec::new();
    let mut render_to_string_subjects: HashSet<String> = HashSet::new();
    let mut live_render_subjects: HashSet<String> = HashSet::new();
    let mut ctrl_c_safe_subjects: HashSet<String> = HashSet::new();

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
                live_render_subjects.insert(comp_name.clone());
                if render_call_has_exit_on_ctrl_c_false(call, source) {
                    ctrl_c_safe_subjects.insert(comp_name);
                }
            }
            // Skip if inside an `if`/`else` branch or immediately `.unmount()`ed
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
                render_calls.push((owner_fn, call.span));
            }
        } else if ink_api == "renderToString"
            && let Some(comp_name) = extract_rendered_component_name(call, source)
        {
            render_to_string_subjects.insert(comp_name);
        }
    }

    if render_calls.len() >= 2 && !source.contains(".unmount(") && !source.contains("unmount:") {
        for i in 1..render_calls.len() {
            if render_calls[i].0 == render_calls[i - 1].0 {
                let span = render_calls[i].1;
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

    // 2. `ink-ctrl-c-handler-requires-exit-option` & `ink-no-live-hooks-in-render-to-string`
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

        if ink_api == "useInput"
            && let Some(first_arg) = call.arguments.first()
        {
            let handler_text = first_arg.span().source_text(source);
            let checks_ctrl_c = handler_text.contains(".ctrl")
                && (handler_text.contains("\"c\"") || handler_text.contains("'c'"));
            if checks_ctrl_c
                && let Some(comp) = &subj_name
                && live_render_subjects.contains(comp)
                && !ctrl_c_safe_subjects.contains(comp)
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
            && let Some(comp) = &subj_name
            && render_to_string_subjects.contains(comp)
            && !live_render_subjects.contains(comp)
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
    reason = "Evaluates all Ink JSXOpeningElement rules in one pass"
)]
fn check_ink_jsx_opening(
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

    // 1. `ink-no-dom-host-elements`: lowercase HTML tag inside an Ink JSX tree
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
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 2. `ink-no-dom-router`: `Link`, `NavLink`, `BrowserRouter`, `HashRouter` from `react-router-dom` inside Ink tree
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
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 3. `ink-no-layout-inside-text`
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
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }
    // 3b. `ink-newline-inside-text`: `<Newline>` outside `<Text>`
    if ink_el == Some("Newline") && !has_ink_text_ancestor(semantic, node_id, ink_imports, source) {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNewlineInsideText,
            subject_name: subject_name.clone(),
            message_id: "inkNewlineInsideText",
            target_name: "Newline".to_string(),
            message: "Ink `<Newline>` must be rendered inside a `<Text>` component.".to_string(),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 3c. `ink-suspense-requires-concurrent`: `<Suspense>` in Ink without `concurrent: true`
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
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 4. `ink-static-is-append-only` & `ink-no-multiple-static`
    if ink_el == Some("Static") {
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

        // `ink-no-multiple-static`: multiple unconditional `<Static>` in the same component
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

    // 5. `ink-valid-aria-semantics`
    if ink_el.is_some() {
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
                    message: format!("Ink does not support `aria-role=\"{role}\"`; use a supported terminal role."),
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
                    let key_name = prop.key.static_name();
                    if let Some(k) = key_name.as_ref().and_then(|n| n.as_str())
                        && !INK_ARIA_STATES.contains(&k)
                    {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::InkValidAriaSemantics,
                            subject_name: subject_name.clone(),
                            message_id: "inkValidAriaSemantics",
                            target_name: k.to_string(),
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

fn check_ink_jsx_element(
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

#[expect(
    clippy::too_many_arguments,
    reason = "Checks process.stdout dimension reads in Ink render with precomputed import map"
)]
fn check_ink_stdout_window_size(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    ink_imports: &HashMap<String, String>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ink_imports.is_empty() || subject_name.is_none() {
        return;
    }
    if !matches!(mem.property.name.as_str(), "columns" | "rows") {
        return;
    }
    let obj_text = mem.object.span().source_text(source).trim();
    if obj_text != "process.stdout" {
        return;
    }
    if let Some(subj_id) = find_enclosing_react_node(semantic, node_id) {
        let subj_text = semantic
            .nodes()
            .get_node(subj_id)
            .span()
            .source_text(source);
        if subj_text.contains("\"resize\"") || subj_text.contains("'resize'") {
            return;
        }
    }
    sites.push(SemanticRuleSite {
        rule: RuleId::InkUseReactiveWindowSize,
        subject_name: subject_name.clone(),
        message_id: "inkUseReactiveWindowSize",
        target_name: mem.property.name.to_string(),
        message: "Reading `process.stdout.columns`/`rows` during render does not re-render on terminal resize; use `useWindowSize()` instead.".to_string(),
        loc: loc_from_line_starts(line_starts, mem.span.start),
        span: ByteSpan {
            start: mem.span.start,
            end: mem.span.end,
        },
        autofix: None,
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all Ink CallExpression rules in a single pass"
)]
fn check_ink_call_rules(
    _program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    ink_imports: &HashMap<String, String>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ink_imports.is_empty() {
        return;
    }

    let callee_text = call.callee.span().source_text(source).trim();
    let ink_api = resolve_ink_name(callee_text, ink_imports);

    // 1. `ink-no-measure-element-in-render`
    if ink_api == Some("measureElement") && is_direct_render_phase_node(semantic, node_id) {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoMeasureElementInRender,
            subject_name: subject_name.clone(),
            message_id: "inkNoMeasureElementInRender",
            target_name: "measureElement".to_string(),
            message: "Calling `measureElement` during render reads layout before Ink commits it."
                .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `ink-no-focus-in-render`
    if is_direct_render_phase_node(semantic, node_id)
        && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && matches!(
            mem.property.name.as_str(),
            "focus" | "focusNext" | "focusPrevious"
        )
        && source.contains("useFocusManager")
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoFocusInRender,
            subject_name: subject_name.clone(),
            message_id: "inkNoFocusInRender",
            target_name: mem.property.name.to_string(),
            message: "Changing Ink focus during render can trigger render loops.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 3. `ink-no-direct-raw-mode`
    if is_direct_render_phase_node(semantic, node_id)
        && (callee_text == "setRawMode" || callee_text.ends_with(".setRawMode"))
        && source.contains("useStdin")
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoDirectRawMode,
            subject_name: subject_name.clone(),
            message_id: "inkNoDirectRawMode",
            target_name: "setRawMode".to_string(),
            message: "Changing terminal raw mode during render is an untracked side effect."
                .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 4. `ink-no-bare-process-exit`
    if callee_text == "process.exit"
        && is_inside_ink_use_input(semantic, node_id, ink_imports, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkNoBareProcessExit,
            subject_name: subject_name.clone(),
            message_id: "inkNoBareProcessExit",
            target_name: "process.exit".to_string(),
            message: "`process.exit()` in an Ink input handler bypasses Ink's terminal cleanup."
                .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 5. `ink-use-suspend-terminal`
    if matches!(callee_text, "spawn" | "spawnSync" | "exec" | "execFile")
        && call
            .arguments
            .iter()
            .any(|a| a.span().source_text(source).contains("inherit"))
        && is_inside_ink_use_input(semantic, node_id, ink_imports, source)
        && !is_inside_suspend_terminal(semantic, node_id, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkUseSuspendTerminal,
            subject_name: subject_name.clone(),
            message_id: "inkUseSuspendTerminal",
            target_name: callee_text.to_string(),
            message: "Spawning an interactive child process inside `useInput` without `suspendTerminal()` corrupts raw terminal input.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 6. `ink-use-string-width-for-cursor`
    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && mem.property.name == "setCursorPosition"
        && source.contains("useCursor")
        && let Some(Argument::ObjectExpression(pos_obj)) = call.arguments.first()
    {
        for prop_kind in &pos_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            if prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("x")
                && let Expression::StaticMemberExpression(x_mem) = prop.value.without_parentheses()
                && x_mem.property.name == "length"
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::InkUseStringWidthForCursor,
                    subject_name: subject_name.clone(),
                    message_id: "inkUseStringWidthForCursor",
                    target_name: "length".to_string(),
                    message:
                        "JavaScript string length is not a terminal column width for Unicode text."
                            .to_string(),
                    loc: loc_from_line_starts(line_starts, x_mem.span.start),
                    span: ByteSpan {
                        start: x_mem.span.start,
                        end: x_mem.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // 7. `ink-prefer-use-paste`
    if ink_api == Some("useInput")
        && let Some(first_arg) = call.arguments.first()
    {
        let body_text = first_arg.span().source_text(source);
        if body_text.contains(".includes(\"\\n\")")
            || body_text.contains(".includes('\\n')")
            || body_text.contains(".split(\"\\n\")")
            || body_text.contains(".split('\\n')")
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::InkPreferUsePaste,
                subject_name: subject_name.clone(),
                message_id: "inkPreferUsePaste",
                target_name: "useInput".to_string(),
                message:
                    "Use `usePaste()` instead of inferring paste events from `useInput()` chunks."
                        .to_string(),
                loc: loc_from_line_starts(line_starts, call.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }

    // 8. `ink-prefer-use-animation`
    if callee_text == "setInterval"
        && is_inside_use_effect(semantic, node_id)
        && let Some(first_arg) = call.arguments.first()
        && first_arg.span().source_text(source).contains("setFrame(")
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::InkPreferUseAnimation,
            subject_name: subject_name.clone(),
            message_id: "inkPreferUseAnimation",
            target_name: "setInterval".to_string(),
            message: "This frame-counter interval is an Ink animation; prefer `useAnimation()`."
                .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn is_inside_ink_use_input(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ink_imports: &HashMap<String, String>,
    source: &str,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(c) = semantic.nodes().kind(anc_id) {
            let name = c.callee.span().source_text(source).trim();
            if resolve_ink_name(name, ink_imports) == Some("useInput") {
                return true;
            }
        }
    }
    false
}

fn is_inside_suspend_terminal(semantic: &Semantic<'_>, node_id: NodeId, source: &str) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(c) = semantic.nodes().kind(anc_id) {
            let name = c.callee.span().source_text(source).trim();
            if name == "suspendTerminal" || name.ends_with(".suspendTerminal") {
                return true;
            }
        }
    }
    false
}

// --- Zod v4 rules ---

fn check_zod_legacy_parse(
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && matches!(mem.property.name.as_str(), "strict" | "passthrough")
        && mem.object.span().source_text(source).contains("z.object(")
    {
        let method = mem.property.name.as_str();
        sites.push(SemanticRuleSite {
            rule: RuleId::ZodV4DeprecatedParse,
            subject_name: subject_name.clone(),
            message_id: "zodV4DeprecatedObjectMethod",
            target_name: method.to_string(),
            message: format!(
                "`z.object(...).{method}()` is deprecated in Zod v4; use `z.strictObject(...)` or `z.looseObject(...)` instead."
            ),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_zod_call_rules(
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_zod_legacy_parse(call, subject_name, source, line_starts, sites);

    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    let recv_text = mem.object.span().source_text(source).trim();

    // 1. `zod-v4-prefer-top-level-string-formats`: `z.string().email()`
    if ZOD_STRING_FORMAT_METHODS.contains(&method) && recv_text.starts_with("z.string(") {
        sites.push(SemanticRuleSite {
            rule: RuleId::ZodV4PreferTopLevelStringFormats,
            subject_name: subject_name.clone(),
            message_id: "zodV4PreferTopLevelStringFormats",
            target_name: method.to_string(),
            message:
                "This `z.string().<format>()` check is deprecated in Zod 4, so it can break during the upgrade."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `zod-v4-no-deprecated-schema-apis`
    let is_deprecated_schema_call = (recv_text == "z"
        && (ZOD_DEPRECATED_TOP_LEVEL_FACTORIES.contains(&method)
            || (method == "record" && call.arguments.len() == 1)))
        || (recv_text.starts_with("z.object(") && ZOD_DEPRECATED_OBJECT_METHODS.contains(&method))
        || (recv_text.starts_with("z.number(") && method == "safe")
        || (recv_text.starts_with("z.function(") && matches!(method, "args" | "returns"));

    if is_deprecated_schema_call {
        sites.push(SemanticRuleSite {
            rule: RuleId::ZodV4NoDeprecatedSchemaApis,
            subject_name: subject_name.clone(),
            message_id: "zodV4NoDeprecatedSchemaApis",
            target_name: method.to_string(),
            message:
                "This Zod 3 schema API changed in Zod 4, so this schema can fail after the upgrade."
                    .to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 3. `zod-v4-no-deprecated-error-customization`
    if recv_text == "z" || recv_text.starts_with("z.") {
        let has_legacy_error_opt = call.arguments.iter().any(|arg| {
            if let Some(Expression::ObjectExpression(obj)) =
                arg.as_expression().map(Expression::without_parentheses)
            {
                obj.properties.iter().any(|p| {
                    let ObjectPropertyKind::ObjectProperty(prop) = p else {
                        return false;
                    };
                    prop.key
                        .static_name()
                        .as_ref()
                        .and_then(|n| n.as_str())
                        .is_some_and(|k| ZOD_ERROR_OPTION_KEYS.contains(&k))
                })
            } else {
                false
            }
        });
        if has_legacy_error_opt {
            sites.push(SemanticRuleSite {
                rule: RuleId::ZodV4NoDeprecatedErrorCustomization,
                subject_name: subject_name.clone(),
                message_id: "zodV4NoDeprecatedErrorCustomization",
                target_name: method.to_string(),
                message: "This Zod 3 error-customization form is not compatible with Zod 4, so custom messages can stop applying during the upgrade.".to_string(),
                loc: loc_from_line_starts(line_starts, call.span.start),
                span: ByteSpan {
                    start: call.span.start,
                    end: call.span.end,
                },
                autofix: None,
            });
        }
    }

    // 4. `zod-v4-no-deprecated-error-apis`: `ZodError.create(...)` or `(new ZodError(...)).format()`
    let is_zod_error_create =
        method == "create" && (recv_text == "ZodError" || recv_text == "z.ZodError");
    let is_zod_error_member_call = ZOD_ERROR_DEPRECATED_MEMBERS.contains(&method)
        && (recv_text.contains("new ZodError")
            || recv_text.contains("new z.ZodError")
            || recv_text.contains("ZodError.create"));

    if is_zod_error_create || is_zod_error_member_call {
        sites.push(SemanticRuleSite {
            rule: RuleId::ZodV4NoDeprecatedErrorApis,
            subject_name: subject_name.clone(),
            message_id: "zodV4NoDeprecatedErrorApis",
            target_name: method.to_string(),
            message: "This ZodError API was removed in Zod 4, so error handling can break during the upgrade.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
}

fn check_zod_member_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Skip if `mem` is the callee of a `CallExpression` (already handled in `check_zod_call_rules`)
    if let AstKind::CallExpression(parent_call) = semantic.nodes().parent_kind(node_id)
        && parent_call.callee.span().contains_inclusive(mem.span)
    {
        return;
    }

    let prop_name = mem.property.name.as_str();
    let recv_text = mem.object.span().source_text(source).trim();

    if ZOD_ERROR_DEPRECATED_MEMBERS.contains(&prop_name)
        && (recv_text.contains("new ZodError")
            || recv_text.contains("new z.ZodError")
            || recv_text.contains("ZodError.create"))
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::ZodV4NoDeprecatedErrorApis,
            subject_name: subject_name.clone(),
            message_id: "zodV4NoDeprecatedErrorApis",
            target_name: prop_name.to_string(),
            message: "This ZodError API was removed in Zod 4, so error handling can break during the upgrade.".to_string(),
            loc: loc_from_line_starts(line_starts, mem.span.start),
            span: ByteSpan {
                start: mem.span.start,
                end: mem.span.end,
            },
            autofix: None,
        });
    }
}
