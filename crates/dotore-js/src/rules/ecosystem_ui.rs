//! Preact (`preact-*`), Ink terminal UI (`ink-*`), and Zod v4 (`zod-v4-*`) rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

mod ink;

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, ImportDeclarationSpecifier, JSXAttributeName,
        JSXAttributeValue, JSXElementName, MethodDefinitionKind, ObjectPropertyKind, Program,
        Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

pub(crate) use self::ink::is_ink_raw_text_violation;
use self::ink::{
    check_ink_jsx_element, check_ink_jsx_opening, check_ink_program_level_rules,
    collect_ink_program_imports, resolve_ink_name,
};
use crate::{
    ir::{
        ByteSpan,
        react_ast::{
            find_enclosing_react_node, get_subject_name, has_import_from,
            is_direct_render_phase_node, is_inside_use_effect,
        },
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const REACT_HOOK_NAMES: &[&str] = &[
    "useCallback", "useContext", "useDebugValue", "useDeferredValue", "useEffect", "useId",
    "useImperativeHandle", "useInsertionEffect", "useLayoutEffect", "useMemo", "useReducer",
    "useRef", "useState", "useSyncExternalStore", "useTransition",
];

const ARRAY_READ_METHODS: &[&str] = &[
    "length", "map", "forEach", "filter", "reduce", "some", "every", "find", "findIndex",
    "flatMap", "slice",
];

const ZOD_STRING_FORMAT_METHODS: &[&str] = &[
    "base64", "base64url", "cidr", "cidrv4", "cidrv6", "cuid", "cuid2", "date", "datetime",
    "duration", "email", "emoji", "ip", "ipv4", "ipv6", "jwt", "nanoid", "time", "ulid", "url",
    "uuid",
];

const ZOD_DEPRECATED_OBJECT_METHODS: &[&str] = &[
    "deepPartial", "merge", "nonstrict", "passthrough", "strict", "strip",
];

const ZOD_DEPRECATED_TOP_LEVEL_FACTORIES: &[&str] = &[
    "nativeEnum", "ostring", "onumber", "oboolean", "oarray", "promise",
];

const ZOD_ERROR_OPTION_KEYS: &[&str] = &["errorMap", "invalid_type_error", "required_error"];

const ZOD_ERROR_DEPRECATED_MEMBERS: &[&str] = &[
    "addIssue", "addIssues", "errors", "flatten", "formErrors", "format",
];

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
                    check_zod_legacy_parse(call, &subject_name, source, line_starts, sites);
                }
            }
            _ => {}
        }
    }
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

    let is_text_like = is_preact_text_like_element(tag, opening);
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        if attr_id.name == "onDoubleClick" {
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
        } else if is_text_like && attr_id.name == "onChange" {
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

fn is_preact_text_like_element(
    tag: &str,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
) -> bool {
    if tag == "textarea" {
        return true;
    }
    if tag != "input" {
        return false;
    }
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
    if subject_name.is_none() || !ARRAY_READ_METHODS.contains(&mem.property.name.as_str()) {
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

// --- Zod v4 rules ---

#[expect(
    clippy::too_many_arguments,
    reason = "Direct site builder helper avoids intermediate wrapper allocation (#50)"
)]
fn push_eco_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
    span: Span,
    line_starts: &[u32],
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.into(),
        message: message.into(),
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix: None,
    });
}

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
        push_eco_site(
            sites,
            RuleId::ZodV4DeprecatedParse,
            subject_name.clone(),
            "zodV4DeprecatedObjectMethod",
            method,
            format!(
                "`z.object(...).{method}()` is deprecated in Zod v4; use `z.strictObject(...)` or `z.looseObject(...)` instead."
            ),
            call.span,
            line_starts,
        );
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

    if ZOD_STRING_FORMAT_METHODS.contains(&method) && recv_text.starts_with("z.string(") {
        push_eco_site(
            sites,
            RuleId::ZodV4PreferTopLevelStringFormats,
            subject_name.clone(),
            "zodV4PreferTopLevelStringFormats",
            method,
            "This `z.string().<format>()` check is deprecated in Zod 4, so it can break during the upgrade.",
            call.span,
            line_starts,
        );
    }

    if is_deprecated_zod_schema_call(recv_text, method, call.arguments.len()) {
        push_eco_site(
            sites,
            RuleId::ZodV4NoDeprecatedSchemaApis,
            subject_name.clone(),
            "zodV4NoDeprecatedSchemaApis",
            method,
            "This Zod 3 schema API changed in Zod 4, so this schema can fail after the upgrade.",
            call.span,
            line_starts,
        );
    }

    if (recv_text == "z" || recv_text.starts_with("z.")) && has_legacy_zod_error_option(call) {
        push_eco_site(
            sites,
            RuleId::ZodV4NoDeprecatedErrorCustomization,
            subject_name.clone(),
            "zodV4NoDeprecatedErrorCustomization",
            method,
            "This Zod 3 error-customization form is not compatible with Zod 4, so custom messages can stop applying during the upgrade.",
            call.span,
            line_starts,
        );
    }

    if is_deprecated_zod_error_call(recv_text, method) {
        push_eco_site(
            sites,
            RuleId::ZodV4NoDeprecatedErrorApis,
            subject_name.clone(),
            "zodV4NoDeprecatedErrorApis",
            method,
            "This ZodError API was removed in Zod 4, so error handling can break during the upgrade.",
            call.span,
            line_starts,
        );
    }
}

fn is_deprecated_zod_schema_call(recv_text: &str, method: &str, arg_count: usize) -> bool {
    (recv_text == "z"
        && (ZOD_DEPRECATED_TOP_LEVEL_FACTORIES.contains(&method)
            || (method == "record" && arg_count == 1)))
        || (recv_text.starts_with("z.object(") && ZOD_DEPRECATED_OBJECT_METHODS.contains(&method))
        || (recv_text.starts_with("z.number(") && method == "safe")
        || (recv_text.starts_with("z.function(") && matches!(method, "args" | "returns"))
}

fn has_legacy_zod_error_option(call: &CallExpression<'_>) -> bool {
    call.arguments.iter().any(|arg| {
        let Some(Expression::ObjectExpression(obj)) =
            arg.as_expression().map(Expression::without_parentheses)
        else {
            return false;
        };
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
    })
}

fn is_deprecated_zod_error_call(recv_text: &str, method: &str) -> bool {
    let is_zod_error_create =
        method == "create" && (recv_text == "ZodError" || recv_text == "z.ZodError");
    let is_zod_error_member_call = ZOD_ERROR_DEPRECATED_MEMBERS.contains(&method)
        && (recv_text.contains("new ZodError")
            || recv_text.contains("new z.ZodError")
            || recv_text.contains("ZodError.create"));
    is_zod_error_create || is_zod_error_member_call
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

// --- Ink call & stdout rules ---

#[expect(
    clippy::too_many_arguments,
    reason = "Checks process.stdout dimension reads in Ink render with precomputed import map (#50)"
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
    if ink_imports.is_empty()
        || subject_name.is_none()
        || !matches!(mem.property.name.as_str(), "columns" | "rows")
        || mem.object.span().source_text(source).trim() != "process.stdout"
    {
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
    reason = "Evaluates all Ink CallExpression rules in a single pass (#50)"
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

    if is_direct_render_phase_node(semantic, node_id) {
        check_ink_render_phase_call(
            call,
            callee_text,
            ink_api,
            subject_name,
            source,
            line_starts,
            sites,
        );
    }
    check_ink_input_and_process_call(
        semantic,
        node_id,
        call,
        callee_text,
        ink_api,
        ink_imports,
        subject_name,
        source,
        line_starts,
        sites,
    );
}

fn check_ink_render_phase_call(
    call: &CallExpression<'_>,
    callee_text: &str,
    ink_api: Option<&str>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ink_api == Some("measureElement") {
        push_eco_site(
            sites,
            RuleId::InkNoMeasureElementInRender,
            subject_name.clone(),
            "inkNoMeasureElementInRender",
            "measureElement",
            "Calling `measureElement` during render reads layout before Ink commits it.",
            call.span,
            line_starts,
        );
    }

    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && matches!(
            mem.property.name.as_str(),
            "focus" | "focusNext" | "focusPrevious"
        )
        && source.contains("useFocusManager")
    {
        push_eco_site(
            sites,
            RuleId::InkNoFocusInRender,
            subject_name.clone(),
            "inkNoFocusInRender",
            mem.property.name.as_str(),
            "Changing Ink focus during render can trigger render loops.",
            call.span,
            line_starts,
        );
    }

    if (callee_text == "setRawMode" || callee_text.ends_with(".setRawMode"))
        && source.contains("useStdin")
    {
        push_eco_site(
            sites,
            RuleId::InkNoDirectRawMode,
            subject_name.clone(),
            "inkNoDirectRawMode",
            "setRawMode",
            "Changing terminal raw mode during render is an untracked side effect.",
            call.span,
            line_starts,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates Ink process exit, suspendTerminal, cursor width, paste, and animation calls (#50)"
)]
fn check_ink_input_and_process_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_text: &str,
    ink_api: Option<&str>,
    ink_imports: &HashMap<String, String>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if callee_text == "process.exit"
        && is_inside_ink_use_input(semantic, node_id, ink_imports, source)
    {
        push_eco_site(
            sites,
            RuleId::InkNoBareProcessExit,
            subject_name.clone(),
            "inkNoBareProcessExit",
            "process.exit",
            "`process.exit()` in an Ink input handler bypasses Ink's terminal cleanup.",
            call.span,
            line_starts,
        );
    }

    if matches!(callee_text, "spawn" | "spawnSync" | "exec" | "execFile")
        && call
            .arguments
            .iter()
            .any(|a| a.span().source_text(source).contains("inherit"))
        && is_inside_ink_use_input(semantic, node_id, ink_imports, source)
        && !is_inside_suspend_terminal(semantic, node_id, source)
    {
        push_eco_site(
            sites,
            RuleId::InkUseSuspendTerminal,
            subject_name.clone(),
            "inkUseSuspendTerminal",
            callee_text,
            "Spawning an interactive child process inside `useInput` without `suspendTerminal()` corrupts raw terminal input.",
            call.span,
            line_starts,
        );
    }

    check_ink_cursor_paste_and_animation_call(
        semantic,
        node_id,
        call,
        callee_text,
        ink_api,
        subject_name,
        source,
        line_starts,
        sites,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks setCursorPosition string length, useInput paste detection, and setInterval animation (#50)"
)]
fn check_ink_cursor_paste_and_animation_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_text: &str,
    ink_api: Option<&str>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && mem.property.name == "setCursorPosition"
        && source.contains("useCursor")
        && let Some(Argument::ObjectExpression(pos_obj)) = call.arguments.first()
    {
        for prop_kind in &pos_obj.properties {
            if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
                && prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some("x")
                && let Expression::StaticMemberExpression(x_mem) = prop.value.without_parentheses()
                && x_mem.property.name == "length"
            {
                push_eco_site(
                    sites,
                    RuleId::InkUseStringWidthForCursor,
                    subject_name.clone(),
                    "inkUseStringWidthForCursor",
                    "length",
                    "JavaScript string length is not a terminal column width for Unicode text.",
                    x_mem.span,
                    line_starts,
                );
            }
        }
    }

    if ink_api == Some("useInput")
        && let Some(first_arg) = call.arguments.first()
    {
        let body_text = first_arg.span().source_text(source);
        if [
            ".includes(\"\\n\")",
            ".includes('\\n')",
            ".split(\"\\n\")",
            ".split('\\n')",
        ]
        .iter()
        .any(|pat| body_text.contains(pat))
        {
            push_eco_site(
                sites,
                RuleId::InkPreferUsePaste,
                subject_name.clone(),
                "inkPreferUsePaste",
                "useInput",
                "Use `usePaste()` instead of inferring paste events from `useInput()` chunks.",
                call.span,
                line_starts,
            );
        }
    }

    if callee_text == "setInterval"
        && is_inside_use_effect(semantic, node_id)
        && call
            .arguments
            .first()
            .is_some_and(|arg| arg.span().source_text(source).contains("setFrame("))
    {
        push_eco_site(
            sites,
            RuleId::InkPreferUseAnimation,
            subject_name.clone(),
            "inkPreferUseAnimation",
            "setInterval",
            "This frame-counter interval is an Ink animation; prefer `useAnimation()`.",
            call.span,
            line_starts,
        );
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
