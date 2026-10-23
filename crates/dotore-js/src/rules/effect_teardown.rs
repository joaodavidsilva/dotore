//! Effect Node teardown and React component, hook, and JSX correctness rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    clippy::too_many_arguments,
    reason = "oxc_ast AST enums have 200+ variants; rule detectors match only relevant AST node kinds"
)]

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        ArrowFunctionBody, AssignmentTarget, BinaryOperator, BindingPattern, CallExpression,
        ClassElement, Expression, ImportDeclarationSpecifier, JSXAttributeItem,
        JSXAttributeValue, JSXElement, JSXElementName, JSXOpeningElement, MethodDefinitionKind,
        Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{
        ByteSpan, SemanticRuleSite, SubjectIr, SubjectKind,
        react_ast::{
            classify_jsx_element_name, find_enclosing_react_node, get_effect_cleanup_span,
            get_effect_fn_node, get_subject_name, is_component_name, is_custom_hook,
            is_custom_hook_name, is_direct_render_phase_node, is_functional_component,
            is_inside_use_effect, is_react_component_class, is_react_hook_callee,
        },
        types::loc_from_line_starts,
    },
    rules::types::{AutofixPatch, ByteEdit, RuleId},
};

const EFFECT_HOOKS: &[&str] = &["useEffect", "useLayoutEffect", "useInsertionEffect"];

const DEPS_HOOKS: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useInsertionEffect",
    "useMemo",
    "useCallback",
    "useImperativeHandle",
];

const OBSERVER_CLASSES: &[&str] = &[
    "ResizeObserver",
    "IntersectionObserver",
    "MutationObserver",
    "PerformanceObserver",
];

const VOID_DOM_TAGS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
    "source", "track", "wbr",
];

const BOOLEAN_DOM_ATTRIBUTES: &[&str] = &[
    "allowFullScreen",
    "async",
    "autoFocus",
    "autoPlay",
    "checked",
    "controls",
    "defaultChecked",
    "defer",
    "disabled",
    "formNoValidate",
    "hidden",
    "inert",
    "ismap",
    "itemScope",
    "loop",
    "multiple",
    "muted",
    "noModule",
    "noValidate",
    "novalidate",
    "open",
    "playsInline",
    "readOnly",
    "readonly",
    "required",
    "reversed",
    "selected",
];

const FORBIDDEN_ELEMENTS: &[&str] = &[
    "acronym",
    "applet",
    "basefont",
    "bgsound",
    "big",
    "blink",
    "center",
    "dir",
    "font",
    "frame",
    "frameset",
    "isindex",
    "keygen",
    "marquee",
    "multicol",
    "nextid",
    "nobr",
    "noembed",
    "noframes",
    "plaintext",
    "spacer",
    "strike",
    "tt",
    "xmp",
    "ForbiddenElement",
];

const FORBIDDEN_DOM_PROPS: &[&str] = &[
    "alink",
    "background",
    "bgcolor",
    "border",
    "forbidProp",
    "forbiddenProp",
    "data-forbidden-prop",
    "frameborder",
    "marginheight",
    "marginwidth",
    "nowrap",
    "scrolling",
    "valign",
    "vlink",
];

const INVALID_PARAGRAPH_CHILD_TAGS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "dd",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "search",
    "section",
    "table",
    "ul",
];

const NATIVE_LABEL_CONTROLS: &[&str] = &[
    "button", "input", "meter", "output", "progress", "select", "textarea",
];

const NONDETERMINISTIC_ID_CALLEES: &[&str] = &[
    "nanoid",
    "uuid",
    "uuidv4",
    "uuidV4",
    "v4",
    "uniqueId",
    "shortid",
    "cuid",
    "cuid2",
    "createId",
    "ulid",
];

const BUILTIN_UPPERCASE_CALLS: &[&str] = &[
    "String",
    "Number",
    "Boolean",
    "BigInt",
    "Symbol",
    "Array",
    "Object",
    "Error",
    "TypeError",
    "RangeError",
    "SyntaxError",
    "Date",
    "RegExp",
    "Promise",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Int8Array",
    "Uint8Array",
    "Float32Array",
    "Float64Array",
];

const ARRAY_MUTATING_METHODS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
    "set",
    "add",
    "delete",
    "clear",
];

/// Extracts all 68 Effect Node teardown and React correctness rule sites in a single pass.
pub(crate) fn extract_effect_teardown_sites(
    path: &Path,
    semantic: &Semantic<'_>,
    subjects: &[SubjectIr],
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_file_level_rules(path, semantic, subjects, line_starts, sites);
    check_class_component_rules(semantic, line_starts, sites);

    let mut seen_subjects = HashSet::new();
    for (node_id, _) in semantic.nodes().iter_enumerated() {
        if let Some(subj_id) = find_enclosing_react_node(semantic, node_id)
            && seen_subjects.insert(subj_id)
        {
            check_subject_effect_and_correctness_rules(semantic, subj_id, line_starts, sites);
        }
    }

    check_ast_node_rules(semantic, subjects, line_starts, sites);
}

fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.into(),
        message,
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix,
    });
}

fn check_file_level_rules(
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
    named: &oxc_ast::ast::ImportSpecifier<'_>,
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

fn is_at_module_scope(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::MethodDefinition(_)
            | AstKind::PropertyDefinition(_)
            | AstKind::StaticBlock(_)
            | AstKind::TSTypeAnnotation(_)
            | AstKind::TSTypeReference(_)
            | AstKind::TSTypeQuery(_)
            | AstKind::TSInterfaceDeclaration(_)
            | AstKind::TSTypeAliasDeclaration(_) => return false,
            _ => {}
        }
    }
    true
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
    ident: &oxc_ast::ast::IdentifierReference<'_>,
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
    if let Some(ref_id) = ident.reference_id.get()
        && semantic.scoping().get_reference(ref_id).symbol_id().is_some()
    {
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
                if text.contains("typeof window")
                    || text.contains(&format!("typeof {name}"))
                {
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

fn is_react_class_component(
    semantic: &Semantic<'_>,
    cls: &oxc_ast::ast::Class<'_>,
) -> Option<ReactClassKind> {
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

fn check_class_component_rules(
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
            let method_name = static_key.as_ref().and_then(|n| n.as_str()).unwrap_or_default();
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
        for mount_span in mount_or_ctor_spans {
            let mount_text = mount_span.source_text(semantic.source_text());
            if mount_text.contains("disposeOnUnmount") {
                continue;
            }
            for (_, inner) in semantic.nodes().iter_enumerated() {
                if !mount_span.contains_inclusive(inner.span()) {
                    continue;
                }
                let acquired_resource = match inner.kind() {
                    AstKind::CallExpression(c) => match c.callee.without_parentheses() {
                        Expression::Identifier(id) => matches!(
                            id.name.as_str(),
                            "setInterval" | "setTimeout" | "requestAnimationFrame"
                        )
                        .then_some((id.name.as_str(), c.span)),
                        Expression::StaticMemberExpression(mem) => matches!(
                            mem.property.name.as_str(),
                            "addEventListener" | "subscribe"
                        )
                        .then_some((mem.property.name.as_str(), c.span)),
                        _ => None,
                    },
                    AstKind::NewExpression(n) => match n.callee.without_parentheses() {
                        Expression::Identifier(id)
                            if OBSERVER_CLASSES.contains(&id.name.as_str()) =>
                        {
                            Some((id.name.as_str(), n.span))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                let Some((res_name, res_span)) = acquired_resource else {
                    continue;
                };
                let has_teardown = unmount_span.is_some_and(|u_span| {
                    let u_text = u_span.source_text(semantic.source_text());
                    u_text.contains("removeEventListener")
                        || u_text.contains("clearInterval")
                        || u_text.contains("clearTimeout")
                        || u_text.contains("cancelAnimationFrame")
                        || u_text.contains("unsubscribe")
                        || u_text.contains("disconnect")
                        || u_text.contains("dispose")
                        || u_text.contains("abort")
                });
                if !has_teardown {
                    push_site(
                        sites,
                        RuleId::ClassComponentMissingComponentWillUnmountTeardown,
                        Some(class_name.clone()),
                        "classComponentMissingComponentWillUnmountTeardown",
                        res_name,
                        format!(
                            "`{class_name}` acquires `{res_name}` without releasing it in `componentWillUnmount`."
                        ),
                        res_span,
                        line_starts,
                        None,
                    );
                }
            }
        }

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

fn check_subject_effect_and_correctness_rules(
    semantic: &Semantic<'_>,
    subj_id: NodeId,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subj_span = semantic.nodes().get_node(subj_id).span();
    let subj_name = get_subject_name(semantic, subj_id);
    let is_comp = is_functional_component(semantic, subj_id);
    let is_hook = is_custom_hook(semantic, subj_id);

    let mut state_to_setter: HashMap<String, String> = HashMap::new();
    let mut setter_to_state: HashMap<String, String> = HashMap::new();
    let mut effect_event_names: HashSet<String> = HashSet::new();
    let mut fresh_render_bindings: HashSet<String> = HashSet::new();
    let mut queried_dom_vars: HashSet<String> = HashSet::new();
    let mut debounce_vars: Vec<(String, Span)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if find_enclosing_react_node(semantic, node_id) != Some(subj_id) {
            continue;
        }

        if let AstKind::VariableDeclarator(decl) = node.kind()
            && let Some(init) = decl.init.as_ref().map(Expression::without_parentheses)
        {
            if let Expression::CallExpression(call) = init {
                if is_react_hook_callee(semantic, &call.callee, "useState")
                    && let BindingPattern::ArrayPattern(arr) = &decl.id
                {
                    let s_opt = arr
                        .elements
                        .first()
                        .and_then(Option::as_ref)
                        .and_then(BindingPattern::get_binding_identifier)
                        .map(|id| id.name.to_string());
                    let set_opt = arr
                        .elements
                        .get(1)
                        .and_then(Option::as_ref)
                        .and_then(BindingPattern::get_binding_identifier)
                        .map(|id| id.name.to_string());
                    if let (Some(s), Some(setter)) = (s_opt, set_opt) {
                        state_to_setter.insert(s.clone(), setter.clone());
                        setter_to_state.insert(setter, s);
                    }
                } else if (is_react_hook_callee(semantic, &call.callee, "useEffectEvent")
                    || is_react_hook_callee(
                        semantic,
                        &call.callee,
                        "experimental_useEffectEvent",
                    ))
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    effect_event_names.insert(id.name.to_string());
                } else if is_memoized_debounce_call(semantic, call)
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    debounce_vars.push((id.name.to_string(), decl.span));
                } else if is_dom_query_call(call)
                    && let Some(id) = decl.id.get_binding_identifier()
                {
                    queried_dom_vars.insert(id.name.to_string());
                }
            }
            if is_direct_render_phase_node(semantic, node_id)
                && is_fresh_render_expression(init)
                && let Some(id) = decl.id.get_binding_identifier()
            {
                fresh_render_bindings.insert(id.name.to_string());
            }
        }
    }

    // `debounce-no-cleanup`
    for (deb_name, deb_span) in &debounce_vars {
        let cancel_pattern = format!("{deb_name}.cancel(");
        let current_cancel_pattern = format!("{deb_name}.current.cancel(");
        let current_opt_cancel_pattern = format!("{deb_name}.current?.cancel(");
        let subj_text = subj_span.source_text(semantic.source_text());
        if !subj_text.contains(&cancel_pattern)
            && !subj_text.contains(&current_cancel_pattern)
            && !subj_text.contains(&current_opt_cancel_pattern)
        {
            push_site(
                sites,
                RuleId::DebounceNoCleanup,
                subj_name.clone(),
                "debounceNoCleanup",
                deb_name.clone(),
                format!(
                    "Memoized debounced/throttled callback `{deb_name}` is never cancelled in a `useEffect` cleanup."
                ),
                *deb_span,
                line_starts,
                None,
            );
        }
    }

    // Collect parameter names of this Subject for `no-effect-wrapper-discards-callback-cleanup-return`
    let subj_param_names = get_function_param_names(semantic, subj_id);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        if !subj_span.contains_inclusive(node.span()) {
            continue;
        }
        if find_enclosing_react_node(semantic, node_id) != Some(subj_id) {
            continue;
        }

        match node.kind() {
            AstKind::ThisExpression(this_expr) if is_comp => {
                if is_direct_subject_this(semantic, node_id, subj_id) {
                    push_site(
                        sites,
                        RuleId::NoThisInSfc,
                        subj_name.clone(),
                        "noThisInSfc",
                        "this",
                        "Function components do not have a `this` instance; read from `props` directly.".to_string(),
                        this_expr.span,
                        line_starts,
                        None,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                check_subject_call_rules(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subj_name,
                    is_comp,
                    is_hook,
                    &subj_param_names,
                    &state_to_setter,
                    &setter_to_state,
                    &effect_event_names,
                    &fresh_render_bindings,
                    &queried_dom_vars,
                    line_starts,
                    sites,
                );
            }
            AstKind::AssignmentExpression(assign) => {
                if !queried_dom_vars.is_empty()
                    && is_mutation_of_queried_dom_target(&assign.left, &queried_dom_vars)
                {
                    push_site(
                        sites,
                        RuleId::NoMutateQueriedDomNodeInComponent,
                        subj_name.clone(),
                        "noMutateQueriedDomNodeInComponent",
                        assign.left.span().source_text(semantic.source_text()),
                        "Avoid querying and mutating DOM nodes inside a React component; drive DOM updates via state or refs.".to_string(),
                        assign.span,
                        line_starts,
                        None,
                    );
                }
            }
            AstKind::BinaryExpression(bin) if is_comp => {
                if matches!(
                    bin.operator,
                    BinaryOperator::StrictEquality
                        | BinaryOperator::Equality
                        | BinaryOperator::StrictInequality
                        | BinaryOperator::Inequality
                ) {
                    let text = bin.span.source_text(semantic.source_text());
                    if text.contains("typeof children")
                        || text.contains("typeof props.children")
                    {
                        push_site(
                            sites,
                            RuleId::NoPolymorphicChildren,
                            subj_name.clone(),
                            "noPolymorphicChildren",
                            "children",
                            "Avoid branching on `typeof children` at runtime.".to_string(),
                            bin.span,
                            line_starts,
                            None,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_memoized_debounce_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    let is_hook_wrapper = is_react_hook_callee(semantic, &call.callee, "useMemo")
        || is_react_hook_callee(semantic, &call.callee, "useCallback")
        || is_react_hook_callee(semantic, &call.callee, "useRef");
    if !is_hook_wrapper {
        return false;
    }
    let Some(first_arg) = call.arguments.first() else {
        return false;
    };
    let text = first_arg.span().source_text(semantic.source_text());
    text.contains("debounce(") || text.contains("throttle(")
}

fn is_dom_query_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(
        mem.object.without_parentheses(),
        Expression::Identifier(id) if id.name == "document"
    ) && matches!(
        mem.property.name.as_str(),
        "getElementById"
            | "querySelector"
            | "querySelectorAll"
            | "getElementsByClassName"
            | "getElementsByTagName"
    )
}

fn is_mutation_of_queried_dom_target(
    target: &AssignmentTarget<'_>,
    queried_dom_vars: &HashSet<String>,
) -> bool {
    let Some(mem) = target.as_member_expression() else {
        return false;
    };
    let mut curr = mem.object().without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return queried_dom_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::CallExpression(c) => return is_dom_query_call(c),
            _ => return false,
        }
    }
}

fn is_fresh_render_expression(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::NewExpression(_) => true,
        Expression::CallExpression(call) => match call.callee.without_parentheses() {
            Expression::StaticMemberExpression(mem) => matches!(
                mem.property.name.as_str(),
                "filter" | "map" | "slice" | "concat" | "flat" | "flatMap" | "from"
            ),
            _ => false,
        },
        _ => false,
    }
}

fn get_function_param_names(semantic: &Semantic<'_>, fn_node_id: NodeId) -> HashSet<String> {
    let mut names = HashSet::new();
    match semantic.nodes().kind(fn_node_id) {
        AstKind::Function(f) => {
            for param in &f.params.items {
                if let Some(id) = param.pattern.get_binding_identifier() {
                    names.insert(id.name.to_string());
                }
            }
        }
        AstKind::ArrowFunctionExpression(arr) => {
            for param in &arr.params.items {
                if let Some(id) = param.pattern.get_binding_identifier() {
                    names.insert(id.name.to_string());
                }
            }
        }
        _ => {}
    }
    names
}

fn is_direct_subject_this(semantic: &Semantic<'_>, node_id: NodeId, subj_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subj_id {
            return true;
        }
        if matches!(
            semantic.nodes().kind(anc_id),
            AstKind::Function(_) | AstKind::MethodDefinition(_) | AstKind::Class(_)
        ) {
            return false;
        }
    }
    false
}

fn check_subject_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_id: NodeId,
    subj_name: &Option<String>,
    is_comp: bool,
    is_hook: bool,
    subj_param_names: &HashSet<String>,
    state_to_setter: &HashMap<String, String>,
    setter_to_state: &HashMap<String, String>,
    effect_event_names: &HashSet<String>,
    fresh_render_bindings: &HashSet<String>,
    queried_dom_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee = call.callee.without_parentheses();
    let in_render_phase = is_direct_render_phase_node(semantic, node_id);

    // 1. Effect hooks (`useEffect`, `useLayoutEffect`, `useInsertionEffect`)
    if EFFECT_HOOKS
        .iter()
        .any(|h| is_react_hook_callee(semantic, callee, h))
    {
        check_effect_hook_call(
            semantic,
            node_id,
            call,
            subj_name,
            is_hook,
            subj_param_names,
            setter_to_state,
            effect_event_names,
            fresh_render_bindings,
            line_starts,
            sites,
        );
    }

    // 2. All hooks with dependency arrays (`hooks-no-nan-in-deps`, `no-mutable-in-deps`, `no-effect-event-in-deps`)
    if let Some(hook_name) = DEPS_HOOKS
        .iter()
        .copied()
        .find(|h| is_react_hook_callee(semantic, callee, h))
    {
        let deps_idx = if hook_name == "useImperativeHandle" {
            2
        } else {
            1
        };
        if let Some(deps_expr) = call.arguments.get(deps_idx).and_then(|a| a.as_expression())
            && let Expression::ArrayExpression(arr) = deps_expr.without_parentheses()
        {
            for elem in &arr.elements {
                let Some(dep_expr) = elem.as_expression() else {
                    continue;
                };
                check_single_dep_expression(
                    semantic,
                    dep_expr.without_parentheses(),
                    hook_name,
                    subj_name,
                    effect_event_names,
                    fresh_render_bindings,
                    line_starts,
                    sites,
                );
            }
        }
    }

    // 3. `useReducer(reducerFn, ...)` -> `no-mutating-reducer-state`
    if is_react_hook_callee(semantic, callee, "useReducer")
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        check_reducer_arg_for_mutation(semantic, first_arg, subj_name, line_starts, sites);
    }

    // 4. `createContext` in render (`no-create-context-in-render`)
    if !is_at_module_scope(semantic, node_id)
        && is_react_hook_callee(semantic, callee, "createContext")
    {
        push_site(
            sites,
            RuleId::NoCreateContextInRender,
            subj_name.clone(),
            "noCreateContextInRender",
            "createContext",
            "Move `createContext(...)` to module scope so context identity does not reset on every render.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // 5. `createRef` in function component (`no-create-ref-in-function-component`)
    if (is_comp || is_hook)
        && !is_at_module_scope(semantic, node_id)
        && is_react_hook_callee(semantic, callee, "createRef")
    {
        push_site(
            sites,
            RuleId::NoCreateRefInFunctionComponent,
            subj_name.clone(),
            "noCreateRefInFunctionComponent",
            "createRef",
            "Replace `createRef()` with `useRef()` inside function components and hooks.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // 6. Render-phase-only calls (`no-create-object-url-in-render`, `no-create-store-in-render`, `no-nondeterministic-id-value-in-render-body`, `waapi-animation-in-render`)
    if in_render_phase && !is_at_module_scope(semantic, node_id) {
        check_render_phase_call(semantic, node_id, call, subj_name, line_starts, sites);
    }

    // 7. State setter calls (`no-boolean-toggle-without-functional-update`, `no-impure-state-updater`, `no-mutate-then-set-or-return-same-reference`)
    if let Expression::Identifier(callee_id) = callee
        && let Some(state_name) = setter_to_state.get(callee_id.name.as_str())
        && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
    {
        check_state_setter_call(
            semantic,
            node_id,
            call,
            callee_id.name.as_str(),
            state_name,
            first_arg.without_parentheses(),
            subj_id,
            subj_name,
            setter_to_state,
            line_starts,
            sites,
        );
    }

    // 8. Mutating method call on queried DOM variable (`no-mutate-queried-dom-node-in-component`)
    if !queried_dom_vars.is_empty()
        && let Expression::StaticMemberExpression(mem) = callee
    {
        let prop = mem.property.name.as_str();
        if matches!(
            prop,
            "setAttribute"
                | "removeAttribute"
                | "toggleAttribute"
                | "appendChild"
                | "removeChild"
                | "replaceChild"
                | "remove"
                | "add"
                | "toggle"
        ) && expr_roots_at_queried_dom(mem.object.without_parentheses(), queried_dom_vars)
        {
            push_site(
                sites,
                RuleId::NoMutateQueriedDomNodeInComponent,
                subj_name.clone(),
                "noMutateQueriedDomNodeInComponent",
                prop,
                "Avoid querying and mutating DOM nodes inside a React component; drive DOM updates via state or refs.".to_string(),
                call.span,
                line_starts,
                None,
            );
        }
    }

    let _ = state_to_setter;
}

fn expr_roots_at_queried_dom(
    expr: &Expression<'_>,
    queried_dom_vars: &HashSet<String>,
) -> bool {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return queried_dom_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::CallExpression(c) => return is_dom_query_call(c),
            _ => return false,
        }
    }
}

#[derive(Clone)]
struct ListenerCallInfo {
    target_text: String,
    event_type: Option<String>,
    event_type_span: Option<Span>,
    handler_text: Option<String>,
    handler_is_ident: bool,
    capture_flag: bool,
    has_abort_signal: bool,
    call_span: Span,
}

fn parse_listener_call(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    expected_method: &str,
) -> Option<ListenerCallInfo> {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return None;
    };
    if mem.property.name.as_str() != expected_method {
        return None;
    }
    let target_text = mem
        .object
        .without_parentheses()
        .span()
        .source_text(semantic.source_text())
        .trim()
        .to_string();

    let first_arg = call.arguments.first()?.as_expression()?.without_parentheses();
    let (event_type, event_type_span) = match first_arg {
        Expression::StringLiteral(s) => (
            Some(s.value.as_str().unwrap_or_default().to_string()),
            Some(s.span),
        ),
        _ => (None, None),
    };

    let second_arg = call.arguments.get(1).and_then(|a| a.as_expression()).map(Expression::without_parentheses);
    let (handler_text, handler_is_ident) = match second_arg {
        Some(Expression::Identifier(id)) => (Some(id.name.to_string()), true),
        Some(Expression::StaticMemberExpression(m)) => (
            Some(
                m.span
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            ),
            true,
        ),
        Some(other) => (
            Some(
                other
                    .span()
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string(),
            ),
            false,
        ),
        None => (None, false),
    };

    let third_arg = call
        .arguments
        .get(2)
        .and_then(|a| a.as_expression())
        .map(Expression::without_parentheses);
    let mut capture_flag = false;
    let mut has_abort_signal = false;
    if let Some(opt) = third_arg {
        match opt {
            Expression::BooleanLiteral(b) => capture_flag = b.value,
            Expression::ObjectExpression(obj) => {
                let obj_text = obj.span.source_text(semantic.source_text());
                if obj_text.contains("capture: true") || obj_text.contains("capture:true") {
                    capture_flag = true;
                }
                if obj_text.contains("signal") {
                    has_abort_signal = true;
                }
            }
            _ => {}
        }
    }

    Some(ListenerCallInfo {
        target_text,
        event_type,
        event_type_span,
        handler_text,
        handler_is_ident,
        capture_flag,
        has_abort_signal,
        call_span: call.span,
    })
}

fn check_effect_hook_call(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    is_hook: bool,
    subj_param_names: &HashSet<String>,
    setter_to_state: &HashMap<String, String>,
    _effect_event_names: &HashSet<String>,
    _fresh_render_bindings: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return;
    };
    let cb = first_arg.without_parentheses();

    // `no-async-effect-callback`
    let is_async = match cb {
        Expression::ArrowFunctionExpression(arr) => arr.r#async,
        Expression::FunctionExpression(f) => f.r#async,
        _ => false,
    };
    if is_async {
        push_site(
            sites,
            RuleId::NoAsyncEffectCallback,
            subj_name.clone(),
            "noAsyncEffectCallback",
            "useEffect",
            "Effect callbacks cannot be `async` because an `async` function returns a Promise instead of a cleanup function.".to_string(),
            cb.span(),
            line_starts,
            None,
        );
    }

    let Some(effect_fn_id) = get_effect_fn_node(semantic, call_node_id) else {
        return;
    };
    let effect_fn_span = semantic.nodes().get_node(effect_fn_id).span();
    let cleanup_span = get_effect_cleanup_span(semantic, effect_fn_id);
    let cleanup_text = cleanup_span
        .map(|s| s.source_text(semantic.source_text()))
        .unwrap_or_default();

    // Collect deps identifier names
    let mut dep_ident_names: HashSet<String> = HashSet::new();
    if let Some(deps_arg) = call.arguments.get(1).and_then(|a| a.as_expression())
        && let Expression::ArrayExpression(arr) = deps_arg.without_parentheses()
    {
        for elem in &arr.elements {
            if let Some(Expression::Identifier(id)) =
                elem.as_expression().map(Expression::without_parentheses)
            {
                dep_ident_names.insert(id.name.to_string());
            }
        }
    }

    // `no-effect-wrapper-discards-callback-cleanup-return`
    if is_hook
        && cleanup_span.is_none()
        && !subj_param_names.is_empty()
        && let AstKind::ArrowFunctionExpression(arr) = semantic.nodes().kind(effect_fn_id)
        && let ArrowFunctionBody::FunctionBody(body) = &arr.body
    {
        for stmt in &body.statements {
            if let Statement::ExpressionStatement(expr_stmt) = stmt
                && let Expression::CallExpression(inner_call) =
                    expr_stmt.expression.without_parentheses()
                && let Expression::Identifier(callee_id) =
                    inner_call.callee.without_parentheses()
                && subj_param_names.contains(callee_id.name.as_str())
            {
                push_site(
                    sites,
                    RuleId::NoEffectWrapperDiscardsCallbackCleanupReturn,
                    subj_name.clone(),
                    "noEffectWrapperDiscardsCallbackCleanupReturn",
                    callee_id.name.as_str(),
                    format!(
                        "Custom effect wrapper calls `{}` without returning its cleanup function; use `return {}()`.",
                        callee_id.name, callee_id.name
                    ),
                    inner_call.span,
                    line_starts,
                    None,
                );
            }
        }
    }

    let mut add_listeners: Vec<ListenerCallInfo> = Vec::new();
    let mut remove_listeners: Vec<ListenerCallInfo> = Vec::new();
    let mut distinct_sync_setters: HashSet<String> = HashSet::new();

    for (inner_id, inner_node) in semantic.nodes().iter_enumerated() {
        let inner_span = inner_node.span();
        if !effect_fn_span.contains_inclusive(inner_span) {
            continue;
        }
        let in_cleanup = cleanup_span.is_some_and(|cs| cs.contains_inclusive(inner_span));

        match inner_node.kind() {
            AstKind::NewExpression(new_expr) if !in_cleanup => {
                if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                    && OBSERVER_CLASSES.contains(&id.name.as_str())
                {
                    let has_disconnect = cleanup_text.contains(".disconnect(")
                        || cleanup_text.contains(".unobserve(");
                    if !has_disconnect {
                        push_site(
                            sites,
                            RuleId::EffectObserverNeedsDisconnect,
                            subj_name.clone(),
                            "effectObserverNeedsDisconnect",
                            id.name.as_str(),
                            format!(
                                "`new {}` in `useEffect` is never disconnected in cleanup; return `() => observer.disconnect()`.",
                                id.name
                            ),
                            new_expr.span,
                            line_starts,
                            None,
                        );
                    }
                }
            }
            AstKind::CallExpression(inner_call) => {
                if in_cleanup {
                    if let Some(rem) =
                        parse_listener_call(semantic, inner_call, "removeEventListener")
                    {
                        remove_listeners.push(rem);
                    }
                    continue;
                }

                if let Some(add) = parse_listener_call(semantic, inner_call, "addEventListener") {
                    // `advanced-event-handler-refs`
                    if let Some(handler_name) = &add.handler_text
                        && add.handler_is_ident
                        && dep_ident_names.contains(handler_name)
                    {
                        push_site(
                            sites,
                            RuleId::AdvancedEventHandlerRefs,
                            subj_name.clone(),
                            "advancedEventHandlerRefs",
                            handler_name.clone(),
                            format!(
                                "Effect re-subscribes `addEventListener` whenever `{handler_name}` changes; store `{handler_name}` in a ref or `useEffectEvent`."
                            ),
                            inner_call.span,
                            line_starts,
                            None,
                        );
                    }
                    add_listeners.push(add);
                }

                // `effect-raf-loop-needs-cancel`
                let is_raf = match inner_call.callee.without_parentheses() {
                    Expression::Identifier(id) => id.name == "requestAnimationFrame",
                    Expression::StaticMemberExpression(mem) => {
                        mem.property.name == "requestAnimationFrame"
                    }
                    _ => false,
                };
                if is_raf && !cleanup_text.contains("cancelAnimationFrame") {
                    push_site(
                        sites,
                        RuleId::EffectRafLoopNeedsCancel,
                        subj_name.clone(),
                        "effectRafLoopNeedsCancel",
                        "requestAnimationFrame",
                        "`requestAnimationFrame` inside `useEffect` has no `cancelAnimationFrame` in cleanup.".to_string(),
                        inner_call.span,
                        line_starts,
                        None,
                    );
                }

                // `no-cascading-set-state`
                if let Expression::Identifier(callee_id) = inner_call.callee.without_parentheses()
                    && setter_to_state.contains_key(callee_id.name.as_str())
                    && crate::ir::dataflow::is_synchronous(semantic, inner_id, effect_fn_id)
                {
                    distinct_sync_setters.insert(callee_id.name.to_string());
                }

                // `no-promise-then-side-effect-in-effect-without-catch`
                if let Expression::StaticMemberExpression(mem) =
                    inner_call.callee.without_parentheses()
                    && mem.property.name == "then"
                    && inner_call.arguments.len() == 1
                {
                    check_promise_then_without_catch(
                        semantic,
                        inner_id,
                        inner_call,
                        setter_to_state,
                        subj_name,
                        line_starts,
                        sites,
                    );
                }
            }
            _ => {}
        }
    }

    if distinct_sync_setters.len() >= 2 {
        push_site(
            sites,
            RuleId::NoCascadingSetState,
            subj_name.clone(),
            "noCascadingSetState",
            "useEffect",
            "Effect calls multiple state setters synchronously; combine related state or derive values during render.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // Match `add_listeners` vs `remove_listeners`
    check_effect_listener_mismatches(
        &add_listeners,
        &remove_listeners,
        cleanup_text,
        subj_name,
        line_starts,
        sites,
    );
}

fn check_effect_listener_mismatches(
    add_listeners: &[ListenerCallInfo],
    remove_listeners: &[ListenerCallInfo],
    cleanup_text: &str,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if add_listeners.is_empty() || remove_listeners.is_empty() {
        return;
    }
    for add in add_listeners {
        if add.has_abort_signal && cleanup_text.contains(".abort(") {
            continue;
        }
        // Check if there is an exact matching remove
        let has_exact_match = remove_listeners.iter().any(|rem| {
            rem.target_text == add.target_text
                && rem.event_type == add.event_type
                && rem.handler_text == add.handler_text
                && rem.handler_is_ident
                && add.handler_is_ident
                && rem.capture_flag == add.capture_flag
        });
        if has_exact_match {
            continue;
        }

        // Check if there is a remove with the same target & event_type, but different handler reference
        if let Some(rem_same_event) = remove_listeners
            .iter()
            .find(|rem| rem.target_text == add.target_text && rem.event_type == add.event_type)
        {
            if rem_same_event.handler_text != add.handler_text
                || !rem_same_event.handler_is_ident
                || !add.handler_is_ident
            {
                push_site(
                    sites,
                    RuleId::EffectListenerCleanupReferenceMismatch,
                    subj_name.clone(),
                    "effectListenerCleanupReferenceMismatch",
                    rem_same_event
                        .handler_text
                        .clone()
                        .unwrap_or_else(|| "removeEventListener".to_string()),
                    "Effect cleanup passes a different listener reference to `removeEventListener` than was registered with `addEventListener`.".to_string(),
                    rem_same_event.call_span,
                    line_starts,
                    None,
                );
            } else if rem_same_event.capture_flag != add.capture_flag {
                push_site(
                    sites,
                    RuleId::EffectListenerCleanupMismatch,
                    subj_name.clone(),
                    "effectListenerCleanupMismatch",
                    rem_same_event
                        .event_type
                        .clone()
                        .unwrap_or_else(|| "removeEventListener".to_string()),
                    "`removeEventListener` capture flag does not match `addEventListener`.".to_string(),
                    rem_same_event.call_span,
                    line_starts,
                    None,
                );
            }
            continue;
        }

        // Otherwise, if there is a remove with the same handler (or only 1 add & 1 remove), it's a listener cleanup mismatch (wrong event type or wrong target)
        let candidate_rem = remove_listeners
            .iter()
            .find(|rem| rem.handler_text == add.handler_text)
            .or_else(|| (add_listeners.len() == 1 && remove_listeners.len() == 1).then(|| &remove_listeners[0]));

        if let Some(rem) = candidate_rem {
            let autofix = if rem.target_text == add.target_text
                && let (Some(add_ev), Some(rem_ev_span)) = (&add.event_type, rem.event_type_span)
            {
                Some(AutofixPatch {
                    description: format!(
                        "Change `removeEventListener` event type to `'{add_ev}'` to match `addEventListener`"
                    ),
                    edits: vec![ByteEdit {
                        file: None,
                        span: ByteSpan {
                            start: rem_ev_span.start,
                            end: rem_ev_span.end,
                        },
                        replacement: format!("'{add_ev}'"),
                    }],
                })
            } else {
                None
            };

            push_site(
                sites,
                RuleId::EffectListenerCleanupMismatch,
                subj_name.clone(),
                "effectListenerCleanupMismatch",
                rem.event_type
                    .clone()
                    .unwrap_or_else(|| "removeEventListener".to_string()),
                "`removeEventListener` in effect cleanup does not match the event type or target of `addEventListener`.".to_string(),
                rem.call_span,
                line_starts,
                autofix,
            );
        }
    }
}

fn check_promise_then_without_catch(
    semantic: &Semantic<'_>,
    then_node_id: NodeId,
    then_call: &CallExpression<'_>,
    setter_to_state: &HashMap<String, String>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Check if an enclosing chain has `.catch(...)` or if this is the outermost `.then(...)`
    for anc_id in semantic.nodes().ancestor_ids(then_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::StaticMemberExpression(mem) => {
                if mem.property.name == "catch" {
                    return;
                }
                if mem.property.name == "then" {
                    // Outer `.then` will be checked instead
                    return;
                }
            }
            AstKind::CallExpression(_) | AstKind::ParenthesizedExpression(_) => {}
            _ => break,
        }
    }

    let Some(cb_arg) = then_call.arguments.first() else {
        return;
    };
    let cb_span = cb_arg.span();
    let mut calls_setter = false;
    for (_, inner) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(inner.span()) {
            continue;
        }
        if let AstKind::CallExpression(c) = inner.kind()
            && let Expression::Identifier(id) = c.callee.without_parentheses()
            && (setter_to_state.contains_key(id.name.as_str()) || id.name.starts_with("set"))
        {
            calls_setter = true;
            break;
        }
    }

    if calls_setter {
        push_site(
            sites,
            RuleId::NoPromiseThenSideEffectInEffectWithoutCatch,
            subj_name.clone(),
            "noPromiseThenSideEffectInEffectWithoutCatch",
            "then",
            "Promise `.then(...)` in `useEffect` updates state without a `.catch(...)` handler.".to_string(),
            then_call.span,
            line_starts,
            None,
        );
    }
}

fn check_single_dep_expression(
    semantic: &Semantic<'_>,
    dep_expr: &Expression<'_>,
    hook_name: &str,
    subj_name: &Option<String>,
    effect_event_names: &HashSet<String>,
    fresh_render_bindings: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_effect_hook = EFFECT_HOOKS.contains(&hook_name);

    match dep_expr {
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            if name == "NaN" {
                push_site(
                    sites,
                    RuleId::HooksNoNanInDeps,
                    subj_name.clone(),
                    "hooksNoNanInDeps",
                    "NaN",
                    "`NaN` should not be listed in hook dependency arrays.".to_string(),
                    id.span,
                    line_starts,
                    None,
                );
            }
            if effect_event_names.contains(name) {
                push_site(
                    sites,
                    RuleId::NoEffectEventInDeps,
                    subj_name.clone(),
                    "noEffectEventInDeps",
                    name,
                    format!(
                        "Effect Event `{name}` must not be listed in `{hook_name}` dependencies."
                    ),
                    id.span,
                    line_starts,
                    None,
                );
            }
            if is_effect_hook && fresh_render_bindings.contains(name) {
                push_site(
                    sites,
                    RuleId::NoEffectWithFreshDeps,
                    subj_name.clone(),
                    "noEffectWithFreshDeps",
                    name,
                    format!(
                        "`{name}` is recreated on every render and listed in `{hook_name}` dependencies."
                    ),
                    id.span,
                    line_starts,
                    None,
                );
            }
        }
        Expression::StaticMemberExpression(mem) => {
            let full_text = mem.span.source_text(semantic.source_text());
            if full_text == "Number.NaN" {
                push_site(
                    sites,
                    RuleId::HooksNoNanInDeps,
                    subj_name.clone(),
                    "hooksNoNanInDeps",
                    "Number.NaN",
                    "`Number.NaN` should not be listed in hook dependency arrays.".to_string(),
                    mem.span,
                    line_starts,
                    None,
                );
            } else if mem.property.name == "current"
                || full_text.starts_with("window.")
                || full_text.starts_with("location.")
                || full_text.starts_with("document.")
                || full_text.starts_with("navigator.")
                || full_text.contains(".current.")
            {
                push_site(
                    sites,
                    RuleId::NoMutableInDeps,
                    subj_name.clone(),
                    "noMutableInDeps",
                    full_text,
                    format!(
                        "Mutable value `{full_text}` in `{hook_name}` dependencies does not trigger re-renders when mutated."
                    ),
                    mem.span,
                    line_starts,
                    None,
                );
            }
        }
        other if is_effect_hook && is_fresh_render_expression(other) => {
            let text = other.span().source_text(semantic.source_text());
            push_site(
                sites,
                RuleId::NoEffectWithFreshDeps,
                subj_name.clone(),
                "noEffectWithFreshDeps",
                text,
                format!(
                    "Fresh inline value `{text}` in `{hook_name}` dependencies causes the effect to re-run every render."
                ),
                other.span(),
                line_starts,
                None,
            );
        }
        _ => {}
    }
}

fn check_reducer_arg_for_mutation(
    semantic: &Semantic<'_>,
    first_arg: &Expression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let reducer_fn_node = match first_arg.without_parentheses() {
        Expression::Identifier(id) => {
            let Some(ref_id) = id.reference_id.get() else {
                return;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            match semantic.nodes().kind(decl_id) {
                AstKind::Function(_) => Some(decl_id),
                AstKind::VariableDeclarator(decl) => {
                    decl.init.as_ref().and_then(|init| {
                        for (nid, n) in semantic.nodes().iter_enumerated() {
                            if n.span() == init.without_parentheses().span()
                                && matches!(
                                    n.kind(),
                                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                                )
                            {
                                return Some(nid);
                            }
                        }
                        None
                    })
                }
                _ => None,
            }
        }
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            let target_span = first_arg.without_parentheses().span();
            semantic
                .nodes()
                .iter_enumerated()
                .find_map(|(nid, n)| (n.span() == target_span).then_some(nid))
        }
        _ => None,
    };

    let Some(fn_id) = reducer_fn_node else {
        return;
    };
    let state_param_name = match semantic.nodes().kind(fn_id) {
        AstKind::Function(f) => f
            .params
            .items
            .first()
            .and_then(|p| p.pattern.get_binding_identifier())
            .map(|id| id.name.to_string()),
        AstKind::ArrowFunctionExpression(arr) => arr
            .params
            .items
            .first()
            .and_then(|p| p.pattern.get_binding_identifier())
            .map(|id| id.name.to_string()),
        _ => None,
    };
    let Some(state_param) = state_param_name else {
        return;
    };
    let fn_span = semantic.nodes().get_node(fn_id).span();

    for (_, node) in semantic.nodes().iter_enumerated() {
        if !fn_span.contains_inclusive(node.span()) {
            continue;
        }
        if is_mutation_of_named_binding(node.kind(), &state_param) {
            push_site(
                sites,
                RuleId::NoMutatingReducerState,
                subj_name.clone(),
                "noMutatingReducerState",
                &state_param,
                format!(
                    "Reducer mutates `{state_param}` in place; return a new state object instead."
                ),
                node.span(),
                line_starts,
                None,
            );
            break;
        }
    }
}

fn is_mutation_of_named_binding(kind: AstKind<'_>, var_name: &str) -> bool {
    match kind {
        AstKind::AssignmentExpression(assign) => {
            let Some(mem) = assign.left.as_member_expression() else {
                return false;
            };
            expr_roots_at_identifier(mem.object(), var_name)
        }
        AstKind::UpdateExpression(upd) => {
            let Some(mem) = upd.argument.as_member_expression() else {
                return false;
            };
            expr_roots_at_identifier(mem.object(), var_name)
        }
        AstKind::UnaryExpression(un) if un.operator == UnaryOperator::Delete => {
            match un.argument.without_parentheses() {
                Expression::StaticMemberExpression(m) => {
                    expr_roots_at_identifier(&m.object, var_name)
                }
                Expression::ComputedMemberExpression(m) => {
                    expr_roots_at_identifier(&m.object, var_name)
                }
                _ => false,
            }
        }
        AstKind::CallExpression(call) => {
            let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
                return false;
            };
            ARRAY_MUTATING_METHODS.contains(&mem.property.name.as_str())
                && expr_roots_at_identifier(&mem.object, var_name)
        }
        _ => false,
    }
}

fn expr_roots_at_identifier(expr: &Expression<'_>, var_name: &str) -> bool {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::Identifier(id) => return id.name.as_str() == var_name,
            Expression::StaticMemberExpression(m) => curr = m.object.without_parentheses(),
            Expression::ComputedMemberExpression(m) => curr = m.object.without_parentheses(),
            _ => return false,
        }
    }
}

fn check_render_phase_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subj_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // Exclude calls inside `useState(() => ...)` or `useMemo(() => ...)` or `useRef(...)`
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(parent_call) = semantic.nodes().kind(anc_id)
            && (is_react_hook_callee(semantic, &parent_call.callee, "useState")
                || is_react_hook_callee(semantic, &parent_call.callee, "useMemo")
                || is_react_hook_callee(semantic, &parent_call.callee, "useRef"))
        {
            return;
        }
    }

    let callee = call.callee.without_parentheses();
    let callee_text = callee.span().source_text(semantic.source_text());

    // `no-create-object-url-in-render`
    if matches!(
        callee_text,
        "URL.createObjectURL" | "webkitURL.createObjectURL" | "window.URL.createObjectURL"
    ) {
        push_site(
            sites,
            RuleId::NoCreateObjectUrlInRender,
            subj_name.clone(),
            "noCreateObjectUrlInRender",
            callee_text,
            "Creating an object URL during render leaks blob memory on every re-render; move `URL.createObjectURL` into `useEffect` or an event handler.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }

    // `no-create-store-in-render`
    let is_store_factory = match callee {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "createStore" | "configureStore")
        }
        Expression::StaticMemberExpression(mem) => {
            matches!(mem.property.name.as_str(), "createStore" | "configureStore")
        }
        _ => false,
    };
    if is_store_factory {
        push_site(
            sites,
            RuleId::NoCreateStoreInRender,
            subj_name.clone(),
            "noCreateStoreInRender",
            callee_text,
            format!(
                "Calling `{callee_text}` during render recreates the store on every render; hoist it to module scope."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    // `no-nondeterministic-id-value-in-render-body`
    let is_nondeterministic_id = match callee {
        Expression::Identifier(id) => NONDETERMINISTIC_ID_CALLEES.contains(&id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            matches!(
                callee_text,
                "crypto.randomUUID" | "_.uniqueId" | "lodash.uniqueId"
            ) || mem.property.name == "randomUUID"
        }
        _ => false,
    };
    if is_nondeterministic_id {
        // Skip if used inside a JSX `key` prop (handled by `no-random-key`)
        let in_jsx_key = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::JSXAttribute(attr) if attr.name.as_identifier().is_some_and(|i| i.name == "key")
            )
        });
        if !in_jsx_key {
            push_site(
                sites,
                RuleId::NoNondeterministicIdValueInRenderBody,
                subj_name.clone(),
                "noNondeterministicIdValueInRenderBody",
                callee_text,
                format!(
                    "`{callee_text}()` in the render body produces a new ID on every render; use `useId()` instead."
                ),
                call.span,
                line_starts,
                None,
            );
        }
    }

    // `waapi-animation-in-render`
    if let Expression::StaticMemberExpression(mem) = callee
        && mem.property.name == "animate"
        && !call.arguments.is_empty()
        && !is_inside_use_effect(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::WaapiAnimationInRender,
            subj_name.clone(),
            "waapiAnimationInRender",
            "animate",
            "Starting a Web Animation (`.animate(...)`) during render causes impure side effects; move it to `useEffect` or an event handler.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
}

fn check_state_setter_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    setter_name: &str,
    state_name: &str,
    first_arg: &Expression<'_>,
    subj_id: NodeId,
    subj_name: &Option<String>,
    setter_to_state: &HashMap<String, String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. `no-boolean-toggle-without-functional-update`: `setX(!x)`
    if let Expression::UnaryExpression(un) = first_arg
        && un.operator == UnaryOperator::LogicalNot
        && let Expression::Identifier(arg_id) = un.argument.without_parentheses()
        && arg_id.name.as_str() == state_name
    {
        push_site(
            sites,
            RuleId::NoBooleanToggleWithoutFunctionalUpdate,
            subj_name.clone(),
            "noBooleanToggleWithoutFunctionalUpdate",
            setter_name,
            format!(
                "Toggle `{state_name}` with `{setter_name}((prev) => !prev)` instead of `{setter_name}(!{state_name})`."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    // 2. `no-mutate-then-set-or-return-same-reference`: `list.push(...); setList(list)`
    if let Expression::Identifier(arg_id) = first_arg
        && arg_id.name.as_str() == state_name
    {
        let scope_span = semantic
            .nodes()
            .ancestor_ids(node_id)
            .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
                AstKind::FunctionBody(b) => Some(b.span),
                AstKind::BlockStatement(b) => Some(b.span),
                _ => None,
            })
            .unwrap_or_else(|| semantic.nodes().get_node(subj_id).span());

        let mutated_in_scope = semantic.nodes().iter_enumerated().any(|(_, n)| {
            scope_span.contains_inclusive(n.span())
                && n.span().start < call.span.start
                && is_mutation_of_named_binding(n.kind(), state_name)
        });
        if mutated_in_scope {
            push_site(
                sites,
                RuleId::NoMutateThenSetOrReturnSameReference,
                subj_name.clone(),
                "noMutateThenSetOrReturnSameReference",
                state_name,
                format!(
                    "`{state_name}` is mutated in place and then passed to `{setter_name}({state_name})`; React ignores updates with the same reference."
                ),
                call.span,
                line_starts,
                None,
            );
        }
    }

    // 3. `no-impure-state-updater` (and `no-mutate-then-set-or-return-same-reference` inside updater)
    let (updater_span, updater_param) = match first_arg {
        Expression::ArrowFunctionExpression(arr) => (
            Some(arr.span),
            arr.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        Expression::FunctionExpression(f) => (
            Some(f.span),
            f.params
                .items
                .first()
                .and_then(|p| p.pattern.get_binding_identifier())
                .map(|id| id.name.to_string()),
        ),
        _ => (None, None),
    };

    if let Some(u_span) = updater_span {
        let mut is_impure = false;
        let mut mutates_param = false;
        for (_, inner) in semantic.nodes().iter_enumerated() {
            if !u_span.contains_inclusive(inner.span()) || inner.span() == u_span {
                continue;
            }
            if let Some(param) = &updater_param
                && is_mutation_of_named_binding(inner.kind(), param)
            {
                is_impure = true;
                mutates_param = true;
            }
            match inner.kind() {
                AstKind::AssignmentExpression(_) | AstKind::UpdateExpression(_) => {
                    is_impure = true;
                }
                AstKind::CallExpression(c) => {
                    let c_text = c
                        .callee
                        .without_parentheses()
                        .span()
                        .source_text(semantic.source_text());
                    if setter_to_state.contains_key(c_text)
                        || c_text.starts_with("localStorage.")
                        || c_text.starts_with("sessionStorage.")
                        || c_text.starts_with("console.")
                        || matches!(
                            c_text,
                            "fetch" | "setTimeout" | "setInterval" | "dispatch" | "alert"
                        )
                    {
                        is_impure = true;
                    }
                }
                _ => {}
            }
        }
        if is_impure {
            push_site(
                sites,
                RuleId::NoImpureStateUpdater,
                subj_name.clone(),
                "noImpureStateUpdater",
                setter_name,
                format!(
                    "State updater passed to `{setter_name}` performs side effects or in-place mutations; keep state updaters pure."
                ),
                u_span,
                line_starts,
                None,
            );
        }
        if mutates_param {
            push_site(
                sites,
                RuleId::NoMutateThenSetOrReturnSameReference,
                subj_name.clone(),
                "noMutateThenSetOrReturnSameReference",
                setter_name,
                format!(
                    "State updater passed to `{setter_name}` mutates the previous state in place and returns the same reference."
                ),
                u_span,
                line_starts,
                None,
            );
        }
    }
}

fn check_ast_node_rules(
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
    if let Expression::StaticMemberExpression(mem) = callee
        && matches!(
            mem.property.name.as_str(),
            "removeEventListener" | "removeListener" | "off"
        )
        && let Some(handler_arg) = call.arguments.get(1).and_then(|a| a.as_expression())
    {
        let handler_unwrapped = handler_arg.without_parentheses();
        let is_inline = match handler_unwrapped {
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
            Expression::CallExpression(c) => matches!(
                c.callee.without_parentheses(),
                Expression::StaticMemberExpression(m) if m.property.name == "bind"
            ),
            _ => false,
        };
        if is_inline {
            push_site(
                sites,
                RuleId::EffectRemoveListenerInlineHandler,
                subj_name.clone(),
                "effectRemoveListenerInlineHandler",
                mem.property.name.as_str(),
                format!(
                    "`{}` called with a fresh inline function reference that can never match the registered listener.",
                    mem.property.name
                ),
                handler_unwrapped.span(),
                line_starts,
                None,
            );
        }
    }

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
        let is_local_component = id
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .is_some_and(|sym_id| {
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
    if matches!(tag_name.as_str(), "Activity" | "unstable_Activity" | "Offscreen") {
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
                        format!(
                            "Block element `<{tag_name}>` cannot be nested inside `<p>`."
                        ),
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
                    span: ByteSpan {
                        start: jsx_el.span.start,
                        end: jsx_el.span.end,
                    },
                    replacement,
                }],
            });
            push_site(
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
    check_jsx_opening_attributes(semantic, opening, &tag_name, is_comp, subj_name, line_starts, sites);
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
                                span: ByteSpan {
                                    start: val_span.start,
                                    end: val_span.end,
                                },
                                replacement: format!("{{{bool_val}}}"),
                            }],
                        });
                        push_site(
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
                            span: ByteSpan {
                                start: s.span.start,
                                end: s.span.end,
                            },
                            replacement: format!("\"{rounded}\""),
                        }],
                    });
                    push_site(
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
    jsx_text: &oxc_ast::ast::JSXText<'_>,
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
