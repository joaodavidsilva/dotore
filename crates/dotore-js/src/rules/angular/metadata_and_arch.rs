//! Angular decorator metadata, output naming/immutability, DI (`inject()`, `providedIn`),
//! host bindings, `forwardRef`, `ViewEncapsulation.None`, and inline template/styles size rules.

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; Angular rules match only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    ast::{
        Argument, ArrayExpression, ArrayExpressionElement, CallExpression, Class, ClassElement,
        Decorator, Expression, FormalParameter, MethodDefinitionKind, ObjectExpression,
        ObjectProperty, ObjectPropertyKind, PropertyDefinition,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{ByteSpan, SemanticRuleSite},
    rules::{AutofixPatch, RuleId},
};

use super::{
    angular_class_decorator_kind, callee_ident_name, decorator_name, enclosing_subject_name,
    extract_angular_stylesheet_sites, extract_template_text_and_offset, prop_key_str,
    push_angular_site, signals_and_lifecycle::extract_decorator_first_string_arg,
};

const NATIVE_DOM_EVENT_NAMES: &[&str] = &[
    "blur",
    "cancel",
    "change",
    "click",
    "close",
    "contextmenu",
    "copy",
    "cut",
    "dblclick",
    "drag",
    "dragend",
    "dragenter",
    "dragleave",
    "dragover",
    "dragstart",
    "drop",
    "error",
    "focus",
    "focusin",
    "focusout",
    "input",
    "invalid",
    "keydown",
    "keypress",
    "keyup",
    "load",
    "mousedown",
    "mouseenter",
    "mouseleave",
    "mousemove",
    "mouseout",
    "mouseover",
    "mouseup",
    "paste",
    "reset",
    "resize",
    "scroll",
    "search",
    "select",
    "submit",
    "toggle",
    "touchcancel",
    "touchend",
    "touchmove",
    "touchstart",
    "wheel",
];

const METADATA_ARRAY_KEYS: &[&str] = &["imports", "providers", "declarations", "exports", "schemas"];

pub(super) fn check_class_metadata_and_architecture_rules(
    cls: &Class<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let class_name = cls.id.as_ref().map(|id| id.name.to_string());
    let decorator_kind = angular_class_decorator_kind(cls);

    for dec in &cls.decorators {
        check_single_class_decorator(dec, class_name.as_deref(), source, line_starts, sites);
    }

    for elem in &cls.body.body {
        match elem {
            ClassElement::PropertyDefinition(prop) => {
                check_host_binding_or_listener_decorators(
                    &prop.decorators,
                    class_name.as_deref(),
                    line_starts,
                    sites,
                );
                check_output_property_rules(prop, class_name.as_deref(), source, line_starts, sites);
            }
            ClassElement::MethodDefinition(method) => {
                check_host_binding_or_listener_decorators(
                    &method.decorators,
                    class_name.as_deref(),
                    line_starts,
                    sites,
                );
                if method.kind == MethodDefinitionKind::Constructor {
                    check_constructor_di_and_attribute_decorators(
                        &method.value.params.items,
                        decorator_kind,
                        class_name.as_deref(),
                        line_starts,
                        sites,
                    );
                }
            }
            ClassElement::AccessorProperty(acc) => {
                check_host_binding_or_listener_decorators(
                    &acc.decorators,
                    class_name.as_deref(),
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

fn check_single_class_decorator(
    dec: &Decorator<'_>,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let target = class_name.unwrap_or("Class").to_string();

    let (dec_name, obj_opt) = match dec.expression.without_parentheses() {
        Expression::Identifier(id) => (id.name.as_str(), None),
        Expression::CallExpression(call) => {
            let Some(name) = callee_ident_name(&call.callee) else {
                return;
            };
            let obj = match call.arguments.first() {
                Some(Argument::ObjectExpression(o)) => Some(o.as_ref()),
                _ => None,
            };
            (name, obj)
        }
        _ => return,
    };

    if dec_name == "Injectable" {
        check_injectable_provided_in(dec, obj_opt, class_name, &target, line_starts, sites);
    }

    let Some(obj) = obj_opt else {
        return;
    };

    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let Some(key) = prop_key_str(&prop.key) else {
            continue;
        };
        check_class_decorator_metadata_prop(
            dec_name,
            prop,
            key,
            class_name,
            &target,
            source,
            line_starts,
            sites,
        );
    }
}

fn check_injectable_provided_in(
    dec: &Decorator<'_>,
    obj_opt: Option<&ObjectExpression<'_>>,
    class_name: Option<&str>,
    target: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let has_provided_in = obj_opt.is_some_and(|obj| {
        obj.properties.iter().any(|p| {
            if let ObjectPropertyKind::ObjectProperty(prop) = p
                && prop_key_str(&prop.key) == Some("providedIn")
            {
                !matches!(
                    prop.value.without_parentheses(),
                    Expression::NullLiteral(_)
                )
            } else {
                false
            }
        })
    });
    if !has_provided_in {
        let patch = AutofixPatch::replace(
            "Add `providedIn: 'root'` to `@Injectable`",
            ByteSpan {
                start: dec.span.start,
                end: dec.span.end,
            },
            "@Injectable({ providedIn: 'root' })",
        );
        push_angular_site(
            sites,
            RuleId::AngularUseInjectableProvidedIn,
            class_name.map(ToOwned::to_owned),
            "angularUseInjectableProvidedIn",
            target.to_string(),
            format!(
                "`@Injectable` `{target}` should specify `providedIn: 'root'` for tree-shakable dependency injection."
            ),
            dec.span,
            line_starts,
            Some(patch),
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates single decorator metadata property across Component, Directive, Pipe, and NgModule (#50)"
)]
fn check_class_decorator_metadata_prop(
    dec_name: &str,
    prop: &ObjectProperty<'_>,
    key: &str,
    class_name: Option<&str>,
    target: &str,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if dec_name == "Pipe"
        && key == "pure"
        && matches!(
            prop.value.without_parentheses(),
            Expression::BooleanLiteral(b) if !b.value
        )
    {
        push_angular_site(
            sites,
            RuleId::AngularNoPipeImpure,
            class_name.map(ToOwned::to_owned),
            "angularNoPipeImpure",
            target.to_string(),
            format!(
                "Impure `@Pipe` `{target}` (`pure: false`) executes on every change detection cycle; use a pure pipe or `computed()` signal."
            ),
            prop.span,
            line_starts,
            None,
        );
    }

    if matches!(dec_name, "Component" | "Directive" | "Pipe")
        && key == "standalone"
        && matches!(
            prop.value.without_parentheses(),
            Expression::BooleanLiteral(b) if !b.value
        )
    {
        let val_span = prop.value.span();
        let patch = AutofixPatch::replace(
            "Set `standalone: true`",
            ByteSpan {
                start: val_span.start,
                end: val_span.end,
            },
            "true",
        );
        push_angular_site(
            sites,
            RuleId::AngularPreferStandalone,
            class_name.map(ToOwned::to_owned),
            "angularPreferStandalone",
            target.to_string(),
            format!(
                "`@{dec_name}` `{target}` sets `standalone: false`; prefer standalone Angular declarations."
            ),
            prop.span,
            line_starts,
            Some(patch),
        );
    }

    if matches!(dec_name, "Component" | "Directive" | "NgModule")
        && METADATA_ARRAY_KEYS.contains(&key)
        && let Expression::ArrayExpression(arr) = prop.value.without_parentheses()
    {
        check_duplicate_metadata_array_elements(arr, key, class_name, source, line_starts, sites);
    }

    if matches!(dec_name, "Component" | "Directive") {
        check_forbidden_io_or_query_metadata_prop(dec_name, prop, key, class_name, line_starts, sites);
    }

    if dec_name == "Component" {
        check_component_specific_metadata_prop(prop, key, class_name, source, line_starts, sites);
    }
}

fn check_forbidden_io_or_query_metadata_prop(
    dec_name: &str,
    prop: &ObjectProperty<'_>,
    key: &str,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let (rule, msg_id, msg) = match key {
        "inputs" => (
            RuleId::AngularNoInputsMetadataProperty,
            "angularNoInputsMetadataProperty",
            format!(
                "Avoid `inputs: [...]` metadata in `@{dec_name}`; declare inputs with `input()` or `@Input()` on class fields."
            ),
        ),
        "outputs" => (
            RuleId::AngularNoOutputsMetadataProperty,
            "angularNoOutputsMetadataProperty",
            format!(
                "Avoid `outputs: [...]` metadata in `@{dec_name}`; declare outputs with `output()` or `@Output()` on class fields."
            ),
        ),
        "queries" => (
            RuleId::AngularNoQueriesMetadataProperty,
            "angularNoQueriesMetadataProperty",
            format!(
                "Avoid `queries: {{ ... }}` metadata in `@{dec_name}`; use `viewChild()` / `contentChild()` or property decorators."
            ),
        ),
        _ => return,
    };
    push_angular_site(
        sites,
        rule,
        class_name.map(ToOwned::to_owned),
        msg_id,
        key.to_string(),
        msg,
        prop.span,
        line_starts,
        None,
    );
}

fn check_component_specific_metadata_prop(
    prop: &ObjectProperty<'_>,
    key: &str,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match key {
        "templateUrl" | "styleUrl" | "styleUrls" => {
            check_component_url_metadata_prop(prop, key, class_name, line_starts, sites);
        }
        "encapsulation" => {
            if matches!(
                prop.value.without_parentheses(),
                Expression::StaticMemberExpression(mem) if mem.property.name == "None"
            ) {
                let target = class_name.unwrap_or("Component").to_string();
                push_angular_site(
                    sites,
                    RuleId::AngularUseComponentViewEncapsulation,
                    class_name.map(ToOwned::to_owned),
                    "angularUseComponentViewEncapsulation",
                    target,
                    "Avoid `ViewEncapsulation.None`; global styles leak across component boundaries.".to_string(),
                    prop.span,
                    line_starts,
                    None,
                );
            }
        }
        "template" | "styles" => {
            check_component_inline_declarations_prop(
                prop,
                key,
                class_name,
                source,
                line_starts,
                sites,
            );
        }
        _ => {}
    }
}

fn check_component_url_metadata_prop(
    prop: &ObjectProperty<'_>,
    key: &str,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if matches!(key, "templateUrl" | "styleUrl")
        && let Expression::StringLiteral(lit) = prop.value.without_parentheses()
        && let Some(url) = lit.value.as_str()
    {
        check_relative_url_literal(url, lit.span, key, class_name, line_starts, sites);
    } else if key == "styleUrls"
        && let Expression::ArrayExpression(arr) = prop.value.without_parentheses()
    {
        for elem in &arr.elements {
            if let ArrayExpressionElement::StringLiteral(lit) = elem
                && let Some(url) = lit.value.as_str()
            {
                check_relative_url_literal(
                    url,
                    lit.span,
                    "styleUrls",
                    class_name,
                    line_starts,
                    sites,
                );
            }
        }
    }
}

fn check_component_inline_declarations_prop(
    prop: &ObjectProperty<'_>,
    key: &str,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if key == "template" {
        if let Some((tpl_text, _)) = extract_template_text_and_offset(&prop.value, source) {
            let line_count = tpl_text.lines().count();
            if line_count > 15 {
                push_angular_site(
                    sites,
                    RuleId::AngularComponentMaxInlineDeclarations,
                    class_name.map(ToOwned::to_owned),
                    "angularComponentMaxInlineDeclarations",
                    "template".to_string(),
                    format!(
                        "Inline `template` has {line_count} lines (max 15); extract it to an external `.component.html` file."
                    ),
                    prop.key.span(),
                    line_starts,
                    None,
                );
            }
        }
    } else if key == "styles" {
        extract_inline_styles_sites(&prop.value, class_name, source, line_starts, sites);
        let style_lines = count_inline_styles_lines(&prop.value, source);
        if style_lines > 15 {
            push_angular_site(
                sites,
                RuleId::AngularComponentMaxInlineDeclarations,
                class_name.map(ToOwned::to_owned),
                "angularComponentMaxInlineDeclarations",
                "styles".to_string(),
                format!(
                    "Inline `styles` has {style_lines} lines (max 15); extract styles to an external stylesheet."
                ),
                prop.key.span(),
                line_starts,
                None,
            );
        }
    }
}

fn count_inline_styles_lines(expr: &Expression<'_>, source: &str) -> usize {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => arr
            .elements
            .iter()
            .filter_map(|e| e.as_expression())
            .filter_map(|e| extract_template_text_and_offset(e, source))
            .map(|(txt, _)| txt.lines().count())
            .sum(),
        other => extract_template_text_and_offset(other, source)
            .map_or(0, |(txt, _)| txt.lines().count()),
    }
}

fn extract_inline_styles_sites(
    expr: &Expression<'_>,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => {
            for elem in &arr.elements {
                if let Some(e) = elem.as_expression()
                    && let Some((txt, inner_start)) = extract_template_text_and_offset(e, source)
                {
                    extract_angular_stylesheet_sites(
                        txt,
                        inner_start,
                        class_name,
                        line_starts,
                        sites,
                    );
                }
            }
        }
        other => {
            if let Some((txt, inner_start)) = extract_template_text_and_offset(other, source) {
                extract_angular_stylesheet_sites(
                    txt,
                    inner_start,
                    class_name,
                    line_starts,
                    sites,
                );
            }
        }
    }
}

fn check_relative_url_literal(
    url: &str,
    lit_span: Span,
    key: &str,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let trimmed = url.trim();
    if trimmed.starts_with("./") || trimmed.starts_with("../") {
        return;
    }
    let clean = trimmed.trim_start_matches('/');
    let fixed_url = format!("'./{clean}'");
    let patch = AutofixPatch::replace(
        format!("Prefix `{key}` path with `./`"),
        ByteSpan {
            start: lit_span.start,
            end: lit_span.end,
        },
        fixed_url,
    );
    push_angular_site(
        sites,
        RuleId::AngularRelativeUrlPrefix,
        class_name.map(ToOwned::to_owned),
        "angularRelativeUrlPrefix",
        url.to_string(),
        format!(
            "`{key}` path `{url}` must start with `./` or `../`."
        ),
        lit_span,
        line_starts,
        Some(patch),
    );
}

fn check_duplicate_metadata_array_elements(
    arr: &ArrayExpression<'_>,
    key: &str,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut seen: HashSet<String> = HashSet::new();
    for elem in &arr.elements {
        if matches!(elem, ArrayExpressionElement::SpreadElement(_)) {
            continue;
        }
        let sp = elem.span();
        let text = source
            .get(sp.start as usize..sp.end as usize)
            .unwrap_or_default()
            .trim();
        if text.is_empty() {
            continue;
        }
        if !seen.insert(text.to_string()) {
            push_angular_site(
                sites,
                RuleId::AngularNoDuplicatesInMetadataArrays,
                class_name.map(ToOwned::to_owned),
                "angularNoDuplicatesInMetadataArrays",
                text.to_string(),
                format!(
                    "Duplicate entry `{text}` in `{key}` metadata array."
                ),
                sp,
                line_starts,
                None,
            );
        }
    }
}

fn check_host_binding_or_listener_decorators(
    decorators: &[Decorator<'_>],
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for dec in decorators {
        let Some(name) = decorator_name(dec) else {
            continue;
        };
        if matches!(name, "HostBinding" | "HostListener") {
            push_angular_site(
                sites,
                RuleId::AngularPreferHostMetadataProperty,
                class_name.map(ToOwned::to_owned),
                "angularPreferHostMetadataProperty",
                format!("@{name}"),
                format!(
                    "Prefer the `host: {{ ... }}` metadata property over `@{name}`."
                ),
                dec.span,
                line_starts,
                None,
            );
        }
    }
}

fn check_output_property_rules(
    prop: &PropertyDefinition<'_>,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(prop_name) = prop_key_str(&prop.key) else {
        return;
    };
    let has_output_dec = prop
        .decorators
        .iter()
        .any(|d| decorator_name(d) == Some("Output"));
    let is_output_fn = prop.value.as_ref().is_some_and(is_output_signal_initializer);

    if !has_output_dec && !is_output_fn {
        return;
    }

    let alias = if has_output_dec {
        extract_decorator_first_string_arg(&prop.decorators, "Output")
    } else {
        prop.value.as_ref().and_then(extract_output_fn_alias)
    };
    let effective_name = alias.as_deref().unwrap_or(prop_name);

    // 14. `angular-no-output-native`
    if NATIVE_DOM_EVENT_NAMES.contains(&effective_name)
        || NATIVE_DOM_EVENT_NAMES.contains(&prop_name)
    {
        push_angular_site(
            sites,
            RuleId::AngularNoOutputNative,
            class_name.map(ToOwned::to_owned),
            "angularNoOutputNative",
            effective_name.to_string(),
            format!(
                "Output `{effective_name}` shadows a native DOM event name; choose a domain-specific event name."
            ),
            prop.key.span(),
            line_starts,
            None,
        );
    }

    // 15. `angular-no-output-on-prefix`
    if is_on_prefixed_output_name(effective_name) || is_on_prefixed_output_name(prop_name) {
        push_angular_site(
            sites,
            RuleId::AngularNoOutputOnPrefix,
            class_name.map(ToOwned::to_owned),
            "angularNoOutputOnPrefix",
            effective_name.to_string(),
            format!(
                "Output `{effective_name}` should not start with `on`; Angular templates bind events with `(eventName)`."
            ),
            prop.key.span(),
            line_starts,
            None,
        );
    }

    // 26. `angular-prefer-output-readonly`
    if !prop.readonly {
        let patch = AutofixPatch::insert(
            format!("Mark output `{prop_name}` as `readonly`"),
            prop.key.span().start,
            "readonly ",
        );
        push_angular_site(
            sites,
            RuleId::AngularPreferOutputReadonly,
            class_name.map(ToOwned::to_owned),
            "angularPreferOutputReadonly",
            prop_name.to_string(),
            format!(
                "Mark output property `{prop_name}` as `readonly` so the emitter reference cannot be reassigned."
            ),
            prop.key.span(),
            line_starts,
            Some(patch),
        );
    }

    // 27. `angular-prefer-output-emitter-ref`
    if is_raw_rxjs_subject_output(prop, source) {
        push_angular_site(
            sites,
            RuleId::AngularPreferOutputEmitterRef,
            class_name.map(ToOwned::to_owned),
            "angularPreferOutputEmitterRef",
            prop_name.to_string(),
            format!(
                "Output `{prop_name}` uses an RxJS `Subject` instead of `output()` or `EventEmitter`."
            ),
            prop.span,
            line_starts,
            None,
        );
    }
}

fn is_output_signal_initializer(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return false;
    };
    matches!(
        callee_ident_name(&call.callee),
        Some("output" | "outputFromObservable")
    )
}

fn extract_output_fn_alias(expr: &Expression<'_>) -> Option<String> {
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return None;
    };
    for arg in &call.arguments {
        let Argument::ObjectExpression(obj) = arg else {
            continue;
        };
        for p in &obj.properties {
            if let ObjectPropertyKind::ObjectProperty(prop) = p
                && prop_key_str(&prop.key) == Some("alias")
                && let Expression::StringLiteral(lit) = prop.value.without_parentheses()
                && let Some(s) = lit.value.as_str()
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn is_on_prefixed_output_name(name: &str) -> bool {
    if name == "on" {
        return true;
    }
    if let Some(rest) = name.strip_prefix("on") {
        return rest
            .chars()
            .next()
            .is_some_and(|c| !c.is_ascii_lowercase());
    }
    false
}

fn is_raw_rxjs_subject_output(prop: &PropertyDefinition<'_>, source: &str) -> bool {
    if let Some(val) = &prop.value
        && let Expression::NewExpression(new_expr) = val.without_parentheses()
        && let Some(callee) = callee_ident_name(&new_expr.callee)
        && matches!(
            callee,
            "Subject" | "BehaviorSubject" | "ReplaySubject" | "AsyncSubject"
        )
    {
        return true;
    }
    if let Some(ann) = &prop.type_annotation {
        let text = source
            .get(ann.span.start as usize..ann.span.end as usize)
            .unwrap_or_default();
        let trimmed = text.trim_start_matches(':').trim();
        if trimmed.starts_with("Subject<")
            || trimmed.starts_with("BehaviorSubject<")
            || trimmed.starts_with("ReplaySubject<")
            || trimmed == "Subject"
            || trimmed == "BehaviorSubject"
        {
            return true;
        }
    }
    false
}

fn check_constructor_di_and_attribute_decorators(
    params: &[FormalParameter<'_>],
    decorator_kind: Option<&str>,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_di_class = matches!(
        decorator_kind,
        Some("Component" | "Directive" | "Injectable" | "Pipe")
    );

    for param in params {
        let param_name = param
            .pattern
            .get_binding_identifier()
            .map_or("param", |id| id.name.as_str());

        let mut has_attribute_dec = false;
        let mut has_inject_dec = false;
        for dec in &param.decorators {
            match decorator_name(dec) {
                Some("Attribute") => {
                    has_attribute_dec = true;
                    push_angular_site(
                        sites,
                        RuleId::AngularNoAttributeDecorator,
                        class_name.map(ToOwned::to_owned),
                        "angularNoAttributeDecorator",
                        param_name.to_string(),
                        format!(
                            "Avoid `@Attribute()` on constructor parameter `{param_name}`; use `input()` or `@Input()` instead."
                        ),
                        dec.span,
                        line_starts,
                        None,
                    );
                }
                Some("Inject" | "Optional" | "Self" | "SkipSelf" | "Host") => {
                    has_inject_dec = true;
                }
                _ => {}
            }
        }

        if is_di_class
            && !has_attribute_dec
            && (param.accessibility.is_some()
                || param.readonly
                || has_inject_dec
                || param.type_annotation.is_some())
        {
            push_angular_site(
                sites,
                RuleId::AngularPreferInject,
                class_name.map(ToOwned::to_owned),
                "angularPreferInject",
                param_name.to_string(),
                format!(
                    "Prefer `inject()` field initialization over constructor parameter injection for `{param_name}`."
                ),
                param.span,
                line_starts,
                None,
            );
        }
    }
}

pub(super) fn check_forward_ref_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if callee_ident_name(&call.callee) != Some("forwardRef") {
        return;
    }
    let subj = enclosing_subject_name(semantic, node_id);
    push_angular_site(
        sites,
        RuleId::AngularNoForwardRef,
        subj,
        "angularNoForwardRef",
        "forwardRef".to_string(),
        "Avoid `forwardRef(() => ...)`; reorder declarations or extract shared tokens to break the reference cycle.".to_string(),
        call.span,
        line_starts,
        None,
    );
}
