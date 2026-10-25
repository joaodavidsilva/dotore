//! Angular Signals (`angular-no-uncalled-signals`, `angular-prefer-signal-model`, `angular-prefer-signals`)
//! and Lifecycle / Decorator Contract rules (`angular-no-conflicting-lifecycle`, `angular-contextual-lifecycle`,
//! `angular-contextual-decorator`, `angular-no-async-lifecycle-method`, `angular-no-lifecycle-call`,
//! `angular-require-lifecycle-on-prototype`, `angular-no-empty-lifecycle-method`,
//! `angular-use-lifecycle-interface`, `angular-use-pipe-transform-interface`).

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; Angular rules match only relevant AST node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Class, ClassElement, Decorator, Expression, MethodDefinition,
        PropertyDefinition, UnaryOperator,
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
    prop_key_str, push_angular_site,
};

const LIFECYCLE_METHODS_AND_INTERFACES: &[(&str, &str)] = &[
    ("ngOnChanges", "OnChanges"),
    ("ngOnInit", "OnInit"),
    ("ngDoCheck", "DoCheck"),
    ("ngAfterContentInit", "AfterContentInit"),
    ("ngAfterContentChecked", "AfterContentChecked"),
    ("ngAfterViewInit", "AfterViewInit"),
    ("ngAfterViewChecked", "AfterViewChecked"),
    ("ngOnDestroy", "OnDestroy"),
];

const COMPONENT_OR_DIRECTIVE_DECORATORS: &[&str] = &[
    "Input",
    "Output",
    "ViewChild",
    "ViewChildren",
    "ContentChild",
    "ContentChildren",
    "HostBinding",
    "HostListener",
];

pub(super) struct KnownSignalsIndex {
    pub class_signal_props: HashMap<NodeId, HashSet<String>>,
    pub local_signals: HashSet<String>,
}

pub(super) fn collect_known_signals(semantic: &Semantic<'_>, source: &str) -> KnownSignalsIndex {
    let mut class_signal_props: HashMap<NodeId, HashSet<String>> = HashMap::new();
    let mut local_signals: HashSet<String> = HashSet::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Class(cls) => {
                let mut props = HashSet::new();
                for elem in &cls.body.body {
                    let ClassElement::PropertyDefinition(prop) = elem else {
                        continue;
                    };
                    let Some(name) = prop_key_str(&prop.key) else {
                        continue;
                    };
                    let init_is_signal = prop.value.as_ref().is_some_and(is_signal_creator_expr);
                    let type_is_signal = prop.type_annotation.as_ref().is_some_and(|ann| {
                        let text = source
                            .get(ann.span.start as usize..ann.span.end as usize)
                            .unwrap_or_default();
                        is_signal_type_annotation(text)
                    });
                    if init_is_signal || type_is_signal {
                        props.insert(name.to_string());
                    }
                }
                if !props.is_empty() {
                    class_signal_props.insert(node_id, props);
                }
            }
            AstKind::VariableDeclarator(decl) => {
                let Some(binding) = decl.id.get_binding_identifier() else {
                    continue;
                };
                if decl.init.as_ref().is_some_and(is_signal_creator_expr) {
                    local_signals.insert(binding.name.to_string());
                }
            }
            _ => {}
        }
    }

    KnownSignalsIndex {
        class_signal_props,
        local_signals,
    }
}

fn is_signal_creator_expr(expr: &Expression<'_>) -> bool {
    let unwrapped = unwrap_ts_and_parens(expr);
    let Expression::CallExpression(call) = unwrapped else {
        return false;
    };
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => matches!(
            id.name.as_str(),
            "signal"
                | "computed"
                | "input"
                | "model"
                | "toSignal"
                | "viewChild"
                | "viewChildren"
                | "contentChild"
                | "contentChildren"
                | "linkedSignal"
        ),
        Expression::StaticMemberExpression(mem) => {
            if mem.property.name == "selectSignal" {
                return true;
            }
            if mem.property.name == "required"
                && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
            {
                return matches!(
                    obj_id.name.as_str(),
                    "input" | "model" | "viewChild" | "contentChild"
                );
            }
            false
        }
        _ => false,
    }
}

fn is_signal_type_annotation(text: &str) -> bool {
    text.contains("Signal<")
        || text.contains("WritableSignal<")
        || text.contains("InputSignal<")
        || text.contains("ModelSignal<")
}

fn unwrap_ts_and_parens<'a>(mut expr: &'a Expression<'a>) -> &'a Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(ts) => expr = &ts.expression,
            Expression::TSSatisfiesExpression(ts) => expr = &ts.expression,
            Expression::TSNonNullExpression(ts) => expr = &ts.expression,
            Expression::TSTypeAssertion(ts) => expr = &ts.expression,
            _ => return expr,
        }
    }
}

pub(super) fn check_uncalled_signal_reference(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    known_signals: &KnownSignalsIndex,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let node = semantic.nodes().get_node(node_id);
    let (sig_name, ref_span) = match node.kind() {
        AstKind::StaticMemberExpression(mem) => {
            if !matches!(
                mem.object.without_parentheses(),
                Expression::ThisExpression(_)
            ) {
                return;
            }
            let Some(cls_id) = semantic
                .nodes()
                .ancestor_ids(node_id)
                .find(|&anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::Class(_)))
            else {
                return;
            };
            let Some(props) = known_signals.class_signal_props.get(&cls_id) else {
                return;
            };
            let prop_name = mem.property.name.as_str();
            if !props.contains(prop_name) {
                return;
            }
            (prop_name.to_string(), mem.span)
        }
        AstKind::IdentifierReference(ident) => {
            let name = ident.name.as_str();
            if !known_signals.local_signals.contains(name) {
                return;
            }
            (name.to_string(), ident.span)
        }
        _ => return,
    };

    if is_signal_called_or_member_accessed(semantic, node_id, ref_span) {
        return;
    }

    if is_in_boolean_or_relational_condition(semantic, node_id, ref_span) {
        let subj = enclosing_subject_name(semantic, node_id);
        let patch = AutofixPatch::insert(
            format!("Call signal getter `{sig_name}()`"),
            ref_span.end,
            "()",
        );
        push_angular_site(
            sites,
            RuleId::AngularNoUncalledSignals,
            subj,
            "angularNoUncalledSignals",
            sig_name.clone(),
            format!(
                "Signal `{sig_name}` is referenced in a condition without calling `{sig_name}()`; a Signal function reference is always truthy."
            ),
            ref_span,
            line_starts,
            Some(patch),
        );
    }
}

fn is_signal_called_or_member_accessed(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ref_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSAsExpression(_) => {}
            AstKind::CallExpression(call) => {
                let callee_span = call.callee.span();
                return ref_span.start >= callee_span.start && ref_span.end <= callee_span.end;
            }
            AstKind::StaticMemberExpression(mem) => {
                let obj_span = mem.object.span();
                if ref_span.start >= obj_span.start && ref_span.end <= obj_span.end {
                    return true;
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

fn is_in_boolean_or_relational_condition(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    ref_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSAsExpression(_) => {}
            AstKind::UnaryExpression(unary) => {
                return unary.operator == UnaryOperator::LogicalNot;
            }
            AstKind::LogicalExpression(_) => {
                return true;
            }
            AstKind::BinaryExpression(bin) => {
                return bin.operator.is_equality() || bin.operator.is_compare();
            }
            AstKind::IfStatement(if_stmt) => {
                let test_span = if_stmt.test.span();
                return ref_span.start >= test_span.start && ref_span.end <= test_span.end;
            }
            AstKind::ConditionalExpression(cond) => {
                let test_span = cond.test.span();
                return ref_span.start >= test_span.start && ref_span.end <= test_span.end;
            }
            AstKind::WhileStatement(w) => {
                let test_span = w.test.span();
                return ref_span.start >= test_span.start && ref_span.end <= test_span.end;
            }
            AstKind::DoWhileStatement(dw) => {
                let test_span = dw.test.span();
                return ref_span.start >= test_span.start && ref_span.end <= test_span.end;
            }
            AstKind::ForStatement(f) => {
                return f.test.as_ref().is_some_and(|t| {
                    let test_span = t.span();
                    ref_span.start >= test_span.start && ref_span.end <= test_span.end
                });
            }
            _ => return false,
        }
    }
    false
}

pub(super) fn check_class_signals_and_lifecycle_rules(
    cls: &Class<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let decorator_kind = angular_class_decorator_kind(cls);
    let class_name = cls.id.as_ref().map(|id| id.name.to_string());
    let implemented = extract_implemented_interfaces(cls, source);

    if decorator_kind == Some("Pipe") && !implemented.contains("PipeTransform") {
        let target = class_name.clone().unwrap_or_else(|| "Pipe".to_string());
        let span = cls.id.as_ref().map_or(cls.span, |id| id.span);
        push_angular_site(
            sites,
            RuleId::AngularUsePipeTransformInterface,
            class_name.clone(),
            "angularUsePipeTransformInterface",
            target.clone(),
            format!(
                "`@Pipe` class `{target}` must implement the `PipeTransform` interface."
            ),
            span,
            line_starts,
            None,
        );
    }

    check_prefer_signals_and_signal_model(cls, decorator_kind, class_name.as_deref(), line_starts, sites);
    check_conflicting_lifecycle(cls, &implemented, class_name.as_deref(), line_starts, sites);
    check_contextual_decorators(cls, decorator_kind, class_name.as_deref(), line_starts, sites);
    check_lifecycle_methods_and_properties(
        cls,
        decorator_kind,
        &implemented,
        class_name.as_deref(),
        source,
        line_starts,
        sites,
    );
}

fn check_prefer_signals_and_signal_model(
    cls: &Class<'_>,
    decorator_kind: Option<&str>,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut input_props: Vec<(String, Span)> = Vec::new();
    let mut output_names: HashSet<String> = HashSet::new();

    for elem in &cls.body.body {
        match elem {
            ClassElement::PropertyDefinition(prop) => {
                let Some(prop_name) = prop_key_str(&prop.key) else {
                    continue;
                };
                let has_input = prop
                    .decorators
                    .iter()
                    .any(|d| decorator_name(d) == Some("Input"));
                let has_output = prop
                    .decorators
                    .iter()
                    .any(|d| decorator_name(d) == Some("Output"));

                if has_input {
                    input_props.push((prop_name.to_string(), prop.span));
                    push_angular_site(
                        sites,
                        RuleId::AngularPreferSignals,
                        class_name.map(ToOwned::to_owned),
                        "angularPreferSignals",
                        prop_name.to_string(),
                        format!(
                            "Prefer signal-based `input()` over `@Input()` on `{prop_name}`."
                        ),
                        prop.span,
                        line_starts,
                        None,
                    );
                }
                if has_output {
                    output_names.insert(prop_name.to_string());
                    if let Some(alias) = extract_decorator_first_string_arg(&prop.decorators, "Output") {
                        output_names.insert(alias);
                    }
                }
                if matches!(decorator_kind, Some("Component" | "Directive"))
                    && !has_output
                    && prop.value.as_ref().is_some_and(is_new_behavior_subject)
                {
                    push_angular_site(
                        sites,
                        RuleId::AngularPreferSignals,
                        class_name.map(ToOwned::to_owned),
                        "angularPreferSignals",
                        prop_name.to_string(),
                        format!(
                            "Prefer `signal(...)` over `BehaviorSubject` for component state `{prop_name}`."
                        ),
                        prop.span,
                        line_starts,
                        None,
                    );
                }
            }
            ClassElement::MethodDefinition(method) => {
                let Some(prop_name) = prop_key_str(&method.key) else {
                    continue;
                };
                if method
                    .decorators
                    .iter()
                    .any(|d| decorator_name(d) == Some("Input"))
                {
                    input_props.push((prop_name.to_string(), method.span));
                    push_angular_site(
                        sites,
                        RuleId::AngularPreferSignals,
                        class_name.map(ToOwned::to_owned),
                        "angularPreferSignals",
                        prop_name.to_string(),
                        format!(
                            "Prefer signal-based `input()` with `computed()` over `@Input()` setter `{prop_name}`."
                        ),
                        method.span,
                        line_starts,
                        None,
                    );
                }
            }
            _ => {}
        }
    }

    for (in_name, in_span) in input_props {
        let paired_change = format!("{in_name}Change");
        if output_names.contains(&paired_change) {
            push_angular_site(
                sites,
                RuleId::AngularPreferSignalModel,
                class_name.map(ToOwned::to_owned),
                "angularPreferSignalModel",
                in_name.clone(),
                format!(
                    "Paired `@Input() {in_name}` and `@Output() {paired_change}` can be replaced with a single two-way `{in_name} = model(...)` signal."
                ),
                in_span,
                line_starts,
                None,
            );
        }
    }
}

fn is_new_behavior_subject(expr: &Expression<'_>) -> bool {
    if let Expression::NewExpression(new_expr) = unwrap_ts_and_parens(expr)
        && let Some(name) = callee_ident_name(&new_expr.callee)
    {
        return name == "BehaviorSubject";
    }
    false
}

pub(super) fn extract_decorator_first_string_arg(
    decorators: &[Decorator<'_>],
    target_dec: &str,
) -> Option<String> {
    for dec in decorators {
        if decorator_name(dec) != Some(target_dec) {
            continue;
        }
        if let Expression::CallExpression(call) = dec.expression.without_parentheses()
            && let Some(Argument::StringLiteral(lit)) = call.arguments.first()
            && let Some(s) = lit.value.as_str()
        {
            return Some(s.to_string());
        }
    }
    None
}

fn check_conflicting_lifecycle(
    cls: &Class<'_>,
    implemented: &HashSet<String>,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut has_on_changes = implemented.contains("OnChanges");
    let mut has_do_check = implemented.contains("DoCheck");
    let mut conflict_span = cls.id.as_ref().map_or(cls.span, |id| id.span);

    for elem in &cls.body.body {
        if let ClassElement::MethodDefinition(method) = elem
            && let Some(name) = prop_key_str(&method.key)
        {
            if name == "ngOnChanges" {
                has_on_changes = true;
            } else if name == "ngDoCheck" {
                has_do_check = true;
                conflict_span = method.key.span();
            }
        }
    }

    if has_on_changes && has_do_check {
        let target = class_name.unwrap_or("Component").to_string();
        push_angular_site(
            sites,
            RuleId::AngularNoConflictingLifecycle,
            class_name.map(ToOwned::to_owned),
            "angularNoConflictingLifecycle",
            target.clone(),
            format!(
                "Class `{target}` implements both `OnChanges` (`ngOnChanges`) and `DoCheck` (`ngDoCheck`); use one change detection hook or reactive signals."
            ),
            conflict_span,
            line_starts,
            None,
        );
    }
}

fn check_contextual_decorators(
    cls: &Class<'_>,
    decorator_kind: Option<&str>,
    class_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(cls_kind) = decorator_kind else {
        return;
    };
    if !matches!(cls_kind, "Injectable" | "Pipe" | "NgModule") {
        return;
    }

    for elem in &cls.body.body {
        let (decorators, member_name) = match elem {
            ClassElement::PropertyDefinition(p) => {
                (p.decorators.as_slice(), prop_key_str(&p.key).unwrap_or("property"))
            }
            ClassElement::MethodDefinition(m) => {
                (m.decorators.as_slice(), prop_key_str(&m.key).unwrap_or("method"))
            }
            ClassElement::AccessorProperty(a) => {
                (a.decorators.as_slice(), prop_key_str(&a.key).unwrap_or("accessor"))
            }
            _ => continue,
        };
        for dec in decorators {
            let Some(dec_name) = decorator_name(dec) else {
                continue;
            };
            if COMPONENT_OR_DIRECTIVE_DECORATORS.contains(&dec_name) {
                push_angular_site(
                    sites,
                    RuleId::AngularContextualDecorator,
                    class_name.map(ToOwned::to_owned),
                    "angularContextualDecorator",
                    format!("@{dec_name}"),
                    format!(
                        "Decorator `@{dec_name}` on `{member_name}` is not valid inside `@{cls_kind}`."
                    ),
                    dec.span,
                    line_starts,
                    None,
                );
            }
        }
    }
}

fn check_lifecycle_methods_and_properties(
    cls: &Class<'_>,
    decorator_kind: Option<&str>,
    implemented: &HashSet<String>,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for elem in &cls.body.body {
        match elem {
            ClassElement::MethodDefinition(method) => {
                let Some(method_name) = prop_key_str(&method.key) else {
                    continue;
                };
                let Some(&(_, iface_name)) = LIFECYCLE_METHODS_AND_INTERFACES
                    .iter()
                    .find(|&&(m, _)| m == method_name)
                else {
                    continue;
                };

                // 5. `angular-contextual-lifecycle`
                if let Some(cls_kind) = decorator_kind
                    && !is_lifecycle_valid_for_class_kind(method_name, cls_kind)
                {
                    push_angular_site(
                        sites,
                        RuleId::AngularContextualLifecycle,
                        class_name.map(ToOwned::to_owned),
                        "angularContextualLifecycle",
                        method_name.to_string(),
                        format!(
                            "Lifecycle hook `{method_name}` is not supported on `@{cls_kind}` classes."
                        ),
                        method.key.span(),
                        line_starts,
                        None,
                    );
                }

                // 7. `angular-no-async-lifecycle-method`
                if method.value.r#async {
                    let patch = build_remove_async_keyword_patch(method, source);
                    push_angular_site(
                        sites,
                        RuleId::AngularNoAsyncLifecycleMethod,
                        class_name.map(ToOwned::to_owned),
                        "angularNoAsyncLifecycleMethod",
                        method_name.to_string(),
                        format!(
                            "Lifecycle method `{method_name}` must not be `async`; Angular does not await lifecycle Promises."
                        ),
                        method.key.span(),
                        line_starts,
                        patch,
                    );
                }

                // 10. `angular-no-empty-lifecycle-method`
                if is_empty_lifecycle_method(method, source) {
                    let patch = AutofixPatch::replace(
                        format!("Remove empty `{method_name}()` lifecycle method"),
                        ByteSpan {
                            start: method.span.start,
                            end: method.span.end,
                        },
                        "",
                    );
                    push_angular_site(
                        sites,
                        RuleId::AngularNoEmptyLifecycleMethod,
                        class_name.map(ToOwned::to_owned),
                        "angularNoEmptyLifecycleMethod",
                        method_name.to_string(),
                        format!(
                            "Lifecycle method `{method_name}()` is empty; remove it to avoid unnecessary lifecycle checks."
                        ),
                        method.span,
                        line_starts,
                        Some(patch),
                    );
                }

                // 11. `angular-use-lifecycle-interface`
                if decorator_kind.is_some() && !implemented.contains(iface_name) {
                    push_angular_site(
                        sites,
                        RuleId::AngularUseLifecycleInterface,
                        class_name.map(ToOwned::to_owned),
                        "angularUseLifecycleInterface",
                        iface_name.to_string(),
                        format!(
                            "Lifecycle method `{method_name}` is declared without implementing `{iface_name}` on the class."
                        ),
                        method.key.span(),
                        line_starts,
                        None,
                    );
                }
            }
            ClassElement::PropertyDefinition(prop) => {
                let Some(prop_name) = prop_key_str(&prop.key) else {
                    continue;
                };
                if LIFECYCLE_METHODS_AND_INTERFACES
                    .iter()
                    .any(|&(m, _)| m == prop_name)
                    && prop.value.as_ref().is_some_and(|v| {
                        matches!(
                            v.without_parentheses(),
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        )
                    })
                {
                    let patch = build_prototype_lifecycle_patch(prop, prop_name, source);
                    push_angular_site(
                        sites,
                        RuleId::AngularRequireLifecycleOnPrototype,
                        class_name.map(ToOwned::to_owned),
                        "angularRequireLifecycleOnPrototype",
                        prop_name.to_string(),
                        format!(
                            "Lifecycle hook `{prop_name}` must be declared as a prototype method (`{prop_name}() {{ ... }}`), not a class field."
                        ),
                        prop.span,
                        line_starts,
                        patch,
                    );
                }
            }
            _ => {}
        }
    }
}

fn is_lifecycle_valid_for_class_kind(method_name: &str, cls_kind: &str) -> bool {
    match cls_kind {
        "Component" | "Directive" => true,
        "Injectable" | "Pipe" => method_name == "ngOnDestroy",
        "NgModule" => false,
        _ => true,
    }
}

fn build_remove_async_keyword_patch(
    method: &MethodDefinition<'_>,
    source: &str,
) -> Option<AutofixPatch> {
    if let Some(body) = &method.value.body {
        let body_text = source
            .get(body.span.start as usize..body.span.end as usize)
            .unwrap_or_default();
        if contains_await_token(body_text) {
            return None;
        }
    }
    let key_start = method.key.span().start as usize;
    let method_start = method.span.start as usize;
    let prefix = source.get(method_start..key_start)?;
    let rel = prefix.find("async ")?;
    let start = method.span.start + u32::try_from(rel).ok()?;
    let end = start + 6;
    Some(AutofixPatch::replace(
        "Remove `async` modifier from Angular lifecycle method",
        ByteSpan { start, end },
        "",
    ))
}

fn contains_await_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let is_ident_char = |b: Option<u8>| {
        b.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$')
    };
    let mut from = 0;
    while let Some(rel) = text.get(from..).and_then(|s| s.find("await")) {
        let start = from + rel;
        let end = start + 5;
        if !is_ident_char(start.checked_sub(1).and_then(|i| bytes.get(i).copied()))
            && !is_ident_char(bytes.get(end).copied())
        {
            return true;
        }
        from = end;
    }
    false
}

fn is_empty_lifecycle_method(method: &MethodDefinition<'_>, source: &str) -> bool {
    let Some(body) = &method.value.body else {
        return false;
    };
    if !body.statements.is_empty() {
        return false;
    }
    let inner = source
        .get((body.span.start + 1) as usize..(body.span.end.saturating_sub(1)) as usize)
        .unwrap_or_default();
    inner.trim().is_empty()
}

fn build_prototype_lifecycle_patch(
    prop: &PropertyDefinition<'_>,
    prop_name: &str,
    source: &str,
) -> Option<AutofixPatch> {
    let val = prop.value.as_ref()?.without_parentheses();
    if let Expression::ArrowFunctionExpression(arrow) = val {
        let body_text =
            source.get(arrow.body.span().start as usize..arrow.body.span().end as usize)?;
        if body_text.starts_with('{') {
            let raw_params = source
                .get(arrow.params.span.start as usize..arrow.params.span.end as usize)
                .unwrap_or("()")
                .trim();
            let params_text = if raw_params.starts_with('(') && raw_params.ends_with(')') {
                raw_params.to_string()
            } else if raw_params.is_empty() {
                "()".to_string()
            } else {
                format!("({raw_params})")
            };
            return Some(AutofixPatch::replace(
                format!("Convert `{prop_name}` property into a prototype method"),
                ByteSpan {
                    start: prop.span.start,
                    end: prop.span.end,
                },
                format!("{prop_name}{params_text} {body_text}"),
            ));
        }
    }
    None
}

pub(super) fn check_direct_lifecycle_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    if matches!(mem.object.without_parentheses(), Expression::Super(_)) {
        return;
    }
    let method_name = mem.property.name.as_str();
    if !LIFECYCLE_METHODS_AND_INTERFACES
        .iter()
        .any(|&(m, _)| m == method_name)
    {
        return;
    }
    let subj = enclosing_subject_name(semantic, node_id);
    push_angular_site(
        sites,
        RuleId::AngularNoLifecycleCall,
        subj,
        "angularNoLifecycleCall",
        method_name.to_string(),
        format!(
            "Do not call Angular lifecycle method `{method_name}()` directly; let Angular manage lifecycle execution."
        ),
        call.span,
        line_starts,
        None,
    );
}

fn extract_implemented_interfaces(cls: &Class<'_>, source: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for imp in &cls.implements {
        let raw = source
            .get(imp.span.start as usize..imp.span.end as usize)
            .unwrap_or_default()
            .trim();
        let without_generics = raw.split('<').next().unwrap_or(raw).trim();
        let short_name = without_generics
            .rsplit('.')
            .next()
            .unwrap_or(without_generics)
            .trim();
        if !short_name.is_empty() {
            set.insert(short_name.to_string());
        }
    }
    set
}
