//! Single-pass Angular rules (`angular-*`) covering Angular Signals, RxJS teardown,
//! `ChangeDetectionStrategy.OnPush` (with `Autofix`), `@for (...; track)` templates,
//! constructor purity, nested `.subscribe()`, and `ElementRef.nativeElement` DOM mutations.

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; Angular rules match only relevant AST node kinds"
)]
use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentTarget, CallExpression, Class, ClassElement, Expression,
        MethodDefinitionKind, ObjectExpression, ObjectPropertyKind, Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{ByteSpan, SemanticRuleSite, SubjectIr, SubjectKind, loc_from_line_starts},
    rules::{AutofixPatch, RuleId},
};

/// Returns `true` if `rule` belongs to the Angular, Angular Template, NgRx, or Angular Material rule suite.
#[must_use]
pub const fn is_evaluated_angular_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::AngularNoSignalWriteInEffect
            | RuleId::AngularRxjsSubscribeRequiresTeardown
            | RuleId::AngularPreferOnPushChangeDetection
            | RuleId::AngularForTrackNoIndex
            | RuleId::AngularNoWorkInConstructor
            | RuleId::AngularNoNestedSubscribe
            | RuleId::AngularNoDirectNativeElementMutation
            | RuleId::AngularNoUncalledSignals
            | RuleId::AngularPreferSignalModel
            | RuleId::AngularPreferSignals
            | RuleId::AngularNoConflictingLifecycle
            | RuleId::AngularContextualLifecycle
            | RuleId::AngularContextualDecorator
            | RuleId::AngularNoAsyncLifecycleMethod
            | RuleId::AngularNoLifecycleCall
            | RuleId::AngularRequireLifecycleOnPrototype
            | RuleId::AngularNoEmptyLifecycleMethod
            | RuleId::AngularUseLifecycleInterface
            | RuleId::AngularUsePipeTransformInterface
            | RuleId::AngularNoPipeImpure
            | RuleId::AngularNoOutputNative
            | RuleId::AngularNoOutputOnPrefix
            | RuleId::AngularRelativeUrlPrefix
            | RuleId::AngularPreferStandalone
            | RuleId::AngularPreferInject
            | RuleId::AngularUseInjectableProvidedIn
            | RuleId::AngularPreferHostMetadataProperty
            | RuleId::AngularNoDuplicatesInMetadataArrays
            | RuleId::AngularNoForwardRef
            | RuleId::AngularNoInputsMetadataProperty
            | RuleId::AngularNoOutputsMetadataProperty
            | RuleId::AngularNoQueriesMetadataProperty
            | RuleId::AngularPreferOutputReadonly
            | RuleId::AngularPreferOutputEmitterRef
            | RuleId::AngularUseComponentViewEncapsulation
            | RuleId::AngularNoAttributeDecorator
            | RuleId::AngularComponentMaxInlineDeclarations
            | RuleId::AngularTemplateNoAny
            | RuleId::AngularTemplateAltText
            | RuleId::AngularTemplateClickEventsHaveKeyEvents
            | RuleId::AngularTemplateMouseEventsHaveKeyEvents
            | RuleId::AngularTemplateElementsHaveContent
            | RuleId::AngularTemplateInteractiveSupportsFocus
            | RuleId::AngularTemplateTableScope
            | RuleId::AngularTemplateValidAria
            | RuleId::NgrxNoMultipleActionsInEffects
            | RuleId::NgrxNoEffectDecoratorAndCreator
            | RuleId::NgrxNoCyclicActionCreators
            | RuleId::NgrxNoTypedGlobalStore
            | RuleId::NgrxOnFunctionExplicitReturnType
            | RuleId::NgrxSelectStyle
            | RuleId::AngularMaterialNoConflictingMixins
    )
}

/// Extracts Angular `@Component`, `@Directive`, `@Injectable`, and `@Pipe` classes as [`SubjectIr`]s
/// so **Subject** counts, **Contextual Owner** spans, and **Fix Capsules** cover Angular classes.
pub(crate) fn extract_angular_class_subjects(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    subjects: &mut Vec<SubjectIr>,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::Class(cls) = node.kind() else {
            continue;
        };
        if angular_class_decorator_kind(cls).is_none() {
            continue;
        }
        let Some(id) = &cls.id else {
            continue;
        };
        let name = id.name.to_string();
        if subjects
            .iter()
            .any(|s| s.name.as_deref() == Some(name.as_str()))
        {
            continue;
        }
        let parent_id = semantic.nodes().parent_id(node_id);
        let full_span = match semantic.nodes().kind(parent_id) {
            AstKind::ExportNamedDeclaration(exp) => Span::new(
                exp.span.start.min(cls.span.start),
                exp.span.end.max(cls.span.end),
            ),
            AstKind::ExportDefaultDeclaration(exp) => Span::new(
                exp.span.start.min(cls.span.start),
                exp.span.end.max(cls.span.end),
            ),
            _ => cls.span,
        };
        let byte_span = ByteSpan {
            start: full_span.start,
            end: full_span.end,
        };
        subjects.push(SubjectIr {
            name: Some(name),
            kind: SubjectKind::Component,
            is_hoc_wrapped: false,
            loc: loc_from_line_starts(line_starts, byte_span.start),
            span: byte_span,
            state_slots: Vec::new(),
            effect_nodes: Vec::new(),
            is_memoized: has_on_push_change_detection(cls),
            has_custom_memo_comparator: false,
            props_in_hook_deps: Vec::new(),
            suspends: false,
            throws_in_render: false,
        });
    }
}

/// Extracts all 7 `angular-*` rule findings in a single pass over the `oxc` AST and semantic model.
pub(crate) fn extract_angular_sites(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let class_teardowns = collect_class_teardown_identifiers(semantic);
    let native_element_vars = collect_native_element_aliases(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Class(cls) => {
                check_angular_class_decorators_and_constructor(
                    semantic,
                    cls,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                if is_angular_effect_call(call) {
                    check_signal_write_in_effect(semantic, node_id, call, line_starts, sites);
                }
                if is_subscribe_call(call) {
                    check_subscribe_teardown_and_nesting(
                        semantic,
                        node_id,
                        call,
                        &class_teardowns,
                        source,
                        line_starts,
                        sites,
                    );
                }
                check_native_element_call_mutation(
                    semantic,
                    node_id,
                    call,
                    &native_element_vars,
                    line_starts,
                    sites,
                );
            }
            AstKind::AssignmentExpression(assign) => {
                check_native_element_assignment_mutation(
                    semantic,
                    node_id,
                    &assign.left,
                    assign.span,
                    &native_element_vars,
                    line_starts,
                    sites,
                );
            }
            AstKind::UnaryExpression(unary)
                if unary.operator == UnaryOperator::Delete
                    && expr_targets_native_element(&unary.argument, &native_element_vars) =>
            {
                let subj = enclosing_subject_name(semantic, node_id);
                push_angular_site(
                    sites,
                    RuleId::AngularNoDirectNativeElementMutation,
                    subj,
                    "angularNoDirectNativeElementMutation",
                    "nativeElement".to_string(),
                    "Avoid mutating `ElementRef.nativeElement` directly; use Angular template bindings or `Renderer2`.".to_string(),
                    unary.span,
                    line_starts,
                    None,
                );
            }
            _ => {}
        }
    }
}

/// Scans an Angular template string (either an external `.html` file or an inline `template: \`...\``)
/// for `@for (...; track ...)` loops that track `$index` or unstable object identity.
pub(crate) fn extract_angular_html_template_sites(
    template_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let bytes = template_source.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let Some(rel_pos) = template_source[i..].find("@for") else {
            break;
        };
        let at_pos = i + rel_pos;
        let after_for = at_pos + 4;
        if after_for < bytes.len()
            && (bytes[after_for].is_ascii_alphanumeric() || bytes[after_for] == b'_')
        {
            i = after_for;
            continue;
        }
        let mut cursor = after_for;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            i = after_for;
            continue;
        }
        let open_paren = cursor;
        let Some(close_paren) = find_matching_paren(template_source, open_paren) else {
            i = open_paren + 1;
            continue;
        };
        let header = template_source
            .get(open_paren + 1..close_paren)
            .unwrap_or_default();
        if let Some((track_target, reason)) = classify_for_header_track_violation(header) {
            let start = base_byte_offset + u32::try_from(at_pos).unwrap_or(0);
            let end = base_byte_offset + u32::try_from(close_paren).unwrap_or(0) + 1;
            sites.push(SemanticRuleSite {
                rule: RuleId::AngularForTrackNoIndex,
                subject_name: subject_name.map(ToOwned::to_owned),
                message_id: "angularForTrackNoIndex",
                target_name: track_target,
                message: reason,
                loc: loc_from_line_starts(line_starts, start),
                span: ByteSpan { start, end },
                autofix: None,
            });
        }
        i = close_paren + 1;
    }
}

fn find_matching_paren(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let bytes = text.as_bytes();
    let mut idx = open_idx;
    while idx < bytes.len() {
        let b = bytes[idx];
        if let Some(q) = in_quote {
            if b == b'\\' {
                idx += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
        } else if b == b'\'' || b == b'"' {
            in_quote = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
        idx += 1;
    }
    None
}

fn classify_for_header_track_violation(header: &str) -> Option<(String, String)> {
    let mut segments = header.split(';');
    let first_seg = segments.next()?.trim();
    let (item_part, _collection_part) = first_seg.split_once(" of ")?;
    let item_var = item_part.trim();
    if item_var.is_empty() {
        return None;
    }

    let mut index_aliases: HashSet<&str> = HashSet::from(["$index"]);
    let mut track_expr: Option<&str> = None;

    for seg in segments {
        let trimmed = seg.trim();
        if let Some(rest) = trimmed.strip_prefix("let ") {
            if let Some((alias, rhs)) = rest.split_once('=')
                && rhs.trim() == "$index"
            {
                index_aliases.insert(alias.trim());
            }
        } else if let Some(rest) = trimmed.strip_prefix("track")
            && rest.starts_with(char::is_whitespace)
        {
            track_expr = Some(rest.trim());
        }
    }

    let track = track_expr?;
    if index_aliases.contains(track) {
        return Some((
            track.to_string(),
            format!(
                "`@for` loop tracks `{track}` (`$index`); track a stable unique property like `track {item_var}.id` so DOM nodes are preserved when items reorder."
            ),
        ));
    }
    if track == item_var {
        return Some((
            track.to_string(),
            format!(
                "`@for` loop tracks raw object identity `track {item_var}`; track a unique key property like `track {item_var}.id` so immutable updates do not tear down DOM nodes."
            ),
        ));
    }
    None
}

fn angular_class_decorator_kind(cls: &Class<'_>) -> Option<&'static str> {
    for dec in &cls.decorators {
        let name = match dec.expression.without_parentheses() {
            Expression::CallExpression(call) => callee_ident_name(&call.callee),
            Expression::Identifier(id) => Some(id.name.as_str()),
            _ => None,
        };
        match name {
            Some("Component") => return Some("Component"),
            Some("Directive") => return Some("Directive"),
            Some("Injectable") => return Some("Injectable"),
            Some("Pipe") => return Some("Pipe"),
            Some("NgModule") => return Some("NgModule"),
            _ => {}
        }
    }
    None
}

fn has_on_push_change_detection(cls: &Class<'_>) -> bool {
    for dec in &cls.decorators {
        let Expression::CallExpression(call) = dec.expression.without_parentheses() else {
            continue;
        };
        if callee_ident_name(&call.callee) != Some("Component") {
            continue;
        }
        let Some(Argument::ObjectExpression(obj)) = call.arguments.first() else {
            continue;
        };
        for prop_kind in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            if prop_key_str(&prop.key) == Some("changeDetection") && expr_is_on_push(&prop.value) {
                return true;
            }
        }
    }
    false
}

fn expr_is_on_push(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => mem.property.name == "OnPush",
        Expression::NumericLiteral(num) => (num.value - 0.0).abs() > f64::EPSILON,
        _ => false,
    }
}

fn check_angular_class_decorators_and_constructor(
    semantic: &Semantic<'_>,
    cls: &Class<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(decorator_kind) = angular_class_decorator_kind(cls) else {
        return;
    };
    let class_name = cls.id.as_ref().map(|id| id.name.to_string());

    for dec in &cls.decorators {
        let Expression::CallExpression(call) = dec.expression.without_parentheses() else {
            continue;
        };
        if callee_ident_name(&call.callee) != Some("Component") {
            continue;
        }
        let Some(Argument::ObjectExpression(obj)) = call.arguments.first() else {
            continue;
        };
        check_component_decorator_metadata(
            dec.span,
            obj,
            class_name.as_deref(),
            source,
            line_starts,
            sites,
        );
    }

    if matches!(
        decorator_kind,
        "Component" | "Directive" | "Injectable" | "Pipe"
    ) {
        for elem in &cls.body.body {
            let ClassElement::MethodDefinition(method) = elem else {
                continue;
            };
            if method.kind == MethodDefinitionKind::Constructor
                && let Some(body) = &method.value.body
            {
                check_constructor_statements(
                    semantic,
                    &body.statements,
                    class_name.as_deref(),
                    source,
                    line_starts,
                    sites,
                );
            }
        }
    }
}

fn check_component_decorator_metadata(
    decorator_span: Span,
    obj: &ObjectExpression<'_>,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut has_change_detection = false;
    let mut has_spread = false;
    let target = class_name.unwrap_or("Component").to_string();

    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            has_spread = true;
            continue;
        };
        let Some(key_name) = prop_key_str(&prop.key) else {
            continue;
        };
        match key_name {
            "template" => {
                if let Some((tpl_text, inner_start)) =
                    extract_template_text_and_offset(&prop.value, source)
                {
                    extract_angular_html_template_sites(
                        tpl_text,
                        inner_start,
                        class_name,
                        line_starts,
                        sites,
                    );
                }
            }
            "changeDetection" => {
                has_change_detection = true;
                if !expr_is_on_push(&prop.value) {
                    let val_span = prop.value.span();
                    let patch = AutofixPatch::replace(
                        "Set `changeDetection: ChangeDetectionStrategy.OnPush`",
                        ByteSpan {
                            start: val_span.start,
                            end: val_span.end,
                        },
                        "ChangeDetectionStrategy.OnPush",
                    );
                    push_angular_site(
                        sites,
                        RuleId::AngularPreferOnPushChangeDetection,
                        class_name.map(ToOwned::to_owned),
                        "angularPreferOnPushChangeDetection",
                        target.clone(),
                        format!(
                            "`@Component` `{target}` uses default change detection; set `changeDetection: ChangeDetectionStrategy.OnPush` to skip unchanged subtrees."
                        ),
                        prop.span,
                        line_starts,
                        Some(patch),
                    );
                }
            }
            _ => {}
        }
    }

    if !has_change_detection && !has_spread {
        let patch = build_insert_on_push_patch(obj, source);
        push_angular_site(
            sites,
            RuleId::AngularPreferOnPushChangeDetection,
            class_name.map(ToOwned::to_owned),
            "angularPreferOnPushChangeDetection",
            target.clone(),
            format!(
                "`@Component` `{target}` is missing `changeDetection: ChangeDetectionStrategy.OnPush`."
            ),
            decorator_span,
            line_starts,
            Some(patch),
        );
    }
}

fn extract_template_text_and_offset<'a>(
    expr: &Expression<'a>,
    source: &'a str,
) -> Option<(&'a str, u32)> {
    let sp = match expr.without_parentheses() {
        Expression::TemplateLiteral(tpl) => tpl.span,
        Expression::StringLiteral(lit) => lit.span,
        _ => return None,
    };
    if sp.end <= sp.start + 1 {
        return None;
    }
    let inner_start = sp.start + 1;
    let inner_end = sp.end - 1;
    let slice = source.get(inner_start as usize..inner_end as usize)?;
    Some((slice, inner_start))
}

fn build_insert_on_push_patch(obj: &ObjectExpression<'_>, source: &str) -> AutofixPatch {
    let description =
        "Add `changeDetection: ChangeDetectionStrategy.OnPush` to `@Component` metadata"
            .to_string();
    let Some(last_prop) = obj.properties.last() else {
        return AutofixPatch::replace(
            description,
            ByteSpan {
                start: obj.span.start,
                end: obj.span.end,
            },
            "{ changeDetection: ChangeDetectionStrategy.OnPush }",
        );
    };

    let last_span = last_prop.span();
    let obj_slice = source
        .get(obj.span.start as usize..obj.span.end as usize)
        .unwrap_or_default();
    let is_multiline = obj_slice.contains('\n');
    let trailing = source
        .get(last_span.end as usize..obj.span.end as usize)
        .unwrap_or_default();
    let trimmed_trailing = trailing.trim_start();
    let has_trailing_comma = trimmed_trailing.starts_with(',');

    if is_multiline {
        let indent = line_leading_indent(source, last_span.start as usize);
        let indent_str = if indent.is_empty() { "  " } else { indent };
        if has_trailing_comma {
            let comma_rel = trailing.find(',').unwrap_or(0);
            let insert_pos = last_span.end + u32::try_from(comma_rel).unwrap_or(0) + 1;
            AutofixPatch::insert(
                description,
                insert_pos,
                format!("\n{indent_str}changeDetection: ChangeDetectionStrategy.OnPush,"),
            )
        } else {
            AutofixPatch::insert(
                description,
                last_span.end,
                format!(",\n{indent_str}changeDetection: ChangeDetectionStrategy.OnPush"),
            )
        }
    } else if has_trailing_comma {
        let comma_rel = trailing.find(',').unwrap_or(0);
        let insert_pos = last_span.end + u32::try_from(comma_rel).unwrap_or(0) + 1;
        AutofixPatch::insert(
            description,
            insert_pos,
            " changeDetection: ChangeDetectionStrategy.OnPush",
        )
    } else {
        AutofixPatch::insert(
            description,
            last_span.end,
            ", changeDetection: ChangeDetectionStrategy.OnPush",
        )
    }
}

fn line_leading_indent(source: &str, byte_pos: usize) -> &str {
    let prefix = source.get(..byte_pos).unwrap_or_default();
    let line_start = prefix.rfind('\n').map_or(0, |idx| idx + 1);
    let line_prefix = source.get(line_start..byte_pos).unwrap_or_default();
    let ws_len = line_prefix
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    line_prefix.get(..ws_len).unwrap_or_default()
}

fn check_constructor_statements(
    semantic: &Semantic<'_>,
    statements: &[Statement<'_>],
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for stmt in statements {
        let stmt_span = stmt.span();
        if matches!(
            stmt,
            Statement::ForStatement(_)
                | Statement::ForOfStatement(_)
                | Statement::ForInStatement(_)
                | Statement::WhileStatement(_)
                | Statement::DoWhileStatement(_)
        ) {
            push_angular_site(
                sites,
                RuleId::AngularNoWorkInConstructor,
                class_name.map(ToOwned::to_owned),
                "angularNoWorkInConstructor",
                "constructor".to_string(),
                "Avoid heavy loops inside `constructor()`; move initialization logic to `ngOnInit()` or `computed()`.".to_string(),
                stmt_span,
                line_starts,
                None,
            );
            continue;
        }

        if let Some((call_span, target_name, reason)) =
            find_impure_constructor_call_in_span(semantic, stmt_span, source)
        {
            push_angular_site(
                sites,
                RuleId::AngularNoWorkInConstructor,
                class_name.map(ToOwned::to_owned),
                "angularNoWorkInConstructor",
                target_name,
                reason,
                call_span,
                line_starts,
                None,
            );
        }
    }
}

fn find_impure_constructor_call_in_span(
    semantic: &Semantic<'_>,
    stmt_span: Span,
    source: &str,
) -> Option<(Span, String, String)> {
    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if call.span.start < stmt_span.start || call.span.end > stmt_span.end {
            continue;
        }
        if let Some((target, reason)) = classify_impure_constructor_call(call, source) {
            return Some((call.span, target, reason));
        }
    }
    None
}

fn classify_impure_constructor_call(
    call: &CallExpression<'_>,
    source: &str,
) -> Option<(String, String)> {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            if matches!(id.name.as_str(), "fetch" | "setInterval" | "setTimeout") {
                return Some((
                    id.name.to_string(),
                    format!(
                        "Avoid calling `{}(...)` inside `constructor()`; move side effects and network requests to `ngOnInit()`.",
                        id.name
                    ),
                ));
            }
        }
        Expression::StaticMemberExpression(mem) => {
            let prop = mem.property.name.as_str();
            let obj_text = source
                .get(mem.object.span().start as usize..mem.object.span().end as usize)
                .unwrap_or_default()
                .trim();

            if prop == "subscribe" {
                let is_http_or_fetch = obj_text.contains("http.")
                    || obj_text.contains("Http")
                    || obj_text.contains(".get(")
                    || obj_text.contains(".post(")
                    || obj_text.contains(".put(")
                    || obj_text.contains(".delete(")
                    || obj_text.contains(".fetch");
                let has_take_until_destroyed = obj_text.contains("takeUntilDestroyed");
                if is_http_or_fetch || !has_take_until_destroyed {
                    let target = extract_stream_target_name(&mem.object, source);
                    return Some((
                        target,
                        "Avoid starting subscriptions or HTTP requests inside `constructor()`; move stream subscriptions to `ngOnInit()` or use `toSignal()`.".to_string(),
                    ));
                }
            }

            if (obj_text == "this.http" || obj_text.ends_with(".http") || obj_text == "http")
                && matches!(
                    prop,
                    "get" | "post" | "put" | "delete" | "patch" | "request" | "head"
                )
            {
                return Some((
                    format!("http.{prop}"),
                    format!(
                        "Avoid triggering `http.{prop}(...)` inside `constructor()`; move HTTP calls to `ngOnInit()` or a declarative data stream."
                    ),
                ));
            }

            if matches!(obj_text, "localStorage" | "sessionStorage" | "document")
                || (obj_text == "window" && prop == "addEventListener")
            {
                return Some((
                    format!("{obj_text}.{prop}"),
                    format!(
                        "Avoid `{obj_text}.{prop}(...)` inside `constructor()`; browser globals break SSR and belong in `ngOnInit()` or `afterNextRender()`."
                    ),
                ));
            }
        }
        _ => {}
    }
    None
}

fn is_angular_effect_call(call: &CallExpression<'_>) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => id.name == "effect",
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "effect"
                && matches!(
                    mem.object.without_parentheses(),
                    Expression::ThisExpression(_)
                )
        }
        _ => false,
    }
}

fn check_signal_write_in_effect(
    semantic: &Semantic<'_>,
    effect_node_id: NodeId,
    effect_call: &CallExpression<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(first_arg) = effect_call.arguments.first() else {
        return;
    };
    let cb_span = first_arg.span();
    let subj = enclosing_subject_name(semantic, effect_node_id);
    let mut found_write = false;

    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(inner_call) = node.kind() else {
            continue;
        };
        if inner_call.span.start <= cb_span.start || inner_call.span.end > cb_span.end {
            continue;
        }
        let Expression::StaticMemberExpression(mem) = inner_call.callee.without_parentheses()
        else {
            continue;
        };
        let method_name = mem.property.name.as_str();
        if !matches!(method_name, "set" | "update") || inner_call.arguments.len() != 1 {
            continue;
        }
        if is_non_signal_collection_receiver(semantic, &mem.object) {
            continue;
        }
        let Some(sig_name) = extract_signal_receiver_name(&mem.object) else {
            continue;
        };
        found_write = true;
        push_angular_site(
            sites,
            RuleId::AngularNoSignalWriteInEffect,
            subj.clone(),
            "angularNoSignalWriteInEffect",
            sig_name.clone(),
            format!(
                "Do not write to signal `{sig_name}` (`.{method_name}(...)`) inside `effect()`; derive reactive state with `computed(() => ...)` instead."
            ),
            inner_call.span,
            line_starts,
            None,
        );
    }

    if !found_write
        && let Some(Argument::ObjectExpression(opts)) = effect_call.arguments.get(1)
        && has_allow_signal_writes_true(opts)
    {
        push_angular_site(
            sites,
            RuleId::AngularNoSignalWriteInEffect,
            subj,
            "angularNoSignalWriteInEffect",
            "effect".to_string(),
            "Avoid `{ allowSignalWrites: true }` on `effect()`; derive dependent signals with `computed(() => ...)`.".to_string(),
            effect_call.span,
            line_starts,
            None,
        );
    }
}

fn has_allow_signal_writes_true(opts: &ObjectExpression<'_>) -> bool {
    opts.properties.iter().any(|p| {
        if let ObjectPropertyKind::ObjectProperty(prop) = p
            && prop_key_str(&prop.key) == Some("allowSignalWrites")
            && let Expression::BooleanLiteral(b) = prop.value.without_parentheses()
        {
            b.value
        } else {
            false
        }
    })
}

fn is_non_signal_collection_receiver(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    let source = semantic.source_text();
    let text = source
        .get(expr.span().start as usize..expr.span().end as usize)
        .unwrap_or_default()
        .trim();
    if matches!(
        text,
        "localStorage" | "sessionStorage" | "Reflect" | "Headers" | "params" | "headers"
    ) {
        return true;
    }
    let prop_name = match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    };
    let Some(name) = prop_name else {
        return false;
    };
    for (_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::PropertyDefinition(prop) => {
                if prop_key_str(&prop.key) == Some(name)
                    && let Some(val) = &prop.value
                    && is_map_or_set_new_expr(val)
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if decl
                    .id
                    .get_binding_identifier()
                    .is_some_and(|b| b.name == name)
                    && let Some(init) = &decl.init
                    && is_map_or_set_new_expr(init)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn is_map_or_set_new_expr(expr: &Expression<'_>) -> bool {
    if let Expression::NewExpression(new_expr) = expr.without_parentheses()
        && let Some(name) = callee_ident_name(&new_expr.callee)
    {
        return matches!(
            name,
            "Map" | "Set" | "WeakMap" | "WeakSet" | "Headers" | "URLSearchParams" | "FormControl"
        );
    }
    false
}

fn extract_signal_receiver_name(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.to_string()),
        _ => None,
    }
}

fn is_subscribe_call(call: &CallExpression<'_>) -> bool {
    matches!(
        call.callee.without_parentheses(),
        Expression::StaticMemberExpression(mem) if mem.property.name == "subscribe"
    )
}

fn collect_class_teardown_identifiers(semantic: &Semantic<'_>) -> HashMap<NodeId, HashSet<String>> {
    let mut map: HashMap<NodeId, HashSet<String>> = HashMap::new();
    let source = semantic.source_text();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::Class(cls) = node.kind() else {
            continue;
        };
        // Collect method definitions by name inside `cls`
        let mut method_spans: HashMap<String, Span> = HashMap::new();
        for elem in &cls.body.body {
            if let ClassElement::MethodDefinition(method_def) = elem
                && let Some(name) = prop_key_str(&method_def.key)
            {
                method_spans.insert(name.to_string(), method_def.span);
            }
        }
        let Some(&ng_on_destroy_span) = method_spans.get("ngOnDestroy") else {
            map.insert(node_id, HashSet::new());
            continue;
        };

        // Collect `ngOnDestroy` span and any class helper methods invoked inside `ngOnDestroy`
        let mut teardown_method_spans = vec![ng_on_destroy_span];
        for (_inner_id, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::CallExpression(call) = inner_node.kind() else {
                continue;
            };
            if call.span.start < ng_on_destroy_span.start || call.span.end > ng_on_destroy_span.end
            {
                continue;
            }
            if let Some(helper_name) = extract_this_method_call_name(&call.callee)
                && let Some(&helper_span) = method_spans.get(helper_name)
            {
                teardown_method_spans.push(helper_span);
            }
        }

        let mut torn_down = HashSet::new();
        for (_inner_id, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::CallExpression(call) = inner_node.kind() else {
                continue;
            };
            let in_teardown_method = teardown_method_spans
                .iter()
                .any(|sp| call.span.start >= sp.start && call.span.end <= sp.end);
            if !in_teardown_method {
                continue;
            }
            let Some(unsub_obj) = extract_unsubscribe_receiver(&call.callee) else {
                continue;
            };
            if let Some(name) = extract_signal_receiver_name(unsub_obj) {
                torn_down.insert(name);
            }
            let recv_text = source
                .get(unsub_obj.span().start as usize..unsub_obj.span().end as usize)
                .unwrap_or_default()
                .trim();
            torn_down.insert(recv_text.to_string());
        }
        map.insert(node_id, torn_down);
    }
    map
}

fn extract_this_method_call_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::StaticMemberExpression(mem)
            if matches!(
                mem.object.without_parentheses(),
                Expression::ThisExpression(_)
            ) =>
        {
            Some(mem.property.name.as_str())
        }
        _ => None,
    }
}

fn extract_unsubscribe_receiver<'a>(callee: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match callee.without_parentheses() {
        Expression::StaticMemberExpression(mem) if mem.property.name == "unsubscribe" => {
            Some(&mem.object)
        }
        Expression::ChainExpression(chain) => {
            if let oxc_ast::ast::ChainElement::StaticMemberExpression(mem) = &chain.expression
                && mem.property.name == "unsubscribe"
            {
                Some(&mem.object)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn check_subscribe_teardown_and_nesting(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    call: &CallExpression<'_>,
    class_teardowns: &HashMap<NodeId, HashSet<String>>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let subj = enclosing_subject_name(semantic, call_node_id);
    let target_name = extract_stream_target_name(&mem.object, source);

    // 1. Check `angular-no-nested-subscribe`: is this `.subscribe(...)` inside an outer `.subscribe(...)`'s arguments?
    let is_nested = semantic.nodes().ancestor_ids(call_node_id).any(|anc_id| {
        if let AstKind::CallExpression(outer_call) = semantic.nodes().kind(anc_id)
            && is_subscribe_call(outer_call)
        {
            outer_call.arguments.iter().any(|arg| {
                let sp = arg.span();
                call.span.start >= sp.start && call.span.end <= sp.end
            })
        } else {
            false
        }
    });

    if is_nested {
        push_angular_site(
            sites,
            RuleId::AngularNoNestedSubscribe,
            subj.clone(),
            "angularNoNestedSubscribe",
            target_name.clone(),
            format!(
                "Nested `.subscribe()` on `{target_name}`; compose streams with `switchMap`, `mergeMap`, `concatMap`, or `exhaustMap` instead."
            ),
            call.span,
            line_starts,
            None,
        );
    }

    // 2. Check `angular-rxjs-subscribe-requires-teardown`
    if let Some(enclosing_cls) = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find_map(|anc_id| match semantic.nodes().kind(anc_id) {
            AstKind::Class(cls) => Some(cls),
            _ => None,
        })
        && angular_class_decorator_kind(enclosing_cls).is_none()
    {
        return;
    }
    if has_pipe_teardown(&mem.object, source)
        || is_subscription_stored_and_torn_down(semantic, call_node_id, class_teardowns)
    {
        return;
    }
    push_angular_site(
        sites,
        RuleId::AngularRxjsSubscribeRequiresTeardown,
        subj,
        "angularRxjsSubscribeRequiresTeardown",
        target_name.clone(),
        format!(
            "Subscription to `{target_name}` lacks teardown; pipe through `takeUntilDestroyed()`, unsubscribe in `ngOnDestroy()`, or use the template `| async` pipe."
        ),
        call.span,
        line_starts,
        None,
    );
}

fn has_pipe_teardown(receiver: &Expression<'_>, source: &str) -> bool {
    let sp = receiver.span();
    let Some(text) = source.get(sp.start as usize..sp.end as usize) else {
        return false;
    };
    text.contains("takeUntilDestroyed(")
        || text.contains("takeUntil(")
        || text.contains("takeWhile(")
        || text.contains("first(")
        || text.contains("single(")
        || text.contains("last(")
        || text.contains("take(1)")
}

fn is_subscription_stored_and_torn_down(
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
    class_teardowns: &HashMap<NodeId, HashSet<String>>,
) -> bool {
    let enclosing_class_id = semantic
        .nodes()
        .ancestor_ids(call_node_id)
        .find(|&anc_id| matches!(semantic.nodes().kind(anc_id), AstKind::Class(_)));
    let Some(cls_id) = enclosing_class_id else {
        return false;
    };
    let Some(torn_down_names) = class_teardowns.get(&cls_id) else {
        return false;
    };
    if torn_down_names.is_empty() {
        return false;
    }

    for anc_id in semantic.nodes().ancestor_ids(call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::AssignmentExpression(assign) => {
                if let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                    && torn_down_names.contains(mem.property.name.as_str())
                {
                    return true;
                }
                if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
                    && torn_down_names.contains(id.name.as_str())
                {
                    return true;
                }
            }
            AstKind::PropertyDefinition(prop) => {
                if let Some(name) = prop_key_str(&prop.key)
                    && torn_down_names.contains(name)
                {
                    return true;
                }
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && torn_down_names.contains(id.name.as_str())
                {
                    return true;
                }
            }
            AstKind::CallExpression(parent_call) => {
                if let Expression::StaticMemberExpression(mem) =
                    parent_call.callee.without_parentheses()
                    && matches!(mem.property.name.as_str(), "add" | "push")
                    && let Some(holder_name) = extract_signal_receiver_name(&mem.object)
                    && torn_down_names.contains(holder_name.as_str())
                {
                    return true;
                }
            }
            AstKind::MethodDefinition(_) | AstKind::Class(_) => break,
            _ => {}
        }
    }
    false
}

fn extract_stream_target_name(expr: &Expression<'_>, source: &str) -> String {
    match expr.without_parentheses() {
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                if mem.property.name == "pipe" {
                    return extract_stream_target_name(&mem.object, source);
                }
                return mem.property.name.to_string();
            }
        }
        Expression::StaticMemberExpression(mem) => {
            return mem.property.name.to_string();
        }
        Expression::Identifier(id) => {
            return id.name.to_string();
        }
        _ => {}
    }
    source
        .get(expr.span().start as usize..expr.span().end as usize)
        .unwrap_or("stream")
        .trim()
        .to_string()
}

fn collect_native_element_aliases(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut aliases = HashSet::new();
    for (_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let Some(binding) = decl.id.get_binding_identifier() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if expr_contains_native_element_access(init) {
            aliases.insert(binding.name.to_string());
        }
    }
    aliases
}

fn expr_contains_native_element_access(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == "nativeElement" || expr_contains_native_element_access(&mem.object)
        }
        Expression::ChainExpression(chain) => {
            if let oxc_ast::ast::ChainElement::StaticMemberExpression(mem) = &chain.expression {
                mem.property.name == "nativeElement"
                    || expr_contains_native_element_access(&mem.object)
            } else {
                false
            }
        }
        Expression::TSNonNullExpression(non_null) => {
            expr_contains_native_element_access(&non_null.expression)
        }
        Expression::TSAsExpression(ts_as) => expr_contains_native_element_access(&ts_as.expression),
        _ => false,
    }
}

fn expr_targets_native_element(expr: &Expression<'_>, native_vars: &HashSet<String>) -> bool {
    if expr_contains_native_element_access(expr) {
        return true;
    }
    match expr.without_parentheses() {
        Expression::Identifier(id) => native_vars.contains(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
        }
        Expression::ComputedMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
        }
        Expression::TSNonNullExpression(non_null) => {
            expr_targets_native_element(&non_null.expression, native_vars)
        }
        Expression::TSAsExpression(ts_as) => {
            expr_targets_native_element(&ts_as.expression, native_vars)
        }
        _ => false,
    }
}

fn check_native_element_assignment_mutation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    left: &AssignmentTarget<'_>,
    assign_span: Span,
    native_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let target_prop = match left {
        AssignmentTarget::StaticMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
                .then(|| mem.property.name.to_string())
        }
        AssignmentTarget::ComputedMemberExpression(mem) => {
            expr_targets_native_element(&mem.object, native_vars)
                .then(|| "nativeElement".to_string())
        }
        _ => None,
    };

    if let Some(prop) = target_prop {
        let subj = enclosing_subject_name(semantic, node_id);
        push_angular_site(
            sites,
            RuleId::AngularNoDirectNativeElementMutation,
            subj,
            "angularNoDirectNativeElementMutation",
            prop.clone(),
            format!(
                "Direct DOM mutation on `nativeElement` (`{prop}`); use Angular template bindings, `@HostBinding`, or `Renderer2` instead."
            ),
            assign_span,
            line_starts,
            None,
        );
    }
}

fn check_native_element_call_mutation(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    native_vars: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let method = mem.property.name.as_str();
    let is_dom_mutating_method = matches!(
        method,
        "add"
            | "remove"
            | "toggle"
            | "replace"
            | "setProperty"
            | "removeProperty"
            | "setAttribute"
            | "removeAttribute"
            | "toggleAttribute"
            | "setAttributeNS"
            | "removeAttributeNS"
            | "appendChild"
            | "removeChild"
            | "insertBefore"
            | "replaceChild"
            | "append"
            | "prepend"
            | "replaceWith"
            | "replaceChildren"
            | "insertAdjacentHTML"
            | "insertAdjacentElement"
            | "insertAdjacentText"
    );
    if !is_dom_mutating_method || !expr_targets_native_element(&mem.object, native_vars) {
        return;
    }
    let subj = enclosing_subject_name(semantic, node_id);
    push_angular_site(
        sites,
        RuleId::AngularNoDirectNativeElementMutation,
        subj,
        "angularNoDirectNativeElementMutation",
        method.to_string(),
        format!(
            "Direct DOM mutation `nativeElement...{method}(...)`; use Angular template bindings or `Renderer2` methods instead."
        ),
        call.span,
        line_starts,
        None,
    );
}

fn callee_ident_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

fn enclosing_subject_name(semantic: &Semantic<'_>, node_id: NodeId) -> Option<String> {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Class(cls) => {
                if let Some(id) = &cls.id {
                    return Some(id.name.to_string());
                }
            }
            AstKind::Function(f) => {
                if let Some(id) = &f.id {
                    return Some(id.name.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[expect(
    clippy::too_many_arguments,
    reason = "Internal diagnostic site constructor takes resolved rule metadata and source span fields"
)]
fn push_angular_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: String,
    message: String,
    span: Span,
    line_starts: &[u32],
    autofix: Option<AutofixPatch>,
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name,
        message,
        loc: loc_from_line_starts(line_starts, span.start),
        span: ByteSpan {
            start: span.start,
            end: span.end,
        },
        autofix,
    });
}

fn prop_key_str<'a>(key: &'a oxc_ast::ast::PropertyKey<'a>) -> Option<&'a str> {
    match key {
        oxc_ast::ast::PropertyKey::StaticIdentifier(id) => Some(id.name.as_str()),
        oxc_ast::ast::PropertyKey::StringLiteral(s) => s.value.as_str(),
        _ => None,
    }
}
