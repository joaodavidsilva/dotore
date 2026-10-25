//! Single-pass Angular rules (`angular-*`) covering Angular Signals, RxJS teardown,
//! `ChangeDetectionStrategy.OnPush` (with `Autofix`), `@for (...; track)` templates,
//! constructor purity, nested `.subscribe()`, `ElementRef.nativeElement` DOM mutations,
//! lifecycle contracts, decorator metadata, and modern Angular architecture rules.

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; Angular rules match only relevant AST node kinds"
)]

pub(crate) mod metadata_and_arch;
pub(crate) mod rxjs_and_dom;
pub(crate) mod signals_and_lifecycle;

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{Argument, Class, Decorator, Expression, ObjectExpression, ObjectPropertyKind, UnaryOperator},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};
use crate::{
    ir::{ByteSpan, SemanticRuleSite, SubjectIr, SubjectKind, loc_from_line_starts},
    rules::{AutofixPatch, RuleId},
};

use metadata_and_arch::{check_class_metadata_and_architecture_rules, check_forward_ref_call};
use rxjs_and_dom::{
    check_angular_class_decorators_and_constructor, check_native_element_assignment_mutation,
    check_native_element_call_mutation, check_signal_write_in_effect,
    check_subscribe_teardown_and_nesting, collect_class_teardown_identifiers,
    collect_native_element_aliases, expr_targets_native_element, is_angular_effect_call,
    is_subscribe_call,
};
use signals_and_lifecycle::{
    KnownSignalsIndex, check_class_signals_and_lifecycle_rules, check_direct_lifecycle_call,
    check_uncalled_signal_reference, collect_known_signals,
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

/// Extracts Angular `@Component`, `@Directive`, `@Injectable`, `@Pipe`, and `@NgModule` classes as [`SubjectIr`]s
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

/// Extracts all `angular-*` rule findings in a single pass over the `oxc` AST and semantic model.
pub(crate) fn extract_angular_sites(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let class_teardowns = collect_class_teardown_identifiers(semantic);
    let native_element_vars = collect_native_element_aliases(semantic);
    let known_signals: KnownSignalsIndex = collect_known_signals(semantic, source);

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
                check_class_signals_and_lifecycle_rules(cls, source, line_starts, sites);
                check_class_metadata_and_architecture_rules(cls, source, line_starts, sites);
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
                check_direct_lifecycle_call(semantic, node_id, call, line_starts, sites);
                check_forward_ref_call(semantic, node_id, call, line_starts, sites);
            }
            AstKind::StaticMemberExpression(_) | AstKind::IdentifierReference(_) => {
                check_uncalled_signal_reference(
                    semantic,
                    node_id,
                    &known_signals,
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

pub(crate) fn angular_class_decorator_kind(cls: &Class<'_>) -> Option<&'static str> {
    for dec in &cls.decorators {
        match decorator_name(dec) {
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

pub(crate) fn decorator_name<'a>(dec: &'a Decorator<'a>) -> Option<&'a str> {
    match dec.expression.without_parentheses() {
        Expression::CallExpression(call) => callee_ident_name(&call.callee),
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

pub(crate) fn callee_ident_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

pub(crate) fn extract_signal_receiver_name(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.to_string()),
        _ => None,
    }
}

pub(crate) fn enclosing_subject_name(semantic: &Semantic<'_>, node_id: NodeId) -> Option<String> {
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
pub(crate) fn push_angular_site(
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

pub(crate) fn prop_key_str<'a>(key: &'a oxc_ast::ast::PropertyKey<'a>) -> Option<&'a str> {
    match key {
        oxc_ast::ast::PropertyKey::StaticIdentifier(id) => Some(id.name.as_str()),
        oxc_ast::ast::PropertyKey::StringLiteral(s) => s.value.as_str(),
        _ => None,
    }
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

pub(crate) fn check_component_decorator_metadata(
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

pub(crate) fn extract_template_text_and_offset<'a>(
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
