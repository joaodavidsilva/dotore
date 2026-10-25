//! Single-pass NgRx (`ngrx-*`) and Angular Material (`angular-material-*`) rules:
//! 1. `ngrx-no-multiple-actions-in-effects`
//! 2. `ngrx-no-effect-decorator-and-creator` (with `Autofix`)
//! 3. `ngrx-no-cyclic-action-creators`
//! 4. `ngrx-no-typed-global-store` (with `Autofix`)
//! 5. `ngrx-on-function-explicit-return-type`
//! 6. `ngrx-select-style` (with `Autofix`)
//! 7. `angular-material-no-conflicting-mixins` (SCSS/inline `styles` + template directives)

#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "AST enums have many variants; NgRx and Material rules match only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, CallExpression, Class, ClassElement, Decorator, Expression,
        ObjectPropertyKind, Statement, TSTypeReference,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    ir::{ByteSpan, SemanticRuleSite, loc_from_line_starts},
    rules::{AutofixPatch, RuleId},
};

use super::{callee_ident_name, decorator_name, enclosing_subject_name, prop_key_str, push_angular_site};

const EFFECT_ACTION_OPERATORS: &[&str] = &[
    "switchMap",
    "mergeMap",
    "concatMap",
    "exhaustMap",
    "map",
    "flatMap",
];

pub(super) fn check_ngrx_class_rules(
    cls: &Class<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let class_name = cls.id.as_ref().map(|id| id.name.to_string());
    for elem in &cls.body.body {
        match elem {
            ClassElement::PropertyDefinition(prop) => {
                let prop_name = prop_key_str(&prop.key).unwrap_or("effect");
                check_effect_decorators(
                    &prop.decorators,
                    prop_name,
                    prop.span.end,
                    class_name.as_deref(),
                    source,
                    line_starts,
                    sites,
                );
            }
            ClassElement::MethodDefinition(method) => {
                let method_name = prop_key_str(&method.key).unwrap_or("effect");
                check_effect_decorators(
                    &method.decorators,
                    method_name,
                    method.span.end,
                    class_name.as_deref(),
                    source,
                    line_starts,
                    sites,
                );
            }
            ClassElement::AccessorProperty(acc) => {
                let acc_name = prop_key_str(&acc.key).unwrap_or("effect");
                check_effect_decorators(
                    &acc.decorators,
                    acc_name,
                    acc.span.end,
                    class_name.as_deref(),
                    source,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

fn check_effect_decorators(
    decorators: &[Decorator<'_>],
    member_name: &str,
    member_end: u32,
    class_name: Option<&str>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    for dec in decorators {
        if decorator_name(dec) != Some("Effect") {
            continue;
        }
        let mut del_end = dec.span.end as usize;
        let bytes = source.as_bytes();
        let limit = (member_end as usize).min(bytes.len());
        while del_end < limit && bytes.get(del_end).is_some_and(u8::is_ascii_whitespace) {
            del_end += 1;
        }
        let patch = AutofixPatch::delete(
            "Remove deprecated `@Effect()` decorator",
            ByteSpan {
                start: dec.span.start,
                end: u32::try_from(del_end).unwrap_or(dec.span.end),
            },
        );
        push_angular_site(
            sites,
            RuleId::NgrxNoEffectDecoratorAndCreator,
            class_name.map(ToOwned::to_owned),
            "ngrxNoEffectDecoratorAndCreator",
            member_name.to_string(),
            format!(
                "Avoid the deprecated `@Effect()` decorator on `{member_name}`; define effects exclusively with `createEffect(() => ...)`."
            ),
            dec.span,
            line_starts,
            Some(patch),
        );
    }
}

pub(super) fn check_ngrx_call_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let callee_name = callee_ident_name(&call.callee);
    if callee_name == Some("createEffect") {
        check_create_effect_call(semantic, node_id, call, source, line_starts, sites);
    }
    if callee_name == Some("on") {
        check_ngrx_on_reducer_call(semantic, node_id, call, source, line_starts, sites);
    }
    check_ngrx_select_style_call(semantic, node_id, call, source, line_starts, sites);
}

fn check_create_effect_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let subject_name = enclosing_subject_name(semantic, node_id);
    let is_dispatch_false = is_non_dispatching_effect(call);
    let (of_type_actions, of_type_spans) = collect_of_type_actions_in_span(semantic, call.span, source);

    for (_, inner_node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(inner_call) = inner_node.kind() else {
            continue;
        };
        if !call.span.contains_inclusive(inner_call.span) || inner_call.span == call.span {
            continue;
        }
        let Some(op_name) = callee_ident_name(&inner_call.callee) else {
            continue;
        };

        if EFFECT_ACTION_OPERATORS.contains(&op_name)
            && let Some(multi_span) = find_multiple_actions_return_span(inner_call)
        {
            push_angular_site(
                sites,
                RuleId::NgrxNoMultipleActionsInEffects,
                subject_name.clone(),
                "ngrxNoMultipleActionsInEffects",
                op_name.to_string(),
                format!(
                    "`createEffect` operator `{op_name}` dispatches multiple actions at once; emit a single event action and let reducers or downstream effects handle fan-out."
                ),
                multi_span,
                line_starts,
                None,
            );
        }

        if !is_dispatch_false
            && !of_type_actions.is_empty()
            && !of_type_spans.iter().any(|sp| sp.contains_inclusive(inner_call.span))
            && let Some(called_action) = normalize_action_expr(&inner_call.callee, source)
            && of_type_actions.contains(&called_action)
        {
            push_angular_site(
                sites,
                RuleId::NgrxNoCyclicActionCreators,
                subject_name.clone(),
                "ngrxNoCyclicActionCreators",
                called_action.clone(),
                format!(
                    "`createEffect` listens for `ofType({called_action})` and re-dispatches `{called_action}()`, causing an infinite action loop."
                ),
                inner_call.span,
                line_starts,
                None,
            );
        }
    }
}

fn is_non_dispatching_effect(call: &CallExpression<'_>) -> bool {
    let Some(Argument::ObjectExpression(obj)) = call.arguments.get(1) else {
        return false;
    };
    obj.properties.iter().any(|prop_kind| {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
            && prop_key_str(&prop.key) == Some("dispatch")
            && let Expression::BooleanLiteral(b) = prop.value.without_parentheses()
        {
            !b.value
        } else {
            false
        }
    })
}

fn collect_of_type_actions_in_span(
    semantic: &Semantic<'_>,
    effect_span: Span,
    source: &str,
) -> (HashSet<String>, Vec<Span>) {
    let mut actions = HashSet::new();
    let mut spans = Vec::new();
    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !effect_span.contains_inclusive(call.span) {
            continue;
        }
        if callee_ident_name(&call.callee) != Some("ofType") {
            continue;
        }
        spans.push(call.span);
        for arg in &call.arguments {
            let Some(expr) = arg.as_expression() else {
                continue;
            };
            if let Some(norm) = normalize_action_expr(expr, source) {
                actions.insert(norm);
            }
        }
    }
    (actions, spans)
}

fn normalize_action_expr(expr: &Expression<'_>, source: &str) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(mem) => {
            let raw = mem.span.source_text(source).trim();
            let stripped = raw.strip_suffix(".type").unwrap_or(raw);
            (!stripped.is_empty()).then(|| stripped.to_string())
        }
        _ => None,
    }
}

fn find_multiple_actions_return_span(op_call: &CallExpression<'_>) -> Option<Span> {
    let first_arg = op_call.arguments.first()?.as_expression()?.without_parentheses();
    match first_arg {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                expr_is_multiple_actions(expr)
            } else if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                find_multiple_actions_in_statements(&body.statements)
            } else {
                None
            }
        }
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            find_multiple_actions_in_statements(&body.statements)
        }
        _ => None,
    }
}

fn find_multiple_actions_in_statements(stmts: &[Statement<'_>]) -> Option<Span> {
    for stmt in stmts {
        if let Statement::ReturnStatement(ret) = stmt
            && let Some(arg) = &ret.argument
            && let Some(sp) = expr_is_multiple_actions(arg)
        {
            return Some(sp);
        }
    }
    None
}

fn expr_is_multiple_actions(expr: &Expression<'_>) -> Option<Span> {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) if arr.elements.len() >= 2 => Some(arr.span),
        Expression::CallExpression(call) => {
            let name = callee_ident_name(&call.callee)?;
            if name == "of" && call.arguments.len() >= 2 {
                return Some(call.span);
            }
            if name == "from"
                && let Some(Argument::ArrayExpression(arr)) = call.arguments.first()
                && arr.elements.len() >= 2
            {
                return Some(call.span);
            }
            None
        }
        _ => None,
    }
}

fn check_ngrx_on_reducer_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !matches!(call.callee.without_parentheses(), Expression::Identifier(id) if id.name == "on") {
        return;
    }
    if call.arguments.len() < 2 {
        return;
    }
    if matches!(call.arguments.first(), Some(Argument::StringLiteral(_))) {
        return;
    }
    let in_reducer = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
        if let AstKind::CallExpression(anc_call) = semantic.nodes().kind(anc_id) {
            matches!(
                callee_ident_name(&anc_call.callee),
                Some("createReducer" | "createFeature")
            )
        } else {
            false
        }
    });
    if !in_reducer && !source.contains("@ngrx/") {
        return;
    }
    let Some(last_expr) = call.arguments.last().and_then(Argument::as_expression) else {
        return;
    };
    let missing_return_type_span = match last_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) if arrow.return_type.is_none() => {
            Some(arrow.span)
        }
        Expression::FunctionExpression(func) if func.return_type.is_none() => Some(func.span),
        _ => None,
    };
    if let Some(fn_span) = missing_return_type_span {
        let subj = enclosing_subject_name(semantic, node_id);
        push_angular_site(
            sites,
            RuleId::NgrxOnFunctionExplicitReturnType,
            subj,
            "ngrxOnFunctionExplicitReturnType",
            "on".to_string(),
            "NgRx `on(...)` reducer handler should declare an explicit return type annotation `(state, action): State => ...`.".to_string(),
            fn_span,
            line_starts,
            None,
        );
    }
}

fn check_ngrx_select_style_call(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return;
    };
    let prop_name = mem.property.name.as_str();
    let subj = enclosing_subject_name(semantic, node_id);

    if prop_name == "pipe" {
        for arg in &call.arguments {
            let Some(Expression::CallExpression(sel_call)) =
                arg.as_expression().map(Expression::without_parentheses)
            else {
                continue;
            };
            if callee_ident_name(&sel_call.callee) != Some("select") {
                continue;
            }
            let patch = if call.arguments.len() == 1
                && let Some(first_sel_arg) = sel_call.arguments.first()
            {
                let sel_arg_sp = first_sel_arg.span();
                source
                    .get(sel_arg_sp.start as usize..sel_arg_sp.end as usize)
                    .map(|sel_arg_text| {
                        AutofixPatch::replace(
                            "Replace `.pipe(select(...))` with `.select(...)`",
                            ByteSpan {
                                start: mem.property.span.start,
                                end: call.span.end,
                            },
                            format!("select({sel_arg_text})"),
                        )
                    })
            } else {
                None
            };
            push_angular_site(
                sites,
                RuleId::NgrxSelectStyle,
                subj,
                "ngrxSelectStyle",
                "select".to_string(),
                "Prefer `store.select(selector)` or `store.selectSignal(selector)` over `store.pipe(select(selector))`.".to_string(),
                sel_call.span,
                line_starts,
                patch,
            );
            return;
        }
    } else if prop_name == "select"
        && is_store_receiver(&mem.object)
        && matches!(
            call.arguments.first(),
            Some(Argument::StringLiteral(_) | Argument::TemplateLiteral(_))
        )
    {
        push_angular_site(
            sites,
            RuleId::NgrxSelectStyle,
            subj,
            "ngrxSelectStyle",
            "select".to_string(),
            "Avoid string-key `store.select('...')`; pass a typed selector function to `store.select(selectFeature)` or `store.selectSignal(selectFeature)`.".to_string(),
            call.span,
            line_starts,
            None,
        );
    }
}

fn is_store_receiver(expr: &Expression<'_>) -> bool {
    let name = match expr.without_parentheses() {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(mem) => mem.property.name.as_str(),
        _ => return false,
    };
    let lower = name.to_ascii_lowercase();
    lower.contains("store")
}

pub(super) fn check_ngrx_type_reference(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    type_ref: &TSTypeReference<'_>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(type_args) = &type_ref.type_arguments else {
        return;
    };
    if type_args.params.is_empty() {
        return;
    }
    let raw_name = type_ref.type_name.span().source_text(source).trim();
    if raw_name != "Store" && !raw_name.ends_with(".Store") {
        return;
    }
    if !source.contains("@ngrx/") && !source.contains("@angular/") {
        return;
    }
    let subj = enclosing_subject_name(semantic, node_id);
    let patch = AutofixPatch::delete(
        "Remove generic type argument from `Store`",
        ByteSpan {
            start: type_args.span.start,
            end: type_args.span.end,
        },
    );
    push_angular_site(
        sites,
        RuleId::NgrxNoTypedGlobalStore,
        subj,
        "ngrxNoTypedGlobalStore",
        "Store".to_string(),
        "Avoid typing the global `Store<T>`; inject untyped `Store` and let typed selectors infer state.".to_string(),
        type_ref.span,
        line_starts,
        Some(patch),
    );
}

struct MaterialMixinTracker {
    has_all_themes: bool,
    has_all_colors: bool,
    has_all_typographies: bool,
    has_all_densities: bool,
    seen_mat_core: bool,
    seen_mixins: HashSet<String>,
}

impl MaterialMixinTracker {
    fn new(style_source: &str) -> Self {
        Self {
            has_all_themes: style_source.contains("all-component-themes(")
                || style_source.contains("angular-material-theme("),
            has_all_colors: style_source.contains("all-component-colors(")
                || style_source.contains("angular-material-color("),
            has_all_typographies: style_source.contains("all-component-typographies(")
                || style_source.contains("angular-material-typography("),
            has_all_densities: style_source.contains("all-component-densities(")
                || style_source.contains("angular-material-density("),
            seen_mat_core: false,
            seen_mixins: HashSet::new(),
        }
    }

    fn is_conflicting_mixin(&mut self, short_mixin: &str) -> bool {
        if short_mixin == "core" {
            let dup = self.seen_mat_core;
            self.seen_mat_core = true;
            return dup;
        }
        if short_mixin.starts_with("all-component-") || short_mixin.starts_with("angular-material-")
        {
            return false;
        }
        let conflicts_with_all = (self.has_all_themes && short_mixin.ends_with("-theme"))
            || (self.has_all_colors && short_mixin.ends_with("-color"))
            || (self.has_all_typographies && short_mixin.ends_with("-typography"))
            || (self.has_all_densities && short_mixin.ends_with("-density"));
        let is_tracked_suffix = ["-theme", "-color", "-typography", "-density"]
            .iter()
            .any(|s| short_mixin.ends_with(s));
        let is_dup_mixin = is_tracked_suffix && !self.seen_mixins.insert(short_mixin.to_string());
        conflicts_with_all || is_dup_mixin
    }
}

/// Scans an Angular stylesheet (`.scss`, `.css`, or `@Component({ styles: [...] })`)
/// for conflicting Angular Material theme/color/typography/density mixins.
pub(crate) fn extract_angular_stylesheet_sites(
    style_source: &str,
    base_byte_offset: u32,
    subject_name: Option<&str>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut tracker = MaterialMixinTracker::new(style_source);
    let mut cursor = 0usize;

    for line in style_source.split('\n') {
        if let Some((mixin_call, short_mixin)) = parse_material_include_line(line)
            && tracker.is_conflicting_mixin(short_mixin)
        {
            let rel_offset = line.find("@include").unwrap_or(0);
            let start = base_byte_offset + u32::try_from(cursor + rel_offset).unwrap_or(0);
            let end =
                base_byte_offset + u32::try_from(cursor + line.trim_end().len()).unwrap_or(start);
            sites.push(SemanticRuleSite {
                rule: RuleId::AngularMaterialNoConflictingMixins,
                subject_name: subject_name.map(ToOwned::to_owned),
                message_id: "angularMaterialNoConflictingMixins",
                target_name: mixin_call.to_string(),
                message: format!(
                    "Conflicting Angular Material mixin `@include {mixin_call}(...)`; `all-component-*` already emits styles for every component."
                ),
                loc: loc_from_line_starts(line_starts, start),
                span: ByteSpan { start, end },
                autofix: None,
            });
        }
        cursor += line.len() + 1;
    }
}

fn parse_material_include_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    let inc_pos = trimmed.find("@include")?;
    let after_inc = trimmed[inc_pos + "@include".len()..].trim();
    let mixin_call = after_inc
        .split('(')
        .next()
        .unwrap_or(after_inc)
        .trim()
        .trim_end_matches(';');
    let short_mixin = mixin_call
        .strip_prefix("mat.")
        .or_else(|| mixin_call.strip_prefix("mat-"))?;
    Some((mixin_call, short_mixin))
}
