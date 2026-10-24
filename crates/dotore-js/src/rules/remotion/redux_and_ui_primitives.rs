//! Redux (`redux-*`) `useSelector` memoization and UI primitive composition
//! (`radix-ui`, `base-ui`, `shadcn`, `styled-components`) single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    clippy::too_many_arguments,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, BindingPattern, CallExpression, Expression, JSXAttributeItem,
        JSXAttributeName, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;

use super::{FileImports, extract_callee_name, find_jsx_attr, get_jsx_element_name, push_site};
use crate::{
    ir::{
        ByteSpan,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::RuleId,
};

const REDUX_DERIVATION_METHODS: &[&str] = &[
    "filter",
    "map",
    "flatMap",
    "reduce",
    "reduceRight",
    "sort",
    "toSorted",
    "reverse",
    "toReversed",
    "slice",
    "concat",
];

const SHADCN_RAW_INPUT_GROUP_CONTROLS: &[&str] = &[
    "input", "textarea", "select", "button", "Input", "Textarea", "Button",
];

const STANDARD_DOM_OR_REACT_PROPS: &[&str] = &[
    "id",
    "className",
    "class",
    "style",
    "children",
    "key",
    "ref",
    "as",
    "forwardedAs",
    "theme",
    "title",
    "role",
    "tabIndex",
    "dir",
    "lang",
    "hidden",
    "draggable",
    "contentEditable",
    "spellCheck",
    "translate",
    "slot",
    "part",
    "inert",
    "popover",
    "popoverTarget",
    "popoverTargetAction",
    "type",
    "name",
    "value",
    "defaultValue",
    "checked",
    "defaultChecked",
    "disabled",
    "readOnly",
    "required",
    "multiple",
    "placeholder",
    "autoFocus",
    "autoComplete",
    "min",
    "max",
    "step",
    "pattern",
    "minLength",
    "maxLength",
    "size",
    "rows",
    "cols",
    "wrap",
    "form",
    "formAction",
    "formEncType",
    "formMethod",
    "formNoValidate",
    "formTarget",
    "href",
    "target",
    "rel",
    "download",
    "src",
    "srcSet",
    "sizes",
    "alt",
    "width",
    "height",
    "loading",
    "decoding",
    "crossOrigin",
    "referrerPolicy",
    "fetchPriority",
    "htmlFor",
    "for",
    "label",
    "open",
    " colSpan",
    "colSpan",
    "rowSpan",
    "headers",
    "scope",
    " dangerouslySetInnerHTML",
    "dangerouslySetInnerHTML",
    "suppressHydrationWarning",
    "suppressContentEditableWarning",
];

pub(crate) fn check_redux_call_expression(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(callee_name) = extract_callee_name(&call.callee) else {
        return;
    };

    // 4 & 5. `redux-useselector-inline-derivation` and `redux-useselector-returns-new-collection`
    if matches!(callee_name, "useSelector" | "useAppSelector")
        && let Some(sel_arg) = call.arguments.first().and_then(Argument::as_expression)
    {
        let has_equality_fn = call.arguments.len() >= 2;
        if !has_equality_fn && selector_returns_new_collection(sel_arg) {
            push_site(
                sites,
                RuleId::ReduxUseselectorReturnsNewCollection,
                subject_name.clone(),
                "reduxUseselectorReturnsNewCollection",
                callee_name,
                format!(
                    "`{callee_name}` returns a new object or array literal on every call; pass `shallowEqual` or select primitive fields."
                ),
                loc_from_line_starts(line_starts, sel_arg.span().start),
                ByteSpan {
                    start: sel_arg.span().start,
                    end: sel_arg.span().end,
                },
            );
        } else if selector_computes_inline_derivation(semantic, sel_arg) {
            push_site(
                sites,
                RuleId::ReduxUseselectorInlineDerivation,
                subject_name.clone(),
                "reduxUseselectorInlineDerivation",
                callee_name,
                format!(
                    "`{callee_name}` computes a derived collection inline; use `createSelector` or `useMemo` so store dispatches do not recompute and force re-renders."
                ),
                loc_from_line_starts(line_starts, sel_arg.span().start),
                ByteSpan {
                    start: sel_arg.span().start,
                    end: sel_arg.span().end,
                },
            );
        }
    }
}

fn selector_returns_new_collection(sel_arg: &Expression<'_>) -> bool {
    let ret_expr = extract_function_returned_expr(sel_arg);
    let Some(ret) = ret_expr else {
        return false;
    };
    matches!(
        ret.without_parentheses(),
        Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
    )
}

fn selector_computes_inline_derivation(semantic: &Semantic<'_>, sel_arg: &Expression<'_>) -> bool {
    let body_span = match sel_arg.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => arrow.body.span(),
        Expression::FunctionExpression(func) => {
            let Some(b) = &func.body else {
                return false;
            };
            b.span
        }
        _ => return false,
    };

    for node in semantic.nodes() {
        if !body_span.contains_inclusive(node.span()) {
            continue;
        }
        match node.kind() {
            AstKind::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                    let prop = mem.property.name.as_str();
                    if REDUX_DERIVATION_METHODS.contains(&prop) {
                        return true;
                    }
                    if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                        if obj.name == "Object"
                            && matches!(prop, "keys" | "values" | "entries" | "fromEntries")
                        {
                            return true;
                        }
                        if obj.name == "Array" && prop == "from" {
                            return true;
                        }
                    }
                }
            }
            AstKind::NewExpression(new_expr) => {
                if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                    && matches!(id.name.as_str(), "Map" | "Set")
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn extract_function_returned_expr<'a>(fn_expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    match fn_expr.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => {
            if let Some(expr) = arrow.body.as_expression() {
                return Some(expr);
            }
            if let ArrowFunctionBody::FunctionBody(body) = &arrow.body {
                for stmt in &body.statements {
                    if let Statement::ReturnStatement(ret) = stmt
                        && let Some(arg) = &ret.argument
                    {
                        return Some(arg);
                    }
                }
            }
            None
        }
        Expression::FunctionExpression(func) => {
            let body = func.body.as_ref()?;
            for stmt in &body.statements {
                if let Statement::ReturnStatement(ret) = stmt
                    && let Some(arg) = &ret.argument
                {
                    return Some(arg);
                }
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn collect_styled_intrinsic_components(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let BindingPattern::BindingIdentifier(id) = &decl.id else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if is_styled_intrinsic_initializer(semantic, init) {
            out.insert(id.name.to_string());
        }
    }
    out
}

fn is_styled_intrinsic_initializer(semantic: &Semantic<'_>, init: &Expression<'_>) -> bool {
    let text = init.span().source_text(semantic.source_text()).trim();
    if let Some(after) = text.strip_prefix("styled.") {
        return after
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase());
    }
    if let Some(after) = text.strip_prefix("styled(") {
        let trimmed = after.trim_start();
        return trimmed.starts_with('"') || trimmed.starts_with('\'');
    }
    false
}

pub(crate) fn check_ui_primitive_jsx_opening(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    subject_name: &Option<String>,
    imports: &FileImports,
    styled_intrinsics: &HashSet<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_name = get_jsx_element_name(&opening.name);
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };

    let has_tabs_list_ancestor =
        has_enclosing_jsx_tag(semantic, node_id, &["Tabs.List", "TabsList", "List"]);

    // 1. `radix-tabs-trigger-requires-list`
    let is_radix_trigger =
        tag_name == "Tabs.Trigger" || imports.radix_tabs_trigger_locals.contains(&tag_name);
    if is_radix_trigger && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::RadixTabsTriggerRequiresList,
            subject_name.clone(),
            "radixTabsTriggerRequiresList",
            &tag_name,
            format!(
                "Radix `<{tag_name}>` must be rendered inside `<Tabs.List>` so roving keyboard focus and `tablist` semantics apply."
            ),
            loc,
            span,
        );
    }

    // 2. `base-ui-tabs-tab-requires-list`
    let is_base_ui_tab = tag_name == "Tabs.Tab" || imports.base_ui_tab_locals.contains(&tag_name);
    if is_base_ui_tab && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::BaseUiTabsTabRequiresList,
            subject_name.clone(),
            "baseUiTabsTabRequiresList",
            &tag_name,
            format!(
                "Base UI `<{tag_name}>` must be rendered inside `<Tabs.List>` so the `tablist` role and arrow-key navigation cover every tab."
            ),
            loc,
            span,
        );
    }

    // 3. `shadcn-tabs-trigger-requires-list`
    let is_shadcn_trigger =
        tag_name == "TabsTrigger" && !imports.radix_tabs_trigger_locals.contains(&tag_name);
    if is_shadcn_trigger && !has_tabs_list_ancestor {
        push_site(
            sites,
            RuleId::ShadcnTabsTriggerRequiresList,
            subject_name.clone(),
            "shadcnTabsTriggerRequiresList",
            &tag_name,
            "`<TabsTrigger>` must be rendered inside `<TabsList>` so keyboard navigation and `tablist` semantics share one scope.".to_string(),
            loc,
            span,
        );
    }

    // 4. `shadcn-command-item-state-variant-requires-value`
    if matches!(tag_name.as_str(), "CommandItem" | "Command.Item")
        && let Some(class_attr) = find_jsx_attr(&opening.attributes, "className")
    {
        let attr_text = class_attr.span.source_text(semantic.source_text());
        if attr_text.contains("data-[selected]:") || attr_text.contains("data-[disabled]:") {
            push_site(
                sites,
                RuleId::ShadcnCommandItemStateVariantRequiresValue,
                subject_name.clone(),
                "shadcnCommandItemStateVariantRequiresValue",
                &tag_name,
                "`<CommandItem>` uses presence-only `data-[selected]:` or `data-[disabled]:` variant; use `data-[selected=true]:` and `data-[disabled=true]:` because cmdk sets both attributes to `\"true\"` or `\"false\"`.".to_string(),
                loc_from_line_starts(line_starts, class_attr.span.start),
                ByteSpan {
                    start: class_attr.span.start,
                    end: class_attr.span.end,
                },
            );
        }
    }

    // 5. `shadcn-input-group-no-raw-controls`
    if SHADCN_RAW_INPUT_GROUP_CONTROLS.contains(&tag_name.as_str())
        && is_direct_child_of_input_group(semantic, node_id)
    {
        push_site(
            sites,
            RuleId::ShadcnInputGroupNoRawControls,
            subject_name.clone(),
            "shadcnInputGroupNoRawControls",
            &tag_name,
            format!(
                "Raw `<{tag_name}>` inside `<InputGroup>` creates conflicting borders and focus rings; use `InputGroupInput`, `InputGroupTextarea`, or `InputGroupAddon` with `InputGroupButton`."
            ),
            loc,
            span,
        );
    }

    // 6. `styled-components-non-transient-custom-prop-on-intrinsic-element`
    if styled_intrinsics.contains(&tag_name) {
        for item in &opening.attributes {
            let JSXAttributeItem::Attribute(attr) = item else {
                continue;
            };
            let JSXAttributeName::Identifier(id) = &attr.name else {
                continue;
            };
            let prop_name = id.name.as_str();
            if !is_transient_or_standard_dom_prop(prop_name) {
                push_site(
                    sites,
                    RuleId::StyledComponentsNonTransientCustomPropOnIntrinsicElement,
                    subject_name.clone(),
                    "styledComponentsNonTransientCustomPropOnIntrinsicElement",
                    prop_name,
                    format!(
                        "Custom prop `{prop_name}` on styled intrinsic component `<{tag_name}>` is forwarded to the DOM; prefix it with `$` (`${prop_name}`) to make it transient."
                    ),
                    loc_from_line_starts(line_starts, attr.span.start),
                    ByteSpan {
                        start: attr.span.start,
                        end: attr.span.end,
                    },
                );
                break;
            }
        }
    }
}

fn has_enclosing_jsx_tag(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    allowed_tags: &[&str],
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_element_name(&el.opening_element.name);
            if allowed_tags.contains(&tag.as_str()) {
                return true;
            }
        }
    }
    false
}

fn is_direct_child_of_input_group(semantic: &Semantic<'_>, opening_node_id: NodeId) -> bool {
    // `opening_node_id` is `JSXOpeningElement`; its parent is `JSXElement`; find the next enclosing `JSXElement`
    let mut skipped_self = false;
    for anc_id in semantic.nodes().ancestor_ids(opening_node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            if !skipped_self {
                skipped_self = true;
                continue;
            }
            let parent_tag = get_jsx_element_name(&el.opening_element.name);
            return parent_tag == "InputGroup" || parent_tag.ends_with(".InputGroup");
        }
    }
    false
}

fn is_transient_or_standard_dom_prop(prop_name: &str) -> bool {
    if prop_name.starts_with('$')
        || prop_name.starts_with("data-")
        || prop_name.starts_with("aria-")
    {
        return true;
    }
    if prop_name.starts_with("on")
        && prop_name
            .as_bytes()
            .get(2)
            .is_some_and(u8::is_ascii_uppercase)
    {
        return true;
    }
    STANDARD_DOM_OR_REACT_PROPS.contains(&prop_name)
}
