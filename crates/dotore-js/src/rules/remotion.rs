//! Motion / Framer Motion, Remotion, TanStack Form/Table/Virtual, Redux,
//! and UI primitive composition (`radix-ui`, `base-ui`, `shadcn`, `styled-components`)
//! single-pass rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    clippy::too_many_arguments,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

pub(crate) mod motion;
pub(crate) mod redux_and_ui_primitives;
pub(crate) mod remotion_video;
pub(crate) mod tanstack_form_table_virtual;

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, BindingPattern, CallExpression, Expression,
        ImportDeclarationSpecifier, JSXAttributeItem, JSXAttributeValue, JSXElementName,
        ObjectExpression, ObjectPropertyKind, Program, PropertyKey, Statement, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::{
    ir::{
        ByteSpan,
        react_ast::{is_component_name, is_custom_hook_name},
        types::{SemanticRuleSite, SourceLoc},
    },
    matchers::{
        callee_name, find_jsx_attr as matcher_find_jsx_attr, imported_local_names_from,
        is_named_hook_call, jsx_element_tag_name,
    },
    rules::RuleId,
};

use self::{
    motion::{check_motion_call_expression, check_motion_jsx_element, check_motion_jsx_opening},
    redux_and_ui_primitives::{
        check_redux_call_expression, check_ui_primitive_jsx_opening,
        collect_styled_intrinsic_components,
    },
    remotion_video::{check_remotion_call_expression, check_remotion_jsx_opening},
    tanstack_form_table_virtual::{
        check_tanstack_jsx_opening, check_tanstack_table_call_expression,
    },
};

/// Extracts all Motion, Remotion, TanStack Form/Table/Virtual, Redux, and UI primitive
/// composition rule sites in a single pass.
pub(crate) fn extract_remotion_and_ecosystem_sites(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let imports = collect_file_imports(program, semantic);
    let animate_bindings = collect_use_animate_bindings(semantic);
    let const_arrays = collect_const_array_lengths(semantic);
    let styled_intrinsics = collect_styled_intrinsic_components(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let (subj_id, subject_name) = find_enclosing_subject(semantic, node_id);

        match node.kind() {
            AstKind::JSXElement(jsx_el) => {
                check_motion_jsx_element(
                    semantic,
                    node_id,
                    jsx_el,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_motion_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_remotion_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_tanstack_jsx_opening(semantic, opening, &subject_name, line_starts, sites);
                check_ui_primitive_jsx_opening(
                    semantic,
                    node_id,
                    opening,
                    &subject_name,
                    &imports,
                    &styled_intrinsics,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_motion_call_expression(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subject_name,
                    &imports,
                    &animate_bindings,
                    &const_arrays,
                    line_starts,
                    sites,
                );
                check_remotion_call_expression(
                    semantic,
                    node_id,
                    call,
                    subj_id,
                    &subject_name,
                    &imports,
                    line_starts,
                    sites,
                );
                check_tanstack_table_call_expression(
                    semantic,
                    call,
                    subj_id,
                    &subject_name,
                    line_starts,
                    sites,
                );
                check_redux_call_expression(semantic, call, &subject_name, line_starts, sites);
            }
            _ => {}
        }
    }
}

#[derive(Default)]
pub(crate) struct FileImports {
    pub(crate) animate_presence_locals: HashSet<String>,
    pub(crate) motion_factory_locals: HashSet<String>,
    pub(crate) motion_animate_locals: HashSet<String>,
    pub(crate) use_transform_locals: HashSet<String>,
    pub(crate) next_image_locals: HashSet<String>,
    pub(crate) delay_render_locals: HashSet<String>,
    pub(crate) radix_tabs_trigger_locals: HashSet<String>,
    pub(crate) base_ui_tab_locals: HashSet<String>,
}

fn is_motion_module(src: &str) -> bool {
    matches!(
        src,
        "framer-motion" | "motion" | "motion/react" | "motion/react-client" | "motion/react-m"
    ) || src.starts_with("framer-motion/")
        || src.starts_with("motion/")
}

fn collect_file_imports(program: &Program<'_>, _semantic: &Semantic<'_>) -> FileImports {
    let mut out = FileImports {
        next_image_locals: imported_local_names_from(program, &["next/image", "next/legacy/image"]),
        ..Default::default()
    };
    out.animate_presence_locals
        .insert("AnimatePresence".to_string());
    out.motion_factory_locals.insert("motion".to_string());
    out.motion_factory_locals.insert("m".to_string());
    out.use_transform_locals.insert("useTransform".to_string());
    out.delay_render_locals.insert("delayRender".to_string());

    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        let Some(src) = imp.source.value.as_str() else {
            continue;
        };
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            if let ImportDeclarationSpecifier::ImportSpecifier(s) = spec {
                let imported = s.imported.name().as_str();
                let local = s.local.name.as_str();
                if is_motion_module(src) {
                    match imported {
                        "AnimatePresence" => {
                            out.animate_presence_locals.insert(local.to_string());
                        }
                        "motion" | "m" => {
                            out.motion_factory_locals.insert(local.to_string());
                        }
                        "animate" => {
                            out.motion_animate_locals.insert(local.to_string());
                        }
                        "useTransform" => {
                            out.use_transform_locals.insert(local.to_string());
                        }
                        _ => {}
                    }
                }
            }
            match spec {
                ImportDeclarationSpecifier::ImportDefaultSpecifier(def) => {
                    if matches!(src, "next/image" | "next/legacy/image") {
                        out.next_image_locals.insert(def.local.name.to_string());
                    }
                }
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    let imported = s.imported.name().as_str();
                    let local = s.local.name.as_str();
                    if matches!(src, "next/image" | "next/legacy/image") {
                        out.next_image_locals.insert(local.to_string());
                    } else if src == "remotion" || src.starts_with("@remotion/") {
                        if imported == "delayRender" {
                            out.delay_render_locals.insert(local.to_string());
                        }
                    } else if src == "radix-ui" || src.starts_with("@radix-ui/") {
                        if matches!(imported, "Trigger" | "TabsTrigger") {
                            out.radix_tabs_trigger_locals.insert(local.to_string());
                        } else if imported == "Tabs" {
                            out.radix_tabs_trigger_locals
                                .insert(format!("{local}.Trigger"));
                        }
                    } else if src.starts_with("@base-ui") {
                        if imported == "Tab" {
                            out.base_ui_tab_locals.insert(local.to_string());
                        } else if imported == "Tabs" {
                            out.base_ui_tab_locals.insert(format!("{local}.Tab"));
                        }
                    }
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                    if src == "radix-ui" || src.starts_with("@radix-ui/") {
                        out.radix_tabs_trigger_locals
                            .insert(format!("{}.Trigger", ns.local.name));
                    } else if src.starts_with("@base-ui") {
                        out.base_ui_tab_locals
                            .insert(format!("{}.Tab", ns.local.name));
                    }
                }
            }
        }
    }
    out
}

fn collect_use_animate_bindings(semantic: &Semantic<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        let Expression::CallExpression(call) = init.without_parentheses() else {
            continue;
        };
        if is_named_hook_call(call, "useAnimate")
            && let BindingPattern::ArrayPattern(arr) = &decl.id
            && let Some(Some(BindingPattern::BindingIdentifier(second))) = arr.elements.get(1)
        {
            out.insert(second.name.to_string());
        }
        if matches!(
            extract_callee_name(&call.callee),
            Some("useAnimation" | "useAnimationControls")
        ) && let BindingPattern::BindingIdentifier(ident) = &decl.id
        {
            out.insert(ident.name.to_string());
        }
    }
    out
}

fn collect_const_array_lengths(semantic: &Semantic<'_>) -> HashMap<SymbolId, usize> {
    let mut out = HashMap::new();
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let BindingPattern::BindingIdentifier(id) = &decl.id else {
            continue;
        };
        let Some(sym_id) = id.symbol_id.get() else {
            continue;
        };
        let Some(init) = &decl.init else {
            continue;
        };
        if let Expression::ArrayExpression(arr) = init.without_parentheses()
            && !arr.elements.iter().any(ArrayExpressionElement::is_spread)
        {
            out.insert(sym_id, arr.elements.len());
        }
    }
    out
}

fn find_enclosing_subject(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> (Option<NodeId>, Option<String>) {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let Some(name) = subject_name(semantic, anc_id) {
            return (Some(anc_id), Some(name));
        }
    }
    (None, None)
}

fn subject_name(semantic: &Semantic<'_>, node_id: NodeId) -> Option<String> {
    match semantic.nodes().kind(node_id) {
        AstKind::Function(func) => {
            if let Some(id) = &func.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            let parent_id = semantic.nodes().parent_id(node_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            None
        }
        AstKind::ArrowFunctionExpression(_) => {
            let parent_id = semantic.nodes().parent_id(node_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(parent_id)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && (is_component_name(&id.name) || is_custom_hook_name(&id.name))
            {
                return Some(id.name.to_string());
            }
            None
        }
        _ => None,
    }
}

pub(crate) fn is_in_direct_render_body(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    subj_id: NodeId,
) -> bool {
    !semantic
        .nodes()
        .ancestor_ids(node_id)
        .take_while(|&anc_id| anc_id != subj_id)
        .any(|anc_id| {
            matches!(
                semantic.nodes().kind(anc_id),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
}

pub(crate) fn is_iteration_call(call: &CallExpression<'_>) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    matches!(mem.property.name.as_str(), "map" | "flatMap" | "forEach")
}

pub(crate) fn extract_callee_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    callee_name(callee)
}

pub(crate) fn get_jsx_element_name(name: &JSXElementName<'_>) -> String {
    jsx_element_tag_name(name)
}

pub(crate) fn find_jsx_attr<'a>(
    attrs: &'a [JSXAttributeItem<'a>],
    target: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    matcher_find_jsx_attr(attrs, target)
}

pub(crate) fn has_jsx_truthy_attr(attrs: &[JSXAttributeItem<'_>], target: &str) -> bool {
    let Some(attr) = find_jsx_attr(attrs, target) else {
        return false;
    };
    match &attr.value {
        None => true,
        Some(JSXAttributeValue::ExpressionContainer(cont)) => {
            if let Some(Expression::BooleanLiteral(b)) = cont
                .expression
                .as_expression()
                .map(Expression::without_parentheses)
            {
                b.value
            } else {
                true
            }
        }
        Some(_) => true,
    }
}

pub(crate) fn extract_attr_string_value<'a>(val: &'a JSXAttributeValue<'a>) -> Option<&'a str> {
    match val {
        JSXAttributeValue::StringLiteral(s) => s.value.as_str(),
        JSXAttributeValue::ExpressionContainer(cont) => {
            if let Some(Expression::StringLiteral(s)) = cont
                .expression
                .as_expression()
                .map(Expression::without_parentheses)
            {
                s.value.as_str()
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn extract_jsx_class_name_str(attrs: &[JSXAttributeItem<'_>]) -> Option<String> {
    let attr = find_jsx_attr(attrs, "className").or_else(|| find_jsx_attr(attrs, "class"))?;
    let val = attr.value.as_ref()?;
    extract_attr_string_value(val).map(ToString::to_string)
}

pub(crate) fn extract_jsx_style_string_prop(
    attrs: &[JSXAttributeItem<'_>],
    prop_name: &str,
) -> Option<String> {
    let attr = find_jsx_attr(attrs, "style")?;
    let Some(JSXAttributeValue::ExpressionContainer(cont)) = &attr.value else {
        return None;
    };
    let Expression::ObjectExpression(obj) = cont.expression.as_expression()?.without_parentheses()
    else {
        return None;
    };
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(prop_name)
            && let Expression::StringLiteral(s) = p.value.without_parentheses()
            && let Some(v) = s.value.as_str()
        {
            return Some(v.to_string());
        }
    }
    None
}

pub(crate) fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => s.value.as_str().map(str::to_string),
        _ => None,
    }
}

pub(crate) fn has_object_prop(obj: &ObjectExpression<'_>, name: &str) -> bool {
    obj.properties.iter().any(|prop| {
        if let ObjectPropertyKind::ObjectProperty(p) = prop {
            property_key_name(&p.key).as_deref() == Some(name)
        } else {
            false
        }
    })
}

pub(crate) fn extract_object_number_prop(obj: &ObjectExpression<'_>, name: &str) -> Option<f64> {
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(name) {
            return extract_numeric_literal(&p.value);
        }
    }
    None
}

fn extract_numeric_literal(expr: &Expression<'_>) -> Option<f64> {
    match expr.without_parentheses() {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            extract_numeric_literal(&u.argument).map(|v| -v)
        }
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryPlus => {
            extract_numeric_literal(&u.argument)
        }
        _ => None,
    }
}

pub(crate) fn extract_object_array_prop_len(
    obj: &ObjectExpression<'_>,
    name: &str,
) -> Option<usize> {
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        if property_key_name(&p.key).as_deref() == Some(name)
            && let Expression::ArrayExpression(arr) = p.value.without_parentheses()
            && !arr.elements.iter().any(ArrayExpressionElement::is_spread)
        {
            return Some(arr.elements.len());
        }
    }
    None
}

pub(crate) fn push_site(
    sites: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
) {
    sites.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix: None,
    });
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
    use crate::rules::RuleId;

    #[test]
    fn remotion_submodules_expose_motion_video_tanstack_and_ui_primitive_detectors() {
        let _ = (
            super::motion::check_motion_jsx_element as fn(_, _, _, _, _, _, _, _),
            super::remotion_video::check_remotion_jsx_opening as fn(_, _, _, _, _, _, _, _),
            super::tanstack_form_table_virtual::check_tanstack_jsx_opening as fn(_, _, _, _, _),
            super::redux_and_ui_primitives::check_ui_primitive_jsx_opening
                as fn(_, _, _, _, _, _, _, _),
        );

        let ir = parse_file_ir(
            Path::new("src/Composition.tsx"),
            r#"
import { motion } from "framer-motion";
import { delayRender } from "remotion";
import { useSelector } from "react-redux";

const handle = delayRender();

export function Comp() {
    const items = useSelector((state: any) => ({ a: state.a }));
    return (
        <div>
            <motion.span layout />
            <video src="/clip.mp4" />
            <form onSubmit={() => form.handleSubmit()} />
            <TabsTrigger value="a">{String(Boolean(handle) || Boolean(items))}</TabsTrigger>
        </div>
    );
}
"#,
        );
        let rules: Vec<RuleId> = ir.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::MotionLayoutOnInlineElement));
        assert!(rules.contains(&RuleId::RemotionNoModuleScopeDelayRender));
        assert!(rules.contains(&RuleId::RemotionNoNativeMediaElements));
        assert!(rules.contains(&RuleId::TanstackFormOnSubmitRequiresPreventDefault));
        assert!(rules.contains(&RuleId::ReduxUseselectorReturnsNewCollection));
        assert!(rules.contains(&RuleId::ShadcnTabsTriggerRequiresList));
    }
}
