//! Cross-file 60fps frame-loop call-graph IR (`FrameLoopRootIr`, `FrameHelperIr`) extraction.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; frame-loop AST traversal matches only relevant node kinds (#50)"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentOperator, BindingPattern, CallExpression, Expression, FormalParameters,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::matchers::{callee_name, collect_pattern_bound_names, span_to_loc_and_byte_span};

use super::{
    react_ast::{find_enclosing_react_node, get_subject_name},
    types::{
        FrameCallTargetIr, FrameHelperHazard, FrameHelperHazardKind, FrameHelperIr,
        FrameLoopRootIr, FrameLoopRootKind, ModuleIr,
    },
};

const SYNC_WEBGL_READBACK_METHODS: &[&str] = &[
    "checkFramebufferStatus",
    "finish",
    "getBufferSubData",
    "getError",
    "getImageData",
    "getParameter",
    "readPixels",
    "readRenderTargetPixels",
];

/// Extracts 60fps [`FrameLoopRootIr`] callback registrations (`useFrame`, `requestAnimationFrame`, `setAnimationLoop`) from `semantic`.
#[must_use]
pub(crate) fn extract_frame_loop_roots<F>(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    is_use_frame_call: F,
) -> Vec<FrameLoopRootIr>
where
    F: Fn(&CallExpression<'_>) -> bool,
{
    let mut roots = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_short = callee_name(&call.callee);
        let root_kind = if is_use_frame_call(call) {
            FrameLoopRootKind::UseFrame
        } else if matches!(
            callee_short,
            Some("requestAnimationFrame" | "setAnimationLoop")
        ) {
            FrameLoopRootKind::AnimationLoop
        } else {
            continue;
        };
        let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let cb = cb_expr.without_parentheses();
        if matches!(callee_short, Some("requestAnimationFrame"))
            && matches!(cb, Expression::Identifier(_))
            && find_enclosing_function_span(semantic, node_id)
                == Some(resolve_callback_body_span(cb, semantic))
        {
            continue;
        }
        let cb_span = resolve_callback_body_span(cb, semantic);
        if cb_span.start == cb_span.end {
            continue;
        }

        let outgoing_calls = collect_outgoing_calls_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            cb_span,
        );
        if outgoing_calls.is_empty() {
            continue;
        }
        let (loc, span) = span_to_loc_and_byte_span(line_starts, call.span);
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));
        roots.push(FrameLoopRootIr {
            kind: root_kind,
            subject_name,
            loc,
            span,
            outgoing_calls,
        });
    }

    roots
}

/// Extracts declared [`FrameHelperIr`] functions and arrow functions with their per-frame hazards and outgoing calls.
#[must_use]
pub(crate) fn extract_frame_helpers(
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    state_setters: &HashSet<String>,
) -> Vec<FrameHelperIr> {
    let mut helpers = Vec::new();

    for (_node_id, node) in semantic.nodes().iter_enumerated() {
        let Some((name, decl_span, body_span, param_names)) =
            extract_helper_declaration_info(node.kind())
        else {
            continue;
        };

        let exported_names = module
            .exports
            .iter()
            .filter(|exp| {
                exp.from_source.is_none()
                    && (exp.name == name || exp.local_name.as_deref() == Some(name.as_str()))
            })
            .map(|exp| exp.name.clone())
            .collect();

        let hazards = collect_helper_hazards_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            state_setters,
            body_span,
            &param_names,
        );
        let outgoing_calls = collect_outgoing_calls_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            body_span,
        );
        let (loc, span) = span_to_loc_and_byte_span(line_starts, decl_span);
        helpers.push(FrameHelperIr {
            name,
            exported_names,
            loc,
            span,
            hazards,
            outgoing_calls,
        });
    }

    helpers
}

fn extract_helper_declaration_info(
    kind: AstKind<'_>,
) -> Option<(String, Span, Span, HashSet<String>)> {
    match kind {
        AstKind::Function(func) => {
            let id = func.id.as_ref()?;
            let body = func.body.as_ref()?;
            Some((
                id.name.to_string(),
                func.span,
                body.span,
                collect_param_names(&func.params),
            ))
        }
        AstKind::VariableDeclarator(decl) => {
            let BindingPattern::BindingIdentifier(id) = &decl.id else {
                return None;
            };
            let init = decl.init.as_ref()?.without_parentheses();
            match init {
                Expression::ArrowFunctionExpression(arrow) => Some((
                    id.name.to_string(),
                    decl.span,
                    arrow.body.span(),
                    collect_param_names(&arrow.params),
                )),
                Expression::FunctionExpression(func) => {
                    let body = func.body.as_ref()?;
                    Some((
                        id.name.to_string(),
                        decl.span,
                        body.span,
                        collect_param_names(&func.params),
                    ))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn collect_param_names(params: &FormalParameters<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for p in &params.items {
        out.extend(collect_pattern_bound_names(&p.pattern));
    }
    out
}

fn collect_outgoing_calls_in_span(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    target_span: Span,
) -> Vec<FrameCallTargetIr> {
    let mut out = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !target_span.contains_inclusive(call.span)
            || is_conditionally_executed_within(semantic, node_id, target_span)
        {
            continue;
        }
        let (call_loc, call_span) = span_to_loc_and_byte_span(line_starts, call.span);
        match call.callee.without_parentheses() {
            Expression::Identifier(id) => {
                let callee_name = id.name.to_string();
                if matches!(
                    callee_name.as_str(),
                    "useFrame" | "requestAnimationFrame" | "cancelAnimationFrame"
                ) {
                    continue;
                }
                let (imported_name, import_source) = imported_symbols
                    .get(callee_name.as_str())
                    .map_or((None, None), |(src, orig)| {
                        (Some(orig.clone()), Some(src.clone()))
                    });
                out.push(FrameCallTargetIr {
                    callee_name,
                    imported_name,
                    import_source,
                    call_loc,
                    call_span,
                });
            }
            Expression::StaticMemberExpression(mem) => {
                if let Expression::Identifier(ns) = mem.object.without_parentheses()
                    && let Some(src) = namespace_imports.get(ns.name.as_str())
                {
                    out.push(FrameCallTargetIr {
                        callee_name: mem.property.name.to_string(),
                        imported_name: Some(mem.property.name.to_string()),
                        import_source: Some(src.clone()),
                        call_loc,
                        call_span,
                    });
                }
            }
            _ => {}
        }
    }

    out
}

fn collect_helper_hazards_in_span(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    state_setters: &HashSet<String>,
    body_span: Span,
    param_names: &HashSet<String>,
) -> Vec<FrameHelperHazard> {
    let source = semantic.source_text();
    let mut hazards = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let nspan = node.span();
        if !body_span.contains_inclusive(nspan)
            || is_conditionally_executed_within(semantic, node_id, body_span)
        {
            continue;
        }
        if let Some(kind) = classify_node_frame_hazard(
            node.kind(),
            source,
            imported_symbols,
            namespace_imports,
            state_setters,
            param_names,
        ) {
            let (loc, span) = span_to_loc_and_byte_span(line_starts, nspan);
            hazards.push(FrameHelperHazard { kind, loc, span });
        }
    }

    hazards
}

fn classify_node_frame_hazard(
    kind: AstKind<'_>,
    source: &str,
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    state_setters: &HashSet<String>,
    param_names: &HashSet<String>,
) -> Option<FrameHelperHazardKind> {
    match kind {
        AstKind::NewExpression(new_expr) => {
            let ctor =
                resolve_callee_ctor_name(&new_expr.callee, imported_symbols, namespace_imports)?;
            Some(FrameHelperHazardKind::NewAllocation(ctor))
        }
        AstKind::ArrayExpression(_) => Some(FrameHelperHazardKind::ArrayAllocation),
        AstKind::ObjectExpression(_) => Some(FrameHelperHazardKind::ObjectAllocation),
        AstKind::CallExpression(call) => {
            classify_call_frame_hazard(call, source, state_setters, param_names)
        }
        _ => None,
    }
}

fn classify_call_frame_hazard(
    call: &CallExpression<'_>,
    source: &str,
    state_setters: &HashSet<String>,
    param_names: &HashSet<String>,
) -> Option<FrameHelperHazardKind> {
    let callee_short = callee_name(&call.callee)?;
    if callee_short == "clone" {
        let recv = match call.callee.without_parentheses() {
            Expression::StaticMemberExpression(m) => {
                m.object.span().source_text(source).to_string()
            }
            _ => "object".to_string(),
        };
        return Some(FrameHelperHazardKind::CloneAllocation(recv));
    }
    if SYNC_WEBGL_READBACK_METHODS.contains(&callee_short) {
        return Some(FrameHelperHazardKind::SyncReadback(
            callee_short.to_string(),
        ));
    }
    if is_state_setter_name(callee_short, state_setters, param_names) {
        return Some(FrameHelperHazardKind::StateUpdate(callee_short.to_string()));
    }
    None
}

fn is_state_setter_name(
    name: &str,
    state_setters: &HashSet<String>,
    param_names: &HashSet<String>,
) -> bool {
    state_setters.contains(name)
        || name == "setState"
        || (name.starts_with("set")
            && name.as_bytes().get(3).is_some_and(u8::is_ascii_uppercase)
            && param_names.contains(name))
}

/// Resolves the body [`Span`] of a callback expression (`ArrowFunctionExpression`, `FunctionExpression`, identifier reference, or `useCallback`).
#[must_use]
pub(crate) fn resolve_callback_body_span(cb: &Expression<'_>, semantic: &Semantic<'_>) -> Span {
    match cb.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => arrow.body.span(),
        Expression::FunctionExpression(func) => func.body.as_ref().map_or(func.span, |b| b.span),
        Expression::Identifier(id) => {
            if let Some(ref_id) = id.reference_id.get()
                && let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id()
            {
                let decl_id = semantic.scoping().symbol_declaration(sym_id);
                match semantic.nodes().kind(decl_id) {
                    AstKind::Function(func) => {
                        return func.body.as_ref().map_or(func.span, |b| b.span);
                    }
                    AstKind::VariableDeclarator(decl) => {
                        if let Some(init) = decl.init.as_ref() {
                            return resolve_callback_body_span(init, semantic);
                        }
                    }
                    _ => {}
                }
            }
            cb.span()
        }
        Expression::CallExpression(call) if callee_name(&call.callee) == Some("useCallback") => {
            if let Some(first) = call.arguments.first().and_then(Argument::as_expression) {
                resolve_callback_body_span(first, semantic)
            } else {
                call.span
            }
        }
        _ => cb.span(),
    }
}

/// Finds the body [`Span`] of the nearest enclosing `Function` or `ArrowFunctionExpression`.
#[must_use]
pub(crate) fn find_enclosing_function_span(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<Span> {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => return func.body.as_ref().map(|b| b.span),
            AstKind::ArrowFunctionExpression(arrow) => return Some(arrow.body.span()),
            _ => {}
        }
    }
    None
}

/// Returns `true` if `node_id` is nested inside a conditional branch (`if`, `?:`, `&&`, `||`, `??`, `switch`, `catch`) within `boundary_span`.
#[must_use]
pub(crate) fn is_conditionally_executed_within(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    boundary_span: Span,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_node = semantic.nodes().get_node(anc_id);
        if !boundary_span.contains_inclusive(anc_node.span()) {
            break;
        }
        match anc_node.kind() {
            AstKind::IfStatement(_)
            | AstKind::ConditionalExpression(_)
            | AstKind::LogicalExpression(_)
            | AstKind::SwitchCase(_)
            | AstKind::CatchClause(_) => return true,
            AstKind::AssignmentExpression(assign)
                if matches!(
                    assign.operator,
                    AssignmentOperator::LogicalNullish
                        | AssignmentOperator::LogicalOr
                        | AssignmentOperator::LogicalAnd
                ) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Resolves the constructor identifier or `THREE.<Ctor>` property name for a `new` expression callee.
#[must_use]
pub(crate) fn resolve_callee_ctor_name(
    callee: &Expression<'_>,
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
) -> Option<String> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => {
            if let Some((_src, orig)) = imported_symbols.get(id.name.as_str()) {
                Some(orig.clone())
            } else {
                Some(id.name.to_string())
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(ns) = mem.object.without_parentheses()
                && (ns.name == "THREE" || namespace_imports.contains_key(ns.name.as_str()))
            {
                return Some(mem.property.name.to_string());
            }
            Some(mem.property.name.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::{
        parse_file_ir,
        types::{FrameHelperHazardKind, FrameLoopRootKind},
    };

    #[test]
    fn extracts_frame_loop_roots_and_helper_hazards() {
        let tsx = r#"
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export function stepPhysics() {
    const v = new THREE.Vector3(1, 2, 3);
    return v.clone();
}

export function Rig() {
    useFrame(() => {
        stepPhysics();
    });
    return null;
}
"#;
        let file = parse_file_ir(Path::new("Rig.tsx"), tsx);
        assert_eq!(file.frame_loop_roots.len(), 1);
        assert_eq!(file.frame_loop_roots[0].kind, FrameLoopRootKind::UseFrame);
        assert_eq!(
            file.frame_loop_roots[0].outgoing_calls[0].callee_name,
            "stepPhysics"
        );

        let helper = file
            .frame_helpers
            .iter()
            .find(|h| h.name == "stepPhysics")
            .expect("stepPhysics helper");
        assert!(
            helper
                .hazards
                .iter()
                .any(|h| h.kind == FrameHelperHazardKind::NewAllocation("Vector3".to_string()))
        );
        assert!(
            helper
                .hazards
                .iter()
                .any(|h| matches!(h.kind, FrameHelperHazardKind::CloneAllocation(_)))
        );
    }
}
