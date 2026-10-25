//! `useFrame`, `requestAnimationFrame` / `setAnimationLoop`, and `useThree` callback
//! rule detectors for R3F and Three.js.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds (#50)"
)]

use oxc_ast::{
    AstKind,
    ast::{Argument, AssignmentOperator, BindingPattern, CallExpression, Expression, FormalParameters},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    FileAnalysisCtx, SYNC_WEBGL_READBACK_METHODS, eval_static_f64, extract_callee_short,
    find_enclosing_function_span, is_conditionally_executed_within, resolve_callback_body_span,
    resolve_callee_ctor_name, webgpu::check_webgpu_use_three_gl_state,
};
use crate::{ir::types::SemanticRuleSite, rules::RuleId};

pub(crate) fn check_use_frame_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_use_frame_second_arg(ctx, node_id, call, sites);

    let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb = cb_expr.without_parentheses();
    let cb_span = resolve_callback_body_span(cb, ctx.semantic);
    let cb_text = cb_span.source_text(ctx.source);

    check_use_frame_callback_header_and_text(ctx, node_id, call, cb, cb_text, sites);

    let delta_param = extract_callback_param_name(cb, 1);
    for (inner_id, inner_node) in ctx.semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        check_use_frame_inner_node(
            ctx,
            node_id,
            inner_id,
            inner_node.kind(),
            cb_span,
            delta_param.as_deref(),
            sites,
        );
    }
}

fn check_use_frame_second_arg(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression) else {
        return;
    };
    let second_unwrapped = second_arg.without_parentheses();
    if matches!(second_unwrapped, Expression::ArrayExpression(_)) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoUseFrameDependencyArray,
            "r3fNoUseFrameDependencyArray",
            "useFrame",
            "`useFrame` does not accept a React dependency array; the second argument is render priority.".to_string(),
            second_arg.span(),
        );
    } else if let Some(priority) = eval_static_f64(second_unwrapped)
        && priority > 0.0
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && !first_arg.span().source_text(ctx.source).contains(".render(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireRenderWithPositivePriority,
            "r3fRequireRenderWithPositivePriority",
            "useFrame",
            "Positive `useFrame` priority disables R3F automatic rendering; call `gl.render(scene, camera)` or `composer.render()` inside the callback.".to_string(),
            call.span,
        );
    }
}

fn check_use_frame_callback_header_and_text(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    cb: &Expression<'_>,
    cb_text: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if is_async_callback_expr(cb) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoAsyncUseFrame,
            "r3fNoAsyncUseFrame",
            "useFrame",
            "`useFrame` callbacks must be synchronous; async callbacks return an ignored Promise and overlap across frames.".to_string(),
            cb.span(),
        );
    }
    if cb_text.contains("clock.getDelta(") || cb_text.contains("clock.getElapsedTime(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoAdvancingClockInUseFrame,
            "r3fNoAdvancingClockInUseFrame",
            "clock",
            "Calling `clock.getDelta()` or `clock.getElapsedTime()` inside `useFrame` advances the shared clock; use the `delta` parameter or `clock.elapsedTime`.".to_string(),
            call.span,
        );
    }
    if cb_text.contains(".compile(") || cb_text.contains(".compileAsync(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoCompileInUseFrame,
            "r3fNoCompileInUseFrame",
            "compile",
            "Precompile shaders outside `useFrame` instead of calling `.compile()` every frame."
                .to_string(),
            call.span,
        );
    }
    if cb_text.contains(".setRenderTarget(") && !cb_text.contains(".setRenderTarget(null)") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireRenderTargetReset,
            "r3fRequireRenderTargetReset",
            "setRenderTarget",
            "Reset the offscreen render target via `gl.setRenderTarget(null)` before the end of `useFrame`.".to_string(),
            call.span,
        );
    }
}

fn check_use_frame_inner_node(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    inner_id: NodeId,
    kind: AstKind<'_>,
    cb_span: Span,
    delta_param: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_cond = is_conditionally_executed_within(ctx.semantic, inner_id, cb_span);
    match kind {
        AstKind::NewExpression(new_expr) if !is_cond => {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoNewInUseFrame,
                "noNewInUseFrame",
                "useFrame",
                "This constructor allocates a new object every executed frame. Reuse an object allocated outside `useFrame` and mutate it in place.".to_string(),
                new_expr.span,
            );
        }
        AstKind::CallExpression(inner_call) => {
            check_use_frame_inner_call(
                ctx,
                node_id,
                inner_id,
                inner_call,
                cb_span,
                is_cond,
                sites,
            );
        }
        AstKind::AssignmentExpression(assign) => {
            check_use_frame_inner_assignment(ctx, node_id, assign, delta_param, is_cond, sites);
        }
        _ => {}
    }
}

fn check_use_frame_inner_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    inner_id: NodeId,
    inner_call: &CallExpression<'_>,
    cb_span: Span,
    is_cond: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(m) = extract_callee_short(&inner_call.callee) else {
        return;
    };
    if !is_cond && m == "clone" {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoCloneInUseFrame,
            "r3fNoCloneInUseFrame",
            "clone",
            "This `.clone()` allocates a new Three.js object every frame; reuse a scratch object outside `useFrame`.".to_string(),
            inner_call.span,
        );
    }
    if !is_cond && SYNC_WEBGL_READBACK_METHODS.contains(&m) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoSyncReadbackInUseFrame,
            "r3fNoSyncReadbackInUseFrame",
            m,
            format!("Synchronous GPU readback `{m}(...)` inside `useFrame` stalls the GPU pipeline."),
            inner_call.span,
        );
    }
    if ctx.state_setters.contains(m) && !is_guarded_state_update_in_frame(ctx, inner_id, cb_span) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoStateInUseFrame,
            "r3fNoStateInUseFrame",
            m,
            format!(
                "React state update `{m}(...)` inside `useFrame` schedules re-renders at 60fps; mutate a ref or guard transitions with an equality check."
            ),
            inner_call.span,
        );
    }
    if matches!(m, "setMatrixAt" | "setColorAt")
        && is_inside_loop_within(ctx.semantic, inner_id, cb_span)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fPreferGpuInstancedAnimation,
            "r3fPreferGpuInstancedAnimation",
            m,
            "Repeated per-instance transform updates in `useFrame`; prefer a vertex shader or GPU instanced attributes.".to_string(),
            inner_call.span,
        );
    }
    if matches!(m, "setXYZ" | "setX" | "setY" | "setZ")
        && is_inside_loop_within(ctx.semantic, inner_id, cb_span)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fPreferGpuPositionAnimation,
            "r3fPreferGpuPositionAnimation",
            m,
            "Per-vertex CPU position animation inside `useFrame`; animate vertex positions in a vertex shader.".to_string(),
            inner_call.span,
        );
    }
}

fn check_use_frame_inner_assignment(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    assign: &oxc_ast::ast::AssignmentExpression<'_>,
    delta_param: Option<&str>,
    is_cond: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let lhs_text = assign.left.span().source_text(ctx.source);
    let rhs_text = assign.right.span().source_text(ctx.source);

    if matches!(
        assign.operator,
        AssignmentOperator::Addition | AssignmentOperator::Subtraction
    ) && [".rotation.", ".position.", ".scale."]
        .iter()
        .any(|p| lhs_text.contains(p))
    {
        let uses_delta = delta_param.is_some_and(|d| rhs_text.contains(d))
            || rhs_text.contains("delta")
            || rhs_text.contains("getDelta");
        if !uses_delta {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fRequireFrameDelta,
                "r3fRequireFrameDelta",
                "useFrame",
                "Incremental transform mutation in `useFrame` does not scale by `delta`, making animation speed frame-rate dependent.".to_string(),
                assign.span,
            );
        }
    }

    if !is_cond
        && (lhs_text.ends_with(".vertexShader")
            || lhs_text.ends_with(".fragmentShader")
            || lhs_text.contains(".defines."))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoShaderConfigurationMutationInUseFrame,
            "r3fNoShaderConfigurationMutationInUseFrame",
            "shaderMaterial",
            "Rewriting shader configuration inside `useFrame` forces shader recompilation; animate uniform values instead.".to_string(),
            assign.span,
        );
    }
}

pub(crate) fn check_animation_loop_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    loop_name: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb = cb_expr.without_parentheses();
    let cb_span = resolve_callback_body_span(cb, ctx.semantic);
    if cb_span.start == cb_span.end {
        return;
    }
    if loop_name == "requestAnimationFrame"
        && matches!(cb, Expression::Identifier(_))
        && find_enclosing_function_span(ctx.semantic, node_id) == Some(cb_span)
    {
        return;
    }

    let cb_text = cb_span.source_text(ctx.source);
    check_animation_loop_header_and_text(ctx, node_id, call, cb, cb_text, loop_name, sites);

    for (inner_id, inner_node) in ctx.semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(inner_node.span()) {
            continue;
        }
        check_animation_loop_inner_node(
            ctx,
            node_id,
            inner_id,
            inner_node.kind(),
            cb_span,
            loop_name,
            sites,
        );
    }
}

fn check_animation_loop_header_and_text(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    cb: &Expression<'_>,
    cb_text: &str,
    loop_name: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_r3f_import && ctx.source.contains("useFrame(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoRecursiveRafWithUseFrame,
            "r3fNoRecursiveRafWithUseFrame",
            loop_name,
            format!(
                "Component starts `{loop_name}` while also using R3F `useFrame`; consolidate frame updates inside `useFrame`."
            ),
            call.span,
        );
    }
    if loop_name == "requestAnimationFrame"
        && cb_text.contains("requestAnimationFrame(")
        && cb_text.contains(".render(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreePreferSetAnimationLoop,
            "threePreferSetAnimationLoop",
            "requestAnimationFrame",
            "Prefer `renderer.setAnimationLoop(callback)` over manual `requestAnimationFrame` for Three.js and WebXR compatibility.".to_string(),
            call.span,
        );
    }
    if loop_name == "setAnimationLoop" && !cb_text.contains(".render(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireRenderInAnimationLoop,
            "threeRequireRenderInAnimationLoop",
            "setAnimationLoop",
            "`setAnimationLoop` callback never calls `renderer.render(...)` or `composer.render()`.".to_string(),
            call.span,
        );
    }
    if is_async_callback_expr(cb) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoAsyncAnimationLoop,
            "threeNoAsyncAnimationLoop",
            loop_name,
            "Keep Three.js animation loop callbacks synchronous.".to_string(),
            cb.span(),
        );
    }
}

fn check_animation_loop_inner_node(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    inner_id: NodeId,
    kind: AstKind<'_>,
    cb_span: Span,
    loop_name: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_cond = is_conditionally_executed_within(ctx.semantic, inner_id, cb_span);
    match kind {
        AstKind::NewExpression(new_expr) if !is_cond => {
            let ctor = resolve_callee_ctor_name(
                &new_expr.callee,
                &ctx.imported_symbols,
                &ctx.namespace_imports,
            )
            .unwrap_or_default();
            if ctor.ends_with("Geometry") {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeNoGeometryInFrameLoop,
                    "noGeometryInFrameLoop",
                    loop_name,
                    "Avoid allocating Three.js Geometry inside `requestAnimationFrame`; create geometries once outside the animation loop.".to_string(),
                    new_expr.span,
                );
            }
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeNoNewInAnimationLoop,
                "threeNoNewInAnimationLoop",
                loop_name,
                "Avoid `new` allocations inside the Three.js animation loop; reuse pre-allocated objects.".to_string(),
                new_expr.span,
            );
        }
        AstKind::CallExpression(inner_call) => {
            check_animation_loop_inner_call(
                ctx,
                node_id,
                inner_id,
                inner_call,
                cb_span,
                is_cond,
                sites,
            );
        }
        AstKind::AssignmentExpression(assign) if !is_cond => {
            let lhs_text = assign.left.span().source_text(ctx.source);
            if lhs_text.ends_with(".needsUpdate")
                && matches!(assign.right.without_parentheses(), Expression::BooleanLiteral(b) if b.value)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeNoMaterialRecompileInAnimationLoop,
                    "threeNoMaterialRecompileInAnimationLoop",
                    "needsUpdate",
                    "Setting `material.needsUpdate = true` every frame forces GPU shader program recompilation.".to_string(),
                    assign.span,
                );
            } else if lhs_text.ends_with(".uniformsNeedUpdate") {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeNoRedundantUniformsNeedUpdate,
                    "threeNoRedundantUniformsNeedUpdate",
                    "uniformsNeedUpdate",
                    "Setting `uniformsNeedUpdate` every frame is redundant.".to_string(),
                    assign.span,
                );
            }
        }
        _ => {}
    }
}

fn check_animation_loop_inner_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    inner_id: NodeId,
    inner_call: &CallExpression<'_>,
    cb_span: Span,
    is_cond: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(m) = extract_callee_short(&inner_call.callee) else {
        return;
    };
    if !is_cond && m == "clone" {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoCloneInAnimationLoop,
            "threeNoCloneInAnimationLoop",
            "clone",
            "Avoid `.clone()` allocations inside the animation loop.".to_string(),
            inner_call.span,
        );
    }
    if !is_cond && SYNC_WEBGL_READBACK_METHODS.contains(&m) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::WebglNoSyncReadbackInAnimationLoop,
            "webglNoSyncReadbackInAnimationLoop",
            m,
            format!("Synchronous GPU readback `{m}(...)` inside animation loop stalls the frame."),
            inner_call.span,
        );
        if m == "readRenderTargetPixels" {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeNoSyncReadbackInAnimationLoop,
                "threeNoSyncReadbackInAnimationLoop",
                m,
                "Use `readRenderTargetPixelsAsync` instead of synchronous `readRenderTargetPixels` in the animation loop.".to_string(),
                inner_call.span,
            );
        }
    }
    if !is_cond && matches!(m, "compile" | "compileAsync") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoCompileInAnimationLoop,
            "threeNoCompileInAnimationLoop",
            m,
            "Precompile materials outside the animation loop.".to_string(),
            inner_call.span,
        );
    }
    if !is_cond && matches!(m, "setSize" | "setDrawingBufferSize") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoUnconditionalRendererResizeInAnimationLoop,
            "threeNoUnconditionalRendererResizeInAnimationLoop",
            m,
            "Do not resize the renderer unconditionally on every animation frame.".to_string(),
            inner_call.span,
        );
    }
    if ctx.state_setters.contains(m) && !is_guarded_state_update_in_frame(ctx, inner_id, cb_span) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoStateInAnimationLoop,
            "threeNoStateInAnimationLoop",
            m,
            "Avoid unguarded React state updates inside a Three.js animation loop.".to_string(),
            inner_call.span,
        );
    }
}

pub(crate) fn check_use_three_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_webgpu_use_three_gl_state(ctx, node_id, call, sites);

    let Some(sel_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let sel = sel_expr.without_parentheses();
    if call.arguments.len() == 1
        && let Expression::ArrowFunctionExpression(arrow) = sel
        && let Some(expr) = arrow.body.as_expression()
    {
        let ret = expr.without_parentheses();
        if matches!(
            ret,
            Expression::ArrayExpression(_) | Expression::ObjectExpression(_)
        ) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoFreshUseThreeSelector,
                "r3fNoFreshUseThreeSelector",
                "useThree",
                "`useThree` selector returns a fresh array or object without an equality function."
                    .to_string(),
                ret.span(),
            );
        } else if let Expression::StaticMemberExpression(outer_mem) = ret
            && let Expression::StaticMemberExpression(inner_mem) =
                outer_mem.object.without_parentheses()
            && matches!(
                inner_mem.property.name.as_str(),
                "camera"
                    | "clock"
                    | "gl"
                    | "mouse"
                    | "pointer"
                    | "raycaster"
                    | "renderer"
                    | "scene"
            )
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoDeepUseThreeSelector,
                "r3fNoDeepUseThreeSelector",
                outer_mem.property.name.as_str(),
                format!(
                    "`useThree` selector reads mutable field `{}.{}`; select `state.{}` and read `.{}` at point of use.",
                    inner_mem.property.name,
                    outer_mem.property.name,
                    inner_mem.property.name,
                    outer_mem.property.name
                ),
                ret.span(),
            );
        }
    }
}

fn is_async_callback_expr(cb: &Expression<'_>) -> bool {
    match cb {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(func) => func.r#async,
        _ => false,
    }
}

fn extract_callback_param_name(cb: &Expression<'_>, index: usize) -> Option<String> {
    let params: &FormalParameters<'_> = match cb.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => &arrow.params,
        Expression::FunctionExpression(func) => &func.params,
        _ => return None,
    };
    let param = params.items.get(index)?;
    if let BindingPattern::BindingIdentifier(id) = &param.pattern {
        Some(id.name.to_string())
    } else {
        None
    }
}

fn is_inside_loop_within(semantic: &Semantic<'_>, node_id: NodeId, boundary_span: Span) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        let anc_node = semantic.nodes().get_node(anc_id);
        if !boundary_span.contains_inclusive(anc_node.span()) {
            break;
        }
        match anc_node.kind() {
            AstKind::ForStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::WhileStatement(_)
            | AstKind::DoWhileStatement(_) => return true,
            AstKind::CallExpression(call)
                if matches!(extract_callee_short(&call.callee), Some("forEach" | "map")) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_guarded_state_update_in_frame(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    boundary_span: Span,
) -> bool {
    for anc_id in ctx.semantic.nodes().ancestor_ids(node_id) {
        let anc_node = ctx.semantic.nodes().get_node(anc_id);
        if !boundary_span.contains_inclusive(anc_node.span()) {
            break;
        }
        match anc_node.kind() {
            AstKind::CatchClause(_) => return true,
            AstKind::IfStatement(if_stmt) => {
                let test_src = if_stmt.test.span().source_text(ctx.source);
                if ["!==", "===", "!=", "=="]
                    .iter()
                    .any(|op| test_src.contains(op))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
