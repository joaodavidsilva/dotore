//! WebGPU & Three.js Shading Language (`r3f-webgpu-*`, `three-webgpu-*`, `three-tsl-*`)
//! compatibility, initialization, and TSL uniform branch rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds"
)]

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentExpression, CallExpression, Expression, JSXOpeningElement,
        ObjectExpression, StaticMemberExpression,
    },
};
use oxc_semantic::NodeId;
use oxc_span::{GetSpan, Span};

use super::{
    COLOR_SPACE_LINEAR_PROPS, COLOR_SPACE_SRGB_PROPS, DEFAULT_TRANSPARENT_MATERIALS,
    FileAnalysisCtx, PBR_MATERIALS, PHYSICAL_NORMALIZED_PROPS, R3F_WEBGPU_MODULES,
    WEBGPU_SYNC_METHODS, eval_static_f64, get_jsx_attr_expr, get_jsx_attr_item, get_obj_prop_expr,
};
use crate::{ir::types::SemanticRuleSite, rules::RuleId};

pub(crate) fn check_canvas_opening(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let has_gl = get_jsx_attr_item(opening, "gl").is_some();
    let has_renderer = get_jsx_attr_item(opening, "renderer").is_some();
    let canvas_src = ctx.imported_symbols.get("Canvas").map(|(s, _)| s.as_str());

    if has_gl && has_renderer {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fWebgpuCanvasPropCompatibility,
            "r3fWebgpuCanvasPropCompatibility",
            "renderer",
            "This Canvas receives both `gl` and `renderer`, but R3F accepts only one renderer API."
                .to_string(),
            opening.span,
        );
    } else if canvas_src == Some("@react-three/fiber/webgpu") && has_gl {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fWebgpuCanvasPropCompatibility,
            "r3fWebgpuCanvasPropCompatibility",
            "gl",
            "The WebGPU Canvas rejects the legacy `gl` prop. Configure its `renderer` prop instead."
                .to_string(),
            opening.span,
        );
    } else if canvas_src == Some("@react-three/fiber/legacy") && has_renderer {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fWebgpuCanvasPropCompatibility,
            "r3fWebgpuCanvasPropCompatibility",
            "renderer",
            "The legacy Canvas rejects the WebGPU `renderer` prop. Configure its `gl` prop instead."
                .to_string(),
            opening.span,
        );
    }

    // `r3f-webgpu-require-async-init`
    if let Some(gl_expr) = get_jsx_attr_expr(opening, "gl") {
        let gl_src = gl_expr.span().source_text(ctx.source);
        if gl_src.contains("WebGPURenderer") {
            let is_async = match gl_expr {
                Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
                Expression::FunctionExpression(func) => func.r#async,
                _ => gl_src.contains("async "),
            };
            let has_awaited_init = gl_src.contains("await ") && gl_src.contains(".init(");
            if !is_async || !has_awaited_init {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fWebgpuRequireAsyncInit,
                    "r3fWebgpuRequireAsyncInit",
                    "gl",
                    "Canvas `gl` factory returns `WebGPURenderer` without an unconditional `await renderer.init()`."
                        .to_string(),
                    gl_expr.span(),
                );
            }
        }
    }

    // `r3f-cap-device-pixel-ratio`
    for prop_name in ["dpr", "pixelRatio"] {
        if let Some(dpr_expr) = get_jsx_attr_expr(opening, prop_name) {
            let dpr_src = dpr_expr.span().source_text(ctx.source);
            if dpr_src.contains("devicePixelRatio") && !dpr_src.contains("Math.min") {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fCapDevicePixelRatio,
                    "r3fCapDevicePixelRatio",
                    prop_name,
                    "Canvas uses uncapped `devicePixelRatio`; bound DPR (e.g. `dpr={[1, 2]}`) to prevent excessive GPU load on high-DPI displays.".to_string(),
                    dpr_expr.span(),
                );
            }
        }
    }
}

pub(crate) fn check_webgpu_jsx_opening(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // WebGPU legacy EffectComposer inside WebGPU Canvas (`r3f-webgpu-no-legacy-effect-composer`)
    if tag == "EffectComposer"
        && ctx.has_webgpu
        && let Some((src, _)) = ctx.imported_symbols.get("EffectComposer")
        && src == "@react-three/postprocessing"
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fWebgpuNoLegacyEffectComposer,
            "r3fWebgpuNoLegacyEffectComposer",
            "EffectComposer",
            "@react-three/postprocessing EffectComposer targets the legacy WebGL pipeline and cannot render this WebGPU Canvas. Use the node-based render pipeline".to_string(),
            opening.span,
        );
    }
}

pub(crate) fn check_webgpu_jsx_material_and_instancing(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // WebGPU legacy material API (`r3f-webgpu-no-legacy-material-api`)
    if ctx.has_webgpu {
        if matches!(tag, "shaderMaterial" | "rawShaderMaterial") {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fWebgpuNoLegacyMaterialApi,
                "r3fWebgpuNoLegacyMaterialApi",
                tag,
                "`ShaderMaterial` and `RawShaderMaterial` do not run on Three.js `WebGPURenderer`. Use a node material and TSL.".to_string(),
                opening.span,
            );
        } else if tag.ends_with("Material")
            && get_jsx_attr_item(opening, "onBeforeCompile").is_some()
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fWebgpuNoLegacyMaterialApi,
                "r3fWebgpuNoLegacyMaterialApi",
                "onBeforeCompile",
                "`onBeforeCompile` patches WebGL shader source and is not supported by `WebGPURenderer`.".to_string(),
                opening.span,
            );
        }
    }

    // `r3f-webgpu-no-high-precision-instancing`
    if matches!(tag, "instancedMesh" | "skinnedMesh")
        && ctx.source.contains("highPrecision")
        && ctx.source.contains("WebGPURenderer")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fWebgpuNoHighPrecisionInstancing,
            "r3fWebgpuNoHighPrecisionInstancing",
            tag,
            "WebGPURenderer `highPrecision` is incompatible with `instancedMesh` and `skinnedMesh`."
                .to_string(),
            opening.span,
        );
    }
}

pub(crate) fn check_webgpu_new_expression(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    span: Span,
    ctor: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_webgpu {
        if matches!(ctor, "ShaderMaterial" | "RawShaderMaterial") {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeWebgpuNoLegacyMaterialApi,
                "threeWebgpuNoLegacyMaterialApi",
                ctor,
                format!(
                    "`{ctor}` is not supported by Three.js `WebGPURenderer`; use node materials and TSL."
                ),
                span,
            );
        } else if ctor == "EffectComposer" {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeWebgpuNoLegacyEffectComposer,
                "threeWebgpuNoLegacyEffectComposer",
                "EffectComposer",
                "Legacy `EffectComposer` does not support `WebGPURenderer`; use the node-based post-processing pipeline.".to_string(),
                span,
            );
        }
    }
}

pub(crate) fn check_webgpu_assignment(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    assign: &AssignmentExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    prop: &str,
    sites: &mut Vec<SemanticRuleSite>,
) -> bool {
    if prop == "highPrecision"
        && matches!(assign.right.without_parentheses(), Expression::BooleanLiteral(b) if b.value)
        && ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("WebGPURenderer")
        && (ctx.source.contains("InstancedMesh") || ctx.source.contains("SkinnedMesh"))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeWebgpuNoHighPrecisionInstancing,
            "threeWebgpuNoHighPrecisionInstancing",
            "highPrecision",
            "`WebGPURenderer.highPrecision` is incompatible with `InstancedMesh` and `SkinnedMesh`."
                .to_string(),
            assign.span,
        );
    }

    if prop == "onBeforeCompile" && ctx.has_webgpu {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeWebgpuNoLegacyMaterialApi,
            "threeWebgpuNoLegacyMaterialApi",
            "onBeforeCompile",
            "`onBeforeCompile` is not supported by `WebGPURenderer`; use node materials and TSL."
                .to_string(),
            assign.span,
        );
        return true;
    }

    false
}

pub(crate) fn check_webgpu_sync_member_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    method: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // `three-webgpu-require-init-before-sync-operation`
    if WEBGPU_SYNC_METHODS.contains(&method)
        && ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("WebGPURenderer")
        && let Expression::Identifier(renderer_id) = mem.object.without_parentheses()
    {
        let before_slice = ctx.source.get(..call.span.start as usize).unwrap_or("");
        let awaited_init = before_slice.contains(&format!("await {}.init()", renderer_id.name));
        if !awaited_init {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeWebgpuRequireInitBeforeSyncOperation,
                "threeWebgpuRequireInitBeforeSyncOperation",
                method,
                format!(
                    "`WebGPURenderer.{method}()` is called before `await {}.init()`.",
                    renderer_id.name
                ),
                call.span,
            );
        }
    }
}

pub(crate) fn check_tsl_and_webgpu_pipeline_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_short: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // TSL & WebGPU uniform branch (`three-tsl-no-js-uniform-branch`, `r3f-webgpu-no-js-uniform-branch`, `r3f-webgpu-no-unregistered-pipeline-pass`)
    if matches!(
        callee_short,
        Some("Fn" | "useNodes" | "useLocalNodes" | "usePostProcessing" | "useRenderPipeline")
    ) && let Some(cb) = call.arguments.first().and_then(Argument::as_expression)
    {
        let cb_src = cb.span().source_text(ctx.source);
        if cb_src.contains("if (") && cb_src.contains(".value") {
            let rule = if callee_short == Some("Fn") {
                RuleId::ThreeTslNoJsUniformBranch
            } else {
                RuleId::R3fWebgpuNoJsUniformBranch
            };
            ctx.push_site(
                sites,
                node_id,
                rule,
                "noJsUniformBranch",
                callee_short.unwrap_or("Fn"),
                "JavaScript `if` branch reads a TSL uniform `.value` during graph construction; use TSL `If(...)` or `select(...)`.".to_string(),
                cb.span(),
            );
        }
        if matches!(
            callee_short,
            Some("usePostProcessing" | "useRenderPipeline")
        ) && cb_src.contains(".passes.")
            && cb_src.contains(" = ")
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fWebgpuNoUnregisteredPipelinePass,
                "r3fWebgpuNoUnregisteredPipelinePass",
                callee_short.unwrap_or("usePostProcessing"),
                "Return custom passes from the WebGPU pipeline callback instead of assigning directly to `state.passes`.".to_string(),
                cb.span(),
            );
        }
    }
}

pub(crate) fn check_webgpu_use_three_gl_state(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let is_webgpu_use_three = ctx
        .imported_symbols
        .get("useThree")
        .is_some_and(|(src, _)| R3F_WEBGPU_MODULES.contains(&src.as_str()));

    if call.arguments.is_empty() && is_webgpu_use_three {
        let parent_kind = ctx.semantic.nodes().parent_kind(node_id);
        match parent_kind {
            AstKind::VariableDeclarator(decl) => {
                let decl_src = decl.id.span().source_text(ctx.source);
                if decl_src.contains("gl") {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fWebgpuNoGlState,
                        "r3fWebgpuNoGlState",
                        "gl",
                        "The R3F WebGPU root exposes `state.gl` only as a deprecated alias; read `state.renderer` instead.".to_string(),
                        decl.id.span(),
                    );
                }
            }
            AstKind::StaticMemberExpression(mem) if mem.property.name == "gl" => {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fWebgpuNoGlState,
                    "r3fWebgpuNoGlState",
                    "gl",
                    "Read `state.renderer` from the R3F WebGPU root instead of `state.gl`."
                        .to_string(),
                    mem.span,
                );
            }
            _ => {}
        }
    }
}

pub(crate) fn check_three_material_options(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    ctor: &str,
    obj: &ObjectExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_three_material_opacity_and_basic(ctx, node_id, ctor, obj, sites);
    check_three_material_pbr_and_physical(ctx, node_id, ctor, obj, sites);
    check_three_material_texture_color_space(ctx, node_id, obj, sites);
}

fn check_three_material_opacity_and_basic(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    ctor: &str,
    obj: &ObjectExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(op_expr) = get_obj_prop_expr(obj, "opacity")
        && let Some(op) = eval_static_f64(op_expr)
    {
        if !(0.0..=1.0).contains(&op) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidMaterialOpacity,
                "threeValidMaterialOpacity",
                "opacity",
                format!("Material opacity {op} is outside [0, 1]."),
                op_expr.span(),
            );
        } else if op < 1.0
            && !DEFAULT_TRANSPARENT_MATERIALS.contains(&ctor)
            && !matches!(get_obj_prop_expr(obj, "transparent"), Some(Expression::BooleanLiteral(b)) if b.value)
            && !matches!(get_obj_prop_expr(obj, "alphaHash"), Some(Expression::BooleanLiteral(b)) if b.value)
            && get_obj_prop_expr(obj, "alphaTest")
                .and_then(eval_static_f64)
                .is_none_or(|v| v <= 0.0)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeRequireTransparentForOpacity,
                "threeRequireTransparentForOpacity",
                "opacity",
                "Material sets `opacity < 1` without `transparent: true`, `alphaHash: true`, or `alphaTest > 0`.".to_string(),
                op_expr.span(),
            );
        }
    }

    if ctor == "MeshBasicMaterial" {
        for ignored in ["roughness", "metalness"] {
            if let Some(expr) = get_obj_prop_expr(obj, ignored) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeNoIgnoredBasicMaterialProperties,
                    "threeNoIgnoredBasicMaterialProperties",
                    ignored,
                    format!(
                        "`MeshBasicMaterial` ignores `{ignored}`; use `MeshStandardMaterial` or `MeshPhysicalMaterial`."
                    ),
                    expr.span(),
                );
            }
        }
    }

    if matches!(ctor, "LineBasicMaterial" | "LineDashedMaterial")
        && let Some(lw_expr) = get_obj_prop_expr(obj, "linewidth")
        && let Some(lw) = eval_static_f64(lw_expr)
        && (lw - 1.0).abs() > f64::EPSILON
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoIgnoredLinewidth,
            "threeNoIgnoredLinewidth",
            "linewidth",
            format!("`linewidth: {lw}` is ignored by WebGL/WebGPU renderers."),
            lw_expr.span(),
        );
    }
}

fn check_three_material_pbr_and_physical(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    ctor: &str,
    obj: &ObjectExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if PBR_MATERIALS.contains(&ctor) {
        for factor in ["roughness", "metalness"] {
            if let Some(expr) = get_obj_prop_expr(obj, factor)
                && let Some(val) = eval_static_f64(expr)
                && !(0.0..=1.0).contains(&val)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidPbrMaterialProperties,
                    "threeValidPbrMaterialProperties",
                    factor,
                    format!("`{factor}` is {val}, outside [0, 1]."),
                    expr.span(),
                );
            }
        }
    }

    if ctor != "MeshPhysicalMaterial" {
        return;
    }
    for prop in PHYSICAL_NORMALIZED_PROPS {
        if let Some(expr) = get_obj_prop_expr(obj, prop)
            && let Some(val) = eval_static_f64(expr)
            && !(0.0..=1.0).contains(&val)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidPhysicalMaterialProperties,
                "threeValidPhysicalMaterialProperties",
                prop,
                format!("`{prop}` is {val}, outside [0, 1]."),
                expr.span(),
            );
        }
    }
    for ior_prop in ["ior", "iridescenceIOR"] {
        if let Some(expr) = get_obj_prop_expr(obj, ior_prop)
            && let Some(val) = eval_static_f64(expr)
            && !(1.0..=2.333).contains(&val)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidPhysicalMaterialProperties,
                "threeValidPhysicalMaterialProperties",
                ior_prop,
                format!("`{ior_prop}` is {val}, outside [1, 2.333]."),
                expr.span(),
            );
        }
    }
}

fn check_three_material_texture_color_space(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    obj: &ObjectExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for &prop in COLOR_SPACE_SRGB_PROPS
        .iter()
        .chain(COLOR_SPACE_LINEAR_PROPS.iter())
    {
        if let Some(Expression::Identifier(tex_id)) = get_obj_prop_expr(obj, prop)
            && !ctx.render_target_vars.contains(tex_id.name.as_str())
            && let Some((cs, 1)) = ctx.texture_color_spaces.get(tex_id.name.as_str())
        {
            let expected = if COLOR_SPACE_SRGB_PROPS.contains(&prop) {
                "SRGBColorSpace"
            } else {
                "NoColorSpace"
            };
            if cs != expected {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidTextureColorSpace,
                    "threeValidTextureColorSpace",
                    prop,
                    format!(
                        "`{prop}` expects `{expected}`, but `{}` is assigned `{cs}`.",
                        tex_id.name
                    ),
                    tex_id.span,
                );
            }
        }
    }
}
