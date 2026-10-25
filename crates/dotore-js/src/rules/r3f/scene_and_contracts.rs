//! Three.js and R3F property assignments, `<Canvas>` / `<mesh>` scene contracts, and
//! imperative Three.js scene/renderer/mixer/controls/buffer contract detectors.

use oxc_ast::{
    AstKind,
    ast::{Argument, AssignmentTarget, Expression, JSXChild, JSXElement},
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    FileAnalysisCtx, LIT_MATERIALS, THREE_CONTROLS_CTORS, THREE_LIGHT_TAGS_AND_CTORS,
    THREE_POSTPROCESSING_CTORS, THREE_RENDER_TARGET_CTORS, THREE_TEXTURE_CTORS,
    UNSUPPORTED_SHADOW_LIGHTS, UV_MAPPED_MATERIALS, extract_callee_short, extract_root_ident_name,
    get_jsx_attr_item, jsx_attr_is_true, jsx_opening_tag_name, webgpu::check_webgpu_assignment,
};
use crate::{ir::types::SemanticRuleSite, rules::RuleId};

pub(crate) fn check_assignments_and_updates(
    ctx: &FileAnalysisCtx<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::AssignmentExpression(assign) = node.kind() else {
            continue;
        };
        let AssignmentTarget::StaticMemberExpression(mem) = &assign.left else {
            continue;
        };
        check_single_static_member_assignment(ctx, node_id, assign, mem, sites);
    }
}

fn check_single_static_member_assignment(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    assign: &oxc_ast::ast::AssignmentExpression<'_>,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let prop = mem.property.name.as_str();
    let root_ident = extract_root_ident_name(&mem.object);

    if let Some(root) = &root_ident
        && ctx.loader_cache_vars.contains(root)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoMutateLoaderCache,
            "r3fNoMutateLoaderCache",
            root,
            format!(
                "Mutating property `.{prop}` on cached loader asset `{root}`; clone before mutating."
            ),
            assign.span,
        );
    }

    if prop == "castShadow"
        && matches!(assign.right.without_parentheses(), Expression::BooleanLiteral(b) if b.value)
        && let Some(ctor) = ctx.resolve_expr_three_ctor(&mem.object)
        && UNSUPPORTED_SHADOW_LIGHTS.contains(&ctor.as_str())
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeNoShadowsOnUnsupportedLight,
            "threeNoShadowsOnUnsupportedLight",
            &ctor,
            format!(
                "`{ctor}` cannot cast shadows; use `DirectionalLight`, `PointLight`, or `SpotLight`."
            ),
            assign.span,
        );
    }

    let handled_webgpu_on_before =
        check_webgpu_assignment(ctx, node_id, assign, mem, prop, sites);
    if !handled_webgpu_on_before
        && prop == "onBeforeCompile"
        && !ctx.source.contains("customProgramCacheKey")
    {
            let rhs_text = assign.right.span().source_text(ctx.source);
            if [".defines", ".vertexShader", ".fragmentShader"]
                .iter()
                .any(|p| rhs_text.contains(p))
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeOnBeforeCompileRequireProgramCacheKey,
                    "threeOnBeforeCompileRequireProgramCacheKey",
                    "onBeforeCompile",
                    "Define `customProgramCacheKey` when `onBeforeCompile` patches shader defines or source.".to_string(),
                    assign.span,
                );
            }
        }

        if matches!(prop, "fov" | "aspect" | "near" | "far" | "zoom")
            && !ctx.source.contains(".updateProjectionMatrix(")
        {
            let obj_src = mem.object.span().source_text(ctx.source);
            if obj_src.contains("camera") || obj_src.contains("Camera") {
                let rule = if ctx.has_r3f_import {
                    RuleId::R3fRequireProjectionMatrixUpdate
                } else {
                    RuleId::ThreeRequireProjectionMatrixUpdate
                };
                ctx.push_site(
                    sites,
                    node_id,
                    rule,
                    "requireProjectionMatrixUpdate",
                    prop,
                    format!(
                        "Call `camera.updateProjectionMatrix()` after mutating `camera.{prop}`."
                    ),
                    assign.span,
                );
            }
    }
}

pub(crate) fn check_scene_and_canvas_contracts(
    ctx: &FileAnalysisCtx<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(el) = node.kind() else {
            continue;
        };
        let Some(tag) = jsx_opening_tag_name(&el.opening_element) else {
            continue;
        };

        if tag == "Canvas" {
            check_jsx_canvas_contracts(ctx, node_id, el, sites);
        }

        check_shadowed_point_light_children(ctx, node_id, el, sites);

        if tag == "mesh" {
            check_jsx_mesh_buffer_geometry_contracts(ctx, node_id, el, sites);
        }
    }

    check_imperative_three_scene_contracts(ctx, sites);
}

fn check_jsx_canvas_contracts(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    el: &JSXElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let canvas_text = el.span.source_text(ctx.source);
    let has_shadows_prop = get_jsx_attr_item(&el.opening_element, "shadows").is_some();
    if !has_shadows_prop
        && (canvas_text.contains("castShadow") || canvas_text.contains("receiveShadow"))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireShadowsEnabled,
            "r3fRequireShadowsEnabled",
            "Canvas",
            "Enable the `<Canvas shadows>` prop when descendants use `castShadow` or `receiveShadow`.".to_string(),
            el.opening_element.span,
        );
    }

    let has_pbr = canvas_text.contains("<meshStandardMaterial")
        || canvas_text.contains("<meshPhysicalMaterial");
    let has_light = THREE_LIGHT_TAGS_AND_CTORS
        .iter()
        .any(|l| canvas_text.contains(&format!("<{l}")))
        || ["<Environment", "envMap=", "lightMap=", "emissive="]
            .iter()
            .any(|p| canvas_text.contains(p));
    if has_pbr && !has_light {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireLightingForPbr,
            "r3fRequireLightingForPbr",
            "Canvas",
            "R3F `<Canvas>` renders a PBR material (`meshStandardMaterial` / `meshPhysicalMaterial`) without any light source or environment.".to_string(),
            el.opening_element.span,
        );
    }

    if ["metalness={1", "metalness={0.8", "metalness={0.9"]
        .iter()
        .any(|p| canvas_text.contains(p))
        && !canvas_text.contains("<Environment")
        && !canvas_text.contains("envMap=")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireEnvironmentForMetal,
            "r3fRequireEnvironmentForMetal",
            "Canvas",
            "Metallic R3F material (`metalness > 0.5`) has no `<Environment>` or `envMap`."
                .to_string(),
            el.opening_element.span,
        );
    }
}

fn check_shadowed_point_light_children(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    el: &JSXElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let direct_shadow_point_lights: Vec<&JSXElement<'_>> = el
        .children
        .iter()
        .filter_map(|child| {
            if let JSXChild::Element(child_el) = child
                && jsx_opening_tag_name(&child_el.opening_element).as_deref() == Some("pointLight")
                && jsx_attr_is_true(&child_el.opening_element, "castShadow")
            {
                Some(child_el.as_ref())
            } else {
                None
            }
        })
        .collect();
    if let Some(extras) = direct_shadow_point_lights.get(2..) {
        for extra in extras {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fLimitShadowedPointLights,
                "r3fLimitShadowedPointLights",
                "pointLight",
                "More than 2 shadow-casting `<pointLight castShadow />` elements in one scene; each omnidirectional shadow map renders 6 cube faces.".to_string(),
                extra.opening_element.span,
            );
        }
    }
}

fn check_jsx_mesh_buffer_geometry_contracts(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    el: &JSXElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mesh_text = el.span.source_text(ctx.source);
    if !mesh_text.contains("<bufferGeometry") || !mesh_text.contains("attributes-position") {
        return;
    }
    if !mesh_text.contains("attributes-normal")
        && LIT_MATERIALS
            .iter()
            .any(|m| mesh_text.contains(&format!("<{m}")))
        && mesh_text.contains("normalMap=")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireLitMaterialNormals,
            "r3fRequireLitMaterialNormals",
            "bufferGeometry",
            "Normal-mapped R3F `<bufferGeometry>` defines `position` without a `normal` attribute."
                .to_string(),
            el.opening_element.span,
        );
    }
    if !mesh_text.contains("attributes-uv")
        && UV_MAPPED_MATERIALS
            .iter()
            .any(|m| mesh_text.contains(&format!("<{m}")))
        && (mesh_text.contains(" map=") || mesh_text.contains(" normalMap="))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fRequireUvForTextureMap,
            "r3fRequireUvForTextureMap",
            "bufferGeometry",
            "Texture-mapped R3F `<bufferGeometry>` defines `position` without a `uv` attribute."
                .to_string(),
            el.opening_element.span,
        );
    }
}

fn check_imperative_three_scene_contracts(
    ctx: &FileAnalysisCtx<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some((first_node_id, first_node)) = ctx.semantic.nodes().iter_enumerated().next() else {
        return;
    };
    let file_span = first_node.span();

    check_imperative_resize_and_mixer_contracts(ctx, first_node_id, file_span, sites);
    check_imperative_buffer_and_composer_contracts(ctx, first_node_id, file_span, sites);
    check_imperative_renderer_and_shadow_contracts(ctx, first_node_id, file_span, sites);
    check_imperative_pbr_and_geometry_contracts(ctx, first_node_id, file_span, sites);
    check_imperative_loop_and_pointer_contracts(ctx, first_node_id, file_span, sites);
}

fn check_imperative_resize_and_mixer_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if ctx.has_r3f_import
        && src.contains("addEventListener(\"resize\"")
        && (src.contains("gl.setSize(") || src.contains("renderer.setSize("))
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::R3fNoManualCanvasResize,
            "r3fNoManualCanvasResize",
            "setSize",
            "Let R3F `<Canvas>` manage renderer sizing instead of registering a manual window `resize` listener.".to_string(),
            file_span,
        );
    }
    if src.contains("<shaderMaterial")
        && src.contains("uniforms={")
        && src.contains("useFrame(")
        && src.contains("uniforms.")
        && !src.contains(".current.uniforms")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::R3fNoMutateUniformPropSourceInUseFrame,
            "r3fNoMutateUniformPropSourceInUseFrame",
            "uniforms",
            "Mutate `materialRef.current.uniforms` inside `useFrame` instead of the prop source object.".to_string(),
            file_span,
        );
    }
    check_imperative_mixer_and_controls_updates(ctx, first_node_id, file_span, sites);
}

fn check_imperative_mixer_and_controls_updates(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if src.contains(".clipAction(") && !src.contains(".update(") {
        if ctx.has_r3f_import && src.contains("useFrame(") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::R3fRequireAnimationMixerUpdate,
                "r3fRequireAnimationMixerUpdate",
                "AnimationMixer",
                "`AnimationMixer.clipAction(...)` is created, but `mixer.update(delta)` is never called in `useFrame`.".to_string(),
                file_span,
            );
        } else if src.contains("setAnimationLoop(") || src.contains("requestAnimationFrame(") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireAnimationMixerUpdate,
                "threeRequireAnimationMixerUpdate",
                "AnimationMixer",
                "`AnimationMixer.clipAction(...)` is created, but `mixer.update(delta)` is never called in the animation loop.".to_string(),
                file_span,
            );
        }
    }
    if (src.contains("enableDamping = true") || src.contains("autoRotate = true"))
        && (src.contains("setAnimationLoop(") || src.contains("requestAnimationFrame("))
        && !src.contains("controls.update(")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeRequireControlsUpdate,
            "threeRequireControlsUpdate",
            "controls",
            "Call `controls.update()` in the animation loop when `enableDamping` or `autoRotate` is enabled.".to_string(),
            file_span,
        );
    }
}

fn check_imperative_buffer_and_composer_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_imperative_buffer_update_contracts(ctx, first_node_id, file_span, sites);
    check_imperative_effect_composer_contracts(ctx, first_node_id, file_span, sites);
}

fn check_imperative_buffer_update_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if src.contains(".image.data[") && !src.contains(".needsUpdate = true") {
        let rule = if ctx.has_r3f_import {
            RuleId::R3fRequireDataTextureUpdate
        } else {
            RuleId::ThreeRequireDataTextureUpdate
        };
        ctx.push_site(
            sites,
            first_node_id,
            rule,
            "requireDataTextureUpdate",
            "DataTexture",
            "Set `texture.needsUpdate = true` after mutating `texture.image.data`.".to_string(),
            file_span,
        );
    }
    if (src.contains("useFrame(") || src.contains("setAnimationLoop("))
        && (src.contains("BufferAttribute") || src.contains("bufferAttribute"))
        && src.contains(".needsUpdate = true")
        && !src.contains("DynamicDrawUsage")
        && !src.contains("StreamDrawUsage")
    {
        let rule = if ctx.has_r3f_import {
            RuleId::R3fRequireDynamicBufferUsage
        } else {
            RuleId::ThreeRequireDynamicBufferUsage
        };
        ctx.push_site(
            sites,
            first_node_id,
            rule,
            "requireDynamicBufferUsage",
            "DynamicDrawUsage",
            "Per-frame buffer attribute upload should set `DynamicDrawUsage`.".to_string(),
            file_span,
        );
    }
    if (src.contains("attributes.position.setXYZ(") || src.contains("attributes.position.array["))
        && !src.contains("position.needsUpdate = true")
    {
        let rule = if ctx.has_r3f_import {
            RuleId::R3fRequirePositionBufferUpdate
        } else {
            RuleId::ThreeRequirePositionBufferUpdate
        };
        ctx.push_site(
            sites,
            first_node_id,
            rule,
            "requirePositionBufferUpdate",
            "position",
            "Set `geometry.attributes.position.needsUpdate = true` after modifying vertex positions on the CPU.".to_string(),
            file_span,
        );
    }
}

fn check_imperative_effect_composer_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if let Some(out_pos) = src.find("new OutputPass(")
        && let Some(last_add) = src.rfind(".addPass(")
        && last_add > out_pos
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeEffectComposerOutputPassLast,
            "threeEffectComposerOutputPassLast",
            "OutputPass",
            "Add `OutputPass` last in the `EffectComposer` pass chain.".to_string(),
            file_span,
        );
    }
    if src.contains("new EffectComposer(")
        && src.contains("addEventListener(\"resize\"")
        && src.contains("renderer.setSize(")
        && !src.contains("composer.setSize(")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeEffectComposerRequireSizeOnResize,
            "threeEffectComposerRequireSizeOnResize",
            "EffectComposer",
            "Call `composer.setSize(width, height)` when resizing the associated renderer."
                .to_string(),
            file_span,
        );
    }
}

fn check_imperative_renderer_and_shadow_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_imperative_renderer_setup(ctx, first_node_id, file_span, sites);
    check_imperative_shadow_and_render_target_setup(ctx, first_node_id, file_span, sites);
}

fn check_imperative_renderer_setup(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if src.contains("new PerspectiveCamera(")
        && src.contains("addEventListener(\"resize\"")
        && src.contains("renderer.setSize(")
        && !src.contains(".aspect =")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeRequireCameraAspectOnResize,
            "threeRequireCameraAspectOnResize",
            "aspect",
            "Update `camera.aspect` and `camera.updateProjectionMatrix()` when resizing the renderer.".to_string(),
            file_span,
        );
    }
    if src.contains("new WebGLRenderer()") && src.contains("renderer.render(") {
        if !src.contains(".domElement") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireRendererDomAttachment,
                "threeRequireRendererDomAttachment",
                "domElement",
                "`new WebGLRenderer()` canvas `renderer.domElement` is never attached to the DOM."
                    .to_string(),
                file_span,
            );
        }
        if !src.contains(".setSize(") && !src.contains(".setDrawingBufferSize(") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireRendererSize,
                "threeRequireRendererSize",
                "setSize",
                "Call `renderer.setSize(width, height)` before rendering.".to_string(),
                file_span,
            );
        }
    }
}

fn check_imperative_shadow_and_render_target_setup(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    if !ctx.has_r3f_import
        && src.contains(".castShadow = true")
        && src.contains("renderer.render(")
        && !src.contains("shadowMap.enabled = true")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeRequireShadowsEnabled,
            "threeRequireShadowsEnabled",
            "shadowMap",
            "Set `renderer.shadowMap.enabled = true` when rendered objects cast or receive shadows.".to_string(),
            file_span,
        );
    }
    if src.matches("new PointLight(").count() > 2 && src.matches(".castShadow = true").count() > 2 {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeLimitShadowedPointLights,
            "threeLimitShadowedPointLights",
            "PointLight",
            "Keep at most two shadow-casting `PointLight` instances in one scene.".to_string(),
            file_span,
        );
    }
    if !ctx.has_r3f_import
        && src.contains("renderer.setRenderTarget(")
        && !src.contains("renderer.setRenderTarget(null)")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeRequireRenderTargetReset,
            "threeRequireRenderTargetReset",
            "setRenderTarget",
            "Call `renderer.setRenderTarget(null)` after rendering to an offscreen render target."
                .to_string(),
            file_span,
        );
    }
    if let Some(render_pos) = src.find("renderer.render(")
        && let Some(wrap_pos) = src.find(".wrapS =").or_else(|| src.find(".wrapT ="))
        && wrap_pos > render_pos
        && !src.get(wrap_pos..).unwrap_or_default().contains(".needsUpdate = true")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreeRequireTextureUpdateAfterWrappingChange,
            "threeRequireTextureUpdateAfterWrappingChange",
            "needsUpdate",
            "Set `texture.needsUpdate = true` after changing `wrapS` or `wrapT` on an already-rendered texture.".to_string(),
            file_span,
        );
    }
}

fn check_imperative_pbr_and_geometry_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.has_r3f_import {
        return;
    }
    let src = ctx.source;

    if src.contains("new Scene(")
        && src.contains("renderer.render(")
        && (src.contains("new MeshStandardMaterial(") || src.contains("new MeshPhysicalMaterial("))
    {
        let has_light = THREE_LIGHT_TAGS_AND_CTORS
            .iter()
            .any(|l| src.contains(&format!("new {l}(")))
            || [".environment =", "envMap:", "emissive:"]
                .iter()
                .any(|p| src.contains(p));
        if !has_light {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireLightingForPbr,
                "threeRequireLightingForPbr",
                "Scene",
                "Scene renders a PBR material (`MeshStandardMaterial` / `MeshPhysicalMaterial`) without any light source or environment.".to_string(),
                file_span,
            );
        }
        if ["metalness: 1", "metalness: 0.9", "metalness: 0.8"]
            .iter()
            .any(|p| src.contains(p))
            && !src.contains(".environment =")
            && !src.contains("envMap:")
        {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireEnvironmentForMetal,
                "threeRequireEnvironmentForMetal",
                "Scene",
                "Strongly metallic Three.js material (`metalness > 0.5`) has no scene `environment` or material `envMap`.".to_string(),
                file_span,
            );
        }
    }

    if src.contains("new BufferGeometry(") && src.contains("setAttribute(\"position\"") {
        if src.contains("normalMap:")
            && !src.contains("setAttribute(\"normal\"")
            && !src.contains(".computeVertexNormals(")
        {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireLitMaterialNormals,
                "threeRequireLitMaterialNormals",
                "BufferGeometry",
                "Normal-mapped custom `BufferGeometry` lacks a `normal` attribute and never calls `computeVertexNormals()`.".to_string(),
                file_span,
            );
        }
        if src.contains("map:") && !src.contains("setAttribute(\"uv\"") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireUvForTextureMap,
                "threeRequireUvForTextureMap",
                "BufferGeometry",
                "Texture-mapped custom `BufferGeometry` defines `position` without a `uv` attribute.".to_string(),
                file_span,
            );
        }
    }
}

fn check_imperative_loop_and_pointer_contracts(
    ctx: &FileAnalysisCtx<'_>,
    first_node_id: NodeId,
    file_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;

    if !ctx.has_r3f_import
        && src.contains(".forEach(")
        && src.contains("new Mesh(")
        && src.contains("scene.add(")
    {
        ctx.push_site(
            sites,
            first_node_id,
            RuleId::ThreePreferInstancedMesh,
            "threePreferInstancedMesh",
            "Mesh",
            "Repeated `new Mesh(sharedGeo, sharedMat)` added in a loop; use `InstancedMesh`."
                .to_string(),
            file_span,
        );
    }
    if src.contains("setAnimationLoop(") {
        if src.contains(".setMatrixAt(") && src.contains("for (") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreePreferGpuInstancedAnimation,
                "threePreferGpuInstancedAnimation",
                "setMatrixAt",
                "Per-instance CPU transform loop inside `setAnimationLoop`; move repeated instance motion to a shader.".to_string(),
                file_span,
            );
        }
        if src.contains("position.setXYZ(") && src.contains("for (") {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreePreferGpuPositionAnimation,
                "threePreferGpuPositionAnimation",
                "setXYZ",
                "Per-vertex CPU position animation inside `setAnimationLoop`; animate positions in a vertex shader.".to_string(),
                file_span,
            );
        }
        if [".rotation.x +=", ".rotation.y +=", ".rotation.z +="]
            .iter()
            .any(|p| src.contains(p))
            && !src.contains("delta")
            && !src.contains("getDelta(")
        {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeRequireFrameDelta,
                "threeRequireFrameDelta",
                "setAnimationLoop",
                "Frame-rate-dependent incremental rotation in animation loop; scale by `clock.getDelta()`.".to_string(),
                file_span,
            );
        }
        if [".fragmentShader =", ".vertexShader =", ".defines."]
            .iter()
            .any(|p| src.contains(p))
        {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeNoShaderConfigurationMutationInAnimationLoop,
                "threeNoShaderConfigurationMutationInAnimationLoop",
                "ShaderMaterial",
                "Do not mutate `ShaderMaterial` shader source or `defines` inside the animation loop.".to_string(),
                file_span,
            );
        }
    }
    if src.contains("addEventListener(\"pointermove\"") {
        if ["new Vector", "new Raycaster", ".clone()"]
            .iter()
            .any(|p| src.contains(p))
        {
            ctx.push_site(
                sites,
                first_node_id,
                RuleId::ThreeNoAllocationInPointerMove,
                "threeNoAllocationInPointerMove",
                "pointermove",
                "Reuse Three.js vectors/raycasters outside the `pointermove` listener.".to_string(),
                file_span,
            );
        }
        for setter in &ctx.state_setters {
            if src.contains(&format!("{setter}(")) {
                ctx.push_site(
                    sites,
                    first_node_id,
                    RuleId::ThreeNoStateInPointerMove,
                    "threeNoStateInPointerMove",
                    setter,
                    "Avoid React state updates inside a continuous `pointermove` listener."
                        .to_string(),
                    file_span,
                );
            }
        }
    }
}

pub(crate) fn check_effect_owned_resource_disposal(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    span: Span,
    ctor: &str,
    effect_body_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let effect_text = effect_body_span.source_text(ctx.source);

    if ctor == "AnimationMixer" {
        if !effect_text.contains(".stopAllAction(") && !effect_text.contains(".uncacheRoot(") {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeRequireAnimationMixerCleanup,
                "threeRequireAnimationMixerCleanup",
                "AnimationMixer",
                "Component-owned `AnimationMixer` actions are not stopped or uncached in React cleanup.".to_string(),
                span,
            );
        }
        return;
    }

    if effect_text.contains(".dispose(") {
        return;
    }

    if THREE_TEXTURE_CTORS.contains(&ctor) {
        for rule in [
            RuleId::ThreeRequireOwnedTextureCleanup,
            RuleId::R3fRequireOwnedTextureCleanup,
        ] {
            ctx.push_site(
                sites,
                node_id,
                rule,
                "requireOwnedTextureCleanup",
                ctor,
                format!(
                    "Locally constructed `{ctor}` has no `.dispose()` call in React effect cleanup."
                ),
                span,
            );
        }
        return;
    }

    if let Some((rule, msg_id, msg)) = classify_single_disposable_three_ctor(ctor) {
        ctx.push_site(sites, node_id, rule, msg_id, ctor, msg, span);
    }
}

fn classify_single_disposable_three_ctor(
    ctor: &str,
) -> Option<(RuleId, &'static str, String)> {
    if ctor.ends_with("Geometry") {
        Some((
            RuleId::ThreeRequireOwnedGeometryCleanup,
            "threeRequireOwnedGeometryCleanup",
            format!("Locally constructed `{ctor}` has no `.dispose()` call in React effect cleanup."),
        ))
    } else if ctor.ends_with("Material") {
        Some((
            RuleId::ThreeRequireOwnedMaterialCleanup,
            "threeRequireOwnedMaterialCleanup",
            format!("Locally constructed `{ctor}` has no `.dispose()` call in React effect cleanup."),
        ))
    } else if THREE_RENDER_TARGET_CTORS.contains(&ctor) || ctor.ends_with("RenderTarget") {
        Some((
            RuleId::ThreeRequireRenderTargetCleanup,
            "threeRequireRenderTargetCleanup",
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
        ))
    } else if matches!(ctor, "WebGLRenderer" | "WebGPURenderer") {
        Some((
            RuleId::ThreeRequireRendererCleanup,
            "threeRequireRendererCleanup",
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
        ))
    } else if THREE_POSTPROCESSING_CTORS.contains(&ctor) {
        Some((
            RuleId::ThreeRequirePostprocessingCleanup,
            "threeRequirePostprocessingCleanup",
            format!("Component-owned postprocessing resource `{ctor}` is not disposed in React effect cleanup."),
        ))
    } else if THREE_CONTROLS_CTORS.contains(&ctor) {
        Some((
            RuleId::ThreeRequireControlsCleanup,
            "threeRequireControlsCleanup",
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
        ))
    } else if ctor == "GPUComputationRenderer" {
        Some((
            RuleId::ThreeRequireGpuComputationCleanup,
            "threeRequireGpuComputationCleanup",
            "Component-owned `GPUComputationRenderer` is not disposed in React cleanup.".to_string(),
        ))
    } else if matches!(ctor, "DRACOLoader" | "KTX2Loader") {
        Some((
            RuleId::ThreeRequireWorkerLoaderCleanup,
            "threeRequireWorkerLoaderCleanup",
            format!("Component-owned worker loader `{ctor}` is not disposed in React cleanup."),
        ))
    } else {
        None
    }
}

pub(crate) fn find_enclosing_effect_body_span(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<Span> {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && matches!(
                extract_callee_short(&call.callee),
                Some("useEffect" | "useLayoutEffect" | "useInsertionEffect")
            )
            && let Some(first) = call.arguments.first().and_then(Argument::as_expression)
        {
            return Some(first.span());
        }
    }
    None
}
