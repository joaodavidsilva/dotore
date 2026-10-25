//! Three.js geometry, material, texture, camera, light, and buffer constructor validation,
//! `useEffect` GPU resource disposal lifecycle (`three-require-*-cleanup`), assignments,
//! and closed scene/canvas contract rule detectors.

use oxc_ast::{
    AstKind,
    ast::{Argument, ArrayExpressionElement, Expression, JSXOpeningElement, NewExpression},
};
use oxc_semantic::NodeId;
use oxc_span::GetSpan;

pub(crate) use super::scene_and_contracts::{
    check_assignments_and_updates, check_scene_and_canvas_contracts,
};
use super::{
    COLOR_SPACE_LINEAR_PROPS, COLOR_SPACE_SRGB_PROPS, DEFAULT_TRANSPARENT_MATERIALS,
    FileAnalysisCtx, PBR_MATERIALS, PHYSICAL_NORMALIZED_PROPS, R3F_BUFFER_ATTR_TAGS,
    R3F_TEXTURE_TAGS, THREE_BUFFER_ATTR_CTORS, UNSUPPORTED_SHADOW_LIGHTS, eval_static_array_len,
    eval_static_f64, get_jsx_args_elem, get_jsx_attr_expr, get_jsx_attr_item,
    is_inside_render_phase, is_valid_shadow_map_size, jsx_attr_is_true, resolve_callee_ctor_name,
    scene_and_contracts::{check_effect_owned_resource_disposal, find_enclosing_effect_body_span},
    webgpu::{
        check_three_material_options, check_webgpu_jsx_material_and_instancing,
        check_webgpu_new_expression,
    },
};
use crate::{ir::types::SemanticRuleSite, rules::RuleId};

pub(crate) fn check_jsx_material_and_light_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    has_spread: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_webgpu_jsx_material_and_instancing(ctx, node_id, opening, tag, sites);
    if has_spread {
        return;
    }

    if tag.ends_with("Material") {
        check_jsx_material_tag_props(ctx, node_id, opening, tag, sites);
    }
    check_jsx_light_and_shadow_props(ctx, node_id, opening, tag, sites);
    check_jsx_camera_fog_and_raycaster_props(ctx, node_id, opening, tag, sites);
    if R3F_BUFFER_ATTR_TAGS.contains(&tag) {
        check_jsx_buffer_attribute_props(ctx, node_id, opening, tag, sites);
    }
    if R3F_TEXTURE_TAGS.contains(&tag) {
        check_jsx_texture_repeat_props(ctx, node_id, opening, sites);
    }
}

fn check_jsx_material_tag_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(op_expr) = get_jsx_attr_expr(opening, "opacity")
        && let Some(op) = eval_static_f64(op_expr)
    {
        if !(0.0..=1.0).contains(&op) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidMaterialOpacity,
                "r3fValidMaterialOpacity",
                "opacity",
                format!("Material opacity is {op}, outside the normalized [0, 1] range."),
                op_expr.span(),
            );
        } else if op < 1.0
            && !DEFAULT_TRANSPARENT_MATERIALS.contains(&tag)
            && !jsx_attr_is_true(opening, "transparent")
            && !jsx_attr_is_true(opening, "alphaHash")
            && get_jsx_attr_expr(opening, "alphaTest")
                .and_then(eval_static_f64)
                .is_none_or(|v| v <= 0.0)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fRequireTransparentForOpacity,
                "r3fRequireTransparentForOpacity",
                "opacity",
                "Material sets `opacity < 1` without `transparent`, `alphaHash`, or `alphaTest`."
                    .to_string(),
                op_expr.span(),
            );
        }
    }

    if tag == "meshBasicMaterial" {
        for ignored in ["roughness", "metalness"] {
            if let Some(attr) = get_jsx_attr_item(opening, ignored) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoIgnoredBasicMaterialProperties,
                    "r3fNoIgnoredBasicMaterialProperties",
                    ignored,
                    format!(
                        "`meshBasicMaterial` ignores `{ignored}`; use `meshStandardMaterial` or `meshPhysicalMaterial`."
                    ),
                    attr.span,
                );
            }
        }
    }

    if matches!(tag, "lineBasicMaterial" | "lineDashedMaterial")
        && let Some(lw_expr) = get_jsx_attr_expr(opening, "linewidth")
        && let Some(lw) = eval_static_f64(lw_expr)
        && (lw - 1.0).abs() > f64::EPSILON
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoIgnoredLinewidth,
            "r3fNoIgnoredLinewidth",
            "linewidth",
            format!(
                "`linewidth={lw}` is ignored by WebGL/WebGPU line primitives; use Drei `<Line>`."
            ),
            lw_expr.span(),
        );
    }

    check_jsx_pbr_and_physical_material_props(ctx, node_id, opening, tag, sites);
    check_jsx_material_texture_color_space(ctx, node_id, opening, sites);
}

fn check_jsx_pbr_and_physical_material_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if PBR_MATERIALS.contains(&tag) {
        for factor in ["roughness", "metalness"] {
            if let Some(expr) = get_jsx_attr_expr(opening, factor)
                && let Some(val) = eval_static_f64(expr)
                && !(0.0..=1.0).contains(&val)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidPbrMaterialProperties,
                    "r3fValidPbrMaterialProperties",
                    factor,
                    format!("PBR `{factor}` is {val}, outside [0, 1]."),
                    expr.span(),
                );
            }
        }
    }

    if tag != "meshPhysicalMaterial" {
        return;
    }
    for prop in PHYSICAL_NORMALIZED_PROPS {
        if let Some(expr) = get_jsx_attr_expr(opening, prop)
            && let Some(val) = eval_static_f64(expr)
            && !(0.0..=1.0).contains(&val)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidPhysicalMaterialProperties,
                "r3fValidPhysicalMaterialProperties",
                prop,
                format!("`{prop}` is {val}, outside [0, 1]."),
                expr.span(),
            );
        }
    }
    for ior_prop in ["ior", "iridescenceIOR"] {
        if let Some(expr) = get_jsx_attr_expr(opening, ior_prop)
            && let Some(val) = eval_static_f64(expr)
            && !(1.0..=2.333).contains(&val)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidPhysicalMaterialProperties,
                "r3fValidPhysicalMaterialProperties",
                ior_prop,
                format!("`{ior_prop}` is {val}, outside [1, 2.333]."),
                expr.span(),
            );
        }
    }
}

fn check_jsx_material_texture_color_space(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for &prop in COLOR_SPACE_SRGB_PROPS
        .iter()
        .chain(COLOR_SPACE_LINEAR_PROPS.iter())
    {
        if let Some(Expression::Identifier(tex_id)) = get_jsx_attr_expr(opening, prop)
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
                    RuleId::R3fValidTextureColorSpace,
                    "r3fValidTextureColorSpace",
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

fn check_jsx_light_and_shadow_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if UNSUPPORTED_SHADOW_LIGHTS.contains(&tag) && jsx_attr_is_true(opening, "castShadow") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoShadowsOnUnsupportedLight,
            "r3fNoShadowsOnUnsupportedLight",
            tag,
            format!(
                "`<{tag}>` cannot cast shadows; use `directionalLight`, `pointLight`, or `spotLight`."
            ),
            opening.span,
        );
    }

    if let Some(Expression::ArrayExpression(arr)) = get_jsx_attr_expr(opening, "shadow-mapSize") {
        for elem in &arr.elements {
            if let Some(expr) = elem.as_expression()
                && let Some(val) = eval_static_f64(expr)
                && !is_valid_shadow_map_size(val)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidShadowMapSize,
                    "r3fValidShadowMapSize",
                    "shadow-mapSize",
                    format!("Shadow map size {val} is not a positive power of two."),
                    expr.span(),
                );
            }
        }
    }
    for dim_attr in ["shadow-mapSize-width", "shadow-mapSize-height"] {
        if let Some(expr) = get_jsx_attr_expr(opening, dim_attr)
            && let Some(val) = eval_static_f64(expr)
            && !is_valid_shadow_map_size(val)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidShadowMapSize,
                "r3fValidShadowMapSize",
                dim_attr,
                format!("Shadow map size {val} is not a positive power of two."),
                expr.span(),
            );
        }
    }

    if tag == "spotLight" {
        check_jsx_spot_light_props(ctx, node_id, opening, sites);
    }
}

fn check_jsx_spot_light_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(angle_expr) =
        get_jsx_attr_expr(opening, "angle").or_else(|| get_jsx_args_elem(opening, 3))
        && let Some(angle) = eval_static_f64(angle_expr)
        && (angle <= 0.0 || angle > std::f64::consts::FRAC_PI_2)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fValidSpotLightProperties,
            "r3fValidSpotLightProperties",
            "angle",
            format!("SpotLight `angle` {angle} must be in (0, Math.PI / 2]."),
            angle_expr.span(),
        );
    }
    if let Some(pen_expr) =
        get_jsx_attr_expr(opening, "penumbra").or_else(|| get_jsx_args_elem(opening, 4))
        && let Some(pen) = eval_static_f64(pen_expr)
        && !(0.0..=1.0).contains(&pen)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fValidSpotLightProperties,
            "r3fValidSpotLightProperties",
            "penumbra",
            format!("SpotLight `penumbra` {pen} must be in [0, 1]."),
            pen_expr.span(),
        );
    }
}

fn check_jsx_camera_fog_and_raycaster_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    match tag {
        "perspectiveCamera" => {
            let fov = get_jsx_attr_or_args_f64(opening, "fov", 0);
            let aspect = get_jsx_attr_or_args_f64(opening, "aspect", 1);
            let near = get_jsx_attr_or_args_f64(opening, "near", 2);
            let far = get_jsx_attr_or_args_f64(opening, "far", 3);
            if is_invalid_perspective_camera_frustum(fov, aspect, near, far) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidPerspectiveCamera,
                    "r3fValidPerspectiveCamera",
                    "perspectiveCamera",
                    "Invalid R3F perspectiveCamera frustum parameters (require fov in (0, 180), aspect > 0, 0 < near < far).".to_string(),
                    opening.span,
                );
            }
        }
        "orthographicCamera" => {
            let left = get_jsx_attr_or_args_f64(opening, "left", 0);
            let right = get_jsx_attr_or_args_f64(opening, "right", 1);
            let top = get_jsx_attr_or_args_f64(opening, "top", 2);
            let bottom = get_jsx_attr_or_args_f64(opening, "bottom", 3);
            let near = get_jsx_attr_or_args_f64(opening, "near", 4);
            let far = get_jsx_attr_or_args_f64(opening, "far", 5);
            if is_invalid_orthographic_camera_frustum(left, right, top, bottom, near, far) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidOrthographicCamera,
                    "r3fValidOrthographicCamera",
                    "orthographicCamera",
                    "Invalid R3F orthographicCamera frustum planes (require left != right, top != bottom, near < far).".to_string(),
                    opening.span,
                );
            }
        }
        "fog" => {
            let near = get_jsx_attr_or_args_f64(opening, "near", 1).unwrap_or(1.0);
            let far = get_jsx_attr_or_args_f64(opening, "far", 2).unwrap_or(1000.0);
            if near < 0.0 || far <= near {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidFogParameters,
                    "r3fValidFogParameters",
                    "fog",
                    "R3F `<fog>` requires `near >= 0` and `far > near`.".to_string(),
                    opening.span,
                );
            }
        }
        "fogExp2" => {
            if get_jsx_attr_or_args_f64(opening, "density", 1).is_some_and(|d| d < 0.0) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidFogParameters,
                    "r3fValidFogParameters",
                    "fogExp2",
                    "R3F `<fogExp2>` requires non-negative `density`.".to_string(),
                    opening.span,
                );
            }
        }
        "raycaster" => {
            let near = get_jsx_attr_or_args_f64(opening, "near", 2);
            let far = get_jsx_attr_or_args_f64(opening, "far", 3);
            if near.is_some_and(|n| n < 0.0) || (near.is_some() && far.is_some() && far < near) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidRaycasterRange,
                    "r3fValidRaycasterRange",
                    "raycaster",
                    "Invalid R3F raycaster range (`near >= 0` and `far >= near` required)."
                        .to_string(),
                    opening.span,
                );
            }
        }
        _ => {}
    }
}

fn get_jsx_attr_or_args_f64(
    opening: &JSXOpeningElement<'_>,
    attr_name: &str,
    arg_idx: usize,
) -> Option<f64> {
    get_jsx_attr_expr(opening, attr_name)
        .or_else(|| get_jsx_args_elem(opening, arg_idx))
        .and_then(eval_static_f64)
}

fn is_invalid_perspective_camera_frustum(
    fov: Option<f64>,
    aspect: Option<f64>,
    near: Option<f64>,
    far: Option<f64>,
) -> bool {
    fov.is_some_and(|v| v <= 0.0 || v >= 180.0)
        || aspect.is_some_and(|v| v <= 0.0)
        || near.is_some_and(|v| v <= 0.0)
        || (near.is_some() && far.is_some() && far <= near)
}

fn is_invalid_orthographic_camera_frustum(
    left: Option<f64>,
    right: Option<f64>,
    top: Option<f64>,
    bottom: Option<f64>,
    near: Option<f64>,
    far: Option<f64>,
) -> bool {
    (left.is_some() && left == right)
        || (top.is_some() && top == bottom)
        || (near.is_some() && far.is_some() && far <= near)
}

fn check_jsx_buffer_attribute_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let arr_expr = get_jsx_args_elem(opening, 0).or_else(|| get_jsx_attr_expr(opening, "array"));
    let item_size_expr =
        get_jsx_args_elem(opening, 1).or_else(|| get_jsx_attr_expr(opening, "itemSize"));
    let norm_expr =
        get_jsx_args_elem(opening, 2).or_else(|| get_jsx_attr_expr(opening, "normalized"));

    if let Some(is_expr) = item_size_expr
        && let Some(item_size) = eval_static_f64(is_expr)
    {
        if item_size < 1.0 || item_size.fract() != 0.0 {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidBufferAttributeItemSize,
                "r3fValidBufferAttributeItemSize",
                "itemSize",
                format!("BufferAttribute `itemSize` {item_size} must be a positive integer."),
                is_expr.span(),
            );
        } else if let Some(a_expr) = arr_expr
            && let Some(arr_len) = eval_static_array_len(a_expr)
        {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "item_size validated >= 1.0 and integer (#50)"
            )]
            let is_usize = item_size as usize;
            if is_usize > 0 && arr_len % is_usize != 0 {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fValidBufferAttributeArrayLength,
                    "r3fValidBufferAttributeArrayLength",
                    "args",
                    format!(
                        "BufferAttribute array length {arr_len} is not divisible by itemSize {is_usize}."
                    ),
                    a_expr.span(),
                );
            }
        }
    }

    let is_normalized_true = norm_expr
        .is_some_and(|e| matches!(e, Expression::BooleanLiteral(b) if b.value))
        || jsx_attr_is_true(opening, "normalized");
    let is_float_attr = matches!(tag, "float16BufferAttribute" | "float32BufferAttribute")
        || arr_expr.is_some_and(|e| is_float_typed_array_source(e.span().source_text(ctx.source)));
    if is_normalized_true && is_float_attr {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoNormalizedFloatBufferAttribute,
            "r3fNoNormalizedFloatBufferAttribute",
            "normalized",
            "BufferAttribute `normalized` only applies to integer data and has no effect on floating-point arrays.".to_string(),
            opening.span,
        );
    }
}

fn is_float_typed_array_source(s: &str) -> bool {
    s.contains("Float32Array") || s.contains("Float64Array") || s.contains("Float16Array")
}

fn check_jsx_texture_repeat_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(Expression::ArrayExpression(rep_arr)) = get_jsx_attr_expr(opening, "repeat") else {
        return;
    };
    let wrap_s_ok = get_jsx_attr_expr(opening, "wrapS").is_some_and(|e| {
        let s = e.span().source_text(ctx.source);
        s.contains("RepeatWrapping") || s.contains("MirroredRepeatWrapping")
    });
    let wrap_t_ok = get_jsx_attr_expr(opening, "wrapT").is_some_and(|e| {
        let s = e.span().source_text(ctx.source);
        s.contains("RepeatWrapping") || s.contains("MirroredRepeatWrapping")
    });
    let rx = rep_arr
        .elements
        .first()
        .and_then(ArrayExpressionElement::as_expression)
        .and_then(eval_static_f64)
        .unwrap_or(1.0);
    let ry = rep_arr
        .elements
        .get(1)
        .and_then(ArrayExpressionElement::as_expression)
        .and_then(eval_static_f64)
        .unwrap_or(1.0);
    if (rx > 1.0 && !wrap_s_ok) || (ry > 1.0 && !wrap_t_ok) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fTextureRepeatRequiresWrapping,
            "r3fTextureRepeatRequiresWrapping",
            "repeat",
            "Texture `repeat > 1` requires `wrapS` / `wrapT` set to `RepeatWrapping` or `MirroredRepeatWrapping`.".to_string(),
            opening.span,
        );
    }
}

pub(crate) fn check_new_expressions_and_lifecycle(
    ctx: &FileAnalysisCtx<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::NewExpression(new_expr) = node.kind() else {
            continue;
        };
        let Some(ctor) = resolve_callee_ctor_name(
            &new_expr.callee,
            &ctx.imported_symbols,
            &ctx.namespace_imports,
        ) else {
            continue;
        };

        if is_inside_render_phase(ctx.semantic, node_id) && is_render_prohibited_three_ctor(&ctor) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeNoObjectConstructionInRender,
                "threeNoObjectConstructionInRender",
                &ctor,
                format!(
                    "`new {ctor}()` creates a fresh mutable Three.js object during React render; move to `useMemo`, `useRef`, or module scope."
                ),
                new_expr.span,
            );
        }

        if let Some(effect_body_span) = find_enclosing_effect_body_span(ctx.semantic, node_id) {
            check_effect_owned_resource_disposal(
                ctx,
                node_id,
                new_expr.span,
                &ctor,
                effect_body_span,
                sites,
            );
        }

        check_webgpu_new_expression(ctx, node_id, new_expr.span, &ctor, sites);
        check_three_constructor_arguments(ctx, node_id, new_expr, &ctor, sites);

        if ctor.ends_with("Material")
            && let Some(Expression::ObjectExpression(obj)) = new_expr
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::without_parentheses)
        {
            check_three_material_options(ctx, node_id, &ctor, obj, sites);
        }
    }
}

fn is_render_prohibited_three_ctor(ctor: &str) -> bool {
    ctor.ends_with("Geometry")
        || ctor.ends_with("Material")
        || matches!(
            ctor,
            "Vector2"
                | "Vector3"
                | "Vector4"
                | "Matrix3"
                | "Matrix4"
                | "Quaternion"
                | "Euler"
                | "Color"
                | "Raycaster"
                | "Box3"
                | "Sphere"
                | "Object3D"
                | "Group"
                | "Mesh"
                | "Scene"
        )
}

fn check_three_constructor_arguments(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    ctor: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    match ctor {
        "PerspectiveCamera" | "OrthographicCamera" | "SpotLight" | "Fog" | "FogExp2" => {
            check_three_camera_light_or_fog_ctor(ctx, node_id, new_expr, ctor, sites);
        }
        "Raycaster" => {
            let near = get_new_arg_f64(new_expr, 2);
            let far = get_new_arg_f64(new_expr, 3);
            if near.is_some_and(|n| n < 0.0) || (near.is_some() && far.is_some() && far < near) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidRaycasterRange,
                    "threeValidRaycasterRange",
                    "Raycaster",
                    "Invalid `Raycaster` distance range (`near >= 0` and `far >= near` required)."
                        .to_string(),
                    new_expr.span,
                );
            }
        }
        "DataTexture" | "Data3DTexture" | "DataArrayTexture" => {
            check_three_data_texture_ctor(ctx, node_id, new_expr, ctor, sites);
        }
        "GPUComputationRenderer" => {
            let w = get_new_arg_f64(new_expr, 0);
            let h = get_new_arg_f64(new_expr, 1);
            if w.is_some_and(|v| v < 1.0 || v.fract() != 0.0)
                || h.is_some_and(|v| v < 1.0 || v.fract() != 0.0)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidGpuComputationDimensions,
                    "threeValidGpuComputationDimensions",
                    "GPUComputationRenderer",
                    "GPUComputationRenderer width and height must be positive integers."
                        .to_string(),
                    new_expr.span,
                );
            }
        }
        _ if THREE_BUFFER_ATTR_CTORS.contains(&ctor) => {
            check_three_buffer_attribute_ctor(ctx, node_id, new_expr, ctor, sites);
        }
        _ => {}
    }
}

fn check_three_camera_light_or_fog_ctor(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    ctor: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    match ctor {
        "PerspectiveCamera" => {
            if is_invalid_perspective_camera_frustum(
                get_new_arg_f64(new_expr, 0),
                get_new_arg_f64(new_expr, 1),
                get_new_arg_f64(new_expr, 2),
                get_new_arg_f64(new_expr, 3),
            ) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidPerspectiveCamera,
                    "threeValidPerspectiveCamera",
                    "PerspectiveCamera",
                    "Invalid `PerspectiveCamera` frustum parameters (require fov in (0, 180), aspect > 0, 0 < near < far).".to_string(),
                    new_expr.span,
                );
            }
        }
        "OrthographicCamera" => {
            if is_invalid_orthographic_camera_frustum(
                get_new_arg_f64(new_expr, 0),
                get_new_arg_f64(new_expr, 1),
                get_new_arg_f64(new_expr, 2),
                get_new_arg_f64(new_expr, 3),
                get_new_arg_f64(new_expr, 4),
                get_new_arg_f64(new_expr, 5),
            ) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidOrthographicCamera,
                    "threeValidOrthographicCamera",
                    "OrthographicCamera",
                    "Invalid `OrthographicCamera` frustum planes (require left != right, top != bottom, near < far).".to_string(),
                    new_expr.span,
                );
            }
        }
        "SpotLight" => check_three_spot_light_ctor(ctx, node_id, new_expr, sites),
        "Fog" => {
            let near = get_new_arg_f64(new_expr, 1).unwrap_or(1.0);
            let far = get_new_arg_f64(new_expr, 2).unwrap_or(1000.0);
            if near < 0.0 || far <= near {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidFogParameters,
                    "threeValidFogParameters",
                    "Fog",
                    "`new Fog(...)` requires `near >= 0` and `far > near`.".to_string(),
                    new_expr.span,
                );
            }
        }
        "FogExp2" if get_new_arg_f64(new_expr, 1).is_some_and(|d| d < 0.0) => {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidFogParameters,
                "threeValidFogParameters",
                "FogExp2",
                "`new FogExp2(...)` requires non-negative `density`.".to_string(),
                new_expr.span,
            );
        }
        _ => {}
    }
}

fn check_three_spot_light_ctor(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(angle) = get_new_arg_f64(new_expr, 3)
        && (angle <= 0.0 || angle > std::f64::consts::FRAC_PI_2)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeValidSpotLightProperties,
            "threeValidSpotLightProperties",
            "angle",
            format!("SpotLight `angle` {angle} must be in (0, Math.PI / 2]."),
            new_expr.span,
        );
    }
    if let Some(pen) = get_new_arg_f64(new_expr, 4)
        && !(0.0..=1.0).contains(&pen)
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeValidSpotLightProperties,
            "threeValidSpotLightProperties",
            "penumbra",
            format!("SpotLight `penumbra` {pen} must be in [0, 1]."),
            new_expr.span,
        );
    }
}

fn check_three_buffer_attribute_ctor(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    ctor: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(item_size) = get_new_arg_f64(new_expr, 1) {
        if item_size < 1.0 || item_size.fract() != 0.0 {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidBufferAttributeItemSize,
                "threeValidBufferAttributeItemSize",
                "itemSize",
                format!("BufferAttribute `itemSize` {item_size} must be a positive integer."),
                new_expr.span,
            );
        } else if let Some(arr_expr) = new_expr.arguments.first().and_then(Argument::as_expression)
            && let Some(arr_len) = eval_static_array_len(arr_expr)
        {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "validated >= 1.0 integer (#50)"
            )]
            let is_usize = item_size as usize;
            if is_usize > 0 && arr_len % is_usize != 0 {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidBufferAttributeArrayLength,
                    "threeValidBufferAttributeArrayLength",
                    ctor,
                    format!(
                        "BufferAttribute array length {arr_len} is not divisible by itemSize {is_usize}."
                    ),
                    arr_expr.span(),
                );
            }
        }
    }
    if let Some(norm_expr) = new_expr.arguments.get(2).and_then(Argument::as_expression)
        && matches!(norm_expr.without_parentheses(), Expression::BooleanLiteral(b) if b.value)
    {
        let is_float = matches!(ctor, "Float16BufferAttribute" | "Float32BufferAttribute")
            || new_expr
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .is_some_and(|e| is_float_typed_array_source(e.span().source_text(ctx.source)));
        if is_float {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeNoNormalizedFloatBufferAttribute,
                "threeNoNormalizedFloatBufferAttribute",
                ctor,
                "BufferAttribute `normalized` only applies to integer data and has no effect on floating-point arrays.".to_string(),
                norm_expr.span(),
            );
        }
    }
}

fn check_three_data_texture_ctor(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    new_expr: &NewExpression<'_>,
    ctor: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let w = get_new_arg_f64(new_expr, 1).unwrap_or(1.0);
    let h = get_new_arg_f64(new_expr, 2).unwrap_or(1.0);
    let d = if ctor == "DataTexture" {
        1.0
    } else {
        get_new_arg_f64(new_expr, 3).unwrap_or(1.0)
    };
    if [w, h, d].iter().any(|&v| v < 1.0 || v.fract() != 0.0) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeValidDataTextureDimensions,
            "threeValidDataTextureDimensions",
            ctor,
            "DataTexture dimensions must be positive integers.".to_string(),
            new_expr.span,
        );
    } else if let Some(data_expr) = new_expr.arguments.first().and_then(Argument::as_expression)
        && let Some(data_len) = eval_static_array_len(data_expr)
    {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "validated >= 1.0 integer dimensions (#50)"
        )]
        let required = (w as usize) * (h as usize) * (d as usize) * 4;
        if data_len < required {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeValidDataTextureDataLength,
                "threeValidDataTextureDataLength",
                ctor,
                format!(
                    "DataTexture storage length {data_len} is smaller than required {required} elements."
                ),
                data_expr.span(),
            );
        }
    }
}

fn get_new_arg_f64(new_expr: &oxc_ast::ast::NewExpression<'_>, index: usize) -> Option<f64> {
    let expr = new_expr.arguments.get(index)?.as_expression()?;
    eval_static_f64(expr)
}

