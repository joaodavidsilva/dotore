//! Three.js geometry, material, texture, camera, light, and buffer constructor validation,
//! `useEffect` GPU resource disposal lifecycle (`three-require-*-cleanup`), assignments,
//! and closed scene/canvas contract rule detectors.
#![expect(
    clippy::excessive_nesting,
    reason = "Single-pass AST pattern matching inspects nested JSX, CallExpression, and ObjectExpression trees directly"
)]

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrayExpressionElement, AssignmentTarget, Expression, JSXChild, JSXElement,
        JSXOpeningElement, ObjectExpression,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    COLOR_SPACE_LINEAR_PROPS, COLOR_SPACE_SRGB_PROPS, DEFAULT_TRANSPARENT_MATERIALS,
    FileAnalysisCtx, LIT_MATERIALS, PBR_MATERIALS, PHYSICAL_NORMALIZED_PROPS, R3F_BUFFER_ATTR_TAGS,
    R3F_TEXTURE_TAGS, THREE_BUFFER_ATTR_CTORS, THREE_CONTROLS_CTORS, THREE_LIGHT_TAGS_AND_CTORS,
    THREE_POSTPROCESSING_CTORS, THREE_RENDER_TARGET_CTORS, THREE_TEXTURE_CTORS,
    UNSUPPORTED_SHADOW_LIGHTS, UV_MAPPED_MATERIALS, eval_static_array_len, eval_static_f64,
    extract_callee_short, extract_root_ident_name, get_jsx_args_elem, get_jsx_attr_expr,
    get_jsx_attr_item, get_obj_prop_expr, is_inside_render_phase, is_valid_shadow_map_size,
    jsx_attr_is_true, jsx_opening_tag_name, resolve_callee_ctor_name,
    webgpu::{
        check_webgpu_assignment, check_webgpu_jsx_material_and_instancing,
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

    // Material rules
    if tag.ends_with("Material") {
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
                    "Material sets `opacity < 1` without `transparent`, `alphaHash`, or `alphaTest`.".to_string(),
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

        if tag == "meshPhysicalMaterial" {
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

        // `r3f-valid-texture-color-space`
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

    // Lights & Shadows (`r3f-no-shadows-on-unsupported-light`, `r3f-valid-shadow-map-size`, `r3f-valid-spot-light-properties`)
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

    if let Some(map_size_expr) = get_jsx_attr_expr(opening, "shadow-mapSize")
        && let Expression::ArrayExpression(arr) = map_size_expr
    {
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

    // Cameras (`r3f-valid-perspective-camera`, `r3f-valid-orthographic-camera`)
    if tag == "perspectiveCamera" {
        let fov = get_jsx_attr_expr(opening, "fov")
            .or_else(|| get_jsx_args_elem(opening, 0))
            .and_then(eval_static_f64);
        let aspect = get_jsx_attr_expr(opening, "aspect")
            .or_else(|| get_jsx_args_elem(opening, 1))
            .and_then(eval_static_f64);
        let near = get_jsx_attr_expr(opening, "near")
            .or_else(|| get_jsx_args_elem(opening, 2))
            .and_then(eval_static_f64);
        let far = get_jsx_attr_expr(opening, "far")
            .or_else(|| get_jsx_args_elem(opening, 3))
            .and_then(eval_static_f64);
        if fov.is_some_and(|v| v <= 0.0 || v >= 180.0)
            || aspect.is_some_and(|v| v <= 0.0)
            || near.is_some_and(|v| v <= 0.0)
            || (near.is_some() && far.is_some() && far <= near)
        {
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

    if tag == "orthographicCamera" {
        let left = get_jsx_attr_expr(opening, "left")
            .or_else(|| get_jsx_args_elem(opening, 0))
            .and_then(eval_static_f64);
        let right = get_jsx_attr_expr(opening, "right")
            .or_else(|| get_jsx_args_elem(opening, 1))
            .and_then(eval_static_f64);
        let top = get_jsx_attr_expr(opening, "top")
            .or_else(|| get_jsx_args_elem(opening, 2))
            .and_then(eval_static_f64);
        let bottom = get_jsx_attr_expr(opening, "bottom")
            .or_else(|| get_jsx_args_elem(opening, 3))
            .and_then(eval_static_f64);
        let near = get_jsx_attr_expr(opening, "near")
            .or_else(|| get_jsx_args_elem(opening, 4))
            .and_then(eval_static_f64);
        let far = get_jsx_attr_expr(opening, "far")
            .or_else(|| get_jsx_args_elem(opening, 5))
            .and_then(eval_static_f64);
        if (left.is_some() && left == right)
            || (top.is_some() && top == bottom)
            || (near.is_some() && far.is_some() && far <= near)
        {
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

    // Fog & Raycaster (`r3f-valid-fog-parameters`, `r3f-valid-raycaster-range`)
    if tag == "fog" {
        let near = get_jsx_attr_expr(opening, "near")
            .or_else(|| get_jsx_args_elem(opening, 1))
            .and_then(eval_static_f64)
            .unwrap_or(1.0);
        let far = get_jsx_attr_expr(opening, "far")
            .or_else(|| get_jsx_args_elem(opening, 2))
            .and_then(eval_static_f64)
            .unwrap_or(1000.0);
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
    } else if tag == "fogExp2" {
        let density = get_jsx_attr_expr(opening, "density")
            .or_else(|| get_jsx_args_elem(opening, 1))
            .and_then(eval_static_f64);
        if density.is_some_and(|d| d < 0.0) {
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

    if tag == "raycaster" {
        let near = get_jsx_attr_expr(opening, "near")
            .or_else(|| get_jsx_args_elem(opening, 2))
            .and_then(eval_static_f64);
        let far = get_jsx_attr_expr(opening, "far")
            .or_else(|| get_jsx_args_elem(opening, 3))
            .and_then(eval_static_f64);
        if near.is_some_and(|n| n < 0.0) || (near.is_some() && far.is_some() && far < near) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fValidRaycasterRange,
                "r3fValidRaycasterRange",
                "raycaster",
                "Invalid R3F raycaster range (`near >= 0` and `far >= near` required).".to_string(),
                opening.span,
            );
        }
    }

    // BufferAttributes (`r3f-valid-buffer-attribute-item-size`, `r3f-valid-buffer-attribute-array-length`, `r3f-no-normalized-float-buffer-attribute`)
    if R3F_BUFFER_ATTR_TAGS.contains(&tag) {
        let arr_expr =
            get_jsx_args_elem(opening, 0).or_else(|| get_jsx_attr_expr(opening, "array"));
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
                    reason = "item_size validated >= 1.0 and integer"
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
            || arr_expr.is_some_and(|e| {
                let s = e.span().source_text(ctx.source);
                s.contains("Float32Array")
                    || s.contains("Float64Array")
                    || s.contains("Float16Array")
            });
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

    // Texture repeat (`r3f-texture-repeat-requires-wrapping`)
    if R3F_TEXTURE_TAGS.contains(&tag)
        && let Some(Expression::ArrayExpression(rep_arr)) = get_jsx_attr_expr(opening, "repeat")
    {
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

        // 1. `three-no-object-construction-in-render`
        if is_inside_render_phase(ctx.semantic, node_id)
            && (ctor.ends_with("Geometry")
                || ctor.ends_with("Material")
                || matches!(
                    ctor.as_str(),
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
                ))
        {
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

        // 2. Resource disposal in `useEffect` (`three-require-*-cleanup` / `r3f-require-owned-texture-cleanup`)
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

        // 3. WebGPU legacy material & EffectComposer (`three-webgpu-no-legacy-material-api`, `three-webgpu-no-legacy-effect-composer`)
        check_webgpu_new_expression(ctx, node_id, new_expr.span, &ctor, sites);

        // 4. Camera, light, fog, raycaster, buffer, and texture constructors
        if ctor == "PerspectiveCamera" {
            let fov = get_new_arg_f64(new_expr, 0);
            let aspect = get_new_arg_f64(new_expr, 1);
            let near = get_new_arg_f64(new_expr, 2);
            let far = get_new_arg_f64(new_expr, 3);
            if fov.is_some_and(|v| v <= 0.0 || v >= 180.0)
                || aspect.is_some_and(|v| v <= 0.0)
                || near.is_some_and(|v| v <= 0.0)
                || (near.is_some() && far.is_some() && far <= near)
            {
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
        } else if ctor == "OrthographicCamera" {
            let left = get_new_arg_f64(new_expr, 0);
            let right = get_new_arg_f64(new_expr, 1);
            let top = get_new_arg_f64(new_expr, 2);
            let bottom = get_new_arg_f64(new_expr, 3);
            let near = get_new_arg_f64(new_expr, 4);
            let far = get_new_arg_f64(new_expr, 5);
            if (left.is_some() && left == right)
                || (top.is_some() && top == bottom)
                || (near.is_some() && far.is_some() && far <= near)
            {
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
        } else if ctor == "SpotLight" {
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
        } else if ctor == "Fog" {
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
        } else if ctor == "FogExp2" {
            if let Some(density) = get_new_arg_f64(new_expr, 1)
                && density < 0.0
            {
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
        } else if ctor == "Raycaster" {
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
        } else if THREE_BUFFER_ATTR_CTORS.contains(&ctor.as_str()) {
            if let Some(item_size) = get_new_arg_f64(new_expr, 1) {
                if item_size < 1.0 || item_size.fract() != 0.0 {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeValidBufferAttributeItemSize,
                        "threeValidBufferAttributeItemSize",
                        "itemSize",
                        format!(
                            "BufferAttribute `itemSize` {item_size} must be a positive integer."
                        ),
                        new_expr.span,
                    );
                } else if let Some(arr_expr) =
                    new_expr.arguments.first().and_then(Argument::as_expression)
                    && let Some(arr_len) = eval_static_array_len(arr_expr)
                {
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "validated >= 1.0 integer"
                    )]
                    let is_usize = item_size as usize;
                    if is_usize > 0 && arr_len % is_usize != 0 {
                        ctx.push_site(
                            sites,
                            node_id,
                            RuleId::ThreeValidBufferAttributeArrayLength,
                            "threeValidBufferAttributeArrayLength",
                            &ctor,
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
                let is_float = matches!(
                    ctor.as_str(),
                    "Float16BufferAttribute" | "Float32BufferAttribute"
                ) || new_expr
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .is_some_and(|e| {
                        let s = e.span().source_text(ctx.source);
                        s.contains("Float32Array")
                            || s.contains("Float64Array")
                            || s.contains("Float16Array")
                    });
                if is_float {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeNoNormalizedFloatBufferAttribute,
                        "threeNoNormalizedFloatBufferAttribute",
                        &ctor,
                        "BufferAttribute `normalized` only applies to integer data and has no effect on floating-point arrays.".to_string(),
                        norm_expr.span(),
                    );
                }
            }
        } else if matches!(
            ctor.as_str(),
            "DataTexture" | "Data3DTexture" | "DataArrayTexture"
        ) {
            let w = get_new_arg_f64(new_expr, 1).unwrap_or(1.0);
            let h = get_new_arg_f64(new_expr, 2).unwrap_or(1.0);
            let d = if ctor == "DataTexture" {
                1.0
            } else {
                get_new_arg_f64(new_expr, 3).unwrap_or(1.0)
            };
            if w < 1.0
                || w.fract() != 0.0
                || h < 1.0
                || h.fract() != 0.0
                || d < 1.0
                || d.fract() != 0.0
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeValidDataTextureDimensions,
                    "threeValidDataTextureDimensions",
                    &ctor,
                    "DataTexture dimensions must be positive integers.".to_string(),
                    new_expr.span,
                );
            } else if let Some(data_expr) =
                new_expr.arguments.first().and_then(Argument::as_expression)
                && let Some(data_len) = eval_static_array_len(data_expr)
            {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "validated >= 1.0 integer dimensions"
                )]
                let required = (w as usize) * (h as usize) * (d as usize) * 4;
                if data_len < required {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeValidDataTextureDataLength,
                        "threeValidDataTextureDataLength",
                        &ctor,
                        format!(
                            "DataTexture storage length {data_len} is smaller than required {required} elements."
                        ),
                        data_expr.span(),
                    );
                }
            }
        } else if ctor == "GPUComputationRenderer" {
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

        // 5. Material options object validation (`three-valid-material-opacity`, `three-require-transparent-for-opacity`, `three-valid-pbr-material-properties`, `three-valid-physical-material-properties`, `three-no-ignored-basic-material-properties`, `three-no-ignored-linewidth`, `three-valid-texture-color-space`)
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

fn check_three_material_options(
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

    if ctor == "MeshPhysicalMaterial" {
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

fn check_effect_owned_resource_disposal(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    span: Span,
    ctor: &str,
    effect_body_span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let effect_text = effect_body_span.source_text(ctx.source);

    if ctor.ends_with("Geometry") && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireOwnedGeometryCleanup,
            "threeRequireOwnedGeometryCleanup",
            ctor,
            format!(
                "Locally constructed `{ctor}` has no `.dispose()` call in React effect cleanup."
            ),
            span,
        );
    } else if ctor.ends_with("Material") && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireOwnedMaterialCleanup,
            "threeRequireOwnedMaterialCleanup",
            ctor,
            format!(
                "Locally constructed `{ctor}` has no `.dispose()` call in React effect cleanup."
            ),
            span,
        );
    } else if THREE_TEXTURE_CTORS.contains(&ctor) && !effect_text.contains(".dispose(") {
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
    } else if (THREE_RENDER_TARGET_CTORS.contains(&ctor) || ctor.ends_with("RenderTarget"))
        && !effect_text.contains(".dispose(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireRenderTargetCleanup,
            "threeRequireRenderTargetCleanup",
            ctor,
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
            span,
        );
    } else if matches!(ctor, "WebGLRenderer" | "WebGPURenderer")
        && !effect_text.contains(".dispose(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireRendererCleanup,
            "threeRequireRendererCleanup",
            ctor,
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
            span,
        );
    } else if THREE_POSTPROCESSING_CTORS.contains(&ctor) && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequirePostprocessingCleanup,
            "threeRequirePostprocessingCleanup",
            ctor,
            format!(
                "Component-owned postprocessing resource `{ctor}` is not disposed in React effect cleanup."
            ),
            span,
        );
    } else if THREE_CONTROLS_CTORS.contains(&ctor) && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireControlsCleanup,
            "threeRequireControlsCleanup",
            ctor,
            format!("Component-owned `{ctor}` is not disposed in React effect cleanup."),
            span,
        );
    } else if ctor == "AnimationMixer"
        && !effect_text.contains(".stopAllAction(")
        && !effect_text.contains(".uncacheRoot(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireAnimationMixerCleanup,
            "threeRequireAnimationMixerCleanup",
            "AnimationMixer",
            "Component-owned `AnimationMixer` actions are not stopped or uncached in React cleanup."
                .to_string(),
            span,
        );
    } else if ctor == "GPUComputationRenderer" && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireGpuComputationCleanup,
            "threeRequireGpuComputationCleanup",
            "GPUComputationRenderer",
            "Component-owned `GPUComputationRenderer` is not disposed in React cleanup."
                .to_string(),
            span,
        );
    } else if matches!(ctor, "DRACOLoader" | "KTX2Loader") && !effect_text.contains(".dispose(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireWorkerLoaderCleanup,
            "threeRequireWorkerLoaderCleanup",
            ctor,
            format!("Component-owned worker loader `{ctor}` is not disposed in React cleanup."),
            span,
        );
    }
}

fn find_enclosing_effect_body_span(semantic: &Semantic<'_>, node_id: NodeId) -> Option<Span> {
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

fn get_new_arg_f64(new_expr: &oxc_ast::ast::NewExpression<'_>, index: usize) -> Option<f64> {
    let expr = new_expr.arguments.get(index)?.as_expression()?;
    eval_static_f64(expr)
}

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
        let prop = mem.property.name.as_str();
        let root_ident = extract_root_ident_name(&mem.object);

        // 1. `r3f-no-mutate-loader-cache`
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

        // 2. `three-no-shadows-on-unsupported-light`
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

        // 3. `three-webgpu-no-high-precision-instancing`, `three-webgpu-no-legacy-material-api`, & `three-on-before-compile-require-program-cache-key`
        let handled_webgpu_on_before =
            check_webgpu_assignment(ctx, node_id, assign, mem, prop, sites);
        if !handled_webgpu_on_before
            && prop == "onBeforeCompile"
            && !ctx.source.contains("customProgramCacheKey")
        {
            let rhs_text = assign.right.span().source_text(ctx.source);
            if rhs_text.contains(".defines")
                || rhs_text.contains(".vertexShader")
                || rhs_text.contains(".fragmentShader")
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

        // 4. `r3f-require-projection-matrix-update` & `three-require-projection-matrix-update`
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

        // 1. `<Canvas>` closed-scene contracts (`r3f-require-shadows-enabled`, `r3f-require-lighting-for-pbr`, `r3f-require-environment-for-metal`)
        if tag == "Canvas" {
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
                || canvas_text.contains("<Environment")
                || canvas_text.contains("envMap=")
                || canvas_text.contains("lightMap=")
                || canvas_text.contains("emissive=");
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
        }

        // 2. `r3f-limit-shadowed-point-lights`
        let direct_shadow_point_lights: Vec<&JSXElement<'_>> = el
            .children
            .iter()
            .filter_map(|child| {
                if let JSXChild::Element(child_el) = child
                    && jsx_opening_tag_name(&child_el.opening_element).as_deref()
                        == Some("pointLight")
                    && jsx_attr_is_true(&child_el.opening_element, "castShadow")
                {
                    Some(child_el.as_ref())
                } else {
                    None
                }
            })
            .collect();
        if direct_shadow_point_lights.len() > 2 {
            for extra in &direct_shadow_point_lights[2..] {
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
        // 3. `<Canvas>` metal environment (`r3f-require-environment-for-metal`)
        if tag == "Canvas" {
            let canvas_text = el.span.source_text(ctx.source);
            if (canvas_text.contains("metalness={1")
                || canvas_text.contains("metalness={0.8")
                || canvas_text.contains("metalness={0.9"))
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

        // 4. `<mesh>` custom `<bufferGeometry>` UVs and normals (`r3f-require-lit-material-normals`, `r3f-require-uv-for-texture-map`)
        if tag == "mesh" {
            let mesh_text = el.span.source_text(ctx.source);
            if mesh_text.contains("<bufferGeometry") && mesh_text.contains("attributes-position") {
                let has_normal_attr = mesh_text.contains("attributes-normal");
                let has_uv_attr = mesh_text.contains("attributes-uv");
                if !has_normal_attr
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
                        "Normal-mapped R3F `<bufferGeometry>` defines `position` without a `normal` attribute.".to_string(),
                        el.opening_element.span,
                    );
                }
                if !has_uv_attr
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
                        "Texture-mapped R3F `<bufferGeometry>` defines `position` without a `uv` attribute.".to_string(),
                        el.opening_element.span,
                    );
                }
            }
        }
    }

    // Imperative Three.js scene, renderer, mixer, controls, buffer, and resize contracts
    check_imperative_three_scene_contracts(ctx, sites);
}

fn check_imperative_three_scene_contracts(
    ctx: &FileAnalysisCtx<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let src = ctx.source;
    let Some((first_node_id, first_node)) = ctx.semantic.nodes().iter_enumerated().next() else {
        return;
    };
    let file_span = first_node.span();

    // 1. `r3f-no-manual-canvas-resize`
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

    // 2. `r3f-no-mutate-uniform-prop-source-in-use-frame`
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

    // 3. `r3f-require-animation-mixer-update` & `three-require-animation-mixer-update`
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

    // 4. `three-require-controls-update`
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

    // 5. `r3f-require-data-texture-update` & `three-require-data-texture-update`
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

    // 6. `r3f-require-dynamic-buffer-usage` & `three-require-dynamic-buffer-usage`
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

    // 7. `r3f-require-position-buffer-update` & `three-require-position-buffer-update`
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

    // 8. `three-effect-composer-output-pass-last` & `three-effect-composer-require-size-on-resize`
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

    // 9. `three-require-camera-aspect-on-resize`, `three-require-renderer-dom-attachment`, `three-require-renderer-size`
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

    // 10. `three-require-shadows-enabled`, `three-limit-shadowed-point-lights`, `three-require-render-target-reset`, `three-require-texture-update-after-wrapping-change`
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
        && !src[wrap_pos..].contains(".needsUpdate = true")
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

    // 11. `three-require-lighting-for-pbr`, `three-require-environment-for-metal`, `three-require-lit-material-normals`, `three-require-uv-for-texture-map`
    if !ctx.has_r3f_import
        && src.contains("new Scene(")
        && src.contains("renderer.render(")
        && (src.contains("new MeshStandardMaterial(") || src.contains("new MeshPhysicalMaterial("))
    {
        let has_light = THREE_LIGHT_TAGS_AND_CTORS
            .iter()
            .any(|l| src.contains(&format!("new {l}(")))
            || src.contains(".environment =")
            || src.contains("envMap:")
            || src.contains("emissive:");
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
        if (src.contains("metalness: 1")
            || src.contains("metalness: 0.9")
            || src.contains("metalness: 0.8"))
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
    if !ctx.has_r3f_import
        && src.contains("new BufferGeometry(")
        && src.contains("setAttribute(\"position\"")
    {
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

    // 12. `three-prefer-instanced-mesh`, `three-prefer-gpu-instanced-animation`, `three-prefer-gpu-position-animation`, `three-require-frame-delta`, `three-no-shader-configuration-mutation-in-animation-loop`, `three-no-allocation-in-pointer-move`, `three-no-state-in-pointer-move`
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
        if (src.contains(".rotation.x +=")
            || src.contains(".rotation.y +=")
            || src.contains(".rotation.z +="))
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
        if src.contains(".fragmentShader =")
            || src.contains(".vertexShader =")
            || src.contains(".defines.")
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
        if src.contains("new Vector") || src.contains("new Raycaster") || src.contains(".clone()") {
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
