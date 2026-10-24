//! WebGL & GLSL shader (`three-shader-*`, `three-raw-shader-*`) stage analysis,
//! uniform/varying compatibility, and `RawShaderMaterial` rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{Argument, Expression, ObjectExpression, ObjectPropertyKind},
};
use oxc_semantic::NodeId;
use oxc_span::{GetSpan, Span};

use super::{FileAnalysisCtx, THREE_SHADER_BUILTINS, get_obj_prop_expr, resolve_callee_ctor_name};
use crate::{ir::types::SemanticRuleSite, rules::RuleId};

pub(crate) fn check_shader_materials(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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
        if !matches!(ctor.as_str(), "ShaderMaterial" | "RawShaderMaterial") {
            continue;
        }
        let Some(Expression::ObjectExpression(obj)) = new_expr
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .map(Expression::without_parentheses)
        else {
            continue;
        };

        let is_raw = ctor == "RawShaderMaterial";
        let is_glsl3 = get_obj_prop_expr(obj, "glslVersion")
            .is_some_and(|e| e.span().source_text(ctx.source).contains("GLSL3"));

        let vert = get_obj_prop_expr(obj, "vertexShader")
            .and_then(|e| extract_static_string(e).map(|s| (s, e.span())));
        let frag = get_obj_prop_expr(obj, "fragmentShader")
            .and_then(|e| extract_static_string(e).map(|s| (s, e.span())));

        if let Some((vsrc, vspan)) = &vert {
            check_single_glsl_stage(ctx, node_id, vsrc, *vspan, true, is_raw, is_glsl3, sites);
        }
        if let Some((fsrc, fspan)) = &frag {
            check_single_glsl_stage(ctx, node_id, fsrc, *fspan, false, is_raw, is_glsl3, sites);
        }
        check_shader_material_pair_and_uniforms(
            ctx,
            node_id,
            obj,
            vert.as_ref().map(|(s, _)| s.as_str()),
            frag.as_ref().map(|(s, _)| s.as_str()),
            new_expr.span,
            sites,
        );
    }
}

fn extract_static_string(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::StringLiteral(s) => s.value.as_str().map(ToString::to_string),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => {
            t.quasis.first().and_then(|q| {
                q.value
                    .cooked
                    .as_ref()
                    .and_then(|c| c.as_str())
                    .map(ToString::to_string)
            })
        }
        _ => None,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Passes stage flags (is_vertex, is_raw, is_glsl3) directly to avoid wrapper struct boilerplate"
)]
fn check_single_glsl_stage(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    glsl: &str,
    span: Span,
    is_vertex: bool,
    is_raw: bool,
    is_glsl3: bool,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. `three-shader-no-version-directive`
    if glsl.lines().any(|l| l.trim_start().starts_with("#version")) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoVersionDirective,
            "threeShaderNoVersionDirective",
            "#version",
            "Set `glslVersion` on the material instead of writing `#version` in shader source."
                .to_string(),
            span,
        );
    }

    // 2. `three-shader-no-reserved-identifiers`
    for token in glsl.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if (token.starts_with("gl_")
            && !matches!(
                token,
                "gl_Position"
                    | "gl_FragColor"
                    | "gl_FragCoord"
                    | "gl_FragDepth"
                    | "gl_FragData"
                    | "gl_FrontFacing"
                    | "gl_PointCoord"
                    | "gl_PointSize"
                    | "gl_VertexID"
                    | "gl_InstanceID"
            ))
            || token.contains("__")
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeShaderNoReservedIdentifiers,
                "threeShaderNoReservedIdentifiers",
                token,
                format!("Shader declares reserved GLSL identifier `{token}`."),
                span,
            );
            break;
        }
    }

    // 3. `three-shader-no-redeclared-builtins`
    if !is_raw {
        for builtin in THREE_SHADER_BUILTINS {
            if glsl.contains(&format!("attribute vec3 {builtin}"))
                || glsl.contains(&format!("attribute vec2 {builtin}"))
                || glsl.contains(&format!("uniform mat4 {builtin}"))
                || glsl.contains(&format!("uniform mat3 {builtin}"))
                || glsl.contains(&format!("uniform vec3 {builtin}"))
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeShaderNoRedeclaredBuiltins,
                    "threeShaderNoRedeclaredBuiltins",
                    builtin,
                    format!("`ShaderMaterial` automatically provides built-in `{builtin}`; do not redeclare it."),
                    span,
                );
                break;
            }
        }
    }

    // 4. `three-raw-shader-require-fragment-float-precision`
    if is_raw
        && !is_vertex
        && !glsl.contains("precision ")
        && (glsl.contains("float ")
            || glsl.contains("vec2 ")
            || glsl.contains("vec3 ")
            || glsl.contains("vec4 "))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRawShaderRequireFragmentFloatPrecision,
            "threeRawShaderRequireFragmentFloatPrecision",
            "RawShaderMaterial",
            "`RawShaderMaterial` fragment shader lacks a default `precision mediump float;` or `precision highp float;` declaration.".to_string(),
            span,
        );
    }

    // 5. `three-raw-shader-require-glsl3-version` & `three-shader-no-glsl1-syntax-with-glsl3`
    if is_raw
        && !is_glsl3
        && (glsl.contains("\nin ")
            || glsl.contains("\nout ")
            || glsl.starts_with("in ")
            || glsl.starts_with("out "))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRawShaderRequireGlsl3Version,
            "threeRawShaderRequireGlsl3Version",
            "glslVersion",
            "`RawShaderMaterial` uses GLSL 3 syntax without `glslVersion: THREE.GLSL3`."
                .to_string(),
            span,
        );
    }
    if is_glsl3
        && (glsl.contains("texture2D(")
            || glsl.contains("gl_FragColor")
            || glsl.contains("varying ")
            || glsl.contains("attribute "))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoGlsl1SyntaxWithGlsl3,
            "threeShaderNoGlsl1SyntaxWithGlsl3",
            "glslVersion",
            "GLSL 3 shader uses legacy GLSL 1 syntax (`attribute`, `varying`, `texture2D`, `gl_FragColor`).".to_string(),
            span,
        );
    }

    // 6. `three-shader-no-invalid-clamp-bounds` & `three-shader-no-invalid-smoothstep-edges`
    if let Some((min_v, max_v)) = parse_glsl_call_two_trailing_floats(glsl, "clamp(")
        && min_v > max_v
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoInvalidClampBounds,
            "threeShaderNoInvalidClampBounds",
            "clamp",
            format!("GLSL `clamp` requires `minVal <= maxVal`, but got {min_v} and {max_v}."),
            span,
        );
    }
    if let Some((edge0, edge1)) = parse_glsl_call_two_leading_floats(glsl, "smoothstep(")
        && edge0 >= edge1
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoInvalidSmoothstepEdges,
            "threeShaderNoInvalidSmoothstepEdges",
            "smoothstep",
            format!("GLSL `smoothstep` requires `edge0 < edge1`, but got {edge0} and {edge1}."),
            span,
        );
    }

    // 7. `three-shader-prefer-small-integer-pow` & `three-shader-prefer-squared-distance-comparison`
    for exp_lit in [", 2.0)", ", 3.0)", ", 4.0)", ", 2)", ", 3)", ", 4)"] {
        if glsl.contains("pow(") && glsl.contains(exp_lit) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeShaderPreferSmallIntegerPow,
                "threeShaderPreferSmallIntegerPow",
                "pow",
                "Prefer explicit multiplication over `pow(x, 2.0/3.0/4.0)` in GLSL.".to_string(),
                span,
            );
            break;
        }
    }
    if (glsl.contains("distance(") || glsl.contains("length("))
        && (glsl.contains(") <")
            || glsl.contains(") >")
            || glsl.contains(") <=")
            || glsl.contains(") >="))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderPreferSquaredDistanceComparison,
            "threeShaderPreferSquaredDistanceComparison",
            "distance",
            "Compare squared distance via `dot(d, d)` instead of `distance(...)` / `length(...)` to avoid `sqrt`.".to_string(),
            span,
        );
    }

    // 8. `three-shader-require-position-on-all-paths` & `three-shader-require-fragment-output-on-all-paths`
    if is_vertex
        && glsl.contains("void main(")
        && (!glsl.contains("gl_Position") || has_early_return_before_target(glsl, "gl_Position"))
        && !glsl.contains("#include <project_vertex>")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderRequirePositionOnAllPaths,
            "threeShaderRequirePositionOnAllPaths",
            "gl_Position",
            "Vertex shader `main` has a path that returns without assigning `gl_Position`."
                .to_string(),
            span,
        );
    }
    if !is_vertex
        && glsl.contains("void main(")
        && glsl.contains("gl_FragColor")
        && has_early_return_before_target(glsl, "gl_FragColor")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderRequireFragmentOutputOnAllPaths,
            "threeShaderRequireFragmentOutputOnAllPaths",
            "gl_FragColor",
            "Fragment shader `main` has a non-discarded return path before assigning `gl_FragColor`.".to_string(),
            span,
        );
    }
    // 9. Additional GLSL expression and declaration checks
    if glsl.contains("inverse(") && glsl.contains("uniform mat") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoInverseOfUniform,
            "threeShaderNoInverseOfUniform",
            "inverse",
            "Precompute uniform matrix inverses on the CPU instead of calling `inverse(uniformMat)` per shader invocation.".to_string(),
            span,
        );
    }
    if !is_vertex && glsl.contains("gl_FragDepth = gl_FragCoord.z") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoRedundantFragDepth,
            "threeShaderNoRedundantFragDepth",
            "gl_FragDepth",
            "Redundant `gl_FragDepth = gl_FragCoord.z` write disables GPU early depth testing."
                .to_string(),
            span,
        );
    }
    if !is_vertex
        && (glsl.contains("dFdx(") || glsl.contains("dFdy(") || glsl.contains("fwidth("))
        && (glsl.contains("if (v") || glsl.contains("if(v"))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoDerivativesInNonuniformFlow,
            "threeShaderNoDerivativesInNonuniformFlow",
            "dFdx",
            "Evaluate screen-space derivatives (`dFdx`, `dFdy`, `fwidth`) outside non-uniform fragment control flow.".to_string(),
            span,
        );
    }
    if glsl.contains("sqrt(-")
        || glsl.contains("log(0.0)")
        || glsl.contains("log(-")
        || glsl.contains(" / 0.0")
        || glsl.contains("acos(2.0)")
        || glsl.contains("asin(2.0)")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoInvalidConstantMath,
            "threeShaderNoInvalidConstantMath",
            "math",
            "GLSL expression has constant out-of-domain math (`sqrt(<0)`, `log(<=0)`, `/ 0.0`, `asin/acos(>1)`).".to_string(),
            span,
        );
    }
    if glsl.contains("<< 32")
        || glsl.contains(">> 32")
        || glsl.contains("<< -1")
        || glsl.contains(">> -1")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoInvalidConstantBitOperations,
            "threeShaderNoInvalidConstantBitOperations",
            "bitshift",
            "GLSL bit shift count is outside the valid 0..31 range for 32-bit integers."
                .to_string(),
            span,
        );
    }
    if glsl.contains("[4]")
        && (glsl.contains("vec4 ") || glsl.contains("vec3 ") || glsl.contains("vec2 "))
        || glsl.contains("[-1]")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderNoConstantOutOfBoundsIndex,
            "threeShaderNoConstantOutOfBoundsIndex",
            "index",
            "Shader uses a constant out-of-bounds vector or array index.".to_string(),
            span,
        );
    }
    for line in glsl.lines() {
        let trimmed = line.trim();
        if ((trimmed.starts_with("uniform ")
            || trimmed.starts_with("varying ")
            || trimmed.starts_with("attribute ")
            || trimmed.starts_with("in ")
            || trimmed.starts_with("out "))
            && trimmed.contains('='))
            || (trimmed.starts_with("const ") && !trimmed.contains('='))
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::ThreeShaderValidGlobalInitializers,
                "threeShaderValidGlobalInitializers",
                "initializer",
                "GLSL interface/uniform globals cannot have initializers, and `const` globals must be initialized.".to_string(),
                span,
            );
            break;
        }
    }
}

fn check_shader_material_pair_and_uniforms(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    obj: &ObjectExpression<'_>,
    vert: Option<&str>,
    frag: Option<&str>,
    span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let uniforms_expr = get_obj_prop_expr(obj, "uniforms");

    if let Some(Expression::ObjectExpression(u_obj)) = uniforms_expr {
        for prop_kind in &u_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let static_key = prop.key.static_name();
            let uname = static_key
                .as_ref()
                .and_then(|n| n.as_str())
                .unwrap_or("uniform");
            let uval = prop.value.without_parentheses();
            if uval.is_literal() || matches!(uval, Expression::ArrayExpression(_)) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeShaderValidUniformDefinitions,
                    "threeShaderValidUniformDefinitions",
                    uname,
                    format!(
                        "Uniform `{uname}` must be defined as `{{ value: ... }}` or `new THREE.Uniform(...)`."
                    ),
                    uval.span(),
                );
            } else if let Expression::ObjectExpression(inner_obj) = uval
                && let Some(val_expr) = get_obj_prop_expr(inner_obj, "value")
            {
                // Check `three-shader-require-compatible-uniform-values`
                for stage_src in [vert, frag].into_iter().flatten() {
                    if stage_src.contains(&format!("uniform float {uname}"))
                        && matches!(
                            val_expr,
                            Expression::BooleanLiteral(_) | Expression::StringLiteral(_)
                        )
                    {
                        ctx.push_site(
                            sites,
                            node_id,
                            RuleId::ThreeShaderRequireCompatibleUniformValues,
                            "threeShaderRequireCompatibleUniformValues",
                            uname,
                            format!(
                                "GLSL `uniform float {uname}` has an incompatible JS value type."
                            ),
                            val_expr.span(),
                        );
                    }
                }
            }
        }
    }

    // Check `three-shader-require-uniform-bindings`
    for stage_src in [vert, frag].into_iter().flatten() {
        for line in stage_src.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("uniform ")
                && let Some(semi_stripped) = rest.strip_suffix(';')
                && let Some(uname) = semi_stripped.split_whitespace().nth(1)
                && !THREE_SHADER_BUILTINS.contains(&uname)
                && !uname.starts_with("gl_")
            {
                let has_binding = uniforms_expr
                    .is_some_and(|u| u.span().source_text(ctx.source).contains(uname));
                if !has_binding {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeShaderRequireUniformBindings,
                        "threeShaderRequireUniformBindings",
                        uname,
                        format!(
                            "GLSL uniform `{uname}` is missing from the `ShaderMaterial` `uniforms` object."
                        ),
                        span,
                    );
                }
            }
        }
    }

    // Check stage matching (`three-shader-require-matching-uniforms`, `three-shader-require-matching-varyings`)
    if let (Some(vsrc), Some(fsrc)) = (vert, frag) {
        let v_uniforms = extract_glsl_qualified_decls(vsrc, &["uniform"]);
        let f_uniforms = extract_glsl_qualified_decls(fsrc, &["uniform"]);
        for (uname, f_type) in &f_uniforms {
            if let Some(v_type) = v_uniforms.get(uname)
                && v_type != f_type
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeShaderRequireMatchingUniforms,
                    "threeShaderRequireMatchingUniforms",
                    uname,
                    format!(
                        "Uniform `{uname}` has type `{v_type}` in vertex shader and `{f_type}` in fragment shader."
                    ),
                    span,
                );
            }
        }

        let v_outs = extract_glsl_qualified_decls(vsrc, &["varying", "out"]);
        let f_ins = extract_glsl_qualified_decls(fsrc, &["varying", "in"]);
        for (vname, f_type) in &f_ins {
            match v_outs.get(vname) {
                Some(v_type) if v_type == f_type => {}
                _ => {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeShaderRequireMatchingVaryings,
                        "threeShaderRequireMatchingVaryings",
                        vname,
                        format!(
                            "Fragment input `{vname}` (`{f_type}`) has no matching vertex output declaration."
                        ),
                        span,
                    );
                }
            }
        }
    }
}

fn extract_glsl_qualified_decls(glsl: &str, qualifiers: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in glsl.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 3 && qualifiers.contains(&tokens[0]) {
            out.insert(tokens[2].to_string(), tokens[1].to_string());
        }
    }
    out
}

fn parse_glsl_call_two_trailing_floats(glsl: &str, needle: &str) -> Option<(f64, f64)> {
    let start = glsl.find(needle)? + needle.len();
    let end = glsl[start..].find(')')? + start;
    let parts: Vec<&str> = glsl[start..end].split(',').map(str::trim).collect();
    if parts.len() == 3 {
        Some((parts[1].parse().ok()?, parts[2].parse().ok()?))
    } else {
        None
    }
}

fn parse_glsl_call_two_leading_floats(glsl: &str, needle: &str) -> Option<(f64, f64)> {
    let start = glsl.find(needle)? + needle.len();
    let end = glsl[start..].find(')')? + start;
    let parts: Vec<&str> = glsl[start..end].split(',').map(str::trim).collect();
    if parts.len() == 3 {
        Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
    } else {
        None
    }
}

fn has_early_return_before_target(glsl: &str, target: &str) -> bool {
    let Some(ret_pos) = glsl.find("return;") else {
        return false;
    };
    let Some(target_pos) = glsl.find(target) else {
        return true;
    };
    ret_pos < target_pos
}
