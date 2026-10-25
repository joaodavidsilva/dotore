//! WebGL & GLSL shader (`three-shader-*`, `three-raw-shader-*`) stage analysis,
//! uniform/varying compatibility, and `RawShaderMaterial` rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
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
            check_single_glsl_stage(
                ctx,
                node_id,
                &GlslStageSource {
                    glsl: vsrc,
                    span: *vspan,
                    is_vertex: true,
                    is_raw,
                    is_glsl3,
                },
                sites,
            );
        }
        if let Some((fsrc, fspan)) = &frag {
            check_single_glsl_stage(
                ctx,
                node_id,
                &GlslStageSource {
                    glsl: fsrc,
                    span: *fspan,
                    is_vertex: false,
                    is_raw,
                    is_glsl3,
                },
                sites,
            );
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

struct GlslStageSource<'a> {
    glsl: &'a str,
    span: Span,
    is_vertex: bool,
    is_raw: bool,
    is_glsl3: bool,
}

fn check_single_glsl_stage(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    check_glsl_version_and_identifiers(ctx, node_id, stage, sites);
    check_glsl_builtins_and_version_compat(ctx, node_id, stage, sites);
    check_glsl_numeric_and_distance_calls(ctx, node_id, stage, sites);
    check_glsl_control_flow_and_output_paths(ctx, node_id, stage, sites);
    check_glsl_math_indexing_and_initializers(ctx, node_id, stage, sites);
}

fn check_glsl_version_and_identifiers(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let GlslStageSource { glsl, span, .. } = *stage;
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

    for token in glsl.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if is_reserved_glsl_identifier(token) {
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
}

fn is_reserved_glsl_identifier(token: &str) -> bool {
    token.contains("__")
        || (token.starts_with("gl_")
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
}

fn check_glsl_builtins_and_version_compat(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let GlslStageSource {
        glsl,
        span,
        is_vertex,
        is_raw,
        is_glsl3,
    } = *stage;

    if !is_raw {
        for builtin in THREE_SHADER_BUILTINS {
            if glsl_redeclares_three_builtin(glsl, builtin) {
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

    if is_raw
        && !is_vertex
        && !glsl.contains("precision ")
        && ["float ", "vec2 ", "vec3 ", "vec4 "]
            .iter()
            .any(|t| glsl.contains(t))
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
        && ["texture2D(", "gl_FragColor", "varying ", "attribute "]
            .iter()
            .any(|p| glsl.contains(p))
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
}

fn glsl_redeclares_three_builtin(glsl: &str, builtin: &str) -> bool {
    [
        format!("attribute vec3 {builtin}"),
        format!("attribute vec2 {builtin}"),
        format!("uniform mat4 {builtin}"),
        format!("uniform mat3 {builtin}"),
        format!("uniform vec3 {builtin}"),
    ]
    .iter()
    .any(|decl| glsl.contains(decl))
}

fn check_glsl_numeric_and_distance_calls(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let GlslStageSource { glsl, span, .. } = *stage;

    if let Some((min_v, max_v)) = parse_glsl_call_two_floats(glsl, "clamp(", 1, 2)
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
    if let Some((edge0, edge1)) = parse_glsl_call_two_floats(glsl, "smoothstep(", 0, 1)
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

    if glsl.contains("pow(")
        && [", 2.0)", ", 3.0)", ", 4.0)", ", 2)", ", 3)", ", 4)"]
            .iter()
            .any(|exp_lit| glsl.contains(exp_lit))
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderPreferSmallIntegerPow,
            "threeShaderPreferSmallIntegerPow",
            "pow",
            "Prefer explicit multiplication over `pow(x, 2.0/3.0/4.0)` in GLSL.".to_string(),
            span,
        );
    }
    if (glsl.contains("distance(") || glsl.contains("length("))
        && [") <", ") >", ") <=", ") >="]
            .iter()
            .any(|op| glsl.contains(op))
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
}

fn check_glsl_control_flow_and_output_paths(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let GlslStageSource {
        glsl,
        span,
        is_vertex,
        ..
    } = *stage;

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
        && ["dFdx(", "dFdy(", "fwidth("]
            .iter()
            .any(|fn_call| glsl.contains(fn_call))
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
}

fn check_glsl_math_indexing_and_initializers(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    stage: &GlslStageSource<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let GlslStageSource { glsl, span, .. } = *stage;

    if [
        "sqrt(-",
        "log(0.0)",
        "log(-",
        " / 0.0",
        "acos(2.0)",
        "asin(2.0)",
    ]
    .iter()
    .any(|p| glsl.contains(p))
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
    if ["<< 32", ">> 32", "<< -1", ">> -1"]
        .iter()
        .any(|p| glsl.contains(p))
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
    if (glsl.contains("[4]")
        && ["vec4 ", "vec3 ", "vec2 "]
            .iter()
            .any(|t| glsl.contains(t)))
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
    if glsl.lines().any(is_invalid_glsl_global_initializer_line) {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeShaderValidGlobalInitializers,
            "threeShaderValidGlobalInitializers",
            "initializer",
            "GLSL interface/uniform globals cannot have initializers, and `const` globals must be initialized.".to_string(),
            span,
        );
    }
}

fn is_invalid_glsl_global_initializer_line(line: &str) -> bool {
    let trimmed = line.trim();
    if ["uniform ", "varying ", "attribute ", "in ", "out "]
        .iter()
        .any(|q| trimmed.starts_with(q))
    {
        return trimmed.contains('=');
    }
    trimmed.starts_with("const ") && !trimmed.contains('=')
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
        check_shader_uniform_definitions_and_types(ctx, node_id, u_obj, vert, frag, sites);
    }
    check_shader_uniform_bindings_present(ctx, node_id, uniforms_expr, vert, frag, span, sites);
    if let (Some(vsrc), Some(fsrc)) = (vert, frag) {
        check_shader_stage_matching_decls(ctx, node_id, vsrc, fsrc, span, sites);
    }
}

fn check_shader_uniform_definitions_and_types(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    u_obj: &ObjectExpression<'_>,
    vert: Option<&str>,
    frag: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
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
            && matches!(
                val_expr,
                Expression::BooleanLiteral(_) | Expression::StringLiteral(_)
            )
        {
            for stage_src in [vert, frag].into_iter().flatten() {
                if stage_src.contains(&format!("uniform float {uname}")) {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeShaderRequireCompatibleUniformValues,
                        "threeShaderRequireCompatibleUniformValues",
                        uname,
                        format!("GLSL `uniform float {uname}` has an incompatible JS value type."),
                        val_expr.span(),
                    );
                }
            }
        }
    }
}

fn check_shader_uniform_bindings_present(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    uniforms_expr: Option<&Expression<'_>>,
    vert: Option<&str>,
    frag: Option<&str>,
    span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
    for stage_src in [vert, frag].into_iter().flatten() {
        for line in stage_src.lines() {
            let Some(uname) = extract_declared_custom_uniform_name(line.trim()) else {
                continue;
            };
            let has_binding =
                uniforms_expr.is_some_and(|u| u.span().source_text(ctx.source).contains(uname));
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

fn extract_declared_custom_uniform_name(trimmed_line: &str) -> Option<&str> {
    let rest = trimmed_line.strip_prefix("uniform ")?;
    let semi_stripped = rest.strip_suffix(';')?;
    let uname = semi_stripped.split_whitespace().nth(1)?;
    (!THREE_SHADER_BUILTINS.contains(&uname) && !uname.starts_with("gl_")).then_some(uname)
}

fn check_shader_stage_matching_decls(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    vsrc: &str,
    fsrc: &str,
    span: Span,
    sites: &mut Vec<SemanticRuleSite>,
) {
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
        if v_outs.get(vname) != Some(f_type) {
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

fn parse_glsl_call_two_floats(
    glsl: &str,
    needle: &str,
    idx_a: usize,
    idx_b: usize,
) -> Option<(f64, f64)> {
    let start = glsl.find(needle)? + needle.len();
    let end = glsl[start..].find(')')? + start;
    let parts: Vec<&str> = glsl[start..end].split(',').map(str::trim).collect();
    if parts.len() == 3 {
        Some((
            parts.get(idx_a)?.parse().ok()?,
            parts.get(idx_b)?.parse().ok()?,
        ))
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
