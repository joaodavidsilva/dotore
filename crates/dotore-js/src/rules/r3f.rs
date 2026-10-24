//! Three.js, React Three Fiber (`r3f`), WebGL, WebGPU, TSL, and GLSL shader rules
//! plus the cross-file 60fps `useFrame` and `requestAnimationFrame` call-graph analyzer.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds"
)]
#![expect(
    clippy::excessive_nesting,
    reason = "Single-pass AST pattern matching inspects nested JSX, CallExpression, and ObjectExpression trees directly"
)]

pub(crate) mod three_lifecycle;
pub(crate) mod use_frame_and_hooks;
pub(crate) mod webgl_and_shaders;
pub(crate) mod webgpu;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentOperator, AssignmentTarget, BinaryOperator, BindingPattern,
        CallExpression, Expression, JSXOpeningElement, ObjectExpression, Program, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::{
    config::{CapabilityGate, DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::{CrossFileFrameLoopFinding, ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, FileIr, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{
            FrameCallTargetIr, FrameHelperHazardKind, FrameHelperIr, FrameLoopRootIr,
            FrameLoopRootKind, ModuleIr, SemanticRuleSite,
        },
    },
    matchers::{
        collect_pattern_bound_names, find_last_jsx_attr,
        get_object_prop as matcher_get_object_prop, has_jsx_truthy_attr, jsx_attr_expr,
        make_diag_for_subject, push_semantic_site,
    },
    rules::{Diagnostic, RuleId, RuleSeverity},
};

use self::{
    three_lifecycle::{
        check_assignments_and_updates, check_new_expressions_and_lifecycle,
        check_scene_and_canvas_contracts,
    },
    use_frame_and_hooks::{check_call_expressions, check_jsx_elements, check_module_imports},
    webgl_and_shaders::check_shader_materials,
};

const R3F_MODULES: &[&str] = &[
    "@react-three/fiber",
    "@react-three/fiber/native",
    "@react-three/fiber/webgpu",
    "@react-three/fiber/legacy",
    "react-three-fiber",
];

pub(crate) const R3F_WEBGPU_MODULES: &[&str] = &["@react-three/fiber/webgpu"];

const DREI_LOADER_HOOKS: &[&str] = &[
    "useCubeTexture",
    "useFBX",
    "useFont",
    "useGLTF",
    "useKTX2",
    "useLoader",
    "useTexture",
    "useVideoTexture",
];

pub(crate) const THREE_BUFFER_ATTR_CTORS: &[&str] = &[
    "BufferAttribute",
    "Float16BufferAttribute",
    "Float32BufferAttribute",
    "InstancedBufferAttribute",
    "Int16BufferAttribute",
    "Int32BufferAttribute",
    "Int8BufferAttribute",
    "Uint16BufferAttribute",
    "Uint32BufferAttribute",
    "Uint8BufferAttribute",
    "Uint8ClampedBufferAttribute",
];

pub(crate) const R3F_BUFFER_ATTR_TAGS: &[&str] = &[
    "bufferAttribute",
    "float16BufferAttribute",
    "float32BufferAttribute",
    "instancedBufferAttribute",
    "int16BufferAttribute",
    "int32BufferAttribute",
    "int8BufferAttribute",
    "uint16BufferAttribute",
    "uint32BufferAttribute",
    "uint8BufferAttribute",
    "uint8ClampedBufferAttribute",
];

pub(crate) const R3F_TEXTURE_TAGS: &[&str] = &[
    "canvasTexture",
    "compressedTexture",
    "data3DTexture",
    "dataArrayTexture",
    "dataTexture",
    "depthTexture",
    "framebufferTexture",
    "texture",
    "videoTexture",
];

pub(crate) const THREE_TEXTURE_CTORS: &[&str] = &[
    "CanvasTexture",
    "CompressedTexture",
    "CubeTexture",
    "Data3DTexture",
    "DataArrayTexture",
    "DataTexture",
    "DepthTexture",
    "FramebufferTexture",
    "Texture",
    "VideoTexture",
];

pub(crate) const THREE_RENDER_TARGET_CTORS: &[&str] = &[
    "RenderTarget",
    "WebGL3DRenderTarget",
    "WebGLArrayRenderTarget",
    "WebGLCubeRenderTarget",
    "WebGLRenderTarget",
];

pub(crate) const THREE_CONTROLS_CTORS: &[&str] = &[
    "ArcballControls",
    "DragControls",
    "FirstPersonControls",
    "FlyControls",
    "MapControls",
    "OrbitControls",
    "PointerLockControls",
    "TrackballControls",
    "TransformControls",
];

pub(crate) const THREE_POSTPROCESSING_CTORS: &[&str] = &[
    "AdaptiveToneMappingPass",
    "AfterimagePass",
    "BloomPass",
    "BokehPass",
    "CubeTexturePass",
    "DotScreenPass",
    "EffectComposer",
    "FXAAPass",
    "FilmPass",
    "GTAOPass",
    "GlitchPass",
    "HalftonePass",
    "LUTPass",
    "OutlinePass",
    "OutputPass",
    "RenderPixelatedPass",
    "RenderTransitionPass",
    "SAOPass",
    "SMAAPass",
    "SSAARenderPass",
    "SSAOPass",
    "SSRPass",
    "SavePass",
    "ShaderPass",
    "TAARenderPass",
    "TexturePass",
    "UnrealBloomPass",
];

pub(crate) const PHYSICAL_NORMALIZED_PROPS: &[&str] = &[
    "anisotropy",
    "clearcoat",
    "clearcoatRoughness",
    "iridescence",
    "reflectivity",
    "sheen",
    "sheenRoughness",
    "specularIntensity",
    "transmission",
];

pub(crate) const COLOR_SPACE_SRGB_PROPS: &[&str] =
    &["emissiveMap", "map", "sheenColorMap", "specularColorMap"];

pub(crate) const COLOR_SPACE_LINEAR_PROPS: &[&str] = &[
    "alphaMap",
    "anisotropyMap",
    "aoMap",
    "bumpMap",
    "clearcoatMap",
    "clearcoatNormalMap",
    "clearcoatRoughnessMap",
    "displacementMap",
    "iridescenceMap",
    "iridescenceThicknessMap",
    "lightMap",
    "metalnessMap",
    "normalMap",
    "roughnessMap",
    "sheenRoughnessMap",
    "specularIntensityMap",
    "thicknessMap",
    "transmissionMap",
];

pub(crate) const DEFAULT_TRANSPARENT_MATERIALS: &[&str] = &[
    "ShadowMaterial",
    "ShadowNodeMaterial",
    "SpriteMaterial",
    "SpriteNodeMaterial",
    "VolumeNodeMaterial",
    "shadowMaterial",
    "shadowNodeMaterial",
    "spriteMaterial",
    "spriteNodeMaterial",
    "volumeNodeMaterial",
];

pub(crate) const UNSUPPORTED_SHADOW_LIGHTS: &[&str] = &[
    "AmbientLight",
    "HemisphereLight",
    "RectAreaLight",
    "ambientLight",
    "hemisphereLight",
    "rectAreaLight",
];

pub(crate) const LIT_MATERIALS: &[&str] = &[
    "MeshLambertMaterial",
    "MeshPhongMaterial",
    "MeshPhysicalMaterial",
    "MeshStandardMaterial",
    "MeshToonMaterial",
    "meshLambertMaterial",
    "meshPhongMaterial",
    "meshPhysicalMaterial",
    "meshStandardMaterial",
    "meshToonMaterial",
];

pub(crate) const UV_MAPPED_MATERIALS: &[&str] = &[
    "MeshBasicMaterial",
    "MeshDepthMaterial",
    "MeshDistanceMaterial",
    "MeshLambertMaterial",
    "MeshMatcapMaterial",
    "MeshNormalMaterial",
    "MeshPhongMaterial",
    "MeshPhysicalMaterial",
    "MeshStandardMaterial",
    "MeshToonMaterial",
    "meshBasicMaterial",
    "meshDepthMaterial",
    "meshDistanceMaterial",
    "meshLambertMaterial",
    "meshMatcapMaterial",
    "meshNormalMaterial",
    "meshPhongMaterial",
    "meshPhysicalMaterial",
    "meshStandardMaterial",
    "meshToonMaterial",
];

pub(crate) const PBR_MATERIALS: &[&str] = &[
    "MeshPhysicalMaterial",
    "MeshStandardMaterial",
    "meshPhysicalMaterial",
    "meshStandardMaterial",
];

pub(crate) const THREE_LIGHT_TAGS_AND_CTORS: &[&str] = &[
    "AmbientLight",
    "DirectionalLight",
    "HemisphereLight",
    "LightProbe",
    "PointLight",
    "RectAreaLight",
    "SpotLight",
    "ambientLight",
    "directionalLight",
    "hemisphereLight",
    "lightProbe",
    "pointLight",
    "rectAreaLight",
    "spotLight",
];

pub(crate) const SYNC_WEBGL_READBACK_METHODS: &[&str] = &[
    "checkFramebufferStatus",
    "finish",
    "getBufferSubData",
    "getError",
    "getImageData",
    "getParameter",
    "readPixels",
    "readRenderTargetPixels",
];

pub(crate) const WEBGPU_SYNC_METHODS: &[&str] = &[
    "clear",
    "clearColor",
    "clearDepth",
    "clearStencil",
    "hasCompatibility",
    "hasFeature",
    "initRenderTarget",
    "initTexture",
    "render",
    "resetState",
];

pub(crate) const THREE_SHADER_BUILTINS: &[&str] = &[
    "cameraPosition",
    "isOrthographic",
    "modelMatrix",
    "modelViewMatrix",
    "normal",
    "normalMatrix",
    "position",
    "projectionMatrix",
    "uv",
    "viewMatrix",
];

const HTML_INTRINSIC_TAGS: &[&str] = &[
    "a", "Area", "audio", "b", "button", "canvas", "code", "div", "em", "footer", "form", "h1",
    "h2", "h3", "h4", "h5", "h6", "header", "hr", "i", "iframe", "img", "input", "label", "li",
    "main", "nav", "ol", "option", "p", "pre", "section", "select", "small", "span", "strong",
    "style", "svg", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "tr", "ul",
    "video",
];

/// Extracts all single-file R3F, Three.js, WebGL, WebGPU, TSL, and GLSL shader [`SemanticRuleSite`]s
/// along with [`FrameLoopRootIr`] and [`FrameHelperIr`] for the cross-file 60fps call graph in [`ProjectGraph`].
pub(crate) fn extract_r3f_webgl_file_ir(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) -> (Vec<FrameLoopRootIr>, Vec<FrameHelperIr>) {
    let ctx = FileAnalysisCtx::build(program, semantic, module, line_starts);

    check_module_imports(&ctx, sites);
    check_jsx_elements(&ctx, sites);
    check_call_expressions(&ctx, sites);
    check_new_expressions_and_lifecycle(&ctx, sites);
    check_assignments_and_updates(&ctx, sites);
    check_scene_and_canvas_contracts(&ctx, sites);
    check_shader_materials(&ctx, sites);

    let frame_loop_roots = crate::ir::motion_and_frame_loop::extract_frame_loop_roots(
        semantic,
        line_starts,
        &ctx.imported_symbols,
        &ctx.namespace_imports,
        |call| ctx.is_r3f_hook_call(call, "useFrame"),
    );
    let frame_helpers = crate::ir::motion_and_frame_loop::extract_frame_helpers(
        semantic,
        ctx.module,
        line_starts,
        &ctx.imported_symbols,
        &ctx.namespace_imports,
        &ctx.state_setters,
    );

    (frame_loop_roots, frame_helpers)
}

/// Traces the cross-file 60fps call graph starting from every `useFrame` and `requestAnimationFrame`
/// callback across module imports (`import { stepPhysics } from './physics'`) and barrel re-exports.
pub(crate) fn trace_cross_file_frame_loops<F>(
    files: &[FileIr],
    mut resolve_specifier: F,
) -> Vec<CrossFileFrameLoopFinding>
where
    F: FnMut(&Path, &str) -> Vec<usize>,
{
    let mut findings = Vec::new();

    for (root_file_idx, root_file) in files.iter().enumerate() {
        for root in &root_file.frame_loop_roots {
            let root_label = match root.kind {
                FrameLoopRootKind::UseFrame => "useFrame",
                FrameLoopRootKind::AnimationLoop => "requestAnimationFrame",
            };

            // Queue entries: `(current_file_idx, helper_name, call_loc, call_span, call_chain, crossed_module)`
            let mut queue: VecDeque<(usize, String, SourceLoc, ByteSpan, Vec<String>, bool)> =
                VecDeque::new();
            let mut visited: HashSet<(usize, String)> = HashSet::new();

            for call in &root.outgoing_calls {
                for (target_file_idx, target_helper_name) in
                    resolve_call_target_in_graph(root_file_idx, call, files, &mut resolve_specifier)
                {
                    let crossed = target_file_idx != root_file_idx;
                    let chain = vec![root_label.to_string(), target_helper_name.clone()];
                    queue.push_back((
                        target_file_idx,
                        target_helper_name,
                        call.call_loc,
                        call.call_span,
                        chain,
                        crossed,
                    ));
                }
            }

            while let Some((
                curr_file_idx,
                helper_name,
                initial_call_loc,
                initial_call_span,
                chain,
                crossed,
            )) = queue.pop_front()
            {
                if !visited.insert((curr_file_idx, helper_name.clone())) {
                    continue;
                }
                let Some(helper_file) = files.get(curr_file_idx) else {
                    continue;
                };
                let Some(helper) = helper_file
                    .frame_helpers
                    .iter()
                    .find(|h| h.name == helper_name)
                else {
                    continue;
                };

                if crossed {
                    for hazard in &helper.hazards {
                        findings.push(CrossFileFrameLoopFinding {
                            root_file_index: root_file_idx,
                            root_kind: root.kind,
                            root_subject_name: root.subject_name.clone(),
                            root_loc: root.loc,
                            root_span: root.span,
                            call_loc: initial_call_loc,
                            call_span: initial_call_span,
                            helper_file_index: curr_file_idx,
                            helper_name: helper.name.clone(),
                            helper_loc: helper.loc,
                            helper_span: helper.span,
                            hazard: hazard.clone(),
                            call_chain: chain.clone(),
                        });
                    }
                }

                for next_call in &helper.outgoing_calls {
                    for (next_file_idx, next_helper_name) in resolve_call_target_in_graph(
                        curr_file_idx,
                        next_call,
                        files,
                        &mut resolve_specifier,
                    ) {
                        let next_crossed = crossed || next_file_idx != root_file_idx;
                        let mut next_chain = chain.clone();
                        next_chain.push(next_helper_name.clone());
                        queue.push_back((
                            next_file_idx,
                            next_helper_name,
                            initial_call_loc,
                            initial_call_span,
                            next_chain,
                            next_crossed,
                        ));
                    }
                }
            }
        }
    }

    findings
}

fn resolve_call_target_in_graph<F>(
    caller_file_idx: usize,
    call: &FrameCallTargetIr,
    files: &[FileIr],
    resolve_specifier: &mut F,
) -> Vec<(usize, String)>
where
    F: FnMut(&Path, &str) -> Vec<usize>,
{
    let Some(caller_file) = files.get(caller_file_idx) else {
        return Vec::new();
    };

    if let Some(specifier) = &call.import_source {
        let export_name = call.imported_name.as_deref().unwrap_or(&call.callee_name);
        let mut visited_exports = HashSet::new();
        let mut out = Vec::new();
        for target_idx in resolve_specifier(&caller_file.path, specifier) {
            resolve_exported_helper_recursive(
                target_idx,
                export_name,
                files,
                resolve_specifier,
                &mut visited_exports,
                &mut out,
            );
        }
        out
    } else if caller_file
        .frame_helpers
        .iter()
        .any(|h| h.name == call.callee_name)
    {
        vec![(caller_file_idx, call.callee_name.clone())]
    } else {
        Vec::new()
    }
}

fn resolve_exported_helper_recursive<F>(
    module_idx: usize,
    export_name: &str,
    files: &[FileIr],
    resolve_specifier: &mut F,
    visited: &mut HashSet<(usize, String)>,
    out: &mut Vec<(usize, String)>,
) where
    F: FnMut(&Path, &str) -> Vec<usize>,
{
    if !visited.insert((module_idx, export_name.to_string())) {
        return;
    }
    let Some(file) = files.get(module_idx) else {
        return;
    };

    // 1. Direct helper in this module matching `export_name`
    for helper in &file.frame_helpers {
        if helper.exported_names.iter().any(|e| e == export_name) || helper.name == export_name {
            out.push((module_idx, helper.name.clone()));
        }
    }

    // 2. Follow barrel re-exports (`export { orig as alias } from './sub'` or `export * from './sub'`)
    for exp in &file.module.exports {
        let Some(from_source) = &exp.from_source else {
            continue;
        };
        if exp.is_namespace_re_export && exp.name == "*" {
            for target_idx in resolve_specifier(&file.path, from_source) {
                resolve_exported_helper_recursive(
                    target_idx,
                    export_name,
                    files,
                    resolve_specifier,
                    visited,
                    out,
                );
            }
        } else if exp.name == export_name {
            let upstream_name = exp.local_name.as_deref().unwrap_or(&exp.name);
            for target_idx in resolve_specifier(&file.path, from_source) {
                resolve_exported_helper_recursive(
                    target_idx,
                    upstream_name,
                    files,
                    resolve_specifier,
                    visited,
                    out,
                );
            }
        }
    }
}

/// Evaluates cross-file 60fps frame-loop call-graph findings recorded on [`ProjectGraph`].
pub(crate) fn evaluate_cross_file_frame_loop_findings<F>(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    resolve_activation: F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(
        RuleId,
        &FileIr,
        &Path,
        &CapabilityGate,
        &DotoreConfig,
        Option<&[RuleId]>,
    ) -> Option<RuleSeverity>,
{
    let mut emitted_keys: HashSet<(usize, RuleId, u32, u32)> = HashSet::new();

    for finding in &graph.frame_loop_findings {
        let Some(root_file) = graph.files.get(finding.root_file_index) else {
            continue;
        };
        let Some(helper_file) = graph.files.get(finding.helper_file_index) else {
            continue;
        };
        let Some(pkg) = resolve_package_for_file(&root_file.path, packages) else {
            continue;
        };
        if pkg.config.is_file_ignored(&root_file.path, &pkg.root_dir) {
            continue;
        }

        let candidate_rules = rules_for_cross_file_hazard(finding.root_kind, &finding.hazard.kind);
        let chain_display = finding.call_chain.join(" -> ");
        let helper_path_str = helper_file.path.to_string_lossy().replace('\\', "/");

        for (rule, message_id, hazard_desc) in candidate_rules {
            let Some(sev) = resolve_activation(
                rule,
                root_file,
                &pkg.root_dir,
                &pkg.capability_gate,
                &pkg.config,
                enabled_rules,
            ) else {
                continue;
            };

            if pkg.config.respect_inline_disables
                && root_file.suppressions.is_suppressed(
                    rule,
                    finding.call_loc.line,
                    finding.call_span,
                    &root_file.jsx_elements,
                    &root_file.subjects,
                )
            {
                continue;
            }

            if !emitted_keys.insert((
                finding.root_file_index,
                rule,
                finding.hazard.loc.line,
                finding.hazard.loc.column,
            )) {
                continue;
            }

            let mut cascade_steps = Vec::with_capacity(finding.call_chain.len() + 1);
            for step in &finding.call_chain {
                cascade_steps.push(format!("60fps frame-loop call chain step: `{step}`"));
            }
            cascade_steps.push(format!(
                "{hazard_desc} in `{helper_path_str}:{}`",
                finding.hazard.loc.line
            ));

            let caller_sites = vec![ResolvedCallerSite {
                caller_file: helper_file.path.clone(),
                parent_subject_name: Some(finding.helper_name.clone()),
                component_name: finding.helper_name.clone(),
                loc: finding.hazard.loc,
                span: finding.hazard.span,
                has_key: false,
                passed_props: Vec::new(),
            }];

            out.push(
                make_diag_for_subject(
                    rule,
                    root_file.path.clone(),
                    finding.root_subject_name.clone(),
                    message_id,
                    finding.helper_name.clone(),
                    format!(
                        "60fps frame loop calls `{chain_display}` which performs {hazard_desc} at `{helper_path_str}:{}`.",
                        finding.hazard.loc.line
                    ),
                    finding.call_loc,
                    finding.call_span,
                )
                .with_severity(sev)
                .with_cascade_steps(cascade_steps)
                .with_caller_sites(caller_sites),
            );
        }
    }
}

fn rules_for_cross_file_hazard(
    root_kind: FrameLoopRootKind,
    hazard_kind: &FrameHelperHazardKind,
) -> Vec<(RuleId, &'static str, String)> {
    match (root_kind, hazard_kind) {
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::NewAllocation(ctor)) => {
            let mut out = vec![(
                RuleId::R3fNoNewInUseFrame,
                "noNewInUseFrame",
                format!("per-frame `new {ctor}()` allocation"),
            )];
            if ctor.ends_with("Geometry") {
                out.push((
                    RuleId::ThreeNoGeometryInFrameLoop,
                    "noGeometryInFrameLoop",
                    format!("per-frame `new {ctor}()` geometry allocation"),
                ));
            }
            out
        }
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::CloneAllocation(expr)) => vec![(
            RuleId::R3fNoCloneInUseFrame,
            "noCloneInUseFrame",
            format!("per-frame `{expr}.clone()` allocation"),
        )],
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::ArrayAllocation) => vec![(
            RuleId::R3fNoNewInUseFrame,
            "noArrayAllocationInUseFrame",
            "per-frame array literal allocation".to_string(),
        )],
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::ObjectAllocation) => vec![(
            RuleId::R3fNoNewInUseFrame,
            "noObjectAllocationInUseFrame",
            "per-frame object literal allocation".to_string(),
        )],
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::StateUpdate(setter)) => vec![(
            RuleId::R3fNoStateInUseFrame,
            "noStateInUseFrame",
            format!("per-frame React state update `{setter}(...)`"),
        )],
        (FrameLoopRootKind::UseFrame, FrameHelperHazardKind::SyncReadback(method)) => vec![
            (
                RuleId::R3fNoSyncReadbackInUseFrame,
                "noSyncReadbackInUseFrame",
                format!("synchronous GPU readback `{method}(...)`"),
            ),
            (
                RuleId::WebglNoSyncReadbackInAnimationLoop,
                "noSyncReadbackInAnimationLoop",
                format!("synchronous GPU readback `{method}(...)`"),
            ),
        ],
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::NewAllocation(ctor)) => {
            let mut out = vec![(
                RuleId::ThreeNoNewInAnimationLoop,
                "noNewInAnimationLoop",
                format!("per-frame `new {ctor}()` allocation"),
            )];
            if ctor.ends_with("Geometry") {
                out.push((
                    RuleId::ThreeNoGeometryInFrameLoop,
                    "noGeometryInFrameLoop",
                    format!("per-frame `new {ctor}()` geometry allocation"),
                ));
            }
            out
        }
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::CloneAllocation(expr)) => vec![(
            RuleId::ThreeNoCloneInAnimationLoop,
            "noCloneInAnimationLoop",
            format!("per-frame `{expr}.clone()` allocation"),
        )],
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::ArrayAllocation) => vec![(
            RuleId::ThreeNoNewInAnimationLoop,
            "noArrayAllocationInAnimationLoop",
            "per-frame array allocation".to_string(),
        )],
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::ObjectAllocation) => vec![(
            RuleId::ThreeNoNewInAnimationLoop,
            "noObjectAllocationInAnimationLoop",
            "per-frame object allocation".to_string(),
        )],
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::StateUpdate(setter)) => vec![(
            RuleId::ThreeNoStateInAnimationLoop,
            "noStateInAnimationLoop",
            format!("per-frame React state update `{setter}(...)`"),
        )],
        (FrameLoopRootKind::AnimationLoop, FrameHelperHazardKind::SyncReadback(method)) => vec![
            (
                RuleId::WebglNoSyncReadbackInAnimationLoop,
                "noSyncReadbackInAnimationLoop",
                format!("synchronous GPU readback `{method}(...)`"),
            ),
            (
                RuleId::ThreeNoSyncReadbackInAnimationLoop,
                "noSyncReadbackInAnimationLoop",
                format!("synchronous GPU readback `{method}(...)`"),
            ),
        ],
    }
}

pub(crate) struct FileAnalysisCtx<'a> {
    pub(crate) semantic: &'a Semantic<'a>,
    pub(crate) module: &'a ModuleIr,
    pub(crate) line_starts: &'a [u32],
    pub(crate) source: &'a str,
    /// `local_name -> (module_source, imported_name)`
    pub(crate) imported_symbols: HashMap<String, (String, String)>,
    /// `namespace_local_name -> module_source`
    pub(crate) namespace_imports: HashMap<String, String>,
    /// `var_name -> constructor_name` (e.g. `"tex" -> "Texture"`, `"renderer" -> "WebGPURenderer"`)
    pub(crate) var_constructors: HashMap<String, String>,
    /// `var_name -> loader_hook_name` (`useGLTF`, `useLoader`, `useTexture`, etc.)
    pub(crate) loader_cache_vars: HashSet<String>,
    /// `ref_name -> jsx_tag_name` (`<group ref={inner} />`)
    pub(crate) jsx_managed_refs: HashMap<String, String>,
    /// `var_name -> colorSpaceName` (`"SRGBColorSpace"` or `"NoColorSpace"`)
    pub(crate) texture_color_spaces: HashMap<String, (String, usize)>,
    /// Render target variable names (`const rt = new WebGLRenderTarget(...)`)
    pub(crate) render_target_vars: HashSet<String>,
    /// State setter names (`const [x, setX] = useState(...)`)
    pub(crate) state_setters: HashSet<String>,
    /// Whether the file imports from `@react-three/fiber/webgpu` or constructs `WebGPURenderer`
    pub(crate) has_webgpu: bool,
    /// Whether the file imports from `@react-three/fiber*` or `@react-three/*`
    pub(crate) has_r3f_import: bool,
}

impl<'a> FileAnalysisCtx<'a> {
    pub(crate) fn build(
        _program: &'a Program<'a>,
        semantic: &'a Semantic<'a>,
        module: &'a ModuleIr,
        line_starts: &'a [u32],
    ) -> Self {
        let source = semantic.source_text();
        let mut imported_symbols = HashMap::new();
        let mut namespace_imports = HashMap::new();
        let mut has_r3f_import = false;
        let mut has_webgpu = false;

        for imp in &module.imports {
            if imp.is_type_only {
                continue;
            }
            if R3F_MODULES.contains(&imp.source.as_str()) || imp.source.starts_with("@react-three/")
            {
                has_r3f_import = true;
            }
            if R3F_WEBGPU_MODULES.contains(&imp.source.as_str()) || imp.source == "three/webgpu" {
                has_webgpu = true;
            }
            for b in &imp.bindings {
                if b.is_type_only {
                    continue;
                }
                if b.is_namespace {
                    namespace_imports.insert(b.local_name.clone(), imp.source.clone());
                } else {
                    imported_symbols.insert(
                        b.local_name.clone(),
                        (imp.source.clone(), b.imported_name.clone()),
                    );
                }
            }
        }

        // Also scan CommonJS `const X = require("...")` and `const { a } = require("...")`
        for node in semantic.nodes() {
            let AstKind::VariableDeclarator(decl) = node.kind() else {
                continue;
            };
            let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
                continue;
            };
            if let Some(req_source) = extract_require_source(init, semantic) {
                if R3F_MODULES.contains(&req_source) || req_source.starts_with("@react-three/") {
                    has_r3f_import = true;
                }
                match &decl.id {
                    BindingPattern::BindingIdentifier(id) => {
                        namespace_imports.insert(id.name.to_string(), req_source.to_string());
                    }
                    BindingPattern::ObjectPattern(obj) => {
                        for prop in &obj.properties {
                            if let Some(key) =
                                prop.key.static_name().as_ref().and_then(|n| n.as_str())
                                && let BindingPattern::BindingIdentifier(id) = &prop.value
                            {
                                imported_symbols.insert(
                                    id.name.to_string(),
                                    (req_source.to_string(), key.to_string()),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut var_constructors = HashMap::new();
        let mut loader_cache_vars = HashSet::new();
        let mut jsx_managed_refs = HashMap::new();
        let mut texture_color_spaces: HashMap<String, (String, usize)> = HashMap::new();
        let mut render_target_vars = HashSet::new();
        let mut state_setters = HashSet::new();

        for node in semantic.nodes() {
            match node.kind() {
                AstKind::VariableDeclarator(decl) => {
                    if let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) {
                        if let Some(ctor) =
                            resolve_new_expr_ctor_name(init, &imported_symbols, &namespace_imports)
                        {
                            if ctor == "WebGPURenderer" {
                                has_webgpu = true;
                            }
                            if let BindingPattern::BindingIdentifier(id) = &decl.id {
                                if THREE_RENDER_TARGET_CTORS.contains(&ctor.as_str())
                                    || ctor.ends_with("RenderTarget")
                                {
                                    render_target_vars.insert(id.name.to_string());
                                }
                                var_constructors.insert(id.name.to_string(), ctor);
                            }
                        } else if let Expression::CallExpression(call) = init {
                            let callee_short = extract_callee_short(&call.callee);
                            if callee_short == Some("useState")
                                || callee_short == Some("useReducer")
                            {
                                if let BindingPattern::ArrayPattern(arr) = &decl.id
                                    && let Some(Some(BindingPattern::BindingIdentifier(setter))) =
                                        arr.elements.get(1)
                                {
                                    state_setters.insert(setter.name.to_string());
                                }
                            } else if is_cached_loader_hook_call(
                                call,
                                &imported_symbols,
                                &namespace_imports,
                            ) {
                                loader_cache_vars.extend(collect_pattern_bound_names(&decl.id));
                            } else if callee_short == Some("useRef")
                                && let Some(first_arg) =
                                    call.arguments.first().and_then(Argument::as_expression)
                                && let Some(ctor) = resolve_new_expr_ctor_name(
                                    first_arg.without_parentheses(),
                                    &imported_symbols,
                                    &namespace_imports,
                                )
                                && let BindingPattern::BindingIdentifier(id) = &decl.id
                            {
                                var_constructors.insert(id.name.to_string(), ctor);
                            }
                        }
                    }
                }
                AstKind::NewExpression(new_expr) => {
                    if let Some(ctor) = resolve_callee_ctor_name(
                        &new_expr.callee,
                        &imported_symbols,
                        &namespace_imports,
                    ) && ctor == "WebGPURenderer"
                    {
                        has_webgpu = true;
                    }
                }
                AstKind::JSXOpeningElement(opening) => {
                    if let Some(tag) = jsx_opening_tag_name(opening)
                        && let Some(Expression::Identifier(ref_id)) =
                            get_jsx_attr_expr(opening, "ref")
                    {
                        jsx_managed_refs.insert(ref_id.name.to_string(), tag);
                    }
                }
                AstKind::AssignmentExpression(assign) => {
                    if assign.operator == AssignmentOperator::Assign
                        && let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                        && mem.property.name == "colorSpace"
                        && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                    {
                        let rhs_name = match assign.right.without_parentheses() {
                            Expression::Identifier(id) => Some(id.name.as_str()),
                            Expression::StaticMemberExpression(m) => Some(m.property.name.as_str()),
                            _ => None,
                        };
                        if let Some(cs) = rhs_name
                            && matches!(
                                cs,
                                "SRGBColorSpace" | "NoColorSpace" | "LinearSRGBColorSpace"
                            )
                        {
                            let normalized = if cs == "LinearSRGBColorSpace" {
                                "NoColorSpace"
                            } else {
                                cs
                            };
                            let entry = texture_color_spaces
                                .entry(obj_id.name.to_string())
                                .or_insert_with(|| (normalized.to_string(), 0));
                            entry.0 = normalized.to_string();
                            entry.1 += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        Self {
            semantic,
            module,
            line_starts,
            source,
            imported_symbols,
            namespace_imports,
            var_constructors,
            loader_cache_vars,
            jsx_managed_refs,
            texture_color_spaces,
            render_target_vars,
            state_setters,
            has_webgpu,
            has_r3f_import,
        }
    }

    pub(crate) fn subject_for_node(&self, node_id: NodeId) -> Option<String> {
        find_enclosing_react_node(self.semantic, node_id)
            .and_then(|subj_id| get_subject_name(self.semantic, subj_id))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Constructs SemanticRuleSite directly from rule metadata and AST span without intermediate builder allocation"
    )]
    pub(crate) fn push_site(
        &self,
        sites: &mut Vec<SemanticRuleSite>,
        node_id: NodeId,
        rule: RuleId,
        message_id: &'static str,
        target_name: &str,
        message: String,
        span: Span,
    ) {
        push_semantic_site(
            sites,
            rule,
            self.subject_for_node(node_id),
            message_id,
            target_name,
            message,
            self.line_starts,
            span,
        );
    }

    pub(crate) fn is_r3f_hook_call(&self, call: &CallExpression<'_>, hook_name: &str) -> bool {
        match call.callee.without_parentheses() {
            Expression::Identifier(id) if id.name == hook_name => {
                if let Some((src, orig)) = self.imported_symbols.get(id.name.as_str()) {
                    return orig == hook_name && R3F_MODULES.contains(&src.as_str());
                }
                // Check if locally declared in this file
                if let Some(ref_id) = id.reference_id.get()
                    && let Some(sym_id) = self.semantic.scoping().get_reference(ref_id).symbol_id()
                {
                    let decl_id = self.semantic.scoping().symbol_declaration(sym_id);
                    if !matches!(
                        self.semantic.nodes().kind(decl_id),
                        AstKind::ImportSpecifier(_)
                            | AstKind::ImportDefaultSpecifier(_)
                            | AstKind::ImportNamespaceSpecifier(_)
                    ) {
                        // Locally declared function/variable/parameter (or destructured from non-R3F require)
                        return false;
                    }
                }
                // Unbound global `useFrame(...)` (e.g. in single-file workspace test fixtures)
                true
            }
            Expression::StaticMemberExpression(mem) if mem.property.name == hook_name => {
                if let Expression::Identifier(ns) = mem.object.without_parentheses()
                    && let Some(src) = self.namespace_imports.get(ns.name.as_str())
                {
                    return R3F_MODULES.contains(&src.as_str())
                        && !self.has_namespace_mutation_before(
                            ns.name.as_str(),
                            hook_name,
                            call.span.start,
                        );
                }
                false
            }
            _ => false,
        }
    }

    fn has_namespace_mutation_before(
        &self,
        ns_name: &str,
        prop_name: &str,
        before_pos: u32,
    ) -> bool {
        for node in self.semantic.nodes() {
            if let AstKind::AssignmentExpression(assign) = node.kind()
                && assign.span.start < before_pos
                && let AssignmentTarget::StaticMemberExpression(mem) = &assign.left
                && mem.property.name == prop_name
                && let Expression::Identifier(obj) = mem.object.without_parentheses()
                && obj.name == ns_name
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn resolve_expr_three_ctor(&self, expr: &Expression<'_>) -> Option<String> {
        match expr.without_parentheses() {
            Expression::NewExpression(new_expr) => resolve_callee_ctor_name(
                &new_expr.callee,
                &self.imported_symbols,
                &self.namespace_imports,
            ),
            Expression::Identifier(id) => self.var_constructors.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(mem) if mem.property.name == "current" => {
                if let Expression::Identifier(id) = mem.object.without_parentheses() {
                    self.var_constructors.get(id.name.as_str()).cloned()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn extract_require_source<'a>(
    expr: &'a Expression<'a>,
    semantic: &Semantic<'_>,
) -> Option<&'a str> {
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return None;
    };
    let Expression::Identifier(callee) = call.callee.without_parentheses() else {
        return None;
    };
    if callee.name != "require" {
        return None;
    }
    if let Some(ref_id) = callee.reference_id.get()
        && semantic
            .scoping()
            .get_reference(ref_id)
            .symbol_id()
            .is_some()
    {
        return None;
    }
    let Some(Argument::StringLiteral(lit)) = call.arguments.first() else {
        return None;
    };
    lit.value.as_str()
}

fn resolve_new_expr_ctor_name(
    expr: &Expression<'_>,
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
) -> Option<String> {
    let Expression::NewExpression(new_expr) = expr.without_parentheses() else {
        return None;
    };
    resolve_callee_ctor_name(&new_expr.callee, imported_symbols, namespace_imports)
}

pub(crate) use crate::ir::motion_and_frame_loop::{
    find_enclosing_function_span, is_conditionally_executed_within, resolve_callback_body_span,
    resolve_callee_ctor_name,
};

pub(crate) fn is_cached_loader_hook_call(
    call: &CallExpression<'_>,
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => {
            if let Some((_src, orig)) = imported_symbols.get(id.name.as_str()) {
                DREI_LOADER_HOOKS.contains(&orig.as_str())
            } else {
                DREI_LOADER_HOOKS.contains(&id.name.as_str())
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(ns) = mem.object.without_parentheses()
                && namespace_imports.contains_key(ns.name.as_str())
            {
                return DREI_LOADER_HOOKS.contains(&mem.property.name.as_str());
            }
            false
        }
        _ => false,
    }
}

pub(crate) use crate::matchers::{callee_name as extract_callee_short, jsx_opening_tag_name};

pub(crate) fn get_jsx_attr_item<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    find_last_jsx_attr(&opening.attributes, name)
}

pub(crate) fn get_jsx_attr_expr<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a Expression<'a>> {
    jsx_attr_expr(&opening.attributes, name)
}

pub(crate) fn jsx_attr_is_true(opening: &JSXOpeningElement<'_>, name: &str) -> bool {
    has_jsx_truthy_attr(&opening.attributes, name)
}

pub(crate) fn is_r3f_intrinsic_tag(tag: &str) -> bool {
    let Some(first) = tag.chars().next() else {
        return false;
    };
    first.is_ascii_lowercase() && !tag.contains('-') && !HTML_INTRINSIC_TAGS.contains(&tag)
}

pub(crate) fn get_jsx_args_elem<'a>(
    opening: &'a JSXOpeningElement<'a>,
    index: usize,
) -> Option<&'a Expression<'a>> {
    let Expression::ArrayExpression(arr) = get_jsx_attr_expr(opening, "args")? else {
        return None;
    };
    arr.elements
        .get(index)?
        .as_expression()
        .map(Expression::without_parentheses)
}

pub(crate) fn is_inside_render_phase(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    let Some(subj_id) = find_enclosing_react_node(semantic, node_id) else {
        return false;
    };
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if anc_id == subj_id {
            return true;
        }
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && let Some(name) = extract_callee_short(&call.callee)
            && matches!(
                name,
                "useMemo" | "useCallback" | "useEffect" | "useLayoutEffect" | "useRef" | "useState"
            )
        {
            return false;
        }
    }
    true
}

pub(crate) fn is_inside_array_map(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && extract_callee_short(&call.callee) == Some("map")
        {
            return true;
        }
    }
    false
}

pub(crate) fn has_unstable_r3f_args(args_expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::ArrayExpression(arr) = args_expr.without_parentheses() else {
        return is_fresh_render_allocation(args_expr, semantic);
    };
    arr.elements.iter().any(|elem| {
        elem.as_expression()
            .is_some_and(|e| is_fresh_render_allocation(e, semantic))
    })
}

pub(crate) fn is_fresh_render_allocation(expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NewExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::FunctionExpression(_) => true,
        Expression::CallExpression(call) => extract_callee_short(&call.callee) == Some("clone"),
        Expression::Identifier(id) => {
            let Some(ref_id) = id.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if find_enclosing_react_node(semantic, decl_id).is_none() {
                return false;
            };
            let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id) else {
                return false;
            };
            let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
                return false;
            };
            is_fresh_render_allocation(init, semantic)
        }
        _ => false,
    }
}

pub(crate) fn eval_static_f64(expr: &Expression<'_>) -> Option<f64> {
    match expr.without_parentheses() {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) => {
            let v = eval_static_f64(&u.argument)?;
            match u.operator {
                UnaryOperator::UnaryNegation => Some(-v),
                UnaryOperator::UnaryPlus => Some(v),
                _ => None,
            }
        }
        Expression::BinaryExpression(b) => {
            let l = eval_static_f64(&b.left)?;
            let r = eval_static_f64(&b.right)?;
            match b.operator {
                BinaryOperator::Addition => Some(l + r),
                BinaryOperator::Subtraction => Some(l - r),
                BinaryOperator::Multiplication => Some(l * r),
                BinaryOperator::Division if r != 0.0 => Some(l / r),
                _ => None,
            }
        }
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses()
                && obj.name == "Math"
                && mem.property.name == "PI"
            {
                Some(std::f64::consts::PI)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn eval_static_array_len(expr: &Expression<'_>) -> Option<usize> {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => Some(arr.elements.len()),
        Expression::NewExpression(new_expr) => {
            let first = new_expr.arguments.first()?.as_expression()?;
            match first.without_parentheses() {
                Expression::NumericLiteral(n) if n.value >= 0.0 && n.value.fract() == 0.0 => {
                    format!("{:.0}", n.value).parse::<usize>().ok()
                }
                Expression::ArrayExpression(arr) => Some(arr.elements.len()),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn is_valid_shadow_map_size(val: f64) -> bool {
    if val < 1.0 || val.fract() != 0.0 || val > 16384.0 {
        return false;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "validated integer in 1..=16384"
    )]
    let n = val as u32;
    n.is_power_of_two()
}

pub(crate) fn extract_root_ident_name(expr: &Expression<'_>) -> Option<String> {
    let mut curr = expr.without_parentheses();
    while let Expression::StaticMemberExpression(mem) = curr {
        curr = mem.object.without_parentheses();
    }
    if let Expression::Identifier(id) = curr {
        Some(id.name.to_string())
    } else {
        None
    }
}

pub(crate) fn is_inside_effect_hook(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && matches!(
                extract_callee_short(&call.callee),
                Some("useEffect" | "useLayoutEffect" | "useInsertionEffect")
            )
        {
            return true;
        }
    }
    false
}

pub(crate) fn get_obj_prop_expr<'a>(
    obj: &'a ObjectExpression<'a>,
    key: &str,
) -> Option<&'a Expression<'a>> {
    matcher_get_object_prop(obj, key).map(|p| p.value.without_parentheses())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
    use crate::rules::RuleId;

    #[test]
    fn r3f_submodules_expose_lifecycle_use_frame_webgl_and_webgpu_detectors() {
        let _ = (
            super::three_lifecycle::check_new_expressions_and_lifecycle as fn(_, _),
            super::use_frame_and_hooks::check_use_frame_call as fn(_, _, _, _),
            super::webgl_and_shaders::check_shader_materials as fn(_, _),
            super::webgpu::check_canvas_opening as fn(_, _, _, _),
        );

        let ir = parse_file_ir(
            Path::new("src/Scene.tsx"),
            r##"
import { Canvas, useFrame } from "@react-three/fiber/webgpu";
import { BoxGeometry, ShaderMaterial, Vector3 } from "three";

export function Scene() {
    const geom = new BoxGeometry(1, 1, 1);
    const mat = new ShaderMaterial({
        vertexShader: "#version 300 es\nvoid main() { gl_Position = vec4(0.0); }",
        fragmentShader: "void main() { gl_FragColor = vec4(1.0); }",
    });
    useFrame(() => {
        const v = new Vector3();
        return v;
    });
    return <Canvas gl={{}}>{String(Boolean(geom) || Boolean(mat))}</Canvas>;
}
"##,
        );
        let rules: Vec<RuleId> = ir.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::ThreeNoObjectConstructionInRender));
        assert!(rules.contains(&RuleId::R3fNoNewInUseFrame));
        assert!(rules.contains(&RuleId::ThreeShaderNoVersionDirective));
        assert!(rules.contains(&RuleId::R3fWebgpuCanvasPropCompatibility));
        assert!(rules.contains(&RuleId::ThreeWebgpuNoLegacyMaterialApi));
    }
}
