//! Three.js, React Three Fiber (`r3f`), WebGL, WebGPU, TSL, and GLSL shader rules
//! plus the cross-file 60fps `useFrame` and `requestAnimationFrame` call-graph analyzer.

mod analysis_ctx;
mod frame_loop_checks;
mod scene_and_contracts;
pub(crate) mod three_lifecycle;
pub(crate) mod use_frame_and_hooks;
pub(crate) mod webgl_and_shaders;
pub(crate) mod webgpu;

use std::{
    collections::{HashSet, VecDeque},
    path::Path,
};

use oxc_ast::ast::Program;
use oxc_semantic::Semantic;

pub(crate) use self::analysis_ctx::*;
use crate::{
    config::{CapabilityGate, DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::{CrossFileFrameLoopFinding, ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, FileIr, SourceLoc,
        types::{
            FrameCallTargetIr, FrameHelperHazardKind, FrameHelperIr, FrameLoopRootIr,
            FrameLoopRootKind, ModuleIr, SemanticRuleSite,
        },
    },
    matchers::make_diag_for_subject,
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
            trace_single_frame_loop_root(
                root_file_idx,
                root,
                files,
                &mut resolve_specifier,
                &mut findings,
            );
        }
    }
    findings
}

fn trace_single_frame_loop_root<F>(
    root_file_idx: usize,
    root: &FrameLoopRootIr,
    files: &[FileIr],
    resolve_specifier: &mut F,
    findings: &mut Vec<CrossFileFrameLoopFinding>,
) where
    F: FnMut(&Path, &str) -> Vec<usize>,
{
    let root_label = match root.kind {
        FrameLoopRootKind::UseFrame => "useFrame",
        FrameLoopRootKind::AnimationLoop => "requestAnimationFrame",
    };

    let mut queue: VecDeque<(usize, String, SourceLoc, ByteSpan, Vec<String>, bool)> =
        VecDeque::new();
    let mut visited: HashSet<(usize, String)> = HashSet::new();

    for call in &root.outgoing_calls {
        for (target_file_idx, target_helper_name) in
            resolve_call_target_in_graph(root_file_idx, call, files, resolve_specifier)
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
            append_helper_frame_hazards(
                root_file_idx,
                root,
                initial_call_loc,
                initial_call_span,
                curr_file_idx,
                helper,
                &chain,
                findings,
            );
        }

        for next_call in &helper.outgoing_calls {
            for (next_file_idx, next_helper_name) in
                resolve_call_target_in_graph(curr_file_idx, next_call, files, resolve_specifier)
            {
                let next_crossed = crossed || next_file_idx != root_file_idx;
                let mut next_chain = Vec::with_capacity(chain.len() + 1);
                next_chain.extend_from_slice(&chain);
                let next_name_for_queue = next_helper_name.as_str().to_owned();
                next_chain.push(next_helper_name);
                queue.push_back((
                    next_file_idx,
                    next_name_for_queue,
                    initial_call_loc,
                    initial_call_span,
                    next_chain,
                    next_crossed,
                ));
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Records all cross-file hazards discovered on a reachable frame helper (#50)"
)]
fn append_helper_frame_hazards(
    root_file_idx: usize,
    root: &FrameLoopRootIr,
    initial_call_loc: SourceLoc,
    initial_call_span: ByteSpan,
    curr_file_idx: usize,
    helper: &FrameHelperIr,
    chain: &[String],
    findings: &mut Vec<CrossFileFrameLoopFinding>,
) {
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
            call_chain: chain.to_vec(),
        });
    }
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
