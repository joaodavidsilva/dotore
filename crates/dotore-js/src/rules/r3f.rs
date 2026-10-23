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

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrayExpressionElement, AssignmentOperator, AssignmentTarget, BinaryOperator,
        BindingPattern, CallExpression, Expression, FormalParameters, JSXAttributeItem,
        JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement, JSXElementName,
        JSXOpeningElement, LogicalOperator, ObjectExpression, ObjectPropertyKind, Program,
        UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use crate::{
    config::{CapabilityGate, DotoreConfig, WorkspacePackage, resolve_package_for_file},
    graph::{CrossFileFrameLoopFinding, ProjectGraph, ResolvedCallerSite},
    ir::{
        ByteSpan, FileIr, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{
            FrameCallTargetIr, FrameHelperHazard, FrameHelperHazardKind, FrameHelperIr,
            FrameLoopRootIr, FrameLoopRootKind, ModuleIr, SemanticRuleSite, loc_from_line_starts,
        },
    },
    rules::{Diagnostic, RuleId, RuleSeverity},
};

const R3F_MODULES: &[&str] = &[
    "@react-three/fiber",
    "@react-three/fiber/native",
    "@react-three/fiber/webgpu",
    "@react-three/fiber/legacy",
    "react-three-fiber",
];

const R3F_WEBGPU_MODULES: &[&str] = &["@react-three/fiber/webgpu"];

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

const THREE_BUFFER_ATTR_CTORS: &[&str] = &[
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

const R3F_BUFFER_ATTR_TAGS: &[&str] = &[
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

const R3F_TEXTURE_TAGS: &[&str] = &[
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

const THREE_TEXTURE_CTORS: &[&str] = &[
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

const THREE_RENDER_TARGET_CTORS: &[&str] = &[
    "RenderTarget",
    "WebGL3DRenderTarget",
    "WebGLArrayRenderTarget",
    "WebGLCubeRenderTarget",
    "WebGLRenderTarget",
];

const THREE_CONTROLS_CTORS: &[&str] = &[
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

const THREE_POSTPROCESSING_CTORS: &[&str] = &[
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

const PHYSICAL_NORMALIZED_PROPS: &[&str] = &[
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

const COLOR_SPACE_SRGB_PROPS: &[&str] =
    &["emissiveMap", "map", "sheenColorMap", "specularColorMap"];

const COLOR_SPACE_LINEAR_PROPS: &[&str] = &[
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

const DEFAULT_TRANSPARENT_MATERIALS: &[&str] = &[
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

const UNSUPPORTED_SHADOW_LIGHTS: &[&str] = &[
    "AmbientLight",
    "HemisphereLight",
    "RectAreaLight",
    "ambientLight",
    "hemisphereLight",
    "rectAreaLight",
];

const LIT_MATERIALS: &[&str] = &[
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

const UV_MAPPED_MATERIALS: &[&str] = &[
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

const PBR_MATERIALS: &[&str] = &[
    "MeshPhysicalMaterial",
    "MeshStandardMaterial",
    "meshPhysicalMaterial",
    "meshStandardMaterial",
];

const THREE_LIGHT_TAGS_AND_CTORS: &[&str] = &[
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

const WEBGPU_SYNC_METHODS: &[&str] = &[
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

const THREE_SHADER_BUILTINS: &[&str] = &[
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

    let frame_loop_roots = extract_frame_loop_roots(&ctx);
    let frame_helpers = extract_frame_helpers(&ctx);

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

            let meta = rule.metadata();
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

            out.push(Diagnostic {
                file: root_file.path.clone(),
                subject_name: finding.root_subject_name.clone(),
                rule,
                category: meta.category,
                severity: sev,
                message_id,
                tier: meta.default_tier,
                target_name: finding.helper_name.clone(),
                message: format!(
                    "60fps frame loop calls `{chain_display}` which performs {hazard_desc} at `{helper_path_str}:{}`.",
                    finding.hazard.loc.line
                ),
                docs_url: meta.docs_url,
                loc: finding.call_loc,
                span: finding.call_span,
                cascade_steps,
                caller_sites,
                autofix: None,
            });
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

struct FileAnalysisCtx<'a> {
    semantic: &'a Semantic<'a>,
    module: &'a ModuleIr,
    line_starts: &'a [u32],
    source: &'a str,
    /// `local_name -> (module_source, imported_name)`
    imported_symbols: HashMap<String, (String, String)>,
    /// `namespace_local_name -> module_source`
    namespace_imports: HashMap<String, String>,
    /// `var_name -> constructor_name` (e.g. `"tex" -> "Texture"`, `"renderer" -> "WebGPURenderer"`)
    var_constructors: HashMap<String, String>,
    /// `var_name -> loader_hook_name` (`useGLTF`, `useLoader`, `useTexture`, etc.)
    loader_cache_vars: HashSet<String>,
    /// `ref_name -> jsx_tag_name` (`<group ref={inner} />`)
    jsx_managed_refs: HashMap<String, String>,
    /// `var_name -> colorSpaceName` (`"SRGBColorSpace"` or `"NoColorSpace"`)
    texture_color_spaces: HashMap<String, (String, usize)>,
    /// Render target variable names (`const rt = new WebGLRenderTarget(...)`)
    render_target_vars: HashSet<String>,
    /// State setter names (`const [x, setX] = useState(...)`)
    state_setters: HashSet<String>,
    /// Whether the file imports from `@react-three/fiber/webgpu` or constructs `WebGPURenderer`
    has_webgpu: bool,
    /// Whether the file imports from `@react-three/fiber*` or `@react-three/*`
    has_r3f_import: bool,
}

impl<'a> FileAnalysisCtx<'a> {
    fn build(
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
                                collect_binding_identifiers(&decl.id, &mut loader_cache_vars);
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

    fn loc_and_span(&self, span: Span) -> (SourceLoc, ByteSpan) {
        (
            loc_from_line_starts(self.line_starts, span.start),
            ByteSpan {
                start: span.start,
                end: span.end,
            },
        )
    }

    fn subject_for_node(&self, node_id: NodeId) -> Option<String> {
        find_enclosing_react_node(self.semantic, node_id)
            .and_then(|subj_id| get_subject_name(self.semantic, subj_id))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Constructs SemanticRuleSite directly from rule metadata and AST span without intermediate builder allocation"
    )]
    fn push_site(
        &self,
        sites: &mut Vec<SemanticRuleSite>,
        node_id: NodeId,
        rule: RuleId,
        message_id: &'static str,
        target_name: &str,
        message: String,
        span: Span,
    ) {
        let (loc, byte_span) = self.loc_and_span(span);
        sites.push(SemanticRuleSite {
            rule,
            subject_name: self.subject_for_node(node_id),
            message_id,
            target_name: target_name.to_string(),
            message,
            loc,
            span: byte_span,
            autofix: None,
        });
    }

    fn is_r3f_hook_call(&self, call: &CallExpression<'_>, hook_name: &str) -> bool {
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

    fn resolve_expr_three_ctor(&self, expr: &Expression<'_>) -> Option<String> {
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

fn resolve_callee_ctor_name(
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

fn is_cached_loader_hook_call(
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

fn collect_binding_identifiers(pat: &BindingPattern<'_>, out: &mut HashSet<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => {
            out.insert(id.name.to_string());
        }
        BindingPattern::ObjectPattern(obj) => {
            for prop in &obj.properties {
                collect_binding_identifiers(&prop.value, out);
            }
            if let Some(rest) = &obj.rest {
                collect_binding_identifiers(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter().flatten() {
                collect_binding_identifiers(elem, out);
            }
            if let Some(rest) = &arr.rest {
                collect_binding_identifiers(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(assign) => {
            collect_binding_identifiers(&assign.left, out);
        }
    }
}

fn extract_callee_short<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => Some(mem.property.name.as_str()),
        _ => None,
    }
}

fn jsx_opening_tag_name(opening: &JSXOpeningElement<'_>) -> Option<String> {
    match &opening.name {
        JSXElementName::Identifier(id) => Some(id.name.to_string()),
        JSXElementName::IdentifierReference(id) => Some(id.name.to_string()),
        JSXElementName::MemberExpression(mem) => Some(mem.property.name.to_string()),
        _ => None,
    }
}

fn get_jsx_attr_item<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    for item in opening.attributes.iter().rev() {
        if let JSXAttributeItem::Attribute(attr) = item
            && let JSXAttributeName::Identifier(id) = &attr.name
            && id.name == name
        {
            return Some(attr);
        }
    }
    None
}

fn get_jsx_attr_expr<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a Expression<'a>> {
    let attr = get_jsx_attr_item(opening, name)?;
    let JSXAttributeValue::ExpressionContainer(container) = attr.value.as_ref()? else {
        return None;
    };
    container
        .expression
        .as_expression()
        .map(Expression::without_parentheses)
}

fn jsx_attr_is_true(opening: &JSXOpeningElement<'_>, name: &str) -> bool {
    let Some(attr) = get_jsx_attr_item(opening, name) else {
        return false;
    };
    match &attr.value {
        None => true,
        Some(JSXAttributeValue::ExpressionContainer(c)) => matches!(
            c.expression.as_expression().map(Expression::without_parentheses),
            Some(Expression::BooleanLiteral(b)) if b.value
        ),
        _ => false,
    }
}

fn is_r3f_intrinsic_tag(tag: &str) -> bool {
    let Some(first) = tag.chars().next() else {
        return false;
    };
    first.is_ascii_lowercase() && !tag.contains('-') && !HTML_INTRINSIC_TAGS.contains(&tag)
}

// =============================================================================
// 1. Module Import Rules (`r3f-no-internal-imports`)
// =============================================================================

fn check_module_imports(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) => {
                let Some(s) = imp.source.value.as_str() else {
                    continue;
                };
                if s.starts_with("@react-three/fiber/dist/")
                    || s.starts_with("@react-three/fiber/src/")
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fNoInternalImports,
                        "r3fNoInternalImports",
                        s,
                        format!(
                            "Importing {s} couples this code to private package layout that can change between releases. Use a documented public entry point"
                        ),
                        imp.source.span,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                if let Expression::Identifier(id) = call.callee.without_parentheses()
                    && id.name == "require"
                    && let Some(Argument::StringLiteral(lit)) = call.arguments.first()
                    && let Some(s) = lit.value.as_str()
                    && (s.starts_with("@react-three/fiber/dist/")
                        || s.starts_with("@react-three/fiber/src/"))
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fNoInternalImports,
                        "r3fNoInternalImports",
                        s,
                        format!(
                            "Importing {s} couples this code to private package layout that can change between releases. Use a documented public entry point"
                        ),
                        lit.span,
                    );
                }
            }
            _ => {}
        }
    }
}

fn check_jsx_elements(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
    let mut primitive_objs_by_subject: HashMap<Option<String>, HashSet<String>> = HashMap::new();

    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::JSXOpeningElement(opening) = node.kind() else {
            continue;
        };
        let Some(tag) = jsx_opening_tag_name(opening) else {
            continue;
        };
        let has_spread = opening
            .attributes
            .iter()
            .any(|a| matches!(a, JSXAttributeItem::SpreadAttribute(_)));

        // 1. Canvas rules (`r3f-cap-device-pixel-ratio`, `r3f-webgpu-canvas-prop-compatibility`, `r3f-webgpu-require-async-init`)
        if tag == "Canvas" {
            check_canvas_opening(ctx, node_id, opening, sites);
        }

        // 2. WebGPU legacy EffectComposer inside WebGPU Canvas (`r3f-webgpu-no-legacy-effect-composer`)
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

        if !is_r3f_intrinsic_tag(&tag) {
            continue;
        }

        // 3. `r3f-no-unstable-args`
        if let Some(args_expr) = get_jsx_attr_expr(opening, "args")
            && is_inside_render_phase(ctx.semantic, node_id)
            && has_unstable_r3f_args(args_expr, ctx.semantic)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoUnstableArgs,
                "r3fNoUnstableArgs",
                "args",
                "Constructor `args` contains a freshly allocated array, object, or instance on every render. Memoize it or hoist to module scope.".to_string(),
                args_expr.span(),
            );
        }

        // 4. `<primitive object={...} />` (`r3f-no-inline-primitive-object`, `r3f-no-duplicate-primitive-object`)
        if tag == "primitive"
            && let Some(obj_expr) = get_jsx_attr_expr(opening, "object")
        {
            if is_inside_render_phase(ctx.semantic, node_id)
                && is_fresh_render_allocation(obj_expr, ctx.semantic)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoInlinePrimitiveObject,
                    "r3fNoInlinePrimitiveObject",
                    "object",
                    "Passing a freshly constructed or cloned object to `<primitive object={...} />` remounts the scene object on every render.".to_string(),
                    obj_expr.span(),
                );
            }
            if !is_inside_array_map(ctx.semantic, node_id)
                && let Expression::Identifier(id) = obj_expr
            {
                let subj = ctx.subject_for_node(node_id);
                let seen = primitive_objs_by_subject.entry(subj).or_default();
                if !seen.insert(id.name.to_string()) {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fNoDuplicatePrimitiveObject,
                        "r3fNoDuplicatePrimitiveObject",
                        id.name.as_str(),
                        format!(
                            "Three.js object `{}` is mounted in multiple `<primitive>` elements; a Three.js Object3D can only have one parent.",
                            id.name
                        ),
                        obj_expr.span(),
                    );
                }
            }
        }

        // 5. `r3f-no-inline-resource-prop` (`geometry={new ...}` / `material={new ...}`)
        for prop_name in ["geometry", "material"] {
            if let Some(prop_expr) = get_jsx_attr_expr(opening, prop_name)
                && is_inside_render_phase(ctx.semantic, node_id)
                && is_fresh_render_allocation(prop_expr, ctx.semantic)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoInlineResourceProp,
                    "r3fNoInlineResourceProp",
                    prop_name,
                    format!(
                        "Prop `{prop_name}` on `<{tag}>` creates a fresh GPU resource during render; memoize with `useMemo` or hoist to module scope."
                    ),
                    prop_expr.span(),
                );
            }
        }

        // 6. `r3f-prefer-instanced-mesh`
        if tag == "mesh"
            && !has_spread
            && is_inside_array_map(ctx.semantic, node_id)
            && let (Some(Expression::Identifier(_)), Some(Expression::Identifier(_))) = (
                get_jsx_attr_expr(opening, "geometry"),
                get_jsx_attr_expr(opening, "material"),
            )
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fPreferInstancedMesh,
                "r3fPreferInstancedMesh",
                "mesh",
                "Repeated `<mesh>` elements in `.map()` share geometry and material; use `<instancedMesh>` to collapse draw calls.".to_string(),
                opening.span,
            );
        }

        // 7. Material, Light, Camera, Buffer, Texture, and WebGPU JSX rules
        check_jsx_material_and_light_props(ctx, node_id, opening, &tag, has_spread, sites);
        check_jsx_pointer_handlers(ctx, node_id, opening, sites);
    }
}

fn check_canvas_opening(
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

fn check_jsx_material_and_light_props(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    has_spread: bool,
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
                        format!("`meshBasicMaterial` ignores `{ignored}`; use `meshStandardMaterial` or `meshPhysicalMaterial`."),
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
                format!("`linewidth={lw}` is ignored by WebGL/WebGPU line primitives; use Drei `<Line>`."),
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
            format!("`<{tag}>` cannot cast shadows; use `directionalLight`, `pointLight`, or `spotLight`."),
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

fn check_jsx_pointer_handlers(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if let Some(pm_expr) = get_jsx_attr_expr(opening, "onPointerMove") {
        let pm_src = pm_expr.span().source_text(ctx.source);
        if pm_src.contains("new ") || pm_src.contains(".clone(") {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoAllocationInPointerMove,
                "r3fNoAllocationInPointerMove",
                "onPointerMove",
                "Avoid object allocations (`new` / `.clone()`) inside `onPointerMove`; reuse scratch vectors.".to_string(),
                pm_expr.span(),
            );
        }
        for setter in &ctx.state_setters {
            if pm_src.contains(&format!("{setter}(")) {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoStateInPointerMove,
                    "r3fNoStateInPointerMove",
                    setter,
                    "Avoid React state updates inside `onPointerMove`; mutate a ref and commit state on pointer-up.".to_string(),
                    pm_expr.span(),
                );
            }
        }
    }

    for item in &opening.attributes {
        let JSXAttributeItem::Attribute(attr) = item else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        if !attr_id.name.starts_with("onPointer")
            && !matches!(attr_id.name.as_str(), "onClick" | "onWheel")
        {
            continue;
        }
        let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
            continue;
        };
        let Some(expr) = c.expression.as_expression() else {
            continue;
        };
        let handler_src = expr.span().source_text(ctx.source);
        if handler_src.contains(".object.setPointerCapture(")
            || handler_src.contains(".eventObject.setPointerCapture(")
            || handler_src.contains(".object.releasePointerCapture(")
            || handler_src.contains(".eventObject.releasePointerCapture(")
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoObjectPointerCapture,
                "r3fNoObjectPointerCapture",
                attr_id.name.as_str(),
                "Call pointer-capture methods on `event.target` or `event.currentTarget`, not `event.object` or `event.eventObject`.".to_string(),
                expr.span(),
            );
        }
        if handler_src.contains(".point.set(")
            || handler_src.contains(".point.add(")
            || handler_src.contains(".point.sub(")
            || handler_src.contains(".point.multiplyScalar(")
            || handler_src.contains(".ray.applyMatrix4(")
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoMutatingPointerEventData,
                "r3fNoMutatingPointerEventData",
                attr_id.name.as_str(),
                "Do not mutate shared R3F pointer-event hit vectors (`point`, `ray`, `uv`, `normal`) in place; clone or copy first.".to_string(),
                expr.span(),
            );
        }
    }
}

fn get_jsx_args_elem<'a>(
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

fn is_inside_render_phase(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
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

fn is_inside_array_map(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id)
            && extract_callee_short(&call.callee) == Some("map")
        {
            return true;
        }
    }
    false
}

fn has_unstable_r3f_args(args_expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::ArrayExpression(arr) = args_expr.without_parentheses() else {
        return is_fresh_render_allocation(args_expr, semantic);
    };
    arr.elements.iter().any(|elem| {
        elem.as_expression()
            .is_some_and(|e| is_fresh_render_allocation(e, semantic))
    })
}

fn is_fresh_render_allocation(expr: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
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
            }
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

fn eval_static_f64(expr: &Expression<'_>) -> Option<f64> {
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

fn eval_static_array_len(expr: &Expression<'_>) -> Option<usize> {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => Some(arr.elements.len()),
        Expression::NewExpression(new_expr) => {
            let first = new_expr.arguments.first()?.as_expression()?;
            match first.without_parentheses() {
                Expression::NumericLiteral(n) if n.value >= 0.0 && n.value.fract() == 0.0 =>
                {
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "validated non-negative integer"
                    )]
                    Some(n.value as usize)
                }
                Expression::ArrayExpression(arr) => Some(arr.elements.len()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_valid_shadow_map_size(val: f64) -> bool {
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

// =============================================================================
// 2. Call Expression & 60fps Frame Loop Rules
// =============================================================================

fn check_call_expressions(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_short = extract_callee_short(&call.callee);

        // 1. `useFrame` rules
        if ctx.is_r3f_hook_call(call, "useFrame") {
            check_use_frame_call(ctx, node_id, call, sites);
        }

        // 2. `requestAnimationFrame` & `setAnimationLoop` rules
        if callee_short == Some("requestAnimationFrame") || callee_short == Some("setAnimationLoop")
        {
            check_animation_loop_call(
                ctx,
                node_id,
                call,
                callee_short.unwrap_or("requestAnimationFrame"),
                sites,
            );
        }

        // 3. `useThree` rules (`r3f-no-fresh-use-three-selector`, `r3f-no-deep-use-three-selector`, `r3f-webgpu-no-gl-state`)
        if ctx.is_r3f_hook_call(call, "useThree") {
            check_use_three_call(ctx, node_id, call, sites);
        }

        // 4. `createPortal` (`r3f-no-fresh-portal-container`)
        if ctx.is_r3f_hook_call(call, "createPortal")
            && is_inside_render_phase(ctx.semantic, node_id)
            && let Some(container) = call.arguments.get(1).and_then(Argument::as_expression)
            && is_fresh_render_allocation(container, ctx.semantic)
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fNoFreshPortalContainer,
                "r3fNoFreshPortalContainer",
                "createPortal",
                "`createPortal` receives a freshly allocated container during render; memoize the container.".to_string(),
                container.span(),
            );
        }

        // 5. `extend` (`r3f-no-extend-in-render`, `r3f-no-extend-three-namespace`)
        if ctx.is_r3f_hook_call(call, "extend") {
            if find_enclosing_react_node(ctx.semantic, node_id).is_some() {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoExtendInRender,
                    "r3fNoExtendInRender",
                    "extend",
                    "Call R3F `extend(...)` at module scope rather than inside a component or hook.".to_string(),
                    call.span,
                );
            }
            if let Some(arg) = call.arguments.first().and_then(Argument::as_expression) {
                let arg_src = arg.span().source_text(ctx.source).trim();
                if arg_src == "THREE" || arg_src.contains("...THREE") {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fNoExtendThreeNamespace,
                        "r3fNoExtendThreeNamespace",
                        "extend",
                        "Registering the entire `THREE` namespace with `extend(THREE)` prevents tree-shaking.".to_string(),
                        arg.span(),
                    );
                }
            }
        }

        // 6. Loader cache & input rules (`r3f-no-null-loader-input`, `r3f-no-dispose-loader-cache`, `r3f-no-mutate-loader-cache`, `r3f-prefer-use-loader`)
        if is_cached_loader_hook_call(call, &ctx.imported_symbols, &ctx.namespace_imports) {
            let url_arg_idx = usize::from(callee_short == Some("useLoader"));
            if let Some(url_expr) = call
                .arguments
                .get(url_arg_idx)
                .and_then(Argument::as_expression)
                && expr_can_be_nullish(url_expr, ctx.source)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoNullLoaderInput,
                    "r3fNoNullLoaderInput",
                    callee_short.unwrap_or("useLoader"),
                    "Loader hook input can be `null` or `undefined`; conditionally render the loading component instead.".to_string(),
                    url_expr.span(),
                );
            }
        }

        if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
            let method = mem.property.name.as_str();
            let root_ident = extract_root_ident_name(&mem.object);

            // `r3f-no-dispose-loader-cache`
            if method == "dispose"
                && let Some(root) = &root_ident
                && ctx.loader_cache_vars.contains(root)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoDisposeLoaderCache,
                    "r3fNoDisposeLoaderCache",
                    root,
                    "Do not call `.dispose()` on assets returned by cached R3F/Drei loader hooks."
                        .to_string(),
                    call.span,
                );
            }

            // `r3f-no-mutate-loader-cache`
            if matches!(
                method,
                "set"
                    | "copy"
                    | "add"
                    | "remove"
                    | "applyMatrix4"
                    | "translate"
                    | "rotateX"
                    | "rotateY"
                    | "rotateZ"
            ) && let Some(root) = &root_ident
                && ctx.loader_cache_vars.contains(root)
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::R3fNoMutateLoaderCache,
                    "r3fNoMutateLoaderCache",
                    root,
                    format!("Mutating cached loader asset `{root}` via `.{method}(...)` corrupts shared cache state; `.clone()` first."),
                    call.span,
                );
            }

            // `r3f-prefer-use-loader`
            if matches!(method, "load" | "loadAsync") && ctx.has_r3f_import {
                let obj_src = mem.object.span().source_text(ctx.source);
                if obj_src.contains("Loader") && is_inside_effect_hook(ctx.semantic, node_id) {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fPreferUseLoader,
                        "r3fPreferUseLoader",
                        method,
                        "Prefer R3F `useLoader` (or Drei `useGLTF` / `useTexture`) over imperative Three.js loader calls in `useEffect`.".to_string(),
                        call.span,
                    );
                }
            }

            // `three-require-loader-error-handling`
            if method == "load" {
                let obj_ctor = ctx.resolve_expr_three_ctor(&mem.object);
                if obj_ctor.as_deref().is_some_and(|c| c.ends_with("Loader"))
                    && call.arguments.len() < 4
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeRequireLoaderErrorHandling,
                        "threeRequireLoaderErrorHandling",
                        "load",
                        "Provide `Loader.load` with an `onError` callback or use `await loader.loadAsync(...)`.".to_string(),
                        call.span,
                    );
                }
            }

            // `three-require-ktx2-detect-support`
            if matches!(method, "load" | "loadAsync")
                && ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("KTX2Loader")
                && !ctx.source.contains(".detectSupport(")
                && !ctx.source.contains(".detectSupportAsync(")
            {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeRequireKtx2DetectSupport,
                    "threeRequireKtx2DetectSupport",
                    "KTX2Loader",
                    "Call `ktx2Loader.detectSupport(renderer)` before loading KTX2 textures."
                        .to_string(),
                    call.span,
                );
            }

            // `three-cap-device-pixel-ratio`
            if method == "setPixelRatio"
                && let Some(arg) = call.arguments.first().and_then(Argument::as_expression)
            {
                let arg_src = arg.span().source_text(ctx.source);
                if arg_src.contains("devicePixelRatio") && !arg_src.contains("Math.min") {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeCapDevicePixelRatio,
                        "threeCapDevicePixelRatio",
                        "setPixelRatio",
                        "Cap `window.devicePixelRatio` (e.g. `Math.min(window.devicePixelRatio, 2)`) before passing to `setPixelRatio`.".to_string(),
                        arg.span(),
                    );
                }
            }

            // `three-valid-shadow-map-size`
            if method == "set" {
                let obj_src = mem.object.span().source_text(ctx.source);
                if obj_src.ends_with(".shadow.mapSize") {
                    for arg in call.arguments.iter().take(2) {
                        if let Some(expr) = arg.as_expression()
                            && let Some(val) = eval_static_f64(expr)
                            && !is_valid_shadow_map_size(val)
                        {
                            ctx.push_site(
                                sites,
                                node_id,
                                RuleId::ThreeValidShadowMapSize,
                                "threeValidShadowMapSize",
                                "mapSize",
                                format!("Shadow map size {val} is invalid; dimensions must be positive powers of two."),
                                expr.span(),
                            );
                        }
                    }
                } else if obj_src.ends_with(".repeat") {
                    // `three-texture-repeat-requires-wrapping`
                    let tex_prefix = obj_src.trim_end_matches(".repeat");
                    let rx = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(eval_static_f64)
                        .unwrap_or(1.0);
                    let ry = call
                        .arguments
                        .get(1)
                        .and_then(Argument::as_expression)
                        .and_then(eval_static_f64)
                        .unwrap_or(1.0);
                    let has_wrap_s = ctx.source.contains(&format!("{tex_prefix}.wrapS ="));
                    let has_wrap_t = ctx.source.contains(&format!("{tex_prefix}.wrapT ="));
                    if (rx > 1.0 && !has_wrap_s) || (ry > 1.0 && !has_wrap_t) {
                        ctx.push_site(
                            sites,
                            node_id,
                            RuleId::ThreeTextureRepeatRequiresWrapping,
                            "threeTextureRepeatRequiresWrapping",
                            "repeat",
                            "Texture `repeat > 1` without setting `wrapS` / `wrapT` to `RepeatWrapping` or `MirroredRepeatWrapping`.".to_string(),
                            call.span,
                        );
                    }
                }
            }

            // `r3f-no-imperative-attach-of-managed-ref`
            if matches!(method, "add" | "attach") {
                for arg in &call.arguments {
                    if let Some(Expression::StaticMemberExpression(arg_mem)) =
                        arg.as_expression().map(Expression::without_parentheses)
                        && arg_mem.property.name == "current"
                        && let Expression::Identifier(ref_id) = arg_mem.object.without_parentheses()
                        && ctx.jsx_managed_refs.contains_key(ref_id.name.as_str())
                    {
                        ctx.push_site(
                            sites,
                            node_id,
                            RuleId::R3fNoImperativeAttachOfManagedRef,
                            "r3fNoImperativeAttachOfManagedRef",
                            ref_id.name.as_str(),
                            format!(
                                "Do not imperatively `.{method}({}.current)` when `{}` is already attached via JSX `ref`.",
                                ref_id.name, ref_id.name
                            ),
                            call.span,
                        );
                    }
                }
            }

            // `three-webgpu-require-init-before-sync-operation`
            if WEBGPU_SYNC_METHODS.contains(&method)
                && ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("WebGPURenderer")
                && let Expression::Identifier(renderer_id) = mem.object.without_parentheses()
            {
                let before_slice = &ctx.source[..call.span.start as usize];
                let awaited_init =
                    before_slice.contains(&format!("await {}.init()", renderer_id.name));
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

            // `three-gpu-computation-handle-init-error`, `three-gpu-computation-require-init-before-compute`, `three-gpu-computation-valid-variable-name`
            if ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("GPUComputationRenderer")
            {
                if method == "init"
                    && matches!(
                        ctx.semantic.nodes().parent_kind(node_id),
                        AstKind::ExpressionStatement(_)
                    )
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeGpuComputationHandleInitError,
                        "threeGpuComputationHandleInitError",
                        "init",
                        "`GPUComputationRenderer.init()` returns an error string on failure; check the returned value.".to_string(),
                        call.span,
                    );
                } else if method == "compute"
                    && !ctx.source[..call.span.start as usize].contains(".init(")
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeGpuComputationRequireInitBeforeCompute,
                        "threeGpuComputationRequireInitBeforeCompute",
                        "compute",
                        "Call `GPUComputationRenderer.init()` before calling `.compute()`."
                            .to_string(),
                        call.span,
                    );
                } else if method == "addVariable"
                    && let Some(Argument::StringLiteral(var_lit)) = call.arguments.first()
                    && let Some(vname) = var_lit.value.as_str()
                    && (vname.is_empty()
                        || vname.starts_with("gl_")
                        || vname.contains("__")
                        || THREE_SHADER_BUILTINS.contains(&vname))
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeGpuComputationValidVariableName,
                        "threeGpuComputationValidVariableName",
                        vname,
                        format!("Invalid GPUComputationRenderer variable name `{vname}`."),
                        var_lit.span,
                    );
                }
            }

            // `r3f-require-instanced-buffer-update` & `three-require-instanced-buffer-update`
            if matches!(method, "setMatrixAt" | "setColorAt" | "setMorphAt") {
                let required_flag = match method {
                    "setColorAt" => "instanceColor.needsUpdate",
                    "setMorphAt" => "morphTexture.needsUpdate",
                    _ => "instanceMatrix.needsUpdate",
                };
                if !ctx.source.contains(required_flag) {
                    let rule = if ctx.has_r3f_import {
                        RuleId::R3fRequireInstancedBufferUpdate
                    } else {
                        RuleId::ThreeRequireInstancedBufferUpdate
                    };
                    ctx.push_site(
                        sites,
                        node_id,
                        rule,
                        "requireInstancedBufferUpdate",
                        method,
                        format!("After `{method}(...)`, set `{required_flag} = true` so the GPU uploads the updated instance buffer."),
                        call.span,
                    );
                }
            }
        }

        // 7. TSL & WebGPU uniform branch (`three-tsl-no-js-uniform-branch`, `r3f-webgpu-no-js-uniform-branch`, `r3f-webgpu-no-unregistered-pipeline-pass`)
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

        // 8. `r3f-require-global-effect-cleanup` & `r3f-require-root-unmount`
        if matches!(
            callee_short,
            Some("addEffect" | "addAfterEffect" | "addTail")
        ) && matches!(
            ctx.semantic.nodes().parent_kind(node_id),
            AstKind::ExpressionStatement(_)
        ) {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fRequireGlobalEffectCleanup,
                "r3fRequireGlobalEffectCleanup",
                callee_short.unwrap_or("addEffect"),
                "Capture and return the disposer from `addEffect` / `addAfterEffect` / `addTail` inside a React cleanup.".to_string(),
                call.span,
            );
        }
        if callee_short == Some("createRoot")
            && ctx.has_r3f_import
            && !ctx.source.contains(".unmount(")
        {
            ctx.push_site(
                sites,
                node_id,
                RuleId::R3fRequireRootUnmount,
                "r3fRequireRootUnmount",
                "createRoot",
                "Component-owned R3F `createRoot(...)` is never unmounted via `root.unmount()` in cleanup.".to_string(),
                call.span,
            );
        }
    }
}

fn check_use_frame_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. `r3f-no-use-frame-dependency-array` & `r3f-require-render-with-positive-priority`
    if let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression) {
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
        {
            let cb_text = first_arg.span().source_text(ctx.source);
            if !cb_text.contains(".render(") {
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
    }

    let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb = cb_expr.without_parentheses();
    let cb_span = resolve_callback_body_span(cb, ctx.semantic);
    let cb_text = cb_span.source_text(ctx.source);

    // 2. `r3f-no-async-use-frame`
    let is_async = match cb {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(func) => func.r#async,
        _ => false,
    };
    if is_async {
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

    // 3. `r3f-no-advancing-clock-in-use-frame`
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

    // 4. `r3f-no-compile-in-use-frame`
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

    // 5. `r3f-require-render-target-reset`
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

    // 6. Inspect AST nodes inside `cb_span`
    let delta_param = extract_callback_param_name(cb, 1);
    for (inner_id, inner_node) in ctx.semantic.nodes().iter_enumerated() {
        let nspan = inner_node.span();
        if !cb_span.contains_inclusive(nspan) {
            continue;
        }
        let is_cond = is_conditionally_executed_within(ctx.semantic, inner_id, cb_span);

        match inner_node.kind() {
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
                let inner_short = extract_callee_short(&inner_call.callee);
                if !is_cond && inner_short == Some("clone") {
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

                if !is_cond
                    && let Some(m) = inner_short
                    && SYNC_WEBGL_READBACK_METHODS.contains(&m)
                {
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

                if let Some(m) = inner_short
                    && ctx.state_setters.contains(m)
                    && !is_guarded_state_update_in_frame(ctx, inner_id, cb_span)
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fNoStateInUseFrame,
                        "r3fNoStateInUseFrame",
                        m,
                        format!("React state update `{m}(...)` inside `useFrame` schedules re-renders at 60fps; mutate a ref or guard transitions with an equality check."),
                        inner_call.span,
                    );
                }

                // `r3f-prefer-gpu-instanced-animation` & `r3f-prefer-gpu-position-animation`
                if matches!(inner_short, Some("setMatrixAt" | "setColorAt"))
                    && is_inside_loop_within(ctx.semantic, inner_id, cb_span)
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fPreferGpuInstancedAnimation,
                        "r3fPreferGpuInstancedAnimation",
                        inner_short.unwrap_or("setMatrixAt"),
                        "Repeated per-instance transform updates in `useFrame`; prefer a vertex shader or GPU instanced attributes.".to_string(),
                        inner_call.span,
                    );
                }
                if matches!(inner_short, Some("setXYZ" | "setX" | "setY" | "setZ"))
                    && is_inside_loop_within(ctx.semantic, inner_id, cb_span)
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::R3fPreferGpuPositionAnimation,
                        "r3fPreferGpuPositionAnimation",
                        inner_short.unwrap_or("setXYZ"),
                        "Per-vertex CPU position animation inside `useFrame`; animate vertex positions in a vertex shader.".to_string(),
                        inner_call.span,
                    );
                }
            }
            AstKind::AssignmentExpression(assign) => {
                let lhs_text = assign.left.span().source_text(ctx.source);
                let rhs_text = assign.right.span().source_text(ctx.source);

                // `r3f-require-frame-delta`
                if matches!(
                    assign.operator,
                    AssignmentOperator::Addition | AssignmentOperator::Subtraction
                ) && (lhs_text.contains(".rotation.")
                    || lhs_text.contains(".position.")
                    || lhs_text.contains(".scale."))
                {
                    let uses_delta = delta_param.as_deref().is_some_and(|d| rhs_text.contains(d))
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

                // `r3f-no-shader-configuration-mutation-in-use-frame`
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
            _ => {}
        }
    }
}

fn check_animation_loop_call(
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
    let cb_text = cb_span.source_text(ctx.source);

    // Avoid duplicate reporting on recursive `requestAnimationFrame(animate)` inside `animate` itself
    if loop_name == "requestAnimationFrame"
        && matches!(cb, Expression::Identifier(_))
        && let Some(enclosing_fn) = find_enclosing_function_span(ctx.semantic, node_id)
        && enclosing_fn == cb_span
    {
        return;
    }

    // `r3f-no-recursive-raf-with-use-frame`
    if ctx.has_r3f_import && ctx.source.contains("useFrame(") {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoRecursiveRafWithUseFrame,
            "r3fNoRecursiveRafWithUseFrame",
            loop_name,
            format!("Component starts `{loop_name}` while also using R3F `useFrame`; consolidate frame updates inside `useFrame`."),
            call.span,
        );
    }

    // `three-prefer-set-animation-loop`
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

    // `three-require-render-in-animation-loop`
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

    // `three-no-async-animation-loop`
    let is_async = match cb {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(func) => func.r#async,
        _ => false,
    };
    if is_async {
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

    for (inner_id, inner_node) in ctx.semantic.nodes().iter_enumerated() {
        let nspan = inner_node.span();
        if !cb_span.contains_inclusive(nspan) {
            continue;
        }
        let is_cond = is_conditionally_executed_within(ctx.semantic, inner_id, cb_span);

        match inner_node.kind() {
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
                let inner_short = extract_callee_short(&inner_call.callee);
                if !is_cond && inner_short == Some("clone") {
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
                if !is_cond
                    && let Some(m) = inner_short
                    && SYNC_WEBGL_READBACK_METHODS.contains(&m)
                {
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
                if !is_cond && matches!(inner_short, Some("compile" | "compileAsync")) {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeNoCompileInAnimationLoop,
                        "threeNoCompileInAnimationLoop",
                        inner_short.unwrap_or("compile"),
                        "Precompile materials outside the animation loop.".to_string(),
                        inner_call.span,
                    );
                }
                if !is_cond && matches!(inner_short, Some("setSize" | "setDrawingBufferSize")) {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeNoUnconditionalRendererResizeInAnimationLoop,
                        "threeNoUnconditionalRendererResizeInAnimationLoop",
                        inner_short.unwrap_or("setSize"),
                        "Do not resize the renderer unconditionally on every animation frame."
                            .to_string(),
                        inner_call.span,
                    );
                }
                if let Some(m) = inner_short
                    && ctx.state_setters.contains(m)
                    && !is_guarded_state_update_in_frame(ctx, inner_id, cb_span)
                {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeNoStateInAnimationLoop,
                        "threeNoStateInAnimationLoop",
                        m,
                        "Avoid unguarded React state updates inside a Three.js animation loop."
                            .to_string(),
                        inner_call.span,
                    );
                }
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
}

fn check_use_three_call(
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

fn resolve_callback_body_span(cb: &Expression<'_>, semantic: &Semantic<'_>) -> Span {
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
        Expression::CallExpression(call)
            if extract_callee_short(&call.callee) == Some("useCallback") =>
        {
            if let Some(first) = call.arguments.first().and_then(Argument::as_expression) {
                resolve_callback_body_span(first, semantic)
            } else {
                call.span
            }
        }
        _ => cb.span(),
    }
}

fn find_enclosing_function_span(semantic: &Semantic<'_>, node_id: NodeId) -> Option<Span> {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => return func.body.as_ref().map(|b| b.span),
            AstKind::ArrowFunctionExpression(arrow) => return Some(arrow.body.span()),
            _ => {}
        }
    }
    None
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

fn is_conditionally_executed_within(
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
                if test_src.contains("!==")
                    || test_src.contains("===")
                    || test_src.contains("!=")
                    || test_src.contains("==")
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn expr_can_be_nullish(expr: &Expression<'_>, source: &str) -> bool {
    match expr.without_parentheses() {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        Expression::ChainExpression(_) => true,
        Expression::ConditionalExpression(cond) => {
            expr_can_be_nullish(&cond.consequent, source)
                || expr_can_be_nullish(&cond.alternate, source)
        }
        Expression::LogicalExpression(log) if log.operator == LogicalOperator::Or => {
            expr_can_be_nullish(&log.right, source)
        }
        _ => {
            let s = expr.span().source_text(source);
            s.contains("?.") || s.ends_with(": null") || s.ends_with(": undefined")
        }
    }
}

fn extract_root_ident_name(expr: &Expression<'_>) -> Option<String> {
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

fn is_inside_effect_hook(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
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

// =============================================================================
// 3. NewExpression Validators & GPU Resource Disposal Lifecycle Rules
// =============================================================================

fn check_new_expressions_and_lifecycle(
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
        if ctx.has_webgpu {
            if matches!(ctor.as_str(), "ShaderMaterial" | "RawShaderMaterial") {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeWebgpuNoLegacyMaterialApi,
                    "threeWebgpuNoLegacyMaterialApi",
                    &ctor,
                    format!("`{ctor}` is not supported by Three.js `WebGPURenderer`; use node materials and TSL."),
                    new_expr.span,
                );
            } else if ctor == "EffectComposer" {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeWebgpuNoLegacyEffectComposer,
                    "threeWebgpuNoLegacyEffectComposer",
                    "EffectComposer",
                    "Legacy `EffectComposer` does not support `WebGPURenderer`; use the node-based post-processing pipeline.".to_string(),
                    new_expr.span,
                );
            }
        }

        // 4. Camera constructors (`three-valid-perspective-camera`, `three-valid-orthographic-camera`)
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
                    format!("`MeshBasicMaterial` ignores `{ignored}`; use `MeshStandardMaterial` or `MeshPhysicalMaterial`."),
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
            format!("Component-owned postprocessing resource `{ctor}` is not disposed in React effect cleanup."),
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

fn get_obj_prop_expr<'a>(obj: &'a ObjectExpression<'a>, key: &str) -> Option<&'a Expression<'a>> {
    for prop_kind in obj.properties.iter().rev() {
        if let ObjectPropertyKind::ObjectProperty(prop) = prop_kind
            && prop.key.static_name().as_ref().and_then(|n| n.as_str()) == Some(key)
        {
            return Some(prop.value.without_parentheses());
        }
    }
    None
}

// =============================================================================
// 4. Assignment & Update Rules
// =============================================================================

fn check_assignments_and_updates(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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
                format!("Mutating property `.{prop}` on cached loader asset `{root}`; clone before mutating."),
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
                format!("`{ctor}` cannot cast shadows; use `DirectionalLight`, `PointLight`, or `SpotLight`."),
                assign.span,
            );
        }

        // 3. `three-webgpu-no-high-precision-instancing` & `three-webgpu-no-legacy-material-api`
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
                "`WebGPURenderer.highPrecision` is incompatible with `InstancedMesh` and `SkinnedMesh`.".to_string(),
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
                "`onBeforeCompile` is not supported by `WebGPURenderer`; use node materials and TSL.".to_string(),
                assign.span,
            );
        } else if prop == "onBeforeCompile" && !ctx.source.contains("customProgramCacheKey") {
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

// =============================================================================
// 5. Closed Scene & Canvas Contracts (Shadows, Point Lights, Lighting, UVs, Normals, Resize)
// =============================================================================

fn check_scene_and_canvas_contracts(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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

// =============================================================================
// 6. GLSL Shader & RawShaderMaterial Rules (`three-shader-*` and `three-raw-shader-*`)
// =============================================================================

fn check_shader_materials(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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
                    format!("Uniform `{uname}` must be defined as `{{ value: ... }}` or `new THREE.Uniform(...)`."),
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
                let has_binding =
                    uniforms_expr.is_some_and(|u| u.span().source_text(ctx.source).contains(uname));
                if !has_binding {
                    ctx.push_site(
                        sites,
                        node_id,
                        RuleId::ThreeShaderRequireUniformBindings,
                        "threeShaderRequireUniformBindings",
                        uname,
                        format!("GLSL uniform `{uname}` is missing from the `ShaderMaterial` `uniforms` object."),
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
                    format!("Uniform `{uname}` has type `{v_type}` in vertex shader and `{f_type}` in fragment shader."),
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
                        format!("Fragment input `{vname}` (`{f_type}`) has no matching vertex output declaration."),
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

// =============================================================================
// 7. Cross-File 60fps Frame-Loop Call-Graph Extraction (`FrameLoopRootIr` & `FrameHelperIr`)
// =============================================================================

fn extract_frame_loop_roots(ctx: &FileAnalysisCtx<'_>) -> Vec<FrameLoopRootIr> {
    let mut roots = Vec::new();

    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_short = extract_callee_short(&call.callee);
        let kind = if ctx.is_r3f_hook_call(call, "useFrame") {
            Some(FrameLoopRootKind::UseFrame)
        } else if matches!(
            callee_short,
            Some("requestAnimationFrame" | "setAnimationLoop")
        ) {
            Some(FrameLoopRootKind::AnimationLoop)
        } else {
            None
        };
        let Some(root_kind) = kind else {
            continue;
        };
        let Some(cb_expr) = call.arguments.first().and_then(Argument::as_expression) else {
            continue;
        };
        let cb = cb_expr.without_parentheses();
        if matches!(callee_short, Some("requestAnimationFrame"))
            && matches!(cb, Expression::Identifier(_))
            && find_enclosing_function_span(ctx.semantic, node_id)
                == Some(resolve_callback_body_span(cb, ctx.semantic))
        {
            continue;
        }
        let cb_span = resolve_callback_body_span(cb, ctx.semantic);
        if cb_span.start == cb_span.end {
            continue;
        }

        let outgoing_calls = collect_outgoing_calls_in_span(ctx, cb_span);
        if outgoing_calls.is_empty() {
            continue;
        }
        let (loc, span) = ctx.loc_and_span(call.span);
        roots.push(FrameLoopRootIr {
            kind: root_kind,
            subject_name: ctx.subject_for_node(node_id),
            loc,
            span,
            outgoing_calls,
        });
    }

    roots
}

fn extract_frame_helpers(ctx: &FileAnalysisCtx<'_>) -> Vec<FrameHelperIr> {
    let mut helpers = Vec::new();

    for (_node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let (name, decl_span, body_span, param_names) = match node.kind() {
            AstKind::Function(func) => {
                let Some(id) = &func.id else {
                    continue;
                };
                let Some(body) = &func.body else {
                    continue;
                };
                let params = collect_param_names(&func.params);
                (id.name.to_string(), func.span, body.span, params)
            }
            AstKind::VariableDeclarator(decl) => {
                let BindingPattern::BindingIdentifier(id) = &decl.id else {
                    continue;
                };
                let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
                    continue;
                };
                match init {
                    Expression::ArrowFunctionExpression(arrow) => (
                        id.name.to_string(),
                        decl.span,
                        arrow.body.span(),
                        collect_param_names(&arrow.params),
                    ),
                    Expression::FunctionExpression(func) => {
                        let Some(body) = &func.body else {
                            continue;
                        };
                        (
                            id.name.to_string(),
                            decl.span,
                            body.span,
                            collect_param_names(&func.params),
                        )
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };

        let mut exported_names = Vec::new();
        for exp in &ctx.module.exports {
            if exp.from_source.is_none()
                && (exp.name == name || exp.local_name.as_deref() == Some(name.as_str()))
            {
                exported_names.push(exp.name.clone());
            }
        }

        let hazards = collect_helper_hazards_in_span(ctx, body_span, &param_names);
        let outgoing_calls = collect_outgoing_calls_in_span(ctx, body_span);
        let (loc, span) = ctx.loc_and_span(decl_span);
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

fn collect_param_names(params: &FormalParameters<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for p in &params.items {
        collect_binding_identifiers(&p.pattern, &mut out);
    }
    out
}

fn collect_outgoing_calls_in_span(
    ctx: &FileAnalysisCtx<'_>,
    target_span: Span,
) -> Vec<FrameCallTargetIr> {
    let mut out = Vec::new();

    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !target_span.contains_inclusive(call.span)
            || is_conditionally_executed_within(ctx.semantic, node_id, target_span)
        {
            continue;
        }
        let (call_loc, call_span) = ctx.loc_and_span(call.span);
        match call.callee.without_parentheses() {
            Expression::Identifier(id) => {
                let callee_name = id.name.to_string();
                if matches!(
                    callee_name.as_str(),
                    "useFrame" | "requestAnimationFrame" | "cancelAnimationFrame"
                ) {
                    continue;
                }
                if let Some((src, orig)) = ctx.imported_symbols.get(callee_name.as_str()) {
                    out.push(FrameCallTargetIr {
                        callee_name,
                        imported_name: Some(orig.clone()),
                        import_source: Some(src.clone()),
                        call_loc,
                        call_span,
                    });
                } else {
                    out.push(FrameCallTargetIr {
                        callee_name,
                        imported_name: None,
                        import_source: None,
                        call_loc,
                        call_span,
                    });
                }
            }
            Expression::StaticMemberExpression(mem) => {
                if let Expression::Identifier(ns) = mem.object.without_parentheses()
                    && let Some(src) = ctx.namespace_imports.get(ns.name.as_str())
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
    ctx: &FileAnalysisCtx<'_>,
    body_span: Span,
    param_names: &HashSet<String>,
) -> Vec<FrameHelperHazard> {
    let mut hazards = Vec::new();

    for (node_id, node) in ctx.semantic.nodes().iter_enumerated() {
        let nspan = node.span();
        if !body_span.contains_inclusive(nspan)
            || is_conditionally_executed_within(ctx.semantic, node_id, body_span)
        {
            continue;
        }
        let (loc, span) = ctx.loc_and_span(nspan);

        match node.kind() {
            AstKind::NewExpression(new_expr) => {
                if let Some(ctor) = resolve_callee_ctor_name(
                    &new_expr.callee,
                    &ctx.imported_symbols,
                    &ctx.namespace_imports,
                ) {
                    hazards.push(FrameHelperHazard {
                        kind: FrameHelperHazardKind::NewAllocation(ctor),
                        loc,
                        span,
                    });
                }
            }
            AstKind::ArrayExpression(_) => {
                hazards.push(FrameHelperHazard {
                    kind: FrameHelperHazardKind::ArrayAllocation,
                    loc,
                    span,
                });
            }
            AstKind::ObjectExpression(_) => {
                hazards.push(FrameHelperHazard {
                    kind: FrameHelperHazardKind::ObjectAllocation,
                    loc,
                    span,
                });
            }
            AstKind::CallExpression(call) => {
                let callee_short = extract_callee_short(&call.callee);
                if callee_short == Some("clone") {
                    let recv = match call.callee.without_parentheses() {
                        Expression::StaticMemberExpression(m) => {
                            m.object.span().source_text(ctx.source).to_string()
                        }
                        _ => "object".to_string(),
                    };
                    hazards.push(FrameHelperHazard {
                        kind: FrameHelperHazardKind::CloneAllocation(recv),
                        loc,
                        span,
                    });
                } else if let Some(m) = callee_short {
                    if SYNC_WEBGL_READBACK_METHODS.contains(&m) {
                        hazards.push(FrameHelperHazard {
                            kind: FrameHelperHazardKind::SyncReadback(m.to_string()),
                            loc,
                            span,
                        });
                    } else if ctx.state_setters.contains(m)
                        || m == "setState"
                        || (m.starts_with("set")
                            && m.len() > 3
                            && m.as_bytes()[3].is_ascii_uppercase()
                            && param_names.contains(m))
                    {
                        hazards.push(FrameHelperHazard {
                            kind: FrameHelperHazardKind::StateUpdate(m.to_string()),
                            loc,
                            span,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    hazards
}
