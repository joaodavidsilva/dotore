//! React Three Fiber (`r3f-*`) `useFrame`, `requestAnimationFrame` / `setAnimationLoop`,
//! `useThree`, loader hooks, pointer handlers, and R3F JSX/import rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentOperator, BindingPattern, CallExpression, Expression, FormalParameters,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXOpeningElement, LogicalOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};

use super::{
    FileAnalysisCtx, SYNC_WEBGL_READBACK_METHODS, THREE_SHADER_BUILTINS, eval_static_f64,
    extract_callee_short, extract_root_ident_name, find_enclosing_function_span, get_jsx_attr_expr,
    has_unstable_r3f_args, is_cached_loader_hook_call, is_conditionally_executed_within,
    is_fresh_render_allocation, is_inside_array_map, is_inside_effect_hook, is_inside_render_phase,
    is_r3f_intrinsic_tag, is_valid_shadow_map_size, jsx_opening_tag_name,
    resolve_callback_body_span, resolve_callee_ctor_name,
    three_lifecycle::check_jsx_material_and_light_props,
    webgpu::{
        check_canvas_opening, check_tsl_and_webgpu_pipeline_call, check_webgpu_jsx_opening,
        check_webgpu_sync_member_call, check_webgpu_use_three_gl_state,
    },
};
use crate::{
    ir::{react_ast::find_enclosing_react_node, types::SemanticRuleSite},
    rules::RuleId,
};

pub(crate) fn check_module_imports(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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

pub(crate) fn check_jsx_elements(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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
        check_webgpu_jsx_opening(ctx, node_id, opening, &tag, sites);

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

pub(crate) fn check_call_expressions(ctx: &FileAnalysisCtx<'_>, sites: &mut Vec<SemanticRuleSite>) {
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
                    format!(
                        "Mutating cached loader asset `{root}` via `.{method}(...)` corrupts shared cache state; `.clone()` first."
                    ),
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
                                format!(
                                    "Shadow map size {val} is invalid; dimensions must be positive powers of two."
                                ),
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
            check_webgpu_sync_member_call(ctx, node_id, call, mem, method, sites);

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
                        format!(
                            "After `{method}(...)`, set `{required_flag} = true` so the GPU uploads the updated instance buffer."
                        ),
                        call.span,
                    );
                }
            }
        }

        // 7. TSL & WebGPU uniform branch (`three-tsl-no-js-uniform-branch`, `r3f-webgpu-no-js-uniform-branch`, `r3f-webgpu-no-unregistered-pipeline-pass`)
        check_tsl_and_webgpu_pipeline_call(ctx, node_id, call, callee_short, sites);

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

pub(crate) fn check_use_frame_call(
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
                        format!(
                            "Synchronous GPU readback `{m}(...)` inside `useFrame` stalls the GPU pipeline."
                        ),
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
                        format!(
                            "React state update `{m}(...)` inside `useFrame` schedules re-renders at 60fps; mutate a ref or guard transitions with an equality check."
                        ),
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
            format!(
                "Component starts `{loop_name}` while also using R3F `useFrame`; consolidate frame updates inside `useFrame`."
            ),
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
                        format!(
                            "Synchronous GPU readback `{m}(...)` inside animation loop stalls the frame."
                        ),
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
