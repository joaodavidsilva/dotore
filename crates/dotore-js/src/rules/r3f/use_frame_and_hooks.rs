//! React Three Fiber (`r3f-*`) `useFrame`, `requestAnimationFrame` / `setAnimationLoop`,
//! `useThree`, loader hooks, pointer handlers, and R3F JSX/import rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, CallExpression, Expression, JSXAttributeItem, JSXAttributeName,
        JSXAttributeValue, JSXOpeningElement, LogicalOperator, StaticMemberExpression,
    },
};
use oxc_semantic::NodeId;
use oxc_span::GetSpan;

pub(crate) use super::frame_loop_checks::check_use_frame_call;
use super::{
    FileAnalysisCtx, THREE_SHADER_BUILTINS, eval_static_f64, extract_callee_short,
    extract_root_ident_name,
    frame_loop_checks::{check_animation_loop_call, check_use_three_call},
    get_jsx_attr_expr, has_unstable_r3f_args, is_cached_loader_hook_call,
    is_fresh_render_allocation, is_inside_array_map, is_inside_effect_hook, is_inside_render_phase,
    is_r3f_intrinsic_tag, is_valid_shadow_map_size, jsx_opening_tag_name,
    three_lifecycle::check_jsx_material_and_light_props,
    webgpu::{
        check_canvas_opening, check_tsl_and_webgpu_pipeline_call, check_webgpu_jsx_opening,
        check_webgpu_sync_member_call,
    },
};
use crate::{
    ir::{react_ast::find_enclosing_react_node, types::SemanticRuleSite},
    matchers::jsx_has_spread_attr,
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
        let has_spread = jsx_has_spread_attr(&opening.attributes);

        if tag == "Canvas" {
            check_canvas_opening(ctx, node_id, opening, sites);
        }
        check_webgpu_jsx_opening(ctx, node_id, opening, &tag, sites);

        if !is_r3f_intrinsic_tag(&tag) {
            continue;
        }

        check_r3f_intrinsic_jsx_allocations(
            ctx,
            node_id,
            opening,
            &tag,
            has_spread,
            &mut primitive_objs_by_subject,
            sites,
        );
        check_jsx_material_and_light_props(ctx, node_id, opening, &tag, has_spread, sites);
        check_jsx_pointer_handlers(ctx, node_id, opening, sites);
    }
}

fn check_r3f_intrinsic_jsx_allocations(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    opening: &JSXOpeningElement<'_>,
    tag: &str,
    has_spread: bool,
    primitive_objs_by_subject: &mut HashMap<Option<String>, HashSet<String>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
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

    if tag == "primitive"
        && let Some(obj_expr) = get_jsx_attr_expr(opening, "object")
    {
        check_r3f_primitive_object_prop(
            ctx,
            node_id,
            obj_expr,
            primitive_objs_by_subject,
            sites,
        );
    }

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

    if tag == "mesh"
        && !has_spread
        && is_inside_array_map(ctx.semantic, node_id)
        && matches!(
            (
                get_jsx_attr_expr(opening, "geometry"),
                get_jsx_attr_expr(opening, "material"),
            ),
            (Some(Expression::Identifier(_)), Some(Expression::Identifier(_)))
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
}

fn check_r3f_primitive_object_prop(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    obj_expr: &Expression<'_>,
    primitive_objs_by_subject: &mut HashMap<Option<String>, HashSet<String>>,
    sites: &mut Vec<SemanticRuleSite>,
) {
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

        check_r3f_hook_and_root_calls(ctx, node_id, call, callee_short, sites);
        if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
            check_r3f_and_three_member_call(ctx, node_id, call, mem, sites);
        }
        check_tsl_and_webgpu_pipeline_call(ctx, node_id, call, callee_short, sites);
    }
}

fn check_r3f_hook_and_root_calls(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    callee_short: Option<&str>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.is_r3f_hook_call(call, "useFrame") {
        check_use_frame_call(ctx, node_id, call, sites);
    }
    if callee_short == Some("requestAnimationFrame") || callee_short == Some("setAnimationLoop") {
        check_animation_loop_call(
            ctx,
            node_id,
            call,
            callee_short.unwrap_or("requestAnimationFrame"),
            sites,
        );
    }
    if ctx.is_r3f_hook_call(call, "useThree") {
        check_use_three_call(ctx, node_id, call, sites);
    }
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
    if ctx.is_r3f_hook_call(call, "extend") {
        check_r3f_extend_call(ctx, node_id, call, sites);
    }
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
    if callee_short == Some("createRoot") && ctx.has_r3f_import && !ctx.source.contains(".unmount(")
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

fn check_r3f_extend_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if find_enclosing_react_node(ctx.semantic, node_id).is_some() {
        ctx.push_site(
            sites,
            node_id,
            RuleId::R3fNoExtendInRender,
            "r3fNoExtendInRender",
            "extend",
            "Call R3F `extend(...)` at module scope rather than inside a component or hook."
                .to_string(),
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

fn check_r3f_and_three_member_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let method = mem.property.name.as_str();
    check_loader_cache_and_method_call(ctx, node_id, call, mem, method, sites);
    check_renderer_shadow_and_attach_member_call(ctx, node_id, call, mem, method, sites);
    check_webgpu_sync_member_call(ctx, node_id, call, mem, method, sites);
    check_gpu_computation_and_instanced_member_call(ctx, node_id, call, mem, method, sites);
}

fn check_loader_cache_and_method_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    method: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let root_ident = extract_root_ident_name(&mem.object);
    if let Some(root) = &root_ident
        && ctx.loader_cache_vars.contains(root)
    {
        if method == "dispose" {
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
        } else if matches!(
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
        ) {
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
    }

    if !matches!(method, "load" | "loadAsync") {
        return;
    }
    let obj_src = mem.object.span().source_text(ctx.source);
    if ctx.has_r3f_import && obj_src.contains("Loader") && is_inside_effect_hook(ctx.semantic, node_id)
    {
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
    let obj_ctor = ctx.resolve_expr_three_ctor(&mem.object);
    if method == "load"
        && obj_ctor.as_deref().is_some_and(|c| c.ends_with("Loader"))
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
    if obj_ctor.as_deref() == Some("KTX2Loader")
        && !ctx.source.contains(".detectSupport(")
        && !ctx.source.contains(".detectSupportAsync(")
    {
        ctx.push_site(
            sites,
            node_id,
            RuleId::ThreeRequireKtx2DetectSupport,
            "threeRequireKtx2DetectSupport",
            "KTX2Loader",
            "Call `ktx2Loader.detectSupport(renderer)` before loading KTX2 textures.".to_string(),
            call.span,
        );
    }
}

fn check_renderer_shadow_and_attach_member_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    method: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
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
            check_texture_repeat_set_call(ctx, node_id, call, obj_src, sites);
        }
    }

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
}

fn check_texture_repeat_set_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    obj_src: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
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

fn check_gpu_computation_and_instanced_member_call(
    ctx: &FileAnalysisCtx<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    mem: &StaticMemberExpression<'_>,
    method: &str,
    sites: &mut Vec<SemanticRuleSite>,
) {
    if ctx.resolve_expr_three_ctor(&mem.object).as_deref() == Some("GPUComputationRenderer") {
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
        } else if method == "compute" {
            let call_start = usize::try_from(call.span.start).unwrap_or(0);
            if !ctx.source.get(..call_start).unwrap_or("").contains(".init(") {
                ctx.push_site(
                    sites,
                    node_id,
                    RuleId::ThreeGpuComputationRequireInitBeforeCompute,
                    "threeGpuComputationRequireInitBeforeCompute",
                    "compute",
                    "Call `GPUComputationRenderer.init()` before calling `.compute()`.".to_string(),
                    call.span,
                );
            }
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
