//! Per-file R3F/Three.js/WebGL/WebGPU AST analysis context and shared expression evaluators.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; rule visitors match only relevant node kinds (#50)"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentOperator, AssignmentTarget, BinaryOperator, BindingPattern,
        CallExpression, Expression, JSXOpeningElement, ObjectExpression, Program, UnaryOperator,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use super::{
    DREI_LOADER_HOOKS, HTML_INTRINSIC_TAGS, R3F_MODULES, R3F_WEBGPU_MODULES,
    THREE_RENDER_TARGET_CTORS,
};
use crate::{
    ir::{
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{ModuleIr, SemanticRuleSite},
    },
    matchers::{
        collect_pattern_bound_names, find_last_jsx_attr,
        get_object_prop as matcher_get_object_prop, has_jsx_truthy_attr, jsx_attr_expr,
        push_semantic_site,
    },
    rules::RuleId,
};

pub(crate) use crate::ir::motion_and_frame_loop::{
    find_enclosing_function_span, is_conditionally_executed_within, resolve_callback_body_span,
    resolve_callee_ctor_name,
};
pub(crate) use crate::matchers::{callee_name as extract_callee_short, jsx_opening_tag_name};

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
        let (mut imported_symbols, mut namespace_imports, mut has_r3f_import, mut has_webgpu) =
            collect_es_module_imports(module);
        collect_commonjs_require_imports(
            semantic,
            &mut imported_symbols,
            &mut namespace_imports,
            &mut has_r3f_import,
        );

        let mut var_constructors = HashMap::new();
        let mut loader_cache_vars = HashSet::new();
        let mut jsx_managed_refs = HashMap::new();
        let mut texture_color_spaces: HashMap<String, (String, usize)> = HashMap::new();
        let mut render_target_vars = HashSet::new();
        let mut state_setters = HashSet::new();

        for node in semantic.nodes() {
            match node.kind() {
                AstKind::VariableDeclarator(decl) => {
                    record_r3f_var_declarator(
                        decl,
                        &imported_symbols,
                        &namespace_imports,
                        &mut has_webgpu,
                        &mut render_target_vars,
                        &mut var_constructors,
                        &mut state_setters,
                        &mut loader_cache_vars,
                    );
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
                    record_texture_color_space_assignment(assign, &mut texture_color_spaces);
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
        reason = "Constructs SemanticRuleSite directly from rule metadata and AST span without intermediate builder allocation (#50)"
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
                        return false;
                    }
                }
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

#[expect(
    clippy::type_complexity,
    reason = "Returns tuple of imported symbol map, namespace map, and R3F/WebGPU capability flags (#50)"
)]
fn collect_es_module_imports(
    module: &ModuleIr,
) -> (
    HashMap<String, (String, String)>,
    HashMap<String, String>,
    bool,
    bool,
) {
    let mut imported_symbols = HashMap::new();
    let mut namespace_imports = HashMap::new();
    let mut has_r3f_import = false;
    let mut has_webgpu = false;

    for imp in &module.imports {
        if imp.is_type_only {
            continue;
        }
        if R3F_MODULES.contains(&imp.source.as_str()) || imp.source.starts_with("@react-three/") {
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
    (
        imported_symbols,
        namespace_imports,
        has_r3f_import,
        has_webgpu,
    )
}

fn collect_commonjs_require_imports(
    semantic: &Semantic<'_>,
    imported_symbols: &mut HashMap<String, (String, String)>,
    namespace_imports: &mut HashMap<String, String>,
    has_r3f_import: &mut bool,
) {
    for node in semantic.nodes() {
        let AstKind::VariableDeclarator(decl) = node.kind() else {
            continue;
        };
        let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
            continue;
        };
        let Some(req_source) = extract_require_source(init, semantic) else {
            continue;
        };
        if R3F_MODULES.contains(&req_source) || req_source.starts_with("@react-three/") {
            *has_r3f_import = true;
        }
        match &decl.id {
            BindingPattern::BindingIdentifier(id) => {
                namespace_imports.insert(id.name.to_string(), req_source.to_string());
            }
            BindingPattern::ObjectPattern(obj) => {
                for prop in &obj.properties {
                    if let Some(key) = prop.key.static_name().as_ref().and_then(|n| n.as_str())
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

#[expect(
    clippy::too_many_arguments,
    reason = "Populates constructor, render-target, state-setter, and loader-cache tables from a VariableDeclarator (#50)"
)]
fn record_r3f_var_declarator(
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    has_webgpu: &mut bool,
    render_target_vars: &mut HashSet<String>,
    var_constructors: &mut HashMap<String, String>,
    state_setters: &mut HashSet<String>,
    loader_cache_vars: &mut HashSet<String>,
) {
    let Some(init) = decl.init.as_ref().map(Expression::without_parentheses) else {
        return;
    };
    if let Some(ctor) = resolve_new_expr_ctor_name(init, imported_symbols, namespace_imports) {
        if ctor == "WebGPURenderer" {
            *has_webgpu = true;
        }
        if let BindingPattern::BindingIdentifier(id) = &decl.id {
            if THREE_RENDER_TARGET_CTORS.contains(&ctor.as_str()) || ctor.ends_with("RenderTarget")
            {
                render_target_vars.insert(id.name.to_string());
            }
            var_constructors.insert(id.name.to_string(), ctor);
        }
        return;
    }

    let Expression::CallExpression(call) = init else {
        return;
    };
    let callee_short = extract_callee_short(&call.callee);
    if callee_short == Some("useState") || callee_short == Some("useReducer") {
        if let BindingPattern::ArrayPattern(arr) = &decl.id
            && let Some(Some(BindingPattern::BindingIdentifier(setter))) = arr.elements.get(1)
        {
            state_setters.insert(setter.name.to_string());
        }
    } else if is_cached_loader_hook_call(call, imported_symbols, namespace_imports) {
        loader_cache_vars.extend(collect_pattern_bound_names(&decl.id));
    } else if callee_short == Some("useRef")
        && let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression)
        && let Some(ctor) = resolve_new_expr_ctor_name(
            first_arg.without_parentheses(),
            imported_symbols,
            namespace_imports,
        )
        && let BindingPattern::BindingIdentifier(id) = &decl.id
    {
        var_constructors.insert(id.name.to_string(), ctor);
    }
}

fn record_texture_color_space_assignment(
    assign: &oxc_ast::ast::AssignmentExpression<'_>,
    texture_color_spaces: &mut HashMap<String, (String, usize)>,
) {
    if assign.operator != AssignmentOperator::Assign {
        return;
    }
    let AssignmentTarget::StaticMemberExpression(mem) = &assign.left else {
        return;
    };
    if mem.property.name != "colorSpace" {
        return;
    }
    let Expression::Identifier(obj_id) = mem.object.without_parentheses() else {
        return;
    };
    let rhs_name = match assign.right.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(m) => Some(m.property.name.as_str()),
        _ => None,
    };
    if let Some(cs @ ("SRGBColorSpace" | "NoColorSpace" | "LinearSRGBColorSpace")) = rhs_name {
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
        Expression::UnaryExpression(u) => eval_static_unary_f64(u),
        Expression::BinaryExpression(b) => eval_static_binary_f64(b),
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

fn eval_static_unary_f64(u: &oxc_ast::ast::UnaryExpression<'_>) -> Option<f64> {
    let v = eval_static_f64(&u.argument)?;
    match u.operator {
        UnaryOperator::UnaryNegation => Some(-v),
        UnaryOperator::UnaryPlus => Some(v),
        _ => None,
    }
}

fn eval_static_binary_f64(b: &oxc_ast::ast::BinaryExpression<'_>) -> Option<f64> {
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

pub(crate) fn eval_static_array_len(expr: &Expression<'_>) -> Option<usize> {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => Some(arr.elements.len()),
        Expression::NewExpression(new_expr) => {
            let first = new_expr.arguments.first()?.as_expression()?;
            match first.without_parentheses() {
                Expression::NumericLiteral(n) if n.value >= 0.0 && n.value.fract() == 0.0 => {
                    n.raw.as_ref().and_then(|r| r.as_str().parse::<usize>().ok())
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
    (0_u32..=14).any(|exp| val == f64::from(1_u32 << exp))
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
