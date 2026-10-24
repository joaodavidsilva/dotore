//! Single-pass motion library / CSS reduced-motion IR (`MotionFileIr`) and
//! 60fps frame-loop call-graph IR (`FrameLoopRootIr`, `FrameHelperIr`) extraction.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants; motion and frame-loop AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, AssignmentOperator, BindingPattern, CallExpression, Declaration, Expression,
        FormalParameters, ImportDeclarationSpecifier, JSXAttributeItem, JSXAttributeName,
        JSXAttributeValue, JSXElementName, JSXMemberExpression, JSXMemberExpressionObject, Program,
        Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

use crate::matchers::{
    callee_name, collect_pattern_bound_names, eval_static_str, span_to_loc_and_byte_span,
    unparenthesized,
};

use super::{
    react_ast::{find_enclosing_react_node, get_subject_name},
    types::{
        FrameCallTargetIr, FrameHelperHazard, FrameHelperHazardKind, FrameHelperIr,
        FrameLoopRootIr, FrameLoopRootKind, ModuleIr, MotionExpressionEvidence, MotionFileIr,
        PendingMotionRef, PendingMotionUsage,
    },
};

const MOTION_PACKAGES: &[&str] = &["framer-motion", "motion"];

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

// =============================================================================
// 1. Motion Library & CSS Reduced-Motion Extraction (`MotionFileIr`)
// =============================================================================

#[derive(Debug, Clone)]
enum Origin {
    Known(MotionExpressionEvidence),
    Pending {
        module_source: String,
        imported_name: String,
        member_chain: Vec<String>,
    },
    None,
}

impl Origin {
    fn member(self, member_name: &str) -> Self {
        match self {
            Self::Known(ev) => Self::Known(classify_motion_member(ev, member_name)),
            Self::Pending {
                module_source,
                imported_name,
                mut member_chain,
            } => {
                member_chain.push(member_name.to_string());
                Self::Pending {
                    module_source,
                    imported_name,
                    member_chain,
                }
            }
            Self::None => Self::None,
        }
    }
}

/// Returns `true` if `source` is a motion package specifier (`"framer-motion"`, `"motion"`, `"motion/react"`, etc.).
#[must_use]
pub(crate) fn is_motion_module_source(source: &str) -> bool {
    MOTION_PACKAGES
        .iter()
        .any(|pkg| source == *pkg || source.starts_with(&format!("{pkg}/")))
}

/// Classifies an exported binding name from a motion package (`animate`, `m`, `motion`, `Reorder`, `MotionConfig`, `useReducedMotion`).
#[must_use]
pub(crate) fn classify_motion_export(export_name: &str) -> MotionExpressionEvidence {
    MotionExpressionEvidence {
        is_animation_function: export_name == "animate",
        is_motion_component: false,
        is_motion_component_factory: matches!(export_name, "m" | "motion"),
        is_motion_component_namespace: export_name == "Reorder",
        is_motion_config: export_name == "MotionConfig",
        is_motion_namespace: false,
        is_reduced_motion_hook: export_name == "useReducedMotion",
    }
}

/// Classifies a member access (`receiver.member_name`) on a motion expression.
#[must_use]
pub(crate) fn classify_motion_member(
    receiver: MotionExpressionEvidence,
    member_name: &str,
) -> MotionExpressionEvidence {
    if receiver.is_motion_namespace {
        return classify_motion_export(member_name);
    }
    if receiver.is_motion_component_factory {
        return MotionExpressionEvidence {
            is_motion_component: true,
            ..MotionExpressionEvidence::default()
        };
    }
    if receiver.is_motion_component_namespace && member_name == "Item" {
        return MotionExpressionEvidence {
            is_motion_component: true,
            ..MotionExpressionEvidence::default()
        };
    }
    MotionExpressionEvidence::default()
}

/// Extracts [`MotionFileIr`] from a CSS or SCSS stylesheet in a single pass.
#[must_use]
pub(crate) fn extract_stylesheet_motion_ir(source: &str) -> MotionFileIr {
    MotionFileIr {
        has_motion_use: false,
        has_reduced_motion_handling: has_reduced_motion_media_query(source),
        exported_evidence: Vec::new(),
        star_reexports: Vec::new(),
        pending_refs: Vec::new(),
    }
}

/// Checks if `content` contains a non-negated `@media (... (prefers-reduced-motion: reduce) ...)`
/// block with at least one CSS declaration (ignoring CSS/SCSS comments and string literals).
#[must_use]
pub(crate) fn has_reduced_motion_media_query(content: &str) -> bool {
    let sanitized = remove_css_comments_and_strings(content);
    let lower = sanitized.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut search_from = 0;

    while let Some(rel_idx) = lower[search_from..].find("@media") {
        let media_idx = search_from + rel_idx;
        let after_media = media_idx + "@media".len();
        if after_media < bytes.len()
            && !bytes[after_media].is_ascii_whitespace()
            && bytes[after_media] != b'('
        {
            search_from = after_media;
            continue;
        }
        let Some(open_rel) = lower[after_media..].find('{') else {
            break;
        };
        let open_brace = after_media + open_rel;
        let prelude = &lower[after_media..open_brace];
        if prelude.contains('}') || prelude.contains(';') {
            search_from = after_media;
            continue;
        }
        if contains_prefers_reduced_motion_reduce(prelude)
            && !contains_word_not(prelude)
            && let Some(close_brace) = find_matching_closing_brace(&sanitized, open_brace)
        {
            let body = &sanitized[open_brace + 1..close_brace];
            if has_css_declaration(body) {
                return true;
            }
        }
        search_from = open_brace + 1;
    }
    false
}

fn contains_prefers_reduced_motion_reduce(prelude: &str) -> bool {
    let compact: String = prelude.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("(prefers-reduced-motion:reduce)")
}

fn contains_word_not(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .any(|tok| tok == "not")
}

fn has_css_declaration(body: &str) -> bool {
    for segment in body.split([';', '{', '}']) {
        let trimmed = segment.trim();
        let Some(colon_idx) = trimmed.find(':') else {
            continue;
        };
        let prop = trimmed[..colon_idx].trim();
        if !prop.is_empty()
            && prop
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_')
            && prop
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return true;
        }
    }
    false
}

fn find_matching_closing_brace(content: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (idx, b) in content.bytes().enumerate().skip(open_brace) {
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn remove_css_comments_and_strings(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut quote: Option<char> = None;
    let mut in_block_comment = false;
    let mut in_line_comment = false;

    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        if in_line_comment {
            if c == '\n' {
                out.push('\n');
                in_line_comment = false;
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_block_comment {
            if c == '*' && next == Some('/') {
                let _ = chars.next();
                out.push_str("  ");
                in_block_comment = false;
            } else if c == '\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if let Some(q) = quote {
            if c == '\\' {
                if chars.next().is_some() {
                    out.push_str("  ");
                }
                continue;
            }
            if c == q {
                quote = None;
            }
            if c == '\n' {
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let _ = chars.next();
            out.push_str("  ");
            in_block_comment = true;
            continue;
        }
        if c == '/' && next == Some('/') {
            let _ = chars.next();
            out.push_str("  ");
            in_line_comment = true;
            continue;
        }
        if c == '"' || c == '\'' {
            out.push(' ');
            quote = Some(c);
            continue;
        }
        out.push(c);
    }
    out
}

/// Extracts [`MotionFileIr`] from a JS/TS/JSX/TSX module during the single OXC pass.
#[must_use]
pub(crate) fn extract_script_motion_ir(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
) -> MotionFileIr {
    let mut motion = MotionFileIr::default();
    let mut sym_origins: HashMap<SymbolId, Origin> = HashMap::new();
    let mut const_strings: HashMap<SymbolId, String> = HashMap::new();

    for stmt in &program.body {
        if let Statement::ImportDeclaration(imp) = stmt {
            if imp.import_kind.is_type() {
                continue;
            }
            let src = imp.source.value.as_str().unwrap_or_default();
            let Some(specs) = &imp.specifiers else {
                continue;
            };
            for spec in specs {
                match spec {
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                        let Some(sym_id) = ns.local.symbol_id.get() else {
                            continue;
                        };
                        if is_motion_module_source(src) {
                            sym_origins.insert(
                                sym_id,
                                Origin::Known(MotionExpressionEvidence {
                                    is_motion_namespace: true,
                                    ..MotionExpressionEvidence::default()
                                }),
                            );
                        } else if src.starts_with('.') {
                            sym_origins.insert(
                                sym_id,
                                Origin::Pending {
                                    module_source: src.to_string(),
                                    imported_name: "*".to_string(),
                                    member_chain: Vec::new(),
                                },
                            );
                        }
                    }
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        if s.import_kind.is_type() {
                            continue;
                        }
                        let Some(sym_id) = s.local.symbol_id.get() else {
                            continue;
                        };
                        let imported_name = s.imported.name().as_str();
                        if is_motion_module_source(src) {
                            sym_origins.insert(
                                sym_id,
                                Origin::Known(classify_motion_export(imported_name)),
                            );
                        } else if src.starts_with('.') {
                            sym_origins.insert(
                                sym_id,
                                Origin::Pending {
                                    module_source: src.to_string(),
                                    imported_name: imported_name.to_string(),
                                    member_chain: Vec::new(),
                                },
                            );
                        }
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(d) => {
                        let Some(sym_id) = d.local.symbol_id.get() else {
                            continue;
                        };
                        if src.starts_with('.') {
                            sym_origins.insert(
                                sym_id,
                                Origin::Pending {
                                    module_source: src.to_string(),
                                    imported_name: "default".to_string(),
                                    member_chain: Vec::new(),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    for _ in 0..3 {
        for (_, node) in semantic.nodes().iter_enumerated() {
            let AstKind::VariableDeclaration(var_decl) = node.kind() else {
                continue;
            };
            let is_const = var_decl.kind == VariableDeclarationKind::Const;
            for declarator in &var_decl.declarations {
                let Some(init) = &declarator.init else {
                    continue;
                };
                if is_const
                    && let BindingPattern::BindingIdentifier(id) = &declarator.id
                    && let Some(sym_id) = id.symbol_id.get()
                    && let Some(str_val) = eval_static_str(semantic, init, &const_strings)
                {
                    const_strings.insert(sym_id, str_val);
                }
                let init_origin = eval_expr_origin(semantic, init, &sym_origins);
                match &declarator.id {
                    BindingPattern::BindingIdentifier(id) => {
                        if let Some(sym_id) = id.symbol_id.get()
                            && !matches!(init_origin, Origin::None)
                        {
                            sym_origins.insert(sym_id, init_origin);
                        }
                    }
                    BindingPattern::ObjectPattern(obj_pat) => {
                        for prop in &obj_pat.properties {
                            let Some(key_name) = prop.key.static_name() else {
                                continue;
                            };
                            let Some(key_str) = key_name.as_str() else {
                                continue;
                            };
                            if let BindingPattern::BindingIdentifier(id) = &prop.value
                                && let Some(sym_id) = id.symbol_id.get()
                            {
                                let member_origin = init_origin.clone().member(key_str);
                                if !matches!(member_origin, Origin::None) {
                                    sym_origins.insert(sym_id, member_origin);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ExportAllDeclaration(exp_all) => {
                if exp_all.export_kind.is_type() {
                    continue;
                }
                let src = exp_all.source.value.as_str().unwrap_or_default();
                if is_motion_module_source(src) || src.starts_with('.') {
                    motion.star_reexports.push(src.to_string());
                }
            }
            AstKind::ExportFromDeclaration(exp_from) => {
                if exp_from.export_kind.is_type() {
                    continue;
                }
                let src = exp_from.source.value.as_str().unwrap_or_default();
                for spec in &exp_from.specifiers {
                    if spec.export_kind.is_type() {
                        continue;
                    }
                    let local_name = spec.local.name().as_str();
                    let exported_name = spec.exported.name().as_str().to_string();
                    if is_motion_module_source(src) {
                        let ev = classify_motion_export(local_name);
                        if ev.has_any() {
                            motion.exported_evidence.push((exported_name, ev));
                        }
                    } else if src.starts_with('.') {
                        motion.pending_refs.push(PendingMotionRef {
                            module_source: src.to_string(),
                            imported_name: local_name.to_string(),
                            member_chain: Vec::new(),
                            usage: PendingMotionUsage::ReExport {
                                exported_as: exported_name,
                            },
                        });
                    }
                }
            }
            AstKind::ExportNamedDeclaration(exp_named) => {
                if exp_named.export_kind.is_type() {
                    continue;
                }
                for spec in &exp_named.specifiers {
                    if spec.export_kind.is_type() {
                        continue;
                    }
                    let exported_name = spec.exported.name().as_str().to_string();
                    let local_name = spec.local.name().as_str();
                    if let Some(sym_id) = semantic.scoping().get_root_binding(local_name.into())
                        && let Some(origin) = sym_origins.get(&sym_id)
                    {
                        record_export_origin(&mut motion, exported_name, origin.clone());
                    }
                }
            }
            AstKind::ExportDeclaration(exp_decl) => {
                if let Declaration::VariableDeclaration(var_decl) = &exp_decl.declaration {
                    for declarator in &var_decl.declarations {
                        if let BindingPattern::BindingIdentifier(id) = &declarator.id
                            && let Some(sym_id) = id.symbol_id.get()
                            && let Some(origin) = sym_origins.get(&sym_id)
                        {
                            record_export_origin(&mut motion, id.name.to_string(), origin.clone());
                        }
                    }
                }
            }
            AstKind::ExportDefaultDeclaration(exp_def) => {
                if let Some(expr) = exp_def.declaration.as_expression() {
                    let origin = eval_expr_origin(semantic, expr, &sym_origins);
                    record_export_origin(&mut motion, "default".to_string(), origin);
                }
            }
            _ => {}
        }
    }

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                let value_consumed = is_call_value_consumed(semantic, node_id);
                let (callee_origin, via_call_or_apply) =
                    eval_call_callee_origin(semantic, call, &sym_origins);
                match callee_origin {
                    Origin::Known(ev) => {
                        if ev.is_animation_function {
                            motion.has_motion_use = true;
                        }
                        if ev.is_reduced_motion_hook && value_consumed && !via_call_or_apply {
                            motion.has_reduced_motion_handling = true;
                        }
                    }
                    Origin::Pending {
                        module_source,
                        imported_name,
                        member_chain,
                    } => {
                        motion.pending_refs.push(PendingMotionRef {
                            module_source,
                            imported_name,
                            member_chain,
                            usage: PendingMotionUsage::Call {
                                value_consumed,
                                via_call_or_apply,
                            },
                        });
                    }
                    Origin::None => {}
                }
            }
            AstKind::JSXOpeningElement(opening) => {
                let tag_origin = eval_jsx_tag_origin(semantic, &opening.name, &sym_origins);
                let reduced_motion_prop =
                    extract_reduced_motion_prop(semantic, &opening.attributes, &const_strings);
                match tag_origin {
                    Origin::Known(ev) => {
                        if ev.is_motion_component || ev.is_motion_component_factory {
                            motion.has_motion_use = true;
                        }
                        if ev.is_motion_config
                            && matches!(reduced_motion_prop.as_deref(), Some("user" | "always"))
                        {
                            motion.has_reduced_motion_handling = true;
                        }
                    }
                    Origin::Pending {
                        module_source,
                        imported_name,
                        member_chain,
                    } => {
                        motion.pending_refs.push(PendingMotionRef {
                            module_source,
                            imported_name,
                            member_chain,
                            usage: PendingMotionUsage::JsxTag {
                                reduced_motion_prop,
                            },
                        });
                    }
                    Origin::None => {}
                }
            }
            _ => {}
        }
    }

    motion
}

fn record_export_origin(motion: &mut MotionFileIr, exported_as: String, origin: Origin) {
    match origin {
        Origin::Known(ev) => {
            if ev.has_any() {
                motion.exported_evidence.push((exported_as, ev));
            }
        }
        Origin::Pending {
            module_source,
            imported_name,
            member_chain,
        } => {
            motion.pending_refs.push(PendingMotionRef {
                module_source,
                imported_name,
                member_chain,
                usage: PendingMotionUsage::ReExport { exported_as },
            });
        }
        Origin::None => {}
    }
}

fn extract_reduced_motion_prop(
    semantic: &Semantic<'_>,
    attrs: &[JSXAttributeItem<'_>],
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    for item in attrs {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(ident) = &attr.name else {
            continue;
        };
        if ident.name != "reducedMotion" {
            continue;
        }
        let val = attr.value.as_ref()?;
        match val {
            JSXAttributeValue::StringLiteral(s) => return s.value.as_str().map(str::to_string),
            JSXAttributeValue::ExpressionContainer(c) => {
                if let Some(expr) = c.expression.as_expression() {
                    return eval_static_str(semantic, expr, const_strings);
                }
            }
            _ => {}
        }
    }
    None
}

fn eval_expr_origin(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
) -> Origin {
    match unparenthesized(expr) {
        Expression::Identifier(ident) => ident
            .reference_id
            .get()
            .and_then(|ref_id| semantic.scoping().get_reference(ref_id).symbol_id())
            .and_then(|sym_id| sym_origins.get(&sym_id).cloned())
            .unwrap_or(Origin::None),
        Expression::StaticMemberExpression(mem) => {
            let recv = eval_expr_origin(semantic, &mem.object, sym_origins);
            recv.member(mem.property.name.as_str())
        }
        Expression::ComputedMemberExpression(mem) => {
            let prop_str = match unparenthesized(&mem.expression) {
                Expression::StringLiteral(s) => s.value.as_str(),
                Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
                    .quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str())),
                _ => None,
            };
            let Some(prop_name) = prop_str else {
                return Origin::None;
            };
            let recv = eval_expr_origin(semantic, &mem.object, sym_origins);
            recv.member(prop_name)
        }
        Expression::CallExpression(call) => {
            if let Expression::Identifier(callee_id) = unparenthesized(&call.callee)
                && callee_id.name == "require"
                && callee_id
                    .reference_id
                    .get()
                    .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
                    .is_none()
                && call.arguments.len() == 1
                && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                && let Expression::StringLiteral(s) = unparenthesized(first_arg)
                && let Some(src) = s.value.as_str()
                && is_motion_module_source(src)
            {
                return Origin::Known(MotionExpressionEvidence {
                    is_motion_namespace: true,
                    ..MotionExpressionEvidence::default()
                });
            }
            if let Expression::StaticMemberExpression(mem) = unparenthesized(&call.callee)
                && mem.property.name == "bind"
            {
                let recv = eval_expr_origin(semantic, &mem.object, sym_origins);
                if let Origin::Known(ev) = &recv
                    && ev.is_animation_function
                {
                    return recv;
                }
            }
            let callee_origin = eval_expr_origin(semantic, &call.callee, sym_origins);
            match callee_origin {
                Origin::Known(ev) if ev.is_motion_component_factory => {
                    Origin::Known(MotionExpressionEvidence {
                        is_motion_component: true,
                        ..MotionExpressionEvidence::default()
                    })
                }
                other => other,
            }
        }
        _ => Origin::None,
    }
}

fn eval_call_callee_origin(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
) -> (Origin, bool) {
    let callee = unparenthesized(&call.callee);
    if let Expression::StaticMemberExpression(mem) = callee
        && matches!(mem.property.name.as_str(), "call" | "apply")
    {
        return (eval_expr_origin(semantic, &mem.object, sym_origins), true);
    }
    if let Expression::ComputedMemberExpression(mem) = callee {
        let is_call_or_apply = match unparenthesized(&mem.expression) {
            Expression::StringLiteral(s) => matches!(s.value.as_str(), Some("call" | "apply")),
            Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
                .quasis
                .first()
                .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str()))
                .is_some_and(|s| matches!(s, "call" | "apply")),
            _ => false,
        };
        if is_call_or_apply {
            return (eval_expr_origin(semantic, &mem.object, sym_origins), true);
        }
    }
    (eval_expr_origin(semantic, callee, sym_origins), false)
}

fn eval_jsx_tag_origin(
    semantic: &Semantic<'_>,
    name: &JSXElementName<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
) -> Origin {
    match name {
        JSXElementName::IdentifierReference(ident) => ident
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .and_then(|sym_id| sym_origins.get(&sym_id).cloned())
            .unwrap_or(Origin::None),
        JSXElementName::MemberExpression(mem) => eval_jsx_member_origin(semantic, mem, sym_origins),
        JSXElementName::Identifier(_)
        | JSXElementName::NamespacedName(_)
        | JSXElementName::ThisExpression(_) => Origin::None,
    }
}

fn eval_jsx_member_origin(
    semantic: &Semantic<'_>,
    mem: &JSXMemberExpression<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
) -> Origin {
    let base = match &mem.object {
        JSXMemberExpressionObject::IdentifierReference(ident) => ident
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .and_then(|sym_id| sym_origins.get(&sym_id).cloned())
            .unwrap_or(Origin::None),
        JSXMemberExpressionObject::MemberExpression(inner) => {
            eval_jsx_member_origin(semantic, inner, sym_origins)
        }
        JSXMemberExpressionObject::ThisExpression(_) => Origin::None,
    };
    base.member(mem.property.name.as_str())
}

fn is_call_value_consumed(semantic: &Semantic<'_>, call_node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSAsExpression(_)
            | AstKind::TSSatisfiesExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSTypeAssertion(_) => {}
            AstKind::ExpressionStatement(_) => return false,
            AstKind::UnaryExpression(u) if u.operator.is_void() => return false,
            _ => return true,
        }
    }
    true
}

// =============================================================================
// 2. Cross-File 60fps Frame-Loop Call-Graph Extraction (`FrameLoopRootIr` & `FrameHelperIr`)
// =============================================================================

/// Extracts 60fps [`FrameLoopRootIr`] callback registrations (`useFrame`, `requestAnimationFrame`, `setAnimationLoop`) from `semantic`.
#[must_use]
pub(crate) fn extract_frame_loop_roots<F>(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    is_use_frame_call: F,
) -> Vec<FrameLoopRootIr>
where
    F: Fn(&CallExpression<'_>) -> bool,
{
    let mut roots = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        let callee_short = callee_name(&call.callee);
        let kind = if is_use_frame_call(call) {
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
            && find_enclosing_function_span(semantic, node_id)
                == Some(resolve_callback_body_span(cb, semantic))
        {
            continue;
        }
        let cb_span = resolve_callback_body_span(cb, semantic);
        if cb_span.start == cb_span.end {
            continue;
        }

        let outgoing_calls = collect_outgoing_calls_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            cb_span,
        );
        if outgoing_calls.is_empty() {
            continue;
        }
        let (loc, span) = span_to_loc_and_byte_span(line_starts, call.span);
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));
        roots.push(FrameLoopRootIr {
            kind: root_kind,
            subject_name,
            loc,
            span,
            outgoing_calls,
        });
    }

    roots
}

/// Extracts declared [`FrameHelperIr`] functions and arrow functions with their per-frame hazards and outgoing calls.
#[must_use]
pub(crate) fn extract_frame_helpers(
    semantic: &Semantic<'_>,
    module: &ModuleIr,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    state_setters: &HashSet<String>,
) -> Vec<FrameHelperIr> {
    let mut helpers = Vec::new();

    for (_node_id, node) in semantic.nodes().iter_enumerated() {
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
        for exp in &module.exports {
            if exp.from_source.is_none()
                && (exp.name == name || exp.local_name.as_deref() == Some(name.as_str()))
            {
                exported_names.push(exp.name.clone());
            }
        }

        let hazards = collect_helper_hazards_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            state_setters,
            body_span,
            &param_names,
        );
        let outgoing_calls = collect_outgoing_calls_in_span(
            semantic,
            line_starts,
            imported_symbols,
            namespace_imports,
            body_span,
        );
        let (loc, span) = span_to_loc_and_byte_span(line_starts, decl_span);
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
        out.extend(collect_pattern_bound_names(&p.pattern));
    }
    out
}

fn collect_outgoing_calls_in_span(
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    target_span: Span,
) -> Vec<FrameCallTargetIr> {
    let mut out = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !target_span.contains_inclusive(call.span)
            || is_conditionally_executed_within(semantic, node_id, target_span)
        {
            continue;
        }
        let (call_loc, call_span) = span_to_loc_and_byte_span(line_starts, call.span);
        match call.callee.without_parentheses() {
            Expression::Identifier(id) => {
                let callee_name = id.name.to_string();
                if matches!(
                    callee_name.as_str(),
                    "useFrame" | "requestAnimationFrame" | "cancelAnimationFrame"
                ) {
                    continue;
                }
                if let Some((src, orig)) = imported_symbols.get(callee_name.as_str()) {
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
                    && let Some(src) = namespace_imports.get(ns.name.as_str())
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
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    imported_symbols: &HashMap<String, (String, String)>,
    namespace_imports: &HashMap<String, String>,
    state_setters: &HashSet<String>,
    body_span: Span,
    param_names: &HashSet<String>,
) -> Vec<FrameHelperHazard> {
    let source = semantic.source_text();
    let mut hazards = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let nspan = node.span();
        if !body_span.contains_inclusive(nspan)
            || is_conditionally_executed_within(semantic, node_id, body_span)
        {
            continue;
        }
        let (loc, span) = span_to_loc_and_byte_span(line_starts, nspan);

        match node.kind() {
            AstKind::NewExpression(new_expr) => {
                if let Some(ctor) = resolve_callee_ctor_name(
                    &new_expr.callee,
                    imported_symbols,
                    namespace_imports,
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
                let callee_short = callee_name(&call.callee);
                if callee_short == Some("clone") {
                    let recv = match call.callee.without_parentheses() {
                        Expression::StaticMemberExpression(m) => {
                            m.object.span().source_text(source).to_string()
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
                    } else if state_setters.contains(m)
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

/// Resolves the body [`Span`] of a callback expression (`ArrowFunctionExpression`, `FunctionExpression`, identifier reference, or `useCallback`).
#[must_use]
pub(crate) fn resolve_callback_body_span(cb: &Expression<'_>, semantic: &Semantic<'_>) -> Span {
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
        Expression::CallExpression(call) if callee_name(&call.callee) == Some("useCallback") => {
            if let Some(first) = call.arguments.first().and_then(Argument::as_expression) {
                resolve_callback_body_span(first, semantic)
            } else {
                call.span
            }
        }
        _ => cb.span(),
    }
}

/// Finds the body [`Span`] of the nearest enclosing `Function` or `ArrowFunctionExpression`.
#[must_use]
pub(crate) fn find_enclosing_function_span(
    semantic: &Semantic<'_>,
    node_id: NodeId,
) -> Option<Span> {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::Function(func) => return func.body.as_ref().map(|b| b.span),
            AstKind::ArrowFunctionExpression(arrow) => return Some(arrow.body.span()),
            _ => {}
        }
    }
    None
}

/// Returns `true` if `node_id` is nested inside a conditional branch (`if`, `?:`, `&&`, `||`, `??`, `switch`, `catch`) within `boundary_span`.
#[must_use]
pub(crate) fn is_conditionally_executed_within(
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

/// Resolves the constructor identifier or `THREE.<Ctor>` property name for a `new` expression callee.
#[must_use]
pub(crate) fn resolve_callee_ctor_name(
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::{
         parse_file_ir,
        types::{FrameHelperHazardKind, FrameLoopRootKind},
    };

    use super::*;

    #[test]
    fn extracts_motion_ir_from_scripts_and_stylesheets() {
        let css = "@media (prefers-reduced-motion: reduce) { .box { animation: none; } }";
        let css_ir = extract_stylesheet_motion_ir(css);
        assert!(css_ir.has_reduced_motion_handling);

        let tsx = r#"
import { motion, useReducedMotion } from "framer-motion";

export function AnimatedHero() {
    const reduced = useReducedMotion();
    return <motion.div animate={{ opacity: 1 }}>{reduced ? "static" : "animated"}</motion.div>;
}
"#;
        let file = parse_file_ir(Path::new("AnimatedHero.tsx"), tsx);
        assert!(file.motion.has_motion_use);
        assert!(file.motion.has_reduced_motion_handling);
    }

    #[test]
    fn extracts_frame_loop_roots_and_helper_hazards() {
        let tsx = r#"
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export function stepPhysics() {
    const v = new THREE.Vector3(1, 2, 3);
    return v.clone();
}

export function Rig() {
    useFrame(() => {
        stepPhysics();
    });
    return null;
}
"#;
        let file = parse_file_ir(Path::new("Rig.tsx"), tsx);
        assert_eq!(file.frame_loop_roots.len(), 1);
        assert_eq!(file.frame_loop_roots[0].kind, FrameLoopRootKind::UseFrame);
        assert_eq!(
            file.frame_loop_roots[0].outgoing_calls[0].callee_name,
            "stepPhysics"
        );

        let helper = file
            .frame_helpers
            .iter()
            .find(|h| h.name == "stepPhysics")
            .expect("stepPhysics helper");
        assert!(
            helper
                .hazards
                .iter()
                .any(|h| h.kind == FrameHelperHazardKind::NewAllocation("Vector3".to_string()))
        );
        assert!(
            helper
                .hazards
                .iter()
                .any(|h| matches!(h.kind, FrameHelperHazardKind::CloneAllocation(_)))
        );
    }
}
