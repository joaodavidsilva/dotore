//! Single-pass motion library / CSS reduced-motion IR (`MotionFileIr`) and
//! 60fps frame-loop call-graph IR (`FrameLoopRootIr`, `FrameHelperIr`) extraction.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; motion and frame-loop AST traversal matches only relevant node kinds"
)]

use std::collections::HashMap;

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Declaration, Expression, ImportDeclarationSpecifier,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName, JSXMemberExpression,
        JSXMemberExpressionObject, Program, Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::matchers::{eval_static_str, unparenthesized};

pub(crate) use super::frame_loop::{
    extract_frame_helpers, extract_frame_loop_roots, find_enclosing_function_span,
    is_conditionally_executed_within, resolve_callback_body_span, resolve_callee_ctor_name,
};

use super::types::{
    MotionExpressionEvidence, MotionFileIr, PendingMotionRef, PendingMotionUsage,
};

const MOTION_PACKAGES: &[&str] = &["framer-motion", "motion"];

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
    fn member(&self, member_name: &str) -> Self {
        match self {
            Self::Known(ev) => Self::Known(classify_motion_member(*ev, member_name)),
            Self::Pending {
                module_source,
                imported_name,
                member_chain,
            } => {
                let mut next_chain = Vec::with_capacity(member_chain.len() + 1);
                next_chain.extend_from_slice(member_chain);
                next_chain.push(member_name.to_string());
                Self::Pending {
                    module_source: module_source.clone(),
                    imported_name: imported_name.clone(),
                    member_chain: next_chain,
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
fn has_reduced_motion_media_query(content: &str) -> bool {
    let sanitized = remove_css_comments_and_strings(content);
    let lower = sanitized.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut search_from = 0;

    while let Some(rel_idx) = lower.get(search_from..).and_then(|s| s.find("@media")) {
        let media_idx = search_from + rel_idx;
        let after_media = media_idx + "@media".len();
        if after_media < bytes.len()
            && !bytes[after_media].is_ascii_whitespace()
            && bytes[after_media] != b'('
        {
            search_from = after_media;
            continue;
        }
        let Some(open_rel) = lower.get(after_media..).and_then(|s| s.find('{')) else {
            break;
        };
        let open_brace = after_media + open_rel;
        let prelude = lower.get(after_media..open_brace).unwrap_or_default();
        if prelude.contains('}') || prelude.contains(';') {
            search_from = after_media;
            continue;
        }
        if contains_prefers_reduced_motion_reduce(prelude)
            && !contains_word_not(prelude)
            && let Some(close_brace) = find_matching_closing_brace(&sanitized, open_brace)
        {
            let body = sanitized.get(open_brace + 1..close_brace).unwrap_or_default();
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

#[derive(Clone, Copy)]
enum CssScanState {
    Normal,
    LineComment,
    BlockComment,
    Quoted(char),
}

fn remove_css_comments_and_strings(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut state = CssScanState::Normal;

    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        state = match state {
            CssScanState::LineComment => step_css_line_comment(c, &mut out),
            CssScanState::BlockComment => step_css_block_comment(c, next, &mut chars, &mut out),
            CssScanState::Quoted(q) => step_css_quoted(c, q, &mut chars, &mut out),
            CssScanState::Normal => step_css_normal(c, next, &mut chars, &mut out),
        };
    }
    out
}

fn step_css_line_comment(c: char, out: &mut String) -> CssScanState {
    if c == '\n' {
        out.push('\n');
        CssScanState::Normal
    } else {
        out.push(' ');
        CssScanState::LineComment
    }
}

fn step_css_block_comment(
    c: char,
    next: Option<char>,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
) -> CssScanState {
    if c == '*' && next == Some('/') {
        let _ = chars.next();
        out.push_str("  ");
        CssScanState::Normal
    } else {
        out.push(if c == '\n' { '\n' } else { ' ' });
        CssScanState::BlockComment
    }
}

fn step_css_quoted(
    c: char,
    quote: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
) -> CssScanState {
    if c == '\\' {
        if chars.next().is_some() {
            out.push_str("  ");
        }
        return CssScanState::Quoted(quote);
    }
    out.push(if c == '\n' { '\n' } else { ' ' });
    if c == quote {
        CssScanState::Normal
    } else {
        CssScanState::Quoted(quote)
    }
}

fn step_css_normal(
    c: char,
    next: Option<char>,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
) -> CssScanState {
    if c == '/' && next == Some('*') {
        let _ = chars.next();
        out.push_str("  ");
        return CssScanState::BlockComment;
    }
    if c == '/' && next == Some('/') {
        let _ = chars.next();
        out.push_str("  ");
        return CssScanState::LineComment;
    }
    if c == '"' || c == '\'' {
        out.push(' ');
        return CssScanState::Quoted(c);
    }
    out.push(c);
    CssScanState::Normal
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

    collect_import_motion_origins(program, &mut sym_origins);
    propagate_declarator_motion_origins(semantic, &mut sym_origins, &mut const_strings);
    collect_export_motion_evidence(semantic, &sym_origins, &mut motion);
    collect_call_and_jsx_motion_usage(semantic, &sym_origins, &const_strings, &mut motion);

    motion
}

fn collect_import_motion_origins(
    program: &Program<'_>,
    sym_origins: &mut HashMap<SymbolId, Origin>,
) {
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.import_kind.is_type() {
            continue;
        }
        let src = imp.source.value.as_str().unwrap_or_default();
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            record_import_specifier_origin(src, spec, sym_origins);
        }
    }
}

fn record_import_specifier_origin(
    src: &str,
    spec: &ImportDeclarationSpecifier<'_>,
    sym_origins: &mut HashMap<SymbolId, Origin>,
) {
    let is_motion_src = is_motion_module_source(src);
    let is_relative_src = src.starts_with('.');
    match spec {
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
            let Some(sym_id) = ns.local.symbol_id.get() else {
                return;
            };
            if is_motion_src {
                sym_origins.insert(
                    sym_id,
                    Origin::Known(MotionExpressionEvidence {
                        is_motion_namespace: true,
                        ..MotionExpressionEvidence::default()
                    }),
                );
            } else if is_relative_src {
                sym_origins.insert(sym_id, pending_origin(src, "*"));
            }
        }
        ImportDeclarationSpecifier::ImportSpecifier(s) if !s.import_kind.is_type() => {
            let Some(sym_id) = s.local.symbol_id.get() else {
                return;
            };
            let imported_name = s.imported.name().as_str();
            if is_motion_src {
                sym_origins.insert(sym_id, Origin::Known(classify_motion_export(imported_name)));
            } else if is_relative_src {
                sym_origins.insert(sym_id, pending_origin(src, imported_name));
            }
        }
        ImportDeclarationSpecifier::ImportDefaultSpecifier(d) if is_relative_src => {
            if let Some(sym_id) = d.local.symbol_id.get() {
                sym_origins.insert(sym_id, pending_origin(src, "default"));
            }
        }
        _ => {}
    }
}

fn pending_origin(src: &str, imported_name: &str) -> Origin {
    Origin::Pending {
        module_source: src.to_string(),
        imported_name: imported_name.to_string(),
        member_chain: Vec::new(),
    }
}

fn propagate_declarator_motion_origins(
    semantic: &Semantic<'_>,
    sym_origins: &mut HashMap<SymbolId, Origin>,
    const_strings: &mut HashMap<SymbolId, String>,
) {
    for _ in 0..3 {
        for (_, node) in semantic.nodes().iter_enumerated() {
            let AstKind::VariableDeclaration(var_decl) = node.kind() else {
                continue;
            };
            let is_const = var_decl.kind == VariableDeclarationKind::Const;
            for declarator in &var_decl.declarations {
                propagate_single_declarator_origin(
                    semantic,
                    declarator,
                    is_const,
                    sym_origins,
                    const_strings,
                );
            }
        }
    }
}

fn propagate_single_declarator_origin(
    semantic: &Semantic<'_>,
    declarator: &oxc_ast::ast::VariableDeclarator<'_>,
    is_const: bool,
    sym_origins: &mut HashMap<SymbolId, Origin>,
    const_strings: &mut HashMap<SymbolId, String>,
) {
    let Some(init) = &declarator.init else {
        return;
    };
    if is_const
        && let BindingPattern::BindingIdentifier(id) = &declarator.id
        && let Some(sym_id) = id.symbol_id.get()
        && let Some(str_val) = eval_static_str(semantic, init, const_strings)
    {
        const_strings.insert(sym_id, str_val);
    }
    let init_origin = eval_expr_origin(semantic, init, sym_origins);
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
                let Some(key_str) = prop.key.static_name().and_then(|k| k.as_str().map(str::to_string)) else {
                    continue;
                };
                if let BindingPattern::BindingIdentifier(id) = &prop.value
                    && let Some(sym_id) = id.symbol_id.get()
                {
                    let member_origin = init_origin.member(&key_str);
                    if !matches!(member_origin, Origin::None) {
                        sym_origins.insert(sym_id, member_origin);
                    }
                }
            }
        }
        _ => {}
    }
}

fn collect_export_motion_evidence(
    semantic: &Semantic<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    motion: &mut MotionFileIr,
) {
    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ExportAllDeclaration(exp_all) if !exp_all.export_kind.is_type() => {
                let src = exp_all.source.value.as_str().unwrap_or_default();
                if is_motion_module_source(src) || src.starts_with('.') {
                    motion.star_reexports.push(src.to_string());
                }
            }
            AstKind::ExportFromDeclaration(exp_from) if !exp_from.export_kind.is_type() => {
                record_export_from_motion(exp_from, motion);
            }
            AstKind::ExportNamedDeclaration(exp_named) if !exp_named.export_kind.is_type() => {
                record_export_named_motion(semantic, exp_named, sym_origins, motion);
            }
            AstKind::ExportDeclaration(exp_decl) => {
                record_export_declaration_motion(exp_decl, sym_origins, motion);
            }
            AstKind::ExportDefaultDeclaration(exp_def) => {
                if let Some(expr) = exp_def.declaration.as_expression() {
                    let origin = eval_expr_origin(semantic, expr, sym_origins);
                    record_export_origin(motion, "default".to_string(), origin);
                }
            }
            _ => {}
        }
    }
}

fn record_export_from_motion(
    exp_from: &oxc_ast::ast::ExportFromDeclaration<'_>,
    motion: &mut MotionFileIr,
) {
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

fn record_export_named_motion(
    semantic: &Semantic<'_>,
    exp_named: &oxc_ast::ast::ExportNamedDeclaration<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    motion: &mut MotionFileIr,
) {
    for spec in &exp_named.specifiers {
        if spec.export_kind.is_type() {
            continue;
        }
        let exported_name = spec.exported.name().as_str().to_string();
        let local_name = spec.local.name().as_str();
        if let Some(sym_id) = semantic.scoping().get_root_binding(local_name.into())
            && let Some(origin) = sym_origins.get(&sym_id)
        {
            record_export_origin(motion, exported_name, origin.clone());
        }
    }
}

fn record_export_declaration_motion(
    exp_decl: &oxc_ast::ast::ExportDeclaration<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    motion: &mut MotionFileIr,
) {
    let Declaration::VariableDeclaration(var_decl) = &exp_decl.declaration else {
        return;
    };
    for declarator in &var_decl.declarations {
        if let BindingPattern::BindingIdentifier(id) = &declarator.id
            && let Some(sym_id) = id.symbol_id.get()
            && let Some(origin) = sym_origins.get(&sym_id)
        {
            record_export_origin(motion, id.name.to_string(), origin.clone());
        }
    }
}

fn collect_call_and_jsx_motion_usage(
    semantic: &Semantic<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    const_strings: &HashMap<SymbolId, String>,
    motion: &mut MotionFileIr,
) {
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                record_call_motion_usage(semantic, node_id, call, sym_origins, motion);
            }
            AstKind::JSXOpeningElement(opening) => {
                record_jsx_opening_motion_usage(semantic, opening, sym_origins, const_strings, motion);
            }
            _ => {}
        }
    }
}

fn record_call_motion_usage(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    motion: &mut MotionFileIr,
) {
    let value_consumed = is_call_value_consumed(semantic, node_id);
    let (callee_origin, via_call_or_apply) = eval_call_callee_origin(semantic, call, sym_origins);
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

fn record_jsx_opening_motion_usage(
    semantic: &Semantic<'_>,
    opening: &oxc_ast::ast::JSXOpeningElement<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
    const_strings: &HashMap<SymbolId, String>,
    motion: &mut MotionFileIr,
) {
    let tag_origin = eval_jsx_tag_origin(semantic, &opening.name, sym_origins);
    let reduced_motion_prop =
        extract_reduced_motion_prop(semantic, &opening.attributes, const_strings);
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
            let prop_name = match unparenthesized(&mem.expression) {
                Expression::StringLiteral(s) => s.value.as_str(),
                Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
                    .quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str())),
                _ => None,
            };
            let Some(prop_name) = prop_name else {
                return Origin::None;
            };
            eval_expr_origin(semantic, &mem.object, sym_origins).member(prop_name)
        }
        Expression::CallExpression(call) => eval_call_expr_origin(semantic, call, sym_origins),
        _ => Origin::None,
    }
}

fn eval_call_expr_origin(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    sym_origins: &HashMap<SymbolId, Origin>,
) -> Origin {
    if is_motion_require_call(semantic, call) {
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
    match eval_expr_origin(semantic, &call.callee, sym_origins) {
        Origin::Known(ev) if ev.is_motion_component_factory => {
            Origin::Known(MotionExpressionEvidence {
                is_motion_component: true,
                ..MotionExpressionEvidence::default()
            })
        }
        other => other,
    }
}

fn is_motion_require_call(semantic: &Semantic<'_>, call: &CallExpression<'_>) -> bool {
    let Expression::Identifier(callee_id) = unparenthesized(&call.callee) else {
        return false;
    };
    if callee_id.name != "require"
        || callee_id
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .is_some()
        || call.arguments.len() != 1
    {
        return false;
    }
    let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression()) else {
        return false;
    };
    let Expression::StringLiteral(s) = unparenthesized(first_arg) else {
        return false;
    };
    s.value.as_str().is_some_and(is_motion_module_source)
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
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

}
