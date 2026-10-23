//! Single-pass motion library and CSS `@media (prefers-reduced-motion: reduce)` extraction
//! and cross-file [`ProjectGraph`] evaluation for `require-reduced-motion` (WCAG 2.3.3).
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and motion AST traversal matches only relevant node kinds"
)]

use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path},
};

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Declaration, Expression, ImportDeclarationSpecifier,
        JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName, JSXMemberExpression,
        JSXMemberExpressionObject, Program, Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};

use crate::{
    config::{Capability, WorkspacePackage, resolve_package_for_file},
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, SourceLoc,
        types::{MotionExpressionEvidence, MotionFileIr, PendingMotionRef, PendingMotionUsage},
    },
    rules::{Diagnostic, PrescriptionTier, RuleCategory, RuleId, RuleSeverity},
};

const MOTION_PACKAGES: &[&str] = &["framer-motion", "motion"];

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

pub(crate) fn is_motion_module_source(source: &str) -> bool {
    MOTION_PACKAGES
        .iter()
        .any(|pkg| source == *pkg || source.starts_with(&format!("{pkg}/")))
}

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

    // 1. Collect imported bindings and const string literals
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

    // 2. Propagate local variable declarations (and const strings) across fixed-point passes
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
                    && let Some(str_val) = eval_static_string(semantic, init, &const_strings)
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

    // 3. Collect module exports and re-exports
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

    // 4. Inspect CallExpressions and JSXOpeningElements
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

fn unwrap_ts_expr<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    loop {
        match expr {
            Expression::ParenthesizedExpression(p) => expr = &p.expression,
            Expression::TSAsExpression(e) => expr = &e.expression,
            Expression::TSSatisfiesExpression(e) => expr = &e.expression,
            Expression::TSNonNullExpression(e) => expr = &e.expression,
            Expression::TSTypeAssertion(e) => expr = &e.expression,
            Expression::TSInstantiationExpression(e) => expr = &e.expression,
            _ => return expr,
        }
    }
}

fn eval_static_string(
    semantic: &Semantic<'_>,
    expr: &Expression<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<String> {
    match unwrap_ts_expr(expr) {
        Expression::StringLiteral(s) => s.value.as_str().map(str::to_string),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => tpl
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref().and_then(|c| c.as_str()))
            .map(str::to_string),
        Expression::Identifier(id) => id
            .reference_id
            .get()
            .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
            .and_then(|sym_id| const_strings.get(&sym_id).cloned()),
        _ => None,
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
                    return eval_static_string(semantic, expr, const_strings);
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
    match unwrap_ts_expr(expr) {
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
            let prop_str = match unwrap_ts_expr(&mem.expression) {
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
            // 1. Unshadowed global `require("framer-motion")`
            if let Expression::Identifier(callee_id) = unwrap_ts_expr(&call.callee)
                && callee_id.name == "require"
                && callee_id
                    .reference_id
                    .get()
                    .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
                    .is_none()
                && call.arguments.len() == 1
                && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                && let Expression::StringLiteral(s) = unwrap_ts_expr(first_arg)
                && let Some(src) = s.value.as_str()
                && is_motion_module_source(src)
            {
                return Origin::Known(MotionExpressionEvidence {
                    is_motion_namespace: true,
                    ..MotionExpressionEvidence::default()
                });
            }
            // 2. `animate.bind(...)`
            if let Expression::StaticMemberExpression(mem) = unwrap_ts_expr(&call.callee)
                && mem.property.name == "bind"
            {
                let recv = eval_expr_origin(semantic, &mem.object, sym_origins);
                if let Origin::Known(ev) = &recv
                    && ev.is_animation_function
                {
                    return recv;
                }
            }
            // 3. `motion(Component)` factory call
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
    let callee = unwrap_ts_expr(&call.callee);
    if let Expression::StaticMemberExpression(mem) = callee
        && matches!(mem.property.name.as_str(), "call" | "apply")
    {
        return (eval_expr_origin(semantic, &mem.object, sym_origins), true);
    }
    if let Expression::ComputedMemberExpression(mem) = callee {
        let is_call_or_apply = match unwrap_ts_expr(&mem.expression) {
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
    let mut current = call_node_id;
    for anc_id in semantic.nodes().ancestor_ids(call_node_id) {
        match semantic.nodes().kind(anc_id) {
            AstKind::ParenthesizedExpression(_)
            | AstKind::TSAsExpression(_)
            | AstKind::TSSatisfiesExpression(_)
            | AstKind::TSNonNullExpression(_)
            | AstKind::TSTypeAssertion(_) => {
                current = anc_id;
            }
            AstKind::ExpressionStatement(_) => return false,
            AstKind::UnaryExpression(u) if u.operator.is_void() => return false,
            _ => {
                let _ = current;
                return true;
            }
        }
    }
    true
}

/// Evaluates project-wide `require-reduced-motion` across each [`WorkspacePackage`] in `graph`.
pub fn evaluate_project_reduced_motion(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if let Some(explicit) = enabled_rules
        && !explicit.contains(&RuleId::RequireReducedMotion)
    {
        return;
    }

    for pkg in packages {
        if !pkg.capability_gate.has(Capability::Motion) {
            continue;
        }
        let Some(effective_sev) = resolve_package_reduced_motion_severity(pkg, enabled_rules)
        else {
            continue;
        };

        let pkg_files: Vec<&FileIr> = graph
            .files
            .iter()
            .filter(|f| {
                resolve_package_for_file(&f.path, packages)
                    .is_some_and(|resolved| resolved.root_dir == pkg.root_dir)
            })
            .collect();

        if pkg_files.is_empty() {
            continue;
        }

        let (has_motion_use, has_reduced_motion_handling) =
            resolve_package_motion_evidence(&pkg_files);

        if has_motion_use && !has_reduced_motion_handling {
            let pkg_json_path =
                if pkg.root_dir == Path::new(".") || pkg.root_dir.as_os_str().is_empty() {
                    std::path::PathBuf::from("package.json")
                } else {
                    pkg.root_dir.join("package.json")
                };
            let meta = RuleId::RequireReducedMotion.metadata();
            out.push(Diagnostic {
                file: pkg_json_path,
                subject_name: None,
                rule: RuleId::RequireReducedMotion,
                category: RuleCategory::Accessibility,
                severity: effective_sev,
                message_id: "requireReducedMotion",
                tier: PrescriptionTier::Surgical,
                target_name: "prefers-reduced-motion".to_string(),
                message: "Project uses a motion library but has no prefers-reduced-motion handling — required for accessibility (WCAG 2.3.3)".to_string(),
                docs_url: meta.docs_url,
                loc: SourceLoc { line: 1, column: 1 },
                span: ByteSpan { start: 0, end: 0 },
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix: None,
            });
        }
    }
}

fn resolve_package_reduced_motion_severity(
    pkg: &WorkspacePackage,
    enabled_rules: Option<&[RuleId]>,
) -> Option<RuleSeverity> {
    let rule = RuleId::RequireReducedMotion;
    let meta = rule.metadata();
    let has_explicit_cli = enabled_rules.is_some_and(|list| list.contains(&rule));
    if !has_explicit_cli && !pkg.capability_gate.allows_rule(meta) {
        return None;
    }
    if has_explicit_cli {
        Some(
            pkg.config
                .effective_severity(rule)
                .unwrap_or(meta.default_severity),
        )
    } else {
        pkg.config.effective_severity(rule)
    }
}

fn resolve_package_motion_evidence(files: &[&FileIr]) -> (bool, bool) {
    let mut has_motion_use = files.iter().any(|f| f.motion.has_motion_use);
    let mut has_reduced_motion_handling =
        files.iter().any(|f| f.motion.has_reduced_motion_handling);

    for file in files {
        for pending in &file.motion.pending_refs {
            match &pending.usage {
                PendingMotionUsage::ReExport { .. } => {}
                PendingMotionUsage::JsxTag {
                    reduced_motion_prop,
                } => {
                    let ev = resolve_pending_ref_evidence(file, pending, files);
                    if ev.is_motion_component || ev.is_motion_component_factory {
                        has_motion_use = true;
                    }
                    if ev.is_motion_config
                        && matches!(reduced_motion_prop.as_deref(), Some("user" | "always"))
                    {
                        has_reduced_motion_handling = true;
                    }
                }
                PendingMotionUsage::Call {
                    value_consumed,
                    via_call_or_apply,
                } => {
                    let ev = resolve_pending_ref_evidence(file, pending, files);
                    if ev.is_animation_function {
                        has_motion_use = true;
                    }
                    if ev.is_reduced_motion_hook && *value_consumed && !*via_call_or_apply {
                        has_reduced_motion_handling = true;
                    }
                }
            }
        }
    }

    (has_motion_use, has_reduced_motion_handling)
}

fn resolve_pending_ref_evidence(
    from_file: &FileIr,
    pending: &PendingMotionRef,
    files: &[&FileIr],
) -> MotionExpressionEvidence {
    let Some(target_file) = find_local_module_file(&from_file.path, &pending.module_source, files)
    else {
        return MotionExpressionEvidence::default();
    };
    let mut visited = HashSet::new();
    let mut ev = if pending.imported_name == "*" {
        MotionExpressionEvidence {
            is_motion_namespace: true,
            ..MotionExpressionEvidence::default()
        }
    } else {
        resolve_module_export_evidence(target_file, &pending.imported_name, files, &mut visited)
    };
    for member in &pending.member_chain {
        if ev.is_motion_namespace {
            ev = resolve_module_export_evidence(target_file, member, files, &mut visited);
        } else {
            ev = classify_motion_member(ev, member);
        }
    }
    ev
}

fn resolve_module_export_evidence<'a>(
    file: &'a FileIr,
    export_name: &str,
    files: &[&'a FileIr],
    visited: &mut HashSet<(&'a Path, String)>,
) -> MotionExpressionEvidence {
    let key = (file.path.as_path(), export_name.to_string());
    if !visited.insert(key) {
        return MotionExpressionEvidence::default();
    }

    let mut combined = MotionExpressionEvidence::default();

    // 1. Direct exported evidence in `file`
    for (name, ev) in &file.motion.exported_evidence {
        if name == export_name {
            combined = combined.merge(*ev);
        }
    }
    if combined.has_any() {
        return combined;
    }

    // 2. Named re-exports in `file.motion.pending_refs`
    for pending in &file.motion.pending_refs {
        let PendingMotionUsage::ReExport { exported_as } = &pending.usage else {
            continue;
        };
        if exported_as != export_name {
            continue;
        }
        if let Some(target_file) = find_local_module_file(&file.path, &pending.module_source, files)
        {
            let mut ev = if pending.imported_name == "*" {
                MotionExpressionEvidence {
                    is_motion_namespace: true,
                    ..MotionExpressionEvidence::default()
                }
            } else {
                resolve_module_export_evidence(target_file, &pending.imported_name, files, visited)
            };
            for member in &pending.member_chain {
                ev = classify_motion_member(ev, member);
            }
            if ev.has_any() {
                return ev;
            }
        }
    }

    // 3. `export * from "..."` star re-exports
    for star_src in &file.motion.star_reexports {
        if is_motion_module_source(star_src) {
            let ev = classify_motion_export(export_name);
            if ev.has_any() {
                return ev;
            }
        } else if star_src.starts_with('.')
            && let Some(target_file) = find_local_module_file(&file.path, star_src, files)
        {
            let ev = resolve_module_export_evidence(target_file, export_name, files, visited);
            if ev.has_any() {
                return ev;
            }
        }
    }

    combined
}

fn find_local_module_file<'a>(
    importing_path: &Path,
    module_source: &str,
    files: &[&'a FileIr],
) -> Option<&'a FileIr> {
    if !module_source.starts_with('.') {
        return None;
    }
    let parent = importing_path.parent().unwrap_or_else(|| Path::new(""));
    let joined = parent.join(module_source);
    let joined_norm = normalize_path_str(&joined);
    let target_stem = strip_known_ext(&joined_norm);
    for candidate in files {
        let cand_norm = normalize_path_str(&candidate.path);
        let cand_stem = strip_known_ext(&cand_norm);
        if cand_stem == target_stem
            || cand_stem
                .strip_suffix("/index")
                .is_some_and(|idx_stem| idx_stem == target_stem)
        {
            return Some(*candidate);
        }
    }
    None
}

fn normalize_path_str(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut has_root = false;
    for comp in path.components() {
        match comp {
            Component::RootDir => has_root = true,
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|last| last != "..") {
                    parts.pop();
                } else if !has_root {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(s) => {
                if let Some(str_val) = s.to_str() {
                    parts.push(str_val.to_string());
                }
            }
        }
    }
    let joined = parts.join("/");
    if has_root {
        format!("/{joined}")
    } else {
        joined
    }
}

fn strip_known_ext(path: &str) -> &str {
    for ext in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".mts", ".cjs", ".cts"] {
        if let Some(s) = path.strip_suffix(ext) {
            return s;
        }
    }
    path
}
