//! Single-pass module import, export, barrel, directive, route, and call fact extraction (`ModuleIr`).
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; module extraction matches only relevant AST node kinds"
)]

use std::collections::HashSet;

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, CallExpression, Declaration, ExportDefaultDeclarationKind, Expression,
        ImportDeclaration, ImportDeclarationSpecifier, ObjectProperty, Program,
    },
};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::GetSpan;

use crate::matchers::collect_pattern_bound_names;

use super::{
    react_ast::{get_subject_name, is_component_name},
    types::{
        ByteSpan, ExportDeclIr, ImportBindingIr, ImportDeclIr, JsxElementIr, ModuleIr, SourceLoc,
        loc_from_line_starts,
    },
};

#[derive(Default)]
struct ModuleIrCollector {
    module: ModuleIr,
    namespace_locals: HashSet<String>,
    local_refs_set: HashSet<String>,
    raw_member_accesses: Vec<(String, String)>,
    raw_whole_uses: HashSet<String>,
}

/// Extracts [`ModuleIr`] (imports, exports, directives, dynamic imports, namespace uses, and barrel status) from `program`.
pub(super) fn extract_module_ir(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    jsx_elements: &[JsxElementIr],
    line_starts: &[u32],
) -> ModuleIr {
    let mut collector = ModuleIrCollector::default();

    for dir in &program.directives {
        record_directive(dir.directive.as_str(), &mut collector.module);
    }

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        collector.visit_node(node_id, node.kind(), semantic, jsx_elements, line_starts);
    }

    collector.finish(program, semantic)
}

fn record_directive(directive: &str, module: &mut ModuleIr) {
    match directive {
        "use client" => module.has_use_client = true,
        "use server" => module.has_use_server = true,
        _ => {}
    }
}

impl ModuleIrCollector {
    fn visit_node(
        &mut self,
        node_id: oxc_semantic::NodeId,
        kind: AstKind<'_>,
        semantic: &Semantic<'_>,
        jsx_elements: &[JsxElementIr],
        line_starts: &[u32],
    ) {
        if self.visit_import_or_export_node(kind, semantic, jsx_elements, line_starts) {
            return;
        }
        self.visit_reference_or_call_node(node_id, kind, semantic);
    }

    fn visit_import_or_export_node(
        &mut self,
        kind: AstKind<'_>,
        semantic: &Semantic<'_>,
        jsx_elements: &[JsxElementIr],
        line_starts: &[u32],
    ) -> bool {
        match kind {
            AstKind::Directive(dir) => record_directive(dir.directive.as_str(), &mut self.module),
            AstKind::ImportDeclaration(imp) => {
                self.record_import_declaration(imp, semantic, jsx_elements, line_starts);
            }
            AstKind::ImportExpression(dyn_imp) => {
                if let Some(val) = extract_static_string_expr(dyn_imp.source.without_parentheses())
                {
                    self.module.dynamic_imports.push(val);
                }
            }
            AstKind::TSImportType(ts_imp) => {
                let raw = ts_imp.span().source_text(semantic.source_text());
                if let Some(pair) = parse_ts_import_type_text(raw) {
                    self.module.type_import_sources.push(pair);
                }
            }
            AstKind::ExportDeclaration(exp) => {
                let loc = loc_from_line_starts(line_starts, exp.span.start);
                let span = ByteSpan {
                    start: exp.span.start,
                    end: exp.span.end,
                };
                collect_declaration_exports(
                    &exp.declaration,
                    exp.export_kind().is_type(),
                    span,
                    loc,
                    &mut self.module.exports,
                );
            }
            AstKind::ExportNamedDeclaration(exp) => {
                record_export_named_declaration(exp, line_starts, &mut self.module.exports);
            }
            AstKind::ExportFromDeclaration(exp) => {
                record_export_from_declaration(exp, line_starts, &mut self.module.exports);
            }
            AstKind::ExportDefaultDeclaration(exp) => {
                record_export_default_declaration(exp, line_starts, &mut self.module.exports);
            }
            AstKind::ExportAllDeclaration(exp) => {
                record_export_all_declaration(exp, line_starts, &mut self.module.exports);
            }
            _ => return false,
        }
        true
    }

    fn record_import_declaration(
        &mut self,
        imp: &ImportDeclaration<'_>,
        semantic: &Semantic<'_>,
        jsx_elements: &[JsxElementIr],
        line_starts: &[u32],
    ) {
        let is_type_only = imp.import_kind.is_type();
        let (specifiers, bindings) =
            extract_import_bindings(imp, is_type_only, semantic, jsx_elements);
        for b in &bindings {
            if b.is_namespace {
                self.namespace_locals.insert(b.local_name.clone());
            }
        }
        self.module.imports.push(ImportDeclIr {
            source: imp.source.value.as_str().unwrap_or_default().to_string(),
            specifiers,
            bindings,
            is_type_only,
            span: ByteSpan {
                start: imp.span.start,
                end: imp.span.end,
            },
            loc: loc_from_line_starts(line_starts, imp.span.start),
        });
    }

    fn visit_reference_or_call_node(
        &mut self,
        node_id: oxc_semantic::NodeId,
        kind: AstKind<'_>,
        semantic: &Semantic<'_>,
    ) {
        match kind {
            AstKind::CallExpression(call) => {
                collect_module_call_facts(call, &mut self.module, &mut self.raw_whole_uses);
            }
            AstKind::ObjectProperty(prop) => {
                collect_angular_object_property_references(prop, &mut self.module);
            }
            AstKind::IdentifierReference(ident) => {
                if !matches!(
                    semantic.nodes().parent_kind(node_id),
                    AstKind::ExportSpecifier(_) | AstKind::ExportDefaultDeclaration(_)
                ) {
                    self.local_refs_set.insert(ident.name.to_string());
                }
            }
            AstKind::TSTypeReference(type_ref) => {
                self.record_ts_type_reference(type_ref, semantic.source_text());
            }
            AstKind::TSInterfaceHeritage(heritage) => {
                let raw = heritage
                    .type_name
                    .span()
                    .source_text(semantic.source_text())
                    .trim();
                let root = raw.split(['.', '<']).next().unwrap_or(raw).trim();
                if !root.is_empty() {
                    self.local_refs_set.insert(root.to_string());
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                    self.raw_member_accesses
                        .push((obj.name.to_string(), mem.property.name.to_string()));
                }
            }
            AstKind::ComputedMemberExpression(comp) => {
                self.record_computed_member_access(comp);
            }
            AstKind::JSXMemberExpression(jsx_mem) => {
                self.record_jsx_member_expression(jsx_mem, semantic.source_text());
            }
            AstKind::VariableDeclarator(decl) => {
                collect_declarator_namespace_uses(
                    decl,
                    &mut self.raw_member_accesses,
                    &mut self.raw_whole_uses,
                );
            }
            AstKind::SpreadElement(spread) => {
                if let Expression::Identifier(id) = spread.argument.without_parentheses() {
                    self.raw_whole_uses.insert(id.name.to_string());
                }
            }
            _ => {}
        }
    }

    fn record_ts_type_reference(
        &mut self,
        type_ref: &oxc_ast::ast::TSTypeReference<'_>,
        source_text: &str,
    ) {
        let raw = type_ref.type_name.span().source_text(source_text).trim();
        let mut parts = raw.split('.');
        if let Some(first) = parts.next().filter(|s| !s.is_empty()) {
            self.local_refs_set.insert(first.to_string());
            if let Some(second) = parts.next().filter(|s| !s.is_empty()) {
                self.raw_member_accesses
                    .push((first.to_string(), second.to_string()));
            }
        }
    }

    fn record_computed_member_access(
        &mut self,
        comp: &oxc_ast::ast::ComputedMemberExpression<'_>,
    ) {
        let Expression::Identifier(obj) = comp.object.without_parentheses() else {
            return;
        };
        if let Some(prop_name) = extract_static_string_expr(comp.expression.without_parentheses()) {
            self.raw_member_accesses
                .push((obj.name.to_string(), prop_name));
        } else {
            self.raw_whole_uses.insert(obj.name.to_string());
        }
    }

    fn record_jsx_member_expression(
        &mut self,
        jsx_mem: &oxc_ast::ast::JSXMemberExpression<'_>,
        source_text: &str,
    ) {
        let full = jsx_mem.span().source_text(source_text).trim();
        let mut parts = full.split('.');
        if let (Some(obj), Some(prop)) = (parts.next(), parts.next()) {
            self.local_refs_set.insert(obj.to_string());
            self.raw_member_accesses
                .push((obj.to_string(), prop.to_string()));
        }
    }

    fn finish(mut self, program: &Program<'_>, semantic: &Semantic<'_>) -> ModuleIr {
        let mut local_references: Vec<String> = self.local_refs_set.into_iter().collect();
        local_references.sort();
        self.module.local_references = local_references;

        if !self.namespace_locals.is_empty() {
            for (obj, member) in self.raw_member_accesses {
                if self.namespace_locals.contains(&obj)
                    && !self
                        .module
                        .namespace_member_accesses
                        .iter()
                        .any(|(o, m)| o == &obj && m == &member)
                {
                    self.module.namespace_member_accesses.push((obj, member));
                }
            }
            let mut whole_uses: Vec<String> = self
                .raw_whole_uses
                .into_iter()
                .filter(|name| self.namespace_locals.contains(name))
                .collect();
            whole_uses.sort();
            self.module.whole_namespace_uses = whole_uses;
        }
        self.module.is_aggregation_barrel = is_aggregation_barrel_program(program, &self.module);
        self.module.component_children_targets = extract_component_children_targets(semantic);
        self.module
    }
}

fn record_export_named_declaration(
    exp: &oxc_ast::ast::ExportNamedDeclaration<'_>,
    line_starts: &[u32],
    exports: &mut Vec<ExportDeclIr>,
) {
    let is_type_only = exp.export_kind.is_type();
    let loc = loc_from_line_starts(line_starts, exp.span.start);
    let span = ByteSpan {
        start: exp.span.start,
        end: exp.span.end,
    };
    for spec in &exp.specifiers {
        let name = spec.exported.name().as_str().to_string();
        let local_name = Some(spec.local.name().as_str().to_string());
        let (spec_span, spec_loc) = if spec.span.start > 0 {
            (
                ByteSpan {
                    start: spec.span.start,
                    end: spec.span.end,
                },
                loc_from_line_starts(line_starts, spec.span.start),
            )
        } else {
            (span, loc)
        };
        exports.push(ExportDeclIr {
            is_component: is_component_name(&name),
            name,
            local_name,
            from_source: None,
            is_namespace_re_export: false,
            is_type_only: is_type_only || spec.export_kind.is_type(),
            span: spec_span,
            loc: spec_loc,
        });
    }
}

fn record_export_from_declaration(
    exp: &oxc_ast::ast::ExportFromDeclaration<'_>,
    line_starts: &[u32],
    exports: &mut Vec<ExportDeclIr>,
) {
    let from_source = exp.source.value.as_str().map(str::to_string);
    let is_type_only = exp.export_kind.is_type();
    let loc = loc_from_line_starts(line_starts, exp.span.start);
    let span = ByteSpan {
        start: exp.span.start,
        end: exp.span.end,
    };
    for spec in &exp.specifiers {
        let name = spec.exported.name().as_str().to_string();
        let local_name = Some(spec.local.name().as_str().to_string());
        exports.push(ExportDeclIr {
            is_component: is_component_name(&name),
            name,
            local_name,
            from_source: from_source.clone(),
            is_namespace_re_export: false,
            is_type_only: is_type_only || spec.export_kind.is_type(),
            span,
            loc,
        });
    }
}

fn record_export_default_declaration(
    exp: &oxc_ast::ast::ExportDefaultDeclaration<'_>,
    line_starts: &[u32],
    exports: &mut Vec<ExportDeclIr>,
) {
    let (is_comp, local_name) = match &exp.declaration {
        ExportDefaultDeclarationKind::FunctionDeclaration(f) => (
            f.id.as_ref().is_none_or(|id| is_component_name(&id.name)),
            f.id.as_ref().map(|id| id.name.to_string()),
        ),
        ExportDefaultDeclarationKind::ClassDeclaration(c) => {
            (true, c.id.as_ref().map(|id| id.name.to_string()))
        }
        ExportDefaultDeclarationKind::Identifier(id) => {
            (is_component_name(&id.name), Some(id.name.to_string()))
        }
        _ => (true, None),
    };
    exports.push(ExportDeclIr {
        name: "default".to_string(),
        local_name,
        from_source: None,
        is_namespace_re_export: false,
        is_type_only: false,
        is_component: is_comp,
        span: ByteSpan {
            start: exp.span.start,
            end: exp.span.end,
        },
        loc: loc_from_line_starts(line_starts, exp.span.start),
    });
}

fn record_export_all_declaration(
    exp: &oxc_ast::ast::ExportAllDeclaration<'_>,
    line_starts: &[u32],
    exports: &mut Vec<ExportDeclIr>,
) {
    let exported_name = exp
        .exported
        .as_ref()
        .map_or_else(|| "*".to_string(), |e| e.name().as_str().to_string());
    exports.push(ExportDeclIr {
        name: exported_name,
        local_name: Some("*".to_string()),
        from_source: exp.source.value.as_str().map(str::to_string),
        is_namespace_re_export: true,
        is_type_only: exp.export_kind.is_type(),
        is_component: false,
        span: ByteSpan {
            start: exp.span.start,
            end: exp.span.end,
        },
        loc: loc_from_line_starts(line_starts, exp.span.start),
    });
}

fn extract_component_children_targets(semantic: &Semantic<'_>) -> Vec<(String, String)> {
    let mut targets = Vec::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let Some(comp_name) = get_subject_name(semantic, node_id) else {
            continue;
        };
        if !is_component_name(&comp_name) {
            continue;
        }
        let comp_span = node.span();
        let comp_src = comp_span.source_text(semantic.source_text());
        if !comp_src.contains("children") && !comp_src.contains("...props") {
            continue;
        }
        for (_, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::JSXElement(jsx_el) = inner_node.kind() else {
                continue;
            };
            if !comp_span.contains_inclusive(jsx_el.span) {
                continue;
            }
            let forwards_in_children = jsx_el.children.iter().any(|ch| {
                let ch_text = ch.span().source_text(semantic.source_text()).trim();
                ch_text == "{children}"
                    || ch_text == "{props.children}"
                    || ch_text == "{content}"
                    || ch_text == "<>{children}</>"
            });
            let forwards_in_attrs = jsx_el.opening_element.attributes.iter().any(|a| {
                let a_text = a.span().source_text(semantic.source_text()).trim();
                a_text == "{...props}" || a_text == "children={children}"
            });
            if forwards_in_children || forwards_in_attrs {
                let target_name = jsx_el
                    .opening_element
                    .name
                    .span()
                    .source_text(semantic.source_text())
                    .trim()
                    .to_string();
                if !target_name.is_empty()
                    && target_name != "Fragment"
                    && target_name != "React.Fragment"
                {
                    targets.push((comp_name.clone(), target_name));
                    break;
                }
            }
        }
    }
    targets
}

fn collect_declarator_namespace_uses(
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    raw_member_accesses: &mut Vec<(String, String)>,
    raw_whole_uses: &mut HashSet<String>,
) {
    let Some(Expression::Identifier(init_id)) =
        decl.init.as_ref().map(Expression::without_parentheses)
    else {
        return;
    };
    let BindingPattern::ObjectPattern(obj_pat) = &decl.id else {
        return;
    };
    let obj_name = init_id.name.to_string();
    if obj_pat.rest.is_some() {
        raw_whole_uses.insert(obj_name.clone());
    }
    for prop in &obj_pat.properties {
        if prop.computed {
            raw_whole_uses.insert(obj_name.clone());
        } else if let Some(key_name) = prop
            .key
            .static_name()
            .and_then(|n| n.as_str().map(str::to_string))
        {
            raw_member_accesses.push((obj_name.clone(), key_name));
        }
    }
}

fn extract_import_bindings(
    imp: &ImportDeclaration<'_>,
    decl_type_only: bool,
    semantic: &Semantic<'_>,
    jsx_elements: &[JsxElementIr],
) -> (Vec<String>, Vec<ImportBindingIr>) {
    let Some(specs) = &imp.specifiers else {
        return (Vec::new(), Vec::new());
    };
    let mut names = Vec::with_capacity(specs.len());
    let mut bindings = Vec::with_capacity(specs.len());
    for spec in specs {
        match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s) => {
                let local = s.local.name.to_string();
                let imported = s.imported.name().as_str().to_string();
                let is_type_only = decl_type_only || s.import_kind.is_type();
                let has_runtime_value_reference = !is_type_only
                    && has_non_reexport_runtime_reference(
                        semantic,
                        s.local.symbol_id.get(),
                        &local,
                        jsx_elements,
                    );
                bindings.push(ImportBindingIr {
                    is_default: imported == "default",
                    imported_name: imported,
                    local_name: local.clone(),
                    is_namespace: false,
                    is_type_only,
                    has_runtime_value_reference,
                });
                names.push(local);
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                let local = s.local.name.to_string();
                let has_runtime_value_reference = !decl_type_only
                    && has_non_reexport_runtime_reference(
                        semantic,
                        s.local.symbol_id.get(),
                        &local,
                        jsx_elements,
                    );
                bindings.push(ImportBindingIr {
                    imported_name: "default".to_string(),
                    local_name: local.clone(),
                    is_default: true,
                    is_namespace: false,
                    is_type_only: decl_type_only,
                    has_runtime_value_reference,
                });
                names.push(local);
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                let local = s.local.name.to_string();
                let has_runtime_value_reference = !decl_type_only
                    && has_non_reexport_runtime_reference(
                        semantic,
                        s.local.symbol_id.get(),
                        &local,
                        jsx_elements,
                    );
                bindings.push(ImportBindingIr {
                    imported_name: "*".to_string(),
                    local_name: local.clone(),
                    is_default: false,
                    is_namespace: true,
                    is_type_only: decl_type_only,
                    has_runtime_value_reference,
                });
                names.push(local);
            }
        }
    }
    (names, bindings)
}

fn has_non_reexport_runtime_reference(
    semantic: &Semantic<'_>,
    sym_id: Option<SymbolId>,
    local_name: &str,
    jsx_elements: &[JsxElementIr],
) -> bool {
    if let Some(sym) = sym_id {
        for reference in semantic.scoping().get_resolved_references(sym) {
            if !reference.is_value() {
                continue;
            }
            let parent_kind = semantic.nodes().parent_kind(reference.node_id());
            if matches!(parent_kind, AstKind::ExportSpecifier(_)) {
                continue;
            }
            let in_type = semantic
                .nodes()
                .ancestor_ids(reference.node_id())
                .any(|anc_id| {
                    matches!(
                        semantic.nodes().kind(anc_id),
                        AstKind::TSTypeAnnotation(_)
                            | AstKind::TSTypeReference(_)
                            | AstKind::TSTypeQuery(_)
                            | AstKind::TSInterfaceDeclaration(_)
                            | AstKind::TSTypeAliasDeclaration(_)
                    )
                });
            if !in_type {
                return true;
            }
        }
    }
    jsx_elements
        .iter()
        .any(|el| el.root_identifier == local_name)
}

fn is_aggregation_barrel_program(program: &Program<'_>, module: &ModuleIr) -> bool {
    let mut has_export_stmt = false;
    for stmt in &program.body {
        match stmt {
            oxc_ast::ast::Statement::ImportDeclaration(_) => {}
            oxc_ast::ast::Statement::ExportAllDeclaration(_)
            | oxc_ast::ast::Statement::ExportFromDeclaration(_)
            | oxc_ast::ast::Statement::ExportNamedDeclaration(_) => {
                has_export_stmt = true;
            }
            _ => return false,
        }
    }
    if !has_export_stmt {
        return false;
    }
    for imp in &module.imports {
        for b in &imp.bindings {
            if b.is_type_only {
                continue;
            }
            let exported = module.exports.iter().any(|e| {
                e.local_name.as_deref() == Some(b.local_name.as_str())
                    || (e.local_name.is_none() && e.name == b.local_name)
            });
            if !exported {
                return false;
            }
        }
    }
    true
}

fn extract_static_string_expr(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => s.value.as_str().map(str::to_string),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() && tpl.quasis.len() == 1 => {
            tpl.quasis[0]
                .value
                .cooked
                .as_ref()
                .and_then(|c| c.as_str().map(str::to_string))
        }
        _ => None,
    }
}

fn collect_module_call_facts(
    call: &CallExpression<'_>,
    module: &mut ModuleIr,
    raw_whole_uses: &mut HashSet<String>,
) {
    let callee = call.callee.without_parentheses();
    match callee {
        Expression::Identifier(id) => {
            if id.name == "require" {
                if let Some(first_expr) = call.arguments.first().and_then(|a| a.as_expression())
                    && let Some(spec) = extract_static_string_expr(first_expr.without_parentheses())
                {
                    module.require_sources.push(spec);
                }
            } else if matches!(id.name.as_str(), "route" | "index" | "layout") {
                let arg_idx = usize::from(id.name == "route");
                if let Some(arg_expr) = call.arguments.get(arg_idx).and_then(|a| a.as_expression())
                    && let Some(route_path) =
                        extract_static_string_expr(arg_expr.without_parentheses())
                {
                    module.route_module_entries.push(route_path);
                }
            }
        }
        Expression::StaticMemberExpression(mem) => {
            let prop = mem.property.name.as_str();
            if prop == "resolve" {
                let is_req_or_meta =
                    matches!(
                        mem.object.without_parentheses(),
                        Expression::Identifier(obj) if obj.name == "require"
                    ) || matches!(mem.object.without_parentheses(), Expression::ImportMeta(_));
                if is_req_or_meta
                    && let Some(first_expr) = call.arguments.first().and_then(|a| a.as_expression())
                    && let Some(spec) = extract_static_string_expr(first_expr.without_parentheses())
                {
                    module.require_sources.push(spec);
                }
            } else if matches!(
                mem.object.without_parentheses(),
                Expression::Identifier(obj) if obj.name == "Object"
            ) && matches!(
                prop,
                "keys"
                    | "values"
                    | "entries"
                    | "assign"
                    | "freeze"
                    | "getOwnPropertyNames"
                    | "getOwnPropertyDescriptors"
            ) && let Some(first_expr) =
                call.arguments.first().and_then(|a| a.as_expression())
                && let Expression::Identifier(arg_id) = first_expr.without_parentheses()
            {
                raw_whole_uses.insert(arg_id.name.to_string());
            }
        }
        _ => {}
    }
}

fn collect_angular_object_property_references(prop: &ObjectProperty<'_>, module: &mut ModuleIr) {
    let Some(static_name) = prop.key.static_name() else {
        return;
    };
    let Some(key_name) = static_name.as_str() else {
        return;
    };
    match key_name {
        "templateUrl" | "styleUrl" => {
            if let Some(url) = extract_static_string_expr(prop.value.without_parentheses()) {
                module.dynamic_imports.push(normalize_angular_rel_spec(&url));
            }
        }
        "styleUrls" => {
            if let Expression::ArrayExpression(arr) = prop.value.without_parentheses() {
                for elem in &arr.elements {
                    if let Some(expr) = elem.as_expression()
                        && let Some(url) = extract_static_string_expr(expr.without_parentheses())
                    {
                        module.dynamic_imports.push(normalize_angular_rel_spec(&url));
                    }
                }
            }
        }
        "loadComponent" | "loadChildren" => {
            if let Some(raw_spec) = extract_static_string_expr(prop.value.without_parentheses()) {
                let clean_spec = raw_spec.split('#').next().unwrap_or(&raw_spec).trim();
                if !clean_spec.is_empty() {
                    let rel = normalize_angular_rel_spec(clean_spec);
                    module.dynamic_imports.push(rel.clone());
                    module.route_module_entries.push(rel);
                }
            }
        }
        _ => {}
    }
}

fn normalize_angular_rel_spec(spec: &str) -> String {
    let trimmed = spec.trim();
    if trimmed.starts_with('.') || trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("./{trimmed}")
    }
}

fn parse_ts_import_type_text(raw: &str) -> Option<(String, Option<String>)> {
    let import_idx = raw.find("import(")?;
    let after_open = raw.get(import_idx + "import(".len()..)?;
    let close_idx = after_open.find(')')?;
    let inside = after_open[..close_idx].trim();
    let specifier = inside
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| inside.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))?
        .to_string();
    let after_close = after_open[close_idx + 1..].trim();
    let qualifier = after_close.strip_prefix('.').and_then(|rest| {
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        (!ident.is_empty()).then_some(ident)
    });
    Some((specifier, qualifier))
}

fn collect_declaration_exports(
    decl: &Declaration<'_>,
    is_type_only: bool,
    span: ByteSpan,
    loc: SourceLoc,
    out: &mut Vec<ExportDeclIr>,
) {
    match decl {
        Declaration::FunctionDeclaration(f) => {
            if let Some(id) = &f.id {
                let name = id.name.to_string();
                out.push(ExportDeclIr {
                    is_component: is_component_name(&name),
                    name,
                    local_name: None,
                    from_source: None,
                    is_namespace_re_export: false,
                    is_type_only,
                    span,
                    loc,
                });
            }
        }
        Declaration::ClassDeclaration(c) => {
            if let Some(id) = &c.id {
                let name = id.name.to_string();
                out.push(ExportDeclIr {
                    is_component: is_component_name(&name),
                    name,
                    local_name: None,
                    from_source: None,
                    is_namespace_re_export: false,
                    is_type_only,
                    span,
                    loc,
                });
            }
        }
        Declaration::VariableDeclaration(v) => {
            for d in &v.declarations {
                for name in collect_pattern_bound_names(&d.id) {
                    out.push(ExportDeclIr {
                        is_component: is_component_name(&name),
                        name,
                        local_name: None,
                        from_source: None,
                        is_namespace_re_export: false,
                        is_type_only,
                        span,
                        loc,
                    });
                }
            }
        }
        Declaration::TSInterfaceDeclaration(i) => {
            out.push(ExportDeclIr {
                name: i.id.name.to_string(),
                local_name: None,
                from_source: None,
                is_namespace_re_export: false,
                is_type_only: true,
                is_component: false,
                span,
                loc,
            });
        }
        Declaration::TSTypeAliasDeclaration(t) => {
            out.push(ExportDeclIr {
                name: t.id.name.to_string(),
                local_name: None,
                from_source: None,
                is_namespace_re_export: false,
                is_type_only: true,
                is_component: false,
                span,
                loc,
            });
        }
        Declaration::TSEnumDeclaration(e) => {
            out.push(ExportDeclIr {
                name: e.id.name.to_string(),
                local_name: None,
                from_source: None,
                is_namespace_re_export: false,
                is_type_only,
                is_component: false,
                span,
                loc,
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;

    #[test]
    fn extracts_module_directives_imports_exports_and_routes() {
        let src = r#"
"use client";
import * as Icons from "./icons";
import { Button } from "./Button";

const UsedIcon = Icons.Check;
const lazyChunk = import("./lazyChunk");
route("/settings", "routes/settings.tsx");

export { Button };
export const Card = ({ children }: any) => <Button>{children}</Button>;
"#;
        let file = parse_file_ir(Path::new("index.tsx"), src);
        assert!(file.module.has_use_client);
        assert!(!file.module.has_use_server);
        assert_eq!(file.module.imports.len(), 2);
        assert_eq!(
            file.module.namespace_member_accesses,
            vec![("Icons".to_string(), "Check".to_string())]
        );
        assert_eq!(file.module.dynamic_imports, vec!["./lazyChunk".to_string()]);
        assert_eq!(
            file.module.route_module_entries,
            vec!["routes/settings.tsx".to_string()]
        );
        assert_eq!(
            file.module.component_children_targets,
            vec![("Card".to_string(), "Button".to_string())]
        );
    }
}
