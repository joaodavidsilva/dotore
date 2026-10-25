//! Single-pass Python architectural facet extraction (`ArchitectureFileFacets`).

use std::{collections::HashSet, path::Path};

use dotore_core::{
    ArchitectureFileFacets, ByteSpan, ConcernBucket, ConcernSignalSite, HelperFingerprintIr,
    InlineTerminalUiPrimitiveSiteIr, SourceLoc, StaticCatalogSiteIr,
    StructLiteralConstructionSiteIr, SymbolKind, SymbolOutline, TerminalUiPrimitiveKind,
    loc_from_line_starts,
};
use ruff_python_ast::{
    CmpOp, Expr, ExprCall, ExprFString, ExprStringLiteral, Stmt, StmtAnnAssign, StmtAssign,
    StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    all_function_parameters, callee_qualified_name, function_def_header_span, slice_source,
    text_range_to_byte_span, walk_expr_children, walk_stmt_exprs, walk_stmt_sub_stmts,
};

use super::hasher::compute_function_structural_hash;

pub(super) fn extract_python_architecture_facets(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    symbol_outlines: &[SymbolOutline],
    dunder_all: &HashSet<String>,
) -> ArchitectureFileFacets {
    if is_stub_file {
        return ArchitectureFileFacets::default();
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let is_named_entrypoint = matches!(
        file_name,
        "main.py" | "__main__.py" | "app.py" | "cli.py" | "manage.py"
    );
    let has_main_guard = suite
        .iter()
        .any(|stmt| matches!(stmt, Stmt::If(if_stmt) if is_dunder_main_guard(&if_stmt.test)));
    let is_entrypoint = is_named_entrypoint || has_main_guard;

    let is_ui_kit_module = matches!(
        file_name,
        "ui.py" | "console.py" | "terminal.py" | "tui.py" | "terminal_ui.py"
    ) || path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| matches!(s, "ui" | "tui" | "terminal_ui"))
    });

    let public_type_count = symbol_outlines
        .iter()
        .filter(|o| o.parent_name.is_none() && o.exported && o.kind == SymbolKind::Class)
        .count();

    let mut facets = ArchitectureFileFacets {
        is_entrypoint,
        is_ui_kit_module,
        public_type_count,
        ..ArchitectureFileFacets::default()
    };

    let mut walker = PyArchFacetWalker {
        source,
        line_starts,
        dunder_all,
        facets: &mut facets,
        in_entrypoint_body: false,
    };
    walker.walk_module_suite(suite);

    facets.domain_clusters = facets
        .distinct_concern_buckets()
        .into_iter()
        .map(|b| b.as_str().to_string())
        .collect();

    facets
}

struct PyArchFacetWalker<'a> {
    source: &'a str,
    line_starts: &'a [u32],
    dunder_all: &'a HashSet<String>,
    facets: &'a mut ArchitectureFileFacets,
    in_entrypoint_body: bool,
}

impl PyArchFacetWalker<'_> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Top-level module walker dispatches declarations and forwards remaining statements to walk_stmt (#50)"
    )]
    fn walk_module_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            match stmt {
                Stmt::ClassDef(cls) => {
                    let span = text_range_to_byte_span(cls.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::TypeDefinitions,
                        detail: format!("class {}", cls.name),
                        loc,
                        span,
                    });
                    self.record_class_builder_definitions(cls);
                    self.walk_suite(&cls.body);
                }
                Stmt::FunctionDef(func_def) => {
                    let fn_name = func_def.name.as_str();
                    if is_ast_or_validation_helper_name(fn_name) {
                        let span = text_range_to_byte_span(func_def.range());
                        let loc = loc_from_line_starts(self.line_starts, span.start);
                        self.facets.concern_signals.push(ConcernSignalSite {
                            bucket: ConcernBucket::AstOrValidationHelper,
                            detail: format!("def {fn_name}"),
                            loc,
                            span,
                        });
                    }
                    self.record_top_level_helper_fingerprint(func_def);
                    self.record_top_level_factory_function(func_def);
                    let is_entry_fn =
                        self.facets.is_entrypoint && matches!(fn_name, "main" | "cli" | "run");
                    let prev = self.in_entrypoint_body;
                    if is_entry_fn {
                        self.in_entrypoint_body = true;
                    }
                    self.walk_suite(&func_def.body);
                    self.in_entrypoint_body = prev;
                }
                Stmt::If(if_stmt) if is_dunder_main_guard(&if_stmt.test) => {
                    let span = text_range_to_byte_span(if_stmt.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    self.facets.concern_signals.push(ConcernSignalSite {
                        bucket: ConcernBucket::EntrypointAdapter,
                        detail: "if __name__ == \"__main__\"".to_string(),
                        loc,
                        span,
                    });
                    let prev = self.in_entrypoint_body;
                    self.in_entrypoint_body = true;
                    self.walk_suite(&if_stmt.body);
                    self.in_entrypoint_body = prev;
                }
                Stmt::Import(imp) => {
                    let span = text_range_to_byte_span(imp.range());
                    let loc = loc_from_line_starts(self.line_starts, span.start);
                    for alias in &imp.names {
                        self.record_import_signal(alias.name.as_str(), loc, span);
                    }
                }
                Stmt::ImportFrom(imp_from) => self.inspect_import_from(imp_from),
                Stmt::Assign(assign) => {
                    self.inspect_top_level_assign(assign);
                    self.walk_expr(&assign.value);
                }
                Stmt::AnnAssign(ann) => {
                    self.inspect_top_level_ann_assign(ann);
                    if let Some(val) = &ann.value {
                        self.walk_expr(val);
                    }
                }
                other => {
                    let prev = self.in_entrypoint_body;
                    if self.facets.is_entrypoint {
                        self.in_entrypoint_body = true;
                    }
                    self.walk_stmt(other);
                    self.in_entrypoint_body = prev;
                }
            }
        }
    }

    fn inspect_import_from(&mut self, imp_from: &ruff_python_ast::StmtImportFrom) {
        let Some(module) = &imp_from.module else {
            return;
        };
        let span = text_range_to_byte_span(imp_from.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let mod_str = module.as_str();
        for alias in &imp_from.names {
            let combined = format!("{mod_str}.{}", alias.name);
            self.record_import_signal(&combined, loc, span);
        }
    }

    fn record_import_signal(&mut self, imported: &str, loc: SourceLoc, span: ByteSpan) {
        if imported.starts_with("rich.console")
            || imported.starts_with("rich.table")
            || imported.starts_with("rich.panel")
            || imported.starts_with("streamlit")
            || imported.ends_with(".render_template")
            || imported.ends_with(".Jinja2Templates")
        {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: format!("import {imported}"),
                loc,
                span,
            });
        } else if imported.starts_with("argparse")
            || imported.starts_with("typer")
            || imported.starts_with("fastapi")
        {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::EntrypointAdapter,
                detail: format!("import {imported}"),
                loc,
                span,
            });
        }
    }

    fn inspect_top_level_assign(&mut self, assign: &StmtAssign) {
        let Some(Expr::Name(target)) = assign.targets.first() else {
            return;
        };
        if target.id.as_str() == "__all__" {
            return;
        }
        let span = text_range_to_byte_span(assign.range());
        self.record_static_catalog_if_applicable(target.id.as_str(), &assign.value, span);
    }

    fn inspect_top_level_ann_assign(&mut self, ann: &StmtAnnAssign) {
        let Expr::Name(target) = ann.target.as_ref() else {
            return;
        };
        if target.id.as_str() == "__all__" {
            return;
        }
        if let Some(val) = &ann.value {
            let span = text_range_to_byte_span(ann.range());
            self.record_static_catalog_if_applicable(target.id.as_str(), val, span);
        }
    }

    fn record_static_catalog_if_applicable(&mut self, name: &str, value: &Expr, span: ByteSpan) {
        let Some(entry_count) = static_collection_entry_count(value) else {
            return;
        };
        if entry_count < 3 {
            return;
        }
        let val_span = text_range_to_byte_span(value.range());
        let byte_len = val_span.end.saturating_sub(val_span.start) as usize;
        let loc = loc_from_line_starts(self.line_starts, span.start);
        self.facets.static_catalog_sites.push(StaticCatalogSiteIr {
            name: name.to_string(),
            entry_count,
            byte_len,
            loc,
            span,
        });
        if entry_count >= 10 {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::StaticDataCatalog,
                detail: format!("{name} ({entry_count} entries)"),
                loc,
                span,
            });
        }
    }

    fn record_class_builder_definitions(&mut self, cls: &StmtClassDef) {
        let cls_name = cls.name.as_str();
        if let Some(target_type) = cls_name.strip_suffix("Builder")
            && !target_type.is_empty()
        {
            push_unique_string(&mut self.facets.defined_builder_types, target_type);
        }
        for stmt in &cls.body {
            let Stmt::FunctionDef(method_def) = stmt else {
                continue;
            };
            let m_name = method_def.name.as_str();
            if matches!(
                m_name,
                "from_defaults" | "builder" | "default" | "create" | "build"
            ) || m_name.starts_with("from_")
                || m_name.starts_with("with_")
                || m_name.starts_with("build_")
            {
                push_unique_string(&mut self.facets.defined_builder_types, cls_name);
                break;
            }
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Inspects Name and StringLiteral return type annotations for builder factories (#50)"
    )]
    fn record_top_level_factory_function(&mut self, func_def: &StmtFunctionDef) {
        let fn_name = func_def.name.as_str();
        if !(fn_name == "from_defaults"
            || fn_name.starts_with("build_")
            || fn_name.starts_with("make_"))
        {
            return;
        }
        if let Some(suffix) = fn_name
            .strip_prefix("build_")
            .or_else(|| fn_name.strip_prefix("make_"))
        {
            let pascal = snake_to_pascal_case(suffix);
            if is_pascal_case_class_name(&pascal) {
                push_unique_string(&mut self.facets.defined_builder_types, &pascal);
            }
        }
        if let Some(ret) = &func_def.returns {
            match ret.as_ref() {
                Expr::Name(n) if is_pascal_case_class_name(n.id.as_str()) => {
                    push_unique_string(&mut self.facets.defined_builder_types, n.id.as_str());
                }
                Expr::StringLiteral(s) if is_pascal_case_class_name(s.value.to_str()) => {
                    push_unique_string(&mut self.facets.defined_builder_types, s.value.to_str());
                }
                _ => {}
            }
        }
        for stmt in &func_def.body {
            if let Stmt::Return(ret_stmt) = stmt
                && let Some(Expr::Call(call)) = ret_stmt.value.as_deref()
            {
                let callee = callee_qualified_name(&call.func);
                let tail = callee.rsplit('.').next().unwrap_or(&callee);
                if is_pascal_case_class_name(tail) {
                    push_unique_string(&mut self.facets.defined_builder_types, tail);
                }
            }
        }
    }

    fn record_top_level_helper_fingerprint(&mut self, func_def: &StmtFunctionDef) {
        let fn_name = func_def.name.as_str();
        let is_dunder = fn_name.starts_with("__") && fn_name.ends_with("__");
        if is_dunder {
            return;
        }
        let is_private = fn_name.starts_with('_')
            || (!self.dunder_all.is_empty() && !self.dunder_all.contains(fn_name));
        let statement_count = count_non_docstring_statements(&func_def.body);
        if statement_count < 2 {
            return;
        }
        let param_count = all_function_parameters(func_def).count();
        let normalized_hash = compute_function_structural_hash(func_def, param_count);
        let span = function_def_header_span(self.source, func_def);
        let loc = loc_from_line_starts(self.line_starts, span.start);
        self.facets.helper_fingerprints.push(HelperFingerprintIr {
            name: fn_name.to_string(),
            normalized_hash,
            statement_count,
            param_count,
            is_private,
            loc,
            span,
        });
    }
}

impl PyArchFacetWalker<'_> {
    fn walk_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.walk_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Walks statements and expressions for architectural facet extraction (#50)"
    )]
    fn walk_stmt(&mut self, stmt: &Stmt) {
        if self.in_entrypoint_body && !is_docstring_stmt(stmt) {
            self.facets.entrypoint_statement_count += 1;
        }
        match stmt {
            Stmt::ClassDef(cls) => {
                let span = text_range_to_byte_span(cls.range());
                let loc = loc_from_line_starts(self.line_starts, span.start);
                self.facets.concern_signals.push(ConcernSignalSite {
                    bucket: ConcernBucket::TypeDefinitions,
                    detail: format!("class {}", cls.name),
                    loc,
                    span,
                });
                self.walk_suite(&cls.body);
            }
            Stmt::FunctionDef(func_def) => {
                self.walk_suite(&func_def.body);
            }
            Stmt::AnnAssign(ann) => {
                if let Some(val) = &ann.value {
                    self.walk_expr(val);
                }
            }
            Stmt::For(for_stmt) => {
                self.record_entrypoint_loop_signal(text_range_to_byte_span(for_stmt.range()));
                self.walk_expr(&for_stmt.iter);
                self.walk_suite(&for_stmt.body);
                self.walk_suite(&for_stmt.orelse);
            }
            Stmt::While(while_stmt) => {
                self.record_entrypoint_loop_signal(text_range_to_byte_span(while_stmt.range()));
                self.walk_expr(&while_stmt.test);
                self.walk_suite(&while_stmt.body);
                self.walk_suite(&while_stmt.orelse);
            }
            _ => {
                walk_stmt_exprs(stmt, |e| self.walk_expr(e));
                walk_stmt_sub_stmts(stmt, |s| self.walk_stmt(s));
            }
        }
    }

    fn record_entrypoint_loop_signal(&mut self, span: ByteSpan) {
        if self.in_entrypoint_body {
            let loc = loc_from_line_starts(self.line_starts, span.start);
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::EntrypointAdapter,
                detail: "entrypoint-domain-loop".to_string(),
                loc,
                span,
            });
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Inspects calls and string literals for I/O and presentation signals (#50)"
    )]
    fn walk_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                self.inspect_call(call);
                walk_expr_children(expr, |child| self.walk_expr(child));
            }
            Expr::StringLiteral(str_lit) => self.inspect_string_literal(str_lit),
            Expr::FString(fstr) => self.inspect_fstring(fstr),
            _ => walk_expr_children(expr, |child| self.walk_expr(child)),
        }
    }

    fn inspect_call(&mut self, call: &ExprCall) {
        let callee = callee_qualified_name(&call.func);
        if callee.is_empty() {
            return;
        }
        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);

        if is_verified_python_io_call(&callee, call) {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::DataOrNetworkIo,
                detail: format!("{callee}(...)"),
                loc,
                span,
            });
        } else if is_verified_python_presentation_call(&callee) {
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: format!("{callee}(...)"),
                loc,
                span,
            });
        }
        self.inspect_struct_literal_call(&callee, call, loc, span);
    }

    fn inspect_struct_literal_call(
        &mut self,
        callee: &str,
        call: &ExprCall,
        loc: SourceLoc,
        span: ByteSpan,
    ) {
        let tail = callee.rsplit('.').next().unwrap_or(callee);
        if !is_pascal_case_class_name(tail) {
            return;
        }
        let mut field_names = Vec::new();
        let mut default_or_literal_fields = Vec::new();
        for kw in &call.arguments.keywords {
            let Some(arg_id) = &kw.arg else {
                continue;
            };
            let key_str = arg_id.as_str();
            if is_default_or_literal_expr(&kw.value) {
                default_or_literal_fields.push(key_str.to_string());
            }
            field_names.push(key_str.to_string());
        }
        if field_names.len() >= 3 {
            self.facets
                .struct_literal_sites
                .push(StructLiteralConstructionSiteIr {
                    type_name: tail.to_string(),
                    field_names,
                    default_or_literal_fields,
                    loc,
                    span,
                });
        }
    }

    fn inspect_string_literal(&mut self, str_lit: &ExprStringLiteral) {
        let span = text_range_to_byte_span(str_lit.range());
        let raw = slice_source(self.source, span);
        let val = str_lit.value.to_str();
        self.check_terminal_ui_text(val, raw, span);
    }

    fn inspect_fstring(&mut self, fstr: &ExprFString) {
        let span = text_range_to_byte_span(fstr.range());
        let raw = slice_source(self.source, span);
        let mut combined = String::new();
        for part in fstr.value.elements() {
            if let Some(lit) = part.as_literal() {
                combined.push_str(&lit.value);
            } else if let Some(interp) = part.as_interpolation() {
                self.walk_expr(&interp.expression);
            }
        }
        self.check_terminal_ui_text(&combined, raw, span);
    }

    fn check_terminal_ui_text(&mut self, decoded: &str, raw: &str, span: ByteSpan) {
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let has_ansi = decoded.contains("\x1b[")
            || raw.contains("\\x1b[")
            || raw.contains("\\u001b[")
            || raw.contains("\\033[");
        let has_box = decoded.chars().any(is_box_drawing_char);

        if has_ansi {
            self.facets
                .inline_terminal_ui_sites
                .push(InlineTerminalUiPrimitiveSiteIr {
                    kind: TerminalUiPrimitiveKind::AnsiEscape,
                    snippet: "\\x1b[".to_string(),
                    loc,
                    span,
                });
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: "ANSI escape sequence".to_string(),
                loc,
                span,
            });
        } else if has_box {
            self.facets
                .inline_terminal_ui_sites
                .push(InlineTerminalUiPrimitiveSiteIr {
                    kind: TerminalUiPrimitiveKind::BoxDrawing,
                    snippet: "box-drawing literal".to_string(),
                    loc,
                    span,
                });
            self.facets.concern_signals.push(ConcernSignalSite {
                bucket: ConcernBucket::TerminalOrUiPresentation,
                detail: "Unicode box-drawing literal".to_string(),
                loc,
                span,
            });
        }
    }
}

fn is_dunder_main_guard(test: &Expr) -> bool {
    let Expr::Compare(cmp) = test else {
        return false;
    };
    let (Some(CmpOp::Eq), Some(left), Some(right)) =
        (cmp.ops.first(), cmp.operands.first(), cmp.operands.get(1))
    else {
        return false;
    };
    if cmp.ops.len() != 1 || cmp.operands.len() != 2 {
        return false;
    }
    let left_is_name = matches!(left, Expr::Name(n) if n.id.as_str() == "__name__");
    let right_is_main = matches!(right, Expr::StringLiteral(s) if s.value.to_str() == "__main__");
    let left_is_main = matches!(left, Expr::StringLiteral(s) if s.value.to_str() == "__main__");
    let right_is_name = matches!(right, Expr::Name(n) if n.id.as_str() == "__name__");
    (left_is_name && right_is_main) || (left_is_main && right_is_name)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Counts entries in top-level static list, tuple, set, dict, or frozenset literals (#50)"
)]
fn static_collection_entry_count(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::List(l) => Some(l.elts.len()),
        Expr::Tuple(t) => Some(t.elts.len()),
        Expr::Set(s) => Some(s.elts.len()),
        Expr::Dict(d) => Some(d.items.len()),
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            if matches!(
                callee.as_str(),
                "frozenset" | "tuple" | "list" | "set" | "dict"
            ) && let Some(first_arg) = call.arguments.args.first()
            {
                static_collection_entry_count(first_arg)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_ast_or_validation_helper_name(fn_name: &str) -> bool {
    let trimmed = fn_name.trim_start_matches('_');
    [
        "parse_",
        "validate_",
        "visit_",
        "walk_",
        "extract_",
        "check_",
        "normalize_",
        "transform_",
        "compute_",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

pub(super) fn is_docstring_stmt(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Expr(expr_stmt) if matches!(expr_stmt.value.as_ref(), Expr::StringLiteral(_))
    )
}

fn is_box_drawing_char(ch: char) -> bool {
    matches!(ch, '\u{2500}'..='\u{257F}')
}

fn is_verified_python_io_call(callee: &str, call: &ExprCall) -> bool {
    if callee == "open" {
        if let Some(Expr::StringLiteral(mode)) = call.arguments.args.get(1) {
            let m = mode.value.to_str();
            if m.contains('w') || m.contains('a') || m.contains('+') || m.contains('x') {
                return true;
            }
        }
        return true;
    }
    if callee.starts_with("httpx.")
        || callee.starts_with("requests.")
        || callee.starts_with("aiohttp.")
        || callee.starts_with("urllib.request.")
        || matches!(
            callee,
            "urlopen" | "write_text" | "write_bytes" | "read_text" | "read_bytes"
        )
    {
        return true;
    }
    if let Some((prefix, method)) = callee.rsplit_once('.') {
        let receiver = prefix.rsplit('.').next().unwrap_or(prefix);
        if matches!(
            method,
            "write_text" | "write_bytes" | "read_text" | "read_bytes"
        ) {
            return true;
        }
        if matches!(
            receiver,
            "session"
                | "db"
                | "cursor"
                | "cur"
                | "conn"
                | "connection"
                | "engine"
                | "objects"
                | "client"
                | "http"
        ) && matches!(
            method,
            "query"
                | "execute"
                | "executemany"
                | "fetchall"
                | "fetchone"
                | "scalars"
                | "scalar"
                | "filter"
                | "get"
                | "post"
                | "put"
                | "delete"
                | "patch"
                | "request"
                | "create"
                | "bulk_create"
        ) {
            return true;
        }
    }
    false
}

fn is_verified_python_presentation_call(callee: &str) -> bool {
    if matches!(
        callee,
        "Console"
            | "rich.console.Console"
            | "click.style"
            | "click.secho"
            | "click.echo"
            | "typer.secho"
            | "typer.echo"
            | "render_template"
            | "flask.render_template"
            | "Jinja2Templates"
    ) || callee.starts_with("streamlit.")
        || callee.starts_with("st.")
        || callee.starts_with("rich.")
    {
        return true;
    }
    if let Some((prefix, method)) = callee.rsplit_once('.') {
        let receiver = prefix.rsplit('.').next().unwrap_or(prefix);
        if matches!(receiver, "console" | "Console") && matches!(method, "print" | "log" | "rule") {
            return true;
        }
        if method == "TemplateResponse" {
            return true;
        }
    }
    false
}

fn push_unique_string(vec: &mut Vec<String>, item: &str) {
    if !vec.iter().any(|s| s == item) {
        vec.push(item.to_string());
    }
}

fn snake_to_pascal_case(snake: &str) -> String {
    let mut out = String::new();
    for part in snake.split('_').filter(|p| !p.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            for ch in chars {
                out.push(ch);
            }
        }
    }
    out
}

fn is_pascal_case_class_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() || !name.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    !matches!(
        name,
        "Path"
            | "PurePath"
            | "PosixPath"
            | "WindowsPath"
            | "Console"
            | "Jinja2Templates"
            | "Exception"
            | "ValueError"
            | "TypeError"
            | "RuntimeError"
            | "KeyError"
            | "SystemExit"
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks default/boilerplate literals (None, bool, numbers, strings, empty collections) (#50)"
)]
fn is_default_or_literal_expr(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) => true,
        Expr::BooleanLiteral(b) => !b.value,
        Expr::NumberLiteral(num) => match &num.value {
            ruff_python_ast::Number::Int(i) => i.as_u64() == Some(0),
            ruff_python_ast::Number::Float(f) => *f == 0.0,
            ruff_python_ast::Number::Complex { real, imag } => *real == 0.0 && *imag == 0.0,
        },
        Expr::StringLiteral(s) => {
            let text = s.value.to_str();
            text.is_empty()
                || matches!(
                    text.to_ascii_lowercase().as_str(),
                    "default" | "none" | "auto" | "utf-8" | "utf8"
                )
        }
        Expr::BytesLiteral(b) => b.value.is_empty(),
        Expr::List(l) => l.elts.is_empty(),
        Expr::Tuple(t) => t.elts.is_empty(),
        Expr::Set(s) => s.elts.is_empty(),
        Expr::Dict(d) => d.items.is_empty(),
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            matches!(callee.as_str(), "list" | "dict" | "set" | "tuple")
                && call.arguments.args.is_empty()
                && call.arguments.keywords.is_empty()
        }
        _ => false,
    }
}

fn count_non_docstring_statements(suite: &[Stmt]) -> usize {
    let mut total = 0;
    for (idx, stmt) in suite.iter().enumerate() {
        if idx == 0 && is_docstring_stmt(stmt) {
            continue;
        }
        total += 1;
        walk_stmt_sub_stmts(stmt, |child| {
            total += count_non_docstring_statements(std::slice::from_ref(child));
        });
    }
    total
}
