//! Cross-file Python `ProjectGraph` extraction and evaluation (`py-arch-no-circular-imports`,
//! `py-arch-no-unused-exports`, and cross-file `async def` tracking).

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
};

use dotore_core::{
    ByteSpan, Diagnostic, ExtractedFile, FileContext, RuleId, SourceLoc, SymbolKind, SymbolOutline,
    WorkspacePackage, loc_from_line_starts,
};
use ruff_python_ast::{Decorator, Expr, Stmt};
use ruff_text_size::Ranged;

use crate::{
    PyFileIr,
    matchers::{
        all_function_parameters, callee_qualified_name, resolve_active_py_rule_severity,
        text_range_to_byte_span,
    },
};

/// Single-file module import/export and reference summary extracted during `extract_file`.
#[derive(Debug, Clone, Default)]
pub(crate) struct PyModuleGraphInfo {
    /// Exported top-level `async def` function names defined in this module.
    pub exported_async_functions: HashSet<String>,
    /// Runtime imports outside `if TYPE_CHECKING:` blocks (`py-arch-no-circular-imports`).
    pub runtime_imports: Vec<PyImportEdge>,
    /// All imported module and symbol names (including `if TYPE_CHECKING:`).
    pub all_imports: Vec<PyImportEdge>,
    /// Public top-level declarations eligible for `py-arch-no-unused-exports`.
    pub public_exports: Vec<PyExportSymbol>,
    /// Explicitly listed symbol names in `__all__ = [...]`.
    pub dunder_all: HashSet<String>,
    /// All identifier and attribute names referenced anywhere in this file.
    pub referenced_names: HashSet<String>,
    /// Unawaited call sites inside this file that may target an `async def` imported from another module.
    pub potential_unawaited_calls: Vec<PyUnawaitedCallCandidate>,
}

/// An `import ...` or `from ... import ...` statement in a Python module.
#[derive(Debug, Clone)]
pub(crate) struct PyImportEdge {
    /// Relative import dot level (`0` for absolute, `1` for `.`, `2` for `..`, etc.).
    pub level: u32,
    /// Optional dotted module path (`from <module> import ...` or `import <module>`).
    pub module: Option<String>,
    /// Imported `(original_name, local_alias)` pairs.
    pub names: Vec<(String, String)>,
    /// Byte span of the import statement.
    pub span: ByteSpan,
    /// 1-based source location of the import statement.
    pub loc: SourceLoc,
}

/// A top-level public symbol defined in a Python module.
#[derive(Debug, Clone)]
pub(crate) struct PyExportSymbol {
    /// Symbol name.
    pub name: String,
    /// Byte span of the symbol declaration or identifier.
    pub span: ByteSpan,
    /// 1-based source location of the symbol.
    pub loc: SourceLoc,
    /// Enclosing subject name, if any.
    pub subject_name: Option<String>,
    /// Whether this symbol is decorated with a route, task, fixture, or callback decorator.
    pub has_registration_decorator: bool,
}

/// An unawaited call expression that could refer to an imported `async def` function.
#[derive(Debug, Clone)]
pub(crate) struct PyUnawaitedCallCandidate {
    /// Callee expression name (`fn_name` or `mod_alias.fn_name`).
    pub callee: String,
    /// Enclosing subject name.
    pub subject_name: Option<String>,
    /// Byte span of the call expression.
    pub span: ByteSpan,
    /// 1-based source location of the call expression.
    pub loc: SourceLoc,
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans top-level function and class declarations for async defs and decorators"
)]
pub(crate) fn extract_module_graph_info(
    _path: &Path,
    _source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    symbol_outlines: &[SymbolOutline],
) -> PyModuleGraphInfo {
    let mut info = PyModuleGraphInfo::default();
    if is_stub_file {
        return info;
    }

    let mut decorated_top_symbols = HashSet::new();
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(func_def) => {
                let name = func_def.name.to_string();
                if func_def.is_async && !name.starts_with('_') {
                    info.exported_async_functions.insert(name.clone());
                }
                if has_external_registration_decorator(&func_def.decorator_list) {
                    decorated_top_symbols.insert(name);
                }
            }
            Stmt::ClassDef(class_def)
                if has_external_registration_decorator(&class_def.decorator_list) =>
            {
                decorated_top_symbols.insert(class_def.name.to_string());
            }
            _ => {}
        }
    }
    for outline in symbol_outlines {
        if outline.parent_name.is_some() || !outline.exported {
            continue;
        }
        if !matches!(
            outline.kind,
            SymbolKind::Function | SymbolKind::Class | SymbolKind::Constant
        ) {
            continue;
        }
        if outline.name.starts_with("__") && outline.name.ends_with("__") {
            continue;
        }
        let subject_name = matches!(outline.kind, SymbolKind::Function | SymbolKind::Class)
            .then(|| outline.name.clone());
        info.public_exports.push(PyExportSymbol {
            has_registration_decorator: decorated_top_symbols.contains(&outline.name),
            name: outline.name.clone(),
            span: outline.span,
            loc: outline.loc,
            subject_name,
        });
    }

    let mut extractor = GraphAstWalker {
        line_starts,
        info: &mut info,
        in_type_checking: false,
        fn_or_class_depth: 0,
    };
    extractor.walk_suite(suite);
    info
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts decorator callee name from Call or other expression"
)]
fn has_external_registration_decorator(decorators: &[Decorator]) -> bool {
    decorators.iter().any(|dec| {
        let name = match &dec.expression {
            Expr::Call(call) => callee_qualified_name(&call.func),
            other => callee_qualified_name(other),
        };
        let tail = name.rsplit('.').next().unwrap_or(name.as_str());
        !matches!(
            tail,
            "dataclass"
                | "staticmethod"
                | "classmethod"
                | "property"
                | "lru_cache"
                | "cache"
                | "cached_property"
        )
    })
}

struct GraphAstWalker<'a> {
    line_starts: &'a [u32],
    info: &'a mut PyModuleGraphInfo,
    in_type_checking: bool,
    fn_or_class_depth: usize,
}

impl<'a> GraphAstWalker<'a> {
    fn walk_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.walk_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Walks Python statements to extract imports, __all__, and symbol references"
    )]
    fn walk_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(import_stmt) => {
                let span = text_range_to_byte_span(import_stmt.range());
                let loc = loc_from_line_starts(self.line_starts, span.start);
                for alias in &import_stmt.names {
                    let orig = alias.name.to_string();
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| orig.clone(), ToString::to_string);
                    let edge = PyImportEdge {
                        level: 0,
                        module: Some(orig.clone()),
                        names: vec![(orig, bound)],
                        span,
                        loc,
                    };
                    if !self.in_type_checking && self.fn_or_class_depth == 0 {
                        self.info.runtime_imports.push(edge.clone());
                    }
                    self.info.all_imports.push(edge);
                }
            }
            Stmt::ImportFrom(import_from) => {
                let span = text_range_to_byte_span(import_from.range());
                let loc = loc_from_line_starts(self.line_starts, span.start);
                let module = import_from.module.as_ref().map(ToString::to_string);
                let mut names = Vec::new();
                for alias in &import_from.names {
                    let orig = alias.name.to_string();
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| orig.clone(), ToString::to_string);
                    self.info.referenced_names.insert(orig.clone());
                    names.push((orig, bound));
                }
                let edge = PyImportEdge {
                    level: import_from.level,
                    module,
                    names,
                    span,
                    loc,
                };
                if !self.in_type_checking && self.fn_or_class_depth == 0 {
                    self.info.runtime_imports.push(edge.clone());
                }
                self.info.all_imports.push(edge);
            }
            Stmt::Assign(assign) => {
                if self.fn_or_class_depth == 0
                    && assign
                        .targets
                        .iter()
                        .any(|t| matches!(t, Expr::Name(n) if n.id.as_str() == "__all__"))
                {
                    extract_string_list_into(&assign.value, &mut self.info.dunder_all);
                }
                self.walk_expr(&assign.value);
            }
            Stmt::AnnAssign(ann) => {
                self.walk_expr(&ann.annotation);
                if let Some(val) = &ann.value {
                    if self.fn_or_class_depth == 0
                        && matches!(ann.target.as_ref(), Expr::Name(n) if n.id.as_str() == "__all__")
                    {
                        extract_string_list_into(val, &mut self.info.dunder_all);
                    }
                    self.walk_expr(val);
                }
            }
            Stmt::AugAssign(aug) => {
                if self.fn_or_class_depth == 0
                    && matches!(aug.target.as_ref(), Expr::Name(n) if n.id.as_str() == "__all__")
                {
                    extract_string_list_into(&aug.value, &mut self.info.dunder_all);
                }
                self.walk_expr(&aug.value);
            }
            Stmt::FunctionDef(func_def) => {
                for dec in &func_def.decorator_list {
                    self.walk_expr(&dec.expression);
                }
                for param in all_function_parameters(func_def) {
                    if let Some(ann) = &param.parameter.annotation {
                        self.walk_expr(ann);
                    }
                    if let Some(def) = &param.default {
                        self.walk_expr(def);
                    }
                }
                if let Some(ret) = &func_def.returns {
                    self.walk_expr(ret);
                }
                self.fn_or_class_depth += 1;
                self.walk_suite(&func_def.body);
                self.fn_or_class_depth -= 1;
            }
            Stmt::ClassDef(class_def) => {
                for dec in &class_def.decorator_list {
                    self.walk_expr(&dec.expression);
                }
                for base in class_def.bases() {
                    self.walk_expr(base);
                }
                for kw in class_def.keywords() {
                    self.walk_expr(&kw.value);
                }
                self.fn_or_class_depth += 1;
                self.walk_suite(&class_def.body);
                self.fn_or_class_depth -= 1;
            }
            Stmt::If(if_stmt) => {
                let is_tc = is_type_checking_guard(&if_stmt.test);
                self.walk_expr(&if_stmt.test);
                let prev_tc = self.in_type_checking;
                if is_tc {
                    self.in_type_checking = true;
                }
                self.walk_suite(&if_stmt.body);
                self.in_type_checking = prev_tc;
                for clause in &if_stmt.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.walk_expr(test);
                    }
                    self.walk_suite(&clause.body);
                }
            }
            Stmt::For(for_stmt) => {
                self.walk_expr(&for_stmt.iter);
                self.walk_suite(&for_stmt.body);
                self.walk_suite(&for_stmt.orelse);
            }
            Stmt::While(while_stmt) => {
                self.walk_expr(&while_stmt.test);
                self.walk_suite(&while_stmt.body);
                self.walk_suite(&while_stmt.orelse);
            }
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    self.walk_expr(&item.context_expr);
                }
                self.walk_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                self.walk_suite(&try_stmt.body);
                for h in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = h;
                    if let Some(t) = &handler.type_ {
                        self.walk_expr(t);
                    }
                    self.walk_suite(&handler.body);
                }
                self.walk_suite(&try_stmt.orelse);
                self.walk_suite(&try_stmt.finalbody);
            }
            Stmt::Expr(expr_stmt) => self.walk_expr(&expr_stmt.value),
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    self.walk_expr(val);
                }
            }
            Stmt::Raise(r) => {
                if let Some(exc) = &r.exc {
                    self.walk_expr(exc);
                }
            }
            Stmt::Assert(a) => {
                self.walk_expr(&a.test);
                if let Some(msg) = &a.msg {
                    self.walk_expr(msg);
                }
            }
            _ => {}
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Collects identifier and attribute references across expressions"
    )]
    fn walk_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Name(n) => {
                self.info.referenced_names.insert(n.id.to_string());
            }
            Expr::Attribute(attr) => {
                self.info.referenced_names.insert(attr.attr.to_string());
                self.walk_expr(&attr.value);
            }
            Expr::Call(call) => {
                self.walk_expr(&call.func);
                for arg in &call.arguments.args {
                    self.walk_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.walk_expr(&kw.value);
                }
            }
            Expr::Await(aw) => self.walk_expr(&aw.value),
            Expr::BinOp(b) => {
                self.walk_expr(&b.left);
                self.walk_expr(&b.right);
            }
            Expr::UnaryOp(u) => self.walk_expr(&u.operand),
            Expr::BoolOp(b) => {
                for v in &b.values {
                    self.walk_expr(v);
                }
            }
            Expr::Compare(cmp) => {
                for op in &cmp.operands {
                    self.walk_expr(op);
                }
            }
            Expr::Subscript(s) => {
                self.walk_expr(&s.value);
                self.walk_expr(&s.slice);
            }
            Expr::List(l) => {
                for e in &l.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Tuple(t) => {
                for e in &t.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Set(s) => {
                for e in &s.elts {
                    self.walk_expr(e);
                }
            }
            Expr::Dict(d) => {
                for item in &d.items {
                    if let Some(k) = &item.key {
                        self.walk_expr(k);
                    }
                    self.walk_expr(&item.value);
                }
            }
            Expr::ListComp(comp) => {
                for g in &comp.generators {
                    self.walk_expr(&g.iter);
                    for i in &g.ifs {
                        self.walk_expr(i);
                    }
                }
                self.walk_expr(&comp.elt);
            }
            Expr::SetComp(comp) => {
                for g in &comp.generators {
                    self.walk_expr(&g.iter);
                    for i in &g.ifs {
                        self.walk_expr(i);
                    }
                }
                self.walk_expr(&comp.elt);
            }
            Expr::DictComp(comp) => {
                for g in &comp.generators {
                    self.walk_expr(&g.iter);
                    for i in &g.ifs {
                        self.walk_expr(i);
                    }
                }
                if let Some(k) = &comp.key {
                    self.walk_expr(k);
                }
                self.walk_expr(&comp.value);
            }
            Expr::Generator(comp) => {
                for g in &comp.generators {
                    self.walk_expr(&g.iter);
                    for i in &g.ifs {
                        self.walk_expr(i);
                    }
                }
                self.walk_expr(&comp.elt);
            }
            Expr::If(i) => {
                self.walk_expr(&i.test);
                self.walk_expr(&i.body);
                self.walk_expr(&i.orelse);
            }
            _ => {}
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches TYPE_CHECKING guard conditions"
)]
fn is_type_checking_guard(test: &Expr) -> bool {
    match test {
        Expr::Name(n) => n.id.as_str() == "TYPE_CHECKING",
        Expr::Attribute(attr) => attr.attr.as_str() == "TYPE_CHECKING",
        Expr::BooleanLiteral(b) => !b.value,
        Expr::BoolOp(b) => b.values.iter().any(is_type_checking_guard),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts string literals from list/tuple/set in __all__ assignments"
)]
fn extract_string_list_into(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::List(l) => {
            for elt in &l.elts {
                if let Expr::StringLiteral(s) = elt {
                    out.insert(s.value.to_str().to_string());
                }
            }
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                if let Expr::StringLiteral(s) = elt {
                    out.insert(s.value.to_str().to_string());
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn evaluate_package_graph_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if files.len() < 2 {
        return;
    }

    let module_index = build_module_lookup(files, &package.root_dir);
    evaluate_cross_file_unawaited_coroutines(
        package,
        files,
        &module_index,
        enabled_rules,
        diagnostics,
    );
    evaluate_circular_imports(package, files, &module_index, enabled_rules, diagnostics);
    evaluate_unused_exports(package, files, enabled_rules, diagnostics);
}

fn build_module_lookup(files: &[ExtractedFile], package_root: &Path) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for (idx, file) in files.iter().enumerate() {
        let rel = file.path.strip_prefix(package_root).unwrap_or(&file.path);
        for key in module_keys_for_path(rel) {
            map.entry(key).or_insert(idx);
        }
        if rel != file.path.as_path() {
            for key in module_keys_for_path(&file.path) {
                map.entry(key).or_insert(idx);
            }
        }
    }
    map
}

fn module_keys_for_path(path: &Path) -> Vec<String> {
    let mut parts: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .filter(|s| !s.is_empty() && *s != ".")
        .map(ToString::to_string)
        .collect();
    let Some(last) = parts.last_mut() else {
        return Vec::new();
    };
    if let Some(stem) = last
        .strip_suffix(".py")
        .or_else(|| last.strip_suffix(".pyi"))
    {
        *last = stem.to_string();
    }
    if parts.last().is_some_and(|s| s == "__init__") {
        parts.pop();
    }
    if parts.is_empty() {
        return Vec::new();
    }

    let mut keys = Vec::new();
    for start in 0..parts.len() {
        keys.push(parts[start..].join("."));
    }
    keys
}

fn resolve_import_targets(
    importer_path: &Path,
    edge: &PyImportEdge,
    files: &[ExtractedFile],
    module_index: &HashMap<String, usize>,
) -> Vec<usize> {
    let mut targets = Vec::new();

    if edge.level > 0 {
        let mut base_dir: Option<&Path> = importer_path.parent();
        for _ in 1..edge.level {
            base_dir = base_dir.and_then(Path::parent);
        }
        let base_dir = base_dir.unwrap_or_else(|| Path::new(""));
        if let Some(mod_str) = &edge.module {
            let rel_mod_path = mod_str.replace('.', "/");
            let candidate_py = base_dir.join(format!("{rel_mod_path}.py"));
            let candidate_init = base_dir.join(&rel_mod_path).join("__init__.py");
            push_matching_file_indices(files, &candidate_py, &candidate_init, &mut targets);
            if targets.is_empty()
                && let Some(&idx) = module_index.get(mod_str)
            {
                targets.push(idx);
            }
        } else {
            for (orig_name, _) in &edge.names {
                let candidate_py = base_dir.join(format!("{orig_name}.py"));
                let candidate_init = base_dir.join(orig_name).join("__init__.py");
                push_matching_file_indices(files, &candidate_py, &candidate_init, &mut targets);
            }
        }
        return targets;
    }

    if let Some(mod_str) = &edge.module {
        if let Some(&idx) = module_index.get(mod_str) {
            targets.push(idx);
        }
        for (orig_name, _) in &edge.names {
            let combined = format!("{mod_str}.{orig_name}");
            if let Some(&idx) = module_index.get(&combined)
                && !targets.contains(&idx)
            {
                targets.push(idx);
            }
        }
    }
    targets
}

fn push_matching_file_indices(
    files: &[ExtractedFile],
    candidate_py: &Path,
    candidate_init: &Path,
    targets: &mut Vec<usize>,
) {
    for (idx, f) in files.iter().enumerate() {
        if f.path == candidate_py || f.path == candidate_init {
            targets.push(idx);
        }
    }
}

fn evaluate_circular_imports(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    module_index: &HashMap<String, usize>,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let n = files.len();
    let mut adj: Vec<Vec<(usize, ByteSpan, SourceLoc)>> = vec![Vec::new(); n];

    for (u, file) in files.iter().enumerate() {
        let Some(ir) = file.downcast_payload::<PyFileIr>() else {
            continue;
        };
        for edge in &ir.module_graph.runtime_imports {
            for v in resolve_import_targets(&file.path, edge, files, module_index) {
                if u != v && !adj[u].iter().any(|(target, _, _)| *target == v) {
                    adj[u].push((v, edge.span, edge.loc));
                }
            }
        }
    }

    let mut emitted_files = HashSet::new();
    for start in 0..n {
        if emitted_files.contains(&start) {
            continue;
        }
        let mut path_stack = vec![start];
        let mut visited = HashSet::from([start]);
        if let Some(cycle) = find_cycle_from(start, start, &adj, &mut path_stack, &mut visited) {
            for window in cycle.windows(2) {
                let u = window[0];
                let v = window[1];
                if !emitted_files.insert(u) {
                    continue;
                }
                let Some((_, span, loc)) = adj[u].iter().find(|(t, _, _)| *t == v).copied() else {
                    continue;
                };
                let file = &files[u];
                let Some(effective_sev) = resolve_active_py_rule_severity(
                    package,
                    file,
                    RuleId::PyArchNoCircularImports,
                    enabled_rules,
                    loc.line,
                    span,
                ) else {
                    continue;
                };
                let cycle_display = format_cycle_from_node(&cycle, u, files);
                let target_file_name = files[v]
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("module")
                    .to_string();
                diagnostics.push(
                    Diagnostic::for_rule(
                        RuleId::PyArchNoCircularImports,
                        file.path.clone(),
                        loc,
                        span,
                        format!(
                            "Circular import cycle detected ({cycle_display}); move type-only imports under `if TYPE_CHECKING:` or extract shared definitions into a separate module."
                        ),
                    )
                    .with_severity(effective_sev)
                    .with_message_id("pyArchNoCircularImports")
                    .with_target_name(target_file_name),
                );
            }
        }
    }
}

fn find_cycle_from(
    start: usize,
    curr: usize,
    adj: &[Vec<(usize, ByteSpan, SourceLoc)>],
    path_stack: &mut Vec<usize>,
    visited: &mut HashSet<usize>,
) -> Option<Vec<usize>> {
    for &(next, _, _) in &adj[curr] {
        if next == start && path_stack.len() >= 2 {
            let mut cycle = path_stack.clone();
            cycle.push(start);
            return Some(cycle);
        }
        if visited.insert(next) {
            path_stack.push(next);
            if let Some(found) = find_cycle_from(start, next, adj, path_stack, visited) {
                return Some(found);
            }
            path_stack.pop();
        }
    }
    None
}

fn format_cycle_from_node(cycle: &[usize], rotate_to: usize, files: &[ExtractedFile]) -> String {
    let core = &cycle[..cycle.len().saturating_sub(1)];
    let pos = core.iter().position(|&n| n == rotate_to).unwrap_or(0);
    let mut rotated: Vec<String> = core[pos..]
        .iter()
        .chain(core[..pos].iter())
        .map(|&idx| {
            files[idx]
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("module.py")
                .to_string()
        })
        .collect();
    if let Some(first) = rotated.first().cloned() {
        rotated.push(first);
    }
    rotated.join(" -> ")
}

fn evaluate_unused_exports(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut star_imported_modules: BTreeSet<usize> = BTreeSet::new();
    let module_index = build_module_lookup(files, &package.root_dir);

    for (u, file) in files.iter().enumerate() {
        let Some(ir) = file.downcast_payload::<PyFileIr>() else {
            continue;
        };
        collect_star_imported_targets(
            u,
            file,
            &ir.module_graph.all_imports,
            files,
            &module_index,
            &mut star_imported_modules,
        );
    }

    for (idx, file) in files.iter().enumerate() {
        if star_imported_modules.contains(&idx)
            || is_entrypoint_or_test_module(&file.path, file.file_context)
        {
            continue;
        }
        let Some(ir) = file.downcast_payload::<PyFileIr>() else {
            continue;
        };

        for export in &ir.module_graph.public_exports {
            if export.has_registration_decorator || ir.module_graph.dunder_all.contains(&export.name)
            {
                continue;
            }
            let used_in_other_file = files.iter().enumerate().any(|(other_idx, other_file)| {
                if other_idx == idx {
                    return false;
                }
                let Some(other_ir) = other_file.downcast_payload::<PyFileIr>() else {
                    return false;
                };
                other_ir
                    .module_graph
                    .referenced_names
                    .contains(&export.name)
            });
            if used_in_other_file {
                continue;
            }
            let Some(effective_sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::PyArchNoUnusedExports,
                enabled_rules,
                export.loc.line,
                export.span,
            ) else {
                continue;
            };
            diagnostics.push(
                Diagnostic::for_rule(
                    RuleId::PyArchNoUnusedExports,
                    file.path.clone(),
                    export.loc,
                    export.span,
                    format!(
                        "Public top-level symbol `{}` is never imported or referenced by any other module in this package; prefix with `_` if module-private or remove if dead code.",
                        export.name
                    ),
                )
                .with_subject(export.subject_name.clone())
                .with_severity(effective_sev)
                .with_message_id("pyArchNoUnusedExports")
                .with_target_name(export.name.clone()),
            );
        }
    }
}

fn collect_star_imported_targets(
    importer_idx: usize,
    importer_file: &ExtractedFile,
    imports: &[PyImportEdge],
    files: &[ExtractedFile],
    module_index: &HashMap<String, usize>,
    star_imported_modules: &mut BTreeSet<usize>,
) {
    for edge in imports {
        if !edge.names.iter().any(|(orig, _)| orig == "*") {
            continue;
        }
        for v in resolve_import_targets(&importer_file.path, edge, files, module_index) {
            if importer_idx != v {
                star_imported_modules.insert(v);
            }
        }
    }
}

fn evaluate_cross_file_unawaited_coroutines(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    module_index: &HashMap<String, usize>,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (u, file) in files.iter().enumerate() {
        let Some(ir) = file.downcast_payload::<PyFileIr>() else {
            continue;
        };
        if ir.module_graph.potential_unawaited_calls.is_empty() {
            continue;
        }
        let imported_async_callees = collect_imported_async_callees(
            u,
            file,
            &ir.module_graph.all_imports,
            files,
            module_index,
        );
        if imported_async_callees.is_empty() {
            continue;
        }

        for call in &ir.module_graph.potential_unawaited_calls {
            if !imported_async_callees.contains(&call.callee) {
                continue;
            }
            let Some(effective_sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::PyAsyncNoUnawaitedCoroutine,
                enabled_rules,
                call.loc.line,
                call.span,
            ) else {
                continue;
            };
            diagnostics.push(
                Diagnostic::for_rule(
                    RuleId::PyAsyncNoUnawaitedCoroutine,
                    file.path.clone(),
                    call.loc,
                    call.span,
                    format!(
                        "Coroutine `{}(...)` imported from package module is called without `await`, `asyncio.gather(...)`, or `TaskGroup.create_task(...)` and will never execute.",
                        call.callee
                    ),
                )
                .with_subject(call.subject_name.clone())
                .with_severity(effective_sev)
                .with_message_id("pyAsyncNoUnawaitedCoroutine")
                .with_target_name(call.callee.clone()),
            );
        }
    }
}

fn collect_imported_async_callees(
    importer_idx: usize,
    importer_file: &ExtractedFile,
    imports: &[PyImportEdge],
    files: &[ExtractedFile],
    module_index: &HashMap<String, usize>,
) -> HashSet<String> {
    let mut callees = HashSet::new();
    for edge in imports {
        for v in resolve_import_targets(&importer_file.path, edge, files, module_index) {
            if importer_idx == v {
                continue;
            }
            let Some(target_ir) = files[v].downcast_payload::<PyFileIr>() else {
                continue;
            };
            record_imported_async_names(
                &edge.names,
                &target_ir.module_graph.exported_async_functions,
                &mut callees,
            );
        }
    }
    callees
}

fn record_imported_async_names(
    names: &[(String, String)],
    exported_async_functions: &HashSet<String>,
    callees: &mut HashSet<String>,
) {
    for (orig, bound) in names {
        if exported_async_functions.contains(orig) {
            callees.insert(bound.clone());
        } else {
            for async_fn in exported_async_functions {
                callees.insert(format!("{bound}.{async_fn}"));
            }
        }
    }
}

fn is_entrypoint_or_test_module(path: &Path, file_context: FileContext) -> bool {
    if file_context != FileContext::Production {
        return true;
    }
    if path.extension().and_then(|e| e.to_str()) == Some("pyi") {
        return true;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if matches!(
        file_name,
        "__init__.py"
            | "__main__.py"
            | "main.py"
            | "app.py"
            | "cli.py"
            | "wsgi.py"
            | "asgi.py"
            | "manage.py"
            | "setup.py"
            | "conftest.py"
    ) || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
    {
        return true;
    }
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| matches!(s, "tests" | "test" | "migrations" | "alembic"))
    })
}
