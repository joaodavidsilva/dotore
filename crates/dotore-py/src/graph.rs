//! Cross-file Python `ProjectGraph` extraction and evaluation (`py-arch-no-circular-imports`,
//! `py-arch-no-unused-exports`, and cross-file `async def` tracking).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
};

use dotore_core::{
    ByteSpan, ConcernBucket, Diagnostic, ExtractedFile, FileContext, HelperFingerprintIr,
    ResolvedCallerSite, RuleId, RuleSeverity, SourceLoc, StructLiteralConstructionSiteIr,
    SymbolKind, SymbolOutline, WorkspacePackage, loc_from_line_starts,
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
    runtime_imports: Vec<PyImportEdge>,
    /// All imported module and symbol names (including `if TYPE_CHECKING:`).
    all_imports: Vec<PyImportEdge>,
    /// Public top-level declarations eligible for `py-arch-no-unused-exports`.
    public_exports: Vec<PyExportSymbol>,
    /// Explicitly listed symbol names in `__all__ = [...]`.
    pub dunder_all: HashSet<String>,
    /// All identifier and attribute names referenced anywhere in this file.
    pub referenced_names: HashSet<String>,
    /// Unawaited call sites inside this file that may target an `async def` imported from another module.
    pub potential_unawaited_calls: Vec<PyUnawaitedCallCandidate>,
}

/// An `import ...` or `from ... import ...` statement in a Python module.
#[derive(Debug, Clone)]
struct PyImportEdge {
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
struct PyExportSymbol {
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
    evaluate_architecture_file_rules(package, files, enabled_rules, diagnostics);
    evaluate_prefer_fluent_builder_rule(package, files, enabled_rules, diagnostics);

    if files.len() < 2 {
        return;
    }

    evaluate_duplicated_helper_logic_rule(package, files, enabled_rules, diagnostics);

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
    let mut ref_file_counts: HashMap<&str, usize> = HashMap::new();
    let mut file_irs: Vec<Option<&PyFileIr>> = Vec::with_capacity(files.len());

    for (u, file) in files.iter().enumerate() {
        let ir = file.downcast_payload::<PyFileIr>();
        if let Some(py_ir) = ir {
            for name in &py_ir.module_graph.referenced_names {
                *ref_file_counts.entry(name.as_str()).or_insert(0) += 1;
            }
            collect_star_imported_targets(
                u,
                file,
                &py_ir.module_graph.all_imports,
                files,
                &module_index,
                &mut star_imported_modules,
            );
        }
        file_irs.push(ir);
    }

    for (idx, file) in files.iter().enumerate() {
        if star_imported_modules.contains(&idx)
            || is_entrypoint_or_test_module(&file.path, file.file_context)
        {
            continue;
        }
        let Some(ir) = file_irs[idx] else {
            continue;
        };

        for export in &ir.module_graph.public_exports {
            if export.has_registration_decorator
                || ir.module_graph.dunder_all.contains(&export.name)
            {
                continue;
            }
            let total_files_referencing = ref_file_counts
                .get(export.name.as_str())
                .copied()
                .unwrap_or(0);
            let self_references = usize::from(
                ir.module_graph
                    .referenced_names
                    .contains(export.name.as_str()),
            );
            if total_files_referencing > self_references {
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

fn evaluate_architecture_file_rules(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for file in files {
        if package
            .config
            .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        evaluate_thin_entrypoint_rule(package, file, enabled_rules, diagnostics);
        evaluate_mixed_io_and_presentation_rule(package, file, enabled_rules, diagnostics);
        evaluate_separate_static_catalog_from_types_rule(package, file, enabled_rules, diagnostics);
        evaluate_mixed_domain_monolith_rule(package, file, enabled_rules, diagnostics);
        evaluate_inline_terminal_ui_primitives_rule(package, file, enabled_rules, diagnostics);
    }
}

fn evaluate_thin_entrypoint_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let facets = &file.architecture_facets;
    if !facets.is_entrypoint {
        return;
    }
    let has_domain_types = facets.has_bucket(ConcernBucket::TypeDefinitions);
    let has_io = facets.has_bucket(ConcernBucket::DataOrNetworkIo);
    let has_entrypoint_loop = facets
        .signals_for_bucket(ConcernBucket::EntrypointAdapter)
        .iter()
        .any(|s| s.detail == "entrypoint-domain-loop");
    let max_stmts = package.config.architecture.max_entrypoint_statements;
    let exceeds_statements = facets.entrypoint_statement_count > max_stmts;
    let embeds_loop_queries = has_entrypoint_loop && has_io && max_stmts <= 25;

    if !(has_domain_types && has_io) && !embeds_loop_queries && !exceeds_statements {
        return;
    }

    let (subject_name, span, loc) = resolve_entrypoint_anchor(file);
    if is_file_level_rule_suppressed(package, file, RuleId::ArchThinEntrypoint, loc, span) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchThinEntrypoint,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("main.py")
        .to_string();
    let mut cascade_steps = Vec::new();
    if has_domain_types && has_io {
        cascade_steps
            .push("concern: type-definitions + data-or-network-io in entrypoint".to_string());
    }
    if embeds_loop_queries {
        cascade_steps.push("concern: entrypoint-domain-loop + data-or-network-io".to_string());
    }
    if exceeds_statements {
        cascade_steps.push(format!(
            "entrypoint_statements={} > max_entrypoint_statements={max_stmts}",
            facets.entrypoint_statement_count
        ));
    }
    let msg = if has_domain_types && has_io {
        format!(
            "Python entrypoint `{target_name}` defines domain/ORM/Pydantic classes and executes direct I/O queries instead of delegating to an imported library runner function."
        )
    } else if embeds_loop_queries {
        format!(
            "Python entrypoint `{target_name}` embeds a domain loop executing direct I/O queries instead of delegating to an imported library runner function."
        )
    } else {
        format!(
            "Python entrypoint `{target_name}` contains {} statements (threshold: {max_stmts}) instead of delegating to a thin library runner function.",
            facets.entrypoint_statement_count
        )
    };

    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchThinEntrypoint,
            file.path.clone(),
            loc,
            span,
            msg,
        )
        .with_subject(subject_name)
        .with_severity(effective_sev)
        .with_message_id("archThinEntrypoint")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_mixed_io_and_presentation_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let respect_disables = package.config.respect_inline_disables;
    let io_signals: Vec<_> = facets
        .signals_for_bucket(ConcernBucket::DataOrNetworkIo)
        .into_iter()
        .filter(|s| {
            !respect_disables
                || !file.is_suppressed(RuleId::ArchNoMixedIoAndPresentation, s.loc.line, s.span)
        })
        .collect();
    let ui_signals: Vec<_> = facets
        .signals_for_bucket(ConcernBucket::TerminalOrUiPresentation)
        .into_iter()
        .filter(|s| {
            !s.detail.starts_with("import ")
                && (!respect_disables
                    || !file.is_suppressed(
                        RuleId::ArchNoMixedIoAndPresentation,
                        s.loc.line,
                        s.span,
                    ))
        })
        .collect();
    if io_signals.is_empty() || ui_signals.is_empty() {
        return;
    }

    let primary_sig = ui_signals[0];
    let span = primary_sig.span;
    let loc = primary_sig.loc;
    let subject_name = enclosing_subject_for_span(file, span);

    if is_file_level_rule_suppressed(
        package,
        file,
        RuleId::ArchNoMixedIoAndPresentation,
        loc,
        span,
    ) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchNoMixedIoAndPresentation,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("module.py")
        .to_string();
    let io_detail = &io_signals[0].detail;
    let ui_detail = &ui_signals[0].detail;
    let cascade_steps = vec![
        format!("data-or-network-io: {io_detail}"),
        format!("terminal-or-ui-presentation: {ui_detail}"),
    ];

    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchNoMixedIoAndPresentation,
            file.path.clone(),
            loc,
            span,
            format!(
                "Module `{target_name}` mixes data/network/file I/O (`{io_detail}`) with terminal or UI presentation (`{ui_detail}`); separate I/O adapters from presentation rendering."
            ),
        )
        .with_subject(subject_name)
        .with_severity(effective_sev)
        .with_message_id("archNoMixedIoAndPresentation")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_separate_static_catalog_from_types_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let min_types = package.config.architecture.min_types_with_catalog;
    let min_entries = package.config.architecture.min_static_catalog_entries;
    if facets.public_type_count < min_types {
        return;
    }
    let Some(catalog) = facets
        .static_catalog_sites
        .iter()
        .find(|c| c.entry_count >= min_entries)
    else {
        return;
    };

    if is_file_level_rule_suppressed(
        package,
        file,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        catalog.loc,
        catalog.span,
    ) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        enabled_rules,
        catalog.loc.line,
        catalog.span,
    ) else {
        return;
    };

    let cascade_steps = vec![
        format!("public_types={} >= {min_types}", facets.public_type_count),
        format!(
            "static_catalog={}: {} entries >= {min_entries}",
            catalog.name, catalog.entry_count
        ),
    ];
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchSeparateStaticCatalogFromTypes,
            file.path.clone(),
            catalog.loc,
            catalog.span,
            format!(
                "Module declares {} domain classes alongside static catalog `{}` ({} entries); extract static catalog data into a dedicated module.",
                facets.public_type_count, catalog.name, catalog.entry_count
            ),
        )
        .with_severity(effective_sev)
        .with_message_id("archSeparateStaticCatalogFromTypes")
        .with_target_name(catalog.name.clone())
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_mixed_domain_monolith_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    let top_level_symbols = file
        .symbol_outlines
        .iter()
        .filter(|s| s.parent_name.is_none())
        .count();
    let min_symbols = package.config.architecture.min_monolith_symbols;
    let min_clusters = package.config.architecture.min_monolith_domain_clusters;
    let buckets = facets.distinct_concern_buckets();
    if top_level_symbols < min_symbols || buckets.len() < min_clusters {
        return;
    }

    let (span, loc) = file.symbol_outlines.first().map_or(
        (
            ByteSpan {
                start: 0,
                end: u32::try_from(file.source.len()).unwrap_or(0),
            },
            SourceLoc { line: 1, column: 1 },
        ),
        |sym| (sym.span, sym.loc),
    );
    if is_file_level_rule_suppressed(package, file, RuleId::ArchNoMixedDomainMonolith, loc, span) {
        return;
    }
    let Some(effective_sev) = resolve_active_py_rule_severity(
        package,
        file,
        RuleId::ArchNoMixedDomainMonolith,
        enabled_rules,
        loc.line,
        span,
    ) else {
        return;
    };

    let target_name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("module.py")
        .to_string();
    let bucket_names: Vec<&str> = buckets.iter().map(|b| b.as_str()).collect();
    let cascade_steps = vec![
        format!("top_level_symbols={top_level_symbols} >= {min_symbols}"),
        format!("concern_buckets=[{}]", bucket_names.join(", ")),
    ];
    diagnostics.push(
        Diagnostic::for_rule(
            RuleId::ArchNoMixedDomainMonolith,
            file.path.clone(),
            loc,
            span,
            format!(
                "Monolithic module `{target_name}` combines {top_level_symbols} top-level symbols across {} orthogonal concern buckets ({}); decompose into focused domain submodules.",
                buckets.len(),
                bucket_names.join(", ")
            ),
        )
        .with_severity(effective_sev)
        .with_message_id("archNoMixedDomainMonolith")
        .with_target_name(target_name)
        .with_cascade_steps(cascade_steps),
    );
}

fn evaluate_inline_terminal_ui_primitives_rule(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if file.file_context != FileContext::Production {
        return;
    }
    let facets = &file.architecture_facets;
    if facets.is_ui_kit_module {
        return;
    }
    for site in &facets.inline_terminal_ui_sites {
        let Some(effective_sev) = resolve_active_py_rule_severity(
            package,
            file,
            RuleId::ArchNoInlineTerminalUiPrimitives,
            enabled_rules,
            site.loc.line,
            site.span,
        ) else {
            continue;
        };
        let subject_name = enclosing_subject_for_span(file, site.span);
        diagnostics.push(
            Diagnostic::for_rule(
                RuleId::ArchNoInlineTerminalUiPrimitives,
                file.path.clone(),
                site.loc,
                site.span,
                format!(
                    "Inline terminal UI primitive (`{}`) used outside a dedicated `ui.py` / `console.py` / `terminal.py` module; extract into a shared terminal UI helper.",
                    site.kind
                ),
            )
            .with_subject(subject_name)
            .with_severity(effective_sev)
            .with_message_id("archNoInlineTerminalUiPrimitives")
            .with_target_name(site.kind.as_str().to_string()),
        );
    }
}

fn evaluate_duplicated_helper_logic_rule(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let min_stmts = package.config.architecture.min_helper_statements;
    let min_modules = package.config.architecture.min_duplicated_helper_modules;

    let mut by_hash: BTreeMap<u64, Vec<(usize, &HelperFingerprintIr, RuleSeverity)>> =
        BTreeMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for helper in &file.architecture_facets.helper_fingerprints {
            if !helper.is_private || helper.statement_count < min_stmts {
                continue;
            }
            let Some(sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::ArchNoDuplicatedHelperLogic,
                enabled_rules,
                helper.loc.line,
                helper.span,
            ) else {
                continue;
            };
            by_hash
                .entry(helper.normalized_hash)
                .or_default()
                .push((file_idx, helper, sev));
        }
    }

    for (hash, sites) in by_hash {
        let distinct_modules: BTreeSet<usize> = sites.iter().map(|(idx, _, _)| *idx).collect();
        if distinct_modules.len() < min_modules {
            continue;
        }
        let primary_target_name = sites[0].1.name.clone();
        for (site_pos, &(file_idx, helper, sev)) in sites.iter().enumerate() {
            let file = &files[file_idx];
            let caller_sites: Vec<ResolvedCallerSite> = sites
                .iter()
                .enumerate()
                .filter(|&(other_pos, _)| other_pos != site_pos)
                .map(
                    |(_, &(other_file_idx, other_helper, _))| ResolvedCallerSite {
                        caller_file: files[other_file_idx].path.clone(),
                        parent_subject_name: Some(other_helper.name.clone()),
                        component_name: other_helper.name.clone(),
                        loc: other_helper.loc,
                        span: other_helper.span,
                        has_key: false,
                        passed_props: Vec::new(),
                    },
                )
                .collect();
            let peer_files: Vec<String> = caller_sites
                .iter()
                .map(|c| format!("{}:{}", c.caller_file.display(), c.loc.line))
                .collect();
            let cascade_steps = vec![
                format!(
                    "normalized_hash=0x{hash:08x}, statements={} >= {min_stmts}",
                    helper.statement_count
                ),
                format!("peer_modules=[{}]", peer_files.join(", ")),
            ];
            diagnostics.push(
                Diagnostic::for_rule(
                    RuleId::ArchNoDuplicatedHelperLogic,
                    file.path.clone(),
                    helper.loc,
                    helper.span,
                    format!(
                        "Private helper `{}` ({} statements, hash `0x{hash:08x}`) duplicates normalized AST logic across {} sibling modules ({}); extract into a shared internal utility module.",
                        helper.name,
                        helper.statement_count,
                        distinct_modules.len(),
                        peer_files.join(", ")
                    ),
                )
                .with_subject(Some(helper.name.clone()))
                .with_severity(sev)
                .with_message_id("archNoDuplicatedHelperLogic")
                .with_target_name(primary_target_name.clone())
                .with_caller_sites(caller_sites)
                .with_cascade_steps(cascade_steps),
            );
        }
    }
}

fn evaluate_prefer_fluent_builder_rule(
    package: &WorkspacePackage,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let min_fields = package.config.architecture.min_builder_fields;
    let min_sites = package.config.architecture.min_builder_sites;

    let mut defined_builders: HashSet<&str> = HashSet::new();
    for file in files {
        for builder_type in &file.architecture_facets.defined_builder_types {
            defined_builders.insert(builder_type.as_str());
        }
    }

    let mut by_type: BTreeMap<
        String,
        Vec<(usize, &StructLiteralConstructionSiteIr, RuleSeverity)>,
    > = BTreeMap::new();

    for (file_idx, file) in files.iter().enumerate() {
        if file.file_context != FileContext::Production
            || package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
        {
            continue;
        }
        for site in &file.architecture_facets.struct_literal_sites {
            if defined_builders.contains(site.type_name.as_str()) {
                continue;
            }
            if site.field_names.len() < min_fields || site.default_or_literal_fields.is_empty() {
                continue;
            }
            let Some(sev) = resolve_active_py_rule_severity(
                package,
                file,
                RuleId::ArchPreferFluentBuilder,
                enabled_rules,
                site.loc.line,
                site.span,
            ) else {
                continue;
            };
            by_type
                .entry(site.type_name.clone())
                .or_default()
                .push((file_idx, site, sev));
        }
    }

    for (type_name, sites) in by_type {
        if sites.len() < min_sites {
            continue;
        }
        let mut default_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for &(_, site, _) in &sites {
            let unique_defaults: BTreeSet<&str> = site
                .default_or_literal_fields
                .iter()
                .map(String::as_str)
                .collect();
            for field in unique_defaults {
                *default_field_counts.entry(field).or_insert(0) += 1;
            }
        }
        let overlapping_defaults: Vec<&str> = default_field_counts
            .into_iter()
            .filter_map(|(field, count)| (count >= 2).then_some(field))
            .collect();
        if overlapping_defaults.len() < 2 {
            continue;
        }
        let qualifying_sites: Vec<(usize, &StructLiteralConstructionSiteIr, RuleSeverity)> = sites
            .into_iter()
            .filter(|(_, s, _)| {
                s.default_or_literal_fields
                    .iter()
                    .filter(|f| overlapping_defaults.contains(&f.as_str()))
                    .count()
                    >= 2
            })
            .collect();
        if qualifying_sites.len() < min_sites {
            continue;
        }
        for (site_pos, &(file_idx, site, sev)) in qualifying_sites.iter().enumerate() {
            let file = &files[file_idx];
            let subject_name = enclosing_subject_for_span(file, site.span);
            let caller_sites: Vec<ResolvedCallerSite> = qualifying_sites
                .iter()
                .enumerate()
                .filter(|&(other_pos, _)| other_pos != site_pos)
                .map(|(_, &(other_file_idx, other_site, _))| ResolvedCallerSite {
                    caller_file: files[other_file_idx].path.clone(),
                    parent_subject_name: enclosing_subject_for_span(
                        &files[other_file_idx],
                        other_site.span,
                    ),
                    component_name: type_name.clone(),
                    loc: other_site.loc,
                    span: other_site.span,
                    has_key: false,
                    passed_props: other_site.field_names.clone(),
                })
                .collect();
            let cascade_steps = vec![
                format!(
                    "type={type_name}, fields={} >= {min_fields}, sites={} >= {min_sites}",
                    site.field_names.len(),
                    qualifying_sites.len()
                ),
                format!(
                    "default_or_literal_fields=[{}]",
                    site.default_or_literal_fields.join(", ")
                ),
            ];
            diagnostics.push(
                Diagnostic::for_rule(
                    RuleId::ArchPreferFluentBuilder,
                    file.path.clone(),
                    site.loc,
                    site.span,
                    format!(
                        "`{type_name}(...)` is constructed across {} call sites with {} keyword arguments including boilerplate defaults (`{}`); define a `{type_name}Builder`, `{type_name}.from_defaults(...)`, or `build_*` factory.",
                        qualifying_sites.len(),
                        site.field_names.len(),
                        overlapping_defaults.join(", ")
                    ),
                )
                .with_subject(subject_name)
                .with_severity(sev)
                .with_message_id("archPreferFluentBuilder")
                .with_target_name(type_name.clone())
                .with_caller_sites(caller_sites)
                .with_cascade_steps(cascade_steps),
            );
        }
    }
}

fn resolve_entrypoint_anchor(file: &ExtractedFile) -> (Option<String>, ByteSpan, SourceLoc) {
    if let Some((subj, span, loc)) = file
        .subject_spans
        .iter()
        .find(|(name, _, _)| matches!(name.as_deref(), Some("main" | "cli" | "run")))
    {
        return (subj.clone(), *span, *loc);
    }
    if let Some(sig) = file
        .architecture_facets
        .signals_for_bucket(ConcernBucket::EntrypointAdapter)
        .first()
    {
        return (None, sig.span, sig.loc);
    }
    if let Some(first_sym) = file.symbol_outlines.first() {
        return (None, first_sym.span, first_sym.loc);
    }
    (
        None,
        ByteSpan {
            start: 0,
            end: u32::try_from(file.source.len()).unwrap_or(0),
        },
        SourceLoc { line: 1, column: 1 },
    )
}

fn enclosing_subject_for_span(file: &ExtractedFile, span: ByteSpan) -> Option<String> {
    file.subject_spans
        .iter()
        .filter(|(_, s, _)| s.start <= span.start && span.end <= s.end)
        .min_by_key(|(_, s, _)| s.end.saturating_sub(s.start))
        .and_then(|(name, _, _)| name.clone())
}

fn is_file_level_rule_suppressed(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    rule: RuleId,
    loc: SourceLoc,
    span: ByteSpan,
) -> bool {
    if !package.config.respect_inline_disables {
        return false;
    }
    let first_code_line = file.symbol_outlines.first().map_or(1, |s| s.loc.line);
    if file.suppressions.matches_line_or_block(rule, 1)
        || file.suppressions.matches_line_or_block(rule, 2)
        || file.suppressions.matches_line_or_block(rule, 3)
        || file
            .suppressions
            .matches_line_or_block(rule, first_code_line)
        || file.is_suppressed(rule, loc.line, span)
    {
        return true;
    }
    let enclosing_subj_span = file
        .subject_spans
        .iter()
        .filter(|(_, s, _)| s.start <= span.start && span.end <= s.end)
        .min_by_key(|(_, s, _)| s.end.saturating_sub(s.start))
        .map(|(_, s, _)| *s);
    file.suppressions.line_directives.iter().any(|d| {
        if d.rules.is_empty() || !dotore_core::rule_list_matches(&d.rules, rule) {
            return false;
        }
        if d.target_line <= 3 {
            return true;
        }
        if let Some(subj_span) = enclosing_subj_span
            && let Some(ir) = file.downcast_payload::<PyFileIr>()
        {
            let subj_start =
                dotore_core::loc_from_line_starts(&ir.line_starts, subj_span.start).line;
            let subj_end = dotore_core::loc_from_line_starts(
                &ir.line_starts,
                subj_span.end.saturating_sub(1).max(subj_span.start),
            )
            .line;
            return d.target_line >= subj_start && d.target_line <= subj_end;
        }
        false
    })
}
