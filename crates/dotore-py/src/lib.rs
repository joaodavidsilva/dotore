//! Single-pass Python static analyzer (`PyLanguageAnalyzer`), `pyproject.toml` / `requirements.txt`
//! **Capability Gate** inference, and Python runtime and resource safety rules.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use dotore_core::{
    AutofixPatch, BlockDisableRange, ByteEdit, ByteSpan, Capability, CapabilityGate,
    ContextualOwnerSpansIr, Diagnostic, ExtractedFile, FileContext, FileSuppressions,
    LanguageAnalyzer, LanguageId, LineDisableDirective, PackageAnalysisResult, RuleId, RuleTag,
    SourceLoc, SymbolKind, SymbolOutline, WorkspacePackage, compute_line_starts,
    loc_from_line_starts,
};
use ruff_python_ast::{
    CmpOp, Expr, ExprCall, ExprSubscript, ModModule, ParameterWithDefault, PySourceType, Stmt,
    StmtClassDef, StmtFunctionDef, UnaryOp, token::TokenKind,
};
use ruff_python_parser::{Parsed, parse_unchecked_source};
use ruff_text_size::Ranged;

mod web_orm_security;
pub(crate) mod async_perf_arch;
pub(crate) mod graph;

/// Single-pass intermediate representation for a Python source file (`.py` or `.pyi`).
#[derive(Debug, Clone)]
pub struct PyFileIr {
    /// Whether the file parsed without syntax errors.
    pub valid_syntax: bool,
    /// Precomputed 0-based byte offsets of each line start.
    pub line_starts: Vec<u32>,
    /// Pre-evaluated candidate rule diagnostics for all 5 core Python safety rules.
    pub candidate_diagnostics: Vec<Diagnostic>,
    /// Cross-file module import/export graph metadata for `py-arch-*` rules.
    pub(crate) module_graph: graph::PyModuleGraphInfo,
}

/// Python [`LanguageAnalyzer`] powered by `ruff_python_parser`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PyLanguageAnalyzer;

impl PyLanguageAnalyzer {
    /// Creates a new [`PyLanguageAnalyzer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageAnalyzer for PyLanguageAnalyzer {
    fn language_id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn supports_path(&self, path: &Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("py" | "pyi")
        )
    }

    fn manifest_filenames(&self) -> &'static [&'static str] {
        &["pyproject.toml", "requirements.txt"]
    }

    fn infer_capability_gate(
        &self,
        package_dir: &Path,
        manifest_sources: &[(PathBuf, &str)],
    ) -> CapabilityGate {
        if manifest_sources.is_empty() {
            return CapabilityGate::default_python();
        }
        let mut gate = CapabilityGate::with_capabilities([Capability::Python]);
        let mut visited_req_files = HashSet::new();

        for (manifest_path, content) in manifest_sources {
            let file_name = manifest_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if file_name == "pyproject.toml" {
                infer_from_pyproject_toml(content, &mut gate);
            } else if file_name == "requirements.txt" || file_name.ends_with(".txt") {
                visited_req_files.insert(manifest_path.clone());
                infer_from_requirements_txt(
                    package_dir,
                    content,
                    manifest_sources,
                    &mut visited_req_files,
                    &mut gate,
                );
            }
        }

        gate
    }

    fn extract_file(&self, path: &Path, source: &str) -> ExtractedFile {
        let source_type = PySourceType::from(path);
        let parsed: Parsed<ModModule> = parse_unchecked_source(source, source_type);
        let valid_syntax = parsed.has_valid_syntax();
        let line_starts = compute_line_starts(source);
        let lines: Vec<&str> = source.lines().collect();

        let suppressions = extract_python_suppressions(source, &lines, &line_starts, &parsed);

        let is_stub_file = path.extension().and_then(|e| e.to_str()) == Some("pyi");
        let mut extractor = PyAstExtractor {
            path,
            source,
            lines: &lines,
            line_starts: &line_starts,
            is_stub_file,
            symbol_outlines: Vec::new(),
            subject_spans: Vec::new(),
            contextual_owner_spans: ContextualOwnerSpansIr::default(),
            candidate_diagnostics: Vec::new(),
            class_stack: Vec::new(),
            subject_stack: Vec::new(),
            finally_closed_vars: vec![collect_finally_closed_vars(parsed.suite())],
            caught_exception_stack: Vec::new(),
            guarded_numeric_vars: vec![HashSet::new()],
            guarded_dict_keys: vec![HashSet::new()],
            in_with_context_expr: false,
            in_return_or_yield: false,
            assigned_var_name: None,
        };
        extractor.extract_suite(parsed.suite(), true);
        web_orm_security::extract_web_orm_security_diagnostics(
            path,
            source,
            &lines,
            &line_starts,
            is_stub_file,
            parsed.suite(),
            &mut extractor.candidate_diagnostics,
        );
        let mut potential_unawaited_calls = Vec::new();
        async_perf_arch::extract_async_and_perf_diagnostics(
            path,
            source,
            &line_starts,
            is_stub_file,
            parsed.suite(),
            &mut extractor.candidate_diagnostics,
            &mut potential_unawaited_calls,
        );
        let subjects_count = extractor.subject_spans.len();
        let symbol_outlines = extractor.symbol_outlines;
        let subject_spans = extractor.subject_spans;
        let contextual_owner_spans = extractor.contextual_owner_spans;
        let candidate_diagnostics = extractor.candidate_diagnostics;
        let mut module_graph = graph::extract_module_graph_info(
            path,
            source,
            &line_starts,
            is_stub_file,
            parsed.suite(),
            &symbol_outlines,
        );
        module_graph.potential_unawaited_calls = potential_unawaited_calls;
        let ir = PyFileIr {
            valid_syntax,
            line_starts,
            candidate_diagnostics,
            module_graph,
        };

        let mut extracted =
            ExtractedFile::new(path.to_path_buf(), source.to_string(), LanguageId::Python);
        extracted.symbol_outlines = symbol_outlines;
        extracted.contextual_owner_spans = contextual_owner_spans;
        extracted.suppressions = suppressions;
        extracted.subjects_count = subjects_count;
        extracted.subject_spans = subject_spans;
        extracted.with_payload(ir)
    }

    fn analyze_package(
        &self,
        package: &WorkspacePackage,
        files: &[ExtractedFile],
        enabled_rules: Option<&[RuleId]>,
    ) -> PackageAnalysisResult {
        let mut diagnostics = Vec::new();
        let mut subjects_scanned = 0;

        for file in files {
            if package
                .config
                .is_file_ignored(&file.path, &package.root_dir)
            {
                continue;
            }
            subjects_scanned += file.subjects_count;
            let Some(ir) = file.downcast_payload::<PyFileIr>() else {
                continue;
            };
            for candidate in &ir.candidate_diagnostics {
                if let Some(allowed) = enabled_rules
                    && !allowed.contains(&candidate.rule)
                {
                    continue;
                }
                if package.config.is_overridden_for_file(
                    candidate.rule,
                    &file.path,
                    &package.root_dir,
                ) {
                    continue;
                }
                let meta = candidate.rule.metadata();
                if !graph::gate_allows_py_rule(package, candidate.rule) {
                    continue;
                }
                if enabled_rules.is_none()
                    && file.file_context != FileContext::Production
                    && meta.tags.contains(&RuleTag::TestNoise)
                    && !meta.tags.contains(&RuleTag::MigrationHint)
                    && package.config.explicit_rule_override(candidate.rule).is_none()
                {
                    continue;
                }
                let Some(effective_sev) = package.config.effective_severity(candidate.rule) else {
                    continue;
                };
                if package.config.respect_inline_disables
                    && file.is_suppressed(candidate.rule, candidate.loc.line, candidate.span)
                {
                    continue;
                }
                let mut diag = candidate.clone();
                diag.severity = effective_sev;
                diagnostics.push(diag);
            }
        }
        graph::evaluate_package_graph_rules(package, files, enabled_rules, &mut diagnostics);

        PackageAnalysisResult {
            diagnostics,
            subjects_scanned,
            effects_scanned: 0,
        }
    }

    fn validate_syntax(&self, path: &Path, source: &str) -> bool {
        let source_type = PySourceType::from(path);
        parse_unchecked_source(source, source_type).has_valid_syntax()
    }
}

fn infer_from_pyproject_toml(content: &str, gate: &mut CapabilityGate) {
    let Ok(doc) = toml::from_str::<toml::Value>(content) else {
        return;
    };

    // [project]
    if let Some(project) = doc.get("project").and_then(toml::Value::as_table) {
        if let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array) {
            for dep in deps.iter().filter_map(toml::Value::as_str) {
                record_pep508_dependency(dep, gate);
            }
        }
        if let Some(opt_deps) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for group_deps in opt_deps.values().filter_map(toml::Value::as_array) {
                for dep in group_deps.iter().filter_map(toml::Value::as_str) {
                    record_pep508_dependency(dep, gate);
                }
            }
        }
    }

    // [dependency-groups] (PEP 735)
    if let Some(dep_groups) = doc.get("dependency-groups").and_then(toml::Value::as_table) {
        for group_deps in dep_groups.values().filter_map(toml::Value::as_array) {
            for item in group_deps {
                if let Some(dep_str) = item.as_str() {
                    record_pep508_dependency(dep_str, gate);
                }
            }
        }
    }

    // [build-system.requires]
    if let Some(requires) = doc
        .get("build-system")
        .and_then(toml::Value::as_table)
        .and_then(|bs| bs.get("requires"))
        .and_then(toml::Value::as_array)
    {
        for dep in requires.iter().filter_map(toml::Value::as_str) {
            record_pep508_dependency(dep, gate);
        }
    }

    // [tool.*]
    if let Some(tool) = doc.get("tool").and_then(toml::Value::as_table) {
        if let Some(pytest_tbl) = tool.get("pytest").and_then(toml::Value::as_table) {
            gate.capabilities.insert(Capability::Pytest);
            if pytest_tbl
                .get("ini_options")
                .and_then(toml::Value::as_table)
                .is_some_and(|ini| ini.contains_key("asyncio_mode"))
            {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        if tool.contains_key("django") {
            gate.capabilities.insert(Capability::Django);
        }
        if let Some(poetry) = tool.get("poetry").and_then(toml::Value::as_table) {
            infer_from_poetry_table(poetry, gate);
        }
        if let Some(uv) = tool.get("uv").and_then(toml::Value::as_table)
            && let Some(dev_deps) = uv.get("dev-dependencies").and_then(toml::Value::as_array)
        {
            for dep in dev_deps.iter().filter_map(toml::Value::as_str) {
                record_pep508_dependency(dep, gate);
            }
        }
        if let Some(pdm) = tool.get("pdm").and_then(toml::Value::as_table)
            && let Some(dev_deps) = pdm.get("dev-dependencies").and_then(toml::Value::as_table)
        {
            for group_deps in dev_deps.values().filter_map(toml::Value::as_array) {
                for dep in group_deps.iter().filter_map(toml::Value::as_str) {
                    record_pep508_dependency(dep, gate);
                }
            }
        }
    }
}

fn infer_from_poetry_table(poetry: &toml::map::Map<String, toml::Value>, gate: &mut CapabilityGate) {
    for section in ["dependencies", "dev-dependencies"] {
        if let Some(deps_tbl) = poetry.get(section).and_then(toml::Value::as_table) {
            for (pkg_name, spec) in deps_tbl {
                record_poetry_dependency(pkg_name, spec, gate);
            }
        }
    }
    let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) else {
        return;
    };
    for group_val in groups.values().filter_map(toml::Value::as_table) {
        let Some(deps_tbl) = group_val.get("dependencies").and_then(toml::Value::as_table) else {
            continue;
        };
        for (pkg_name, spec) in deps_tbl {
            record_poetry_dependency(pkg_name, spec, gate);
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only string and table dependency specifications carry version/extras metadata"
)]
fn record_poetry_dependency(pkg_name: &str, spec: &toml::Value, gate: &mut CapabilityGate) {
    let mut extras = Vec::new();
    let version = match spec {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(tbl) => {
            if let Some(ext_arr) = tbl.get("extras").and_then(toml::Value::as_array) {
                for ext in ext_arr.iter().filter_map(toml::Value::as_str) {
                    extras.push(ext.to_ascii_lowercase());
                }
            }
            tbl.get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("*")
                .to_string()
        }
        _ => "*".to_string(),
    };
    apply_python_dependency_capabilities(pkg_name, &extras, &version, gate);
}

fn infer_from_requirements_txt(
    package_dir: &Path,
    content: &str,
    manifest_sources: &[(PathBuf, &str)],
    visited: &mut HashSet<PathBuf>,
    gate: &mut CapabilityGate,
) {
    for raw_line in content.lines() {
        let without_comment = raw_line.split('#').next().unwrap_or("").trim();
        if without_comment.is_empty() {
            continue;
        }
        if let Some(included_rel) = without_comment
            .strip_prefix("-r ")
            .or_else(|| without_comment.strip_prefix("--requirement "))
            .map(str::trim)
        {
            let inc_path = package_dir.join(included_rel);
            if visited.insert(inc_path.clone()) {
                if let Some((_, inc_src)) = manifest_sources
                    .iter()
                    .find(|(p, _)| p == &inc_path || p.ends_with(included_rel))
                {
                    infer_from_requirements_txt(
                        package_dir,
                        inc_src,
                        manifest_sources,
                        visited,
                        gate,
                    );
                } else if let Ok(disk_src) = fs::read_to_string(&inc_path) {
                    infer_from_requirements_txt(
                        package_dir,
                        &disk_src,
                        manifest_sources,
                        visited,
                        gate,
                    );
                }
            }
            continue;
        }
        if without_comment.starts_with('-') {
            if let Some(idx) = without_comment.find("#egg=") {
                let egg = &without_comment[idx + 5..];
                record_pep508_dependency(egg, gate);
            }
            continue;
        }
        record_pep508_dependency(without_comment, gate);
    }
}

fn record_pep508_dependency(raw_spec: &str, gate: &mut CapabilityGate) {
    let before_marker = raw_spec.split(';').next().unwrap_or("").trim();
    if before_marker.is_empty() {
        return;
    }

    // Separate package name, optional `[extras]`, and version specifier
    let (name_and_extras, version_part) = split_pep508_name_and_version(before_marker);
    let (raw_name, extras) = if let Some(bracket_start) = name_and_extras.find('[') {
        let name = name_and_extras[..bracket_start].trim();
        let extras_str = name_and_extras[bracket_start + 1..]
            .split(']')
            .next()
            .unwrap_or("");
        let parsed_extras: Vec<String> = extras_str
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        (name, parsed_extras)
    } else {
        (name_and_extras.trim(), Vec::new())
    };

    if raw_name.is_empty() {
        return;
    }
    let version = if version_part.is_empty() {
        "*"
    } else {
        version_part
    };
    apply_python_dependency_capabilities(raw_name, &extras, version, gate);
}

fn split_pep508_name_and_version(spec: &str) -> (&str, &str) {
    let mut in_brackets = false;
    for (idx, ch) in spec.char_indices() {
        match ch {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            '=' | '<' | '>' | '!' | '~' | '@' | ' ' | '\t' if !in_brackets => {
                return (spec[..idx].trim(), spec[idx..].trim());
            }
            _ => {}
        }
    }
    (spec.trim(), "")
}

fn normalize_python_pkg_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        if ch == '_' || ch == '-' || ch == '.' {
            if !prev_dash && !normalized.is_empty() {
                normalized.push('-');
                prev_dash = true;
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    while normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

fn apply_python_dependency_capabilities(
    raw_name: &str,
    extras: &[String],
    version: &str,
    gate: &mut CapabilityGate,
) {
    let norm = normalize_python_pkg_name(raw_name);
    if norm.is_empty() || norm == "python" {
        return;
    }
    gate.dependencies
        .insert(norm.clone(), version.trim().to_string());

    match norm.as_str() {
        "fastapi" => {
            gate.capabilities.insert(Capability::FastApi);
            gate.capabilities.insert(Capability::Pydantic);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "pydantic" | "pydantic-settings" | "pydantic-core" | "pydantic-extra-types" => {
            gate.capabilities.insert(Capability::Pydantic);
        }
        "sqlmodel" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            gate.capabilities.insert(Capability::Pydantic);
        }
        "sqlalchemy" | "flask-sqlalchemy" | "alembic" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            if extras.iter().any(|e| e == "asyncio") {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        "asyncpg" | "aiosqlite" | "aiomysql" | "aiopg" => {
            gate.capabilities.insert(Capability::SqlAlchemy);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "django" | "djangorestframework" | "django-ninja" | "django-environ" | "channels" => {
            gate.capabilities.insert(Capability::Django);
            if norm == "channels" || norm == "django-ninja" {
                gate.capabilities.insert(Capability::Asyncio);
            }
        }
        "pytest" | "pytest-cov" | "pytest-mock" | "pytest-xdist" => {
            gate.capabilities.insert(Capability::Pytest);
        }
        "pytest-asyncio" | "pytest-trio" => {
            gate.capabilities.insert(Capability::Pytest);
            gate.capabilities.insert(Capability::Asyncio);
        }
        "pytest-django" => {
            gate.capabilities.insert(Capability::Pytest);
            gate.capabilities.insert(Capability::Django);
        }
        "asyncio" | "aiohttp" | "httpx" | "uvicorn" | "starlette" | "anyio" | "trio" | "quart"
        | "sanic" | "litestar" | "motor" => {
            gate.capabilities.insert(Capability::Asyncio);
        }
        _ => {}
    }
}

struct PyAstExtractor<'a> {
    path: &'a Path,
    source: &'a str,
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    is_stub_file: bool,
    symbol_outlines: Vec<SymbolOutline>,
    subject_spans: Vec<(Option<String>, ByteSpan, SourceLoc)>,
    contextual_owner_spans: ContextualOwnerSpansIr,
    candidate_diagnostics: Vec<Diagnostic>,
    class_stack: Vec<String>,
    subject_stack: Vec<String>,
    finally_closed_vars: Vec<HashSet<String>>,
    caught_exception_stack: Vec<HashSet<String>>,
    guarded_numeric_vars: Vec<HashSet<String>>,
    guarded_dict_keys: Vec<HashSet<(String, String)>>,
    in_with_context_expr: bool,
    in_return_or_yield: bool,
    assigned_var_name: Option<String>,
}

impl<'a> PyAstExtractor<'a> {
    fn extract_suite(&mut self, suite: &[Stmt], is_module_top: bool) {
        self.guarded_numeric_vars.push(HashSet::new());
        self.guarded_dict_keys.push(HashSet::new());
        for stmt in suite {
            self.extract_stmt(stmt, is_module_top);
        }
        self.guarded_dict_keys.pop();
        self.guarded_numeric_vars.pop();
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Python Stmt enum has many variants; extractor inspects structural declarations and recurses into compound statements"
    )]
    fn extract_stmt(&mut self, stmt: &Stmt, is_module_or_class_scope: bool) {
        match stmt {
            Stmt::ClassDef(class_def) => self.extract_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.extract_function_def(func_def),
            Stmt::Assign(assign) => {
                if is_module_or_class_scope {
                    self.record_assign_symbol_outlines(assign);
                }
                let prev_assigned = self.assigned_var_name.take();
                self.assigned_var_name = assign.targets.first().and_then(extract_target_var_name);
                self.visit_expr(&assign.value);
                self.assigned_var_name = prev_assigned;
            }
            Stmt::AnnAssign(ann_assign) => {
                if is_module_or_class_scope
                    && let Expr::Name(name_expr) = ann_assign.target.as_ref()
                {
                    let span = text_range_to_byte_span(ann_assign.range());
                    let start_loc = loc_from_line_starts(self.line_starts, span.start);
                    let end_loc = loc_from_line_starts(
                        self.line_starts,
                        span.end.saturating_sub(1).max(span.start),
                    );
                    let sig = self
                        .lines
                        .get((start_loc.line.saturating_sub(1)) as usize)
                        .map(|l| l.trim().to_string())
                        .unwrap_or_default();
                    let (doc_comment, comment_start_line) =
                        extract_leading_hash_comment(self.lines, start_loc.line);
                    let parent_name = self.class_stack.last().cloned();
                    let name = name_expr.id.to_string();
                    let is_final = annotation_is_final(&ann_assign.annotation);
                    let kind = if is_upper_snake_case(&name) || is_final {
                        SymbolKind::Constant
                    } else {
                        SymbolKind::Variable
                    };
                    let name_span = text_range_to_byte_span(name_expr.range());
                    let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
                    self.symbol_outlines.push(SymbolOutline {
                        exported: !name.starts_with('_'),
                        name,
                        kind,
                        signature: sig,
                        doc_comment,
                        comment_start_line,
                        parent_name,
                        span,
                        signature_end_line: start_loc.line,
                        loc: name_loc,
                        end_line: end_loc.line,
                    });
                }
                if let Some(val) = &ann_assign.value {
                    let prev_assigned = self.assigned_var_name.take();
                    self.assigned_var_name = extract_target_var_name(&ann_assign.target);
                    self.visit_expr(val);
                    self.assigned_var_name = prev_assigned;
                }
            }
            Stmt::AugAssign(aug) => {
                self.visit_expr(&aug.value);
            }
            Stmt::Expr(expr_stmt) => {
                self.visit_expr(&expr_stmt.value);
            }
            Stmt::Return(ret_stmt) => {
                if let Some(val) = &ret_stmt.value {
                    let prev = self.in_return_or_yield;
                    self.in_return_or_yield = true;
                    self.visit_expr(val);
                    self.in_return_or_yield = prev;
                }
            }
            Stmt::Raise(raise_stmt) => {
                if let Some(exc) = &raise_stmt.exc {
                    self.visit_expr(exc);
                }
            }
            Stmt::Assert(assert_stmt) => {
                self.visit_expr(&assert_stmt.test);
                if let Some(msg) = &assert_stmt.msg {
                    self.visit_expr(msg);
                }
            }
            Stmt::If(if_stmt) => {
                self.visit_expr(&if_stmt.test);
                let (pos_num, pos_keys, neg_num, neg_keys) =
                    extract_if_guards(self.source, &if_stmt.test);
                self.guarded_numeric_vars.push(pos_num);
                self.guarded_dict_keys.push(pos_keys);
                self.extract_suite(&if_stmt.body, false);
                self.guarded_dict_keys.pop();
                self.guarded_numeric_vars.pop();

                for clause in &if_stmt.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.visit_expr(test);
                        let (c_pos_num, c_pos_keys, _, _) = extract_if_guards(self.source, test);
                        self.guarded_numeric_vars.push(c_pos_num);
                        self.guarded_dict_keys.push(c_pos_keys);
                        self.extract_suite(&clause.body, false);
                        self.guarded_dict_keys.pop();
                        self.guarded_numeric_vars.pop();
                    } else {
                        self.guarded_numeric_vars.push(neg_num.clone());
                        self.guarded_dict_keys.push(neg_keys.clone());
                        self.extract_suite(&clause.body, false);
                        self.guarded_dict_keys.pop();
                        self.guarded_numeric_vars.pop();
                    }
                }

                if suite_terminates_early(&if_stmt.body) {
                    if let Some(top_num) = self.guarded_numeric_vars.last_mut() {
                        top_num.extend(neg_num);
                    }
                    if let Some(top_keys) = self.guarded_dict_keys.last_mut() {
                        top_keys.extend(neg_keys);
                    }
                }
            }
            Stmt::For(for_stmt) => {
                self.visit_expr(&for_stmt.iter);
                self.extract_suite(&for_stmt.body, false);
                self.extract_suite(&for_stmt.orelse, false);
            }
            Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.extract_suite(&while_stmt.body, false);
                self.extract_suite(&while_stmt.orelse, false);
            }
            Stmt::With(with_stmt) => {
                let span = text_range_to_byte_span(with_stmt.range());
                self.contextual_owner_spans.element_spans.push(span);
                let prev_with = self.in_with_context_expr;
                self.in_with_context_expr = true;
                for item in &with_stmt.items {
                    self.visit_expr(&item.context_expr);
                }
                self.in_with_context_expr = prev_with;
                self.extract_suite(&with_stmt.body, false);
            }
            Stmt::Try(try_stmt) => {
                let span = text_range_to_byte_span(try_stmt.range());
                self.contextual_owner_spans.element_spans.push(span);
                let caught = collect_caught_exceptions(&try_stmt.handlers);
                self.caught_exception_stack.push(caught);
                self.extract_suite(&try_stmt.body, false);
                self.caught_exception_stack.pop();
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
                    self.check_except_handler(h);
                    self.extract_suite(&h.body, false);
                }
                self.extract_suite(&try_stmt.orelse, false);
                self.extract_suite(&try_stmt.finalbody, false);
            }
            Stmt::Match(match_stmt) => {
                self.visit_expr(&match_stmt.subject);
                for case in &match_stmt.cases {
                    if let Some(guard) = &case.guard {
                        self.visit_expr(guard);
                    }
                    self.extract_suite(&case.body, false);
                }
            }
            _ => {}
        }
    }

    fn record_assign_symbol_outlines(&mut self, assign: &ruff_python_ast::StmtAssign) {
        let span = text_range_to_byte_span(assign.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let end_loc = loc_from_line_starts(
            self.line_starts,
            span.end.saturating_sub(1).max(span.start),
        );
        let sig = self
            .lines
            .get((start_loc.line.saturating_sub(1)) as usize)
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        let (doc_comment, comment_start_line) =
            extract_leading_hash_comment(self.lines, start_loc.line);
        let parent_name = self.class_stack.last().cloned();

        for target in &assign.targets {
            let Expr::Name(name_expr) = target else {
                continue;
            };
            let name = name_expr.id.to_string();
            let kind = if is_upper_snake_case(&name) {
                SymbolKind::Constant
            } else {
                SymbolKind::Variable
            };
            let name_span = text_range_to_byte_span(name_expr.range());
            let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
            self.symbol_outlines.push(SymbolOutline {
                exported: !name.starts_with('_'),
                name,
                kind,
                signature: sig.clone(),
                doc_comment: doc_comment.clone(),
                comment_start_line,
                parent_name: parent_name.clone(),
                span,
                signature_end_line: start_loc.line,
                loc: name_loc,
                end_line: end_loc.line,
            });
        }
    }

    fn extract_class_def(&mut self, class_def: &StmtClassDef) {
        let span = text_range_to_byte_span(class_def.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let name_span = text_range_to_byte_span(class_def.name.range());
        let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
        let end_loc = loc_from_line_starts(
            self.line_starts,
            span.end.saturating_sub(1).max(span.start),
        );

        let class_name = class_def.name.to_string();
        let qualified_subject = if let Some(parent_cls) = self.class_stack.last() {
            format!("{parent_cls}.{class_name}")
        } else {
            class_name.clone()
        };

        self.subject_spans
            .push((Some(qualified_subject.clone()), span, start_loc));
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);
        self.contextual_owner_spans.element_spans.push(span);

        let body_start = class_def
            .body
            .first()
            .map_or(span.end, |s| s.range().start().to_u32());
        let (signature, signature_end_line) = extract_header_signature(
            self.source,
            self.line_starts,
            name_span.start,
            span.start,
            body_start,
        );
        let (doc_comment, comment_start_line) =
            extract_docstring_or_leading_comment(&class_def.body, self.lines, start_loc.line);
        let parent_name = self.class_stack.last().cloned();

        self.symbol_outlines.push(SymbolOutline {
            exported: !class_name.starts_with('_'),
            name: class_name.clone(),
            kind: SymbolKind::Class,
            signature,
            doc_comment,
            comment_start_line,
            parent_name,
            span,
            signature_end_line,
            loc: name_loc,
            end_line: end_loc.line,
        });

        self.class_stack.push(class_name);
        self.subject_stack.push(qualified_subject);
        self.extract_suite(&class_def.body, true);
        self.subject_stack.pop();
        self.class_stack.pop();
    }

    fn extract_function_def(&mut self, func_def: &StmtFunctionDef) {
        let span = text_range_to_byte_span(func_def.range());
        let start_loc = loc_from_line_starts(self.line_starts, span.start);
        let name_span = text_range_to_byte_span(func_def.name.range());
        let name_loc = loc_from_line_starts(self.line_starts, name_span.start);
        let end_loc = loc_from_line_starts(
            self.line_starts,
            span.end.saturating_sub(1).max(span.start),
        );

        let fn_name = func_def.name.to_string();
        let enclosing_class = self.class_stack.last().cloned();
        let subject_name = if let Some(cls) = &enclosing_class {
            format!("{cls}.{fn_name}")
        } else {
            fn_name.clone()
        };

        self.subject_spans
            .push((Some(subject_name.clone()), span, start_loc));
        self.contextual_owner_spans
            .function_boundary_spans
            .push(span);

        let body_start = func_def
            .body
            .first()
            .map_or(span.end, |s| s.range().start().to_u32());
        let def_header_start = func_def
            .decorator_list
            .last()
            .map_or(span.start, |d| d.range().end().to_u32());
        let (signature, signature_end_line) = extract_header_signature(
            self.source,
            self.line_starts,
            name_span.start,
            def_header_start,
            body_start,
        );
        let (doc_comment, comment_start_line) =
            extract_docstring_or_leading_comment(&func_def.body, self.lines, start_loc.line);

        let kind = if enclosing_class.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        };
        let exported = if enclosing_class.is_some() {
            !fn_name.starts_with('_') || fn_name == "__init__"
        } else {
            !fn_name.starts_with('_')
        };

        self.symbol_outlines.push(SymbolOutline {
            exported,
            name: fn_name,
            kind,
            signature,
            doc_comment,
            comment_start_line,
            parent_name: enclosing_class,
            span,
            signature_end_line,
            loc: name_loc,
            end_line: end_loc.line,
        });

        self.check_mutable_default_args(func_def, &subject_name, signature_end_line);

        // Clear class_stack while traversing nested functions inside a method so inner functions are Function, not Method
        let saved_classes = std::mem::take(&mut self.class_stack);
        self.subject_stack.push(subject_name);
        self.finally_closed_vars
            .push(collect_finally_closed_vars(&func_def.body));
        self.extract_suite(&func_def.body, false);
        self.finally_closed_vars.pop();
        self.subject_stack.pop();
        self.class_stack = saved_classes;
    }

    fn check_mutable_default_args(
        &mut self,
        func_def: &StmtFunctionDef,
        subject_name: &str,
        signature_end_line: u32,
    ) {
        if self.is_stub_file || is_ellipsis_only_body(&func_def.body) {
            return;
        }

        let params: Vec<&ParameterWithDefault> = func_def
            .parameters
            .posonlyargs
            .iter()
            .chain(func_def.parameters.args.iter())
            .chain(func_def.parameters.kwonlyargs.iter())
            .collect();

        for param in params {
            let Some(default_expr) = param.default.as_deref() else {
                continue;
            };
            if !is_mutable_default_expr(default_expr) {
                continue;
            }

            let param_name = param.parameter.name.to_string();
            let param_span = text_range_to_byte_span(param.range());
            let default_span = text_range_to_byte_span(default_expr.range());
            let loc = loc_from_line_starts(self.line_starts, param_span.start);
            let default_text = slice_source(self.source, default_span);

            let autofix = build_mutable_default_autofix(
                self.source,
                self.lines,
                self.line_starts,
                &func_def.body,
                signature_end_line,
                &param_name,
                default_span,
                default_text,
            );

            let meta = RuleId::PyNoMutableDefaultArg.metadata();
            self.candidate_diagnostics.push(Diagnostic {
                file: self.path.to_path_buf(),
                subject_name: Some(subject_name.to_string()),
                rule: RuleId::PyNoMutableDefaultArg,
                category: meta.category,
                severity: meta.default_severity,
                message_id: "pyNoMutableDefaultArg",
                tier: meta.default_tier,
                target_name: param_name.clone(),
                message: format!(
                    "Parameter `{param_name}` uses mutable default `{default_text}` which is shared across all calls to `{subject_name}`; default to `None` and initialize inside the function body."
                ),
                docs_url: meta.docs_url,
                loc,
                span: param_span,
                cascade_steps: Vec::new(),
                caller_sites: Vec::new(),
                autofix,
            });
        }
    }

    fn check_except_handler(&mut self, handler: &ruff_python_ast::ExceptHandlerExceptHandler) {
        if self.is_stub_file || !is_silent_handler_body(&handler.body) {
            return;
        }
        let target_name = match handler.type_.as_deref() {
            None => "except".to_string(),
            Some(type_expr) if expr_contains_broad_exception(type_expr) => {
                slice_source(self.source, text_range_to_byte_span(type_expr.range())).to_string()
            }
            Some(_) => return,
        };

        let span = text_range_to_byte_span(handler.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyNoSilentBroadExcept.metadata();
        self.candidate_diagnostics.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyNoSilentBroadExcept,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyNoSilentBroadExcept",
            tier: meta.default_tier,
            target_name: target_name.clone(),
            message: format!(
                "Broad exception handler `{target_name}` silently swallows errors without logging, re-raising, or returning a fallback value."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python expression kinds for single-pass rule detection"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = callee_qualified_name(&call.func);
                let is_cm_wrapper = matches!(
                    callee.as_str(),
                    "closing" | "contextlib.closing" | "nullcontext" | "contextlib.nullcontext"
                ) || callee.ends_with(".enter_context")
                    || callee.ends_with(".enter_async_context");

                if !is_cm_wrapper {
                    self.check_resource_context_manager(call, &callee);
                }
                self.check_unguarded_parse_call(call, &callee);
                self.check_timezone_aware_datetime(call);
                // Visit receiver of method call (e.g., `open("header.txt").read()`) with `in_with_context_expr = false`
                let prev_assigned = self.assigned_var_name.take();
                self.visit_expr(&call.func);
                self.assigned_var_name = prev_assigned;

                let prev_with = self.in_with_context_expr;
                self.in_with_context_expr = is_cm_wrapper;
                for arg in &call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.visit_expr(&kw.value);
                }
                self.in_with_context_expr = prev_with;
            }
            Expr::Attribute(attr) => {
                let prev_with = self.in_with_context_expr;
                self.in_with_context_expr = false;
                self.visit_expr(&attr.value);
                self.in_with_context_expr = prev_with;
            }
            Expr::Await(await_expr) => {
                self.visit_expr(&await_expr.value);
            }
            Expr::Yield(yield_expr) => {
                if let Some(val) = &yield_expr.value {
                    let prev = self.in_return_or_yield;
                    self.in_return_or_yield = true;
                    self.visit_expr(val);
                    self.in_return_or_yield = prev;
                }
            }
            Expr::YieldFrom(yield_from) => {
                let prev = self.in_return_or_yield;
                self.in_return_or_yield = true;
                self.visit_expr(&yield_from.value);
                self.in_return_or_yield = prev;
            }
            Expr::BinOp(bin) => {
                self.visit_expr(&bin.left);
                self.visit_expr(&bin.right);
            }
            Expr::UnaryOp(un) => {
                self.visit_expr(&un.operand);
            }
            Expr::BoolOp(bool_op) => {
                for v in &bool_op.values {
                    self.visit_expr(v);
                }
            }
            Expr::Compare(cmp) => {
                for op_expr in &cmp.operands {
                    self.visit_expr(op_expr);
                }
            }
            Expr::Subscript(sub) => {
                self.check_unguarded_subscript(sub);
                self.visit_expr(&sub.value);
                self.visit_expr(&sub.slice);
            }
            Expr::If(if_expr) => {
                self.visit_expr(&if_expr.test);
                self.visit_expr(&if_expr.body);
                self.visit_expr(&if_expr.orelse);
            }
            Expr::List(list) => {
                for elt in &list.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Tuple(tuple) => {
                for elt in &tuple.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Set(set) => {
                for elt in &set.elts {
                    self.visit_expr(elt);
                }
            }
            Expr::Dict(dict) => {
                for item in &dict.items {
                    if let Some(k) = &item.key {
                        self.visit_expr(k);
                    }
                    self.visit_expr(&item.value);
                }
            }
            Expr::Named(named) => {
                let prev_assigned = self.assigned_var_name.take();
                self.assigned_var_name = extract_target_var_name(&named.target);
                self.visit_expr(&named.value);
                self.assigned_var_name = prev_assigned;
            }
            _ => {}
        }
    }

    fn check_resource_context_manager(&mut self, call: &ExprCall, callee: &str) {
        if self.is_stub_file || self.in_with_context_expr || self.in_return_or_yield {
            return;
        }
        if self.subject_stack.last().is_some_and(|s| {
            s.ends_with(".__enter__") || s.ends_with(".__aenter__")
        }) {
            return;
        }
        if !is_resource_acquisition_callee(callee, &call.func) {
            return;
        }
        if let Some(var_name) = &self.assigned_var_name
            && self
                .finally_closed_vars
                .last()
                .is_some_and(|closed| closed.contains(var_name))
        {
            return;
        }

        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyRequireContextManagerForResource.metadata();
        self.candidate_diagnostics.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyRequireContextManagerForResource,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyRequireContextManagerForResource",
            tier: meta.default_tier,
            target_name: callee.to_string(),
            message: format!(
                "Resource `{callee}(...)` is acquired outside a `with` or `async with` context manager and may leak file descriptors or database connections."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn check_unguarded_parse_call(&mut self, call: &ExprCall, callee: &str) {
        if self.is_stub_file {
            return;
        }
        let is_json_loads = matches!(
            callee,
            "json.loads" | "orjson.loads" | "ujson.loads" | "tomllib.loads" | "loads"
        );
        if is_json_loads {
            let first_arg = call.arguments.args.first();
            if matches!(
                first_arg,
                Some(Expr::StringLiteral(_) | Expr::BytesLiteral(_))
            ) {
                return;
            }
            if self.is_caught(&[
                "ValueError",
                "JSONDecodeError",
                "TOMLDecodeError",
                "DecodeError",
            ]) {
                return;
            }
            self.push_unguarded_parse_or_key_diag(
                text_range_to_byte_span(call.range()),
                callee.to_string(),
                format!(
                    "Call to `{callee}(...)` on untrusted input is not wrapped in `try/except (json.JSONDecodeError, ValueError)`."
                ),
            );
            return;
        }

        if matches!(callee, "int" | "float") {
            let Some(first_arg) = call.arguments.args.first() else {
                return;
            };
            if is_safe_numeric_parse_arg(first_arg) {
                return;
            }
            if self.is_caught(&["ValueError", "TypeError"]) {
                return;
            }
            if let Expr::Name(n) = first_arg
                && self.is_numeric_var_guarded(n.id.as_str())
            {
                return;
            }
            self.push_unguarded_parse_or_key_diag(
                text_range_to_byte_span(call.range()),
                callee.to_string(),
                format!(
                    "Call to `{callee}(...)` on non-literal input can raise `ValueError` at runtime; wrap in `try/except ValueError` or guard with `.isdigit()`."
                ),
            );
        }
    }

    fn check_unguarded_subscript(&mut self, sub: &ExprSubscript) {
        if self.is_stub_file || !sub.ctx.is_load() {
            return;
        }
        // Skip slices and numeric indices
        if matches!(
            sub.slice.as_ref(),
            Expr::Slice(_) | Expr::NumberLiteral(_) | Expr::Tuple(_)
        ) {
            return;
        }
        if let Expr::UnaryOp(un) = sub.slice.as_ref()
            && matches!(un.op, UnaryOp::USub | UnaryOp::UAdd)
            && matches!(un.operand.as_ref(), Expr::NumberLiteral(_))
        {
            return;
        }
        let recv_name = callee_qualified_name(&sub.value);
        if recv_name.is_empty() || is_typing_generic_receiver(&recv_name) {
            return;
        }
        if !is_dict_or_external_mapping_receiver(&recv_name)
            && !matches!(sub.slice.as_ref(), Expr::StringLiteral(_))
        {
            return;
        }
        if self.is_caught(&["KeyError", "LookupError", "IndexError"]) {
            return;
        }
        let key_span = text_range_to_byte_span(sub.slice.range());
        let key_text = slice_source(self.source, key_span).trim();
        if self.is_dict_key_guarded(&recv_name, key_text) {
            return;
        }
        let span = text_range_to_byte_span(sub.range());
        let expr_text = slice_source(self.source, span);
        self.push_unguarded_parse_or_key_diag(
            span,
            recv_name.clone(),
            format!(
                "Direct key access `{expr_text}` can raise `KeyError` on missing keys; use `{recv_name}.get({key_text})`, check `if {key_text} in {recv_name}:`, or wrap in `try/except KeyError`."
            ),
        );
    }

    fn push_unguarded_parse_or_key_diag(
        &mut self,
        span: ByteSpan,
        target_name: String,
        message: String,
    ) {
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let meta = RuleId::PyNoUnguardedParseOrKeyAccess.metadata();
        self.candidate_diagnostics.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyNoUnguardedParseOrKeyAccess,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyNoUnguardedParseOrKeyAccess",
            tier: meta.default_tier,
            target_name,
            message,
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        });
    }

    fn is_caught(&self, accepted: &[&str]) -> bool {
        self.caught_exception_stack.iter().any(|frame| {
            frame.contains("Exception")
                || frame.contains("BaseException")
                || accepted.iter().any(|&name| frame.contains(name))
        })
    }

    fn is_numeric_var_guarded(&self, var_name: &str) -> bool {
        self.guarded_numeric_vars
            .iter()
            .any(|frame| frame.contains(var_name))
    }

    fn is_dict_key_guarded(&self, recv_name: &str, key_text: &str) -> bool {
        let target = (recv_name.to_string(), key_text.to_string());
        self.guarded_dict_keys
            .iter()
            .any(|frame| frame.contains(&target))
    }

    fn check_timezone_aware_datetime(&mut self, call: &ExprCall) {
        if self.is_stub_file {
            return;
        }
        let Expr::Attribute(attr) = call.func.as_ref() else {
            return;
        };
        let method = attr.attr.as_str();
        if !matches!(
            method,
            "now" | "utcnow" | "fromtimestamp" | "utcfromtimestamp"
        ) {
            return;
        }
        let recv = callee_qualified_name(&attr.value);
        let tz_utc = if recv == "datetime" {
            "timezone.utc".to_string()
        } else if let Some(mod_prefix) = recv.strip_suffix(".datetime") {
            format!("{mod_prefix}.timezone.utc")
        } else {
            return;
        };

        let has_tz_kw = call.arguments.keywords.iter().any(|kw| {
            kw.arg.as_ref().is_some_and(|k| k.as_str() == "tz")
                && !matches!(kw.value, Expr::NoneLiteral(_))
        });

        let replacement = match method {
            "utcnow" => format!("{recv}.now({tz_utc})"),
            "now" => {
                let has_pos_tz = call
                    .arguments
                    .args
                    .first()
                    .is_some_and(|a| !matches!(a, Expr::NoneLiteral(_)));
                if has_pos_tz || has_tz_kw {
                    return;
                }
                format!("{recv}.now({tz_utc})")
            }
            "utcfromtimestamp" => {
                let Some(ts_arg) = call.arguments.args.first() else {
                    return;
                };
                let ts_text = slice_source(self.source, text_range_to_byte_span(ts_arg.range()));
                format!("{recv}.fromtimestamp({ts_text}, tz={tz_utc})")
            }
            "fromtimestamp" => {
                let has_pos_tz = call
                    .arguments
                    .args
                    .get(1)
                    .is_some_and(|a| !matches!(a, Expr::NoneLiteral(_)));
                if has_pos_tz || has_tz_kw {
                    return;
                }
                let Some(ts_arg) = call.arguments.args.first() else {
                    return;
                };
                let ts_text = slice_source(self.source, text_range_to_byte_span(ts_arg.range()));
                format!("{recv}.fromtimestamp({ts_text}, tz={tz_utc})")
            }
            _ => return,
        };

        let span = text_range_to_byte_span(call.range());
        let loc = loc_from_line_starts(self.line_starts, span.start);
        let callee_display = format!("{recv}.{method}");
        let meta = RuleId::PyRequireTimezoneAwareDatetime.metadata();
        self.candidate_diagnostics.push(Diagnostic {
            file: self.path.to_path_buf(),
            subject_name: self.subject_stack.last().cloned(),
            rule: RuleId::PyRequireTimezoneAwareDatetime,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "pyRequireTimezoneAwareDatetime",
            tier: meta.default_tier,
            target_name: callee_display.clone(),
            message: format!(
                "Call to `{callee_display}(...)` produces a timezone-naive `datetime`; use `{replacement}` with an explicit timezone."
            ),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: Some(AutofixPatch {
                description: format!("Rewrite `{callee_display}(...)` to `{replacement}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span,
                    replacement,
                }],
            }),
        });
    }
}

fn is_ellipsis_only_body(body: &[Stmt]) -> bool {
    matches!(
        body,
        [Stmt::Expr(expr_stmt)] if matches!(expr_stmt.value.as_ref(), Expr::EllipsisLiteral(_))
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches only bare or broad Exception/BaseException names and tuples"
)]
fn expr_contains_broad_exception(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "Exception" | "BaseException"),
        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "Exception" | "BaseException"),
        Expr::Tuple(t) => t.elts.iter().any(expr_contains_broad_exception),
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only pass and literal/ellipsis expression statements count as silent no-op bodies"
)]
fn is_silent_handler_body(body: &[Stmt]) -> bool {
    !body.is_empty()
        && body.iter().all(|stmt| match stmt {
            Stmt::Pass(_) => true,
            Stmt::Expr(expr_stmt) => matches!(
                expr_stmt.value.as_ref(),
                Expr::EllipsisLiteral(_)
                    | Expr::StringLiteral(_)
                    | Expr::BytesLiteral(_)
                    | Expr::NumberLiteral(_)
                    | Expr::BooleanLiteral(_)
                    | Expr::NoneLiteral(_)
            ),
            _ => false,
        })
}

fn extract_target_var_name(expr: &Expr) -> Option<String> {
    if let Expr::Name(n) = expr {
        Some(n.id.to_string())
    } else {
        None
    }
}

fn is_resource_acquisition_callee(callee: &str, func_expr: &Expr) -> bool {
    if matches!(
        callee,
        "open"
            | "io.open"
            | "codecs.open"
            | "builtins.open"
            | "tempfile.NamedTemporaryFile"
            | "NamedTemporaryFile"
            | "tempfile.TemporaryFile"
            | "TemporaryFile"
            | "sqlite3.connect"
            | "psycopg2.connect"
            | "psycopg.connect"
            | "asyncpg.connect"
            | "pymysql.connect"
            | "aiomysql.connect"
            | "mysql.connector.connect"
            | "sqlalchemy.orm.Session"
            | "Session"
            | "AsyncSession"
            | "SessionLocal"
            | "AsyncSessionLocal"
    ) {
        return true;
    }
    if let Expr::Attribute(attr) = func_expr {
        let method = attr.attr.as_str();
        let recv = callee_qualified_name(&attr.value);
        if matches!(method, "connect" | "begin")
            && matches!(
                recv.as_str(),
                "engine" | "db_engine" | "async_engine" | "self.engine"
            )
        {
            return true;
        }
        if method == "open"
            && (recv.starts_with("Path")
                || recv.starts_with("pathlib.Path")
                || recv.ends_with("_path")
                || recv.ends_with("_file")
                || recv == "path")
        {
            return true;
        }
    }
    false
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans compound statements in a scope for try...finally blocks that call .close() / .aclose()"
)]
fn collect_finally_closed_vars(suite: &[Stmt]) -> HashSet<String> {
    let mut closed = HashSet::new();
    for stmt in suite {
        match stmt {
            Stmt::Try(try_stmt) => {
                collect_close_calls_in_suite(&try_stmt.finalbody, &mut closed);
                closed.extend(collect_finally_closed_vars(&try_stmt.body));
            }
            Stmt::If(if_stmt) => {
                closed.extend(collect_finally_closed_vars(&if_stmt.body));
                for clause in &if_stmt.elif_else_clauses {
                    closed.extend(collect_finally_closed_vars(&clause.body));
                }
            }
            Stmt::With(with_stmt) => {
                closed.extend(collect_finally_closed_vars(&with_stmt.body));
            }
            _ => {}
        }
    }
    closed
}

fn collect_close_calls_in_suite(suite: &[Stmt], out: &mut HashSet<String>) {
    for stmt in suite {
        if let Stmt::Expr(expr_stmt) = stmt {
            let inner = if let Expr::Await(aw) = expr_stmt.value.as_ref() {
                aw.value.as_ref()
            } else {
                expr_stmt.value.as_ref()
            };
            if let Expr::Call(call) = inner
                && let Expr::Attribute(attr) = call.func.as_ref()
                && matches!(attr.attr.as_str(), "close" | "aclose")
                && let Expr::Name(n) = attr.value.as_ref()
            {
                out.insert(n.id.to_string());
            }
        }
    }
}

fn collect_caught_exceptions(handlers: &[ruff_python_ast::ExceptHandler]) -> HashSet<String> {
    let mut caught = HashSet::new();
    for handler in handlers {
        let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
        match h.type_.as_deref() {
            None => {
                caught.insert("BaseException".to_string());
                caught.insert("Exception".to_string());
            }
            Some(type_expr) => collect_exception_names_from_expr(type_expr, &mut caught),
        }
    }
    caught
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts exception identifiers from Name, Attribute, and Tuple AST nodes"
)]
fn collect_exception_names_from_expr(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Name(n) => {
            out.insert(n.id.to_string());
        }
        Expr::Attribute(attr) => {
            out.insert(attr.attr.to_string());
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                collect_exception_names_from_expr(elt, out);
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::type_complexity,
    clippy::wildcard_enum_match_arm,
    reason = "Extracts positive and negative numeric and dict-membership guards from an if condition"
)]
fn extract_if_guards(
    source: &str,
    test: &Expr,
) -> (
    HashSet<String>,
    HashSet<(String, String)>,
    HashSet<String>,
    HashSet<(String, String)>,
) {
    let mut pos_num = HashSet::new();
    let mut pos_keys = HashSet::new();
    let mut neg_num = HashSet::new();
    let mut neg_keys = HashSet::new();

    match test {
        Expr::Call(call) => {
            if let Expr::Attribute(attr) = call.func.as_ref()
                && matches!(attr.attr.as_str(), "isdigit" | "isnumeric" | "isdecimal")
                && let Expr::Name(n) = attr.value.as_ref()
            {
                pos_num.insert(n.id.to_string());
            } else if matches!(callee_qualified_name(&call.func).as_str(), "isinstance")
                && let Some(Expr::Name(n)) = call.arguments.args.first()
            {
                pos_num.insert(n.id.to_string());
            }
        }
        Expr::Compare(cmp) => {
            if let (Some(op), Some(right)) = (cmp.ops.first(), cmp.comparators().first()) {
                // Left operand starts at `cmp.range().start()` and ends before `right.range().start()`
                let full_text = slice_source(source, text_range_to_byte_span(cmp.range()));
                let left_text = extract_in_left_operand(full_text);
                let right_name = callee_qualified_name(right);
                if !left_text.is_empty() && !right_name.is_empty() {
                    match op {
                        CmpOp::In => {
                            pos_keys.insert((right_name, left_text.to_string()));
                        }
                        CmpOp::NotIn => {
                            neg_keys.insert((right_name, left_text.to_string()));
                        }
                        _ => {}
                    }
                }
            }
        }
        Expr::UnaryOp(un) if un.op == UnaryOp::Not => {
            let (inner_pos_num, inner_pos_keys, inner_neg_num, inner_neg_keys) =
                extract_if_guards(source, &un.operand);
            pos_num.extend(inner_neg_num);
            pos_keys.extend(inner_neg_keys);
            neg_num.extend(inner_pos_num);
            neg_keys.extend(inner_pos_keys);
        }
        Expr::BoolOp(bool_op) => {
            for val in &bool_op.values {
                let (p_num, p_keys, n_num, n_keys) = extract_if_guards(source, val);
                pos_num.extend(p_num);
                pos_keys.extend(p_keys);
                neg_num.extend(n_num);
                neg_keys.extend(n_keys);
            }
        }
        _ => {}
    }

    (pos_num, pos_keys, neg_num, neg_keys)
}

fn extract_in_left_operand(compare_text: &str) -> &str {
    if let Some((left, _)) = compare_text.split_once(" not in ") {
        return left.trim();
    }
    if let Some((left, _)) = compare_text.split_once(" in ") {
        return left.trim();
    }
    ""
}

fn suite_terminates_early(suite: &[Stmt]) -> bool {
    matches!(
        suite.last(),
        Some(Stmt::Return(_) | Stmt::Raise(_) | Stmt::Continue(_) | Stmt::Break(_))
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an int()/float() argument is a known-safe literal or numeric expression"
)]
fn is_safe_numeric_parse_arg(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(_) | Expr::BooleanLiteral(_) => true,
        Expr::StringLiteral(s) => {
            let text = s.value.to_str().trim();
            text.parse::<i128>().is_ok() || text.parse::<f64>().is_ok()
        }
        Expr::UnaryOp(un)
            if matches!(un.op, UnaryOp::USub | UnaryOp::UAdd)
                && is_safe_numeric_parse_arg(&un.operand) =>
        {
            true
        }
        Expr::Call(call) => matches!(
            callee_qualified_name(&call.func).as_str(),
            "len" | "abs" | "round" | "min" | "max" | "sum"
        ),
        _ => false,
    }
}

fn is_typing_generic_receiver(recv: &str) -> bool {
    let tail = recv.rsplit('.').next().unwrap_or(recv);
    matches!(
        tail,
        "dict"
            | "list"
            | "set"
            | "frozenset"
            | "tuple"
            | "type"
            | "Dict"
            | "List"
            | "Set"
            | "FrozenSet"
            | "Tuple"
            | "Type"
            | "Optional"
            | "Union"
            | "Literal"
            | "Annotated"
            | "Callable"
            | "Sequence"
            | "MutableSequence"
            | "Mapping"
            | "MutableMapping"
            | "Iterable"
            | "Iterator"
            | "AsyncIterator"
            | "AsyncIterable"
            | "Generator"
            | "AsyncGenerator"
            | "Awaitable"
            | "Coroutine"
            | "ClassVar"
            | "Final"
            | "Generic"
            | "Protocol"
    ) || tail
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
}

fn is_dict_or_external_mapping_receiver(recv: &str) -> bool {
    matches!(
        recv,
        "os.environ"
            | "environ"
            | "payload"
            | "data"
            | "body"
            | "json_body"
            | "params"
            | "query"
            | "query_params"
            | "headers"
            | "cookies"
            | "row"
            | "record"
            | "event"
            | "config"
            | "settings"
            | "kwargs"
            | "context"
            | "meta"
            | "metadata"
            | "response"
            | "res"
            | "req"
            | "request"
    ) || recv.starts_with("request.")
        || recv.starts_with("req.")
        || recv.ends_with(".headers")
        || recv.ends_with(".cookies")
        || recv.ends_with(".query_params")
        || recv.ends_with(".path_params")
        || recv.ends_with(".environ")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only mutable collection literals, comprehensions, and mutable collection constructors are flagged"
)]
fn is_mutable_default_expr(expr: &Expr) -> bool {
    match expr {
        Expr::List(_)
        | Expr::Dict(_)
        | Expr::Set(_)
        | Expr::ListComp(_)
        | Expr::DictComp(_)
        | Expr::SetComp(_) => true,
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            matches!(
                callee.as_str(),
                "list"
                    | "dict"
                    | "set"
                    | "bytearray"
                    | "deque"
                    | "collections.deque"
                    | "defaultdict"
                    | "collections.defaultdict"
                    | "OrderedDict"
                    | "collections.OrderedDict"
                    | "Counter"
                    | "collections.Counter"
                    | "ChainMap"
                    | "collections.ChainMap"
            )
        }
        _ => false,
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only Name and Attribute expressions form dotted callee names"
)]
pub(crate) fn callee_qualified_name(func: &Expr) -> String {
    match func {
        Expr::Name(n) => n.id.to_string(),
        Expr::Attribute(attr) => {
            let prefix = callee_qualified_name(&attr.value);
            if prefix.is_empty() {
                attr.attr.to_string()
            } else {
                format!("{prefix}.{}", attr.attr)
            }
        }
        _ => String::new(),
    }
}

pub(crate) fn slice_source(source: &str, span: ByteSpan) -> &str {
    let start = (span.start as usize).min(source.len());
    let end = (span.end as usize).min(source.len());
    if start <= end && source.is_char_boundary(start) && source.is_char_boundary(end) {
        &source[start..end]
    } else {
        ""
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Autofix builder takes parsed body, line table, and parameter metadata directly"
)]
fn build_mutable_default_autofix(
    _source: &str,
    lines: &[&str],
    line_starts: &[u32],
    body: &[Stmt],
    signature_end_line: u32,
    param_name: &str,
    default_span: ByteSpan,
    default_text: &str,
) -> Option<AutofixPatch> {
    let first_stmt = body.first()?;
    let is_first_docstring = matches!(
        first_stmt,
        Stmt::Expr(expr_stmt) if matches!(expr_stmt.value.as_ref(), Expr::StringLiteral(_))
    );
    let target_stmt = if is_first_docstring && body.len() >= 2 {
        &body[1]
    } else {
        first_stmt
    };

    let stmt_span = text_range_to_byte_span(target_stmt.range());
    let stmt_loc = loc_from_line_starts(line_starts, stmt_span.start);
    if stmt_loc.line <= signature_end_line {
        return None;
    }
    let stmt_line = lines.get((stmt_loc.line - 1) as usize).copied()?;
    let indent_len = stmt_line.len() - stmt_line.trim_start().len();
    let body_indent = &stmt_line[..indent_len];

    let (insert_pos, guard_replacement) = if is_first_docstring && body.len() == 1 {
        let end_pos = stmt_span.end;
        (
            end_pos,
            format!(
                "\n{body_indent}if {param_name} is None:\n{body_indent}    {param_name} = {default_text}"
            ),
        )
    } else {
        let insert_pos = stmt_span.start;
        (
            insert_pos,
            format!(
                "if {param_name} is None:\n{body_indent}    {param_name} = {default_text}\n{body_indent}"
            ),
        )
    };

    Some(AutofixPatch {
        description: format!(
            "Replace mutable default `{default_text}` on `{param_name}` with `None` and initialize inside function body"
        ),
        edits: vec![
            ByteEdit {
                file: None,
                span: default_span,
                replacement: "None".to_string(),
            },
            ByteEdit {
                file: None,
                span: ByteSpan {
                    start: insert_pos,
                    end: insert_pos,
                },
                replacement: guard_replacement,
            },
        ],
    })
}

pub(crate) fn text_range_to_byte_span(range: ruff_text_size::TextRange) -> ByteSpan {
    ByteSpan {
        start: range.start().to_u32(),
        end: range.end().to_u32(),
    }
}

fn is_upper_snake_case(name: &str) -> bool {
    let trimmed = name.trim_start_matches('_');
    !trimmed.is_empty()
        && trimmed.chars().any(|c| c.is_ascii_uppercase())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks Final annotation across Name, Attribute, and Subscript AST nodes"
)]
fn annotation_is_final(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => n.id.as_str() == "Final",
        Expr::Attribute(attr) => attr.attr.as_str() == "Final",
        Expr::Subscript(sub) => annotation_is_final(&sub.value),
        _ => false,
    }
}

fn extract_header_signature(
    source: &str,
    line_starts: &[u32],
    name_start: u32,
    header_search_start: u32,
    body_start: u32,
) -> (String, u32) {
    let start = header_search_start as usize;
    let end = (body_start as usize).min(source.len());
    if start >= end {
        let loc = loc_from_line_starts(line_starts, name_start);
        return (String::new(), loc.line);
    }
    let raw_slice = &source[start..end];
    let trimmed = raw_slice.trim();
    // Strip trailing `:` and any inline comment after `:`
    let without_colon = strip_trailing_colon(trimmed);
    let collapsed = without_colon
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let sig_end_offset = header_search_start
        .saturating_add(u32::try_from(without_colon.len()).unwrap_or(0))
        .max(name_start);
    let sig_end_loc = loc_from_line_starts(line_starts, sig_end_offset);
    (collapsed, sig_end_loc.line)
}

fn strip_trailing_colon(header: &str) -> &str {
    // Strip trailing comment lines or inline comment after colon
    let mut lines: Vec<&str> = header.lines().collect();
    while let Some(last) = lines.last() {
        let code_part = last.split('#').next().unwrap_or("").trim_end();
        if let Some(before_colon) = code_part.strip_suffix(':') {
            let prefix_len = header.len() - last.len() + before_colon.len();
            return header[..prefix_len].trim_end();
        }
        if code_part.is_empty() {
            lines.pop();
        } else {
            break;
        }
    }
    header.trim_end_matches(':').trim_end()
}

fn extract_docstring_or_leading_comment(
    body: &[Stmt],
    lines: &[&str],
    decl_start_line: u32,
) -> (Option<String>, Option<u32>) {
    if let Some(Stmt::Expr(expr_stmt)) = body.first()
        && let Expr::StringLiteral(str_lit) = expr_stmt.value.as_ref()
    {
        let value = str_lit.value.to_str().trim().to_string();
        if !value.is_empty() {
            return (Some(value), None);
        }
    }
    extract_leading_hash_comment(lines, decl_start_line)
}

fn extract_leading_hash_comment(
    lines: &[&str],
    decl_start_line: u32,
) -> (Option<String>, Option<u32>) {
    if decl_start_line <= 1 {
        return (None, None);
    }
    let mut idx = (decl_start_line - 1) as usize;
    let mut collected = Vec::new();
    let mut first_line = None;
    while idx > 0 {
        idx -= 1;
        let trimmed = lines.get(idx).copied().unwrap_or_default().trim();
        if let Some(comment_body) = trimmed.strip_prefix('#') {
            let text = comment_body.trim();
            if is_suppression_comment_body(text) {
                continue;
            }
            first_line = Some(u32::try_from(idx + 1).unwrap_or(1));
            collected.push(text);
        } else {
            break;
        }
    }
    if collected.is_empty() {
        (None, None)
    } else {
        collected.reverse();
        (Some(collected.join("\n")), first_line)
    }
}

fn is_suppression_comment_body(text: &str) -> bool {
    text.starts_with("dotore-disable")
        || text.starts_with("dotore-enable")
        || text.starts_with("noqa")
        || text.starts_with("ruff:")
        || text.starts_with("type:")
        || text.starts_with("pragma:")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PyDirectiveKind {
    DisableNextLine,
    DisableLine,
    BlockDisable,
    BlockEnable,
}

fn extract_python_suppressions(
    source: &str,
    lines: &[&str],
    line_starts: &[u32],
    parsed: &Parsed<ModModule>,
) -> FileSuppressions {
    let mut line_directives = Vec::new();
    let mut block_ranges: Vec<BlockDisableRange> = Vec::new();

    for token in parsed.tokens() {
        if token.kind() != TokenKind::Comment {
            continue;
        }
        let range = token.range();
        let start = range.start().to_usize();
        let end = range.end().to_usize().min(source.len());
        if start >= end {
            continue;
        }
        let comment_loc = loc_from_line_starts(line_starts, range.start().to_u32());
        let line_num = comment_loc.line;
        let raw_comment = &source[start..end];
        let body = raw_comment.trim_start_matches('#').trim();

        let Some((kind, rules)) = parse_python_disable_comment(body) else {
            continue;
        };

        match kind {
            PyDirectiveKind::DisableLine => {
                line_directives.push(LineDisableDirective {
                    target_line: line_num,
                    rules,
                });
            }
            PyDirectiveKind::DisableNextLine => {
                let target_line =
                    resolve_next_python_code_line(lines, (line_num.saturating_sub(1)) as usize);
                line_directives.push(LineDisableDirective { target_line, rules });
            }
            PyDirectiveKind::BlockDisable => {
                block_ranges.push(BlockDisableRange {
                    start_line: line_num,
                    end_line: u32::MAX,
                    rules,
                });
            }
            PyDirectiveKind::BlockEnable => {
                close_python_block_ranges(&mut block_ranges, &rules, line_num);
            }
        }
    }

    FileSuppressions {
        line_directives,
        block_ranges,
    }
}

fn parse_python_disable_comment(body: &str) -> Option<(PyDirectiveKind, Vec<String>)> {
    let trimmed = body.trim();

    for (prefix, kind) in [
        ("dotore-disable-next-line", PyDirectiveKind::DisableNextLine),
        ("dotore-disable-line", PyDirectiveKind::DisableLine),
        ("dotore-disable", PyDirectiveKind::BlockDisable),
        ("dotore-enable", PyDirectiveKind::BlockEnable),
    ] {
        if let Some(after) = trimmed.strip_prefix(prefix) {
            if !after.is_empty()
                && !after.starts_with(char::is_whitespace)
                && !after.starts_with(',')
                && !after.starts_with(':')
            {
                continue;
            }
            let cleaned = after.strip_prefix(':').unwrap_or(after);
            return Some((kind, tokenize_rule_list(cleaned)));
        }
    }

    // File-wide `# ...: noqa` suppression directive
    if let Some((prefix, rest)) = trimmed.split_once(':')
        && !prefix.trim().is_empty()
        && prefix.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && let Some(after) = rest.trim().strip_prefix("noqa")
    {
        let cleaned = after.trim().strip_prefix(':').unwrap_or(after);
        return Some((PyDirectiveKind::BlockDisable, tokenize_rule_list(cleaned)));
    }

    // `# noqa` or `# noqa: B006, E722`
    if let Some(after) = trimmed
        .strip_prefix("noqa")
        .or_else(|| trimmed.strip_prefix("NOQA"))
    {
        if after.is_empty() {
            return Some((PyDirectiveKind::DisableLine, Vec::new()));
        }
        if let Some(codes) = after.strip_prefix(':') {
            return Some((PyDirectiveKind::DisableLine, tokenize_rule_list(codes)));
        }
        if after.starts_with(char::is_whitespace) {
            return Some((PyDirectiveKind::DisableLine, Vec::new()));
        }
    }

    None
}

fn tokenize_rule_list(raw_tail: &str) -> Vec<String> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let before_desc = if let Some(idx) = trimmed.find(" -- ") {
        &trimmed[..idx]
    } else if trimmed.starts_with("-- ") || trimmed == "--" {
        ""
    } else {
        trimmed
    };

    before_desc
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn resolve_next_python_code_line(lines: &[&str], comment_line_idx: usize) -> u32 {
    let mut candidate = comment_line_idx + 1;
    while candidate < lines.len() {
        let text = lines[candidate].trim();
        if text.is_empty() {
            candidate += 1;
            continue;
        }
        if let Some(comment_body) = text.strip_prefix('#')
            && matches!(
                parse_python_disable_comment(comment_body),
                Some((PyDirectiveKind::DisableNextLine, _))
            )
        {
            candidate += 1;
            continue;
        }
        break;
    }
    u32::try_from(candidate + 1).unwrap_or(1)
}

fn close_python_block_ranges(
    ranges: &mut [BlockDisableRange],
    enable_rules: &[String],
    enable_line: u32,
) {
    for range in ranges.iter_mut() {
        if range.end_line != u32::MAX {
            continue;
        }
        if enable_rules.is_empty()
            || range
                .rules
                .iter()
                .any(|r| enable_rules.iter().any(|en| r == en))
        {
            range.end_line = enable_line;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use dotore_core::{
        ByteSpan, Capability, FileContext, LanguageAnalyzer, LanguageId, RuleId, SymbolKind,
    };

    use super::{PyFileIr, PyLanguageAnalyzer};

    #[test]
    fn supports_python_paths_and_declares_manifest_filenames() {
        let analyzer = PyLanguageAnalyzer::new();
        assert_eq!(analyzer.language_id(), LanguageId::Python);
        assert!(analyzer.supports_path(Path::new("app/main.py")));
        assert!(analyzer.supports_path(Path::new("stubs/types.pyi")));
        assert!(!analyzer.supports_path(Path::new("src/App.tsx")));
        assert!(!analyzer.supports_path(Path::new("src/lib.rs")));
        assert_eq!(
            analyzer.manifest_filenames(),
            &["pyproject.toml", "requirements.txt"]
        );
    }

    #[test]
    fn infers_capability_gates_from_pyproject_toml_and_requirements_txt() {
        let analyzer = PyLanguageAnalyzer::new();

        let pyproject = r#"
[project]
name = "billing-api"
dependencies = [
    "fastapi[standard]>=0.115.0",
    "pydantic>=2.9,<3.0",
    "SQLAlchemy==2.0.35 ; python_version >= '3.11'",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

[dependency-groups]
test = ["django>=5.1"]
"#;
        let gate = analyzer.infer_capability_gate(
            Path::new("services/billing"),
            &[(PathBuf::from("services/billing/pyproject.toml"), pyproject)],
        );
        assert!(gate.has(Capability::Python));
        assert!(gate.has(Capability::FastApi));
        assert!(gate.has(Capability::Pydantic));
        assert!(gate.has(Capability::SqlAlchemy));
        assert!(gate.has(Capability::Pytest));
        assert!(gate.has(Capability::Asyncio));
        assert!(gate.has(Capability::Django));

        // Poetry + requirements.txt with comments, -r, and extras
        let poetry_pyproject = r#"
[tool.poetry]
name = "worker"

[tool.poetry.dependencies]
python = "^3.12"
pydantic-settings = "^2.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.2"
"#;
        let requirements = r#"
# Core web & DB dependencies
-r base.txt
fastapi[all]~=0.110.0 # inline comment
sqlalchemy[asyncio]>=2.0.0
"#;
        let combined_gate = analyzer.infer_capability_gate(
            Path::new("services/worker"),
            &[
                (
                    PathBuf::from("services/worker/pyproject.toml"),
                    poetry_pyproject,
                ),
                (
                    PathBuf::from("services/worker/requirements.txt"),
                    requirements,
                ),
            ],
        );
        assert!(combined_gate.has(Capability::Python));
        assert!(combined_gate.has(Capability::FastApi));
        assert!(combined_gate.has(Capability::Pydantic));
        assert!(combined_gate.has(Capability::SqlAlchemy));
        assert!(combined_gate.has(Capability::Asyncio));
        assert!(combined_gate.has(Capability::Pytest));
        assert!(!combined_gate.has(Capability::Django));
    }

    #[test]
    fn extracts_subjects_symbol_outlines_docstrings_suppressions_and_owner_spans() {
        let analyzer = PyLanguageAnalyzer::new();
        let source = r#"MAX_RETRIES = 3
default_timeout: int = 30

class OrderService:
    """Processes customer orders."""

    def __init__(self, db_url: str) -> None:
        self.db_url = db_url

    async def fetch_order(self, order_id: int) -> dict:
        """Fetches an order by ID."""
        # dotore-disable-next-line py-no-unguarded-parse-or-key-access
        return {"id": order_id}

def _helper(items=None):  # dotore-disable-line py-no-mutable-default-arg
    return items  # noqa: E501
"#;
        let extracted = analyzer.extract_file(Path::new("services/orders.py"), source);
        assert_eq!(extracted.language_id, LanguageId::Python);
        assert_eq!(extracted.file_context, FileContext::Production);
        let ir = extracted
            .downcast_payload::<PyFileIr>()
            .expect("Expected PyFileIr payload");
        assert!(ir.valid_syntax);

        // Subjects: OrderService, __init__, fetch_order, _helper
        assert_eq!(extracted.subjects_count, 4);
        let subject_names: Vec<Option<&str>> = extracted
            .subject_spans
            .iter()
            .map(|(n, _, _)| n.as_deref())
            .collect();
        assert!(subject_names.contains(&Some("OrderService")));
        assert!(subject_names.contains(&Some("OrderService.__init__")));
        assert!(subject_names.contains(&Some("OrderService.fetch_order")));
        assert!(subject_names.contains(&Some("_helper")));

        // Symbol Outlines
        let find_sym = |name: &str| {
            extracted
                .symbol_outlines
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("Missing symbol outline {name}"))
        };
        let max_retries = find_sym("MAX_RETRIES");
        assert_eq!(max_retries.kind, SymbolKind::Constant);
        assert!(max_retries.exported);

        let default_timeout = find_sym("default_timeout");
        assert_eq!(default_timeout.kind, SymbolKind::Variable);
        assert!(default_timeout.exported);

        let cls = find_sym("OrderService");
        assert_eq!(cls.kind, SymbolKind::Class);
        assert_eq!(
            cls.doc_comment.as_deref(),
            Some("Processes customer orders.")
        );
        assert!(cls.exported);

        let fetch_method = find_sym("fetch_order");
        assert_eq!(fetch_method.kind, SymbolKind::Method);
        assert_eq!(fetch_method.parent_name.as_deref(), Some("OrderService"));
        assert_eq!(
            fetch_method.doc_comment.as_deref(),
            Some("Fetches an order by ID.")
        );
        assert!(
            fetch_method
                .signature
                .contains("async def fetch_order(self, order_id: int) -> dict")
        );

        let helper_fn = find_sym("_helper");
        assert_eq!(helper_fn.kind, SymbolKind::Function);
        assert!(!helper_fn.exported);

        // Suppressions
        assert!(extracted.is_suppressed(
            RuleId::PyNoUnguardedParseOrKeyAccess,
            13,
            ByteSpan { start: 320, end: 340 },
        ));
        assert!(extracted.is_suppressed(
            RuleId::PyNoMutableDefaultArg,
            15,
            ByteSpan { start: 350, end: 365 },
        ));

        // Contextual Owner spans
        assert!(
            !extracted
                .contextual_owner_spans
                .function_boundary_spans
                .is_empty()
        );
    }

    #[test]
    fn validates_python_syntax_for_py_and_pyi() {
        let analyzer = PyLanguageAnalyzer::new();
        assert!(analyzer.validate_syntax(
            Path::new("app/main.py"),
            "def add(a: int, b: int) -> int:\n    return a + b\n"
        ));
        assert!(analyzer.validate_syntax(
            Path::new("app/main.pyi"),
            "def add(a: int, b: int) -> int: ...\n"
        ));
        assert!(!analyzer.validate_syntax(
            Path::new("app/broken.py"),
            "def add(a: int, :\n    return a\n"
        ));
    }
}
