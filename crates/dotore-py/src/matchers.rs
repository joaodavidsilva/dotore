//! Shared Python AST matchers, scope tracking (`PyScopeTracker`), rule activation gating,
//! and `Diagnostic` / `AutofixPatch` builder helpers used across all Python rule evaluators.

use std::{collections::HashSet, path::Path};

use dotore_core::{
    AutofixPatch, ByteSpan, Capability, Diagnostic, ExtractedFile, FileContext, RuleId,
    RuleSeverity, RuleTag, WorkspacePackage, loc_from_line_starts,
};
use ruff_python_ast::{Expr, ParameterWithDefault, StmtFunctionDef};
use ruff_text_size::{Ranged, TextRange};

/// Saved outer scope state restored when exiting a `def` or `async def` function body.
#[derive(Debug, Clone)]
pub struct PySavedFunctionScope {
    saved_classes: Vec<String>,
    saved_loop_depth: usize,
    /// Qualified subject name (`"ClassName.method"` or `"func_name"`).
    pub(crate) subject_name: String,
    /// Immediate enclosing class name if this function is a method (`Some("ClassName")`), or `None`.
    pub(crate) enclosing_class: Option<String>,
}

/// Reusable lexical scope tracker for Python AST visitors (`class`, `def`/`async def`, loops,
/// `with` context expressions, and `return`/`yield` value expressions).
#[derive(Debug, Clone, Default)]
pub(crate) struct PyScopeTracker {
    class_stack: Vec<String>,
    subject_stack: Vec<String>,
    async_fn_stack: Vec<bool>,
    fn_depth: usize,
    loop_depth: usize,
    /// `true` while visiting a `with <expr>:` context manager header expression.
    pub(crate) in_with_context_expr: bool,
    /// `true` while visiting a `return <expr>` or `yield <expr>` value expression.
    pub(crate) in_return_or_yield: bool,
}

impl PyScopeTracker {
    /// Creates a new empty [`PyScopeTracker`] at module scope.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the innermost enclosing **Subject** name (`"Class"`, `"Class.method"`, or `"func"`).
    #[must_use]
    pub(crate) fn current_subject(&self) -> Option<String> {
        self.subject_stack.last().cloned()
    }

    /// Returns the innermost enclosing **Subject** name as a string slice.
    #[must_use]
    pub(crate) fn current_subject_str(&self) -> Option<&str> {
        self.subject_stack.last().map(String::as_str)
    }

    /// Returns the innermost active class name when directly inside a class body.
    #[must_use]
    pub(crate) fn current_class(&self) -> Option<String> {
        self.class_stack.last().cloned()
    }

    /// Returns `true` if the innermost enclosing function is an `async def`.
    #[must_use]
    pub(crate) fn is_in_async_fn(&self) -> bool {
        self.async_fn_stack.last().copied().unwrap_or(false)
    }

    /// Returns the current function nesting depth (`0` at module/class scope).
    #[must_use]
    pub(crate) const fn fn_depth(&self) -> usize {
        self.fn_depth
    }

    /// Returns `true` if currently inside a `for`/`while` loop or comprehension (`loop_depth > 0`).
    #[must_use]
    pub(crate) const fn in_loop(&self) -> bool {
        self.loop_depth > 0
    }

    /// Pushes a class scope and returns its qualified subject name (`"Outer.Inner"` or `"ClassName"`).
    pub(crate) fn enter_class(&mut self, class_name: impl Into<String>) -> String {
        let class_name = class_name.into();
        let qualified = if let Some(parent_cls) = self.class_stack.last() {
            format!("{parent_cls}.{class_name}")
        } else {
            class_name.clone()
        };
        self.class_stack.push(class_name);
        self.subject_stack.push(qualified.clone());
        qualified
    }

    /// Pops the current class scope.
    pub(crate) fn exit_class(&mut self) {
        self.subject_stack.pop();
        self.class_stack.pop();
    }

    /// Computes `(subject_name, enclosing_class)` for `fn_name` in the current scope without mutating stacks.
    #[must_use]
    pub(crate) fn compute_function_subject(&self, fn_name: &str) -> (String, Option<String>) {
        let enclosing_class = self.class_stack.last().cloned();
        let subject_name = if let Some(cls) = &enclosing_class {
            format!("{cls}.{fn_name}")
        } else {
            fn_name.to_string()
        };
        (subject_name, enclosing_class)
    }

    /// Enters a `def` or `async def` function body, clearing `class_stack` and resetting `loop_depth`
    /// so nested functions inside methods are treated as standalone functions rather than methods.
    pub(crate) fn enter_function(&mut self, fn_name: &str, is_async: bool) -> PySavedFunctionScope {
        let (subject_name, enclosing_class) = self.compute_function_subject(fn_name);
        let saved_classes = std::mem::take(&mut self.class_stack);
        let saved_loop_depth = std::mem::replace(&mut self.loop_depth, 0);
        self.fn_depth += 1;
        self.async_fn_stack.push(is_async);
        self.subject_stack.push(subject_name.clone());
        PySavedFunctionScope {
            saved_classes,
            saved_loop_depth,
            subject_name,
            enclosing_class,
        }
    }

    /// Restores the outer scope saved by [`PyScopeTracker::enter_function`].
    pub(crate) fn exit_function(&mut self, saved: PySavedFunctionScope) {
        self.subject_stack.pop();
        self.async_fn_stack.pop();
        self.fn_depth = self.fn_depth.saturating_sub(1);
        self.loop_depth = saved.saved_loop_depth;
        self.class_stack = saved.saved_classes;
    }

    /// Increments the active loop nesting depth.
    pub(crate) fn enter_loop(&mut self) {
        self.loop_depth += 1;
    }

    /// Decrements the active loop nesting depth.
    pub(crate) fn exit_loop(&mut self) {
        self.loop_depth = self.loop_depth.saturating_sub(1);
    }
}

/// Extracts a dotted qualified name from a `Name` or chained `Attribute` expression (e.g. `"asyncio.create_task"`).
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only Name and Attribute expressions form dotted callee names"
)]
#[must_use]
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

/// Safely slices `source` by `span`, returning `""` if out-of-bounds or not on UTF-8 char boundaries.
#[must_use]
pub(crate) fn slice_source(source: &str, span: ByteSpan) -> &str {
    let start = (span.start as usize).min(source.len());
    let end = (span.end as usize).min(source.len());
    if start <= end && source.is_char_boundary(start) && source.is_char_boundary(end) {
        &source[start..end]
    } else {
        ""
    }
}

/// Converts a `ruff_text_size::TextRange` into a `dotore_core::ByteSpan`.
#[must_use]
pub(crate) fn text_range_to_byte_span(range: TextRange) -> ByteSpan {
    ByteSpan {
        start: range.start().to_u32(),
        end: range.end().to_u32(),
    }
}

/// Returns `true` if `name` (after stripping leading underscores) is `UPPER_SNAKE_CASE`.
#[must_use]
pub(crate) fn is_upper_snake_case(name: &str) -> bool {
    let trimmed = name.trim_start_matches('_');
    !trimmed.is_empty()
        && trimmed.chars().any(|c| c.is_ascii_uppercase())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Returns `true` if `expr` is a `Final` or `typing.Final[...]` type annotation.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks Final annotation across Name, Attribute, and Subscript AST nodes"
)]
#[must_use]
pub(crate) fn annotation_is_final(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => n.id.as_str() == "Final",
        Expr::Attribute(attr) => attr.attr.as_str() == "Final",
        Expr::Subscript(sub) => annotation_is_final(&sub.value),
        _ => false,
    }
}

/// Returns `true` if `expr` is a `ClassVar` or `Final` type annotation (`ClassVar[T]`, `typing.Final[T]`, etc.).
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks ClassVar and Final annotations across Name, Attribute, and Subscript"
)]
#[must_use]
pub(crate) fn annotation_is_classvar_or_final(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "ClassVar" | "Final"),
        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "ClassVar" | "Final"),
        Expr::Subscript(sub) => annotation_is_classvar_or_final(&sub.value),
        _ => false,
    }
}

/// Computes the byte span of `func_def` starting at `def` / `async def` (after any decorators).
#[must_use]
pub(crate) fn function_def_header_span(source: &str, func_def: &StmtFunctionDef) -> ByteSpan {
    let full_span = text_range_to_byte_span(func_def.range());
    let search_start = func_def
        .decorator_list
        .last()
        .map_or(full_span.start as usize, |d| d.range().end().to_usize());
    let bytes = source.as_bytes();
    let mut start = search_start.min(bytes.len());
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let start_u32 = u32::try_from(start).unwrap_or(full_span.start);
    ByteSpan {
        start: start_u32,
        end: full_span.end.max(start_u32),
    }
}

/// Iterates over all positional-only, standard, and keyword-only parameters of `func_def`.
pub(crate) fn all_function_parameters(
    func_def: &StmtFunctionDef,
) -> impl Iterator<Item = &ParameterWithDefault> {
    func_def
        .parameters
        .posonlyargs
        .iter()
        .chain(func_def.parameters.args.iter())
        .chain(func_def.parameters.kwonlyargs.iter())
}

/// Extracts a simple identifier name from an assignment target expression (`Expr::Name`).
#[must_use]
pub(crate) fn extract_target_var_name(expr: &Expr) -> Option<String> {
    if let Expr::Name(n) = expr {
        Some(n.id.to_string())
    } else {
        None
    }
}

/// Collects all identifier names (`Expr::Name`) referenced inside `expr` into `out`.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Collects identifier names referenced inside an expression"
)]
pub(crate) fn collect_expr_load_names(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Name(n) => {
            out.insert(n.id.to_string());
        }
        Expr::Attribute(a) => {
            collect_expr_load_names(&a.value, out);
        }
        Expr::Call(c) => {
            collect_expr_load_names(&c.func, out);
            for arg in &c.arguments.args {
                collect_expr_load_names(arg, out);
            }
            for kw in &c.arguments.keywords {
                collect_expr_load_names(&kw.value, out);
            }
        }
        Expr::Await(aw) => collect_expr_load_names(&aw.value, out),
        Expr::BinOp(b) => {
            collect_expr_load_names(&b.left, out);
            collect_expr_load_names(&b.right, out);
        }
        Expr::UnaryOp(u) => collect_expr_load_names(&u.operand, out),
        Expr::BoolOp(b) => {
            for v in &b.values {
                collect_expr_load_names(v, out);
            }
        }
        Expr::Compare(cmp) => {
            for op in &cmp.operands {
                collect_expr_load_names(op, out);
            }
        }
        Expr::Subscript(s) => {
            collect_expr_load_names(&s.value, out);
            collect_expr_load_names(&s.slice, out);
        }
        Expr::List(l) => {
            for e in &l.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Set(s) => {
            for e in &s.elts {
                collect_expr_load_names(e, out);
            }
        }
        Expr::Dict(d) => {
            for item in &d.items {
                if let Some(k) = &item.key {
                    collect_expr_load_names(k, out);
                }
                collect_expr_load_names(&item.value, out);
            }
        }
        Expr::If(i) => {
            collect_expr_load_names(&i.test, out);
            collect_expr_load_names(&i.body, out);
            collect_expr_load_names(&i.orelse, out);
        }
        _ => {}
    }
}

/// Returns `true` if `expr` is a `pathlib.Path(...)` constructor call.
#[must_use]
pub(crate) fn is_path_constructor_expr(expr: &Expr) -> bool {
    if let Expr::Call(call) = expr {
        let callee = callee_qualified_name(&call.func);
        return matches!(
            callee.as_str(),
            "Path" | "pathlib.Path" | "PurePath" | "pathlib.PurePath" | "PosixPath" | "WindowsPath"
        );
    }
    false
}

/// Returns `true` if `callee` is a standard library `subprocess` invocation helper.
#[must_use]
pub(crate) fn is_subprocess_callee(callee: &str) -> bool {
    matches!(
        callee,
        "subprocess.run"
            | "subprocess.Popen"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "Popen"
            | "check_output"
            | "check_call"
    )
}

/// Returns `true` if `rule` is a Python diagnostic rule evaluated by `dotore-py`.
#[must_use]
pub const fn is_evaluated_python_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::PyNoMutableDefaultArg
            | RuleId::PyNoSilentBroadExcept
            | RuleId::PyRequireContextManagerForResource
            | RuleId::PyNoUnguardedParseOrKeyAccess
            | RuleId::PyRequireTimezoneAwareDatetime
            | RuleId::PyPydanticPreferDefaultFactory
            | RuleId::PyFastapiRequireResponseModel
            | RuleId::PyFastapiMutatingRouteRequiresAuth
            | RuleId::PyOrmNoQueryInLoop
            | RuleId::PySecurityNoRawSqlInterpolation
            | RuleId::PySecurityNoUnsafeDeserializationOrShell
            | RuleId::PyAsyncNoBlockingCall
            | RuleId::PyAsyncNoSequentialAwaitInLoop
            | RuleId::PyAsyncNoUnawaitedCoroutine
            | RuleId::PyAsyncNoFireAndForgetTask
            | RuleId::PyPerfHoistRegex
            | RuleId::PyPerfNoLinearMembershipInLoop
            | RuleId::PyArchNoCircularImports
            | RuleId::PyArchNoUnusedExports
            | RuleId::PyZenComplexFunction
            | RuleId::PyZenDeepNesting
            | RuleId::PyZenLongFunction
            | RuleId::PyZenTooManyParams
            | RuleId::PyZenLargeClass
            | RuleId::PyZenNoDenseSemicolonStatements
            | RuleId::PyNoWildcardImport
            | RuleId::PySecurityHttpRequestRequiresTimeout
            | RuleId::PySecurityNoDisabledTlsVerify
            | RuleId::PySecurityNoWeakCryptoOrRandom
            | RuleId::PySecurityNoXxeOrUnsafeArchive
            | RuleId::PySecurityNoHardcodedSecretOrTmp
            | RuleId::PyStructureMissingPyTyped
            | RuleId::PyStructureLowTypeHintCoverage
            | RuleId::ArchThinEntrypoint
            | RuleId::ArchNoMixedIoAndPresentation
            | RuleId::ArchSeparateStaticCatalogFromTypes
            | RuleId::ArchNoMixedDomainMonolith
            | RuleId::ArchNoInlineTerminalUiPrimitives
            | RuleId::ArchPreferFluentBuilder
            | RuleId::ArchNoDuplicatedHelperLogic
    )
}

/// Returns `true` if `package`'s **Capability Gate** allows `rule`.
#[must_use]
fn gate_allows_py_rule(package: &WorkspacePackage, rule: RuleId) -> bool {
    if !is_evaluated_python_rule(rule) {
        return false;
    }
    let meta = rule.metadata();
    if package.capability_gate.allows_rule(meta) {
        return true;
    }
    matches!(
        rule,
        RuleId::PyAsyncNoBlockingCall
            | RuleId::PyAsyncNoSequentialAwaitInLoop
            | RuleId::PyAsyncNoUnawaitedCoroutine
            | RuleId::PyAsyncNoFireAndForgetTask
    ) && package.capability_gate.has(Capability::Asyncio)
}

/// Evaluates whether `rule` is enabled and active for `file` in `package` at `(loc_line, span)`,
/// returning `Some(effective_severity)` if the diagnostic should be emitted.
#[must_use]
pub(crate) fn resolve_active_py_rule_severity(
    package: &WorkspacePackage,
    file: &ExtractedFile,
    rule: RuleId,
    enabled_rules: Option<&[RuleId]>,
    loc_line: u32,
    span: ByteSpan,
) -> Option<RuleSeverity> {
    if let Some(allowed) = enabled_rules
        && !allowed.contains(&rule)
    {
        return None;
    }
    if package
        .config
        .is_overridden_for_file(rule, &file.path, &package.root_dir)
    {
        return None;
    }
    if !gate_allows_py_rule(package, rule) {
        return None;
    }
    let meta = rule.metadata();
    if enabled_rules.is_none()
        && file.file_context != FileContext::Production
        && meta.tags.contains(&RuleTag::TestNoise)
        && !meta.tags.contains(&RuleTag::MigrationHint)
        && package.config.explicit_rule_override(rule).is_none()
    {
        return None;
    }
    let effective_sev = package.config.effective_severity(rule)?;
    if package.config.respect_inline_disables && file.is_suppressed(rule, loc_line, span) {
        return None;
    }
    Some(effective_sev)
}

/// Builds a Python [`Diagnostic`] using [`Diagnostic::for_rule`] with location computed from `line_starts`.
#[expect(
    clippy::too_many_arguments,
    reason = "Diagnostic builder helper binds file path, line table, span, subject, rule, message_id, target, and message"
)]
#[must_use]
pub(crate) fn build_py_diagnostic(
    path: &Path,
    line_starts: &[u32],
    span: ByteSpan,
    subject_name: Option<String>,
    rule: RuleId,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
) -> Diagnostic {
    let loc = loc_from_line_starts(line_starts, span.start);
    Diagnostic::for_rule(rule, path, loc, span, message)
        .with_subject(subject_name)
        .with_message_id(message_id)
        .with_target_name(target_name)
}

/// Builds a Python [`Diagnostic`] with an optional [`AutofixPatch`].
#[expect(
    clippy::too_many_arguments,
    reason = "Diagnostic builder helper binds file path, line table, span, subject, rule, message_id, target, message, and autofix"
)]
#[must_use]
pub(crate) fn build_py_diagnostic_with_autofix(
    path: &Path,
    line_starts: &[u32],
    span: ByteSpan,
    subject_name: Option<String>,
    rule: RuleId,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
    autofix: Option<AutofixPatch>,
) -> Diagnostic {
    let default_tier = rule.metadata().default_tier;
    build_py_diagnostic(
        path,
        line_starts,
        span,
        subject_name,
        rule,
        message_id,
        target_name,
        message,
    )
    .with_autofix(autofix)
    .with_tier(default_tier)
}

/// Builds a Python [`Diagnostic`] with a deterministic [`AutofixPatch`].
#[expect(
    clippy::too_many_arguments,
    reason = "Diagnostic builder helper binds file path, line table, span, subject, rule, message_id, target, message, and patch"
)]
#[must_use]
pub(crate) fn build_py_diagnostic_with_patch(
    path: &Path,
    line_starts: &[u32],
    span: ByteSpan,
    subject_name: Option<String>,
    rule: RuleId,
    message_id: &'static str,
    target_name: impl Into<String>,
    message: impl Into<String>,
    patch: AutofixPatch,
) -> Diagnostic {
    build_py_diagnostic(
        path,
        line_starts,
        span,
        subject_name,
        rule,
        message_id,
        target_name,
        message,
    )
    .with_patch(patch)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::Path};

    use dotore_core::{AutofixPatch, ByteSpan, PrescriptionTier, RuleId, compute_line_starts};
    use ruff_python_ast::{ModModule, PySourceType, Stmt};
    use ruff_python_parser::{Parsed, parse_unchecked_source};

    use super::{
        PyScopeTracker, all_function_parameters, annotation_is_classvar_or_final,
        annotation_is_final, build_py_diagnostic, build_py_diagnostic_with_patch,
        callee_qualified_name, collect_expr_load_names, extract_target_var_name,
        function_def_header_span, is_upper_snake_case, slice_source,
    };

    fn parse_py(source: &str) -> Parsed<ModModule> {
        parse_unchecked_source(source, PySourceType::Python)
    }

    #[test]
    fn resolves_qualified_callees_annotations_and_function_parameters() {
        let source = r#"
class Config:
    MAX_ITEMS: typing.Final[int] = 10
    SHARED: ClassVar[list[str]] = []

@app.post("/items")
async def create_item(pos_only, /, normal: int = 1, *, kw_only: str = "x"):
    return client.http.post(pos_only, normal, kw=kw_only)
"#;
        let parsed = parse_py(source);
        let suite = parsed.suite();

        let Stmt::ClassDef(cls) = &suite[0] else {
            panic!("expected ClassDef");
        };
        let Stmt::AnnAssign(ann1) = &cls.body[0] else {
            panic!("expected AnnAssign 1");
        };
        assert_eq!(
            extract_target_var_name(&ann1.target).as_deref(),
            Some("MAX_ITEMS")
        );
        assert!(is_upper_snake_case("MAX_ITEMS"));
        assert!(is_upper_snake_case("_PRIVATE_CONST_2"));
        assert!(!is_upper_snake_case("normal_var"));
        assert!(annotation_is_final(&ann1.annotation));
        assert!(annotation_is_classvar_or_final(&ann1.annotation));

        let Stmt::AnnAssign(ann2) = &cls.body[1] else {
            panic!("expected AnnAssign 2");
        };
        assert!(!annotation_is_final(&ann2.annotation));
        assert!(annotation_is_classvar_or_final(&ann2.annotation));

        let Stmt::FunctionDef(func_def) = &suite[1] else {
            panic!("expected FunctionDef");
        };
        let header_span = function_def_header_span(source, func_def);
        assert!(slice_source(source, header_span).starts_with("async def create_item"));

        let param_names: Vec<&str> = all_function_parameters(func_def)
            .map(|p| p.parameter.name.as_str())
            .collect();
        assert_eq!(param_names, vec!["pos_only", "normal", "kw_only"]);

        let Stmt::Return(ret) = &func_def.body[0] else {
            panic!("expected Return");
        };
        let call_expr = ret.value.as_deref().expect("return value");
        let ruff_python_ast::Expr::Call(call) = call_expr else {
            panic!("expected Call");
        };
        assert_eq!(callee_qualified_name(&call.func), "client.http.post");

        let mut loaded = HashSet::new();
        collect_expr_load_names(call_expr, &mut loaded);
        assert!(loaded.contains("client"));
        assert!(loaded.contains("pos_only"));
        assert!(loaded.contains("normal"));
        assert!(loaded.contains("kw_only"));
    }

    #[test]
    fn tracks_nested_class_function_async_and_loop_scopes() {
        let mut scope = PyScopeTracker::new();
        assert_eq!(scope.current_subject(), None);
        assert_eq!(scope.fn_depth(), 0);
        assert!(!scope.in_loop());

        let cls_subj = scope.enter_class("OrderService");
        assert_eq!(cls_subj, "OrderService");
        assert_eq!(scope.current_subject_str(), Some("OrderService"));
        assert_eq!(scope.current_class().as_deref(), Some("OrderService"));

        scope.enter_loop();
        assert!(scope.in_loop());

        // Entering a method records OrderService.process and resets class_stack + loop_depth for inner defs
        let saved_method = scope.enter_function("process", true);
        assert_eq!(saved_method.subject_name, "OrderService.process");
        assert_eq!(
            saved_method.enclosing_class.as_deref(),
            Some("OrderService")
        );
        assert!(scope.is_in_async_fn());
        assert_eq!(scope.fn_depth(), 1);
        assert!(!scope.in_loop());
        assert_eq!(scope.current_class(), None);

        // Nested helper inside a method is not qualified with OrderService
        let saved_inner = scope.enter_function("inner_helper", false);
        assert_eq!(saved_inner.subject_name, "inner_helper");
        assert_eq!(saved_inner.enclosing_class, None);
        assert!(!scope.is_in_async_fn());
        assert_eq!(scope.fn_depth(), 2);

        scope.exit_function(saved_inner);
        assert!(scope.is_in_async_fn());
        assert_eq!(scope.current_subject_str(), Some("OrderService.process"));

        scope.exit_function(saved_method);
        assert!(scope.in_loop());
        assert_eq!(scope.current_class().as_deref(), Some("OrderService"));

        scope.exit_loop();
        scope.exit_class();
        assert_eq!(scope.current_subject(), None);
    }

    #[test]
    fn builds_diagnostics_and_autofix_patches_from_rule_metadata() {
        let source = "from datetime import datetime\nx = datetime.utcnow()\n";
        let line_starts = compute_line_starts(source);
        let span = ByteSpan { start: 34, end: 51 };

        let diag = build_py_diagnostic(
            Path::new("app/clock.py"),
            &line_starts,
            span,
            Some("current_time".to_string()),
            RuleId::PyNoSilentBroadExcept,
            "pyNoSilentBroadExcept",
            "except",
            "Silent except block.",
        );
        assert_eq!(diag.loc.line, 2);
        assert_eq!(diag.loc.column, 5);
        assert_eq!(diag.subject_name.as_deref(), Some("current_time"));
        assert_eq!(diag.target_name, "except");
        assert!(diag.autofix.is_none());

        let patch = AutofixPatch::replace("Use timezone.utc", span, "datetime.now(timezone.utc)");
        let autofix_diag = build_py_diagnostic_with_patch(
            Path::new("app/clock.py"),
            &line_starts,
            span,
            None,
            RuleId::PyRequireTimezoneAwareDatetime,
            "pyRequireTimezoneAwareDatetime",
            "datetime.utcnow",
            "Use timezone-aware datetime.",
            patch,
        );
        assert_eq!(autofix_diag.tier, PrescriptionTier::Autofix);
        assert_eq!(autofix_diag.autofix.as_ref().unwrap().edits.len(), 1);
    }
}
