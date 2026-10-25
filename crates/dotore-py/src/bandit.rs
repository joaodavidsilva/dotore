//! Native Rust AST detectors for the Python Bandit security surface (`dotore-py`):
//! - `py-security-http-request-requires-timeout` (`bandit/B113`)
//! - `py-security-no-disabled-tls-verify` (`bandit/B501`)
//! - `py-security-no-weak-crypto-or-random` (`bandit/B303`, `B311`, `B324`)
//! - `py-security-no-xxe-or-unsafe-archive` (`bandit/B202`, `B314`–`B320`)
//! - `py-security-no-hardcoded-secret-or-tmp` (`bandit/B105`–`B108`)

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use dotore_core::{AutofixPatch, ByteSpan, Diagnostic, FileContext, RuleId, classify_file_context};
use ruff_python_ast::{
    CmpOp, Expr, ExprCall, ExprCompare, ExprFString, ExprStringLiteral, Stmt, StmtAnnAssign,
    StmtAssign, StmtClassDef, StmtFunctionDef,
};
use ruff_text_size::Ranged;

use crate::matchers::{
    PyScopeTracker, all_function_parameters, build_py_diagnostic, build_py_diagnostic_with_patch,
    callee_qualified_name, text_range_to_byte_span,
};

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "head", "options", "patch", "request",
];

/// Evaluates the 5 native Bandit security rules over `suite`, skipping `.pyi` stubs and test/example files.
pub(crate) fn extract_bandit_diagnostics(
    path: &Path,
    source: &str,
    line_starts: &[u32],
    is_stub_file: bool,
    suite: &[Stmt],
    out: &mut Vec<Diagnostic>,
) {
    if is_stub_file || is_test_or_example_python_path(path) {
        return;
    }
    let mut visitor = BanditRuleVisitor {
        path,
        source,
        line_starts,
        out,
        scope: PyScopeTracker::new(),
        import_aliases: HashMap::new(),
        tar_vars: HashSet::new(),
        zip_vars: HashSet::new(),
        in_sensitive_value_context: false,
        current_fn_is_sensitive: false,
    };
    visitor.visit_suite(suite);
}

fn is_test_or_example_python_path(path: &Path) -> bool {
    if classify_file_context(path) != FileContext::Production {
        return true;
    }
    let normalized = path.to_string_lossy().replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    if file_name.starts_with("example_")
        || file_name.ends_with("_example.py")
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name == "conftest.py"
    {
        return true;
    }
    normalized.split('/').any(|seg| {
        matches!(
            seg,
            "tests" | "test" | "testing" | "examples" | "example" | "docs_src" | "samples" | "demo" | "demos" | "benchmarks"
        )
    })
}

struct BanditRuleVisitor<'a> {
    path: &'a Path,
    source: &'a str,
    line_starts: &'a [u32],
    out: &'a mut Vec<Diagnostic>,
    scope: PyScopeTracker,
    /// Maps local imported alias name -> canonical qualified module/symbol path (e.g. `"ET"` -> `"xml.etree.ElementTree"`).
    import_aliases: HashMap<String, String>,
    tar_vars: HashSet<String>,
    zip_vars: HashSet<String>,
    in_sensitive_value_context: bool,
    current_fn_is_sensitive: bool,
}

impl<'a> BanditRuleVisitor<'a> {
    fn visit_suite(&mut self, suite: &[Stmt]) {
        for stmt in suite {
            self.visit_stmt(stmt);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses relevant Python statement variants for Bandit security rules"
    )]
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(import_stmt) => {
                for alias in &import_stmt.names {
                    let orig = alias.name.to_string();
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| orig.clone(), ToString::to_string);
                    self.import_aliases.insert(bound, orig);
                }
            }
            Stmt::ImportFrom(import_from) => {
                let Some(mod_name) = &import_from.module else {
                    return;
                };
                for alias in &import_from.names {
                    let orig = alias.name.as_str();
                    let bound = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| orig.to_string(), ToString::to_string);
                    let qualified = format!("{mod_name}.{orig}");
                    self.import_aliases.insert(bound, qualified);
                }
            }
            Stmt::ClassDef(class_def) => self.visit_class_def(class_def),
            Stmt::FunctionDef(func_def) => self.visit_function_def(func_def),
            Stmt::Assign(assign) => self.visit_assign(assign),
            Stmt::AnnAssign(ann_assign) => self.visit_ann_assign(ann_assign),
            Stmt::AugAssign(aug) => self.visit_expr(&aug.value),
            Stmt::Expr(expr_stmt) => self.visit_expr(&expr_stmt.value),
            Stmt::Return(ret) => {
                if let Some(val) = &ret.value {
                    let prev = self.in_sensitive_value_context;
                    if self.current_fn_is_sensitive {
                        self.in_sensitive_value_context = true;
                    }
                    self.visit_expr(val);
                    self.in_sensitive_value_context = prev;
                }
            }
            Stmt::Raise(raise_stmt) => raise_stmt.exc.iter().for_each(|e| self.visit_expr(e)),
            Stmt::Assert(assert_stmt) => {
                self.visit_expr(&assert_stmt.test);
                assert_stmt.msg.iter().for_each(|m| self.visit_expr(m));
            }
            Stmt::If(if_stmt) => {
                self.visit_expr(&if_stmt.test);
                self.visit_suite(&if_stmt.body);
                for clause in &if_stmt.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        self.visit_expr(test);
                    }
                    self.visit_suite(&clause.body);
                }
            }
            Stmt::For(for_stmt) => {
                self.visit_expr(&for_stmt.iter);
                self.scope.enter_loop();
                self.visit_suite(&for_stmt.body);
                self.visit_suite(&for_stmt.orelse);
                self.scope.exit_loop();
            }
            Stmt::While(while_stmt) => {
                self.visit_expr(&while_stmt.test);
                self.scope.enter_loop();
                self.visit_suite(&while_stmt.body);
                self.visit_suite(&while_stmt.orelse);
                self.scope.exit_loop();
            }
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    if let Some(Expr::Name(var_name)) = item.optional_vars.as_deref() {
                        self.record_archive_binding(var_name.id.as_str(), &item.context_expr);
                    }
                    self.visit_expr(&item.context_expr);
                }
                self.visit_suite(&with_stmt.body);
            }
            Stmt::Try(try_stmt) => {
                self.visit_suite(&try_stmt.body);
                for handler in &try_stmt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
                    self.visit_suite(&h.body);
                }
                self.visit_suite(&try_stmt.orelse);
                self.visit_suite(&try_stmt.finalbody);
            }
            Stmt::Match(match_stmt) => {
                self.visit_expr(&match_stmt.subject);
                for case in &match_stmt.cases {
                    if let Some(guard) = &case.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_suite(&case.body);
                }
            }
            _ => {}
        }
    }

    fn visit_class_def(&mut self, class_def: &StmtClassDef) {
        self.scope.enter_class(class_def.name.as_str());
        self.visit_suite(&class_def.body);
        self.scope.exit_class();
    }

    fn visit_function_def(&mut self, func_def: &StmtFunctionDef) {
        for dec in &func_def.decorator_list {
            self.visit_expr(&dec.expression);
        }
        let saved_scope = self
            .scope
            .enter_function(func_def.name.as_str(), func_def.is_async);
        let prev_fn_sensitive = self.current_fn_is_sensitive;
        self.current_fn_is_sensitive = is_sensitive_random_binding_name(func_def.name.as_str());

        for param in all_function_parameters(func_def) {
            if let Some(default_expr) = &param.default {
                let param_name = param.parameter.name.as_str();
                if is_secret_binding_name(param_name)
                    && let Some(secret_val) = extract_non_placeholder_secret_literal(default_expr)
                {
                    let _ = secret_val;
                    let span = text_range_to_byte_span(param.range());
                    self.emit_hardcoded_secret(span, param_name);
                }
                let prev = self.in_sensitive_value_context;
                if is_sensitive_random_binding_name(param_name) {
                    self.in_sensitive_value_context = true;
                }
                self.visit_expr(default_expr);
                self.in_sensitive_value_context = prev;
            }
        }

        let saved_tar = self.tar_vars.clone();
        let saved_zip = self.zip_vars.clone();
        self.visit_suite(&func_def.body);
        self.tar_vars = saved_tar;
        self.zip_vars = saved_zip;
        self.current_fn_is_sensitive = prev_fn_sensitive;
        self.scope.exit_function(saved_scope);
    }

    fn visit_assign(&mut self, assign: &StmtAssign) {
        let mut any_sensitive_random_target = false;
        for target in &assign.targets {
            if let Some(target_name) = extract_binding_target_name(target) {
                self.record_archive_binding(&target_name, &assign.value);
                if is_secret_binding_name(&target_name)
                    && let Some(_secret_val) = extract_non_placeholder_secret_literal(&assign.value)
                {
                    let span = text_range_to_byte_span(assign.range());
                    self.emit_hardcoded_secret(span, &target_name);
                }
                if is_sensitive_random_binding_name(&target_name) {
                    any_sensitive_random_target = true;
                }
            }
        }
        let prev = self.in_sensitive_value_context;
        if any_sensitive_random_target {
            self.in_sensitive_value_context = true;
        }
        self.visit_expr(&assign.value);
        self.in_sensitive_value_context = prev;
    }

    fn visit_ann_assign(&mut self, ann_assign: &StmtAnnAssign) {
        let target_name = extract_binding_target_name(&ann_assign.target);
        if let Some(val) = &ann_assign.value {
            let mut sensitive_random_target = false;
            if let Some(name) = &target_name {
                self.record_archive_binding(name, val);
                if is_secret_binding_name(name)
                    && let Some(_secret_val) = extract_non_placeholder_secret_literal(val)
                {
                    let span = text_range_to_byte_span(ann_assign.range());
                    self.emit_hardcoded_secret(span, name);
                }
                if is_sensitive_random_binding_name(name) {
                    sensitive_random_target = true;
                }
            }
            let prev = self.in_sensitive_value_context;
            if sensitive_random_target {
                self.in_sensitive_value_context = true;
            }
            self.visit_expr(val);
            self.in_sensitive_value_context = prev;
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Traverses Python expression variants for Bandit security rules"
    )]
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let raw_callee = callee_qualified_name(&call.func);
                let resolved_callee = self.resolve_callee(&raw_callee);
                self.check_http_timeout(call, &raw_callee, &resolved_callee);
                self.check_disabled_tls_verify(call, &raw_callee, &resolved_callee);
                self.check_weak_crypto_or_random_call(call, &raw_callee, &resolved_callee);
                self.check_xxe_or_unsafe_archive(call, &raw_callee, &resolved_callee);

                self.visit_expr(&call.func);
                for arg in &call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &call.arguments.keywords {
                    self.visit_call_keyword(kw);
                }
            }
            Expr::Compare(cmp) => {
                self.check_timing_unsafe_digest_compare(cmp);
                for op_expr in &cmp.operands {
                    self.visit_expr(op_expr);
                }
            }
            Expr::StringLiteral(str_lit) => {
                self.check_hardcoded_tmp_literal(str_lit);
            }
            Expr::FString(fstr) => {
                self.check_hardcoded_tmp_fstring(fstr);
            }
            Expr::Attribute(attr) => self.visit_expr(&attr.value),
            Expr::Await(aw) => self.visit_expr(&aw.value),
            Expr::Yield(y) => y.value.iter().for_each(|v| self.visit_expr(v)),
            Expr::YieldFrom(yf) => self.visit_expr(&yf.value),
            Expr::BinOp(bin) => {
                self.visit_expr(&bin.left);
                self.visit_expr(&bin.right);
            }
            Expr::UnaryOp(un) => self.visit_expr(&un.operand),
            Expr::BoolOp(b) => b.values.iter().for_each(|v| self.visit_expr(v)),
            Expr::Subscript(sub) => {
                self.visit_expr(&sub.value);
                self.visit_expr(&sub.slice);
            }
            Expr::If(if_expr) => {
                self.visit_expr(&if_expr.test);
                self.visit_expr(&if_expr.body);
                self.visit_expr(&if_expr.orelse);
            }
            Expr::List(l) => l.elts.iter().for_each(|e| self.visit_expr(e)),
            Expr::Tuple(t) => t.elts.iter().for_each(|e| self.visit_expr(e)),
            Expr::Set(s) => s.elts.iter().for_each(|e| self.visit_expr(e)),
            Expr::Dict(d) => {
                for item in &d.items {
                    if let Some(k) = &item.key {
                        self.visit_expr(k);
                    }
                    self.visit_expr(&item.value);
                }
            }
            Expr::ListComp(comp) => self.visit_comprehension(&comp.elt, &comp.generators),
            Expr::SetComp(comp) => self.visit_comprehension(&comp.elt, &comp.generators),
            Expr::Generator(comp) => self.visit_comprehension(&comp.elt, &comp.generators),
            Expr::Named(n) => self.visit_expr(&n.value),
            _ => {}
        }
    }


    fn visit_comprehension(&mut self, elt: &Expr, generators: &[ruff_python_ast::Comprehension]) {
        self.visit_expr(elt);
        for g in generators {
            self.visit_expr(&g.iter);
            for if_clause in &g.ifs {
                self.visit_expr(if_clause);
            }
        }
    }
    fn visit_call_keyword(&mut self, kw: &ruff_python_ast::Keyword) {
        let mut kw_sensitive = false;
        if let Some(arg_id) = &kw.arg {
            let kw_name = arg_id.as_str();
            if is_secret_binding_name(kw_name)
                && extract_non_placeholder_secret_literal(&kw.value).is_some()
            {
                let span = text_range_to_byte_span(kw.range());
                self.emit_hardcoded_secret(span, kw_name);
            }
            kw_sensitive = is_sensitive_random_binding_name(kw_name);
        }
        let prev = self.in_sensitive_value_context;
        if kw_sensitive {
            self.in_sensitive_value_context = true;
        }
        self.visit_expr(&kw.value);
        self.in_sensitive_value_context = prev;
    }

    fn resolve_callee(&self, raw: &str) -> String {
        if raw.is_empty() {
            return String::new();
        }
        if let Some(exact) = self.import_aliases.get(raw) {
            return exact.clone();
        }
        if let Some((head, tail)) = raw.split_once('.')
            && let Some(resolved_head) = self.import_aliases.get(head)
        {
            return format!("{resolved_head}.{tail}");
        }
        raw.to_string()
    }

    fn record_archive_binding(&mut self, var_name: &str, expr: &Expr) {
        let Expr::Call(call) = expr else {
            return;
        };
        let resolved = self.resolve_callee(&callee_qualified_name(&call.func));
        if matches!(
            resolved.as_str(),
            "tarfile.open" | "tarfile.TarFile" | "TarFile"
        ) {
            self.tar_vars.insert(var_name.to_string());
        } else if matches!(resolved.as_str(), "zipfile.ZipFile" | "ZipFile") {
            self.zip_vars.insert(var_name.to_string());
        }
    }

    /// 1. `py-security-http-request-requires-timeout` (`bandit/B113`)
    fn check_http_timeout(&mut self, call: &ExprCall, raw_callee: &str, resolved_callee: &str) {
        let is_http_call = [raw_callee, resolved_callee].iter().any(|c| {
            c.split_once('.').is_some_and(|(pkg, method)| {
                matches!(pkg, "requests" | "httpx") && HTTP_METHODS.contains(&method)
            })
        });
        if !is_http_call {
            return;
        }

        let timeout_kw = call
            .arguments
            .keywords
            .iter()
            .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "timeout"));

        let missing_or_none = match timeout_kw {
            None => true,
            Some(kw) => matches!(kw.value, Expr::NoneLiteral(_)),
        };
        if !missing_or_none {
            return;
        }

        let call_span = text_range_to_byte_span(call.range());
        let patch = if let Some(kw) = timeout_kw {
            let kw_span = text_range_to_byte_span(kw.range());
            AutofixPatch::replace(
                format!("Set explicit timeout on `{raw_callee}`"),
                kw_span,
                "timeout=10.0",
            )
        } else {
            let insert_pos = call_span.end.saturating_sub(1);
            let has_args =
                !call.arguments.args.is_empty() || !call.arguments.keywords.is_empty();
            let replacement = if has_args {
                ", timeout=10.0"
            } else {
                "timeout=10.0"
            };
            AutofixPatch::replace(
                format!("Add `timeout=10.0` to `{raw_callee}`"),
                ByteSpan {
                    start: insert_pos,
                    end: insert_pos,
                },
                replacement,
            )
        };

        self.out.push(build_py_diagnostic_with_patch(
            self.path,
            self.line_starts,
            call_span,
            self.scope.current_subject(),
            RuleId::PySecurityHttpRequestRequiresTimeout,
            "pySecurityHttpRequestRequiresTimeout",
            raw_callee.to_string(),
            format!(
                "HTTP request `{raw_callee}(...)` omits an explicit `timeout=` argument (or passes `timeout=None`); pass a finite timeout (e.g. `timeout=10.0`) so hung upstream servers cannot block workers indefinitely."
            ),
            patch,
        ));
    }

    /// 2. `py-security-no-disabled-tls-verify` (`bandit/B501`)
    fn check_disabled_tls_verify(
        &mut self,
        call: &ExprCall,
        raw_callee: &str,
        resolved_callee: &str,
    ) {
        let span = text_range_to_byte_span(call.range());

        if matches!(
            resolved_callee,
            "urllib3.disable_warnings" | "requests.packages.urllib3.disable_warnings"
        ) || raw_callee.ends_with(".disable_warnings")
        {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoDisabledTlsVerify,
                "pySecurityNoDisabledTlsVerify",
                raw_callee.to_string(),
                format!(
                    "`{raw_callee}()` suppresses TLS certificate verification warnings; configure a valid CA bundle instead of disabling certificate checks."
                ),
            ));
            return;
        }

        if matches!(
            resolved_callee,
            "ssl._create_unverified_context" | "ssl._create_stdlib_context"
        ) || raw_callee == "_create_unverified_context"
        {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoDisabledTlsVerify,
                "pySecurityNoDisabledTlsVerify",
                raw_callee.to_string(),
                format!(
                    "`{raw_callee}()` disables SSL/TLS certificate verification (MITM vulnerability); use `ssl.create_default_context()` instead."
                ),
            ));
            return;
        }

        let is_requests_or_httpx = [raw_callee, resolved_callee].iter().any(|c| {
            c.starts_with("requests.")
                || c.starts_with("httpx.")
                || matches!(*c, "Client" | "AsyncClient")
        });
        if is_requests_or_httpx
            && call.arguments.keywords.iter().any(|kw| {
                kw.arg.as_ref().is_some_and(|a| a.as_str() == "verify")
                    && matches!(&kw.value, Expr::BooleanLiteral(b) if !b.value)
            })
        {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoDisabledTlsVerify,
                "pySecurityNoDisabledTlsVerify",
                raw_callee.to_string(),
                format!(
                    "`{raw_callee}(..., verify=False)` disables TLS certificate verification; keep `verify=True` or pass a trusted CA bundle path."
                ),
            ));
        }
    }

    /// 3. `py-security-no-weak-crypto-or-random` (`bandit/B303`, `B311`, `B324`)
    fn check_weak_crypto_or_random_call(
        &mut self,
        call: &ExprCall,
        raw_callee: &str,
        resolved_callee: &str,
    ) {
        let span = text_range_to_byte_span(call.range());

        let used_for_security_false = call.arguments.keywords.iter().any(|kw| {
            kw.arg
                .as_ref()
                .is_some_and(|a| a.as_str() == "usedforsecurity")
                && matches!(&kw.value, Expr::BooleanLiteral(b) if !b.value)
        });

        let is_weak_hash_direct = matches!(
            resolved_callee,
            "hashlib.md5" | "hashlib.sha1" | "Crypto.Hash.MD5.new" | "Crypto.Hash.SHA.new"
        );
        let is_weak_hash_new = resolved_callee == "hashlib.new"
            && call
                .arguments
                .args
                .first()
                .or_else(|| {
                    call.arguments.keywords.iter().find_map(|kw| {
                        kw.arg
                            .as_ref()
                            .is_some_and(|a| a.as_str() == "name")
                            .then_some(&kw.value)
                    })
                })
                .and_then(|e| {
                    if let Expr::StringLiteral(s) = e {
                        Some(s.value.to_str().to_ascii_lowercase())
                    } else {
                        None
                    }
                })
                .is_some_and(|alg| matches!(alg.as_str(), "md5" | "sha1" | "sha" | "md4"));

        if (is_weak_hash_direct || is_weak_hash_new) && !used_for_security_false {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoWeakCryptoOrRandom,
                "pySecurityNoWeakCryptoOrRandom",
                raw_callee.to_string(),
                format!(
                    "Weak cryptographic hash `{raw_callee}(...)` (MD5/SHA1) is vulnerable to collisions; use `hashlib.sha256()` or pass `usedforsecurity=False` for non-security checksums."
                ),
            ));
            return;
        }

        let is_weak_random = [raw_callee, resolved_callee].iter().any(|c| {
            matches!(
                *c,
                "random.random" | "random.randint" | "random.randrange" | "random.choice"
                    | "random.choices" | "random.sample" | "random.getrandbits"
                    | "random.randbytes" | "random.uniform"
            )
        });
        if is_weak_random && self.in_sensitive_value_context {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoWeakCryptoOrRandom,
                "pySecurityNoWeakCryptoOrRandom",
                raw_callee.to_string(),
                format!(
                    "`{raw_callee}(...)` uses a non-cryptographic PRNG for a security-sensitive secret/token/key/OTP value; use the `secrets` module (`secrets.token_urlsafe`, `secrets.token_hex`, `secrets.randbelow`)."
                ),
            ));
        }
    }

    fn check_timing_unsafe_digest_compare(&mut self, cmp: &ExprCompare) {
        if !cmp
            .ops
            .iter()
            .any(|op| matches!(op, CmpOp::Eq | CmpOp::NotEq))
        {
            return;
        }
        let [left, right, ..] = &*cmp.operands else {
            return;
        };
        if is_trivial_non_secret_comparand(left) || is_trivial_non_secret_comparand(right) {
            return;
        }
        let left_digest = is_digest_or_signature_expr(left);
        let right_digest = is_digest_or_signature_expr(right);
        if !left_digest && !right_digest {
            return;
        }
        let span = text_range_to_byte_span(cmp.range());
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PySecurityNoWeakCryptoOrRandom,
            "pySecurityNoWeakCryptoOrRandom",
            "hmac.compare_digest",
            "Comparing HMAC/signature/digest values with `==` or `!=` is vulnerable to timing side-channel attacks; use `hmac.compare_digest(a, b)` instead.",
        ));
    }

    /// 4. `py-security-no-xxe-or-unsafe-archive` (`bandit/B202`, `B314`–`B320`)
    fn check_xxe_or_unsafe_archive(
        &mut self,
        call: &ExprCall,
        raw_callee: &str,
        resolved_callee: &str,
    ) {
        let span = text_range_to_byte_span(call.range());

        if raw_callee.ends_with(".extractall") {
            let receiver = raw_callee.rsplit_once('.').map_or("", |(r, _)| r);
            let is_tar = self.tar_vars.contains(receiver)
                || receiver.contains("tar")
                || resolved_callee.starts_with("tarfile.");
            if is_tar {
                let has_safe_filter = call.arguments.keywords.iter().any(|kw| {
                    kw.arg.as_ref().is_some_and(|a| a.as_str() == "filter")
                        && is_safe_tarfile_filter_expr(&kw.value)
                });
                if !has_safe_filter {
                    self.out.push(build_py_diagnostic(
                        self.path,
                        self.line_starts,
                        span,
                        self.scope.current_subject(),
                        RuleId::PySecurityNoXxeOrUnsafeArchive,
                        "pySecurityNoXxeOrUnsafeArchive",
                        raw_callee.to_string(),
                        format!(
                            "`{raw_callee}(...)` extracts tar archives without a traversal filter (Zip-Slip / path traversal risk); pass `filter=\"data\"`."
                        ),
                    ));
                }
                return;
            }

            let has_validated_members = call.arguments.args.len() >= 2
                || call
                    .arguments
                    .keywords
                    .iter()
                    .any(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "members"));
            if !has_validated_members {
                self.out.push(build_py_diagnostic(
                    self.path,
                    self.line_starts,
                    span,
                    self.scope.current_subject(),
                    RuleId::PySecurityNoXxeOrUnsafeArchive,
                    "pySecurityNoXxeOrUnsafeArchive",
                    raw_callee.to_string(),
                    format!(
                        "`{raw_callee}(...)` extracts archive members without path traversal validation; validate member paths and pass safe `members=`."
                    ),
                ));
            }
            return;
        }

        if resolved_callee.starts_with("defusedxml.") {
            return;
        }

        let is_unsafe_stdlib_xml = matches!(
            resolved_callee,
            "xml.etree.ElementTree.parse" | "xml.etree.ElementTree.iterparse"
                | "xml.etree.ElementTree.fromstring" | "xml.etree.ElementTree.fromstringlist"
                | "xml.etree.ElementTree.XML" | "xml.etree.ElementTree.XMLParser"
                | "xml.etree.cElementTree.parse" | "xml.etree.cElementTree.iterparse"
                | "xml.etree.cElementTree.fromstring" | "xml.dom.minidom.parse"
                | "xml.dom.minidom.parseString" | "xml.dom.pulldom.parse"
                | "xml.dom.pulldom.parseString" | "xml.sax.parse"
                | "xml.sax.parseString" | "xml.sax.make_parser" | "xml.expatreader.create_parser"
        );
        let is_unsafe_lxml = matches!(resolved_callee, "lxml.etree.XMLParser" | "etree.XMLParser")
            && call.arguments.keywords.iter().any(|kw| {
                kw.arg
                    .as_ref()
                    .is_some_and(|a| matches!(a.as_str(), "resolve_entities" | "load_dtd"))
                    && matches!(&kw.value, Expr::BooleanLiteral(b) if b.value)
            });

        if is_unsafe_stdlib_xml || is_unsafe_lxml {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoXxeOrUnsafeArchive,
                "pySecurityNoXxeOrUnsafeArchive",
                raw_callee.to_string(),
                format!(
                    "Unsafe XML parser `{raw_callee}(...)` is vulnerable to XXE / entity expansion attacks; use `defusedxml` or `lxml.etree.XMLParser(resolve_entities=False, no_network=True)`."
                ),
            ));
        }
    }

    /// 5. `py-security-no-hardcoded-secret-or-tmp` (`bandit/B105`–`B108`)
    fn emit_hardcoded_secret(&mut self, span: ByteSpan, binding_name: &str) {
        self.out.push(build_py_diagnostic(
            self.path,
            self.line_starts,
            span,
            self.scope.current_subject(),
            RuleId::PySecurityNoHardcodedSecretOrTmp,
            "pySecurityNoHardcodedSecretOrTmp",
            binding_name.to_string(),
            format!(
                "Hardcoded secret or credential assigned to `{binding_name}`; load secrets from `os.environ` or a secret manager instead of embedding string literals."
            ),
        ));
    }

    fn check_hardcoded_tmp_literal(&mut self, str_lit: &ExprStringLiteral) {
        let val = str_lit.value.to_str();
        if is_hardcoded_tmp_path(val) {
            let span = text_range_to_byte_span(str_lit.range());
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoHardcodedSecretOrTmp,
                "pySecurityNoHardcodedSecretOrTmp",
                val.to_string(),
                format!(
                    "Hardcoded temporary path `\"{val}\"` is vulnerable to symlink/race attacks; use `tempfile.NamedTemporaryFile()` or `tempfile.TemporaryDirectory()`."
                ),
            ));
        }
    }

    fn check_hardcoded_tmp_fstring(&mut self, fstr: &ExprFString) {
        let span = text_range_to_byte_span(fstr.range());
        let raw = crate::matchers::slice_source(self.source, span);
        let trimmed = raw
            .trim_start_matches(['f', 'F', 'r', 'R'])
            .trim_matches(['"', '\'']);
        if is_hardcoded_tmp_path(trimmed) {
            self.out.push(build_py_diagnostic(
                self.path,
                self.line_starts,
                span,
                self.scope.current_subject(),
                RuleId::PySecurityNoHardcodedSecretOrTmp,
                "pySecurityNoHardcodedSecretOrTmp",
                trimmed.to_string(),
                "Hardcoded `/tmp` or `/var/tmp` f-string path is vulnerable to symlink/race attacks; use the `tempfile` module instead.",
            ));
        }
    }
}

fn is_hardcoded_tmp_path(val: &str) -> bool {
    val == "/tmp"
        || val == "/var/tmp"
        || val.starts_with("/tmp/")
        || val.starts_with("/var/tmp/")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches string literal or qualified filter function reference"
)]
fn is_safe_tarfile_filter_expr(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(s) => matches!(s.value.to_str(), "data" | "tar"),
        other => matches!(
            callee_qualified_name(other).as_str(),
            "data_filter" | "tar_filter" | "tarfile.data_filter" | "tarfile.tar_filter"
        ),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts variable or attribute name from assignment target"
)]
fn extract_binding_target_name(target: &Expr) -> Option<String> {
    match target {
        Expr::Name(n) => Some(n.id.to_string()),
        Expr::Attribute(attr) => Some(attr.attr.to_string()),
        _ => None,
    }
}

fn is_secret_binding_name(name: &str) -> bool {
    let lower = name.trim_matches('_').to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    for non_secret_suffix in [
        "_env", "_env_name", "_var", "_url", "_uri", "_endpoint", "_path", "_file", "_filename",
        "_dir", "_header", "_key_name", "_field", "_column", "_table", "_label", "_title", "_msg",
        "_message", "_error", "_err", "_regex", "_pattern", "_prefix", "_suffix", "_type", "_kind",
        "_format", "_alg", "_algorithm", "_method", "_route", "_scope", "_id", "_count", "_len",
        "_length", "_ttl", "_timeout", "_expiry",
    ] {
        if lower.ends_with(non_secret_suffix) {
            return false;
        }
    }
    if ["placeholder_", "dummy_", "mock_", "fake_", "example_"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return false;
    }

    matches!(
        lower.as_str(),
        "password" | "passwd" | "pwd" | "secret" | "secret_key" | "api_key" | "apikey"
            | "access_token" | "auth_token" | "refresh_token" | "bearer_token" | "private_key"
            | "client_secret" | "signing_key" | "jwt_secret" | "webhook_secret"
            | "encryption_key" | "master_key"
    ) || [
        "_password", "_passwd", "_secret", "_api_key", "_apikey", "_private_key",
        "_access_token", "_auth_token", "_signing_key",
    ]
    .iter()
    .any(|s| lower.ends_with(s))
}

fn extract_non_placeholder_secret_literal(expr: &Expr) -> Option<&str> {
    let Expr::StringLiteral(str_lit) = expr else {
        return None;
    };
    let val = str_lit.value.to_str().trim();
    if val.len() < 4 || is_hardcoded_tmp_path(val) {
        return None;
    }
    let lower = val.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "changeme" | "change_me" | "password" | "passwd" | "secret" | "token" | "api_key"
            | "apikey" | "none" | "null" | "nil" | "todo" | "tbd" | "fixme" | "example"
            | "dummy" | "fake" | "test" | "testing" | "sample" | "default" | "placeholder"
            | "your_api_key" | "your-api-key" | "replace_me" | "xxx" | "xxxx" | "****"
            | "redacted" | "<redacted>"
    ) {
        return None;
    }
    if ["http://", "https://", "/", "${", "<", "{{"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return None;
    }
    let is_env_var_name = val.contains('_')
        && val.chars().any(|c| c.is_ascii_uppercase())
        && val
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    (!is_env_var_name).then_some(val)
}

fn is_sensitive_random_binding_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "secret", "token", "password", "passwd", "pwd", "api_key", "apikey", "otp", "nonce",
        "salt", "csrf", "session_id", "private_key", "signing_key", "verification_code",
        "reset_code", "auth_code",
    ]
    .iter()
    .any(|tok| lower.contains(tok))
        || lower == "key"
        || lower.ends_with("_key")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks digest/HMAC/signature identifiers and .hexdigest()/.digest() calls"
)]
fn is_digest_or_signature_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => is_digest_or_signature_name(n.id.as_str()),
        Expr::Attribute(attr) => is_digest_or_signature_name(attr.attr.as_str()),
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            callee.ends_with(".hexdigest") || callee.ends_with(".digest")
        }
        _ => false,
    }
}

fn is_digest_or_signature_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "signature" | "sig" | "expected_signature" | "computed_signature" | "webhook_signature"
            | "hmac" | "hmac_digest" | "digest" | "expected_digest" | "computed_digest" | "mac"
            | "expected_mac" | "computed_mac" | "secret_token" | "auth_token" | "expected_token"
    ) || lower.ends_with("_signature")
        || lower.ends_with("_digest")
        || lower.ends_with("_hmac")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only None, booleans, numbers, and empty string literals are trivial non-secret comparands"
)]
fn is_trivial_non_secret_comparand(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) | Expr::BooleanLiteral(_) | Expr::NumberLiteral(_) => true,
        Expr::StringLiteral(s) => s.value.to_str().is_empty(),
        _ => false,
    }
}
