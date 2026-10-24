//! Single-pass detectors for Rust allocation and hot-loop performance rules:
//!
//! 1. `rs-perf-no-clone-in-loop` ([`RuleId::RsPerfNoCloneInLoop`])
//! 2. `rs-perf-hoist-regex-to-lazylock` ([`RuleId::RsPerfHoistRegexToLazylock`])
//! 3. `rs-perf-prefer-vec-with-capacity` ([`RuleId::RsPerfPreferVecWithCapacity`])
//! 4. `rs-perf-no-unnecessary-format` ([`RuleId::RsPerfNoUnnecessaryFormat`])

use std::collections::{HashMap, HashSet};

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Attribute, Block, Expr, ExprCall, ExprForLoop, ExprLoop, ExprMethodCall, ExprWhile, Fields,
    File, FnArg, GenericArgument, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, Lit, Macro, Pat, PathArguments, Signature, Stmt, Token, TraitItemFn,
    Type,
    parse::Parser,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_expr_ident, extract_pat_ident,
    extract_receiver_label, is_cheap_clone_ctor, is_cheap_clone_type, is_cheap_handle_ident,
    is_format_macro_path, loc_at, path_to_string, span_to_bytes,
};

/// All 9 Tokio async hazard, Rust allocation performance, and deterministic serialization rules.
pub const TOKIO_AND_PERF_RULES: &[RuleId] = &[
    RuleId::RsTokioNoStdLockAcrossAwait,
    RuleId::RsTokioNoBlockingInAsync,
    RuleId::RsTokioPreferBoundedChannel,
    RuleId::RsPerfNoCloneInLoop,
    RuleId::RsPerfHoistRegexToLazylock,
    RuleId::RsPerfPreferVecWithCapacity,
    RuleId::RsPerfNoUnnecessaryFormat,
    RuleId::RsPerfNoSyscallInLoop,
    RuleId::RsNoUnorderedCollectionInSerialize,
];

/// Runs single-pass Rust allocation performance detectors on the parsed [`syn::File`].
pub(crate) fn extract_perf_findings(
    file: &File,
    line_starts: &[u32],
    findings: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = PerfVisitor {
        line_starts,
        findings,
        scope: RsScopeTracker::for_file(file),
        cheap_clone_vars: HashSet::new(),
        in_iter_closure: 0,
    };
    visitor.visit_file(file);
}

struct PerfVisitor<'a> {
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    cheap_clone_vars: HashSet<String>,
    in_iter_closure: u32,
}

impl PerfVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn populate_sig_vars(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            if let FnArg::Typed(pat_type) = input
                && let Some(ident) = extract_pat_ident(&pat_type.pat)
                && is_cheap_clone_type(&pat_type.ty)
            {
                self.cheap_clone_vars.insert(ident);
            }
        }
    }

    fn is_cheap_clone_receiver(&self, receiver: &Expr) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has many variants; receiver classification inspects paths, field accesses, references, and calls"
        )]
        match receiver {
            Expr::Paren(p) => self.is_cheap_clone_receiver(&p.expr),
            Expr::Group(g) => self.is_cheap_clone_receiver(&g.expr),
            Expr::Reference(r) => self.is_cheap_clone_receiver(&r.expr),
            Expr::Path(expr_path) => {
                if let Some(ident) = expr_path.path.segments.last() {
                    let name = ident.ident.to_string();
                    if self.cheap_clone_vars.contains(&name) || is_cheap_handle_ident(&name) {
                        return true;
                    }
                }
                false
            }
            Expr::Field(field) => {
                if let syn::Member::Named(member_ident) = &field.member {
                    let member_name = member_ident.to_string();
                    if is_cheap_handle_ident(&member_name) {
                        return true;
                    }
                }
                self.is_cheap_clone_receiver(&field.base)
            }
            Expr::Call(call) => {
                if let Expr::Path(ep) = call.func.as_ref() {
                    let path_str = path_to_string(&ep.path);
                    if path_str.ends_with("Arc::new")
                        || path_str.ends_with("Rc::new")
                        || path_str.ends_with("Weak::new")
                    {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn check_regex_new_in_fn(&mut self, node: &ExprCall) {
        if self.scope.in_test()
            || self.scope.in_executable_body == 0
            || self.scope.in_static_or_lazy_init > 0
        {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        if matches!(
            path_str.as_str(),
            "Regex::new"
                | "regex::Regex::new"
                | "regex::bytes::Regex::new"
                | "RegexBuilder::new"
                | "regex::RegexBuilder::new"
                | "RegexSet::new"
                | "regex::RegexSet::new"
        ) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfHoistRegexToLazylock,
                self.scope.subject_name(),
                path_str.clone(),
                "rsPerfHoistRegexToLazylock",
                format!(
                    "`{path_str}(...)` compiles a regular expression on every execution; hoist static patterns into `std::sync::LazyLock<Regex>`."
                ),
                loc,
                span,
            ));
        }
    }

    fn check_syscall_in_loop(&mut self, node: &ExprCall) {
        if self.scope.in_test()
            || (!self.scope.in_loop() && self.in_iter_closure == 0)
            || self.scope.in_static_or_lazy_init > 0
        {
            return;
        }
        let Expr::Path(expr_path) = node.func.as_ref() else {
            return;
        };
        let path_str = path_to_string(&expr_path.path);
        let is_zero_arg_env_syscall = node.args.is_empty()
            && matches!(
                path_str.as_str(),
                "env::current_dir"
                    | "std::env::current_dir"
                    | "env::temp_dir"
                    | "std::env::temp_dir"
                    | "env::current_exe"
                    | "std::env::current_exe"
            );
        let is_const_env_var_syscall = node.args.len() == 1
            && matches!(
                path_str.as_str(),
                "env::var" | "std::env::var" | "env::var_os" | "std::env::var_os"
            )
            && matches!(
                node.args.first(),
                Some(Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(_),
                    ..
                }))
            );
        if is_zero_arg_env_syscall || is_const_env_var_syscall {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfNoSyscallInLoop,
                self.scope.subject_name(),
                path_str.clone(),
                "rsPerfNoSyscallInLoop",
                format!(
                    "`{path_str}(...)` queries OS process/environment state inside a loop or iterator closure; hoist the lookup once before the loop and reuse the cached value."
                ),
                loc,
                span,
            ));
        }
    }

    fn check_serializable_fields(&mut self, type_name: &str, fields: &Fields) {
        if self.scope.in_test() {
            return;
        }
        for field in fields {
            if field_has_deterministic_or_skip_serde_attr(&field.attrs) {
                continue;
            }
            let Some(coll_kind) = unordered_collection_type_name(&field.ty) else {
                continue;
            };
            let replacement = if coll_kind == "HashSet" {
                "BTreeSet"
            } else {
                "BTreeMap"
            };
            let field_label = field
                .ident
                .as_ref()
                .map_or_else(|| type_name.to_string(), ToString::to_string);
            let span = self.span_to_bytes(field.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsNoUnorderedCollectionInSerialize,
                Some(type_name.to_string()),
                field_label.clone(),
                "rsNoUnorderedCollectionInSerialize",
                format!(
                    "`{type_name}.{field_label}` serializes `{coll_kind}` with non-deterministic per-process `RandomState` iteration order; use `{replacement}` or annotate with `#[serde(serialize_with = ...)]` for deterministic output."
                ),
                loc,
                span,
            ));
        }
    }

    fn inspect_stmt_for_vec_capacity(
        &mut self,
        stmt: &Stmt,
        unreserved_vecs: &mut HashMap<String, (SourceLoc, ByteSpan)>,
    ) {
        if self.scope.in_test() {
            return;
        }
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init
                    && is_empty_vec_init(&init.expr)
                    && let Some(ident) = extract_pat_ident(&local.pat)
                {
                    let span = self.span_to_bytes(local.span());
                    let loc = self.loc_at(span.start);
                    unreserved_vecs.insert(ident, (loc, span));
                }
            }
            Stmt::Expr(Expr::MethodCall(mc), _) => {
                let method = mc.method.to_string();
                if matches!(method.as_str(), "reserve" | "reserve_exact" | "try_reserve")
                    && let Some(recv) = extract_expr_ident(&mc.receiver)
                {
                    unreserved_vecs.remove(&recv);
                }
            }
            Stmt::Expr(Expr::ForLoop(for_loop), _) => {
                let mut pushed_vars = Vec::new();
                collect_unconditional_pushed_vecs(&for_loop.body, &mut pushed_vars);
                for vec_name in pushed_vars {
                    let Some((loc, span)) = unreserved_vecs.remove(&vec_name) else {
                        continue;
                    };
                    self.findings.push(RsCandidateFinding::new(
                        RuleId::RsPerfPreferVecWithCapacity,
                        self.scope.subject_name(),
                        vec_name.clone(),
                        "rsPerfPreferVecWithCapacity",
                        format!(
                            "`{vec_name}` is initialized with `Vec::new()` and populated unconditionally in a `for` loop; prefer `Vec::with_capacity(...)` to avoid repeated reallocations."
                        ),
                        loc,
                        span,
                    ));
                }
            }
            Stmt::Item(_) | Stmt::Expr(..) | Stmt::Macro(_) => {}
        }
    }

    fn record_local_stmt_bindings(&mut self, local: &syn::Local) {
        if let Pat::Type(pat_type) = &local.pat
            && let Some(ident) = extract_pat_ident(&pat_type.pat)
            && is_cheap_clone_type(&pat_type.ty)
        {
            self.cheap_clone_vars.insert(ident);
        }

        let Some(init) = &local.init else {
            return;
        };
        let Some(ident) = extract_pat_ident(&local.pat) else {
            return;
        };
        if is_cheap_clone_ctor(&init.expr) {
            self.cheap_clone_vars.insert(ident);
        }
    }
}

impl<'ast> Visit<'ast> for PerfVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        if !self.scope.in_test()
            && !crate::matchers::attrs_indicate_test_context(&i.attrs)
            && attrs_derive_serialize(&i.attrs)
        {
            self.check_serializable_fields(&i.ident.to_string(), &i.fields);
        }
        visit::visit_item_struct(self, i);
    }

    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        if !self.scope.in_test()
            && !crate::matchers::attrs_indicate_test_context(&i.attrs)
            && attrs_derive_serialize(&i.attrs)
        {
            let enum_name = i.ident.to_string();
            for variant in &i.variants {
                if !field_has_deterministic_or_skip_serde_attr(&variant.attrs) {
                    self.check_serializable_fields(&enum_name, &variant.fields);
                }
            }
        }
        visit::visit_item_enum(self, i);
    }

    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_static(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        let snap = self.scope.enter_static_or_const();
        visit::visit_item_const(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        let prev_cheap_vars = std::mem::take(&mut self.cheap_clone_vars);
        self.populate_sig_vars(&i.sig);

        visit::visit_trait_item_fn(self, i);

        self.cheap_clone_vars = prev_cheap_vars;
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let mut unreserved_vecs: HashMap<String, (SourceLoc, ByteSpan)> = HashMap::new();

        for stmt in &b.stmts {
            self.inspect_stmt_for_vec_capacity(stmt, &mut unreserved_vecs);
            self.visit_stmt(stmt);
            if let Stmt::Local(local) = stmt {
                self.record_local_stmt_bindings(local);
            }
        }
    }

    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_pat(&i.pat);
        self.visit_expr(&i.expr);
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&i.cond);
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
    }

    fn visit_expr_loop(&mut self, i: &'ast ExprLoop) {
        for attr in &i.attrs {
            self.visit_attribute(attr);
        }
        let snap = self.scope.enter_loop();
        self.visit_block(&i.body);
        self.scope.exit(snap);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        self.check_regex_new_in_fn(node);
        self.check_syscall_in_loop(node);

        let is_lazy_init = is_lazy_lock_init_call(node);
        if is_lazy_init {
            self.scope.in_static_or_lazy_init += 1;
        }
        visit::visit_expr_call(self, node);
        if is_lazy_init {
            self.scope.in_static_or_lazy_init -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();

        if !self.scope.in_test()
            && self.scope.in_loop()
            && method_name == "clone"
            && node.args.is_empty()
            && !self.is_cheap_clone_receiver(&node.receiver)
        {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let recv_label =
                extract_receiver_label(&node.receiver).unwrap_or_else(|| "value".to_string());
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfNoCloneInLoop,
                self.scope.subject_name(),
                format!("{recv_label}.clone()"),
                "rsPerfNoCloneInLoop",
                format!(
                    "Heap `.clone()` on `{recv_label}` inside a loop allocates on every iteration; borrow `&{recv_label}`, hoist the clone outside the loop, or wrap shared data in `Arc`."
                ),
                loc,
                span,
            ));
        }

        let is_once_init = matches!(
            method_name.as_str(),
            "get_or_init" | "get_or_try_init" | "call_once"
        );
        let is_iter_adapter = matches!(
            method_name.as_str(),
            "map"
                | "filter"
                | "filter_map"
                | "flat_map"
                | "for_each"
                | "any"
                | "all"
                | "find"
                | "find_map"
                | "position"
                | "max_by_key"
                | "min_by_key"
                | "sort_by"
                | "sort_by_key"
        ) && node.args.iter().any(|arg| matches!(arg, Expr::Closure(_)));
        if is_once_init {
            self.scope.in_static_or_lazy_init += 1;
        }
        for attr in &node.attrs {
            self.visit_attribute(attr);
        }
        self.visit_expr(&node.receiver);
        if is_iter_adapter {
            self.in_iter_closure += 1;
        }
        for arg in &node.args {
            self.visit_expr(arg);
        }
        if is_iter_adapter {
            self.in_iter_closure -= 1;
        }
        if is_once_init {
            self.scope.in_static_or_lazy_init -= 1;
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if !self.scope.in_test()
            && is_format_macro_path(&mac.path)
            && is_unnecessary_format_tokens(&mac.tokens)
        {
            let span = self.span_to_bytes(mac.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsPerfNoUnnecessaryFormat,
                self.scope.subject_name(),
                "format!",
                "rsPerfNoUnnecessaryFormat",
                "Unnecessary `format!(...)` call allocates a formatted `String` without formatting; use `.to_string()`, `String::from(...)`, or a borrowed `&str`.",
                loc,
                span,
            ));
        }
        visit::visit_macro(self, mac);
    }
}

fn is_lazy_lock_init_call(node: &ExprCall) -> bool {
    if let Expr::Path(ep) = node.func.as_ref() {
        let full = path_to_string(&ep.path);
        return full.ends_with("LazyLock::new") || full.ends_with("Lazy::new");
    }
    false
}

fn is_empty_vec_init(expr: &Expr) -> bool {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Expr has many variants; checks Vec::new() calls and empty vec![] macros"
    )]
    match expr {
        Expr::Paren(p) => is_empty_vec_init(&p.expr),
        Expr::Group(g) => is_empty_vec_init(&g.expr),
        Expr::Call(call) if call.args.is_empty() => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let full = path_to_string(&ep.path);
                matches!(
                    full.as_str(),
                    "Vec::new" | "std::vec::Vec::new" | "alloc::vec::Vec::new"
                )
            } else {
                false
            }
        }
        Expr::Macro(expr_macro) => {
            expr_macro.mac.path.is_ident("vec") && expr_macro.mac.tokens.is_empty()
        }
        _ => false,
    }
}

fn collect_unconditional_pushed_vecs(block: &Block, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        if let Stmt::Expr(expr, _) = stmt
            && let Expr::MethodCall(mc) = expr
            && mc.method == "push"
            && mc.args.len() == 1
            && let Some(recv) = extract_expr_ident(&mc.receiver)
            && !out.contains(&recv)
        {
            out.push(recv);
        }
    }
}

fn is_unnecessary_format_tokens(tokens: &proc_macro2::TokenStream) -> bool {
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    let Ok(args) = parser.parse2(tokens.clone()) else {
        return false;
    };
    let Some(Expr::Lit(expr_lit)) = args.first() else {
        return false;
    };
    let Lit::Str(lit_str) = &expr_lit.lit else {
        return false;
    };
    let val = lit_str.value();
    match args.len() {
        1 => !has_format_placeholder(&val) || is_single_trivial_placeholder(&val),
        2 => val == "{}" || val == "{0}",
        _ => false,
    }
}

fn has_format_placeholder(s: &str) -> bool {
    let cleaned = s.replace("{{", "").replace("}}", "");
    cleaned.contains('{') && cleaned.contains('}')
}

fn is_single_trivial_placeholder(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('{').and_then(|rest| rest.strip_suffix('}')) else {
        return false;
    };
    if inner.is_empty() {
        return true;
    }
    !inner.contains('{')
        && !inner.contains('}')
        && !inner.contains(':')
        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn attrs_derive_serialize(attrs: &[Attribute]) -> bool {
    let mut has_serialize = false;
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta
                .path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "Serialize")
            {
                has_serialize = true;
            }
            Ok(())
        });
    }
    has_serialize
}

fn field_has_deterministic_or_skip_serde_attr(attrs: &[Attribute]) -> bool {
    let mut safe = false;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("serialize_with")
                || meta.path.is_ident("with")
                || meta.path.is_ident("skip")
                || meta.path.is_ident("skip_serializing")
                || meta.path.is_ident("into")
            {
                safe = true;
            }
            if meta.input.peek(Token![=]) {
                let _: Token![=] = meta.input.parse()?;
                let _: syn::Expr = meta.input.parse()?;
            }
            Ok(())
        });
    }
    safe
}

fn unordered_collection_type_name(ty: &Type) -> Option<&'static str> {
    let Type::Path(tp) = ty else {
        return None;
    };
    let last = tp.path.segments.last()?;
    let ident_str = last.ident.to_string();
    if ident_str == "HashSet" {
        return Some("HashSet");
    }
    if ident_str == "HashMap" {
        return Some("HashMap");
    }
    if matches!(ident_str.as_str(), "Option" | "Vec" | "Box" | "Arc" | "Rc")
        && let PathArguments::AngleBracketed(args) = &last.arguments
    {
        for arg in &args.args {
            if let GenericArgument::Type(inner_ty) = arg
                && let Some(found) = unordered_collection_type_name(inner_ty)
            {
                return Some(found);
            }
        }
    }
    None
}
