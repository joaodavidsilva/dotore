//! Single-pass detectors for the 5 core production Rust safety rules:
//!
//! 1. `rs-no-unwrap-in-production` ([`RuleId::RsNoUnwrapInProduction`])
//! 2. `rs-no-unguarded-slice-index` ([`RuleId::RsNoUnguardedSliceIndex`])
//! 3. `rs-no-lossy-numeric-as-cast` ([`RuleId::RsNoLossyNumericAsCast`])
//! 4. `rs-require-safety-comment-on-unsafe` ([`RuleId::RsRequireSafetyCommentOnUnsafe`])
//! 5. `rs-no-mem-forget` ([`RuleId::RsNoMemForget`])

mod bounds;
mod casts;
mod guards;

use std::collections::HashMap;

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprCast, ExprClosure, ExprForLoop, ExprIf,
    ExprIndex, ExprMatch, ExprMethodCall, ExprUnsafe, ExprWhile, File, ImplItemFn, Item, ItemFn,
    ItemImpl, ItemMod, Signature, Stmt, TraitItemFn,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_pat_ident, extract_type_name, loc_at,
    normalize_expr_key, span_to_bytes,
};

use self::{
    bounds::{
        SliceGuard, extract_fixed_array_expr_len, extract_fixed_array_type_len,
        extract_len_equivalent_source, extract_search_receiver_and_offset,
    },
    casts::{
        NumericType, extract_local_ident_and_type, extract_numeric_type,
        is_lossy_or_sign_changing_cast, is_mem_forget_path, use_tree_imports_mem_forget,
    },
    guards::{
        extract_cond_bounds_guards, extract_let_pattern_bounds_guards,
        extract_local_init_bounds_guards, extract_post_stmt_bounds_guards,
        extract_while_body_reassignment_guards,
    },
};

/// Evaluates the 5 core Rust production safety rules on `ast` and appends candidate findings to `out`.
pub(crate) fn extract_safety_findings(
    ast: &File,
    lines: &[&str],
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut has_imported_mem_forget = false;
    let mut const_array_lengths = HashMap::new();
    for item in &ast.items {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only use, const, and static items contribute top-level imports and array lengths (#50)"
        )]
        match item {
            Item::Use(item_use) => {
                if use_tree_imports_mem_forget(&item_use.tree, "") {
                    has_imported_mem_forget = true;
                }
            }
            Item::Const(item_const) => {
                let len = extract_fixed_array_type_len(&item_const.ty)
                    .or_else(|| extract_fixed_array_expr_len(&item_const.expr));
                if let Some(n) = len
                    && n > 0
                {
                    const_array_lengths.insert(item_const.ident.to_string(), n);
                }
            }
            Item::Static(item_static) => {
                let len = extract_fixed_array_type_len(&item_static.ty)
                    .or_else(|| extract_fixed_array_expr_len(&item_static.expr));
                if let Some(n) = len
                    && n > 0
                {
                    const_array_lengths.insert(item_static.ident.to_string(), n);
                }
            }
            _ => {}
        }
    }

    let mut visitor = SafetyVisitor {
        lines,
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        has_imported_mem_forget,
        local_types: HashMap::new(),
        const_array_lengths: const_array_lengths.clone(),
        fixed_array_lengths: const_array_lengths,
        len_equivalents: HashMap::new(),
        active_guards: Vec::new(),
        block_guards: Vec::new(),
    };
    visitor.visit_file(ast);
}

struct SafetyVisitor<'a> {
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    has_imported_mem_forget: bool,
    local_types: HashMap<String, NumericType>,
    const_array_lengths: HashMap<String, usize>,
    fixed_array_lengths: HashMap<String, usize>,
    len_equivalents: HashMap<String, String>,
    active_guards: Vec<SliceGuard>,
    block_guards: Vec<SliceGuard>,
}

impl SafetyVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn populate_sig_param_types(&mut self, sig: &Signature) {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input
                && let Some(ident) = extract_pat_ident(&pat_type.pat)
            {
                if let Some(num_ty) = extract_numeric_type(&pat_type.ty) {
                    self.local_types.insert(ident.clone(), num_ty);
                }
                if let Some(arr_len) = extract_fixed_array_type_len(&pat_type.ty) {
                    self.fixed_array_lengths.insert(ident, arr_len);
                }
            }
        }
    }

    fn record_local_stmt_facts(&mut self, local: &syn::Local) {
        let pat_ident = extract_local_ident_and_type(&local.pat);
        if let Some((name, explicit_ty)) = &pat_ident {
            if let Some(ty) = explicit_ty {
                self.local_types.insert(name.clone(), *ty);
            }
            let Some(init) = &local.init else {
                return;
            };
            if explicit_ty.is_none()
                && let Some(inferred_ty) = self.infer_expr_numeric_type(&init.expr)
            {
                self.local_types.insert(name.clone(), inferred_ty);
            }
            if let Some(arr_len) = extract_fixed_array_expr_len(&init.expr) {
                self.fixed_array_lengths.insert(name.clone(), arr_len);
            } else if let Some(len_src) =
                extract_len_equivalent_source(&init.expr, &self.len_equivalents)
            {
                self.len_equivalents.insert(name.clone(), len_src);
            }
            extract_local_init_bounds_guards(
                name,
                &init.expr,
                &self.active_guards,
                &mut self.block_guards,
            );
        } else if let Some(init) = &local.init {
            extract_let_pattern_bounds_guards(&local.pat, &init.expr, &mut self.block_guards);
        }
    }
}

impl<'ast> Visit<'ast> for SafetyVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        let prev_types = std::mem::take(&mut self.local_types);
        let prev_arrays = std::mem::replace(
            &mut self.fixed_array_lengths,
            self.const_array_lengths.clone(),
        );
        let prev_len_eq = std::mem::take(&mut self.len_equivalents);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
        self.len_equivalents = prev_len_eq;
        self.block_guards = prev_block_guards;
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        let prev_types = std::mem::take(&mut self.local_types);
        self.populate_sig_param_types(&i.sig);
        visit::visit_trait_item_fn(self, i);
        self.local_types = prev_types;
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let span = self.span_to_bytes(i.span());
        let loc = self.loc_at(span.start);
        let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);

        let snap = self.scope.enter_impl(i);
        let impl_subject_name = self
            .scope
            .subject_name()
            .unwrap_or_else(|| "Impl".to_string());

        if let Some(unsafe_token) = &i.unsafety
            && !self.scope.in_test()
        {
            let unsafe_span = self.span_to_bytes(unsafe_token.span);
            let unsafe_loc = self.loc_at(unsafe_span.start);
            if !self.has_safety_comment_near(unsafe_loc.line, end_line) {
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsRequireSafetyCommentOnUnsafe,
                    Some(impl_subject_name.clone()),
                    format!("unsafe impl {impl_subject_name}"),
                    "rsRequireSafetyCommentOnUnsafe",
                    format!(
                        "`unsafe impl {impl_subject_name}` is missing a preceding `// SAFETY:` invariant comment explaining why the trait's safety contract holds."
                    ),
                    unsafe_loc,
                    span,
                ));
            }
        }

        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        let prev_types = std::mem::take(&mut self.local_types);
        let prev_arrays = std::mem::replace(
            &mut self.fixed_array_lengths,
            self.const_array_lengths.clone(),
        );
        let prev_len_eq = std::mem::take(&mut self.len_equivalents);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
        self.len_equivalents = prev_len_eq;
        self.block_guards = prev_block_guards;
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let saved_block_guards_len = self.block_guards.len();

        for stmt in &b.stmts {
            self.visit_stmt(stmt);
            extract_post_stmt_bounds_guards(stmt, &mut self.block_guards);
        }

        self.block_guards.truncate(saved_block_guards_len);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Local(local) = s {
            self.record_local_stmt_facts(local);
        }
        visit::visit_stmt(self, s);
    }

    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        self.visit_expr(&i.expr);
        if let Expr::MethodCall(mc) = i.expr.as_ref()
            && let Some(elem_ty) = match mc.method.to_string().as_str() {
                "chars" => Some(NumericType::Char),
                "bytes" => Some(NumericType::U8),
                _ => None,
            }
            && let Some(ident) = extract_pat_ident(&i.pat)
        {
            self.local_types.insert(ident, elem_ty);
        }

        let saved_guards_len = self.active_guards.len();
        let mut added_window_var: Option<String> = None;

        self.collect_for_loop_guards(i, &mut added_window_var);

        self.visit_block(&i.body);
        self.active_guards.truncate(saved_guards_len);
        if let Some(win_var) = added_window_var {
            self.fixed_array_lengths.remove(&win_var);
        }
    }

    fn visit_expr_closure(&mut self, i: &'ast ExprClosure) {
        for input in &i.inputs {
            if let Some((name, Some(explicit_ty))) = extract_local_ident_and_type(input) {
                self.local_types.insert(name, explicit_ty);
            }
        }
        visit::visit_expr_closure(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.visit_expr(&i.cond);

        let mut cond_guards = Vec::new();
        extract_cond_bounds_guards(&i.cond, false, &mut cond_guards);
        let saved_len = self.active_guards.len();
        self.active_guards.extend(cond_guards);
        self.visit_block(&i.then_branch);
        self.active_guards.truncate(saved_len);

        if let Some((_, else_expr)) = &i.else_branch {
            let mut else_guards = Vec::new();
            extract_cond_bounds_guards(&i.cond, true, &mut else_guards);
            let saved_else_len = self.active_guards.len();
            self.active_guards.extend(else_guards);
            self.visit_expr(else_expr);
            self.active_guards.truncate(saved_else_len);
        }
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        let mut cond_guards = Vec::new();
        extract_cond_bounds_guards(&i.cond, false, &mut cond_guards);
        extract_while_body_reassignment_guards(&i.body, &cond_guards, &mut self.block_guards);

        self.visit_expr(&i.cond);

        let saved_len = self.active_guards.len();
        self.active_guards.extend(cond_guards);
        self.visit_block(&i.body);
        self.active_guards.truncate(saved_len);
    }

    fn visit_expr_match(&mut self, i: &'ast ExprMatch) {
        self.visit_expr(&i.expr);
        for arm in &i.arms {
            let mut arm_guards = Vec::new();
            extract_let_pattern_bounds_guards(&arm.pat, &i.expr, &mut arm_guards);
            if let Some((_, guard_expr)) = &arm.guard {
                extract_cond_bounds_guards(guard_expr, false, &mut arm_guards);
            }
            let saved_len = self.active_guards.len();
            self.active_guards.extend(arm_guards);
            if let Some((_, guard_expr)) = &arm.guard {
                self.visit_expr(guard_expr);
            }
            self.visit_expr(&arm.body);
            self.active_guards.truncate(saved_len);
        }
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only short-circuit logical `&&` and `||` operators propagate LHS bounds guards into RHS (#50)"
        )]
        match i.op {
            BinOp::And(_) => {
                self.visit_expr(&i.left);
                let mut lhs_guards = Vec::new();
                extract_cond_bounds_guards(&i.left, false, &mut lhs_guards);
                let saved_len = self.active_guards.len();
                self.active_guards.extend(lhs_guards);
                self.visit_expr(&i.right);
                self.active_guards.truncate(saved_len);
            }
            BinOp::Or(_) => {
                self.visit_expr(&i.left);
                let mut lhs_guards = Vec::new();
                extract_cond_bounds_guards(&i.left, true, &mut lhs_guards);
                let saved_len = self.active_guards.len();
                self.active_guards.extend(lhs_guards);
                self.visit_expr(&i.right);
                self.active_guards.truncate(saved_len);
            }
            _ => visit::visit_expr_binary(self, i),
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if !self.scope.in_test() {
            let is_unwrap = method_name == "unwrap" && node.args.is_empty();
            let is_expect = method_name == "expect" && node.args.len() == 1;
            if is_unwrap || is_expect {
                let full_span = self.span_to_bytes(node.span());
                let method_span = self.span_to_bytes(node.method.span());
                let loc = self.loc_at(method_span.start);
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsNoUnwrapInProduction,
                    self.scope.subject_name(),
                    method_name.clone(),
                    "rsNoUnwrapInProduction",
                    format!(
                        "Avoid `.{method_name}()` in production Rust code; propagate errors with `?`, match with `let ... else`, or use `.unwrap_or_default()`."
                    ),
                    loc,
                    full_span,
                ));
            }
        }
        if matches!(
            method_name.as_str(),
            "map" | "and_then" | "map_or" | "map_or_else" | "is_some_and"
        ) && let Some((base_coll, pat_off)) = extract_search_receiver_and_offset(&node.receiver)
            && let Some(closure_arg) = node.args.iter().find_map(|a| {
                if let Expr::Closure(c) = a {
                    Some(c)
                } else {
                    None
                }
            })
            && let Some(first_input) = closure_arg.inputs.first()
            && let Some(param_name) = extract_pat_ident(first_input)
        {
            self.visit_expr(&node.receiver);
            let saved_len = self.active_guards.len();
            self.active_guards.push(SliceGuard {
                collection: base_coll.clone(),
                index: Some(param_name.clone()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
            if let Some(off) = pat_off {
                self.active_guards.push(SliceGuard {
                    collection: base_coll,
                    index: Some(format!("{param_name}+{off}")),
                    min_len: 1,
                    inclusive_upper_bound: true,
                });
            }
            for arg in &node.args {
                self.visit_expr(arg);
            }
            self.active_guards.truncate(saved_len);
            return;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        if !self.scope.in_test() && !self.is_slice_index_guarded(node) {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            let coll_key = normalize_expr_key(&node.expr);
            let idx_key = normalize_expr_key(&node.index);
            let target = if coll_key.is_empty() {
                "slice[idx]".to_string()
            } else {
                format!("{coll_key}[{idx_key}]")
            };
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsNoUnguardedSliceIndex,
                self.scope.subject_name(),
                target.clone(),
                "rsNoUnguardedSliceIndex",
                format!(
                    "Direct indexing `{target}` can panic out of bounds; prefer `{coll_key}.get({idx_key})` or guard `{idx_key} < {coll_key}.len()` first."
                ),
                loc,
                span,
            ));
        }
        visit::visit_expr_index(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast ExprCast) {
        if !self.scope.in_test()
            && let Some(target_ty) = extract_numeric_type(&node.ty)
        {
            let src_ty = self.infer_expr_numeric_type(&node.expr);
            if is_lossy_or_sign_changing_cast(src_ty, target_ty) {
                let span = self.span_to_bytes(node.span());
                let loc = self.loc_at(span.start);
                let target_ty_str =
                    extract_type_name(&node.ty).unwrap_or_else(|| "numeric".to_string());
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsNoLossyNumericAsCast,
                    self.scope.subject_name(),
                    format!("as {target_ty_str}"),
                    "rsNoLossyNumericAsCast",
                    format!(
                        "Potentially lossy or sign-changing `as {target_ty_str}` cast; prefer `{target_ty_str}::try_from(...)` / `.try_into()` or lossless `{target_ty_str}::from(...)`."
                    ),
                    loc,
                    span,
                ));
            }
        }
        visit::visit_expr_cast(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        if !self.scope.in_test() {
            let span = self.span_to_bytes(node.span());
            let unsafe_token_span = self.span_to_bytes(node.unsafe_token.span);
            let loc = self.loc_at(unsafe_token_span.start);
            let end_line = self.loc_at(span.end.saturating_sub(1)).line.max(loc.line);
            if !self.has_safety_comment_near(loc.line, end_line) {
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsRequireSafetyCommentOnUnsafe,
                    self.scope.subject_name(),
                    "unsafe",
                    "rsRequireSafetyCommentOnUnsafe",
                    "`unsafe` block is missing a preceding `// SAFETY:` invariant comment explaining why all unsafe preconditions hold.",
                    loc,
                    span,
                ));
            }
        }
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if !self.scope.in_test()
            && let Expr::Path(expr_path) = node.func.as_ref()
            && is_mem_forget_path(&expr_path.path, self.has_imported_mem_forget)
        {
            let span = self.span_to_bytes(node.span());
            let loc = self.loc_at(span.start);
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsNoMemForget,
                self.scope.subject_name(),
                "mem::forget",
                "rsNoMemForget",
                "Avoid `mem::forget(...)`, which leaks resources and skips `Drop` destructors; use `std::mem::ManuallyDrop` if ownership transfer requires suppressing drop.",
                loc,
                span,
            ));
        }
        visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests;
